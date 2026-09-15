//! `rustunnel-server`：frp v2 兼容的服务端（等价于原版 frps）。
//!
//! 与原版一致，控制连接与工作连接复用**同一个端口**，靠首帧消息类型区分：
//! `Login` 走控制连接流程，`NewWorkConn` 走工作连接流程，
//! `NewVisitorConn` 走 visitor 接入流程（stcp / xtcp）。
//!
//! 已实现的代理类型：`tcp` / `udp` / `http` / `https` / `stcp` / `xtcp`。

mod udp_proxy;
mod vhost;
mod visitor;

use std::{
    collections::{HashMap, HashSet, VecDeque},
    net::SocketAddr,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use anyhow::{anyhow, Context, Result};
use clap::Parser;
use rustunnel_common::{
    config::{default_config_path, Protocol, ServerConfig},
    frp::{
        self,
        conn::{self, FrpConn, ServerAccept},
        msg::{
            FrpMessage, Login, NatHoleResp, NewProxyResp, NewVisitorConn, NewVisitorConnResp,
            NewWorkConn, Pong, StartWorkConn,
        },
        stream::{BoxStream, PrefixedStream},
    },
    util,
};
use tokio::{
    net::TcpListener,
    net::TcpStream,
    sync::{mpsc, Notify},
    task::AbortHandle,
};
use tracing::{debug, error, info, warn};

use visitor::{VisitorEntry, VisitorTable};
use vhost::{VhostRoute, VhostTable};

// ---------------------------------------------------------------------------
// CLI
// ---------------------------------------------------------------------------

#[derive(Parser, Debug)]
#[command(name = "rustunnel-server", version, about = "rustunnel 服务端（兼容原版 frp）")]
struct Cli {
    /// 配置文件路径（默认 ./server.toml）
    #[arg(short, long, value_name = "PATH")]
    config: Option<std::path::PathBuf>,

    /// 打印一份示例配置到标准输出
    #[arg(long)]
    print_example: bool,

    /// 生成示例配置文件到指定路径
    #[arg(long, value_name = "PATH")]
    gen_config: Option<std::path::PathBuf>,

    /// 覆盖配置里的日志级别
    #[arg(long, value_name = "LEVEL")]
    log_level: Option<String>,

    /// 覆盖配置里的线协议（frp-v2 / rustunnel）
    #[arg(long, value_name = "PROTOCOL")]
    protocol: Option<String>,

    /// 监听端口（覆盖配置）
    #[arg(short, long, value_name = "PORT")]
    port: Option<u16>,

    /// 认证 token（覆盖配置）
    #[arg(short, long, value_name = "TOKEN")]
    token: Option<String>,
}

// ---------------------------------------------------------------------------
// 工作连接池 / 待配对的用户连接
// ---------------------------------------------------------------------------

/// 一条已握手完成、等待分配代理的工作连接。
struct WorkItem {
    conn: FrpConn,
    at: Instant,
}

/// 一个已经连进来、等待工作连接的用户连接。
///
/// `stream` 可能是：
/// * 公网端口上进来的 TCP（tcp / udp / http / https 走这条）；
/// * visitor 连接（stcp / xtcp）：握手完成后它本身就是裸字节通道。
struct PendingUser {
    proxy: String,
    remote_port: u16,
    stream: BoxStream,
    peer: SocketAddr,
    at: Instant,
}

type Paired = (PendingUser, WorkItem);

#[derive(Default)]
struct PoolState {
    work: VecDeque<WorkItem>,
    users: VecDeque<PendingUser>,
}

impl PoolState {
    /// 丢弃超时的工作连接与用户连接，避免半开连接堆积。
    fn reap(&mut self, timeout: Duration) {
        let now = Instant::now();
        while self
            .work
            .front()
            .map(|w| now.duration_since(w.at) > timeout)
            .unwrap_or(false)
        {
            self.work.pop_front();
        }
        while self
            .users
            .front()
            .map(|u| now.duration_since(u.at) > timeout)
            .unwrap_or(false)
        {
            self.users.pop_front();
        }
    }
}

/// 一个已登录客户端的全部状态。
struct ClientState {
    run_id: String,
    client_id: String,
    /// 客户端在 Login 里声明的用户名，用于 stcp/xtcp 的 `allow_users` 白名单匹配。
    user: String,
    /// 代理监听器用它通知控制连接"需要一条工作连接"。
    req_tx: mpsc::UnboundedSender<()>,
    pool: Mutex<PoolState>,
    listeners: Mutex<HashMap<String, AbortHandle>>,
    /// 本次会话协商出的 UDP 报文编码（true = 二进制），工作连接要跟着用。
    udp_binary: bool,
    /// 有新工作连接入池 / 代理被停止时唤醒等待者（UDP 与 HTTP 都要主动取工作连接）。
    work_notify: Notify,
    stopped: std::sync::atomic::AtomicBool,
    idle_timeout: Duration,
}

impl ClientState {
    fn new(
        run_id: String,
        client_id: String,
        user: String,
        req_tx: mpsc::UnboundedSender<()>,
        idle_timeout: Duration,
        udp_binary: bool,
    ) -> Self {
        Self {
            run_id,
            client_id,
            user,
            req_tx,
            pool: Mutex::new(PoolState::default()),
            listeners: Mutex::new(HashMap::new()),
            udp_binary,
            work_notify: Notify::new(),
            stopped: std::sync::atomic::AtomicBool::new(false),
            idle_timeout,
        }
    }

    fn udp_codec_is_binary(&self) -> bool {
        self.udp_binary
    }

    fn is_stopped(&self) -> bool {
        self.stopped.load(std::sync::atomic::Ordering::Relaxed)
    }

    /// 主动取一条工作连接：池里没有就向客户端要，并等待它到来。
    ///
    /// UDP 代理和 HTTP 代理都不是"用户连进来才要连接"，必须自己发起。
    async fn acquire_work_conn(self: &Arc<Self>, wait: Duration) -> Option<WorkItem> {
        if let Some(w) = self.pool.lock().unwrap().work.pop_front() {
            return Some(w);
        }
        let deadline = Instant::now() + wait;
        loop {
            if self.is_stopped() {
                return None;
            }
            let remaining = deadline.checked_duration_since(Instant::now())?;
            let _ = self.req_tx.send(());
            if tokio::time::timeout(remaining, self.work_notify.notified())
                .await
                .is_err()
            {
                return None;
            }
            if let Some(w) = self.pool.lock().unwrap().work.pop_front() {
                return Some(w);
            }
        }
    }

    /// 用户连接进来：有空闲工作连接就立即配对，否则排队并请求新工作连接。
    fn submit_user(&self, user: PendingUser) -> Option<Paired> {
        let mut g = self.pool.lock().unwrap();
        g.reap(self.idle_timeout);
        match g.work.pop_front() {
            Some(w) => Some((user, w)),
            None => {
                g.users.push_back(user);
                None
            }
        }
    }

    /// 工作连接到来：有排队的用户就立即配对，否则进池备用并唤醒等待者。
    fn submit_work(&self, w: WorkItem) -> Option<Paired> {
        let paired = {
            let mut g = self.pool.lock().unwrap();
            g.reap(self.idle_timeout);
            match g.users.pop_front() {
                Some(u) => Some((u, w)),
                None => {
                    g.work.push_back(w);
                    None
                }
            }
        };
        if paired.is_none() {
            self.work_notify.notify_waiters();
        }
        paired
    }

    fn add_listener(&self, name: String, handle: AbortHandle) {
        self.listeners.lock().unwrap().insert(name, handle);
    }

    fn stop(&self) {
        self.stopped
            .store(true, std::sync::atomic::Ordering::Relaxed);
        for (_, h) in self.listeners.lock().unwrap().drain() {
            h.abort();
        }
        self.pool.lock().unwrap().work.clear();
        self.work_notify.notify_waiters();
    }
}

// ---------------------------------------------------------------------------
// 全局注册表
// ---------------------------------------------------------------------------

struct Registry {
    clients: Mutex<HashMap<String, Arc<ClientState>>>,
    /// TCP + UDP 共用一份端口占用表，避免同一个端口号被两种协议同时申领。
    ports: Mutex<HashSet<u16>>,
    /// HTTP / HTTPS 虚拟主机路由表（启动时若配置了 vhost 端口才挂上）。
    vhosts: Mutex<Option<Arc<VhostTable>>>,
    /// stcp / xtcp 的 visitor 接入表（始终可用，不需要额外端口配置）。
    visitors: Arc<VisitorTable>,
}

impl Registry {
    fn new() -> Self {
        Self {
            clients: Mutex::new(HashMap::new()),
            ports: Mutex::new(HashSet::new()),
            vhosts: Mutex::new(None),
            visitors: Arc::new(VisitorTable::default()),
        }
    }

    fn attach_vhosts(&self, table: Arc<VhostTable>) {
        *self.vhosts.lock().unwrap() = Some(table);
    }

    fn vhosts(&self) -> Option<Arc<VhostTable>> {
        self.vhosts.lock().unwrap().clone()
    }

    fn insert(&self, client: Arc<ClientState>) {
        self.clients.lock().unwrap().insert(client.run_id.clone(), client);
    }

    fn get(&self, run_id: &str) -> Option<Arc<ClientState>> {
        self.clients.lock().unwrap().get(run_id).cloned()
    }

    fn remove(&self, run_id: &str) -> Option<Arc<ClientState>> {
        let c = self.clients.lock().unwrap().remove(run_id);
        if let Some(c) = &c {
            c.stop();
            // 客户端的 http/https 域名要一并回收，否则域名会一直被占着
            if let Some(t) = self.vhosts() {
                t.unregister_client(c);
            }
            // stcp / xtcp 的代理名同理
            self.visitors.unregister_client(c);
        }
        c
    }

    /// 占用端口，返回 false 表示已被占用。
    fn reserve_port(&self, port: u16) -> bool {
        self.ports.lock().unwrap().insert(port)
    }

    fn release_port(&self, port: u16) {
        self.ports.lock().unwrap().remove(&port);
    }
}

/// 控制连接退出时自动清理该客户端的全部资源。
struct ClientGuard {
    registry: Arc<Registry>,
    run_id: String,
}

impl Drop for ClientGuard {
    fn drop(&mut self) {
        self.registry.remove(&self.run_id);
    }
}

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    if cli.print_example {
        println!("{}", ServerConfig::example_toml());
        return Ok(());
    }
    if let Some(path) = &cli.gen_config {
        ServerConfig::write_example(path)?;
        println!("已生成示例配置：{}", path.display());
        return Ok(());
    }

    let path = cli.config.clone().unwrap_or_else(|| default_config_path("server.toml"));
    if !path.exists() {
        anyhow::bail!(
            "配置文件不存在：{}\n可先执行：{} --gen-config {}",
            path.display(),
            std::env::args().next().unwrap_or_else(|| "rustunnel-server".into()),
            path.display()
        );
    }
    let mut cfg = ServerConfig::load(&path)
        .with_context(|| format!("读取配置 {} 失败", path.display()))?;
    if let Some(p) = &cli.protocol {
        cfg.protocol = p.parse::<Protocol>().map_err(anyhow::Error::msg)?;
    }
    if let Some(port) = cli.port {
        cfg.bind_port = Some(port);
    }
    if let Some(token) = &cli.token {
        cfg.token = token.clone();
    }
    if cfg.token.is_empty() {
        warn!("未配置 token：任何人都能连接本服务端，强烈建议设置");
    }

    let level = cli.log_level.clone().unwrap_or_else(|| cfg.log_level.clone());
    util::init_tracing(&level);

    if cfg.protocol != Protocol::FrpV2 {
        anyhow::bail!("当前版本服务端仅实现 frp-v2 协议（可在配置里设置 protocol = \"frp-v2\"）");
    }

    let cfg = Arc::new(cfg);
    let port = cfg.frp_bind_port();
    let addr = util::resolve_addr(&format!("{}:{}", cfg.bind_addr, port))
        .await
        .with_context(|| format!("解析监听地址 {}:{} 失败", cfg.bind_addr, port))?;
    let listener = TcpListener::bind(addr)
        .await
        .with_context(|| format!("监听 {addr} 失败（端口可能被占用）"))?;

    info!("rustunnel-server 已启动：frp v2 协议，监听 {addr}");
    info!("支持的代理类型：tcp / udp / http / https / stcp / xtcp（xtcp 走中继，不实现 UDP 打洞）");
    info!("token = {}（{}）",
        if cfg.token.is_empty() { "<空>" } else { "已设置" },
        if cfg.token.is_empty() { "不安全" } else { "已启用" }
    );

    let registry = Arc::new(Registry::new());

    // HTTP / HTTPS 虚拟主机端口（可选）
    if cfg.vhost_http_port.is_some() || cfg.vhost_https_port.is_some() {
        let table = Arc::new(VhostTable::default());
        registry.attach_vhosts(table.clone());
        for (port, is_https) in [
            (cfg.vhost_http_port, false),
            (cfg.vhost_https_port, true),
        ] {
            let Some(vport) = port else { continue };
            let addr = util::resolve_addr(&format!("{}:{}", cfg.bind_addr, vport))
                .await
                .with_context(|| format!("解析 vhost 地址 {}:{} 失败", cfg.bind_addr, vport))?;
            let listener = vhost::bind(addr).await?;
            tokio::spawn(vhost::run_http(listener, table.clone(), vport, is_https));
        }
    }

    let shutdown = util::shutdown_signal();
    tokio::pin!(shutdown);

    loop {
        tokio::select! {
            accepted = listener.accept() => {
                let (stream, peer) = accepted.context("accept 失败")?;
                let cfg = cfg.clone();
                let registry = registry.clone();
                tokio::spawn(async move {
                    if let Err(e) = handle_conn(stream, peer, cfg, registry).await {
                        warn!(%peer, "连接结束：{e:#}");
                    }
                });
            }
            _ = &mut shutdown => {
                info!("服务端已停止");
                break;
            }
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// 连接分发
// ---------------------------------------------------------------------------

/// yamux 帧头的第一个字节是协议版本号（固定 0）。
///
/// frp v2 的魔术字以 `F`(0x46) 开头，两者不会混淆，服务端因此可以自动探测。
const YAMUX_VERSION_BYTE: u8 = 0x00;

/// 探测首字节的超时时间。
const PROBE_TIMEOUT: Duration = Duration::from_secs(10);

async fn handle_conn(
    stream: TcpStream,
    peer: SocketAddr,
    cfg: Arc<ServerConfig>,
    registry: Arc<Registry>,
) -> Result<()> {
    // 第一层：TLS。靠首字节自动识别（0x17 = frp 自定义首字节，0x16 = 标准 TLS）。
    let stream = frp::tls::accept_server(stream, true, cfg.tls_force)
        .await
        .context("TLS 协商失败")?;

    // 第二层：yamux（可选）。自动探测，兼容 tcpMux=true / false 的客户端。
    if cfg.tcp_mux {
        let mut stream = stream;
        let mut first = [0u8; 1];
        let n = match tokio::time::timeout(
            PROBE_TIMEOUT,
            tokio::io::AsyncReadExt::read(&mut stream, &mut first),
        )
        .await
        {
            Ok(r) => r?,
            Err(_) => {
                debug!(%peer, "等待首字节超时，断开");
                return Ok(());
            }
        };
        if n == 0 {
            return Ok(());
        }
        if first[0] == YAMUX_VERSION_BYTE {
            // yamux 会话：每个 stream 都是一条独立的 frp 连接
            let mut acceptor = frp::mux::serve(Box::pin(PrefixedStream::new(
                vec![first[0]],
                stream,
            )));
            while let Some(s) = acceptor.accept().await {
                let cfg = cfg.clone();
                let registry = registry.clone();
                tokio::spawn(async move {
                    if let Err(e) = handle_frp_stream(s, cfg, registry).await {
                        debug!(%peer, "yamux stream 结束：{e:#}");
                    }
                });
            }
            return Ok(());
        }
        let stream: BoxStream = Box::pin(PrefixedStream::new(vec![first[0]], stream));
        return handle_frp_stream(stream, cfg, registry).await;
    }

    handle_frp_stream(stream, cfg, registry).await
}

/// 在一条流上完成 frp v2 握手并分发到控制连接 / 工作连接。
async fn handle_frp_stream(
    stream: BoxStream,
    cfg: Arc<ServerConfig>,
    registry: Arc<Registry>,
) -> Result<()> {
    let run_id = util::new_run_id();
    match conn::server_handshake(stream, &cfg.token, &run_id).await {
        Ok(ServerAccept::Control {
            conn,
            login,
            udp_binary,
        }) => handle_control(conn, login, run_id, udp_binary, cfg, registry).await,
        Ok(ServerAccept::Work { conn, msg }) => handle_work(conn, msg, registry).await,
        Ok(ServerAccept::Visitor { conn, msg }) => handle_visitor(conn, msg, registry).await,
        Err(e) => {
            debug!("握手失败：{e:#}");
            Err(e)
        }
    }
}

// ---------------------------------------------------------------------------
// 控制连接
// ---------------------------------------------------------------------------

async fn handle_control(
    mut conn: FrpConn,
    login: Login,
    run_id: String,
    udp_binary: bool,
    cfg: Arc<ServerConfig>,
    registry: Arc<Registry>,
) -> Result<()> {
    let client_id = if login.client_id.is_empty() {
        run_id.clone()
    } else {
        login.client_id.clone()
    };
    info!(%client_id, %run_id, os = %login.os, arch = %login.arch, "客户端登录成功");

    let (req_tx, mut req_rx) = mpsc::unbounded_channel::<()>();
    let idle_timeout = Duration::from_secs(cfg.work_conn_idle_timeout.max(5));
    let client = Arc::new(ClientState::new(
        run_id.clone(),
        client_id.clone(),
        login.user.clone(),
        req_tx,
        idle_timeout,
        udp_binary,
    ));
    registry.insert(client.clone());
    let _guard = ClientGuard {
        registry: registry.clone(),
        run_id: run_id.clone(),
    };

    let mut hb_ticker = tokio::time::interval(Duration::from_secs(5));
    let mut last_seen = Instant::now();

    loop {
        tokio::select! {
            msg = conn.recv_msg() => {
                let Some(msg) = msg? else { break };
                last_seen = Instant::now();
                match msg {
                    FrpMessage::NewProxy(m) => {
                        let name = m.proxy_name.clone();
                        let port = m.remote_port;
                        let resp = match register_proxy(&cfg, &registry, &client, &m).await {
                            Ok(remote_addr) => {
                                info!(proxy = %name, port, remote = %remote_addr, "代理注册成功");
                                NewProxyResp {
                                    proxy_name: name.clone(),
                                    remote_addr,
                                    ..Default::default()
                                }
                            }
                            Err(e) => {
                                warn!(proxy = %name, port, "代理注册失败：{e:#}");
                                NewProxyResp { proxy_name: name, error: e.to_string(), ..Default::default() }
                            }
                        };
                        conn.send_msg(&FrpMessage::NewProxyResp(resp)).await?;
                    }
                    FrpMessage::Ping(_) => {
                        conn.send_msg(&FrpMessage::Pong(Pong::default())).await?;
                    }
                    FrpMessage::CloseProxy(m) => {
                        info!(proxy = %m.proxy_name, "客户端关闭代理");
                        registry.visitors.remove(&m.proxy_name);
                        client.stop_proxy(&m.proxy_name);
                    }
                    // xtcp 真·P2P 需要 UDP 打洞（QUIC/KCP + NAT 类型探测），rustunnel 未实现。
                    // 这里明确回一条错误，让官方 frpc 的 xtcp visitor 立刻失败并走它自己的
                    // fallbackTo 逻辑，而不是一直挂在那里等超时。
                    FrpMessage::NatHoleVisitor(m) => {
                        debug!(proxy = %m.proxy_name, tx = %m.transaction_id, "收到 NatHoleVisitor，回错误");
                        conn.send_msg(&FrpMessage::NatHoleResp(NatHoleResp {
                            transaction_id: m.transaction_id,
                            error: "nat hole is not supported by rustunnel-server (use stcp instead)"
                                .to_string(),
                            ..Default::default()
                        }))
                        .await?;
                    }
                    FrpMessage::NatHoleClient(m) => {
                        debug!(proxy = %m.proxy_name, "收到 NatHoleClient，rustunnel 不支持打洞，忽略");
                    }
                    FrpMessage::NatHoleReport(m) => {
                        debug!(sid = %m.sid, success = m.success, "收到 NatHoleReport，忽略");
                    }
                    other => {
                        debug!("忽略消息：{}", other.name());
                    }
                }
            }
            Some(()) = req_rx.recv() => {
                // 有用户连接排队，向客户端索要一条工作连接
                conn.send_msg(&FrpMessage::ReqWorkConn).await?;
            }
            _ = hb_ticker.tick() => {
                if last_seen.elapsed() > Duration::from_secs(cfg.heartbeat_timeout) {
                    warn!(%client_id, "心跳超时 {}s，断开控制连接", cfg.heartbeat_timeout);
                    break;
                }
            }
        }
    }
    Ok(())
}

/// 按代理类型注册：tcp / udp 绑端口，http / https 注册虚拟主机域名。
///
/// 返回给客户端的 `remote_addr` 文案（frp 用它展示"暴露在哪"）。
async fn register_proxy(
    cfg: &Arc<ServerConfig>,
    registry: &Arc<Registry>,
    client: &Arc<ClientState>,
    m: &rustunnel_common::frp::msg::NewProxy,
) -> Result<String> {
    if m.proxy_name.is_empty() {
        anyhow::bail!("代理名为空");
    }
    match m.proxy_type.as_str() {
        "tcp" => register_tcp(cfg, registry, client, m).await,
        "udp" => register_udp(cfg, registry, client, m).await,
        "http" => register_vhost(cfg, registry, client, m, false).await,
        "https" => register_vhost(cfg, registry, client, m, true).await,
        "stcp" => register_visitor_proxy(registry, client, m, "stcp").await,
        "xtcp" => register_visitor_proxy(registry, client, m, "xtcp").await,
        other => anyhow::bail!(
            "暂不支持的代理类型：{other}（支持 tcp / udp / http / https / stcp / xtcp）"
        ),
    }
}

/// stcp / xtcp：**不需要公网端口**，只在 visitor 表里登记一条记录。
///
/// 之后 visitor 主动连进来时才会校验密钥并配对工作连接。
///
/// 说明：rustunnel 目前**不实现 xtcp 的 UDP 打洞**（真 P2P 需要 QUIC/KCP +
/// NAT 类型探测），`xtcp` 走与 `stcp` 完全相同的中继路径。
async fn register_visitor_proxy(
    registry: &Arc<Registry>,
    client: &Arc<ClientState>,
    m: &rustunnel_common::frp::msg::NewProxy,
    kind: &str,
) -> Result<String> {
    if m.sk.is_empty() {
        anyhow::bail!("{kind} 代理必须配置 secret_key（frpc 里叫 secretKey）");
    }
    registry
        .visitors
        .register(VisitorEntry {
            proxy_name: m.proxy_name.clone(),
            secret_key: m.sk.clone(),
            allow_users: m.allow_users.clone(),
            provider_user: client.user.clone(),
            client: client.clone(),
            proxy_type: kind.to_string(),
        })
        .map_err(|e| anyhow!(e))?;
    // 与官方 frps 一致：visitor 类代理没有公网地址，remote_addr 留空
    Ok(String::new())
}

/// TCP：绑定公网端口，用户连进来时向客户端要工作连接配对。
async fn register_tcp(
    cfg: &Arc<ServerConfig>,
    registry: &Arc<Registry>,
    client: &Arc<ClientState>,
    m: &rustunnel_common::frp::msg::NewProxy,
) -> Result<String> {
    if m.remote_port == 0 {
        anyhow::bail!("tcp 代理必须指定 remote_port");
    }
    if !registry.reserve_port(m.remote_port) {
        anyhow::bail!("端口 {} 已被占用", m.remote_port);
    }

    let addr = util::resolve_addr(&format!("{}:{}", cfg.bind_addr, m.remote_port))
        .await
        .with_context(|| format!("解析 {}:{} 失败", cfg.bind_addr, m.remote_port))?;
    let listener = match TcpListener::bind(addr).await {
        Ok(l) => l,
        Err(e) => {
            registry.release_port(m.remote_port);
            return Err(e).with_context(|| format!("监听 {addr} 失败"));
        }
    };

    let proxy_name = m.proxy_name.clone();
    let remote_port = m.remote_port;
    let client2 = client.clone();
    let handle = tokio::spawn(async move {
        proxy_accept_loop(listener, proxy_name, remote_port, client2).await;
    });
    client.add_listener(m.proxy_name.clone(), handle.abort_handle());
    Ok(format!("{}:{}", cfg.bind_addr, m.remote_port))
}

/// UDP：绑定 UDP 端口 + 维持一条专用工作连接。
async fn register_udp(
    cfg: &Arc<ServerConfig>,
    registry: &Arc<Registry>,
    client: &Arc<ClientState>,
    m: &rustunnel_common::frp::msg::NewProxy,
) -> Result<String> {
    if m.remote_port == 0 {
        anyhow::bail!("udp 代理必须指定 remote_port");
    }
    if !registry.reserve_port(m.remote_port) {
        anyhow::bail!("端口 {} 已被占用", m.remote_port);
    }
    let udp = match udp_proxy::bind_udp(&cfg.bind_addr, m.remote_port).await {
        Ok(u) => u,
        Err(e) => {
            registry.release_port(m.remote_port);
            return Err(e);
        }
    };
    let handle = udp_proxy::spawn(Arc::new(udp), m.proxy_name.clone(), client.clone());
    client.add_listener(m.proxy_name.clone(), handle.abort_handle());
    Ok(format!("{}:{}/udp", cfg.bind_addr, m.remote_port))
}

/// HTTP / HTTPS：把域名注册进虚拟主机路由表（不需要额外端口）。
async fn register_vhost(
    cfg: &Arc<ServerConfig>,
    registry: &Arc<Registry>,
    client: &Arc<ClientState>,
    m: &rustunnel_common::frp::msg::NewProxy,
    is_https: bool,
) -> Result<String> {
    let kind = if is_https { "https" } else { "http" };
    let vhost_port = if is_https {
        cfg.vhost_https_port
    } else {
        cfg.vhost_http_port
    };
    let Some(vhost_port) = vhost_port else {
        anyhow::bail!(
            "服务端未配置 vhost_{}_port，无法注册 {kind} 代理",
            if is_https { "https" } else { "http" }
        );
    };
    let table = registry
        .vhosts()
        .ok_or_else(|| anyhow!("虚拟主机路由表未初始化"))?;

    let mut domains: Vec<String> = m
        .custom_domains
        .iter()
        .map(|d| d.trim().to_ascii_lowercase())
        .filter(|d| !d.is_empty())
        .collect();
    if !m.subdomain.is_empty() {
        if cfg.subdomain_host.is_empty() {
            anyhow::bail!("客户端用了 subdomain，但服务端未配置 subdomain_host");
        }
        domains.push(format!(
            "{}.{}",
            m.subdomain.trim().to_ascii_lowercase(),
            cfg.subdomain_host.trim().to_ascii_lowercase()
        ));
    }
    if domains.is_empty() {
        anyhow::bail!("{kind} 代理必须配置 custom_domains 或 subdomain");
    }

    let mut locations: Vec<String> = if m.locations.is_empty() {
        vec!["/".to_string()]
    } else {
        m.locations.clone()
    };
    // 长前缀优先匹配（frp 的路由优先级规则）
    locations.sort_by_key(|a| std::cmp::Reverse(a.len()));
    for domain in &domains {
        table.register(Arc::new(VhostRoute {
            proxy_name: m.proxy_name.clone(),
            client: client.clone(),
            domain: domain.clone(),
            locations: locations.clone(),
            http_user: m.http_user.clone(),
            http_pwd: m.http_pwd.clone(),
            route_by_http_user: m.route_by_http_user.clone(),
            rewrite_host: m.host_header_rewrite.clone(),
            req_headers: m.headers.clone(),
            resp_headers: m.response_headers.clone(),
            is_https,
        }))?;
    }
    Ok(domains
        .iter()
        .map(|d| format!("{d}:{vhost_port}"))
        .collect::<Vec<_>>()
        .join(","))
}

impl ClientState {
    fn stop_proxy(&self, name: &str) {
        if let Some(h) = self.listeners.lock().unwrap().remove(name) {
            h.abort();
        }
    }
}

async fn proxy_accept_loop(
    listener: TcpListener,
    proxy_name: String,
    remote_port: u16,
    client: Arc<ClientState>,
) {
    loop {
        match listener.accept().await {
            Ok((stream, peer)) => {
                let _ = stream.set_nodelay(true);
                debug!(proxy = %proxy_name, %peer, "收到用户连接");
                let user = PendingUser {
                    proxy: proxy_name.clone(),
                    remote_port,
                    stream: Box::pin(stream),
                    peer,
                    at: Instant::now(),
                };
                match client.submit_user(user) {
                    Some((user, work)) => spawn_bridge(user, work),
                    None => {
                        // 池里没有空闲工作连接，通知控制连接去要一条
                        let _ = client.req_tx.send(());
                    }
                }
            }
            Err(e) => {
                error!(proxy = %proxy_name, "监听失败：{e}");
                break;
            }
        }
    }
}

// ---------------------------------------------------------------------------
// 工作连接
// ---------------------------------------------------------------------------

async fn handle_work(mut conn: FrpConn, msg: NewWorkConn, registry: Arc<Registry>) -> Result<()> {
    let client = registry
        .get(&msg.run_id)
        .ok_or_else(|| anyhow!("找不到 run_id={} 对应的客户端", msg.run_id))?;
    // 工作连接继承控制连接协商出的 UDP 报文编码
    conn.set_udp_codec(client.udp_codec_is_binary());
    let work = WorkItem {
        conn,
        at: Instant::now(),
    };
    match client.submit_work(work) {
        Some((user, work)) => {
            debug!(proxy = %user.proxy, "工作连接与排队用户配对");
            spawn_bridge(user, work);
        }
        None => debug!(client = %client.client_id, "工作连接进入空闲池"),
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// visitor 连接（stcp / xtcp 的接入方）
// ---------------------------------------------------------------------------

/// 处理一条 visitor 连接：校验 -> 回 Resp -> 与 provider 的工作连接配对。
///
/// 配对成功后这条 visitor 连接就变成"用户连接"，转发逻辑与 tcp 完全一样。
async fn handle_visitor(
    mut conn: FrpConn,
    msg: NewVisitorConn,
    registry: Arc<Registry>,
) -> Result<()> {
    let proxy_name = msg.proxy_name.clone();

    /// 回一条错误响应并结束（官方 frpc 会把 error 原样打到日志上）。
    async fn reject(conn: &mut FrpConn, proxy_name: &str, err: String) -> Result<()> {
        let _ = conn
            .send_msg(&FrpMessage::NewVisitorConnResp(NewVisitorConnResp {
                proxy_name: proxy_name.to_string(),
                error: err.clone(),
            }))
            .await;
        // 必须优雅关闭：直接 drop 会变成 RST，对端读不到 error，只会看到 connection reset
        let _ = conn.shutdown().await;
        anyhow::bail!("visitor 接入被拒绝：{err}");
    }

    // 1) run_id 必须能对上一条已登录的控制会话（对应 frps 的 admitVisitorByRunID）
    if !msg.run_id.is_empty() && registry.get(&msg.run_id).is_none() {
        return reject(
            &mut conn,
            &proxy_name,
            format!("no client control found for run id [{}]", msg.run_id),
        )
        .await;
    }

    // 2) 代理必须已注册
    let Some(entry) = registry.visitors.get(&proxy_name) else {
        return reject(
            &mut conn,
            &proxy_name,
            format!("custom listener for [{proxy_name}] doesn't exist"),
        )
        .await;
    };

    // 3) 密钥签名校验：hex(md5(secret_key + timestamp))
    if !entry.check_sign(&msg.sign_key, msg.timestamp) {
        warn!(proxy = %proxy_name, "visitor 密钥校验失败");
        return reject(
            &mut conn,
            &proxy_name,
            format!("visitor connection of [{proxy_name}] auth failed"),
        )
        .await;
    }

    // 4) 访客用户白名单
    //
    // 与官方 frps 一致：比对的**不是** visitor 的 name，而是发起这条 visitor 连接的那个
    // frpc 在 Login 里声明的顶层 `user`（对应 frpc.toml 的 `user = "alice"`）。
    let visitor_user = registry
        .get(&msg.run_id)
        .map(|c| c.user.clone())
        .unwrap_or_default();
    if !entry.check_user(&visitor_user) {
        warn!(proxy = %proxy_name, user = %visitor_user, "visitor 用户不在 allow_users 白名单内");
        return reject(
            &mut conn,
            &proxy_name,
            format!("visitor connection of [{proxy_name}] user [{visitor_user}] not allowed"),
        )
        .await;
    }

    // 5) 先回成功（官方 frps 也是先 PutConn 再回 ok，之后才去池里取工作连接）
    conn.send_msg(&FrpMessage::NewVisitorConnResp(NewVisitorConnResp {
        proxy_name: proxy_name.clone(),
        error: String::new(),
    }))
    .await
    .context("发送 NewVisitorConnResp 失败")?;

    // 6) 向 provider 要一条工作连接并配对
    let Some(work) = entry
        .client
        .acquire_work_conn(Duration::from_secs(10))
        .await
    else {
        anyhow::bail!("provider [{proxy_name}] 没有可用的工作连接，visitor 连接关闭");
    };

    let (stream, leftover) = conn.into_stream();
    let user = PendingUser {
        proxy: proxy_name.clone(),
        // visitor 没有公网端口概念
        remote_port: 0,
        stream: Box::pin(PrefixedStream::new(leftover, stream)),
        peer: SocketAddr::from(([0, 0, 0, 0], 0)),
        at: Instant::now(),
    };
    info!(proxy = %proxy_name, kind = %entry.proxy_type, "visitor 接入成功，开始中继");
    spawn_bridge(user, work);
    Ok(())
}

fn spawn_bridge(user: PendingUser, work: WorkItem) {
    tokio::spawn(async move {
        if let Err(e) = bridge(user, work).await {
            debug!("转发结束：{e:#}");
        }
    });
}

/// 通知客户端这条工作连接属于哪个代理，然后开始双向转发原始字节。
async fn bridge(user: PendingUser, work: WorkItem) -> Result<()> {
    let PendingUser {
        proxy,
        remote_port,
        stream: mut user_stream,
        peer,
        ..
    } = user;
    let mut work_conn = work.conn;

    work_conn
        .send_msg(&FrpMessage::StartWorkConn(StartWorkConn {
            proxy_name: proxy.clone(),
            src_addr: peer.ip().to_string(),
            dst_addr: String::new(),
            src_port: peer.port(),
            dst_port: remote_port,
            ..Default::default()
        }))
        .await
        .context("发送 StartWorkConn 失败")?;

    let (mut work_stream, leftover) = work_conn.into_stream();
    if !leftover.is_empty() {
        use tokio::io::AsyncWriteExt;
        user_stream.write_all(&leftover).await?;
    }

    match util::relay_between(&mut user_stream, &mut work_stream).await {
        Ok((up, down)) => debug!(proxy = %proxy, "转发结束：上行 {up}B / 下行 {down}B"),
        Err(e) => debug!(proxy = %proxy, "转发中断：{e}"),
    }
    Ok(())
}
