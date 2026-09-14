//! `rustunnel-server`：frp v2 兼容的服务端（等价于原版 frps）。
//!
//! 与原版一致，控制连接与工作连接复用**同一个端口**，靠首帧消息类型区分：
//! `Login` 走控制连接流程，`NewWorkConn` 走工作连接流程。

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
        msg::{FrpMessage, Login, NewProxyResp, NewWorkConn, Pong, StartWorkConn},
        stream::{BoxStream, PrefixedStream},
    },
    util,
};
use tokio::{net::TcpListener, net::TcpStream, sync::mpsc, task::AbortHandle};
use tracing::{debug, error, info, warn};

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
struct PendingUser {
    proxy: String,
    remote_port: u16,
    stream: TcpStream,
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
    /// 代理监听器用它通知控制连接"需要一条工作连接"。
    req_tx: mpsc::UnboundedSender<()>,
    pool: Mutex<PoolState>,
    listeners: Mutex<HashMap<String, AbortHandle>>,
    idle_timeout: Duration,
}

impl ClientState {
    fn new(
        run_id: String,
        client_id: String,
        req_tx: mpsc::UnboundedSender<()>,
        idle_timeout: Duration,
    ) -> Self {
        Self {
            run_id,
            client_id,
            req_tx,
            pool: Mutex::new(PoolState::default()),
            listeners: Mutex::new(HashMap::new()),
            idle_timeout,
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

    /// 工作连接到来：有排队的用户就立即配对，否则进池备用。
    fn submit_work(&self, w: WorkItem) -> Option<Paired> {
        let mut g = self.pool.lock().unwrap();
        g.reap(self.idle_timeout);
        match g.users.pop_front() {
            Some(u) => Some((u, w)),
            None => {
                g.work.push_back(w);
                None
            }
        }
    }

    fn add_listener(&self, name: String, handle: AbortHandle) {
        self.listeners.lock().unwrap().insert(name, handle);
    }

    fn stop(&self) {
        for (_, h) in self.listeners.lock().unwrap().drain() {
            h.abort();
        }
        self.pool.lock().unwrap().work.clear();
    }
}

// ---------------------------------------------------------------------------
// 全局注册表
// ---------------------------------------------------------------------------

struct Registry {
    clients: Mutex<HashMap<String, Arc<ClientState>>>,
    ports: Mutex<HashSet<u16>>,
}

impl Registry {
    fn new() -> Self {
        Self {
            clients: Mutex::new(HashMap::new()),
            ports: Mutex::new(HashSet::new()),
        }
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
    info!("token = {}（{}）",
        if cfg.token.is_empty() { "<空>" } else { "已设置" },
        if cfg.token.is_empty() { "不安全" } else { "已启用" }
    );

    let registry = Arc::new(Registry::new());
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
        Ok(ServerAccept::Control { conn, login }) => {
            handle_control(conn, login, run_id, cfg, registry).await
        }
        Ok(ServerAccept::Work { conn, msg }) => handle_work(conn, msg, registry).await,
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
        req_tx,
        idle_timeout,
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
                            Ok(()) => {
                                info!(proxy = %name, port, "代理注册成功");
                                NewProxyResp {
                                    proxy_name: name.clone(),
                                    remote_addr: format!("{}:{}", cfg.bind_addr, port),
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
                        client.stop_proxy(&m.proxy_name);
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

/// 绑定 remote_port 并启动该代理的 accept 循环。
async fn register_proxy(
    cfg: &Arc<ServerConfig>,
    registry: &Arc<Registry>,
    client: &Arc<ClientState>,
    m: &rustunnel_common::frp::msg::NewProxy,
) -> Result<()> {
    if m.proxy_name.is_empty() {
        anyhow::bail!("代理名为空");
    }
    if m.proxy_type != "tcp" {
        anyhow::bail!("暂不支持的代理类型：{}（MVP 仅支持 tcp）", m.proxy_type);
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
    Ok(())
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
                    stream,
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

async fn handle_work(conn: FrpConn, msg: NewWorkConn, registry: Arc<Registry>) -> Result<()> {
    let client = registry
        .get(&msg.run_id)
        .ok_or_else(|| anyhow!("找不到 run_id={} 对应的客户端", msg.run_id))?;
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
        stream: mut user,
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
        user.write_all(&leftover).await?;
    }

    match tokio::io::copy_bidirectional(&mut user, &mut work_stream).await {
        Ok((up, down)) => debug!(proxy = %proxy, "转发结束：上行 {up}B / 下行 {down}B"),
        Err(e) => debug!(proxy = %proxy, "转发中断：{e}"),
    }
    Ok(())
}
