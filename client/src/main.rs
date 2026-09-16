//! `rustunnel-client`：frp v2 兼容的客户端（等价于原版 frpc）。
//!
//! 支持的代理类型：`tcp` / `udp` / `http` / `https` / `stcp` / `xtcp`。
//! 其中 http / https 在客户端侧与 tcp 无差别（服务端已经把 HTTP 语义处理完了，
//! 客户端只负责把裸字节转给内网服务）；stcp / xtcp 还额外支持 `[[visitors]]`
//! （作为接入方）。

mod health;
mod p2p;
mod plugin;
mod udp_proxy;
mod visitor;

use std::{collections::HashMap, sync::Arc, time::Duration};

use anyhow::{anyhow, bail, Context, Result};
use clap::Parser;
use rustunnel_common::{
    config::{default_config_path, is_quic, ClientConfig, Protocol, ProxyConfig},
    frp::{
        self,
        conn::{self, FrpConn},
        msg::{FrpMessage, NewProxy, Ping},
        mux::MuxSession,
        stream::BoxStream,
        tls,
    },
    throttle, util,
};
use tokio::io::AsyncWriteExt;
use tokio::{net::TcpStream, time::interval};
use tracing::{debug, error, info, warn};

#[derive(Parser, Debug)]
#[command(
    name = "rustunnel-client",
    version,
    about = "rustunnel 客户端（兼容原版 frp）"
)]
struct Cli {
    /// 配置文件路径（默认 ./client.toml）
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

    /// 服务端地址（覆盖配置）
    #[arg(long, value_name = "ADDR")]
    server_addr: Option<String>,

    /// 服务端端口（覆盖配置）
    #[arg(short, long, value_name = "PORT")]
    server_port: Option<u16>,

    /// 认证 token（覆盖配置）
    #[arg(short, long, value_name = "TOKEN")]
    token: Option<String>,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    if cli.print_example {
        println!("{}", ClientConfig::example_toml());
        return Ok(());
    }
    if let Some(path) = &cli.gen_config {
        ClientConfig::write_example(path)?;
        println!("已生成示例配置：{}", path.display());
        return Ok(());
    }

    let path = cli
        .config
        .clone()
        .unwrap_or_else(|| default_config_path("client.toml"));
    if !path.exists() {
        bail!(
            "配置文件不存在：{}\n可先执行：{} --gen-config {}",
            path.display(),
            std::env::args()
                .next()
                .unwrap_or_else(|| "rustunnel-client".into()),
            path.display()
        );
    }
    let mut cfg =
        ClientConfig::load(&path).with_context(|| format!("读取配置 {} 失败", path.display()))?;
    if let Some(p) = &cli.protocol {
        cfg.protocol = p.parse::<Protocol>().map_err(anyhow::Error::msg)?;
    }
    if let Some(a) = &cli.server_addr {
        cfg.server_addr = a.clone();
    }
    if let Some(p) = cli.server_port {
        cfg.server_port = p;
    }
    if let Some(t) = &cli.token {
        cfg.token = t.clone();
    }

    let level = cli
        .log_level
        .clone()
        .unwrap_or_else(|| cfg.log_level.clone());
    util::init_tracing(&level);

    if cfg.protocol != Protocol::FrpV2 {
        bail!("当前版本客户端仅实现 frp-v2 协议（可在配置里设置 protocol = \"frp-v2\"）");
    }
    if cfg.proxies.is_empty() && cfg.visitors.is_empty() {
        warn!("配置里既没有 [[proxies]] 也没有 [[visitors]]，客户端不会做任何转发");
    }

    let cfg = Arc::new(cfg);
    // 健康检查是进程级的：跨重连持续探测，状态不随会话重建而丢失
    let health = health::Monitor::start(&cfg);

    info!(
        "rustunnel-client 启动：连接 {}:{}，共 {} 个代理 / {} 个访客",
        cfg.server_addr,
        cfg.server_port,
        cfg.proxies.len(),
        cfg.visitors.len()
    );

    // visitor 是**进程级**的：本地监听只绑一次，跨重连复用。
    // 通过 watch 通道拿到"当前有效的控制会话"，避免重连后拿到已死的连接。
    let (session_tx, session_rx) = tokio::sync::watch::channel::<Option<Arc<ClientSession>>>(None);
    for v in &cfg.visitors {
        let name = v.name.clone();
        let rx = session_rx.clone();
        let v = v.clone();
        let user = Arc::new(cfg.user.clone());
        tokio::spawn(async move {
            if let Err(e) = visitor::run(rx, v, user).await {
                error!("visitor [{name}] 退出：{e:#}");
            }
        });
    }

    let shutdown = util::shutdown_signal();
    tokio::pin!(shutdown);

    loop {
        let fut = run_session(cfg.clone(), session_tx.clone(), health.clone());
        tokio::select! {
            r = fut => {
                match r {
                    Ok(()) => info!("与控制服务端的会话结束"),
                    Err(e) => error!("会话出错：{e:#}"),
                }
            }
            _ = &mut shutdown => {
                info!("客户端已停止");
                return Ok(());
            }
        }
        // 会话已失效，visitor 在拿到新会话之前不要再用旧连接
        let _ = session_tx.send(None);

        info!("{} 秒后重连…", cfg.reconnect_interval);
        tokio::select! {
            _ = tokio::time::sleep(Duration::from_secs(cfg.reconnect_interval)) => {}
            _ = &mut shutdown => {
                info!("客户端已停止");
                return Ok(());
            }
        }
    }
}

/// 当前有效的控制会话。visitor 需要用它开新连接、拿 run_id。
pub(crate) struct ClientSession {
    pub(crate) link: Arc<ServerLink>,
    pub(crate) run_id: Arc<String>,
    /// xtcp 打洞上下文；未配置 `p2p_port` 时为 None（xtcp 只走中继）。
    pub(crate) p2p: Option<Arc<p2p::P2PRoute>>,
}

/// 与服务端之间的连接工厂。
///
/// 负责按配置依次套上 TLS 与 yamux：
/// - `tls_enable` 打开时先发 frp 自定义首字节再握手；
/// - `tcp_mux` 打开时只在会话开始时建一条 TCP，后续所有连接都开 yamux stream。
struct ServerLink {
    cfg: Arc<ClientConfig>,
    mux: Option<MuxSession>,
    /// QUIC 传输：一条 QUIC 连接上的每条双向流就是一条 frp 连接。
    ///
    /// `Endpoint` 必须一起存着 —— 它被 drop 时上面的连接会立刻断开，
    /// 只留 `Connection` 是不够的。
    quic: Option<(quinn::Endpoint, quinn::Connection)>,
    /// 本次会话协商出的 UDP 报文编码（true = 二进制），工作连接要跟着用。
    udp_binary: std::sync::atomic::AtomicBool,
}

impl ServerLink {
    async fn open(cfg: Arc<ClientConfig>) -> Result<Self> {
        // QUIC 自带加密与多路复用，所以 tls / tcp_mux 这两层都跳过
        let quic = if is_quic(&cfg.transport_protocol) {
            let addr = quic_server_addr(&cfg).await?;
            let (endpoint, conn) = frp::quic::connect(&addr, None).await?;
            info!(%addr, "QUIC 传输已建立");
            Some((endpoint, conn))
        } else {
            None
        };

        let mux = if quic.is_none() && cfg.tcp_mux {
            let stream = raw_connect(&cfg).await?;
            Some(MuxSession::new(stream))
        } else {
            None
        };
        Ok(Self {
            cfg,
            mux,
            quic,
            udp_binary: std::sync::atomic::AtomicBool::new(false),
        })
    }

    /// 取得一条到服务端的流：QUIC 双向流、yamux stream，或一条新的 TCP（+TLS）。
    async fn connect(&self) -> Result<BoxStream> {
        if let Some((_ep, conn)) = &self.quic {
            let (send, recv) = conn.open_bi().await.context("在 QUIC 连接上开双向流失败")?;
            return Ok(Box::pin(frp::quic::QuicStream::new(send, recv)));
        }
        match &self.mux {
            Some(m) => m.open_stream().await,
            None => raw_connect(&self.cfg).await,
        }
    }
}

/// 服务端 QUIC 地址（与 TCP 用同一个端口号，只是走 UDP）。
async fn quic_server_addr(cfg: &ClientConfig) -> Result<std::net::SocketAddr> {
    let s = format!("{}:{}", cfg.server_addr, cfg.server_port);
    util::resolve_addr(&s)
        .await
        .with_context(|| format!("解析服务端 QUIC 地址 {s} 失败"))
}

/// 建立一条到服务端的底层连接（TCP，按需 TLS）。
async fn raw_connect(cfg: &ClientConfig) -> Result<BoxStream> {
    let server = format!("{}:{}", cfg.server_addr, cfg.server_port);
    let addr = util::resolve_addr(&server)
        .await
        .with_context(|| format!("解析服务端地址 {server} 失败"))?;
    let stream = TcpStream::connect(addr)
        .await
        .with_context(|| format!("连接 {addr} 失败"))?;
    stream.set_nodelay(true).ok();

    let name = if cfg.tls_server_name.is_empty() {
        &cfg.server_addr
    } else {
        &cfg.tls_server_name
    };
    tls::connect_client(stream, cfg.tls_enable, name, !cfg.tls_custom_first_byte).await
}

/// 建立一次完整的控制连接会话，直到连接断开或出错。
/// 把一条客户端代理配置翻译成线协议上的 `NewProxy`。
///
/// 单独抽成函数是为了**能测**：这段映射以前内联在注册流程里，
/// 于是新增配置字段（`group` / `group_key`）时忘了搬进消息体，
/// 服务端单测测的是注册表、客户端也没有对应用例，最后是端到端冒烟才把它翻出来。
fn build_new_proxy(user: &str, p: &ProxyConfig) -> NewProxy {
    let wire_name = util::add_user_prefix(user, &p.name);
    match p.proxy_type.as_str() {
        "http" | "https" => NewProxy {
            proxy_name: wire_name,
            proxy_type: p.proxy_type.clone(),
            custom_domains: p.custom_domains.clone(),
            subdomain: p.subdomain.clone(),
            locations: p.locations.clone(),
            http_user: p.http_user.clone(),
            http_pwd: p.http_pwd.clone(),
            host_header_rewrite: p.host_header_rewrite.clone(),
            group: p.group.clone(),
            group_key: p.group_key.clone(),
            ..Default::default()
        },
        // stcp / xtcp：不带 remote_port，靠共享密钥 + visitor 接入
        "stcp" | "xtcp" => NewProxy {
            proxy_name: wire_name,
            proxy_type: p.proxy_type.clone(),
            sk: p.secret_key.clone(),
            allow_users: p.allow_users.clone(),
            ..Default::default()
        },
        // tcp / udp：remote_port + 负载均衡分组
        _ => NewProxy {
            proxy_name: wire_name,
            proxy_type: p.proxy_type.clone(),
            remote_port: p.remote_port,
            group: p.group.clone(),
            group_key: p.group_key.clone(),
            ..Default::default()
        },
    }
}

async fn run_session(
    cfg: Arc<ClientConfig>,
    session_tx: tokio::sync::watch::Sender<Option<Arc<ClientSession>>>,
    health: Arc<health::Monitor>,
) -> Result<()> {
    let server = format!("{}:{}", cfg.server_addr, cfg.server_port);
    let link = Arc::new(ServerLink::open(cfg.clone()).await?);
    info!(%server, "已连接到服务端，开始握手");

    let stream = link.connect().await?;
    let (mut conn, run_id, udp_binary) = conn::client_handshake(
        stream,
        &cfg.token,
        &cfg.client_id,
        &cfg.user,
        cfg.pool_count,
    )
    .await?;
    link.udp_binary
        .store(udp_binary, std::sync::atomic::Ordering::Relaxed);
    if udp_binary {
        debug!("服务端选择了二进制 UDP 报文编码");
    }
    info!(%run_id, "登录成功（控制通道已启用 AES-256-GCM）");

    let run_id = Arc::new(run_id);

    // xtcp 真 P2P：只有配置了 p2p_port 才建立打洞中枢
    let (p2p_route, mut punch_rx) = match p2p::setup(&cfg).await {
        Some((route, rx)) => (Some(route), Some(rx)),
        None => (None, None),
    };
    if p2p_route.is_none() && cfg.proxies.iter().any(|p| p.proxy_type == "xtcp") {
        warn!("有 xtcp 代理但未配置 p2p_port，xtcp 将退化为中继（与 stcp 相同）");
    }

    // 把当前会话公布出去，visitor 从这里取连接与 run_id
    let _ = session_tx.send(Some(Arc::new(ClientSession {
        link: link.clone(),
        run_id: run_id.clone(),
        p2p: p2p_route.clone(),
    })));

    // 注册代理
    //
    // 注意：官方 frps 会在 NewProxyResp 之间插入 ReqWorkConn（填充工作连接池），
    // 所以不能发送一个就死等一个响应，必须边读边按代理名匹配。
    // 官方 frp 的线协议名带顶层 `user` 前缀（`naming.AddUserPrefix`），
    // 本地映射表与发出的 NewProxy 都用这个名字，服务端回包也是它。
    let proxies: Arc<HashMap<String, ProxyConfig>> = Arc::new(
        cfg.proxies
            .iter()
            .map(|p| (util::add_user_prefix(&cfg.user, &p.name), p.clone()))
            .collect(),
    );

    for p in &cfg.proxies {
        let msg = build_new_proxy(&cfg.user, p);
        conn.send_msg(&FrpMessage::NewProxy(msg)).await?;
    }

    let mut pending: std::collections::HashSet<String> = cfg
        .proxies
        .iter()
        .map(|p| util::add_user_prefix(&cfg.user, &p.name))
        .collect();
    while !pending.is_empty() {
        let msg = tokio::time::timeout(Duration::from_secs(15), conn.recv_msg())
            .await
            .context("等待 NewProxyResp 超时")??;
        match msg {
            Some(FrpMessage::NewProxyResp(r)) => {
                pending.remove(&r.proxy_name);
                let raw = util::strip_user_prefix(&cfg.user, &r.proxy_name);
                let local = proxies
                    .get(&r.proxy_name)
                    .map(|p| p.local_addr.clone())
                    .unwrap_or_else(|| "?".to_string());
                if r.error.is_empty() {
                    info!(proxy = %raw, remote = %r.remote_addr, local, "代理注册成功");
                } else {
                    error!(proxy = %raw, "代理注册失败：{}", r.error);
                }
            }
            Some(FrpMessage::ReqWorkConn) => {
                spawn_work_conn(
                    link.clone(),
                    run_id.clone(),
                    proxies.clone(),
                    health.clone(),
                );
            }
            Some(other) => debug!("注册期间收到 {}，忽略", other.name()),
            None => bail!("服务端在代理注册完成前断开"),
        }
    }

    // 预建工作连接（与官方 frpc 的 pool_count 行为一致）
    for _ in 0..cfg.pool_count.max(0) {
        spawn_work_conn(
            link.clone(),
            run_id.clone(),
            proxies.clone(),
            health.clone(),
        );
    }

    let mut ticker = interval(Duration::from_secs(cfg.heartbeat_interval.max(1)));
    ticker.tick().await; // 丢掉立即触发的第一次
    let mut last_pong = std::time::Instant::now();

    loop {
        tokio::select! {
            msg = conn.recv_msg() => {
                let Some(msg) = msg? else {
                    info!("服务端关闭了控制连接");
                    // 控制连接没了：还在等的打洞请求必须立刻失败，
                    // 否则 visitor 会干等到超时才回退中继
                    if let Some(route) = &p2p_route {
                        route.bus.clear();
                    }
                    break;
                };
                match msg {
                    FrpMessage::ReqWorkConn => {
                        debug!("收到 ReqWorkConn，建立工作连接");
                        spawn_work_conn(
                    link.clone(),
                    run_id.clone(),
                    proxies.clone(),
                    health.clone(),
                );
                    }
                    FrpMessage::Pong(p) => {
                        if !p.error.is_empty() {
                            warn!("服务端 Pong 返回错误：{}", p.error);
                        }
                        last_pong = std::time::Instant::now();
                    }
                    FrpMessage::NewProxyResp(_) => {}
                    // xtcp：服务端通知本端（provider）去打洞
                    FrpMessage::NatHoleClient(m) => {
                        debug!(proxy = %m.proxy_name, sid = %m.sid, "收到打洞通知");
                        match proxies.get(&m.proxy_name) {
                            Some(proxy) => {
                                let cfg = cfg.clone();
                                let proxy = proxy.clone();
                                tokio::spawn(async move {
                                    if let Err(e) = p2p::serve_as_provider(cfg, proxy, m).await {
                                        debug!("xtcp 打洞未成功（访客会回退中继）：{e:#}");
                                    }
                                });
                            }
                            None => warn!(proxy = %m.proxy_name, "收到未知代理的打洞通知，忽略"),
                        }
                    }
                    // xtcp：服务端对 visitor 打洞请求的响应，转交给等待者
                    FrpMessage::NatHoleResp(r) => match &p2p_route {
                        Some(route) => route.bus.deliver(r),
                        None => debug!("未启用 P2P，忽略 NatHoleResp"),
                    },
                    other => debug!("忽略消息：{}", other.name()),
                }
            }
            Some(req) = async {
                match punch_rx.as_mut() {
                    Some(rx) => rx.recv().await,
                    // 没开 P2P 时这个分支永不就绪，否则会空转烧 CPU
                    None => std::future::pending().await,
                }
            } => {
                conn.send_msg(&FrpMessage::NatHoleVisitor(req)).await?;
            }
            _ = ticker.tick() => {
                conn.send_msg(&FrpMessage::Ping(Ping {
                    timestamp: util::now_unix_secs() as i64,
                    ..Default::default()
                }))
                .await?;
                if last_pong.elapsed() > Duration::from_secs(cfg.heartbeat_timeout) {
                    bail!("{} 秒未收到 Pong，判定连接已死", cfg.heartbeat_timeout);
                }
            }
        }
    }
    Ok(())
}

fn spawn_work_conn(
    link: Arc<ServerLink>,
    run_id: Arc<String>,
    proxies: Arc<HashMap<String, ProxyConfig>>,
    health: Arc<health::Monitor>,
) {
    tokio::spawn(async move {
        if let Err(e) = work_conn_flow(link, run_id, proxies, health).await {
            debug!("工作连接结束：{e:#}");
        }
    });
}

/// 建立一条工作连接：取流 -> NewWorkConn -> 等 StartWorkConn -> 连内网服务 -> 双向转发。
async fn work_conn_flow(
    link: Arc<ServerLink>,
    run_id: Arc<String>,
    proxies: Arc<HashMap<String, ProxyConfig>>,
    health: Arc<health::Monitor>,
) -> Result<()> {
    let stream = link.connect().await?;

    let ts = util::now_unix_secs() as i64;
    let (mut work, leftover, start) =
        conn::client_work_conn(stream, &run_id, &link.cfg.token, ts).await?;

    let proxy = proxies
        .get(&start.proxy_name)
        .ok_or_else(|| anyhow!("服务端指定了未知代理：{}", start.proxy_name))?
        .clone();

    // 健康检查不通过：直接拒掉这条工作连接，让用户去连别的后端
    if !health.is_healthy(&start.proxy_name) {
        anyhow::bail!(
            "代理 [{}] 健康检查未通过，暂不提供服务",
            util::strip_user_prefix(&link.cfg.user, &start.proxy_name)
        );
    }

    // UDP 代理：工作连接上跑的是 UdpPacket 消息，交给专门的转发器
    if proxy.proxy_type == "udp" {
        // 工作连接握手后是裸字节流，这里重新包一层帧读写器
        // （工作连接本身不加密，所以直接 new 即可）。
        let mut udp_conn = FrpConn::new(work);
        udp_conn.set_udp_codec(link.udp_binary.load(std::sync::atomic::Ordering::Relaxed));
        return udp_proxy::run(udp_conn, proxy.local_addr.clone(), start.proxy_name.clone()).await;
    }

    // 插件：工作连接直接接到插件上，不再连内网服务
    if let Some(built) = plugin::Plugin::from_proxy(&proxy) {
        let plug = built.with_context(|| format!("代理 [{}] 的插件配置有误", proxy.name))?;
        debug!(proxy = %start.proxy_name, "工作连接交给插件处理");
        return plug.serve(work, leftover, &start.proxy_name).await;
    }

    let local_addr = &proxy.local_addr;
    let local = util::resolve_addr(local_addr)
        .await
        .with_context(|| format!("解析内网地址 {local_addr} 失败"))?;
    let mut local_stream = TcpStream::connect(local)
        .await
        .with_context(|| format!("连接内网服务 {local} 失败"))?;
    local_stream.set_nodelay(true).ok();

    debug!(proxy = %start.proxy_name, %local, "工作连接已建立，开始转发");
    if !leftover.is_empty() {
        local_stream.write_all(&leftover).await?;
    }
    // 带宽限流：配了就按令牌桶限速，没配就走原路径（行为完全不变）
    let limit = throttle::parse_bandwidth(&proxy.bandwidth_limit).unwrap_or(0);
    let r = if limit > 0 {
        debug!(proxy = %start.proxy_name, limit, "按 {} 字节/秒限速", limit);
        throttle::relay_throttled(work, local_stream, limit, limit).await
    } else {
        util::relay_between(&mut work, &mut local_stream).await
    };
    if let Err(e) = r {
        debug!(proxy = %start.proxy_name, "转发中断：{e}");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    //! `build_new_proxy` 的字段搬运测试。
    //!
    //! 存在的理由很具体：`group` / `group_key` 加进 `ProxyConfig` 之后，
    //! 注册流程里那段内联的 `match` 忘了把它们放进 `NewProxy`。
    //! 服务端单测测的是注册表本身（全绿），客户端当时没有对应用例，
    //! 结果只有端到端冒烟才暴露出来 —— 用户配置写了 `group` 却完全没生效。
    //!
    //! 所以这里用一个「所有字段都给独特值」的配置去过一遍，
    //! 谁没被搬过去，断言就会指名道姓地失败。

    use super::*;

    /// 一个所有字段都填满独特值的 tcp 代理配置。
    fn full_tcp_config() -> ProxyConfig {
        ProxyConfig {
            name: "web-a".into(),
            proxy_type: "tcp".into(),
            local_addr: "127.0.0.1:8080".into(),
            remote_port: 6100,
            custom_domains: vec!["a.example.com".into()],
            subdomain: "sub".into(),
            locations: vec!["/api".into()],
            http_user: "hu".into(),
            http_pwd: "hp".into(),
            host_header_rewrite: "backend.internal".into(),
            bandwidth_limit: "1MB".into(),
            group: "web".into(),
            group_key: "gk".into(),
            health_check_type: "http".into(),
            health_check_timeout_s: 7,
            health_check_max_failed: 5,
            health_check_interval_s: 11,
            health_check_url: "/healthz".into(),
            plugin: "http_proxy".into(),
            plugin_local_path: "/tmp/x".into(),
            plugin_strip_prefix: "/p".into(),
            plugin_user: "pu".into(),
            plugin_passwd: "pp".into(),
            secret_key: "sk".into(),
            allow_users: vec!["alice".into()],
        }
    }

    #[test]
    fn tcp_carries_port_and_group() {
        let c = full_tcp_config();
        let m = build_new_proxy("alice", &c);
        assert_eq!(m.proxy_name, "alice.web-a", "线协议名要带 user 前缀");
        assert_eq!(m.proxy_type, "tcp");
        assert_eq!(m.remote_port, 6100);
        assert_eq!(m.group, "web", "group 没搬过去的话负载均衡等于没配");
        assert_eq!(m.group_key, "gk");
        // tcp 不该带 http / stcp 的东西
        assert!(m.custom_domains.is_empty());
        assert!(m.sk.is_empty());
    }

    #[test]
    fn http_carries_routing_fields() {
        let c = ProxyConfig {
            proxy_type: "http".into(),
            ..full_tcp_config()
        };
        let m = build_new_proxy("bob", &c);
        assert_eq!(m.proxy_name, "bob.web-a");
        assert_eq!(m.custom_domains, vec!["a.example.com".to_string()]);
        assert_eq!(m.subdomain, "sub");
        assert_eq!(m.locations, vec!["/api".to_string()]);
        assert_eq!(m.http_user, "hu");
        assert_eq!(m.http_pwd, "hp");
        assert_eq!(m.host_header_rewrite, "backend.internal");
        assert_eq!(m.group, "web", "http 也应当带上 group");
        // http 不用 remote_port
        assert_eq!(m.remote_port, 0);
    }

    #[test]
    fn stcp_carries_secret_and_allow_list_only() {
        let c = ProxyConfig {
            proxy_type: "stcp".into(),
            ..full_tcp_config()
        };
        let m = build_new_proxy("alice", &c);
        assert_eq!(m.proxy_name, "alice.web-a");
        assert_eq!(m.sk, "sk");
        assert_eq!(m.allow_users, vec!["alice".to_string()]);
        // stcp / xtcp 不占公网端口，带上 remote_port 会让服务端误判
        assert_eq!(m.remote_port, 0);
        assert!(m.group.is_empty(), "stcp 不走端口组，不该带 group");
    }

    /// 没配 user 时不该凭空造出一个 `.` 前缀。
    #[test]
    fn empty_user_leaves_name_untouched() {
        let m = build_new_proxy("", &full_tcp_config());
        assert_eq!(m.proxy_name, "web-a");
    }

    /// 没配 group 时必须原样为空 —— 服务端把空 group 当「独占端口」，
    /// 凭空塞个默认值会让所有代理挤进同一组、端口冲突检测直接失效。
    #[test]
    fn absent_group_stays_empty() {
        let c = ProxyConfig {
            group: String::new(),
            group_key: String::new(),
            ..full_tcp_config()
        };
        let m = build_new_proxy("alice", &c);
        assert!(m.group.is_empty());
        assert!(m.group_key.is_empty());
    }

    /// 防漂移：`ProxyConfig` 里凡是和 `NewProxy` 同名同义、应当下发的字段，
    /// 都在这里被点名检查一遍。以后再加字段，忘了搬就会红。
    #[test]
    fn every_shareable_field_is_carried() {
        let c = full_tcp_config();
        // 用 tcp 分支检查「端口类」字段
        let tcp = build_new_proxy("u", &c);
        assert_eq!(tcp.remote_port, c.remote_port);
        assert_eq!(tcp.group, c.group);
        assert_eq!(tcp.group_key, c.group_key);

        // 用 http 分支检查「路由类」字段
        let http = build_new_proxy(
            "u",
            &ProxyConfig {
                proxy_type: "http".into(),
                ..c.clone()
            },
        );
        assert_eq!(http.custom_domains, c.custom_domains);
        assert_eq!(http.subdomain, c.subdomain);
        assert_eq!(http.locations, c.locations);
        assert_eq!(http.http_user, c.http_user);
        assert_eq!(http.http_pwd, c.http_pwd);
        assert_eq!(http.host_header_rewrite, c.host_header_rewrite);

        // 用 stcp 分支检查「私密隧道类」字段
        let stcp = build_new_proxy(
            "u",
            &ProxyConfig {
                proxy_type: "stcp".into(),
                ..c.clone()
            },
        );
        assert_eq!(stcp.sk, c.secret_key);
        assert_eq!(stcp.allow_users, c.allow_users);
    }
}
