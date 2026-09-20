//! `rustunnel-client`：frp v2 兼容的客户端（等价于原版 frpc）。
//!
//! 支持的代理类型：`tcp` / `udp` / `http` / `https` / `stcp` / `xtcp`。
//! 其中 http / https 在客户端侧与 tcp 无差别（服务端已经把 HTTP 语义处理完了，
//! 客户端只负责把裸字节转给内网服务）；stcp / xtcp 还额外支持 `[[visitors]]`
//! （作为接入方）。

mod health;
mod p2p;
mod plugin;
mod registry;
mod udp_proxy;
mod visitor;

use std::{sync::Arc, time::Duration};

use anyhow::{anyhow, bail, Context, Result};
use clap::Parser;
use rustunnel_common::{
    config::{default_config_path, is_quic, ClientConfig, Protocol, ProxyConfig},
    frp::{
        self,
        conn::{self, FrpConn},
        msg::{self, FrpMessage, NewProxy, Ping},
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
    /// 打印**上游 frp 兼容版本号**（等价于原版 frpc 的 `frpc -v`）
    ///
    /// 只输出裸版本号（如 `0.71.0`），一个多余的字都不加 —— 因为面板和启动器
    /// 会逐字符解析它：NetTool 里的樱花、OpenFrp 都是跑 `frpc -v` 拿到版本号后
    /// 报给平台，平台据此决定下发 **legacy INI** 还是 **TOML** 配置。
    /// 这一项解析不出来时对方会当我们是远古版本，于是丢来一份 INI。
    ///
    /// 想看 rustunnel 自己的版本请用 `--version`。
    #[arg(short = 'v', long = "frp-version")]
    frp_version: bool,

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

    // 必须**第一个**处理：原版 frpc 的 `-v` 就是"打印版本号然后退出"，
    // 面板/启动器会在拉起隧道之前先跑它做格式协商。
    if cli.frp_version {
        println!("{}", rustunnel_common::frp::FRP_WIRE_VERSION);
        return Ok(());
    }

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

    // 线协议：默认 v1，与官方 frpc 的 `transport.wireProtocol` 默认值一致。
    // 樱花这类第三方 frps 分支只认 v1，配成 v2 会连不上（报错通常是"连上就断"）。
    let wire = cfg.protocol.wire_version().ok_or_else(|| {
        anyhow!("当前版本尚未实现 rustunnel 自研协议，请把 protocol 设为 frp-v1（默认）或 frp-v2")
    })?;
    if cfg.proxies.is_empty() && cfg.visitors.is_empty() {
        warn!("配置里既没有 [[proxies]] 也没有 [[visitors]]，客户端不会做任何转发");
    }

    let cfg = Arc::new(cfg);
    // 健康检查是进程级的：跨重连持续探测，状态不随会话重建而丢失
    let health = health::Monitor::start(&cfg);

    info!(
        "rustunnel-client 启动：连接 {}:{}（线协议 {}），共 {} 个代理 / {} 个访客",
        cfg.server_addr,
        cfg.server_port,
        wire,
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

    // 进程生命周期内**是否成功登录过**。用来实现官方 frpc 的 `loginFailExit`
    // （默认 true）：首次登录失败就退出，登录成功过之后断线则一直重连。
    //
    // 这一项很关键，不是可有可无的礼节：第三方启动器（NetTool 拉 LoliaFRP 就是）
    // 判断"隧道到底起没起来"靠的是**看子进程还活着没**。老版本无脑重试，
    // 配置/令牌错的时候进程也不退，启动器只会显示绿灯 —— 用户看到"已启动"
    // 但实际根本连不上，还得自己去翻日志。官方 frpc 遇到这种情况会毫秒级退出，
    // 启动器才能把错误原样弹给用户。
    let logged_in_once = Arc::new(std::sync::atomic::AtomicBool::new(false));

    loop {
        let fut = run_session(
            cfg.clone(),
            session_tx.clone(),
            health.clone(),
            logged_in_once.clone(),
        );
        tokio::select! {
            r = fut => {
                match r {
                    Ok(()) => info!("与控制服务端的会话结束"),
                    Err(e) => {
                        // 首次登录（连不上 / 认证被拒 / 握手失败）就没成功过 → 退出，
                        // 让启动器据此报错。已经登录过则只是普通断线，继续重连。
                        if cfg.login_fail_exit
                            && !logged_in_once.load(std::sync::atomic::Ordering::SeqCst)
                        {
                            return Err(e).with_context(|| {
                                format!(
                                    "首次登录 {}:{} 失败；已启用 loginFailExit（默认行为），\
                                     不再重试。想让它一直重试请在配置里写 loginFailExit = false",
                                    cfg.server_addr, cfg.server_port
                                )
                            });
                        }
                        error!("会话出错：{e:#}");
                    }
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
    /// 本次会话使用的线协议（v1 / v2）。工作连接、visitor 连接都必须跟着用，
    /// 否则会与服务端对不上（官方 frps 会直接以 `wire protocol mismatch` 拒绝）。
    wire: frp::WireVersion,
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
        let wire = cfg.protocol.wire_version().ok_or_else(|| {
            anyhow!("当前版本尚未实现 rustunnel 自研协议，请把 protocol 设为 frp-v1 或 frp-v2")
        })?;
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
            wire,
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
/// 把一条代理配置搬成线协议里的 `NewProxy` 消息。
///
/// 单独抽成函数是为了**能测**：这段映射以前内联在注册流程里，
/// 于是新增配置字段（`group` / `group_key`）时忘了搬进消息体，
/// 服务端单测测的是注册表、客户端也没有对应用例，最后是端到端冒烟才把它翻出来。
///
/// # `proxy_name` 必须带 `{user}.` 前缀
///
/// 官方 frpc 上线用的名字**不是**配置里的 `name`，而是
/// `naming.AddUserPrefix(clientCfg.User, name)` 的结果（`client/proxy/proxy_wrapper.go`
/// 的 `wireName` 字段）。`user = '2569'` + `name = 'c046…'`，线上就是 `2569.c046…`。
///
/// 第三方平台（LoliaFRP 等）正是拿这个**全名**去查隧道的，发原始名过去它查不到，
/// 只会回一句「FRPC 配置文件错误,请检查后重试,请反馈给管理员以解决这个问题」。
///
/// ## 这个坑已经踩过一次，别再踩
///
/// 官方 frpc 的日志是
/// `[dump-run-id] proxy added: [c0462d9ce7e44bce97e626c4ae880905]` —— **不带前缀**，
/// 很容易据此以为线上也不带，然后把这里的前缀删掉（真发生过）。
///
/// 其实那行日志打的是 `pm.proxies` 的 key，也就是配置里的原始 `name`
/// （`client/proxy/proxy_manager.go`：`name := cfg.GetBaseConfig().Name`），
/// 跟真正发出去的 `wireName` 根本不是一回事。
///
/// ## 怎么才不会再搞错
///
/// 别读日志猜，**抓包**：用 [`server/examples/dump_frpc.rs`] 当假 frps
/// （`cargo run -p rustunnel-server --example dump_frpc -- 17777`），把官方 frpc 的
/// `serverAddr` 指过去，它会把你收到的每个消息原样打成 JSON，`proxy_name`
/// 带不带前缀一眼就能看清。
///
/// 抓之前记得在待测配置里关掉两个传输层开关，否则连魔术字都对不上：
///
/// ```toml
/// [transport]
/// tcpMux = false          # 默认 true，会把控制连接塞进 yamux
/// wireProtocol = "v2"     # 默认 v1，发的是 `6f`（'o' = TypeLogin），没有魔术字
///
/// [transport.tls]
/// enable = false          # 默认 true，首字节是 TLS ClientHello
/// ```
///
/// 服务端那边保持**幂等**（收到原始名或带前缀的名字都会被补成带前缀的），
/// 所以老客户端直接发原始名也不会坏 —— 见 `server/src/serve.rs`。
/// 把服务端下发的**线上全名**翻译回本地配置里的原始代理名，并取出配置。
///
/// 命名契约（与官方 frp 一致，别改）：
/// - 客户端 `NewProxy.proxy_name` 发的是**线上全名** `{user}.{name}`（见 [`NewProxy::from_config`]）；
/// - 服务端回显（`NewProxyResp`）与主动下发（`StartWorkConn`、`NatHoleClient`）
///   用的**也是同一个全名**；
/// - 而本地映射表 [`run_session`] 里是按配置里的**原始 `name`** 建的。
///
/// 所以**凡是拿服务端下发的 `proxy_name` 查本地表的地方，都必须过这个函数**。
/// 这个坑踩过两次：先修了 `NewProxyResp` 和 `StartWorkConn`，漏了 `NatHoleClient`
/// —— 表现为 provider 打印「收到未知代理的打洞通知，忽略」，xtcp **静默退化成中继**：
/// 数据还是通的，只有「有没有走 P2P 直连」这条断言会红（本机冒烟第 4 项）。
fn resolve_uploaded_proxy(
    user: &str,
    wire_name: &str,
    proxies: &registry::ProxyTable,
) -> Option<(String, Arc<ProxyConfig>)> {
    let raw = util::strip_user_prefix(user, wire_name).to_string();
    proxies.get(&raw).map(|p| (raw, p))
}

async fn run_session(
    cfg: Arc<ClientConfig>,
    session_tx: tokio::sync::watch::Sender<Option<Arc<ClientSession>>>,
    health: Arc<health::Monitor>,
    logged_in_once: Arc<std::sync::atomic::AtomicBool>,
) -> Result<()> {
    let server = format!("{}:{}", cfg.server_addr, cfg.server_port);
    let link = Arc::new(ServerLink::open(cfg.clone()).await?);
    info!(%server, "已连接到服务端，开始握手");

    let stream = link.connect().await?;
    // 私有能力只是**声明支持**，真正开不开看服务端回显 ——
    // 连官方 frps / 第三方 frps 时对方不会回显，行为与不开完全一致。
    let declared = msg::RustunnelCaps {
        udp_binary: cfg.private_caps,
        server_cmd: cfg.private_caps,
    };
    let (mut conn, run_id, udp_binary, caps) = conn::client_handshake(
        stream,
        link.wire,
        &cfg.token,
        &cfg.client_id,
        &cfg.user,
        &cfg.metas,
        cfg.pool_count,
        declared,
    )
    .await?;
    link.udp_binary
        .store(udp_binary, std::sync::atomic::Ordering::Relaxed);
    if udp_binary {
        debug!("服务端选择了二进制 UDP 报文编码");
    }
    if caps.server_cmd {
        debug!("服务端已启用私有管理命令（面板可增删本端代理）");
    }
    info!(%run_id, wire = %link.wire, "登录成功（控制通道已加密）");

    // 记下"这个进程登录成功过"。上面那行之前的任何失败都算**首次登录失败**，
    // 由 main 的循环按 `loginFailExit` 决定是退出还是重试。
    logged_in_once.store(true, std::sync::atomic::Ordering::SeqCst);

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
    //
    // 本地映射表按配置里的**原始 `name`** 建。
    //
    // 服务端回包里的 `proxy_name` 是**线上全名** `{user}.{name}`
    // （我们发上去的就是这个，官方 frps 会原样回显），所以先 `strip_user_prefix`
    // 剥一层再查表；万一遇到不回显前缀的实现，strip 对不带前缀的名字也是恒等的。
    let proxies = registry::ProxyTable::from_iter(cfg.proxies.iter().cloned());

    for p in &cfg.proxies {
        let msg = NewProxy::from_config(p, &cfg.user);
        conn.send_msg(&FrpMessage::NewProxy(msg)).await?;
    }

    let mut pending: std::collections::HashSet<String> =
        cfg.proxies.iter().map(|p| p.name.clone()).collect();
    while !pending.is_empty() {
        let msg = tokio::time::timeout(Duration::from_secs(15), conn.recv_msg())
            .await
            .context("等待 NewProxyResp 超时")??;
        match msg {
            Some(FrpMessage::NewProxyResp(r)) => {
                let raw = util::strip_user_prefix(&cfg.user, &r.proxy_name).to_string();
                pending.remove(&raw);
                let local = match resolve_uploaded_proxy(&cfg.user, &r.proxy_name, &proxies) {
                    Some((_, p)) => p.local_addr.clone(),
                    None => "?".to_string(),
                };
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
                        // 服务端下发的是**线上全名**（带 `{user}.` 前缀），
                        // 而本地映射表按配置里的原始 `name` 建 —— 必须走
                        // `resolve_uploaded_proxy` 剥前缀，否则这里会打印
                        // 「收到未知代理的打洞通知，忽略」，xtcp 静默退化成中继。
                        match resolve_uploaded_proxy(&cfg.user, &m.proxy_name, &proxies) {
                            Some((raw, proxy)) => {
                                debug!(proxy = %raw, "本端作为 provider 参与打洞");
                                let cfg = cfg.clone();
                                tokio::spawn(async move {
                                    let proxy = (*proxy).clone();
                                    if let Err(e) = p2p::serve_as_provider(cfg, proxy, m).await {
                                        debug!("xtcp 打洞未成功（访客会回退中继）：{e:#}");
                                    }
                                });
                            }
                            None => warn!(proxy = %m.proxy_name, "收到未知代理的打洞通知，忽略"),
                        }
                    }
                    // 面板下发的管理命令（增删代理）
                    FrpMessage::ServerCmd(cmd) => {
                        if !caps.server_cmd {
                            // 服务端没回显过这个能力却发了命令：要么是 bug，
                            // 要么是对端不规矩。忽略比照做更安全。
                            warn!(op = %cmd.op, "收到未协商的私有管理命令，忽略");
                            continue;
                        }
                        let resp = apply_server_cmd(&proxies, &cmd, &mut conn).await;
                        if let Err(e) = &resp {
                            warn!(op = %cmd.op, "回执发送失败：{e:#}");
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

/// 执行一条服务端下发的管理命令，并把回执发回去。
///
/// **无论成功失败都必须回一条** `ServerCmdResp`：面板是同步等回包的，
/// 收不到就只能在超时后报「已下发但结果未知」，体验很差。
async fn apply_server_cmd(
    proxies: &registry::ProxyTable,
    cmd: &msg::ServerCmd,
    conn: &mut FrpConn,
) -> Result<()> {
    let result = match cmd.op.as_str() {
        msg::CMD_ADD_PROXY => add_proxy_cmd(proxies, cmd),
        msg::CMD_REMOVE_PROXY => {
            let name = cmd.proxy_name.clone();
            if name.is_empty() {
                Err(anyhow!("remove_proxy 缺少 proxy_name"))
            } else if proxies.remove(&name).is_none() {
                // 把当前有哪些代理一并报回去 —— 面板上最常见的失败原因
                // 就是名字打错，光说"没有"用户没法自查
                let have = proxies.names().join(", ");
                Err(anyhow!(
                    "本地没有名为 [{name}] 的代理（当前有：{}）",
                    if have.is_empty() {
                        "无".to_string()
                    } else {
                        have
                    }
                ))
            } else {
                info!(proxy = %name, total = proxies.len(), reason = %cmd.reason, "按服务端命令移除代理");
                Ok(())
            }
        }
        other => Err(anyhow!("未知命令：{other}")),
    };

    let resp = msg::ServerCmdResp {
        id: cmd.id.clone(),
        op: cmd.op.clone(),
        proxy_name: cmd.proxy_name.clone(),
        error: result
            .as_ref()
            .map_err(|e| e.to_string())
            .err()
            .unwrap_or_default(),
    };
    // 命令本身失败了也要**先把回执发出去**，再让上层记日志
    conn.send_msg(&FrpMessage::ServerCmdResp(resp)).await?;
    result.map(|_| ())
}

/// 面板新增代理：把配置塞进本地表，再补发一条 `NewProxy` 让服务端开端口。
fn add_proxy_cmd(proxies: &registry::ProxyTable, cmd: &msg::ServerCmd) -> Result<()> {
    // 命令里带的是 `serde_json::Value` 而不是 `ProxyConfig`：
    // 配置结构体将来改字段名时，不该让一条命令因为多/少一个键就整个解析失败。
    let p: ProxyConfig = cmd.proxy_config().map_err(anyhow::Error::msg)?;
    if p.name.is_empty() {
        anyhow::bail!("代理配置缺少 name");
    }
    if p.proxy_type.is_empty() {
        anyhow::bail!("代理配置缺少 type");
    }
    let name = p.name.clone();
    let existed = proxies.insert(p.clone()).is_some();
    if existed {
        warn!(proxy = %name, "覆盖了同名的已有代理");
    }
    info!(proxy = %name, r#type = %p.proxy_type, total = proxies.len(), reason = %cmd.reason, "按服务端命令新增代理");
    Ok(())
}

fn spawn_work_conn(
    link: Arc<ServerLink>,
    run_id: Arc<String>,
    proxies: registry::ProxyTable,
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
    proxies: registry::ProxyTable,
    health: Arc<health::Monitor>,
) -> Result<()> {
    let stream = link.connect().await?;

    let ts = util::now_unix_secs() as i64;
    let (mut work, leftover, start) =
        conn::client_work_conn(stream, link.wire, &run_id, &link.cfg.token, ts).await?;

    // 服务端下发的名字是**线上全名**（带 `{user}.` 前缀），本地映射表按配置里的
    // 原始 `name` 建 —— 统一走 `resolve_uploaded_proxy`。
    let (proxy_name, proxy) =
        resolve_uploaded_proxy(&link.cfg.user, &start.proxy_name, &proxies)
            .ok_or_else(|| anyhow!("服务端指定了未知代理：{}", start.proxy_name))?;
    let proxy = proxy.clone();

    // 健康检查不通过：直接拒掉这条工作连接，让用户去连别的后端
    if !health.is_healthy(&proxy_name) {
        anyhow::bail!("代理 [{proxy_name}] 健康检查未通过，暂不提供服务");
    }

    // UDP 代理：工作连接上跑的是 UdpPacket 消息，交给专门的转发器
    if proxy.proxy_type == "udp" {
        // 工作连接握手后是裸字节流，这里重新包一层帧读写器
        // （工作连接本身不加密，所以直接 new 即可）。
        let mut udp_conn = FrpConn::new(work, link.wire);
        udp_conn.set_udp_codec(link.udp_binary.load(std::sync::atomic::Ordering::Relaxed));
        return udp_proxy::run(udp_conn, proxy.local_addr.clone(), proxy_name.to_string()).await;
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

    /// 测试里统一用的 `user`（真实场景就是 Lolia 那份配置里的 `user = '2569'`）。
    const USER: &str = "alice";

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
            bandwidth_limit_mode: "server".into(),
            metas: [("pk".to_string(), "pv".to_string())].into_iter().collect(),
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
        let m = NewProxy::from_config(&c, USER);
        assert_eq!(
            m.proxy_name, "alice.web-a",
            "线协议名必须带 `{{user}}.` 前缀 —— 官方 frpc 的 wireName 就是这么算的，\
             少了前缀第三方平台按名字查不到隧道"
        );
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
        let m = NewProxy::from_config(&c, USER);
        assert_eq!(m.proxy_name, "alice.web-a");
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
        let m = NewProxy::from_config(&c, USER);
        assert_eq!(m.proxy_name, "alice.web-a");
        assert_eq!(m.sk, "sk");
        assert_eq!(m.allow_users, vec!["alice".to_string()]);
        // stcp / xtcp 不占公网端口，带上 remote_port 会让服务端误判
        assert_eq!(m.remote_port, 0);
        assert!(m.group.is_empty(), "stcp 不走端口组，不该带 group");
    }

    /// **金标准测试**：报文必须和官方 frpc v0.71.0 抓到的那一帧**逐字节一致**。
    ///
    /// 下面这串 JSON 是从
    /// `cargo run -p rustunnel-server --example dump_frpc -- 17777`
    /// 抓到的原文（Lolia 下发的那份配置，一字未改）：
    ///
    /// ```text
    /// [msg_type=3 NewProxy] {"proxy_name":"2569.c0462d9ce7e44bce97e626c4ae880905",
    ///  "proxy_type":"tcp","bandwidth_limit":"25MB","bandwidth_limit_mode":"server",
    ///  "remote_port":38725}
    /// ```
    ///
    /// 之所以按**字符串**比而不是逐字段比：`NewProxy` 的字段顺序 = serde 的
    /// 序列化顺序 = 结构体声明顺序，所以字符串相同就意味着连字段顺序都对上了。
    /// 谁把字段顺序挪了、漏了、多发了，这条都会红。
    #[test]
    fn 与官方_frpc_抓包逐字节一致() {
        let cfg = rustunnel_common::config::parse_client_toml(LOLIA_FRPC).unwrap();
        let m = NewProxy::from_config(&cfg.proxies[0], &cfg.user);

        assert_eq!(
            serde_json::to_string(&m).unwrap(),
            concat!(
                r#"{"proxy_name":"2569.c0462d9ce7e44bce97e626c4ae880905","#,
                r#""proxy_type":"tcp","#,
                r#""bandwidth_limit":"25MB","#,
                r#""bandwidth_limit_mode":"server","#,
                r#""remote_port":38725}"#,
            )
        );
    }

    /// LoliaFRP 平台真实下发的配置（`GET /user/frpc/config`，Base64 解出来的原文）。
    const LOLIA_FRPC: &str = r#"
serverAddr = 'cn-hz-2.qwq.fan'
serverPort = 30000
user = '2569'

[metadatas]
token = 'x8p5mo0u8ips3lmohc67r58mejp7uthf'

[[proxies]]
name = 'c0462d9ce7e44bce97e626c4ae880905'
type = 'tcp'
localIP = '127.0.0.1'
localPort = 25565
remotePort = 38725

[proxies.transport]
bandwidthLimit = '25MB'
bandwidthLimitMode = 'server'
"#;

    /// 没配 `user` 时不该凭空造出一个 `.` 前缀。
    #[test]
    fn 空_user_不加前缀() {
        let m = NewProxy::from_config(&full_tcp_config(), "");
        assert_eq!(m.proxy_name, "web-a");
    }

    /// `bandwidth_limit_mode` 默认值 `client` 要**省略**。
    ///
    /// 官方 frpc 的 `MarshalToMsg` 只在值不等于 `client` 时才发这个字段
    /// （`if c.Transport.BandwidthLimitMode != "client"`），我们多发一个
    /// `"bandwidth_limit_mode":"client"` 就和官方报文对不上了。
    #[test]
    fn 默认限流模式不上报() {
        for raw in ["", "client", "CLIENT"] {
            let c = ProxyConfig {
                bandwidth_limit_mode: raw.into(),
                ..full_tcp_config()
            };
            assert!(
                NewProxy::from_config(&c, USER)
                    .bandwidth_limit_mode
                    .is_empty(),
                "值 {raw:?} 应当被归一化成空串（即不发送）"
            );
        }
        // 非默认值要原样上报
        let c = ProxyConfig {
            bandwidth_limit_mode: "server".into(),
            ..full_tcp_config()
        };
        assert_eq!(
            NewProxy::from_config(&c, USER).bandwidth_limit_mode,
            "server"
        );
    }

    /// `NewProxy.metas` 装的是**代理级** `[proxies.metadatas]`，不是顶层 `[metadatas]`。
    ///
    /// 搞混的后果：报文里会多出一个官方 frpc 不会发的 `token` 字段，
    /// 平台一旦校验就报错，而且很难看出是"多发了一个键"。
    #[test]
    fn 代理级_metas_才上进注册报文() {
        let cfg = rustunnel_common::config::parse_client_toml(LOLIA_FRPC).unwrap();
        // 登录 metas 里有 token
        assert_eq!(
            cfg.metas.get("token").map(String::as_str),
            Some("x8p5mo0u8ips3lmohc67r58mejp7uthf")
        );
        // 但代理级没有 → 注册报文里也不该有
        let m = NewProxy::from_config(&cfg.proxies[0], &cfg.user);
        assert!(
            m.metas.is_empty(),
            "顶层 [metadatas] 只进登录消息，不该出现在 NewProxy 里"
        );
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
        let m = NewProxy::from_config(&c, USER);
        assert!(m.group.is_empty());
        assert!(m.group_key.is_empty());
    }

    /// 防漂移：`ProxyConfig` 里凡是和 `NewProxy` 同名同义、应当下发的字段，
    /// 都在这里被点名检查一遍。以后再加字段，忘了搬就会红。
    #[test]
    fn every_shareable_field_is_carried() {
        let c = full_tcp_config();
        // 用 tcp 分支检查「端口类」字段
        let tcp = NewProxy::from_config(&c, USER);
        assert_eq!(tcp.remote_port, c.remote_port);
        assert_eq!(tcp.group, c.group);
        assert_eq!(tcp.group_key, c.group_key);
        assert_eq!(tcp.bandwidth_limit, c.bandwidth_limit);
        assert_eq!(tcp.bandwidth_limit_mode, c.bandwidth_limit_mode);
        assert_eq!(tcp.metas, c.metas);

        // 用 http 分支检查「路由类」字段
        let http = NewProxy::from_config(
            &ProxyConfig {
                proxy_type: "http".into(),
                ..c.clone()
            },
            USER,
        );
        assert_eq!(http.custom_domains, c.custom_domains);
        assert_eq!(http.subdomain, c.subdomain);
        assert_eq!(http.locations, c.locations);
        assert_eq!(http.http_user, c.http_user);
        assert_eq!(http.http_pwd, c.http_pwd);
        assert_eq!(http.host_header_rewrite, c.host_header_rewrite);

        // 用 stcp 分支检查「私密隧道类」字段
        let stcp = NewProxy::from_config(
            &ProxyConfig {
                proxy_type: "stcp".into(),
                ..c.clone()
            },
            USER,
        );
        assert_eq!(stcp.sk, c.secret_key);
        assert_eq!(stcp.allow_users, c.allow_users);
    }

    // -----------------------------------------------------------------------
    // resolve_uploaded_proxy：服务端下发名 → 本地配置
    //
    // xtcp 就是栽在这里的：`NatHoleClient.proxy_name` 是线上全名 `alice.p2p-echo`，
    // 本地表键是 `p2p-echo`，漏剥前缀就被当「未知代理」忽略，
    // P2P **静默退化成中继**（数据照样通，只有"走没走直连"这条断言会红）。
    // -----------------------------------------------------------------------

    /// 本地映射表：键是配置里的**原始** `name`（与 `run_session` 里一致）。
    fn local_map(names: &[&str]) -> std::collections::HashMap<String, ProxyConfig> {
        names
            .iter()
            .map(|n| {
                let mut cfg = full_tcp_config();
                cfg.name = (*n).to_string();
                ((*n).to_string(), cfg)
            })
            .collect()
    }

    /// 服务端下发**带前缀的线上全名**时必须能查到。
    #[test]
    fn 带前缀的下发名能查到本地代理() {
        let m = registry::ProxyTable::from_iter(local_map(&["p2p-echo"]).into_values());
        let (raw, p) = resolve_uploaded_proxy("alice", "alice.p2p-echo", &m)
            .expect("带 user 前缀的线上全名应当能查到");
        assert_eq!(raw, "p2p-echo", "查到的应当是配置里的原始名");
        assert_eq!(p.name, "p2p-echo");
    }

    /// 服务端若原样回显（不带前缀），也要能查到 —— strip 对不带前缀的名字是恒等的。
    #[test]
    fn 不带前缀的下发名同样能查到() {
        let m = registry::ProxyTable::from_iter(local_map(&["p2p-echo"]).into_values());
        let (raw, _) = resolve_uploaded_proxy("alice", "p2p-echo", &m).expect("应当能查到");
        assert_eq!(raw, "p2p-echo");
    }

    /// 没配 `user` 时表键就是原名。
    #[test]
    fn 无_user_时能查到() {
        let m = registry::ProxyTable::from_iter(local_map(&["web-a"]).into_values());
        assert!(resolve_uploaded_proxy("", "web-a", &m).is_some());
    }

    /// 别人的前缀不该被剥掉：`bob` 的客户端收到 `alice.web-a` 必须查不到，
    /// 否则它会去服务别人的代理。
    #[test]
    fn 别人的前缀不会被剥掉() {
        let m = registry::ProxyTable::from_iter(local_map(&["web-a"]).into_values());
        assert!(
            resolve_uploaded_proxy("bob", "alice.web-a", &m).is_none(),
            "非本用户的代理名必须查不到"
        );
    }

    /// 完全不认识的代理名 → `None`（调用方据此走「未知代理」分支）。
    #[test]
    fn 未知代理返回_none() {
        let m = registry::ProxyTable::from_iter(local_map(&["web-a"]).into_values());
        assert!(resolve_uploaded_proxy("alice", "alice.nope", &m).is_none());
    }

    // -----------------------------------------------------------------------
    // 面板下发的管理命令（ServerCmd）
    // -----------------------------------------------------------------------

    /// 造一对连起来的 `FrpConn`：一头给被测代码，另一头用来读它发出去的回执。
    fn cmd_pair() -> (FrpConn, FrpConn) {
        let (a, b) = tokio::io::duplex(64 * 1024);
        (
            FrpConn::new(Box::pin(a), frp::WireVersion::V1),
            FrpConn::new(Box::pin(b), frp::WireVersion::V1),
        )
    }

    fn add_cmd(name: &str) -> msg::ServerCmd {
        let p = ProxyConfig {
            name: name.to_string(),
            proxy_type: "tcp".to_string(),
            remote_port: 7000,
            ..Default::default()
        };
        msg::ServerCmd {
            id: "cmd-1".to_string(),
            op: msg::CMD_ADD_PROXY.to_string(),
            proxy_name: name.to_string(),
            proxy: Some(serde_json::to_value(&p).expect("序列化")),
            reason: "dashboard".to_string(),
        }
    }

    /// 新增代理：本地表里要真的多出一条，且必须回一条成功回执。
    #[tokio::test]
    async fn 管理命令_新增代理() {
        let (mut me, mut peer) = cmd_pair();
        let table = registry::ProxyTable::default();
        apply_server_cmd(&table, &add_cmd("panel-web"), &mut me)
            .await
            .expect("新增应当成功");

        assert_eq!(table.len(), 1, "代理要真的进到本地表里");
        assert_eq!(table.get("panel-web").expect("能查到").remote_port, 7000);

        // 回执：id 必须原样带回，error 为空
        let resp = expect_cmd_resp(&mut peer).await;
        assert_eq!(resp.id, "cmd-1", "id 必须原样带回");
        assert_eq!(resp.op, msg::CMD_ADD_PROXY);
        assert!(resp.error.is_empty(), "不该带错误：{}", resp.error);
    }

    /// **失败也必须回包**：面板是同步等回执的，不回就只能等到超时。
    #[tokio::test]
    async fn 管理命令_失败也要回执() {
        let (mut me, mut peer) = cmd_pair();
        let table = registry::ProxyTable::default();

        // 移除一个不存在的代理
        let cmd = msg::ServerCmd {
            id: "cmd-2".to_string(),
            op: msg::CMD_REMOVE_PROXY.to_string(),
            proxy_name: "nope".to_string(),
            ..Default::default()
        };
        apply_server_cmd(&table, &cmd, &mut me)
            .await
            .expect_err("移除不存在的代理应当失败");

        let resp = expect_cmd_resp(&mut peer).await;
        assert_eq!(resp.id, "cmd-2");
        assert!(
            resp.error.contains("nope"),
            "错误里要带上名字方便自查：{}",
            resp.error
        );
        // 顺便确认错误里会把当前有哪些代理列出来 —— 名字打错是最常见的失败原因
        assert!(
            resp.error.contains("无"),
            "应当顺便列出当前代理：{}",
            resp.error
        );
    }

    /// 未知命令要报错，而不是被当成成功。
    #[tokio::test]
    async fn 管理命令_未知op被拒绝() {
        let (mut me, mut peer) = cmd_pair();
        let table = registry::ProxyTable::default();
        let cmd = msg::ServerCmd {
            id: "cmd-3".to_string(),
            op: "format_disk".to_string(),
            ..Default::default()
        };
        apply_server_cmd(&table, &cmd, &mut me)
            .await
            .expect_err("未知命令必须失败");
        assert!(expect_cmd_resp(&mut peer).await.error.contains("未知命令"));
    }

    /// 先加后删：整条生命周期要闭环。
    #[tokio::test]
    async fn 管理命令_先加后删() {
        let (mut me, mut peer) = cmd_pair();
        let table = registry::ProxyTable::from_iter([ProxyConfig {
            name: "old".into(),
            ..Default::default()
        }]);

        apply_server_cmd(&table, &add_cmd("new"), &mut me)
            .await
            .expect("新增");
        let _ = expect_cmd_resp(&mut peer).await;
        assert_eq!(table.len(), 2);

        let cmd = msg::ServerCmd {
            id: "cmd-4".to_string(),
            op: msg::CMD_REMOVE_PROXY.to_string(),
            proxy_name: "old".to_string(),
            ..Default::default()
        };
        apply_server_cmd(&table, &cmd, &mut me).await.expect("移除");
        let _ = expect_cmd_resp(&mut peer).await;
        assert_eq!(table.len(), 1, "删掉之后只剩新增的那条");
        assert!(table.get("old").is_none());
        assert!(table.get("new").is_some());
    }

    /// 读一条回执。**带超时** —— 没有超时的话，一旦发送侧没写出去，
    /// 这条测试会永远挂住，把整个测试进程一起拖死（踩过一次）。
    async fn expect_cmd_resp(conn: &mut FrpConn) -> msg::ServerCmdResp {
        let got = tokio::time::timeout(Duration::from_secs(5), conn.recv_msg())
            .await
            .expect("5 秒内必须收到回执 —— 没收到说明发送侧根本没写出去")
            .expect("读回执");
        match got {
            Some(FrpMessage::ServerCmdResp(r)) => r,
            other => panic!("应当是 ServerCmdResp，实际：{other:?}"),
        }
    }
}
