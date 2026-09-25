//! `nfrp-client`：frp v2 兼容的客户端（等价于原版 frpc）。
//!
//! 支持的代理类型：`tcp` / `udp` / `http` / `https` / `stcp` / `xtcp`。
//! 其中 http / https 在客户端侧与 tcp 无差别（服务端已经把 HTTP 语义处理完了，
//! 客户端只负责把裸字节转给内网服务）；stcp / xtcp 还额外支持 `[[visitors]]`
//! （作为接入方）。

mod health;
mod p2p;
mod plugin;
mod registry;
mod store;
mod udp_proxy;
mod visitor;
mod vnet;
mod web;

use std::{sync::Arc, time::Duration};

use anyhow::{anyhow, bail, Context, Result};
use clap::Parser;
use nfrp_common::{
    config::{default_config_path, is_kcp, is_quic, ClientConfig, Protocol, ProxyConfig},
    frp::{
        self,
        conn::{self, FrpConn},
        msg::{self, FrpMessage, NewProxy, Ping},
        mux::MuxSession,
        stream::BoxStream,
        tls,
    },
    proxy_protocol, throttle, util, ws,
};
use tokio::io::AsyncWriteExt;
use tokio::{
    net::{TcpStream, UdpSocket},
    time::interval,
};
use tracing::{debug, error, info, warn};

#[derive(Parser, Debug)]
#[command(name = "nfrp-client", version, about = "NFrp 客户端（兼容原版 frp）")]
struct Cli {
    /// 子命令：`verify` / `status` / `reload` / `stop`，对应原版 frpc 的同名命令。
    ///
    /// **不写子命令时行为与以前完全一致**（读配置、跑隧道）—— 只是多了一层
    /// 可选的分支，老脚本、启动器拉的 `nfrp-client -c xxx.toml` 不受影响。
    #[command(subcommand)]
    command: Option<Command>,

    /// 打印**上游 frp 兼容版本号**（等价于原版 frpc 的 `frpc -v`）
    ///
    /// 只输出裸版本号（如 `0.71.0`），一个多余的字都不加 —— 因为面板和启动器
    /// 会逐字符解析它：NetTool 里的樱花、OpenFrp 都是跑 `frpc -v` 拿到版本号后
    /// 报给平台，平台据此决定下发 **legacy INI** 还是 **TOML** 配置。
    /// 这一项解析不出来时对方会当我们是远古版本，于是丢来一份 INI。
    ///
    /// 想看 NFrp 自己的版本请用 `--version`。
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

    /// 覆盖配置里的线协议（frp-v2 / nfrp）
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

/// 子命令（对齐原版 frpc 的命令面）。
#[derive(clap::Subcommand, Debug)]
enum Command {
    /// 校验配置文件（等价原版 `frpc verify -c <配置>`）
    ///
    /// 解析配置并检查语义（代理类型是否支持、必填项是否齐全），**不建立任何连接**。
    /// 退出码 0 = 通过，非 0 = 有问题 —— 启动器/脚本可以据此判断。
    Verify(VerifyArgs),

    /// 查看运行中的客户端状态（走本地管理界面的 API，需配置里开了 [webServer]）
    Status(AdminArgs),

    /// 停止运行中的客户端（等价原版 `frpc stop`）
    Stop(AdminArgs),
}

/// `verify` 的参数。
#[derive(clap::Args, Debug)]
struct VerifyArgs {
    /// 要校验的配置文件（默认 ./client.toml）
    #[arg(short, long, value_name = "PATH")]
    config: Option<std::path::PathBuf>,
}

/// `status` / `stop` 共享的参数：都要从配置里找到管理界面地址。
#[derive(clap::Args, Debug)]
struct AdminArgs {
    /// 客户端配置文件（用于取 [webServer] 的地址，默认 ./client.toml）
    #[arg(short, long, value_name = "PATH")]
    config: Option<std::path::PathBuf>,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    // 必须**第一个**处理：原版 frpc 的 `-v` 就是"打印版本号然后退出"，
    // 面板/启动器会在拉起隧道之前先跑它做格式协商。
    if cli.frp_version {
        println!("{}", nfrp_common::frp::FRP_WIRE_VERSION);
        return Ok(());
    }
    // 子命令不跑隧道：处理完直接退出。
    if let Some(cmd) = &cli.command {
        return match cmd {
            Command::Verify(a) => cmd_verify(a),
            Command::Status(a) => cmd_status(a).await,
            Command::Stop(a) => cmd_stop(a).await,
        };
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
                .unwrap_or_else(|| "nfrp-client".into()),
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

    // 官方 frp 支持、但 nfrp **未实现**的字段：官方 frpc 默认 strict 解析，
    // 未知字段**直接报错**；NFrp 的 serde 不拒绝未知字段，于是它们被**静默
    // 吞掉**。最危险的是 useEncryption / useCompression —— 用户以为加密了，
    // 实际跑的是明文，日志里一个字都没有。这里必须明说，不能留"配了就等于生效"的错觉。
    if !cfg.unsupported_fields.is_empty() {
        warn!(
            "配置里有 {} 项字段是官方 frp 支持、但 nfrp **未实现**的，已按默认值忽略：{} \
             —— 它们不会生效（尤其是 useEncryption / useCompression：写了也仍是明文、不压缩）",
            cfg.unsupported_fields.len(),
            cfg.unsupported_fields.join(", ")
        );
    }

    // 线协议：默认 v1，与官方 frpc 的 `transport.wireProtocol` 默认值一致。
    // 樱花这类第三方 frps 分支只认 v1，配成 v2 会连不上（报错通常是"连上就断"）。
    let wire = cfg.protocol.wire_version().ok_or_else(|| {
        anyhow!("当前版本尚未实现 NFrp 自研协议，请把 protocol 设为 frp-v1（默认）或 frp-v2")
    })?;
    if cfg.proxies.is_empty() && cfg.visitors.is_empty() {
        warn!("配置里既没有 [[proxies]] 也没有 [[visitors]]，客户端不会做任何转发");
    }

    // PROXY 协议版本写错是个**静默**故障：不生效、日志里也看不出。
    // 在这里逐个代理点出来，别让用户对着后端"protocol error"猜半天。
    for p in &cfg.proxies {
        if let Some(bad) = p.has_invalid_proxy_protocol_version() {
            warn!(
                proxy = %p.name,
                value = %bad,
                "proxyProtocolVersion 只认 \"v1\" / \"v2\"（大小写不敏感），\
                 其它值一律**不启用** PROXY 协议，已按不启用处理"
            );
        }
    }

    // 认证配置先校验一遍：字段写错要在**启动时**就报出来，
    // 而不是等每次连接都失败、用户对着"登录失败"发呆。
    cfg.auth.validate()?;
    let token_source = match cfg.auth.method {
        nfrp_common::security::AuthMethod::Oidc => {
            let ts = nfrp_common::auth::oidc::TokenSource::new(cfg.auth.oidc.clone())?;
            info!(
                endpoint = %cfg.auth.oidc.token_endpoint_url,
                "OIDC 认证：连接前用 Client Credentials 换取 access token（带缓存）"
            );
            Some(ts)
        }
        nfrp_common::security::AuthMethod::Token => None,
    };

    // 动态代理（面板 / Web API 加过的）从 store 里恢复，**并进 `cfg.proxies`**。
    //
    // 并进配置而不是单独维护一张表，是因为后面有四个消费者：健康检查、
    // 登录时逐条发 NewProxy、工作连接查本地表、面板列表。并一次，
    // 四处都自然看得见；分开维护就迟早会漏掉其中一处。
    let store = Arc::new(store::Store::from_config(&cfg)?);
    if store.is_enabled() {
        let restored = store.dynamic();
        if !restored.is_empty() {
            info!(
                count = restored.len(),
                names = %store.dynamic_names().join(", "),
                "从 store 恢复了动态添加的代理"
            );
        }
        cfg.proxies = store::merge_initial(&cfg.proxies, restored);
    }

    let cfg = Arc::new(cfg);
    // 健康检查是进程级的：跨重连持续探测，状态不随会话重建而丢失
    let health = health::Monitor::start(&cfg);

    info!(
        "nfrp-client 启动：连接 {}:{}（线协议 {}），共 {} 个代理 / {} 个访客",
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

    // VirtualNet：给本机加一块虚拟网卡，与同网段的其他客户端三层互通。
    //
    // 与普通代理不同，它**不是**由控制会话驱动的：控制连接断了虚拟网络照样
    // 应该重连（两条连接本来就独立），所以单独起一个常驻任务。
    if cfg.virtual_net.is_enabled() {
        // 配置写错要在启动时就报出来，而不是等用户对着"网卡没出来"发呆
        cfg.virtual_net.validate()?;
        if cfg.virtual_net.server_port == 0 {
            bail!(
                "开了 [virtualNet] 但没写 serverPort —— 需要与服务端的 vnet_port 一致。\
                 服务端配置里那句 `vnet_port = <端口>` 就是要填进来的值。"
            );
        }
        let c = cfg.clone();
        let ts = token_source.clone();
        tokio::spawn(async move {
            if let Err(e) = vnet::run(c, ts).await {
                error!("VirtualNet 已停止：{e:#}");
            }
        });
    }

    // 代理表是**进程级**的：本地管理界面与会话共用同一张表。
    //
    // 各建一张的话，"刚在界面上加的代理"要等下次重连才会被会话看见 ——
    // 而那期间界面显示"已添加"、流量却进不来。
    let proxies = registry::ProxyTable::from_iter(cfg.proxies.iter().cloned());

    // 客户端本地管理界面（`[webServer]`）。
    //
    // `port` 为 0（默认）时整段都不执行：不绑端口、不起任务，
    // 与没有这个功能的版本**完全一致**。
    let hub = if cfg.web_server.is_enabled() {
        let addr = format!("{}:{}", cfg.web_server.addr, cfg.web_server.port);
        let listener = tokio::net::TcpListener::bind(&addr)
            .await
            .with_context(|| {
                format!("客户端管理界面绑定 {addr} 失败（检查 [webServer] 的 addr / port）")
            })?;
        let hub = web::Hub::new(
            cfg.clone(),
            proxies.clone(),
            store.clone(),
            health.clone(),
            session_rx.clone(),
        );
        let serving = hub.clone();
        tokio::spawn(web::run(listener, serving));
        Some(hub)
    } else {
        None
    };

    // `stop` 子命令的信号源（[webServer] 没启用时为 None，永远不触发）。
    let mut stop_rx = hub.as_ref().map(|h| h.stop_receiver());

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
        let fut = run_session(SessionDeps {
            cfg: cfg.clone(),
            session_tx: session_tx.clone(),
            health: health.clone(),
            logged_in_once: logged_in_once.clone(),
            token_source: token_source.clone(),
            store: store.clone(),
            proxies: proxies.clone(),
            hub: hub.clone(),
        });
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
            _ = wait_stop(&mut stop_rx) => {
                info!("收到 stop 命令（来自本地管理界面），客户端退出");
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
            _ = wait_stop(&mut stop_rx) => {
                info!("收到 stop 命令（来自本地管理界面），客户端退出");
                return Ok(());
            }
        }
    }
}

/// 等 `stop` 信号；没启用 `[webServer]` 时（None）永远挂起。
///
/// 先看**当前值**再等变化：`watch` 的 `changed()` 只等下一次变化，
/// 若 stop 请求在订阅之前就到了，光等 `changed()` 会永远等下去。
async fn wait_stop(rx: &mut Option<tokio::sync::watch::Receiver<bool>>) {
    match rx.as_mut() {
        Some(r) => {
            if *r.borrow() {
                return;
            }
            let _ = r.changed().await;
        }
        None => std::future::pending::<()>().await,
    }
}

/// `verify` 子命令：解析配置并报告结果，**不建立任何连接**。
///
/// 等价原版 `frpc verify -c <配置>`：官方默认 strict 解析、有问题就非 0 退出，
/// 启动器据此判断"这份配置能不能用"。这里把 `unsupported_fields` 一并报出来 ——
/// 官方 frpc 对未知字段会**直接报错**，NFrp 只是忽略，得让用户知道差在哪。
fn cmd_verify(a: &VerifyArgs) -> Result<()> {
    let path = a
        .config
        .clone()
        .unwrap_or_else(|| default_config_path("client.toml"));
    if !path.exists() {
        bail!("配置文件不存在：{}", path.display());
    }
    let raw = std::fs::read_to_string(&path)
        .with_context(|| format!("读取配置 {} 失败", path.display()))?;
    match nfrp_common::config::parse_client(&raw) {
        Ok(cfg) => {
            println!("配置校验通过：{}", path.display());
            println!("  服务端：{}:{}", cfg.server_addr, cfg.server_port);
            println!(
                "  代理 {} 个 / 访客 {} 个",
                cfg.proxies.len(),
                cfg.visitors.len()
            );
            for p in &cfg.proxies {
                println!("    - [{}] {} -> {}", p.name, p.proxy_type, p.local_addr);
            }
            for v in &cfg.visitors {
                println!(
                    "    - [{}] {} -> {}.{}",
                    v.name, v.visitor_type, v.server_user, v.server_name
                );
            }
            if !cfg.unsupported_fields.is_empty() {
                println!(
                    "  警告：{} 项是官方 frp 支持、但 NFrp 未实现的字段（已忽略）：{}",
                    cfg.unsupported_fields.len(),
                    cfg.unsupported_fields.join(", ")
                );
            }
            Ok(())
        }
        Err(e) => {
            eprintln!("配置校验失败：{}", path.display());
            eprintln!("{e:#}");
            std::process::exit(1);
        }
    }
}

/// 从配置的 `[webServer]` 取本地管理界面地址。
///
/// `status` / `stop` 靠它定位运行中的进程 —— 官方 frpc 也是这个路子
/// （读配置里的 `webServer.addr/port`，再打本地 API）。
fn admin_base(cfg: &ClientConfig) -> Result<String> {
    if !cfg.web_server.is_enabled() {
        bail!(
            "配置里没有启用 [webServer]，无法定位运行中的客户端。\n\
             请在配置里加上：\n  [webServer]\n  addr = \"127.0.0.1\"\n  port = 7400"
        );
    }
    let host = if cfg.web_server.addr.trim().is_empty() {
        "127.0.0.1"
    } else {
        cfg.web_server.addr.trim()
    };
    Ok(format!("http://{host}:{}", cfg.web_server.port))
}

/// 读配置、算出管理界面地址。
fn load_admin_base(a: &AdminArgs) -> Result<String> {
    let path = a
        .config
        .clone()
        .unwrap_or_else(|| default_config_path("client.toml"));
    if !path.exists() {
        bail!("配置文件不存在：{}", path.display());
    }
    let cfg =
        ClientConfig::load(&path).with_context(|| format!("读取配置 {} 失败", path.display()))?;
    admin_base(&cfg)
}

/// `status` 子命令：打印运行中客户端的状态（走本地管理界面 API）。
async fn cmd_status(a: &AdminArgs) -> Result<()> {
    let base = load_admin_base(a)?;
    let url = format!("{base}/api/status");
    let resp = nfrp_common::httpc::get(&url, &[], &Default::default())
        .await
        .with_context(|| format!("请求 {url} 失败（客户端没在跑？或 [webServer] 地址不对）"))?;
    println!("{}", String::from_utf8_lossy(&resp.body));
    if resp.status != 200 {
        std::process::exit(1);
    }
    Ok(())
}

/// `stop` 子命令：让运行中的客户端退出（走本地管理界面 API）。
async fn cmd_stop(a: &AdminArgs) -> Result<()> {
    let base = load_admin_base(a)?;
    let url = format!("{base}/api/stop");
    let resp = nfrp_common::httpc::request("POST", &url, &[], None, &Default::default())
        .await
        .with_context(|| format!("请求 {url} 失败（客户端没在跑？或 [webServer] 地址不对）"))?;
    println!("{}", String::from_utf8_lossy(&resp.body).trim());
    if resp.status != 200 {
        std::process::exit(1);
    }
    Ok(())
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
            anyhow!("当前版本尚未实现 NFrp 自研协议，请把 protocol 设为 frp-v1 或 frp-v2")
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

/// 建立一条到服务端的底层连接（TCP，按需 TLS，按需 WebSocket）。
///
/// 套壳顺序与官方 frpc 一致：`TCP -> [TLS] -> [WebSocket]`，
/// yamux 由 [`ServerLink`] 再套在外面。
async fn raw_connect(cfg: &ClientConfig) -> Result<BoxStream> {
    // KCP 是另一条路：裸 UDP 上的可靠传输，TLS / WebSocket 那几层跟它没关系
    if is_kcp(&cfg.transport_protocol) {
        return kcp_connect(cfg).await;
    }
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
    // `protocol = "wss"` 自带 TLS，不用再写一遍 `transport.tls.enable`。
    let tls_on = cfg.tls_enable || cfg.websocket_tls();
    let stream = tls::connect_client(stream, tls_on, name, !cfg.tls_custom_first_byte).await?;

    if !cfg.websocket_enabled() {
        return Ok(stream);
    }

    // TLS + WebSocket 同时打开是个真实的坑，必须当场喊出来：
    // 官方 frps 在 **TLS 之前**按明文前缀 `GET /~!frp` 嗅探 WebSocket，
    // 套了 TLS 之后首字节变成 0x16，服务端只会把它当成一条普通 frp 连接，
    // 表现为"连上就断"，而两边日志都看不出所以然。
    if tls_on && !cfg.websocket_tls() {
        warn!(
            "同时打开了 transport.tls 与 WebSocket：官方 frps 在 TLS **之前**嗅探 \
             WebSocket 前缀，这种组合直连主端口会握手失败；\
             如果要 wss，请把 protocol 设为 \"wss\" 并由前置代理（nginx 等）终结 TLS"
        );
    }

    let host = if cfg.websocket.host.trim().is_empty() {
        cfg.server_addr.as_str()
    } else {
        cfg.websocket.host.as_str()
    };
    let path = cfg.websocket.effective_path();
    let ws = ws::connect(stream, host, path, &[])
        .await
        .with_context(|| format!("WebSocket 握手失败（{host}{path}）"))?;
    info!(%host, %path, tls = tls_on, "控制连接改走 WebSocket 传输");
    Ok(Box::pin(ws))
}

/// 建立一条 KCP 连接（裸 UDP 上的可靠传输）。
///
/// 服务端要开 `kcp_bind_port`，客户端把 `transport.protocol` 设成 `kcp` 即可；
/// 上层照旧套 yamux（`tcp_mux`），所以控制连接和工作连接共用这一条 KCP 会话。
async fn kcp_connect(cfg: &ClientConfig) -> Result<BoxStream> {
    let server = format!("{}:{}", cfg.server_addr, cfg.server_port);
    let addr = util::resolve_addr(&server)
        .await
        .with_context(|| format!("解析服务端 KCP 地址 {server} 失败"))?;
    let sock = Arc::new(
        UdpSocket::bind("0.0.0.0:0")
            .await
            .context("绑定本地 UDP 端口失败（KCP 传输需要）")?,
    );
    // conv 由发起方定，服务端从第一个数据报的头里读出来照抄。
    // 用时间戳派生即可，只要保证非零（0 容易被当成无效会话号）。
    let conv = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.subsec_nanos())
        .unwrap_or(0)
        | 1;
    let stream = frp::kcp::KcpStream::connect(sock, addr, conv).await;
    info!(%addr, conv, "KCP 传输已建立");
    Ok(Box::pin(stream))
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
/// （`cargo run -p nfrp-server --example dump_frpc -- 17777`），把官方 frpc 的
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

/// 取本次连接要用的登录凭证。
///
/// - token 方式：直接用配置里的共享密钥（真正上线时会派生 `privilege_key`）；
/// - OIDC 方式：**现取**一次 access token。绝不能缓存到调用方 ——
///   token 会过期，复用上一次的会让"重连"变成"拿过期 token 再失败一次"。
///   `TokenSource` 自己带缓存，没到期时不会真去打 IdP。
///
/// 抽成函数是因为 VirtualNet 也要用同一套凭证（见 `vnet.rs`）——
/// 两边各写一遍的话，"OIDC 的 privilege_key 是原样 token"这条语义迟早会在
/// 其中一边漏掉（这个坑在 `security.rs` 的注释里专门标过）。
pub(crate) async fn current_credential(
    cfg: &ClientConfig,
    token_source: &Option<Arc<nfrp_common::auth::oidc::TokenSource>>,
) -> Result<nfrp_common::security::Credential> {
    Ok(match token_source {
        Some(src) => nfrp_common::security::Credential::Oidc(
            src.token()
                .await
                .context("向 IdP 换取 OIDC access token 失败")?,
        ),
        None => nfrp_common::security::Credential::Token(cfg.effective_token().to_string()),
    })
}

/// 一次控制会话需要的全部外部依赖。
///
/// 打成一个结构体而不是摊成八个参数：会话每重连一次就要跑一遍，
/// 而依赖永远只有这一组 —— 摊平只会让调用点越来越难读
/// （也过不了 clippy 的参数个数上限）。
struct SessionDeps {
    cfg: Arc<ClientConfig>,
    session_tx: tokio::sync::watch::Sender<Option<Arc<ClientSession>>>,
    health: Arc<health::Monitor>,
    logged_in_once: Arc<std::sync::atomic::AtomicBool>,
    token_source: Option<Arc<nfrp_common::auth::oidc::TokenSource>>,
    store: Arc<store::Store>,
    proxies: registry::ProxyTable,
    hub: Option<Arc<web::Hub>>,
}

async fn run_session(deps: SessionDeps) -> Result<()> {
    // 解构出来而不是满篇写 `deps.cfg` —— 下面这段是本文件最长的一段代码，
    // 到处加前缀只会让它更难读。
    let SessionDeps {
        cfg,
        session_tx,
        health,
        logged_in_once,
        token_source,
        store,
        proxies,
        hub,
    } = deps;
    let server = format!("{}:{}", cfg.server_addr, cfg.server_port);
    let link = Arc::new(ServerLink::open(cfg.clone()).await?);
    info!(%server, "已连接到服务端，开始握手");

    let stream = link.connect().await?;
    // 私有能力只是**声明支持**，真正开不开看服务端回显 ——
    // 连官方 frps / 第三方 frps 时对方不会回显，行为与不开完全一致。
    let declared = msg::NfrpCaps {
        udp_binary: cfg.private_caps,
        server_cmd: cfg.private_caps,
    };
    // 每次（重）连都重新取一次凭证：OIDC 的 access token 会过期，
    // 复用上一次的会让"重连"变成"用过期 token 再失败一次"。
    // TokenSource 内部有缓存，没到期时不会真的去打 IdP。
    let cred = current_credential(&cfg, &token_source).await?;
    let (mut conn, run_id, udp_binary, caps) = conn::client_handshake(
        stream,
        link.wire,
        &cred,
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

    // 本地管理界面（`[webServer]`）的写请求通道。
    //
    // `_web_guard` 负责在会话结束时摘掉通道 —— 包括下面各种提前 `?` 返回。
    // 不摘的话，重连窗口期的请求会被投进一个没人读的队列，
    // 用户只能干等 20 秒超时，而不是立刻被告知"客户端没连上"。
    //
    // 没开管理界面时 `hub` 是 None：闭包不执行，`web_tx` 随之被丢弃，
    // `web_rx.recv()` 立刻返回 None，下面那个 select 分支被自动禁用。
    let (web_tx, mut web_rx) = tokio::sync::mpsc::unbounded_channel::<web::Request>();
    let _web_guard = hub
        .as_ref()
        .map(|h| web::SessionGuard::new(h.clone(), web_tx));

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
    // 代理表由 `main` 建好传进来（与本地管理界面共用同一张），这里**不重建** ——
    // 重建会把界面上刚加进去的代理抹掉。
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
                        let resp = apply_server_cmd(&proxies, &store, &cmd, &mut conn).await;
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
            // 本地管理界面（`[webServer]`）发来的写请求。
            //
            // 必须在这里处理：控制连接被本循环独占，也只有在这里才能
            // "一边等 `NewProxyResp`、一边顺手处理 `ReqWorkConn`" ——
            // 服务端正等着工作连接，慢一步它就认为本端掉线了。
            Some(req) = web_rx.recv() => {
                web::handle_request(
                    req,
                    &mut conn,
                    &link,
                    &run_id,
                    &proxies,
                    &store,
                    &health,
                    &cfg,
                )
                .await;
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
    store: &store::Store,
    cmd: &msg::ServerCmd,
    conn: &mut FrpConn,
) -> Result<()> {
    let result = match cmd.op.as_str() {
        msg::CMD_ADD_PROXY => add_proxy_cmd(proxies, store, cmd),
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
                // store 里也要删 —— 否则下次启动它又"复活"，而用户已经
                // 在面板上明确删过一次了
                if let Err(e) = store.remove(&name) {
                    warn!(proxy = %name, error = %e, "从 store 删除失败（内存里已移除）");
                }
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
fn add_proxy_cmd(
    proxies: &registry::ProxyTable,
    store: &store::Store,
    cmd: &msg::ServerCmd,
) -> Result<()> {
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
    // 动态加进来的代理要落盘，否则重启就丢（`[store] path` 没配时是空操作）
    if let Err(e) = store.put(&p) {
        // 落盘失败不该让"这次添加"失败：内存里已经生效、端口已经开了，
        // 告诉面板"失败"反而会让用户以为隧道没起来。
        warn!(proxy = %name, error = %e, "写入 store 失败：重启后这条代理会丢失");
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

    // UDP / SUDP 代理：工作连接上跑的是 UdpPacket 消息，交给专门的转发器。
    // SUDP（secret UDP）的数据面与普通 UDP 完全一致——都是一条专用工作连接
    // 上跑 UdpPacket 帧；差别只在它没有公网端口、访问方走 visitor 通道进来。
    if matches!(proxy.proxy_type.as_str(), "udp" | "sudp") {
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

    // ---- PROXY 协议：把真实客户端地址告诉内网服务 ----
    //
    // 不加这一段，后端看到的对端永远是从 frpc 自己发起的连接，来源地址变成
    // `127.0.0.1` —— 于是所有按 IP 做的限流 / 审计 / 风控全部失效。
    //
    // 头**写在内网服务这一侧**（顺序：先 PROXY 头，再真实业务数据），
    // 与官方 frpc 的 `HandleTCPWorkConnection` 完全一致：
    //
    // ```go
    // if baseCfg.Transport.ProxyProtocolVersion != "" && m.SrcAddr != "" && m.SrcPort != 0 {
    //     header := netpkg.BuildProxyProtocolHeaderStruct(connInfo.SrcAddr, connInfo.DstAddr, ...)
    // }
    // ...
    // if connInfo.ProxyProtocolHeader != nil {
    //     connInfo.ProxyProtocolHeader.WriteTo(localConn)
    // }
    // ```
    //
    // dst 的取值也照抄官方：`StartWorkConn.dst_addr` 为空时**回落 `127.0.0.1`**
    // （`if m.DstAddr == "" { m.DstAddr = "127.0.0.1" }`）。别自作聪明改用
    // `local_addr` 里的主机名 —— 官方就是回落到回环地址，后端收到的目的地址
    // 与真 frpc 不一致，会让"和官方行为对拍"这件事失去意义。
    if let Some(ver) = proxy.proxy_protocol_version() {
        if start.src_addr.is_empty() || start.src_port == 0 {
            debug!(
                proxy = %start.proxy_name,
                "服务端没下发来源地址（官方 frps 才有），PROXY 头跳过"
            );
        } else {
            let dst_ip = if start.dst_addr.trim().is_empty() {
                "127.0.0.1".to_string()
            } else {
                start.dst_addr.clone()
            };
            let src = util::resolve_addr(&format!("{}:{}", start.src_addr, start.src_port))
                .await
                .with_context(|| format!("解析 PROXY 头源地址 {} 失败", start.src_addr))?;
            let dst = util::resolve_addr(&format!("{}:{}", dst_ip, start.dst_port))
                .await
                .with_context(|| format!("解析 PROXY 头目的地址 {dst_ip} 失败"))?;
            let head = proxy_protocol::encode(&src, &dst, ver)
                .with_context(|| format!("生成 PROXY {ver} 头失败"))?;
            local_stream
                .write_all(&head)
                .await
                .context("向内网服务写 PROXY 头失败")?;
            debug!(
                proxy = %start.proxy_name,
                version = ver,
                %src,
                %dst,
                "已向内网服务发送 PROXY 协议头"
            );
        }
    }

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
            proxy_protocol_version: "v2".into(),
            transport: Default::default(),
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
    fn proxy_protocol_版本解析_两种写法都认() {
        // 官方写法：[proxies.transport] proxyProtocolVersion = "v2"
        let official = ProxyConfig {
            proxy_protocol_version: String::new(),
            transport: nfrp_common::config::ProxyTransportConfig {
                proxy_protocol_version: "v2".into(),
            },
            ..full_tcp_config()
        };
        assert_eq!(official.proxy_protocol_version(), Some("v2"));

        // 老式 INI / 早期 TOML 写法：代理顶层的 proxy_protocol_version
        let legacy = ProxyConfig {
            proxy_protocol_version: "v1".into(),
            transport: Default::default(),
            ..full_tcp_config()
        };
        assert_eq!(legacy.proxy_protocol_version(), Some("v1"));

        // 两处都写：transport 优先
        let both = ProxyConfig {
            proxy_protocol_version: "v1".into(),
            transport: nfrp_common::config::ProxyTransportConfig {
                proxy_protocol_version: "v2".into(),
            },
            ..full_tcp_config()
        };
        assert_eq!(both.proxy_protocol_version(), Some("v2"));
    }

    /// 写错的值（大小写、`"2"`、`"v3"`）**必须当作不启用**，而不是"非 v1 即 v2"。
    ///
    /// 官方是 `if version != "v1" { use v2 }` 的写法，于是 `"V2"` 这种大小写
    /// 差一个字母的配置会往用户后端灌一段二进制垃圾 —— 后端把它当业务数据，
    /// 报出来的是"协议错误"，没人会想到是 frpc 的配置拼错了。
    #[test]
    fn proxy_protocol_写错的值宁可不生效() {
        for bad in ["false", "2", "v3", "yes"] {
            let c = ProxyConfig {
                proxy_protocol_version: bad.into(),
                ..full_tcp_config()
            };
            assert_eq!(
                c.proxy_protocol_version(),
                None,
                "{bad:?} 不该被当成任何一版 PROXY 协议"
            );
            assert_eq!(c.has_invalid_proxy_protocol_version(), Some(bad.trim()));
        }
        // 大小写宽容：跑完 to_ascii_lowercase 之后能认
        let c = ProxyConfig {
            proxy_protocol_version: "V2".into(),
            ..full_tcp_config()
        };
        assert_eq!(c.proxy_protocol_version(), Some("v2"));

        // 空串 = 不启用，也不算"写错了"
        let c = ProxyConfig {
            proxy_protocol_version: String::new(),
            ..full_tcp_config()
        };
        assert_eq!(c.proxy_protocol_version(), None);
        assert_eq!(c.has_invalid_proxy_protocol_version(), None);
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
    /// `cargo run -p nfrp-server --example dump_frpc -- 17777`
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
        let cfg = nfrp_common::config::parse_client_toml(LOLIA_FRPC).unwrap();
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
        let cfg = nfrp_common::config::parse_client_toml(LOLIA_FRPC).unwrap();
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

    /// 测试用的"不落盘"的 store（`[store] path` 没配就是它）。
    fn no_store() -> store::Store {
        store::Store::from_config(&ClientConfig::default()).expect("默认配置永远不该失败")
    }

    /// 新增代理：本地表里要真的多出一条，且必须回一条成功回执。
    #[tokio::test]
    async fn 管理命令_新增代理() {
        let (mut me, mut peer) = cmd_pair();
        let table = registry::ProxyTable::default();
        apply_server_cmd(&table, &no_store(), &add_cmd("panel-web"), &mut me)
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
        apply_server_cmd(&table, &no_store(), &cmd, &mut me)
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
        apply_server_cmd(&table, &no_store(), &cmd, &mut me)
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

        apply_server_cmd(&table, &no_store(), &add_cmd("new"), &mut me)
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
        apply_server_cmd(&table, &no_store(), &cmd, &mut me)
            .await
            .expect("移除");
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
