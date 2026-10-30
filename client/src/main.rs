//! `nfrp-client`：frp v2 兼容的客户端（等价于原版 frpc）。
//!
//! 支持的代理类型：`tcp` / `udp` / `http` / `https` / `tcpmux` / `stcp` /
//! `xtcp` / `sudp`（与官方 frpc 一致；对应的 visitor 侧是 `stcp` / `xtcp` / `sudp`）。
//! 其中 http / https 在客户端侧与 tcp 无差别（服务端已经把 HTTP 语义处理完了，
//! 客户端只负责把裸字节转给内网服务）；stcp / xtcp 还额外支持 `[[visitors]]`
//! （作为接入方）。

mod health;
mod nlink;
mod p2p;
mod plugin;
mod plugin_bridge;
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
        mux::{MuxKeepalive, MuxSession},
        stream::BoxStream,
        tls,
    },
    proxy_protocol, throttle, util, ws,
};
use tokio::io::AsyncWriteExt;
use tokio::{
    net::{TcpSocket, TcpStream, UdpSocket},
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
    util::init_tracing(&level, &cfg.log_to, cfg.max_days, cfg.disable_print_color);

    // ★ v0.6.5：`auth.tokenSource` —— 从文件 / 外部命令取 token。
    //
    // 位置很关键：必须在 CLI 的 `-t/--token` **之后**、真正登录**之前**。
    // 语义与官方 `AuthClientConfig` 一致（注释原文 "mutually exclusive with
    // Token field"）：两者都配时**以 tokenSource 为准**并告警。
    //
    // CLI 显式给了 `-t` 是用户的即时意图，优先级最高；但只要 tokenSource
    // 存在且 CLI 没给，就走 tokenSource。
    if let Some(src) = cfg.auth.token_source.clone() {
        if cli.token.is_some() {
            debug!("命令行给了 -t/--token，本次忽略 auth.tokenSource");
        } else {
            // 先校验配置形状，把"写错 type / 缺子段"报在取 token 之前，
            // 错误信息才对得上用户写的配置
            src.validate()
                .with_context(|| "auth.tokenSource 配置有误")?;
            match src.kind.as_str() {
                "file" => {
                    let p = src
                        .file
                        .as_ref()
                        .map(|f| f.path.as_str())
                        .unwrap_or_default();
                    info!("认证令牌来自文件 [{}]", p);
                }
                "exec" => {
                    // exec 会执行外部程序，必须让审计日志能看见
                    let c = src
                        .exec
                        .as_ref()
                        .map(|e| e.command.as_str())
                        .unwrap_or_default();
                    info!("认证令牌来自外部命令 [{}]（以本进程身份执行）", c);
                }
                _ => {}
            }
            let resolved = src
                .resolve()
                .with_context(|| "从 auth.tokenSource 读取认证令牌失败")?;
            if !cfg.token.is_empty() && cfg.token != resolved {
                warn!(
                    "auth.token 与 auth.tokenSource 同时配置且值不同，\
                     按官方语义以 tokenSource 为准"
                );
            }
            cfg.token = resolved;
        }
    }

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
    // ★ v0.5.5（第四轮 F2/F3）：记住**哪些名字来自配置文件**。
    //
    // `merge_initial` 把 store 恢复的动态代理并进了 `cfg.proxies`，
    // 于是那份列表里配置代理与动态代理混在一起、看不出区别了。
    // 而代理表必须区分它们（远程下发只许动动态的），所以在合并**之前**
    // 先把配置里的名字记下来，构造表时据此打来源标记。
    let config_proxy_names: std::collections::HashSet<String> =
        cfg.proxies.iter().map(|p| p.name.clone()).collect();
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
    // ★ v0.5.5（第四轮 F2/F3）：配置来源的先建表，**store 恢复的再作为动态并入**。
    //
    // 不能一把 `from_iter(cfg.proxies)` 了事 —— 那样所有条目（含 store 恢复的
    // 动态代理）都会被标成 `Config`，于是面板连自己加的代理都删不掉了。
    let proxies = registry::ProxyTable::from_iter(
        cfg.proxies
            .iter()
            .filter(|p| config_proxy_names.contains(&p.name))
            .cloned(),
    );
    proxies.load_dynamic(
        cfg.proxies
            .iter()
            .filter(|p| !config_proxy_names.contains(&p.name))
            .cloned(),
    );

    // ★ v0.5.9 修（第九轮 D9-7，低危）：启动时**预检插件配置**。
    //
    // `Plugin::from_proxy` 是纯函数（不连网、不落盘），但原先只有工作连接
    // 真正建立时才会调用 —— 于是"Windows 上配了 unix_domain_socket 插件"
    // 这类**一眼可知**的错误要等到第一条用户流量进来，才在工作连接收尾里
    // 以 `debug`（默认看不见）留一句。这里在启动时逐条检查，一次说清。
    for p in cfg.proxies.iter() {
        if let Some(Err(e)) = plugin::Plugin::from_proxy(p) {
            warn!(
                proxy = %p.name,
                "代理的插件配置有问题，该代理将无法工作：{e:#}"
            );
        }
    }

    // 客户端本地管理界面（`[webServer]`）。
    //
    // `port` 为 0（默认）时整段都不执行：不绑端口、不起任务，
    // 与没有这个功能的版本**完全一致**。
    let hub = if cfg.web_server.is_enabled() {
        // ★ 安全检查必须在 **bind 之前**。
        //
        // 非回环 + 无凭据 = 任何能访问这个端口的人都能增删隧道、直接停止
        // 客户端。原先只打一条 warn 就放行。
        //
        // 这里必须 `bail!` 而不是"起了任务再在里面 return" —— 那样端口已经
        // 绑上了、监听已经在跑，日志写着"已拒绝启动"而实际开着，比不检查更糟。
        check_web_server_is_safe(&cfg)?;
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
        // 官方 `[webServer.tls]`：与 frps 面板同一套语义，配置 cert/key 后
        // 本地面板只接受 HTTPS。
        let tls_acceptor = match cfg.web_server.tls.files()? {
            Some((cert, key)) => {
                let tls = nfrp_common::frp::tls::server_config_from_pem_with_ca(cert, key, "")
                    .with_context(|| format!("加载客户端面板 HTTPS 证书失败（{cert} / {key}）"))?;
                Some(tokio_rustls::TlsAcceptor::from(tls))
            }
            None => None,
        };
        if tls_acceptor.is_some() {
            tokio::spawn(web::run_with_tls(listener, serving, tls_acceptor));
        } else {
            tokio::spawn(web::run(listener, serving));
        }
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
///
/// ★★ v0.5.7 修（第六轮审计 F-1，中危）：**必须跑完整启动校验，不能只解析配置**。
///
/// # 原先为什么错了
///
/// 原实现只调 `parse_client` 就报"配置校验通过"，而真正启动还会跑
/// [`check_web_server_is_safe`] 等启动期检查。实测
/// （`tmp/audit6-aclverify/verify_client_verify.py`）：
///
/// ```toml
/// [webServer]
/// addr = "0.0.0.0"    # 绑对外
/// port = 17300        # 且没配 user/password
/// ```
///
/// * `frpc verify` ⇒ **"配置校验通过"**（退出码 0）
/// * 真正启动 ⇒ **立刻退出**，报的是"请二选一：① 配 user+password；
///   ② 把 addr 改回 127.0.0.1；③ 显式写 allowInsecureRemote = true"
///
/// ⇒ 与服务端 `frps --check` 是**同一个毛病**（预检只做浅层校验），
///   属系统性缺陷而非某一处的疏漏。
///
/// # 为什么这个方向的假绿灯特别危险
///
/// 被漏掉的那条检查恰恰是**安全**检查（对外裸奔的管理界面 = 任何能访问
/// 该端口的人都能增删隧道、直接停掉客户端）。绿灯会让人**不去检查**它。
/// 本项目**此前已因"假绿灯"栽过一次**：`reject_unimplemented_plugin` 的注释里
/// 写着 `frpc verify` 对着未实现的插件回"配置校验通过"，用户拿绿灯上线、
/// 全量连接才逐个失败。
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
            // ★ v0.5.7（F-1）：与启动同口径的启动期校验。
            //
            // 注意**放在打印"通过"之前** —— 否则会先打"配置校验通过"
            // 再报错退出，用户（和解析输出的启动器）会被那句"通过"误导。
            // 这是本节修复的要点：不是"多跑一个检查"，而是
            // **"通过"这两个字必须只在校验全过之后才出现**。
            if let Err(e) = check_web_server_is_safe(&cfg) {
                eprintln!("配置校验失败：{}", path.display());
                eprintln!("{e:#}");
                std::process::exit(1);
            }

            println!("配置校验通过：{}", path.display());
            println!("  服务端：{}:{}", cfg.server_addr, cfg.server_port);
            println!(
                "  代理 {} 个 / 访客 {} 个",
                cfg.proxies.len(),
                cfg.visitors.len()
            );
            for p in &cfg.proxies {
                if p.plugin.is_empty() {
                    println!("    - [{}] {} -> {}", p.name, p.proxy_type, p.local_addr);
                } else {
                    // 插件代理不看 `localIP` / `localPort`，工作连接是交给插件的。
                    // 照直打会得到 `127.0.0.1:0`，看着像配错了 —— 显示插件的上游。
                    let up = if p.plugin_local_addr.is_empty() {
                        &p.local_addr
                    } else {
                        &p.plugin_local_addr
                    };
                    println!(
                        "    - [{}] {} + 插件 [{}] -> {}",
                        p.name, p.proxy_type, p.plugin, up
                    );
                }
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

/// 启动前检查 `[webServer]` 的鉴权配置是否安全。
///
/// **必须在 bind 之前调用** —— 这是"拒绝启动"与"起了一半"的分界：
/// 端口一旦绑上，管理界面就已经在服务了，此时再 `return` 只会留下
/// "日志说拒绝了、端口却开着"的误导状态。
///
/// 规则：监听非回环地址时**必须**配 `user`/`password`，除非显式写
/// `allowInsecureRemote = true` 表明知情。回环地址上留空是允许的
/// （默认值就是 127.0.0.1，只有本机能连）。
///
/// ★★ v0.5.6 修（审计总报告 H1，高危）：判据同时看 `user` **与** `password`。
///
/// 原先只判 `user.trim().is_empty()`，但上面这段注释写的是
/// "必须配 `user`/`password`" —— **注释与实现不符**（审计报告 H1 的 C 处）。
///
/// 为什么空密码必须算"没有凭据"：`web.rs` 的鉴权把两者拼成
/// `format!("{}:{}", user, password)` 再比 Basic 头，密码为空时期望值就是
/// `"admin:"` —— 任何能访问该端口的人送一个 `admin:` 就能进来，
/// 等于**鉴权退化成"知道用户名就能进"**。
///
/// ★ 与服务端共用同一个真源 `nfrp_common::config::has_dashboard_creds()`，
///   保证两端口径永不漂移。
fn check_web_server_is_safe(cfg: &ClientConfig) -> Result<()> {
    // 先校验 TLS 文件成对，避免端口已经绑定后才在启动路径深处失败。
    cfg.web_server.tls.files()?;
    let has_creds =
        nfrp_common::config::has_dashboard_creds(&cfg.web_server.user, &cfg.web_server.password);
    if !has_creds
        && !nfrp_common::util::is_loopback_addr(&cfg.web_server.addr)
        && !cfg.web_server.allow_insecure_remote
    {
        bail!(
            "管理界面配置为监听 {}:{} 却没有配置**完整的** user/password（两者都不能为空）—— \
             任何能访问这个端口的人都能增删你的隧道、并可直接停止客户端。\n\
             请二选一：① 配置 [webServer] user + password；\
             ② 把 addr 改回 127.0.0.1；\
             ③ 确实要裸奔就显式写 allowInsecureRemote = true（自担风险）。",
            cfg.web_server.addr,
            cfg.web_server.port
        );
    }
    Ok(())
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
    /// 本会话协商出来的 NLink 能力位（0 = 没协商）。
    ///
    /// 放在 `ServerLink` 而不是 `FrpConn` 上，是因为工作连接、visitor、
    /// web 面板都可能要读它，而它们只拿得到 `Arc<ServerLink>`。
    nlink_caps: std::sync::atomic::AtomicU64,
}

impl ServerLink {
    async fn open(cfg: Arc<ClientConfig>) -> Result<Self> {
        let wire = cfg.protocol.wire_version().ok_or_else(|| {
            anyhow!("当前版本尚未实现 NFrp 自研协议，请把 protocol 设为 frp-v1 或 frp-v2")
        })?;
        // QUIC 自带加密与多路复用，所以 tls / tcp_mux 这两层都跳过。
        //
        // NLink 的 QUIC 用另一个 ALPN（`nfrp-nlink`）与独立端口，
        // 优先级高于标准 `transport_protocol = "quic"`：两个都配时按 NLink 走
        // （否则 preamble 会发到只认 `nfrp-frp` 的端点上，握手失败）。
        let nlink_quic = cfg.nlink.enable
            && cfg.nlink.quic
            && cfg
                .nlink
                .features()
                .active()
                .contains(nfrp_common::nlink::CAP_QUIC);
        let quic = if nlink_quic {
            let addr = nlink_quic_server_addr(&cfg).await?;
            let (endpoint, conn) =
                frp::quic::connect_with_alpn(&addr, None, nfrp_common::nlink::ALPN).await?;
            info!(%addr, alpn = "nfrp-nlink", "NLink QUIC 传输已建立");
            Some((endpoint, conn))
        } else if is_quic(&cfg.transport_protocol) {
            let addr = quic_server_addr(&cfg).await?;
            let (endpoint, conn) = frp::quic::connect(&addr, None).await?;
            info!(%addr, "QUIC 传输已建立");
            Some((endpoint, conn))
        } else {
            None
        };

        let mux = if quic.is_none() && cfg.tcp_mux {
            let stream = raw_connect(&cfg).await?;
            // yamux 保活（限制①批次2，官方 `tcpMuxKeepaliveInterval`）：
            // 0 = 关闭看门狗（None），默认 30 秒。
            Some(MuxSession::new(
                stream,
                MuxKeepalive::from_secs(cfg.tcp_mux_keepalive_interval),
            ))
        } else {
            None
        };
        Ok(Self {
            cfg,
            wire,
            mux,
            quic,
            udp_binary: std::sync::atomic::AtomicBool::new(false),
            nlink_caps: std::sync::atomic::AtomicU64::new(0),
        })
    }

    /// 本会话协商出来的 NLink 能力位。
    pub(crate) fn nlink_caps(&self) -> nfrp_common::nlink::Caps {
        nfrp_common::nlink::Caps(
            self.nlink_caps
                .load(std::sync::atomic::Ordering::Relaxed),
        )
    }

    /// 登录成功后由 `run_session` 写入。
    fn set_nlink_caps(&self, caps: nfrp_common::nlink::Caps) {
        self.nlink_caps
            .store(caps.bits(), std::sync::atomic::Ordering::Relaxed);
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

    /// QUIC 连接当前的本地地址（迁移前后对比用）。非 QUIC 时为 None。
    fn quic_local_addr(&self) -> Option<std::net::SocketAddr> {
        self.quic
            .as_ref()
            .and_then(|(ep, _)| frp::quic::local_addr(ep))
    }

    /// 把 QUIC 连接的本地出口换到 `local`。
    ///
    /// quinn 靠连接 ID 识别连接，换源地址不会断开在途流 —— 这正是
    /// "从 WiFi 切到 4G 不用重连"的底层机制。
    async fn rebind_quic(&self, local: std::net::SocketAddr) -> Result<()> {
        let Some((ep, _)) = &self.quic else {
            bail!("当前连接不是 QUIC，无法迁移");
        };
        frp::quic::rebind(ep, local).await
    }
}

/// 网络切换自动迁移：每 5 秒看一次"到服务端的出口 IP 变了没"。
///
/// 用一个 `Weak` 持有 `ServerLink`：会话结束、链路被回收后这个任务自己退出，
/// 不会因为"迁移器还活着"把整条连接（以及它的 QUIC endpoint）留着不放。
///
/// 5 秒是"WiFi 切 4G 后用户能忍受的空窗"与"不要无谓唤醒"之间的折中：
/// 迁移本身是一次 `rebind`，不重建连接，所以快慢只影响切换后的恢复时间。
fn spawn_quic_migrator(link: std::sync::Weak<ServerLink>, cfg: Arc<ClientConfig>) {
    tokio::spawn(async move {
        let Ok(server) = nlink_quic_server_addr(&cfg).await else {
            return;
        };
        let mut ticker = interval(Duration::from_secs(5));
        loop {
            ticker.tick().await;
            let Some(link) = link.upgrade() else {
                break;
            };
            let Some(cur) = link.quic_local_addr() else {
                break;
            };
            let Some(ip) = outbound_ip(server).await else {
                continue;
            };
            if ip == cur.ip() {
                continue;
            }
            let target = std::net::SocketAddr::new(ip, 0);
            match link.rebind_quic(target).await {
                Ok(()) => info!(from = %cur, to = %target, "QUIC 连接已迁移到新的本地出口"),
                Err(e) => warn!("QUIC 连接迁移失败：{e:#}"),
            }
        }
    });
}

/// 到 `server` 的出口 IP：连一个 UDP socket（不发包）读本地地址。
///
/// 这是"取默认路由源地址"的常用办法：`connect` 只设置路由与本地端点，
/// 不会真的产生流量，也不需要任何外部服务配合。
async fn outbound_ip(server: std::net::SocketAddr) -> Option<std::net::IpAddr> {
    let any: std::net::SocketAddr = if server.is_ipv4() {
        "0.0.0.0:0".parse().ok()?
    } else {
        "[::]:0".parse().ok()?
    };
    let sock = UdpSocket::bind(any).await.ok()?;
    sock.connect(server).await.ok()?;
    Some(sock.local_addr().ok()?.ip())
}

/// 服务端 QUIC 地址（与 TCP 用同一个端口号，只是走 UDP）。
async fn quic_server_addr(cfg: &ClientConfig) -> Result<std::net::SocketAddr> {
    let s = format!("{}:{}", cfg.server_addr, cfg.server_port);
    util::resolve_addr(&s)
        .await
        .with_context(|| format!("解析服务端 QUIC 地址 {s} 失败"))
}

/// NLink QUIC 服务端地址：显式 `quic_addr` 优先，否则退回 `server_addr:server_port`。
async fn nlink_quic_server_addr(cfg: &ClientConfig) -> Result<std::net::SocketAddr> {
    let s = if cfg.nlink.quic_addr.trim().is_empty() {
        format!("{}:{}", cfg.server_addr, cfg.server_port)
    } else {
        cfg.nlink.quic_addr.trim().to_string()
    };
    util::resolve_addr(&s)
        .await
        .with_context(|| format!("解析 NLink QUIC 地址 {s} 失败（检查 [nlink] quic_addr）"))
}

/// 带 `dialServerTimeout` / `connectServerLocalIP` 的拨号（限制①批次1）。
///
/// 官方语义（`pkg/config/v1/connector.go` 的建连路径）：
/// * `dialServerTimeout`（默认 10 秒）—— 建连超时，**控制连接与每条新拨的
///   工作连接都过这里**（`tcpMux = true` 时工作连接复用控制连接，不再拨号）；
/// * `connectServerLocalIP` —— 拨号前把本地出口绑到指定 IP（官方注释：仅
///   TCP / WebSocket 协议有效，KCP 不支持；nfrp 同样只在 TCP 路径用它）；
/// * `dialServerKeepalive`（默认 7200 秒）—— 建连成功后给 socket 打开
///   `SO_KEEPALIVE` 并把空闲时长设为该值（`0` = 不打开）。
///
/// `dial_server_timeout = 0` 表示**不设超时**（跟随系统默认），与项目其它
/// 超时项"0 = 关掉这项"的约定一致（官方把 0 折算成 10，这里不复刻）。
async fn dial_server(cfg: &ClientConfig, addr: std::net::SocketAddr) -> Result<TcpStream> {
    let fut = async {
        if cfg.connect_server_local_ip.trim().is_empty() {
            return TcpStream::connect(addr).await.map_err(anyhow::Error::from);
        }
        let local = parse_local_bind(&cfg.connect_server_local_ip)?;
        let socket = match (local, addr) {
            (std::net::SocketAddr::V4(_), std::net::SocketAddr::V4(_)) => TcpSocket::new_v4(),
            (std::net::SocketAddr::V6(_), std::net::SocketAddr::V6(_)) => TcpSocket::new_v6(),
            _ => {
                return Err(anyhow!(
                    "connectServerLocalIP 与远端地址的协议族不一致：本地是 {local}，远端是 {addr}"
                ))
            }
        }?;
        // 本地端口默认取 0（让内核分配），与官方 `ResolveTCPAddr` 缺端口补 0 一致。
        socket
            .bind(local)
            .with_context(|| format!("绑定本地地址 {local} 失败"))?;
        socket.connect(addr).await.map_err(anyhow::Error::from)
    };
    let stream = if cfg.dial_server_timeout == 0 {
        fut.await
    } else {
        let limit = Duration::from_secs(cfg.dial_server_timeout);
        tokio::time::timeout(limit, fut).await.map_err(|_| {
            anyhow!(
                "等待建连超时（dialServerTimeout = {} 秒；设 0 可关闭该超时）",
                cfg.dial_server_timeout
            )
        })?
    }?;

    // TCP keepalive（限制①批次2，官方 `dialServerKeepalive`）：官方挂在拨号器
    // （`libnet.WithKeepAlive`）上，控制连接与每条新拨的工作连接都过这里，
    // 所以放在 `dial_server` 出口处一次覆盖。`0` = 不打开（项目约定）。
    if cfg.dial_server_keepalive > 0 {
        if let Err(e) = util::set_tcp_keepalive(&stream, cfg.dial_server_keepalive) {
            warn!(
                "设置 TCP keepalive 失败（dialServerKeepalive = {} 秒）：{e}",
                cfg.dial_server_keepalive
            );
        }
    }
    Ok(stream)
}

/// 解析 `connectServerLocalIP`：接受 `IP`（端口补 0）或 `IP:端口`。
///
/// 带方括号的 IPv6（`[::1]:0`）与裸 IPv6（`::1`，按整个字符串当地址解析、
/// 端口 0）都认；解析不出来就报错，不做猜测。
fn parse_local_bind(raw: &str) -> Result<std::net::SocketAddr> {
    let s = raw.trim();
    if s.is_empty() {
        return Err(anyhow!("connectServerLocalIP 是空串"));
    }
    // 先按完整 SocketAddr 解析（`1.2.3.4:0` / `[::1]:0`）
    if let Ok(sa) = s.parse::<std::net::SocketAddr>() {
        return Ok(sa);
    }
    // 再按裸 IP 解析（端口取 0）
    if let Ok(ip) = s.parse::<std::net::IpAddr>() {
        return Ok(std::net::SocketAddr::new(ip, 0));
    }
    Err(anyhow!(
        "connectServerLocalIP {s:?} 不是合法地址（应为 `IP` 或 `IP:端口`；\
         IPv6 带端口要写方括号，如 `[::1]:0`）"
    ))
}

/// 建立一条到服务端的底层连接（TCP，按需 TLS，按需 WebSocket）。
///
/// 套壳顺序与官方 frpc 一致：`TCP -> [TLS] -> [WebSocket]`，
/// yamux 由 [`ServerLink`] 再套在外面。
/// 把代理 URL 里的 `user:pass@` 抹掉，只留 `scheme://host:port`。
///
/// 代理密码写进日志是真实事故（日志会被收集、转发、贴到 issue 里），
/// 所以**每一处**打代理地址的地方都必须过这里。
fn redact_proxy(url: &str) -> String {
    match url.rsplit_once('@') {
        Some((_, rest)) => match url.split_once("://") {
            Some((scheme, _)) => format!("{scheme}://{rest}"),
            None => rest.to_string(),
        },
        None => url.to_string(),
    }
}

async fn raw_connect(cfg: &ClientConfig) -> Result<BoxStream> {
    // KCP 是另一条路：裸 UDP 上的可靠传输，TLS / WebSocket 那几层跟它没关系
    if is_kcp(&cfg.transport_protocol) {
        return kcp_connect(cfg).await;
    }
    let server = format!("{}:{}", cfg.server_addr, cfg.server_port);
    // ★ v0.6.6：配了 `dnsServer` 就用它解析服务端域名；
    // 没配就走系统 resolver（原路径，行为不变）。
    let addr = if cfg.dns_server.trim().is_empty() {
        util::resolve_addr(&server)
            .await
            .with_context(|| format!("解析服务端地址 {server} 失败"))?
    } else {
        nfrp_common::dns::resolve_addr_via(&cfg.dns_server, &server)
            .await
            .with_context(|| {
                format!(
                    "用自定义 DNS {} 解析服务端地址 {server} 失败",
                    cfg.dns_server
                )
            })?
    };
    // ★ v0.6.6：`transport.proxyURL` —— 走出站代理时直接拿到一条已建好的隧道流；
    // 不走代理时保持原样（TcpStream + nodelay）——零回归。
    //
    // 为什么代理路径跳过 `set_nodelay`：那个方法只在 `TcpStream` 上有，
    // 而代理链路上拿到的是 `BoxStream`（可能还包了 TLS）。
    // 代理链路上延迟主要来自代理本身，nodelay 作用有限。
    let stream: BoxStream = if cfg.proxy_url.trim().is_empty() {
        let s = dial_server(cfg, addr)
            .await
            .with_context(|| format!("连接 {addr} 失败"))?;
        s.set_nodelay(true).ok();
        Box::pin(s)
    } else {
        debug!(
            proxy = %redact_proxy(&cfg.proxy_url),
            %server,
            "通过代理连接服务端"
        );
        nfrp_common::net_proxy::connect(&cfg.proxy_url, &cfg.server_addr, cfg.server_port, None)
            .await
            .with_context(|| {
                format!(
                    "经代理 {} 连接服务端 {server} 失败",
                    redact_proxy(&cfg.proxy_url)
                )
            })?
    };

    let name = if cfg.tls_server_name.is_empty() {
        &cfg.server_addr
    } else {
        &cfg.tls_server_name
    };
    // `protocol = "wss"` 自带 TLS，不用再写一遍 `transport.tls.enable`。
    let tls_on = cfg.tls_enable || cfg.websocket_tls();

    // ★★ v0.5.8 修（第七轮审计 **B-2**，中危）：**`verifyServerCert = true`
    //    但 TLS 没开时必须显著告警** —— 否则这是"安全配置静默失效"。
    //
    // # 原先为什么危险
    //
    // `tls::connect_client`（`common/src/frp/tls.rs:312`）第一件事是
    // `if !enable { return Ok(Box::pin(stream)); }` ——
    // **`verify` 参数在 `enable == false` 时被完全忽略**，而原先这里
    // 只在 `tls_on` 为真时才打印"已开启证书校验"。于是：
    //
    // 用户配了 `verifyServerCert = true`，看到配置"校验通过"，
    // 以为**既加密又校验**；实际**两个都没有**，链路是明文。
    //
    // # 实测铁证（`tmp/audit7/b_independent/repro_b2_tls.py`，4/4）
    //
    // 抓链路首字节：
    // * 正确开 TLS ⇒ `17 16 03 01 …`（TLS 记录）✓
    // * 驼峰 `tlsEnable = true` + `verifyServerCert = true` ⇒ **明文**
    // * 只写 `verifyServerCert = true` ⇒ **明文**
    //
    // 明文里**直接可见凭据**：
    // ```text
    // {"version":"0.71.0","hostname":"NUO","os":"windows",
    //  "privilege_key":"35a8601c28fa58a4fdb819c451100ae6", …}
    // ```
    // 而 `privilege_key = md5(token + timestamp)` —— 拿到它**可以直接重放登录**。
    //
    // ★ 这一条还叠加了第二个坑：**同一结构体里命名风格混用**
    //   （`config.rs`）：`tls_verify_server_cert` 的 serde 名是驼峰
    //   `verifyServerCert`，而 `tls_enable` **没有任何 rename**（只能是
    //   `tls_enable`）。用户照着驼峰风格写 `tlsEnable = true`，
    //   **serde 静默丢弃**（不报错）⇒ `tls_enable` 保持 false ⇒ 触发本条。
    if cfg.tls_verify_server_cert && !tls_on {
        warn!(
            "配置里写了 `verifyServerCert = true`，但 **TLS 没有开启** —— \
             证书校验**不会生效**，且链路是**明文**：\
             登录凭据（privilege_key）可被链路上任何人嗅探并重放。\
             请同时配上 TLS：`[transport.tls] enable = true`（或 `tls_enable = true`）。"
        );
    }

    // ★ v0.5.6（L16）：`verifyServerCert = true` 时**真正校验**对端证书。
    //   默认 false ⇒ 与官方 frp 一致（`InsecureSkipVerify = true`），保互通。
    if cfg.tls_verify_server_cert && tls_on {
        info!(
            server_name = %name,
            trusted_ca = %if cfg.tls_trusted_ca_file.is_empty() {
                "（未配 trustedCaFile，只用内置根证书）".to_string()
            } else {
                cfg.tls_trusted_ca_file.clone()
            },
            "已开启服务端证书校验（verifyServerCert = true）"
        );
    }
    let stream = tls::connect_client(
        stream,
        &tls::ClientTlsOptions {
            enable: tls_on,
            server_name: name,
            disable_custom_first_byte: !cfg.tls_custom_first_byte,
            verify: cfg.tls_verify_server_cert,
            trusted_ca_file: &cfg.tls_trusted_ca_file,
            client_cert_file: &cfg.tls_cert_file,
            client_key_file: &cfg.tls_key_file,
        },
    )
    .await?;

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

/// 处理一条来自服务端的 NLink 扩展帧。
///
/// 只处理**服务端主动下发**的那几类；不认识的整帧忽略（前向兼容）。
async fn handle_nlink_frame(
    frame: &nfrp_common::nlink::Frame,
    nlink: &nlink::ClientNLink,
    link: &Arc<ServerLink>,
    run_id: &Arc<String>,
    proxies: &registry::ProxyTable,
    health: &Arc<health::Monitor>,
) {
    use nfrp_common::nlink::frame::{FrameKind, TAG_CODE, TAG_COUNT, TAG_DETAIL, TAG_IDENTITY, TAG_OK};

    match frame.kind {
        FrameKind::Identity => {
            if let Some(tok) = frame.tlvs.get_str(TAG_IDENTITY) {
                debug!("收到 NLink 身份令牌，之后的工作连接会出示它");
                nlink.set_identity(tok);
            }
        }
        FrameKind::ResumeResp => {
            let ok = frame
                .tlvs
                .get(TAG_OK)
                .and_then(|v| v.first().copied())
                .map(|b| b != 0)
                .unwrap_or(false);
            if ok {
                info!("NLink 断线续传成功：沿用上次的会话状态");
            } else {
                info!("NLink 续传票已过期或不存在，本次按新会话处理");
            }
        }
        FrameKind::BatchReq => {
            let count = frame
                .tlvs
                .get_u32(TAG_COUNT)
                .unwrap_or(1)
                .clamp(1, 256) as usize;
            debug!(count, "收到批量工作连接请求");
            for _ in 0..count {
                spawn_work_conn(
                    link.clone(),
                    run_id.clone(),
                    proxies.clone(),
                    health.clone(),
                    nlink::current(),
                );
            }
        }
        FrameKind::CompatResp => {
            let detail = frame.tlvs.get_str(TAG_DETAIL).unwrap_or_default();
            info!("服务端兼容性矩阵：{}", detail.trim_end());
        }
        FrameKind::Failure => {
            warn!(
                code = frame.tlvs.get_u32(TAG_CODE).unwrap_or(0),
                detail = %frame.tlvs.get_str(TAG_DETAIL).unwrap_or_default(),
                "服务端回报 NLink 失败"
            );
        }
        other => debug!(kind = ?other, "忽略 NLink 扩展帧"),
    }
}

/// 一次控制连接握手的完整尝试。
///
/// `with_preamble` 为 `false` 时走**标准模式**（连官方 frps 就是这条路径）。
/// 拆成独立函数是为了让"带 preamble 失败 → 回退重试"这段逻辑清晰可见，
/// 而不是在 `run_session` 里堆两层嵌套。
async fn handshake_once(
    cfg: &ClientConfig,
    link: &ServerLink,
    token_source: &Option<Arc<nfrp_common::auth::oidc::TokenSource>>,
    nlink: &nlink::ClientNLink,
    with_preamble: bool,
) -> Result<(FrpConn, String, bool, msg::NfrpCaps)> {
    let stream = link.connect().await?;
    // 私有能力只是**声明支持**，真正开不开看服务端回显 ——
    // 连官方 frps / 第三方 frps 时对方不会回显，行为与不开完全一致。
    let declared = msg::NfrpCaps {
        udp_binary: cfg.private_caps,
        server_cmd: cfg.private_caps,
        // ★ v0.5.5（第四轮 A-1）：**无条件**声明"我的工作连接会带凭证"。
        //
        // 这不是一个可选优化，而是客户端**真实行为**的声明：客户端
        // 一直都在工作连接上发 `auth_key(token, ts)`（`conn.rs` 的
        // `client_work_conn`），只是服务端以前不看它。
        // 服务端据这个位决定"对这条会话要求凭证"，从而能拒绝那些
        // 拿 run_id 冒充的伪造工作连接 —— 又不必对官方 frpc 提同样要求
        // （官方默认不带凭证，实测一刀切会把它挡死）。
        work_conn_cred: true,
    };
    // 每次（重）连都重新取一次凭证：OIDC 的 access token 会过期，
    // 复用上一次的会让"重连"变成"用过期 token 再失败一次"。
    // TokenSource 内部有缓存，没到期时不会真的去打 IdP。
    let cred = current_credential(cfg, token_source).await?;
    let pre = if with_preamble { nlink.preamble() } else { None };
    conn::client_handshake_with(
        stream,
        link.wire,
        &cred,
        &cfg.client_id,
        &cfg.user,
        &cfg.metas,
        cfg.pool_count,
        declared,
        pre,
    )
    .await
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
    // 走 NLink QUIC 且开了迁移时，起一个"出口 IP 变了就 rebind"的看门狗。
    if cfg.nlink.enable && cfg.nlink.quic && cfg.nlink.quic_migrate {
        spawn_quic_migrator(Arc::downgrade(&link), cfg.clone());
    }
    info!(%server, "已连接到服务端，开始握手");

    // NLink：一个进程一份状态（connection id 跨重连不变，续传要它）。
    let nlink = nlink::install(&cfg);
    let (mut conn, run_id, udp_binary, caps) =
        match handshake_once(&cfg, &link, &token_source, &nlink, true).await {
            Ok(v) => v,
            // ★ 自动回退：对端不认 preamble 时（官方 frps 会把 `NFRPLNK1` 当成
            //   v1 消息头直接报错），立刻用标准模式重连一次。用户只会在日志里
            //   看到一行 warn，隧道照常工作。
            Err(e) if nlink.want_preamble() => {
                warn!("NLink 握手未成功（对端可能不支持扩展层），自动回退标准模式：{e:#}");
                nlink.mark_fallback();
                handshake_once(&cfg, &link, &token_source, &nlink, false).await?
            }
            Err(e) => return Err(e),
        };
    link.udp_binary
        .store(udp_binary, std::sync::atomic::Ordering::Relaxed);
    if udp_binary {
        debug!("服务端选择了二进制 UDP 报文编码");
    }
    if caps.server_cmd {
        debug!("服务端已启用私有管理命令（面板可增删本端代理）");
    }
    match conn.nlink() {
        Some(st) => {
            link.set_nlink_caps(st.caps);
            info!(
                caps = %st.caps,
                trace = %st.trace,
                session = %st.session,
                "NLink v1 协商成功"
            )
        }
        None => {
            if nlink.want_preamble() {
                // preamble 发出去了但服务端没回显：按标准模式跑，本次进程不再尝试。
                warn!("服务端未回显 NLink 能力，按标准模式运行");
                nlink.mark_fallback();
            }
        }
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
        let mut msg = NewProxy::from_config(p, &cfg.user);
        // ★ 官方语义：`[transport].useEncryption` 是**客户端级**开关，作用于所有代理。
        // 代理级字段是 NFRP 的扩展（允许单条代理单独开），两者取或。
        // 服务端就是按这个字段决定要不要解密/解压的，漏传会导致"客户端加密、
        // 服务端明文透传"—— 用户看到的是能连上但数据全乱。
        msg.use_encryption |= cfg.use_encryption;
        msg.use_compression |= cfg.use_compression;
        conn.send_msg(&FrpMessage::NewProxy(msg)).await?;
    }

    let mut pending: std::collections::HashSet<String> =
        cfg.proxies.iter().map(|p| p.name.clone()).collect();
    while !pending.is_empty() {
        let event = tokio::time::timeout(Duration::from_secs(15), conn.recv_event())
            .await
            .context("等待 NewProxyResp 超时")??;
        let msg = match event {
            nfrp_common::frp::conn::ConnEvent::Msg(m) => Some(m),
            nfrp_common::frp::conn::ConnEvent::Closed => None,
            nfrp_common::frp::conn::ConnEvent::NLink(f) => {
                // 注册窗口期内就可能收到身份令牌 / 续传回执，必须立刻处理：
                // 令牌丢了会导致之后每一条工作连接都被服务端拒绝。
                handle_nlink_frame(&f, &nlink, &link, &run_id, &proxies, &health).await;
                continue;
            }
        };
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
                    nlink.clone(),
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
            nlink.clone(),
        );
    }

    let mut ticker = interval(Duration::from_secs(cfg.heartbeat_interval.max(1)));
    ticker.tick().await; // 丢掉立即触发的第一次
    let mut last_pong = std::time::Instant::now();

    loop {
        tokio::select! {
            event = conn.recv_event() => {
                let msg = match event? {
                    nfrp_common::frp::conn::ConnEvent::Msg(m) => m,
                    nfrp_common::frp::conn::ConnEvent::Closed => {
                        info!("服务端关闭了控制连接");
                        // 控制连接没了：还在等的打洞请求必须立刻失败，
                        // 否则 visitor 会干等到超时才回退中继
                        if let Some(route) = &p2p_route {
                            route.bus.clear();
                        }
                        break;
                    }
                    nfrp_common::frp::conn::ConnEvent::NLink(f) => {
                        handle_nlink_frame(&f, &nlink, &link, &run_id, &proxies, &health).await;
                        continue;
                    }
                };
                match msg {
                    FrpMessage::ReqWorkConn => {
                        debug!("收到 ReqWorkConn，建立工作连接");
                        spawn_work_conn(
                    link.clone(),
                    run_id.clone(),
                    proxies.clone(),
                    health.clone(),
                    nlink.clone(),
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
                        let resp = apply_server_cmd(&proxies, &cfg.user, &store, &cmd, &mut conn).await;
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
    user: &str,
    store: &store::Store,
    cmd: &msg::ServerCmd,
    conn: &mut FrpConn,
) -> Result<()> {
    let result = match cmd.op.as_str() {
        msg::CMD_ADD_PROXY => add_proxy_cmd(proxies, store, cmd),
        msg::CMD_REMOVE_PROXY => {
            let requested = cmd.proxy_name.clone();
            if requested.is_empty() {
                Err(anyhow!("remove_proxy 缺少 proxy_name"))
            } else {
                // ★★ v0.5.5（第四轮 F2）：**只许删动态代理，不许删配置里的**。
                //
                // 配置文件的语义是"本机用户写下的意图"，服务端不该有能力让它
                // 在运行期失效。实弹（`tmp/f2_remove_config_proxy.py`）：
                // 面板对配置里的 `victim-ssh` 发一条 remove，端口立刻连不上，
                // 客户端日志 `按服务端命令移除代理 proxy=victim-ssh total=0`。
                //
                // `remove_dynamic` 会对配置来源的条目返回 Err（带人话原因）。
                //
                // ★ v0.5.8 修（第八轮审计 F8-L2，低危）：**列表名字必须能直接删**。
                //
                // 面板列表展示的是线上全名 `{user}.{name}`；v0.5.8 起服务端
                // 下发的已是本地名，这里再兜一层：原样查不到时，剥掉本客户端
                // `user` 前缀再查 —— 覆盖"客户端先升级、服务端还是旧版"的
                // 滚动升级窗口（旧服务端转发的就是面板给的全名）。
                // 修复前客户端拿全名查本地表 ⇒ 拒删，而服务端侧已经摘干净 ⇒
                // 两端状态分裂、接口回 502 把"半成功"表达成失败。
                let mut name = requested.clone();
                let mut removed = proxies.remove_dynamic(&name);
                if matches!(removed, Ok(None)) {
                    let local = util::strip_user_prefix(user, &requested);
                    if local != requested {
                        let local = local.to_string();
                        let again = proxies.remove_dynamic(&local);
                        if !matches!(again, Ok(None)) {
                            name = local;
                            removed = again;
                        }
                    }
                }
                match removed {
                    Err(e) => Err(anyhow!(e)),
                    Ok(None) => {
                        // 把当前有哪些代理一并报回去 —— 面板上最常见的失败原因
                        // 就是名字打错，光说"没有"用户没法自查
                        let have = proxies.names().join(", ");
                        Err(anyhow!(
                            "本地没有名为 [{requested}] 的代理（当前有：{}）",
                            if have.is_empty() {
                                "无".to_string()
                            } else {
                                have
                            }
                        ))
                    }
                    Ok(Some(_)) => {
                        // store 里也要删 —— 否则下次启动它又"复活"，而用户已经
                        // 在面板上明确删过一次了
                        if let Err(e) = store.remove(&name) {
                            warn!(proxy = %name, error = %e, "从 store 删除失败（内存里已移除）");
                        }
                        info!(proxy = %name, total = proxies.len(), reason = %cmd.reason, "按服务端命令移除代理");
                        Ok(())
                    }
                }
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
    // ★ 服务端下发的配置**不能**只查 name/type 就照单全收。
    //
    // 走配置文件的代理要过类型 / 插件 / tcpmux 三道校验，而这条路径原先
    // 一道都不过。更要命的是 `ProxyConfig` 里混着「本机资源字段」——
    // `plugin_local_path`（读哪个文件）、`plugin_local_addr`（连哪个内网地址）、
    // `plugin_crt_path` / `plugin_key_path`（读哪对证书）。服务端能下发这些，
    // 就等于让它决定客户端去读本机哪个文件、连内网哪个地址。
    //
    // `is_remote = true` ⇒ 上述本机资源字段一律拒绝；类型/插件/tcpmux 照常校验。
    nfrp_common::config::validate_remote_proxy(&p, true)
        .map_err(|e| anyhow::anyhow!("服务端下发的代理配置未通过校验：{e}"))?;
    let name = p.name.clone();
    // ★★ v0.5.5（第四轮 F3）：**远程下发不许覆盖配置文件里的代理**。
    //
    // 这是"双杀"链条的第一环，也是必须堵的那一环：
    //   1. 服务端下发同名 `add_proxy(my-web)`（用户配置里已有 `my-web`）；
    //   2. 客户端 `insert` 覆盖 ⇒ **用户那条此刻已经没了**；
    //   3. 服务端 `register_proxy` 失败（端口被旧连接占着）⇒ 走回滚，
    //      再下发 `remove_proxy("my-web")`；
    //   4. 客户端按名删 ⇒ 删掉的是第 2 步塞进去的那条，
    //      **用户原本的配置永远不会被恢复**。
    //
    // 结果：一条**服务端自己都判为失败**（HTTP 400 "已回滚"）的命令，
    // 把用户的隧道永久打掉了（实弹 `tmp/f3b_rollback_kills_config_proxy.py`）。
    //
    // 只在第一步拒绝，整条链就断了 —— 用户的配置代理从头到尾没被动过。
    let existed = proxies
        .insert_dynamic(p.clone())
        .map_err(|e| anyhow::anyhow!(e))?
        .is_some();
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
    nlink: Arc<nlink::ClientNLink>,
) {
    tokio::spawn(async move {
        if let Err(e) = work_conn_flow(link, run_id, proxies, health, nlink).await {
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
    nlink: Arc<nlink::ClientNLink>,
) -> Result<()> {
    let stream = link.connect().await?;

    let ts = util::now_unix_secs() as i64;
    // NLink 身份令牌：协商了才带（`identity()` 为 None 时字段不出现）。
    let identity = nlink.identity();
    let (work, leftover, start) = conn::client_work_conn_with(
        stream,
        link.wire,
        &run_id,
        &link.cfg.token,
        ts,
        identity.as_deref(),
    )
    .await?;

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
        return udp_proxy::run(
            udp_conn,
            proxy.local_addr.clone(),
            proxy_name.to_string(),
            nfrp_common::config::clamp_udp_packet_size(link.cfg.udp_packet_size),
        )
        .await;
    }

    // 插件：工作连接直接接到插件上，不再连内网服务
    if let Some(built) = plugin::Plugin::from_proxy(&proxy) {
        let plug = built.with_context(|| format!("代理 [{}] 的插件配置有误", proxy.name))?;
        debug!(proxy = %start.proxy_name, "工作连接交给插件处理");
        // 真实客户端地址来自服务端下发的 `src_addr/src_port`：只有它能写进
        // `X-Forwarded-For`（工作连接的对端是 frps 自己，那是 `127.0.0.1`）。
        let src = if start.src_addr.is_empty() || start.src_port == 0 {
            None
        } else {
            util::resolve_addr(&format!("{}:{}", start.src_addr, start.src_port))
                .await
                .ok()
        };
        let ctx = plugin::Ctx {
            proxy_name: &start.proxy_name,
            src,
        };
        return plug.serve(work, leftover, &ctx).await;
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

    // ★★ 加密/压缩时 leftover 必须进 ProxyStream，不能直接写给内网服务！
    //
    // leftover 是读 StartWorkConn 时多读到的字节，它属于 **frps → frpc** 方向。
    // 明文时它就是用户请求的开头，直接写给内网服务是对的；
    // **但开了加密/压缩时它是密文/压缩流的前缀**，直接写会把内网服务
    // 破坏成倒时间头（实测：本地 HTTP 服务报 "Exception occurred during
    // processing of request"，然后不返回响应，客户端看到的就是超时）。
    //
    // 正确做法：把 leftover 当作 work 流的**前缀**，先拼回去，再包 ProxyStream。
    let need_wrap_early = proxy.use_encryption
        || link.cfg.use_encryption
        || proxy.use_compression
        || link.cfg.use_compression;
    if !leftover.is_empty() && !need_wrap_early {
        local_stream.write_all(&leftover).await?;
    }
    let work: nfrp_common::frp::stream::BoxStream = if need_wrap_early {
        Box::pin(nfrp_common::frp::stream::PrefixedStream::new(
            leftover, work,
        ))
    } else {
        work
    };
    let mut work = work;

    // 带宽限流：配了就按令牌桶限速，没配就走原路径（行为完全不变）
    let limit = throttle::parse_bandwidth(&proxy.bandwidth_limit).unwrap_or(0);

    // ★ v0.6.6：数据面加密 / 压缩（官方 transport.useEncryption / useCompression）
    //
    // 位置很关键：包在**工作连接**这一侧（`work` = 到 frps 的那条连接），
    // 内网服务那一侧（`local_stream`）保持明文 —— 与官方 `GetRealConn` 的
    // 包装方向一致。
    //
    // 不配时**一个字节都不多走**：`need_wrap` 为假直接走原路径，
    // 行为与之前完全一致。
    // ★ 官方语义：客户端级 `[transport]` 开关 + NFRP 的代理级开关，取或。
    let eff_enc = proxy.use_encryption || link.cfg.use_encryption;
    let eff_comp = proxy.use_compression || link.cfg.use_compression;
    if eff_enc || eff_comp {
        let key = eff_enc.then(|| nfrp_common::frp::v1::derive_key(link.cfg.token.as_bytes()));
        debug!(
            proxy = %start.proxy_name,
            enc = eff_enc,
            comp = eff_comp,
            "数据面已启用加密/压缩"
        );
        let wrapped = nfrp_common::frp::proxy_stream::ProxyStream::new(work, key, eff_comp);
        // relay_throttled 按值接收并要求 'static，所以这里把 wrapped 交出去
        let r = if limit > 0 {
            throttle::relay_throttled(wrapped, local_stream, limit, limit).await
        } else {
            let mut w = wrapped;
            util::relay_between(&mut w, &mut local_stream).await
        };
        if let Err(e) = r {
            debug!(proxy = %start.proxy_name, "转发中断：{e}");
        }
        return Ok(());
    }

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

    /// 限制①批次2：`dialServerKeepalive > 0` 时拨号成功返回的 socket 必须真的
    /// 开上 TCP keepalive；`0` 时保持内核默认（不开）。
    ///
    /// ★★ v0.5.10 修（云端 Linux 实测 `Connection refused (os error 111)`）：
    /// 原先的 accept task **只等一次连接就结束** ——
    ///
    /// ```rust
    /// tokio::spawn(async move { let _ = l.accept().await; });  // ← 只 accept 一次
    /// let s  = dial_server(&cfg,  addr)...;   // 第 1 次 OK
    /// let s2 = dial_server(&cfg0, addr)...;   // 第 2 次：listener 已 drop ⇒ ECONNREFUSED
    /// ```
    ///
    /// 本机（Windows）能过，是因为第 2 次 `connect` 恰好在 listener 被回收前
    /// 完成了三次握手；Linux 上 listener 一 drop 端口立即失效 ⇒ 稳定失败。
    ///
    /// ⇒ 改成**常驻 accept 循环**（与产品 `web::run` / `serve.rs` 的写法一致）。
    ///   本测试要验证的是 keepalive 的 setsockopt 行为，与 accept 次数无关。
    #[tokio::test]
    async fn dial_server_按配置开_keepalive() {
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap();
        tokio::spawn(async move {
            // 常驻：本测试会拨两次号
            while let Ok((stream, _)) = l.accept().await {
                drop(stream);
            }
        });

        let cfg = ClientConfig {
            dial_server_timeout: 5,
            dial_server_keepalive: 321,
            ..Default::default()
        };
        let s = dial_server(&cfg, addr).await.unwrap();
        assert!(
            util::tcp_keepalive_enabled(&s).unwrap(),
            "dialServerKeepalive > 0 时必须开 SO_KEEPALIVE"
        );
        #[cfg(unix)]
        assert_eq!(
            util::tcp_keepalive_idle(&s).unwrap(),
            std::time::Duration::from_secs(321),
            "空闲时长要等于 dialServerKeepalive"
        );

        // 0 = 不打开
        let cfg0 = ClientConfig {
            dial_server_timeout: 5,
            dial_server_keepalive: 0,
            ..Default::default()
        };
        let s2 = dial_server(&cfg0, addr).await.unwrap();
        assert!(
            !util::tcp_keepalive_enabled(&s2).unwrap(),
            "dialServerKeepalive = 0 时不得开"
        );
    }

    /// `connectServerLocalIP` 的解析：`IP`、`IP:端口`、带方括号的 IPv6 都要认，
    /// 垃圾输入要明确报错（限制①批次1）。
    #[test]
    fn connect_server_local_ip_解析() {
        let a = parse_local_bind("192.168.1.5").unwrap();
        assert_eq!(a.ip().to_string(), "192.168.1.5");
        assert_eq!(a.port(), 0);

        let a = parse_local_bind("192.168.1.5:1234").unwrap();
        assert_eq!(a.port(), 1234);

        let a = parse_local_bind("::1").unwrap();
        assert!(a.is_ipv6());
        assert_eq!(a.port(), 0);

        let a = parse_local_bind("[::1]:0").unwrap();
        assert!(a.is_ipv6());
        assert_eq!(a.port(), 0);

        assert!(parse_local_bind("not-an-ip").is_err());
        assert!(parse_local_bind("").is_err());
    }

    /// 测试里统一用的 `user`（真实场景就是 Lolia 那份配置里的 `user = '2569'`）。
    const USER: &str = "alice";

    /// ★ 回归测试：管理界面监听非回环却不配凭据，必须**拒绝启动**。
    ///
    /// 原先只打一条 warn 就放行 ⇒ 任何能访问该端口的人都能增删隧道、
    /// 直接停止客户端。而且这个检查必须在 bind **之前** —— 否则端口已经
    /// 在服务了，日志说拒绝了也没用。
    #[test]
    fn 管理界面对外监听却不配凭据必须拒绝启动() {
        let mut cfg = ClientConfig::default();
        cfg.web_server.port = 7400;
        cfg.web_server.addr = "0.0.0.0".into();
        let e = check_web_server_is_safe(&cfg)
            .expect_err("必须拒绝启动")
            .to_string();
        assert!(e.contains("user"), "错误里要点名该怎么修：{e}");

        // 配了用户名就能起
        cfg.web_server.user = "admin".into();
        cfg.web_server.password = "pw".into();
        assert!(check_web_server_is_safe(&cfg).is_ok());

        // 或者显式声明知情
        cfg.web_server.user.clear();
        cfg.web_server.allow_insecure_remote = true;
        assert!(check_web_server_is_safe(&cfg).is_ok());
    }

    /// 绑回环时不配凭据是合法的（默认配置就是这样），不能误伤。
    #[test]
    fn 管理界面只监听回环时不配凭据可以启动() {
        let mut cfg = ClientConfig::default();
        cfg.web_server.port = 7400;
        // 默认 addr 就是 127.0.0.1
        assert_eq!(cfg.web_server.addr, "127.0.0.1");
        assert!(check_web_server_is_safe(&cfg).is_ok());
    }

    /// 一个所有字段都填满独特值的 tcp 代理配置。
    fn full_tcp_config() -> ProxyConfig {
        ProxyConfig {
            proxy_protocol_version: "v2".into(),
            transport: Default::default(),
            use_encryption: false,
            use_compression: false,
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
            route_by_http_user: "hu-route".into(),
            multiplexer: "httpconnect".into(),
            bandwidth_limit: "1MB".into(),
            bandwidth_limit_mode: "server".into(),
            metas: [("pk".to_string(), "pv".to_string())].into_iter().collect(),
            // 限制①批次1：注解要随 NewProxy 透传（官方 `m.Annotations = c.Annotations`）
            annotations: [("example.com/team".to_string(), "infra".to_string())]
                .into_iter()
                .collect(),
            // `enabled` 不参与注册报文：`Some(false)` 的条目在解析期就被摘掉了
            //（官方 FilterClientConfigurers），注册时恒为 None。
            enabled: None,
            group: "web".into(),
            group_key: "gk".into(),
            health_check_type: "http".into(),
            health_check_timeout_s: 7,
            health_check_max_failed: 5,
            health_check_interval_s: 11,
            health_check_url: "/healthz".into(),
            health_check_http_headers: vec![nfrp_common::config::HttpHeader {
                name: "Authorization".into(),
                value: "Bearer x".into(),
            }],
            plugin: "http_proxy".into(),
            plugin_local_path: "/tmp/x".into(),
            plugin_strip_prefix: "/p".into(),
            plugin_user: "pu".into(),
            plugin_passwd: "pp".into(),
            plugin_local_addr: "127.0.0.1:9000".into(),
            plugin_crt_path: "/tmp/c.crt".into(),
            plugin_key_path: "/tmp/c.key".into(),
            plugin_host_header_rewrite: "plugin.internal".into(),
            plugin_request_headers: [("X-Plugin".to_string(), "yes".to_string())]
                .into_iter()
                .collect(),
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

    /// tcpmux 上报的字段对齐官方 `TCPMuxProxyConfig.MarshalToMsg`：
    /// `customDomains` / `subdomain` / `multiplexer` / `httpUser` / `httpPwd` /
    /// `routeByHTTPUser` —— **不带 `locations`**（官方那个结构体里没有这个字段）。
    #[test]
    fn tcpmux_carries_multiplexer_and_domain_routing() {
        let c = ProxyConfig {
            proxy_type: "tcpmux".into(),
            ..full_tcp_config()
        };
        let m = NewProxy::from_config(&c, USER);
        assert_eq!(m.proxy_name, "alice.web-a");
        assert_eq!(m.multiplexer, "httpconnect");
        assert_eq!(m.custom_domains, vec!["a.example.com".to_string()]);
        assert_eq!(m.subdomain, "sub");
        assert_eq!(m.http_user, "hu");
        assert_eq!(m.http_pwd, "hp");
        assert_eq!(m.route_by_http_user, "hu-route");
        // 不占端口、也没有路径前缀
        assert_eq!(m.remote_port, 0);
        assert!(
            m.locations.is_empty(),
            "官方 tcpmux 没有 locations，不能多发"
        );
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
        // 限制①批次1：注解必须跟着走（服务端只存不查，但报文要逐字段对齐官方）
        assert_eq!(tcp.annotations, c.annotations);

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
            // ★ v0.5.8（第七轮审计 E7 附带发现）：**必须给一个合法的 local_addr**。
            //
            // 原先这里是 `..Default::default()`（`local_addr` = 空串），
            // 于是这些用例**意外依赖了"空地址也会被接受"**这个行为。
            // 而空地址的 tcp 代理**必然连不上任何地方** ——
            // 面板却回「已生效」（实测见 `tmp/audit7/e/localip_bypass_probe.py`），
            // 属于"假绿灯"。v0.5.8 起远程下发**拒绝**空 `local_addr`。
            //
            // ⇒ 这是**有意的行为收紧**，测试数据跟上被测行为是正确的处置
            //   （与第六轮"冒烟脚本过时"同一处理原则：先分清是设计变更还是回归，
            //    确认是前者后再更新测试工件）。
            //
            // 给默认值还有个好处：像"不支持的代理类型必须被拒绝"这类用例
            // 现在能**先过** local_addr 检查，从而确保拒绝的原因真的是**类型**
            // —— 判据的区分力变强了。
            local_addr: "127.0.0.1:8080".to_string(),
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

    /// 造一条带某个插件字段的服务端管理命令。
    fn add_cmd_with(name: &str, f: impl FnOnce(&mut ProxyConfig)) -> msg::ServerCmd {
        let mut p = ProxyConfig {
            name: name.to_string(),
            proxy_type: "tcp".to_string(),
            // ★ 同上：默认给一个合法回环地址，避免用例意外依赖"空地址被接受"。
            local_addr: "127.0.0.1:8080".to_string(),
            remote_port: 7000,
            ..Default::default()
        };
        f(&mut p);
        msg::ServerCmd {
            id: "cmd-1".to_string(),
            op: msg::CMD_ADD_PROXY.to_string(),
            proxy_name: name.to_string(),
            proxy: Some(serde_json::to_value(&p).expect("序列化")),
            reason: "dashboard".to_string(),
        }
    }

    /// 造一条"移除代理"的服务端管理命令。
    fn remove_cmd(name: &str) -> msg::ServerCmd {
        msg::ServerCmd {
            id: "cmd-rm".to_string(),
            op: msg::CMD_REMOVE_PROXY.to_string(),
            proxy_name: name.to_string(),
            reason: "dashboard".to_string(),
            ..Default::default()
        }
    }

    /// ★ 回归测试：服务端**不能**用管理命令让客户端去读任意本机文件。
    ///
    /// `pluginLocalPath` 这类本机资源字段只该由本机配置文件指定。放行它的
    /// 后果是：服务端配一条 `plugin = "static_file"` + `localPath = "/etc"`
    /// 的代理，就能借公网端口把客户端本机的文件服务出去。
    /// 这几条字段曾经**完全没有校验**（只查 name/type 非空）。
    #[tokio::test]
    async fn 远程下发的_plugin_local_path_必须被拒绝() {
        for (field, set) in [
            (
                "pluginLocalPath",
                Box::new(|p: &mut ProxyConfig| p.plugin_local_path = "/etc".to_string())
                    as Box<dyn FnOnce(&mut ProxyConfig)>,
            ),
            (
                "pluginLocalAddr",
                Box::new(|p: &mut ProxyConfig| {
                    p.plugin_local_addr = "169.254.169.254:80".to_string()
                }),
            ),
            (
                "pluginCrtPath",
                Box::new(|p: &mut ProxyConfig| p.plugin_crt_path = "/etc/shadow".to_string()),
            ),
            (
                "pluginKeyPath",
                Box::new(|p: &mut ProxyConfig| p.plugin_key_path = "/etc/shadow".to_string()),
            ),
        ] {
            let (mut me, _peer) = cmd_pair();
            let table = registry::ProxyTable::default();
            let cmd = add_cmd_with("evil", set);
            let err = apply_server_cmd(&table, "", &no_store(), &cmd, &mut me)
                .await
                .expect_err(&format!("{field} 必须被拒绝"));
            let msg = err.to_string();
            assert!(msg.contains(field), "错误里要点名 {field}：{msg}");
            assert_eq!(table.len(), 0, "{field} 被拒时不该留下代理");
        }
    }

    /// ★★ v0.5.4 回归（H4）：服务端下发的 `local_addr` **只能指向本机回环**。
    ///
    /// 威胁模型：`local_addr` 决定客户端**往哪里连**（见本文件里
    /// `TcpStream::connect(local)`）。它原先不在远程黑名单里，于是不可信的
    /// 服务端/面板只要下发 `169.254.169.254:80`，就能让客户端去连**云元数据服务**
    /// —— 服务端可控的 SSRF。内网地址（`10.0.0.5:6379`）同理可做横向。
    #[tokio::test]
    async fn 远程下发的_local_addr_只能指向本机() {
        // —— 这些必须被拒 ——
        for bad in [
            "169.254.169.254:80", // 云元数据服务
            "10.0.0.5:6379",      // 内网 Redis
            "192.168.1.1:22",     // 内网主机
            "0.0.0.0:80",         // "监听全部"不是"连本机"
            "[fd00::1]:80",       // IPv6 内网
            "example.com:80",     // 域名（解析结果不可控）
        ] {
            let (mut me, _peer) = cmd_pair();
            let table = registry::ProxyTable::default();
            let cmd = add_cmd_with("ssrf", |p| p.local_addr = bad.to_string());
            let err = apply_server_cmd(&table, "", &no_store(), &cmd, &mut me)
                .await
                .expect_err(&format!("{bad} 必须被拒绝"));
            assert!(
                err.to_string().contains("local_addr"),
                "错误里要点名 local_addr：{err}"
            );
            assert_eq!(table.len(), 0, "{bad} 被拒时不该留下代理");
        }

        // —— 这些是合法用法，必须放行 ——
        //
        // ★★ v0.5.8（第七轮审计 **E-1**）修正：**`localhost` 从这份白名单里去掉了。**
        //
        // 原先这里把 `localhost:3000` 当作"合法的本机地址"放行。E-1 实测证明
        // 那个假设**不成立**：
        //
        // 在 `127.0.0.1:<P>` 与 `[::1]:<P>` 上各起一个诱饵（同端口号），
        // 远程下发 `local_addr = "localhost:<P>"` ⇒ 被接受，且流量命中
        // **v6** 诱饵（v4=0 / v6=1）—— 用户配的"本机 v4 服务"被绕到了另一个地址族。
        // （`tmp/audit7/e_independent/repro_e1_localhost.py`，9/9）
        //
        // 根因是**同一语义两套相反实现**：
        //   * `util::is_loopback_addr` 对 `localhost` 返回 **false**
        //     （注释写明"解析结果取决于 hosts 与 DNS，不能靠名字赌"）；
        //   * `config::is_loopback_host` 原先无条件返回 **true**；
        //   而守卫远程下发路径的是**后者**（弱的那套）。
        //
        // ⇒ 现在两边口径统一为"从严"：`localhost` **不再是**合法的远程下发地址。
        //   要连本机就写 `127.0.0.1` / `::1` —— 明确且不受 hosts/DNS 影响。
        //   本机配置文件里的 `localhost` 不受影响（这条检查只作用于远程下发）。
        for ok in ["127.0.0.1:8080", "127.0.0.2:9000", "[::1]:8080"] {
            let (mut me, _peer) = cmd_pair();
            let table = registry::ProxyTable::default();
            let cmd = add_cmd_with("local-ok", |p| p.local_addr = ok.to_string());
            apply_server_cmd(&table, "", &no_store(), &cmd, &mut me)
                .await
                .unwrap_or_else(|e| panic!("{ok} 是合法的本机地址，不该被拒：{e}"));
            assert_eq!(table.len(), 1, "{ok} 应当成功加入");
        }

        // ★ E-1：`localhost` 现在必须被拒（含大小写变体）。
        //   这是**有意的行为收紧**，不是回归 —— 理由见上面那段注释。
        for bad_host in ["localhost:3000", "LocalHost:3000", "LOCALHOST:3000"] {
            let (mut me, _peer) = cmd_pair();
            let table = registry::ProxyTable::default();
            let cmd = add_cmd_with("local-bad", |p| p.local_addr = bad_host.to_string());
            let err = apply_server_cmd(&table, "", &no_store(), &cmd, &mut me)
                .await
                .expect_err(&format!(
                    "{bad_host} 必须被拒（E-1）：它的解析结果取决于本机 hosts 与 DNS，\
                     判据不能靠名字赌"
                ));
            assert!(
                err.to_string().contains("local_addr"),
                "错误里要点名 local_addr：{err}"
            );
            assert_eq!(table.len(), 0, "{bad_host} 被拒时不该留下代理");
        }
    }

    // ------------------------------------------------------------------
    // 第四轮 F1：插件路径绕过 H4（远程下发开放代理）
    // ------------------------------------------------------------------

    /// ★★ F1 核心回归：远程下发**一律不许带插件**。
    ///
    /// 这是第四轮实弹打出来的高危（`tmp/audit4-verify-F1b.py`）：
    ///
    /// * H4 的回环检查有前提 —— `local_addr` 非空
    ///   （`config.rs` 里 `if !p.local_addr.trim().is_empty()`）；
    /// * 而插件路径**根本不需要 `local_addr`**；
    /// * `plugin` 这个"能力开关"本身又不在黑名单里。
    ///
    /// 三者叠加 ⇒ 下发 `local_addr="" + plugin="http_proxy"` 全部校验通过 ⇒
    /// 客户端那个公网端口变成**开放正向代理**，攻击者可现指定任意目标
    /// （内网横向 + 拿客户端当跳板隐藏来源）。
    ///
    /// 实测对照：同一目标 `192.168.3.15:17912`，普通代理被 400 拒，
    /// 换成 `plugin=http_proxy`/`socks5` 就 200 放行并取回内网数据。
    #[tokio::test]
    async fn 远程下发不得携带插件字段() {
        // 每一种都单独验证（不能只测一个组合）
        type Case = (&'static str, Box<dyn FnOnce(&mut ProxyConfig)>);
        let cases: Vec<Case> = vec![
            (
                "plugin",
                Box::new(|p: &mut ProxyConfig| p.plugin = "http_proxy".to_string()),
            ),
            (
                "plugin",
                Box::new(|p: &mut ProxyConfig| p.plugin = "socks5".to_string()),
            ),
            (
                "plugin",
                Box::new(|p: &mut ProxyConfig| p.plugin = "static_file".to_string()),
            ),
            (
                "pluginUser",
                Box::new(|p: &mut ProxyConfig| p.plugin_user = "u".to_string()),
            ),
            (
                "pluginPasswd",
                Box::new(|p: &mut ProxyConfig| p.plugin_passwd = "pw".to_string()),
            ),
            (
                "pluginHostHeaderRewrite",
                Box::new(|p: &mut ProxyConfig| p.plugin_host_header_rewrite = "x".to_string()),
            ),
            (
                "pluginStripPrefix",
                Box::new(|p: &mut ProxyConfig| p.plugin_strip_prefix = "/a".to_string()),
            ),
        ];

        for (label, set) in cases {
            let (mut me, _peer) = cmd_pair();
            let table = registry::ProxyTable::default();
            // ★ 关键：**local_addr 留空** —— 这正是绕开 H4 的那种形态
            let cmd = add_cmd_with("openproxy", |p| {
                p.local_addr = String::new();
                set(p);
            });
            let err = apply_server_cmd(&table, "", &no_store(), &cmd, &mut me)
                .await
                .expect_err(&format!("{label} 必须被拒绝（哪怕 local_addr 为空）"));
            assert!(
                err.to_string().contains(label),
                "错误里要点名 {label}：{err}"
            );
            assert_eq!(table.len(), 0, "{label} 被拒时不该留下代理");
        }
    }

    /// F1 的反向保护：**不带插件**的合法远程下发仍然要能用。
    ///
    /// 这一条防止"修得太狠" —— 面板的正常「添加代理」功能必须照旧工作。
    #[tokio::test]
    async fn 不带插件的远程下发仍然可用() {
        let (mut me, _peer) = cmd_pair();
        let table = registry::ProxyTable::default();
        let cmd = add_cmd_with("normal", |p| {
            p.local_addr = "127.0.0.1:8080".to_string();
            p.remote_port = 6100;
        });
        apply_server_cmd(&table, "", &no_store(), &cmd, &mut me)
            .await
            .expect("普通的回环代理应当照常放行");
        assert_eq!(table.len(), 1);
    }

    /// ★ 回归测试：服务端下发**不认识的插件类型**要在解析阶段就被拒。
    ///
    /// 原先这条路径一道校验都不过，拼错的插件名能一路溜到运行期，
    /// 变成"每条工作连接逐个失败"。
    ///
    /// ★ v0.5.5（第四轮 F1）调整：现在**任何**插件都不许远程下发，
    /// 所以这条用例改到**配置文件**路径去验证（`is_remote = false`）——
    /// "拼错的插件名要被解析阶段拦住"这个不变量本身仍然有效，
    /// 只是它的适用场景从"远程下发"变成了"本机配置"。
    #[test]
    fn 不认识插件类型在解析阶段被拒() {
        let mut p = ProxyConfig {
            name: "bad-plugin".into(),
            proxy_type: "tcp".into(),
            local_addr: "127.0.0.1:80".into(),
            plugin: "totally_made_up".into(),
            ..Default::default()
        };
        // 本机配置路径：仍然要走插件类型自检
        let err = nfrp_common::config::validate_remote_proxy(&p, false)
            .expect_err("本机配置里的未知插件类型也必须被拒");
        assert!(
            err.to_string().contains("totally_made_up"),
            "错误里要点名插件：{err}"
        );

        // 远程路径：连合法插件名都不许（F1 的更严不变量）
        p.plugin = "socks5".into();
        let err2 = nfrp_common::config::validate_remote_proxy(&p, true)
            .expect_err("远程下发不得携带任何插件");
        assert!(err2.to_string().contains("plugin"), "{err2}");
    }

    /// ★ 回归测试：服务端下发**不受支持的代理类型**要被拒。
    #[tokio::test]
    async fn 远程下发的不支持代理类型必须被拒绝() {
        let (mut me, _peer) = cmd_pair();
        let table = registry::ProxyTable::default();
        let cmd = add_cmd_with("bad-type", |p| p.proxy_type = "not-a-thing".to_string());
        let err = apply_server_cmd(&table, "", &no_store(), &cmd, &mut me)
            .await
            .expect_err("不支持的代理类型必须被拒绝");
        assert!(
            err.to_string().contains("not-a-thing"),
            "错误里要点名类型：{err}"
        );
        assert_eq!(table.len(), 0);
    }

    /// 新增代理：本地表里要真的多出一条，且必须回一条成功回执。
    #[tokio::test]
    async fn 管理命令_新增代理() {
        let (mut me, mut peer) = cmd_pair();
        let table = registry::ProxyTable::default();
        apply_server_cmd(&table, "", &no_store(), &add_cmd("panel-web"), &mut me)
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
        apply_server_cmd(&table, "", &no_store(), &cmd, &mut me)
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
        apply_server_cmd(&table, "", &no_store(), &cmd, &mut me)
            .await
            .expect_err("未知命令必须失败");
        assert!(expect_cmd_resp(&mut peer).await.error.contains("未知命令"));
    }

    /// 先加后删：整条生命周期要闭环。
    ///
    /// ★ v0.5.5（第四轮 F2）调整：原来这条用例删的是 `from_iter` 建进来的
    /// `"old"` —— 那是**配置来源**的代理，现在远程 `remove` 会（正确地）拒绝它。
    /// 也就是说这条测试原先在无意中**断言了 F2 那个漏洞**（面板能删配置代理）。
    /// 现在改成"加一条动态的、再删那条动态的"，生命周期照样闭环，
    /// 而配置代理必须原样留着 —— 下面多加了断言把这个不变量钉住。
    #[tokio::test]
    async fn 管理命令_先加后删() {
        let (mut me, mut peer) = cmd_pair();
        let table = registry::ProxyTable::from_iter([ProxyConfig {
            name: "old".into(),
            ..Default::default()
        }]);

        apply_server_cmd(&table, "", &no_store(), &add_cmd("new"), &mut me)
            .await
            .expect("新增");
        let _ = expect_cmd_resp(&mut peer).await;
        assert_eq!(table.len(), 2);

        // 删**动态加进来的**那条 —— 这是合法路径
        let cmd = msg::ServerCmd {
            id: "cmd-4".to_string(),
            op: msg::CMD_REMOVE_PROXY.to_string(),
            proxy_name: "new".to_string(),
            ..Default::default()
        };
        apply_server_cmd(&table, "", &no_store(), &cmd, &mut me)
            .await
            .expect("移除动态代理");
        let _ = expect_cmd_resp(&mut peer).await;
        assert_eq!(table.len(), 1, "删掉之后只剩配置里那条");
        assert!(table.get("new").is_none(), "动态那条应当被删掉");
        assert!(table.get("old").is_some(), "配置那条必须原样留着（F2）");

        // ★ 反向：远程删**配置来源**的代理必须被拒，且那条要还在
        let cmd = msg::ServerCmd {
            id: "cmd-5".to_string(),
            op: msg::CMD_REMOVE_PROXY.to_string(),
            proxy_name: "old".to_string(),
            ..Default::default()
        };
        apply_server_cmd(&table, "", &no_store(), &cmd, &mut me)
            .await
            .expect_err("删配置代理必须被拒（F2）");
        let resp = expect_cmd_resp(&mut peer).await;
        assert!(
            resp.error.contains("配置文件"),
            "回执要说清原因：{}",
            resp.error
        );
        assert!(table.get("old").is_some(), "被拒之后配置代理必须还在");
    }

    /// ★★ F3 回归：远程下发**同名** `add_proxy` 不得覆盖配置里的代理。
    ///
    /// 这是"双杀"链条的第一环：覆盖成功 → 服务端回滚发 remove →
    /// 用户的配置永久消失。堵住第一环，整条链就断了。
    #[tokio::test]
    async fn 管理命令_不得覆盖配置里的同名代理() {
        let (mut me, mut peer) = cmd_pair();
        let mut cfg = ProxyConfig {
            name: "my-web".into(),
            ..Default::default()
        };
        cfg.remote_port = 18202;
        let table = registry::ProxyTable::from_iter([cfg]);

        let cmd = add_cmd_with("my-web", |p| {
            p.remote_port = 9999;
            p.local_addr = "127.0.0.1:9".into();
        });
        apply_server_cmd(&table, "", &no_store(), &cmd, &mut me)
            .await
            .expect_err("覆盖配置代理必须被拒（F3）");
        let resp = expect_cmd_resp(&mut peer).await;
        assert!(
            resp.error.contains("配置文件"),
            "回执要说清原因：{}",
            resp.error
        );
        // 用户那条必须原样（端口没变）
        assert_eq!(
            table.get("my-web").expect("配置代理必须还在").remote_port,
            18202,
            "配置代理不该被改掉"
        );
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

    /// ★ v0.5.8（第八轮审计 F8-L2，低危）回归：面板列表里的**线上全名**
    /// 也要能直接删掉。
    ///
    /// 服务端 v0.5.8 起下发的已是本地名（`admin.rs` 剥了前缀）；这里覆盖
    /// "客户端先升级、服务端仍是旧版"的滚动升级窗口 —— 旧服务端转发的就是
    /// 面板给的全名。修复前客户端拿全名查本地表 ⇒ 拒删 ⇒ 服务端已摘、
    /// 客户端留条目（两端状态分裂，v2 回 502）。
    #[tokio::test]
    async fn 用线上全名也能删除动态代理() {
        let (mut me, _peer) = cmd_pair();
        let table = registry::ProxyTable::default();
        let user = "probeuser";

        // 动态加两条（`add_proxy_cmd` 会把它们放进"可被远程删除"的表）
        apply_server_cmd(&table, user, &no_store(), &add_cmd("web"), &mut me)
            .await
            .expect("动态添加 web");
        apply_server_cmd(&table, user, &no_store(), &add_cmd("web2"), &mut me)
            .await
            .expect("动态添加 web2");
        assert_eq!(table.len(), 2);

        // ① 旧服务端行为：下发**全名** `probeuser.web` —— 必须容错到本地名
        apply_server_cmd(
            &table,
            user,
            &no_store(),
            &remove_cmd("probeuser.web"),
            &mut me,
        )
        .await
        .expect("全名删除必须成功（剥本端 user 前缀兜底）");
        assert!(
            !table.names().iter().any(|n| n == "web"),
            "web 应已从本地表删除"
        );

        // ② 对照：下发本地名（v0.5.8 服务端的正常契约）
        apply_server_cmd(&table, user, &no_store(), &remove_cmd("web2"), &mut me)
            .await
            .expect("本地名删除应成功");
        assert_eq!(table.len(), 0);

        // ③ 窥探面：不相干的名字不能被"剥前缀"误删
        //     （user=probeuser，删 "alice.web" 时 strip 是恒等 ⇒ 仍应报"没有"）
        let err = apply_server_cmd(&table, user, &no_store(), &remove_cmd("alice.web"), &mut me)
            .await
            .expect_err("别人的前缀不该被剥");
        assert!(
            err.to_string().contains("alice.web"),
            "错误里保留原名：{err}"
        );
    }
}
