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

mod admin;
mod cli;
mod commands;
mod dial;
mod link;
mod session;
mod work_conn;

#[cfg(test)]
mod tests;

use std::{sync::Arc, time::Duration};

use anyhow::{anyhow, bail, Context, Result};
use clap::Parser;
use nfrp_common::{
    config::{default_config_path, ClientConfig, Protocol},
    frp::conn,
    util,
};
use tracing::{debug, error, info, warn};

pub(crate) use link::ServerLink;
pub(crate) use session::{current_credential, ClientSession};
pub(crate) use work_conn::spawn_work_conn;

use crate::{
    admin::{check_web_server_is_safe, cmd_status, cmd_stop, cmd_verify},
    cli::{Cli, Command},
    session::{run_session, SessionDeps},
};

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

    // `auth.tokenSource` —— 从文件 / 外部命令取 token。
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
    // 记住**哪些名字来自配置文件**。
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
    // 配置来源的先建表，**store 恢复的再作为动态并入**。
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

    // 启动时**预检插件配置**。
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
        // 安全检查必须在 **bind 之前**。
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

    // 进程生命周期内**是否成功登录过**。
    //
    // 登录成功后断线 → 按 `reconnect_interval` 无限重连；
    // 从未登录成功 → 区分"连不上"与"被服务端拒绝"：
    //   * 连不上（dial / DNS / 代理 / KCP(UDP) / 握手超时）：开机自启时网络、
    //     代理、UDP 通道都可能还没就绪，**必须退避重试**，不能被 loginFailExit
    //     一刀切杀掉进程；
    //   * 被拒绝（服务端已回包且明确报错）：重试不会变，按 `loginFailExit` 退出，
    //     让启动器把配置错误如实报出来。
    let logged_in_once = Arc::new(std::sync::atomic::AtomicBool::new(false));
    // 首次登录连续失败次数：只用于指数退避与日志升级（登录成功后不再累加）。
    let mut first_login_failures: u32 = 0;

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
        let mut retry_delay = Duration::from_secs(cfg.reconnect_interval);
        tokio::select! {
            r = fut => {
                match r {
                    Ok(()) => {
                        info!("与控制服务端的会话结束");
                        if let Some(h) = &hub {
                            h.note_session_error("控制连接已断开（正在重连）");
                        }
                    }
                    Err(e) => {
                        // 把失败原因也写进本地面板。
                        //
                        // 开机自启用 `frpc.vbs` 隐藏窗口拉起，没有控制台；
                        // 0.7.5 起进程又按退避策略持续重试、不再退出 ——
                        // 结果就是"进程活着、代理列表空白、却没有任何线索"。
                        // 面板（`[webServer]` 启用时）是唯一还能看到原因的地方。
                        if let Some(h) = &hub {
                            h.note_session_error(format!("{e:#}"));
                        }
                        if logged_in_once.load(std::sync::atomic::Ordering::SeqCst) {
                            // 已经成功登录过：这次只是普通断线。
                            error!("会话出错：{e:#}");
                        } else if is_login_rejected(&e) {
                            // 服务端明确拒绝（令牌错 / 用户被禁用 / 协议不兼容…）。
                            if cfg.login_fail_exit {
                                return Err(e).with_context(|| {
                                    format!(
                                        "登录 {}:{} 被服务端拒绝；已启用 loginFailExit（默认行为），\
                                         不再重试。loginFailExit 只对“服务端明确拒绝”生效 —— \
                                         连不上（网络/代理/KCP 未就绪）会自动退避重试。",
                                        cfg.server_addr, cfg.server_port
                                    )
                                });
                            }
                            warn!("服务端拒绝登录（loginFailExit = false，将继续重试）：{e:#}");
                        } else {
                            // 连不上：开机自启场景最常见的失败点。
                            first_login_failures = first_login_failures.saturating_add(1);
                            retry_delay = startup_retry_delay(first_login_failures);
                            if first_login_failures >= 5 {
                                error!(
                                    attempt = first_login_failures,
                                    delay = retry_delay.as_secs(),
                                    "首次登录连续失败（{e:#}）；{} 秒后继续重试。\
                                     若 serverAddr / 端口 / proxyURL 写错，请检查配置",
                                    retry_delay.as_secs()
                                );
                            } else {
                                warn!(
                                    attempt = first_login_failures,
                                    delay = retry_delay.as_secs(),
                                    "首次登录失败（网络 / 代理 / KCP(UDP) 可能尚未就绪），\
                                     {} 秒后重试：{e:#}",
                                    retry_delay.as_secs()
                                );
                            }
                        }
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

        info!("{} 秒后重连…", retry_delay.as_secs());
        tokio::select! {
            _ = tokio::time::sleep(retry_delay) => {}
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

/// 首次登录**连不上**时的重试间隔：1、2、4、8、10、10… 秒。
///
/// 与官方 frpc 的 `loopLoginUntilSuccess` 同一思路（`wait.FastBackoffManager`，
/// 起始 1 秒、翻倍、上限 10 秒）。上限 10 秒是为了让开机时"网络刚就绪"
/// 能在十秒内被接住，而不是退到几分钟后才重连。
fn startup_retry_delay(failures: u32) -> Duration {
    const CAP_SECS: u64 = 10;
    let secs = match failures {
        0 | 1 => 1,
        n => 1u64 << (n - 1).min(4), // 1,2,4,8,16 → 与上限取 min
    };
    Duration::from_secs(secs.min(CAP_SECS))
}

/// 登录阶段（拨号 + 握手 + 等 LoginResp）的墙钟上限。
///
/// 沿用 `dialServerTimeout`（官方默认 10 秒）。配 0（"不设拨号超时"）时这里
/// 仍取 10 秒 —— 登录阶段**不能**没有死线：KCP/UDP 的"连接"只是建本地
/// socket，服务端不存在时不会报错，只能靠这个上限把它变成一次可重试的失败。
pub(crate) fn login_stage_timeout(cfg: &ClientConfig) -> Duration {
    let secs = if cfg.dial_server_timeout == 0 {
        10
    } else {
        cfg.dial_server_timeout
    };
    Duration::from_secs(secs)
}

/// 这次失败是不是"服务端明确拒绝登录"。
///
/// 只有 [`conn::LoginRejected`] 才算；dial 失败、DNS 未就绪、代理/KCP 通道
/// 未起、等待 LoginResp 超时等都算**瞬时**失败 → 退避重试。
fn is_login_rejected(e: &anyhow::Error) -> bool {
    e.chain()
        .any(|cause| cause.downcast_ref::<conn::LoginRejected>().is_some())
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

#[cfg(test)]
mod startup_tests {
    use super::*;

    /// 开机自启回归：只有"服务端明确拒绝"才算致命，连不上必须继续重试。
    #[test]
    fn 首次登录失败分类_拒绝才算致命() {
        let rejected = anyhow::Error::new(conn::LoginRejected {
            message: "token 不正确".into(),
        });
        assert!(is_login_rejected(&rejected));
        // context 包一层也不能丢类型（实际链路里会带 `首次登录 …` 之类上下文）
        let wrapped = rejected.context("登录 1.2.3.4:7000 被拒绝");
        assert!(is_login_rejected(&wrapped));

        let dial = anyhow::Error::new(std::io::Error::new(
            std::io::ErrorKind::ConnectionRefused,
            "actively refused",
        ))
        .context("连接 127.0.0.1:1 失败");
        assert!(
            !is_login_rejected(&dial),
            "拨号失败是瞬时错误，必须走退避重试"
        );

        let timeout = anyhow!("等待登录应答超时（10 秒）：服务端未回 LoginResp");
        assert!(!is_login_rejected(&timeout), "登录超时同样必须重试");
    }

    /// 首次登录退避：1、2、4、8、10、10… 秒，有上限、不回到 0。
    #[test]
    fn 首次登录退避_指数增长且封顶() {
        let got: Vec<u64> = (1..=7).map(|n| startup_retry_delay(n).as_secs()).collect();
        assert_eq!(got, vec![1, 2, 4, 8, 10, 10, 10]);
        assert_eq!(startup_retry_delay(0).as_secs(), 1, "0 次也要有正延迟");
        assert_eq!(
            startup_retry_delay(u32::MAX).as_secs(),
            10,
            "溢出/极值都不能 panic，且仍要封顶"
        );
    }

    /// 登录阶段必须有墙钟上限：KCP/UDP 与"接通但不回包"都靠它变成可重试失败。
    #[test]
    fn 登录阶段超时_默认十秒_配零也兜底() {
        let mut cfg = ClientConfig::default();
        assert_eq!(login_stage_timeout(&cfg).as_secs(), 10);
        cfg.dial_server_timeout = 3;
        assert_eq!(login_stage_timeout(&cfg).as_secs(), 3);
        cfg.dial_server_timeout = 0;
        assert_eq!(
            login_stage_timeout(&cfg).as_secs(),
            10,
            "dialServerTimeout = 0（不设拨号超时）时登录阶段仍要死线"
        );
    }
}
