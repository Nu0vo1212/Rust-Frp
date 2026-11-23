//! 服务端启动与监听生命周期。
//!
//! 职责：`serve` / `serve_with` / `serve_on` / `serve_on_with` 的启动流程、
//! `preflight` 启动前校验、`limits_from` 配置折算、`log_limits` 启动日志、
//! `load_not_found_page` 404 页面预读、`ensure_protocol` 线协议校验，以及
//! 认证前连接失败日志折叠器 `CONN_END_LOG`。
//!
//! 锁顺序契约：启动期只在 `registry.set_*` / `attach_*` 上短暂持有 `Registry`
//! 内部锁，随后立刻 clone 出 `Arc` 交给 spawn 的后台任务；`log_limits` 读取
//! `registry.limits()` 时也只在本地完成。所有监听任务之后的锁序为
//! registry → client state → pool，本模块不持有任何长生命周期锁。
//!
//! 不变量：配置在启动期解析一次（监听地址、端口、证书、安全上下文），
//! 运行期只读；`CONN_END_LOG` 是全局单例，唯一的写者（`observe`）在 accept 任务里。

use std::{
    path::PathBuf,
    sync::{Arc, RwLock},
    time::Duration,
};

use anyhow::{Context, Result};
use nfrp_common::{
    config::{is_quic, ServerConfig},
    frp::{self, stream::BoxStream},
    util,
};
use tokio::net::{TcpListener, UdpSocket};
use tracing::{debug, error, info, warn};

use crate::{
    dashboard,
    registry::{Registry, ServerLimits},
    vhost::{self, VhostTable},
    vnet,
};

use super::conn::{handle_conn, handle_frp_stream, handle_stream};
use super::preauth::PreauthSlot;

/// ★★ v0.5.8（第七轮审计 A-1）：**认证前连接失败日志的折叠器**。
///
/// # 为什么是"折叠"而不是"限速"—— 这是实测踩出来的
///
/// 第一版只做了速率限制（20 条/秒）。复现时发现：**攻击者只要把速率压到
/// 配额以下就能继续写盘** ——
///
/// | 版本 | 慢速打（100 条/1.2s，低于配额）的日志增长 |
/// |---|---|
/// | 修复前 | 12500 B/轮（放大 **125×**） |
/// | 速率限制版 | 2549 B/轮（放大 **12.5×**，**仍然在涨**） |
///
/// ⇒ 速率限制对"慢速打"**结构性无效**。
///
/// 真正有界的是折叠：同一失败原因在一个窗口内只写**首条**，
/// 其余只累加计数，下个窗口写一条"已折叠 N 条"的汇总。
/// ⇒ 无论攻击者打多快多慢，**每窗口最多两条日志**，磁盘增长有**上界**。
///
/// 取 1 条/秒、突发 2 条：正常部署里"每秒一条同类连接失败"本身就值得注意，
/// 而汇总信息保证运维不会误以为风平浪静。
/// ⇒ 磁盘增长上界 ≈ 1 条/秒 × 125 B ≈ **0.4 MiB/小时**（修复前是 274 MiB/小时）。
static CONN_END_LOG: nfrp_common::util::FoldedLog = nfrp_common::util::FoldedLog::new(1.0, 2.0);

/// 由 [`ServerConfig`] 里的上限字段折算出来的结构体。
pub fn limits_from(cfg: &ServerConfig) -> ServerLimits {
    ServerLimits {
        max_total_conns: cfg.max_total_conns,
        max_clients: cfg.max_clients,
        max_conns_per_client: cfg.max_conns_per_client,
        max_pending_per_client: cfg.max_pending_per_client,
        max_proxies_per_client: cfg.max_proxies_per_client,
    }
}

/// 启动主循环时可选的附加信息（只有二进制入口会填，集成测试用默认值）。
#[derive(Default)]
pub struct ServeExtras {
    /// 配置文件路径：填了才会启用热重载。
    pub config_path: Option<PathBuf>,
    /// 日志热重载句柄：填了才能热改 `log_level`。
    pub log_handle: Option<nfrp_common::util::LogFilterHandle>,
}

/// 启动服务端主循环（含 HTTP/HTTPS vhost 端口），直到收到退出信号。
pub async fn serve(cfg: Arc<ServerConfig>, registry: Arc<Registry>) -> Result<()> {
    serve_with(cfg, registry, ServeExtras::default()).await
}

/// **启动前的完整校验** —— `frps --check` 应当走这条。
///
/// ★★ v0.5.7 修（第六轮审计 F-1，中危）：**预检必须与启动同口径**。
///
/// # 原先为什么错了
///
/// `--check` 只调用 `main.rs` 里的 `validate(&cfg)` 就返回，而真正启动走的
/// `serve_with` 还会构造 [`SecurityContext`]（`guard.rs::from_config`），
/// 那里有一整块**只在启动时**才跑的校验：
///
/// | 校验 | 位置 |
/// |---|---|
/// | `auth_cfg.validate()` | `guard.rs` |
/// | `acl.compile()`（CIDR 解析） | `guard.rs` |
/// | `rbac_config().compile()`（角色 / 端口范围） | `guard.rs` |
/// | `AuditLog::from_config()`（审计路径可写性） | `guard.rs` |
///
/// ⇒ 实测（`tmp/audit6-aclverify/verify_check_gap.py`）：
/// **`--check` 放过了 5/7 条"启动时必然失败"的配置**，包括
/// `deny = ["10.0.0.1/33"]`、`portRange = "abc"`、`portRange = "30000-20000"`。
///
/// 而 `guard.rs` 的注释原话是：
/// > 「任何一处配置写错都**在启动时报错**……尤其是 **CIDR / 端口范围这类
/// >   字符串**，写错了没人会主动去发现。」
///
/// —— 这句话描述的**正是** `--check` 应该覆盖的东西，而它恰恰漏了。
///
/// # 为什么这不是小事
///
/// `--check` 的 help 写着用途是「systemd reload 前的预检 / CI」。
/// 拿它的绿灯去上线 ⇒ **服务起不来**；更糟的是它**恰好覆盖安全相关配置**
/// （ACL、RBAC），绿灯会让人**不去检查**这些"写错了没人会主动发现"的部分。
/// 本项目**此前已因"假绿灯"栽过一次**：`reject_unimplemented_plugin` 的注释里
/// 写着 `frpc verify` 对着未实现的插件回"配置校验通过"，用户拿绿灯上线、
/// 全量连接才逐个失败 ⇒ 这是同一类问题的第二次出现。
///
/// # 副作用（如实说明）
///
/// 与启动一致：配了 `[audit] enable = true` 时**会创建审计日志目录与文件**。
/// 这是有意的 —— 审计路径不可写属于"启动时才炸"的那一类，预检就该发现它。
/// 不想要这个副作用就别开审计，或让 `--check` 指向一个可写的临时路径。
pub fn preflight(cfg: &ServerConfig) -> Result<()> {
    // 与 `serve_with` 启动路径**同一份**校验，只是不绑端口、不拉 JWKS。
    crate::guard::SecurityContext::from_config(cfg)?;
    // 限制①批次3：证书/私钥/CA 能否装载，必须在 --check 阶段就暴露，
    // 不能等到真正 TLS 握手时才报错。
    frp::tls::validate_server_tls_files(
        &cfg.tls_cert_file,
        &cfg.tls_key_file,
        &cfg.tls_trusted_ca_file,
    )?;
    // 面板 HTTPS 也在启动/`--check` 阶段验一遍证书，不能等到 bind 后才发现。
    if let Some((cert, key)) = cfg.web_tls().files()? {
        let _ = frp::tls::server_config_from_pem_with_ca(cert, key, "")
            .with_context(|| format!("加载面板 HTTPS 证书失败（{cert} / {key}）"))?;
    }
    crate::ssh_gateway::validate_config(cfg)?;
    Ok(())
}

/// [`serve`] 的完整版本：二进制入口用它把配置文件路径与日志句柄传进来。
pub async fn serve_with(
    cfg: Arc<ServerConfig>,
    registry: Arc<Registry>,
    extras: ServeExtras,
) -> Result<()> {
    // 官方 `natholeAnalysisDataReserveHours`（默认 168）是进程级策略，
    // 在监听前安装，避免首批 xtcp 会话仍用默认值。
    crate::nathole_official::configure_analysis_reserve(cfg.nathole_analysis_data_reserve_hours);
    // 直接调用 `serve_with` 的测试 / 嵌入方可能没在 Registry 上装插件，
    // 这里兜底一次；main 已装过则等价覆盖。
    if !cfg.http_plugins.is_empty() {
        registry.set_plugins(Arc::new(nfrp_common::plugin::PluginManager::from_config(
            &cfg.http_plugins,
        )?));
    }
    let port = cfg.frp_bind_port();
    let addr = util::resolve_addr(&format!("{}:{}", cfg.bind_addr, port))
        .await
        .with_context(|| format!("解析监听地址 {}:{} 失败", cfg.bind_addr, port))?;
    let listener = TcpListener::bind(addr)
        .await
        .with_context(|| format!("监听 {addr} 失败（端口可能被占用）"))?;
    serve_on_with(listener, cfg, registry, extras).await
}

/// 在一个**已经 bind 好**的监听器上跑主循环。
///
/// 拆出这个入口是为了集成测试：绑 `:0` 拿到内核分配的端口后，
/// 测试才知道该往哪里连；否则 serve 内部的端口只有它自己知道。
pub async fn serve_on(
    listener: TcpListener,
    cfg: Arc<ServerConfig>,
    registry: Arc<Registry>,
) -> Result<()> {
    serve_on_with(listener, cfg, registry, ServeExtras::default()).await
}

/// [`serve_on`] 的完整版本：额外启动内置面板与配置热重载。
pub async fn serve_on_with(
    listener: TcpListener,
    cfg: Arc<ServerConfig>,
    registry: Arc<Registry>,
    extras: ServeExtras,
) -> Result<()> {
    let addr = listener.local_addr().context("取不到监听地址")?;

    // 限制①批次3：自定义证书 / mTLS。必须在任何 accept_server 之前安装。
    frp::tls::configure_server_tls(
        &cfg.tls_cert_file,
        &cfg.tls_key_file,
        &cfg.tls_trusted_ca_file,
    )?;

    // 安全上下文：认证方式 / IP 白黑名单 / 角色权限 / 审计日志。
    //
    // ★ 编译失败必须**拦住启动**：配置里写错一个 CIDR 就静默退化成
    //   "没有访问控制"，那比起不来危险得多。
    let security = Arc::new(crate::guard::SecurityContext::from_config(&cfg)?);
    registry.set_security(security.clone());

    // NLink v1：把配置变成运行期对象。即使 `[nlink]` 没写，这里也会装一个
    // 「全关」的实例，后续所有 `registry.nlink()` 调用都不需要判空。
    let nlink_rt = Arc::new(crate::nlink::NLinkRuntime::from_config(
        &cfg,
        &cfg.effective_auth().token,
    ));
    if cfg.nlink.enable {
        if nlink_rt.enabled() {
            info!(
                caps = %nlink_rt.features.active(),
                resume_ttl = nlink_rt.resume_ttl().as_secs(),
                quic_listen = %cfg.nlink.quic_listen,
                "NLink v1 已启用"
            );
            // 续传的会话 ID / client_id 在 preamble 里，TLS 没强制时是明文。
            // 这本身不是提权：攻击者仍然需要一把能登录服务端的有效 token；
            // 但同一把共享 token 的持有者 / 链路上的观察者可以抢在客户端之前
            // 用同一个 session_id 续传。把边界显式写进启动日志，避免"以为
            // 续传自带认证"的误判。
            if nlink_rt
                .features
                .active()
                .contains(nfrp_common::nlink::CAP_RESUME)
                && !cfg.tls_force
            {
                warn!(
                    "NLink 断线续传已启用，但 transport.tls.force = false：\
                     续传会话 ID 与 client_id 走明文 preamble，\
                     拿到有效 token 的链路观察者可以抢先续传。\
                     生产环境请开 TLS；一次性 resume token 在后续版本补上。"
                );
            }
        } else {
            info!("NLink v1 开关打开但 `features` 为空：只协商、不启用任何扩展能力");
        }
    }
    registry.set_nlink(nlink_rt.clone());

    // ---- NLink QUIC 监听 ----
    //
    // 独立 UDP 端口 + 独立 ALPN（`nfrp-nlink`）：与标准 QUIC 传输
    // （`nfrp-frp`）互不干扰，一条流就是一条 frp 连接。
    //
    // 没开 `quic` 能力或 `quic_listen` 留空时这一段完全不执行。
    if nlink_rt.enabled()
        && nlink_rt
            .features
            .active()
            .contains(nfrp_common::nlink::CAP_QUIC)
        && !cfg.nlink.quic_listen.trim().is_empty()
    {
        let addr: std::net::SocketAddr = cfg.nlink.quic_listen.parse().with_context(|| {
            format!(
                "[nlink] quic_listen 不是合法地址：{:?}（应形如 0.0.0.0:7000）",
                cfg.nlink.quic_listen
            )
        })?;
        let endpoint = frp::quic::listen_with_alpn(&addr, nfrp_common::nlink::ALPN).await?;
        info!(
            addr = %endpoint.local_addr().map(|a| a.to_string()).unwrap_or_else(|_| addr.to_string()),
            alpn = "nfrp-nlink",
            "NLink QUIC 监听已启动"
        );
        let cfg_q = cfg.clone();
        let reg_q = registry.clone();
        frp::quic::spawn_stream_acceptor(endpoint, move |stream, peer| {
            let cfg = cfg_q.clone();
            let registry = reg_q.clone();
            async move {
                // 复用与 TCP 完全相同的入口：preamble 识别、认证、授权、
                // 能力协商都在 `handle_frp_stream` 里，两条传输没有分叉逻辑。
                if let Err(e) = handle_frp_stream(
                    Box::pin(stream),
                    peer,
                    cfg,
                    registry,
                    PreauthSlot::Deferred,
                    None,
                )
                .await
                {
                    debug!(%peer, "NLink QUIC 流结束：{e:#}");
                }
            }
        });
    }

    // ---- NLink 续传过期回收 ----
    //
    // 续传窗口内监听器 / 端口是被“故意留着”的；如果客户端再也不回来，
    // 必须有人到点把它们收掉。放在这里而不是 `suspend` 里边，是因为
    // “断开后没人再登录”正是最需要回收的场景 —— 只靠下一次登录顺带清理
    // 等于永远不清。
    //
    // 无条件启动（空表时几乎零成本）：配置热重载可能在运行中才打开
    // resume，回收任务不能依赖启动那一刻的开关。
    {
        let reg = registry.clone();
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(Duration::from_secs(5));
            ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            loop {
                ticker.tick().await;
                let n = reg.sweep_suspended();
                if n > 0 {
                    debug!(reclaimed = n, "回收过期的 NLink 续传会话");
                }
            }
        });
    }

    // group 负载均衡策略：默认 roundrobin（与官方 frp 的 channel fan-out 行为一致）。
    let lb = crate::registry::LbPolicy::parse(&cfg.lb_policy);
    registry.set_lb_policy(lb);
    if lb != crate::registry::LbPolicy::RoundRobin {
        info!(
            policy = lb.as_str(),
            "已启用非默认的 group 负载均衡策略（官方 frp 为 roundrobin）"
        );
    }
    // OIDC 模式下顺带拉一次 JWKS。拉不到只告警、不拦启动
    // （IdP 可能只是暂时不可达），期间登录会被明确拒绝而不是放行。
    if let Err(e) = security.refresh_oidc().await {
        error!(
            error = %e,
            issuer = %cfg.effective_auth().oidc.issuer,
            "拉取 OIDC JWKS 失败：暂时没有人能通过 OIDC 登录；\
             请检查 issuer 与网络，恢复后会自动重试"
        );
    }

    info!("nfrp-server 已启动：frp v2 协议，监听 {addr}");
    // ★ 这份清单必须与 `register_proxy` 的 match 分支一一对应。
    //   tcpmux 加进来时漏过一次：代理类型真能用，但启动日志里没有它，
    //   用户按日志判断"这个版本支不支持 tcpmux"会得到相反的结论。
    info!("支持的代理类型：tcp / udp / http / https / tcpmux / stcp / xtcp / sudp");
    let eff = cfg.effective_auth();
    info!(
        "认证方式 = {}，token = {}（{}）",
        eff.method.as_str(),
        if eff.token.is_empty() {
            "<空>"
        } else {
            "已设置"
        },
        if eff.method == nfrp_common::security::AuthMethod::Token && eff.token.is_empty() {
            "不安全：任何人都能连"
        } else {
            "已启用"
        }
    );
    log_limits(&registry, &cfg);

    // HTTP / HTTPS / tcpmux 虚拟主机端口（各自可选）
    if cfg.vhost_http_port.is_some()
        || cfg.vhost_https_port.is_some()
        || cfg.tcpmux_http_connect_port.is_some()
    {
        let table = Arc::new(VhostTable::default());
        registry.attach_vhosts(table.clone());

        // 自定义 404 页面**启动时读一次**常驻内存。
        // 若每个 404 都去读盘，这个配置项就成了"用磁盘 IO 拖垮服务端"的入口；
        // 而且官方 `getNotFoundPageContent()` 虽然每次读盘、读失败也只是回落到
        // 内置页，我们读一次失败时同样只警告 + 回落，行为对外一致。
        let not_found_page = load_not_found_page(&cfg.custom_404_page);

        let ports = [
            (cfg.vhost_http_port, vhost::VhostKind::Http),
            (cfg.vhost_https_port, vhost::VhostKind::Https),
            (cfg.tcpmux_http_connect_port, vhost::VhostKind::TcpMux),
        ];
        // ★ 限制①批次1：vhost 的 HTTP/HTTPS/tcpmux 监听跟随 `proxyBindAddr`
        //   （官方 `ProxyBindAddr` 的作用范围之一就是 vhost 端口；留空时
        //   = `bindAddr`，行为与老版本一致）。
        let proxy_host = cfg.effective_proxy_bind_addr();
        for (port, kind) in ports {
            let Some(vport) = port else { continue };
            let addr = util::resolve_addr(&format!("{proxy_host}:{vport}"))
                .await
                .with_context(|| format!("解析 vhost 地址 {proxy_host}:{vport} 失败"))?;
            let listener = vhost::bind(addr).await?;
            let mut opts = vhost::VhostOpts::new(kind, cfg.tcpmux_passthrough);
            if kind == vhost::VhostKind::Http {
                // 官方只给 http vhost 的 ReverseProxy 配了 ResponseHeaderTimeout，
                // https 是纯透传、tcpmux 是 CONNECT 回合，都没有"读响应头"这一步。
                opts = opts
                    .with_timeout(cfg.vhost_http_timeout())
                    .with_not_found_page(not_found_page.clone());
            }
            tokio::spawn(vhost::run_vhost(
                listener,
                table.clone(),
                vport,
                opts,
                registry.clone(),
            ));
        }
    }

    // 官方 `[sshTunnelGateway]`：SSH 反向隧道入口。
    if cfg.ssh_tunnel_gateway.enabled() {
        let bind_addr = cfg.bind_addr.clone();
        crate::ssh_gateway::run(cfg.clone(), registry.clone(), security.clone(), &bind_addr)
            .await?;
    }

    // xtcp 真 P2P：牵线用的 UDP 端口（不配置时 xtcp 自动退化成中继）
    if let Some(p2p_port) = cfg.p2p_port {
        let hub = crate::p2p::P2PHub::new();
        registry.attach_p2p(hub.clone());
        let addr = util::resolve_addr(&format!("{}:{}", cfg.bind_addr, p2p_port))
            .await
            .with_context(|| format!("解析 p2p 地址 {}:{} 失败", cfg.bind_addr, p2p_port))?;
        let sock = Arc::new(
            UdpSocket::bind(addr)
                .await
                .with_context(|| format!("监听 UDP {addr} 失败"))?,
        );
        // ★ v0.5.9（第九轮审计 E9-1）：牵线 UDP 也过 ACL（纵深防御，口径统一）。
        tokio::spawn(crate::p2p::run_rendezvous(sock, hub, registry.security()));
    }

    // 内置面板 + /metrics：与 frp 的 dashboard 一样是可选端口
    //
    // ★ v0.5.6 修（审计总报告 H1）：这是同一判定的**第五处**（审计报告漏列了它），
    //   原先同样只判 `dashboard_user.is_empty()`。必须用唯一真源，
    //   否则"用户名非空 + 密码为空"会初始化出 `Some(("admin", ""))`，
    //   而 `dashboard.rs` 会拿它去比 `"admin:"` —— 鉴权形同虚设。
    let (dash_user, dash_pwd) = cfg.effective_dashboard_creds();
    let has_dash_creds = nfrp_common::config::has_dashboard_creds(&dash_user, &dash_pwd);
    let dashboard_auth: dashboard::DashboardAuth = Arc::new(RwLock::new(if has_dash_creds {
        Some((dash_user, dash_pwd))
    } else {
        None
    }));
    if let Some(dport) = cfg.effective_dashboard_port() {
        // 防御性兜底：`validate()` 已经在启动路径上拦过一次，但这里再挡一次 ——
        // `serve_with` 是所有启动方式的必经之地（包括将来新加的加载路径、
        // 以及嵌进别的宿主程序时直接调它的场景）。面板无鉴权 + 非回环 =
        // 匿名者可写，这条不能只靠上游校验。
        // ★ v0.5.6（H1）：同样要判**密码**，不能只看用户名。
        if !has_dash_creds
            && !nfrp_common::util::is_loopback_addr(&cfg.bind_addr)
            && !cfg.allow_insecure_dashboard
        {
            anyhow::bail!(
                "拒绝启动面板：bind_addr = {:?} 是对外地址，但没有配置**完整的**凭据\
                 （dashboard_user 与 dashboard_pwd 都非空才行）。\
                 要么配齐用户名密码，要么把 bind_addr 改成 127.0.0.1，\
                 要么显式写 allow_insecure_dashboard = true。",
                cfg.bind_addr
            );
        }
        let addr = util::resolve_addr(&format!("{}:{}", cfg.bind_addr, dport))
            .await
            .with_context(|| format!("解析面板地址 {}:{} 失败", cfg.bind_addr, dport))?;
        let listener = TcpListener::bind(addr)
            .await
            .with_context(|| format!("监听 {addr} 失败（面板端口可能被占用）"))?;
        // 官方 `[webServer.tls]`：cert/key 同时配置时整个面板只接受 HTTPS。
        // 证书加载失败直接阻止启动，不能静默退回 HTTP。
        let tls_acceptor = match cfg.web_tls().files()? {
            Some((cert, key)) => {
                let tls = frp::tls::server_config_from_pem_with_ca(cert, key, "")
                    .with_context(|| format!("加载面板 HTTPS 证书失败（{cert} / {key}）"))?;
                Some(tokio_rustls::TlsAcceptor::from(tls))
            }
            None => None,
        };
        tokio::spawn(dashboard::run_with_tls(
            listener,
            registry.clone(),
            dashboard_auth.clone(),
            cfg.clone(),
            tls_acceptor,
        ));
    }

    // 配置热重载：改完日志级别/面板密码不用重启
    if cfg.hot_reload {
        if let Some(path) = extras.config_path.clone() {
            // ★ watch 持有这份快照的**所有权**（`Arc<ServerConfig>` 按值传入，
            // 由它自己 `current = Arc::new(new)` 更新），所以这里给它一份克隆。
            // 关键点是它**内部会更新自己那份**，不再像 v0.5.2 那样拿一份永不
            // 更新的启动快照做 diff（那会导致「改回去不生效」的不可逆状态）。
            tokio::spawn(crate::reload::watch(
                path,
                cfg.clone(),
                extras.log_handle.clone(),
                dashboard_auth.clone(),
            ));
        } else {
            warn!("配置了 hot_reload 但没有传入配置文件路径，已跳过");
        }
    }

    // VirtualNet 虚拟网络：单独一个端口，不配就完全不启用（默认）。
    if let Some(vport) = cfg.vnet_listen_port() {
        // 配置写错必须拦住启动：网段/网关联不对，客户端连上来也只会拿到
        // 一堆莫名其妙的分配结果，不如当场报出来。
        let hub = Arc::new(vnet::VnetHub::from_config(&cfg)?);
        registry.attach_vnet(hub.clone());
        let addr = util::resolve_addr(&format!("{}:{}", cfg.bind_addr, vport))
            .await
            .with_context(|| format!("解析 VirtualNet 地址 {}:{} 失败", cfg.bind_addr, vport))?;
        let listener = TcpListener::bind(addr)
            .await
            .with_context(|| format!("监听 VirtualNet {addr} 失败"))?;
        info!("VirtualNet 虚拟网络已监听 {addr}（三层转发，客户端需 root/CAP_NET_ADMIN）");
        tokio::spawn(vnet::run(listener, hub, registry.clone()));
    }

    // QUIC 传输。
    //
    // ★ v0.6.5：**优先用独立的 `quicBindPort`**（对齐官方 frps 语义）。
    //
    // 旧行为是"`transport_protocol = quic` 时在 `bindPort` 的同名 UDP 端口
    // 上额外监听"，客户端没法指定别的端口。现在：
    //
    // * 配了 `quicBindPort` ⇒ 只在那个端口开 UDP，**不再**顺带占 `bindPort/udp`
    //   （避免"我配了 7101，为什么 7000/udp 也被占"这种困惑）；
    // * 没配 `quicBindPort` 且 `transport_protocol = quic` ⇒ 退回旧行为
    //   （`bindPort` 同名 UDP），保持老部署不变。
    //
    // 两种情况都**保留 TCP 监听**：老客户端照旧能连，切传输协议不会一刀切。
    let quic_port = cfg.quic_bind_port.or_else(|| {
        if is_quic(&cfg.transport_protocol) {
            Some(addr.port())
        } else {
            None
        }
    });

    if let Some(qport) = quic_port {
        let qaddr = util::resolve_addr(&format!("{}:{}", cfg.bind_addr, qport))
            .await
            .with_context(|| format!("解析 QUIC 地址 {}:{} 失败", cfg.bind_addr, qport))?;
        let endpoint = frp::quic::listen(&qaddr)
            .await
            .with_context(|| format!("监听 QUIC {qaddr} 失败"))?;
        info!(
            "QUIC 传输已启用，UDP {}（来自 {}）",
            endpoint
                .local_addr()
                .ok()
                .map(|a| a.to_string())
                .unwrap_or_default(),
            if cfg.quic_bind_port.is_some() {
                "quicBindPort"
            } else {
                "transport_protocol = quic"
            }
        );
        let cfg2 = cfg.clone();
        let registry2 = registry.clone();
        tokio::spawn(async move {
            while let Some(incoming) = endpoint.accept().await {
                let cfg = cfg2.clone();
                let registry = registry2.clone();
                tokio::spawn(async move {
                    let conn = match incoming.accept() {
                        Ok(c) => match c.await {
                            Ok(c) => c,
                            Err(e) => {
                                debug!("QUIC 握手失败：{e}");
                                return;
                            }
                        },
                        Err(e) => {
                            debug!("接受 QUIC 连接失败：{e}");
                            return;
                        }
                    };
                    let peer = conn.remote_address();
                    // 每条双向流 = 一条独立的 frp 连接（控制 / 工作 / visitor 都走这里）
                    while let Ok((send, recv)) = conn.accept_bi().await {
                        let cfg = cfg.clone();
                        let registry = registry.clone();
                        tokio::spawn(async move {
                            let stream: BoxStream =
                                Box::pin(frp::quic::QuicStream::new(send, recv));
                            if let Err(e) = handle_stream(stream, peer, cfg, registry, true).await {
                                debug!(%peer, "QUIC 流结束：{e:#}");
                            }
                        });
                    }
                });
            }
        });
    }

    // KCP 传输：**独立** UDP 端口（官方 frps 的 `kcpBindPort`）。
    //
    // KCP 是裸 UDP 上的可靠传输，没有 QUIC 那种"先握手再分流"的能力，
    // 只能另开端口靠源地址区分客户端（见 `KcpListener` 的注释）。
    // 上面跑的仍然是 yamux + frp，所以 `tcp_mux` 开关对它同样生效。
    if let Some(kport) = cfg.kcp_bind_port {
        let kaddr = util::resolve_addr(&format!("{}:{}", cfg.bind_addr, kport))
            .await
            .with_context(|| format!("解析 KCP 地址 {}:{} 失败", cfg.bind_addr, kport))?;
        // ★ v0.6.2：会话上限可配（默认 1024，约 15 MB 峰值）。
        //
        // 这是内存上界的**唯一**决定因素：KCP 每会话约 15.3 KB。
        // 超大规模部署应该拆实例或改用 TCP/QUIC 承载控制连接，
        // 而不是无限调大这个值。
        let max_sess = if cfg.kcp_max_sessions == 0 {
            nfrp_common::frp::kcp::MAX_KCP_SESSIONS
        } else {
            cfg.kcp_max_sessions
        };
        let listener = frp::kcp::KcpListener::bind(kaddr)
            .await
            .with_context(|| format!("监听 KCP {kaddr} 失败（端口可能被占用）"))?
            .with_max_sessions(max_sess);
        info!(
            "KCP 传输已启用，UDP {kaddr}（TCP {addr} 照旧可用），会话上限 {}",
            listener.max_sessions()
        );
        let cfg2 = cfg.clone();
        let registry2 = registry.clone();
        tokio::spawn(async move {
            loop {
                match listener.accept().await {
                    Ok((stream, peer)) => {
                        let cfg = cfg2.clone();
                        let registry = registry2.clone();
                        tokio::spawn(async move {
                            let stream: BoxStream = Box::pin(stream);
                            // secure=false：KCP 不自带加密，按 tcp_mux 走 yamux 探测
                            if let Err(e) = handle_stream(stream, peer, cfg, registry, false).await
                            {
                                debug!(%peer, "KCP 会话结束：{e:#}");
                            }
                        });
                    }
                    Err(e) => {
                        // 单个收包错误不该把整个监听循环打死
                        warn!("KCP accept 失败：{e}");
                        tokio::time::sleep(Duration::from_millis(50)).await;
                    }
                }
            }
        });
    }

    let shutdown = util::shutdown_signal();
    tokio::pin!(shutdown);

    loop {
        tokio::select! {
            accepted = listener.accept() => {
                let (stream, peer) = accepted.context("accept 失败")?;
                // 主端口 TCP keepalive（限制①批次2，官方 `tcpKeepalive`：
                // 官方在 `bind_port` 主监听器上 `SetKeepAlive`，作用范围一致）。
                // `0` = 不打开（项目约定）。
                if cfg.tcp_keepalive > 0 {
                    if let Err(e) = util::set_tcp_keepalive(&stream, cfg.tcp_keepalive) {
                        warn!(
                            %peer,
                            "设置 TCP keepalive 失败（tcpKeepalive = {} 秒）：{e}",
                            cfg.tcp_keepalive
                        );
                    }
                }
                let cfg = cfg.clone();
                let registry = registry.clone();
                tokio::spawn(async move {
                    if let Err(e) = handle_conn(stream, peer, cfg, registry).await {
                        // ★★ v0.5.8 修（第七轮审计 **A-1**，中危）：**限流这条 WARN**。
                        //
                        // # 原先为什么错了
                        //
                        // 这是**认证之前**的连接失败日志，而每一条连接失败都会
                        // 走这里。触发成本极低：连上 `bind_port` 后发**一个非法字节**
                        // （或直接连接后关闭）即可。
                        //
                        // 实测（`tmp/audit7/a/a22_final_log_amplification.py`）：
                        //
                        // | 指标 | 实测值 |
                        // |---|---|
                        // | 放大比 | **125×**（1 字节上行 ⇒ 125 字节日志） |
                        // | 速率 | **77.9 KiB/s ≈ 274 MiB/小时** |
                        // | 对照组（合法登录） | **0.99×**（无放大） |
                        // | 轮转 | 按天，**无大小上限** ⇒ 当天写入不受约束 |
                        //
                        // ⇒ **未认证的对手可以用极小带宽把日志盘打满**。
                        //   而服务端**不会崩溃**（RSS 稳定、进程存活），所以极易被忽视。
                        //
                        // # 修法（第二版，折叠而非限速）
                        //
                        // 只**折叠日志**，不改任何行为：连接照常拒绝、审计照常记录。
                        // 同一失败原因每 5 秒窗口最多写两条（首条 + 汇总），
                        // ⇒ 磁盘增长有**上界**，与攻击速率无关。
                        //
                        // ★ 第一版只做速率限制（20 条/秒），实测**对慢速打无效**
                        //   —— 攻击者把速率压到配额以下就绕过了（仍有 12.5× 放大）。
                        //   详见 `CONN_END_LOG` 的文档注释。
                        let d = CONN_END_LOG.observe();
                        if d.emit() {
                            warn!(%peer, "连接结束：{e:#}{}", d.suffix());
                        }
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

fn log_limits(registry: &Registry, cfg: &ServerConfig) {
    let l = registry.limits();
    if !l.max_total_conns.gt(&0)
        && !l.max_clients.gt(&0)
        && !l.max_conns_per_client.gt(&0)
        && !l.max_proxies_per_client.gt(&0)
    {
        // 对外监听时把后果说具体：这条 warn 原来只说"能耗尽配额"，
        // 用户看不出它跟"我把端口开在公网上"有什么关系。
        if nfrp_common::util::is_loopback_addr(&cfg.bind_addr) {
            warn!("未配置任何资源上限：单个客户端即可耗尽服务端连接/代理配额");
        } else {
            warn!(
                "未配置任何资源上限，且监听在对外地址 {}：**任何**能连上本端口的人\
                 （未配 token 时就是字面意义上的任何人）都可以不断建连接 / 占代理名额，\
                 把服务端拖垮。对外提供服务时建议至少配 max_clients 与 max_total_conns。",
                cfg.bind_addr
            );
        }
    } else if l.max_total_conns > 0 || l.max_conns_per_client > 0 {
        info!(
            "资源上限：全局连接 {} / 客户端数 {} / 单客户端连接 {} / 排队 {} / 代理数 {}（0 = 不限）",
            l.max_total_conns,
            l.max_clients,
            l.max_conns_per_client,
            l.max_pending_per_client,
            l.max_proxies_per_client
        );
    }
}

/// 读自定义 404 页面（`custom404Page`）。空路径 / 读失败都回 `None`。
///
/// 读失败只警告不致命：这个文件只影响"没有代理匹配时给用户看什么"，
/// 不值得让整个服务端起不来（官方的 `getNotFoundPageContent()` 同样是
/// 打一条 warn 后回落）。
fn load_not_found_page(path: &str) -> Option<Arc<Vec<u8>>> {
    let path = path.trim();
    if path.is_empty() {
        return None;
    }
    match std::fs::read(path) {
        Ok(b) => {
            info!("自定义 404 页面已加载：{path}（{} 字节）", b.len());
            Some(Arc::new(b))
        }
        Err(e) => {
            warn!("自定义 404 页面 {path} 读取失败（{e}），将使用内置提示页");
            None
        }
    }
}

/// 当前服务端支持的线协议校验（保持与原 main 的行为一致）。
/// 校验配置里的线协议。
///
/// 服务端**按魔术字自动识别**对端用的是 v1 还是 v2（与官方 frps 的
/// `wire.CheckMagic` 一致），所以 `frp-v1` / `frp-v2` 都能用、且同一端口可以
/// 同时服务两种客户端 —— 这一项对服务端而言只是"别配错"。官方 frps 也是这样：
/// 它的 `transport.wireProtocol` 在接收侧实际上不参与判断。
///
/// 只有 `nfrp` 自研协议还没实现，必须显式拒绝（否则用户会以为配了就生效）。
pub fn ensure_protocol(cfg: &ServerConfig) -> Result<()> {
    if cfg.protocol.wire_version().is_none() {
        anyhow::bail!(
            "当前版本服务端尚未实现 NFrp 自研协议，\
             请把 protocol 设为 frp-v1（默认）或 frp-v2"
        );
    }
    Ok(())
}
