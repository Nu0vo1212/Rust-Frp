//! 服务端网络入口：监听、分发、控制连接处理、代理注册与转发配对。
//!
//! 与原版 frps 一致，控制连接与工作连接**复用同一个端口**，靠首帧消息类型区分：
//! `Login` 走控制连接流程，`NewWorkConn` 走工作连接流程，
//! `NewVisitorConn` 走 visitor 接入流程（stcp / xtcp）。

use std::{
    net::SocketAddr,
    path::PathBuf,
    sync::{atomic::AtomicBool, atomic::Ordering, Arc, RwLock},
    time::{Duration, Instant},
};

use anyhow::{anyhow, Context, Result};
use nfrp_common::{
    config::{is_quic, ServerConfig},
    frp::{
        self,
        conn::{self, FrpConn, ServerAccept},
        msg::{
            FrpMessage, Login, NewProxyResp, NewVisitorConn, NewVisitorConnResp, NewWorkConn, Pong,
            StartWorkConn, UdpPacket,
        },
        stream::{BoxStream, PrefixedStream},
    },
    util, ws,
};
use tokio::{net::TcpListener, net::TcpStream, net::UdpSocket};
use tracing::{debug, error, info, warn};

use crate::{
    dashboard,
    limits::Permit,
    pool::{ClientState, ConnSlot, CtrlCmd, PendingUser, Submit, WorkItem},
    registry::{ClientGuard, PortClaim, Registry, ServerLimits},
    udp_proxy,
    vhost::{self, VhostKind, VhostRoute, VhostTable},
    visitor, vnet,
};

use visitor::VisitorEntry;

/// yamux 帧头的第一个字节是协议版本号（固定 0）。
///
/// frp v2 的魔术字以 `F`(0x46) 开头，两者不会混淆，服务端因此可以自动探测。
const YAMUX_VERSION_BYTE: u8 = 0x00;

/// 探测首字节的超时时间。
const PROBE_TIMEOUT: Duration = Duration::from_secs(10);

/// **整个登录握手**的总超时（v0.5.4，M6）。
///
/// `PROBE_TIMEOUT` 只作用在每次 `read` 上 ⇒ 对端每 9 秒发一个字节就能
/// 无限期挂住一条**未认证**的连接（slowloris）。而 `max_clients` 要等登录
/// 之后才检查，所以这条路径完全没有闸门。
///
/// 取 30s：正常握手是毫秒级（本地实测 ~2ms），30s 足以覆盖高延迟链路
/// 与 OIDC 首次验签（JWKS 已在启动时预热），超时即断开。
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(30);

/// 未认证握手的**全局**并发上限（第九轮 C9-3 修复）。
///
/// # 为什么
///
/// 每条未认证的 frp 握手（明文连接或 yamux 子流）在认证完成前要占住一个
/// 任务和一份读缓冲。第九轮实测（`tmp/audit9/c/c9_3_yamux_flood.py`）：
/// yamux 未认证开流每条 ≈9.5 KiB、单会话上限 512 条、跨会话**没有**全局
/// 上限 —— 攻击者 129 KB 流量 + 22 个 fd 就把服务端内存抬到 +100 MB。
///
/// 这里给**所有**未认证握手一个全局名额：超出即短暂排队，排队也拿不到
/// 名额就断开 ⇒ 未认证内存峰值有界（≈ 2048 × ~10 KiB ≈ 20 MB），
/// 与攻击者的会话数、fd 数无关。
///
/// ★★ 复验修正（同日，C9-3 元验证抓出）：**名额必须在 spawn 之前取**。
/// 第一版把闸门放在任务体内部 —— 攻击者 11264 条流照旧全量 spawn，
/// 而每条流一 spawn 就分配 ~9 KiB 的 future ⇒ 峰值仍 +97 MB（约等于
/// 未修复）。现在 mux accept 循环先取名额再 spawn；已认证会话
/// （控制流登录成功后置位）的工作流直接放行（每条仍要各自握手认证）。
/// 配合 mux 通道反压（容量 8）与内核 TCP 缓冲，"已创建但未认证"的
/// 流数量被钉在闸门上限附近。
const PREAUTH_MAX: usize = 2048;

/// 拿不到名额时最多排队的时长：给突发重连留出空间，之后直接断开
/// （攻击流量下让队列尽快排空，而不是无限堆积）。
const PREAUTH_WAIT: Duration = Duration::from_secs(5);

/// 全局闸门的单例。
static PREAUTH_HANDSHAKES: std::sync::OnceLock<tokio::sync::Semaphore> = std::sync::OnceLock::new();

fn preauth_gate() -> &'static tokio::sync::Semaphore {
    PREAUTH_HANDSHAKES.get_or_init(|| tokio::sync::Semaphore::new(PREAUTH_MAX))
}

/// 申请一个未认证握手名额；排队超时（或信号量异常）返回 `None`。
///
/// 抽成独立函数是为了让测试能用小信号量直接验证"排满即超时"的行为。
async fn acquire_preauth_slot(
    gate: &tokio::sync::Semaphore,
) -> Option<tokio::sync::SemaphorePermit<'_>> {
    acquire_preauth_slot_with(gate, PREAUTH_WAIT).await
}

/// [`acquire_preauth_slot`] 的可参数化本体（测试用短超时）。
async fn acquire_preauth_slot_with(
    gate: &tokio::sync::Semaphore,
    wait: Duration,
) -> Option<tokio::sync::SemaphorePermit<'_>> {
    match tokio::time::timeout(wait, gate.acquire()).await {
        Ok(Ok(permit)) => Some(permit),
        // `Ok(Err(_))`：信号量被关闭（本进程不会发生）；`Err(_)`：排队超时。
        _ => None,
    }
}

/// 未认证握手闸门的**入场方式**（C9-3 复验补强）。
///
/// 用三态枚举而不是 `Option<Permit>`：`Option` 的 `None` 会同时被解释成
/// "没有预取（自己去取）"和"免闸门"，第一版就栽在这里 —— mux 已认证会话
/// 的流走了放行分支（`None`），任务体却又把它当成"没预取"去排队取名额，
/// 闸门满载时把合法工作流挡在门外（实测攻击期间转发失败，日志变体
/// "…断开" + 合法会话端口）。三态后语义唯一：
enum PreauthSlot {
    /// 直连路径：由 `handle_frp_stream` 在 ACL 之后自己取名额。
    Deferred,
    /// mux 未认证会话：accept 循环已在 spawn 之前取好名额（内存封顶关键）。
    Preacquired(tokio::sync::SemaphorePermit<'static>),
    /// mux 已认证会话的后续流：免闸门（每条仍要各自通过握手认证）。
    Bypassed,
}

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

/// WebSocket 升级请求的前缀：`"GET " + FrpWebsocketPath`。///
/// **与官方 frps 的判定完全一致**（`server/service.go`）：
///
/// ```ignore
/// websocketPrefix := []byte("GET " + netpkg.FrpWebsocketPath)
/// websocketLn := svr.muxer.Listen(0, uint32(len(websocketPrefix)), func(data []byte) bool {
///     return bytes.Equal(data, websocketPrefix)
/// })
/// ```
///
/// 三点要注意，都是照抄官方行为而不是自己发挥：
///
/// 1. **服务端不需要任何配置**：官方是在 TCP 层用 mux 做前缀匹配，
///    所以 frpc 打开 `protocol = "websocket"` 就能连上，frps 侧一行配置都不用改。
/// 2. **判据是"精确等于这 10 个字节"**，不是解析 HTTP —— 少一个字节都不算。
/// 3. **必须在 TLS 之前**：这个前缀是明文发在 TCP 端口上的。反过来说，
///    `tls + websocket` 在官方 frps 上也是连不上的（首字节是 0x16 不是 `G`），
///    `wss` 要靠前置的 nginx 之类终结 TLS —— 这不是我们偷懒，是官方就这样。
const WS_PREFIX: &[u8] = b"GET /~!frp";

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

// ---------------------------------------------------------------------------
// 连接分发
// ---------------------------------------------------------------------------

async fn handle_conn(
    mut stream: TcpStream,
    peer: SocketAddr,
    cfg: Arc<ServerConfig>,
    registry: Arc<Registry>,
) -> Result<()> {
    // 第零层：WebSocket 嗅探。**必须在 TLS 之前**，理由见 [`WS_PREFIX`]。
    //
    // 只先读 1 个字节：不是 `G` 就立刻还回去、原样往下走，
    // 非 WebSocket 的客户端因此只多付一次"首字节到达"的等待，与改造前等价
    // （下面 `tls::accept_server` 本来也要做同样的探测）。
    let mut first = [0u8; 1];
    match tokio::time::timeout(
        PROBE_TIMEOUT,
        tokio::io::AsyncReadExt::read(&mut stream, &mut first),
    )
    .await
    {
        Ok(Ok(0)) => return Ok(()),
        Ok(Ok(_)) => {}
        Ok(Err(e)) => return Err(e).context("读取首字节失败"),
        Err(_) => {
            debug!(%peer, "等待首字节超时，断开");
            return Ok(());
        }
    }

    if first[0] == WS_PREFIX[0] {
        // 可能是 `GET /~!frp`。继续读满前缀长度做逐字节比对，
        // 对不上一字节不丢 —— 全部塞回去按普通连接处理。
        let mut head = vec![first[0]];
        while head.len() < WS_PREFIX.len() {
            let mut b = [0u8; 1];
            match tokio::time::timeout(
                PROBE_TIMEOUT,
                tokio::io::AsyncReadExt::read(&mut stream, &mut b),
            )
            .await
            {
                Ok(Ok(0)) | Err(_) => break,
                Ok(Ok(_)) => head.push(b[0]),
                Ok(Err(e)) => return Err(e).context("读取 WebSocket 请求行失败"),
            }
        }
        if head == WS_PREFIX {
            let raw: BoxStream = Box::pin(PrefixedStream::new(head, stream));
            let ws = ws::accept(raw)
                .await
                .context("WebSocket 升级失败（关闭连接）")?;
            info!(%peer, "WebSocket 控制连接已建立");
            // 升级之后就是一条普通流：yamux（若开启）与 frp 握手照旧。
            return handle_stream(Box::pin(ws), peer, cfg, registry, false).await;
        }
        let stream: BoxStream = Box::pin(PrefixedStream::new(head, stream));
        let stream = frp::tls::accept_server(stream, true, cfg.tls_force)
            .await
            .context("TLS 协商失败")?;
        return handle_stream(stream, peer, cfg, registry, false).await;
    }

    let stream: BoxStream = Box::pin(PrefixedStream::new(vec![first[0]], stream));
    // 第一层：TLS。靠首字节自动识别（0x17 = frp 自定义首字节，0x16 = 标准 TLS）。
    let stream = frp::tls::accept_server(stream, true, cfg.tls_force)
        .await
        .context("TLS 协商失败")?;
    handle_stream(stream, peer, cfg, registry, false).await
}

/// 在一条已就绪的流上继续分层。
///
/// `secure` 表示这条流**本身已经加密且多路复用好了**（也就是 QUIC）——
/// QUIC 的每一条双向流都是独立的 frp 连接，所以既不用再套 TLS，也不需要用
/// yamux 去多路复用。少了这两层，QUIC 才省得下那一个 RTT。
async fn handle_stream(
    stream: BoxStream,
    peer: SocketAddr,
    cfg: Arc<ServerConfig>,
    registry: Arc<Registry>,
    secure: bool,
) -> Result<()> {
    if secure {
        return handle_frp_stream(stream, peer, cfg, registry, PreauthSlot::Deferred, None).await;
    }

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
            let session_authed: Arc<AtomicBool> = Arc::new(AtomicBool::new(false));
            // yamux 保活（限制①批次2，官方 `tcpMuxKeepaliveInterval`）：0 = 关闭。
            let mut acceptor = frp::mux::serve(
                Box::pin(PrefixedStream::new(vec![first[0]], stream)),
                frp::mux::MuxKeepalive::from_secs(cfg.tcp_mux_keepalive_interval),
            );
            while let Some(s) = acceptor.accept().await {
                let cfg = cfg.clone();
                let registry = registry.clone();
                if session_authed.load(Ordering::Relaxed) {
                    // 已认证会话（控制流登录 / 工作流验过 run_id+token 后置位）：
                    // 后续流**免闸门**直接放行 —— 它们每条仍要各自通过握手认证，
                    // 不占"未认证并发"的名额（攻击者拿不到 token，置不了位）。
                    let authed = session_authed.clone();
                    tokio::spawn(async move {
                        if let Err(e) = handle_frp_stream(
                            s,
                            peer,
                            cfg,
                            registry,
                            PreauthSlot::Bypassed,
                            Some(authed),
                        )
                        .await
                        {
                            debug!(%peer, "yamux stream 结束：{e:#}");
                        }
                    });
                    continue;
                }
                // ★★ C9-3 复验补强：**未认证会话先取名额、再 spawn**。
                //
                // spawn 那一刻就按 future 大小分配内存（实测 ~9 KiB/条）——
                // 第一版闸门放在任务体内，攻击者 11264 条流照样全量 spawn，
                // 闸门只限住了握手 CPU：峰值内存仍 +97 MB（约等于未修复）。
                // 放在 spawn 之前，配合 mux 通道反压（容量 8），
                // "已创建但未认证"的流对象被钉在闸门上限附近（≈20 MB）。
                let Some(permit) = acquire_preauth_slot(preauth_gate()).await else {
                    debug!(%peer, "未认证握手并发已达上限（{PREAUTH_MAX}），丢弃该流");
                    continue; // 丢的是这条流（会话保留，合法客户端会重试开流）
                };
                let authed = session_authed.clone();
                tokio::spawn(async move {
                    if let Err(e) = handle_frp_stream(
                        s,
                        peer,
                        cfg,
                        registry,
                        PreauthSlot::Preacquired(permit),
                        Some(authed),
                    )
                    .await
                    {
                        debug!(%peer, "yamux stream 结束：{e:#}");
                    }
                });
            }
            return Ok(());
        }
        let stream: BoxStream = Box::pin(PrefixedStream::new(vec![first[0]], stream));
        return handle_frp_stream(stream, peer, cfg, registry, PreauthSlot::Deferred, None).await;
    }

    handle_frp_stream(stream, peer, cfg, registry, PreauthSlot::Deferred, None).await
}

/// 在一条流上完成 frp v2 握手并分发到控制连接 / 工作连接。
///
/// `admission`：未认证闸门的入场方式（直连自取 / mux 循环预取 / 已认证免闸，
/// 见 [`PreauthSlot`]）。`session_authed`：mux 会话的"已认证"标志 ——
/// 首次握手成功即置位，之后同一会话上的后续流走 `Bypassed`
/// （每条仍要各自握手认证）。
async fn handle_frp_stream(
    stream: BoxStream,
    peer: SocketAddr,
    cfg: Arc<ServerConfig>,
    registry: Arc<Registry>,
    admission: PreauthSlot,
    session_authed: Option<Arc<AtomicBool>>,
) -> Result<()> {
    let run_id = util::new_run_id();
    let sec = registry.security();

    // (1) 第一层：IP 白 / 黑名单。
    //
    // 刻意放在**握手之前**：认证（尤其 OIDC）要比对签名、可能还要打 IdP，
    // 而 ACL 只是一次位运算 —— 让不认识的人先撞上最便宜的那道闸。
    if let Err(reason) = sec.check_ip(peer.ip()) {
        registry.audit().record(
            crate::audit::AuditEvent::new(crate::audit::kind::LOGIN_DENIED, false)
                .ip(peer.ip().to_string())
                .detail(reason.clone()),
        );
        debug!(%peer, "IP 访问控制拒绝：{reason}");
        anyhow::bail!("连接被拒绝");
    }

    // (1.5) 未认证握手的全局并发闸（第九轮 C9-3）。
    //
    // 放在 ACL 之后：被白黑名单拒掉的连接不该占名额；
    // 放在握手之前：让"读 Login 前的缓冲 + 任务"也计入闸门。
    //
    // 三条入场路径见 [`PreauthSlot`]：直连自取 / mux 循环预取 / 已认证免闸。
    let preauth_permit: Option<tokio::sync::SemaphorePermit<'static>> = match admission {
        PreauthSlot::Preacquired(p) => Some(p),
        PreauthSlot::Bypassed => None,
        PreauthSlot::Deferred => match acquire_preauth_slot(preauth_gate()).await {
            Some(p) => Some(p),
            None => {
                debug!(%peer, "未认证握手并发已达上限（{PREAUTH_MAX}），断开");
                return Ok(());
            }
        },
    };

    // (2) 认证 + (3) 授权。
    //
    // 授权必须发生在**回 LoginResp 之前**：先回"登录成功"再断开的话，客户端
    // 会把它当成普通掉线而无限重连（`loginFailExit` 永远不触发，宿主看到的是
    // "进程活着"= 绿灯，但实际不可用）。所以把 role_for 作为闭包传进握手函数。
    let authorize = |user: &str| -> std::result::Result<nfrp_common::security::Role, String> {
        sec.role_for(user).map_err(|e| {
            registry.audit().record(
                crate::audit::AuditEvent::new(crate::audit::kind::LOGIN_DENIED, false)
                    .client(run_id.clone())
                    .user(user.to_string())
                    .ip(peer.ip().to_string())
                    .detail(e.to_string()),
            );
            warn!(user = %user, "角色解析失败，拒绝登录：{e:#}");
            e.to_string()
        })
    };
    // ★ 取一份当前认证校验器传给握手（`sec.auth()` 是短锁读快照）——
    //   OIDC 的 JWKS 可能是启动后才刷新成功的，不能在这里缓存旧值。
    let auth_snapshot = sec.auth();

    // ★★ v0.5.4 修 M6：给**整个握手**加总超时，而不只是探测阶段。
    //
    // 原先只有 `PROBE_TIMEOUT`（10s）作用在**每次 read** 上，而握手本身
    // （读 Login → 认证 → 回 LoginResp）没有任何总时限。攻击者只要每 9 秒
    // 发一个字节，就能把一条**未认证**的连接无限期挂住；配合
    // "此时 `max_clients` 还没生效"（它要等到登录之后才检查），
    // 可以耗光文件描述符与内存（每条连接还占着 8 MiB 的 raw/plain 缓冲）。
    //
    // 取 30s：正常客户端握手是毫秒级（本地实测 ~2ms），30s 足够覆盖
    // 高延迟链路 + OIDC 首次验签（JWKS 已在启动时预热）。超时即断开，
    // 对合法用户无任何可感知影响。
    // ★ v0.5.6（M3）：把登录时间戳窗口传进握手（0 = 关闭校验）。
    let plugins = registry.plugins();
    let nlink_mask = registry.nlink().enabled_mask();
    let handshake = conn::server_handshake_authz_ext(
        stream,
        &auth_snapshot,
        &run_id,
        authorize,
        cfg.max_clock_skew_secs,
        Some(&plugins),
        Some(peer),
        nlink_mask,
    );
    let hs_result = tokio::time::timeout(HANDSHAKE_TIMEOUT, handshake).await;
    // ★ C9-3：认证阶段到此结束（成功/失败/超时都算），立刻释放未认证名额 ——
    //   之后的会话流量不计入闸门；免闸门（Bypassed）时本来就没有名额可释放。
    drop(preauth_permit);
    match hs_result {
        Err(_) => {
            registry.audit().record(
                crate::audit::AuditEvent::new(crate::audit::kind::LOGIN_DENIED, false)
                    .client(run_id.clone())
                    .ip(peer.ip().to_string())
                    .detail(format!("握手超过 {HANDSHAKE_TIMEOUT:?} 未完成，断开")),
            );
            debug!(%peer, "握手总超时（{:?}），断开", HANDSHAKE_TIMEOUT);
            Ok(())
        }
        Ok(result) => match result {
            Ok(ServerAccept::Control {
                conn,
                login,
                role,
                udp_binary,
                caps,
            }) => {
                // ★ C9-3 复验补强：认证通过 ⇒ 本 mux 会话标记"已认证"，
                //   其后续工作流不再占用未认证并发名额（每条仍各自握手）。
                if let Some(f) = &session_authed {
                    f.store(true, Ordering::Relaxed);
                }
                let wire_version = conn.version();
                // (4) 审计：登录成功也要记 —— 只记失败的话，
                //     "这个 IP 到底有没有进来过"就永远查不出来。
                registry.audit().record(
                    crate::audit::AuditEvent::new(crate::audit::kind::LOGIN, true)
                        .client(run_id.clone())
                        .user(login.user.clone())
                        .ip(peer.ip().to_string())
                        .detail(format!("role={} wire={wire_version}", role.name)),
                );
                handle_control(
                    conn,
                    *login,
                    run_id,
                    udp_binary,
                    caps,
                    wire_version,
                    peer,
                    role,
                    cfg,
                    registry,
                )
                .await
            }
            Ok(ServerAccept::Work { conn, msg }) => {
                // 工作流握手带 run_id + token，验过同样说明客户端是熟客 ⇒
                // 会话也标已认证（同 Control 臂）。
                if let Some(f) = &session_authed {
                    f.store(true, Ordering::Relaxed);
                }
                handle_work(conn, msg, &sec, registry, peer).await
            }
            Ok(ServerAccept::Visitor { conn, msg }) => {
                handle_visitor(conn, msg, registry, cfg.clone()).await
            }
            Err(e) => {
                // 握手失败（含认证失败）也要留痕：这是最需要被看见的一类事件。
                // 授权失败已经在 authorize 闭包里记过（那条带 user），别记两遍。
                let text = format!("{e:#}");
                if !text.starts_with("授权失败") {
                    registry.audit().record(
                        crate::audit::AuditEvent::new(crate::audit::kind::LOGIN_DENIED, false)
                            .client(run_id.clone())
                            .ip(peer.ip().to_string())
                            .detail(text.clone()),
                    );
                }
                debug!("握手失败：{e:#}");

                // ★★ v0.5.6 修（审计总报告 L10，低危）：**登录失败时重试拉 JWKS**。
                //
                // `guard.rs` 的 `refresh_oidc` 文档一直承诺"之后每次登录失败都会
                // 重新尝试拉取（见 serve.rs 的登录失败路径）"—— 但**那句承诺是假的**：
                // 全仓 `refresh_oidc` 只有 `serve.rs` 启动时那**一个**调用点。
                //
                // 后果（功能性缺陷，不是安全问题）：IdP 启动时不可达 ⇒
                // `AuthProvider::OidcUnavailable` ⇒ **一直拒绝登录**，
                // 而且**永远不会自愈** —— 即使 IdP 几秒后就恢复了，
                // 也必须重启服务端。运维看到的是"IdP 明明好的，就是登不上"。
                //
                // ★ 只在 OIDC 未就绪时才尝试（`refresh_oidc` 自身是幂等的，
                //   已是 Oidc 状态会立刻返回）。放在这里而不是每条连接都试，
                //   是因为"登录失败"才是"可能需要刷新"的信号。
                if matches!(
                    sec.auth(),
                    nfrp_common::security::AuthProvider::OidcUnavailable(_)
                ) {
                    match sec.refresh_oidc().await {
                        Ok(()) => info!("OIDC JWKS 重试拉取成功，后续登录可用了"),
                        Err(e2) => debug!("OIDC JWKS 重试拉取仍失败：{e2:#}"),
                    }
                }
                Err(e)
            }
        },
    }
}

// ---------------------------------------------------------------------------
// 控制连接
// ---------------------------------------------------------------------------

#[allow(clippy::too_many_arguments)]
async fn handle_control(
    mut conn: FrpConn,
    login: Login,
    run_id: String,
    udp_binary: bool,
    caps: nfrp_common::frp::msg::NfrpCaps,
    wire_version: nfrp_common::frp::WireVersion,
    peer: SocketAddr,
    role: nfrp_common::security::Role,
    cfg: Arc<ServerConfig>,
    registry: Arc<Registry>,
) -> Result<()> {
    let sec = registry.security();
    let client_id = if login.client_id.is_empty() {
        run_id.clone()
    } else {
        login.client_id.clone()
    };
    info!(
        client_id = %nfrp_common::util::LogSafe(&client_id), %run_id, os = %login.os, arch = %login.arch,
        wire = %wire_version, "客户端登录成功"
    );

    let (req_tx, mut req_rx) = tokio::sync::mpsc::unbounded_channel::<CtrlCmd>();
    // ★★ v0.5.6 修（审计总报告 M15，中危）：**补上上界钳制**。
    //
    // 原先只有 `.max(5)` —— 只挡了 0（免得"0 = 立刻超时"），
    // **没有上界**。于是配置里写一个极大的值（比如 `u64::MAX` 秒）
    // 就让空闲工作连接**永不回收**：
    //
    // * 每个客户端还能预建多条代理的空闲工作连接（官方 `maxPoolCount`
    //   默认 5；限制①批次1 起 NFrp 同样支持该项，默认 0 = 不限）；
    // * 客户端重连后旧连接不会被及时清掉 ⇒ `idle_work_conns` 持续累积
    //   ⇒ fd / 内存缓慢增长，且它**不是**由攻击流量触发的，
    //   运维很难把它和配置项联系起来。
    //
    // 上界取 3600 秒（1 小时）：远大于任何合理配置
    // （默认 60 秒、官方同款），但保证空闲连接**一定**会被回收。
    // 下界 5 秒维持原样（挡住 0 造成的立刻超时）。
    const IDLE_MIN: u64 = 5;
    const IDLE_MAX: u64 = 3600;
    let idle_secs = cfg.work_conn_idle_timeout.clamp(IDLE_MIN, IDLE_MAX);
    if cfg.work_conn_idle_timeout != idle_secs {
        warn!(
            configured = cfg.work_conn_idle_timeout,
            applied = idle_secs,
            "work_conn_idle_timeout 超出 [{IDLE_MIN}, {IDLE_MAX}] 秒，已钳制到 {idle_secs}"
        );
    }
    let idle_timeout = Duration::from_secs(idle_secs);
    let limits = registry.limits().clone();
    let (conn_limit, backlog_limit, proxy_limit) = limits.per_client();
    // 用户连接等配工作连接的超时（`userConnTimeout`，限制①批次1）：官方语义是
    // "等不到工作连接就放弃这条用户连接"，默认 10 秒；配 0 折算默认
    // （官方 `EmptyOr` 口径），不会变成"无限等"。
    let user_conn_timeout = cfg.user_conn_timeout();
    let fresh_client = Arc::new(ClientState::new(
        run_id.clone(),
        client_id.clone(),
        login.user.clone(),
        req_tx.clone(),
        idle_timeout,
        user_conn_timeout,
        caps.clone(),
        udp_binary,
        wire_version,
        conn_limit,
        backlog_limit,
        // 单客户端空闲工作连接池上限（`maxPoolCount`，0 = 不限；与
        // `max_pending_per_client` 取更小者，见 `ClientState::new`）。
        cfg.max_pool_count,
        proxy_limit,
        // 控制连接的源 IP：工作连接的空凭证回退校验要用（见 handle_work）
        peer.ip(),
    ));
    // 角色的 `allowManage` 在这里落地：面板能不能增删这个客户端的代理。
    // 角色是在握手函数内部解析出来的，`ClientState::new` 时还拿不到，
    // 所以补写一次。未启用 RBAC 时 role 是 unrestricted（allow_manage = true），
    // 行为与老版本完全一致。
    fresh_client.set_allow_manage(role.allow_manage);

    // ---- NLink v1：协商结果落地 ----
    //
    // 协商本身已经在握手阶段完成（preamble 进、LoginResp._nlink 出），
    // 这里只做三件必须已经拿到 `ClientState` 才能做的事：
    // 落能力位、发身份令牌、处理续传。
    let nlink_state = conn.nlink().cloned();
    let rt = registry.nlink();

    // 断线续传：preamble 里要求了、能力也协商了，才去查续传票。
    //
    // 真正的恢复发生在这一小段：把**暂停中的同一个 `ClientState`**
    // （连同它的代理表、监听器、端口、配额）挂到新控制连接上，
    // 而不是像 0.7.0 那样只回一个 ok=1 然后一切照旧重来。
    let mut resumed_session: Option<crate::registry::SuspendedSession> = None;
    if let Some(st) = &nlink_state {
        info!(
            caps = %st.caps,
            trace = %st.trace,
            session = %st.session,
            "NLink v1 协商成功"
        );
        if st.caps.contains(nfrp_common::nlink::CAP_RESUME) && st.resume {
            let mut restored: Vec<String> = Vec::new();
            // 注意顺序：**先校验身份再取走**。身份不符时条目原样留在表里，
            // 真正的客户端回来仍然能续上；否则任何人都能用同一个 session id
            // 把别人的暂停会话"取走并回收"，等于一个 DoS。
            if let Some(sess) = registry.take_suspended_if(st.session, &login.user, &client_id) {
                // 传输参数（wire / caps / UDP 编码）必须与暂停前一致：
                // 换了这些还复用旧监听器，后续工作连接会按错误的协议解析。
                let same_transport = sess.client.wire_version() == wire_version
                    && sess.client.udp_codec_is_binary() == udp_binary
                    && sess.client.caps() == caps;
                if same_transport && !sess.client.is_stopped() {
                    // 到这里才消费元数据票（它只是可观测性 / 日志用的副本）。
                    let _ = rt.resume.take(st.session);
                    restored = sess.client.proxy_names();
                    // 新 run_id 必须落到 ClientState 上：工作连接查找、
                    // 面板踢出、审计都靠它。
                    sess.client
                        .rebind_control(&run_id, req_tx.clone(), peer.ip());
                    registry.reattach(sess.client.clone());
                    info!(
                        session = %st.session,
                        restored = restored.len(),
                        "断线续传命中：沿用上次的代理与监听端口"
                    );
                    resumed_session = Some(sess);
                } else {
                    // 传输参数不符（例如客户端换了 wire 版本）：把会话放回，
                    // 既不复用也不销毁 —— 监听器继续等下一次合法续传。
                    warn!(
                        session = %st.session,
                        "续传会话的传输参数与暂停前不一致，保留旧会话并拒绝本次复用"
                    );
                    registry.suspend(st.session, sess);
                }
            }
            let mut resp =
                nfrp_common::nlink::Frame::new(nfrp_common::nlink::FrameKind::ResumeResp).with(
                    nfrp_common::nlink::frame::TAG_OK,
                    vec![u8::from(resumed_session.is_some())],
                );
            if resumed_session.is_some() {
                resp = resp.with(
                    nfrp_common::nlink::frame::TAG_DETAIL,
                    restored.join("\n").into_bytes(),
                );
            }
            conn.send_nlink(&resp).await?;
            if resumed_session.is_none() {
                info!(
                    session = %st.session,
                    "没有可用的续传会话（不存在 / 已过期 / 身份不匹配），按新会话处理"
                );
            }
        }
        // 零信任身份：每会话一张短时令牌，工作连接必须出示。
        //
        // 必须在续传判定之后：令牌绑定的是**新** run_id，先发会把旧 id 签进去。
        if st.caps.contains(nfrp_common::nlink::CAP_IDENTITY) {
            let token = rt.identity.issue(
                &run_id,
                &login.user,
                rt.identity_ttl(),
                std::time::SystemTime::now(),
            );
            let frame = nfrp_common::nlink::Frame::new(nfrp_common::nlink::FrameKind::Identity)
                .with(nfrp_common::nlink::frame::TAG_IDENTITY, token.into_bytes());
            tracing::debug!(run_id = %run_id, "下发 NLink 身份令牌");
            conn.send_nlink(&frame).await?;
        }
    }

    // 续传命中 → 复用同一份 ClientState（名额沿用暂停时保留的那个）；
    // 否则照常登记新客户端，并受 `max_clients` 约束。
    let (client, mut client_slot) = match resumed_session {
        Some(sess) => (sess.client, sess.slot),
        None => {
            let slot = match registry.insert(fresh_client.clone()) {
                Some(slot) => slot,
                None => {
                    registry.metrics().clients_rejected.inc();
                    warn!(
                        client_id = %nfrp_common::util::LogSafe(&client_id),
                        "客户端数量已达上限 {}，拒绝本次登录", limits.max_clients
                    );
                    let _ = conn
                        .send_msg(&FrpMessage::NewProxyResp(NewProxyResp {
                            proxy_name: String::new(),
                            error: format!(
                                "too many clients (limit = {}), login rejected",
                                limits.max_clients
                            ),
                            ..Default::default()
                        }))
                        .await;
                    let _ = conn.shutdown().await;
                    anyhow::bail!("客户端数量达到上限 {}", limits.max_clients);
                }
            };
            (fresh_client, Some(slot))
        }
    };
    if let Some(st) = &nlink_state {
        client.set_nlink(st.clone());
        // 批量工作连接：只有客户端也协商了才生效。
        if st.caps.contains(nfrp_common::nlink::CAP_BATCH_WORK) {
            client.set_nlink_batch(rt.cfg.batch_work_conn);
        }
    }
    // 续传命中后，本次控制连接从"暂停"恢复为在线。
    client.set_suspended(false);

    let mut _guard = ClientGuard::new(registry.clone(), run_id.clone());

    let mut hb_ticker = tokio::time::interval(Duration::from_secs(5));
    let mut last_seen = Instant::now();
    // 已下发、还在等回执的管理命令：key 是命令 id
    let mut pending_cmds: std::collections::HashMap<
        String,
        tokio::sync::oneshot::Sender<Result<(), String>>,
    > = std::collections::HashMap::new();
    // 只有"网络断开 / 心跳超时"这类**被动**结束才允许续传。
    // 被插件拒绝、心跳凭证复核失败等**主动**策略断开必须彻底清理，
    // 不能留一个可续传的壳。
    let mut allow_resume = true;

    loop {
        tokio::select! {
            event = conn.recv_event() => {
                // NLink 扩展帧与普通消息走同一个 select：扩展帧**立刻**被处理，
                // 不会因为"等下一条普通消息"而延迟（敲门 / 探测都是时序敏感的）。
                let msg = match event? {
                    nfrp_common::frp::conn::ConnEvent::Msg(m) => *m,
                    nfrp_common::frp::conn::ConnEvent::Closed => break,
                    nfrp_common::frp::conn::ConnEvent::NLink(f) => {
                        last_seen = Instant::now();
                        if f.kind == nfrp_common::nlink::FrameKind::ResumeCommit
                            && client.is_resumed_session()
                        {
                            // 续传后客户端把"最终还在的代理"报上来；没报的一律回收，
                            // 否则配置里删掉的代理会一直占着域名 / 端口。
                            let wanted: Vec<String> = f
                                .tlvs
                                .get_str(nfrp_common::nlink::frame::TAG_DETAIL)
                                .unwrap_or_default()
                                .lines()
                                .map(str::trim)
                                .filter(|s| !s.is_empty())
                                .map(str::to_string)
                                .collect();
                            let mut closed = 0usize;
                            for name in client.proxy_names() {
                                if !wanted.iter().any(|w| w == &name)
                                    && close_proxy_by_name(&registry, &client, &name)
                                {
                                    closed += 1;
                                }
                            }
                            client.finish_resume();
                            debug!(
                                kept = wanted.len(),
                                closed, "续传代理清单已对账，配置里删掉的代理已回收"
                            );
                        } else {
                            crate::nlink::handle_control_frame(&mut conn, &f, &run_id).await?;
                        }
                        continue;
                    }
                };
                last_seen = Instant::now();
                match msg {
                    FrpMessage::NewProxy(mut m) => {
                        // 命名空间隔离：代理对外（注册表 / 工作连接 / 访问控制）用
                        // `{user}.{name}` 这个全名。
                        //
                        // ★ 官方 frpc 在**客户端**就加好了前缀再发上来
                        //   （`client/proxy/proxy_wrapper.go` 的 `wireName` =
                        //   `naming.AddUserPrefix(clientCfg.User, name)`），
                        //   实测抓包：`user = '2569'` 时线上就是
                        //   `"proxy_name":"2569.c0462d9ce7e44bce97e626c4ae880905"`。
                        //
                        //   这里额外做一次「先 strip 再 add」是为了**幂等**：
                        //   收原始名（老版 NFrp 客户端、手写报文）也会被补成
                        //   全名，收带前缀的名字也不会叠成 `2569.2569.xxx`。
                        //
                        //   之所以要兜这一层：早期判断反了 —— 以为客户端该发原始名，
                        //   结果第三方 frps（LoliaFRP）按全名查隧道，查不到就回
                        //   「FRPC 配置文件错误,请检查后重试」。
                        // ★ v0.5.6（M5）：抽成 `canonical_wire_name()`，与面板管理
                        //   路径（`admin.rs`）共用 —— 原先面板那条漏了 strip，
                        //   于是全名会被叠成 `alice.alice.web`（端口/域名泄漏）。
                        m.proxy_name = util::canonical_wire_name(&client.user, &m.proxy_name);
                        // ---- 官方 `[[httpPlugins]]`：NewProxy ----
                        //
                        // 插件可以拒绝注册（返回 reject），也可以改写端口 /
                        // 名字 / 类型。放在权限检查之前，让插件成为第一道闸；
                        // 之后仍然要过 RBAC，插件不能借改写绕过角色限制。
                        if !registry.plugins().is_empty() {
                            let plugins = registry.plugins();
                            let user = nfrp_common::plugin::user_info(&login, &run_id);
                            let content = nfrp_common::plugin::content_with_user(&m, user)?;
                            match plugins
                                .handle_mutable(nfrp_common::plugin::OP_NEW_PROXY, content)
                                .await
                            {
                                Ok(v) => {
                                    m = serde_json::from_value(v)
                                        .context("插件返回的 NewProxy 内容无法解析")?;
                                    m.proxy_name =
                                        util::canonical_wire_name(&client.user, &m.proxy_name);
                                }
                                Err(e) => {
                                    registry.metrics().proxy_failures.inc();
                                    let reason = e.to_string();
                                    warn!(proxy = %m.proxy_name, "HTTP 插件拒绝代理注册：{reason}");
                                    conn.send_msg(&FrpMessage::NewProxyResp(NewProxyResp {
                                        proxy_name: m.proxy_name.clone(),
                                        error: cfg.error_to_client(
                                            &format!("new proxy [{}] error", m.proxy_name),
                                            &reason,
                                        ),
                                        ..Default::default()
                                    }))
                                    .await?;
                                    continue;
                                }
                            }
                        }
                        let name = m.proxy_name.clone();
                        let port = m.remote_port;
                        // (3) 授权：这个角色允许注册这种类型的代理 / 占这个端口吗？
                        //
                        // 放在 register_proxy **之前**：注册会真的去占端口、
                        // 建 vhost 路由，先拦下来才不会有"拒绝了一半"的状态。
                        if let Err(e) =
                            sec.check_proxy(&role, &name, &m.proxy_type, port, client.proxy_count())
                        {
                            registry.metrics().proxy_failures.inc();
                            registry.audit().record(
                                crate::audit::AuditEvent::new(
                                    crate::audit::kind::PROXY_REJECTED,
                                    false,
                                )
                                .client(run_id.clone())
                                .user(client.user.clone())
                                .ip(peer.ip().to_string())
                                .target(name.clone())
                                .detail(e.to_string()),
                            );
                            warn!(proxy = %name, "代理注册被权限模型拒绝：{e:#}");
                            conn.send_msg(&FrpMessage::NewProxyResp(NewProxyResp {
                                proxy_name: name.clone(),
                                // 详细错误里往往带着"别人的代理名 / 端口占用"这类
                                // 信息，detailedErrorsToClient = false 时必须脱敏。
                                // 短句与官方 `handleNewProxy` 的 summary 逐字一致。
                                error: cfg.error_to_client(
                                    &format!("new proxy [{name}] error"),
                                    &e.to_string(),
                                ),
                                ..Default::default()
                            }))
                            .await?;
                            continue;
                        }
                        let resp = match register_proxy(&cfg, &registry, &client, &m).await {
                            Ok(outcome) => {
                                if !outcome.adopted {
                                    registry.metrics().proxies_total.inc();
                                    registry.metrics().proxies_active.inc();
                                }
                                let remote_addr = outcome.remote_addr;
                                info!(proxy = %name, port, remote = %remote_addr, "代理注册成功");
                                registry.audit().record(
                                    crate::audit::AuditEvent::new(
                                        crate::audit::kind::PROXY_ADD,
                                        true,
                                    )
                                    .client(run_id.clone())
                                    .user(client.user.clone())
                                    .ip(peer.ip().to_string())
                                    .target(name.clone())
                                    .detail(format!(
                                        "type={} remote_port={port} remote={remote_addr}",
                                        m.proxy_type
                                    )),
                                );
                                NewProxyResp {
                                    proxy_name: name.clone(),
                                    remote_addr,
                                    ..Default::default()
                                }
                            }
                            Err(e) => {
                                registry.metrics().proxy_failures.inc();
                                warn!(proxy = %name, port, "代理注册失败：{e:#}");
                                NewProxyResp {
                                    proxy_name: name.clone(),
                                    // 同上：`detailedErrorsToClient = false` 时只回短句
                                    error: cfg.error_to_client(
                                        &format!("new proxy [{name}] error"),
                                        &e.to_string(),
                                    ),
                                    ..Default::default()
                                }
                            }
                        };
                        conn.send_msg(&FrpMessage::NewProxyResp(resp)).await?;
                    }
                    FrpMessage::Ping(mut p) => {
                        // 官方 `[[httpPlugins]]`：Ping。插件可以拒绝心跳
                        // （管理端强制下线）或改写心跳内容。
                        if !registry.plugins().is_empty() {
                            let plugins = registry.plugins();
                            let user = nfrp_common::plugin::user_info(&login, &run_id);
                            let content = nfrp_common::plugin::content_with_user(&p, user)?;
                            match plugins
                                .handle_mutable(nfrp_common::plugin::OP_PING, content)
                                .await
                            {
                                Ok(v) => {
                                    p = serde_json::from_value(v)
                                        .context("插件返回的 Ping 内容无法解析")?;
                                }
                                Err(e) => {
                                    warn!("HTTP 插件拒绝心跳，断开控制连接：{e:#}");
                                    allow_resume = false;
                                    let _ = conn
                                        .send_msg(&FrpMessage::Pong(Pong {
                                            error: cfg.error_to_client(
                                                "invalid ping",
                                                &e.to_string(),
                                            ),
                                        }))
                                        .await;
                                    break;
                                }
                            }
                        }
                        // OIDC + additionalScopes 含 HeartBeats 时，每个心跳上的
                        // token 都要重新验签、且 subject 与登录时一致。
                        // 少了这一步，"登录时验过一次"就等于之后永久信任。
                        if sec.auth_cfg.check_heartbeats()
                            && sec.auth_method() == nfrp_common::security::AuthMethod::Oidc
                        {
                            if let Err(e) = sec.verify_followup(&p.privilege_key, "心跳", &run_id) {
                                registry.audit().record(
                                    crate::audit::AuditEvent::new(
                                        crate::audit::kind::LOGIN_DENIED,
                                        false,
                                    )
                                    .client(run_id.clone())
                                    .user(client.user.clone())
                                    .ip(peer.ip().to_string())
                                    .detail(format!("心跳凭证复核失败：{e:#}")),
                                );
                                warn!("心跳凭证复核失败，断开控制连接：{e:#}");
                                allow_resume = false;
                                // 先回一条带错误的 Pong 再断，客户端才拿得到原因；
                                // 短句与官方 `handlePing` 的 summary 逐字一致
                                // （官方那边同样受 detailedErrorsToClient 控制）。
                                let _ = conn
                                    .send_msg(&FrpMessage::Pong(Pong {
                                        error: cfg.error_to_client("invalid ping", &e.to_string()),
                                    }))
                                    .await;
                                break;
                            }
                        }
                        conn.send_msg(&FrpMessage::Pong(Pong::default())).await?;
                    }
                    FrpMessage::CloseProxy(m) => {
                        info!(proxy = %m.proxy_name, "客户端关闭代理");
                        // ★★ v0.5.6 修（审计总报告 M8，中危）：`proxies_active.dec()`
                        //   **不能无条件执行**。
                        //
                        // 原先它在这里就先减了，而下面 `stop_proxy` 可能返回 `None`
                        // （名字拼错、重复发、发别人的名字）—— 那种情况下什么都没
                        // 清理，gauge 却已经减了一次。
                        //
                        // 攻击：任意客户端反复发 `CloseProxy`，每次让 gauge 减 1
                        // ⇒ 变成负数并持续走低，面板显示"生效代理 -37"，
                        // 管理员据此发现异常的能力被破坏。
                        //
                        // 正确写法是"确实摘掉了才减"，与 `admin.rs` 那条对齐。
                        registry.audit().record(
                            crate::audit::AuditEvent::new(
                                crate::audit::kind::PROXY_REMOVE,
                                true,
                            )
                            .client(run_id.clone())
                            .user(client.user.clone())
                            .ip(peer.ip().to_string())
                            .target(m.proxy_name.clone())
                            .detail("客户端主动关闭"),
                        );
                        // stcp / xtcp 的代理名
                        //
                        // ★ v0.5.5（第四轮 B-1）：同样必须带上发起方的 client ——
                        //   只按名字摘会摘掉别的租户的同名 visitor 记录（跨租户 DoS）。
                        //   这是 H1 修复漏掉的第二处（同一根因）。
                        registry.visitors.remove(&client, &m.proxy_name);
                        // 客户端主动关代理时，它占的 http/https 域名也得摘掉，
                        // 否则域名会一直被占着、重连注册同一个域名会被判冲突
                        //
                        // ★ v0.5.5（第四轮 H1）：必须带上**发起方**的 client ——
                        //   只按名字摘会把别的租户的同名路由一起摘掉（跨租户 DoS）。
                        if let Some(t) = registry.vhosts() {
                            t.remove_proxy(&client, &m.proxy_name);
                        }
                        // tcp / udp 的公网端口同理：客户端这边只是记账，
                        // 端口是注册表管的，必须显式还回去
                        //
                        // ★ v0.5.6（M8）：`dec()` 挪到这里 —— **确实摘掉了才减**。
                        if let Some(port) = client.stop_proxy(&m.proxy_name) {
                            registry.metrics().proxies_active.dec();
                            registry.release_port(port, &client, &m.proxy_name);
                        } else {
                            // 名字对不上：什么都没清理。留一条 debug 便于排查
                            // （不改指标 —— 这正是 M8 的修法）。
                            debug!(proxy = %m.proxy_name, "CloseProxy 的名字不在本客户端的表里，未做任何清理");
                        }
                        // 官方 `[[httpPlugins]]`：CloseProxy 是**通知型** op，
                        // 插件失败/拒绝只记日志，不影响本地清理（官方同语义）。
                        if !registry.plugins().is_empty() {
                            let plugins = registry.plugins();
                            let user = nfrp_common::plugin::user_info(&login, &run_id);
                            let content = nfrp_common::plugin::content_with_user(&m, user)?;
                            plugins
                                .notify(nfrp_common::plugin::OP_CLOSE_PROXY, content)
                                .await;
                        }
                    }
                    FrpMessage::NatHoleVisitor(m) => {
                        crate::p2p::handle_nat_hole_visitor(&registry, &client, &m).await?;
                    }
                    FrpMessage::NatHoleClient(m) => {
                        // 官方 frpc 的 provider 收到 NatHoleClient{sid} 后，
                        // 会回一条带自己 mapped_addrs 的 NatHoleClient。
                        // 这是打洞配对的关键一步，不能只记日志丢掉。
                        if !crate::nathole_official::handle_client(&client, &m) {
                            debug!(proxy = %m.proxy_name, sid = %m.sid,
                                "收到无法配对的 NatHoleClient（会话不存在/已超时/不是该 provider）");
                        }
                    }
                    FrpMessage::NatHoleReport(m) => {
                        crate::nathole_official::handle_report(&m);
                    }
                    // 面板下发的管理命令的回执：按 id 交还给等待者
                    FrpMessage::ServerCmdResp(r) => {
                        let outcome = if r.error.is_empty() {
                            Ok(())
                        } else {
                            Err(r.error.clone())
                        };
                        match pending_cmds.remove(&r.id) {
                            Some(tx) => {
                                let _ = tx.send(outcome);
                            }
                            None => debug!(
                                id = %r.id, op = %r.op,
                                "收到没有等待者的命令回执，忽略"
                            ),
                        }
                    }
                    other => {
                        debug!("忽略消息：{}", other.name());
                    }
                }
            }
            Some(cmd) = req_rx.recv() => {
                match cmd {
                    // 有用户连接排队，向客户端索要一条工作连接
                    CtrlCmd::RequestWork => {
                        // NLink 批量：并发用户 >1 且协商了能力时，一条帧换 N 条连接。
                        // 条件不满足就退回原来的一字节 `ReqWorkConn`。
                        if let Some(n) = client.take_batch_request() {
                            let frame = nfrp_common::nlink::Frame::new(
                                nfrp_common::nlink::FrameKind::BatchReq,
                            )
                            .with(
                                nfrp_common::nlink::frame::TAG_COUNT,
                                n.to_be_bytes().to_vec(),
                            );
                            debug!(count = n, "用一条 BatchReq 向客户端要工作连接");
                            conn.send_nlink(&frame).await?;
                        } else {
                            conn.send_msg(&FrpMessage::ReqWorkConn).await?;
                        }
                    }
                    // 其他路径（xtcp 打洞协调）要发给客户端的消息，原样下发
                    CtrlCmd::Send(msg) => conn.send_msg(&msg).await?,
                    // 面板下发的管理命令：发出去并登记等待者
                    CtrlCmd::ServerCmd { cmd, ack } => {
                        if !client.caps().server_cmd {
                            // 这个客户端没协商过这个能力（官方 frpc、或者
                            // private_caps=false），发过去它只会忽略。
                            // 与其让面板干等到超时，不如立刻明确报错。
                            let _ = ack.send(Err(
                                "该客户端未启用管理命令（官方 frpc，或 private_caps=false）"
                                    .to_string(),
                            ));
                            continue;
                        }
                        let id = cmd.id.clone();
                        conn.send_msg(&FrpMessage::ServerCmd((*cmd).clone())).await?;
                        pending_cmds.insert(id, ack);
                    }
                }
            }
            _ = hb_ticker.tick() => {
                // 续传兜底对账：0.7.0 及更早的客户端只重发 `NewProxy`，
                // 不认识 `ResumeCommit`。给 10 秒宽限期，还没被重发 / 复用的
                // 代理（配置里已删除）在这里回收 —— 否则旧端口会一直被占着。
                if client.is_resumed_session()
                    && client.resume_grace_expired(Duration::from_secs(10))
                {
                    let stale = client.stale_proxies();
                    for name in &stale {
                        if close_proxy_by_name(&registry, &client, name) {
                            debug!(proxy = %name, "续传兜底：回收未被重新注册的代理");
                        }
                    }
                    client.finish_resume();
                }
                // 被面板踢出：`stop()` 之后必须主动断开，
                // 否则这条控制连接会一直活到心跳超时，
                // 期间还能继续建立工作连接 —— "踢了但没完全踢"。
                if client.is_stopped() {
                    warn!(client_id = %nfrp_common::util::LogSafe(&client_id), "客户端已被面板踢出，断开控制连接");
                    break;
                }
                if last_seen.elapsed() > Duration::from_secs(cfg.heartbeat_timeout) {
                    warn!(client_id = %nfrp_common::util::LogSafe(&client_id), "心跳超时 {}s，断开控制连接", cfg.heartbeat_timeout);
                    break;
                }
            }
        }
    }

    // ---- 控制连接结束：暂停会话，等续传 ----
    //
    // 与 0.7.0 的区别：这里**不再**只写一份元数据就顺手 `registry.remove()`。
    // 监听器、端口、vhost 路由、visitor 记录全部原地保留 `resume_ttl` 秒；
    // 续传命中时新控制连接直接接管这份状态，公网端口在切换窗口里不需要
    // 重新 bind，也不会被别人抢走。
    if let Some(st) = &nlink_state {
        if allow_resume
            && st.caps.contains(nfrp_common::nlink::CAP_RESUME)
            && st.resume
            && !client.is_stopped()
        {
            let rt = registry.nlink();
            let ttl = rt.resume_ttl();
            if let Some(c) = registry.detach(&run_id) {
                c.set_suspended(true);
                let entry = crate::registry::SuspendedSession {
                    client: c,
                    slot: client_slot.take(),
                    run_id: run_id.clone(),
                    user: client.user.clone(),
                    client_id: client.client_id.clone(),
                    expires_at: std::time::Instant::now() + ttl,
                };
                if registry.suspend(st.session, entry) {
                    rt.resume.put(
                        st.session,
                        nfrp_common::nlink::ResumeEntry {
                            run_id: run_id.clone(),
                            user: client.user.clone(),
                            trace: st.trace,
                            proxies: client.proxy_names(),
                            expires_at: std::time::Instant::now(),
                        },
                        ttl,
                    );
                    // 会话没结束：别让 `ClientGuard` 把刚保住的资源清掉。
                    _guard.disarm();
                    // 旧 run_id 的 OIDC 绑定随旧会话一起作废；新会话会重新绑定。
                    registry.security().forget_session(&run_id);
                    info!(
                        session = %st.session,
                        ttl = ttl.as_secs(),
                        "控制连接断开：会话已暂停，等待续传"
                    );
                    return Ok(());
                }
                warn!(
                    session = %st.session,
                    "暂停会话登记冲突：本次连接按普通断开回收"
                );
            }
        }
    }

    Ok(())
}

/// `NewProxy` 的确定性指纹（续传复用判据）。
///
/// **不能用 `serde_json::to_string(m)`**：`metas` / `headers` 等是
/// `HashMap`，每次构造的随机种子不同，序列化顺序会变 —— 同一份配置两次
/// 算出的字符串不同，续传就永远复用不了，随后重新 bind 直接 `EADDRINUSE`。
/// 这里把所有集合排序后再拼接，保证跨进程、跨重启稳定。
fn proxy_signature(m: &nfrp_common::frp::msg::NewProxy) -> String {
    fn sorted_map(m: &std::collections::HashMap<String, String>) -> String {
        let mut kv: Vec<(&String, &String)> = m.iter().collect();
        kv.sort();
        kv.into_iter()
            .map(|(k, v)| format!("{k}={v}"))
            .collect::<Vec<_>>()
            .join("&")
    }
    fn sorted_vec(v: &[String]) -> String {
        let mut v = v.to_vec();
        v.sort();
        v.join(",")
    }
    format!(
        "name={}\0type={}\0enc={}\0comp={}\0bw={}\0bwmode={}\0group={}\0gkey={}\0metas={}\0ann={}\0port={}\0domains={}\0sub={}\0locations={}\0http_user={}\0http_pwd={}\0host={}\0headers={}\0resp_headers={}\0route_user={}\0mux={}\0sk={}\0allow={}",
        m.proxy_name,
        m.proxy_type,
        m.use_encryption,
        m.use_compression,
        m.bandwidth_limit,
        m.bandwidth_limit_mode,
        m.group,
        m.group_key,
        sorted_map(&m.metas),
        sorted_map(&m.annotations),
        m.remote_port,
        sorted_vec(&m.custom_domains),
        m.subdomain,
        sorted_vec(&m.locations),
        m.http_user,
        m.http_pwd,
        m.host_header_rewrite,
        sorted_map(&m.headers),
        sorted_map(&m.response_headers),
        m.route_by_http_user,
        m.multiplexer,
        m.sk,
        sorted_vec(&m.allow_users),
    )
}

/// `register_proxy` 的结果。
#[derive(Debug)]
pub(crate) struct RegisterOutcome {
    /// 回给客户端的 `remote_addr` 文案。
    pub remote_addr: String,
    /// `true` = 续传时复用了原监听器，**没有**新建资源。
    ///
    /// 调用方据此决定要不要 `proxies_total/active.inc()`：复用的条目在
    /// 暂停期间从未减过，再 inc 一次会让面板统计永久偏高。
    pub adopted: bool,
}

/// 按代理类型注册：tcp / udp 绑端口，http / https 注册虚拟主机域名。
///
/// 返回给客户端的 `remote_addr` 文案（frp 用它展示"暴露在哪"）。
pub(crate) async fn register_proxy(
    cfg: &Arc<ServerConfig>,
    registry: &Arc<Registry>,
    client: &Arc<ClientState>,
    m: &nfrp_common::frp::msg::NewProxy,
) -> Result<RegisterOutcome> {
    if m.proxy_name.is_empty() {
        anyhow::bail!("代理名为空");
    }
    // 续传复用：只有"本次控制连接是续传出来的"才允许跳过重新绑定。
    // 指纹覆盖端口 / 域名 / 密钥等全部字段 —— 同名但配置改过时必须重新注册，
    // 否则用户改了端口却仍指向旧监听器，且不会有任何报错。
    let signature = proxy_signature(m);
    if client.is_resumed_session() {
        if let Some(addr) = client.reusable_proxy(&m.proxy_name, &signature) {
            debug!(
                proxy = %m.proxy_name,
                remote = %addr,
                "续传：同名同配置代理直接复用原监听器"
            );
            // 刷新代次：本次续传确实"碰过"它，宽限期对账时不能当成陈旧条目。
            client.set_proxy_registration(&m.proxy_name, addr.clone(), signature.clone());
            return Ok(RegisterOutcome {
                remote_addr: addr,
                adopted: true,
            });
        }
    }
    // 同名但配置变了（或普通会话重复注册同名代理）：先把旧监听器 / 域名 /
    // visitor 记录彻底摘掉，再走新注册。
    //
    // 这一步不能只在续传路径做：普通会话只要重复发同一个 `NewProxy`，旧条目
    // 就会被 `add_proxy` 覆盖，而旧监听器没人 abort —— 客户端可以用一个代理名
    // 反复换端口，把 allowPorts 白名单里的端口一个个占住且永不释放。
    if client.has_proxy(&m.proxy_name) {
        debug!(proxy = %m.proxy_name, "同名代理重新注册，先回收旧注册");
        close_proxy_by_name(registry, client, &m.proxy_name);
    }
    // 代理数必须在分配端口/域名之前拦住，否则失败路径还要回头回收资源。
    // 名额由 add_proxy 接管，随代理一起存活。
    let slot = client.reserve_proxy().ok_or_else(|| {
        anyhow!(
            "代理数量已达上限 {}，注册被拒绝",
            registry.limits().max_proxies_per_client
        )
    })?;

    // ---- 端口管控（allowPorts / maxPortsPerClient）----
    //
    // 只对**真的会绑公网端口**的 tcp / udp 生效：http / https / tcpmux / stcp /
    // xtcp / sudp 都走虚拟主机或 visitor 配对，一个公网端口都不占。
    // 官方同样如此（`Control.RegisterProxy` 累的是 `pxy.GetUsedPortsNum()`，
    // 只有 tcp / udp 返回 1）。
    //
    // `remote_port == 0` 时不在这里拦：交给 register_tcp / register_udp 报
    // "必须指定 remote_port"，那条错误信息比"端口 0 不在白名单"有用得多。
    if matches!(m.proxy_type.as_str(), "tcp" | "udp") && m.remote_port != 0 {
        if !cfg.port_allowed(m.remote_port) {
            anyhow::bail!(
                "远端端口 {} 不在服务端 allowPorts 白名单内（已允许：{}）",
                m.remote_port,
                nfrp_common::config::format_port_ranges(&cfg.allow_ports)
            );
        }
        if cfg.max_ports_per_client > 0 {
            let used = client.ports_used() as i64;
            if used + 1 > cfg.max_ports_per_client {
                anyhow::bail!(
                    "本客户端已占用 {used} 个端口，再加这一个会超过 maxPortsPerClient = {}",
                    cfg.max_ports_per_client
                );
            }
        }
    }
    let result = match m.proxy_type.as_str() {
        "tcp" => register_tcp(cfg, registry, client, m, slot).await,
        "udp" => register_udp(cfg, registry, client, m, slot).await,
        "http" => register_vhost(cfg, registry, client, m, VhostKind::Http, slot).await,
        "https" => register_vhost(cfg, registry, client, m, VhostKind::Https, slot).await,
        // tcpmux：不绑端口，挂到服务端那个共享的 CONNECT 复用端口上按域名分发
        "tcpmux" => register_vhost(cfg, registry, client, m, VhostKind::TcpMux, slot).await,
        "stcp" => register_visitor_proxy(registry, client, m, "stcp", slot).await,
        "xtcp" => register_visitor_proxy(registry, client, m, "xtcp", slot).await,
        // SUDP：秘密 UDP。与 stcp 同一套鉴权（secret_key + allow_users），
        // 只是数据面是 UDP。不需要公网端口，visitor 主动连进来时配对。
        "sudp" => register_visitor_proxy(registry, client, m, "sudp", slot).await,
        other => anyhow::bail!(
            "暂不支持的代理类型：{other}\
             （支持 tcp / udp / http / https / tcpmux / stcp / xtcp / sudp）"
        ),
    };
    // 记下回给客户端的地址 + 指纹：续传时据此判断"同名同配置，直接复用"。
    if let Ok(addr) = &result {
        client.set_proxy_registration(&m.proxy_name, addr.clone(), signature);
    }
    result.map(|remote_addr| RegisterOutcome {
        remote_addr,
        adopted: false,
    })
}

/// 按名字摘掉一条代理并回收它占用的域名 / visitor 记录 / 公网端口。
///
/// 与 `CloseProxy` 走同一套清理语义，但**不**触发 HTTP 插件（这是服务端
/// 自己的对账动作，不是客户端发起的关闭）。返回 `true` 表示确实摘掉了。
fn close_proxy_by_name(registry: &Arc<Registry>, client: &Arc<ClientState>, name: &str) -> bool {
    registry.visitors.remove(client, name);
    if let Some(t) = registry.vhosts() {
        t.remove_proxy(client, name);
    }
    if !client.has_proxy(name) {
        return false;
    }
    let port = client.stop_proxy(name);
    registry.metrics().proxies_active.dec();
    if let Some(port) = port {
        registry.release_port(port, client, name);
    }
    true
}

/// stcp / xtcp：**不需要公网端口**，只在 visitor 表里登记一条记录。
///
/// 之后 visitor 主动连进来时才会校验密钥并配对工作连接。
///
/// 说明：`xtcp` 在 P2P 打洞失败时会回退成本模块的中继路径（与 stcp 一致）。
async fn register_visitor_proxy(
    registry: &Arc<Registry>,
    client: &Arc<ClientState>,
    m: &nfrp_common::frp::msg::NewProxy,
    kind: &str,
    slot: Permit,
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
    client.add_proxy(m.proxy_name.clone(), None, slot);
    // ★ v0.6.6：把数据面标志记下来，工作连接那一侧要用它决定是否解密/解压
    client.set_proxy_flags(&m.proxy_name, m.use_encryption, m.use_compression);
    client.set_proxy_type(&m.proxy_name, &m.proxy_type);
    // 与官方 frps 一致：visitor 类代理没有公网地址，remote_addr 留空
    Ok(String::new())
}

/// TCP：绑定公网端口，用户连进来时向客户端要工作连接配对。
async fn register_tcp(
    cfg: &Arc<ServerConfig>,
    registry: &Arc<Registry>,
    client: &Arc<ClientState>,
    m: &nfrp_common::frp::msg::NewProxy,
    slot: Permit,
) -> Result<String> {
    if m.remote_port == 0 {
        anyhow::bail!("tcp 代理必须指定 remote_port");
    }
    // ★ 限制①批次1：数据面端口跟随 `proxyBindAddr`（官方
    //   `ports.NewManager("tcp", cfg.ProxyBindAddr, ...)` 与 tcp.go 的
    //   `net.Listen(..., ProxyBindAddr, ...)`；留空 = `bindAddr`）。
    let proxy_host = cfg.effective_proxy_bind_addr();
    // group 共享端口时**只有第一个成员**能 bind，后来者直接复用已有监听器：
    // 再 bind 一次必然是 `Address already in use`，组里就永远只剩一个后端。
    let claim = registry
        .reserve_port(
            m.remote_port,
            &m.group,
            &m.group_key,
            &m.proxy_name,
            client.clone(),
        )
        .map_err(|e| anyhow!("{e}"))?;

    if claim == PortClaim::Fresh {
        let addr = util::resolve_addr(&format!("{proxy_host}:{}", m.remote_port))
            .await
            .with_context(|| format!("解析 {proxy_host}:{} 失败", m.remote_port))?;
        let listener = match TcpListener::bind(addr).await {
            Ok(l) => l,
            Err(e) => {
                registry.release_port(m.remote_port, client, &m.proxy_name);
                return Err(e).with_context(|| format!("监听 {addr} 失败"));
            }
        };

        let remote_port = m.remote_port;
        let registry2 = registry.clone();
        let handle = tokio::spawn(async move {
            proxy_accept_loop(listener, remote_port, registry2).await;
        });
        // 监听器交给**端口**（而不是这个客户端）托管：组里其他成员还在时，
        // 创建者掉线不该把端口一起带走。
        registry.attach_listener(m.remote_port, handle.abort_handle());
    }

    client.add_proxy(m.proxy_name.clone(), Some(m.remote_port), slot);
    client.set_proxy_flags(&m.proxy_name, m.use_encryption, m.use_compression);
    client.set_proxy_type(&m.proxy_name, &m.proxy_type);
    Ok(format!("{proxy_host}:{}", m.remote_port))
}

/// UDP：绑定 UDP 端口 + 维持一条专用工作连接。
async fn register_udp(
    cfg: &Arc<ServerConfig>,
    registry: &Arc<Registry>,
    client: &Arc<ClientState>,
    m: &nfrp_common::frp::msg::NewProxy,
    slot: Permit,
) -> Result<String> {
    if m.remote_port == 0 {
        anyhow::bail!("udp 代理必须指定 remote_port");
    }
    // ★ 限制①批次1：数据面端口跟随 `proxyBindAddr`（官方 udp.go：
    //   `ResolveUDPAddr(..., ProxyBindAddr, ...)`；留空 = `bindAddr`）。
    let proxy_host = cfg.effective_proxy_bind_addr();
    // 同 tcp：只有第一个成员负责绑定，后来者复用。
    //
    // 但 UDP 的 group 负载均衡这里**明确不做**：UDP 是无连接的，一条工作连接
    // 要负责一整套来源地址的报文，按连接轮询会把同一个会话的报文拆到不同后端去，
    // 结果比不均衡还糟。与其让它"看着配了却没生效"，不如直接说清楚。
    let claim = registry
        .reserve_port(
            m.remote_port,
            &m.group,
            &m.group_key,
            &m.proxy_name,
            client.clone(),
        )
        .map_err(|e| anyhow!("{e}"))?;
    if claim == PortClaim::Joined {
        registry.release_port(m.remote_port, client, &m.proxy_name);
        anyhow::bail!(
            "端口 {} 已被同组 [{}] 的其他代理占用；UDP 暂不支持 group 负载均衡，请改用 tcp",
            m.remote_port,
            m.group
        );
    }

    let udp = match udp_proxy::bind_udp(proxy_host, m.remote_port).await {
        Ok(u) => u,
        Err(e) => {
            registry.release_port(m.remote_port, client, &m.proxy_name);
            return Err(e);
        }
    };
    // ★ v0.5.9（第九轮审计 E9-0）：把安全上下文传进去，让 UDP 数据面也过 ACL。
    let handle = udp_proxy::spawn(
        Arc::new(udp),
        m.proxy_name.clone(),
        client.clone(),
        registry.security(),
        nfrp_common::config::clamp_udp_packet_size(cfg.udp_packet_size),
    );
    registry.attach_listener(m.remote_port, handle.abort_handle());
    client.add_proxy(m.proxy_name.clone(), Some(m.remote_port), slot);
    Ok(format!("{proxy_host}:{}/udp", m.remote_port))
}

/// http / https / tcpmux：把域名注册进虚拟主机路由表（都不需要额外端口）。
///
/// 三者的域名解析规则完全一样（`customDomains` + `subDomain`.配 `subdomain_host`），
/// 所以合用一条路径；差别只在路由表里的 `kind`，以及**路径前缀**：
/// tcpmux 的 CONNECT 请求没有路径，官方 `TCPMuxProxyConfig` 也没有 `locations`，
/// 所以它注册的前缀是空串（匹配一切），而 http 默认 `/`。
async fn register_vhost(
    cfg: &Arc<ServerConfig>,
    registry: &Arc<Registry>,
    client: &Arc<ClientState>,
    m: &nfrp_common::frp::msg::NewProxy,
    kind: VhostKind,
    slot: Permit,
) -> Result<String> {
    let name = kind.label();
    let vhost_port = match kind {
        VhostKind::Http => cfg.vhost_http_port,
        VhostKind::Https => cfg.vhost_https_port,
        VhostKind::TcpMux => cfg.tcpmux_http_connect_port,
    };
    let Some(vhost_port) = vhost_port else {
        anyhow::bail!(
            "服务端未配置 {}，无法注册 {name} 代理",
            match kind {
                VhostKind::Http => "vhost_http_port",
                VhostKind::Https => "vhost_https_port",
                VhostKind::TcpMux =>
                    "tcpmux_http_connect_port（frps.toml 里叫 tcpmuxHTTPConnectPort）",
            }
        );
    };
    if kind == VhostKind::TcpMux && m.multiplexer != "httpconnect" {
        // 官方 `server/proxy/tcpmux.go` 的 `Run()`：`unknown multiplexer [%s]`
        anyhow::bail!(
            "tcpmux 代理 [{}] 的 multiplexer 是 {:?}，只支持 \"httpconnect\"",
            m.proxy_name,
            m.multiplexer
        );
    }
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
        anyhow::bail!("{name} 代理必须配置 custom_domains 或 subdomain");
    }

    let mut locations: Vec<String> = match kind {
        VhostKind::TcpMux => vec![String::new()],
        _ if m.locations.is_empty() => vec!["/".to_string()],
        _ => m.locations.clone(),
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
            kind,
        }))?;
    }
    client.add_proxy(m.proxy_name.clone(), None, slot);
    Ok(domains
        .iter()
        .map(|d| format!("{d}:{vhost_port}"))
        .collect::<Vec<_>>()
        .join(","))
}

async fn proxy_accept_loop(listener: TcpListener, remote_port: u16, registry: Arc<Registry>) {
    loop {
        match listener.accept().await {
            Ok((stream, peer)) => {
                // ★★ v0.5.8 修（第七轮审计 F7-1，中危）：**数据面也要过 ACL**。
                //
                // # 原先为什么错了
                //
                // `[acl]`（IP 白/黑名单）的唯一判定入口是
                // `SecurityContext::check_ip`，而它全仓只有 2 处调用：
                // 控制连接握手（`handle_frp_stream`）与 VirtualNet 注册。
                // **公网代理端口这条承载用户流量的路径上完全没有它。**
                //
                // 实测（`tmp/audit7/f/acl_dataplane_v3.py`，9/9 判据通过）：
                // 同一个服务端、同一份配置 `deny = ["127.0.0.1"]`，
                // 只改源地址 ——
                //
                // | 路径 | 源地址 | 结果 |
                // |---|---|---|
                // | 控制面 | 127.0.0.1（被 deny） | 被拒 ✓ |
                // | 控制面 | 192.168.3.15（放行） | 登录成功 ✓ |
                // | 数据面 | 192.168.3.15（正对照） | 转发成功 ✓ |
                // | **数据面** | **127.0.0.1（被 deny）** | **照常转发** ✗ |
                //
                // ⇒ 管理员用 ACL 表达"只允许某些来源访问"，实际只挡住了管理面，
                //   业务端口对全网开放。用**白名单**模式时更糟 —— 白名单形同虚设。
                //
                // 这与本项目连续六轮的模式一致："防线写对了，但没铺满它声称
                // 保护的所有路径"。修法就是把它铺到数据面的 accept 点上。
                //
                // 顺序与 `handle_frp_stream` 一致：ACL 是位运算，放在最前面最便宜。
                // 拒绝时**静默关连接**（不回任何数据）：这条路径上面对的是
                // 陌生访客，不该泄露"你被 ACL 拒了"这类可区分信息。
                let sec = registry.security();
                if let Err(reason) = sec.check_ip(peer.ip()) {
                    registry.audit().record(
                        crate::audit::AuditEvent::new(crate::audit::kind::LOGIN_DENIED, false)
                            .ip(peer.ip().to_string())
                            .detail(format!("{reason}（公网端口 {remote_port} 数据面）")),
                    );
                    debug!(%peer, port = remote_port, "数据面 IP 访问控制拒绝：{reason}");
                    continue;
                }
                // 小包请求-响应式流量（HTTP / RPC 等）关闭 Nagle：避免攒包引入
                // 毫秒级延迟；与 `vhost` / `vnet` 等其它数据面入口的处理一致。
                // 纯套接字选项，设置失败不影响转发。
                stream.set_nodelay(true).ok();
                // ---- NLink 端口敲门 ----
                //
                // 配了规则就默认**不信任任何来源**：必须先把敲门序列发上来，
                // 放行窗口内才允许真正的业务连接。
                //
                // 两条路径都关连接：
                // * 敲门成功 —— 这条连接本身不是业务流量（它只发了 33 字节）；
                // * 敲门失败/超时 —— 对外表现与"端口没开放"一致，不泄露存在性。
                //
                // 没配规则时这一段完全不执行（`knock_rule` 返回 None）。
                {
                    let nlink_rt = registry.nlink();
                    if let Some(rule) = nlink_rt.knock_rule(remote_port) {
                        if !nlink_rt.knock.is_allowed(peer.ip(), remote_port) {
                            let mut probe = stream;
                            let _ = crate::nlink::try_knock(
                                &mut probe,
                                rule,
                                peer.ip(),
                                &nlink_rt.knock,
                            )
                            .await;
                            debug!(%peer, port = remote_port, "未敲门的连接已关闭");
                            continue;
                        }
                    }
                }
                // group 负载均衡：这个端口背后可能挂着多个客户端（同组代理），
                // 每条新连接轮询挑一个；挑不到说明后端全掉了，直接关掉。
                // 选**在途连接最少**的后端，并立刻给它记一条 ——
                // 计数令牌一路带进 PendingUser，转发结束（或被拒）时自动减回去。
                let Some((backend, load)) = registry.pick_and_hold(remote_port) else {
                    debug!(%peer, port = remote_port, "端口没有可用后端，关闭连接");
                    continue;
                };
                let client = backend.client;
                let user = PendingUser {
                    // 必须用**被选中那个后端自己的**代理名：服务端就是靠它
                    // 在 StartWorkConn 里告诉客户端该服务哪条代理，
                    // 组内各成员的 name 可以完全不同（alice.web-a / bob.web-b），
                    // 拿创建监听器那个成员的名字下发，其他成员会找不到这条代理。
                    proxy: backend.proxy_name.clone(),
                    proxy_type: client.proxy_type(&backend.proxy_name),
                    client_user: client.user.clone(),
                    client_run_id: client.run_id(),
                    // ★ v0.6.6：数据面标志随用户连接带下去
                    use_encryption: {
                        let (e, _) = client.proxy_flags(&backend.proxy_name);
                        e
                    },
                    use_compression: {
                        let (_, c) = client.proxy_flags(&backend.proxy_name);
                        c
                    },
                    data_key: {
                        let (e, _) = client.proxy_flags(&backend.proxy_name);
                        e.then(|| nfrp_common::frp::v1::derive_key(sec.auth_cfg.token.as_bytes()))
                    },
                    remote_port,
                    stream: Box::pin(stream),
                    peer,
                    at: Instant::now(),
                    slot: ConnSlot::acquire(&registry.conn_limit, &client),
                    queue_permit: None,
                    load: Some(load),
                };
                admit_user(user, &client, &registry);
            }
            Err(e) => {
                tracing::error!(port = remote_port, "监听失败：{e}");
                break;
            }
        }
    }
}

/// 把一条用户连接交给客户端：先过配额，再排队配对。
///
/// 三条验收规则：
/// 1. **没有转发配额**（命中全局或单客户端上限）——立刻关连接，不留尾巴；
/// 2. **队列已满**——同样立刻关，别让它无限堆积；
/// 3. 成功入队——记得向控制连接索要一条新的工作连接。
pub fn admit_user(user: PendingUser, client: &Arc<ClientState>, registry: &Arc<Registry>) {
    if user.slot.is_none() {
        registry.metrics().conns_rejected.inc();
        warn!(
            proxy = %user.proxy,
            "转发连接数已达上限（全局 {} / 客户端 {}），拒绝本次连接",
            registry.limits().max_total_conns,
            registry.limits().max_conns_per_client
        );
        return;
    }
    registry.metrics().conns_total.inc();
    // ★★ v0.5.6 修（审计总报告 M7）：`conns_active.inc()` **不在这里**。
    //
    // 原先 `admit_user` 与 `handle_work` 各 inc 一次，而 `finish_conn` 只 dec 一次
    // ⇒ "用户先到、工作连接后到"这条路径 **+2 / -1**，每来一条连接就虚高 1。
    // 现在把 +1 收敛到配对成功的**唯一那一刻**（`bridge` 里的 `ConnGuard`）。
    match client.submit_user(user) {
        Submit::Paired(pair) => {
            let p = *pair;
            spawn_bridge(p.user, p.work, registry.clone())
        }
        Submit::Queued => client.request_work_conn(),
        Submit::Full(_u) => {
            registry.metrics().conns_rejected.inc();
            warn!(proxy = %_u.proxy, "待配对队列已满，拒绝本次连接");
        }
    }
}

// ---------------------------------------------------------------------------
// 工作连接
// ---------------------------------------------------------------------------

async fn handle_work(
    mut conn: FrpConn,
    mut msg: NewWorkConn,
    sec: &crate::guard::SecurityContext,
    registry: Arc<Registry>,
    peer: SocketAddr,
) -> Result<()> {
    let mut client = registry
        .get(&msg.run_id)
        .ok_or_else(|| anyhow!("找不到 run_id={} 对应的客户端", msg.run_id))?;

    // ---- NLink 零信任身份 ----
    //
    // 会话协商了 `identity` 才要求令牌。令牌绑定 `run_id + user + 过期时间`，
    // 由服务端 HMAC 签发 —— 比"源 IP 相同"强得多：拿到 run_id 也伪造不出来，
    // 而且过期就作废。官方 frpc 不会协商这个能力，所以永远走不到这里。
    if client.nlink_has(nfrp_common::nlink::CAP_IDENTITY) {
        let rt = registry.nlink();
        let token = msg.nlink.clone().unwrap_or_default();
        if let Err(e) = rt.identity.verify(
            &token,
            &msg.run_id,
            &client.user,
            std::time::SystemTime::now(),
        ) {
            tracing::debug!(run_id = %msg.run_id, user = %client.user, "身份令牌校验失败：{e:#}");
            registry.audit().record(
                crate::audit::AuditEvent::new(crate::audit::kind::LOGIN_DENIED, false)
                    .client(msg.run_id.clone())
                    .ip(peer.ip().to_string())
                    .detail(format!("工作连接身份令牌校验失败：{e:#}")),
            );
            anyhow::bail!("工作连接身份令牌校验失败：{e:#}");
        }
    }

    // 官方 `[[httpPlugins]]`：NewWorkConn。插件在凭证校验之前执行，
    // 可以拒绝（例如池被盗用）或改写 run_id / privilege_key。
    if !registry.plugins().is_empty() {
        let plugins = registry.plugins();
        let user = nfrp_common::plugin::user_info(
            &Login {
                user: client.user.clone(),
                ..Default::default()
            },
            &client.run_id(),
        );
        let content = nfrp_common::plugin::content_with_user(&msg, user)?;
        let new_content = plugins
            .handle_mutable(nfrp_common::plugin::OP_NEW_WORK_CONN, content)
            .await
            .map_err(|e| anyhow!("HTTP 插件拒绝工作连接：{e}"))?;
        msg = serde_json::from_value(new_content).context("插件返回的 NewWorkConn 内容无法解析")?;
        client = registry
            .get(&msg.run_id)
            .ok_or_else(|| anyhow!("插件改写后的 run_id={} 不存在", msg.run_id))?;
    }

    // ★★ v0.5.5 修（第四轮 A-1，高危）：工作连接必须绑定到**发起它的那个客户端**。
    //
    // 原先这里被 `auth_method() == Oidc` 门住，于是 **token 模式（默认）下
    // `msg.privilege_key` / `msg.timestamp` 从头到尾没人读** —— `run_id` 成了
    // 唯一门槛。而 `run_id` 是在 v1 的 `LoginResp` 里**明文**下发的
    // （登录前的报文不加密），所以拿到它并不难。
    //
    // 实测危险（`tmp/audit4-verify-A2b.py`，用真 frpc 拿真 run_id）：
    //
    // ```text
    // privilege_key 空 + ts=0        -> 接受（连接保持）
    // privilege_key 错误 + ts=1       -> 接受
    // privilege_key 垃圾 + 当前 ts     -> 接受
    // privilege_key 任意 + ts=-1      -> 接受
    // 服务端日志：工作连接进入空闲池 client=client-83284   × 5
    // ```
    //
    // 后果：攻击者往**受害者的空闲工作连接池**里灌自己的连接，
    // 此后连到受害者隧道的用户流量会落到攻击者的连接上 —— 完整 MITM。
    // A 组独立复现时 6/6 用户连接全部被劫持。
    //
    // ★★ 但"一刀切要求凭证"会**破坏与官方 frpc 的互通** —— 这是实测出来的，
    //   不是推测。官方 `pkg/auth/token.go` 的 `SetNewWorkConn`：
    //
    // ```go
    // if !slices.Contains(auth.additionalAuthScopes, v1.AuthScopeNewWorkConns) {
    //     return nil          // ← 不改 PrivilegeKey，保持零值 ""
    // }
    // ```
    //
    //   即**默认配置下官方 frpc 的工作连接不带凭证**。第一版修复直接要求
    //   "凭证必须等于 auth_key(token, ts)"，实测结果（`tmp/audit4-a1-diag.py`）：
    //
    // ```text
    // DEBUG yamux stream 结束：工作连接凭证不符（privilege_key 不是本会话 token 派生的）
    // → 官方 frpc 的 tcp 代理完全不通（用户连接超时）
    // ```
    //
    //   README 明确承诺"官方客户端不需要改任何配置就能连上"，所以不能这么修。
    //
    // ★★ 最终策略（既不破坏互通、又堵住劫持）：
    //
    // | 凭证 | 处理 |
    // |---|---|
    // | **非空** | 必须等于 `auth_key(token, ts)`（NFrp 客户端走这条） |
    // | **为空** | 要求工作连接的**源 IP 与控制连接一致**（官方 frpc 走这条） |
    //
    //   官方 frpc 天然满足"同源 IP"（同一个进程、同一个出口），**零兼容代价**；
    //   而攻击者要伪造源 IP 比"知道 run_id"难得多。这不是完美方案（NAT 后的
    //   同网段攻击者仍可能同 IP），但比"只查 run_id"强一个数量级。
    //
    //   实测验证：官方 frpc 0.71.0 经本服务端的 tcp 代理**转发成功**，
    //   而伪造凭证的四种形态（空/错误/垃圾/ts=-1）在"空凭证 + 源 IP 不同"
    //   的组合下全部被拒。
    let is_oidc = sec.auth_method() == nfrp_common::security::AuthMethod::Oidc;
    if is_oidc {
        // OIDC：沿用原有语义（验签 + subject 绑定到会话）
        if sec.auth_cfg.check_new_work_conns() {
            if let Err(e) = sec.verify_followup(&msg.privilege_key, "新工作连接", &msg.run_id)
            {
                registry.audit().record(
                    crate::audit::AuditEvent::new(crate::audit::kind::LOGIN_DENIED, false)
                        .client(msg.run_id.clone())
                        .detail(format!("工作连接凭证复核失败：{e:#}")),
                );
                anyhow::bail!("工作连接凭证复核失败：{e:#}");
            }
        }
    } else {
        // token 模式
        let token = sec.auth().secret().to_string();
        if token.is_empty() {
            // 空 token = 认证本来就没开（启动时已明确告警）。此时凭证无从校验，
            // 仍然要求同源 IP —— 比完全放行强。
            if peer.ip() != client.peer_ip() {
                registry.audit().record(
                    crate::audit::AuditEvent::new(crate::audit::kind::LOGIN_DENIED, false)
                        .client(msg.run_id.clone())
                        .ip(peer.ip().to_string())
                        .detail(format!(
                            "工作连接源 IP {} 与控制连接 {} 不一致（空 token 模式下仍拒绝）",
                            peer.ip(),
                            client.peer_ip()
                        )),
                );
                anyhow::bail!(
                    "工作连接来源与登录来源不一致（{} vs {}）",
                    peer.ip(),
                    client.peer_ip()
                );
            }
        } else if !msg.privilege_key.is_empty() {
            // 带了凭证 ⇒ **必须正确**。这是 NFrp 客户端的路径，
            // 也是攻击者最容易露馅的地方（凭证 = md5(token+ts)，猜不出来）。
            //
            // ★★ v0.5.7 修（第六轮审计 G-1，高危）：**改调 `verify_login`**。
            //
            //   原先这里是就地手写 `auth_key(token, ts)` 比对 —— 内容判对了，
            //   但**不知道有"新鲜性"这回事**（M3 的时间窗口只加在主登录一处）。
            //   实测：**一年前**的 `NewWorkConn` 凭证仍被接受，并且打通了
            //   完整双向 MITM（用户的明文落到攻击者手里、回包由攻击者伪造）。
            //
            //   改调 `verify_login` 而不是在这里补一行 `check_freshness`，
            //   是刻意的：前者的 `skew` 是**必需参数**，想校验凭证就必然
            //   带上时间窗口 —— 堵掉"下次又有人忘了加"的可能。
            //   token 模式下 `verify_login` 判的正是同一件事
            //   （`expected = auth_key(secret, ts)` 再定长比较），语义等价。
            if let Err(e) = sec.verify_login(&msg.privilege_key, msg.timestamp, &msg.run_id) {
                registry.audit().record(
                    crate::audit::AuditEvent::new(crate::audit::kind::LOGIN_DENIED, false)
                        .client(msg.run_id.clone())
                        .ip(peer.ip().to_string())
                        .detail(format!("工作连接凭证校验失败：{e:#}")),
                );
                anyhow::bail!(
                    "工作连接凭证不符（privilege_key 不是本会话 token 派生的，或已过期）"
                );
            }
        } else if client.caps().work_conn_cred {
            // ★★ 这条会话**自己声明过**"我的工作连接带凭证"
            //   （NFrp ≥ 0.5.5 恒声明，见 `client/src/main.rs`）。
            //   那它就必须带，且必须正确 —— **空凭证也拒**。
            //
            //   这是最有说服力的判据：`work_conn_cred` 是**受害者自己**在
            //   登录时声明的，攻击者改不了它。所以"拿 run_id 冒充"这条路
            //   在这里彻底断了，不必依赖源 IP（同 NAT 后的攻击者也拦得住）。
            registry.audit().record(
                crate::audit::AuditEvent::new(crate::audit::kind::LOGIN_DENIED, false)
                    .client(msg.run_id.clone())
                    .ip(peer.ip().to_string())
                    .detail("会话声明了 workConnCred 能力，但工作连接未携带凭证".to_string()),
            );
            anyhow::bail!("该会话声明了工作连接凭证能力，但本次工作连接未携带凭证");
        } else if peer.ip() != client.peer_ip() {
            // 没声明这个能力（官方 frpc、或老版 NFrp）：官方默认**不带凭证**，
            // 所以不能拦。退而求其次 —— 要求同源 IP。
            //
            // ★★ v0.5.6 修（审计总报告 L5，低危）：**把"可能是误拒"说清楚**。
            //
            // 这条判据在**混合传输**下可能误伤合法用户：控制连接走 TCP、
            // 工作连接走 QUIC（`protocol = "quic"`）时，两条连接的出口 IP
            // 可能不同 —— 多宿主机、多网卡、或 NAT 池有多个公网 IP 时都会发生。
            // 而官方 frpc 不带凭证，所以它**必然**走这条分支。
            //
            // 现状下用户的症状是：**控制连接登录成功、但每条用户连接都失败**，
            // 日志里只有一句"来源与登录来源不一致" —— 完全指不到"是网络路径不同"。
            //
            // ★ 为什么**不**放宽判据（如实说明）：
            //   放宽就等于让"拿 run_id 冒充"重新变得容易（那正是 A-1 要堵的）。
            //   在"可用性"和"防冒充"之间，这里选择**保住防线**，
            //   但把诊断信息补足，让人能一眼看出自己踩的是哪种情况。
            // ★ 提示语之所以**不**按"哪种传输"分支：`handle_work` 里拿不到
            //   服务端配置（它只收 registry / peer / conn），而为了写一句提示
            //   去把 `Arc<ServerConfig>` 一路传进来，代价大于收益。
            //   两种情况合并成一条，信息量一样够用。
            let hint = "（常见原因：多网卡 / NAT 池有多个出口 IP / 中间有代理，\
                        或控制连接与工作连接走了不同传输（TCP vs QUIC/KCP）\
                        导致出口 IP 不同；\
                        升级到 NFrp ≥0.5.5 客户端可改用凭证校验，不再依赖源 IP）";
            registry.audit().record(
                crate::audit::AuditEvent::new(crate::audit::kind::LOGIN_DENIED, false)
                    .client(msg.run_id.clone())
                    .ip(peer.ip().to_string())
                    .detail(format!(
                        "工作连接源 IP {} 与控制连接 {} 不一致（无凭证时必须同源）",
                        peer.ip(),
                        client.peer_ip()
                    )),
            );
            warn!(
                run_id = %msg.run_id,
                work_ip = %peer.ip(),
                control_ip = %client.peer_ip(),
                "工作连接与控制连接来源 IP 不一致，已拒绝 —— 若你确认是同一台机器，\
                 多半是两条连接走了不同网络路径"
            );
            anyhow::bail!(
                "工作连接来源与登录来源不一致（{} vs {}）—— 无凭证时必须同源。{hint}",
                peer.ip(),
                client.peer_ip()
            );
        } else {
            // ★★ v0.5.6 修（审计总报告 M14，中危）：**放行分支也必须审计**。
            //
            // 原先这条"无凭证 + 同源 IP ⇒ 放行"的路径**零审计** ——
            // 上面三条拒绝路径全都记了审计事件，唯独**真正放行**的这条什么都没记。
            //
            // 为什么这条特别值得记：它正是 A-1（工作连接凭证）修复的**兼容回退**
            // 分支，也是**最弱**的一条认证路径 —— 只靠源 IP 判断。
            // 攻击者若与受害者在同一出口 IP（同 NAT、同办公网、云上同 VPC），
            // 这里就是唯一还能拦住他的地方，而它**原本在日志里完全不可见**。
            //
            // ⇒ 事后审计时，"哪些工作连接是靠最弱判据放行的"必须是可回答的。
            //   记成 `detail` 而不是独立事件类型，是为了不改变既有事件 schema
            //   （避免下游解析器被新类型打乱）。
            registry.audit().record(
                crate::audit::AuditEvent::new(crate::audit::kind::LOGIN, true)
                    .client(msg.run_id.clone())
                    .user(client.user.clone())
                    .ip(peer.ip().to_string())
                    .target(msg.run_id.clone())
                    .detail(format!(
                        "工作连接以**无凭证 + 同源 IP** 放行（客户端未声明 workConnCred 能力，\
                         判据仅源 IP={}）；若要收紧请升级客户端到 ≥0.5.5",
                        peer.ip()
                    )),
            );
        }
    }
    // 工作连接必须与控制连接用同一套线协议 —— 与官方 frps 的
    // `work connection wire protocol mismatch` 检查对齐。
    // 对不上的话后面收发消息会直接解析失败，报错信息离原因很远，所以先挡下来。
    if conn.version() != client.wire_version() {
        anyhow::bail!(
            "run_id={} 的工作连接线协议是 {}，控制连接是 {}",
            msg.run_id,
            conn.version(),
            client.wire_version()
        );
    }
    // 工作连接继承控制连接协商出的 UDP 报文编码
    conn.set_udp_codec(client.udp_codec_is_binary());
    let work = WorkItem::new(conn);
    match client.submit_work(work) {
        Some(p) => {
            debug!(proxy = %p.user.proxy, "工作连接与排队用户配对");
            // ★★ v0.5.6（M7）：这里**不再** inc —— 计数收敛到 `bridge` 的
            //   `ConnGuard`（配对成功那一刻 +1，作用域结束 -1）。
            //   原先这里与 `admit_user` 各加一次，于是 +2/-1 虚高。
            spawn_bridge(p.user, p.work, registry.clone());
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
/// SUDP 例外：数据面是 UDP 帧（`UdpPacket` 消息），走 [`sudp_bridge`] 而不是裸字节 relay。
async fn handle_visitor(
    mut conn: FrpConn,
    msg: NewVisitorConn,
    registry: Arc<Registry>,
    cfg: Arc<ServerConfig>,
) -> Result<()> {
    let proxy_name = msg.proxy_name.clone();

    /// 回一条错误响应并结束（官方 frpc 会把 error 原样打到日志上）。
    async fn reject(
        conn: &mut FrpConn,
        proxy_name: &str,
        err: String,
        registry: &Registry,
    ) -> Result<()> {
        reject_with(conn, proxy_name, err, registry, None).await
    }

    /// 同上，但把"回给对端的文案"与"日志里的详情"分开。
    ///
    /// ★ v0.5.3 修：visitor 这条路径原来**完全没走** `detailed_errors_to_client`
    /// 开关，把内部细节原样回给了**尚未通过任何认证**的来访者，包括：
    ///
    /// * 代理名是否存在（可用来枚举 stcp 隧道名）；
    /// * `allow_users` 里的真实用户名（`visitor connection of [x] user [alice] not allowed`）；
    /// * `run_id` 是否在线。
    ///
    /// 现在：`client_msg = None` 时按开关脱敏成短句，详情只留在服务端日志/审计里。
    async fn reject_with(
        conn: &mut FrpConn,
        proxy_name: &str,
        err: String,
        registry: &Registry,
        client_msg: Option<String>,
    ) -> Result<()> {
        registry.metrics().visitor_rejected.inc();
        // 日志始终保留完整详情（排障需要），但对端只看到脱敏后的文案
        let shown = client_msg.unwrap_or_else(|| err.clone());
        let _ = conn
            .send_msg(&FrpMessage::NewVisitorConnResp(NewVisitorConnResp {
                proxy_name: proxy_name.to_string(),
                error: shown,
            }))
            .await;
        // 必须优雅关闭：直接 drop 会变成 RST，对端读不到 error，只会看到 connection reset
        let _ = conn.shutdown().await;
        anyhow::bail!("visitor 接入被拒绝：{err}");
    }

    // 1) run_id 必须能对上一条已登录的控制会话（对应 frps 的 admitVisitorByRunID）
    //
    // ★★ v0.5.7 修（第六轮审计 D-2，中危）：**空 `run_id` 不再被放行**。
    //
    // # 原先为什么错了
    //
    // 原判据是 `if !msg.run_id.is_empty() && registry.get(&msg.run_id).is_none()`
    // —— `run_id` 为空时**整条判断被短路**，于是"会话存在性"这一环被整个跳过。
    // 接着身份推导 `registry.get(&msg.run_id).map(|c| c.user).unwrap_or_default()`
    // 在空 `run_id` 下退化成**空串**，而 `check_user` 里
    // `.any(|u| u == "*" || u == visitor_user)` 让空串**命中 `"*"`** ⇒
    // **一条完全没有登录、没有 token、没有 run_id 的连接**被判定为合法访客。
    //
    // 实测（`tmp/audit6-d/_repro_d2_anon.py`）端到端确认：匿名连接发出的
    // `ANON-PAYLOAD-FROM-NOBODY` **真的到达了 alice 的工作连接**。
    //
    // # 为什么可以要求非空
    //
    // 官方 frpc 的 visitor **一定**会带自己的 `run_id`
    // （`common/src/frp/msg.rs` 的 `NewVisitorConn.run_id` 字段注释），
    // 所以这个收紧对官方客户端**零影响**；而"字段缺失 ⇒ 跳过校验"
    // 本来就是认证路径上最危险的模式之一。
    //
    // 文案与下面所有拒绝路径**完全一致**（不新增可区分信息）——
    // 否则"空 run_id 被单独拒绝"本身又成了一个可区分信号。
    let Some(session) = registry.get(&msg.run_id) else {
        // ★★ v0.5.5 修（第四轮 A-3）：**这一条无论如何都只回通用文案**，
        // 不受 `detailed_errors_to_client` 影响。
        //
        // 为什么单独处理它：它本质上是一个 **run_id 在线预言机** ——
        // 攻击者可以拿任意 run_id 来问"这个会话在线吗"。而
        // `detailed_errors_to_client` 默认是 `true`（与官方一致），
        // 于是默认配置下这个预言机是**敞开的**（实弹 `tmp/a4_t10_state.py`
        // 打出三条可区分文本）。现在空 run_id 也走这一条。
        //
        // 为什么可以直接忽略那个开关：`run_id` 是**服务端/客户端内部**生成的，
        // 合法的 visitor 从来不需要"我这条 run_id 在不在线"这个细节 ——
        // 那个开关的存在意义是帮用户排查**自己的配置**（代理名、密钥），
        // 而这条错误里没有任何用户配置信息。所以对它脱敏**不损失可用性**，
        // 只堵掉探测面。详情仍然进服务端日志与审计。
        warn!(
            %proxy_name,
            run_id_empty = msg.run_id.is_empty(),
            "visitor 的 run_id 为空或找不到对应会话"
        );
        return reject_with(
            &mut conn,
            &proxy_name,
            format!("no client control found for run id [{}]", msg.run_id),
            &registry,
            Some("visitor connection failed".to_string()),
        )
        .await;
    };

    // 2) 代理必须已注册
    //
    // ★★ v0.5.7 修（第六轮审计 D-4，中危）：**两条拒绝路径共用同一条文案**。
    //
    // # 原先为什么错了
    //
    // 原注释写着"短句与『密钥不对』保持同一形态，攻击者无法据此区分
    // 『名字错』还是『名字对但密钥错』" —— **但代码没有做到**：
    // 这里回 `custom listener for [X] doesn't exist`，
    // 下面密钥失败回 `visitor connection of [X] auth failed`，
    // 两条**结构完全不同**；而且它们都经过 `cfg.error_to_client(...)`，
    // 受 `detailed_errors_to_client` 控制 —— 那个开关**默认为 `true`**，
    // 所以注释声称的"无法区分"**在默认配置下完全不成立**。
    //
    // 实测（`tmp/audit6-d/d06c_oracle.py`）：4/4 真实隧道名被识别为"存在"、
    // 3/3 假名被排除，**准确率 100%**，而且**不需要登录 / token / run_id**
    // （配合上面 D-2 的匿名路径）。
    //
    // # 修法：抄同一文件里已经做对的那一处
    //
    // 上面 run_id 预言机（A-3）用的是**硬编码固定文案 + 不经过开关** ——
    // 同一个文件里同类问题的两种处理方式，这次统一成对的那种。
    // 用户排查自己配置所需的信息（"代理名/密钥配错了"）仍然进服务端日志
    // 与审计，只是不再回给未认证的对端。
    let Some(entry) = registry.visitors.get(&proxy_name) else {
        warn!(%proxy_name, "visitor 请求的代理名不存在（细节仅服务端可见）");
        return reject_with(
            &mut conn,
            &proxy_name,
            "visitor connection failed".to_string(),
            &registry,
            Some("visitor connection failed".to_string()),
        )
        .await;
    };

    // 3) 密钥签名校验：hex(md5(secret_key + timestamp))
    //
    // ★ v0.5.7（第六轮审计 G-1）：把 `registry` 的时钟窗口传进去 ——
    //   新鲜性校验在 `check_sign` 内部，不是可选项。
    if !entry.check_sign(
        &msg.sign_key,
        msg.timestamp,
        registry.security().max_clock_skew_secs(),
    ) {
        warn!(proxy = %proxy_name, "visitor 密钥校验失败");
        // ★ v0.5.7（第六轮审计 D-4）：文案与"代理名不存在"那条**逐字一致**，
        //   且不经过 `detailed_errors_to_client`（那个开关默认 true，
        //   经过它就等于把"名字对不对"送出去）。
        //   排查信息进服务端日志，不回给未认证的对端。
        return reject_with(
            &mut conn,
            &proxy_name,
            "visitor connection failed".to_string(),
            &registry,
            Some("visitor connection failed".to_string()),
        )
        .await;
    }

    // 4) 访客用户白名单
    //
    // 与官方 frps 一致：比对的**不是** visitor 的 name，而是发起这条 visitor 连接的那个
    // frpc 在 Login 里声明的顶层 `user`（对应 frpc.toml 的 `user = "alice"`）。
    //
    // ★★ v0.5.7 修（第六轮审计 D-2）：**从上面已经取到的 `session` 直接拿**，
    //   不再 `registry.get(&msg.run_id).unwrap_or_default()`。
    //
    //   后者在 `run_id` 为空（或会话刚好掉线）时退化成**空串**，而
    //   `check_user` 里 `.any(|u| u == "*" || u == visitor_user)` 会让
    //   空串**命中 `"*"`** ⇒ 匿名连接被当成合法访客。
    //   现在第 1 步已经保证会话存在，`user` 必然是真实身份。
    let visitor_user = session.user.clone();
    if !entry.check_user(&visitor_user) {
        warn!(proxy = %proxy_name, user = %visitor_user, "visitor 用户不在 allow_users 白名单内");
        // ★ 脱敏：**绝不能**把 allow_users 里的真实用户名回显出去 ——
        //   那直接泄露了"谁被允许访问这条隧道"，也等于确认了这个用户名有效。
        return reject_with(
            &mut conn,
            &proxy_name,
            format!("visitor connection of [{proxy_name}] user [{visitor_user}] not allowed"),
            &registry,
            Some(cfg.error_to_client(
                "visitor connection failed",
                &format!("visitor connection of [{proxy_name}] user not allowed"),
            )),
        )
        .await;
    }

    // 5) 转发配额（stcp 走中继时同样占用一条连接）
    let slot = ConnSlot::acquire(&registry.conn_limit, &entry.client);
    if slot.is_none() {
        registry.metrics().conns_rejected.inc();
        return reject(
            &mut conn,
            &proxy_name,
            "server is busy: too many active connections".to_string(),
            &registry,
        )
        .await;
    }

    // 6) 先回成功（官方 frps 也是先 PutConn 再回 ok，之后才去池里取工作连接）
    conn.send_msg(&FrpMessage::NewVisitorConnResp(NewVisitorConnResp {
        proxy_name: proxy_name.clone(),
        error: String::new(),
    }))
    .await
    .context("发送 NewVisitorConnResp 失败")?;
    registry.metrics().visitor_conns.inc();
    registry.metrics().conns_total.inc();
    // ★★ v0.5.6（M7）：这里**不再** inc —— `bridge` / `spawn_sudp_bridge`
    //   里的守卫会各自在配对成功那一刻 +1，并在离开作用域时 -1。
    //   原先这里 inc + `acquire_work_conn` 失败时手工 dec，是"配对前就加、
    //   失败要手工回滚"的脆弱写法。

    // 7) 向 provider 要一条工作连接并配对
    let Some(work) = entry.client.acquire_work_conn().await else {
        anyhow::bail!("provider [{proxy_name}] 没有可用的工作连接，visitor 连接关闭");
    };

    // SUDP：数据面是 UDP 帧，走专门的搬运路径（与 stcp / xtcp 的裸字节 relay 区分）
    // UDP 编码用该 visitor 连接所属控制会话协商出的值（`ServerAccept::Visitor` 里带过来）
    if entry.proxy_type == "sudp" {
        info!(proxy = %proxy_name, kind = "sudp", "SUDP visitor 接入成功，开始 UDP 帧中继");
        spawn_sudp_bridge(conn, work, registry.clone(), proxy_name.clone());
        return Ok(());
    }

    let (stream, leftover) = conn.into_stream();
    let user = PendingUser {
        proxy: proxy_name.clone(),
        proxy_type: entry.proxy_type.clone(),
        client_user: entry.client.user.clone(),
        client_run_id: entry.client.run_id(),
        // visitor 走的是 visitor 自己那条通道，加密/压缩由它自己协商
        use_encryption: false,
        use_compression: false,
        data_key: None,
        // visitor 没有公网端口概念
        remote_port: 0,
        stream: Box::pin(PrefixedStream::new(leftover, stream)),
        peer: SocketAddr::from(([0, 0, 0, 0], 0)),
        at: Instant::now(),
        slot,
        queue_permit: None,
        load: None,
    };
    info!(proxy = %proxy_name, kind = %entry.proxy_type, "visitor 接入成功，开始中继");
    spawn_bridge(user, work, registry.clone());
    Ok(())
}
/// 活跃转发连接的**计数守卫**（v0.5.6 修审计总报告 M7）。
///
/// # 为什么用 RAII 而不是手工 `dec()`
///
/// 审计报告在 `serve.rs` 里找出**四处**同类问题：
///
/// | 位置 | 问题 |
/// |---|---|
/// | `admit_user` + `handle_work` | **重复 inc**（用户先到 + 工作后到 ⇒ +2 只 -1） |
/// | `CloseProxy` 分支 | 无条件 dec（对不存在的名字也减）—— 同 M8，已修 |
/// | `bridge` 里两处 `?` | 提前返回**漏 dec** |
/// | `sudp_bridge` 里两处 `?` | 同上 |
///
/// ⇒ 攻击者持合法凭证反复"建连接 → 立刻断开"，就能让 `conns_active`
/// **单调上涨**（指标不可信，削弱管理员发现异常的能力；**不构成配额绕过**，
/// 配额走信号量）。
///
/// ★ 关键洞察：这四处**不是四个 bug，是同一个 bug 的四个表现** ——
///   "配对的 +1 与结束的 -1 分散在两处，中间任何一条提前返回都会漏掉 -1"。
///   手工在每个返回点补 `dec()` 只会把"四处"变成"更多处"，下次加一个
///   `?` 又漏。**用 Drop 把 -1 绑到作用域上，就再也不可能漏**。
///
/// ★ 用法：**配对成功那一刻**创建守卫，之后函数怎么返回都无所谓：
///
/// ```ignore
/// let _guard = ConnGuard::new(&registry);   // +1
/// ... 任意多个 `?` ...
/// ```                                       // 作用域结束自动 -1
struct ConnGuard<'a> {
    registry: &'a Registry,
    /// 结束时要把流量统计一起记账（`relay_between` 的返回值）。
    bytes: std::cell::Cell<(u64, u64)>,
}

impl<'a> ConnGuard<'a> {
    fn new(registry: &'a Registry) -> Self {
        registry.metrics().conns_active.inc();
        Self {
            registry,
            bytes: std::cell::Cell::new((0, 0)),
        }
    }

    /// 记下本次转发的字节数（由 relay 的返回值提供）。
    fn record_bytes(&self, up: u64, down: u64) {
        self.bytes.set((up, down));
    }
}

impl Drop for ConnGuard<'_> {
    fn drop(&mut self) {
        let (up, down) = self.bytes.get();
        self.registry.metrics().bytes_up.inc_by(up);
        self.registry.metrics().bytes_down.inc_by(down);
        self.registry.metrics().conns_active.dec();
    }
}

pub fn spawn_bridge(user: PendingUser, work: WorkItem, registry: Arc<Registry>) {
    tokio::spawn(async move {
        // 官方 `[[httpPlugins]]`：NewUserConn。
        //
        // 放在所有用户连接路径的汇合点（tcp / vhost / visitor 最终都会走
        // `spawn_bridge`），因此不会出现"只给 tcp 调、http 漏掉"这种
        // 防线铺不满的问题。插件拒绝时直接关闭这条用户连接。
        if !registry.plugins().is_empty() {
            let plugins = registry.plugins();
            let info = nfrp_common::plugin::user_info(
                &Login {
                    user: user.client_user.clone(),
                    ..Default::default()
                },
                &user.client_run_id,
            );
            let content = serde_json::json!({
                "user": info,
                "proxy_name": user.proxy.clone(),
                "proxy_type": user.proxy_type.clone(),
                "remote_addr": user.peer.to_string(),
            });
            if let Err(e) = plugins
                .handle_mutable(nfrp_common::plugin::OP_NEW_USER_CONN, content)
                .await
            {
                registry.metrics().conns_rejected.inc();
                warn!(proxy = %user.proxy, "HTTP 插件拒绝用户连接：{e:#}");
                return;
            }
        }
        if let Err(e) = bridge(user, work, &registry).await {
            debug!("转发结束：{e:#}");
        }
    });
}

/// 通知客户端这条工作连接属于哪个代理，然后开始双向转发原始字节。
pub async fn bridge(user: PendingUser, work: WorkItem, registry: &Arc<Registry>) -> Result<()> {
    let PendingUser {
        proxy,
        remote_port,
        client_user,
        stream: mut user_stream,
        peer,
        use_encryption: user_enc,
        use_compression: user_comp,
        data_key: user_key,
        ..
    } = user;
    let mut work_conn = work.conn;

    // ★★ v0.5.6（M7）：**配对成功这一刻**建守卫 ⇒ +1，且保证**只有一次**。
    //   于是 `admit_user` 与 `handle_work` 里那两处 inc 都不需要了
    //   （它们分别在"用户到达"和"工作连接配对"时各加一次，导致 +2/-1）。
    let guard = ConnGuard::new(registry);

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

    let (work_stream, leftover) = work_conn.into_stream();

    // ★★ leftover 是 frpc → frps 方向多读到的字节。明文时它就是响应的
    // 开头，直接写给用户是对的；但**开了加密/压缩时它是密文前缀**，
    // 直接写给用户会把响应破坏成乱码（实测：用户收到的
    // HTTP 响应长度对不上 / 完全超时）。
    //
    // 所以这里只在"不包" 的情况下直接写；要包的话把 leftover
    // 当作 work_stream 的前缀拼回去，交给 ProxyStream 去解。
    // 标志已随 PendingUser 带下来，这里直接用
    let will_wrap = user_enc || user_comp;
    if !leftover.is_empty() && !will_wrap {
        use tokio::io::AsyncWriteExt;
        user_stream.write_all(&leftover).await?;
    }
    let mut work_stream: nfrp_common::frp::stream::BoxStream = if will_wrap {
        Box::pin(nfrp_common::frp::stream::PrefixedStream::new(
            leftover,
            work_stream,
        ))
    } else {
        Box::pin(work_stream)
    };

    // 无论成功、失败、还是上面某个 `?` 提前返回，`guard` 都会在作用域结束时
    // 归还计数 —— 这就是 RAII 修法的全部价值。
    // ★ v0.6.6：数据面解密 / 解压（官方 transport.useEncryption / useCompression）
    //
    // 与客户端对称：包在**工作连接**这一侧（work_stream = 到 frpc 的那条），
    // 用户连接（user_stream）保持明文。
    //
    // 标志来自注册时记下的 NewProxy 字段。查不到就当没配（明文透传）——
    // 绝不能“查不到就按密文解”，那会把正常流量解成垃圾。
    let (enc, comp) = (user_enc, user_comp);
    // NLink 限流：规则表为空时**完全走原来的路径**（零额外开销、零行为差异）。
    let nlink_rt = registry.nlink();
    let limiter = if nlink_rt.rate_limit_enabled() {
        Some(&nlink_rt.limiter)
    } else {
        None
    };
    let relay_result = match (limiter, enc || comp) {
        (None, true) => {
            let key = user_key;
            debug!(proxy = %proxy, enc, comp, "服务端数据面已启用解密/解压");
            let mut wrapped =
                nfrp_common::frp::proxy_stream::ProxyStream::new(work_stream, key, comp);
            util::relay_between(&mut user_stream, &mut wrapped).await
        }
        (None, false) => util::relay_between(&mut user_stream, &mut work_stream).await,
        (Some(lim), true) => {
            let key = user_key;
            debug!(proxy = %proxy, enc, comp, "服务端数据面已启用解密/解压（带限流）");
            let mut wrapped =
                nfrp_common::frp::proxy_stream::ProxyStream::new(work_stream, key, comp);
            crate::nlink::relay_throttled(lim, &client_user, &proxy, &mut user_stream, &mut wrapped)
                .await
        }
        (Some(lim), false) => {
            crate::nlink::relay_throttled(
                lim,
                &client_user,
                &proxy,
                &mut user_stream,
                &mut work_stream,
            )
            .await
        }
    };

    match relay_result {
        Ok((up, down)) => {
            debug!(proxy = %proxy, "转发结束：上行 {up}B / 下行 {down}B");
            guard.record_bytes(up, down);
        }
        Err(e) => {
            debug!(proxy = %proxy, "转发中断：{e}");
        }
    }
    drop(guard);
    Ok(())
}

/// SUDP 配对：把一条已握手成功的 visitor 连接（`conn`）与 provider 的一条工作连接（`work`）
/// 组成一条 UDP 帧双向通道。
///
/// 与官方 SUDP 一致：
/// * visitor 侧跑 `UdpPacket` 帧（type 13），`remote_addr` 标识"本地应用进程"；
/// * provider 侧同样跑 `UdpPacket` 帧（`udp_proxy::run` 里的那套）；
/// * 服务端只是把**整条 `UdpPacket` 帧（含 `remote_addr`）**原样在两端之间搬过来，
///   不解析 payload —— 这样 provider 侧仍能按 `remote_addr` 把响应写回正确的本地应用；
/// * UDP 编码（JSON / 二进制）必须跟控制会话协商值一致。
fn spawn_sudp_bridge(conn: FrpConn, work: WorkItem, registry: Arc<Registry>, proxy_name: String) {
    tokio::spawn(async move {
        if let Err(e) = sudp_bridge(conn, work, &registry, proxy_name).await {
            debug!("SUDP 转发结束：{e:#}");
        }
    });
}

async fn sudp_bridge(
    visitor_conn: FrpConn,
    work: WorkItem,
    registry: &Arc<Registry>,
    proxy_name: String,
) -> Result<()> {
    let mut provider_conn = work.conn;

    // ★★ v0.5.6（M7）：配对成功这一刻建守卫 ⇒ +1，且离开作用域必然 -1。
    //   原先 `finish_conn` 只在最后一行调用，而下面 `?` 提前返回时会漏掉
    //   （审计报告指出的 `:1905` / `:1913` 两处）。
    let guard = ConnGuard::new(registry);

    // ★ 与官方 frps 一致：拿到工作连接后**先**发 `StartWorkConn` 告诉客户端
    //   "这条连接服务哪个代理"，之后才谈业务帧。
    //   少了这一步，客户端的 `client_work_conn` 还停在等 StartWorkConn，
    //   收到我们的 UdpPacket 只会报"期望 StartWorkConn"并关掉连接 ——
    //   症状很迷惑：上行有字节、下行永远 0，通道每隔几秒重建一次。
    provider_conn
        .send_msg(&FrpMessage::StartWorkConn(StartWorkConn {
            // 必须用**线上全名**（带 `{user}.` 前缀），客户端按它查本地代理表
            proxy_name: proxy_name.clone(),
            ..Default::default()
        }))
        .await
        .context("发送 StartWorkConn 失败")?;

    // ★ UDP 编码用每条连接**自己**协商出来的值：visitor 连接在握手时定，
    //   provider 工作连接在 `handle_work` 里已从控制会话继承。这里再覆盖一次
    //   （哪怕是"正确"的值）都会与官方 frpc 分叉——它只认协商结果。
    //
    // 双向搬运整条 UdpPacket 帧（含 remote_addr），直到任一端断开。
    // 注意这里按值交出连接：relay_sudp_frames 内部要把每条连接独占给一个协程。
    let (up, down) = relay_sudp_frames(visitor_conn, provider_conn).await?;
    debug!(proxy = %proxy_name, "SUDP 转发结束：上行 {up}B / 下行 {down}B");
    guard.record_bytes(up, down);
    drop(guard);
    Ok(())
}

/// 在两条 frp 连接之间双向搬运整条 `UdpPacket` 帧。
///
/// 搬运的是**完整帧**（保留 `remote_addr`），`Ping` 不转发（各端自己心跳即可），
/// 任一端读关闭（`recv_msg` 返回 `None`）即整体结束。
///
/// 实现：`FrpConn` 是**单所有者**，读写必须收敛进同一个协程的 `select!`
/// （与 `udp_proxy::run_session` 一个套路——它的三个分支都在借用同一个 conn）。
/// 所以这里不是「两读两写四个协程」，而是**两条连接各归一个协程独占**：
/// 协程 A 独占 visitor 连接、协程 B 独占 provider 工作连接，两者用两条 mpsc
/// 通道交换报文。任一端退出会 drop 掉自己那侧的 sender，对侧 `recv` 因此
/// 返回 `None` 而连锁收工，不会留下半边悬挂。
async fn relay_sudp_frames(a: FrpConn, b: FrpConn) -> Result<(u64, u64)> {
    use std::sync::atomic::{AtomicU64, Ordering};
    use tokio::sync::mpsc;

    // a -> b 方向：协程 A 读 a，协程 B 写 b（上行，访客请求）
    let (to_b_tx, to_b_rx) = mpsc::channel::<UdpPacket>(1024);
    // b -> a 方向：协程 B 读 b，协程 A 写 a（下行，服务回包）
    let (to_a_tx, to_a_rx) = mpsc::channel::<UdpPacket>(1024);

    let up = std::sync::Arc::new(AtomicU64::new(0));
    let down = std::sync::Arc::new(AtomicU64::new(0));

    // 协程 A：独占 visitor 连接
    let side_a = {
        let mut a = a;
        let tx = to_b_tx;
        let mut rx = to_a_rx;
        let down = std::sync::Arc::clone(&down);
        async move {
            loop {
                tokio::select! {
                    msg = a.recv_msg() => {
                        let Ok(Some(m)) = msg else { break };
                        // 只搬 UdpPacket，Ping 等控制帧各端自己消化
                        if let FrpMessage::UdpPacket(pkt) = m {
                            if tx.send(pkt).await.is_err() {
                                break;
                            }
                        }
                    }
                    pkt = rx.recv() => match pkt {
                        Some(pkt) => {
                            let n = pkt.payload().len() as u64;
                            if a.send_msg(&FrpMessage::UdpPacket(pkt)).await.is_err() {
                                break;
                            }
                            down.fetch_add(n, Ordering::Relaxed);
                        }
                        // 对侧协程已收工，队列不再有数据
                        None => break,
                    },
                }
            }
        }
    };

    // 协程 B：独占 provider 工作连接
    let side_b = {
        let mut b = b;
        let tx = to_a_tx;
        let mut rx = to_b_rx;
        let up = std::sync::Arc::clone(&up);
        async move {
            loop {
                tokio::select! {
                    msg = b.recv_msg() => {
                        let Ok(Some(m)) = msg else { break };
                        if let FrpMessage::UdpPacket(pkt) = m {
                            if tx.send(pkt).await.is_err() {
                                break;
                            }
                        }
                    }
                    pkt = rx.recv() => match pkt {
                        Some(pkt) => {
                            let n = pkt.payload().len() as u64;
                            if b.send_msg(&FrpMessage::UdpPacket(pkt)).await.is_err() {
                                break;
                            }
                            up.fetch_add(n, Ordering::Relaxed);
                        }
                        None => break,
                    },
                }
            }
        }
    };

    // 就地并发（不用 spawn：&mut 借用跨不了 'static，而这里已经按值交出所有权）
    tokio::join!(side_a, side_b);

    Ok((up.load(Ordering::Relaxed), down.load(Ordering::Relaxed)))
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

/// 供单元测试构造 pending user 的辅助函数。
#[cfg(test)]
pub(crate) fn test_pending(proxy: &str, slot: Option<ConnSlot>) -> PendingUser {
    PendingUser {
        proxy: proxy.to_string(),
        proxy_type: "tcp".to_string(),
        client_user: "test".to_string(),
        client_run_id: "test-run".to_string(),
        use_encryption: false,
        use_compression: false,
        data_key: None,
        remote_port: 0,
        stream: Box::pin(tokio::io::empty()),
        peer: SocketAddr::from(([127, 0, 0, 1], 8080)),
        at: Instant::now(),
        slot,
        queue_permit: None,
        load: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::limits::Limit;
    use crate::registry::ServerLimits;
    use tokio::sync::mpsc;

    fn client_with(conn_limit: Limit, registry: &Registry) -> Arc<ClientState> {
        let (tx, rx) = mpsc::unbounded_channel::<CtrlCmd>();
        std::mem::forget(rx);
        let (_, backlog, proxy) = registry.limits().per_client();
        Arc::new(ClientState::new(
            "run".into(),
            "id".into(),
            String::new(),
            tx,
            Duration::from_secs(60),
            Duration::from_secs(10),
            Default::default(),
            false,
            nfrp_common::frp::WireVersion::V1,
            conn_limit,
            backlog,
            0,
            proxy,
            "127.0.0.1".parse::<std::net::IpAddr>().unwrap(),
        ))
    }

    #[test]
    fn limits_from_config_defaults_to_unlimited() {
        let cfg = ServerConfig::default();
        let l = limits_from(&cfg);
        assert_eq!(l.max_total_conns, 0, "默认必须保持向后兼容：不限制");
        assert_eq!(l.max_clients, 0);
    }

    /// ★ C9-3 修复的回归锁：闸门排满后必须**排队超时放弃**，而不是无限等待。
    #[tokio::test]
    async fn 未认证闸门排满后排队超时放弃() {
        let gate = tokio::sync::Semaphore::new(1);
        let held = gate.acquire().await.expect("拿住唯一名额");
        let got = acquire_preauth_slot_with(&gate, Duration::from_millis(50)).await;
        assert!(got.is_none(), "排满时必须超时放弃");
        drop(held);
        let got2 = acquire_preauth_slot_with(&gate, Duration::from_millis(50)).await;
        assert!(got2.is_some(), "名额释放后应当立刻拿到");
    }

    // ---- allowPorts / maxPortsPerClient ----

    fn tcp_proxy(name: &str, port: u16) -> nfrp_common::frp::msg::NewProxy {
        nfrp_common::frp::msg::NewProxy {
            proxy_name: name.to_string(),
            proxy_type: "tcp".to_string(),
            remote_port: port,
            ..Default::default()
        }
    }

    /// ★ `allowPorts` 是安全项：白名单外的端口必须在**绑定之前**就被拒。
    #[tokio::test]
    async fn allow_ports_拦下白名单外的端口() {
        let registry = Arc::new(Registry::unlimited());
        let client = client_with(Limit::unlimited(), &registry);
        let cfg = Arc::new(ServerConfig {
            bind_addr: "127.0.0.1".into(),
            allow_ports: nfrp_common::config::parse_port_ranges("20000-30000,8443").unwrap(),
            ..Default::default()
        });

        // 22 不在白名单
        let err = register_proxy(&cfg, &registry, &client, &tcp_proxy("sshd", 22))
            .await
            .expect_err("白名单外的端口必须被拒")
            .to_string();
        assert!(err.contains("allowPorts"), "错误里要点名配置项：{err}");
        assert!(err.contains("22"), "错误里要带上是哪个端口：{err}");
        assert!(err.contains("20000-30000"), "错误里要带上允许范围：{err}");

        // 30001 刚好越过上界
        assert!(
            register_proxy(&cfg, &registry, &client, &tcp_proxy("p", 30001))
                .await
                .is_err()
        );
        // 8443 是 single 项，必须算数
        assert!(cfg.port_allowed(8443));
    }

    /// 白名单**内**的端口不能被这道闸拦下 —— 它应该一路走到"真的去 bind"。
    /// 这里把 `bind_addr` 故意写成一个解析不了的地址，于是错误一定是"解析失败"，
    /// 从而能确定地证明 allowPorts 这一关放行了（不依赖任何"空闲端口"的运气）。
    #[tokio::test]
    async fn allow_ports_放行白名单内的端口() {
        let registry = Arc::new(Registry::unlimited());
        let client = client_with(Limit::unlimited(), &registry);
        let cfg = Arc::new(ServerConfig {
            bind_addr: "300.300.300.300".into(),
            allow_ports: nfrp_common::config::parse_port_ranges("20000-30000").unwrap(),
            ..Default::default()
        });

        let err = register_proxy(&cfg, &registry, &client, &tcp_proxy("ok", 25000))
            .await
            .expect_err("地址解析不了，后面必然失败")
            .to_string();
        assert!(
            !err.contains("allowPorts"),
            "白名单内的端口不该被 allowPorts 拦下：{err}"
        );
        assert!(err.contains("解析"), "应该走到解析地址那一步：{err}");
    }

    /// ★ `maxPortsPerClient`：按**端口数**（不是代理数）封顶。
    #[tokio::test]
    async fn max_ports_per_client_按端口数封顶() {
        let registry = Arc::new(Registry::unlimited());
        let client = client_with(Limit::unlimited(), &registry);
        let cfg = Arc::new(ServerConfig {
            bind_addr: "300.300.300.300".into(),
            max_ports_per_client: 2,
            ..Default::default()
        });

        // 先手工占掉 2 个端口（注册内存里的条目就够，不必真的 bind）
        for (i, name) in ["a", "b"].iter().enumerate() {
            let slot = client.reserve_proxy().expect("名额充足");
            client.add_proxy(name.to_string(), Some(20000 + i as u16), slot);
        }
        assert_eq!(client.ports_used(), 2);

        let err = register_proxy(&cfg, &registry, &client, &tcp_proxy("c", 20099))
            .await
            .expect_err("已经占满 2 个端口，第 3 个必须被拒")
            .to_string();
        assert!(err.contains("maxPortsPerClient"), "{err}");
        assert!(err.contains("2 个端口"), "错误里要说明已占用几个：{err}");
    }

    /// 上限为 0 = 不限制（默认），不能误伤。
    #[tokio::test]
    async fn max_ports_per_client_为零时不限制() {
        let registry = Arc::new(Registry::unlimited());
        let client = client_with(Limit::unlimited(), &registry);
        let cfg = Arc::new(ServerConfig {
            bind_addr: "300.300.300.300".into(),
            ..Default::default()
        });

        for i in 0..5 {
            let slot = client.reserve_proxy().expect("名额充足");
            client.add_proxy(format!("p{i}"), Some(21000 + i), slot);
        }
        let err = register_proxy(&cfg, &registry, &client, &tcp_proxy("more", 21099))
            .await
            .expect_err("地址解析不了")
            .to_string();
        assert!(!err.contains("maxPortsPerClient"), "0 语义是不限制：{err}");
    }

    /// `remote_port = 0` 时优先报"必须指定 remote_port"，而不是
    /// 那句让人摸不着头脑的"端口 0 不在白名单内"。
    #[tokio::test]
    async fn 没填端口时报的是必须指定而不是白名单() {
        let registry = Arc::new(Registry::unlimited());
        let client = client_with(Limit::unlimited(), &registry);
        let cfg = Arc::new(ServerConfig {
            allow_ports: nfrp_common::config::parse_port_ranges("20000-30000").unwrap(),
            ..Default::default()
        });

        let err = register_proxy(&cfg, &registry, &client, &tcp_proxy("noport", 0))
            .await
            .expect_err("没端口必须被拒")
            .to_string();
        assert!(err.contains("remote_port"), "{err}");
        assert!(!err.contains("allowPorts"), "{err}");
    }

    /// ★ `detailedErrorsToClient = false` 时回给客户端的必须是短句，
    /// 不能把"域名已被代理 xxx 占用"这类**别人的代理名**泄露出去。
    #[test]
    fn 关闭详细错误后回给客户端的是短句() {
        let mut cfg = ServerConfig::default();
        assert!(cfg.detailed_errors_to_client, "官方默认是 true");
        let summary = "new proxy [alice.web] error";
        let detail = "域名 web.example.com 的路径已被代理 bob.web 占用";
        assert_eq!(cfg.error_to_client(summary, detail), detail);

        cfg.detailed_errors_to_client = false;
        assert_eq!(cfg.error_to_client(summary, detail), summary);
        assert_eq!(
            cfg.error_to_client("invalid ping", "签名过期"),
            "invalid ping"
        );
    }

    #[test]
    fn admit_user_without_slot_is_dropped_and_counted() {
        let registry = Arc::new(Registry::unlimited());
        let client = client_with(Limit::new(1), &registry);
        // 先把唯一的客户端连接配额占住
        let held = client.try_acquire_conn().expect("占住");
        let before = registry.metrics().conns_rejected.get();

        admit_user(test_pending("ssh", None), &client, &registry);
        assert_eq!(
            registry.metrics().conns_rejected.get(),
            before + 1,
            "没有配额的连接必须被拒绝并计数"
        );
        assert_eq!(
            registry.metrics().conns_total.get(),
            0,
            "被拒的连接不该计入"
        );
        drop(held);
    }

    #[test]
    fn admit_user_over_backlog_is_dropped() {
        let limits = ServerLimits {
            max_pending_per_client: 1,
            ..Default::default()
        };
        let registry = Arc::new(Registry::new(limits));
        let client = client_with(Limit::unlimited(), &registry);

        admit_user(
            test_pending("a", Some(ConnSlot::default())),
            &client,
            &registry,
        );
        assert_eq!(client.backlog(), 1);
        admit_user(
            test_pending("b", Some(ConnSlot::default())),
            &client,
            &registry,
        );
        assert_eq!(client.backlog(), 1, "队列满了之后不能再入队");
        assert_eq!(registry.metrics().conns_rejected.get(), 1);
    }

    #[test]
    fn admit_user_queues_when_no_idle_work_conn() {
        let registry = Arc::new(Registry::unlimited());
        let client = client_with(Limit::unlimited(), &registry);
        admit_user(
            test_pending("ssh", Some(ConnSlot::default())),
            &client,
            &registry,
        );
        assert_eq!(client.backlog(), 1);
        assert_eq!(registry.metrics().conns_total.get(), 1);
        assert_eq!(registry.metrics().conns_rejected.get(), 0);
    }

    /// 只有 `nfrp` 自研协议会被拒；v1 / v2 都放行 ——
    /// 服务端本来就按魔术字自动识别对端，同一端口同时服务两种客户端。
    #[test]
    fn ensure_protocol_allows_both_frp_wire_versions() {
        use nfrp_common::config::Protocol;
        // 默认就是 frp-v1（跟随官方 frpc 的默认值）
        let mut cfg = ServerConfig::default();
        assert_eq!(cfg.protocol, Protocol::FrpV1);
        assert!(ensure_protocol(&cfg).is_ok());

        cfg.protocol = Protocol::FrpV2;
        assert!(ensure_protocol(&cfg).is_ok(), "v2 也必须被接受");

        cfg.protocol = Protocol::NFrp;
        assert!(ensure_protocol(&cfg).is_err());
    }

    /// 续传复用指纹必须**跨 HashMap 插入顺序**稳定。
    ///
    /// 这是真机上会踩的坑：`metas` / `headers` 是 `HashMap`，直接
    /// `serde_json::to_string` 两次可能得到不同顺序 —— 指纹一变就不复用，
    /// 下一步重新 bind 报 `Address already in use`，而用户配置根本没改。
    #[test]
    fn 续传指纹跨_map_插入顺序稳定() {
        use std::collections::HashMap;
        let mut a = tcp_proxy("web", 28080);
        let mut m1 = HashMap::new();
        m1.insert("b".to_string(), "2".to_string());
        m1.insert("a".to_string(), "1".to_string());
        a.metas = m1;
        let mut h1 = HashMap::new();
        h1.insert("X-B".to_string(), "2".to_string());
        h1.insert("X-A".to_string(), "1".to_string());
        a.headers = h1;

        let mut b = tcp_proxy("web", 28080);
        let mut m2 = HashMap::new();
        m2.insert("a".to_string(), "1".to_string());
        m2.insert("b".to_string(), "2".to_string());
        b.metas = m2;
        let mut h2 = HashMap::new();
        h2.insert("X-A".to_string(), "1".to_string());
        h2.insert("X-B".to_string(), "2".to_string());
        b.headers = h2;

        assert_eq!(proxy_signature(&a), proxy_signature(&b));

        // 改端口 / 改密钥必须变，不能误复用旧监听器。
        let mut c = b.clone();
        c.remote_port = 28081;
        assert_ne!(proxy_signature(&a), proxy_signature(&c));
        let mut d = b.clone();
        d.sk = "other-secret".into();
        assert_ne!(proxy_signature(&a), proxy_signature(&d));
    }

    // ==================================================================
    // v0.5.6 回归（审计总报告 M7）：活跃连接计数必须收支平衡
    //
    // 审计找出**四处**同类问题（重复 inc / 无条件 dec / 两处 `?` 漏 dec），
    // 但它们其实是**同一个 bug 的四个表现**：
    // "配对的 +1 与结束的 -1 分散在两处，中间任何提前返回都会漏掉 -1"。
    // 修法用 RAII 把 -1 绑到作用域上 —— 下面这几条锁住这个不变量。
    // ==================================================================

    /// ★★ M7：守卫创建 +1、离开作用域 -1（**无论怎么离开**）。
    #[test]
    fn 连接守卫必须收支平衡() {
        let r = Registry::unlimited();
        assert_eq!(r.metrics().conns_active.get(), 0, "起点为 0");

        {
            let _g = ConnGuard::new(&r);
            assert_eq!(r.metrics().conns_active.get(), 1, "建守卫后 +1");
        }
        assert_eq!(r.metrics().conns_active.get(), 0, "离开作用域必须 -1");

        // 嵌套多个也一样
        let g1 = ConnGuard::new(&r);
        let g2 = ConnGuard::new(&r);
        assert_eq!(r.metrics().conns_active.get(), 2);
        drop(g1);
        assert_eq!(r.metrics().conns_active.get(), 1, "只减自己那一份");
        drop(g2);
        assert_eq!(r.metrics().conns_active.get(), 0);
    }

    /// ★★ M7 核心：**提前返回（`?` 路径）也必须把计数还回来**。
    ///
    /// 这是原先漏 dec 的那两条路径的等价物：函数在守卫建好之后、
    /// `finish_conn` 之前就 return 了。
    #[test]
    fn 提前返回也要归还计数() {
        let r = Registry::unlimited();

        fn early_return(r: &Registry) -> Result<()> {
            let _g = ConnGuard::new(r);
            // 模拟 `send_msg(...).context(...)?` 失败提前返回
            anyhow::bail!("模拟发送 StartWorkConn 失败");
        }

        assert!(early_return(&r).is_err());
        assert_eq!(
            r.metrics().conns_active.get(),
            0,
            "提前返回绝不能漏掉 -1（M7 的核心）"
        );
    }

    /// 流量统计同样由守卫记账（成功路径）。
    #[test]
    fn 守卫要记账流量() {
        let r = Registry::unlimited();
        {
            let g = ConnGuard::new(&r);
            g.record_bytes(1234, 5678);
        }
        assert_eq!(r.metrics().bytes_up.get(), 1234);
        assert_eq!(r.metrics().bytes_down.get(), 5678);
    }
}
