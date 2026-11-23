//! 连接接入与首帧探测。
//!
//! 职责：主端口的首字节探测（WebSocket 前缀 / TLS 自动识别）、`handle_stream`
//! 的 yamux 分层，以及 `handle_frp_stream` 的 ACL → 未认证闸门 → 握手 →
//! 按 `ServerAccept` 分发到控制 / 工作 / visitor 三条路径。
//!
//! 锁顺序契约：先读 `Registry` 的安全上下文 / 插件 / nlink（短暂快照），
//! 再取未认证握手名额；名额在握手结束立刻释放，之后才进入控制连接的
//! registry → client state → pool 锁序。本模块不嵌套获取后两者。
//!
//! 不变量：`WS_PREFIX` / `YAMUX_VERSION_BYTE` / `PROBE_TIMEOUT` /
//! `HANDSHAKE_TIMEOUT` 只读；`session_authed` 只由本模块在工作 / 控制握手成功后
//! 置位（`Store`），yamux accept 循环只读（`Load`）。

use std::{
    net::SocketAddr,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::Duration,
};

use anyhow::{Context, Result};
use nfrp_common::{
    config::ServerConfig,
    frp::{
        self,
        conn::{self, ServerAccept},
        stream::{BoxStream, PrefixedStream},
    },
    util, ws,
};
use tokio::net::TcpStream;
use tracing::{debug, info, warn};

use crate::registry::Registry;

use super::control::handle_control;
use super::preauth::{acquire_preauth_slot, preauth_gate, PreauthSlot, PREAUTH_MAX};
use super::work::{handle_visitor, handle_work};

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

// ---------------------------------------------------------------------------
// 连接分发
// ---------------------------------------------------------------------------

pub(super) async fn handle_conn(
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
pub(super) async fn handle_stream(
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
pub(super) async fn handle_frp_stream(
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
