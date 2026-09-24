//! 服务端网络入口：监听、分发、控制连接处理、代理注册与转发配对。
//!
//! 与原版 frps 一致，控制连接与工作连接**复用同一个端口**，靠首帧消息类型区分：
//! `Login` 走控制连接流程，`NewWorkConn` 走工作连接流程，
//! `NewVisitorConn` 走 visitor 接入流程（stcp / xtcp）。

use std::{
    net::SocketAddr,
    path::PathBuf,
    sync::{Arc, RwLock},
    time::{Duration, Instant},
};

use anyhow::{anyhow, Context, Result};
use rustunnel_common::{
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
    vhost::{self, VhostRoute, VhostTable},
    visitor, vnet,
};

use visitor::VisitorEntry;

/// yamux 帧头的第一个字节是协议版本号（固定 0）。
///
/// frp v2 的魔术字以 `F`(0x46) 开头，两者不会混淆，服务端因此可以自动探测。
const YAMUX_VERSION_BYTE: u8 = 0x00;

/// 探测首字节的超时时间。
const PROBE_TIMEOUT: Duration = Duration::from_secs(10);

/// WebSocket 升级请求的前缀：`"GET " + FrpWebsocketPath`。
///
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
    pub log_handle: Option<rustunnel_common::util::LogFilterHandle>,
}

/// 启动服务端主循环（含 HTTP/HTTPS vhost 端口），直到收到退出信号。
pub async fn serve(cfg: Arc<ServerConfig>, registry: Arc<Registry>) -> Result<()> {
    serve_with(cfg, registry, ServeExtras::default()).await
}

/// [`serve`] 的完整版本：二进制入口用它把配置文件路径与日志句柄传进来。
pub async fn serve_with(
    cfg: Arc<ServerConfig>,
    registry: Arc<Registry>,
    extras: ServeExtras,
) -> Result<()> {
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

    // 安全上下文：认证方式 / IP 白黑名单 / 角色权限 / 审计日志。
    //
    // ★ 编译失败必须**拦住启动**：配置里写错一个 CIDR 就静默退化成
    //   "没有访问控制"，那比起不来危险得多。
    let security = Arc::new(crate::guard::SecurityContext::from_config(&cfg)?);
    registry.set_security(security.clone());
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

    info!("rustunnel-server 已启动：frp v2 协议，监听 {addr}");
    info!("支持的代理类型：tcp / udp / http / https / stcp / sudp / xtcp");
    let eff = cfg.effective_auth();
    info!(
        "认证方式 = {}，token = {}（{}）",
        eff.method.as_str(),
        if eff.token.is_empty() {
            "<空>"
        } else {
            "已设置"
        },
        if eff.method == rustunnel_common::security::AuthMethod::Token && eff.token.is_empty() {
            "不安全：任何人都能连"
        } else {
            "已启用"
        }
    );
    log_limits(&registry);

    // HTTP / HTTPS 虚拟主机端口（可选）
    if cfg.vhost_http_port.is_some() || cfg.vhost_https_port.is_some() {
        let table = Arc::new(VhostTable::default());
        registry.attach_vhosts(table.clone());
        for (port, is_https) in [(cfg.vhost_http_port, false), (cfg.vhost_https_port, true)] {
            let Some(vport) = port else { continue };
            let addr = util::resolve_addr(&format!("{}:{}", cfg.bind_addr, vport))
                .await
                .with_context(|| format!("解析 vhost 地址 {}:{} 失败", cfg.bind_addr, vport))?;
            let listener = vhost::bind(addr).await?;
            tokio::spawn(vhost::run_http(
                listener,
                table.clone(),
                vport,
                is_https,
                registry.clone(),
            ));
        }
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
        tokio::spawn(crate::p2p::run_rendezvous(sock, hub));
    }

    // 内置面板 + /metrics：与 frp 的 dashboard 一样是可选端口
    let dashboard_auth: dashboard::DashboardAuth =
        Arc::new(RwLock::new(if cfg.dashboard_user.is_empty() {
            None
        } else {
            Some((cfg.dashboard_user.clone(), cfg.dashboard_pwd.clone()))
        }));
    if let Some(dport) = cfg.dashboard_port {
        let addr = util::resolve_addr(&format!("{}:{}", cfg.bind_addr, dport))
            .await
            .with_context(|| format!("解析面板地址 {}:{} 失败", cfg.bind_addr, dport))?;
        let listener = TcpListener::bind(addr)
            .await
            .with_context(|| format!("监听 {addr} 失败（面板端口可能被占用）"))?;
        tokio::spawn(dashboard::run(
            listener,
            registry.clone(),
            dashboard_auth.clone(),
            cfg.clone(),
        ));
    }

    // 配置热重载：改完日志级别/面板密码不用重启
    if cfg.hot_reload {
        if let Some(path) = extras.config_path.clone() {
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

    // QUIC 传输：在同一个端口号上额外监听 UDP。
    //
    // 保留 TCP 监听是有意的 —— 这样老客户端照旧能连，切换传输协议不会一刀切。
    if is_quic(&cfg.transport_protocol) {
        let qport = addr.port();
        let qaddr = util::resolve_addr(&format!("{}:{}", cfg.bind_addr, qport))
            .await
            .with_context(|| format!("解析 QUIC 地址 {}:{} 失败", cfg.bind_addr, qport))?;
        let endpoint = frp::quic::listen(&qaddr)
            .await
            .with_context(|| format!("监听 QUIC {qaddr} 失败"))?;
        info!(
            "QUIC 传输已启用，UDP {}",
            endpoint
                .local_addr()
                .ok()
                .map(|a| a.to_string())
                .unwrap_or_default()
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
        let listener = frp::kcp::KcpListener::bind(kaddr)
            .await
            .with_context(|| format!("监听 KCP {kaddr} 失败（端口可能被占用）"))?;
        info!("KCP 传输已启用，UDP {kaddr}（TCP {addr} 照旧可用）");
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

fn log_limits(registry: &Registry) {
    let l = registry.limits();
    if !l.max_total_conns.gt(&0)
        && !l.max_clients.gt(&0)
        && !l.max_conns_per_client.gt(&0)
        && !l.max_proxies_per_client.gt(&0)
    {
        warn!("未配置任何资源上限：单个客户端即可耗尽服务端连接/代理配额");
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
        return handle_frp_stream(stream, peer, cfg, registry).await;
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
            let mut acceptor =
                frp::mux::serve(Box::pin(PrefixedStream::new(vec![first[0]], stream)));
            while let Some(s) = acceptor.accept().await {
                let cfg = cfg.clone();
                let registry = registry.clone();
                tokio::spawn(async move {
                    if let Err(e) = handle_frp_stream(s, peer, cfg, registry).await {
                        debug!(%peer, "yamux stream 结束：{e:#}");
                    }
                });
            }
            return Ok(());
        }
        let stream: BoxStream = Box::pin(PrefixedStream::new(vec![first[0]], stream));
        return handle_frp_stream(stream, peer, cfg, registry).await;
    }

    handle_frp_stream(stream, peer, cfg, registry).await
}

/// 在一条流上完成 frp v2 握手并分发到控制连接 / 工作连接。
async fn handle_frp_stream(
    stream: BoxStream,
    peer: SocketAddr,
    cfg: Arc<ServerConfig>,
    registry: Arc<Registry>,
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

    // (2) 认证 + (3) 授权。
    //
    // 授权必须发生在**回 LoginResp 之前**：先回"登录成功"再断开的话，客户端
    // 会把它当成普通掉线而无限重连（`loginFailExit` 永远不触发，宿主看到的是
    // "进程活着"= 绿灯，但实际不可用）。所以把 role_for 作为闭包传进握手函数。
    let authorize = |user: &str| -> std::result::Result<rustunnel_common::security::Role, String> {
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
    match conn::server_handshake_authz(stream, &sec.auth, &run_id, authorize).await {
        Ok(ServerAccept::Control {
            conn,
            login,
            role,
            udp_binary,
            caps,
        }) => {
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
        Ok(ServerAccept::Work { conn, msg }) => handle_work(conn, msg, &sec, registry).await,
        Ok(ServerAccept::Visitor { conn, msg }) => handle_visitor(conn, msg, registry).await,
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
            Err(e)
        }
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
    caps: rustunnel_common::frp::msg::RustunnelCaps,
    wire_version: rustunnel_common::frp::WireVersion,
    peer: SocketAddr,
    role: rustunnel_common::security::Role,
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
        %client_id, %run_id, os = %login.os, arch = %login.arch,
        wire = %wire_version, "客户端登录成功"
    );

    let (req_tx, mut req_rx) = tokio::sync::mpsc::unbounded_channel::<CtrlCmd>();
    let idle_timeout = Duration::from_secs(cfg.work_conn_idle_timeout.max(5));
    let limits = registry.limits().clone();
    let (conn_limit, backlog_limit, proxy_limit) = limits.per_client();
    let client = Arc::new(ClientState::new(
        run_id.clone(),
        client_id.clone(),
        login.user.clone(),
        req_tx,
        idle_timeout,
        caps,
        udp_binary,
        wire_version,
        conn_limit,
        backlog_limit,
        proxy_limit,
    ));

    // 客户端数上限：超出时明确拒绝并带上 reason，方便排查
    let _client_slot = match registry.insert(client.clone()) {
        Some(slot) => slot,
        None => {
            registry.metrics().clients_rejected.inc();
            warn!(
                %client_id,
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
    let _guard = ClientGuard::new(registry.clone(), run_id.clone());

    let mut hb_ticker = tokio::time::interval(Duration::from_secs(5));
    let mut last_seen = Instant::now();
    // 已下发、还在等回执的管理命令：key 是命令 id
    let mut pending_cmds: std::collections::HashMap<
        String,
        tokio::sync::oneshot::Sender<Result<(), String>>,
    > = std::collections::HashMap::new();

    loop {
        tokio::select! {
            msg = conn.recv_msg() => {
                let Some(msg) = msg? else { break };
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
                        //   收原始名（老版 rustunnel 客户端、手写报文）也会被补成
                        //   全名，收带前缀的名字也不会叠成 `2569.2569.xxx`。
                        //
                        //   之所以要兜这一层：早期判断反了 —— 以为客户端该发原始名，
                        //   结果第三方 frps（LoliaFRP）按全名查隧道，查不到就回
                        //   「FRPC 配置文件错误,请检查后重试」。
                        m.proxy_name = util::add_user_prefix(
                            &client.user,
                            util::strip_user_prefix(&client.user, &m.proxy_name),
                        );
                        let name = m.proxy_name.clone();
                        let port = m.remote_port;
                        // (3) 授权：这个角色允许注册这种类型的代理 / 占这个端口吗？
                        //
                        // 放在 register_proxy **之前**：注册会真的去占端口、
                        // 建 vhost 路由，先拦下来才不会有"拒绝了一半"的状态。
                        if let Err(e) = sec.check_proxy(&role, &name, &m.proxy_type, port) {
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
                                proxy_name: name,
                                error: e.to_string(),
                                ..Default::default()
                            }))
                            .await?;
                            continue;
                        }
                        let resp = match register_proxy(&cfg, &registry, &client, &m).await {
                            Ok(remote_addr) => {
                                registry.metrics().proxies_total.inc();
                                registry.metrics().proxies_active.inc();
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
                                NewProxyResp { proxy_name: name, error: e.to_string(), ..Default::default() }
                            }
                        };
                        conn.send_msg(&FrpMessage::NewProxyResp(resp)).await?;
                    }
                    FrpMessage::Ping(p) => {
                        // OIDC + additionalScopes 含 HeartBeats 时，每个心跳上的
                        // token 都要重新验签、且 subject 与登录时一致。
                        // 少了这一步，"登录时验过一次"就等于之后永久信任。
                        if sec.auth_cfg.check_heartbeats()
                            && sec.auth.method()
                                == rustunnel_common::security::AuthMethod::Oidc
                        {
                            if let Err(e) = sec.auth.verify_followup(&p.privilege_key, "心跳") {
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
                                break;
                            }
                        }
                        conn.send_msg(&FrpMessage::Pong(Pong::default())).await?;
                    }
                    FrpMessage::CloseProxy(m) => {
                        info!(proxy = %m.proxy_name, "客户端关闭代理");
                        registry.metrics().proxies_active.dec();
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
                        registry.visitors.remove(&m.proxy_name);
                        // 客户端主动关代理时，它占的 http/https 域名也得摘掉，
                        // 否则域名会一直被占着、重连注册同一个域名会被判冲突
                        if let Some(t) = registry.vhosts() {
                            t.remove_proxy(&m.proxy_name);
                        }
                        // tcp / udp 的公网端口同理：客户端这边只是记账，
                        // 端口是注册表管的，必须显式还回去
                        if let Some(port) = client.stop_proxy(&m.proxy_name) {
                            registry.release_port(port, &client);
                        }
                    }
                    FrpMessage::NatHoleVisitor(m) => {
                        crate::p2p::handle_nat_hole_visitor(&registry, &client, &m).await?;
                    }
                    FrpMessage::NatHoleClient(m) => {
                        debug!(proxy = %m.proxy_name, "收到 NatHoleClient（客户端侧不应下发），忽略");
                    }
                    FrpMessage::NatHoleReport(m) => {
                        debug!(sid = %m.sid, success = m.success, "收到 NatHoleReport");
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
                    CtrlCmd::RequestWork => conn.send_msg(&FrpMessage::ReqWorkConn).await?,
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
                // 被面板踢出：`stop()` 之后必须主动断开，
                // 否则这条控制连接会一直活到心跳超时，
                // 期间还能继续建立工作连接 —— "踢了但没完全踢"。
                if client.is_stopped() {
                    warn!(%client_id, "客户端已被面板踢出，断开控制连接");
                    break;
                }
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
pub(crate) async fn register_proxy(
    cfg: &Arc<ServerConfig>,
    registry: &Arc<Registry>,
    client: &Arc<ClientState>,
    m: &rustunnel_common::frp::msg::NewProxy,
) -> Result<String> {
    if m.proxy_name.is_empty() {
        anyhow::bail!("代理名为空");
    }
    // 代理数必须在分配端口/域名之前拦住，否则失败路径还要回头回收资源。
    // 名额由 add_proxy 接管，随代理一起存活。
    let slot = client.reserve_proxy().ok_or_else(|| {
        anyhow!(
            "代理数量已达上限 {}，注册被拒绝",
            registry.limits().max_proxies_per_client
        )
    })?;
    match m.proxy_type.as_str() {
        "tcp" => register_tcp(cfg, registry, client, m, slot).await,
        "udp" => register_udp(cfg, registry, client, m, slot).await,
        "http" => register_vhost(cfg, registry, client, m, false, slot).await,
        "https" => register_vhost(cfg, registry, client, m, true, slot).await,
        "stcp" => register_visitor_proxy(registry, client, m, "stcp", slot).await,
        "xtcp" => register_visitor_proxy(registry, client, m, "xtcp", slot).await,
        // SUDP：秘密 UDP。与 stcp 同一套鉴权（secret_key + allow_users），
        // 只是数据面是 UDP。不需要公网端口，visitor 主动连进来时配对。
        "sudp" => register_visitor_proxy(registry, client, m, "sudp", slot).await,
        other => anyhow::bail!(
            "暂不支持的代理类型：{other}（支持 tcp / udp / http / https / stcp / xtcp / sudp）"
        ),
    }
}

/// stcp / xtcp：**不需要公网端口**，只在 visitor 表里登记一条记录。
///
/// 之后 visitor 主动连进来时才会校验密钥并配对工作连接。
///
/// 说明：`xtcp` 在 P2P 打洞失败时会回退成本模块的中继路径（与 stcp 一致）。
async fn register_visitor_proxy(
    registry: &Arc<Registry>,
    client: &Arc<ClientState>,
    m: &rustunnel_common::frp::msg::NewProxy,
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
    // 与官方 frps 一致：visitor 类代理没有公网地址，remote_addr 留空
    Ok(String::new())
}

/// TCP：绑定公网端口，用户连进来时向客户端要工作连接配对。
async fn register_tcp(
    cfg: &Arc<ServerConfig>,
    registry: &Arc<Registry>,
    client: &Arc<ClientState>,
    m: &rustunnel_common::frp::msg::NewProxy,
    slot: Permit,
) -> Result<String> {
    if m.remote_port == 0 {
        anyhow::bail!("tcp 代理必须指定 remote_port");
    }
    // group 共享端口时**只有第一个成员**能 bind，后来者直接复用已有监听器：
    // 再 bind 一次必然是 `Address already in use`，组里就永远只剩一个后端。
    let claim = registry
        .reserve_port(m.remote_port, &m.group, &m.proxy_name, client.clone())
        .map_err(|e| anyhow!("{e}"))?;

    if claim == PortClaim::Fresh {
        let addr = util::resolve_addr(&format!("{}:{}", cfg.bind_addr, m.remote_port))
            .await
            .with_context(|| format!("解析 {}:{} 失败", cfg.bind_addr, m.remote_port))?;
        let listener = match TcpListener::bind(addr).await {
            Ok(l) => l,
            Err(e) => {
                registry.release_port(m.remote_port, client);
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
    Ok(format!("{}:{}", cfg.bind_addr, m.remote_port))
}

/// UDP：绑定 UDP 端口 + 维持一条专用工作连接。
async fn register_udp(
    cfg: &Arc<ServerConfig>,
    registry: &Arc<Registry>,
    client: &Arc<ClientState>,
    m: &rustunnel_common::frp::msg::NewProxy,
    slot: Permit,
) -> Result<String> {
    if m.remote_port == 0 {
        anyhow::bail!("udp 代理必须指定 remote_port");
    }
    // 同 tcp：只有第一个成员负责绑定，后来者复用。
    //
    // 但 UDP 的 group 负载均衡这里**明确不做**：UDP 是无连接的，一条工作连接
    // 要负责一整套来源地址的报文，按连接轮询会把同一个会话的报文拆到不同后端去，
    // 结果比不均衡还糟。与其让它"看着配了却没生效"，不如直接说清楚。
    let claim = registry
        .reserve_port(m.remote_port, &m.group, &m.proxy_name, client.clone())
        .map_err(|e| anyhow!("{e}"))?;
    if claim == PortClaim::Joined {
        registry.release_port(m.remote_port, client);
        anyhow::bail!(
            "端口 {} 已被同组 [{}] 的其他代理占用；UDP 暂不支持 group 负载均衡，请改用 tcp",
            m.remote_port,
            m.group
        );
    }

    let udp = match udp_proxy::bind_udp(&cfg.bind_addr, m.remote_port).await {
        Ok(u) => u,
        Err(e) => {
            registry.release_port(m.remote_port, client);
            return Err(e);
        }
    };
    let handle = udp_proxy::spawn(Arc::new(udp), m.proxy_name.clone(), client.clone());
    registry.attach_listener(m.remote_port, handle.abort_handle());
    client.add_proxy(m.proxy_name.clone(), Some(m.remote_port), slot);
    Ok(format!("{}:{}/udp", cfg.bind_addr, m.remote_port))
}

/// HTTP / HTTPS：把域名注册进虚拟主机路由表（不需要额外端口）。
async fn register_vhost(
    cfg: &Arc<ServerConfig>,
    registry: &Arc<Registry>,
    client: &Arc<ClientState>,
    m: &rustunnel_common::frp::msg::NewProxy,
    is_https: bool,
    slot: Permit,
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
    registry.metrics().conns_active.inc();
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
    msg: NewWorkConn,
    sec: &crate::guard::SecurityContext,
    registry: Arc<Registry>,
) -> Result<()> {
    let client = registry
        .get(&msg.run_id)
        .ok_or_else(|| anyhow!("找不到 run_id={} 对应的客户端", msg.run_id))?;

    // OIDC + additionalScopes 含 NewWorkConns：工作连接上必须带一个
    // **与登录同 subject** 的有效 token。
    //
    // 这条挡的是：拿到 run_id 的人自己新建一条工作连接，绕过
    // "工作连接必须来自同一个客户端"这个隐含前提。
    if sec.auth_cfg.check_new_work_conns()
        && sec.auth.method() == rustunnel_common::security::AuthMethod::Oidc
    {
        if let Err(e) = sec.auth.verify_followup(&msg.privilege_key, "新工作连接") {
            registry.audit().record(
                crate::audit::AuditEvent::new(crate::audit::kind::LOGIN_DENIED, false)
                    .client(msg.run_id.clone())
                    .detail(format!("工作连接凭证复核失败：{e:#}")),
            );
            anyhow::bail!("工作连接凭证复核失败：{e:#}");
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
    let work = WorkItem {
        conn,
        at: Instant::now(),
    };
    match client.submit_work(work) {
        Some(p) => {
            debug!(proxy = %p.user.proxy, "工作连接与排队用户配对");
            registry.metrics().conns_active.inc();
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
) -> Result<()> {
    let proxy_name = msg.proxy_name.clone();

    /// 回一条错误响应并结束（官方 frpc 会把 error 原样打到日志上）。
    async fn reject(
        conn: &mut FrpConn,
        proxy_name: &str,
        err: String,
        registry: &Registry,
    ) -> Result<()> {
        registry.metrics().visitor_rejected.inc();
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
            &registry,
        )
        .await;
    }

    // 2) 代理必须已注册
    let Some(entry) = registry.visitors.get(&proxy_name) else {
        return reject(
            &mut conn,
            &proxy_name,
            format!("custom listener for [{proxy_name}] doesn't exist"),
            &registry,
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
            &registry,
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
            &registry,
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
    registry.metrics().conns_active.inc();

    // 7) 向 provider 要一条工作连接并配对
    let Some(work) = entry
        .client
        .acquire_work_conn(Duration::from_secs(10))
        .await
    else {
        registry.metrics().conns_active.dec();
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
/// 一条转发连接结束时的收尾：归还活跃连接计数与流量统计。
fn finish_conn(registry: &Registry, up: u64, down: u64) {
    registry.metrics().conns_active.dec();
    registry.metrics().bytes_up.inc_by(up);
    registry.metrics().bytes_down.inc_by(down);
}

pub fn spawn_bridge(user: PendingUser, work: WorkItem, registry: Arc<Registry>) {
    tokio::spawn(async move {
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
        Ok((up, down)) => {
            debug!(proxy = %proxy, "转发结束：上行 {up}B / 下行 {down}B");
            finish_conn(registry, up, down);
        }
        Err(e) => {
            debug!(proxy = %proxy, "转发中断：{e}");
            finish_conn(registry, 0, 0);
        }
    }
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
    finish_conn(registry, up, down);
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
/// 只有 `rustunnel` 自研协议还没实现，必须显式拒绝（否则用户会以为配了就生效）。
pub fn ensure_protocol(cfg: &ServerConfig) -> Result<()> {
    if cfg.protocol.wire_version().is_none() {
        anyhow::bail!(
            "当前版本服务端尚未实现 rustunnel 自研协议，\
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
            Default::default(),
            false,
            rustunnel_common::frp::WireVersion::V1,
            conn_limit,
            backlog,
            proxy,
        ))
    }

    #[test]
    fn limits_from_config_defaults_to_unlimited() {
        let cfg = ServerConfig::default();
        let l = limits_from(&cfg);
        assert_eq!(l.max_total_conns, 0, "默认必须保持向后兼容：不限制");
        assert_eq!(l.max_clients, 0);
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

    /// 只有 `rustunnel` 自研协议会被拒；v1 / v2 都放行 ——
    /// 服务端本来就按魔术字自动识别对端，同一端口同时服务两种客户端。
    #[test]
    fn ensure_protocol_allows_both_frp_wire_versions() {
        use rustunnel_common::config::Protocol;
        // 默认就是 frp-v1（跟随官方 frpc 的默认值）
        let mut cfg = ServerConfig::default();
        assert_eq!(cfg.protocol, Protocol::FrpV1);
        assert!(ensure_protocol(&cfg).is_ok());

        cfg.protocol = Protocol::FrpV2;
        assert!(ensure_protocol(&cfg).is_ok(), "v2 也必须被接受");

        cfg.protocol = Protocol::Rustunnel;
        assert!(ensure_protocol(&cfg).is_err());
    }
}
