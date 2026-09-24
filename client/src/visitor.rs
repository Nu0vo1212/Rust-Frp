//! stcp / xtcp / sudp 的 **visitor**（接入方）实现。
//!
//! 与 provider 相反，visitor 不在公网暴露任何东西：它在**本地**监听一个端口，
//! 每来一个连接就新开一条到服务端的连接，用 `NewVisitorConn` 表明身份，
//! 校验通过后这条连接直接变成指向 provider 内网服务的通道。
//!
//! ```text
//! 本地程序 -> visitor(bind_addr:bind_port)
//!         -> [新建连接 + magic + NewVisitorConn{sk 签名}]
//!         -> rustunnel-server（校验 + 与 provider 工作连接配对）
//!         -> provider frpc -> provider 的 local_addr
//! ```
//!
//! 数据面随类型而变：
//! * `stcp` / `xtcp`：**TCP** 裸字节中继（xtcp 打洞失败时自动回退这条中继路径）；
//! * `sudp`：**UDP**。本地开一个 UDP socket，建一条持久 `NewVisitorConn` 工作连接，
//!   帧上跑 `UdpPacket` 消息，按访客地址复用本地回写 socket（与官方 SUDP 一致）。
//!
//! xtcp 会先尝试真 P2P（见 [`crate::p2p`]）：打洞成功则数据直连，
//! 失败自动回退到与 stcp 相同的中继路径。

use std::sync::Arc;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use rustunnel_common::{
    config::VisitorConfig,
    frp::{
        conn,
        conn::FrpConn,
        msg::{FrpMessage, Ping, UdpPacket},
    },
    util,
};
use tokio::{
    io::AsyncWriteExt,
    net::{TcpListener, TcpStream, UdpSocket},
    sync::watch,
};
use tracing::{debug, info, warn};

use crate::{p2p, ClientSession};

/// 等控制会话就绪（客户端重连期间会短暂等待）。
async fn wait_session(
    session_rx: &mut watch::Receiver<Option<Arc<ClientSession>>>,
) -> Result<Arc<ClientSession>> {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(15);
    loop {
        if let Some(s) = (*session_rx.borrow()).clone() {
            return Ok(s);
        }
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            bail!("等待控制会话就绪超时（客户端还在重连？）");
        }
        if tokio::time::timeout(remaining, session_rx.changed())
            .await
            .is_err()
        {
            bail!("等待控制会话就绪超时（客户端还在重连？）");
        }
    }
}

/// 启动一个 visitor：在配置的地址上监听，直到监听失败或进程退出。
///
/// 本地监听是**进程级**的（跨重连只绑一次）；具体用哪条控制会话，
/// 每个本地连接到来时从 `session_rx` 里取当前有效的那一份。
pub async fn run(
    session_rx: watch::Receiver<Option<Arc<ClientSession>>>,
    cfg: VisitorConfig,
    user: Arc<String>,
) -> Result<()> {
    if cfg.server_name.is_empty() {
        bail!("visitor [{}] 未配置 server_name（目标代理名）", cfg.name);
    }
    if cfg.secret_key.is_empty() {
        bail!("visitor [{}] 未配置 secret_key", cfg.name);
    }
    if cfg.bind_port == 0 {
        // 与 frp 一致：bindPort = 0 表示不监听本地端口（只用于给别的 visitor 做 fallback）
        info!(visitor = %cfg.name, "bind_port 为 0，visitor 不监听本地端口");
        return Ok(());
    }

    // 与官方 frpc 一致：目标代理名带 user 前缀；
    // 优先用 visitor 自己的 `serverUser`，没配才退回本客户端的顶层 `user`。
    let prefix_user = if cfg.server_user.is_empty() {
        user.as_str()
    } else {
        cfg.server_user.as_str()
    };
    let target = util::add_user_prefix(prefix_user, &cfg.server_name);
    let listen = format!("{}:{}", cfg.bind_addr, cfg.bind_port);
    let addr = util::resolve_addr(&listen)
        .await
        .with_context(|| format!("解析 visitor 监听地址 {listen} 失败"))?;

    // SUDP：数据面是 UDP。本地开 UDP socket，每个访客地址复用一条持久工作连接。
    if cfg.visitor_type == "sudp" {
        let mut rx = session_rx;
        return run_sudp(&mut rx, cfg, target, addr).await;
    }

    let listener = TcpListener::bind(addr)
        .await
        .with_context(|| format!("visitor [{}] 监听 {addr} 失败（端口可能被占用）", cfg.name))?;

    info!(
        visitor = %cfg.name,
        %addr,
        server_name = %target,
        kind = %cfg.visitor_type,
        "visitor 已开始监听"
    );

    loop {
        let (user_conn, peer) = match listener.accept().await {
            Ok(v) => v,
            Err(e) => {
                warn!(visitor = %cfg.name, "visitor 监听中断：{e}");
                break;
            }
        };
        user_conn.set_nodelay(true).ok();
        let mut rx = session_rx.clone();
        let cfg = cfg.clone();
        let target = target.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_user(&mut rx, cfg, target, user_conn, peer).await {
                debug!(%peer, "visitor 连接结束：{e:#}");
            }
        });
    }
    Ok(())
}

/// SUDP 访问方：本地 UDP 监听 + **一条**持久 visitor 工作连接。
///
/// 与官方 SUDP 行为一致：
/// * 本地开**一个** UDP socket（`bind_addr:bind_port`），收发都用它；
/// * 建**一条** `NewVisitorConn` 工作连接，帧上跑 `UdpPacket` 消息（type 13）；
/// * 服务端的响应按帧里的 `remote_addr` 写回对应访客 —— 注意**必须用监听的那个
///   socket 回**：访客只认自己发往的那个端口，另起一个随机端口的 socket 发出去，
///   对端要么收不到、要么当成陌生来源丢掉（"能发出去"不等于"对端认"）；
/// * 空闲 30 秒没数据就往工作连接发 `Ping` 保活（官方 frps 对 UDP 工作连接设 60s 读超时）；
/// * 工作连接断开后回到外层重新等一个有效会话再重建通道 —— 控制连接重连不该
///   让 visitor 直接死掉。
///
/// 一条持久工作连接 + 一个本地 socket —— 不是"每个报文新建一条连接"。
async fn run_sudp(
    session_rx: &mut watch::Receiver<Option<Arc<ClientSession>>>,
    cfg: VisitorConfig,
    target: String,
    addr: std::net::SocketAddr,
) -> Result<()> {
    let sock = UdpSocket::bind(addr).await.with_context(|| {
        format!(
            "SUDP visitor [{}] 绑定本地 UDP {addr} 失败（端口可能被占用）",
            cfg.name
        )
    })?;
    info!(
        visitor = %cfg.name,
        %addr,
        server_name = %target,
        kind = "sudp",
        "SUDP visitor 已开始监听"
    );

    let mut buf = vec![0u8; 65507];
    loop {
        // 每次（重）建通道都取当前有效会话：控制连接重连后这里会拿到新的那份
        let session = wait_session(session_rx).await?;
        let mut udp_conn = match open_sudp_work_conn(&session, &cfg, &target).await {
            Ok(c) => c,
            Err(e) => {
                warn!(visitor = %cfg.name, "SUDP 通道建立失败，2 秒后重试：{e:#}");
                tokio::time::sleep(Duration::from_secs(2)).await;
                continue;
            }
        };
        debug!(visitor = %cfg.name, server_name = %target, "SUDP 通道已建立");

        let mut keepalive = tokio::time::interval(Duration::from_secs(30));
        keepalive.tick().await; // 丢掉立即触发的那次

        // 内层：正常转发，任一侧断开就退出去重连
        loop {
            tokio::select! {
                // 本地 UDP -> 工作连接
                res = sock.recv_from(&mut buf) => {
                    match res {
                        Ok((n, remote)) => {
                            // 直接在工作连接上发 UdpPacket 帧（remote_addr 标识访客）
                            if let Err(e) = udp_conn.send_msg(&FrpMessage::UdpPacket(UdpPacket::new(&buf[..n], &remote))).await {
                                warn!(visitor = %cfg.name, "SUDP 报文写往工作连接失败：{e}");
                                break;
                            }
                        }
                        Err(e) => {
                            warn!(visitor = %cfg.name, "SUDP 本地读取失败：{e}");
                            break;
                        }
                    }
                }
                // 工作连接 -> 本地 socket（响应写回访客）
                msg = udp_conn.recv_msg() => {
                    match msg {
                        Ok(Some(FrpMessage::UdpPacket(pkt))) => {
                            let Some(dst) = pkt.remote_addr.as_ref().and_then(|a| a.to_socket()) else {
                                debug!(visitor = %cfg.name, "SUDP 回包缺少访客地址，丢弃");
                                continue;
                            };
                            if let Err(e) = sock.send_to(pkt.payload(), dst).await {
                                debug!(%dst, "SUDP 回写访客失败：{e}");
                            }
                        }
                        Ok(Some(_)) => {} // Ping 之类控制帧，本端自己消化
                        _ => break,
                    }
                }
                _ = keepalive.tick() => {
                    let _ = udp_conn.send_msg(&FrpMessage::Ping(Ping::default())).await;
                }
            }
        }
        warn!(visitor = %cfg.name, "SUDP 通道断开，准备重建");
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
}

/// 建 SUDP visitor 的工作连接（`NewVisitorConn` + 签名，握手后返回带帧的 `FrpConn`）。
async fn open_sudp_work_conn(
    session: &ClientSession,
    cfg: &VisitorConfig,
    target: &str,
) -> Result<FrpConn> {
    let (tunnel, leftover) = conn::client_visitor_conn(
        session.link.connect().await?,
        session.link.wire,
        &session.run_id,
        target,
        &cfg.secret_key,
    )
    .await
    .with_context(|| {
        format!(
            "SUDP visitor [{}] 接入 {target} 失败（密钥不对、user 不在 allow_users、或 provider 未注册？）",
            cfg.name
        )
    })?;
    let mut udp_conn = FrpConn::new(tunnel, session.link.wire);
    // 握手时可能把对端已经发来的第一帧一并读进了缓冲区，必须塞回去。
    // SUDP 是**一条长连接跑所有报文**，丢掉它就是丢一个真实的业务报文
    // （stcp 那种裸字节转发可以直接 write_all 给对端，这里不行）。
    if !leftover.is_empty() {
        udp_conn.push_leftover(leftover, false);
    }
    // UDP 编码要跟控制会话协商值走
    udp_conn.set_udp_codec(
        session
            .link
            .udp_binary
            .load(std::sync::atomic::Ordering::Relaxed),
    );
    Ok(udp_conn)
}

/// 一个本地连接：等控制会话就绪 -> 建 visitor 通道 -> 与本地连接双向转发。
async fn handle_user(
    session_rx: &mut watch::Receiver<Option<Arc<ClientSession>>>,
    cfg: VisitorConfig,
    target: String,
    mut user: TcpStream,
    peer: std::net::SocketAddr,
) -> Result<()> {
    debug!(visitor = %cfg.name, %peer, "收到本地连接，等待控制会话就绪");

    let session = wait_session(session_rx).await?;

    // xtcp 先试真 P2P：打通了数据就不经过服务端，带宽不再受它限制。
    // 打洞失败（对称 NAT、UDP 被封等）时静默回退中继 —— xtcp 因此不会比 stcp 更差。
    if cfg.visitor_type == "xtcp" {
        if let Some(route) = &session.p2p {
            debug!(visitor = %cfg.name, %peer, "xtcp 尝试 P2P 直连");
            match p2p::try_punch_as_visitor(route, &session.run_id, &target, &cfg.secret_key).await
            {
                Ok(mut stream) => {
                    match util::relay_between(&mut user, &mut stream).await {
                        Ok((up, down)) => {
                            debug!(visitor = %cfg.name, "P2P 转发结束：上行 {up}B / 下行 {down}B")
                        }
                        Err(e) => debug!(visitor = %cfg.name, "P2P 转发中断：{e}"),
                    }
                    return Ok(());
                }
                Err(e) => {
                    debug!(visitor = %cfg.name, "P2P 打洞失败，回退中继：{e:#}");
                }
            }
        }
    }

    debug!(visitor = %cfg.name, %peer, "建立 visitor 通道 target={target}");

    let (mut tunnel, leftover) = conn::client_visitor_conn(
        session.link.connect().await?,
        session.link.wire,
        &session.run_id,
        &target,
        &cfg.secret_key,
    )
    .await
    .with_context(|| {
        format!(
            "visitor [{}] 接入 {target} 失败（密钥不对、user 不在 allow_users、或 provider 未注册？）",
            cfg.name
        )
    })?;

    // 校验通过后本端可能已经开始发数据，残留字节要原样写进去
    if !leftover.is_empty() {
        user.write_all(&leftover).await?;
    }

    match util::relay_between(&mut user, &mut tunnel).await {
        Ok((up, down)) => {
            debug!(visitor = %cfg.name, "visitor 转发结束：上行 {up}B / 下行 {down}B")
        }
        Err(e) => debug!(visitor = %cfg.name, "visitor 转发中断：{e}"),
    }
    Ok(())
}
