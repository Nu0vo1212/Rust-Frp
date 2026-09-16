//! stcp / xtcp 的 **visitor**（接入方）实现。
//!
//! 与 provider 相反，visitor 不在公网暴露任何东西：它在**本地**监听一个端口，
//! 每来一个连接就新开一条到服务端的连接，用 `NewVisitorConn` 表明身份，
//! 校验通过后这条连接直接变成指向 provider 内网服务的裸字节通道。
//!
//! ```text
//! 本地程序 -> visitor(bind_addr:bind_port)
//!         -> [新建连接 + magic + NewVisitorConn{sk 签名}]
//!         -> rustunnel-server（校验 + 与 provider 工作连接配对）
//!         -> provider frpc -> provider 的 local_addr
//! ```
//!
//! xtcp 会先尝试真 P2P（见 [`crate::p2p`]）：打洞成功则数据直连，
//! 失败自动回退到与 stcp 相同的中继路径。

use std::sync::Arc;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use rustunnel_common::{config::VisitorConfig, frp::conn, util};
use tokio::{io::AsyncWriteExt, net::TcpListener, net::TcpStream, sync::watch};
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
