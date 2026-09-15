//! UDP 代理（等价官方 `server/proxy/udp.go`）。
//!
//! 与 TCP 代理最大的区别：
//!
//! * 公网侧是 **UDP socket**，没有"连接"概念，靠 `remote_addr` 区分访客；
//! * 客户端侧**每个 UDP 代理只占一条专用工作连接**（不是每个访客一条），
//!   所有访客的报文都复用这一条连接，靠 `UdpPacket.remote_addr` 标识归属；
//! * 这条工作连接上跑的是 frp 消息帧（type 13 `UdpPacket`），
//!   而不是像 TCP 那样转发裸字节。
//!
//! ```text
//! 访客 --UDP--> 服务端 udp socket --UdpPacket--> 专用工作连接 --> 客户端 --> 内网 UDP 服务
//! ```

use std::{net::SocketAddr, sync::Arc, time::Duration};

use anyhow::{Context, Result};
use rustunnel_common::frp::{
    conn::FrpConn,
    msg::{FrpMessage, Ping, StartWorkConn, UdpPacket},
};
use tokio::{net::UdpSocket, sync::mpsc, time::interval};
use tracing::{debug, info, warn};

use crate::ClientState;

/// 单个 UDP 报文缓冲上限（与 frp `MaxUDPPayloadSize` 一致）。
const MAX_UDP_PAYLOAD: usize = 65507;

/// 工作连接上发送 Ping 的间隔：官方 frps 对 UDP 工作连接设了 60s 读超时，
/// 心跳间隔必须小于它。
const KEEPALIVE_INTERVAL: Duration = Duration::from_secs(30);

/// 向客户端索要工作连接的等待上限。
const WORK_CONN_WAIT: Duration = Duration::from_secs(15);

/// 启动一个 UDP 代理：绑定 UDP 端口并持续维护"专用工作连接"。
pub fn spawn(
    udp: Arc<UdpSocket>,
    proxy_name: String,
    client: Arc<ClientState>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        loop {
            let work = match client.acquire_work_conn(WORK_CONN_WAIT).await {
                Some(w) => w,
                None => {
                    if client.is_stopped() {
                        return;
                    }
                    warn!(proxy = %proxy_name, "等待工作连接超时，1s 后重试");
                    tokio::time::sleep(Duration::from_secs(1)).await;
                    continue;
                }
            };
            if let Err(e) = run_session(work.conn, udp.clone(), &proxy_name).await {
                debug!(proxy = %proxy_name, "UDP 工作连接结束：{e:#}");
            }
            if client.is_stopped() {
                info!(proxy = %proxy_name, "UDP 代理已停止");
                return;
            }
            // 工作连接断了就再要一条（与 frp 行为一致）
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
    })
}

/// 一条 UDP 工作连接的生命周期：双向搬运 + 心跳。
async fn run_session(mut conn: FrpConn, udp: Arc<UdpSocket>, proxy_name: &str) -> Result<()> {
    conn.send_msg(&FrpMessage::StartWorkConn(StartWorkConn {
        proxy_name: proxy_name.to_string(),
        ..Default::default()
    }))
    .await
    .context("发送 StartWorkConn 失败")?;

    // 公网 UDP 报文 → 队列 → 工作连接。
    // FrpConn 是单所有者，所以读写都收敛在本任务的 select 里，避免加锁。
    let (to_client_tx, mut to_client_rx) = mpsc::channel::<UdpPacket>(1024);
    let udp_task = {
        let udp = udp.clone();
        tokio::spawn(async move {
            let mut buf = vec![0u8; MAX_UDP_PAYLOAD];
            loop {
                match udp.recv_from(&mut buf).await {
                    Ok((n, src)) => {
                        if to_client_tx.send(UdpPacket::new(&buf[..n], &src)).await.is_err() {
                            return;
                        }
                    }
                    Err(e) => {
                        debug!("UDP 读取失败：{e}");
                        return;
                    }
                }
            }
        })
    };

    let mut keepalive = interval(KEEPALIVE_INTERVAL);
    keepalive.tick().await; // 丢掉立即触发的那次

    let result = loop {
        tokio::select! {
            // 客户端 → 访客
            msg = conn.recv_msg() => {
                let Some(msg) = msg? else { break Ok(()) };
                match msg {
                    FrpMessage::UdpPacket(pkt) => {
                        if let Some(dst) = pkt.remote_addr.as_ref().and_then(|a| a.to_socket()) {
                            if let Err(e) = udp.send_to(pkt.payload(), dst).await {
                                debug!(%dst, "UDP 回写访客失败：{e}");
                            }
                        } else {
                            debug!("UDP 报文缺少访客地址，丢弃");
                        }
                    }
                    FrpMessage::Ping(_) => {
                        // 客户端心跳，无需回包
                    }
                    other => debug!("UDP 工作连接忽略消息：{}", other.name()),
                }
            }
            // 访客 → 客户端
            Some(pkt) = to_client_rx.recv() => {
                if let Err(e) = conn.send_msg(&FrpMessage::UdpPacket(pkt)).await {
                    break Err(e).context("UDP 报文写往工作连接失败");
                }
            }
            _ = keepalive.tick() => {
                let _ = conn.send_msg(&FrpMessage::Ping(Ping::default())).await;
            }
        }
    };

    udp_task.abort();
    result
}

/// 绑定 UDP 端口。
pub async fn bind_udp(bind_addr: &str, port: u16) -> Result<UdpSocket> {
    let addr: SocketAddr =
        rustunnel_common::util::resolve_addr(&format!("{bind_addr}:{port}")).await?;
    UdpSocket::bind(addr)
        .await
        .with_context(|| format!("监听 UDP {addr} 失败"))
}
