//! 客户端 UDP 转发（等价官方 `client/proxy/udp.go` + `pkg/proto/udp.Forwarder`）。
//!
//! 一条专用工作连接 + 每个访客一个本地 UDP socket：
//!
//! ```text
//! 工作连接 --UdpPacket--> 按 remote_addr 找到本地 socket --> 内网 UDP 服务
//! 内网 UDP 服务 --> 同一个 socket --UdpPacket--> 工作连接（带回 remote_addr）
//! ```
//!
//! 访客身份由 `remote_addr` 决定，所以服务端能把响应写回正确的访客。
//! 会话 30 秒没有数据来往就回收（与 frp 的读超时一致）。

use std::{
    collections::HashMap,
    net::SocketAddr,
    sync::{Arc, Mutex},
    time::Duration,
};

use anyhow::{Context, Result};
use rustunnel_common::{
    frp::{
        conn::FrpConn,
        msg::{FrpMessage, Ping, UdpAddr, UdpPacket},
    },
    util,
};
use tokio::{net::UdpSocket, sync::mpsc, time::interval};
use tracing::{debug, info};

/// 单条 UDP 报文上限（与 frp `MaxUDPPayloadSize` 一致）。
const MAX_UDP_PAYLOAD: usize = 65507;
/// 会话空闲回收时间：与 frp 客户端的 30s 读超时一致。
const SESSION_IDLE: Duration = Duration::from_secs(30);
/// 工作连接心跳间隔（官方 frps 对 UDP 工作连接有 60s 读超时）。
const KEEPALIVE_INTERVAL: Duration = Duration::from_secs(30);

/// 一个访客对应的本地会话：往这里塞数据就会发到内网 UDP 服务。
type SessionTx = mpsc::Sender<Vec<u8>>;

/// 跑一条 UDP 工作连接，直到断开。
pub async fn run(conn: FrpConn, local_addr: String, proxy_name: String) -> Result<()> {
    let local: SocketAddr = util::resolve_addr(&local_addr)
        .await
        .with_context(|| format!("解析内网 UDP 地址 {local_addr} 失败"))?;
    info!(proxy = %proxy_name, %local, "UDP 工作连接已建立");

    let sessions: Arc<Mutex<HashMap<String, SessionTx>>> = Arc::new(Mutex::new(HashMap::new()));
    // 内网服务的响应 → 工作连接
    let (to_server_tx, mut to_server_rx) = mpsc::channel::<UdpPacket>(1024);

    let mut conn = conn;
    let mut keepalive = interval(KEEPALIVE_INTERVAL);
    keepalive.tick().await; // 丢掉立即触发的那次

    let result = loop {
        tokio::select! {
            msg = conn.recv_msg() => {
                let Some(msg) = msg? else { break Ok(()) };
                match msg {
                    FrpMessage::UdpPacket(pkt) => {
                        let Some(remote) = pkt.remote_addr.clone() else {
                            debug!("UDP 报文缺少访客地址，丢弃");
                            continue;
                        };
                        // 注意：锁必须在本语句内释放，不能在 match 的临时变量里跨越 await
                        let existing = {
                            sessions.lock().unwrap().get(&remote.key()).cloned()
                        };
                        let tx = match existing {
                            Some(tx) => tx,
                            None => match new_session(&local, &remote, &sessions, &to_server_tx).await {
                                Ok(tx) => tx,
                                Err(e) => {
                                    debug!(%remote, "创建 UDP 会话失败：{e:#}");
                                    continue;
                                }
                            },
                        };
                        if tx.send(pkt.payload().to_vec()).await.is_err() {
                            sessions.lock().unwrap().remove(&remote.key());
                        }
                    }
                    FrpMessage::Ping(_) => {}
                    other => debug!(proxy = %proxy_name, "UDP 工作连接忽略消息：{}", other.name()),
                }
            }
            Some(pkt) = to_server_rx.recv() => {
                if let Err(e) = conn.send_msg(&FrpMessage::UdpPacket(pkt)).await {
                    break Err(e).context("UDP 响应写往工作连接失败");
                }
            }
            _ = keepalive.tick() => {
                let _ = conn.send_msg(&FrpMessage::Ping(Ping::default())).await;
            }
        }
    };

    sessions.lock().unwrap().clear();
    result
}

/// 为某个访客建立一个本地 UDP 会话（socket + 收发任务）。
async fn new_session(
    local: &SocketAddr,
    remote: &UdpAddr,
    sessions: &Arc<Mutex<HashMap<String, SessionTx>>>,
    to_server: &mpsc::Sender<UdpPacket>,
) -> Result<SessionTx> {
    let bind: SocketAddr = if local.is_ipv4() {
        "0.0.0.0:0".parse().unwrap()
    } else {
        "[::]:0".parse().unwrap()
    };
    let sock = Arc::new(
        UdpSocket::bind(bind)
            .await
            .with_context(|| format!("绑定本地 UDP {bind} 失败"))?,
    );
    sock.connect(local)
        .await
        .with_context(|| format!("连接内网 UDP {local} 失败"))?;

    let (tx, mut rx) = mpsc::channel::<Vec<u8>>(256);

    // 发送：访客 → 内网服务
    {
        let sock = sock.clone();
        tokio::spawn(async move {
            while let Some(data) = rx.recv().await {
                if let Err(e) = sock.send(&data).await {
                    debug!("发送 UDP 到内网服务失败：{e}");
                    return;
                }
            }
        });
    }

    // 接收：内网服务 → 访客（带回访客地址，服务端据此写回）
    {
        let sock = sock.clone();
        let key = remote.key();
        let remote2 = remote.clone();
        let sessions = sessions.clone();
        let to_server = to_server.clone();
        tokio::spawn(async move {
            let mut buf = vec![0u8; MAX_UDP_PAYLOAD];
            loop {
                match tokio::time::timeout(SESSION_IDLE, sock.recv(&mut buf)).await {
                    Ok(Ok(n)) => {
                        let Some(dst) = remote2.to_socket() else { return };
                        if to_server
                            .send(UdpPacket::new(&buf[..n], &dst))
                            .await
                            .is_err()
                        {
                            break;
                        }
                    }
                    Ok(Err(e)) => {
                        debug!("读取内网 UDP 响应失败：{e}");
                        break;
                    }
                    Err(_) => {
                        debug!(key = %key, "UDP 会话空闲超时，回收");
                        break;
                    }
                }
            }
            sessions.lock().unwrap().remove(&key);
        });
    }

    sessions.lock().unwrap().insert(remote.key(), tx.clone());
    Ok(tx)
}
