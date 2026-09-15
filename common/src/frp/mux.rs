//! yamux 多路复用，对应 frp 的 `transport.tcpMux`。
//!
//! 层次：`TCP -> [TLS] -> yamux 会话 -> 每条 stream 上跑一次 frp v2 握手`。
//! 控制连接与所有工作连接复用同一条 TCP，每条连接占一个 yamux stream。
//!
//! 实现要点：rust-yamux 的 `Connection` 必须由外部持续 poll 来驱动，
//! 子流 `Stream` 只是从共享缓冲里取数据。因此这里把 `Connection` 放进后台任务。

use anyhow::{anyhow, bail, Result};
use futures::future::poll_fn;
use tokio::sync::{mpsc, oneshot};
use tokio_util::compat::{FuturesAsyncReadCompatExt, TokioAsyncReadCompatExt};
use yamux::{Config, Connection, Mode};

use super::stream::BoxStream;

/// 开流请求的应答通道。
type OpenReq = oneshot::Sender<std::result::Result<yamux::Stream, yamux::ConnectionError>>;

fn mux_config() -> Config {
    // 默认 `split_send_size` 只有 16 KiB：单流打满时每 16 KiB 就要走一遍
    // "分配缓冲 + 加锁 + 写 frame 头 + 唤醒驱动任务"的流程，
    // 本机回环实测单流只有 ~530 Mbps（官方 frp 用 Go yamux 能到 ~2 Gbps）。
    // 提高到 128 KiB 后单流吞吐明显改善；多流场景本来就够快。
    let mut cfg = Config::default();
    cfg.set_split_send_size(128 * 1024);
    cfg
}

/// 服务端：接收对端打开的 yamux stream。
pub struct MuxAcceptor {
    rx: mpsc::Receiver<yamux::Stream>,
}

impl MuxAcceptor {
    /// 等待下一条 stream；会话关闭时返回 `None`。
    pub async fn accept(&mut self) -> Option<BoxStream> {
        let s = self.rx.recv().await?;
        Some(Box::pin(s.compat()))
    }
}

/// 在已有流上建立 yamux 服务端会话。
pub fn serve(stream: BoxStream) -> MuxAcceptor {
    let (tx, rx) = mpsc::channel(64);
    let mut conn = Connection::new(stream.compat(), mux_config(), Mode::Server);
    tokio::spawn(async move {
        loop {
            let item = poll_fn(|cx| conn.poll_next_inbound(cx)).await;
            match item {
                Some(Ok(s)) => {
                    if tx.send(s).await.is_err() {
                        break;
                    }
                }
                Some(Err(e)) => {
                    tracing::debug!("yamux 会话错误：{e}");
                    break;
                }
                None => break,
            }
        }
    });
    MuxAcceptor { rx }
}

/// 客户端：在一条底层流上按需开新的 yamux stream。
///
/// 会话本身跑在后台任务里，通过 channel 请求开流。
#[derive(Clone)]
pub struct MuxSession {
    req_tx: mpsc::Sender<OpenReq>,
}

impl MuxSession {
    pub fn new(stream: BoxStream) -> Self {
        let (req_tx, req_rx) = mpsc::channel(64);
        let conn = Connection::new(stream.compat(), mux_config(), Mode::Client);
        tokio::spawn(drive_client(conn, req_rx));
        Self { req_tx }
    }

    /// 打开一条新的 stream（控制连接、工作连接都走这里）。
    pub async fn open_stream(&self) -> Result<BoxStream> {
        let (tx, rx) = oneshot::channel();
        self.req_tx
            .send(tx)
            .await
            .map_err(|_| anyhow!("yamux 会话已关闭，无法开流"))?;
        match rx.await.map_err(|_| anyhow!("yamux 会话已关闭"))? {
            Ok(s) => Ok(Box::pin(s.compat())),
            Err(e) => bail!("yamux 打开 stream 失败：{e}"),
        }
    }
}

/// 后台驱动任务：既要持续 poll 连接推进数据，又要响应开流请求。
///
/// 两者都要独占 `&mut Connection`，所以放在同一个 `poll_fn` 里顺序处理，
/// 用 `pending` 暂存"已经取出但还没就绪"的开流请求。
async fn drive_client<S>(mut conn: Connection<S>, mut req_rx: mpsc::Receiver<OpenReq>)
where
    S: futures::AsyncRead + futures::AsyncWrite + Unpin,
{
    let mut pending: Option<OpenReq> = None;

    enum Ev {
        /// 收到入站 stream。frp 服务端不会主动向客户端开流，直接丢弃即可。
        Inbound,
        InboundErr(String),
        Outbound(OpenReq, std::result::Result<yamux::Stream, yamux::ConnectionError>),
        Closed,
    }

    loop {
        let ev = poll_fn(|cx| {
            // 1) 驱动会话，顺带取入站 stream（客户端模式下通常没有）
            match conn.poll_next_inbound(cx) {
                std::task::Poll::Ready(Some(Ok(_))) => return std::task::Poll::Ready(Ev::Inbound),
                std::task::Poll::Ready(Some(Err(e))) => {
                    return std::task::Poll::Ready(Ev::InboundErr(e.to_string()))
                }
                std::task::Poll::Ready(None) => return std::task::Poll::Ready(Ev::Closed),
                std::task::Poll::Pending => {}
            }

            // 2) 处理开流请求（每条分支都会返回，所以不需要循环）
            if pending.is_none() {
                match req_rx.poll_recv(cx) {
                    std::task::Poll::Ready(Some(tx)) => pending = Some(tx),
                    std::task::Poll::Ready(None) => return std::task::Poll::Ready(Ev::Closed),
                    std::task::Poll::Pending => return std::task::Poll::Pending,
                }
            }
            let Some(tx) = pending.take() else {
                return std::task::Poll::Pending;
            };
            match conn.poll_new_outbound(cx) {
                std::task::Poll::Ready(r) => std::task::Poll::Ready(Ev::Outbound(tx, r)),
                std::task::Poll::Pending => {
                    pending = Some(tx);
                    std::task::Poll::Pending
                }
            }
        })
        .await;

        match ev {
            Ev::Inbound => {
                // frp 服务端不会主动向客户端开流，收到就丢弃
                tracing::debug!("yamux 收到意外的入站 stream，忽略");
            }
            Ev::InboundErr(e) => {
                tracing::debug!("yamux 会话结束：{e}");
                break;
            }
            Ev::Outbound(tx, r) => {
                let _ = tx.send(r);
            }
            Ev::Closed => break,
        }
    }
}
