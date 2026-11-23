//! 与服务端的控制连接工厂（TCP / TLS / yamux / QUIC）及 QUIC 迁移看门狗。
//!
//! 职责：按配置建立控制链路（`ServerLink::open`）、按需开流（`connect`）、读写
//! 协商出的能力位，以及出口 IP 变化时的 QUIC rebind。
//! 并发/所有权契约：`ServerLink` 由 `Arc` 在 main 的重连循环、会话、工作连接、
//! visitor、web 面板之间共享；迁移器只持 `Weak`，链路回收后自行退出。
//! 不变量：`cfg` / `wire` / `udp_binary` / `token_source` 由本会话的写入口
//! （`open`、`run_session`）写入，其余使用方只读；`quic` 的 `Endpoint` 必须与
//! `Connection` 同生共死（只留 Connection 会在 drop 时断链）。

use std::{sync::Arc, time::Duration};

use anyhow::{anyhow, bail, Context, Result};
use nfrp_common::{
    config::{is_quic, ClientConfig},
    frp::{
        self,
        mux::{MuxKeepalive, MuxSession},
        stream::BoxStream,
    },
};
use portable_atomic::AtomicU64;
use tokio::time::interval;
use tracing::{info, warn};

use crate::dial::{nlink_quic_server_addr, outbound_ip, quic_server_addr, raw_connect};

/// 与服务端之间的连接工厂。
///
/// 负责按配置依次套上 TLS 与 yamux：
/// - `tls_enable` 打开时先发 frp 自定义首字节再握手；
/// - `tcp_mux` 打开时只在会话开始时建一条 TCP，后续所有连接都开 yamux stream。
pub(crate) struct ServerLink {
    pub(crate) cfg: Arc<ClientConfig>,
    /// 本次会话使用的线协议（v1 / v2）。工作连接、visitor 连接都必须跟着用，
    /// 否则会与服务端对不上（官方 frps 会直接以 `wire protocol mismatch` 拒绝）。
    pub(crate) wire: frp::WireVersion,
    mux: Option<MuxSession>,
    /// QUIC 传输：一条 QUIC 连接上的每条双向流就是一条 frp 连接。
    ///
    /// `Endpoint` 必须一起存着 —— 它被 drop 时上面的连接会立刻断开，
    /// 只留 `Connection` 是不够的。
    quic: Option<(quinn::Endpoint, quinn::Connection)>,
    /// 本次会话协商出的 UDP 报文编码（true = 二进制），工作连接要跟着用。
    pub(crate) udp_binary: std::sync::atomic::AtomicBool,
    /// 本会话协商出来的 NLink 能力位（0 = 没协商）。
    ///
    /// 放在 `ServerLink` 而不是 `FrpConn` 上，是因为工作连接、visitor、
    /// web 面板都可能要读它，而它们只拿得到 `Arc<ServerLink>`。
    nlink_caps: AtomicU64,
    /// OIDC 令牌源。
    ///
    /// 工作连接也要现取 access token（见 [`current_credential`]），
    /// 而工作连接只拿得到 `Arc<ServerLink>`。放在这里就不用把
    /// `token_source` 一路透传到 `spawn_work_conn` 的每个调用点。
    pub(crate) token_source: Option<Arc<nfrp_common::auth::oidc::TokenSource>>,
}

/// NLink QUIC 是否应在本会话尝试。
///
/// 判据是「运行期开关 + 编译期实现」，**不是**裸的 `features` 列表：
/// `quic = true` 是便利开关，`ClientNLink::from_config` 会隐式补上
/// `CAP_QUIC`。0.7.0 在 `ServerLink::open` 里查裸列表，导致只写
/// `quic = true` 时静默走 TCP（服务端那边却以为客户端支持 QUIC）。
fn nlink_quic_requested(cfg: &ClientConfig) -> bool {
    cfg.nlink.enable
        && cfg.nlink.quic
        && nfrp_common::nlink::compiled_caps().contains(nfrp_common::nlink::CAP_QUIC)
}

impl ServerLink {
    pub(crate) async fn open(
        cfg: Arc<ClientConfig>,
        token_source: Option<Arc<nfrp_common::auth::oidc::TokenSource>>,
    ) -> Result<Self> {
        let wire = cfg.protocol.wire_version().ok_or_else(|| {
            anyhow!("当前版本尚未实现 NFrp 自研协议，请把 protocol 设为 frp-v1 或 frp-v2")
        })?;
        // QUIC 自带加密与多路复用，所以 tls / tcp_mux 这两层都跳过。
        //
        // NLink 的 QUIC 用另一个 ALPN（`nfrp-nlink`）与独立端口，
        // 优先级高于标准 `transport_protocol = "quic"`：两个都配时按 NLink 走
        // （否则 preamble 会发到只认 `nfrp-frp` 的端点上，握手失败）。
        //
        // ★ 判据必须看**编译期能力 ∩ 便利开关**，而不是裸 `features()`：
        //   `quic = true` 会由 `ClientNLink::from_config` 隐式补上 CAP_QUIC，
        //   0.7.0 这里查裸列表，导致只写 `quic = true` 时静默走 TCP。
        let nlink_quic = nlink_quic_requested(&cfg);
        let quic = if nlink_quic {
            // NLink QUIC 是**增强路径**：失败必须回退到 TCP，而不是让整个
            // 会话失败。用户配了 quic=true 但 UDP 被防火墙挡住时，TCP
            // 仍然能用；只是失去多路复用与连接迁移。
            let attempt = async {
                let addr = nlink_quic_server_addr(&cfg).await?;
                let (endpoint, conn) =
                    frp::quic::connect_with_alpn(&addr, None, nfrp_common::nlink::ALPN).await?;
                Ok::<_, anyhow::Error>((addr, endpoint, conn))
            }
            .await;
            match attempt {
                Ok((addr, endpoint, conn)) => {
                    info!(%addr, alpn = "nfrp-nlink", "NLink QUIC 传输已建立");
                    Some((endpoint, conn))
                }
                Err(e) => {
                    warn!(
                        "NLink QUIC 连接失败，回退到 TCP：{e:#}（本次会话没有 QUIC 多路复用 / 迁移）"
                    );
                    None
                }
            }
        } else if is_quic(&cfg.transport_protocol) {
            let addr = quic_server_addr(&cfg).await?;
            let (endpoint, conn) = frp::quic::connect(&addr, None).await?;
            info!(%addr, "QUIC 传输已建立");
            Some((endpoint, conn))
        } else {
            None
        };

        let mux = if quic.is_none() && cfg.tcp_mux {
            let stream = raw_connect(&cfg).await?;
            // yamux 保活（限制①批次2，官方 `tcpMuxKeepaliveInterval`）：
            // 0 = 关闭看门狗（None），默认 30 秒。
            Some(MuxSession::new(
                stream,
                MuxKeepalive::from_secs(cfg.tcp_mux_keepalive_interval),
            ))
        } else {
            None
        };
        Ok(Self {
            cfg,
            wire,
            mux,
            quic,
            udp_binary: std::sync::atomic::AtomicBool::new(false),
            nlink_caps: AtomicU64::new(0),
            token_source,
        })
    }

    /// 本会话协商出来的 NLink 能力位。
    pub(crate) fn nlink_caps(&self) -> nfrp_common::nlink::Caps {
        nfrp_common::nlink::Caps(self.nlink_caps.load(std::sync::atomic::Ordering::Relaxed))
    }

    /// 登录成功后由 `run_session` 写入。
    pub(crate) fn set_nlink_caps(&self, caps: nfrp_common::nlink::Caps) {
        self.nlink_caps
            .store(caps.bits(), std::sync::atomic::Ordering::Relaxed);
    }

    /// 取得一条到服务端的流：QUIC 双向流、yamux stream，或一条新的 TCP（+TLS）。
    pub(crate) async fn connect(&self) -> Result<BoxStream> {
        if let Some((_ep, conn)) = &self.quic {
            let (send, recv) = conn.open_bi().await.context("在 QUIC 连接上开双向流失败")?;
            return Ok(Box::pin(frp::quic::QuicStream::new(send, recv)));
        }
        match &self.mux {
            Some(m) => m.open_stream().await,
            None => raw_connect(&self.cfg).await,
        }
    }

    /// QUIC 连接当前的本地地址（迁移前后对比用）。非 QUIC 时为 None。
    fn quic_local_addr(&self) -> Option<std::net::SocketAddr> {
        self.quic
            .as_ref()
            .and_then(|(ep, _)| frp::quic::local_addr(ep))
    }

    /// 把 QUIC 连接的本地出口换到 `local`。
    ///
    /// quinn 靠连接 ID 识别连接，换源地址不会断开在途流 —— 这正是
    /// "从 WiFi 切到 4G 不用重连"的底层机制。
    async fn rebind_quic(&self, local: std::net::SocketAddr) -> Result<()> {
        let Some((ep, _)) = &self.quic else {
            bail!("当前连接不是 QUIC，无法迁移");
        };
        frp::quic::rebind(ep, local).await
    }
}

/// 网络切换自动迁移：每 5 秒看一次"到服务端的出口 IP 变了没"。
///
/// 用一个 `Weak` 持有 `ServerLink`：会话结束、链路被回收后这个任务自己退出，
/// 不会因为"迁移器还活着"把整条连接（以及它的 QUIC endpoint）留着不放。
///
/// 5 秒是"WiFi 切 4G 后用户能忍受的空窗"与"不要无谓唤醒"之间的折中：
/// 迁移本身是一次 `rebind`，不重建连接，所以快慢只影响切换后的恢复时间。
pub(crate) fn spawn_quic_migrator(link: std::sync::Weak<ServerLink>, cfg: Arc<ClientConfig>) {
    tokio::spawn(async move {
        let Ok(server) = nlink_quic_server_addr(&cfg).await else {
            return;
        };
        let mut ticker = interval(Duration::from_secs(5));
        loop {
            ticker.tick().await;
            let Some(link) = link.upgrade() else {
                break;
            };
            let Some(cur) = link.quic_local_addr() else {
                break;
            };
            let Some(ip) = outbound_ip(server).await else {
                continue;
            };
            if ip == cur.ip() {
                continue;
            }
            let target = std::net::SocketAddr::new(ip, 0);
            match link.rebind_quic(target).await {
                Ok(()) => info!(from = %cur, to = %target, "QUIC 连接已迁移到新的本地出口"),
                Err(e) => warn!("QUIC 连接迁移失败：{e:#}"),
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nlink_quic_门控看运行期开关与编译期能力() {
        let mut cfg = ClientConfig::default();
        cfg.nlink.quic = true;
        // 总开关关着：无论怎么配都不尝试。
        cfg.nlink.enable = false;
        assert!(!nlink_quic_requested(&cfg));

        cfg.nlink.enable = true;
        // 只写 quic = true、features 留空：便利开关必须生效，
        // 不能被"裸 features 列表里没有 quic"挡成 TCP。
        assert_eq!(
            nlink_quic_requested(&cfg),
            nfrp_common::nlink::compiled_caps().contains(nfrp_common::nlink::CAP_QUIC),
            "quic = true 应由便利开关隐式启用"
        );

        cfg.nlink.quic = false;
        assert!(
            !nlink_quic_requested(&cfg),
            "显式关掉 quic 时即使 features 里写了也不应尝试"
        );
    }
}
