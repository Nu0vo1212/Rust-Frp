//! 服务端侧的 NLink 运行期状态。
//!
//! 把"配置 → 运行期对象"这一步集中在一个地方，避免 `serve.rs` 里散落
//! 一堆 `if cfg.nlink.enable`。四个组件：
//!
//! * `limiter`：按用户×代理的令牌桶（数据面桥接层扣费）；
//! * `knock`：敲门放行表（数据面 accept 点查询）；
//! * `resume`：断线续传状态（控制连接断开时写入，重连时取走）；
//! * `identity`：零信任身份令牌的签名密钥（由 token 派生）。

use std::net::IpAddr;
use std::time::Duration;

use nfrp_common::config::ServerConfig;
use nfrp_common::nlink::knock::{KnockAuthorizer, KnockRule};
use nfrp_common::nlink::ratelimit::RateLimiter;
use nfrp_common::nlink::session::{IdentityKey, ResumeRegistry};
use nfrp_common::nlink::{Caps, FeatureSet, ServerNLinkConfig};
use tokio::io::AsyncReadExt;
use tokio::net::TcpStream;

/// 服务端 NLink 的只读运行期状态（热重载时整体替换）。
pub struct NLinkRuntime {
    pub cfg: ServerNLinkConfig,
    pub features: FeatureSet,
    pub limiter: RateLimiter,
    pub knock: KnockAuthorizer,
    pub resume: ResumeRegistry,
    pub identity: IdentityKey,
}

impl NLinkRuntime {
    pub fn from_config(cfg: &ServerConfig, identity_secret: &str) -> Self {
        let nlink = cfg.nlink.clone();
        let features = nlink.features();
        Self {
            limiter: RateLimiter::new(nlink.limits.clone()),
            knock: KnockAuthorizer::new(),
            resume: ResumeRegistry::new(),
            identity: IdentityKey::derive(identity_secret),
            features,
            cfg: nlink,
        }
    }

    /// 全部关闭的默认实例（未配置 / 热重载失败时兜底）。
    pub fn disabled() -> Self {
        Self {
            cfg: ServerNLinkConfig::default(),
            features: FeatureSet::default(),
            limiter: RateLimiter::new(vec![]),
            knock: KnockAuthorizer::new(),
            resume: ResumeRegistry::new(),
            identity: IdentityKey::derive(""),
        }
    }

    pub fn enabled(&self) -> bool {
        self.cfg.enable && self.features.active().any()
    }

    /// 传给握手的运行期能力掩码；`None` = 本次连接不协商。
    pub fn enabled_mask(&self) -> Option<u64> {
        if self.enabled() {
            Some(self.features.active().bits())
        } else {
            None
        }
    }

    pub fn knock_rule(&self, port: u16) -> Option<&KnockRule> {
        self.cfg
            .knock
            .iter()
            .find(|r| r.port == port && r.effective())
    }

    pub fn resume_ttl(&self) -> Duration {
        Duration::from_secs(self.cfg.resume_ttl.clamp(5, 600))
    }

    pub fn identity_ttl(&self) -> Duration {
        Duration::from_secs(self.cfg.identity_ttl.clamp(30, 3600))
    }

    /// 协商结果是否包含某一项能力。
    pub fn has(caps: Option<Caps>, bit: u64) -> bool {
        caps.map(|c| c.contains(bit)).unwrap_or(false)
    }
}

/// 数据面的敲门尝试。
///
/// 只在端口配了敲门规则时调用。读取最多 2 秒：
///
/// * 读到合法序列 ⇒ 记入放行表，返回 `true`（调用方随即关掉这条"敲门连接"）；
/// * 读到别的东西 / 超时 / 对端关闭 ⇒ 返回 `false`（调用方静默关闭，
///   对外表现与"端口没开"一致）。
pub async fn try_knock(
    stream: &mut TcpStream,
    rule: &KnockRule,
    peer: IpAddr,
    auth: &KnockAuthorizer,
) -> bool {
    let mut buf = vec![0u8; nfrp_common::nlink::knock::KNOCK_LEN];
    let read = tokio::time::timeout(Duration::from_secs(2), stream.read_exact(&mut buf)).await;
    let Ok(Ok(_)) = read else {
        return false;
    };
    match nfrp_common::nlink::knock::verify_knock(rule, &buf, peer, std::time::SystemTime::now()) {
        Ok(()) => {
            auth.allow(peer, rule.port, Duration::from_secs(rule.window.clamp(1, 3600)));
            tracing::info!(%peer, port = rule.port, "端口敲门通过，临时放行");
            true
        }
        Err(e) => {
            tracing::debug!(%peer, port = rule.port, "端口敲门失败：{e}");
            false
        }
    }
}

/// 处理一条来自客户端的扩展帧（控制连接上）。
///
/// 这里只处理\"服务端应答\"的那几类；其余（BatchResp / ResumeResp 等本就该由
/// 客户端处理）记 debug 后忽略 —— **不认识就忽略**是这一层的硬约定。
pub async fn handle_control_frame(
    conn: &mut nfrp_common::frp::conn::FrpConn,
    frame: &nfrp_common::nlink::Frame,
    run_id: &str,
) -> anyhow::Result<()> {
    use nfrp_common::nlink::frame::{FrameKind, TAG_DETAIL, TAG_VERSION};
    use nfrp_common::nlink::Frame as NFrame;

    match frame.kind {
        FrameKind::Trace => {
            tracing::debug!(
                target: "nlink_trace",
                %run_id,
                trace = %frame.tlvs.get_str(nfrp_common::nlink::frame::TAG_TRACE_ID).unwrap_or_default(),
                span = %frame.tlvs.get_str(nfrp_common::nlink::frame::TAG_SPAN).unwrap_or_default(),
                "收到 trace 扩展帧"
            );
        }
        FrameKind::CompatProbe => {
            // 把兼容性矩阵原样回给客户端：答应\"服务端会怎么对待官方字段\"
            // 这种问题，不该让用户去翻源码。
            let mut detail = String::new();
            for row in nfrp_common::nlink::policy::MATRIX {
                detail.push_str(row.feature);
                detail.push('|');
                detail.push_str(row.level.as_str());
                detail.push('|');
                detail.push_str(row.e2e);
                detail.push('|');
                detail.push_str(row.note);
                detail.push('\n');
            }
            let resp = NFrame::new(FrameKind::CompatResp)
                .with(TAG_VERSION, vec![nfrp_common::nlink::PROTOCOL_VERSION])
                .with(TAG_DETAIL, detail.into_bytes());
            conn.send_nlink(&resp).await?;
        }
        FrameKind::Knock => {
            // 控制面敲门：数据面才是真正生效的地方（见 knock.rs），
            // 这里只记录，不下发放行 —— 免得\"控制连接通了\"变成放行依据。
            tracing::debug!(%run_id, "收到控制面敲门帧（数据面另行校验）");
        }
        other => {
            tracing::debug!(%run_id, kind = ?other, "忽略不处理的 NLink 扩展帧");
        }
    }
    Ok(())
}

/// 单方向搬运 + 令牌桶扣费。
///
/// 每读到一块就按**实际字节数**申请额度：欠账时 `sleep` 等桶回血，
/// 而不是丢包或截断 —— 对大响应体来说，"慢一点"永远好过"少一截"。
async fn copy_throttled<R, W>(
    r: &mut R,
    w: &mut W,
    limiter: &RateLimiter,
    user: &str,
    proxy: &str,
) -> std::io::Result<u64>
where
    R: tokio::io::AsyncRead + Unpin,
    W: tokio::io::AsyncWrite + Unpin,
{
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    // 16 KiB 是"够大不至于 syscall 太密、够小不至于让限流粒度变得很粗"的折中。
    // 不用 `util::RELAY_BUF`：那个是给无限速路径调大的，套上限流只会
    // 让令牌桶一次扣掉一大块，突发感更明显。
    let mut buf = vec![0u8; 16 * 1024];
    let mut total = 0u64;
    loop {
        let n = match r.read(&mut buf).await {
            Ok(0) => break,
            Ok(n) => n,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        };
        limiter.throttle(user, proxy, n as u64).await;
        w.write_all(&buf[..n]).await?;
        w.flush().await?;
        total += n as u64;
    }
    Ok(total)
}

/// 带限流的双向转发（`util::relay_between` 的限流版）。
///
/// 两个方向共用**同一个**令牌桶（按 `user + proxy` 划分），
/// 所以上行 + 下行合计不超过规则里的 `rate` —— 与官方 `bandwidthLimit`
/// 的语义一致（官方也是按代理算总带宽）。
pub async fn relay_throttled<A, B>(
    limiter: &RateLimiter,
    user: &str,
    proxy: &str,
    a: &mut A,
    b: &mut B,
) -> std::io::Result<(u64, u64)>
where
    A: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
    B: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let (mut ar, mut aw) = tokio::io::split(a);
    let (mut br, mut bw) = tokio::io::split(b);
    let up = copy_throttled(&mut ar, &mut bw, limiter, user, proxy);
    let down = copy_throttled(&mut br, &mut aw, limiter, user, proxy);
    let (up, down) = tokio::try_join!(up, down)?;
    Ok((up, down))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn 默认实例是关闭的() {
        let rt = NLinkRuntime::disabled();
        assert!(!rt.enabled());
        assert!(rt.enabled_mask().is_none());
        assert_eq!(rt.resume_ttl(), Duration::from_secs(30));
    }

    #[test]
    fn 打开但没写能力名时仍然不协商() {
        let mut cfg = ServerConfig::default();
        cfg.nlink.enable = true;
        let rt = NLinkRuntime::from_config(&cfg, "token");
        assert!(!rt.enabled(), "只开开关不列能力 = 仅协商不启用");
        assert!(rt.enabled_mask().is_none());
    }

    #[test]
    fn 写了一个能力名就协商该能力() {
        let mut cfg = ServerConfig::default();
        cfg.nlink.enable = true;
        cfg.nlink.features = vec!["trace".into()];
        let rt = NLinkRuntime::from_config(&cfg, "token");
        assert_eq!(rt.enabled_mask(), Some(nfrp_common::nlink::CAP_TRACE));
    }

    #[test]
    fn ttl_有上下界() {
        let mut cfg = ServerConfig::default();
        cfg.nlink.resume_ttl = 100_000;
        cfg.nlink.enable = true;
        cfg.nlink.features = vec!["resume".into()];
        let rt = NLinkRuntime::from_config(&cfg, "t");
        assert_eq!(rt.resume_ttl(), Duration::from_secs(600));
    }
}
