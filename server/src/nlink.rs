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
    /// 一次性续传令牌的签名密钥。
    ///
    /// 与 `identity` 分开派生（`nlink-resume|` 前缀不同），
    /// 这样身份令牌和续传令牌互不通用。
    pub resume_key: nfrp_common::nlink::session::ResumeKey,
    /// 已签发、待消费的续传令牌。消费与校验在同一把锁里完成，防重放。
    pub resume_tokens: nfrp_common::nlink::session::PendingTokens,
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
            resume_key: nfrp_common::nlink::session::ResumeKey::derive(identity_secret),
            resume_tokens: nfrp_common::nlink::session::PendingTokens::new(),
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
            resume_key: nfrp_common::nlink::session::ResumeKey::derive(""),
            resume_tokens: nfrp_common::nlink::session::PendingTokens::new(),
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
        // 运行期总开关 / 能力协商都没过时，配置里写了规则也不生效。
        // 否则 `enable = false` 会变成一句空话：端口仍然被敲门表拦截，
        // 运维以为关掉了 NLink，实际数据面还在按它的规则跑。
        if !self.enabled()
            || !self
                .features
                .active()
                .contains(nfrp_common::nlink::CAP_PORT_KNOCK)
        {
            return None;
        }
        self.cfg
            .knock
            .iter()
            .find(|r| r.port == port && r.effective())
    }

    /// 数据面限流是否生效（同样受总开关 + 能力位门控）。
    pub fn rate_limit_enabled(&self) -> bool {
        self.enabled()
            && self
                .features
                .active()
                .contains(nfrp_common::nlink::CAP_RATE_LIMIT)
            && !self.limiter.is_empty()
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
            auth.allow(
                peer,
                rule.port,
                Duration::from_secs(rule.window.clamp(1, 3600)),
            );
            tracing::info!(%peer, port = rule.port, "端口敲门通过，临时放行");
            true
        }
        Err(e) => {
            tracing::debug!(%peer, port = rule.port, "端口敲门失败：{e}");
            false
        }
    }
}

/// 签发并登记一张一次性续传令牌，返回令牌原文。
///
/// 返回 `None` 表示当前配置没开续传能力，不需要令牌。
///
/// # 为什么在登录成功时就签发
///
/// 断线那一刻控制连接已经没了，发不出任何东西。所以令牌必须**提前下发**，
/// 由客户端保存到下一次重连。
pub fn issue_resume_token(
    rt: &NLinkRuntime,
    session: nfrp_common::nlink::ConnectionId,
    user: &str,
    client_id: &str,
    ttl_secs: u64,
) -> Option<String> {
    if !rt
        .features
        .active()
        .contains(nfrp_common::nlink::CAP_RESUME)
    {
        return None;
    }
    let ttl = std::time::Duration::from_secs(ttl_secs.max(1));
    let now = std::time::SystemTime::now();
    let tok = rt.resume_key.issue(session, user, client_id, ttl, now);
    rt.resume_tokens.issue(session, tok.clone(), ttl);
    Some(tok)
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
    // 但**低速率**下 16 KiB 一块会让令牌桶一次欠 16 秒的量：老实现把等待
    // 截断到 burst/rate（=1 秒），于是 1 KiB/s 实际跑成 ~16 KiB/s。
    // 现在按速率切块：最慢每秒读一块，等待时间自然 ≈ 1 秒，速率准确。
    let budget = limiter
        .rate_for(user, proxy)
        .unwrap_or(16 * 1024)
        .clamp(1, 16 * 1024) as usize;
    let mut buf = vec![0u8; budget];
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

    // ★ 读到 EOF 后必须 shutdown 写端。
    //
    // 否则对侧的 `read()` 永远等不到 EOF，`relay_throttled` 里的
    // `try_join!` 就永远不返回 —— 工作连接不释放。这正是官方
    // 「服务端带宽限制时工作连接不关闭」那条修复的同一个形态。
    //
    // 失败可忽略：链路本来就可能已经断了，这不该让整个转发判失败。
    let _ = w.shutdown().await;
    Ok(total)
}

/// 限流的双向转发（`util::relay_between` 的限流版）。
///
/// 两个方向共用**同一个**令牌桶（按 `user + proxy` 划分），
/// 所以上行 + 下行合计不超过规则里的 `rate` —— 与官方 `bandwidthLimit`
/// 的语义一致（官方也是按代理算总带宽）。
///
/// # ★ 为什么不能简单用 `try_join!` 等两边都结束
///
/// 这是 0.7.4 修的一个真实缺陷（对应官方「服务端带宽限制时工作连接不关闭」）：
///
/// 客户端常常只关**一个**方向（半关闭）。一侧读到 EOF 退出后，另一侧的
/// `read()` 还会挂着等数据 —— 而 `try_join!` 必须两边都完成才返回，
/// 于是整个 bridge 任务永远不结束，**工作连接和它占用的 fd 都不释放**。
///
/// 这是限流路径独有的问题：不限流走 `copy_bidirectional`，它在一侧 EOF 时
/// 会 shutdown 另一侧的写端，对端收到 FIN 后自然结束。
///
/// 修法：`copy_throttled` 在自己读到 EOF 后**主动 shutdown 写端**（它本来就
/// 持有 `w` 的独占借用，能这么做），对端收到 FIN 后也会读到 EOF 并退出，
/// 于是 `try_join!` 自然收敛。
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

    /// 半关闭后 `relay_throttled` 必须返回，不能两边互相等。
    ///
    /// 对应官方「服务端带宽限制时工作连接不关闭」那条修复。
    ///
    /// # 场景
    ///
    /// 客户端发完数据就关掉自己的写端（TCP 半关闭），但**继续读**响应。
    /// 旧的 `try_join!` 实现里，正向 `copy_throttled` 读到 EOF 退出了，
    /// 反向还在 `read()` 上等 —— 而 `try_join!` 要两边都完成，于是永远不返回，
    /// 工作连接和它的 fd 都泄漏。
    ///
    /// 现在 `copy_throttled` 在 EOF 时 shutdown 写端，对端读到 EOF 后也会退出，
    /// 整个转发随之返回。
    ///
    /// 用 `timeout` 包住：一旦回归，失败是 2 秒后报"超时"，
    /// 而不是把整个测试挂死。
    #[tokio::test]
    async fn 限流转发在半关闭后必须返回释放连接() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let limiter = RateLimiter::new(vec![]); // 空规则 = 不限速，但走同一条代码路径

        // 服务端侧 a <-> b（都用 duplex 模拟两条真实连接）
        let (mut a_server, mut a_client) = tokio::io::duplex(64 * 1024);
        let (mut b_server, mut b_client) = tokio::io::duplex(64 * 1024);

        let relay = tokio::spawn(async move {
            relay_throttled(&limiter, "u", "p", &mut a_server, &mut b_server).await
        });

        // a 侧发一句话，然后**关掉写端**（半关闭）
        a_client.write_all(b"hello").await.unwrap();
        a_client.shutdown().await.unwrap();

        // b 侧应当收到那句话，并读到 EOF
        let mut got = Vec::new();
        b_client.read_to_end(&mut got).await.unwrap();
        assert_eq!(got, b"hello", "b 侧必须收到完整数据");

        // b 侧也关掉写端，让反向也结束
        b_client.shutdown().await.unwrap();

        // 关键断言：转发必须在超时内返回，而不是挂住
        let r = tokio::time::timeout(std::time::Duration::from_secs(2), relay)
            .await
            .expect("限流转发在半关闭后必须返回（否则工作连接泄漏）")
            .expect("任务不应 panic");
        let (up, _down) = r.expect("转发不应报错");
        assert_eq!(up, 5, "正向应当搬运 5 字节");
    }

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

    #[test]
    fn 总开关关闭时敲门与限流都不生效() {
        use nfrp_common::nlink::knock::KnockRule;
        use nfrp_common::nlink::ratelimit::RateLimitRule;

        let mut cfg = ServerConfig::default();
        // 故意把规则都配上，只把 enable 留 false：配置里有不等于会执行。
        cfg.nlink.enable = false;
        cfg.nlink.features = vec!["port-knock".into(), "rate-limit".into()];
        cfg.nlink.knock = vec![KnockRule {
            port: 7000,
            secret: "s".into(),
            window: 10,
        }];
        cfg.nlink.limits = vec![RateLimitRule {
            user: "*".into(),
            proxy: "*".into(),
            rate: 1024,
            burst: 1024,
        }];
        let rt = NLinkRuntime::from_config(&cfg, "t");
        assert!(rt.knock_rule(7000).is_none(), "enable=false 时敲门不得拦截");
        assert!(!rt.rate_limit_enabled(), "enable=false 时限流不得生效");
    }

    #[test]
    fn 能力没协商时对应数据面也不生效() {
        use nfrp_common::nlink::knock::KnockRule;
        use nfrp_common::nlink::ratelimit::RateLimitRule;

        let mut cfg = ServerConfig::default();
        cfg.nlink.enable = true;
        // 只协商 trace：knock / rate-limit 的配置都在，但能力位没开。
        cfg.nlink.features = vec!["trace".into()];
        cfg.nlink.knock = vec![KnockRule {
            port: 7001,
            secret: "s".into(),
            window: 10,
        }];
        cfg.nlink.limits = vec![RateLimitRule {
            user: "*".into(),
            proxy: "*".into(),
            rate: 2048,
            burst: 2048,
        }];
        let rt = NLinkRuntime::from_config(&cfg, "t");
        assert!(rt.knock_rule(7001).is_none());
        assert!(!rt.rate_limit_enabled());

        // 显式协商后同一份配置才生效。
        cfg.nlink.features = vec!["port-knock".into(), "rate-limit".into()];
        let rt = NLinkRuntime::from_config(&cfg, "t");
        assert!(rt.knock_rule(7001).is_some());
        assert!(rt.rate_limit_enabled());
    }
}
