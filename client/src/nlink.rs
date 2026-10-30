//! 客户端侧的 NLink 运行期状态。
//!
//! 一个进程只有一份：`ConnectionId` 在进程整个生命周期内不变（断线续传要它），
//! 协商出来的身份令牌也在这里，工作连接建立时从这里取。
//!
//! # 自动回退
//!
//! 回退的目标是「用户无感」。具体约定：
//!
//! * 第一次连接尝试带 preamble；
//! * 如果**握手阶段**就失败（典型场景：对端是官方 frps，它把 `NFRPLNK1`
//!   当成 v1 消息头，直接报错断开），立刻用**标准模式**重试一次；
//! * 回退只发生一次：`fallback` 标记置位后，本次进程不再尝试 preamble，
//!   避免每一轮重连都多花一次握手；
//! * 回退不会静默：日志里有明确的一行，面板也能看到能力位为空。

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, OnceLock};

use nfrp_common::config::ClientConfig;
use nfrp_common::nlink::frame::{Preamble, TAG_TRACE_ID};
use nfrp_common::nlink::session::{ConnectionId, TraceId};
use nfrp_common::nlink::{
    Caps, FeatureSet, CAP_BATCH_WORK, CAP_QUIC, CAP_QUIC_MIGRATION, CAP_RESUME, CAP_TRACE,
    FLAG_QUIC, FLAG_RESUME,
};

/// 客户端 NLink 状态。
#[derive(Debug)]
pub struct ClientNLink {
    /// 进程级 connection id（续传 / QUIC 迁移共用）。
    pub session: ConnectionId,
    /// 本次进程的 trace id。
    pub trace: TraceId,
    /// 编译期实现 ∩ 运行期开启。
    pub features: FeatureSet,
    /// 总开关（配置里的 `nlink.enable`）。
    pub enabled: bool,
    /// 想要续传（`nlink.resume`）。
    pub resume: bool,
    /// 想走 QUIC（`nlink.quic`）。
    pub quic: bool,
    /// 服务端下发的身份令牌（工作连接建立时出示）。
    identity: Mutex<Option<String>>,
    /// 是否已经因为对端不支持而回退到标准模式。
    fallback: AtomicBool,
}

impl ClientNLink {
    pub fn from_config(cfg: &ClientConfig) -> Self {
        let n = &cfg.nlink;
        let mut enabled = n.features();
        // 便利开关：写了 `resume = true` / `batch_work_conn = N` / `quic = true`
        // 却没在 `features` 里列对应能力时，隐式打开它对应的位。
        // 这样配置不会因为"少写一个名字"而静默不生效。
        let mut bits = enabled.enabled.bits();
        if n.resume {
            bits |= CAP_RESUME;
        }
        if n.batch_work_conn > 0 {
            bits |= CAP_BATCH_WORK;
        }
        if n.quic {
            bits |= CAP_QUIC | CAP_QUIC_MIGRATION;
        }
        bits |= CAP_TRACE; // trace 始终可用：它只是搭车一个 id
        enabled.enabled = Caps::new(bits);

        Self {
            session: ConnectionId::random(),
            trace: TraceId::random(),
            features: enabled,
            enabled: n.enable,
            resume: n.resume,
            quic: n.quic,
            identity: Mutex::new(None),
            fallback: AtomicBool::new(false),
        }
    }

    /// 全部关闭的实例（`[nlink]` 没写时用）。
    pub fn disabled() -> Self {
        Self {
            session: ConnectionId::random(),
            trace: TraceId::random(),
            features: FeatureSet::default(),
            enabled: false,
            resume: false,
            quic: false,
            identity: Mutex::new(None),
            fallback: AtomicBool::new(true),
        }
    }

    /// 这次连接要不要带 preamble。
    pub fn want_preamble(&self) -> bool {
        self.enabled && !self.fallback.load(Ordering::Relaxed) && self.features.active().any()
    }

    pub fn preamble(&self) -> Option<Preamble> {
        if !self.want_preamble() {
            return None;
        }
        let mut pre = Preamble::new(self.features.active(), self.session);
        if self.resume {
            pre.flags |= FLAG_RESUME;
        }
        if self.quic {
            pre.flags |= FLAG_QUIC;
        }
        pre.tlvs.push(TAG_TRACE_ID, self.trace.as_bytes().to_vec());
        Some(pre)
    }

    /// 标记"对端不支持"，之后不再尝试。
    pub fn mark_fallback(&self) {
        self.fallback.store(true, Ordering::Relaxed);
    }

    #[cfg(test)]
    pub fn fell_back(&self) -> bool {
        self.fallback.load(Ordering::Relaxed)
    }

    pub fn set_identity(&self, token: String) {
        *self.identity.lock().unwrap_or_else(|e| e.into_inner()) = Some(token);
    }

    pub fn identity(&self) -> Option<String> {
        self.identity
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }
}

/// 进程级单例。
///
/// 为什么需要：`web.rs`（本地管理界面）在建工作连接时也要拿身份令牌，
/// 但它只拿到若干零散参数，没有 `run_session` 的局部变量。用一个
/// `OnceLock` 比把 `Arc<ClientNLink>` 穿过五层调用干净得多 ——
/// 而且 connection id 本来就该是**进程级**的（续传要跨会话稳定）。
static GLOBAL: OnceLock<Arc<ClientNLink>> = OnceLock::new();

/// 安装（幂等）并返回进程级实例。`run_session` 每次重连都会调，
/// 但只有第一次真正构造 —— 后面拿到的还是同一个 session id。
pub fn install(cfg: &ClientConfig) -> Arc<ClientNLink> {
    GLOBAL
        .get_or_init(|| Arc::new(ClientNLink::from_config(cfg)))
        .clone()
}

/// 取进程级实例；没安装过时返回"全关"的临时实例（测试 / 特殊入口）。
pub fn current() -> Arc<ClientNLink> {
    GLOBAL
        .get()
        .cloned()
        .unwrap_or_else(|| Arc::new(ClientNLink::disabled()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn enabled_cfg() -> ClientConfig {
        let mut cfg = ClientConfig::default();
        cfg.nlink.enable = true;
        cfg.nlink.features = vec!["trace".into()];
        cfg
    }

    #[test]
    fn 默认配置不产生_preamble() {
        let n = ClientNLink::from_config(&ClientConfig::default());
        assert!(!n.enabled);
        assert!(n.preamble().is_none());
    }

    #[test]
    fn 打开后_preamble_带_trace_id() {
        let n = ClientNLink::from_config(&enabled_cfg());
        let pre = n.preamble().expect("应当产生 preamble");
        assert!(pre.enabled());
        assert_eq!(
            pre.tlvs.get(TAG_TRACE_ID).map(|v| v.len()),
            Some(16),
            "trace id 必须搭在 preamble 里"
        );
        assert_eq!(pre.session, n.session);
    }

    #[test]
    fn 便利开关会自动补上能力位() {
        let mut cfg = ClientConfig::default();
        cfg.nlink.enable = true;
        cfg.nlink.resume = true;
        cfg.nlink.batch_work_conn = 8;
        let n = ClientNLink::from_config(&cfg);
        let caps = n.features.active();
        assert!(caps.contains(CAP_RESUME));
        assert!(caps.contains(CAP_BATCH_WORK));
        let pre = n.preamble().unwrap();
        assert!(pre.wants_resume());
    }

    #[test]
    fn 回退之后不再带_preamble() {
        let n = ClientNLink::from_config(&enabled_cfg());
        assert!(n.want_preamble());
        n.mark_fallback();
        assert!(!n.want_preamble());
        assert!(n.preamble().is_none());
        assert!(n.fell_back());
    }

    #[test]
    fn 身份令牌可以存取() {
        let n = ClientNLink::from_config(&enabled_cfg());
        assert!(n.identity().is_none());
        n.set_identity("v1.1.abc".into());
        assert_eq!(n.identity().as_deref(), Some("v1.1.abc"));
    }

    #[test]
    fn quic_开关会补上两个能力位() {
        let mut cfg = ClientConfig::default();
        cfg.nlink.enable = true;
        cfg.nlink.quic = true;
        let n = ClientNLink::from_config(&cfg);
        let caps = n.features.active();
        assert!(caps.contains(CAP_QUIC));
        assert!(caps.contains(CAP_QUIC_MIGRATION));
        assert!(n.preamble().unwrap().wants_quic());
    }
}
