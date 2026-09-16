//! 服务端资源上限：防止单个或多个客户端把进程的连接数 / task 数打爆。
//!
//! frp 服务端是「每连接一个 task」的模型：一个恶意（或写错）的客户端只要不停地
//! 连进来，就能让 frps 的 goroutine / tokio task 数量线性上涨，最后 OOM 或者
//! 把 CPU 全耗在调度上。所以必须有三档闸：
//!
//! * **全局转发连接数**（`max_total_conns`）：跨所有客户端的总量；
//! * **单客户端转发连接数**（`max_conns_per_client`）：防一个客户端吃满；
//! * **单客户端待配对队列**（`max_pending_per_client`）：用户连接排着等工作连接的上限。
//!
//! 三者都用 [`tokio::sync::Semaphore`] 实现：`0` 表示不限制（保持向后兼容的默认行为）。

use std::sync::Arc;

use tokio::sync::{OwnedSemaphorePermit, Semaphore};

/// 拿到手的配额凭证；drop 时自动归还，不需要手动 release。
///
/// 为什么要分两种：**不能**用 `Option<OwnedSemaphorePermit>` 表示"没限制"，
/// 因为上层看到 `None` 会理解成"被拒绝了"，于是把不限流的服务端
/// 变成谁都连不上。没启用上限时必须返回一个真的、但什么都不做的凭证。
pub enum Permit {
    /// 未启用上限，无需归还（保持 API 一致，避免调用方到处写 if）。
    Unlimited,
    /// 真的占到了一个名额，drop 时归还。
    Counted(OwnedSemaphorePermit),
}

/// 把「0 = 不限」翻译成可用于比较的数值。
pub fn unbounded(max: usize) -> usize {
    if max == 0 {
        usize::MAX
    } else {
        max
    }
}

/// 一个可选的信号量上限。
///
/// `max == 0` 时内部为 `None`，任何获取都立即成功、零开销，
/// 这样不限制的场景（默认配置）不会白白付出同步代价。
#[derive(Clone, Debug)]
pub struct Limit {
    inner: Option<Arc<Semaphore>>,
    max: usize,
}

impl Limit {
    /// 构造一个上限；`max == 0` 表示不限制。
    pub fn new(max: usize) -> Self {
        let inner = (max > 0).then(|| Arc::new(Semaphore::new(max)));
        Self { inner, max }
    }

    /// 不限制的 [`Limit`]（默认值）。
    pub fn unlimited() -> Self {
        Self::new(0)
    }

    /// 是否真的启用了限制。
    pub fn is_enabled(&self) -> bool {
        self.inner.is_some()
    }

    /// 配置里的原始上限（`0` = 不限）。
    pub fn max(&self) -> usize {
        self.max
    }

    /// 非阻塞取一个令牌；返回 `None` 表示**已达上限**。
    ///
    /// 限流的语义必须是非阻塞的：连接路径上的任何等待都会变成
    /// 「攻击者慢慢耗，服务端一直挂着连接」的另一种打法。
    pub fn try_acquire(&self) -> Option<Permit> {
        match &self.inner {
            None => Some(Permit::Unlimited),
            Some(sem) => Arc::clone(sem)
                .try_acquire_owned()
                .ok()
                .map(Permit::Counted),
        }
    }

    /// 当前剩余配额；未启用限制时返回 `usize::MAX`。
    pub fn available(&self) -> usize {
        match &self.inner {
            Some(s) => s.available_permits(),
            None => usize::MAX,
        }
    }

    /// 已占用的配额数。
    pub fn used(&self) -> usize {
        match &self.inner {
            Some(s) => self.max.saturating_sub(s.available_permits()),
            None => 0,
        }
    }
}

impl Default for Limit {
    fn default() -> Self {
        Self::unlimited()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unlimited_never_blocks() {
        let l = Limit::unlimited();
        assert!(!l.is_enabled());
        assert_eq!(l.max(), 0);
        assert_eq!(l.available(), usize::MAX);
        // 连续取一万次也必须成功 —— 不限就是真的不限
        assert_eq!(
            (0..10_000).filter(|_| l.try_acquire().is_some()).count(),
            10_000
        );
    }

    #[tokio::test]
    async fn limited_rejects_overflow_and_recovers_on_drop() {
        let l = Limit::new(2);
        assert!(l.is_enabled());
        assert_eq!(l.available(), 2);

        let a = l.try_acquire().expect("第 1 个令牌");
        let b = l.try_acquire().expect("第 2 个令牌");
        assert_eq!(l.available(), 0);
        assert_eq!(l.used(), 2);
        // 第 3 个必须被拒绝（这才是限流的意义）
        assert!(l.try_acquire().is_none());

        drop(a);
        assert_eq!(l.available(), 1, "drop 后必须立刻归还");
        let c = l.try_acquire().expect("归还后应能再取");
        assert!(l.try_acquire().is_none());
        drop(b);
        drop(c);
        assert_eq!(l.available(), 2);
    }

    #[test]
    fn unbounded_helper_translates_zero() {
        assert_eq!(unbounded(0), usize::MAX);
        assert_eq!(unbounded(7), 7);
    }

    #[test]
    fn limit_is_cheap_to_clone_and_shares_state() {
        let l = Limit::new(1);
        let twin = l.clone();
        let keep = l.try_acquire().expect("先占住唯一配额");
        assert!(twin.try_acquire().is_none(), "clone 必须共享同一个信号量");
        drop(keep);
        assert!(twin.try_acquire().is_some());
    }
}
