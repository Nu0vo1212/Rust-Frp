//! 细粒度限流：令牌桶，按「用户 + 代理」维度计费。
//!
//! 与官方 `bandwidthLimit` 的区别：
//!
//! * 官方是**每代理一条**的粗粒度上限，且落在一个简单的"每秒清零"计数器上；
//! * 这里是**规则表**（用户 × 代理，支持 `*` 通配），每个键一个独立令牌桶，
//!   支持突发（burst）而不是硬性按秒切断 —— 后者会让大响应体在秒边界上
//!   出现规律性抖动。
//!
//! 计费点在服务端的桥接层（`bridge`），按**实际搬运的字节数**扣令牌，
//! 欠账时桥接任务 `sleep` 等桶回满，而不是丢包。

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

/// 一条限流规则。
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct RateLimitRule {
    /// 代理全名（`user.name`）；`*` 表示任意。
    #[serde(default)]
    pub proxy: String,
    /// 用户；`*` 表示任意。
    #[serde(default)]
    pub user: String,
    /// 速率，字节/秒。0 = 该规则不生效。
    #[serde(default)]
    pub rate: u64,
    /// 突发上限，字节。0 折算成 `rate`（即最多攒 1 秒的量）。
    #[serde(default)]
    pub burst: u64,
}

impl RateLimitRule {
    pub fn effective(&self) -> bool {
        self.rate > 0
    }

    pub fn burst(&self) -> u64 {
        if self.burst > 0 {
            self.burst
        } else {
            self.rate
        }
    }

    fn matches(&self, user: &str, proxy: &str) -> bool {
        let user_ok = self.user.is_empty() || self.user == "*" || self.user == user;
        let proxy_ok = self.proxy.is_empty()
            || self.proxy == "*"
            || self.proxy == proxy
            // 允许只写短名（`web`）匹配全名（`alice.web`）
            || proxy.rsplit('.').next() == Some(self.proxy.as_str());
        user_ok && proxy_ok
    }
}

/// 令牌桶。
#[derive(Debug, Clone)]
pub struct TokenBucket {
    rate: f64,
    burst: f64,
    tokens: f64,
    last: Instant,
}

impl TokenBucket {
    pub fn new(rate: u64, burst: u64, now: Instant) -> Self {
        let burst = burst.max(1) as f64;
        Self {
            rate: rate.max(1) as f64,
            burst,
            tokens: burst,
            last: now,
        }
    }

    /// 申请 `n` 字节的额度。
    ///
    /// 返回需要等待的时间（`ZERO` = 立即放行）。欠账上限压在一个 burst 内，
    /// 避免一个 8 MB 的响应把后续所有流量卡住十几秒。
    pub fn take(&mut self, n: u64, now: Instant) -> Duration {
        let elapsed = now.saturating_duration_since(self.last).as_secs_f64();
        self.last = now;
        self.tokens = (self.tokens + elapsed * self.rate).min(self.burst);
        self.tokens -= n as f64;
        if self.tokens >= 0.0 {
            return Duration::ZERO;
        }
        let wait = (-self.tokens) / self.rate;
        // 欠账不无限累积
        self.tokens = self.tokens.max(-self.burst);
        Duration::from_secs_f64(wait.min(self.burst / self.rate))
    }

    pub fn tokens(&self) -> f64 {
        self.tokens
    }
}

/// 规则表 + 每个键的桶。
#[derive(Debug, Default)]
pub struct RateLimiter {
    rules: Vec<RateLimitRule>,
    buckets: Mutex<HashMap<String, TokenBucket>>,
    /// 统计：累计因限流等待的次数（指标 / 测试用）。
    throttled: std::sync::atomic::AtomicU64,
}

impl RateLimiter {
    pub fn new(rules: Vec<RateLimitRule>) -> Self {
        Self {
            rules: rules.into_iter().filter(|r| r.effective()).collect(),
            ..Default::default()
        }
    }

    pub fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }

    pub fn rules(&self) -> &[RateLimitRule] {
        &self.rules
    }

    pub fn throttled_count(&self) -> u64 {
        self.throttled.load(std::sync::atomic::Ordering::Relaxed)
    }

    /// 命中该用户 + 代理的第一条规则。
    pub fn rule_for(&self, user: &str, proxy: &str) -> Option<&RateLimitRule> {
        self.rules.iter().find(|r| r.matches(user, proxy))
    }

    /// 申请额度，返回需要等待的时间。
    pub fn acquire(&self, user: &str, proxy: &str, n: u64) -> Duration {
        self.acquire_at(user, proxy, n, Instant::now())
    }

    /// 可注入时钟的版本（测试用）。
    pub fn acquire_at(&self, user: &str, proxy: &str, n: u64, now: Instant) -> Duration {
        let Some(rule) = self.rule_for(user, proxy) else {
            return Duration::ZERO;
        };
        let key = format!("{user}\0{proxy}\0{}\0{}", rule.rate, rule.burst());
        let mut g = self.buckets.lock().unwrap_or_else(|e| e.into_inner());
        let bucket = g
            .entry(key)
            .or_insert_with(|| TokenBucket::new(rule.rate, rule.burst(), now));
        let wait = bucket.take(n, now);
        if !wait.is_zero() {
            self.throttled
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }
        wait
    }

    /// 异步版：需要等就 `sleep`。
    pub async fn throttle(&self, user: &str, proxy: &str, n: u64) {
        let wait = self.acquire(user, proxy, n);
        if !wait.is_zero() {
            tokio::time::sleep(wait).await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn t0() -> Instant {
        Instant::now()
    }

    #[test]
    fn 没有规则时不等待() {
        let lim = RateLimiter::new(vec![]);
        assert!(lim.acquire_at("u", "p", 1_000_000, t0()).is_zero());
    }

    #[test]
    fn 突发额度内立即放行超出后要等() {
        let lim = RateLimiter::new(vec![RateLimitRule {
            proxy: "*".into(),
            user: "*".into(),
            rate: 1000,
            burst: 2000,
        }]);
        let now = t0();
        // 桶初始 2000：先拿走 2000，不等待
        assert!(lim.acquire_at("u", "p", 2000, now).is_zero());
        // 再要 1000：需要 1 秒回血
        let wait = lim.acquire_at("u", "p", 1000, now);
        assert!(wait >= Duration::from_millis(900), "实际 {wait:?}");
        assert_eq!(lim.throttled_count(), 1);
    }

    #[test]
    fn 时间推进后额度会恢复() {
        let lim = RateLimiter::new(vec![RateLimitRule {
            proxy: "*".into(),
            user: "*".into(),
            rate: 1000,
            burst: 1000,
        }]);
        let now = t0();
        assert!(lim.acquire_at("u", "p", 1000, now).is_zero());
        let later = now + Duration::from_millis(1500);
        assert!(
            lim.acquire_at("u", "p", 1000, later).is_zero(),
            "1.5 秒后应攒够 1 秒的量"
        );
    }

    #[test]
    fn 规则按用户和代理区分_桶也分开() {
        let lim = RateLimiter::new(vec![RateLimitRule {
            proxy: "web".into(),
            user: "alice".into(),
            rate: 100,
            burst: 100,
        }]);
        let now = t0();
        assert!(lim.acquire_at("alice", "alice.web", 100, now).is_zero());
        // 桶分开：bob 用同名代理不受 alice 的欠账影响
        assert!(lim.acquire_at("bob", "bob.web", 100, now).is_zero());
        // 不同代理也不共享
        assert!(lim.acquire_at("alice", "alice.ssh", 100, now).is_zero());
    }

    #[test]
    fn 通配规则能命中短名() {
        let lim = RateLimiter::new(vec![RateLimitRule {
            proxy: "*".into(),
            user: "*".into(),
            rate: 1,
            burst: 1,
        }]);
        assert!(lim.rule_for("anyone", "anyone.anything").is_some());

        let lim = RateLimiter::new(vec![RateLimitRule {
            proxy: "web".into(),
            user: "".into(),
            rate: 1,
            burst: 1,
        }]);
        assert!(
            lim.rule_for("alice", "alice.web").is_some(),
            "短名应匹配全名"
        );
    }

    #[test]
    fn 零速率规则被忽略() {
        let lim = RateLimiter::new(vec![RateLimitRule {
            proxy: "*".into(),
            user: "*".into(),
            rate: 0,
            burst: 100,
        }]);
        assert!(lim.is_empty());
        assert!(lim.acquire_at("u", "p", 1 << 30, t0()).is_zero());
    }

    #[test]
    fn 欠账不会无限累积() {
        let lim = RateLimiter::new(vec![RateLimitRule {
            proxy: "*".into(),
            user: "*".into(),
            rate: 1000,
            burst: 1000,
        }]);
        let now = t0();
        // 一次要 10 MB：等待时间必须被 burst/rate 钳住（= 1 秒），不是 10000 秒
        let wait = lim.acquire_at("u", "p", 10_000_000, now);
        assert!(wait <= Duration::from_secs(1), "实际 {wait:?}");
    }
}
