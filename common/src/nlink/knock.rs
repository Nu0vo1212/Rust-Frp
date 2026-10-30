//! 端口敲门：默认不可见，敲门后按 IP 临时放行。
//!
//! # 为什么放在数据面而不是控制连接
//!
//! 敲门的人是**任意外部客户端**（浏览器、ssh、扫描器），它没有我们的控制连接，
//! 不可能用扩展帧。所以敲门必须发生在**被保护的端口本身**上：
//!
//! ```text
//! 普通访问者：  TCP 连上 -> 服务端读 2 秒 -> 没等到敲门序列 -> 立刻断开
//! 敲门者：      TCP 连上 -> 发 33 字节敲门序列 -> 服务端验签 -> 放行该 IP
//!               -> 关掉这条"敲门连接" -> 正式连接在 window 秒内被正常转发
//! ```
//!
//! 对扫描器的表现与"端口关闭"几乎一样（连上就断、没有 banner），但敲门者
//! 不需要预先知道隧道协议。序列里带时间戳与 HMAC，所以：
//!
//! * 重放窗口只有 [`KnockRule::window`] 秒；
//! * 序列绑定来源 IP 和目标端口，换一个 IP 重放无效。

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Mutex;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::{bail, Result};
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

/// 敲门序列的魔术字（9 字节）。
pub const KNOCK_MAGIC: &[u8] = b"NFRPKNOCK";

/// 序列总长：magic(9) + ts(8) + mac(16)。
pub const KNOCK_LEN: usize = KNOCK_MAGIC.len() + 8 + 16;

/// 服务端一条敲门规则。
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct KnockRule {
    /// 需要敲门的代理远端端口。
    pub port: u16,
    /// 共享密钥。为空时该规则**不生效**（避免"配了端口忘了配密钥"变成默认放行）。
    #[serde(default)]
    pub secret: String,
    /// 敲门后放行多少秒；同时也是时间戳允许的偏差。
    #[serde(default = "default_window")]
    pub window: u64,
}

fn default_window() -> u64 {
    30
}

impl KnockRule {
    pub fn effective(&self) -> bool {
        !self.secret.is_empty() && self.window > 0 && self.port > 0
    }
}

/// 生成敲门序列。
pub fn build_knock(secret: &str, ip: IpAddr, port: u16, now: SystemTime) -> Vec<u8> {
    let ts = now.duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
    let mac = knock_mac(secret, ip, port, ts);
    let mut out = Vec::with_capacity(KNOCK_LEN);
    out.extend_from_slice(KNOCK_MAGIC);
    out.extend_from_slice(&ts.to_be_bytes());
    out.extend_from_slice(&mac);
    out
}

fn knock_mac(secret: &str, ip: IpAddr, port: u16, ts: u64) -> [u8; 16] {
    let mut m = HmacSha256::new_from_slice(secret.as_bytes()).expect("HMAC 支持任意长度密钥");
    m.update(b"nlink-knock-v1|");
    m.update(ip.to_string().as_bytes());
    m.update(b"|");
    m.update(port.to_be_bytes().as_slice());
    m.update(b"|");
    m.update(ts.to_be_bytes().as_slice());
    let full = m.finalize().into_bytes();
    let mut out = [0u8; 16];
    out.copy_from_slice(&full[..16]);
    out
}

/// 校验一个敲门序列。
pub fn verify_knock(
    rule: &KnockRule,
    seq: &[u8],
    ip: IpAddr,
    now: SystemTime,
) -> Result<()> {
    if !rule.effective() {
        bail!("敲门规则未启用");
    }
    if seq.len() != KNOCK_LEN {
        bail!("敲门序列长度不对（{}）", seq.len());
    }
    if &seq[..KNOCK_MAGIC.len()] != KNOCK_MAGIC {
        bail!("敲门序列魔术字不对");
    }
    let mut ts_b = [0u8; 8];
    ts_b.copy_from_slice(&seq[9..17]);
    let ts = u64::from_be_bytes(ts_b);
    let now_secs = now.duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
    if now_secs.abs_diff(ts) > rule.window {
        bail!("敲门序列已过期（偏差 {} 秒）", now_secs.abs_diff(ts));
    }
    let want = knock_mac(&rule.secret, ip, rule.port, ts);
    let got = &seq[17..33];
    let mut diff = 0u8;
    for (a, b) in got.iter().zip(want.iter()) {
        diff |= a ^ b;
    }
    if diff != 0 {
        bail!("敲门序列签名不匹配");
    }
    Ok(())
}

/// 放行表：来源 IP -> 到期时刻。
///
/// 只在内存里，进程重启即失效（敲门本来就是"临时"的，持久化反而危险）。
#[derive(Debug, Default)]
pub struct KnockAuthorizer {
    inner: Mutex<HashMap<(IpAddr, u16), Instant>>,
}

impl KnockAuthorizer {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn allow(&self, ip: IpAddr, port: u16, window: Duration) {
        let mut g = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        let now = Instant::now();
        g.retain(|_, exp| *exp > now);
        g.insert((ip, port), now + window);
    }

    pub fn is_allowed(&self, ip: IpAddr, port: u16) -> bool {
        let now = Instant::now();
        let mut g = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        g.retain(|_, exp| *exp > now);
        g.contains_key(&(ip, port))
    }

    pub fn revoke(&self, ip: IpAddr, port: u16) {
        let mut g = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        g.remove(&(ip, port));
    }

    pub fn len(&self) -> usize {
        let now = Instant::now();
        let mut g = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        g.retain(|_, exp| *exp > now);
        g.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn rule() -> KnockRule {
        KnockRule {
            port: 7001,
            secret: "knock-secret".into(),
            window: 30,
        }
    }

    #[test]
    fn 正确序列可以通过() {
        let now = UNIX_EPOCH + Duration::from_secs(1_700_000_000);
        let ip = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7));
        let seq = build_knock("knock-secret", ip, 7001, now);
        assert_eq!(seq.len(), KNOCK_LEN);
        assert!(verify_knock(&rule(), &seq, ip, now).is_ok());
    }

    #[test]
    fn 换_ip_或换端口都不认() {
        let now = UNIX_EPOCH + Duration::from_secs(1_700_000_000);
        let ip = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7));
        let seq = build_knock("knock-secret", ip, 7001, now);
        let other_ip = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 8));
        assert!(verify_knock(&rule(), &seq, other_ip, now).is_err());

        let mut other_port = rule();
        other_port.port = 7002;
        assert!(verify_knock(&other_port, &seq, ip, now).is_err());
    }

    #[test]
    fn 序列过了窗口就失效() {
        let now = UNIX_EPOCH + Duration::from_secs(1_700_000_000);
        let ip = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 1));
        let seq = build_knock("knock-secret", ip, 7001, now);
        let later = now + Duration::from_secs(31);
        assert!(verify_knock(&rule(), &seq, ip, later).is_err());
        // 反向偏差同样拒绝
        let earlier = now - Duration::from_secs(31);
        assert!(verify_knock(&rule(), &seq, ip, earlier).is_err());
    }

    #[test]
    fn 篡改与坏序列都拒绝() {
        let now = UNIX_EPOCH + Duration::from_secs(1_700_000_000);
        let ip = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 2));
        let mut seq = build_knock("knock-secret", ip, 7001, now);
        seq[20] ^= 0xff;
        assert!(verify_knock(&rule(), &seq, ip, now).is_err());

        assert!(verify_knock(&rule(), b"short", ip, now).is_err());
        assert!(verify_knock(&rule(), &[0u8; KNOCK_LEN], ip, now).is_err());
    }

    #[test]
    fn 空密钥的规则一律不生效() {
        let now = UNIX_EPOCH + Duration::from_secs(1_700_000_000);
        let ip = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 3));
        let mut r = rule();
        r.secret.clear();
        let seq = build_knock("", ip, 7001, now);
        assert!(
            verify_knock(&r, &seq, ip, now).is_err(),
            "空密钥必须拒绝，不能变成『不填密钥就放行』"
        );
    }

    #[test]
    fn 放行表按_ip_和端口隔离() {
        let a = KnockAuthorizer::new();
        let ip = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1));
        a.allow(ip, 7001, Duration::from_secs(10));
        assert!(a.is_allowed(ip, 7001));
        assert!(!a.is_allowed(ip, 7002));
        a.revoke(ip, 7001);
        assert!(!a.is_allowed(ip, 7001));
    }

    #[test]
    fn 放行会过期() {
        let a = KnockAuthorizer::new();
        let ip = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 2));
        a.allow(ip, 7001, Duration::from_millis(1));
        std::thread::sleep(Duration::from_millis(5));
        assert!(!a.is_allowed(ip, 7001));
    }
}
