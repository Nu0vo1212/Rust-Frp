//! 会话标识、trace id、零信任身份令牌、断线续传状态。

use std::collections::HashMap;
use std::fmt;
use std::sync::Mutex;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::{bail, Result};
use hmac::{Hmac, Mac};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

// ---------------------------------------------------------------------------
// connection id
// ---------------------------------------------------------------------------

/// 16 字节连接标识。
///
/// 它与四元组**解耦**：客户端进程生成一次，之后所有重连都带同一个值。
/// 这是"断线续传"（服务端保留代理状态）与"QUIC 连接迁移"（连接地址变了但
/// 逻辑连接没变）的共同基础。
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct ConnectionId([u8; 16]);

impl ConnectionId {
    pub fn random() -> Self {
        use rand::RngCore;
        let mut b = [0u8; 16];
        rand::thread_rng().fill_bytes(&mut b);
        // 版本位：与 UUIDv4 同样的布局，方便人眼识别"这是随机 id"
        b[6] = (b[6] & 0x0f) | 0x40;
        b[8] = (b[8] & 0x3f) | 0x80;
        Self(b)
    }

    pub fn from_bytes(b: [u8; 16]) -> Self {
        Self(b)
    }

    pub fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }

    pub fn to_hex(self) -> String {
        self.0.iter().map(|b| format!("{b:02x}")).collect()
    }
}

impl fmt::Display for ConnectionId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_hex())
    }
}

// ---------------------------------------------------------------------------
// trace id
// ---------------------------------------------------------------------------

/// 端到端 trace id。控制连接、工作连接、日志、扩展帧共用同一个值。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct TraceId([u8; 16]);

impl TraceId {
    pub fn random() -> Self {
        Self(ConnectionId::random().0)
    }

    pub fn from_bytes(b: [u8; 16]) -> Self {
        Self(b)
    }

    pub fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }

    pub fn to_hex(self) -> String {
        self.0.iter().map(|b| format!("{b:02x}")).collect()
    }

    /// 从字符串解析（32 位十六进制）。接受带 `-` 的 UUID 写法。
    pub fn parse(s: &str) -> Option<Self> {
        let clean: String = s.chars().filter(|c| *c != '-').collect();
        if clean.len() != 32 {
            return None;
        }
        let mut out = [0u8; 16];
        for i in 0..16 {
            out[i] = u8::from_str_radix(&clean[i * 2..i * 2 + 2], 16).ok()?;
        }
        Some(Self(out))
    }
}

impl fmt::Display for TraceId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_hex())
    }
}

// ---------------------------------------------------------------------------
// 零信任身份令牌
// ---------------------------------------------------------------------------

/// 身份令牌的签名密钥。
///
/// 从服务端 token（或 OIDC 的 client secret）派生，不额外引入新的配置项：
/// 换了 token 就等于吊销了所有旧令牌。派生用 `sha256("nlink-identity|" + token)`，
/// 与 frp 控制通道的密钥派生（HKDF / PBKDF2）**分开域**，避免同一份密钥
/// 在两种用途之间复用。
#[derive(Clone)]
pub struct IdentityKey([u8; 32]);

impl fmt::Debug for IdentityKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // 密钥不进日志：与项目里其它凭据类型的处理保持一致。
        f.write_str("IdentityKey(<redacted>)")
    }
}

impl IdentityKey {
    pub fn derive(secret: &str) -> Self {
        use sha2::Digest;
        let mut h = Sha256::new();
        h.update(b"nlink-identity|");
        h.update(secret.as_bytes());
        let out = h.finalize();
        let mut key = [0u8; 32];
        key.copy_from_slice(&out);
        Self(key)
    }

    fn mac(&self, msg: &[u8]) -> [u8; 32] {
        let mut m = HmacSha256::new_from_slice(&self.0).expect("HMAC 支持任意长度密钥");
        m.update(msg);
        m.finalize().into_bytes().into()
    }

    /// 签发：`v1.<过期秒>.<64 位十六进制>`。
    ///
    /// 令牌绑定 `run_id + user + 过期时间`，所以：
    /// * 换客户端 / 换用户 → 旧令牌立即失效；
    /// * 过期 → 失效（默认 300 秒，够一次重连 + 一批工作连接）。
    pub fn issue(&self, run_id: &str, user: &str, ttl: Duration, now: SystemTime) -> String {
        let exp = now
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
            + ttl.as_secs().max(1);
        let mac = self.mac(&identity_message(run_id, user, exp));
        format!("v1.{exp}.{}", hex(&mac))
    }

    /// 校验。
    pub fn verify(
        &self,
        token: &str,
        run_id: &str,
        user: &str,
        now: SystemTime,
    ) -> Result<()> {
        let mut it = token.split('.');
        let (Some("v1"), Some(exp), Some(sig), None) =
            (it.next(), it.next(), it.next(), it.next())
        else {
            bail!("身份令牌格式不对");
        };
        let exp: u64 = exp.parse().map_err(|_| anyhow::anyhow!("身份令牌过期时间不是数字"))?;
        let now_secs = now.duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
        // 允许 30 秒时钟回拨，不放宽过期。
        if now_secs > exp + 30 {
            bail!("身份令牌已过期");
        }
        let want = self.mac(&identity_message(run_id, user, exp));
        let got = unhex(sig).ok_or_else(|| anyhow::anyhow!("身份令牌签名不是十六进制"))?;
        // 常量时间比较
        if got.len() != want.len() {
            bail!("身份令牌签名长度不对");
        }
        let mut diff = 0u8;
        for (a, b) in got.iter().zip(want.iter()) {
            diff |= a ^ b;
        }
        if diff != 0 {
            bail!("身份令牌签名不匹配");
        }
        Ok(())
    }
}

fn identity_message(run_id: &str, user: &str, exp: u64) -> Vec<u8> {
    let mut v = Vec::with_capacity(run_id.len() + user.len() + 32);
    v.extend_from_slice(b"nlink-identity-v1\0");
    v.extend_from_slice(run_id.as_bytes());
    v.push(0);
    v.extend_from_slice(user.as_bytes());
    v.push(0);
    v.extend_from_slice(&exp.to_be_bytes());
    v
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn unhex(s: &str) -> Option<Vec<u8>> {
    if s.len() % 2 != 0 {
        return None;
    }
    (0..s.len() / 2)
        .map(|i| u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).ok())
        .collect()
}

// ---------------------------------------------------------------------------
// 断线续传状态
// ---------------------------------------------------------------------------

/// 服务端为一次会话保留的状态。
#[derive(Debug, Clone)]
pub struct ResumeEntry {
    pub run_id: String,
    pub user: String,
    pub trace: TraceId,
    /// 已注册的代理全名（只用于日志与自检；真正的监听器在 `ClientState` 里）。
    pub proxies: Vec<String>,
    pub expires_at: Instant,
}

impl ResumeEntry {
    pub fn alive(&self, now: Instant) -> bool {
        now < self.expires_at
    }
}

/// 续传状态的短期存储。
///
/// 只保留 `resume_ttl`（默认 30 秒）—— 足够覆盖"切网 / 地铁进隧道"这类
/// 秒级中断，又不会让状态无限堆积。过期条目在每次 `put` / `take` 时顺带清理。
#[derive(Debug, Default)]
pub struct ResumeRegistry {
    inner: Mutex<HashMap<ConnectionId, ResumeEntry>>,
}

impl ResumeRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn put(&self, id: ConnectionId, mut entry: ResumeEntry, ttl: Duration) {
        let now = Instant::now();
        entry.expires_at = now + ttl;
        let mut g = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        g.retain(|_, v| v.alive(now));
        g.insert(id, entry);
    }

    /// 取走一个仍有效的条目（一次性：续传成功后不应再被第二个连接复用）。
    pub fn take(&self, id: ConnectionId) -> Option<ResumeEntry> {
        let now = Instant::now();
        let mut g = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        g.retain(|_, v| v.alive(now));
        g.remove(&id)
    }

    pub fn len(&self) -> usize {
        let now = Instant::now();
        let mut g = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        g.retain(|_, v| v.alive(now));
        g.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// 清掉过期条目，返回清理数量。
    pub fn sweep(&self) -> usize {
        let now = Instant::now();
        let mut g = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        let before = g.len();
        g.retain(|_, v| v.alive(now));
        before - g.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn connection_id_是随机的且带版本位() {
        let a = ConnectionId::random();
        let b = ConnectionId::random();
        assert_ne!(a, b);
        assert_eq!(a.as_bytes()[6] & 0xf0, 0x40);
        assert_eq!(a.to_hex().len(), 32);
    }

    #[test]
    fn trace_id_可以十六进制往返() {
        let t = TraceId::random();
        assert_eq!(TraceId::parse(&t.to_hex()), Some(t));
        // 带横线的 UUID 写法也要认
        let h = t.to_hex();
        let dashed = format!(
            "{}-{}-{}-{}-{}",
            &h[0..8],
            &h[8..12],
            &h[12..16],
            &h[16..20],
            &h[20..32]
        );
        assert_eq!(TraceId::parse(&dashed), Some(t));
        assert_eq!(TraceId::parse("不是十六进制"), None);
    }

    #[test]
    fn 身份令牌签验往返() {
        let key = IdentityKey::derive("s3cret");
        let now = UNIX_EPOCH + Duration::from_secs(1_700_000_000);
        let tok = key.issue("run-1", "alice", Duration::from_secs(300), now);
        assert!(key.verify(&tok, "run-1", "alice", now).is_ok());
        // 换用户 / 换 run_id 都不认
        assert!(key.verify(&tok, "run-2", "alice", now).is_err());
        assert!(key.verify(&tok, "run-1", "bob", now).is_err());
        // 换密钥不认
        let other = IdentityKey::derive("other");
        assert!(other.verify(&tok, "run-1", "alice", now).is_err());
    }

    #[test]
    fn 身份令牌会过期且篡改必失败() {
        let key = IdentityKey::derive("s3cret");
        let now = UNIX_EPOCH + Duration::from_secs(1_700_000_000);
        let tok = key.issue("r", "u", Duration::from_secs(60), now);
        let later = now + Duration::from_secs(120);
        assert!(key.verify(&tok, "r", "u", later).is_err(), "过期必须拒绝");

        let mut tampered = tok.clone();
        let last = tampered.pop().unwrap();
        tampered.push(if last == 'a' { 'b' } else { 'a' });
        assert!(
            key.verify(&tampered, "r", "u", now).is_err(),
            "改一个字符必须失败"
        );
        assert!(key.verify("v1.1.zz", "r", "u", now).is_err());
        assert!(key.verify("garbage", "r", "u", now).is_err());
    }

    #[test]
    fn 身份密钥不进_debug() {
        let key = IdentityKey::derive("s3cret");
        let s = format!("{key:?}");
        assert!(!s.contains("s3cret"));
        assert!(s.contains("redacted"));
    }

    #[test]
    fn 续传条目过期后取不到() {
        let reg = ResumeRegistry::new();
        let id = ConnectionId::random();
        reg.put(
            id,
            ResumeEntry {
                run_id: "r".into(),
                user: "u".into(),
                trace: TraceId::random(),
                proxies: vec!["u.web".into()],
                expires_at: Instant::now(),
            },
            Duration::from_millis(1),
        );
        std::thread::sleep(Duration::from_millis(5));
        assert!(reg.take(id).is_none());
        assert!(reg.is_empty());
    }

    #[test]
    fn 续传条目只能被取一次() {
        let reg = ResumeRegistry::new();
        let id = ConnectionId::random();
        reg.put(
            id,
            ResumeEntry {
                run_id: "r".into(),
                user: "u".into(),
                trace: TraceId::random(),
                proxies: vec![],
                expires_at: Instant::now(),
            },
            Duration::from_secs(30),
        );
        assert!(reg.take(id).is_some());
        assert!(reg.take(id).is_none(), "同一条续传状态不能被复用两次");
    }
}
