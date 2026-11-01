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
        let exp =
            now.duration_since(UNIX_EPOCH).unwrap_or_default().as_secs() + ttl.as_secs().max(1);
        let mac = self.mac(&identity_message(run_id, user, exp));
        format!("v1.{exp}.{}", hex(&mac))
    }

    /// 校验。
    pub fn verify(&self, token: &str, run_id: &str, user: &str, now: SystemTime) -> Result<()> {
        let mut it = token.split('.');
        let (Some("v1"), Some(exp), Some(sig), None) = (it.next(), it.next(), it.next(), it.next())
        else {
            bail!("身份令牌格式不对");
        };
        let exp: u64 = exp
            .parse()
            .map_err(|_| anyhow::anyhow!("身份令牌过期时间不是数字"))?;
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
// 一次性续传令牌
// ---------------------------------------------------------------------------

/// 续传令牌的签名密钥。
///
/// # 为什么续传需要一次性令牌
///
/// 0.7.1 及以前，续传的身份凭据是 `user + client_id + session_id` 三元组。
/// 那是**长期有效的会话标识**，不是凭证：`session_id` 一旦泄露（明文链路上的
/// 观察者就能看到 preamble），持有者可以抢在原客户端之前完成续传，
/// 占住原会话的代理与端口。
///
/// 这里引入一次性令牌：
///
/// * 服务端在**登录成功时**签发（那时连接还在，能发得出去），写入 `ResumeResp`；
/// * 令牌用 HMAC 绑定 `session + user + client_id + 过期 + nonce`，
///   所以拿到 `session_id` 也伪造不出；
/// * 重连时客户端在 preamble TLV 里带回，服务端验证后**立即消费**；
/// * 被抢先使用 ⇒ 真客户端再来时令牌已失效，会明确失败并告警 ——
///   攻击从"静默成功"变成"可检测"。
///
/// **注意：这不是 TLS 的替代品。** 明文链路上观察者仍能直接抄走令牌并抢先消费，
/// 只是能检测到。根治中间人仍然需要 `transport.tls.force = true`。
#[derive(Clone)]
pub struct ResumeKey([u8; 32]);

impl fmt::Debug for ResumeKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // 密钥不进日志
        f.write_str("ResumeKey(<redacted>)")
    }
}

impl ResumeKey {
    pub fn derive(secret: &str) -> Self {
        use sha2::Digest;
        let mut h = Sha256::new();
        // 与 identity 的派生前缀不同，避免两种令牌共用密钥材料
        h.update(b"nlink-resume|");
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

    /// 签发：`r1.<过期秒>.<nonce 十六进制>.<签名十六进制>`。
    ///
    /// `nonce` 让每次签发的令牌都不同 —— 即使同一会话重复签，旧令牌也不会
    /// 因为"签名相同"而被误判成新令牌。
    pub fn issue(
        &self,
        session: ConnectionId,
        user: &str,
        client_id: &str,
        ttl: Duration,
        now: SystemTime,
    ) -> String {
        let exp =
            now.duration_since(UNIX_EPOCH).unwrap_or_default().as_secs() + ttl.as_secs().max(1);
        let mut nonce = [0u8; 16];
        {
            use rand::RngCore;
            rand::thread_rng().fill_bytes(&mut nonce);
        }
        let sig = self.mac(&resume_message(session, user, client_id, exp, &nonce));
        format!("r1.{exp}.{}.{}", hex(&nonce), hex(&sig))
    }

    /// 校验令牌。
    ///
    /// 只做**签名与过期**校验；"是否已被消费"由调用方的待用表负责——
    /// 因为消费必须是原子的（校验 + 删除一步完成），放在这里会拆成两步。
    pub fn verify(
        &self,
        token: &str,
        session: ConnectionId,
        user: &str,
        client_id: &str,
        now: SystemTime,
    ) -> Result<()> {
        let mut it = token.split('.');
        let (Some("r1"), Some(exp), Some(nonce_hex), Some(sig), None) =
            (it.next(), it.next(), it.next(), it.next(), it.next())
        else {
            bail!("续传令牌格式不对");
        };
        let exp: u64 = exp
            .parse()
            .map_err(|_| anyhow::anyhow!("续传令牌过期时间不是数字"))?;
        let now_secs = now.duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
        // 允许 30 秒时钟回拨，但不放宽过期
        if now_secs > exp + 30 {
            bail!("续传令牌已过期");
        }
        let nonce =
            unhex(nonce_hex).ok_or_else(|| anyhow::anyhow!("续传令牌 nonce 不是十六进制"))?;
        if nonce.len() != 16 {
            bail!("续传令牌 nonce 长度不对");
        }
        let mut n = [0u8; 16];
        n.copy_from_slice(&nonce);
        let want = self.mac(&resume_message(session, user, client_id, exp, &n));
        let got = unhex(sig).ok_or_else(|| anyhow::anyhow!("续传令牌签名不是十六进制"))?;
        if got.len() != want.len() {
            bail!("续传令牌签名长度不对");
        }
        // 常量时间比较，避免按字节计时侧信道
        let mut diff = 0u8;
        for (a, b) in got.iter().zip(want.iter()) {
            diff |= a ^ b;
        }
        if diff != 0 {
            bail!("续传令牌签名不匹配");
        }
        Ok(())
    }
}

fn resume_message(
    session: ConnectionId,
    user: &str,
    client_id: &str,
    exp: u64,
    nonce: &[u8; 16],
) -> Vec<u8> {
    let mut v = Vec::with_capacity(64 + user.len() + client_id.len());
    v.extend_from_slice(b"nlink-resume-v1\0");
    v.extend_from_slice(session.as_bytes());
    v.extend_from_slice(&exp.to_be_bytes());
    v.extend_from_slice(nonce);
    v.push(0);
    v.extend_from_slice(user.as_bytes());
    v.push(0);
    v.extend_from_slice(client_id.as_bytes());
    v
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

// ---------------------------------------------------------------------------
// 待用续传令牌表
// ---------------------------------------------------------------------------

/// 一条已签发、尚未被使用的续传令牌。
#[derive(Debug, Clone)]
struct IssuedToken {
    /// 令牌原文（含签名）。用整串做键，消费时直接比对。
    token: String,
    /// 这条令牌属于哪个会话。
    ///
    /// 留着是为了将来排查"令牌串会话"——校验时只用 `token`，但这个字段
    /// 让 Debug 输出能直接看出归属，不至于只剩一个裸签名。
    #[allow(dead_code)]
    session: ConnectionId,
    expires_at: Instant,
}

/// 服务端持有的"已签发待消费"令牌集合。
///
/// # 为什么需要这张表
///
/// 只靠签名校验挡不住重放：令牌一旦泄露，签名依然是有效的。所以签发的每个
/// 令牌都要登记，续传时**校验 + 删除**在同一把锁里完成 —— 用掉一次就没了。
///
/// # 容量保护
///
/// 每个会话只保留**最近一次**签发的令牌（同一 session 重复签发时旧的作废），
/// 所以表大小天然被并发会话数限制，不需要额外的 LRU。过期条目在每次操作时清理。
#[derive(Debug, Default)]
pub struct PendingTokens {
    inner: Mutex<HashMap<ConnectionId, IssuedToken>>,
}

impl PendingTokens {
    pub fn new() -> Self {
        Self::default()
    }

    /// 登记一个新签发的令牌，返回是否登记成功。
    ///
    /// 同一会话重新签发时**覆盖**旧令牌：客户端重连成功后会拿到新令牌，
    /// 旧的自然失效，不需要同时保留两个有效凭证。
    pub fn issue(&self, session: ConnectionId, token: String, ttl: Duration) -> bool {
        let now = Instant::now();
        let mut g = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        g.retain(|_, v| v.expires_at > now);
        g.insert(
            session,
            IssuedToken {
                token,
                session,
                expires_at: now + ttl,
            },
        );
        true
    }

    /// 消费一个令牌：**校验 + 删除在同一个临界区内完成**。
    ///
    /// 返回 `Ok(())` 表示令牌有效且已被消费；之后同一个令牌再来就是失败。
    /// 这是防重放的核心 —— 如果分成"先校验、后删除"两步，两个并发请求
    /// 可能都通过校验。
    pub fn consume(
        &self,
        session: ConnectionId,
        token: &str,
        user: &str,
        client_id: &str,
        key: &ResumeKey,
        now: SystemTime,
    ) -> Result<()> {
        let mut g = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        let inst = Instant::now();
        let Some(entry) = g.get(&session) else {
            bail!("该会话没有待用的续传令牌（未签发或已被使用）");
        };
        if entry.expires_at <= inst {
            g.remove(&session);
            bail!("续传令牌已过期");
        }
        // 先验签名，再比对原文，最后才删除 —— 任何一步失败都不消费，
        // 否则一个畸形令牌就能把合法客户端的凭证"用掉"。
        key.verify(token, session, user, client_id, now)?;
        if entry.token != token {
            bail!("续传令牌与本次签发的不一致");
        }
        g.remove(&session);
        Ok(())
    }

    pub fn len(&self) -> usize {
        let now = Instant::now();
        let mut g = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        g.retain(|_, v| v.expires_at > now);
        g.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// 清掉过期令牌，返回清理数量。
    pub fn sweep(&self) -> usize {
        let now = Instant::now();
        let mut g = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        let before = g.len();
        g.retain(|_, v| v.expires_at > now);
        before - g.len()
    }

    /// 会话彻底结束（不续传）时丢弃它的令牌。
    pub fn forget(&self, session: ConnectionId) {
        let mut g = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        g.remove(&session);
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

    // ---- 一次性续传令牌 ----

    fn now() -> SystemTime {
        SystemTime::now()
    }

    #[test]
    fn 续传令牌签验往返() {
        let key = ResumeKey::derive("secret");
        let sid = ConnectionId::random();
        let tok = key.issue(sid, "alice", "cid-1", Duration::from_secs(60), now());
        key.verify(&tok, sid, "alice", "cid-1", now())
            .expect("同一组参数应当验得过");
    }

    #[test]
    fn 续传令牌换了任何一项绑定值都失败() {
        let key = ResumeKey::derive("secret");
        let sid = ConnectionId::random();
        let tok = key.issue(sid, "alice", "cid-1", Duration::from_secs(60), now());

        // 换 session
        let other = ConnectionId::random();
        assert!(key.verify(&tok, other, "alice", "cid-1", now()).is_err());
        // 换 user
        assert!(key.verify(&tok, sid, "bob", "cid-1", now()).is_err());
        // 换 client_id
        assert!(key.verify(&tok, sid, "alice", "cid-2", now()).is_err());
        // 篡改签名
        let mut bad = tok.clone();
        bad.pop();
        bad.push(if tok.ends_with('0') { '1' } else { '0' });
        assert!(key.verify(&bad, sid, "alice", "cid-1", now()).is_err());
    }

    #[test]
    fn 续传令牌会过期() {
        let key = ResumeKey::derive("secret");
        let sid = ConnectionId::random();
        let tok = key.issue(sid, "alice", "cid-1", Duration::from_secs(1), now());
        // 用未来的时间去验：远超过期 + 30 秒宽限
        let future = now() + Duration::from_secs(3600);
        assert!(key.verify(&tok, sid, "alice", "cid-1", future).is_err());
    }

    #[test]
    fn 不同密钥签出的令牌互不认() {
        let a = ResumeKey::derive("secret-a");
        let b = ResumeKey::derive("secret-b");
        let sid = ConnectionId::random();
        let tok = a.issue(sid, "u", "c", Duration::from_secs(60), now());
        assert!(b.verify(&tok, sid, "u", "c", now()).is_err());
    }

    #[test]
    fn 续传密钥不进_debug() {
        let k = ResumeKey::derive("super-secret-value");
        let s = format!("{k:?}");
        assert!(
            !s.contains("super-secret-value"),
            "密钥不能出现在 Debug 里：{s}"
        );
    }

    #[test]
    fn 令牌只能用一次() {
        let key = ResumeKey::derive("secret");
        let sid = ConnectionId::random();
        let table = PendingTokens::new();
        let tok = key.issue(sid, "alice", "cid-1", Duration::from_secs(60), now());
        table.issue(sid, tok.clone(), Duration::from_secs(60));

        table
            .consume(sid, &tok, "alice", "cid-1", &key, now())
            .expect("首次应当成功");
        // 第二次：令牌已被消费
        let e = table
            .consume(sid, &tok, "alice", "cid-1", &key, now())
            .unwrap_err();
        assert!(
            format!("{e:#}").contains("已被使用") || format!("{e:#}").contains("没有待用"),
            "第二次必须失败：{e:#}"
        );
    }

    #[test]
    fn 畸形令牌不会消耗合法客户的凭证() {
        let key = ResumeKey::derive("secret");
        let sid = ConnectionId::random();
        let table = PendingTokens::new();
        let good = key.issue(sid, "alice", "cid-1", Duration::from_secs(60), now());
        table.issue(sid, good.clone(), Duration::from_secs(60));

        // 先用一个乱码令牌试图消费
        assert!(table
            .consume(sid, "r1.garbage", "alice", "cid-1", &key, now())
            .is_err());
        // 合法令牌必须仍然可用 —— 校验失败不能消费
        table
            .consume(sid, &good, "alice", "cid-1", &key, now())
            .expect("畸形令牌不该把合法凭证用掉");
    }

    #[test]
    fn 重新签发会覆盖旧令牌() {
        let key = ResumeKey::derive("secret");
        let sid = ConnectionId::random();
        let table = PendingTokens::new();
        let old = key.issue(sid, "alice", "cid-1", Duration::from_secs(60), now());
        table.issue(sid, old.clone(), Duration::from_secs(60));
        let new = key.issue(sid, "alice", "cid-1", Duration::from_secs(60), now());
        table.issue(sid, new.clone(), Duration::from_secs(60));

        // 旧令牌已作废
        assert!(table
            .consume(sid, &old, "alice", "cid-1", &key, now())
            .is_err());
        // 新令牌可用
        table
            .consume(sid, &new, "alice", "cid-1", &key, now())
            .expect("新令牌应当可用");
    }

    #[test]
    fn 没有登记过的令牌不可用() {
        let key = ResumeKey::derive("secret");
        let sid = ConnectionId::random();
        let table = PendingTokens::new();
        // 签名合法，但没登记
        let tok = key.issue(sid, "alice", "cid-1", Duration::from_secs(60), now());
        assert!(table
            .consume(sid, &tok, "alice", "cid-1", &key, now())
            .is_err());
    }

    #[test]
    fn 忘记会话后令牌失效() {
        let key = ResumeKey::derive("secret");
        let sid = ConnectionId::random();
        let table = PendingTokens::new();
        let tok = key.issue(sid, "alice", "cid-1", Duration::from_secs(60), now());
        table.issue(sid, tok.clone(), Duration::from_secs(60));
        table.forget(sid);
        assert!(table.is_empty());
        assert!(table
            .consume(sid, &tok, "alice", "cid-1", &key, now())
            .is_err());
    }
}
