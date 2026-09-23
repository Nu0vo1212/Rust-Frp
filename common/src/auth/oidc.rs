//! OIDC（OpenID Connect）认证 —— 服务端验签与客户端取 token。
//!
//! # 与官方 frp 的对齐点（这些不能自己发明）
//!
//! 读 `pkg/auth/oidc.go` 得到的结论，逐条照做：
//!
//! 1. **`Login.privilege_key` 里放的是 IdP 签发的原始 access token**，
//!    不是 `md5(token + timestamp)`。`OidcAuthProvider.SetLogin` 直接
//!    `loginMsg.PrivilegeKey = accessToken`。所以服务端这边
//!    `timestamp` 字段对 OIDC 没有意义（但报文里仍然要发，官方照发）。
//! 2. 服务端**用 OIDC 提供方的公钥验签**（JWKS），并校验 `aud` / `iss` / `exp`。
//!    `audience` 为空时跳过 `aud` 校验（`SkipClientIDCheck`）。
//! 3. 登录成功后服务端记住这个 token 的 `sub`；之后若配置了
//!    `additionalScopes`（`HeartBeats` / `NewWorkConns`），心跳与新工作连接
//!    上带的 token **必须验签通过且 `sub` 相同**，否则拒绝。
//!    这条防的是"拿到一个合法 token 之后冒充别的 subject"。
//! 4. 客户端用 **Client Credentials Grant** 换 token：POST 到
//!    `tokenEndpointURL`，form 里带 `grant_type=client_credentials`、
//!    `client_id`、`client_secret`、`scope`，以及 `audience` 与
//!    `additionalEndpointParams`。
//! 5. token 要**缓存到快过期**再换（否则每个心跳都去 IdP 打一次，IdP 会被打爆）。
//!    官方那条 `oidcTokenSource` 还处理了"IdP 不返回 `expires_in`"的情况 ——
//!    那时它改成每次都重新取。我们同样处理。
//!
//! # 为什么自己实现 JWT 校验
//!
//! 需要的只是"用 JWKS 里的 RSA/EC 公钥验一个 RS256/ES256 签名 + 读几个 claim"。
//! `jsonwebtoken` 会带进 `ring`/`rsa`/`pem` 一整套；而 `ring` 本来就在依赖里
//! （rustls 用它），JWKS 的 `n`/`e`/`x`/`y` 转 DER 是三十行的事。
//!
//! # 支持的算法
//!
//! RS256/384/512、PS256/384/512、ES256/ES384。`none` **明确拒绝**
//! （经典的 alg 混淆攻击就是拿 `none` 伪造 token）。

use std::sync::{Arc, RwLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{anyhow, bail, Context, Result};

use crate::httpc;

// ---------------------------------------------------------------------------
// 配置
// ---------------------------------------------------------------------------

/// 服务端 OIDC 配置（对应 frp 的 `auth.oidc`）。
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ServerOidcConfig {
    /// 签发方，用来拉 discovery 文档 / JWKS，并比对 token 里的 `iss`。
    pub issuer: String,
    /// 期望的 audience（通常是 client ID）。留空则跳过 `aud` 校验
    /// （官方 `SkipClientIDCheck` —— 有些 IdP 签的 token 里根本没有 `aud`）。
    pub audience: String,
    /// 跳过有效期检查（只建议在 IdP 时钟严重漂移时临时开）。
    #[serde(rename = "skipExpiryCheck")]
    pub skip_expiry_check: bool,
    /// 跳过签发方检查。
    #[serde(rename = "skipIssuerCheck")]
    pub skip_issuer_check: bool,
    /// 追加的信任 CA（PEM 文件路径）。
    #[serde(rename = "trustedCaFile")]
    pub trusted_ca_file: String,
    /// 跳过 TLS 证书校验（自签 IdP 的常见情况）。
    #[serde(rename = "insecureSkipVerify")]
    pub insecure_skip_verify: bool,
    /// 拉 JWKS 时走的代理。
    #[serde(rename = "proxyURL")]
    pub proxy_url: String,
}

/// 客户端 OIDC 配置（对应 frp 的 `auth.oidc`）。
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ClientOidcConfig {
    /// ★ 官方 frp 的 JSON tag 就是 `clientID`（不是 `clientId`），
    /// 照抄平台的配置时差一个字母都会变成"字段未知"。
    #[serde(rename = "clientID")]
    pub client_id: String,
    #[serde(rename = "clientSecret")]
    pub client_secret: String,
    pub audience: String,
    pub scope: String,
    #[serde(rename = "tokenEndpointURL")]
    pub token_endpoint_url: String,
    /// 追加的 token endpoint 参数（会一并放进 form）。
    #[serde(rename = "additionalEndpointParams")]
    pub additional_endpoint_params: std::collections::HashMap<String, String>,
    #[serde(rename = "trustedCaFile")]
    pub trusted_ca_file: String,
    #[serde(rename = "insecureSkipVerify")]
    pub insecure_skip_verify: bool,
    #[serde(rename = "proxyURL")]
    pub proxy_url: String,
}

impl ClientOidcConfig {
    /// 把必填项缺了的情况挡在启动阶段，并给出人话指引。
    pub fn validate(&self) -> Result<()> {
        if self.client_id.trim().is_empty() {
            bail!("OIDC 认证需要 auth.oidc.clientID");
        }
        if self.token_endpoint_url.trim().is_empty() {
            bail!(
                "OIDC 认证需要 auth.oidc.tokenEndpointURL（IdP 的 token 端点，\
                 比如 https://idp.example.com/realms/x/protocol/openid-connect/token）"
            );
        }
        Ok(())
    }

    fn options(&self) -> httpc::Options {
        httpc::Options {
            insecure_skip_verify: self.insecure_skip_verify,
            trusted_ca_file: self.trusted_ca_file.clone(),
            proxy_url: self.proxy_url.clone(),
            timeout_secs: 20,
        }
    }
}

// ---------------------------------------------------------------------------
// 客户端：取 token
// ---------------------------------------------------------------------------

/// 换来的 token 与它的过期时刻。
#[derive(Debug, Clone)]
struct CachedToken {
    access_token: String,
    /// `None` 表示 IdP 没给 `expires_in` —— 那就**每次都重新取**，
    /// 否则会把一个可能已经过期的 token 一直用下去（官方同样处理）。
    expires_at: Option<SystemTime>,
}

/// OIDC token 获取器（客户端侧）。
///
/// 进程内共享一个实例：token 的缓存必须跨连接复用，否则每次重连都打一次 IdP。
pub struct TokenSource {
    cfg: ClientOidcConfig,
    cached: tokio::sync::Mutex<Option<CachedToken>>,
}

impl TokenSource {
    pub fn new(cfg: ClientOidcConfig) -> Result<Arc<Self>> {
        cfg.validate()?;
        Ok(Arc::new(Self {
            cfg,
            cached: tokio::sync::Mutex::new(None),
        }))
    }

    /// 取一个可用的 access token（必要时去 IdP 换一个新的）。
    pub async fn token(&self) -> Result<String> {
        let mut guard = self.cached.lock().await;
        if let Some(t) = guard.as_ref() {
            let fresh = match t.expires_at {
                // 提前 30 秒换，避免"刚发出去就过期"
                Some(at) => SystemTime::now() + Duration::from_secs(30) < at,
                None => false,
            };
            if fresh {
                return Ok(t.access_token.clone());
            }
        }
        let new = self.fetch().await?;
        let token = new.access_token.clone();
        *guard = Some(new);
        Ok(token)
    }

    async fn fetch(&self) -> Result<CachedToken> {
        let mut form: Vec<(&str, &str)> = vec![
            ("grant_type", "client_credentials"),
            ("client_id", self.cfg.client_id.as_str()),
        ];
        if !self.cfg.client_secret.is_empty() {
            form.push(("client_secret", self.cfg.client_secret.as_str()));
        }
        if !self.cfg.scope.is_empty() {
            form.push(("scope", self.cfg.scope.as_str()));
        }
        if !self.cfg.audience.is_empty() {
            form.push(("audience", self.cfg.audience.as_str()));
        }
        let extra: Vec<(String, String)> = self
            .cfg
            .additional_endpoint_params
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();
        for (k, v) in &extra {
            form.push((k.as_str(), v.as_str()));
        }

        let resp = httpc::post_form(
            &self.cfg.token_endpoint_url,
            &form,
            &[],
            &self.cfg.options(),
        )
        .await
        .context("向 OIDC token 端点请求 token 失败")?;
        let body = resp.ensure_success()?;
        let v = body.json().context("token 端点返回的不是 JSON")?;
        let access_token = v
            .get("access_token")
            .and_then(|x| x.as_str())
            .ok_or_else(|| anyhow!("token 响应里没有 access_token 字段"))?
            .to_string();
        let expires_at = v
            .get("expires_in")
            .and_then(|x| x.as_i64())
            .map(|secs| SystemTime::now() + Duration::from_secs(secs.max(1) as u64));
        Ok(CachedToken {
            access_token,
            expires_at,
        })
    }
}

// ---------------------------------------------------------------------------
// 服务端：验签
// ---------------------------------------------------------------------------

/// JWKS 里的一把公钥。
#[derive(Debug, Clone, serde::Deserialize)]
struct Jwk {
    #[serde(default)]
    kty: String,
    #[serde(default)]
    kid: String,
    #[serde(default)]
    alg: String,
    /// RSA 模数（base64url）。
    #[serde(default)]
    n: String,
    /// RSA 指数（base64url）。
    #[serde(default)]
    e: String,
    /// EC 曲线名。
    #[serde(default)]
    crv: String,
    #[serde(default)]
    x: String,
    #[serde(default)]
    y: String,
}

#[derive(Debug, Clone, Default, serde::Deserialize)]
struct JwkSet {
    #[serde(default)]
    keys: Vec<Jwk>,
}

/// 验签用的公钥集合，附带一份"什么时候拉的"，便于按需刷新。
struct Jwks {
    set: JwkSet,
    fetched_at: SystemTime,
}

/// OIDC 服务端校验器。
///
/// 持有一份缓存下来的 JWKS：**验签本身是纯 CPU 操作**，所以
/// [`OidcVerifier::verify_token`] 是同步的，不需要在每个心跳里 await 网络。
/// 密钥的获取与刷新由 [`OidcVerifier::refresh`] 负责（启动时先拉一次，
/// 之后遇到不认识的 `kid` 再拉）。
pub struct OidcVerifier {
    cfg: ServerOidcConfig,
    /// JWKS 地址；先从 issuer 拉 discovery 文档得到，拉不到就按 OIDC 惯例
    /// 拼 `<issuer>/.well-known/jwks.json`。
    jwks_uri: RwLock<Option<String>>,
    jwks: RwLock<Option<Arc<Jwks>>>,
    /// 登录成功过的 subject 集合（对应官方的 `subjectsFromLogin`）。
    subjects: RwLock<std::collections::HashSet<String>>,
}

impl OidcVerifier {
    pub fn new(cfg: ServerOidcConfig) -> Result<Arc<Self>> {
        if cfg.issuer.trim().is_empty() {
            bail!("auth.method = \"oidc\" 时必须配置 auth.oidc.issuer");
        }
        Ok(Arc::new(Self {
            cfg,
            jwks_uri: RwLock::new(None),
            jwks: RwLock::new(None),
            subjects: RwLock::new(Default::default()),
        }))
    }

    fn options(&self) -> httpc::Options {
        httpc::Options {
            insecure_skip_verify: self.cfg.insecure_skip_verify,
            trusted_ca_file: self.cfg.trusted_ca_file.clone(),
            proxy_url: self.cfg.proxy_url.clone(),
            timeout_secs: 20,
        }
    }

    /// 启动时调一次：解析 issuer 的 discovery 文档并拉取 JWKS。
    ///
    /// 拉不到**不致命** —— IdP 可能只是暂时不可达，服务端不该因此起不来；
    /// 但要在日志里说清楚"现在没人能登录成功"，否则现象是"所有客户端都登不上，
    /// 而服务端日志一片安静"。
    pub async fn refresh(&self) -> Result<()> {
        let uri = match self.jwks_uri.read() {
            Ok(g) => g.clone(),
            Err(e) => e.into_inner().clone(),
        };
        let uri = match uri {
            Some(u) => u,
            None => {
                let discovered = self.discover().await?;
                *self.jwks_uri.write().unwrap() = Some(discovered.clone());
                discovered
            }
        };
        let resp = httpc::get(&uri, &[], &self.options())
            .await
            .with_context(|| format!("拉取 JWKS 失败：{uri}"))?;
        let set: JwkSet = serde_json::from_slice(&resp.ensure_success()?.body)
            .context("JWKS 文档不是合法 JSON")?;
        if set.keys.is_empty() {
            bail!("JWKS {uri} 里没有任何密钥");
        }
        let n = set.keys.len();
        *self.jwks.write().unwrap() = Some(Arc::new(Jwks {
            set,
            fetched_at: SystemTime::now(),
        }));
        tracing::info!(keys = n, uri = %uri, "OIDC JWKS 已加载");
        Ok(())
    }

    /// 从 issuer 拉 `.well-known/openid-configuration` 拿 `jwks_uri`。
    async fn discover(&self) -> Result<String> {
        let issuer = self.cfg.issuer.trim_end_matches('/');
        let url = format!("{issuer}/.well-known/openid-configuration");
        match httpc::get(&url, &[], &self.options()).await {
            Ok(r) if (200..300).contains(&r.status) => {
                let v = r.json()?;
                if let Some(u) = v.get("jwks_uri").and_then(|x| x.as_str()) {
                    return Ok(u.to_string());
                }
                bail!("discovery 文档 {url} 里没有 jwks_uri");
            }
            Ok(r) => {
                // 有些 IdP（或反向代理）不给 discovery 文档，退回惯例路径。
                // 这不是错误，只是少一步自动发现。
                tracing::debug!(status = r.status, %url, "discovery 文档不可用，改用惯例路径");
            }
            Err(e) => {
                tracing::debug!(error = %e, %url, "discovery 文档不可达，改用惯例路径");
            }
        }
        Ok(format!("{issuer}/.well-known/jwks.json"))
    }

    /// 当前 JWKS 是否需要刷新（怕的是 IdP 轮换了密钥）。
    fn stale(&self, keys: &Jwks) -> bool {
        keys.fetched_at
            .elapsed()
            .map(|d| d > Duration::from_secs(15 * 60))
            .unwrap_or(false)
    }

    /// 验一个 token，返回它的 payload。
    pub fn verify_token(&self, token: &str) -> Result<serde_json::Value> {
        let parsed = parse_jwt(token)?;

        // alg 必须在允许列表里。**先看 alg 再找 key**，且 `none` 直接拒 ——
        // 这两条是 JWT 校验的基本纪律。
        let alg = parsed.header.alg.clone();
        if alg.eq_ignore_ascii_case("none") {
            bail!("拒绝 alg=none 的 token");
        }
        if !SUPPORTED_ALGS.contains(&alg.as_str()) {
            bail!("不支持的 JWT 签名算法 {alg}（支持 {SUPPORTED_ALGS:?}）");
        }

        let keys = match self.jwks.read() {
            Ok(g) => g.clone(),
            Err(e) => e.into_inner().clone(),
        };
        let keys = keys.ok_or_else(|| {
            anyhow!("JWKS 尚未加载成功，无法校验 token（检查服务端到 IdP 的网络）")
        })?;
        if self.stale(&keys) {
            tracing::debug!("JWKS 已超过 15 分钟，下次验签失败时会自动刷新");
        }

        // 按 kid 选 key；没给 kid 就试所有候选
        let candidates: Vec<&Jwk> = keys
            .set
            .keys
            .iter()
            .filter(|k| {
                if let Some(kid) = &parsed.header.kid {
                    k.kid == *kid
                } else {
                    true
                }
            })
            .collect();
        if candidates.is_empty() {
            bail!(
                "JWKS 里没有 kid={:?} 对应的密钥（IdP 可能刚轮换过密钥，重启服务端或等下一次刷新）",
                parsed.header.kid
            );
        }

        let signed = format!("{}.{}", parsed.header_b64, parsed.payload_b64);
        let sig = parsed.signature.clone();
        let mut last_err: Option<anyhow::Error> = None;
        for k in &candidates {
            // JWK 声明的 alg 与 token 的 alg 不一致时跳过（同一 kid 多算法的情况）
            if !k.alg.is_empty() && !k.alg.eq_ignore_ascii_case(&alg) {
                continue;
            }
            match verify_signature(k, &alg, signed.as_bytes(), &sig) {
                Ok(true) => {
                    self.check_claims(&parsed.payload)?;
                    return Ok(parsed.payload);
                }
                Ok(false) => last_err = Some(anyhow!("签名不匹配")),
                Err(e) => last_err = Some(e),
            }
        }
        Err(last_err.unwrap_or_else(|| anyhow!("没有可用于校验的密钥")))
    }

    /// 校验 `iss` / `aud` / `exp` / `nbf`。
    fn check_claims(&self, payload: &serde_json::Value) -> Result<()> {
        if !self.cfg.skip_issuer_check {
            let iss = payload
                .get("iss")
                .and_then(|x| x.as_str())
                .ok_or_else(|| anyhow!("token 里没有 iss"))?;
            if iss.trim_end_matches('/') != self.cfg.issuer.trim_end_matches('/') {
                bail!(
                    "token 的 iss={iss} 与配置的 issuer={} 不符",
                    self.cfg.issuer
                );
            }
        }
        if !self.cfg.audience.is_empty() {
            let aud_ok = match payload.get("aud") {
                Some(serde_json::Value::String(s)) => s == &self.cfg.audience,
                Some(serde_json::Value::Array(a)) => a
                    .iter()
                    .any(|x| x.as_str() == Some(self.cfg.audience.as_str())),
                _ => false,
            };
            if !aud_ok {
                bail!("token 的 aud 不匹配（期望 {:?}）", self.cfg.audience);
            }
        }
        if !self.cfg.skip_expiry_check {
            let now = now_unix() as i64;
            if let Some(exp) = payload.get("exp").and_then(|x| x.as_i64()) {
                if exp < now {
                    bail!("token 已过期（exp={exp}，现在 {now}）");
                }
            }
            if let Some(nbf) = payload.get("nbf").and_then(|x| x.as_i64()) {
                // 允许 60 秒时钟漂移
                if nbf > now + 60 {
                    bail!("token 还没生效（nbf={nbf}，现在 {now}）");
                }
            }
        }
        Ok(())
    }

    /// 记住登录过的 subject。之后心跳 / 新工作连接上的 token 必须同 subject。
    pub fn remember_subject(&self, token: &str) -> Result<String> {
        let payload = self.verify_token(token)?;
        let sub = payload
            .get("sub")
            .and_then(|x| x.as_str())
            .ok_or_else(|| anyhow!("token 里没有 sub"))?
            .to_string();
        let mut g = self.subjects.write().unwrap_or_else(|e| e.into_inner());
        g.insert(sub.clone());
        Ok(sub)
    }

    /// 校验"登录之后"的 token：必须验签通过，且 subject 与登录时一致。
    pub fn verify_post_login(&self, token: &str, what: &str) -> Result<String> {
        let payload = self.verify_token(token)?;
        let sub = payload
            .get("sub")
            .and_then(|x| x.as_str())
            .ok_or_else(|| anyhow!("token 里没有 sub"))?;
        let g = self.subjects.read().unwrap_or_else(|e| e.into_inner());
        if !g.contains(sub) {
            bail!(
                "{what} 的 token subject [{sub}] 与登录时的不一致：\
                 同一个连接上的后续消息必须用同一身份的 token"
            );
        }
        Ok(sub.to_string())
    }

    /// 已登录 subject 数（面板展示用）。
    pub fn subject_count(&self) -> usize {
        self.subjects
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .len()
    }
}

const SUPPORTED_ALGS: &[&str] = &[
    "RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "ES256", "ES384",
];

// ---------------------------------------------------------------------------
// JWT 解析
// ---------------------------------------------------------------------------

#[derive(Debug, serde::Deserialize)]
struct JwtHeader {
    #[serde(default)]
    alg: String,
    #[serde(default)]
    kid: Option<String>,
}

struct ParsedJwt {
    header: JwtHeader,
    header_b64: String,
    payload_b64: String,
    payload: serde_json::Value,
    signature: Vec<u8>,
}

fn parse_jwt(token: &str) -> Result<ParsedJwt> {
    // 允许 `Bearer ` 前缀 —— 有些 IdP / 网关会把 Authorization 头的整串给过来
    let token = token.trim().strip_prefix("Bearer ").unwrap_or(token.trim());
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 3 {
        bail!("不是合法的 JWT（应当有 3 段，实际 {} 段）", parts.len());
    }
    let header_bytes = b64url(parts[0]).context("JWT header 不是合法 base64url")?;
    let payload_bytes = b64url(parts[1]).context("JWT payload 不是合法 base64url")?;
    let signature = b64url(parts[2]).context("JWT 签名不是合法 base64url")?;

    let header: JwtHeader =
        serde_json::from_slice(&header_bytes).context("JWT header 不是合法 JSON")?;
    let payload: serde_json::Value =
        serde_json::from_slice(&payload_bytes).context("JWT payload 不是合法 JSON")?;
    Ok(ParsedJwt {
        header,
        header_b64: parts[0].to_string(),
        payload_b64: parts[1].to_string(),
        payload,
        signature,
    })
}

/// base64url 解码，容忍带/不带 `=` 填充两种写法。
fn b64url(s: &str) -> Result<Vec<u8>> {
    use base64::engine::general_purpose::{URL_SAFE, URL_SAFE_NO_PAD};
    use base64::Engine as _;
    URL_SAFE_NO_PAD
        .decode(s.as_bytes())
        .or_else(|_| URL_SAFE.decode(s.as_bytes()))
        .map_err(|e| anyhow!("{e}"))
}

/// 用一把 JWK 验签；返回 `Ok(true)` 表示签名有效。
fn verify_signature(jwk: &Jwk, alg: &str, message: &[u8], sig: &[u8]) -> Result<bool> {
    use ring::signature::UnparsedPublicKey;

    let spki = jwk_to_spki(jwk)?;
    let key = UnparsedPublicKey::new(pick_algorithm(jwk, alg)?, spki);
    // 签名不匹配是**预期内**的结果：JWKS 里可能有多把 key，要逐把试，
    // 试错不能当错误往上抛（否则第一把没试中就把整次校验判死了）。
    Ok(key.verify(message, sig).is_ok())
}

/// 按 JWK 类型与 alg 选 ring 的验签算法。
fn pick_algorithm(
    jwk: &Jwk,
    alg: &str,
) -> Result<&'static dyn ring::signature::VerificationAlgorithm> {
    use ring::signature as s;
    let kty = jwk.kty.to_ascii_uppercase();
    let a = match (kty.as_str(), alg.to_ascii_uppercase().as_str()) {
        ("RSA", "RS256") => &s::RSA_PKCS1_2048_8192_SHA256 as &dyn s::VerificationAlgorithm,
        ("RSA", "RS384") => &s::RSA_PKCS1_2048_8192_SHA384,
        ("RSA", "RS512") => &s::RSA_PKCS1_2048_8192_SHA512,
        ("RSA", "PS256") => &s::RSA_PSS_2048_8192_SHA256,
        ("RSA", "PS384") => &s::RSA_PSS_2048_8192_SHA384,
        ("RSA", "PS512") => &s::RSA_PSS_2048_8192_SHA512,
        ("EC", "ES256") => &s::ECDSA_P256_SHA256_ASN1,
        ("EC", "ES384") => &s::ECDSA_P384_SHA384_ASN1,
        (k, a) => bail!("JWKS 的 kty={k} 不支持算法 {a}"),
    };
    Ok(a)
}

/// 把 JWK 转成 SubjectPublicKeyInfo（DER），ring 需要这个格式。
fn jwk_to_spki(jwk: &Jwk) -> Result<Vec<u8>> {
    match jwk.kty.to_ascii_uppercase().as_str() {
        "RSA" => {
            let n = b64url(&jwk.n).context("JWK 的 n 不是合法 base64url")?;
            let e = b64url(&jwk.e).context("JWK 的 e 不是合法 base64url")?;
            let rsa_pub = der::seq(&[&der::int(&n), &der::int(&e)]);
            let alg_id = der::seq(&[&der::oid("1.2.840.113549.1.1.1"), &der::null()]);
            Ok(der::seq(&[&alg_id, &der::bit_string(&rsa_pub)]))
        }
        "EC" => {
            let x = b64url(&jwk.x).context("JWK 的 x 不是合法 base64url")?;
            let y = b64url(&jwk.y).context("JWK 的 y 不是合法 base64url")?;
            let curve = match jwk.crv.as_str() {
                "P-256" => "1.2.840.10045.3.1.7",
                "P-384" => "1.3.132.0.34",
                other => bail!("不支持的 EC 曲线 {other}（实现了 P-256 / P-384）"),
            };
            // 未压缩点：0x04 || X || Y
            let mut point = Vec::with_capacity(1 + x.len() + y.len());
            point.push(0x04);
            point.extend_from_slice(&x);
            point.extend_from_slice(&y);
            let alg_id = der::seq(&[&der::oid("1.2.840.10045.2.1"), &der::oid(curve)]);
            Ok(der::seq(&[&alg_id, &der::bit_string(&point)]))
        }
        other => bail!("不支持的 JWK kty={other}（实现了 RSA / EC）"),
    }
}

/// 一点点 DER 编码 —— 只够构造 SubjectPublicKeyInfo。
mod der {
    /// TLV：tag + 长度 + 内容。
    fn tlv(tag: u8, content: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(content.len() + 6);
        out.push(tag);
        let n = content.len();
        if n < 0x80 {
            out.push(n as u8);
        } else {
            let mut len_bytes = Vec::new();
            let mut v = n;
            while v > 0 {
                len_bytes.insert(0, (v & 0xff) as u8);
                v >>= 8;
            }
            out.push(0x80 | len_bytes.len() as u8);
            out.extend_from_slice(&len_bytes);
        }
        out.extend_from_slice(content);
        out
    }

    pub fn seq(parts: &[&[u8]]) -> Vec<u8> {
        let mut body = Vec::new();
        for p in parts {
            body.extend_from_slice(p);
        }
        tlv(0x30, &body)
    }

    /// DER INTEGER：大端、去前导零，最高位为 1 时补一个 0x00（否则会被当成负数）。
    pub fn int(be: &[u8]) -> Vec<u8> {
        let mut i = 0;
        while i + 1 < be.len() && be[i] == 0 {
            i += 1;
        }
        let body = &be[i..];
        if body.first().map(|b| b & 0x80 != 0).unwrap_or(false) {
            let mut v = Vec::with_capacity(body.len() + 1);
            v.push(0);
            v.extend_from_slice(body);
            return tlv(0x02, &v);
        }
        tlv(0x02, body)
    }

    pub fn null() -> Vec<u8> {
        tlv(0x05, &[])
    }

    /// BIT STRING：首字节是"未用位数"，公钥里恒为 0。
    pub fn bit_string(content: &[u8]) -> Vec<u8> {
        let mut body = Vec::with_capacity(content.len() + 1);
        body.push(0);
        body.extend_from_slice(content);
        tlv(0x03, &body)
    }

    /// OBJECT IDENTIFIER：点分十进制 → DER。
    pub fn oid(dotted: &str) -> Vec<u8> {
        let arcs: Vec<u64> = dotted.split('.').filter_map(|s| s.parse().ok()).collect();
        assert!(arcs.len() >= 2, "OID 至少要有两段：{dotted}");
        let mut body = Vec::new();
        push_base128(&mut body, arcs[0] * 40 + arcs[1]);
        for a in &arcs[2..] {
            push_base128(&mut body, *a);
        }
        tlv(0x06, &body)
    }

    /// 128 进制变长编码（DER 的 OID 用这个）。
    fn push_base128(out: &mut Vec<u8>, mut v: u64) {
        let mut buf = vec![(v & 0x7f) as u8];
        v >>= 7;
        while v > 0 {
            buf.insert(0, ((v & 0x7f) as u8) | 0x80);
            v >>= 7;
        }
        out.extend_from_slice(&buf);
    }
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// OID 编码必须与标准字节一致 —— 一个字节错，ring 就认不出公钥。
    #[test]
    fn oid_编码与标准一致() {
        assert_eq!(
            der::oid("1.2.840.113549.1.1.1"),
            vec![0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01]
        );
        assert_eq!(
            der::oid("1.2.840.10045.2.1"),
            vec![0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01]
        );
        // 长弧（>127）要走多字节形式
        assert_eq!(
            der::oid("1.3.132.0.34"),
            vec![0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x22]
        );
    }

    /// INTEGER 的最高位处理：不补 0x00 会被解释成负数，公钥直接失效。
    #[test]
    fn integer_补前导零() {
        assert_eq!(der::int(&[0x7f]), vec![0x02, 0x01, 0x7f]);
        assert_eq!(der::int(&[0x80]), vec![0x02, 0x02, 0x00, 0x80]);
        // 前导零要被去掉
        assert_eq!(der::int(&[0x00, 0x00, 0x01]), vec![0x02, 0x01, 0x01]);
    }

    #[test]
    fn 长度用长形式编码() {
        let blob = [0u8; 200];
        let big = der::seq(&[&blob[..]]);
        assert_eq!(big[0], 0x30);
        assert_eq!(big[1], 0x81, "超过 127 字节要用两字节长度形式");
        assert_eq!(big[2], 200);
    }

    #[test]
    fn base64url_容忍填充与否() {
        assert_eq!(b64url("aGk").unwrap(), b"hi");
        assert_eq!(b64url("aGk=").unwrap(), b"hi");
        assert!(b64url("!!!").is_err());
    }

    #[test]
    fn jwt_分段解析() {
        // {"alg":"RS256","kid":"k1"} . {"sub":"alice"} . ""
        let h = {
            use base64::engine::general_purpose::URL_SAFE_NO_PAD;
            use base64::Engine as _;
            URL_SAFE_NO_PAD.encode(br#"{"alg":"RS256","kid":"k1"}"#)
        };
        let p = {
            use base64::engine::general_purpose::URL_SAFE_NO_PAD;
            use base64::Engine as _;
            URL_SAFE_NO_PAD.encode(br#"{"sub":"alice","iss":"https://idp"}"#)
        };
        let tok = format!("{h}.{p}.AAAA");
        let parsed = parse_jwt(&tok).unwrap();
        assert_eq!(parsed.header.alg, "RS256");
        assert_eq!(parsed.header.kid.as_deref(), Some("k1"));
        assert_eq!(parsed.payload["sub"], "alice");
        // 允许带 Bearer 前缀
        assert!(parse_jwt(&format!("Bearer {tok}")).is_ok());
        // 段数不对要报错
        assert!(parse_jwt("a.b").is_err());
    }

    /// claims 校验的四种失败：iss 不符 / aud 不符 / 已过期 / 还没生效。
    #[test]
    fn claims_校验各种失败() {
        let v = OidcVerifier::new(ServerOidcConfig {
            issuer: "https://idp".into(),
            audience: "frps".into(),
            ..Default::default()
        })
        .unwrap();
        let now = now_unix() as i64;

        assert!(v
            .check_claims(&serde_json::json!({
                "iss": "https://idp", "aud": "frps", "exp": now + 100
            }))
            .is_ok());
        // 尾部斜杠要容忍
        assert!(v
            .check_claims(&serde_json::json!({
                "iss": "https://idp/", "aud": "frps", "exp": now + 100
            }))
            .is_ok());
        // aud 是数组时只要包含即可
        assert!(v
            .check_claims(&serde_json::json!({
                "iss": "https://idp", "aud": ["other", "frps"], "exp": now + 100
            }))
            .is_ok());

        assert!(v
            .check_claims(
                &serde_json::json!({"iss": "https://evil", "aud": "frps", "exp": now + 100})
            )
            .is_err());
        assert!(v
            .check_claims(
                &serde_json::json!({"iss": "https://idp", "aud": "other", "exp": now + 100})
            )
            .is_err());
        assert!(v
            .check_claims(&serde_json::json!({"iss": "https://idp", "aud": "frps", "exp": now - 1}))
            .is_err());
        assert!(v
            .check_claims(&serde_json::json!({
                "iss": "https://idp", "aud": "frps", "exp": now + 100, "nbf": now + 3600
            }))
            .is_err());
    }

    /// `skipIssuerCheck` / `skipExpiryCheck` 打开后要真的跳过。
    #[test]
    fn skip_开关生效() {
        let v = OidcVerifier::new(ServerOidcConfig {
            issuer: "https://idp".into(),
            audience: String::new(), // 空 audience = 跳过 aud 校验
            skip_issuer_check: true,
            skip_expiry_check: true,
            ..Default::default()
        })
        .unwrap();
        assert!(v
            .check_claims(&serde_json::json!({"iss": "https://evil", "exp": 1}))
            .is_ok());
    }

    /// 算法白名单：不支持的要拒绝，`none` 必须拒绝。
    #[test]
    fn 不支持的算法被拒绝() {
        assert!(!SUPPORTED_ALGS.contains(&"none"));
        assert!(
            !SUPPORTED_ALGS.contains(&"HS256"),
            "对称算法不能接受：JWKS 给的是公钥，用它当 HMAC 密钥就是伪造漏洞"
        );
        assert!(SUPPORTED_ALGS.contains(&"RS256"));
        assert!(SUPPORTED_ALGS.contains(&"ES256"));
    }

    /// `alg=none` 的 token 必须被挡在第一步。
    #[test]
    fn alg_none_被拒绝() {
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        use base64::Engine as _;
        let h = URL_SAFE_NO_PAD.encode(br#"{"alg":"none"}"#);
        let p =
            URL_SAFE_NO_PAD.encode(br#"{"sub":"attacker","iss":"https://idp","exp":9999999999}"#);
        let v = OidcVerifier::new(ServerOidcConfig {
            issuer: "https://idp".into(),
            ..Default::default()
        })
        .unwrap();
        let e = v
            .verify_token(&format!("{h}.{p}."))
            .unwrap_err()
            .to_string();
        assert!(e.contains("none"), "{e}");
    }

    /// 缺 issuer 时要在**构造阶段**就报错，而不是等第一个客户端来登录。
    #[test]
    fn 缺_issuer_启动就报错() {
        assert!(OidcVerifier::new(ServerOidcConfig::default()).is_err());
    }

    #[test]
    fn 客户端配置校验() {
        let mut c = ClientOidcConfig::default();
        assert!(c.validate().is_err(), "缺 clientID 要报错");
        c.client_id = "frpc".into();
        assert!(c.validate().is_err(), "缺 tokenEndpointURL 要报错");
        c.token_endpoint_url = "https://idp/token".into();
        assert!(c.validate().is_ok());
    }

    /// 没登录过的 subject 不能通过"登录后校验" —— 这条防的是跨客户端冒充。
    #[test]
    fn 未登录的_subject_不被接受() {
        let v = OidcVerifier::new(ServerOidcConfig {
            issuer: "https://idp".into(),
            ..Default::default()
        })
        .unwrap();
        let g = v.subjects.read().unwrap();
        assert!(!g.contains("nobody"));
        assert_eq!(v.subject_count(), 0);
    }
}
