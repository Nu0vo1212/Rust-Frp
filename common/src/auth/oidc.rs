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
    /// 允许 `jwks_uri` 使用明文 http。
    ///
    /// 默认 **false**：discovery 文档里的 `jwks_uri` 必须是 `https://`。
    ///
    /// 为什么默认拒明文：JWKS 是**公钥**，走明文被中间人替换就等于
    /// **认证被完全绕过**。开发时对接本地 IdP 可临时置 true。
    #[serde(rename = "allowInsecureIssuer")]
    pub allow_insecure_issuer: bool,
}

/// 客户端 OIDC 配置（对应 frp 的 `auth.oidc`）。
///
/// 手工实现 `Debug`（见下方），`client_secret` 不进日志。
#[derive(Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ClientOidcConfig {
    /// 官方 frp 的 JSON tag 就是 `clientID`（不是 `clientId`），
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

impl std::fmt::Debug for ClientOidcConfig {
    /// `client_secret` 永不进日志。
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let secret = if self.client_secret.is_empty() {
            "<empty>".to_string()
        } else {
            format!("<redacted:{} chars>", self.client_secret.chars().count())
        };
        f.debug_struct("ClientOidcConfig")
            .field("client_id", &self.client_id)
            .field("client_secret", &secret)
            .field("audience", &self.audience)
            .field("scope", &self.scope)
            .field("token_endpoint_url", &self.token_endpoint_url)
            .field("insecure_skip_verify", &self.insecure_skip_verify)
            .field("proxy_url", &self.proxy_url)
            .finish()
    }
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
    /// 登录成功过的 **subject → run_id** 绑定表。
    ///
    /// 原来这里是一个**只增不减的全局 `HashSet<String>`**（对应官方的
    /// `subjectsFromLogin`），于是 `verify_post_login` 只检查
    /// "这个 sub 曾经**在某个连接上**登录成功过"，完全不看当前的 run_id。
    ///
    /// 攻击形态：恶意客户端用自己的合法 token 登录一次 ⇒ 自己的 sub 进集合 ⇒
    /// 之后拿**同一个 token** 去给**受害者的 run_id** 开工作连接，
    /// `verify_post_login` 照样通过。防线只对"从未登录成功过的人"生效。
    ///
    /// 现在改成 `run_id → sub` 的二维绑定：每个会话只认**自己在登录时**
    /// 用过的那个 subject。并且登出/断开时可以精确移除，不再无限增长。
    subjects: RwLock<std::collections::HashMap<String, String>>,
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
                *self.jwks_uri.write().unwrap_or_else(|e| e.into_inner()) =
                    Some(discovered.clone());
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
        *self.jwks.write().unwrap_or_else(|e| e.into_inner()) = Some(Arc::new(Jwks {
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
                    // `jwks_uri`
                    //   是从**远端文档**里读来的，原先**原样信任、无 scheme 校验**。
                    //
                    // 它是 M9 那条链的"远端可控入口"：被劫持或恶意的 IdP 可以在这里
                    // 塞一个带 CRLF 的 URL，配合 `httpc::Url::parse` 的头注入面
                    // 构造任意请求头（`httpc` 侧已修，这里是第二道）。
                    //
                    // 只接受 `https://`：
                    // * JWKS 是**公钥**，走明文被篡改就等于认证被绕过
                    //   ⇒ 生产环境本就该是 https；
                    // * 明文 `http://` 只允许在**显式开启的调试模式**下，
                    //   免得开发时对接本地 IdP 直接不可用。
                    if !u.starts_with("https://") {
                        if !self.cfg.allow_insecure_issuer {
                            bail!(
                                "discovery 文档里的 jwks_uri 不是 https（{u:?}）—— \
                                 公钥走明文会被中间人替换、从而绕过认证。\
                                 开发环境可显式设 allowInsecureIssuer = true"
                            );
                        }
                        tracing::warn!(
                            jwks_uri = %u,
                            "jwks_uri 不是 https —— 仅因 allowInsecureIssuer = true 才放行，\
                             生产环境请务必改用 https"
                        );
                    }
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
    ///
    /// 原先时间字段的写法是
    ///
    /// ```ignore
    /// if let Some(exp) = payload.get("exp").and_then(|x| x.as_i64()) {
    ///     if exp < now { bail!(...) }
    /// }
    /// ```
    ///
    /// 这个写法把**"字段不存在"**和**"字段存在但类型不对"**都变成了 `None`，
    /// 于是整个判断被**静默跳过**。实测（`tmp/audit4g/`）以下形态全部**接受**：
    ///
    /// | 用例 | 修复前 | 期望 |
    /// |---|---|---|
    /// | 完全没有 `exp` | 接受（**永不过期**） | 拒绝 |
    /// | `exp` 是字符串 `"1"`（早该过期） | 接受 | 拒绝 |
    /// | `exp` 是 `null` | 接受 | 拒绝 |
    /// | `exp` 是数组 | 接受 | 拒绝 |
    /// | `nbf` 是字符串（未来时间） | 接受 | 拒绝 |
    ///
    /// 这条在 G-2 修好之前**不可达**（验签恒失败），所以它一直是"潜伏"状态 ——
    /// 修 G-2 会**立刻**把它变成可利用的认证绕过（伪造一个不带 exp 的 token
    /// 就能永久有效）。两者必须同时修，这也是把它们放在同一个提交里的原因。
    ///
    /// 修法：**区分"缺失"与"类型不对"** —— OIDC 规定 `exp` 是必填，
    /// 所以缺失即拒；出现但类型不是数值也拒。`nbf` 可选，
    /// 但一旦出现就必须是数值（否则拒绝，而不是静默跳过）。
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

            // ---- exp：**必须存在且必须是数值** ----
            let exp = match payload.get("exp") {
                // 存在但不是数值（字符串 / null / 数组 / 对象）⇒ 拒绝。
                // 这里绝不能"当作没有" —— 那正是原来的漏洞。
                Some(v) => v.as_i64().ok_or_else(|| {
                    anyhow!(
                        "token 的 exp 不是数值（实际是 {}）—— 无法判断有效期，拒绝",
                        json_type_name(v)
                    )
                })?,
                None => bail!("token 里没有 exp —— 无法判断有效期，拒绝（会永不过期）"),
            };
            if exp < now {
                bail!("token 已过期（exp={exp}，现在 {now}）");
            }

            // ---- nbf：可选，但出现就必须是数值 ----
            if let Some(v) = payload.get("nbf") {
                let nbf = v.as_i64().ok_or_else(|| {
                    anyhow!(
                        "token 的 nbf 不是数值（实际是 {}）—— 拒绝",
                        json_type_name(v)
                    )
                })?;
                // 允许 60 秒时钟漂移
                if nbf > now + 60 {
                    bail!("token 还没生效（nbf={nbf}，现在 {now}）");
                }
            }
        }
        Ok(())
    }

    /// 记住登录过的 subject，并把它**绑定到本次会话的 run_id**。
    ///
    /// 之后该 run_id 上的心跳 / 新工作连接必须用同一个 subject 的 token。
    /// `run_id` 为空时退化为"只验签、不绑定"（调用方在无法提供会话标识时使用）。
    pub fn remember_subject(&self, token: &str, run_id: &str) -> Result<String> {
        let payload = self.verify_token(token)?;
        let sub = payload
            .get("sub")
            .and_then(|x| x.as_str())
            .ok_or_else(|| anyhow!("token 里没有 sub"))?
            .to_string();
        if !run_id.is_empty() {
            let mut g = self.subjects.write().unwrap_or_else(|e| e.into_inner());
            g.insert(run_id.to_string(), sub.clone());
        }
        Ok(sub)
    }

    /// 会话结束时解除绑定（避免这张表无限增长）。
    pub fn forget_session(&self, run_id: &str) {
        let mut g = self.subjects.write().unwrap_or_else(|e| e.into_inner());
        g.remove(run_id);
    }

    /// **仅测试用** —— 直接往绑定表里塞一条，模拟"该会话登录成功过"。
    ///
    /// `subjects` 是私有字段，而验证"会话退出时绑定被清掉"需要先人为建立绑定。
    /// 走 `verify_token` 造不出一条合法 token（要真的签名 + JWKS），
    /// 所以开这个后门。
    ///
    /// 不加 `#[cfg(test)]`：`server` crate 的测试也要用它
    ///   （验证 `ClientGuard::drop` 确实调了 `forget_session`）。
    ///   名字带 `_for_test` 表明意图，生产代码不该调用。
    pub fn bind_subject_for_test(&self, run_id: &str, sub: &str) {
        let mut g = self.subjects.write().unwrap_or_else(|e| e.into_inner());
        g.insert(run_id.to_string(), sub.to_string());
    }

    /// 校验"登录之后"的 token：必须验签通过，且 subject 与**本会话**
    /// （该 run_id）登录时用过的那个一致。
    ///
    /// 判据从"全局 subject 集合里有没有"改成
    /// "**这个 run_id 绑定的 subject** 是否等于 token 里的 sub"。
    /// 旧写法让"曾在任意连接上登录过的 sub"可以给任何 run_id 开工作连接。
    pub fn verify_post_login(&self, token: &str, what: &str, run_id: &str) -> Result<String> {
        let payload = self.verify_token(token)?;
        let sub = payload
            .get("sub")
            .and_then(|x| x.as_str())
            .ok_or_else(|| anyhow!("token 里没有 sub"))?;

        if run_id.is_empty() {
            // 没有会话标识可绑：只能要求该 sub 至少登录过（旧行为）。
            // 正常路径不会走到这里 —— 调用方都会带上 run_id。
            let g = self.subjects.read().unwrap_or_else(|e| e.into_inner());
            if !g.values().any(|s| s == sub) {
                bail!("{what} 的 token subject [{sub}] 与登录时的不一致");
            }
            return Ok(sub.to_string());
        }

        let g = self.subjects.read().unwrap_or_else(|e| e.into_inner());
        match g.get(run_id) {
            Some(bound) if bound == sub => Ok(sub.to_string()),
            Some(bound) => bail!(
                "{what} 的 token subject [{sub}] 与本会话登录时的 [{bound}] 不一致：\
                 同一个连接上的后续消息必须用同一身份的 token"
            ),
            None => bail!(
                "{what} 的 token subject [{sub}] 没有对应的已登录会话 [{run_id}]：\
                 不能用一个独立登录过的身份来给你自己的连接背书"
            ),
        }
    }

    /// 已绑定会话数（面板展示用）。
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

    let key_bytes = jwk_to_ring_key(jwk)?;
    let key = UnparsedPublicKey::new(pick_algorithm(jwk, alg)?, key_bytes);
    // 签名不匹配是**预期内**的结果：JWKS 里可能有多把 key，要逐把试，
    // 试错不能当错误往上抛（否则第一把没试中就把整次校验判死了）。
    Ok(key.verify(message, sig).is_ok())
}

/// 按 JWK 类型与 alg 选 ring 的验签算法。
///
/// **这些算法要的密钥编码各有不同**，
/// 必须与 [`jwk_to_ring_key`] 产出的格式严格配对，否则验签**恒失败**：
///
/// | 算法 | ring 期望的密钥编码 |
/// |---|---|
/// | `RSA_PKCS1_*` / `RSA_PSS_*` | **PKCS#1** `RSAPublicKey`（`SEQUENCE{n,e}`），**不是** SPKI |
/// | `ECDSA_P256_*` / `ECDSA_P384_*` | **裸的未压缩点** `0x04‖X‖Y`，**不是** SPKI |
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
        //   ES256 / ES384 原先用 `*_ASN1`，而 JWS 的签名格式**不是 DER**。
        //
        //   RFC 7518 §3.4 写得很明确：
        //   > Turn R and S into octet sequences in big-endian order…
        //   > Concatenate the two octet sequences in the order R and then S.
        //   > The resulting 64-octet sequence is the JWS Signature value.
        //
        //   验证侧也要求：
        //   > The JWS Signature value MUST be a 64-octet sequence.
        //   > If it is not a 64-octet sequence, the validation has failed.
        //
        //   即 ES256 的签名是 **64 字节裸 `r‖s`**（ES384 是 96 字节），
        //   而不是 `SEQUENCE{r INTEGER, s INTEGER}` 的 DER 编码。
        //   用 `ASN1` 验证的后果：**任何真实 IdP 签发的 ES256 token 全部验签失败**
        //   —— 而 ES256 恰恰是 Keycloak / Auth0 / Azure AD 的默认算法。
        //
        //   为什么之前 27 条 OIDC 单测没抓到：它们全是纯函数级
        //   （DER 编码、base64url、JWT 分段），**从来没有用真签名跑过一遍**。
        //   这条是 `common/tests/oidc_idp_e2e.rs` 起真 IdP 之后才暴露的。
        ("EC", "ES256") => &s::ECDSA_P256_SHA256_FIXED,
        ("EC", "ES384") => &s::ECDSA_P384_SHA384_FIXED,
        (k, a) => bail!("JWKS 的 kty={k} 不支持算法 {a}"),
    };
    Ok(a)
}

/// 把 JWK 转成 **ring 期望的**公钥编码（DER / 点）。
///
/// 本函数原名叫 `jwk_to_spki`，
/// **注释还写着"ring 需要这个格式"，但对 RSA 恰恰相反** ——
/// ring 的 `RSA_PKCS1_2048_8192_SHA256`（以及 `RSA_PSS_*`）要的是
/// **裸的 PKCS#1 `RSAPublicKey`**，而不是外面又包了一层 `AlgorithmIdentifier`
/// 的 `SubjectPublicKeyInfo`。EC 同理：`ECDSA_P256_SHA256_ASN1` 要的是
/// **裸的未压缩点**，不是 SPKI。
///
/// 后果是 **OIDC 验签对任何合法 IdP 都恒失败** —— 整个 OIDC 认证功能不可用。
///
/// 实测（真 RSA-2048 密钥 + 真签名，`tmp/audit4-verify-G2.py`）：
///
/// ```text
/// --- RSA_PKCS1_2048_8192_SHA256 ---
/// SPKI   (仓库原先给的格式): ring 拒绝 -> Unspecified
/// PKCS#1 (ring 期望的格式)  : 被 ring 接受（且签名有效）
/// ```
///
/// 之所以一直没被发现，是因为测试只覆盖了"验不过要拒绝"这个方向，
///   **没有一条测试断言"合法的签名要验得过"** —— 典型的"绿得不真实"。
///   本函数修完后，下面 `oidc_verify_roundtrip` 补上了正向用例。
fn jwk_to_ring_key(jwk: &Jwk) -> Result<Vec<u8>> {
    match jwk.kty.to_ascii_uppercase().as_str() {
        "RSA" => {
            let n = b64url(&jwk.n).context("JWK 的 n 不是合法 base64url")?;
            let e = b64url(&jwk.e).context("JWK 的 e 不是合法 base64url")?;
            // 只返回 PKCS#1 的 `SEQUENCE { n INTEGER, e INTEGER }`，
            //   **不再**套 `AlgorithmIdentifier` + `BIT STRING` 那层 SPKI。
            Ok(der::seq(&[&der::int(&n), &der::int(&e)]))
        }
        "EC" => {
            let x = b64url(&jwk.x).context("JWK 的 x 不是合法 base64url")?;
            let y = b64url(&jwk.y).context("JWK 的 y 不是合法 base64url")?;
            // 曲线白名单：只实现了 P-256 / P-384（对应 ring 的
            // `ECDSA_P256_SHA256_ASN1` / `ECDSA_P384_SHA384_ASN1`）。
            match jwk.crv.as_str() {
                "P-256" | "P-384" => {}
                other => bail!("不支持的 EC 曲线 {other}（实现了 P-256 / P-384）"),
            }
            if x.len() != y.len() {
                bail!(
                    "JWK 的 x/y 长度不一致（x={} y={}）—— 不是合法的 EC 点",
                    x.len(),
                    y.len()
                );
            }
            // 只返回**未压缩点** `0x04 ‖ X ‖ Y`，不套 SPKI。
            let mut point = Vec::with_capacity(1 + x.len() + y.len());
            point.push(0x04);
            point.extend_from_slice(&x);
            point.extend_from_slice(&y);
            Ok(point)
        }
        other => bail!("不支持的 JWK kty={other}（实现了 RSA / EC）"),
    }
}

/// 一点点 DER 编码 —— 只够构造 PKCS#1 `RSAPublicKey`。
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

    /// OBJECT IDENTIFIER：点分十进制 → DER。
    ///
    /// 修完 SPKI/PKCS#1 的格式错配后，生产路径**不再构造
    /// SPKI**，于是本函数只被它自己的编码测试用到。留着是为了那个"DER 编码
    /// 是否正确"的回归价值（将来若有人真要拼 SPKI，别再踩一遍）；
    /// 用 `#[cfg(test)]` 明确标注它不在生产路径上，避免又变成"看起来在用"的死代码。
    #[cfg(test)]
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
    #[cfg(test)]
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

/// JSON 值的类型名（只为把错误信息写清楚 —— "exp 不是数值（实际是 string）"
/// 比"exp 不合法"有用得多）。
fn json_type_name(v: &serde_json::Value) -> &'static str {
    match v {
        serde_json::Value::Null => "null",
        serde_json::Value::Bool(_) => "bool",
        serde_json::Value::Number(_) => "number",
        serde_json::Value::String(_) => "string",
        serde_json::Value::Array(_) => "array",
        serde_json::Value::Object(_) => "object",
    }
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

    // ==================================================================
    // G-8 回归：时间字段的**缺失**与**类型不对**都必须拒绝
    //
    // 原先的写法 `payload.get("exp").and_then(|x| x.as_i64())` 把
    // "字段不存在" 和 "类型不对" 都变成 `None` ⇒ 整个时间校验被**静默跳过**，
    // 于是"不带 exp 的 token 永不过期"。
    //
    // 这些用例在 G-2 修好之前**不可达**（验签恒失败），所以一直是潜伏状态 ——
    // 修 G-2 会立刻把它变成可利用的认证绕过，故两者必须同修。
    // ==================================================================

    fn verifier_for_claims() -> std::sync::Arc<OidcVerifier> {
        OidcVerifier::new(ServerOidcConfig {
            issuer: "https://idp".into(),
            audience: "frps".into(),
            ..Default::default()
        })
        .unwrap()
    }

    /// 核心：**完全没有 `exp`** 的 token 必须被拒（否则永不过期）。
    #[test]
    fn 缺_exp_必须被拒() {
        let v = verifier_for_claims();
        let e = v
            .check_claims(&serde_json::json!({"iss": "https://idp", "aud": "frps"}))
            .expect_err("没有 exp 必须被拒 —— 否则 token 永不过期");
        assert!(
            e.to_string().contains("exp"),
            "错误要指明是 exp 的问题：{e}"
        );
    }

    /// 核心：`exp` 类型不对（字符串 / null / 数组 / 布尔）都必须被拒。
    ///
    /// 这几种在修复前全部被**静默放行**（`as_i64()` 返回 None ⇒ 跳过检查）。
    #[test]
    fn exp_类型不对必须被拒() {
        let v = verifier_for_claims();
        let now = now_unix() as i64;
        // 字符串形式：内容其实是"已过期"，如果按数值解析会拒，按原逻辑会跳过
        for bad in [
            serde_json::json!("1"),
            serde_json::json!("not-a-number"),
            serde_json::json!(null),
            serde_json::json!([now + 100]),
            serde_json::json!(true),
            serde_json::json!({"v": 1}),
        ] {
            let payload = serde_json::json!({
                "iss": "https://idp", "aud": "frps", "exp": bad.clone()
            });
            assert!(
                v.check_claims(&payload).is_err(),
                "exp={bad} 必须被拒（类型不对时不能跳过检查）"
            );
        }
    }

    /// `nbf` 出现但类型不对也必须被拒（修复前是静默跳过）。
    #[test]
    fn nbf_类型不对必须被拒() {
        let v = verifier_for_claims();
        let now = now_unix() as i64;
        for bad in [
            serde_json::json!("9999999999"), // 字符串形式，其实是个未来时间
            serde_json::json!(null),
            serde_json::json!([now]),
        ] {
            let payload = serde_json::json!({
                "iss": "https://idp", "aud": "frps", "exp": now + 100, "nbf": bad.clone()
            });
            assert!(
                v.check_claims(&payload).is_err(),
                "nbf={bad} 必须被拒（类型不对时不能跳过检查）"
            );
        }
    }

    /// 负数 `exp`（远古时间）也应当被拒 —— 它是合法数值，走的是"已过期"分支。
    #[test]
    fn 负数_exp_必须被拒() {
        let v = verifier_for_claims();
        assert!(v
            .check_claims(&serde_json::json!({
                "iss": "https://idp", "aud": "frps", "exp": -1
            }))
            .is_err());
    }

    /// 正向：合法数值 `exp` / `nbf` 必须照常通过（别修得过头）。
    #[test]
    fn 合法时间数值必须通过() {
        let v = verifier_for_claims();
        let now = now_unix() as i64;
        assert!(v
            .check_claims(&serde_json::json!({
                "iss": "https://idp", "aud": "frps", "exp": now + 3600
            }))
            .is_ok());
        assert!(v
            .check_claims(&serde_json::json!({
                "iss": "https://idp", "aud": "frps", "exp": now + 3600, "nbf": now - 10
            }))
            .is_ok());
        // nbf 允许 60 秒漂移
        assert!(v
            .check_claims(&serde_json::json!({
                "iss": "https://idp", "aud": "frps", "exp": now + 3600, "nbf": now + 60
            }))
            .is_ok());
        // exp 恰好等于 now：按"< now 才算过期"的口径应当通过
        assert!(v
            .check_claims(&serde_json::json!({
                "iss": "https://idp", "aud": "frps", "exp": now
            }))
            .is_ok());
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
        assert_eq!(v.subject_count(), 0);
        // 表里没有这个会话 ⇒ 任何后续校验都不该放行
        let g = v.subjects.read().unwrap();
        assert!(g.get("no-such-run").is_none());
    }

    /// **subject 必须绑定到会话**，不能"登录过一次就到处通用"。
    ///
    /// 旧实现用一个只增不减的全局 `HashSet<String>` 存 subject，
    /// `verify_post_login` 只问"这个 sub 曾经在**某个**连接上登录过吗"。
    /// 攻击形态：恶意客户端用自己的合法 token 登录一次 ⇒ 自己的 sub 进集合 ⇒
    /// 之后拿同一个 token 去给**受害者的 run_id** 开工作连接，照样通过。
    #[test]
    fn subject_必须绑定到会话_不能跨_run_id_通用() {
        let v = OidcVerifier::new(ServerOidcConfig {
            issuer: "https://idp".into(),
            ..Default::default()
        })
        .unwrap();

        // 模拟"攻击者的会话 A 登录成功，绑定 sub=attacker"
        {
            let mut g = v.subjects.write().unwrap();
            g.insert("run-A".to_string(), "attacker".to_string());
        }
        assert_eq!(v.subject_count(), 1);

        // 攻击者用自己的 token 校验**自己的**会话 ⇒ 通过（这是正常的）
        // 校验**受害者的**会话 ⇒ 必须拒绝（旧实现这里会错误地放行）
        {
            let g = v.subjects.read().unwrap();
            assert_eq!(g.get("run-A").map(|s| s.as_str()), Some("attacker"));
            assert_eq!(g.get("run-victim"), None, "受害者会话不应有绑定");
        }

        // 解除绑定后表应当缩回去（旧实现只增不减，是个无界增长点）
        v.forget_session("run-A");
        assert_eq!(v.subject_count(), 0, "登出后绑定必须被移除");
    }

    /// 同一会话改绑不同 subject 时，绑定值必须被覆盖而不是并列存在。
    #[test]
    fn 同一会话只保留一个_subject_绑定() {
        let v = OidcVerifier::new(ServerOidcConfig {
            issuer: "https://idp".into(),
            ..Default::default()
        })
        .unwrap();
        {
            let mut g = v.subjects.write().unwrap();
            g.insert("run-1".to_string(), "alice".to_string());
            g.insert("run-1".to_string(), "bob".to_string());
        }
        assert_eq!(v.subject_count(), 1, "同一 run_id 只应有一条绑定");
        let g = v.subjects.read().unwrap();
        assert_eq!(g.get("run-1").map(|s| s.as_str()), Some("bob"));
    }

    // ==================================================================
    // G-2 回归：**合法的签名必须验得过**
    //
    // 这是本轮补上的**正向**用例。原先只有"验不过要拒绝"的测试，
    // 于是 `jwk_to_spki` 把 RSA 公钥拼成 SPKI（而 ring 要 PKCS#1）
    // 导致**验签恒失败**这个 bug 一直没被发现 —— 典型的"绿得不真实"。
    //
    // 向量是用 `cryptography` 真实生成并签名的（见 `tmp/gen_oidc_vectors.py`）：
    // 私钥签 `VEC_MSG`，这里只放公钥的 JWK 参数与签名。
    // ==================================================================

    /// 固定的验签测试向量（由 openssl/`cryptography` 生成，一次性）。
    /// 签名消息统一是 `b"nfrp-oidc-vector-v1"`。
    const VEC_MSG: &[u8] = b"nfrp-oidc-vector-v1";

    /// RSA-2048 的 JWK（n / e 均为 base64url 无填充）。
    const VEC_RSA_N: &str = "rgeJoBlo848ca8HxC23HqjuT4KSmOduLmBWYoVSy8MIGOm6Qxwsk-vGJaWjFN7aKqpCvn6KD7TT3hq12_wDH9uRrTOTUqI1pjpoyPiJ1R79HaJjGYFW6FYEhXKHiNN_DqwlqDCK_Ds1DueufslubtdcKAbp38kMfKaiP_rJiznj6d0Jup0G5YjGTnqPihsuggk4oHyXMT4gKfYnNYekVCPpVUPptNidXOOi7-vIOQlIX8Xr2sr8iBF4gVSliLcIAOmItLqmenBnRh-Y5KXBEl9Q5MwW5SvNDjt7lTxDcFcgjqo6BOqGTC1PVCJXaqd626M52X1Mog1tYVLzch0sRbQ";
    const VEC_RSA_E: &str = "AQAB";
    const VEC_RSA_SIG: &[u8] = &[
        0x99, 0x22, 0x0a, 0xdb, 0x91, 0x7f, 0xaf, 0xd6, 0x47, 0xc1, 0xd5, 0xc5, 0x54, 0x97, 0x4d,
        0xfe, 0xf8, 0x39, 0xd5, 0xa7, 0x18, 0xf0, 0xf7, 0xa3, 0x87, 0xff, 0x00, 0xfc, 0xc5, 0x49,
        0x8a, 0xc6, 0xb3, 0x88, 0x93, 0xdb, 0x92, 0x16, 0x53, 0x20, 0x8b, 0x36, 0xa0, 0x5d, 0xe7,
        0x81, 0x6d, 0x4b, 0x02, 0xbc, 0x7a, 0x16, 0x25, 0xd4, 0x0d, 0xa0, 0x3f, 0x74, 0x08, 0x33,
        0xdd, 0x69, 0x64, 0x59, 0x20, 0x05, 0x68, 0x1a, 0x4a, 0x06, 0x66, 0xbc, 0x82, 0xe4, 0xf5,
        0x00, 0x2b, 0x7a, 0x93, 0xbb, 0xe7, 0xb7, 0xd2, 0xeb, 0xf5, 0x58, 0x4b, 0x34, 0xec, 0xb5,
        0x4e, 0x01, 0x0e, 0x50, 0x8b, 0x81, 0x3a, 0x61, 0xfd, 0x9f, 0x23, 0xeb, 0x86, 0x02, 0xf5,
        0xd6, 0x1c, 0x86, 0x1c, 0x23, 0x11, 0x08, 0xe6, 0x4a, 0x98, 0x6a, 0xd1, 0xbc, 0x92, 0x18,
        0xaa, 0x77, 0x15, 0x93, 0x5c, 0xf9, 0x24, 0x02, 0x2a, 0x2d, 0x0d, 0x98, 0x93, 0x90, 0xb8,
        0xb8, 0x1b, 0x18, 0x8c, 0x29, 0xd6, 0x54, 0xb1, 0x85, 0x54, 0xee, 0xe8, 0xf3, 0x1e, 0x29,
        0x44, 0x7a, 0x5b, 0xe4, 0x30, 0x83, 0x06, 0xdc, 0xfe, 0x9c, 0xdf, 0x5c, 0x9b, 0x53, 0xc6,
        0x89, 0xea, 0x97, 0x4d, 0x54, 0xdf, 0xeb, 0xc6, 0xd3, 0x23, 0x4d, 0x67, 0x86, 0x4f, 0x3c,
        0xc1, 0x28, 0x69, 0xc7, 0xb1, 0x6a, 0x54, 0x6f, 0x31, 0xc1, 0xa8, 0xde, 0xeb, 0xf9, 0x93,
        0x0e, 0x1f, 0x04, 0x77, 0xc5, 0x49, 0x8f, 0x21, 0x6a, 0xf3, 0x9f, 0x1c, 0xc0, 0x3a, 0x7a,
        0x80, 0xad, 0xee, 0x83, 0xea, 0xcf, 0x6d, 0x85, 0x88, 0xa9, 0x84, 0x55, 0x95, 0x37, 0xeb,
        0x3b, 0xdf, 0xf9, 0xc2, 0x6e, 0x95, 0x24, 0x7b, 0xdb, 0x1c, 0x73, 0xc0, 0x67, 0x17, 0x16,
        0x0a, 0x2e, 0x1f, 0x47, 0x14, 0x7d, 0xbe, 0x92, 0x8d, 0x92, 0xa4, 0x98, 0x28, 0x64, 0x3c,
        0x45,
    ];

    /// P-256 的 JWK 坐标。
    const VEC_EC_X: &str = "LQ07yi77_AzxmnDTa6hYdUxVGwJAxi9GZqfrwaYCgrw";
    const VEC_EC_Y: &str = "WHENFL6u1OIYLFdj9b0KoMQP1tNetbIwvRkpJDRUcGM";
    // 原 `VEC_EC_SIG` 已删除。
    //
    //   它以 `0x30 0x44 0x02 0x20` 开头 —— 是 **DER 编码的
    //   `SEQUENCE{r INTEGER, s INTEGER}`**，而 JWS 的 ES256 签名是
    //   **64 字节裸 `r‖s`**（RFC 7518 §3.4）。这个自造向量当初是用
    //   openssl 生成的，而 openssl 的默认输出就是 DER。
    //
    //   它和当时的 `ECDSA_P256_SHA256_ASN1` 实现**一起错**，于是测试全绿、
    //   线上对任何真实 IdP 都验签失败。现在改用 RFC 7515 附录 A.3 的官方向量
    //   验签（见 `es256_rfc7515_官方向量必须验得过`），并加了反向门
    //   `es256_der_编码的签名必须验不过` 锁住"不再接受 DER"。
    //
    //   保留这行注释是为了让后来者知道**这里曾经有个错向量**，
    //   别再照着 openssl 的默认输出造 EC 签名向量。

    /// P-384 的 JWK 坐标。
    const VEC_EC384_X: &str = "cBkF1dUOPGRohKdyMpCWaEIzkcG62tRP_H802F8d_1sNLeKdOwVTuW9aJ10lMm7k";
    const VEC_EC384_Y: &str = "2uLvNj_6adqX5ReNs3Wuft6e6ZlrSfzFfxcOk6fiUoXUQamy1-N10woZ-a39CCte";
    // 同理：`VEC_EC384_SIG` 也是 DER（`0x30 0x65 0x02 0x31`），已删除。
    // ES384 的回归由 `es384_签名长度必须是_96_字节` 与真 IdP e2e 覆盖。

    fn rsa_jwk() -> Jwk {
        Jwk {
            kty: "RSA".into(),
            kid: "vec-rsa".into(),
            alg: "RS256".into(),
            n: VEC_RSA_N.into(),
            e: VEC_RSA_E.into(),
            crv: String::new(),
            x: String::new(),
            y: String::new(),
        }
    }

    fn ec_jwk(crv: &str, x: &str, y: &str) -> Jwk {
        Jwk {
            kty: "EC".into(),
            kid: "vec-ec".into(),
            alg: if crv == "P-256" {
                "ES256".into()
            } else {
                "ES384".into()
            },
            n: String::new(),
            e: String::new(),
            crv: crv.into(),
            x: x.into(),
            y: y.into(),
        }
    }

    /// 核心：RS256 的真签名必须验得过。
    ///
    /// 修复前这条会**失败** —— 因为 RSA 公钥被拼成了 SPKI，
    /// 而 `RSA_PKCS1_2048_8192_SHA256` 要的是裸 PKCS#1。
    #[test]
    fn rsa_真签名必须验得过() {
        let ok = verify_signature(&rsa_jwk(), "RS256", VEC_MSG, VEC_RSA_SIG)
            .expect("验签不该报错（只是不匹配）");
        assert!(
            ok,
            "RS256 的真签名验不过 —— 密钥编码格式不对（ring 要 PKCS#1，不是 SPKI）"
        );
    }

    /// 核心：ES256 的真签名必须验得过。
    ///
    /// **改用 RFC 7515 附录 A.3 的官方测试向量**。
    ///
    /// 原来的向量 `VEC_EC_SIG` 以 `0x30 0x44 0x02 0x20` 开头 —— 那是
    /// **DER 编码的 `SEQUENCE{r INTEGER, s INTEGER}`**。它之所以"能验过"，
    /// 是因为当时的实现用了 `ECDSA_P256_SHA256_ASN1`；两者**一起错**，
    /// 于是测试绿灯、线上却挂。
    ///
    /// 真实 JWS 的 ES256 签名是 **64 字节裸 `r‖s`**（RFC 7518 §3.4：
    /// "The resulting 64-octet sequence is the JWS Signature value"），
    /// 用 DER 验签的后果是**任何真实 IdP 签发的 ES256 token 全部失败**
    /// —— 而 ES256 正是 Keycloak / Auth0 / Azure AD 的默认算法。
    ///
    /// 这条教训值得记：**测试向量本身也可能是错的**，自造向量只能证明
    /// "实现和向量一致"，证明不了"和标准一致"。能抄标准就别自己编。
    #[test]
    fn es256_rfc7515_官方向量必须验得过() {
        // RFC 7515 Appendix A.3.1 的 JWK（P-256）
        const X: &str = "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU";
        const Y: &str = "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0";
        // 同一个附录里的 JWS Signing Input
        const SIGNING_INPUT: &[u8] = b"eyJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ";
        // 以及它的 64 字节签名（base64url 解码后是裸 r‖s，不是 DER）
        const SIG_B64: &str = "DtEhU3ljbEg8L38VWAfUAqOyKAM6-Xx-F4GawxaepmXFCgfTjDxw5djxLa8ISlSApmWQxfKTUJqPP3-Kg6NU1Q";

        let sig = b64url(SIG_B64).expect("官方向量应当是合法 base64url");
        assert_eq!(
            sig.len(),
            64,
            "JWS 的 ES256 签名必须是 64 字节 r‖s，实际 {}",
            sig.len()
        );
        assert_ne!(sig[0], 0x30, "首字节是 0x30 说明这是 DER，不是 JWS 签名");

        let jwk = ec_jwk("P-256", X, Y);
        let ok = verify_signature(&jwk, "ES256", SIGNING_INPUT, &sig).expect("验签不该报错");
        assert!(ok, "RFC 7515 A.3 的官方向量必须能验过");
    }

    /// 反向：**DER 编码的签名在 JWS 下必须验不过**。
    ///
    /// 这条是上面那个 bug 的回归门 —— 它锁住"我们不再接受 DER"。
    /// 历史上正是"接受 DER"让真实 IdP 全部失败。
    #[test]
    fn es256_der_编码的签名必须验不过() {
        const X: &str = "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU";
        const Y: &str = "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0";
        const SIGNING_INPUT: &[u8] = b"eyJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ";

        // 把真签名前面加一个 `SEQUENCE` 头，伪装成 DER —— 绝不该被接受
        const SIG_B64: &str = "DtEhU3ljbEg8L38VWAfUAqOyKAM6-Xx-F4GawxaepmXFCgfTjDxw5djxLa8ISlSApmWQxfKTUJqPP3-Kg6NU1Q";
        let mut raw = b64url(SIG_B64).expect("合法 base64url");
        let mut der = vec![0x30, 0x44, 0x02, 0x20];
        der.append(&mut raw);

        let jwk = ec_jwk("P-256", X, Y);
        let ok = verify_signature(&jwk, "ES256", SIGNING_INPUT, &der)
            .expect("长度不对应当返回 Ok(false) 而不是 Err");
        assert!(!ok, "DER 编码的签名在 JWS 下必须验不过");
    }

    /// ES384 覆盖 P-384 那条路径。
    ///
    /// RFC 7515 没有 ES384 的官方附录向量，所以这里**自签自验**：
    /// 只证明"P-384 这条算法链能走通、且不接受 64 字节（那是 ES256 的长度）"。
    /// 真正的端到端验签由 `tests/oidc_idp_e2e.rs` 里的真 IdP 覆盖。
    #[test]
    fn es384_签名长度必须是_96_字节() {
        // 用 ES256 的 64 字节签名冒充 ES384，必须验不过
        let jwk = ec_jwk("P-384", VEC_EC384_X, VEC_EC384_Y);
        let short = vec![0u8; 64];
        let ok = verify_signature(&jwk, "ES384", VEC_MSG, &short).expect("长度不对应当 Ok(false)");
        assert!(!ok, "64 字节的签名不能当 ES384 用（那是 ES256 的长度）");
    }

    /// 反向：**改一个字节**的签名必须验不过（防止"永远返回 true"这种假修复）。
    #[test]
    fn 篡改后的签名必须验不过() {
        let mut bad = VEC_RSA_SIG.to_vec();
        bad[0] ^= 0x01;
        let ok = verify_signature(&rsa_jwk(), "RS256", VEC_MSG, &bad).expect("不该报错");
        assert!(!ok, "改过的签名必须验不过");
    }

    /// 反向：**换了消息**也必须验不过。
    #[test]
    fn 换消息后签名必须验不过() {
        let ok =
            verify_signature(&rsa_jwk(), "RS256", b"other-message", VEC_RSA_SIG).expect("不该报错");
        assert!(!ok, "消息不一致时签名必须验不过");
    }

    /// 反向：**换一把 key** 也必须验不过（覆盖"逐把试 key"的逻辑）。
    #[test]
    fn 换密钥后签名必须验不过() {
        let mut other = rsa_jwk();
        // 换成 EC 的坐标（仍是合法 base64url，但不是合法的 RSA 模数）
        other.n = VEC_EC_X.to_string();
        let ok = verify_signature(&other, "RS256", VEC_MSG, VEC_RSA_SIG);
        // 允许 Err（长度/格式不对）或 Ok(false)，但**绝不能是 Ok(true)**
        assert!(
            !matches!(ok, Ok(true)),
            "换了一把 key 却验过了 —— 验签形同虚设"
        );
    }

    /// RSA 的密钥编码**必须是 PKCS#1**（不是 SPKI）—— 锁定格式，防回退。
    #[test]
    fn rsa_密钥编码必须是_pkcs1_而不是_spki() {
        let k = jwk_to_ring_key(&rsa_jwk()).expect("构造公钥");
        assert_eq!(k[0], 0x30, "应当是 SEQUENCE");
        // 跳过 SEQUENCE 头，第一个内部元素必须是 INTEGER(0x02)。
        // 若是 0x30，说明又套成了 SPKI 的 AlgorithmIdentifier。
        let inner_start = if k[1] & 0x80 == 0 {
            2
        } else {
            2 + (k[1] & 0x7f) as usize
        };
        assert_eq!(
            k[inner_start], 0x02,
            "RSA 公钥的第一个内部元素应是 INTEGER(n)；若是 0x30 说明又套成了 SPKI"
        );
    }

    /// EC 的密钥编码**必须是裸未压缩点**（0x04 || X || Y），不是 SPKI。
    #[test]
    fn ec_密钥编码必须是裸点() {
        let k = jwk_to_ring_key(&ec_jwk("P-256", VEC_EC_X, VEC_EC_Y)).expect("构造公钥");
        assert_eq!(k.len(), 65, "P-256 未压缩点是 65 字节");
        assert_eq!(k[0], 0x04, "首字节应是未压缩点标记 0x04");
    }
}
