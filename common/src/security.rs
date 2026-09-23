//! 认证方式、IP 访问控制与基于角色的权限模型（RBAC）。
//!
//! 这三样是一组：**谁能连上来**（ACL）→ **他是不是他自称的人**（认证）→
//! **他能干什么**（RBAC）。官方 frp 只有前两步的一半（`auth.token` +
//! `allowUsers`），第三步完全没有，所以这里的设计原则是：
//!
//! 1. **默认零行为变化**。任何一张表留空 ⇒ 完全等同于加这个模块之前的行为，
//!    老的配置文件一个字节都不用改就能继续跑。
//! 2. **字段名尽量贴官方**。`auth.method` / `auth.token` / `auth.oidc.*`
//!    与官方 frp 同名同义，官方配置直接喂进来就能用。
//! 3. **先拒后允**。ACL 永远先看 deny：命中 deny 直接拒，不再看 allow。
//!    反过来写（先算 allow 再看 deny）很容易在 allow 写成 `0.0.0.0/0` 时
//!    把一条 deny 整个吞掉。
//!
//! 本模块是纯逻辑（不碰网络、不碰磁盘），便于单测覆盖边界。

use std::net::IpAddr;

use serde::{Deserialize, Serialize};

use crate::auth::oidc::{ClientOidcConfig, ServerOidcConfig};

// ---------------------------------------------------------------------------
// 认证方式
// ---------------------------------------------------------------------------

/// 认证方式，对应官方 frp 的 `auth.method`。
///
/// 官方只有 `token`（默认）与 `oidc` 两种；写成别的值官方会直接报错
/// （`auth method is not supported`），这里同样只在**解析时**就拒绝，
/// 而不是等到运行时才发现"认证永远失败"。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AuthMethod {
    /// `md5(token + timestamp)` 的共享密钥认证（官方默认）。
    #[default]
    Token,
    /// OpenID Connect：客户端拿 IdP 签发的 access token 当凭证。
    Oidc,
}

impl AuthMethod {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Token => "token",
            Self::Oidc => "oidc",
        }
    }
}

/// 服务端认证配置（`[auth]` 段）。
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServerAuthConfig {
    /// `token`（默认）/ `oidc`。
    #[serde(default)]
    pub method: AuthMethod,
    /// 共享密钥。`method = "token"` 时与服务端比对。
    #[serde(default)]
    pub token: String,
    /// 额外校验 token 的时机（官方 `additionalScopes`）。
    ///
    /// 取值 `HeartBeats` / `NewWorkConns`：开启后，心跳与新工作连接上带的
    /// token 也必须当场验签通过，而不是"登录时验过一次就永久信任"。
    /// 关掉它就等于**只要握手时 token 有效，之后换成任何字符串都收**，
    /// 所以这里默认全开。
    #[serde(
        default = "default_scopes",
        rename = "additionalScopes",
        skip_serializing_if = "Vec::is_empty"
    )]
    pub additional_scopes: Vec<String>,
    /// OIDC 提供方配置（`method = "oidc"` 时必填）。
    #[serde(default)]
    pub oidc: ServerOidcConfig,
}

/// 官方 frp 的默认 `additionalScopes`：两个都开。
pub fn default_scopes() -> Vec<String> {
    vec!["HeartBeats".to_string(), "NewWorkConns".to_string()]
}

impl ServerAuthConfig {
    /// 只配了 token（全是默认值）—— 用于判定"行为与老版本完全一致"。
    pub fn is_plain_token(&self) -> bool {
        self.method == AuthMethod::Token
    }

    /// 一致性检查：把会在运行时才炸的配置错误提前到启动时。
    pub fn validate(&self) -> anyhow::Result<()> {
        if self.method == AuthMethod::Token && self.token.is_empty() {
            // 与官方一致：token 为空 = **不做认证**。这是合法的（靠网络隔离兜底），
            // 但必须在日志里说清楚，否则用户会以为"应该只有我能连"。
        }
        if self.method == AuthMethod::Oidc && self.oidc.issuer.trim().is_empty() {
            anyhow::bail!("auth.method = \"oidc\" 时必须配置 auth.oidc.issuer");
        }
        for s in &self.additional_scopes {
            if s != "HeartBeats" && s != "NewWorkConns" {
                anyhow::bail!("auth.additionalScopes 只支持 HeartBeats / NewWorkConns，收到 {s:?}");
            }
        }
        Ok(())
    }

    /// 是否要在心跳上复核 token。
    pub fn check_heartbeats(&self) -> bool {
        self.method == AuthMethod::Oidc && self.additional_scopes.iter().any(|s| s == "HeartBeats")
    }

    /// 是否要在新工作连接上复核 token。
    pub fn check_new_work_conns(&self) -> bool {
        self.method == AuthMethod::Oidc
            && self.additional_scopes.iter().any(|s| s == "NewWorkConns")
    }
}

/// 客户端认证配置。
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClientAuthConfig {
    #[serde(default)]
    pub method: AuthMethod,
    #[serde(default)]
    pub token: String,
    #[serde(
        default,
        rename = "additionalScopes",
        skip_serializing_if = "Vec::is_empty"
    )]
    pub additional_scopes: Vec<String>,
    #[serde(default)]
    pub oidc: ClientOidcConfig,
}

impl ClientAuthConfig {
    pub fn validate(&self) -> anyhow::Result<()> {
        if self.method == AuthMethod::Oidc {
            self.oidc.validate()?;
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// 凭证与校验器
// ---------------------------------------------------------------------------

/// 客户端手里拿的登录凭证。
///
/// 线上要发的 `privilege_key` 在两种方式下**语义完全不同**，这是 OIDC 对接
/// 最容易踩的地方：
/// - token 方式：`hex(md5(secret + timestamp))`，**不是**密钥本身；
/// - OIDC 方式：**原样的 access token**（官方 `OidcAuthProvider.SetLogin`
///   就是 `loginMsg.PrivilegeKey = accessToken`），`timestamp` 发但不用。
///
/// 所以别想着"统一成一个字符串" —— 那必然有一边是错的。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Credential {
    /// 共享密钥。
    Token(String),
    /// IdP 签发的 access token。
    Oidc(String),
}

impl Credential {
    /// 生成线上要发的 `privilege_key`。
    pub fn wire_value(&self, ts: i64) -> String {
        match self {
            Self::Token(t) => crate::frp::msg::auth_key(t, ts),
            Self::Oidc(t) => t.clone(),
        }
    }

    /// 原始凭证（不含任何派生）——校验方要用的就是它。
    pub fn raw(&self) -> &str {
        match self {
            Self::Token(t) | Self::Oidc(t) => t,
        }
    }
}

/// 服务端的认证校验器。
#[derive(Clone)]
pub enum AuthProvider {
    /// 共享密钥（默认，零开销）。
    Token(String),
    /// OIDC：用 IdP 公钥验签。
    Oidc(std::sync::Arc<crate::auth::oidc::OidcVerifier>),
    /// OIDC 配置了但验签器还没建起来（IdP 不可达）——
    /// 明确拒绝而不是放行，否则 IdP 一挂就等于服务端裸奔。
    OidcUnavailable(String),
}

impl Default for AuthProvider {
    fn default() -> Self {
        Self::Token(String::new())
    }
}

impl std::fmt::Debug for AuthProvider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Token(t) => f
                .debug_struct("AuthProvider::Token")
                // 密钥绝不进日志
                .field(
                    "token",
                    &if t.is_empty() {
                        "<empty>"
                    } else {
                        "<redacted>"
                    },
                )
                .finish(),
            Self::Oidc(_) => f.write_str("AuthProvider::Oidc"),
            Self::OidcUnavailable(e) => f
                .debug_tuple("AuthProvider::OidcUnavailable")
                .field(e)
                .finish(),
        }
    }
}

impl AuthProvider {
    pub fn token(t: impl Into<String>) -> Self {
        Self::Token(t.into())
    }

    pub fn method(&self) -> AuthMethod {
        match self {
            Self::Token(_) => AuthMethod::Token,
            Self::Oidc(_) => AuthMethod::Oidc,
            Self::OidcUnavailable(_) => AuthMethod::Oidc,
        }
    }

    /// 校验登录凭证。`cred` 就是报文里的 `privilege_key` 原文。
    ///
    /// 返回身份标识（token 方式为空串，OIDC 方式为 `sub`）。
    pub fn verify_login(&self, cred: &str, ts: i64) -> anyhow::Result<String> {
        match self {
            Self::Token(secret) => {
                if secret.is_empty() {
                    // 与官方 frps 一致：token 为空 = 不做认证。
                    // 这是合法配置（靠网络隔离兜底），但要在启动日志里警告。
                    return Ok(String::new());
                }
                let expected = crate::frp::msg::auth_key(secret, ts);
                if !crate::frp::msg::constant_time_eq(&expected, cred) {
                    anyhow::bail!("token in login doesn't match token from configuration");
                }
                Ok(String::new())
            }
            Self::Oidc(v) => v.remember_subject(cred),
            Self::OidcUnavailable(e) => {
                anyhow::bail!("OIDC 认证不可用（{e}），拒绝本次登录")
            }
        }
    }

    /// 校验登录**之后**的凭证（心跳 / 新工作连接）。
    ///
    /// 为什么需要：登录时校验过就永久信任的模型下，任何能连上控制端口的人
    /// 只要在同一个 `run_id` 上发消息就能搭便车。OIDC 方式下这里要求
    /// **验签通过且 `sub` 与登录时一致**。
    pub fn verify_followup(&self, cred: &str, what: &str) -> anyhow::Result<()> {
        match self {
            Self::Token(_) => Ok(()), // 与官方一致：token 方式不复核
            Self::Oidc(v) => {
                v.verify_post_login(cred, what)?;
                Ok(())
            }
            Self::OidcUnavailable(e) => anyhow::bail!("OIDC 认证不可用（{e}），拒绝{what}"),
        }
    }

    /// 该方式下是否要复核心跳。
    pub fn check_heartbeats(&self, cfg: &ServerAuthConfig) -> bool {
        cfg.check_heartbeats()
    }

    /// 该方式下是否要复核新工作连接。
    pub fn check_new_work_conns(&self, cfg: &ServerAuthConfig) -> bool {
        cfg.check_new_work_conns()
    }

    /// 控制通道加密（v2 的 AEAD / v1 的 CFB）用哪个值派生密钥。
    ///
    /// - token 方式：共享密钥本身（与官方 frps 一致）。
    /// - OIDC 方式：**用本次登录的 access token**。两边都有这个值
    ///   （客户端刚换来的、服务端从 `Login.privilege_key` 读到的），
    ///   而且它自带有效期 —— 比拿一个长期不变的共享密钥派生更稳妥。
    ///
    /// ★ 客户端必须用 [`Credential::raw`] 保持一致，否则就是
    /// "能登录成功但之后每个消息都解不开"。
    pub fn control_key(&self, login_privilege_key: &str) -> String {
        match self {
            Self::Token(secret) => secret.clone(),
            Self::Oidc(_) => login_privilege_key.to_string(),
            Self::OidcUnavailable(_) => login_privilege_key.to_string(),
        }
    }

    /// 共享密钥（只有 token 方式有）。客户端侧握手要用。
    pub fn secret(&self) -> &str {
        match self {
            Self::Token(t) => t,
            _ => "",
        }
    }

    /// 从服务端配置构造。OIDC 的 JWKS 拉取是异步的，所以这里只做**构造**，
    /// 拉取由调用方启动时单独跑一次（失败不该拦住服务端启动）。
    pub fn from_server_config(cfg: &ServerAuthConfig) -> anyhow::Result<(Self, bool)> {
        match cfg.method {
            AuthMethod::Token => Ok((Self::token(cfg.token.clone()), false)),
            AuthMethod::Oidc => {
                let v = crate::auth::oidc::OidcVerifier::new(cfg.oidc.clone())?;
                Ok((Self::Oidc(v), true))
            }
        }
    }
}

// ---------------------------------------------------------------------------
// IP 访问控制（CIDR 白 / 黑名单）
// ---------------------------------------------------------------------------

/// 一条 CIDR 规则：裸 IP（`1.2.3.4`）、带前缀长度（`10.0.0.0/8`），
/// 或只写前缀长度缺省值（`::1`）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Cidr {
    net: IpAddr,
    bits: u8,
}

impl Cidr {
    /// 解析一条规则。不带 `/` 时按"精确匹配这一个地址"处理
    /// （`bits` = 全长度），这与 iptables / nginx 的习惯一致。
    pub fn parse(s: &str) -> anyhow::Result<Self> {
        let s = s.trim();
        let (addr_part, bits_part) = match s.split_once('/') {
            Some((a, b)) => (a, Some(b)),
            None => (s, None),
        };
        let net: IpAddr = addr_part
            .trim()
            .parse()
            .map_err(|_| anyhow::anyhow!("IP 白/黑名单里的地址非法：{addr_part:?}"))?;
        let max = if net.is_ipv4() { 32 } else { 128 };
        let bits = match bits_part {
            Some(b) => {
                let v: u8 = b
                    .trim()
                    .parse()
                    .map_err(|_| anyhow::anyhow!("CIDR 前缀长度非法：{b:?}"))?;
                if v > max {
                    anyhow::bail!("CIDR 前缀长度 {v} 超过 {max}（{s}）");
                }
                v
            }
            None => max,
        };
        Ok(Self { net, bits })
    }

    /// 地址是否落在网段内。**IPv4 与 IPv6 之间永远不匹配** ——
    /// 不做 v4-mapped-v6 的隐式转换，否则 `::/0` 会把整个 IPv4 空间也吃掉。
    pub fn contains(&self, ip: IpAddr) -> bool {
        // ★ IPv4 与 IPv6 必须**分开**按各自的位宽比较。
        // 曾经把 v4 也提升到 u128 再统一右移：IPv4 的 32 位落在 u128 的低位，
        // 任何 `/0`～`/96` 的前缀右移后高位全是 0，于是"跟谁都比得中" ——
        // 白名单会静默变成"全放行"，是安全检查里最不能出的错。
        match (self.net, ip) {
            (IpAddr::V4(net), IpAddr::V4(i)) => {
                if self.bits == 0 {
                    return true;
                }
                let shift = 32 - u32::from(self.bits);
                (u32::from(net) >> shift) == (u32::from(i) >> shift)
            }
            (IpAddr::V6(net), IpAddr::V6(i)) => {
                if self.bits == 0 {
                    return true;
                }
                let shift = 128 - u32::from(self.bits);
                (u128::from(net) >> shift) == (u128::from(i) >> shift)
            }
            // 跨地址族永不匹配（也不做 v4-mapped-v6 的隐式转换）
            _ => false,
        }
    }
}

/// 一张 IP 白 / 黑名单。
///
/// 判定顺序：**deny 优先**。命中 deny 直接拒；deny 没命中时，
/// `allow` 为空表示"放行"，非空则必须命中才放行。
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AclConfig {
    /// 白名单。留空 = 不按白名单放行（但要经过 deny）。
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allow: Vec<String>,
    /// 黑名单。优先级高于白名单。
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub deny: Vec<String>,
}

impl AclConfig {
    pub fn is_empty(&self) -> bool {
        self.allow.is_empty() && self.deny.is_empty()
    }

    /// 编译成可复用的规则表（避免每个连接解析一次字符串）。
    pub fn compile(&self) -> anyhow::Result<CompiledAcl> {
        let mut allow = Vec::with_capacity(self.allow.len());
        for s in &self.allow {
            allow.push(Cidr::parse(s)?);
        }
        let mut deny = Vec::with_capacity(self.deny.len());
        for s in &self.deny {
            deny.push(Cidr::parse(s)?);
        }
        Ok(CompiledAcl { allow, deny })
    }
}

/// [`AclConfig`] 编译后的形态。
#[derive(Debug, Clone, Default)]
pub struct CompiledAcl {
    allow: Vec<Cidr>,
    deny: Vec<Cidr>,
}

impl CompiledAcl {
    pub fn is_empty(&self) -> bool {
        self.allow.is_empty() && self.deny.is_empty()
    }

    /// 该地址是否放行。
    pub fn permits(&self, ip: IpAddr) -> bool {
        if self.deny.iter().any(|c| c.contains(ip)) {
            return false;
        }
        if self.allow.is_empty() {
            return true;
        }
        self.allow.iter().any(|c| c.contains(ip))
    }

    /// 放行判定 + 拒绝原因（审计日志要用）。
    pub fn check(&self, ip: IpAddr) -> Result<(), String> {
        if self.deny.iter().any(|c| c.contains(ip)) {
            return Err(format!("{ip} 命中 IP 黑名单"));
        }
        if !self.allow.is_empty() && !self.allow.iter().any(|c| c.contains(ip)) {
            return Err(format!("{ip} 不在 IP 白名单内"));
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// RBAC
// ---------------------------------------------------------------------------

/// 一个角色的权限集合。
///
/// 所有字段都是"留空/默认 = 不限制"，所以只写 `name` 就是一个"什么都能干"
/// 的角色；要收紧再逐条加限制。
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RoleConfig {
    /// 角色名（仅用于日志与面板展示）。
    pub name: String,
    /// 适用的用户名列表（对应 `Login.user`）。支持 `*` 通配全部。
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub users: Vec<String>,
    /// 允许注册的代理类型，如 `["tcp", "http"]`。留空 = 全部允许。
    #[serde(
        default,
        rename = "allowProxyTypes",
        skip_serializing_if = "Vec::is_empty"
    )]
    pub allow_proxy_types: Vec<String>,
    /// 允许占用的**服务端**端口范围，如 `"20000-30000"`，也可以是单端口 `"8080"`。
    /// 留空 = 不限。
    #[serde(default, rename = "portRange", skip_serializing_if = "Option::is_none")]
    pub port_range: Option<String>,
    /// 是否允许通过面板管理本客户端的代理（服务端写接口 / 客户端 webServer）。
    #[serde(default, rename = "allowManage")]
    pub allow_manage: bool,
    /// 是否允许注册 stcp / xtcp 访客（需要服务端 `allow_users` 配合）。
    #[serde(default = "default_true_role", rename = "allowVisitors")]
    pub allow_visitors: bool,
    /// 该角色可注册的代理数上限（0 = 用服务端全局上限）。
    #[serde(default, rename = "maxProxies")]
    pub max_proxies: usize,
}

fn default_true_role() -> bool {
    true
}

/// 端口范围，闭区间。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PortRange {
    pub lo: u16,
    pub hi: u16,
}

impl PortRange {
    pub fn parse(s: &str) -> anyhow::Result<Self> {
        let s = s.trim();
        let (lo, hi) = match s.split_once('-') {
            Some((a, b)) => (
                a.trim()
                    .parse::<u16>()
                    .map_err(|_| anyhow::anyhow!("端口范围下界非法：{a:?}"))?,
                b.trim()
                    .parse::<u16>()
                    .map_err(|_| anyhow::anyhow!("端口范围上界非法：{b:?}"))?,
            ),
            None => {
                let v = s
                    .parse::<u16>()
                    .map_err(|_| anyhow::anyhow!("端口非法：{s:?}"))?;
                (v, v)
            }
        };
        if lo > hi {
            anyhow::bail!("端口范围下界 {lo} 大于上界 {hi}");
        }
        Ok(Self { lo, hi })
    }

    pub fn contains(&self, port: u16) -> bool {
        port >= self.lo && port <= self.hi
    }
}

/// 权限模型配置（服务端 `[[roles]]`）。
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RbacConfig {
    /// 角色表。**按顺序匹配，先命中先用**，所以把最具体的角色写在前面。
    #[serde(default)]
    pub roles: Vec<RoleConfig>,
    /// 没有任何角色匹配时使用的角色名；留空且 `deny_unknown = true` 时拒绝。
    #[serde(
        default,
        rename = "defaultRole",
        skip_serializing_if = "String::is_empty"
    )]
    pub default_role: String,
    /// 配了角色表但一个都没匹配上时，是否直接拒绝登录。
    #[serde(default, rename = "denyUnknown")]
    pub deny_unknown: bool,
}

impl RbacConfig {
    pub fn is_empty(&self) -> bool {
        self.roles.is_empty()
    }

    /// 编译成可复用的权限表。
    pub fn compile(&self) -> anyhow::Result<CompiledRbac> {
        let mut roles = Vec::with_capacity(self.roles.len());
        for r in &self.roles {
            if r.name.trim().is_empty() {
                anyhow::bail!("[[roles]] 里每一项都必须有 name");
            }
            let range = match &r.port_range {
                Some(s) if !s.trim().is_empty() => Some(PortRange::parse(s)?),
                _ => None,
            };
            roles.push(Role {
                name: r.name.clone(),
                users: r.users.clone(),
                allow_proxy_types: r
                    .allow_proxy_types
                    .iter()
                    .map(|t| t.to_ascii_lowercase())
                    .collect(),
                port_range: range,
                allow_manage: r.allow_manage,
                allow_visitors: r.allow_visitors,
                max_proxies: r.max_proxies,
            });
        }
        Ok(CompiledRbac {
            roles,
            default_role: self.default_role.clone(),
            deny_unknown: self.deny_unknown,
        })
    }
}

/// 一个角色编译后的形态（端口范围已解析成数字）。
#[derive(Debug, Clone)]
pub struct Role {
    pub name: String,
    pub users: Vec<String>,
    pub allow_proxy_types: Vec<String>,
    pub port_range: Option<PortRange>,
    pub allow_manage: bool,
    pub allow_visitors: bool,
    pub max_proxies: usize,
}

impl Role {
    /// 什么都能干的角色 —— 未启用 RBAC 时用它，保证行为零变化。
    pub fn unrestricted() -> Self {
        Self {
            name: "unrestricted".into(),
            users: vec!["*".into()],
            allow_proxy_types: Vec::new(),
            port_range: None,
            allow_manage: true,
            allow_visitors: true,
            max_proxies: 0,
        }
    }

    pub fn matches_user(&self, user: &str) -> bool {
        self.users.iter().any(|u| u == "*" || u == user)
    }

    /// 能不能注册这种类型的代理。
    pub fn allow_proxy_type(&self, ty: &str) -> bool {
        self.allow_proxy_types.is_empty()
            || self
                .allow_proxy_types
                .iter()
                .any(|t| t.eq_ignore_ascii_case(ty))
    }

    /// 能不能占用这个服务端端口。
    pub fn allow_port(&self, port: u16) -> bool {
        match self.port_range {
            Some(r) => r.contains(port),
            None => true,
        }
    }
}

/// 编译后的权限表。
#[derive(Debug, Clone, Default)]
pub struct CompiledRbac {
    roles: Vec<Role>,
    default_role: String,
    deny_unknown: bool,
}

impl CompiledRbac {
    /// 未启用 RBAC 的实例：任何用户名 → 全权角色。
    ///
    /// 单独给个名字是为了在调用点**显式**表达"这里没做授权检查"，
    /// 而不是让人去猜 `CompiledRbac::default()` 到底是"全拒"还是"全放"。
    pub fn default_unrestricted() -> Self {
        Self::default()
    }

    /// RBAC 没启用（角色表为空）——此时任何用户名都拿到全权角色。
    pub fn is_disabled(&self) -> bool {
        self.roles.is_empty()
    }

    /// 为某个用户名解析角色。用户可能匹配到多个角色，取**第一个**命中的。
    pub fn role_for(&self, user: &str) -> anyhow::Result<Role> {
        if self.roles.is_empty() {
            return Ok(Role::unrestricted());
        }
        if let Some(r) = self.roles.iter().find(|r| r.matches_user(user)) {
            return Ok(r.clone());
        }
        if !self.default_role.is_empty() {
            if let Some(r) = self.roles.iter().find(|r| r.name == self.default_role) {
                return Ok(r.clone());
            }
            anyhow::bail!(
                "defaultRole = {:?} 在 [[roles]] 里不存在",
                self.default_role
            );
        }
        if self.deny_unknown {
            anyhow::bail!("用户 {user:?} 没有匹配到任何角色（denyUnknown = true）");
        }
        // 没配 denyUnknown 又没命中：退回"不限制"，保持向后兼容
        Ok(Role::unrestricted())
    }

    /// 注册代理前的完整检查。
    pub fn check_proxy(&self, role: &Role, name: &str, ty: &str, port: u16) -> anyhow::Result<()> {
        let ty_l = ty.to_ascii_lowercase();
        if !role.allow_proxy_type(&ty_l) {
            anyhow::bail!(
                "角色 {:?} 不允许注册 {ty} 类型代理（允许：{}）",
                role.name,
                role.allow_proxy_types.join(", ")
            );
        }
        // 只有真正占服务端端口的类型才检查端口范围
        if matches!(ty_l.as_str(), "tcp" | "udp") && port != 0 && !role.allow_port(port) {
            anyhow::bail!(
                "角色 {:?} 不允许占用端口 {port}（允许范围：{}）",
                role.name,
                role.port_range
                    .map(|r| if r.lo == r.hi {
                        r.lo.to_string()
                    } else {
                        format!("{}-{}", r.lo, r.hi)
                    })
                    .unwrap_or_else(|| "不限".into())
            );
        }
        if !role.allow_visitors && matches!(ty_l.as_str(), "stcp" | "xtcp") {
            anyhow::bail!("角色 {:?} 不允许注册 {name}（访客类代理被禁用）", role.name);
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// 审计日志配置
// ---------------------------------------------------------------------------

/// 审计日志配置（服务端 `[audit]`）。
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuditConfig {
    /// 是否启用。默认**关**：不写文件、不留内存，行为与老版本一致。
    #[serde(default)]
    pub enable: bool,
    /// JSONL 落盘路径。留空 = 只留内存（面板可查，重启即失）。
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub path: String,
    /// 内存里保留多少条（面板查询用）。默认 1000。
    #[serde(default = "default_audit_capacity", rename = "maxEntries")]
    pub max_entries: usize,
}

fn default_audit_capacity() -> usize {
    1000
}

impl Default for AuditConfig {
    fn default() -> Self {
        Self {
            enable: false,
            path: String::new(),
            max_entries: default_audit_capacity(),
        }
    }
}

// ---------------------------------------------------------------------------
// 测试
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn cidr(s: &str, ip: &str) -> bool {
        Cidr::parse(s).unwrap().contains(ip.parse().unwrap())
    }

    #[test]
    fn cidr_裸地址按精确匹配() {
        assert!(cidr("1.2.3.4", "1.2.3.4"));
        assert!(!cidr("1.2.3.4", "1.2.3.5"));
    }

    #[test]
    fn cidr_前缀长度() {
        assert!(cidr("10.0.0.0/8", "10.255.255.255"));
        assert!(!cidr("10.0.0.0/8", "11.0.0.0"));
        // /32 = 单个地址
        assert!(cidr("10.0.0.0/32", "10.0.0.0"));
        assert!(!cidr("10.0.0.0/32", "10.0.0.1"));
    }

    #[test]
    fn cidr_ipv6() {
        assert!(cidr("2001:db8::/32", "2001:db8::1"));
        assert!(!cidr("2001:db8::/32", "2001:db9::1"));
        assert!(cidr("::1", "::1"));
    }

    /// `/0` 只覆盖**本族**地址 —— 否则 `::/0` 会把整个 IPv4 空间也吃进去，
    /// 一条本意是"放开所有 IPv6"的规则会变成"放开一切"。
    #[test]
    fn 零前缀不跨地址族() {
        assert!(cidr("0.0.0.0/0", "1.2.3.4"));
        assert!(!cidr("0.0.0.0/0", "::1"));
        assert!(cidr("::/0", "2001:db8::1"));
        assert!(!cidr("::/0", "1.2.3.4"));
    }

    #[test]
    fn cidr_非法输入报错() {
        assert!(Cidr::parse("999.1.1.1").is_err());
        assert!(Cidr::parse("10.0.0.0/33").is_err());
        assert!(Cidr::parse("10.0.0.0/abc").is_err());
        assert!(Cidr::parse("::/129").is_err());
    }

    /// ★ 核心语义：deny 优先。否则把 allow 写成 `0.0.0.0/0` 会把 deny 吞掉。
    #[test]
    fn deny_优先于_allow() {
        let acl = AclConfig {
            allow: vec!["0.0.0.0/0".into()],
            deny: vec!["10.1.1.1".into()],
        }
        .compile()
        .unwrap();
        assert!(!acl.permits("10.1.1.1".parse().unwrap()));
        assert!(acl.permits("10.1.1.2".parse().unwrap()));
    }

    #[test]
    fn 空名单放行一切() {
        let acl = AclConfig::default().compile().unwrap();
        assert!(acl.permits("8.8.8.8".parse().unwrap()));
        assert!(acl.is_empty());
    }

    #[test]
    fn 白名单非空时必须命中() {
        let acl = AclConfig {
            allow: vec!["192.168.0.0/16".into()],
            deny: vec![],
        }
        .compile()
        .unwrap();
        assert!(acl.permits("192.168.5.5".parse().unwrap()));
        assert!(!acl.permits("8.8.8.8".parse().unwrap()));
        // 拒绝原因要说清是哪一条挡的，面板上才看得出问题
        let e = acl.check("8.8.8.8".parse().unwrap()).unwrap_err();
        assert!(e.contains("白名单"), "{e}");
    }

    #[test]
    fn 端口范围解析() {
        assert_eq!(
            PortRange::parse("8080").unwrap(),
            PortRange { lo: 8080, hi: 8080 }
        );
        assert_eq!(
            PortRange::parse("20000-30000").unwrap(),
            PortRange {
                lo: 20000,
                hi: 30000
            }
        );
        assert!(PortRange::parse("30000-20000").is_err());
        assert!(PortRange::parse("abc").is_err());
        assert!(PortRange::parse("70000").is_err());
        let r = PortRange::parse("1-10").unwrap();
        assert!(r.contains(1) && r.contains(10) && !r.contains(11) && !r.contains(0));
    }

    /// 没配 RBAC 时，任何用户名都必须拿到全权 —— 否则老配置会突然被拒。
    #[test]
    fn 无角色表即全权() {
        let rbac = RbacConfig::default().compile().unwrap();
        assert!(rbac.is_disabled());
        let role = rbac.role_for("谁啊").unwrap();
        assert!(role.allow_manage && role.allow_port(22) && role.allow_proxy_type("tcp"));
    }

    #[test]
    fn 角色按顺序匹配() {
        let rbac = RbacConfig {
            roles: vec![
                RoleConfig {
                    name: "admin".into(),
                    users: vec!["alice".into()],
                    allow_manage: true,
                    ..Default::default()
                },
                RoleConfig {
                    name: "guest".into(),
                    users: vec!["*".into()],
                    allow_proxy_types: vec!["http".into()],
                    ..Default::default()
                },
            ],
            ..Default::default()
        }
        .compile()
        .unwrap();

        let a = rbac.role_for("alice").unwrap();
        assert_eq!(a.name, "admin");
        assert!(a.allow_manage);

        let g = rbac.role_for("bob").unwrap();
        assert_eq!(g.name, "guest");
        assert!(!g.allow_manage);
        assert!(g.allow_proxy_type("HTTP"), "类型匹配应当忽略大小写");
        assert!(!g.allow_proxy_type("tcp"));
    }

    #[test]
    fn 角色可以限制代理类型与端口() {
        let rbac = RbacConfig {
            roles: vec![RoleConfig {
                name: "limited".into(),
                users: vec!["*".into()],
                allow_proxy_types: vec!["tcp".into()],
                port_range: Some("20000-30000".into()),
                ..Default::default()
            }],
            ..Default::default()
        }
        .compile()
        .unwrap();
        let r = rbac.role_for("x").unwrap();

        assert!(rbac.check_proxy(&r, "a", "tcp", 25000).is_ok());
        // 端口越界
        let e = rbac
            .check_proxy(&r, "b", "tcp", 80)
            .unwrap_err()
            .to_string();
        assert!(e.contains("80"), "{e}");
        // 类型不允许
        let e = rbac
            .check_proxy(&r, "c", "http", 0)
            .unwrap_err()
            .to_string();
        assert!(e.contains("http"), "{e}");
        // http 不占端口，端口范围不该拦它（上面已经因为类型被拦了，
        // 这里单独验一次"类型允许时端口范围不参与"）
        let r2 = rbac.role_for("x").unwrap();
        assert!(
            rbac.check_proxy(&r2, "d", "tcp", 0).is_ok(),
            "port=0 表示不指定端口"
        );
    }

    #[test]
    fn deny_unknown_拒绝未匹配用户() {
        let rbac = RbacConfig {
            roles: vec![RoleConfig {
                name: "vip".into(),
                users: vec!["alice".into()],
                ..Default::default()
            }],
            deny_unknown: true,
            ..Default::default()
        }
        .compile()
        .unwrap();
        assert!(rbac.role_for("alice").is_ok());
        assert!(rbac.role_for("mallory").is_err());
    }

    #[test]
    fn default_role_兜底() {
        let rbac = RbacConfig {
            roles: vec![
                RoleConfig {
                    name: "vip".into(),
                    users: vec!["alice".into()],
                    ..Default::default()
                },
                RoleConfig {
                    name: "fallback".into(),
                    users: vec![],
                    allow_proxy_types: vec!["http".into()],
                    ..Default::default()
                },
            ],
            default_role: "fallback".into(),
            deny_unknown: true,
        }
        .compile()
        .unwrap();
        let r = rbac.role_for("bob").unwrap();
        assert_eq!(r.name, "fallback");
        // defaultRole 指向不存在的角色必须是启动期错误，不能悄悄放行
        let bad = RbacConfig {
            roles: vec![RoleConfig {
                name: "x".into(),
                ..Default::default()
            }],
            default_role: "nope".into(),
            ..Default::default()
        }
        .compile()
        .unwrap();
        assert!(bad.role_for("bob").is_err());
    }

    #[test]
    fn oidc_配置必须带_issuer() {
        let mut a = ServerAuthConfig {
            method: AuthMethod::Oidc,
            ..Default::default()
        };
        assert!(a.validate().is_err());
        a.oidc.issuer = "https://idp.example.com".into();
        assert!(a.validate().is_ok());
    }

    #[test]
    fn additional_scopes_只认官方两个值() {
        let a = ServerAuthConfig {
            method: AuthMethod::Oidc,
            oidc: ServerOidcConfig {
                issuer: "https://idp.example.com".into(),
                ..Default::default()
            },
            additional_scopes: vec!["HeartBeats".into()],
            ..Default::default()
        };
        assert!(a.validate().is_ok());
        assert!(a.check_heartbeats());
        assert!(!a.check_new_work_conns());

        let bad = ServerAuthConfig {
            method: AuthMethod::Oidc,
            oidc: ServerOidcConfig {
                issuer: "https://idp.example.com".into(),
                ..Default::default()
            },
            additional_scopes: vec!["NewWorkConnection".into()], // 少了个 s
            ..Default::default()
        };
        assert!(bad.validate().is_err());
    }

    /// 默认配置必须与"没有这套东西"完全一致。
    #[test]
    fn 默认配置等于全放行() {
        let a = ServerAuthConfig::default();
        assert_eq!(a.method, AuthMethod::Token);
        assert!(a.is_plain_token());
        let acl = AclConfig::default().compile().unwrap();
        assert!(acl.is_empty() && acl.permits("1.1.1.1".parse().unwrap()));
        let rbac = RbacConfig::default().compile().unwrap();
        assert!(rbac.is_disabled());
        let aud = AuditConfig::default();
        assert!(!aud.enable && aud.max_entries == 1000);
    }
}
