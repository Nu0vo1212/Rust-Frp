//! 服务端的安全守卫：把认证 / ACL / RBAC / 审计四件事收在一处。
//!
//! 不把它们散在 `serve.rs` 各处，是因为这四者**共用同一份配置快照**，
//! 而且判定的**顺序**是有约束的：
//!
//! ```text
//!   连上来 ──▶ ① ACL（IP 白/黑名单）      ← 最便宜，先挡掉
//!          ──▶ ② 认证（token / OIDC）     ← 决定"你是谁"
//!          ──▶ ③ RBAC（你能不能加这条代理）← 决定"你能干什么"
//!          ──▶ ④ 审计（谁在什么时候做了什么）← 前面每一步都要留痕
//! ```
//!
//! 顺序反过来会出问题：先认证再查 ACL 意味着攻击者能用无效凭证把
//! 认证路径刷爆（OIDC 上一次失败就是一次 JWKS 验签，很贵）。
//!
//! # 关闭时零开销
//!
//! 四件都关（默认）时，[`SecurityContext`] 里的判定就是几条空 `Vec` 的
//! `is_empty()` —— 不构造事件、不查表、不分配。

use std::net::IpAddr;
use std::sync::{Arc, RwLock};

use nfrp_common::config::ServerConfig;
use nfrp_common::security::{
    AclConfig, AuthProvider, CompiledAcl, CompiledRbac, Role, ServerAuthConfig,
};

use crate::audit::AuditLog;

/// 认证校验器，可**在运行期被替换**。
///
/// ★ v0.5.3 修：这里原来是裸的 `AuthProvider`（普通字段 + 外层 `Arc<SecurityContext>`），
/// 于是 `refresh_oidc(&self)` 拿不到 `&mut`，**拉到的 JWKS 根本没法回填** ——
/// 旧代码在 `refresh_oidc` 里新建一个 verifier、拉完就让它随函数结束被 drop，
/// `self.auth` 永远是 `OidcUnavailable`。后果是配了 `method = "oidc"` 的服务端
/// **拒绝所有人登录**（fail-closed，无绕过，但功能是死的）。
/// 换成 `Arc<RwLock<...>>` 之后刷新才能真正生效。
pub type AuthSlot = Arc<RwLock<AuthProvider>>;

/// 服务端安全上下文（配置的**编译产物**）。
pub struct SecurityContext {
    /// 认证校验器（可热替换 —— OIDC 的 JWKS 拉取成功后要回填）。
    pub auth: AuthSlot,
    /// 认证配置（决定心跳/工作连接要不要复核）。
    pub auth_cfg: ServerAuthConfig,
    acl: CompiledAcl,
    rbac: CompiledRbac,
    /// 审计日志（未启用时是个空操作实例）。
    pub audit: Arc<AuditLog>,
    /// 凭证时间戳允许的偏差秒数（0 = 显式关闭）。
    ///
    /// ★ v0.5.7（第六轮审计 G-1）：放在这里而不是每个调用点各传一次 ——
    ///   让"校验凭证"与"查新鲜性"用**同一个**来源，调用方没有机会漏。
    max_clock_skew_secs: u64,
}

impl SecurityContext {
    /// 读当前认证校验器（短临界区，只 clone 一份 `AuthProvider`）。
    ///
    /// 锁中毒时沿用项目口径（`unwrap_or_else(|e| e.into_inner())`）：
    /// 毒化只意味着"之前有线程 panic 过"，校验器本身仍可用，
    /// 在这里直接 panic 会把一次偶发故障放大成永久不可用。
    pub fn auth(&self) -> AuthProvider {
        self.auth.read().unwrap_or_else(|e| e.into_inner()).clone()
    }

    /// 凭证时间戳允许的偏差秒数（**所有**凭证校验路径都该用它）。
    pub fn max_clock_skew_secs(&self) -> u64 {
        self.max_clock_skew_secs
    }
}

impl std::fmt::Debug for SecurityContext {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SecurityContext")
            .field("auth", &self.auth())
            .field("acl_empty", &self.acl.is_empty())
            .field("rbac_disabled", &self.rbac.is_disabled())
            .field("audit_enabled", &self.audit.is_enabled())
            .finish()
    }
}

impl Default for SecurityContext {
    fn default() -> Self {
        Self {
            auth: Arc::new(RwLock::new(AuthProvider::default())),
            auth_cfg: ServerAuthConfig::default(),
            acl: CompiledAcl::default(),
            rbac: CompiledRbac::default_unrestricted(),
            audit: Arc::new(AuditLog::disabled()),
            // 默认与 `ServerConfig::default_max_clock_skew()` 保持一致（300 秒）。
            // 测试里直接构造 `SecurityContext::default()` 时也应当有窗口，
            // 否则测试会掩盖"忘了传 skew"的问题。
            max_clock_skew_secs: 300,
        }
    }
}

impl SecurityContext {
    /// 从服务端配置编译。
    ///
    /// 任何一处配置写错都**在启动时报错**，而不是等到某个客户端连上来才炸 ——
    /// 尤其是 CIDR / 端口范围这类字符串，写错了没人会主动去发现。
    pub fn from_config(cfg: &ServerConfig) -> anyhow::Result<Self> {
        let auth_cfg = cfg.effective_auth();
        auth_cfg.validate()?;
        let (auth, needs_refresh) = AuthProvider::from_server_config(&auth_cfg)?;
        let auth = if needs_refresh {
            // OIDC 的 JWKS 要联网拉，构造函数里不做（异步 + 可能超时）。
            // 拉取在 `serve_with` 启动时单独跑一次；这里先标记为"未就绪"，
            // 于是"IdP 拉不到"时是**明确拒绝登录**，而不是放行。
            AuthProvider::OidcUnavailable("JWKS 尚未拉取".into())
        } else {
            auth
        };
        let acl = cfg.acl.compile()?;
        if !cfg.acl.is_empty() {
            tracing::info!(
                allow = cfg.acl.allow.len(),
                deny = cfg.acl.deny.len(),
                "已启用 IP 白/黑名单（deny 优先）"
            );
        }
        let rbac = cfg.rbac_config().compile()?;
        if !rbac.is_disabled() {
            tracing::info!(roles = cfg.roles.len(), "已启用基于角色的权限校验");
        }
        let audit = Arc::new(AuditLog::from_config(&cfg.audit)?);
        if audit.is_enabled() {
            tracing::info!(
                path = ?audit.path(),
                capacity = cfg.audit.max_entries,
                "已启用审计日志"
            );
        }

        // token 为空又开着 OIDC？那 OIDC 才是实际生效的，不用说"没有认证"。
        //
        // ★ v0.5.6（审计总报告 M6）：改用唯一真源 `ServerConfig::has_no_auth()`。
        //   原先这里是就地写的一套口径（`auth.method() == Token &&
        //   cfg.effective_auth().token.is_empty()`），而 `main.rs` 那边用的是
        //   裸的 `cfg.token.is_empty()` —— **两套口径必然漂移一处**：
        //   纯 OIDC 部署会被 main.rs 误报成"没有认证，任何人都能连"。
        //   本处的口径本来就是对的，收进 `has_no_auth()` 让两处共用。
        if cfg.has_no_auth() {
            tracing::warn!(
                "服务端没有配置任何 token —— 任何人都能连上来。\
                 请配置 token 或 [auth] method = \"oidc\"；\
                 仅在没有公网入口时才可以这样跑。"
            );
        }

        Ok(Self {
            auth: Arc::new(RwLock::new(auth)),
            auth_cfg,
            acl,
            rbac,
            audit,
            max_clock_skew_secs: cfg.max_clock_skew_secs,
        })
    }

    /// OIDC 模式下启动时拉一次 JWKS，**成功后真正回填** `self.auth`。
    ///
    /// 拉不到**不拦启动**（IdP 可能只是暂时不可达），但会一直拒绝登录，
    /// 并在日志里把原因说清楚；之后每次登录失败都会重新尝试拉取
    /// （见 [`Self::refresh_oidc`] 自身的幂等性 + `serve.rs` 的登录失败路径），
    /// IdP 恢复后自动可用。
    ///
    /// ★★ v0.5.3 修（这是一个真实的功能性缺陷）：
    ///
    /// 旧实现是：
    /// ```ignore
    /// match &self.auth {
    ///     AuthProvider::OidcUnavailable(_) => {
    ///         let (v, _) = AuthProvider::from_server_config(&self.auth_cfg)?;
    ///         if let AuthProvider::Oidc(verifier) = v {
    ///             verifier.refresh().await?;      // ← 拉成功了……
    ///             info!("OIDC JWKS 已就绪");
    ///         }
    ///     }                                       // ← ……然后 verifier 在这里被 drop
    ///     ...
    /// }
    /// ```
    /// `self.auth` 是普通字段（外层 `Arc<SecurityContext>`），`&self` 拿不到 `&mut`，
    /// 所以拉到的 JWKS **没有任何地方能存**，`self.auth` 永远停在 `OidcUnavailable`
    /// ⇒ 配了 `method = "oidc"` 的服务端**拒绝所有人登录**，且日志还写着"已就绪"。
    /// 更糟的是文档引用的 `Self::ensure_ready` **全仓根本不存在**（那句注释在说谎）。
    ///
    /// 现在 `auth` 是 `Arc<RwLock<AuthProvider>>`，可以真正写回。
    pub async fn refresh_oidc(&self) -> anyhow::Result<()> {
        // 已经是可用状态就不用再拉
        if matches!(self.auth(), AuthProvider::Oidc(_)) {
            return Ok(());
        }
        let current = self.auth();
        if !matches!(current, AuthProvider::OidcUnavailable(_)) {
            return Ok(()); // token 方式，与 OIDC 无关
        }

        // 新建一个 verifier 去拉 JWKS（拉取失败时保留 OidcUnavailable，继续拒绝登录）
        let (v, needs_refresh) = AuthProvider::from_server_config(&self.auth_cfg)?;
        if !needs_refresh {
            return Ok(());
        }
        let AuthProvider::Oidc(verifier) = v else {
            return Ok(());
        };
        verifier.refresh().await?;

        // ★ 关键：把拉好的 verifier 写回去，否则这次刷新等于白做
        match self.auth.write() {
            Ok(mut g) => *g = AuthProvider::Oidc(verifier),
            Err(e) => *e.into_inner() = AuthProvider::Oidc(verifier),
        }
        tracing::info!(issuer = %self.auth_cfg.oidc.issuer, "OIDC JWKS 已就绪");
        Ok(())
    }

    /// ① IP 白 / 黑名单。
    pub fn check_ip(&self, ip: IpAddr) -> Result<(), String> {
        self.acl.check(ip)
    }

    /// ② 认证。返回身份（OIDC 的 `sub`，token 方式为空）。
    ///
    /// `run_id` 会把 OIDC 的 subject 绑定到本会话（v0.5.3）。
    pub fn verify_login(&self, cred: &str, ts: i64, run_id: &str) -> anyhow::Result<String> {
        // 取一份当前快照（短锁），避免在验签（可能很贵）期间占着读锁。
        let auth = self.auth();
        // 新鲜性校验在 `verify_login` 内部完成（`skew` 是必需参数）——
        // 这里把配置里的窗口传进去，调用方**没有机会漏**。
        auth.verify_login(cred, ts, run_id, self.max_clock_skew_secs)
    }

    /// 校验**原始 token**（SSH 网关专用，见 `common::security::verify_raw_token`）。
    ///
    /// SSH 网关的 `--token` 是用户在 SSH 命令行里输入的原始值，不是
    /// `auth_key(token, ts)` 派生值，所以不能走 [`Self::verify_login`]。
    pub fn verify_raw_token(&self, raw: &str) -> anyhow::Result<String> {
        self.auth().verify_raw_token(raw)
    }

    /// 只做新鲜性校验（不校验凭证内容）。
    ///
    /// 给"自己手写凭证比对"的路径用：工作连接在 token 模式下是就地
    /// `auth_key(token, ts)` 比对的，不适合整体改走 `verify_login`
    /// （那条路径还要处理"空 token / 空凭证 / 能力位"三种兼容形态）。
    ///
    /// ★ 但"忘了调它"这件事本身是 G-1 的成因，所以：
    ///   1. 工作连接那处**已经改成调用 `verify_login`**，本函数目前只作为
    ///      纵深防御与测试入口保留；
    ///   2. 新增的 `visitor` / `p2p` 两处走
    ///      [`nfrp_common::security::verify_shared_secret_proof`]，
    ///      那里的新鲜性校验是**嵌在函数体里**的，不是可选项。
    pub fn check_freshness(&self, ts: i64, what: &str) -> anyhow::Result<()> {
        nfrp_common::security::check_freshness(ts, self.max_clock_skew_secs, what)
    }

    /// ② 心跳 / 工作连接的后续复核。判据与登录一致，走同一份当前校验器。
    ///
    /// `run_id` 必需：要求 token 的 subject 与**该会话**登录时的一致。
    pub fn verify_followup(&self, key: &str, what: &str, run_id: &str) -> anyhow::Result<()> {
        let auth = self.auth();
        auth.verify_followup(key, what, run_id)
    }

    /// 会话结束时解除 OIDC subject 绑定。
    pub fn forget_session(&self, run_id: &str) {
        let auth = self.auth();
        auth.forget_session(run_id);
    }

    /// 当前认证方式（决定心跳/工作连接要不要复核）。
    pub fn auth_method(&self) -> nfrp_common::security::AuthMethod {
        self.auth().method()
    }

    /// ③ 为某个用户名解析角色。
    pub fn role_for(&self, user: &str) -> anyhow::Result<Role> {
        self.rbac.role_for(user)
    }

    /// ③ 注册代理前的权限检查。`used_proxies` 见 [`CompiledRbac::check_proxy`]。
    pub fn check_proxy(
        &self,
        role: &Role,
        name: &str,
        ty: &str,
        port: u16,
        used_proxies: usize,
    ) -> anyhow::Result<()> {
        self.rbac.check_proxy(role, name, ty, port, used_proxies)
    }

    pub fn rbac(&self) -> &CompiledRbac {
        &self.rbac
    }

    pub fn acl(&self) -> &CompiledAcl {
        &self.acl
    }
}

/// 让配置里的 [`AclConfig`] 能被直接编译（类型别名方便调用方）。
pub type AclSource = AclConfig;

#[cfg(test)]
mod tests {
    use super::*;
    use nfrp_common::security::{AuditConfig, RoleConfig};

    fn cfg_with<F: FnOnce(&mut ServerConfig)>(f: F) -> ServerConfig {
        let mut c = ServerConfig::default();
        f(&mut c);
        c
    }

    #[test]
    fn 默认配置不改变任何行为() {
        let ctx = SecurityContext::from_config(&ServerConfig::default()).unwrap();
        assert!(ctx.acl().is_empty());
        assert!(ctx.rbac().is_disabled());
        assert!(!ctx.audit.is_enabled());
        // 默认 token 为空 = 不校验（与官方 frps 一致）
        //
        // ★ v0.5.7：时间戳要用**当前时间** —— `verify_login` 现在自带
        //   新鲜性校验（G-1 修复），传 0（1970）会被窗口先拦下，
        //   那样就测不到"空 token 不校验凭证"这件事了。
        assert!(ctx
            .verify_login("随便", nfrp_common::util::now_unix_secs() as i64, "run-x")
            .is_ok());
        // 任何人都拿到全权
        let r = ctx.role_for("anyone").unwrap();
        assert!(r.allow_manage && r.allow_port(22));
        // 没有 ACL 时任何 IP 都放行
        assert!(ctx.check_ip("8.8.8.8".parse().unwrap()).is_ok());
    }

    #[test]
    fn acl_在构造期就校验格式() {
        let c = cfg_with(|c| {
            c.acl = AclConfig {
                allow: vec!["不是网段".into()],
                deny: vec![],
            };
        });
        let e = SecurityContext::from_config(&c).unwrap_err().to_string();
        assert!(e.contains("非法"), "{e}");
    }

    #[test]
    fn rbac_在构造期就校验端口范围() {
        let c = cfg_with(|c| {
            c.roles = vec![RoleConfig {
                name: "x".into(),
                port_range: Some("30000-20000".into()),
                ..Default::default()
            }];
        });
        assert!(SecurityContext::from_config(&c).is_err());
    }

    #[test]
    fn 完整链路_acl_认证_权限() {
        let c = cfg_with(|c| {
            c.token = "s3cret".into();
            c.acl = AclConfig {
                allow: vec!["10.0.0.0/8".into()],
                deny: vec!["10.9.9.9".into()],
            };
            c.roles = vec![RoleConfig {
                name: "dev".into(),
                users: vec!["*".into()],
                allow_proxy_types: vec!["tcp".into()],
                port_range: Some("20000-30000".into()),
                ..Default::default()
            }];
        });
        let ctx = SecurityContext::from_config(&c).unwrap();

        // ① ACL
        assert!(ctx.check_ip("10.1.2.3".parse().unwrap()).is_ok());
        assert!(
            ctx.check_ip("10.9.9.9".parse().unwrap()).is_err(),
            "deny 优先"
        );
        assert!(
            ctx.check_ip("8.8.8.8".parse().unwrap()).is_err(),
            "不在白名单"
        );

        // ② 认证：正确的 md5 才过
        //
        // ★ v0.5.7：用**当前时间**（原先写死 1700000000 = 2023-11-14）。
        //   `verify_login` 现在自带新鲜性校验，写死的时间戳会被窗口拦下，
        //   于是这条测试会"因为过期而失败"而不是"因为凭证对而通过"。
        let ts = nfrp_common::util::now_unix_secs() as i64;
        let good = nfrp_common::frp::msg::auth_key("s3cret", ts);
        assert!(ctx.verify_login(&good, ts, "run-1").is_ok());
        assert!(ctx.verify_login("wrong", ts, "run-1").is_err());

        // ★ 新增（G-1 回归）：**同一个正确凭证、换成过期的时间戳必须被拒**。
        //   这是漏洞的核心：原先"凭证对"就放行，不看有多旧。
        let stale_ts = ts - 365 * 24 * 3600; // 一年前
        let stale_good = nfrp_common::frp::msg::auth_key("s3cret", stale_ts);
        assert!(
            ctx.verify_login(&stale_good, stale_ts, "run-1").is_err(),
            "一年前的正确凭证必须被拒（否则就是无限期重放）"
        );

        // ③ RBAC
        let r = ctx.role_for("whoever").unwrap();
        assert!(ctx.check_proxy(&r, "a", "tcp", 25000, 0).is_ok());
        assert!(ctx.check_proxy(&r, "b", "tcp", 80, 0).is_err());
        assert!(ctx.check_proxy(&r, "c", "http", 0, 0).is_err());
    }

    #[test]
    fn oidc_未就绪时拒绝登录而不是放行() {
        let c = cfg_with(|c| {
            c.auth = ServerAuthConfig {
                method: nfrp_common::security::AuthMethod::Oidc,
                oidc: nfrp_common::auth::oidc::ServerOidcConfig {
                    issuer: "https://idp.example.com".into(),
                    ..Default::default()
                },
                ..Default::default()
            };
        });
        let ctx = SecurityContext::from_config(&c).unwrap();
        // JWKS 还没拉：必须拒绝。**绝不能**因为"验不了"就放行。
        //
        // ★ v0.5.7：时间戳要用当前时间 —— `verify_login` 现在先判新鲜性，
        //   传 0 会先撞上"时间戳超出偏差"，就测不到"OIDC 未就绪必须拒绝"了。
        //   两种失败**都拒绝**（都是 fail-closed），但这条测试要盯的是后者。
        let e = ctx
            .verify_login(
                "any.token.here",
                nfrp_common::util::now_unix_secs() as i64,
                "run-a",
            )
            .unwrap_err()
            .to_string();
        assert!(e.contains("OIDC"), "{e}");
        assert!(ctx.auth_method() == nfrp_common::security::AuthMethod::Oidc);
    }

    /// ★★ v0.5.3 回归：**认证槽必须可被写回** —— 这是 C 那个缺陷的锁定测试。
    ///
    /// 旧实现把 `auth` 做成不可变字段，`refresh_oidc` 拉到的 JWKS **没有任何
    /// 地方能存**，函数一结束 verifier 就被 drop，`self.auth` 永远停在
    /// `OidcUnavailable` ⇒ 配了 oidc 的服务端拒绝所有人登录。
    /// 这里直接锁"槽位可写、且写进去之后验签行为随之改变"这个不变量。
    #[test]
    fn 认证槽可写回_否则_oidc_永久不可用() {
        let c = cfg_with(|c| {
            c.auth = ServerAuthConfig {
                method: nfrp_common::security::AuthMethod::Oidc,
                oidc: nfrp_common::auth::oidc::ServerOidcConfig {
                    issuer: "https://idp.example.com".into(),
                    ..Default::default()
                },
                ..Default::default()
            };
        });
        let ctx = SecurityContext::from_config(&c).unwrap();

        // 初始：未就绪，拒绝登录（fail-closed）
        assert!(matches!(ctx.auth(), AuthProvider::OidcUnavailable(_)));
        assert!(ctx.verify_login("t", 0, "run-a").is_err());

        // 模拟"JWKS 拉取成功、verifier 被回填"
        let (v, _) = AuthProvider::from_server_config(&c.effective_auth()).unwrap();
        assert!(matches!(v, AuthProvider::Oidc(_)), "应当构造出 Oidc 变体");
        *ctx.auth.write().unwrap() = v;

        // 槽位真的变了 —— 旧实现做不到这一点（它会永远停在 OidcUnavailable）
        assert!(
            matches!(ctx.auth(), AuthProvider::Oidc(_)),
            "回填后槽位必须是 Oidc，否则 oidc 模式永远登不上"
        );
        // 认证方式不变（仍走 OIDC 路径）
        assert_eq!(ctx.auth_method(), nfrp_common::security::AuthMethod::Oidc);
    }

    /// 刷新是幂等的：已经是可用状态时不应重复拉取（也不能把状态改坏）。
    #[tokio::test]
    async fn oidc_已就绪时刷新是空操作() {
        let c = cfg_with(|c| {
            c.auth = ServerAuthConfig {
                method: nfrp_common::security::AuthMethod::Oidc,
                oidc: nfrp_common::auth::oidc::ServerOidcConfig {
                    issuer: "https://idp.example.com".into(),
                    ..Default::default()
                },
                ..Default::default()
            };
        });
        let ctx = SecurityContext::from_config(&c).unwrap();
        let (v, _) = AuthProvider::from_server_config(&c.effective_auth()).unwrap();
        *ctx.auth.write().unwrap() = v;

        // 已是 Oidc：直接返回 Ok，不去联网
        ctx.refresh_oidc().await.unwrap();
        assert!(matches!(ctx.auth(), AuthProvider::Oidc(_)));
    }

    /// token 方式下刷新 OIDC 不应当改变任何东西。
    #[tokio::test]
    async fn token_方式下刷新_oidc_是空操作() {
        let c = cfg_with(|c| {
            c.token = "s3cret".into();
        });
        let ctx = SecurityContext::from_config(&c).unwrap();
        ctx.refresh_oidc().await.unwrap();
        assert_eq!(ctx.auth_method(), nfrp_common::security::AuthMethod::Token);
    }

    #[test]
    fn oidc_配置缺_issuer_时构造就失败() {
        let c = cfg_with(|c| {
            c.auth = ServerAuthConfig {
                method: nfrp_common::security::AuthMethod::Oidc,
                ..Default::default()
            };
        });
        assert!(SecurityContext::from_config(&c).is_err());
    }

    #[test]
    fn 审计启用后能查到登录事件() {
        let c = cfg_with(|c| {
            c.audit = AuditConfig {
                enable: true,
                path: String::new(),
                max_entries: 10,
                max_file_mb: 0, // 本用例不涉轮转
            };
        });
        let ctx = SecurityContext::from_config(&c).unwrap();
        assert!(ctx.audit.is_enabled());
        ctx.audit.record(crate::audit::AuditEvent::new(
            crate::audit::kind::LOGIN,
            true,
        ));
        assert_eq!(ctx.audit.len(), 1);
    }
}
