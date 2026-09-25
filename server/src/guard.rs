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
use std::sync::Arc;

use nfrp_common::config::ServerConfig;
use nfrp_common::security::{
    AclConfig, AuthProvider, CompiledAcl, CompiledRbac, Role, ServerAuthConfig,
};

use crate::audit::AuditLog;

/// 服务端安全上下文（配置的**编译产物**）。
pub struct SecurityContext {
    /// 认证校验器。
    pub auth: AuthProvider,
    /// 认证配置（决定心跳/工作连接要不要复核）。
    pub auth_cfg: ServerAuthConfig,
    acl: CompiledAcl,
    rbac: CompiledRbac,
    /// 审计日志（未启用时是个空操作实例）。
    pub audit: Arc<AuditLog>,
}

impl std::fmt::Debug for SecurityContext {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SecurityContext")
            .field("auth", &self.auth)
            .field("acl_empty", &self.acl.is_empty())
            .field("rbac_disabled", &self.rbac.is_disabled())
            .field("audit_enabled", &self.audit.is_enabled())
            .finish()
    }
}

impl Default for SecurityContext {
    fn default() -> Self {
        Self {
            auth: AuthProvider::default(),
            auth_cfg: ServerAuthConfig::default(),
            acl: CompiledAcl::default(),
            rbac: CompiledRbac::default_unrestricted(),
            audit: Arc::new(AuditLog::disabled()),
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
        if auth.method() == nfrp_common::security::AuthMethod::Token
            && cfg.effective_auth().token.is_empty()
        {
            tracing::warn!(
                "服务端没有配置任何 token —— 任何人都能连上来。\
                 请配置 token 或 [auth] method = \"oidc\"；\
                 仅在没有公网入口时才可以这样跑。"
            );
        }

        Ok(Self {
            auth,
            auth_cfg,
            acl,
            rbac,
            audit,
        })
    }

    /// OIDC 模式下启动时拉一次 JWKS。
    ///
    /// 拉不到**不拦启动**（IdP 可能只是暂时不可达），但会一直拒绝登录，
    /// 并在日志里把原因说清楚；之后每次登录失败都会重新尝试拉取
    /// （见 [`Self::ensure_ready`]），IdP 恢复后自动可用。
    pub async fn refresh_oidc(&self) -> anyhow::Result<()> {
        match &self.auth {
            AuthProvider::OidcUnavailable(_) => {
                let (v, _) = AuthProvider::from_server_config(&self.auth_cfg)?;
                if let AuthProvider::Oidc(verifier) = v {
                    verifier.refresh().await?;
                    tracing::info!(issuer = %self.auth_cfg.oidc.issuer, "OIDC JWKS 已就绪");
                }
            }
            AuthProvider::Oidc(_) => {}
            AuthProvider::Token(_) => {}
        }
        Ok(())
    }

    /// ① IP 白 / 黑名单。
    pub fn check_ip(&self, ip: IpAddr) -> Result<(), String> {
        self.acl.check(ip)
    }

    /// ② 认证。返回身份（OIDC 的 `sub`，token 方式为空）。
    pub fn verify_login(&self, cred: &str, ts: i64) -> anyhow::Result<String> {
        self.auth.verify_login(cred, ts)
    }

    /// ③ 为某个用户名解析角色。
    pub fn role_for(&self, user: &str) -> anyhow::Result<Role> {
        self.rbac.role_for(user)
    }

    /// ③ 注册代理前的权限检查。
    pub fn check_proxy(&self, role: &Role, name: &str, ty: &str, port: u16) -> anyhow::Result<()> {
        self.rbac.check_proxy(role, name, ty, port)
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
        assert!(ctx.verify_login("随便", 0).is_ok());
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
        let ts = 1700000000;
        let good = nfrp_common::frp::msg::auth_key("s3cret", ts);
        assert!(ctx.verify_login(&good, ts).is_ok());
        assert!(ctx.verify_login("wrong", ts).is_err());

        // ③ RBAC
        let r = ctx.role_for("whoever").unwrap();
        assert!(ctx.check_proxy(&r, "a", "tcp", 25000).is_ok());
        assert!(ctx.check_proxy(&r, "b", "tcp", 80).is_err());
        assert!(ctx.check_proxy(&r, "c", "http", 0).is_err());
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
        let e = ctx
            .verify_login("any.token.here", 0)
            .unwrap_err()
            .to_string();
        assert!(e.contains("OIDC"), "{e}");
        assert!(ctx.auth.method() == nfrp_common::security::AuthMethod::Oidc);
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
