//! 配置文件热重载。
//!
//! ## 为什么要限制"哪些字段能热生效"
//!
//! 一股脑 reload 是最容易埋雷的做法：端口、协议、资源上限这些字段
//! 要么已经在运行中被固化（监听器早就 bind 了），要么改一半会导致
//! 新旧配置并存的状态机。所以这里明确分成两类：
//!
//! * **可热生效**：`log_level`、`dashboard_user` / `dashboard_pwd`
//!   —— 只是读一下就能生效，改错也不会让进程崩；
//! * **需要重启**：端口、token、协议、资源上限
//!   —— 检测到变化就**明确告警**并列出字段，而不是假装生效。
//!
//! 这样运维改完配置立刻知道"这次要不要重启"。

use std::{
    path::{Path, PathBuf},
    sync::Arc,
    time::{Duration, UNIX_EPOCH},
};

use rustunnel_common::{config::ServerConfig, util::LogFilterHandle};
use tracing::{info, warn};

use crate::dashboard::DashboardAuth;

/// 轮询配置文件的间隔。
const POLL_INTERVAL: Duration = Duration::from_secs(2);

/// 需要重启才能生效的字段（用于告警文案）。
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct NeedsRestart {
    pub fields: Vec<&'static str>,
}

impl NeedsRestart {
    pub fn is_empty(&self) -> bool {
        self.fields.is_empty()
    }
}

/// 比较新旧配置：能热改的直接改掉，改不了的收集起来返回。
pub fn apply_dynamic(
    old: &ServerConfig,
    new: &ServerConfig,
    log: Option<&LogFilterHandle>,
    auth: &DashboardAuth,
) -> NeedsRestart {
    let mut out = NeedsRestart::default();

    // ---- 可热生效 ----
    if old.log_level != new.log_level {
        match log {
            Some(h) if rustunnel_common::util::reload_log_level(h, &new.log_level) => {
                info!("日志级别已热更新：{} -> {}", old.log_level, new.log_level);
            }
            Some(_) => warn!(
                "日志级别格式非法，保持 {}：{}",
                old.log_level, new.log_level
            ),
            None => out.fields.push("log_level"),
        }
    }
    if old.dashboard_user != new.dashboard_user || old.dashboard_pwd != new.dashboard_pwd {
        if let Ok(mut g) = auth.write() {
            *g = if new.dashboard_user.is_empty() {
                None
            } else {
                Some((new.dashboard_user.clone(), new.dashboard_pwd.clone()))
            };
            info!("面板鉴权已热更新（用户：{}）", new.dashboard_user);
        }
    }

    // ---- 需要重启 ----
    let mut changed = |field: &'static str, differs: bool| {
        if differs {
            out.fields.push(field);
        }
    };
    changed("bind_addr", old.bind_addr != new.bind_addr);
    changed("bind_port", old.bind_port != new.bind_port);
    changed("control_port", old.control_port != new.control_port);
    changed("work_port", old.work_port != new.work_port);
    changed("token", old.token != new.token);
    changed("protocol", old.protocol != new.protocol);
    changed("tcp_mux", old.tcp_mux != new.tcp_mux);
    changed("tls_force", old.tls_force != new.tls_force);
    changed(
        "vhost_http_port",
        old.vhost_http_port != new.vhost_http_port,
    );
    changed(
        "vhost_https_port",
        old.vhost_https_port != new.vhost_https_port,
    );
    changed("subdomain_host", old.subdomain_host != new.subdomain_host);
    changed("p2p_port", old.p2p_port != new.p2p_port);
    changed("dashboard_port", old.dashboard_port != new.dashboard_port);
    changed(
        "max_total_conns",
        old.max_total_conns != new.max_total_conns,
    );
    changed("max_clients", old.max_clients != new.max_clients);
    changed(
        "max_conns_per_client",
        old.max_conns_per_client != new.max_conns_per_client,
    );
    changed(
        "max_pending_per_client",
        old.max_pending_per_client != new.max_pending_per_client,
    );
    changed(
        "max_proxies_per_client",
        old.max_proxies_per_client != new.max_proxies_per_client,
    );

    out
}

fn mtime(path: &Path) -> Option<u128> {
    let meta = std::fs::metadata(path).ok()?;
    let t = meta.modified().ok()?;
    t.duration_since(UNIX_EPOCH).ok().map(|d| d.as_millis())
}

/// 后台任务：盯着配置文件，变了就重载。
pub async fn watch(
    path: PathBuf,
    current: Arc<ServerConfig>,
    log: Option<LogFilterHandle>,
    auth: DashboardAuth,
) {
    info!("配置热重载已启用：监听 {}", path.display());
    let mut last = mtime(&path);
    loop {
        tokio::time::sleep(POLL_INTERVAL).await;
        let now = mtime(&path);
        if now == last {
            continue;
        }
        last = now;

        // 解析失败时**绝不**应用半份配置：宁可继续用旧的
        let new = match ServerConfig::load(&path) {
            Ok(c) => c,
            Err(e) => {
                warn!("配置文件有语法错误，已忽略本次变更：{e:#}");
                continue;
            }
        };
        let pending = apply_dynamic(&current, &new, log.as_ref(), &auth);
        if pending.is_empty() {
            info!("配置已热重载：{}", path.display());
        } else {
            warn!(
                "配置已部分重载；以下字段需重启服务端才能生效：{}",
                pending.fields.join(", ")
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg() -> ServerConfig {
        ServerConfig::default()
    }

    #[test]
    fn identical_config_needs_nothing() {
        let a = cfg();
        let auth: DashboardAuth = Arc::new(std::sync::RwLock::new(None));
        let pending = apply_dynamic(&a, &cfg(), None, &auth);
        assert!(
            pending.is_empty(),
            "配置没变却要求重启：{:?}",
            pending.fields
        );
    }

    #[test]
    fn log_level_change_is_applied_in_place() {
        let a = cfg();
        let mut b = cfg();
        b.log_level = "debug".into();
        let auth: DashboardAuth = Arc::new(std::sync::RwLock::new(None));
        // 没有 reload 句柄时只能列为"需要重启"
        let pending = apply_dynamic(&a, &b, None, &auth);
        assert_eq!(pending.fields, vec!["log_level"]);
    }

    #[test]
    fn dashboard_credentials_are_applied_in_place() {
        let a = cfg();
        let mut b = cfg();
        b.dashboard_user = "admin".into();
        b.dashboard_pwd = "s3cret".into();
        let auth: DashboardAuth = Arc::new(std::sync::RwLock::new(None));

        let pending = apply_dynamic(&a, &b, None, &auth);
        assert!(pending.is_empty(), "面板凭据应该能热生效");
        let stored = auth.read().unwrap().clone();
        assert_eq!(
            stored,
            Some(("admin".to_string(), "s3cret".to_string())),
            "凭据必须真的写进去"
        );

        // 清空用户名 = 关闭鉴权
        let mut c = b.clone();
        c.dashboard_user.clear();
        c.dashboard_pwd.clear();
        apply_dynamic(&b, &c, None, &auth);
        assert!(auth.read().unwrap().is_none(), "清空用户名应关闭面板鉴权");
    }

    #[test]
    fn port_and_token_changes_require_restart() {
        let a = cfg();
        let mut b = cfg();
        b.bind_port = Some(7100);
        b.token = "new-token".into();
        b.max_clients = 10;
        let auth: DashboardAuth = Arc::new(std::sync::RwLock::new(None));

        let pending = apply_dynamic(&a, &b, None, &auth);
        let f = &pending.fields;
        assert!(f.contains(&"bind_port"), "{f:?}");
        assert!(f.contains(&"token"), "{f:?}");
        assert!(f.contains(&"max_clients"), "{f:?}");
    }

    #[test]
    fn p2p_port_change_requires_restart() {
        // 牵线 UDP socket 启动后就固定了，改端口必须重启
        let a = cfg();
        let mut b = cfg();
        b.p2p_port = Some(7002);
        let auth: DashboardAuth = Arc::new(std::sync::RwLock::new(None));
        assert_eq!(apply_dynamic(&a, &b, None, &auth).fields, vec!["p2p_port"]);
    }

    #[test]
    fn mtime_of_missing_file_is_none() {
        assert!(mtime(Path::new("definitely/not/here.toml")).is_none());
    }

    #[test]
    fn mtime_of_existing_file_is_stable() {
        let dir = std::env::temp_dir().join("rustunnel-reload-test");
        std::fs::create_dir_all(&dir).ok();
        let p = dir.join("c.toml");
        std::fs::write(&p, "bind_port = 7000\n").unwrap();
        let a = mtime(&p);
        assert!(a.is_some());
        assert_eq!(a, mtime(&p), "同一个文件两次读到的 mtime 必须一致");
        std::fs::remove_dir_all(&dir).ok();
    }
}
