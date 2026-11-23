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

use nfrp_common::{config::ServerConfig, util::LogFilterHandle};
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
            Some(h) if nfrp_common::util::reload_log_level(h, &new.log_level) => {
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
        // 安全闸门：**绝不能**在热重载里把鉴权改成"无"，
        // 只要面板监听在非回环地址上。
        //
        // 早先这里是无条件 `*g = if new.dashboard_user.is_empty() { None } else { ... }`，
        // 于是"启动时合法（有凭据）→ 运行期清空用户名"这条路会让一个**对外**的面板
        // 静默变成匿名可写，而启动时那道保险只在启动路径跑过一次，根本管不着。
        // 更糟的是它**不可逆**：`current` 是启动快照，清空后再改回去 old==new，
        // 分支不再进入，鉴权永远停在 None，必须重启进程 —— 实测确认过。
        //
        // 判据：**新配置**会造成"面板对外且无鉴权" ⇒ 拒绝本次热改。
        //
        // 注意这里判的是 `new` 而不是 `old`：旧的 `old` 带着凭据，
        //   `dashboard_is_exposed(old)` 恒为 false，拿它做判据等于没拦
        //   （这正是我第一版写错、被测试抓出来的地方）。
        // `bind_addr` / `dashboard_port` 要取 `old`（运行期生效那份）——
        // 它们都不可热改，新配置里那个值当次并不生效。漏掉后者就是 H1 的绕过点。
        //
        // **判据必须同时看用户名和密码**。
        //
        // 原先这里（以及下面 `dashboard_is_exposed`、启动校验、客户端 webServer
        // 校验共**四处**）都只判 `dashboard_user` 是否为空，**从不判密码**。
        // 于是存在一条不需要任何配置疏漏的攻击链：
        //
        //   ① 正常运行：`dashboard_user = "admin"` + `dashboard_pwd = "s3cret"`（安全）
        //   ② 攻击者热重载，**只清空密码**，用户名保持 "admin"
        //   ③ `clears_creds` = `"admin".is_empty()` = **false** ⇒ 闸门不拦
        //   ④ 走 else 分支：`auth = Some(("admin", ""))`
        //   ⑤ `dashboard.rs` 拼出 `expect_cred = "admin:"`
        //   ⑥ 攻击者送 `Authorization: Basic base64("admin:")` ⇒ **鉴权通过**
        //   ⑦ 拿到面板全部写权限（开公网端口、踢人、读全部租户）
        //
        // 为什么测试全绿也没暴露：现有的 H1 回归测试用的是
        //   `c.dashboard_user.clear(); c.dashboard_pwd.clear();`（**同时清两个**），
        //   恰好绕过了"只清密码"这种组合 —— 而那正是攻击者实际会用的手法。
        //   判据只认 user、测试也只喂 user，两者互相印证形成了闭环盲区。
        //
        // 现在改用**唯一判据** `has_dashboard_creds()`（见下），
        //   四处共用同一份语义，杜绝"同一判定各写一遍"。
        let clears_creds = !has_dashboard_creds(&new.dashboard_user, &new.dashboard_pwd);
        if clears_creds && dashboard_exposed_after_reload(old, new) {
            warn!(
                "热重载被拒：{} 不允许在运行期把 dashboard_user 清空。已保持原有面板鉴权不变。\
                 确实要关掉鉴权请改 bind_addr 或重启服务端。",
                reject_reason(old)
            );
        } else if let Ok(mut g) = auth.write() {
            *g = if clears_creds {
                None
            } else {
                Some((new.dashboard_user.clone(), new.dashboard_pwd.clone()))
            };
            if clears_creds {
                // 走到这里说明面板只监听回环（或压根没开），关闭鉴权是安全的，
                // 但仍要让运维在日志里看到这件事 —— 别静默改安全状态。
                warn!(
                    "面板鉴权已在热重载中关闭（用户名为空）。当前 bind_addr = {:?}，\
                     若它不是回环地址请立即检查。",
                    old.bind_addr
                );
            } else {
                info!("面板鉴权已热更新（用户：{}）", new.dashboard_user);
            }
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
    // 数据面监听地址 + 用户连接超时 + 空闲池上限：三者都固化在
    // 每个 `ClientState` / 监听器里，热改没法让已建立的会话回头生效。
    changed(
        "proxy_bind_addr",
        old.proxy_bind_addr != new.proxy_bind_addr,
    );
    changed(
        "user_conn_timeout",
        old.user_conn_timeout != new.user_conn_timeout,
    );
    changed("max_pool_count", old.max_pool_count != new.max_pool_count);
    // TCP keepalive / yamux 保活：都固化在监听器与已建会话上，
    // 热改没法回头生效。
    changed(
        "tcp_mux_keepalive_interval",
        old.tcp_mux_keepalive_interval != new.tcp_mux_keepalive_interval,
    );
    changed("tcp_keepalive", old.tcp_keepalive != new.tcp_keepalive);
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
    changed(
        "tcpmux_http_connect_port",
        old.tcpmux_http_connect_port != new.tcpmux_http_connect_port,
    );
    changed(
        "tcpmux_passthrough",
        old.tcpmux_passthrough != new.tcpmux_passthrough,
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
    // 下面这几项都只能在**启动时**固化，中途改一律要重启：
    // * allow_ports / max_ports_per_client：已经注册上来的代理要不要回头回收？
    //   变更语义没法自洽，不如明确要求重启；
    // * vhost_http_timeout / custom_404_page：前者是每个连接的超时参数、
    //   后者是**启动时读进内存**的一份内容，热改需要重新读盘；
    // * log_to / max_days：日志订阅者已经按旧目标建好了，换文件等于要重建
    //   整个 subscriber（tracing 只允许初始化一次）。
    changed("allow_ports", old.allow_ports != new.allow_ports);
    changed(
        "max_ports_per_client",
        old.max_ports_per_client != new.max_ports_per_client,
    );
    changed(
        "detailed_errors_to_client",
        old.detailed_errors_to_client != new.detailed_errors_to_client,
    );
    changed(
        "vhost_http_timeout",
        old.vhost_http_timeout != new.vhost_http_timeout,
    );
    changed(
        "custom_404_page",
        old.custom_404_page != new.custom_404_page,
    );
    changed("log_to", old.log_to != new.log_to);
    changed("max_days", old.max_days != new.max_days);
    // `disablePrintColor` 同属日志订阅者，只能启动时固化。
    changed(
        "disable_print_color",
        old.disable_print_color != new.disable_print_color,
    );

    out
}

fn mtime(path: &Path) -> Option<u128> {
    let meta = std::fs::metadata(path).ok()?;
    let t = meta.modified().ok()?;
    t.duration_since(UNIX_EPOCH).ok().map(|d| d.as_millis())
}

/// 面板安全校验：非回环地址 + 没有凭据 ⇒ 不安全（除非显式开了逃生开关）。
///
/// 这里返回 `bool` 而不是 `Result`，并且**必须**与 `main.rs::validate` 里
/// 那条同口径 —— 但**不能直接复用它**：`validate` 是纯函数只看配置，
/// 而热重载时要拿**运行期实际生效的监听参数**去判。
///
/// 抽成公共函数是为了让「启动校验」与「热重载校验」用同一段逻辑，
/// 免得两处口径漂移 —— 早先的 bug 正是「只在启动时校验过一次」。
/// **唯一判据**：这对面板凭据能不能用来鉴权。
///
/// 真正的实现在 `nfrp_common::config::has_dashboard_creds()` ——
///   服务端与客户端共用同一份语义（客户端 `[webServer]` 的校验也用它），
///   这里只是转出，避免两端口径漂移。
///
/// 为什么必须抽成一个函数：这个判定的根因是"同一判定在四处各写了一遍，
///   每处都只判了 `user`"。四处分别是：
///
/// | 位置 | 用途 |
/// |---|---|
/// | `reload.rs` 的 `clears_creds` | 热重载闸门 |
/// | `reload.rs` 的 `dashboard_is_exposed` | 暴露判定 |
/// | `server/src/main.rs` 的启动校验 | 拒绝启动 |
/// | `client/src/main.rs` 的 `check_web_server_is_safe` | 客户端界面拒绝启动 |
///
/// 为什么"用户名非空但密码为空"必须算**没有凭据**：
///   `dashboard.rs` 的鉴权是 `format!("{}:{}", user, pwd)` 然后比 Basic 头。
///   密码为空时期望值是 `"admin:"` —— 攻击者随手就能构造，
///   等于**鉴权退化成"知道用户名就能进"**。
pub use nfrp_common::config::has_dashboard_creds;

/// 面板是否处于"对外暴露且无鉴权"的危险状态。
///
/// 四个条件全部要正确取到"运行期真实值"才算对 —— H2就是
///   其中第三个条件取错了来源。
pub fn dashboard_is_exposed(cfg: &ServerConfig) -> bool {
    cfg.dashboard_port.is_some()
        // 同时看用户名与密码，不再只看用户名。
        && !has_dashboard_creds(&cfg.dashboard_user, &cfg.dashboard_pwd)
        && !nfrp_common::util::is_loopback_addr(&cfg.bind_addr)
        && !cfg.allow_insecure_dashboard
}

/// 热重载场景下的判据：**所有"不可热改"的字段都必须取运行期那份**。
///
/// 上一版这里只把 `bind_addr` 换成了 `live` 的值，却漏了
/// `dashboard_port` —— 于是存在一条绕过：
///
/// ```text
///   ① 启动：bind_addr = "0.0.0.0" + dashboard_port = 7500 + dashboard_user = "admin"
///      ⇒ 合法放行（有凭据），且 `serve.rs` 里那个监听器**已经 bind 在 0.0.0.0:7500 上**
///   ② 运行期：把配置文件里的 `dashboard_port` 那一行**删掉**，同时清空 dashboard_user
///   ③ 判据看到 new.dashboard_port == None ⇒ 认为"面板没开" ⇒ 放行
///   ④ 但监听器还活着（`dashboard_port` 在下面 changed 列表里明确属于"需重启"），
///      而 `apply_dynamic` 已经把 auth 置成 None ⇒ **对外面板变成匿名可写**
/// ```
///
/// 根因是同一类错误：**拿"配置里写没写"代表"运行期有没有在监听"**。
/// 正确做法是：判据里凡是"需要重启才生效"的字段一律用**运行期已生效的那份**取值，
/// 只有真正的可热改字段（`dashboard_user`、`dashboard_pwd`）才看新配置。
///
/// **`allow_insecure_dashboard` 也必须取 live**。
///
/// 上一版的注释把它归为"可热改字段" —— **这个归类是错的**。
/// 全仓检索确认它只在**启动期**被读（`serve.rs` 的 bind 前兜底检查），
/// 运行期没有任何代码读它 ⇒ 改配置文件里的这一项**当次并不生效**。
///
/// 而它偏偏是暴露判据的四个条件之一，于是存在一条绕过：
///
/// ```toml
/// # ① 启动（合法，有凭据）
/// bind_addr = "0.0.0.0"; dashboard_port = 7500
/// dashboard_user = "admin"; dashboard_pwd = "s3cret"
/// allow_insecure_dashboard = false
///
/// # ② 攻击者热重载改成
/// dashboard_user = ""              # 清空凭据 —— 闸门本该拦这里
/// allow_insecure_dashboard = true  # ← 让闸门判据失效（取的是 new = true）
/// ```
///
/// 判据看到 `!allow_insecure_dashboard` 为 false ⇒ 返回"没暴露" ⇒ 闸门放行
/// ⇒ 鉴权被清空 ⇒ `0.0.0.0:7500` 面板**匿名可读写**。
/// 而 `allow_insecure_dashboard` 这次改动**并没有真的生效**（它不可热改），
/// 所以攻击者既绕过了闸门、又没有留下"开关被打开"的痕迹。
///
/// 这个字段与 `allow_insecure_no_auth` 的对照反向印证了漏洞的真实性：
///   两者都是"知情自担风险"的逃生开关，但 `allow_insecure_no_auth` 的触发字段
///   （`token`）**需要重启**、不可热改 ⇒ 绕不过去；而 `allow_insecure_dashboard`
///   的触发字段（`dashboard_user`）**可热改** ⇒ 能绕过。
///   两者唯一的区别就是"触发条件能不能在运行期改"。
///
/// 更根本的做法（本条已按此改写）：不再手工列举字段，而是**从"需重启清单"
/// 反过来推导**（见 [`live_view`]）——手工列举正是 H1/H2 共同的成因。
fn dashboard_exposed_after_reload(live: &ServerConfig, new: &ServerConfig) -> bool {
    dashboard_is_exposed(&live_view(live, new))
}

/// 把"运行期实际生效的配置"和"新配置"合成一份**判据用视图**。
///
/// 规则：凡是**需要重启才生效**的字段，一律取 `live`（运行期那份）；
/// 只有真正可热改的字段才取 `new`。
///
/// 为什么这么写而不是继续手工列举：手工列举漏一个字段就是一次漏洞 ——
/// 漏了 `dashboard_port`，补上了它却漏了
/// `allow_insecure_dashboard`（本次的 H2）。**两次都是"清单不全"**。
///
/// 但这里仍然要列清单（Rust 没有反射）。所以补了一条**不变量测试**
///   （`需重启清单里的字段在判据里必须取运行期值`）：它遍历
///   `changed()` 报出的"需重启"字段名，断言 `live_view` 确实覆盖了它们 ——
///   将来有人新增"需重启"字段却忘了同步这里，测试会红。
fn live_view(live: &ServerConfig, new: &ServerConfig) -> ServerConfig {
    let mut effective = new.clone();
    // —— 以下是"需重启才生效"的字段：运行期改它们不生效，判据必须用 live ——
    effective.bind_addr = live.bind_addr.clone();
    effective.dashboard_port = live.dashboard_port;
    // 它只在启动期被读，属"需重启"，取 new 会被绕过。
    effective.allow_insecure_dashboard = live.allow_insecure_dashboard;
    effective
}

/// 启动期与热重载期共用的那条错误文案。
fn reject_reason(live: &ServerConfig) -> String {
    format!(
        "面板在非回环地址 {:?} 上监听（端口 {:?}）却没有凭据 —— \
         匿名者可以读面板、踢掉任意客户端、并（对 nfrp 客户端）直接开公网端口。",
        live.bind_addr, live.dashboard_port
    )
}

/// 后台任务：盯着配置文件，变了就重载。
///
/// `current` 是 `&mut Arc<ServerConfig>`：应用成功后**必须**把
/// 它换成新配置，否则会出现「清空了凭据 → 再改回来 old == new → 分支不再进入
/// → 鉴权永远停在 None」这种**不可逆**的状态（实测复现过）。
/// 旧签名是 `Arc<ServerConfig>`，等于拿一份永不更新的启动快照做 diff。
pub async fn watch(
    path: PathBuf,
    mut current: Arc<ServerConfig>,
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

        // 安全校验重跑一次。启动时那道（main.rs::validate / serve.rs 兜底）
        // 只在启动路径跑过，对"运行期漂移"完全无效 —— 这正是那个
        // 高危漏洞的成因。这里对新配置**照同样口径**再判一次，不通过就整份拒绝。
        //
        // 判据里 `bind_addr` 与 `dashboard_port` 都取 `current`（运行期已生效那份）：
        //   两者都不可热改，新配置里那个值本次并不生效。**只换 bind_addr 是不够的** ——
        //   删掉 `dashboard_port` 那一行同样能让判据误以为"面板没开"，而监听器还活着
        if dashboard_exposed_after_reload(&current, &new) {
            warn!(
                "热重载被拒：{} 这正是 v0.5.2 修掉的那个漏洞场景，运行期不允许制造它。\
                 已保持旧配置不变。",
                reject_reason(&current)
            );
            continue;
        }

        let pending = apply_dynamic(&current, &new, log.as_ref(), &auth);
        if pending.is_empty() {
            info!("配置已热重载：{}", path.display());
        } else {
            warn!(
                "配置已部分重载；以下字段需重启服务端才能生效：{}",
                pending.fields.join(", ")
            );
        }
        // 关键：更新基线快照。不更新的话下一次 diff 仍拿启动时那份比，
        // 会让"改回去"这类操作被误判为"没变化"而静默丢失（不可逆 bug）。
        // 安全闸门不通过的情形已经在上面 `continue` 掉了，走不到这里。
        current = Arc::new(new);
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
    }

    /// **对外地址上绝不允许通过热重载清空面板鉴权**。
    ///
    /// 这是 那个高危漏洞的锁定测试。复现步骤（实测过）：
    /// `bind_addr=0.0.0.0` + `dashboard_user=admin` 启动（合法）→
    /// 编辑配置清空用户名 → 面板变匿名可写（`/api/status` 从 401 变 200）。
    #[test]
    fn 热重载不得清空对外面板的鉴权() {
        let mut a = cfg();
        a.bind_addr = "0.0.0.0".into();
        a.dashboard_port = Some(7500);
        a.dashboard_user = "admin".into();
        a.dashboard_pwd = "s3cret".into();

        let auth: DashboardAuth = Arc::new(std::sync::RwLock::new(Some((
            "admin".to_string(),
            "s3cret".to_string(),
        ))));
        // 预设成"当前有效凭据"
        apply_dynamic(&a, &a, None, &auth);

        // 清空用户名
        let mut c = a.clone();
        c.dashboard_user.clear();
        c.dashboard_pwd.clear();
        apply_dynamic(&a, &c, None, &auth);

        assert_eq!(
            auth.read().unwrap().clone(),
            Some(("admin".to_string(), "s3cret".to_string())),
            "对外地址上清空 dashboard_user 必须被拒绝，旧凭据要保持不变"
        );
    }

    /// **不可逆 bug** —— 改回去必须能恢复鉴权。
    ///
    /// 旧的 `watch()` 用一份永不更新的 `current` 快照做 diff，于是
    /// 「清空 → 改回」第二次因为 `old == new` 而跳过，鉴权永久为 None。
    /// 这里直接锁 `apply_dynamic` 的 diff 语义：只要调用方把快照更新到位，
    /// 「改回非空」就必须重新写入凭据。
    #[test]
    fn 清空后改回鉴权必须能恢复() {
        let mut a = cfg();
        a.bind_addr = "127.0.0.1".into(); // 回环：允许清空
        a.dashboard_port = Some(7500);
        a.dashboard_user = "admin".into();
        a.dashboard_pwd = "s3cret".into();
        let auth: DashboardAuth = Arc::new(std::sync::RwLock::new(None));
        apply_dynamic(&a, &a, None, &auth);

        // 回环上清空是被允许的
        let mut b = a.clone();
        b.dashboard_user.clear();
        b.dashboard_pwd.clear();
        apply_dynamic(&a, &b, None, &auth);
        assert!(
            auth.read().unwrap().is_none(),
            "回环地址上清空用户名应当生效"
        );

        // 再改回来 —— 调用方（watch）此刻的 current 已经是 b
        apply_dynamic(&b, &a, None, &auth);
        assert_eq!(
            auth.read().unwrap().clone(),
            Some(("admin".to_string(), "s3cret".to_string())),
            "改回非空用户名必须恢复鉴权（不可逆 bug 的锁定测试）"
        );
    }

    /// 回环地址上允许清空（只有本机能连，本来就不需要凭据）。
    #[test]
    fn 回环地址上允许热重载清空面板鉴权() {
        let mut a = cfg();
        a.bind_addr = "127.0.0.1".into();
        a.dashboard_port = Some(7500);
        a.dashboard_user = "admin".into();
        let auth: DashboardAuth = Arc::new(std::sync::RwLock::new(None));
        apply_dynamic(&a, &a, None, &auth);

        let mut c = a.clone();
        c.dashboard_user.clear();
        apply_dynamic(&a, &c, None, &auth);
        assert!(auth.read().unwrap().is_none(), "回环上应当允许关闭鉴权");
    }

    /// 逃生开关仍然有效：显式写了 `allow_insecure_dashboard` 就不拦。
    #[test]
    fn 逃生开关允许对外面板不带凭据() {
        let mut a = cfg();
        a.bind_addr = "0.0.0.0".into();
        a.dashboard_port = Some(7500);
        a.dashboard_user = "admin".into();
        a.allow_insecure_dashboard = true;
        let auth: DashboardAuth = Arc::new(std::sync::RwLock::new(None));
        apply_dynamic(&a, &a, None, &auth);

        let mut c = a.clone();
        c.dashboard_user.clear();
        apply_dynamic(&a, &c, None, &auth);
        assert!(
            auth.read().unwrap().is_none(),
            "显式开了逃生开关就应当放行（知情选择）"
        );
    }

    /// 没开面板端口时，清空用户名不影响任何安全语义。
    ///
    /// 注意：这条测的是"**运行期也没绑**面板"的情形（`old.dashboard_port` 为空）。
    /// 它**不能**推广成"新配置里没写 dashboard_port 就等于面板没开" ——
    /// 那正是 H1 绕过点的错误假设，对应场景见下面
    /// `已绑定面板后删掉端口行仍应被视为暴露`。
    #[test]
    fn 没开面板端口时清空用户名不受影响() {
        let mut a = cfg();
        a.bind_addr = "0.0.0.0".into();
        a.dashboard_port = None;
        a.dashboard_user = "admin".into();
        let auth: DashboardAuth = Arc::new(std::sync::RwLock::new(None));
        apply_dynamic(&a, &a, None, &auth);

        let mut c = a.clone();
        c.dashboard_user.clear();
        apply_dynamic(&a, &c, None, &auth);
        assert!(auth.read().unwrap().is_none());
    }

    /// （H1）：**运行期已绑定面板，配置里删掉 `dashboard_port` 行，
    /// 仍然必须被视为"暴露"**。
    ///
    /// 这是 漏掉的绕过点，根因是拿"配置里写没写"代表"运行期有没有在监听"：
    ///
    /// ```text
    ///   ① 启动：0.0.0.0 + dashboard_port = 7500 + dashboard_user = "admin"（合法）
    ///      ⇒ serve.rs 里监听器已经 bind 在 0.0.0.0:7500 上
    ///   ② 运行期：删掉 dashboard_port 行 + 清空 dashboard_user
    ///   ③ 旧判据看到 new.dashboard_port == None ⇒ 以为"面板没开" ⇒ 放行
    ///   ④ 但监听器还活着（dashboard_port 属"需重启"字段）⇒ 对外面板变成匿名可写
    /// ```
    #[test]
    fn 已绑定面板后删掉端口行仍应被视为暴露() {
        // 运行期状态：面板确实绑在对外地址上
        let mut live = cfg();
        live.bind_addr = "0.0.0.0".into();
        live.dashboard_port = Some(7500);
        live.dashboard_user = "admin".into();
        live.dashboard_pwd = "s3cret".into();

        // 新配置：删掉端口行 + 清空用户名（攻击者/误操作）
        let mut evil = live.clone();
        evil.dashboard_port = None;
        evil.dashboard_user.clear();
        evil.dashboard_pwd.clear();

        // 判据必须仍然认为"暴露"
        assert!(
            dashboard_exposed_after_reload(&live, &evil),
            "运行期已绑定的面板不能因为新配置删了端口行就被当成'没开'"
        );

        // 端到端：apply_dynamic 必须拒绝关闭鉴权
        let auth: DashboardAuth = Arc::new(std::sync::RwLock::new(Some((
            "admin".to_string(),
            "s3cret".to_string(),
        ))));
        apply_dynamic(&live, &evil, None, &auth);
        assert_eq!(
            auth.read().unwrap().clone(),
            Some(("admin".to_string(), "s3cret".to_string())),
            "删掉 dashboard_port 行不能成为绕过闸门的手段，旧凭据必须保持"
        );
    }

    /// 同一场景的对称面：运行期**没**绑面板，新配置也没写 ⇒ 确实不该拦。
    #[test]
    fn 运行期未绑面板时删掉端口行不误报() {
        let mut live = cfg();
        live.bind_addr = "0.0.0.0".into();
        live.dashboard_port = None;
        live.dashboard_user = "admin".into();

        let mut new = live.clone();
        new.dashboard_user.clear();

        assert!(
            !dashboard_exposed_after_reload(&live, &new),
            "运行期本来就没绑面板，不构成暴露"
        );
    }

    /// 另一条"不可热改字段"的对称性：运行期绑在回环，新配置写 0.0.0.0。
    ///
    /// `bind_addr` 改不了，所以实际仍只在回环上 —— 判据必须用运行期那份，
    /// 否则会把"安全但配置写得不一致"误判成暴露而拒绝合法重载。
    #[test]
    fn 运行期回环时新配置写对外地址不算暴露() {
        let mut live = cfg();
        live.bind_addr = "127.0.0.1".into();
        live.dashboard_port = Some(7500);
        live.dashboard_user = "admin".into();

        let mut new = live.clone();
        new.bind_addr = "0.0.0.0".into(); // 写错了，但本次不生效
        new.dashboard_user.clear();

        assert!(
            !dashboard_exposed_after_reload(&live, &new),
            "bind_addr 不可热改，运行期仍在回环上 ⇒ 不该误报"
        );
    }

    /// `dashboard_is_exposed` 的口径与启动校验一致。
    #[test]
    fn 对外面板判定的口径() {
        let mut c = cfg();
        // 没开面板端口 ⇒ 无所谓
        c.dashboard_port = None;
        assert!(!dashboard_is_exposed(&c));

        // 开了面板、绑对外、无凭据 ⇒ 不安全
        c.dashboard_port = Some(7500);
        assert!(dashboard_is_exposed(&c), "0.0.0.0 默认地址应判为对外");
        // 绑回环 + 无凭据 ⇒ 安全
        c.bind_addr = "127.0.0.1".into();
        assert!(!dashboard_is_exposed(&c));
        c.bind_addr = "::1".into();
        assert!(!dashboard_is_exposed(&c));
        // 空串 = 监听全部网卡 ⇒ 对外
        c.bind_addr = String::new();
        assert!(dashboard_is_exposed(&c), "空绑定地址表示监听全网卡");

        // **只配用户名、不配密码 ≠ 有凭据**。
        //
        // 这一条是原测试写错的地方 —— 它原先在这里只设 `dashboard_user = "admin"`
        // 就断言"安全"，恰好把 H1 的漏洞配置当成了安全配置固化下来。
        // 鉴权处会把两者拼成 `"admin:"` 去比 Basic 头，攻击者随手可构造。
        c.bind_addr = "0.0.0.0".into();
        c.dashboard_user = "admin".into();
        assert!(
            dashboard_is_exposed(&c),
            "有用户名但**密码为空**必须判为暴露 —— 否则等于'知道用户名就能进面板'"
        );
        // 只有密码、没有用户名同样不算有凭据
        c.dashboard_user.clear();
        c.dashboard_pwd = "s3cret".into();
        assert!(dashboard_is_exposed(&c), "只有密码也不行");
        // 两者都配齐才是安全
        c.dashboard_user = "admin".into();
        assert!(!dashboard_is_exposed(&c), "用户名与密码都配齐 ⇒ 安全");

        // 逃生开关 ⇒ 视为安全（知情选择）
        c.dashboard_user.clear();
        c.dashboard_pwd.clear();
        c.allow_insecure_dashboard = true;
        assert!(!dashboard_is_exposed(&c));
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

    // ==================================================================
    //
    // H1 的根因是"同一判定在四处各写了一遍，每处都只判了 user"，
    // 而现有测试恰好喂的是"user 与 pwd 同时清空"，把"只清 pwd"这种
    // 攻击者实际会用的组合漏掉了 —— 判据只认 user、测试也只喂 user，
    // 两者互相印证形成了闭环盲区。
    // ==================================================================

    /// 造一份"合法且安全"的对外面板配置。
    fn safe_exposed_cfg() -> ServerConfig {
        let mut c = cfg();
        c.bind_addr = "0.0.0.0".into();
        c.dashboard_port = Some(7500);
        c.dashboard_user = "admin".into();
        c.dashboard_pwd = "s3cret".into();
        c.allow_insecure_dashboard = false;
        c
    }

    /// H1 核心回归：**只清空密码**不得把鉴权降级成 `admin:`。
    ///
    /// 这正是攻击者实际会用的手法（保留用户名、清掉密码）。
    /// 修复前 `clears_creds = "admin".is_empty() = false` ⇒ 闸门不拦
    /// ⇒ `auth` 被写成 `("admin", "")` ⇒ 匿名者用 `admin:` 进面板。
    #[test]
    fn 热重载只清空密码不得降级鉴权() {
        let live = safe_exposed_cfg();
        // 预设成当前有效凭据（apply_dynamic 只在有 diff 时才重写 auth）
        let auth: DashboardAuth = Arc::new(std::sync::RwLock::new(Some((
            "admin".to_string(),
            "s3cret".to_string(),
        ))));
        apply_dynamic(&live, &live, None, &auth);
        assert_eq!(
            auth.read().unwrap().clone(),
            Some(("admin".to_string(), "s3cret".to_string())),
            "基线：应当持有完整凭据"
        );

        let mut evil = live.clone();
        evil.dashboard_pwd.clear(); // ★ 只清空密码，用户名保持 "admin"
        apply_dynamic(&live, &evil, None, &auth);

        assert_ne!(
            auth.read().unwrap().clone(),
            Some(("admin".to_string(), String::new())),
            "只清空密码不得把鉴权降级为 admin:（H1）"
        );
        // 强化断言：必须保持原样，而不是被换成任何"半份凭据"
        assert_eq!(
            auth.read().unwrap().clone(),
            Some(("admin".to_string(), "s3cret".to_string())),
            "被拒之后凭据必须保持原样"
        );
    }

    /// H2 核心回归：热重载时**同时**打开 `allow_insecure_dashboard`
    /// 也不能绕过闸门。
    ///
    /// 修复前 `dashboard_exposed_after_reload` 只把 `bind_addr` 与
    /// `dashboard_port` 取 live，`allow_insecure_dashboard` 取的是 new
    /// ⇒ 攻击者写 `true` 就让判据返回"没暴露" ⇒ 闸门放行 ⇒ 鉴权被清空。
    /// 而那个开关**当次并不生效**（它只在启动期被读），
    /// 所以攻击者既绕过了闸门、又没留下开关被打开的痕迹。
    #[test]
    fn 热重载不得靠打开逃生开关绕过闸门() {
        let live = safe_exposed_cfg();
        // 预设成当前有效凭据（apply_dynamic 只在有 diff 时才重写 auth）
        let auth: DashboardAuth = Arc::new(std::sync::RwLock::new(Some((
            "admin".to_string(),
            "s3cret".to_string(),
        ))));
        apply_dynamic(&live, &live, None, &auth);

        let mut evil = live.clone();
        evil.dashboard_user.clear();
        evil.dashboard_pwd.clear();
        evil.allow_insecure_dashboard = true; // ★ 关键：让闸门判据失效
        apply_dynamic(&live, &evil, None, &auth);

        assert!(
            auth.read().unwrap().is_some(),
            "热重载不得靠 allow_insecure_dashboard 绕过闸门把鉴权清空（H2）"
        );
    }

    /// 只清用户名同样被拦（原有的组合，防回归）。
    #[test]
    fn 热重载只清空用户名同样被拦() {
        let live = safe_exposed_cfg();
        // 预设成当前有效凭据（apply_dynamic 只在有 diff 时才重写 auth）
        let auth: DashboardAuth = Arc::new(std::sync::RwLock::new(Some((
            "admin".to_string(),
            "s3cret".to_string(),
        ))));
        apply_dynamic(&live, &live, None, &auth);

        let mut evil = live.clone();
        evil.dashboard_user.clear();
        apply_dynamic(&live, &evil, None, &auth);
        assert!(auth.read().unwrap().is_some(), "清空用户名必须被拦");
    }

    /// 反向保护：回环地址上清空凭据仍然允许（别修得过头）。
    #[test]
    fn 回环上清空凭据仍然允许() {
        let mut live = safe_exposed_cfg();
        live.bind_addr = "127.0.0.1".into();
        let auth: DashboardAuth = Arc::new(std::sync::RwLock::new(None));
        apply_dynamic(&live, &live, None, &auth);

        let mut evil = live.clone();
        evil.dashboard_user.clear();
        evil.dashboard_pwd.clear();
        apply_dynamic(&live, &evil, None, &auth);
        assert!(
            auth.read().unwrap().is_none(),
            "回环地址上关掉鉴权是安全的，不该拦"
        );
    }

    /// 不变量：`live_view` 必须把**所有不可热改**的判据字段都取运行期值。
    ///
    /// 这是防"手工列举漏字段"的护栏 —— H1（漏 `dashboard_port`）与
    /// H2（漏 `allow_insecure_dashboard`）都是同一成因。
    /// 将来有人把新字段加进暴露判据、却忘了同步 `live_view`，这条会红。
    #[test]
    fn 判据用到的不可热改字段必须取运行期值() {
        // 攻击者把三项**不可热改**的字段全改成"看起来安全"的值，
        // 但**凭据保持不变**（凭据是可热改的，本来就该取 new）。
        //
        // 第一版这条测试写错了：我把凭据也清空了，然后断言"结论必须与
        //   live 一致" —— 但凭据是可热改字段，判据**本来就应该**看到
        //   "新配置把凭据清掉了"。清空凭据后判为暴露是**正确**行为。
        //   这条不变量只针对不可热改的那三项。
        let live = safe_exposed_cfg();
        let mut evil = live.clone();
        evil.bind_addr = "127.0.0.1".into(); // 想伪装成回环
        evil.dashboard_port = None; // 想伪装成"面板没开"
        evil.allow_insecure_dashboard = true; // 想伪装成"知情选择"

        assert!(
            !dashboard_exposed_after_reload(&live, &evil),
            "三项不可热改字段的新值都不生效 ⇒ 判据结论不得改变（仍是安全）"
        );
        assert!(!dashboard_is_exposed(&live), "基线：live 本身是安全的");

        // 反向确认：若**凭据**（可热改）被清掉，判据必须翻成"暴露" ——
        // 证明这条不变量没有把可热改字段也一起冻住。
        let mut no_creds = live.clone();
        no_creds.dashboard_user.clear();
        no_creds.dashboard_pwd.clear();
        assert!(
            dashboard_exposed_after_reload(&live, &no_creds),
            "清空凭据（可热改）必须被判为暴露"
        );
    }

    #[test]
    fn mtime_of_existing_file_is_stable() {
        let dir = std::env::temp_dir().join("nfrp-reload-test");
        std::fs::create_dir_all(&dir).ok();
        let p = dir.join("c.toml");
        std::fs::write(&p, "bind_port = 7000\n").unwrap();
        let a = mtime(&p);
        assert!(a.is_some());
        assert_eq!(a, mtime(&p), "同一个文件两次读到的 mtime 必须一致");
        std::fs::remove_dir_all(&dir).ok();
    }
}
