//! 面板的**写操作**：增删代理、踢客户端。
//!
//! 官方 frp 到 v0.68 才补上"通过 API 操作代理"，而且客户端必须是自家的 frpc。
//! 这里做成 NFrp 私有能力：服务端在 `LoginResp` 里回显 `server_cmd`
//! 之后，才往客户端发 [`ServerCmd`]；连着官方 frpc 时能力不开，
//! 面板直接回一句人话错误，而不是干等到超时。
//!
//! 三个操作都走同一条纪律：**先问客户端，再动服务端**，且客户端说不行就回滚。

use std::{sync::Arc, time::Duration};

use nfrp_common::{
    config::{ProxyConfig, ServerConfig},
    frp::msg::{self, NewProxy, ServerCmd},
};
use tokio::sync::oneshot;

use crate::{
    pool::{ClientState, CtrlCmd},
    registry::Registry,
};

/// 等客户端回执的最长时间。
///
/// 面板是同步等这个结果的，太长会让界面卡住；太短又会把"慢但成功"的操作
/// 误判成失败。5 秒足够一个正常客户端解析配置并回包。
const ACK_TIMEOUT: Duration = Duration::from_secs(5);

/// 一次管理操作的结果：要么是给人看的成功文案，要么是人话错误。
pub type AdminResult = Result<String, String>;

/// 给某个客户端**新增**一条代理。
///
/// 顺序很讲究：
///
/// 1. 先让客户端把代理放进它自己的表（它不认识这条代理，后面所有
///    工作连接都会因为"未知代理"而失败）；
/// 2. 客户端确认了，服务端才开端口 / 注册域名；
/// 3. 服务端开端口失败，要回头让客户端把刚加的那条删掉。
///
/// 反过来（先开端口再通知客户端）会留下一个"端口开着但没有后端"的洞，
/// 而洞比失败更难发现。
pub async fn add_proxy(
    cfg: &Arc<ServerConfig>,
    registry: &Arc<Registry>,
    run_id: &str,
    proxy: ProxyConfig,
) -> AdminResult {
    if proxy.name.is_empty() {
        return Err("代理配置缺少 name".to_string());
    }
    if proxy.proxy_type.is_empty() {
        return Err("代理配置缺少 type".to_string());
    }
    let client = registry
        .client(run_id)
        .ok_or_else(|| format!("没有在线客户端 [{run_id}]"))?;
    // RBAC 的 `allowManage = false`：角色不允许被面板管理。
    // 曾经这个字段是死的（读进来就没人再看），用户以为禁掉了其实没有。
    if !client.allow_manage() {
        return Err(format!(
            "客户端 [{run_id}] 所属角色不允许被面板管理（allowManage = false）"
        ));
    }

    // ★★ v0.5.5 修（第四轮 D-AUTH-02）：**面板路径也必须过 RBAC 的逐条代理检查**。
    //
    // `sec.check_proxy()`（角色允许的代理类型 / 端口范围 / maxProxies）
    // 原先全仓**唯一**的调用点是客户端发 `NewProxy` 的那条路
    // （`serve.rs` 的 `register_proxy` 上游）。而面板这条路
    // （`dashboard.rs` → 本函数 → `serve::register_proxy`）只查了 `allow_manage`
    // —— 那是有用的，但它不是类型/端口/配额限制。
    //
    // 实弹（`tmp/audit4-verify-D2.py`）：角色 `guest` 配
    // `allowProxyTypes=["http"]` / `portRange="30000-30010"` / `maxProxies=1`，
    //   * 客户端自己发 `tcp:30005` ⇒ **被拒**（RBAC 有效）；
    //   * 面板发 `tcp:12347/12348/12349` ⇒ **三条全部生效**。
    // 即：面板可达时，任何被角色刻意收紧的客户端都能被越权开端口。
    //
    // 这与第四轮 H1 是**同一类**：同一个语义（"这个客户端能不能注册这条代理"）
    // 在两条路径上用了两套规则。修法就是把闸门补到这条路径上。
    //
    // ★ 放在最前面（问客户端之前）：先拦下来才不会有"客户端已经认下、
    //   服务端却拒绝"的半成品状态。
    let sec = registry.security();
    let role = sec
        .role_for(&client.user)
        .map_err(|e| format!("客户端 [{}] 的角色解析失败，拒绝面板下发：{e}", client.user))?;
    sec.check_proxy(
        &role,
        &proxy.name,
        &proxy.proxy_type,
        proxy.remote_port,
        client.proxy_count(),
    )
    .map_err(|e| format!("面板下发被权限模型拒绝：{e}"))?;

    let name = proxy.name.clone();

    // 1) 客户端先认下这条代理
    ask(
        &client,
        ServerCmd {
            id: new_cmd_id(),
            op: msg::CMD_ADD_PROXY.to_string(),
            proxy_name: name.clone(),
            proxy: Some(serde_json::to_value(&proxy).map_err(|e| e.to_string())?),
            reason: "dashboard".to_string(),
        },
    )
    .await
    .map_err(|e| format!("客户端拒绝新增代理：{e}"))?;

    // 2) 服务端开端口 / 注册域名
    let wire = NewProxy::from_config(&proxy, &client.user);
    match crate::serve::register_proxy(cfg, registry, &client, &wire).await {
        Ok(outcome) => {
            if !outcome.adopted {
                registry.metrics().proxies_total.inc();
                registry.metrics().proxies_active.inc();
            }
            let remote = outcome.remote_addr;
            tracing::info!(%run_id, proxy = %name, remote = %remote, "面板新增代理成功");
            // ★★ v0.6.1 修（Shannon 审计）：**面板下发的增删也要进审计链**。
            // 原先只有 `serve.rs` 里"客户端自己注册"那条记 `PROXY_ADD`，
            // 面板这条路（走 `ServerCmd`）一条都没记 —— 审计里看不到管理操作。
            registry.audit().record(
                crate::audit::AuditEvent::new(crate::audit::kind::ADMIN_ACTION, true)
                    .client(run_id.to_string())
                    .target(name.clone())
                    .detail(format!("add_proxy：已生效 remote={remote}")),
            );
            Ok(format!("代理 [{name}] 已生效：{remote}"))
        }
        Err(e) => {
            // 3) 回滚：端口没开成，客户端那边也不能留着这条
            let _ = ask(
                &client,
                ServerCmd {
                    id: new_cmd_id(),
                    op: msg::CMD_REMOVE_PROXY.to_string(),
                    proxy_name: name.clone(),
                    reason: "rollback".to_string(),
                    ..Default::default()
                },
            )
            .await;
            Err(format!("服务端注册代理失败（已回滚）：{e}"))
        }
    }
}

/// 停掉某个客户端的一条代理。**先停服务端，再让客户端摘掉**。
///
/// 与 [`add_proxy`] 的顺序相反是故意的：撤资源没有"开洞"的风险，
/// 而先停服务端能立刻切断新流量，不用等客户端回包。
pub async fn remove_proxy(registry: &Arc<Registry>, run_id: &str, name: &str) -> AdminResult {
    if name.is_empty() {
        return Err("缺少代理名".to_string());
    }
    let client = registry
        .client(run_id)
        .ok_or_else(|| format!("没有在线客户端 [{run_id}]"))?;
    if !client.allow_manage() {
        return Err(format!(
            "客户端 [{run_id}] 所属角色不允许被面板管理（allowManage = false）"
        ));
    }

    // 服务端这侧：端口 / 域名 / visitor 全摘掉（与客户端主动 CloseProxy 同款清理）
    //
    // ★★ v0.5.6 修（审计总报告 M5，中危）：**前缀必须幂等**（strip 再 add）。
    //
    // 面板传进来的 `name` 是**线上全名**（带 `{user}.` 前缀，因为它是从
    // `/api/status` / `/api/v2/proxies` 列表里读出来的，那些地方展示的就是全名）。
    // 原先直接 `add_user_prefix(&client.user, name)` ⇒ 得到 `"alice.alice.web"`，
    // 而 `add_user_prefix` **只在 `user` 为空时短路**，不认已有的前缀。
    //
    // 后果（逐条都可观测）：
    // * `client.stop_proxy("alice.alice.web")` → `None` ⇒ **`release_port` 被跳过，
    //   端口不归还** ⇒ 端口/域名**持续泄漏**，期间任何人重注册同一端口都得到
    //   "已被占用"，可反复触发形成**跨租户 DoS**；
    // * `t.remove_proxy(&client, "alice.alice.web")` → 摘不到 ⇒ 域名仍被占；
    // * 但**客户端侧**用的是原始名（下面发的是 `name`）⇒ 客户端**真的删成功了**；
    // * 返回文案还说"已移除" —— 与真实状态不符。
    //
    // ★ 服务端直连那条路径（`serve.rs` 的 `NewProxy` 处理）一直是
    //   `add_user_prefix(user, strip_user_prefix(user, name))` 的幂等写法，
    //   面板这条路漏了那半截。现在抽成 `canonical_wire_name()` 让两处共用。
    let wire_name = nfrp_common::util::canonical_wire_name(&client.user, name);
    // ★ v0.5.5（第四轮 B-1）：同样带上归属，避免误删其它租户的同名 visitor 记录。
    registry.visitors.remove(&client, &wire_name);
    if let Some(t) = registry.vhosts() {
        // ★ v0.5.5（第四轮 H1）：带上是**哪个客户端**的代理 ——
        //   只按名字摘会误删其它租户的同名路由。
        t.remove_proxy(&client, &wire_name);
    }
    // ★★ v0.5.6 修（审计总报告 M8，中危）：`proxies_active.dec()` 必须**只在本客户端
    //   确实持有这条代理时**执行。
    //
    // 原先它是无条件执行的 —— 于是任何客户端反复发 `CloseProxy`（或面板反复删
    // 一个不存在/别人的名字），每次都能把 gauge 减 1 ⇒ 变成负数并持续走低，
    // 面板显示"生效代理 -37"，管理员据此判断异常的能力被破坏。
    //
    // 参照：`serve.rs` 的 `CloseProxy` 分支也是同样的写法问题（一并在本轮修了）。
    if let Some(port) = client.stop_proxy(&wire_name) {
        registry.metrics().proxies_active.dec();
        registry.release_port(port, &client, &wire_name);
    }

    // 客户端那侧：失败也只是它表里多留一条（服务端已经不放流量进来了），
    // 所以这里只告警、不回滚
    //
    // ★ v0.5.8 修（第八轮审计 F8-L2，低危）：下发给客户端的是**本地名**。
    //
    // 面板列表（`/api/status`、`/api/v2/proxies`）展示的是线上全名
    // `{user}.{name}`，管理员照抄列表里的全名来删是最自然的用法。原先这里
    // 原样转发面板给的名字 ⇒ 客户端拿全名去查**本地表**（键是无前缀的原始名）
    // 必然查不到 ⇒ 拒删、回执失败。而此时服务端侧已经摘干净了（上面
    // `canonical_wire_name` 生效）—— 结果是**两端状态分裂**：服务端已摘、
    // 客户端本地表仍保留，接口却用 502/400 把"半成功"表达成失败
    // （自动化按返回码判断会得出错误结论：重试/放弃都不对）。
    //
    // `wire_name` 既然已是 canonical 全名，剥掉前缀就是客户端契约里的名字；
    // 客户端侧另有兜底（兼容"客户端先升级、服务端还是旧版"的滚动升级窗口）。
    let local_name = nfrp_common::util::strip_user_prefix(&client.user, &wire_name).to_string();
    match ask(
        &client,
        ServerCmd {
            id: new_cmd_id(),
            op: msg::CMD_REMOVE_PROXY.to_string(),
            proxy_name: local_name,
            reason: "dashboard".to_string(),
            ..Default::default()
        },
    )
    .await
    {
        Ok(()) => {
            tracing::info!(%run_id, proxy = %name, "面板移除代理成功");
            // ★★ v0.6.1 修（Shannon 审计）：面板下发的删除也进审计链（同上）。
            registry.audit().record(
                crate::audit::AuditEvent::new(crate::audit::kind::ADMIN_ACTION, true)
                    .client(run_id.to_string())
                    .target(name)
                    .detail("remove_proxy：已移除"),
            );
            Ok(format!("代理 [{name}] 已移除"))
        }
        Err(e) => Err(format!(
            "服务端已移除，但客户端侧失败（{e}）—— 它会在下次重连后自愈"
        )),
    }
}

/// 踢掉一个客户端：立刻切断它的所有代理，并结束它的控制连接。
pub async fn kick(registry: &Arc<Registry>, run_id: &str, reason: &str) -> AdminResult {
    // 先查 allowManage 再 remove —— `remove` 会把客户端从名册里摘掉，
    // 摘掉之后就再也查不到它属于哪个角色了。
    //
    // ★ 这一条尤其要紧：`kick` 不像 `add_proxy` / `remove_proxy` 那样要经
    // 客户端回执，它**无条件生效**。面板零鉴权的配置下，匿名者能踢掉任意
    // 客户端（含官方 frpc），是共享 frps 上的直接 DoS，所以这层角色闸门
    // 必须在最前面。
    if let Some(c) = registry.client(run_id) {
        if !c.allow_manage() {
            return Err(format!(
                "客户端 [{run_id}] 所属角色不允许被面板管理（allowManage = false）"
            ));
        }
    }
    let client = registry
        .remove(run_id)
        .ok_or_else(|| format!("没有在线客户端 [{run_id}]"))?;
    // `remove` 内部已经 `stop()` 了：它名下的工作连接请求会立刻失败，
    // 控制连接也会在下一个心跳周期自己退出（见 serve.rs 的 stopped 检查）。
    client.stop();
    registry.release_ports_of(&client);
    tracing::warn!(%run_id, %reason, "面板踢出客户端");
    // ★★ v0.6.1 修（Shannon 审计，低危）：**踢人必须进审计链**。
    //
    // 原先只有 `tracing::warn!` —— 日志和审计是两条不同的链：
    // 日志会轮转/被删，审计是 `[audit]` 配置下独立的 JSONL，用于事后追责。
    // 踢人是**不可回滚**的高危操作（客户端所有隧道立刻失效），
    // 只留日志等于"查不到谁在什么时候踢了谁"。
    registry.audit().record(
        crate::audit::AuditEvent::new(crate::audit::kind::ADMIN_ACTION, true)
            .client(run_id.to_string())
            .user(client.user.clone())
            .target(run_id.to_string())
            .detail(if reason.is_empty() {
                "kick：无理由".to_string()
            } else {
                format!("kick：{reason}")
            }),
    );
    Ok(format!(
        "客户端 [{run_id}] 已踢出（{}）",
        if reason.is_empty() {
            "无理由"
        } else {
            reason
        }
    ))
}

/// 下发一条命令并等回执。
async fn ask(client: &Arc<ClientState>, cmd: ServerCmd) -> Result<(), String> {
    let (tx, rx) = oneshot::channel();
    let sent = client.req_tx().send(CtrlCmd::ServerCmd {
        cmd: Box::new(cmd),
        ack: tx,
    });
    if sent.is_err() {
        return Err("客户端的控制连接已断开".to_string());
    }
    match tokio::time::timeout(ACK_TIMEOUT, rx).await {
        // 控制连接先断了：rx 那头被 drop
        Ok(Err(_)) => Err("客户端在回执前断开".to_string()),
        Ok(Ok(outcome)) => outcome,
        Err(_) => Err(format!("{} 秒内没有收到回执", ACK_TIMEOUT.as_secs())),
    }
}

fn new_cmd_id() -> String {
    nfrp_common::util::new_run_id()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::registry::ServerLimits;

    fn client(run_id: &str) -> Arc<ClientState> {
        let (tx, rx) = tokio::sync::mpsc::unbounded_channel::<CtrlCmd>();
        std::mem::forget(rx);
        let (conn, backlog, proxy) = ServerLimits::default().per_client();
        Arc::new(ClientState::new(
            run_id.to_string(),
            run_id.to_string(),
            "alice".to_string(),
            tx,
            Duration::from_secs(60),
            Duration::from_secs(10),
            Default::default(),
            false,
            nfrp_common::frp::WireVersion::V1,
            conn,
            backlog,
            0,
            proxy,
            "127.0.0.1".parse::<std::net::IpAddr>().unwrap(),
        ))
    }

    /// 客户端不在线时必须给出**人话**错误，而不是 panic 或空成功。
    #[tokio::test]
    async fn missing_client_is_reported_not_panicked() {
        let r = Arc::new(Registry::unlimited());

        let e = remove_proxy(&r, "nope", "web").await.expect_err("应当报错");
        assert!(e.contains("nope"), "错误里要带上找不到的 run_id：{e}");
        let e = kick(&r, "nope", "").await.expect_err("应当报错");
        assert!(e.contains("nope"));
    }

    /// 缺字段要**在发命令之前**被拦住 —— 发过去也是被客户端拒绝，
    /// 白白多一次往返，而且错误信息还没这里的清楚。
    #[tokio::test]
    async fn missing_fields_are_rejected_locally() {
        let r = Arc::new(Registry::unlimited());
        let cfg = Arc::new(ServerConfig::default());
        let c = client("c1");
        r.insert(c.clone()).expect("插入");

        let e = add_proxy(&cfg, &r, "c1", ProxyConfig::default())
            .await
            .expect_err("缺 name 应当报错");
        assert!(e.contains("name"), "错误要指名道姓：{e}");

        let p = ProxyConfig {
            name: "web".into(),
            ..Default::default()
        };
        let e = add_proxy(&cfg, &r, "c1", p)
            .await
            .expect_err("缺 type 应当报错");
        assert!(e.contains("type"), "错误要指名道姓：{e}");
    }

    /// 踢人之后这个客户端必须真的从注册表里消失。
    #[tokio::test]
    async fn kick_removes_the_client() {
        let r = Arc::new(Registry::unlimited());
        let c = client("c1");
        r.insert(c.clone()).expect("插入");
        assert_eq!(r.clients().len(), 1);

        kick(&r, "c1", "测试").await.expect("踢出成功");
        assert_eq!(r.clients().len(), 0, "踢完之后不该还留在注册表里");
        assert!(c.is_stopped(), "被踢的客户端必须标记为已停止");
        // 再踢一次应当是"没有这个客户端"，而不是 panic
        assert!(kick(&r, "c1", "").await.is_err());
    }

    /// ★★ v0.6.1 回归（Shannon 审计，低危）：**踢人必须写进审计链。**
    ///
    /// # 原先的问题
    ///
    /// `kick` 只调了 `tracing::warn!` —— 日志和审计是两条链：
    /// 日志会轮转，`[audit]` 的 JSONL 才是事后追责用的。
    /// 踢人是**不可回滚**的操作（客户端所有隧道立刻失效），
    /// 只留日志等于"查不到谁在什么时候踢了谁"。
    ///
    /// 而且 `audit::kind::ADMIN_ACTION` 这个常量**定义了但全仓没有任何使用点** ——
    /// 也就是面板的增/删/踢三个操作一条审计都没记。
    ///
    /// # 测试要注意
    ///
    /// `AuditLog::record()` 在 `enabled == false` 时**直接 return**，
    /// 而 `Registry::unlimited()` 默认是不启用审计的 ——
    /// 不换上下文的话，这条测试会**因为"审计没开"而不是"代码没写"** 而失败，
    /// 那样就测不到修复点。
    #[tokio::test]
    async fn kick_必须写审计() {
        let r = Arc::new(Registry::unlimited());
        // 换一个**开启审计**的安全上下文（内存模式，不落盘）
        let mut cfg = nfrp_common::config::ServerConfig::default();
        cfg.audit.enable = true;
        cfg.audit.path = String::new(); // 只留内存
        cfg.audit.max_entries = 128;
        r.set_security(Arc::new(
            crate::guard::SecurityContext::from_config(&cfg).expect("构造安全上下文"),
        ));

        // 前置自检：审计必须真的在记。否则下面的断言会因"审计没开"而失败，
        // 而不是因为"代码没写" —— 那就测不到修复点。
        r.audit()
            .record(crate::audit::AuditEvent::new("selftest", true));
        assert_eq!(
            r.audit().recent(10).len(),
            1,
            "前置失败：审计没启用，本测试无法验证修复"
        );

        r.insert(client("c-audit")).expect("插入");

        let before = r.audit().recent(100).len();
        kick(&r, "c-audit", "回归测试").await.expect("踢出成功");
        let after = r.audit().recent(100);

        assert!(
            after.len() > before,
            "踢人之后审计条目数必须增加（原先一条都不记）；before={before} after={}",
            after.len()
        );
        let hit = after
            .iter()
            .find(|e| e.kind == crate::audit::kind::ADMIN_ACTION && e.target == "c-audit");
        let e = hit.expect("审计里必须有这条 ADMIN_ACTION（target=被踢的 run_id）");
        assert!(e.ok, "成功踢出应当记 ok=true");
        assert!(
            e.detail.contains("kick"),
            "detail 要能看出是哪种管理操作，实际：{}",
            e.detail
        );
        assert!(
            e.detail.contains("回归测试"),
            "理由要落进审计，实际：{}",
            e.detail
        );
    }

    // ------------------------------------------------------------------
    // 第四轮 D-AUTH-02：面板路径也要过 RBAC
    // ------------------------------------------------------------------

    /// 造一个"角色把类型收紧到只允许 http"的注册表。
    fn registry_with_guest_role() -> Arc<Registry> {
        let r = Arc::new(Registry::unlimited());
        let toml = r#"
[[roles]]
name = "guest"
users = ["alice"]
allowProxyTypes = ["http"]
portRange = "30000-30010"
maxProxies = 1
"#;
        let cfg: ServerConfig = nfrp_common::config::parse_server_toml(toml).expect("解析角色");
        r.set_security(Arc::new(
            crate::guard::SecurityContext::from_config(&cfg).expect("构造安全上下文"),
        ));
        r
    }

    /// ★★ D-AUTH-02 回归：**面板下发**同样受 RBAC 的类型限制。
    ///
    /// 修复前 `sec.check_proxy` 只在客户端 `NewProxy` 那条路上调用，
    /// 面板路径只查 `allow_manage` ⇒ 角色收紧的客户端可被面板越权开端口
    /// （实弹：`guest` 角色下客户端发 tcp 被拒，面板发 tcp 三条全过）。
    #[tokio::test]
    async fn 面板下发必须受_rbac_类型限制() {
        let r = registry_with_guest_role();
        let c = client("c1"); // user = "alice"，命中 guest 角色
        r.insert(c.clone()).expect("插入");
        let cfg = Arc::new(ServerConfig::default());

        // guest 只许 http ⇒ tcp 必须被拒
        let p = ProxyConfig {
            name: "sneaky".into(),
            proxy_type: "tcp".into(),
            local_addr: "127.0.0.1:9".into(),
            remote_port: 12347,
            ..Default::default()
        };
        let e = add_proxy(&cfg, &r, "c1", p)
            .await
            .expect_err("面板下发 tcp 必须被角色拒绝");
        assert!(
            e.contains("tcp") || e.contains("权限"),
            "错误要说清是权限拒绝：{e}"
        );
    }

    /// ★★ D-AUTH-02 回归：**面板下发**同样受 RBAC 的端口范围限制。
    #[tokio::test]
    async fn 面板下发必须受_rbac_端口范围限制() {
        let r = registry_with_guest_role();
        let c = client("c1");
        r.insert(c.clone()).expect("插入");
        let cfg = Arc::new(ServerConfig::default());

        // http 类型允许，但端口 12347 不在 30000-30010 内 ⇒ 仍须被拒
        let p = ProxyConfig {
            name: "outofrange".into(),
            proxy_type: "http".into(),
            local_addr: "127.0.0.1:9".into(),
            remote_port: 12347,
            ..Default::default()
        };
        let e = add_proxy(&cfg, &r, "c1", p)
            .await
            .expect_err("端口越界必须被角色拒绝");
        assert!(!e.is_empty(), "应当给出拒绝理由：{e}");
    }

    /// ★ v0.5.8（第八轮审计 F8-L2，低危）回归：面板传**线上全名**时，
    /// 下发给客户端的必须剥成**本地名**。
    ///
    /// 客户端按本地表（键 = 配置/动态添加时的原始名）查名字，收到
    /// `alice.web` 这种全名必然查不到 ⇒ 拒删；而服务端侧已经摘干净了 ⇒
    /// 两端状态分裂 + 接口回 502。这里直接截获下发的 `CtrlCmd::ServerCmd`
    /// 断言名字契约，避免整机启动客户端的重量级集成。
    #[tokio::test]
    async fn 面板传全名时下发给客户端的是本地名() {
        let r = Arc::new(Registry::unlimited());
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<CtrlCmd>();
        let (conn, backlog, proxy) = ServerLimits::default().per_client();
        let c = Arc::new(ClientState::new(
            "c1".to_string(),
            "c1".to_string(),
            "alice".to_string(), // 线上全名 = alice.{name}
            tx,
            Duration::from_secs(60),
            Duration::from_secs(10),
            Default::default(),
            false,
            nfrp_common::frp::WireVersion::V1,
            conn,
            backlog,
            0,
            proxy,
            "127.0.0.1".parse::<std::net::IpAddr>().unwrap(),
        ));
        r.insert(c.clone()).expect("插入");

        // 管理员从列表复制的全名
        let runner = tokio::spawn({
            let r = r.clone();
            async move { remove_proxy(&r, "c1", "alice.web").await }
        });

        match rx.recv().await.expect("必须向客户端下发删除命令") {
            CtrlCmd::ServerCmd { cmd, ack } => {
                assert_eq!(cmd.op, msg::CMD_REMOVE_PROXY);
                assert_eq!(
                    cmd.proxy_name, "web",
                    "客户端侧的名字契约是本地名（无 alice. 前缀）"
                );
                let _ = ack.send(Ok(()));
            }
            _ => panic!("下发的应当是 ServerCmd"),
        }
        let msg = runner
            .await
            .expect("任务不 panic")
            .expect("回执成功后应返回 Ok");
        assert!(
            msg.contains("alice.web"),
            "返回文案保留面板给的名字，便于对照：{msg}"
        );

        // 传本地名时同样下发本地名（幂等，不能把正常路径弄坏）
        let runner = tokio::spawn({
            let r = r.clone();
            async move { remove_proxy(&r, "c1", "web").await }
        });
        match rx.recv().await.expect("第二次删除命令") {
            CtrlCmd::ServerCmd { cmd, ack } => {
                assert_eq!(cmd.proxy_name, "web");
                let _ = ack.send(Ok(()));
            }
            _ => panic!("下发的应当是 ServerCmd"),
        }
        runner.await.expect("任务不 panic").expect("成功");
    }
}
