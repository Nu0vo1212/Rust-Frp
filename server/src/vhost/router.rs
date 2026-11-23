//! 虚拟主机路由表（等价官方 `pkg/util/vhost`）。
//!
//! 职责：持有全局 `VhostTable`，负责路由注册 / 注销 / 查找与同名冲突判定；
//! 域名匹配（精确 → 逐级通配 → `*` 兜底）、最长路径前缀、`routeByHTTPUser`
//! 三级优先级的语义全部收敛在这里。
//!
//! 锁顺序契约：`VhostTable::inner` 的 `Mutex<VhostInner>` 是**唯一**路由表锁，
//! 所有读写都在锁内完成；持锁期间**不**获取任何其它锁（`ClientState` 的
//! 连接池锁、`Registry` 的锁都只在锁外调用），因此不存在与连接计数原子量
//! 或连接池锁的嵌套关系。调用方也不得在持有其它锁时回调本模块。
//!
//! 不变量：`inner.exact` / `inner.wildcard` 里的空 `Vec` 在注销路径上立即清掉，
//! map 不堆只增不减的 key；`VhostRoute.client` 恒为服务端握手后持有的
//! `Arc<ClientState>`，归属判定只用 `Arc::ptr_eq`，绝不读客户端自报字段。
//! 写者只有 `register` / `remove_proxy` / `unregister_client`，`lookup` /
//! `contains_domain` 只读；`routes` 只追加/替换，不原地改字段。

use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};

use anyhow::{bail, Result};
use tracing::debug;

use crate::pool::ClientState;

// ---------------------------------------------------------------------------
// 路由表
// ---------------------------------------------------------------------------
/// 虚拟主机的三种形态。
///
/// 路由本身（域名匹配、最长前缀、`routeByHTTPUser`）三种完全共用 —— 都是官方
/// `pkg/util/vhost` 那一套。差别只有两点：
///
/// * **域名从哪来**：http 看 `Host` 头、https 看 ClientHello 的 SNI、
///   tcpmux 看 CONNECT 请求行里的 authority；
/// * **连接怎么交给内网服务**：http 要按帧收发报文、https 原样透传 TLS 字节、
///   tcpmux 是"回合"一次然后变成裸 TCP 隧道。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum VhostKind {
    /// 明文 HTTP。
    Http,
    /// HTTPS（只嗅探 SNI，**不终止 TLS**）。
    Https,
    /// tcpmux：若干条代理共用服务端的 `tcpmuxHTTPConnectPort`，按 CONNECT 的
    /// authority 分发。
    TcpMux,
}

impl VhostKind {
    /// 日志 / 报错里用的名字。
    pub fn label(self) -> &'static str {
        match self {
            VhostKind::Http => "http",
            VhostKind::Https => "https",
            VhostKind::TcpMux => "tcpmux",
        }
    }
}

/// 一条虚拟主机路由。
pub struct VhostRoute {
    pub proxy_name: String,
    pub client: Arc<ClientState>,
    /// 域名（小写）。支持前缀通配 `*.example.com`。
    pub domain: String,
    /// 路径前缀，按长度倒序排列；空表示匹配全部。
    pub locations: Vec<String>,
    pub http_user: String,
    pub http_pwd: String,
    pub route_by_http_user: String,
    pub rewrite_host: String,
    pub req_headers: HashMap<String, String>,
    pub resp_headers: HashMap<String, String>,
    /// 这条路由属于哪种虚拟主机。
    pub kind: VhostKind,
}

impl VhostRoute {
    /// 本条路由里**命中且最长**的路径前缀。
    ///
    /// 必须取最长：同一个代理可以配多个 `locations`（例如 `/api` 与 `/api/admin`），
    /// 用 `find` 会退化成"配置里写在前头的赢"，那 `/api/admin` 永远轮不到。
    pub fn match_location(&self, path: &str) -> Option<&str> {
        self.locations
            .iter()
            .filter(|loc| path.starts_with(loc.as_str()))
            .max_by_key(|loc| loc.len())
            .map(|s| s.as_str())
    }
}

#[derive(Default)]
struct VhostInner {
    /// 精确域名 → 路由列表
    exact: HashMap<String, Vec<Arc<VhostRoute>>>,
    /// 通配后缀（`*.example.com` 记作 `example.com`）→ 路由列表
    wildcard: HashMap<String, Vec<Arc<VhostRoute>>>,
}

/// 全局虚拟主机路由表。
#[derive(Default)]
pub struct VhostTable {
    inner: Mutex<VhostInner>,
}

/// "这两条路由属于同一个客户端吗"（第四轮 H1）。
///
/// 用 `Arc::ptr_eq` 比**连接身份**，而不是比客户端可自报的字段：
/// `VhostRoute.client` 是服务端在握手后持有的 `Arc<ClientState>`，
/// 客户端无法伪造。与 `unregister_client` 用的是同一套判据。
fn same_owner(a: &VhostRoute, b: &VhostRoute) -> bool {
    Arc::ptr_eq(&a.client, &b.client)
}

impl VhostTable {
    /// 注册路由；同一域名 + 同一路径前缀冲突时报错（与 frp 行为一致）。
    ///
    /// ★★ v0.5.5 修（第四轮 H1）：**"这条路由是不是我的"必须同时比客户端身份，
    /// 不能只比代理名。**
    ///
    /// 原先这里三处都只比 `proxy_name`：
    ///
    /// ```ignore
    /// let same_proxy = existing.proxy_name == route.proxy_name;
    /// ...
    /// list.retain(|r| r.proxy_name != route.proxy_name);
    /// ```
    ///
    /// 而 `proxy_name` 是**线协议名** `{user}.{name}`，其中的 `user` 由客户端在
    /// 登录报文里**自报**（`serve.rs:774` 的 `login.user`），默认配置（无 `[[roles]]`）
    /// 下 `role_for` 对任何用户名都返回 unrestricted（`security.rs:785`）。
    ///
    /// 于是两个**不同租户**只要声明同一个 `user`，就得到**同一个 wire name**：
    /// `same_proxy` 为真 ⇒ 冲突检查被跳过 ⇒ `retain` 把**对方**的路由删掉 ⇒
    /// 攻击者顶掉受害者已生效的域名，之后发往该域名的**全部流量**（含 Cookie、
    /// Authorization）都改投攻击者的内网服务。
    ///
    /// 实测（`tmp/audit4-probe-vhost-hijack.py`）：受害者注册后 `web.test` 回
    /// `I-AM-VICTIM`，攻击者用同一 `user` 注册同名代理后变成 `I-AM-ATTACKER`。
    ///
    /// 对照：**TCP 端口那条路径没有这个洞**（`registry.rs:573` 用的是
    /// `same_client(&b.client, &client) && b.proxy_name == proxy_name`）。
    /// 也就是说"这条代理是不是我的"这个判断，仓库里**已经有一处写对了**，
    /// 只是没铺到 vhost。本函数与下面的 `remove_proxy` 就是把那半截补上。
    pub fn register(&self, route: Arc<VhostRoute>) -> Result<()> {
        let mut g = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        let list = if let Some(suffix) = route.domain.strip_prefix("*.") {
            g.wildcard.entry(suffix.to_string()).or_default()
        } else {
            g.exact.entry(route.domain.clone()).or_default()
        };
        for existing in list.iter() {
            // ★ 同一个客户端 + 同一个名字，才算"同一条代理的重复注册"。
            let same_proxy =
                same_owner(existing, &route) && existing.proxy_name == route.proxy_name;
            // 只有**完全相同**的路径才算冲突。
            //
            // 早先这里把"前缀互相包含"也算冲突（`/api` 与 `/api/admin` 不能共存），
            // 但路由本来就是按**最长前缀**匹配的，嵌套路径之间并没有歧义，
            // 官方 frp 也是按精确路径去重、允许嵌套的。
            let duplicate = existing
                .locations
                .iter()
                .any(|a| route.locations.iter().any(|b| a == b));
            // ★ `route_by_http_user` 的**合法用途**：**同一个租户**自己在
            //   同一「域名 + 路径」上开多条路由，靠访问者用户名区分
            //   （官方 tcpmux 的 "Route by HTTP user" 就是这个拓扑）。
            //
            // ★★ v0.5.6 修（审计总报告 M1，中危）：**跨租户一律算冲突**，
            //   不许用 `route_by_http_user` 逃逸归属判定。
            //
            // 原先是 `duplicate && same_scope`（作用域**相同**才算冲突），
            // 于是**跨租户 + 作用域不同**这一组合被放行。而
            // `route_by_http_user` **完全由客户端自报、注册时全仓无校验**
            // （`serve.rs` → `msg.rs` 直传；`CompiledRbac::check_proxy` 从不读它）。
            //
            // 攻击链（实测可复现）：
            //   ① 受害者 B 注册 `custom_domains=["web.test"]` + `locations=["/"]`，
            //      未配 `routeByHTTPUser`（默认空串 ⇒ 兜底路由）；
            //   ② 攻击者 A 注册**同样的域名与路径**，但带 `routeByHTTPUser="alice"`；
            //   ③ `same_proxy=false`（H1 已拦）、`duplicate=true`、
            //      **`same_scope=false`** ⇒ 冲突检查跳过 ⇒ 攻击者路由入表，
            //      且**返回注册成功、无任何告警**；
            //   ④ 之后**带 `Authorization: Basic alice:...` 的访客请求**会在
            //      `lookup` 的第 1 轮（`exact_user=true`）命中攻击者的路由
            //      ⇒ 流量改投攻击者内网服务 —— 可读取其 Authorization / Cookie
            //      （**凭证收割**）并返回任意响应（钓鱼）。
            //      而 `same_scope` 永久为 false ⇒ 受害者之后怎么重注册都不冲突，
            //      域名被**静默寄生**。
            //
            // ★★ 关于审计报告给的修法：它建议
            //   `same_scope = same_owner(existing,&route) && existing.route_by_http_user == route.route_by_http_user`。
            //   **那个写法是错的**（本轮实测核对）：跨租户攻击时 `same_owner` 本来就是
            //   false，改完 `same_scope` 仍是 false、结论**完全不变**（对攻击无效）；
            //   反而在"跨租户 + 作用域相同"时把原本生效的冲突检查**关掉**了
            //   —— 等于**新开一个洞**。这正是"审计建议不能照抄"的又一例。
            //
            // ★ 正确判据（本处实现）：**豁免共存的前提是"同一个租户"**，
            //   与作用域是否相同无关：
            //   * 同租户 + 作用域不同 ⇒ 允许共存（自己的二级路由）；
            //   * 同租户 + 作用域相同 ⇒ 冲突（真重复）；
            //   * 跨租户 ⇒ 一律冲突。
            //
            // ★ 这是一处**有意的行为收紧**：跨租户共用域名 + 路径、靠
            //   `routeByHTTPUser` 区分，从本版起不再允许。同租户的多作用域
            //   拓扑（官方 tcpmux 文档里的用法）**不受影响**。
            //   理由：服务端无法分辨"合法的跨租户多作用域"与"寄生劫持"，
            //   而后者能直接收割凭据 —— 收紧比放开安全。
            let same_scope = existing.route_by_http_user == route.route_by_http_user;
            let cross_owner = !same_owner(existing, &route);
            if !same_proxy && duplicate && (cross_owner || same_scope) {
                // ★★ v0.5.7 修（第六轮审计 D-3，低危）：**文案不再回显占用者的代理名**。
                //
                // 原先这里是 `"域名 {} 的路径已被代理 {} 占用"`，把
                // `existing.proxy_name`（带租户前缀的**线上全名**，
                // 如 `alice.site`）原样回给了调用方。实测可复现：
                //
                // ```json
                // {"error":"域名 alice-internal.corp.local 的路径已被代理 alice.site 占用"}
                // ```
                //
                // # 为什么这是问题
                //
                // 1. **同轮已经修过同类问题**：`registry.rs::reserve_port` 的
                //    端口冲突文案已被刻意统一成"不含占用者"（见那里的 L14 注释），
                //    **这条漏了** —— 又一次"防线没铺满"。
                // 2. 它把**别人的代理名**送出来，而代理名正是 D-4/D-2 那类
                //    攻击所需的"别家租户的名字"。
                // 3. 它的可复现性取决于 `detailed_errors_to_client`
                //    （默认 `true`，与官方一致）—— 但"要不要回显**别人的**名字"
                //    不该由那个面向**自己配置排查**的通用开关决定。
                //
                // # 修法
                //
                // 照搬 `registry.rs` 的做法：回一条只承认"冲突"的固定文案，
                // 细节（域名 + 占用者）走 `debug!` 只进服务端日志。
                // ★ 注意**保留 route.domain**：它是**调用方自己请求的**域名，
                //   不是别人的信息，回显它有助于用户排查自己的配置。
                debug!(
                    domain = %route.domain,
                    occupied_by = %existing.proxy_name,
                    "http 路由冲突（细节仅服务端可见）"
                );
                bail!("域名 {} 的路径已被占用（详情见服务端日志）", route.domain);
            }
        }
        // ★ 只清理**自己**的旧路由（同一客户端 + 同名），不再误删别人的。
        list.retain(|r| !(same_owner(r, &route) && r.proxy_name == route.proxy_name));
        list.push(route);
        Ok(())
    }

    /// 摘掉某一条代理注册的全部路由（客户端主动 `CloseProxy`）。
    ///
    /// 早先只有 `unregister_client`，于是客户端单独关掉一个 http 代理时，
    /// 域名仍然留在表里：重连再注册同一个域名会被判成路径冲突，
    /// 而且请求还会被路由到一个已经关掉的代理上。
    ///
    /// ★★ v0.5.5 修（第四轮 H1，同一根因的第二个面）：本函数原先也**只比名字**，
    /// 于是客户端 A 对 `"victim.web"` 调一次 `CloseProxy`，就能把**受害者 B**
    /// 的路由一起摘掉 —— 一次不需要任何权限的拒绝服务（B 的隧道在自己的客户端
    /// 还活着的情况下对外静默失效）。现在必须带客户端身份。
    pub fn remove_proxy(&self, client: &Arc<ClientState>, proxy_name: &str) -> bool {
        let mut g = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        let mut removed = false;
        for list in g.exact.values_mut() {
            let before = list.len();
            list.retain(|r| !(Arc::ptr_eq(&r.client, client) && r.proxy_name == proxy_name));
            removed |= list.len() != before;
        }
        for list in g.wildcard.values_mut() {
            let before = list.len();
            list.retain(|r| !(Arc::ptr_eq(&r.client, client) && r.proxy_name == proxy_name));
            removed |= list.len() != before;
        }
        g.exact.retain(|_, v| !v.is_empty());
        g.wildcard.retain(|_, v| !v.is_empty());
        removed
    }

    /// 客户端断开时清掉它注册的所有路由。
    pub fn unregister_client(&self, client: &Arc<ClientState>) {
        let mut g = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        for list in g.exact.values_mut() {
            list.retain(|r| !Arc::ptr_eq(&r.client, client));
        }
        for list in g.wildcard.values_mut() {
            list.retain(|r| !Arc::ptr_eq(&r.client, client));
        }
        g.exact.retain(|_, v| !v.is_empty());
        g.wildcard.retain(|_, v| !v.is_empty());
    }

    /// 按域名 + 路径查路由（精确优先，其次通配）。
    pub fn lookup(
        &self,
        host: &str,
        path: &str,
        auth_user: Option<&str>,
        kind: VhostKind,
    ) -> Option<(Arc<VhostRoute>, String)> {
        let host = host.trim().trim_end_matches('.').to_ascii_lowercase();
        let g = self.inner.lock().unwrap_or_else(|e| e.into_inner());

        // 同一域名下可能有多条路由都匹配得上（例如 A 的 `/` 和 B 的 `/api`），
        // 必须按"前缀最长者胜"来选 —— 取第一条匹配会让注册顺序偷偷决定路由结果。
        //
        // `exact_user` 分两轮：先只认"用户名精确匹配"的路由，找不到才退到
        // "不限用户名"的兜底路由。顺序必须这样，不能混在一轮里 ——
        // 兜底路由的 `route_by_http_user` 是空串，混着扫的话它先注册就会
        // 把精确路由盖掉（官方 `getExactOrAllUsersLocked` 也是这个顺序）。
        let matched = |list: &Vec<Arc<VhostRoute>>,
                       exact_user: bool|
         -> Option<(Arc<VhostRoute>, String)> {
            let mut best: Option<(Arc<VhostRoute>, String)> = None;
            for route in list {
                if route.kind != kind {
                    continue;
                }
                let wanted = auth_user.unwrap_or("");
                if exact_user {
                    if route.route_by_http_user.is_empty() || route.route_by_http_user != wanted {
                        continue;
                    }
                } else if !route.route_by_http_user.is_empty() {
                    continue;
                }
                let Some(loc) = route.match_location(path) else {
                    continue;
                };
                let better = best
                    .as_ref()
                    .map(|(_, chosen)| loc.len() > chosen.len())
                    .unwrap_or(true);
                if better {
                    best = Some((route.clone(), loc.to_string()));
                }
            }
            best
        };

        // 候选域名的顺序 = 官方 `getByRoute`：精确域名 → 逐级通配 → `*`。
        // 通配走查要求"替换后至少还剩三段"（`*.example.com`），否则 `a.b` 会去
        // 匹配 `*.b`、`example.com` 会匹配 `*.com` —— 官方明确不让这样兜底。
        let labels: Vec<&str> = host.split('.').collect();
        let mut wildcards: Vec<String> = Vec::new();
        for i in 1..labels.len().saturating_sub(1) {
            wildcards.push(labels[i..].join("."));
        }

        // 同一张表里也要两轮：先精确用户名、再兜底（见上面 `matched` 的说明）
        let in_table = |list: Option<&Vec<Arc<VhostRoute>>>| -> Option<(Arc<VhostRoute>, String)> {
            let list = list?;
            for exact_user in [true, false] {
                if let Some(hit) = matched(list, exact_user) {
                    return Some(hit);
                }
            }
            None
        };

        if let Some(hit) = in_table(g.exact.get(&host)) {
            return Some(hit);
        }
        for suffix in &wildcards {
            if let Some(hit) = in_table(g.wildcard.get(suffix)) {
                return Some(hit);
            }
        }
        // 全部域名都不中时看有没有 `*` 兜底代理（官方 `getByRoute` 的最后一步）
        in_table(g.exact.get("*"))
    }

    /// 该域名有没有被任何路由占用（用于提示冲突）。
    #[allow(dead_code)]
    pub fn contains_domain(&self, host: &str) -> bool {
        let g = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        g.exact.contains_key(host) || g.wildcard.values().any(|v| !v.is_empty())
    }
}
#[cfg(test)]
pub(crate) mod tests {
    //! 路由表单元测试：域名优先级、路径前缀、跨租户归属与注销回收。
    //!
    //! `route` / `route_of` / `table_with` 是**跨模块**共用的测试构造器，
    //! 因此对 crate 可见；其余辅助函数保持私有。

    use super::*;
    use crate::pool::dummy_client;
    // -----------------------------------------------------------------------
    // 辅助构造
    // -----------------------------------------------------------------------

    pub(crate) fn route(
        name: &str,
        domain: &str,
        locations: &[&str],
        kind: VhostKind,
    ) -> Arc<VhostRoute> {
        Arc::new(VhostRoute {
            proxy_name: name.to_string(),
            client: dummy_client(name),
            domain: domain.to_string(),
            locations: locations.iter().map(|s| s.to_string()).collect(),
            http_user: String::new(),
            http_pwd: String::new(),
            route_by_http_user: String::new(),
            rewrite_host: String::new(),
            req_headers: HashMap::new(),
            resp_headers: HashMap::new(),
            kind,
        })
    }

    fn http_route(name: &str, domain: &str) -> Arc<VhostRoute> {
        route(name, domain, &["/"], VhostKind::Http)
    }

    /// 用**指定的**客户端构造路由（第四轮 H1 的测试要用它来区分租户）。
    ///
    /// `route()` 每次都会新建一个 `Arc<ClientState>`，两个路由即便同名也属于
    /// **不同**租户 —— 这正好是 H1 要覆盖的场景，所以需要能显式传入归属。
    pub(crate) fn route_of(
        client: &Arc<ClientState>,
        name: &str,
        domain: &str,
        locations: &[&str],
    ) -> Arc<VhostRoute> {
        Arc::new(VhostRoute {
            proxy_name: name.to_string(),
            client: client.clone(),
            domain: domain.to_string(),
            locations: locations.iter().map(|s| s.to_string()).collect(),
            http_user: String::new(),
            http_pwd: String::new(),
            route_by_http_user: String::new(),
            rewrite_host: String::new(),
            req_headers: HashMap::new(),
            resp_headers: HashMap::new(),
            kind: VhostKind::Http,
        })
    }

    pub(crate) fn table_with(routes: Vec<Arc<VhostRoute>>) -> VhostTable {
        let t = VhostTable::default();
        for r in routes {
            t.register(r).expect("注册路由");
        }
        t
    }

    // -----------------------------------------------------------------------
    // 路由表
    // -----------------------------------------------------------------------

    #[test]
    fn exact_domain_lookup() {
        let t = table_with(vec![http_route("web", "a.example.com")]);
        let (hit, loc) = t
            .lookup("a.example.com", "/x", None, VhostKind::Http)
            .expect("应命中");
        assert_eq!(hit.proxy_name, "web");
        assert_eq!(loc, "/");
        assert!(t
            .lookup("nope.example.com", "/", None, VhostKind::Http)
            .is_none());
    }

    #[test]
    fn host_matching_is_case_insensitive_and_tolerates_trailing_dot() {
        let t = table_with(vec![http_route("web", "a.example.com")]);
        // DNS 大小写无关，且很多客户端会带上根域名的尾部点
        assert!(t
            .lookup("A.Example.COM", "/", None, VhostKind::Http)
            .is_some());
        assert!(t
            .lookup("a.example.com.", "/", None, VhostKind::Http)
            .is_some());
    }

    #[test]
    fn wildcard_matches_subdomains_at_any_depth() {
        let t = table_with(vec![http_route("web", "*.example.com")]);
        assert!(t
            .lookup("a.example.com", "/", None, VhostKind::Http)
            .is_some());
        assert!(t
            .lookup("a.b.example.com", "/", None, VhostKind::Http)
            .is_some());
        // 裸域名本身不该被 *.example.com 匹配
        assert!(t
            .lookup("example.com", "/", None, VhostKind::Http)
            .is_none());
    }

    #[test]
    fn exact_route_wins_over_wildcard() {
        let t = table_with(vec![
            http_route("wild", "*.example.com"),
            http_route("exact", "a.example.com"),
        ]);
        let (hit, _) = t
            .lookup("a.example.com", "/", None, VhostKind::Http)
            .expect("应命中");
        assert_eq!(hit.proxy_name, "exact", "精确域名必须优先于通配");
        let (hit2, _) = t
            .lookup("b.example.com", "/", None, VhostKind::Http)
            .expect("应命中");
        assert_eq!(hit2.proxy_name, "wild");
    }

    #[test]
    fn longest_location_prefix_wins() {
        // 注册顺序故意打乱：排序必须发生在查表侧或者通过 locations 的顺序保证
        let t = table_with(vec![
            route("admin", "x.com", &["/api/admin"], VhostKind::Http),
            route("api", "x.com", &["/api"], VhostKind::Http),
            route("root", "x.com", &["/"], VhostKind::Http),
        ]);
        let hit = |p: &str| {
            t.lookup("x.com", p, None, VhostKind::Http)
                .unwrap()
                .0
                .proxy_name
                .clone()
        };
        assert_eq!(hit("/api/admin/u"), "admin");
        assert_eq!(hit("/api/u"), "api");
        assert_eq!(hit("/other"), "root");
    }

    #[test]
    fn https_routes_do_not_leak_into_http_lookups() {
        let t = table_with(vec![route("secure", "x.com", &["/"], VhostKind::Https)]);
        assert!(
            t.lookup("x.com", "/", None, VhostKind::Http).is_none(),
            "http 请求绝不能打到 https 路由上（两者在同一张表里）"
        );
        assert!(t.lookup("x.com", "/", None, VhostKind::Https).is_some());
    }

    /// `route_by_http_user` 让**同一个租户**的多条路由共用一个域名 + 路径。
    ///
    /// ★ v0.5.6（审计总报告 M1）：这些路由必须来自**同一个客户端** ——
    ///   跨租户的"多作用域"现在一律算冲突（服务端无法分辨合法的多作用域
    ///   与寄生劫持，而后者能直接收割凭据）。原先用 `route()` 辅助函数
    ///   逐个新建客户端，恰好把"跨租户"这个语义喂了进去。
    #[test]
    fn route_by_http_user_filters_candidates() {
        let t = VhostTable::default();
        // ★ 两条路由同属一个客户端（真实拓扑：一台 frpc 挂多条代理）
        let me = dummy_client("me");
        let mut alice = route_of(&me, "alice-app", "x.com", &["/"]);
        Arc::get_mut(&mut alice).unwrap().route_by_http_user = "alice".to_string();
        t.register(alice).expect("注册");
        t.register(route_of(&me, "anon", "x.com", &["/"]))
            .expect("同租户 + 不同作用域 ⇒ 允许共存");

        assert_eq!(
            t.lookup("x.com", "/", Some("alice"), VhostKind::Http)
                .unwrap()
                .0
                .proxy_name,
            "alice-app"
        );
        assert_eq!(
            t.lookup("x.com", "/", Some("bob"), VhostKind::Http)
                .unwrap()
                .0
                .proxy_name,
            "anon"
        );
        assert_eq!(
            t.lookup("x.com", "/", None, VhostKind::Http)
                .unwrap()
                .0
                .proxy_name,
            "anon"
        );
    }

    /// ★★ v0.5.6 回归（审计总报告 M1）：**跨租户**不得靠 `route_by_http_user`
    /// 在同一个域名 + 路径上寄生。
    ///
    /// 修复前 `same_scope` 只比字符串 ⇒ 攻击者填一个**不同的作用域值**
    /// 就能跳过冲突检查、注册成功且无告警；之后**带该用户名的 Basic 凭据**
    /// 的访客请求会被 `lookup` 第 1 轮命中攻击者的路由，流量与凭据一起被收割。
    #[test]
    fn 跨租户不得靠_route_by_http_user_寄生() {
        let t = VhostTable::default();
        let victim = dummy_client("victim-run");
        let attacker = dummy_client("attacker-run");

        // 受害者：兜底路由（未配 routeByHTTPUser）
        t.register(route_of(&victim, "victim-web", "web.test", &["/"]))
            .expect("受害者注册");

        // 攻击者：同样的域名 + 路径，但带一个**不同的**作用域值
        let mut evil = route_of(&attacker, "evil-web", "web.test", &["/"]);
        Arc::get_mut(&mut evil).unwrap().route_by_http_user = "alice".to_string();
        let e = t
            .register(evil)
            .expect_err("跨租户 + 不同作用域也必须冲突（M1）");
        // ★ v0.5.7（第六轮审计 D-3）：文案改为"已被占用"，**不再回显占用者**。
        //   同时断言它**不泄露**别人的代理名。
        let msg = e.to_string();
        assert!(msg.contains("已被占用"), "{msg}");
        assert!(
            !msg.contains("victim-web"),
            "冲突文案不得回显占用者的代理名（D-3）：{msg}"
        );

        // 关键断言：带 alice 凭据的请求仍然打到**受害者**那里，没被寄生
        assert_eq!(
            t.lookup("web.test", "/", Some("alice"), VhostKind::Http)
                .unwrap()
                .0
                .proxy_name,
            "victim-web",
            "攻击者没能入表，带凭据的请求必须仍归受害者"
        );
    }

    /// 跨租户 + **相同**作用域同样冲突（原有保护，防回退）。
    ///
    /// ★ 这一条专门盯着审计报告给的那个**错误修法**：它建议把
    ///   `same_scope` 改成 `same_owner && (作用域相等)`，那会让跨租户同作用域
    ///   从"冲突"变成"共存" —— **新开一个洞**。
    #[test]
    fn 跨租户同作用域必须冲突() {
        let t = VhostTable::default();
        let a = dummy_client("a-run");
        let b = dummy_client("b-run");
        t.register(route_of(&a, "a-web", "web.test", &["/"]))
            .expect("先注册");
        assert!(
            t.register(route_of(&b, "b-web", "web.test", &["/"]))
                .is_err(),
            "跨租户 + 同作用域 + 同路径必须冲突"
        );
    }

    #[test]
    fn duplicate_location_is_rejected_but_nesting_is_allowed() {
        let t = table_with(vec![route("a", "x.com", &["/api"], VhostKind::Http)]);
        // 完全相同的路径：两个代理没法区分 -> 冲突
        assert!(t
            .register(route("dup", "x.com", &["/api"], VhostKind::Http))
            .is_err());
        // 嵌套路径：由最长前缀规则裁决，不算冲突（frp 同款行为）
        assert!(t
            .register(route("nested", "x.com", &["/api/v1"], VhostKind::Http))
            .is_ok());
        assert!(t
            .register(route("root", "x.com", &["/"], VhostKind::Http))
            .is_ok());
        assert!(t
            .register(route("side", "x.com", &["/admin"], VhostKind::Http))
            .is_ok());
        // 验证嵌套之后路由仍然走得对
        assert_eq!(
            t.lookup("x.com", "/api/v1/x", None, VhostKind::Http)
                .unwrap()
                .0
                .proxy_name,
            "nested"
        );
        assert_eq!(
            t.lookup("x.com", "/api/x", None, VhostKind::Http)
                .unwrap()
                .0
                .proxy_name,
            "a"
        );
    }

    /// 同一条代理（**同一客户端**同名）重复注册 ⇒ 替换而非堆积。
    ///
    /// ★ v0.5.5（第四轮 H1）：这个用例现在必须显式用**同一个** client ——
    /// 原先 `route()` 每次都新建 Arc，两个路由其实属于不同租户，
    /// 恰好因为修复前的代码"只比名字"才通过。修复后它正确地判成了冲突，
    /// 于是这条测试暴露了自己在无意中依赖了那个 bug（见下面的 H1 用例）。
    #[test]
    fn same_proxy_reregistration_replaces_old_route() {
        let t = VhostTable::default();
        let me = dummy_client("me");
        t.register(route_of(&me, "same", "x.com", &["/old"]))
            .unwrap();
        t.register(route_of(&me, "same", "x.com", &["/new"]))
            .unwrap();
        let list = { t.inner.lock().unwrap().exact.get("x.com").cloned().unwrap() };
        assert_eq!(list.len(), 1, "同一客户端的同名代理重复注册应替换而非堆积");
        assert_eq!(list[0].locations, vec!["/new"]);
    }

    // ------------------------------------------------------------------
    // 第四轮 H1：跨租户的域名路由劫持
    // ------------------------------------------------------------------

    /// ★★ H1 核心回归：**不同租户**用同一个代理名注册同一个域名 ⇒ 必须被拒。
    ///
    /// 修复前的行为：`same_proxy` 只比名字 ⇒ 判成"同一条代理的重复注册" ⇒
    /// 跳过冲突检查 ⇒ `retain` 把**对方**的路由删掉 ⇒ 攻击者顶掉受害者的域名。
    ///
    /// 修复后：`same_owner` 比 `Arc::ptr_eq`，两个租户 ⇒ 不是 same_proxy ⇒
    /// 同名同路径 ⇒ 走冲突检查 ⇒ 拒绝。
    #[test]
    fn 跨租户同名代理不得顶掉别人的域名路由() {
        let t = VhostTable::default();
        let victim = dummy_client("victim-run");
        let attacker = dummy_client("attacker-run");

        // 受害者先注册并生效
        t.register(route_of(&victim, "victim.web", "web.test", &["/"]))
            .expect("受害者注册");
        let (hit, _) = t
            .lookup("web.test", "/", None, VhostKind::Http)
            .expect("域名应可用");
        assert!(Arc::ptr_eq(&hit.client, &victim), "域名此时应归受害者");

        // 攻击者用**同一个代理名**注册**同一个域名** ⇒ 必须被拒
        let err = t
            .register(route_of(&attacker, "victim.web", "web.test", &["/"]))
            .expect_err("跨租户同名同域名必须被拒绝");
        let msg = err.to_string();
        // ★ v0.5.7（第六轮审计 D-3）：文案改为"已被占用"，**不再回显占用者**。
        assert!(msg.contains("已被占用"), "错误要说清冲突：{msg}");
        assert!(
            !msg.contains("victim.web"),
            "冲突文案不得回显占用者的代理名（D-3）：{msg}"
        );

        // ★ 关键断言：域名**仍然**归受害者，没有被顶掉
        let (hit2, _) = t
            .lookup("web.test", "/", None, VhostKind::Http)
            .expect("域名仍应可用");
        assert!(
            Arc::ptr_eq(&hit2.client, &victim),
            "攻击者注册被拒后，域名必须仍归受害者"
        );
        assert_eq!(hit2.proxy_name, "victim.web");
    }

    /// H1 的第二个面：客户端 A 不能靠 `CloseProxy` 摘掉 B 的同名路由。
    #[test]
    fn 跨租户不得靠关代理摘掉别人的域名路由() {
        let t = VhostTable::default();
        let victim = dummy_client("victim-run");
        let attacker = dummy_client("attacker-run");
        t.register(route_of(&victim, "victim.web", "web.test", &["/"]))
            .unwrap();

        // 攻击者"关掉"一个自己根本没有的同名代理
        let removed = t.remove_proxy(&attacker, "victim.web");
        assert!(!removed, "攻击者没有这条代理，不该摘掉任何东西");
        assert!(
            t.lookup("web.test", "/", None, VhostKind::Http).is_some(),
            "受害者的域名路由必须还在"
        );

        // 受害者自己关才有效
        assert!(t.remove_proxy(&victim, "victim.web"));
        assert!(
            t.lookup("web.test", "/", None, VhostKind::Http).is_none(),
            "持有者自己关应当真的摘掉"
        );
    }

    #[test]
    fn different_proxies_can_share_exact_domain_with_distinct_paths() {
        let t = VhostTable::default();
        for (n, p) in [("one", "/a"), ("two", "/b")] {
            t.register(route(n, "x.com", &[p], VhostKind::Http))
                .unwrap();
        }
        let list = { t.inner.lock().unwrap().exact.get("x.com").cloned().unwrap() };
        assert_eq!(list.len(), 2);
    }

    #[test]
    fn unregister_client_reclaims_all_its_domains() {
        let t = VhostTable::default();
        let client = dummy_client("owner");
        for d in ["a.com", "b.com", "*.c.com"] {
            let mut r = route("p", d, &["/"], VhostKind::Http);
            Arc::get_mut(&mut r).unwrap().client = client.clone();
            t.register(r).unwrap();
        }
        assert!(t.lookup("a.com", "/", None, VhostKind::Http).is_some());
        t.unregister_client(&client);
        for d in ["a.com", "b.com", "x.c.com"] {
            assert!(
                t.lookup(d, "/", None, VhostKind::Http).is_none(),
                "{d} 应被回收"
            );
        }
        // 空桶也要清掉，否则长期跑下来 map 里会堆满只增不减的 key
        let g = t.inner.lock().unwrap();
        assert!(g.exact.is_empty() && g.wildcard.is_empty());
    }

    #[test]
    fn unrelated_client_keeps_its_routes() {
        let t = VhostTable::default();
        let owner = dummy_client("owner");
        let other = dummy_client("other");
        let mut keep = route("keep", "keep.com", &["/"], VhostKind::Http);
        Arc::get_mut(&mut keep).unwrap().client = other.clone();
        let mut drop_me = route("drop", "drop.com", &["/"], VhostKind::Http);
        Arc::get_mut(&mut drop_me).unwrap().client = owner.clone();
        t.register(keep).unwrap();
        t.register(drop_me).unwrap();

        t.unregister_client(&owner);
        assert!(t.lookup("drop.com", "/", None, VhostKind::Http).is_none());
        assert!(
            t.lookup("keep.com", "/", None, VhostKind::Http).is_some(),
            "不能误删别人的域名"
        );
    }

    /// 通配走查的规则与官方 `getByRoute` 一致：逐级把**最左标签**换成 `*`，
    /// 且不会退到只剩两段的后缀 —— 所以 `*.com` 谁都匹配不到
    /// （官方那句注释就是"别让 example.com 命中 *.com"）。
    #[test]
    fn 通配走查不会退到只剩两段的后缀() {
        let t = table_with(vec![route("tld", "*.com", &["/"], VhostKind::Http)]);
        assert!(t
            .lookup("example.com", "/", None, VhostKind::Http)
            .is_none());
        assert!(t
            .lookup("a.example.com", "/", None, VhostKind::Http)
            .is_none());

        // 正常的三段通配照旧要多深有多深
        let t2 = table_with(vec![route(
            "wild",
            "*.example.com",
            &["/"],
            VhostKind::Http,
        )]);
        assert!(t2
            .lookup("a.example.com", "/", None, VhostKind::Http)
            .is_some());
        assert!(t2
            .lookup("a.b.example.com", "/", None, VhostKind::Http)
            .is_some());
    }
}
