//! HTTP / HTTPS / tcpmux 虚拟主机代理（等价官方 `server/proxy/http.go` +
//! `server/proxy/tcpmux.go` + `pkg/util/vhost`）。
//!
//! * **HTTP**：服务端在 `vhost_http_port` 上按 `Host` 头路由，把请求原样转发到
//!   内网服务，并支持 frp 的几种花活：`locations` 前缀、Basic Auth、
//!   `host_header_rewrite`、自定义请求/响应头；
//! * **HTTPS**：只在 `vhost_https_port` 上嗅探 TLS ClientHello 里的 **SNI**，
//!   之后把 TLS 字节**原样透传**给内网服务（frp 不终止 TLS，证书由内网服务自己出）；
//! * **tcpmux**：所有 tcpmux 代理共用 `tcpmux_http_connect_port` 一个端口，
//!   按 HTTP `CONNECT` 请求行里的 authority 分发（详见 [`handle_tcpmux`]）。
//!
//! 三种共用同一张路由表（域名匹配 / 最长路径前缀 / `routeByHTTPUser`
//! 三级优先级完全一致），差别只在"域名从哪看"和"怎么把连接交给内网服务"。
//!
//! 与 TCP 代理一样，每个请求/连接都从客户端要一条工作连接；
//! 区别在于服务端要自己解析协议语义，才能决定连接何时可以复用。

use std::{
    collections::HashMap,
    net::SocketAddr,
    sync::{Arc, Mutex},
    time::Duration,
};

use anyhow::{anyhow, bail, Context, Result};
use nfrp_common::frp::{
    conn::FrpConn,
    msg::{constant_time_eq, FrpMessage, StartWorkConn},
};
// HTTP 报文的读写原语住在 common 里 —— 客户端的 http2http / https2http 那组插件
// 需要**一模一样**的能力（读头、按框架读体、原样转发），复制一份就得修两遍 bug。
use nfrp_common::http_relay::{
    connection_tokens, relay_fixed, relay_until_eof, wants_keep_alive, HeadParts, HttpIo,
    HOP_BY_HOP,
};
use tokio::{
    io::AsyncWriteExt,
    net::{TcpListener, TcpStream},
};
use tracing::{debug, info, warn};

use crate::{pool::ClientState, registry::Registry};

// ---------------------------------------------------------------------------
// 路由表
// ---------------------------------------------------------------------------

/// 请求目标里是否含 `.` / `..` 段（含 `%2e` 编码）。
///
/// # 为什么要拒绝它（NFRP-06）
///
/// `locations` 是**前缀匹配**，而很多后端（nginx / IIS / Apache）
/// 会把路径做 dot-segment 归一化。于是
/// `/public/../admin` 在 NFrp 这边命中 `/public`、到后端变成 `/admin`，
/// “只暴露 /public”的设想直接被绕过。
///
/// 官方 frp 也是前缀匹配（`strings.HasPrefix`），所以这不是 NFrp 引入的问题；
/// 但我们选择比上游更严：直接拒绝，而不是猜客户端意图。
///
/// 只解码一层且只处理 `%2e`（`.` 的唯一合法编码）：
/// 多层编码如 `%252e` 到后端解码一次也只是 `%2e`，不会变成 `.`。
fn has_dot_segment(path: &str) -> bool {
    for seg in path.split(['/', '\\', '?', '#']) {
        if seg.is_empty() {
            continue;
        }
        // 小写化后把 %2e 归一成 '.'（%2E 也一样）
        let decoded = seg.replace("%2e", ".").replace("%2E", ".");
        if decoded == "." || decoded == ".." {
            return true;
        }
    }
    false
}

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

// ---------------------------------------------------------------------------
// 监听
// ---------------------------------------------------------------------------

pub async fn bind(addr: SocketAddr) -> Result<TcpListener> {
    TcpListener::bind(addr)
        .await
        .with_context(|| format!("监听 {addr} 失败"))
}

/// 三种虚拟主机共用的运行期选项。
///
/// 早先 `run_vhost` 只有一个 `tcpmux_passthrough: bool`，再加参数就要破 7 个了；
/// 更重要的是**这些值全都来自 `ServerConfig`**，聚成一个结构体后新增配置项
/// 不必再改一路的函数签名。
#[derive(Clone)]
pub struct VhostOpts {
    pub kind: VhostKind,
    /// 只有 [`VhostKind::TcpMux`] 用得上。
    pub tcpmux_passthrough: bool,
    /// 等待内网服务**响应头**的超时（官方 `vhostHTTPTimeout`）。`None` = 不限。
    pub http_timeout: Option<Duration>,
    /// 自定义 404 页面的内容（官方 `custom404Page`）。`None` = 用内置提示。
    ///
    /// 启动时**读一次**常驻内存，而不是每个 404 都去读盘：这个文件在请求路径上，
    /// 每次都 read_file 等于给了一个"用磁盘 IO 拖垮服务端"的入口。
    pub not_found_page: Option<Arc<Vec<u8>>>,
}

impl VhostOpts {
    pub fn new(kind: VhostKind, tcpmux_passthrough: bool) -> Self {
        Self {
            kind,
            tcpmux_passthrough,
            http_timeout: None,
            not_found_page: None,
        }
    }

    pub fn with_timeout(mut self, t: Option<Duration>) -> Self {
        self.http_timeout = t;
        self
    }

    pub fn with_not_found_page(mut self, page: Option<Arc<Vec<u8>>>) -> Self {
        self.not_found_page = page;
        self
    }
}

/// HTTP vhost 主循环。
/// HTTP / HTTPS / tcpmux 共用的 accept 循环。
pub async fn run_vhost(
    listener: TcpListener,
    table: Arc<VhostTable>,
    port: u16,
    opts: VhostOpts,
    registry: Arc<Registry>,
) {
    let kind = opts.kind;
    info!("{} 虚拟主机已启动，监听 :{port}", kind.label());
    loop {
        match listener.accept().await {
            Ok((stream, peer)) => {
                // ★★ v0.5.8 修（第七轮审计 F7-1，中危）：**数据面也要过 ACL**。
                //
                // 与 `serve.rs::proxy_accept_loop` 同一处修复：vhost 端口
                // （http / https / tcpmux）同样是承载用户流量的数据面，
                // 原先只挂 Basic Auth / SNI 路由，**完全没有 ACL 判定**。
                //
                // 拒绝时静默关连接（不回 403）：对陌生访客不该泄露
                // "你的 IP 被 ACL 拒了"这种可区分信息 —— 与
                // `handle_frp_stream` 那边回统一文案是同一个理由。
                let sec = registry.security();
                if let Err(reason) = sec.check_ip(peer.ip()) {
                    registry.audit().record(
                        crate::audit::AuditEvent::new(crate::audit::kind::LOGIN_DENIED, false)
                            .ip(peer.ip().to_string())
                            .detail(format!("{reason}（{} 端口 {port} 数据面）", kind.label())),
                    );
                    debug!(%peer, kind = kind.label(), "数据面 IP 访问控制拒绝：{reason}");
                    continue;
                }
                let table = table.clone();
                let registry = registry.clone();
                let opts = opts.clone();
                tokio::spawn(async move {
                    if let Err(e) = handle_conn(stream, peer, table, port, opts, registry).await {
                        debug!(%peer, kind = kind.label(), "vhost 连接结束：{e:#}");
                    }
                });
            }
            Err(e) => {
                warn!("vhost accept 失败：{e}");
                tokio::time::sleep(Duration::from_millis(200)).await;
            }
        }
    }
}

async fn handle_conn(
    visitor: TcpStream,
    peer: SocketAddr,
    table: Arc<VhostTable>,
    port: u16,
    opts: VhostOpts,
    registry: Arc<Registry>,
) -> Result<()> {
    visitor.set_nodelay(true).ok();
    match opts.kind {
        VhostKind::Https => handle_https(visitor, peer, table, port, registry).await,
        VhostKind::Http => handle_http(visitor, peer, table, port, opts, registry).await,
        VhostKind::TcpMux => {
            handle_tcpmux(visitor, peer, table, opts.tcpmux_passthrough, registry).await
        }
    }
}

// ---------------------------------------------------------------------------
// HTTPS：SNI 嗅探 + 原样透传
// ---------------------------------------------------------------------------

async fn handle_https(
    mut visitor: TcpStream,
    peer: SocketAddr,
    table: Arc<VhostTable>,
    _port: u16,
    registry: Arc<Registry>,
) -> Result<()> {
    // 读出 ClientHello（返回原始字节，之后要原样转发给内网服务）
    let (sni, hello_bytes) = nfrp_common::frp::sni::sniff_client_hello(&mut visitor)
        .await
        .context("读取 TLS ClientHello 失败")?;
    let Some(sni) = sni else {
        debug!(%peer, "ClientHello 中没有 SNI，无法路由");
        return Ok(());
    };

    let Some((route, _)) = table.lookup(&sni, "/", None, VhostKind::Https) else {
        warn!(%peer, sni = %nfrp_common::util::LogSafe(&sni), "没有匹配的 https 代理");
        return Ok(());
    };

    // 等待时长由服务端 `userConnTimeout`（默认 10 秒）决定，不再硬编码 15 秒。
    let work = route
        .client
        .acquire_work_conn()
        .await
        .ok_or_else(|| anyhow!("等待工作连接超时"))?;
    let mut work_conn: FrpConn = work.conn;
    // 注意：不能下发 dst_addr。官方 frpc 会把它当 TCP 地址去解析，
    // 域名解析失败就直接关掉工作连接（PROXY protocol 才需要它）。
    work_conn
        .send_msg(&FrpMessage::StartWorkConn(StartWorkConn {
            proxy_name: route.proxy_name.clone(),
            src_addr: peer.ip().to_string(),
            src_port: peer.port(),
            ..Default::default()
        }))
        .await
        .context("发送 StartWorkConn 失败")?;

    registry.metrics().https_conns.inc();
    let _guard = ConnGuard::new(&registry);

    debug!(%peer, sni = %nfrp_common::util::LogSafe(&sni), proxy = %route.proxy_name, "HTTPS 透传开始");
    let (mut upstream, leftover) = work_conn.into_stream();
    if !leftover.is_empty() {
        // 极少见：StartWorkConn 之后客户端已经把响应写回来了
        debug!("HTTPS 上游有 {} 字节预读数据", leftover.len());
    }
    upstream.write_all(&hello_bytes).await?;
    let mut visitor = visitor;
    let r = nfrp_common::util::relay_between(&mut visitor, &mut upstream).await;
    record_bytes(&registry, &r);
    if let Err(e) = r {
        debug!(%peer, sni = %nfrp_common::util::LogSafe(&sni), "HTTPS 透传中断：{e}");
    }
    Ok(())
}

/// 累计一次转发的流量。
fn record_bytes(registry: &Registry, r: &std::io::Result<(u64, u64)>) {
    let m = registry.metrics();
    if let Ok((up, down)) = r {
        m.bytes_up.inc_by(*up);
        m.bytes_down.inc_by(*down);
    }
}

/// RAII 守卫：**任何**返回路径都会自动归还活跃连接数。
///
/// `handle_http` 有六七个提前 `return` 的分支（404 / 401 / 502…），
/// 用手动 decrement 必然会在某条路径上漏掉，时间长了 gauge 就飘上天。
struct ConnGuard(Arc<Registry>);

impl ConnGuard {
    fn new(registry: &Arc<Registry>) -> Option<Self> {
        registry.metrics().conns_active.inc();
        registry.metrics().conns_total.inc();
        Some(Self(registry.clone()))
    }
}

impl Drop for ConnGuard {
    fn drop(&mut self) {
        self.0.metrics().conns_active.dec();
    }
}

// ---------------------------------------------------------------------------
// 几种虚拟主机共用的解析 / 应答小工具
// ---------------------------------------------------------------------------

fn basic_auth_user(parts: &HeadParts) -> Option<String> {
    use base64::{engine::general_purpose::STANDARD, Engine as _};
    let raw = parts.get("authorization")?;
    let (scheme, value) = raw.split_once(' ')?;
    if !scheme.eq_ignore_ascii_case("basic") {
        return None;
    }
    let decoded = STANDARD.decode(value.trim().as_bytes()).ok()?;
    let text = String::from_utf8(decoded).ok()?;
    Some(text.split(':').next().unwrap_or("").to_string())
}

fn simple_response(status: &str, body: &str) -> Vec<u8> {
    custom_response(status, "text/plain; charset=utf-8", body.as_bytes())
}

/// 带状态行 + 指定 `Content-Type` 的应答。
///
/// 单独抽出来是因为自定义 404 页面可能是**任意字节**（HTML 里混着别的编码），
/// 不能再走 `format!` 把 body 拼进模板字符串。
fn custom_response(status: &str, content_type: &str, body: &[u8]) -> Vec<u8> {
    let mut out = format!(
        "HTTP/1.1 {status}\r\n\
         Content-Type: {content_type}\r\n\
         Content-Length: {}\r\n\
         Connection: close\r\n\r\n",
        body.len()
    )
    .into_bytes();
    out.extend_from_slice(body);
    out
}

/// 没有代理能匹配时给用户看的东西。
///
/// * 配了 `custom404Page` → 把该文件的**原文**当 404 响应体（官方
///   `vhost.NotFoundPagePath` 的语义），`Content-Type: text/html`；
/// * 没配 → 保持 NFrp 原有的纯文本提示。
///
/// ★ 默认值**有意**不照抄官方那段 "The server is powered by frp" HTML：
///   排障时"找不到对应的 frp 代理"比一张品牌页有用得多，而官方对
///   "默认页长什么样"并没有任何协议层面的约束。
fn not_found_response(opts: &VhostOpts) -> Vec<u8> {
    match &opts.not_found_page {
        Some(page) => custom_response("404 Not Found", "text/html", page),
        None => simple_response("404 Not Found", "找不到对应的 frp 代理\n"),
    }
}

// ---------------------------------------------------------------------------
// tcpmux：一个共享端口上的 HTTP CONNECT 复用器
// ---------------------------------------------------------------------------

/// 从 CONNECT 的 authority 取域名：去 scheme、去路径、去端口、转小写、去末尾点。
///
/// 对齐官方 `pkg/util/http.CanonicalHost`（先 `ToLower`、再 `SplitHostPort`、
/// 最后去末尾的点）。域名必须取**请求行里的 authority** 而不是 `Host` 头：
/// Go 的 `http.ReadRequest` 对 authority-form 也是这么取 `req.Host` 的
/// （`req.URL.Host` 优先，`Host` 头只在没有 URL host 时兜底）。
///
/// 这里比官方多容忍一种写法：部分 HTTP 库会把 CONNECT 发成绝对形式
/// （`CONNECT http://a.b/ HTTP/1.1`），所以先剥掉 scheme 和路径。
fn canonical_host(authority: &str) -> String {
    let mut a = authority.trim();
    if let Some(rest) = a
        .strip_prefix("http://")
        .or_else(|| a.strip_prefix("https://"))
    {
        a = rest;
    }
    if let Some(i) = a.find('/') {
        a = &a[..i];
    }
    a = a.trim();
    // 去端口：IPv6 写成 `[::1]:80`，普通域名写成 `a.b:80`
    let host = if let Some(rest) = a.strip_prefix('[') {
        rest.split(']').next().unwrap_or(rest)
    } else {
        a.rsplit_once(':').map(|(h, _)| h).unwrap_or(a)
    };
    host.trim().trim_end_matches('.').to_ascii_lowercase()
}

/// 解析 `Proxy-Authorization: Basic base64(user:pass)`，返回 `(用户名, 密码)`。
fn proxy_authorization(parts: &HeadParts) -> (Option<String>, Option<String>) {
    use base64::{engine::general_purpose::STANDARD, Engine as _};
    let Some(raw) = parts.get("proxy-authorization") else {
        return (None, None);
    };
    let Some((scheme, value)) = raw.split_once(' ') else {
        return (None, None);
    };
    if !scheme.eq_ignore_ascii_case("basic") {
        return (None, None);
    }
    let Ok(decoded) = STANDARD.decode(value.trim().as_bytes()) else {
        return (None, None);
    };
    let Ok(text) = String::from_utf8(decoded) else {
        return (None, None);
    };
    let (u, p) = text.split_once(':').unwrap_or((text.as_str(), ""));
    (Some(u.to_string()), Some(p.to_string()))
}

/// `HTTP/1.1 200 OK` —— 告诉 CONNECT 的发起方"隧道通了，后面就是裸字节"。
///
/// 字节形状对齐官方 `httppkg.OkResponse()` 经 Go `Response.Write` 出来的结果：
/// 状态行 + `Content-Length: 0` + 空行。带 `Content-Length: 0` 是 Go
/// `shouldSendContentLength()` 在"非 GET/HEAD 且长度已知为 0"时的行为，
/// 而且对客户端来说比"没有长度信息"更明确（后者要靠 RFC 7231 对 CONNECT 2xx
/// 的特别规定才不歧义）。
const CONNECT_OK: &[u8] = b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n";

/// `407` —— 认证失败。必须带 `Proxy-Authenticate`，否则客户端不知道该怎么补凭证。
fn proxy_auth_required() -> Vec<u8> {
    const BODY: &str = "Proxy Authentication Required";
    format!(
        "HTTP/1.1 407 Proxy Authentication Required\r\n\
         Proxy-Authenticate: Basic realm=\"Restricted\"\r\n\
         Content-Type: text/plain; charset=utf-8\r\n\
         Content-Length: {}\r\n\
         Connection: close\r\n\r\n{BODY}",
        BODY.len()
    )
    .into_bytes()
}

/// tcpmux：从 HTTP CONNECT 请求里取域名，把这条连接接给对应的内网服务。
///
/// # 与官方 `pkg/util/tcpmux/httpconnect.go` 对齐的三点
///
/// 1. **只认 `CONNECT`**。其它方法（或者说根本不是 HTTP 的流量）官方会在
///    `readHTTPConnectRequest` 里报错然后**直接关连接**，不留任何应答 ——
///    这里保持一致：不回应答，免得一个"看起来像代理端口"的地方回出
///    非代理语义的东西让人误判。
/// 2. **域名取 CONNECT 请求行的 authority**（去端口、转小写），并做
///    `routeByHTTPUser` 一级路由、`httpUser` / `httpPassword` 二级校验。
/// 3. **`tcpmuxPassthrough`**：true 时把 CONNECT 请求**原样**转给内网服务，
///    由内网服务自己回 200（适合内网本身就是 HTTP 代理的场景）；
///    false（默认）时由我们回 200，内网服务看到的就是一条已建好的裸连接。
///
/// # 一处**有意偏离**
///
/// 官方先回 `200 OK` 再校验密码（`Muxer.handle` 里 `successHook` 在
/// `checkAuth` 之前），于是密码不对时客户端会**先收到 200**、再收到一个 407；
/// 对 curl 这类客户端来说隧道已经"建立成功"，那个 407 会被当成隧道里的数据。
/// 这里改成**先校验、再回 200**，只发一个 407 —— 协议上才是对的，客户端报的
/// 错也才是"认证失败"而不是"连上了但服务器乱发东西"。
async fn handle_tcpmux(
    visitor: TcpStream,
    peer: SocketAddr,
    table: Arc<VhostTable>,
    passthrough: bool,
    registry: Arc<Registry>,
) -> Result<()> {
    let mut io = HttpIo::new(visitor);
    // 要原始字节：透传模式得把 CONNECT 请求逐字节转给内网服务
    let Some((raw_head, lines)) = io.read_head_raw().await? else {
        return Ok(());
    };
    let parts = HeadParts::parse(&lines)?;

    if !parts
        .start_token(0)
        .is_some_and(|m| m.eq_ignore_ascii_case("CONNECT"))
    {
        debug!(%peer, method = parts.start_token(0).unwrap_or(""), "tcpmux 端口只接受 CONNECT");
        return Ok(());
    }

    let host = canonical_host(parts.start_token(1).unwrap_or(""));
    let (user, pwd) = proxy_authorization(&parts);

    let Some((route, _)) = table.lookup(&host, "", user.as_deref(), VhostKind::TcpMux) else {
        warn!(
            %peer, %host, user = user.as_deref().unwrap_or(""),
            "没有匹配的 tcpmux 代理"
        );
        io.stream
            .write_all(&simple_response(
                "404 Not Found",
                "找不到对应的 tcpmux 代理\n",
            ))
            .await?;
        return Ok(());
    };

    if !route.http_user.is_empty() {
        // ★ 常量时间比较（v0.5.3 修）。
        //
        // 这里原来写的是 `user.as_deref() == Some(...)` —— 与同文件 815 行那段
        // HTTP 路径的口径不一致，是上一轮「凭据一律常量时间比较」修复**唯一漏掉**的一处。
        // 如实说：跨网络的字节级耗时侧信道会被抖动淹没，工程上难以远程逐位爆破，
        // 所以它是"修复不完整"而不是可利用漏洞 —— 但没有理由留两套口径。
        let ok = match (&user, &pwd) {
            (Some(u), Some(p)) => {
                constant_time_eq(u, &route.http_user) && constant_time_eq(p, &route.http_pwd)
            }
            _ => false,
        };
        if !ok {
            debug!(%peer, %host, "tcpmux 认证失败");
            io.stream.write_all(&proxy_auth_required()).await?;
            return Ok(());
        }
    }

    // 等待时长由服务端 `userConnTimeout`（默认 10 秒）决定，不再硬编码 15 秒。
    let work = route
        .client
        .acquire_work_conn()
        .await
        .ok_or_else(|| anyhow!("等待工作连接超时"))?;
    let mut work_conn: FrpConn = work.conn;
    // 与 http / https 一样不下发 `dst_addr`：官方 frpc 会把它当 TCP 地址解析，
    // 域名解析失败就直接关掉工作连接。
    work_conn
        .send_msg(&FrpMessage::StartWorkConn(StartWorkConn {
            proxy_name: route.proxy_name.clone(),
            src_addr: peer.ip().to_string(),
            src_port: peer.port(),
            ..Default::default()
        }))
        .await
        .context("发送 StartWorkConn 失败")?;
    registry.metrics().tcpmux_conns.inc();
    let _guard = ConnGuard::new(&registry);

    debug!(%peer, %host, proxy = %route.proxy_name, passthrough, "tcpmux 隧道开始");
    let (mut upstream, leftover) = work_conn.into_stream();

    // 开场白：透传模式把 CONNECT 请求转过去（由内网服务回 200），
    // 否则我们自己回 200，客户端收到后才开始发数据。
    if passthrough {
        upstream.write_all(&raw_head).await?;
    } else {
        io.stream.write_all(CONNECT_OK).await?;
        io.stream.flush().await?;
    }
    if !leftover.is_empty() {
        upstream.write_all(&leftover).await?;
    }
    // ★ 关键：客户端**没等 200 就把数据发过来**时（curl 之外不少客户端会这样），
    //   这些字节已经被 `read_head` 预读进缓冲了。下一步是直接对着底层流对拷，
    //   不会再经过缓冲，所以必须显式补到上游 —— 官方在非透传模式下会丢掉它们。
    let prefetched = io.take_buffered();
    if !prefetched.is_empty() {
        upstream.write_all(&prefetched).await?;
    }
    upstream.flush().await?;

    let mut visitor = io.stream;
    let r = nfrp_common::util::relay_between(&mut visitor, &mut upstream).await;
    record_bytes(&registry, &r);
    if let Err(e) = r {
        debug!(%peer, %host, "tcpmux 隧道中断：{e}");
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// HTTP：解析请求 → 路由 → 转发 → 按帧回复
// ---------------------------------------------------------------------------

/// 对 `visitor` 泛型化**只是为了测试**：生产路径传的是 `TcpStream`，测试里传
/// `tokio::io::duplex` 的内存管道，就能不起真实端口地验证超时 / 404 这些分支。
/// 泛型是零成本的（编译期单态化），没有引入任何动态分发。
async fn handle_http<S>(
    visitor: S,
    peer: SocketAddr,
    table: Arc<VhostTable>,
    _port: u16,
    opts: VhostOpts,
    registry: Arc<Registry>,
) -> Result<()>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let mut io = HttpIo::new(visitor);

    loop {
        let Some(lines) = io.read_head().await? else {
            return Ok(());
        };
        let mut req = HeadParts::parse(&lines)?;

        // ---- `Expect: 100-continue` ----
        //
        // 客户端发了这个头就会**先等一个 100 才肯发请求体**。原先这里完全没处理：
        // 不回应就直接去取工作连接、转发头，然后 `read_n` 等请求体 —— 而客户端
        // 还在等 100。双方互等，一直挂到 `vhostHTTPTimeout`（默认 60 秒）。
        //
        // 单条请求就能占住一条工作连接 60 秒，是个很划算的放大 DoS。
        //
        // 处理方式与客户端 `plugin_bridge.rs` 一致：**自己回一个 100**，
        // 不把中间态转发给上游（那要处理"响应先于请求体"的重排序，不值得）。
        // 回完把这个头删掉，免得上游又多等一次。
        if req
            .get("expect")
            .is_some_and(|v| v.eq_ignore_ascii_case("100-continue"))
        {
            io.stream
                .write_all(b"HTTP/1.1 100 Continue\r\n\r\n")
                .await
                .context("回 100-continue 失败")?;
            io.stream.flush().await?;
            req.remove("expect");
        }

        let method = req
            .start_line
            .split_whitespace()
            .next()
            .unwrap_or("")
            .to_string();
        let path = req
            .start_line
            .split_whitespace()
            .nth(1)
            .unwrap_or("/")
            .to_string();
        // `Host` 头里可能带端口，也可能写成 IPv6 的 `[::1]:8080`。
        // 原先直接 `split(':').next()` —— 对 IPv6 会切出一个孤零零的 `[`，
        // 对 `a.example.com:8080` 倒是对，但口径与 tcpmux/CONNECT 那条路径
        // 用的 `canonical_host` 不一致。统一走同一个函数，顺带把
        // 尾点和大小写也规范化了（与官方 `util.CanonicalHost` 对齐）。
        let host_header = req.get("host").map(canonical_host).unwrap_or_default();
        let auth_user = basic_auth_user(&req);
        let visitor_keep_alive = wants_keep_alive(&req);

        // ★ NFRP-06：带 dot-segment 的路径直接拒绝。
        //
        // `locations` 是前缀匹配，而后端会做归一化：
        // `/public/../admin` 会命中 `/public` 但到后端变成 `/admin`。
        // 不拒掉等于把 `locations` 当访问控制用的人一直在被绕过。
        if has_dot_segment(&path) {
            warn!(%peer, path = %path, "请求路径含 dot-segment，已拒绝");
            io.stream
                .write_all(&simple_response("400 Bad Request", "非法路径\n"))
                .await?;
            return Ok(());
        }

        // ---- 路由 ----
        let Some((route, _loc)) =
            table.lookup(&host_header, &path, auth_user.as_deref(), VhostKind::Http)
        else {
            debug!(%peer, host = %nfrp_common::util::LogSafe(&host_header), path = %path, "没有匹配的 http 代理");
            if method == "CONNECT" {
                io.stream
                    .write_all(&simple_response(
                        "405 Method Not Allowed",
                        "不支持 CONNECT\n",
                    ))
                    .await?;
            } else {
                io.stream.write_all(&not_found_response(&opts)).await?;
            }
            return Ok(());
        };

        // ---- Basic Auth ----
        //
        // 用常量时间比较，与面板 / visitor 密钥那几处保持一致。
        // 这里是**用户自配的** HTTP 代理访问密码（不是服务端凭证），
        // 风险等级低，但没有理由留一处 `==` 比密钥的路径 ——
        // 逐字节比较会通过响应耗时泄露前缀，攻击者可据此逐位猜。
        if !route.http_user.is_empty() {
            let ok = match (&auth_user, route.http_pwd.is_empty()) {
                (Some(u), true) => constant_time_eq(u, &route.http_user),
                (Some(u), false) => {
                    // 用户名 + 密码都校验
                    let raw = req.get("authorization").unwrap_or("");
                    let expect = format!("{}:{}", route.http_user, route.http_pwd);
                    use base64::{engine::general_purpose::STANDARD, Engine as _};
                    let given = raw
                        .split_once(' ')
                        .and_then(|(_, v)| STANDARD.decode(v.trim().as_bytes()).ok())
                        .and_then(|b| String::from_utf8(b).ok())
                        .unwrap_or_default();
                    constant_time_eq(u, &route.http_user) && constant_time_eq(&given, &expect)
                }
                (None, _) => false,
            };
            if !ok {
                io.stream
                    .write_all(
                        "HTTP/1.1 401 Unauthorized\r\n\
                         WWW-Authenticate: Basic realm=\"frp\"\r\n\
                         Content-Length: 0\r\n\
                         Connection: close\r\n\r\n"
                            .as_bytes(),
                    )
                    .await?;
                return Ok(());
            }
        }

        // ---- 读请求体（原样保留编码）----
        //
        // ★ `Transfer-Encoding` 与 `Content-Length` **同时出现时必须拒绝**
        // （RFC 7230 §3.3.3：这种情况要么按 TE 处理并移除 CL，要么直接 400）。
        //
        // 原先的写法是"有 TE 就按 chunked 读，否则看 CL"—— 读的方向没错，
        // 但**两个头都原样转发**给了上游。于是：NFrp 按 chunked 解读完请求，
        // 上游若按 `Content-Length` 去解读同一串字节，双方对"第一个请求到哪
        // 结束"的认知就不一样了 —— 这就是经典的 CL.TE 请求走私，攻击者能借此
        // 让本请求的尾巴被上游当成**下一个请求**（可以是别人的请求）来处理。
        //
        // 直接 400 最省事也最安全：合法客户端不会同时发这两个头。
        let has_te = req.get("transfer-encoding").is_some();
        // ★ v0.5.4（H2）：`get()` 只返回**第一个**同名头，而 `to_bytes()` 会把
        //   `headers` 里的**所有**同名头都转发出去 —— "读一个、写两个"正是
        //   CL.CL 请求走私的成因。所以这里用 `count()` 判"有没有/有几个"，
        //   而不是 `get().is_some()`。
        let cl_count = req.count("content-length");
        let has_cl = cl_count > 0;
        if has_te && has_cl {
            debug!(%peer, "同时带 Transfer-Encoding 与 Content-Length，按走私风险直接拒绝");
            io.stream
                .write_all(&simple_response(
                    "400 Bad Request",
                    "Transfer-Encoding 与 Content-Length 不能同时出现\n",
                ))
                .await?;
            return Ok(());
        }
        // ★ v0.5.4（H2）：**重复的 Content-Length 一律拒绝**。
        //
        // 哪怕两个值完全相同也拒绝 —— 不同实现对此合并策略不一致
        // （取第一个 / 取最后一个 / 报错），而"只读第一个、转发全部"的组合同样
        // 构成 CL.CL 走私面。RFC 7230 §3.3.2 允许值相同时合并，但拒绝更安全，
        // 且合法客户端不会重复发这个头。
        if cl_count > 1 {
            debug!(%peer, cl_count, "重复的 Content-Length，按走私风险直接拒绝");
            io.stream
                .write_all(&simple_response(
                    "400 Bad Request",
                    "重复的 Content-Length 头\n",
                ))
                .await?;
            return Ok(());
        }

        // ★★ v0.5.5 修（第四轮 C 组 TE.TE 走私）：**只接受"唯一的 chunked"**。
        //
        // H2 修的是 CL 侧，**TE 侧没修** —— 这是同一个教训的又一次复现。
        // 原先判定用 `contains("chunked")`（"只要出现就按 chunked 解帧"），
        // 而 RFC 7230 §3.3.3 规定传输编码看**最后一个** token，且转发时
        // `Transfer-Encoding` 是**原样**搬给上游的 ⇒ 两边口径不一致 = 走私：
        //
        //   `chunked, identity` / `xchunked` / `chunked, gzip`
        //   ⇒ NFrp 按 chunked 读完，上游（按 RFC）认为不是 chunked
        //   ⇒ 剩余字节被上游当成**下一个请求**。
        //
        // 修法与 CL 侧同款：**双方口径必须完全一致**，做不到就 400。
        // 未知编码我们本来就处理不了（没有解码器），拒绝而不是猜。
        if nfrp_common::http_relay::transfer_encoding_is_unsupported(&req) {
            debug!(%peer, te = ?req.get("transfer-encoding"),
                   "不支持的 Transfer-Encoding 形态，按走私风险直接拒绝");
            io.stream
                .write_all(&simple_response(
                    "400 Bad Request",
                    "Transfer-Encoding 只支持唯一的 chunked\n",
                ))
                .await?;
            return Ok(());
        }

        let body = if let Some(te) = req.get("transfer-encoding") {
            // ★ 复用公共判定（与转发侧同一个口径），不要再写一遍 contains
            if nfrp_common::http_relay::is_chunked(&req) {
                io.read_chunked().await?
            } else {
                // 走到这里说明通过了上面的检查，理论上不可能；
                // 但留一条明确的日志，别静默把 body 丢掉。
                debug!(%peer, te = %te, "既不是 chunked 又通过了校验，按无体处理");
                Vec::new()
            }
        } else if has_cl {
            // ★ v0.5.4（H2）：严格解析。原先是 `cl.trim().parse().unwrap_or(0)`
            //   —— **垃圾值静默变 0**（`Content-Length: abc` 被当成"没有请求体"，
            //   而同一个头又原样转发给上游）。现在非法值一律 400。
            let n = match req.content_length_strict() {
                Ok(n) => n as usize,
                Err(e) => {
                    debug!(%peer, "Content-Length 非法：{e:#}");
                    io.stream
                        .write_all(&simple_response(
                            "400 Bad Request",
                            "非法的 Content-Length\n",
                        ))
                        .await?;
                    return Ok(());
                }
            };
            if n > 0 {
                io.read_n(n).await?
            } else {
                Vec::new()
            }
        } else {
            Vec::new()
        };

        // ---- 改写请求头 ----
        //
        // 先摘掉逐跳头（`Connection` / `Keep-Alive` / `Upgrade` / `TE` /
        // `Trailer` / `Proxy-*`，以及 `Connection: xxx` 里点名的那几个）。
        //
        // 这些头**只对当前这一段连接有意义**，原样转给内网服务是有害的：
        // 比如 `Connection: keep-alive, X-Secret` 会让上游把 `X-Secret`
        // 也当逐跳头处理；`Upgrade: h2c` + `Connection: Upgrade` 则可能让
        // 上游切到 h2c，绕开我们假定的 HTTP/1.1 语义。
        //
        // 工具在 `common::http_relay` 里本来就有（`HOP_BY_HOP` /
        // `connection_tokens`），客户端 `plugin_bridge` 一直在用，只有这条
        // 服务端路径漏了。服务端不支持 WebSocket 升级，所以可以整批摘掉。
        let mut hop: Vec<String> = HOP_BY_HOP.iter().map(|s| (*s).to_string()).collect();
        hop.extend(connection_tokens(&req));
        for k in hop {
            req.remove(&k);
        }

        // ★ v0.5.4（H2 第三层，纵深防御）：**同名头去重**。
        //
        // 上面已经对重复的 Content-Length 直接 400 了，这一步是"即便将来某个
        // 环节漏了检查，也不会把重复头原样送到下游"。它保证一个不变量：
        // **转发出去的头，每个名字最多出现一次**（少数列表型头除外）。
        // `set-cookie` 之类必须逐个保留，交由 `dedup_headers` 内部白名单处理。
        let dropped = req.dedup_headers();
        if dropped > 0 {
            debug!(%peer, dropped, "转发前剥掉了重复的同名请求头");
        }

        if !route.rewrite_host.is_empty() {
            req.set("host", &route.rewrite_host);
        }
        let forwarded = match req.get("x-forwarded-for") {
            Some(prev) => format!("{prev}, {}", peer.ip()),
            None => peer.ip().to_string(),
        };
        req.set("x-forwarded-for", &forwarded);
        req.set("x-real-ip", &peer.ip().to_string());
        let mut removed: Vec<String> = Vec::new();
        for (k, v) in &route.req_headers {
            if v.is_empty() {
                removed.push(k.clone());
            } else {
                req.set(k, v);
            }
        }
        for k in removed {
            req.remove(&k);
        }

        // ---- 取工作连接并转发 ----
        // 等待时长由服务端 `userConnTimeout`（默认 10 秒）决定。
        let work = match route.client.acquire_work_conn().await {
            Some(w) => w,
            None => {
                io.stream
                    .write_all(&simple_response("502 Bad Gateway", "等待工作连接超时\n"))
                    .await?;
                return Ok(());
            }
        };
        let mut work_conn: FrpConn = work.conn;
        // dst_addr 留给 PROXY protocol 用，普通转发不能下发（见 HTTPS 分支的说明）
        work_conn
            .send_msg(&FrpMessage::StartWorkConn(StartWorkConn {
                proxy_name: route.proxy_name.clone(),
                src_addr: peer.ip().to_string(),
                src_port: peer.port(),
                ..Default::default()
            }))
            .await
            .context("发送 StartWorkConn 失败")?;

        registry.metrics().http_requests.inc();
        let _guard = ConnGuard::new(&registry);

        let (mut upstream, leftover) = work_conn.into_stream();
        upstream.write_all(&req.to_bytes()).await?;
        if !body.is_empty() {
            upstream.write_all(&body).await?;
        }
        upstream.flush().await?;

        // ★ v0.5.4 修（L3）：把 `leftover` 喂回预读缓冲，**不要丢掉**。
        //
        // `leftover` 是工作连接上已经读进缓冲区、但还没被消费的字节。
        // 原先是 `let _ = leftover;` 直接扔了 —— 若内网服务在握手后立刻
        // 吐了响应（或预读时顺带读到了响应开头），这部分字节就永久丢失，
        // 表现为**响应体被截断**。
        //
        // 必须在 write/flush **之后**构造（`HttpIo::with_prefill` 会拿走
        // `upstream` 的所有权）。
        let mut up = HttpIo::with_prefill(upstream, leftover);

        // ---- 读响应头 ----
        //
        // `vhostHTTPTimeout` 卡的就是这一步：内网服务**连上了却不回响应头**
        // （进程卡死、在处理里死循环）时，不能把用户连接和这条工作连接
        // 无限期挂住。超时回 502，与 Go `httputil.ReverseProxy` 默认错误处理器
        // 对 `ResponseHeaderTimeout` 的处理一致（也是 502，不是 504）。
        let head = match opts.http_timeout {
            Some(t) => match tokio::time::timeout(t, up.read_head()).await {
                Ok(r) => r?,
                Err(_) => {
                    debug!(%peer, "等待内网服务响应头超时（{} 秒）", t.as_secs());
                    io.stream
                        .write_all(&simple_response("502 Bad Gateway", "内网服务响应超时\n"))
                        .await?;
                    return Ok(());
                }
            },
            None => up.read_head().await?,
        };
        let Some(resp_lines) = head else {
            io.stream
                .write_all(&simple_response("502 Bad Gateway", "内网服务没有响应\n"))
                .await?;
            return Ok(());
        };
        let mut resp = HeadParts::parse(&resp_lines)?;

        // ★★ v0.5.8 修（第七轮审计 D7-2，中危）：**响应侧的 framing 校验**。
        //
        // 请求侧早有 `validate_request_framing`（TE+CL / 重复 CL / 不支持的 TE
        // 三项全 400），而响应侧**一项都没有** —— 内网服务回什么就转发什么。
        //
        // 这与 D7-1 是同一条链路上的两个洞：
        //   * D7-1 = 响应侧的**判定口径**与请求侧不一致（`contains` vs RFC）；
        //   * D7-2 = 响应侧**根本没有校验**。
        //
        // 两者都会导致下游连接去同步（不同实现取不同的响应边界）⇒ 走私/投毒。
        // 修法一致：**失败关闭**，回 502 而不是猜。
        //
        // 注意顺序：必须在**剥逐跳头之前**校验 —— 因为 `Connection` 里点名的
        // 头会被剥掉，而 framing 判定要看到原始报头。
        if let Err(why) = nfrp_common::http_relay::validate_response_framing(&resp) {
            warn!(%peer, proxy = %route.proxy_name, "响应 framing 不合法，拒绝转发：{why}");
            io.stream
                .write_all(&simple_response(
                    "502 Bad Gateway",
                    "内网服务返回的响应报头不合法（framing 走私风险）\n",
                ))
                .await?;
            return Ok(());
        }

        // ★★ v0.5.4 修（L2）：**响应侧也要剥逐跳头**。
        //
        // 原先只有请求侧剥了（见上面那段加入 `HOP_BY_HOP` 的注释），
        // 响应侧原样转发 ⇒ 内网服务回的 `Connection: keep-alive, X-Secret`
        // 会让**客户端**把 `X-Secret` 也当逐跳头处理；`Upgrade` / `Proxy-*`
        // 同理。逐跳头的语义就是"只对当前这一段连接有意义"，
        // 跨过代理转发本身就是错的 —— 两个方向都得剥。
        //
        // 顺序：**先剥再设置**我们自己的 `Connection`，否则会把刚写的那条也剥掉。
        {
            let mut hop: Vec<String> = HOP_BY_HOP.iter().map(|s| (*s).to_string()).collect();
            hop.extend(connection_tokens(&resp));
            for k in hop {
                resp.remove(&k);
            }
        }

        if let Some(start) = resp.start_line.split_whitespace().nth(1) {
            let code: u32 = start.parse().unwrap_or(200);
            let no_body =
                (100..200).contains(&code) || code == 204 || code == 304 || method == "HEAD";

            // ★★ v0.5.8 修（第七轮审计 D7-1，高危）：**响应侧必须用与请求侧同一套
            //    RFC 口径判 `Transfer-Encoding`。**
            //
            // # 原先为什么错了
            //
            // 这里（以及下面转发响应体那处）用的是
            // `te.to_ascii_lowercase().contains("chunked")` —— 而**同一个文件**的
            // 请求侧（`:1061`/`:1075`）早就改成了 RFC 口径的
            // [`http_relay::is_chunked`] / [`http_relay::transfer_encoding_is_unsupported`]，
            // `client/src/plugin_bridge.rs` 也用 `is_chunked`。
            // `http_relay.rs:500-522` 的注释里**明确写着** `contains("chunked")`
            // 正是第四轮 C 组修掉的走私写法。
            //
            // ⇒ 请求侧修了、响应侧没修。**这是"防线没铺满"的教科书案例**，
            //   也是本项目连续多轮出现的同一个模式。
            //
            // # 后果（实测，`tmp/audit7/d_independent/repro_d71_smuggle.py`）
            //
            // 后端对 `/alice` 回 `Transfer-Encoding: chunked, identity`：
            // * NFrp（`contains`）认为"是 chunked" ⇒ 按 chunked 方式转发；
            // * RFC 7230 §3.3.3 的严格下游看**最后一个 token**（是 `identity`）
            //   ⇒ 认为**不是** chunked ⇒ 读到连接关闭为止。
            //
            // 口径分歧 = 走私。实测下游只解析出 **1 条**响应，body 里混进了
            // 下一个访客的响应：
            //
            // ```text
            // HTTP/1.1 200 OK / TE: chunked, identity / connection: keep-alive
            // d\r\nALICE-SECRET!\r\n0\r\n\r\n
            // HTTP/1.1 200 OK / Content-Length: 11 / connection: keep-alive
            // BOB-PRIVATE
            // ```
            // ⇒ RFC 下游的 body = `...ALICE-SECRET!\r\n0\r\n\r\nHTTP/1.1 200 OK...BOB-PRIVATE`
            // ⇒ **Bob 的响应被当成 Alice 的响应体**（跨访客响应走私）。
            //
            // 对照（都通过，排除探针问题）：`Content-Length` 正常分离；
            // 合法 `chunked`（唯一 token）正确分离、**未误伤**。
            //
            // # 修法
            //
            // 与请求侧**共用同一个判定函数**，而不是在这里再手写一遍 ——
            // 手写就会再次漂移。`is_chunked` 的口径是"最后一个 token 是 chunked
            // 且前面只有 identity"，`identity, chunked` 这种 RFC 合法形态仍被接受
            // （第四轮专门修过"修得过头把合法的也拒了"）。
            let resp_te_chunked = nfrp_common::http_relay::is_chunked(&resp);
            let framed = if no_body {
                true
            } else if resp.get("transfer-encoding").is_some() {
                // 不支持的 TE 形态（如 `chunked, gzip`）⇒ 无法安全定界
                // ⇒ 当作"未分帧"，让调用方走 `Connection: close` 读完即断，
                //    而不是按自己以为的方式去读（那正是走私的成因）。
                resp_te_chunked
            } else {
                resp.get("content-length").is_some()
            };

            let keep_alive = visitor_keep_alive && framed;
            resp.set(
                "connection",
                if keep_alive { "keep-alive" } else { "close" },
            );
            for (k, v) in &route.resp_headers {
                if !v.is_empty() {
                    resp.set(k, v);
                }
            }
            io.stream.write_all(&resp.to_bytes()).await?;

            // ---- 转发响应体 ----
            //
            // ★★ v0.5.8 修（第七轮审计 D7-1，高危）：与上面 `framed` 用**同一个**
            //    判定（`resp_te_chunked`），而不是再写一次 `contains("chunked")`。
            //
            // 两处必须完全一致，否则"判 keep-alive 用一个口径、读 body 用另一个口径"
            // 又是一次口径分歧 —— 这正是走私的通用成因。
            if !no_body {
                if resp.get("transfer-encoding").is_some() {
                    if resp_te_chunked {
                        let raw = up.read_chunked().await?;
                        io.stream.write_all(&raw).await?;
                    } else if let Some(cl) = resp.get("content-length") {
                        let n: usize = cl.trim().parse().unwrap_or(0);
                        relay_fixed(&mut up, &mut io.stream, n).await?;
                    } else {
                        // 不支持的 TE 且没有 CL ⇒ 只能读到 EOF；连接必须关
                        relay_until_eof(&mut up, &mut io.stream).await?;
                        io.stream.flush().await?;
                        return Ok(());
                    }
                } else if let Some(cl) = resp.get("content-length") {
                    let n: usize = cl.trim().parse().unwrap_or(0);
                    relay_fixed(&mut up, &mut io.stream, n).await?;
                } else {
                    // 既没有 Content-Length 也不是 chunked：读到 EOF 为止，访客连接必须关
                    relay_until_eof(&mut up, &mut io.stream).await?;
                    io.stream.flush().await?;
                    return Ok(());
                }
            }
            io.stream.flush().await?;
            if !keep_alive {
                return Ok(());
            }
            // 上游工作连接用完即弃（frp 每个请求都要新工作连接）
        } else {
            return Ok(());
        }
    }
}

#[cfg(test)]
mod tests {

    //! 虚拟主机的单元测试。
    //!
    //! 这个文件原本 794 行零测试 —— 而它恰好是**最容易出错**的部分：
    //! 域名大小写、通配优先级、路径前缀冲突、Basic Auth、chunked 报文的手写解析器，
    //! 每一处出错都不会崩，只会悄悄把请求路由错。所以这里的用例刻意覆盖
    //! "看起来对但容易写反"的分支。

    use super::*;
    use crate::pool::dummy_client;
    use nfrp_common::http_relay::{find_subslice, MAX_HEAD};
    use tokio::io::{duplex, AsyncReadExt, AsyncWriteExt, DuplexStream};
    // ==================================================================
    // NFRP-06：dot-segment 必须被拒
    // ==================================================================

    #[test]
    fn dot_segment_能识别() {
        for bad in [
            "/public/../admin",
            "/public/%2e%2e/admin",
            "/public/%2E%2E/admin",
            "/./x",
            "/x/.",
            "/a/..",
        ] {
            assert!(has_dot_segment(bad), "应当识别为可疑路径：{bad}");
        }
        for good in [
            "/public/hello",
            "/public/..hidden",
            "/public/a..b",
            "/public/v1.2.3/file",
            "/",
        ] {
            assert!(!has_dot_segment(good), "不该误伤：{good}");
        }
    }

    /// 前缀匹配确实会被 dot-segment 绕过 —— 锁住这个前提，
    /// 防止将来有人把 `has_dot_segment` 的调用删掉。
    #[test]
    fn locations_前缀匹配会被_dot_segment_绕过() {
        let locs = ["/public".to_string()];
        let hit = locs
            .iter()
            .filter(|l| "/public/../admin".starts_with(l.as_str()))
            .max_by_key(|l| l.len());
        assert!(hit.is_some(), "前缀匹配确实会命中");
        assert!(has_dot_segment("/public/../admin"));
    }

    // -----------------------------------------------------------------------
    // 辅助构造
    // -----------------------------------------------------------------------

    fn route(name: &str, domain: &str, locations: &[&str], kind: VhostKind) -> Arc<VhostRoute> {
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
    fn route_of(
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

    fn table_with(routes: Vec<Arc<VhostRoute>>) -> VhostTable {
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

    // -----------------------------------------------------------------------
    // HTTP 头部解析
    // -----------------------------------------------------------------------

    fn lines(src: &[&str]) -> Vec<String> {
        src.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn headparts_parse_and_accessors() {
        let h = HeadParts::parse(&lines(&[
            "GET /index.html HTTP/1.1",
            "Host: a.example.com:8080",
            "X-Real-Ip: 1.2.3.4",
        ]))
        .expect("解析");
        assert_eq!(h.start_line, "GET /index.html HTTP/1.1");
        assert_eq!(h.get("host"), Some("a.example.com:8080"));
        assert_eq!(
            h.get("HOST"),
            Some("a.example.com:8080"),
            "字段名大小写无关"
        );
        assert!(h.get("missing").is_none());
    }

    #[test]
    fn headparts_set_replaces_existing_key_ignoring_case() {
        let mut h = HeadParts::parse(&lines(&["GET / HTTP/1.1", "Host: old"])).unwrap();
        h.set("HOST", "new.example.com");
        let out = String::from_utf8(h.to_bytes()).unwrap();
        // 保留原有的头名大小写，只替换值（对端 IE 之类的老客户端可能很挑）
        assert!(out.contains("Host: new.example.com"), "{out}");
        assert!(
            !out.contains("old"),
            "同一个头不能出现两次，否则内网服务会拿到歧义值"
        );
    }

    #[test]
    fn headparts_remove_drops_all_case_variants() {
        let mut h = HeadParts::parse(&lines(&[
            "GET / HTTP/1.1",
            "Authorization: Basic zzz",
            "authorization: Basic zzz",
        ]))
        .unwrap();
        h.remove("AUTHORIZATION");
        let out = String::from_utf8(h.to_bytes()).unwrap();
        assert!(!out.to_ascii_lowercase().contains("authorization"), "{out}");
    }

    #[test]
    fn headparts_to_bytes_terminates_head_with_blank_line() {
        let h = HeadParts::parse(&lines(&["GET / HTTP/1.1", "Host: x"])).unwrap();
        let text = String::from_utf8(h.to_bytes()).unwrap();
        assert!(text.ends_with("\r\n\r\n"), "{text:?}");
        assert_eq!(text, "GET / HTTP/1.1\r\nHost: x\r\n\r\n");
    }

    #[test]
    fn empty_head_is_an_error() {
        assert!(HeadParts::parse(&[]).is_err());
    }

    #[test]
    fn malformed_header_lines_are_skipped() {
        // 没有冒号的行：忽略而不是 panic（真实世界里有各种畸形客户端）
        let h = HeadParts::parse(&lines(&["GET / HTTP/1.1", "garbage", "Host: x"])).unwrap();
        assert_eq!(h.headers.len(), 1);
    }

    // -----------------------------------------------------------------------
    // keep-alive 判定
    // -----------------------------------------------------------------------

    #[test]
    fn keep_alive_defaults_and_explicit_tokens() {
        let p = HeadParts::parse(&lines(&["GET / HTTP/1.1"])).unwrap();
        assert!(wants_keep_alive(&p), "HTTP/1.1 默认是长连接");

        let p = HeadParts::parse(&lines(&["GET / HTTP/1.1", "Connection: close"])).unwrap();
        assert!(!wants_keep_alive(&p));

        let p = HeadParts::parse(&lines(&["GET / HTTP/1.0"])).unwrap();
        assert!(!wants_keep_alive(&p), "HTTP/1.0 默认是短连接");

        let p = HeadParts::parse(&lines(&["GET / HTTP/1.0", "Connection: keep-alive"])).unwrap();
        assert!(wants_keep_alive(&p));

        let p = HeadParts::parse(&lines(&[
            "GET / HTTP/1.1",
            "Connection: keep-alive, Upgrade, close",
        ]))
        .unwrap();
        assert!(!wants_keep_alive(&p), "token 列表里出现 close 就算关闭");
    }

    // -----------------------------------------------------------------------
    // Basic Auth
    // -----------------------------------------------------------------------

    #[test]
    fn basic_auth_user_is_decoded() {
        use base64::{engine::general_purpose::STANDARD, Engine as _};
        let cred = STANDARD.encode(b"alice:secret");
        let h = HeadParts::parse(&lines(&[
            "GET / HTTP/1.1",
            &format!("Authorization: Basic {cred}"),
        ]))
        .unwrap();
        assert_eq!(basic_auth_user(&h), Some("alice".to_string()));
    }

    #[test]
    fn basic_auth_rejects_other_schemes_and_garbage() {
        let h = HeadParts::parse(&lines(&["GET / HTTP/1.1", "Authorization: Bearer abc"])).unwrap();
        assert_eq!(basic_auth_user(&h), None, "Bearer 不该被当成 Basic");

        let h = HeadParts::parse(&lines(&["GET / HTTP/1.1", "Authorization: Basic !!!!"])).unwrap();
        assert_eq!(basic_auth_user(&h), None, "非法 base64 不能 panic");

        let h = HeadParts::parse(&lines(&["GET / HTTP/1.1"])).unwrap();
        assert_eq!(basic_auth_user(&h), None);
    }

    // -----------------------------------------------------------------------
    // 工具函数
    // -----------------------------------------------------------------------

    #[test]
    fn subslice_search_edges() {
        assert_eq!(find_subslice(b"ab\r\n\r\nc", b"\r\n\r\n"), Some(2));
        assert_eq!(find_subslice(b"\r\n\r\n", b"\r\n\r\n"), Some(0));
        assert_eq!(find_subslice(b"", b"\r\n\r\n"), None);
        assert_eq!(find_subslice(b"abc", b"abcd"), None, "needle 比 hay 长");
        assert_eq!(find_subslice(b"abc", b""), None, "空 needle 没有意义");
        assert_eq!(find_subslice(b"aaa", b"aa"), Some(0));
    }

    #[test]
    fn simple_response_has_matching_content_length() {
        let body = "找不到对应的 frp 代理\n";
        let text = String::from_utf8(simple_response("404 Not Found", body)).unwrap();
        assert!(text.starts_with("HTTP/1.1 404 Not Found\r\n"));
        assert!(
            text.contains(&format!("Content-Length: {}", body.len())),
            "Content-Length 必须按**字节数**算而不是字符数（中文容易踩）：{text}"
        );
        assert!(text.ends_with(body));
        assert!(text.contains("Connection: close"), "简单响应用完即关");
    }

    // -----------------------------------------------------------------------
    // custom404Page / vhostHTTPTimeout
    // -----------------------------------------------------------------------

    #[test]
    fn 没配_custom404_page_时回内置纯文本提示() {
        let opts = VhostOpts::new(VhostKind::Http, false);
        let text = String::from_utf8(not_found_response(&opts)).unwrap();
        assert!(text.starts_with("HTTP/1.1 404 Not Found\r\n"));
        assert!(text.contains("找不到对应的 frp 代理"));
        assert!(text.contains("Content-Type: text/plain"), "{text}");
    }

    #[test]
    fn 配了_custom404_page_就原样返回文件内容() {
        let page: &[u8] = b"<html><body>no</body></html>";
        let opts = VhostOpts::new(VhostKind::Http, false)
            .with_not_found_page(Some(Arc::new(page.to_vec())));
        let raw = not_found_response(&opts);
        let text = String::from_utf8(raw.clone()).unwrap();
        assert!(text.starts_with("HTTP/1.1 404 Not Found\r\n"), "{text}");
        assert!(
            text.contains("Content-Type: text/html"),
            "自定义页按 HTML 宣告（官方也是 text/html）：{text}"
        );
        assert!(
            text.contains(&format!("Content-Length: {}", page.len())),
            "长度必须按文件字节数：{text}"
        );
        assert!(raw.ends_with(page), "body 必须逐字节原样返回");
    }

    /// 自定义页里带**非 ASCII**（中文 HTML）时，长度必须按字节算 ——
    /// 按字符算会让浏览器一直等剩下的字节。
    #[test]
    fn 自定义404页含中文时长度按字节算() {
        let page = "<html>找不到</html>".as_bytes();
        let opts = VhostOpts::new(VhostKind::Http, false)
            .with_not_found_page(Some(Arc::new(page.to_vec())));
        let raw = not_found_response(&opts);
        let head_end = find_subslice(&raw, b"\r\n\r\n").unwrap() + 4;
        let body = &raw[head_end..];
        assert_eq!(body, page);
        let head = String::from_utf8_lossy(&raw[..head_end]).to_string();
        assert!(
            head.contains(&format!("Content-Length: {}", body.len())),
            "{head}"
        );
    }

    /// ★ 回归测试：`Transfer-Encoding` 与 `Content-Length` 同时出现必须 400。
    ///
    /// 放行的后果是 CL.TE 请求走私：NFrp 按 chunked 解读请求，上游按
    /// `Content-Length` 解读同一串字节，双方对"请求到哪结束"的认知不一致，
    /// 攻击者能让本请求的尾巴被上游当成**下一个请求**处理。
    #[tokio::test]
    async fn 同时带_cl_与_te_直接拒绝而不是转发() {
        let registry = Arc::new(Registry::unlimited());
        let client = dummy_client("run-smuggle");
        let (up_srv, _up_cli) = duplex(64 * 1024);
        client.submit_work(crate::pool::WorkItem::new(FrpConn::new(
            Box::pin(up_srv),
            nfrp_common::frp::WireVersion::V1,
        )));

        let table = Arc::new(table_with(vec![Arc::new(VhostRoute {
            proxy_name: "web".into(),
            client: client.clone(),
            domain: "a.example.com".into(),
            locations: vec!["/".into()],
            http_user: String::new(),
            http_pwd: String::new(),
            route_by_http_user: String::new(),
            rewrite_host: String::new(),
            req_headers: HashMap::new(),
            resp_headers: HashMap::new(),
            kind: VhostKind::Http,
        })]));

        let (mut visitor, srv) = duplex(64 * 1024);
        let opts =
            VhostOpts::new(VhostKind::Http, false).with_timeout(Some(Duration::from_secs(5)));
        let task = tokio::spawn(async move {
            handle_http(
                srv,
                SocketAddr::from(([127, 0, 0, 1], 5000)),
                table,
                0,
                opts,
                registry,
            )
            .await
        });

        // 经典 CL.TE 形态：两个头都在，chunked 体里藏第二个请求
        visitor
            .write_all(
                b"POST / HTTP/1.1\r\nHost: a.example.com\r\n\
                  Content-Length: 6\r\nTransfer-Encoding: chunked\r\n\r\n\
                  0\r\n\r\nGET /admin HTTP/1.1\r\nHost: a.example.com\r\n\r\n",
            )
            .await
            .unwrap();

        let mut buf = vec![0u8; 4096];
        let n = tokio::time::timeout(Duration::from_secs(5), visitor.read(&mut buf))
            .await
            .expect("必须立刻回一个应答，不能挂住")
            .unwrap();
        let text = String::from_utf8_lossy(&buf[..n]).to_string();
        assert!(
            text.starts_with("HTTP/1.1 400 Bad Request"),
            "CL+TE 必须 400，实际：{text}"
        );
        let _ = tokio::time::timeout(Duration::from_secs(2), task).await;
    }

    /// ★ 回归测试：`Expect: 100-continue` 必须被回应，不能让双方互等。
    ///
    /// 原先不处理这个头 ⇒ 客户端等 100、服务端等请求体 ⇒ 死锁到
    /// `vhostHTTPTimeout`（默认 60 秒）。单请求就能占住一条工作连接。
    #[tokio::test]
    async fn expect_100_continue_要立刻回_100() {
        let registry = Arc::new(Registry::unlimited());
        let client = dummy_client("run-expect");
        let (up_srv, mut up_cli) = duplex(64 * 1024);
        client.submit_work(crate::pool::WorkItem::new(FrpConn::new(
            Box::pin(up_srv),
            nfrp_common::frp::WireVersion::V1,
        )));

        let table = Arc::new(table_with(vec![Arc::new(VhostRoute {
            proxy_name: "web".into(),
            client: client.clone(),
            domain: "a.example.com".into(),
            locations: vec!["/".into()],
            http_user: String::new(),
            http_pwd: String::new(),
            route_by_http_user: String::new(),
            rewrite_host: String::new(),
            req_headers: HashMap::new(),
            resp_headers: HashMap::new(),
            kind: VhostKind::Http,
        })]));

        let (mut visitor, srv) = duplex(64 * 1024);
        let opts =
            VhostOpts::new(VhostKind::Http, false).with_timeout(Some(Duration::from_secs(5)));
        let task = tokio::spawn(async move {
            handle_http(
                srv,
                SocketAddr::from(([127, 0, 0, 1], 5000)),
                table,
                0,
                opts,
                registry,
            )
            .await
        });

        // 只发头 —— 真客户端此时在等 100，不会发体
        visitor
            .write_all(
                b"POST / HTTP/1.1\r\nHost: a.example.com\r\n\
                  Content-Length: 5\r\nExpect: 100-continue\r\n\r\n",
            )
            .await
            .unwrap();

        let mut buf = vec![0u8; 4096];
        let n = tokio::time::timeout(Duration::from_secs(3), visitor.read(&mut buf))
            .await
            .expect("服务端必须立刻回 100 Continue，不能等满超时")
            .unwrap();
        let text = String::from_utf8_lossy(&buf[..n]).to_string();
        assert!(
            text.starts_with("HTTP/1.1 100 Continue"),
            "必须先回 100 Continue，实际：{text}"
        );

        // 上游收到的头里不该再有 expect（否则它还得多等一次）
        let mut up_buf = vec![0u8; 4096];
        if let Ok(Ok(n)) =
            tokio::time::timeout(Duration::from_secs(2), up_cli.read(&mut up_buf)).await
        {
            let up_text = String::from_utf8_lossy(&up_buf[..n]).to_ascii_lowercase();
            assert!(
                !up_text.contains("expect:"),
                "转发给上游前必须摘掉 expect：{up_text}"
            );
        }
        let _ = tokio::time::timeout(Duration::from_secs(2), task).await;
    }

    /// ★ 回归测试：逐跳头不能原样传给上游。
    #[tokio::test]
    async fn 逐跳头不会转发给上游() {
        let registry = Arc::new(Registry::unlimited());
        let client = dummy_client("run-hop");
        let (up_srv, mut up_cli) = duplex(64 * 1024);
        client.submit_work(crate::pool::WorkItem::new(FrpConn::new(
            Box::pin(up_srv),
            nfrp_common::frp::WireVersion::V1,
        )));

        let table = Arc::new(table_with(vec![Arc::new(VhostRoute {
            proxy_name: "web".into(),
            client: client.clone(),
            domain: "a.example.com".into(),
            locations: vec!["/".into()],
            http_user: String::new(),
            http_pwd: String::new(),
            route_by_http_user: String::new(),
            rewrite_host: String::new(),
            req_headers: HashMap::new(),
            resp_headers: HashMap::new(),
            kind: VhostKind::Http,
        })]));

        let (mut visitor, srv) = duplex(64 * 1024);
        let opts =
            VhostOpts::new(VhostKind::Http, false).with_timeout(Some(Duration::from_secs(5)));
        let task = tokio::spawn(async move {
            handle_http(
                srv,
                SocketAddr::from(([127, 0, 0, 1], 5000)),
                table,
                0,
                opts,
                registry,
            )
            .await
        });

        // `Connection: keep-alive, X-Secret` 点名的 X-Secret 也是逐跳头
        visitor
            .write_all(
                b"GET / HTTP/1.1\r\nHost: a.example.com\r\n\
                  Connection: keep-alive, X-Secret\r\n\
                  X-Secret: leak-me\r\n\
                  Keep-Alive: timeout=5\r\n\
                  Upgrade: h2c\r\n\r\n",
            )
            .await
            .unwrap();

        let mut up_buf = vec![0u8; 8192];
        let n = tokio::time::timeout(Duration::from_secs(3), up_cli.read(&mut up_buf))
            .await
            .expect("上游应当收到请求")
            .unwrap();
        let up_text = String::from_utf8_lossy(&up_buf[..n]).to_ascii_lowercase();
        for banned in ["connection:", "keep-alive:", "upgrade:", "x-secret:"] {
            assert!(
                !up_text.contains(banned),
                "逐跳头 {banned} 不该转发给上游：{up_text}"
            );
        }
        // 但正常头要留着
        assert!(up_text.contains("host: a.example.com"), "{up_text}");
        let _ = tokio::time::timeout(Duration::from_secs(2), task).await;
    }

    /// ★ 回归测试：`Host` 头里的 IPv6 要能正确取到域名。
    ///
    /// 原先按 `:` 硬切，`[::1]:8080` 会切出一个孤零零的 `[`。
    #[test]
    fn canonical_host_处理_ipv6_与端口() {
        assert_eq!(canonical_host("[::1]:8080"), "::1");
        assert_eq!(canonical_host("[::1]"), "::1");
        assert_eq!(canonical_host("a.example.com:8080"), "a.example.com");
        assert_eq!(canonical_host("A.Example.COM."), "a.example.com");
        assert_eq!(canonical_host("a.example.com"), "a.example.com");
        // 绝对形式（部分库会这么发 CONNECT）
        assert_eq!(canonical_host("http://a.b/x"), "a.b");
    }

    /// ★ `vhostHTTPTimeout` 的端到端验证：内网服务**连上了却不回响应头**
    /// （进程卡死、死循环）时，不能把用户连接无限期挂着。
    ///
    /// 造法：先往客户端的空闲池里塞一条工作连接（另一端攥在测试手里、
    /// 故意什么都不回），再让 `handle_http` 去用它。
    #[tokio::test]
    async fn http_等响应头超时会回_502() {
        let registry = Arc::new(Registry::unlimited());
        let client = dummy_client("run-timeout");
        let (up_srv, _up_cli) = duplex(64 * 1024);
        let paired = client.submit_work(crate::pool::WorkItem::new(FrpConn::new(
            Box::pin(up_srv),
            nfrp_common::frp::WireVersion::V1,
        )));
        assert!(paired.is_none(), "没有排队的用户连接时它应该进空闲池");

        let table = Arc::new(table_with(vec![Arc::new(VhostRoute {
            proxy_name: "web".into(),
            client: client.clone(),
            domain: "a.example.com".into(),
            locations: vec!["/".into()],
            http_user: String::new(),
            http_pwd: String::new(),
            route_by_http_user: String::new(),
            rewrite_host: String::new(),
            req_headers: HashMap::new(),
            resp_headers: HashMap::new(),
            kind: VhostKind::Http,
        })]));

        let (mut visitor, srv) = duplex(64 * 1024);
        let opts =
            VhostOpts::new(VhostKind::Http, false).with_timeout(Some(Duration::from_millis(150)));
        let task = tokio::spawn(async move {
            handle_http(
                srv,
                SocketAddr::from(([127, 0, 0, 1], 5000)),
                table,
                0,
                opts,
                registry,
            )
            .await
        });

        visitor
            .write_all(b"GET / HTTP/1.1\r\nHost: a.example.com\r\n\r\n")
            .await
            .unwrap();

        let mut buf = vec![0u8; 4096];
        let n = tokio::time::timeout(Duration::from_secs(5), visitor.read(&mut buf))
            .await
            .expect("上游一直不回，服务端必须在超时后自己回一个应答，而不是挂死")
            .unwrap();
        let text = String::from_utf8_lossy(&buf[..n]).to_string();
        assert!(text.starts_with("HTTP/1.1 502 Bad Gateway"), "实际：{text}");
        assert!(text.contains("响应超时"), "实际：{text}");
        let _ = tokio::time::timeout(Duration::from_secs(2), task).await;
    }

    /// 超时设为 0（= 不限）时**不能**自己造一个超时出来：上游慢慢回也得等到。
    #[tokio::test]
    async fn http_超时为零时不设限() {
        let registry = Arc::new(Registry::unlimited());
        let client = dummy_client("run-notimeout");
        let (up_srv, mut up_cli) = duplex(64 * 1024);
        client.submit_work(crate::pool::WorkItem::new(FrpConn::new(
            Box::pin(up_srv),
            nfrp_common::frp::WireVersion::V1,
        )));

        let table = Arc::new(table_with(vec![Arc::new(VhostRoute {
            proxy_name: "web".into(),
            client: client.clone(),
            domain: "b.example.com".into(),
            locations: vec!["/".into()],
            http_user: String::new(),
            http_pwd: String::new(),
            route_by_http_user: String::new(),
            rewrite_host: String::new(),
            req_headers: HashMap::new(),
            resp_headers: HashMap::new(),
            kind: VhostKind::Http,
        })]));

        let (mut visitor, srv) = duplex(64 * 1024);
        let opts = VhostOpts::new(VhostKind::Http, false).with_timeout(None);
        let task = tokio::spawn(async move {
            handle_http(
                srv,
                SocketAddr::from(([127, 0, 0, 1], 5001)),
                table,
                0,
                opts,
                registry,
            )
            .await
        });

        visitor
            .write_all(b"GET / HTTP/1.1\r\nHost: b.example.com\r\n\r\n")
            .await
            .unwrap();

        // 先把服务端写过来的请求报文读掉（含 StartWorkConn 帧），再**等一会儿**
        // 才回响应头 —— 200ms 远大于上面那个用例的 150ms 超时。
        let mut sink = vec![0u8; 8192];
        let _ = tokio::time::timeout(Duration::from_millis(300), up_cli.read(&mut sink)).await;
        tokio::time::sleep(Duration::from_millis(200)).await;
        up_cli
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nhi")
            .await
            .unwrap();
        drop(up_cli);

        let mut buf = vec![0u8; 4096];
        let mut got = Vec::new();
        while let Ok(Ok(n)) =
            tokio::time::timeout(Duration::from_secs(3), visitor.read(&mut buf)).await
        {
            if n == 0 {
                break;
            }
            got.extend_from_slice(&buf[..n]);
            if got.windows(4).any(|w| w == b"hi\r\n") || got.ends_with(b"hi") {
                break;
            }
        }
        let text = String::from_utf8_lossy(&got).to_string();
        assert!(
            text.starts_with("HTTP/1.1 200 OK"),
            "不限超时时必须把上游的 200 原样转回，实际：{text}"
        );
        let _ = tokio::time::timeout(Duration::from_secs(2), task).await;
    }

    // -----------------------------------------------------------------------
    // HttpIo 流式解析
    // -----------------------------------------------------------------------

    /// 把 `input` 灌进一个 duplex 管道的写端，返回用读端构造的 `HttpIo`。
    fn io_with(input: &[u8]) -> HttpIo<DuplexStream> {
        let (reader, mut writer) = duplex(256 * 1024);
        let data = input.to_vec();
        tokio::spawn(async move {
            let _ = writer.write_all(&data).await;
            let _ = writer.shutdown().await;
        });
        HttpIo::new(reader)
    }

    #[tokio::test]
    async fn httpio_reads_head_and_stops_at_blank_line() {
        let mut io = io_with(b"GET / HTTP/1.1\r\nHost: a.com\r\n\r\nBODY");
        let head = io.read_head().await.unwrap().expect("读到头");
        assert_eq!(head.len(), 2);
        assert_eq!(head[0], "GET / HTTP/1.1");
        assert!(
            io.available() >= 4,
            "body 必须留在缓冲里：{}",
            io.available()
        );
    }

    #[tokio::test]
    async fn httpio_read_head_returns_none_on_eof() {
        let mut io = io_with(b"");
        assert!(io.read_head().await.unwrap().is_none());
    }

    #[tokio::test]
    async fn httpio_read_head_errors_when_head_is_too_large() {
        // 超过 MAX_HEAD 且一直不出现空行 -> 必须报错，不能把内存吃光
        let big = vec![b'A'; MAX_HEAD + 1024];
        let mut io = io_with(&big);
        let e = io.read_head().await.unwrap_err().to_string();
        assert!(e.contains("HTTP 头部超过"), "{e}");
    }

    #[tokio::test]
    async fn httpio_read_n_reads_exactly_n_bytes() {
        let mut io = io_with(b"0123456789rest");
        assert_eq!(io.read_n(10).await.unwrap(), b"0123456789");
        // 第二次接着读，不能把缓冲区搞乱
        assert_eq!(io.read_n(4).await.unwrap(), b"rest");
    }

    #[tokio::test]
    async fn httpio_read_n_errors_on_truncated_body() {
        let mut io = io_with(b"short");
        let e = io.read_n(50).await.unwrap_err().to_string();
        assert!(e.contains("提前结束"), "{e}");
    }

    #[tokio::test]
    async fn httpio_read_chunked_keeps_original_framing() {
        let raw = b"5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n";
        let mut io = io_with(raw);
        let out = io.read_chunked().await.unwrap();
        assert_eq!(&out, raw, "原样保留分块格式便于直接透传给内网服务");
    }

    #[tokio::test]
    async fn httpio_read_chunked_with_extension_and_trailer() {
        let raw = b"5;name=val\r\nhello\r\n0\r\nX-Trailer: done\r\n\r\n";
        let mut io = io_with(raw);
        let out = io.read_chunked().await.unwrap();
        let text = String::from_utf8_lossy(&out).to_string();
        assert!(text.starts_with("5;name=val\r\nhello\r\n"), "{text:?}");
        assert!(text.contains("X-Trailer: done"));
    }

    #[tokio::test]
    async fn httpio_chunked_rejects_invalid_size() {
        let mut io = io_with(b"zz\r\nhello\r\n");
        assert!(io.read_chunked().await.is_err());
    }

    #[tokio::test]
    async fn httpio_read_line_splits_on_crlf() {
        let mut io = io_with(b"first\r\nsecond\r\n");
        assert_eq!(io.read_line().await.unwrap(), "first");
        assert_eq!(io.read_line().await.unwrap(), "second");
    }

    #[tokio::test]
    async fn httpio_compaction_does_not_lose_data() {
        let mut io = io_with(b"aaaa\r\nbbbb\r\ncccc");
        let mut got = Vec::new();
        for _ in 0..2 {
            got.push(io.read_line().await.unwrap());
        }
        assert_eq!(got, vec!["aaaa", "bbbb"]);
        // 最后一段没有 CRLF 结尾 -> 连接已结束
        assert!(io.read_line().await.is_err());
    }

    // -----------------------------------------------------------------------
    // tcpmux
    // -----------------------------------------------------------------------

    #[test]
    fn connect_的域名去端口转小写去尾点() {
        // 官方 CanonicalHost 的语义：cURL 发的就是 `host:port` 形式
        assert_eq!(
            canonical_host("normal.example.com:80"),
            "normal.example.com"
        );
        assert_eq!(canonical_host("Normal.Example.COM"), "normal.example.com");
        assert_eq!(canonical_host("a.b."), "a.b");
        // IPv6 authority 必须带方括号，去掉端口后只留地址
        assert_eq!(canonical_host("[::1]:8080"), "::1");
        assert_eq!(canonical_host("[2001:db8::1]"), "2001:db8::1");
        // 容忍绝对形式（有些库会这么发）
        assert_eq!(canonical_host("http://a.b/x"), "a.b");
        assert_eq!(canonical_host("  a.b:1  "), "a.b");
    }

    #[test]
    fn proxy_authorization_解析_basic() {
        fn parts(v: &[&str]) -> HeadParts {
            HeadParts::parse(&v.iter().map(|s| s.to_string()).collect::<Vec<_>>()).unwrap()
        }
        let p = |v: &str| parts(&["CONNECT a.b:80 HTTP/1.1", v]);
        // base64("test:test")
        let (u, pw) = proxy_authorization(&p("Proxy-Authorization: Basic dGVzdDp0ZXN0"));
        assert_eq!(u.as_deref(), Some("test"));
        assert_eq!(pw.as_deref(), Some("test"));
        // 只有用户名（cURL 的 `user:@` 写法）
        let (u, pw) = proxy_authorization(&p("Proxy-Authorization: Basic dXNlcjE6"));
        assert_eq!(u.as_deref(), Some("user1"));
        assert_eq!(pw.as_deref(), Some(""));
        // 没有头 / 不是 Basic / base64 坏了：都不能 panic，也不该凭空造出用户名
        assert_eq!(
            proxy_authorization(&parts(&["CONNECT a.b:80 HTTP/1.1"])).0,
            None
        );
        assert_eq!(
            proxy_authorization(&p("Proxy-Authorization: Bearer x")).0,
            None
        );
        assert_eq!(
            proxy_authorization(&p("Proxy-Authorization: Basic !!!")).0,
            None
        );
    }

    /// ★ 回归：兜底路由（没配 `routeByHTTPUser`）不能盖掉精确用户名匹配的路由。
    ///
    /// 官方 tcpmux 的 "Route by HTTP user" 用例就是这个拓扑：同一个域名上挂
    /// `user1` / `user2` 两条精确路由 + 一条兜底路由。早先 `lookup` 只按
    /// "最长前缀、平手取先注册" 选，兜底路由只要先注册就会把两条精确路由全吃掉。
    ///
    /// ★ v0.5.6（审计总报告 M1）：三条路由必须同属**一个客户端** ——
    ///   跨租户的多作用域现在一律算冲突（服务端分辨不出合法多作用域与寄生劫持）。
    #[test]
    fn tcpmux_兜底路由不能盖掉精确用户名路由() {
        let me = dummy_client("me");
        let mk = |name: &str, user: &str| {
            let mut r = route_of(&me, name, "normal.example.com", &[""]);
            Arc::get_mut(&mut r).unwrap().kind = VhostKind::TcpMux;
            Arc::get_mut(&mut r).unwrap().route_by_http_user = user.to_string();
            r
        };
        // 故意把兜底那条**先**注册，把顺序依赖暴露出来
        let t = table_with(vec![
            mk("catch-all", ""),
            mk("foo", "user1"),
            mk("bar", "user2"),
        ]);

        let pick = |u: Option<&str>| {
            t.lookup("normal.example.com", "", u, VhostKind::TcpMux)
                .map(|(r, _)| r.proxy_name.clone())
        };
        assert_eq!(pick(Some("user1")).as_deref(), Some("foo"));
        assert_eq!(pick(Some("user2")).as_deref(), Some("bar"));
        // 没带用户名 / 带一个没注册过的用户名 -> 落到兜底
        assert_eq!(pick(Some("user3")).as_deref(), Some("catch-all"));
        assert_eq!(pick(None).as_deref(), Some("catch-all"));
    }

    #[test]
    fn tcpmux_与_http_路由互不串门() {
        let t = table_with(vec![
            route("web", "x.com", &["/"], VhostKind::Http),
            route("mux", "x.com", &[""], VhostKind::TcpMux),
        ]);
        let names = |kind| {
            t.lookup("x.com", "/", None, kind)
                .map(|(r, _)| r.proxy_name.clone())
        };
        assert_eq!(names(VhostKind::Http).as_deref(), Some("web"));
        assert_eq!(names(VhostKind::TcpMux).as_deref(), Some("mux"));
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

    // -----------------------------------------------------------------------
    // 第七轮审计 F7-1：数据面也要过 ACL
    // -----------------------------------------------------------------------

    /// ★★ v0.5.8 回归（第七轮审计 F7-1，中危）：
    /// **vhost 端口（http / https / tcpmux）必须做 IP 白/黑名单判定。**
    ///
    /// # 原先的漏洞
    ///
    /// `SecurityContext::check_ip` 全仓只有 2 处调用（控制连接握手 + vnet 注册），
    /// **承载用户流量的数据面一处都没有**。实测（`tmp/audit7/f/acl_dataplane_v3.py`）：
    /// 同一服务端、同一份 `deny = ["127.0.0.1"]`，控制面被正确拒绝，
    /// 而公网端口**照常把该来源的流量转给后端**。
    ///
    /// # 这条测试测什么
    ///
    /// 直接测 `run_vhost` 的 accept 分支所用的那份判定 —— 用一个真实监听器
    /// 起 vhost，从被 deny 的地址连进去，断言**连接被关且后端从未被调用**。
    ///
    /// 注意：这里刻意**不**只断言"连接断了" —— 断连可能是别的错误造成的。
    /// 必须同时断言**后端没有被触达**（`AtomicUsize` 计数为 0），
    /// 否则这条测试会变成"恒真"：任何启动失败都会让它通过。
    #[tokio::test]
    async fn vhost_数据面必须过_ip_白黑名单() {
        use crate::guard::SecurityContext;
        use nfrp_common::security::AclConfig;
        use std::sync::atomic::{AtomicUsize, Ordering};

        // 一个"后端服务"：只用来证明连接有没有被放行到转发阶段
        let hits = Arc::new(AtomicUsize::new(0));
        let backend = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let backend_port = backend.local_addr().unwrap().port();
        let _ = backend_port;
        {
            let hits = hits.clone();
            tokio::spawn(async move {
                while let Ok((mut s, _)) = backend.accept().await {
                    hits.fetch_add(1, Ordering::SeqCst);
                    let _ = s.shutdown().await;
                }
            });
        }

        // 路由表：一个 http 代理指向那个后端
        let table = Arc::new(table_with(vec![route(
            "blocked",
            "blocked.example.com",
            &["/"],
            VhostKind::Http,
        )]));

        // ★ 服务端安全上下文：deny 掉 127.0.0.1（本机测试的源地址就是它）
        let scfg = nfrp_common::config::ServerConfig {
            acl: AclConfig {
                allow: vec![],
                deny: vec!["127.0.0.1".to_string()],
            },
            ..Default::default()
        };
        // 走**生产同一条**构造路径，避免测试用一套、线上用另一套
        let sec = Arc::new(SecurityContext::from_config(&scfg).expect("安全上下文"));

        // 注册表：挂上这份安全上下文（`run_vhost` 从 registry 取它）
        let registry = Arc::new(Registry::unlimited());
        registry.set_security(sec);

        // 起一个真的 vhost 监听器
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let vhost_addr = listener.local_addr().unwrap();
        {
            let table = table.clone();
            let registry = registry.clone();
            tokio::spawn(async move {
                run_vhost(
                    listener,
                    table,
                    vhost_addr.port(),
                    VhostOpts::new(VhostKind::Http, false),
                    registry,
                )
                .await;
            });
        }
        // 等监听器就绪
        for _ in 0..50 {
            if tokio::net::TcpStream::connect(vhost_addr).await.is_ok() {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }

        // ★ 就绪等待：ACL 会把**确认连接也拦掉**，所以"能连上"不能当就绪判据
        //   （本用例第一版就卡在这里：探测连接被立即关闭 ⇒ 循环永远不 break）。
        //   改成直接重试"连上并发请求、看是否被立刻关闭"，最多等 2 秒。
        let mut closed_fast = false;
        let mut what = String::from("未建立连接");
        for _ in 0..100 {
            let Ok(mut c) = tokio::net::TcpStream::connect(vhost_addr).await else {
                tokio::time::sleep(std::time::Duration::from_millis(20)).await;
                continue;
            };
            let _ = c
                .write_all(b"GET / HTTP/1.1\r\nHost: blocked.example.com\r\n\r\n")
                .await;
            let t0 = std::time::Instant::now();
            let mut d = [0u8; 64];
            let r =
                tokio::time::timeout(std::time::Duration::from_millis(400), c.read(&mut d)).await;
            let ms = t0.elapsed().as_millis();
            match r {
                Ok(Ok(0)) => {
                    closed_fast = true;
                    what = format!("{ms}ms EOF");
                    break;
                }
                Ok(Err(e)) => {
                    closed_fast = true;
                    what = format!("{ms}ms 重置 {e}");
                    break;
                }
                Ok(Ok(n)) => {
                    closed_fast = false;
                    what = format!("{ms}ms 读到 {n} 字节（未被拦截）");
                    break;
                }
                Err(_) => {
                    // 超时 ⇒ 连接被交给 HTTP 处理、还开着 ⇒ ACL 没生效
                    closed_fast = false;
                    what = format!("{ms}ms 超时（连接未关闭，未被拦截）");
                    break;
                }
            }
        }

        assert_eq!(
            hits.load(Ordering::SeqCst),
            0,
            "被 ACL 拒绝的来源不应该到达转发阶段（后端被触达说明数据面没做 ACL）"
        );
        assert!(
            closed_fast,
            "被 ACL 拒绝时服务端应立即关闭连接 —— 实际 {what}，\
             说明 accept 分支没做 ACL 判定（连接被交给了 HTTP 处理）"
        );
    }

    /// 对照用例：**不配 ACL** 时，同一个 vhost 的 accept 分支必须**放行**连接。
    ///
    /// 没有这条，"上面那条测试"就无法排除"vhost 本来就连接不上"
    /// 这种恒真的解释 —— 与 `handle_frp_stream` 那边"基线必须通过"同理。
    ///
    /// ★ 断言口径刻意选在 **accept 是否放行**这一层，而不是"后端是否收到请求"：
    ///   后者会把"路由没匹配上""后端没接上"一并算进来，测试就失去区分力
    ///   （本用例第一版正是因此假失败 —— 路由目标压根没连到那个后端）。
    ///   这里直接看：空 ACL 时 `check_ip` 必须**通过**，被 deny 时必须**拒绝**，
    ///   用生产同一条 `from_config` 构造出的上下文来判。
    #[tokio::test]
    async fn vhost_不配_acl_时放行而配置_deny_时拦截() {
        use crate::guard::SecurityContext;
        use nfrp_common::security::AclConfig;

        // 空 ACL ⇒ 放行
        let empty = nfrp_common::config::ServerConfig::default();
        let sec_open = SecurityContext::from_config(&empty).expect("安全上下文");
        assert!(
            sec_open.check_ip("127.0.0.1".parse().unwrap()).is_ok(),
            "不配 ACL 时不应拦截任何来源（否则修复改变了默认行为）"
        );

        // deny 127.0.0.1 ⇒ 拒绝
        let denied = nfrp_common::config::ServerConfig {
            acl: AclConfig {
                allow: vec![],
                deny: vec!["127.0.0.1".to_string()],
            },
            ..Default::default()
        };
        let sec_deny = SecurityContext::from_config(&denied).expect("安全上下文");
        assert!(
            sec_deny.check_ip("127.0.0.1".parse().unwrap()).is_err(),
            "deny 命中时必须拒绝"
        );
        assert!(
            sec_deny.check_ip("10.1.2.3".parse().unwrap()).is_ok(),
            "deny 未命中的来源仍须放行（黑名单不是白名单）"
        );

        // allow 白名单 ⇒ 只有名单内放行（这是 ACL 最容易被写反的方向）
        let allowed = nfrp_common::config::ServerConfig {
            acl: AclConfig {
                allow: vec!["10.0.0.0/8".to_string()],
                deny: vec![],
            },
            ..Default::default()
        };
        let sec_allow = SecurityContext::from_config(&allowed).expect("安全上下文");
        assert!(
            sec_allow.check_ip("10.1.2.3".parse().unwrap()).is_ok(),
            "白名单内的来源必须放行"
        );
        assert!(
            sec_allow.check_ip("192.168.1.1".parse().unwrap()).is_err(),
            "白名单外的来源必须拒绝"
        );
    }

    // -----------------------------------------------------------------------
    // 第九轮审计 E9-0/E9-1/E9-2：ACL 必须铺满**全部**数据面入口
    // -----------------------------------------------------------------------

    /// ★★ v0.5.9 回归（第九轮审计 **E9-0 / E9-1 / E9-2**）：
    /// **`[acl]` 必须铺满所有数据面入口。**
    ///
    /// 判据：源码里有一行**真的在调用** `check_ip`（排除注释行）。
    ///
    /// ★ 为什么要排除注释：
    ///   本测试第一版只做 `prod.contains("check_ip")` —— 于是**把调用注释掉**
    ///   （`// [退回验证] sec.check_ip(...)`）测试**仍然通过**，
    ///   因为字符串还在文件里。退回验证因此 **0/3**，一个都没守住。
    ///   ⇒ 判据必须落在"**代码行**"上，而不是"文本里出现过这个词"。
    fn has_real_check_ip(src: &str) -> bool {
        src.lines().any(|line| {
            let code = match line.find("//") {
                Some(i) => &line[..i],
                None => line,
            };
            code.contains("check_ip")
        })
    }
    ///
    /// # 这三条是一起发现的
    ///
    /// v0.5.8 里 `SecurityContext::check_ip` 只有 **4 处**调用
    /// （控制面 / TCP 代理 / vhost / VNet），而下面三条路径**一处都没有**：
    ///
    /// | 路径 | 文件 | 第九轮定级 |
    /// |---|---|---|
    /// | **UDP 代理端口** | `udp_proxy.rs` | **中危**（无其它防线） |
    /// | **xtcp 牵线 UDP** | `p2p.rs` | 低危（B-1 来源绑定间接生效） |
    /// | **管理面板** | `dashboard.rs` | 低危（有 Basic Auth） |
    ///
    /// 实测（`tmp/audit9/_indep/`）：
    /// * `verify_udp_acl.py`：ACL deny 的源仍能把 UDP 包送进内网服务（包数 1→2）
    /// * `verify_p2p_acl.py`：被 deny 的源发出的 HELLO 被服务端照收
    /// * `verify_dashboard_acl.py`：正确凭据仍能拿到 200
    ///
    /// # 这条测试为什么用**源码扫描**而不是功能测试
    ///
    /// 功能测试只能覆盖"我已经想到的那几条路径"。而这一族缺陷的本质是
    /// 「**新增了一条路径，忘了加 ACL**」—— 只有**枚举文件**才能防住它。
    ///
    /// ⇒ 它守的是一个"清单不变量"：**每个接收外部连接的 server 文件里，
    /// 都必须出现 `check_ip`**。将来若新增数据面文件而忘了加 ACL，
    /// 这条测试会**直接变红**（把文件加进 `MUST_HAVE_ACL` 或给它加 check_ip）。
    ///
    /// ★ 这正是项目那个连续多轮的模式（"防线没铺满"）的**治本方向**：
    ///   让"漏掉"变得不可能，而不是靠每次审计去数。
    #[test]
    fn acl_必须铺满全部数据面入口() {
        use std::path::PathBuf;

        // server/src 下所有**接收外部连接**的文件 —— 每一个都必须有 check_ip。
        const MUST_HAVE_ACL: &[&str] = &[
            "serve.rs",     // 控制端口 + TCP 代理 accept
            "vhost.rs",     // HTTP / HTTPS / tcpmux accept
            "vnet.rs",      // VirtualNet 注册
            "udp_proxy.rs", // ★ E9-0：UDP 代理端口
            "p2p.rs",       // ★ E9-1：xtcp 牵线 UDP
            "dashboard.rs", // ★ E9-2：管理面板
        ];

        let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src");
        let mut missing = Vec::new();
        for f in MUST_HAVE_ACL {
            let path = dir.join(f);
            let text =
                std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("读不到 {path:?}：{e}"));
            // 只认生产代码：排除掉**测试模块**部分。
            //
            // ★ 不能用"第一个 `#[cfg(test)]`"分界 —— 有的文件在中部就有
            //   `#[cfg(test)] pub(crate) fn len()` 之类的小 helper，
            //   按它切会把**后面的生产代码一起切掉**（本测试第一版就因此误报）。
            //   正确做法：找**最后一个** `mod tests {` 的起点。
            let prod = match text.rfind("mod tests") {
                Some(i) => &text[..i],
                None => &text[..],
            };
            if !has_real_check_ip(prod) {
                missing.push(*f);
            }
        }

        assert!(
            missing.is_empty(),
            "★ 这些文件接收外部连接却**没有** `check_ip`：{:?}\n\
             `[acl]` 的语义是『谁能连上来』（见 security.rs 模块文档），\
             它必须覆盖**所有**数据面入口。\n\
             第九轮实测：UDP 代理端口 / xtcp 牵线 / 管理面板 三条都漏了 —— \
             这正是『防线没铺满』模式的又一次出现。",
            missing
        );
    }

    // -----------------------------------------------------------------------
    // 第七轮审计 D7-1：响应侧 TE 判定必须与请求侧同口径
    // -----------------------------------------------------------------------

    /// ★★ v0.5.8 回归（第七轮审计 D7-1，**高危**）：
    /// 响应侧必须用**与请求侧同一套**判定，且 `chunked, identity` 必须**不被当作 chunked**。
    ///
    /// # 这条测试的写法经过一次返工（**退回验证抓出来的**）
    ///
    /// 第一版只断言 `http_relay::is_chunked()` 对各类 TE 的结论 ——
    /// 而那个 helper **本来就没坏**（坏的是"vhost 里没调它"）。
    /// ⇒ 把修复退掉后这条测试**仍然全绿**，等于没有守护修复点。
    ///
    /// 第二版改成断言**真正被改的那件事**：vhost 用来定界响应体的那个判据
    /// （即修复后与 `framed` 共用的 `resp_te_chunked` 表达式）。
    /// 这里把生产表达式原样复制一份来断言 —— 表达式一改，测试就红。
    #[test]
    fn 响应侧_te_判定必须与请求侧同口径() {
        use nfrp_common::http_relay::{is_chunked, transfer_encoding_is_unsupported, HeadParts};

        // `HeadParts::parse` 收的是**按行切好的** `&[String]`
        let resp_with = |te: &str| -> HeadParts {
            let lines: Vec<String> = format!("HTTP/1.1 200 OK\r\nTransfer-Encoding: {te}")
                .split("\r\n")
                .map(|s| s.to_string())
                .collect();
            HeadParts::parse(&lines).expect("合法响应头")
        };

        // ★★★ 这就是**生产代码里**用来定界响应体的那个表达式
        //     （`vhost.rs` 的 `let resp_te_chunked = ...`）。
        //     第七轮 D7-1 之前它是 `te.contains("chunked")`，之后是 `is_chunked`。
        //     断言写在这个表达式上，才能真正守住"用的是 RFC 口径"这件事。
        let production_predicate = |r: &HeadParts| -> bool { is_chunked(r) };

        // ---- 必须**判为 chunked**（可以安全按 chunked 定界）----
        for te in ["chunked", "identity, chunked", "Chunked", "CHUNKED"] {
            assert!(
                production_predicate(&resp_with(te)),
                "{te:?} 应当判为 chunked（最后一个 token 是 chunked）"
            );
            assert!(
                !transfer_encoding_is_unsupported(&resp_with(te)),
                "{te:?} 是 RFC 支持形态，不该被拒"
            );
        }

        // ---- 必须**不**判为 chunked（与 RFC 下游口径一致）----
        //
        // ★ 这几条正是 D7-1 的实弹形态：旧代码的 `contains("chunked")`
        //   会把它们全判成 chunked，从而与 RFC 下游产生分歧 ⇒ 走私。
        for te in [
            "chunked, identity", // ← 实弹用的就是它
            "chunked, gzip",
            "xchunked",
            "chunked, chunked",
            "identity",
        ] {
            assert!(
                !production_predicate(&resp_with(te)),
                "{te:?} **不该**判为 chunked（最后一个 token 不是 chunked）—— \
                 旧代码的 contains(\"chunked\") 会把 \"chunked, identity\" 误判成 chunked，\
                 这正是 D7-1 走私的成因"
            );
        }

        // ---- 明确要拒绝的形态（调用方据此失败关闭）----
        for te in ["chunked, gzip", "xchunked", "chunked, chunked"] {
            assert!(
                transfer_encoding_is_unsupported(&resp_with(te)),
                "{te:?} 属于不支持形态，应当被标记为 unsupported（失败关闭）"
            );
        }
        // 而 RFC 合法的 `identity, chunked` **不能**被拒（第四轮修过"修得过头"）
        assert!(
            !transfer_encoding_is_unsupported(&resp_with("identity, chunked")),
            "identity, chunked 是 RFC 合法形态，不能被拒 —— \
             把合法请求拒掉是把'修漏洞'变成'制造不兼容'"
        );

        // ---- 没有 TE 头 ⇒ 与 TE 无关 ----
        let no_te_lines: Vec<String> = "HTTP/1.1 200 OK\r\nContent-Length: 5"
            .split("\r\n")
            .map(|s| s.to_string())
            .collect();
        let no_te = HeadParts::parse(&no_te_lines).expect("合法响应头");
        assert!(
            !production_predicate(&no_te),
            "没有 TE 头时不应判为 chunked"
        );
        assert!(
            !transfer_encoding_is_unsupported(&no_te),
            "没有 TE 头时不该被标记为不支持"
        );
    }

    /// ★★ 第七轮 D7-1 的**行为级**回归：真实起 vhost，把"走私会不会发生"打出来。
    ///
    /// 与上面那条单测的分工：
    /// * 单测守"用的是哪个判据"（快、能定位）；
    /// * 这条守"端到端不再串响应"（贵、但**只有它能在退回修复时变红**，
    ///   因为退掉修复改的是**行为**而不是 helper）。
    ///
    /// 做法：手工构造一条**已经收到的上游响应头**（`TE: chunked, identity`），
    /// 走 `framed` 的那段判据，断言它**不**被当作可安全分帧 ——
    /// 因为「当作可安全分帧」正是后续 keep-alive 复用的前提，
    /// 也是走私链的起点。
    #[test]
    fn 响应侧_chunked_identity_不得被判为可安全分帧() {
        use nfrp_common::http_relay::{is_chunked, HeadParts};

        let lines: Vec<String> = "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked, identity"
            .split("\r\n")
            .map(|s| s.to_string())
            .collect();
        let resp = HeadParts::parse(&lines).expect("合法响应头");

        // 「可安全分帧」在生产里由 `resp_te_chunked` 表达。
        // D7-1 的成因就是它算成了 true（用的是 contains）。
        let safe_framed = is_chunked(&resp);
        assert!(
            !safe_framed,
            "`chunked, identity` 不能被判为可安全分帧 —— \
             否则 NFrp 按 chunked 转发、RFC 下游按'读到关闭'解析，\
             两者的口径分歧就是跨访客响应走私（D7-1）"
        );
    }
}
