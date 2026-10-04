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

/// 向客户端索要工作连接的超时。
const WORK_CONN_WAIT: Duration = Duration::from_secs(15);

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

impl VhostTable {
    /// 注册路由；同一域名 + 同一路径前缀冲突时报错（与 frp 行为一致）。
    pub fn register(&self, route: Arc<VhostRoute>) -> Result<()> {
        let mut g = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        let list = if let Some(suffix) = route.domain.strip_prefix("*.") {
            g.wildcard.entry(suffix.to_string()).or_default()
        } else {
            g.exact.entry(route.domain.clone()).or_default()
        };
        for existing in list.iter() {
            let same_proxy = existing.proxy_name == route.proxy_name;
            // 只有**完全相同**的路径才算冲突。
            //
            // 早先这里把"前缀互相包含"也算冲突（`/api` 与 `/api/admin` 不能共存），
            // 但路由本来就是按**最长前缀**匹配的，嵌套路径之间并没有歧义，
            // 官方 frp 也是按精确路径去重、允许嵌套的。
            let duplicate = existing
                .locations
                .iter()
                .any(|a| route.locations.iter().any(|b| a == b));
            // `route_by_http_user` 的作用恰恰是让多个代理共用同一个域名 + 路径，
            // 只按访问用户名区分，所以作用域不同就不算抢。
            let same_scope = existing.route_by_http_user == route.route_by_http_user;
            if !same_proxy && duplicate && same_scope {
                bail!(
                    "域名 {} 的路径已被代理 {} 占用",
                    route.domain,
                    existing.proxy_name
                );
            }
        }
        list.retain(|r| r.proxy_name != route.proxy_name);
        list.push(route);
        Ok(())
    }

    /// 摘掉某一条代理注册的全部路由（客户端主动 `CloseProxy`）。
    ///
    /// 早先只有 `unregister_client`，于是客户端单独关掉一个 http 代理时，
    /// 域名仍然留在表里：重连再注册同一个域名会被判成路径冲突，
    /// 而且请求还会被路由到一个已经关掉的代理上。
    pub fn remove_proxy(&self, proxy_name: &str) -> bool {
        let mut g = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        let mut removed = false;
        for list in g.exact.values_mut() {
            let before = list.len();
            list.retain(|r| r.proxy_name != proxy_name);
            removed |= list.len() != before;
        }
        for list in g.wildcard.values_mut() {
            let before = list.len();
            list.retain(|r| r.proxy_name != proxy_name);
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
        warn!(%peer, %sni, "没有匹配的 https 代理");
        return Ok(());
    };

    let work = route
        .client
        .acquire_work_conn(WORK_CONN_WAIT)
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

    debug!(%peer, %sni, proxy = %route.proxy_name, "HTTPS 透传开始");
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
        debug!(%peer, %sni, "HTTPS 透传中断：{e}");
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
        let ok = user.as_deref() == Some(route.http_user.as_str())
            && pwd.as_deref() == Some(route.http_pwd.as_str());
        if !ok {
            debug!(%peer, %host, "tcpmux 认证失败");
            io.stream.write_all(&proxy_auth_required()).await?;
            return Ok(());
        }
    }

    let work = route
        .client
        .acquire_work_conn(WORK_CONN_WAIT)
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

        // ---- 路由 ----
        let Some((route, _loc)) =
            table.lookup(&host_header, &path, auth_user.as_deref(), VhostKind::Http)
        else {
            debug!(%peer, host = %host_header, path = %path, "没有匹配的 http 代理");
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
        let has_cl = req.get("content-length").is_some();
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

        let body = if let Some(te) = req.get("transfer-encoding") {
            if te.to_ascii_lowercase().contains("chunked") {
                io.read_chunked().await?
            } else {
                Vec::new()
            }
        } else if let Some(cl) = req.get("content-length") {
            let n: usize = cl.trim().parse().unwrap_or(0);
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
        let work = match route.client.acquire_work_conn(WORK_CONN_WAIT).await {
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

        let mut up = HttpIo::with_prefill(upstream, Vec::new());
        let _ = leftover;

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
        if let Some(start) = resp.start_line.split_whitespace().nth(1) {
            let code: u32 = start.parse().unwrap_or(200);
            let no_body =
                (100..200).contains(&code) || code == 204 || code == 304 || method == "HEAD";
            let framed = if no_body {
                true
            } else if let Some(te) = resp.get("transfer-encoding") {
                te.to_ascii_lowercase().contains("chunked")
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
            if !no_body {
                if let Some(te) = resp.get("transfer-encoding") {
                    if te.to_ascii_lowercase().contains("chunked") {
                        let raw = up.read_chunked().await?;
                        io.stream.write_all(&raw).await?;
                    } else if let Some(cl) = resp.get("content-length") {
                        let n: usize = cl.trim().parse().unwrap_or(0);
                        relay_fixed(&mut up, &mut io.stream, n).await?;
                    } else {
                        relay_until_eof(&mut up, &mut io.stream).await?;
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

    #[test]
    fn route_by_http_user_filters_candidates() {
        let t = VhostTable::default();
        let mut alice = route("alice-app", "x.com", &["/"], VhostKind::Http);
        Arc::get_mut(&mut alice).unwrap().route_by_http_user = "alice".to_string();
        t.register(alice).expect("注册");
        t.register(http_route("anon", "x.com")).expect("注册");

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

    #[test]
    fn same_proxy_reregistration_replaces_old_route() {
        let t = VhostTable::default();
        t.register(route("same", "x.com", &["/old"], VhostKind::Http))
            .unwrap();
        t.register(route("same", "x.com", &["/new"], VhostKind::Http))
            .unwrap();
        let list = { t.inner.lock().unwrap().exact.get("x.com").cloned().unwrap() };
        assert_eq!(list.len(), 1, "同名代理重复注册应替换而非堆积");
        assert_eq!(list[0].locations, vec!["/new"]);
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
        client.submit_work(crate::pool::WorkItem {
            conn: FrpConn::new(Box::pin(up_srv), nfrp_common::frp::WireVersion::V1),
            at: std::time::Instant::now(),
        });

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
        client.submit_work(crate::pool::WorkItem {
            conn: FrpConn::new(Box::pin(up_srv), nfrp_common::frp::WireVersion::V1),
            at: std::time::Instant::now(),
        });

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
        client.submit_work(crate::pool::WorkItem {
            conn: FrpConn::new(Box::pin(up_srv), nfrp_common::frp::WireVersion::V1),
            at: std::time::Instant::now(),
        });

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
        let paired = client.submit_work(crate::pool::WorkItem {
            conn: FrpConn::new(Box::pin(up_srv), nfrp_common::frp::WireVersion::V1),
            at: std::time::Instant::now(),
        });
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
        client.submit_work(crate::pool::WorkItem {
            conn: FrpConn::new(Box::pin(up_srv), nfrp_common::frp::WireVersion::V1),
            at: std::time::Instant::now(),
        });

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
    #[test]
    fn tcpmux_兜底路由不能盖掉精确用户名路由() {
        let mk = |name: &str, user: &str| {
            let mut r = route(name, "normal.example.com", &[""], VhostKind::TcpMux);
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
}
