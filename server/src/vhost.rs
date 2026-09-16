//! HTTP / HTTPS 虚拟主机代理（等价官方 `server/proxy/http.go` + `pkg/util/vhost`）。
//!
//! * **HTTP**：服务端在 `vhost_http_port` 上按 `Host` 头路由，把请求原样转发到
//!   内网服务，并支持 frp 的几种花活：`locations` 前缀、Basic Auth、
//!   `host_header_rewrite`、自定义请求/响应头；
//! * **HTTPS**：只在 `vhost_https_port` 上嗅探 TLS ClientHello 里的 **SNI**，
//!   之后把 TLS 字节**原样透传**给内网服务（frp 不终止 TLS，证书由内网服务自己出）。
//!
//! 与 TCP 代理一样，每个请求/连接都从客户端要一条工作连接；
//! 区别在于服务端要自己解析 HTTP 语义，才能决定连接何时可以复用。

use std::{
    collections::HashMap,
    net::SocketAddr,
    sync::{Arc, Mutex},
    time::Duration,
};

use anyhow::{anyhow, bail, Context, Result};
use rustunnel_common::frp::{
    conn::FrpConn,
    msg::{FrpMessage, StartWorkConn},
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};
use tracing::{debug, info, warn};

use crate::{pool::ClientState, registry::Registry};

/// 单条请求头允许的最大字节数。
const MAX_HEAD: usize = 64 * 1024;
/// 请求体 / 响应体在内存里中转的上限（超过则拒绝，避免大文件把内存打爆）。
const MAX_BODY: usize = 32 * 1024 * 1024;
/// 向客户端索要工作连接的超时。
const WORK_CONN_WAIT: Duration = Duration::from_secs(15);

// ---------------------------------------------------------------------------
// 路由表
// ---------------------------------------------------------------------------

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
    /// HTTPS 路由（走 SNI 匹配，无 locations / auth）。
    pub is_https: bool,
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
        let mut g = self.inner.lock().unwrap();
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
        let mut g = self.inner.lock().unwrap();
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
        let mut g = self.inner.lock().unwrap();
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
        https: bool,
    ) -> Option<(Arc<VhostRoute>, String)> {
        let host = host.trim().trim_end_matches('.').to_ascii_lowercase();
        let g = self.inner.lock().unwrap();

        // 在同一域名下可能有**多条**路由都匹配得上（例如 A 的 `/` 和 B 的 `/api`），
        // 必须按"前缀最长者胜"来选。早先这里是"取第一条匹配"，
        // 于是注册顺序就偷偷决定了路由结果：`/api/admin` 会被先注册的 `/api` 抢走。
        let matched = |list: &Vec<Arc<VhostRoute>>| -> Option<(Arc<VhostRoute>, String)> {
            let mut best: Option<(Arc<VhostRoute>, String)> = None;
            for route in list {
                if route.is_https != https {
                    continue;
                }
                if !route.route_by_http_user.is_empty()
                    && route.route_by_http_user != auth_user.unwrap_or("")
                {
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

        if let Some(list) = g.exact.get(&host) {
            if let Some(hit) = matched(list) {
                return Some(hit);
            }
        }
        // 通配：a.b.example.com 依次尝试 example.com、b.example.com
        let labels: Vec<&str> = host.split('.').collect();
        for i in 1..labels.len() {
            let suffix = labels[i..].join(".");
            if let Some(list) = g.wildcard.get(&suffix) {
                if let Some(hit) = matched(list) {
                    return Some(hit);
                }
            }
        }
        None
    }

    /// 该域名有没有被任何路由占用（用于提示冲突）。
    #[allow(dead_code)]
    pub fn contains_domain(&self, host: &str) -> bool {
        let g = self.inner.lock().unwrap();
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

/// HTTP vhost 主循环。
#[allow(clippy::too_many_arguments)]
pub async fn run_http(
    listener: TcpListener,
    table: Arc<VhostTable>,
    port: u16,
    is_https: bool,
    registry: Arc<Registry>,
) {
    info!(
        "{} 虚拟主机已启动，监听 :{port}",
        if is_https { "HTTPS" } else { "HTTP" }
    );
    loop {
        match listener.accept().await {
            Ok((stream, peer)) => {
                let table = table.clone();
                let registry = registry.clone();
                tokio::spawn(async move {
                    if let Err(e) = handle_conn(stream, peer, table, port, is_https, registry).await
                    {
                        debug!(%peer, "vhost 连接结束：{e:#}");
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

#[allow(clippy::too_many_arguments)]
async fn handle_conn(
    visitor: TcpStream,
    peer: SocketAddr,
    table: Arc<VhostTable>,
    port: u16,
    is_https: bool,
    registry: Arc<Registry>,
) -> Result<()> {
    visitor.set_nodelay(true).ok();
    if is_https {
        handle_https(visitor, peer, table, port, registry).await
    } else {
        handle_http(visitor, peer, table, port, registry).await
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
    let (sni, hello_bytes) = rustunnel_common::frp::sni::sniff_client_hello(&mut visitor)
        .await
        .context("读取 TLS ClientHello 失败")?;
    let Some(sni) = sni else {
        debug!(%peer, "ClientHello 中没有 SNI，无法路由");
        return Ok(());
    };

    let Some((route, _)) = table.lookup(&sni, "/", None, true) else {
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
    let r = rustunnel_common::util::relay_between(&mut visitor, &mut upstream).await;
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
// HTTP：解析请求 → 路由 → 转发 → 按帧回复
// ---------------------------------------------------------------------------

/// 带缓冲的 HTTP 读写器（over 任意 AsyncRead/AsyncWrite）。
struct HttpIo<S> {
    stream: S,
    buf: Vec<u8>,
    pos: usize,
}

impl<S: AsyncRead + Unpin> HttpIo<S> {
    fn new(stream: S) -> Self {
        Self {
            stream,
            buf: Vec::new(),
            pos: 0,
        }
    }

    fn with_prefill(stream: S, prefill: Vec<u8>) -> Self {
        Self {
            stream,
            buf: prefill,
            pos: 0,
        }
    }

    fn available(&self) -> usize {
        self.buf.len() - self.pos
    }

    fn take(&mut self, n: usize) -> Vec<u8> {
        let end = self.pos + n;
        let out = self.buf[self.pos..end].to_vec();
        self.pos = end;
        self.compact();
        out
    }

    fn compact(&mut self) {
        if self.pos > 0 && self.pos == self.buf.len() {
            self.buf.clear();
            self.pos = 0;
        } else if self.pos > 64 * 1024 {
            self.buf.drain(..self.pos);
            self.pos = 0;
        }
    }

    async fn fill(&mut self) -> Result<usize> {
        let mut chunk = [0u8; 16 * 1024];
        let n = self.stream.read(&mut chunk).await?;
        if n == 0 {
            return Ok(0);
        }
        self.buf.extend_from_slice(&chunk[..n]);
        Ok(n)
    }

    /// 读出一个 `\r\n\r\n` 结尾的头部块，返回行列表（含空行前的所有行）。
    async fn read_head(&mut self) -> Result<Option<Vec<String>>> {
        loop {
            if let Some(idx) = find_subslice(&self.buf[self.pos..], b"\r\n\r\n") {
                let end = self.pos + idx + 4;
                let raw = self.buf[self.pos..end].to_vec();
                self.pos = end;
                self.compact();
                let text = String::from_utf8_lossy(&raw).to_string();
                let lines: Vec<String> = text
                    .split("\r\n")
                    .filter(|l| !l.is_empty())
                    .map(|l| l.to_string())
                    .collect();
                return Ok(Some(lines));
            }
            if self.available() > MAX_HEAD {
                bail!("HTTP 头部超过 {MAX_HEAD} 字节");
            }
            if self.fill().await? == 0 {
                return Ok(None);
            }
        }
    }

    /// 精确读取 n 字节。
    async fn read_n(&mut self, n: usize) -> Result<Vec<u8>> {
        if n > MAX_BODY {
            bail!("请求体过大：{n} 字节");
        }
        while self.available() < n {
            if self.fill().await? == 0 {
                bail!(
                    "连接在读取 {} 字节时提前结束（已有 {}）",
                    n,
                    self.available()
                );
            }
        }
        Ok(self.take(n))
    }

    /// 按 chunked 编码读取完整报文体（保留原始分块格式，便于原样转发）。
    async fn read_chunked(&mut self) -> Result<Vec<u8>> {
        let mut out = Vec::new();
        loop {
            let line = self.read_line().await?;
            let size_str = line.split(';').next().unwrap_or("").trim().to_string();
            let size = usize::from_str_radix(&size_str, 16)
                .map_err(|_| anyhow!("chunk 长度非法：{size_str:?}"))?;
            out.extend_from_slice(line.as_bytes());
            out.extend_from_slice(b"\r\n");
            if size == 0 {
                // 结尾的 trailer（可能为空行）
                loop {
                    let trailer = self.read_line().await?;
                    out.extend_from_slice(trailer.as_bytes());
                    out.extend_from_slice(b"\r\n");
                    if trailer.is_empty() {
                        break;
                    }
                }
                return Ok(out);
            }
            if out.len() + size > MAX_BODY {
                bail!("chunked 报文超过 {MAX_BODY} 字节");
            }
            let data = self.read_n(size).await?;
            out.extend_from_slice(&data);
            let crlf = self.read_n(2).await?;
            out.extend_from_slice(&crlf);
        }
    }

    async fn read_line(&mut self) -> Result<String> {
        loop {
            if let Some(idx) = find_subslice(&self.buf[self.pos..], b"\r\n") {
                let end = self.pos + idx;
                let line = String::from_utf8_lossy(&self.buf[self.pos..end]).to_string();
                self.pos = end + 2;
                self.compact();
                return Ok(line);
            }
            if self.available() > MAX_HEAD {
                bail!("HTTP 行超长");
            }
            if self.fill().await? == 0 {
                bail!("连接在读取行时结束");
            }
        }
    }
}

fn find_subslice(hay: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || hay.len() < needle.len() {
        return None;
    }
    hay.windows(needle.len()).position(|w| w == needle)
}

/// 解析后的请求头。
struct HeadParts {
    start_line: String,
    headers: Vec<(String, String)>,
}

impl HeadParts {
    fn parse(lines: &[String]) -> Result<Self> {
        let mut it = lines.iter();
        let start_line = it.next().cloned().ok_or_else(|| anyhow!("空头部"))?;
        let mut headers = Vec::new();
        for line in it {
            if let Some((k, v)) = line.split_once(':') {
                headers.push((k.trim().to_string(), v.trim().to_string()));
            }
        }
        Ok(Self {
            start_line,
            headers,
        })
    }

    fn get(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }

    fn set(&mut self, name: &str, value: &str) {
        for (k, v) in self.headers.iter_mut() {
            if k.eq_ignore_ascii_case(name) {
                *v = value.to_string();
                return;
            }
        }
        self.headers.push((name.to_string(), value.to_string()));
    }

    fn remove(&mut self, name: &str) {
        self.headers.retain(|(k, _)| !k.eq_ignore_ascii_case(name));
    }

    /// 序列化回字节（保留原有头顺序）。
    fn to_bytes(&self) -> Vec<u8> {
        let mut s = String::with_capacity(256);
        s.push_str(&self.start_line);
        s.push_str("\r\n");
        for (k, v) in &self.headers {
            s.push_str(k);
            s.push_str(": ");
            s.push_str(v);
            s.push_str("\r\n");
        }
        s.push_str("\r\n");
        s.into_bytes()
    }
}

fn wants_keep_alive(parts: &HeadParts) -> bool {
    let conn = parts
        .get("connection")
        .map(|v| v.to_ascii_lowercase())
        .unwrap_or_default();
    if conn.split(',').any(|t| t.trim() == "close") {
        return false;
    }
    if parts.start_line.to_ascii_uppercase().contains("HTTP/1.0") {
        return conn.split(',').any(|t| t.trim() == "keep-alive");
    }
    true
}

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
    format!(
        "HTTP/1.1 {status}\r\n\
         Content-Type: text/plain; charset=utf-8\r\n\
         Content-Length: {}\r\n\
         Connection: close\r\n\r\n{body}",
        body.len()
    )
    .into_bytes()
}

async fn handle_http(
    visitor: TcpStream,
    peer: SocketAddr,
    table: Arc<VhostTable>,
    _port: u16,
    registry: Arc<Registry>,
) -> Result<()> {
    let mut io = HttpIo::new(visitor);

    loop {
        let Some(lines) = io.read_head().await? else {
            return Ok(());
        };
        let mut req = HeadParts::parse(&lines)?;

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
        let host_header = req
            .get("host")
            .map(|h| h.split(':').next().unwrap_or("").to_string())
            .unwrap_or_default();
        let auth_user = basic_auth_user(&req);
        let visitor_keep_alive = wants_keep_alive(&req);

        // ---- 路由 ----
        let Some((route, _loc)) = table.lookup(&host_header, &path, auth_user.as_deref(), false)
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
                io.stream
                    .write_all(&simple_response("404 Not Found", "找不到对应的 frp 代理\n"))
                    .await?;
            }
            return Ok(());
        };

        // ---- Basic Auth ----
        if !route.http_user.is_empty() {
            let ok = match (&auth_user, route.http_pwd.is_empty()) {
                (Some(u), true) => u == &route.http_user,
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
                    u == &route.http_user && given == expect
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
        let Some(resp_lines) = up.read_head().await? else {
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

async fn relay_fixed<S: AsyncRead + Unpin, W: AsyncWrite + Unpin>(
    up: &mut HttpIo<S>,
    down: &mut W,
    n: usize,
) -> Result<()> {
    let mut remaining = n;
    while remaining > 0 {
        let want = remaining.min(64 * 1024);
        if up.available() == 0 && up.fill().await? == 0 {
            bail!("上游提前结束（还差 {remaining} 字节）");
        }
        let take = up.available().min(want);
        let chunk = up.take(take);
        down.write_all(&chunk).await?;
        remaining -= chunk.len();
    }
    Ok(())
}

async fn relay_until_eof<S: AsyncRead + Unpin, W: AsyncWrite + Unpin>(
    up: &mut HttpIo<S>,
    down: &mut W,
) -> Result<()> {
    loop {
        if up.available() > 0 {
            let chunk = up.take(up.available());
            down.write_all(&chunk).await?;
            continue;
        }
        if up.fill().await? == 0 {
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
    use tokio::io::{duplex, AsyncWriteExt, DuplexStream};

    // -----------------------------------------------------------------------
    // 辅助构造
    // -----------------------------------------------------------------------

    fn route(name: &str, domain: &str, locations: &[&str], https: bool) -> Arc<VhostRoute> {
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
            is_https: https,
        })
    }

    fn http_route(name: &str, domain: &str) -> Arc<VhostRoute> {
        route(name, domain, &["/"], false)
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
            .lookup("a.example.com", "/x", None, false)
            .expect("应命中");
        assert_eq!(hit.proxy_name, "web");
        assert_eq!(loc, "/");
        assert!(t.lookup("nope.example.com", "/", None, false).is_none());
    }

    #[test]
    fn host_matching_is_case_insensitive_and_tolerates_trailing_dot() {
        let t = table_with(vec![http_route("web", "a.example.com")]);
        // DNS 大小写无关，且很多客户端会带上根域名的尾部点
        assert!(t.lookup("A.Example.COM", "/", None, false).is_some());
        assert!(t.lookup("a.example.com.", "/", None, false).is_some());
    }

    #[test]
    fn wildcard_matches_subdomains_at_any_depth() {
        let t = table_with(vec![http_route("web", "*.example.com")]);
        assert!(t.lookup("a.example.com", "/", None, false).is_some());
        assert!(t.lookup("a.b.example.com", "/", None, false).is_some());
        // 裸域名本身不该被 *.example.com 匹配
        assert!(t.lookup("example.com", "/", None, false).is_none());
    }

    #[test]
    fn exact_route_wins_over_wildcard() {
        let t = table_with(vec![
            http_route("wild", "*.example.com"),
            http_route("exact", "a.example.com"),
        ]);
        let (hit, _) = t.lookup("a.example.com", "/", None, false).expect("应命中");
        assert_eq!(hit.proxy_name, "exact", "精确域名必须优先于通配");
        let (hit2, _) = t.lookup("b.example.com", "/", None, false).expect("应命中");
        assert_eq!(hit2.proxy_name, "wild");
    }

    #[test]
    fn longest_location_prefix_wins() {
        // 注册顺序故意打乱：排序必须发生在查表侧或者通过 locations 的顺序保证
        let t = table_with(vec![
            route("admin", "x.com", &["/api/admin"], false),
            route("api", "x.com", &["/api"], false),
            route("root", "x.com", &["/"], false),
        ]);
        let hit = |p: &str| {
            t.lookup("x.com", p, None, false)
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
        let t = table_with(vec![route("secure", "x.com", &["/"], true)]);
        assert!(
            t.lookup("x.com", "/", None, false).is_none(),
            "http 请求绝不能打到 https 路由上（两者在同一张表里）"
        );
        assert!(t.lookup("x.com", "/", None, true).is_some());
    }

    #[test]
    fn route_by_http_user_filters_candidates() {
        let t = VhostTable::default();
        let mut alice = route("alice-app", "x.com", &["/"], false);
        Arc::get_mut(&mut alice).unwrap().route_by_http_user = "alice".to_string();
        t.register(alice).expect("注册");
        t.register(http_route("anon", "x.com")).expect("注册");

        assert_eq!(
            t.lookup("x.com", "/", Some("alice"), false)
                .unwrap()
                .0
                .proxy_name,
            "alice-app"
        );
        assert_eq!(
            t.lookup("x.com", "/", Some("bob"), false)
                .unwrap()
                .0
                .proxy_name,
            "anon"
        );
        assert_eq!(
            t.lookup("x.com", "/", None, false).unwrap().0.proxy_name,
            "anon"
        );
    }

    #[test]
    fn duplicate_location_is_rejected_but_nesting_is_allowed() {
        let t = table_with(vec![route("a", "x.com", &["/api"], false)]);
        // 完全相同的路径：两个代理没法区分 -> 冲突
        assert!(t.register(route("dup", "x.com", &["/api"], false)).is_err());
        // 嵌套路径：由最长前缀规则裁决，不算冲突（frp 同款行为）
        assert!(t
            .register(route("nested", "x.com", &["/api/v1"], false))
            .is_ok());
        assert!(t.register(route("root", "x.com", &["/"], false)).is_ok());
        assert!(t
            .register(route("side", "x.com", &["/admin"], false))
            .is_ok());
        // 验证嵌套之后路由仍然走得对
        assert_eq!(
            t.lookup("x.com", "/api/v1/x", None, false)
                .unwrap()
                .0
                .proxy_name,
            "nested"
        );
        assert_eq!(
            t.lookup("x.com", "/api/x", None, false)
                .unwrap()
                .0
                .proxy_name,
            "a"
        );
    }

    #[test]
    fn same_proxy_reregistration_replaces_old_route() {
        let t = VhostTable::default();
        t.register(route("same", "x.com", &["/old"], false))
            .unwrap();
        t.register(route("same", "x.com", &["/new"], false))
            .unwrap();
        let list = { t.inner.lock().unwrap().exact.get("x.com").cloned().unwrap() };
        assert_eq!(list.len(), 1, "同名代理重复注册应替换而非堆积");
        assert_eq!(list[0].locations, vec!["/new"]);
    }

    #[test]
    fn different_proxies_can_share_exact_domain_with_distinct_paths() {
        let t = VhostTable::default();
        for (n, p) in [("one", "/a"), ("two", "/b")] {
            t.register(route(n, "x.com", &[p], false)).unwrap();
        }
        let list = { t.inner.lock().unwrap().exact.get("x.com").cloned().unwrap() };
        assert_eq!(list.len(), 2);
    }

    #[test]
    fn unregister_client_reclaims_all_its_domains() {
        let t = VhostTable::default();
        let client = dummy_client("owner");
        for d in ["a.com", "b.com", "*.c.com"] {
            let mut r = route("p", d, &["/"], false);
            Arc::get_mut(&mut r).unwrap().client = client.clone();
            t.register(r).unwrap();
        }
        assert!(t.lookup("a.com", "/", None, false).is_some());
        t.unregister_client(&client);
        for d in ["a.com", "b.com", "x.c.com"] {
            assert!(t.lookup(d, "/", None, false).is_none(), "{d} 应被回收");
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
        let mut keep = route("keep", "keep.com", &["/"], false);
        Arc::get_mut(&mut keep).unwrap().client = other.clone();
        let mut drop_me = route("drop", "drop.com", &["/"], false);
        Arc::get_mut(&mut drop_me).unwrap().client = owner.clone();
        t.register(keep).unwrap();
        t.register(drop_me).unwrap();

        t.unregister_client(&owner);
        assert!(t.lookup("drop.com", "/", None, false).is_none());
        assert!(
            t.lookup("keep.com", "/", None, false).is_some(),
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
}
