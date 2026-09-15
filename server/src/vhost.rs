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

use crate::ClientState;

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
    /// 路径是否命中（最长前缀优先由查表顺序保证）。
    pub fn match_location(&self, path: &str) -> Option<&str> {
        self.locations
            .iter()
            .find(|loc| path.starts_with(loc.as_str()))
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
            let overlap = existing.locations.iter().any(|a| {
                route
                    .locations
                    .iter()
                    .any(|b| a == b || a.starts_with(b.as_str()) || b.starts_with(a.as_str()))
            });
            if !same_proxy && overlap {
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

        let matched = |list: &Vec<Arc<VhostRoute>>| -> Option<(Arc<VhostRoute>, String)> {
            for route in list {
                if route.is_https != https {
                    continue;
                }
                if !route.route_by_http_user.is_empty()
                    && route.route_by_http_user != auth_user.unwrap_or("")
                {
                    continue;
                }
                if let Some(loc) = route.match_location(path) {
                    return Some((route.clone(), loc.to_string()));
                }
            }
            None
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
pub async fn run_http(
    listener: TcpListener,
    table: Arc<VhostTable>,
    port: u16,
    is_https: bool,
) {
    info!(
        "{} 虚拟主机已启动，监听 :{port}",
        if is_https { "HTTPS" } else { "HTTP" }
    );
    loop {
        match listener.accept().await {
            Ok((stream, peer)) => {
                let table = table.clone();
                tokio::spawn(async move {
                    if let Err(e) = handle_conn(stream, peer, table, port, is_https).await {
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

async fn handle_conn(
    visitor: TcpStream,
    peer: SocketAddr,
    table: Arc<VhostTable>,
    port: u16,
    is_https: bool,
) -> Result<()> {
    visitor.set_nodelay(true).ok();
    if is_https {
        handle_https(visitor, peer, table, port).await
    } else {
        handle_http(visitor, peer, table, port).await
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

    debug!(%peer, %sni, proxy = %route.proxy_name, "HTTPS 透传开始");
    let (mut upstream, leftover) = work_conn.into_stream();
    if !leftover.is_empty() {
        // 极少见：StartWorkConn 之后客户端已经把响应写回来了
        debug!("HTTPS 上游有 {} 字节预读数据", leftover.len());
    }
    upstream.write_all(&hello_bytes).await?;
    let mut visitor = visitor;
    let r = rustunnel_common::util::relay_between(&mut visitor, &mut upstream).await;
    if let Err(e) = r {
        debug!(%peer, %sni, "HTTPS 透传中断：{e}");
    }
    Ok(())
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
                bail!("连接在读取 {} 字节时提前结束（已有 {}）", n, self.available());
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
        Ok(Self { start_line, headers })
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
        let Some((route, _loc)) =
            table.lookup(&host_header, &path, auth_user.as_deref(), false)
        else {
            debug!(%peer, host = %host_header, path = %path, "没有匹配的 http 代理");
            if method == "CONNECT" {
                io.stream
                    .write_all(&simple_response("405 Method Not Allowed", "不支持 CONNECT\n"))
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
