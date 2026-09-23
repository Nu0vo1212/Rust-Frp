//! 极简 HTTP/1.1 客户端 —— 只为 OIDC（拉 JWKS、换 token）和自检用。
//!
//! # 为什么不引 reqwest / hyper
//!
//! 需要的能力只有三件：GET 一个 JSON、POST 一个 form、走 http(s) 代理。
//! 而 `reqwest` 会带进 hyper + tower + 一堆异步抽象，在 `lto + opt-level=s`
//! 的 release profile 下体积代价很大，且这里没有连接池 / 重定向 / cookie 的需求。
//! rustls 本来就在依赖里（frp 的 TLS 传输用它），复用它即可。
//!
//! # 覆盖范围与边界
//!
//! * 支持 `http` / `https`；
//! * 支持 `http://` 与 `https://` 代理（后者用 CONNECT 隧道）；
//! * 支持 `Connection: close` 的一次性请求，支持 `Content-Length` 与 `chunked`；
//! * **不支持** HTTP/2、重定向、cookie —— OIDC 的 token endpoint 与 JWKS
//!   都不需要这些（个别 IdP 的 discovery 文档会 302，那种情况请直接把
//!   `tokenEndpointURL` / `issuer` 写成最终地址）。

use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};
use rustls::pki_types::CertificateDer;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

use crate::frp::stream::BoxStream;
use crate::frp::tls::crypto_provider;
use crate::util;

/// 响应体上限，防止对端灌爆内存。
const MAX_BODY: usize = 8 * 1024 * 1024;

/// 一次请求的可选项。
#[derive(Debug, Clone, Default)]
pub struct Options {
    /// 跳过 TLS 证书校验（对应 frp 的 `insecureSkipVerify`，只建议调试时开）。
    pub insecure_skip_verify: bool,
    /// 追加信任的 CA 证书文件（PEM）。
    pub trusted_ca_file: String,
    /// 代理地址，形如 `http://127.0.0.1:8080` / `https://proxy:8443`。
    pub proxy_url: String,
    /// 整体超时（秒），0 表示用默认 20 秒。
    pub timeout_secs: u64,
}

/// 一次请求的响应。
#[derive(Debug, Clone)]
pub struct Response {
    pub status: u16,
    pub body: Vec<u8>,
}

impl Response {
    /// 把响应体当 JSON 解析。
    pub fn json(&self) -> Result<serde_json::Value> {
        serde_json::from_slice(&self.body).with_context(|| {
            format!(
                "响应不是合法 JSON（HTTP {}）：{}",
                self.status,
                String::from_utf8_lossy(&self.body[..self.body.len().min(200)])
            )
        })
    }

    /// 2xx 之外的响应一律当失败，并把响应体带进错误信息（IdP 的错误描述都在里面）。
    pub fn ensure_success(&self) -> Result<&Self> {
        if (200..300).contains(&self.status) {
            return Ok(self);
        }
        bail!(
            "HTTP {} ：{}",
            self.status,
            String::from_utf8_lossy(&self.body[..self.body.len().min(400)])
        )
    }
}

/// 发一个 GET（不带 body）。
pub async fn get(url: &str, headers: &[(&str, &str)], opts: &Options) -> Result<Response> {
    request("GET", url, headers, None, opts).await
}

/// 发一个 form 编码的 POST（OIDC 的 client_credentials 就是这个形状）。
pub async fn post_form(
    url: &str,
    form: &[(&str, &str)],
    headers: &[(&str, &str)],
    opts: &Options,
) -> Result<Response> {
    let body = form
        .iter()
        .map(|(k, v)| format!("{}={}", percent_encode(k), percent_encode(v)))
        .collect::<Vec<_>>()
        .join("&");
    let mut hs = headers.to_vec();
    hs.push(("Content-Type", "application/x-www-form-urlencoded"));
    request("POST", url, &hs, Some(body.into_bytes()), opts).await
}

/// 发一个 `application/json` 的 POST。
pub async fn post_json(
    url: &str,
    body: &serde_json::Value,
    headers: &[(&str, &str)],
    opts: &Options,
) -> Result<Response> {
    let mut hs = headers.to_vec();
    hs.push(("Content-Type", "application/json"));
    let raw = serde_json::to_vec(body)?;
    request("POST", url, &hs, Some(raw), opts).await
}

/// 发一个任意方法的请求。
pub async fn request(
    method: &str,
    url: &str,
    headers: &[(&str, &str)],
    body: Option<Vec<u8>>,
    opts: &Options,
) -> Result<Response> {
    let target = Url::parse(url)?;
    let timeout = Duration::from_secs(if opts.timeout_secs == 0 {
        20
    } else {
        opts.timeout_secs
    });
    match tokio::time::timeout(timeout, request_inner(method, &target, headers, body, opts)).await {
        Ok(r) => r,
        Err(_) => bail!("请求 {url} 超时（{} 秒）", timeout.as_secs()),
    }
}

async fn request_inner(
    method: &str,
    target: &Url,
    headers: &[(&str, &str)],
    body: Option<Vec<u8>>,
    opts: &Options,
) -> Result<Response> {
    let default_port = if target.tls { 443 } else { 80 };
    let port = target.port.unwrap_or(default_port);
    let hostport = format!("{}:{}", target.host, port);
    let via_proxy = !opts.proxy_url.trim().is_empty();

    let mut stream: BoxStream = if via_proxy {
        connect_via_proxy(&hostport, target, opts).await?
    } else {
        Box::pin(connect_tcp(&hostport).await?)
    };

    if target.tls {
        let name = rustls::pki_types::ServerName::try_from(target.host.clone())
            .map_err(|e| anyhow!("无效的 TLS 主机名 {}：{e:?}", target.host))?;
        let cfg = client_tls_config(opts)?;
        stream = Box::pin(
            TlsConnector::from(cfg)
                .connect(name, stream)
                .await
                .with_context(|| format!("与 {} 的 TLS 握手失败", target.host))?,
        );
    }

    // 请求行：走 http 代理时必须是**绝对 URI**（RFC 7230 §5.3.2），
    // 直连或已经 CONNECT 建好隧道时用相对路径。
    let request_target = if via_proxy && !target.tls {
        target.full()
    } else {
        target.path_and_query().to_string()
    };

    // `Connection: close` 是刻意的：读响应体时可以直接读到 EOF，
    // 不用处理 Keep-Alive 的边界（我们也不需要复用连接）。
    let mut req = format!(
        "{method} {request_target} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\nAccept: application/json\r\n",
        target.host_header()
    );
    for (k, v) in headers {
        req.push_str(&format!("{k}: {v}\r\n"));
    }
    if let Some(b) = &body {
        req.push_str(&format!("Content-Length: {}\r\n", b.len()));
    }
    req.push_str("\r\n");

    stream
        .write_all(req.as_bytes())
        .await
        .context("发送请求头失败")?;
    if let Some(b) = &body {
        stream.write_all(b).await.context("发送请求体失败")?;
    }
    stream.flush().await.ok();

    let raw = read_all(stream).await?;
    parse_response(&raw)
}

/// 直连一个 `host:port`。
async fn connect_tcp(hostport: &str) -> Result<TcpStream> {
    let addr = util::resolve_addr(hostport)
        .await
        .with_context(|| format!("解析 {hostport} 失败"))?;
    let s = TcpStream::connect(addr)
        .await
        .with_context(|| format!("连接 {addr} 失败"))?;
    s.set_nodelay(true).ok();
    Ok(s)
}

/// 连到代理。
///
/// * 目标是 https → 发 `CONNECT` 建隧道，返回隧道流（后面再套 TLS）；
/// * 目标是 http  → 返回裸代理连接，由调用方用**绝对 URI** 发请求。
///
/// 只实现 http / https 代理。socks5 会**明确报错**而不是悄悄直连 ——
/// 静默直连会绕过用户刻意配置的网络路径，属于安全上的意外。
async fn connect_via_proxy(hostport: &str, target: &Url, opts: &Options) -> Result<BoxStream> {
    let proxy = Url::parse(&opts.proxy_url)?;
    if !proxy.raw_scheme.eq_ignore_ascii_case("http")
        && !proxy.raw_scheme.eq_ignore_ascii_case("https")
    {
        bail!(
            "暂不支持 {} 代理（OIDC 只实现了 http / https 代理）：{}",
            proxy.raw_scheme,
            opts.proxy_url
        );
    }
    let pport = proxy.port.unwrap_or(if proxy.tls { 443 } else { 80 });
    let mut stream: BoxStream = Box::pin(connect_tcp(&format!("{}:{}", proxy.host, pport)).await?);
    if proxy.tls {
        let name = rustls::pki_types::ServerName::try_from(proxy.host.clone())
            .map_err(|e| anyhow!("无效的代理主机名 {}：{e:?}", proxy.host))?;
        stream = Box::pin(
            TlsConnector::from(client_tls_config(opts)?)
                .connect(name, stream)
                .await
                .context("与代理的 TLS 握手失败")?,
        );
    }

    if target.tls {
        let req = format!("CONNECT {hostport} HTTP/1.1\r\nHost: {hostport}\r\n\r\n");
        stream.write_all(req.as_bytes()).await?;
        stream.flush().await.ok();
        let head = read_until_headers_end(&mut stream).await?;
        let status = head
            .lines()
            .next()
            .and_then(|l| l.split_whitespace().nth(1))
            .and_then(|s| s.parse::<u16>().ok())
            .unwrap_or(0);
        if status != 200 {
            bail!("代理拒绝 CONNECT {hostport}：HTTP {status}");
        }
    }
    Ok(stream)
}

/// 读满整个响应（到 EOF）。
async fn read_all(mut stream: BoxStream) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    let mut chunk = vec![0u8; 16 * 1024];
    loop {
        let n = stream.read(&mut chunk).await.context("读响应失败")?;
        if n == 0 {
            break;
        }
        out.extend_from_slice(&chunk[..n]);
        if out.len() > MAX_BODY {
            bail!("响应体超过 {MAX_BODY} 字节");
        }
    }
    Ok(out)
}

/// 只读到响应头结束（用于 CONNECT 的 200 响应）。
async fn read_until_headers_end(stream: &mut BoxStream) -> Result<String> {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 1024];
    loop {
        let n = stream.read(&mut chunk).await?;
        if n == 0 {
            break;
        }
        buf.extend_from_slice(&chunk[..n]);
        if buf.windows(4).any(|w| w == b"\r\n\r\n") || buf.len() > 64 * 1024 {
            break;
        }
    }
    Ok(String::from_utf8_lossy(&buf).to_string())
}

/// 解析 HTTP 响应（headers + body，支持 chunked）。
fn parse_response(raw: &[u8]) -> Result<Response> {
    let sep = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .ok_or_else(|| anyhow!("响应里没有头部结束标记"))?;
    let head = String::from_utf8_lossy(&raw[..sep]).to_string();
    let body_raw = &raw[sep + 4..];

    let status = head
        .lines()
        .next()
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|s| s.parse::<u16>().ok())
        .ok_or_else(|| anyhow!("响应状态行无法解析：{}", head.lines().next().unwrap_or("")))?;

    let chunked = header(&head, "transfer-encoding")
        .map(|v| v.to_ascii_lowercase().contains("chunked"))
        .unwrap_or(false);
    let body = if chunked {
        decode_chunked(body_raw)?
    } else {
        body_raw.to_vec()
    };
    Ok(Response { status, body })
}

fn header(head: &str, name: &str) -> Option<String> {
    head.lines().skip(1).find_map(|l| {
        let (k, v) = l.split_once(':')?;
        k.trim()
            .eq_ignore_ascii_case(name)
            .then(|| v.trim().to_string())
    })
}

/// 解 chunked 编码。
fn decode_chunked(raw: &[u8]) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    let mut i = 0usize;
    // `i + 1 < raw.len()`：末尾缺 CRLF 时不能让 `raw[i..]` 越界 panic
    while i + 1 < raw.len() {
        // 找这一段的长度行
        let line_end = match raw[i..].windows(2).position(|w| w == b"\r\n") {
            Some(p) => i + p,
            None => break,
        };
        let line = String::from_utf8_lossy(&raw[i..line_end]).to_string();
        let size_text = line.split(';').next().unwrap_or("").trim();
        let size = usize::from_str_radix(size_text, 16)
            .map_err(|_| anyhow!("chunked 段长度非法：{size_text:?}"))?;
        i = line_end + 2;
        if size == 0 {
            break;
        }
        if raw.len() < i + size {
            bail!("chunked 数据被截断");
        }
        out.extend_from_slice(&raw[i..i + size]);
        i += size + 2; // 跳过数据与结尾 CRLF
        if out.len() > MAX_BODY {
            bail!("chunked 响应体超过 {MAX_BODY} 字节");
        }
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// URL
// ---------------------------------------------------------------------------

/// 够用的 URL 解析（scheme / host / port / path?query）。
#[derive(Debug, Clone)]
pub struct Url {
    raw_scheme: String,
    pub host: String,
    pub port: Option<u16>,
    pub tls: bool,
    path_and_query: String,
}

impl Url {
    pub fn parse(s: &str) -> Result<Self> {
        let s = s.trim();
        let (scheme, rest) = s
            .split_once("://")
            .ok_or_else(|| anyhow!("URL 缺少 scheme：{s}"))?;
        let scheme = scheme.to_ascii_lowercase();
        let tls = match scheme.as_str() {
            "https" | "wss" => true,
            "http" | "ws" => false,
            other => bail!("不支持的 scheme {other}（只实现了 http / https）"),
        };
        // 允许 URL 里带 userinfo，但这里用不到，直接丢掉
        let rest = match rest.split_once('@') {
            Some((_, r)) => r,
            None => rest,
        };
        let (authority, path) = match rest.find('/') {
            Some(i) => (&rest[..i], &rest[i..]),
            None => (rest, "/"),
        };
        let (host, port) = match authority.rsplit_once(':') {
            // 注意 IPv6 是 [::1]:8080 的形式
            Some((h, p)) if !h.ends_with(']') || authority.starts_with('[') => {
                match p.parse::<u16>() {
                    Ok(p) => (
                        h.trim_matches(|c| c == '[' || c == ']').to_string(),
                        Some(p),
                    ),
                    Err(_) => (authority.to_string(), None),
                }
            }
            _ => (authority.to_string(), None),
        };
        if host.is_empty() {
            bail!("URL 里没有主机名：{s}");
        }
        Ok(Self {
            raw_scheme: scheme,
            host,
            port,
            tls,
            path_and_query: if path.is_empty() {
                "/".into()
            } else {
                path.to_string()
            },
        })
    }

    pub fn path_and_query(&self) -> &str {
        &self.path_and_query
    }

    /// `Host:` 头里的值（非默认端口才带端口）。
    pub fn host_header(&self) -> String {
        let dflt = if self.tls { 443 } else { 80 };
        match self.port {
            Some(p) if p != dflt => format!("{}:{}", self.host, p),
            _ => self.host.clone(),
        }
    }

    /// 完整的 URL（http 代理的请求行要用它）。
    pub fn full(&self) -> String {
        let scheme = if self.tls { "https" } else { "http" };
        format!("{}://{}{}", scheme, self.host_header(), self.path_and_query)
    }
}

// ---------------------------------------------------------------------------
// TLS 配置
// ---------------------------------------------------------------------------

/// 构造 OIDC 用的 rustls 客户端配置。
///
/// 与 frp 隧道那条 TLS 不同：这里**默认是要校验证书的**（对面的 IdP 有正经证书），
/// 只有显式配了 `insecureSkipVerify` 才跳过。
fn client_tls_config(opts: &Options) -> Result<Arc<rustls::ClientConfig>> {
    let builder = rustls::ClientConfig::builder_with_provider(crypto_provider())
        .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])
        .map_err(|e| anyhow!("TLS 协议版本配置失败：{e}"))?;

    if opts.insecure_skip_verify {
        return Ok(Arc::new(
            builder
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(crate::frp::tls::SkipServerVerification))
                .with_no_client_auth(),
        ));
    }

    let mut roots = rustls::RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    if !opts.trusted_ca_file.trim().is_empty() {
        for der in read_pem_certs(&opts.trusted_ca_file)? {
            roots
                .add(der)
                .with_context(|| format!("加载 CA 文件 {} 里的证书失败", opts.trusted_ca_file))?;
        }
    }
    Ok(Arc::new(
        builder.with_root_certificates(roots).with_no_client_auth(),
    ))
}

/// 从 PEM 文件里读出所有 CERTIFICATE 块。
fn read_pem_certs(path: &str) -> Result<Vec<CertificateDer<'static>>> {
    use base64::{engine::general_purpose::STANDARD, Engine as _};
    let text =
        std::fs::read_to_string(path).with_context(|| format!("读取 CA 文件 {path} 失败"))?;
    let mut out = Vec::new();
    let mut in_block = false;
    let mut b64 = String::new();
    for line in text.lines() {
        let l = line.trim();
        if l.contains("BEGIN CERTIFICATE") {
            in_block = true;
            b64.clear();
            continue;
        }
        if l.contains("END CERTIFICATE") {
            if in_block {
                let der = STANDARD
                    .decode(b64.as_bytes())
                    .map_err(|e| anyhow!("CA 文件里的证书不是合法 base64：{e}"))?;
                out.push(CertificateDer::from(der));
            }
            in_block = false;
            continue;
        }
        if in_block {
            b64.push_str(l);
        }
    }
    if out.is_empty() {
        bail!("CA 文件 {path} 里没有找到任何 CERTIFICATE 块");
    }
    Ok(out)
}

/// form 编码用的百分号转义（`application/x-www-form-urlencoded`）。
fn percent_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char)
            }
            b' ' => out.push('+'),
            other => out.push_str(&format!("%{other:02X}")),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn url_解析各种形态() {
        let u = Url::parse("https://idp.example.com/token").unwrap();
        assert!(u.tls);
        assert_eq!(u.host, "idp.example.com");
        assert_eq!(u.port, None);
        assert_eq!(u.path_and_query(), "/token");
        assert_eq!(u.host_header(), "idp.example.com");
        assert_eq!(u.full(), "https://idp.example.com/token");

        let u = Url::parse("http://127.0.0.1:8080/.well-known/openid-configuration").unwrap();
        assert!(!u.tls);
        assert_eq!(u.port, Some(8080));
        assert_eq!(u.host_header(), "127.0.0.1:8080");

        // 非默认端口才带在 Host 头里
        let u = Url::parse("https://idp.example.com:8443/a?b=c").unwrap();
        assert_eq!(u.host_header(), "idp.example.com:8443");
        assert_eq!(u.path_and_query(), "/a?b=c");

        // 没有 path 时补 `/`
        assert_eq!(Url::parse("https://x").unwrap().path_and_query(), "/");
        // userinfo 被丢掉
        assert_eq!(Url::parse("https://u:p@x/y").unwrap().host, "x");
        // 非法 scheme
        assert!(Url::parse("ftp://x/y").is_err());
        assert!(Url::parse("no-scheme").is_err());
    }

    #[test]
    fn form_编码转义正确() {
        assert_eq!(percent_encode("abc-_.~"), "abc-_.~");
        assert_eq!(percent_encode("a b"), "a+b");
        assert_eq!(percent_encode("a/b&c=d"), "a%2Fb%26c%3Dd");
        assert_eq!(percent_encode("中文"), "%E4%B8%AD%E6%96%87");
    }

    #[test]
    fn 响应解析带_content_length() {
        let raw =
            b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 2\r\n\r\n{}";
        let r = parse_response(raw).unwrap();
        assert_eq!(r.status, 200);
        assert_eq!(r.body, b"{}");
        assert_eq!(r.json().unwrap(), serde_json::json!({}));
    }

    /// IdP 常用 chunked 返回；不会解就会拿到一堆十六进制长度前缀。
    #[test]
    fn 响应解析带_chunked() {
        // 两段：`{"a`(3) + `":1}`(4)，拼起来正好是 7 字节的 `{"a":1}`
        let raw = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n\
                    3\r\n{\"a\r\n4\r\n\":1}\r\n0\r\n\r\n";
        let r = parse_response(raw).unwrap();
        assert_eq!(r.status, 200);
        assert_eq!(r.body, b"{\"a\":1}");
    }

    #[test]
    fn 非_2xx_会带出响应体() {
        let raw = b"HTTP/1.1 400 Bad Request\r\nContent-Length: 9\r\n\r\nno_such_u";
        let r = parse_response(raw).unwrap();
        let e = r.ensure_success().unwrap_err().to_string();
        assert!(e.contains("400") && e.contains("no_such_u"), "{e}");
        assert!(parse_response(b"HTTP/1.1 200 OK\r\n\r\n")
            .unwrap()
            .ensure_success()
            .is_ok());
    }

    #[test]
    fn 缺头部结束标记时报错() {
        assert!(parse_response(b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\n").is_err());
    }

    /// 坏掉的 chunked 要报错，不能悄悄丢掉后半截（那样 JSON 会莫名其妙残缺）。
    #[test]
    fn 截断的_chunked_会报错() {
        // `ff` = 声明 255 字节，实际只跟了 5 字节 —— 必须报错
        let raw = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nff\r\nshort\r\n";
        assert!(
            parse_response(raw).is_err(),
            "截断的 chunked 不能被当成正常响应"
        );
        assert!(decode_chunked(b"ff\r\nshort\r\n").is_err());
    }
}
