//! 极简 HTTP/1.1 服务端工具。
//!
//! 只实现内置面板需要的那一小块：读一条请求、解 Basic Auth、发一条响应。
//! **刻意不引 HTTP 框架** —— 整个项目只有两个进程内的管理面板，
//! 为它们拖进 hyper + tower + http-body 一整条依赖链不划算，
//! 而这一小块的代码量比那些依赖的 `Cargo.lock` 行数还少。
//!
//! # 三个踩过的坑，改的时候别踩回去
//!
//! 1. **必须按 `Content-Length` 把请求体读全**。只读到 `\r\n\r\n` 就收手的话，
//!    跨 TCP 段过来的请求体会被截断（JSON 解析莫名失败）；更糟的是我们没读完
//!    就关 socket，内核回的是 **RST 而不是 FIN** —— Windows 上客户端连已经
//!    写出来的响应都收不到，表现为"面板明明回了 401，我却只看到连接被重置"。
//! 2. **Basic Auth 要连密码一起比**，只比用户名等于把面板敞开；而且必须**定长比较**，
//!    否则能通过响应耗时逐字节把密码试出来。
//! 3. **健康探针必须在鉴权之前放行**（由调用方决定顺序）。k8s / docker / LB 的
//!    探针不方便带凭据，而放行它泄露的信息量为零；早先它排在鉴权后面，
//!    容器因此被反复重启。

use std::collections::BTreeMap;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// 请求行 + 请求头允许的最大字节数。
///
/// 超过就当这条请求已经读完 —— 真发这么大的头，多半是打错了协议或者在被扫描，
/// 没必要为了把它读完而吃内存。
pub const MAX_HEAD: usize = 32 * 1024;

/// 一条已经读完的请求。
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Request {
    /// 已转大写（`GET` / `POST` / …）。
    pub method: String,
    /// 不含 query string；至少是 `/`。
    pub path: String,
    /// `?` 之后的部分，不含 `?`。没有就是空串。
    pub query: String,
    /// `\r\n\r\n` 之后的全部内容。
    pub body: String,
    /// 原始请求头区（含请求行，不含结尾的空行）。
    pub head: String,
}

impl Request {
    /// 解析后的 query 参数。
    pub fn params(&self) -> BTreeMap<String, String> {
        parse_query(&self.query)
    }

    /// 取某个请求头（大小写不敏感）。
    pub fn header(&self, name: &str) -> Option<String> {
        header_in_head(&self.head, name)
    }

    /// 请求头里的 `Content-Length`（没有就是 0）。
    pub fn content_length(&self) -> usize {
        self.header("content-length")
            .and_then(|v| v.parse::<usize>().ok())
            .unwrap_or(0)
    }

    /// 请求头里的 `Authorization`。
    pub fn authorization(&self) -> Option<String> {
        self.header("authorization")
    }
}

/// 从原始请求头里取某个头的值。
fn header_in_head(head: &str, name: &str) -> Option<String> {
    // skip(1) 跳过请求行 —— 否则 `GET /a:b HTTP/1.1` 会被当成一个叫 `a` 的头
    for line in head.split("\r\n").skip(1) {
        if let Some((k, v)) = line.split_once(':') {
            if k.trim().eq_ignore_ascii_case(name) {
                return Some(v.trim().to_string());
            }
        }
    }
    None
}

/// 读一条完整的 HTTP 请求（到请求体读完为止；每个连接只处理一条）。
pub async fn read_request<S>(stream: &mut S) -> std::io::Result<Request>
where
    S: AsyncRead + Unpin,
{
    let mut buf: Vec<u8> = Vec::with_capacity(1024);
    let mut chunk = [0u8; 2048];
    let mut want_body = 0usize;

    loop {
        let n = stream.read(&mut chunk).await?;
        if n == 0 {
            break;
        }
        buf.extend_from_slice(&chunk[..n]);

        if buf.len() > MAX_HEAD * 4 {
            break;
        }
        let Some(off) = body_offset(&buf) else {
            continue;
        };
        if want_body == 0 {
            // 头齐了才谈得上请求体长度
            let head = String::from_utf8_lossy(&buf[..off]).to_string();
            want_body = header_in_head(&head, "content-length")
                .and_then(|v| v.parse::<usize>().ok())
                .unwrap_or(0);
        }
        if buf.len() - off >= want_body {
            break;
        }
    }
    Ok(parse(&buf))
}

/// `\r\n\r\n` 之后第一个字节的下标。
fn body_offset(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n").map(|i| i + 4)
}

/// 把原始字节解析成 [`Request`]。
pub fn parse(buf: &[u8]) -> Request {
    parse_str(&String::from_utf8_lossy(buf))
}

/// 纯文本版本的解析（[`parse`] 的正文，抽出来便于单测）。
pub fn parse_str(raw: &str) -> Request {
    let (head, body) = match raw.find("\r\n\r\n") {
        Some(i) => (&raw[..i], &raw[i + 4..]),
        None => (raw, ""),
    };
    let req_line = head.split("\r\n").next().unwrap_or("");
    let mut parts = req_line.split_whitespace();
    let method = parts.next().unwrap_or("").to_ascii_uppercase();
    let target = parts.next().unwrap_or("/");
    let (path, query) = match target.split_once('?') {
        Some((p, q)) => (p, q),
        None => (target, ""),
    };
    Request {
        method,
        path: if path.is_empty() {
            "/".into()
        } else {
            path.into()
        },
        query: query.into(),
        body: body.into(),
        head: head.to_string(),
    }
}

/// 把 `a=1&b=2` 拆成键值对（键与值都做百分号解码）。
///
/// 容忍开头多一个 `?`：调用方拿到的可能是"纯 query"，也可能是完整
/// request-target，两种都得能解。
pub fn parse_query(raw: &str) -> BTreeMap<String, String> {
    let raw = raw.strip_prefix('?').unwrap_or(raw);
    let mut out = BTreeMap::new();
    for pair in raw.split('&') {
        if pair.is_empty() {
            continue;
        }
        let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
        out.insert(percent_decode(k), percent_decode(v));
    }
    out
}

/// `%XX` 与 `+` 解码。
///
/// 只用到这两条规则，为它引一个 `urlencoding` 依赖不划算；
/// 而且我们只需要"解"，不需要"编"。
pub fn percent_decode(s: &str) -> String {
    let b = s.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            b'%' if i + 2 < b.len() => match (hex_val(b[i + 1]), hex_val(b[i + 2])) {
                (Some(h), Some(l)) => {
                    out.push(h * 16 + l);
                    i += 3;
                }
                // 不是合法的 %XX：原样吐出，别把用户的数据吃掉
                _ => {
                    out.push(b[i]);
                    i += 1;
                }
            },
            c => {
                out.push(c);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn hex_val(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

/// 解析 `Authorization: Basic xxx` 的头部值。
///
/// **只认 Basic**：把 Bearer / 其它方案当成"没带凭据"，
/// 免得哪天某个方案被误当成合法凭证放进来。
pub fn basic_auth(header: Option<&str>) -> Option<String> {
    use base64::{engine::general_purpose::STANDARD, Engine as _};
    let raw = header?;
    let (scheme, value) = raw.split_once(' ')?;
    if !scheme.eq_ignore_ascii_case("basic") {
        return None;
    }
    let decoded = STANDARD.decode(value.trim().as_bytes()).ok()?;
    String::from_utf8(decoded).ok()
}

/// 定长比较，避免通过响应时间推测密码。
pub fn constant_time_eq(a: &str, b: &str) -> bool {
    crate::frp::msg::constant_time_eq(a, b)
}

/// 状态码对应的 reason phrase。
pub fn reason(code: u16) -> &'static str {
    match code {
        200 => "OK",
        201 => "Created",
        204 => "No Content",
        301 => "Moved Permanently",
        302 => "Found",
        304 => "Not Modified",
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        409 => "Conflict",
        413 => "Payload Too Large",
        415 => "Unsupported Media Type",
        429 => "Too Many Requests",
        500 => "Internal Server Error",
        501 => "Not Implemented",
        502 => "Bad Gateway",
        503 => "Service Unavailable",
        504 => "Gateway Timeout",
        _ => "Status",
    }
}

/// 发一条响应。`Connection: close` —— 每个连接只服务一条请求，简单且不会
/// 因为 keep-alive 状态机的 bug 把自己挂住。
pub async fn send<S>(
    stream: &mut S,
    code: u16,
    content_type: &str,
    body: &[u8],
    extra: &[(&str, &str)],
) -> std::io::Result<()>
where
    S: AsyncWrite + Unpin,
{
    let mut out = format!(
        "HTTP/1.1 {code} {}\r\n\
         Content-Type: {content_type}\r\n\
         Content-Length: {}\r\n\
         Connection: close\r\n",
        reason(code),
        body.len()
    );
    for (k, v) in extra {
        out.push_str(&format!("{k}: {v}\r\n"));
    }
    out.push_str("\r\n");
    stream.write_all(out.as_bytes()).await?;
    stream.write_all(body).await?;
    stream.flush().await?;
    Ok(())
}

/// 发一段 JSON。
pub async fn send_json<S>(stream: &mut S, code: u16, body: &str) -> std::io::Result<()>
where
    S: AsyncWrite + Unpin,
{
    send(
        stream,
        code,
        "application/json; charset=utf-8",
        body.as_bytes(),
        &[],
    )
    .await
}

/// 发一段 HTML。
pub async fn send_html<S>(stream: &mut S, code: u16, body: &str) -> std::io::Result<()>
where
    S: AsyncWrite + Unpin,
{
    send(
        stream,
        code,
        "text/html; charset=utf-8",
        body.as_bytes(),
        &[],
    )
    .await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn 解析请求行与_query() {
        let r = parse_str("GET /api/v2/clients?page=2&page_size=5 HTTP/1.1\r\nHost: x\r\n\r\n");
        assert_eq!(r.method, "GET");
        assert_eq!(r.path, "/api/v2/clients");
        assert_eq!(r.query, "page=2&page_size=5");
        assert_eq!(r.params().get("page").unwrap(), "2");
    }

    #[test]
    fn 方法转大写_路径至少是斜杠() {
        let r = parse_str("get /x HTTP/1.1\r\n\r\n");
        assert_eq!(r.method, "GET");
        assert_eq!(r.path, "/x");
        assert_eq!(r.query, "");

        // 只有方法、没有 target 的畸形请求行：path 不能变成空串，
        // 否则后面的 `path == "/"` 之类的判断会全部落空
        let r = parse_str("GET\r\n\r\n");
        assert_eq!(r.method, "GET");
        assert_eq!(r.path, "/");
    }

    #[test]
    fn 请求体在空行之后() {
        let r = parse_str("POST /x HTTP/1.1\r\nContent-Length: 5\r\n\r\n{\"a\"}");
        assert_eq!(r.body, "{\"a\"}");
    }

    #[test]
    fn 没有空行时请求体为空() {
        let r = parse_str("GET / HTTP/1.1");
        assert_eq!(r.body, "");
    }

    #[test]
    fn 头部查询大小写不敏感且不吃请求体() {
        let head = "POST /x HTTP/1.1\r\nContent-Type: text/plain\r\nX-Custom: v";
        assert_eq!(header_in_head(head, "content-type").unwrap(), "text/plain");
        assert_eq!(header_in_head(head, "CONTENT-TYPE").unwrap(), "text/plain");
        assert_eq!(header_in_head(head, "x-custom").unwrap(), "v");
        assert!(header_in_head(head, "missing").is_none());
        // 请求行不能被当成头
        assert!(header_in_head("GET /a:b HTTP/1.1", "a").is_none());
    }

    #[test]
    fn basic_auth_只认_basic() {
        use base64::{engine::general_purpose::STANDARD, Engine as _};
        let ok = format!("Basic {}", STANDARD.encode("u:p"));
        assert_eq!(basic_auth(Some(&ok)).unwrap(), "u:p");

        // Bearer 不能被当成合法凭据
        assert!(basic_auth(Some("Bearer abc")).is_none());
        assert!(basic_auth(None).is_none());
        // 非法 base64 不 panic
        assert!(basic_auth(Some("Basic !!!")).is_none());
        // 合法 base64 但不是 UTF-8
        let raw = STANDARD.encode([0xff, 0xfe]);
        assert!(basic_auth(Some(&format!("Basic {raw}"))).is_none());
    }

    #[test]
    fn query_解码() {
        let q = parse_query("?user=%E5%BC%A0%E4%B8%89&q=a+b&flag&empty=");
        assert_eq!(q.get("user").unwrap(), "张三");
        assert_eq!(q.get("q").unwrap(), "a b");
        assert_eq!(q.get("flag").unwrap(), "");
        assert_eq!(q.get("empty").unwrap(), "");
    }

    #[test]
    fn 非法百分号原样保留() {
        assert_eq!(percent_decode("a%zzb"), "a%zzb");
        assert_eq!(percent_decode("100%"), "100%");
        assert_eq!(percent_decode("%4"), "%4");
    }

    #[test]
    fn reason_覆盖常用码() {
        assert_eq!(reason(200), "OK");
        assert_eq!(reason(401), "Unauthorized");
        assert_eq!(reason(502), "Bad Gateway");
        assert_eq!(reason(599), "Status");
    }

    #[tokio::test]
    async fn 读请求会按_content_length_把体读全() {
        use tokio::io::AsyncWriteExt as _;
        // 构造一条"头与体分开到达"的请求：用 duplex 手动喂两段
        let (mut client, mut server) = tokio::io::duplex(4096);
        let writer = tokio::spawn(async move {
            client
                .write_all(b"POST /x HTTP/1.1\r\nContent-Length: 11\r\n\r\n")
                .await
                .unwrap();
            client.flush().await.unwrap();
            // 故意分两次写，模拟跨 TCP 段
            client.write_all(b"{\"a\":1,").await.unwrap();
            client.flush().await.unwrap();
            client.write_all(b"\"b\":2}").await.unwrap();
            client.flush().await.unwrap();
            // 保持连接开着，模拟对端还没关
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        });

        let req =
            tokio::time::timeout(std::time::Duration::from_secs(5), read_request(&mut server))
                .await
                .expect("不该超时")
                .expect("读请求");

        assert_eq!(req.method, "POST");
        assert_eq!(
            req.body, "{\"a\":1,\"b\":2}",
            "请求体必须按 Content-Length 读全，不能被 TCP 分段截断"
        );
        writer.abort();
    }

    #[tokio::test]
    async fn 发响应带完整的长度与关闭标记() {
        let (mut client, mut server) = tokio::io::duplex(4096);
        let writer = tokio::spawn(async move {
            send_json(&mut server, 404, "{\"e\":1}").await.unwrap();
        });
        let mut got = Vec::new();
        client.read_to_end(&mut got).await.unwrap();
        let text = String::from_utf8_lossy(&got);
        assert!(text.starts_with("HTTP/1.1 404 Not Found\r\n"), "{text}");
        assert!(text.contains("Content-Length: 7\r\n"), "{text}");
        assert!(text.contains("Connection: close\r\n"), "{text}");
        assert!(text.ends_with("{\"e\":1}"), "{text}");
        writer.await.unwrap();
    }
}
