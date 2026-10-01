//! 带缓冲的 HTTP/1.1 中继原语：读头、按框架读体、原样转发。
//!
//! # 为什么在 common 里而不是 `server/src/vhost.rs`
//!
//! 这套东西原先只长在服务端的虚拟主机里（服务端要解析 `Host` 才能路由）。
//! 后来客户端的 `http2http / http2https / https2http / https2https` 四个插件也需要
//! **一模一样的**能力：读一条请求 → 改头 → 转发 → 把响应搬回来。
//!
//! 复制一份的代价不是这 200 行代码，而是**以后修 HTTP 解析 bug 要修两遍**——
//! 而这里的 bug 全都不会崩，只会悄悄把请求转错（分块解析错、`Content-Length`
//! 少读一位、keep-alive 判反），是最不容易发现的一类。所以抽到公共层。
//!
//! # 与 [`crate::http1`] 的区别
//!
//! [`crate::http1`] 是**面板专用**的：它把请求体整个读进 `String`，够用就行。
//! 这里要转发**任意**流量（含二进制、含 chunked），所以按框架读、原样搬，
//! 不解释内容。
//!
//! # 两个刻意的取舍
//!
//! * 报文体在内存里中转，上限 [`MAX_BODY`]（32 MiB）—— 超过直接拒绝，
//!   而不是把内存打爆。真要传大文件请走 tcp 代理，那些是流式直通的。
//! * `HttpIo` 的 `stream` 是 `pub` 的：调用方需要直接往上写响应
//!   （比如"找不到代理"时回一个 404），也需要拿它做 TLS 握手。

use anyhow::{anyhow, bail, Result};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// 单条请求头 / 响应头允许的最大字节数。
pub const MAX_HEAD: usize = 64 * 1024;
/// 报文体在内存里中转的上限（超过则拒绝，避免大文件把内存打爆）。
pub const MAX_BODY: usize = 32 * 1024 * 1024;

/// 带缓冲的 HTTP 读写器（over 任意 AsyncRead/AsyncWrite）。
pub struct HttpIo<S> {
    /// 底层流。**故意公开**：调用方要直接写响应头、或拿它做 TLS 握手。
    pub stream: S,
    buf: Vec<u8>,
    pos: usize,
}

impl<S: AsyncRead + Unpin> HttpIo<S> {
    pub fn new(stream: S) -> Self {
        Self {
            stream,
            buf: Vec::new(),
            pos: 0,
        }
    }

    /// 用一段**已经读出来的**字节做缓冲前缀。
    ///
    /// 用途：工作连接握手后可能已经把紧随其后的业务数据读进了自己的缓冲区
    /// （`leftover`），丢掉它就会让第一条请求神秘地少一截。
    pub fn with_prefill(stream: S, prefill: Vec<u8>) -> Self {
        Self {
            stream,
            buf: prefill,
            pos: 0,
        }
    }

    /// 缓冲区里还没被取走的字节数。
    pub fn available(&self) -> usize {
        self.buf.len() - self.pos
    }

    /// 取走 n 字节（调用方保证 `n <= available()`）。
    pub fn take(&mut self, n: usize) -> Vec<u8> {
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

    /// 再读一段进缓冲，返回读到的字节数（0 = 对端关闭）。
    pub async fn fill(&mut self) -> Result<usize> {
        let mut chunk = [0u8; 16 * 1024];
        let n = self.stream.read(&mut chunk).await?;
        if n == 0 {
            return Ok(0);
        }
        self.buf.extend_from_slice(&chunk[..n]);
        Ok(n)
    }

    /// 读出一个 `\r\n\r\n` 结尾的头部块，返回行列表（不含结尾空行）。
    ///
    /// `Ok(None)` 表示还没读到任何字节对端就关了（干净的连接结束），
    /// 调用方据此安静收尾而不是报错。
    pub async fn read_head(&mut self) -> Result<Option<Vec<String>>> {
        Ok(self.read_head_raw().await?.map(|(_, lines)| lines))
    }

    /// 与 [`Self::read_head`] 相同，但**连原始字节一起给出来**。
    ///
    /// 需要原始字节的场合：tcpmux 的 `tcpmuxPassthrough` 要把 CONNECT 请求
    /// **原样**转给内网服务（由内网服务自己回应答）。用解析后的结构重新序列化
    /// 过一遍虽然语义等价，但会改掉头字段的原始间距 —— 对一个"我自己就是 HTTP
    /// 代理"的后端来说，没必要冒这个险。
    pub async fn read_head_raw(&mut self) -> Result<Option<(Vec<u8>, Vec<String>)>> {
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
                return Ok(Some((raw, lines)));
            }
            if self.available() > MAX_HEAD {
                bail!("HTTP 头部超过 {MAX_HEAD} 字节");
            }
            if self.fill().await? == 0 {
                return Ok(None);
            }
        }
    }

    /// 取走缓冲里**剩下的全部**字节并清空缓冲。
    ///
    /// 用途：中继阶段要直接对着底层流做双向对拷（那里不会再经过本缓冲），
    /// 所以之前预读进来的字节必须**显式**交给上游，否则第一条报文会缺开头。
    pub fn take_buffered(&mut self) -> Vec<u8> {
        let n = self.available();
        if n == 0 {
            return Vec::new();
        }
        self.take(n)
    }

    /// 精确读取 n 字节。
    pub async fn read_n(&mut self, n: usize) -> Result<Vec<u8>> {
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

    /// 按 chunked 编码读取完整报文体（**保留原始分块格式**，便于原样转发）。
    ///
    /// 保留原始格式很重要：自己重新分块就得处理 trailer 和分块扩展，
    /// 而下游服务对分块边界的假设五花八门。原样搬最安全。
    pub async fn read_chunked(&mut self) -> Result<Vec<u8>> {
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

    /// 读一行（不含 `\r\n`）。
    pub async fn read_line(&mut self) -> Result<String> {
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

/// 在 `hay` 里找 `needle` 第一次出现的位置。
pub fn find_subslice(hay: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || hay.len() < needle.len() {
        return None;
    }
    hay.windows(needle.len()).position(|w| w == needle)
}

/// 解析后的请求 / 响应头。
pub struct HeadParts {
    /// 起始行（请求行或状态行）。
    pub start_line: String,
    /// 头字段，**保留原有顺序**（顺序不敏感但保序能让 diff 好看、也少一层意外）。
    pub headers: Vec<(String, String)>,
}

impl HeadParts {
    pub fn parse(lines: &[String]) -> Result<Self> {
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

    pub fn get(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }

    pub fn set(&mut self, name: &str, value: &str) {
        for (k, v) in self.headers.iter_mut() {
            if k.eq_ignore_ascii_case(name) {
                *v = value.to_string();
                return;
            }
        }
        self.headers.push((name.to_string(), value.to_string()));
    }

    pub fn remove(&mut self, name: &str) {
        self.headers.retain(|(k, _)| !k.eq_ignore_ascii_case(name));
    }

    /// 起始行按空格切出来的第 n 段（请求行是 `方法 目标 版本`）。
    pub fn start_token(&self, n: usize) -> Option<&str> {
        self.start_line.split_whitespace().nth(n)
    }

    /// 序列化回字节（保留原有头顺序）。
    pub fn to_bytes(&self) -> Vec<u8> {
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

/// 这条请求/响应还打算复用连接吗（HTTP/1.1 默认复用，1.0 要显式 `keep-alive`）。
pub fn wants_keep_alive(parts: &HeadParts) -> bool {
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

/// 报文体长度。
///
/// * `Some(n)` —— 有 `Content-Length`，正好 n 字节；
/// * `None` —— 没有长度信息（读法由调用方按 chunked / 读到 EOF 决定）。
pub fn body_length(parts: &HeadParts) -> Option<usize> {
    parts.get("content-length")?.trim().parse().ok()
}

/// 这条报文用的是 chunked 传输编码吗。
pub fn is_chunked(parts: &HeadParts) -> bool {
    parts
        .get("transfer-encoding")
        .map(|v| v.to_ascii_lowercase().contains("chunked"))
        .unwrap_or(false)
}

/// 这个状态码/方法**不允许**有报文体（即使有 `Content-Length` 也不能读）。
///
/// 判错会怎样：`204` 后面跟的是下一条响应，把它当正文读走 = 整个连接错位。
pub fn has_no_body(parts: &HeadParts) -> bool {
    let line = parts.start_line.to_ascii_uppercase();
    if line.starts_with("HTTP/") {
        // 响应：1xx / 204 / 304 无正文
        let code = parts.start_token(1).and_then(|c| c.parse::<u16>().ok());
        return matches!(code, Some(c) if (100..200).contains(&c) || c == 204 || c == 304);
    }
    false
}

/// 从 `up` 精确搬 n 字节到 `down`。
pub async fn relay_fixed<S: AsyncRead + Unpin, W: AsyncWrite + Unpin>(
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

/// 把 `up` 一直搬到 EOF。
pub async fn relay_until_eof<S: AsyncRead + Unpin, W: AsyncWrite + Unpin>(
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

/// 把一条报文（请求或响应）的**体**按它的框架从 `up` 搬到 `down`。
///
/// 三种读法都在这里收口，省得每个调用方各写一遍、各漏一种：
/// 无正文（1xx/204/304）→ chunked → 定长 → 读到 EOF。
///
/// ★ 只适合**响应**。请求请用 [`relay_request_body`] —— 两者在"没有框架信息"
/// 时的语义**相反**，混用会死锁。
pub async fn relay_body<S: AsyncRead + Unpin, W: AsyncWrite + Unpin>(
    up: &mut HttpIo<S>,
    down: &mut W,
    head: &HeadParts,
) -> Result<()> {
    if has_no_body(head) {
        return Ok(());
    }
    if is_chunked(head) {
        let raw = up.read_chunked().await?;
        down.write_all(&raw).await?;
        return Ok(());
    }
    if let Some(n) = body_length(head) {
        if n > 0 {
            relay_fixed(up, down, n).await?;
        }
        return Ok(());
    }
    // 既没长度也不是 chunked：按"读到对端关闭"处理（HTTP/1.0 的老写法）。
    relay_until_eof(up, down).await
}

/// 转发**请求**体。
///
/// ★ 与 [`relay_body`] 的唯一区别，也是必须分开的原因：请求没有
/// "读到 EOF" 这种形态。一个请求既没有 `Content-Length` 也没有
/// `Transfer-Encoding: chunked`，就是**没有请求体**。
///
/// 如果这里误用 [`relay_body`] 的 EOF 分支，就会变成"等客户端把连接关了"，
/// 而客户端正等着我们的响应 —— 双方各等各的，直接死锁。
/// 这类 bug 的表现是"某些请求永远挂住"，加了 `Content-Length` 又好了，
/// 排查起来非常费劲。
pub async fn relay_request_body<S: AsyncRead + Unpin, W: AsyncWrite + Unpin>(
    up: &mut HttpIo<S>,
    down: &mut W,
    head: &HeadParts,
) -> Result<()> {
    if is_chunked(head) {
        let raw = up.read_chunked().await?;
        down.write_all(&raw).await?;
        return Ok(());
    }
    if let Some(n) = body_length(head) {
        if n > 0 {
            relay_fixed(up, down, n).await?;
        }
    }
    Ok(())
}

/// 这条请求是不是在请求协议升级（WebSocket 等）。
///
/// `Upgrade: xxx` 必须配 `Connection: upgrade` 才作数 —— 只看 `Upgrade`
/// 会被随手的 `Upgrade` 头带偏。
pub fn wants_upgrade(parts: &HeadParts) -> bool {
    if parts.get("upgrade").is_none() {
        return false;
    }
    parts
        .get("connection")
        .map(|v| {
            v.split(',')
                .any(|t| t.trim().eq_ignore_ascii_case("upgrade"))
        })
        .unwrap_or(false)
}

/// 逐跳（hop-by-hop）头：只对**这一段连接**有意义，转发时必须摘掉。
///
/// ★ `Transfer-Encoding` **不在此列**。转发时我们是把 chunked 的分块格式
/// 原样搬过去的，摘掉它下游就不知道该怎么解帧了。
pub const HOP_BY_HOP: &[&str] = &[
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailer",
    "upgrade",
];

/// `Connection: a, b` 里额外点名的字段同样是逐跳的。
pub fn connection_tokens(parts: &HeadParts) -> Vec<String> {
    parts
        .get("connection")
        .map(|v| {
            v.split(',')
                .map(|t| t.trim().to_string())
                .filter(|t| !t.is_empty())
                .collect()
        })
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::duplex;

    fn lines(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn 头部解析保留顺序并能读写字段() {
        let mut h = HeadParts::parse(&lines(&["GET /a HTTP/1.1", "Host: old", "X-A: 1"])).unwrap();
        assert_eq!(h.get("host"), Some("old"));
        h.set("Host", "new");
        assert_eq!(h.get("HOST"), Some("new"));
        h.set("X-B", "2");
        h.remove("x-a");
        let text = String::from_utf8(h.to_bytes()).unwrap();
        assert_eq!(text, "GET /a HTTP/1.1\r\nHost: new\r\nX-B: 2\r\n\r\n");
    }

    #[test]
    fn 起始行的第_n_段() {
        let h = HeadParts::parse(&lines(&["POST /x?y=1 HTTP/1.1", "Host: a"])).unwrap();
        assert_eq!(h.start_token(0), Some("POST"));
        assert_eq!(h.start_token(1), Some("/x?y=1"));
        assert_eq!(h.start_token(2), Some("HTTP/1.1"));
        assert_eq!(h.start_token(9), None);
    }

    #[test]
    fn keep_alive_的判定() {
        let ka = |v: &[&str]| HeadParts::parse(&lines(v)).unwrap();
        assert!(wants_keep_alive(&ka(&["GET / HTTP/1.1"])));
        assert!(!wants_keep_alive(&ka(&[
            "GET / HTTP/1.1",
            "Connection: close"
        ])));
        // 1.0 默认不复用
        assert!(!wants_keep_alive(&ka(&["GET / HTTP/1.0"])));
        assert!(wants_keep_alive(&ka(&[
            "GET / HTTP/1.0",
            "Connection: keep-alive"
        ])));
        // 大小写与逗号列表都要认
        assert!(!wants_keep_alive(&ka(&[
            "GET / HTTP/1.1",
            "Connection: TE, CLOSE"
        ])));
    }

    #[test]
    fn 无正文的状态码不能当有正文读() {
        let p = |s: &str| HeadParts::parse(&lines(&[s])).unwrap();
        assert!(has_no_body(&p("HTTP/1.1 100 Continue")));
        assert!(has_no_body(&p("HTTP/1.1 204 No Content")));
        assert!(has_no_body(&p("HTTP/1.1 304 Not Modified")));
        assert!(!has_no_body(&p("HTTP/1.1 200 OK")));
        // 请求行不该被误判成响应
        assert!(!has_no_body(&p("GET / HTTP/1.1")));
    }

    #[test]
    fn 体长与_chunked_的识别() {
        let p = HeadParts::parse(&lines(&[
            "POST / HTTP/1.1",
            "Content-Length: 12",
            "Transfer-Encoding: chunked",
        ]))
        .unwrap();
        assert_eq!(body_length(&p), Some(12));
        assert!(is_chunked(&p));
        assert_eq!(
            body_length(&HeadParts::parse(&lines(&["GET / HTTP/1.1"])).unwrap()),
            None
        );
    }

    #[tokio::test]
    async fn read_head_在空行处收手() {
        let (mut a, b) = duplex(256);
        a.write_all(b"GET / HTTP/1.1\r\nHost: x\r\n\r\nBODY")
            .await
            .unwrap();
        let mut io = HttpIo::new(b);
        let head = io.read_head().await.unwrap().unwrap();
        assert_eq!(head, lines(&["GET / HTTP/1.1", "Host: x"]));
        // 空行之后的字节必须留在缓冲里，不能被吃掉
        assert_eq!(io.available(), 4);
        assert_eq!(io.take(4), b"BODY".to_vec());
    }

    #[tokio::test]
    async fn read_head_对端直接关闭返回_none() {
        let (a, b) = duplex(64);
        drop(a);
        let mut io = HttpIo::new(b);
        assert!(io.read_head().await.unwrap().is_none());
    }

    #[tokio::test]
    async fn chunked_原样保留分块与_trailer() {
        let (mut a, b) = duplex(256);
        let raw = b"4;ext=1\r\nWiki\r\n5\r\npedia\r\n0\r\nX-T: 1\r\n\r\n";
        a.write_all(raw).await.unwrap();
        let mut io = HttpIo::new(b);
        assert_eq!(io.read_chunked().await.unwrap(), raw.to_vec());
    }

    #[tokio::test]
    async fn with_prefill_不会丢掉握手后残留的字节() {
        let (mut a, b) = duplex(256);
        a.write_all(b"Host: x\r\n\r\n").await.unwrap();
        let mut io = HttpIo::with_prefill(b, b"GET / HTTP/1.1\r\n".to_vec());
        let head = io.read_head().await.unwrap().unwrap();
        assert_eq!(head, lines(&["GET / HTTP/1.1", "Host: x"]));
    }

    #[tokio::test]
    async fn relay_body_按_content_length_精确搬运() {
        let (mut a, b) = duplex(256);
        a.write_all(b"hello worldNEXT").await.unwrap();
        let (mut out, mut sink) = duplex(256);
        let head = HeadParts::parse(&lines(&["POST / HTTP/1.1", "Content-Length: 11"])).unwrap();
        let mut up = HttpIo::new(b);
        relay_body(&mut up, &mut sink, &head).await.unwrap();
        drop(sink);
        let mut got = Vec::new();
        out.read_to_end(&mut got).await.unwrap();
        assert_eq!(got, b"hello world".to_vec(), "不能多搬 NEXT");
    }

    #[tokio::test]
    async fn relay_body_遇到_204_一个字节都不读() {
        let (mut a, b) = duplex(256);
        a.write_all(b"garbage").await.unwrap();
        let (mut out, mut sink) = duplex(256);
        let head = HeadParts::parse(&lines(&["HTTP/1.1 204 No Content"])).unwrap();
        let mut up = HttpIo::new(b);
        relay_body(&mut up, &mut sink, &head).await.unwrap();
        drop(sink);
        let mut got = Vec::new();
        out.read_to_end(&mut got).await.unwrap();
        assert!(got.is_empty(), "204 不能有正文");
        // 关键：后面的字节必须**原封不动留在流里** —— 当成正文读走会让整个连接错位，
        // 表现是"204 之后的下一条响应神秘消失"，极难排查。
        let mut rest = [0u8; 7];
        up.stream.read_exact(&mut rest).await.unwrap();
        assert_eq!(&rest, b"garbage");
    }
}
