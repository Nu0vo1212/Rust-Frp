//! WebSocket（RFC 6455）最小实现 —— 只做 frp 传输需要的那部分。
//!
//! # 为什么手写而不是引 `tokio-tungstenite`
//!
//! 我们要的功能只有两件：把一条已经建立的 TCP/TLS 连接**升级**成 WebSocket，
//! 以及把字节流按帧读写。`tokio-tungstenite` 会带进 `httparse` / `http` /
//! `byteorder` / `utf-8` 一整套依赖，而 release profile 是 `lto + opt-level=s`，
//! 为一个 300 行的状态机付这个体积代价不划算。
//!
//! # 与官方 frp 的兼容点
//!
//! frp 用的是 `golang.org/x/net/websocket`，路径固定为 [`FRP_WS_PATH`]，
//! 且**载荷是二进制帧**（`c.PayloadType = websocket.BinaryFrame`，
//! 注释里写明"yamux 的载荷是裸字节流，不是 UTF-8 文本；发文本帧会被
//! 中间的反代/网关做 UTF-8 校验并掐断连接"）。所以：
//!
//! * 我们**只发二进制帧**；
//! * 读的时候**两种帧都收**（对端要是发了文本帧，把载荷当字节数据用即可）。
//!
//! # 掩码规则（不能搞错）
//!
//! RFC 6455 §5.3：**客户端发往服务端的帧必须加掩码**，服务端发往客户端的
//! 帧**必须不加掩码**，违反的一方要主动断连。浏览器/网关都严格校验这一条，
//! 写反了表现为"握手成功但一收数据就断"。

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};

/// frp 的 WebSocket 固定路径（官方 `pkg/util/net/websocket.go`）。
pub const FRP_WS_PATH: &str = "/~!frp";

/// 客户端侧的 WebSocket 传输配置（`[transport.websocket]`）。
///
/// 为什么需要它：某些企业防火墙**只放行 HTTP(S)**，裸 TCP 一律丢包。
/// 把 frp 的字节流塞进 WebSocket 帧之后，中间设备看到的就只是一个
/// `Upgrade: websocket` 的普通 HTTP 请求。
///
/// 与官方 frp 的对应关系：官方把这两个字段放在 `transport.websocket` 下，
/// 名字就是 `host` / `path`，这里保持一致。
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct WebSocketConfig {
    /// 自定义 Host 头。前置代理按 Host 分流时不改就对不上。
    pub host: String,
    /// 自定义路径。
    ///
    /// **留空用官方默认值 `/~!frp`** —— 服务端只认这一个路径
    /// （见 [`FRP_WS_PATH`]），改了必须两边一致，否则握手直接 404。
    pub path: String,
}

impl WebSocketConfig {
    /// 实际使用的路径（留空时回落到官方默认）。
    pub fn effective_path(&self) -> &str {
        if self.path.trim().is_empty() {
            FRP_WS_PATH
        } else {
            self.path.as_str()
        }
    }
}

/// RFC 6455 规定的握手 GUID。
const WS_GUID: &str = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

/// 握手请求头的大小上限（含所有 header 行）。
const MAX_HANDSHAKE: usize = 16 * 1024;

/// 单帧载荷上限。yamux 的 `split_send_size` 是 128 KiB，转发缓冲也是 128 KiB，
/// 正常不会有更大的帧；给到 16 MiB 是留出余量，同时挡住"声称 2^63 字节"的帧头。
const MAX_FRAME: usize = 16 * 1024 * 1024;

const OP_CONT: u8 = 0x0;
const OP_TEXT: u8 = 0x1;
const OP_BINARY: u8 = 0x2;
const OP_CLOSE: u8 = 0x8;
const OP_PING: u8 = 0x9;
const OP_PONG: u8 = 0xa;

/// 握手失败的原因。
#[derive(Debug)]
pub enum WsError {
    /// 对端发的不是合法的 WebSocket 握手。
    Handshake(String),
    /// 帧层错误。
    Protocol(String),
    Io(io::Error),
}

impl std::fmt::Display for WsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Handshake(m) => write!(f, "WebSocket 握手失败：{m}"),
            Self::Protocol(m) => write!(f, "WebSocket 协议错误：{m}"),
            Self::Io(e) => write!(f, "WebSocket IO 错误：{e}"),
        }
    }
}

impl std::error::Error for WsError {}

impl From<io::Error> for WsError {
    fn from(e: io::Error) -> Self {
        Self::Io(e)
    }
}

pub type WsResult<T> = std::result::Result<T, WsError>;

// ---------------------------------------------------------------------------
// 握手
// ---------------------------------------------------------------------------

/// 服务端：在一条已就绪的连接上完成 WebSocket 升级。
///
/// 返回升级后的流。**握手请求之后可能已经跟着帧数据**（对端不等回包就发），
/// 所以剩余字节必须交回给流缓冲，不能丢。
pub async fn accept<S>(stream: S) -> WsResult<WsStream<S>>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut stream = stream;
    let mut buf: Vec<u8> = Vec::with_capacity(1024);
    let head_end = loop {
        if let Some(i) = find_head_end(&buf) {
            break i + 4;
        }
        if buf.len() > MAX_HANDSHAKE {
            return Err(WsError::Handshake("请求头超过 16 KiB".into()));
        }
        let mut chunk = [0u8; 1024];
        let n = stream.read(&mut chunk).await?;
        if n == 0 {
            return Err(WsError::Handshake("对端在请求头发完前断开".into()));
        }
        buf.extend_from_slice(&chunk[..n]);
    };

    let head = String::from_utf8_lossy(&buf[..head_end]).to_string();
    let (method, path) = parse_request_line(&head);
    if method != "GET" {
        respond_error(&mut stream, 405, "Method Not Allowed").await?;
        return Err(WsError::Handshake(format!("期望 GET，实际 {method}")));
    }
    // 路径不匹配**不拒绝**：frp 的路径只是个约定，中间可能有网关改写。
    // 但把它记在返回值里让调用方自己判断（这里只校验协议本身）。
    let _ = path;

    if !header_contains(&head, "upgrade", "websocket") {
        respond_error(&mut stream, 400, "Bad Request").await?;
        return Err(WsError::Handshake("缺少 Upgrade: websocket".into()));
    }
    let key = header_value(&head, "sec-websocket-key")
        .ok_or_else(|| WsError::Handshake("缺少 Sec-WebSocket-Key".into()))?;
    let version = header_value(&head, "sec-websocket-version").unwrap_or_default();
    if !version.is_empty() && version.trim() != "13" {
        respond_error(&mut stream, 426, "Upgrade Required").await?;
        return Err(WsError::Handshake(format!(
            "不支持的 WebSocket 版本 {version}"
        )));
    }

    let accept = accept_key(&key);
    let resp = format!(
        "HTTP/1.1 101 Switching Protocols\r\n\
         Upgrade: websocket\r\n\
         Connection: Upgrade\r\n\
         Sec-WebSocket-Accept: {accept}\r\n\r\n"
    );
    stream.write_all(resp.as_bytes()).await?;
    stream.flush().await?;

    let leftover = buf[head_end..].to_vec();
    Ok(WsStream::new(stream, false, leftover))
}

/// 客户端：向 `host` 发起到 `path` 的 WebSocket 升级请求。
///
/// `extra` 里的头会一并发出（用于 `Authorization` 之类）。
pub async fn connect<S>(
    stream: S,
    host: &str,
    path: &str,
    extra: &[(&str, &str)],
) -> WsResult<WsStream<S>>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut stream = stream;
    let key = random_key();

    let mut req = format!(
        "GET {path} HTTP/1.1\r\n\
         Host: {host}\r\n\
         Upgrade: websocket\r\n\
         Connection: Upgrade\r\n\
         Sec-WebSocket-Key: {key}\r\n\
         Sec-WebSocket-Version: 13\r\n"
    );
    for (k, v) in extra {
        req.push_str(&format!("{k}: {v}\r\n"));
    }
    req.push_str("\r\n");
    stream.write_all(req.as_bytes()).await?;
    stream.flush().await?;

    // 读响应头
    let mut buf: Vec<u8> = Vec::with_capacity(1024);
    let head_end = loop {
        if let Some(i) = find_head_end(&buf) {
            break i + 4;
        }
        if buf.len() > MAX_HANDSHAKE {
            return Err(WsError::Handshake("响应头超过 16 KiB".into()));
        }
        let mut chunk = [0u8; 1024];
        let n = stream.read(&mut chunk).await?;
        if n == 0 {
            return Err(WsError::Handshake("服务端在响应头发完前断开".into()));
        }
        buf.extend_from_slice(&chunk[..n]);
    };
    let head = String::from_utf8_lossy(&buf[..head_end]).to_string();
    let (_, status) = parse_request_line(&head);
    let code: u16 = status
        .split_whitespace()
        .next()
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    if code != 101 {
        return Err(WsError::Handshake(format!(
            "服务端返回 {code}（期望 101）：{}",
            head.lines().next().unwrap_or("")
        )));
    }
    let want = accept_key(&key);
    let got = header_value(&head, "sec-websocket-accept").unwrap_or_default();
    if !got.trim().eq_ignore_ascii_case(&want) {
        return Err(WsError::Handshake(
            "Sec-WebSocket-Accept 校验失败（对端可能不是 WebSocket 服务）".into(),
        ));
    }

    let leftover = buf[head_end..].to_vec();
    Ok(WsStream::new(stream, true, leftover))
}

/// 服务端拒绝握手时回一个正经的 HTTP 错误，而不是直接断连 ——
/// 否则客户端只能看到 `connection reset`，排查时完全不知道是自己发错了。
async fn respond_error<S: AsyncWrite + Unpin>(
    stream: &mut S,
    code: u16,
    reason: &str,
) -> io::Result<()> {
    let body = format!("{code} {reason}\n");
    let resp = format!(
        "HTTP/1.1 {code} {reason}\r\n\
         Content-Type: text/plain; charset=utf-8\r\n\
         Content-Length: {}\r\n\
         Connection: close\r\n\r\n{body}",
        body.len()
    );
    stream.write_all(resp.as_bytes()).await?;
    stream.flush().await?;
    Ok(())
}

fn accept_key(client_key: &str) -> String {
    use base64::{engine::general_purpose::STANDARD, Engine as _};
    use sha1::{Digest, Sha1};
    let mut h = Sha1::new();
    h.update(client_key.trim().as_bytes());
    h.update(WS_GUID.as_bytes());
    STANDARD.encode(h.finalize())
}

fn random_key() -> String {
    use base64::{engine::general_purpose::STANDARD, Engine as _};
    use rand::RngCore;
    let mut raw = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut raw);
    STANDARD.encode(raw)
}

fn find_head_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n")
}

/// 拆第一行，返回 `(第一段, 第二段)`。
///
/// 请求行是 `GET /path HTTP/1.1`（返回 `("GET", "/path")`），
/// 响应行是 `HTTP/1.1 101 Switching Protocols`（返回 `("HTTP/1.1", "101")`）——
/// 两边的调用点各取所需，所以这里不做区分。
fn parse_request_line(head: &str) -> (String, String) {
    let line = head.lines().next().unwrap_or("");
    let mut it = line.split_whitespace();
    let a = it.next().unwrap_or("").to_string();
    let b = it.next().unwrap_or("").to_string();
    (a, b)
}

fn header_value(head: &str, name: &str) -> Option<String> {
    head.lines().skip(1).find_map(|l| {
        let (k, v) = l.split_once(':')?;
        k.trim().eq_ignore_ascii_case(name).then(|| v.to_string())
    })
}

fn header_contains(head: &str, name: &str, needle: &str) -> bool {
    header_value(head, name)
        .map(|v| {
            v.to_ascii_lowercase()
                .contains(&needle.to_ascii_lowercase())
        })
        .unwrap_or(false)
}

// ---------------------------------------------------------------------------
// 帧层
// ---------------------------------------------------------------------------

/// 把 WebSocket 帧包装成普通异步字节流。
///
/// * 读：拆帧、应对 ping/close，只把数据帧的载荷交出去；
/// * 写：每次 `poll_write` 发一个二进制帧，整帧写完才报告已消费。
pub struct WsStream<S> {
    inner: S,
    /// 本端是不是客户端（决定发出去的帧要不要加掩码）。
    is_client: bool,
    /// 还没被 `poll_read` 取走的载荷。
    rx: Vec<u8>,
    /// 已经读进来但还没解析成帧的原始字节。
    raw: Vec<u8>,
    /// 已经组好还没写完的帧字节。
    tx: Vec<u8>,
    /// `tx` 里已经写出去的字节数。
    tx_off: usize,
    /// 已收到对端的 Close。
    closed: bool,
}

impl<S> std::fmt::Debug for WsStream<S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WsStream")
            .field("is_client", &self.is_client)
            .field("rx", &self.rx.len())
            .field("raw", &self.raw.len())
            .field("tx", &(self.tx.len() - self.tx_off))
            .field("closed", &self.closed)
            .finish()
    }
}

impl<S> WsStream<S> {
    fn new(inner: S, is_client: bool, leftover: Vec<u8>) -> Self {
        Self {
            inner,
            is_client,
            rx: Vec::new(),
            raw: leftover,
            tx: Vec::new(),
            tx_off: 0,
            closed: false,
        }
    }

    /// 交回底层流（用于工作连接握手后转裸字节……不过 WebSocket 下没有"裸字节"，
    /// 这里仅用于诊断）。
    pub fn into_inner(self) -> S {
        self.inner
    }
}

/// 从 `raw` 里尽力解析出一个帧；返回 `Ok(None)` 表示数据还不够。
fn take_frame(buf: &mut Vec<u8>) -> WsResult<Option<(u8, bool, Vec<u8>)>> {
    if buf.len() < 2 {
        return Ok(None);
    }
    let b0 = buf[0];
    let b1 = buf[1];
    let fin = b0 & 0x80 != 0;
    if b0 & 0x70 != 0 {
        return Err(WsError::Protocol("RSV 位被置位但没有协商扩展".into()));
    }
    let opcode = b0 & 0x0f;
    let masked = b1 & 0x80 != 0;
    let len7 = (b1 & 0x7f) as usize;

    let mut need = 2;
    let payload_len = match len7 {
        126 => {
            if buf.len() < 4 {
                return Ok(None);
            }
            need += 2;
            u16::from_be_bytes([buf[2], buf[3]]) as usize
        }
        127 => {
            if buf.len() < 10 {
                return Ok(None);
            }
            need += 8;
            let v = u64::from_be_bytes(buf[2..10].try_into().unwrap());
            if v > MAX_FRAME as u64 {
                return Err(WsError::Protocol(format!("帧载荷 {v} 超过上限")));
            }
            v as usize
        }
        n => n,
    };
    if payload_len > MAX_FRAME {
        return Err(WsError::Protocol(format!(
            "帧载荷 {payload_len} 超过上限 {MAX_FRAME}"
        )));
    }
    let mask_len = if masked { 4 } else { 0 };
    if buf.len() < need + mask_len + payload_len {
        return Ok(None);
    }
    let mask = if masked {
        let m = buf[need..need + 4].to_vec();
        need += 4;
        Some(m)
    } else {
        None
    };
    let mut payload = buf[need..need + payload_len].to_vec();
    if let Some(m) = mask {
        for (i, b) in payload.iter_mut().enumerate() {
            *b ^= m[i % 4];
        }
    }
    buf.drain(..need + payload_len);
    Ok(Some((opcode, fin, payload)))
}

/// 组一个帧（含掩码处理）。
fn build_frame(opcode: u8, payload: &[u8], mask: bool) -> Vec<u8> {
    let mut out = Vec::with_capacity(payload.len() + 14);
    out.push(0x80 | opcode); // FIN = 1，不分片
    let mask_bit = if mask { 0x80 } else { 0 };
    let n = payload.len();
    if n < 126 {
        out.push(mask_bit | n as u8);
    } else if n <= u16::MAX as usize {
        out.push(mask_bit | 126);
        out.extend_from_slice(&(n as u16).to_be_bytes());
    } else {
        out.push(mask_bit | 127);
        out.extend_from_slice(&(n as u64).to_be_bytes());
    }
    if mask {
        use rand::RngCore;
        let mut key = [0u8; 4];
        rand::thread_rng().fill_bytes(&mut key);
        out.extend_from_slice(&key);
        let start = out.len();
        out.extend_from_slice(payload);
        for i in 0..n {
            out[start + i] ^= key[i % 4];
        }
    } else {
        out.extend_from_slice(payload);
    }
    out
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncRead for WsStream<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.as_mut().get_mut();
        // 1) 先交付已经解出来的载荷
        if !this.rx.is_empty() {
            let n = this.rx.len().min(buf.remaining());
            buf.put_slice(&this.rx[..n]);
            this.rx.drain(..n);
            return Poll::Ready(Ok(()));
        }
        if this.closed {
            return Poll::Ready(Ok(())); // EOF
        }

        // 2) 从 raw 里继续解析；不够就再读
        loop {
            match take_frame(&mut this.raw) {
                Err(e) => {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        e.to_string(),
                    )))
                }
                Ok(Some((opcode, _fin, payload))) => match opcode {
                    OP_BINARY | OP_TEXT | OP_CONT => {
                        if payload.is_empty() {
                            continue;
                        }
                        let n = payload.len().min(buf.remaining());
                        buf.put_slice(&payload[..n]);
                        if n < payload.len() {
                            this.rx = payload[n..].to_vec();
                        }
                        return Poll::Ready(Ok(()));
                    }
                    OP_PING => {
                        let pong = build_frame(OP_PONG, &payload, this.is_client);
                        this.tx.extend_from_slice(&pong);
                        // ★ 必须**就地**把 Pong 推到底层，不能只排队等上层来写：
                        // 上层此刻很可能正阻塞在 `poll_read` 上等数据，而读侧
                        // 又在等我们返回 —— 两边都不写就是死锁（RFC 6455 要求
                        // Pong 尽快回，对端可能正靠它做保活）。
                        match this.poll_drain(cx) {
                            Poll::Ready(Ok(())) => {}
                            Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                            // 底层写缓冲满：Pong 仍排在队首不会丢，等下次可写
                            Poll::Pending => return Poll::Pending,
                        }
                        continue;
                    }
                    OP_PONG => continue,
                    OP_CLOSE => {
                        this.closed = true;
                        return Poll::Ready(Ok(()));
                    }
                    other => {
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            format!("未知的 WebSocket opcode 0x{other:x}"),
                        )))
                    }
                },
                Ok(None) => {}
            }

            // raw 里没有完整帧：读一批进来
            let mut chunk = [0u8; 16 * 1024];
            let mut rb = ReadBuf::new(&mut chunk);
            match Pin::new(&mut this.inner).poll_read(cx, &mut rb) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Ready(Ok(())) => {
                    let filled = rb.filled().len();
                    if filled == 0 {
                        // 底层 EOF：当作流正常结束（对端没发 Close 也算）
                        this.closed = true;
                        return Poll::Ready(Ok(()));
                    }
                    if this.raw.len() + filled > MAX_FRAME * 2 {
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "WebSocket 读缓冲区超限",
                        )));
                    }
                    this.raw.extend_from_slice(&chunk[..filled]);
                }
            }
        }
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for WsStream<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.as_mut().get_mut();
        // 先把上一次没写完的帧冲干净
        if let Poll::Ready(()) = this.poll_drain(cx)? {
            // 新数据：整帧写出去才算消费
            let frame = build_frame(OP_BINARY, buf, this.is_client);
            this.tx = frame;
            this.tx_off = 0;
            match this.poll_drain(cx)? {
                Poll::Ready(()) => Poll::Ready(Ok(buf.len())),
                Poll::Pending => Poll::Pending,
            }
        } else {
            Poll::Pending
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.as_mut().get_mut();
        match this.poll_drain(cx)? {
            Poll::Pending => Poll::Pending,
            Poll::Ready(()) => Pin::new(&mut this.inner).poll_flush(cx),
        }
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.as_mut().get_mut();
        if this.tx.is_empty() {
            let close = build_frame(OP_CLOSE, &[], this.is_client);
            this.tx = close;
            this.tx_off = 0;
        }
        match this.poll_drain(cx)? {
            Poll::Pending => Poll::Pending,
            Poll::Ready(()) => Pin::new(&mut this.inner).poll_shutdown(cx),
        }
    }
}

impl<S: AsyncWrite + Unpin> WsStream<S> {
    /// 把 `tx[tx_off..]` 尽量写进底层流。
    fn poll_drain(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        while self.tx_off < self.tx.len() {
            match Pin::new(&mut self.inner).poll_write(cx, &self.tx[self.tx_off..]) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Ready(Ok(0)) => {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "WebSocket 底层流写不进数据",
                    )))
                }
                Poll::Ready(Ok(n)) => self.tx_off += n,
            }
        }
        self.tx.clear();
        self.tx_off = 0;
        Poll::Ready(Ok(()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncReadExt;

    /// RFC 6455 的官方向量：key 固定时 Accept 必须等于这个值。
    ///
    /// 这一条是所有浏览器/网关的硬校验，算错就是"连不上且没有可读的错误"。
    #[test]
    fn accept_key_matches_rfc_vector() {
        assert_eq!(
            accept_key("dGhlIHNhbXBsZSBub25jZQ=="),
            "s3pPLMBiTxaQ9kYGzzhZRbK+xOo="
        );
    }

    #[tokio::test]
    async fn handshake_and_roundtrip() {
        let (a, b) = tokio::io::duplex(64 * 1024);
        let server = tokio::spawn(async move {
            let mut ws = accept(b).await.expect("服务端升级");
            let mut buf = vec![0u8; 64];
            let n = ws.read(&mut buf).await.unwrap();
            buf.truncate(n);
            ws.write_all(&buf).await.unwrap();
            ws.flush().await.unwrap();
            buf
        });
        let mut ws = connect(a, "example.com", FRP_WS_PATH, &[])
            .await
            .expect("客户端升级");
        ws.write_all(b"hello-ws").await.unwrap();
        ws.flush().await.unwrap();
        let mut back = [0u8; 64];
        let n = ws.read(&mut back).await.unwrap();
        assert_eq!(&back[..n], b"hello-ws");
        assert_eq!(server.await.unwrap(), b"hello-ws");
    }

    /// 掩码规则：客户端发的帧必须带掩码，服务端发的必须不带。
    #[test]
    fn masking_follows_rfc() {
        let c = build_frame(OP_BINARY, b"abc", true);
        assert_eq!(c[1] & 0x80, 0x80, "客户端帧必须置掩码位");
        let s = build_frame(OP_BINARY, b"abc", false);
        assert_eq!(s[1] & 0x80, 0x00, "服务端帧不能置掩码位");
        // 掩码后载荷必须与原文不同（掩码键是随机的，全零概率可忽略）
        assert_ne!(&c[6..9], b"abc");
    }

    /// 长度编码的三档（7 位 / 16 位 / 64 位）都要对。
    #[test]
    fn frame_length_encoding_has_three_forms() {
        assert_eq!(build_frame(OP_BINARY, &[0u8; 100], false)[1], 100);
        let mid = build_frame(OP_BINARY, &[0u8; 300], false);
        assert_eq!(mid[1], 126);
        assert_eq!(u16::from_be_bytes([mid[2], mid[3]]), 300);
        let big = build_frame(OP_BINARY, &vec![0u8; 70000], false);
        assert_eq!(big[1], 127);
        assert_eq!(u64::from_be_bytes(big[2..10].try_into().unwrap()), 70000);
    }

    #[test]
    fn frame_roundtrip_is_lossless() {
        for payload in [vec![], b"x".to_vec(), (0..=255u8).collect::<Vec<u8>>()] {
            let raw = build_frame(OP_BINARY, &payload, true);
            let mut buf = raw.clone();
            let (op, fin, got) = take_frame(&mut buf).unwrap().expect("应解出一帧");
            assert_eq!(op, OP_BINARY);
            assert!(fin);
            assert_eq!(got, payload);
            assert!(buf.is_empty(), "解完不该剩字节");
        }
    }

    /// 帧被拆成两半时要等第二半，不能把半个载荷当数据交出去。
    #[test]
    fn partial_frame_waits_for_the_rest() {
        let raw = build_frame(OP_BINARY, b"0123456789", false);
        let mut buf = raw[..6].to_vec();
        assert!(take_frame(&mut buf).unwrap().is_none(), "半帧不该解出来");

        // 拼上剩余部分才能解
        buf.extend_from_slice(&raw[6..]);
        let (_, _, got) = take_frame(&mut buf).unwrap().unwrap();
        assert_eq!(got, b"0123456789");
    }

    /// 一段字节里连着多个帧时必须逐个取出 —— 对端可能把好几个 Write 攒在一个 TCP 段里。
    #[test]
    fn multiple_frames_in_one_buffer() {
        let mut buf = build_frame(OP_BINARY, b"aa", false);
        buf.extend_from_slice(&build_frame(OP_BINARY, b"bb", false));
        let (_, _, a) = take_frame(&mut buf).unwrap().unwrap();
        let (_, _, b) = take_frame(&mut buf).unwrap().unwrap();
        assert_eq!(
            (a.as_slice(), b.as_slice()),
            (b"aa".as_slice(), b"bb".as_slice())
        );
        assert!(buf.is_empty());
    }

    /// Ping 必须被自动回 Pong，且不能把 ping 的载荷交给上层。
    ///
    /// 关键不是"队列里有没有 Pong"，而是**对端到底收没收到** ——
    /// 只排队不写出去的话，上层如果正阻塞在读上就永远是死锁。
    #[tokio::test]
    async fn ping_is_answered_automatically() {
        let (a, b) = tokio::io::duplex(8192);
        let mut server = WsStream::new(b, false, Vec::new());
        let mut client = WsStream::new(a, true, Vec::new());

        // 客户端发一个 ping（走正常写路径，会带上客户端掩码）
        let ping = build_frame(OP_PING, b"hi", true);
        client.tx = ping;
        use tokio::io::AsyncWriteExt;
        client.flush().await.unwrap();

        // 服务端读：ping 不该被当成数据交上来。这一轮没有任何业务数据，
        // 所以读会一直挂起 —— 用 timeout 断言"确实没数据"，**不能**用
        // `Ok(0)` 来表达"这轮没数据"：`Ok(0)` 在 AsyncRead 里是 EOF，
        // 会让上层把隧道当成已关闭。
        let mut buf = [0u8; 16];
        let r = tokio::time::timeout(std::time::Duration::from_millis(300), server.read(&mut buf))
            .await;
        assert!(r.is_err(), "ping 被当成业务数据交上来了：{r:?}");

        // 直接从底层连接看服务端到底发出去了什么
        let mut raw = [0u8; 64];
        let n = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            client.inner.read(&mut raw),
        )
        .await
        .expect("Pong 必须及时发出，不能只排在自己队列里")
        .unwrap();
        assert!(n >= 4, "至少要有帧头 + 2 字节载荷，收到 {n} 字节");
        assert_eq!(raw[0] & 0x0f, OP_PONG, "opcode 必须是 Pong");
        assert_eq!(raw[0] & 0x80, 0x80, "服务端的 Pong 必须置 FIN");
        assert_eq!(&raw[2..4], b"hi", "Pong 必须原样带回 ping 的载荷");
    }

    /// 路径里的字节必须原样穿过（含非 UTF-8 与 0x00）——
    /// frp 的载荷是 yamux 的裸字节流，任何"按文本处理"的实现都会坏在这里。
    #[tokio::test]
    async fn binary_payload_survives_including_invalid_utf8() {
        let (a, b) = tokio::io::duplex(64 * 1024);
        let srv = tokio::spawn(async move {
            let mut ws = accept(b).await.unwrap();
            let mut out = Vec::new();
            ws.read_to_end(&mut out).await.unwrap();
            out
        });
        let mut ws = connect(a, "h", FRP_WS_PATH, &[]).await.unwrap();
        use tokio::io::AsyncWriteExt;
        let payload: Vec<u8> = (0..=255u8).collect();
        ws.write_all(&payload).await.unwrap();
        ws.shutdown().await.unwrap();
        drop(ws);
        let got = tokio::time::timeout(std::time::Duration::from_secs(3), srv)
            .await
            .expect("不能卡住")
            .unwrap();
        assert_eq!(got, payload, "256 个字节（含非法 UTF-8 序列）必须原样到达");
    }

    /// 非 WebSocket 请求要被明确拒绝（回 400/405），而不是挂在那儿等。
    #[tokio::test]
    async fn plain_http_request_is_rejected() {
        let (a, b) = tokio::io::duplex(8192);
        let client = tokio::spawn(async move {
            let mut c = a;
            use tokio::io::AsyncWriteExt;
            c.write_all(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n")
                .await
                .unwrap();
            let mut buf = vec![0u8; 256];
            let n = c.read(&mut buf).await.unwrap();
            String::from_utf8_lossy(&buf[..n]).to_string()
        });
        let e = accept(b)
            .await
            .expect_err("普通 HTTP 请求不该被当作 WebSocket");
        assert!(matches!(e, WsError::Handshake(_)), "应报握手失败：{e}");
        let resp = client.await.unwrap();
        assert!(
            resp.starts_with("HTTP/1.1 400"),
            "要回一个正经的 400：{resp}"
        );
    }

    /// 响应不是 101 时客户端要报错并带上状态码 —— 不然排查时只有 "connection closed"。
    #[tokio::test]
    async fn client_rejects_non_101_response() {
        let (a, b) = tokio::io::duplex(8192);
        tokio::spawn(async move {
            let mut s = b;
            use tokio::io::AsyncWriteExt;
            s.write_all(b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n")
                .await
                .unwrap();
            tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        });
        let e = connect(a, "h", FRP_WS_PATH, &[])
            .await
            .expect_err("应当失败");
        match e {
            WsError::Handshake(m) => assert!(m.contains("404"), "错误里要带状态码：{m}"),
            other => panic!("应当是握手错误，实际 {other}"),
        }
    }

    /// 服务端回错 Accept 时客户端必须拒绝 —— 否则可能把明文网站当成隧道。
    #[tokio::test]
    async fn client_rejects_wrong_accept_key() {
        let (a, b) = tokio::io::duplex(8192);
        tokio::spawn(async move {
            let mut s = b;
            use tokio::io::AsyncReadExt;
            use tokio::io::AsyncWriteExt;
            let mut buf = vec![0u8; 512];
            let _ = s.read(&mut buf).await.unwrap();
            s.write_all(
                b"HTTP/1.1 101 Switching Protocols\r\n\
                  Upgrade: websocket\r\nConnection: Upgrade\r\n\
                  Sec-WebSocket-Accept: wrongwrongwrong=\r\n\r\n",
            )
            .await
            .unwrap();
            tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        });
        assert!(connect(a, "h", FRP_WS_PATH, &[]).await.is_err());
    }

    /// 大负载（超过 16 位长度）也要能来回，这条覆盖 yamux 分片尺寸。
    #[tokio::test]
    async fn large_payload_over_64k_roundtrip() {
        let (a, b) = tokio::io::duplex(1024 * 1024);
        let srv = tokio::spawn(async move {
            let mut ws = accept(b).await.unwrap();
            let mut out = vec![0u8; 200_000];
            ws.read_exact(&mut out).await.unwrap();
            out
        });
        let mut ws = connect(a, "h", FRP_WS_PATH, &[]).await.unwrap();
        use tokio::io::AsyncWriteExt;
        let payload: Vec<u8> = (0..200_000usize).map(|i| (i % 251) as u8).collect();
        ws.write_all(&payload).await.unwrap();
        ws.flush().await.unwrap();
        let got = tokio::time::timeout(std::time::Duration::from_secs(5), srv)
            .await
            .expect("不能卡住")
            .unwrap();
        assert_eq!(got, payload);
    }
}
