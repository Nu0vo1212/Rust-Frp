//! frp v2 连接：帧读写、明文/加密阶段切换、握手流程。

use anyhow::{anyhow, bail, Result};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use super::stream::BoxStream;

use crate::util::now_unix_secs;

use super::crypto::{derive_control_keys, transcript_hash, AeadReader, AeadWriter};
use super::msg;
use super::msg::{FrpMessage, Login, LoginResp, NewVisitorConn, NewWorkConn, StartWorkConn};
use super::wire::{
    self, ClientHello, ServerHello, FRAME_CLIENT_HELLO, FRAME_MESSAGE, FRAME_SERVER_HELLO, MAGIC_V2,
};

/// 缓冲区上限，避免对端恶意灌数据。
const MAX_BUFFER: usize = 8 * 1024 * 1024;

/// 一条 frp v2 连接。
///
/// 握手阶段为明文，握手成功后调用 [`FrpConn::upgrade`] 切换为 AES-256-GCM 帧流。
pub struct FrpConn {
    stream: BoxStream,
    /// 从套接字读到的原始字节（加密阶段为密文）。
    raw: Vec<u8>,
    /// 解密后的明文（仅加密阶段使用）。
    plain: Vec<u8>,
    writer: Option<AeadWriter>,
    reader: Option<AeadReader>,
    /// UDP 报文用二进制编码（v2 握手协商结果），默认 JSON。
    udp_binary: bool,
}

impl FrpConn {
    pub fn new(stream: BoxStream) -> Self {
        Self {
            stream,
            raw: Vec::new(),
            plain: Vec::new(),
            writer: None,
            reader: None,
            udp_binary: false,
        }
    }

    /// 设置 UDP 报文编码（由握手协商结果决定）。
    pub fn set_udp_codec(&mut self, binary: bool) {
        self.udp_binary = binary;
    }

    pub fn udp_codec_is_binary(&self) -> bool {
        self.udp_binary
    }


    /// 写入 v2 魔术字（客户端必须先发）。
    pub async fn write_magic(&mut self) -> Result<()> {
        self.stream.write_all(MAGIC_V2).await?;
        self.stream.flush().await?;
        Ok(())
    }

    /// 服务端探测魔术字；不匹配则返回 false（说明不是 frp v2 客户端）。
    pub async fn peek_magic(&mut self) -> Result<bool> {
        let mut head = [0u8; MAGIC_V2.len()];
        self.stream.read_exact(&mut head).await?;
        Ok(head == MAGIC_V2)
    }

    /// 切换为加密帧流。
    pub fn upgrade(&mut self, read_key: Vec<u8>, write_key: Vec<u8>) -> Result<()> {
        self.writer = Some(AeadWriter::new(&write_key)?);
        self.reader = Some(AeadReader::new(&read_key)?);
        Ok(())
    }

    pub fn is_encrypted(&self) -> bool {
        self.writer.is_some()
    }

    /// 写入一个帧。
    pub async fn write_frame(&mut self, frame_type: u16, payload: &[u8]) -> Result<()> {
        let raw = wire::encode_frame(frame_type, payload);
        match self.writer.as_mut() {
            Some(w) => {
                let enc = w.seal(&raw)?;
                self.stream.write_all(&enc).await?;
            }
            None => self.stream.write_all(&raw).await?,
        }
        self.stream.flush().await?;
        Ok(())
    }

    /// 读取一个帧；对端干净关闭时返回 `Ok(None)`。
    pub async fn read_frame(&mut self) -> Result<Option<(u16, Vec<u8>)>> {
        loop {
            {
                let buf = if self.reader.is_some() {
                    &mut self.plain
                } else {
                    &mut self.raw
                };
                if let Some(frame) = take_frame(buf)? {
                    return Ok(Some(frame));
                }
            }
            if !self.fill().await? {
                return Ok(None);
            }
        }
    }

    /// 发送一条消息。
    ///
    /// UDP 报文（`UdpPacket`）在协商为 binary codec 时会改用二进制编码，
    /// 与官方 frp 的 `V2BinaryUDPPacketReadWriter` 保持一致。
    pub async fn send_msg(&mut self, m: &FrpMessage) -> Result<()> {
        if self.udp_binary {
            if let FrpMessage::UdpPacket(pkt) = m {
                let body = msg::encode_udp_binary(pkt)?;
                let mut payload = Vec::with_capacity(2 + body.len());
                payload.extend_from_slice(&msg::TYPE_UDP_PACKET_BINARY.to_be_bytes());
                payload.extend_from_slice(&body);
                return self.write_frame(FRAME_MESSAGE, &payload).await;
            }
        }
        let payload = m.encode()?;
        self.write_frame(FRAME_MESSAGE, &payload).await
    }

    /// 优雅关闭：先 flush，再对底层流 shutdown。
    ///
    /// 用于「回一条错误响应就断开」的场景（如 visitor 被拒）：
    /// 直接 drop 会让 yamux 流以 RST 收场，对端只能看到 `connection reset`，
    /// 读不到我们刚写进去的 error 文本。
    pub async fn shutdown(&mut self) -> Result<()> {
        use tokio::io::AsyncWriteExt;
        self.stream.flush().await.ok();
        self.stream.shutdown().await.ok();
        Ok(())
    }

    /// 接收一条消息。
    pub async fn recv_msg(&mut self) -> Result<Option<FrpMessage>> {
        match self.read_frame().await? {
            Some((ft, payload)) => {
                if ft != FRAME_MESSAGE {
                    bail!("期望消息帧({FRAME_MESSAGE})，实际收到帧类型 {ft}");
                }
                if payload.len() < 2 {
                    bail!("消息帧负载过短");
                }
                let type_id = u16::from_be_bytes([payload[0], payload[1]]);
                if type_id == msg::TYPE_UDP_PACKET_BINARY {
                    let pkt = msg::decode_udp_binary(&payload[2..])?;
                    return Ok(Some(FrpMessage::UdpPacket(pkt)));
                }
                Ok(Some(FrpMessage::decode(type_id, &payload[2..])?))
            }
            None => Ok(None),
        }
    }

    /// 从套接字补数据；返回 false 表示 EOF。
    async fn fill(&mut self) -> Result<bool> {
        let mut chunk = [0u8; 16 * 1024];
        let n = self.stream.read(&mut chunk).await?;
        if n == 0 {
            return Ok(false);
        }
        if self.raw.len() + n > MAX_BUFFER {
            bail!("接收缓冲区超限");
        }
        self.raw.extend_from_slice(&chunk[..n]);
        if let Some(rd) = self.reader.as_mut() {
            while let Some(pt) = rd.open(&mut self.raw)? {
                self.plain.extend_from_slice(&pt);
            }
        }
        Ok(true)
    }

    /// 交回底层 BoxStream 以及**尚未消费**的残留字节。
    ///
    /// 工作连接握手完成后要转原始字节流转发，残留字节必须交给调用方，
    /// 否则会丢掉用户已经发来的第一笔数据。
    pub fn into_stream(mut self) -> (BoxStream, Vec<u8>) {
        let leftover = if self.reader.is_some() {
            std::mem::take(&mut self.plain)
        } else {
            std::mem::take(&mut self.raw)
        };
        (self.stream, leftover)
    }
}

/// 从缓冲区里切出一个完整帧（`8 字节头 + payload`）。
fn take_frame(buf: &mut Vec<u8>) -> Result<Option<(u16, Vec<u8>)>> {
    if buf.len() < 8 {
        return Ok(None);
    }
    let frame_type = u16::from_be_bytes([buf[0], buf[1]]);
    let flags = u16::from_be_bytes([buf[2], buf[3]]);
    if flags != 0 {
        bail!("不支持的帧 flags: {flags}");
    }
    let len = u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]) as usize;
    if len > wire::MAX_FRAME_PAYLOAD {
        bail!("帧负载 {} 超过上限 {}", len, wire::MAX_FRAME_PAYLOAD);
    }
    if buf.len() < 8 + len {
        return Ok(None);
    }
    let payload = buf[8..8 + len].to_vec();
    buf.drain(..8 + len);
    Ok(Some((frame_type, payload)))
}

// ---------------------------------------------------------------------------
// 客户端握手
// ---------------------------------------------------------------------------

/// 客户端建立控制连接，返回 `(连接, run_id)`。
pub async fn client_handshake(
    stream: BoxStream,
    token: &str,
    client_id: &str,
    user: &str,
    pool_count: i32,
) -> Result<(FrpConn, String, bool)> {
    let mut conn = FrpConn::new(stream);
    conn.write_magic().await?;

    let hello = wire::new_client_hello("tcp", false, false);
    let hello_payload = serde_json::to_vec(&hello)?;
    conn.write_frame(FRAME_CLIENT_HELLO, &hello_payload).await?;

    let ts = now_unix_secs() as i64;
    conn.send_msg(&FrpMessage::Login(Login {
        version: format!("rustunnel/{}", env!("CARGO_PKG_VERSION")),
        hostname: crate::util::hostname(),
        os: std::env::consts::OS.to_string(),
        arch: std::env::consts::ARCH.to_string(),
        // 官方 frps 用 Login.User 匹配 stcp/xtcp 的 allow_users 白名单
        user: user.to_string(),
        privilege_key: msg::auth_key(token, ts),
        timestamp: ts,
        client_id: client_id.to_string(),
        pool_count,
        ..Default::default()
    }))
    .await?;

    // 1) ServerHello
    let (ft, sh_payload) = conn
        .read_frame()
        .await?
        .ok_or_else(|| anyhow!("服务端在 ServerHello 之前断开"))?;
    if ft != FRAME_SERVER_HELLO {
        bail!("期望 ServerHello 帧，实际收到帧类型 {ft}");
    }
    let server_hello: ServerHello = serde_json::from_slice(&sh_payload)?;
    if !server_hello.error.is_empty() {
        bail!("ServerHello 返回错误: {}", server_hello.error);
    }
    wire::validate_server_hello(&hello, &server_hello)?;
    let algorithm = server_hello.selected.crypto.algorithm.clone();

    // 2) LoginResp（仍然是明文）
    let login_resp: LoginResp = match conn.recv_msg().await? {
        Some(FrpMessage::LoginResp(r)) => r,
        Some(other) => bail!("期望 LoginResp，收到 {}", other.name()),
        None => bail!("服务端在 LoginResp 之前断开连接"),
    };
    if !login_resp.error.is_empty() {
        bail!("登录失败: {}", login_resp.error);
    }
    if login_resp.run_id.is_empty() {
        bail!("服务端未下发 run_id");
    }

    // 3) 协商出的 UDP 报文编码：官方 frps 默认选二进制
    let udp_binary = server_hello.selected.message.udp_packet_codec == wire::UDP_PACKET_CODEC_BINARY;
    conn.set_udp_codec(udp_binary);

    // 4) 切换到加密帧流
    let transcript = transcript_hash(&hello_payload, &sh_payload);
    let (c2s, s2c) = derive_control_keys(token.as_bytes(), &algorithm, &transcript)?;
    conn.upgrade(s2c, c2s)?; // 客户端用 s2c 读、c2s 写

    Ok((conn, login_resp.run_id, udp_binary))
}

// ---------------------------------------------------------------------------
// 服务端握手
// ---------------------------------------------------------------------------

/// 服务端接受一条连接后的分类。
pub enum ServerAccept {
    /// 控制连接（已通过 token 校验并升级加密）
    Control {
        conn: FrpConn,
        login: Login,
        /// 本次会话协商出的 UDP 报文编码（true = 二进制）
        udp_binary: bool,
    },
    /// 工作连接（明文，等待分配代理后回 StartWorkConn）
    Work { conn: FrpConn, msg: NewWorkConn },
    /// visitor 连接（stcp / xtcp 的接入方，明文，等待校验后回 NewVisitorConnResp）
    Visitor { conn: FrpConn, msg: NewVisitorConn },
}

/// 服务端握手。
///
/// * `run_id` —— 本次会话的标识，会写进 LoginResp 下发给客户端。
pub async fn server_handshake(
    stream: BoxStream,
    token: &str,
    run_id: &str,
) -> Result<ServerAccept> {
    let mut conn = FrpConn::new(stream);

    if !conn.peek_magic().await? {
        bail!("不是 frp v2 协议（魔术字不匹配），请确认对端是 v0.70+ 的 frpc");
    }

    let (ft, payload) = conn
        .read_frame()
        .await?
        .ok_or_else(|| anyhow!("客户端在发送首帧前断开"))?;

    // 首帧可能是 ClientHello（控制连接），也可能直接是消息帧（工作连接）
    let (msg_frame, crypto_state) = if ft == FRAME_CLIENT_HELLO {
        let hello: ClientHello = serde_json::from_slice(&payload)?;
        let server_hello = match wire::new_server_hello(&hello) {
            Ok(h) => h,
            Err(e) => {
                let mut h = ServerHello::default();
                h.selected.message.codec = wire::MESSAGE_CODEC_JSON.to_string();
                h.error = e.to_string();
                h
            }
        };
        let sh_payload = serde_json::to_vec(&server_hello)?;
        conn.write_frame(FRAME_SERVER_HELLO, &sh_payload).await?;
        if !server_hello.error.is_empty() {
            bail!("ServerHello 协商失败: {}", server_hello.error);
        }
        let algorithm = server_hello.selected.crypto.algorithm.clone();
        // 与 frp 一致：客户端宣告支持 binary 就选 binary
        let udp_binary =
            server_hello.selected.message.udp_packet_codec == wire::UDP_PACKET_CODEC_BINARY;
        conn.set_udp_codec(udp_binary);
        let next = conn
            .read_frame()
            .await?
            .ok_or_else(|| anyhow!("客户端在发送 Login 前断开"))?;
        (next, Some((payload, sh_payload, algorithm, udp_binary)))
    } else {
        ((ft, payload), None)
    };

    if msg_frame.0 != FRAME_MESSAGE {
        bail!("期望消息帧，实际收到帧类型 {}", msg_frame.0);
    }
    let body = &msg_frame.1;
    if body.len() < 2 {
        bail!("消息帧负载过短");
    }
    let type_id = u16::from_be_bytes([body[0], body[1]]);

    // 工作连接：不允许携带 ClientHello
    if type_id == msg::TYPE_NEW_WORK_CONN {
        if crypto_state.is_some() {
            bail!("工作连接不允许携带 ClientHello");
        }
        let m = FrpMessage::decode(type_id, &body[2..])?;
        match m {
            FrpMessage::NewWorkConn(nwc) => return Ok(ServerAccept::Work { conn, msg: nwc }),
            _ => unreachable!(),
        }
    }

    // visitor 连接：同样不允许携带 ClientHello
    if type_id == msg::TYPE_NEW_VISITOR_CONN {
        if crypto_state.is_some() {
            bail!("visitor 连接不允许携带 ClientHello");
        }
        let m = FrpMessage::decode(type_id, &body[2..])?;
        match m {
            FrpMessage::NewVisitorConn(nvc) => {
                return Ok(ServerAccept::Visitor { conn, msg: nvc })
            }
            _ => unreachable!(),
        }
    }

    if type_id != msg::TYPE_LOGIN {
        bail!("期望 Login 或 NewWorkConn，收到 type_id {type_id}");
    }
    let login = match FrpMessage::decode(type_id, &body[2..])? {
        FrpMessage::Login(l) => l,
        _ => unreachable!(),
    };

    // token 校验
    let expected = msg::auth_key(token, login.timestamp);
    if !msg::constant_time_eq(&expected, &login.privilege_key) {
        let _ = conn
            .send_msg(&FrpMessage::LoginResp(LoginResp {
                error: "token in login doesn't match token from configuration".into(),
                ..Default::default()
            }))
            .await;
        bail!("token 校验失败");
    }

    // LoginResp 必须明文发送（客户端此时还没升级加密）
    conn.send_msg(&FrpMessage::LoginResp(LoginResp {
        version: format!("rustunnel/{}", env!("CARGO_PKG_VERSION")),
        run_id: run_id.to_string(),
        ..Default::default()
    }))
    .await?;

    let udp_binary = crypto_state
        .as_ref()
        .map(|(_, _, _, udp_binary)| *udp_binary)
        .unwrap_or(false);
    if let Some((ch_payload, sh_payload, algorithm, _)) = crypto_state {
        let transcript = transcript_hash(&ch_payload, &sh_payload);
        let (c2s, s2c) = derive_control_keys(token.as_bytes(), &algorithm, &transcript)?;
        conn.upgrade(c2s, s2c)?; // 服务端用 c2s 读、s2c 写
    }

    Ok(ServerAccept::Control {
        conn,
        login,
        udp_binary,
    })
}

// ---------------------------------------------------------------------------
// 工作连接握手（助手）
// ---------------------------------------------------------------------------

/// 客户端建立一条工作连接并等待 `StartWorkConn`。
///
/// 返回 `(stream, leftover, start_msg)`：之后直接在这条流上转发原始字节。
pub async fn client_work_conn(
    stream: BoxStream,
    run_id: &str,
    token: &str,
    ts: i64,
) -> Result<(BoxStream, Vec<u8>, StartWorkConn)> {
    let mut conn = FrpConn::new(stream);
    conn.write_magic().await?;
    conn.send_msg(&FrpMessage::NewWorkConn(NewWorkConn {
        run_id: run_id.to_string(),
        privilege_key: msg::auth_key(token, ts),
        timestamp: ts,
    }))
    .await?;

    match conn.recv_msg().await? {
        Some(FrpMessage::StartWorkConn(s)) => {
            if !s.error.is_empty() {
                bail!("StartWorkConn 返回错误: {}", s.error);
            }
            let (stream, leftover) = conn.into_stream();
            Ok((stream, leftover, s))
        }
        Some(other) => bail!("期望 StartWorkConn，收到 {}", other.name()),
        None => bail!("服务端在工作连接握手完成前断开"),
    }
}

/// 客户端建立一条 **visitor 连接**（stcp / xtcp 的接入通道）。
///
/// 时序与工作连接类似，但首帧是 `NewVisitorConn`，服务端回 `NewVisitorConnResp`。
/// 校验通过后这条连接直接变成裸字节通道（服务端会把它与 provider 的工作连接对接）。
///
/// 返回 `(stream, leftover)`：leftover 是已经读进来但还没消费的字节
/// （visitor 收到 Resp 后可能立刻开始发数据，必须原样交给转发方）。
pub async fn client_visitor_conn(
    stream: BoxStream,
    run_id: &str,
    proxy_name: &str,
    secret_key: &str,
) -> Result<(BoxStream, Vec<u8>)> {
    let mut conn = FrpConn::new(stream);
    conn.write_magic().await?;

    let ts = now_unix_secs() as i64;
    conn.send_msg(&FrpMessage::NewVisitorConn(NewVisitorConn {
        run_id: run_id.to_string(),
        proxy_name: proxy_name.to_string(),
        // 与官方 frpc 一致：hex(md5(secret_key + timestamp))
        sign_key: msg::auth_key(secret_key, ts),
        timestamp: ts,
        ..Default::default()
    }))
    .await?;

    match conn.recv_msg().await? {
        Some(FrpMessage::NewVisitorConnResp(r)) => {
            if !r.error.is_empty() {
                bail!("NewVisitorConnResp 返回错误: {}", r.error);
            }
            let (stream, leftover) = conn.into_stream();
            Ok((stream, leftover))
        }
        Some(other) => bail!("期望 NewVisitorConnResp，收到 {}", other.name()),
        None => bail!("服务端在 visitor 连接握手完成前断开"),
    }
}
