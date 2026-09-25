//! NFrp 线协议。
//!
//! # 帧格式
//!
//! ```text
//! +---------------+-------------------------+
//! | 4 bytes (BE)  |  JSON payload (n bytes) |
//! | length = n    |  serde_json(ControlMsg) |
//! +---------------+-------------------------+
//! ```
//!
//! 控制连接全程使用该帧格式；工作连接在握手阶段（`NewWorkConn` /
//! `StartWorkConn`）使用该帧格式，握手完成后退化为**原始字节流**，
//! 由 `tokio::io::copy_bidirectional` 直接桥接。
//!
//! 消息语义与 Go 版 frp 一一对应，详见 [`crate::compat`]。

use bytes::{Buf, BufMut, BytesMut};
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio_util::codec::{Decoder, Encoder};

use crate::error::{Error, Result};

/// 协议版本号。
pub const PROTOCOL_VERSION: u32 = 1;

/// 单帧负载上限（8 MiB），防止恶意超大帧打爆内存。
pub const MAX_FRAME_LEN: usize = 8 * 1024 * 1024;

/// 控制连接 / 工作连接握手阶段传输的消息。
///
/// 采用 `serde` 的内部标签（`{"type":"login", ...}`），JSON 可读性好，
/// 便于用 `nc` / Wireshark 抓包调试，也方便与 Go frp 做字段级映射。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ControlMessage {
    /// 客户端 -> 服务端：控制连接建立后的第一条消息。
    Login { token: String, client_id: String },
    /// 服务端 -> 客户端：登录结果。
    LoginResp {
        success: bool,
        message: String,
        /// 服务端的工作端口。可选字段：服务端可借此把 work_port 告知客户端，
        /// 客户端无需在配置里重复填写（配置显式指定时以配置为准）。
        #[serde(default, skip_serializing_if = "Option::is_none")]
        work_port: Option<u16>,
    },
    /// 客户端 -> 服务端：注册一个 TCP 代理。
    NewProxy {
        name: String,
        remote_port: u16,
        local_addr: String,
    },
    /// 服务端 -> 客户端：注册结果。
    NewProxyResp {
        name: String,
        success: bool,
        message: String,
    },
    /// 服务端 -> 客户端：请求客户端建一条工作连接。
    ReqWorkConn { proxy_name: String },
    /// 客户端 -> 服务端（工作连接首包）：声明这条工作连接属于哪个代理。
    NewWorkConn { proxy_name: String, token: String },
    /// 服务端 -> 客户端（工作连接回包）：握手完成，之后直接传原始字节。
    StartWorkConn { proxy_name: String },
    /// 客户端 -> 服务端：心跳。
    Heartbeat { timestamp: u64 },
    /// 双向：关闭 / 下线某个代理。
    CloseProxy { name: String },
}

impl ControlMessage {
    /// 返回消息类型名，用于日志。
    pub fn kind(&self) -> &'static str {
        match self {
            ControlMessage::Login { .. } => "login",
            ControlMessage::LoginResp { .. } => "login_resp",
            ControlMessage::NewProxy { .. } => "new_proxy",
            ControlMessage::NewProxyResp { .. } => "new_proxy_resp",
            ControlMessage::ReqWorkConn { .. } => "req_work_conn",
            ControlMessage::NewWorkConn { .. } => "new_work_conn",
            ControlMessage::StartWorkConn { .. } => "start_work_conn",
            ControlMessage::Heartbeat { .. } => "heartbeat",
            ControlMessage::CloseProxy { .. } => "close_proxy",
        }
    }

    /// 是否是只需要服务端处理、客户端不会主动发的消息（便于校验与日志）。
    pub fn is_server_originated(&self) -> bool {
        matches!(
            self,
            ControlMessage::LoginResp { .. }
                | ControlMessage::NewProxyResp { .. }
                | ControlMessage::ReqWorkConn { .. }
                | ControlMessage::StartWorkConn { .. }
        )
    }
}

/// 控制消息的编解码器（配合 `tokio_util::codec::Framed{Read,Write}` 使用）。
#[derive(Debug, Clone, Copy, Default)]
pub struct ControlCodec {
    max_frame_len: Option<usize>,
}

impl ControlCodec {
    /// 使用默认上限（8 MiB）创建编解码器。
    pub fn new() -> Self {
        Self {
            max_frame_len: None,
        }
    }

    /// 自定义单帧上限。
    pub fn with_max_frame_len(max_frame_len: usize) -> Self {
        Self {
            max_frame_len: Some(max_frame_len),
        }
    }

    fn limit(&self) -> usize {
        self.max_frame_len.unwrap_or(MAX_FRAME_LEN)
    }
}

impl Decoder for ControlCodec {
    type Item = ControlMessage;
    type Error = Error;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<ControlMessage>> {
        if src.len() < 4 {
            return Ok(None);
        }
        let len = u32::from_be_bytes([src[0], src[1], src[2], src[3]]) as usize;
        let limit = self.limit();
        if len > limit {
            return Err(Error::FrameTooLarge { len, max: limit });
        }
        if src.len() < 4 + len {
            // 通知底层预留足够空间，避免反复小块扩容。
            src.reserve(4 + len - src.len());
            return Ok(None);
        }
        src.advance(4);
        let payload = src.split_to(len);
        let msg = serde_json::from_slice(&payload)?;
        Ok(Some(msg))
    }
}

impl Encoder<ControlMessage> for ControlCodec {
    type Error = Error;

    fn encode(&mut self, item: ControlMessage, dst: &mut BytesMut) -> Result<()> {
        let payload = serde_json::to_vec(&item)?;
        let limit = self.limit();
        if payload.len() > limit {
            return Err(Error::FrameTooLarge {
                len: payload.len(),
                max: limit,
            });
        }
        dst.reserve(4 + payload.len());
        dst.put_u32(payload.len() as u32);
        dst.extend_from_slice(&payload);
        Ok(())
    }
}

/// 往一条**尚未分帧**的流（如工作连接）写入一条 JSON 消息。
pub async fn write_message<W, M>(writer: &mut W, msg: &M) -> Result<()>
where
    W: AsyncWrite + Unpin + ?Sized,
    M: Serialize + ?Sized,
{
    let payload = serde_json::to_vec(msg)?;
    if payload.len() > MAX_FRAME_LEN {
        return Err(Error::FrameTooLarge {
            len: payload.len(),
            max: MAX_FRAME_LEN,
        });
    }
    let mut buf = BytesMut::with_capacity(4 + payload.len());
    buf.put_u32(payload.len() as u32);
    buf.extend_from_slice(&payload);
    writer.write_all(&buf).await?;
    writer.flush().await?;
    Ok(())
}

/// 从一条**尚未分帧**的流读取一条 JSON 消息。
///
/// 返回 `Ok(None)` 表示对端在帧边界处干净地关闭了连接（EOF）。
pub async fn read_message<R, M>(reader: &mut R) -> Result<Option<M>>
where
    R: AsyncRead + Unpin + ?Sized,
    M: for<'de> Deserialize<'de>,
{
    let mut head = [0u8; 4];
    match reader.read_exact(&mut head).await {
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(Error::Io(e)),
    }
    let len = u32::from_be_bytes(head) as usize;
    if len > MAX_FRAME_LEN {
        return Err(Error::FrameTooLarge {
            len,
            max: MAX_FRAME_LEN,
        });
    }
    let mut payload = vec![0u8; len];
    if let Err(e) = reader.read_exact(&mut payload).await {
        if e.kind() == std::io::ErrorKind::UnexpectedEof {
            return Err(Error::Closed);
        }
        return Err(Error::Io(e));
    }
    Ok(Some(serde_json::from_slice(&payload)?))
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::BytesMut;

    #[test]
    fn codec_roundtrip() {
        let mut codec = ControlCodec::new();
        let msg = ControlMessage::NewProxy {
            name: "ssh".into(),
            remote_port: 6000,
            local_addr: "127.0.0.1:22".into(),
        };
        let mut buf = BytesMut::new();
        codec.encode(msg.clone(), &mut buf).unwrap();
        let n = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]) as usize;
        assert_eq!(n + 4, buf.len());
        let decoded = codec.decode(&mut buf).unwrap().unwrap();
        assert_eq!(decoded, msg);
    }

    #[test]
    fn login_resp_omits_work_port_when_none() {
        let m = ControlMessage::LoginResp {
            success: true,
            message: "ok".into(),
            work_port: None,
        };
        let s = serde_json::to_string(&m).unwrap();
        assert!(!s.contains("work_port"));
        assert!(s.contains("\"type\":\"login_resp\""));
    }
}
