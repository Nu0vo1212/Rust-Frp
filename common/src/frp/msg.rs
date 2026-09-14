//! frp v2 消息类型（`pkg/msg/msg.go` + `pkg/msg/wire_v2.go`）。
//!
//! 帧负载 = `2 字节大端 type_id` + `JSON`。
//! JSON 字段名与 Go `json:"...,omitempty"` 标签一致，因此这里用
//! `skip_serializing_if` 复刻 omitempty 语义，保证与官方字节兼容。

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

// v2 消息 type_id（pkg/msg/wire_v2.go）
pub const TYPE_LOGIN: u16 = 1;
pub const TYPE_LOGIN_RESP: u16 = 2;
pub const TYPE_NEW_PROXY: u16 = 3;
pub const TYPE_NEW_PROXY_RESP: u16 = 4;
pub const TYPE_CLOSE_PROXY: u16 = 5;
pub const TYPE_NEW_WORK_CONN: u16 = 6;
pub const TYPE_REQ_WORK_CONN: u16 = 7;
pub const TYPE_START_WORK_CONN: u16 = 8;
pub const TYPE_NEW_VISITOR_CONN: u16 = 9;
pub const TYPE_NEW_VISITOR_CONN_RESP: u16 = 10;
pub const TYPE_PING: u16 = 11;
pub const TYPE_PONG: u16 = 12;
pub const TYPE_UDP_PACKET: u16 = 13;

fn is_false(b: &bool) -> bool {
    !*b
}
fn is_zero_u16(v: &u16) -> bool {
    *v == 0
}
fn is_zero_i64(v: &i64) -> bool {
    *v == 0
}
fn is_empty_str(s: &str) -> bool {
    s.is_empty()
}
fn is_empty_map(m: &HashMap<String, String>) -> bool {
    m.is_empty()
}

// ---------------------------------------------------------------------------
// 消息体
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Login {
    #[serde(default, skip_serializing_if = "is_empty_str")]
    pub version: String,
    #[serde(default, skip_serializing_if = "is_empty_str")]
    pub hostname: String,
    #[serde(default, skip_serializing_if = "is_empty_str")]
    pub os: String,
    #[serde(default, skip_serializing_if = "is_empty_str")]
    pub arch: String,
    #[serde(default, skip_serializing_if = "is_empty_str")]
    pub user: String,
    #[serde(default, skip_serializing_if = "is_empty_str")]
    pub privilege_key: String,
    #[serde(default, skip_serializing_if = "is_zero_i64")]
    pub timestamp: i64,
    #[serde(default, skip_serializing_if = "is_empty_str")]
    pub run_id: String,
    #[serde(default, skip_serializing_if = "is_empty_str")]
    pub client_id: String,
    #[serde(default, skip_serializing_if = "is_empty_map")]
    pub metas: HashMap<String, String>,
    #[serde(default)]
    pub pool_count: i32,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct LoginResp {
    #[serde(default, skip_serializing_if = "is_empty_str")]
    pub version: String,
    #[serde(default, skip_serializing_if = "is_empty_str")]
    pub run_id: String,
    #[serde(default, skip_serializing_if = "is_empty_str")]
    pub error: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct NewProxy {
    #[serde(default, skip_serializing_if = "is_empty_str")]
    pub proxy_name: String,
    #[serde(default, skip_serializing_if = "is_empty_str")]
    pub proxy_type: String,
    #[serde(default, skip_serializing_if = "is_false")]
    pub use_encryption: bool,
    #[serde(default, skip_serializing_if = "is_false")]
    pub use_compression: bool,
    #[serde(default, skip_serializing_if = "is_empty_str")]
    pub group: String,
    #[serde(default, skip_serializing_if = "is_empty_str")]
    pub group_key: String,
    #[serde(default, skip_serializing_if = "is_empty_map")]
    pub metas: HashMap<String, String>,
    #[serde(default, skip_serializing_if = "is_zero_u16")]
    pub remote_port: u16,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct NewProxyResp {
    #[serde(default, skip_serializing_if = "is_empty_str")]
    pub proxy_name: String,
    #[serde(default, skip_serializing_if = "is_empty_str")]
    pub remote_addr: String,
    #[serde(default, skip_serializing_if = "is_empty_str")]
    pub error: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CloseProxy {
    #[serde(default, skip_serializing_if = "is_empty_str")]
    pub proxy_name: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct NewWorkConn {
    #[serde(default, skip_serializing_if = "is_empty_str")]
    pub run_id: String,
    #[serde(default, skip_serializing_if = "is_empty_str")]
    pub privilege_key: String,
    #[serde(default, skip_serializing_if = "is_zero_i64")]
    pub timestamp: i64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct StartWorkConn {
    #[serde(default, skip_serializing_if = "is_empty_str")]
    pub proxy_name: String,
    #[serde(default, skip_serializing_if = "is_empty_str")]
    pub src_addr: String,
    #[serde(default, skip_serializing_if = "is_empty_str")]
    pub dst_addr: String,
    #[serde(default, skip_serializing_if = "is_zero_u16")]
    pub src_port: u16,
    #[serde(default, skip_serializing_if = "is_zero_u16")]
    pub dst_port: u16,
    #[serde(default, skip_serializing_if = "is_empty_str")]
    pub error: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Ping {
    #[serde(default, skip_serializing_if = "is_empty_str")]
    pub privilege_key: String,
    #[serde(default, skip_serializing_if = "is_zero_i64")]
    pub timestamp: i64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Pong {
    #[serde(default, skip_serializing_if = "is_empty_str")]
    pub error: String,
}

// ---------------------------------------------------------------------------
// 枚举封装
// ---------------------------------------------------------------------------

/// 一条 frp 消息。
#[derive(Debug, Clone)]
pub enum FrpMessage {
    Login(Login),
    LoginResp(LoginResp),
    NewProxy(NewProxy),
    NewProxyResp(NewProxyResp),
    CloseProxy(CloseProxy),
    NewWorkConn(NewWorkConn),
    ReqWorkConn,
    StartWorkConn(StartWorkConn),
    Ping(Ping),
    Pong(Pong),
}

impl FrpMessage {
    /// 对应的 v2 type_id。
    pub fn type_id(&self) -> u16 {
        match self {
            Self::Login(_) => TYPE_LOGIN,
            Self::LoginResp(_) => TYPE_LOGIN_RESP,
            Self::NewProxy(_) => TYPE_NEW_PROXY,
            Self::NewProxyResp(_) => TYPE_NEW_PROXY_RESP,
            Self::CloseProxy(_) => TYPE_CLOSE_PROXY,
            Self::NewWorkConn(_) => TYPE_NEW_WORK_CONN,
            Self::ReqWorkConn => TYPE_REQ_WORK_CONN,
            Self::StartWorkConn(_) => TYPE_START_WORK_CONN,
            Self::Ping(_) => TYPE_PING,
            Self::Pong(_) => TYPE_PONG,
        }
    }

    /// 编码为消息帧负载：`2 字节 type_id + JSON`。
    pub fn encode(&self) -> Result<Vec<u8>, crate::error::Error> {
        let body = match self {
            Self::Login(m) => serde_json::to_vec(m)?,
            Self::LoginResp(m) => serde_json::to_vec(m)?,
            Self::NewProxy(m) => serde_json::to_vec(m)?,
            Self::NewProxyResp(m) => serde_json::to_vec(m)?,
            Self::CloseProxy(m) => serde_json::to_vec(m)?,
            Self::NewWorkConn(m) => serde_json::to_vec(m)?,
            // Go 侧 `json.Marshal(&msg.ReqWorkConn{})` 产出 `{}` 而不是空串，
            // 官方 frpc 对空 body 会报 "unexpected end of JSON input"，必须保持一致。
            Self::ReqWorkConn => br"{}".to_vec(),
            Self::StartWorkConn(m) => serde_json::to_vec(m)?,
            Self::Ping(m) => serde_json::to_vec(m)?,
            Self::Pong(m) => serde_json::to_vec(m)?,
        };
        let mut out = Vec::with_capacity(2 + body.len());
        out.extend_from_slice(&self.type_id().to_be_bytes());
        out.extend_from_slice(&body);
        Ok(out)
    }

    /// 从消息帧负载解码。
    pub fn decode(type_id: u16, body: &[u8]) -> Result<Self, crate::error::Error> {
        let msg = match type_id {
            TYPE_LOGIN => Self::Login(serde_json::from_slice(body)?),
            TYPE_LOGIN_RESP => Self::LoginResp(serde_json::from_slice(body)?),
            TYPE_NEW_PROXY => Self::NewProxy(serde_json::from_slice(body)?),
            TYPE_NEW_PROXY_RESP => Self::NewProxyResp(serde_json::from_slice(body)?),
            TYPE_CLOSE_PROXY => Self::CloseProxy(serde_json::from_slice(body)?),
            TYPE_NEW_WORK_CONN => Self::NewWorkConn(serde_json::from_slice(body)?),
            TYPE_REQ_WORK_CONN => Self::ReqWorkConn,
            TYPE_START_WORK_CONN => Self::StartWorkConn(serde_json::from_slice(body)?),
            TYPE_PING => Self::Ping(serde_json::from_slice(body)?),
            TYPE_PONG => Self::Pong(serde_json::from_slice(body)?),
            other => {
                return Err(crate::error::Error::Protocol(format!(
                    "未知的 frp 消息 type_id: {other}"
                )))
            }
        };
        Ok(msg)
    }

    /// 人类可读的名字，用于日志。
    pub fn name(&self) -> &'static str {
        match self {
            Self::Login(_) => "Login",
            Self::LoginResp(_) => "LoginResp",
            Self::NewProxy(_) => "NewProxy",
            Self::NewProxyResp(_) => "NewProxyResp",
            Self::CloseProxy(_) => "CloseProxy",
            Self::NewWorkConn(_) => "NewWorkConn",
            Self::ReqWorkConn => "ReqWorkConn",
            Self::StartWorkConn(_) => "StartWorkConn",
            Self::Ping(_) => "Ping",
            Self::Pong(_) => "Pong",
        }
    }
}

// ---------------------------------------------------------------------------
// token 鉴权：hex(md5(token + timestamp))
// ---------------------------------------------------------------------------

/// 计算 frp token 鉴权 key，等价于 Go `util.GetAuthKey`。
pub fn auth_key(token: &str, timestamp: i64) -> String {
    use md5::{Digest, Md5};
    let mut h = Md5::new();
    h.update(token.as_bytes());
    h.update(timestamp.to_string().as_bytes());
    let digest = h.finalize();
    let mut s = String::with_capacity(digest.len() * 2);
    for b in digest {
        use std::fmt::Write;
        let _ = write!(s, "{b:02x}");
    }
    s
}

/// 常量时间字符串比较。
pub fn constant_time_eq(a: &str, b: &str) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut acc = 0u8;
    for (x, y) in a.bytes().zip(b.bytes()) {
        acc |= x ^ y;
    }
    acc == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn auth_key_matches_go() {
        // Go: util.GetAuthKey("your_secret_token", 1700000000)
        //   = hex(md5("your_secret_token" + "1700000000"))
        assert_eq!(
            auth_key("your_secret_token", 1_700_000_000),
            "196ac62ac046b172fdd69d748a3583d0"
        );
    }

    #[test]
    fn message_roundtrip() {
        let m = FrpMessage::NewProxy(NewProxy {
            proxy_name: "ssh".into(),
            proxy_type: "tcp".into(),
            remote_port: 6000,
            ..Default::default()
        });
        let bytes = m.encode().unwrap();
        assert_eq!(&bytes[..2], &TYPE_NEW_PROXY.to_be_bytes());
        let json = String::from_utf8(bytes[2..].to_vec()).unwrap();
        assert!(json.contains("\"proxy_name\":\"ssh\""));
        assert!(!json.contains("use_encryption"), "omitempty 应省略 false");
    }
}
