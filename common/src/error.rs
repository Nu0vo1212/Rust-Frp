//! 统一错误类型。
//!
//! 使用 `thiserror` 定义库级错误，二进制侧统一用 `anyhow::Result` 承载，
//! 这样可以 `?` 直接把本 crate 的错误转成 `anyhow::Error`。

use thiserror::Error;

/// rustunnel 的库级错误。
#[derive(Debug, Error)]
pub enum Error {
    /// 底层 IO 错误。
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    /// JSON 序列化 / 反序列化错误。
    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),

    /// TOML 配置解析错误。
    #[error("toml error: {0}")]
    Toml(#[from] toml::de::Error),

    /// TOML 序列化错误（生成示例配置时）。
    #[error("toml serialize error: {0}")]
    TomlSer(#[from] toml::ser::Error),

    /// 单帧超过上限，可能是攻击者或对端实现不一致。
    #[error("frame too large: {len} bytes (max {max})")]
    FrameTooLarge { len: usize, max: usize },

    /// 协议层面的错误（非法帧、未知消息类型、协商失败等）。
    #[error("protocol error: {0}")]
    Protocol(String),

    /// 收到不期望的消息类型。
    #[error("unexpected message: expected {expected}, got {got}")]
    UnexpectedMessage {
        expected: &'static str,
        got: &'static str,
    },

    /// token 校验失败。
    #[error("authentication failed: {0}")]
    Auth(String),

    /// 代理名重复。
    #[error("proxy already exists: {0}")]
    ProxyExists(String),

    /// 远端端口被占用。
    #[error("remote port already in use: {0}")]
    PortInUse(u16),

    /// 找不到指定代理。
    #[error("proxy not found: {0}")]
    ProxyNotFound(String),

    /// 地址解析失败。
    #[error("cannot resolve address {addr}: {source}")]
    Resolve {
        addr: String,
        #[source]
        source: std::io::Error,
    },

    /// 对端在数据交互前关闭了连接。
    #[error("connection closed by peer")]
    Closed,

    /// 等待对端响应超时。
    #[error("timeout: {0}")]
    Timeout(&'static str),

    /// 其他错误。
    #[error("{0}")]
    Other(String),
}

/// 本 crate 的 Result 别名。
pub type Result<T> = std::result::Result<T, Error>;
