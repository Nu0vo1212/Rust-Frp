//! `rustunnel-common`：服务端与客户端共享的公共库。
//!
//! 包含六部分：
//! - [`protocol`]：rustunnel 原生线协议（4 字节大端长度前缀 + JSON）；
//! - [`frp`]：**Go 版 frp wire protocol v2** 的完整实现，用于与原版 frpc/frps 互通；
//! - [`config`]：TOML 配置结构与示例模板；
//! - [`transport`]：传输层抽象（MVP 明文，后续可换 rustls / snow）；
//! - [`util`]：地址解析、日志初始化、连接桥接等跨平台工具；
//! - [`error`]：统一错误类型。
//!
//! 本 crate 不含任何平台特定代码，Windows / Linux 行为一致。

pub mod compat;
pub mod config;
pub mod error;
pub mod frp;
pub mod p2p;
pub mod protocol;
pub mod throttle;
pub mod transport;
pub mod util;

pub use error::{Error, Result};
pub use protocol::ControlMessage;
pub use transport::{PlainTransport, Transport, TunnelIo, TunnelStream};

/// 当前实现的协议版本号（用于日志与后续协商）。
pub const PROTOCOL_VERSION: u32 = protocol::PROTOCOL_VERSION;
