//! Go 版 frp 协议兼容层（映射表 + 接入点说明）。
//!
//! # 现状
//!
//! MVP 使用「4 字节长度前缀 + JSON」的原生编码，消息**语义**与 Go frp 完全一致，
//! 但没有直接复用 frp 的 msgpack + `msg` 包二进制布局。这样做的理由：
//!
//! 1. MVP 阶段先跑通「控制连接 + 工作连接」状态机，避免被 frp 的历史字段
//!    （`RunID`、`Metas`、`UseEncryption`、`PoolCount` …）拖慢；
//! 2. JSON 帧便于 `nc` / Wireshark 直接观测，调试成本低；
//! 3. 编码层被隔离在 [`crate::protocol::ControlCodec`] 内，后续替换不影响上层。
//!
//! # 后续接入 Go frp 线协议的步骤
//!
//! 1. 在 `protocol.rs` 中新增 `FrpCodec`，实现 `Decoder<Item = ControlMessage>` /
//!    `Encoder<ControlMessage>`：内部用 `rmp-serde` 解码 frp 的
//!    `msg.Login / msg.NewProxy / msg.ReqWorkConn / msg.NewWorkConn / msg.StartWorkConn`；
//! 2. 在 [`crate::transport`] 中新增 `TlsTransport`（frpc 的 `tls_enable`），
//!    或 `NoiseTransport`（与 `snow` 对应）；
//! 3. 在二进制入口按配置选择 codec / transport，状态机代码保持不变。
//!
//! 下表给出消息类型的对应关系：

use crate::protocol::ControlMessage;

/// 目标兼容的 Go frp 版本线。
pub const FRP_COMPAT_VERSION: &str = "0.5x";

/// 把 rustunnel 消息映射到 Go frp 的 `msg` 类型名。
pub fn frp_msg_type(msg: &ControlMessage) -> &'static str {
    match msg {
        ControlMessage::Login { .. } => "msg.Login",
        ControlMessage::LoginResp { .. } => "msg.LoginResp",
        ControlMessage::NewProxy { .. } => "msg.NewProxy",
        ControlMessage::NewProxyResp { .. } => "msg.NewProxyResp",
        ControlMessage::ReqWorkConn { .. } => "msg.ReqWorkConn",
        ControlMessage::NewWorkConn { .. } => "msg.NewWorkConn",
        ControlMessage::StartWorkConn { .. } => "msg.StartWorkConn",
        // frp 的心跳消息叫 Ping / Pong
        ControlMessage::Heartbeat { .. } => "msg.Ping",
        ControlMessage::CloseProxy { .. } => "msg.CloseProxy",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mapping_is_stable() {
        let m = ControlMessage::ReqWorkConn {
            proxy_name: "ssh".into(),
        };
        assert_eq!(frp_msg_type(&m), "msg.ReqWorkConn");
    }
}
