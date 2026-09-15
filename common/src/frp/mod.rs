//! Go 版 frp **wire protocol v2** 的完整 Rust 实现。
//!
//! 这是 rustunnel 与原版 frp（v0.70+ 默认协议）互通的核心。所有细节都对
//! 照官方源码实现，字段名 / 编码 / 密钥派生保持逐字节一致：
//!
//! | 内容 | 官方参考 |
//! |---|---|
//! | 魔术字、帧格式 | `pkg/proto/wire/wire.go` |
//! | 消息类型 ID 与 JSON 字段 | `pkg/msg/wire_v2.go` / `pkg/msg/msg.go` |
//! | Hello 协商、transcript 哈希 | `pkg/proto/wire/crypto.go` |
//! | 控制通道 AEAD 帧流 | `golib/crypto/aead_stream.go` |
//! | 密钥派生 | `pkg/util/net/conn.go` (`deriveAEADControlKey`) |
//! | token 鉴权 | `pkg/auth/token.go` + `pkg/util/util.GetAuthKey` |
//!
//! # 连接时序（控制连接）
//!
//! ```text
//! C -> S  "FRP\0\x02\r\n"                      magic（v2 标识）
//! C -> S  frame(ClientHello)                   明文
//! C -> S  frame(Login{privilege_key, ...})     明文
//! S -> C  frame(ServerHello{algorithm, random})明文
//! S -> C  frame(LoginResp{run_id})             明文
//! ==== 之后双向切换为 AES-256-GCM 帧流 ====
//! C -> S  NewProxy / Ping ...                  密文
//! S -> C  NewProxyResp / ReqWorkConn / Pong    密文
//! ```
//!
//! # 工作连接
//!
//! ```text
//! C -> S  "FRP\0\x02\r\n" + frame(NewWorkConn{run_id})   明文（不允许 ClientHello）
//! S -> C  frame(StartWorkConn{proxy_name})               明文
//! ==== 之后直接转发原始字节 ====
//! ```
//!
//! # 完整传输层次
//!
//! ```text
//! TCP -> [TLS(transport.tls)] -> [yamux(transport.tcpMux)] -> frp v2 连接
//! ```
//!
//! TLS 与 yamux 都是可选的，取决于两端配置；开启 tcpMux 时，
//! 控制连接和所有工作连接都跑在同一条 TCP 的不同 yamux stream 上。

pub mod conn;
pub mod crypto;
pub mod msg;
pub mod mux;
pub mod sni;
pub mod stream;
pub mod tls;
pub mod wire;

pub use conn::{
    client_handshake, client_visitor_conn, client_work_conn, server_handshake, FrpConn, ServerAccept,
};
pub use msg::FrpMessage;
pub use stream::BoxStream;
