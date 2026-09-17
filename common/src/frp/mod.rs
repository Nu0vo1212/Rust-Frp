//! Go 版 frp **线协议 v1 / v2** 的完整 Rust 实现。
//!
//! 这是 rustunnel 与原版 frp 互通的核心。所有细节都对照官方源码实现，
//! 字段名 / 编码 / 密钥派生保持逐字节一致：
//!
//! # 两套线协议
//!
//! | | v1（官方默认） | v2（`transport.wireProtocol = "v2"` 才启用） |
//! |---|---|---|
//! | 标识 | 无魔术字，直接发消息 | 魔术字 `FRP\0\x02\r\n` |
//! | 握手 | `Login` → `LoginResp` | ClientHello/ServerHello 协商 + `Login` → `LoginResp` |
//! | 帧格式 | `[类型字节][i64 大端长度][JSON]` | `[类型 u16][flags u16][长度 u32][载荷]` |
//! | 消息号 | 单字节（`'o'` = Login） | u16（1 = Login） |
//! | 控制通道加密 | AES-128-CFB（PBKDF2-SHA1 派生密钥，登录后生效） | AES-256-GCM（HKDF-SHA256 派生，每帧 AEAD） |
//! | 消息体 | **同一份 JSON**（两套协议共用字段名） | 同左 |
//!
//! 关键事实：**官方 frpc/frps 到 v0.71.0 为止的默认线协议仍然是 v1**
//! （`pkg/config/v1/client.go`：`WireProtocol = util.EmptyOr(..., "v1")`）。
//! 所以只实现 v2 等于"和原版 frp 默认配置连不上" —— 这也是 rustunnel 之前
//! 连不上樱花等第三方 frps 的根因。现在两套都实现，默认走 v1。
//!
//! 服务端与官方 frps 一样**自动探测**：先按 `wire.CheckMagic` 读 8 字节，
//! 等于 v2 魔术字就走 v2，否则把字节回填当 v1 的消息前缀用。
//!
//! | 内容 | 官方参考 |
//! |---|---|
//! | v1 帧格式 / 类型字节 / 加密 | `pkg/msg/msg.go`、`golib/msg/json/`、`golib/crypto/` |
//! | 魔术字、v2 帧格式 | `pkg/proto/wire/wire.go` |
//! | v2 消息类型 ID 与 JSON 字段 | `pkg/msg/wire_v2.go` / `pkg/msg/msg.go` |
//! | Hello 协商、transcript 哈希 | `pkg/proto/wire/crypto.go` |
//! | 控制通道 AEAD 帧流 | `golib/crypto/aead_stream.go` |
//! | v2 密钥派生 | `pkg/util/net/conn.go` (`deriveAEADControlKey`) |
//! | token 鉴权（两套协议相同） | `pkg/auth/token.go` + `pkg/util/util.GetAuthKey` |
//!
//! # 连接时序
//!
//! v1（控制连接）：
//!
//! ```text
//! C -> S  msg(Login{privilege_key, ...})        明文
//! S -> C  msg(LoginResp{run_id})                明文
//! ==== 之后双向切为 AES-128-CFB 流 ====
//! C -> S  NewProxy / Ping ...                   密文
//! S -> C  NewProxyResp / ReqWorkConn / Pong     密文
//! ```
//!
//! v2（控制连接）：
//!
//! ```text
//! C -> S  "FRP\0\x02\r\n"                      magic（v2 标识）
//! C -> S  frame(ClientHello)                   明文
//! C -> S  frame(Login{privilege_key, ...})     明文
//! S -> C  frame(ServerHello{algorithm, random})明文
//! S -> C  frame(LoginResp{run_id})             明文
//! ==== 之后双向切换为 AES-256-GCM 帧流 ====
//! ```
//!
//! 工作连接（两套协议同构，区别只是外层容器）：
//!
//! ```text
//! C -> S  NewWorkConn{run_id}          明文（v2 还要先发魔术字，且不允许 ClientHello）
//! S -> C  StartWorkConn{proxy_name}    明文
//! ==== 之后直接转发原始字节 ====
//! ```
//!
//! # 完整传输层次
//!
//! ```text
//! TCP -> [TLS(transport.tls)] -> [yamux(transport.tcpMux)] -> frp 连接
//! ```
//!
//! TLS 与 yamux 都是可选的，取决于两端配置；开启 tcpMux 时，
//! 控制连接和所有工作连接都跑在同一条 TCP 的不同 yamux stream 上。

pub mod conn;
pub mod crypto;
pub mod msg;
pub mod mux;
pub mod quic;
pub mod sni;
pub mod stream;
pub mod tls;
pub mod v1;
pub mod wire;

pub use conn::{
    client_handshake, client_visitor_conn, client_work_conn, server_handshake, FrpConn,
    ServerAccept,
};
pub use msg::FrpMessage;
pub use stream::BoxStream;

// ---------------------------------------------------------------------------
// 线协议版本
// ---------------------------------------------------------------------------

/// frp 线协议版本。
///
/// 与官方配置项 `transport.wireProtocol` 取值一一对应（`"v1"` / `"v2"`），
/// 默认值也跟随官方 —— **v1**。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Hash)]
pub enum WireVersion {
    /// 官方默认。无魔术字，`[类型字节][i64 长度][JSON]`，登录后套 AES-128-CFB。
    #[default]
    V1,
    /// `transport.wireProtocol = "v2"`。魔术字 + Hello 协商 + AEAD 帧流。
    V2,
}

impl WireVersion {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::V1 => "v1",
            Self::V2 => "v2",
        }
    }

    pub fn is_v2(&self) -> bool {
        matches!(self, Self::V2)
    }
}

impl std::fmt::Display for WireVersion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl std::str::FromStr for WireVersion {
    type Err = String;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s.trim().to_ascii_lowercase().as_str() {
            // 空值按官方 `util.EmptyOr(..., "v1")` 的语义落到 v1
            "" | "v1" | "frp-v1" | "frpv1" => Ok(Self::V1),
            "v2" | "frp-v2" | "frpv2" => Ok(Self::V2),
            other => Err(format!("未知线协议 {other}，可选：v1 / v2")),
        }
    }
}

/// rustunnel 这套 wire protocol 实现所**对齐的上游 frp 版本**。
///
/// 两个用途，都不是"装饰性"的：
///
/// 1. **给面板/启动器做版本协商**。各种 frp 面板会跑 `frpc -v`，把拿到的版本号
///    报给平台，平台据此决定下发哪种格式的配置 —— 报老版本给 legacy INI，
///    报 0.52+ 才给 TOML。所以客户端的 `-v` 必须输出这个值，
///    否则对方会当我们在跑远古版本（NetTool 里的樱花、OpenFrp 都是这套逻辑）。
/// 2. **线协议对拍基准**。`client/src/main.rs` 里那条金标准测试就是拿
///    v0.71.0 真实发出的 `NewProxy` 报文逐字节比对的。
pub const FRP_WIRE_VERSION: &str = "0.71.0";

#[cfg(test)]
mod tests {
    use super::FRP_WIRE_VERSION;

    /// `FRP_WIRE_VERSION` 必须始终是 `x.y.z` 三段式。
    ///
    /// 面板/启动器抠版本号的方式是"扫到一个至少 3 段点分数字的串"（NetTool 的
    /// `parse_frpc_version` 就是这么写的）。写成 `0.71` 这种两段式是**悄悄失效**：
    /// 对方解析不出来 → 回落到"老客户端"的假设 → 平台下发 legacy INI。
    /// 症状离原因很远，所以在源头钉死。
    #[test]
    fn frp_兼容版本号必须是三段式纯数字() {
        let parts: Vec<&str> = FRP_WIRE_VERSION.split('.').collect();
        assert!(
            parts.len() >= 3,
            "必须写成 x.y.z，实际是 {FRP_WIRE_VERSION:?}"
        );
        for (i, p) in parts.iter().take(2).enumerate() {
            assert!(
                !p.is_empty() && p.chars().all(|c| c.is_ascii_digit()),
                "第 {} 段必须是纯数字，实际是 {p:?}",
                i + 1
            );
        }
    }
}
