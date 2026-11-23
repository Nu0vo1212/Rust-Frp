//! 线协议枚举。
//!
//! 职责：定义 [`Protocol`] 及其字符串表示、与官方 frp 线协议版本的映射。
//! 并发/所有权契约：纯值类型（`Copy`），无锁、无共享可变状态；解析与序列化均为纯函数。
//! 不变量：serde 的字符串表示只由 `as_str` / `FromStr` 决定，默认值只由 `Protocol::default()`（`FrpV1`）定义。

use serde::{Deserialize, Serialize};

/// 线协议选择。
///
/// 与 frp 配置里的 `transport.wireProtocol` **一一对应**，并且默认值也跟随官方：
///
/// * `frp-v1`    —— 官方 frpc/frps **至今为止的默认线协议**
///   （`pkg/config/v1/client.go`：`WireProtocol = util.EmptyOr(..., "v1")`）。
///   无魔术字，`[类型字节][i64 长度][JSON]`，登录后套 AES-128-CFB。
///   樱花这类第三方 frps 分支基本只认它。
/// * `frp-v2`    —— v0.70 引入的新协议，魔术字 + Hello 协商 + AEAD 帧流。
///   需要服务端也显式启用（官方 frps 会按魔术字自动识别，nfrp-server 同理）。
/// * `nfrp` —— NFrp 自研的简化协议，尚未实现（配置成它会被直接拒绝）。
///
/// 想写哪种都行：`"v1"` / `"v2"` / `"frp-v1"` / `"frp-v2"` 都认，
/// 也可以直接照抄 frp 配置里的 `[transport] wireProtocol = "v2"`。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Protocol {
    #[default]
    FrpV1,
    FrpV2,
    NFrp,
}

impl Protocol {
    pub fn as_str(&self) -> &'static str {
        match self {
            Protocol::FrpV1 => "frp-v1",
            Protocol::FrpV2 => "frp-v2",
            Protocol::NFrp => "nfrp",
        }
    }

    /// 对应的 frp 线协议版本；`nfrp` 自研协议没有对应版本。
    pub fn wire_version(&self) -> Option<crate::frp::WireVersion> {
        match self {
            Protocol::FrpV1 => Some(crate::frp::WireVersion::V1),
            Protocol::FrpV2 => Some(crate::frp::WireVersion::V2),
            Protocol::NFrp => None,
        }
    }
}

impl std::fmt::Display for Protocol {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl std::str::FromStr for Protocol {
    type Err = String;
    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s.trim().to_ascii_lowercase().as_str() {
            // 照抄 frp 的 `wireProtocol = "v1"` 也认；空值按官方 EmptyOr 的语义落到 v1
            "" | "v1" | "frp-v1" | "frpv1" | "frp" => Ok(Protocol::FrpV1),
            "v2" | "frp-v2" | "frpv2" => Ok(Protocol::FrpV2),
            "nfrp" | "native" => Ok(Protocol::NFrp),
            other => Err(format!(
                "未知协议 {other}，可选：frp-v1（默认）/ frp-v2 / nfrp"
            )),
        }
    }
}

impl Serialize for Protocol {
    fn serialize<S: serde::Serializer>(&self, s: S) -> std::result::Result<S::Ok, S::Error> {
        s.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for Protocol {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        s.parse::<Protocol>().map_err(serde::de::Error::custom)
    }
}
