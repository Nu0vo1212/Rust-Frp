//! frp v2 帧格式与 Hello 协商结构体。
//!
//! 对应 `pkg/proto/wire/wire.go` / `pkg/proto/wire/crypto.go`。

use anyhow::{bail, Result};
use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use rand::RngCore;
use serde::{Deserialize, Serialize};

/// v2 协议魔术字：`FRP` + 版本号 2 + `\r\n`。
pub const MAGIC_V2: &[u8] = b"FRP\x00\x02\r\n";

pub const FRAME_CLIENT_HELLO: u16 = 1;
pub const FRAME_SERVER_HELLO: u16 = 2;
pub const FRAME_MESSAGE: u16 = 16;

/// 单帧负载上限（官方 `DefaultMaxFramePayloadSize`）。
pub const MAX_FRAME_PAYLOAD: usize = 64 * 1024;

pub const MESSAGE_CODEC_JSON: &str = "json";
pub const UDP_PACKET_CODEC_BINARY: &str = "binary-v1";

pub const AEAD_AES_256_GCM: &str = "aes-256-gcm";
pub const AEAD_XCHACHA20_POLY1305: &str = "xchacha20-poly1305";

/// Hello 里 random 字段的长度（字节）。
pub const CRYPTO_RANDOM_SIZE: usize = 32;

/// transcript 哈希用的标签。
pub const CRYPTO_TRANSCRIPT_LABEL: &str = "frp wire v2 crypto transcript";

// ---------------------------------------------------------------------------
// 帧：8 字节头（type u16 | flags u16 | length u32，全大端）+ payload
// ---------------------------------------------------------------------------

/// 构造一个帧的完整字节序列。
pub fn encode_frame(frame_type: u16, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(8 + payload.len());
    out.extend_from_slice(&frame_type.to_be_bytes());
    out.extend_from_slice(&0u16.to_be_bytes()); // flags 必须为 0
    out.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    out.extend_from_slice(payload);
    out
}

// ---------------------------------------------------------------------------
// Hello 结构体（Go json tag 一一对应）
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct BootstrapInfo {
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub transport: String,
    #[serde(default)]
    pub tls: bool,
    #[serde(default, rename = "tcpMux")]
    pub tcp_mux: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct MessageCapabilities {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub codecs: Vec<String>,
    #[serde(
        default,
        skip_serializing_if = "Vec::is_empty",
        rename = "udpPacketCodecs"
    )]
    pub udp_packet_codecs: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct CryptoCapabilities {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub algorithms: Vec<String>,
    /// Go 侧是 `[]byte`，JSON 里是 base64 字符串。
    #[serde(
        default,
        skip_serializing_if = "String::is_empty",
        rename = "clientRandom"
    )]
    pub client_random: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ClientCapabilities {
    #[serde(default)]
    pub message: MessageCapabilities,
    #[serde(default)]
    pub crypto: CryptoCapabilities,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ClientHello {
    #[serde(default)]
    pub bootstrap: BootstrapInfo,
    #[serde(default)]
    pub capabilities: ClientCapabilities,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct MessageSelection {
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub codec: String,
    #[serde(
        default,
        skip_serializing_if = "String::is_empty",
        rename = "udpPacketCodec"
    )]
    pub udp_packet_codec: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct CryptoSelection {
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub algorithm: String,
    #[serde(
        default,
        skip_serializing_if = "String::is_empty",
        rename = "serverRandom"
    )]
    pub server_random: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ServerSelection {
    #[serde(default)]
    pub message: MessageSelection,
    #[serde(default)]
    pub crypto: CryptoSelection,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ServerHello {
    #[serde(default)]
    pub selected: ServerSelection,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub error: String,
}

// ---------------------------------------------------------------------------
// 协商逻辑
// ---------------------------------------------------------------------------

/// 生成 32 字节随机数并做 base64（与 Go `[]byte` 的 JSON 编码一致）。
pub fn new_crypto_random() -> String {
    let mut buf = [0u8; CRYPTO_RANDOM_SIZE];
    rand::rngs::OsRng.fill_bytes(&mut buf);
    B64.encode(buf)
}

/// 构造 ClientHello。只声明我们真正实现的算法，避免选到没实现的。
pub fn new_client_hello(transport: &str, tls: bool, tcp_mux: bool) -> ClientHello {
    ClientHello {
        bootstrap: BootstrapInfo {
            transport: transport.to_string(),
            tls,
            tcp_mux,
        },
        capabilities: ClientCapabilities {
            message: MessageCapabilities {
                codecs: vec![MESSAGE_CODEC_JSON.to_string()],
                udp_packet_codecs: vec![UDP_PACKET_CODEC_BINARY.to_string()],
            },
            crypto: CryptoCapabilities {
                algorithms: vec![AEAD_AES_256_GCM.to_string()],
                client_random: new_crypto_random(),
            },
        },
    }
}

/// 服务端校验 ClientHello（对应 `ValidateClientHello`）。
///
/// `clientRandom` 补上 **base64 形态与长度**校验。
///
/// 原先只查"非空"（`is_empty()`）—— 于是 `clientRandom = "!!!"` 这种
/// 根本不是 base64 的串也能通过协商。实际影响很小（见下），但
/// **在协商阶段就报错**比"走到密钥派生再失败"清楚得多。
///
/// 为什么影响小：`client_random` 并不直接当密钥材料用 —— 它对密钥的贡献
/// 只通过 transcript 哈希（`crypto::transcript_hash` 用的是 ClientHello /
/// ServerHello 的**原始负载字节**）。密钥的真正强度来自 `token`。
/// 所以这不是漏洞，是**输入校验的完备性**问题。
///
/// 校验口径刻意**宽松**（不查精确长度）：官方各版本发的长度不一定都等于
/// `CRYPTO_RANDOM_SIZE`，卡死长度会有互通风险。这里只要求
/// "是合法 base64（标准或 URL-safe、带不带填充都行）且解码后 ≥16 字节"——
/// 足够挡掉明显的垃圾输入，又不会误伤合法客户端。
pub fn validate_client_hello(hello: &ClientHello) -> Result<()> {
    if !hello
        .capabilities
        .message
        .codecs
        .iter()
        .any(|c| c == MESSAGE_CODEC_JSON)
    {
        bail!("unsupported message codec");
    }
    let random = hello.capabilities.crypto.client_random.as_str();
    if random.is_empty() {
        bail!("invalid crypto client random length 0");
    }
    match decode_client_random(random) {
        Some(bytes) if bytes.len() >= 16 => {}
        Some(bytes) => bail!("crypto client random 太短（{} 字节，至少 16）", bytes.len()),
        None => bail!("crypto client random 不是合法的 base64"),
    }
    if select_algorithm(&hello.capabilities.crypto.algorithms).is_none() {
        bail!("no supported crypto algorithm");
    }
    Ok(())
}

/// 把 `clientRandom` 按 base64 解出来（兼容标准 / URL-safe、带 / 不带填充）。
///
/// 返回 `None` 表示不是合法 base64。
fn decode_client_random(s: &str) -> Option<Vec<u8>> {
    use base64::Engine as _;
    for eng in [
        &base64::engine::general_purpose::STANDARD,
        &base64::engine::general_purpose::STANDARD_NO_PAD,
        &base64::engine::general_purpose::URL_SAFE,
        &base64::engine::general_purpose::URL_SAFE_NO_PAD,
    ] {
        if let Ok(v) = eng.decode(s.as_bytes()) {
            return Some(v);
        }
    }
    None
}

/// 从客户端 advertised 列表里挑一个我们支持的算法（优先顺序跟随客户端）。
pub fn select_algorithm(algorithms: &[String]) -> Option<&'static str> {
    algorithms.iter().find_map(|a| match a.as_str() {
        // MVP 只实现了 AES-256-GCM。官方 frpc 默认优先声明 aes-256-gcm，
        // 因此这里总是能选中它；xchacha20 留给后续扩展。
        AEAD_AES_256_GCM => Some(AEAD_AES_256_GCM),
        _ => None,
    })
}

/// 构造 ServerHello（对应 `NewServerHello`）。
pub fn new_server_hello(hello: &ClientHello) -> Result<ServerHello> {
    validate_client_hello(hello)?;
    let algorithm = select_algorithm(&hello.capabilities.crypto.algorithms)
        .ok_or_else(|| anyhow::anyhow!("no supported crypto algorithm"))?;
    let udp_codec = if hello
        .capabilities
        .message
        .udp_packet_codecs
        .iter()
        .any(|c| c == UDP_PACKET_CODEC_BINARY)
    {
        UDP_PACKET_CODEC_BINARY.to_string()
    } else {
        String::new()
    };
    Ok(ServerHello {
        selected: ServerSelection {
            message: MessageSelection {
                codec: MESSAGE_CODEC_JSON.to_string(),
                udp_packet_codec: udp_codec,
            },
            crypto: CryptoSelection {
                algorithm: algorithm.to_string(),
                server_random: new_crypto_random(),
            },
        },
        error: String::new(),
    })
}

/// 客户端校验 ServerHello（对应 `ValidateServerHelloForClient`）。
pub fn validate_server_hello(client_hello: &ClientHello, server_hello: &ServerHello) -> Result<()> {
    if server_hello.selected.message.codec != MESSAGE_CODEC_JSON {
        bail!(
            "unsupported selected message codec: {}",
            server_hello.selected.message.codec
        );
    }
    let algo = &server_hello.selected.crypto.algorithm;
    if algo != AEAD_AES_256_GCM && algo != AEAD_XCHACHA20_POLY1305 {
        bail!("unknown selected crypto algorithm: {algo}");
    }
    if !client_hello
        .capabilities
        .crypto
        .algorithms
        .iter()
        .any(|a| a == algo)
    {
        bail!("selected crypto algorithm was not advertised by client: {algo}");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A-5 回归：`clientRandom` 必须是合法 base64。
    ///
    /// 修复前只查非空，`"!!!"` 这类垃圾串也能通过协商。
    #[test]
    fn client_random_必须是合法_base64() {
        let mut hello = new_client_hello("tcp", false, true);
        // 自带的是合法 base64（32 字节随机）⇒ 必须通过
        assert!(
            validate_client_hello(&hello).is_ok(),
            "自己生成的 ClientHello 必须能通过校验"
        );

        // 垃圾串 ⇒ 拒绝
        for bad in ["!!!", "not base64 @@", "====", "a"] {
            hello.capabilities.crypto.client_random = bad.to_string();
            assert!(
                validate_client_hello(&hello).is_err(),
                "{bad:?} 不是合法 base64，必须被拒"
            );
        }

        // 太短（合法 base64 但解码后 <16 字节）⇒ 拒绝
        // "AAAA" = 3 字节
        hello.capabilities.crypto.client_random = "QUFBQQ==".to_string();
        assert!(
            validate_client_hello(&hello).is_err(),
            "解码后只有 4 字节，必须被拒"
        );

        // 空串的原有错误信息要保留（面板/日志里有人在看这句话）
        hello.capabilities.crypto.client_random = String::new();
        let e = validate_client_hello(&hello).expect_err("空串必须被拒");
        assert!(e.to_string().contains("length 0"), "{e}");

        // 兼容性：标准 / URL-safe / 带不带填充都要认
        hello.capabilities.crypto.client_random = "AAAAAAAAAAAAAAAAAAAAAAAA".to_string(); // 16 字节
        assert!(validate_client_hello(&hello).is_ok(), "16 字节无填充应通过");
        hello.capabilities.crypto.client_random = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=".to_string(); // 23 字节带填充
        assert!(validate_client_hello(&hello).is_ok(), "带填充应通过");
    }

    /// base64 解码本身的口径（标准 / URL-safe / 填充）。
    #[test]
    fn client_random_解码口径() {
        assert!(decode_client_random("QUFBQQ==").is_some(), "标准带填充");
        assert!(decode_client_random("QUFBQQ").is_some(), "标准无填充");
        assert!(decode_client_random("_-_-_w").is_some(), "URL-safe");
        assert!(
            decode_client_random("").is_some(),
            "空串是合法 base64（0 字节）"
        );
        assert!(decode_client_random("!!!").is_none(), "非法字符");
    }
}
