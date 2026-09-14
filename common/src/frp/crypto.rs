//! frp v2 控制通道加密：HKDF-SHA256 密钥派生 + AES-256-GCM 帧流。
//!
//! 严格对齐：
//! * 密钥派生 —— `pkg/util/net/conn.go` 的 `deriveAEADControlKey`：
//!   `HKDF-SHA256(ikm = token, salt = transcript_hash,
//!                info = "frp wire v2 control aead {alg} {direction}", len = 32)`
//! * 帧流 —— `fatedier/golib/crypto/aead_stream.go`：
//!   `stream_nonce(12B 明文) || 每帧 [u32 BE 密文长度][AES-GCM 密文+16B tag]`，
//!   每帧 AAD = `stream_nonce || 长度头`，nonce 每帧按大端 +1。

use aes_gcm::{
    aead::{Aead, KeyInit, Payload},
    Aes256Gcm, Nonce,
};
use anyhow::{anyhow, bail, Result};
use hkdf::Hkdf;
use rand::RngCore;
use sha2::{Digest, Sha256};

use super::wire::{CRYPTO_TRANSCRIPT_LABEL, CRYPTO_RANDOM_SIZE};

/// 官方支持的算法，本实现使用 AES-256-GCM。
pub const ALGORITHM: &str = "aes-256-gcm";
pub const KEY_LEN: usize = 32;
pub const NONCE_LEN: usize = 12;
pub const TAG_LEN: usize = 16;
/// 单帧明文上限（golib `DefaultAEADMaxPayloadSize`）。
pub const MAX_PAYLOAD: usize = 64 * 1024;

const HKDF_INFO_PREFIX: &str = "frp wire v2 control aead";
const DIRECTION_C2S: &str = "client-to-server";
const DIRECTION_S2C: &str = "server-to-client";

/// 计算握手 transcript 哈希（ClientHello / ServerHello 帧负载）。
pub fn transcript_hash(client_hello_payload: &[u8], server_hello_payload: &[u8]) -> Vec<u8> {
    let mut h = Sha256::new();
    h.update(CRYPTO_TRANSCRIPT_LABEL.as_bytes());
    transcript_part(&mut h, "client hello", client_hello_payload);
    transcript_part(&mut h, "server hello", server_hello_payload);
    h.finalize().to_vec()
}

fn transcript_part(h: &mut Sha256, label: &str, payload: &[u8]) {
    h.update([0u8]);
    h.update(label.as_bytes());
    h.update([0u8]);
    h.update((payload.len() as u64).to_be_bytes());
    h.update(payload);
}

fn hkdf_expand(ikm: &[u8], salt: &[u8], info: &[u8]) -> Result<Vec<u8>> {
    let hkdf = Hkdf::<Sha256>::new(Some(salt), ikm);
    let mut okm = vec![0u8; KEY_LEN];
    hkdf.expand(info, &mut okm)
        .map_err(|e| anyhow!("hkdf 派生失败: {e}"))?;
    Ok(okm)
}

/// 派生双向密钥，返回 `(client_to_server, server_to_client)`。
pub fn derive_control_keys(
    token: &[u8],
    algorithm: &str,
    transcript: &[u8],
) -> Result<(Vec<u8>, Vec<u8>)> {
    let c2s_info = format!("{HKDF_INFO_PREFIX} {algorithm} {DIRECTION_C2S}");
    let s2c_info = format!("{HKDF_INFO_PREFIX} {algorithm} {DIRECTION_S2C}");
    let c2s = hkdf_expand(token, transcript, c2s_info.as_bytes())?;
    let s2c = hkdf_expand(token, transcript, s2c_info.as_bytes())?;
    Ok((c2s, s2c))
}

/// 生成 32 字节随机数，base64 后用于 Hello 的 random 字段。
pub fn random_b64() -> String {
    let mut buf = vec![0u8; CRYPTO_RANDOM_SIZE];
    rand::rngs::OsRng.fill_bytes(&mut buf);
    base64::Engine::encode(&base64::engine::general_purpose::STANDARD, buf)
}

// ---------------------------------------------------------------------------
// 写方向：明文 -> 密文帧
// ---------------------------------------------------------------------------

pub struct AeadWriter {
    cipher: Aes256Gcm,
    stream_nonce: [u8; NONCE_LEN],
    nonce: [u8; NONCE_LEN],
    header_sent: bool,
}

impl AeadWriter {
    pub fn new(key: &[u8]) -> Result<Self> {
        let cipher = Aes256Gcm::new_from_slice(key).map_err(|e| anyhow!("AES-256-GCM 初始化失败: {e}"))?;
        let mut nonce = [0u8; NONCE_LEN];
        rand::rngs::OsRng.fill_bytes(&mut nonce);
        Ok(Self {
            cipher,
            stream_nonce: nonce,
            nonce,
            header_sent: false,
        })
    }

    /// 加密一段明文，返回待写入套接字的字节（首帧附带 stream nonce）。
    pub fn seal(&mut self, plaintext: &[u8]) -> Result<Vec<u8>> {
        let mut out = Vec::with_capacity(NONCE_LEN + plaintext.len() + 64);
        if !self.header_sent {
            out.extend_from_slice(&self.stream_nonce);
            self.header_sent = true;
        }
        for chunk in plaintext.chunks(MAX_PAYLOAD) {
            let header = ((chunk.len() + TAG_LEN) as u32).to_be_bytes();
            let mut aad = Vec::with_capacity(NONCE_LEN + 4);
            aad.extend_from_slice(&self.stream_nonce);
            aad.extend_from_slice(&header);
            let ct = self
                .cipher
                .encrypt(
                    Nonce::from_slice(&self.nonce),
                    Payload { msg: chunk, aad: &aad },
                )
                .map_err(|_| anyhow!("AEAD 加密失败"))?;
            out.extend_from_slice(&header);
            out.extend_from_slice(&ct);
            increment_nonce(&mut self.nonce);
        }
        Ok(out)
    }
}

// ---------------------------------------------------------------------------
// 读方向：密文帧 -> 明文
// ---------------------------------------------------------------------------

pub struct AeadReader {
    cipher: Aes256Gcm,
    stream_nonce: Option<[u8; NONCE_LEN]>,
    nonce: [u8; NONCE_LEN],
}

impl AeadReader {
    pub fn new(key: &[u8]) -> Result<Self> {
        let cipher = Aes256Gcm::new_from_slice(key).map_err(|e| anyhow!("AES-256-GCM 初始化失败: {e}"))?;
        Ok(Self {
            cipher,
            stream_nonce: None,
            nonce: [0u8; NONCE_LEN],
        })
    }

    /// 从密文缓冲区里尝试解出一帧。
    ///
    /// * `Ok(Some(pt))` —— 成功解出一帧（已从 `buf` 移除对应字节）
    /// * `Ok(None)`     —— 数据还不够一整帧
    pub fn open(&mut self, buf: &mut Vec<u8>) -> Result<Option<Vec<u8>>> {
        if self.stream_nonce.is_none() {
            if buf.len() < NONCE_LEN {
                return Ok(None);
            }
            let mut n = [0u8; NONCE_LEN];
            n.copy_from_slice(&buf[..NONCE_LEN]);
            buf.drain(..NONCE_LEN);
            self.nonce = n;
            self.stream_nonce = Some(n);
        }
        if buf.len() < 4 {
            return Ok(None);
        }
        let mut header = [0u8; 4];
        header.copy_from_slice(&buf[..4]);
        let ct_len = u32::from_be_bytes(header) as usize;
        if ct_len < TAG_LEN {
            bail!("AEAD 密文长度 {ct_len} 小于 tag 长度");
        }
        if ct_len > MAX_PAYLOAD + TAG_LEN {
            bail!("AEAD 密文长度 {ct_len} 超过上限");
        }
        if buf.len() < 4 + ct_len {
            return Ok(None);
        }
        let ct = buf[4..4 + ct_len].to_vec();

        let stream_nonce = self.stream_nonce.expect("stream nonce 已初始化");
        let mut aad = Vec::with_capacity(NONCE_LEN + 4);
        aad.extend_from_slice(&stream_nonce);
        aad.extend_from_slice(&header);

        let pt = self
            .cipher
            .decrypt(Nonce::from_slice(&self.nonce), Payload { msg: &ct, aad: &aad })
            .map_err(|_| anyhow!("AEAD 解密失败：token 不一致或数据被篡改"))?;

        buf.drain(..4 + ct_len);
        increment_nonce(&mut self.nonce);
        Ok(Some(pt))
    }
}

/// nonce 按大端整数 +1（与 Go `incrementNonce` 一致）。
fn increment_nonce(nonce: &mut [u8]) {
    for i in (0..nonce.len()).rev() {
        if nonce[i] == u8::MAX {
            nonce[i] = 0;
        } else {
            nonce[i] += 1;
            break;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn aead_roundtrip() {
        let key = vec![7u8; KEY_LEN];
        let mut w = AeadWriter::new(&key).unwrap();
        let mut r = AeadReader::new(&key).unwrap();

        let wire = w.seal(b"hello frp").unwrap();
        let mut buf = wire.clone();
        let pt = r.open(&mut buf).unwrap().unwrap();
        assert_eq!(pt, b"hello frp");

        // 连续多帧：nonce 必须递增且能对上
        let wire2 = w.seal(b"second").unwrap();
        buf.extend_from_slice(&wire2);
        let pt2 = r.open(&mut buf).unwrap().unwrap();
        assert_eq!(pt2, b"second");
    }

    #[test]
    fn derive_keys_are_distinct() {
        let (c2s, s2c) = derive_control_keys(b"token", ALGORITHM, &[0u8; 32]).unwrap();
        assert_eq!(c2s.len(), 32);
        assert_ne!(c2s, s2c);
    }
}
