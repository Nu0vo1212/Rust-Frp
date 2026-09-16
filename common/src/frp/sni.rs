//! TLS ClientHello 嗅探：只为从里面抠出 **SNI**（HTTPS 虚拟主机路由用）。
//!
//! frp 的 https 代理**不终止 TLS**：服务端只读 ClientHello 拿到域名，
//! 然后把读到的字节原样 + 后续所有字节透传给内网服务，证书由内网服务自己提供。
//! 所以这里只做最小解析，不引入任何密码学。

use anyhow::{anyhow, bail, Result};
use tokio::io::{AsyncRead, AsyncReadExt};

/// 最多拼几个 TLS record（ClientHello 正常只占 1 个 record）。
const MAX_RECORDS: usize = 4;
/// 累计读取上限。
const MAX_BYTES: usize = 32 * 1024;

/// 读出一个 ClientHello，返回 `(SNI, 原始字节)`。
///
/// 原始字节必须原样转发给上游，否则 TLS 握手会失败。
pub async fn sniff_client_hello<S: AsyncRead + Unpin>(
    stream: &mut S,
) -> Result<(Option<String>, Vec<u8>)> {
    let mut raw: Vec<u8> = Vec::new();
    let mut payload: Vec<u8> = Vec::new();
    let mut need: Option<usize> = None; // 握手体总长度（4 + body_len）

    for _ in 0..MAX_RECORDS {
        // record header
        let mut header = [0u8; 5];
        stream
            .read_exact(&mut header)
            .await
            .map_err(|e| anyhow!("读取 TLS record 头失败：{e}"))?;
        if header[0] != 0x16 {
            bail!("不是 TLS 握手记录（content type = 0x{:02x}）", header[0]);
        }
        let rec_len = u16::from_be_bytes([header[3], header[4]]) as usize;
        if raw.len() + 5 + rec_len > MAX_BYTES {
            bail!("ClientHello 超过 {MAX_BYTES} 字节");
        }
        let mut body = vec![0u8; rec_len];
        stream
            .read_exact(&mut body)
            .await
            .map_err(|e| anyhow!("读取 TLS record 体失败：{e}"))?;
        raw.extend_from_slice(&header);
        raw.extend_from_slice(&body);
        payload.extend_from_slice(&body);

        // 握手头：type(1) + length(3)
        if payload.len() >= 4 {
            if payload[0] != 0x01 {
                bail!("不是 ClientHello（handshake type = 0x{:02x}）", payload[0]);
            }
            let body_len =
                ((payload[1] as usize) << 16) | ((payload[2] as usize) << 8) | payload[3] as usize;
            need = Some(4 + body_len);
        }
        if let Some(need) = need {
            if payload.len() >= need {
                payload.truncate(need);
                return Ok((parse_sni(&payload)?, raw));
            }
        }
    }
    bail!("ClientHello 不完整")
}

/// 从完整的 ClientHello（含 4 字节握手头）里解析 SNI。
fn parse_sni(body: &[u8]) -> Result<Option<String>> {
    let mut i = 4; // 跳过 handshake header
    let need = |i: usize, n: usize| -> Result<()> {
        if i + n > body.len() {
            bail!("ClientHello 截断");
        }
        Ok(())
    };

    need(i, 2)?;
    i += 2; // client_version
    need(i, 32)?;
    i += 32; // random

    need(i, 1)?;
    let sid_len = body[i] as usize;
    i += 1 + sid_len;

    need(i, 2)?;
    let cs_len = u16::from_be_bytes([body[i], body[i + 1]]) as usize;
    i += 2 + cs_len;

    need(i, 1)?;
    let comp_len = body[i] as usize;
    i += 1 + comp_len;

    // 没有扩展（老客户端）就没有 SNI
    if i + 2 > body.len() {
        return Ok(None);
    }
    let ext_total = u16::from_be_bytes([body[i], body[i + 1]]) as usize;
    i += 2;
    let ext_end = (i + ext_total).min(body.len());

    while i + 4 <= ext_end {
        let ext_type = u16::from_be_bytes([body[i], body[i + 1]]);
        let ext_len = u16::from_be_bytes([body[i + 2], body[i + 3]]) as usize;
        i += 4;
        if i + ext_len > ext_end {
            break;
        }
        if ext_type == 0x0000 {
            // server_name 扩展
            let data = &body[i..i + ext_len];
            if data.len() < 2 {
                return Ok(None);
            }
            let list_len = u16::from_be_bytes([data[0], data[1]]) as usize;
            let mut j = 2;
            let end = (2 + list_len).min(data.len());
            while j + 3 <= end {
                let name_type = data[j];
                let name_len = u16::from_be_bytes([data[j + 1], data[j + 2]]) as usize;
                j += 3;
                if j + name_len > end {
                    break;
                }
                if name_type == 0 {
                    let name = String::from_utf8_lossy(&data[j..j + name_len]).to_string();
                    return Ok(Some(name));
                }
                j += name_len;
            }
            return Ok(None);
        }
        i += ext_len;
    }
    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 构造一个最小的 ClientHello（仅用于验证解析逻辑）。
    fn build_hello(sni: &str) -> Vec<u8> {
        let mut ext = Vec::new();
        // server_name 扩展
        let mut name = Vec::new();
        name.extend_from_slice(&((sni.len() + 3) as u16).to_be_bytes()); // list len
        name.push(0); // host_name
        name.extend_from_slice(&(sni.len() as u16).to_be_bytes());
        name.extend_from_slice(sni.as_bytes());
        ext.extend_from_slice(&0u16.to_be_bytes());
        ext.extend_from_slice(&(name.len() as u16).to_be_bytes());
        ext.extend_from_slice(&name);

        let mut body = Vec::new();
        body.extend_from_slice(&[0x03, 0x03]); // version
        body.extend_from_slice(&[0u8; 32]); // random
        body.push(0); // session id len
        body.extend_from_slice(&2u16.to_be_bytes()); // cipher suites len
        body.extend_from_slice(&[0x13, 0x01]); // cipher
        body.push(1); // compression len
        body.push(0); // null
        body.extend_from_slice(&(ext.len() as u16).to_be_bytes());
        body.extend_from_slice(&ext);

        let mut hs = Vec::new();
        hs.push(0x01);
        let l = body.len();
        hs.extend_from_slice(&[(l >> 16) as u8, (l >> 8) as u8, l as u8]);
        hs.extend_from_slice(&body);

        let mut rec = Vec::new();
        rec.push(0x16);
        rec.extend_from_slice(&[0x03, 0x01]);
        rec.extend_from_slice(&(hs.len() as u16).to_be_bytes());
        rec.extend_from_slice(&hs);
        rec
    }

    #[test]
    fn parses_sni() {
        let raw = build_hello("test.example.com");
        let payload = raw[5..].to_vec();
        assert_eq!(
            parse_sni(&payload).unwrap().as_deref(),
            Some("test.example.com")
        );
    }

    #[test]
    fn sniffs_from_stream() {
        let raw = build_hello("a.b.c");
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            let mut cursor = std::io::Cursor::new(raw.clone());
            let (sni, bytes) = sniff_client_hello(&mut cursor).await.unwrap();
            assert_eq!(sni.as_deref(), Some("a.b.c"));
            assert_eq!(bytes, raw);
        });
    }
}
