//! 版本化 TLV 与扩展帧、preamble 的编解码。
//!
//! # 格式（全部大端）
//!
//! ```text
//! 扩展帧（v2: 帧类型 0x4E 的负载；v1: 消息类型字节 0x7F 的 JSON 位置）
//!   u8   version        当前 1
//!   u8   kind           见 [FrameKind]
//!   u16  flags          保留，必须为 0（不认识就忽略）
//!   TLV*                 每个：u16 tag + u32 len + len 字节
//!
//! preamble（客户端 -> 服务端，紧贴在第一条协议消息之前）
//!   [8]  magic          b"NFRPLNK1"
//!   u8   version
//!   u64  caps
//!   u8   flags          FLAG_ENABLED / FLAG_RESUME / FLAG_QUIC
//!   [16] session        connection id
//!   u16  tlv_len
//!   TLV*
//! ```
//!
//! # 三条硬约束
//!
//! * **长度自描述**：每个 TLV 自带 `u32` 长度，不认识的 tag 直接
//!   `pos += len` 跳过，绝不因为"多了个字段"报错；
//! * **版本化**：帧头带 version。未来格式变了，老代码看到 `version != 1`
//!   会整帧忽略（返回 [`Decoded::Unknown`]），连接继续可用；
//! * **独立编号段**：TLV tag 全部落在 `0x4E00..0x4EFF`，与任何"标准帧字段"
//!   都不共享编号空间。

use anyhow::{bail, Result};

/// 单帧上限。v1 的 `DEFAULT_MAX_MSG_LENGTH` 是 10240（含 9 字节头），
/// 这里取 8192，保证扩展帧在 v1 下永远塞得进去。
pub const MAX_FRAME: usize = 8192;

/// TLV tag 的编号段前缀。
pub const TAG_BASE: u16 = 0x4E00;

pub const TAG_TRACE_ID: u16 = TAG_BASE + 1;
pub const TAG_SPAN: u16 = TAG_BASE + 2;
pub const TAG_KNOCK_TOKEN: u16 = TAG_BASE + 3;
pub const TAG_COUNT: u16 = TAG_BASE + 4;
pub const TAG_GRANTED: u16 = TAG_BASE + 5;
pub const TAG_TICKET: u16 = TAG_BASE + 6;
pub const TAG_OK: u16 = TAG_BASE + 7;
pub const TAG_IDENTITY: u16 = TAG_BASE + 8;
pub const TAG_PROXY: u16 = TAG_BASE + 9;
pub const TAG_RATE: u16 = TAG_BASE + 10;
pub const TAG_BURST: u16 = TAG_BASE + 11;
pub const TAG_ROUND: u16 = TAG_BASE + 12;
pub const TAG_TTL: u16 = TAG_BASE + 13;
pub const TAG_CODE: u16 = TAG_BASE + 14;
pub const TAG_ADDR: u16 = TAG_BASE + 15;
pub const TAG_POLICY: u16 = TAG_BASE + 16;
pub const TAG_DETAIL: u16 = TAG_BASE + 17;
pub const TAG_VERSION: u16 = TAG_BASE + 18;

/// 一个 TLV 项。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Tlv {
    pub tag: u16,
    pub value: Vec<u8>,
}

/// 有序 TLV 列表（同一 tag 出现多次时保留第一次）。
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TlvMap {
    items: Vec<Tlv>,
}

impl TlvMap {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn push(&mut self, tag: u16, value: impl Into<Vec<u8>>) {
        self.items.push(Tlv {
            tag,
            value: value.into(),
        });
    }

    pub fn with(mut self, tag: u16, value: impl Into<Vec<u8>>) -> Self {
        self.push(tag, value);
        self
    }

    pub fn push_u32(&mut self, tag: u16, v: u32) {
        self.push(tag, v.to_be_bytes().to_vec());
    }

    pub fn push_u64(&mut self, tag: u16, v: u64) {
        self.push(tag, v.to_be_bytes().to_vec());
    }

    pub fn get(&self, tag: u16) -> Option<&[u8]> {
        self.items
            .iter()
            .find(|t| t.tag == tag)
            .map(|t| t.value.as_slice())
    }

    pub fn get_str(&self, tag: u16) -> Option<String> {
        self.get(tag)
            .map(|v| String::from_utf8_lossy(v).into_owned())
    }

    pub fn get_u32(&self, tag: u16) -> Option<u32> {
        self.get(tag)
            .and_then(|v| v.get(..4))
            .map(|v| u32::from_be_bytes([v[0], v[1], v[2], v[3]]))
    }

    pub fn get_u64(&self, tag: u16) -> Option<u64> {
        self.get(tag).and_then(|v| {
            v.get(..8)
                .map(|v| u64::from_be_bytes([v[0], v[1], v[2], v[3], v[4], v[5], v[6], v[7]]))
        })
    }

    pub fn len(&self) -> usize {
        self.items.len()
    }

    pub fn is_empty(&self) -> bool {
        self.items.is_empty()
    }

    pub fn iter(&self) -> impl Iterator<Item = &Tlv> {
        self.items.iter()
    }

    fn encode_into(&self, out: &mut Vec<u8>) -> Result<()> {
        for tlv in &self.items {
            if tlv.value.len() > u32::MAX as usize {
                bail!("TLV 值过长");
            }
            out.extend_from_slice(&tlv.tag.to_be_bytes());
            out.extend_from_slice(&(tlv.value.len() as u32).to_be_bytes());
            out.extend_from_slice(&tlv.value);
        }
        Ok(())
    }

    /// 从 `buf[pos..]` 解析 TLV，直到结尾。
    ///
    /// 不认识的 tag **不报错**（这是前向兼容的核心）；只有"长度字段把
    /// 自己指到缓冲区外面"才算错 —— 那是坏帧，不是未来字段。
    fn decode_all(buf: &[u8], mut pos: usize) -> Result<Self> {
        let mut map = TlvMap::new();
        while pos < buf.len() {
            if buf.len() - pos < 6 {
                bail!("TLV 头不完整（剩 {} 字节）", buf.len() - pos);
            }
            let tag = u16::from_be_bytes([buf[pos], buf[pos + 1]]);
            let len = u32::from_be_bytes([buf[pos + 2], buf[pos + 3], buf[pos + 4], buf[pos + 5]])
                as usize;
            pos += 6;
            if buf.len() - pos < len {
                bail!("TLV 长度 {len} 超出剩余缓冲 {}", buf.len() - pos);
            }
            map.items.push(Tlv {
                tag,
                value: buf[pos..pos + len].to_vec(),
            });
            pos += len;
        }
        Ok(map)
    }
}

/// 扩展帧类型。
///
/// 数字一旦发布就不能改语义（只能新增）。不认识的一律整帧忽略。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrameKind {
    /// 端到端 trace：控制连接与数据面共享同一个 trace id。
    Trace = 1,
    /// 端口敲门（控制面授权，数据面另有魔术字敲门）。
    Knock = 2,
    /// 批量申请工作连接。
    BatchReq = 3,
    /// 批量申请的回执。
    BatchResp = 4,
    /// 断线续传：客户端出示 ticket。
    ResumeReq = 5,
    /// 断线续传的回执。
    ResumeResp = 6,
    /// 零信任身份令牌。
    Identity = 7,
    /// 限流规则下发 / 回报。
    RateLimit = 8,
    /// P2P 探测请求（TTL 阶梯）。
    NatProbe = 9,
    /// P2P 探测结果（含失败原因码）。
    NatResult = 10,
    /// XTCP 直连策略。
    XtcpPolicy = 11,
    /// 通用失败回报（带原因码）。
    Failure = 12,
    /// 兼容性边界探测。
    CompatProbe = 13,
    /// 兼容性边界探测回执。
    CompatResp = 14,
    /// 续传完成后的代理清单（客户端 -> 服务端）。
    ///
    /// 客户端在续传会话里把**最终**代理名列表发上来，服务端据此回收
    /// "上次会话有、这次配置里已经删掉"的监听器。没有这一帧时服务端
    /// 只能保守保留旧监听器到 TTL 过期。
    ResumeCommit = 15,
}

impl FrameKind {
    pub fn from_u8(v: u8) -> Option<Self> {
        Some(match v {
            1 => Self::Trace,
            2 => Self::Knock,
            3 => Self::BatchReq,
            4 => Self::BatchResp,
            5 => Self::ResumeReq,
            6 => Self::ResumeResp,
            7 => Self::Identity,
            8 => Self::RateLimit,
            9 => Self::NatProbe,
            10 => Self::NatResult,
            11 => Self::XtcpPolicy,
            12 => Self::Failure,
            13 => Self::CompatProbe,
            14 => Self::CompatResp,
            15 => Self::ResumeCommit,
            _ => return None,
        })
    }

    pub fn as_u8(self) -> u8 {
        self as u8
    }
}

/// 一条扩展帧。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Frame {
    pub kind: FrameKind,
    pub flags: u16,
    pub tlvs: TlvMap,
}

/// 解码结果。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decoded<T> {
    Known(T),
    /// 版本或类型不认识：整帧忽略，连接照常。
    Unknown {
        version: u8,
        kind: u8,
    },
}

impl Frame {
    pub fn new(kind: FrameKind) -> Self {
        Self {
            kind,
            flags: 0,
            tlvs: TlvMap::new(),
        }
    }

    pub fn with(mut self, tag: u16, value: impl Into<Vec<u8>>) -> Self {
        self.tlvs.push(tag, value);
        self
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(32);
        out.push(crate::nlink::PROTOCOL_VERSION);
        out.push(self.kind.as_u8());
        out.extend_from_slice(&self.flags.to_be_bytes());
        // 上面不可能失败（tag 与 len 都是定长），这里 unwrap 也安全；
        // 但既然返回值是 Result，就不在库内部制造 panic 点。
        let _ = self.tlvs.encode_into(&mut out);
        out
    }

    pub fn decode(buf: &[u8]) -> Result<Decoded<Self>> {
        if buf.len() < 4 {
            bail!("扩展帧头不完整（{} 字节）", buf.len());
        }
        let version = buf[0];
        let kind = buf[1];
        let flags = u16::from_be_bytes([buf[2], buf[3]]);
        if version != crate::nlink::PROTOCOL_VERSION {
            return Ok(Decoded::Unknown { version, kind });
        }
        let Some(kind) = FrameKind::from_u8(kind) else {
            return Ok(Decoded::Unknown { version, kind });
        };
        let tlvs = TlvMap::decode_all(buf, 4)?;
        Ok(Decoded::Known(Self { kind, flags, tlvs }))
    }
}

// ---------------------------------------------------------------------------
// preamble
// ---------------------------------------------------------------------------

/// 客户端第一条协议消息之前的那段"搭车"信息。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Preamble {
    pub version: u8,
    pub caps: crate::nlink::Caps,
    pub flags: u8,
    pub session: crate::nlink::ConnectionId,
    pub tlvs: TlvMap,
}

/// `magic(8) + version(1) + caps(8) + flags(1) + session(16) + tlv_len(2)`
pub const PREAMBLE_FIXED: usize = 36;

impl Preamble {
    pub fn new(caps: crate::nlink::Caps, session: crate::nlink::ConnectionId) -> Self {
        Self {
            version: crate::nlink::PROTOCOL_VERSION,
            caps,
            flags: crate::nlink::FLAG_ENABLED,
            session,
            tlvs: TlvMap::new(),
        }
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut body = Vec::with_capacity(32);
        let _ = self.tlvs.encode_into(&mut body);
        let mut out = Vec::with_capacity(PREAMBLE_FIXED + body.len());
        out.extend_from_slice(&crate::nlink::MAGIC);
        out.push(self.version);
        out.extend_from_slice(&self.caps.bits().to_be_bytes());
        out.push(self.flags);
        out.extend_from_slice(self.session.as_bytes());
        out.extend_from_slice(&(body.len() as u16).to_be_bytes());
        out.extend_from_slice(&body);
        out
    }

    /// 解析固定部分 + TLV。`buf` 不包含那 8 字节魔术字（调用方已经比对过）。
    pub fn decode_after_magic(buf: &[u8]) -> Result<Self> {
        if buf.len() < PREAMBLE_FIXED - 8 {
            bail!("preamble 不完整（{} 字节）", buf.len());
        }
        let version = buf[0];
        let caps = u64::from_be_bytes([
            buf[1], buf[2], buf[3], buf[4], buf[5], buf[6], buf[7], buf[8],
        ]);
        let flags = buf[9];
        let mut sid = [0u8; 16];
        sid.copy_from_slice(&buf[10..26]);
        let tlv_len = u16::from_be_bytes([buf[26], buf[27]]) as usize;
        if buf.len() < 28 + tlv_len {
            bail!("preamble 的 TLV 长度 {tlv_len} 超出缓冲");
        }
        let tlvs = TlvMap::decode_all(&buf[28..28 + tlv_len], 0)?;
        Ok(Self {
            version,
            caps: crate::nlink::Caps::new(caps),
            flags,
            session: crate::nlink::ConnectionId::from_bytes(sid),
            tlvs,
        })
    }

    pub fn enabled(&self) -> bool {
        self.flags & crate::nlink::FLAG_ENABLED != 0
    }

    pub fn wants_resume(&self) -> bool {
        self.flags & crate::nlink::FLAG_RESUME != 0
    }

    pub fn wants_quic(&self) -> bool {
        self.flags & crate::nlink::FLAG_QUIC != 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::nlink::{CAP_RESUME, CAP_TRACE};

    #[test]
    fn 帧往返编解码() {
        let f = Frame::new(FrameKind::BatchReq)
            .with(TAG_COUNT, 8u32.to_be_bytes().to_vec())
            .with(TAG_TRACE_ID, vec![7u8; 16]);
        let raw = f.encode();
        match Frame::decode(&raw).unwrap() {
            Decoded::Known(got) => {
                assert_eq!(got.kind, FrameKind::BatchReq);
                assert_eq!(got.tlvs.get_u32(TAG_COUNT), Some(8));
                assert_eq!(got.tlvs.get(TAG_TRACE_ID).unwrap().len(), 16);
            }
            other => panic!("应解出已知帧，实际 {other:?}"),
        }
    }

    #[test]
    fn 不认识的_tlv_被跳过而不是报错() {
        // 手工拼一个含未来 tag 的帧
        let mut raw = vec![
            crate::nlink::PROTOCOL_VERSION,
            FrameKind::Trace.as_u8(),
            0,
            0,
        ];
        raw.extend_from_slice(&0x4EFFu16.to_be_bytes()); // 未来 tag
        raw.extend_from_slice(&5u32.to_be_bytes());
        raw.extend_from_slice(b"hello");
        raw.extend_from_slice(&TAG_TRACE_ID.to_be_bytes());
        raw.extend_from_slice(&2u32.to_be_bytes());
        raw.extend_from_slice(&[9, 9]);
        match Frame::decode(&raw).unwrap() {
            Decoded::Known(f) => {
                assert_eq!(f.kind, FrameKind::Trace);
                assert_eq!(f.tlvs.get(TAG_TRACE_ID), Some(&[9u8, 9][..]));
                assert_eq!(f.tlvs.len(), 2, "未知 tag 也要保留在 map 里（可再转发）");
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn 未来版本的帧整帧忽略() {
        let raw = vec![crate::nlink::PROTOCOL_VERSION + 1, 1, 0, 0];
        match Frame::decode(&raw).unwrap() {
            Decoded::Unknown { version, kind } => {
                assert_eq!(version, crate::nlink::PROTOCOL_VERSION + 1);
                assert_eq!(kind, 1);
            }
            other => panic!("未来版本必须忽略，实际 {other:?}"),
        }
    }

    #[test]
    fn 未来帧类型整帧忽略() {
        let raw = vec![crate::nlink::PROTOCOL_VERSION, 0xFE, 0, 0];
        assert!(matches!(
            Frame::decode(&raw).unwrap(),
            Decoded::Unknown { kind: 0xFE, .. }
        ));
    }

    #[test]
    fn 坏长度必须报错() {
        let mut raw = vec![
            crate::nlink::PROTOCOL_VERSION,
            FrameKind::Trace.as_u8(),
            0,
            0,
        ];
        raw.extend_from_slice(&TAG_TRACE_ID.to_be_bytes());
        raw.extend_from_slice(&999u32.to_be_bytes());
        assert!(
            Frame::decode(&raw).is_err(),
            "长度指到缓冲外是坏帧，不能静默"
        );
    }

    #[test]
    fn preamble_往返() {
        let sid = crate::nlink::ConnectionId::random();
        let mut p = Preamble::new(crate::nlink::Caps(CAP_TRACE | CAP_RESUME), sid);
        p.flags |= crate::nlink::FLAG_RESUME;
        p.tlvs.push(TAG_TRACE_ID, vec![3u8; 16]);
        let raw = p.encode();
        assert_eq!(&raw[..8], &crate::nlink::MAGIC);
        let got = Preamble::decode_after_magic(&raw[8..]).unwrap();
        assert_eq!(got.caps, p.caps);
        assert_eq!(got.session, sid);
        assert!(got.wants_resume());
        assert_eq!(got.tlvs.get(TAG_TRACE_ID).unwrap().len(), 16);
        assert_eq!(raw.len(), PREAMBLE_FIXED + 22);
    }

    #[test]
    fn preamble_截断报错而不是猜() {
        let sid = crate::nlink::ConnectionId::random();
        let raw = Preamble::new(crate::nlink::Caps::EMPTY, sid).encode();
        for cut in [1usize, 8, 20, 27] {
            assert!(
                Preamble::decode_after_magic(&raw[8..8 + cut]).is_err(),
                "截断 {cut} 字节时必须报错"
            );
        }
    }

    /// v1 的消息长度前缀是 10240，扩展帧必须留得下 9 字节头。
    ///
    /// 用 const 断言而不是运行时 ssert!：这是**编译期常量之间的关系**，
    /// 运行期断言会被 clippy 判成"断言值恒为真"，而且真出问题时也要等到
    /// 跑测试才发现 —— const 断言让它在编译期就失败。
    const _: () = assert!(MAX_FRAME + 9 < 10240);
}
