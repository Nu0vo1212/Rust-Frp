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
/// `ResumeCommit` 分片：本片序号（从 0 开始，u16 大端）。
///
/// 代理名列表超过单帧上限时拆成多帧，每帧带这个 tag。
/// 只有一片时不带（兼容 0.7.1 的行为）。
pub const TAG_CHUNK: u16 = TAG_BASE + 19;
/// `ResumeCommit` 分片：总片数（u16 大端）。
pub const TAG_CHUNKS: u16 = TAG_BASE + 20;
/// 续传令牌（一次性）。登录成功时由服务端下发，重连时客户端带回。
pub const TAG_RESUME_TOKEN: u16 = TAG_BASE + 21;

/// `ResumeCommit` 名单的**总字节预算**（不是片数）。
///
/// 这是**防 DoS 的硬上限**：没有它，恶意客户端可以一直发分片让服务端攒内存，
/// 或者声称一个巨大的总片数然后永远不发完。
///
/// # 为什么改成按字节而不是按片数
///
/// 0.7.2 写的是"最多 64 片"，换算下来约 512 KiB —— 按每个代理名平均 40 字节
/// 算只能放 1.3 万个代理。单 frps 实际能承载的代理数虽然远小于此，但把上限
/// 硬编码成"片数"有个隐患：`MAX_FRAME` 将来变大或变小，56 KiB 的实际承载
/// 能力会跟着漂移，而代码里的常量不会跟着变。
///
/// 改成字节预算后，片数由 `总字节 / 单片预算` 自动推出，语义更稳。
///
/// 取 8 MiB：按每名 40 字节算可容纳约 20 万个代理名 —— 远超任何单机 frps 的
/// 实际承载量，同时这个量级的内存占用对服务端是完全可接受的（而且只有**续传
/// 会话**才会走到这条路径）。
pub const MAX_COMMIT_BYTES: usize = 8 * 1024 * 1024;

/// 由字节预算推出的片数上限。
///
/// 仍然保留一个片数常量供协议字段（`u16`）使用：`TAG_CHUNKS` 是 u16，
/// 不能超过 65535。8 MiB / 7.5 KiB ≈ 1093 片，远在 u16 范围内。
pub const MAX_COMMIT_CHUNKS: u16 = {
    let n = MAX_COMMIT_BYTES.div_ceil(COMMIT_CHUNK_BUDGET) as u32;
    // 编译期断言：必须能用 u16 表示
    if n > u16::MAX as u32 {
        u16::MAX
    } else {
        n as u16
    }
};

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

    /// `ResumeCommit` 分片：本片序号 / 总片数。返回 `None` 表示这是单帧（不分片）。
    pub fn commit_chunk_info(&self) -> Option<(u16, u16)> {
        let idx = self
            .get(TAG_CHUNK)
            .and_then(|v| v.get(..2))
            .map(|v| u16::from_be_bytes([v[0], v[1]]))?;
        let total = self
            .get(TAG_CHUNKS)
            .and_then(|v| v.get(..2))
            .map(|v| u16::from_be_bytes([v[0], v[1]]))?;
        Some((idx, total))
    }
}

// ---------------------------------------------------------------------------
// ResumeCommit 分片
// ---------------------------------------------------------------------------

/// 一片 `ResumeCommit` 实际能装多少字节。
///
/// 帧总上限 [`MAX_FRAME`] 减掉帧头（version+kind+flags = 4）、
/// `TAG_CHUNK` / `TAG_CHUNKS` 两个 TLV 各 6+2 字节、以及 `TAG_DETAIL`
/// 自己的 6 字节头，再留一点余量。
pub const COMMIT_CHUNK_BUDGET: usize = MAX_FRAME - 4 - (6 + 2) * 2 - 6 - 16;

/// 把代理名列表切成若干段，每段长度不超过 `budget` 字节（含换行分隔）。
///
/// # 为什么需要分片
///
/// 0.7.1 把整份名单塞进一帧的 `TAG_DETAIL`。代理名多的会话会超过
/// [`MAX_FRAME`]，客户端只能**拒绝发送**并记日志 —— 续传照样成功，但
/// "已删除的代理立即可回收"这个对账能力就静默降级成 10 秒宽限期。
///
/// 分片后不再有名单长度上限（只受 [`MAX_COMMIT_CHUNKS`] 约束）。
///
/// # 切分规则
///
/// 按**代理名边界**切，不切断单个名字。
pub fn split_commit_names(names: &[String], budget: usize) -> Vec<Vec<String>> {
    let budget = budget.max(1);
    let mut out: Vec<Vec<String>> = Vec::new();
    let mut cur: Vec<String> = Vec::new();
    let mut cur_len = 0usize;

    for name in names {
        let add = name.len() + if cur.is_empty() { 0 } else { 1 };
        if !cur.is_empty() && cur_len + add > budget {
            out.push(std::mem::take(&mut cur));
            cur_len = name.len();
            cur.push(name.clone());
        } else {
            cur_len += add;
            cur.push(name.clone());
        }
    }
    if !cur.is_empty() {
        out.push(cur);
    }
    out
}

/// 把一份名单编码成一条或多条 `ResumeCommit` 帧。
///
/// 只有一片时**不带** `TAG_CHUNK` / `TAG_CHUNKS`，与 0.7.1 的线上格式一致
/// （老服务端仍能照常解析）。
pub fn encode_resume_commit(names: &[String]) -> Vec<Frame> {
    let chunks = split_commit_names(names, COMMIT_CHUNK_BUDGET);
    if chunks.is_empty() {
        // 空名单也要发一条，表示"一个都不剩"，否则服务端不会对账
        return vec![Frame::new(FrameKind::ResumeCommit).with(TAG_DETAIL, Vec::new())];
    }
    if chunks.len() == 1 {
        return vec![
            Frame::new(FrameKind::ResumeCommit).with(TAG_DETAIL, chunks[0].join("\n").into_bytes())
        ];
    }
    let total = chunks.len() as u16;
    chunks
        .into_iter()
        .enumerate()
        .map(|(i, part)| {
            Frame::new(FrameKind::ResumeCommit)
                .with(TAG_DETAIL, part.join("\n").into_bytes())
                .with(TAG_CHUNK, (i as u16).to_be_bytes().to_vec())
                .with(TAG_CHUNKS, total.to_be_bytes().to_vec())
        })
        .collect()
}

/// 组装 `ResumeCommit` 分片。
///
/// 调用方每收到一片调用一次；返回 `Ok(Some(names))` 表示**已收齐**。
///
/// # 防护
///
/// * `total == 0` 或 `total > MAX_COMMIT_CHUNKS` 直接判错 —— 前者是坏帧，
///   后者是 DoS 尝试（否则恶意客户端可以声称 65535 片让服务端一直攒内存）；
/// * `idx >= total` 判错，防止用越界序号把表撑大；
/// * **累计字节**超过 [`MAX_COMMIT_BYTES`] 也判错 —— 片数在范围内但每片塞满时，
///   总量仍可能超出预算；
/// * 收不到的片永远不完成，但表是按会话保存的，会话断开即释放。
#[derive(Debug, Default)]
pub struct CommitAssembler {
    total: u16,
    parts: Vec<Option<Vec<String>>>,
    received: u16,
    /// 已收到的名字累计字节数（用于总的字节预算检查）。
    bytes: usize,
}

impl CommitAssembler {
    pub fn new() -> Self {
        Self::default()
    }

    /// 喂一片。返回 `Ok(Some(names))` = 收齐；`Ok(None)` = 还差。
    pub fn push(
        &mut self,
        idx: u16,
        total: u16,
        names: Vec<String>,
    ) -> Result<Option<Vec<String>>> {
        if total == 0 {
            bail!("ResumeCommit 分片总数为 0");
        }
        if total > MAX_COMMIT_CHUNKS {
            bail!("ResumeCommit 分片数 {total} 超过上限 {MAX_COMMIT_CHUNKS}");
        }
        if idx >= total {
            bail!("ResumeCommit 分片序号 {idx} 越界（总数 {total}）");
        }
        // 总片数变了说明是两轮分片混在一起，重置：只认最新一轮
        if self.total != total {
            self.total = total;
            self.parts = vec![None; total as usize];
            self.received = 0;
            self.bytes = 0;
        }

        // 字节预算：替换同一片时要先扣掉旧的
        let incoming: usize = names.iter().map(|n| n.len() + 1).sum();
        let slot = &mut self.parts[idx as usize];
        let replaced = slot
            .as_ref()
            .map(|old| old.iter().map(|n| n.len() + 1).sum::<usize>())
            .unwrap_or(0);
        let projected = self.bytes - replaced + incoming;
        if projected > MAX_COMMIT_BYTES {
            bail!("ResumeCommit 名单总量 {projected} 字节超过预算 {MAX_COMMIT_BYTES}");
        }
        if slot.is_none() {
            self.received += 1;
        }
        *slot = Some(names);
        self.bytes = projected;

        if self.received == self.total {
            let mut all: Vec<String> = Vec::new();
            // 用 flatten 而不是 `if let Some(..)` + append：
            // clippy 把后者判成"只用到 Some 变体"的多余写法。
            for v in self.parts.drain(..).flatten() {
                all.extend(v);
            }
            self.total = 0;
            self.received = 0;
            self.bytes = 0;
            return Ok(Some(all));
        }
        Ok(None)
    }

    pub fn is_idle(&self) -> bool {
        self.total == 0
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

    // ---- ResumeCommit 分片 ----

    #[test]
    fn 单帧能装下时不分片且不带分片标记() {
        let names = vec!["alice.tcp1".to_string(), "alice.tcp2".to_string()];
        let frames = encode_resume_commit(&names);
        assert_eq!(frames.len(), 1, "小名单应当只发一帧");
        assert!(
            frames[0].tlvs.commit_chunk_info().is_none(),
            "单帧不应带分片标记（保持与 0.7.1 线上格式一致）"
        );
        let body = frames[0].tlvs.get_str(TAG_DETAIL).unwrap();
        assert_eq!(body, "alice.tcp1\nalice.tcp2");
    }

    #[test]
    fn 空名单也会发一条空帧() {
        let frames = encode_resume_commit(&[]);
        assert_eq!(frames.len(), 1);
        assert_eq!(frames[0].tlvs.get_str(TAG_DETAIL).unwrap(), "");
    }

    #[test]
    fn 超长名单会分片且每片都不超上限() {
        // 造 2000 个名字，每个 40 字节 → 约 80 KB，必然超过单帧
        let names: Vec<String> = (0..2000)
            .map(|i| format!("user{i:04}.proxy-name-padding-xxxx"))
            .collect();
        let frames = encode_resume_commit(&names);
        assert!(frames.len() > 1, "应当被拆成多帧（实际 {}）", frames.len());
        assert!(
            frames.len() <= MAX_COMMIT_CHUNKS as usize,
            "片数不能超过上限"
        );
        for f in &frames {
            let detail_len = f.tlvs.get(TAG_DETAIL).map(|v| v.len()).unwrap_or(0);
            assert!(
                detail_len <= COMMIT_CHUNK_BUDGET,
                "单片 {detail_len} 字节超过预算 {COMMIT_CHUNK_BUDGET}"
            );
        }
    }

    #[test]
    fn 分片按名字边界切不切断单个名字() {
        let names: Vec<String> = (0..300)
            .map(|i| format!("u{i}.a-fairly-long-proxy-name-for-testing"))
            .collect();
        let chunks = split_commit_names(&names, COMMIT_CHUNK_BUDGET);
        let mut flat: Vec<String> = Vec::new();
        for c in &chunks {
            for n in c {
                // 每个名字都必须是完整的
                assert!(names.contains(n), "分片里出现了被截断的名字：{n}");
                flat.push(n.clone());
            }
        }
        assert_eq!(flat, names, "重组后必须与原始顺序完全一致");
    }

    #[test]
    fn 组装器收齐后返回完整名单() {
        let names: Vec<String> = (0..1500)
            .map(|i| format!("user.proxy-{i:05}-padding-xxxxxxxx"))
            .collect();
        let frames = encode_resume_commit(&names);
        assert!(frames.len() > 1);

        let mut asm = CommitAssembler::new();
        let mut got: Option<Vec<String>> = None;
        for f in &frames {
            let (idx, total) = f.tlvs.commit_chunk_info().expect("应当是分片帧");
            let part: Vec<String> = f
                .tlvs
                .get_str(TAG_DETAIL)
                .unwrap_or_default()
                .split('\n')
                .filter(|s| !s.is_empty())
                .map(|s| s.to_string())
                .collect();
            if let Some(all) = asm.push(idx, total, part).unwrap() {
                got = Some(all);
            }
        }
        let got = got.expect("应当收齐");
        assert_eq!(got, names, "重组的名单必须与原始一致");
        assert!(asm.is_idle(), "收齐后组装器应复位");
    }

    #[test]
    fn 分片数超上限被拒() {
        let mut asm = CommitAssembler::new();
        let e = asm
            .push(0, MAX_COMMIT_CHUNKS.saturating_add(1), vec!["x".into()])
            .unwrap_err();
        assert!(format!("{e:#}").contains("超过上限"), "应当报超限：{e:#}");
    }

    /// 片数在范围内、但**累计字节**超预算时也必须拒。
    ///
    /// 这是 0.7.4 新加的防护：0.7.2 只按"片数 ≤ 64"限，现在改成按字节预算，
    /// 就需要一条针对"每片塞满"的测试 —— 否则片数合法却能把内存吃光。
    #[test]
    fn 累计字节超预算被拒() {
        let mut asm = CommitAssembler::new();
        // 单片塞到预算的一半，两片就超
        let half = MAX_COMMIT_BYTES / 2;
        let big = "x".repeat(half);

        // 第一片：约占一半，能收下
        asm.push(0, 2, vec![big.clone()])
            .expect("单片占一半预算应当可以");

        // 第二片：再来一半 → 超预算
        let e = asm.push(1, 2, vec![big]).unwrap_err();
        assert!(
            format!("{e:#}").contains("超过预算"),
            "累计超预算必须报错：{e:#}"
        );
    }

    /// 预算上限足够装下非常大的名单。
    ///
    /// 0.7.2 的 64 片 ≈ 512 KiB（约 1.3 万代理）；0.7.4 提到 8 MiB
    /// （约 20 万代理）。这条测试钉住"上限不能被悄悄改小"。
    #[test]
    fn 预算能装下十万级代理名() {
        // 造 5 万个 40 字节的代理名 ≈ 2 MB，仍在预算内
        let names: Vec<String> = (0..50_000)
            .map(|i| format!("u.proxy-{i:06}-padding-xxxxxxxx"))
            .collect();
        let total: usize = names.iter().map(|n| n.len() + 1).sum();
        assert!(
            total < MAX_COMMIT_BYTES,
            "5 万个代理名（{total} 字节）应当能装进预算 {MAX_COMMIT_BYTES}"
        );

        let frames = encode_resume_commit(&names);
        assert!(
            frames.len() <= MAX_COMMIT_CHUNKS as usize,
            "片数 {} 不应超过上限 {}",
            frames.len(),
            MAX_COMMIT_CHUNKS
        );

        // 走一遍完整重组，确认大名单不会在中途出问题
        let mut asm = CommitAssembler::new();
        let mut got = None;
        for f in &frames {
            let (idx, tot) = f.tlvs.commit_chunk_info().expect("多帧必须带分片标记");
            let part: Vec<String> = f
                .tlvs
                .get_str(TAG_DETAIL)
                .unwrap_or_default()
                .lines()
                .filter(|s| !s.is_empty())
                .map(|s| s.to_string())
                .collect();
            if let Some(all) = asm.push(idx, tot, part).expect("分片合法") {
                got = Some(all);
            }
        }
        assert_eq!(
            got.expect("必须收齐").len(),
            50_000,
            "重组的代理数必须对得上"
        );
    }

    #[test]
    fn 分片序号越界被拒() {
        let mut asm = CommitAssembler::new();
        let e = asm.push(3, 3, vec!["x".into()]).unwrap_err();
        assert!(format!("{e:#}").contains("越界"), "应当报越界：{e:#}");
    }

    #[test]
    fn 分片总数为零被拒() {
        let mut asm = CommitAssembler::new();
        let e = asm.push(0, 0, vec!["x".into()]).unwrap_err();
        assert!(format!("{e:#}").contains("总数为 0"), "应当报错：{e:#}");
    }

    #[test]
    fn 分片乱序到达也能正确重组() {
        let mut asm = CommitAssembler::new();
        // 先喂第 2 片，再喂第 1 片，最后第 0 片
        assert!(asm.push(2, 3, vec!["c".into()]).unwrap().is_none());
        assert!(asm.push(1, 3, vec!["b".into()]).unwrap().is_none());
        let all = asm.push(0, 3, vec!["a".into()]).unwrap().expect("收齐");
        // 结果必须按片序号排序，不是按到达顺序
        assert_eq!(all, vec!["a".to_string(), "b".into(), "c".into()]);
    }

    #[test]
    fn 重复到达的分片不会重复计入() {
        let mut asm = CommitAssembler::new();
        assert!(asm.push(0, 2, vec!["a".into()]).unwrap().is_none());
        // 同一片再来一次：不应把 received 加两次
        assert!(asm.push(0, 2, vec!["a".into()]).unwrap().is_none());
        let all = asm.push(1, 2, vec!["b".into()]).unwrap().expect("收齐");
        assert_eq!(all, vec!["a".to_string(), "b".into()]);
    }

    #[test]
    fn 新一轮分片会重置旧状态() {
        let mut asm = CommitAssembler::new();
        // 上一轮只到了一片就断了
        assert!(asm.push(0, 3, vec!["old".into()]).unwrap().is_none());
        // 新一轮：总数变成 2
        assert!(asm.push(0, 2, vec!["new1".into()]).unwrap().is_none());
        let all = asm.push(1, 2, vec!["new2".into()]).unwrap().expect("收齐");
        assert_eq!(
            all,
            vec!["new1".to_string(), "new2".into()],
            "不能混进上一轮的数据"
        );
    }
}
