//! frp 连接：帧读写、明密文阶段切换、两套线协议（v1 / v2）的握手流程。
//!
//! 同一个 [`FrpConn`] 同时支持 v1 与 v2 —— 两者的差别被收敛成三件事：
//!
//! | | v1 | v2 |
//! |---|---|---|
//! | 外层容器 | `[类型字节][i64 长度][JSON]` | `[u16 类型号][JSON]` 装进帧 |
//! | 登录前 | 什么都不发，直接发 Login | 先发魔术字 + ClientHello，收 ServerHello |
//! | 登录后加密 | AES-128-CFB 流密码 | AES-256-GCM AEAD 帧流 |
//!
//! 消息体本身两套协议完全一样，由 [`super::msg::FrpMessage::encode_body`] 产出。
//!
//! # 服务端自动探测
//!
//! 与官方 frps 的 `wire.CheckMagic` 行为一致：先读 8 字节，等于 v2 魔术字就
//! 走 v2，否则把这 8 字节**回填**当 v1 的消息前缀 —— 所以同一个端口能同时
//! 服务两套协议的客户端，不需要任何配置。

use super::stream::BoxStream;
use anyhow::{anyhow, bail, Result};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::util::now_unix_secs;

use super::crypto::{derive_control_keys, transcript_hash, AeadReader, AeadWriter};
use super::msg;
use super::msg::{FrpMessage, Login, LoginResp, NewVisitorConn, NewWorkConn, StartWorkConn};
use super::v1;
use super::wire::{
    self, ClientHello, ServerHello, FRAME_CLIENT_HELLO, FRAME_MESSAGE, FRAME_SERVER_HELLO, MAGIC_V2,
};
use super::WireVersion;

// NLink 扩展层（编译期可关：关掉时下面所有 `#[cfg]` 分支都不存在）
use crate::nlink;

/// 缓冲区上限，避免对端恶意灌数据。
const MAX_BUFFER: usize = 8 * 1024 * 1024;

/// 解密后明文的缓冲上限（v0.5.4，M6）。
///
/// 与 [`MAX_BUFFER`] 同量级：`plain` 是"已解密、还没被上层取走"的字节，
/// 正常运行时它几乎是空的（上层每条消息都会取走）。真堆到这个量级
/// 只可能是对端在灌数据 ⇒ 断开。
const MAX_PLAIN: usize = 8 * 1024 * 1024;

/// v2 的控制通道加密状态（AES-256-GCM AEAD 帧流，`golib/crypto/aead_stream.go`）。
///
/// 单独成结构体并装箱，理由见 [`ControlCrypto`]。
struct V2Crypto {
    writer: AeadWriter,
    reader: AeadReader,
}

/// 控制通道的加密状态。
///
/// 三条状态互斥，对应"握手明文期 / v1 登录后 / v2 登录后"。
///
/// 两个加密变体内的密码学状态都有一两 KB（AES 轮密钥展开 + 收发缓冲区），
/// 而一条连接只持有一份、生命周期与连接等长，所以统一装箱：
/// 否则 `FrpConn` 每条连接都要多背 1.6 KB 的枚举体量，
/// **而且明文态（工作连接/visitor 连接，数量远多于控制连接）也得跟着背**。
enum ControlCrypto {
    /// 明文：v1 登录前的握手阶段，以及所有工作连接/visitor 连接。
    None,
    /// v1：AES-128-CFB 流密码（`golib/crypto`）。
    V1(Box<v1::CryptoStream>),
    /// v2：AES-256-GCM AEAD 帧流。
    V2(Box<V2Crypto>),
}

/// 一条 frp 连接（v1 或 v2）。
///
/// 握手阶段为明文，握手成功后按协议切换加密：
/// v1 用 [`FrpConn::enable_v1_crypto`]，v2 用 [`FrpConn::upgrade`]。
pub struct FrpConn {
    stream: BoxStream,
    /// 本连接使用的线协议。
    version: WireVersion,
    /// 从套接字读到的原始字节（加密阶段为密文）。
    raw: Vec<u8>,
    /// 解密后的明文（仅加密阶段使用）。
    plain: Vec<u8>,
    crypto: ControlCrypto,
    /// UDP 报文用二进制编码（**v2** 握手协商结果），默认 JSON。
    udp_binary: bool,
    /// v1 下也用二进制 UDP 编码（私有能力协商结果），默认 JSON。
    v1_udp_binary: bool,
    /// NLink 扩展状态：**只有协商成功（服务端在 LoginResp 里回显）才存在**。
    nlink: Option<NLinkState>,
    /// `detect_version` 吃到的 preamble，等握手阶段取走。
    nlink_pending: Option<nlink::Preamble>,
}

/// 一条连接上的 NLink 状态。
///
/// 生命周期与连接等长；协商结果**中途不改**（这是约束 1 的要求：
/// 一次协商决定本次连接的全部行为）。
#[derive(Debug, Clone)]
pub struct NLinkState {
    /// 双方确认启用的能力（交集）。
    pub caps: nlink::Caps,
    /// 客户端进程级的 connection id（断线续传 / QUIC 迁移共用）。
    pub session: nlink::ConnectionId,
    /// 端到端 trace id。
    pub trace: nlink::TraceId,
    /// 客户端在 preamble 里是否要求续传。
    pub resume: bool,
    /// 抢占式取走的扩展帧（`recv_msg` 顺手收进来的）。
    pub inbox: Vec<nlink::Frame>,
}

impl NLinkState {
    pub fn new(caps: nlink::Caps, session: nlink::ConnectionId, trace: nlink::TraceId) -> Self {
        Self {
            caps,
            session,
            trace,
            resume: false,
            inbox: Vec::new(),
        }
    }
}

/// `recv_event` 的返回：普通消息 / 扩展帧 / 对端关闭。
///
/// 为什么不让扩展帧伪装成 `FrpMessage`：那会污染消息枚举，所有 match 都得
/// 多一条永真分支。分开返回，控制循环只在需要时处理扩展帧。
///
/// `Msg` 里的 `FrpMessage` 有 584 字节，而扩展帧只有 32 字节 —— 枚举按最大
/// 变体开内存，若直接内联，**每一条**扩展帧事件都要按 584 字节搬运。装箱后
/// 两个变体都只剩一个指针，热路径（每条消息都会走这里）拷贝成本立降。
pub enum ConnEvent {
    Msg(Box<FrpMessage>),
    NLink(nlink::Frame),
    Closed,
}

impl FrpConn {
    pub fn new(stream: BoxStream, version: WireVersion) -> Self {
        Self {
            stream,
            version,
            raw: Vec::new(),
            plain: Vec::new(),
            crypto: ControlCrypto::None,
            udp_binary: false,
            v1_udp_binary: false,
            nlink: None,
            nlink_pending: None,
        }
    }

    /// 本连接的线协议。
    pub fn version(&self) -> WireVersion {
        self.version
    }

    /// 协商成功后的 NLink 状态；未协商时为 `None`。
    pub fn nlink(&self) -> Option<&NLinkState> {
        self.nlink.as_ref()
    }

    pub fn nlink_mut(&mut self) -> Option<&mut NLinkState> {
        self.nlink.as_mut()
    }

    /// 启用 NLink（**只能在服务端回显 / 客户端收到回显之后调用**）。
    pub fn enable_nlink(&mut self, state: NLinkState) {
        self.nlink = Some(state);
    }

    /// 服务端在 `detect_version` 里吃到的 preamble（未探测到则为 `None`）。
    pub fn take_preamble(&mut self) -> Option<nlink::Preamble> {
        self.nlink_pending.take()
    }

    /// 在读满 `n` 字节之前持续从套接字补数据。
    async fn fill_exact(&mut self, n: usize) -> Result<()> {
        while self.raw.len() < n {
            if !self.fill().await? {
                bail!("对端在读满 {n} 字节前就断开了（已读 {}）", self.raw.len());
            }
        }
        Ok(())
    }

    /// 解析 preamble 的固定部分 + TLV（魔术字已由调用方消费）。
    async fn read_nlink_preamble(&mut self) -> Result<nlink::Preamble> {
        // 固定部分去掉魔术字后是 28 字节：version(1)+caps(8)+flags(1)+sid(16)+tlv_len(2)
        let fixed = nlink::frame::PREAMBLE_FIXED - nlink::MAGIC.len();
        self.fill_exact(fixed).await?;
        let tlv_len = u16::from_be_bytes([self.raw[26], self.raw[27]]) as usize;
        if tlv_len > nlink::frame::MAX_FRAME {
            bail!("preamble 的 TLV 部分过长（{tlv_len}）");
        }
        self.fill_exact(fixed + tlv_len).await?;
        let pre = nlink::Preamble::decode_after_magic(&self.raw[..fixed + tlv_len])?;
        self.raw.drain(..fixed + tlv_len);
        Ok(pre)
    }

    /// 在**任何协议字节之前**写入一段原始字节（目前只有 NLink preamble 用）。
    ///
    /// 故意不复用 `write_bytes`：preamble 必须走明文，且必须在 v2 魔术字之前。
    pub async fn write_preamble(&mut self, pre: &nlink::Preamble) -> Result<()> {
        let raw = pre.encode();
        self.stream.write_all(&raw).await?;
        self.stream.flush().await?;
        Ok(())
    }

    /// 发送一条扩展帧。
    ///
    /// 未协商成功时**拒绝发送**：宁可报错，也不能让一条没有协商的连接
    /// 凭空出现扩展字节（对端会当成坏帧）。
    pub async fn send_nlink(&mut self, frame: &nlink::Frame) -> Result<()> {
        if self.nlink.is_none() {
            bail!("NLink 未协商成功，不能发送扩展帧");
        }
        let payload = frame.encode();
        if payload.len() > nlink::frame::MAX_FRAME {
            bail!("扩展帧过大（{} 字节）", payload.len());
        }
        match self.version {
            WireVersion::V2 => self.write_frame(nlink::V2_FRAME_TYPE, &payload).await,
            WireVersion::V1 => {
                // 与普通消息走同一条加密路径：登录后扩展帧也是密文。
                let raw = v1::encode_msg(nlink::V1_TYPE_BYTE, &payload);
                self.write_bytes(&raw).await
            }
        }
    }

    /// 探测并锁定线协议（仅服务端用）。
    ///
    /// 严格对照官方 `pkg/proto/wire/wire.go` 的 `CheckMagic`：
    /// 读满 8 字节，与 v2 魔术字逐字节比较；相同则**消费掉**这 8 字节走 v2，
    /// 不同则**原样留在缓冲区里**走 v1（那 8 字节本来就是 v1 的
    /// 类型字节 + 长度前缀）。
    ///
    /// 官方用 `libnet.NewSharedConnSize` 把已读的字节"塞回去"，这里等价地
    /// 让字节留在 `raw` 缓冲区，后续解析照常从 `raw` 开头继续。
    pub async fn detect_version(&mut self) -> Result<WireVersion> {
        // 一次性读满两者里更长的那个：`MAGIC_V2` 是 7 字节（`FRP\0\x02\r\n`），
        // NLink 魔术字是 8 字节（`NFRPLNK1`）。只按 `MAGIC_V2.len()` 去填，
        // 紧接着切 8 字节会**越界 panic** —— 一个只发 7 字节就闭嘴的客户端
        // 足以打挂服务端，所以这里按较长者取。
        let probe = MAGIC_V2.len().max(nlink::MAGIC.len());
        self.fill_exact(probe).await?;

        // ---- NLink preamble（可选，搭车在第一条协议消息之前）----
        //
        // 首字节 `N` 是标准 frp 永远不会产生的：v1 首字节是 `{`（JSON），
        // v2 是 `F`（FRP 魔术字），TLS 是 0x16。所以这里不会误判。
        if self.raw[..nlink::MAGIC.len()] == nlink::MAGIC {
            self.raw.drain(..nlink::MAGIC.len());
            let pre = self.read_nlink_preamble().await?;
            self.nlink_pending = Some(pre);
            // preamble 之后才是真正的协议字节，重新读满再判断
            self.fill_exact(probe).await?;
        }

        if self.raw[..MAGIC_V2.len()] == *MAGIC_V2 {
            self.raw.drain(..MAGIC_V2.len());
            self.version = WireVersion::V2;
        } else {
            // v1：这 8 字节属于第一条消息，留在 raw 里等 take_msg 消费
            self.version = WireVersion::V1;
        }
        Ok(self.version)
    }

    /// 设置 UDP 报文编码（由 **v2** 握手协商结果决定）。
    pub fn set_udp_codec(&mut self, binary: bool) {
        self.udp_binary = binary;
    }

    pub fn udp_codec_is_binary(&self) -> bool {
        self.udp_binary
    }

    /// v1 下改用二进制 UDP 报文编码。
    ///
    /// 只能在**双方都声明了该能力**之后调用（见 `msg::NfrpCaps`）：
    /// v1 没有握手协商这一步，官方 frps 只会发 JSON，
    /// 单方面开启会让两端的编码对不上。
    pub fn set_v1_udp_binary(&mut self, binary: bool) {
        self.v1_udp_binary = binary;
    }

    /// 本连接上 UDP 报文是不是走二进制编码（v1 / v2 各有一个开关）。
    pub fn udp_is_binary(&self) -> bool {
        if self.version == WireVersion::V1 {
            self.v1_udp_binary
        } else {
            self.udp_binary
        }
    }

    /// 写入 v2 魔术字（客户端在 v2 下必须先发）。v1 下什么都不做。
    pub async fn write_magic(&mut self) -> Result<()> {
        if self.version.is_v2() {
            self.stream.write_all(MAGIC_V2).await?;
            self.stream.flush().await?;
        }
        Ok(())
    }

    /// v1：登录成功后给控制连接套上 AES-128-CFB 流密码。
    ///
    /// 时序必须与官方一致 —— **`Login` 与 `LoginResp` 都是明文**，
    /// 加密从下一条消息开始（Go 的 `crypto.Writer` 是惰性的：第一次写才发 IV）。
    pub fn enable_v1_crypto(&mut self, token: &str) -> Result<()> {
        if self.version != WireVersion::V1 {
            bail!("v1 控制通道加密只能用在 v1 连接上");
        }
        self.crypto = ControlCrypto::V1(Box::new(v1::CryptoStream::new(token)));
        Ok(())
    }

    /// v2：切换为 AEAD 加密帧流。
    pub fn upgrade(&mut self, read_key: Vec<u8>, write_key: Vec<u8>) -> Result<()> {
        if self.version != WireVersion::V2 {
            bail!("AEAD 升级只能用在 v2 连接上");
        }
        self.crypto = ControlCrypto::V2(Box::new(V2Crypto {
            writer: AeadWriter::new(&write_key)?,
            reader: AeadReader::new(&read_key)?,
        }));
        // ★ 已经把**密文**读进 `raw` 的那部分，必须当场解出来。
        //
        // 典型场景：服务端回完 LoginResp（明文）后立刻推数据（NLink 的身份令牌、
        // 续传回执、批量申请）。两次 `write` 经常被合进同一个 TCP 段，于是
        // `take_frame` 消费掉 LoginResp 之后，`raw` 里剩下的正是加密记录。
        // 如果等到下一次 `fill()` 才处理，`read_buf()` 已经切到 `plain`，
        // 这批字节就再也没人解密 —— 症状是"对端日志明明说发了，本端一直阻塞"。
        self.decrypt_raw_into_plain()
    }

    /// 把 `raw` 里**已经收到**的密文解进 `plain`（可重复调用，幂等）。
    ///
    /// 解密不完整时剩余字节留在 `raw` 里等下一次 `fill()` 补齐。
    fn decrypt_raw_into_plain(&mut self) -> Result<()> {
        match &mut self.crypto {
            ControlCrypto::None => {}
            ControlCrypto::V1(c) => {
                // v1 是流密码：把缓冲区里所有能解的字节都解出来
                let pt = c.decrypt(&mut self.raw);
                // ★★ v0.5.4 修 M6：`plain` 也必须有自己的硬顶。
                //
                // 原先只卡了 `raw`（`fill` 里的 MAX_BUFFER），`plain` 完全没有上限。
                // 后果：**未认证**的连接就能让对端不断喂数据，把已解密明文堆到
                // 远大于 8 MiB —— 攻击者只需建约 1000 条连接（受系统 fd 限制）
                // 就能吃掉接近 8 GB 内存，无需任何凭据。
                //
                // 为什么 8 MiB 够：`plain` 里的数据会被上层按消息/帧消费掉，
                // 正常情况下几乎总是空的。真堆到 8 MiB 说明对端在灌数据而我们
                // 没消费 —— 那本身就是异常，断开是对的。
                if self.plain.len() + pt.len() > MAX_PLAIN {
                    bail!("解密缓冲超限（{MAX_PLAIN} 字节），断开连接");
                }
                self.plain.extend_from_slice(&pt);
            }
            ControlCrypto::V2(v) => {
                while let Some(pt) = v.reader.open(&mut self.raw)? {
                    if self.plain.len() + pt.len() > MAX_PLAIN {
                        bail!("解密缓冲超限（{MAX_PLAIN} 字节），断开连接");
                    }
                    self.plain.extend_from_slice(&pt);
                }
            }
        }
        Ok(())
    }

    pub fn is_encrypted(&self) -> bool {
        !matches!(self.crypto, ControlCrypto::None)
    }

    /// 写一个 v2 帧。v1 没有帧概念，调用会报错 —— 走 [`FrpConn::send_msg`]。
    pub async fn write_frame(&mut self, frame_type: u16, payload: &[u8]) -> Result<()> {
        if self.version != WireVersion::V2 {
            bail!("v1 协议没有帧结构，请用 send_msg");
        }
        let raw = wire::encode_frame(frame_type, payload);
        self.write_bytes(&raw).await
    }

    /// 读一个 v2 帧；对端干净关闭时返回 `Ok(None)`。
    pub async fn read_frame(&mut self) -> Result<Option<(u16, Vec<u8>)>> {
        if self.version != WireVersion::V2 {
            bail!("v1 协议没有帧结构");
        }
        loop {
            {
                let buf = self.read_buf();
                if let Some(frame) = take_frame(buf)? {
                    return Ok(Some(frame));
                }
            }
            if !self.fill().await? {
                return Ok(None);
            }
        }
    }

    /// 发送一条消息（两套协议共用入口）。
    ///
    /// UDP 报文（`UdpPacket`）在 **v2** 协商为 binary codec 时会改用二进制编码，
    /// 与官方 frp 的 `V2BinaryUDPPacketReadWriter` 保持一致；v1 没有这套协商，
    /// 永远走 JSON。
    pub async fn send_msg(&mut self, m: &FrpMessage) -> Result<()> {
        match self.version {
            WireVersion::V2 => {
                if self.udp_binary {
                    if let FrpMessage::UdpPacket(pkt) = m {
                        let body = msg::encode_udp_binary(pkt)?;
                        let mut payload = Vec::with_capacity(2 + body.len());
                        payload.extend_from_slice(&msg::TYPE_UDP_PACKET_BINARY.to_be_bytes());
                        payload.extend_from_slice(&body);
                        return self.write_frame(FRAME_MESSAGE, &payload).await;
                    }
                }
                let payload = m.encode()?;
                self.write_frame(FRAME_MESSAGE, &payload).await
            }
            WireVersion::V1 => {
                if self.v1_udp_binary {
                    if let FrpMessage::UdpPacket(pkt) = m {
                        // 类型字节仍然是官方的 'u'，只是**消息体**换成二进制。
                        // 两端都只在协商成功后才这么做，官方 frps 永远走下面的 JSON 分支。
                        let body = msg::encode_udp_binary(pkt)?;
                        let frame = v1::encode_msg(v1::TYPE_UDP_PACKET, &body);
                        return self.write_bytes(&frame).await;
                    }
                }
                let byte = v1::type_byte(m.type_id()).ok_or_else(|| {
                    anyhow!(
                        "消息 {} 在 frp v1 里没有对应的类型字节（它是 v2 独有的）",
                        m.name()
                    )
                })?;
                let frame = v1::encode_msg(byte, &m.encode_body()?);
                self.write_bytes(&frame).await
            }
        }
    }

    /// 优雅关闭：先 flush，再对底层流 shutdown。
    ///
    /// 用于「回一条错误响应就断开」的场景（如 visitor 被拒）：
    /// 直接 drop 会让 yamux 流以 RST 收场，对端只能看到 `connection reset`，
    /// 读不到我们刚写进去的 error 文本。
    pub async fn shutdown(&mut self) -> Result<()> {
        self.stream.flush().await.ok();
        self.stream.shutdown().await.ok();
        Ok(())
    }

    /// 接收一个事件：普通消息 / NLink 扩展帧 / 对端关闭。
    ///
    /// 未来版本 / 未来类型的扩展帧会被**整帧跳过**（记录 debug 日志），
    /// 继续等下一条 —— 这是前向兼容的落点。
    pub async fn recv_event(&mut self) -> Result<ConnEvent> {
        loop {
            match self.version {
                WireVersion::V2 => {
                    let Some((ft, payload)) = self.read_frame().await? else {
                        return Ok(ConnEvent::Closed);
                    };
                    if ft == nlink::V2_FRAME_TYPE {
                        if self.nlink.is_none() {
                            bail!("未协商 NLink 却收到扩展帧");
                        }
                        match nlink::Frame::decode(&payload)? {
                            nlink::frame::Decoded::Known(f) => return Ok(ConnEvent::NLink(f)),
                            nlink::frame::Decoded::Unknown { version, kind } => {
                                tracing::debug!(version, kind, "跳过不认识的 NLink 扩展帧");
                                continue;
                            }
                        }
                    }
                    if ft != FRAME_MESSAGE {
                        // 未知**帧类型**整帧跳过：v2 的帧头带长度，跳过是安全的，
                        // 而且这是"以后加新帧类型不炸老版本"的唯一前提。
                        // 与 TLV / 未知 NLink 帧种类的处理保持一致。
                        //
                        // 注意 v1 没这个待遇：v1 消息类型写在 JSON 的第一字节上，
                        // 官方 frps 遇到不认识的类型会直接断开，我们也一样
                        // （见下面 `FrpMessage::decode` 的错误分支）。
                        tracing::debug!(frame_type = ft, "跳过不认识的 v2 帧类型");
                        continue;
                    }
                    if payload.len() < 2 {
                        bail!("消息帧负载过短");
                    }
                    let type_id = u16::from_be_bytes([payload[0], payload[1]]);
                    if type_id == msg::TYPE_UDP_PACKET_BINARY {
                        let pkt = msg::decode_udp_binary(&payload[2..])?;
                        return Ok(ConnEvent::Msg(Box::new(FrpMessage::UdpPacket(pkt))));
                    }
                    return Ok(ConnEvent::Msg(Box::new(FrpMessage::decode(
                        type_id,
                        &payload[2..],
                    )?)));
                }
                WireVersion::V1 => {
                    let taken = {
                        let buf = self.read_buf();
                        v1::take_msg(buf)?
                    };
                    let Some((byte, body)) = taken else {
                        if !self.fill().await? {
                            return Ok(ConnEvent::Closed);
                        }
                        continue;
                    };
                    if byte == nlink::V1_TYPE_BYTE {
                        if self.nlink.is_none() {
                            bail!("未协商 NLink 却收到扩展帧");
                        }
                        match nlink::Frame::decode(&body)? {
                            nlink::frame::Decoded::Known(f) => return Ok(ConnEvent::NLink(f)),
                            nlink::frame::Decoded::Unknown { version, kind } => {
                                tracing::debug!(version, kind, "跳过不认识的 NLink 扩展帧");
                                continue;
                            }
                        }
                    }
                    let type_id = v1::type_id(byte).expect("take_msg 已校验过类型字节");
                    if self.v1_udp_binary && byte == v1::TYPE_UDP_PACKET {
                        return Ok(ConnEvent::Msg(Box::new(FrpMessage::UdpPacket(
                            msg::decode_udp_binary(&body)?,
                        ))));
                    }
                    return Ok(ConnEvent::Msg(Box::new(FrpMessage::decode(
                        type_id, &body,
                    )?)));
                }
            }
        }
    }

    /// 接收一条消息。
    ///
    /// 收到扩展帧时顺手放进 `inbox`（供 [`FrpConn::nlink`] 取用），
    /// 然后继续等下一条消息 —— 这样**所有老调用点都不用改**。
    pub async fn recv_msg(&mut self) -> Result<Option<FrpMessage>> {
        loop {
            match self.recv_event().await? {
                ConnEvent::Msg(m) => return Ok(Some(*m)),
                ConnEvent::NLink(f) => {
                    if let Some(n) = self.nlink.as_mut() {
                        n.inbox.push(f);
                    }
                }
                ConnEvent::Closed => return Ok(None),
            }
        }
    }

    /// 当前应该从哪个缓冲区取明文帧 / 消息。
    ///
    /// 加密阶段读解密后的 `plain`，明文阶段直接读 `raw`。
    fn read_buf(&mut self) -> &mut Vec<u8> {
        if self.is_encrypted() {
            &mut self.plain
        } else {
            &mut self.raw
        }
    }

    /// 把一段**明文**写出去（内部按当前加密状态处理）。
    async fn write_bytes(&mut self, data: &[u8]) -> Result<()> {
        match &mut self.crypto {
            ControlCrypto::None => self.stream.write_all(data).await?,
            ControlCrypto::V1(c) => {
                let enc = c.encrypt(data);
                self.stream.write_all(&enc).await?;
            }
            ControlCrypto::V2(v) => {
                let enc = v.writer.seal(data)?;
                self.stream.write_all(&enc).await?;
            }
        }
        self.stream.flush().await?;
        Ok(())
    }

    /// 从套接字补数据；返回 false 表示 EOF。
    async fn fill(&mut self) -> Result<bool> {
        let mut chunk = [0u8; 16 * 1024];
        let n = self.stream.read(&mut chunk).await?;
        if n == 0 {
            return Ok(false);
        }
        if self.raw.len() + n > MAX_BUFFER {
            bail!("接收缓冲区超限");
        }
        self.raw.extend_from_slice(&chunk[..n]);
        self.decrypt_raw_into_plain()?;
        Ok(true)
    }

    /// 交回底层 BoxStream 以及**尚未消费**的残留字节。
    ///
    /// 工作连接握手完成后要转原始字节流转发，残留字节必须交给调用方，
    /// 否则会丢掉用户已经发来的第一笔数据。
    pub fn into_stream(mut self) -> (BoxStream, Vec<u8>) {
        // 加密阶段返回解密后的明文；明文阶段默认 v2 语义（工作连接不加密，
        // 只有 v2 控制连接会走到这里之外的分支）。
        let leftover = if self.is_encrypted() {
            std::mem::take(&mut self.plain)
        } else {
            std::mem::take(&mut self.raw)
        };
        (self.stream, leftover)
    }

    /// 把一段**已读但未消费**的握手残留字节塞回读缓冲（与 [`FrpConn::into_stream`] 配对）。
    ///
    /// 握手函数（`client_visitor_conn` 等）交还的是裸流 + 残留字节：裸字节转发的
    /// 调用方（stcp）把残留直接写给对端就行，但**还要按消息继续收发**的调用方
    /// （SUDP 的 visitor 工作连接）必须把这段塞回 `FrpConn`，否则对端在握手响应
    /// 之后紧接着发来的第一帧会被静默吞掉 —— 症状是"偶发丢第一个包"，极难查。
    ///
    /// `encrypted` 表示这段字节是密文还是明文：加密阶段 `into_stream` 交出的是
    /// 解密后的明文，得塞进 `plain`；明文阶段直接塞进 `raw`。
    pub fn push_leftover(&mut self, leftover: Vec<u8>, encrypted: bool) {
        if encrypted {
            self.plain.extend_from_slice(&leftover);
        } else {
            self.raw.extend_from_slice(&leftover);
        }
    }
}

/// 从缓冲区里切出一个 v2 帧（`8 字节头 + payload`）。
fn take_frame(buf: &mut Vec<u8>) -> Result<Option<(u16, Vec<u8>)>> {
    if buf.len() < 8 {
        return Ok(None);
    }
    let frame_type = u16::from_be_bytes([buf[0], buf[1]]);
    let flags = u16::from_be_bytes([buf[2], buf[3]]);
    if flags != 0 {
        bail!("不支持的帧 flags: {flags}");
    }
    let len = u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]) as usize;
    if len > wire::MAX_FRAME_PAYLOAD {
        bail!("帧负载 {} 超过上限 {}", len, wire::MAX_FRAME_PAYLOAD);
    }
    if buf.len() < 8 + len {
        return Ok(None);
    }
    let payload = buf[8..8 + len].to_vec();
    buf.drain(..8 + len);
    Ok(Some((frame_type, payload)))
}

/// 构造登录消息（两套协议共用）。
///
/// `version` 必须是**官方的裸版本号**（如 `0.71.0`），不能带 `nfrp/` 之类
/// 的前缀：第三方 frps 与面板会解析这个字段，不认识的写法可能直接被判为
/// "不支持的客户端版本"。
fn build_login(
    cred: &crate::security::Credential,
    client_id: &str,
    user: &str,
    metas: &std::collections::HashMap<String, String>,
    pool_count: i32,
    ts: i64,
) -> Login {
    Login {
        version: super::FRP_WIRE_VERSION.to_string(),
        hostname: crate::util::hostname(),
        os: std::env::consts::OS.to_string(),
        arch: std::env::consts::ARCH.to_string(),
        // 官方 frps 用 Login.User 匹配 stcp/xtcp 的 allow_users 白名单
        user: user.to_string(),
        // ★ 两种认证方式的 privilege_key 语义完全不同：
        // token = hex(md5(secret+ts))，OIDC = 原样的 access token。
        // 统一走 Credential 生成，别在这里手写。
        privilege_key: cred.wire_value(ts),
        timestamp: ts,
        client_id: client_id.to_string(),
        // frp 的 `[metadatas]` 原样透传：不少 frp 平台靠 `metas["token"]`
        // 识别隧道（拿不到它只会回一句「FRPC 配置文件错误」）
        metas: metas.clone(),
        pool_count,
        ..Default::default()
    }
}

// ---------------------------------------------------------------------------
// 客户端握手
// ---------------------------------------------------------------------------

/// 客户端建立控制连接，返回 `(连接, run_id, udp_binary)`。
#[allow(clippy::too_many_arguments)]
pub async fn client_handshake(
    stream: BoxStream,
    version: WireVersion,
    cred: &crate::security::Credential,
    client_id: &str,
    user: &str,
    metas: &std::collections::HashMap<String, String>,
    pool_count: i32,
    caps: msg::NfrpCaps,
) -> Result<(FrpConn, String, bool, msg::NfrpCaps)> {
    client_handshake_with(
        stream, version, cred, client_id, user, metas, pool_count, caps, None,
    )
    .await
}

/// [`client_handshake`] + NLink preamble。
///
/// `pre` 为 `Some` 时会在**任何协议字节之前**先把 preamble 写出去（v2 的
/// 魔术字也在它之后）。服务端的协商结果仍然搭 `LoginResp` 回来，所以
/// 全程没有新增往返。
#[allow(clippy::too_many_arguments)]
pub async fn client_handshake_with(
    stream: BoxStream,
    version: WireVersion,
    cred: &crate::security::Credential,
    client_id: &str,
    user: &str,
    metas: &std::collections::HashMap<String, String>,
    pool_count: i32,
    caps: msg::NfrpCaps,
    pre: Option<nlink::Preamble>,
) -> Result<(FrpConn, String, bool, msg::NfrpCaps)> {
    let mut conn = FrpConn::new(stream, version);
    let ts = now_unix_secs() as i64;
    let mut login = build_login(cred, client_id, user, metas, pool_count, ts);
    // 只是"声明支持"，真正开不开由服务端在 LoginResp 里回显决定
    login.nfrp = if caps.any() { Some(caps) } else { None };

    // NLink preamble 必须最先写：它要早于 v2 魔术字 / v1 的 Login。
    if let Some(p) = pre {
        conn.write_preamble(&p).await?;
    }

    // ---------------------------------------------------------------- v1
    if version == WireVersion::V1 {
        conn.send_msg(&FrpMessage::Login(login)).await?;
        let login_resp: LoginResp = match conn.recv_msg().await? {
            Some(FrpMessage::LoginResp(r)) => r,
            Some(other) => bail!("期望 LoginResp，收到 {}", other.name()),
            None => bail!("服务端在 LoginResp 之前断开连接"),
        };
        if !login_resp.error.is_empty() {
            bail!("登录失败: {}", login_resp.error);
        }
        if login_resp.run_id.is_empty() {
            bail!("服务端未下发 run_id");
        }
        // 官方时序：Login / LoginResp 明文，之后的控制消息才走 CFB
        conn.enable_v1_crypto(cred.raw())?;
        // v1 的二进制 UDP 只有在**服务端回显**了才算数：连官方 frps 时
        // 它不会回这个字段，于是这里拿到 default()，行为与以前完全一致。
        let accepted = login_resp.nfrp.clone().unwrap_or_default();
        conn.set_v1_udp_binary(accepted.udp_binary);
        apply_nlink_ack(&mut conn, &login_resp);
        return Ok((conn, login_resp.run_id, accepted.udp_binary, accepted));
    }

    // ---------------------------------------------------------------- v2
    conn.write_magic().await?;

    let hello = wire::new_client_hello("tcp", false, false);
    let hello_payload = serde_json::to_vec(&hello)?;
    conn.write_frame(FRAME_CLIENT_HELLO, &hello_payload).await?;

    conn.send_msg(&FrpMessage::Login(login)).await?;

    // 1) ServerHello
    let (ft, sh_payload) = conn
        .read_frame()
        .await?
        .ok_or_else(|| anyhow!("服务端在 ServerHello 之前断开"))?;
    if ft != FRAME_SERVER_HELLO {
        bail!("期望 ServerHello 帧，实际收到帧类型 {ft}");
    }
    let server_hello: ServerHello = serde_json::from_slice(&sh_payload)?;
    if !server_hello.error.is_empty() {
        bail!("ServerHello 返回错误: {}", server_hello.error);
    }
    wire::validate_server_hello(&hello, &server_hello)?;
    let algorithm = server_hello.selected.crypto.algorithm.clone();

    // 2) LoginResp（仍然是明文）
    let login_resp: LoginResp = match conn.recv_msg().await? {
        Some(FrpMessage::LoginResp(r)) => r,
        Some(other) => bail!("期望 LoginResp，收到 {}", other.name()),
        None => bail!("服务端在 LoginResp 之前断开连接"),
    };
    if !login_resp.error.is_empty() {
        bail!("登录失败: {}", login_resp.error);
    }
    if login_resp.run_id.is_empty() {
        bail!("服务端未下发 run_id");
    }

    // 3) 协商出的 UDP 报文编码：官方 frps 默认选二进制
    let udp_binary =
        server_hello.selected.message.udp_packet_codec == wire::UDP_PACKET_CODEC_BINARY;
    conn.set_udp_codec(udp_binary);

    // 4) 切换到加密帧流
    let transcript = transcript_hash(&hello_payload, &sh_payload);
    // 加密密钥与"线上凭证"必须同源：token 方式用共享密钥，OIDC 方式用 access token。
    // 服务端用 `AuthProvider::control_key(login.privilege_key)` 得到同样的字节。
    let (c2s, s2c) = derive_control_keys(cred.raw().as_bytes(), &algorithm, &transcript)?;
    conn.upgrade(s2c, c2s)?; // 客户端用 s2c 读、c2s 写

    // 5) 私有能力：仍然只认服务端回显的那一份
    let accepted = login_resp.nfrp.clone().unwrap_or_default();
    apply_nlink_ack(&mut conn, &login_resp);
    Ok((conn, login_resp.run_id, udp_binary, accepted))
}

/// 服务端对一次 preamble 的协商结果。
struct NegotiatedNLink {
    /// 要回显给客户端的协商结果。
    ///
    /// 只有打开 `nlink` feature 时 `LoginResp` 才有这个字段可写；
    /// 关掉时它无处安放，所以单独放行"未读取"。
    #[cfg_attr(not(feature = "nlink"), allow(dead_code))]
    ack: nlink::LoginAck,
    caps: nlink::Caps,
    session: nlink::ConnectionId,
    trace: nlink::TraceId,
    resume: bool,
}

/// 计算协商结果：编译期实现 ∩ 对端声明 ∩ 运行期允许。
///
/// 返回 `None` 的情况（都等价于"这次连接没有 NLink"）：
/// * 对端没发 preamble（官方 frpc / 老版 NFrp）；
/// * 运行期没开（`nlink_enabled == None`）；
/// * 对端 preamble 显式标了"不启用"；
/// * 交集为空。
fn negotiate_nlink(pre: Option<nlink::Preamble>, enabled: Option<u64>) -> Option<NegotiatedNLink> {
    if !cfg!(feature = "nlink") {
        return None;
    }
    let pre = pre?;
    let mask = enabled?;
    if !pre.enabled() {
        return None;
    }
    let caps = nlink::Caps::agree(nlink::compiled_caps(), pre.caps, nlink::Caps::new(mask));
    if !caps.any() {
        return None;
    }
    let trace = pre
        .tlvs
        .get(nlink::frame::TAG_TRACE_ID)
        .and_then(|v| <[u8; 16]>::try_from(v).ok())
        .map(nlink::TraceId::from_bytes)
        .unwrap_or_else(nlink::TraceId::random);
    Some(NegotiatedNLink {
        ack: nlink::LoginAck {
            version: nlink::PROTOCOL_VERSION,
            caps: caps.bits(),
            trace_id: trace.to_hex(),
            session: pre.session.to_hex(),
        },
        caps,
        session: pre.session,
        trace,
        resume: pre.wants_resume(),
    })
}

/// 把 `LoginResp._nlink` 的协商结果落到连接状态上。
///
/// 只有服务端回显了**非空能力**才启用；回显为空 / 没有这个字段（官方 frps）
/// 一律视为未协商。
fn apply_nlink_ack(conn: &mut FrpConn, resp: &LoginResp) {
    #[cfg(feature = "nlink")]
    {
        let Some(ack) = resp.nlink.as_ref() else {
            return;
        };
        let caps = nlink::Caps::new(ack.caps);
        if !caps.any() {
            return;
        }
        let session = nlink::TraceId::parse(&ack.session)
            .map(|t| nlink::ConnectionId::from_bytes(*t.as_bytes()))
            .unwrap_or_else(nlink::ConnectionId::random);
        let trace = nlink::TraceId::parse(&ack.trace_id).unwrap_or_else(nlink::TraceId::random);
        conn.enable_nlink(NLinkState::new(caps, session, trace));
        tracing::debug!(
            caps = %caps,
            trace = %trace,
            "NLink 协商成功"
        );
    }
    #[cfg(not(feature = "nlink"))]
    {
        let _ = (conn, resp);
    }
}

// ---------------------------------------------------------------------------
// 服务端握手
// ---------------------------------------------------------------------------

/// 服务端接受一条连接后的分类。
pub enum ServerAccept {
    /// 控制连接（已通过 token 校验并升级加密）
    Control {
        conn: FrpConn,
        /// 装箱：`Login` 是这个枚举里最大的成员，直接内联会把整个枚举撑大
        /// （clippy::large_enum_variant）。只有控制连接会用到它，装箱零代价。
        login: Box<Login>,
        /// 本次会话的角色（RBAC）。未启用 RBAC 时是「全权」角色。
        role: crate::security::Role,
        /// 本次会话协商出的 UDP 报文编码（true = 二进制）
        udp_binary: bool,
        /// 服务端**确认**启用的 NFrp 私有能力。
        ///
        /// 官方 frpc 不会在 Login 里声明能力，所以这里永远是 `default()`
        /// （全关）—— 于是它发这些私有消息的路径根本不会打开。
        caps: msg::NfrpCaps,
    },
    /// 工作连接（明文，等待分配代理后回 StartWorkConn）
    Work { conn: FrpConn, msg: NewWorkConn },
    /// visitor 连接（stcp / xtcp / sudp 的接入方，明文，等待校验后回 NewVisitorConnResp）。
    ///
    /// 注意 `conn` 上已经带着这条控制会话协商出的 UDP 报文编码；配对 SUDP 时
    /// **不要**再去覆盖它——工作连接那侧也各自继承自己的协商值，两边本就一致。
    Visitor { conn: FrpConn, msg: NewVisitorConn },
}

/// 服务端握手。**自动探测**对端是 v1 还是 v2（与官方 frps 一致）。
///
/// * `run_id` —— 本次会话的标识，会写进 LoginResp 下发给客户端。
/// * `max_clock_skew_secs` —— 登录时间戳允许的偏差（0 = 不校验，v0.5.6 M3）。
pub async fn server_handshake(
    stream: BoxStream,
    auth: &crate::security::AuthProvider,
    run_id: &str,
    max_clock_skew_secs: u64,
) -> Result<ServerAccept> {
    // 不做授权：任何通过认证的用户都拿到全权角色，等价于"没启用 RBAC"。
    server_handshake_authz(
        stream,
        auth,
        run_id,
        |_| Ok(crate::security::Role::unrestricted()),
        max_clock_skew_secs,
    )
    .await
}
/// 带授权的服务端握手。
///
/// `authorize` 在**认证通过之后、`LoginResp` 发出之前**被调用 —— 只有它返回
/// `Ok` 才会回"登录成功"，否则回一条带 `error` 的 `LoginResp`。
///
/// 这个顺序是硬要求。把授权放在响应之后（先回 OK 再断开）会出现一个很难查的
/// 现象：客户端认为自己**登录成功**了，于是这次断开只当成普通掉线，
/// 转入无限重连 —— 而 `loginFailExit`（默认 true，NetTool 那类宿主靠
/// "看子进程活没活"判断成败）永远不会触发，表现为"显示绿灯但实际不可用"。
pub async fn server_handshake_authz<F>(
    stream: BoxStream,
    auth: &crate::security::AuthProvider,
    run_id: &str,
    authorize: F,
    max_clock_skew_secs: u64,
) -> Result<ServerAccept>
where
    F: FnOnce(&str) -> std::result::Result<crate::security::Role, String>,
{
    server_handshake_authz_ext(
        stream,
        auth,
        run_id,
        authorize,
        max_clock_skew_secs,
        None,
        None,
        None,
    )
    .await
}

/// [`server_handshake_authz`] + 官方 `[[httpPlugins]]` 的 Login 钩子。
///
/// 插件在**认证之前**执行：它可以拒绝登录（`reject`）或改写登录内容
/// （例如把 `user` 换成插件查出来的账号）。这与官方 `Control.worker()`
/// 的顺序一致 —— 插件先于 token/OIDC 校验。
///
/// `peer` 只用于插件响应的 `client_address` 字段；`None` 时留空。
///
/// `nlink_enabled` 是**运行期允许启用的能力位**（`None` = 运行期关掉 NLink）。
/// 协商结果 = 编译期实现 ∩ 对端声明 ∩ 运行期允许，三者缺一不可。
///
/// 参数确实多（连接、认证、run_id、授权闭包、时钟容差、插件、对端地址、
/// NLink 能力位），但每个都是握手必需的独立输入。打包成结构体只会把
/// 同一组参数搬到另一处定义，所以这里放行。
#[allow(clippy::too_many_arguments)]
pub async fn server_handshake_authz_ext<F>(
    stream: BoxStream,
    auth: &crate::security::AuthProvider,
    run_id: &str,
    authorize: F,
    max_clock_skew_secs: u64,
    plugins: Option<&crate::plugin::PluginManager>,
    peer: Option<std::net::SocketAddr>,
    nlink_enabled: Option<u64>,
) -> Result<ServerAccept>
where
    F: FnOnce(&str) -> std::result::Result<crate::security::Role, String>,
{
    // 先用 v1 建连接对象：探测只在 raw 缓冲区上做事，跟协议无关
    let mut conn = FrpConn::new(stream, WireVersion::V1);
    let version = conn.detect_version().await?;

    // NLink：preamble 已经在 detect_version 里吃掉，这里只做"是否同意"。
    // 注意协商发生在**认证之前**也没问题：它只决定"能不能用扩展"，
    // 不携带任何身份信息，认证仍然在下面照常做。
    let negotiated = negotiate_nlink(conn.take_preamble(), nlink_enabled);

    // 首帧/首消息的解析：v2 要先处理 ClientHello，v1 直接就是消息
    let (type_id, body, crypto_state) = if version.is_v2() {
        let (ft, payload) = conn
            .read_frame()
            .await?
            .ok_or_else(|| anyhow!("客户端在发送首帧前断开"))?;

        let mut msg_payload: Option<Vec<u8>> = None;
        let crypto_state = if ft == FRAME_CLIENT_HELLO {
            let hello: ClientHello = serde_json::from_slice(&payload)?;
            let server_hello = match wire::new_server_hello(&hello) {
                Ok(h) => h,
                Err(e) => {
                    let mut h = ServerHello::default();
                    h.selected.message.codec = wire::MESSAGE_CODEC_JSON.to_string();
                    h.error = e.to_string();
                    h
                }
            };
            let sh_payload = serde_json::to_vec(&server_hello)?;
            conn.write_frame(FRAME_SERVER_HELLO, &sh_payload).await?;
            if !server_hello.error.is_empty() {
                bail!("ServerHello 协商失败: {}", server_hello.error);
            }
            let algorithm = server_hello.selected.crypto.algorithm.clone();
            // 与 frp 一致：客户端宣告支持 binary 就选 binary
            let udp_binary =
                server_hello.selected.message.udp_packet_codec == wire::UDP_PACKET_CODEC_BINARY;
            conn.set_udp_codec(udp_binary);

            let next = conn
                .read_frame()
                .await?
                .ok_or_else(|| anyhow!("客户端在发送 Login 前断开"))?;
            if next.0 != FRAME_MESSAGE {
                bail!("期望消息帧，实际收到帧类型 {}", next.0);
            }
            msg_payload = Some(next.1);
            // ClientHello 的原始字节要留着算 transcript 哈希（v2 密钥派生的输入）
            Some((payload.clone(), sh_payload, algorithm, udp_binary))
        } else {
            None
        };

        let payload = msg_payload.unwrap_or(payload);
        if payload.len() < 2 {
            bail!("消息帧负载过短");
        }
        (
            u16::from_be_bytes([payload[0], payload[1]]),
            payload[2..].to_vec(),
            crypto_state,
        )
    } else {
        // v1：第一条就是消息本身（类型字节 + 长度 + JSON），已由探测阶段
        // 留在缓冲区里，这里直接解析。
        loop {
            let taken = {
                let buf = &mut conn.raw;
                v1::take_msg(buf)?
            };
            if let Some((byte, body)) = taken {
                break (v1::type_id(byte).expect("take_msg 已校验"), body, None);
            }
            if !conn.fill().await? {
                bail!("客户端在发送第一条消息前断开");
            }
        }
    };

    // ---- 工作连接：不允许携带 ClientHello ----
    if type_id == msg::TYPE_NEW_WORK_CONN {
        if crypto_state.is_some() {
            bail!("工作连接不允许携带 ClientHello");
        }
        let m = FrpMessage::decode(type_id, &body)?;
        match m {
            FrpMessage::NewWorkConn(nwc) => return Ok(ServerAccept::Work { conn, msg: nwc }),
            _ => unreachable!(),
        }
    }

    // ---- visitor 连接：同样不允许携带 ClientHello ----
    if type_id == msg::TYPE_NEW_VISITOR_CONN {
        if crypto_state.is_some() {
            bail!("visitor 连接不允许携带 ClientHello");
        }
        let m = FrpMessage::decode(type_id, &body)?;
        match m {
            FrpMessage::NewVisitorConn(nvc) => {
                return Ok(ServerAccept::Visitor { conn, msg: nvc });
            }
            _ => unreachable!(),
        }
    }

    if type_id != msg::TYPE_LOGIN {
        bail!("期望 Login 或 NewWorkConn，收到 type_id {type_id}");
    }
    let mut login = match FrpMessage::decode(type_id, &body)? {
        FrpMessage::Login(l) => l,
        _ => unreachable!(),
    };

    // ---- 官方 `[[httpPlugins]]`：Login 钩子 ----
    //
    // 必须在 token / OIDC 校验之前，与官方 frps 的 `Control.worker()` 一致。
    // 插件可以：① 直接拒绝（用户管理 / 黑名单）；② 改写 user 等字段，让
    // 后面的认证按插件给定的身份执行。失败/拒绝时明文回 LoginResp，
    // 让客户端明确知道"登录被拒"而不是无限重连。
    if let Some(plugins) = plugins {
        if !plugins.is_empty() {
            let content = crate::plugin::login_content(
                &login,
                &peer.map(|p| p.to_string()).unwrap_or_default(),
            )?;
            match plugins
                .handle_mutable(crate::plugin::OP_LOGIN, content)
                .await
            {
                Ok(mut new_content) => {
                    // 插件通常会原样带回 `client_address`，但把它去掉更稳妥：
                    // Login 结构里本来就没有这个字段，serde 会忽略，不过
                    // 这里显式移除能避免插件把任意大对象塞回来。
                    if let Some(obj) = new_content.as_object_mut() {
                        obj.remove("client_address");
                    }
                    crate::plugin::apply_login_content(&mut login, new_content)?;
                }
                Err(e) => {
                    let reason = e.to_string();
                    let _ = conn
                        .send_msg(&FrpMessage::LoginResp(LoginResp {
                            error: reason.clone(),
                            ..Default::default()
                        }))
                        .await;
                    bail!("HTTP 插件拒绝登录：{reason}");
                }
            }
        }
    }

    // ★★ v0.5.6 修（审计总报告 M3，中危）：**先校验时间戳新鲜性**，
    //   再比凭证。
    //
    // 顺序有讲究：先判时间成本更低，而且能让"过期"与"凭证错"两种失败
    // 在日志里**分开**，便于运维定位（时钟不准 vs 配置错）。
    //
    // 为什么必须加这一步：v1 的凭证是 `md5(token + ts)`，原先只用报文
    // 自报的 ts 重算比对、**不做新鲜性校验**；而 `Login` 在加密建立之前
    // **明文发送**。⇒ 同链路嗅探到一条 Login 就能**原样重放**拿到完整会话
    // （无期限），并且每个候选 token 只需 1 次 MD5 即可离线验证。
    //
    // `max_clock_skew_secs == 0` 表示关闭（逃生开关，给时钟严重不准的设备）。
    // 官方 frpc 的 `Login.Timestamp` 就是发报文时的 unix 时间，
    // 默认 ±300 秒窗口对它**零感知**。
    //
    // ★★ v0.5.7（第六轮审计 G-1，高危）：**这一步不再单独调用** ——
    //   新鲜性校验已经并进 `verify_login` 内部（见那里的长注释）。
    //
    //   为什么并进去：原先它是**独立的一步**，于是"想校验凭证就顺手调一下"
    //   成了调用方的责任，而**另外四条凭证路径全都忘了**（vnet / 工作连接 /
    //   visitor 签名 / p2p 打洞签名），实测可无限期重放并打通双向 MITM。
    //   现在 `verify_login` 的 `skew` 是必需参数，**没有"只校验凭证"的入口**。
    //
    //   两种失败在日志里仍然分得开（错误文案不同），所以原设计的收益没丢。

    // 认证：token 方式比 `md5(secret+ts)`，OIDC 方式验签 access token。
    //
    // 失败时回的文案与官方 frps **逐字一致**（token 方式下），因为第三方
    // 平台的错误提示会拿它做匹配 —— 换了措辞用户会以为是自己配置错了。
    let subject = match auth.verify_login(
        &login.privilege_key,
        login.timestamp,
        run_id,
        max_clock_skew_secs,
    ) {
        Ok(s) => s,
        Err(e) => {
            // 官方 frps 也是明文回这条错误（此时还没建立加密）
            let _ = conn
                .send_msg(&FrpMessage::LoginResp(LoginResp {
                    error: e.to_string(),
                    ..Default::default()
                }))
                .await;
            bail!("认证失败：{e}");
        }
    };
    if !subject.is_empty() {
        tracing::debug!(subject = %subject, user = %login.user, "OIDC 登录成功");
    }

    // 授权（RBAC / 用户白名单）。必须在这里做 —— 见函数注释：
    // 落到 LoginResp 之后，客户端就会把"被拒"当成"连上又掉线"。
    let role = match authorize(&login.user) {
        Ok(r) => r,
        Err(e) => {
            // 此刻还没升级加密，LoginResp 明文发（与认证失败路径一致）
            let _ = conn
                .send_msg(&FrpMessage::LoginResp(LoginResp {
                    error: e.clone(),
                    ..Default::default()
                }))
                .await;
            bail!("授权失败：{e}");
        }
    };

    // 能力协商：客户端声明了、且服务端也支持，才回显 —— 回显了才算生效。
    let declared = login.nfrp.clone().unwrap_or_default();
    let mut caps = msg::NfrpCaps::default();
    if declared.server_cmd {
        caps.server_cmd = true;
    }
    // ★ v0.5.5（第四轮 A-1）：回显"工作连接必须带凭证"。
    //
    // 这是**服务端对这条会话的期待**，由客户端自己在 Login 里声明
    // （NFrp ≥ 0.5.5 恒声明）。回显之后服务端就知道：这条会话的
    // 工作连接**必须**带正确凭证，空凭证一律拒绝。
    //
    // 官方 frpc 不声明这个位 ⇒ 不会回显 ⇒ 服务端对它的工作连接
    // 退回"源 IP 一致"校验（官方默认不带凭证，实测一刀切会把它挡死）。
    if declared.work_conn_cred {
        caps.work_conn_cred = true;
    }
    // v2 的二进制 UDP 是握手协商出来的，与 Login 里的声明无关；
    // v1 没有握手协商这一步，只能靠这里。
    if version == WireVersion::V1 && declared.udp_binary {
        caps.udp_binary = true;
        conn.set_v1_udp_binary(true);
    }

    // LoginResp 必须明文发送（客户端此时还没升级加密）。
    // 多挂一个 `_nfrp` 字段：官方 frpc 会忽略未知字段，而 NFrp 客户端
    // 只认**回显**过来的能力 —— 这是"连官方 frps 时行为不变"的关键。
    conn.send_msg(&FrpMessage::LoginResp(LoginResp {
        version: super::FRP_WIRE_VERSION.to_string(),
        run_id: run_id.to_string(),
        nfrp: if caps.any() { Some(caps.clone()) } else { None },
        #[cfg(feature = "nlink")]
        nlink: negotiated.as_ref().map(|n| n.ack.clone()),
        ..Default::default()
    }))
    .await?;

    // 控制通道加密密钥：token 方式 = 共享密钥，OIDC 方式 = access token
    let control_key = auth.control_key(&login.privilege_key);
    let udp_binary = crypto_state
        .as_ref()
        .map(|(_, _, _, udp_binary)| *udp_binary)
        .unwrap_or(false);
    match crypto_state {
        // v2：用 transcript 派生 AEAD 密钥
        Some((ch_payload, sh_payload, algorithm, _)) => {
            let transcript = transcript_hash(&ch_payload, &sh_payload);
            let (c2s, s2c) = derive_control_keys(control_key.as_bytes(), &algorithm, &transcript)?;
            conn.upgrade(c2s, s2c)?; // 服务端用 c2s 读、s2c 写
        }
        // v1：套 PBKDF2 + AES-128-CFB
        None => conn.enable_v1_crypto(&control_key)?,
    }

    // NLink 状态在加密**之后**落到连接上：之后的扩展帧都走密文，
    // 与标准消息同一条路径。
    if let Some(n) = negotiated {
        let mut st = NLinkState::new(n.caps, n.session, n.trace);
        st.resume = n.resume;
        conn.enable_nlink(st);
    }

    Ok(ServerAccept::Control {
        conn,
        login: Box::new(login),
        role,
        udp_binary,
        caps,
    })
}

// ---------------------------------------------------------------------------
// 工作连接握手（助手）
// ---------------------------------------------------------------------------

/// 客户端建立一条工作连接并等待 `StartWorkConn`。
///
/// 返回 `(stream, leftover, start_msg)`：之后直接在这条流上转发原始字节。
pub async fn client_work_conn(
    stream: BoxStream,
    version: WireVersion,
    run_id: &str,
    token: &str,
    ts: i64,
) -> Result<(BoxStream, Vec<u8>, StartWorkConn)> {
    client_work_conn_with(stream, version, run_id, token, ts, None).await
}

/// [`client_work_conn`] + NLink 身份令牌。
///
/// 会话协商了 `CAP_IDENTITY` 时，服务端会**要求**这张令牌；没协商时传 `None`，
/// 报文与 0.6.x 逐字节一致（`_nlink` 字段不会出现）。
pub async fn client_work_conn_with(
    stream: BoxStream,
    version: WireVersion,
    run_id: &str,
    token: &str,
    ts: i64,
    // 关掉 `nlink` feature 时这个参数用不上（下面整段被 cfg 掉），
    // 但签名保持一致，免得调用点也要跟着写 `#[cfg]`。
    #[cfg_attr(not(feature = "nlink"), allow(unused_variables))] nlink_identity: Option<&str>,
) -> Result<(BoxStream, Vec<u8>, StartWorkConn)> {
    let mut conn = FrpConn::new(stream, version);
    // v2 要求每条连接都先发魔术字；v1 什么都不发，直接上消息
    conn.write_magic().await?;
    // 两种 feature 配置下字段数不同，所以整个构造函数写两遍。
    // 用 `#[cfg]` 而不是 `..Default::default()`：后者在默认配置下会被
    // clippy 判成"所有字段都已指定、这行没作用"（needless_update）。
    #[cfg(feature = "nlink")]
    let new_work = NewWorkConn {
        run_id: run_id.to_string(),
        privilege_key: msg::auth_key(token, ts),
        timestamp: ts,
        nlink: nlink_identity.map(str::to_string),
    };
    #[cfg(not(feature = "nlink"))]
    let new_work = NewWorkConn {
        run_id: run_id.to_string(),
        privilege_key: msg::auth_key(token, ts),
        timestamp: ts,
    };
    conn.send_msg(&FrpMessage::NewWorkConn(new_work)).await?;

    match conn.recv_msg().await? {
        Some(FrpMessage::StartWorkConn(s)) => {
            if !s.error.is_empty() {
                bail!("StartWorkConn 返回错误: {}", s.error);
            }
            let (stream, leftover) = conn.into_stream();
            Ok((stream, leftover, s))
        }
        Some(other) => bail!("期望 StartWorkConn，收到 {}", other.name()),
        None => bail!("服务端在工作连接握手完成前断开"),
    }
}

/// 客户端建立一条 **visitor 连接**（stcp / xtcp 的接入通道）。
///
/// 时序与工作连接类似，但首帧是 `NewVisitorConn`，服务端回 `NewVisitorConnResp`。
/// 校验通过后这条连接直接变成裸字节通道（服务端会把它与 provider 的工作连接对接）。
///
/// 返回 `(stream, leftover)`：leftover 是已经读进来但还没消费的字节
/// （visitor 收到 Resp 后可能立刻开始发数据，必须原样交给转发方）。
pub async fn client_visitor_conn(
    stream: BoxStream,
    version: WireVersion,
    run_id: &str,
    proxy_name: &str,
    secret_key: &str,
) -> Result<(BoxStream, Vec<u8>)> {
    let mut conn = FrpConn::new(stream, version);
    conn.write_magic().await?;

    let ts = now_unix_secs() as i64;
    conn.send_msg(&FrpMessage::NewVisitorConn(NewVisitorConn {
        run_id: run_id.to_string(),
        proxy_name: proxy_name.to_string(),
        // 与官方 frpc 一致：hex(md5(secret_key + timestamp))
        sign_key: msg::auth_key(secret_key, ts),
        timestamp: ts,
        ..Default::default()
    }))
    .await?;

    match conn.recv_msg().await? {
        Some(FrpMessage::NewVisitorConnResp(r)) => {
            if !r.error.is_empty() {
                bail!("NewVisitorConnResp 返回错误: {}", r.error);
            }
            let (stream, leftover) = conn.into_stream();
            Ok((stream, leftover))
        }
        Some(other) => bail!("期望 NewVisitorConnResp，收到 {}", other.name()),
        None => bail!("服务端在 visitor 连接握手完成前断开"),
    }
}

// ---------------------------------------------------------------------------
// 测试
// ---------------------------------------------------------------------------
//
// 这里用 `tokio::io::duplex` 当场造一条内存流，一端跑真的客户端握手，
// 另一端当"假 frps"**直接看线上字节**。价值在于：握手时序（哪条消息是明文、
// 从哪一条开始加密）是纯时序契约，只有盯着字节才能验证。
#[cfg(test)]
mod tests {
    use super::*;
    use crate::frp::msg::{FrpMessage, LoginResp, Ping};
    use crate::frp::v1;
    use tokio::io::AsyncReadExt;

    const TOKEN: &str = "tok";
    const RUN_ID: &str = "run-1";

    #[test]
    fn v2_帧解析_拒绝非法_flags_和超长负载() {
        let mut partial = vec![0u8, 16, 0, 0, 0, 0];
        assert!(take_frame(&mut partial).unwrap().is_none(), "头不完整");

        let mut bad_flags = wire::encode_frame(FRAME_MESSAGE, b"x");
        bad_flags[2] = 1;
        let err = take_frame(&mut bad_flags).unwrap_err().to_string();
        assert!(err.contains("flags"), "{err}");

        let mut too_big = Vec::new();
        too_big.extend_from_slice(&FRAME_MESSAGE.to_be_bytes());
        too_big.extend_from_slice(&0u16.to_be_bytes());
        too_big.extend_from_slice(&((wire::MAX_FRAME_PAYLOAD + 1) as u32).to_be_bytes());
        let err = take_frame(&mut too_big).unwrap_err().to_string();
        assert!(err.contains("超过上限"), "{err}");
    }

    #[test]
    fn v2_帧解析_保留剩余字节并允许零长负载() {
        let mut buf = wire::encode_frame(FRAME_MESSAGE, b"hello");
        buf.extend_from_slice(&wire::encode_frame(FRAME_SERVER_HELLO, b""));
        let (ft, payload) = take_frame(&mut buf).unwrap().unwrap();
        assert_eq!(ft, FRAME_MESSAGE);
        assert_eq!(payload, b"hello");
        let (ft, payload) = take_frame(&mut buf).unwrap().unwrap();
        assert_eq!(ft, FRAME_SERVER_HELLO);
        assert!(payload.is_empty());
        assert!(take_frame(&mut buf).unwrap().is_none());
    }

    /// 未知帧类型必须**整帧跳过**，而不是断开。
    ///
    /// 这条以前叫 `v2_未知帧类型由_recv_拒绝`，而"拒绝"其实是个很强的承诺：
    /// 一旦 v2 侧以后要加新帧类型（比如 NLink 之外的扩展），老版本服务端会
    /// 直接把连接踢掉，等于"加一个帧类型就砸一次兼容"。现在改成跳过，
    /// 与 TLV / 未知 NLink 帧种类的处理一致 —— v2 帧头自带长度，跳过是安全的。
    ///
    /// 反过来说：这条测试盯着的是"跳过一个未知帧之后，**下一条正常消息还能收到**"，
    /// 只断言 `ft != FRAME_MESSAGE` 那种写法证明不了任何东西。
    #[tokio::test]
    async fn v2_未知帧类型被跳过_控制连接继续可用() {
        let (client, server) = tokio::io::duplex(64 * 1024);
        let mut conn = FrpConn::new(Box::pin(server), WireVersion::V2);

        let mut wire = wire::encode_frame(999, b"future-frame");
        // 后面跟一条正常消息：必须能被收出来，才说明未知帧只是被跳过、
        // 而不是把连接搞坏。
        wire.extend_from_slice(&wire::encode_frame(
            FRAME_MESSAGE,
            &FrpMessage::Ping(Ping {
                timestamp: 7,
                ..Default::default()
            })
            .encode()
            .unwrap(),
        ));
        let mut client = client;
        client.write_all(&wire).await.unwrap();

        match conn.recv_event().await.unwrap() {
            ConnEvent::Msg(m) => assert!(matches!(*m, FrpMessage::Ping(p) if p.timestamp == 7)),
            _ => panic!("期望跳过未知帧后收到 Ping"),
        }
    }

    /// 回归：`upgrade()` 之前已经读进 `raw` 的**密文**必须当场解出来。
    ///
    /// 真实触发场景：服务端回完 `LoginResp`（明文）后立刻推 NLink 身份令牌
    /// （密文），两段落进同一个 TCP 段。`take_frame` 只消费掉 LoginResp，
    /// 剩下的密文留在 `raw`；若 `upgrade` 不处理它，`read_buf()` 已切到 `plain`，
    /// 这批字节就永远没人解密 —— 对端"明明发了"，本端一直阻塞。
    ///
    /// 用 `timeout` 包住最后一步：一旦回归，失败是 2 秒后报"超时"，
    /// 而不是把整个 CI 挂死。
    #[tokio::test]
    async fn v2_升级加密时已缓冲的密文不能丢() {
        let (a, b) = tokio::io::duplex(64 * 1024);
        let mut server = FrpConn::new(Box::pin(a), WireVersion::V2);
        let mut client = FrpConn::new(Box::pin(b), WireVersion::V2);
        let (s2c, c2s) = (vec![7u8; 32], vec![9u8; 32]);

        // 1) 明文帧（相当于 LoginResp）
        server
            .send_msg(&FrpMessage::LoginResp(LoginResp {
                run_id: RUN_ID.into(),
                ..Default::default()
            }))
            .await
            .unwrap();
        // 2) 服务端升级加密后立刻推一帧（相当于身份令牌）
        server.upgrade(s2c.clone(), c2s.clone()).unwrap();
        let frame = crate::nlink::Frame::new(crate::nlink::FrameKind::Identity)
            .with(crate::nlink::frame::TAG_IDENTITY, b"v1.tok".to_vec());
        server
            .write_frame(crate::nlink::V2_FRAME_TYPE, &frame.encode())
            .await
            .unwrap();

        // 客户端此时仍是明文状态：把两段**一起**读进 raw，模拟"同一个 TCP 段"。
        client.fill().await.unwrap();
        let (ft, _) = client.read_frame().await.unwrap().unwrap();
        assert_eq!(ft, FRAME_MESSAGE);
        assert!(
            !client.raw.is_empty(),
            "密文应当已经留在 raw 里（否则这条测试没测到东西）"
        );

        client.upgrade(c2s, s2c).unwrap();
        client.enable_nlink(NLinkState::new(
            crate::nlink::Caps::new(crate::nlink::CAP_TRACE),
            crate::nlink::ConnectionId::random(),
            crate::nlink::TraceId::random(),
        ));
        let ev = tokio::time::timeout(std::time::Duration::from_secs(2), client.recv_event())
            .await
            .expect("升级后必须能立刻解出已缓冲的密文（超时 = 回归）")
            .unwrap();
        match ev {
            ConnEvent::NLink(f) => {
                assert_eq!(f.kind, crate::nlink::FrameKind::Identity);
                assert_eq!(
                    f.tlvs.get_str(crate::nlink::frame::TAG_IDENTITY).unwrap(),
                    "v1.tok"
                );
            }
            _ => panic!("期望拿到已缓冲的 NLink 帧"),
        }
    }

    fn empty_metas() -> std::collections::HashMap<String, String> {
        Default::default()
    }
    /// 从流里读一条 v1 消息（`[类型字节][i64 长度][JSON]`）。
    async fn read_v1_raw<S: AsyncReadExt + Unpin>(s: &mut S) -> (u8, Vec<u8>) {
        let mut head = [0u8; 9];
        s.read_exact(&mut head).await.unwrap();
        let len = i64::from_be_bytes(head[1..9].try_into().unwrap()) as usize;
        let mut body = vec![0u8; len];
        s.read_exact(&mut body).await.unwrap();
        (head[0], body)
    }

    /// **金标准时序测试**：v1 的 `Login` / `LoginResp` 必须是明文，
    /// 从第三条消息起必须变成 AES-128-CFB 密文，且用官方算法能解回来。
    ///
    /// 这条测试盯着三件事，任何一件错了线上就是"连上就断"：
    /// 1. 首字节就是 `'o'`（TypeLogin），**没有**任何魔术字前缀；
    /// 2. 长度是 8 字节大端 i64，消息体是可读 JSON；
    /// 3. 登录之后的字节不是明文，而是 `16 字节 IV + 密文`，且能被
    ///    `PBKDF2-HMAC-SHA1(token, "frp", 64, 16)` + AES-128-CFB 解回原文。
    #[tokio::test]
    async fn v1_登录是明文_之后立刻走_aes_cfb() {
        let (client, mut server) = tokio::io::duplex(64 * 1024);

        let client_task = tokio::spawn(async move {
            let (conn, run_id, udp, _caps) = client_handshake(
                Box::pin(client),
                WireVersion::V1,
                &crate::security::Credential::Token(TOKEN.to_string()),
                "cid",
                "alice",
                &empty_metas(),
                0,
                msg::NfrpCaps::default(),
            )
            .await
            .unwrap();
            assert!(conn.is_encrypted(), "v1 登录成功后控制通道必须已加密");
            assert_eq!(conn.version(), WireVersion::V1);
            // 登录之后的第一条消息要自己发，这样它必然落在加密阶段
            let mut conn = conn;
            conn.send_msg(&FrpMessage::Ping(Ping {
                timestamp: 42,
                ..Default::default()
            }))
            .await
            .unwrap();
            (run_id, udp)
        });

        // ---- 1) Login 必须是明文 v1 帧 ----
        let (byte, body) = read_v1_raw(&mut server).await;
        assert_eq!(byte, v1::TYPE_LOGIN, "首字节必须是 'o'（TypeLogin）");
        let login: Login = serde_json::from_slice(&body).expect("登录消息必须是可读 JSON");
        assert_eq!(
            login.version,
            crate::frp::FRP_WIRE_VERSION,
            "上报的版本号必须是官方的裸版本号（第三方平台会解析它）"
        );
        assert_eq!(login.user, "alice");
        assert!(login.timestamp > 0, "必须带时间戳（鉴权签名要用它）");
        assert_eq!(
            login.privilege_key,
            msg::auth_key(TOKEN, login.timestamp),
            "privilege_key 必须是 md5(token + timestamp)"
        );

        // ---- 2) LoginResp 同样是明文 ----
        let resp = serde_json::to_vec(&LoginResp {
            version: crate::frp::FRP_WIRE_VERSION.to_string(),
            run_id: RUN_ID.to_string(),
            ..Default::default()
        })
        .unwrap();
        server
            .write_all(&v1::encode_msg(v1::TYPE_LOGIN_RESP, &resp))
            .await
            .unwrap();

        // ---- 3) 之后的字节必须是 IV + CFB 密文 ----
        let mut iv = [0u8; v1::IV_LEN];
        server.read_exact(&mut iv).await.expect("应收到 16 字节 IV");

        let expect_plain = v1::encode_msg(
            v1::TYPE_PING,
            &serde_json::to_vec(&Ping {
                timestamp: 42,
                ..Default::default()
            })
            .unwrap(),
        );
        let mut ct = vec![0u8; expect_plain.len()];
        server.read_exact(&mut ct).await.expect("应收到等长密文");
        assert_ne!(ct, expect_plain, "登录之后的控制消息不能是明文");
        assert!(
            std::str::from_utf8(&ct).is_err(),
            "密文里不该能直接读出 JSON 文本"
        );

        // 用官方算法解密：PBKDF2-HMAC-SHA1(token, "frp", 64, 16) + AES-128-CFB
        let mut wire = iv.to_vec();
        wire.extend_from_slice(&ct);
        let mut dec = v1::CryptoStream::with_key(v1::derive_key(TOKEN.as_bytes()));
        let plain = dec.decrypt(&mut wire);
        assert_eq!(plain, expect_plain, "密文必须能用官方算法解回原来那条 Ping");

        // 解出来的确实是那条 Ping，不是别的
        let mut buf = plain;
        let (byte, body) = v1::take_msg(&mut buf).unwrap().unwrap();
        assert_eq!(byte, v1::TYPE_PING);
        assert!(String::from_utf8_lossy(&body).contains("\"timestamp\":42"));

        let (run_id, udp) = client_task.await.unwrap();
        assert_eq!(run_id, RUN_ID);
        assert!(!udp, "v1 没有 UDP 二进制编码协商，恒为 false");
    }

    /// 只发 7 字节就断开（或停住）的客户端不能把服务端打挂。
    ///
    /// 回归的是一次真实越界：`detect_version` 先用 `MAGIC_V2.len()`（7）去填，
    /// 紧接着切 `[..8]` 做 NLink 魔术字比较 —— 一个畸形首包就 panic。
    /// 现在必须变成一条**错误**（连接被拒），而不是进程级崩溃。
    #[tokio::test]
    async fn 首帧不足时_detect_version_报错而不是_panic() {
        let (mut client, server) = tokio::io::duplex(64);
        client.write_all(b"FRP\x00\x02\r").await.unwrap(); // 7 字节
        drop(client);
        let mut conn = FrpConn::new(Box::pin(server), WireVersion::V1);
        let err = conn.detect_version().await.unwrap_err().to_string();
        assert!(err.contains("断开"), "应当是明确的错误，实际：{err}");
    }

    /// 服务端必须按魔术字自动识别（对应官方 `wire.CheckMagic`）。
    ///
    /// 关键点：认不出 v2 时那 8 字节**不能丢** —— 它们就是 v1 消息的
    /// 类型字节 + 长度前缀。官方用 `SharedConn` 把它们"塞回去"，
    /// 这里靠让字节留在读缓冲区实现。
    #[tokio::test]
    async fn 服务端按魔术字自动识别_v1_与_v2() {
        // ---- v2：首字节是魔术字 ----
        let (mut client, server) = tokio::io::duplex(4096);
        client.write_all(MAGIC_V2).await.unwrap();
        // ★ 探测要读 max(MAGIC_V2.len(), nlink::MAGIC.len()) = 8 字节，
        //   而 MAGIC_V2 只有 7 字节 —— 这里必须补足第 8 字节，否则
        //   `detect_version` 会一直等下一条永远不会来的数据（测试挂死）。
        //   识别只看前 7 字节，所以补什么都行；真机上这字节是帧头第一个字节。
        client.write_all(&[0u8]).await.unwrap();
        let mut conn = FrpConn::new(Box::pin(server), WireVersion::V1);
        assert_eq!(conn.detect_version().await.unwrap(), WireVersion::V2);

        // ---- v1：首字节是 'o'，8 字节要原样留着当消息前缀 ----
        let (mut client, server) = tokio::io::duplex(4096);
        let login_bytes = v1::encode_msg(v1::TYPE_LOGIN, br#"{"timestamp":7}"#);
        client.write_all(&login_bytes).await.unwrap();
        let mut conn = FrpConn::new(Box::pin(server), WireVersion::V1);
        assert_eq!(conn.detect_version().await.unwrap(), WireVersion::V1);
        match conn.recv_msg().await.unwrap().unwrap() {
            FrpMessage::Login(l) => assert_eq!(l.timestamp, 7, "被回填的 8 字节必须参与解析"),
            other => panic!("应当解出 Login，实际是 {}", other.name()),
        }
    }

    /// 默认线协议必须是 v1 —— 官方 frpc 的 `transport.wireProtocol` 默认就是它。
    ///
    /// 这条钉死默认值：哪天有人"顺手"把默认改成 v2，第三方面板（樱花之类）
    /// 就会全线连不上，而报错只会是含糊的"连上就断"。
    #[test]
    fn 默认线协议是_v1() {
        assert_eq!(WireVersion::default(), WireVersion::V1);
        assert_eq!(WireVersion::V1.to_string(), "v1");
        assert_eq!("v2".parse::<WireVersion>().unwrap(), WireVersion::V2);
        // 官方配置里写的就是这两个值
        assert_eq!("v1".parse::<WireVersion>().unwrap(), WireVersion::V1);
        assert_eq!(
            <WireVersion as std::str::FromStr>::from_str("").unwrap(),
            WireVersion::V1,
            "空值按官方 EmptyOr 语义落到 v1"
        );
    }
    /// 私有能力必须**服务端回显**才算数。
    ///
    /// 这条测试防的是一个很隐蔽的事故：客户端单方面"声明即启用"，
    /// 于是连官方 frps 时也按二进制去解 UDP 报文 —— 而官方 frps 发的是 JSON，
    /// 两边直接鸡同鸭讲，且症状是"UDP 代理时通时不通"，极难定位。
    #[tokio::test]
    async fn v1_能力协商_服务端不回显就不启用() {
        let (client, mut server) = tokio::io::duplex(64 * 1024);
        let declared = msg::NfrpCaps {
            udp_binary: true,
            server_cmd: true,
            work_conn_cred: true,
        };

        let client_task = tokio::spawn(async move {
            client_handshake(
                Box::pin(client),
                WireVersion::V1,
                &crate::security::Credential::Token(TOKEN.to_string()),
                "cid",
                "alice",
                &empty_metas(),
                0,
                declared,
            )
            .await
            .unwrap()
        });

        // Login 里必须带上能力声明
        let (byte, body) = read_v1_raw(&mut server).await;
        assert_eq!(byte, v1::TYPE_LOGIN);
        let login: Login = serde_json::from_slice(&body).unwrap();
        assert_eq!(
            login.nfrp,
            Some(msg::NfrpCaps {
                udp_binary: true,
                server_cmd: true,
                work_conn_cred: true
            }),
            "客户端必须声明自己支持哪些能力"
        );

        // 官方 frps（以及任何不认识这个字段的服务端）回的 LoginResp 里没有它
        let resp = serde_json::to_vec(&LoginResp {
            version: crate::frp::FRP_WIRE_VERSION.to_string(),
            run_id: RUN_ID.to_string(),
            ..Default::default()
        })
        .unwrap();
        server
            .write_all(&v1::encode_msg(v1::TYPE_LOGIN_RESP, &resp))
            .await
            .unwrap();
        server.flush().await.unwrap();

        let (_conn, run_id, udp_binary, caps) = client_task.await.unwrap();
        assert_eq!(run_id, RUN_ID);
        assert!(!udp_binary, "服务端没回显，v1 下必须继续走 JSON");
        assert!(
            !caps.udp_binary && !caps.server_cmd,
            "没回显的能力一律当作未启用：{caps:?}"
        );
    }

    #[tokio::test]
    async fn v1_能力协商_服务端回显后才启用() {
        let (client, mut server) = tokio::io::duplex(64 * 1024);
        let client_task = tokio::spawn(async move {
            client_handshake(
                Box::pin(client),
                WireVersion::V1,
                &crate::security::Credential::Token(TOKEN.to_string()),
                "cid",
                "alice",
                &empty_metas(),
                0,
                msg::NfrpCaps {
                    udp_binary: true,
                    server_cmd: true,
                    work_conn_cred: true,
                },
            )
            .await
            .unwrap()
        });

        let (_byte, _body) = read_v1_raw(&mut server).await;
        let resp = serde_json::to_vec(&LoginResp {
            version: crate::frp::FRP_WIRE_VERSION.to_string(),
            run_id: RUN_ID.to_string(),
            nfrp: Some(msg::NfrpCaps {
                udp_binary: true,
                server_cmd: true,
                work_conn_cred: true,
            }),
            ..Default::default()
        })
        .unwrap();
        server
            .write_all(&v1::encode_msg(v1::TYPE_LOGIN_RESP, &resp))
            .await
            .unwrap();
        server.flush().await.unwrap();

        let (conn, _run_id, udp_binary, caps) = client_task.await.unwrap();
        assert!(udp_binary, "服务端回显后 v1 必须走二进制 UDP");
        assert!(caps.udp_binary && caps.server_cmd);
        assert!(conn.udp_is_binary());
    }

    /// v1 协商成功之后，UDP 报文的**消息体**必须是二进制，类型字节仍是官方的 `'u'`。
    #[tokio::test]
    async fn v1_udp_协商后走二进制编码() {
        let (a, b) = tokio::io::duplex(64 * 1024);
        let mut sender = FrpConn::new(Box::pin(a), WireVersion::V1);
        let mut receiver = FrpConn::new(Box::pin(b), WireVersion::V1);
        sender.set_v1_udp_binary(true);
        receiver.set_v1_udp_binary(true);

        let pkt = msg::UdpPacket::new(b"hello-udp", &"203.0.113.9:45001".parse().unwrap());
        sender
            .send_msg(&FrpMessage::UdpPacket(pkt.clone()))
            .await
            .unwrap();

        // 直接看线上字节：类型字节是 'u'，但消息体不是 JSON
        let raw = sender_side_bytes(&pkt);
        assert_eq!(raw[0], v1::TYPE_UDP_PACKET, "类型字节必须还是官方的 'u'");
        assert_ne!(raw[9], b'{', "协商成功时消息体不该是 JSON");

        match receiver.recv_msg().await.unwrap() {
            Some(FrpMessage::UdpPacket(got)) => assert_eq!(got, pkt),
            other => panic!("应当解出一个 UdpPacket，实际：{other:?}"),
        }
    }

    /// 没协商时 v1 必须保持 JSON（这是与官方互通的底线）。
    #[tokio::test]
    async fn v1_udp_未协商时保持_json() {
        let (a, b) = tokio::io::duplex(64 * 1024);
        let mut sender = FrpConn::new(Box::pin(a), WireVersion::V1);
        let mut receiver = FrpConn::new(Box::pin(b), WireVersion::V1);

        let pkt = msg::UdpPacket::new(b"x", &"203.0.113.9:1".parse().unwrap());
        let raw = v1::encode_msg(v1::TYPE_UDP_PACKET, &serde_json::to_vec(&pkt).unwrap());
        assert_eq!(raw[9], b'{', "未协商时消息体必须是 JSON");
        sender
            .send_msg(&FrpMessage::UdpPacket(pkt.clone()))
            .await
            .unwrap();
        match receiver.recv_msg().await.unwrap() {
            Some(FrpMessage::UdpPacket(got)) => assert_eq!(got, pkt),
            other => panic!("应当解出一个 UdpPacket，实际：{other:?}"),
        }
    }

    /// 单独编码一个二进制 UDP 帧（供上面那条断言对照）。
    fn sender_side_bytes(pkt: &msg::UdpPacket) -> Vec<u8> {
        v1::encode_msg(
            v1::TYPE_UDP_PACKET,
            &msg::encode_udp_binary(pkt).expect("二进制编码"),
        )
    }

    /// ★★ v0.5.4 回归（M6）：解密缓冲（`plain`）必须有硬顶。
    ///
    /// 原先只卡了 `raw`（8 MiB），`plain` 完全没有上限 ⇒ 一条**未认证**的连接
    /// 就能让对端把已解密明文堆到任意大小，约 1000 条连接即可吃掉数 GB 内存。
    ///
    /// 这里直接验证常量与判据的口径（不真的灌 8 MiB，那太慢）：
    /// 用 `MAX_PLAIN` 的边界值检查"加多少会越界"。
    #[test]
    fn 解密缓冲上限的口径() {
        assert_eq!(MAX_PLAIN, 8 * 1024 * 1024, "plain 上限应与 raw 同量级");

        // 复刻 `fill()` 里的判据：`self.plain.len() + pt.len() > MAX_PLAIN`
        let would_overflow = |have: usize, add: usize| have + add > MAX_PLAIN;

        // 正好填满：允许；多 1 字节：拒绝
        assert!(!would_overflow(0, MAX_PLAIN), "正好填满应当允许");
        assert!(would_overflow(0, MAX_PLAIN + 1), "超出 1 字节必须被拒");

        // 累计判断（不是只看单次增量）
        let have = MAX_PLAIN - 10;
        assert!(!would_overflow(have, 10), "累计正好到顶应当允许");
        assert!(would_overflow(have, 11), "累计超限必须被拒");

        // 已有内容已经超限时，再加 0 也要拒
        assert!(would_overflow(MAX_PLAIN + 1, 0), "已超限时应当继续拒绝");
    }
}
