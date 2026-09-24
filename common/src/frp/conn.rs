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

/// 缓冲区上限，避免对端恶意灌数据。
const MAX_BUFFER: usize = 8 * 1024 * 1024;

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
        }
    }

    /// 本连接的线协议。
    pub fn version(&self) -> WireVersion {
        self.version
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
        while self.raw.len() < MAGIC_V2.len() {
            let need = MAGIC_V2.len() - self.raw.len();
            let mut chunk = vec![0u8; need];
            let n = self.stream.read(&mut chunk).await?;
            if n == 0 {
                bail!("对端在读满 {} 字节线协议标识前就断开了", MAGIC_V2.len());
            }
            self.raw.extend_from_slice(&chunk[..n]);
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
    /// 只能在**双方都声明了该能力**之后调用（见 `msg::RustunnelCaps`）：
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

    /// 接收一条消息。
    pub async fn recv_msg(&mut self) -> Result<Option<FrpMessage>> {
        match self.version {
            WireVersion::V2 => match self.read_frame().await? {
                Some((ft, payload)) => {
                    if ft != FRAME_MESSAGE {
                        bail!("期望消息帧({FRAME_MESSAGE})，实际收到帧类型 {ft}");
                    }
                    if payload.len() < 2 {
                        bail!("消息帧负载过短");
                    }
                    let type_id = u16::from_be_bytes([payload[0], payload[1]]);
                    if type_id == msg::TYPE_UDP_PACKET_BINARY {
                        let pkt = msg::decode_udp_binary(&payload[2..])?;
                        return Ok(Some(FrpMessage::UdpPacket(pkt)));
                    }
                    Ok(Some(FrpMessage::decode(type_id, &payload[2..])?))
                }
                None => Ok(None),
            },
            WireVersion::V1 => loop {
                {
                    let buf = self.read_buf();
                    if let Some((byte, body)) = v1::take_msg(buf)? {
                        let type_id = v1::type_id(byte).expect("take_msg 已校验过类型字节");
                        if self.v1_udp_binary && byte == v1::TYPE_UDP_PACKET {
                            return Ok(Some(FrpMessage::UdpPacket(msg::decode_udp_binary(&body)?)));
                        }
                        return Ok(Some(FrpMessage::decode(type_id, &body)?));
                    }
                }
                if !self.fill().await? {
                    return Ok(None);
                }
            },
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
        match &mut self.crypto {
            ControlCrypto::None => {}
            ControlCrypto::V1(c) => {
                // v1 是流密码：把缓冲区里所有能解的字节都解出来
                let pt = c.decrypt(&mut self.raw);
                self.plain.extend_from_slice(&pt);
            }
            ControlCrypto::V2(v) => {
                while let Some(pt) = v.reader.open(&mut self.raw)? {
                    self.plain.extend_from_slice(&pt);
                }
            }
        }
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
/// `version` 必须是**官方的裸版本号**（如 `0.71.0`），不能带 `rustunnel/` 之类
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
    caps: msg::RustunnelCaps,
) -> Result<(FrpConn, String, bool, msg::RustunnelCaps)> {
    let mut conn = FrpConn::new(stream, version);
    let ts = now_unix_secs() as i64;
    let mut login = build_login(cred, client_id, user, metas, pool_count, ts);
    // 只是"声明支持"，真正开不开由服务端在 LoginResp 里回显决定
    login.rustunnel = if caps.any() { Some(caps) } else { None };

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
        let accepted = login_resp.rustunnel.clone().unwrap_or_default();
        conn.set_v1_udp_binary(accepted.udp_binary);
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
    let accepted = login_resp.rustunnel.clone().unwrap_or_default();
    Ok((conn, login_resp.run_id, udp_binary, accepted))
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
        /// 服务端**确认**启用的 rustunnel 私有能力。
        ///
        /// 官方 frpc 不会在 Login 里声明能力，所以这里永远是 `default()`
        /// （全关）—— 于是它发这些私有消息的路径根本不会打开。
        caps: msg::RustunnelCaps,
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
pub async fn server_handshake(
    stream: BoxStream,
    auth: &crate::security::AuthProvider,
    run_id: &str,
) -> Result<ServerAccept> {
    // 不做授权：任何通过认证的用户都拿到全权角色，等价于"没启用 RBAC"。
    server_handshake_authz(stream, auth, run_id, |_| {
        Ok(crate::security::Role::unrestricted())
    })
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
) -> Result<ServerAccept>
where
    F: FnOnce(&str) -> std::result::Result<crate::security::Role, String>,
{
    // 先用 v1 建连接对象：探测只在 raw 缓冲区上做事，跟协议无关
    let mut conn = FrpConn::new(stream, WireVersion::V1);
    let version = conn.detect_version().await?;

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
    let login = match FrpMessage::decode(type_id, &body)? {
        FrpMessage::Login(l) => l,
        _ => unreachable!(),
    };

    // 认证：token 方式比 `md5(secret+ts)`，OIDC 方式验签 access token。
    //
    // 失败时回的文案与官方 frps **逐字一致**（token 方式下），因为第三方
    // 平台的错误提示会拿它做匹配 —— 换了措辞用户会以为是自己配置错了。
    let subject = match auth.verify_login(&login.privilege_key, login.timestamp) {
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
    let declared = login.rustunnel.clone().unwrap_or_default();
    let mut caps = msg::RustunnelCaps::default();
    if declared.server_cmd {
        caps.server_cmd = true;
    }
    // v2 的二进制 UDP 是握手协商出来的，与 Login 里的声明无关；
    // v1 没有握手协商这一步，只能靠这里。
    if version == WireVersion::V1 && declared.udp_binary {
        caps.udp_binary = true;
        conn.set_v1_udp_binary(true);
    }

    // LoginResp 必须明文发送（客户端此时还没升级加密）。
    // 多挂一个 `_rustunnel` 字段：官方 frpc 会忽略未知字段，而 rustunnel 客户端
    // 只认**回显**过来的能力 —— 这是"连官方 frps 时行为不变"的关键。
    conn.send_msg(&FrpMessage::LoginResp(LoginResp {
        version: super::FRP_WIRE_VERSION.to_string(),
        run_id: run_id.to_string(),
        rustunnel: if caps.any() { Some(caps.clone()) } else { None },
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
    let mut conn = FrpConn::new(stream, version);
    // v2 要求每条连接都先发魔术字；v1 什么都不发，直接上消息
    conn.write_magic().await?;
    conn.send_msg(&FrpMessage::NewWorkConn(NewWorkConn {
        run_id: run_id.to_string(),
        privilege_key: msg::auth_key(token, ts),
        timestamp: ts,
    }))
    .await?;

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
                msg::RustunnelCaps::default(),
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
        let declared = msg::RustunnelCaps {
            udp_binary: true,
            server_cmd: true,
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
            login.rustunnel,
            Some(msg::RustunnelCaps {
                udp_binary: true,
                server_cmd: true
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
                msg::RustunnelCaps {
                    udp_binary: true,
                    server_cmd: true,
                },
            )
            .await
            .unwrap()
        });

        let (_byte, _body) = read_v1_raw(&mut server).await;
        let resp = serde_json::to_vec(&LoginResp {
            version: crate::frp::FRP_WIRE_VERSION.to_string(),
            run_id: RUN_ID.to_string(),
            rustunnel: Some(msg::RustunnelCaps {
                udp_binary: true,
                server_cmd: true,
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
}
