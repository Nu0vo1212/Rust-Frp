//! Go 版 frp **wire protocol v1** 的完整 Rust 移植。
//!
//! v1 是官方 frpc/frps 至今为止的**默认**线协议（`transport.wireProtocol`
//! 缺省值就是 `"v1"`，见 `pkg/config/v1/client.go` 的
//! `c.Transport.WireProtocol = util.EmptyOr(c.Transport.WireProtocol, "v1")`）。
//! v2 只有显式配置才会启用。所以一个"兼容 frp"的实现必须以 v1 为默认。
//!
//! 这里逐条对照官方源码实现，字段名 / 编码 / 密钥派生 / 流密码状态机
//! 全部保持逐字节一致：
//!
//! | 内容 | 官方参考 |
//! |---|---|
//! | 消息类型字节 | `pkg/msg/msg.go` 的 `TypeLogin` 等常量 |
//! | 帧格式 | `golib/msg/json/pack.go` 的 `Pack` |
//! | 帧解析 / 长度上限 | `golib/msg/json/process.go` 的 `readMsg` |
//! | 控制通道加密 | `golib/crypto/encode.go` / `decode.go` |
//! | 密钥派生 | `golib/crypto` 的 `pbkdf2.Key(key, []byte("frp"), 64, 16, sha1.New)` |
//!
//! # ⚠ 盐是 `"frp"`，**不是** `"crypto"`
//!
//! 这是踩过的最大一个坑，写死在这里：**官方 frp 用的 salt 是 `frp`**。
//!
//! `github.com/fatedier/golib` 的 master 分支里 `DefaultSalt = "crypto"`，
//! 但 frp 0.71.0 的 `go.mod` 锁的是 **`golib v0.8.2`**，那个版本里是
//! `DefaultSalt = "frp"`。照着 master 写会得到一个"自洽但错误"的实现 ——
//! 自己加密自己解密完全正常，一接官方 frps 就连上即断（服务端解不开我们的
//! 密文），而且报错离原因十万八千里。
//!
//! 定论来自实测：抓一条**官方 frpc -> 官方 frps** 的 v1 连接，拿已知明文
//! （客户端发的 NewProxy）反推出除该块密钥流，穷举盐/迭代/摘要，唯一命中的就是
//! `PBKDF2-HMAC-SHA1(token, "frp", 64, 16)`；用它把双向密文都解开了
//! （客户端 `p …{"proxy_name":…}`、服务端 `r …{}`）。
//!
//! # 帧格式
//!
//! ```text
//! [typeByte u8][json 长度 i64 大端][json]
//! ```
//!
//! 注意和 v2 的区别：v1 **没有**魔术字、没有 ClientHello/ServerHello、
//! 没有 u16 消息号前缀，类型就是那一个字节本身。
//!
//! # 控制通道加密
//!
//! v1 登录成功之后，控制连接会被套上一层 **AES-128-CFB 流密码**：
//!
//! ```text
//! 16 字节随机 IV（写方向首次写数据时才发）
//! 之后：AES-128-CFB128(key, IV) 对整个字节流连续加解密
//! ```
//!
//! 两个容易写错的点，都在这里对齐了官方：
//!
//! 1. **IV 是惰性发送的**：Go 的 `crypto.Writer` 在第一次 `Write` 时才把 IV
//!    写出去。所以 `Login` / `LoginResp` 都是**明文**，从下一条消息起才加密。
//! 2. **CFB 是字节粒度的流式密码**：Go 的 `cipher.NewCFBEncrypter` 在多次
//!    `Write` 之间保持状态 —— 一个 16 字节的密钥流块可以被两次写入拼着用完。
//!    所以不能用"按块加密"的实现（那样跨写的密文就对不上了）。

use aes::cipher::generic_array::GenericArray;
use aes::cipher::BlockEncrypt;
use aes::cipher::KeyInit;
use aes::Aes128;
use anyhow::{bail, Result};
use hmac::{Hmac, Mac};
use sha1::Sha1;

// ---------------------------------------------------------------------------
// 消息类型字节（pkg/msg/msg.go）
// ---------------------------------------------------------------------------

pub const TYPE_LOGIN: u8 = b'o';
pub const TYPE_LOGIN_RESP: u8 = b'1';
pub const TYPE_NEW_PROXY: u8 = b'p';
pub const TYPE_NEW_PROXY_RESP: u8 = b'2';
pub const TYPE_CLOSE_PROXY: u8 = b'c';
pub const TYPE_NEW_WORK_CONN: u8 = b'w';
pub const TYPE_REQ_WORK_CONN: u8 = b'r';
pub const TYPE_START_WORK_CONN: u8 = b's';
pub const TYPE_NEW_VISITOR_CONN: u8 = b'v';
pub const TYPE_NEW_VISITOR_CONN_RESP: u8 = b'3';
pub const TYPE_PING: u8 = b'h';
pub const TYPE_PONG: u8 = b'4';
pub const TYPE_UDP_PACKET: u8 = b'u';
pub const TYPE_NAT_HOLE_VISITOR: u8 = b'i';
pub const TYPE_NAT_HOLE_CLIENT: u8 = b'n';
pub const TYPE_NAT_HOLE_RESP: u8 = b'm';
pub const TYPE_NAT_HOLE_SID: u8 = b'5';
pub const TYPE_NAT_HOLE_REPORT: u8 = b'6';
/// NFrp 私有的服务端管理命令（对应 v2 的 type_id 100）。
///
/// 官方 frp 到 v0.71.0 为止只用小写字母和数字当类型字节，所以这里挑了
/// **大写** `Z` / `Y`：与官方当前及可预见的取值都不冲突。
/// 而且它只在双方都声明了 `server_cmd` 能力的会话里出现。
pub const TYPE_SERVER_CMD: u8 = b'Z';
/// [`TYPE_SERVER_CMD`] 的回执（对应 v2 的 type_id 101）。
pub const TYPE_SERVER_CMD_RESP: u8 = b'Y';

/// 单条消息 JSON 体的长度上限（`golib/msg/json` 的 `defaultMaxMsgLength`）。
///
/// 官方从没调用过 `SetMaxMsgLength`，所以这个 10240 就是实际生效的值：
/// 超过它的**入站**消息会被直接判为 `ErrMaxMsgLength`。
pub const DEFAULT_MAX_MSG_LENGTH: i64 = 10240;

/// v2 的 u16 消息号 → v1 的类型字节。
///
/// 两套协议的消息**体是同一份 JSON**（字段名都是 snake_case，见 `msg.rs`），
/// 差别只在外层容器，所以这里只要一张映射表就够了。
///
/// v2 独有的 `TYPE_UDP_PACKET_BINARY`(19) 没有对应字节 —— 它是 v2 握手协商
/// 出来的二进制 UDP 编码，v1 里根本不存在，调用方必须自己拒绝。
pub fn type_byte(type_id: u16) -> Option<u8> {
    Some(match type_id {
        1 => TYPE_LOGIN,
        2 => TYPE_LOGIN_RESP,
        3 => TYPE_NEW_PROXY,
        4 => TYPE_NEW_PROXY_RESP,
        5 => TYPE_CLOSE_PROXY,
        6 => TYPE_NEW_WORK_CONN,
        7 => TYPE_REQ_WORK_CONN,
        8 => TYPE_START_WORK_CONN,
        9 => TYPE_NEW_VISITOR_CONN,
        10 => TYPE_NEW_VISITOR_CONN_RESP,
        11 => TYPE_PING,
        12 => TYPE_PONG,
        13 => TYPE_UDP_PACKET,
        14 => TYPE_NAT_HOLE_VISITOR,
        15 => TYPE_NAT_HOLE_CLIENT,
        16 => TYPE_NAT_HOLE_RESP,
        17 => TYPE_NAT_HOLE_SID,
        18 => TYPE_NAT_HOLE_REPORT,
        100 => TYPE_SERVER_CMD,
        101 => TYPE_SERVER_CMD_RESP,
        _ => return None,
    })
}

/// v1 的类型字节 → v2 的 u16 消息号。
pub fn type_id(byte: u8) -> Option<u16> {
    Some(match byte {
        TYPE_LOGIN => 1,
        TYPE_LOGIN_RESP => 2,
        TYPE_NEW_PROXY => 3,
        TYPE_NEW_PROXY_RESP => 4,
        TYPE_CLOSE_PROXY => 5,
        TYPE_NEW_WORK_CONN => 6,
        TYPE_REQ_WORK_CONN => 7,
        TYPE_START_WORK_CONN => 8,
        TYPE_NEW_VISITOR_CONN => 9,
        TYPE_NEW_VISITOR_CONN_RESP => 10,
        TYPE_PING => 11,
        TYPE_PONG => 12,
        TYPE_UDP_PACKET => 13,
        TYPE_NAT_HOLE_VISITOR => 14,
        TYPE_NAT_HOLE_CLIENT => 15,
        TYPE_NAT_HOLE_RESP => 16,
        TYPE_NAT_HOLE_SID => 17,
        TYPE_NAT_HOLE_REPORT => 18,
        TYPE_SERVER_CMD => 100,
        TYPE_SERVER_CMD_RESP => 101,
        _ => return None,
    })
}

// ---------------------------------------------------------------------------
// 帧编解码（golib/msg/json/pack.go + process.go）
// ---------------------------------------------------------------------------

/// 打包一帧：`[typeByte][i64 大端长度][json]`。
///
/// 与 Go 的 `Pack` 一样**不做**长度检查 —— 超限由接收方拒绝
/// （`Pack` 里没有 maxMsgLength 的校验，只有 `readMsg` 有）。
pub fn encode_msg(type_byte: u8, json: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(9 + json.len());
    out.push(type_byte);
    out.extend_from_slice(&(json.len() as i64).to_be_bytes());
    out.extend_from_slice(json);
    out
}

/// 从缓冲区里切出一帧（`Ok(None)` 表示数据还不够）。
///
/// 对应 Go 的 `readMsg`，包括它的两个错误分支：
/// 未知类型字节 → 报错；长度超过 [`DEFAULT_MAX_MSG_LENGTH`] → 报错。
pub fn take_msg(buf: &mut Vec<u8>) -> Result<Option<(u8, Vec<u8>)>> {
    if buf.is_empty() {
        return Ok(None);
    }
    let type_byte = buf[0];
    if type_id(type_byte).is_none() {
        bail!(
            "未知的 frp v1 消息类型字节 0x{type_byte:02x}（'{}'）",
            type_byte as char
        );
    }
    if buf.len() < 9 {
        return Ok(None);
    }
    let mut len_bytes = [0u8; 8];
    len_bytes.copy_from_slice(&buf[1..9]);
    let len = i64::from_be_bytes(len_bytes);
    if len > DEFAULT_MAX_MSG_LENGTH {
        bail!("frp v1 消息长度 {len} 超过上限 {DEFAULT_MAX_MSG_LENGTH}");
    }
    if len < 0 {
        bail!("frp v1 消息长度为负：{len}");
    }
    let len = len as usize;
    if buf.len() < 9 + len {
        return Ok(None);
    }
    let body = buf[9..9 + len].to_vec();
    buf.drain(..9 + len);
    Ok(Some((type_byte, body)))
}

// ---------------------------------------------------------------------------
// 密钥派生：pbkdf2.Key(token, "frp", 64, 16, sha1.New)
// ---------------------------------------------------------------------------

/// PBKDF2 的盐（`golib` 的 `DefaultSalt`）。
///
/// **必须是 `frp`** —— frp 0.71.0 锁的 `golib v0.8.2` 用的就是它。
/// golib **master** 分支后来改成了 `crypto`，照着 master 写会得到一个
/// "自洽但跟官方不通"的实现（详见模块头部的说明与 `salt_必须与官方一致` 测试）。
pub const DEFAULT_SALT: &[u8] = b"frp";
/// PBKDF2 迭代次数。
pub const PBKDF2_ITERATIONS: u32 = 64;
/// 派生密钥长度 = AES 分组长度（= AES-128 的密钥长度）。
pub const KEY_LEN: usize = 16;

/// 从 token 派生控制通道的 AES-128 密钥。
///
/// 官方是 `pbkdf2.Key(key, []byte("frp"), 64, aes.BlockSize, sha1.New)`
/// （盐见 [`DEFAULT_SALT`]）。
/// 因为要的字节数（16）**小于** SHA-1 的输出（20），PBKDF2 只会算出第一个块，
/// 也就是：
///
/// ```text
/// U1     = HMAC-SHA1(P, S || 0x00000001)
/// U2     = HMAC-SHA1(P, U1)
/// ...
/// U64    = HMAC-SHA1(P, U63)
/// dk[..16] = (U1 xor U2 xor ... xor U64)[..16]
/// ```
///
/// 所以没必要引 PBKDF2 依赖 —— 十几行就写完了，而且能对着官方向量测。
pub fn derive_key(token: &[u8]) -> [u8; KEY_LEN] {
    let mut block = [0u8; 20];
    {
        let mut mac = <Hmac<Sha1> as Mac>::new_from_slice(token).expect("HMAC 接受任意长度密钥");
        mac.update(DEFAULT_SALT);
        mac.update(&1u32.to_be_bytes());
        block.copy_from_slice(&mac.finalize().into_bytes());
    }
    let mut acc = block;
    for _ in 1..PBKDF2_ITERATIONS {
        let mut mac = <Hmac<Sha1> as Mac>::new_from_slice(token).expect("HMAC 接受任意长度密钥");
        mac.update(&block);
        block.copy_from_slice(&mac.finalize().into_bytes());
        for (a, b) in acc.iter_mut().zip(block.iter()) {
            *a ^= *b;
        }
    }
    let mut key = [0u8; KEY_LEN];
    key.copy_from_slice(&acc[..KEY_LEN]);
    key
}

// ---------------------------------------------------------------------------
// AES-128-CFB128 流密码（字节粒度，跨写保持状态）
// ---------------------------------------------------------------------------

/// CFB128 的加解密初始化向量长度（= AES 分组长度）。
pub const IV_LEN: usize = 16;

/// AES-128-CFB128 流密码。
///
/// # 加解密**不能**共用一份代码
///
/// 这里踩过一次坑，写下来免得再踩：CFB 的加密与解密看起来完全对称
/// （`out = in ^ keystream`，反馈寄存器都填密文），但"密文"在两侧指的
/// 不是同一个东西：
///
/// * 加密：`输入 = 明文`，`输出 = 密文` → 反馈寄存器填**输出**；
/// * 解密：`输入 = 密文`，`输出 = 明文` → 反馈寄存器填**输入**。
///
/// 如果写成"就地翻转、反馈填输出"的一份代码，解密时就会把**明文**喂回反馈
/// 寄存器。前 16 字节看不出任何问题（第一个密钥流块来自 IV），
/// 从第 17 字节起整段乱掉 —— 症状是"前 16 字节明文正常，之后全是乱码"。
/// 单元测试里那条跨块边界的分段向量就是冲着这一点写的。
pub struct Cfb {
    cipher: Aes128,
    /// 当前密钥流块。
    keystream: [u8; IV_LEN],
    /// 反馈寄存器（下一块密钥流的输入）。初始为 IV。
    feedback: [u8; IV_LEN],
    /// 当前密钥流块已经用掉几个字节（0..IV_LEN）。
    used: usize,
}

impl Cfb {
    pub fn new(key: &[u8; KEY_LEN], iv: &[u8; IV_LEN]) -> Self {
        Self {
            cipher: Aes128::new_from_slice(key).expect("密钥长度固定为 16 字节"),
            keystream: [0u8; IV_LEN],
            feedback: *iv,
            used: 0,
        }
    }

    /// 取当前字节要用的密钥流字节，必要时先算出下一块。
    fn keystream_byte(&mut self) -> u8 {
        if self.used == 0 {
            let mut block = GenericArray::clone_from_slice(&self.feedback);
            self.cipher.encrypt_block(&mut block);
            self.keystream.copy_from_slice(&block);
        }
        self.keystream[self.used]
    }

    /// 就地加密。
    ///
    /// 故意写成"一个字节一个字节"而不是"凑满 16 字节再处理"：Go 的
    /// `cipher.Stream` 允许调用方想怎么写就怎么写，一个密钥流块可以被两次
    /// `Write` 拼着用完，反馈寄存器也是逐字节推进的。按块实现在整块数据上
    /// 结果相同，但只要跨块边界分次写入就会错位。
    pub fn encrypt(&mut self, buf: &mut [u8]) {
        for b in buf.iter_mut() {
            let ks = self.keystream_byte();
            let c = *b ^ ks;
            // 反馈寄存器填密文（= 本函数的输出）
            self.feedback[self.used] = c;
            self.used = (self.used + 1) % IV_LEN;
            *b = c;
        }
    }

    /// 就地解密。
    pub fn decrypt(&mut self, buf: &mut [u8]) {
        for b in buf.iter_mut() {
            let ks = self.keystream_byte();
            let c = *b;
            // 反馈寄存器填密文（= 本函数的输入）
            self.feedback[self.used] = c;
            self.used = (self.used + 1) % IV_LEN;
            *b = c ^ ks;
        }
    }
}

// ---------------------------------------------------------------------------
// 控制通道加解密流（惰性 IV）
// ---------------------------------------------------------------------------

/// 控制连接的 v1 加解密流。
///
/// 与 Go 的 `crypto.Reader` + `crypto.Writer` 组合等价：
/// * 写方向：第一次写之前先塞 16 字节随机 IV；
/// * 读方向：先把开头 16 字节当 IV 吃掉，之后才是密文。
pub struct CryptoStream {
    key: [u8; KEY_LEN],
    out: Option<Cfb>,
    /// 写方向的 IV；`out` 建好之前一直留着。
    out_iv: [u8; IV_LEN],
    out_iv_sent: bool,
    inp: Option<Cfb>,
}

impl CryptoStream {
    /// `token` 就是 frp 的认证 token（登录用的同一份）。
    pub fn new(token: &str) -> Self {
        Self::with_key(derive_key(token.as_bytes()))
    }

    /// 直接指定派生好的密钥（测试用，能对死官方向量）。
    pub fn with_key(key: [u8; KEY_LEN]) -> Self {
        let mut out_iv = [0u8; IV_LEN];
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut out_iv);
        Self {
            key,
            out: None,
            out_iv,
            out_iv_sent: false,
            inp: None,
        }
    }

    /// 加密一段明文，返回应该写到线上的字节。
    ///
    /// 第一次调用会把 16 字节 IV 放在最前面（顺序与 Go 的 `Writer.Write` 一致）。
    pub fn encrypt(&mut self, plain: &[u8]) -> Vec<u8> {
        let out_iv = self.out_iv;
        let cfb = self.out.get_or_insert_with(|| Cfb::new(&self.key, &out_iv));
        let mut buf = plain.to_vec();
        cfb.encrypt(&mut buf);

        if self.out_iv_sent {
            buf
        } else {
            self.out_iv_sent = true;
            let mut with_iv = Vec::with_capacity(IV_LEN + buf.len());
            with_iv.extend_from_slice(&out_iv);
            with_iv.extend_from_slice(&buf);
            with_iv
        }
    }

    /// 从密文缓冲区里**吃掉**已经能解出的字节，返回明文。
    ///
    /// IV 还没凑满 16 字节时返回空 —— 对应 Go 那边 `io.ReadFull` 会阻塞着等，
    /// 这里是"先攒着，等对端把 IV 发全"。
    pub fn decrypt(&mut self, cipher: &mut Vec<u8>) -> Vec<u8> {
        if self.inp.is_none() {
            if cipher.len() < IV_LEN {
                return Vec::new();
            }
            let mut iv = [0u8; IV_LEN];
            iv.copy_from_slice(&cipher[..IV_LEN]);
            cipher.drain(..IV_LEN);
            self.inp = Some(Cfb::new(&self.key, &iv));
        }
        let mut buf = std::mem::take(cipher);
        if let Some(cfb) = self.inp.as_mut() {
            cfb.decrypt(&mut buf);
        }
        buf
    }

    /// 写方向是否已经把 IV 发出去了（测试用）。
    pub fn out_iv_sent(&self) -> bool {
        self.out_iv_sent
    }
}

// ---------------------------------------------------------------------------
// 测试：全部对着**官方算法算出来的金标准向量**
// ---------------------------------------------------------------------------
//
// 向量由 `tmp/v1_vectors.py` 生成，用的就是 Go 官方那套算法
// （Python `cryptography` 的 PBKDF2HMAC(SHA1) 与 AES-CFB128，
// 与 Go 的 `pbkdf2.Key` / `cipher.NewCFBEncrypter` 是同一套标准算法）。
// 生成脚本里有断言：CFB 必须是字节粒度的流式密码，长度不守恒就直接报错。

#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // 类型字节：必须和 pkg/msg/msg.go 一字不差
    // -----------------------------------------------------------------------

    /// 类型字节表 —— 手抄自 `pkg/msg/msg.go`，钉死防止漂移。
    ///
    /// 这些字节是**直接印在线上**的，写错一个字符就是"对端读不懂"，
    /// 而且报错信息离原因很远（通常表现为连上就断）。
    #[test]
    fn 类型字节与官方一致() {
        let want: &[(u16, u8, char)] = &[
            (1, 0x6f, 'o'),
            (2, 0x31, '1'),
            (3, 0x70, 'p'),
            (4, 0x32, '2'),
            (5, 0x63, 'c'),
            (6, 0x77, 'w'),
            (7, 0x72, 'r'),
            (8, 0x73, 's'),
            (9, 0x76, 'v'),
            (10, 0x33, '3'),
            (11, 0x68, 'h'),
            (12, 0x34, '4'),
            (13, 0x75, 'u'),
            (14, 0x69, 'i'),
            (15, 0x6e, 'n'),
            (16, 0x6d, 'm'),
            (17, 0x35, '5'),
            (18, 0x36, '6'),
        ];
        for (id, byte, ch) in want {
            assert_eq!(type_byte(*id), Some(*byte), "v2 消息号 {id} 的 v1 字节不对");
            assert_eq!(type_id(*byte), Some(*id), "v1 字节 {ch:?} 反查消息号不对");
        }
        // v2 独有的二进制 UDP 编码（19）在 v1 里不存在
        assert_eq!(type_byte(19), None, "19 是 v2 独有的 UDP 二进制编码");
    }

    /// **金标准**：登录帧必须和抓到的官方 frpc v0.71.0 报文逐字节一致。
    ///
    /// 目标报文来自 relay_dump 抓的官方 frpc（v1，无魔术字）登录帧：
    ///
    /// ```text
    /// 6f 00 00 00 00 00 00 00 c7 {"version":"0.71.0","user":"s-023…
    /// ^^                        ^^^^^^^^^^^^^^^
    /// 'o' = TypeLogin           长度 199
    /// ```
    #[test]
    fn 登录帧与官方抓包一致() {
        let json = br#"{"version":"0.71.0","user":"s-023hiy2ko60pc5"}"#;
        let frame = encode_msg(TYPE_LOGIN, json);
        assert_eq!(frame[0], 0x6f, "首字节必须是 'o'");
        assert_eq!(
            &frame[1..9],
            &(json.len() as i64).to_be_bytes(),
            "长度必须是 8 字节大端 i64"
        );
        assert_eq!(&frame[9..], json);
        // 帧总长 = 1 + 8 + json
        assert_eq!(frame.len(), 9 + json.len());

        // 官方抓包那一帧的头部（长度字段真实值 0xc7 = 199）
        let real = encode_msg(TYPE_LOGIN, &[b'x'; 199]);
        assert_eq!(real[..9], [0x6f, 0, 0, 0, 0, 0, 0, 0, 0xc7]);
    }

    /// 登录报文里那串 privilege_key 是我们自己算的 md5(token+ts)。
    ///
    /// 抓包里官方 frpc 发的是
    /// `privilege_key = 2c08db852d70a34e5e5d78a66b4d3183`（timestamp 1789649666），
    /// 与 `msg::auth_key` 的输出一致 —— 所以 v1 与 v2 的 token 鉴权算法是同一个。
    #[test]
    fn v1_鉴权算法与_v2_相同() {
        assert_eq!(
            crate::frp::msg::auth_key("2ko6vise7hy1nyuyyekm4ek5t75a0pc5", 1789649666),
            "2c08db852d70a34e5e5d78a66b4d3183"
        );
    }

    // -----------------------------------------------------------------------
    // 帧解析
    // -----------------------------------------------------------------------

    #[test]
    fn 帧解析能处理粘包与半包() {
        let a = encode_msg(TYPE_PING, br#"{"timestamp":1}"#);
        let b = encode_msg(TYPE_PONG, br#"{"error":"x"}"#);
        let mut buf = Vec::new();

        // 半包：一个字节都还没到齐
        buf.extend_from_slice(&a[..5]);
        assert!(take_msg(&mut buf).unwrap().is_none());
        // 补齐
        buf.extend_from_slice(&a[5..]);
        let (t, body) = take_msg(&mut buf).unwrap().unwrap();
        assert_eq!(t, TYPE_PING);
        assert_eq!(body, br#"{"timestamp":1}"#);
        assert!(buf.is_empty());

        // 粘包：两帧一次到齐
        buf.extend_from_slice(&a);
        buf.extend_from_slice(&b);
        assert_eq!(take_msg(&mut buf).unwrap().unwrap().0, TYPE_PING);
        assert_eq!(take_msg(&mut buf).unwrap().unwrap().0, TYPE_PONG);
        assert!(take_msg(&mut buf).unwrap().is_none());
    }

    #[test]
    fn 未知类型字节要报错() {
        let mut buf = vec![0xff, 0, 0, 0, 0, 0, 0, 0, 0];
        let err = take_msg(&mut buf).unwrap_err().to_string();
        assert!(err.contains("未知的 frp v1 消息类型字节"), "{err}");
    }

    /// 超过 10240 字节的入站消息必须被拒 —— 这是官方的硬行为
    /// （`golib/msg/json.readMsg` 的 `length > maxMsgLength` 分支）。
    #[test]
    fn 超长消息要报错() {
        let mut buf = encode_msg(
            TYPE_NEW_PROXY,
            &vec![b'x'; DEFAULT_MAX_MSG_LENGTH as usize + 1],
        );
        let err = take_msg(&mut buf).unwrap_err().to_string();
        assert!(err.contains("超过上限"), "{err}");

        // 刚好等于上限则放行（官方是 `>` 而不是 `>=`）
        let mut ok = encode_msg(TYPE_NEW_PROXY, &vec![b'x'; DEFAULT_MAX_MSG_LENGTH as usize]);
        assert!(take_msg(&mut ok).unwrap().is_some());
    }

    #[test]
    fn 负长度要报错() {
        let mut buf = vec![TYPE_PING];
        buf.extend_from_slice(&(-1i64).to_be_bytes());
        let err = take_msg(&mut buf).unwrap_err().to_string();
        assert!(err.contains("为负"), "{err}");
    }

    // -----------------------------------------------------------------------
    // 密钥派生（金标准向量）
    // -----------------------------------------------------------------------

    /// 对照 Python `hashlib` 的 PBKDF2-HMAC-SHA1 算出的向量。
    ///
    /// 最后一条是真实互通测试用的 token，它与抓包反推出来的密钥**逐字节一致** ——
    /// 也就是说这里的盐/迭代/摘要只要动一点，这条就会红。
    #[test]
    fn pbkdf2_派生与官方一致() {
        let cases: &[(&str, &str)] = &[
            ("your_secret_token", "7b38633bc2d73efe69f131ca65dc5d8f"),
            (
                "2ko6vise7hy1nyuyyekm4ek5t75a0pc5",
                "ffb672b26338f08a95bf44f60e7d0f7f",
            ),
            ("", "cdc9dc4c472c37331281df4c232a8407"),
            ("interop-token-123", "8561619ac9e5f01030082c7479c3a42c"),
        ];
        for (token, want) in cases {
            let got = derive_key(token.as_bytes());
            let hex: String = got.iter().map(|b| format!("{b:02x}")).collect();
            assert_eq!(&hex, want, "token {token:?} 的派生密钥不对");
        }
    }

    /// 把十六进制串解成字节（测试用）。
    fn hex(s: &str) -> Vec<u8> {
        let s: String = s.chars().filter(|c| !c.is_whitespace()).collect();
        assert!(s.len() % 2 == 0, "十六进制串长度必须是偶数");
        (0..s.len() / 2)
            .map(|i| u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).expect("非法十六进制"))
            .collect()
    }

    /// **真实抓包回归**：官方 frpc / frps 实际发出的密文，必须能解开。
    ///
    /// 向量来自 `tmp/dump_v1.py` 抓的一条
    /// **官方 frpc v0.71.0 -> 官方 frps v0.71.0**（v1 + tcpMux）会话，
    /// yamux 帧头已经剥掉，剩下的是纯 frp 字节流上的真实密文。
    ///
    /// 这条测试是"盐必须写对"的最强保证：它不依赖我们自己的任何实现，
    /// 而是把官方二进制的输出原样解回来。只要盐/迭代/摘要/CFB 有任何一处不对，
    /// 这里立刻就是乱码。
    #[test]
    fn 官方抓包的密文必须能解开() {
        let key = derive_key(b"interop-token-123");

        // --- 官方 frpc 发的第一条加密消息：NewProxy ---
        // 线上形状 = [16 字节 IV][CFB 密文]
        let mut wire = hex("73533fa9c71925b5bfdb54b1558cd977");
        wire.extend_from_slice(&hex(
            "014618d317d95cee38e944500bf0ae86f177b45b55cd7a678d41cee63c256cc7\
             47496ad58afc3739e78b4f350afc18883e86fe860ff542fad6a2c7f95dec4957\
             a117d885a252ad541f0f50",
        ));
        let mut c = CryptoStream::with_key(key);
        let pt = c.decrypt(&mut wire);
        assert_eq!(
            pt,
            &b"p\x00\x00\x00\x00\x00\x00\x00\x42{\"proxy_name\":\"alice.echo\",\
                \"proxy_type\":\"tcp\",\"remote_port\":17973}"[..],
            "官方 frpc 的 NewProxy 密文解不出来 —— 密钥派生（盐！）或 CFB 实现有问题"
        );
        assert!(wire.is_empty(), "解完应当把缓冲区吃干净");

        // --- 官方 frps 发的第一条加密消息：ReqWorkConn（body 是空的 `{}`）---
        let mut wire2 = hex("2ba133fa54278d96ca0dd80afdb73368");
        wire2.extend_from_slice(&hex("712dffc1146baa97747717"));
        let mut s = CryptoStream::with_key(derive_key(b"interop-token-123"));
        let pt2 = s.decrypt(&mut wire2);
        assert_eq!(
            pt2,
            &b"r\x00\x00\x00\x00\x00\x00\x00\x02{}"[..],
            "官方 frps 的 ReqWorkConn 密文解不出来"
        );
    }

    /// **钉死盐**：官方用的是 `"frp"`，不是 golib master 里的 `"crypto"`。
    ///
    /// 这条测试的存在意义非常具体：写实现时照着 golib **master** 抄了
    /// `DefaultSalt = "crypto"`，结果"自己加密自己解"全绿，一接官方 frps
    /// 就"连上即断"（服务端解不开我们的密文，直接把连接关掉）。定位它花了很久，
    /// 最后是靠抓一条**官方 frpc ↔ 官方 frps** 的连接、用已知明文反推密钥流
    /// 才定案的：唯一命中的就是盐 `frp`。
    ///
    /// 所以这里同时否定 `"crypto"` —— 哪天有人"顺手"改回去，这条会立刻红。
    #[test]
    fn salt_必须与官方一致() {
        assert_eq!(DEFAULT_SALT, b"frp", "golib v0.8.2 的 DefaultSalt 是 frp");
        assert_ne!(
            DEFAULT_SALT, b"crypto",
            "crypto 是 golib master 的盐，连不上官方 frps"
        );
        // 真实互通 token 的派生结果（抓包验证过）
        let hex: String = derive_key(b"interop-token-123")
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        assert_eq!(hex, "8561619ac9e5f01030082c7479c3a42c");
        // 用错盐会得到另一个 key —— 顺手把这个差值也钉住
        assert_ne!(
            hex, "08083b42f553d5d60fa2ce82c0fe8eda",
            "这是 salt=crypto 的结果"
        );
    }

    // -----------------------------------------------------------------------
    // AES-128-CFB（金标准向量，含跨写状态机）
    // -----------------------------------------------------------------------

    /// CFB 向量：明文被故意拆成 5 + 11 + 20 + 7 四段，
    /// 第二段正好把第一个 16 字节密钥流块用满，第三段跨到第二块。
    ///
    /// 这条测试的价值就在于"分段"：按整块加密的实现能通过单次加密的测试，
    /// 但过不了这条 —— 而官方 frpc 恰恰是分多次 `Write` 发的。
    #[test]
    fn aes_cfb_流式加密与官方一致() {
        let key = derive_key(b"your_secret_token");
        let iv: [u8; IV_LEN] = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f,
        ];
        let chunks: [&[u8]; 4] = [
            b"hello",
            b"world-12345",
            &[
                0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d,
                0x2e, 0x2f, 0x30, 0x31, 0x32, 0x33,
            ],
            &[0x00, 0xff, 0x7f, 0x80, 0x01, 0x02, 0x03],
        ];
        const WANT: &str =
            "a76cfb88454bc22d08db7d8b1c4f2d6df6e4e85b309f7cb4d4af7e4b98c162f52f01b15f16ffad0c4347cd";

        // 分段加密，跨写复用同一个 CFB 状态
        let mut enc = Cfb::new(&key, &iv);
        let mut got = Vec::new();
        for c in chunks {
            let mut b = c.to_vec();
            enc.encrypt(&mut b);
            got.extend_from_slice(&b);
        }
        let hex: String = got.iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(hex, WANT, "分段加密结果与官方不一致");

        // 反过来分段解密（分段边界故意和加密时不同）
        let mut dec = Cfb::new(&key, &iv);
        let mut back = Vec::new();
        for c in [&got[..3], &got[3..19], &got[19..]] {
            let mut b = c.to_vec();
            dec.decrypt(&mut b);
            back.extend_from_slice(&b);
        }
        let plain: Vec<u8> = chunks.iter().flat_map(|c| c.to_vec()).collect();
        assert_eq!(back, plain, "解密必须能还原（且同样是字节粒度流式）");
    }

    // -----------------------------------------------------------------------
    // CryptoStream：IV 惰性发送 / 先读
    // -----------------------------------------------------------------------

    /// 第一次 `encrypt` 必须在最前面带上 16 字节 IV，之后不再带。
    ///
    /// 对应 Go `crypto.Writer.Write` 里那个 `ivSend` 标志。
    #[test]
    fn 首次写出带_iv_之后不带() {
        let mut s = CryptoStream::with_key(derive_key(b"your_secret_token"));
        assert!(!s.out_iv_sent());

        let first = s.encrypt(b"hello");
        assert_eq!(first.len(), IV_LEN + 5, "首帧应是 IV + 密文");
        assert!(s.out_iv_sent());

        let second = s.encrypt(b"hello");
        assert_eq!(second.len(), 5, "后续帧不该再带 IV");
        assert_ne!(
            &first[IV_LEN..],
            &second[..],
            "同一个密钥流块被复用两次说明 CFB 状态没推进"
        );
    }

    /// 收发两端各自独立建流，必须能互通（用在真实连接前的最后一道自检）。
    #[test]
    fn 双向加解密能互通() {
        let client = CryptoStream::with_key(derive_key(b"tok"));
        let server = CryptoStream::with_key(derive_key(b"tok"));
        let mut s = server;
        let mut c = client;

        // 客户端写、服务端读
        let a = c.encrypt(b"login-resp-followup");
        let mut wire = a.clone();
        assert_eq!(s.decrypt(&mut wire), b"login-resp-followup");
        let b = c.encrypt(b"second");
        wire.extend_from_slice(&b);
        assert_eq!(s.decrypt(&mut wire), b"second");

        // 服务端写、客户端读
        let d = s.encrypt(b"pong");
        let mut wire2 = d;
        assert_eq!(c.decrypt(&mut wire2), b"pong");
    }

    /// IV 还没到齐时不能吐出任何明文，也不能把半截 IV 当密文算掉。
    #[test]
    fn iv_不齐时先攒着() {
        let mut s = CryptoStream::with_key(derive_key(b"tok"));
        let mut wire: Vec<u8> = vec![1, 2, 3];
        assert!(s.decrypt(&mut wire).is_empty());
        assert_eq!(wire, vec![1, 2, 3], "IV 不足 16 字节时数据必须原样留着");

        let more: Vec<u8> = (4..=40u8).collect();
        wire.extend_from_slice(&more);
        let pt = s.decrypt(&mut wire);
        // 前 13 字节补足了 IV，剩下的才是密文
        let mut cipher_only = more.clone();
        cipher_only.drain(..13);
        assert_eq!(pt.len(), cipher_only.len());
    }
}
