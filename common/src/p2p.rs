//! xtcp 真 P2P 的**牵线报文**（rendezvous）编解码，服务端与客户端共用。
//!
//! ## 为什么需要它
//!
//! NAT 打洞的关键不是"发了什么"，而是**两个私网主机在同一时刻知道了对方的公网
//! `IP:port`**。这个信息只能由一个双方都能连上的第三方（也就是服务端）提供，
//! 所以服务端要跑一个极简的 UDP 地址交换服务：
//!
//! ```text
//!   visitor ──HELLO──▶ ┌────────────┐ ◀──HELLO── provider
//!                      │ rustunnel  │
//!   visitor ◀──PEER─── │ rendezvous │ ───PEER──▶ provider
//! ```
//!
//! 拿到对方地址后双方**同时**互发 QUIC Initial 包：各自 NAT 上留下 outbound 记录，
//! 于是对方的入站包就能通过。这一步之后数据不再经过服务端。
//!
//! ## 报文格式
//!
//! ```text
//! 0..4   魔数 b"RTNL"
//! 4      版本 = 1
//! 5      类型：1 = HELLO，2 = PEER
//! 6      角色：1 = visitor，2 = provider
//! 7..39  sid（32 个 ASCII 十六进制字符）
//! [仅 PEER] 39..   对方的 "ip:port"（UTF-8）
//! ```
//!
//! 故意做成定长头部 + 变长尾：解析只要一次长度检查，不需要流式状态机，
//! 也就不存在"半包处理复杂"带来的 bug。

use std::net::SocketAddr;

/// 报文魔数，用来过滤掉 NAT / 扫描器发来的野包。
pub const MAGIC: [u8; 4] = *b"RTNL";
/// 当前版本号。
pub const VERSION: u8 = 1;
/// 头部长度：魔数(4) + 版本(1) + 类型(1) + 角色(1)。
pub const HEADER_LEN: usize = 7;
/// sid 的 ASCII 长度（16 字节内容的十六进制形式）。
pub const SID_LEN: usize = 32;
/// HELLO 报文总长度。
pub const HELLO_LEN: usize = HEADER_LEN + SID_LEN;

/// 类型码。
pub mod kind {
    /// peer → 服务端：注册自己（服务端从 UDP 源地址学它的公网地址）。
    pub const HELLO: u8 = 1;
    /// 服务端 → peer：下发对端的公网地址。
    pub const PEER: u8 = 2;
}

/// 参与方角色。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    /// 接入方（本地监听端口的那个 frpc）。
    Visitor = 1,
    /// 提供方（把内网服务暴露出来的那个 frpc）。
    Provider = 2,
}

impl Role {
    pub fn to_u8(self) -> u8 {
        self as u8
    }

    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            1 => Some(Role::Visitor),
            2 => Some(Role::Provider),
            _ => None,
        }
    }

    /// 对端角色。
    pub fn peer(self) -> Self {
        match self {
            Role::Visitor => Role::Provider,
            Role::Provider => Role::Visitor,
        }
    }
}

/// 打洞用的裸 UDP 载荷（provider 在等连接期间持续向 visitor 公网地址发它）。
///
/// 内容本身没有意义，目的只有一个：让 provider 自己的 NAT 上留下一条
/// "本地端口 -> visitor" 的 outbound 记录，这样 visitor 随后的 QUIC Initial
/// 才能被 NAT 放行进来。QUIC 侧会把它当成无法解析的包直接丢掉，不影响握手。
pub const PUNCH_MAGIC: &[u8] = b"RTNL-PUNCH";

/// QUIC 的 ALPN 标识；两端不一致会握手失败。
pub const ALPN: &[u8] = b"rustunnel-xtcp";

/// 服务端名字：证书是自签且跳过校验的，但 rustls 仍要求它是合法 DNS 名。
pub const SERVER_NAME: &str = "xtcp.rustunnel.local";

/// 应用握手成功时回的字节。
pub const HANDSHAKE_OK: &[u8] = b"RTNL-OK";

/// P2P 直连建立后的**应用握手口令**。
///
/// 打洞成功后拿到的是一条裸 QUIC 连接：只要猜中端口，NAT 外的任何人都能连进来。
/// 所以 QUIC 握手之后必须再校验一次口令，把"能连上"和"有权限"这两件事分开。
///
/// 口令绑定 `sid`：一次会话一个值，录下来也重放不到下一次。
pub fn handshake_token(secret_key: &str, sid: &str) -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(secret_key.as_bytes());
    h.update(b":");
    h.update(sid.as_bytes());
    format!("{:x}", h.finalize())
}

/// 解析后的牵线报文。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Packet {
    /// 注册自己的公网地址（地址本身来自 UDP 源地址，不在报文里）。
    Hello { role: Role, sid: String },
    /// 服务端下发的对端地址。
    Peer {
        role: Role,
        sid: String,
        addr: SocketAddr,
    },
}

fn push_header(out: &mut Vec<u8>, kind: u8, role: Role, sid: &str) -> bool {
    if sid.len() != SID_LEN {
        return false;
    }
    out.extend_from_slice(&MAGIC);
    out.push(VERSION);
    out.push(kind);
    out.push(role.to_u8());
    out.extend_from_slice(sid.as_bytes());
    true
}

/// 编码一个 HELLO 报文。
pub fn encode_hello(role: Role, sid: &str) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(HELLO_LEN);
    push_header(&mut out, kind::HELLO, role, sid).then_some(out)
}

/// 编码一个 PEER 报文（下发对方的公网地址）。
pub fn encode_peer(role: Role, sid: &str, addr: &SocketAddr) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(HELLO_LEN + 24);
    if !push_header(&mut out, kind::PEER, role, sid) {
        return None;
    }
    out.extend_from_slice(addr.to_string().as_bytes());
    Some(out)
}

/// 解码一个报文；格式不对就返回 `None`（调用方直接丢弃）。
pub fn decode(pkt: &[u8]) -> Option<Packet> {
    if pkt.len() < HELLO_LEN {
        return None;
    }
    if pkt[..4] != MAGIC {
        return None;
    }
    if pkt[4] != VERSION {
        return None;
    }
    let role = Role::from_u8(pkt[6])?;
    let sid = std::str::from_utf8(&pkt[HEADER_LEN..HEADER_LEN + SID_LEN])
        .ok()?
        .to_string();
    if !sid.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    match pkt[5] {
        kind::HELLO => Some(Packet::Hello { role, sid }),
        kind::PEER => {
            let addr: SocketAddr = std::str::from_utf8(&pkt[HELLO_LEN..])
                .ok()
                .and_then(|s| s.parse().ok())?;
            Some(Packet::Peer { role, sid, addr })
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sid() -> String {
        format!("{:032x}", 0xdead_beef_u64)
    }

    #[test]
    fn hello_roundtrip() {
        let pkt = encode_hello(Role::Visitor, &sid()).expect("32 字符的 sid");
        assert_eq!(pkt.len(), HELLO_LEN);
        assert_eq!(&pkt[..4], b"RTNL");
        match decode(&pkt) {
            Some(Packet::Hello { role, sid: s }) => {
                assert_eq!(role, Role::Visitor);
                assert_eq!(s, sid());
            }
            other => panic!("解析失败：{other:?}"),
        }
    }

    #[test]
    fn peer_roundtrip_keeps_address() {
        let addr: SocketAddr = "203.0.113.9:45001".parse().unwrap();
        let pkt = encode_peer(Role::Provider, &sid(), &addr).unwrap();
        match decode(&pkt) {
            Some(Packet::Peer {
                role,
                sid: s,
                addr: a,
            }) => {
                assert_eq!(role, Role::Provider);
                assert_eq!(s, sid());
                assert_eq!(a, addr);
            }
            other => panic!("解析失败：{other:?}"),
        }
    }

    #[test]
    fn ipv6_address_survives_encoding() {
        let addr: SocketAddr = "[2001:db8::1]:7788".parse().unwrap();
        let pkt = encode_peer(Role::Visitor, &sid(), &addr).unwrap();
        assert_eq!(
            decode(&pkt),
            Some(Packet::Peer {
                role: Role::Visitor,
                sid: sid(),
                addr
            })
        );
    }

    #[test]
    fn garbage_is_rejected() {
        assert_eq!(decode(b""), None, "空包");
        assert_eq!(decode(b"XXXX\x01\x01\x01"), None, "魔数不对");
        assert_eq!(decode(b"RTNL\x02\x01\x01"), None, "版本号不对");
        assert_eq!(decode(b"RTNL\x01\x09\x01"), None, "未知类型");
        // sid 长度不对
        assert_eq!(decode(b"RTNL\x01\x01\x02abc"), None);
    }

    #[test]
    fn sid_must_be_hex() {
        // 非十六进制字符（比如 'z'）不能被当成 sid 接受
        let bad = std::str::from_utf8(b"zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz").unwrap();
        let mut pkt = encode_hello(Role::Visitor, bad);
        assert!(pkt.is_some(), "长度够编码就能成功");
        // 手动塞进去一个非法 sid 应当被 decode 拒绝
        let mut fake = vec![b'R', b'T', b'N', b'L', VERSION, kind::HELLO, 1];
        fake.extend_from_slice(bad.as_bytes());
        assert_eq!(decode(&fake), None);
        pkt = None;
        let _ = pkt;
    }

    #[test]
    fn wrong_sid_length_cannot_be_encoded() {
        assert!(encode_hello(Role::Visitor, "short").is_none());
        assert!(encode_peer(Role::Visitor, "short", &"1.2.3.4:1".parse().unwrap()).is_none());
    }

    #[test]
    fn handshake_token_binds_secret_and_session() {
        let a = handshake_token("sk", "sid1");
        let b = handshake_token("sk", "sid1");
        assert_eq!(a, b, "同参数必须稳定（否则两端永远对不上）");
        assert_ne!(a, handshake_token("sk2", "sid1"), "换密钥必须变");
        assert_ne!(a, handshake_token("sk", "sid2"), "换会话必须变（防止重放）");
        // 定长十六进制，方便按字节数读取
        assert_eq!(a.len(), 64);
        assert!(a.bytes().all(|b| b.is_ascii_hexdigit()));
    }

    #[test]
    fn roles_are_symmetric() {
        assert_eq!(Role::Visitor.peer(), Role::Provider);
        assert_eq!(Role::Provider.peer(), Role::Visitor);
        assert_eq!(Role::from_u8(1).unwrap(), Role::Visitor);
        assert_eq!(Role::from_u8(2).unwrap(), Role::Provider);
        assert!(Role::from_u8(3).is_none());
    }
}
