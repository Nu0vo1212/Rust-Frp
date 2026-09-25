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
//!                      │ nfrp  │
//!   visitor ◀──PEER─── │ rendezvous │ ───PEER──▶ provider
//! ```
//!
//! 拿到对方地址后双方**同时**互发握手包：各自 NAT 上留下 outbound 记录，
//! 于是对方的入站包就能通过。这一步之后数据不再经过服务端。
//!
//! ## 对称 NAT 与端口预测
//!
//! 上面的流程只在两端的 NAT 都是 **cone**（锥型）时才成立：cone NAT 给
//! "内网 `ip:port`" 分配的公网端口与**目的地无关**，所以服务端看到的那个端口
//! 就是 peer 之间通信用的端口。
//!
//! 对称 NAT 不一样：**每换一个目的地就换一个公网端口**。于是服务端看到的
//! `1.2.3.4:51000` 是 peer 连**服务端**时用的端口，peer 连对方时用的是
//! `1.2.3.4:5xxxx`，谁也不知道是几 —— 官方 frp 到这里就放弃，回退中继。
//!
//! 但现实里的对称 NAT 绝大多数不是真随机，而是**顺序分配**：每开一条新流，
//! 端口号 +1（或 +2、+4，步长固定）。于是可以：
//!
//! ```text
//!  1. 采样  peer 用 N 个 socket 依次向服务端发 HELLO，服务端看到
//!           `51000, 51001, 51002` —— 步长 = 1；
//!  2. 预测  它接下来连 peer 时会拿到的端口 ≈ 51003, 51004, 51005…；
//!  3. 喷洒  把候选端口当成一个集合，两端同时往集合里的所有端口打，
//!           ️命中任何一个就能握手成功。
//! ```
//!
//! 见 [`predict_ports`]。这条路**不保证成功**（真随机对称 NAT 仍然无解），
//! 但它把"对称 NAT 必然回退"变成了"大概率能直连"，而且失败时的代价
//! 只是多花了 `PUNCH_TIMEOUT`，仍然会回退中继。
//!
//! ## 报文格式（v2）
//!
//! ```text
//! 0..4    魔数 b"RTNL"
//! 4       版本 = 2
//! 5       类型：1 = HELLO，2 = PEER，3 = PEERS
//! 6       角色：1 = visitor，2 = provider
//! 7       传输：1 = quic，2 = kcp
//! 8..40   sid（32 个 ASCII 十六进制字符）
//! 40..    [HELLO]  无
//!         [PEER]   1 字节长度 + 地址串
//!         [PEERS]  1 字节个数 + 每个（1 字节长度 + 地址串）
//! ```
//!
//! v1（40 字节头里没有传输字节、地址串直接裸放在后面）仍然能解，
//! 只是拿不到传输协商与多地址 —— 解出来按 quic + 单地址处理。
//!
//! 故意做成定长头部 + 变长尾：解析只要一次长度检查，不需要流式状态机，
//! 也就不存在"半包处理复杂"带来的 bug。

use std::net::SocketAddr;

/// 报文魔数，用来过滤掉 NAT / 扫描器发来的野包。
pub const MAGIC: [u8; 4] = *b"RTNL";
/// 第 1 版格式（无传输协商、地址串裸放）。仍可解码。
pub const VERSION_V1: u8 = 1;
/// 第 2 版格式（含传输字节、长度前缀地址、多地址 PEERS）。
pub const VERSION_V2: u8 = 2;
/// 当前使用的版本。
pub const CURRENT_VERSION: u8 = VERSION_V2;
/// v1 头部长度：魔数(4) + 版本(1) + 类型(1) + 角色(1)。
pub const HEADER_LEN_V1: usize = 7;
/// v2 头部长度：v1 头部 + 传输(1)。
pub const HEADER_LEN: usize = 8;
/// sid 的 ASCII 长度（16 字节内容的十六进制形式）。
pub const SID_LEN: usize = 32;
/// v1 的 sid 起始偏移。
pub const SID_OFF_V1: usize = HEADER_LEN_V1;
/// v2 的 sid 起始偏移。
pub const SID_OFF: usize = HEADER_LEN;
/// v1 HELLO 报文总长度。
pub const HELLO_LEN_V1: usize = HEADER_LEN_V1 + SID_LEN;
/// v2 HELLO 报文总长度。
pub const HELLO_LEN: usize = HEADER_LEN + SID_LEN;

/// 类型码。
pub mod kind {
    /// peer → 服务端：注册自己（服务端从 UDP 源地址学它的公网地址）。
    pub const HELLO: u8 = 1;
    /// 服务端 → peer：下发对端的**一个**公网地址。
    pub const PEER: u8 = 2;
    /// 服务端 → peer：下发对端的**多个**公网地址（端口预测用）。
    pub const PEERS: u8 = 3;
}

/// P2P 数据通道跑在哪种传输上。
///
/// * `Quic` —— 默认。自带加密与拥塞控制，握手即鉴权。
/// * `Kcp`  —— 弱网备选。KCP 的重传更激进（不等 RTO、可跳包重传），
///   在高丢包 / 高延迟链路（移动网络、跨国）上往往比 QUIC 更快把数据推过去，
///   代价是没有内建的加密（P2P 场景下由应用层口令鉴权，与 QUIC 侧一致）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Transport {
    Quic = 1,
    Kcp = 2,
}

impl Transport {
    pub fn to_u8(self) -> u8 {
        self as u8
    }

    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            1 => Some(Transport::Quic),
            2 => Some(Transport::Kcp),
            _ => None,
        }
    }
}

/// 默认传输。
pub const DEFAULT_TRANSPORT: Transport = Transport::Quic;

/// 参与方角色。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
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
/// "本地端口 -> visitor" 的 outbound 记录，这样 visitor 随后的握手包
/// 才能被 NAT 放行进来。QUIC 侧会把它当成无法解析的包直接丢掉，不影响握手。
pub const PUNCH_MAGIC: &[u8] = b"RTNL-PUNCH";

/// QUIC 的 ALPN 标识；两端不一致会握手失败。
pub const ALPN: &[u8] = b"nfrp-xtcp";

/// 服务端名字：证书是自签且跳过校验的，但 rustls 仍要求它是合法 DNS 名。
pub const SERVER_NAME: &str = "xtcp.nfrp.local";

/// 应用握手成功时回的字节。
pub const HANDSHAKE_OK: &[u8] = b"RTNL-OK";

/// P2P 直连建立后的**应用握手口令**。
///
/// 打洞成功后拿到的是一条裸通道：只要猜中端口，NAT 外的任何人都能连进来。
/// 所以传输握手之后必须再校验一次口令，把"能连上"和"有权限"这两件事分开。
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

// ---------------------------------------------------------------------------
// 对称 NAT 端口预测
// ---------------------------------------------------------------------------

/// 端口预测的候选窗口：往预测值之后多试几个。
///
/// 顺序分配的 NAT 也有抖动（中间可能插进别人家的流），所以只押一个端口太脆。
pub const PREDICT_WINDOW: u16 = 16;

/// 认为是"顺序分配"的步长上限。
///
/// 家用路由器的增量一般是 1 或 2；超过这个值基本就是随机分配了，
/// 预测没有意义（后面仍然会把观测到的端口本身也当候选洒一遍）。
const MAX_STEP: u16 = 32;

/// 候选端口总数上限。
///
/// 每个候选都要发一批打洞包，太多会把自己和对方的 NAT 表打爆，
/// 也会让握手阶段变成一次小型 DDoS。
const MAX_CANDIDATES: usize = 48;

/// 由观察到的公网端口序列，推测"下一条流"会落在哪些端口上。
///
/// # 算法
///
/// ```text
/// 1. 取相邻观测端口的差，取中位数当步长 step；
/// 2. step 在 1..=MAX_STEP 之间 → 认定为顺序分配，
///    候选 = last + k*step（k = 1..=window）；
/// 3. 否则认定为随机分配，候选 = 每个观测端口附近 ±window 的一个小窗口
///    （碰运气，成功率低但成本低）。
/// ```
///
/// # 排序：**观测到的端口排在最前**
///
/// 这不是随手排的。锥型 NAT 下服务端看到的端口就是 peer 之间通信用的端口，
/// 而锥型 NAT 占了绝大多数 —— 把它排第一，这类场景第一发就中，
/// 不用等预测窗口一个个试过去。对称 NAT 下第一发打空也无所谓：
/// 调用方本来就会把所有候选都洒一遍，预测端口只是排在后面多试几个。
pub fn predict_ports(samples: &[u16], window: u16) -> Vec<u16> {
    let window = window.max(1);
    if samples.is_empty() {
        return Vec::new();
    }
    // 端口是 u16，加步长可能溢出，全程用 u32 算再夹回来
    let mut out: Vec<u32> = Vec::new();

    // 观测端口优先：锥型 NAT 的第一发就靠它
    out.extend(samples.iter().map(|p| *p as u32));

    if samples.len() >= 2 {
        let mut deltas: Vec<u32> = Vec::with_capacity(samples.len() - 1);
        for w in samples.windows(2) {
            // 用 wrapping 的方式算差，避免端口回绕（65535 -> 1）时算出巨大值
            deltas.push(w[1].wrapping_sub(w[0]) as u32);
        }
        deltas.sort_unstable();
        let step = deltas[deltas.len() / 2];
        if (1..=MAX_STEP as u32).contains(&step) {
            // 顺序分配：从最后一个观测端口往后推
            let last = samples[samples.len() - 1] as u32;
            for k in 1..=window as u32 {
                out.push(last.wrapping_add(k.wrapping_mul(step)) & 0xffff);
            }
        } else {
            // 随机分配：以每个观测端口为中心洒一个小窗口
            let spread = (window / 4).max(1) as u32;
            for p in samples {
                for d in 1..=spread {
                    out.push((*p as u32).wrapping_add(d) & 0xffff);
                    out.push((*p as u32).wrapping_sub(d) & 0xffff);
                }
            }
        }
    } else {
        // 只有一个样本：什么规律都看不出来，往后推一个窗口
        let base = samples[0] as u32;
        for k in 1..=window as u32 {
            out.push(base.wrapping_add(k) & 0xffff);
        }
    }

    // 去重（保留靠前的 = 可能性高的）
    let mut seen = std::collections::HashSet::new();
    out.retain(|p| seen.insert(*p));
    out.truncate(MAX_CANDIDATES);
    out.into_iter().map(|p| p as u16).collect()
}

/// 把一组候选端口嵌回对端的公网地址里（IP 不变）。
pub fn expand_candidates(sample_addrs: &[SocketAddr], window: u16) -> Vec<SocketAddr> {
    let Some(first) = sample_addrs.first() else {
        return Vec::new();
    };
    let ports: Vec<u16> = sample_addrs.iter().map(|a| a.port()).collect();
    let mut out: Vec<SocketAddr> = Vec::new();
    for p in predict_ports(&ports, window) {
        let mut a = *first;
        a.set_port(p);
        out.push(a);
    }
    out
}

// ---------------------------------------------------------------------------
// 编解码
// ---------------------------------------------------------------------------

/// 解析后的牵线报文。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Packet {
    /// 注册自己的公网地址（地址本身来自 UDP 源地址，不在报文里）。
    Hello {
        role: Role,
        sid: String,
        transport: Transport,
    },
    /// 服务端下发的对端地址（单个）。
    Peer {
        role: Role,
        sid: String,
        transport: Transport,
        addr: SocketAddr,
    },
    /// 服务端下发的对端地址（多个，用于端口预测）。
    Peers {
        role: Role,
        sid: String,
        transport: Transport,
        addrs: Vec<SocketAddr>,
    },
}

/// 编码一个 HELLO 报文。
pub fn encode_hello(role: Role, sid: &str, transport: Transport) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(HELLO_LEN);
    push_header(&mut out, kind::HELLO, role, sid, transport).then_some(out)
}

/// 编码一个 PEER 报文（下发对方的**单个**公网地址）。
pub fn encode_peer(
    role: Role,
    sid: &str,
    transport: Transport,
    addr: &SocketAddr,
) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(HELLO_LEN + 24);
    if !push_header(&mut out, kind::PEER, role, sid, transport) {
        return None;
    }
    put_str(&mut out, &addr.to_string());
    Some(out)
}

/// 编码一个 PEERS 报文（下发对方的**多个**公网地址，端口预测用）。
pub fn encode_peers(
    role: Role,
    sid: &str,
    transport: Transport,
    addrs: &[SocketAddr],
) -> Option<Vec<u8>> {
    if addrs.is_empty() || addrs.len() > 255 {
        return None;
    }
    let mut out = Vec::with_capacity(HELLO_LEN + 24 * addrs.len());
    if !push_header(&mut out, kind::PEERS, role, sid, transport) {
        return None;
    }
    out.push(addrs.len() as u8);
    for a in addrs {
        put_str(&mut out, &a.to_string());
    }
    Some(out)
}

fn push_header(out: &mut Vec<u8>, kind: u8, role: Role, sid: &str, transport: Transport) -> bool {
    if sid.len() != SID_LEN {
        return false;
    }
    out.extend_from_slice(&MAGIC);
    out.push(CURRENT_VERSION);
    out.push(kind);
    out.push(role.to_u8());
    out.push(transport.to_u8());
    out.extend_from_slice(sid.as_bytes());
    true
}

/// 长度前缀字符串（1 字节长度 + UTF-8）。
fn put_str(out: &mut Vec<u8>, s: &str) {
    let b = s.as_bytes();
    out.push(b.len().min(255) as u8);
    out.extend_from_slice(&b[..b.len().min(255)]);
}

/// 读取一个长度前缀字符串，返回 (内容, 新偏移)。
fn take_str(body: &[u8], i: &mut usize) -> Option<String> {
    if *i >= body.len() {
        return None;
    }
    let len = body[*i] as usize;
    *i += 1;
    if body.len() - *i < len {
        return None;
    }
    let s = std::str::from_utf8(&body[*i..*i + len]).ok()?.to_string();
    *i += len;
    Some(s)
}

/// 解码一个报文；格式不对就返回 `None`（调用方直接丢弃）。
pub fn decode(pkt: &[u8]) -> Option<Packet> {
    if pkt.len() < HELLO_LEN_V1 {
        return None;
    }
    if pkt[..4] != MAGIC {
        return None;
    }
    match pkt[4] {
        VERSION_V1 => decode_v1(pkt),
        VERSION_V2 => decode_v2(pkt),
        _ => None,
    }
}

/// v1 格式：头部 7 字节，地址串裸放在 sid 之后直到包尾。
fn decode_v1(pkt: &[u8]) -> Option<Packet> {
    let role = Role::from_u8(pkt[6])?;
    let sid = sid_at(pkt, SID_OFF_V1)?;
    match pkt[5] {
        kind::HELLO => Some(Packet::Hello {
            role,
            sid,
            transport: DEFAULT_TRANSPORT,
        }),
        kind::PEER => {
            let addr = std::str::from_utf8(&pkt[HELLO_LEN_V1..])
                .ok()
                .and_then(|s| s.parse().ok())?;
            Some(Packet::Peer {
                role,
                sid,
                transport: DEFAULT_TRANSPORT,
                addr,
            })
        }
        _ => None,
    }
}

/// v2 格式：头部 8 字节（含传输），地址串带长度前缀。
fn decode_v2(pkt: &[u8]) -> Option<Packet> {
    if pkt.len() < HELLO_LEN {
        return None;
    }
    let role = Role::from_u8(pkt[6])?;
    let transport = Transport::from_u8(pkt[7])?;
    let sid = sid_at(pkt, SID_OFF)?;
    let body = &pkt[HELLO_LEN..];
    match pkt[5] {
        kind::HELLO => Some(Packet::Hello {
            role,
            sid,
            transport,
        }),
        kind::PEER => {
            let mut i = 0;
            let addr = take_str(body, &mut i)?.parse().ok()?;
            Some(Packet::Peer {
                role,
                sid,
                transport,
                addr,
            })
        }
        kind::PEERS => {
            let mut i = 0;
            if body.is_empty() {
                return None;
            }
            let count = body[i] as usize;
            i += 1;
            let mut addrs = Vec::with_capacity(count);
            for _ in 0..count {
                addrs.push(take_str(body, &mut i)?.parse().ok()?);
            }
            if addrs.is_empty() {
                return None;
            }
            Some(Packet::Peers {
                role,
                sid,
                transport,
                addrs,
            })
        }
        _ => None,
    }
}

fn sid_at(pkt: &[u8], off: usize) -> Option<String> {
    let sid = std::str::from_utf8(&pkt[off..off + SID_LEN])
        .ok()?
        .to_string();
    if !sid.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    Some(sid)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sid() -> String {
        format!("{:032x}", 0xdead_beef_u64)
    }

    const V4: &str = "203.0.113.9:45001";

    #[test]
    fn hello_roundtrip() {
        let pkt = encode_hello(Role::Visitor, &sid(), Transport::Kcp).expect("32 字符的 sid");
        assert_eq!(pkt.len(), HELLO_LEN);
        assert_eq!(&pkt[..4], b"RTNL");
        assert_eq!(pkt[4], CURRENT_VERSION);
        assert_eq!(pkt[7], Transport::Kcp.to_u8());
        assert_eq!(
            decode(&pkt),
            Some(Packet::Hello {
                role: Role::Visitor,
                sid: sid(),
                transport: Transport::Kcp,
            })
        );
    }

    #[test]
    fn peer_roundtrip_keeps_address() {
        let addr: SocketAddr = V4.parse().unwrap();
        let pkt = encode_peer(Role::Provider, &sid(), Transport::Quic, &addr).unwrap();
        assert_eq!(
            decode(&pkt),
            Some(Packet::Peer {
                role: Role::Provider,
                sid: sid(),
                transport: Transport::Quic,
                addr,
            })
        );
    }

    #[test]
    fn peers_roundtrip_keeps_every_address() {
        let addrs: Vec<SocketAddr> = vec![
            "203.0.113.9:45001".parse().unwrap(),
            "203.0.113.9:45002".parse().unwrap(),
            "203.0.113.9:45003".parse().unwrap(),
        ];
        let pkt = encode_peers(Role::Visitor, &sid(), Transport::Quic, &addrs).unwrap();
        assert_eq!(
            decode(&pkt),
            Some(Packet::Peers {
                role: Role::Visitor,
                sid: sid(),
                transport: Transport::Quic,
                addrs,
            })
        );
    }

    #[test]
    fn ipv6_address_survives_encoding() {
        let addr: SocketAddr = "[2001:db8::1]:7788".parse().unwrap();
        let pkt = encode_peer(Role::Visitor, &sid(), Transport::Quic, &addr).unwrap();
        match decode(&pkt).unwrap() {
            Packet::Peer { addr: a, .. } => assert_eq!(a, addr),
            other => panic!("解析失败：{other:?}"),
        }
    }

    /// v1 报文（老版本 peer）必须还能解出来，只是没有传输协商。
    #[test]
    fn legacy_v1_packets_still_decode() {
        let mut hello = Vec::new();
        hello.extend_from_slice(&MAGIC);
        hello.push(VERSION_V1);
        hello.push(kind::HELLO);
        hello.push(Role::Visitor.to_u8());
        hello.extend_from_slice(sid().as_bytes());
        assert_eq!(
            decode(&hello),
            Some(Packet::Hello {
                role: Role::Visitor,
                sid: sid(),
                transport: DEFAULT_TRANSPORT,
            })
        );

        let mut peer = hello.clone();
        peer[5] = kind::PEER;
        peer.extend_from_slice(V4.as_bytes());
        match decode(&peer).unwrap() {
            Packet::Peer {
                addr, transport, ..
            } => {
                assert_eq!(addr, V4.parse::<SocketAddr>().unwrap());
                assert_eq!(transport, DEFAULT_TRANSPORT);
            }
            other => panic!("解析失败：{other:?}"),
        }
    }

    #[test]
    fn garbage_is_rejected() {
        assert_eq!(decode(b""), None, "空包");
        assert_eq!(decode(b"XXXX\x02\x01\x01\x01"), None, "魔数不对");
        assert_eq!(decode(b"RTNL\x09\x01\x01\x01"), None, "版本号不对");
        // 头部够长但类型未知
        let mut p = encode_hello(Role::Visitor, &sid(), Transport::Quic).unwrap();
        p[5] = 0x7f;
        assert_eq!(decode(&p), None, "未知类型");
        // 传输字节非法
        let mut p = encode_hello(Role::Visitor, &sid(), Transport::Quic).unwrap();
        p[7] = 9;
        assert_eq!(decode(&p), None);
        // 地址个数为 0 的 PEERS
        let mut p = encode_hello(Role::Visitor, &sid(), Transport::Quic).unwrap();
        p[5] = kind::PEERS;
        p.push(0);
        assert_eq!(decode(&p), None);
    }

    #[test]
    fn truncated_peers_is_rejected() {
        let addrs: Vec<SocketAddr> =
            vec!["1.2.3.4:1".parse().unwrap(), "1.2.3.4:2".parse().unwrap()];
        let mut pkt = encode_peers(Role::Visitor, &sid(), Transport::Quic, &addrs).unwrap();
        pkt.pop();
        assert_eq!(decode(&pkt), None, "截断的地址列表必须被拒绝");
    }

    #[test]
    fn sid_must_be_hex() {
        let bad = std::str::from_utf8(b"zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz").unwrap();
        let mut fake = vec![b'R', b'T', b'N', b'L', CURRENT_VERSION, kind::HELLO, 1, 1];
        fake.extend_from_slice(bad.as_bytes());
        assert_eq!(decode(&fake), None);
    }

    #[test]
    fn wrong_sid_length_cannot_be_encoded() {
        assert!(encode_hello(Role::Visitor, "short", Transport::Quic).is_none());
        assert!(encode_peers(Role::Visitor, "short", Transport::Quic, &[]).is_none());
        assert!(encode_peers(Role::Visitor, &sid(), Transport::Quic, &[]).is_none());
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

    // -----------------------------------------------------------------------
    // 端口预测
    // -----------------------------------------------------------------------

    #[test]
    fn sequential_nat_predicts_next_ports() {
        // 观测到 51000/51001/51002 → 步长 1 → 往 51003 之后推
        let c = predict_ports(&[51000, 51001, 51002], 4);
        // 观测端口排在最前（锥型 NAT 第一发就中），预测窗口跟在后面
        assert_eq!(
            c[..3],
            [51000, 51001, 51002],
            "观测端口必须排在最前：锥型 NAT 靠它第一发就中"
        );
        for p in [51003u16, 51004, 51005, 51006] {
            assert!(c.contains(&p), "顺序分配的预测端口 {p} 应当在候选里");
        }
    }

    #[test]
    fn step_of_two_is_detected() {
        let c = predict_ports(&[41000, 41002, 41004], 3);
        // 步长 2：从最后一个观测端口往后推
        for p in [41006u16, 41008, 41010] {
            assert!(c.contains(&p), "步长 2 应当预测出 {p}");
        }
        assert_eq!(c[..3], [41000, 41002, 41004]);
    }

    #[test]
    fn single_sample_predicts_a_window() {
        let c = predict_ports(&[60000], 3);
        assert_eq!(c[0], 60000, "观测端口排第一");
        for p in [60001u16, 60002, 60003] {
            assert!(c.contains(&p), "只有一个样本时也要往后推，{p} 应在候选里");
        }
    }

    #[test]
    fn random_nat_falls_back_to_a_spread() {
        // 差值大到不可能是顺序分配 → 退化为在观测端口附近洒点
        let c = predict_ports(&[10000, 55555, 20000], 8);
        assert!(!c.is_empty());
        for p in [10000u16, 55555, 20000] {
            assert!(c.contains(&p), "随机分配时观测端口本身必须保留");
        }
        // 窗口要能覆盖到邻近端口
        assert!(c.contains(&10001) || c.contains(&9999));
    }

    #[test]
    fn prediction_is_bounded_and_unique() {
        let c = predict_ports(&[1000, 1001, 1002, 1003, 1004], 200);
        assert!(c.len() <= MAX_CANDIDATES, "候选数必须有上限：{}", c.len());
        let mut sorted = c.clone();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(sorted.len(), c.len(), "候选端口不能重复");
    }

    #[test]
    fn port_wraparound_does_not_panic() {
        // 65534 -> 65535 -> 0：差值是 1（回绕），不能算出 4294967295
        let c = predict_ports(&[65534, 65535, 0], 3);
        assert!(
            c.contains(&1) && c.contains(&2) && c.contains(&3),
            "回绕后应当继续往后推 1、2、3，实际：{c:?}"
        );
    }

    #[test]
    fn empty_samples_predict_nothing() {
        assert!(predict_ports(&[], 8).is_empty());
        assert!(expand_candidates(&[], 8).is_empty());
    }

    #[test]
    fn expand_candidates_keeps_ip() {
        let addrs: Vec<SocketAddr> = vec![
            "203.0.113.9:51000".parse().unwrap(),
            "203.0.113.9:51001".parse().unwrap(),
        ];
        let c = expand_candidates(&addrs, 2);
        assert!(c.iter().all(|a| a.ip().to_string() == "203.0.113.9"));
        assert!(c.contains(&"203.0.113.9:51002".parse().unwrap()));
    }
}
