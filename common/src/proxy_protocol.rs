//! HAProxy PROXY protocol（v1 文本 / v2 二进制）编解码。
//!
//! # 为什么需要
//!
//! 内网服务想知道"真实来访者的 IP"时，最省事的做法是让前面的那一跳把来源地址
//! 写进连接本身 —— 这就是 PROXY protocol。NFrp 在这里要扮演那一跳：
//! 客户端拿到工作连接后，先往内网服务写一段 PROXY 头，再开始转发用户字节。
//!
//! 对比：
//!
//! | | v1 | v2 |
//! |---|---|---|
//! | 形态 | 一行 ASCII，`PROXY TCP4 1.2.3.4 5.6.7.8 1 2\r\n` | 12 字节签名 + 二进制地址块 |
//! | 上限 | 107 字节 | 16 + 4 + 2×(16+2) = 52 字节 |
//! | 支持 | TCP4 / TCP6 / UNKNOWN | TCP/UDP × IPv4/IPv6/UNIX |
//! | 兼容 | 几乎所有（Nginx / HAProxy / MySQL 都认） | 需要对方显式开启 |
//!
//! 两端都实现：**编码**用于客户端连内网服务时注入，**解码**用于服务端在
//! `vhost` 入口前置 LB 场景下把真实来源地址还原回 `StartWorkConn` 的字段。
//!
//! # 官方参考
//!
//! frp 用的是 `github.com/pires/go-proxyproto`：
//! `BuildProxyProtocolHeader(srcAddr, dstAddr, version)` 里
//! 「`v1` → versionByte=1，其余 → 2」，与我们这里的语义一致。

use std::net::SocketAddr;

use crate::error::{Error, Result};

/// v1 头部的长度上限（规范里写死 107，含结尾 CRLF）。
pub const V1_MAX_LEN: usize = 107;

/// v2 的 12 字节固定签名。
pub const V2_SIGNATURE: [u8; 12] = [
    0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A,
];

/// v2 版本 + 命令字节：高 4 位固定是 2（版本），低 4 位是命令。
const V2_CMD_PROXY: u8 = 0x21;
/// `LOCAL`：连接是 LB 自己发起的（健康检查），地址块必须为空。
const V2_CMD_LOCAL: u8 = 0x20;

/// 地址族/协议字节的低 4 位。
const V2_FAM_INET: u8 = 0x1;
const V2_FAM_INET6: u8 = 0x2;
/// 高 4 位：1 = STREAM（TCP），2 = DGRAM（UDP）。
const V2_PROTO_STREAM: u8 = 0x1;
const V2_PROTO_DGRAM: u8 = 0x2;

/// 传输层协议。目前只做 TCP —— frp 的 proxyProtocol 也只用在 tcp 代理上。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Transport {
    #[default]
    Stream,
    Datagram,
}

impl Transport {
    fn nibble(&self) -> u8 {
        match self {
            Self::Stream => V2_PROTO_STREAM,
            Self::Datagram => V2_PROTO_DGRAM,
        }
    }
}

/// PROXY 头解析结果。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Header {
    /// 明确的来源 / 目的地址。
    Proxy {
        src: SocketAddr,
        dst: SocketAddr,
        transport: Transport,
    },
    /// v1 的 `PROXY UNKNOWN`，或 v2 的 `LOCAL` 命令：**不带**地址信息，
    /// 后面直接就是应用数据。
    Unknown,
}

impl Header {
    /// 取来源地址（`Unknown` 时返回 None）。
    pub fn src(&self) -> Option<SocketAddr> {
        match self {
            Self::Proxy { src, .. } => Some(*src),
            Self::Unknown => None,
        }
    }

    /// 取目的地址（`Unknown` 时返回 None）。
    pub fn dst(&self) -> Option<SocketAddr> {
        match self {
            Self::Proxy { dst, .. } => Some(*dst),
            Self::Unknown => None,
        }
    }
}

// ---------------------------------------------------------------------------
// 编码
// ---------------------------------------------------------------------------

/// 按 `version` 生成一个 PROXY 头。
///
/// `version` 的取值与 frp 一致：`"v1"` 走文本版，**其它任何值**（含空串之外的
/// `"v2"`）都走二进制版。注意空串表示"不启用"，由调用方在外面判断，
/// 这里拿到空串会当作 v2 —— 所以别把空串传进来。
pub fn encode(src: &SocketAddr, dst: &SocketAddr, version: &str) -> Result<Vec<u8>> {
    if version.eq_ignore_ascii_case("v1") {
        encode_v1(src, dst)
    } else {
        encode_v2(src, dst, Transport::Stream)
    }
}

/// 生成 v1（文本）头。
///
/// 地址族必须左右一致：`TCP4` 行里塞 IPv6 是非法的，混用会让下游直接丢连接。
pub fn encode_v1(src: &SocketAddr, dst: &SocketAddr) -> Result<Vec<u8>> {
    let family = match (src, dst) {
        (SocketAddr::V4(_), SocketAddr::V4(_)) => "TCP4",
        (SocketAddr::V6(_), SocketAddr::V6(_)) => "TCP6",
        _ => {
            return Err(Error::Protocol(
                "PROXY v1 的两端地址族必须一致（不能一边 IPv4 一边 IPv6）".into(),
            ))
        }
    };
    // IPv6 在 v1 里是不带方括号的裸地址
    let text = format!(
        "PROXY {family} {} {} {} {}\r\n",
        src.ip(),
        dst.ip(),
        src.port(),
        dst.port()
    );
    if text.len() > V1_MAX_LEN {
        return Err(Error::Protocol(format!(
            "PROXY v1 头 {} 字节，超过规范上限 {V1_MAX_LEN}",
            text.len()
        )));
    }
    Ok(text.into_bytes())
}

/// 生成 v2（二进制）头。
pub fn encode_v2(src: &SocketAddr, dst: &SocketAddr, transport: Transport) -> Result<Vec<u8>> {
    let (family, src_bytes, dst_bytes) = match (src, dst) {
        (SocketAddr::V4(s), SocketAddr::V4(d)) => (
            V2_FAM_INET,
            s.ip().octets().to_vec(),
            d.ip().octets().to_vec(),
        ),
        (SocketAddr::V6(s), SocketAddr::V6(d)) => (
            V2_FAM_INET6,
            s.ip().octets().to_vec(),
            d.ip().octets().to_vec(),
        ),
        _ => {
            return Err(Error::Protocol(
                "PROXY v2 的两端地址族必须一致（不能一边 IPv4 一边 IPv6）".into(),
            ))
        }
    };
    let addr_len = (src_bytes.len() + dst_bytes.len() + 4) as u16;

    let mut out = Vec::with_capacity(16 + addr_len as usize);
    out.extend_from_slice(&V2_SIGNATURE);
    out.push(V2_CMD_PROXY);
    // 第 13 字节：**高半字节 = 地址族、低半字节 = 传输协议**（HAProxy 规范）。
    // 写反了本实现对拷能过，但 HAProxy / Nginx 会整个读错 —— 必须按规范来。
    out.push((family << 4) | transport.nibble());
    out.extend_from_slice(&addr_len.to_be_bytes());
    out.extend_from_slice(&src_bytes);
    out.extend_from_slice(&dst_bytes);
    out.extend_from_slice(&src.port().to_be_bytes());
    out.extend_from_slice(&dst.port().to_be_bytes());
    Ok(out)
}

/// 生成 v2 的 `LOCAL` 头（不带地址，共 16 字节）。
///
/// 用途：LB 自己发起连接（健康检查）时不能瞎填来源地址 —— 规范要求用 LOCAL
/// 命令，且地址块长度为 0。下游解析到它就当"没有 PROXY 信息"。
pub fn encode_v2_local() -> Vec<u8> {
    let mut out = Vec::with_capacity(16);
    out.extend_from_slice(&V2_SIGNATURE);
    out.push(V2_CMD_LOCAL);
    out.push(0x00);
    out.extend_from_slice(&0u16.to_be_bytes());
    out
}

// ---------------------------------------------------------------------------
// 解码
// ---------------------------------------------------------------------------

/// 嗅探缓冲区开头是不是 PROXY 头；**不消费**任何字节。
///
/// 返回 `None` 表示"不像 PROXY 头" —— 调用方应当原样把字节当应用数据处理。
///
/// 返回 `Some((header, n))` 表示**确实**是 PROXY 头，`n` 是头长度（字节），
/// 调用方应跳过这 `n` 个字节。`n == 0` 是个特殊信号：**看起来像但还没收全**，
/// 调用方应继续读一段再 `sniff`。
///
/// 之所以用 `n == 0` 而不是 `None` 表达"没收全"：`None` 一旦被调用方理解成
/// "不是 PROXY 头"，它会把这半截二进制当成应用数据吐给后端 —— 这正是
/// PROXY 协议最经典的注入漏洞。区分开才不会误判。
pub fn sniff(buf: &[u8]) -> Option<(Header, usize)> {
    // 已经收到的字节必须是签名的**前缀**（哪怕只收到前两个字节），
    // 否则直接判定"不是 PROXY"。少收几个字节就放行会让半截二进制漏给后端。
    let sig_probe = buf.len().min(V2_SIGNATURE.len());
    if buf[..sig_probe] == V2_SIGNATURE[..sig_probe] {
        // v2 至少要 16 字节才够读固定头里的长度字段
        if buf.len() < 16 {
            return Some((Header::Unknown, 0));
        }
        return match decode_v2(buf) {
            Ok((h, n)) => Some((h, n)),
            // 签名对了但长度还不够（local 地址 / TLVs 没收全）
            Err(_) => Some((Header::Unknown, 0)),
        };
    }
    // v1 一定以 "PROXY " 开头（6 字节）。前缀本身可能还没收全。
    let probe = buf.len().min(6);
    if buf[..probe].eq_ignore_ascii_case(&b"PROXY "[..probe]) {
        if probe < 6 {
            return Some((Header::Unknown, 0));
        }
        return match decode_v1(buf) {
            Ok(Some((h, n))) => Some((h, n)),
            // 行还没收全：让调用方继续读
            Ok(None) => Some((Header::Unknown, 0)),
            // 格式非法：头确实是 PROXY，但没法用 —— 交给调用方按策略拒绝
            Err(_) => Some((Header::Unknown, 0)),
        };
    }
    None
}

/// 解析 v1 头。返回 `Ok(None)` 表示"行还没收全"，需要继续读。
pub fn decode_v1(buf: &[u8]) -> Result<Option<(Header, usize)>> {
    let end = match find_crlf(buf) {
        Some(i) => i,
        None => {
            if buf.len() > V1_MAX_LEN {
                return Err(Error::Protocol("PROXY v1 头超过 107 字节仍未结束".into()));
            }
            return Ok(None);
        }
    };
    let line = std::str::from_utf8(&buf[..end])
        .map_err(|_| Error::Protocol("PROXY v1 头不是合法 ASCII".into()))?;
    let total = end + 2;

    let mut it = line.split(' ');
    let magic = it.next().unwrap_or_default();
    if !magic.eq_ignore_ascii_case("PROXY") {
        return Err(Error::Protocol(format!("PROXY v1 头前缀非法：{magic:?}")));
    }
    let proto = it.next().unwrap_or_default();
    if proto.eq_ignore_ascii_case("UNKNOWN") {
        // 规范：UNKNOWN 后面允许跟任意内容，全部忽略
        return Ok(Some((Header::Unknown, total)));
    }
    let (v4, v6) = (
        proto.eq_ignore_ascii_case("TCP4"),
        proto.eq_ignore_ascii_case("TCP6"),
    );
    if !v4 && !v6 {
        return Err(Error::Protocol(format!("PROXY v1 不支持的协议：{proto:?}")));
    }
    let mut next = || it.next().unwrap_or_default().to_string();
    let (sip, dip, sport, dport) = (next(), next(), next(), next());
    if it.next().is_some() {
        return Err(Error::Protocol("PROXY v1 头字段过多".into()));
    }

    let src = parse_v1_addr(&sip, &sport, v6)?;
    let dst = parse_v1_addr(&dip, &dport, v6)?;
    Ok(Some((
        Header::Proxy {
            src,
            dst,
            transport: Transport::Stream,
        },
        total,
    )))
}

fn parse_v1_addr(ip: &str, port: &str, v6: bool) -> Result<SocketAddr> {
    let ip: std::net::IpAddr = ip
        .parse()
        .map_err(|_| Error::Protocol(format!("PROXY v1 里的 IP 非法：{ip:?}")))?;
    if ip.is_ipv4() == v6 {
        return Err(Error::Protocol(format!(
            "PROXY v1 声明的是 {}，却给了 {ip}",
            if v6 { "TCP6" } else { "TCP4" }
        )));
    }
    let port: u16 = port
        .parse()
        .map_err(|_| Error::Protocol(format!("PROXY v1 里的端口非法：{port:?}")))?;
    Ok(SocketAddr::new(ip, port))
}

/// 解析 v2 头，返回 `(头部, 总长度)`。
pub fn decode_v2(buf: &[u8]) -> Result<(Header, usize)> {
    if buf.len() < 16 {
        return Err(Error::Protocol("PROXY v2 头不足 16 字节".into()));
    }
    if buf[..12] != V2_SIGNATURE {
        return Err(Error::Protocol("PROXY v2 签名不匹配".into()));
    }
    let ver_cmd = buf[12];
    if ver_cmd >> 4 != 2 {
        return Err(Error::Protocol(format!(
            "PROXY v2 版本号应为 2，实际 {}",
            ver_cmd >> 4
        )));
    }
    let cmd = ver_cmd & 0x0f;
    let fam_proto = buf[13];
    let addr_len = u16::from_be_bytes([buf[14], buf[15]]) as usize;
    let total = 16 + addr_len;
    if buf.len() < total {
        return Err(Error::Protocol("PROXY v2 地址块被截断".into()));
    }
    if cmd == 0x0 {
        // LOCAL：地址块必须为空（规范要求），但我们**不因此报错** ——
        // 有些实现会多塞几个字节，宽容一点不会出安全问题。
        return Ok((Header::Unknown, total));
    }
    if cmd != 0x1 {
        return Err(Error::Protocol(format!("PROXY v2 命令不支持：{cmd}")));
    }

    // 第 13 字节：高半字节 = 地址族，低半字节 = 传输协议（与 encode_v2 对称）
    let family = fam_proto >> 4;
    let proto = fam_proto & 0x0f;
    let transport = match proto {
        V2_PROTO_STREAM => Transport::Stream,
        V2_PROTO_DGRAM => Transport::Datagram,
        other => return Err(Error::Protocol(format!("PROXY v2 传输协议不支持：{other}"))),
    };
    let body = &buf[16..total];
    let (src, dst) = match family {
        V2_FAM_INET => {
            if body.len() < 12 {
                return Err(Error::Protocol("PROXY v2 IPv4 地址块过短".into()));
            }
            let s = std::net::Ipv4Addr::new(body[0], body[1], body[2], body[3]);
            let d = std::net::Ipv4Addr::new(body[4], body[5], body[6], body[7]);
            let sp = u16::from_be_bytes([body[8], body[9]]);
            let dp = u16::from_be_bytes([body[10], body[11]]);
            (SocketAddr::from((s, sp)), SocketAddr::from((d, dp)))
        }
        V2_FAM_INET6 => {
            if body.len() < 36 {
                return Err(Error::Protocol("PROXY v2 IPv6 地址块过短".into()));
            }
            let mut s = [0u8; 16];
            let mut d = [0u8; 16];
            s.copy_from_slice(&body[0..16]);
            d.copy_from_slice(&body[16..32]);
            let sp = u16::from_be_bytes([body[32], body[33]]);
            let dp = u16::from_be_bytes([body[34], body[35]]);
            (
                SocketAddr::from((std::net::Ipv6Addr::from(s), sp)),
                SocketAddr::from((std::net::Ipv6Addr::from(d), dp)),
            )
        }
        other => {
            return Err(Error::Protocol(format!(
                "PROXY v2 地址族不支持：{other}（只实现了 IPv4 / IPv6）"
            )))
        }
    };
    Ok((
        Header::Proxy {
            src,
            dst,
            transport,
        },
        total,
    ))
}

/// 从头里取出 `"\r\n"` 的位置（不含）。
fn find_crlf(buf: &[u8]) -> Option<usize> {
    buf.windows(2).position(|w| w == b"\r\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v4() -> (SocketAddr, SocketAddr) {
        (
            "192.0.2.10:45678".parse().unwrap(),
            "203.0.113.5:443".parse().unwrap(),
        )
    }

    /// v1 的文本形态必须与规范逐字节一致 —— 下游（Nginx / MySQL）是按
    /// 空格切分再逐字段解析的，多一个空格都会让它认不出来。
    #[test]
    fn v1_文本与规范逐字节一致() {
        let (s, d) = v4();
        let got = encode_v1(&s, &d).unwrap();
        assert_eq!(
            String::from_utf8(got).unwrap(),
            "PROXY TCP4 192.0.2.10 203.0.113.5 45678 443\r\n"
        );
    }

    #[test]
    fn v1_ipv6_不带方括号() {
        let s: SocketAddr = "[2001:db8::1]:1".parse().unwrap();
        let d: SocketAddr = "[2001:db8::2]:2".parse().unwrap();
        let text = String::from_utf8(encode_v1(&s, &d).unwrap()).unwrap();
        assert_eq!(text, "PROXY TCP6 2001:db8::1 2001:db8::2 1 2\r\n");
        assert!(!text.contains('['), "v1 规范里 IPv6 是裸地址：{text}");
    }

    /// 两边地址族不一致要**报错**，不能凑合 —— 凑合出来的头下游会直接丢连接，
    /// 而且报错点离现场很远。
    #[test]
    fn 地址族混用被拒绝() {
        let s: SocketAddr = "192.0.2.1:1".parse().unwrap();
        let d: SocketAddr = "[2001:db8::1]:2".parse().unwrap();
        assert!(encode_v1(&s, &d).is_err());
        assert!(encode_v2(&s, &d, Transport::Stream).is_err());
    }

    #[test]
    fn v2_二进制头布局正确() {
        let (s, d) = v4();
        let got = encode_v2(&s, &d, Transport::Stream).unwrap();
        assert_eq!(got.len(), 16 + 12, "12 字节签名/头 + 12 字节 IPv4 地址块");
        assert_eq!(&got[..12], &V2_SIGNATURE);
        assert_eq!(got[12], 0x21, "版本 2 + 命令 PROXY");
        assert_eq!(got[13], 0x11, "STREAM + AF_INET");
        assert_eq!(u16::from_be_bytes([got[14], got[15]]), 12);
        assert_eq!(&got[16..20], &[192, 0, 2, 10]);
        assert_eq!(&got[20..24], &[203, 0, 113, 5]);
        assert_eq!(u16::from_be_bytes([got[24], got[25]]), 45678);
        assert_eq!(u16::from_be_bytes([got[26], got[27]]), 443);
    }

    #[test]
    fn v2_local_头没有地址块() {
        let h = encode_v2_local();
        assert_eq!(h.len(), 16);
        assert_eq!(h[12], 0x20, "版本 2 + 命令 LOCAL");
        assert_eq!(u16::from_be_bytes([h[14], h[15]]), 0);
        match decode_v2(&h).unwrap() {
            (Header::Unknown, 16) => {}
            other => panic!("LOCAL 头应当解成 Unknown，实际 {other:?}"),
        }
    }

    /// 编码 → 解码必须原样还原（四种地址族组合）。
    #[test]
    fn v1_v2_往返() {
        for (s, d) in [
            v4(),
            (
                "[2001:db8::1]:65535".parse().unwrap(),
                "[fe80::2]:1".parse().unwrap(),
            ),
        ] {
            for ver in ["v1", "v2", "anything-else"] {
                let raw = encode(&s, &d, ver).unwrap();
                let (h, n) = sniff(&raw).expect("应当被识别成 PROXY 头");
                assert_eq!(n, raw.len(), "给出的长度必须正好是头的长度");
                assert_eq!(h.src(), Some(s), "版本 {ver} 的来源地址");
                assert_eq!(h.dst(), Some(d), "版本 {ver} 的目的地址");
            }
        }
    }

    /// 不是 PROXY 头的字节流不能被误判 —— 否则普通业务流量会被吃掉一段。
    #[test]
    fn 普通数据不会被误判() {
        assert!(sniff(b"GET / HTTP/1.1\r\n").is_none());
        assert!(
            sniff(b"\x16\x03\x01\x00\x00").is_none(),
            "TLS 握手不是 PROXY"
        );
        // 半个签名 / 只收到 "PROXY"：**像**但没定论。这时绝不能回 `None`
        // （`None` 意味着"不是 PROXY 头，按普通数据放行"）—— 那正是
        // PROXY 协议最经典的注入漏洞。要用 `(Unknown, 0)` 表示"继续读"。
        assert!(matches!(sniff(b"PROXY"), Some((Header::Unknown, 0))));
        assert!(matches!(
            sniff(&V2_SIGNATURE[..8]),
            Some((Header::Unknown, 0))
        ));
        // 完整签名 + 但是头没读全，同样是"继续读"
        assert!(matches!(sniff(&V2_SIGNATURE), Some((Header::Unknown, 0))));
    }

    /// 收到完整的 v2 头之后必须给出正确长度，绝不许多吞或少吞一个字节。
    #[test]
    fn v2_头长度与规范一致() {
        let (s, d) = v4();
        let raw = encode_v2(&s, &d, Transport::Stream).unwrap();
        // 12 字节签名 + 4 字节定长头 + (4+4+2+2) 地址块 = 28
        assert_eq!(raw.len(), 28);
        assert_eq!(sniff(&raw), Some((decode_v2(&raw).unwrap().0, 28)));
    }

    #[test]
    fn v1_unknown_行被识别为无地址() {
        let (h, n) = decode_v1(b"PROXY UNKNOWN\r\n").unwrap().unwrap();
        assert_eq!(h, Header::Unknown);
        assert_eq!(n, 15);
    }

    /// 行没收全时必须回 `Ok(None)` 让调用方继续读，而不是直接报错 ——
    /// TCP 分段把一行切成两半是常态。
    #[test]
    fn v1_半行返回未就绪() {
        assert!(decode_v1(b"PROXY TCP4 192.0.2.10 203.0.113.5 45678 44")
            .unwrap()
            .is_none());
        // 超过 107 字节还没 CRLF 才是真的错
        let long = vec![b'x'; 120];
        assert!(decode_v1(&long).is_err());
    }

    #[test]
    fn v1_字段非法时报错而不是猜() {
        assert!(decode_v1(b"PROXY TCP4 999.1.1.1 203.0.113.5 1 2\r\n").is_err());
        assert!(decode_v1(b"PROXY TCP4 192.0.2.10 203.0.113.5 1 2 3\r\n").is_err());
        assert!(decode_v1(b"PROXY SCTP 192.0.2.10 203.0.113.5 1 2\r\n").is_err());
        // 声明 TCP6 却给 IPv4
        assert!(decode_v1(b"PROXY TCP6 192.0.2.10 203.0.113.5 1 2\r\n").is_err());
    }

    #[test]
    fn v2_ipv6_往返() {
        let s: SocketAddr = "[2001:db8::1]:1000".parse().unwrap();
        let d: SocketAddr = "[2001:db8::2]:2000".parse().unwrap();
        let raw = encode_v2(&s, &d, Transport::Stream).unwrap();
        assert_eq!(raw[13], 0x21, "STREAM + AF_INET6");
        let (h, n) = decode_v2(&raw).unwrap();
        assert_eq!(n, raw.len());
        assert_eq!(h.src(), Some(s));
        assert_eq!(h.dst(), Some(d));
    }

    #[test]
    fn v2_udp_传输位被保留() {
        let (s, d) = v4();
        let raw = encode_v2(&s, &d, Transport::Datagram).unwrap();
        assert_eq!(raw[13], 0x12, "DGRAM + AF_INET");
        match decode_v2(&raw).unwrap().0 {
            Header::Proxy { transport, .. } => assert_eq!(transport, Transport::Datagram),
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn v2_错误输入被拒绝() {
        let (s, d) = v4();
        let mut raw = encode_v2(&s, &d, Transport::Stream).unwrap();
        raw[12] = 0x31; // 版本 3
        assert!(decode_v2(&raw).is_err());
        let raw2 = encode_v2(&s, &d, Transport::Stream).unwrap();
        assert!(decode_v2(&raw2[..20]).is_err(), "地址块被截断要报错");
    }
}
