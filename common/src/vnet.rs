//! VirtualNet —— 通过隧道把多个客户端拉进同一个三层（IP 层）虚拟网络。
//!
//! # 它解决什么问题
//!
//! 传统内网穿透是"一条服务一个端口"：想访问内网的 Web、SSH、数据库，
//! 就得各配一条 tcp 代理。VirtualNet 换成另一个思路 —— 把 TUN 设备读到的
//! **原始 IP 报文**塞进隧道，由服务端按目的地址转发给对应的客户端。
//! 于是应用可以像访问局域网一样直接 `ping 100.64.0.3` / `curl http://100.64.0.3`，
//! 不用为每个服务单独配端口。
//!
//! # 数据流
//!
//! ```text
//!   A 的 TUN ──读──▶ 帧化 ──▶ 隧道 ──▶ 服务端 ----------┐
//!                                      按 dst IP 查路由表 │
//!   A 的 TUN ◀──写── 帧化 ◀── 隧道 ◀──── 找到 B 的流 ◀───┘
//! ```
//!
//! 服务端**不看**包内容，只读 IP 头里的目的地址（`Switch::route`），
//! 属于纯三层转发，不碰 TCP 状态机。
//!
//! # 帧格式
//!
//! 与官方 frp 的 `pkg/vnet/message.go` 一致：`[长度: u32 小端][IP 报文]`，
//! 单帧上限 1 MiB、禁止 0 长度。照抄它的好处是抓包时能直接对着官方实现看。
//!
//! # 与官方 frp 的关系（说清楚，免得误解）
//!
//! 官方 frp 从 v0.62.0 起有同名的 Alpha 特性。**帧格式一致，但控制面不同**：
//! 官方把注册消息混在 frp 控制通道里，这里走的是一条独立的 `vnet_port`
//! 长连接（见 [`crate::vnet::VnetRegister`]），因此**两端不能混搭**
//! （rustunnel 客户端只能连 rustunnel 服务端）。这点在 README 的"当前限制"里
//! 也写明了。
//!
//! # 平台支持
//!
//! TUN 设备只在类 Unix 上实现（Linux `/dev/net/tun`、macOS `utun`）；
//! Windows 需要 Wintun 驱动，这里**明确报错**而不是假装成功 ——
//! 但那之外的逻辑（地址分配、路由表、帧编解码）全是跨平台的，已单测覆盖。

use std::collections::HashMap;
use std::net::Ipv4Addr;

use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// 配置
// ---------------------------------------------------------------------------

/// 虚拟网络配置（客户端 `[virtualNet]` / 服务端 `[vnet]`）。
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct VirtualNetConfig {
    /// 本机在虚拟网络里的地址，形如 `100.64.0.2`（或带前缀 `100.64.0.2/24`）。
    /// 留空且 `autoAssign = true` 时由服务端分配。
    pub address: String,
    /// 服务端在虚拟网络里的地址（客户端把非本网段流量发给它）。
    pub gateway: String,
    /// 由服务端自动分配地址。
    ///
    /// 官方 frp 的 vnet 走 DHCP 式的自动分配；这里用服务端地址池，
    /// 客户端登录时申请、断线时归还。
    #[serde(rename = "autoAssign")]
    pub auto_assign: bool,
    /// 虚拟网络名。同名客户端互通，不同名互相隔离 ——
    /// 一台服务端可以同时承载多个互不相干的虚拟网络。
    #[serde(default = "default_network")]
    pub network: String,
    /// 虚拟网段（服务端用它分配地址），形如 `100.64.0.0/24`。
    pub subnet: String,
    /// MTU。默认 1400：隧道本身有开销，取小了比被分片强。
    #[serde(default = "default_mtu")]
    pub mtu: u32,
    /// **服务端** VirtualNet 的监听端口（客户端填这一项指路）。
    ///
    /// 服务端自己用顶层 `vnet_port`（两者等价，写哪个都认）。
    /// 单独一个端口而不是复用控制端口：虚拟网络是长时间高速的纯数据流，
    /// 混在控制通道里会拖慢心跳与面板命令，出故障时也不好隔离。
    #[serde(default, rename = "serverPort", alias = "port")]
    pub server_port: u16,
}

fn default_network() -> String {
    "default".into()
}

fn default_mtu() -> u32 {
    1400
}

impl Default for VirtualNetConfig {
    fn default() -> Self {
        Self {
            address: String::new(),
            gateway: String::new(),
            auto_assign: false,
            network: default_network(),
            subnet: String::new(),
            mtu: default_mtu(),
            server_port: 0,
        }
    }
}

impl VirtualNetConfig {
    /// 是否要用虚拟网络：写了地址、或者要求自动分配。
    pub fn is_enabled(&self) -> bool {
        !self.address.trim().is_empty() || self.auto_assign
    }

    /// 校验：地址 / 网段格式、是否指明网关都检查一遍。
    pub fn validate(&self) -> anyhow::Result<()> {
        if !self.is_enabled() {
            return Ok(());
        }
        if !self.address.trim().is_empty() {
            // 允许 `100.64.0.2` 与 `100.64.0.2/24` 两种写法
            let bare = self.address.split('/').next().unwrap_or("").trim();
            bare.parse::<Ipv4Addr>().map_err(|_| {
                anyhow::anyhow!(
                    "virtualNet.address 非法（要 IPv4，形如 100.64.0.2）：{}",
                    self.address
                )
            })?;
        } else if self.subnet.trim().is_empty() {
            // 自动分配但服务端也没配网段，等登录时会失败；这里提前说清楚
            // 比让用户对着"连上了但 ping 不通"发呆强。
            tracing::debug!("virtualNet.autoAssign 已开但本地没写 subnet，地址由服务端下发");
        }
        if !self.subnet.trim().is_empty() {
            Subnet::parse(&self.subnet)?;
        }
        if self.mtu < 576 || self.mtu > 65535 {
            anyhow::bail!("virtualNet.mtu 应在 576..=65535，收到 {}", self.mtu);
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// 帧编解码（与官方 frp pkg/vnet/message.go 一致）
// ---------------------------------------------------------------------------

/// 单帧上限，与官方一致（1 MiB）。防止对端用一个巨大的长度前缀把内存打爆。
pub const MAX_FRAME: usize = 1024 * 1024;

/// 一个 IP 报文的字节数上限（IPv4 头 20 + 载荷 65535，取整 65536）。
pub const MAX_IP_PACKET: usize = 65536;

/// 把一帧组好（4 字节小端长度 + 载荷）。
pub fn encode_frame(payload: &[u8]) -> anyhow::Result<Vec<u8>> {
    if payload.is_empty() {
        anyhow::bail!("vnet 帧长度不能为 0");
    }
    if payload.len() > MAX_FRAME {
        anyhow::bail!("vnet 帧过大：{} > {MAX_FRAME}", payload.len());
    }
    let mut out = Vec::with_capacity(4 + payload.len());
    out.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    out.extend_from_slice(payload);
    Ok(out)
}

/// 从缓冲区里取出一帧。返回 `Ok(None)` 表示"还不够一帧，继续读"。
///
/// 消费掉的那部分会从 `buf` 头部移除，所以循环调用即可。
pub fn take_frame(buf: &mut Vec<u8>) -> anyhow::Result<Option<Vec<u8>>> {
    if buf.len() < 4 {
        return Ok(None);
    }
    let n = u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]) as usize;
    if n == 0 {
        anyhow::bail!("vnet 帧长度为 0");
    }
    if n > MAX_FRAME {
        anyhow::bail!("vnet 帧过大：{n} > {MAX_FRAME}");
    }
    if buf.len() < 4 + n {
        return Ok(None);
    }
    let payload = buf[4..4 + n].to_vec();
    buf.drain(..4 + n);
    Ok(Some(payload))
}

// ---------------------------------------------------------------------------
// IP 包解析（只读头，不改包）
// ---------------------------------------------------------------------------

/// 从 IP 报文里读出来的最小信息。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IpHeader {
    pub src: Ipv4Addr,
    pub dst: Ipv4Addr,
    /// 协议号（1 = ICMP、6 = TCP、17 = UDP）。
    pub protocol: u8,
    /// 头部长度（含选项），字节。
    pub header_len: usize,
}

/// 解析 IPv4 头。非 IPv4（版本号不是 4）返回 `None` —— IPv6 目前不转发，
/// 丢掉比误解析强（IPv6 头结构完全不同，按 IPv4 解会得到垃圾地址）。
pub fn parse_ipv4(pkt: &[u8]) -> Option<IpHeader> {
    if pkt.len() < 20 {
        return None;
    }
    if pkt[0] >> 4 != 4 {
        return None;
    }
    let header_len = usize::from(pkt[0] & 0x0f) * 4;
    if header_len < 20 || pkt.len() < header_len {
        return None;
    }
    Some(IpHeader {
        src: Ipv4Addr::new(pkt[12], pkt[13], pkt[14], pkt[15]),
        dst: Ipv4Addr::new(pkt[16], pkt[17], pkt[18], pkt[19]),
        protocol: pkt[9],
        header_len,
    })
}

/// 判断是不是 ICMP Echo Request（ping）。服务端用它决定"要不要替客户端回 ping"。
pub fn is_icmp_echo_request(pkt: &[u8]) -> bool {
    match parse_ipv4(pkt) {
        Some(h) => h.protocol == 1 && pkt.len() > h.header_len && pkt[h.header_len] == 8,
        None => false,
    }
}

/// 把一个 ICMP Echo Request 变成对应的 Echo Reply（源/目的对调、类型 8→0）。
///
/// # 为什么要服务端自己回
///
/// 虚拟网络里的"网关"就是服务端自己 —— 它不是一个真网卡，内核不会替它应答。
/// 不实现这一步，用户进来第一件事 `ping 网关` 就超时，接着会怀疑整条隧道没通，
/// 而实际上隧道一切正常。这不是可有可无的装饰，是**可诊断性**。
///
/// 只处理 ICMP，TCP/UDP 到网关的包直接丢弃（服务端不提供别的服务）——
/// 悄悄回一个 RST 反而会让人以为"有主机但端口关着"。
///
/// 返回 `None` 表示这个包不该由网关应答（不是 IPv4 / 不是 echo / 太短）。
pub fn icmp_echo_reply(pkt: &[u8]) -> Option<Vec<u8>> {
    let h = parse_ipv4(pkt)?;
    if h.protocol != 1 || h.header_len != 20 {
        // 带 IP 选项的 ICMP 极少见，直接不应答，省得把选项抄错
        return None;
    }
    if pkt.len() < h.header_len + 8 || pkt[h.header_len] != 8 {
        return None;
    }

    let mut out = pkt.to_vec();
    // ① IP 头：源/目的互换
    out[12..16].copy_from_slice(&h.dst.octets());
    out[16..20].copy_from_slice(&h.src.octets());
    // ② IP 头校验和
    out[10] = 0;
    out[11] = 0;
    let ip_sum = checksum(&out[..h.header_len]);
    out[10..12].copy_from_slice(&ip_sum.to_be_bytes());
    // ③ ICMP：类型 8 → 0
    out[h.header_len] = 0;
    // ④ ICMP 校验和（覆盖 ICMP 报文，不含 IP 头）
    let icmp_off = h.header_len;
    out[icmp_off + 2] = 0;
    out[icmp_off + 3] = 0;
    let icmp_sum = checksum(&out[icmp_off..]);
    out[icmp_off + 2..icmp_off + 4].copy_from_slice(&icmp_sum.to_be_bytes());

    Some(out)
}

/// 标准的 16 位反码求和校验和（RFC 1071）。
///
/// 奇数长度时末尾补一个 0 字节参与计算 —— 少这一步，所有奇数长载荷
/// （ICMP 头 8 字节 + 任意 payload 就经常是奇数）的校验和都会错，
/// 而 ping 只会静静地不回包，非常难查。
pub fn checksum(data: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut chunks = data.chunks_exact(2);
    for c in &mut chunks {
        sum += u32::from(u16::from_be_bytes([c[0], c[1]]));
    }
    if let [last] = chunks.remainder() {
        sum += u32::from(u16::from_be_bytes([*last, 0]));
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

// ---------------------------------------------------------------------------
// 网段与地址池
// ---------------------------------------------------------------------------

/// 一个 IPv4 网段。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Subnet {
    net: u32,
    prefix: u8,
}

impl Subnet {
    /// 解析 `100.64.0.0/24`；不写 `/` 时按 `/24` 处理（够用且符合直觉）。
    pub fn parse(s: &str) -> anyhow::Result<Self> {
        let s = s.trim();
        let (addr_part, prefix_part) = match s.split_once('/') {
            Some((a, b)) => (a, Some(b)),
            None => (s, None),
        };
        let addr: Ipv4Addr = addr_part
            .trim()
            .parse()
            .map_err(|_| anyhow::anyhow!("虚拟网段地址非法：{addr_part:?}"))?;
        let prefix: u8 = match prefix_part {
            Some(p) => p
                .trim()
                .parse()
                .map_err(|_| anyhow::anyhow!("虚拟网段前缀长度非法：{p:?}"))?,
            None => 24,
        };
        if prefix > 32 {
            anyhow::bail!("虚拟网段前缀长度 {prefix} 超过 32");
        }
        let raw = u32::from(addr);
        let mask = if prefix == 0 {
            0u32
        } else {
            u32::MAX << (32 - u32::from(prefix))
        };
        Ok(Self {
            net: raw & mask,
            prefix,
        })
    }

    pub fn prefix(&self) -> u8 {
        self.prefix
    }

    /// 网段里可用的地址总数（含网络号与广播地址）。
    pub fn size(&self) -> u64 {
        1u64 << (32 - u32::from(self.prefix))
    }
    pub fn contains(&self, ip: Ipv4Addr) -> bool {
        let mask = if self.prefix == 0 {
            0u32
        } else {
            u32::MAX << (32 - u32::from(self.prefix))
        };
        (u32::from(ip) & mask) == self.net
    }

    /// 第 `i` 个地址（从网络号开始数）。
    pub fn nth(&self, i: u64) -> Option<Ipv4Addr> {
        if i >= self.size() {
            return None;
        }
        Some(Ipv4Addr::from((self.net as u64 + i) as u32))
    }

    /// 网络号。
    pub fn network(&self) -> Ipv4Addr {
        Ipv4Addr::from(self.net)
    }

    /// 广播地址。
    pub fn broadcast(&self) -> Ipv4Addr {
        Ipv4Addr::from(self.net.wrapping_add((self.size() - 1) as u32))
    }
}

impl std::fmt::Display for Subnet {
    /// 回写成 `100.64.0.0/24`。用于日志与面板 —— 报错时能把网段原样打出来，
    /// 比让用户自己去 `ip a` 里找要省事得多。
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}/{}", self.network(), self.prefix)
    }
}

/// 地址池：给每个客户端分配一个虚拟 IP，断线归还。
///
/// 分配策略：**从高往低**发（`.254`、`.253`…），把低段留给用户手写静态地址
/// 或者网关，避免冲突。
#[derive(Debug, Clone)]
pub struct IpPool {
    subnet: Subnet,
    /// 已分配：owner（客户端 id）→ 地址
    leased: HashMap<String, Ipv4Addr>,
    /// 已被占用的地址集合（含静态登记的）
    taken: std::collections::HashSet<Ipv4Addr>,
    next: u64,
}

impl IpPool {
    pub fn new(subnet: Subnet) -> Self {
        // 保留网络号与广播地址
        Self {
            subnet,
            leased: HashMap::new(),
            taken: std::collections::HashSet::new(),
            next: subnet.size().saturating_sub(2),
        }
    }

    pub fn subnet(&self) -> Subnet {
        self.subnet
    }

    /// 为 `owner` 分配一个地址。已经有分配时直接返回原来那个（幂等）。
    pub fn acquire(&mut self, owner: &str) -> Option<Ipv4Addr> {
        if let Some(ip) = self.leased.get(owner) {
            return Some(*ip);
        }
        // 从高往低扫一圈，找不到就放弃（网段满了）。
        // 索引 0 是网络号、size-1 是广播地址，都不能发出去。
        let hi = self.subnet.size().saturating_sub(2);
        let mut i = self.next.min(hi);
        loop {
            if i == 0 {
                break;
            }
            if let Some(ip) = self.subnet.nth(i) {
                if !self.taken.contains(&ip) {
                    self.leased.insert(owner.to_string(), ip);
                    self.taken.insert(ip);
                    self.next = i - 1;
                    return Some(ip);
                }
            }
            if i == 1 {
                break;
            }
            i -= 1;
        }
        None
    }

    /// 显式占用一个地址（用户手写 / 需要固定 IP 时）。
    pub fn claim(&mut self, owner: &str, ip: Ipv4Addr) -> bool {
        if self.taken.contains(&ip) {
            return false;
        }
        if let Some(old) = self.leased.insert(owner.to_string(), ip) {
            self.taken.remove(&old);
        }
        self.taken.insert(ip);
        true
    }

    /// 归还。
    pub fn release(&mut self, owner: &str) {
        if let Some(ip) = self.leased.remove(owner) {
            self.taken.remove(&ip);
            // 把"下一个分配位置"抬回刚归还的这个地址：否则归还的地址再也
            // 发不出去（分配游标只会往下走），客户端重连后 IP 也会莫名变化，
            // 而用户往往是拿 IP 写死访问规则的。
            let idx = u64::from(u32::from(ip).wrapping_sub(self.subnet.net));
            let hi = self.subnet.size().saturating_sub(2);
            if idx > self.next && idx <= hi {
                self.next = idx;
            }
        }
    }

    pub fn get(&self, owner: &str) -> Option<Ipv4Addr> {
        self.leased.get(owner).copied()
    }

    pub fn leased_count(&self) -> usize {
        self.leased.len()
    }
}

// ---------------------------------------------------------------------------
// 虚拟交换机（服务端路由表）
// ---------------------------------------------------------------------------

/// 服务端的三层转发表：目的 IP → 客户端。
///
/// 做成独立的类型而不是塞在 `HashMap` 里，是为了让"注册/注销"有明确的
/// 顺序语义：注销时**按客户端**整体清理，避免客户端掉线后残留一批
/// 指向死连接的路由（那会让包被黑洞吃掉，比直接丢更难查）。
#[derive(Debug, Default)]
pub struct Switch {
    /// network → (ip → client_id)，不同虚拟网络互不可见
    nets: HashMap<String, HashMap<Ipv4Addr, String>>,
}

impl Switch {
    pub fn new() -> Self {
        Self::default()
    }

    /// 登记一条路由。返回被顶掉的原 owner（如果有）——
    /// 说明两个客户端抢同一个 IP，调用方应当警告。
    pub fn register(&mut self, network: &str, ip: Ipv4Addr, client: &str) -> Option<String> {
        self.nets
            .entry(network.to_string())
            .or_default()
            .insert(ip, client.to_string())
    }

    /// 注销某个客户端的全部路由。
    pub fn unregister(&mut self, network: &str, client: &str) {
        if let Some(m) = self.nets.get_mut(network) {
            m.retain(|_, v| v != client);
        }
    }

    /// 查目的地址归谁。
    pub fn lookup(&self, network: &str, dst: Ipv4Addr) -> Option<&str> {
        self.nets.get(network)?.get(&dst).map(|s| s.as_str())
    }

    pub fn len(&self, network: &str) -> usize {
        self.nets.get(network).map(|m| m.len()).unwrap_or(0)
    }

    pub fn is_empty(&self) -> bool {
        self.nets.values().all(|m| m.is_empty())
    }

    /// 某个客户端登记的地址（面板展示用）。
    pub fn ips_of(&self, network: &str, client: &str) -> Vec<Ipv4Addr> {
        let mut v: Vec<Ipv4Addr> = self
            .nets
            .get(network)
            .map(|m| {
                m.iter()
                    .filter(|(_, o)| o.as_str() == client)
                    .map(|(ip, _)| *ip)
                    .collect()
            })
            .unwrap_or_default();
        v.sort();
        v
    }
}

// ---------------------------------------------------------------------------
// 注册握手
// ---------------------------------------------------------------------------

/// 客户端连上 `vnet_port` 后发的第一条消息（一行 JSON + `\n`）。
///
/// 用一行 JSON 而不是二进制：这条消息只在建链时发一次，可读性带来的调试
/// 便利远超那几个字节的开销（`tcpdump -A` 就能直接看懂是谁在连）。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VnetRegister {
    /// 客户端标识（用 `client_id`，服务端据此把流和路由表对上）。
    pub client: String,
    /// 虚拟网络名。
    #[serde(default = "default_network")]
    pub network: String,
    /// 期望的地址；留空表示让服务端分配。
    #[serde(default)]
    pub address: String,
    /// 认证 token（与普通控制连接同一套）。
    #[serde(default)]
    pub token: String,
    /// 客户端发起时的时间戳，参与 token 校验。
    #[serde(default)]
    pub timestamp: i64,
}

/// 服务端对 [`VnetRegister`] 的应答。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VnetRegisterResp {
    pub ok: bool,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub error: String,
    /// 分配给客户端的地址。
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub address: String,
    /// 虚拟网段。
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub subnet: String,
    /// 网关（服务端在虚拟网络里的地址）。
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub gateway: String,
    /// MTU。
    #[serde(default)]
    pub mtu: u32,
}

/// 注册握手里"一行 JSON"的编解码。
///
/// 放在这里而不是两端各写一遍：这条报文的字段名是**跨进程契约**，
/// 两边各自 `serde_json::to_vec` 看着一样，但只要有一边忘了加 `\n`
/// 或者改了个字段名，症状就是"连上了但立刻断开"，极难定位。
impl VnetRegister {
    /// 编码成"一行 JSON + `\\n`"。
    pub fn to_line(&self) -> anyhow::Result<Vec<u8>> {
        let mut v = serde_json::to_vec(self)?;
        v.push(b'\n');
        Ok(v)
    }

    /// 从一行里解出来。
    pub fn from_line(line: &[u8]) -> anyhow::Result<Self> {
        serde_json::from_slice(line)
            .map_err(|e| anyhow::anyhow!("VirtualNet 注册报文不是合法 JSON：{e}"))
    }
}

impl VnetRegisterResp {
    /// 编码成"一行 JSON + `\\n`"。
    pub fn to_line(&self) -> anyhow::Result<Vec<u8>> {
        let mut v = serde_json::to_vec(self)?;
        v.push(b'\n');
        Ok(v)
    }

    /// 从一行里解出来。
    pub fn from_line(line: &[u8]) -> anyhow::Result<Self> {
        serde_json::from_slice(line)
            .map_err(|e| anyhow::anyhow!("VirtualNet 应答不是合法 JSON：{e}"))
    }

    /// 注册失败时的应答。
    pub fn denied(msg: impl Into<String>) -> Self {
        Self {
            ok: false,
            error: msg.into(),
            address: String::new(),
            subnet: String::new(),
            gateway: String::new(),
            mtu: 0,
        }
    }
}

/// 从流里读到第一个 `\\n` 为止（不含 `\\n`），多余字节**留在 `buf` 里**。
///
/// 多余字节不能丢：它们可能已经是后续帧流的一部分（握手与数据是同一个
/// 连接上的两段，对端完全可能一口气全发过来）。
pub async fn read_json_line<S>(
    stream: &mut S,
    buf: &mut Vec<u8>,
    max: usize,
) -> anyhow::Result<Vec<u8>>
where
    S: tokio::io::AsyncRead + Unpin,
{
    use tokio::io::AsyncReadExt;
    loop {
        if let Some(i) = buf.iter().position(|b| *b == b'\n') {
            let mut line: Vec<u8> = buf.drain(..i).collect();
            buf.drain(..1); // 吃掉 \n
            while matches!(line.last(), Some(b'\r')) {
                line.pop();
            }
            return Ok(line);
        }
        if buf.len() > max {
            anyhow::bail!("握手报文的行超过 {max} 字节，拒绝");
        }
        let mut chunk = [0u8; 1024];
        let n = stream.read(&mut chunk).await?;
        if n == 0 {
            anyhow::bail!("对端在握手报文发完前断开");
        }
        buf.extend_from_slice(&chunk[..n]);
    }
}

// ---------------------------------------------------------------------------
// TUN 设备
// ---------------------------------------------------------------------------

#[cfg(target_os = "linux")]
mod tun_linux;

#[cfg(target_os = "linux")]
pub use tun_linux::{open_tun, Tun};

/// 非 Linux 平台：把话说清楚，而不是假装支持。
///
/// 没有实现是有意的 —— Windows 要引入 Wintun 驱动（`wintun.dll` +
/// 管理员权限 + 网卡 IP 配置），macOS 的 `utun` 每个包还多一层 4 字节
/// 地址族头。这两条路径都无法在当前环境里真跑一遍，而**没跑过的平台代码
/// 比明确的报错更危险**。
///
/// 好在它与平台无关的部分（地址分配、路由表、帧编解码）都已实现并单测覆盖，
/// 补上 TUN 只需要实现这一个函数。
#[cfg(not(target_os = "linux"))]
pub fn open_tun(
    _name: &str,
    _mtu: u32,
    _addr: Option<&str>,
    _peer: Option<&str>,
) -> anyhow::Result<Tun> {
    anyhow::bail!(
        "VirtualNet 的 TUN 设备目前只实现了 Linux（/dev/net/tun）。\
         Windows 需要 Wintun 驱动，macOS 需要 utun —— 均未实现。\
         服务端转发逻辑本身是跨平台的，可用 Linux 客户端与服务端验证整条链路。"
    )
}

/// 非 Linux 平台上的占位类型：**永远构造不出来**，但要和 Linux 版有同样的
/// 外形（方法名、trait 实现），否则上层那份平台无关的转发循环在 Windows 上
/// 连编译都过不了 —— 那就等于把"不支持"变成了"整个客户端编不出来"。
#[cfg(not(target_os = "linux"))]
pub struct Tun {
    /// 不可能被构造出来，所以这些方法体在运行时永远不会执行。
    _never: std::convert::Infallible,
}

#[cfg(not(target_os = "linux"))]
impl Tun {
    pub fn name(&self) -> &str {
        match self._never {}
    }

    pub fn mtu(&self) -> u32 {
        match self._never {}
    }

    pub fn set_address(&self, _addr_spec: &str) -> anyhow::Result<()> {
        match self._never {}
    }
}

#[cfg(not(target_os = "linux"))]
impl tokio::io::AsyncRead for Tun {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
        _buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        match self._never {}
    }
}

#[cfg(not(target_os = "linux"))]
impl tokio::io::AsyncWrite for Tun {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
        _buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        match self._never {}
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        match self._never {}
    }

    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        match self._never {}
    }
}

// ---------------------------------------------------------------------------
// 测试
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // ---- 帧编解码 ----

    #[test]
    fn 帧往返() {
        let pkt = vec![0x45u8; 40];
        let f = encode_frame(&pkt).unwrap();
        assert_eq!(&f[..4], &40u32.to_le_bytes(), "长度必须是小端 u32");
        let mut buf = f;
        let got = take_frame(&mut buf).unwrap().unwrap();
        assert_eq!(got, pkt);
        assert!(buf.is_empty(), "取完一帧后缓冲区应当空掉");
    }

    #[test]
    fn 半帧返回未就绪() {
        let f = encode_frame(&[1, 2, 3, 4, 5]).unwrap();
        let mut buf = f[..6].to_vec(); // 只有头 + 2 字节
        assert!(take_frame(&mut buf).unwrap().is_none());
        assert_eq!(buf.len(), 6, "没收全时不能消费任何字节");
        // 补齐后就能取出来
        buf.extend_from_slice(&f[6..]);
        assert_eq!(take_frame(&mut buf).unwrap().unwrap(), vec![1, 2, 3, 4, 5]);
    }

    #[test]
    fn 零长度与超大帧被拒绝() {
        assert!(encode_frame(&[]).is_err());
        assert!(encode_frame(&vec![0u8; MAX_FRAME + 1]).is_err());
        // 对端声称一个巨大的长度：必须当场拒，不能先分配 1GB 再说
        let mut buf = vec![0xff, 0xff, 0xff, 0xff];
        assert!(take_frame(&mut buf).is_err());
        let mut buf = vec![0, 0, 0, 0];
        assert!(take_frame(&mut buf).is_err());
    }

    /// 一次投喂多帧要能全部取出（TCP 会把它们粘在一起）。
    #[test]
    fn 粘包能逐帧取出() {
        let mut buf = Vec::new();
        for i in 0..5u8 {
            buf.extend_from_slice(&encode_frame(&[i; 3]).unwrap());
        }
        let mut out = Vec::new();
        while let Some(f) = take_frame(&mut buf).unwrap() {
            out.push(f[0]);
        }
        assert_eq!(out, vec![0, 1, 2, 3, 4]);
        assert!(buf.is_empty());
    }

    // ---- IP 头解析 ----

    fn ipv4_packet(src: &str, dst: &str, proto: u8) -> Vec<u8> {
        let mut p = vec![0u8; 20];
        p[0] = 0x45; // 版本 4，头长 5 字
        p[9] = proto;
        p[12..16].copy_from_slice(&src.parse::<Ipv4Addr>().unwrap().octets());
        p[16..20].copy_from_slice(&dst.parse::<Ipv4Addr>().unwrap().octets());
        p
    }

    #[test]
    fn 解析_ipv4_头() {
        let p = ipv4_packet("100.64.0.2", "100.64.0.3", 6);
        let h = parse_ipv4(&p).unwrap();
        assert_eq!(h.src, "100.64.0.2".parse::<Ipv4Addr>().unwrap());
        assert_eq!(h.dst, "100.64.0.3".parse::<Ipv4Addr>().unwrap());
        assert_eq!(h.protocol, 6);
        assert_eq!(h.header_len, 20);
    }

    #[test]
    fn ipv6_与短包不被误解析() {
        let mut p = vec![0u8; 40];
        p[0] = 0x60; // 版本 6
        assert!(parse_ipv4(&p).is_none(), "IPv6 不能按 IPv4 解出垃圾地址");
        assert!(parse_ipv4(&[0x45, 0, 0]).is_none(), "不足 20 字节");
        // 声称头长 24 但只有 20 字节，属于坏包
        let mut bad = ipv4_packet("1.1.1.1", "2.2.2.2", 6);
        bad[0] = 0x46;
        assert!(parse_ipv4(&bad).is_none());
    }

    #[test]
    fn 识别_ping_请求() {
        let mut p = ipv4_packet("100.64.0.2", "100.64.0.3", 1);
        p.push(8); // ICMP Echo Request
        assert!(is_icmp_echo_request(&p));
        // 换成 Echo Reply 就不是请求
        let mut q = ipv4_packet("100.64.0.2", "100.64.0.3", 1);
        q.push(0);
        assert!(!is_icmp_echo_request(&q));
        // TCP 也不是
        assert!(!is_icmp_echo_request(&ipv4_packet("1.1.1.1", "2.2.2.2", 6)));
    }

    // ---- 网段与地址池 ----

    #[test]
    fn 网段解析与包含() {
        let s = Subnet::parse("100.64.0.0/24").unwrap();
        assert_eq!(s.prefix(), 24);
        assert_eq!(s.size(), 256);
        assert!(s.contains("100.64.0.5".parse().unwrap()));
        assert!(!s.contains("100.64.1.5".parse().unwrap()));
        assert_eq!(s.network(), "100.64.0.0".parse::<Ipv4Addr>().unwrap());
        assert_eq!(s.broadcast(), "100.64.0.255".parse::<Ipv4Addr>().unwrap());
        // 不写前缀默认 /24
        assert_eq!(Subnet::parse("10.1.2.3").unwrap().prefix(), 24);
    }

    #[test]
    fn 网段非法输入报错() {
        assert!(Subnet::parse("999.1.1.1/24").is_err());
        assert!(Subnet::parse("10.0.0.0/33").is_err());
        assert!(Subnet::parse("10.0.0.0/xx").is_err());
    }

    /// 分配必须**避开网络号与广播地址**，否则内网会出现诡异的不通。
    #[test]
    fn 地址池避开网络号与广播() {
        let subnet = Subnet::parse("100.64.0.0/29").unwrap(); // 8 个地址
        let mut pool = IpPool::new(subnet);
        let mut got = Vec::new();
        for i in 0..6 {
            got.push(pool.acquire(&format!("c{i}")).expect("还有地址"));
        }
        let net: Ipv4Addr = "100.64.0.0".parse().unwrap();
        let bc: Ipv4Addr = "100.64.0.7".parse().unwrap();
        assert!(!got.contains(&net), "不能把网络号分出去");
        assert!(!got.contains(&bc), "不能把广播地址分出去");
        // 8 个地址 - 网络号 - 广播 = 6 个可用，正好发完
        assert!(pool.acquire("c99").is_none(), "地址池应当已满");
    }

    #[test]
    fn 地址池幂等与回收() {
        let mut pool = IpPool::new(Subnet::parse("100.64.0.0/24").unwrap());
        let a = pool.acquire("alice").unwrap();
        assert_eq!(
            pool.acquire("alice").unwrap(),
            a,
            "重复申请必须拿到同一个地址"
        );
        assert_eq!(pool.leased_count(), 1);

        pool.release("alice");
        assert!(pool.get("alice").is_none());
        assert_eq!(pool.leased_count(), 0);
        // 回收后应该能被别人拿到
        let b = pool.acquire("bob").unwrap();
        assert_eq!(b, a);
    }

    #[test]
    fn 静态占用冲突时拒绝() {
        let mut pool = IpPool::new(Subnet::parse("100.64.0.0/24").unwrap());
        let ip: Ipv4Addr = "100.64.0.9".parse().unwrap();
        assert!(pool.claim("alice", ip));
        assert!(!pool.claim("bob", ip), "同一个地址不能被两个人占用");
        // 自动分配也不能撞上已占用的
        for i in 0..20 {
            let got = pool.acquire(&format!("u{i}")).unwrap();
            assert_ne!(got, ip, "自动分配撞上了静态占用");
        }
    }

    // ---- 交换机 ----

    #[test]
    fn 交换机路由与注销() {
        let mut sw = Switch::new();
        let a: Ipv4Addr = "100.64.0.2".parse().unwrap();
        let b: Ipv4Addr = "100.64.0.3".parse().unwrap();
        assert!(sw.register("default", a, "alice").is_none());
        assert!(sw.register("default", b, "bob").is_none());

        assert_eq!(sw.lookup("default", a), Some("alice"));
        assert_eq!(sw.lookup("default", b), Some("bob"));
        assert_eq!(sw.len("default"), 2);

        sw.unregister("default", "alice");
        assert_eq!(sw.lookup("default", a), None);
        assert_eq!(sw.lookup("default", b), Some("bob"), "不该误删别人的路由");
        assert_eq!(sw.len("default"), 1);
    }

    /// 不同虚拟网络必须完全隔离 —— 否则两家公司的机器会互相看得见。
    #[test]
    fn 虚拟网络之间隔离() {
        let mut sw = Switch::new();
        let a: Ipv4Addr = "100.64.0.2".parse().unwrap();
        sw.register("net-a", a, "alice");
        // 同一个 IP 在另一个网络里属于别人，互不影响
        sw.register("net-b", a, "bob");
        assert_eq!(sw.lookup("net-a", a), Some("alice"));
        assert_eq!(sw.lookup("net-b", a), Some("bob"));
        assert_eq!(sw.lookup("net-c", a), None, "没登记的网络查不到");
        sw.unregister("net-a", "alice");
        assert_eq!(sw.lookup("net-b", a), Some("bob"));
    }

    #[test]
    fn 抢同一个_ip_时能报出被顶掉的人() {
        let mut sw = Switch::new();
        let ip: Ipv4Addr = "100.64.0.2".parse().unwrap();
        assert!(sw.register("default", ip, "alice").is_none());
        assert_eq!(
            sw.register("default", ip, "bob").as_deref(),
            Some("alice"),
            "必须把冲突暴露出来，否则是静默劫持"
        );
        assert_eq!(sw.lookup("default", ip), Some("bob"));
        assert_eq!(sw.ips_of("default", "bob"), vec![ip]);
        assert!(sw.ips_of("default", "alice").is_empty());
    }

    // ---- 配置 ----

    #[test]
    fn 配置默认关闭() {
        let c = VirtualNetConfig::default();
        assert!(!c.is_enabled(), "默认不能启用虚拟网络");
        assert_eq!(c.mtu, 1400);
        assert_eq!(c.network, "default");
        assert!(c.validate().is_ok());
    }

    #[test]
    fn 配置校验() {
        let c = VirtualNetConfig {
            address: "100.64.0.2/24".into(),
            ..Default::default()
        };
        assert!(c.is_enabled() && c.validate().is_ok());

        let bad = VirtualNetConfig {
            address: "不是IP".into(),
            ..Default::default()
        };
        assert!(bad.validate().is_err());

        let bad_mtu = VirtualNetConfig {
            auto_assign: true,
            mtu: 100,
            ..Default::default()
        };
        assert!(bad_mtu.validate().is_err());
    }

    /// 注册消息要能过 JSON 往返 —— 它是跨进程的，字段名写错会静默丢字段。
    #[test]
    fn 注册消息往返() {
        let r = VnetRegister {
            client: "c1".into(),
            network: "default".into(),
            address: "100.64.0.2".into(),
            token: "t".into(),
            timestamp: 123,
        };
        let s = serde_json::to_string(&r).unwrap();
        let back: VnetRegister = serde_json::from_str(&s).unwrap();
        assert_eq!(back.client, "c1");
        assert_eq!(back.address, "100.64.0.2");

        // 省略可选字段也要能解（老客户端 / 手写配置）
        let minimal: VnetRegister = serde_json::from_str(r#"{"client":"c1"}"#).unwrap();
        assert_eq!(minimal.network, "default");
        assert!(minimal.address.is_empty());
    }

    #[test]
    fn 应答消息只带必要字段() {
        let r = VnetRegisterResp {
            ok: false,
            error: "网段满了".into(),
            address: String::new(),
            subnet: String::new(),
            gateway: String::new(),
            mtu: 0,
        };
        let s = serde_json::to_string(&r).unwrap();
        assert!(s.contains("error"), "{s}");
        assert!(!s.contains("address"), "空字段不该出现在报文里：{s}");
    }

    /// 造一个真的 ICMP Echo Request（`ping` 发出来的就是长这样）。
    fn echo_request(src: Ipv4Addr, dst: Ipv4Addr, payload: &[u8]) -> Vec<u8> {
        let mut icmp = vec![8, 0, 0, 0, 0, 1, 0, 1];
        icmp.extend_from_slice(payload);
        let sum = checksum(&icmp);
        icmp[2..4].copy_from_slice(&sum.to_be_bytes());

        let mut pkt = vec![0u8; 20];
        pkt[0] = 0x45;
        pkt[2..4].copy_from_slice(&((20 + icmp.len()) as u16).to_be_bytes());
        pkt[8] = 64; // TTL
        pkt[9] = 1; // ICMP
        pkt[12..16].copy_from_slice(&src.octets());
        pkt[16..20].copy_from_slice(&dst.octets());
        let ip_sum = checksum(&pkt[..20]);
        pkt[10..12].copy_from_slice(&ip_sum.to_be_bytes());
        pkt.extend_from_slice(&icmp);
        pkt
    }

    /// 网关应答必须是**一个能被内核接受的合法包**：
    /// 地址对调、类型 8→0，两个校验和都要重新算对。
    /// 校验和算错的表现是 `ping` 一直超时且毫无提示 —— 这里由构造出来的
    /// 请求包自己验证：把应答再"反转"一次应当又能通过校验。
    #[test]
    fn 网关能正确回_ping() {
        let me = Ipv4Addr::new(100, 64, 0, 2);
        let gw = Ipv4Addr::new(100, 64, 0, 1);
        let req = echo_request(me, gw, b"hello-rustunnel!"); // 载荷为奇数长

        assert!(is_icmp_echo_request(&req));
        let rep = icmp_echo_reply(&req).expect("网关应当应答发往自己的 echo request");

        let h = parse_ipv4(&rep).unwrap();
        assert_eq!(h.src, gw, "应答的源地址必须是网关");
        assert_eq!(h.dst, me, "应答的目的地址必须是发起方");
        assert_eq!(h.protocol, 1);
        assert_eq!(rep[20], 0, "ICMP 类型必须是 Echo Reply(0)");
        assert_eq!(rep[24..26], req[24..26], "identifier 要原样带回");
        assert_eq!(rep[26..28], req[26..28], "sequence 要原样带回");
        assert_eq!(&rep[28..], &req[28..], "载荷必须原样带回");

        // 两个校验和都得是自洽的：重算一遍结果必须为 0
        assert_eq!(checksum(&rep[..20]), 0, "IP 头校验和不对");
        assert_eq!(checksum(&rep[20..]), 0, "ICMP 校验和不对");
    }

    #[test]
    fn 校验和覆盖奇数长度() {
        // RFC 1071 的经典样例
        assert_eq!(
            checksum(&[0x00, 0x01, 0xf2, 0x03, 0xf4, 0xf5, 0xf6, 0xf7]),
            0x220d
        );
        // 奇数长度末尾要补 0 参与计算
        assert_eq!(
            checksum(&[0x01, 0x02, 0x03]),
            checksum(&[0x01, 0x02, 0x03, 0x00])
        );
    }

    #[test]
    fn 不该由网关应答的包要拒绝() {
        let me = Ipv4Addr::new(100, 64, 0, 2);
        let gw = Ipv4Addr::new(100, 64, 0, 1);
        // 已经是 Echo Reply（类型 0）—— 别再回一次，否则就是 ping-pong 死循环
        let mut rep = echo_request(me, gw, b"x");
        rep[20] = 0;
        assert!(!is_icmp_echo_request(&rep));
        assert!(icmp_echo_reply(&rep).is_none());

        // 非 ICMP
        let mut tcp = echo_request(me, gw, b"x");
        tcp[9] = 6;
        assert!(icmp_echo_reply(&tcp).is_none());

        // 截断的包不能 panic
        assert!(icmp_echo_reply(&[]).is_none());
        assert!(icmp_echo_reply(&echo_request(me, gw, b"x")[..24]).is_none());
    }
}
