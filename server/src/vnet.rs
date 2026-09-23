//! VirtualNet 服务端：一台"虚拟交换机 + 网关"。
//!
//! # 它在哪一层
//!
//! 客户端侧是一个 TUN 网卡（三层，只有 IP 报文，没有以太头），所以这里做的
//! 是**三层转发**：谁的 IP 是目的地址，就把这包投给谁。没有 ARP、没有 MAC、
//! 没有广播域 —— 那些是二层的事，TUN 上根本不存在。
//!
//! ```text
//!   客户端 A                服务端（本模块）                客户端 B
//!   tun0 ──[u32 len|IP 包]──▶ 解析目的 IP ──┬─ 网关自己？ → 回 ICMP echo reply
//!                                          ├─ 广播地址？ → 泛洪给同网段其他人
//!                                          └─ 查路由表 ──[u32 len|IP 包]──▶ tun0
//! ```
//!
//! # 为什么单独一个端口
//!
//! 见 `common/src/vnet.rs` 的说明：虚拟网络是长时间高速的纯数据流，混在控制
//! 通道里会拖慢心跳与面板命令，出故障时也不好隔离。
//!
//! # 关闭时零开销
//!
//! 没配 `vnet_port` 就压根不会调用 [`run`]，一行业务代码都不多执行。
//! 老配置文件一个字节都不用改。

use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::{Arc, Mutex};

use anyhow::{Context, Result};
use rustunnel_common::config::ServerConfig;
use rustunnel_common::vnet::{
    self, encode_frame, take_frame, IpPool, Subnet, Switch, VnetRegister, VnetRegisterResp,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;
use tracing::{debug, info, warn};

use crate::guard::SecurityContext;
use crate::registry::Registry;

/// 每个客户端的待发队列长度。
///
/// 满了就**丢包**而不是阻塞发送方：一个卡住的下游客户端不能拖垮整台交换机
/// （其余客户端仍然要能互通）。IP 网络本来就是"尽力而为"，丢包由上层重传。
const PEER_QUEUE: usize = 1024;

/// 注册行上限（一行 JSON）。防止对端发一根无限长的"行"把内存吃光。
const MAX_REGISTER_LINE: usize = 8 * 1024;

/// 注册握手的整体超时。
const REGISTER_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

// ---------------------------------------------------------------------------
// 转发中枢
// ---------------------------------------------------------------------------

/// 一台虚拟交换机 + 地址池 + 网关。
pub struct VnetHub {
    inner: Mutex<HubInner>,
}

struct HubInner {
    /// 虚拟网络名（同名互通，异名隔离）。
    network: String,
    subnet: Subnet,
    gateway: Ipv4Addr,
    mtu: u32,
    /// 地址池：客户端登录时申请、断线时归还。
    pool: IpPool,
    /// 路由表：目的 IP → 客户端 id。
    routes: Switch,
    /// 客户端 id → 该连接的发送端。
    ///
    /// 与 `routes` 分开存：`routes` 面向"目的 IP 是什么"，这里面向"id 是谁"。
    /// 注销时要**两边一起清**，只清一边会出现"路由指向一个没人收的信箱"，
    /// 包被悄悄丢掉，比直接报错更难查。
    sinks: HashMap<String, mpsc::Sender<Vec<u8>>>,
    /// 统计：目的地址查不到人的包。
    dropped_unroutable: u64,
    /// 统计：下游队列满了被丢掉的包。
    dropped_full: u64,
}

/// 面板展示用的快照。
#[derive(Debug, Clone, serde::Serialize)]
pub struct VnetStats {
    pub network: String,
    pub subnet: String,
    pub gateway: String,
    pub mtu: u32,
    /// 已加入的客户端数。
    pub peers: usize,
    /// 地址池里已分配的地址数。
    pub leased: usize,
    pub dropped_unroutable: u64,
    pub dropped_full: u64,
}

/// 加入成功后返回给客户端的参数。
#[derive(Debug, Clone)]
pub struct Joined {
    pub ip: Ipv4Addr,
    pub subnet: Subnet,
    pub gateway: Ipv4Addr,
    pub mtu: u32,
}

impl VnetHub {
    /// 从服务端配置构造。**配置写错就在启动时报错**，而不是等第一个客户端连上来。
    pub fn from_config(cfg: &ServerConfig) -> Result<Self> {
        let subnet_s = cfg.vnet.subnet.trim();
        if subnet_s.is_empty() {
            anyhow::bail!(
                "启用了 vnet_port 就必须配 [vnet] subnet（形如 subnet = \"100.64.0.0/24\"）——\
                 地址池没法凭空猜"
            );
        }
        let subnet = Subnet::parse(subnet_s)?;
        if subnet.size() < 4 {
            anyhow::bail!("[vnet] subnet 太小（{subnet_s}），至少要能放下网关和几个客户端");
        }
        let gateway = if cfg.vnet.gateway.trim().is_empty() {
            // 网关默认取网段里第一个可用地址
            subnet
                .nth(1)
                .ok_or_else(|| anyhow::anyhow!("网段 {subnet_s} 里取不出网关地址"))?
        } else {
            let bare = cfg.vnet.gateway.split('/').next().unwrap_or("").trim();
            let gw: Ipv4Addr = bare
                .parse()
                .with_context(|| format!("[vnet] gateway 非法：{}", cfg.vnet.gateway))?;
            if !subnet.contains(gw) {
                anyhow::bail!("[vnet] gateway {gw} 不在网段 {subnet_s} 里");
            }
            gw
        };

        info!(
            network = %cfg.vnet.network,
            subnet = %subnet_s,
            %gateway,
            mtu = cfg.vnet.mtu,
            "VirtualNet 已启用"
        );

        Ok(Self {
            inner: Mutex::new(HubInner {
                network: cfg.vnet.network.clone(),
                subnet,
                gateway,
                mtu: cfg.vnet.mtu,
                pool: IpPool::new(subnet),
                routes: Switch::new(),
                sinks: HashMap::new(),
                dropped_unroutable: 0,
                dropped_full: 0,
            }),
        })
    }

    /// 客户端加入。`want` 为 `None` 表示由服务端分配。
    pub fn join(
        &self,
        client: &str,
        want: Option<Ipv4Addr>,
        sink: mpsc::Sender<Vec<u8>>,
    ) -> Result<Joined> {
        let mut g = self.inner.lock().unwrap();

        // 同一个 client_id 重连（上一次的连接可能还没死透）：先把旧的清掉。
        // 不清的话 `routes` 里会留着指向旧连接的条目，包全打进黑洞。
        if g.sinks.contains_key(client) {
            debug!(%client, "同一个客户端重复加入，先清掉旧登记");
            Self::leave_locked(&mut g, client);
        }

        let ip = match want {
            Some(w) => {
                if !g.subnet.contains(w) {
                    anyhow::bail!("请求的地址 {w} 不在虚拟网段 {} 内", g.subnet);
                }
                if w == g.gateway {
                    anyhow::bail!("{w} 是网关地址，不能分配给客户端");
                }
                if !g.pool.claim(client, w) {
                    anyhow::bail!("地址 {w} 已被占用");
                }
                w
            }
            None => g
                .pool
                .acquire(client)
                .ok_or_else(|| anyhow::anyhow!("虚拟网段 {} 的地址已用完", g.subnet))?,
        };

        let net = g.network.clone();
        if let Some(old) = g.routes.register(&net, ip, client) {
            if old != client {
                warn!(%ip, old = %old, new = %client, "两个客户端抢同一个虚拟 IP，旧路由被顶掉");
            }
        }
        g.sinks.insert(client.to_string(), sink);

        Ok(Joined {
            ip,
            subnet: g.subnet,
            gateway: g.gateway,
            mtu: g.mtu,
        })
    }

    /// 客户端离开：路由与地址**一起**回收。
    pub fn leave(&self, client: &str) {
        let mut g = self.inner.lock().unwrap();
        Self::leave_locked(&mut g, client);
    }

    fn leave_locked(g: &mut HubInner, client: &str) {
        g.routes.unregister(&g.network, client);
        g.pool.release(client);
        g.sinks.remove(client);
    }

    /// 处理一个从 `from` 客户端收到的 IP 报文：按目的地址转发。
    ///
    /// 返回 `true` 表示包被投出去了（发给了别人或由网关应答），
    /// `false` 表示丢弃（查不到人 / 解析失败）。
    fn route(&self, from: &str, pkt: &[u8]) -> bool {
        let Some(h) = vnet::parse_ipv4(pkt) else {
            // IPv6 或畸形包。**静默丢弃**而不是回 ICMP unreachable：
            // 我们不是路由器，装作会发 ICMP 只会让人以为链路有问题。
            return false;
        };
        let mut g = self.inner.lock().unwrap();

        // ① 网关自己（服务端）：只应答 ICMP echo，TCP/UDP 丢弃
        if h.dst == g.gateway {
            match vnet::icmp_echo_reply(pkt) {
                Some(reply) => {
                    drop(g);
                    return self.deliver(from, &reply);
                }
                None => return false,
            }
        }

        // ② 广播（255.255.255.255 或本网段广播地址）→ 泛洪给同网段的其他人
        if h.dst == Ipv4Addr::BROADCAST || h.dst == g.subnet.broadcast() {
            let targets: Vec<String> = g
                .sinks
                .keys()
                .filter(|k| k.as_str() != from)
                .cloned()
                .collect();
            let mut any = false;
            for t in targets {
                if let Some(tx) = g.sinks.get(&t) {
                    match tx.try_send(pkt.to_vec()) {
                        Ok(()) => any = true,
                        Err(_) => g.dropped_full += 1,
                    }
                }
            }
            return any;
        }

        // ③ 单播：查路由表
        let Some(owner) = g.routes.lookup(&g.network, h.dst) else {
            g.dropped_unroutable += 1;
            debug!(dst = %h.dst, "虚拟网络里没有这个地址，丢弃");
            return false;
        };
        let owner = owner.to_string();
        let Some(tx) = g.sinks.get(&owner) else {
            // 路由表有、但信箱没了 —— 说明注销时清漏了一边。这条日志是那种
            // "出现即代表有 bug"的日志，值得留着。
            g.dropped_unroutable += 1;
            warn!(dst = %h.dst, owner = %owner, "路由指向的客户端已不在线");
            return false;
        };
        match tx.try_send(pkt.to_vec()) {
            Ok(()) => true,
            Err(_) => {
                // 队列满：丢最合理（IP 网络本来就是尽力而为），不能阻塞发送方
                g.dropped_full += 1;
                false
            }
        }
    }

    /// 往某个客户端投一个包（网关应答走这条路）。
    fn deliver(&self, to: &str, pkt: &[u8]) -> bool {
        let mut g = self.inner.lock().unwrap();
        match g.sinks.get(to) {
            Some(tx) => match tx.try_send(pkt.to_vec()) {
                Ok(()) => true,
                Err(_) => {
                    g.dropped_full += 1;
                    false
                }
            },
            None => false,
        }
    }

    pub fn stats(&self) -> Option<VnetStats> {
        let g = self.inner.lock().unwrap();
        Some(VnetStats {
            network: g.network.clone(),
            subnet: g.subnet.to_string(),
            gateway: g.gateway.to_string(),
            mtu: g.mtu,
            peers: g.sinks.len(),
            leased: g.pool.leased_count(),
            dropped_unroutable: g.dropped_unroutable,
            dropped_full: g.dropped_full,
        })
    }

    /// 某个客户端分到的地址（测试与面板用）。
    pub fn address_of(&self, client: &str) -> Option<Ipv4Addr> {
        let g = self.inner.lock().unwrap();
        g.routes.ips_of(&g.network, client).into_iter().next()
    }
}

impl std::fmt::Debug for VnetHub {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "VnetHub{:?}", self.stats())
    }
}

// ---------------------------------------------------------------------------
// 监听循环
// ---------------------------------------------------------------------------

/// 在 `vnet_port` 上接受连接，直到进程退出。
///
/// 取 [`SecurityContext`] 走 `registry` 而不是启动时捕获一份：配置热重载会
/// **整体换掉**它（改 ACL / 改 token 不该要求重启），捕获一份就等于把热重载废了。
pub async fn run(listener: TcpListener, hub: Arc<VnetHub>, registry: Arc<Registry>) {
    loop {
        match listener.accept().await {
            Ok((stream, peer)) => {
                let hub = hub.clone();
                let sec = registry.security();
                tokio::spawn(async move {
                    if let Err(e) = serve_conn(stream, peer, hub, sec).await {
                        debug!(%peer, "VirtualNet 连接结束：{e:#}");
                    }
                });
            }
            Err(e) => {
                warn!("VirtualNet accept 失败：{e}");
                // accept 错误（EMFILE 之类）不能转死循环打日志
                tokio::time::sleep(std::time::Duration::from_millis(200)).await;
            }
        }
    }
}

/// 一条 VirtualNet 客户端连接的完整生命周期。
async fn serve_conn(
    mut stream: TcpStream,
    peer: SocketAddr,
    hub: Arc<VnetHub>,
    sec: Arc<SecurityContext>,
) -> Result<()> {
    stream.set_nodelay(true).ok();

    // ① IP 白/黑名单：与普通控制连接同一套，顺序也一样（最便宜的放前面）
    if let Err(reason) = sec.check_ip(peer.ip()) {
        warn!(%peer, "VirtualNet: IP 访问控制拒绝：{reason}");
        return Ok(());
    }

    // ② 读一行 JSON 注册报文
    let mut buf: Vec<u8> = Vec::with_capacity(512);
    let line = tokio::time::timeout(
        REGISTER_TIMEOUT,
        vnet::read_json_line(&mut stream, &mut buf, MAX_REGISTER_LINE),
    )
    .await
    .map_err(|_| anyhow::anyhow!("等待注册报文超时"))?
    .context("读取注册报文失败")?;
    let reg: VnetRegister = match VnetRegister::from_line(&line) {
        Ok(r) => r,
        Err(e) => {
            // 尽量把错误回给对方，否则客户端只能看到"连接被重置"
            let _ = write_resp(&mut stream, &VnetRegisterResp::denied(format!("{e:#}"))).await;
            anyhow::bail!("{e:#}");
        }
    };
    if reg.client.trim().is_empty() {
        let _ = write_resp(&mut stream, &VnetRegisterResp::denied("client 不能为空")).await;
        anyhow::bail!("注册报文缺少 client");
    }

    // ③ 认证：与普通控制连接**同一套凭证**（token / OIDC 都走这里）
    if let Err(e) = sec.verify_login(&reg.token, reg.timestamp) {
        let _ = write_resp(&mut stream, &VnetRegisterResp::denied("认证失败")).await;
        // 审计里只写"失败"，不回显凭证，也不给攻击者更多信息
        sec.audit.record(
            crate::audit::AuditEvent::new(crate::audit::kind::VNET_JOIN, false)
                .client(reg.client.clone())
                .ip(peer.ip().to_string())
                .detail(format!("{e:#}")),
        );
        anyhow::bail!("VirtualNet 认证失败：{e:#}");
    }

    // ④ 分配地址并登记路由
    let want: Option<Ipv4Addr> = if reg.address.trim().is_empty() {
        None
    } else {
        let bare = reg.address.split('/').next().unwrap_or("").trim();
        match bare.parse::<Ipv4Addr>() {
            Ok(ip) => Some(ip),
            Err(_) => {
                let _ = write_resp(
                    &mut stream,
                    &VnetRegisterResp::denied(format!("地址非法：{}", reg.address)),
                )
                .await;
                anyhow::bail!("注册地址非法：{}", reg.address);
            }
        }
    };
    let (tx, mut rx) = mpsc::channel::<Vec<u8>>(PEER_QUEUE);
    let joined = match hub.join(&reg.client, want, tx) {
        Ok(j) => j,
        Err(e) => {
            let _ = write_resp(&mut stream, &VnetRegisterResp::denied(format!("{e:#}"))).await;
            anyhow::bail!("VirtualNet 加入失败：{e:#}");
        }
    };

    // 五元组之外还要记 `_guard`：它 drop 时把路由与地址一起收回，
    // 无论下面是从正常路径返回还是 panic/取消，都不会漏。
    let _guard = JoinGuard {
        hub: hub.clone(),
        client: reg.client.clone(),
    };

    let resp = VnetRegisterResp {
        ok: true,
        error: String::new(),
        address: joined.ip.to_string(),
        subnet: joined.subnet.to_string(),
        gateway: joined.gateway.to_string(),
        mtu: joined.mtu,
    };
    write_resp(&mut stream, &resp).await?;
    info!(
        client = %reg.client,
        %peer,
        ip = %joined.ip,
        network = %reg.network,
        "VirtualNet 客户端已加入"
    );
    sec.audit.record(
        crate::audit::AuditEvent::new(crate::audit::kind::VNET_JOIN, true)
            .client(reg.client.clone())
            .ip(peer.ip().to_string())
            .detail(format!("ip={} network={}", joined.ip, reg.network)),
    );

    // ⑤ 转发主循环：一个任务同时管收发。
    //
    // 收：从 socket 读 → 拆帧 → 按目的地址转发。
    // 发：自己的队列 → 封帧 → 写 socket。
    //
    // 只用一个任务（而不是读/写各一个）是为了让"写"永远是顺序的 ——
    // IP 报文之间没有顺序依赖，但少一个 `Arc<Mutex<TcpStream>>` 就少一处死锁。
    let mut write_buf: Vec<u8> = Vec::new();
    let mut chunk = vec![0u8; 64 * 1024];
    loop {
        // 先把待发队列里已经攒好的包一次性写出去
        while let Ok(pkt) = rx.try_recv() {
            write_buf.extend_from_slice(&encode_frame(&pkt)?);
        }
        if !write_buf.is_empty() {
            stream.write_all(&write_buf).await?;
            stream.flush().await?;
            write_buf.clear();
        }

        tokio::select! {
            maybe = rx.recv() => {
                let Some(pkt) = maybe else { break };
                write_buf.extend_from_slice(&encode_frame(&pkt)?);
            }
            n = stream.read(&mut chunk) => {
                let n = n?;
                if n == 0 {
                    debug!(client = %reg.client, "VirtualNet 对端关闭");
                    break;
                }
                buf.extend_from_slice(&chunk[..n]);
                while let Some(pkt) = take_frame(&mut buf)? {
                    hub.route(&reg.client, &pkt);
                }
            }
        }
    }
    Ok(())
}

/// 确保客户端离开时一定被注销。
struct JoinGuard {
    hub: Arc<VnetHub>,
    client: String,
}

impl Drop for JoinGuard {
    fn drop(&mut self) {
        self.hub.leave(&self.client);
        debug!(client = %self.client, "VirtualNet 客户端已离开，地址与路由已回收");
    }
}

async fn write_resp(stream: &mut TcpStream, resp: &VnetRegisterResp) -> Result<()> {
    stream.write_all(&resp.to_line()?).await?;
    stream.flush().await?;
    Ok(())
}

/// 服务端自己的 IP（在虚拟网络里）—— 面板展示用。
pub fn gateway_ip(cfg: &ServerConfig) -> Option<Ipv4Addr> {
    let s = cfg.vnet.subnet.trim();
    if s.is_empty() {
        return None;
    }
    let sub = Subnet::parse(s).ok()?;
    if cfg.vnet.gateway.trim().is_empty() {
        return sub.nth(1);
    }
    cfg.vnet.gateway.split('/').next()?.trim().parse().ok()
}

/// 客户端用的：`[virtualNet] serverPort` 与 `vnet_port` 哪个都没写就没法连。
pub fn client_server_port(cfg: &rustunnel_common::config::ClientConfig) -> Option<u16> {
    let p = cfg.virtual_net.server_port;
    (p != 0).then_some(p)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hub() -> VnetHub {
        let cfg = ServerConfig {
            vnet_port: Some(17020),
            vnet: rustunnel_common::vnet::VirtualNetConfig {
                subnet: "100.64.0.0/24".into(),
                ..Default::default()
            },
            ..Default::default()
        };
        VnetHub::from_config(&cfg).unwrap()
    }

    fn sink() -> (mpsc::Sender<Vec<u8>>, mpsc::Receiver<Vec<u8>>) {
        mpsc::channel(16)
    }

    #[test]
    fn 默认配置不启用() {
        let cfg = ServerConfig::default();
        assert!(!cfg.vnet_enabled());
        assert!(cfg.vnet_listen_port().is_none());
    }

    #[test]
    fn 没配网段就报错而不是瞎猜() {
        let cfg = ServerConfig {
            vnet_port: Some(17020),
            ..Default::default()
        };
        let e = VnetHub::from_config(&cfg).unwrap_err().to_string();
        assert!(e.contains("subnet"), "{e}");
    }

    #[test]
    fn 网关默认取网段第一个可用地址() {
        let cfg = ServerConfig {
            vnet_port: Some(17020),
            vnet: rustunnel_common::vnet::VirtualNetConfig {
                subnet: "10.10.0.0/24".into(),
                ..Default::default()
            },
            ..Default::default()
        };
        assert_eq!(gateway_ip(&cfg).unwrap(), Ipv4Addr::new(10, 10, 0, 1));
    }

    #[test]
    fn 加入后再离开_地址与路由都要回收() {
        let h = hub();
        let (tx, _rx) = sink();
        let j = h.join("a", None, tx).unwrap();
        assert_eq!(h.address_of("a"), Some(j.ip));

        h.leave("a");
        assert_eq!(h.address_of("a"), None, "路由必须清掉");
        // 释放之后同一个地址必须能被别人拿到，否则地址池会越用越少
        let (tx2, _rx2) = sink();
        let j2 = h.join("b", Some(j.ip), tx2).unwrap();
        assert_eq!(j2.ip, j.ip, "释放过的地址应当可复用");
    }

    #[test]
    fn 同一客户端重连不会漏掉旧登记() {
        let h = hub();
        let (tx1, _rx1) = sink();
        let j1 = h.join("a", None, tx1).unwrap();
        let (tx2, mut rx2) = sink();
        let j2 = h.join("a", None, tx2).unwrap();
        assert_eq!(h.stats().unwrap().peers, 1, "同一个人不该占两个名额");
        assert_eq!(h.address_of("a"), Some(j2.ip));

        // 无论地址是否复用，**地址池不能漏**：这是这条用例真正要盯的东西。
        // （高→低分配 + 释放游标回退，所以这里通常确实会复用同一个地址。）
        assert_eq!(
            h.stats().unwrap().leased,
            1,
            "旧租约必须被回收，否则地址池越用越少（j1={}）",
            j1.ip
        );

        // 旧连接的信箱必须被清掉：往这个地址发包不能再进旧队列
        let pkt = fake_udp(Ipv4Addr::new(100, 64, 0, 200), j2.ip, b"x");
        assert!(h.route("someone", &pkt));
        assert_eq!(rx2.try_recv().unwrap(), pkt, "新连接必须能收到");
    }

    #[test]
    fn 点对点转发() {
        let h = hub();
        let (txa, mut rxa) = sink();
        let (txb, mut rxb) = sink();
        let ja = h.join("a", None, txa).unwrap();
        let jb = h.join("b", None, txb).unwrap();

        // a → b
        let pkt = fake_udp(ja.ip, jb.ip, b"hi");
        assert!(h.route("a", &pkt));
        let got = rxb.try_recv().expect("b 应当收到包");
        assert_eq!(got, pkt);
        assert!(rxa.try_recv().is_err(), "不该回给自己");

        // b → a
        let pkt2 = fake_udp(jb.ip, ja.ip, b"yo");
        assert!(h.route("b", &pkt2));
        assert_eq!(rxa.try_recv().unwrap(), pkt2);
    }

    #[test]
    fn 发往网关的_ping_由服务端自己回() {
        let h = hub();
        let (tx, mut rx) = sink();
        let j = h.join("a", None, tx).unwrap();
        let gw = h.stats().unwrap().gateway.parse::<Ipv4Addr>().unwrap();

        let mut pkt = fake_udp(j.ip, gw, b"");
        pkt[9] = 1; // ICMP
        pkt[20] = 8; // echo request
        pkt.resize(28, 0);
        assert!(h.route("a", &pkt), "网关应当把这个包收下并回包");

        let reply = rx.try_recv().expect("应当收到网关的应答");
        let hdr = vnet::parse_ipv4(&reply).unwrap();
        assert_eq!(hdr.src, gw);
        assert_eq!(hdr.dst, j.ip);
        assert_eq!(reply[20], 0, "必须是 Echo Reply");
    }

    #[test]
    fn 查不到目的地址就丢弃并计数() {
        let h = hub();
        let (tx, _rx) = sink();
        let j = h.join("a", None, tx).unwrap();
        let pkt = fake_udp(j.ip, Ipv4Addr::new(100, 64, 0, 99), b"x");
        assert!(!h.route("a", &pkt));
        assert_eq!(h.stats().unwrap().dropped_unroutable, 1);
    }

    #[test]
    fn 广播泛洪给其他所有人但不回自己() {
        let h = hub();
        let (txa, mut rxa) = sink();
        let (txb, mut rxb) = sink();
        let (txc, mut rxc) = sink();
        let ja = h.join("a", None, txa).unwrap();
        h.join("b", None, txb).unwrap();
        h.join("c", None, txc).unwrap();

        let pkt = fake_udp(ja.ip, Ipv4Addr::BROADCAST, b"who");
        assert!(h.route("a", &pkt));
        assert_eq!(rxb.try_recv().unwrap(), pkt);
        assert_eq!(rxc.try_recv().unwrap(), pkt);
        assert!(rxa.try_recv().is_err(), "广播不该回到发送者");
    }

    #[test]
    fn 畸形包被安全丢弃() {
        let h = hub();
        let (tx, _rx) = sink();
        h.join("a", None, tx).unwrap();
        for bad in [&b""[..], &b"\x60"[..], &b"\x45"[..]] {
            assert!(!h.route("a", bad), "畸形包必须被安全丢弃");
        }
    }

    /// 造一个最小的合法 IPv4/UDP 报文（只要能解析出地址就够）。
    fn fake_udp(src: Ipv4Addr, dst: Ipv4Addr, payload: &[u8]) -> Vec<u8> {
        let mut pkt = vec![0u8; 20];
        pkt[0] = 0x45;
        let total = (20 + 8 + payload.len()) as u16;
        pkt[2..4].copy_from_slice(&total.to_be_bytes());
        pkt[9] = 17;
        pkt[12..16].copy_from_slice(&src.octets());
        pkt[16..20].copy_from_slice(&dst.octets());
        pkt.extend_from_slice(&[0u8; 8]);
        pkt.extend_from_slice(payload);
        pkt
    }
}
