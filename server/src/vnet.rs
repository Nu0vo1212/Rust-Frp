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
use nfrp_common::config::ServerConfig;
use nfrp_common::vnet::{
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

/// ★★ v0.5.8 新增（第七轮审计 **C-1**）：**VirtualNet 的会话键**。
///
/// # 为什么不能直接用 `String`
///
/// VNet 里同时存在两种"客户端标识"：
///
/// | 概念 | 取值 | 用途 |
/// |---|---|---|
/// | **显示名** `reg.client` | 客户端**自报**，可重复（两个客户端都能叫 `laptop`） | 日志 / 审计 |
/// | **会话键** `SessionKey` | `"{client}-{run_id}"`，服务端生成，**全局唯一** | 路由 / 地址池 / 收发信箱 |
///
/// 两者都是字符串。C-1 的成因正是**建立时用会话键、转发时传了显示名** ——
/// 因为都是 `String`，编译器一点都拦不住，而运行期表现为
/// "每个包都被判成冒充并丢弃"（`dropped_spoofed` 对合法包也自增）。
///
/// ⇒ 用一个**独立类型**把两者在类型层面分开：`route()` 只接受
/// [`SessionKey`]，想把 `reg.client` 传进去会**直接编译失败**。
/// 这正是本项目方法论里说的"让漏掉变得不可能"。
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SessionKey(String);

impl SessionKey {
    /// 由显示名生成一个**新的**会话键（服务端生成，不与显示名相等）。
    pub fn new_for(display_name: &str) -> Self {
        Self(format!(
            "{display_name}-{}",
            nfrp_common::util::new_run_id()
        ))
    }

    /// 仅供测试与内部查找使用：由已知字符串构造。
    pub fn from_raw(s: impl Into<String>) -> Self {
        Self(s.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for SessionKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

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
    /// 客户端 id → 当前登记的代次。
    ///
    /// `JoinGuard` 只能回收**自己那一次**登记：旧连接如果在同一 id 被新连接
    /// 接手后才 Drop，不能把新连接的路由/租约删掉。官方 v0.71.1 修的正是
    /// 这种"stale cleanup 删 replacement route"的黑洞。
    owners: HashMap<String, u64>,
    next_generation: u64,
    /// 统计：目的地址查不到人的包。
    dropped_unroutable: u64,
    /// 统计：下游队列满了被丢掉的包。
    dropped_full: u64,
    /// 统计：**源地址不属于发送者**而被丢弃的包（v0.5.5，第四轮 F4）。
    ///
    /// 这个指标是有人在冒充别人的**唯一可观测信号** —— VNet 本就没有 ACL，
    /// 源地址就是身份；它非零就意味着网络里有人在伪造源地址。
    dropped_spoofed: u64,
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
    /// 源地址伪造而被丢弃的包数（第四轮 F4）。非零 = 有人在冒充别人。
    pub dropped_spoofed: u64,
}

/// 加入成功后返回给客户端的参数。
#[derive(Debug, Clone)]
pub struct Joined {
    pub ip: Ipv4Addr,
    pub subnet: Subnet,
    pub gateway: Ipv4Addr,
    pub mtu: u32,
    /// 本次登记的代次；`JoinGuard` 用它避免旧连接清掉新连接。
    generation: u64,
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
                owners: HashMap::new(),
                next_generation: 0,
                dropped_unroutable: 0,
                dropped_full: 0,
                dropped_spoofed: 0,
            }),
        })
    }

    /// 客户端加入。`want` 为 `None` 表示由服务端分配。
    ///
    /// ★ v0.5.8（C-1）：`client` 参数是 [`SessionKey`] 而不是 `&str` ——
    ///   加入、路由、离开三处**必须用同一个键**，用类型把它锁住。
    pub fn join(
        &self,
        client: &SessionKey,
        want: Option<Ipv4Addr>,
        sink: mpsc::Sender<Vec<u8>>,
    ) -> Result<Joined> {
        let mut g = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        let client = client.as_str();

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
        let generation = g.next_generation.wrapping_add(1);
        g.next_generation = generation;
        g.owners.insert(client.to_string(), generation);

        Ok(Joined {
            ip,
            subnet: g.subnet,
            gateway: g.gateway,
            mtu: g.mtu,
            generation,
        })
    }

    /// 客户端离开：路由与地址**一起**回收。
    ///
    /// 这是无条件清理，主要给测试和显式管理用。连接生命周期请用
    /// [`JoinGuard`]：它只会清理**自己那一代**登记。
    pub fn leave(&self, client: &SessionKey) {
        let mut g = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        Self::leave_locked(&mut g, client.as_str());
    }

    /// 只有当前登记仍然是 `generation` 时才清理。
    ///
    /// 旧连接的 `JoinGuard` 可能在新连接完成登记之后才 Drop；如果按 id
    /// 无条件删，就会把新连接的路由、租约和 sink 一起删掉。官方 frp
    /// v0.71.1 的 VNet 修复就是要求"清理必须属于当前 owner"。
    fn leave_if_current(&self, client: &SessionKey, generation: u64) {
        let mut g = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        if g.owners.get(client.as_str()).copied() != Some(generation) {
            debug!(%client, generation, "旧 VNet 会话的清理晚到，跳过（当前登记已属于新连接）");
            return;
        }
        Self::leave_locked(&mut g, client.as_str());
    }

    fn leave_locked(g: &mut HubInner, client: &str) {
        g.routes.unregister(&g.network, client);
        g.pool.release(client);
        g.sinks.remove(client);
        g.owners.remove(client);
    }

    /// 处理一个从 `from` 客户端收到的 IP 报文：按目的地址转发。
    ///
    /// 返回 `true` 表示包被投出去了（发给了别人或由网关应答），
    /// `false` 表示丢弃（查不到人 / 解析失败）。
    ///
    /// ★★ v0.5.5 修（第四轮 F4）：**必须校验源地址**。
    ///
    /// 原先本函数**只读 `h.dst`，从不读 `h.src`**（全文件 `src` 只出现在
    /// 一处测试断言里）。注册层抢地址是拦住的，但转发层不校验 ⇒
    /// 成员 A 可以发出 `src = 其他成员` 甚至 `src = 网关` 的包，而 B 照收。
    ///
    /// 影响：VNet 里**没有任何可信的源身份** —— 可以冒充别人发起连接，
    /// 也可以让受害者以为流量来自网关。VNet 本来就没有 ACL，
    /// 源地址就是唯一的"身份"，不校验等于身份可以自由伪造。
    ///
    /// 实弹：`tmp/f4_vnet_spoof.py`（对照组：注册层抢地址是拦住的）。
    ///
    /// ★★ v0.5.8 修（第七轮审计 **C-1**）：参数改成 [`SessionKey`]，
    /// **从类型上杜绝**"把显示名传进来"。
    ///
    /// # 为什么需要类型而不只是改对实参
    ///
    /// C-1 的成因是：身份建立用 `session_key`（`"{client}-{run_id}"`），
    /// 而转发时传了 `reg.client`（**显示名**）。
    /// 两者都是 `String`，**传错了编译器不会拦** —— 实测每一个包都被判成
    /// "冒充"并丢弃（连客户端自己的地址都判冒充），
    /// 且 `dropped_spoofed` 这个"有人在冒充"的唯一信号被彻底污染。
    ///
    /// 本项目连续多轮的模式是"**防线写对了，但没铺满**"，
    /// 治本方向一直是"把同一判定收敛成唯一来源，并让漏掉变得**不可能**
    /// （类型层面的约束，而不是靠调用方记得）"。
    /// 这里就照这个思路做：**显示名与会话键是两种不同的类型**，
    /// 想把 `reg.client` 传进来会直接编译失败。
    ///
    /// 成员 A 可以发出 `src = 其他成员` 甚至 `src = 网关` 的包，而 B 照收。
    ///
    /// 影响：VNet 里**没有任何可信的源身份** —— 可以冒充别人发起连接，
    /// 也可以让受害者以为流量来自网关。VNet 本来就没有 ACL，
    /// 源地址就是唯一的"身份"，不校验等于身份可以自由伪造。
    ///
    /// 实弹：`tmp/f4_vnet_spoof.py`（对照组：注册层抢地址是拦住的）。
    fn route(&self, from: &SessionKey, pkt: &[u8]) -> bool {
        let from = from.as_str();
        let Some(h) = vnet::parse_ipv4(pkt) else {
            // IPv6 或畸形包。**静默丢弃**而不是回 ICMP unreachable：
            // 我们不是路由器，装作会发 ICMP 只会让人以为链路有问题。
            return false;
        };
        let mut g = self.inner.lock().unwrap_or_else(|e| e.into_inner());

        // ★ ⓪ 源地址校验（F4）：`h.src` 必须是 `from` **自己**的地址之一。
        //
        // 为什么是"属于自己"而不是"等于某个固定值"：一个客户端可以注册
        // 多个 IP（`Switch::register` 按 ip → client 存，`ips_of` 返回
        // 一个人的全部地址），多网卡场景下源地址可以是其中任意一个。
        //
        // 不需要给网关开例外：网关自己回的 ICMP 回复走 `deliver`，
        // 不经过这条路径。
        if !g.routes.ips_of(&g.network, from).contains(&h.src) {
            g.dropped_spoofed += 1;
            debug!(
                from = %from,
                src = %h.src,
                "虚拟网络源地址不属于发送者，丢弃（防冒充）"
            );
            return false;
        }

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
        let mut g = self.inner.lock().unwrap_or_else(|e| e.into_inner());
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
        let g = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        Some(VnetStats {
            network: g.network.clone(),
            subnet: g.subnet.to_string(),
            gateway: g.gateway.to_string(),
            mtu: g.mtu,
            peers: g.sinks.len(),
            leased: g.pool.leased_count(),
            dropped_unroutable: g.dropped_unroutable,
            dropped_full: g.dropped_full,
            dropped_spoofed: g.dropped_spoofed,
        })
    }

    /// 某个客户端分到的地址（测试与面板用）。
    pub fn address_of(&self, client: &str) -> Option<Ipv4Addr> {
        let g = self.inner.lock().unwrap_or_else(|e| e.into_inner());
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
    //
    // ★ v0.5.3：这里把 OIDC 的 subject 绑定到 `reg.client`（VirtualNet 的会话标识），
    //   与普通控制连接绑定到 run_id 是同一个道理 —— 不能让"曾在别处登录过的
    //   subject"给本次注册背书。
    if let Err(e) = sec.verify_login(&reg.token, reg.timestamp, &reg.client) {
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
    // ★★ v0.5.6 修（审计总报告 L12，低危）：**身份键不再用客户端自报的字符串**。
    //
    // # 问题
    //
    // `reg.client` 是**客户端自报**的任意非空字符串（上面只查了非空），
    // 而它被当作 `Hub` 的**唯一身份键**：
    //
    // * `Hub::join` 的第一件事就是 —— 如果这个键已存在，
    //   **先把旧的踢掉**（`leave_locked`，注释写着"同一个 client_id 重连"）；
    // * 它同时是 IP 池的 `claim` / `acquire` 的键、`routes` 的键、`sinks` 的键。
    //
    // ⇒ 攻击者只要用**别人的 client 名**注册，就能：
    //   ① 把对方**踢下线**（其 `sinks` 被移除、路由被撤）；
    //   ② 顶替对方的虚拟 IP（`routes.register` 会把旧路由顶掉并 warn）。
    //
    // # 为什么这仍然是 Low（如实说明，不夸大）
    //
    // 上面那道 `sec.verify_login(&reg.token, reg.timestamp, &reg.client)`
    // **要求通过认证**（token / OIDC）—— 未持凭据者进不来。
    // 所以这是"**已认证租户之间**可以互相打断"，
    // 在默认配置（无 RBAC、单一共享 token）下等价于"同一个信任域内的成员互扰"。
    // 定 Low 合适；但它确实是全仓**唯一**用客户端自报字段当身份键的地方
    // （其余身份键都绑定了连接身份或服务端生成值）。
    //
    // # 修法：会话键 = 服务端生成的随机值，`reg.client` 降级为**显示名**
    //
    // 这样"同名"不再等于"同一个身份"：两个客户端可以都叫 `laptop`，
    // 但它们拿到各自独立的会话键、各自独立的 IP，谁也踢不掉谁。
    //
    // ★ 兼容性：`reg.client` 仍然照原样用于**日志与审计**，
    //   客户端侧看不到任何变化（响应里从来不含这个键）。
    //   代价是"同名重连时自动顶掉旧连接"这个便利没了 ——
    //   但那正是漏洞本身，去掉是对的；旧连接会由 `JoinGuard` / 读写超时回收。
    // ★ 会话键用项目自己的随机 ID 生成器（`OsRng` 支撑，16 字节十六进制）。
    //   不引新依赖 —— `util::new_run_id()` 就是为这类场景写的。
    // ★★ v0.5.8（第七轮审计 C-1）：改用 [`SessionKey`] 类型。
    //   以前是裸 `String`，于是转发路径**误传了显示名**而编译器毫无反应
    //   ⇒ 每个包都被判成冒充。现在两者是不同类型，传错**编译不过**。
    let session_key = SessionKey::new_for(&reg.client);
    let joined = match hub.join(&session_key, want, tx) {
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
        client: session_key.clone(),
        generation: joined.generation,
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
                    // ★★ v0.5.8 修（第七轮审计 **C-1**）：这里原先传的是
                    //    `&reg.client`（**显示名**），而身份建立时用的是
                    //    `session_key`（`"{client}-{run_id}"`，见上面 `:510`）。
                    //
                    // # 后果（实测，C 组 `tmp/audit7/c/c03_vnet_key.py`）
                    //
                    // `route()` 的第一步是**源地址校验**（本文件 `:266`）：
                    //
                    // ```ignore
                    // if !g.routes.ips_of(&g.network, from).contains(&h.src) {
                    //     g.dropped_spoofed += 1;   // 计入"防冒充"
                    //     return false;             // 丢弃
                    // }
                    // ```
                    //
                    // 而 `ips_of` 是**精确匹配**（`common/src/vnet.rs:532`：
                    // `o.as_str() == client`）—— owner 是 `"laptop-3f2a…"`，
                    // 传进去的是 `"laptop"` ⇒ 恒不匹配 ⇒ `ips_of` 恒空
                    // ⇒ **每一个包都被判成冒充并丢弃**。
                    //
                    // 实测日志原文（连它**自己**的地址都被判成冒充）：
                    // ```text
                    // 虚拟网络源地址不属于发送者，丢弃（防冒充）
                    //   from=laptop src=100.64.0.254
                    // ```
                    //
                    // # 两重影响
                    //
                    // 1. **功能面**：广播 / 网关 ICMP / 单播 A→B **全部不可达**
                    //    —— VNet 转发整条失效。
                    // 2. **可观测性面**：`dropped_spoofed` 是第四轮 F4 之后
                    //    "有人在冒充"的**唯一信号**，现在对**每个合法包**都自增
                    //    ⇒ 真实的冒充告警被噪音淹没，指标**失去判别力**。
                    //
                    // # 为什么前几轮没发现
                    //
                    // `session_key` 是第四轮修 F4（同名客户端互相踢掉）时引入的，
                    // 但**只改了建立侧**，查找侧（这条转发路径）漏改了。
                    // ⇒ "引入一个新的键"时必须把它**所有**使用点一起改，
                    //   否则就会出现这种"一半新键、一半旧名"的错配。
                    //
                    // ★ 安全姿态：这是 **fail-closed**（拒绝一切），不是放行，
                    //   所以不构成越权；主要损失是可用性与告警可信度。
                    hub.route(&session_key, &pkt);
                }
            }
        }
    }
    Ok(())
}

/// 确保客户端离开时一定被注销。
///
/// ★ v0.5.8（C-1）：持有的必须是 [`SessionKey`]（而不是裸 `String`）——
///   这样 `hub.leave()` 才能编译通过，同时保证**离开用的键与加入用的键同源**。
struct JoinGuard {
    hub: Arc<VnetHub>,
    client: SessionKey,
    generation: u64,
}

impl Drop for JoinGuard {
    fn drop(&mut self) {
        self.hub.leave_if_current(&self.client, self.generation);
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
pub fn client_server_port(cfg: &nfrp_common::config::ClientConfig) -> Option<u16> {
    let p = cfg.virtual_net.server_port;
    (p != 0).then_some(p)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hub() -> VnetHub {
        let cfg = ServerConfig {
            vnet_port: Some(17020),
            vnet: nfrp_common::vnet::VirtualNetConfig {
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

    /// ★ v0.5.8（C-1）：测试里构造会话键。
    ///
    /// 用 `from_raw` 而不是 `new_for` —— 测试需要**可预测**的键
    /// （比如同一个名字要拿到同一个键来验证"重连清旧登记"）。
    /// 生产代码走 `new_for`（带随机后缀、保证唯一）。
    fn sk(name: &str) -> SessionKey {
        SessionKey::from_raw(name)
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
            vnet: nfrp_common::vnet::VirtualNetConfig {
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
        let j = h.join(&sk("a"), None, tx).unwrap();
        assert_eq!(h.address_of("a"), Some(j.ip));

        h.leave(&sk("a"));
        assert_eq!(h.address_of("a"), None, "路由必须清掉");
        // 释放之后同一个地址必须能被别人拿到，否则地址池会越用越少
        let (tx2, _rx2) = sink();
        let j2 = h.join(&sk("b"), Some(j.ip), tx2).unwrap();
        assert_eq!(j2.ip, j.ip, "释放过的地址应当可复用");
    }

    #[test]
    fn 同一客户端重连不会漏掉旧登记() {
        let h = hub();
        let (tx1, _rx1) = sink();
        let j1 = h.join(&sk("a"), None, tx1).unwrap();
        let (tx2, mut rx2) = sink();
        let j2 = h.join(&sk("a"), None, tx2).unwrap();
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
        //
        // ★ v0.5.5（第四轮 F4）：发送者必须是一个**真的注册过、且拥有该源地址**
        //   的客户端 —— 源地址校验上线后，原来那个虚构的 `"someone"` 会被
        //   正确地拒掉（它不拥有 `100.64.0.200`）。这里改成让 s 真加入。
        let (txs, _rxs) = sink();
        let js = h.join(&sk("s"), None, txs).unwrap();
        let pkt = fake_udp(js.ip, j2.ip, b"x");
        assert!(h.route(&sk("s"), &pkt));
        assert_eq!(rx2.try_recv().unwrap(), pkt, "新连接必须能收到");
    }

    #[test]
    fn 点对点转发() {
        let h = hub();
        let (txa, mut rxa) = sink();
        let (txb, mut rxb) = sink();
        let ja = h.join(&sk("a"), None, txa).unwrap();
        let jb = h.join(&sk("b"), None, txb).unwrap();

        // a → b
        let pkt = fake_udp(ja.ip, jb.ip, b"hi");
        assert!(h.route(&sk("a"), &pkt));
        let got = rxb.try_recv().expect("b 应当收到包");
        assert_eq!(got, pkt);
        assert!(rxa.try_recv().is_err(), "不该回给自己");

        // b → a
        let pkt2 = fake_udp(jb.ip, ja.ip, b"yo");
        assert!(h.route(&sk("b"), &pkt2));
        assert_eq!(rxa.try_recv().unwrap(), pkt2);
    }

    #[test]
    fn 发往网关的_ping_由服务端自己回() {
        let h = hub();
        let (tx, mut rx) = sink();
        let j = h.join(&sk("a"), None, tx).unwrap();
        let gw = h.stats().unwrap().gateway.parse::<Ipv4Addr>().unwrap();

        let mut pkt = fake_udp(j.ip, gw, b"");
        pkt[9] = 1; // ICMP
        pkt[20] = 8; // echo request
        pkt.resize(28, 0);
        assert!(h.route(&sk("a"), &pkt), "网关应当把这个包收下并回包");

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
        let j = h.join(&sk("a"), None, tx).unwrap();
        let pkt = fake_udp(j.ip, Ipv4Addr::new(100, 64, 0, 99), b"x");
        assert!(!h.route(&sk("a"), &pkt));
        assert_eq!(h.stats().unwrap().dropped_unroutable, 1);
    }

    #[test]
    fn 广播泛洪给其他所有人但不回自己() {
        let h = hub();
        let (txa, mut rxa) = sink();
        let (txb, mut rxb) = sink();
        let (txc, mut rxc) = sink();
        let ja = h.join(&sk("a"), None, txa).unwrap();
        h.join(&sk("b"), None, txb).unwrap();
        h.join(&sk("c"), None, txc).unwrap();

        let pkt = fake_udp(ja.ip, Ipv4Addr::BROADCAST, b"who");
        assert!(h.route(&sk("a"), &pkt));
        assert_eq!(rxb.try_recv().unwrap(), pkt);
        assert_eq!(rxc.try_recv().unwrap(), pkt);
        assert!(rxa.try_recv().is_err(), "广播不该回到发送者");
    }

    #[test]
    fn 畸形包被安全丢弃() {
        let h = hub();
        let (tx, _rx) = sink();
        h.join(&sk("a"), None, tx).unwrap();
        for bad in [&b""[..], &b"\x60"[..], &b"\x45"[..]] {
            assert!(!h.route(&sk("a"), bad), "畸形包必须被安全丢弃");
        }
    }

    // ------------------------------------------------------------------
    // 第四轮 F4：源地址伪造必须被拦
    // ------------------------------------------------------------------

    /// ★★ F4 核心回归：**冒充别人的源地址必须被丢弃**。
    ///
    /// 修复前 `route()` 只读 `h.dst`，A 可以发出 `src = B 的地址` 的包，
    /// 而 B 照收 —— VNet 里身份可以自由伪造。
    #[test]
    fn 冒充他人源地址必须被丢弃() {
        let h = hub();
        let (txa, mut rxa) = sink();
        let (txb, mut rxb) = sink();
        let ja = h.join(&sk("a"), None, txa).unwrap();
        let jb = h.join(&sk("b"), None, txb).unwrap();

        // A 伪造"源地址 = B"，发给 B
        let spoof = fake_udp(jb.ip, jb.ip, b"i-am-not-b");
        assert!(!h.route(&sk("a"), &spoof), "伪造成 B 的源地址必须被丢弃");
        assert!(
            rxb.try_recv().is_err(),
            "B 不该收到那条伪造包（这正是修复前会发生的事）"
        );
        assert_eq!(
            h.stats().unwrap().dropped_spoofed,
            1,
            "必须计入 dropped_spoofed（这是唯一的可观测信号）"
        );

        // 对照：A 用自己的地址发，必须正常送达
        let ok = fake_udp(ja.ip, jb.ip, b"from-a");
        assert!(h.route(&sk("a"), &ok), "用自己的源地址发应当正常转发");
        assert_eq!(rxb.try_recv().unwrap(), ok);

        // 确认没有误伤：合法那次不该增加 spoofed 计数
        assert_eq!(h.stats().unwrap().dropped_spoofed, 1);
        assert!(rxa.try_recv().is_err(), "不该回给自己");
    }

    /// 冒充**网关**的源地址同样必须被拒。
    #[test]
    fn 冒充网关源地址必须被丢弃() {
        let h = hub();
        let (txa, _rxa) = sink();
        let (txb, mut rxb) = sink();
        h.join(&sk("a"), None, txa).unwrap();
        let jb = h.join(&sk("b"), None, txb).unwrap();
        let gw = h.stats().unwrap().gateway.parse::<Ipv4Addr>().unwrap();

        let spoof = fake_udp(gw, jb.ip, b"i-am-gateway");
        assert!(!h.route(&sk("a"), &spoof), "冒称网关必须被丢弃");
        assert!(rxb.try_recv().is_err(), "B 不该以为这来自网关");
        assert_eq!(h.stats().unwrap().dropped_spoofed, 1);
    }

    /// 广播：源地址校验要照常生效（伪造的广播也要丢）。
    #[test]
    fn 伪造源地址的广播也要丢弃() {
        let h = hub();
        let (txa, _rxa) = sink();
        let (txb, mut rxb) = sink();
        let ja = h.join(&sk("a"), None, txa).unwrap();
        let jb = h.join(&sk("b"), None, txb).unwrap();

        // 伪造 B 的源地址去广播
        let spoof = fake_udp(jb.ip, Ipv4Addr::BROADCAST, b"spoofed-bcast");
        assert!(!h.route(&sk("a"), &spoof));
        assert!(rxb.try_recv().is_err(), "B 不该收到伪造来源的广播");
        assert_eq!(h.stats().unwrap().dropped_spoofed, 1);

        // 合法广播照常
        let ok = fake_udp(ja.ip, Ipv4Addr::BROADCAST, b"ok-bcast");
        assert!(h.route(&sk("a"), &ok));
        assert_eq!(rxb.try_recv().unwrap(), ok);
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

    // ------------------------------------------------------------------
    // v0.5.6 回归（审计总报告 L12）：身份键不得用客户端自报字符串
    // ------------------------------------------------------------------

    /// ★★ L12：**同名会话必须是两个独立身份**，不能互相踢。
    ///
    /// 修复前 `reg.client` 直接当 `Hub` 的身份键，而 `Hub::join` 第一件事
    /// 就是"这个键已存在 ⇒ 先把旧的踢掉"（那段逻辑本意是处理重连）。
    /// ⇒ 攻击者用别人的 client 名注册即可把对方**踢下线并顶替其虚拟 IP**。
    ///
    /// 这里在 `Hub` 层面锁住不变量：**不同的 key 就是不同的成员**。
    /// 调用方（`handle_vnet`）负责把 `reg.client` 换成一个服务端生成的
    /// `session_key`（`reg.client` 只留作显示名）。
    #[test]
    fn 同名会话必须是独立身份() {
        let h = hub();
        let (tx1, _rx1) = sink();
        let (tx2, _rx2) = sink();

        // 模拟两个客户端都自报 "laptop"，但会话键不同（服务端生成）
        let key1 = SessionKey::new_for("laptop");
        let key2 = SessionKey::new_for("laptop");
        assert_ne!(key1, key2, "前置：两个会话键必须不同");

        let j1 = h.join(&key1, None, tx1).expect("第一个加入");
        let j2 = h.join(&key2, None, tx2).expect("第二个加入");

        assert_ne!(j1.ip, j2.ip, "同名但不同会话 ⇒ 必须拿到不同的 IP");
        // ★ 关键：第二个加入**不能**把第一个挤掉 —— 两个会话都还在
        assert_eq!(
            h.address_of(key1.as_str()),
            Some(j1.ip),
            "后加入的同名会话不得踢掉先加入者（L12）"
        );
        assert_eq!(h.address_of(key2.as_str()), Some(j2.ip));
    }

    // ------------------------------------------------------------------
    // 第七轮审计 C-1：转发路径必须用**会话键**，不能用显示名
    // ------------------------------------------------------------------

    /// ★★ v0.5.8 回归（第七轮审计 **C-1**，中危）：
    /// **转发路径传的身份键必须与建立时一致（会话键），否则一切包都被判成冒充。**
    ///
    /// # 这个 bug 的形态（一行实参传错）
    ///
    /// `vnet.rs` 里建立身份用 `session_key = "{client}-{run_id}"`，
    /// 而转发时传的是 `reg.client`（**显示名**，没有 `-{run_id}` 后缀）。
    /// `route()` 第一步的源地址校验是**精确匹配**owner ⇒ 恒不匹配
    /// ⇒ 每个包都计入 `dropped_spoofed` 并丢弃。
    ///
    /// 实测（C 组 `c03_vnet_key.py`）：连客户端**自己**的地址都被判成冒充，
    /// 日志 `虚拟网络源地址不属于发送者，丢弃（防冒充） from=laptop src=100.64.0.254`。
    ///
    /// # 这条测试测什么（**两个层面，缺一不可**）
    ///
    /// 1. **功能**：用会话键路由时，A→B 的单播必须送达；
    /// 2. **指标**：**没有冒充流量时 `dropped_spoofed` 必须保持 0** ——
    ///    这一条才是 C-1 真正的判据。因为"转发通了"可以在指标依然失真的
    ///    情况下成立，而 `dropped_spoofed` 是"有人在冒充"的唯一信号，
    ///    它对合法包误增就等于告警失效。
    ///
    /// ★ 另外**刻意用显示名反测一次**：证明"用错键确实会导致全部丢弃"，
    ///   这样如果将来有人把实参改回 `reg.client`，第 2 条断言会立刻变红。
    #[test]
    fn 转发必须用会话键而不是显示名() {
        let h = hub();
        let (tx_a, mut rx_a) = sink();
        let (tx_b, mut rx_b) = sink();

        // 两个客户端都自称 "laptop"（显示名相同），会话键不同
        let key_a = SessionKey::new_for("laptop");
        let key_b = SessionKey::new_for("laptop");
        let ja = h.join(&key_a, None, tx_a).expect("A 加入");
        let jb = h.join(&key_b, None, tx_b).expect("B 加入");

        let before = h.stats().unwrap().dropped_spoofed;

        // ---- ① 用**会话键**路由：A→B 单播必须送达，且不增加防冒充计数 ----
        let pkt = fake_udp(ja.ip, jb.ip, b"hello-b");
        let ok = h.route(&key_a, &pkt);
        assert!(
            ok,
            "用会话键路由合法包必须成功 —— 若这里失败，说明身份键又错配了（C-1）"
        );
        let got = rx_b.try_recv().ok();
        assert_eq!(
            got.as_deref(),
            Some(pkt.as_slice()),
            "B 必须收到 A 发来的单播（VNet 转发的核心功能）"
        );

        assert_eq!(
            h.stats().unwrap().dropped_spoofed,
            before,
            "★ 合法流量**不得**增加 dropped_spoofed —— 这个指标是'有人在冒充'的\
             唯一信号；对合法包误增会让真实告警淹没在噪音里（C-1 的第二重危害）"
        );

        // ---- ② 用**显示名**路由：必须失败并计入防冒充（证明判据有区分力）----
        //
        // 这一条是"把实参改回 reg.client"时的报警器：
        // 显示名不是任何 owner ⇒ 精确匹配失败 ⇒ 丢弃 + 计数。
        let pkt2 = fake_udp(ja.ip, jb.ip, b"hello-b2");
        let ok2 = h.route(&sk("laptop"), &pkt2);
        assert!(!ok2, "用**显示名**路由必须被拒 —— 这正是 C-1 修复前的情形");
        assert!(
            h.stats().unwrap().dropped_spoofed > before,
            "用错身份键时应当计入 dropped_spoofed（这正是线上观察到的现象）"
        );
        let _ = rx_a.try_recv();
    }

    /// ★ 回归测试（对应官方 v0.71.1 的 VNet 路由清理）：
    /// **旧会话的 `JoinGuard` 晚于新会话触发时，只能回收自己的路由/租约。**
    ///
    /// 官方修复的形态是"replacement route 已注册，stale cleanup 按名字把它删了"。
    /// NFrp 的 owner 是 `"{client}-{run_id}"`，旧连接不可能删掉新连接的 key；
    /// 这条用例在 Hub 层锁住这个不变量，并确认旧租约不会把新租约一起释放。
    #[test]
    fn 旧会话清理不得回收新会话的路由() {
        let h = hub();
        let old = SessionKey::new_for("laptop");
        let new = SessionKey::new_for("laptop");
        let (tx_old, _rx_old) = sink();
        let (tx_new, _rx_new) = sink();

        let j_old = h.join(&old, None, tx_old).expect("旧会话加入");
        let j_new = h.join(&new, None, tx_new).expect("新会话加入");
        assert_ne!(j_old.ip, j_new.ip, "不同会话应当拿到不同地址");

        // 模拟旧连接晚到的 Drop：只清理旧 key
        h.leave(&old);

        assert_eq!(
            h.address_of(new.as_str()),
            Some(j_new.ip),
            "旧会话清理把新会话的路由删掉了"
        );
        assert_eq!(h.stats().unwrap().peers, 1);
        assert_eq!(h.stats().unwrap().leased, 1, "新会话的租约不能被旧清理释放");

        // 新会话仍然可用：自己发广播能被其他成员收到（这里先加一个成员）
        let (tx_peer, mut rx_peer) = sink();
        h.join(&SessionKey::new_for("peer"), None, tx_peer)
            .expect("peer 加入");
        let pkt = fake_udp(j_new.ip, Ipv4Addr::BROADCAST, b"still-alive");
        assert!(h.route(&new, &pkt), "新会话必须仍能转发");
        assert_eq!(rx_peer.try_recv().unwrap(), pkt);
    }

    /// ★ 回归测试：即使**同一个会话键**发生了重连，旧 `JoinGuard` 晚到的
    /// Drop 也只能按代次跳过，不能把新登记一起删掉。
    ///
    /// 这比"服务端总是生成唯一 key"更硬一层：将来如果有人改成复用 key，
    /// 也不会退回官方那个"stale cleanup 删 replacement route"的黑洞。
    #[test]
    fn 同一会话键的旧_guard_不得删掉新登记() {
        let h = Arc::new(hub());
        let key = sk("laptop-same-key");
        let (tx1, _rx1) = sink();
        let (tx2, _rx2) = sink();

        let j1 = h.join(&key, None, tx1).expect("旧连接加入");
        let old_guard = JoinGuard {
            hub: h.clone(),
            client: key.clone(),
            generation: j1.generation,
        };

        let j2 = h.join(&key, None, tx2).expect("新连接接手");
        // 旧连接此刻才 Drop（网络延迟/调度都可能导致这种顺序）
        drop(old_guard);

        assert_eq!(
            h.address_of(key.as_str()),
            Some(j2.ip),
            "旧 Guard 把新连接的路由删掉了"
        );
        assert_eq!(h.stats().unwrap().peers, 1);
        assert_eq!(h.stats().unwrap().leased, 1, "新连接的租约不能丢");
    }

    /// 反向：**同一个会话键**重连时，仍然要清掉旧登记（原有行为，防回归）。
    ///
    /// 这条保证修 L12 时没把"重连自愈"一起弄坏。
    #[test]
    fn 同一会话键重连仍然清掉旧登记() {
        let h = hub();
        let key = SessionKey::from_raw("laptop-same-session");
        let (tx1, _rx1) = sink();
        let (tx2, _rx2) = sink();

        let j1 = h.join(&key, None, tx1).expect("首次加入");
        let j2 = h.join(&key, None, tx2).expect("重连");

        assert_eq!(j1.ip, j2.ip, "同一会话重连应拿回同一个 IP");
        assert_eq!(h.address_of(key.as_str()), Some(j2.ip));
        // 旧登记必须被清掉：只有一个成员
        assert_eq!(
            h.stats().map(|s| s.peers).unwrap_or(0),
            1,
            "旧登记必须被清掉，不能留两份"
        );
    }
}
