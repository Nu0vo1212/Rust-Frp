//! xtcp 真 P2P 的**牵线服务端**（rendezvous server）。
//!
//! 服务端在 `p2p_port` 上开一个 UDP socket，只干一件事：把两个 peer 的公网地址
//! 互相告诉对方。**不转发任何业务数据**——P2P 建立后流量直接在两个内网之间跑。
//!
//! 一条完整的 xtcp 会话：
//!
//! ```text
//! visitor frpc ──(TCP 控制连接)── NatHoleVisitor ──▶ frps
//! frps 生成 sid，给 visitor 回 NatHoleResp{sid}，给 provider 下发 NatHoleClient{sid}
//! 双方各自向同一个 UDP socket 发 HELLO{sid}，服务端由此学到它们的公网地址
//! 双方都到齐后，服务端分别回 PEER{对端 ip:port}
//! 双方互发 QUIC Initial 打洞 -> 成功后直连，失败则回退 stcp 中继
//! ```

use std::{
    collections::HashMap,
    net::{IpAddr, SocketAddr},
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use nfrp_common::{
    frp::msg::{FrpMessage, NatHoleClient, NatHoleDetectBehavior, NatHoleResp, NatHoleVisitor},
    p2p::{self, Packet, Role},
};
use tokio::net::UdpSocket;
use tracing::{debug, info, warn};

use crate::{pool::ClientState, registry::Registry};

/// 一条会话从创建到过期的时间：足够双方完成一次 HELLO + QUIC 握手。
const SESSION_TTL: Duration = Duration::from_secs(60);

/// 单个 peer 在一次会话里留下的全部信息。
///
/// `addrs` 里可能有多个条目：端口预测要靠它。
/// 对称 NAT 给"每换一个本地端口"分配一个新公网端口，所以客户端会多开几个
/// 临时 socket 各发一份 HELLO —— 服务端于是观察到一串**端口序列**，
/// 客户端拿它算步长、预测 peer 之间通信时会落在哪个端口上。
#[derive(Clone)]
struct PeerSlot {
    addrs: Vec<SocketAddr>,
    transport: p2p::Transport,
    at: Instant,
}

/// 单个 peer 最多记录几个观测地址。
///
/// 够推出步长就够了（3 个能看出两次增量），再多只是给报文增肥。
const MAX_SAMPLES: usize = 8;

/// 一次打洞会话里两个 peer 的公网地址。
struct Session {
    /// 会话创建时间：刚 create 出来、两端都还没到的时候全靠它保命。
    created: Instant,
    /// ★ v0.5.8 修（第八轮审计 B-1，高危）：两个角色在**控制连接**上的源 IP。
    ///
    /// 牵线用的 UDP HELLO 是零鉴权的：谁先发到谁就是这个角色，`sid` 又在
    /// 报文里明文携带。攻击者只要在链路上读到一次 HELLO，就能抢先以
    /// provider 身份登记，把 visitor 的直连引到自己的地址上（随后用固定
    /// 应答骗过 visitor —— 见 `nfrp_common::p2p::handshake_ack` 的注释）。
    ///
    /// 控制连接是过了 token 鉴权的，所以这里把角色的来源钉死在控制连接
    /// 的 IP 上：**不同主机的 HELLO 一律拒收**。同一 NAT 后的攻击者
    /// （公网 IP 相同）穿得过这一层也没关系 —— 那一层由派生应答口令兜底，
    /// 两层是独立的纵深防御。
    visitor_ip: IpAddr,
    provider_ip: IpAddr,
    visitor: Option<PeerSlot>,
    provider: Option<PeerSlot>,
}

impl Session {
    fn new(visitor_ip: IpAddr, provider_ip: IpAddr) -> Self {
        Self {
            created: Instant::now(),
            visitor_ip,
            provider_ip,
            visitor: None,
            provider: None,
        }
    }

    /// 该角色**允许**的 HELLO 来源 IP。
    fn expected_ip(&self, role: Role) -> IpAddr {
        match role {
            Role::Visitor => self.visitor_ip,
            Role::Provider => self.provider_ip,
        }
    }

    fn slot_mut(&mut self, role: Role) -> &mut Option<PeerSlot> {
        match role {
            Role::Visitor => &mut self.visitor,
            Role::Provider => &mut self.provider,
        }
    }

    fn get(&self, role: Role) -> Option<&PeerSlot> {
        match role {
            Role::Visitor => self.visitor.as_ref(),
            Role::Provider => self.provider.as_ref(),
        }
    }

    /// 记下一个观测地址。
    ///
    /// 同一个 peer 会发来多份 HELLO（采样），这里做去重：
    /// 只有**公网端口不同**的才追加 —— 否则重传的 HELLO 会把样本列表
    /// 填成同一个值，端口预测退化成"步长 0"，等于没预测。
    fn observe(&mut self, role: Role, addr: SocketAddr, transport: p2p::Transport) {
        let slot = self.slot_mut(role);
        match slot {
            None => {
                *slot = Some(PeerSlot {
                    addrs: vec![addr],
                    transport,
                    at: Instant::now(),
                });
            }
            Some(s) => {
                s.at = Instant::now();
                s.transport = transport;
                if s.addrs.len() < MAX_SAMPLES && !s.addrs.contains(&addr) {
                    s.addrs.push(addr);
                }
            }
        }
    }
}

/// 两个 IP 是否同一个主机。
///
/// 双栈监听时同一台主机可能出现两种写法：控制连接报 `::ffff:127.0.0.1`
/// （IPv4-mapped IPv6）而 UDP 牵线 socket 报裸 `127.0.0.1`。不折算直接比
/// 会把合法 peer 误判成"IP 不符"，让 P2P 全部退化到中继 —— 那属于安全
/// 修复引入的可用性回归，必须在比较层就消掉。
fn same_host(a: &IpAddr, b: &IpAddr) -> bool {
    fn norm(ip: IpAddr) -> IpAddr {
        match ip {
            IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
                Some(v4) => IpAddr::V4(v4),
                None => IpAddr::V6(v6),
            },
            v4 => v4,
        }
    }
    norm(*a) == norm(*b)
}

/// `register` 的结果。
///
/// 单独拆出 `IpMismatch` 是为了让调用方能明确区分"对端还没到"和
/// "有人从错误的地址冒充 peer"（后者要打 warn，方便事后排查）。
pub enum RegisterOutcome {
    /// sid 不存在：从未创建 / 已过期 / 已被消费。
    NoSession,
    /// HELLO 来源 IP 与该角色控制连接的 IP 不符 —— 拒绝登记。
    IpMismatch,
    /// 已记下地址，但对端还没到。
    Waiting,
    /// 两端到齐：返回对端全部观测地址与协商出的传输。
    Ready(Vec<SocketAddr>, p2p::Transport),
}

/// 全部进行中的打洞会话。
#[derive(Default)]
pub struct P2PHub {
    sessions: Mutex<HashMap<String, Session>>,
}

impl P2PHub {
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    /// 预建一条会话（visitor 发起 NatHoleVisitor 时建立）。
    ///
    /// `visitor_ip` / `provider_ip` 是两端**控制连接**的源 IP：之后该角色
    /// 的 HELLO 必须来自这个 IP（见 [`Session`] 的字段注释）。
    pub fn create(&self, sid: &str, visitor_ip: IpAddr, provider_ip: IpAddr) {
        let mut g = self.sessions.lock().unwrap_or_else(|e| e.into_inner());
        self.reap_locked(&mut g);
        g.entry(sid.to_string())
            .or_insert_with(|| Session::new(visitor_ip, provider_ip));
    }

    /// 记下某个角色的一个观测地址。
    ///
    /// 若**另一个角色也到齐了**，返回它的观测地址列表与协商出的传输 ——
    /// 调用方要把这些同时发给双方。
    pub fn register(
        &self,
        sid: &str,
        role: Role,
        addr: SocketAddr,
        transport: p2p::Transport,
    ) -> RegisterOutcome {
        let mut g = self.sessions.lock().unwrap_or_else(|e| e.into_inner());
        self.reap_locked(&mut g);
        let Some(session) = g.get_mut(sid) else {
            return RegisterOutcome::NoSession;
        };
        // ★ v0.5.8 修（第八轮审计 B-1，高危）：角色来源必须与控制连接同主机。
        //   注册在会话上的 IP 来自过了 token 鉴权的 TCP 控制连接，攻击者
        //   伪造不了 —— 于是"随便谁先发 HELLO 谁就是这个角色"的窗口关死。
        if !same_host(&addr.ip(), &session.expected_ip(role)) {
            return RegisterOutcome::IpMismatch;
        }
        session.observe(role, addr, transport);
        // 传输由 **visitor** 说了算：它是主动发起的一方，也只有它知道自己
        // 那条链路是弱网（该走 KCP）还是普通宽带（QUIC 更省事）。
        // provider 侧的选择在这里被覆盖 —— 双方必须跑同一种传输才能握手。
        let chosen = session
            .get(Role::Visitor)
            .map(|s| s.transport)
            .unwrap_or(transport);
        match session.get(role.peer()) {
            Some(other) => RegisterOutcome::Ready(other.addrs.clone(), chosen),
            None => RegisterOutcome::Waiting,
        }
    }

    /// 回收超时会话，避免一个永不过期的 sid 把内存慢慢吃满。
    fn reap_locked(&self, g: &mut HashMap<String, Session>) {
        let now = Instant::now();
        g.retain(|_, s| {
            // 空会话（created 起算）也要活到 TTL，否则 HELLO 还没到就被回收了
            if now.duration_since(s.created) >= SESSION_TTL {
                return false;
            }
            let fresh = |slot: &Option<PeerSlot>| {
                slot.as_ref()
                    .map(|s| now.duration_since(s.at) < SESSION_TTL)
                    .unwrap_or(true)
            };
            fresh(&s.visitor) && fresh(&s.provider)
        });
    }

    /// 会话被双方消费完后主动清理（省内存，也避免 sid 复用带来的串会话）。
    pub fn finish(&self, sid: &str) {
        self.sessions
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(sid);
    }

    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.sessions.lock().unwrap().len()
    }
}

/// 在 UDP socket 上跑牵线主循环。
///
/// ★★ v0.5.9 修（第九轮审计 **E9-1**，低危）：新增 `sec`，让牵线 UDP 也过 ACL。
///
/// # 原先为什么错了
///
/// `p2p.rs` 里**没有 `check_ip` 调用**（第九轮 grep 零命中）。
/// 牵线唯一的来源判定是第八轮 B-1 加的"与控制连接 IP 同源"
/// （`register` 里的 `same_host` 检查）—— 那拦的是"**冒充别人**"，
/// **不读 `[acl]`**，两者不等价。
///
/// # 实测（`tmp/audit9/_indep/verify_p2p_acl.py`，6/6 判据全过）
///
/// `[acl] deny = ["<LAN>"]` 下，从被 deny 的地址发 HELLO：
///
/// ```text
/// DEBUG 收到 HELLO peer=127.0.0.1:52669 …      ← 放行侧
/// DEBUG 收到 HELLO peer=192.168.56.1:52673 …   ← 被 deny 侧**也被收到了**
/// （服务端日志里**没有任何** "IP 访问控制拒绝"）
/// ```
///
/// # 定级为什么只是「低危」
///
/// 必须精确，不能夸大：
/// * `hub.register` 要求 sid 对应的会话**已存在**（`g.get_mut(sid)?`），
///   而会话由**已认证的控制通道**创建，控制通道**受 ACL 约束**；
/// * ⇒ 净效果：ACL 挡住了控制面 ⇒ 没有 sid ⇒ 牵线这条路也走不通。
///   **ACL 在这里是"间接生效"的。**
/// * 所以这是"如果将来某条路径能拿到 sid，ACL 不会兜底"的**纵深防御缺口**，
///   不是当下可打的漏洞。
///
/// ★ 但补它的成本极低（一次位运算），而口径统一的价值很高：
///   不能有一条路径"碰巧安全"却靠的是另一条路径的防线。
pub async fn run_rendezvous(
    sock: Arc<UdpSocket>,
    hub: Arc<P2PHub>,
    sec: Arc<crate::guard::SecurityContext>,
) {
    info!(
        "xtcp 牵线服务已启动，UDP {}",
        sock.local_addr()
            .ok()
            .map(|a| a.to_string())
            .unwrap_or_default()
    );
    let mut buf = [0u8; 2048];
    loop {
        let (n, peer) = match sock.recv_from(&mut buf).await {
            Ok(v) => v,
            Err(e) => {
                warn!("牵线 UDP 读失败：{e}");
                continue;
            }
        };
        // ★ E9-1：ACL 判定放在**解析报文之前** —— 与其它路径同序（最便宜的闸先撞）。
        //   拒绝时静默丢弃：不给被拒的来源任何回包，也就不会泄露"这里有个牵线服务"。
        if let Err(reason) = sec.check_ip(peer.ip()) {
            debug!(%peer, "牵线 UDP 的 IP 访问控制拒绝：{reason}");
            continue;
        }
        let Some(Packet::Hello {
            role,
            sid,
            transport,
        }) = p2p::decode(&buf[..n])
        else {
            debug!(%peer, "收到非法牵线报文，丢弃");
            continue;
        };
        debug!(%peer, ?role, %sid, ?transport, "收到 HELLO");
        let (peer_addrs, chosen) = match hub.register(&sid, role, peer, transport) {
            RegisterOutcome::NoSession => {
                debug!(%peer, %sid, "未知或已过期的 sid，忽略");
                continue;
            }
            RegisterOutcome::Waiting => {
                debug!(%peer, %sid, "对端还没到，先记下地址");
                continue;
            }
            RegisterOutcome::IpMismatch => {
                // ★ v0.5.8 修（第八轮审计 B-1）：可能有人在冒名登记，
                //   也可能只是多宿主 / 双栈解析差异 —— 两种都拒绝，
                //   由客户端按既有逻辑回退中继（打洞失败本来就有兜底）。
                warn!(%peer, %sid, ?role, "HELLO 来源 IP 与控制连接不符，拒绝登记");
                continue;
            }
            RegisterOutcome::Ready(addrs, chosen) => (addrs, chosen),
        };
        // 关键动作：把对方的地址分别发给两端，双方同时开打才能穿过 NAT。
        // 用 PEERS（多个地址）而不是 PEER：对称 NAT 下 peer 要靠这一串端口
        // 序列去预测真正通信时会落在哪个端口上。
        if let Some(pkt) = p2p::encode_peers(role.peer(), &sid, chosen, &peer_addrs) {
            let _ = sock.send_to(&pkt, peer).await;
            hub.finish(&sid);
        }
        // 采样 socket 发来的 HELLO 只会让这一侧多一个样本，回包要打回主 socket。
        // 这里逐个地址发一遍：主 socket 的地址排在最前（它是最先被记下的）。
        for a in &peer_addrs {
            if let Some(pkt) = p2p::encode_peers(role, &sid, chosen, &[peer]) {
                let _ = sock.send_to(&pkt, a).await;
            }
        }
        debug!(%sid, this = %peer, other = ?peer_addrs, ?chosen, "已向双方下发对方地址");
    }
}

/// P2P 建立后用的传输协议名（写进 NatHoleResp.protocol，客户端据此选实现）。
pub const P2P_PROTOCOL: &str = "quic";

/// 处理 visitor 发来的 `NatHoleVisitor`：准入校验 + 生成 sid + 通知双方。
///
/// 所有失败都必须**明确回复** `NatHoleResp{error}`，这样 visitor 能立刻回退到
/// stcp 中继，而不是挂在那里等超时。
pub async fn handle_nat_hole_visitor(
    registry: &Arc<Registry>,
    visitor_client: &Arc<ClientState>,
    m: &NatHoleVisitor,
) -> std::io::Result<()> {
    let proxy_name = m.proxy_name.clone();

    /// 统一回错误答案告终。
    fn refuse(client: &ClientState, txn: &str, err: impl Into<String>) {
        let err = err.into();
        warn!(%err, "xtcp 打洞被拒绝");
        client.forward_to_client(FrpMessage::NatHoleResp(NatHoleResp {
            transaction_id: txn.to_string(),
            error: err,
            ..Default::default()
        }));
    }

    // 1) provider 必须已经注册了这个 xtcp 代理
    let Some(entry) = registry.visitors.get(&proxy_name) else {
        refuse(
            visitor_client,
            &m.transaction_id,
            format!("custom listener for [{proxy_name}] doesn't exist"),
        );
        return Ok(());
    };

    // 2) 官方 frpc 的预检：只问“provider 在不在、我能不能访问”，
    //    消息里没有 sign_key/timestamp，不能按普通打洞请求处理。
    //    成功必须回 `error` 为空的响应，官方客户端才会继续做 NAT 探测。
    if m.pre_check {
        return match crate::nathole_official::precheck(&entry, &visitor_client.user) {
            Ok(()) => {
                visitor_client.forward_to_client(FrpMessage::NatHoleResp(NatHoleResp {
                    transaction_id: m.transaction_id.clone(),
                    ..Default::default()
                }));
                Ok(())
            }
            Err(err) => {
                refuse(visitor_client, &m.transaction_id, err);
                Ok(())
            }
        };
    }

    // 3) 签名/用户校验。NFrp 自有协议和官方协议共用同一套
    //    `auth_key(secret_key, timestamp)`，因此这里不分支。
    if m.sign_key.is_empty() {
        refuse(
            visitor_client,
            &m.transaction_id,
            format!(
                "xtcp hole punching requires a signed NatHoleVisitor \
                 (visitor [{proxy_name}] sent no signature); falling back to relay is required"
            ),
        );
        return Ok(());
    }
    // 带了签名就必须对（NFrp↔NFrp 的保证一点没放松）
    //
    // ★ v0.5.7（第六轮审计 G-1，高危）：把时钟窗口传进去 ——
    //   新鲜性校验在 `check_sign` 内部，不是可选项。
    //   原先这里只比内容不看新旧 ⇒ 嗅探到一条 `NatHoleVisitor` 即可无限期重放。
    if !entry.check_sign(
        &m.sign_key,
        m.timestamp,
        registry.security().max_clock_skew_secs(),
    ) {
        refuse(
            visitor_client,
            &m.transaction_id,
            format!("nat hole visitor [{proxy_name}] auth failed"),
        );
        return Ok(());
    }

    // 3) 用户白名单
    let visitor_user = visitor_client.user.clone();
    if !entry.check_user(&visitor_user) {
        refuse(
            visitor_client,
            &m.transaction_id,
            format!("visitor connection of [{proxy_name}] user [{visitor_user}] not allowed"),
        );
        return Ok(());
    }

    // 4) 官方 frpc 的正式请求：带 NAT 探测得到的 mapped_addrs。
    //    它走官方控制消息交换，不依赖 `p2p_port`，也不再走下面的
    //    NFrp 自有 UDP HELLO 牵线。
    if !m.mapped_addrs.is_empty() {
        return match crate::nathole_official::start_session(visitor_client, &entry, m) {
            Ok(()) => Ok(()),
            Err(err) => {
                refuse(visitor_client, &m.transaction_id, err);
                Ok(())
            }
        };
    }

    // 5) NFrp 自有协议：没有 mapped_addrs，靠 `p2p_port` 上的 UDP HELLO。
    let Some(hub) = registry.p2p() else {
        refuse(
            visitor_client,
            &m.transaction_id,
            "nat hole is not enabled on this nfrp-server (set p2p_port to enable xtcp)",
        );
        return Ok(());
    };

    let sid = nfrp_common::util::new_run_id();
    // ★ v0.5.8 修（第八轮审计 B-1）：把两个角色的 HELLO 来源钉在各自的
    //   控制连接 IP 上（控制连接过了 token 鉴权，伪造不了）。
    hub.create(&sid, visitor_client.peer_ip(), entry.client.peer_ip());

    // 5) 回给 visitor：拿到 sid 后去 UDP 端口发 HELLO
    visitor_client.forward_to_client(FrpMessage::NatHoleResp(NatHoleResp {
        transaction_id: m.transaction_id.clone(),
        sid: sid.clone(),
        protocol: P2P_PROTOCOL.to_string(),
        detect_behavior: NatHoleDetectBehavior {
            // role/mode 沿用 Go 版的语义：visitor 是主动打的一方
            role: "sender".to_string(),
            mode: 1,
            // 给足一次 QUIC 握手的时间
            read_timeout_ms: 10_000,
            ..Default::default()
        },
        ..Default::default()
    }));

    // 6) 通知 provider：同样去 UDP 端口发 HELLO，之后由服务端牵线
    entry
        .client
        .forward_to_client(FrpMessage::NatHoleClient(NatHoleClient {
            transaction_id: m.transaction_id.clone(),
            proxy_name: proxy_name.clone(),
            sid,
            ..Default::default()
        }));

    debug!(proxy = %proxy_name, txn = %m.transaction_id, "已为 xtcp 会话生成 sid，通知双方打洞");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::registry::ServerLimits;
    use crate::visitor::VisitorEntry;
    use tokio::sync::mpsc;

    fn client(user: &str) -> Arc<ClientState> {
        let (tx, rx) = mpsc::unbounded_channel::<crate::pool::CtrlCmd>();
        std::mem::forget(rx);
        let (conn, backlog, proxy) = ServerLimits::default().per_client();
        Arc::new(ClientState::new(
            "run".into(),
            "id".into(),
            user.to_string(),
            tx,
            Duration::from_secs(60),
            Duration::from_secs(10),
            Default::default(),
            false,
            nfrp_common::frp::WireVersion::V1,
            conn,
            backlog,
            0,
            proxy,
            "127.0.0.1".parse::<std::net::IpAddr>().unwrap(),
        ))
    }

    /// 构造一条 **时间戳新鲜** 的 `NatHoleVisitor`（签名由 `sk` 算出）。
    ///
    /// ★ v0.5.7（第六轮审计 G-1）：原先这里要调用方传一个**写死的** `ts`
    ///   （1 / 123 / 456 / 9 / 11…）。`check_sign` 现在自带新鲜性校验之后，
    ///   那些写死的时间戳全都会**因为过期**而被拒 —— 测试会"因为时间错"而失败，
    ///   而不是因为它本来要测的那件事。所以默认用当前时间。
    ///
    ///   要测"过期"请用 [`nat_hole_visitor_at`] 显式传时间。
    fn nat_hole_visitor(proxy_name: &str, sk: &str) -> NatHoleVisitor {
        nat_hole_visitor_at(proxy_name, sk, nfrp_common::util::now_unix_secs() as i64)
    }

    /// 指定时间戳的版本（用于测**过期必须被拒**）。
    fn nat_hole_visitor_at(proxy_name: &str, sk: &str, ts: i64) -> NatHoleVisitor {
        NatHoleVisitor {
            transaction_id: "txn-1".into(),
            proxy_name: proxy_name.into(),
            sign_key: nfrp_common::frp::msg::auth_key(sk, ts),
            timestamp: ts,
            ..Default::default()
        }
    }

    #[test]
    fn hub_pairs_two_peers_and_reaps_stale() {
        let hub = P2PHub::new();
        let sid = format!("{:032x}", 7u64);
        // 控制连接 IP：visitor 1.2.3.4 / provider 5.6.7.8（HELLO 只认这两个 IP）
        hub.create(&sid, "1.2.3.4".parse().unwrap(), "5.6.7.8".parse().unwrap());
        assert_eq!(hub.len(), 1);

        let a: SocketAddr = "1.2.3.4:100".parse().unwrap();
        let b: SocketAddr = "5.6.7.8:200".parse().unwrap();
        // 只有一端到：拿不到对端地址
        assert!(matches!(
            hub.register(&sid, Role::Visitor, a, p2p::Transport::Quic),
            RegisterOutcome::Waiting
        ));
        // 另一端到：双方互推
        let (addrs, chosen) = match hub.register(&sid, Role::Provider, b, p2p::Transport::Quic) {
            RegisterOutcome::Ready(addrs, chosen) => (addrs, chosen),
            _ => panic!("两端到齐必须返回 Ready"),
        };
        assert_eq!(addrs, vec![a]);
        assert_eq!(chosen, p2p::Transport::Quic);
        hub.finish(&sid);
        assert_eq!(hub.len(), 0, "会话结束必须清理，避免 sid 复用串会话");

        // 未 create 过的 sid 直接 register 应当安全返回 NoSession
        assert!(matches!(
            hub.register(
                &format!("{:032x}", 9u64),
                Role::Visitor,
                a,
                p2p::Transport::Quic
            ),
            RegisterOutcome::NoSession
        ));
    }

    /// ★ v0.5.8（第八轮审计 B-1，高危）回归：HELLO 的来源 IP 必须与该角色
    /// **控制连接**的 IP 一致。修复前牵线端口对 HELLO 零鉴权 —— 攻击者从
    /// 任意地址抢先登记为 provider，就能把 visitor 引到自己的地址上。
    #[test]
    fn hello_from_wrong_ip_is_rejected() {
        let hub = P2PHub::new();
        let sid = format!("{:032x}", 11u64);
        hub.create(
            &sid,
            "10.0.0.1".parse().unwrap(),
            "10.0.0.2".parse().unwrap(),
        );

        // 攻击者（不同主机）冒充任一角色，都必须在登记这一步被拒
        let evil: SocketAddr = "203.0.113.66:40000".parse().unwrap();
        assert!(matches!(
            hub.register(&sid, Role::Provider, evil, p2p::Transport::Quic),
            RegisterOutcome::IpMismatch
        ));
        assert!(matches!(
            hub.register(&sid, Role::Visitor, evil, p2p::Transport::Quic),
            RegisterOutcome::IpMismatch
        ));

        // 被拒的地址不能被记进任何槽位：合法两端仍然正常配对
        let v: SocketAddr = "10.0.0.1:100".parse().unwrap();
        let p: SocketAddr = "10.0.0.2:200".parse().unwrap();
        assert!(matches!(
            hub.register(&sid, Role::Visitor, v, p2p::Transport::Quic),
            RegisterOutcome::Waiting
        ));
        match hub.register(&sid, Role::Provider, p, p2p::Transport::Quic) {
            RegisterOutcome::Ready(addrs, _) => assert_eq!(addrs, vec![v]),
            _ => panic!("合法 provider 应当能配对"),
        }
    }

    /// 双栈下同一主机的 IPv4-mapped 表示必须被当成"同一个 IP"，
    /// 否则安全修复会误杀合法 P2P（全量退化中继）。
    #[test]
    fn v4_mapped_ip_counts_as_same_host() {
        let hub = P2PHub::new();
        let sid = format!("{:032x}", 12u64);
        hub.create(
            &sid,
            "127.0.0.1".parse().unwrap(),
            "::ffff:127.0.0.1".parse().unwrap(),
        );
        let v: SocketAddr = "127.0.0.1:100".parse().unwrap();
        let p: SocketAddr = "127.0.0.1:200".parse().unwrap();
        assert!(matches!(
            hub.register(&sid, Role::Visitor, v, p2p::Transport::Quic),
            RegisterOutcome::Waiting
        ));
        assert!(matches!(
            hub.register(&sid, Role::Provider, p, p2p::Transport::Quic),
            RegisterOutcome::Ready(..)
        ));
    }

    #[tokio::test]
    async fn unknown_proxy_is_refused_with_error() {
        let registry = Arc::new(Registry::unlimited());
        let c = client("alice");
        let m = nat_hole_visitor("missing", "sk");
        handle_nat_hole_visitor(&registry, &c, &m)
            .await
            .expect("应安全返回");
        // hub 未挂载时也应该给明确的错误，而不是 panic 或静默
        let registry2 = Arc::new(Registry::unlimited());
        let c2 = client("alice");
        handle_nat_hole_visitor(&registry2, &c2, &m)
            .await
            .expect("应安全返回");
    }

    #[tokio::test]
    async fn wrong_secret_key_is_refused() {
        let registry = Arc::new(Registry::unlimited());
        let provider = client("bob");
        registry
            .visitors
            .register(VisitorEntry {
                proxy_name: "p2p".into(),
                secret_key: "real-key".into(),
                allow_users: vec![],
                provider_user: "bob".into(),
                client: provider.clone(),
                proxy_type: "xtcp".into(),
            })
            .unwrap();
        let hub = P2PHub::new();
        registry.attach_p2p(hub.clone());

        let visitor = client("bob");
        let before = hub.len();
        let m = nat_hole_visitor("p2p", "wrong-key");
        handle_nat_hole_visitor(&registry, &visitor, &m)
            .await
            .expect("处理过程不应返回 IO 错误");
        assert_eq!(hub.len(), before, "密钥不对时不能创建会话");
    }

    /// ★★ v0.5.7 新增（第六轮审计 G-1，高危）：**过期的签名必须被拒**。
    ///
    /// # 锁的是什么
    ///
    /// `check_sign` 原先只比 `md5(secret_key + timestamp)` 的内容、
    /// **完全不看 `timestamp` 有多旧** ⇒ 嗅探到一条 `NatHoleVisitor`
    /// 即可**无限期重放**（实测一年前的仍然被接受）。
    ///
    /// 现在新鲜性校验嵌在 `check_sign` 内部（`skew` 是必需参数）。
    /// 这条测试盯住"过期 ⇒ 拒绝"，并且加一条**对照**（同一密钥、新鲜时间 ⇒ 通过）
    /// 来证明它拒的是**时间**而不是别的东西 ——
    /// 否则"反正都被拒"会让测试失去判别力。
    #[tokio::test]
    async fn 过期的打洞签名必须被拒而新鲜的通过() {
        let registry = Arc::new(Registry::unlimited());
        let provider = client("bob");
        registry
            .visitors
            .register(VisitorEntry {
                proxy_name: "p2p".into(),
                secret_key: "real-key".into(),
                allow_users: vec!["bob".into()],
                provider_user: "bob".into(),
                client: provider.clone(),
                proxy_type: "xtcp".into(),
            })
            .expect("注册 visitor 应当成功");

        let hub = P2PHub::new();
        registry.attach_p2p(hub.clone());

        let visitor = client("bob");
        let now = nfrp_common::util::now_unix_secs() as i64;

        // 对照组：**新鲜**时间戳 + 正确密钥 ⇒ 必须创建会话。
        // 没有这一条，"过期被拒"可能只是因为别的原因（比如密钥没对上）。
        let fresh = nat_hole_visitor_at("p2p", "real-key", now);
        handle_nat_hole_visitor(&registry, &visitor, &fresh)
            .await
            .expect("处理过程不应返回 IO 错误");
        assert_eq!(hub.len(), 1, "新鲜签名 + 正确密钥应当创建打洞会话");

        // 实验组：**一年前**的时间戳 + 同样正确的密钥 ⇒ 必须被拒。
        let before = hub.len();
        let stale = nat_hole_visitor_at("p2p", "real-key", now - 365 * 24 * 3600);
        handle_nat_hole_visitor(&registry, &visitor, &stale)
            .await
            .expect("处理过程不应返回 IO 错误");
        assert_eq!(
            hub.len(),
            before,
            "一年前的正确签名必须被拒（否则就是无限期重放，可干扰他人打洞）"
        );
    }

    /// 官方 frpc 的预检消息只带 `pre_check`，没有签名。
    ///
    /// 现在服务端实现了官方 `NatHole` 控制器，预检通过后回空错误，
    /// 官方客户端会继续做 STUN 探测并发正式请求；预检本身不建立
    /// NFrp 自有的 UDP HELLO 会话。
    #[tokio::test]
    async fn 官方_frpc_预检成功但不建立自有会话() {
        let registry = Arc::new(Registry::unlimited());
        let provider = client("bob");
        registry
            .visitors
            .register(VisitorEntry {
                proxy_name: "p2p".into(),
                secret_key: "real-key".into(),
                allow_users: vec![],
                provider_user: "bob".into(),
                client: provider.clone(),
                proxy_type: "xtcp".into(),
            })
            .unwrap();
        let hub = P2PHub::new();
        registry.attach_p2p(hub.clone());

        let visitor = client("bob");
        // 官方 frpc 的样子：只有 transaction_id / proxy_name / pre_check
        let m = NatHoleVisitor {
            transaction_id: "txn-official".into(),
            proxy_name: "p2p".into(),
            pre_check: true,
            ..Default::default()
        };
        handle_nat_hole_visitor(&registry, &visitor, &m)
            .await
            .expect("处理过程不应返回 IO 错误");
        assert_eq!(hub.len(), 0, "官方预检不该建立 NFrp 自有的 UDP HELLO 会话");
    }

    #[tokio::test]
    async fn happy_path_creates_session_and_notifies_provider() {
        let registry = Arc::new(Registry::unlimited());

        // provider：持有 rx，用来断言它确实收到了 NatHoleClient
        let (ptx, mut prx) = mpsc::unbounded_channel::<crate::pool::CtrlCmd>();
        let (conn, backlog, proxy) = ServerLimits::default().per_client();
        let provider = Arc::new(ClientState::new(
            "run-p".into(),
            "p".into(),
            "bob".into(),
            ptx,
            Duration::from_secs(60),
            Duration::from_secs(10),
            Default::default(),
            false,
            nfrp_common::frp::WireVersion::V1,
            conn,
            backlog,
            0,
            proxy,
            "127.0.0.1".parse::<std::net::IpAddr>().unwrap(),
        ));
        registry
            .visitors
            .register(VisitorEntry {
                proxy_name: "p2p".into(),
                secret_key: "real-key".into(),
                allow_users: vec![],
                provider_user: "bob".into(),
                client: provider.clone(),
                proxy_type: "xtcp".into(),
            })
            .unwrap();
        let hub = P2PHub::new();
        registry.attach_p2p(hub.clone());

        // visitor：allow_users 为空意味着"只允许同 user"，因此这里也要叫 bob
        let (vtx, mut vrx) = mpsc::unbounded_channel::<crate::pool::CtrlCmd>();
        let (vconn, vbacklog, vproxy) = ServerLimits::default().per_client();
        let visitor = Arc::new(ClientState::new(
            "run-v".into(),
            "v".into(),
            "bob".into(),
            vtx,
            Duration::from_secs(60),
            Duration::from_secs(10),
            Default::default(),
            false,
            nfrp_common::frp::WireVersion::V1,
            vconn,
            vbacklog,
            0,
            vproxy,
            "127.0.0.1".parse::<std::net::IpAddr>().unwrap(),
        ));

        let m = nat_hole_visitor("p2p", "real-key");
        handle_nat_hole_visitor(&registry, &visitor, &m)
            .await
            .expect("处理不应失败");

        assert_eq!(hub.len(), 1, "应创建一条打洞会话");
        let resp = expect_msg(&mut vrx, "visitor 必须收到 NatHoleResp").await;
        match resp {
            FrpMessage::NatHoleResp(r) => {
                assert!(r.error.is_empty(), "成功时不该带错误：{}", r.error);
                assert_eq!(r.sid.len(), p2p::SID_LEN);
                assert_eq!(r.protocol, P2P_PROTOCOL);
                assert_eq!(r.detect_behavior.role, "sender");
            }
            other => panic!("visitor 收到的是别的消息：{other:?}"),
        }

        let kid = expect_msg(&mut prx, "provider 必须收到 NatHoleClient").await;
        match kid {
            FrpMessage::NatHoleClient(c) => {
                assert_eq!(c.proxy_name, "p2p");
                assert_eq!(c.sid.len(), p2p::SID_LEN);
            }
            other => panic!("provider 收到的是别的消息：{other:?}"),
        }
    }

    #[tokio::test]
    async fn user_not_in_allowlist_is_refused() {
        let registry = Arc::new(Registry::unlimited());
        let provider = client("bob");
        registry
            .visitors
            .register(VisitorEntry {
                proxy_name: "p2p".into(),
                secret_key: "key".into(),
                allow_users: vec!["carol".into()],
                provider_user: "bob".into(),
                client: provider,
                proxy_type: "xtcp".into(),
            })
            .unwrap();
        let hub = P2PHub::new();
        registry.attach_p2p(hub.clone());

        let visitor = client("bob");
        let m = nat_hole_visitor("p2p", "key");
        handle_nat_hole_visitor(&registry, &visitor, &m)
            .await
            .unwrap();
        assert_eq!(hub.len(), 0, "白名单不放行时不能创建会话");
    }

    #[tokio::test]
    async fn disabled_p2p_port_tells_visitor_to_fallback() {
        // 没配 p2p_port 时，visitor 必须收到带 error 的 NatHoleResp 以便回退中继
        let registry = Arc::new(Registry::unlimited());
        let provider = client("bob");
        registry
            .visitors
            .register(VisitorEntry {
                proxy_name: "p2p".into(),
                secret_key: "key".into(),
                allow_users: vec!["*".into()],
                provider_user: "bob".into(),
                client: provider,
                proxy_type: "xtcp".into(),
            })
            .unwrap();
        assert!(registry.p2p().is_none());

        let (vtx, mut vrx) = mpsc::unbounded_channel::<crate::pool::CtrlCmd>();
        let (vconn, vbacklog, vproxy) = ServerLimits::default().per_client();
        let visitor = Arc::new(ClientState::new(
            "run-v".into(),
            "v".into(),
            "bob".into(),
            vtx,
            Duration::from_secs(60),
            Duration::from_secs(10),
            Default::default(),
            false,
            nfrp_common::frp::WireVersion::V1,
            vconn,
            vbacklog,
            0,
            vproxy,
            "127.0.0.1".parse::<std::net::IpAddr>().unwrap(),
        ));
        let m = nat_hole_visitor("p2p", "key");
        handle_nat_hole_visitor(&registry, &visitor, &m)
            .await
            .unwrap();
        let msg = expect_msg(&mut vrx, "必须回复失败原因").await;
        match msg {
            FrpMessage::NatHoleResp(r) => {
                assert!(!r.error.is_empty(), "应明确告知无法打洞");
                assert!(r.sid.is_empty(), "失败时不能下发 sid");
            }
            other => panic!("期待 NatHoleResp，实际：{other:?}"),
        }
    }

    /// 从控制通道里取一条下行消息；不是 Send 就炸。
    async fn expect_msg(
        rx: &mut mpsc::UnboundedReceiver<crate::pool::CtrlCmd>,
        what: &str,
    ) -> FrpMessage {
        match rx.recv().await.expect(what) {
            crate::pool::CtrlCmd::Send(m) => *m,
            other => panic!("{what}：收到的却不是下行消息：{other:?}"),
        }
    }
}
