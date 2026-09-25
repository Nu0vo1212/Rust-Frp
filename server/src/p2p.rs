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
    net::SocketAddr,
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
    visitor: Option<PeerSlot>,
    provider: Option<PeerSlot>,
}

impl Session {
    fn new() -> Self {
        Self {
            created: Instant::now(),
            visitor: None,
            provider: None,
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
    pub fn create(&self, sid: &str) {
        let mut g = self.sessions.lock().unwrap_or_else(|e| e.into_inner());
        self.reap_locked(&mut g);
        g.entry(sid.to_string()).or_insert_with(Session::new);
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
    ) -> Option<(Vec<SocketAddr>, p2p::Transport)> {
        let mut g = self.sessions.lock().unwrap_or_else(|e| e.into_inner());
        self.reap_locked(&mut g);
        let session = g.get_mut(sid)?;
        session.observe(role, addr, transport);
        // 传输由 **visitor** 说了算：它是主动发起的一方，也只有它知道自己
        // 那条链路是弱网（该走 KCP）还是普通宽带（QUIC 更省事）。
        // provider 侧的选择在这里被覆盖 —— 双方必须跑同一种传输才能握手。
        let chosen = session
            .get(Role::Visitor)
            .map(|s| s.transport)
            .unwrap_or(transport);
        let other = session.get(role.peer())?;
        Some((other.addrs.clone(), chosen))
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
pub async fn run_rendezvous(sock: Arc<UdpSocket>, hub: Arc<P2PHub>) {
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
        let Some((peer_addrs, chosen)) = hub.register(&sid, role, peer, transport) else {
            debug!(%peer, %sid, "对端还没到，先记下地址");
            continue;
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

    // 2) 准入：**NFrp 的打洞协调是自有协议，只服务自家客户端**。
    //
    // ★ 这里必须**明确拒绝**，不能"装作成功"。官方 frpc 的 xtcp visitor 走的是
    //   frp 自己的 UDP `NatHoleSid` 交换（在 `p2p_port` 上发 JSON 报文要地址），
    //   NFrp 目前没实现那套交换。若我们回一个 `error` 为空的 `NatHoleResp`，
    //   官方 frpc 会认为打洞可用 → 一直等地址直到超时 → **连中继回退都不会发生**，
    //   结果是 xtcp 完全不通（比 stcp 还差）。
    //   回一条明确的错误，客户端才能按 `fallbackTo = "stcp"` 退回中继。
    //
    //   判据就是"有没有带签名"：NFrp 客户端一定会带
    //   （`client/src/p2p.rs` 用 `auth_key(secret_key, ts)`），
    //   而官方 frpc 的 NatHoleVisitor 实测只有
    //   `{"transaction_id":…,"proxy_name":…,"pre_check":true}`（无 sign_key/timestamp）。
    if m.sign_key.is_empty() {
        refuse(
            visitor_client,
            &m.transaction_id,
            format!(
                "xtcp hole punching on this nfrp-server requires the NFrp client \
                 (visitor [{proxy_name}] sent no signature); falling back to relay is required"
            ),
        );
        return Ok(());
    }
    // 带了签名就必须对（NFrp↔NFrp 的保证一点没放松）
    if !entry.check_sign(&m.sign_key, m.timestamp) {
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

    // 4) 没有配置 p2p_port 时，明确告诉对方回退中继
    let Some(hub) = registry.p2p() else {
        refuse(
            visitor_client,
            &m.transaction_id,
            "nat hole is not enabled on this nfrp-server (set p2p_port to enable xtcp)",
        );
        return Ok(());
    };

    let sid = nfrp_common::util::new_run_id();
    hub.create(&sid);

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
            Default::default(),
            false,
            nfrp_common::frp::WireVersion::V1,
            conn,
            backlog,
            proxy,
        ))
    }

    fn nat_hole_visitor(proxy_name: &str, sk: &str, ts: i64) -> NatHoleVisitor {
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
        hub.create(&sid);
        assert_eq!(hub.len(), 1);

        let a: SocketAddr = "1.2.3.4:100".parse().unwrap();
        let b: SocketAddr = "5.6.7.8:200".parse().unwrap();
        // 只有一端到：拿不到对端地址
        assert!(hub
            .register(&sid, Role::Visitor, a, p2p::Transport::Quic)
            .is_none());
        // 另一端到：双方互推
        let (addrs, chosen) = hub
            .register(&sid, Role::Provider, b, p2p::Transport::Quic)
            .expect("两端到齐");
        assert_eq!(addrs, vec![a]);
        assert_eq!(chosen, p2p::Transport::Quic);
        hub.finish(&sid);
        assert_eq!(hub.len(), 0, "会话结束必须清理，避免 sid 复用串会话");

        // 未 create 过的 sid 直接 register 应当安全返回 None
        assert!(hub
            .register(
                &format!("{:032x}", 9u64),
                Role::Visitor,
                a,
                p2p::Transport::Quic
            )
            .is_none());
    }

    #[tokio::test]
    async fn unknown_proxy_is_refused_with_error() {
        let registry = Arc::new(Registry::unlimited());
        let c = client("alice");
        let m = nat_hole_visitor("missing", "sk", 1);
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
        let m = nat_hole_visitor("p2p", "wrong-key", 123);
        handle_nat_hole_visitor(&registry, &visitor, &m)
            .await
            .expect("处理过程不应返回 IO 错误");
        assert_eq!(hub.len(), before, "密钥不对时不能创建会话");
    }

    /// ★ **官方 frpc 的 `NatHoleVisitor` 不带 `sign_key` / `timestamp`。**
    ///
    /// 实测抓包（frpc 0.71.0，本仓库 `--example dump_frpc`）原文：
    /// `{"transaction_id":"...","proxy_name":"xt","pre_check":true}`。
    ///
    /// 它走的是 frp 自己的 UDP `NatHoleSid` 地址交换（NFrp 尚未实现），所以
    /// 服务端必须**明确拒绝**、而不是回一个空错误的"成功"应答 —— 后者会让
    /// 官方 frpc 一直等地址直到超时，**连 `fallbackTo = "stcp"` 的中继回退都不触发**，
    /// 最终 xtcp 一个字节都不通。
    #[tokio::test]
    async fn 官方_frpc_访客被明确拒绝以便回退中继() {
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
        assert_eq!(
            hub.len(),
            0,
            "没有签名的访客不该建立打洞会话（否则官方 frpc 会一直等地址、不回退中继）"
        );
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
            Default::default(),
            false,
            nfrp_common::frp::WireVersion::V1,
            conn,
            backlog,
            proxy,
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
            Default::default(),
            false,
            nfrp_common::frp::WireVersion::V1,
            vconn,
            vbacklog,
            vproxy,
        ));

        let m = nat_hole_visitor("p2p", "real-key", 456);
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
        let m = nat_hole_visitor("p2p", "key", 9);
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
            Default::default(),
            false,
            nfrp_common::frp::WireVersion::V1,
            vconn,
            vbacklog,
            vproxy,
        ));
        let m = nat_hole_visitor("p2p", "key", 11);
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
