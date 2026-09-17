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

use rustunnel_common::{
    frp::msg::{FrpMessage, NatHoleClient, NatHoleDetectBehavior, NatHoleResp, NatHoleVisitor},
    p2p::{self, Packet, Role},
};
use tokio::net::UdpSocket;
use tracing::{debug, info, warn};

use crate::{pool::ClientState, registry::Registry};

/// 一条会话从创建到过期的时间：足够双方完成一次 HELLO + QUIC 握手。
const SESSION_TTL: Duration = Duration::from_secs(60);

/// 一次打洞会话里两个 peer 的公网地址。
struct Session {
    /// 会话创建时间：刚 create 出来、两端都还没到的时候全靠它保命。
    created: Instant,
    visitor: Option<(SocketAddr, Instant)>,
    provider: Option<(SocketAddr, Instant)>,
}

impl Session {
    fn new() -> Self {
        Self {
            created: Instant::now(),
            visitor: None,
            provider: None,
        }
    }
}

impl Session {
    fn slot_mut(&mut self, role: Role) -> &mut Option<(SocketAddr, Instant)> {
        match role {
            Role::Visitor => &mut self.visitor,
            Role::Provider => &mut self.provider,
        }
    }

    fn get(&self, role: Role) -> Option<SocketAddr> {
        match role {
            Role::Visitor => self.visitor.as_ref().map(|(a, _)| *a),
            Role::Provider => self.provider.as_ref().map(|(a, _)| *a),
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
        let mut g = self.sessions.lock().unwrap();
        self.reap_locked(&mut g);
        g.entry(sid.to_string()).or_insert_with(Session::new);
    }

    /// 记下某个角色的公网地址。
    ///
    /// 若**另一个角色也到齐了**，返回它的地址 —— 调用方要把这个地址同时发给双方。
    pub fn register(&self, sid: &str, role: Role, addr: SocketAddr) -> Option<SocketAddr> {
        let mut g = self.sessions.lock().unwrap();
        self.reap_locked(&mut g);
        let session = g.get_mut(sid)?;
        *session.slot_mut(role) = Some((addr, Instant::now()));
        session.get(role.peer())
    }

    /// 回收超时会话，避免一个永不过期的 sid 把内存慢慢吃满。
    fn reap_locked(&self, g: &mut HashMap<String, Session>) {
        let now = Instant::now();
        g.retain(|_, s| {
            // 空会话（created 起算）也要活到 TTL，否则 HELLO 还没到就被回收了
            if now.duration_since(s.created) >= SESSION_TTL {
                return false;
            }
            let fresh = |slot: &Option<(SocketAddr, Instant)>| {
                slot.map(|(_, at)| now.duration_since(at) < SESSION_TTL)
                    .unwrap_or(true)
            };
            fresh(&s.visitor) && fresh(&s.provider)
        });
    }

    /// 会话被双方消费完后主动清理（省内存，也避免 sid 复用带来的串tracking）。
    pub fn finish(&self, sid: &str) {
        self.sessions.lock().unwrap().remove(sid);
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
        let Some(Packet::Hello { role, sid }) = p2p::decode(&buf[..n]) else {
            debug!(%peer, "收到非法牵线报文，丢弃");
            continue;
        };
        debug!(%peer, ?role, %sid, "收到 HELLO");
        let Some(peer_addr) = hub.register(&sid, role, peer) else {
            debug!(%peer, %sid, "对端还没到，先记下地址");
            continue;
        };
        // 关键动作：把对方的地址分别发给两端，双方同时开打才能穿过 NAT
        if let Some(pkt) = p2p::encode_peer(role.peer(), &sid, &peer_addr) {
            let _ = sock.send_to(&pkt, peer).await;
        }
        if let Some(pkt) = p2p::encode_peer(role, &sid, &peer) {
            let _ = sock.send_to(&pkt, peer_addr).await;
        }
        debug!(%sid, this = %peer, other = %peer_addr, "已向双方下发对方地址");
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

    // 2) 密钥校验（与 stcp 完全一致：hex(md5(secret_key + timestamp))）
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
            "nat hole is not enabled on this rustunnel-server (set p2p_port to enable xtcp)",
        );
        return Ok(());
    };

    let sid = rustunnel_common::util::new_run_id();
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
            false,
            rustunnel_common::frp::WireVersion::V1,
            conn,
            backlog,
            proxy,
        ))
    }

    fn nat_hole_visitor(proxy_name: &str, sk: &str, ts: i64) -> NatHoleVisitor {
        NatHoleVisitor {
            transaction_id: "txn-1".into(),
            proxy_name: proxy_name.into(),
            sign_key: rustunnel_common::frp::msg::auth_key(sk, ts),
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
        assert!(hub.register(&sid, Role::Visitor, a).is_none());
        // 另一端到：双方互推
        assert_eq!(hub.register(&sid, Role::Provider, b), Some(a));
        hub.finish(&sid);
        assert_eq!(hub.len(), 0, "会话结束必须清理，避免 sid 复用串会话");

        // 未 create 过的 sid 直接 register 应当安全返回 None
        assert!(hub
            .register(&format!("{:032x}", 9u64), Role::Visitor, a)
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
            false,
            rustunnel_common::frp::WireVersion::V1,
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
            false,
            rustunnel_common::frp::WireVersion::V1,
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
            false,
            rustunnel_common::frp::WireVersion::V1,
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
