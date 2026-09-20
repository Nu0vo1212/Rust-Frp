//! 工作连接池与「用户连接 <-> 工作连接」配对。
//!
//! frp 的模型是：**用户连接**在服务端等着，**工作连接**由 frpc 主动建过来，
//! 两者在服务端配对后开始双向转发原始字节。
//! 这个模块只负责两者的排队 / 配对 / 超时回收，不含任何读写 socket 的代码，
//! 因此可以脱离网络做纯内存单元测试。

use std::{
    collections::{HashMap, VecDeque},
    net::SocketAddr,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
    time::{Duration, Instant},
};

use rustunnel_common::frp::{
    conn::FrpConn,
    msg::{FrpMessage, RustunnelCaps},
    stream::BoxStream,
    WireVersion,
};
use tokio::sync::mpsc;

use crate::limits::{Limit, Permit};

/// 发给控制连接所在 task 的命令。
///
/// 控制连接只有一处（`handle_control` 的 select 循环），其他路径
/// （tcp 监听器、xtcp 打洞协调）要往客户端发消息都得走这条通道。
#[derive(Debug)]
pub enum CtrlCmd {
    /// 索要一条工作连接。
    RequestWork,
    /// 把这条消息原样发给客户端。
    ///
    /// 装箱是因为 `FrpMessage` 有几十个变体，裸放在这里会把整个枚举撑到几百字节；
    /// 而绝大多数命令都是只有 1 字节语义的 `RequestWork`。
    Send(Box<FrpMessage>),
    /// 面板下发管理命令，并等客户端的回执。
    ///
    /// `ack` 拿到的是客户端**自己报的**结果（成功 / 为什么失败），
    /// 服务端据此决定要不要把刚开的资源收回去。
    /// 另一端被 drop（比如控制连接断了）时 `ack` 会返回 Err，
    /// 调用方据此把这次操作判为失败。
    ServerCmd {
        cmd: Box<rustunnel_common::frp::msg::ServerCmd>,
        ack: tokio::sync::oneshot::Sender<Result<(), String>>,
    },
}

/// 一条已握手完成、等待分配代理的工作连接。
pub struct WorkItem {
    pub conn: FrpConn,
    pub at: Instant,
}

/// 一个已经连进来、等待工作连接的用户连接。
///
/// `stream` 可能是：
/// * 公网端口上进来的 TCP（tcp / udp / http / https 走这条）；
/// * visitor 连接（stcp / xtcp）：握手完成后它本身就是裸字节通道。
pub struct PendingUser {
    pub proxy: String,
    pub remote_port: u16,
    pub stream: BoxStream,
    pub peer: SocketAddr,
    pub at: Instant,
    /// 这条转发所占用的配额（全局 + 单客户端两种），连接结束时随 PendingUser drop 归还。
    pub slot: Option<ConnSlot>,
    /// 排队等待工作连接时持有的队列配额。
    pub queue_permit: Option<Permit>,
    /// group 负载均衡用的"在途连接数"计数。
    ///
    /// 与 `slot` 一样靠 drop 归还：只要这条 PendingUser 还在，
    /// 它选中的那个后端就被记着一条在途连接，下一轮 `pick` 会据此让路。
    pub load: Option<crate::registry::LoadGuard>,
}

/// 一条转发连接同时占用的两档配额。
///
/// 必须**同时**拿不到才允许转发：只限全局会让一个客户端吃满；
/// 只限单客户端会让十个客户端各跑一千条把机器压垮。
/// 这两个字段只读代理/Object 不完全 参与任何计算 —— 它们的存在本身就是目的：
/// 只要 ConnSlot 还活着，配额就还在手上，drop 时自动归还。
#[derive(Default)]
pub struct ConnSlot {
    #[allow(dead_code)]
    global: Option<Permit>,
    #[allow(dead_code)]
    client: Option<Permit>,
}

impl ConnSlot {
    /// 同时领一个上限各自的名额；任一边满了都算拿不到（此时另一个必须归还）。
    pub fn acquire(global_limit: &Limit, client: &ClientState) -> Option<Self> {
        let global = global_limit.try_acquire()?;
        match client.try_acquire_conn() {
            Some(client) => Some(Self {
                global: Some(global),
                client: Some(client),
            }),
            None => {
                // 关键：别把 global 令牌吞掉，否则会永久泄漏一个全局名额
                drop(global);
                None
            }
        }
    }
}

/// 一个已登记的代理：占住的名额 + 它使用的公网端口。
///
/// 这里**不**持有监听器句柄 —— `tcp` / `udp` 的监听器归端口所有，
/// 由 [`crate::registry::Registry`] 托管（见 `PortGroup::handle`）。
/// 组内成员各自掉线时只需把自己从端口上摘掉，端口本身继续服务其他成员。
struct ProxyEntry {
    /// 只在 drop 时起作用：代理存在期间名额被占，注销时自动归还。
    #[allow(dead_code)]
    slot: Permit,
    /// 占用的公网端口；`http` / `https` / `stcp` / `xtcp` 这类没有公网端口的为 `None`。
    port: Option<u16>,
}

/// 一对已经配对成功的（用户连接，工作连接）。
pub struct PairedBox {
    pub user: PendingUser,
    pub work: WorkItem,
}

/// 投递用户连接的结果。
pub enum Submit {
    /// 池里正好有空闲工作连接，可以立刻开始转发。
    Paired(Box<PairedBox>),
    /// 已入队等工作连接；调用方需要据此向客户端索要新连接。
    Queued,
    /// 待处理队列已满，必须立刻拒绝这条连接。
    Full(PendingUser),
}

#[derive(Default)]
struct PoolState {
    work: VecDeque<WorkItem>,
    users: VecDeque<PendingUser>,
}

impl PoolState {
    /// 丢弃超时的空闲工作连接与排队用户，避免半开连接无限堆积。
    fn reap(&mut self, timeout: Duration) {
        let now = Instant::now();
        while self
            .work
            .front()
            .map(|w| now.duration_since(w.at) > timeout)
            .unwrap_or(false)
        {
            self.work.pop_front();
        }
        while self
            .users
            .front()
            .map(|u| now.duration_since(u.at) > timeout)
            .unwrap_or(false)
        {
            self.users.pop_front();
        }
    }

    fn backlog(&self) -> usize {
        self.users.len()
    }
}

/// 一个已登录客户端的全部状态。
pub struct ClientState {
    pub run_id: String,
    pub client_id: String,
    /// 客户端在 Login 里声明的用户名，用于 stcp/xtcp 的 `allow_users` 白名单匹配。
    pub user: String,
    /// 代理监听器用它通知控制连接"需要一条工作连接"，或者转发一条下行消息。
    req_tx: mpsc::UnboundedSender<CtrlCmd>,
    pool: Mutex<PoolState>,
    /// 已登记的代理（占住的名额 + 占用的端口）。
    ///
    /// 名额必须**活着**：代理一注销就 drop，名额才真正回到池子里。
    /// 同理端口也要记着，客户端主动 `CloseProxy` 时才知道该归还哪一个。
    proxies: Mutex<HashMap<String, ProxyEntry>>,
    /// 本会话**协商成功**的 rustunnel 私有能力（见 [`RustunnelCaps`]）。
    ///
    /// 只有这里为真，服务端才可以往这个客户端发管理命令。
    /// 官方 frpc 不会声明能力，所以永远是全关。
    caps: RustunnelCaps,
    /// 本次会话协商出的 UDP 报文编码（true = 二进制），工作连接要跟着用。
    ///
    /// 只有 **v2** 才有这套协商；v1 永远是 JSON。
    udp_binary: bool,
    /// 本控制会话用的线协议。工作连接必须与之一致（与官方 frps 的
    /// `work connection wire protocol mismatch` 检查对齐）。
    wire_version: WireVersion,
    /// 有新工作连接入池 / 代理被停止时唤醒等待者（UDP 与 HTTP 都要主动取工作连接）。
    work_notify: tokio::sync::Notify,
    stopped: AtomicBool,
    idle_timeout: Duration,
    /// 本客户端的同时活跃转发连接上限。
    conn_limit: Limit,
    /// 本客户端的排队上限（用户连接排着等工作连接）。
    backlog_limit: Limit,
    /// 本客户端可注册的代理数上限。
    proxy_limit: Limit,
}

impl ClientState {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        run_id: String,
        client_id: String,
        user: String,
        req_tx: mpsc::UnboundedSender<CtrlCmd>,
        idle_timeout: Duration,
        caps: RustunnelCaps,
        udp_binary: bool,
        wire_version: WireVersion,
        conn_limit: Limit,
        backlog_limit: Limit,
        proxy_limit: Limit,
    ) -> Self {
        Self {
            run_id,
            client_id,
            user,
            req_tx,
            pool: Mutex::new(PoolState::default()),
            proxies: Mutex::new(HashMap::new()),
            caps,
            udp_binary,
            wire_version,
            work_notify: tokio::sync::Notify::new(),
            stopped: AtomicBool::new(false),
            idle_timeout,
            conn_limit,
            backlog_limit,
            proxy_limit,
        }
    }

    pub fn udp_codec_is_binary(&self) -> bool {
        self.udp_binary
    }

    /// 这个客户端能不能收私有管理命令（面板增删代理）。
    pub fn caps(&self) -> RustunnelCaps {
        self.caps.clone()
    }

    pub fn wire_version(&self) -> WireVersion {
        self.wire_version
    }

    pub fn is_stopped(&self) -> bool {
        self.stopped.load(Ordering::Relaxed)
    }

    /// 取一个转发配额；返回 `None` 表示本客户端已达连接上限。
    pub fn try_acquire_conn(&self) -> Option<crate::limits::Permit> {
        self.conn_limit.try_acquire()
    }

    /// 是否已达到连接上限。
    pub fn conns_full(&self) -> bool {
        self.conn_limit.available() == 0
    }

    /// 取一个排队配额；返回 `None` 表示待处理队列已满。
    ///
    /// 调用方拿到后要塞进 [`PendingUser::queue_permit`]，连接被配对或回收时自动归还。
    pub fn try_acquire_backlog(&self) -> Option<crate::limits::Permit> {
        self.backlog_limit.try_acquire()
    }

    /// 占一个代理名额；返回 `None` 表示已达 `max_proxies_per_client`。
    ///
    /// 拿到的凭证要交给 [`ClientState::add_proxy`] 保管 —— 随手丢掉的话
    /// 名额会被立刻归还，上限就等于没配。
    pub fn reserve_proxy(&self) -> Option<Permit> {
        self.proxy_limit.try_acquire()
    }

    /// 登记一个代理，并接管它占住的名额。
    ///
    /// `port` 传这条代理实际占用的公网端口；`http` / `https` / `stcp` / `xtcp`
    /// 不占公网端口，传 `None` 即可。
    pub fn add_proxy(&self, name: String, port: Option<u16>, slot: Permit) {
        self.proxies
            .lock()
            .unwrap()
            .insert(name, ProxyEntry { slot, port });
    }

    /// 当前登记的代理数。
    pub fn proxy_count(&self) -> usize {
        self.proxies.lock().unwrap().len()
    }

    /// 已登记的代理名（面板展示用）。
    pub fn proxy_names(&self) -> Vec<String> {
        let mut v: Vec<String> = self.proxies.lock().unwrap().keys().cloned().collect();
        v.sort();
        v
    }

    /// 是否为 xtcp 打洞提供过会话（面板用；仅统计，不参与路由）。
    pub fn client_id(&self) -> &str {
        &self.client_id
    }

    /// 当前排队等待工作连接的用户连接数。
    pub fn backlog(&self) -> usize {
        self.pool.lock().unwrap().backlog()
    }

    /// 通知控制连接："我需要一条工作连接"。
    pub fn request_work_conn(&self) {
        let _ = self.req_tx.send(CtrlCmd::RequestWork);
    }

    /// 控制连接命令通道的发送端（面板下发管理命令时要用它带上 oneshot 回执）。
    pub fn req_tx(&self) -> &mpsc::UnboundedSender<CtrlCmd> {
        &self.req_tx
    }

    /// 让控制连接把这条消息原样发给客户端（xtcp 打洞协调用）。
    pub fn forward_to_client(&self, msg: FrpMessage) {
        let _ = self.req_tx.send(CtrlCmd::Send(Box::new(msg)));
    }

    /// 主动取一条工作连接：池里没有就向客户端要，并等待它到来。
    ///
    /// UDP 代理和 HTTP 代理都不是"用户连进来才要连接"，必须自己发起。
    pub async fn acquire_work_conn(self: &Arc<Self>, wait: Duration) -> Option<WorkItem> {
        if let Some(w) = self.pool.lock().unwrap().work.pop_front() {
            return Some(w);
        }
        let deadline = Instant::now() + wait;
        loop {
            if self.is_stopped() {
                return None;
            }
            let remaining = deadline.checked_duration_since(Instant::now())?;
            self.request_work_conn();
            if tokio::time::timeout(remaining, self.work_notify.notified())
                .await
                .is_err()
            {
                return None;
            }
            if let Some(w) = self.pool.lock().unwrap().work.pop_front() {
                return Some(w);
            }
        }
    }

    /// 用户连接进来：有空闲工作连接就立即配对，否则入队并请求新工作连接。
    ///
    /// 队列达到上限时返回 [`Submit::Full`]，由调用方给访客回一个失败，
    /// 而不是让它无限排队（那是另一种形式的资源耗尽）。
    pub fn submit_user(&self, mut user: PendingUser) -> Submit {
        let mut g = self.pool.lock().unwrap();
        g.reap(self.idle_timeout);
        if let Some(w) = g.work.pop_front() {
            return Submit::Paired(Box::new(PairedBox { user, work: w }));
        }
        let Some(permit) = self.backlog_limit.try_acquire() else {
            return Submit::Full(user);
        };
        user.queue_permit = Some(permit);
        g.users.push_back(user);
        Submit::Queued
    }

    /// 工作连接到来：有排队的用户就立即配对，否则进池备用并唤醒等待者。
    pub fn submit_work(&self, w: WorkItem) -> Option<PairedBox> {
        let paired = {
            let mut g = self.pool.lock().unwrap();
            g.reap(self.idle_timeout);
            match g.users.pop_front() {
                Some(u) => Some(PairedBox { user: u, work: w }),
                None => {
                    g.work.push_back(w);
                    None
                }
            }
        };
        if paired.is_none() {
            self.work_notify.notify_waiters();
        }
        paired
    }

    /// 当前空闲池里的工作连接数（测试用）。
    pub fn idle_work_conns(&self) -> usize {
        self.pool.lock().unwrap().work.len()
    }

    /// 注销一个代理并释放它占的名额（客户端主动 `CloseProxy`）。
    ///
    /// 返回它占用的公网端口（如果有）。**调用方必须拿这个端口去
    /// `Registry::release_port`** —— 端口是注册表管的，客户端这边只是记账；
    /// 不还的话端口会一直被占着，重连同一端口会一直报"已被占用"。
    pub fn stop_proxy(&self, name: &str) -> Option<u16> {
        let e = self.proxies.lock().unwrap().remove(name)?;
        // `slot` 在这里被 drop，名额随之归还
        e.port
    }

    pub fn stop(&self) {
        self.stopped.store(true, Ordering::Relaxed);
        // 名额随 ProxyEntry 一起 drop；端口由 `Registry::release_ports_of` 统一收回
        self.proxies.lock().unwrap().clear();
        self.pool.lock().unwrap().work.clear();
        self.work_notify.notify_waiters();
    }
}

/// 为单元测试构造一个"不需要真连接"的 [`ClientState`]。
#[cfg(test)]
pub(crate) fn dummy_client(run_id: &str) -> Arc<ClientState> {
    let (tx, rx) = mpsc::unbounded_channel::<CtrlCmd>();
    // 必须持有 rx，否则 tx.send() 立刻失败（虽然 submit_user 并不依赖它成功）
    std::mem::forget(rx);
    Arc::new(ClientState::new(
        run_id.to_string(),
        run_id.to_string(),
        String::new(),
        tx,
        Duration::from_secs(60),
        Default::default(),
        false,
        rustunnel_common::frp::WireVersion::V1,
        Limit::unlimited(),
        Limit::unlimited(),
        Limit::unlimited(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn work(now: Instant) -> WorkItem {
        WorkItem {
            conn: FrpConn::new(Box::pin(tokio::io::empty()), WireVersion::V1),
            at: now,
        }
    }

    fn user(name: &str, now: Instant) -> PendingUser {
        PendingUser {
            proxy: name.to_string(),
            remote_port: 0,
            stream: Box::pin(tokio::io::empty()),
            peer: SocketAddr::from(([127, 0, 0, 1], 1234)),
            at: now,
            slot: None,
            queue_permit: None,
            load: None,
        }
    }

    fn now() -> Instant {
        Instant::now()
    }

    /// 按指定的三档上限造一个 [`ClientState`]。
    fn client_with(conn: Limit, backlog: Limit, proxy: Limit) -> Arc<ClientState> {
        let (tx, rx) = mpsc::unbounded_channel::<CtrlCmd>();
        // 必须持有 rx：tx.send() 若立即失败会掩盖真实问题
        std::mem::forget(rx);
        Arc::new(ClientState::new(
            "test".into(),
            "test".into(),
            String::new(),
            tx,
            Duration::from_secs(60),
            Default::default(),
            false,
            rustunnel_common::frp::WireVersion::V1,
            conn,
            backlog,
            proxy,
        ))
    }

    #[test]
    fn user_arrives_first_then_work_pairs() {
        let c = dummy_client("c1");
        let t = now();
        // 用户先来，池里没工作连接 -> 入队
        assert!(matches!(c.submit_user(user("ssh", t)), Submit::Queued));
        assert_eq!(c.backlog(), 1, "用户连接应该排在队列里");
        assert_eq!(c.idle_work_conns(), 0);

        // 工作连接到来 -> 立即配对
        let paired = c.submit_work(work(t)).expect("有排队用户时必须配对");
        assert_eq!(paired.user.proxy, "ssh");
        assert_eq!(c.backlog(), 0);
        assert_eq!(c.idle_work_conns(), 0, "配对后不应入空闲池");
    }

    #[test]
    fn work_arrives_first_parks_in_idle_pool() {
        let c = dummy_client("c2");
        let t = now();
        assert!(c.submit_work(work(t)).is_none(), "没有排队用户时应进空闲池");
        assert_eq!(c.idle_work_conns(), 1);
        let Submit::Paired(p) = c.submit_user(user("ssh", t)) else {
            panic!("有空闲工作连接时应立刻配对");
        };
        assert_eq!(p.user.proxy, "ssh");
        assert_eq!(c.idle_work_conns(), 0);
    }

    #[test]
    fn stale_idle_work_conns_are_reaped() {
        // idle_timeout 只有 50ms，等一小会儿就该被回收 —— 这是对真实时钟的测试，
        // 比伪造一个 `Instant` 后缀可靠（伪造的时间戳在 reap 里其实也走同一条路径）
        let (tx, rx) = mpsc::unbounded_channel::<CtrlCmd>();
        std::mem::forget(rx);
        let c = ClientState::new(
            "c3".into(),
            "c3".into(),
            String::new(),
            tx,
            Duration::from_millis(50),
            Default::default(),
            false,
            rustunnel_common::frp::WireVersion::V1,
            Limit::unlimited(),
            Limit::unlimited(),
            Limit::unlimited(),
        );
        c.submit_work(work(Instant::now()));
        assert_eq!(c.idle_work_conns(), 1);

        std::thread::sleep(Duration::from_millis(90));
        // 下一次 submit 会顺带触发 reap
        c.submit_user(user("fresh", Instant::now()));
        assert_eq!(c.idle_work_conns(), 0, "过期的工作连接应被回收");
        assert_eq!(c.backlog(), 1, "新来的连接必须留住");
    }

    #[test]
    fn backlog_limit_rejects_when_full() {
        let c = client_with(Limit::unlimited(), Limit::new(1), Limit::unlimited());
        let t = now();
        assert!(matches!(c.submit_user(user("a", t)), Submit::Queued));
        // 第二个应该被拒绝（队列已满）
        match c.submit_user(user("b", t)) {
            Submit::Full(u) => assert_eq!(u.proxy, "b"),
            _ => panic!("队列达到上限后必须拒绝而不是无限堆积"),
        }
    }

    #[test]
    fn backlog_permit_is_released_after_pairing() {
        // 队列上限为 1：第一条入队占满；配对后配额必须归还，否则后续连接永远排不进来
        let c = client_with(Limit::unlimited(), Limit::new(1), Limit::unlimited());
        let t = now();
        c.submit_user(user("a", t));
        c.submit_work(work(t)).expect("应配对");
        // 再入队一次应当成功（说明配额已随连接被消费而归还）
        assert!(
            matches!(c.submit_user(user("c", t)), Submit::Queued),
            "配对后排队配额必须归还"
        );
    }

    #[test]
    fn conn_limit_counts_active_forwards() {
        let c = client_with(Limit::new(2), Limit::unlimited(), Limit::unlimited());
        let p1 = c.try_acquire_conn().expect("第 1 条");
        let p2 = c.try_acquire_conn().expect("第 2 条");
        assert!(c.try_acquire_conn().is_none(), "超过上限必须拿不到配额");
        assert!(c.conns_full());
        drop(p1);
        let p3 = c
            .try_acquire_conn()
            .expect("drop 之后配额必须归还，否则服务端会被慢慢耗死");
        drop(p2);
        drop(p3);
        assert!(!c.conns_full());
    }

    #[test]
    fn proxy_slot_limit_is_held_until_proxy_is_closed() {
        let c = client_with(Limit::unlimited(), Limit::unlimited(), Limit::new(1));
        let slot = c.reserve_proxy().expect("第 1 个代理名额");
        assert!(
            c.reserve_proxy().is_none(),
            "代理数上限必须生效，否则一个客户端能注册无数代理抢占端口"
        );
        c.add_proxy("ssh".into(), None, slot);
        assert_eq!(c.proxy_count(), 1);
        assert!(c.reserve_proxy().is_none(), "代理还在，名额不能松手");

        c.stop_proxy("ssh");
        assert_eq!(c.proxy_count(), 0);
        assert!(
            c.reserve_proxy().is_some(),
            "代理注销后名额必须归还，否则重连几次就再也注册不了"
        );
    }

    #[test]
    fn stop_marks_client_and_clears_pool() {
        let c = dummy_client("c7");
        c.submit_work(work(now()));
        assert!(!c.is_stopped());
        c.stop();
        assert!(c.is_stopped());
        assert_eq!(c.idle_work_conns(), 0, "stop 后必须清掉空闲连接");
        assert_eq!(c.proxy_count(), 0);
    }

    #[tokio::test]
    async fn acquire_work_conn_times_out_without_client() {
        let c = dummy_client("c8");
        let started = Instant::now();
        let r = c.acquire_work_conn(Duration::from_millis(120)).await;
        assert!(r.is_none(), "客户端一直不来工作连接时应超时返回 None");
        assert!(started.elapsed() >= Duration::from_millis(100));
    }

    #[tokio::test]
    async fn acquire_work_conn_returns_parked_connection() {
        let c = dummy_client("c9");
        let parked = c.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(60)).await;
            parked.submit_work(work(Instant::now()));
        });
        let r = tokio::time::timeout(
            Duration::from_secs(2),
            c.acquire_work_conn(Duration::from_secs(2)),
        )
        .await
        .expect("不应超时");
        assert!(r.is_some(), "工作连接到来后必须被等待者拿到");
    }
}
