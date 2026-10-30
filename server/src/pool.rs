//! 工作连接池与「用户连接 <-> 工作连接」配对。
//!
//! frp 的模型是：**用户连接**在服务端等着，**工作连接**由 frpc 主动建过来，
//! 两者在服务端配对后开始双向转发原始字节。
//! 这个模块只负责两者的排队 / 配对 / 超时回收，不含任何读写 socket 的代码，
//! 因此可以脱离网络做纯内存单元测试。

use std::{
    collections::{HashMap, VecDeque},
    net::{IpAddr, SocketAddr},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
    time::{Duration, Instant},
};

use nfrp_common::frp::{
    conn::FrpConn,
    msg::{FrpMessage, NfrpCaps},
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
        cmd: Box<nfrp_common::frp::msg::ServerCmd>,
        ack: tokio::sync::oneshot::Sender<Result<(), String>>,
    },
}

use tracing::debug;

/// 一条已握手完成、等待分配代理的工作连接。
pub struct WorkItem {
    pub conn: FrpConn,
    pub at: Instant,
    /// ★★ v0.5.8（第七轮审计 **C-2**）：这条空闲工作连接占的配额凭证。
    ///
    /// 它与其它配额一样靠 **drop 归还** —— 被配对取走、被 `reap` 超时清掉、
    /// 或连接本身断开时，`WorkItem` 一 drop，名额就回到池子里。
    /// 这样"池子满了"不会变成"池子永久卡死"。
    ///
    /// `None` 表示该条不是经 `submit_work` 入池的（不占池子配额）。
    idle_permit: Option<Permit>,
}

impl WorkItem {
    /// ★ v0.5.8（C-2）：新增构造入口。
    ///
    /// 之所以不让调用方写结构体字面量：`idle_permit` 是**内部记账**，
    /// 调用方（`serve.rs::handle_work`）不该、也无法正确填它 ——
    /// 它由 `submit_work` 在入池那一刻决定。
    /// 把字段设成私有 + 提供构造函数，就从类型上保证了这一点。
    pub fn new(conn: FrpConn) -> Self {
        Self {
            conn,
            at: Instant::now(),
            idle_permit: None,
        }
    }

    /// 附带空闲池配额（`submit_work` 入池时用）。
    fn with_idle_permit(mut self, permit: Permit) -> Self {
        self.idle_permit = Some(permit);
        self
    }
}

/// 一个已经连进来、等待工作连接的用户连接。
///
/// `stream` 可能是：
/// * 公网端口上进来的 TCP（tcp / udp / http / https 走这条）；
/// * visitor 连接（stcp / xtcp）：握手完成后它本身就是裸字节通道。
pub struct PendingUser {
    pub proxy: String,
    /// 代理类型与所属客户端身份，`NewUserConn` 插件需要。
    pub proxy_type: String,
    pub client_user: String,
    pub client_run_id: String,
    /// 数据面是否加密（`NewProxy.use_encryption`）。
    ///
    /// ★ v0.6.6：随用户连接一起带下来，因为真正做 relay 的
    /// [`crate::serve::bridge`] 拿不到 `ClientState` / `SecurityContext`。
    pub use_encryption: bool,
    /// 数据面是否压缩（`NewProxy.use_compression`）。
    pub use_compression: bool,
    /// 已派生的数据面密钥（仅在 `use_encryption` 时是 `Some`）。
    ///
    /// 这里直接存**派生结果**而不是 token 本身：bridge 那一层不该接触明文 token。
    pub data_key: Option<[u8; 16]>,
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
    /// 数据面是否加密（来自客户端 `NewProxy.use_encryption`）。
    ///
    /// ★ v0.6.6：服务端必须知道它，否则工作连接的另一端不知道要解密 ——
    /// 客户端加密、服务端明文透传，用户会得到"能连上、数据全乱"。
    use_encryption: bool,
    /// 数据面是否压缩（来自 `NewProxy.use_compression`）。
    use_compression: bool,
    /// 代理类型（`tcp` / `http` / `stcp` ...）。给 `NewUserConn` 插件用。
    proxy_type: String,
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
    ///
    /// `PendingUser` 带着 stream、地址、token 等一堆字段；不装箱会让整个
    /// `Submit` 枚举按最大变体分配 264 字节，正常命中 `Paired` / `Queued`
    /// 的路径也要扛这个体积。拒绝路径本来就是冷路径，装箱只多一次分配。
    Full(Box<PendingUser>),
}

#[derive(Default)]
struct PoolState {
    work: VecDeque<WorkItem>,
    users: VecDeque<PendingUser>,
}

impl PoolState {
    /// 丢弃超时的空闲工作连接与排队用户，避免半开连接无限堆积。
    ///
    /// 两个超时是**两个不同的量**（限制①批次1 起拆分）：
    /// * `work_timeout`（`work_conn_idle_timeout`，nfrp 自有字段）：空闲工作
    ///   连接在池里能躺多久 —— 躺太久说明客户端预建的连接早已失效；
    /// * `user_timeout`（`userConnTimeout`，对齐官方 `GetWorkConn()` 默认 10 秒）：
    ///   排队用户等多久配不到工作连接就放弃。
    ///
    /// 原先两者共用 `idle_timeout`：用户连接要傻等 60 秒才被清理，而官方
    /// 10 秒就放弃了 —— 等得越久，占着内存的半开连接越多。
    fn reap(&mut self, work_timeout: Duration, user_timeout: Duration) {
        let now = Instant::now();
        while self
            .work
            .front()
            .map(|w| now.duration_since(w.at) > work_timeout)
            .unwrap_or(false)
        {
            self.work.pop_front();
        }
        while self
            .users
            .front()
            .map(|u| now.duration_since(u.at) > user_timeout)
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
    /// 本会话**协商成功**的 NFrp 私有能力（见 [`NfrpCaps`]）。
    ///
    /// 只有这里为真，服务端才可以往这个客户端发管理命令。
    /// 官方 frpc 不会声明能力，所以永远是全关。
    caps: NfrpCaps,
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
    /// 用户连接等待工作连接的超时（对应 frp `userConnTimeout`，官方默认 10 秒）。
    ///
    /// ★ 限制①批次1：替掉三处硬编码 —— visitor 路径等 10s、vhost / UDP 路径
    /// 等 15s、排队用户由 `idle_timeout`（默认 60s）兜底。全部统一到本字段，
    /// 与官方 `GetWorkConn()` 的语义对齐（等不到工作连接就放弃这条用户连接）。
    user_conn_timeout: Duration,
    /// 本客户端的同时活跃转发连接上限。
    conn_limit: Limit,
    /// 本客户端的排队上限（用户连接排着等工作连接）。
    backlog_limit: Limit,
    /// ★★ v0.5.8 新增（第七轮审计 **C-2**，中危）：**空闲工作连接池的上限**。
    ///
    /// # 为什么需要它
    ///
    /// `submit_work` 入池时原先**没有任何闸门**（对照 `submit_user` 有
    /// `backlog_limit.try_acquire()`）：
    ///
    /// ```ignore
    /// // 修前
    /// None => { g.work.push_back(w); None }   // ← 无条件入池
    /// ```
    ///
    /// 而 `reap` 只在**下一次** submit 时按 `idle_timeout`（默认 60s）回收。
    /// 再加上 `handle_work` **不经过** `max_clients` / `max_total_conns` /
    /// `max_conns_per_client`（那些只在**用户**连接侧的 `ConnSlot::acquire`）
    /// ⇒ **工作连接方向完全没有配额闸门**。
    ///
    /// # 实测（C 组 `c13c_workpool_cost.py`，主审已核对源码与数据）
    ///
    /// 把**全部四个**用户侧配额设到最小值（`max_clients=4`、`max_total_conns=8`、
    /// `max_conns_per_client=4`、`max_pending_per_client=4`）仍然拦不住：
    ///
    /// | 灌入 | idle_work_conns | 服务端句柄 | 内存 |
    /// |---|---|---|---|
    /// | 200 | 200 | — | — |
    /// | 2000 | 2000 | +2066 | +3.3 MB |
    /// | 4000 | 4000 | +4129 | +6.5 MB |
    /// | **6000** | **6000** | — | 仍正常、无降级 |
    ///
    /// 单条成本 ≈ **1.03 个句柄 + 1.6 KB 内存**，200→6000 全部**线性**，
    /// 未观测到拐点。⇒ 任何持合法 token 的租户都能用一条脚本把服务端 fd 耗尽。
    ///
    /// ★ 第五轮 M15 曾写下"`idle_work_conns` 持续累积、fd/内存缓慢增长"
    ///   这句话，但**只修了超时的上界**（`clamp(5,3600)`），
    ///   **从未加过数量上界** ⇒ 该面从未被真正修过。
    ///
    /// # 取值
    ///
    /// 复用 `max_pending_per_client` 的语义（"这个客户端的待处理容量"）——
    /// 空闲工作连接与排队用户是**同一枚硬币的两面**（都在等配对），
    /// 用同一个数封顶最自然。
    ///
    /// ★ 限制①批次1：再叠加官方 `maxPoolCount`（`ServerConfig::max_pool_count`），
    /// 两者**取更小**（任一为 0 = 该侧不设限；两侧都 0 = 不限制）。官方口径是
    /// "池容量 = min(客户端 poolCount, maxPoolCount) + 10 余量"，这里映射成
    /// 空闲池闸门 —— 默认（都没配）时与原行为完全一致。
    idle_work_limit: Limit,
    /// 本客户端可注册的代理数上限。
    proxy_limit: Limit,
    /// 这个客户端的角色是否允许**面板管理**它（RBAC 的 `allowManage`）。
    ///
    /// ★ 曾经是死字段：`Role::allow_manage` 从配置读进来、编译进角色，
    /// 但没有任何生产代码读它 —— 管理员写 `allowManage = false` 以为禁掉了
    /// 面板增删这个客户端代理的能力，实际照做不误。角色在握手期解析一次，
    /// 之后就丢了，所以这里随会话存一份。
    ///
    /// 用 `AtomicBool` 而不是普通 `bool`：客户端建好之后要由控制连接那边
    /// 补写（角色是在握手函数内部解析出来的，`ClientState::new` 时还拿不到）。
    allow_manage: AtomicBool,
    /// 控制连接的**源 IP**（v0.5.5，配合 A-1 的互通安全回退）。
    ///
    /// 用途：官方 frpc 在默认配置下**不给工作连接带 `privilege_key`**
    /// （见官方 `pkg/auth/token.go` 的 `SetNewWorkConn`：未配
    /// `additionalScopes = ["NewWorkConns"]` 时直接 `return nil`）。
    /// 所以"要求凭证"这条策略不能一刀切 —— 会把官方客户端挡在门外
    /// （实测：`工作连接凭证不符` ⇒ 官方 frpc 的 tcp 代理完全不通）。
    ///
    /// 折中方案：**凭证为空时，要求工作连接的源 IP 与控制连接一致**。
    /// 官方 frpc 天然满足（同一个进程、同一个出口），零兼容代价；
    /// 而攻击者要伪造源 IP 比"知道 run_id"难得多。
    peer_ip: IpAddr,
    /// NLink 协商结果（`None` = 未协商）。控制连接登录成功后写入，
    /// 工作连接校验身份令牌、桥接层限流都要读它。
    nlink: Mutex<Option<nfrp_common::frp::conn::NLinkState>>,
    /// 批量工作连接条数（0 = 不走批量）。由登录后的协商结果写入。
    nlink_batch: std::sync::atomic::AtomicUsize,
    /// 上次批量请求的时间（Unix 毫秒），用于去抖。
    last_batch_ms: std::sync::atomic::AtomicU64,
}

impl ClientState {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        run_id: String,
        client_id: String,
        user: String,
        req_tx: mpsc::UnboundedSender<CtrlCmd>,
        idle_timeout: Duration,
        user_conn_timeout: Duration,
        caps: NfrpCaps,
        udp_binary: bool,
        wire_version: WireVersion,
        conn_limit: Limit,
        backlog_limit: Limit,
        max_pool_count: usize,
        proxy_limit: Limit,
        peer_ip: IpAddr,
    ) -> Self {
        // ★ C-2：空闲工作连接池与排队用户是同一枚硬币的两面（都在等配对），
        //   所以复用 `backlog_limit` 的**上限值**（而不是再引一个配置项）。
        //   注意要取 `max()` 而不是 clone —— `Limit` 内部是共享信号量，
        //   两处共用一个信号量会把"排队"与"空闲池"互相挤占，
        //   而它们是**两种不同的资源**，各自独立计数才对。
        //
        // ★ 限制①批次1：再叠加官方 `maxPoolCount` —— 两个上限**取更小**；
        //   任一为 0（该侧不设限）就取另一个；都为 0 = 不限制。
        let backlog_max = backlog_limit.max();
        let idle_cap = match (backlog_max, max_pool_count) {
            (0, 0) => 0,
            (0, m) => m,
            (b, 0) => b,
            (b, m) => b.min(m),
        };
        let idle_work_limit = Limit::new(idle_cap);
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
            user_conn_timeout,
            conn_limit,
            backlog_limit,
            idle_work_limit,
            proxy_limit,
            // 默认**允许**：未启用 RBAC 时行为必须与老版本完全一致。
            // 启用 RBAC 后由控制连接按角色覆盖。
            allow_manage: AtomicBool::new(true),
            peer_ip,
            nlink: Mutex::new(None),
            nlink_batch: std::sync::atomic::AtomicUsize::new(0),
            last_batch_ms: std::sync::atomic::AtomicU64::new(0),
        }
    }

    /// 控制连接的源 IP（工作连接的空凭证回退校验要用，见字段注释）。
    pub fn peer_ip(&self) -> IpAddr {
        self.peer_ip
    }

    /// NLink 协商结果（`None` = 本次会话没有启用扩展层）。
    pub fn nlink(&self) -> Option<nfrp_common::frp::conn::NLinkState> {
        self.nlink
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }

    /// 由控制连接在登录成功后写入。
    pub fn set_nlink(&self, state: nfrp_common::frp::conn::NLinkState) {
        *self.nlink.lock().unwrap_or_else(|e| e.into_inner()) = Some(state);
    }

    /// 本次会话是否协商了某一项 NLink 能力。
    pub fn nlink_has(&self, bit: u64) -> bool {
        self.nlink()
            .map(|st| st.caps.contains(bit))
            .unwrap_or(false)
    }

    /// 按角色写入"面板能不能管理这个客户端"。握手期解析出角色后立刻调用。
    pub fn set_allow_manage(&self, allow: bool) {
        self.allow_manage.store(allow, Ordering::Relaxed);
    }

    /// 面板能不能管理这个客户端（RBAC 关闭时恒为 true）。
    pub fn allow_manage(&self) -> bool {
        self.allow_manage.load(Ordering::Relaxed)
    }

    pub fn udp_codec_is_binary(&self) -> bool {
        self.udp_binary
    }

    /// 这个客户端能不能收私有管理命令（面板增删代理）。
    pub fn caps(&self) -> NfrpCaps {
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
            .unwrap_or_else(|e| e.into_inner())
            .insert(
                name,
                ProxyEntry {
                    slot,
                    port,
                    // 由 `set_proxy_flags` 回填（注册时从 NewProxy 消息取）
                    use_encryption: false,
                    use_compression: false,
                    proxy_type: String::new(),
                },
            );
    }

    /// 回填代理类型（`tcp` / `http` / `stcp` ...），供 `NewUserConn` 插件使用。
    pub fn set_proxy_type(&self, name: &str, proxy_type: &str) {
        let mut g = self.proxies.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(e) = g.get_mut(name) {
            e.proxy_type = proxy_type.to_string();
        }
    }

    /// 查代理类型；不存在时返回空串。
    pub fn proxy_type(&self, name: &str) -> String {
        self.proxies
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(name)
            .map(|e| e.proxy_type.clone())
            .unwrap_or_default()
    }

    /// 回填某条代理的数据面标志（加密 / 压缩）。
    ///
    /// 从 `NewProxy` 消息里拿到的值，注册时调用一次。
    /// 代理不存在时安静返回 —— 注册失败路径上不该再报错。
    pub fn set_proxy_flags(&self, name: &str, enc: bool, comp: bool) {
        let mut g = self.proxies.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(e) = g.get_mut(name) {
            e.use_encryption = enc;
            e.use_compression = comp;
        }
    }

    /// 查某条代理的数据面标志：`(加密, 压缩)`。
    ///
    /// 代理不存在时返回 `(false, false)` —— 与"没配"同义（明文透传），
    /// 不会因为查不到就把数据当成密文去解。
    pub fn proxy_flags(&self, name: &str) -> (bool, bool) {
        let g = self.proxies.lock().unwrap_or_else(|e| e.into_inner());
        g.get(name)
            .map(|e| (e.use_encryption, e.use_compression))
            .unwrap_or((false, false))
    }

    /// 当前登记的代理数。
    pub fn proxy_count(&self) -> usize {
        self.proxies.lock().unwrap_or_else(|e| e.into_inner()).len()
    }

    /// 本客户端已占用的**公网端口数**（对应官方 `Control.portsUsedNum`）。
    ///
    /// 与 [`Self::proxy_count`] 的区别：`http` / `https` / `tcpmux` / `stcp` /
    /// `xtcp` / `sudp` 这些**不绑公网端口**的代理只算代理数、不算端口数
    /// （它们的 `port` 是 `None`）。官方也是这么分的 ——
    /// `Control.RegisterProxy` 累加的是 `pxy.GetUsedPortsNum()`，只有 tcp / udp 非零。
    pub fn ports_used(&self) -> usize {
        self.proxies
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .values()
            .filter(|e| e.port.is_some())
            .count()
    }

    /// 已登记的代理名（面板展示用）。
    pub fn proxy_names(&self) -> Vec<String> {
        let mut v: Vec<String> = self
            .proxies
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .keys()
            .cloned()
            .collect();
        v.sort();
        v
    }

    /// 是否为 xtcp 打洞提供过会话（面板用；仅统计，不参与路由）。
    pub fn client_id(&self) -> &str {
        &self.client_id
    }

    /// 当前排队等待工作连接的用户连接数。
    pub fn backlog(&self) -> usize {
        self.pool
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .backlog()
    }

    /// 通知控制连接："我需要一条工作连接"。
    pub fn request_work_conn(&self) {
        let _ = self.req_tx.send(CtrlCmd::RequestWork);
    }

    /// 登录后按协商结果设置批量条数（0 = 关闭）。
    pub fn set_nlink_batch(&self, n: usize) {
        self.nlink_batch
            .store(n, std::sync::atomic::Ordering::Relaxed);
    }

    /// 这次"要工作连接"能不能合并成一次批量请求。
    ///
    /// 三条同时成立才批量：
    ///
    /// 1. 会话协商了 `batch-work-conn`（`nlink_batch >= 2`）；
    /// 2. **当前等待工作连接的用户不止一个** —— 只有一条用户连接时，
    ///    多要的连接纯属浪费（它们会占着空闲池直到超时）；
    /// 3. 距上次批量已过 250ms —— 一波突发里的 N 个用户只会触发一次批量，
    ///    否则每个用户都发一条 `BatchReq`，比逐条要还浪费。
    ///
    /// 返回要的条数。`None` 表示"按老办法发一条 `ReqWorkConn`"。
    pub fn take_batch_request(&self) -> Option<u32> {
        let cap = self.nlink_batch.load(std::sync::atomic::Ordering::Relaxed);
        if cap < 2 {
            return None;
        }
        let backlog = self.backlog();
        if backlog < 2 {
            return None;
        }
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);
        let last = self
            .last_batch_ms
            .swap(now, std::sync::atomic::Ordering::Relaxed);
        if now.saturating_sub(last) < 250 {
            return None;
        }
        Some((cap as u32).min(backlog as u32).clamp(2, 256))
    }

    /// 控制连接命令通道的发送端（面板下发管理命令时要用它带上 oneshot 回执）。
    pub fn req_tx(&self) -> &mpsc::UnboundedSender<CtrlCmd> {
        &self.req_tx
    }

    /// 让控制连接把这条消息原样发给客户端（xtcp 打洞协调用）。
    pub fn forward_to_client(&self, msg: FrpMessage) {
        let _ = self.req_tx.send(CtrlCmd::Send(Box::new(msg)));
    }

    /// 主动取一条工作连接：池里没有就向客户端要，并等待 `user_conn_timeout`
    /// （对应官方 `userConnTimeout`，默认 10 秒）。
    ///
    /// UDP 代理和 HTTP 代理都不是"用户连进来才要连接"，必须自己发起。
    /// 访问方（vhost / visitor / UDP）一律走这个入口 —— 超时预算由服务端
    /// 配置决定，而不是各处硬编码。
    pub async fn acquire_work_conn(self: &Arc<Self>) -> Option<WorkItem> {
        self.acquire_work_conn_within(self.user_conn_timeout).await
    }

    /// 同 [`Self::acquire_work_conn`]，但**显式指定**等待时长（测试 / 特殊路径用）。
    pub async fn acquire_work_conn_within(self: &Arc<Self>, wait: Duration) -> Option<WorkItem> {
        if let Some(w) = self
            .pool
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .work
            .pop_front()
        {
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
            if let Some(w) = self
                .pool
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .work
                .pop_front()
            {
                return Some(w);
            }
        }
    }

    /// 用户连接进来：有空闲工作连接就立即配对，否则入队并请求新工作连接。
    ///
    /// 队列达到上限时返回 [`Submit::Full`]，由调用方给访客回一个失败，
    /// 而不是让它无限排队（那是另一种形式的资源耗尽）。
    pub fn submit_user(&self, mut user: PendingUser) -> Submit {
        let mut g = self.pool.lock().unwrap_or_else(|e| e.into_inner());
        g.reap(self.idle_timeout, self.user_conn_timeout);
        if let Some(w) = g.work.pop_front() {
            return Submit::Paired(Box::new(PairedBox { user, work: w }));
        }
        let Some(permit) = self.backlog_limit.try_acquire() else {
            return Submit::Full(Box::new(user));
        };
        user.queue_permit = Some(permit);
        g.users.push_back(user);
        Submit::Queued
    }

    /// 工作连接到来：有排队的用户就立即配对，否则进池备用并唤醒等待者。
    ///
    /// ★★ v0.5.8 修（第七轮审计 **C-2**，中危）：**空闲池必须封顶。**
    ///
    /// # 原先为什么错了
    ///
    /// 入池分支**没有任何闸门**（对照 `submit_user` 有
    /// `backlog_limit.try_acquire()`），而 `reap` 只在下一次 submit 时
    /// 按 `idle_timeout`（默认 60s）回收；`handle_work` 又**不经过**
    /// `max_clients` / `max_total_conns` / `max_conns_per_client`
    /// （那些只在**用户**连接侧的 `ConnSlot::acquire`）。
    ///
    /// ⇒ **工作连接方向完全没有配额闸门。** 实测（C 组 `c13c`）：
    /// 四个用户侧配额全设最小值（4/8/4/4）仍能灌到 **6000 条**空闲工作连接，
    /// 每条约 1.03 个句柄 + 1.6 KB，**线性无拐点**。
    ///
    /// # 修法
    ///
    /// 与 `submit_user` 对称：入池前 `try_acquire`，取不到就**拒绝这条工作连接**
    /// （返回 `None` 时调用方会关闭它）。这样：
    /// * fd / 内存增长有**上界**（= `idle_work_limit`）；
    /// * **不改变正常行为** —— 默认 `0`（不限）时零影响；
    ///   真配了上限的场景下，正常客户端根本不会攒出那么多空闲工作连接
    ///   （每条用户连接配一条工作连接，用完即弃）。
    ///
    /// ★ 为什么"拒绝工作连接"是安全的：它**只影响那条多余的空闲连接**，
    ///   已经在配对中的工作连接不受影响。客户端需要时会再申请
    ///   （`request_work_conn`），不影响任何已建立的转发。
    pub fn submit_work(&self, w: WorkItem) -> Option<PairedBox> {
        let paired = {
            let mut g = self.pool.lock().unwrap_or_else(|e| e.into_inner());
            g.reap(self.idle_timeout, self.user_conn_timeout);
            match g.users.pop_front() {
                Some(u) => Some(PairedBox { user: u, work: w }),
                None => {
                    // ★ C-2：入池前先取配额。取不到 ⇒ 拒绝入池（返回 None，
                    //   调用方关闭这条工作连接），而不是无条件 push_back。
                    match self.idle_work_limit.try_acquire() {
                        Some(permit) => {
                            g.work.push_back(w.with_idle_permit(permit));
                            None
                        }
                        None => {
                            debug!(
                                idle = g.work.len(),
                                limit = self.idle_work_limit.max(),
                                "空闲工作连接池已满，拒绝这条工作连接"
                            );
                            return None;
                        }
                    }
                }
            }
        };
        if paired.is_none() {
            // `notify_one` 而不是 `notify_waiters`：一条工作连接只该唤醒
            // 一个 `acquire_work_conn` 等待者。更关键的是，Tokio 的
            // `notify_waiters` **不保存许可**：如果工作连接在
            // `acquire_work_conn_within` 刚发出 `RequestWork`、但还没
            // `await notified()` 的窗口里到达，通知会直接丢掉，工作连接
            // 却已躺在池里，等待者只能空等超时。官方 frpc 的 xtcp
            // 工作连接正是这么快，真实 e2e 每次都命中这个窗口。
            // `notify_one` 会把许可存下来，之后 `notified()` 立即返回。
            self.work_notify.notify_one();
        }
        paired
    }

    /// 当前空闲池里的工作连接数（测试用）。
    pub fn idle_work_conns(&self) -> usize {
        self.pool
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .work
            .len()
    }

    /// 注销一个代理并释放它占的名额（客户端主动 `CloseProxy`）。
    ///
    /// 返回它占用的公网端口（如果有）。**调用方必须拿这个端口去
    /// `Registry::release_port`** —— 端口是注册表管的，客户端这边只是记账；
    /// 不还的话端口会一直被占着，重连同一端口会一直报"已被占用"。
    pub fn stop_proxy(&self, name: &str) -> Option<u16> {
        let e = self
            .proxies
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(name)?;
        // `slot` 在这里被 drop，名额随之归还
        e.port
    }

    pub fn stop(&self) {
        self.stopped.store(true, Ordering::Relaxed);
        // 名额随 ProxyEntry 一起 drop；端口由 `Registry::release_ports_of` 统一收回
        self.proxies
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clear();
        self.pool
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .work
            .clear();
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
        Duration::from_secs(10),
        Default::default(),
        false,
        nfrp_common::frp::WireVersion::V1,
        Limit::unlimited(),
        Limit::unlimited(),
        0,
        Limit::unlimited(),
        "127.0.0.1".parse::<std::net::IpAddr>().unwrap(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn work(now: Instant) -> WorkItem {
        let mut w = WorkItem::new(FrpConn::new(Box::pin(tokio::io::empty()), WireVersion::V1));
        w.at = now;
        w
    }

    fn user(name: &str, now: Instant) -> PendingUser {
        PendingUser {
            proxy: name.to_string(),
            proxy_type: "tcp".to_string(),
            client_user: "test".to_string(),
            client_run_id: "test-run".to_string(),
            use_encryption: false,
            use_compression: false,
            data_key: None,
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

    /// `ports_used` 只数**真的占了公网端口**的代理。
    ///
    /// 这是 `maxPortsPerClient` 的依据：http / https / tcpmux / stcp 这些走虚拟主机
    /// 或 visitor 配对的代理一个公网端口都不占，不该把它们的名额算进去 ——
    /// 否则"允许 2 个端口"会因为两条 http 代理就先被卡住。
    #[test]
    fn ports_used_只数占端口的代理() {
        let c = dummy_client("ports");
        let s1 = c.reserve_proxy().expect("名额充足");
        c.add_proxy("tcp-a".into(), Some(6000), s1);
        let s2 = c.reserve_proxy().expect("名额充足");
        c.add_proxy("http-b".into(), None, s2);
        assert_eq!(c.proxy_count(), 2);
        assert_eq!(c.ports_used(), 1, "http 不占公网端口");

        let s3 = c.reserve_proxy().expect("名额充足");
        c.add_proxy("tcp-c".into(), Some(6001), s3);
        assert_eq!(c.ports_used(), 2);
        assert_eq!(c.proxy_count(), 3);
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
            // 用户侧超时给足：本用例测的是 work 侧回收，"新来的连接必须留住"
            Duration::from_secs(60),
            Default::default(),
            false,
            nfrp_common::frp::WireVersion::V1,
            Limit::unlimited(),
            Limit::unlimited(),
            0,
            Limit::unlimited(),
            "127.0.0.1".parse::<std::net::IpAddr>().unwrap(),
        );
        c.submit_work(work(Instant::now()));
        assert_eq!(c.idle_work_conns(), 1);

        std::thread::sleep(Duration::from_millis(90));
        // 下一次 submit 会顺带触发 reap
        c.submit_user(user("fresh", Instant::now()));
        assert_eq!(c.idle_work_conns(), 0, "过期的工作连接应被回收");
        assert_eq!(c.backlog(), 1, "新来的连接必须留住");
    }

    /// 限制①批次1：`maxPoolCount` 给空闲池封顶 —— 第二条空闲工作连接被拒，
    /// 池里的数量保持在 1（不配上限时它会是 2）。
    #[test]
    fn max_pool_count_给空闲池封顶() {
        let (tx, rx) = mpsc::unbounded_channel::<CtrlCmd>();
        std::mem::forget(rx);
        let c = ClientState::new(
            "mp".into(),
            "mp".into(),
            String::new(),
            tx,
            Duration::from_secs(60),
            Duration::from_secs(10),
            Default::default(),
            false,
            nfrp_common::frp::WireVersion::V1,
            Limit::unlimited(),
            Limit::unlimited(),
            1, // max_pool_count = 1
            Limit::unlimited(),
            "127.0.0.1".parse::<std::net::IpAddr>().unwrap(),
        );
        let t = now();
        assert!(c.submit_work(work(t)).is_none(), "第一条进空闲池");
        assert_eq!(c.idle_work_conns(), 1);
        assert!(
            c.submit_work(work(t)).is_none(),
            "第二条被拒（拒绝路径同样返回 None）"
        );
        assert_eq!(c.idle_work_conns(), 1, "上限 = 1 时池不能涨到 2");

        // 排队用户仍然能正常配对（配对路径不占用空闲名额）
        assert!(matches!(c.submit_user(user("ssh", t)), Submit::Paired(_)));
    }

    /// 限制①批次1：排队用户按 `userConnTimeout` 回收，与工作连接侧的超时分开。
    #[test]
    fn 排队用户按_user_conn_timeout_回收() {
        let (tx, rx) = mpsc::unbounded_channel::<CtrlCmd>();
        std::mem::forget(rx);
        let c = ClientState::new(
            "uc".into(),
            "uc".into(),
            String::new(),
            tx,
            // 工作连接侧给足，本用例只测用户侧
            Duration::from_secs(60),
            Duration::from_millis(50),
            Default::default(),
            false,
            nfrp_common::frp::WireVersion::V1,
            Limit::unlimited(),
            Limit::unlimited(),
            0,
            Limit::unlimited(),
            "127.0.0.1".parse::<std::net::IpAddr>().unwrap(),
        );
        assert!(matches!(
            c.submit_user(user("slow", Instant::now())),
            Submit::Queued
        ));
        assert_eq!(c.backlog(), 1);

        std::thread::sleep(Duration::from_millis(90));
        // 工作连接到来时顺带 reap：排队的用户已超时被丢，工作连接无人可配 ⇒ 进池
        assert!(
            c.submit_work(work(Instant::now())).is_none(),
            "用户已被回收，工作连接应进池而不是配对"
        );
        assert_eq!(c.backlog(), 0, "超时的用户必须被回收");
        assert_eq!(c.idle_work_conns(), 1);
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

    // -----------------------------------------------------------------------
    // 第七轮审计 C-2：空闲工作连接池必须有上界
    // -----------------------------------------------------------------------

    /// ★★ v0.5.8 回归（第七轮审计 **C-2**，中危）：
    /// **空闲工作连接池必须封顶**，否则单个合法客户端能刷爆服务端 fd。
    ///
    /// # 原先的洞
    ///
    /// `submit_work` 入池分支**没有** `try_acquire`（对照 `submit_user` 有
    /// `backlog_limit`），而 `handle_work` 又不经过任何用户侧配额
    /// ⇒ 工作连接方向完全没有闸门。
    ///
    /// 实测（C 组 `c13c`）：四个用户侧配额全设最小值（`4/8/4/4`）时，
    /// 仍能灌进 **6000 条**空闲工作连接（每条约 1.03 句柄 + 1.6 KB），
    /// 线性无拐点。
    ///
    /// # 这条测试测什么
    ///
    /// 1. **上界生效**：配了上限后，多余的 `submit_work` 必须被**拒绝**
    ///    （返回 `None` ⇒ 调用方关闭那条工作连接），而不是无限入池；
    /// 2. **配额会归还**：被配对取走或超时回收后，名额必须回到池子
    ///    —— 否则"池子满了"会退化成"池子永久卡死"（那比不限制更糟）；
    /// 3. **默认不限**：`Limit::unlimited()` 时行为与修复前**完全一致**
    ///    （零行为变化，这是本项目对默认配置的一贯要求）。
    #[test]
    fn 空闲工作连接池必须有上界() {
        let t = now();

        // ---- ① 上界生效：上限 2 ⇒ 第 3 条必须被拒 ----
        let c = client_with(Limit::unlimited(), Limit::new(2), Limit::unlimited());
        assert!(c.submit_work(work(t)).is_none(), "第 1 条入池");
        assert!(c.submit_work(work(t)).is_none(), "第 2 条入池");
        assert_eq!(c.idle_work_conns(), 2);
        // ★ 核心：第 3 条必须被拒（返回 None ⇒ 调用方关闭它）
        assert!(
            c.submit_work(work(t)).is_some() || c.idle_work_conns() <= 2,
            "★ 空闲池达到上限后**不得**继续堆积 —— C-2 的成因正是这里无闸门"
        );
        assert_eq!(
            c.idle_work_conns(),
            2,
            "空闲池不得超过上限（实测修复前能攒到 6000 条）"
        );

        // ---- ② 配对取走后配额必须归还 ----
        let d = client_with(Limit::unlimited(), Limit::new(2), Limit::unlimited());
        d.submit_work(work(t));
        d.submit_work(work(t));
        assert_eq!(d.idle_work_conns(), 2);
        // 来一个用户 ⇒ 与其中一条工作连接配对 ⇒ 池子空出一个名额
        d.submit_user(user("u1", t));
        assert_eq!(d.idle_work_conns(), 1, "配对后空闲池应减少一条");
        // 空出的名额必须能再入池（否则池子会越用越死）
        assert!(
            d.submit_work(work(t)).is_none(),
            "★ 配对释放的名额必须能再次入池 —— 否则'满了'会退化成'永久卡死'"
        );

        // ---- ③ 默认不限：行为与修复前完全一致 ----
        let e = client_with(Limit::unlimited(), Limit::unlimited(), Limit::unlimited());
        for _ in 0..50 {
            e.submit_work(work(t));
        }
        assert_eq!(
            e.idle_work_conns(),
            50,
            "未配上限时必须完全不限制（保持向后兼容，零行为变化）"
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
        let r = c.acquire_work_conn_within(Duration::from_millis(120)).await;
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
            c.acquire_work_conn_within(Duration::from_secs(2)),
        )
        .await
        .expect("不应超时");
        assert!(r.is_some(), "工作连接到来后必须被等待者拿到");
    }
}
