//! 全局注册表：客户端、端口占用、虚拟主机路由表、visitor 表。
//!
//! 一个服务端进程只有一份 [`Registry`]，所有入口（控制/工作/visitor/vhost）
//! 都通过它查找目标。这里同时持有全局资源上限与指标收集器。

use std::{
    collections::{hash_map::Entry, HashMap},
    sync::atomic::{AtomicUsize, Ordering},
    sync::{Arc, Mutex},
};

use crate::{
    guard::SecurityContext,
    limits::Limit,
    observability::{self, Metrics},
    p2p::P2PHub,
    pool::ClientState,
    vhost::VhostTable,
    visitor::VisitorTable,
};

/// 由配置折算出来的服务端资源上限（`0` 表示不限）。
#[derive(Debug, Clone, Default)]
pub struct ServerLimits {
    /// 跨所有客户端的同时活跃转发连接数上限（0 = 不限）。
    pub max_total_conns: usize,
    /// 同时在线的客户端数上限（0 = 不限）。
    pub max_clients: usize,
    /// 单客户端同时活跃转发连接数上限（0 = 不限）。
    pub max_conns_per_client: usize,
    /// 单客户端待配对队列长度上限（0 = 不限）。
    pub max_pending_per_client: usize,
    /// 单客户端可注册的代理数上限（0 = 不限）。
    pub max_proxies_per_client: usize,
}

impl ServerLimits {
    /// 派生出单客户端用的三档上限。
    pub fn per_client(&self) -> (Limit, Limit, Limit) {
        (
            Limit::new(self.max_conns_per_client),
            Limit::new(self.max_pending_per_client),
            Limit::new(self.max_proxies_per_client),
        )
    }
}

/// 一个在线客户端的只读快照（面板展示用，不持有任何句柄）。
#[derive(Debug, Clone)]
pub struct ClientInfo {
    pub run_id: String,
    pub client_id: String,
    pub user: String,
    pub proxies: Vec<String>,
    /// 正在排队等工作连接的用户连接数。
    pub backlog: usize,
    /// 池里空闲的工作连接数。
    pub idle_work_conns: usize,
    /// 这个客户端能不能接受面板的管理命令（增删代理）。
    ///
    /// 官方 frpc 不会协商这个能力，所以永远是 false —— 面板据此把按钮
    /// 置灰并给出解释，而不是让用户点了才发现没反应。
    pub managed: bool,
}

pub struct Registry {
    clients: Mutex<HashMap<String, Arc<ClientState>>>,
    /// TCP + UDP 共用一份端口占用表，避免同一个端口号被两种协议同时申领。
    ///
    /// 值不是简单的"占用标记"，而是该端口背后的**一组客户端** ——
    /// 同 `group` 的多个代理可以共享一个端口，用户连接按轮询分摊到它们身上。
    ports: Mutex<HashMap<u16, PortGroup>>,
    /// HTTP / HTTPS 虚拟主机路由表（启动时若配置了 vhost 端口才挂上）。
    vhosts: Mutex<Option<Arc<VhostTable>>>,
    /// stcp / xtcp 的 visitor 接入表（始终可用，不需要额外端口配置）。
    pub visitors: Arc<VisitorTable>,
    /// 全局转发连接数上限。
    pub conn_limit: Limit,
    /// 客户端数上限。
    pub client_limit: Limit,
    /// 指标收集器。
    pub observ: observability::Registry,
    /// xtcp 打洞的牵线中心；未配置 `p2p_port` 时为 None（xtcp 自动退化成中继）。
    p2p: Mutex<Option<Arc<P2PHub>>>,
    /// VirtualNet 的转发中枢；未配置 `vnet_port` 时为 None。
    vnet: Mutex<Option<Arc<crate::vnet::VnetHub>>>,
    limits: ServerLimits,
    /// 安全上下文：认证 / IP 白黑名单 / 角色权限 / 审计日志。
    ///
    /// 放在 `Mutex<Arc<..>>` 而不是 `Arc<..>` 里，是为了让**配置热重载**
    /// 能整体换掉它（改 AclConfig / 审计路径都不该要求重启）。
    /// 读侧只取一次锁再克隆 Arc，热路径上没有额外开销。
    security: Mutex<Arc<SecurityContext>>,
}

impl Registry {
    pub fn new(limits: ServerLimits) -> Self {
        Self {
            clients: Mutex::new(HashMap::new()),
            ports: Mutex::new(HashMap::new()),
            vhosts: Mutex::new(None),
            visitors: Arc::new(VisitorTable::default()),
            conn_limit: Limit::new(limits.max_total_conns),
            client_limit: Limit::new(limits.max_clients),
            observ: observability::Registry::new(),
            p2p: Mutex::new(None),
            vnet: Mutex::new(None),
            limits,
            // 默认上下文 = 不做认证/不限权限/不审计，行为与引入这套东西之前完全一致
            security: Mutex::new(Arc::new(SecurityContext::default())),
        }
    }

    /// 取当前安全上下文（克隆 Arc，几乎零成本）。
    pub fn security(&self) -> Arc<SecurityContext> {
        self.security
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }

    /// 整体替换安全上下文（启动时装载配置 / 热重载）。
    pub fn set_security(&self, ctx: Arc<SecurityContext>) {
        *self.security.lock().unwrap_or_else(|e| e.into_inner()) = ctx;
    }

    /// 审计日志句柄。
    pub fn audit(&self) -> Arc<crate::audit::AuditLog> {
        self.security().audit.clone()
    }

    /// 不限制任何资源的注册表（测试与默认配置用）。
    pub fn unlimited() -> Self {
        Self::new(ServerLimits::default())
    }

    pub fn limits(&self) -> &ServerLimits {
        &self.limits
    }

    pub fn metrics(&self) -> Arc<Metrics> {
        self.observ.metrics()
    }

    /// 挂上 xtcp 牵线中心（只有配置了 `p2p_port` 时才调）。
    pub fn attach_p2p(&self, hub: Arc<P2PHub>) {
        *self.p2p.lock().unwrap_or_else(|e| e.into_inner()) = Some(hub);
    }

    /// 取牵线中心；None 表示未启用 P2P。
    pub fn p2p(&self) -> Option<Arc<P2PHub>> {
        self.p2p.lock().unwrap_or_else(|e| e.into_inner()).clone()
    }

    /// 挂上 VirtualNet 转发中枢（只有配置了 `vnet_port` 时才调）。
    pub fn attach_vnet(&self, hub: Arc<crate::vnet::VnetHub>) {
        *self.vnet.lock().unwrap_or_else(|e| e.into_inner()) = Some(hub);
    }

    /// 取 VirtualNet 中枢；None 表示未启用虚拟网络。
    pub fn vnet(&self) -> Option<Arc<crate::vnet::VnetHub>> {
        self.vnet.lock().unwrap_or_else(|e| e.into_inner()).clone()
    }

    pub fn attach_vhosts(&self, table: Arc<VhostTable>) {
        *self.vhosts.lock().unwrap_or_else(|e| e.into_inner()) = Some(table);
    }

    pub fn vhosts(&self) -> Option<Arc<VhostTable>> {
        self.vhosts
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }

    /// 尝试登记一个客户端；超出 `max_clients` 时返回 `None`。
    pub fn insert(&self, client: Arc<ClientState>) -> Option<LimitGuard> {
        let permit = self.client_limit.try_acquire()?;
        self.clients
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(client.run_id.clone(), client);
        self.metrics().clients_total.inc();
        self.metrics().clients_active.inc();
        Some(LimitGuard(Some(permit)))
    }

    pub fn get(&self, run_id: &str) -> Option<Arc<ClientState>> {
        self.clients
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(run_id)
            .cloned()
    }

    /// 按 `run_id` 取一个在线客户端（面板管理操作用）。
    pub fn client(&self, run_id: &str) -> Option<Arc<ClientState>> {
        self.clients
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(run_id)
            .cloned()
    }

    pub fn remove(&self, run_id: &str) -> Option<Arc<ClientState>> {
        let c = self
            .clients
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(run_id);
        if let Some(c) = &c {
            // 这个客户端被回收时还挂着几个代理，`proxies_active` 就得减几个。
            //
            // 客户端**主动**关代理走的是 `CloseProxy`，那条路径自己已经减过了；
            // 但被 kill / 断网时它根本发不出这条消息，只有这里能兜底 ——
            // 否则面板上的"生效代理"只增不减，跑几天全是水分。
            // 必须趁 `stop()` 清空名册**之前**取数，之后再取永远是 0。
            let outstanding = c.proxy_names().len() as i64;
            c.stop();
            if outstanding > 0 {
                self.metrics().proxies_active.add(-outstanding);
            }
            // 客户端的 http/https 域名要一并回收，否则域名会一直被占着
            if let Some(t) = self.vhosts() {
                t.unregister_client(c);
            }
            // stcp / xtcp 的代理名同理
            self.visitors.unregister_client(c);
            // 它占的公网端口（含 group 成员身份）也要收回
            self.release_ports_of(c);
            self.metrics().clients_active.dec();
        }
        c
    }

    pub fn client_count(&self) -> usize {
        self.clients.lock().unwrap_or_else(|e| e.into_inner()).len()
    }

    /// 占用端口（或加入某个 group 共享它）。
    ///
    /// 规则与官方 frps 一致：
    /// - 端口没人用 -> 占用成功，并记下 group 名（返回 [`PortClaim::Fresh`]）；
    /// - group 名相同 -> 视为同一组，追加一个后端（返回 [`PortClaim::Joined`]）；
    /// - group 名不同（或已有的是独占端口）-> 冲突。
    ///
    /// 返回值决定调用方要不要 bind 监听器 —— 见 [`PortClaim`]。
    pub fn reserve_port(
        &self,
        port: u16,
        group: &str,
        proxy_name: &str,
        client: Arc<ClientState>,
    ) -> Result<PortClaim, String> {
        let mut g = self.ports.lock().unwrap_or_else(|e| e.into_inner());
        match g.entry(port) {
            Entry::Vacant(v) => {
                v.insert(PortGroup::new(group, client, proxy_name));
                Ok(PortClaim::Fresh)
            }
            Entry::Occupied(mut o) => {
                let pg = o.get_mut();
                // 只有"两边都是非空且同名的组"才能共享端口。
                // 空 group 表示这个代理**不参与**分组，语义上就是独占 ——
                // 早先这里只比 `pg.name != group`，于是两个都没配 group 的代理
                // 反而被当成同组，端口冲突检测直接失效。
                let err = if pg.name.is_empty() {
                    Some(format!("端口 {port} 已被占用（另一个代理正在独占使用它）"))
                } else if group.is_empty() {
                    Some(format!(
                        "端口 {port} 已被组 [{}] 占用，未指定 group 的代理不能共享它",
                        pg.name
                    ))
                } else if pg.name != group {
                    Some(format!(
                        "端口 {port} 已被组 [{}] 占用，与组 [{group}] 不同",
                        pg.name
                    ))
                } else {
                    None
                };
                match err {
                    Some(e) => Err(e),
                    None => {
                        pg.push(client, proxy_name);
                        Ok(PortClaim::Joined)
                    }
                }
            }
        }
    }

    /// 把某个端口的监听器交给注册表托管。
    ///
    /// 调用方（`register_tcp` / `register_udp`）在 `PortClaim::Fresh` 的路径上
    /// bind 成功后调它。之后监听器的存活就只跟"端口还有没有后端"有关，
    /// 与创建它的那个客户端是否掉线无关。
    pub fn attach_listener(&self, port: u16, handle: tokio::task::AbortHandle) {
        if let Some(pg) = self
            .ports
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get_mut(&port)
        {
            pg.handle = Some(handle);
        }
    }

    /// 归还端口；同组还有其他后端时只是把自己摘掉。
    ///
    /// `proxy_name` 是**配置里的原始名**（本地表用的那个），用于在组里精确定位
    /// 要摘掉的那一个成员 —— 同一客户端可能在这个端口上注册了多个组的成员。
    pub fn release_port(&self, port: u16, client: &Arc<ClientState>, proxy_name: &str) {
        let mut g = self.ports.lock().unwrap_or_else(|e| e.into_inner());
        let mut empty = false;
        if let Some(pg) = g.get_mut(&port) {
            pg.remove(client, proxy_name);
            empty = pg.is_empty();
        }
        // 最后一个后端走了，端口和它的监听器一起收回
        if empty {
            if let Some(pg) = g.remove(&port) {
                pg.abort_listener();
            }
        }
    }

    /// 客户端掉线时把它占的所有端口一次性收回（不用记住它注册过哪些端口）。
    pub fn release_ports_of(&self, client: &Arc<ClientState>) {
        let mut g = self.ports.lock().unwrap_or_else(|e| e.into_inner());
        let mut dead: Vec<u16> = Vec::new();
        for (port, pg) in g.iter_mut() {
            pg.remove_all_of(client);
            if pg.is_empty() {
                dead.push(*port);
            }
        }
        for port in dead {
            if let Some(pg) = g.remove(&port) {
                pg.abort_listener();
            }
        }
    }

    /// 选一个后端：**在途连接最少**的那个（group 负载均衡）。
    ///
    /// 只有一个成员时就是"取它自己"。多成员时挑选会向空闲的后端倾斜 ——
    /// 各后端处理能力不一样时，纯轮询会把慢的那个压死。
    ///
    /// 返回的 [`Backend`] 里带着一份 [`LoadGuard`]：`pick` 的调用方必须把它
    /// 存进 `PendingUser::load`，本次转发结束时才会自动减回去。
    pub fn pick(&self, port: u16) -> Option<Backend> {
        let g = self.ports.lock().unwrap_or_else(|e| e.into_inner());
        g.get(&port)?.pick()
    }

    /// 取一个后端并**立刻记一条在途连接**。
    ///
    /// 与 [`Registry::pick`] 的差别就是这一步记账：监听器拿到后端之后
    /// 总归要建 PendingUser，不如在这里一次做完，免得漏。
    pub fn pick_and_hold(&self, port: u16) -> Option<(Backend, LoadGuard)> {
        let b = self.pick(port)?;
        let g = b.hold();
        Some((b, g))
    }

    /// 某个端口背后各后端的在途连接数（面板展示 + 调度自测用）。
    pub fn backend_loads(&self, port: u16) -> Vec<(String, usize)> {
        self.ports
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(&port)
            .map(|pg| {
                pg.members
                    .iter()
                    .map(|b| (b.proxy_name.clone(), b.inflight()))
                    .collect()
            })
            .unwrap_or_default()
    }

    /// 某个端口背后有几个后端（面板展示用）。
    pub fn backend_count(&self, port: u16) -> usize {
        self.ports
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(&port)
            .map(|pg| pg.len())
            .unwrap_or(0)
    }

    /// 全部在线客户端的快照（面板 / API 展示用）。
    pub fn clients(&self) -> Vec<ClientInfo> {
        self.clients
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .values()
            .map(|c| ClientInfo {
                run_id: c.run_id.clone(),
                client_id: c.client_id.clone(),
                user: c.user.clone(),
                proxies: c.proxy_names(),
                backlog: c.backlog(),
                idle_work_conns: c.idle_work_conns(),
                managed: c.caps().server_cmd,
            })
            .collect()
    }

    /// 按客户端 `run_id` 直接取出组里某个后端（**仅测试用**）。
    ///
    /// 生产路径永远走 [`Registry::pick`]；测试要"人为把某个后端的在途数压高"，
    /// 而 `pick` 只会挑最闲的那个，拿不到指定的成员，只能开这个口子。
    #[cfg(test)]
    pub(crate) fn backend_of(&self, port: u16, run_id: &str) -> Option<Backend> {
        self.ports
            .lock()
            .unwrap()
            .get(&port)?
            .members
            .iter()
            .find(|b| b.client.run_id == run_id)
            .cloned()
    }

    /// 当前占用的公网端口列表（dashboard 展示用）。
    pub fn reserved_ports(&self) -> Vec<u16> {
        let mut v: Vec<u16> = self
            .ports
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .keys()
            .copied()
            .collect();
        v.sort_unstable();
        v
    }
}

/// 一个后端：某个客户端 + 它**自己**为这条代理起的名字。
///
/// 代理名必须随后端一起走，不能沿用"创建监听器那个成员"的名字 ——
/// 服务端就是用这个名字在 `StartWorkConn` 里告诉客户端"你该服务哪条代理"，
/// 组内各成员的 `name` 完全可以不一样（`alice.web-a` / `bob.web-b`）。
#[derive(Clone)]
pub struct Backend {
    pub client: Arc<ClientState>,
    pub proxy_name: String,
    /// 这个后端当前扛着几条**在途**连接。
    ///
    /// "在途"指的是从 `pick` 选中它、到这条转发彻底结束（或被拒）为止 ——
    /// 排队等工作连接的时间也算，因为那同样占着这个后端的能力。
    load: Arc<Load>,
}

impl Backend {
    /// 当前在途连接数（面板 / 测试用）。
    pub fn inflight(&self) -> usize {
        self.load.inflight.load(Ordering::Relaxed)
    }

    /// 拿一份计数令牌：只要它还活着，本次转发就记在这个后端头上。
    pub fn hold(&self) -> LoadGuard {
        self.load.inflight.fetch_add(1, Ordering::Relaxed);
        LoadGuard(self.load.clone())
    }
}

/// 后端的在途连接计数。组内每个成员各有一份。
#[derive(Default)]
struct Load {
    inflight: AtomicUsize,
}

/// 在途计数的归还令牌。
///
/// 靠 `Drop` 归还而不是让调用方手动减 —— 转发路径上有好几个提前 return /
/// 被拒 / panic 的出口，手动减迟早漏一处，一漏这个后端的计数就永久偏高，
/// 调度器从此再也不把流量分给它。
pub struct LoadGuard(Arc<Load>);

impl Drop for LoadGuard {
    fn drop(&mut self) {
        // 减到 0 就停： saturating 防止异常路径上多减一次把计数打到 usize::MAX
        self.0
            .inflight
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |v| {
                Some(v.saturating_sub(1))
            })
            .ok();
    }
}

/// 两个 `ClientState` 是不是**同一个控制会话**。
///
/// 同一个连接上的对象必然 `Arc::ptr_eq`；跨重连时靠 `run_id` 认亲
/// （`run_id` 由服务端在 `LoginResp` 里下发，同一次会话内不变）。
///
/// ★ 注意这是"客户端级"的判据，**不能**用来判断"同一个代理" ——
/// 一个客户端可以注册多个代理，判代理要再加上 `proxy_name`。
fn same_client(a: &Arc<ClientState>, b: &Arc<ClientState>) -> bool {
    Arc::ptr_eq(a, b) || a.run_id == b.run_id
}

/// 端口申领的结果。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PortClaim {
    /// 这个端口之前没人占：调用方**必须**去 bind 监听器，再交回
    /// [`Registry::attach_listener`]。
    Fresh,
    /// 加入了已存在的 group：监听器已经在跑了，**不要再 bind**。
    ///
    /// 再 bind 一次必然返回 `Address already in use`，于是组里永远只有
    /// 第一个成员能成为后端 —— 那正是"配了 group 却完全不负载均衡"的根因。
    Joined,
}

/// 一个公网端口背后的后端集合。
///
/// `name` 为空表示这个端口被**独占**（普通代理）；非空表示同组共享，
/// 用户连接会在成员之间轮询 —— 这就是 group 负载均衡。
struct PortGroup {
    name: String,
    members: Vec<Backend>,
    /// 轮询游标。用 `fetch_add` 取模，天然无锁。
    cursor: std::sync::atomic::AtomicUsize,
    /// 该端口的监听器任务。
    ///
    /// 归**端口**所有而不是归某个客户端：组里还有别的成员时，
    /// 创建监听器的那个成员掉线不能把整个端口一起带走。
    handle: Option<tokio::task::AbortHandle>,
}

impl PortGroup {
    fn new(name: &str, client: Arc<ClientState>, proxy_name: &str) -> Self {
        Self {
            name: name.to_string(),
            members: vec![Backend {
                client,
                proxy_name: proxy_name.to_string(),
                load: Arc::new(Load::default()),
            }],
            cursor: std::sync::atomic::AtomicUsize::new(0),
            handle: None,
        }
    }

    fn push(&mut self, client: Arc<ClientState>, proxy_name: &str) {
        // 同一个代理重复注册（重连 / 重复 NewProxy）不该把成员表撑爆。
        //
        // ★ 去重键必须是 **(客户端, 代理名)**，不能只看客户端。
        // 官方 frp 允许**同一个 frpc** 注册多个同 group 的代理（一份配置里两条
        // `[[proxies]]` 共用一个 remotePort、group 相同），那时两条的 run_id 一样；
        // 早先按 run_id 去重会把兄弟成员一起删掉，于是组里永远只剩最后一个，
        // 表现为"配了 group 却完全不负载均衡"（真机实测：24 次连接全打到同一个后端）。
        self.members
            .retain(|b| !(same_client(&b.client, &client) && b.proxy_name == proxy_name));
        self.members.push(Backend {
            client,
            proxy_name: proxy_name.to_string(),
            load: Arc::new(Load::default()),
        });
    }

    /// 摘掉**某一个**成员（同组其他成员要留着）。
    ///
    /// 与 [`PortGroup::push`] 同理：按 (客户端, 代理名) 精确定位，不能把同一
    /// 客户端的其它 group 成员一起摘掉。
    fn remove(&mut self, client: &Arc<ClientState>, proxy_name: &str) {
        self.members
            .retain(|b| !(same_client(&b.client, client) && b.proxy_name == proxy_name));
    }

    /// 客户端整个掉线时，把它在这个端口上的**所有**成员一次摘掉。
    fn remove_all_of(&mut self, client: &Arc<ClientState>) {
        self.members.retain(|b| !same_client(&b.client, client));
    }

    fn is_empty(&self) -> bool {
        self.members.is_empty()
    }

    fn len(&self) -> usize {
        self.members.len()
    }

    /// 挑一个后端：**在途连接最少的那个**，一样多时再轮着来。
    ///
    /// 纯轮询（`cursor` 取模）在各后端处理能力不一样时会把慢的那个压死：
    /// 慢后端处理一条要 10 秒、快的只要 10 毫秒，但两者分到的请求数一样多，
    /// 于是慢后端前面永远堆着一截队列。改成看在途数之后，
    /// 快的那个自然会分到更多 —— 它手上的连接消得快，计数就一直低。
    ///
    /// ## 为什么从 cursor 开始扫
    ///
    /// 计数相同时必须有个稳定的打破平局的规则，否则每次都挑中同一个成员
    /// （其余成员永远 0 流量）。从 cursor 往后扫，等价于"平局时轮询"，
    /// 既公平又不需要额外状态。
    fn pick(&self) -> Option<Backend> {
        let n = self.members.len();
        if n == 0 {
            return None;
        }
        let mut best = 0usize;
        let mut best_load = self.members[0].inflight();
        // 起点每次挪一格：平局时轮流坐庄
        let start = self.cursor.fetch_add(1, Ordering::Relaxed) % n;
        for k in 1..n {
            let i = (start + k) % n;
            let l = self.members[i].inflight();
            if l < best_load {
                best = i;
                best_load = l;
            }
        }
        // start 那个位置也要参与比较（上面的循环从 start+1 开始扫的）
        let start_load = self.members[start].inflight();
        if start_load <= best_load {
            best = start;
        }
        self.members.get(best).cloned()
    }

    /// 端口彻底空掉时收掉监听器。
    fn abort_listener(&self) {
        if let Some(h) = &self.handle {
            h.abort();
        }
    }
}

/// 客户端在线期间持有的配额令牌；掉要自动归还。
pub struct LimitGuard(#[allow(dead_code)] Option<crate::limits::Permit>);

/// 控制连接退出时自动清理该客户端的全部资源。
pub struct ClientGuard {
    registry: Arc<Registry>,
    run_id: String,
}

impl ClientGuard {
    pub fn new(registry: Arc<Registry>, run_id: String) -> Self {
        Self { registry, run_id }
    }
}

impl Drop for ClientGuard {
    fn drop(&mut self) {
        self.registry.remove(&self.run_id);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pool::{self, CtrlCmd};
    use std::time::Duration;
    use tokio::sync::mpsc;

    fn client(run_id: &str) -> Arc<ClientState> {
        let (tx, rx) = mpsc::unbounded_channel::<CtrlCmd>();
        std::mem::forget(rx);
        let (conn, backlog, proxy) = ServerLimits::default().per_client();
        Arc::new(ClientState::new(
            run_id.into(),
            run_id.into(),
            String::new(),
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

    #[test]
    fn insert_get_remove_lifecycle() {
        let r = Registry::unlimited();
        assert_eq!(r.client_count(), 0);
        let c = client("r1");
        let _guard = r.insert(c.clone()).expect("不限时应能登记");
        assert_eq!(r.client_count(), 1);
        assert!(Arc::ptr_eq(&r.get("r1").unwrap(), &c));
        assert_eq!(r.metrics().clients_active.get(), 1);

        r.remove("r1");
        assert_eq!(r.client_count(), 0);
        assert!(r.get("r1").is_none());
        assert_eq!(r.metrics().clients_active.get(), 0);
        // 未注册的 run_id 删除应当是安全的空操作
        assert!(r.remove("nope").is_none());
    }

    /// 客户端被强杀（没机会发 `CloseProxy`）时，它挂着的代理必须由
    /// `remove` 兜底回收，否则面板上的"生效代理"只增不减。
    ///
    /// 这个 bug 是在云端真机上看出来的：客户端 kill 后重连，
    /// `proxies_active` 停在 3 不回落，而面板明细里只剩 1 个代理。
    #[test]
    fn remove_reclaims_proxies_active_when_client_is_killed() {
        let r = Registry::unlimited();
        let m = r.metrics();
        let c = client("r1");
        let _guard = r.insert(c.clone()).expect("不限时应能登记");

        // 模拟客户端注册了两个代理（只走登记 + 指标，不真起监听）
        for name in ["web", "ssh"] {
            let slot = c.reserve_proxy().expect("默认不限名额");
            c.add_proxy(name.into(), None, slot);
            m.proxies_active.inc();
        }
        assert_eq!(m.proxies_active.get(), 2);

        r.remove("r1");
        assert_eq!(
            m.proxies_active.get(),
            0,
            "客户端断开后 proxies_active 必须回落，否则指标只增不减"
        );
    }

    /// 主动 `CloseProxy` 已经减过一次，`remove` 不能再减一次。
    #[test]
    fn remove_does_not_double_count_closed_proxies() {
        let r = Registry::unlimited();
        let m = r.metrics();
        let c = client("r1");
        let _guard = r.insert(c.clone()).expect("不限时应能登记");

        // 两个代理，其中一个被客户端主动关掉（走 CloseProxy 那条路径）
        for name in ["web", "ssh"] {
            let slot = c.reserve_proxy().expect("默认不限名额");
            c.add_proxy(name.into(), None, slot);
            m.proxies_active.inc();
        }
        c.stop_proxy("ssh");
        m.proxies_active.dec();
        assert_eq!(m.proxies_active.get(), 1);

        r.remove("r1");
        assert_eq!(
            m.proxies_active.get(),
            0,
            "只在册的 1 个代理该被回收，已关掉的那个不能重复扣"
        );
    }

    #[test]
    fn max_clients_is_enforced() {
        let limits = ServerLimits {
            max_clients: 1,
            ..Default::default()
        };
        let r = Registry::new(limits);
        let keep = r.insert(client("a")).expect("第 1 个客户端");
        assert!(
            r.insert(client("b")).is_none(),
            "超过 max_clients 必须拒绝：否则一个脚本能把服务端连满"
        );
        assert_eq!(r.client_count(), 1);
        drop(keep);
        // 令牌归还后又能登记
        assert!(r.insert(client("c")).is_some());
    }

    #[test]
    fn ports_cannot_be_double_reserved() {
        let r = Registry::unlimited();
        let a = client("a");
        let b = client("b");
        assert_eq!(
            r.reserve_port(6000, "", "a", a.clone()).unwrap(),
            PortClaim::Fresh,
            "端口没人占时必须告诉调用方去 bind"
        );
        assert!(
            r.reserve_port(6000, "", "b", b.clone()).is_err(),
            "同一个端口不能被两个代理同时占"
        );
        assert!(r.reserve_port(6001, "", "a", a.clone()).is_ok());
        assert_eq!(r.reserved_ports(), vec![6000, 6001]);
        r.release_port(6000, &a, "a");
        assert!(
            r.reserve_port(6000, "", "b", b.clone()).is_ok(),
            "release 之后应可再次申领"
        );
        // release 一个没占过的端口不应 panic
        r.release_port(65535, &a, "a");
    }

    /// ★ 同一个客户端注册的**多个 group 成员**必须都留在组里。
    ///
    /// 这是真机上抓到的 bug：`PortGroup::push` 早先按 `run_id` 去重，同一次会话的
    /// 第二个成员会把第一个成员删掉，于是组里永远只剩最后一个 —— 表现为
    /// "配了 group 却完全不负载均衡"（实测 24 次连接全打到同一个后端）。
    #[test]
    fn 同一客户端的多个组成员都要留在组里() {
        let r = Registry::unlimited();
        let one = client("same-session");
        assert_eq!(
            r.reserve_port(6000, "web", "a", one.clone()).unwrap(),
            PortClaim::Fresh
        );
        assert_eq!(
            r.reserve_port(6000, "web", "b", one.clone()).unwrap(),
            PortClaim::Joined
        );
        assert_eq!(r.backend_count(6000), 2, "同一客户端的两个成员都要在组里");

        // 摘掉其中一个，另一个必须留着（端口不能跟着收回）
        r.release_port(6000, &one, "a");
        assert_eq!(r.backend_count(6000), 1, "只摘掉指名的那一个成员");

        // 重复注册同一个代理名才应该去重
        r.reserve_port(6000, "web", "b", one.clone()).unwrap();
        assert_eq!(r.backend_count(6000), 1, "同名代理重复注册不该撑大成员表");

        // 整个客户端掉线才清空
        r.release_ports_of(&one);
        assert_eq!(r.backend_count(6000), 0);
    }

    /// group 的全部意义：同名组的多个代理共享一个端口，实现负载均衡。
    #[test]
    fn same_group_shares_one_port() {
        let r = Registry::unlimited();
        // 第一个成员负责 bind
        assert_eq!(
            r.reserve_port(6000, "web", "alice.web-a", client("a"))
                .unwrap(),
            PortClaim::Fresh,
            "组里第一个成员要负责创建监听器"
        );
        // 后续成员**必须**拿到 Joined —— 否则它们会再去 bind 同一端口，
        // 得到 `Address already in use`，组里就永远只剩一个后端。
        assert_eq!(
            r.reserve_port(6000, "web", "bob.web-b", client("b"))
                .unwrap(),
            PortClaim::Joined,
            "同组后续成员不该重复 bind 端口"
        );
        assert_eq!(
            r.reserve_port(6000, "web", "carol.web-c", client("c"))
                .unwrap(),
            PortClaim::Joined
        );
        assert_eq!(r.backend_count(6000), 3, "三个后端都挂在同一个端口上");
    }

    #[test]
    fn different_groups_still_conflict() {
        let r = Registry::unlimited();
        assert!(r.reserve_port(6000, "web", "a", client("a")).is_ok());
        let e = r
            .reserve_port(6000, "api", "b", client("b"))
            .expect_err("不同组不能抢同一个端口");
        assert!(
            e.contains("api") && e.contains("web"),
            "错误信息要说清是谁占了：{e}"
        );

        // 独占端口同样不能被组抢走
        let r2 = Registry::unlimited();
        assert!(r2.reserve_port(7000, "", "a", client("a")).is_ok());
        assert!(r2.reserve_port(7000, "web", "b", client("b")).is_err());
    }

    /// 空闲时轮询：连续取 N 次必须把 N 个后端都轮到一遍。
    ///
    /// 注意这里**不能**持有 `pick` 出来的在途计数（用 `pick` 而不是
    /// `pick_and_hold`），否则第二次取的时候三个后端计数各不相同，
    /// 调度器会一直挑那个最闲的 —— 那是下面那条测试要验的行为。
    #[test]
    fn pick_round_robins_over_group_members() {
        let r = Registry::unlimited();
        for n in ["a", "b", "c"] {
            assert!(r.reserve_port(6000, "web", n, client(n)).is_ok());
        }
        // 一轮 3 次，每个后端各一次
        let mut seen = std::collections::HashSet::new();
        for _ in 0..3 {
            seen.insert(r.pick(6000).expect("应有后端").client.run_id.clone());
        }
        assert_eq!(seen.len(), 3, "三轮必须轮到三个不同的后端：{seen:?}");

        // 再走一轮，同样要覆盖全部后端
        let second: Vec<String> = (0..3)
            .map(|_| r.pick(6000).unwrap().client.run_id.clone())
            .collect();
        assert_eq!(
            second
                .iter()
                .collect::<std::collections::HashSet<_>>()
                .len(),
            3,
            "第二轮同样要覆盖全部后端：{second:?}"
        );
        assert!(r.pick(9999).is_none(), "没占过的端口不该有后端");
    }

    /// 负载不均时必须往空闲的后端倾斜 —— 这是最小连接数调度的全部意义。
    ///
    /// 场景：a 手上还压着 5 条没结束的转发，b 一条都没有。
    /// 纯轮询会把第 6 条照样分给 a（各 50%），最小连接数则应当全给 b。
    #[test]
    fn pick_prefers_the_least_loaded_backend() {
        let r = Registry::unlimited();
        for n in ["a", "b"] {
            assert!(r.reserve_port(6100, "web", n, client(n)).is_ok());
        }
        // 直接给 a 挂 5 条在途连接（令牌**留着**不 drop，计数才一直在）
        let a = r.backend_of(6100, "a").expect("组里应当有 a");
        let held: Vec<_> = (0..5).map(|_| a.hold()).collect();
        assert_eq!(a.inflight(), 5, "a 的在途数必须是 5");

        // 之后的每一次挑选都应当落在 b 上
        for _ in 0..6 {
            let b = r.pick(6100).expect("应有后端");
            assert_eq!(b.client.run_id, "b", "a 压着 5 条，新流量必须全给 b");
            drop(b.hold()); // 立刻还回去，b 的计数始终是 0
        }
        drop(held);
        assert_eq!(
            r.backend_loads(6100).iter().map(|(_, v)| *v).sum::<usize>(),
            0,
            "令牌全部 drop 之后计数必须归零，否则调度器会永久歧视这个后端"
        );
    }

    /// 令牌必须**自动**归还：`pick_and_hold` 出来的计数不能泄漏。
    ///
    /// 这是最容易写错的地方 —— 转发路径上有好几个提前 return / 被拒的出口，
    /// 手动减迟早漏一处。靠 Drop 归还就是为了根治这件事。
    #[test]
    fn load_guard_returns_the_count_on_drop() {
        let r = Registry::unlimited();
        assert!(r.reserve_port(6200, "web", "a", client("a")).is_ok());
        let (b, g) = r.pick_and_hold(6200).expect("应有后端");
        assert_eq!(b.inflight(), 1, "hold 之后立刻是 1");
        drop(g);
        assert_eq!(r.backend_loads(6200)[0].1, 0, "drop 之后必须归零");

        // 多减一次不该把计数打到 usize::MAX（异常路径上可能发生）
        let (b2, g2) = r.pick_and_hold(6200).expect("应有后端");
        drop(g2);
        drop(b2);
        assert_eq!(r.backend_loads(6200)[0].1, 0);
    }

    /// 平局时不能永远挑同一个 —— 要给每个成员机会。
    #[test]
    fn ties_are_broken_round_robin() {
        let r = Registry::unlimited();
        for n in ["a", "b", "c"] {
            assert!(r.reserve_port(6300, "web", n, client(n)).is_ok());
        }
        // 每次取完立刻还回去，三个后端的计数始终都是 0（永远平局）
        let mut seen = std::collections::HashSet::new();
        for _ in 0..6 {
            let (b, g) = r.pick_and_hold(6300).expect("应有后端");
            seen.insert(b.client.run_id.clone());
            drop(g);
        }
        assert_eq!(seen.len(), 3, "一直平局时必须轮流坐庄，实际只轮到 {seen:?}");
    }

    /// **回归**：每个后端要带上**自己**的代理名。
    ///
    /// 服务端是用这个名字在 `StartWorkConn` 里告诉客户端"你该服务哪条代理"，
    /// 组内各成员的 `name` 完全可以不一样。早先 accept 循环用的是
    /// "创建监听器那个成员"的名字，于是轮询到其他成员时，对方根本找不到这条代理。
    #[test]
    fn picked_backend_carries_its_own_proxy_name() {
        let r = Registry::unlimited();
        assert!(r
            .reserve_port(6000, "web", "alice.web-a", client("a"))
            .is_ok());
        assert!(r
            .reserve_port(6000, "web", "bob.web-b", client("b"))
            .is_ok());

        // 每个 run_id 对应哪条代理名，是我们注册时指定的，一一对上才算对
        let expect = |run_id: &str| match run_id {
            "a" => "alice.web-a",
            "b" => "bob.web-b",
            other => panic!("出现了没注册过的客户端：{other}"),
        };
        let mut seen = std::collections::HashSet::new();
        for _ in 0..2 {
            let b = r.pick(6000).expect("应有后端");
            assert_eq!(
                b.proxy_name,
                expect(&b.client.run_id),
                "轮询到的后端必须带着它**自己**的代理名"
            );
            seen.insert(b.proxy_name);
        }
        assert_eq!(seen.len(), 2, "两条连接应落到两个不同的代理名上：{seen:?}");
    }

    #[tokio::test]
    async fn releasing_one_member_keeps_the_port_alive() {
        let r = Registry::unlimited();
        let a = client("a");
        let b = client("b");
        assert!(r.reserve_port(6000, "web", "a", a.clone()).is_ok());
        assert!(r.reserve_port(6000, "web", "b", b.clone()).is_ok());
        // 第一个成员（也就是创建监听器的那个）先挂着监听器
        let (_tx, rx) = tokio::sync::oneshot::channel::<()>();
        let h = tokio::spawn(async move {
            let _ = rx.await;
        });
        r.attach_listener(6000, h.abort_handle());

        r.release_port(6000, &a, "a");
        assert_eq!(r.backend_count(6000), 1, "只摘掉一个，端口还得继续服务");
        assert!(r.reserved_ports().contains(&6000));
        assert!(
            !h.is_finished(),
            "组里还有成员在服务，创建者掉线不能把监听器一起带走"
        );

        r.release_port(6000, &b, "b");
        assert!(
            !r.reserved_ports().contains(&6000),
            "最后一个后端走了，端口必须释放"
        );
        // abort 是异步生效的，给它一点时间（也让出线程给被 abort 的任务）
        for _ in 0..50 {
            if h.is_finished() {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        assert!(h.is_finished(), "端口空掉后监听器必须被收掉");
    }

    #[test]
    fn removing_a_client_reclaims_all_its_ports() {
        let r = Registry::unlimited();
        let a = client("a");
        let b = client("b");
        assert!(r.reserve_port(6000, "web", "a", a.clone()).is_ok());
        assert!(r.reserve_port(6001, "", "a", a.clone()).is_ok());
        assert!(r.reserve_port(6000, "web", "b", b.clone()).is_ok());

        // 客户端掉线：它占的端口要全部收回，同组其他后端不受影响
        r.release_ports_of(&a);
        assert!(!r.reserved_ports().contains(&6001), "独占端口应被释放");
        assert_eq!(r.backend_count(6000), 1, "组里只剩另一个后端");
        assert_eq!(r.pick(6000).unwrap().client.run_id, b.run_id);
    }

    /// 同一个客户端重连时重复注册，不该把成员表越撑越大。
    #[test]
    fn reregistration_does_not_duplicate_members() {
        let r = Registry::unlimited();
        let a = client("a");
        for _ in 0..3 {
            assert!(r.reserve_port(6000, "web", "a", a.clone()).is_ok());
        }
        assert_eq!(
            r.backend_count(6000),
            1,
            "同一 run_id 重复注册应视作同一个后端"
        );
    }

    #[test]
    fn vhost_table_is_optional() {
        let r = Registry::unlimited();
        assert!(r.vhosts().is_none());
        r.attach_vhosts(Arc::new(VhostTable::default()));
        assert!(r.vhosts().is_some());
    }

    #[test]
    fn removing_client_reclaims_its_domains_and_visitors() {
        let r = Registry::unlimited();
        let table = Arc::new(VhostTable::default());
        r.attach_vhosts(table.clone());
        let c = client("reap1");
        r.insert(c.clone()).expect("登记");

        use crate::vhost::VhostRoute;

        table
            .register(Arc::new(VhostRoute {
                proxy_name: "web".into(),
                client: c.clone(),
                domain: "a.example.com".into(),
                locations: vec!["/".into()],
                http_user: String::new(),
                http_pwd: String::new(),
                route_by_http_user: String::new(),
                rewrite_host: String::new(),
                req_headers: Default::default(),
                resp_headers: Default::default(),
                is_https: false,
            }))
            .expect("注册域名");
        assert!(table.lookup("a.example.com", "/", None, false).is_some());

        r.remove("reap1");
        assert!(
            table.lookup("a.example.com", "/", None, false).is_none(),
            "客户端断开后它的域名必须回收，否则别人再也注册不了这个域名"
        );
    }

    #[test]
    fn per_client_limits_derive_from_config() {
        let limits = ServerLimits {
            max_conns_per_client: 5,
            max_pending_per_client: 7,
            max_proxies_per_client: 3,
            ..Default::default()
        };
        let (conn, backlog, proxy) = limits.per_client();
        assert_eq!(conn.max(), 5);
        assert_eq!(backlog.max(), 7);
        assert_eq!(proxy.max(), 3);
        // 配置为 0 时应不限制
        let (c2, b2, p2) = ServerLimits::default().per_client();
        assert!(!c2.is_enabled() && !b2.is_enabled() && !p2.is_enabled());
        let _ = pool::dummy_client("unused");
    }
}
