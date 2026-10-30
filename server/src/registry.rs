//! 全局注册表：客户端、端口占用、虚拟主机路由表、visitor 表。
//!
//! 一个服务端进程只有一份 [`Registry`]，所有入口（控制/工作/visitor/vhost）
//! 都通过它查找目标。这里同时持有全局资源上限与指标收集器。

use std::{
    collections::{hash_map::Entry, HashMap},
    sync::atomic::{AtomicU8, AtomicUsize, Ordering},
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
use nfrp_common::plugin::PluginManager;
use tracing::debug;

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
    /// group 负载均衡策略。
    ///
    /// 放 `AtomicU8` 而不是 `Mutex`：热路径上每次用户连接都要读它，
    /// 而它只在启动 / 热重载时写一次。用原子量避免在 `pick` 里多取一把锁。
    lb_policy: AtomicU8,
    /// 官方 `[[httpPlugins]]`。热重载时整体换掉，读侧克隆 `Arc`。
    plugins: Mutex<Arc<PluginManager>>,
    /// NLink v1 的运行期状态（限流器 / 敲门放行表 / 续传表 / 身份密钥）。
    ///
    /// 默认是「全关」的实例：未配置 `[nlink]` 时，`enabled_mask()` 返回 `None`，
    /// 握手阶段连协商都不会发生 —— 行为与 0.6.x 逐字节一致。
    nlink: Mutex<Arc<crate::nlink::NLinkRuntime>>,
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
            // 默认轮询：与官方 frp 的 group 行为一致
            lb_policy: AtomicU8::new(LbPolicy::RoundRobin as u8),
            plugins: Mutex::new(Arc::new(PluginManager::default())),
            nlink: Mutex::new(Arc::new(crate::nlink::NLinkRuntime::disabled())),
        }
    }

    /// 取当前 NLink 运行期状态（克隆 Arc，零成本）。
    pub fn nlink(&self) -> Arc<crate::nlink::NLinkRuntime> {
        self.nlink.lock().unwrap_or_else(|e| e.into_inner()).clone()
    }

    /// 整体替换 NLink 运行期状态（启动装载 / 配置热重载）。
    pub fn set_nlink(&self, rt: Arc<crate::nlink::NLinkRuntime>) {
        *self.nlink.lock().unwrap_or_else(|e| e.into_inner()) = rt;
    }

    /// 安装 / 替换 HTTP 插件集合（启动装载与配置热重载共用）。
    pub fn set_plugins(&self, plugins: Arc<PluginManager>) {
        *self.plugins.lock().unwrap_or_else(|e| e.into_inner()) = plugins;
    }

    /// 取当前 HTTP 插件集合。
    pub fn plugins(&self) -> Arc<PluginManager> {
        self.plugins
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
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
    /// - group 名相同**且 group_key 相同** -> 视为同一组，追加一个后端（返回 [`PortClaim::Joined`]）；
    /// - group 名不同（或已有的是独占端口）-> 冲突；
    /// - group 名相同但 group_key 不同 -> 认证失败（对应官方 `ErrGroupAuthFailed`）。
    ///
    /// ★ `group_key` 是**认证凭据**而非标签：只比对组名会让任何知道组名的客户端
    /// 混入他人的负载均衡组、分走该端口的流量份额（跨租户流量劫持）。
    /// 官方的 `TCPGroup.Listen` 在加入分支上做同样的校验。
    ///
    /// 返回值决定调用方要不要 bind 监听器 —— 见 [`PortClaim`]。
    pub fn reserve_port(
        &self,
        port: u16,
        group: &str,
        group_key: &str,
        proxy_name: &str,
        client: Arc<ClientState>,
    ) -> Result<PortClaim, String> {
        let mut g = self.ports.lock().unwrap_or_else(|e| e.into_inner());
        match g.entry(port) {
            Entry::Vacant(v) => {
                v.insert(PortGroup::new(group, group_key, client, proxy_name));
                Ok(PortClaim::Fresh)
            }
            Entry::Occupied(mut o) => {
                let pg = o.get_mut();
                // 只有"两边都是非空且同名的组"才能共享端口。
                // 空 group 表示这个代理**不参与**分组，语义上就是独占 ——
                // 早先这里只比 `pg.name != group`，于是两个都没配 group 的代理
                // 反而被当成同组，端口冲突检测直接失效。
                //
                // ★★ v0.5.6 修（审计总报告 L14，低危）：**错误文案统一，不再区分原因**。
                //
                // 原先这里有**四种**可区分的文案，对未认证 / 低权限的调用方构成
                // 一个**枚举预言机**：
                //
                // | 返回的文案 | 泄露的信息 |
                // |---|---|
                // | "已被占用（另一个代理正在独占使用它）" | 该端口有人独占 |
                // | "已被组 [X] 占用，未指定 group 的代理不能共享它" | **组名 X** |
                // | "已被组 [X] 占用，与组 [Y] 不同" | **组名 X** |
                // | "组 [Y] 的 group_key 校验失败" | 组名存在且**组名猜对了** |
                //
                // ⇒ 攻击者逐个猜组名：只有"组名猜对"才会拿到第 4 条，
                //   于是**组名可枚举** —— 而组名正是官方 group 负载均衡的
                //   唯一共享凭据名。
                //
                // ★ 与下面 `constant_time_eq` 的意图自相矛盾：那行注释写着
                //   "用常量时间比较，避免按字节泄露密钥前缀" —— 定长比较挡住了
                //   逐字节试探，**却用错误文案把整个组名送了出去**。
                //   又是一次"防线写对了、但同一件事的另一半没铺满"。
                //
                // ★ 修法：所有失败原因共用**一条**文案（只承认"端口被占用"，
                //   既不说是谁占的、也不说组名对不对）。
                //   真正需要区分原因的只有服务端日志 —— 那走 `debug!`，不外泄。
                let reason = if pg.name.is_empty() {
                    "被另一个代理独占"
                } else if group.is_empty() {
                    "未指定 group 的代理不能共享"
                } else if pg.owner_user != client.user {
                    // ★★ v0.5.7 修（第六轮审计 D-1，高危）：**跨租户一律拒绝**。
                    //
                    // 原先这里没有这一条：判定只看 (组名, group_key)，
                    // 于是"知道组名"就能把工作连接挂到别人的公网端口上，
                    // 用户流量按轮询分给攻击者 —— 实测 6/12 条被劫持，
                    // 攻击者的内网服务收到了用户的请求（凭证收割 + 响应伪造）。
                    //
                    // 放在 `name != group` **之前**：这是更根本的理由
                    // （"这不是你的组"比"组名不同"更准确），
                    // 且与其它分支共用同一条对外文案，不新增可区分信息。
                    "跨租户不能共享端口"
                } else if pg.name != group {
                    "与占用方的 group 不同"
                } else if !nfrp_common::frp::msg::constant_time_eq(&pg.key, group_key) {
                    // 组名对得上但密钥不对 —— 与官方 ErrGroupAuthFailed 同义。
                    // 用常量时间比较，避免按字节泄露密钥前缀。
                    "group_key 校验失败"
                } else {
                    debug!(port, group = %group, "端口共享成功（同组、同租户且密钥正确）");
                    pg.push(client, proxy_name);
                    return Ok(PortClaim::Joined);
                };
                // 细节只进服务端日志（运维排查"为什么端口共享不上"需要它），
                // 回给调用方的文案**不含任何组名 / 占用者信息**。
                debug!(
                    port,
                    requested_group = %group,
                    reason,
                    "端口占用判定失败（细节仅服务端可见）"
                );
                Err(format!(
                    "端口 {port} 已被占用（可能与 group / group_key 配置有关，\
                     详情见服务端日志）"
                ))
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

    /// 选一个后端（按当前负载均衡策略）。
    ///
    /// 只有一个成员时就是"取它自己"。
    ///
    /// 策略见 [`LbPolicy`]：默认轮询（与官方一致），可切到最少连接。
    ///
    /// 返回的 [`Backend`] 里带着一份 [`LoadGuard`]：`pick` 的调用方必须把它
    /// 存进 `PendingUser::load`，本次转发结束时才会自动减回去。
    pub fn pick(&self, port: u16) -> Option<Backend> {
        let policy = self.lb_policy();
        let g = self.ports.lock().unwrap_or_else(|e| e.into_inner());
        g.get(&port)?.pick(policy)
    }

    /// 当前负载均衡策略。
    pub fn lb_policy(&self) -> LbPolicy {
        LbPolicy::from_u8(self.lb_policy.load(Ordering::Relaxed))
    }

    /// 设置负载均衡策略（启动时装载配置 / 热重载）。
    pub fn set_lb_policy(&self, p: LbPolicy) {
        self.lb_policy.store(p as u8, Ordering::Relaxed);
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
        // 减到 0 就停：saturating 防止异常路径上多减一次把计数打到 usize::MAX
        //
        // 跨版本兼容：`fetch_update` 在更新的 rustc 里被标记为 deprecated
        // （建议改用 `try_update`），但本地工具链仍是 1.98.1，那里没有
        // `try_update`。CI 用的是最新 stable，两边都得能编译 —— 这里的行为
        // 就是"饱和减一"，用 allow 比写两套 cfg 更清楚。
        #[allow(deprecated)]
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
/// 用户连接会在成员之间按 [`LbPolicy`] 分摊 —— 这就是 group 负载均衡。
struct PortGroup {
    name: String,
    /// 组密钥（`groupKey`）。官方 frps 在第二个成员加入时用 `tg.groupKey != groupKey`
    /// 拒绝不匹配者（`server/group/tcp.go` 的 `ErrGroupAuthFailed`）。
    ///
    /// 只有 `name` 非空时才有意义：独占端口的 `key` 恒为空串。
    key: String,
    /// ★★ 建立这个组的**租户**（`ClientState.user`），后续成员必须同租户。
    ///
    /// v0.5.7 新增（第六轮审计 D-1，高危）。
    ///
    /// # 为什么必须有这个字段
    ///
    /// 原先 `PortGroup` 只有 `name` / `key` / `members` / `cursor` / `handle`，
    /// **没有任何"归属租户"的概念**，加入判定只看 (组名, group_key) ——
    /// 于是"知道组名"就能把自己的工作连接挂到**别人**的公网端口上，
    /// 之后用户流量按轮询分给攻击者（实测 6/12 条连接被劫持）。
    ///
    /// **最危险的形态是双方都不配 `group_key`**（官方 frp 的常见写法，
    /// `groupKey` 在官方是可选的）：此时 `constant_time_eq("", "")` 为真，
    /// **组名就是唯一凭据且不需要任何密钥**。
    ///
    /// 本结构体上方的注释原话就把 `group_key` 称作"认证凭据"，并点名了
    /// 这个攻击 —— 既然已承认它是跨租户安全边界，就不能只在
    /// "双方都配了非空 key"时才成立。
    ///
    /// # 为什么按 `user` 判而不是按 `run_id`
    ///
    /// 同一租户的多个 frpc（重连、多开、一份配置里多条 `[[proxies]]`）
    /// **共用同一个 `user`**，而 `run_id` **每次重连都变** ——
    /// 用 `run_id` 判会把合法的负载均衡打成不通。
    ///
    /// # 诚实说明残留风险
    ///
    /// `user` 是客户端自报字段（D-5），所以**伪造 `user` 仍可混入**。
    /// 本字段挡住的是"用自己真实身份 + 知道组名"这条路径（即审计实测的那条），
    /// 要彻底解决需要**每租户独立凭据**（见 D-5 的修法）。
    owner_user: String,
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
    fn new(name: &str, key: &str, client: Arc<ClientState>, proxy_name: &str) -> Self {
        Self {
            name: name.to_string(),
            key: key.to_string(),
            owner_user: client.user.clone(),
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
    /// 挑一个后端。
    ///
    /// 策略由 [`LbPolicy`] 决定，默认按官方 frp 对齐（`group` 用轮询）。
    ///
    /// ## 平局规则
    ///
    /// 无论哪种策略，起点都从 `cursor` 开始每次挪一格。这保证：
    /// - 轮询：严格按 1/N 均分（这就是官方的行为）
    /// - 最少连接：计数相同时轮流坐庄，不会永远压着同一个后端
    fn pick(&self, policy: LbPolicy) -> Option<Backend> {
        let n = self.members.len();
        if n == 0 {
            return None;
        }

        // 起点每次挪一格（无锁 fetch_add）
        let start = self.cursor.fetch_add(1, Ordering::Relaxed) % n;

        if policy == LbPolicy::RoundRobin {
            return self.members.get(start).cloned();
        }

        // ★ 最少连接：**必须从 start 自身开始比较**。
        //
        // 旧实现先把 best_load 初始化成 members[0]，而循环从 start+1 扫，
        // 于是 start 从没进过循环、members[0] 却在 start≠0 时被多算一次 ——
        // 某些后端被系统性偏袒。现在改成从 start 起扫满一整圈。
        let mut best = start;
        let mut best_load = self.members[start].inflight();
        for k in 1..n {
            let i = (start + k) % n;
            let l = self.members[i].inflight();
            if l < best_load {
                best = i;
                best_load = l;
            }
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

/// group 负载均衡策略。
///
/// # 为什么要做成可配置
///
/// 官方 frp 的 `server/group/*.go` 用 **channel fan-out** 实现：
/// 真实监听器的 `Accept()` 把连接丢进共享 `acceptCh`，哪个代理先
/// `Accept()` 谁拿到 —— 效果就是**轮询（RoundRobin）**，无状态且可预测。
///
/// 本项目早期实现的是**最少连接（LeastConn）**：多后端处理能力不均时
/// 会向快的倾斜。两者各有取舍：
///
/// | 策略 | 优点 | 缺点 |
/// |---|---|---|
/// | `RoundRobin` | 无状态、可预测、**与官方行为一致** | 慢后端前面会堆队列 |
/// | `LeastConn` | 能力不均时自动倾斜 | 要维护在途计数，与官方行为不同 |
///
/// 默认 **RoundRobin**，对齐官方优先。需要自适应调度时显式切到
/// `LeastConn` —— 这是**超集**：调度完全发生在服务端内部，不影响与
/// 官方客户端的互通性。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[repr(u8)]
pub enum LbPolicy {
    /// 轮询：严格 1/N 均分。**默认，与官方 frp 行为一致。**
    #[default]
    RoundRobin = 0,
    /// 最少连接：优先给在途连接最少的后端。
    LeastConn = 1,
}

impl LbPolicy {
    /// 从 `AtomicU8` 存的值还原。未知值回落到默认。
    pub fn from_u8(v: u8) -> Self {
        match v {
            1 => Self::LeastConn,
            _ => Self::RoundRobin,
        }
    }

    /// 从配置字符串解析，无法识别时回落到默认值并告警。
    ///
    /// 接受 `roundrobin` / `round-robin` / `rr` 与 `leastconn` / `least-conn` / `lc`。
    pub fn parse(s: &str) -> Self {
        let norm: String = s
            .trim()
            .to_ascii_lowercase()
            .chars()
            .filter(|c| *c != '-' && *c != '_')
            .collect();
        match norm.as_str() {
            "" | "roundrobin" | "rr" => Self::RoundRobin,
            "leastconn" | "lc" => Self::LeastConn,
            other => {
                tracing::warn!(
                    value = other,
                    "无法识别的负载均衡策略，回落到 roundrobin（与官方一致）"
                );
                Self::RoundRobin
            }
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::RoundRobin => "roundrobin",
            Self::LeastConn => "leastconn",
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
        // ★★ v0.6.1 修（Shannon 审计，低危）：**会话结束时清掉 OIDC 的 subject 绑定**。
        //
        // `forget_session` 早就写好（`security.rs` / `guard.rs` / `oidc.rs`），
        // 但**除了一处单测，全仓没有任何生产调用点** ⇒
        // `OidcVerifier::subjects` 这张 `run_id -> sub` 表
        // **每个 OIDC 会话泄漏一条，直到进程重启**。
        //
        // 泄漏的量很小（一条 map 条目），但它同时意味着：
        // 已经登出的 run_id 仍能在表里查到绑定关系 —— 而 `run_id` 是会被复用的
        // 语义符号，留着旧绑定没有任何好处。
        //
        // 放在 `Drop` 里是为了**覆盖所有退出路径**（正常断开、被踢、panic 展开），
        // 与上面 `remove` 同一个位置，不会漏。
        self.registry.security().forget_session(&self.run_id);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pool::{self, CtrlCmd};
    use std::time::Duration;
    use tokio::sync::mpsc;

    /// ★★ v0.6.1 回归（Shannon 审计，低危）：**控制连接退出时必须清掉 OIDC 的 subject 绑定。**
    ///
    /// # 原先的问题
    ///
    /// `forget_session` 早就写好（`security.rs` / `guard.rs` / `oidc.rs` 三层都有），
    /// 但**除了一处单测，全仓没有任何生产调用点** ——
    /// `OidcVerifier::subjects` 这张 `run_id -> sub` 表
    /// **每个会话泄漏一条，直到进程重启**。
    ///
    /// # 这条测试测什么
    ///
    /// 造一个**真的 OIDC 上下文**（`AuthProvider::Oidc`），手工塞一条绑定，
    /// 然后 drop 一个 `ClientGuard` —— 绑定必须消失。
    ///
    /// ★ 不用 `SecurityContext::from_config`：那条路径在 JWKS 未拉取时会把
    ///   认证换成 `OidcUnavailable`，`forget_session` 变成空操作，测不到修复点。
    #[test]
    fn 控制连接退出必须清掉_oidc_subject_绑定() {
        use nfrp_common::security::AuthProvider;
        use std::sync::Arc;

        let r = Arc::new(Registry::unlimited());

        let verifier =
            nfrp_common::auth::oidc::OidcVerifier::new(nfrp_common::auth::oidc::ServerOidcConfig {
                issuer: "https://idp.example".into(),
                ..Default::default()
            })
            .expect("构造 OidcVerifier");
        {
            let sec = r.security();
            let mut slot = sec.auth.write().unwrap_or_else(|e| e.into_inner());
            *slot = AuthProvider::Oidc(verifier.clone());
        }

        verifier.bind_subject_for_test("run-guard", "alice");
        assert_eq!(
            verifier.subject_count(),
            1,
            "前置：绑定表里应当有 1 条（否则是测试没跑通，不是修复生效）"
        );

        {
            let _guard = ClientGuard::new(r.clone(), "run-guard".to_string());
        }
        assert_eq!(
            verifier.subject_count(),
            0,
            "控制连接退出后必须清掉 OIDC subject 绑定\
             （原先漏了这一步，每个会话泄漏一条直到重启）"
        );
    }

    fn client(run_id: &str) -> Arc<ClientState> {
        client_with_user("", run_id)
    }

    /// 指定 `user`（租户）的客户端。
    ///
    /// ★ v0.5.7（第六轮审计 D-1）：`PortGroup` 现在带 `owner_user`，
    /// 跨租户共享端口会被拒 —— 测这条边界需要一个能设 `user` 的构造器。
    /// 注意上面的 [`client`] 传的是**空 user**，所以既有的组测试
    /// （都视为同一租户）行为不变。
    fn client_with_user(user: &str, run_id: &str) -> Arc<ClientState> {
        let (tx, rx) = mpsc::unbounded_channel::<CtrlCmd>();
        std::mem::forget(rx);
        let (conn, backlog, proxy) = ServerLimits::default().per_client();
        Arc::new(ClientState::new(
            run_id.into(),
            run_id.into(),
            user.into(),
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
            r.reserve_port(6000, "", "", "a", a.clone()).unwrap(),
            PortClaim::Fresh,
            "端口没人占时必须告诉调用方去 bind"
        );
        assert!(
            r.reserve_port(6000, "", "", "b", b.clone()).is_err(),
            "同一个端口不能被两个代理同时占"
        );
        assert!(r.reserve_port(6001, "", "", "a", a.clone()).is_ok());
        assert_eq!(r.reserved_ports(), vec![6000, 6001]);
        r.release_port(6000, &a, "a");
        assert!(
            r.reserve_port(6000, "", "", "b", b.clone()).is_ok(),
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
            r.reserve_port(6000, "web", "", "a", one.clone()).unwrap(),
            PortClaim::Fresh
        );
        assert_eq!(
            r.reserve_port(6000, "web", "", "b", one.clone()).unwrap(),
            PortClaim::Joined
        );
        assert_eq!(r.backend_count(6000), 2, "同一客户端的两个成员都要在组里");

        // 摘掉其中一个，另一个必须留着（端口不能跟着收回）
        r.release_port(6000, &one, "a");
        assert_eq!(r.backend_count(6000), 1, "只摘掉指名的那一个成员");

        // 重复注册同一个代理名才应该去重
        r.reserve_port(6000, "web", "", "b", one.clone()).unwrap();
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
            r.reserve_port(6000, "web", "", "alice.web-a", client("a"))
                .unwrap(),
            PortClaim::Fresh,
            "组里第一个成员要负责创建监听器"
        );
        // 后续成员**必须**拿到 Joined —— 否则它们会再去 bind 同一端口，
        // 得到 `Address already in use`，组里就永远只剩一个后端。
        assert_eq!(
            r.reserve_port(6000, "web", "", "bob.web-b", client("b"))
                .unwrap(),
            PortClaim::Joined,
            "同组后续成员不该重复 bind 端口"
        );
        assert_eq!(
            r.reserve_port(6000, "web", "", "carol.web-c", client("c"))
                .unwrap(),
            PortClaim::Joined
        );
        assert_eq!(r.backend_count(6000), 3, "三个后端都挂在同一个端口上");
    }

    /// ★ 回归测试（H5）：组名相同但 `group_key` 不同**必须被拒绝**。
    ///
    /// `group_key` 是认证凭据，不是标签。早先 `reserve_port` 只比对组名，
    /// 于是任何知道组名的客户端（多租户 frps 上就是任意一个持合法 token 的用户）
    /// 都能混进他人的负载均衡组、分走该端口的流量份额。
    /// 官方 frps 在 `TCPGroup.Listen` 的加入分支上返回 `ErrGroupAuthFailed`。
    #[test]
    fn same_group_with_wrong_key_is_rejected() {
        let r = Registry::unlimited();
        // 受害者建组，密钥是 "s3cret"
        assert_eq!(
            r.reserve_port(6001, "web", "s3cret", "alice.web-a", client("a"))
                .unwrap(),
            PortClaim::Fresh
        );

        // 攻击者知道组名 "web" 与端口 6001，但不知道密钥 —— 必须被拒。
        let err = r
            .reserve_port(6001, "web", "guess", "mallory.web-x", client("m"))
            .expect_err("组名对但 group_key 不对，绝不能加入");
        assert!(
            err.contains("group_key"),
            "错误信息应点明是 group_key 校验失败，实际：{err}"
        );
        assert_eq!(
            r.backend_count(6001),
            1,
            "被拒绝的攻击者不得进入成员表（否则就会分走流量）"
        );

        // 连"密钥为空"也不能蹭进有密钥的组。
        assert!(
            r.reserve_port(6001, "web", "", "mallory.web-y", client("m"))
                .is_err(),
            "空密钥不能加入已设密钥的组"
        );

        // 密钥正确才放行。
        assert_eq!(
            r.reserve_port(6001, "web", "s3cret", "bob.web-b", client("b"))
                .unwrap(),
            PortClaim::Joined,
            "密钥正确应当正常加入"
        );
        assert_eq!(r.backend_count(6001), 2);
    }

    /// 组密钥可用（双方都留空）时，行为与老版本一致 —— 不能因为加了校验
    /// 就把"没配 group_key 的普通负载均衡组"一起打死。
    ///
    /// 这是兼容性回归：官方 frp 里 `groupKey` 是可选字段，两个成员都不写
    /// 就都是空串，空 == 空，照常成组。
    ///
    /// ★ v0.5.7（第六轮审计 D-1）：**这条兼容性仍然保留，但多了"同租户"前提**。
    ///   两个成员都不写 `group_key` 时**照常成组**（本测试锁定这一点），
    ///   但它们必须属于**同一租户**（同 `user`）—— 跨租户见
    ///   [`跨租户不能靠组名寄生到别人的公网端口`]。
    ///
    ///   理由：`group_key` 为空时它是**唯一**凭据，而"空密钥"本身
    ///   不构成任何凭据；把同租户作为额外的必要条件，既不破坏
    ///   "一个运维的多个冗余后端做负载均衡"这个真实用法，
    ///   又堵掉了"知道组名就能寄生"。
    #[test]
    fn same_group_with_both_keys_empty_still_joins() {
        let r = Registry::unlimited();
        assert_eq!(
            r.reserve_port(6002, "web", "", "a", client("a")).unwrap(),
            PortClaim::Fresh
        );
        assert_eq!(
            r.reserve_port(6002, "web", "", "b", client("b")).unwrap(),
            PortClaim::Joined,
            "双方都未配 group_key 时应照常成组（不能破坏既有部署）"
        );
        assert_eq!(r.backend_count(6002), 2);
    }

    /// ★★ v0.5.7 新增（第六轮审计 D-1，高危）：**跨租户不得靠组名寄生**。
    ///
    /// # 锁的是什么
    ///
    /// 原先 `PortGroup` 没有归属租户的概念，加入只看 (组名, group_key) ⇒
    /// 攻击者知道组名就能成为**别人公网端口**的后端，用户流量按轮询分给他
    /// （实测 6/12 条连接落到攻击者的内网服务上）。
    ///
    /// **最危险的形态是双方都不配 `group_key`**（官方常见写法）：
    /// 此时组名是唯一凭据、**不需要任何密钥**。
    ///
    /// # 三条断言各自的作用
    ///
    /// 1. 跨租户 + **空密钥** ⇒ 拒（这是实测打出来的那条攻击）
    /// 2. 跨租户 + **密钥正确** ⇒ 也拒（知道密钥也不行，租户边界先于密钥）
    /// 3. **同租户** + 空密钥 ⇒ 放行（对照，证明不是把负载均衡一起打死了）
    #[test]
    fn 跨租户不能靠组名寄生到别人的公网端口() {
        let r = Registry::unlimited();

        // 受害者 bob 起了一个负载均衡组（**不配 group_key**，官方常见写法）
        assert_eq!(
            r.reserve_port(
                6500,
                "web-lb",
                "",
                "bob.victim",
                client_with_user("bob", "run-b")
            )
            .unwrap(),
            PortClaim::Fresh
        );

        // ① 攻击者用**自己的真实身份** + 猜到的组名 ⇒ 必须被拒
        let e = r
            .reserve_port(
                6500,
                "web-lb",
                "",
                "alice.parasite",
                client_with_user("alice", "run-a"),
            )
            .expect_err("跨租户 + 空 group_key 必须被拒（组名不是凭据）");
        // 文案必须与其它占用失败**完全一致**，不泄露"组名猜对了"这个信息
        assert!(
            !e.contains("web-lb") && !e.contains("bob"),
            "错误文案不得泄露组名或占用者：{e}"
        );
        assert_eq!(r.backend_count(6500), 1, "被拒后不能多出后端");

        // ② 就算攻击者**知道 group_key**，跨租户一样拒 ——
        //    租户边界先于密钥，否则"密钥泄露 = 可寄生"
        assert!(
            r.reserve_port(
                6500,
                "web-lb",
                "",
                "alice.guess",
                client_with_user("alice", "run-a2"),
            )
            .is_err(),
            "跨租户即使密钥正确也必须被拒"
        );

        // ③ 对照：**同租户**的第二个后端照常加入（合法的负载均衡拓扑）
        assert_eq!(
            r.reserve_port(
                6500,
                "web-lb",
                "",
                "bob.victim-2",
                client_with_user("bob", "run-b2")
            )
            .unwrap(),
            PortClaim::Joined,
            "同租户的多个后端必须照常成组（否则就把负载均衡打死了）"
        );
        assert_eq!(r.backend_count(6500), 2);
    }

    /// 同一租户的多个 frpc **重连之后**仍要能加入 —— 用 `run_id` 判会打成不通。
    ///
    /// `run_id` 每次重连都变，而 `user` 不变；负载均衡组的合法性
    /// 必须按租户判。这条锁住"别改成用 run_id"。
    #[test]
    fn 同租户重连后仍能加入负载均衡组() {
        let r = Registry::unlimited();
        assert_eq!(
            r.reserve_port(6600, "lb", "k", "bob.a", client_with_user("bob", "run-1"))
                .unwrap(),
            PortClaim::Fresh
        );
        // 重连：run_id 变了、user 没变 ⇒ 必须仍能加入
        assert_eq!(
            r.reserve_port(6600, "lb", "k", "bob.b", client_with_user("bob", "run-2"))
                .unwrap(),
            PortClaim::Joined,
            "同一租户重连后 run_id 会变，不能因此拒绝它加入自己的组"
        );
    }

    #[test]
    fn different_groups_still_conflict() {
        let r = Registry::unlimited();
        assert!(r.reserve_port(6000, "web", "", "a", client("a")).is_ok());
        let e = r
            .reserve_port(6000, "api", "", "b", client("b"))
            .expect_err("不同组不能抢同一个端口");

        // ★★ v0.5.6 修（审计总报告 L14）：**错误文案不得泄露任何组名**。
        //
        // 原先这条测试断言 `e.contains("api") && e.contains("web")`
        // —— 那正是在**固化枚举预言机**：调用方（未认证 / 低权限）
        // 能从文案里读出任一方的组名。
        //
        // 现在反过来断言：文案里**不能出现**任何组名。
        assert!(
            !e.contains("api") && !e.contains("web"),
            "错误文案不得泄露组名（L14 枚举预言机）：{e}"
        );
        assert!(e.contains("6000"), "但仍要说是哪个端口：{e}");
        assert!(e.contains("已被占用"), "{e}");

        // 独占端口同样不能被组抢走
        let r2 = Registry::unlimited();
        assert!(r2.reserve_port(7000, "", "", "a", client("a")).is_ok());
        assert!(r2.reserve_port(7000, "web", "", "b", client("b")).is_err());
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
            assert!(r.reserve_port(6000, "web", "", n, client(n)).is_ok());
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
    ///
    /// ★ v0.6.2：这条测试现在**显式把策略设成 LeastConn**。
    ///   默认策略已改为 RoundRobin（对齐官方 frp），不再默认倾斜。
    #[test]
    fn pick_prefers_the_least_loaded_backend() {
        let r = Registry::unlimited();
        r.set_lb_policy(LbPolicy::LeastConn);
        for n in ["a", "b"] {
            assert!(r.reserve_port(6100, "web", "", n, client(n)).is_ok());
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

    /// ★ v0.6.2 回归：**默认策略必须是轮询**，与官方 frp 的 group 行为一致。
    ///
    /// 官方 `server/group/base.go` 的 `worker` 把连接丢进共享 `acceptCh`，
    /// 哪个代理先 `Accept()` 谁拿到 —— 等价于无状态的轮询。
    ///
    /// 这条测试锁住两件事：
    /// 1. 未配置时就是 `RoundRobin`
    /// 2. 负载不均时**照样均分**（不因为 a 压着 5 条就让 b 独占）
    #[test]
    fn default_policy_is_round_robin_like_official() {
        let r = Registry::unlimited();
        assert_eq!(
            r.lb_policy(),
            LbPolicy::RoundRobin,
            "默认必须是 roundrobin（对齐官方 frp）"
        );

        for n in ["a", "b"] {
            assert!(r.reserve_port(6200, "web", "", n, client(n)).is_ok());
        }
        // 给 a 压 5 条在途 —— 轮询策略下这**不应该**影响分配
        let a = r.backend_of(6200, "a").expect("组里应当有 a");
        let held: Vec<_> = (0..5).map(|_| a.hold()).collect();

        let mut counts = std::collections::HashMap::new();
        for _ in 0..10 {
            let b = r.pick(6200).expect("应有后端");
            *counts.entry(b.client.run_id.clone()).or_insert(0) += 1;
            drop(b.hold());
        }
        drop(held);

        assert_eq!(
            counts.get("a").copied().unwrap_or(0),
            5,
            "轮询下 a 应分到一半，实际分配：{counts:?}"
        );
        assert_eq!(
            counts.get("b").copied().unwrap_or(0),
            5,
            "轮询下 b 应分到一半，实际分配：{counts:?}"
        );
    }

    /// 策略字符串解析：认得常见写法，认不出时回落到默认并告警。
    #[test]
    fn lb_policy_parsing() {
        assert_eq!(LbPolicy::parse(""), LbPolicy::RoundRobin);
        assert_eq!(LbPolicy::parse("roundrobin"), LbPolicy::RoundRobin);
        assert_eq!(LbPolicy::parse("Round-Robin"), LbPolicy::RoundRobin);
        assert_eq!(LbPolicy::parse("rr"), LbPolicy::RoundRobin);
        assert_eq!(LbPolicy::parse("leastconn"), LbPolicy::LeastConn);
        assert_eq!(LbPolicy::parse("Least_Conn"), LbPolicy::LeastConn);
        assert_eq!(LbPolicy::parse("lc"), LbPolicy::LeastConn);
        // 认不出的值回落到官方行为，而不是随机挑一个
        assert_eq!(LbPolicy::parse("random"), LbPolicy::RoundRobin);
        assert_eq!(LbPolicy::parse("  "), LbPolicy::RoundRobin);
    }

    /// 令牌必须**自动**归还：`pick_and_hold` 出来的计数不能泄漏。
    ///
    /// 这是最容易写错的地方 —— 转发路径上有好几个提前 return / 被拒的出口，
    /// 手动减迟早漏一处。靠 Drop 归还就是为了根治这件事。
    #[test]
    fn load_guard_returns_the_count_on_drop() {
        let r = Registry::unlimited();
        assert!(r.reserve_port(6200, "web", "", "a", client("a")).is_ok());
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
            assert!(r.reserve_port(6300, "web", "", n, client(n)).is_ok());
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
            .reserve_port(6000, "web", "", "alice.web-a", client("a"))
            .is_ok());
        assert!(r
            .reserve_port(6000, "web", "", "bob.web-b", client("b"))
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
        assert!(r.reserve_port(6000, "web", "", "a", a.clone()).is_ok());
        assert!(r.reserve_port(6000, "web", "", "b", b.clone()).is_ok());
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
        assert!(r.reserve_port(6000, "web", "", "a", a.clone()).is_ok());
        assert!(r.reserve_port(6001, "", "", "a", a.clone()).is_ok());
        assert!(r.reserve_port(6000, "web", "", "b", b.clone()).is_ok());

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
            assert!(r.reserve_port(6000, "web", "", "a", a.clone()).is_ok());
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

        use crate::vhost::{VhostKind, VhostRoute};

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
                kind: VhostKind::Http,
            }))
            .expect("注册域名");
        assert!(table
            .lookup("a.example.com", "/", None, VhostKind::Http)
            .is_some());

        r.remove("reap1");
        assert!(
            table
                .lookup("a.example.com", "/", None, VhostKind::Http)
                .is_none(),
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
