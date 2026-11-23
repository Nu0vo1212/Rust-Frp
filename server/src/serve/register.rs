//! 代理注册（按类型分发）与公网端口 accept 循环。
//!
//! 职责：`register_proxy` 的续传复用 / 名额 / 端口管控与按类型分发，
//! tcp / udp / vhost / stcp / xtcp / sudp 的注册实现，以及
//! `proxy_accept_loop`（数据面 ACL、端口敲门、group 负载均衡后 `admit_user`）。
//!
//! 锁顺序契约：registry → client state → pool。`reserve_port` / `release_port`
//! / `attach_listener` 在 `Registry` 内部锁内完成且不回调 `ClientState`；
//! `ClientState` 的代理表 / 端口计数锁在其后获取；`VhostTable` 锁最后获取。
//! 端口 accept 循环每轮只读安全上下文与 nlink（短锁），不持有跨 await 的锁。
//!
//! 不变量：代理名 / 端口 / 域名在注册成功后由 `ClientState` 唯一持有，
//! `close_proxy_by_name` 是唯一的回收写者；`PortClaim::Fresh` 才 bind，
//! `Joined` 只复用已有监听器。

use std::{sync::Arc, time::Instant};

use anyhow::{anyhow, Context, Result};
use nfrp_common::{config::ServerConfig, util};
use tokio::net::TcpListener;
use tracing::debug;

use crate::{
    limits::Permit,
    pool::{ClientState, ConnSlot, PendingUser},
    registry::{PortClaim, Registry},
    udp_proxy,
    vhost::{VhostKind, VhostRoute},
    visitor::VisitorEntry,
};

use super::control::proxy_signature;
use super::work::admit_user;

/// `register_proxy` 的结果。
#[derive(Debug)]
pub(crate) struct RegisterOutcome {
    /// 回给客户端的 `remote_addr` 文案。
    pub remote_addr: String,
    /// `true` = 续传时复用了原监听器，**没有**新建资源。
    ///
    /// 调用方据此决定要不要 `proxies_total/active.inc()`：复用的条目在
    /// 暂停期间从未减过，再 inc 一次会让面板统计永久偏高。
    pub adopted: bool,
}

/// 按代理类型注册：tcp / udp 绑端口，http / https 注册虚拟主机域名。
///
/// 返回给客户端的 `remote_addr` 文案（frp 用它展示"暴露在哪"）。
pub(crate) async fn register_proxy(
    cfg: &Arc<ServerConfig>,
    registry: &Arc<Registry>,
    client: &Arc<ClientState>,
    m: &nfrp_common::frp::msg::NewProxy,
) -> Result<RegisterOutcome> {
    if m.proxy_name.is_empty() {
        anyhow::bail!("代理名为空");
    }
    // 续传复用：只有"本次控制连接是续传出来的"才允许跳过重新绑定。
    // 指纹覆盖端口 / 域名 / 密钥等全部字段 —— 同名但配置改过时必须重新注册，
    // 否则用户改了端口却仍指向旧监听器，且不会有任何报错。
    let signature = proxy_signature(m);
    if client.is_resumed_session() {
        if let Some(addr) = client.reusable_proxy(&m.proxy_name, &signature) {
            debug!(
                proxy = %m.proxy_name,
                remote = %addr,
                "续传：同名同配置代理直接复用原监听器"
            );
            // 刷新代次：本次续传确实"碰过"它，宽限期对账时不能当成陈旧条目。
            client.set_proxy_registration(&m.proxy_name, addr.clone(), signature.clone());
            return Ok(RegisterOutcome {
                remote_addr: addr,
                adopted: true,
            });
        }
    }
    // 同名但配置变了（或普通会话重复注册同名代理）：先把旧监听器 / 域名 /
    // visitor 记录彻底摘掉，再走新注册。
    //
    // 这一步不能只在续传路径做：普通会话只要重复发同一个 `NewProxy`，旧条目
    // 就会被 `add_proxy` 覆盖，而旧监听器没人 abort —— 客户端可以用一个代理名
    // 反复换端口，把 allowPorts 白名单里的端口一个个占住且永不释放。
    if client.has_proxy(&m.proxy_name) {
        debug!(proxy = %m.proxy_name, "同名代理重新注册，先回收旧注册");
        close_proxy_by_name(registry, client, &m.proxy_name);
    }
    // 代理数必须在分配端口/域名之前拦住，否则失败路径还要回头回收资源。
    // 名额由 add_proxy 接管，随代理一起存活。
    let slot = client.reserve_proxy().ok_or_else(|| {
        anyhow!(
            "代理数量已达上限 {}，注册被拒绝",
            registry.limits().max_proxies_per_client
        )
    })?;

    // ---- 端口管控（allowPorts / maxPortsPerClient）----
    //
    // 只对**真的会绑公网端口**的 tcp / udp 生效：http / https / tcpmux / stcp /
    // xtcp / sudp 都走虚拟主机或 visitor 配对，一个公网端口都不占。
    // 官方同样如此（`Control.RegisterProxy` 累的是 `pxy.GetUsedPortsNum()`，
    // 只有 tcp / udp 返回 1）。
    //
    // `remote_port == 0` 时不在这里拦：交给 register_tcp / register_udp 报
    // "必须指定 remote_port"，那条错误信息比"端口 0 不在白名单"有用得多。
    if matches!(m.proxy_type.as_str(), "tcp" | "udp") && m.remote_port != 0 {
        if !cfg.port_allowed(m.remote_port) {
            anyhow::bail!(
                "远端端口 {} 不在服务端 allowPorts 白名单内（已允许：{}）",
                m.remote_port,
                nfrp_common::config::format_port_ranges(&cfg.allow_ports)
            );
        }
        if cfg.max_ports_per_client > 0 {
            let used = client.ports_used() as i64;
            if used + 1 > cfg.max_ports_per_client {
                anyhow::bail!(
                    "本客户端已占用 {used} 个端口，再加这一个会超过 maxPortsPerClient = {}",
                    cfg.max_ports_per_client
                );
            }
        }
    }
    let result = match m.proxy_type.as_str() {
        "tcp" => register_tcp(cfg, registry, client, m, slot).await,
        "udp" => register_udp(cfg, registry, client, m, slot).await,
        "http" => register_vhost(cfg, registry, client, m, VhostKind::Http, slot).await,
        "https" => register_vhost(cfg, registry, client, m, VhostKind::Https, slot).await,
        // tcpmux：不绑端口，挂到服务端那个共享的 CONNECT 复用端口上按域名分发
        "tcpmux" => register_vhost(cfg, registry, client, m, VhostKind::TcpMux, slot).await,
        "stcp" => register_visitor_proxy(registry, client, m, "stcp", slot).await,
        "xtcp" => register_visitor_proxy(registry, client, m, "xtcp", slot).await,
        // SUDP：秘密 UDP。与 stcp 同一套鉴权（secret_key + allow_users），
        // 只是数据面是 UDP。不需要公网端口，visitor 主动连进来时配对。
        "sudp" => register_visitor_proxy(registry, client, m, "sudp", slot).await,
        other => anyhow::bail!(
            "暂不支持的代理类型：{other}\
             （支持 tcp / udp / http / https / tcpmux / stcp / xtcp / sudp）"
        ),
    };
    // 记下回给客户端的地址 + 指纹：续传时据此判断"同名同配置，直接复用"。
    if let Ok(addr) = &result {
        client.set_proxy_registration(&m.proxy_name, addr.clone(), signature);
    }
    result.map(|remote_addr| RegisterOutcome {
        remote_addr,
        adopted: false,
    })
}

/// 按名字摘掉一条代理并回收它占用的域名 / visitor 记录 / 公网端口。
///
/// 与 `CloseProxy` 走同一套清理语义，但**不**触发 HTTP 插件（这是服务端
/// 自己的对账动作，不是客户端发起的关闭）。返回 `true` 表示确实摘掉了。
pub(super) fn close_proxy_by_name(
    registry: &Arc<Registry>,
    client: &Arc<ClientState>,
    name: &str,
) -> bool {
    registry.visitors.remove(client, name);
    if let Some(t) = registry.vhosts() {
        t.remove_proxy(client, name);
    }
    if !client.has_proxy(name) {
        return false;
    }
    let port = client.stop_proxy(name);
    registry.metrics().proxies_active.dec();
    if let Some(port) = port {
        registry.release_port(port, client, name);
    }
    true
}

/// stcp / xtcp：**不需要公网端口**，只在 visitor 表里登记一条记录。
///
/// 之后 visitor 主动连进来时才会校验密钥并配对工作连接。
///
/// 说明：`xtcp` 在 P2P 打洞失败时会回退成本模块的中继路径（与 stcp 一致）。
async fn register_visitor_proxy(
    registry: &Arc<Registry>,
    client: &Arc<ClientState>,
    m: &nfrp_common::frp::msg::NewProxy,
    kind: &str,
    slot: Permit,
) -> Result<String> {
    if m.sk.is_empty() {
        anyhow::bail!("{kind} 代理必须配置 secret_key（frpc 里叫 secretKey）");
    }
    registry
        .visitors
        .register(VisitorEntry {
            proxy_name: m.proxy_name.clone(),
            secret_key: m.sk.clone(),
            allow_users: m.allow_users.clone(),
            provider_user: client.user.clone(),
            client: client.clone(),
            proxy_type: kind.to_string(),
        })
        .map_err(|e| anyhow!(e))?;
    client.add_proxy(m.proxy_name.clone(), None, slot);
    // ★ v0.6.6：把数据面标志记下来，工作连接那一侧要用它决定是否解密/解压
    client.set_proxy_flags(&m.proxy_name, m.use_encryption, m.use_compression);
    client.set_proxy_type(&m.proxy_name, &m.proxy_type);
    // 与官方 frps 一致：visitor 类代理没有公网地址，remote_addr 留空
    Ok(String::new())
}

/// TCP：绑定公网端口，用户连进来时向客户端要工作连接配对。
async fn register_tcp(
    cfg: &Arc<ServerConfig>,
    registry: &Arc<Registry>,
    client: &Arc<ClientState>,
    m: &nfrp_common::frp::msg::NewProxy,
    slot: Permit,
) -> Result<String> {
    if m.remote_port == 0 {
        anyhow::bail!("tcp 代理必须指定 remote_port");
    }
    // ★ 限制①批次1：数据面端口跟随 `proxyBindAddr`（官方
    //   `ports.NewManager("tcp", cfg.ProxyBindAddr, ...)` 与 tcp.go 的
    //   `net.Listen(..., ProxyBindAddr, ...)`；留空 = `bindAddr`）。
    let proxy_host = cfg.effective_proxy_bind_addr();
    // group 共享端口时**只有第一个成员**能 bind，后来者直接复用已有监听器：
    // 再 bind 一次必然是 `Address already in use`，组里就永远只剩一个后端。
    let claim = registry
        .reserve_port(
            m.remote_port,
            &m.group,
            &m.group_key,
            &m.proxy_name,
            client.clone(),
        )
        .map_err(|e| anyhow!("{e}"))?;

    if claim == PortClaim::Fresh {
        let addr = util::resolve_addr(&format!("{proxy_host}:{}", m.remote_port))
            .await
            .with_context(|| format!("解析 {proxy_host}:{} 失败", m.remote_port))?;
        let listener = match TcpListener::bind(addr).await {
            Ok(l) => l,
            Err(e) => {
                registry.release_port(m.remote_port, client, &m.proxy_name);
                return Err(e).with_context(|| format!("监听 {addr} 失败"));
            }
        };

        let remote_port = m.remote_port;
        let registry2 = registry.clone();
        let handle = tokio::spawn(async move {
            proxy_accept_loop(listener, remote_port, registry2).await;
        });
        // 监听器交给**端口**（而不是这个客户端）托管：组里其他成员还在时，
        // 创建者掉线不该把端口一起带走。
        registry.attach_listener(m.remote_port, handle.abort_handle());
    }

    client.add_proxy(m.proxy_name.clone(), Some(m.remote_port), slot);
    client.set_proxy_flags(&m.proxy_name, m.use_encryption, m.use_compression);
    client.set_proxy_type(&m.proxy_name, &m.proxy_type);
    Ok(format!("{proxy_host}:{}", m.remote_port))
}

/// UDP：绑定 UDP 端口 + 维持一条专用工作连接。
async fn register_udp(
    cfg: &Arc<ServerConfig>,
    registry: &Arc<Registry>,
    client: &Arc<ClientState>,
    m: &nfrp_common::frp::msg::NewProxy,
    slot: Permit,
) -> Result<String> {
    if m.remote_port == 0 {
        anyhow::bail!("udp 代理必须指定 remote_port");
    }
    // ★ 限制①批次1：数据面端口跟随 `proxyBindAddr`（官方 udp.go：
    //   `ResolveUDPAddr(..., ProxyBindAddr, ...)`；留空 = `bindAddr`）。
    let proxy_host = cfg.effective_proxy_bind_addr();
    // 同 tcp：只有第一个成员负责绑定，后来者复用。
    //
    // 但 UDP 的 group 负载均衡这里**明确不做**：UDP 是无连接的，一条工作连接
    // 要负责一整套来源地址的报文，按连接轮询会把同一个会话的报文拆到不同后端去，
    // 结果比不均衡还糟。与其让它"看着配了却没生效"，不如直接说清楚。
    let claim = registry
        .reserve_port(
            m.remote_port,
            &m.group,
            &m.group_key,
            &m.proxy_name,
            client.clone(),
        )
        .map_err(|e| anyhow!("{e}"))?;
    if claim == PortClaim::Joined {
        registry.release_port(m.remote_port, client, &m.proxy_name);
        anyhow::bail!(
            "端口 {} 已被同组 [{}] 的其他代理占用；UDP 暂不支持 group 负载均衡，请改用 tcp",
            m.remote_port,
            m.group
        );
    }

    let udp = match udp_proxy::bind_udp(proxy_host, m.remote_port).await {
        Ok(u) => u,
        Err(e) => {
            registry.release_port(m.remote_port, client, &m.proxy_name);
            return Err(e);
        }
    };
    // ★ v0.5.9（第九轮审计 E9-0）：把安全上下文传进去，让 UDP 数据面也过 ACL。
    let handle = udp_proxy::spawn(
        Arc::new(udp),
        m.proxy_name.clone(),
        client.clone(),
        registry.security(),
        nfrp_common::config::clamp_udp_packet_size(cfg.udp_packet_size),
    );
    registry.attach_listener(m.remote_port, handle.abort_handle());
    client.add_proxy(m.proxy_name.clone(), Some(m.remote_port), slot);
    // ★ v0.7.6 修：udp 此前漏记数据面标志与代理类型。
    //
    // tcp / stcp / xtcp 都在注册后写了这两项，只有 udp 没写 —— 于是
    // `proxy_flags()` 永远返回 (false,false)、`proxy_type()` 返回空串。
    // udp 的数据面由 `udp_proxy` 自己处理加解密，但类型缺失会直接影响
    // `NewUserConn` 插件与面板/审计里的类型展示，口径必须与其它类型一致。
    client.set_proxy_flags(&m.proxy_name, m.use_encryption, m.use_compression);
    client.set_proxy_type(&m.proxy_name, &m.proxy_type);
    Ok(format!("{proxy_host}:{}/udp", m.remote_port))
}

/// http / https / tcpmux：把域名注册进虚拟主机路由表（都不需要额外端口）。
///
/// 三者的域名解析规则完全一样（`customDomains` + `subDomain`.配 `subdomain_host`），
/// 所以合用一条路径；差别只在路由表里的 `kind`，以及**路径前缀**：
/// tcpmux 的 CONNECT 请求没有路径，官方 `TCPMuxProxyConfig` 也没有 `locations`，
/// 所以它注册的前缀是空串（匹配一切），而 http 默认 `/`。
async fn register_vhost(
    cfg: &Arc<ServerConfig>,
    registry: &Arc<Registry>,
    client: &Arc<ClientState>,
    m: &nfrp_common::frp::msg::NewProxy,
    kind: VhostKind,
    slot: Permit,
) -> Result<String> {
    let name = kind.label();
    let vhost_port = match kind {
        VhostKind::Http => cfg.vhost_http_port,
        VhostKind::Https => cfg.vhost_https_port,
        VhostKind::TcpMux => cfg.tcpmux_http_connect_port,
    };
    let Some(vhost_port) = vhost_port else {
        anyhow::bail!(
            "服务端未配置 {}，无法注册 {name} 代理",
            match kind {
                VhostKind::Http => "vhost_http_port",
                VhostKind::Https => "vhost_https_port",
                VhostKind::TcpMux =>
                    "tcpmux_http_connect_port（frps.toml 里叫 tcpmuxHTTPConnectPort）",
            }
        );
    };
    if kind == VhostKind::TcpMux && m.multiplexer != "httpconnect" {
        // 官方 `server/proxy/tcpmux.go` 的 `Run()`：`unknown multiplexer [%s]`
        anyhow::bail!(
            "tcpmux 代理 [{}] 的 multiplexer 是 {:?}，只支持 \"httpconnect\"",
            m.proxy_name,
            m.multiplexer
        );
    }
    let table = registry
        .vhosts()
        .ok_or_else(|| anyhow!("虚拟主机路由表未初始化"))?;

    let mut domains: Vec<String> = m
        .custom_domains
        .iter()
        .map(|d| d.trim().to_ascii_lowercase())
        .filter(|d| !d.is_empty())
        .collect();
    if !m.subdomain.is_empty() {
        if cfg.subdomain_host.is_empty() {
            anyhow::bail!("客户端用了 subdomain，但服务端未配置 subdomain_host");
        }
        domains.push(format!(
            "{}.{}",
            m.subdomain.trim().to_ascii_lowercase(),
            cfg.subdomain_host.trim().to_ascii_lowercase()
        ));
    }
    if domains.is_empty() {
        anyhow::bail!("{name} 代理必须配置 custom_domains 或 subdomain");
    }

    let mut locations: Vec<String> = match kind {
        VhostKind::TcpMux => vec![String::new()],
        _ if m.locations.is_empty() => vec!["/".to_string()],
        _ => m.locations.clone(),
    };
    // 长前缀优先匹配（frp 的路由优先级规则）
    locations.sort_by_key(|a| std::cmp::Reverse(a.len()));
    for domain in &domains {
        table.register(Arc::new(VhostRoute {
            proxy_name: m.proxy_name.clone(),
            client: client.clone(),
            domain: domain.clone(),
            locations: locations.clone(),
            http_user: m.http_user.clone(),
            http_pwd: m.http_pwd.clone(),
            route_by_http_user: m.route_by_http_user.clone(),
            rewrite_host: m.host_header_rewrite.clone(),
            req_headers: m.headers.clone(),
            resp_headers: m.response_headers.clone(),
            kind,
        }))?;
    }
    client.add_proxy(m.proxy_name.clone(), None, slot);
    // ★ v0.7.6 修：vhost（http / https / tcpmux）此前**既没记类型，也没记
    // 加密/压缩标志** —— tcp / stcp / xtcp 都记了，只有这三条漏了。
    //
    // 后果不是"少个字段"，而是数据面错误：客户端开了 `useEncryption` 后
    // 工作连接上是密文，而 vhost 转发路径按明文透传（还不做解压），
    // 表现为"隧道建立了、页面空白或连接超时"，日志里却没有任何报错。
    client.set_proxy_flags(&m.proxy_name, m.use_encryption, m.use_compression);
    client.set_proxy_type(&m.proxy_name, &m.proxy_type);
    Ok(domains
        .iter()
        .map(|d| format!("{d}:{vhost_port}"))
        .collect::<Vec<_>>()
        .join(","))
}

async fn proxy_accept_loop(listener: TcpListener, remote_port: u16, registry: Arc<Registry>) {
    loop {
        match listener.accept().await {
            Ok((stream, peer)) => {
                // ★★ v0.5.8 修（第七轮审计 F7-1，中危）：**数据面也要过 ACL**。
                //
                // # 原先为什么错了
                //
                // `[acl]`（IP 白/黑名单）的唯一判定入口是
                // `SecurityContext::check_ip`，而它全仓只有 2 处调用：
                // 控制连接握手（`handle_frp_stream`）与 VirtualNet 注册。
                // **公网代理端口这条承载用户流量的路径上完全没有它。**
                //
                // 实测（`tmp/audit7/f/acl_dataplane_v3.py`，9/9 判据通过）：
                // 同一个服务端、同一份配置 `deny = ["127.0.0.1"]`，
                // 只改源地址 ——
                //
                // | 路径 | 源地址 | 结果 |
                // |---|---|---|
                // | 控制面 | 127.0.0.1（被 deny） | 被拒 ✓ |
                // | 控制面 | 192.168.3.15（放行） | 登录成功 ✓ |
                // | 数据面 | 192.168.3.15（正对照） | 转发成功 ✓ |
                // | **数据面** | **127.0.0.1（被 deny）** | **照常转发** ✗ |
                //
                // ⇒ 管理员用 ACL 表达"只允许某些来源访问"，实际只挡住了管理面，
                //   业务端口对全网开放。用**白名单**模式时更糟 —— 白名单形同虚设。
                //
                // 这与本项目连续六轮的模式一致："防线写对了，但没铺满它声称
                // 保护的所有路径"。修法就是把它铺到数据面的 accept 点上。
                //
                // 顺序与 `handle_frp_stream` 一致：ACL 是位运算，放在最前面最便宜。
                // 拒绝时**静默关连接**（不回任何数据）：这条路径上面对的是
                // 陌生访客，不该泄露"你被 ACL 拒了"这类可区分信息。
                let sec = registry.security();
                if let Err(reason) = sec.check_ip(peer.ip()) {
                    registry.audit().record(
                        crate::audit::AuditEvent::new(crate::audit::kind::LOGIN_DENIED, false)
                            .ip(peer.ip().to_string())
                            .detail(format!("{reason}（公网端口 {remote_port} 数据面）")),
                    );
                    debug!(%peer, port = remote_port, "数据面 IP 访问控制拒绝：{reason}");
                    continue;
                }
                // 小包请求-响应式流量（HTTP / RPC 等）关闭 Nagle：避免攒包引入
                // 毫秒级延迟；与 `vhost` / `vnet` 等其它数据面入口的处理一致。
                // 纯套接字选项，设置失败不影响转发。
                stream.set_nodelay(true).ok();
                // ---- NLink 端口敲门 ----
                //
                // 配了规则就默认**不信任任何来源**：必须先把敲门序列发上来，
                // 放行窗口内才允许真正的业务连接。
                //
                // 两条路径都关连接：
                // * 敲门成功 —— 这条连接本身不是业务流量（它只发了 33 字节）；
                // * 敲门失败/超时 —— 对外表现与"端口没开放"一致，不泄露存在性。
                //
                // 没配规则时这一段完全不执行（`knock_rule` 返回 None）。
                {
                    let nlink_rt = registry.nlink();
                    if let Some(rule) = nlink_rt.knock_rule(remote_port) {
                        if !nlink_rt.knock.is_allowed(peer.ip(), remote_port) {
                            let mut probe = stream;
                            let _ = crate::nlink::try_knock(
                                &mut probe,
                                rule,
                                peer.ip(),
                                &nlink_rt.knock,
                            )
                            .await;
                            debug!(%peer, port = remote_port, "未敲门的连接已关闭");
                            continue;
                        }
                    }
                }
                // group 负载均衡：这个端口背后可能挂着多个客户端（同组代理），
                // 每条新连接轮询挑一个；挑不到说明后端全掉了，直接关掉。
                // 选**在途连接最少**的后端，并立刻给它记一条 ——
                // 计数令牌一路带进 PendingUser，转发结束（或被拒）时自动减回去。
                let Some((backend, load)) = registry.pick_and_hold(remote_port) else {
                    debug!(%peer, port = remote_port, "端口没有可用后端，关闭连接");
                    continue;
                };
                let client = backend.client;
                let user = PendingUser {
                    // 必须用**被选中那个后端自己的**代理名：服务端就是靠它
                    // 在 StartWorkConn 里告诉客户端该服务哪条代理，
                    // 组内各成员的 name 可以完全不同（alice.web-a / bob.web-b），
                    // 拿创建监听器那个成员的名字下发，其他成员会找不到这条代理。
                    proxy: backend.proxy_name.clone(),
                    proxy_type: client.proxy_type(&backend.proxy_name),
                    client_user: client.user.clone(),
                    client_run_id: client.run_id(),
                    // ★ v0.6.6：数据面标志随用户连接带下去
                    use_encryption: {
                        let (e, _) = client.proxy_flags(&backend.proxy_name);
                        e
                    },
                    use_compression: {
                        let (_, c) = client.proxy_flags(&backend.proxy_name);
                        c
                    },
                    data_key: {
                        let (e, _) = client.proxy_flags(&backend.proxy_name);
                        e.then(|| nfrp_common::frp::v1::derive_key(sec.auth_cfg.token.as_bytes()))
                    },
                    remote_port,
                    stream: Box::pin(stream),
                    peer,
                    at: Instant::now(),
                    slot: ConnSlot::acquire(&registry.conn_limit, &client),
                    queue_permit: None,
                    load: Some(load),
                };
                admit_user(user, &client, &registry);
            }
            Err(e) => {
                tracing::error!(port = remote_port, "监听失败：{e}");
                break;
            }
        }
    }
}
