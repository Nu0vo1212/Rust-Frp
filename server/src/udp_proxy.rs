//! UDP 代理（等价官方 `server/proxy/udp.go`）。
//!
//! 与 TCP 代理最大的区别：
//!
//! * 公网侧是 **UDP socket**，没有"连接"概念，靠 `remote_addr` 区分访客；
//! * 客户端侧**每个 UDP 代理只占一条专用工作连接**（不是每个访客一条），
//!   所有访客的报文都复用这一条连接，靠 `UdpPacket.remote_addr` 标识归属；
//! * 这条工作连接上跑的是 frp 消息帧（type 13 `UdpPacket`），
//!   而不是像 TCP 那样转发裸字节。
//!
//! ```text
//! 访客 --UDP--> 服务端 udp socket --UdpPacket--> 专用工作连接 --> 客户端 --> 内网 UDP 服务
//! ```

use std::{collections::HashSet, net::IpAddr, net::SocketAddr, sync::Arc, time::Duration};

use anyhow::{Context, Result};
use nfrp_common::frp::{
    conn::FrpConn,
    msg::{FrpMessage, Ping, StartWorkConn, UdpPacket},
};
use tokio::{net::UdpSocket, sync::mpsc, time::interval};
use tracing::{debug, info, warn};

use crate::ClientState;

/// "最近见过的访客 IP"集合上限。
///
/// 取 4096：一个 UDP 代理同时活跃的访客极少超过这个量级；
/// 超过就清空重建，避免内存无上限增长。
const MAX_SEEN_VISITOR_IPS: usize = 4096;

/// "最近见过的访客 IP"集合。
///
/// 抽成独立类型是为了**可测** —— 判定逻辑放在 `run_session` 那种
/// `tokio::select!` 循环里根本没法单测。
#[derive(Default)]
struct SeenVisitorIps {
    inner: std::sync::Mutex<HashSet<IpAddr>>,
}

impl SeenVisitorIps {
    /// 记下一个"真的给我们发过包"的访客 IP。
    fn record(&self, ip: IpAddr) {
        if let Ok(mut g) = self.inner.lock() {
            if g.len() >= MAX_SEEN_VISITOR_IPS {
                // 满了就清空重建：UDP 访客地址本就易变，清空最多让极少数
                // 在途回包被丢，不会让内存无上限增长。
                g.clear();
            }
            g.insert(ip);
        }
    }

    /// 允许回写给这个地址吗？
    ///
    /// **只校验 IP、不校验端口** —— TFTP 之类协议会换端口回包，
    /// 卡死端口会误伤它们；而反射/放大必须跨 IP（把响应打给受害者），
    /// 所以按 IP 收紧就够。
    ///
    /// 锁中毒时返回 `true`（放行）：这里的选择是"宁可少拦，不要卡死转发"。
    ///   UDP 代理断掉是**确定的**服务中断，而漏拦一个回包只是少一层加固。
    fn allows(&self, ip: IpAddr) -> bool {
        match self.inner.lock() {
            Ok(g) => g.contains(&ip),
            Err(_) => true,
        }
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.inner.lock().map(|g| g.len()).unwrap_or(0)
    }
}

/// 工作连接上发送 Ping 的间隔：官方 frps 对 UDP 工作连接设了 60s 读超时，
/// 心跳间隔必须小于它。
const KEEPALIVE_INTERVAL: Duration = Duration::from_secs(30);

/// 启动一个 UDP 代理：绑定 UDP 端口并持续维护"专用工作连接"。
///
/// 新增 `sec` 参数。
///
/// # 原先为什么错了
///
/// `[acl]`（IP 白/黑名单）的唯一判定入口 `SecurityContext::check_ip`
/// 在 里只有 **4 处**调用（控制面 / TCP 代理 / vhost / VNet），
/// **UDP 代理端口一处都没有** ⇒ 管理员用 `[acl]` 表达"只允许某些来源"时，
/// **UDP 代理完全不遵守**（静默失效）。
///
/// # 实测（`tmp/audit9/_indep/verify_udp_acl.py`，12/12 判据全过）
///
/// 服务端绑 `0.0.0.0`、`[acl] deny = ["<LAN>"]`，**只改源地址**：
///
/// | 场景 | 结果 |
/// |---|---|
/// | 不配 ACL，从 LAN 发 UDP | ✅ 通（`UDP-REPLY-HELLO-UDP`） |
/// | **同一条 ACL ⇒ 控制面登录** | ✅ **被拒**（证明 ACL 真的在起作用） |
/// | 从 `127.0.0.1`（放行）发 UDP | ✅ 通（正对照） |
/// | **从 LAN（被 deny）发 UDP** | ❌ **仍被转发**（内网服务收到包数 1 → 2） |
///
/// ⇒ 与 F7-1（TCP 数据面未过 ACL）**完全同型**：
/// 补了 TCP，**UDP 被漏掉了**。
///
/// 这条比面板那条严重：**UDP 代理没有别的防线**（不需要认证），
///   ACL 是唯一的来源管控手段。
pub fn spawn(
    udp: Arc<UdpSocket>,
    proxy_name: String,
    client: Arc<ClientState>,
    sec: Arc<crate::guard::SecurityContext>,
    // 单报文缓冲上限（官方 frps 的 `udpPacketSize`）。
    // 由配置传入而不是写死常量 —— 见 `ServerConfig::udp_packet_size` 的说明。
    packet_size: usize,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        loop {
            // 等待时长由服务端 `userConnTimeout`（默认 10 秒）决定。
            let work = match client.acquire_work_conn().await {
                Some(w) => w,
                None => {
                    if client.is_stopped() {
                        return;
                    }
                    warn!(proxy = %proxy_name, "等待工作连接超时，1s 后重试");
                    tokio::time::sleep(Duration::from_secs(1)).await;
                    continue;
                }
            };
            if let Err(e) = run_session(
                work.conn,
                udp.clone(),
                &proxy_name,
                sec.clone(),
                packet_size,
            )
            .await
            {
                debug!(proxy = %proxy_name, "UDP 工作连接结束：{e:#}");
            }
            if client.is_stopped() {
                info!(proxy = %proxy_name, "UDP 代理已停止");
                return;
            }
            // 工作连接断了就再要一条（与 frp 行为一致）
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
    })
}

/// 一条 UDP 工作连接的生命周期：双向搬运 + 心跳。
///
/// 新增 `sec`，用于在**每个数据报**上做 ACL 判定。
async fn run_session(
    mut conn: FrpConn,
    udp: Arc<UdpSocket>,
    proxy_name: &str,
    sec: Arc<crate::guard::SecurityContext>,
    packet_size: usize,
) -> Result<()> {
    conn.send_msg(&FrpMessage::StartWorkConn(StartWorkConn {
        proxy_name: proxy_name.to_string(),
        ..Default::default()
    }))
    .await
    .context("发送 StartWorkConn 失败")?;

    // 公网 UDP 报文 → 队列 → 工作连接。
    // FrpConn 是单所有者，所以读写都收敛在本任务的 select 里，避免加锁。
    let (to_client_tx, mut to_client_rx) = mpsc::channel::<UdpPacket>(1024);

    // **记录"真的给我们发过包的访客 IP"**。
    //
    // # 漏洞（报告判"不可利用"，我核实后认为**有一个真实增量**）
    //
    // 服务端下面回写访客时，直接用客户端自报的 `pkt.remote_addr`（第 115 行附近），
    // **不做任何来源校验**。
    //
    // 报告的论证是"provider 客户端只是原样回填服务端下发的地址 ⇒ 不可利用"。
    // 那对**诚实的 frpc** 成立。但它漏了一点：**恶意/被控的客户端可以直接
    // 指定任意 `remote_addr`**，从而让 frps 向**从未给 frps 发过包**的地址发 UDP。
    //
    // 正常路径下 frps 只向"刚给它发过包"的地址回包（`recv_from` 拿到的 `src`）；
    // 而恶意客户端可以打破这个约束 ⇒ **frps 变成"无需请求的 UDP 发射源"**，
    // 可被用作 UDP 反射/放大的跳板（把源 IP 指向受害者，
    // 流量从 frps 的 IP 发出）。
    //
    // 报告说的"他本来就能转发任意内容"是对的，但那要求**先有访客发包**；
    // 这里多出来的能力是"**无需访客、直接指定目标**"。
    //
    // # 修法：IP 级白名单（**端口无关**）
    //
    // 只允许回写给"最近真的发过包的访客 IP"。**刻意不校验端口** ——
    // TFTP 之类协议会**换一个端口**回包（甚至换到新的临时端口），
    // 卡死端口会误伤它们；而反射/放大攻击必须跨 **IP**（把响应打给受害者），
    // 所以按 IP 收紧就足以堵住那条路，兼容风险极小。
    //
    // # 为什么这不是"把客户端当敌人"
    //
    // 客户端本来就是**租户自己的**代码，frps 不该无条件信任它指定的任意目标 ——
    // 尤其 frps 是**多租户**的：一个租户恶意，受害的是 frps 的 IP 声誉
    // 和链路上的第三方。
    let seen_ips = Arc::new(SeenVisitorIps::default());

    let udp_task = {
        let udp = udp.clone();
        let seen_ips = seen_ips.clone();
        // `proxy_name` 是 `&str`，而 spawn 的任务要求 `'static`
        //   （日志里要用它）⇒ 克隆一份。这只是一次短字符串分配，可忽略。
        let proxy_name_owned = proxy_name.to_string();
        tokio::spawn(async move {
            let mut buf = vec![0u8; packet_size];
            loop {
                match udp.recv_from(&mut buf).await {
                    Ok((n, src)) => {
                        //    **UDP 数据面也要过 ACL**。
                        //
                        // 这是 ACL 在 UDP 代理端口上**唯一**的判定点 ——
                        // UDP 没有"连接建立"这个时刻，只能在每个数据报上判。
                        //
                        // 顺序与 TCP 侧一致：ACL 是一次位运算，放在最前面最便宜。
                        // 拒绝时**静默丢弃**（不回任何 UB 报文，也不记 seen_ips）：
                        // 被拒的 IP 不该因为"发过包"而获得回写资格。
                        if let Err(reason) = sec.check_ip(src.ip()) {
                            debug!(
                                %src,
                                proxy = %proxy_name_owned,
                                "UDP 数据面 IP 访问控制拒绝：{reason}"
                            );
                            continue;
                        }
                        // 记下这个"真的发过包的"访客 IP
                        seen_ips.record(src.ip());
                        if to_client_tx
                            .send(UdpPacket::new(&buf[..n], &src))
                            .await
                            .is_err()
                        {
                            return;
                        }
                    }
                    Err(e) => {
                        debug!("UDP 读取失败：{e}");
                        return;
                    }
                }
            }
        })
    };

    let mut keepalive = interval(KEEPALIVE_INTERVAL);
    keepalive.tick().await; // 丢掉立即触发的那次

    // 越界回写只 warn 一次，之后降 debug（防日志刷屏）
    let mut warned_off_path = false;

    let result = loop {
        tokio::select! {
            // 客户端 → 访客
            msg = conn.recv_msg() => {
                let Some(msg) = msg? else { break Ok(()) };
                match msg {
                    FrpMessage::UdpPacket(pkt) => {
                        if let Some(dst) = pkt.remote_addr.as_ref().and_then(|a| a.to_socket()) {
                            // 只回写给"真的给我们发过包的访客 IP"。
                            //
                            // 恶意客户端可以在这里塞任意地址，让 frps 向从未
                            // 请求过的目标发 UDP（反射/放大跳板）。
                            if !seen_ips.allows(dst.ip()) {
                                // 首次 warn（让运维看得见），之后降到 debug（防刷屏）。
                                // 这条**只在客户端行为异常时**触发，正常情况下
                                // 一次都不会出现。
                                if !warned_off_path {
                                    warned_off_path = true;
                                    warn!(
                                        %dst,
                                        proxy = %proxy_name,
                                        "客户端要求向一个从未向本代理发过包的 IP 回写 UDP，已丢弃。\
                                         这通常是客户端被改坏或被控（L18 防反射）；\
                                         后续同类丢弃只记 debug"
                                    );
                                } else {
                                    debug!(%dst, proxy = %proxy_name, "再次丢弃越界回写（L18）");
                                }
                                continue;
                            }
                            if let Err(e) = udp.send_to(pkt.payload(), dst).await {
                                debug!(%dst, "UDP 回写访客失败：{e}");
                            }
                        } else {
                            debug!("UDP 报文缺少访客地址，丢弃");
                        }
                    }
                    FrpMessage::Ping(_) => {
                        // 客户端心跳，无需回包
                    }
                    other => debug!("UDP 工作连接忽略消息：{}", other.name()),
                }
            }
            // 访客 → 客户端
            Some(pkt) = to_client_rx.recv() => {
                if let Err(e) = conn.send_msg(&FrpMessage::UdpPacket(pkt)).await {
                    break Err(e).context("UDP 报文写往工作连接失败");
                }
            }
            _ = keepalive.tick() => {
                let _ = conn.send_msg(&FrpMessage::Ping(Ping::default())).await;
            }
        }
    };

    udp_task.abort();
    result
}

/// 绑定 UDP 端口。
pub async fn bind_udp(bind_addr: &str, port: u16) -> Result<UdpSocket> {
    let addr: SocketAddr = nfrp_common::util::resolve_addr(&format!("{bind_addr}:{port}")).await?;
    UdpSocket::bind(addr)
        .await
        .with_context(|| format!("监听 UDP {addr} 失败"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    /// **从未发过包的 IP 不许回写**。
    ///
    /// 修复前服务端直接拿客户端自报的 `pkt.remote_addr` 去 `send_to`，
    /// 于是恶意客户端能让 frps 向**从未请求过**的目标发 UDP
    /// ⇒ frps 成为"无需请求的 UDP 发射源"（反射/放大跳板）。
    #[test]
    fn 未见过包的_ip_不许回写() {
        let seen = SeenVisitorIps::default();

        // 什么都没收到时，谁都不许回写
        assert!(!seen.allows(ip("203.0.113.7")), "空集合不得放行任何地址");

        // 记下真实访客后，它自己可以
        seen.record(ip("203.0.113.7"));
        assert!(seen.allows(ip("203.0.113.7")), "见过的访客应放行");

        // 关键：别人仍然不行（这正是反射攻击的目标）
        assert!(
            !seen.allows(ip("198.51.100.9")),
            "没给我们发过包的 IP 必须被拒（否则可被当反射源）"
        );
    }

    /// 端口无关：TFTP 之类"换端口回包"的协议不能被误伤。
    ///
    /// 而反射/放大必须**跨 IP**（把响应打给受害者），所以按 IP 收紧就够，
    /// 不必（也不该）卡端口。
    #[test]
    fn 同一个_ip_换端口仍放行() {
        let seen = SeenVisitorIps::default();
        seen.record(ip("203.0.113.7"));

        // `allows` 只收 IpAddr，所以端口天然不参与判定 ——
        // 这条测试把这个设计意图**钉死**：将来有人改成收 SocketAddr
        // 做全字段比对，就会破坏 TFTP 场景。
        assert!(seen.allows(ip("203.0.113.7")));
    }

    /// IPv4 / IPv6 各自独立，不能互相串。
    #[test]
    fn v4_与_v6_互不放行() {
        let seen = SeenVisitorIps::default();
        seen.record(ip("203.0.113.7"));
        assert!(seen.allows(ip("203.0.113.7")));
        assert!(
            !seen.allows(ip("2001:db8::1")),
            "v6 地址不得被 v4 的登记放行"
        );
        assert!(
            !seen.allows(ip("::ffff:203.0.113.7")),
            "v4-mapped v6 也是不同地址"
        );
    }

    /// 超过上限时**清空重建**，内存不无上限增长（且不 panic）。
    #[test]
    fn 超过上限要清空而不是无限增长() {
        let seen = SeenVisitorIps::default();
        // 塞满 + 再多一条，触发清空路径
        for i in 0..(MAX_SEEN_VISITOR_IPS + 10) {
            let a = (i % 250) as u8;
            let b = ((i / 250) % 250) as u8;
            seen.record(IpAddr::from([10, a, b, 1]));
        }
        assert!(
            seen.len() <= MAX_SEEN_VISITOR_IPS,
            "集合不得超过上限，实际 {}",
            seen.len()
        );
        // 清空之后刚记下的那个必须仍在（不能整个丢掉）
        seen.record(ip("192.0.2.5"));
        assert!(seen.allows(ip("192.0.2.5")));
    }

    /// 多线程并发登记不 panic、结果可用（锁中毒路径不该被触发）。
    #[test]
    fn 并发登记安全() {
        let seen = Arc::new(SeenVisitorIps::default());
        let mut hs = Vec::new();
        for i in 0..8u8 {
            let s = seen.clone();
            hs.push(std::thread::spawn(move || {
                for j in 0..100u8 {
                    s.record(IpAddr::from([172, 16, i, j]));
                }
            }));
        }
        for h in hs {
            h.join().expect("线程不该 panic");
        }
        assert!(seen.allows(IpAddr::from([172, 16, 3, 42])));
    }
}
