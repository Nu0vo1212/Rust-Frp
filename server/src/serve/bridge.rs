//! 配对后的双向转发与 SUDP 帧中继。
//!
//! 职责：`ConnGuard` 的活跃连接 / 流量 RAII 记账、`spawn_bridge` 的
//! `NewUserConn` 插件闸、`bridge` 的 `StartWorkConn` + 加解密 / 限流中继，
//! 以及 `spawn_sudp_bridge` / `sudp_bridge` / `relay_sudp_frames`。
//!
//! 锁顺序契约：本模块不获取 `Registry` / `ClientState` 的锁；`registry.plugins()`
//! 与 `registry.nlink()` 只取短锁快照。指标计数均为原子量，中继阶段无锁。
//!
//! 不变量：`ConnGuard` 在配对成功那一刻 +1，`Drop` 时恰好 -1（含所有提前返回）；
//! 字节数只由 `record_bytes` 写入、`Drop` 读取；`relay_sudp_frames` 中每条
//! `FrpConn` 只被一个协程独占。

use std::sync::Arc;

use anyhow::{Context, Result};
use nfrp_common::{
    frp::{
        conn::FrpConn,
        msg::{FrpMessage, Login, StartWorkConn, UdpPacket},
    },
    util,
};
use tracing::{debug, warn};

use crate::{
    pool::{PendingUser, WorkItem},
    registry::Registry,
};

/// 活跃转发连接的**计数守卫**。
///
/// # 为什么用 RAII 而不是手工 `dec()`
///
/// 审计报告在 `serve.rs` 里找出**四处**同类问题：
///
/// | 位置 | 问题 |
/// |---|---|
/// | `admit_user` + `handle_work` | **重复 inc**（用户先到 + 工作后到 ⇒ +2 只 -1） |
/// | `CloseProxy` 分支 | 无条件 dec（对不存在的名字也减）—— 同 M8，已修 |
/// | `bridge` 里两处 `?` | 提前返回**漏 dec** |
/// | `sudp_bridge` 里两处 `?` | 同上 |
///
/// ⇒ 攻击者持合法凭证反复"建连接 → 立刻断开"，就能让 `conns_active`
/// **单调上涨**（指标不可信，削弱管理员发现异常的能力；**不构成配额绕过**，
/// 配额走信号量）。
///
/// 关键洞察：这四处**不是四个 bug，是同一个 bug 的四个表现** ——
///   "配对的 +1 与结束的 -1 分散在两处，中间任何一条提前返回都会漏掉 -1"。
///   手工在每个返回点补 `dec()` 只会把"四处"变成"更多处"，下次加一个
///   `?` 又漏。**用 Drop 把 -1 绑到作用域上，就再也不可能漏**。
///
/// 用法：**配对成功那一刻**创建守卫，之后函数怎么返回都无所谓：
///
/// ```ignore
/// let _guard = ConnGuard::new(&registry);   // +1
/// ... 任意多个 `?` ...
/// ```                                       // 作用域结束自动 -1
pub(super) struct ConnGuard<'a> {
    registry: &'a Registry,
    /// 结束时要把流量统计一起记账（`relay_between` 的返回值）。
    bytes: std::cell::Cell<(u64, u64)>,
}

impl<'a> ConnGuard<'a> {
    pub(super) fn new(registry: &'a Registry) -> Self {
        registry.metrics().conns_active.inc();
        Self {
            registry,
            bytes: std::cell::Cell::new((0, 0)),
        }
    }

    /// 记下本次转发的字节数（由 relay 的返回值提供）。
    pub(super) fn record_bytes(&self, up: u64, down: u64) {
        self.bytes.set((up, down));
    }
}

impl Drop for ConnGuard<'_> {
    fn drop(&mut self) {
        let (up, down) = self.bytes.get();
        self.registry.metrics().bytes_up.inc_by(up);
        self.registry.metrics().bytes_down.inc_by(down);
        self.registry.metrics().conns_active.dec();
    }
}

pub fn spawn_bridge(user: PendingUser, work: WorkItem, registry: Arc<Registry>) {
    tokio::spawn(async move {
        // 官方 `[[httpPlugins]]`：NewUserConn。
        //
        // 放在所有用户连接路径的汇合点（tcp / vhost / visitor 最终都会走
        // `spawn_bridge`），因此不会出现"只给 tcp 调、http 漏掉"这种
        // 防线铺不满的问题。插件拒绝时直接关闭这条用户连接。
        if !registry.plugins().is_empty() {
            let plugins = registry.plugins();
            let info = nfrp_common::plugin::user_info(
                &Login {
                    user: user.client_user.clone(),
                    ..Default::default()
                },
                &user.client_run_id,
            );
            let content = serde_json::json!({
                "user": info,
                "proxy_name": user.proxy.clone(),
                "proxy_type": user.proxy_type.clone(),
                "remote_addr": user.peer.to_string(),
            });
            if let Err(e) = plugins
                .handle_mutable(nfrp_common::plugin::OP_NEW_USER_CONN, content)
                .await
            {
                registry.metrics().conns_rejected.inc();
                warn!(proxy = %user.proxy, "HTTP 插件拒绝用户连接：{e:#}");
                return;
            }
        }
        if let Err(e) = bridge(user, work, &registry).await {
            debug!("转发结束：{e:#}");
        }
    });
}

/// 通知客户端这条工作连接属于哪个代理，然后开始双向转发原始字节。
pub async fn bridge(user: PendingUser, work: WorkItem, registry: &Arc<Registry>) -> Result<()> {
    let PendingUser {
        proxy,
        remote_port,
        client_user,
        stream: mut user_stream,
        peer,
        use_encryption: user_enc,
        use_compression: user_comp,
        data_key: user_key,
        ..
    } = user;
    let mut work_conn = work.conn;

    // **配对成功这一刻**建守卫 ⇒ +1，且保证**只有一次**。
    //   于是 `admit_user` 与 `handle_work` 里那两处 inc 都不需要了
    //   （它们分别在"用户到达"和"工作连接配对"时各加一次，导致 +2/-1）。
    let guard = ConnGuard::new(registry);

    work_conn
        .send_msg(&FrpMessage::StartWorkConn(StartWorkConn {
            proxy_name: proxy.clone(),
            src_addr: peer.ip().to_string(),
            dst_addr: String::new(),
            src_port: peer.port(),
            dst_port: remote_port,
            ..Default::default()
        }))
        .await
        .context("发送 StartWorkConn 失败")?;

    let (work_stream, leftover) = work_conn.into_stream();

    // leftover 是 frpc → frps 方向多读到的字节。明文时它就是响应的
    // 开头，直接写给用户是对的；但**开了加密/压缩时它是密文前缀**，
    // 直接写给用户会把响应破坏成乱码（实测：用户收到的
    // HTTP 响应长度对不上 / 完全超时）。
    //
    // 所以这里只在"不包" 的情况下直接写；要包的话把 leftover
    // 当作 work_stream 的前缀拼回去，交给 ProxyStream 去解。
    // 标志已随 PendingUser 带下来，这里直接用
    let will_wrap = user_enc || user_comp;
    if !leftover.is_empty() && !will_wrap {
        use tokio::io::AsyncWriteExt;
        user_stream.write_all(&leftover).await?;
    }
    let mut work_stream: nfrp_common::frp::stream::BoxStream = if will_wrap {
        Box::pin(nfrp_common::frp::stream::PrefixedStream::new(
            leftover,
            work_stream,
        ))
    } else {
        Box::pin(work_stream)
    };

    // 无论成功、失败、还是上面某个 `?` 提前返回，`guard` 都会在作用域结束时
    // 归还计数 —— 这就是 RAII 修法的全部价值。
    // 数据面解密 / 解压（官方 transport.useEncryption / useCompression）
    //
    // 与客户端对称：包在**工作连接**这一侧（work_stream = 到 frpc 的那条），
    // 用户连接（user_stream）保持明文。
    //
    // 标志来自注册时记下的 NewProxy 字段。查不到就当没配（明文透传）——
    // 绝不能“查不到就按密文解”，那会把正常流量解成垃圾。
    let (enc, comp) = (user_enc, user_comp);
    // NLink 限流：规则表为空时**完全走原来的路径**（零额外开销、零行为差异）。
    let nlink_rt = registry.nlink();
    let limiter = if nlink_rt.rate_limit_enabled() {
        Some(&nlink_rt.limiter)
    } else {
        None
    };
    let relay_result = match (limiter, enc || comp) {
        (None, true) => {
            let key = user_key;
            debug!(proxy = %proxy, enc, comp, "服务端数据面已启用解密/解压");
            let mut wrapped =
                nfrp_common::frp::proxy_stream::ProxyStream::new(work_stream, key, comp);
            util::relay_between(&mut user_stream, &mut wrapped).await
        }
        (None, false) => util::relay_between(&mut user_stream, &mut work_stream).await,
        (Some(lim), true) => {
            let key = user_key;
            debug!(proxy = %proxy, enc, comp, "服务端数据面已启用解密/解压（带限流）");
            let mut wrapped =
                nfrp_common::frp::proxy_stream::ProxyStream::new(work_stream, key, comp);
            crate::nlink::relay_throttled(lim, &client_user, &proxy, &mut user_stream, &mut wrapped)
                .await
        }
        (Some(lim), false) => {
            crate::nlink::relay_throttled(
                lim,
                &client_user,
                &proxy,
                &mut user_stream,
                &mut work_stream,
            )
            .await
        }
    };

    match relay_result {
        Ok((up, down)) => {
            debug!(proxy = %proxy, "转发结束：上行 {up}B / 下行 {down}B");
            guard.record_bytes(up, down);
        }
        Err(e) => {
            debug!(proxy = %proxy, "转发中断：{e}");
        }
    }
    drop(guard);
    Ok(())
}

/// SUDP 配对：把一条已握手成功的 visitor 连接（`conn`）与 provider 的一条工作连接（`work`）
/// 组成一条 UDP 帧双向通道。
///
/// 与官方 SUDP 一致：
/// * visitor 侧跑 `UdpPacket` 帧（type 13），`remote_addr` 标识"本地应用进程"；
/// * provider 侧同样跑 `UdpPacket` 帧（`udp_proxy::run` 里的那套）；
/// * 服务端只是把**整条 `UdpPacket` 帧（含 `remote_addr`）**原样在两端之间搬过来，
///   不解析 payload —— 这样 provider 侧仍能按 `remote_addr` 把响应写回正确的本地应用；
/// * UDP 编码（JSON / 二进制）必须跟控制会话协商值一致。
pub(super) fn spawn_sudp_bridge(
    conn: FrpConn,
    work: WorkItem,
    registry: Arc<Registry>,
    proxy_name: String,
) {
    tokio::spawn(async move {
        if let Err(e) = sudp_bridge(conn, work, &registry, proxy_name).await {
            debug!("SUDP 转发结束：{e:#}");
        }
    });
}

async fn sudp_bridge(
    visitor_conn: FrpConn,
    work: WorkItem,
    registry: &Arc<Registry>,
    proxy_name: String,
) -> Result<()> {
    let mut provider_conn = work.conn;

    // 配对成功这一刻建守卫 ⇒ +1，且离开作用域必然 -1。
    //   原先 `finish_conn` 只在最后一行调用，而下面 `?` 提前返回时会漏掉
    //   （审计报告指出的 `:1905` / `:1913` 两处）。
    let guard = ConnGuard::new(registry);

    // 与官方 frps 一致：拿到工作连接后**先**发 `StartWorkConn` 告诉客户端
    //   "这条连接服务哪个代理"，之后才谈业务帧。
    //   少了这一步，客户端的 `client_work_conn` 还停在等 StartWorkConn，
    //   收到我们的 UdpPacket 只会报"期望 StartWorkConn"并关掉连接 ——
    //   症状很迷惑：上行有字节、下行永远 0，通道每隔几秒重建一次。
    provider_conn
        .send_msg(&FrpMessage::StartWorkConn(StartWorkConn {
            // 必须用**线上全名**（带 `{user}.` 前缀），客户端按它查本地代理表
            proxy_name: proxy_name.clone(),
            ..Default::default()
        }))
        .await
        .context("发送 StartWorkConn 失败")?;

    // UDP 编码用每条连接**自己**协商出来的值：visitor 连接在握手时定，
    //   provider 工作连接在 `handle_work` 里已从控制会话继承。这里再覆盖一次
    //   （哪怕是"正确"的值）都会与官方 frpc 分叉——它只认协商结果。
    //
    // 双向搬运整条 UdpPacket 帧（含 remote_addr），直到任一端断开。
    // 注意这里按值交出连接：relay_sudp_frames 内部要把每条连接独占给一个协程。
    let (up, down) = relay_sudp_frames(visitor_conn, provider_conn).await?;
    debug!(proxy = %proxy_name, "SUDP 转发结束：上行 {up}B / 下行 {down}B");
    guard.record_bytes(up, down);
    drop(guard);
    Ok(())
}

/// 在两条 frp 连接之间双向搬运整条 `UdpPacket` 帧。
///
/// 搬运的是**完整帧**（保留 `remote_addr`），`Ping` 不转发（各端自己心跳即可），
/// 任一端读关闭（`recv_msg` 返回 `None`）即整体结束。
///
/// 实现：`FrpConn` 是**单所有者**，读写必须收敛进同一个协程的 `select!`
/// （与 `udp_proxy::run_session` 一个套路——它的三个分支都在借用同一个 conn）。
/// 所以这里不是「两读两写四个协程」，而是**两条连接各归一个协程独占**：
/// 协程 A 独占 visitor 连接、协程 B 独占 provider 工作连接，两者用两条 mpsc
/// 通道交换报文。任一端退出会 drop 掉自己那侧的 sender，对侧 `recv` 因此
/// 返回 `None` 而连锁收工，不会留下半边悬挂。
async fn relay_sudp_frames(a: FrpConn, b: FrpConn) -> Result<(u64, u64)> {
    use portable_atomic::{AtomicU64, Ordering};
    use tokio::sync::mpsc;

    // a -> b 方向：协程 A 读 a，协程 B 写 b（上行，访客请求）
    let (to_b_tx, to_b_rx) = mpsc::channel::<UdpPacket>(1024);
    // b -> a 方向：协程 B 读 b，协程 A 写 a（下行，服务回包）
    let (to_a_tx, to_a_rx) = mpsc::channel::<UdpPacket>(1024);

    let up = std::sync::Arc::new(AtomicU64::new(0));
    let down = std::sync::Arc::new(AtomicU64::new(0));

    // 协程 A：独占 visitor 连接
    let side_a = {
        let mut a = a;
        let tx = to_b_tx;
        let mut rx = to_a_rx;
        let down = std::sync::Arc::clone(&down);
        async move {
            loop {
                tokio::select! {
                    msg = a.recv_msg() => {
                        let Ok(Some(m)) = msg else { break };
                        // 只搬 UdpPacket，Ping 等控制帧各端自己消化
                        if let FrpMessage::UdpPacket(pkt) = m {
                            if tx.send(pkt).await.is_err() {
                                break;
                            }
                        }
                    }
                    pkt = rx.recv() => match pkt {
                        Some(pkt) => {
                            let n = pkt.payload().len() as u64;
                            if a.send_msg(&FrpMessage::UdpPacket(pkt)).await.is_err() {
                                break;
                            }
                            down.fetch_add(n, Ordering::Relaxed);
                        }
                        // 对侧协程已收工，队列不再有数据
                        None => break,
                    },
                }
            }
        }
    };

    // 协程 B：独占 provider 工作连接
    let side_b = {
        let mut b = b;
        let tx = to_a_tx;
        let mut rx = to_b_rx;
        let up = std::sync::Arc::clone(&up);
        async move {
            loop {
                tokio::select! {
                    msg = b.recv_msg() => {
                        let Ok(Some(m)) = msg else { break };
                        if let FrpMessage::UdpPacket(pkt) = m {
                            if tx.send(pkt).await.is_err() {
                                break;
                            }
                        }
                    }
                    pkt = rx.recv() => match pkt {
                        Some(pkt) => {
                            let n = pkt.payload().len() as u64;
                            if b.send_msg(&FrpMessage::UdpPacket(pkt)).await.is_err() {
                                break;
                            }
                            up.fetch_add(n, Ordering::Relaxed);
                        }
                        None => break,
                    },
                }
            }
        }
    };

    // 就地并发（不用 spawn：&mut 借用跨不了 'static，而这里已经按值交出所有权）
    tokio::join!(side_a, side_b);

    Ok((up.load(Ordering::Relaxed), down.load(Ordering::Relaxed)))
}
