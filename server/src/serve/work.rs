//! visitor 准入与工作连接认证 / 配对。
//!
//! 职责：`admit_user` 的用户连接配额与排队、`handle_work` 的工作连接身份
//! 校验（NLink 令牌 / 插件 / 凭证 / 同源 IP / 线协议）与配对、
//! `handle_visitor` 的 stcp / xtcp / sudp 准入，以及 `reject` / `reject_with`
//! 的脱敏拒绝响应。
//!
//! 锁顺序契约：registry → client state → pool。工作连接只从 `Registry` 取
//! `ClientState` 快照后操作其内部锁；`admit_user` 先读 `Registry` 指标与上限，
//! 再进 `ClientState` 队列。`reject_with` 只读指标原子量并写连接，不加锁。
//!
//! 不变量：`conns_total` 只在准入成功时 +1；`conns_active` 只由 `bridge`
//! 的 `ConnGuard` 在配对成功那一刻 +1；`visitor_rejected` 每条拒绝 +1。

use std::{net::SocketAddr, sync::Arc, time::Instant};

use anyhow::{anyhow, Context, Result};
use nfrp_common::{
    config::ServerConfig,
    frp::{
        conn::FrpConn,
        msg::{FrpMessage, Login, NewVisitorConn, NewVisitorConnResp, NewWorkConn},
        stream::PrefixedStream,
    },
};
use tracing::{debug, info, warn};

use crate::{
    pool::{ClientState, ConnSlot, PendingUser, Submit, WorkItem},
    registry::Registry,
};

use super::bridge::{spawn_bridge, spawn_sudp_bridge};

/// 把一条用户连接交给客户端：先过配额，再排队配对。
///
/// 三条验收规则：
/// 1. **没有转发配额**（命中全局或单客户端上限）——立刻关连接，不留尾巴；
/// 2. **队列已满**——同样立刻关，别让它无限堆积；
/// 3. 成功入队——记得向控制连接索要一条新的工作连接。
pub fn admit_user(user: PendingUser, client: &Arc<ClientState>, registry: &Arc<Registry>) {
    if user.slot.is_none() {
        registry.metrics().conns_rejected.inc();
        warn!(
            proxy = %user.proxy,
            "转发连接数已达上限（全局 {} / 客户端 {}），拒绝本次连接",
            registry.limits().max_total_conns,
            registry.limits().max_conns_per_client
        );
        return;
    }
    registry.metrics().conns_total.inc();
    // ★★ v0.5.6 修（审计总报告 M7）：`conns_active.inc()` **不在这里**。
    //
    // 原先 `admit_user` 与 `handle_work` 各 inc 一次，而 `finish_conn` 只 dec 一次
    // ⇒ "用户先到、工作连接后到"这条路径 **+2 / -1**，每来一条连接就虚高 1。
    // 现在把 +1 收敛到配对成功的**唯一那一刻**（`bridge` 里的 `ConnGuard`）。
    match client.submit_user(user) {
        Submit::Paired(pair) => {
            let p = *pair;
            spawn_bridge(p.user, p.work, registry.clone())
        }
        Submit::Queued => client.request_work_conn(),
        Submit::Full(_u) => {
            registry.metrics().conns_rejected.inc();
            warn!(proxy = %_u.proxy, "待配对队列已满，拒绝本次连接");
        }
    }
}

// ---------------------------------------------------------------------------
// 工作连接
// ---------------------------------------------------------------------------

pub(super) async fn handle_work(
    mut conn: FrpConn,
    mut msg: NewWorkConn,
    sec: &crate::guard::SecurityContext,
    registry: Arc<Registry>,
    peer: SocketAddr,
) -> Result<()> {
    let mut client = registry
        .get(&msg.run_id)
        .ok_or_else(|| anyhow!("找不到 run_id={} 对应的客户端", msg.run_id))?;

    // ---- NLink 零信任身份 ----
    //
    // 会话协商了 `identity` 才要求令牌。令牌绑定 `run_id + user + 过期时间`，
    // 由服务端 HMAC 签发 —— 比"源 IP 相同"强得多：拿到 run_id 也伪造不出来，
    // 而且过期就作废。官方 frpc 不会协商这个能力，所以永远走不到这里。
    if client.nlink_has(nfrp_common::nlink::CAP_IDENTITY) {
        let rt = registry.nlink();
        let token = msg.nlink.clone().unwrap_or_default();
        if let Err(e) = rt.identity.verify(
            &token,
            &msg.run_id,
            &client.user,
            std::time::SystemTime::now(),
        ) {
            tracing::debug!(run_id = %msg.run_id, user = %client.user, "身份令牌校验失败：{e:#}");
            registry.audit().record(
                crate::audit::AuditEvent::new(crate::audit::kind::LOGIN_DENIED, false)
                    .client(msg.run_id.clone())
                    .ip(peer.ip().to_string())
                    .detail(format!("工作连接身份令牌校验失败：{e:#}")),
            );
            anyhow::bail!("工作连接身份令牌校验失败：{e:#}");
        }
    }

    // 官方 `[[httpPlugins]]`：NewWorkConn。插件在凭证校验之前执行，
    // 可以拒绝（例如池被盗用）或改写 run_id / privilege_key。
    if !registry.plugins().is_empty() {
        let plugins = registry.plugins();
        let user = nfrp_common::plugin::user_info(
            &Login {
                user: client.user.clone(),
                ..Default::default()
            },
            &client.run_id(),
        );
        let content = nfrp_common::plugin::content_with_user(&msg, user)?;
        let new_content = plugins
            .handle_mutable(nfrp_common::plugin::OP_NEW_WORK_CONN, content)
            .await
            .map_err(|e| anyhow!("HTTP 插件拒绝工作连接：{e}"))?;
        msg = serde_json::from_value(new_content).context("插件返回的 NewWorkConn 内容无法解析")?;
        client = registry
            .get(&msg.run_id)
            .ok_or_else(|| anyhow!("插件改写后的 run_id={} 不存在", msg.run_id))?;
    }

    // ★★ v0.5.5 修（第四轮 A-1，高危）：工作连接必须绑定到**发起它的那个客户端**。
    //
    // 原先这里被 `auth_method() == Oidc` 门住，于是 **token 模式（默认）下
    // `msg.privilege_key` / `msg.timestamp` 从头到尾没人读** —— `run_id` 成了
    // 唯一门槛。而 `run_id` 是在 v1 的 `LoginResp` 里**明文**下发的
    // （登录前的报文不加密），所以拿到它并不难。
    //
    // 实测危险（`tmp/audit4-verify-A2b.py`，用真 frpc 拿真 run_id）：
    //
    // ```text
    // privilege_key 空 + ts=0        -> 接受（连接保持）
    // privilege_key 错误 + ts=1       -> 接受
    // privilege_key 垃圾 + 当前 ts     -> 接受
    // privilege_key 任意 + ts=-1      -> 接受
    // 服务端日志：工作连接进入空闲池 client=client-83284   × 5
    // ```
    //
    // 后果：攻击者往**受害者的空闲工作连接池**里灌自己的连接，
    // 此后连到受害者隧道的用户流量会落到攻击者的连接上 —— 完整 MITM。
    // A 组独立复现时 6/6 用户连接全部被劫持。
    //
    // ★★ 但"一刀切要求凭证"会**破坏与官方 frpc 的互通** —— 这是实测出来的，
    //   不是推测。官方 `pkg/auth/token.go` 的 `SetNewWorkConn`：
    //
    // ```go
    // if !slices.Contains(auth.additionalAuthScopes, v1.AuthScopeNewWorkConns) {
    //     return nil          // ← 不改 PrivilegeKey，保持零值 ""
    // }
    // ```
    //
    //   即**默认配置下官方 frpc 的工作连接不带凭证**。第一版修复直接要求
    //   "凭证必须等于 auth_key(token, ts)"，实测结果（`tmp/audit4-a1-diag.py`）：
    //
    // ```text
    // DEBUG yamux stream 结束：工作连接凭证不符（privilege_key 不是本会话 token 派生的）
    // → 官方 frpc 的 tcp 代理完全不通（用户连接超时）
    // ```
    //
    //   README 明确承诺"官方客户端不需要改任何配置就能连上"，所以不能这么修。
    //
    // ★★ 最终策略（既不破坏互通、又堵住劫持）：
    //
    // | 凭证 | 处理 |
    // |---|---|
    // | **非空** | 必须等于 `auth_key(token, ts)`（NFrp 客户端走这条） |
    // | **为空** | 要求工作连接的**源 IP 与控制连接一致**（官方 frpc 走这条） |
    //
    //   官方 frpc 天然满足"同源 IP"（同一个进程、同一个出口），**零兼容代价**；
    //   而攻击者要伪造源 IP 比"知道 run_id"难得多。这不是完美方案（NAT 后的
    //   同网段攻击者仍可能同 IP），但比"只查 run_id"强一个数量级。
    //
    //   实测验证：官方 frpc 0.71.0 经本服务端的 tcp 代理**转发成功**，
    //   而伪造凭证的四种形态（空/错误/垃圾/ts=-1）在"空凭证 + 源 IP 不同"
    //   的组合下全部被拒。
    let is_oidc = sec.auth_method() == nfrp_common::security::AuthMethod::Oidc;
    if is_oidc {
        // OIDC：沿用原有语义（验签 + subject 绑定到会话）
        if sec.auth_cfg.check_new_work_conns() {
            if let Err(e) = sec.verify_followup(&msg.privilege_key, "新工作连接", &msg.run_id)
            {
                registry.audit().record(
                    crate::audit::AuditEvent::new(crate::audit::kind::LOGIN_DENIED, false)
                        .client(msg.run_id.clone())
                        .detail(format!("工作连接凭证复核失败：{e:#}")),
                );
                anyhow::bail!("工作连接凭证复核失败：{e:#}");
            }
        }
    } else {
        // token 模式
        let token = sec.auth().secret().to_string();
        if token.is_empty() {
            // 空 token = 认证本来就没开（启动时已明确告警）。此时凭证无从校验，
            // 仍然要求同源 IP —— 比完全放行强。
            if peer.ip() != client.peer_ip() {
                registry.audit().record(
                    crate::audit::AuditEvent::new(crate::audit::kind::LOGIN_DENIED, false)
                        .client(msg.run_id.clone())
                        .ip(peer.ip().to_string())
                        .detail(format!(
                            "工作连接源 IP {} 与控制连接 {} 不一致（空 token 模式下仍拒绝）",
                            peer.ip(),
                            client.peer_ip()
                        )),
                );
                anyhow::bail!(
                    "工作连接来源与登录来源不一致（{} vs {}）",
                    peer.ip(),
                    client.peer_ip()
                );
            }
        } else if !msg.privilege_key.is_empty() {
            // 带了凭证 ⇒ **必须正确**。这是 NFrp 客户端的路径，
            // 也是攻击者最容易露馅的地方（凭证 = md5(token+ts)，猜不出来）。
            //
            // ★★ v0.5.7 修（第六轮审计 G-1，高危）：**改调 `verify_login`**。
            //
            //   原先这里是就地手写 `auth_key(token, ts)` 比对 —— 内容判对了，
            //   但**不知道有"新鲜性"这回事**（M3 的时间窗口只加在主登录一处）。
            //   实测：**一年前**的 `NewWorkConn` 凭证仍被接受，并且打通了
            //   完整双向 MITM（用户的明文落到攻击者手里、回包由攻击者伪造）。
            //
            //   改调 `verify_login` 而不是在这里补一行 `check_freshness`，
            //   是刻意的：前者的 `skew` 是**必需参数**，想校验凭证就必然
            //   带上时间窗口 —— 堵掉"下次又有人忘了加"的可能。
            //   token 模式下 `verify_login` 判的正是同一件事
            //   （`expected = auth_key(secret, ts)` 再定长比较），语义等价。
            if let Err(e) = sec.verify_login(&msg.privilege_key, msg.timestamp, &msg.run_id) {
                registry.audit().record(
                    crate::audit::AuditEvent::new(crate::audit::kind::LOGIN_DENIED, false)
                        .client(msg.run_id.clone())
                        .ip(peer.ip().to_string())
                        .detail(format!("工作连接凭证校验失败：{e:#}")),
                );
                anyhow::bail!(
                    "工作连接凭证不符（privilege_key 不是本会话 token 派生的，或已过期）"
                );
            }
        } else if client.caps().work_conn_cred {
            // ★★ 这条会话**自己声明过**"我的工作连接带凭证"
            //   （NFrp ≥ 0.5.5 恒声明，见 `client/src/main.rs`）。
            //   那它就必须带，且必须正确 —— **空凭证也拒**。
            //
            //   这是最有说服力的判据：`work_conn_cred` 是**受害者自己**在
            //   登录时声明的，攻击者改不了它。所以"拿 run_id 冒充"这条路
            //   在这里彻底断了，不必依赖源 IP（同 NAT 后的攻击者也拦得住）。
            registry.audit().record(
                crate::audit::AuditEvent::new(crate::audit::kind::LOGIN_DENIED, false)
                    .client(msg.run_id.clone())
                    .ip(peer.ip().to_string())
                    .detail("会话声明了 workConnCred 能力，但工作连接未携带凭证".to_string()),
            );
            anyhow::bail!("该会话声明了工作连接凭证能力，但本次工作连接未携带凭证");
        } else if peer.ip() != client.peer_ip() {
            // 没声明这个能力（官方 frpc、或老版 NFrp）：官方默认**不带凭证**，
            // 所以不能拦。退而求其次 —— 要求同源 IP。
            //
            // ★★ v0.5.6 修（审计总报告 L5，低危）：**把"可能是误拒"说清楚**。
            //
            // 这条判据在**混合传输**下可能误伤合法用户：控制连接走 TCP、
            // 工作连接走 QUIC（`protocol = "quic"`）时，两条连接的出口 IP
            // 可能不同 —— 多宿主机、多网卡、或 NAT 池有多个公网 IP 时都会发生。
            // 而官方 frpc 不带凭证，所以它**必然**走这条分支。
            //
            // 现状下用户的症状是：**控制连接登录成功、但每条用户连接都失败**，
            // 日志里只有一句"来源与登录来源不一致" —— 完全指不到"是网络路径不同"。
            //
            // ★ 为什么**不**放宽判据（如实说明）：
            //   放宽就等于让"拿 run_id 冒充"重新变得容易（那正是 A-1 要堵的）。
            //   在"可用性"和"防冒充"之间，这里选择**保住防线**，
            //   但把诊断信息补足，让人能一眼看出自己踩的是哪种情况。
            // ★ 提示语之所以**不**按"哪种传输"分支：`handle_work` 里拿不到
            //   服务端配置（它只收 registry / peer / conn），而为了写一句提示
            //   去把 `Arc<ServerConfig>` 一路传进来，代价大于收益。
            //   两种情况合并成一条，信息量一样够用。
            let hint = "（常见原因：多网卡 / NAT 池有多个出口 IP / 中间有代理，\
                        或控制连接与工作连接走了不同传输（TCP vs QUIC/KCP）\
                        导致出口 IP 不同；\
                        升级到 NFrp ≥0.5.5 客户端可改用凭证校验，不再依赖源 IP）";
            registry.audit().record(
                crate::audit::AuditEvent::new(crate::audit::kind::LOGIN_DENIED, false)
                    .client(msg.run_id.clone())
                    .ip(peer.ip().to_string())
                    .detail(format!(
                        "工作连接源 IP {} 与控制连接 {} 不一致（无凭证时必须同源）",
                        peer.ip(),
                        client.peer_ip()
                    )),
            );
            warn!(
                run_id = %msg.run_id,
                work_ip = %peer.ip(),
                control_ip = %client.peer_ip(),
                "工作连接与控制连接来源 IP 不一致，已拒绝 —— 若你确认是同一台机器，\
                 多半是两条连接走了不同网络路径"
            );
            anyhow::bail!(
                "工作连接来源与登录来源不一致（{} vs {}）—— 无凭证时必须同源。{hint}",
                peer.ip(),
                client.peer_ip()
            );
        } else {
            // ★★ v0.5.6 修（审计总报告 M14，中危）：**放行分支也必须审计**。
            //
            // 原先这条"无凭证 + 同源 IP ⇒ 放行"的路径**零审计** ——
            // 上面三条拒绝路径全都记了审计事件，唯独**真正放行**的这条什么都没记。
            //
            // 为什么这条特别值得记：它正是 A-1（工作连接凭证）修复的**兼容回退**
            // 分支，也是**最弱**的一条认证路径 —— 只靠源 IP 判断。
            // 攻击者若与受害者在同一出口 IP（同 NAT、同办公网、云上同 VPC），
            // 这里就是唯一还能拦住他的地方，而它**原本在日志里完全不可见**。
            //
            // ⇒ 事后审计时，"哪些工作连接是靠最弱判据放行的"必须是可回答的。
            //   记成 `detail` 而不是独立事件类型，是为了不改变既有事件 schema
            //   （避免下游解析器被新类型打乱）。
            registry.audit().record(
                crate::audit::AuditEvent::new(crate::audit::kind::LOGIN, true)
                    .client(msg.run_id.clone())
                    .user(client.user.clone())
                    .ip(peer.ip().to_string())
                    .target(msg.run_id.clone())
                    .detail(format!(
                        "工作连接以**无凭证 + 同源 IP** 放行（客户端未声明 workConnCred 能力，\
                         判据仅源 IP={}）；若要收紧请升级客户端到 ≥0.5.5",
                        peer.ip()
                    )),
            );
        }
    }
    // 工作连接必须与控制连接用同一套线协议 —— 与官方 frps 的
    // `work connection wire protocol mismatch` 检查对齐。
    // 对不上的话后面收发消息会直接解析失败，报错信息离原因很远，所以先挡下来。
    if conn.version() != client.wire_version() {
        anyhow::bail!(
            "run_id={} 的工作连接线协议是 {}，控制连接是 {}",
            msg.run_id,
            conn.version(),
            client.wire_version()
        );
    }
    // 工作连接继承控制连接协商出的 UDP 报文编码
    conn.set_udp_codec(client.udp_codec_is_binary());
    let work = WorkItem::new(conn);
    match client.submit_work(work) {
        Some(p) => {
            debug!(proxy = %p.user.proxy, "工作连接与排队用户配对");
            // ★★ v0.5.6（M7）：这里**不再** inc —— 计数收敛到 `bridge` 的
            //   `ConnGuard`（配对成功那一刻 +1，作用域结束 -1）。
            //   原先这里与 `admit_user` 各加一次，于是 +2/-1 虚高。
            spawn_bridge(p.user, p.work, registry.clone());
        }
        None => debug!(client = %client.client_id, "工作连接进入空闲池"),
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// visitor 连接（stcp / xtcp 的接入方）
// ---------------------------------------------------------------------------

/// 回一条错误响应并结束（官方 frpc 会把 error 原样打到日志上）。
pub(super) async fn reject(
    conn: &mut FrpConn,
    proxy_name: &str,
    err: String,
    registry: &Registry,
) -> Result<()> {
    reject_with(conn, proxy_name, err, registry, None).await
}

/// 同上，但把"回给对端的文案"与"日志里的详情"分开。
///
/// ★ v0.5.3 修：visitor 这条路径原来**完全没走** `detailed_errors_to_client`
/// 开关，把内部细节原样回给了**尚未通过任何认证**的来访者，包括：
///
/// * 代理名是否存在（可用来枚举 stcp 隧道名）；
/// * `allow_users` 里的真实用户名（`visitor connection of [x] user [alice] not allowed`）；
/// * `run_id` 是否在线。
///
/// 现在：`client_msg = None` 时按开关脱敏成短句，详情只留在服务端日志/审计里。
pub(super) async fn reject_with(
    conn: &mut FrpConn,
    proxy_name: &str,
    err: String,
    registry: &Registry,
    client_msg: Option<String>,
) -> Result<()> {
    registry.metrics().visitor_rejected.inc();
    // 日志始终保留完整详情（排障需要），但对端只看到脱敏后的文案
    let shown = client_msg.unwrap_or_else(|| err.clone());
    let _ = conn
        .send_msg(&FrpMessage::NewVisitorConnResp(NewVisitorConnResp {
            proxy_name: proxy_name.to_string(),
            error: shown,
        }))
        .await;
    // 必须优雅关闭：直接 drop 会变成 RST，对端读不到 error，只会看到 connection reset
    let _ = conn.shutdown().await;
    anyhow::bail!("visitor 接入被拒绝：{err}");
}

/// 处理一条 visitor 连接：校验 -> 回 Resp -> 与 provider 的工作连接配对。
///
/// 配对成功后这条 visitor 连接就变成"用户连接"，转发逻辑与 tcp 完全一样。
/// SUDP 例外：数据面是 UDP 帧（`UdpPacket` 消息），走 [`sudp_bridge`] 而不是裸字节 relay。
pub(super) async fn handle_visitor(
    mut conn: FrpConn,
    msg: NewVisitorConn,
    registry: Arc<Registry>,
    cfg: Arc<ServerConfig>,
) -> Result<()> {
    let proxy_name = msg.proxy_name.clone();

    // 1) run_id 必须能对上一条已登录的控制会话（对应 frps 的 admitVisitorByRunID）
    //
    // ★★ v0.5.7 修（第六轮审计 D-2，中危）：**空 `run_id` 不再被放行**。
    //
    // # 原先为什么错了
    //
    // 原判据是 `if !msg.run_id.is_empty() && registry.get(&msg.run_id).is_none()`
    // —— `run_id` 为空时**整条判断被短路**，于是"会话存在性"这一环被整个跳过。
    // 接着身份推导 `registry.get(&msg.run_id).map(|c| c.user).unwrap_or_default()`
    // 在空 `run_id` 下退化成**空串**，而 `check_user` 里
    // `.any(|u| u == "*" || u == visitor_user)` 让空串**命中 `"*"`** ⇒
    // **一条完全没有登录、没有 token、没有 run_id 的连接**被判定为合法访客。
    //
    // 实测（`tmp/audit6-d/_repro_d2_anon.py`）端到端确认：匿名连接发出的
    // `ANON-PAYLOAD-FROM-NOBODY` **真的到达了 alice 的工作连接**。
    //
    // # 为什么可以要求非空
    //
    // 官方 frpc 的 visitor **一定**会带自己的 `run_id`
    // （`common/src/frp/msg.rs` 的 `NewVisitorConn.run_id` 字段注释），
    // 所以这个收紧对官方客户端**零影响**；而"字段缺失 ⇒ 跳过校验"
    // 本来就是认证路径上最危险的模式之一。
    //
    // 文案与下面所有拒绝路径**完全一致**（不新增可区分信息）——
    // 否则"空 run_id 被单独拒绝"本身又成了一个可区分信号。
    let Some(session) = registry.get(&msg.run_id) else {
        // ★★ v0.5.5 修（第四轮 A-3）：**这一条无论如何都只回通用文案**，
        // 不受 `detailed_errors_to_client` 影响。
        //
        // 为什么单独处理它：它本质上是一个 **run_id 在线预言机** ——
        // 攻击者可以拿任意 run_id 来问"这个会话在线吗"。而
        // `detailed_errors_to_client` 默认是 `true`（与官方一致），
        // 于是默认配置下这个预言机是**敞开的**（实弹 `tmp/a4_t10_state.py`
        // 打出三条可区分文本）。现在空 run_id 也走这一条。
        //
        // 为什么可以直接忽略那个开关：`run_id` 是**服务端/客户端内部**生成的，
        // 合法的 visitor 从来不需要"我这条 run_id 在不在线"这个细节 ——
        // 那个开关的存在意义是帮用户排查**自己的配置**（代理名、密钥），
        // 而这条错误里没有任何用户配置信息。所以对它脱敏**不损失可用性**，
        // 只堵掉探测面。详情仍然进服务端日志与审计。
        warn!(
            %proxy_name,
            run_id_empty = msg.run_id.is_empty(),
            "visitor 的 run_id 为空或找不到对应会话"
        );
        return reject_with(
            &mut conn,
            &proxy_name,
            format!("no client control found for run id [{}]", msg.run_id),
            &registry,
            Some("visitor connection failed".to_string()),
        )
        .await;
    };

    // 2) 代理必须已注册
    //
    // ★★ v0.5.7 修（第六轮审计 D-4，中危）：**两条拒绝路径共用同一条文案**。
    //
    // # 原先为什么错了
    //
    // 原注释写着"短句与『密钥不对』保持同一形态，攻击者无法据此区分
    // 『名字错』还是『名字对但密钥错』" —— **但代码没有做到**：
    // 这里回 `custom listener for [X] doesn't exist`，
    // 下面密钥失败回 `visitor connection of [X] auth failed`，
    // 两条**结构完全不同**；而且它们都经过 `cfg.error_to_client(...)`，
    // 受 `detailed_errors_to_client` 控制 —— 那个开关**默认为 `true`**，
    // 所以注释声称的"无法区分"**在默认配置下完全不成立**。
    //
    // 实测（`tmp/audit6-d/d06c_oracle.py`）：4/4 真实隧道名被识别为"存在"、
    // 3/3 假名被排除，**准确率 100%**，而且**不需要登录 / token / run_id**
    // （配合上面 D-2 的匿名路径）。
    //
    // # 修法：抄同一文件里已经做对的那一处
    //
    // 上面 run_id 预言机（A-3）用的是**硬编码固定文案 + 不经过开关** ——
    // 同一个文件里同类问题的两种处理方式，这次统一成对的那种。
    // 用户排查自己配置所需的信息（"代理名/密钥配错了"）仍然进服务端日志
    // 与审计，只是不再回给未认证的对端。
    let Some(entry) = registry.visitors.get(&proxy_name) else {
        warn!(%proxy_name, "visitor 请求的代理名不存在（细节仅服务端可见）");
        return reject_with(
            &mut conn,
            &proxy_name,
            "visitor connection failed".to_string(),
            &registry,
            Some("visitor connection failed".to_string()),
        )
        .await;
    };

    // 3) 密钥签名校验：hex(md5(secret_key + timestamp))
    //
    // ★ v0.5.7（第六轮审计 G-1）：把 `registry` 的时钟窗口传进去 ——
    //   新鲜性校验在 `check_sign` 内部，不是可选项。
    if !entry.check_sign(
        &msg.sign_key,
        msg.timestamp,
        registry.security().max_clock_skew_secs(),
    ) {
        warn!(proxy = %proxy_name, "visitor 密钥校验失败");
        // ★ v0.5.7（第六轮审计 D-4）：文案与"代理名不存在"那条**逐字一致**，
        //   且不经过 `detailed_errors_to_client`（那个开关默认 true，
        //   经过它就等于把"名字对不对"送出去）。
        //   排查信息进服务端日志，不回给未认证的对端。
        return reject_with(
            &mut conn,
            &proxy_name,
            "visitor connection failed".to_string(),
            &registry,
            Some("visitor connection failed".to_string()),
        )
        .await;
    }

    // 4) 访客用户白名单
    //
    // 与官方 frps 一致：比对的**不是** visitor 的 name，而是发起这条 visitor 连接的那个
    // frpc 在 Login 里声明的顶层 `user`（对应 frpc.toml 的 `user = "alice"`）。
    //
    // ★★ v0.5.7 修（第六轮审计 D-2）：**从上面已经取到的 `session` 直接拿**，
    //   不再 `registry.get(&msg.run_id).unwrap_or_default()`。
    //
    //   后者在 `run_id` 为空（或会话刚好掉线）时退化成**空串**，而
    //   `check_user` 里 `.any(|u| u == "*" || u == visitor_user)` 会让
    //   空串**命中 `"*"`** ⇒ 匿名连接被当成合法访客。
    //   现在第 1 步已经保证会话存在，`user` 必然是真实身份。
    let visitor_user = session.user.clone();
    if !entry.check_user(&visitor_user) {
        warn!(proxy = %proxy_name, user = %visitor_user, "visitor 用户不在 allow_users 白名单内");
        // ★ 脱敏：**绝不能**把 allow_users 里的真实用户名回显出去 ——
        //   那直接泄露了"谁被允许访问这条隧道"，也等于确认了这个用户名有效。
        return reject_with(
            &mut conn,
            &proxy_name,
            format!("visitor connection of [{proxy_name}] user [{visitor_user}] not allowed"),
            &registry,
            Some(cfg.error_to_client(
                "visitor connection failed",
                &format!("visitor connection of [{proxy_name}] user not allowed"),
            )),
        )
        .await;
    }

    // 5) 转发配额（stcp 走中继时同样占用一条连接）
    let slot = ConnSlot::acquire(&registry.conn_limit, &entry.client);
    if slot.is_none() {
        registry.metrics().conns_rejected.inc();
        return reject(
            &mut conn,
            &proxy_name,
            "server is busy: too many active connections".to_string(),
            &registry,
        )
        .await;
    }

    // 6) 先回成功（官方 frps 也是先 PutConn 再回 ok，之后才去池里取工作连接）
    conn.send_msg(&FrpMessage::NewVisitorConnResp(NewVisitorConnResp {
        proxy_name: proxy_name.clone(),
        error: String::new(),
    }))
    .await
    .context("发送 NewVisitorConnResp 失败")?;
    registry.metrics().visitor_conns.inc();
    registry.metrics().conns_total.inc();
    // ★★ v0.5.6（M7）：这里**不再** inc —— `bridge` / `spawn_sudp_bridge`
    //   里的守卫会各自在配对成功那一刻 +1，并在离开作用域时 -1。
    //   原先这里 inc + `acquire_work_conn` 失败时手工 dec，是"配对前就加、
    //   失败要手工回滚"的脆弱写法。

    // 7) 向 provider 要一条工作连接并配对
    let Some(work) = entry.client.acquire_work_conn().await else {
        anyhow::bail!("provider [{proxy_name}] 没有可用的工作连接，visitor 连接关闭");
    };

    // SUDP：数据面是 UDP 帧，走专门的搬运路径（与 stcp / xtcp 的裸字节 relay 区分）
    // UDP 编码用该 visitor 连接所属控制会话协商出的值（`ServerAccept::Visitor` 里带过来）
    if entry.proxy_type == "sudp" {
        info!(proxy = %proxy_name, kind = "sudp", "SUDP visitor 接入成功，开始 UDP 帧中继");
        spawn_sudp_bridge(conn, work, registry.clone(), proxy_name.clone());
        return Ok(());
    }

    let (stream, leftover) = conn.into_stream();
    let user = PendingUser {
        proxy: proxy_name.clone(),
        proxy_type: entry.proxy_type.clone(),
        client_user: entry.client.user.clone(),
        client_run_id: entry.client.run_id(),
        // visitor 走的是 visitor 自己那条通道，加密/压缩由它自己协商
        use_encryption: false,
        use_compression: false,
        data_key: None,
        // visitor 没有公网端口概念
        remote_port: 0,
        stream: Box::pin(PrefixedStream::new(leftover, stream)),
        peer: SocketAddr::from(([0, 0, 0, 0], 0)),
        at: Instant::now(),
        slot,
        queue_permit: None,
        load: None,
    };
    info!(proxy = %proxy_name, kind = %entry.proxy_type, "visitor 接入成功，开始中继");
    spawn_bridge(user, work, registry.clone());
    Ok(())
}
