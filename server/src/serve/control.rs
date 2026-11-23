//! 控制连接状态机。
//!
//! 职责：`handle_control` 的事件循环（NLink 扩展帧、`NewProxy` / `Ping` /
//! `CloseProxy` / NatHole* / 命令回执、请求工作连接、心跳与踢出），以及
//! 续传复用判据 `proxy_signature` 与按名回收 `close_proxy_by_name`。
//!
//! 锁顺序契约：registry → client state → pool。`registry.security()` /
//! `registry.plugins()` / `registry.nlink()` 只取短锁快照后释放；
//! `ClientState` 内部锁只在注册 / 关闭代理时短暂持有；`VhostTable` 锁在
//! `ClientState` 锁之外获取，从不反向。`proxy_signature` 纯计算，不加锁。
//!
//! 不变量：`ClientState` 由本模块创建并唯一写入（受 `ClientGuard` 保护），
//! 工作连接 / 面板只读；`allow_resume` 只在 `Ping` 校验失败等主动断开时置 false。

use std::{
    net::SocketAddr,
    sync::Arc,
    time::{Duration, Instant},
};

use anyhow::{Context, Result};
use nfrp_common::{
    config::ServerConfig,
    frp::{
        conn::FrpConn,
        msg::{FrpMessage, Login, NewProxyResp, Pong},
    },
    util,
};
use tracing::{debug, info, warn};

use crate::{
    pool::{ClientState, CtrlCmd},
    registry::{ClientGuard, Registry},
};

use super::register::{close_proxy_by_name, register_proxy};

// ---------------------------------------------------------------------------
// 控制连接
// ---------------------------------------------------------------------------

#[allow(clippy::too_many_arguments)]
pub(super) async fn handle_control(
    mut conn: FrpConn,
    login: Login,
    run_id: String,
    udp_binary: bool,
    caps: nfrp_common::frp::msg::NfrpCaps,
    wire_version: nfrp_common::frp::WireVersion,
    peer: SocketAddr,
    role: nfrp_common::security::Role,
    cfg: Arc<ServerConfig>,
    registry: Arc<Registry>,
) -> Result<()> {
    let sec = registry.security();
    let client_id = if login.client_id.is_empty() {
        run_id.clone()
    } else {
        login.client_id.clone()
    };
    info!(
        client_id = %nfrp_common::util::LogSafe(&client_id), %run_id, os = %login.os, arch = %login.arch,
        wire = %wire_version, "客户端登录成功"
    );

    let (req_tx, mut req_rx) = tokio::sync::mpsc::unbounded_channel::<CtrlCmd>();
    // **补上上界钳制**。
    //
    // 原先只有 `.max(5)` —— 只挡了 0（免得"0 = 立刻超时"），
    // **没有上界**。于是配置里写一个极大的值（比如 `u64::MAX` 秒）
    // 就让空闲工作连接**永不回收**：
    //
    // * 每个客户端还能预建多条代理的空闲工作连接（官方 `maxPoolCount`
    // 默认 5；NFrp 同样支持该项，默认 0 = 不限）；
    // * 客户端重连后旧连接不会被及时清掉 ⇒ `idle_work_conns` 持续累积
    //   ⇒ fd / 内存缓慢增长，且它**不是**由攻击流量触发的，
    //   运维很难把它和配置项联系起来。
    //
    // 上界取 3600 秒（1 小时）：远大于任何合理配置
    // （默认 60 秒、官方同款），但保证空闲连接**一定**会被回收。
    // 下界 5 秒维持原样（挡住 0 造成的立刻超时）。
    const IDLE_MIN: u64 = 5;
    const IDLE_MAX: u64 = 3600;
    let idle_secs = cfg.work_conn_idle_timeout.clamp(IDLE_MIN, IDLE_MAX);
    if cfg.work_conn_idle_timeout != idle_secs {
        warn!(
            configured = cfg.work_conn_idle_timeout,
            applied = idle_secs,
            "work_conn_idle_timeout 超出 [{IDLE_MIN}, {IDLE_MAX}] 秒，已钳制到 {idle_secs}"
        );
    }
    let idle_timeout = Duration::from_secs(idle_secs);
    let limits = registry.limits().clone();
    let (conn_limit, backlog_limit, proxy_limit) = limits.per_client();
    // 用户连接等配工作连接的超时（`userConnTimeout`）：官方语义是
    // "等不到工作连接就放弃这条用户连接"，默认 10 秒；配 0 折算默认
    // （官方 `EmptyOr` 口径），不会变成"无限等"。
    let user_conn_timeout = cfg.user_conn_timeout();
    let fresh_client = Arc::new(ClientState::new(
        run_id.clone(),
        client_id.clone(),
        login.user.clone(),
        req_tx.clone(),
        idle_timeout,
        user_conn_timeout,
        caps.clone(),
        udp_binary,
        wire_version,
        conn_limit,
        backlog_limit,
        // 单客户端空闲工作连接池上限（`maxPoolCount`，0 = 不限；与
        // `max_pending_per_client` 取更小者，见 `ClientState::new`）。
        cfg.max_pool_count,
        proxy_limit,
        // 控制连接的源 IP：工作连接的空凭证回退校验要用（见 handle_work）
        peer.ip(),
    ));
    // 角色的 `allowManage` 在这里落地：面板能不能增删这个客户端的代理。
    // 角色是在握手函数内部解析出来的，`ClientState::new` 时还拿不到，
    // 所以补写一次。未启用 RBAC 时 role 是 unrestricted（allow_manage = true），
    // 行为与老版本完全一致。
    fresh_client.set_allow_manage(role.allow_manage);

    // ---- NLink v1：协商结果落地 ----
    //
    // 协商本身已经在握手阶段完成（preamble 进、LoginResp._nlink 出），
    // 这里只做三件必须已经拿到 `ClientState` 才能做的事：
    // 落能力位、发身份令牌、处理续传。
    let nlink_state = conn.nlink().cloned();
    let rt = registry.nlink();

    // 断线续传：preamble 里要求了、能力也协商了，才去查续传票。
    //
    // 真正的恢复发生在这一小段：把**暂停中的同一个 `ClientState`**
    // （连同它的代理表、监听器、端口、配额）挂到新控制连接上，
    // 而不是像 0.7.0 那样只回一个 ok=1 然后一切照旧重来。
    let mut resumed_session: Option<crate::registry::SuspendedSession> = None;
    if let Some(st) = &nlink_state {
        info!(
            caps = %st.caps,
            trace = %st.trace,
            session = %st.session,
            "NLink v1 协商成功"
        );
        if st.caps.contains(nfrp_common::nlink::CAP_RESUME) && st.resume {
            let mut restored: Vec<String> = Vec::new();

            // 客户端在 preamble TLV 里出示的一次性令牌（0.7.1 及更早没有这个）。
            let preamble_token: Option<String> = st.resume_token.clone();

            // 第一步：校验一次性续传令牌（0.7.2 起）。
            //
            // 只靠 user + client_id + session_id 是不够的：那三个值都是**标识**
            // 而不是凭证，明文链路上的观察者抄走 preamble 就能冒充。
            // 令牌用 HMAC 绑定四项且登记在待用表里，**用一次就作废**。
            //
            // 顺序很关键：令牌校验必须**先于** take_suspended_if。反过来的话，
            // 一个带错令牌的请求已经把会话取走了，合法客户端回来时就续不上了。
            let presented = preamble_token.as_deref();
            let token_ok = match presented {
                Some(tok) => rt
                    .resume_tokens
                    .consume(
                        st.session,
                        tok,
                        &login.user,
                        &client_id,
                        &rt.resume_key,
                        std::time::SystemTime::now(),
                    )
                    .map_err(|e| {
                        warn!(
                            session = %st.session,
                            client_id = %nfrp_common::util::LogSafe(&client_id),
                            "续传令牌校验失败：{e:#}"
                        );
                        e
                    })
                    .is_ok(),
                None => {
                    // 老客户端（0.7.1 及以前）不会带令牌。为了不把它们的续传
                    // 直接废掉，这里仍然放行，但明确记一条 warn —— 运维能看到
                    // 自己正在用弱凭证形式，也知道升级后会更强。
                    warn!(
                        session = %st.session,
                        client_id = %nfrp_common::util::LogSafe(&client_id),
                        "续传请求没有携带一次性令牌（客户端可能是 0.7.1 或更早），按旧式会话标识校验"
                    );
                    true
                }
            };

            // 注意顺序：**先校验身份再取走**。身份不符时条目原样留在表里，
            // 真正的客户端回来仍然能续上；否则任何人都能用同一个 session id
            // 把别人的暂停会话"取走并回收"，等于一个 DoS。
            if token_ok {
                if let Some(sess) = registry.take_suspended_if(st.session, &login.user, &client_id)
                {
                    // 传输参数（wire / caps / UDP 编码）必须与暂停前一致：
                    // 换了这些还复用旧监听器，后续工作连接会按错误的协议解析。
                    let same_transport = sess.client.wire_version() == wire_version
                        && sess.client.udp_codec_is_binary() == udp_binary
                        && sess.client.caps() == caps;
                    if same_transport && !sess.client.is_stopped() {
                        // 到这里才消费元数据票（它只是可观测性 / 日志用的副本）。
                        let _ = rt.resume.take(st.session);
                        restored = sess.client.proxy_names();
                        // 新 run_id 必须落到 ClientState 上：工作连接查找、
                        // 面板踢出、审计都靠它。
                        sess.client
                            .rebind_control(&run_id, req_tx.clone(), peer.ip());
                        registry.reattach(sess.client.clone());
                        info!(
                            session = %st.session,
                            restored = restored.len(),
                            "断线续传命中：沿用上次的代理与监听端口"
                        );
                        resumed_session = Some(sess);
                    } else {
                        // 传输参数不符（例如客户端换了 wire 版本）：把会话放回，
                        // 既不复用也不销毁 —— 监听器继续等下一次合法续传。
                        warn!(
                            session = %st.session,
                            "续传会话的传输参数与暂停前不一致，保留旧会话并拒绝本次复用"
                        );
                        registry.suspend(st.session, sess);
                    }
                }
            }
            let mut resp =
                nfrp_common::nlink::Frame::new(nfrp_common::nlink::FrameKind::ResumeResp).with(
                    nfrp_common::nlink::frame::TAG_OK,
                    vec![u8::from(resumed_session.is_some())],
                );
            if resumed_session.is_some() {
                resp = resp.with(
                    nfrp_common::nlink::frame::TAG_DETAIL,
                    restored.join("\n").into_bytes(),
                );
            }
            // 无论本次是否续传成功，都签发**下一轮**用的一次性令牌。
            //
            // 续传成功 ⇒ 客户端拿新令牌，下次断线用；旧令牌已在 consume 时作废。
            // 续传失败 ⇒ 仍给一个新令牌，让客户端这次建立的会话也能在未来续传
            //            （否则第一次连上就没凭证，等于续传永远用不了）。
            //
            // 令牌通过这条帧下发，因为此刻控制连接还在 —— 断了就发不出去了，
            // 所以必须"提前给"而不是"断线时给"。
            if let Some(tok) = crate::nlink::issue_resume_token(
                &rt,
                st.session,
                &login.user,
                &client_id,
                cfg.nlink.resume_ttl.max(30),
            ) {
                resp = resp.with(
                    nfrp_common::nlink::frame::TAG_RESUME_TOKEN,
                    tok.into_bytes(),
                );
            }
            conn.send_nlink(&resp).await?;
            if resumed_session.is_none() {
                info!(
                    session = %st.session,
                    "没有可用的续传会话（不存在 / 已过期 / 身份不匹配），按新会话处理"
                );
            }
        }
        // 零信任身份：每会话一张短时令牌，工作连接必须出示。
        //
        // 必须在续传判定之后：令牌绑定的是**新** run_id，先发会把旧 id 签进去。
        if st.caps.contains(nfrp_common::nlink::CAP_IDENTITY) {
            let token = rt.identity.issue(
                &run_id,
                &login.user,
                rt.identity_ttl(),
                std::time::SystemTime::now(),
            );
            let frame = nfrp_common::nlink::Frame::new(nfrp_common::nlink::FrameKind::Identity)
                .with(nfrp_common::nlink::frame::TAG_IDENTITY, token.into_bytes());
            tracing::debug!(run_id = %run_id, "下发 NLink 身份令牌");
            conn.send_nlink(&frame).await?;
        }

        // 一次性续传令牌：**首连也要下发**。
        //
        // 续传判定那一支里已经发过一次（覆盖"带着令牌回来"的路径）；
        // 但首次连接根本不带 FLAG_RESUME，压根不会走进那一支 ——
        // 如果这里不补，客户端第一次连上就永远拿不到令牌，续传等于白做。
        //
        // 两条路径不会重复发：`st.resume` 为真时走上面那一支，为假时走这里。
        if !st.resume {
            if let Some(tok) = crate::nlink::issue_resume_token(
                &rt,
                st.session,
                &login.user,
                &client_id,
                rt.cfg.resume_ttl.max(30),
            ) {
                let frame =
                    nfrp_common::nlink::Frame::new(nfrp_common::nlink::FrameKind::ResumeResp)
                        // ok=0：这不是"续传成功"，只是一张预授令牌
                        .with(nfrp_common::nlink::frame::TAG_OK, vec![0u8])
                        .with(
                            nfrp_common::nlink::frame::TAG_RESUME_TOKEN,
                            tok.into_bytes(),
                        );
                tracing::debug!(run_id = %run_id, "下发一次性续传令牌（首连预授）");
                conn.send_nlink(&frame).await?;
            }
        }
    }

    // 续传命中 → 复用同一份 ClientState（名额沿用暂停时保留的那个）；
    // 否则照常登记新客户端，并受 `max_clients` 约束。
    let (client, mut client_slot) = match resumed_session {
        Some(sess) => (sess.client, sess.slot),
        None => {
            let slot = match registry.insert(fresh_client.clone()) {
                Some(slot) => slot,
                None => {
                    registry.metrics().clients_rejected.inc();
                    warn!(
                        client_id = %nfrp_common::util::LogSafe(&client_id),
                        "客户端数量已达上限 {}，拒绝本次登录", limits.max_clients
                    );
                    let _ = conn
                        .send_msg(&FrpMessage::NewProxyResp(NewProxyResp {
                            proxy_name: String::new(),
                            error: format!(
                                "too many clients (limit = {}), login rejected",
                                limits.max_clients
                            ),
                            ..Default::default()
                        }))
                        .await;
                    let _ = conn.shutdown().await;
                    anyhow::bail!("客户端数量达到上限 {}", limits.max_clients);
                }
            };
            (fresh_client, Some(slot))
        }
    };
    if let Some(st) = &nlink_state {
        client.set_nlink(st.clone());
        // 批量工作连接：只有客户端也协商了才生效。
        if st.caps.contains(nfrp_common::nlink::CAP_BATCH_WORK) {
            client.set_nlink_batch(rt.cfg.batch_work_conn);
        }
    }
    // 续传命中后，本次控制连接从"暂停"恢复为在线。
    client.set_suspended(false);

    let mut _guard = ClientGuard::new(registry.clone(), run_id.clone());

    let mut hb_ticker = tokio::time::interval(Duration::from_secs(5));
    let mut last_seen = Instant::now();
    // 续传对账名单的分片组装器。名单可能超过单帧上限被拆成多帧，
    // 收齐一片才算一轮结算。只有续传会话才会用到，其它会话保持 idle。
    let mut commit_asm = nfrp_common::nlink::frame::CommitAssembler::new();
    // 已下发、还在等回执的管理命令：key 是命令 id
    let mut pending_cmds: std::collections::HashMap<
        String,
        tokio::sync::oneshot::Sender<Result<(), String>>,
    > = std::collections::HashMap::new();
    // 只有"网络断开 / 心跳超时"这类**被动**结束才允许续传。
    // 被插件拒绝、心跳凭证复核失败等**主动**策略断开必须彻底清理，
    // 不能留一个可续传的壳。
    let mut allow_resume = true;

    loop {
        tokio::select! {
            event = conn.recv_event() => {
                // NLink 扩展帧与普通消息走同一个 select：扩展帧**立刻**被处理，
                // 不会因为"等下一条普通消息"而延迟（敲门 / 探测都是时序敏感的）。
                let msg = match event? {
                    nfrp_common::frp::conn::ConnEvent::Msg(m) => *m,
                    nfrp_common::frp::conn::ConnEvent::Closed => break,
                    nfrp_common::frp::conn::ConnEvent::NLink(f) => {
                        last_seen = Instant::now();
                        if f.kind == nfrp_common::nlink::FrameKind::ResumeCommit
                            && client.is_resumed_session()
                        {
                            // 续传后客户端把"最终还在的代理"报上来；没报的一律回收，
                            // 否则配置里删掉的代理会一直占着域名 / 端口。
                            //
                            // 名单可能被拆成多帧（0.7.2 起）：单帧上限 8192 字节，
                            // 代理多的会话一份名单装不下。这里按片组装，收齐才结算。
                            let body = f
                                .tlvs
                                .get_str(nfrp_common::nlink::frame::TAG_DETAIL)
                                .unwrap_or_default();
                            let part: Vec<String> = body
                                .lines()
                                .map(str::trim)
                                .filter(|s| !s.is_empty())
                                .map(str::to_string)
                                .collect();

                            let maybe_wanted = if let Some((idx, total)) =
                                f.tlvs.commit_chunk_info()
                            {
                                match commit_asm.push(idx, total, part) {
                                    Ok(done) => done,
                                    Err(e) => {
                                        // 畸形分片不能让整条会话崩掉，记 warn 后继续
                                        warn!(
                                            client_id = %nfrp_common::util::LogSafe(&client_id),
                                            "ResumeCommit 分片被拒：{e:#}"
                                        );
                                        continue;
                                    }
                                }
                            } else {
                                // 没带分片标记 = 单帧（0.7.1 的格式），直接结算
                                Some(part)
                            };

                            let Some(wanted) = maybe_wanted else {
                                // 还差几片，等下一帧
                                continue;
                            };
                            let mut closed = 0usize;
                            for name in client.proxy_names() {
                                if !wanted.iter().any(|w| w == &name)
                                    && close_proxy_by_name(&registry, &client, &name)
                                {
                                    closed += 1;
                                }
                            }
                            client.finish_resume();
                            debug!(
                                kept = wanted.len(),
                                closed, "续传代理清单已对账，配置里删掉的代理已回收"
                            );
                        } else {
                            crate::nlink::handle_control_frame(&mut conn, &f, &run_id).await?;
                        }
                        continue;
                    }
                };
                last_seen = Instant::now();
                match msg {
                    FrpMessage::NewProxy(m) => {
                        handle_new_proxy(
                            &mut conn, m, &client, &role, &cfg, &registry, &run_id, &login, peer,
                            &sec,
                        )
                        .await?;
                    }
                    FrpMessage::Ping(p) => {
                        if handle_ping(
                            &mut conn, p, &client, &cfg, &registry, &run_id, &login, peer, &sec,
                            &mut allow_resume,
                        )
                        .await?
                        {
                            break;
                        }
                    }
                    FrpMessage::CloseProxy(m) => {
                        handle_close(&client, m, &registry, &run_id, &login, peer).await?;
                    }
                    FrpMessage::NatHoleVisitor(m) => {
                        crate::p2p::handle_nat_hole_visitor(&registry, &client, &m).await?;
                    }
                    FrpMessage::NatHoleClient(m) => {
                        // 官方 frpc 的 provider 收到 NatHoleClient{sid} 后，
                        // 会回一条带自己 mapped_addrs 的 NatHoleClient。
                        // 这是打洞配对的关键一步，不能只记日志丢掉。
                        if !crate::nathole_official::handle_client(&client, &m) {
                            debug!(proxy = %m.proxy_name, sid = %m.sid,
                                "收到无法配对的 NatHoleClient（会话不存在/已超时/不是该 provider）");
                        }
                    }
                    FrpMessage::NatHoleReport(m) => {
                        crate::nathole_official::handle_report(&m);
                    }
                    // 面板下发的管理命令的回执：按 id 交还给等待者
                    FrpMessage::ServerCmdResp(r) => {
                        let outcome = if r.error.is_empty() {
                            Ok(())
                        } else {
                            Err(r.error.clone())
                        };
                        match pending_cmds.remove(&r.id) {
                            Some(tx) => {
                                let _ = tx.send(outcome);
                            }
                            None => debug!(
                                id = %r.id, op = %r.op,
                                "收到没有等待者的命令回执，忽略"
                            ),
                        }
                    }
                    other => {
                        debug!("忽略消息：{}", other.name());
                    }
                }
            }
            Some(cmd) = req_rx.recv() => {
                match cmd {
                    // 有用户连接排队，向客户端索要一条工作连接
                    CtrlCmd::RequestWork => {
                        handle_req_work_conn(&mut conn, &client).await?;
                    }
                    // 其他路径（xtcp 打洞协调）要发给客户端的消息，原样下发
                    CtrlCmd::Send(msg) => conn.send_msg(&msg).await?,
                    // 面板下发的管理命令：发出去并登记等待者
                    CtrlCmd::ServerCmd { cmd, ack } => {
                        if !client.caps().server_cmd {
                            // 这个客户端没协商过这个能力（官方 frpc、或者
                            // private_caps=false），发过去它只会忽略。
                            // 与其让面板干等到超时，不如立刻明确报错。
                            let _ = ack.send(Err(
                                "该客户端未启用管理命令（官方 frpc，或 private_caps=false）"
                                    .to_string(),
                            ));
                            continue;
                        }
                        let id = cmd.id.clone();
                        conn.send_msg(&FrpMessage::ServerCmd((*cmd).clone())).await?;
                        pending_cmds.insert(id, ack);
                    }
                }
            }
            _ = hb_ticker.tick() => {
                // 续传兜底对账：0.7.0 及更早的客户端只重发 `NewProxy`，
                // 不认识 `ResumeCommit`。给 10 秒宽限期，还没被重发 / 复用的
                // 代理（配置里已删除）在这里回收 —— 否则旧端口会一直被占着。
                if client.is_resumed_session()
                    && client.resume_grace_expired(Duration::from_secs(10))
                {
                    let stale = client.stale_proxies();
                    for name in &stale {
                        if close_proxy_by_name(&registry, &client, name) {
                            debug!(proxy = %name, "续传兜底：回收未被重新注册的代理");
                        }
                    }
                    client.finish_resume();
                }
                // 被面板踢出：`stop()` 之后必须主动断开，
                // 否则这条控制连接会一直活到心跳超时，
                // 期间还能继续建立工作连接 —— "踢了但没完全踢"。
                if client.is_stopped() {
                    warn!(client_id = %nfrp_common::util::LogSafe(&client_id), "客户端已被面板踢出，断开控制连接");
                    break;
                }
                if last_seen.elapsed() > Duration::from_secs(cfg.heartbeat_timeout) {
                    warn!(client_id = %nfrp_common::util::LogSafe(&client_id), "心跳超时 {}s，断开控制连接", cfg.heartbeat_timeout);
                    break;
                }
            }
        }
    }

    // ---- 控制连接结束：暂停会话，等续传 ----
    //
    // 与 0.7.0 的区别：这里**不再**只写一份元数据就顺手 `registry.remove()`。
    // 监听器、端口、vhost 路由、visitor 记录全部原地保留 `resume_ttl` 秒；
    // 续传命中时新控制连接直接接管这份状态，公网端口在切换窗口里不需要
    // 重新 bind，也不会被别人抢走。
    if let Some(st) = &nlink_state {
        if allow_resume
            && st.caps.contains(nfrp_common::nlink::CAP_RESUME)
            && st.resume
            && !client.is_stopped()
        {
            let rt = registry.nlink();
            let ttl = rt.resume_ttl();
            if let Some(c) = registry.detach(&run_id) {
                c.set_suspended(true);
                let entry = crate::registry::SuspendedSession {
                    client: c,
                    slot: client_slot.take(),
                    run_id: run_id.clone(),
                    user: client.user.clone(),
                    client_id: client.client_id.clone(),
                    expires_at: std::time::Instant::now() + ttl,
                };
                if registry.suspend(st.session, entry) {
                    rt.resume.put(
                        st.session,
                        nfrp_common::nlink::ResumeEntry {
                            run_id: run_id.clone(),
                            user: client.user.clone(),
                            trace: st.trace,
                            proxies: client.proxy_names(),
                            expires_at: std::time::Instant::now(),
                        },
                        ttl,
                    );
                    // 会话没结束：别让 `ClientGuard` 把刚保住的资源清掉。
                    _guard.disarm();
                    // 旧 run_id 的 OIDC 绑定随旧会话一起作废；新会话会重新绑定。
                    registry.security().forget_session(&run_id);
                    info!(
                        session = %st.session,
                        ttl = ttl.as_secs(),
                        "控制连接断开：会话已暂停，等待续传"
                    );
                    return Ok(());
                }
                warn!(
                    session = %st.session,
                    "暂停会话登记冲突：本次连接按普通断开回收"
                );
            }
        }
    }

    Ok(())
}

/// `NewProxy` 阶段：命名空间归一化、插件闸、RBAC 与注册。
///
/// 从 `handle_control` 内联分支原样搬出：原来的 `continue`（跳过本分支剩余
/// 逻辑）对应这里的提前 `return Ok(())`；判断顺序、日志文案、错误文案、
/// 指标与审计更新时点均未改变。
#[allow(clippy::too_many_arguments)]
async fn handle_new_proxy(
    conn: &mut FrpConn,
    mut m: nfrp_common::frp::msg::NewProxy,
    client: &Arc<ClientState>,
    role: &nfrp_common::security::Role,
    cfg: &Arc<ServerConfig>,
    registry: &Arc<Registry>,
    run_id: &str,
    login: &Login,
    peer: SocketAddr,
    sec: &Arc<crate::guard::SecurityContext>,
) -> Result<()> {
    // 命名空间隔离：代理对外（注册表 / 工作连接 / 访问控制）用
    // `{user}.{name}` 这个全名。
    //
    // 官方 frpc 在**客户端**就加好了前缀再发上来
    //   （`client/proxy/proxy_wrapper.go` 的 `wireName` =
    //   `naming.AddUserPrefix(clientCfg.User, name)`），
    //   实测抓包：`user = '2569'` 时线上就是
    //   `"proxy_name":"2569.c0462d9ce7e44bce97e626c4ae880905"`。
    //
    //   这里额外做一次「先 strip 再 add」是为了**幂等**：
    //   收原始名（老版 NFrp 客户端、手写报文）也会被补成
    //   全名，收带前缀的名字也不会叠成 `2569.2569.xxx`。
    //
    //   之所以要兜这一层：早期判断反了 —— 以为客户端该发原始名，
    //   结果第三方 frps（LoliaFRP）按全名查隧道，查不到就回
    //   「FRPC 配置文件错误,请检查后重试」。
    // 抽成 `canonical_wire_name()`，与面板管理
    //   路径（`admin.rs`）共用 —— 原先面板那条漏了 strip，
    //   于是全名会被叠成 `alice.alice.web`（端口/域名泄漏）。
    m.proxy_name = util::canonical_wire_name(&client.user, &m.proxy_name);
    // ---- 官方 `[[httpPlugins]]`：NewProxy ----
    //
    // 插件可以拒绝注册（返回 reject），也可以改写端口 /
    // 名字 / 类型。放在权限检查之前，让插件成为第一道闸；
    // 之后仍然要过 RBAC，插件不能借改写绕过角色限制。
    if !registry.plugins().is_empty() {
        let plugins = registry.plugins();
        let user = nfrp_common::plugin::user_info(login, run_id);
        let content = nfrp_common::plugin::content_with_user(&m, user)?;
        match plugins
            .handle_mutable(nfrp_common::plugin::OP_NEW_PROXY, content)
            .await
        {
            Ok(v) => {
                m = serde_json::from_value(v).context("插件返回的 NewProxy 内容无法解析")?;
                m.proxy_name = util::canonical_wire_name(&client.user, &m.proxy_name);
            }
            Err(e) => {
                registry.metrics().proxy_failures.inc();
                let reason = e.to_string();
                warn!(proxy = %m.proxy_name, "HTTP 插件拒绝代理注册：{reason}");
                conn.send_msg(&FrpMessage::NewProxyResp(NewProxyResp {
                    proxy_name: m.proxy_name.clone(),
                    error: cfg
                        .error_to_client(&format!("new proxy [{}] error", m.proxy_name), &reason),
                    ..Default::default()
                }))
                .await?;
                return Ok(());
            }
        }
    }
    let name = m.proxy_name.clone();
    let port = m.remote_port;
    // (3) 授权：这个角色允许注册这种类型的代理 / 占这个端口吗？
    //
    // 放在 register_proxy **之前**：注册会真的去占端口、
    // 建 vhost 路由，先拦下来才不会有"拒绝了一半"的状态。
    if let Err(e) = sec.check_proxy(role, &name, &m.proxy_type, port, client.proxy_count()) {
        registry.metrics().proxy_failures.inc();
        registry.audit().record(
            crate::audit::AuditEvent::new(crate::audit::kind::PROXY_REJECTED, false)
                .client(run_id.to_string())
                .user(client.user.clone())
                .ip(peer.ip().to_string())
                .target(name.clone())
                .detail(e.to_string()),
        );
        warn!(proxy = %name, "代理注册被权限模型拒绝：{e:#}");
        conn.send_msg(&FrpMessage::NewProxyResp(NewProxyResp {
            proxy_name: name.clone(),
            // 详细错误里往往带着"别人的代理名 / 端口占用"这类
            // 信息，detailedErrorsToClient = false 时必须脱敏。
            // 短句与官方 `handleNewProxy` 的 summary 逐字一致。
            error: cfg.error_to_client(&format!("new proxy [{name}] error"), &e.to_string()),
            ..Default::default()
        }))
        .await?;
        return Ok(());
    }
    let resp = match register_proxy(cfg, registry, client, &m).await {
        Ok(outcome) => {
            if !outcome.adopted {
                registry.metrics().proxies_total.inc();
                registry.metrics().proxies_active.inc();
            }
            let remote_addr = outcome.remote_addr;
            info!(proxy = %name, port, remote = %remote_addr, "代理注册成功");
            registry.audit().record(
                crate::audit::AuditEvent::new(crate::audit::kind::PROXY_ADD, true)
                    .client(run_id.to_string())
                    .user(client.user.clone())
                    .ip(peer.ip().to_string())
                    .target(name.clone())
                    .detail(format!(
                        "type={} remote_port={port} remote={remote_addr}",
                        m.proxy_type
                    )),
            );
            NewProxyResp {
                proxy_name: name.clone(),
                remote_addr,
                ..Default::default()
            }
        }
        Err(e) => {
            registry.metrics().proxy_failures.inc();
            warn!(proxy = %name, port, "代理注册失败：{e:#}");
            NewProxyResp {
                proxy_name: name.clone(),
                // 同上：`detailedErrorsToClient = false` 时只回短句
                error: cfg.error_to_client(&format!("new proxy [{name}] error"), &e.to_string()),
                ..Default::default()
            }
        }
    };
    conn.send_msg(&FrpMessage::NewProxyResp(resp)).await?;
    Ok(())
}

/// `Ping` 阶段：插件闸 + 心跳凭证复核。
///
/// 返回 `Ok(true)` 表示原分支里的 `break`（主动断开且禁止续传），
/// `Ok(false)` 表示继续循环。`allow_resume` 由调用方持有并原样传引用，
/// 保证置 false 的时点与原先一致。
#[allow(clippy::too_many_arguments)]
async fn handle_ping(
    conn: &mut FrpConn,
    mut p: nfrp_common::frp::msg::Ping,
    client: &Arc<ClientState>,
    cfg: &Arc<ServerConfig>,
    registry: &Arc<Registry>,
    run_id: &str,
    login: &Login,
    peer: SocketAddr,
    sec: &Arc<crate::guard::SecurityContext>,
    allow_resume: &mut bool,
) -> Result<bool> {
    // 官方 `[[httpPlugins]]`：Ping。插件可以拒绝心跳
    // （管理端强制下线）或改写心跳内容。
    if !registry.plugins().is_empty() {
        let plugins = registry.plugins();
        let user = nfrp_common::plugin::user_info(login, run_id);
        let content = nfrp_common::plugin::content_with_user(&p, user)?;
        match plugins
            .handle_mutable(nfrp_common::plugin::OP_PING, content)
            .await
        {
            Ok(v) => {
                p = serde_json::from_value(v).context("插件返回的 Ping 内容无法解析")?;
            }
            Err(e) => {
                warn!("HTTP 插件拒绝心跳，断开控制连接：{e:#}");
                *allow_resume = false;
                let _ = conn
                    .send_msg(&FrpMessage::Pong(Pong {
                        error: cfg.error_to_client("invalid ping", &e.to_string()),
                    }))
                    .await;
                return Ok(true);
            }
        }
    }
    // OIDC + additionalScopes 含 HeartBeats 时，每个心跳上的
    // token 都要重新验签、且 subject 与登录时一致。
    // 少了这一步，"登录时验过一次"就等于之后永久信任。
    if sec.auth_cfg.check_heartbeats()
        && sec.auth_method() == nfrp_common::security::AuthMethod::Oidc
    {
        if let Err(e) = sec.verify_followup(&p.privilege_key, "心跳", run_id) {
            registry.audit().record(
                crate::audit::AuditEvent::new(crate::audit::kind::LOGIN_DENIED, false)
                    .client(run_id.to_string())
                    .user(client.user.clone())
                    .ip(peer.ip().to_string())
                    .detail(format!("心跳凭证复核失败：{e:#}")),
            );
            warn!("心跳凭证复核失败，断开控制连接：{e:#}");
            *allow_resume = false;
            // 先回一条带错误的 Pong 再断，客户端才拿得到原因；
            // 短句与官方 `handlePing` 的 summary 逐字一致
            // （官方那边同样受 detailedErrorsToClient 控制）。
            let _ = conn
                .send_msg(&FrpMessage::Pong(Pong {
                    error: cfg.error_to_client("invalid ping", &e.to_string()),
                }))
                .await;
            return Ok(true);
        }
    }
    conn.send_msg(&FrpMessage::Pong(Pong::default())).await?;
    Ok(false)
}

/// `CloseProxy` 阶段：审计、visitor / vhost / 端口回收与插件通知。
///
/// 与内联分支逐行等价（含 `proxies_active` 只在确实摘掉后才递减）。
async fn handle_close(
    client: &Arc<ClientState>,
    m: nfrp_common::frp::msg::CloseProxy,
    registry: &Arc<Registry>,
    run_id: &str,
    login: &Login,
    peer: SocketAddr,
) -> Result<()> {
    info!(proxy = %m.proxy_name, "客户端关闭代理");
    // `proxies_active.dec()`
    //   **不能无条件执行**。
    //
    // 原先它在这里就先减了，而下面 `stop_proxy` 可能返回 `None`
    // （名字拼错、重复发、发别人的名字）—— 那种情况下什么都没
    // 清理，gauge 却已经减了一次。
    //
    // 攻击：任意客户端反复发 `CloseProxy`，每次让 gauge 减 1
    // ⇒ 变成负数并持续走低，面板显示"生效代理 -37"，
    // 管理员据此发现异常的能力被破坏。
    //
    // 正确写法是"确实摘掉了才减"，与 `admin.rs` 那条对齐。
    registry.audit().record(
        crate::audit::AuditEvent::new(crate::audit::kind::PROXY_REMOVE, true)
            .client(run_id.to_string())
            .user(client.user.clone())
            .ip(peer.ip().to_string())
            .target(m.proxy_name.clone())
            .detail("客户端主动关闭"),
    );
    // stcp / xtcp 的代理名
    //
    // 同样必须带上发起方的 client ——
    //   只按名字摘会摘掉别的租户的同名 visitor 记录（跨租户 DoS）。
    // 这是 H1 修复漏掉的第二处（同一根因）。
    registry.visitors.remove(client, &m.proxy_name);
    // 客户端主动关代理时，它占的 http/https 域名也得摘掉，
    // 否则域名会一直被占着、重连注册同一个域名会被判冲突
    //
    // 必须带上**发起方**的 client ——
    //   只按名字摘会把别的租户的同名路由一起摘掉（跨租户 DoS）。
    if let Some(t) = registry.vhosts() {
        t.remove_proxy(client, &m.proxy_name);
    }
    // tcp / udp 的公网端口同理：客户端这边只是记账，
    // 端口是注册表管的，必须显式还回去
    //
    // `dec()` 挪到这里 —— **确实摘掉了才减**。
    if let Some(port) = client.stop_proxy(&m.proxy_name) {
        registry.metrics().proxies_active.dec();
        registry.release_port(port, client, &m.proxy_name);
    } else {
        // 名字对不上：什么都没清理。留一条 debug 便于排查
        // （不改指标 —— 这正是 M8 的修法）。
        debug!(proxy = %m.proxy_name, "CloseProxy 的名字不在本客户端的表里，未做任何清理");
    }
    // 官方 `[[httpPlugins]]`：CloseProxy 是**通知型** op，
    // 插件失败/拒绝只记日志，不影响本地清理（官方同语义）。
    if !registry.plugins().is_empty() {
        let plugins = registry.plugins();
        let user = nfrp_common::plugin::user_info(login, run_id);
        let content = nfrp_common::plugin::content_with_user(&m, user)?;
        plugins
            .notify(nfrp_common::plugin::OP_CLOSE_PROXY, content)
            .await;
    }
    Ok(())
}

/// `CtrlCmd::RequestWork` 阶段：按协商结果发 `BatchReq` 或单字节 `ReqWorkConn`。
async fn handle_req_work_conn(conn: &mut FrpConn, client: &Arc<ClientState>) -> Result<()> {
    // NLink 批量：并发用户 >1 且协商了能力时，一条帧换 N 条连接。
    // 条件不满足就退回原来的一字节 `ReqWorkConn`。
    if let Some(n) = client.take_batch_request() {
        let frame = nfrp_common::nlink::Frame::new(nfrp_common::nlink::FrameKind::BatchReq).with(
            nfrp_common::nlink::frame::TAG_COUNT,
            n.to_be_bytes().to_vec(),
        );
        debug!(count = n, "用一条 BatchReq 向客户端要工作连接");
        conn.send_nlink(&frame).await?;
    } else {
        conn.send_msg(&FrpMessage::ReqWorkConn).await?;
    }
    Ok(())
}

/// `NewProxy` 的确定性指纹（续传复用判据）。
///
/// **不能用 `serde_json::to_string(m)`**：`metas` / `headers` 等是
/// `HashMap`，每次构造的随机种子不同，序列化顺序会变 —— 同一份配置两次
/// 算出的字符串不同，续传就永远复用不了，随后重新 bind 直接 `EADDRINUSE`。
/// 这里把所有集合排序后再拼接，保证跨进程、跨重启稳定。
pub(super) fn proxy_signature(m: &nfrp_common::frp::msg::NewProxy) -> String {
    fn sorted_map(m: &std::collections::HashMap<String, String>) -> String {
        let mut kv: Vec<(&String, &String)> = m.iter().collect();
        kv.sort();
        kv.into_iter()
            .map(|(k, v)| format!("{k}={v}"))
            .collect::<Vec<_>>()
            .join("&")
    }
    fn sorted_vec(v: &[String]) -> String {
        let mut v = v.to_vec();
        v.sort();
        v.join(",")
    }
    format!(
        "name={}\0type={}\0enc={}\0comp={}\0bw={}\0bwmode={}\0group={}\0gkey={}\0metas={}\0ann={}\0port={}\0domains={}\0sub={}\0locations={}\0http_user={}\0http_pwd={}\0host={}\0headers={}\0resp_headers={}\0route_user={}\0mux={}\0sk={}\0allow={}",
        m.proxy_name,
        m.proxy_type,
        m.use_encryption,
        m.use_compression,
        m.bandwidth_limit,
        m.bandwidth_limit_mode,
        m.group,
        m.group_key,
        sorted_map(&m.metas),
        sorted_map(&m.annotations),
        m.remote_port,
        sorted_vec(&m.custom_domains),
        m.subdomain,
        sorted_vec(&m.locations),
        m.http_user,
        m.http_pwd,
        m.host_header_rewrite,
        sorted_map(&m.headers),
        sorted_map(&m.response_headers),
        m.route_by_http_user,
        m.multiplexer,
        m.sk,
        sorted_vec(&m.allow_users),
    )
}
