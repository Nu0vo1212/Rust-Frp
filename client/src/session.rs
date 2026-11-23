//! 控制会话生命周期：登录握手、代理注册、心跳与消息分发。
//!
//! 职责：`run_session` 驱动一条控制连接从 `ServerLink::open` 到断线；
//! `handshake_once` 负责（可回退的）登录握手；`handle_nlink_frame` 处理 NLink
//! 扩展帧；`resolve_uploaded_proxy` / `current_credential` 供工作连接与 visitor 复用。
//! 并发/所有权契约：会话任务独占 `FrpConn`；`session_tx` 向 visitor 广播当前会话，
//! `web_tx` 由面板写入、会话循环消费；`logged_in_once` 与 main 的重连循环共享
//! （原子 Bool），`ServerLink` 由本模块创建并以 `Arc` 外发。
//! 不变量：服务端下发的代理名一律是线上全名 `{user}.{name}`，查本地表前必须过
//! `resolve_uploaded_proxy`；登录成功后 `logged_in_once` 置真，首登失败计数不再累加。

use std::{sync::Arc, time::Duration};

use anyhow::{anyhow, bail, Context, Result};
use nfrp_common::{
    config::{ClientConfig, ProxyConfig},
    frp::{
        conn::{self, FrpConn},
        msg::{self, FrpMessage, NewProxy, Ping},
    },
    util,
};
use tokio::time::interval;
use tracing::{debug, error, info, warn};

use crate::{
    commands::apply_server_cmd,
    health,
    link::{spawn_quic_migrator, ServerLink},
    login_stage_timeout, nlink, p2p, registry, store, web,
    work_conn::spawn_work_conn,
};

/// 当前有效的控制会话。visitor 需要用它开新连接、拿 run_id。
pub(crate) struct ClientSession {
    pub(crate) link: Arc<ServerLink>,
    pub(crate) run_id: Arc<String>,
    /// xtcp 打洞上下文；未配置 `p2p_port` 时为 None（xtcp 只走中继）。
    pub(crate) p2p: Option<Arc<p2p::P2PRoute>>,
}

/// 建立一次完整的控制连接会话，直到连接断开或出错。
/// 把一条代理配置搬成线协议里的 `NewProxy` 消息。
///
/// 单独抽成函数是为了**能测**：这段映射以前内联在注册流程里，
/// 于是新增配置字段（`group` / `group_key`）时忘了搬进消息体，
/// 服务端单测测的是注册表、客户端也没有对应用例，最后是端到端冒烟才把它翻出来。
///
/// # `proxy_name` 必须带 `{user}.` 前缀
///
/// 官方 frpc 上线用的名字**不是**配置里的 `name`，而是
/// `naming.AddUserPrefix(clientCfg.User, name)` 的结果（`client/proxy/proxy_wrapper.go`
/// 的 `wireName` 字段）。`user = '2569'` + `name = 'c046…'`，线上就是 `2569.c046…`。
///
/// 第三方平台（LoliaFRP 等）正是拿这个**全名**去查隧道的，发原始名过去它查不到，
/// 只会回一句「FRPC 配置文件错误,请检查后重试,请反馈给管理员以解决这个问题」。
///
/// ## 这个坑已经踩过一次，别再踩
///
/// 官方 frpc 的日志是
/// `[dump-run-id] proxy added: [c0462d9ce7e44bce97e626c4ae880905]` —— **不带前缀**，
/// 很容易据此以为线上也不带，然后把这里的前缀删掉（真发生过）。
///
/// 其实那行日志打的是 `pm.proxies` 的 key，也就是配置里的原始 `name`
/// （`client/proxy/proxy_manager.go`：`name := cfg.GetBaseConfig().Name`），
/// 跟真正发出去的 `wireName` 根本不是一回事。
///
/// ## 怎么才不会再搞错
///
/// 别读日志猜，**抓包**：用 [`server/examples/dump_frpc.rs`] 当假 frps
/// （`cargo run -p nfrp-server --example dump_frpc -- 17777`），把官方 frpc 的
/// `serverAddr` 指过去，它会把你收到的每个消息原样打成 JSON，`proxy_name`
/// 带不带前缀一眼就能看清。
///
/// 抓之前记得在待测配置里关掉两个传输层开关，否则连魔术字都对不上：
///
/// ```toml
/// [transport]
/// tcpMux = false          # 默认 true，会把控制连接塞进 yamux
/// wireProtocol = "v2"     # 默认 v1，发的是 `6f`（'o' = TypeLogin），没有魔术字
///
/// [transport.tls]
/// enable = false          # 默认 true，首字节是 TLS ClientHello
/// ```
///
/// 服务端那边保持**幂等**（收到原始名或带前缀的名字都会被补成带前缀的），
/// 所以老客户端直接发原始名也不会坏 —— 见 `server/src/serve.rs`。
/// 把服务端下发的**线上全名**翻译回本地配置里的原始代理名，并取出配置。
///
/// 命名契约（与官方 frp 一致，别改）：
/// - 客户端 `NewProxy.proxy_name` 发的是**线上全名** `{user}.{name}`（见 [`NewProxy::from_config`]）；
/// - 服务端回显（`NewProxyResp`）与主动下发（`StartWorkConn`、`NatHoleClient`）
///   用的**也是同一个全名**；
/// - 而本地映射表 [`run_session`] 里是按配置里的**原始 `name`** 建的。
///
/// 所以**凡是拿服务端下发的 `proxy_name` 查本地表的地方，都必须过这个函数**。
/// 这个坑踩过两次：先修了 `NewProxyResp` 和 `StartWorkConn`，漏了 `NatHoleClient`
/// —— 表现为 provider 打印「收到未知代理的打洞通知，忽略」，xtcp **静默退化成中继**：
/// 数据还是通的，只有「有没有走 P2P 直连」这条断言会红（本机冒烟第 4 项）。
pub(crate) fn resolve_uploaded_proxy(
    user: &str,
    wire_name: &str,
    proxies: &registry::ProxyTable,
) -> Option<(String, Arc<ProxyConfig>)> {
    let raw = util::strip_user_prefix(user, wire_name).to_string();
    proxies.get(&raw).map(|p| (raw, p))
}

/// 取本次连接要用的登录凭证。
///
/// - token 方式：直接用配置里的共享密钥（真正上线时会派生 `privilege_key`）；
/// - OIDC 方式：**现取**一次 access token。绝不能缓存到调用方 ——
///   token 会过期，复用上一次的会让"重连"变成"拿过期 token 再失败一次"。
///   `TokenSource` 自己带缓存，没到期时不会真去打 IdP。
///
/// 抽成函数是因为 VirtualNet 也要用同一套凭证（见 `vnet.rs`）——
/// 两边各写一遍的话，"OIDC 的 privilege_key 是原样 token"这条语义迟早会在
/// 其中一边漏掉（这个坑在 `security.rs` 的注释里专门标过）。
pub(crate) async fn current_credential(
    cfg: &ClientConfig,
    token_source: &Option<Arc<nfrp_common::auth::oidc::TokenSource>>,
) -> Result<nfrp_common::security::Credential> {
    Ok(match token_source {
        Some(src) => nfrp_common::security::Credential::Oidc(
            src.token()
                .await
                .context("向 IdP 换取 OIDC access token 失败")?,
        ),
        None => nfrp_common::security::Credential::Token(cfg.effective_token().to_string()),
    })
}

/// 一次控制会话需要的全部外部依赖。
///
/// 打成一个结构体而不是摊成八个参数：会话每重连一次就要跑一遍，
/// 而依赖永远只有这一组 —— 摊平只会让调用点越来越难读
/// （也过不了 clippy 的参数个数上限）。
pub(crate) struct SessionDeps {
    pub(crate) cfg: Arc<ClientConfig>,
    pub(crate) session_tx: tokio::sync::watch::Sender<Option<Arc<ClientSession>>>,
    pub(crate) health: Arc<health::Monitor>,
    pub(crate) logged_in_once: Arc<std::sync::atomic::AtomicBool>,
    pub(crate) token_source: Option<Arc<nfrp_common::auth::oidc::TokenSource>>,
    pub(crate) store: Arc<store::Store>,
    pub(crate) proxies: registry::ProxyTable,
    pub(crate) hub: Option<Arc<web::Hub>>,
}

/// 处理一条来自服务端的 NLink 扩展帧。
///
/// 只处理**服务端主动下发**的那几类；不认识的整帧忽略（前向兼容）。
async fn handle_nlink_frame(
    frame: &nfrp_common::nlink::Frame,
    nlink: &nlink::ClientNLink,
    link: &Arc<ServerLink>,
    run_id: &Arc<String>,
    proxies: &registry::ProxyTable,
    health: &Arc<health::Monitor>,
) {
    use nfrp_common::nlink::frame::{
        FrameKind, TAG_CODE, TAG_COUNT, TAG_DETAIL, TAG_IDENTITY, TAG_OK, TAG_RESUME_TOKEN,
    };

    match frame.kind {
        FrameKind::Identity => {
            if let Some(tok) = frame.tlvs.get_str(TAG_IDENTITY) {
                debug!("收到 NLink 身份令牌，之后的工作连接会出示它");
                nlink.set_identity(tok);
            }
        }
        FrameKind::ResumeResp => {
            let ok = frame
                .tlvs
                .get(TAG_OK)
                .and_then(|v| v.first().copied())
                .map(|b| b != 0)
                .unwrap_or(false);
            // 服务端在这条帧里同时下发了**下一轮**用的一次性令牌，无论本次
            // 续传成功与否都有。存下来，下次断线重连时带回去。
            if let Some(tok) = frame.tlvs.get_str(TAG_RESUME_TOKEN) {
                if !tok.is_empty() {
                    nlink.set_resume_token(tok);
                    debug!("已保存服务端下发的一次性续传令牌");
                }
            }
            if ok {
                info!("NLink 断线续传成功：沿用上次的会话状态");
            } else {
                info!("NLink 续传票已过期或不存在，本次按新会话处理");
            }
        }
        FrameKind::BatchReq => {
            let count = frame.tlvs.get_u32(TAG_COUNT).unwrap_or(1).clamp(1, 256) as usize;
            debug!(count, "收到批量工作连接请求");
            for _ in 0..count {
                spawn_work_conn(
                    link.clone(),
                    run_id.clone(),
                    proxies.clone(),
                    health.clone(),
                    nlink::current(),
                );
            }
        }
        FrameKind::CompatResp => {
            let detail = frame.tlvs.get_str(TAG_DETAIL).unwrap_or_default();
            info!("服务端兼容性矩阵：{}", detail.trim_end());
        }
        FrameKind::Failure => {
            warn!(
                code = frame.tlvs.get_u32(TAG_CODE).unwrap_or(0),
                detail = %frame.tlvs.get_str(TAG_DETAIL).unwrap_or_default(),
                "服务端回报 NLink 失败"
            );
        }
        other => debug!(kind = ?other, "忽略 NLink 扩展帧"),
    }
}

/// 一次控制连接握手的完整尝试。
///
/// `with_preamble` 为 `false` 时走**标准模式**（连官方 frps 就是这条路径）。
/// 拆成独立函数是为了让"带 preamble 失败 → 回退重试"这段逻辑清晰可见，
/// 而不是在 `run_session` 里堆两层嵌套。
async fn handshake_once(
    cfg: &ClientConfig,
    link: &ServerLink,
    token_source: &Option<Arc<nfrp_common::auth::oidc::TokenSource>>,
    nlink: &nlink::ClientNLink,
    with_preamble: bool,
) -> Result<(FrpConn, String, bool, msg::NfrpCaps)> {
    let stream = link.connect().await?;
    // 私有能力只是**声明支持**，真正开不开看服务端回显 ——
    // 连官方 frps / 第三方 frps 时对方不会回显，行为与不开完全一致。
    let declared = msg::NfrpCaps {
        udp_binary: cfg.private_caps,
        server_cmd: cfg.private_caps,
        // **无条件**声明"我的工作连接会带凭证"。
        //
        // 这不是一个可选优化，而是客户端**真实行为**的声明：客户端
        // 一直都在工作连接上发 `auth_key(token, ts)`（`conn.rs` 的
        // `client_work_conn`），只是服务端以前不看它。
        // 服务端据这个位决定"对这条会话要求凭证"，从而能拒绝那些
        // 拿 run_id 冒充的伪造工作连接 —— 又不必对官方 frpc 提同样要求
        // （官方默认不带凭证，实测一刀切会把它挡死）。
        work_conn_cred: true,
    };
    // 每次（重）连都重新取一次凭证：OIDC 的 access token 会过期，
    // 复用上一次的会让"重连"变成"用过期 token 再失败一次"。
    // TokenSource 内部有缓存，没到期时不会真的去打 IdP。
    let cred = current_credential(cfg, token_source).await?;
    let pre = if with_preamble {
        nlink.preamble()
    } else {
        None
    };
    conn::client_handshake_with(
        stream,
        link.wire,
        &cred,
        &cfg.client_id,
        &cfg.user,
        &cfg.metas,
        cfg.pool_count,
        declared,
        pre,
    )
    .await
}

pub(crate) async fn run_session(deps: SessionDeps) -> Result<()> {
    // 解构出来而不是满篇写 `deps.cfg` —— 下面这段是本文件最长的一段代码，
    // 到处加前缀只会让它更难读。
    let SessionDeps {
        cfg,
        session_tx,
        health,
        logged_in_once,
        token_source,
        store,
        proxies,
        hub,
    } = deps;
    let server = format!("{}:{}", cfg.server_addr, cfg.server_port);
    // 登录阶段（拨号 + 握手 + 等 LoginResp）的墙钟上限。
    //
    // 官方 frpc 在 `exchangeLogin` 里给读取设了 10 秒死线；这里把整个登录阶段
    // 包起来。否则 KCP/UDP（建"连接"不发包）或"TCP 已建立但服务端不回"会
    // **永久挂住** —— 既不退出也不重试，比直接退出更糟，开机自启时无从恢复。
    let login_timeout = login_stage_timeout(&cfg);
    let link = Arc::new(
        tokio::time::timeout(
            login_timeout,
            ServerLink::open(cfg.clone(), token_source.clone()),
        )
        .await
        .map_err(|_| {
            anyhow!(
                "连接服务端超时（{} 秒）：网络 / 代理 / KCP(UDP) 可能尚未就绪",
                login_timeout.as_secs()
            )
        })??,
    );
    // 走 NLink QUIC 且开了迁移时，起一个"出口 IP 变了就 rebind"的看门狗。
    if cfg.nlink.enable && cfg.nlink.quic && cfg.nlink.quic_migrate {
        spawn_quic_migrator(Arc::downgrade(&link), cfg.clone());
    }
    info!(%server, "已连接到服务端，开始握手");

    // NLink：一个进程一份状态（connection id 跨重连不变，续传要它）。
    let nlink = nlink::install(&cfg);
    let handshake = async {
        match handshake_once(&cfg, &link, &token_source, &nlink, true).await {
            Ok(v) => Ok(v),
            // 自动回退：对端不认 preamble 时（官方 frps 会把 `NFRPLNK1` 当成
            //   v1 消息头直接报错），立刻用标准模式重连一次。用户只会在日志里
            //   看到一行 warn，隧道照常工作。
            Err(e) if nlink.want_preamble() => {
                warn!("NLink 握手未成功（对端可能不支持扩展层），自动回退标准模式：{e:#}");
                nlink.mark_fallback();
                handshake_once(&cfg, &link, &token_source, &nlink, false).await
            }
            Err(e) => Err(e),
        }
    };
    let (mut conn, run_id, udp_binary, caps) = tokio::time::timeout(login_timeout, handshake)
        .await
        .map_err(|_| {
            anyhow!(
                "等待登录应答超时（{} 秒）：服务端未回 LoginResp",
                login_timeout.as_secs()
            )
        })??;
    link.udp_binary
        .store(udp_binary, std::sync::atomic::Ordering::Relaxed);
    if udp_binary {
        debug!("服务端选择了二进制 UDP 报文编码");
    }
    if caps.server_cmd {
        debug!("服务端已启用私有管理命令（面板可增删本端代理）");
    }
    match conn.nlink() {
        Some(st) => {
            link.set_nlink_caps(st.caps);
            info!(
                caps = %st.caps,
                trace = %st.trace,
                session = %st.session,
                "NLink v1 协商成功"
            )
        }
        None => {
            if nlink.want_preamble() {
                // preamble 发出去了但服务端没回显：按标准模式跑，本次进程不再尝试。
                warn!("服务端未回显 NLink 能力，按标准模式运行");
                nlink.mark_fallback();
            }
        }
    }
    info!(%run_id, wire = %link.wire, "登录成功（控制通道已加密）");

    // 登录成功 ⇒ 清掉上一轮的失败原因与注册结果：面板上的状态必须反映
    // **这一次**会话，而不是上一次重试留下的旧错误。
    if let Some(h) = &hub {
        h.on_session_started();
    }

    // 记下"这个进程登录成功过"。上面那行之前的任何失败都算**首次登录失败**，
    // 由 main 的循环按 `loginFailExit` 决定是退出还是重试。
    logged_in_once.store(true, std::sync::atomic::Ordering::SeqCst);

    let run_id = Arc::new(run_id);

    // 本地管理界面（`[webServer]`）的写请求通道。
    //
    // `_web_guard` 负责在会话结束时摘掉通道 —— 包括下面各种提前 `?` 返回。
    // 不摘的话，重连窗口期的请求会被投进一个没人读的队列，
    // 用户只能干等 20 秒超时，而不是立刻被告知"客户端没连上"。
    //
    // 没开管理界面时 `hub` 是 None：闭包不执行，`web_tx` 随之被丢弃，
    // `web_rx.recv()` 立刻返回 None，下面那个 select 分支被自动禁用。
    let (web_tx, mut web_rx) = tokio::sync::mpsc::unbounded_channel::<web::Request>();
    let _web_guard = hub
        .as_ref()
        .map(|h| web::SessionGuard::new(h.clone(), web_tx));

    // xtcp 真 P2P：只有配置了 p2p_port 才建立打洞中枢
    let (p2p_route, mut punch_rx) = match p2p::setup(&cfg).await {
        Some((route, rx)) => (Some(route), Some(rx)),
        None => (None, None),
    };
    if p2p_route.is_none() && cfg.proxies.iter().any(|p| p.proxy_type == "xtcp") {
        warn!("有 xtcp 代理但未配置 p2p_port，xtcp 将退化为中继（与 stcp 相同）");
    }

    // 把当前会话公布出去，visitor 从这里取连接与 run_id
    let _ = session_tx.send(Some(Arc::new(ClientSession {
        link: link.clone(),
        run_id: run_id.clone(),
        p2p: p2p_route.clone(),
    })));

    // 注册代理
    //
    // 注意：官方 frps 会在 NewProxyResp 之间插入 ReqWorkConn（填充工作连接池），
    // 所以不能发送一个就死等一个响应，必须边读边按代理名匹配。
    //
    // 本地映射表按配置里的**原始 `name`** 建。
    //
    // 服务端回包里的 `proxy_name` 是**线上全名** `{user}.{name}`
    // （我们发上去的就是这个，官方 frps 会原样回显），所以先 `strip_user_prefix`
    // 剥一层再查表；万一遇到不回显前缀的实现，strip 对不带前缀的名字也是恒等的。
    // 代理表由 `main` 建好传进来（与本地管理界面共用同一张），这里**不重建** ——
    // 重建会把界面上刚加进去的代理抹掉。
    for p in &cfg.proxies {
        let mut msg = NewProxy::from_config(p, &cfg.user);
        // 官方语义：`[transport].useEncryption` 是**客户端级**开关，作用于所有代理。
        // 代理级字段是 NFRP 的扩展（允许单条代理单独开），两者取或。
        // 服务端就是按这个字段决定要不要解密/解压的，漏传会导致"客户端加密、
        // 服务端明文透传"—— 用户看到的是能连上但数据全乱。
        msg.use_encryption |= cfg.use_encryption;
        msg.use_compression |= cfg.use_compression;
        conn.send_msg(&FrpMessage::NewProxy(msg)).await?;
    }

    let mut pending: std::collections::HashSet<String> =
        cfg.proxies.iter().map(|p| p.name.clone()).collect();
    while !pending.is_empty() {
        let event = tokio::time::timeout(Duration::from_secs(15), conn.recv_event())
            .await
            .context("等待 NewProxyResp 超时")??;
        let msg = match event {
            nfrp_common::frp::conn::ConnEvent::Msg(m) => Some(*m),
            nfrp_common::frp::conn::ConnEvent::Closed => None,
            nfrp_common::frp::conn::ConnEvent::NLink(f) => {
                // 注册窗口期内就可能收到身份令牌 / 续传回执，必须立刻处理：
                // 令牌丢了会导致之后每一条工作连接都被服务端拒绝。
                handle_nlink_frame(&f, &nlink, &link, &run_id, &proxies, &health).await;
                continue;
            }
        };
        match msg {
            Some(FrpMessage::NewProxyResp(r)) => {
                let raw = util::strip_user_prefix(&cfg.user, &r.proxy_name).to_string();
                pending.remove(&raw);
                let local = match resolve_uploaded_proxy(&cfg.user, &r.proxy_name, &proxies) {
                    Some((_, p)) => p.local_addr.clone(),
                    None => "?".to_string(),
                };
                if r.error.is_empty() {
                    info!(proxy = %raw, remote = %r.remote_addr, local, "代理注册成功");
                } else {
                    error!(proxy = %raw, "代理注册失败：{}", r.error);
                }
                if let Some(h) = &hub {
                    if r.error.is_empty() {
                        h.note_proxy_ok(&raw);
                    } else {
                        h.note_proxy_err(&raw, &r.error);
                    }
                }
            }
            Some(FrpMessage::ReqWorkConn) => {
                spawn_work_conn(
                    link.clone(),
                    run_id.clone(),
                    proxies.clone(),
                    health.clone(),
                    nlink.clone(),
                );
            }
            Some(other) => debug!("注册期间收到 {}，忽略", other.name()),
            None => bail!("服务端在代理注册完成前断开"),
        }
    }

    // 续传对账：把**最终**代理清单交给服务端，让它回收"上次会话有、
    // 这次配置里已经删掉"的监听器 / 域名 / 端口。
    //
    // 无条件发送：服务端只有在本次控制连接确实是续传出来的时候才处理它
    // （普通新会话 `is_resumed_session()` 为假，收到也只当未知帧忽略）。
    // 这样即使 0 个代理、注册循环一次都没跑，也不会漏掉对账。
    if nlink.resume
        && nlink
            .features
            .active()
            .contains(nfrp_common::nlink::CAP_RESUME)
    {
        let names: Vec<String> = cfg
            .proxies
            .iter()
            .map(|p| NewProxy::from_config(p, &cfg.user).proxy_name)
            .collect();
        // 名单超过单帧上限时自动分片（0.7.2 起）。
        // 只有一片时线上格式与 0.7.1 完全相同，老服务端照常解析。
        let frames = nfrp_common::nlink::frame::encode_resume_commit(&names);
        if frames.len() > 1 {
            debug!(
                chunks = frames.len(),
                proxies = names.len(),
                "代理名单较大，ResumeCommit 拆成多帧发送"
            );
        }
        for frame in frames {
            conn.send_nlink(&frame).await?;
        }
    }

    // 预建工作连接（与官方 frpc 的 pool_count 行为一致）
    for _ in 0..cfg.pool_count.max(0) {
        spawn_work_conn(
            link.clone(),
            run_id.clone(),
            proxies.clone(),
            health.clone(),
            nlink.clone(),
        );
    }

    let mut ticker = interval(Duration::from_secs(cfg.heartbeat_interval.max(1)));
    ticker.tick().await; // 丢掉立即触发的第一次
    let mut last_pong = std::time::Instant::now();

    loop {
        tokio::select! {
            event = conn.recv_event() => {
                let msg = match event? {
                    nfrp_common::frp::conn::ConnEvent::Msg(m) => *m,
                    nfrp_common::frp::conn::ConnEvent::Closed => {
                        info!("服务端关闭了控制连接");
                        // 控制连接没了：还在等的打洞请求必须立刻失败，
                        // 否则 visitor 会干等到超时才回退中继
                        if let Some(route) = &p2p_route {
                            route.bus.clear();
                        }
                        break;
                    }
                    nfrp_common::frp::conn::ConnEvent::NLink(f) => {
                        handle_nlink_frame(&f, &nlink, &link, &run_id, &proxies, &health).await;
                        continue;
                    }
                };
                match msg {
                    FrpMessage::ReqWorkConn => {
                        debug!("收到 ReqWorkConn，建立工作连接");
                        spawn_work_conn(
                    link.clone(),
                    run_id.clone(),
                    proxies.clone(),
                    health.clone(),
                    nlink.clone(),
                );
                    }
                    FrpMessage::Pong(p) => {
                        if !p.error.is_empty() {
                            warn!("服务端 Pong 返回错误：{}", p.error);
                        }
                        last_pong = std::time::Instant::now();
                    }
                    FrpMessage::NewProxyResp(_) => {}
                    // xtcp：服务端通知本端（provider）去打洞
                    FrpMessage::NatHoleClient(m) => {
                        debug!(proxy = %m.proxy_name, sid = %m.sid, "收到打洞通知");
                        // 服务端下发的是**线上全名**（带 `{user}.` 前缀），
                        // 而本地映射表按配置里的原始 `name` 建 —— 必须走
                        // `resolve_uploaded_proxy` 剥前缀，否则这里会打印
                        // 「收到未知代理的打洞通知，忽略」，xtcp 静默退化成中继。
                        match resolve_uploaded_proxy(&cfg.user, &m.proxy_name, &proxies) {
                            Some((raw, proxy)) => {
                                debug!(proxy = %raw, "本端作为 provider 参与打洞");
                                let cfg = cfg.clone();
                                tokio::spawn(async move {
                                    let proxy = (*proxy).clone();
                                    if let Err(e) = p2p::serve_as_provider(cfg, proxy, m).await {
                                        debug!("xtcp 打洞未成功（访客会回退中继）：{e:#}");
                                    }
                                });
                            }
                            None => warn!(proxy = %m.proxy_name, "收到未知代理的打洞通知，忽略"),
                        }
                    }
                    // 面板下发的管理命令（增删代理）
                    FrpMessage::ServerCmd(cmd) => {
                        if !caps.server_cmd {
                            // 服务端没回显过这个能力却发了命令：要么是 bug，
                            // 要么是对端不规矩。忽略比照做更安全。
                            warn!(op = %cmd.op, "收到未协商的私有管理命令，忽略");
                            continue;
                        }
                        let resp = apply_server_cmd(&proxies, &cfg.user, &store, &cmd, &mut conn).await;
                        if let Err(e) = &resp {
                            warn!(op = %cmd.op, "回执发送失败：{e:#}");
                        }
                    }
                    // xtcp：服务端对 visitor 打洞请求的响应，转交给等待者
                    FrpMessage::NatHoleResp(r) => match &p2p_route {
                        Some(route) => route.bus.deliver(r),
                        None => debug!("未启用 P2P，忽略 NatHoleResp"),
                    },
                    other => debug!("忽略消息：{}", other.name()),
                }
            }
            Some(req) = async {
                match punch_rx.as_mut() {
                    Some(rx) => rx.recv().await,
                    // 没开 P2P 时这个分支永不就绪，否则会空转烧 CPU
                    None => std::future::pending().await,
                }
            } => {
                conn.send_msg(&FrpMessage::NatHoleVisitor(req)).await?;
            }
            // 本地管理界面（`[webServer]`）发来的写请求。
            //
            // 必须在这里处理：控制连接被本循环独占，也只有在这里才能
            // "一边等 `NewProxyResp`、一边顺手处理 `ReqWorkConn`" ——
            // 服务端正等着工作连接，慢一步它就认为本端掉线了。
            Some(req) = web_rx.recv() => {
                web::handle_request(
                    req,
                    &mut conn,
                    &link,
                    &run_id,
                    &proxies,
                    &store,
                    &health,
                    &cfg,
                )
                .await;
            }
            _ = ticker.tick() => {
                conn.send_msg(&FrpMessage::Ping(Ping {
                    timestamp: util::now_unix_secs() as i64,
                    ..Default::default()
                }))
                .await?;
                if last_pong.elapsed() > Duration::from_secs(cfg.heartbeat_timeout) {
                    bail!("{} 秒未收到 Pong，判定连接已死", cfg.heartbeat_timeout);
                }
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use nfrp_common::config::ProxyConfig;

    use crate::tests::full_tcp_config;

    // -----------------------------------------------------------------------
    // resolve_uploaded_proxy：服务端下发名 → 本地配置
    //
    // xtcp 就是栽在这里的：`NatHoleClient.proxy_name` 是线上全名 `alice.p2p-echo`，
    // 本地表键是 `p2p-echo`，漏剥前缀就被当「未知代理」忽略，
    // P2P **静默退化成中继**（数据照样通，只有"走没走直连"这条断言会红）。
    // -----------------------------------------------------------------------

    /// 本地映射表：键是配置里的**原始** `name`（与 `run_session` 里一致）。
    fn local_map(names: &[&str]) -> std::collections::HashMap<String, ProxyConfig> {
        names
            .iter()
            .map(|n| {
                let mut cfg = full_tcp_config();
                cfg.name = (*n).to_string();
                ((*n).to_string(), cfg)
            })
            .collect()
    }

    /// 服务端下发**带前缀的线上全名**时必须能查到。
    #[test]
    fn 带前缀的下发名能查到本地代理() {
        let m = registry::ProxyTable::from_iter(local_map(&["p2p-echo"]).into_values());
        let (raw, p) = resolve_uploaded_proxy("alice", "alice.p2p-echo", &m)
            .expect("带 user 前缀的线上全名应当能查到");
        assert_eq!(raw, "p2p-echo", "查到的应当是配置里的原始名");
        assert_eq!(p.name, "p2p-echo");
    }

    /// 服务端若原样回显（不带前缀），也要能查到 —— strip 对不带前缀的名字是恒等的。
    #[test]
    fn 不带前缀的下发名同样能查到() {
        let m = registry::ProxyTable::from_iter(local_map(&["p2p-echo"]).into_values());
        let (raw, _) = resolve_uploaded_proxy("alice", "p2p-echo", &m).expect("应当能查到");
        assert_eq!(raw, "p2p-echo");
    }

    /// 没配 `user` 时表键就是原名。
    #[test]
    fn 无_user_时能查到() {
        let m = registry::ProxyTable::from_iter(local_map(&["web-a"]).into_values());
        assert!(resolve_uploaded_proxy("", "web-a", &m).is_some());
    }

    /// 别人的前缀不该被剥掉：`bob` 的客户端收到 `alice.web-a` 必须查不到，
    /// 否则它会去服务别人的代理。
    #[test]
    fn 别人的前缀不会被剥掉() {
        let m = registry::ProxyTable::from_iter(local_map(&["web-a"]).into_values());
        assert!(
            resolve_uploaded_proxy("bob", "alice.web-a", &m).is_none(),
            "非本用户的代理名必须查不到"
        );
    }

    /// 完全不认识的代理名 → `None`（调用方据此走「未知代理」分支）。
    #[test]
    fn 未知代理返回_none() {
        let m = registry::ProxyTable::from_iter(local_map(&["web-a"]).into_values());
        assert!(resolve_uploaded_proxy("alice", "alice.nope", &m).is_none());
    }
}
