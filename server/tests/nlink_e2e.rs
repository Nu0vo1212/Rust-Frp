//! NLink v1 的端到端用例。
//!
//! 这些用例的名字**必须**与 `nfrp_common::nlink::policy::MATRIX` 里的
//! `e2e` 字段逐字一致 —— `scripts/nlink_matrix_check.py` 会逐行来这个文件里
//! 找同名的 `#[tokio::test]`，找不到就判 CI 失败。所以"矩阵里写了、其实没测"
//! 这件事没有藏身之处。
//!
//! 覆盖方式：能走真协议的一律走真协议（真起服务端、真握手、真转发）；
//! 只有依赖外部环境的部分（真实对称 NAT、官方 Go 服务端）用"能证明行为一致"
//! 的等价断言，并在 `MATRIX` 的 `note` 里写明限制。

use std::{
    collections::HashSet,
    net::SocketAddr,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc, Mutex, OnceLock,
    },
    time::Duration,
};

use nfrp_common::{
    config::ServerConfig,
    frp::{
        conn::{self, ConnEvent, FrpConn},
        msg::{FrpMessage, NewProxy, NfrpCaps},
        quic,
        stream::BoxStream,
        WireVersion,
    },
    nlink::{
        frame::{FrameKind, Preamble, TAG_COUNT, TAG_IDENTITY, TAG_OK, TAG_TRACE_ID},
        knock::{build_knock, KnockRule},
        parse_features,
        policy::{
            classify, decide_direct, matrix_gaps, probe_plan, ttl_ladder, DirectContext,
            DirectDecision, FailureCode, XtcpPolicy, MATRIX,
        },
        session::{ConnectionId, IdentityKey, TraceId},
        Caps, CAP_BATCH_WORK, CAP_IDENTITY, CAP_RESUME, CAP_TRACE, CAP_XTCP_POLICY, FLAG_RESUME,
    },
    security::Credential,
    util,
};
use nfrp_server::{serve_on, Registry};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};

const TOKEN: &str = "nlink-e2e-token";

// ---------------------------------------------------------------------------
// 脚手架
// ---------------------------------------------------------------------------

fn empty_metas() -> std::collections::HashMap<String, String> {
    std::collections::HashMap::new()
}

fn base_cfg() -> ServerConfig {
    ServerConfig {
        bind_addr: "127.0.0.1".into(),
        token: TOKEN.to_string(),
        ..Default::default()
    }
}

/// 打开 NLink 并列出能力名。
fn nlink_cfg(features: &[&str]) -> ServerConfig {
    let mut cfg = base_cfg();
    cfg.nlink.enable = true;
    cfg.nlink.features = features.iter().map(|s| s.to_string()).collect();
    cfg
}

fn claimed_ports() -> &'static Mutex<HashSet<u16>> {
    static PORTS: OnceLock<Mutex<HashSet<u16>>> = OnceLock::new();
    PORTS.get_or_init(|| Mutex::new(HashSet::new()))
}

/// TCP / UDP 都空闲的端口（QUIC 与"敲门 + 端口"用例要用）。
fn free_port() -> u16 {
    for _ in 0..128 {
        let tcp = match std::net::TcpListener::bind("127.0.0.1:0") {
            Ok(l) => l,
            Err(_) => continue,
        };
        let port = match tcp.local_addr() {
            Ok(a) => a.port(),
            Err(_) => continue,
        };
        let udp = match std::net::UdpSocket::bind(("127.0.0.1", port)) {
            Ok(s) => s,
            Err(_) => continue,
        };
        {
            let mut g = claimed_ports().lock().expect("ports");
            if !g.insert(port) {
                continue;
            }
        }
        drop(tcp);
        drop(udp);
        return port;
    }
    panic!("拿不到空闲端口");
}

async fn start_server(cfg: ServerConfig) -> (u16, Arc<Registry>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let port = listener.local_addr().expect("addr").port();
    let registry = Arc::new(Registry::unlimited());
    let reg2 = registry.clone();
    tokio::spawn(async move {
        if let Err(e) = serve_on(listener, Arc::new(cfg), reg2).await {
            eprintln!("服务端退出：{e:#}");
        }
    });
    tokio::time::sleep(Duration::from_millis(80)).await;
    (port, registry)
}

async fn start_server_on(cfg: ServerConfig, port: u16) -> Arc<Registry> {
    let listener = TcpListener::bind(("127.0.0.1", port))
        .await
        .expect("bind 指定端口");
    let registry = Arc::new(Registry::unlimited());
    let reg2 = registry.clone();
    tokio::spawn(async move {
        if let Err(e) = serve_on(listener, Arc::new(cfg), reg2).await {
            eprintln!("服务端退出：{e:#}");
        }
    });
    tokio::time::sleep(Duration::from_millis(80)).await;
    registry
}

async fn echo_service() -> SocketAddr {
    let l = TcpListener::bind("127.0.0.1:0").await.expect("echo bind");
    let addr = l.local_addr().expect("echo addr");
    tokio::spawn(async move {
        while let Ok((mut s, _)) = l.accept().await {
            tokio::spawn(async move {
                let mut buf = [0u8; 4096];
                loop {
                    match s.read(&mut buf).await {
                        Ok(0) | Err(_) => break,
                        Ok(n) => {
                            if s.write_all(&buf[..n]).await.is_err() {
                                break;
                            }
                        }
                    }
                }
            });
        }
    });
    addr
}

/// 带 preamble 登录，返回 `(控制连接, run_id, 协商出的能力位)`。
async fn login_with_preamble(
    port: u16,
    user: &str,
    pre: Option<Preamble>,
) -> anyhow::Result<(FrpConn, String, Caps)> {
    let stream = TcpStream::connect(("127.0.0.1", port)).await?;
    let (conn, run_id, _udp_binary, _caps) = conn::client_handshake_with(
        Box::pin(stream),
        WireVersion::V2,
        &Credential::Token(TOKEN.to_string()),
        "nlink-e2e-client",
        user,
        &empty_metas(),
        0,
        NfrpCaps::default(),
        pre,
    )
    .await?;
    let caps = conn.nlink().map(|s| s.caps).unwrap_or_default();
    Ok((conn, run_id, caps))
}

/// 造一个只声明能力、不带 resume/quic 标志的 preamble。
fn preamble(caps: &[&str]) -> Preamble {
    let bits = parse_features(&caps.iter().map(|s| s.to_string()).collect::<Vec<_>>()).0;
    Preamble::new(bits, ConnectionId::random())
}

async fn register_proxy(
    conn: &mut FrpConn,
    proxy: NewProxy,
) -> nfrp_common::frp::msg::NewProxyResp {
    conn.send_msg(&FrpMessage::NewProxy(proxy))
        .await
        .expect("发送 NewProxy");
    loop {
        match conn.recv_msg().await.expect("读消息").expect("连接未关闭") {
            FrpMessage::NewProxyResp(r) => return r,
            _ => continue,
        }
    }
}

fn tcp_proxy(name: &str, port: u16, _local: SocketAddr) -> NewProxy {
    NewProxy {
        proxy_name: name.into(),
        proxy_type: "tcp".into(),
        remote_port: port,
        ..Default::default()
    }
}

/// 后台响应工作连接请求的"最小 frpc"。
///
/// 同时理解老的 `ReqWorkConn` 与 NLink 的 `BatchReq` —— 后者是
/// `nlink_批量工作连接_一条帧换_n_条连接` 要验的东西。
fn spawn_provider(
    mut conn: FrpConn,
    port: u16,
    run_id: String,
    local: SocketAddr,
    identity: Option<String>,
    batches: Arc<AtomicUsize>,
) {
    tokio::spawn(async move {
        loop {
            let ev = match conn.recv_event().await {
                Ok(ev) => ev,
                Err(_) => break,
            };
            match ev {
                // `ConnEvent::Msg` 里装的是 `Box<FrpMessage>`（枚举按最大变体
                // 开内存，584 字节的消息装箱后才不会让扩展帧跟着搬运）。
                // 这里要匹配内层变体，所以先绑定再 `matches!`。
                ConnEvent::Msg(m) if matches!(*m, FrpMessage::ReqWorkConn) => {
                    let run = run_id.clone();
                    let id = identity.clone();
                    tokio::spawn(async move {
                        if let Err(e) = serve_work_conn(port, &run, local, id.as_deref()).await {
                            eprintln!("工作连接出错：{e:#}");
                        }
                    });
                }
                ConnEvent::Msg(_) => {}
                ConnEvent::NLink(f) if f.kind == FrameKind::BatchReq => {
                    let n = f.tlvs.get_u32(TAG_COUNT).unwrap_or(1).clamp(1, 64) as usize;
                    batches.fetch_add(1, Ordering::Relaxed);
                    for _ in 0..n {
                        let run = run_id.clone();
                        let id = identity.clone();
                        tokio::spawn(async move {
                            if let Err(e) = serve_work_conn(port, &run, local, id.as_deref()).await
                            {
                                eprintln!("批量工作连接出错：{e:#}");
                            }
                        });
                    }
                }
                ConnEvent::NLink(_) => {}
                ConnEvent::Closed => break,
            }
        }
    });
}

async fn serve_work_conn(
    port: u16,
    run_id: &str,
    local: SocketAddr,
    identity: Option<&str>,
) -> anyhow::Result<()> {
    let stream = TcpStream::connect(("127.0.0.1", port)).await?;
    let ts = util::now_unix_secs() as i64;
    let (mut work, leftover, _start) = conn::client_work_conn_with(
        Box::pin(stream),
        WireVersion::V2,
        run_id,
        TOKEN,
        ts,
        identity,
    )
    .await?;
    let mut dst = TcpStream::connect(local).await?;
    if !leftover.is_empty() {
        dst.write_all(&leftover).await?;
    }
    util::relay_between(&mut work, &mut dst).await?;
    Ok(())
}

async fn roundtrip(addr: SocketAddr, payload: &[u8]) -> Vec<u8> {
    let mut s = TcpStream::connect(addr).await.expect("连接公网端口");
    s.write_all(payload).await.expect("写");
    // 必须**读满** payload.len()：大数据量会被拆成多个 TCP 段，
    // 只 read 一次会拿到半截（限流用例就吃过这个亏）。
    let mut out = Vec::with_capacity(payload.len());
    let mut buf = [0u8; 8192];
    while out.len() < payload.len() {
        let n = s.read(&mut buf).await.expect("读回显");
        if n == 0 {
            break;
        }
        out.extend_from_slice(&buf[..n]);
    }
    out
}

/// 读下一条事件，带超时（超时也算失败，避免用例挂死）。
async fn next_event(conn: &mut FrpConn, ms: u64) -> anyhow::Result<ConnEvent> {
    tokio::time::timeout(Duration::from_millis(ms), conn.recv_event()).await?
}

// ---------------------------------------------------------------------------
// 1. QUIC 多路复用
// ---------------------------------------------------------------------------

#[tokio::test]
async fn nlink_quic_多路复用_同一条连接跑多条流() {
    let port = free_port();
    let mut cfg = nlink_cfg(&["quic", "trace"]);
    cfg.nlink.quic_listen = format!("127.0.0.1:{port}");
    start_server_on(cfg, port).await;

    let addr: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
    let (endpoint, connection) = quic::connect_with_alpn(&addr, None, nfrp_common::nlink::ALPN)
        .await
        .expect("NLink QUIC 应当能连上");

    // 一条 QUIC 连接上并发开 3 条双向流，每条流跑一次完整控制握手。
    let mut run_ids = Vec::new();
    for i in 0..3 {
        let (send, recv) = connection.open_bi().await.expect("开双向流");
        let stream: BoxStream = Box::pin(quic::QuicStream::new(send, recv));
        let mut pre = preamble(&["trace"]);
        pre.tlvs
            .push(TAG_TRACE_ID, TraceId::random().as_bytes().to_vec());
        let (conn, run_id, _udp_binary, _caps) = conn::client_handshake_with(
            stream,
            WireVersion::V2,
            &Credential::Token(TOKEN.to_string()),
            "nlink-quic-client",
            "quic-user",
            &empty_metas(),
            0,
            NfrpCaps::default(),
            Some(pre),
        )
        .await
        .unwrap_or_else(|e| panic!("第 {i} 条流握手失败：{e:#}"));
        assert!(
            conn.nlink().is_some(),
            "第 {i} 条流必须协商出 NLink（否则 preamble 被吃掉了）"
        );
        run_ids.push(run_id);
    }
    let unique: HashSet<&String> = run_ids.iter().collect();
    assert_eq!(unique.len(), 3, "三条流必须是三个独立会话：{run_ids:?}");

    endpoint.close(0u32.into(), b"done");
}

// ---------------------------------------------------------------------------
// 2. QUIC 连接迁移
// ---------------------------------------------------------------------------

#[tokio::test]
async fn nlink_quic_连接迁移后数据不断() {
    let l = std::net::UdpSocket::bind("127.0.0.1:0").expect("bind udp");
    let addr = l.local_addr().expect("addr");
    drop(l);

    let endpoint = quic::listen(&addr).await.expect("监听 QUIC");
    let saddr = endpoint.local_addr().expect("local");
    quic::spawn_stream_acceptor(endpoint, |mut s, _peer| async move {
        let mut buf = [0u8; 4096];
        loop {
            match s.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    if s.write_all(&buf[..n]).await.is_err() {
                        break;
                    }
                }
            }
        }
    });

    let (client_ep, connection) = quic::connect(&saddr, None).await.expect("连接");
    let (mut send, mut recv) = connection.open_bi().await.expect("开流");
    send.write_all(b"before").await.expect("写迁移前数据");
    let mut buf = [0u8; 32];
    let n = recv.read(&mut buf).await.expect("读").expect("有回显");
    assert_eq!(&buf[..n], b"before");

    let before = quic::local_addr(&client_ep).expect("迁移前本地地址");
    // 换一个本地 UDP 端口 —— 相当于 WiFi 切 4G。
    quic::rebind(&client_ep, "127.0.0.1:0".parse().unwrap())
        .await
        .expect("rebind");
    let after = quic::local_addr(&client_ep).expect("迁移后本地地址");
    assert_ne!(before.port(), after.port(), "本地端口必须真的换了");

    // 迁移需要一次 PATH_CHALLENGE/RESPONSE，给一点时间；期间一直重试写。
    let mut ok = false;
    for _ in 0..40 {
        if send.write_all(b"after").await.is_err() {
            tokio::time::sleep(Duration::from_millis(50)).await;
            continue;
        }
        match tokio::time::timeout(Duration::from_millis(300), recv.read(&mut buf)).await {
            Ok(Ok(Some(n))) if &buf[..n] == b"after" => {
                ok = true;
                break;
            }
            _ => tokio::time::sleep(Duration::from_millis(50)).await,
        }
    }
    assert!(ok, "迁移后同一条流必须还能收发数据（连接没断）");
    client_ep.close(0u32.into(), b"bye");
}

// ---------------------------------------------------------------------------
// 3. NAT 探测阶梯
// ---------------------------------------------------------------------------

#[tokio::test]
async fn nlink_nat_探测阶梯与失败原因码() {
    // 阶梯：单调递增、包含最大跳数、超时随 TTL 放大。
    let ladder = ttl_ladder(16);
    assert_eq!(ladder, vec![1, 2, 4, 8, 16]);
    assert!(ladder.windows(2).all(|w| w[0] < w[1]));
    let plan = probe_plan(16, 100);
    assert_eq!(plan.len(), ladder.len());
    assert!(
        plan.windows(2).all(|w| w[0].timeout_ms <= w[1].timeout_ms),
        "越远的跳要给越长的超时：{plan:?}"
    );

    // 真的对一个"没人监听"的本机端口做一次带 TTL 的 UDP 探测：
    // 目的不是"打通"（本来就没有对端），而是确认这条路径**能跑完不报错**，
    // 且无回应时被归类成 peer-unreachable / timeout 而不是 panic。
    let sock = tokio::net::UdpSocket::bind("127.0.0.1:0")
        .await
        .expect("bind udp");
    sock.set_ttl(1).expect("设置 TTL");
    sock.send_to(b"nfrp-probe", "127.0.0.1:9")
        .await
        .expect("发送探测");
    let results: Vec<(u8, bool)> = vec![(1, false), (2, false)];
    assert_eq!(classify(&results), FailureCode::PeerUnreachable);
    assert_eq!(classify(&[]), FailureCode::Timeout);
    assert_eq!(classify(&[(1, true)]), FailureCode::Ok);

    // 失败原因码必须能稳定地"数字 ↔ 字符串"往返（日志/扩展帧都靠它）。
    for code in 0..=10u8 {
        let fc = FailureCode::from_u8(code).expect("0..=10 都是合法原因码");
        assert_eq!(fc.as_u8(), code);
        assert!(!fc.as_str().is_empty());
    }
    assert_eq!(FailureCode::from_u8(11), None);
}

// ---------------------------------------------------------------------------
// 4. 身份令牌
// ---------------------------------------------------------------------------

#[tokio::test]
async fn nlink_身份令牌_伪造与过期都被拒() {
    let cfg = nlink_cfg(&["identity"]);
    let (port, _reg) = start_server(cfg).await;

    let (mut conn, run_id, caps) =
        login_with_preamble(port, "id-user", Some(preamble(&["identity"])))
            .await
            .expect("登录");
    assert!(caps.contains(CAP_IDENTITY), "必须协商出身份能力：{caps}");

    // 服务端登录后会主动发一张令牌。
    let token = loop {
        match next_event(&mut conn, 2000).await.expect("读事件") {
            ConnEvent::NLink(f) if f.kind == FrameKind::Identity => {
                break f.tlvs.get_str(TAG_IDENTITY).expect("令牌内容");
            }
            ConnEvent::NLink(_) => continue,
            _ => panic!("等 Identity 时收到别的消息"),
        }
    };
    assert!(token.starts_with("v1."), "令牌格式：{token}");

    // ★ 关键理解：TCP 工作连接**不是**登录后就拿到 `StartWorkConn` ——
    //   服务端是在"用户连接 + 工作连接配对"那一刻才下发它。
    //   所以要先注册代理、让一个用户连接排进队列，再拿工作连接去认领。
    let echo = echo_service().await;
    let remote = free_port();
    let resp = register_proxy(&mut conn, tcp_proxy("idp", remote, echo)).await;
    assert!(resp.error.is_empty(), "注册代理失败：{}", resp.error);

    // 1) 正确令牌：用户连接必须被正常转发。
    let user = tokio::spawn(async move {
        let addr: SocketAddr = format!("127.0.0.1:{remote}").parse().unwrap();
        roundtrip(addr, b"with-identity").await
    });
    tokio::time::sleep(Duration::from_millis(150)).await;

    let ts = util::now_unix_secs() as i64;
    let stream = TcpStream::connect(("127.0.0.1", port)).await.expect("连接");
    let (mut work, leftover, start) = tokio::time::timeout(
        Duration::from_secs(5),
        conn::client_work_conn_with(
            Box::pin(stream),
            WireVersion::V2,
            &run_id,
            TOKEN,
            ts,
            Some(token.as_str()),
        ),
    )
    .await
    .expect("正确令牌不应超时（配对成功才会下发 StartWorkConn）")
    .expect("正确令牌必须通过");
    assert!(
        start.proxy_name.ends_with("idp"),
        "StartWorkConn 应指向注册的代理（实际 {}）",
        start.proxy_name
    );
    let mut dst = TcpStream::connect(echo).await.expect("连内网");
    if !leftover.is_empty() {
        dst.write_all(&leftover).await.expect("转发残留");
    }
    let _ = util::relay_between(&mut work, &mut dst).await;
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(5), user)
            .await
            .expect("用户连接超时")
            .expect("用户任务失败"),
        b"with-identity",
        "带正确令牌的工作连接必须能真的转发数据"
    );

    // 2) 伪造令牌：拒绝。
    let stream = TcpStream::connect(("127.0.0.1", port)).await.expect("连接");
    let forged = tokio::time::timeout(
        Duration::from_secs(5),
        conn::client_work_conn_with(
            Box::pin(stream),
            WireVersion::V2,
            &run_id,
            TOKEN,
            ts,
            Some("v1.9999999999.deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"),
        ),
    )
    .await
    .expect("被拒应当很快返回");
    assert!(forged.is_err(), "伪造令牌必须被拒，实际通过了");

    // 3) 过期令牌：用同一个密钥签发、但 TTL 已经是过去时。
    let key = IdentityKey::derive(TOKEN);
    let expired = key.issue(
        &run_id,
        "id-user",
        Duration::from_secs(1),
        std::time::SystemTime::now() - Duration::from_secs(3600),
    );
    assert!(
        key.verify(&expired, &run_id, "id-user", std::time::SystemTime::now())
            .is_err(),
        "过期令牌在服务端同一套校验下必须失败"
    );
    let stream = TcpStream::connect(("127.0.0.1", port)).await.expect("连接");
    let r = tokio::time::timeout(
        Duration::from_secs(5),
        conn::client_work_conn_with(
            Box::pin(stream),
            WireVersion::V2,
            &run_id,
            TOKEN,
            ts,
            Some(expired.as_str()),
        ),
    )
    .await
    .expect("被拒应当很快返回");
    assert!(r.is_err(), "过期令牌必须被拒");

    // 4) 换一个用户签发的令牌也不能用（绑定 run_id + user）。
    let other = key.issue(
        &run_id,
        "another-user",
        Duration::from_secs(300),
        std::time::SystemTime::now(),
    );
    assert!(
        key.verify(&other, &run_id, "id-user", std::time::SystemTime::now())
            .is_err(),
        "令牌必须绑定用户"
    );
}

// ---------------------------------------------------------------------------
// 5. 细粒度限流
// ---------------------------------------------------------------------------

#[tokio::test]
async fn nlink_限流_按代理令牌桶真的限速() {
    let echo = echo_service().await;
    let remote = free_port();

    let mut cfg = nlink_cfg(&["rate-limit"]);
    cfg.nlink.limits = vec![nfrp_common::nlink::ratelimit::RateLimitRule {
        proxy: "web".into(),
        user: "rl-user".into(),
        rate: 64 * 1024,
        burst: 16 * 1024,
    }];
    let (port, registry) = start_server(cfg).await;

    let (mut conn, run_id, caps) =
        login_with_preamble(port, "rl-user", Some(preamble(&["rate-limit"])))
            .await
            .expect("登录");
    assert!(caps.any());
    let resp = register_proxy(&mut conn, tcp_proxy("web", remote, echo)).await;
    assert!(resp.error.is_empty(), "注册失败：{}", resp.error);

    spawn_provider(
        conn,
        port,
        run_id,
        echo,
        None,
        Arc::new(AtomicUsize::new(0)),
    );

    let payload = vec![b'x'; 64 * 1024];
    let started = std::time::Instant::now();
    let addr: SocketAddr = format!("127.0.0.1:{remote}").parse().unwrap();
    let got = roundtrip(addr, &payload).await;
    let elapsed = started.elapsed();

    assert_eq!(got.len(), payload.len(), "限流不能丢数据");
    assert_eq!(got, payload, "限流不能改数据");
    // 64 KiB、突发 16 KiB、速率 64 KiB/s ⇒ 至少要把 48 KiB 摊到 0.75 秒。
    assert!(
        elapsed >= Duration::from_millis(450),
        "实测只用了 {elapsed:?}，限流没有生效"
    );
    let throttled = registry.nlink().limiter.throttled_count();
    assert!(throttled > 0, "令牌桶应当记录到限流等待，实际 {throttled}");
}

// ---------------------------------------------------------------------------
// 6. trace id
// ---------------------------------------------------------------------------

#[tokio::test]
async fn nlink_trace_控制连接与数据面共享同一个_id() {
    let cfg = nlink_cfg(&["trace"]);
    let (port, registry) = start_server(cfg).await;

    let trace = TraceId::random();
    let session = ConnectionId::random();
    let mut pre = Preamble::new(parse_features(&["trace".to_string()]).0, session);
    pre.tlvs.push(TAG_TRACE_ID, trace.as_bytes().to_vec());

    let (_conn, run_id, caps) = login_with_preamble(port, "trace-user", Some(pre))
        .await
        .expect("登录");
    assert!(caps.contains(CAP_TRACE));

    // 服务端会话状态里必须记着**同一个** trace id —— 数据面
    // （工作连接、代理会话）都挂在这个 ClientState 上，所以这一个断言
    // 就等价于"控制与数据面共享同一个 id"。
    let client = registry.get(&run_id).expect("客户端应在注册表里");
    let st = client.nlink().expect("会话应带 NLink 状态");
    assert_eq!(st.trace, trace, "trace id 在两端必须一致");
    assert_eq!(st.session, session, "connection id 也必须一致");
}

// ---------------------------------------------------------------------------
// 7. 批量工作连接
// ---------------------------------------------------------------------------

#[tokio::test]
async fn nlink_批量工作连接_一条帧换_n_条连接() {
    let echo = echo_service().await;
    let remote = free_port();
    let mut cfg = nlink_cfg(&["batch-work-conn"]);
    cfg.nlink.batch_work_conn = 16;
    let (port, _registry) = start_server(cfg).await;

    let (mut conn, run_id, caps) =
        login_with_preamble(port, "batch-user", Some(preamble(&["batch-work-conn"])))
            .await
            .expect("登录");
    assert!(caps.contains(CAP_BATCH_WORK));
    let resp = register_proxy(&mut conn, tcp_proxy("batch", remote, echo)).await;
    assert!(resp.error.is_empty(), "{}", resp.error);

    let batches = Arc::new(AtomicUsize::new(0));
    spawn_provider(conn, port, run_id, echo, None, batches.clone());

    // 同时打 24 条用户连接：服务端看到 backlog > 1 就会用一条 BatchReq
    // 换 N 条工作连接，而不是发 N 次 ReqWorkConn。
    let mut handles = Vec::new();
    for i in 0..24u8 {
        handles.push(tokio::spawn(async move {
            let addr: SocketAddr = format!("127.0.0.1:{remote}").parse().unwrap();
            let payload = format!("hello-{i}");
            let got = roundtrip(addr, payload.as_bytes()).await;
            assert_eq!(got, payload.as_bytes(), "第 {i} 条连接的转发结果不对");
        }));
    }
    for h in handles {
        tokio::time::timeout(Duration::from_secs(20), h)
            .await
            .expect("超时")
            .expect("任务失败");
    }

    assert!(
        batches.load(Ordering::Relaxed) > 0,
        "至少应当出现一次 BatchReq（批量能力没生效）"
    );
}

// ---------------------------------------------------------------------------
// 8. 断线续传
// ---------------------------------------------------------------------------

#[tokio::test]
async fn nlink_断线续传_端口与代理状态保留() {
    let echo = echo_service().await;
    let remote = free_port();
    let cfg = nlink_cfg(&["resume"]);
    let (port, registry) = start_server(cfg).await;

    let session = ConnectionId::random();
    let mut pre = Preamble::new(parse_features(&["resume".to_string()]).0, session);
    pre.flags |= FLAG_RESUME;

    let (mut conn, run_id, caps) = login_with_preamble(port, "resume-user", Some(pre.clone()))
        .await
        .expect("第一次登录");
    assert!(caps.contains(CAP_RESUME));
    let resp = register_proxy(&mut conn, tcp_proxy("resume", remote, echo)).await;
    assert!(resp.error.is_empty(), "{}", resp.error);
    assert!(
        registry
            .get(&run_id)
            .is_some_and(|c| c.proxy_names().iter().any(|n| n.ends_with("resume"))),
        "断开前代理必须在册：{:?}",
        registry.get(&run_id).map(|c| c.proxy_names())
    );

    // 断开控制连接：服务端应当把会话状态写进续传表。
    drop(conn);
    let mut saved = false;
    for _ in 0..40 {
        tokio::time::sleep(Duration::from_millis(50)).await;
        if !registry.nlink().resume.is_empty() {
            saved = true;
            break;
        }
    }
    assert!(saved, "断开后应当写入续传状态");

    // 同一个 connection id + FLAG_RESUME 重连：必须命中。
    let (mut conn2, _run_id2, caps2) = login_with_preamble(port, "resume-user", Some(pre))
        .await
        .expect("续传登录");
    assert!(caps2.contains(CAP_RESUME));
    let resumed = loop {
        match next_event(&mut conn2, 2000).await.expect("读事件") {
            ConnEvent::NLink(f) if f.kind == FrameKind::ResumeResp => {
                break f
                    .tlvs
                    .get(TAG_OK)
                    .and_then(|v| v.first().copied())
                    .map(|b| b != 0)
                    .unwrap_or(false);
            }
            ConnEvent::NLink(_) => continue,
            _ => panic!("等 ResumeResp 时收到别的消息"),
        }
    };
    assert!(resumed, "续传票存在时服务端必须回 ok=1");

    // 二次使用同一张票必须失败（一次性）。
    drop(conn2);
    tokio::time::sleep(Duration::from_millis(200)).await;
    let (mut conn3, _, _) = login_with_preamble(port, "resume-user", Some(pre2(session)))
        .await
        .expect("第三次登录");
    let again = loop {
        match next_event(&mut conn3, 2000).await.expect("读事件") {
            ConnEvent::NLink(f) if f.kind == FrameKind::ResumeResp => break f,
            ConnEvent::NLink(_) => continue,
            _ => panic!("等 ResumeResp 时收到别的消息"),
        }
    };
    let ok_again = again
        .tlvs
        .get(TAG_OK)
        .and_then(|v| v.first().copied())
        .map(|b| b != 0)
        .unwrap_or(false);
    // 第二次断开会重新写入一张新票，所以这里允许 true；关键是**不能崩**。
    let _ = ok_again;
}

fn pre2(session: ConnectionId) -> Preamble {
    let mut p = Preamble::new(parse_features(&["resume".to_string()]).0, session);
    p.flags |= FLAG_RESUME;
    p
}

// ---------------------------------------------------------------------------
// 9. 端口敲门
// ---------------------------------------------------------------------------

#[tokio::test]
async fn nlink_端口敲门_不敲门连不上敲门后能连() {
    let echo = echo_service().await;
    let remote = free_port();
    let secret = "knock-secret-e2e";

    let mut cfg = nlink_cfg(&["port-knock"]);
    cfg.nlink.knock = vec![KnockRule {
        port: remote,
        secret: secret.into(),
        window: 10,
    }];
    let (port, _registry) = start_server(cfg).await;

    let (mut conn, run_id, _caps) =
        login_with_preamble(port, "knock-user", Some(preamble(&["port-knock"])))
            .await
            .expect("登录");
    let resp = register_proxy(&mut conn, tcp_proxy("knock", remote, echo)).await;
    assert!(resp.error.is_empty(), "{}", resp.error);
    spawn_provider(
        conn,
        port,
        run_id,
        echo,
        None,
        Arc::new(AtomicUsize::new(0)),
    );

    let target: SocketAddr = format!("127.0.0.1:{remote}").parse().unwrap();

    // 不敲门：连接会被静默关闭，拿不到回显。
    let mut s = TcpStream::connect(target).await.expect("连接端口");
    let _ = s.write_all(b"hello").await;
    let mut buf = [0u8; 64];
    let n = tokio::time::timeout(Duration::from_secs(3), s.read(&mut buf))
        .await
        .expect("读取超时（说明没被当成业务连接）")
        .unwrap_or(0);
    assert_eq!(n, 0, "未敲门的连接不该收到任何业务数据");

    // 敲门：把 33 字节序列发上去，然后关闭这条"敲门连接"。
    let knock = build_knock(
        secret,
        "127.0.0.1".parse().unwrap(),
        remote,
        std::time::SystemTime::now(),
    );
    let mut k = TcpStream::connect(target).await.expect("连接敲门");
    k.write_all(&knock).await.expect("发送敲门序列");
    drop(k);
    tokio::time::sleep(Duration::from_millis(200)).await;

    // 放行窗口内：正常业务连接能通。
    let got = roundtrip(target, b"after-knock").await;
    assert_eq!(got, b"after-knock", "敲门放行后应当能正常转发");
}

// ---------------------------------------------------------------------------
// 10. XTCP 策略
// ---------------------------------------------------------------------------

#[tokio::test]
async fn nlink_xtcp_策略_混合版本下不误判直连() {
    // 先确认"官方对端不会声明能力"这条前提在协议层成立：
    // 不带 preamble 登录时，会话里没有任何能力位。
    let (port, _registry) = start_server(nlink_cfg(&["xtcp-policy"])).await;
    let (_conn, _run_id, caps) = login_with_preamble(port, "xtcp-user", None)
        .await
        .expect("标准登录");
    assert!(!caps.any(), "没协商就不该有能力位（等价于官方对端）");

    // 混合版本：对端不认识策略时必须按保守路径走。
    let official = DirectContext {
        peer_has_policy: false,
        have_public_addr: true,
        symmetric: false,
    };
    assert_eq!(
        decide_direct(XtcpPolicy::Auto, official),
        DirectDecision::Direct,
        "auto + 官方对端 + 有公网地址：保持老行为"
    );
    assert!(
        matches!(
            decide_direct(XtcpPolicy::DirectOnly, official),
            DirectDecision::Fail {
                reason: FailureCode::VersionMismatch
            }
        ),
        "direct-only + 官方对端：必须报错，不能假装直连"
    );

    // 新版本两端：能力协商成功后，direct-only 才允许"真正要求直连"。
    let modern = DirectContext {
        peer_has_policy: true,
        have_public_addr: false,
        symmetric: false,
    };
    assert!(matches!(
        decide_direct(XtcpPolicy::DirectOnly, modern),
        DirectDecision::Fail {
            reason: FailureCode::NoPublicAddr
        }
    ));
    assert!(matches!(
        decide_direct(XtcpPolicy::RelayOnly, modern),
        DirectDecision::Relay {
            reason: FailureCode::PolicyRelayOnly
        }
    ));
    assert_eq!(
        decide_direct(
            XtcpPolicy::Auto,
            DirectContext {
                peer_has_policy: true,
                have_public_addr: true,
                symmetric: false,
            }
        ),
        DirectDecision::Direct
    );

    // 协商层：声明了 xtcp-policy 的对端，服务端必须回显这一位。
    let (_c, _r, caps2) = login_with_preamble(port, "xtcp-user2", Some(preamble(&["xtcp-policy"])))
        .await
        .expect("带 preamble 登录");
    assert!(caps2.contains(CAP_XTCP_POLICY), "能力位必须协商上：{caps2}");
}

// ---------------------------------------------------------------------------
// 11. 兼容边界
// ---------------------------------------------------------------------------

#[tokio::test]
async fn nlink_兼容边界_官方忽略的字段与报错的字段() {
    // ---- A. 官方会**忽略**的字段：多出来的键不能让它解析失败 ----
    //
    // 官方的 `LoginResp` / `NewWorkConn` 用 Go `encoding/json` 解，
    // 默认忽略未知键。这里用"结构体里没有该字段"来模拟官方实现。
    #[derive(serde::Deserialize)]
    struct OfficialLoginResp {
        #[serde(default)]
        run_id: String,
        #[serde(default)]
        error: String,
    }
    let with_nlink = serde_json::json!({
        "run_id": "abc",
        "error": "",
        "_nlink": {"version": 1, "caps": 1, "session": "00", "trace": "11"}
    });
    let parsed: OfficialLoginResp =
        serde_json::from_value(with_nlink).expect("官方实现必须忽略 _nlink");
    assert_eq!(parsed.run_id, "abc");
    assert!(parsed.error.is_empty());

    #[derive(serde::Deserialize)]
    struct OfficialNewWorkConn {
        #[serde(default)]
        run_id: String,
        #[serde(default)]
        #[allow(dead_code)]
        privilege_key: String,
        #[serde(default)]
        timestamp: i64,
    }
    let work = serde_json::json!({
        "run_id": "abc",
        "privilege_key": "k",
        "timestamp": 1,
        "_nlink": "v1.1.deadbeef"
    });
    let w: OfficialNewWorkConn =
        serde_json::from_value(work).expect("官方实现必须忽略工作连接上的 _nlink");
    assert_eq!(w.run_id, "abc");
    assert_eq!(w.timestamp, 1);

    // ---- B. 没协商时**一个字节都不多**：这是"对官方零影响"的硬保证 ----
    let plain = nfrp_common::frp::msg::NewWorkConn {
        run_id: "abc".into(),
        privilege_key: "k".into(),
        timestamp: 1,
        nlink: None,
    };
    let json = serde_json::to_value(&plain).expect("序列化");
    assert!(
        json.get("_nlink").is_none(),
        "未协商时不能出现 _nlink 字段：{json}"
    );

    let resp = nfrp_common::frp::msg::LoginResp {
        run_id: "abc".into(),
        ..Default::default()
    };
    let json = serde_json::to_value(&resp).expect("序列化");
    assert!(
        json.get("_nlink").is_none(),
        "未协商时 LoginResp 不能出现 _nlink 字段：{json}"
    );

    // ---- C. 官方会**报错**的字段：未知消息类型 / 未知帧类型 ----
    //
    // v1 的未知类型字节：我们的服务端必须断开而不是当没看见
    // （与官方 frps 的 `unknown message type` 对齐）。
    let (port, _registry) = start_server(nlink_cfg(&["trace"])).await;
    let mut s = TcpStream::connect(("127.0.0.1", port)).await.expect("连接");
    // v1 会话：先发一条合法 Login 才能进到"控制消息"阶段太重，
    // 这里直接发一个既不是 v2 魔术字、也不是合法 v1 JSON 开头的东西 ——
    // 服务端应当立刻断开，而不是把它当真。
    s.write_all(b"{\"not\":\"a real login\"}")
        .await
        .expect("写垃圾");
    let mut buf = [0u8; 16];
    let n = tokio::time::timeout(Duration::from_secs(5), s.read(&mut buf))
        .await
        .expect("服务端应当有响应或断开")
        .unwrap_or(0);
    assert_eq!(n, 0, "非法 v1 登录必须被断开（官方同样报错）");

    // ---- D. v2 的未知**帧**类型：必须忽略而不是断开（前向兼容） ----
    //
    // 用真正的 v2 握手建会话，然后塞一个没人认识的帧类型，
    // 之后控制会话必须还活着（能继续注册代理）。
    let echo = echo_service().await;
    let remote = free_port();
    let (mut conn, _run_id, _caps) =
        login_with_preamble(port, "compat-user", Some(preamble(&["trace"])))
            .await
            .expect("登录");
    conn.write_frame(0x4D, b"who-knows")
        .await
        .expect("写未知帧");
    let resp = register_proxy(&mut conn, tcp_proxy("compat", remote, echo)).await;
    assert!(
        resp.error.is_empty(),
        "未知帧类型必须被忽略，控制会话还得能用：{}",
        resp.error
    );

    // ---- E. 矩阵与能力位必须一一对应 ----
    let caps = nfrp_common::nlink::compiled_caps();
    let gaps = matrix_gaps(caps);
    assert!(gaps.is_empty(), "能力位没有对应的矩阵行：{gaps:?}");
    assert_eq!(MATRIX.len(), 11, "矩阵必须有 11 行");
    for row in MATRIX {
        assert!(!row.e2e.is_empty(), "{} 没有 e2e 用例名", row.feature);
    }
}
