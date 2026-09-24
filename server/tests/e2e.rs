//! 端到端集成测试：进程内起一个**真的** rustunnel-server，
//! 再用一个"最小 frp 客户端"按 frp v2 线协议连上来，验证转发是真通的。
//!
//! 为什么要这一层：单元测试再全也只能证明"每个零件符合预期"，
//! 而线上事故几乎都出在**零件之间的时序**上 —— 控制连接建好了但工作连接
//! 要不到、配对成功却没发 StartWorkConn、visitor 校验通过却没取到工作连接。
//! 这些只有在真跑一遍完整协议时才暴露。

use std::{net::SocketAddr, sync::Arc, time::Duration};

use rustunnel_common::{
    config::ServerConfig,
    frp::{
        conn::{self, FrpConn},
        kcp::KcpStream,
        msg::{FrpMessage, NewProxy, NewProxyResp, UdpPacket},
        stream::BoxStream,
        WireVersion,
    },
    util,
};
use rustunnel_server::{serve_on, Registry};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream, UdpSocket},
};

const TOKEN: &str = "e2e-token";

/// 握手用的空 `metas`。
///
/// frp 的 `[metadatas]` 会原样进 `Login.metas`（frp 平台靠 `metas["token"]`
/// 识别隧道）；这些用例走的是自带 token 的模式，不需要附加元数据。
fn empty_metas() -> std::collections::HashMap<String, String> {
    std::collections::HashMap::new()
}

// ---------------------------------------------------------------------------
// 测试脚手架
// ---------------------------------------------------------------------------

/// 起一个真的服务端，返回它监听的端口。
async fn start_server(cfg: ServerConfig) -> u16 {
    start_server_with_registry(cfg).await.0
}

/// 在**指定端口**上起服务端（QUIC 用：端口号得提前挑好，保证 UDP 也能 bind）。
async fn start_server_on(cfg: ServerConfig, port: u16) -> u16 {
    let listener = TcpListener::bind(("127.0.0.1", port))
        .await
        .expect("bind 指定端口");
    let registry = Arc::new(Registry::unlimited());
    tokio::spawn(async move {
        if let Err(e) = serve_on(listener, Arc::new(cfg), registry).await {
            eprintln!("服务端退出：{e:#}");
        }
    });
    tokio::time::sleep(Duration::from_millis(80)).await;
    port
}

/// 与 [`start_server`] 相同，但把 `Registry` 也交出来。
///
/// 有些行为（比如"这个端口背后挂了几个后端"）只能从注册表里读，
/// 光看协议层是看不出来的。
async fn start_server_with_registry(cfg: ServerConfig) -> (u16, Arc<Registry>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let port = listener.local_addr().expect("local_addr").port();
    let registry = Arc::new(Registry::unlimited());
    let reg2 = registry.clone();
    tokio::spawn(async move {
        if let Err(e) = serve_on(listener, Arc::new(cfg), reg2).await {
            eprintln!("服务端退出：{e:#}");
        }
    });
    // 等一小会儿，确保 accept 循环已经就绪
    tokio::time::sleep(Duration::from_millis(80)).await;
    (port, registry)
}

fn base_cfg() -> ServerConfig {
    ServerConfig {
        bind_addr: "127.0.0.1".into(),
        token: TOKEN.to_string(),
        ..Default::default()
    }
}

/// 挑一个此刻空闲的端口（给 `remote_port` 用）。
///
/// 端口被释放到再被服务端 bind 之间有一小段窗口，理论上存在竞态；
/// 相比写死端口号（CI 上迟早冲突），这点风险可以接受。
fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .expect("bind ephemeral")
        .local_addr()
        .expect("local_addr")
        .port()
}

/// 挑一个**TCP 和 UDP 都 bind 得上**的端口（QUIC 服务端用）。
///
/// 两个协议空间是独立的：TCP:0 拿到的端口号，UDP 未必能 bind。
/// Windows 上尤其如此 —— Hyper-V 会预留一段 UDP 端口
/// （`netsh interface ipv4 show excludedportrange protocol=udp` 能看到），
/// 落在这段里的号 bind UDP 会直接 `os error 10013`。
/// 早先这里只按 TCP 挑号，测试在本机上就随机红。
fn free_port_both() -> u16 {
    for _ in 0..64 {
        let p = free_port();
        if std::net::UdpSocket::bind(("127.0.0.1", p)).is_ok() {
            return p;
        }
    }
    panic!("试了 64 次都没拿到 TCP/UDP 都能 bind 的端口")
}

/// 带标签的回显服务：回 `{tag}:` + 收到的内容。
///
/// 用来分辨"这一条连接到底是被哪台后端服务的" —— 负载均衡的对错
/// 只能从这个角度看，光看"有没有回包"是看不出来的。
async fn tagged_echo_service(tag: &'static str) -> SocketAddr {
    let l = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind tagged echo");
    let addr = l.local_addr().expect("tagged echo local_addr");
    tokio::spawn(async move {
        while let Ok((mut s, _)) = l.accept().await {
            tokio::spawn(async move {
                let mut buf = [0u8; 4096];
                loop {
                    match s.read(&mut buf).await {
                        Ok(0) | Err(_) => break,
                        Ok(n) => {
                            let mut out = format!("{tag}:").into_bytes();
                            out.extend_from_slice(&buf[..n]);
                            if s.write_all(&out).await.is_err() {
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

/// 一个会**原样回显**的内网服务，用来假装是 SSH / HTTP 之类的后端。
async fn echo_service() -> SocketAddr {
    let l = TcpListener::bind("127.0.0.1:0").await.expect("bind echo");
    let addr = l.local_addr().expect("echo local_addr");
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

/// 完成一次 frp **v2** 登录（历史用例默认走 v2，保持既有覆盖率）。
async fn login(port: u16, token: &str, user: &str) -> (FrpConn, String) {
    login_with(port, token, user, WireVersion::V2).await
}

/// 指定线协议登录，返回控制连接与服务端分配的 run_id。
///
/// 两套协议的服务端入口是同一个端口 —— 服务端按魔术字自动识别
/// （对应官方 frps 的 `wire.CheckMagic`），所以这里只是发不发魔术字的区别。
async fn login_with(port: u16, token: &str, user: &str, wire: WireVersion) -> (FrpConn, String) {
    let stream = TcpStream::connect(("127.0.0.1", port))
        .await
        .expect("连接服务端");
    let (conn, run_id, _udp_binary, _caps) = conn::client_handshake(
        Box::pin(stream),
        wire,
        &rustunnel_common::security::Credential::Token(token.to_string()),
        "e2e-client",
        user,
        &empty_metas(),
        0,
        Default::default(),
    )
    .await
    .expect("frp 握手");
    (conn, run_id)
}

/// 注册一个代理，返回服务端的应答。
///
/// 注意：注册期间服务端**可能**先插进来 ReqWorkConn（填池子），
/// 所以不能发完就死等 Resp，要边读边匹配，这也是真客户端的写法。
///
/// 命名的契约（与官方 frp 一致，别改）：
/// - 客户端 `NewProxy.proxy_name` 发的是**线上全名** `"{user}.{name}"`
///   （官方 frpc 的 `wireName` 就是这么算的：`naming.AddUserPrefix(user, name)`）；
/// - 注册表里的键与 `NewProxyResp.proxy_name` 同样是这个全名；
/// - rustunnel 服务端还额外做了层幂等（收到原始名也会补成全名），
///   所以本文件里传原始名进来也能跑通；
/// - 所以 visitor 的 `serverName` 必须自己拼上前缀（`serverUser` 或本机 `user`）。
async fn register_proxy(conn: &mut FrpConn, proxy: NewProxy) -> NewProxyResp {
    conn.send_msg(&FrpMessage::NewProxy(proxy))
        .await
        .expect("发送 NewProxy");
    loop {
        match conn
            .recv_msg()
            .await
            .expect("读取服务端消息")
            .expect("连接未关闭")
        {
            FrpMessage::NewProxyResp(r) => return r,
            other => eprintln!("注册期间忽略消息：{}", other.name()),
        }
    }
}

/// 把控制连接交给后台任务：它只负责响应 ReqWorkConn，
/// 收到一次就开一条工作连接去连 `local`。
fn spawn_provider(conn: FrpConn, port: u16, run_id: String, local: SocketAddr) {
    spawn_provider_with(conn, port, run_id, local, WireVersion::V2);
}

/// 同 [`spawn_provider`]，但显式指定线协议 —— 工作连接必须与控制连接一致。
fn spawn_provider_with(
    mut conn: FrpConn,
    port: u16,
    run_id: String,
    local: SocketAddr,
    wire: WireVersion,
) {
    tokio::spawn(async move {
        while let Ok(Some(msg)) = conn.recv_msg().await {
            if matches!(msg, FrpMessage::ReqWorkConn) {
                let run = run_id.clone();
                tokio::spawn(async move {
                    if let Err(e) = serve_work_conn_with(port, &run, local, wire).await {
                        eprintln!("工作连接出错：{e:#}");
                    }
                });
            }
        }
    });
}

/// 与 [`spawn_provider`] 相同，但工作连接走 QUIC 的新流。
fn spawn_provider_quic(mut conn: FrpConn, q: quinn::Connection, run_id: String, local: SocketAddr) {
    tokio::spawn(async move {
        while let Ok(Some(msg)) = conn.recv_msg().await {
            if matches!(msg, FrpMessage::ReqWorkConn) {
                let run = run_id.clone();
                let q = q.clone();
                tokio::spawn(async move {
                    if let Err(e) = serve_work_conn_quic(q, &run, local).await {
                        eprintln!("QUIC 工作连接出错：{e:#}");
                    }
                });
            }
        }
    });
}

/// 客户端侧的"工作连接"完整流程：NewWorkConn -> StartWorkConn -> 连内网 -> 双向转发。
async fn serve_work_conn_with(
    port: u16,
    run_id: &str,
    local: SocketAddr,
    wire: WireVersion,
) -> anyhow::Result<()> {
    let stream = TcpStream::connect(("127.0.0.1", port)).await?;
    let ts = util::now_unix_secs() as i64;
    let (mut work, leftover, _start) =
        conn::client_work_conn(Box::pin(stream), wire, run_id, TOKEN, ts).await?;
    let mut dst = TcpStream::connect(local).await?;
    if !leftover.is_empty() {
        dst.write_all(&leftover).await?;
    }
    util::relay_between(&mut work, &mut dst).await?;
    Ok(())
}

/// 连到某个公网端口上发一串数据，取回内网服务的回显。
async fn roundtrip(addr: SocketAddr, payload: &[u8]) -> Vec<u8> {
    let mut s = TcpStream::connect(addr).await.expect("连接公网端口");
    s.write_all(payload).await.expect("写数据");
    let mut buf = [0u8; 1024];
    let n = s.read(&mut buf).await.expect("读回显");
    buf[..n].to_vec()
}

/// 向面板端口发一个裸 HTTP 请求，只取状态码。
///
/// 不用 HTTP 客户端库：这里要验的恰恰是**裸请求**的行为（尤其是
/// 不带 `Authorization` 时会不会被拦），自己拼一个才最贴近探针的真实处境。
async fn http_status(addr: SocketAddr, path: &str, basic: Option<&str>) -> u16 {
    // 面板是随服务端一起异步起的，给它一点时间；连不上就重试，
    // 免得 CI 上抖动一下就把测试弄红
    let mut ready = None;
    for _ in 0..50 {
        match TcpStream::connect(addr).await {
            Ok(s) => {
                ready = Some(s);
                break;
            }
            Err(_) => tokio::time::sleep(Duration::from_millis(20)).await,
        }
    }
    let mut s = ready.expect("面板端口一直连不上");

    let auth = match basic {
        Some(cred) => format!("Authorization: Basic {cred}\r\n"),
        None => String::new(),
    };
    let req = format!("GET {path} HTTP/1.1\r\nHost: panel\r\n{auth}Connection: close\r\n\r\n");
    s.write_all(req.as_bytes()).await.expect("写请求");
    let mut resp = Vec::new();
    s.read_to_end(&mut resp).await.expect("读响应");
    String::from_utf8_lossy(&resp)
        .split_whitespace()
        .nth(1)
        .and_then(|c| c.parse().ok())
        .unwrap_or(0)
}

/// 走 QUIC 传输完成一次登录。
///
/// 返回的 `Endpoint` 必须一路持有到测试结束：它被 drop 时连接会立刻断掉。
async fn login_quic(
    port: u16,
    token: &str,
    user: &str,
) -> (quinn::Endpoint, quinn::Connection, FrpConn, String) {
    let addr = SocketAddr::from(([127, 0, 0, 1], port));
    let (endpoint, conn) = rustunnel_common::frp::quic::connect(&addr, None)
        .await
        .expect("QUIC 连接");
    let (send, recv) = conn.open_bi().await.expect("开控制流");
    let stream = Box::pin(rustunnel_common::frp::quic::QuicStream::new(send, recv));
    let (frp, run_id, _, _caps) = conn::client_handshake(
        stream,
        WireVersion::V2,
        &rustunnel_common::security::Credential::Token(token.to_string()),
        "e2e-quic",
        user,
        &empty_metas(),
        0,
        Default::default(),
    )
    .await
    .expect("frp 握手（QUIC）");
    (endpoint, conn, frp, run_id)
}

/// 在**同一条** QUIC 连接上再开一条流当工作连接 —— 这正是 QUIC 的优势：
/// 每条 frp 连接只是流，不需要重新握手、也不受其它流的丢包影响。
async fn serve_work_conn_quic(
    conn: quinn::Connection,
    run_id: &str,
    local: SocketAddr,
) -> anyhow::Result<()> {
    let (send, recv) = conn.open_bi().await?;
    let ts = util::now_unix_secs() as i64;
    let (mut work, leftover, _start) = conn::client_work_conn(
        Box::pin(rustunnel_common::frp::quic::QuicStream::new(send, recv)),
        WireVersion::V2,
        run_id,
        TOKEN,
        ts,
    )
    .await?;
    let mut dst = TcpStream::connect(local).await?;
    if !leftover.is_empty() {
        dst.write_all(&leftover).await?;
    }
    util::relay_between(&mut work, &mut dst).await?;
    Ok(())
}

// ---------------------------------------------------------------------------
// 用例
// ---------------------------------------------------------------------------

#[tokio::test]
async fn tcp_proxy_roundtrip_through_real_wire_protocol() {
    let port = start_server(base_cfg()).await;
    let local = echo_service().await;

    let (mut conn, run_id) = login(port, TOKEN, "alice").await;
    let remote_port = free_port();
    let resp = register_proxy(
        &mut conn,
        NewProxy {
            proxy_name: "ssh".into(),
            proxy_type: "tcp".into(),
            remote_port,
            ..Default::default()
        },
    )
    .await;
    assert!(resp.error.is_empty(), "代理注册失败：{}", resp.error);
    // 这里传的是配置里的原始名 `ssh`，服务端的幂等兜底会把它补成全名 `alice.ssh`。
    // （真客户端会自己先发全名 —— 官方 frpc 的 `wireName` 就带前缀，别被它
    //  `proxy added: [ssh]` 那行日志骗了，那打的是配置原始名。）
    assert_eq!(
        resp.proxy_name, "alice.ssh",
        "注册表名字要带 `{{user}}.` 前缀"
    );

    spawn_provider(conn, port, run_id, local);

    // 用户 -> 公网端口 -> 服务端 -> 工作连接 -> 内网服务 -> 原路返回
    let echoed = roundtrip(
        SocketAddr::from(([127, 0, 0, 1], remote_port)),
        b"hello-frp",
    )
    .await;
    assert_eq!(echoed, b"hello-frp", "数据必须原样往返，不能被截断或改写");
}

#[tokio::test]
async fn wrong_token_is_rejected_at_handshake() {
    let port = start_server(base_cfg()).await;
    let stream = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    let r = conn::client_handshake(
        Box::pin(stream),
        WireVersion::V2,
        &rustunnel_common::security::Credential::Token("wrong-token".into()),
        "x",
        "",
        &empty_metas(),
        0,
        Default::default(),
    )
    .await;
    assert!(r.is_err(), "token 不对时必须握手失败，否则等于没有鉴权");
}

#[tokio::test]
async fn duplicate_remote_port_is_rejected() {
    let port = start_server(base_cfg()).await;

    let (mut conn_a, run_a) = login(port, TOKEN, "a").await;
    let remote = free_port();
    let first = register_proxy(
        &mut conn_a,
        NewProxy {
            proxy_name: "first".into(),
            proxy_type: "tcp".into(),
            remote_port: remote,
            ..Default::default()
        },
    )
    .await;
    assert!(first.error.is_empty(), "{:?}", first.error);
    tokio::spawn(async move { while conn_a.recv_msg().await.ok().flatten().is_some() {} });
    let _ = run_a;

    let (mut conn_b, _run_b) = login(port, TOKEN, "b").await;
    let second = register_proxy(
        &mut conn_b,
        NewProxy {
            proxy_name: "second".into(),
            proxy_type: "tcp".into(),
            remote_port: remote,
            ..Default::default()
        },
    )
    .await;
    assert!(
        second.error.contains("已被占用"),
        "同一个公网端口不能被两个代理抢占，实际返回：{:?}",
        second.error
    );
}

#[tokio::test]
async fn stcp_visitor_is_paired_with_provider() {
    let port = start_server(base_cfg()).await;
    let local = echo_service().await;

    // ---- provider：注册 stcp 代理，允许任何访客 ----
    let (mut provider, provider_run) = login(port, TOKEN, "provider").await;
    let resp = register_proxy(
        &mut provider,
        NewProxy {
            proxy_name: "secret".into(),
            proxy_type: "stcp".into(),
            sk: "my-secret".into(),
            allow_users: vec!["*".into()],
            ..Default::default()
        },
    )
    .await;
    assert!(resp.error.is_empty(), "stcp 注册失败：{}", resp.error);
    assert!(
        resp.remote_addr.is_empty(),
        "stcp 不占公网端口，remote_addr 应为空"
    );
    spawn_provider(provider, port, provider_run, local);

    // ---- visitor：按密钥签名发起接入 ----
    let (mut _visitor_ctrl, visitor_run) = login(port, TOKEN, "guest").await;
    // 控制连接要保持活着（run_id 要对得上），交给后台任务读着
    tokio::spawn(async move { while _visitor_ctrl.recv_msg().await.ok().flatten().is_some() {} });

    let stream = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    let (mut tunnel, leftover) =
        // frp 规则：visitor 的 serverName 要拼上前缀 —— 没写 `serverUser` 时用
        // **本客户端的 user**，这里 provider 的 user 是 "provider"。
        // 服务端存的监听器名就是 `provider.secret`（provider 登录时加的）。
        conn::client_visitor_conn(
            Box::pin(stream),
            WireVersion::V2,
            &visitor_run,
            "provider.secret",
            "my-secret",
        )
            .await
            .expect("visitor 接入");
    assert!(leftover.is_empty());

    tunnel.write_all(b"p2p-or-relay").await.unwrap();
    let mut buf = [0u8; 64];
    let n = tunnel.read(&mut buf).await.expect("读回显");
    assert_eq!(
        &buf[..n],
        b"p2p-or-relay",
        "visitor 到 provider 的链路必须通"
    );
}

#[tokio::test]
async fn stcp_visitor_with_wrong_secret_is_rejected() {
    let port = start_server(base_cfg()).await;

    let (mut provider, provider_run) = login(port, TOKEN, "provider").await;
    let resp = register_proxy(
        &mut provider,
        NewProxy {
            proxy_name: "secret".into(),
            proxy_type: "stcp".into(),
            sk: "real-secret".into(),
            allow_users: vec!["*".into()],
            ..Default::default()
        },
    )
    .await;
    assert!(resp.error.is_empty());
    tokio::spawn(async move { while provider.recv_msg().await.ok().flatten().is_some() {} });
    let _ = provider_run;

    let (_v, visitor_run) = login(port, TOKEN, "guest").await;
    let stream = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    // 名字按 frp 规则带上 provider 的 user 前缀，确保拒绝的原因是**密钥不对**，
    // 而不是"这个监听器不存在"
    let r = conn::client_visitor_conn(
        Box::pin(stream),
        WireVersion::V2,
        &visitor_run,
        "provider.secret",
        "wrong-secret",
    )
    .await;
    assert!(r.is_err(), "密钥不对时必须拒绝接入，否则 stcp 形同虚设");
}

/// SUDP 的 provider 侧模拟：工作连接上跑的是 `UdpPacket` 帧而不是裸字节，
/// 这里把收到的每个报文加 `echo:` 前缀、**按原访客地址**发回去 ——
/// 等价于一个内网 UDP 服务，只是省掉了真的去 bind 一个 UDP socket。
///
/// ⚠️ UDP / SUDP 的工作连接握手方向与 TCP **相反**：`StartWorkConn` 是客户端
/// 主动发的（见 `client/src/udp_proxy.rs`），服务端 `handle_work` 收到
/// `NewWorkConn` 后直接把连接丢进池子、**从不回** StartWorkConn。
/// 所以这里不能用 TCP 用的 `conn::client_work_conn`（它会阻塞等服务端那条）。
async fn serve_sudp_work_conn(
    port: u16,
    run_id: &str,
    proxy_name: &str,
    wire: WireVersion,
) -> anyhow::Result<()> {
    let stream = TcpStream::connect(("127.0.0.1", port)).await?;
    let ts = util::now_unix_secs() as i64;
    //
    // ★ 握手方向：工作连接由**服务端**下发 `StartWorkConn` 指定代理名，客户端等待。
    //   这一点对所有代理类型都一样（udp / sudp 也不例外）—— 曾经误以为 UDP 语义下
    //   是客户端主动发，于是把 SUDP 桥写成了"直接开搬"，真机上的症状是
    //   provider 侧报「期望 StartWorkConn，收到 UdpPacket」、上行有字节下行永远 0。
    //   这个用例就是为了锁住这个方向，别再改回去。
    let (stream, leftover, start) =
        conn::client_work_conn(Box::pin(stream), wire, run_id, TOKEN, ts).await?;
    // 服务端下发的一律是**线上全名**（`{user}.{name}`），本地才用原始 name。
    assert!(
        start.proxy_name.ends_with(&format!(".{proxy_name}")),
        "服务端必须用 StartWorkConn 指定这条工作连接服务哪个代理，实际是 {}",
        start.proxy_name
    );
    let mut work = FrpConn::new(stream, wire);
    // 服务端回完 StartWorkConn 就紧接着把 visitor 的第一帧发过来了，所以
    // leftover 通常**不为空** —— 必须塞回读缓冲，否则第一个业务报文被吞。
    work.push_leftover(leftover, false);
    // 编码必须跟服务端给 provider 这条连接设的一致（本例协商结果是 JSON）
    work.set_udp_codec(false);
    while let Ok(Some(msg)) = work.recv_msg().await {
        let FrpMessage::UdpPacket(pkt) = msg else {
            continue;
        };
        let Some(src) = pkt.remote_addr.as_ref().and_then(|a| a.to_socket()) else {
            continue;
        };
        let reply = format!("echo:{}", String::from_utf8_lossy(pkt.payload()));
        if work
            .send_msg(&FrpMessage::UdpPacket(UdpPacket::new(
                reply.as_bytes(),
                &src,
            )))
            .await
            .is_err()
        {
            break;
        }
    }
    Ok(())
}

#[tokio::test]
async fn sudp_visitor_relays_udp_frames_with_remote_addr() {
    let port = start_server(base_cfg()).await;

    // ---- provider：注册 sudp 代理（与 stcp 同一套 sk / allow_users 鉴权）----
    let (mut provider, provider_run) = login(port, TOKEN, "provider").await;
    let resp = register_proxy(
        &mut provider,
        NewProxy {
            proxy_name: "udpsvc".into(),
            proxy_type: "sudp".into(),
            sk: "udp-secret".into(),
            allow_users: vec!["*".into()],
            ..Default::default()
        },
    )
    .await;
    assert!(resp.error.is_empty(), "sudp 注册失败：{}", resp.error);
    assert!(
        resp.remote_addr.is_empty(),
        "sudp 不占公网端口，remote_addr 应为空"
    );

    // provider 的工作连接按 UDP 帧应答（不是裸字节转发，这正是 sudp 与 stcp 的分界线）
    tokio::spawn(async move {
        while let Ok(Some(msg)) = provider.recv_msg().await {
            if matches!(msg, FrpMessage::ReqWorkConn) {
                let run = provider_run.clone();
                tokio::spawn(async move {
                    if let Err(e) =
                        serve_sudp_work_conn(port, &run, "udpsvc", WireVersion::V2).await
                    {
                        eprintln!("SUDP 工作连接出错：{e:#}");
                    }
                });
            }
        }
    });

    // ---- visitor：按密钥签名接入 ----
    let (mut _visitor_ctrl, visitor_run) = login(port, TOKEN, "guest").await;
    tokio::spawn(async move { while _visitor_ctrl.recv_msg().await.ok().flatten().is_some() {} });

    let stream = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    let (tunnel, leftover) = conn::client_visitor_conn(
        Box::pin(stream),
        WireVersion::V2,
        &visitor_run,
        "provider.udpsvc",
        "udp-secret",
    )
    .await
    .expect("sudp visitor 接入");
    assert!(leftover.is_empty());

    let mut v = FrpConn::new(tunnel, WireVersion::V2);
    v.set_udp_codec(false);

    let peer: SocketAddr = "10.9.9.9:4321".parse().unwrap();
    v.send_msg(&FrpMessage::UdpPacket(UdpPacket::new(b"hello-udp", &peer)))
        .await
        .expect("发送 UdpPacket");

    // 回包必须带着**访客地址**原样回来：访问方要靠它把数据交回正确的对端，
    // 丢掉 remote_addr 的"能通"是假通——UDP 无连接，回包根本没法投递。
    let reply = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            match v.recv_msg().await {
                Ok(Some(FrpMessage::UdpPacket(pkt))) => break pkt,
                Ok(Some(_)) => continue, // Ping 之类跳过
                other => panic!("SUDP 读帧失败：{other:?}"),
            }
        }
    })
    .await
    .expect("SUDP 回包超时：服务端没有把 provider 的回包搬回 visitor");

    assert_eq!(
        reply.payload(),
        &b"echo:hello-udp"[..],
        "SUDP 报文必须双向贯通"
    );
    assert_eq!(
        reply.remote_addr.as_ref().and_then(|a| a.to_socket()),
        Some(peer),
        "回包必须带回访客地址，否则访问方无法把数据交回正确的对端"
    );
}

/// 测试用的 KCP 会话号。
///
/// 服务端按**源地址**区分会话（conv 只是该会话内的标识），所以多条流共用
/// 同一个 conv 不会串味 —— 真客户端也用固定 conv，靠 UDP 端口区分连接。
const KCP_CONV: u32 = 0x5A5A_0001;

/// 起一个服务端：TCP 在 `port`，**KCP 在独立的 `kport`**。
///
/// KCP 与 QUIC 的分工差别就在这一点上：QUIC 复用 `bindPort`，而 KCP 是裸 UDP
/// 上的可靠传输、没有"先握手再分流"的能力，只能另开端口靠源地址区分客户端
/// （对应官方 frps 的 `kcpBindPort`）。
async fn start_server_kcp(cfg: ServerConfig, port: u16) -> u16 {
    let listener = TcpListener::bind(("127.0.0.1", port))
        .await
        .expect("bind 指定端口");
    let registry = Arc::new(Registry::unlimited());
    tokio::spawn(async move {
        if let Err(e) = serve_on(listener, Arc::new(cfg), registry).await {
            eprintln!("服务端退出：{e:#}");
        }
    });
    tokio::time::sleep(Duration::from_millis(80)).await;
    port
}

/// 建一条 KCP 流：每条 frp 连接（控制 / 工作 / visitor）各占一条。
async fn kcp_stream(kaddr: SocketAddr) -> BoxStream {
    let sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.expect("绑定本地 UDP"));
    Box::pin(KcpStream::connect(sock, kaddr, KCP_CONV).await)
}

/// 在 KCP 传输上完成一次 frp v2 登录。
async fn login_kcp(kaddr: SocketAddr, token: &str, user: &str) -> (FrpConn, String) {
    let (conn, run_id, _udp_binary, _caps) = conn::client_handshake(
        kcp_stream(kaddr).await,
        WireVersion::V2,
        &rustunnel_common::security::Credential::Token(token.to_string()),
        "e2e-kcp-client",
        user,
        &empty_metas(),
        0,
        Default::default(),
    )
    .await
    .expect("KCP 上的 frp 握手");
    (conn, run_id)
}

/// 客户端侧的 KCP 工作连接：`NewWorkConn` -> `StartWorkConn` -> 连内网 -> 双向转发。
async fn serve_work_conn_kcp(
    kaddr: SocketAddr,
    run_id: &str,
    local: SocketAddr,
) -> anyhow::Result<()> {
    let ts = util::now_unix_secs() as i64;
    let (mut work, leftover, _start) =
        conn::client_work_conn(kcp_stream(kaddr).await, WireVersion::V2, run_id, TOKEN, ts).await?;
    let mut dst = TcpStream::connect(local).await?;
    if !leftover.is_empty() {
        dst.write_all(&leftover).await?;
    }
    util::relay_between(&mut work, &mut dst).await?;
    Ok(())
}

#[tokio::test]
async fn tcp_proxy_roundtrip_over_kcp_transport() {
    let port = free_port_both();
    let kport = free_port_both();
    let remote_port = free_port();
    let mut cfg = base_cfg();
    cfg.kcp_bind_port = Some(kport);
    start_server_kcp(cfg, port).await;
    let local = echo_service().await;
    let kaddr = SocketAddr::from(([127, 0, 0, 1], kport));

    // 控制连接走 KCP：验证 yamux / QUIC 之外的这条传输层也能跑完整 frp 握手
    let (mut conn, run_id) = login_kcp(kaddr, TOKEN, "kcpuser").await;
    let resp = register_proxy(
        &mut conn,
        NewProxy {
            proxy_name: "kcp".into(),
            proxy_type: "tcp".into(),
            remote_port,
            ..Default::default()
        },
    )
    .await;
    assert!(resp.error.is_empty(), "KCP 上注册代理失败：{}", resp.error);

    // provider 的工作连接也走 KCP（新本地端口 → 服务端的一条新会话）
    tokio::spawn(async move {
        while let Ok(Some(msg)) = conn.recv_msg().await {
            if matches!(msg, FrpMessage::ReqWorkConn) {
                let run = run_id.clone();
                tokio::spawn(async move {
                    if let Err(e) = serve_work_conn_kcp(kaddr, &run, local).await {
                        eprintln!("KCP 工作连接出错：{e:#}");
                    }
                });
            }
        }
    });

    let echoed = roundtrip(SocketAddr::from(([127, 0, 0, 1], remote_port)), b"over-kcp").await;
    assert_eq!(echoed, b"over-kcp", "KCP 传输上的代理数据必须原样往返");
}

#[tokio::test]
async fn http_vhost_routes_by_host_header() {
    // 内网放一个极简 HTTP 服务：无论什么请求都回 `pong:<path>`
    let local = {
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap();
        tokio::spawn(async move {
            while let Ok((mut s, _)) = l.accept().await {
                tokio::spawn(async move {
                    let mut buf = [0u8; 4096];
                    let n = s.read(&mut buf).await.unwrap_or(0);
                    let req = String::from_utf8_lossy(&buf[..n]).to_string();
                    let path = req.split_whitespace().nth(1).unwrap_or("/").to_string();
                    let body = format!("pong:{path}");
                    let resp = format!(
                        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                        body.len(),
                        body
                    );
                    let _ = s.write_all(resp.as_bytes()).await;
                });
            }
        });
        addr
    };

    let mut cfg = base_cfg();
    cfg.vhost_http_port = Some(free_port());
    let vhost_port = cfg.vhost_http_port.unwrap();
    let port = start_server(cfg).await;

    let (mut conn, run_id) = login(port, TOKEN, "web").await;
    let resp = register_proxy(
        &mut conn,
        NewProxy {
            proxy_name: "site".into(),
            proxy_type: "http".into(),
            custom_domains: vec!["demo.example.com".into()],
            ..Default::default()
        },
    )
    .await;
    assert!(resp.error.is_empty(), "http 注册失败：{}", resp.error);
    spawn_provider(conn, port, run_id, local);

    let mut s = TcpStream::connect(("127.0.0.1", vhost_port))
        .await
        .expect("连接 vhost 端口");
    let req = format!(
        "GET /api/test HTTP/1.1\r\nHost: demo.example.com:{}\r\nConnection: close\r\n\r\n",
        vhost_port
    );
    s.write_all(req.as_bytes()).await.unwrap();
    let mut raw = Vec::new();
    s.read_to_end(&mut raw).await.unwrap();
    let text = String::from_utf8_lossy(&raw).to_string();
    assert!(
        text.starts_with("HTTP/1.1 200 OK"),
        "期望 200，实际：{text}"
    );
    assert!(
        text.ends_with("pong:/api/test"),
        "路径必须透传给内网服务：{text}"
    );

    // 换个没注册的域名 -> 404
    let mut s2 = TcpStream::connect(("127.0.0.1", vhost_port)).await.unwrap();
    s2.write_all(
        format!(
            "GET / HTTP/1.1\r\nHost: unknown.example.com:{}\r\nConnection: close\r\n\r\n",
            vhost_port
        )
        .as_bytes(),
    )
    .await
    .unwrap();
    let mut raw2 = Vec::new();
    s2.read_to_end(&mut raw2).await.unwrap();
    let text2 = String::from_utf8_lossy(&raw2).to_string();
    assert!(
        text2.starts_with("HTTP/1.1 404"),
        "未注册域名应回 404：{text2}"
    );
}

/// QUIC 传输：同样的 frp 协议，跑在 QUIC 上而不是 TCP 上。
///
/// 这条用例证明 QUIC 真的能承载完整链路（控制连接 + 工作连接 + 数据往返），
/// 而不只是"能连上"。
#[tokio::test]
async fn tcp_proxy_roundtrip_over_quic_transport() {
    let cfg = ServerConfig {
        bind_addr: "127.0.0.1".into(),
        token: TOKEN.to_string(),
        transport_protocol: "quic".to_string(),
        ..Default::default()
    };
    // QUIC 是 UDP：端口号必须先确认 UDP 也能 bind（见 `free_port_both`）
    let port = start_server_on(cfg, free_port_both()).await;
    let local = echo_service().await;

    let (_endpoint, qconn, mut ctrl, run_id) = login_quic(port, TOKEN, "alice").await;
    let remote_port = free_port();
    let resp = register_proxy(
        &mut ctrl,
        NewProxy {
            proxy_name: "quic-ssh".into(),
            proxy_type: "tcp".into(),
            remote_port,
            ..Default::default()
        },
    )
    .await;
    assert!(resp.error.is_empty(), "代理注册失败：{}", resp.error);

    spawn_provider_quic(ctrl, qconn, run_id, local);

    let echoed = roundtrip(
        SocketAddr::from(([127, 0, 0, 1], remote_port)),
        b"hello-over-quic",
    )
    .await;
    assert_eq!(echoed, b"hello-over-quic", "QUIC 传输上的数据必须原样往返");
}

/// **回归**：同 group 的多个客户端共享同一个公网端口做负载均衡。
///
/// 冒烟时暴露的真问题：第二个成员也去 bind 同一个端口，必然
/// `Address already in use`，于是组里永远只剩一个后端 —— 参数配了、日志
/// 也报"注册失败"，但用户看到的只是"配了 group 却完全不均衡"。
///
/// 同时钉住第二件事：轮询到的后端必须让**它自己**的客户端去服务，
/// 也就是 `StartWorkConn` 里带的代理名得是那个成员的 `name`。
#[tokio::test]
async fn group_members_share_one_port_and_round_robin() {
    let (port, registry) = start_server_with_registry(base_cfg()).await;
    let local_a = tagged_echo_service("alice").await;
    let local_b = tagged_echo_service("bob").await;
    let remote_port = free_port();

    let (mut ctrl_a, run_a) = login(port, TOKEN, "alice").await;
    let resp_a = register_proxy(
        &mut ctrl_a,
        NewProxy {
            proxy_name: "alice.web-a".into(),
            proxy_type: "tcp".into(),
            remote_port,
            group: "web".into(),
            ..Default::default()
        },
    )
    .await;
    assert!(
        resp_a.error.is_empty(),
        "组里第一个成员注册失败：{}",
        resp_a.error
    );

    let (mut ctrl_b, run_b) = login(port, TOKEN, "bob").await;
    let resp_b = register_proxy(
        &mut ctrl_b,
        NewProxy {
            proxy_name: "bob.web-b".into(),
            proxy_type: "tcp".into(),
            remote_port,
            group: "web".into(),
            ..Default::default()
        },
    )
    .await;
    assert!(
        resp_b.error.is_empty(),
        "同 group 的第二个成员必须能共享端口，却被拒了：{}",
        resp_b.error
    );
    assert_eq!(
        registry.backend_count(remote_port),
        2,
        "两个成员都该成为这个端口上的后端"
    );

    spawn_provider(ctrl_a, port, run_a, local_a);
    spawn_provider(ctrl_b, port, run_b, local_b);

    // 轮询：连续几条连接必须把两个后端都轮到
    let target = SocketAddr::from(([127, 0, 0, 1], remote_port));
    let mut seen = std::collections::HashSet::new();
    for i in 0..4 {
        let reply = roundtrip(target, b"ping").await;
        let text = String::from_utf8_lossy(&reply).to_string();
        let tag = text.split(':').next().unwrap_or("").to_string();
        assert!(
            tag == "alice" || tag == "bob",
            "第 {i} 条连接拿到的回包不像我们的后端：{text:?}"
        );
        seen.insert(tag);
    }
    assert!(
        seen.contains("alice") && seen.contains("bob"),
        "4 条连接必须两个后端都轮到，实际只有 {seen:?} —— 负载均衡没生效"
    );
}

/// 健康探针必须**免鉴权**：k8s 的 liveness/readiness、docker 的
/// HEALTHCHECK、各类 LB 都带不了 Basic Auth，而它泄露的信息量为零。
///
/// 同时确认这**不是**把面板敞开 —— 其余端点仍然必须鉴权。
#[tokio::test]
async fn dashboard_healthz_is_public_but_other_paths_need_auth() {
    use base64::{engine::general_purpose::STANDARD, Engine as _};

    let dport = free_port();
    let cfg = ServerConfig {
        dashboard_port: Some(dport),
        dashboard_user: "admin".into(),
        dashboard_pwd: "s3cret".into(),
        ..base_cfg()
    };
    let _frp_port = start_server(cfg).await;
    let panel = SocketAddr::from(([127, 0, 0, 1], dport));

    assert_eq!(
        http_status(panel, "/api/healthz", None).await,
        200,
        "健康探针不该被鉴权拦住（探针带不了凭据）"
    );
    assert_eq!(
        http_status(panel, "/api/status", None).await,
        401,
        "状态接口必须鉴权，否则等于把面板敞开"
    );
    assert_eq!(
        http_status(panel, "/metrics", None).await,
        401,
        "指标含业务信息，必须鉴权（Prometheus 可以在采集配置里带 basic_auth）"
    );

    let cred = STANDARD.encode(b"admin:s3cret");
    assert_eq!(
        http_status(panel, "/api/status", Some(&cred)).await,
        200,
        "带上正确凭据应当能访问"
    );
    let wrong = STANDARD.encode(b"admin:guess");
    assert_eq!(
        http_status(panel, "/api/status", Some(&wrong)).await,
        401,
        "密码不对必须拒绝"
    );
}

// ---------------------------------------------------------------------------
// v1 线协议（官方默认协议）
// ---------------------------------------------------------------------------
//
// 为什么必须单独测：v1 与 v2 的差别不在"功能"上，而在**每一条字节的排布**上
// —— 有没有魔术字、长度是 8 字节 i64 还是 4 字节 u32、登录之后是 CFB 还是 AEAD。
// 功能测试全绿也证明不了这些：只要两端用的是同一套错误实现，自环测试照样过。
// 所以下面除了自环，还靠 `conn.rs` 里那条"盯着线上字节解密"的测试兜底。

/// v1 上跑完整的 tcp 隧道：登录 -> 注册 -> 工作连接 -> 数据往返。
#[tokio::test]
async fn tcp_proxy_roundtrip_over_wire_v1() {
    let port = start_server(base_cfg()).await;
    let local = echo_service().await;

    let (mut conn, run_id) = login_with(port, TOKEN, "alice", WireVersion::V1).await;
    assert_eq!(conn.version(), WireVersion::V1);
    assert!(conn.is_encrypted(), "v1 登录后控制通道必须已加密");

    let remote_port = free_port();
    let resp = register_proxy(
        &mut conn,
        NewProxy {
            proxy_name: "ssh".into(),
            proxy_type: "tcp".into(),
            remote_port,
            ..Default::default()
        },
    )
    .await;
    assert!(resp.error.is_empty(), "代理注册失败：{}", resp.error);
    assert_eq!(resp.proxy_name, "alice.ssh");

    spawn_provider_with(conn, port, run_id, local, WireVersion::V1);

    let echoed = roundtrip(SocketAddr::from(([127, 0, 0, 1], remote_port)), b"hello-v1").await;
    assert_eq!(echoed, b"hello-v1", "v1 上数据必须原样往返");
}

/// 同一个端口上 v1 与 v2 客户端必须能**共存**。
///
/// 官方 frps 就是靠魔术字自动分流（`wire.CheckMagic`），rustunnel-server 同理。
/// 这条测试的价值：证明"接到一个 frp 服务端上，不用问它支持哪一版"。
#[tokio::test]
async fn wire_v1_and_v2_coexist_on_one_port() {
    let port = start_server(base_cfg()).await;
    let local_v1 = tagged_echo_service("v1").await;
    let local_v2 = tagged_echo_service("v2").await;

    // 两条控制连接同时挂在一个端口上，各用一套协议
    let (mut c1, run1) = login_with(port, TOKEN, "one", WireVersion::V1).await;
    let (mut c2, run2) = login_with(port, TOKEN, "two", WireVersion::V2).await;

    let port1 = free_port();
    let resp1 = register_proxy(
        &mut c1,
        NewProxy {
            proxy_name: "p1".into(),
            proxy_type: "tcp".into(),
            remote_port: port1,
            ..Default::default()
        },
    )
    .await;
    assert!(resp1.error.is_empty(), "v1 注册失败：{}", resp1.error);

    let port2 = free_port();
    let resp2 = register_proxy(
        &mut c2,
        NewProxy {
            proxy_name: "p2".into(),
            proxy_type: "tcp".into(),
            remote_port: port2,
            ..Default::default()
        },
    )
    .await;
    assert!(resp2.error.is_empty(), "v2 注册失败：{}", resp2.error);

    spawn_provider_with(c1, port, run1, local_v1, WireVersion::V1);
    spawn_provider_with(c2, port, run2, local_v2, WireVersion::V2);

    // 后端会把 tag 前缀回显出来，所以看回包就能知道**这条链路走到了哪个后端**
    assert_eq!(
        roundtrip(SocketAddr::from(([127, 0, 0, 1], port1)), b"ping").await,
        b"v1:ping",
        "v1 通道应连到 v1 后端"
    );
    assert_eq!(
        roundtrip(SocketAddr::from(([127, 0, 0, 1], port2)), b"ping").await,
        b"v2:ping",
        "v2 通道应连到 v2 后端"
    );
}

/// 工作连接跟控制连接**协议不一致**时必须被拒。
///
/// 与官方 frps 的 `work connection wire protocol mismatch` 对齐。
/// 不挡的话，后面的 `StartWorkConn` 会用错误的容器发出去，
/// 对端只会看到一句难懂的解析错误，回头看日志根本不知道哪里配错了。
#[tokio::test]
async fn work_conn_wire_protocol_mismatch_is_rejected() {
    let port = start_server(base_cfg()).await;

    // 控制连接走 v1，工作连接故意走 v2
    let (_conn, run_id) = login_with(port, TOKEN, "alice", WireVersion::V1).await;

    let stream = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    let ts = util::now_unix_secs() as i64;
    let r = conn::client_work_conn(Box::pin(stream), WireVersion::V2, &run_id, TOKEN, ts).await;
    assert!(
        r.is_err(),
        "线协议对不上的工作连接必须被拒绝，否则会带着错误的容器一路错下去"
    );
}
