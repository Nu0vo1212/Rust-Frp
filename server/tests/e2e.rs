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
        msg::{FrpMessage, NewProxy, NewProxyResp},
    },
    util,
};
use rustunnel_server::{serve_on, Registry};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};

const TOKEN: &str = "e2e-token";

// ---------------------------------------------------------------------------
// 测试脚手架
// ---------------------------------------------------------------------------

/// 起一个真的服务端，返回它监听的端口。
async fn start_server(cfg: ServerConfig) -> u16 {
    start_server_with_registry(cfg).await.0
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

/// 完成一次 frp v2 登录，返回控制连接与服务端分配的 run_id。
async fn login(port: u16, token: &str, user: &str) -> (FrpConn, String) {
    let stream = TcpStream::connect(("127.0.0.1", port))
        .await
        .expect("连接服务端");
    let (conn, run_id, _udp_binary) =
        conn::client_handshake(Box::pin(stream), token, "e2e-client", user, 0)
            .await
            .expect("frp 握手");
    (conn, run_id)
}

/// 注册一个代理，返回服务端的应答。
///
/// 注意：注册期间服务端**可能**先插进来 ReqWorkConn（填池子），
/// 所以不能发完就死等 Resp，要边读边匹配，这也是真客户端的写法。
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
fn spawn_provider(mut conn: FrpConn, port: u16, run_id: String, local: SocketAddr) {
    tokio::spawn(async move {
        while let Ok(Some(msg)) = conn.recv_msg().await {
            if matches!(msg, FrpMessage::ReqWorkConn) {
                let run = run_id.clone();
                tokio::spawn(async move {
                    if let Err(e) = serve_work_conn(port, &run, local).await {
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
async fn serve_work_conn(port: u16, run_id: &str, local: SocketAddr) -> anyhow::Result<()> {
    let stream = TcpStream::connect(("127.0.0.1", port)).await?;
    let ts = util::now_unix_secs() as i64;
    let (mut work, leftover, _start) =
        conn::client_work_conn(Box::pin(stream), run_id, TOKEN, ts).await?;
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
    let (frp, run_id, _) = conn::client_handshake(stream, token, "e2e-quic", user, 0)
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
    assert_eq!(resp.proxy_name, "ssh");

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
    let r = conn::client_handshake(Box::pin(stream), "wrong-token", "x", "", 0).await;
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
        conn::client_visitor_conn(Box::pin(stream), &visitor_run, "secret", "my-secret")
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
    let r =
        conn::client_visitor_conn(Box::pin(stream), &visitor_run, "secret", "wrong-secret").await;
    assert!(r.is_err(), "密钥不对时必须拒绝接入，否则 stcp 形同虚设");
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
    let port = start_server(cfg).await;
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
