//! `serve` 模块的单元测试（拆分前内嵌于 `serve.rs`）。
//!
//! 职责：钉死配额 / 端口管控 / 脱敏文案 / 限流闸门 / 续传指纹 / 连接计数
//! 等可观测行为。
//!
//! 锁顺序契约：测试只使用 `Registry::unlimited()` / 独立信号量，
//! 不构造跨模块锁嵌套。
//!
//! 不变量：所有断言针对公开或 `pub(super)` 的内部函数，不改变业务可见性。

use std::{
    net::SocketAddr,
    sync::Arc,
    time::{Duration, Instant},
};

use anyhow::Result;
use nfrp_common::{
    config::ServerConfig,
    frp::{conn::FrpConn, msg::FrpMessage},
};

use crate::{
    pool::{ClientState, ConnSlot, CtrlCmd, PendingUser},
    registry::Registry,
};

use super::bridge::ConnGuard;
use super::control::proxy_signature;
use super::preauth::acquire_preauth_slot_with;
use super::register::register_proxy;
use super::work::{reject, reject_with};

/// 供单元测试构造 pending user 的辅助函数。
#[cfg(test)]
pub(crate) fn test_pending(proxy: &str, slot: Option<ConnSlot>) -> PendingUser {
    PendingUser {
        proxy: proxy.to_string(),
        proxy_type: "tcp".to_string(),
        client_user: "test".to_string(),
        client_run_id: "test-run".to_string(),
        use_encryption: false,
        use_compression: false,
        data_key: None,
        remote_port: 0,
        stream: Box::pin(tokio::io::empty()),
        peer: SocketAddr::from(([127, 0, 0, 1], 8080)),
        at: Instant::now(),
        slot,
        queue_permit: None,
        load: None,
    }
}

use super::*;
use crate::limits::Limit;
use crate::registry::ServerLimits;
use tokio::sync::mpsc;

fn client_with(conn_limit: Limit, registry: &Registry) -> Arc<ClientState> {
    let (tx, rx) = mpsc::unbounded_channel::<CtrlCmd>();
    std::mem::forget(rx);
    let (_, backlog, proxy) = registry.limits().per_client();
    Arc::new(ClientState::new(
        "run".into(),
        "id".into(),
        String::new(),
        tx,
        Duration::from_secs(60),
        Duration::from_secs(10),
        Default::default(),
        false,
        nfrp_common::frp::WireVersion::V1,
        conn_limit,
        backlog,
        0,
        proxy,
        "127.0.0.1".parse::<std::net::IpAddr>().unwrap(),
    ))
}

#[test]
fn limits_from_config_defaults_to_unlimited() {
    let cfg = ServerConfig::default();
    let l = limits_from(&cfg);
    assert_eq!(l.max_total_conns, 0, "默认必须保持向后兼容：不限制");
    assert_eq!(l.max_clients, 0);
}

/// characterization：`limits_from` 必须逐字段映射，不能漏项或串位。
#[test]
fn limits_from_映射全部上限字段() {
    let cfg = ServerConfig {
        max_total_conns: 7,
        max_clients: 3,
        max_conns_per_client: 11,
        max_pending_per_client: 5,
        max_proxies_per_client: 9,
        ..Default::default()
    };
    let l = limits_from(&cfg);
    assert_eq!(l.max_total_conns, 7);
    assert_eq!(l.max_clients, 3);
    assert_eq!(l.max_conns_per_client, 11);
    assert_eq!(l.max_pending_per_client, 5);
    assert_eq!(l.max_proxies_per_client, 9);
}

/// characterization：`reject` 的日志文案必须带上完整详情，并计入 visitor 拒绝数。
#[tokio::test]
async fn visitor_reject_文案带详情并计数() {
    let registry = Registry::unlimited();
    let (server_io, _peer_io) = tokio::io::duplex(4096);
    let mut conn = FrpConn::new(Box::pin(server_io), nfrp_common::frp::WireVersion::V1);
    let before = registry.metrics().visitor_rejected.get();

    let err = reject(&mut conn, "web", "代理名不存在".to_string(), &registry)
        .await
        .expect_err("reject 必须返回错误");
    assert_eq!(err.to_string(), "visitor 接入被拒绝：代理名不存在");
    assert_eq!(
        registry.metrics().visitor_rejected.get(),
        before + 1,
        "拒绝必须计数"
    );
}

/// characterization：`reject_with` 回给对端的只能是脱敏文案，详情留在错误里。
#[tokio::test]
async fn visitor_reject_with_对端只看脱敏文案() {
    let registry = Registry::unlimited();
    let (server_io, peer_io) = tokio::io::duplex(4096);
    let mut server = FrpConn::new(Box::pin(server_io), nfrp_common::frp::WireVersion::V1);
    let mut peer = FrpConn::new(Box::pin(peer_io), nfrp_common::frp::WireVersion::V1);

    let err = reject_with(
        &mut server,
        "web",
        "visitor connection of [web] user [alice] not allowed".to_string(),
        &registry,
        Some("visitor connection failed".to_string()),
    )
    .await
    .expect_err("必须拒绝");
    assert!(
        err.to_string().contains("user [alice] not allowed"),
        "日志详情必须保留：{err}"
    );

    match peer.recv_msg().await.expect("读取响应") {
        Some(FrpMessage::NewVisitorConnResp(resp)) => {
            assert_eq!(resp.proxy_name, "web");
            assert_eq!(
                resp.error, "visitor connection failed",
                "对端只能看到脱敏文案"
            );
        }
        _other => panic!("期望 NewVisitorConnResp"),
    }
}

/// characterization：未给脱敏文案时，`reject_with` 回给对端的就是原始详情。
#[tokio::test]
async fn visitor_reject_with_缺省回详情() {
    let registry = Registry::unlimited();
    let (server_io, peer_io) = tokio::io::duplex(4096);
    let mut server = FrpConn::new(Box::pin(server_io), nfrp_common::frp::WireVersion::V1);
    let mut peer = FrpConn::new(Box::pin(peer_io), nfrp_common::frp::WireVersion::V1);

    let err = reject_with(
        &mut server,
        "web",
        "server is busy: too many active connections".to_string(),
        &registry,
        None,
    )
    .await
    .expect_err("必须拒绝");
    assert!(err.to_string().contains("server is busy"));

    match peer.recv_msg().await.expect("读取响应") {
        Some(FrpMessage::NewVisitorConnResp(resp)) => {
            assert_eq!(resp.error, "server is busy: too many active connections");
        }
        _other => panic!("期望 NewVisitorConnResp"),
    }
}

/// C9-3 修复的回归锁：闸门排满后必须**排队超时放弃**，而不是无限等待。
#[tokio::test]
async fn 未认证闸门排满后排队超时放弃() {
    let gate = tokio::sync::Semaphore::new(1);
    let held = gate.acquire().await.expect("拿住唯一名额");
    let got = acquire_preauth_slot_with(&gate, Duration::from_millis(50)).await;
    assert!(got.is_none(), "排满时必须超时放弃");
    drop(held);
    let got2 = acquire_preauth_slot_with(&gate, Duration::from_millis(50)).await;
    assert!(got2.is_some(), "名额释放后应当立刻拿到");
}

// ---- allowPorts / maxPortsPerClient ----

fn tcp_proxy(name: &str, port: u16) -> nfrp_common::frp::msg::NewProxy {
    nfrp_common::frp::msg::NewProxy {
        proxy_name: name.to_string(),
        proxy_type: "tcp".to_string(),
        remote_port: port,
        ..Default::default()
    }
}

/// `allowPorts` 是安全项：白名单外的端口必须在**绑定之前**就被拒。
#[tokio::test]
async fn allow_ports_拦下白名单外的端口() {
    let registry = Arc::new(Registry::unlimited());
    let client = client_with(Limit::unlimited(), &registry);
    let cfg = Arc::new(ServerConfig {
        bind_addr: "127.0.0.1".into(),
        allow_ports: nfrp_common::config::parse_port_ranges("20000-30000,8443").unwrap(),
        ..Default::default()
    });

    // 22 不在白名单
    let err = register_proxy(&cfg, &registry, &client, &tcp_proxy("sshd", 22))
        .await
        .expect_err("白名单外的端口必须被拒")
        .to_string();
    assert!(err.contains("allowPorts"), "错误里要点名配置项：{err}");
    assert!(err.contains("22"), "错误里要带上是哪个端口：{err}");
    assert!(err.contains("20000-30000"), "错误里要带上允许范围：{err}");

    // 30001 刚好越过上界
    assert!(
        register_proxy(&cfg, &registry, &client, &tcp_proxy("p", 30001))
            .await
            .is_err()
    );
    // 8443 是 single 项，必须算数
    assert!(cfg.port_allowed(8443));
}

/// 白名单**内**的端口不能被这道闸拦下 —— 它应该一路走到"真的去 bind"。
/// 这里把 `bind_addr` 故意写成一个解析不了的地址，于是错误一定是"解析失败"，
/// 从而能确定地证明 allowPorts 这一关放行了（不依赖任何"空闲端口"的运气）。
#[tokio::test]
async fn allow_ports_放行白名单内的端口() {
    let registry = Arc::new(Registry::unlimited());
    let client = client_with(Limit::unlimited(), &registry);
    let cfg = Arc::new(ServerConfig {
        bind_addr: "300.300.300.300".into(),
        allow_ports: nfrp_common::config::parse_port_ranges("20000-30000").unwrap(),
        ..Default::default()
    });

    let err = register_proxy(&cfg, &registry, &client, &tcp_proxy("ok", 25000))
        .await
        .expect_err("地址解析不了，后面必然失败")
        .to_string();
    assert!(
        !err.contains("allowPorts"),
        "白名单内的端口不该被 allowPorts 拦下：{err}"
    );
    assert!(err.contains("解析"), "应该走到解析地址那一步：{err}");
}

/// `maxPortsPerClient`：按**端口数**（不是代理数）封顶。
#[tokio::test]
async fn max_ports_per_client_按端口数封顶() {
    let registry = Arc::new(Registry::unlimited());
    let client = client_with(Limit::unlimited(), &registry);
    let cfg = Arc::new(ServerConfig {
        bind_addr: "300.300.300.300".into(),
        max_ports_per_client: 2,
        ..Default::default()
    });

    // 先手工占掉 2 个端口（注册内存里的条目就够，不必真的 bind）
    for (i, name) in ["a", "b"].iter().enumerate() {
        let slot = client.reserve_proxy().expect("名额充足");
        client.add_proxy(name.to_string(), Some(20000 + i as u16), slot);
    }
    assert_eq!(client.ports_used(), 2);

    let err = register_proxy(&cfg, &registry, &client, &tcp_proxy("c", 20099))
        .await
        .expect_err("已经占满 2 个端口，第 3 个必须被拒")
        .to_string();
    assert!(err.contains("maxPortsPerClient"), "{err}");
    assert!(err.contains("2 个端口"), "错误里要说明已占用几个：{err}");
}

/// 上限为 0 = 不限制（默认），不能误伤。
#[tokio::test]
async fn max_ports_per_client_为零时不限制() {
    let registry = Arc::new(Registry::unlimited());
    let client = client_with(Limit::unlimited(), &registry);
    let cfg = Arc::new(ServerConfig {
        bind_addr: "300.300.300.300".into(),
        ..Default::default()
    });

    for i in 0..5 {
        let slot = client.reserve_proxy().expect("名额充足");
        client.add_proxy(format!("p{i}"), Some(21000 + i), slot);
    }
    let err = register_proxy(&cfg, &registry, &client, &tcp_proxy("more", 21099))
        .await
        .expect_err("地址解析不了")
        .to_string();
    assert!(!err.contains("maxPortsPerClient"), "0 语义是不限制：{err}");
}

/// `remote_port = 0` 时优先报"必须指定 remote_port"，而不是
/// 那句让人摸不着头脑的"端口 0 不在白名单内"。
#[tokio::test]
async fn 没填端口时报的是必须指定而不是白名单() {
    let registry = Arc::new(Registry::unlimited());
    let client = client_with(Limit::unlimited(), &registry);
    let cfg = Arc::new(ServerConfig {
        allow_ports: nfrp_common::config::parse_port_ranges("20000-30000").unwrap(),
        ..Default::default()
    });

    let err = register_proxy(&cfg, &registry, &client, &tcp_proxy("noport", 0))
        .await
        .expect_err("没端口必须被拒")
        .to_string();
    assert!(err.contains("remote_port"), "{err}");
    assert!(!err.contains("allowPorts"), "{err}");
}

/// `detailedErrorsToClient = false` 时回给客户端的必须是短句，
/// 不能把"域名已被代理 xxx 占用"这类**别人的代理名**泄露出去。
#[test]
fn 关闭详细错误后回给客户端的是短句() {
    let mut cfg = ServerConfig::default();
    assert!(cfg.detailed_errors_to_client, "官方默认是 true");
    let summary = "new proxy [alice.web] error";
    let detail = "域名 web.example.com 的路径已被代理 bob.web 占用";
    assert_eq!(cfg.error_to_client(summary, detail), detail);

    cfg.detailed_errors_to_client = false;
    assert_eq!(cfg.error_to_client(summary, detail), summary);
    assert_eq!(
        cfg.error_to_client("invalid ping", "签名过期"),
        "invalid ping"
    );
}

#[test]
fn admit_user_without_slot_is_dropped_and_counted() {
    let registry = Arc::new(Registry::unlimited());
    let client = client_with(Limit::new(1), &registry);
    // 先把唯一的客户端连接配额占住
    let held = client.try_acquire_conn().expect("占住");
    let before = registry.metrics().conns_rejected.get();

    admit_user(test_pending("ssh", None), &client, &registry);
    assert_eq!(
        registry.metrics().conns_rejected.get(),
        before + 1,
        "没有配额的连接必须被拒绝并计数"
    );
    assert_eq!(
        registry.metrics().conns_total.get(),
        0,
        "被拒的连接不该计入"
    );
    drop(held);
}

#[test]
fn admit_user_over_backlog_is_dropped() {
    let limits = ServerLimits {
        max_pending_per_client: 1,
        ..Default::default()
    };
    let registry = Arc::new(Registry::new(limits));
    let client = client_with(Limit::unlimited(), &registry);

    admit_user(
        test_pending("a", Some(ConnSlot::default())),
        &client,
        &registry,
    );
    assert_eq!(client.backlog(), 1);
    admit_user(
        test_pending("b", Some(ConnSlot::default())),
        &client,
        &registry,
    );
    assert_eq!(client.backlog(), 1, "队列满了之后不能再入队");
    assert_eq!(registry.metrics().conns_rejected.get(), 1);
}

#[test]
fn admit_user_queues_when_no_idle_work_conn() {
    let registry = Arc::new(Registry::unlimited());
    let client = client_with(Limit::unlimited(), &registry);
    admit_user(
        test_pending("ssh", Some(ConnSlot::default())),
        &client,
        &registry,
    );
    assert_eq!(client.backlog(), 1);
    assert_eq!(registry.metrics().conns_total.get(), 1);
    assert_eq!(registry.metrics().conns_rejected.get(), 0);
}

/// 只有 `nfrp` 自研协议会被拒；v1 / v2 都放行 ——
/// 服务端本来就按魔术字自动识别对端，同一端口同时服务两种客户端。
#[test]
fn ensure_protocol_allows_both_frp_wire_versions() {
    use nfrp_common::config::Protocol;
    // 默认就是 frp-v1（跟随官方 frpc 的默认值）
    let mut cfg = ServerConfig::default();
    assert_eq!(cfg.protocol, Protocol::FrpV1);
    assert!(ensure_protocol(&cfg).is_ok());

    cfg.protocol = Protocol::FrpV2;
    assert!(ensure_protocol(&cfg).is_ok(), "v2 也必须被接受");

    cfg.protocol = Protocol::NFrp;
    assert!(ensure_protocol(&cfg).is_err());
}

/// 续传复用指纹必须**跨 HashMap 插入顺序**稳定。
///
/// 这是真机上会踩的坑：`metas` / `headers` 是 `HashMap`，直接
/// `serde_json::to_string` 两次可能得到不同顺序 —— 指纹一变就不复用，
/// 下一步重新 bind 报 `Address already in use`，而用户配置根本没改。
#[test]
fn 续传指纹跨_map_插入顺序稳定() {
    use std::collections::HashMap;
    let mut a = tcp_proxy("web", 28080);
    let mut m1 = HashMap::new();
    m1.insert("b".to_string(), "2".to_string());
    m1.insert("a".to_string(), "1".to_string());
    a.metas = m1;
    let mut h1 = HashMap::new();
    h1.insert("X-B".to_string(), "2".to_string());
    h1.insert("X-A".to_string(), "1".to_string());
    a.headers = h1;

    let mut b = tcp_proxy("web", 28080);
    let mut m2 = HashMap::new();
    m2.insert("a".to_string(), "1".to_string());
    m2.insert("b".to_string(), "2".to_string());
    b.metas = m2;
    let mut h2 = HashMap::new();
    h2.insert("X-A".to_string(), "1".to_string());
    h2.insert("X-B".to_string(), "2".to_string());
    b.headers = h2;

    assert_eq!(proxy_signature(&a), proxy_signature(&b));

    // 改端口 / 改密钥必须变，不能误复用旧监听器。
    let mut c = b.clone();
    c.remote_port = 28081;
    assert_ne!(proxy_signature(&a), proxy_signature(&c));
    let mut d = b.clone();
    d.sk = "other-secret".into();
    assert_ne!(proxy_signature(&a), proxy_signature(&d));
}

// ==================================================================
// 活跃连接计数必须收支平衡
//
// 审计找出**四处**同类问题（重复 inc / 无条件 dec / 两处 `?` 漏 dec），
// 但它们其实是**同一个 bug 的四个表现**：
// "配对的 +1 与结束的 -1 分散在两处，中间任何提前返回都会漏掉 -1"。
// 修法用 RAII 把 -1 绑到作用域上 —— 下面这几条锁住这个不变量。
// ==================================================================

/// 守卫创建 +1、离开作用域 -1（**无论怎么离开**）。
#[test]
fn 连接守卫必须收支平衡() {
    let r = Registry::unlimited();
    assert_eq!(r.metrics().conns_active.get(), 0, "起点为 0");

    {
        let _g = ConnGuard::new(&r);
        assert_eq!(r.metrics().conns_active.get(), 1, "建守卫后 +1");
    }
    assert_eq!(r.metrics().conns_active.get(), 0, "离开作用域必须 -1");

    // 嵌套多个也一样
    let g1 = ConnGuard::new(&r);
    let g2 = ConnGuard::new(&r);
    assert_eq!(r.metrics().conns_active.get(), 2);
    drop(g1);
    assert_eq!(r.metrics().conns_active.get(), 1, "只减自己那一份");
    drop(g2);
    assert_eq!(r.metrics().conns_active.get(), 0);
}

/// **提前返回（`?` 路径）也必须把计数还回来**。
///
/// 这是原先漏 dec 的那两条路径的等价物：函数在守卫建好之后、
/// `finish_conn` 之前就 return 了。
#[test]
fn 提前返回也要归还计数() {
    let r = Registry::unlimited();

    fn early_return(r: &Registry) -> Result<()> {
        let _g = ConnGuard::new(r);
        // 模拟 `send_msg(...).context(...)?` 失败提前返回
        anyhow::bail!("模拟发送 StartWorkConn 失败");
    }

    assert!(early_return(&r).is_err());
    assert_eq!(
        r.metrics().conns_active.get(),
        0,
        "提前返回绝不能漏掉 -1（M7 的核心）"
    );
}

/// 流量统计同样由守卫记账（成功路径）。
#[test]
fn 守卫要记账流量() {
    let r = Registry::unlimited();
    {
        let g = ConnGuard::new(&r);
        g.record_bytes(1234, 5678);
    }
    assert_eq!(r.metrics().bytes_up.get(), 1234);
    assert_eq!(r.metrics().bytes_down.get(), 5678);
}
