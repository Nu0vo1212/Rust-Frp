//! 虚拟主机监听生命周期。
//!
//! 职责：`bind` 绑定端口、`run_vhost` 的 accept 循环（含数据面 ACL 判定）、
//! `VhostOpts` 运行期选项，以及按 `VhostKind` 把每条连接交给对应的协议处理函数。
//!
//! 锁顺序契约：本模块不持有长生命周期锁；每轮 accept 先读 `Registry` 的
//! 安全上下文与审计记录器（短锁/原子量），再 `clone` 出 `Arc` 交给 spawn 的
//! 任务。`VhostTable` 的锁只在具体协议处理函数内部短暂持有，且不在
//! `Registry` 锁内获取 —— 顺序恒为「先 Registry，后 VhostTable」，从不反向。
//!
//! 不变量：`port` / `opts` 在一次 `run_vhost` 生命周期内不变；被 ACL 拒绝的
//! 连接静默关闭、绝不进入协议处理；端口 / accept 错误只记日志并退避重试，
//! 不让 accept 循环退出。写者只有 `run_vhost` 的本地状态，`VhostOpts` 创建后只读。

use std::{net::SocketAddr, sync::Arc, time::Duration};

use anyhow::{Context, Result};
use tokio::net::{TcpListener, TcpStream};
use tracing::{debug, info, warn};

use crate::registry::Registry;

use super::{
    http::handle_http,
    https::handle_https,
    router::{VhostKind, VhostTable},
    tcpmux::handle_tcpmux,
};

// ---------------------------------------------------------------------------
// 监听
// ---------------------------------------------------------------------------
pub async fn bind(addr: SocketAddr) -> Result<TcpListener> {
    TcpListener::bind(addr)
        .await
        .with_context(|| format!("监听 {addr} 失败"))
}

/// 三种虚拟主机共用的运行期选项。
///
/// 早先 `run_vhost` 只有一个 `tcpmux_passthrough: bool`，再加参数就要破 7 个了；
/// 更重要的是**这些值全都来自 `ServerConfig`**，聚成一个结构体后新增配置项
/// 不必再改一路的函数签名。
#[derive(Clone)]
pub struct VhostOpts {
    pub kind: VhostKind,
    /// 只有 [`VhostKind::TcpMux`] 用得上。
    pub tcpmux_passthrough: bool,
    /// 等待内网服务**响应头**的超时（官方 `vhostHTTPTimeout`）。`None` = 不限。
    pub http_timeout: Option<Duration>,
    /// 自定义 404 页面的内容（官方 `custom404Page`）。`None` = 用内置提示。
    ///
    /// 启动时**读一次**常驻内存，而不是每个 404 都去读盘：这个文件在请求路径上，
    /// 每次都 read_file 等于给了一个"用磁盘 IO 拖垮服务端"的入口。
    pub not_found_page: Option<Arc<Vec<u8>>>,
}

impl VhostOpts {
    pub fn new(kind: VhostKind, tcpmux_passthrough: bool) -> Self {
        Self {
            kind,
            tcpmux_passthrough,
            http_timeout: None,
            not_found_page: None,
        }
    }

    pub fn with_timeout(mut self, t: Option<Duration>) -> Self {
        self.http_timeout = t;
        self
    }

    pub fn with_not_found_page(mut self, page: Option<Arc<Vec<u8>>>) -> Self {
        self.not_found_page = page;
        self
    }
}

/// HTTP vhost 主循环。
/// HTTP / HTTPS / tcpmux 共用的 accept 循环。
pub async fn run_vhost(
    listener: TcpListener,
    table: Arc<VhostTable>,
    port: u16,
    opts: VhostOpts,
    registry: Arc<Registry>,
) {
    let kind = opts.kind;
    info!("{} 虚拟主机已启动，监听 :{port}", kind.label());
    loop {
        match listener.accept().await {
            Ok((stream, peer)) => {
                // ★★ v0.5.8 修（第七轮审计 F7-1，中危）：**数据面也要过 ACL**。
                //
                // 与 `serve.rs::proxy_accept_loop` 同一处修复：vhost 端口
                // （http / https / tcpmux）同样是承载用户流量的数据面，
                // 原先只挂 Basic Auth / SNI 路由，**完全没有 ACL 判定**。
                //
                // 拒绝时静默关连接（不回 403）：对陌生访客不该泄露
                // "你的 IP 被 ACL 拒了"这种可区分信息 —— 与
                // `handle_frp_stream` 那边回统一文案是同一个理由。
                let sec = registry.security();
                if let Err(reason) = sec.check_ip(peer.ip()) {
                    registry.audit().record(
                        crate::audit::AuditEvent::new(crate::audit::kind::LOGIN_DENIED, false)
                            .ip(peer.ip().to_string())
                            .detail(format!("{reason}（{} 端口 {port} 数据面）", kind.label())),
                    );
                    debug!(%peer, kind = kind.label(), "数据面 IP 访问控制拒绝：{reason}");
                    continue;
                }
                let table = table.clone();
                let registry = registry.clone();
                let opts = opts.clone();
                tokio::spawn(async move {
                    if let Err(e) = handle_conn(stream, peer, table, port, opts, registry).await {
                        debug!(%peer, kind = kind.label(), "vhost 连接结束：{e:#}");
                    }
                });
            }
            Err(e) => {
                warn!("vhost accept 失败：{e}");
                tokio::time::sleep(Duration::from_millis(200)).await;
            }
        }
    }
}

async fn handle_conn(
    visitor: TcpStream,
    peer: SocketAddr,
    table: Arc<VhostTable>,
    port: u16,
    opts: VhostOpts,
    registry: Arc<Registry>,
) -> Result<()> {
    visitor.set_nodelay(true).ok();
    match opts.kind {
        VhostKind::Https => handle_https(visitor, peer, table, port, registry).await,
        VhostKind::Http => handle_http(visitor, peer, table, port, opts, registry).await,
        VhostKind::TcpMux => {
            handle_tcpmux(visitor, peer, table, opts.tcpmux_passthrough, registry).await
        }
    }
}
#[cfg(test)]
mod tests {
    //! accept 分支的数据面 ACL 回归（含一条「不配 ACL 必须放行」的对照）。
    //!
    //! 注意：`acl_必须铺满全部数据面入口` 这条源码扫描测试跨模块，放在 `tests.rs`。

    use super::*;
    use crate::vhost::router::tests::{route, table_with};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    // -----------------------------------------------------------------------
    // 第七轮审计 F7-1：数据面也要过 ACL
    // -----------------------------------------------------------------------

    /// ★★ v0.5.8 回归（第七轮审计 F7-1，中危）：
    /// **vhost 端口（http / https / tcpmux）必须做 IP 白/黑名单判定。**
    ///
    /// # 原先的漏洞
    ///
    /// `SecurityContext::check_ip` 全仓只有 2 处调用（控制连接握手 + vnet 注册），
    /// **承载用户流量的数据面一处都没有**。实测（`tmp/audit7/f/acl_dataplane_v3.py`）：
    /// 同一服务端、同一份 `deny = ["127.0.0.1"]`，控制面被正确拒绝，
    /// 而公网端口**照常把该来源的流量转给后端**。
    ///
    /// # 这条测试测什么
    ///
    /// 直接测 `run_vhost` 的 accept 分支所用的那份判定 —— 用一个真实监听器
    /// 起 vhost，从被 deny 的地址连进去，断言**连接被关且后端从未被调用**。
    ///
    /// 注意：这里刻意**不**只断言"连接断了" —— 断连可能是别的错误造成的。
    /// 必须同时断言**后端没有被触达**（`AtomicUsize` 计数为 0），
    /// 否则这条测试会变成"恒真"：任何启动失败都会让它通过。
    #[tokio::test]
    async fn vhost_数据面必须过_ip_白黑名单() {
        use crate::guard::SecurityContext;
        use nfrp_common::security::AclConfig;
        use std::sync::atomic::{AtomicUsize, Ordering};

        // 一个"后端服务"：只用来证明连接有没有被放行到转发阶段
        let hits = Arc::new(AtomicUsize::new(0));
        let backend = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let backend_port = backend.local_addr().unwrap().port();
        let _ = backend_port;
        {
            let hits = hits.clone();
            tokio::spawn(async move {
                while let Ok((mut s, _)) = backend.accept().await {
                    hits.fetch_add(1, Ordering::SeqCst);
                    let _ = s.shutdown().await;
                }
            });
        }

        // 路由表：一个 http 代理指向那个后端
        let table = Arc::new(table_with(vec![route(
            "blocked",
            "blocked.example.com",
            &["/"],
            VhostKind::Http,
        )]));

        // ★ 服务端安全上下文：deny 掉 127.0.0.1（本机测试的源地址就是它）
        let scfg = nfrp_common::config::ServerConfig {
            acl: AclConfig {
                allow: vec![],
                deny: vec!["127.0.0.1".to_string()],
            },
            ..Default::default()
        };
        // 走**生产同一条**构造路径，避免测试用一套、线上用另一套
        let sec = Arc::new(SecurityContext::from_config(&scfg).expect("安全上下文"));

        // 注册表：挂上这份安全上下文（`run_vhost` 从 registry 取它）
        let registry = Arc::new(Registry::unlimited());
        registry.set_security(sec);

        // 起一个真的 vhost 监听器
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let vhost_addr = listener.local_addr().unwrap();
        {
            let table = table.clone();
            let registry = registry.clone();
            tokio::spawn(async move {
                run_vhost(
                    listener,
                    table,
                    vhost_addr.port(),
                    VhostOpts::new(VhostKind::Http, false),
                    registry,
                )
                .await;
            });
        }
        // 等监听器就绪
        for _ in 0..50 {
            if tokio::net::TcpStream::connect(vhost_addr).await.is_ok() {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }

        // ★ 就绪等待：ACL 会把**确认连接也拦掉**，所以"能连上"不能当就绪判据
        //   （本用例第一版就卡在这里：探测连接被立即关闭 ⇒ 循环永远不 break）。
        //   改成直接重试"连上并发请求、看是否被立刻关闭"，最多等 2 秒。
        let mut closed_fast = false;
        let mut what = String::from("未建立连接");
        for _ in 0..100 {
            let Ok(mut c) = tokio::net::TcpStream::connect(vhost_addr).await else {
                tokio::time::sleep(std::time::Duration::from_millis(20)).await;
                continue;
            };
            let _ = c
                .write_all(b"GET / HTTP/1.1\r\nHost: blocked.example.com\r\n\r\n")
                .await;
            let t0 = std::time::Instant::now();
            let mut d = [0u8; 64];
            let r =
                tokio::time::timeout(std::time::Duration::from_millis(400), c.read(&mut d)).await;
            let ms = t0.elapsed().as_millis();
            match r {
                Ok(Ok(0)) => {
                    closed_fast = true;
                    what = format!("{ms}ms EOF");
                    break;
                }
                Ok(Err(e)) => {
                    closed_fast = true;
                    what = format!("{ms}ms 重置 {e}");
                    break;
                }
                Ok(Ok(n)) => {
                    closed_fast = false;
                    what = format!("{ms}ms 读到 {n} 字节（未被拦截）");
                    break;
                }
                Err(_) => {
                    // 超时 ⇒ 连接被交给 HTTP 处理、还开着 ⇒ ACL 没生效
                    closed_fast = false;
                    what = format!("{ms}ms 超时（连接未关闭，未被拦截）");
                    break;
                }
            }
        }

        assert_eq!(
            hits.load(Ordering::SeqCst),
            0,
            "被 ACL 拒绝的来源不应该到达转发阶段（后端被触达说明数据面没做 ACL）"
        );
        assert!(
            closed_fast,
            "被 ACL 拒绝时服务端应立即关闭连接 —— 实际 {what}，\
         说明 accept 分支没做 ACL 判定（连接被交给了 HTTP 处理）"
        );
    }

    /// 对照用例：**不配 ACL** 时，同一个 vhost 的 accept 分支必须**放行**连接。
    ///
    /// 没有这条，"上面那条测试"就无法排除"vhost 本来就连接不上"
    /// 这种恒真的解释 —— 与 `handle_frp_stream` 那边"基线必须通过"同理。
    ///
    /// ★ 断言口径刻意选在 **accept 是否放行**这一层，而不是"后端是否收到请求"：
    ///   后者会把"路由没匹配上""后端没接上"一并算进来，测试就失去区分力
    ///   （本用例第一版正是因此假失败 —— 路由目标压根没连到那个后端）。
    ///   这里直接看：空 ACL 时 `check_ip` 必须**通过**，被 deny 时必须**拒绝**，
    ///   用生产同一条 `from_config` 构造出的上下文来判。
    #[tokio::test]
    async fn vhost_不配_acl_时放行而配置_deny_时拦截() {
        use crate::guard::SecurityContext;
        use nfrp_common::security::AclConfig;

        // 空 ACL ⇒ 放行
        let empty = nfrp_common::config::ServerConfig::default();
        let sec_open = SecurityContext::from_config(&empty).expect("安全上下文");
        assert!(
            sec_open.check_ip("127.0.0.1".parse().unwrap()).is_ok(),
            "不配 ACL 时不应拦截任何来源（否则修复改变了默认行为）"
        );

        // deny 127.0.0.1 ⇒ 拒绝
        let denied = nfrp_common::config::ServerConfig {
            acl: AclConfig {
                allow: vec![],
                deny: vec!["127.0.0.1".to_string()],
            },
            ..Default::default()
        };
        let sec_deny = SecurityContext::from_config(&denied).expect("安全上下文");
        assert!(
            sec_deny.check_ip("127.0.0.1".parse().unwrap()).is_err(),
            "deny 命中时必须拒绝"
        );
        assert!(
            sec_deny.check_ip("10.1.2.3".parse().unwrap()).is_ok(),
            "deny 未命中的来源仍须放行（黑名单不是白名单）"
        );

        // allow 白名单 ⇒ 只有名单内放行（这是 ACL 最容易被写反的方向）
        let allowed = nfrp_common::config::ServerConfig {
            acl: AclConfig {
                allow: vec!["10.0.0.0/8".to_string()],
                deny: vec![],
            },
            ..Default::default()
        };
        let sec_allow = SecurityContext::from_config(&allowed).expect("安全上下文");
        assert!(
            sec_allow.check_ip("10.1.2.3".parse().unwrap()).is_ok(),
            "白名单内的来源必须放行"
        );
        assert!(
            sec_allow.check_ip("192.168.1.1".parse().unwrap()).is_err(),
            "白名单外的来源必须拒绝"
        );
    }
}
