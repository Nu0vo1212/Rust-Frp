//! 客户端侧的**健康检查**。
//!
//! frp 的健康检查由 frpc 自己做：它比谁都清楚内网服务是不是还活着。
//! 判定不健康之后这里采取的做法是**停止为该代理提供工作连接** ——
//! 服务端随后建工作连接会被直接拒掉，用户侧表现为连不上，
//! 而不是连上一个"黑洞"。探测恢复后自动重新服务，无需重启。
//!
//! 之所以不主动注销代理：注销要等服务端确认，期间用户照样会被分到这个
//! 坏后端；而"拒绝工作连接"是即时生效的，恢复也同样即时。

use std::{collections::HashMap, sync::Arc, time::Duration};

use nfrp_common::{config::ClientConfig, util};
use tokio::{io::AsyncWriteExt, net::TcpStream};
use tracing::{info, warn};

/// 一次探测的结果记录。
#[derive(Debug, Clone, Copy, Default)]
struct State {
    healthy: bool,
    consecutive_failures: u32,
}

impl State {
    /// 初始状态是健康的：刚启动就判死会让所有代理在第一次探测前不可用。
    fn new() -> Self {
        Self {
            healthy: true,
            consecutive_failures: 0,
        }
    }
}

/// 全进程共享的健康状态表。
pub struct Monitor {
    states: std::sync::Mutex<HashMap<String, State>>,
}

impl Monitor {
    /// 按配置启动探测任务；没有配健康检查的代理不会出现在表里。
    pub fn start(cfg: &ClientConfig) -> Arc<Self> {
        let m = Arc::new(Self {
            states: std::sync::Mutex::new(HashMap::new()),
        });
        for p in &cfg.proxies {
            if p.health_check_type.is_empty() {
                continue;
            }
            // 键用**配置里的原始 `name`**（不带 `{user}.` 前缀）。
            // 服务端回包里的名字前缀策略各实现不一致，统一在这里剥掉再查。
            let wire = p.name.clone();
            m.lock().insert(wire.clone(), State::new());

            let mon = m.clone();
            let p = p.clone();
            let interval = Duration::from_secs(p.health_check_interval_s.max(1));
            let timeout = Duration::from_secs(p.health_check_timeout_s.max(1));
            tokio::spawn(async move {
                info!(proxy = %p.name, kind = %p.health_check_type, "健康检查已启动");
                loop {
                    tokio::time::sleep(interval).await;
                    let ok = match p.health_check_type.as_str() {
                        "http" => {
                            probe_http(
                                &p.local_addr,
                                &p.health_check_url,
                                &p.health_check_http_headers,
                                timeout,
                            )
                            .await
                        }
                        _ => probe_tcp(&p.local_addr, timeout).await,
                    };
                    mon.record(&wire, &p.name, ok, p.health_check_max_failed.max(1));
                }
            });
        }
        Arc::clone(&m)
    }

    /// 该代理现在能提供服务吗？没配健康检查的永远返回 true。
    pub fn is_healthy(&self, proxy: &str) -> bool {
        self.lock().get(proxy).map(|s| s.healthy).unwrap_or(true)
    }

    /// 记录一次探测结果；**只在状态翻转时打日志**，否则日志会被探测刷屏。
    fn record(&self, wire: &str, name: &str, ok: bool, max_failed: u32) {
        let mut g = self.lock();
        let st = g.entry(wire.to_string()).or_default();
        let was = st.healthy;
        if ok {
            st.consecutive_failures = 0;
            st.healthy = true;
        } else {
            st.consecutive_failures = st.consecutive_failures.saturating_add(1);
            if st.consecutive_failures >= max_failed {
                st.healthy = false;
            }
        }
        if was && !st.healthy {
            warn!(
                proxy = %name,
                failed = st.consecutive_failures,
                "健康检查连续失败，已停止为该代理提供服务"
            );
        } else if !was && st.healthy {
            info!(proxy = %name, "健康检查恢复，重新提供服务");
        }
    }

    /// 取状态表的锁；**锁被 poison 时照用不误**。
    ///
    /// 这里原先直接 `.unwrap()`。危害不在于"当场 panic"，而在于 panic 之后：
    /// 一旦某个持锁者 panic 把锁写脏，**后续每一次**探测/查询都会 panic。
    /// 探测任务跑在 `tokio::spawn` 里，panic 表现为任务静默消失 ——
    /// 而 `is_healthy` 那侧因为 `.unwrap_or(true)` 会退化成"永远健康"，
    /// 于是故障被彻底掩盖：隧道明明已经不通，界面和日志都说没事。
    ///
    /// 与 `store.rs` / `registry.rs` 的处理方式保持一致。
    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<String, State>> {
        self.states.lock().unwrap_or_else(|e| e.into_inner())
    }
}

/// TCP 探测：能连上就算活着（不发送任何数据，避免污染服务）。
async fn probe_tcp(addr: &str, timeout: Duration) -> bool {
    let Ok(resolved) = util::resolve_addr(addr).await else {
        return false;
    };
    tokio::time::timeout(timeout, TcpStream::connect(resolved))
        .await
        .map(|r| r.is_ok())
        .unwrap_or(false)
}

/// HTTP 探测：**只有 2xx 才算活着**。
///
/// 官方：官方 `client/health/health.go` 的 `doHTTPCheck` 用的是
/// `if resp.StatusCode/100 != 2 { return error }` —— **严格 2xx**。
///
/// 原先这里判的是 `code < 400`，把 3xx 也算健康。差别在真实场景里很明显：
///
/// * 服务配了强制 HTTPS 跳转（301/302）时，探测请求永远拿到 301，
///   旧判据会认为它**一直健康** —— 但那个端口其实没在提供内容；
/// * 反向代理返回 404 时同理（404 在旧判据里也是"健康"）。
///
/// 对齐官方之后，这类部署需要把 `healthCheckPath` 指到一个真的返回 2xx
/// 的路径上 —— 这正是官方文档要求的行为。
async fn probe_http(
    addr: &str,
    path: &str,
    headers: &[nfrp_common::config::HttpHeader],
    timeout: Duration,
) -> bool {
    let Ok(resolved) = util::resolve_addr(addr).await else {
        return false;
    };
    let fut = async {
        let mut s = TcpStream::connect(resolved).await.ok()?;
        let req = build_probe_request(path, headers);
        s.write_all(req.as_bytes()).await.ok()?;
        let mut buf = [0u8; 64];
        // 只读状态行就够了，没必要把整个响应读完
        let n = tokio::io::AsyncReadExt::read(&mut s, &mut buf).await.ok()?;
        let head = String::from_utf8_lossy(&buf[..n]).to_string();
        let code = head.split_whitespace().nth(1)?.parse::<u16>().ok()?;
        // 严格 2xx，与官方 doHTTPCheck 一致
        Some((200..300).contains(&code))
    };
    tokio::time::timeout(timeout, fut)
        .await
        .unwrap_or(Some(false))
        .unwrap_or(false)
}

/// 拼一次 HTTP 探测请求。
///
///   官方在 `doHTTPCheck` 里把配置的 header 全设进 `req.Header`，再用
///   `req.Host = header.Get("Host")` 单独覆盖 Host。这里照做：
///   配置里有 `Host` 就用它，没有才用兜底值 `healthcheck`。
///
/// # 头注入防护
///
/// 这里是**手写**请求，不像 Go 的 `http.Header` 会替我们校验，
/// 所以必须自己挡：头名和头值里都不能出现 CR / LF。
/// 否则配一个含 `\r\n` 的值就能往探测请求里插入任意额外的头，
/// 甚至拼出第二条请求（请求走私）。
fn build_probe_request(path: &str, headers: &[nfrp_common::config::HttpHeader]) -> String {
    let path = if path.is_empty() { "/" } else { path };
    let mut req = format!("GET {path} HTTP/1.1\r\n");
    let mut host_written = false;

    for h in headers {
        // 头名同样要清洗：`X-A: 1\r\nInjected` 这种形态会被当成两行
        let name = h.name.trim().replace(['\r', '\n'], "");
        if name.is_empty() {
            continue;
        }
        let value = h.value.replace(['\r', '\n'], "");
        if name.eq_ignore_ascii_case("host") {
            req.push_str(&format!("Host: {value}\r\n"));
            host_written = true;
        } else {
            req.push_str(&format!("{name}: {value}\r\n"));
        }
    }

    if !host_written {
        req.push_str("Host: healthcheck\r\n");
    }
    req.push_str("Connection: close\r\n\r\n");
    req
}

#[cfg(test)]
mod tests {
    use super::*;

    // ------------------------------------------------------------------
    // 探测请求构造（对齐官方 HTTPHeaders）
    // ------------------------------------------------------------------

    fn hdr(name: &str, value: &str) -> nfrp_common::config::HttpHeader {
        nfrp_common::config::HttpHeader {
            name: name.into(),
            value: value.into(),
        }
    }

    /// 不配 header 时用兜底 Host，且请求形态完整。
    #[test]
    fn probe_request_defaults() {
        let req = build_probe_request("", &[]);
        assert!(
            req.starts_with("GET / HTTP/1.1\r\n"),
            "空路径应当用 /：{req:?}"
        );
        assert!(req.contains("Host: healthcheck\r\n"), "应当有兜底 Host");
        assert!(req.ends_with("\r\n\r\n"), "请求头必须以空行结束");
    }

    /// 配置的 header 全部出现在请求里。
    #[test]
    fn probe_request_includes_configured_headers() {
        let req = build_probe_request(
            "/healthz",
            &[hdr("Authorization", "Bearer t0ken"), hdr("X-Src", "nfrp")],
        );
        assert!(req.starts_with("GET /healthz HTTP/1.1\r\n"), "{req:?}");
        assert!(req.contains("Authorization: Bearer t0ken\r\n"), "{req:?}");
        assert!(req.contains("X-Src: nfrp\r\n"), "{req:?}");
        // 没配 Host 时仍要有兜底
        assert!(req.contains("Host: healthcheck\r\n"), "{req:?}");
    }

    /// 配了 Host 就用配置的，不重复写。
    #[test]
    fn probe_request_honours_configured_host() {
        let req = build_probe_request("/", &[hdr("Host", "api.internal:8080")]);
        assert!(req.contains("Host: api.internal:8080\r\n"), "{req:?}");
        assert!(
            !req.contains("Host: healthcheck"),
            "配了 Host 就不该再写兜底值：{req:?}"
        );
        // 整个请求里只能出现一个 Host 行
        assert_eq!(req.matches("Host:").count(), 1, "Host 头必须唯一：{req:?}");
    }

    /// 头注入：值里的 CR/LF 必须被剥掉，不能让配置伪造出额外请求头。
    ///
    /// 手写 HTTP 请求不像 Go 的 `http.Header` 会替我们校验，
    /// 一个含 `\r\n` 的值就能插进任意头、甚至拼出第二条请求。
    ///
    /// 判据要精确：剥掉 CR/LF 之后，攻击者控制的**字符串本身**仍会出现在
    ///   请求里（被压进上一个头的值），那是无害的 —— 关键是它**不能构成
    ///   独立的头行**。所以这里验"请求行的结构"，而非"某串字面量不存在"。
    #[test]
    fn probe_request_strips_crlf_from_values() {
        let req = build_probe_request(
            "/",
            &[hdr(
                "X-Evil",
                "a\r\nX-Injected: yes\r\n\r\nGET /admin HTTP/1.1",
            )],
        );

        let lines: Vec<&str> = req.split("\r\n").collect();

        // ① 每个非空行都必须以已知的请求行/头名开头，不能凭空多一行
        for line in &lines {
            if line.is_empty() {
                continue;
            }
            assert!(
                line.starts_with("GET ")
                    || line.starts_with("Host:")
                    || line.starts_with("Connection:")
                    || line.starts_with("X-Evil:"),
                "出现了非预期的请求行（注入成功）：{line:?}"
            );
        }

        // ② 注入的头不能变成独立行
        assert!(
            !lines.iter().any(|l| l.starts_with("X-Injected:")),
            "注入的头不能被拆成独立行：{req:?}"
        );

        // ③ 不能拼出第二条请求
        assert!(
            !lines.iter().any(|l| l.starts_with("GET /admin")),
            "不能拼出第二条请求行：{req:?}"
        );

        // ④ 整个请求只有一个空行（结尾那个）
        assert_eq!(
            req.matches("\r\n\r\n").count(),
            1,
            "请求里只能有一个空行（结尾）：{req:?}"
        );

        // ⑤ 注入内容被压成了同一个头的值
        assert!(
            req.contains("X-Evil: aX-Injected: yesGET /admin HTTP/1.1\r\n"),
            "CR/LF 应被剥掉、内容压进同一个头的值里：{req:?}"
        );
    }

    /// 头名里的 CR/LF 同样要剥掉。
    #[test]
    fn probe_request_strips_crlf_from_names() {
        let req = build_probe_request("/", &[hdr("X-Bad\r\nX-Leak", "v")]);

        let lines: Vec<&str> = req.split("\r\n").collect();
        assert!(
            !lines.iter().any(|l| l.starts_with("X-Leak:")),
            "头名里的注入不能被拆成独立行：{req:?}"
        );
        assert_eq!(req.matches("\r\n\r\n").count(), 1, "{req:?}");
    }

    /// 空头名的条目直接跳过，不要产出 `: value` 这种非法行。
    #[test]
    fn probe_request_skips_empty_names() {
        let req = build_probe_request("/", &[hdr("   ", "v"), hdr("", "v2")]);
        assert!(!req.contains(": v"), "空头名不该产出非法请求行：{req:?}");
        assert!(req.contains("Host: healthcheck\r\n"), "{req:?}");
    }

    fn mon() -> Monitor {
        Monitor {
            states: std::sync::Mutex::new(HashMap::new()),
        }
    }

    #[test]
    fn unknown_proxy_is_healthy() {
        // 没配健康检查的代理不该被拦住
        assert!(mon().is_healthy("whatever"));
    }

    #[test]
    fn needs_several_failures_before_giving_up() {
        let m = mon();
        m.record("p", "p", true, 3);
        assert!(m.is_healthy("p"));
        // 前两次失败只是抖动，仍然服务
        m.record("p", "p", false, 3);
        assert!(m.is_healthy("p"), "一次抖动不该让后端下线");
        m.record("p", "p", false, 3);
        assert!(m.is_healthy("p"));
        // 第三次达到阈值
        m.record("p", "p", false, 3);
        assert!(!m.is_healthy("p"), "连续失败到阈值必须下线");
    }

    #[test]
    fn one_success_clears_the_streak() {
        let m = mon();
        m.record("p", "p", false, 2);
        m.record("p", "p", false, 2);
        assert!(!m.is_healthy("p"));
        m.record("p", "p", true, 2);
        assert!(m.is_healthy("p"), "恢复后必须立刻重新服务");
        // 恢复一次之后又要重新累计
        m.record("p", "p", false, 2);
        assert!(m.is_healthy("p"));
        m.record("p", "p", false, 2);
        assert!(!m.is_healthy("p"));
    }

    #[tokio::test]
    async fn tcp_probe_detects_dead_ports() {
        // 端口几乎不可能有人监听
        assert!(!probe_tcp("127.0.0.1:1", Duration::from_millis(200)).await);
    }

    #[tokio::test]
    async fn tcp_probe_detects_live_ports() {
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                if l.accept().await.is_err() {
                    break;
                }
            }
        });
        assert!(probe_tcp(&addr.to_string(), Duration::from_secs(2)).await);
    }

    #[tokio::test]
    async fn http_probe_rejects_bad_status() {
        // 起一个只回 500 的小服务
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap();
        tokio::spawn(async move {
            while let Ok((mut s, _)) = l.accept().await {
                use tokio::io::AsyncReadExt;
                let mut buf = [0u8; 1024];
                let _ = s.read(&mut buf).await;
                let _ = s
                    .write_all(b"HTTP/1.1 500 Internal Server Error\r\n\r\n")
                    .await;
            }
        });
        assert!(
            !probe_http(&addr.to_string(), "/", &[], Duration::from_secs(2)).await,
            "500 不能算健康"
        );
    }

    #[tokio::test]
    async fn http_probe_accepts_2xx() {
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap();
        tokio::spawn(async move {
            while let Ok((mut s, _)) = l.accept().await {
                use tokio::io::AsyncReadExt;
                let mut buf = [0u8; 1024];
                let _ = s.read(&mut buf).await;
                let _ = s
                    .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
                    .await;
            }
        });
        assert!(probe_http(&addr.to_string(), "/healthz", &[], Duration::from_secs(2)).await);
    }
}
