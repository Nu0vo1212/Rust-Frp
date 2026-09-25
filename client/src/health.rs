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
            m.states.lock().unwrap().insert(wire.clone(), State::new());

            let mon = m.clone();
            let p = p.clone();
            let interval = Duration::from_secs(p.health_check_interval_s.max(1));
            let timeout = Duration::from_secs(p.health_check_timeout_s.max(1));
            tokio::spawn(async move {
                info!(proxy = %p.name, kind = %p.health_check_type, "健康检查已启动");
                loop {
                    tokio::time::sleep(interval).await;
                    let ok = match p.health_check_type.as_str() {
                        "http" => probe_http(&p.local_addr, &p.health_check_url, timeout).await,
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
        self.states
            .lock()
            .unwrap()
            .get(proxy)
            .map(|s| s.healthy)
            .unwrap_or(true)
    }

    /// 记录一次探测结果；**只在状态翻转时打日志**，否则日志会被探测刷屏。
    fn record(&self, wire: &str, name: &str, ok: bool, max_failed: u32) {
        let mut g = self.states.lock().unwrap();
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

/// HTTP 探测：拿到 2xx/3xx 才算活着。
async fn probe_http(addr: &str, path: &str, timeout: Duration) -> bool {
    let Ok(resolved) = util::resolve_addr(addr).await else {
        return false;
    };
    let fut = async {
        let mut s = TcpStream::connect(resolved).await.ok()?;
        let path = if path.is_empty() { "/" } else { path };
        // 不带 Host 的话很多服务直接 400，所以随便填一个
        let req = format!("GET {path} HTTP/1.1\r\nHost: healthcheck\r\nConnection: close\r\n\r\n");
        s.write_all(req.as_bytes()).await.ok()?;
        let mut buf = [0u8; 64];
        // 只读状态行就够了，没必要把整个响应读完
        let n = tokio::io::AsyncReadExt::read(&mut s, &mut buf).await.ok()?;
        let head = String::from_utf8_lossy(&buf[..n]).to_string();
        let code = head.split_whitespace().nth(1)?.parse::<u16>().ok()?;
        Some(code < 400)
    };
    tokio::time::timeout(timeout, fut)
        .await
        .unwrap_or(Some(false))
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

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
            !probe_http(&addr.to_string(), "/", Duration::from_secs(2)).await,
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
        assert!(probe_http(&addr.to_string(), "/healthz", Duration::from_secs(2)).await);
    }
}
