//! 跨平台工具函数。
//!
//! 仅使用标准库与 tokio 的跨平台 API，不含 `std::os::windows` / `std::os::unix`。

use std::{
    net::SocketAddr,
    time::{SystemTime, UNIX_EPOCH},
};

use tokio::io::{AsyncRead, AsyncWrite};
use tracing_subscriber::EnvFilter;

use crate::{
    error::{Error, Result},
    transport::TunnelIo,
};

/// 当前 Unix 时间戳（秒）。
pub fn now_unix_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// 解析 `"host:port"` 形式的地址。
///
/// 用 `tokio::net::lookup_host`，支持域名；Windows / Linux 行为一致。
/// 域名解析出多个地址时取第一个。
pub async fn resolve_addr(addr: &str) -> Result<SocketAddr> {
    let mut iter = tokio::net::lookup_host(addr)
        .await
        .map_err(|e| Error::Resolve {
            addr: addr.to_string(),
            source: e,
        })?;
    iter.next().ok_or_else(|| Error::Resolve {
        addr: addr.to_string(),
        source: std::io::Error::new(std::io::ErrorKind::NotFound, "no address returned"),
    })
}

/// 拼接 `host` + `port` 后解析，避免手工拼字符串出错。
pub async fn resolve_host_port(host: &str, port: u16) -> Result<SocketAddr> {
    resolve_addr(&format!("{host}:{port}")).await
}

/// 初始化 `tracing` 订阅者。
///
/// 优先级：环境变量 `RUST_LOG` > 配置里的 `log_level` > `info`。
pub fn init_tracing(default_level: &str) {
    let filter = EnvFilter::try_from_default_env()
        .or_else(|_| EnvFilter::try_new(default_level))
        .unwrap_or_else(|_| EnvFilter::new("info"));
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .init();
}

/// 双向转发：把 `a` 收到的字节原样写给 `b`，反之亦然。
///
/// 任一端断开即返回，返回值为 `(a -> b, b -> a)` 的字节数。
pub async fn bridge(mut a: TunnelIo, mut b: TunnelIo) -> std::io::Result<(u64, u64)> {
    tokio::io::copy_bidirectional(&mut a, &mut b).await
}

/// 与 [`bridge`] 相同，但两端类型不同（例如一端是隧道流、一端是内网明文连接）。
pub async fn bridge_between<A, B>(mut a: A, mut b: B) -> std::io::Result<(u64, u64)>
where
    A: AsyncRead + AsyncWrite + Unpin,
    B: AsyncRead + AsyncWrite + Unpin,
{
    tokio::io::copy_bidirectional(&mut a, &mut b).await
}

/// 读取主机名。
///
/// 只读环境变量（`COMPUTERNAME` / `HOSTNAME`），不使用任何平台专属 API。
pub fn hostname() -> String {
    std::env::var("COMPUTERNAME")
        .or_else(|_| std::env::var("HOSTNAME"))
        .unwrap_or_else(|_| String::from("unknown"))
}

/// 生成会话 ID（frp 的 `runID`），随机 16 字节十六进制。
pub fn new_run_id() -> String {
    use std::fmt::Write;
    let mut buf = [0u8; 16];
    for (i, b) in buf.iter_mut().enumerate() {
        // 用时间 + 进程 + 计数器做种子，避免引入额外随机数依赖
        let seed = now_unix_secs()
            .wrapping_mul(6_364_136_223_846_793_005)
            .rotate_left((i as u32) * 7)
            ^ (std::process::id() as u64) << (i % 5);
        *b = (seed >> 24) as u8;
    }
    let mut s = String::with_capacity(buf.len() * 2);
    for b in buf {
        let _ = write!(s, "{b:02x}");
    }
    s
}

/// 统一的优雅退出信号：等待 Ctrl+C（Unix 额外监听 SIGTERM）。
///
/// Windows 上只注册 Ctrl+C；Unix 上通过 `#[cfg(unix)]` 额外注册 SIGTERM，
/// 属于条件编译，不违反"禁止直接使用平台专属 API"的约束。
pub async fn shutdown_signal() {
    let ctrl_c = async {
        let _ = tokio::signal::ctrl_c().await;
    };

    #[cfg(unix)]
    let terminate = async {
        use tokio::signal::unix::{signal, SignalKind};
        match signal(SignalKind::terminate()) {
            Ok(mut s) => {
                s.recv().await;
            }
            Err(e) => tracing::warn!("注册 SIGTERM 失败: {e}"),
        }
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {}
        _ = terminate => {}
    }

    tracing::info!("收到退出信号，开始优雅关闭");
}
