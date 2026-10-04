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
///
/// `log_to` / `max_days` 对应官方 frp 的 `[log] to` / `[log] maxDays`：
/// `to` 为空或 `console`（默认）时写控制台，否则写文件并按天轮转。
/// 详见 [`crate::logfile`]。
///
/// 日志要不要带 ANSI 颜色转义码。
///
/// 只在**输出是终端**时才上色。这一点对第三方启动器很关键：NetTool 之类
/// 是把 frpc 的 stdout/stderr **按行读进日志面板**的，如果日志里夹着
/// `\x1b[2m` / `\x1b[32m` 这些转义码，面板上就会显示成
/// `[2m2026-09-17T...` 这种乱码。官方 frpc 也是同样的判断
/// （`IsTerminal`），所以行为和原版一致。
fn ansi_enabled() -> bool {
    use std::io::IsTerminal as _;
    std::io::stdout().is_terminal()
}

/// 按配置装配一个订阅者，落到控制台或日志文件。
///
/// 上色只在**输出是终端**时才开：写文件时开关颜色没有意义，只会往文件里
/// 塞 `\x1b[` 转义码（官方 `disableLogColor` 的默认行为也是写文件不上色）。
pub fn init_tracing(default_level: &str, log_to: &str, max_days: i64) {
    let filter = EnvFilter::try_from_default_env()
        .or_else(|_| EnvFilter::try_new(default_level))
        .unwrap_or_else(|_| EnvFilter::new("info"));
    match crate::logfile::sink_from_config(log_to, max_days) {
        Some(sink) => tracing_subscriber::fmt()
            .with_env_filter(filter)
            .with_target(false)
            .with_ansi(false)
            .with_writer(sink)
            .init(),
        None => tracing_subscriber::fmt()
            .with_env_filter(filter)
            .with_target(false)
            .with_ansi(ansi_enabled())
            .init(),
    }
}

/// 可以在运行时替换日志级别的热重载句柄。
///
/// 配置热重载需要在不重启进程的前提下改 `log_level`（排障时最想动的字段），
/// 所以用 tracing-subscriber 的 reload layer 把过滤器换成可替换的。
pub type LogFilterHandle =
    tracing_subscriber::reload::Handle<EnvFilter, tracing_subscriber::Registry>;

/// 与 [`init_tracing`] 相同，但额外返回一个热重载句柄。
pub fn init_tracing_reloadable(
    default_level: &str,
    log_to: &str,
    max_days: i64,
) -> Option<LogFilterHandle> {
    let filter = EnvFilter::try_from_default_env()
        .or_else(|_| EnvFilter::try_new(default_level))
        .unwrap_or_else(|_| EnvFilter::new("info"));
    use tracing_subscriber::layer::SubscriberExt as _;
    use tracing_subscriber::util::SubscriberInitExt as _;

    let (layer, handle) = tracing_subscriber::reload::Layer::new(filter);
    match crate::logfile::sink_from_config(log_to, max_days) {
        Some(sink) => tracing_subscriber::registry()
            .with(layer)
            .with(
                tracing_subscriber::fmt::layer()
                    .with_target(false)
                    .with_ansi(false)
                    .with_writer(sink),
            )
            .init(),
        None => tracing_subscriber::registry()
            .with(layer)
            .with(
                tracing_subscriber::fmt::layer()
                    .with_target(false)
                    .with_ansi(ansi_enabled()),
            )
            .init(),
    }
    Some(handle)
}

/// 通过热重载句柄替换日志级别；返回是否成功。
pub fn reload_log_level(handle: &LogFilterHandle, level: &str) -> bool {
    match EnvFilter::try_new(level) {
        Ok(f) => handle.reload(f).is_ok(),
        Err(_) => false,
    }
}

/// 中继转发的缓冲区大小。
///
/// tokio 的 `copy_bidirectional` 默认只给 **8 KiB**，在高速链路（回环 / 内网 10G）
/// 下单流吞吐会被它压住：本机回环实测官方 frp（Go，`io.Copy` 用 32 KiB + 内核零拷贝）
/// 单流 1.6 Gbps，而 8 KiB 缓冲只能跑到 475 Mbps。
/// 换成 128 KiB 后差距基本抹平。
///
/// 内存代价：每条**活跃**转发连接多占 2 × 128 KiB；连接结束即释放，
/// 空闲进程不持有，所以常驻内存仍然很低。
pub const RELAY_BUF: usize = 128 * 1024;

/// 官方 frp 的“线协议代理名”：客户端的顶层 `user` 非空时，代理名会带 `"{user}."` 前缀。
///
/// 对应 Go 的 `naming.AddUserPrefix`。provider 注册 `NewProxy`、
/// visitor 发起 `NewVisitorConn` 都要用这个带前缀的名字，否则跨实现找不到对方。
pub fn add_user_prefix(user: &str, name: &str) -> String {
    if user.is_empty() {
        name.to_string()
    } else {
        format!("{user}.{name}")
    }
}

/// 去掉 `"{user}."` 前缀（只剥一层），对应 Go 的 `naming.StripUserPrefix`。
///
/// 服务端在 `NewProxyResp` / `StartWorkConn` 里回的是带前缀的名字，
/// 客户端要剥掉后才能对回本地配置。
pub fn strip_user_prefix<'a>(user: &str, name: &'a str) -> &'a str {
    if user.is_empty() {
        return name;
    }
    match name.strip_prefix(user) {
        Some(rest) => rest.strip_prefix('.').unwrap_or(name),
        None => name,
    }
}

/// 双向转发的统一入口（使用 [`RELAY_BUF`] 大小的缓冲）。
pub async fn relay_between<A, B>(a: &mut A, b: &mut B) -> std::io::Result<(u64, u64)>
where
    A: AsyncRead + AsyncWrite + Unpin,
    B: AsyncRead + AsyncWrite + Unpin,
{
    tokio::io::copy_bidirectional_with_sizes(a, b, RELAY_BUF, RELAY_BUF).await
}

/// 双向转发：把 `a` 收到的字节原样写给 `b`，反之亦然。
///
/// 任一端断开即返回，返回值为 `(a -> b, b -> a)` 的字节数。
pub async fn bridge(mut a: TunnelIo, mut b: TunnelIo) -> std::io::Result<(u64, u64)> {
    relay_between(&mut a, &mut b).await
}

/// 与 [`bridge`] 相同，但两端类型不同（例如一端是隧道流、一端是内网明文连接）。
pub async fn bridge_between<A, B>(mut a: A, mut b: B) -> std::io::Result<(u64, u64)>
where
    A: AsyncRead + AsyncWrite + Unpin,
    B: AsyncRead + AsyncWrite + Unpin,
{
    relay_between(&mut a, &mut b).await
}

/// 这个监听地址是不是"只有本机能连"？
///
/// 用途是**给管理端口做安全默认值**：面板 / 客户端管理界面在回环上不配密码
/// 可以接受（只有本机能碰），一旦绑到非回环就等于对外开放，必须要求凭据。
///
/// 判定口径刻意从严 —— **无法确认是回环的一律当作"非回环"**：
/// 空串（`""` 在所有平台上都表示"监听全部网卡"）、`0.0.0.0`、`::` 都是非回环；
/// 只有明确的 `127.x.x.x`（整个 127/8 都是回环）与 `::1` 才算。
///
/// `localhost` 也按**非回环**处理：它解析到哪个地址取决于本机 hosts 与 DNS，
/// 解析到非回环地址时就是一个对外端口，不能靠名字赌。
pub fn is_loopback_addr(addr: &str) -> bool {
    let a = addr.trim();
    if a.is_empty() {
        return false;
    }
    // `[::1]` 带方括号的写法也要认
    let bare = a
        .strip_prefix('[')
        .and_then(|s| s.strip_suffix(']'))
        .unwrap_or(a);
    match bare.parse::<std::net::IpAddr>() {
        Ok(std::net::IpAddr::V4(v4)) => v4.is_loopback(),
        Ok(std::net::IpAddr::V6(v6)) => v6.is_loopback(),
        // 解析不出来（域名等）⇒ 从严当作非回环
        Err(_) => false,
    }
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
///
/// 这里**必须**每次都不同：`run_id` 是服务端 `Registry` 里控制会话的主键，
/// 撞号会让新会话顶掉旧会话（visitor 会被算到错误的 client 头上）。
/// 早先的实现只用「当前秒 + pid」当种子，同一秒内接受的两个连接会得到同一个
/// run_id —— 这个坑在同时跑多个 frpc 时才会暴露。
///
/// 现在混入 `RandomState`（由 OS 随机数播种，且每次 `new()` 递增计数器）与
/// 进程内自增序号，既有熵又不需要引入 `rand` 依赖。
pub fn new_run_id() -> String {
    use std::fmt::Write;
    use std::hash::{BuildHasher, Hasher};
    use std::sync::atomic::{AtomicU64, Ordering};

    static SEQ: AtomicU64 = AtomicU64::new(0);

    let seq = SEQ.fetch_add(1, Ordering::Relaxed);

    let mut h1 = std::collections::hash_map::RandomState::new().build_hasher();
    h1.write_u64(now_unix_secs());
    h1.write_u32(std::process::id());
    h1.write_u64(seq);
    let a = h1.finish();

    let mut h2 = std::collections::hash_map::RandomState::new().build_hasher();
    h2.write_u64(a);
    h2.write_u64(seq ^ 0x9e37_79b9_7f4a_7c15);
    let b = h2.finish();

    let mut s = String::with_capacity(32);
    let _ = write!(s, "{a:016x}{b:016x}");
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

#[cfg(test)]
mod tests {
    use super::*;

    /// run_id 必须每次都不同：同秒内连续生成 1000 个也要互不相同
    /// （服务端 Registry 以它为会话主键，撞号会顶掉已有会话）。
    #[test]
    fn run_id_is_unique() {
        let ids: std::collections::HashSet<String> = (0..1000).map(|_| new_run_id()).collect();
        assert_eq!(ids.len(), 1000, "run_id 出现重复");
        for id in &ids {
            assert_eq!(id.len(), 32, "run_id 应为 32 个十六进制字符：{id}");
            assert!(id.chars().all(|c| c.is_ascii_hexdigit()));
        }
    }

    /// 官方 frp 的代理名带用户前缀：`user` 非空时是 `"{user}.{name}"`。
    #[test]
    fn user_prefix_roundtrip() {
        assert_eq!(add_user_prefix("", "ssh"), "ssh");
        assert_eq!(add_user_prefix("alice", "ssh"), "alice.ssh");
        assert_eq!(strip_user_prefix("", "ssh"), "ssh");
        assert_eq!(strip_user_prefix("alice", "alice.ssh"), "ssh");
        // 前缀不匹配时原样返回（与 Go 的 StripUserPrefix 一致）
        assert_eq!(strip_user_prefix("bob", "alice.ssh"), "alice.ssh");
        assert_eq!(strip_user_prefix("alice", "alice"), "alice");
    }

    /// 回环判定：口径从严 —— 确认不了的都算"非回环"。
    #[test]
    fn loopback_detection_is_strict() {
        // 明确的回环
        assert!(is_loopback_addr("127.0.0.1"));
        assert!(is_loopback_addr("127.1.2.3"), "整个 127/8 都是回环");
        assert!(is_loopback_addr("::1"));
        assert!(is_loopback_addr("[::1]"));
        assert!(is_loopback_addr("  127.0.0.1  "), "两侧空白要忽略");

        // 对外（或无法确认）一律 false
        assert!(!is_loopback_addr("0.0.0.0"));
        assert!(!is_loopback_addr("::"));
        assert!(!is_loopback_addr(""), "空串在所有平台都表示监听全部网卡");
        assert!(!is_loopback_addr("192.168.1.10"));
        assert!(
            !is_loopback_addr("localhost"),
            "名字解析结果不可控，不能当回环"
        );
    }
}
