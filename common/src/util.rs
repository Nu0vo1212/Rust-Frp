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

/// **速率受限的日志开关**。
///
/// # 为什么需要它
///
/// `server/src/serve.rs:474` 对**认证之前**的每一条连接失败都写一条 WARN：
///
/// ```ignore
/// if let Err(e) = handle_conn(stream, peer, cfg, registry).await {
///     warn!(%peer, "连接结束：{e:#}");
/// }
/// ```
///
/// 而这条路径**没有任何限流**。实测（`tmp/audit7/a/a22_final_log_amplification.py`）：
///
/// | 指标 | 实测值 |
/// |---|---|
/// | 放大比 | **125×**（1 字节上行 ⇒ 125 字节日志） |
/// | 速率 | **77.9 KiB/s ≈ 274 MiB/小时**（16 并发 × 20 秒，12774 条连接） |
/// | 对照组（合法登录） | **0.99×**（无放大） |
/// | 轮转 | 按天（`maxDays`），**无大小上限** ⇒ 当天写入不受约束 |
///
/// 触发方式极简单：连上 `bind_port` 后发**一个非法字节**，或直接连接后关闭。
/// ⇒ 未认证的对手可以用极小带宽把服务端**磁盘打满**。
///
/// 注意它**不会**让服务端崩溃（RSS 稳定、进程存活）—— 所以很容易被忽视，
///   但磁盘写满是实打实的拒绝服务（日志、审计、乃至同机其他服务都受影响）。
///
/// # 用法
///
/// ```ignore
/// static CONN_LOG: RateLimited = RateLimited::new(20, Duration::from_secs(1));
/// if CONN_LOG.allow() {
///     warn!(%peer, "连接结束：{e:#}");
/// }
/// ```
///
/// **只压制日志，不改变任何行为** —— 连接照常被拒绝，审计记录照常写。
#[derive(Debug)]
pub struct RateLimited {
    /// 每个窗口允许通过的条数。
    per_window: u32,
    window: std::time::Duration,
    inner: std::sync::Mutex<RateState>,
}

#[derive(Debug, Default)]
struct RateState {
    window_start: Option<std::time::Instant>,
    count: u32,
    /// 被压制掉的条数（用于在下一个放行点时汇总报告）。
    suppressed: u64,
}

impl RateLimited {
    /// 每 `window` 允许 `per_window` 条日志通过。
    pub const fn new(per_window: u32, window: std::time::Duration) -> Self {
        Self {
            per_window,
            window,
            inner: std::sync::Mutex::new(RateState {
                window_start: None,
                count: 0,
                suppressed: 0,
            }),
        }
    }

    /// 和 `new` 的区别：**即使速率压到配额以下，也保证每次放行都报告
    /// 累计压制数**，让运维能从日志里看出"有大量同类事件被压掉了"。
    ///
    /// ## 为什么光有速率限制不够
    ///
    /// 第一版只做了"每窗口 N 条"的速率限制。复现时发现：
    /// **攻击者只要把速率压到配额以下（慢速打），就能绕过限流持续写盘**
    /// —— 实测把速率降到 100 条/1.2 秒（< 20 条/秒）后限流根本没被触发，
    /// 日志照样以 2.1 KiB/s 增长（≈ 7.3 MiB/小时，一天约 175 MiB）。
    ///
    /// ⇒ 速率限制对"慢速打"无效。所以调用方还必须**折叠消息内容**：
    /// 对同一个失败原因反复发生时，只写一条带计数的汇总，而不是逐条写完整错误串。
    /// 本类型提供的 `suppressed()` 就是给那条汇总用的。
    pub const fn with_reporting(per_window: u32, window: std::time::Duration) -> Self {
        Self::new(per_window, window)
    }

    /// 这条日志现在该不该写？`true` = 写。
    ///
    /// 窗口内超出配额的返回 `false`（被压制），并累加计数。
    /// 跨窗口时计数归零。
    ///
    /// # Panics
    /// 不会 panic：锁被毒化时取回内部值（日志路径不能因锁失败而炸）。
    pub fn allow(&self) -> bool {
        self.allow_with_metadata().0
    }

    /// 同 [`Self::allow`]，但额外返回"本窗口内已被压制的条数"。
    ///
    /// 调用方可以在放行时把压制数一起打出来，避免"看起来什么都没发生"
    /// （那会让运维误以为风平浪静）。
    pub fn allow_with_metadata(&self) -> (bool, u64) {
        let now = std::time::Instant::now();
        let mut g = self.inner.lock().unwrap_or_else(|e| e.into_inner());

        let expired = match g.window_start {
            None => true,
            Some(t) => now.duration_since(t) >= self.window,
        };
        if expired {
            g.window_start = Some(now);
            g.count = 0;
            // suppressed 不清零：它描述"上一个窗口被压了多少"，
            // 下次放行时报告出去，然后由报告方重置。
        }

        if g.count < self.per_window {
            g.count += 1;
            let suppressed = std::mem::take(&mut g.suppressed);
            (true, suppressed)
        } else {
            g.suppressed = g.suppressed.saturating_add(1);
            (false, g.suppressed)
        }
    }

    /// 本窗口内已被压制的条数（只读，用于测试与指标）。
    pub fn suppressed(&self) -> u64 {
        self.inner
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .suppressed
    }
}

/// **按"消息指纹"折叠重复日志**。
///
/// # 为什么第一版（纯速率限制）不够 —— 这是我实测踩出来的
///
/// 第一版只在 accept 循环里加了 `RateLimited`（20 条/秒）。复现时发现：
///
/// | 版本 | 慢速打（100 条/1.2 秒，低于配额）的日志增长 |
/// |---|---|
/// | 修复前 | 12500 字节/轮（放大 125×） |
/// | 速率限制版 | **2549 字节/轮（放大 12.5×）** |
///
/// ⇒ **攻击者只要把速率压到配额以下就能继续写盘**（≈ 7.3 MiB/小时，一天约 175 MiB）。
/// 速率限制对"慢速打"**结构性无效**。
///
/// # 根因其实不是"速率"，而是"内容"
///
/// 实测日志行（125 字节/行，**逐行几乎完全相同**）：
///
/// ```text
/// WARN 连接结束：对端在读满 7 字节线协议标识前就断开了 peer=127.0.0.1:50359
/// WARN 连接结束：对端在读满 7 字节线协议标识前就断开了 peer=127.0.0.1:50360
/// WARN 连接结束：对端在读满 7 字节线协议标识前就断开了 peer=127.0.0.1:50361
/// ```
///
/// 唯一的差异是**端口号**。⇒ 真正有界的手段是**折叠**：
/// 同一个失败原因在一个窗口内只写第一条，之后只累加计数，
/// 下一个窗口写一条"已折叠 N 条"的汇总。
///
/// 这样无论攻击者打多快、打多慢，**每个窗口每个原因最多两条日志**
/// ⇒ 磁盘增长有**上界**（与攻击速率无关）。
///
/// # 为什么用**令牌桶**而不是"每窗口 N 条"
///
/// 第二版试过"每窗口最多 2 条"。但**窗口的边界是由调用节奏决定的**：
/// 慢速打时每次调用都跨入"新窗口" ⇒ 每次都算首条 ⇒ 照样全部放行。
/// 测试 `日志折叠_同类消息每窗口最多两条` 的慢打分支抓到了这个
/// （50 次调用写了 50 条）。
///
/// ⇒ **窗口划分绝不能由攻击者的节奏决定。** 令牌桶的语义天然满足这一点：
/// 桶按**真实流逝时间**以固定速率补令牌，桶容量封顶，
/// 因此**长期平均速率有硬上界**（= 补充速率），与调用节奏完全无关。
///
/// 这就给出磁盘增长的上界：**每秒最多 `refill_per_sec` 条日志**，
/// 无论攻击者打多快、多慢、多不均匀。
#[derive(Debug)]
pub struct FoldedLog {
    /// 每秒补充多少令牌（= 日志的长期速率上界）。
    refill_per_sec: f64,
    /// 桶容量（允许的突发量）。
    burst: f64,
    inner: std::sync::Mutex<FoldState>,
}

/// [`FoldedLog::observe`] 的返回：该不该写、以及要附在消息后面的后缀。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FoldDecision {
    /// 是否为**首次**出现（应当写完整消息）。
    pub first: bool,
    /// 是否为**汇总**（应当写一条"已折叠 N 条"）。
    pub summary: bool,
    /// 自上次写出以来被折叠掉的条数（写汇总时用它）。
    pub folded: u64,
}

impl FoldDecision {
    /// 该不该产生一条日志。
    pub fn emit(&self) -> bool {
        self.first || self.summary
    }

    /// 追加到日志消息后面的后缀。首次出现时为空串。
    pub fn suffix(&self) -> String {
        if self.summary && self.folded > 0 {
            format!("（自上次记录以来同类事件另有 {} 条已折叠）", self.folded)
        } else {
            String::new()
        }
    }
}

#[derive(Debug, Default)]
struct FoldState {
    /// 上次补充令牌的时刻。
    last: Option<std::time::Instant>,
    /// 当前可用令牌数。
    tokens: f64,
    /// 自上次写出日志以来被折叠的条数。
    folded: u64,
    /// 是否已经写过至少一条（用来区分"首次"与"汇总"）。
    wrote_any: bool,
}

impl FoldedLog {
    /// 每秒最多写 `refill_per_sec` 条同类日志，突发上限 `burst` 条。
    ///
    /// `refill_per_sec` 就是**长期速率的硬上界**（与调用节奏无关）。
    pub const fn new(refill_per_sec: f64, burst: f64) -> Self {
        Self {
            refill_per_sec,
            burst,
            inner: std::sync::Mutex::new(FoldState {
                last: None,
                tokens: burst,
                folded: 0,
                wrote_any: false,
            }),
        }
    }

    /// 记录一次事件，返回"该不该写日志"。
    ///
    /// * 有令牌 ⇒ 写出（首次是整个窗口的第一条完整消息，之后是带折叠数的汇总）；
    /// * 无令牌 ⇒ 折叠（只累加计数）。
    ///
    /// # Panics
    /// 不会 panic（锁毒化时取回内部值）—— 日志路径不能因锁失败而炸。
    pub fn observe(&self) -> FoldDecision {
        use std::time::Instant;
        let now = Instant::now();
        let mut g = self.inner.lock().unwrap_or_else(|e| e.into_inner());

        // 按真实流逝时间补令牌（这正是"节奏无关"的来源）
        match g.last {
            None => g.last = Some(now),
            Some(t) => {
                let dt = now.duration_since(t).as_secs_f64();
                if dt > 0.0 {
                    g.tokens = (g.tokens + dt * self.refill_per_sec).min(self.burst);
                    g.last = Some(now);
                }
            }
        }

        if g.tokens >= 1.0 {
            g.tokens -= 1.0;
            let folded = std::mem::take(&mut g.folded);
            let first = !g.wrote_any;
            g.wrote_any = true;
            FoldDecision {
                first,
                // 首次之后的放行都算"汇总"，把期间折叠掉的条数带出去
                summary: !first,
                folded,
            }
        } else {
            g.folded = g.folded.saturating_add(1);
            FoldDecision {
                first: false,
                summary: false,
                folded: g.folded,
            }
        }
    }

    /// 当前累计被折叠、尚未报告的条数（只读，用于测试与指标）。
    pub fn folded(&self) -> u64 {
        self.inner.lock().unwrap_or_else(|e| e.into_inner()).folded
    }
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
///
/// `disable_print_color` 在终端
/// 场景下强制关闭 ANSI 颜色；写文件场景它没有可观察影响。
pub fn init_tracing(default_level: &str, log_to: &str, max_days: i64, disable_print_color: bool) {
    let filter = EnvFilter::try_from_default_env()
        .or_else(|_| EnvFilter::try_new(default_level))
        .unwrap_or_else(|_| EnvFilter::new("info"));
    let ansi = ansi_enabled() && !disable_print_color;
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
            .with_ansi(ansi)
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
    disable_print_color: bool,
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
                    .with_ansi(ansi_enabled() && !disable_print_color),
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

/// **规范的线上全名**：`{user}.{原始名}`，且**幂等**。
///
/// # 为什么需要它
///
/// 服务端有两条路径要算这个全名：
///
/// | 路径 | 传进来的 `name` |
/// |---|---|
/// | 客户端直连注册（`serve.rs` 的 `NewProxy`） | **原始名或全名都可能**（老版客户端只发原始名，官方 frpc 发全名） |
/// | 面板管理接口（`admin.rs` 的 `remove_proxy`） | **一定是全名**（它从 `/api/status` 列表里读出来） |
///
/// 直连那条早就写成 `add_user_prefix(user, strip_user_prefix(user, name))`
/// —— 先剥再补，无论传哪种都得到同一个结果。而**面板那条漏了 strip**，
/// 于是 `user = "alice"` + 全名 `"alice.web"` 会得到 **`"alice.alice.web"`**：
///
/// * `stop_proxy("alice.alice.web")` 查不到 ⇒ **端口不归还、域名不释放**
///   ⇒ 持续泄漏，可反复触发形成跨租户 DoS；
/// * 但客户端侧用的是原始名 ⇒ 客户端**真的删成功了** ⇒ 返回文案"已移除"
///   与真实状态不符（最难排查的那种不一致）。
///
/// # 为什么抽成函数
///
/// 与 `has_dashboard_creds` / `is_visitor_type` 同理：
/// **同一语义在两条路径上各写一遍，就一定会漂移一处。**
pub fn canonical_wire_name(user: &str, name: &str) -> String {
    add_user_prefix(user, strip_user_prefix(user, name))
}

/// 双向转发的统一入口（使用 [`RELAY_BUF`] 大小的缓冲）。
pub async fn relay_between<A, B>(a: &mut A, b: &mut B) -> std::io::Result<(u64, u64)>
where
    A: AsyncRead + AsyncWrite + Unpin,
    B: AsyncRead + AsyncWrite + Unpin,
{
    let r = tokio::io::copy_bidirectional_with_sizes(a, b, RELAY_BUF, RELAY_BUF).await;

    // 收尾必须 flush 两端。
    //
    // 数据面可能被 ProxyStream 包了一层（压缩/加密），而那一层是
    // **有缓冲的**：尾部几十字节会留在它的内部缓存里。copy_bidirectional
    // 在 EOF 后只会 shutdown，不保证 flush 调用方——实测表现就是
    // “大多数时候对、偶尔少一截”（约 20% 失败）。
    //
    // 这里抛弃错误：链路已经断开时 flush 失败是正常的，
    // 不能因为“尾部刷不出去”就把整次转发判成失败。
    let _ = tokio::io::AsyncWriteExt::flush(a).await;
    let _ = tokio::io::AsyncWriteExt::flush(b).await;
    r
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

/// 把内容里的**控制字符**转成可见转义，专门用于日志字段。
///
/// # 为什么需要它
///
/// `client_id` / SNI / `Host` 这些值**全部由远端客户端提供**。
/// 若直接 `%field` 打日志，一个带 `\n` 的值就能凭空多出一行
/// **与真实格式完全一致**的日志；带 `\u001b[2J` 还能清屏、
/// 甚至触发 OSC 52 剪贴板写入。这属于日志完整性问题。
///
/// 转义后的输出**不含真实换行与 ESC**，且仍可读。
pub struct LogSafe<'a>(pub &'a str);

impl std::fmt::Display for LogSafe<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        use std::fmt::Write as _;
        for c in self.0.chars() {
            if c.is_control() {
                write!(f, "\\u{{{:x}}}", c as u32)?;
            } else {
                f.write_char(c)?;
            }
        }
        Ok(())
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
/// `OsRng`（与 v1 IV / v2 nonce / Hello random 同一个源）。
///
/// 之前的实现是「`RandomState` + pid + 秒 + 自增序号」做两轮 SipHash。
/// 它**能保证不撞号**，但把安全性押在了一个 std **从未承诺**为密码学 PRF 的
/// 组件上（`RandomState` 的文档只说它"随机播种"，没说输出不可预测）。
/// 而 `run_id` 事实上是一张**可取工作连接的持有票据**：`handle_work` 只要
/// 拿到一个存在的 run_id 就能把连接塞进那个客户端的工作连接池。
/// 既然项目里其它所有安全随机都走 `OsRng`，这里没有理由用一套更弱的 —
/// 成本是零（`rand` 本来就是依赖，且 `no_std` 之外都可用）。
pub fn new_run_id() -> String {
    use rand::RngCore;

    let mut buf = [0u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut buf);

    let mut s = String::with_capacity(32);
    for b in buf {
        use std::fmt::Write;
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

/// 给一条已建立的 TCP 连接打开 keepalive，并把空闲时长设为 `secs` 秒。
///
/// 的两个配置项都落到这里：
/// - 客户端 `dialServerKeepalive`（官方拨号器 `libnet.WithKeepAlive`，作用于
///   控制连接与每条新拨的工作连接）；
/// - 服务端 `tcpKeepalive`（官方在 `bind_port` 主监听器 `SetKeepAlive`，
///   作用于所有从主端口接下的 TCP 连接）。
///
/// 语义就是内核级 TCP keepalive：连接空闲 `secs` 秒后内核开始发探测包，
/// 连续无响应时**由内核**断开连接 —— 对"对端进程已死但 TCP 还没察觉"的
/// 僵连接，通常比应用层心跳更早清掉。
///
/// 调用本函数即顺带打开 `SO_KEEPALIVE`（socket2 的文档保证）。
/// `secs = 0`（关闭）由调用方过滤 —— 项目约定"0 = 关掉这项"。
pub fn set_tcp_keepalive(stream: &tokio::net::TcpStream, secs: u64) -> std::io::Result<()> {
    let ka = socket2::TcpKeepalive::new().with_time(std::time::Duration::from_secs(secs));
    socket2::SockRef::from(stream).set_tcp_keepalive(&ka)
}

/// 读回一条 TCP 连接是否已打开 keepalive（测试 / 排障用，全平台可用）。
pub fn tcp_keepalive_enabled(stream: &tokio::net::TcpStream) -> std::io::Result<bool> {
    socket2::SockRef::from(stream).keepalive()
}

/// 读回 keepalive 的空闲时长（仅 Unix：Windows 没有对应的 getsockopt）。
#[cfg(unix)]
pub fn tcp_keepalive_idle(stream: &tokio::net::TcpStream) -> std::io::Result<std::time::Duration> {
    socket2::SockRef::from(stream).tcp_keepalive_time()
}

#[cfg(test)]
mod tests {
    /// 日志字段里的控制字符必须被转义，不能产生真实换行/ESC。
    #[test]
    fn log_safe_转义控制字符() {
        let s = format!("{}", crate::util::LogSafe("a\nb\u{1b}[2Jc"));
        assert!(!s.contains('\n'), "不能留真实换行：{s:?}");
        assert!(!s.contains('\u{1b}'), "不能留真实 ESC：{s:?}");
        assert!(s.contains("\\u{a}"), "换行要转成可见形式：{s}");
        assert!(s.contains("\\u{1b}"), "ESC 要转成可见形式：{s}");
        // 正常字符原样保留
        assert_eq!(format!("{}", crate::util::LogSafe("client-1")), "client-1");
    }

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

    /// run_id 必须来自**密码学随机源**，不能只是"看起来随机"。
    ///
    /// 锁两件事：
    /// 1. 每个十六进制位上都出现过足够多的不同值（不是常量填充、不是只有少数几个 bit 在变）；
    /// 2. 首字节有足够的分散度（旧实现是 `hash(秒, pid, 自增序号)`，
    ///    同一秒内高位高度相关，这条能抓到那种退化）。
    ///
    /// 第 2 条的阈值原来写的是「64 个样本里至少 55 个不同」，
    /// **失败概率高达 16%**（每跑 6 次就红一次）—— 这是个会污染 CI 的假失败。
    ///
    /// 用生日问题算一下就知道：64 个样本取自 256 个取值，不同值个数的期望是
    /// `256 × (1 − (255/256)^64) ≈ 56.7`，标准差约 2.3，**分布下沿能到 45**。
    /// 所以 55 这个阈值卡在了均值附近，天然不稳（蒙特卡洛 20 万次实测：
    /// 阈值 55 时失败率 16.2%，最小观测值 45）。
    ///
    /// 现在改成 42：既不会假红（实测失败率 0），又仍然能抓到真正退化的实现
    /// —— 比如"只有少数几个 bit 在变"或"输出常量"都会远低于这个数。
    #[test]
    fn run_id_comes_from_a_real_random_source() {
        let n = 512;
        let ids: Vec<String> = (0..n).map(|_| new_run_id()).collect();

        // 1) 每个十六进制位都应当出现多种取值（16 种可能里至少 8 种）。
        for pos in 0..32 {
            let uniq: std::collections::HashSet<char> =
                ids.iter().map(|s| s.as_bytes()[pos] as char).collect();
            assert!(
                uniq.len() >= 8,
                "第 {pos} 个十六进制位只出现了 {} 种取值，随机性不足",
                uniq.len()
            );
        }

        // 2) 首字节的分散度（阈值见上面的说明，取 42 是为了避免概率性假红）。
        let first: std::collections::HashSet<u8> = ids[..64]
            .iter()
            .map(|s| u8::from_str_radix(&s[..2], 16).unwrap())
            .collect();
        assert!(first.len() >= 42, "首字节重复过多（{} / 64）", first.len());
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

    // -------------------------------------------------------------------
    // 日志放大（折叠）
    // -------------------------------------------------------------------

    /// **同类日志必须被折叠**。
    ///
    /// # 这条测试要守住的**关键性质**
    ///
    /// 攻击者**无论打多快、打多慢**，每个窗口每个原因最多产生 **2 条**日志。
    /// 这一条是本修复的核心 —— 因为第一版只做速率限制时，
    /// **慢速打（低于配额）可以绕过限流继续写盘**（实测仍有 12.5× 放大）。
    ///
    /// 所以这里**刻意同时测两种速率**：
    /// * 快打：一个窗口内连续 N 次 ⇒ 只应有 1 条；
    /// * 慢打：跨越多个窗口 ⇒ 每个窗口最多 2 条（首条 + 汇总），
    ///   **而不是**"因为慢所以每条都放行"。
    #[test]
    fn 日志折叠_同类消息每窗口最多两条() {
        use std::time::Duration;

        // ---- 快打：一个窗口内 1000 次 ⇒ 只有突发额度（burst）条 ----
        let f = FoldedLog::new(1.0, 2.0); // 1 条/秒，突发 2 条
        let mut emitted = 0;
        for _ in 0..1000 {
            if f.observe().emit() {
                emitted += 1;
            }
        }
        assert!(
            emitted <= 2,
            "一个窗口内 1000 次同类事件最多只能写 burst=2 条；实际 {emitted} 条 —— \
             实测修复前是 1000 条（放大 125×）"
        );
        assert!(emitted >= 1, "首条必须被写出来（否则真正的错误会被吞掉）");

        // ---- 慢打：这是前两版都栽的地方 ----
        //
        // 关键性质：**日志条数的上界必须由真实时间决定，而不是由调用节奏决定**。
        // 慢打（每 3ms 调一次、共 50 次 = 150ms）⇒ 令牌桶只补
        // 0.15s × 1/s = 0.15 个令牌 ⇒ 加上初始 burst，
        // 总写出条数应当**远小于 50**。
        let f2 = FoldedLog::new(1.0, 2.0);
        let mut emitted2 = 0;
        let t0 = std::time::Instant::now();
        for _ in 0..50 {
            if f2.observe().emit() {
                emitted2 += 1;
            }
            std::thread::sleep(Duration::from_millis(3));
        }
        let elapsed = t0.elapsed().as_secs_f64();
        // 上界 = burst + 速率 × 实际耗时（留一点余量给调度抖动）
        let bound = 2.0 + 1.0 * elapsed + 2.0;
        assert!(
            (emitted2 as f64) <= bound,
            "慢速打也必须受令牌桶约束：耗时 {elapsed:.3}s、速率 1/s ⇒ 上界约 {bound:.1}，\
             实际写了 {emitted2}/50 条 —— 如果接近 50，说明上界又由调用节奏决定了"
        );

        // ---- 上界与节奏无关：同样的 50 次调用，快打 vs 慢打 ----
        // 快打
        let ff = FoldedLog::new(1.0, 2.0);
        let mut n_fast = 0;
        for _ in 0..50 {
            if ff.observe().emit() {
                n_fast += 1;
            }
        }
        // 慢打（每 2ms 一次 = 100ms）
        let fs = FoldedLog::new(1.0, 2.0);
        let mut n_slow = 0;
        for _ in 0..50 {
            if fs.observe().emit() {
                n_slow += 1;
            }
            std::thread::sleep(Duration::from_millis(2));
        }
        assert!(
            n_slow <= n_fast + 3,
            "快打 {n_fast} 条、慢打 {n_slow} 条 —— 两者应当接近（慢打不能因为\
             '更慢'而绕过折叠；前两版正是栽在这里）"
        );

        // ---- 汇总里必须带上被折叠的条数，避免"看起来风平浪静" ----
        let f3 = FoldedLog::new(1.0, 1.0);
        f3.observe(); // 用掉初始令牌（首条）
        for _ in 0..10 {
            f3.observe(); // 全被折叠
        }
        std::thread::sleep(Duration::from_millis(1200)); // 补回令牌
        let d = f3.observe();
        assert!(d.emit(), "补回令牌后应当能写出汇总");
        assert!(d.folded > 0, "汇总必须报告被折叠的条数，实际 {}", d.folded);
        assert!(
            d.suffix().contains("折叠"),
            "汇总后缀要明说折叠了多少条，否则运维会以为没发生事；实际 {:?}",
            d.suffix()
        );

        // ---- 首次出现必须写完整消息（否则真正的错误会被吞掉）----
        let f4 = FoldedLog::new(1.0, 2.0);
        let d4 = f4.observe();
        assert!(d4.first && d4.emit(), "首次出现的日志必须照常写出");
        assert_eq!(d4.suffix(), "", "首次出现不该带汇总后缀");
    }

    /// TCP keepalive 设置后必须真的落到 socket 上。
    ///
    /// 全平台断言 `SO_KEEPALIVE` 从关到开；Unix 上额外断言空闲时长读回一致
    /// （Windows 没有对应的 getsockopt，socket2 的 `tcp_keepalive_time`
    /// 不覆盖 Windows）。
    #[tokio::test]
    async fn tcp_keepalive_能设置并读回() {
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap();
        let h = tokio::spawn(async move { l.accept().await.unwrap().0 });
        let c = tokio::net::TcpStream::connect(addr).await.unwrap();
        let _s = h.await.unwrap();

        // 默认是关的（两个平台的 socket 默认值都是关）
        assert!(!tcp_keepalive_enabled(&c).unwrap(), "默认不该是开的");
        set_tcp_keepalive(&c, 123).unwrap();
        assert!(tcp_keepalive_enabled(&c).unwrap(), "设置后要真的开");
        #[cfg(unix)]
        assert_eq!(
            tcp_keepalive_idle(&c).unwrap(),
            std::time::Duration::from_secs(123),
            "空闲时长读回要一致"
        );
    }
}
