//! 可观测性：进程内指标收集 + Prometheus 文本导出。
//!
//! 只用原子计数器（portable_atomic 的 `AtomicU64` / `AtomicI64`），
//! 不引入 Prometheus client crate：一是保持二进制体积，二是这里的指标量级
//! 很小（十几个时间序列），手写一个符合 [exposition format] 的编码器就是
//! 几十行的成本。
//!
//! portable_atomic 在 x86_64 / aarch64 上就是 std 原子的类型别名，
//! 在 MIPS32（OpenWrt 24kc）上提供 64 位原子 fallback，行为一致。
//!
//! [exposition format]: https://prometheus.io/docs/instrumenting/exposition_formats/

use std::{
    sync::Arc,
    time::{Instant, SystemTime, UNIX_EPOCH},
};

use portable_atomic::{AtomicI64, AtomicU64, Ordering};

// ---------------------------------------------------------------------------
// 原子计数器 / 计量表
// ---------------------------------------------------------------------------

/// 单调递增计数器（Prometheus 的 `counter`）。
#[derive(Debug, Default)]
pub struct Counter(AtomicU64);

impl Counter {
    pub fn inc(&self) {
        self.inc_by(1);
    }
    pub fn inc_by(&self, n: u64) {
        self.0.fetch_add(n, Ordering::Relaxed);
    }
    pub fn get(&self) -> u64 {
        self.0.load(Ordering::Relaxed)
    }
}

/// 可增可减的瞬时值（Prometheus 的 `gauge`）。
#[derive(Debug, Default)]
pub struct Gauge(AtomicI64);

impl Gauge {
    pub fn inc(&self) {
        self.add(1);
    }
    pub fn dec(&self) {
        self.add(-1);
    }
    pub fn add(&self, n: i64) {
        self.0.fetch_add(n, Ordering::Relaxed);
    }
    pub fn set(&self, n: i64) {
        self.0.store(n, Ordering::Relaxed);
    }
    pub fn get(&self) -> i64 {
        self.0.load(Ordering::Relaxed)
    }
}

// ---------------------------------------------------------------------------
// 指标集合
// ---------------------------------------------------------------------------

/// 服务端全部运行指标。
#[derive(Debug, Default)]
pub struct Metrics {
    pub clients_total: Counter,
    pub clients_active: Gauge,
    /// 因 token 错误 / 达到客户端上限而被拒的连接。
    pub clients_rejected: Counter,

    pub proxies_total: Counter,
    pub proxies_active: Gauge,
    pub proxy_failures: Counter,

    pub conns_total: Counter,
    pub conns_active: Gauge,
    /// 命中资源上限而被直接丢弃的连接。
    pub conns_rejected: Counter,

    /// 上行：用户 -> 内网服务（写入上行=sent to client? 约定见 bridge）
    pub bytes_up: Counter,
    /// 下行：内网服务 -> 用户
    pub bytes_down: Counter,

    pub http_requests: Counter,
    pub https_conns: Counter,
    /// tcpmux：接入的 CONNECT 隧道数（一个共享端口上的多次分发各算一次）。
    pub tcpmux_conns: Counter,

    pub visitor_conns: Counter,
    pub visitor_rejected: Counter,

    /// xtcp 打洞：成功建立 P2P 直连的次数。
    pub p2p_success: Counter,
    /// xtcp 打洞失败、回退到中继的次数。
    pub p2p_failed: Counter,
}

impl Metrics {
    pub fn new() -> Self {
        Self::default()
    }
}

/// 某一时刻的指标快照（全部转成普通数值，便于序列化 / 断言）。
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Snapshot {
    pub uptime_secs: u64,
    pub clients_total: u64,
    pub clients_active: i64,
    pub clients_rejected: u64,
    pub proxies_total: u64,
    pub proxies_active: i64,
    pub proxy_failures: u64,
    pub conns_total: u64,
    pub conns_active: i64,
    pub conns_rejected: u64,
    pub bytes_up: u64,
    pub bytes_down: u64,
    pub http_requests: u64,
    pub https_conns: u64,
    pub tcpmux_conns: u64,
    pub visitor_conns: u64,
    pub visitor_rejected: u64,
    pub p2p_success: u64,
    pub p2p_failed: u64,
}

/// 指标收集器：持有全部原子指标与进程启动时间。
pub struct Registry {
    metrics: Arc<Metrics>,
    started: Instant,
    /// 进程启动的 Unix 秒（供 Prometheus 的 process_start_time_seconds 用）。
    started_unix: u64,
}

impl Registry {
    pub fn new() -> Self {
        Self {
            metrics: Arc::new(Metrics::new()),
            started: Instant::now(),
            started_unix: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0),
        }
    }

    pub fn metrics(&self) -> Arc<Metrics> {
        Arc::clone(&self.metrics)
    }

    pub fn started_unix(&self) -> u64 {
        self.started_unix
    }

    pub fn snapshot(&self) -> Snapshot {
        let m = &self.metrics;
        Snapshot {
            uptime_secs: self.started.elapsed().as_secs(),
            clients_total: m.clients_total.get(),
            clients_active: m.clients_active.get(),
            clients_rejected: m.clients_rejected.get(),
            proxies_total: m.proxies_total.get(),
            proxies_active: m.proxies_active.get(),
            proxy_failures: m.proxy_failures.get(),
            conns_total: m.conns_total.get(),
            conns_active: m.conns_active.get(),
            conns_rejected: m.conns_rejected.get(),
            bytes_up: m.bytes_up.get(),
            bytes_down: m.bytes_down.get(),
            http_requests: m.http_requests.get(),
            https_conns: m.https_conns.get(),
            tcpmux_conns: m.tcpmux_conns.get(),
            visitor_conns: m.visitor_conns.get(),
            visitor_rejected: m.visitor_rejected.get(),
            p2p_success: m.p2p_success.get(),
            p2p_failed: m.p2p_failed.get(),
        }
    }
}

impl Default for Registry {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Prometheus 文本导出
// ---------------------------------------------------------------------------

fn push(out: &mut String, ns: &str, name: &str, help: &str, kind: &str, value: i64) {
    let full = format!("{ns}{name}");
    out.push_str("# HELP ");
    out.push_str(&full);
    out.push(' ');
    out.push_str(help);
    out.push_str("\n# TYPE ");
    out.push_str(&full);
    out.push(' ');
    out.push_str(kind);
    out.push('\n');
    out.push_str(&full);
    out.push(' ');
    out.push_str(&value.to_string());
    out.push_str("\n\n");
}

/// `u64` 计数器 → Prometheus 用的 `i64`（v0.5.6 修审计总报告 L15，低危）。
///
/// # 为什么不能直接 `as i64`
///
/// Rust 的 `as` 在溢出时**回绕**：`u64::MAX as i64 == -1`。
/// 于是一个累加到超过 `i64::MAX`（约 9.22 × 10¹⁸）的计数器会突然变成负数。
///
/// # 为什么这值得修（尽管触发门槛极高）
///
/// Prometheus 对 `counter` 类型有硬性语义：**只能单调递增**，回绕会被
/// 判定为计数器重置（`rate()` / `increase()` 会算出离谱的值）。
/// 尤其 `bytes_up_total` / `bytes_down_total` 是业务量指标 ——
/// 在极高吞吐的部署上（8 EB 流量）真的可能摸到那条线，
/// 而一旦摸到，**所有基于它的告警与容量规划同时失真**。
///
/// ★ 报告把这条定为"纯理论"（需 8 EB 才触发），这个判断是对的；
///   但修它的成本是**一行 `saturating`**，而收益是"这个指标永远不会撒谎"。
///   饱和到 `i64::MAX` 至少保持单调，Prometheus 不会误判重置。
///
/// ★ 用的是**饱和**而不是"报错/丢弃"：监控指标不该因为极端值而整个消失 ——
///   那会让运维在最需要数据的时候失去数据。
fn to_metric_u64(v: u64) -> i64 {
    i64::try_from(v).unwrap_or(i64::MAX)
}

/// 把快照编码成 Prometheus exposition format。
///
/// `namespace` 为空时不加前缀（测试与实践里都更方便拼）。
pub fn encode_prometheus(snap: &Snapshot, namespace: &str) -> String {
    let ns = if namespace.is_empty() {
        String::new()
    } else {
        format!("{}_", namespace.trim_end_matches('_'))
    };
    let mut out = String::with_capacity(4096);

    let counters: &[(&str, &str, i64)] = &[
        (
            "clients_total",
            "历史累计登录的客户端数",
            to_metric_u64(snap.clients_total),
        ),
        (
            "clients_rejected",
            "被拒绝的客户端连接数",
            to_metric_u64(snap.clients_rejected),
        ),
        (
            "proxies_total",
            "历史累计注册的代理数",
            to_metric_u64(snap.proxies_total),
        ),
        (
            "proxy_failures",
            "注册失败的代理数",
            to_metric_u64(snap.proxy_failures),
        ),
        (
            "conns_total",
            "历史累计的转发连接数",
            to_metric_u64(snap.conns_total),
        ),
        (
            "conns_rejected",
            "因资源上限被拒的转发连接数",
            to_metric_u64(snap.conns_rejected),
        ),
        (
            "bytes_up_total",
            "上行的累计字节数",
            to_metric_u64(snap.bytes_up),
        ),
        (
            "bytes_down_total",
            "下行的累计字节数",
            to_metric_u64(snap.bytes_down),
        ),
        (
            "http_requests_total",
            "处理的 HTTP 请求数",
            to_metric_u64(snap.http_requests),
        ),
        (
            "https_conns_total",
            "处理的 HTTPS 透传连接数",
            to_metric_u64(snap.https_conns),
        ),
        (
            "tcpmux_conns_total",
            "处理的 tcpmux CONNECT 隧道数",
            to_metric_u64(snap.tcpmux_conns),
        ),
        (
            "visitor_conns_total",
            "visitor 接入次数",
            to_metric_u64(snap.visitor_conns),
        ),
        (
            "visitor_rejected_total",
            "被拒绝的 visitor 接入次数",
            to_metric_u64(snap.visitor_rejected),
        ),
        (
            "p2p_success_total",
            "xtcp 打洞成功次数",
            to_metric_u64(snap.p2p_success),
        ),
        (
            "p2p_failed_total",
            "xtcp 打洞失败并回退的次数",
            to_metric_u64(snap.p2p_failed),
        ),
    ];
    for (name, help, v) in counters {
        push(&mut out, &ns, name, help, "counter", *v);
    }

    let gauges: &[(&str, &str, i64)] = &[
        ("clients_active", "当前在线的客户端数", snap.clients_active),
        ("proxies_active", "当前生效的代理数", snap.proxies_active),
        ("conns_active", "当前活跃的转发连接数", snap.conns_active),
        (
            "uptime_seconds",
            "服务端已运行的秒数",
            to_metric_u64(snap.uptime_secs),
        ),
    ];
    for (name, help, v) in gauges {
        push(&mut out, &ns, name, help, "gauge", *v);
    }

    out
}

/// 把快照输出为 JSON 对象（dashboard 的 `/api/status` 与 `/metrics?format=json` 用）。
pub fn encode_json(snap: &Snapshot) -> String {
    macro_rules! kv {
        ($k:expr, $v:expr) => {
            format!("\"{}\":{}", $k, $v)
        };
    }
    format!(
        "{{{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{}}}",
        kv!("uptime_secs", snap.uptime_secs),
        kv!("clients_total", snap.clients_total),
        kv!("clients_active", snap.clients_active),
        kv!("clients_rejected", snap.clients_rejected),
        kv!("proxies_total", snap.proxies_total),
        kv!("proxies_active", snap.proxies_active),
        kv!("proxy_failures", snap.proxy_failures),
        kv!("conns_total", snap.conns_total),
        kv!("conns_active", snap.conns_active),
        kv!("conns_rejected", snap.conns_rejected),
        kv!("bytes_up", snap.bytes_up),
        kv!("bytes_down", snap.bytes_down),
        kv!("http_requests", snap.http_requests),
        kv!("https_conns", snap.https_conns),
        kv!("tcpmux_conns", snap.tcpmux_conns),
        kv!("visitor_conns", snap.visitor_conns),
        kv!("visitor_rejected", snap.visitor_rejected),
        kv!("p2p_success", snap.p2p_success),
        kv!("p2p_failed", snap.p2p_failed),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn snap_with(v: u64) -> Snapshot {
        Snapshot {
            uptime_secs: v,
            clients_total: v,
            clients_active: v as i64,
            conns_active: v as i64,
            ..Snapshot::default()
        }
    }

    #[test]
    fn counter_and_gauge_semantics() {
        let c = Counter::default();
        c.inc();
        c.inc_by(4);
        assert_eq!(c.get(), 5);

        let g = Gauge::default();
        g.inc();
        g.inc();
        g.dec();
        assert_eq!(g.get(), 1);
        g.set(-3);
        assert_eq!(g.get(), -3, "连接释放时可能出现短暂负值也不该 panic");
    }

    #[test]
    fn prometheus_output_has_help_and_type_lines() {
        let out = encode_prometheus(&snap_with(7), "nfrp");
        // 每个指标都必须有 HELP 与 TYPE，否则 Prometheus 会把它当 untyped
        for line in out.lines() {
            if line.is_empty() {
                continue;
            }
            assert!(
                line.starts_with("# ") || line.starts_with("nfrp_"),
                "出现了既不是注释也不带命名空间的指标行：{line:?}"
            );
        }
        assert!(out.contains("# HELP nfrp_conns_active "));
        assert!(out.contains("# TYPE nfrp_conns_active gauge"));
        assert!(out.contains("nfrp_conns_active 7\n"));
        assert!(out.contains("# TYPE nfrp_clients_total counter"));
    }

    #[test]
    fn prometheus_namespace_is_optional() {
        let out = encode_prometheus(&Snapshot::default(), "");
        assert!(out.contains("uptime_seconds 0\n"), "{out}");
        assert!(!out.contains("__"), "空命名空间不能产生双下划线");
    }

    #[test]
    fn json_export_is_parseable_shape() {
        let j = encode_json(&snap_with(3));
        assert!(j.starts_with('{') && j.ends_with('}'));
        assert!(j.contains("\"uptime_secs\":3"));
        assert!(j.contains("\"clients_active\":3"));
        // 简单的合法 JSON 检查：逗号数量 = 字段数 - 1（19 个字段）
        assert_eq!(j.matches(',').count(), 18, "{j}");
        assert!(!j.contains(",,"), "{j}");
    }

    #[test]
    fn registry_snapshot_tracks_changes() {
        let reg = Registry::new();
        assert_eq!(reg.snapshot().conns_active, 0);
        let m = reg.metrics();
        m.conns_total.inc();
        m.conns_active.inc();
        m.bytes_up.inc_by(1024);
        let s = reg.snapshot();
        assert_eq!(s.conns_total, 1);
        assert_eq!(s.conns_active, 1);
        assert_eq!(s.bytes_up, 1024);
        m.conns_active.dec();
        assert_eq!(reg.snapshot().conns_active, 0);
        // metrics() 必须返回同一份计数（Arc 语义）
        let m2 = reg.metrics();
        m2.bytes_down.inc();
        assert_eq!(reg.metrics().bytes_down.get(), 1);
    }

    // ------------------------------------------------------------------
    // v0.5.6 回归（审计总报告 L15）：u64 → i64 不得回绕成负数
    // ------------------------------------------------------------------

    /// ★★ L15：越界的 `u64` 计数器必须**饱和**到 `i64::MAX`，绝不能变成负数。
    ///
    /// 直接 `as i64` 会回绕（`u64::MAX as i64 == -1`）。Prometheus 的
    /// `counter` 语义要求**单调递增**，一个突然变负的计数器会被判定为
    /// "计数器重置"，`rate()` / `increase()` 随即算出离谱的值 ——
    /// **基于它的告警与容量规划同时失真**。
    #[test]
    fn 越界计数器必须饱和不得回绕() {
        assert_eq!(to_metric_u64(0), 0);
        assert_eq!(to_metric_u64(1024), 1024);
        assert_eq!(to_metric_u64(i64::MAX as u64), i64::MAX);

        // ★ 关键：越界后必须仍是**正**的
        for v in [i64::MAX as u64 + 1, u64::MAX / 2, u64::MAX - 1, u64::MAX] {
            let got = to_metric_u64(v);
            assert!(got > 0, "u64 {v} 转换后不得变成非正数（回绕），实际 {got}");
            assert_eq!(got, i64::MAX, "越界一律饱和到 i64::MAX");
        }
    }

    /// 导出出来的文本里，计数器不得出现负号。
    #[test]
    fn 导出的计数器不含负值() {
        let snap = Snapshot {
            bytes_up: u64::MAX, // 极端值
            clients_total: u64::MAX,
            ..Default::default()
        };
        let s = encode_prometheus(&snap, "nfrp");

        for line in s.lines() {
            if line.starts_with('#') || line.is_empty() {
                continue;
            }
            let Some((name, val)) = line.rsplit_once(' ') else {
                continue;
            };
            if name.ends_with("_total") {
                let n: i64 = val.parse().unwrap_or_else(|_| panic!("{line} 不是整数"));
                assert!(n >= 0, "{name} 导出了负值 {n}（u64 回绕，L15）：{line}");
            }
        }
        assert!(s.contains("9223372036854775807"), "应饱和到 i64::MAX");
    }
}
