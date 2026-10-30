//! 官方 frp ≥0.52 的 xtcp `NatHole` 控制器（服务端侧）。
//!
//! 这里不是 NFrp 自己那套“UDP HELLO + 服务端回 PEER”的牵线协议，而是
//! 官方 frpc 使用的控制连接消息流：
//!
//! ```text
//! visitor --NatHoleVisitor--------> frps
//! frps --- StartWorkConn --------> provider
//! frps --- NatHoleSid -----------> provider（在刚拿到的工作连接上）
//! provider --NatHoleClient--------> frps
//! visitor <--NatHoleResp---------- frps --NatHoleResp--> provider
//! ```
//!
//! 注意 `NatHoleSid` 必须走**工作连接**，不是控制连接。官方 frpc 的
//! xtcp 代理在 `InWorkConn()` 里读这条消息，控制连接上只有 `NatHoleClient`
//! 和 `NatHoleResp`。
//!
//! 双方拿到 `NatHoleResp` 后，各自在本地 UDP socket 上按
//! `detect_behavior` 发/收探测包，真正的打洞数据不经过 frps。
//!
//! # 覆盖范围
//!
//! 已按官方 `pkg/nathole/{classify,analysis,controller}.go` 实现：
//!
//! * NAT 分类：`EasyNAT` / `HardNAT`、NoChange / IPChanged / PortChanged /
//!   BothChanged、端口差值与“规律端口变化”；
//! * 官方 mode 0~4 行为表、按历史成功率打分和成功回报；
//! * 端口预测（`portsRangeNumber` / `portsRandomNumber`）、随机监听端口
//!   （`listenRandomPorts`）、TTL、send delay、read timeout；
//! * 多个 STUN 映射地址（`candidateAddrs` 全量传给双方，由 frpc 自己探测）。
//!
//! 服务端只负责**分类和下发行为**；真正的 UDP 探测/端口扫描仍由官方 frpc
//! 在本地完成。失败时官方客户端会按 `fallbackTo = "stcp"` 回退中继。

use std::{
    collections::HashMap,
    sync::{Arc, Mutex, OnceLock},
    time::{Duration, Instant},
};

use nfrp_common::frp::msg::{
    FrpMessage, NatHoleClient, NatHoleDetectBehavior, NatHoleReport, NatHoleResp, NatHoleSid,
    NatHoleVisitor, PortsRange, StartWorkConn,
};
use tracing::{debug, info, warn};

use crate::{pool::ClientState, visitor::VisitorEntry};

/// 等 provider 回 `NatHoleClient` 的时间，对齐官方 `NatHoleTimeout`（10 秒）。
const WAIT_CLIENT: Duration = Duration::from_secs(10);

/// 最多同时保留多少条未配对会话。每条只存几个地址字符串，但仍要防
/// 已认证客户端无限建会话；超过就把新的挡回去，让它回退中继。
const MAX_SESSIONS: usize = 2048;

struct Session {
    sid: String,
    proxy_name: String,
    visitor_client: Arc<ClientState>,
    provider_client: Arc<ClientState>,
    visitor_txn: String,
    visitor_protocol: String,
    visitor_mapped: Vec<String>,
    visitor_assisted: Vec<String>,
    created: Instant,
}

fn sessions() -> &'static Mutex<HashMap<String, Session>> {
    static SESSIONS: OnceLock<Mutex<HashMap<String, Session>>> = OnceLock::new();
    SESSIONS.get_or_init(|| Mutex::new(HashMap::new()))
}

fn lock_sessions() -> std::sync::MutexGuard<'static, HashMap<String, Session>> {
    sessions().lock().unwrap_or_else(|e| e.into_inner())
}

/// 官方 `natholeAnalysisDataReserveHours` 的默认值（168 小时）。
const DEFAULT_ANALYSIS_RESERVE_HOURS: u64 = 168;
/// 分析记录上限：保留期再长也不能让内存无限增长。
/// 每条只有两三个 `String`，8192 条约几 MB，足够覆盖一台 frps 的常见规模。
const MAX_ANALYSIS_RECORDS: usize = 8192;

#[derive(Debug, Clone)]
struct AnalysisRecord {
    last_seen: Instant,
    attempts: u64,
    successes: u64,
}

fn analysis() -> &'static Mutex<HashMap<String, AnalysisRecord>> {
    static ANALYSIS: OnceLock<Mutex<HashMap<String, AnalysisRecord>>> = OnceLock::new();
    ANALYSIS.get_or_init(|| Mutex::new(HashMap::new()))
}

fn analysis_reserve() -> &'static Mutex<Duration> {
    static RESERVE: OnceLock<Mutex<Duration>> = OnceLock::new();
    RESERVE.get_or_init(|| Mutex::new(Duration::from_secs(DEFAULT_ANALYSIS_RESERVE_HOURS * 3600)))
}

/// 安装官方 `natholeAnalysisDataReserveHours`。
///
/// 0 按官方语义处理为“不保留历史记录”（配置仍合法；不把 0 当 168，
/// 否则用户明确写 0 想关掉分析缓存却关不掉）。
pub fn configure_analysis_reserve(hours: u64) {
    let secs = hours.saturating_mul(3600);
    *analysis_reserve().lock().unwrap_or_else(|e| e.into_inner()) = Duration::from_secs(secs);
    if hours == 0 {
        analysis().lock().unwrap_or_else(|e| e.into_inner()).clear();
        hole_records()
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clear();
        report_infos()
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clear();
    }
}

fn analysis_key(visitor: &ClientState, provider: &ClientState, proxy: &str) -> String {
    format!("{}|{}|{}", visitor.peer_ip(), provider.peer_ip(), proxy)
}

/// 记录一次尝试，并按保留期清理过期项。
fn record_analysis(key: &str, success: bool) {
    let reserve = *analysis_reserve().lock().unwrap_or_else(|e| e.into_inner());
    let mut g = analysis().lock().unwrap_or_else(|e| e.into_inner());
    if reserve.is_zero() {
        g.clear();
        return;
    }
    g.retain(|_, r| r.last_seen.elapsed() < reserve);
    let entry = g.entry(key.to_string()).or_insert(AnalysisRecord {
        last_seen: Instant::now(),
        attempts: 0,
        successes: 0,
    });
    entry.last_seen = Instant::now();
    entry.attempts += 1;
    if success {
        entry.successes += 1;
    }
    // 上限保护：超过后按最久未使用淘汰，保持 O(n log n) 的极低频清理。
    if g.len() > MAX_ANALYSIS_RECORDS {
        let mut items: Vec<(String, Instant)> =
            g.iter().map(|(k, r)| (k.clone(), r.last_seen)).collect();
        items.sort_by_key(|(_, at)| *at);
        for (k, _) in items.into_iter().take(g.len() - MAX_ANALYSIS_RECORDS) {
            g.remove(&k);
        }
    }
}

/// 官方 `RecommandBehavior` 的 Rust 镜像。
#[derive(Clone, Copy, Default, Debug)]
struct RecommandBehavior {
    role: &'static str,
    ttl: i64,
    send_delay_ms: i64,
    ports_range_number: i64,
    ports_random_number: i64,
    listen_random_ports: i64,
}

const fn behavior(
    role: &'static str,
    ttl: i64,
    send_delay_ms: i64,
    ports_range_number: i64,
    ports_random_number: i64,
    listen_random_ports: i64,
) -> RecommandBehavior {
    RecommandBehavior {
        role,
        ttl,
        send_delay_ms,
        ports_range_number,
        ports_random_number,
        listen_random_ports,
    }
}

const SENDER: &str = "sender";
const RECEIVER: &str = "receiver";

// 完全照抄官方 `analysis.go` 的 mode0Behaviors。
const MODE0: &[(RecommandBehavior, RecommandBehavior)] = &[
    (
        behavior(SENDER, 0, 0, 0, 0, 0),
        behavior(RECEIVER, 7, 0, 0, 0, 0),
    ),
    (
        behavior(RECEIVER, 7, 0, 0, 0, 0),
        behavior(SENDER, 0, 0, 0, 0, 0),
    ),
    (
        behavior(SENDER, 0, 0, 0, 0, 0),
        behavior(RECEIVER, 4, 0, 0, 0, 0),
    ),
    (
        behavior(RECEIVER, 4, 0, 0, 0, 0),
        behavior(SENDER, 0, 0, 0, 0, 0),
    ),
    (
        behavior(SENDER, 0, 0, 0, 0, 0),
        behavior(RECEIVER, 0, 0, 0, 0, 0),
    ),
    (
        behavior(RECEIVER, 0, 0, 0, 0, 0),
        behavior(SENDER, 0, 0, 0, 0, 0),
    ),
    (
        behavior(SENDER, 0, 5000, 0, 0, 0),
        behavior(RECEIVER, 0, 0, 0, 0, 0),
    ),
    (
        behavior(SENDER, 0, 10000, 0, 0, 0),
        behavior(RECEIVER, 0, 0, 0, 0, 0),
    ),
    (
        behavior(RECEIVER, 0, 0, 0, 0, 0),
        behavior(SENDER, 0, 5000, 0, 0, 0),
    ),
    (
        behavior(RECEIVER, 0, 0, 0, 0, 0),
        behavior(SENDER, 0, 10000, 0, 0, 0),
    ),
];

const MODE1: &[(RecommandBehavior, RecommandBehavior)] = &[
    (
        behavior(SENDER, 0, 0, 0, 0, 0),
        behavior(RECEIVER, 7, 0, 10, 0, 0),
    ),
    (
        behavior(SENDER, 0, 2000, 0, 0, 0),
        behavior(RECEIVER, 7, 0, 10, 0, 0),
    ),
    (
        behavior(SENDER, 0, 0, 0, 0, 0),
        behavior(RECEIVER, 4, 0, 10, 0, 0),
    ),
    (
        behavior(SENDER, 0, 2000, 0, 0, 0),
        behavior(RECEIVER, 4, 0, 10, 0, 0),
    ),
    (
        behavior(SENDER, 0, 0, 0, 0, 0),
        behavior(RECEIVER, 0, 0, 10, 0, 0),
    ),
    (
        behavior(SENDER, 0, 2000, 0, 0, 0),
        behavior(RECEIVER, 0, 0, 10, 0, 0),
    ),
];

const MODE2: &[(RecommandBehavior, RecommandBehavior)] = &[
    (
        behavior(SENDER, 0, 3000, 0, 1000, 0),
        behavior(RECEIVER, 7, 0, 0, 0, 256),
    ),
    (
        behavior(SENDER, 0, 3000, 0, 1000, 0),
        behavior(RECEIVER, 4, 0, 0, 0, 256),
    ),
    (
        behavior(SENDER, 0, 3000, 0, 1000, 0),
        behavior(RECEIVER, 0, 0, 0, 0, 256),
    ),
];

const MODE3: &[(RecommandBehavior, RecommandBehavior)] = &[
    (
        behavior(SENDER, 0, 0, 10, 0, 0),
        behavior(RECEIVER, 7, 0, 10, 0, 0),
    ),
    (
        behavior(SENDER, 0, 0, 10, 0, 0),
        behavior(RECEIVER, 4, 0, 10, 0, 0),
    ),
    (
        behavior(SENDER, 0, 0, 10, 0, 0),
        behavior(RECEIVER, 0, 0, 10, 0, 0),
    ),
    (
        behavior(RECEIVER, 7, 0, 10, 0, 0),
        behavior(SENDER, 0, 0, 10, 0, 0),
    ),
    (
        behavior(RECEIVER, 4, 0, 10, 0, 0),
        behavior(SENDER, 0, 0, 10, 0, 0),
    ),
    (
        behavior(RECEIVER, 0, 0, 10, 0, 0),
        behavior(SENDER, 0, 0, 10, 0, 0),
    ),
];

const MODE4: &[(RecommandBehavior, RecommandBehavior)] = &[
    (
        behavior(SENDER, 0, 3000, 0, 1000, 0),
        behavior(RECEIVER, 7, 0, 2, 0, 256),
    ),
    (
        behavior(SENDER, 0, 3000, 0, 1000, 0),
        behavior(RECEIVER, 4, 0, 2, 0, 256),
    ),
    (
        behavior(SENDER, 0, 3000, 0, 1000, 0),
        behavior(RECEIVER, 0, 0, 2, 0, 256),
    ),
];

fn behaviors_by_mode(mode: i64) -> &'static [(RecommandBehavior, RecommandBehavior)] {
    match mode {
        1 => MODE1,
        2 => MODE2,
        3 => MODE3,
        4 => MODE4,
        _ => MODE0,
    }
}

/// 官方 `ClassifyNATFeature` 的 Rust 镜像。
#[derive(Debug, Clone, PartialEq, Eq)]
struct NatFeature {
    nat_type: &'static str,
    behavior: &'static str,
    ports_difference: i64,
    regular_ports_change: bool,
    public_network: bool,
}

fn split_host_port(addr: &str) -> Result<(String, String), String> {
    if let Ok(sa) = addr.parse::<std::net::SocketAddr>() {
        return Ok((sa.ip().to_string(), sa.port().to_string()));
    }
    // 兼容带方括号的 IPv6 与主机名；官方位置只会拿到 IP。
    if let Some((host, port)) = addr.rsplit_once(':') {
        let host = host.trim_start_matches('[').trim_end_matches(']');
        if !host.is_empty() && port.parse::<u16>().is_ok() {
            return Ok((host.to_string(), port.to_string()));
        }
    }
    Err(format!("invalid address: {addr}"))
}

fn parse_ips(addrs: &[String]) -> Vec<String> {
    addrs
        .iter()
        .filter_map(|a| split_host_port(a).ok().map(|(ip, _)| ip))
        .collect()
}

fn classify_nat_feature(addresses: &[String], local_ips: &[String]) -> Result<NatFeature, String> {
    if addresses.len() <= 1 {
        return Err("not enough addresses".to_string());
    }
    let mut feature = NatFeature {
        nat_type: "EasyNAT",
        behavior: "BehaviorNoChange",
        ports_difference: 0,
        regular_ports_change: false,
        public_network: false,
    };
    let mut ip_changed = false;
    let mut port_changed = false;
    let mut base_ip = String::new();
    let mut base_port = String::new();
    let mut port_max = 0i64;
    let mut port_min = 0i64;

    for addr in addresses {
        let (ip, port) = split_host_port(addr)?;
        let port_num = port
            .parse::<i64>()
            .map_err(|_| format!("invalid port in {addr}"))?;
        if local_ips.iter().any(|local| local == &ip) {
            feature.public_network = true;
        }
        if base_ip.is_empty() {
            base_ip = ip;
            base_port = port;
            port_max = port_num;
            port_min = port_num;
            continue;
        }
        port_max = port_max.max(port_num);
        port_min = port_min.min(port_num);
        if base_ip != ip {
            ip_changed = true;
        }
        if base_port != port {
            port_changed = true;
        }
    }

    if ip_changed && port_changed {
        feature.nat_type = "HardNAT";
        feature.behavior = "BehaviorBothChanged";
    } else if ip_changed {
        feature.nat_type = "HardNAT";
        feature.behavior = "BehaviorIPChanged";
    } else if port_changed {
        feature.nat_type = "HardNAT";
        feature.behavior = "BehaviorPortChanged";
    }
    if feature.behavior == "BehaviorPortChanged" {
        feature.ports_difference = port_max - port_min;
        feature.regular_ports_change = (1..=5).contains(&feature.ports_difference);
    }
    Ok(feature)
}

fn classify_feature_count(features: &[&NatFeature]) -> (usize, usize, usize) {
    let mut easy = 0;
    let mut hard = 0;
    let mut regular = 0;
    for f in features {
        if f.nat_type == "EasyNAT" {
            easy += 1;
        } else {
            hard += 1;
            if f.regular_ports_change {
                regular += 1;
            }
        }
    }
    (easy, hard, regular)
}

#[derive(Debug, Clone)]
struct BehaviorScore {
    mode: i64,
    index: usize,
    score: i32,
}

#[derive(Debug)]
struct HoleRecords {
    scores: Vec<BehaviorScore>,
    last_update: Instant,
}

fn scores_by_mode(mode: i64, default: i32) -> Vec<BehaviorScore> {
    behaviors_by_mode(mode)
        .iter()
        .enumerate()
        .map(|(index, _)| BehaviorScore {
            mode,
            index,
            score: default,
        })
        .collect()
}

fn scores_by_mode2(mode: i64, sender_score: i32, receiver_score: i32) -> Vec<BehaviorScore> {
    behaviors_by_mode(mode)
        .iter()
        .enumerate()
        .map(|(index, (a, _))| BehaviorScore {
            mode,
            index,
            score: if a.role == SENDER {
                sender_score
            } else {
                receiver_score
            },
        })
        .collect()
}

impl HoleRecords {
    fn new(c: &NatFeature, v: &NatFeature) -> Self {
        let mut scores = Vec::new();
        let (easy, hard, regular) = classify_feature_count(&[c, v]);
        let append_mode0 = |scores: &mut Vec<BehaviorScore>| {
            if c.public_network {
                // client 是公网：让 client 当 sender 会失败，官方把 client
                // 的 sender 分数压到 0、receiver 分数设为 1。
                scores.extend(scores_by_mode2(0, 0, 1));
            } else if v.public_network {
                scores.extend(scores_by_mode2(0, 1, 0));
            } else {
                scores.extend(scores_by_mode(0, 0));
            }
        };

        if easy == 2 {
            append_mode0(&mut scores);
        } else if hard == 1 && regular == 1 {
            scores.extend(scores_by_mode(1, 0));
            scores.extend(scores_by_mode(2, 0));
            append_mode0(&mut scores);
        } else if hard == 1 && regular == 0 {
            scores.extend(scores_by_mode(2, 0));
            scores.extend(scores_by_mode(1, 0));
            append_mode0(&mut scores);
        } else if hard == 2 && regular == 2 {
            scores.extend(scores_by_mode(3, 0));
            scores.extend(scores_by_mode(4, 0));
        } else if hard == 2 && regular == 1 {
            scores.extend(scores_by_mode(4, 0));
        } else {
            scores.extend(scores_by_mode(0, 1));
            scores.extend(scores_by_mode(1, 1));
            scores.extend(scores_by_mode(3, 1));
        }
        Self {
            scores,
            last_update: Instant::now(),
        }
    }

    fn recommend(&mut self) -> (i64, usize) {
        if self.scores.is_empty() {
            return (0, 0);
        }
        // 官方 `slices.MaxFunc` 在并列时保留**第一个**，Rust 的 max_by_key
        // 会保留最后一个，因此这里手写循环。
        let mut best = 0usize;
        for i in 1..self.scores.len() {
            if self.scores[i].score > self.scores[best].score {
                best = i;
            }
        }
        let mode = self.scores[best].mode;
        let index = self.scores[best].index;
        self.scores[best].score -= 1;
        self.last_update = Instant::now();
        (mode, index)
    }

    fn report_success(&mut self, mode: i64, index: usize) {
        self.last_update = Instant::now();
        if let Some(s) = self
            .scores
            .iter_mut()
            .find(|s| s.mode == mode && s.index == index)
        {
            s.score = (s.score + 2).min(10);
        }
    }
}

fn hole_records() -> &'static Mutex<HashMap<String, HoleRecords>> {
    static RECORDS: OnceLock<Mutex<HashMap<String, HoleRecords>>> = OnceLock::new();
    RECORDS.get_or_init(|| Mutex::new(HashMap::new()))
}

fn fingerprint_key(
    c: &NatFeature,
    v: &NatFeature,
    c_addrs: &[String],
    v_addrs: &[String],
) -> String {
    // 官方用 MD5 拼接同样的字段；这里直接保留可读串，语义完全一致，
    // 而且不需要为一个内部缓存键额外引入 md5 依赖。
    let v_ip = parse_ips(v_addrs).into_iter().next().unwrap_or_default();
    let c_ip = parse_ips(c_addrs).into_iter().next().unwrap_or_default();
    format!(
        "{}|{}|{}|{}|{}|{}|{}|{}",
        v_ip,
        v.nat_type,
        v.behavior,
        v.regular_ports_change,
        c_ip,
        c.nat_type,
        c.behavior,
        c.regular_ports_change
    )
}

/// 官方 `Analyzer.GetRecommandBehaviors`：选 mode/index，并按方向交换行为。
fn get_recommand_behaviors(
    key: &str,
    c: &NatFeature,
    v: &NatFeature,
) -> (i64, usize, RecommandBehavior, RecommandBehavior) {
    let mut g = hole_records().lock().unwrap_or_else(|e| e.into_inner());
    let reserve = *analysis_reserve().lock().unwrap_or_else(|e| e.into_inner());
    g.retain(|_, r| reserve.is_zero() || r.last_update.elapsed() < reserve);
    let records = g
        .entry(key.to_string())
        .or_insert_with(|| HoleRecords::new(c, v));
    let (mode, index) = records.recommend();
    let behaviors = behaviors_by_mode(mode);
    let (mut c_behavior, mut v_behavior) = behaviors
        .get(index)
        .copied()
        .unwrap_or((RecommandBehavior::default(), RecommandBehavior::default()));
    match mode {
        1 => {
            // HardNAT 永远是 sender。
            if c.nat_type == "EasyNAT" {
                std::mem::swap(&mut c_behavior, &mut v_behavior);
            }
        }
        2 => {
            // HardNAT 永远是 receiver。
            if c.nat_type == "HardNAT" {
                std::mem::swap(&mut c_behavior, &mut v_behavior);
            }
        }
        // 规律端口变化的一侧是 sender。
        4 if !c.regular_ports_change => {
            std::mem::swap(&mut c_behavior, &mut v_behavior);
        }
        4 => {}
        _ => {}
    }
    (mode, index, c_behavior, v_behavior)
}

fn report_success(key: &str, mode: i64, index: usize) {
    let mut g = hole_records().lock().unwrap_or_else(|e| e.into_inner());
    if let Some(r) = g.get_mut(key) {
        r.report_success(mode, index);
    }
}

/// sid -> (analysis key, mode, index)，供 `NatHoleReport` 回写成功率。
struct ReportInfo {
    key: String,
    mode: i64,
    index: usize,
    created: Instant,
}

fn report_infos() -> &'static Mutex<HashMap<String, ReportInfo>> {
    static REPORTS: OnceLock<Mutex<HashMap<String, ReportInfo>>> = OnceLock::new();
    REPORTS.get_or_init(|| Mutex::new(HashMap::new()))
}

/// 官方 `Controller.HandleReport`：只有 `success = true` 才加分。
pub fn handle_report(m: &NatHoleReport) {
    if m.sid.is_empty() {
        return;
    }
    let info = {
        let mut g = report_infos().lock().unwrap_or_else(|e| e.into_inner());
        g.retain(|_, r| r.created.elapsed() < Duration::from_secs(60));
        g.remove(&m.sid)
    };
    if let Some(info) = info {
        if m.success {
            report_success(&info.key, info.mode, info.index);
        }
        info!(
            sid = %m.sid,
            success = m.success,
            mode = info.mode,
            index = info.index,
            "官方 NatHole 打洞结果回报"
        );
    } else {
        debug!(sid = %m.sid, success = m.success, "NatHoleReport 对应会话已过期");
    }
}

fn get_range_ports(addrs: &[String], difference: i64, max_number: i64) -> Vec<PortsRange> {
    if max_number <= 0 {
        return Vec::new();
    }
    let Some(addr) = addrs.last() else {
        return Vec::new();
    };
    let Ok((_, port)) = split_host_port(addr) else {
        return Vec::new();
    };
    let Ok(port) = port.parse::<i64>() else {
        return Vec::new();
    };
    vec![PortsRange {
        from: (port - difference - 5).max(port - max_number).max(1),
        to: (port + difference + 5).min(port + max_number).min(65535),
    }]
}

/// visitor 的第一条消息只是 `pre_check`：官方 frpc 用它确认
/// “provider 在不在、我这个 user 能不能访问”，此时还没有 NAT 地址。
///
/// 成功后必须回 `error` 为空的响应；失败要回明确的错误，官方客户端
/// 才会按 `fallbackTo = "stcp"` 回退。
pub fn precheck(entry: &VisitorEntry, visitor_user: &str) -> Result<(), String> {
    if !entry.check_user(visitor_user) {
        return Err(format!(
            "xtcp visitor user [{}] not allowed for [{}]",
            visitor_user, entry.proxy_name
        ));
    }
    Ok(())
}

/// 收到带 `mapped_addrs` 的官方 `NatHoleVisitor` 后开一条会话。
///
/// 调用方（[`crate::p2p::handle_nat_hole_visitor`]）已完成 provider 存在性、
/// 签名、用户白名单校验；这里只负责配对和超时。
pub fn start_session(
    visitor_client: &Arc<ClientState>,
    entry: &Arc<VisitorEntry>,
    m: &NatHoleVisitor,
) -> Result<(), String> {
    if m.mapped_addrs.is_empty() {
        return Err("nat hole visitor has no mapped_addrs".to_string());
    }

    let sid = format!(
        "{}{}",
        nfrp_common::util::now_unix_secs(),
        nfrp_common::util::new_run_id()
    );
    let provider_client = entry.client.clone();
    let session = Session {
        sid: sid.clone(),
        proxy_name: entry.proxy_name.clone(),
        visitor_client: visitor_client.clone(),
        provider_client: provider_client.clone(),
        visitor_txn: m.transaction_id.clone(),
        visitor_protocol: m.protocol.clone(),
        visitor_mapped: m.mapped_addrs.clone(),
        visitor_assisted: m.assisted_addrs.clone(),
        created: Instant::now(),
    };

    {
        let mut g = lock_sessions();
        g.retain(|_, s| s.created.elapsed() < WAIT_CLIENT);
        if g.len() >= MAX_SESSIONS {
            return Err("too many pending nat hole sessions".to_string());
        }
        g.insert(sid.clone(), session);
    }
    // 官方 `natholeAnalysisDataReserveHours`：每次配对尝试都留一条记录，
    // 保留期到期后在下一次写入时清理。当前 mode0 不用它挑选行为，但这条
    // 数据是真实产生/过期的，不是一个只解析不生效的配置。
    record_analysis(
        &analysis_key(visitor_client, &provider_client, &entry.proxy_name),
        false,
    );

    // 官方 frps 的 xtcp 并不是把 `NatHoleClient` 发在 provider 的控制连接上，
    // 而是先向 provider 要一条工作连接，在这条连接上写 `NatHoleSid`，然后
    // provider 才用控制连接回 `NatHoleClient{sid, mapped_addrs}`。
    //
    // 先前这里直接把 `NatHoleClient` 投递到控制连接，官方 frpc 的 xtcp
    // 处理器根本不会读它（它在等 `StartWorkConn`），表现为 visitor 5 秒后
    // `context deadline exceeded`、服务端 10 秒后报“等 provider 超时”。
    // 真实 0.71 frpc e2e 暴露了这一点，因此按官方 `server/proxy/xtcp.go`
    // 的 `writeNatHoleSid` 流程补上。
    //
    // 不能在这里 await：本函数跑在 visitor 的控制连接循环里，等 provider
    // 交工作连接会一起阻塞 visitor 的响应。用独立任务做，失败就把明确错误
    // 投递回 visitor 的控制通道。
    let sid_for_work = sid.clone();
    let provider_for_work = provider_client.clone();
    let visitor_for_work = visitor_client.clone();
    let txn_for_work = m.transaction_id.clone();
    let proxy_for_work = entry.proxy_name.clone();
    tokio::spawn(async move {
        let work = provider_for_work
            .acquire_work_conn_within(Duration::from_secs(5))
            .await;
        let Some(work) = work else {
            let removed = lock_sessions().remove(&sid_for_work);
            if removed.is_some() {
                warn!(sid = %sid_for_work, "provider 未在 5 秒内交出 NatHole 工作连接");
                send_error(
                    &visitor_for_work,
                    &txn_for_work,
                    "provider did not provide a work connection for nat hole",
                );
            }
            return;
        };
        let mut work_conn = work.conn;
        // 官方 `GetWorkConnFromPool` 在拿到工作连接后**立即**写一条
        // `StartWorkConn`，frpc 的 `handleReqWorkConn` 靠它决定把这条连接
        // 交给哪个代理。直接写 `NatHoleSid` 会让 frpc 用错误的类型读
        // StartWorkConn，随后按空代理名分发失败，工作连接被丢弃。
        let err = match work_conn
            .send_msg(&FrpMessage::StartWorkConn(StartWorkConn {
                proxy_name: proxy_for_work,
                ..Default::default()
            }))
            .await
        {
            Err(e) => Some(format!("failed to send StartWorkConn: {e:#}")),
            Ok(()) => match work_conn
                .send_msg(&FrpMessage::NatHoleSid(NatHoleSid {
                    sid: sid_for_work.clone(),
                    ..Default::default()
                }))
                .await
            {
                Err(e) => Some(format!("failed to send NatHoleSid: {e:#}")),
                Ok(()) => None,
            },
        };
        if let Some(err) = err {
            let removed = lock_sessions().remove(&sid_for_work);
            if removed.is_some() {
                warn!(sid = %sid_for_work, "向 provider 发送 NatHole 工作连接消息失败：{err}");
                send_error(&visitor_for_work, &txn_for_work, err);
            }
        }
        // 官方写完 Sid 就关闭工作连接；provider 的数据面走 UDP。
        drop(work_conn);
    });

    // 独立超时任务，只把错误投递回控制通道。
    let sid_for_timeout = sid.clone();
    let txn = m.transaction_id.clone();
    tokio::spawn(async move {
        tokio::time::sleep(WAIT_CLIENT).await;
        let removed = lock_sessions().remove(&sid_for_timeout);
        if let Some(s) = removed {
            warn!(
                sid = %sid_for_timeout,
                proxy = %s.proxy_name,
                "等待 provider 的 NatHoleClient 超时"
            );
            s.visitor_client
                .forward_to_client(FrpMessage::NatHoleResp(NatHoleResp {
                    transaction_id: txn,
                    error: "wait for provider NatHoleClient timeout".to_string(),
                    ..Default::default()
                }));
        }
    });

    debug!(
        %sid, proxy = %entry.proxy_name, txn = %m.transaction_id,
        "已创建官方 NatHole 会话，等待 provider 回 NatHoleClient"
    );
    Ok(())
}

/// 处理 provider 回来的 `NatHoleClient`：配对成功后分别给双方回
/// `NatHoleResp`。返回 `true` 表示确实消费了一条已知会话。
pub fn handle_client(provider_client: &Arc<ClientState>, m: &NatHoleClient) -> bool {
    if m.sid.is_empty() {
        return false;
    }

    // 先确认 sid 存在且确实是这个 provider 的会话，再摘除；否则一个
    // 认证过的其他客户端只要猜到 sid 就能把别人的会话顶掉。
    let session = {
        let mut g = lock_sessions();
        match g.get(&m.sid) {
            Some(s) if Arc::ptr_eq(&s.provider_client, provider_client) => g.remove(&m.sid),
            _ => None,
        }
    };
    let Some(s) = session else {
        return false;
    };

    if s.proxy_name != m.proxy_name {
        warn!(
            sid = %m.sid,
            expected = %s.proxy_name,
            got = %m.proxy_name,
            "NatHoleClient 的代理名不匹配，丢弃"
        );
        send_error(
            &s.visitor_client,
            &s.visitor_txn,
            "NatHoleClient proxy_name mismatch",
        );
        return true;
    }

    if m.mapped_addrs.is_empty() {
        send_error(
            &s.visitor_client,
            &s.visitor_txn,
            "provider NatHoleClient has no mapped_addrs",
        );
        send_error(
            provider_client,
            &m.transaction_id,
            "provider NatHoleClient has no mapped_addrs",
        );
        return true;
    }

    let protocol = if s.visitor_protocol.is_empty() {
        // 官方 0.71 的 visitor 会带 `quic`；没带时按官方默认走 quic。
        "quic"
    } else {
        &s.visitor_protocol
    };

    let c_feature = match classify_nat_feature(&m.mapped_addrs, &parse_ips(&m.assisted_addrs)) {
        Ok(f) => f,
        Err(e) => {
            let msg = format!("classify provider nat feature error: {e}");
            send_error(&s.visitor_client, &s.visitor_txn, msg.clone());
            send_error(provider_client, &m.transaction_id, msg);
            return true;
        }
    };
    let v_feature = match classify_nat_feature(&s.visitor_mapped, &parse_ips(&s.visitor_assisted)) {
        Ok(f) => f,
        Err(e) => {
            let msg = format!("classify visitor nat feature error: {e}");
            send_error(&s.visitor_client, &s.visitor_txn, msg.clone());
            send_error(provider_client, &m.transaction_id, msg);
            return true;
        }
    };

    let key = fingerprint_key(&c_feature, &v_feature, &m.mapped_addrs, &s.visitor_mapped);
    let (mode, index, c_behavior, v_behavior) =
        get_recommand_behaviors(&key, &c_feature, &v_feature);

    // 官方 `analysis()` 的 read timeout：两端最大 send delay + 5s；任一端
    // 使用随机监听端口时再留 30s 扫描窗口。
    let mut timeout_ms = c_behavior.send_delay_ms.max(v_behavior.send_delay_ms) + 5_000;
    if c_behavior.listen_random_ports > 0 || v_behavior.listen_random_ports > 0 {
        timeout_ms += 30_000;
    }

    let v_read_timeout = timeout_ms - v_behavior.send_delay_ms;
    let c_read_timeout = timeout_ms - c_behavior.send_delay_ms;
    let visitor_resp = build_response(
        &s.visitor_txn,
        &s.sid,
        protocol,
        &m.mapped_addrs,
        &m.assisted_addrs,
        detect_behavior(
            mode,
            v_behavior,
            v_read_timeout,
            c_feature.ports_difference,
            &m.mapped_addrs,
        ),
    );
    let provider_resp = build_response(
        &m.transaction_id,
        &s.sid,
        protocol,
        &s.visitor_mapped,
        &s.visitor_assisted,
        detect_behavior(
            mode,
            c_behavior,
            c_read_timeout,
            v_feature.ports_difference,
            &s.visitor_mapped,
        ),
    );

    {
        let mut g = report_infos().lock().unwrap_or_else(|e| e.into_inner());
        g.retain(|_, r| r.created.elapsed() < Duration::from_secs(60));
        g.insert(
            s.sid.clone(),
            ReportInfo {
                key,
                mode,
                index,
                created: Instant::now(),
            },
        );
    }

    record_analysis(
        &analysis_key(&s.visitor_client, provider_client, &s.proxy_name),
        true,
    );
    info!(
        sid = %s.sid,
        proxy = %s.proxy_name,
        mode,
        index,
        provider_nat = ?c_feature,
        visitor_nat = ?v_feature,
        provider_role = c_behavior.role,
        visitor_role = v_behavior.role,
        "官方 NatHole 配对成功，已按 NAT 分类下发 mode {mode} index {index}"
    );
    s.visitor_client
        .forward_to_client(FrpMessage::NatHoleResp(visitor_resp));
    provider_client.forward_to_client(FrpMessage::NatHoleResp(provider_resp));
    true
}

fn build_response(
    transaction_id: &str,
    sid: &str,
    protocol: &str,
    candidate_addrs: &[String],
    assisted_addrs: &[String],
    detect_behavior: NatHoleDetectBehavior,
) -> NatHoleResp {
    // 官方 `newNatHoleResponse` 用 `slices.Compact` 去掉**相邻**重复地址。
    let mut candidates = candidate_addrs.to_vec();
    candidates.dedup();
    let mut assisted = assisted_addrs.to_vec();
    assisted.dedup();
    NatHoleResp {
        transaction_id: transaction_id.to_string(),
        sid: sid.to_string(),
        protocol: protocol.to_string(),
        candidate_addrs: candidates,
        assisted_addrs: assisted,
        detect_behavior,
        ..Default::default()
    }
}

fn detect_behavior(
    mode: i64,
    behavior: RecommandBehavior,
    read_timeout_ms: i64,
    ports_difference: i64,
    candidate_addrs: &[String],
) -> NatHoleDetectBehavior {
    NatHoleDetectBehavior {
        role: behavior.role.to_string(),
        mode,
        ttl: behavior.ttl,
        send_delay_ms: behavior.send_delay_ms,
        read_timeout_ms,
        candidate_ports: get_range_ports(
            candidate_addrs,
            ports_difference,
            behavior.ports_range_number,
        ),
        send_random_ports: behavior.ports_random_number,
        listen_random_ports: behavior.listen_random_ports,
    }
}

fn send_error(client: &ClientState, txn: &str, err: impl Into<String>) {
    client.forward_to_client(FrpMessage::NatHoleResp(NatHoleResp {
        transaction_id: txn.to_string(),
        error: err.into(),
        ..Default::default()
    }));
}

/// 清理会话表（测试与进程退出前用；正常超时由 spawn 的任务负责）。
#[cfg(test)]
pub(crate) fn clear_sessions() {
    lock_sessions().clear();
}

#[cfg(test)]
pub(crate) fn clear_analysis() {
    analysis().lock().unwrap_or_else(|e| e.into_inner()).clear();
}

#[cfg(test)]
pub(crate) fn analysis_snapshot() -> Vec<(String, u64, u64)> {
    analysis()
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .iter()
        .map(|(k, r)| (k.clone(), r.attempts, r.successes))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        pool::{CtrlCmd, WorkItem},
        registry::ServerLimits,
    };
    use nfrp_common::frp::{conn::FrpConn, WireVersion};
    use tokio::sync::mpsc;

    fn client(user: &str, ip: &str) -> (Arc<ClientState>, mpsc::UnboundedReceiver<CtrlCmd>) {
        let (tx, rx) = mpsc::unbounded_channel();
        let (conn, backlog, proxy) = ServerLimits::default().per_client();
        let c = Arc::new(ClientState::new(
            "run".into(),
            "id".into(),
            user.to_string(),
            tx,
            Duration::from_secs(60),
            Duration::from_secs(10),
            Default::default(),
            false,
            WireVersion::V1,
            conn,
            backlog,
            0,
            proxy,
            ip.parse().unwrap(),
        ));
        (c, rx)
    }

    fn test_lock() -> &'static tokio::sync::Mutex<()> {
        static LOCK: OnceLock<tokio::sync::Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| tokio::sync::Mutex::new(()))
    }

    #[test]
    fn 分析记录受保留期与_0_小时开关控制() {
        let _l = test_lock().blocking_lock();
        clear_analysis();
        configure_analysis_reserve(1);
        record_analysis("a|b|p", false);
        record_analysis("a|b|p", true);
        let snap = analysis_snapshot();
        assert_eq!(snap.len(), 1);
        assert_eq!(snap[0].1, 2);
        assert_eq!(snap[0].2, 1);

        // 0 小时 = 不保留历史（与官方“保留 0 小时”一致），不能装作默认 168。
        configure_analysis_reserve(0);
        assert!(analysis_snapshot().is_empty());
        configure_analysis_reserve(168);
    }

    #[test]
    fn classify_官方三种_nat_行为() {
        let easy =
            classify_nat_feature(&["1.2.3.4:1000".into(), "1.2.3.4:1000".into()], &[]).unwrap();
        assert_eq!(easy.nat_type, "EasyNAT");
        assert_eq!(easy.behavior, "BehaviorNoChange");

        let regular =
            classify_nat_feature(&["1.2.3.4:1000".into(), "1.2.3.4:1002".into()], &[]).unwrap();
        assert_eq!(regular.nat_type, "HardNAT");
        assert_eq!(regular.behavior, "BehaviorPortChanged");
        assert_eq!(regular.ports_difference, 2);
        assert!(regular.regular_ports_change);

        let both =
            classify_nat_feature(&["1.2.3.4:1000".into(), "5.6.7.8:1200".into()], &[]).unwrap();
        assert_eq!(both.nat_type, "HardNAT");
        assert_eq!(both.behavior, "BehaviorBothChanged");
        assert!(!both.regular_ports_change);

        let public = classify_nat_feature(
            &["127.0.0.1:1000".into(), "127.0.0.1:1000".into()],
            &["127.0.0.1".into()],
        )
        .unwrap();
        assert!(public.public_network);
        assert_eq!(public.nat_type, "EasyNAT");
        assert!(classify_nat_feature(&["1.2.3.4:1".into()], &[]).is_err());
    }

    #[test]
    fn mode_选择与端口预测范围() {
        hole_records()
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clear();
        let c = classify_nat_feature(&["1.1.1.1:1000".into(), "1.1.1.1:1002".into()], &[]).unwrap();
        let v = classify_nat_feature(&["2.2.2.2:2000".into(), "2.2.2.2:2000".into()], &[]).unwrap();
        let (mode, index, cb, vb) = get_recommand_behaviors("t-hard-easy", &c, &v);
        assert_eq!((mode, index), (1, 0), "HardNAT + 规律端口应先试 mode1");
        assert_eq!(cb.role, SENDER, "HardNAT 一侧必须是 sender");
        assert_eq!(vb.role, RECEIVER);

        let ports = get_range_ports(&["2.2.2.2:2000".into()], 2, 10);
        assert_eq!(ports.len(), 1);
        assert_eq!(ports[0].from, 1993);
        assert_eq!(ports[0].to, 2007);

        let behavior = detect_behavior(1, vb, 5_000, 2, &["2.2.2.2:2000".into()]);
        assert_eq!(behavior.mode, 1);
        assert_eq!(behavior.candidate_ports[0].from, 1993);
        assert_eq!(behavior.read_timeout_ms, 5_000);
    }

    #[test]
    fn 公网一侧永远做_receiver() {
        hole_records()
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clear();
        let c = classify_nat_feature(
            &["127.0.0.1:1000".into(), "127.0.0.1:1000".into()],
            &["127.0.0.1".into()],
        )
        .unwrap();
        let v = classify_nat_feature(&["2.2.2.2:2000".into(), "2.2.2.2:2000".into()], &[]).unwrap();
        let (mode, index, cb, vb) = get_recommand_behaviors("t-public", &c, &v);
        assert_eq!(mode, 0);
        assert_eq!(index, 1, "公网一侧的 receiver 行为应优先");
        assert_eq!(cb.role, RECEIVER);
        assert_eq!(vb.role, SENDER);
    }

    #[test]
    fn nat_report_成功会回写分数() {
        hole_records()
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clear();
        let c = classify_nat_feature(&["1.1.1.1:1000".into(), "1.1.1.1:1002".into()], &[]).unwrap();
        let v = classify_nat_feature(&["2.2.2.2:2000".into(), "2.2.2.2:2000".into()], &[]).unwrap();
        let (mode, index, _, _) = get_recommand_behaviors("t-report", &c, &v);
        let score = |m, i| {
            hole_records()
                .lock()
                .unwrap()
                .get("t-report")
                .unwrap()
                .scores
                .iter()
                .find(|s| s.mode == m && s.index == i)
                .unwrap()
                .score
        };
        let before = score(mode, index);
        report_success("t-report", mode, index);
        assert_eq!(score(mode, index), (before + 2).min(10));
    }

    fn take_nat_hole_resp(rx: &mut mpsc::UnboundedReceiver<CtrlCmd>) -> NatHoleResp {
        match rx.try_recv().expect("expected queued message") {
            CtrlCmd::Send(msg) => match *msg {
                FrpMessage::NatHoleResp(resp) => resp,
                other => panic!("unexpected message: {}", other.name()),
            },
            _ => panic!("unexpected command"),
        }
    }

    #[test]
    fn precheck_uses_provider_user_and_allowlist() {
        let (provider, _prx) = client("provider", "5.6.7.8");
        let entry = VisitorEntry {
            proxy_name: "xtcp-test".into(),
            secret_key: "sk".into(),
            allow_users: vec![],
            provider_user: "provider".into(),
            client: provider,
            proxy_type: "xtcp".into(),
        };
        assert!(precheck(&entry, "provider").is_ok());
        assert!(precheck(&entry, "visitor").is_err());

        let entry2 = VisitorEntry {
            allow_users: vec!["*".into()],
            ..entry
        };
        assert!(precheck(&entry2, "visitor").is_ok());
        assert!(precheck(&entry2, "").is_err());
    }

    #[tokio::test]
    async fn mode0_swaps_candidate_addresses_and_roles() {
        let _guard = test_lock().lock().await;
        clear_sessions();
        let (visitor, mut vrx) = client("visitor", "1.2.3.4");
        let (provider, mut prx) = client("provider", "5.6.7.8");
        let entry = Arc::new(VisitorEntry {
            proxy_name: "xtcp-test".into(),
            secret_key: "sk".into(),
            allow_users: vec![],
            provider_user: "provider".into(),
            client: provider.clone(),
            proxy_type: "xtcp".into(),
        });
        let m = NatHoleVisitor {
            transaction_id: "v-txn".into(),
            proxy_name: "xtcp-test".into(),
            protocol: "quic".into(),
            mapped_addrs: vec!["1.2.3.4:1000".into(), "1.2.3.4:1000".into()],
            assisted_addrs: vec!["192.168.1.10:1001".into()],
            ..Default::default()
        };
        start_session(&visitor, &entry, &m).unwrap();

        let sid = {
            let g = lock_sessions();
            g.keys().next().cloned().unwrap()
        };
        // 官方流程：先向 provider 要一条工作连接，在它上面写 NatHoleSid。
        let req = tokio::time::timeout(Duration::from_secs(2), prx.recv())
            .await
            .expect("provider 未及时收到 RequestWork")
            .expect("provider 通道关闭");
        assert!(
            matches!(req, CtrlCmd::RequestWork),
            "provider 必须先收到 RequestWork"
        );
        let (server_side, provider_side) = tokio::io::duplex(64 * 1024);
        let mut provider_frp = FrpConn::new(Box::pin(provider_side), WireVersion::V1);
        assert!(provider
            .submit_work(WorkItem::new(FrpConn::new(
                Box::pin(server_side),
                WireVersion::V1
            )))
            .is_none());
        let first = tokio::time::timeout(Duration::from_secs(2), provider_frp.recv_msg())
            .await
            .expect("provider 应收到 StartWorkConn")
            .expect("读取 StartWorkConn 失败")
            .expect("连接提前关闭");
        match first {
            FrpMessage::StartWorkConn(m) => assert_eq!(m.proxy_name, "xtcp-test"),
            other => panic!("unexpected provider message: {}", other.name()),
        }
        let second = tokio::time::timeout(Duration::from_secs(2), provider_frp.recv_msg())
            .await
            .expect("provider 应收到 NatHoleSid")
            .expect("读取 NatHoleSid 失败")
            .expect("连接提前关闭");
        match second {
            FrpMessage::NatHoleSid(m) => assert_eq!(m.sid, sid),
            other => panic!("unexpected provider message: {}", other.name()),
        }
        drop(provider_frp);

        let cm = NatHoleClient {
            transaction_id: "c-txn".into(),
            proxy_name: "xtcp-test".into(),
            sid,
            mapped_addrs: vec!["5.6.7.8:2000".into(), "5.6.7.8:2000".into()],
            assisted_addrs: vec!["192.168.1.11:2001".into()],
        };
        assert!(handle_client(&provider, &cm));

        let vresp = take_nat_hole_resp(&mut vrx);
        assert_eq!(vresp.transaction_id, "v-txn");
        assert_eq!(vresp.protocol, "quic");
        assert_eq!(vresp.candidate_addrs, vec!["5.6.7.8:2000"]);
        assert_eq!(vresp.assisted_addrs, vec!["192.168.1.11:2001"]);
        assert_eq!(vresp.detect_behavior.role, "receiver");
        assert_eq!(vresp.detect_behavior.mode, 0);
        assert_eq!(vresp.detect_behavior.ttl, 7);

        let presp = take_nat_hole_resp(&mut prx);
        assert_eq!(presp.transaction_id, "c-txn");
        assert_eq!(presp.candidate_addrs, vec!["1.2.3.4:1000"]);
        assert_eq!(presp.assisted_addrs, vec!["192.168.1.10:1001"]);
        assert_eq!(presp.detect_behavior.role, "sender");

        assert!(lock_sessions().is_empty());
    }

    #[tokio::test]
    async fn wrong_provider_cannot_steal_session() {
        let _guard = test_lock().lock().await;
        clear_sessions();
        let (visitor, _vrx) = client("visitor", "1.2.3.4");
        let (provider, _prx) = client("provider", "5.6.7.8");
        let (attacker, _arx) = client("attacker", "9.9.9.9");
        let entry = Arc::new(VisitorEntry {
            proxy_name: "xtcp-test".into(),
            secret_key: "sk".into(),
            allow_users: vec![],
            provider_user: "provider".into(),
            client: provider,
            proxy_type: "xtcp".into(),
        });
        let m = NatHoleVisitor {
            transaction_id: "v-txn".into(),
            proxy_name: "xtcp-test".into(),
            mapped_addrs: vec!["1.2.3.4:1000".into()],
            ..Default::default()
        };
        start_session(&visitor, &entry, &m).unwrap();
        let sid = lock_sessions().keys().next().cloned().unwrap();
        let cm = NatHoleClient {
            transaction_id: "a-txn".into(),
            proxy_name: "xtcp-test".into(),
            sid: sid.clone(),
            mapped_addrs: vec!["9.9.9.9:3000".into()],
            ..Default::default()
        };
        assert!(!handle_client(&attacker, &cm));
        assert!(lock_sessions().contains_key(&sid));
    }
}
