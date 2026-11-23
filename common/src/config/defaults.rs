//! serde 默认值与传输协议判定。
//!
//! 职责：集中定义配置常量、所有 `default_*` 函数，以及 `clamp_udp_packet_size` / `is_quic` / `is_kcp` / `is_websocket` / `is_wss`。
//! 并发/所有权契约：纯函数与常量，无锁、无共享可变状态；不读环境、不碰文件系统（`default_client_id` 只读进程 id）。
//! 不变量：serde 默认值**只由本模块定义**，其他模块只能通过 `#[serde(default = "...")]` 引用，禁止另写默认值。

pub const DEFAULT_BIND_ADDR: &str = "0.0.0.0";
pub const DEFAULT_CONTROL_PORT: u16 = 7000;
pub const DEFAULT_WORK_PORT: u16 = 7001;

pub const DEFAULT_HEARTBEAT_INTERVAL: u64 = 30;
pub const DEFAULT_HEARTBEAT_TIMEOUT: u64 = 90;
pub const DEFAULT_WORK_CONN_IDLE_TIMEOUT: u64 = 60;
pub const DEFAULT_RECONNECT_INTERVAL: u64 = 5;
pub const DEFAULT_LOG_LEVEL: &str = "info";
/// 官方 `LogConfig.Complete()`：`MaxDays = util.EmptyOr(c.MaxDays, 3)`。
pub const DEFAULT_LOG_MAX_DAYS: i64 = 3;
/// 官方 `ServerConfig.Complete()`：`VhostHTTPTimeout = util.EmptyOr(…, 60)`。
pub const DEFAULT_VHOST_HTTP_TIMEOUT: u64 = 60;

// ---------------------------------------------------------------------------
// serde 默认值
// ---------------------------------------------------------------------------

/// xtcp 默认传输：QUIC 自带加密与拥塞控制，是通用场景下的稳妥选择。
pub(super) fn default_xtcp_transport() -> String {
    "quic".to_string()
}

/// 端口预测的默认窗口（往预测值之后推几个端口）。
pub(super) fn default_predict_window() -> u16 {
    crate::p2p::PREDICT_WINDOW
}

pub(super) fn default_transport_protocol() -> String {
    "tcp".to_string()
}

/// UDP 单报文缓冲的默认上限：65507（UDP over IPv4 的最大载荷）。
///
/// 官方 frp 默认 1500，这里**故意不同** —— 见字段文档里"为什么默认不同"。
pub const MAX_UDP_PACKET_SIZE: usize = 65507;

pub(super) fn default_udp_packet_size() -> usize {
    MAX_UDP_PACKET_SIZE
}

/// 官方 frps 的默认值：168 小时（7 天）。
pub(super) fn default_nathole_analysis_reserve_hours() -> u64 {
    168
}

/// 把配置里的 `udpPacketSize` 夹到有意义的范围。
///
/// 0 会让读取长度变成 0（等于收不到任何报文），超 65507 也没有意义
/// （UDP 协议上限）。**夹紧而不是报错**：这类值通常是手误，
/// 让它退回默认比拒绝启动更友好，但要留下告警（调用方负责打）。
pub fn clamp_udp_packet_size(n: usize) -> usize {
    if n == 0 {
        MAX_UDP_PACKET_SIZE
    } else {
        n.min(MAX_UDP_PACKET_SIZE)
    }
}

/// 判断配置是否选择了 QUIC 传输（大小写与下划线一律宽容处理）。
pub fn is_quic(protocol: &str) -> bool {
    let p = protocol.trim().to_ascii_lowercase().replace(['-', '_'], "");
    p == "quic"
}

/// 判断配置是否选择了 KCP 传输（大小写与下划线一律宽容处理）。
pub fn is_kcp(protocol: &str) -> bool {
    let p = protocol.trim().to_ascii_lowercase().replace(['-', '_'], "");
    p == "kcp"
}

/// 是否走**明文** WebSocket 传输（`transport.protocol = "websocket"`）。
pub fn is_websocket(protocol: &str) -> bool {
    let p = protocol.trim().to_ascii_lowercase().replace(['-', '_'], "");
    p == "websocket" || p == "ws"
}

/// 是否走 **TLS 之上的** WebSocket 传输（`transport.protocol = "wss"`）。
///
/// ⚠️ 官方 frps 是在 **TLS 之前**按明文前缀 `GET /~!frp` 嗅探 WebSocket 的
/// （见 `server/service.go` 的 mux 前缀匹配），所以 `wss` **不能**直连 frps 主端口：
/// 首字节是 0x16 而不是 `G`，会被当成普通 frp 连接。
/// 这条路要求前面有个 nginx / caddy 终结 TLS 再转发明文 ws 给 frps。
pub fn is_wss(protocol: &str) -> bool {
    let p = protocol.trim().to_ascii_lowercase().replace(['-', '_'], "");
    p == "wss" || p == "websockets"
}

pub(super) fn default_health_timeout() -> u64 {
    3
}

pub(super) fn default_health_max_failed() -> u32 {
    3
}

pub(super) fn default_health_interval() -> u64 {
    10
}

pub(super) fn default_bind_addr() -> String {
    DEFAULT_BIND_ADDR.to_string()
}

/// visitor 本地监听口的默认绑定地址（v0.5.6 修审计总报告 L1）。
///
/// 与**服务端**的 [`DEFAULT_BIND_ADDR`]（`0.0.0.0`）刻意不同：
/// 服务端是"对外提供服务"，默认全网卡有道理；而 visitor 的监听口是
/// **本机入口**，默认对外没有必要。
///
/// 这个值同时与 INI 解析路径（`frp_legacy.rs`）和官方示例配置保持一致 ——
/// 在此之前 TOML 路径用的是 `0.0.0.0`，导致同一份配置在两个解析路径下
/// 得到不同的监听范围。
pub(super) fn default_visitor_bind_addr() -> String {
    "127.0.0.1".to_string()
}

/// 登录时间戳默认允许的偏差（秒），v0.5.6 修审计总报告 M3。
/// 300 秒足够容纳常见的时钟漂移与网络延迟，同时把"录下一条 Login 报文
/// 就能无限期重放"压到 5 分钟窗口。官方 frpc 发的是当前时间，**零感知**。
pub(super) fn default_max_clock_skew() -> u64 {
    300
}
pub(super) fn default_control_port() -> u16 {
    DEFAULT_CONTROL_PORT
}
pub(super) fn default_work_port() -> u16 {
    DEFAULT_WORK_PORT
}
pub(super) fn default_heartbeat_timeout() -> u64 {
    DEFAULT_HEARTBEAT_TIMEOUT
}
pub(super) fn default_heartbeat_interval() -> u64 {
    DEFAULT_HEARTBEAT_INTERVAL
}
pub(super) fn default_work_conn_idle_timeout() -> u64 {
    DEFAULT_WORK_CONN_IDLE_TIMEOUT
}
pub(super) fn default_reconnect_interval() -> u64 {
    DEFAULT_RECONNECT_INTERVAL
}
pub(super) fn default_log_level() -> String {
    DEFAULT_LOG_LEVEL.to_string()
}
pub(super) fn default_log_max_days() -> i64 {
    DEFAULT_LOG_MAX_DAYS
}
pub(super) fn default_vhost_http_timeout() -> u64 {
    DEFAULT_VHOST_HTTP_TIMEOUT
}
/// 客户端连接服务端的默认超时（官方 `dialServerTimeout` 默认 10 秒）。
pub(super) fn default_dial_server_timeout() -> u64 {
    10
}
/// 服务端等"用户连接配工作连接"的默认超时（官方 `userConnTimeout` 默认 10 秒）。
pub(super) fn default_user_conn_timeout() -> u64 {
    10
}
/// 客户端拨号 TCP 连接的 keepalive 空闲时长（官方 `dialServerKeepalive` 默认 7200 秒）。
pub(super) fn default_dial_server_keepalive() -> u64 {
    7200
}
/// yamux 会话保活间隔（官方 `tcpMuxKeepaliveInterval` 默认 30 秒）。
pub(super) fn default_tcp_mux_keepalive_interval() -> u64 {
    30
}
/// 服务端主端口 TCP 连接的 keepalive 空闲时长（官方 `tcpKeepalive` 默认 7200 秒）。
pub(super) fn default_tcp_keepalive() -> u64 {
    7200
}
/// 代理类型默认 tcp。
pub(super) fn default_proxy_type() -> String {
    "tcp".to_string()
}

/// visitor 类型默认 stcp。
pub(super) fn default_visitor_type() -> String {
    "stcp".to_string()
}

pub(super) fn default_webserver_addr() -> String {
    "127.0.0.1".into()
}

/// frp 客户端默认预建 1 条工作连接（与官方 frpc 默认一致）。
pub(super) fn default_pool_count() -> i32 {
    1
}

pub(super) fn default_true() -> bool {
    true
}
/// 默认客户端 ID：进程级唯一，跨平台（`std::process::id` 是标准库 API）。
pub(super) fn default_client_id() -> String {
    format!("client-{}", std::process::id())
}
