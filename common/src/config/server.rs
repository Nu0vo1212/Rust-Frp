//! 服务端配置结构。
//!
//! 职责：定义 `HttpPluginConfig`、`SshTunnelGatewayConfig`、`ServerConfig` 及其 Debug/Default/有效值方法，以及 `has_dashboard_creds`。
//! 并发/所有权契约：配置在解析后只读，无锁、无共享可变状态；`load` 只读文件，`write_example` 只写文件。
//! 不变量：serde 默认值只由 `defaults` 模块定义；`token` / `dashboard_pwd` 在 Debug 中必须脱敏。

use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::error::Result;

use super::client::{WebServerConfig, WebTlsConfig};
use super::defaults::{
    default_bind_addr, default_control_port, default_heartbeat_timeout, default_log_level,
    default_log_max_days, default_max_clock_skew, default_nathole_analysis_reserve_hours,
    default_tcp_keepalive, default_tcp_mux_keepalive_interval, default_transport_protocol,
    default_true, default_udp_packet_size, default_user_conn_timeout, default_vhost_http_timeout,
    default_work_conn_idle_timeout, default_work_port,
};
use super::parse::parse_server_toml;
use super::ports::{de_port_ranges, port_allowed, PortRange};
use super::protocol::Protocol;

// ---------------------------------------------------------------------------
// 服务端配置
// ---------------------------------------------------------------------------

/// 官方 frps 的 `[[httpPlugins]]` 一项。
///
/// 语义与官方 `pkg/plugin/server/http.go` 对齐：每个受支持的 op 都会向
/// `addr + path?version=0.1.0&op=...` 发一个 JSON POST，插件可以拒绝
/// （`reject`）或改写（`unchange = false`）请求内容。
#[derive(Clone, Serialize, Deserialize, Default)]
pub struct HttpPluginConfig {
    /// 插件名，只用于日志与排障。
    #[serde(default)]
    pub name: String,
    /// 插件地址，如 `127.0.0.1:9000`；没写 scheme 时按 `http://` 处理。
    #[serde(default)]
    pub addr: String,
    /// URL 路径，如 `/handler`。
    #[serde(default)]
    pub path: String,
    /// 该插件要接收的 op 列表；空表示一个都不接（与官方一致）。
    #[serde(default)]
    pub ops: Vec<String>,
    /// 是否校验插件 HTTPS 证书。
    ///
    /// 官方字段是 `tlsVerify`，**默认 false = 跳过校验**（历史行为）。
    /// 生产环境应显式设为 true；这里保留官方默认以免破坏现有插件部署。
    #[serde(default, rename = "tlsVerify", alias = "tls_verify")]
    pub tls_verify: bool,
}

impl std::fmt::Debug for HttpPluginConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HttpPluginConfig")
            .field("name", &self.name)
            .field("addr", &self.addr)
            .field("path", &self.path)
            .field("ops", &self.ops)
            .field("tls_verify", &self.tls_verify)
            .finish()
    }
}

/// 官方 frps 的 `[sshTunnelGateway]`。
///
/// `bind_port > 0` 才启用；其余字段与官方同名。
#[derive(Clone, Serialize, Deserialize, Default)]
pub struct SshTunnelGatewayConfig {
    #[serde(default, rename = "bindPort", alias = "bind_port")]
    pub bind_port: u16,
    #[serde(default, rename = "privateKeyFile", alias = "private_key_file")]
    pub private_key_file: String,
    #[serde(
        default,
        rename = "autoGenPrivateKeyPath",
        alias = "auto_gen_private_key_path"
    )]
    pub auto_gen_private_key_path: String,
    #[serde(default, rename = "authorizedKeysFile", alias = "authorized_keys_file")]
    pub authorized_keys_file: String,
}

impl std::fmt::Debug for SshTunnelGatewayConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SshTunnelGatewayConfig")
            .field("bind_port", &self.bind_port)
            .field("private_key_file", &self.private_key_file)
            .field("auto_gen_private_key_path", &self.auto_gen_private_key_path)
            .field("authorized_keys_file", &self.authorized_keys_file)
            .finish()
    }
}

impl SshTunnelGatewayConfig {
    pub fn enabled(&self) -> bool {
        self.bind_port > 0
    }
}

/// 服务端配置，对应 `server.toml`。
///
/// 手工实现 `Debug`（见文件下方），`token` 与 `dashboard_pwd`
/// 一律脱敏，避免任何调试打印把密钥写进日志。
#[derive(Clone, Serialize, Deserialize)]
pub struct ServerConfig {
    /// 监听地址，`0.0.0.0` 表示所有网卡。
    #[serde(default = "default_bind_addr")]
    pub bind_addr: String,

    /// NLink v1 扩展层（默认关闭）。
    ///
    /// 默认关闭时服务端行为与 0.6.x 完全一致：不认 preamble、不处理扩展帧、
    /// `LoginResp` 里也没有 `_nlink` 字段。
    #[serde(default)]
    pub nlink: crate::nlink::ServerNLinkConfig,

    /// 用户是否**显式写过** `bind_addr`。
    ///
    /// 为什么需要这个标志：认不出"默认值"和"用户明确写了 0.0.0.0"，
    /// 就没法区分这两种情形 ——
    ///
    /// * 用户**主动**把监听地址改成对外地址却没配 token ⇒ 明显是搞错了，该拦；
    /// * 用户**什么都没写**、直接 `nfrp-server` 起来 ⇒ 这是出厂默认，
    ///   拦住会让"默认配置无法启动"，比漏洞本身更糟。
    ///
    /// `#[serde(skip)]`：它不进配置文件、也不参与序列化，只作为**解析副产品**
    /// 由 `load` 在读完原始 TOML 后填上（见 [`ServerConfig::bind_addr_explicitly_set`] 的赋值点）。
    #[serde(skip)]
    pub bind_addr_explicitly_set: bool,

    /// 代理（公网端口 / 虚拟主机 / tcpmux）的监听地址（对应 frp `proxyBindAddr`）。
    ///
    /// 与官方一致：**留空（默认）时跟随 `bind_addr`**（官方 `Complete()`：
    /// `if ProxyBindAddr == "" { ProxyBindAddr = BindAddr }`）。
    /// 配上之后 tcp/udp 的 remote_port 监听、http/https 虚拟主机、
    /// tcpmux 的 CONNECT 端口都绑到它上面；控制端口 / 工作端口 / 面板 /
    /// VirtualNet 仍然绑 `bind_addr`（与官方 `service.go` 的用法一致）。
    ///
    /// 典型用途：控制端口开在 `0.0.0.0`，而公网代理端口只想开在
    /// 内网网卡或某个特定地址上。
    #[serde(default)]
    pub proxy_bind_addr: String,

    /// 控制端口：客户端在这里建控制连接。
    #[serde(default = "default_control_port")]
    pub control_port: u16,

    /// 工作端口：客户端按需在这里建工作连接。
    #[serde(default = "default_work_port")]
    pub work_port: u16,

    /// 认证 token。
    #[serde(default)]
    pub token: String,

    /// 心跳超时（秒）：超过该时间没收到客户端任何消息则断开控制连接。
    #[serde(default = "default_heartbeat_timeout")]
    pub heartbeat_timeout: u64,

    /// 池中空闲工作连接的存活时间（秒）。
    #[serde(default = "default_work_conn_idle_timeout")]
    pub work_conn_idle_timeout: u64,

    /// 用户连接等待工作连接的超时（秒，对应 frp `userConnTimeout`，官方默认 10）。
    ///
    /// 官方 `GetWorkConn()`：池里没有空闲工作连接时向客户端要一条，最多等
    /// `userConnTimeout` 秒，超时就关掉这条用户连接（`timeout trying to get
    /// work connection`）。nfrp 的对应路径：TCP 用户连接的排队回收 + vhost /
    /// UDP / visitor 的 `acquire_work_conn`，全部由它决定。
    ///
    /// `0` 按官方 `Complete()` 的 `util.EmptyOr(..., 10)` 口径**折算为 10 秒**
    /// —— 而不是"不限"：不设等待上限会让对端瘫掉时用户连接永远挂着。
    /// 取值入口见 [`ServerConfig::user_conn_timeout`]。
    #[serde(default = "default_user_conn_timeout")]
    pub user_conn_timeout: u64,

    /// 单个客户端**空闲工作连接池**的上限（对应 frp `maxPoolCount`）。
    ///
    /// 官方语义（`server/control.go`）：`effectivePoolCount = min(客户端
    /// Login.poolCount, 本项)`，空闲池容量 = 该值 + 10 的余量，超出即拒。
    /// nfrp 把它落到空闲池闸门上（C-2 修的 `idle_work_limit`），与
    /// `max_pending_per_client` 同口径**取更小者**。
    ///
    /// `0`（默认）= 不限制 —— 保持向后兼容（与项目其它 `Limit` 一致）。
    /// 与官方的默认值 5 **不同**：官方不写就是 5（+10 余量），nfrp 不写
    ///   就是不限制；只有显式写入才生效。官方配置原样搬过来时照常起作用。
    #[serde(default)]
    pub max_pool_count: usize,

    /// yamux 会话的保活间隔（秒，对应 frp `tcpMuxKeepaliveInterval`，官方默认 30）。
    ///
    /// 官方把该值交给 Go yamux：每 `interval` 秒向对端发一个 Ping，超时收不到
    /// Pong 就关会话。rust-yamux **没有** keepalive API（0.13 / 0.14 均无），
    /// nfrp 落成等价看门狗：驱动器持续轮询，让 crate 自带的 yamux Ping/Pong
    /// 保持流动，同时盯载体流**有没有从对端读到任何字节** —— 静默超过
    /// `interval + 10` 秒（10 秒对齐官方 yamux 的 Pong 超时
    /// `ConnectionWriteTimeout`）、且不低于 30 秒，即判定会话已死并关闭
    /// （所有流一起断开，客户端按既有逻辑重连）。健康会话的静默上限 ≈ 10~12
    /// 秒，下限 30 秒保证不会误杀。
    ///
    /// 对官方对端完全互通：官方 yamux 的 Ping 由 crate 原生应答，反向的
    /// Ping/Pong 也照常流动，本看门狗只是补上"静默即断"的判定。
    ///
    /// `0` 表示**关闭看门狗**—— 项目约定
    /// "0 = 关掉这项"；官方把 0 折算成 30，这里不复刻。
    ///
    /// 只在 `tcp_mux = true` 时有意义（官方注释同）。
    #[serde(default = "default_tcp_mux_keepalive_interval")]
    pub tcp_mux_keepalive_interval: u64,

    /// 控制口接下的 TCP 连接的 keepalive 空闲时长（秒，对应 frp
    /// `tcpKeepalive`，官方默认 7200）。
    ///
    /// 官方在 `bind_port` 主监听器上 `SetKeepAlive` —— 即**所有从主端口接下的
    /// TCP 连接**（控制连接、v1 协议下客户端拨入的工作连接等）。nfrp 在
    /// accept 之后对每条连接做同样的事（`SO_KEEPALIVE` + 空闲时长）。
    ///
    /// `0` 表示**不打开**（内核默认行为）；官方把 0 折算成 7200，这里不复刻。
    ///
    /// 只作用于 TCP 主端口；vhost / dashboard 端口与 KCP / QUIC 不受影响
    /// （与官方只包装主监听器一致）。
    #[serde(default = "default_tcp_keepalive")]
    pub tcp_keepalive: u64,

    /// frp 兼容模式端口（控制连接与工作连接复用同一个端口）。
    /// 未配置时回退到 `control_port`。
    #[serde(default)]
    pub bind_port: Option<u16>,

    /// 线协议。服务端**按魔术字自动识别**对端走 v1 还是 v2（与官方 frps 一致），
    /// 所以这一项只是为了"原版 frps 的配置能直接喂进来"；同一端口可以同时
    /// 服务两种客户端。只有 `nfrp` 自研协议尚未实现，会被直接拒绝。
    #[serde(default)]
    pub protocol: Protocol,

    /// 是否允许客户端使用 yamux 多路复用（对应 frp `transport.tcpMux`）。
    ///
    /// 服务端会自动探测：yamux 的 SYN 帧以 `0x00` 开头，frp v2 魔术字以 `F` 开头，
    /// 两者不冲突，所以开启后仍能同时服务 tcpMux=false 的客户端。
    #[serde(default = "default_true")]
    pub tcp_mux: bool,

    /// 是否强制客户端必须使用 TLS（对应 frp `transport.tls.force`）。
    ///
    /// 不强制时服务端仍然接受 TLS：靠首字节 `0x17` / `0x16` 自动识别。
    #[serde(default)]
    pub tls_force: bool,

    /// 服务端 TLS 证书（PEM，对应官方 `transport.tls.certFile`）。
    ///
    /// 留空 = 继续用进程启动时生成的自签名证书（与官方默认一致）。
    /// 与 `tls_key_file` 必须同时配置；只配一个会在启动时明确报错。
    #[serde(default, rename = "certFile")]
    pub tls_cert_file: String,

    /// 服务端 TLS 私钥（PEM，对应官方 `transport.tls.keyFile`）。
    #[serde(default, rename = "keyFile")]
    pub tls_key_file: String,

    /// 校验客户端证书的 CA（PEM，对应官方 `transport.tls.trustedCaFile`）。
    ///
    /// 非空时启用 **mTLS**：客户端必须出示由该 CA 签发的证书。
    /// 官方 frpc 默认不带客户端证书，因此这条路径主要给"NFrp 客户端 + NFrp 服务端"
    /// 或自建证书的双端使用。
    #[serde(default, rename = "trustedCaFile")]
    pub tls_trusted_ca_file: String,

    /// HTTP 代理的虚拟主机端口（对应 frp `vhostHTTPPort`）。
    /// 留空表示不启用 http 类型代理。
    #[serde(default)]
    pub vhost_http_port: Option<u16>,

    /// HTTPS 代理的虚拟主机端口（对应 frp `vhostHTTPSPort`）。
    /// 服务端按 TLS ClientHello 里的 SNI 路由，证书由内网服务自己提供（纯透传）。
    #[serde(default)]
    pub vhost_https_port: Option<u16>,

    /// tcpmux 代理的 HTTP CONNECT 复用端口（对应 frp `tcpmuxHTTPConnectPort`）。
    ///
    /// 这是**一个共享端口**：所有 tcpmux 代理都挂在它上面，靠 CONNECT 请求里的
    /// host 分发。留空表示不启用 tcpmux 类型代理。
    #[serde(default)]
    pub tcpmux_http_connect_port: Option<u16>,

    /// tcpmux 的 CONNECT 请求是否**原样透传**给内网服务（对应 frp `tcpmuxPassthrough`）。
    ///
    /// * `false`（默认，与官方一致）：服务端自己回 `HTTP/1.1 200 OK`，再把后续字节
    ///   转发给内网服务 —— 内网服务看到的是一条**已经建好**的裸 TCP 连接。
    /// * `true`：连 CONNECT 请求本身都转发过去，由内网服务自己回 200。
    ///   适合内网本身就是一个 HTTP 代理的场景。
    #[serde(default)]
    pub tcpmux_passthrough: bool,

    /// vhost HTTP **等待内网服务响应头**的超时（秒，对应 frp `vhostHTTPTimeout`，默认 60）。
    ///
    /// 0 = 不限。对应官方 `vhost.HTTPReverseProxyOptions.ResponseHeaderTimeoutS`：
    /// 内网服务连上了却迟迟不回响应头时，服务端不会一直挂着这条用户连接。
    #[serde(default = "default_vhost_http_timeout")]
    pub vhost_http_timeout: u64,

    /// 自定义 404 页面文件路径（对应 frp `custom404Page`）。空 = 用内置提示。
    ///
    /// 与官方 `vhost.NotFoundPagePath` 一致：没有代理能匹配该域名时，
    /// 把这个文件的**原文**当作 404 响应体返回（不改变状态码）。
    #[serde(default)]
    pub custom_404_page: String,

    /// 泛域名后缀（对应 frp `subdomainHost`），形如 `example.com`。
    /// 配置后客户端可用 `subdomain = "abc"` 注册 `abc.example.com`。
    #[serde(default)]
    pub subdomain_host: String,

    /// 日志级别，形如 `info` / `debug` / `nfrp_server=debug`。
    #[serde(default = "default_log_level")]
    pub log_level: String,

    /// 日志落盘路径（对应 frp `log.to`）。空 / `console` = 写标准输出（默认）。
    ///
    /// 配了非 console 的值就写文件，并在**跨天**时把当前文件改名成
    /// `<名>.<YYYYMMDD-HHMMSS><扩展名>`、再建一个新的，按 `max_days` 清理老备份。
    /// 细节与与官方的一处时区差异见 [`crate::logfile`]。
    #[serde(default)]
    pub log_to: String,

    /// 日志保留天数（对应 frp `log.maxDays`，默认 3；`<= 0` = 不清理）。
    #[serde(default = "default_log_max_days")]
    pub max_days: i64,

    /// 禁用控制台日志的 ANSI 颜色（对应 frp `log.disablePrintColor`）。
    ///
    /// 默认 false = 跟随官方行为（输出到**终端**才上色，写文件本来就不上色）；
    /// 置 true 后即使输出是终端也不上色 —— 给"终端里重定向 stdout"这类
    /// 场景一个显式开关。
    #[serde(default)]
    pub disable_print_color: bool,

    // ---- 资源上限（0 = 不限，默认全部不限制以保持向后兼容）----
    /// 全局同时活跃的转发连接数上限。
    #[serde(default)]
    pub max_total_conns: usize,
    /// 同时在线的客户端数上限。
    #[serde(default)]
    pub max_clients: usize,
    /// 单个客户端同时活跃的转发连接数上限。
    #[serde(default)]
    pub max_conns_per_client: usize,
    /// 单个客户端待配对队列长度上限（用户连接排着等工作连接）。
    #[serde(default)]
    pub max_pending_per_client: usize,
    /// 单个客户端可注册的代理数上限。
    #[serde(default)]
    pub max_proxies_per_client: usize,

    /// group 负载均衡策略（**NFrp 扩展**，官方 frp 没有这个配置项）。
    ///
    /// 同 `group` 的多个代理共享一个公网端口，用户连接在它们之间分摊。
    ///
    /// | 值 | 行为 |
    /// |---|---|
    /// | `roundrobin`（默认） | 严格 1/N 轮询，**与官方 frp 一致** |
    /// | `leastconn` | 优先给在途连接最少的后端，能力不均时更优 |
    ///
    /// 默认选 `roundrobin` 是刻意的：官方 `server/group/*.go` 用 channel
    /// fan-out 实现，效果就是轮询 —— 它无状态、可预测，把"谁不健康"交给
    /// 健康检查去处理，而不是让调度器猜。
    ///
    /// `leastconn` 是本项目的超集能力，开它不影响与官方客户端的互通
    /// （调度完全发生在服务端内部）。
    ///
    /// ```toml
    /// lbPolicy = "leastconn"
    /// ```
    #[serde(default)]
    pub lb_policy: String,

    /// KCP 会话表条数上限（**NFrp 扩展**，默认 1024）。
    ///
    /// KCP 是"每个 UDP 源端口一个会话"的模型，每个会话约占 15.3 KB。
    /// 上限直接决定内存上界：`值 × 15.3 KB`。
    ///
    /// | 值 | 峰值内存 | 适用 |
    /// |---|---|---|
    /// | 1024（默认） | ≈ 15 MB | 绝大多数部署 |
    /// | 4096 | ≈ 62 MB | 数千客户端的单实例 |
    /// | 16384 | ≈ 250 MB | 需要确认内存充足 |
    ///
    /// 超大规模部署的正确做法**不是无限调大**，而是：
    /// 1. 用 TCP / QUIC 承载控制连接（KCP 只在这些都走不通时才需要）；
    /// 2. 或者在前面挂负载均衡，把客户端拆到多个 frps 实例上。
    ///
    /// 低于 64 会被抬到安全下限（配成 0 等于关掉 KCP）。
    /// 0 或未配置表示用默认值 1024。
    ///
    /// ```toml
    /// kcpMaxSessions = 4096
    /// ```
    #[serde(default)]
    pub kcp_max_sessions: usize,

    /// **端口白名单**（对应 frp `allowPorts`）：客户端能申请的**公网远端端口**。
    ///
    /// 空 = 不限制（与官方一致）。这是一项**安全**配置 —— 不配的话任何拿到 token
    /// 的客户端都能把 22 / 3306 这类端口映射到公网，配了却静默失效比不配更危险。
    ///
    /// ```toml
    /// allowPorts = [
    ///   { start = 20000, end = 30000 },
    ///   { single = 8443 },
    /// ]
    /// ```
    ///
    /// 也接受字符串写法（legacy INI / 官方 `--allow_ports` 的形式）：
    /// `allowPorts = ["20000-30000", "8443"]`。
    #[serde(default, deserialize_with = "de_port_ranges")]
    pub allow_ports: Vec<PortRange>,

    /// 单个客户端可占用的远端端口数上限（对应 frp `maxPortsPerClient`，0 = 不限）。
    ///
    /// 与 `max_proxies_per_client` 不是一回事：http / https / tcpmux / stcp 这些
    /// **不占公网端口**的代理只算代理数、不占端口数。官方也是这么分的
    /// （`Control.RegisterProxy` 里累加的是 `pxy.GetUsedPortsNum()`）。
    #[serde(default)]
    pub max_ports_per_client: i64,

    /// 是否把**详细**失败原因回给客户端（对应 frp `detailedErrorsToClient`，默认 true）。
    ///
    /// 关掉之后的文案与官方逐字对齐（官方 `util.GenerateResponseErrorString`）：
    ///
    /// * 注册代理失败 → `new proxy [<名字>] error`
    /// * 心跳校验失败 → `invalid ping`
    ///
    /// 这是一项**安全**配置：默认的详细错误里会带上"域名 xxx 已被代理 yyy 占用"
    /// 这类**别人的代理名**，多方共用一个 frps 时等于把别人的隧道名泄露出去。
    /// 单租户自用没必要关；对外提供服务时建议关掉。
    #[serde(default = "default_true")]
    pub detailed_errors_to_client: bool,

    // ---- 传输层 ----
    /// 客户端与服务端之间的传输协议：`tcp`（默认）、`quic` 或 `kcp`。
    ///
    /// QUIC 自带加密与多路复用，握手只需 1-RTT、丢包不会阻塞其它流，
    /// 在高延迟 / 弱网链路上明显优于 TCP；代价是需要放行 UDP 端口。
    #[serde(default = "default_transport_protocol")]
    pub transport_protocol: String,
    /// KCP 传输的监听端口（官方 frps 的 `kcpBindPort`，不配则不启用）。
    ///
    /// 与 QUIC 不同，KCP 在官方 frp 里是**独立端口**而不是复用 `bindPort`：
    /// 它是裸 UDP 上的可靠传输，没有 QUIC 那种"先握手再分流"的能力，
    /// 只能另开一个 UDP 端口、靠源地址区分客户端。
    ///
    /// 配了它之后，客户端把 `transport.protocol` 设成 `kcp` 并连这个端口即可；
    /// TCP 端口照旧保留，老客户端不受影响。
    #[serde(default, alias = "kcpBindPort", alias = "kcp_bind_port")]
    pub kcp_bind_port: Option<u16>,

    /// QUIC 传输的**独立**监听端口（官方 frps 的 `quicBindPort`）。
    ///
    /// # 与 `transport_protocol = "quic"` 的区别
    ///
    /// 后者是"服务端说自己也走 QUIC"，但旧实现只在 `bindPort` 的**同名 UDP
    /// 端口**上额外监听 —— 客户端没法指定别的端口。
    ///
    /// 官方语义是：`quicBindPort` **配了就开**一个独立 UDP 端口，与 `bindPort`
    /// 无关。好处是能把 QUIC 放到另一个端口（`bindPort` 已被占用、或要做端口
    /// 分流），防火墙规则也更好写。
    ///
    /// 配了它之后，QUIC 监听**只**在这个端口上开，**不再**顺带占用
    /// `bindPort` 的同名 UDP 端口。那是旧行为的隐式副作用，会让
    /// "我明明配了 quicBindPort=7101，为什么 7000/udp 也被占了" 变成谜。
    ///
    /// ```toml
    /// quicBindPort = 7101
    /// ```
    #[serde(default, alias = "quicBindPort", alias = "quic_bind_port")]
    pub quic_bind_port: Option<u16>,

    // ---- xtcp 真 P2P ----
    /// 牵线（rendezvous）用的 UDP 端口。
    ///
    /// 配置了它才会启用 xtcp 的 UDP 打洞；不配置时 xtcp 退化为 stcp 中继，
    /// 并且服务端会在 `NatHoleResp` 里明确告知 visitor 让它立即回退。
    #[serde(default)]
    pub p2p_port: Option<u16>,

    // ---- 可观测性 ----
    /// 内置面板 + `/metrics` 端点的监听端口（留空则不启用）。
    #[serde(default)]
    pub dashboard_port: Option<u16>,

    /// 官方 frps 的 `[webServer]` 段落。
    ///
    /// NFrp 历史上使用 `dashboard_port` / `dashboard_user` / `dashboard_pwd`。
    /// 现在同时接受官方写法：`[webServer] port` 作为 dashboard 端口的备用值，
    /// `user` / `password` 作为 dashboard 凭据的备用值，`[webServer.tls]`
    /// 用于面板 HTTPS。两者都写时显式的 `dashboard_*` 优先。
    #[serde(default, rename = "webServer")]
    pub web_server: WebServerConfig,

    /// 是否在面板端口上导出 Prometheus 指标（官方 frps 的 `enablePrometheus`）。
    ///
    /// **默认关闭**，与官方一致。此前是无条件开放 `/metrics`。
    ///
    /// 为什么默认关：
    /// * 官方默认就不开（`server.go` 的注释写明"配了才导出"），
    ///   照官方文档部署的人会以为它关着；
    /// * 指标里含业务信息（在线客户端数、代理名、流量字节），
    ///   在"只想开个面板看看"的部署里等于**默认多暴露一份数据面**。
    ///
    /// 要采集就显式打开：
    ///
    /// ```toml
    /// enablePrometheus = true
    /// ```
    ///
    /// `/api/healthz` 不受这个开关影响 —— 健康探针永远可用，
    /// 否则 k8s / docker 的探针会因为"没开指标"而反复重启容器。
    #[serde(default, rename = "enablePrometheus", alias = "enable_prometheus")]
    pub enable_prometheus: bool,

    /// UDP 转发的单报文缓冲上限（官方 frps 的 `udpPacketSize`）。
    ///
    /// 官方默认 **1500**，而 NFrp 一直用 **65507**（UDP 协议上限）。
    ///
    /// 为什么默认**故意与官方不同**：
    /// * 它决定"单个 UDP 报文最多能带多少字节"，超过就被截断；
    /// * 我们此前一直按 65507 工作，改成 1500 会**截断现有用户的大报文**
    ///   （某些游戏 / 私有协议单包就上千字节）—— 那是静默的数据损坏；
    /// * 想把行为对齐官方的部署，显式配 `udpPacketSize = 1500` 即可。
    ///
    /// 取值会被夹在 `[1, 65507]`：0 或超限都没有意义。
    #[serde(
        default = "default_udp_packet_size",
        rename = "udpPacketSize",
        alias = "udp_packet_size"
    )]
    pub udp_packet_size: usize,

    /// 面板静态资源目录（官方 frps 的 `webServer.assetsDir`）。
    ///
    /// 配了它之后，面板的 `/` 与其它路径会**优先从这个目录读文件**，
    /// 而不是用内嵌的那份 HTML。这样可以把面板换成自己的页面（换 logo、
    /// 加公司信息之类），不用改二进制。
    ///
    /// 安全约束（实现里逐条落实）：
    /// * 先 `canonicalize`，再检查结果仍在 `assets_dir` 之内 —— 挡 `../` 穿越；
    /// * 只读普通文件，不列目录、不跟符号链接到目录外；
    /// * 按扩展名给 MIME，认不出来的按 `application/octet-stream`。
    ///
    /// 留空 = 用内嵌面板（默认行为，与之前完全一致）。
    #[serde(default, alias = "assetsDir", alias = "assets_dir")]
    pub assets_dir: String,

    /// 是否在面板端口上挂 `/debug/pprof/profile`（官方 `webServer.pprofEnable`）。
    ///
    /// 默认关闭。与 `enablePrometheus` 同口径 —— 诊断端点不该在
    /// "只想开个面板"的部署里默认暴露。
    ///
    /// Unix 上由 pprof-rs 采集并输出 Go pprof 兼容的 protobuf；Windows 没有
    /// perf 事件，端点会明确返回 501 而不是假装成功。
    #[serde(
        default,
        rename = "pprofEnable",
        alias = "pprof_enable",
        alias = "PprofEnable",
        alias = "PPROFENABLE"
    )]
    pub pprof_enable: bool,

    /// 官方 `natholeAnalysisDataReserveHours`：NAT 打洞分析记录的保留小时数。
    ///
    /// 官方默认 168（7 天）。NFrp 目前只实现 mode 0，因此这里的记录用于
    /// 统计每一对 client/visitor 的反复配对情况，并按此值过期清理；它是
    /// 真实的资源上限，不是只解析不生效的占位字段。
    #[serde(
        default = "default_nathole_analysis_reserve_hours",
        rename = "natholeAnalysisDataReserveHours",
        alias = "nathole_analysis_data_reserve_hours"
    )]
    pub nathole_analysis_data_reserve_hours: u64,

    /// 官方 `[[httpPlugins]]`：登录 / 注册 / 心跳等事件的 HTTP 钩子。
    #[serde(default, rename = "httpPlugins", alias = "http_plugins")]
    pub http_plugins: Vec<HttpPluginConfig>,

    /// 官方 `[sshTunnelGateway]`：SSH 隧道网关。
    #[serde(default, rename = "sshTunnelGateway", alias = "ssh_tunnel_gateway")]
    pub ssh_tunnel_gateway: SshTunnelGatewayConfig,

    /// 面板用户名（留空表示**不做鉴权**）。
    ///
    /// 留空只在 `bind_addr` 是回环时被接受（本机自用）。配了
    /// `dashboard_port` 却把面板绑在非回环地址上又留空用户名，服务端会
    /// **拒绝启动** —— 那等于把面板连同"开端口 / 踢人"的写接口对外开放。
    /// 确实需要就显式打开 [`Self::allow_insecure_dashboard`]。
    #[serde(default)]
    pub dashboard_user: String,
    #[serde(default)]
    pub dashboard_pwd: String,
    /// 明确同意"面板不鉴权且对外监听"。
    ///
    /// 默认 `false` ⇒ 那种配置会被启动校验拦下。置 `true` 表示知情自担风险
    /// （典型合法场景：面板只在跳板机能到的内网里，靠网络隔离兜底）。
    #[serde(default)]
    pub allow_insecure_dashboard: bool,
    /// 明确同意"**服务端不做认证**且对外监听"。
    ///
    /// 背景：`token` 留空时认证被完全跳过（与官方 frps 一致，靠网络隔离兜底）。
    /// 但"留空 + 绑 0.0.0.0"等于对外开放一个**任何人都能用**的 frps ——
    /// 谁都能注册代理、申请公网端口，把服务器变成公共内网穿透节点。
    ///
    /// 原先这种组合只打一条 `warn!` 就放行，而**同一个风险在面板路径上
    /// 是硬性 `ensure!` 拒绝启动的** —— 两种标准。现在统一：
    /// 默认 `false` ⇒ 拒绝启动；确实需要（比如纯内网lab）显式置 `true`。
    ///
    /// 为什么不干脆禁止：官方 frp 允许空 token，而且确实有大量内网部署
    /// 这么跑。直接砍掉会破坏兼容性；"拒绝启动 + 显式逃生开关"既堵住了
    /// 无意的误配置（把空 token 部署到公网），又保留了知情选择。
    #[serde(default)]
    pub allow_insecure_no_auth: bool,
    /// 登录时间戳允许的偏差（秒），
    ///
    /// # 为什么需要
    ///
    /// v1 的登录凭证是 `md5(token + timestamp)`，而服务端原先**只用报文自报的
    /// timestamp 重算比对、不做新鲜性校验**；同时 `Login` 在加密建立**之前**
    /// 明文发送（官方时序）。
    ///
    /// ⇒ 同链路嗅探到一条 `Login` 就能**原样重放**拿到完整会话（无期限）。
    ///
    /// # 为什么加它不破坏互通
    ///
    /// 官方 frpc 的 `Login.Timestamp` 就是发报文时的 unix 时间，
    /// 宽窗口下**零感知**。这**不改任何线协议格式** ——
    /// "协议格式不能改" ≠ "安全语义不能加强"。
    ///
    /// # 取值
    ///
    /// * **默认 300 秒**：容纳常见时钟漂移与网络延迟，同时把重放窗口
    ///   从"永久"压到 5 分钟。
    /// * **0 = 关闭校验**：给时钟严重不准的嵌入式设备留的逃生开关
    ///   （关闭会在启动日志里告警）。
    ///
    /// 与官方 frp 的默认值不同：官方**完全不校验**。对需要与
    ///   时钟严重不准的官方客户端互通的场景，把它设为 0 即可。
    #[serde(default = "default_max_clock_skew")]
    pub max_clock_skew_secs: u64,
    /// 是否监听配置文件变化并自动重载可动态生效的字段。
    #[serde(default)]
    pub hot_reload: bool,

    // ================= 扩展配置 =================
    // 全部 `#[serde(default)]`，且默认值都等价于"不启用"——
    // 老的 server.toml 一个字节都不用改就能继续跑。
    /// 认证配置（`[auth]`）：`method = "token" | "oidc"` + `auth.oidc.*`。
    ///
    /// 不写 `[auth]` 时行为与老版本完全一致（用顶层 `token`）。
    #[serde(default)]
    pub auth: crate::security::ServerAuthConfig,

    /// 客户端 IP 白 / 黑名单（`[acl]`）。**先看 deny，再看 allow。**
    ///
    /// 这是"连不上"和"连得上但什么都能干"之间的第一道闸：
    /// 面板/控制端口暴露在公网时，没有它就只能靠 token 硬扛。
    #[serde(default)]
    pub acl: crate::security::AclConfig,

    /// 角色表（`[[roles]]`）。留空 = 不做授权限制（与老版本一致）。
    ///
    /// 放在**顶层**而不是 `[rbac.roles]`，是为了写起来跟官方 frp 的
    /// `[[httpPlugins]]` 一样自然：
    /// ```toml
    /// [[roles]]
    /// name = "ops"
    /// users = ["alice"]
    /// portRange = "20000-30000"
    /// ```
    #[serde(default)]
    pub roles: Vec<crate::security::RoleConfig>,

    /// 没匹配到任何角色时使用的角色名（留空表示不兜底）。
    #[serde(
        default,
        rename = "defaultRole",
        skip_serializing_if = "String::is_empty"
    )]
    pub default_role: String,

    /// 配了角色表但一个都没匹配上时，是否直接拒绝登录。
    #[serde(default, rename = "denyUnknown")]
    pub deny_unknown: bool,

    /// 审计日志（`[audit]`）。默认关闭。
    #[serde(default)]
    pub audit: crate::security::AuditConfig,

    /// WebSocket 传输（`[transport.websocket]`）。
    ///
    /// 服务端只要配了 `websocket` 段就**同时**接受 WebSocket 与裸 TCP 控制连接
    /// （靠首字节区分：`GET ` = 0x47 / yamux 版本字节 0x00 / v2 魔术字 0x46），
    /// 不需要单独端口。
    #[serde(default)]
    pub websocket: crate::ws::WebSocketConfig,

    /// VirtualNet 虚拟网络（`[vnet]`）。
    #[serde(default)]
    pub vnet: crate::vnet::VirtualNetConfig,

    /// VirtualNet 的监听端口。不配 = 不启用虚拟网络。
    ///
    /// 单独一个端口而不是复用控制端口：虚拟网络是**长时间高速**的纯数据流，
    /// 混在控制通道里会拖慢心跳与面板命令，出故障时也不好隔离。
    #[serde(default)]
    pub vnet_port: Option<u16>,

    /// 解析时发现的、**官方 frps 支持但 NFrp 未实现**的字段名。
    ///
    /// 纯诊断用（`#[serde(skip)]`）：官方 frps 配置里的 `allowPorts` 这类项
    /// 会被静默忽略，启动日志据此明说。填值见
    /// [`crate::frp_config::unsupported_server_fields`]。
    #[serde(skip)]
    pub unsupported_fields: Vec<String>,
}

impl std::fmt::Debug for ServerConfig {
    /// `token` / `dashboard_pwd` 永不进日志。
    ///
    /// 这两个字段原来会随 `#[derive(Debug)]` 一起打出来 ——
    /// 任何一句 `tracing::debug!(?cfg)` 都会把面板口令写进日志文件。
    /// 只保留"有没有配、多长"这类排障够用的信息。
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        fn redact(s: &str) -> String {
            if s.is_empty() {
                "<empty>".to_string()
            } else {
                format!("<redacted:{} chars>", s.chars().count())
            }
        }
        f.debug_struct("ServerConfig")
            .field("bind_addr", &self.bind_addr)
            .field("bind_port", &self.bind_port)
            .field("control_port", &self.control_port)
            .field("token", &redact(&self.token))
            .field("dashboard_port", &self.dashboard_port)
            .field("dashboard_user", &self.dashboard_user)
            .field("dashboard_pwd", &redact(&self.dashboard_pwd))
            .field("web_server", &self.web_server)
            .field("allow_insecure_dashboard", &self.allow_insecure_dashboard)
            .field("allow_insecure_no_auth", &self.allow_insecure_no_auth)
            .field("hot_reload", &self.hot_reload)
            .field("log_level", &self.log_level)
            .field("auth", &self.auth)
            .field("acl", &self.acl)
            .field("roles", &self.roles.len())
            .field("audit", &self.audit)
            .finish_non_exhaustive()
    }
}

impl ServerConfig {
    /// frp 模式实际监听的端口。
    pub fn frp_bind_port(&self) -> u16 {
        self.bind_port.unwrap_or(self.control_port)
    }

    /// 实际生效的面板端口。
    ///
    /// 显式的 `dashboard_port` 优先；否则使用官方写法
    /// `[webServer] port`。两者都为 0/空时面板不启动。
    pub fn effective_dashboard_port(&self) -> Option<u16> {
        self.dashboard_port
            .filter(|p| *p != 0)
            .or_else(|| (self.web_server.port != 0).then_some(self.web_server.port))
    }

    /// 实际生效的面板 Basic Auth 凭据。
    ///
    /// 显式 `dashboard_user` / `dashboard_pwd` 优先；都为空时回退到
    /// 官方 `[webServer] user` / `password`。
    pub fn effective_dashboard_creds(&self) -> (String, String) {
        if has_dashboard_creds(&self.dashboard_user, &self.dashboard_pwd) {
            (self.dashboard_user.clone(), self.dashboard_pwd.clone())
        } else if has_dashboard_creds(&self.web_server.user, &self.web_server.password) {
            (
                self.web_server.user.clone(),
                self.web_server.password.clone(),
            )
        } else {
            (self.dashboard_user.clone(), self.dashboard_pwd.clone())
        }
    }

    /// 面板静态资源目录：官方 `[webServer] assetsDir` 可作为顶层
    /// `assets_dir` 的备用值。
    pub fn effective_assets_dir(&self) -> &str {
        if self.assets_dir.trim().is_empty() {
            &self.web_server.assets_dir
        } else {
            &self.assets_dir
        }
    }

    /// 面板 pprof：顶层开关或官方 `[webServer] pprofEnable` 任一开启。
    pub fn effective_pprof_enable(&self) -> bool {
        self.pprof_enable || self.web_server.pprof_enable
    }

    /// 面板 HTTPS 配置（官方 `[webServer.tls]`）。
    pub fn web_tls(&self) -> &WebTlsConfig {
        &self.web_server.tls
    }

    /// 实际生效的认证配置。
    ///
    /// 顶层 `token` 是历史写法（也正好是官方 frps 的 `auth.token` 展开），
    /// `[auth] token` 是新写法。**新的优先，旧的兜底** —— 于是两种配置
    /// 混着写不会出现"明明配了 token 却认证失败"。
    pub fn effective_auth(&self) -> crate::security::ServerAuthConfig {
        let mut a = self.auth.clone();
        if a.token.is_empty() {
            a.token = self.token.clone();
        }
        a
    }

    /// 把顶层的角色 / 兜底项组装成可编译的 RBAC 配置。
    pub fn rbac_config(&self) -> crate::security::RbacConfig {
        crate::security::RbacConfig {
            roles: self.roles.clone(),
            default_role: self.default_role.clone(),
            deny_unknown: self.deny_unknown,
        }
    }

    /// VirtualNet 是否可用。
    ///
    /// 顶层 `vnet_port` 与 `[vnet] serverPort` 等价，写哪个都认；
    /// 都没写就是不启用（默认），此时一个字节都不监听、老行为完全不变。
    pub fn vnet_enabled(&self) -> bool {
        self.vnet_listen_port().is_some()
    }

    /// 实际生效的 VirtualNet 监听端口。
    pub fn vnet_listen_port(&self) -> Option<u16> {
        self.vnet_port
            .filter(|p| *p != 0)
            .or(if self.vnet.server_port != 0 {
                Some(self.vnet.server_port)
            } else {
                None
            })
    }

    /// 客户端申请的远端端口是否被 `allowPorts` 放行（空名单 = 全放行）。
    pub fn port_allowed(&self, port: u16) -> bool {
        port_allowed(&self.allow_ports, port)
    }

    /// 回给客户端的错误文案：`detailed_errors_to_client = false` 时换成短句。
    ///
    /// `summary` 与官方 `util.GenerateResponseErrorString` 的第一个参数对齐
    /// （官方写法见 `server/control.go` 的 `handleNewProxy` / `handlePing`）。
    pub fn error_to_client(&self, summary: &str, detail: &str) -> String {
        if self.detailed_errors_to_client {
            detail.to_string()
        } else {
            summary.to_string()
        }
    }

    /// vhost HTTP 等待内网响应头的超时；0 表示不限。
    pub fn vhost_http_timeout(&self) -> Option<std::time::Duration> {
        (self.vhost_http_timeout > 0)
            .then(|| std::time::Duration::from_secs(self.vhost_http_timeout))
    }

    /// 数据面实际生效的监听地址：代理端口 / 虚拟主机 / tcpmux 都绑它
    /// （对应 frp `proxyBindAddr`）。
    ///
    /// 与官方一致：**空 = 跟随 `bind_addr`**（官方 `Complete()` 的
    /// `if ProxyBindAddr == "" { ProxyBindAddr = BindAddr }`）。
    pub fn effective_proxy_bind_addr(&self) -> &str {
        if self.proxy_bind_addr.trim().is_empty() {
            &self.bind_addr
        } else {
            &self.proxy_bind_addr
        }
    }

    /// 用户连接等待工作连接的超时（对应 frp `userConnTimeout`，官方默认 10 秒）。
    ///
    /// `0` 按官方 `Complete()` 的 `util.EmptyOr(..., 10)` 口径**折算为默认值 10**，
    /// 而不是"不限" —— 不设等待上限会让对端瘫掉时用户连接永远挂着。
    pub fn user_conn_timeout(&self) -> std::time::Duration {
        let secs = if self.user_conn_timeout == 0 {
            10
        } else {
            self.user_conn_timeout
        };
        std::time::Duration::from_secs(secs)
    }
}

/// **唯一判据**：这对面板 / 管理界面凭据能不能用来鉴权。
///
/// # 为什么必须是"用户名与密码都非空"
///
/// 两处鉴权都是把用户名和密码**拼成 `"user:pwd"`** 再与 HTTP Basic 头比较
/// （`server/src/dashboard.rs` 与 `client/src/web.rs`）。于是密码为空时期望值
/// 就是 `"admin:"` —— 攻击者随手可构造。
/// **空密码不是弱密码，是"没有密码"**：鉴权退化成"知道用户名就能进"，
/// 而用户名往往是默认的 `admin`。
///
/// # 为什么必须抽成唯一真源
///
/// 这个判定原先在**四处各写了一遍**，每处都只判了用户名：
///
/// | 位置 | 用途 |
/// |---|---|
/// | `server/src/reload.rs` 的热重载闸门 | 拒绝"运行期清空凭据" |
/// | `server/src/reload.rs` 的 `dashboard_is_exposed` | 暴露判定 |
/// | `server/src/main.rs` 的启动校验 | 拒绝启动 |
/// | `client/src/main.rs` 的 `check_web_server_is_safe` | 客户端界面拒绝启动 |
///
/// 四处都漏了密码，于是存在一条**不需要任何配置疏漏**的攻击链：
/// 攻击者热重载时**只清空密码**（用户名保持 `admin`），
/// 闸门判 `"admin".is_empty()` 为 false ⇒ 不拦 ⇒ `auth` 被写成 `("admin", "")`
/// ⇒ 匿名者用 `admin:` 即可进面板拿到全部写权限。
///
/// ⇒ 判定散在多处就一定会漂移 —— 这正是本项目反复出现的那个模式
///   （"防线写对了，但没有铺满它声称保护的所有字段 / 路径"）。
///
/// # trim 只用于"有没有配凭据"，凭据本身**逐字比对**
///
/// 密码里的空格是**合法字符**（`dashboard_pwd = " a "` 是三个字符的密码），
/// 把它 trim 掉会让用户配的密码与期望值对不上。用户名同理：`user.trim()`
/// 在这里只参与**非空判定**（全空白的用户名 = 没配上），真正的比对在
/// `dashboard.rs` —— 用配置里的**原样**字符串拼 `user:password` 再定长比较。
///
/// ⇒ `dashboard_user = " admin "` 的部署**不能**用 `admin` 登录，必须发
/// 字面量 `" admin "`。原先这里的注释写成
///   "用户名惯例允许两侧空白"，与实现不符，会给排障指错方向。
pub fn has_dashboard_creds(user: &str, pwd: &str) -> bool {
    !user.trim().is_empty() && !pwd.is_empty()
}

impl ServerConfig {
    /// **唯一判据**：本服务端是不是处于"**没有任何认证**"的状态
    ///
    /// # 为什么需要它
    ///
    /// "有没有配置认证"这件事原先在**两处用了两套口径**：
    ///
    /// | 位置 | 口径 |
    /// |---|---|
    /// | `server/src/guard.rs` 的启动告警 | `auth.method() == Token && effective_auth().token.is_empty()` |
    /// | `server/src/main.rs` 的启动告警 | `cfg.token.is_empty()` —— **只看顶层字段，且不看 method** |
    ///
    /// 后者的后果：**纯 OIDC 部署**（`[auth] method = "oidc"` + `issuer`，
    /// **不配 token —— 这是完全正确的配置**）下 `cfg.token` 为空 ⇒
    /// 进入分支 ⇒ 打出"未配置 token 且正在监听对外地址 —— **任何人**都能
    /// 连上来注册代理、申请公网端口"。
    ///
    /// **而事实是 OIDC 认证已正确启用。告警与事实完全相反。**
    ///
    /// 二级危害是这类"狼来了"告警会训练管理员忽略同类告警，
    /// 或者为了"消掉告警"随手塞一个多余 token —— 后者会**改变认证语义**。
    ///
    /// `effective_auth()` 会做字段合并（`[auth] token` 为空时回落到顶层
    ///   `token`），所以判据必须用它，而不是直接读 `self.token`。
    /// 必须同时判 `method`：OIDC 模式下没有 token 是**正常**的。
    pub fn has_no_auth(&self) -> bool {
        let eff = self.effective_auth();
        eff.method == crate::security::AuthMethod::Token && eff.token.is_empty()
    }
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            bind_addr: default_bind_addr(),
            nlink: crate::nlink::ServerNLinkConfig::default(),
            // 默认（没从文件读过）⇒ 视为"用户没显式写过"
            bind_addr_explicitly_set: false,
            // 空 = 跟随 bind_addr（与官方 proxyBindAddr 的语义一致）
            proxy_bind_addr: String::new(),
            control_port: default_control_port(),
            work_port: default_work_port(),
            token: String::new(),
            heartbeat_timeout: default_heartbeat_timeout(),
            work_conn_idle_timeout: default_work_conn_idle_timeout(),
            user_conn_timeout: default_user_conn_timeout(),
            max_pool_count: 0,
            tcp_mux_keepalive_interval: default_tcp_mux_keepalive_interval(),
            tcp_keepalive: default_tcp_keepalive(),
            bind_port: None,
            protocol: Protocol::default(),
            tcp_mux: true,
            tls_force: false,
            tls_cert_file: String::new(),
            tls_key_file: String::new(),
            tls_trusted_ca_file: String::new(),
            vhost_http_port: None,
            vhost_https_port: None,
            tcpmux_http_connect_port: None,
            tcpmux_passthrough: false,
            vhost_http_timeout: default_vhost_http_timeout(),
            custom_404_page: String::new(),
            subdomain_host: String::new(),
            log_level: default_log_level(),
            log_to: String::new(),
            max_days: default_log_max_days(),
            disable_print_color: false,
            transport_protocol: default_transport_protocol(),
            kcp_bind_port: None,
            quic_bind_port: None,
            max_total_conns: 0,
            max_clients: 0,
            max_conns_per_client: 0,
            max_pending_per_client: 0,
            max_proxies_per_client: 0,
            // 空串 = roundrobin（与官方 frp 的 group 行为一致）
            lb_policy: String::new(),
            // 0 = 用默认值 1024
            kcp_max_sessions: 0,
            allow_ports: Vec::new(),
            max_ports_per_client: 0,
            detailed_errors_to_client: true,
            p2p_port: None,
            dashboard_port: None,
            web_server: WebServerConfig::default(),
            enable_prometheus: false,
            udp_packet_size: default_udp_packet_size(),
            assets_dir: String::new(),
            pprof_enable: false,
            nathole_analysis_data_reserve_hours: default_nathole_analysis_reserve_hours(),
            http_plugins: Vec::new(),
            ssh_tunnel_gateway: SshTunnelGatewayConfig::default(),
            dashboard_user: String::new(),
            dashboard_pwd: String::new(),
            allow_insecure_dashboard: false,
            allow_insecure_no_auth: false,
            // 默认 ±300 秒的登录时间戳窗口（0 = 关闭）
            max_clock_skew_secs: default_max_clock_skew(),
            hot_reload: false,
            auth: Default::default(),
            acl: Default::default(),
            roles: Vec::new(),
            default_role: String::new(),
            deny_unknown: false,
            audit: Default::default(),
            websocket: Default::default(),
            vnet: Default::default(),
            vnet_port: None,
            unsupported_fields: Vec::new(),
        }
    }
}

impl ServerConfig {
    /// 从 TOML 文件加载。
    ///
    /// 走 [`parse_server_toml`]，因此**原版 frps 的配置文件可以直接用**。
    pub fn load<P: AsRef<Path>>(path: P) -> Result<Self> {
        let raw = std::fs::read_to_string(path.as_ref()).map_err(crate::error::Error::Io)?;
        parse_server_toml(&raw)
    }

    /// 写入一份带注释的示例配置。
    pub fn write_example<P: AsRef<Path>>(path: P) -> Result<()> {
        std::fs::write(path.as_ref(), Self::example_toml()).map_err(crate::error::Error::Io)?;
        Ok(())
    }

    /// 示例配置文本。
    /// 示例配置。
    ///
    /// 这里**手写**而不是序列化 `Default`：toml 会把 `None` / 空值整项跳过，
    /// 于是 P2P、面板、资源上限这些"默认关闭但很重要"的能力在示例里根本看不见，
    /// 用户也就永远不知道它们存在。
    pub fn example_toml() -> String {
        r##"# nfrp-server 示例配置
# 用法：nfrp-server -c server.toml
# 生成：nfrp-server --gen-config server.toml

# ---- 基础 ----
bind_addr = "0.0.0.0"
bind_port = 7000
token = "your_secret_token"
log_level = "info"

# ---- 线协议 ----
# 不需要配：服务端和官方 frps 一样，靠**魔术字自动识别**对端是 v1 还是 v2
# （读 8 字节比对，不是 v2 魔术字就回填当 v1 的消息前缀）。
# 所以同一个端口上，官方 frpc（默认 v1）和 nfrp（可配 v2）都能连。
# 这一项留着只是为了"原版 frps 的配置文件能直接喂进来"。
# protocol = "frp-v1"

# ---- 虚拟主机（http / https 代理共用端口）----
vhost_http_port = 8080
# vhost_https_port = 8443
# subdomain_host = "example.com"

# ---- xtcp 真 P2P ----
# 牵线用的 UDP 端口。配置后 xtcp 才会尝试 UDP 打洞 + QUIC 直连；
# 不配置时 xtcp 退化为中继（与 stcp 相同），并会明确告知访客回退。
# 注意：防火墙要放行这个 UDP 端口。
p2p_port = 7002

# ---- 内置面板与指标（/metrics 为 Prometheus 格式）----
dashboard_port = 7500
dashboard_user = "admin"
dashboard_pwd = "change_me"

# ---- 配置热重载：改完 log_level / 面板密码不用重启 ----
hot_reload = true

# ---- 资源上限（0 或不填 = 不限）----
max_clients = 100            # 同时在线的客户端数
max_proxies_per_client = 50  # 单个客户端可注册的代理数
max_conns_per_client = 200   # 单个客户端同时转发的连接数
max_total_conns = 5000       # 全局同时转发的连接数
max_pending_per_client = 64  # 单个客户端排队等工作连接的请求数

# ---- 端口管控（安全相关，对外提供服务时强烈建议配）----
# ★ 不配 allow_ports 的话，**任何**拿到 token 的客户端都能申请 22 / 3306
#   这类端口并直接暴露到公网。写法与官方 frps.toml 一致，也接受字符串形式。
allow_ports = [
  { start = 20000, end = 30000 },
  # { single = 8443 },
]
# 单个客户端最多占用几个公网端口（0 = 不限）。注意它与 max_proxies_per_client
# 不是一回事：http / https / tcpmux / stcp 这些不占公网端口的只算代理数。
max_ports_per_client = 20

# ---- 虚拟主机行为 ----
vhost_http_timeout = 60          # 等内网服务**响应头**的秒数（0 = 不限）
# custom_404_page = "/etc/nfrp/404.html"   # 没有代理匹配时返回这个文件

# ---- 回给客户端的错误要不要带上细节 ----
# false 时只回 `new proxy [xxx] error` / `invalid ping`，不会把
# "这个域名已被别的代理占用"这类**别人的隧道名**泄露出去。默认 true（与官方一致）。
# detailed_errors_to_client = true

# ---- 日志 ----
# log_level 也可以写在下面这个 [log] 段里（与官方 frps.toml 一致）：
# [log]
# to = "/var/log/nfrps.log"   # 默认 console；配了文件就写文件，按天轮转
# maxDays = 3                 # 备份日志保留天数（<=0 = 不清理）
# level = "info"
"##
        .to_string()
    }
}
