//! TOML 配置结构与示例模板。
//!
//! 所有路径相关参数统一使用 [`std::path::PathBuf`]，不在代码中硬编码路径分隔符。

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::error::Result;

pub const DEFAULT_BIND_ADDR: &str = "0.0.0.0";
pub const DEFAULT_CONTROL_PORT: u16 = 7000;
pub const DEFAULT_WORK_PORT: u16 = 7001;

/// 线协议选择。
///
/// * `frp-v2`    —— **原版 frp（v0.70+）默认线协议**，可与官方 frpc / frps 互通；
/// * `rustunnel` —— rustunnel 自研的简化协议（4 字节长度前缀 + JSON），仅两个 rustunnel 之间互通。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Protocol {
    #[default]
    FrpV2,
    Rustunnel,
}

impl Protocol {
    pub fn as_str(&self) -> &'static str {
        match self {
            Protocol::FrpV2 => "frp-v2",
            Protocol::Rustunnel => "rustunnel",
        }
    }
}

impl std::fmt::Display for Protocol {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl std::str::FromStr for Protocol {
    type Err = String;
    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s.trim().to_ascii_lowercase().as_str() {
            "frp-v2" | "frpv2" | "frp" => Ok(Protocol::FrpV2),
            "rustunnel" | "native" => Ok(Protocol::Rustunnel),
            other => Err(format!("未知协议 {other}，可选：frp-v2 / rustunnel")),
        }
    }
}
pub const DEFAULT_HEARTBEAT_INTERVAL: u64 = 30;
pub const DEFAULT_HEARTBEAT_TIMEOUT: u64 = 90;
pub const DEFAULT_WORK_CONN_IDLE_TIMEOUT: u64 = 60;
pub const DEFAULT_RECONNECT_INTERVAL: u64 = 5;
pub const DEFAULT_LOG_LEVEL: &str = "info";

// ---------------------------------------------------------------------------
// 服务端配置
// ---------------------------------------------------------------------------

/// 服务端配置，对应 `server.toml`。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerConfig {
    /// 监听地址，`0.0.0.0` 表示所有网卡。
    #[serde(default = "default_bind_addr")]
    pub bind_addr: String,

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

    /// frp 兼容模式端口（控制连接与工作连接复用同一个端口）。
    /// 未配置时回退到 `control_port`。
    #[serde(default)]
    pub bind_port: Option<u16>,

    /// 线协议：`frp-v2`（默认，可与原版 frp 互通）或 `rustunnel`（自研简化协议）。
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

    /// HTTP 代理的虚拟主机端口（对应 frp `vhostHTTPPort`）。
    /// 留空表示不启用 http 类型代理。
    #[serde(default)]
    pub vhost_http_port: Option<u16>,

    /// HTTPS 代理的虚拟主机端口（对应 frp `vhostHTTPSPort`）。
    /// 服务端按 TLS ClientHello 里的 SNI 路由，证书由内网服务自己提供（纯透传）。
    #[serde(default)]
    pub vhost_https_port: Option<u16>,

    /// 泛域名后缀（对应 frp `subdomainHost`），形如 `example.com`。
    /// 配置后客户端可用 `subdomain = "abc"` 注册 `abc.example.com`。
    #[serde(default)]
    pub subdomain_host: String,

    /// 日志级别，形如 `info` / `debug` / `rustunnel_server=debug`。
    #[serde(default = "default_log_level")]
    pub log_level: String,

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

    // ---- 传输层 ----
    /// 客户端与服务端之间的传输协议：`tcp`（默认）或 `quic`。
    ///
    /// QUIC 自带加密与多路复用，握手只需 1-RTT、丢包不会阻塞其它流，
    /// 在高延迟 / 弱网链路上明显优于 TCP；代价是需要放行 UDP 端口。
    #[serde(default = "default_transport_protocol")]
    pub transport_protocol: String,

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
    /// 面板用户名（留空表示不做鉴权，只建议在回环地址上这样配置）。
    #[serde(default)]
    pub dashboard_user: String,
    #[serde(default)]
    pub dashboard_pwd: String,
    /// 是否监听配置文件变化并自动重载可动态生效的字段。
    #[serde(default)]
    pub hot_reload: bool,
}

impl ServerConfig {
    /// frp 模式实际监听的端口。
    pub fn frp_bind_port(&self) -> u16 {
        self.bind_port.unwrap_or(self.control_port)
    }
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            bind_addr: default_bind_addr(),
            control_port: default_control_port(),
            work_port: default_work_port(),
            token: String::new(),
            heartbeat_timeout: default_heartbeat_timeout(),
            work_conn_idle_timeout: default_work_conn_idle_timeout(),
            bind_port: None,
            protocol: Protocol::default(),
            tcp_mux: true,
            tls_force: false,
            vhost_http_port: None,
            vhost_https_port: None,
            subdomain_host: String::new(),
            log_level: default_log_level(),
            transport_protocol: default_transport_protocol(),
            max_total_conns: 0,
            max_clients: 0,
            max_conns_per_client: 0,
            max_pending_per_client: 0,
            max_proxies_per_client: 0,
            p2p_port: None,
            dashboard_port: None,
            dashboard_user: String::new(),
            dashboard_pwd: String::new(),
            hot_reload: false,
        }
    }
}

impl ServerConfig {
    /// 从 TOML 文件加载。
    pub fn load<P: AsRef<Path>>(path: P) -> Result<Self> {
        let raw = std::fs::read_to_string(path.as_ref()).map_err(crate::error::Error::Io)?;
        Ok(toml::from_str(&raw)?)
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
        r##"# rustunnel-server 示例配置
# 用法：rustunnel-server -c server.toml
# 生成：rustunnel-server --gen-config server.toml

# ---- 基础 ----
bind_addr = "0.0.0.0"
bind_port = 7000
token = "your_secret_token"
log_level = "info"

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
"##
        .to_string()
    }
}

// ---------------------------------------------------------------------------
// 客户端配置
// ---------------------------------------------------------------------------

/// 单个代理的配置。
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ProxyConfig {
    /// 代理名，全局唯一（服务端用它匹配工作连接）。
    pub name: String,
    /// 代理类型：`tcp`（默认）/ `udp` / `http` / `https`。
    #[serde(rename = "type", default = "default_proxy_type")]
    pub proxy_type: String,
    /// 内网服务地址，形如 `127.0.0.1:22`。
    pub local_addr: String,
    /// 希望服务端开放的公网端口（tcp / udp 必填）。
    #[serde(default)]
    pub remote_port: u16,

    // ---- http / https 专用 ----
    /// 自定义域名（http / https 必填其一，或配合 `subdomain`）。
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub custom_domains: Vec<String>,
    /// 泛域名子域前缀，配合服务端 `subdomain_host`。
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub subdomain: String,
    /// 路由前缀列表（留空等价于 `/`）。
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub locations: Vec<String>,
    /// HTTP Basic Auth 用户名 / 密码。
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub http_user: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub http_pwd: String,
    /// 转发到内网服务时重写 Host 头。
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub host_header_rewrite: String,

    // ---- 带宽限流 ----
    /// 带宽上限，形如 `1MB` / `500KB`；留空或 `0` 表示不限。
    ///
    /// 单位是**字节/秒**（frp 同款写法：`KB = 1000`、`KiB = 1024`）。
    /// 防止某一条代理把整条上行链路吃满。
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub bandwidth_limit: String,

    // ---- 负载均衡分组 ----
    /// 组名：同名组的多个代理可以**共享同一个 remote_port**，
    /// 服务端把用户连接按轮询分摊到组内各后端（官方 frp 的 `loadBalancer.group`）。
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub group: String,
    /// 组密钥（官方 frp 的 `groupKey`），同组代理保持一致即可，可留空。
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub group_key: String,

    // ---- 健康检查 ----
    /// 健康检查类型：`tcp` / `http`；留空表示不检查。
    ///
    /// 连续失败达到 `health_check_max_failed` 次后，客户端会**停止为该代理
    /// 提供工作连接**（表现为用户连不上），探测恢复后自动重新服务 ——
    /// 这样坏掉的后端不会再把请求吞掉。
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub health_check_type: String,
    /// 单次探测的超时秒数。
    #[serde(default = "default_health_timeout")]
    pub health_check_timeout_s: u64,
    /// 连续失败多少次才判定为不健康（避免一次抖动就下线）。
    #[serde(default = "default_health_max_failed")]
    pub health_check_max_failed: u32,
    /// 探测间隔秒数。
    #[serde(default = "default_health_interval")]
    pub health_check_interval_s: u64,
    /// `http` 检查用的路径，例如 `/healthz`；留空则用 `/`。
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub health_check_url: String,

    // ---- 客户端插件 ----
    /// 插件类型：`http_proxy` / `socks5` / `static_file` / `unix_domain_socket`。
    ///
    /// 配了插件就不再连 `local_addr`，而是把工作连接接到插件上 ——
    /// 于是 frpc 本身就能当正向代理 / 静态文件服务器用。
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub plugin: String,
    /// 插件的本地路径：`static_file` 的目录、`unix_domain_socket` 的套接字路径。
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub plugin_local_path: String,
    /// `static_file` 插件：回源时剥掉的路径前缀。
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub plugin_strip_prefix: String,
    /// `socks5` / `http_proxy` 插件的用户名（留空 = 不要求认证）。
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub plugin_user: String,
    /// `socks5` / `http_proxy` 插件的密码。
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub plugin_passwd: String,

    // ---- stcp / xtcp 专用 ----
    /// 共享密钥（frpc 里叫 `secretKey`）。provider 与 visitor 必须一致。
    #[serde(default, alias = "secretKey", skip_serializing_if = "String::is_empty")]
    pub secret_key: String,
    /// 允许接入的访客用户列表（对应 frpc 的 `allowUsers`）。
    ///
    /// 与官方 frp 一致：比对的是**访问方 frpc 的顶层 `user`**（`client.user`），
    /// 不是 `[[visitors]]` 的 `name`。留空 = 允许所有访客。
    #[serde(default, alias = "allowUsers", skip_serializing_if = "Vec::is_empty")]
    pub allow_users: Vec<String>,
}

/// 一个 visitor（访客）的配置，对应 frpc 的 `[[visitors]]` 段。
///
/// visitor 是 stcp / xtcp 的**接入方**：它在本地监听一个端口，
/// 把连上来的流量通过服务端送到远端的 provider，最后到达 provider 的内网服务。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VisitorConfig {
    /// visitor 自己的名字（仅本地使用，可与 provider 的代理名不同）。
    ///
    /// 注意：provider 的 `allow_users` 比对的是本客户端顶层的 `user`，**不是**这个名字。
    pub name: String,
    /// 类型：`stcp` 或 `xtcp`。
    #[serde(rename = "type", default = "default_visitor_type")]
    pub visitor_type: String,
    /// 目标 provider 注册的代理名（frpc 里叫 `serverName`）。
    #[serde(default, alias = "serverName")]
    pub server_name: String,
    /// 目标 provider 所属客户端的 user（frpc 里叫 `serverUser`）。
    ///
    /// 留空则用**本客户端**的顶层 `user`。目标名会按官方规则拼成
    /// `"{server_user|本客户端 user}.{server_name}"`。
    #[serde(default, alias = "serverUser")]
    pub server_user: String,
    /// 共享密钥，必须与 provider 的 `secret_key` 相同。
    #[serde(default, alias = "secretKey")]
    pub secret_key: String,
    /// 本地监听地址。
    #[serde(default = "default_bind_addr")]
    pub bind_addr: String,
    /// 本地监听端口。为 0 时不监听（仅用于给别的 visitor 做 fallback 目标）。
    #[serde(default, alias = "bindPort")]
    pub bind_port: u16,
}

impl Default for VisitorConfig {
    fn default() -> Self {
        Self {
            name: String::new(),
            visitor_type: default_visitor_type(),
            server_name: String::new(),
            server_user: String::new(),
            secret_key: String::new(),
            bind_addr: default_bind_addr(),
            bind_port: 0,
        }
    }
}

/// visitor 类型默认 stcp。
fn default_visitor_type() -> String {
    "stcp".to_string()
}

/// 客户端配置，对应 `client.toml`。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientConfig {
    /// 服务端地址（域名或 IP，不含端口）。
    pub server_addr: String,

    /// 服务端控制端口。
    #[serde(default = "default_control_port")]
    pub server_port: u16,

    /// 服务端工作端口。留空则由服务端在 `LoginResp.work_port` 中下发。
    #[serde(default)]
    pub server_work_port: Option<u16>,

    /// 认证 token，需与服务端一致。
    #[serde(default)]
    pub token: String,

    /// 客户端标识，用于服务端日志与多客户端区分。
    #[serde(default = "default_client_id")]
    pub client_id: String,

    /// 客户端用户名，对应 frp 顶层的 `user`。
    ///
    /// 官方 frp 用它做 stcp / xtcp 的 `allow_users` 白名单匹配
    /// （服务端比对的是 `Login.User`，不是 visitor 的 `name`）。
    #[serde(default)]
    pub user: String,

    /// 心跳间隔（秒）。
    #[serde(default = "default_heartbeat_interval")]
    pub heartbeat_interval: u64,

    /// 多久没收到 Pong 就认为连接已死（秒）。
    #[serde(default = "default_heartbeat_timeout")]
    pub heartbeat_timeout: u64,

    /// 控制连接断开后的重连间隔（秒）。
    #[serde(default = "default_reconnect_interval")]
    pub reconnect_interval: u64,

    /// 线协议：`frp-v2`（默认，可与原版 frp 互通）或 `rustunnel`。
    #[serde(default)]
    pub protocol: Protocol,

    /// frp 模式下预先建立的工作连接数量（0 表示按需建立）。
    #[serde(default = "default_pool_count")]
    pub pool_count: i32,

    /// 是否启用 yamux 多路复用（对应 frp `transport.tcpMux`）。
    ///
    /// 开启后控制连接与所有工作连接复用同一条 TCP，能显著减少连接数。
    /// 需要服务端也允许 yamux。
    #[serde(default = "default_true")]
    pub tcp_mux: bool,

    /// 是否启用 TLS（对应 frp `transport.tls.enable`）。
    ///
    /// 与 frp 一致：默认不校验服务端证书（自签名即可）。
    #[serde(default)]
    pub tls_enable: bool,

    /// TLS 的 SNI / 证书校验用的主机名，留空则用 `server_addr`。
    #[serde(default)]
    pub tls_server_name: String,

    /// 是否在 TLS 握手前发送 frp 自定义首字节 `0x17`
    /// （对应 frp `transport.tls.disableCustomTLSFirstByte`，这里语义相反）。
    #[serde(default = "default_true")]
    pub tls_custom_first_byte: bool,

    /// 日志级别。
    #[serde(default = "default_log_level")]
    pub log_level: String,

    // ---- 传输层 ----
    /// 与服务端之间的传输协议：`tcp`（默认）或 `quic`，需与服务端一致。
    #[serde(default = "default_transport_protocol")]
    pub transport_protocol: String,

    // ---- xtcp 真 P2P ----
    /// 服务端牵线（rendezvous）用的 UDP 端口，需与服务端 `p2p_port` 一致。
    ///
    /// 不配置时 xtcp 只会走中继（与 stcp 相同），不会尝试打洞。
    #[serde(default)]
    pub p2p_port: Option<u16>,
    /// 是否允许 xtcp 尝试 P2P 直连；打洞失败会自动回退到中继。
    #[serde(default = "default_true")]
    pub p2p_enable: bool,

    /// 需要暴露的代理列表。
    #[serde(default)]
    pub proxies: Vec<ProxyConfig>,

    /// 需要接入的访客列表（stcp / xtcp）。
    #[serde(default)]
    pub visitors: Vec<VisitorConfig>,
}

impl Default for ClientConfig {
    fn default() -> Self {
        Self {
            server_addr: "127.0.0.1".into(),
            server_port: default_control_port(),
            server_work_port: None,
            token: String::new(),
            client_id: default_client_id(),
            user: String::new(),
            heartbeat_interval: default_heartbeat_interval(),
            heartbeat_timeout: default_heartbeat_timeout(),
            reconnect_interval: default_reconnect_interval(),
            protocol: Protocol::default(),
            pool_count: default_pool_count(),
            tcp_mux: true,
            tls_enable: false,
            tls_server_name: String::new(),
            tls_custom_first_byte: true,
            log_level: default_log_level(),
            transport_protocol: default_transport_protocol(),
            p2p_port: None,
            p2p_enable: true,
            proxies: Vec::new(),
            visitors: Vec::new(),
        }
    }
}

impl ClientConfig {
    /// 从 TOML 文件加载。
    pub fn load<P: AsRef<Path>>(path: P) -> Result<Self> {
        let raw = std::fs::read_to_string(path.as_ref()).map_err(crate::error::Error::Io)?;
        Ok(toml::from_str(&raw)?)
    }

    /// 写入一份带注释的示例配置。
    pub fn write_example<P: AsRef<Path>>(path: P) -> Result<()> {
        std::fs::write(path.as_ref(), Self::example_toml()).map_err(crate::error::Error::Io)?;
        Ok(())
    }

    /// 示例配置文本。
    /// 示例配置（手写的原因同 [`ServerConfig::example_toml`]）。
    pub fn example_toml() -> String {
        r##"# rustunnel-client 示例配置
# 用法：rustunnel-client -c client.toml
# 生成：rustunnel-client --gen-config client.toml

server_addr = "1.2.3.4"
server_port = 7000
token = "your_secret_token"
user = "alice"          # stcp / xtcp 的 allow_users 比对的就是它
log_level = "info"

# ---- xtcp 真 P2P ----
# 必须与服务端 p2p_port 一致；不填则 xtcp 只走中继。
p2p_port = 7002
p2p_enable = true       # 打洞失败会自动回退中继

# ---- 需要暴露出去的内网服务 ----
[[proxies]]
name = "ssh"
type = "tcp"
local_addr = "127.0.0.1:22"
remote_port = 6000

# [[proxies]]
# name = "home-web"
# type = "http"
# local_addr = "127.0.0.1:8080"
# custom_domains = ["home.example.com"]

# stcp：不占公网端口，靠密钥接入
# [[proxies]]
# name = "secure-echo"
# type = "stcp"
# local_addr = "127.0.0.1:9000"
# secret_key = "same_on_both_sides"

# xtcp：优先 P2P 直连，打洞失败自动回退中继
# [[proxies]]
# name = "p2p-echo"
# type = "xtcp"
# local_addr = "127.0.0.1:9001"
# secret_key = "same_on_both_sides"

# ---- 作为访客接入别人的 stcp / xtcp ----
# [[visitors]]
# name = "echo-visitor"
# type = "xtcp"
# server_name = "p2p-echo"          # 对端的代理名
# secret_key = "same_on_both_sides"
# bind_addr = "127.0.0.1"
# bind_port = 9001
"##
        .to_string()
    }
}

// ---------------------------------------------------------------------------
// serde 默认值
// ---------------------------------------------------------------------------

/// 传输协议默认用 TCP：它不需要额外放行 UDP，兼容性最好。
pub fn default_transport_protocol() -> String {
    "tcp".to_string()
}

/// 判断配置是否选择了 QUIC 传输（大小写与下划线一律宽容处理）。
pub fn is_quic(protocol: &str) -> bool {
    let p = protocol.trim().to_ascii_lowercase().replace(['-', '_'], "");
    p == "quic"
}

fn default_health_timeout() -> u64 {
    3
}

fn default_health_max_failed() -> u32 {
    3
}

fn default_health_interval() -> u64 {
    10
}

fn default_bind_addr() -> String {
    DEFAULT_BIND_ADDR.to_string()
}
fn default_control_port() -> u16 {
    DEFAULT_CONTROL_PORT
}
fn default_work_port() -> u16 {
    DEFAULT_WORK_PORT
}
fn default_heartbeat_timeout() -> u64 {
    DEFAULT_HEARTBEAT_TIMEOUT
}
fn default_heartbeat_interval() -> u64 {
    DEFAULT_HEARTBEAT_INTERVAL
}
fn default_work_conn_idle_timeout() -> u64 {
    DEFAULT_WORK_CONN_IDLE_TIMEOUT
}
fn default_reconnect_interval() -> u64 {
    DEFAULT_RECONNECT_INTERVAL
}
fn default_log_level() -> String {
    DEFAULT_LOG_LEVEL.to_string()
}
/// 代理类型默认 tcp。
fn default_proxy_type() -> String {
    "tcp".to_string()
}

/// frp 客户端默认预建 1 条工作连接（与官方 frpc 默认一致）。
fn default_pool_count() -> i32 {
    1
}

fn default_true() -> bool {
    true
}
/// 默认客户端 ID：进程级唯一，跨平台（`std::process::id` 是标准库 API）。
fn default_client_id() -> String {
    format!("client-{}", std::process::id())
}

/// 配置文件默认路径：当前工作目录下的 `file_name`。
///
/// 用 `PathBuf::join` 拼接，不硬编码任何路径分隔符。
pub fn default_config_path(file_name: impl AsRef<Path>) -> PathBuf {
    std::env::current_dir()
        .unwrap_or_else(|_| PathBuf::from("."))
        .join(file_name)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 示例配置是**手写**的 TOML，一旦字段名与结构体漂移，
    /// 用户 `--gen-config` 出来的文件就根本加载不了 —— 而这类错误
    /// 只有真正去解析才会暴露，所以必须测。
    #[test]
    fn server_example_config_loads() {
        let cfg: ServerConfig =
            toml::from_str(&ServerConfig::example_toml()).expect("服务端示例配置必须可解析");
        assert_eq!(cfg.p2p_port, Some(7002), "示例里要展示 P2P 端口");
        assert_eq!(cfg.dashboard_port, Some(7500));
        assert!(cfg.hot_reload, "示例里应示范热重载");
        assert_eq!(cfg.max_clients, 100);
        assert_eq!(cfg.max_total_conns, 5000);
        // 示例里的 token 不能是空的，否则用户照抄会得到一个不设防的服务端
        assert!(!cfg.token.is_empty());
    }

    #[test]
    fn client_example_config_loads() {
        let cfg: ClientConfig =
            toml::from_str(&ClientConfig::example_toml()).expect("客户端示例配置必须可解析");
        assert_eq!(cfg.p2p_port, Some(7002));
        assert!(cfg.p2p_enable);
        assert_eq!(cfg.proxies.len(), 1);
        assert_eq!(cfg.proxies[0].name, "ssh");
        assert_eq!(cfg.proxies[0].proxy_type, "tcp");
        assert_eq!(cfg.proxies[0].remote_port, 6000);
        assert!(!cfg.token.is_empty());
    }

    /// 两端默认的 P2P 端口一致时才能开箱即用。
    #[test]
    fn example_configs_agree_on_p2p_port() {
        let s: ServerConfig = toml::from_str(&ServerConfig::example_toml()).unwrap();
        let c: ClientConfig = toml::from_str(&ClientConfig::example_toml()).unwrap();
        assert_eq!(
            s.p2p_port, c.p2p_port,
            "两端示例的 p2p_port 必须一致，否则用户照抄会打不通"
        );
    }

    #[test]
    fn defaults_are_lenient() {
        // 老配置文件里没有新字段时必须照样能起来
        let s: ServerConfig = toml::from_str("token = \"t\"").expect("最小服务端配置");
        // 不填端口时用 frp 原生的 7000（示例里也是这个值）
        assert_eq!(s.frp_bind_port(), 7000);
        assert!(s.p2p_port.is_none(), "默认不启用 P2P");
        assert!(!s.hot_reload);
        assert_eq!(s.max_clients, 0, "0 = 不限");

        let c: ClientConfig =
            toml::from_str("server_addr = \"127.0.0.1\"").expect("最小客户端配置");
        assert_eq!(c.server_port, 7000, "与 frp 原生默认值保持一致");
        assert!(c.p2p_enable, "默认允许 P2P，只是没端口可用");
    }
}
