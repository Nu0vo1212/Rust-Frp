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
    pub fn example_toml() -> String {
        let cfg = ServerConfig {
            token: "your_secret_token".into(),
            ..Default::default()
        };
        let body = toml::to_string_pretty(&cfg).unwrap_or_default();
        format!(
            "# rustunnel-server 示例配置\n\
             # 用法：rustunnel-server -c server.toml\n\
             # 生成：rustunnel-server --gen-config server.toml\n\
             \n\
             {body}"
        )
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
    pub fn example_toml() -> String {
        let cfg = ClientConfig {
            token: "your_secret_token".into(),
            proxies: vec![ProxyConfig {
                name: "ssh".into(),
                proxy_type: "tcp".into(),
                local_addr: "127.0.0.1:22".into(),
                remote_port: 6000,
                ..Default::default()
            }],
            ..Default::default()
        };
        let body = toml::to_string_pretty(&cfg).unwrap_or_default();
        format!(
            "# rustunnel-client 示例配置\n\
             # 用法：rustunnel-client -c client.toml\n\
             # 生成：rustunnel-client --gen-config client.toml\n\
             \n\
             {body}"
        )
    }
}

// ---------------------------------------------------------------------------
// serde 默认值
// ---------------------------------------------------------------------------

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
