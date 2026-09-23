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
/// 与 frp 配置里的 `transport.wireProtocol` **一一对应**，并且默认值也跟随官方：
///
/// * `frp-v1`    —— 官方 frpc/frps **至今为止的默认线协议**
///   （`pkg/config/v1/client.go`：`WireProtocol = util.EmptyOr(..., "v1")`）。
///   无魔术字，`[类型字节][i64 长度][JSON]`，登录后套 AES-128-CFB。
///   樱花这类第三方 frps 分支基本只认它。
/// * `frp-v2`    —— v0.70 引入的新协议，魔术字 + Hello 协商 + AEAD 帧流。
///   需要服务端也显式启用（官方 frps 会按魔术字自动识别，rustunnel-server 同理）。
/// * `rustunnel` —— rustunnel 自研的简化协议，尚未实现（配置成它会被直接拒绝）。
///
/// 想写哪种都行：`"v1"` / `"v2"` / `"frp-v1"` / `"frp-v2"` 都认，
/// 也可以直接照抄 frp 配置里的 `[transport] wireProtocol = "v2"`。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Protocol {
    #[default]
    FrpV1,
    FrpV2,
    Rustunnel,
}

impl Protocol {
    pub fn as_str(&self) -> &'static str {
        match self {
            Protocol::FrpV1 => "frp-v1",
            Protocol::FrpV2 => "frp-v2",
            Protocol::Rustunnel => "rustunnel",
        }
    }

    /// 对应的 frp 线协议版本；`rustunnel` 自研协议没有对应版本。
    pub fn wire_version(&self) -> Option<crate::frp::WireVersion> {
        match self {
            Protocol::FrpV1 => Some(crate::frp::WireVersion::V1),
            Protocol::FrpV2 => Some(crate::frp::WireVersion::V2),
            Protocol::Rustunnel => None,
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
            // 照抄 frp 的 `wireProtocol = "v1"` 也认；空值按官方 EmptyOr 的语义落到 v1
            "" | "v1" | "frp-v1" | "frpv1" | "frp" => Ok(Protocol::FrpV1),
            "v2" | "frp-v2" | "frpv2" => Ok(Protocol::FrpV2),
            "rustunnel" | "native" => Ok(Protocol::Rustunnel),
            other => Err(format!(
                "未知协议 {other}，可选：frp-v1（默认）/ frp-v2 / rustunnel"
            )),
        }
    }
}

impl Serialize for Protocol {
    fn serialize<S: serde::Serializer>(&self, s: S) -> std::result::Result<S::Ok, S::Error> {
        s.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for Protocol {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        s.parse::<Protocol>().map_err(serde::de::Error::custom)
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

    /// 线协议。服务端**按魔术字自动识别**对端走 v1 还是 v2（与官方 frps 一致），
    /// 所以这一项只是为了"原版 frps 的配置能直接喂进来"；同一端口可以同时
    /// 服务两种客户端。只有 `rustunnel` 自研协议尚未实现，会被直接拒绝。
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

    // ================= 以下为 v0.3.4 新增 =================
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
}

impl ServerConfig {
    /// frp 模式实际监听的端口。
    pub fn frp_bind_port(&self) -> u16 {
        self.bind_port.unwrap_or(self.control_port)
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
            auth: Default::default(),
            acl: Default::default(),
            roles: Vec::new(),
            default_role: String::new(),
            deny_unknown: false,
            audit: Default::default(),
            websocket: Default::default(),
            vnet: Default::default(),
            vnet_port: None,
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
        r##"# rustunnel-server 示例配置
# 用法：rustunnel-server -c server.toml
# 生成：rustunnel-server --gen-config server.toml

# ---- 基础 ----
bind_addr = "0.0.0.0"
bind_port = 7000
token = "your_secret_token"
log_level = "info"

# ---- 线协议 ----
# 不需要配：服务端和官方 frps 一样，靠**魔术字自动识别**对端是 v1 还是 v2
# （读 8 字节比对，不是 v2 魔术字就回填当 v1 的消息前缀）。
# 所以同一个端口上，官方 frpc（默认 v1）和 rustunnel（可配 v2）都能连。
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
"##
        .to_string()
    }
}

// ---------------------------------------------------------------------------
// 客户端配置
// ---------------------------------------------------------------------------

/// 单个代理的传输层配置（官方 frp 的 `[proxies.transport]`）。
///
/// 只放**真正实现了**的项。没实现的（`useEncryption` / `useCompression`）
/// 故意不在这里声明 —— 声明了却不生效，等于给用户一个"我加密了"的假象，
/// 那比配置报错危险得多。至今为止它们是"未知字段被忽略"，行为不变。
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ProxyTransportConfig {
    /// 与顶层 `proxyProtocolVersion` 是同一件事，两种写法都认
    /// （官方 frp 放这里，老式 INI 放代理顶层）。
    #[serde(
        default,
        rename = "proxyProtocolVersion",
        skip_serializing_if = "String::is_empty"
    )]
    pub proxy_protocol_version: String,
}

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
    /// 限流在哪一端执行：`client`（默认，等价于不写）/ `server`。
    ///
    /// 对应 frp 的 `transport.bandwidthLimitMode`。这个值会**原样上报给服务端**
    /// （见 [`crate::frp::msg::NewProxy`]），让服务端按同样的口径限速；
    /// 官方 frpc 只在值不是 `client` 时才发这个字段。
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub bandwidth_limit_mode: String,

    // ---- 代理级元数据 ----
    /// 随 `NewProxy` 消息带给服务端的键值对（官方 frp 的 `metadatas`）。
    ///
    /// ★ 和顶层 `[metadatas]` 不是一回事：
    /// - 顶层 `[metadatas]` → `Login.metas`，登录时就发了，平台靠它认账号/隧道；
    /// - 这里的 `[proxies.metadatas]` → `NewProxy.metas`，注册单条代理时才发。
    ///
    /// 官方 frpc 发的是**这一份**（`MarshalToMsg` 里的 `m.Metas = c.Metadatas`），
    /// 所以别把登录用的 metas 塞进来 —— 那会让报文和官方 frpc 不一致。
    #[serde(default, skip_serializing_if = "std::collections::HashMap::is_empty")]
    pub metas: std::collections::HashMap<String, String>,

    // ---- 负载均衡分组 ----
    /// 组名：同名组的多个代理可以**共享同一个 remote_port**，
    /// 服务端把用户连接按轮询分摊到组内各后端（官方 frp 的 `loadBalancer.group`）。
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub group: String,
    /// 组密钥（官方 frp 的 `groupKey`），同组代理保持一致即可，可留空。
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub group_key: String,

    // ---- Proxy Protocol ----
    /// 转发到内网服务时先发一个 PROXY 协议头，把**真实客户端 IP** 告诉后端。
    ///
    /// 为什么需要：隧道会在中间插一段，后端看到的对端地址永远变成
    /// `127.0.0.1`（客户端侧）—— 于是按 IP 做限流、审计、风控的功能全废。
    /// PROXY 协议就是在业务数据前多一段固定格式的头，把这个信息带过去。
    ///
    /// 取值（与官方 frp 的 `proxyProtocolVersion` 一致）：
    /// - `""`（默认）：不发，行为完全不变；
    /// - `"v1"`：文本格式 `PROXY TCP4 <src> <dst> <sport> <dport>`；
    /// - `"v2"`：二进制格式，支持 TLV 扩展、必须能塞进一个 TCP 段。
    ///
    /// ★ **后端必须支持它**（Nginx `proxy_protocol`、HAProxy `accept-proxy`、
    /// MySQL 8.0.29+ 等）。后端不认识时会把这段头当业务数据处理 ——
    /// 表现是"连上了但协议报错"，所以两端要一起改。
    #[serde(
        default,
        rename = "proxyProtocolVersion",
        skip_serializing_if = "String::is_empty"
    )]
    pub proxy_protocol_version: String,

    /// 官方 frp 的写法：`[proxies.transport] proxyProtocolVersion = "v2"`。
    #[serde(default)]
    pub transport: ProxyTransportConfig,

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

impl ProxyConfig {
    /// 实际生效的 PROXY 协议版本。
    ///
    /// 官方 frp 把它放在 `[proxies.transport]` 下，老式 INI 与早期 TOML 放在
    /// 代理顶层 —— 两种都认，`transport` 优先。
    ///
    /// 只认 `"v1"` / `"v2"`；**其它任何值都当"不启用"**（含空串）。
    /// 官方是"非 v1 即 v2"的写法，那意味着写错一个字母（`"V2"` 大写、
    /// `"2"`）都会悄悄往用户的后端灌一段二进制垃圾 —— 那比不生效难查得多。
    pub fn proxy_protocol_version(&self) -> Option<&'static str> {
        let raw = if self.transport.proxy_protocol_version.trim().is_empty() {
            self.proxy_protocol_version.trim()
        } else {
            self.transport.proxy_protocol_version.trim()
        };
        match raw.to_ascii_lowercase().as_str() {
            "" => None,
            "v1" => Some("v1"),
            "v2" => Some("v2"),
            _ => None,
        }
    }

    /// 是否配置了 PROXY 协议但写的是个不认识的值（启动时用来警告）。
    pub fn has_invalid_proxy_protocol_version(&self) -> Option<&str> {
        let raw = if self.transport.proxy_protocol_version.trim().is_empty() {
            self.proxy_protocol_version.trim()
        } else {
            self.transport.proxy_protocol_version.trim()
        };
        if raw.is_empty() || raw.eq_ignore_ascii_case("v1") || raw.eq_ignore_ascii_case("v2") {
            None
        } else {
            Some(raw)
        }
    }
}

/// 一个 visitor（访客）的配置，对应 frpc 的 `[[visitors]]` 段。///
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

    /// 附加元数据，原样随 `Login` 消息发给服务端（对应 frp 的 `[metadatas]`）。
    ///
    /// 为什么要有它：很多 frp 平台（LoliaFRP、OpenFrp 之类）不给全局 auth token，
    /// 而是**靠 `metas["token"]` 认出这是哪条隧道**。平台下发的配置长这样：
    ///
    /// ```toml
    /// [metadatas]
    /// token = 'x8p5mo0u8ips3lmohc67r58mejp7uthf'
    /// ```
    ///
    /// 少了这张表，服务端只会回一句没头没尾的「FRPC 配置文件错误」。
    #[serde(default)]
    pub metas: std::collections::HashMap<String, String>,

    /// 心跳间隔（秒）。
    #[serde(default = "default_heartbeat_interval")]
    pub heartbeat_interval: u64,

    /// 多久没收到 Pong 就认为连接已死（秒）。
    #[serde(default = "default_heartbeat_timeout")]
    pub heartbeat_timeout: u64,

    /// 控制连接断开后的重连间隔（秒）。
    #[serde(default = "default_reconnect_interval")]
    pub reconnect_interval: u64,

    /// **首次**登录失败后是否直接退出（对应 frp 的 `loginFailExit`，默认 `true`）。
    ///
    /// 语义与官方 frpc 对齐，不是"一失败就永远不重试"：
    /// - 进程启动后第一次登录（连不上 / 认证被拒 / 握手失败）如果失败，
    ///   直接以非 0 退出码结束 —— 这样外部启动器（NetTool、systemd 之流）
    ///   能立刻知道"没起来"并把错误原样报给用户，而不是显示一个假的"已启动"；
    /// - **一旦成功登录过**，之后断线就永远按 `reconnect_interval` 重连，不受此项影响。
    ///
    /// 官方 frp 里这一项默认就是 `true`（`pkg/config/v1/client.go`：
    /// `c.LoginFailExit = util.EmptyOr(c.LoginFailExit, lo.ToPtr(true))`），
    /// 想让客户端无脑一直重试就写 `loginFailExit = false`。
    #[serde(default = "default_true")]
    pub login_fail_exit: bool,

    /// 线协议：默认 `frp-v1`（与原版 frp 一致，樱花这类第三方 frps 只认它），
    /// 也可以写 `frp-v2` 或照抄原版 frp 配置里的 `transport.wireProtocol`。
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

    /// xtcp 直连建好之后跑哪种传输：`quic`（默认）或 `kcp`。
    ///
    /// KCP 的重传更激进（不等 RTO、可跳包重传），在高丢包 / 高延迟链路
    /// （移动网络、跨国）上往往能压出更低延迟；代价是不自带加密 ——
    /// P2P 通道本来就要过一遍应用层口令鉴权，所以这里差别不大。
    ///
    /// 两端不必配置一致：**visitor 的选择会通过牵线服务端同步给 provider**。
    #[serde(default = "default_xtcp_transport")]
    pub xtcp_transport: String,

    /// 对称 NAT 下是否启用端口预测（默认开）。
    ///
    /// 对称 NAT 给"每换一个目的地"分配一个新公网端口，于是服务端看到的端口
    /// 根本不是 peer 之间通信用的端口 —— 官方 frp 到这里就只能回退中继。
    /// 现实里这一类 NAT 大多是**顺序分配**端口的，于是可以先采样几个端口、
    /// 推出步长、预测下一个，再把候选端口全部打一遍。
    ///
    /// 关掉它就退回官方行为（只打牵线下发的那一个地址）。
    #[serde(default = "default_true")]
    pub xtcp_port_predict: bool,

    /// 端口预测的候选窗口（往预测值之后推几个）。
    #[serde(default = "default_predict_window")]
    pub xtcp_predict_window: u16,

    /// 是否在 `Login` 里声明 rustunnel 私有能力（默认开）。
    ///
    /// 开了之后，服务端才能在面板上增删本端的代理、以及让 v1 下的 UDP 报文
    /// 走二进制编码。能力**必须经服务端回显**才生效，所以连官方 frps /
    /// 第三方 frps 时对方不会回显，行为与不开完全一致。
    ///
    /// 唯一需要关掉它的场景：遇到一个会**严格校验** `Login` 字段的非 Go 实现
    /// （Go 的 `encoding/json` 会忽略未知字段，绝大多数服务端都是 Go 写的）。
    #[serde(default = "default_true")]
    pub private_caps: bool,

    /// 需要暴露的代理列表。
    #[serde(default)]
    pub proxies: Vec<ProxyConfig>,

    /// 需要接入的访客列表（stcp / xtcp）。
    #[serde(default)]
    pub visitors: Vec<VisitorConfig>,

    // ================= 以下为 v0.3.4 新增 =================
    // 同样全部默认关闭，老的 client.toml 行为不变。
    /// 认证配置（`[auth]`）：`method = "token" | "oidc"` + `auth.oidc.*`。
    #[serde(default)]
    pub auth: crate::security::ClientAuthConfig,

    /// 动态代理的持久化（`[store]`）。
    ///
    /// 面板 / 客户端 Web UI 上临时加的代理，默认只活在内存里，进程一重启就没了。
    /// 配了 `store.path` 之后会落盘，重启时自动恢复 —— 这也是官方 frp
    /// `frpc store` 的语义。
    #[serde(default)]
    pub store: StoreConfig,

    /// 客户端自带的 Web 管理界面（`[webServer]`）。
    #[serde(default, rename = "webServer")]
    pub web_server: WebServerConfig,

    /// WebSocket 传输（`[transport.websocket]`）。
    #[serde(default)]
    pub websocket: crate::ws::WebSocketConfig,

    /// 是否让控制连接走 WebSocket（`transport.websocket.enable` 的等价开关）。
    ///
    /// 有些防火墙只放行 HTTP(S)，裸 TCP 一律丢包；这时把控制连接包进
    /// WebSocket 帧就能过去。走的是**同一个端口**，服务端自动识别，不用改配置。
    #[serde(default, rename = "websocketEnable")]
    pub websocket_enable: bool,

    /// VirtualNet 虚拟网络（`[virtualNet]`）。
    #[serde(default, rename = "virtualNet")]
    pub virtual_net: crate::vnet::VirtualNetConfig,
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
            metas: Default::default(),
            heartbeat_interval: default_heartbeat_interval(),
            heartbeat_timeout: default_heartbeat_timeout(),
            reconnect_interval: default_reconnect_interval(),
            login_fail_exit: true,
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
            xtcp_transport: default_xtcp_transport(),
            xtcp_port_predict: true,
            xtcp_predict_window: default_predict_window(),
            private_caps: true,
            proxies: Vec::new(),
            visitors: Vec::new(),
            auth: Default::default(),
            store: Default::default(),
            web_server: Default::default(),
            websocket: Default::default(),
            websocket_enable: false,
            virtual_net: Default::default(),
        }
    }
}

// ---------------------------------------------------------------------------
// 客户端管理相关配置
// ---------------------------------------------------------------------------

/// 动态代理的持久化配置（`[store]`）。
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct StoreConfig {
    /// 落盘路径。留空 = 不持久化（与老版本一致）。
    ///
    /// 目录会自动创建。文件内容是 JSON，与 rustunnel 自己的格式兼容；
    /// **官方 frp 的 store 是另一套结构**（Go 的 `configmgmt` 序列化），
    /// 两者不通用 —— 换实现时需要重新加一遍代理，这一点在 README 里写明了。
    pub path: String,
}

/// 客户端 Web 管理界面配置（`[webServer]`）。
///
/// 官方 frpc 也有同名段落，字段名保持一致（`addr` / `port` / `user` / `password`）。
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct WebServerConfig {
    /// 监听地址。**默认 `127.0.0.1`** —— 这个界面能动态开端口，
    /// 默认暴露到公网等于把内网敞开，需要远程访问请显式写 `0.0.0.0`
    /// 并**务必配上 user/password**。
    pub addr: String,
    /// 监听端口。0 = 不启用。
    pub port: u16,
    /// Basic Auth 用户名。留空表示不鉴权。
    pub user: String,
    /// Basic Auth 密码。
    pub password: String,
}

fn default_webserver_addr() -> String {
    "127.0.0.1".into()
}

impl Default for WebServerConfig {
    fn default() -> Self {
        Self {
            addr: default_webserver_addr(),
            port: 0,
            user: String::new(),
            password: String::new(),
        }
    }
}

impl WebServerConfig {
    pub fn is_enabled(&self) -> bool {
        self.port != 0
    }
}

impl ClientConfig {
    /// 是否让控制连接（以及它上面的工作连接）走 WebSocket 传输。
    ///
    /// 两种写法等价，都认：
    /// - 官方原味：`transport.protocol = "websocket"`（或 `"wss"`）；
    /// - 速记开关：`transport.websocket.enable = true` / `websocketEnable = true`。
    pub fn websocket_enabled(&self) -> bool {
        self.websocket_enable
            || is_websocket(&self.transport_protocol)
            || is_wss(&self.transport_protocol)
    }

    /// WebSocket 之前是否要先做 TLS（也就是 `wss`）。
    pub fn websocket_tls(&self) -> bool {
        is_wss(&self.transport_protocol)
    }

    /// 实际生效的共享密钥。
    ///
    /// `[auth] token` 与顶层 `token` 都能写；**新的优先、旧的兜底**，
    /// 与官方 frp 的 `auth.token` 展开式配置兼容。
    pub fn effective_token(&self) -> &str {
        if self.auth.token.is_empty() {
            &self.token
        } else {
            &self.auth.token
        }
    }

    /// 从配置文件加载（**自动识别 TOML / 原版 frpc 的 legacy INI**）。
    ///
    /// 走 [`parse_client`]，因此**原版 frpc 的配置文件可以直接用** ——
    /// 不管是新式 `frpc.toml` 还是老式 `frpc.ini`（樱花这类平台就是按
    /// `frpc -v` 的版本协商结果决定下发哪一种）。
    pub fn load<P: AsRef<Path>>(path: P) -> Result<Self> {
        let raw = std::fs::read_to_string(path.as_ref()).map_err(crate::error::Error::Io)?;
        parse_client(&raw)
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

# ---- 线协议（对应原版 frp 的 `transport.wireProtocol`，默认就是 v1）----
# v1：原版 frp 至今的默认协议，无魔术字、消息体是裸 JSON、登录后套 AES-128-CFB。
#     樱花 / 各类第三方 frps 分支基本只认它 —— 这也是 rustunnel 的默认值。
# v2：v0.70 引入的新协议，魔术字 + Hello 协商 + AES-256-GCM AEAD 帧流，
#     需要服务端也支持（rustunnel-server 会自动识别，无需配置）。
# 写错的表现是"连上就断"，日志里不会告诉你原因，所以拿不准就别写。
# protocol = "frp-v1"
# protocol = "frp-v2"

# ---- 启动失败时的行为（对应原版 frp 的 loginFailExit，默认 true）----
# true：**首次**登录失败就退出（退出码非 0）。
#       外部启动器靠"进程退没退"判断隧道起没起来，所以默认跟随 frp 取 true；
#       连不上时会立刻报错，而不是默默重试、让面板误显示"已启动"。
# false：无脑一直重试。手机热点 / 隧道机房抖动等场景更耐操。
# 注意：**成功登录过之后**，断线永远会自动重连，不受这一项影响。
# login_fail_exit = true

# ---- 附加元数据（原版 frp 叫 `[metadatas]`，会原样发给服务端）----
# 大多数场景不需要；但 LoliaFRP / OpenFrp 这类平台靠 metas 里的 token
# 认出隧道，从平台拿到的配置里带这一段，照抄即可。
# [metadatas]
# token = "平台给的隧道令牌"

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

# ---- 带宽限流（原版 frp 叫 [proxies.transport] bandwidthLimit）----
# 单位是字节/秒，写法 `KB`=1000、`KiB`=1024。留空或 0 表示不限。
# bandwidth_limit = "25MB"
# bandwidth_limit_mode = "server"   # client（默认）/ server：限流在哪一端执行

# ---- 代理级元数据（原版 frp 叫 [proxies.metadatas]）----
# 注意和顶层 [metadatas] 是两回事：顶层那份进登录消息（平台靠它认隧道），
# 这一份随注册单条代理的 NewProxy 一起上报。大多数场景用不到。
# [proxies.metadatas]
# role = "web"

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

/// xtcp 默认传输：QUIC 自带加密与拥塞控制，是通用场景下的稳妥选择。
fn default_xtcp_transport() -> String {
    "quic".to_string()
}

/// 端口预测的默认窗口（往预测值之后推几个端口）。
fn default_predict_window() -> u16 {
    crate::p2p::PREDICT_WINDOW
}

fn default_transport_protocol() -> String {
    "tcp".to_string()
}

/// 判断配置是否选择了 QUIC 传输（大小写与下划线一律宽容处理）。
pub fn is_quic(protocol: &str) -> bool {
    let p = protocol.trim().to_ascii_lowercase().replace(['-', '_'], "");
    p == "quic"
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

// ---------------------------------------------------------------------------
// 带原版 frp 兼容的解析入口
// ---------------------------------------------------------------------------

/// 解析客户端配置文本，**自动识别 TOML / legacy INI**。
///
/// 嗅探顺序与官方 frp 一致（`pkg/config/load.go` 的 `LoadClientConfigResult`）：
/// 先看是不是 legacy INI（能解析出 `[common]` 段），不是才按 TOML 走。
/// 判定逻辑见 [`crate::frp_legacy::is_legacy_ini`]。
///
/// 之所以不能只看扩展名：各种面板 / 启动器把配置写到哪个后缀是它们自己的事
/// （樱花就把同一份隧道同时给 `.ini` 和 `.toml` 两份），而官方 frp 也确实是
/// 按**内容**判定的。
pub fn parse_client(raw: &str) -> Result<ClientConfig> {
    let cfg = if crate::frp_legacy::is_legacy_ini(raw) {
        let value = crate::frp_legacy::legacy_client_to_value(raw)?;
        let cfg: ClientConfig = value.try_into()?;
        cfg
    } else {
        parse_client_toml(raw)?
    };
    reject_unimplemented_types(&cfg)?;
    Ok(cfg)
}

/// 解析服务端配置文本，自动识别 TOML / legacy INI。规则同 [`parse_client`]。
pub fn parse_server(raw: &str) -> Result<ServerConfig> {
    if crate::frp_legacy::is_legacy_ini(raw) {
        let value = crate::frp_legacy::legacy_server_to_value(raw)?;
        return Ok(value.try_into()?);
    }
    parse_server_toml(raw)
}

/// rustunnel 真正实现的代理 / 访客类型。
///
/// 原版 frp 还认 `tcpmux` 与 `sudp`，rustunnel 没实现。**宁可在这里报错，
/// 也不能静默当成 tcp 放过去** —— 静默降级会"看起来连上了"，实际按错的语义
/// 转发用户流量，比启动阶段报一句清楚的话危险得多。
///
/// （官方 frp 对未知 `type` 同样是在解码阶段直接报错，所以这也不算额外收紧。）
const SUPPORTED_PROXY_TYPES: &[&str] = &["tcp", "udp", "http", "https", "stcp", "xtcp"];
const SUPPORTED_VISITOR_TYPES: &[&str] = &["stcp", "xtcp"];

fn reject_unimplemented_types(cfg: &ClientConfig) -> Result<()> {
    for p in &cfg.proxies {
        if !SUPPORTED_PROXY_TYPES.contains(&p.proxy_type.as_str()) {
            return Err(crate::error::Error::Protocol(format!(
                "代理 [{}] 的类型 {:?} 不受支持（rustunnel 实现了 {}）",
                p.name,
                p.proxy_type,
                SUPPORTED_PROXY_TYPES.join(" / ")
            )));
        }
    }
    for v in &cfg.visitors {
        if !SUPPORTED_VISITOR_TYPES.contains(&v.visitor_type.as_str()) {
            return Err(crate::error::Error::Protocol(format!(
                "访客 [{}] 的类型 {:?} 不受支持（rustunnel 实现了 {}）",
                v.name,
                v.visitor_type,
                SUPPORTED_VISITOR_TYPES.join(" / ")
            )));
        }
    }
    Ok(())
}

/// 解析客户端配置文本（**仅 TOML**）。
///
/// 解析前先过一遍 [`crate::frp_config::normalize_client`]，所以**原版 frpc 的
/// 配置可以直接拿来用**（`serverAddr` / `localIP` / `localPort` / `auth.token` /
/// 顶层 `[metadatas]` ...）。rustunnel 自己的写法同时有效，两种写法混用时原生字段优先。
///
/// 需要"连 legacy INI 一起认"时用 [`parse_client`]（`ClientConfig::load` 走的那个）。
pub fn parse_client_toml(raw: &str) -> Result<ClientConfig> {
    let mut value: toml::Value = toml::from_str(raw)?;
    crate::frp_config::normalize_client(&mut value);
    Ok(value.try_into()?)
}

/// 解析服务端配置文本（**仅 TOML**）。同 [`parse_client_toml`]，兼容原版 `frps.toml` 的字段名。
pub fn parse_server_toml(raw: &str) -> Result<ServerConfig> {
    let mut value: toml::Value = toml::from_str(raw)?;
    crate::frp_config::normalize_server(&mut value);
    Ok(value.try_into()?)
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
