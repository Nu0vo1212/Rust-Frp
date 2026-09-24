//! frp v2 消息类型（`pkg/msg/msg.go` + `pkg/msg/wire_v2.go`）。
//!
//! 帧负载 = `2 字节大端 type_id` + `JSON`。
//! JSON 字段名与 Go `json:"...,omitempty"` 标签一致，因此这里用
//! `skip_serializing_if` 复刻 omitempty 语义，保证与官方字节兼容。

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::config::ProxyConfig;

// v2 消息 type_id（pkg/msg/wire_v2.go）
pub const TYPE_LOGIN: u16 = 1;
pub const TYPE_LOGIN_RESP: u16 = 2;
pub const TYPE_NEW_PROXY: u16 = 3;
pub const TYPE_NEW_PROXY_RESP: u16 = 4;
pub const TYPE_CLOSE_PROXY: u16 = 5;
pub const TYPE_NEW_WORK_CONN: u16 = 6;
pub const TYPE_REQ_WORK_CONN: u16 = 7;
pub const TYPE_START_WORK_CONN: u16 = 8;
pub const TYPE_NEW_VISITOR_CONN: u16 = 9;
pub const TYPE_NEW_VISITOR_CONN_RESP: u16 = 10;
pub const TYPE_PING: u16 = 11;
pub const TYPE_PONG: u16 = 12;
pub const TYPE_UDP_PACKET: u16 = 13;
/// xtcp 打洞协调用的 5 种消息（`pkg/msg/wire_v2.go` 14~18）。
pub const TYPE_NAT_HOLE_VISITOR: u16 = 14;
pub const TYPE_NAT_HOLE_CLIENT: u16 = 15;
pub const TYPE_NAT_HOLE_RESP: u16 = 16;
pub const TYPE_NAT_HOLE_SID: u16 = 17;
pub const TYPE_NAT_HOLE_REPORT: u16 = 18;
/// UDP 报文的**二进制**编码（v2 握手协商后默认用它）：
/// `pkg/msg/udp_binary.go` 的 `V2TypeUDPPacketBinary`。
pub const TYPE_UDP_PACKET_BINARY: u16 = 19;
/// rustunnel 私有的服务端管理命令（面板增删代理）。
///
/// 从 100 起步是故意的：官方 frp 目前只用到 19，留足空间避免将来撞号。
/// 而且它只会出现在**双方都声明了能力**的会话里（见 [`RustunnelCaps`]），
/// 官方 frpc 一辈子也不会收到这个 type_id。
pub const TYPE_SERVER_CMD: u16 = 100;
/// [`TYPE_SERVER_CMD`] 的回执。
pub const TYPE_SERVER_CMD_RESP: u16 = 101;

fn is_false(b: &bool) -> bool {
    !*b
}
fn is_zero_u16(v: &u16) -> bool {
    *v == 0
}
fn is_zero_i64(v: &i64) -> bool {
    *v == 0
}
fn is_empty_str(s: &str) -> bool {
    s.is_empty()
}
fn is_empty_map(m: &HashMap<String, String>) -> bool {
    m.is_empty()
}

// ---------------------------------------------------------------------------
// 消息体
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Login {
    #[serde(default, skip_serializing_if = "is_empty_str")]
    pub version: String,
    #[serde(default, skip_serializing_if = "is_empty_str")]
    pub hostname: String,
    #[serde(default, skip_serializing_if = "is_empty_str")]
    pub os: String,
    #[serde(default, skip_serializing_if = "is_empty_str")]
    pub arch: String,
    #[serde(default, skip_serializing_if = "is_empty_str")]
    pub user: String,
    #[serde(default, skip_serializing_if = "is_empty_str")]
    pub privilege_key: String,
    #[serde(default, skip_serializing_if = "is_zero_i64")]
    pub timestamp: i64,
    #[serde(default, skip_serializing_if = "is_empty_str")]
    pub run_id: String,
    #[serde(default, skip_serializing_if = "is_empty_str")]
    pub client_id: String,
    #[serde(default, skip_serializing_if = "is_empty_map")]
    pub metas: HashMap<String, String>,
    #[serde(default)]
    pub pool_count: i32,
    /// 本端**支持**的 rustunnel 私有能力（能力清单见 [`RustunnelCaps`]）。
    ///
    /// 注意这只是"我支持"，**不等于已启用**：必须由服务端在 `LoginResp` 里
    /// 回显才算协商成功。理由见 [`RustunnelCaps`] 的文档。
    #[serde(
        rename = "_rustunnel",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub rustunnel: Option<RustunnelCaps>,
}

/// rustunnel 的**私有能力协商**。
///
/// # 为什么可以往官方消息里塞字段
///
/// 官方 frps / frpc 与市面上所有第三方 frps 都是 Go 写的，解析消息用
/// `encoding/json` —— 它对**未知字段是直接忽略**的，不会因为多了一个键就报错。
/// 所以往 `Login` / `LoginResp` 里挂一个额外字段是零风险的：
///
/// * 对方是官方 frps → 它看不见这个字段，也就**永远不会回显**能力；
///   客户端拿不到回显就不开启，行为与今天完全一致；
/// * 对方是 rustunnel 服务端 → 双方协商，开启增强能力。
///
/// 反过来说：**绝不能只看客户端自己声明了就启用**。否则连官方 frps 时
/// 客户端会按"已协商"行事（比如发二进制 UDP），而服务端回的是 JSON，
/// 两边直接鸡同鸭讲。所以必须由**服务端回显**才算数。
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct RustunnelCaps {
    /// v1 线协议下也用二进制 UDP 报文编码。
    ///
    /// v2 本来就有（握手协商出来的），v1 官方只支持 JSON —— 而 JSON 版要把
    /// 载荷做 base64，每个包多出 ~33% 的体积加几十字节字段名。UDP 代理在
    /// v1（也就是**默认**协议）下正是最需要省这几个字节的场景。
    #[serde(default, skip_serializing_if = "is_false")]
    pub udp_binary: bool,
    /// 支持服务端下发管理命令（面板上增删代理 / 踢人）。
    #[serde(default, skip_serializing_if = "is_false")]
    pub server_cmd: bool,
}

impl RustunnelCaps {
    /// 有没有任何一项被打开；没有就整个字段都不往报文里写。
    pub fn any(&self) -> bool {
        self.udp_binary || self.server_cmd
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct LoginResp {
    #[serde(default, skip_serializing_if = "is_empty_str")]
    pub version: String,
    #[serde(default, skip_serializing_if = "is_empty_str")]
    pub run_id: String,
    #[serde(default, skip_serializing_if = "is_empty_str")]
    pub error: String,
    /// 服务端**确认**启用的 rustunnel 私有能力（见 [`RustunnelCaps`]）。
    ///
    /// 只有这里出现了的能力才算协商成功。官方 frps 不会回这个字段。
    #[serde(
        rename = "_rustunnel",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub rustunnel: Option<RustunnelCaps>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct NewProxy {
    #[serde(default, skip_serializing_if = "is_empty_str")]
    pub proxy_name: String,
    #[serde(default, skip_serializing_if = "is_empty_str")]
    pub proxy_type: String,
    #[serde(default, skip_serializing_if = "is_false")]
    pub use_encryption: bool,
    #[serde(default, skip_serializing_if = "is_false")]
    pub use_compression: bool,
    /// 带宽上限的字符串写法（`1MB` / `500KB` / `25MB`…）。
    ///
    /// 对应官方 frpc `ProxyBaseConfig.MarshalToMsg` 里的
    /// `m.BandwidthLimit = c.Transport.BandwidthLimit.String()` —— 配了才发，
    /// 没配就是空串（`omitempty` 直接省略）。第三方平台会照它做限流校验，
    /// 所以本地配了 `[proxies.transport] bandwidthLimit` 就得原样带上去。
    #[serde(default, skip_serializing_if = "is_empty_str")]
    pub bandwidth_limit: String,
    /// 限流在哪一端执行：`client`（默认）/ `server`。
    ///
    /// ★ 官方 frpc **只在值不等于默认的 `client` 时才发**
    /// （`MarshalToMsg` 里写着 `if c.Transport.BandwidthLimitMode != "client"`）。
    /// 所以发之前必须把 `client` 归一化成空串，否则报文和官方 frpc 不一致。
    #[serde(default, skip_serializing_if = "is_empty_str")]
    pub bandwidth_limit_mode: String,
    #[serde(default, skip_serializing_if = "is_empty_str")]
    pub group: String,
    #[serde(default, skip_serializing_if = "is_empty_str")]
    pub group_key: String,
    #[serde(default, skip_serializing_if = "is_empty_map")]
    pub metas: HashMap<String, String>,
    /// 仅 tcp / udp 使用。
    #[serde(default, skip_serializing_if = "is_zero_u16")]
    pub remote_port: u16,

    // ---- http / https 使用（Go: pkg/msg/msg.go NewProxy）----
    /// 自定义域名列表，对应 frpc 的 `customDomains`。
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub custom_domains: Vec<String>,
    /// 泛域名子域前缀，配合服务端 `subdomain_host` 使用。
    #[serde(default, skip_serializing_if = "is_empty_str")]
    pub subdomain: String,
    /// 路由前缀（默认 `/`）。
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub locations: Vec<String>,
    #[serde(default, skip_serializing_if = "is_empty_str")]
    pub http_user: String,
    #[serde(default, skip_serializing_if = "is_empty_str")]
    pub http_pwd: String,
    /// 转发时重写 Host 头。
    #[serde(default, skip_serializing_if = "is_empty_str")]
    pub host_header_rewrite: String,
    /// 追加的请求头 / 响应头。
    #[serde(default, skip_serializing_if = "is_empty_map")]
    pub headers: HashMap<String, String>,
    #[serde(default, skip_serializing_if = "is_empty_map")]
    pub response_headers: HashMap<String, String>,
    /// 按 HTTP Basic Auth 用户名路由。
    #[serde(default, skip_serializing_if = "is_empty_str")]
    pub route_by_http_user: String,

    // ---- stcp / xtcp / sudp 使用（Go: NewProxy 的 Sk / AllowUsers）----
    /// 共享密钥：visitor 必须提供相同的 `sk` 算出签名才能接入。
    #[serde(default, skip_serializing_if = "is_empty_str")]
    pub sk: String,
    /// 允许的访客用户列表；空表示只允许同用户的访客。
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allow_users: Vec<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct NewProxyResp {
    #[serde(default, skip_serializing_if = "is_empty_str")]
    pub proxy_name: String,
    #[serde(default, skip_serializing_if = "is_empty_str")]
    pub remote_addr: String,
    #[serde(default, skip_serializing_if = "is_empty_str")]
    pub error: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CloseProxy {
    #[serde(default, skip_serializing_if = "is_empty_str")]
    pub proxy_name: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct NewWorkConn {
    #[serde(default, skip_serializing_if = "is_empty_str")]
    pub run_id: String,
    #[serde(default, skip_serializing_if = "is_empty_str")]
    pub privilege_key: String,
    #[serde(default, skip_serializing_if = "is_zero_i64")]
    pub timestamp: i64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct StartWorkConn {
    #[serde(default, skip_serializing_if = "is_empty_str")]
    pub proxy_name: String,
    #[serde(default, skip_serializing_if = "is_empty_str")]
    pub src_addr: String,
    #[serde(default, skip_serializing_if = "is_empty_str")]
    pub dst_addr: String,
    #[serde(default, skip_serializing_if = "is_zero_u16")]
    pub src_port: u16,
    #[serde(default, skip_serializing_if = "is_zero_u16")]
    pub dst_port: u16,
    #[serde(default, skip_serializing_if = "is_empty_str")]
    pub error: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Ping {
    #[serde(default, skip_serializing_if = "is_empty_str")]
    pub privilege_key: String,
    #[serde(default, skip_serializing_if = "is_zero_i64")]
    pub timestamp: i64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Pong {
    #[serde(default, skip_serializing_if = "is_empty_str")]
    pub error: String,
}

// ---------------------------------------------------------------------------
// visitor 连接（stcp / xtcp / sudp 的接入方）
// ---------------------------------------------------------------------------
//
// visitor 与 provider 是**两个不同的 frpc 进程**：
// * provider 注册一条 `stcp` 代理，服务端为它建一个"内部 listener"；
// * visitor 在本地 `bindAddr:bindPort` 监听，每来一个连接就新开一条工作连接，
//   先发 `NewVisitorConn` 表明身份，收到 `NewVisitorConnResp` 成功后
//   **这条连接本身就是裸字节数据通道**（不再有 frp 帧）。

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct NewVisitorConn {
    /// visitor 自己的控制会话 run_id（服务端据此找到对应控制连接做校验）。
    #[serde(default, skip_serializing_if = "is_empty_str")]
    pub run_id: String,
    /// 目标代理名（provider 注册时用的 `proxy_name`）。
    #[serde(default, skip_serializing_if = "is_empty_str")]
    pub proxy_name: String,
    /// `hex(md5(secret_key + timestamp))`，与 token 鉴权算法相同。
    #[serde(default, skip_serializing_if = "is_empty_str")]
    pub sign_key: String,
    #[serde(default, skip_serializing_if = "is_zero_i64")]
    pub timestamp: i64,
    #[serde(default, skip_serializing_if = "is_false")]
    pub use_encryption: bool,
    #[serde(default, skip_serializing_if = "is_false")]
    pub use_compression: bool,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct NewVisitorConnResp {
    #[serde(default, skip_serializing_if = "is_empty_str")]
    pub proxy_name: String,
    #[serde(default, skip_serializing_if = "is_empty_str")]
    pub error: String,
}

// ---------------------------------------------------------------------------
// xtcp 打洞协调消息（1:1 对应 Go 的 msg.NatHole*）
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct NatHoleVisitor {
    #[serde(default, skip_serializing_if = "is_empty_str")]
    pub transaction_id: String,
    #[serde(default, skip_serializing_if = "is_empty_str")]
    pub proxy_name: String,
    #[serde(default, skip_serializing_if = "is_false")]
    pub pre_check: bool,
    #[serde(default, skip_serializing_if = "is_empty_str")]
    pub protocol: String,
    #[serde(default, skip_serializing_if = "is_empty_str")]
    pub sign_key: String,
    #[serde(default, skip_serializing_if = "is_zero_i64")]
    pub timestamp: i64,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub mapped_addrs: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub assisted_addrs: Vec<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct NatHoleClient {
    #[serde(default, skip_serializing_if = "is_empty_str")]
    pub transaction_id: String,
    #[serde(default, skip_serializing_if = "is_empty_str")]
    pub proxy_name: String,
    #[serde(default, skip_serializing_if = "is_empty_str")]
    pub sid: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub mapped_addrs: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub assisted_addrs: Vec<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PortsRange {
    #[serde(default, skip_serializing_if = "is_zero_i64")]
    pub from: i64,
    #[serde(default, skip_serializing_if = "is_zero_i64")]
    pub to: i64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct NatHoleDetectBehavior {
    /// `sender` 或 `receiver`。
    #[serde(default, skip_serializing_if = "is_empty_str")]
    pub role: String,
    #[serde(default, skip_serializing_if = "is_zero_i64")]
    pub mode: i64,
    #[serde(default, skip_serializing_if = "is_zero_i64")]
    pub ttl: i64,
    #[serde(default, skip_serializing_if = "is_zero_i64")]
    pub send_delay_ms: i64,
    #[serde(default, skip_serializing_if = "is_zero_i64")]
    pub read_timeout_ms: i64,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub candidate_ports: Vec<PortsRange>,
    #[serde(default, skip_serializing_if = "is_zero_i64")]
    pub send_random_ports: i64,
    #[serde(default, skip_serializing_if = "is_zero_i64")]
    pub listen_random_ports: i64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct NatHoleResp {
    #[serde(default, skip_serializing_if = "is_empty_str")]
    pub transaction_id: String,
    #[serde(default, skip_serializing_if = "is_empty_str")]
    pub sid: String,
    #[serde(default, skip_serializing_if = "is_empty_str")]
    pub protocol: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub candidate_addrs: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub assisted_addrs: Vec<String>,
    #[serde(default)]
    pub detect_behavior: NatHoleDetectBehavior,
    #[serde(default, skip_serializing_if = "is_empty_str")]
    pub error: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct NatHoleSid {
    #[serde(default, skip_serializing_if = "is_empty_str")]
    pub transaction_id: String,
    #[serde(default, skip_serializing_if = "is_empty_str")]
    pub sid: String,
    #[serde(default, skip_serializing_if = "is_false")]
    pub response: bool,
    #[serde(default, skip_serializing_if = "is_empty_str")]
    pub nonce: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct NatHoleReport {
    #[serde(default, skip_serializing_if = "is_empty_str")]
    pub sid: String,
    #[serde(default, skip_serializing_if = "is_false")]
    pub success: bool,
}

// ---------------------------------------------------------------------------
// rustunnel 私有的服务端管理命令（面板：增删代理 / 踢人）
// ---------------------------------------------------------------------------
//
// 官方 frp 的消息类型表里没有"服务端让客户端加一条代理"这种东西 ——
// 官方的做法要么是改配置文件后热重载，要么是 frpc 自己开一个管理 API。
// 想让**面板**直接下发，就必须有这条消息。
//
// 安全边界很清楚：服务端只会在客户端于 `Login` 里声明了 `server_cmd`
// 能力时才发它（见 [`RustunnelCaps`]），官方 frpc 永远不会收到。

/// 面板下发的管理命令：新增一条代理。
pub const CMD_ADD_PROXY: &str = "add_proxy";
/// 面板下发的管理命令：停掉一条代理。
pub const CMD_REMOVE_PROXY: &str = "remove_proxy";

/// 服务端 → 客户端的管理命令。
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ServerCmd {
    /// 命令 ID，回执里**原样带回**。
    ///
    /// 服务端靠它把 `ServerCmdResp` 对回自己正在等的那条命令 ——
    /// 面板一次只发一条，但控制连接上还跑着心跳、工作连接请求，
    /// 没有 ID 就只能"收到回执就算这条成了"，并发时必然串行出错。
    #[serde(default, skip_serializing_if = "is_empty_str")]
    pub id: String,
    /// [`CMD_ADD_PROXY`] / [`CMD_REMOVE_PROXY`]。
    #[serde(default, skip_serializing_if = "is_empty_str")]
    pub op: String,
    /// 目标代理名（**不带** `{user}.` 前缀，客户端自己会加）。
    ///
    /// `add_proxy` 时若与 `proxy.name` 不一致，以 `proxy.name` 为准。
    #[serde(default, skip_serializing_if = "is_empty_str")]
    pub proxy_name: String,
    /// `add_proxy` 时携带的整条代理配置（原版 frp `[[proxies]]` 的 JSON 形态）。
    ///
    /// 用 `serde_json::Value` 而不是 `ProxyConfig`：这条消息要能被任何版本的
    /// 客户端解析，配置结构体演进时不该因为一个字段改名就把整条命令打废。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proxy: Option<serde_json::Value>,
    /// 给人看的理由（会进客户端日志）。
    #[serde(default, skip_serializing_if = "is_empty_str")]
    pub reason: String,
}

impl NewProxy {
    pub fn from_config(p: &ProxyConfig, user: &str) -> Self {
        // 线上名字 = `{user}.{name}`，与官方 frpc 的 `wireName` 对齐
        let proxy_name = crate::util::add_user_prefix(user, &p.name);

        // 官方 frpc 只在值**不等于默认的 `client`** 时才发 `bandwidth_limit_mode`
        // （`MarshalToMsg` 里写着 `if c.Transport.BandwidthLimitMode != "client"`），
        // 所以这里把 `client` 归一化成空串，报文才能和官方 frpc 逐字段一致。
        let bandwidth_limit_mode = if p.bandwidth_limit_mode.eq_ignore_ascii_case("client") {
            String::new()
        } else {
            p.bandwidth_limit_mode.clone()
        };

        let mut m = NewProxy {
            proxy_name,
            proxy_type: p.proxy_type.clone(),
            // 带宽上限：官方 frpc 会原样上报，平台拿它做限流校验
            bandwidth_limit: p.bandwidth_limit.clone(),
            bandwidth_limit_mode,
            // ★ 这里放的是**代理级** `[proxies.metadatas]`，不是顶层 `[metadatas]`。
            //   官方 frpc 的 `MarshalToMsg` 写的是 `m.Metas = c.Metadatas`，
            //   顶层那份只进登录消息（`Login.Metas`）。
            metas: p.metas.clone(),
            ..Default::default()
        };

        match p.proxy_type.as_str() {
            "http" | "https" => {
                m.custom_domains = p.custom_domains.clone();
                m.subdomain = p.subdomain.clone();
                m.locations = p.locations.clone();
                m.http_user = p.http_user.clone();
                m.http_pwd = p.http_pwd.clone();
                m.host_header_rewrite = p.host_header_rewrite.clone();
                m.group = p.group.clone();
                m.group_key = p.group_key.clone();
            }
            // stcp / xtcp / sudp：不带 remote_port，靠共享密钥 + visitor 接入
            // （sudp 与 stcp 同一套鉴权，只是数据面是 UDP）
            "stcp" | "xtcp" | "sudp" => {
                m.sk = p.secret_key.clone();
                m.allow_users = p.allow_users.clone();
            }
            // tcp / udp：remote_port + 负载均衡分组
            _ => {
                m.remote_port = p.remote_port;
                m.group = p.group.clone();
                m.group_key = p.group_key.clone();
            }
        }

        m
    }
}

impl ServerCmd {
    /// 把 `proxy` 字段反序列化成配置类型。
    ///
    /// 放在这里而不是客户端里，是为了让「命令里的 JSON → 代理配置」只有一份实现：
    /// 配置结构体将来改字段名时不用两处改。失败只返回人话错误串 ——
    /// 这条路径的错误是要原样显示到面板上的。
    pub fn proxy_config<T: serde::de::DeserializeOwned>(&self) -> Result<T, String> {
        let v = self
            .proxy
            .clone()
            .ok_or_else(|| "add_proxy 缺少 proxy 配置".to_string())?;
        serde_json::from_value(v).map_err(|e| format!("解析代理配置失败：{e}"))
    }
}

/// 客户端 → 服务端：命令执行结果。
///
/// 面板是同步等这个回包的（超时就当成"已下发但结果未知"），
/// 所以客户端**必须**对每条 `ServerCmd` 回一条，哪怕失败了。
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ServerCmdResp {
    /// 对应 [`ServerCmd::id`]。
    #[serde(default, skip_serializing_if = "is_empty_str")]
    pub id: String,
    #[serde(default, skip_serializing_if = "is_empty_str")]
    pub op: String,
    #[serde(default, skip_serializing_if = "is_empty_str")]
    pub proxy_name: String,
    /// 空串表示成功。
    #[serde(default, skip_serializing_if = "is_empty_str")]
    pub error: String,
}

// ---------------------------------------------------------------------------
// UDP 数据包（UDP 代理专用：走**专用工作连接**，一端一个）
// ---------------------------------------------------------------------------

/// Go `net.UDPAddr` 的 JSON 形态。
///
/// Go 结构体没有 json tag，所以字段名就是 `IP` / `Port` / `Zone`，
/// 且**不带 omitempty**，正常序列化时三个字段都会出现。
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct UdpAddr {
    #[serde(rename = "IP", default)]
    pub ip: String,
    #[serde(rename = "Port", default)]
    pub port: u16,
    #[serde(rename = "Zone", default)]
    pub zone: String,
}

impl UdpAddr {
    pub fn from_socket(addr: &std::net::SocketAddr) -> Self {
        match addr {
            std::net::SocketAddr::V4(v4) => Self {
                ip: v4.ip().to_string(),
                port: v4.port(),
                zone: String::new(),
            },
            std::net::SocketAddr::V6(v6) => Self {
                ip: v6.ip().to_string(),
                port: v6.port(),
                zone: v6.scope_id().to_string(),
            },
        }
    }

    pub fn to_socket(&self) -> Option<std::net::SocketAddr> {
        let ip: std::net::IpAddr = self.ip.parse().ok()?;
        Some(std::net::SocketAddr::new(ip, self.port))
    }

    /// 用作会话 map 的 key（与 frp 的 `UDPAddr.String()` 语义一致）。
    pub fn key(&self) -> String {
        format!("{}:{}", self.ip, self.port)
    }
}

impl std::fmt::Display for UdpAddr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.zone.is_empty() {
            write!(f, "{}:{}", self.ip, self.port)
        } else {
            write!(f, "{}%{}:{}", self.ip, self.zone, self.port)
        }
    }
}

/// frp `msg.UDPPacket`：`Content []byte` + 两个地址。
///
/// Go 侧 `[]byte` 在 JSON 里是 **base64**，这里用自定义 serde 复刻。
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct UdpPacket {
    /// 负载（JSON 里是 base64 字符串）。
    #[serde(
        rename = "c",
        default,
        with = "b64_opt",
        skip_serializing_if = "Option::is_none"
    )]
    pub content: Option<Vec<u8>>,
    /// 本地地址（frp 服务端发往客户端时为 None）。
    #[serde(rename = "l", default, skip_serializing_if = "Option::is_none")]
    pub local_addr: Option<UdpAddr>,
    /// 访客地址：服务端 → 客户端方向用于标识"这条报文属于哪个访客"，
    /// 客户端 → 服务端方向用于告诉服务端把响应写回谁。
    #[serde(rename = "r", default, skip_serializing_if = "Option::is_none")]
    pub remote_addr: Option<UdpAddr>,
}

impl UdpPacket {
    pub fn new(payload: &[u8], remote: &std::net::SocketAddr) -> Self {
        Self {
            content: Some(payload.to_vec()),
            local_addr: None,
            remote_addr: Some(UdpAddr::from_socket(remote)),
        }
    }

    pub fn payload(&self) -> &[u8] {
        self.content.as_deref().unwrap_or(&[])
    }
}

// ---------------------------------------------------------------------------
// UDP 报文的二进制编码（v2 协商 codec = binary）
// ---------------------------------------------------------------------------
//
// 帧负载 = `type(2, 固定 19)` + body，body 布局：
//
// ```text
// flags(1)   bit0=带本地地址 bit1=带远端地址（远端必须带）
// [local addr]
// remote addr
// payload 长度(2, 大端)
// payload
//
// addr = family(1: 4 或 6) + ip(4/16) + port(2, 大端) + zoneLen(1) + zone
// ```
//
// 相比 JSON 版省掉了 base64 与 JSON 开销，是官方 frp 当前版本的默认选择。

const UDP_BINARY_FLAG_LOCAL: u8 = 1 << 0;
const UDP_BINARY_FLAG_REMOTE: u8 = 1 << 1;
/// 单个 UDP 载荷上限（Go `MaxUDPPayloadSize`）。
pub const MAX_UDP_PAYLOAD_SIZE: usize = 65507;

/// 编码二进制 UDP 报文体（不含 type 前缀）。
pub fn encode_udp_binary(pkt: &UdpPacket) -> Result<Vec<u8>, crate::error::Error> {
    use crate::error::Error;
    let remote = pkt
        .remote_addr
        .as_ref()
        .ok_or_else(|| Error::Protocol("UDP 报文缺少远端地址".into()))?;
    if pkt.payload().len() > MAX_UDP_PAYLOAD_SIZE {
        return Err(Error::Protocol(format!(
            "UDP 载荷 {} 字节超过上限 {}",
            pkt.payload().len(),
            MAX_UDP_PAYLOAD_SIZE
        )));
    }

    let mut flags = UDP_BINARY_FLAG_REMOTE;
    if pkt.local_addr.is_some() {
        flags |= UDP_BINARY_FLAG_LOCAL;
    }

    let mut body = Vec::with_capacity(8 + pkt.payload().len());
    body.push(flags);
    if let Some(local) = &pkt.local_addr {
        put_udp_addr(&mut body, local)?;
    }
    put_udp_addr(&mut body, remote)?;
    body.extend_from_slice(&(pkt.payload().len() as u16).to_be_bytes());
    body.extend_from_slice(pkt.payload());
    Ok(body)
}

/// 解码二进制 UDP 报文体（不含 type 前缀）。
pub fn decode_udp_binary(body: &[u8]) -> Result<UdpPacket, crate::error::Error> {
    use crate::error::Error;
    if body.len() < 3 {
        return Err(Error::Protocol(format!("UDP 报文体过短：{}", body.len())));
    }
    let flags = body[0];
    if flags & !(UDP_BINARY_FLAG_LOCAL | UDP_BINARY_FLAG_REMOTE) != 0 {
        return Err(Error::Protocol(format!(
            "UDP 保留标志位被置位：0x{flags:02x}"
        )));
    }
    if flags & UDP_BINARY_FLAG_REMOTE == 0 {
        return Err(Error::Protocol("UDP 报文缺少远端地址".into()));
    }

    let mut i = 1;
    let mut pkt = UdpPacket::default();
    if flags & UDP_BINARY_FLAG_LOCAL != 0 {
        pkt.local_addr = Some(take_udp_addr(body, &mut i)?);
    }
    pkt.remote_addr = Some(take_udp_addr(body, &mut i)?);
    if body.len() - i < 2 {
        return Err(Error::Protocol("UDP 载荷长度被截断".into()));
    }
    let len = u16::from_be_bytes([body[i], body[i + 1]]) as usize;
    i += 2;
    if len > MAX_UDP_PAYLOAD_SIZE {
        return Err(Error::Protocol(format!("UDP 载荷长度非法：{len}")));
    }
    if body.len() - i != len {
        return Err(Error::Protocol(format!(
            "UDP 载荷长度不符：声明 {len}，实际 {}",
            body.len() - i
        )));
    }
    pkt.content = Some(body[i..].to_vec());
    Ok(pkt)
}

fn put_udp_addr(out: &mut Vec<u8>, addr: &UdpAddr) -> Result<(), crate::error::Error> {
    use crate::error::Error;
    let ip: std::net::IpAddr = addr
        .ip
        .parse()
        .map_err(|_| Error::Protocol(format!("非法 IP：{}", addr.ip)))?;
    match ip {
        std::net::IpAddr::V4(v4) => {
            if !addr.zone.is_empty() {
                return Err(Error::Protocol("IPv4 不允许带 zone".into()));
            }
            out.push(4);
            out.extend_from_slice(&v4.octets());
        }
        std::net::IpAddr::V6(v6) => {
            if addr.zone.len() > 255 {
                return Err(Error::Protocol("IPv6 zone 过长".into()));
            }
            out.push(6);
            out.extend_from_slice(&v6.octets());
        }
    }
    out.extend_from_slice(&addr.port.to_be_bytes());
    out.push(addr.zone.len() as u8);
    out.extend_from_slice(addr.zone.as_bytes());
    Ok(())
}

fn take_udp_addr(body: &[u8], i: &mut usize) -> Result<UdpAddr, crate::error::Error> {
    use crate::error::Error;
    if *i >= body.len() {
        return Err(Error::Protocol("地址族被截断".into()));
    }
    let family = body[*i];
    *i += 1;
    let ip_len = match family {
        4 => 4usize,
        6 => 16usize,
        other => return Err(Error::Protocol(format!("未知地址族：{other}"))),
    };
    if body.len() - *i < ip_len + 3 {
        return Err(Error::Protocol("地址被截断".into()));
    }
    let ip_bytes = &body[*i..*i + ip_len];
    *i += ip_len;
    let port = u16::from_be_bytes([body[*i], body[*i + 1]]);
    *i += 2;
    let zone_len = body[*i] as usize;
    *i += 1;
    if body.len() - *i < zone_len {
        return Err(Error::Protocol("zone 被截断".into()));
    }
    let zone = String::from_utf8_lossy(&body[*i..*i + zone_len]).to_string();
    *i += zone_len;
    let ip = if family == 4 {
        std::net::IpAddr::V4(std::net::Ipv4Addr::new(
            ip_bytes[0],
            ip_bytes[1],
            ip_bytes[2],
            ip_bytes[3],
        ))
    } else {
        let mut octets = [0u8; 16];
        octets.copy_from_slice(ip_bytes);
        std::net::IpAddr::V6(std::net::Ipv6Addr::from(octets))
    };
    Ok(UdpAddr {
        ip: ip.to_string(),
        port,
        zone,
    })
}

/// Go `[]byte` JSON base64（标准字母表 + 填充）。
mod b64_opt {
    use base64::{engine::general_purpose::STANDARD, Engine as _};
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(v: &Option<Vec<u8>>, s: S) -> Result<S::Ok, S::Error> {
        match v {
            Some(bytes) => s.serialize_str(&STANDARD.encode(bytes)),
            None => s.serialize_none(),
        }
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Option<Vec<u8>>, D::Error> {
        match Option::<String>::deserialize(d)? {
            Some(text) => STANDARD
                .decode(text.as_bytes())
                .map(Some)
                .map_err(serde::de::Error::custom),
            None => Ok(None),
        }
    }
}

// ---------------------------------------------------------------------------
// 枚举封装
// ---------------------------------------------------------------------------

/// 一条 frp 消息。
///
/// `NewProxy` 明显大于其他变体（HTTP 相关字段多），不过消息一经解出就会立刻
/// 被消费掉，不值得为省这点栈空间在热路径上加一层 `Box`。
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone)]
pub enum FrpMessage {
    Login(Login),
    LoginResp(LoginResp),
    NewProxy(NewProxy),
    NewProxyResp(NewProxyResp),
    CloseProxy(CloseProxy),
    NewWorkConn(NewWorkConn),
    ReqWorkConn,
    StartWorkConn(StartWorkConn),
    NewVisitorConn(NewVisitorConn),
    NewVisitorConnResp(NewVisitorConnResp),
    Ping(Ping),
    Pong(Pong),
    UdpPacket(UdpPacket),
    NatHoleVisitor(NatHoleVisitor),
    NatHoleClient(NatHoleClient),
    NatHoleResp(NatHoleResp),
    NatHoleSid(NatHoleSid),
    NatHoleReport(NatHoleReport),
    ServerCmd(ServerCmd),
    ServerCmdResp(ServerCmdResp),
}

impl FrpMessage {
    /// 对应的 v2 type_id。
    pub fn type_id(&self) -> u16 {
        match self {
            Self::Login(_) => TYPE_LOGIN,
            Self::LoginResp(_) => TYPE_LOGIN_RESP,
            Self::NewProxy(_) => TYPE_NEW_PROXY,
            Self::NewProxyResp(_) => TYPE_NEW_PROXY_RESP,
            Self::CloseProxy(_) => TYPE_CLOSE_PROXY,
            Self::NewWorkConn(_) => TYPE_NEW_WORK_CONN,
            Self::ReqWorkConn => TYPE_REQ_WORK_CONN,
            Self::StartWorkConn(_) => TYPE_START_WORK_CONN,
            Self::NewVisitorConn(_) => TYPE_NEW_VISITOR_CONN,
            Self::NewVisitorConnResp(_) => TYPE_NEW_VISITOR_CONN_RESP,
            Self::Ping(_) => TYPE_PING,
            Self::Pong(_) => TYPE_PONG,
            Self::UdpPacket(_) => TYPE_UDP_PACKET,
            Self::NatHoleVisitor(_) => TYPE_NAT_HOLE_VISITOR,
            Self::NatHoleClient(_) => TYPE_NAT_HOLE_CLIENT,
            Self::NatHoleResp(_) => TYPE_NAT_HOLE_RESP,
            Self::NatHoleSid(_) => TYPE_NAT_HOLE_SID,
            Self::NatHoleReport(_) => TYPE_NAT_HOLE_REPORT,
            Self::ServerCmd(_) => TYPE_SERVER_CMD,
            Self::ServerCmdResp(_) => TYPE_SERVER_CMD_RESP,
        }
    }

    /// 编码**消息体**（纯 JSON，不含任何类型前缀）。
    ///
    /// v1 与 v2 的消息体是同一份 JSON，差别只在外层容器：
    /// * v1 外层是 `[类型字节][i64 长度]`；
    /// * v2 外层是 `[u16 类型号][JSON]` 的帧载荷。
    ///
    /// 所以两套协议共用这一个函数，谁也别自己拼 JSON。
    pub fn encode_body(&self) -> Result<Vec<u8>, crate::error::Error> {
        Ok(match self {
            Self::Login(m) => serde_json::to_vec(m)?,
            Self::LoginResp(m) => serde_json::to_vec(m)?,
            Self::NewProxy(m) => serde_json::to_vec(m)?,
            Self::NewProxyResp(m) => serde_json::to_vec(m)?,
            Self::CloseProxy(m) => serde_json::to_vec(m)?,
            Self::NewWorkConn(m) => serde_json::to_vec(m)?,
            // Go 侧 `json.Marshal(&msg.ReqWorkConn{})` 产出 `{}` 而不是空串，
            // 官方 frpc 对空 body 会报 "unexpected end of JSON input"，必须保持一致。
            Self::ReqWorkConn => br"{}".to_vec(),
            Self::StartWorkConn(m) => serde_json::to_vec(m)?,
            Self::NewVisitorConn(m) => serde_json::to_vec(m)?,
            Self::NewVisitorConnResp(m) => serde_json::to_vec(m)?,
            Self::Ping(m) => serde_json::to_vec(m)?,
            Self::Pong(m) => serde_json::to_vec(m)?,
            Self::UdpPacket(m) => serde_json::to_vec(m)?,
            Self::NatHoleVisitor(m) => serde_json::to_vec(m)?,
            Self::NatHoleClient(m) => serde_json::to_vec(m)?,
            Self::NatHoleResp(m) => serde_json::to_vec(m)?,
            Self::NatHoleSid(m) => serde_json::to_vec(m)?,
            Self::NatHoleReport(m) => serde_json::to_vec(m)?,
            Self::ServerCmd(m) => serde_json::to_vec(m)?,
            Self::ServerCmdResp(m) => serde_json::to_vec(m)?,
        })
    }

    /// 编码为 **v2** 的消息帧载荷：`2 字节 type_id + JSON`。
    pub fn encode(&self) -> Result<Vec<u8>, crate::error::Error> {
        let body = self.encode_body()?;
        let mut out = Vec::with_capacity(2 + body.len());
        out.extend_from_slice(&self.type_id().to_be_bytes());
        out.extend_from_slice(&body);
        Ok(out)
    }

    /// 从消息帧负载解码。
    pub fn decode(type_id: u16, body: &[u8]) -> Result<Self, crate::error::Error> {
        let msg = match type_id {
            TYPE_LOGIN => Self::Login(serde_json::from_slice(body)?),
            TYPE_LOGIN_RESP => Self::LoginResp(serde_json::from_slice(body)?),
            TYPE_NEW_PROXY => Self::NewProxy(serde_json::from_slice(body)?),
            TYPE_NEW_PROXY_RESP => Self::NewProxyResp(serde_json::from_slice(body)?),
            TYPE_CLOSE_PROXY => Self::CloseProxy(serde_json::from_slice(body)?),
            TYPE_NEW_WORK_CONN => Self::NewWorkConn(serde_json::from_slice(body)?),
            TYPE_REQ_WORK_CONN => Self::ReqWorkConn,
            TYPE_START_WORK_CONN => Self::StartWorkConn(serde_json::from_slice(body)?),
            TYPE_NEW_VISITOR_CONN => Self::NewVisitorConn(serde_json::from_slice(body)?),
            TYPE_NEW_VISITOR_CONN_RESP => Self::NewVisitorConnResp(serde_json::from_slice(body)?),
            TYPE_PING => Self::Ping(serde_json::from_slice(body)?),
            TYPE_PONG => Self::Pong(serde_json::from_slice(body)?),
            TYPE_UDP_PACKET => Self::UdpPacket(serde_json::from_slice(body)?),
            TYPE_NAT_HOLE_VISITOR => Self::NatHoleVisitor(serde_json::from_slice(body)?),
            TYPE_NAT_HOLE_CLIENT => Self::NatHoleClient(serde_json::from_slice(body)?),
            TYPE_NAT_HOLE_RESP => Self::NatHoleResp(serde_json::from_slice(body)?),
            TYPE_NAT_HOLE_SID => Self::NatHoleSid(serde_json::from_slice(body)?),
            TYPE_NAT_HOLE_REPORT => Self::NatHoleReport(serde_json::from_slice(body)?),
            TYPE_SERVER_CMD => Self::ServerCmd(serde_json::from_slice(body)?),
            TYPE_SERVER_CMD_RESP => Self::ServerCmdResp(serde_json::from_slice(body)?),
            other => {
                return Err(crate::error::Error::Protocol(format!(
                    "未知的 frp 消息 type_id: {other}"
                )))
            }
        };
        Ok(msg)
    }

    /// 人类可读的名字，用于日志。
    pub fn name(&self) -> &'static str {
        match self {
            Self::Login(_) => "Login",
            Self::LoginResp(_) => "LoginResp",
            Self::NewProxy(_) => "NewProxy",
            Self::NewProxyResp(_) => "NewProxyResp",
            Self::CloseProxy(_) => "CloseProxy",
            Self::NewWorkConn(_) => "NewWorkConn",
            Self::ReqWorkConn => "ReqWorkConn",
            Self::StartWorkConn(_) => "StartWorkConn",
            Self::NewVisitorConn(_) => "NewVisitorConn",
            Self::NewVisitorConnResp(_) => "NewVisitorConnResp",
            Self::Ping(_) => "Ping",
            Self::Pong(_) => "Pong",
            Self::UdpPacket(_) => "UdpPacket",
            Self::NatHoleVisitor(_) => "NatHoleVisitor",
            Self::NatHoleClient(_) => "NatHoleClient",
            Self::NatHoleResp(_) => "NatHoleResp",
            Self::NatHoleSid(_) => "NatHoleSid",
            Self::NatHoleReport(_) => "NatHoleReport",
            Self::ServerCmd(_) => "ServerCmd",
            Self::ServerCmdResp(_) => "ServerCmdResp",
        }
    }
}

// ---------------------------------------------------------------------------
// token 鉴权：hex(md5(token + timestamp))
// ---------------------------------------------------------------------------

/// 计算 frp token 鉴权 key，等价于 Go `util.GetAuthKey`。
pub fn auth_key(token: &str, timestamp: i64) -> String {
    use md5::{Digest, Md5};
    let mut h = Md5::new();
    h.update(token.as_bytes());
    h.update(timestamp.to_string().as_bytes());
    let digest = h.finalize();
    let mut s = String::with_capacity(digest.len() * 2);
    for b in digest {
        use std::fmt::Write;
        let _ = write!(s, "{b:02x}");
    }
    s
}

/// 常量时间字符串比较。
pub fn constant_time_eq(a: &str, b: &str) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut acc = 0u8;
    for (x, y) in a.bytes().zip(b.bytes()) {
        acc |= x ^ y;
    }
    acc == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn auth_key_matches_go() {
        // Go: util.GetAuthKey("your_secret_token", 1700000000)
        //   = hex(md5("your_secret_token" + "1700000000"))
        assert_eq!(
            auth_key("your_secret_token", 1_700_000_000),
            "196ac62ac046b172fdd69d748a3583d0"
        );
    }

    #[test]
    fn udp_binary_roundtrip() {
        let pkt = UdpPacket {
            content: Some(b"hello-udp".to_vec()),
            local_addr: None,
            remote_addr: Some(UdpAddr {
                ip: "1.2.3.4".into(),
                port: 5353,
                zone: String::new(),
            }),
        };
        let body = encode_udp_binary(&pkt).unwrap();
        assert_eq!(body[0], 0b10, "只应有远端地址标志位");
        assert_eq!(decode_udp_binary(&body).unwrap(), pkt);
    }

    #[test]
    fn udp_binary_ipv6_with_local() {
        let pkt = UdpPacket {
            content: Some(vec![0xde, 0xad]),
            local_addr: Some(UdpAddr {
                ip: "::1".into(),
                port: 1,
                zone: String::new(),
            }),
            remote_addr: Some(UdpAddr {
                ip: "2001:db8::1".into(),
                port: 65535,
                zone: "eth0".into(),
            }),
        };
        let body = encode_udp_binary(&pkt).unwrap();
        assert_eq!(decode_udp_binary(&body).unwrap(), pkt);
    }

    #[test]
    fn udp_json_shape_matches_go() {
        let pkt = UdpPacket {
            content: Some(b"hi".to_vec()),
            local_addr: None,
            remote_addr: Some(UdpAddr {
                ip: "1.2.3.4".into(),
                port: 53,
                zone: String::new(),
            }),
        };
        let json = serde_json::to_string(&pkt).unwrap();
        assert!(
            json.contains("\"c\":\"aGk=\""),
            "content 应是 base64：{json}"
        );
        assert!(json.contains("\"IP\":\"1.2.3.4\""), "地址字段名：{json}");
        assert!(json.contains("\"Port\":53"), "端口字段名：{json}");
        let back: UdpPacket = serde_json::from_str(&json).unwrap();
        assert_eq!(back, pkt);
    }

    #[test]
    fn message_roundtrip() {
        let m = FrpMessage::NewProxy(NewProxy {
            proxy_name: "ssh".into(),
            proxy_type: "tcp".into(),
            remote_port: 6000,
            ..Default::default()
        });
        let bytes = m.encode().unwrap();
        assert_eq!(&bytes[..2], &TYPE_NEW_PROXY.to_be_bytes());
        let json = String::from_utf8(bytes[2..].to_vec()).unwrap();
        assert!(json.contains("\"proxy_name\":\"ssh\""));
        assert!(!json.contains("use_encryption"), "omitempty 应省略 false");
    }

    /// stcp 代理注册：`sk` / `allow_users` 的 JSON 字段名必须与 Go 一致。
    #[test]
    fn stcp_newproxy_shape_matches_go() {
        let m = FrpMessage::NewProxy(NewProxy {
            proxy_name: "secret-ssh".into(),
            proxy_type: "stcp".into(),
            sk: "abc123".into(),
            ..Default::default()
        });
        let bytes = m.encode().unwrap();
        let json = String::from_utf8(bytes[2..].to_vec()).unwrap();
        assert!(json.contains("\"sk\":\"abc123\""), "sk 字段名：{json}");
        assert!(!json.contains("allow_users"), "omitempty 应省略空数组");
        assert!(!json.contains("remote_port"), "stcp 没有公网端口");
    }

    /// visitor 连接请求的字段名与 type_id。
    #[test]
    fn new_visitor_conn_shape_matches_go() {
        let m = FrpMessage::NewVisitorConn(NewVisitorConn {
            run_id: "run-1".into(),
            proxy_name: "secret-ssh".into(),
            sign_key: auth_key("abc123", 1_700_000_000),
            timestamp: 1_700_000_000,
            ..Default::default()
        });
        let bytes = m.encode().unwrap();
        assert_eq!(&bytes[..2], &9u16.to_be_bytes(), "v2 里 NewVisitorConn = 9");
        let json = String::from_utf8(bytes[2..].to_vec()).unwrap();
        assert!(json.contains("\"sign_key\""), "字段名：{json}");
        assert!(json.contains("\"run_id\":\"run-1\""), "字段名：{json}");
        // 官方 frpc 用 hex(md5(sk + ts)) 做签名，这里对死一个外部算出来的值
        assert_eq!(
            auth_key("abc123", 1_700_000_000),
            "c7f13d9712607facf2852c93b90a15b5"
        );
    }

    /// nat hole 消息的编号：官方 v2 里是 14~18，UDP 二进制是 19。
    #[test]
    fn nat_hole_type_ids_match_go() {
        assert_eq!(
            FrpMessage::NatHoleVisitor(NatHoleVisitor::default()).type_id(),
            14
        );
        assert_eq!(
            FrpMessage::NatHoleClient(NatHoleClient::default()).type_id(),
            15
        );
        assert_eq!(
            FrpMessage::NatHoleResp(NatHoleResp::default()).type_id(),
            16
        );
        assert_eq!(FrpMessage::NatHoleSid(NatHoleSid::default()).type_id(), 17);
        assert_eq!(
            FrpMessage::NatHoleReport(NatHoleReport::default()).type_id(),
            18
        );
        assert_eq!(TYPE_UDP_PACKET_BINARY, 19);
    }

    /// 服务端回给 visitor 的错误响应能被解出来。
    #[test]
    fn visitor_conn_resp_roundtrip() {
        let m = FrpMessage::NewVisitorConnResp(NewVisitorConnResp {
            proxy_name: "secret-ssh".into(),
            error: "proxy not found".into(),
        });
        let bytes = m.encode().unwrap();
        assert_eq!(&bytes[..2], &10u16.to_be_bytes());
        match FrpMessage::decode(10, &bytes[2..]).unwrap() {
            FrpMessage::NewVisitorConnResp(r) => {
                assert_eq!(r.proxy_name, "secret-ssh");
                assert_eq!(r.error, "proxy not found");
            }
            other => panic!("解出的类型不对：{other:?}"),
        }
    }

    /// nat hole 消息整体 roundtrip（含 detect_behavior 嵌套结构）。
    #[test]
    fn nat_hole_resp_roundtrip() {
        let m = FrpMessage::NatHoleResp(NatHoleResp {
            transaction_id: "tx-1".into(),
            sid: "sid-1".into(),
            protocol: "quic".into(),
            candidate_addrs: vec!["1.2.3.4:5000".into()],
            assisted_addrs: vec![],
            detect_behavior: NatHoleDetectBehavior {
                role: "sender".into(),
                mode: 1,
                ttl: 5,
                send_delay_ms: 20,
                read_timeout_ms: 500,
                candidate_ports: vec![PortsRange {
                    from: 5000,
                    to: 5010,
                }],
                send_random_ports: 0,
                listen_random_ports: 0,
            },
            error: String::new(),
        });
        let bytes = m.encode().unwrap();
        let back = FrpMessage::decode(16, &bytes[2..]).unwrap();
        match back {
            FrpMessage::NatHoleResp(r) => {
                assert_eq!(r.sid, "sid-1");
                assert_eq!(r.detect_behavior.role, "sender");
                assert_eq!(r.detect_behavior.candidate_ports[0].from, 5000);
                assert_eq!(r.detect_behavior.candidate_ports[0].to, 5010);
            }
            other => panic!("解出的类型不对：{other:?}"),
        }
    }
}
