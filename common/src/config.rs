//! TOML 配置结构与示例模板。
//!
//! 所有路径相关参数统一使用 [`std::path::PathBuf`]，不在代码中硬编码路径分隔符。

use std::collections::BTreeMap;
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
///   需要服务端也显式启用（官方 frps 会按魔术字自动识别，nfrp-server 同理）。
/// * `nfrp` —— NFrp 自研的简化协议，尚未实现（配置成它会被直接拒绝）。
///
/// 想写哪种都行：`"v1"` / `"v2"` / `"frp-v1"` / `"frp-v2"` 都认，
/// 也可以直接照抄 frp 配置里的 `[transport] wireProtocol = "v2"`。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Protocol {
    #[default]
    FrpV1,
    FrpV2,
    Nfrp,
}

impl Protocol {
    pub fn as_str(&self) -> &'static str {
        match self {
            Protocol::FrpV1 => "frp-v1",
            Protocol::FrpV2 => "frp-v2",
            Protocol::Nfrp => "nfrp",
        }
    }

    /// 对应的 frp 线协议版本；`nfrp` 自研协议没有对应版本。
    pub fn wire_version(&self) -> Option<crate::frp::WireVersion> {
        match self {
            Protocol::FrpV1 => Some(crate::frp::WireVersion::V1),
            Protocol::FrpV2 => Some(crate::frp::WireVersion::V2),
            Protocol::Nfrp => None,
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
            "nfrp" | "native" => Ok(Protocol::Nfrp),
            other => Err(format!(
                "未知协议 {other}，可选：frp-v1（默认）/ frp-v2 / nfrp"
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
/// 官方 `LogConfig.Complete()`：`MaxDays = util.EmptyOr(c.MaxDays, 3)`。
pub const DEFAULT_LOG_MAX_DAYS: i64 = 3;
/// 官方 `ServerConfig.Complete()`：`VhostHTTPTimeout = util.EmptyOr(…, 60)`。
pub const DEFAULT_VHOST_HTTP_TIMEOUT: u64 = 60;

// ---------------------------------------------------------------------------
// allowPorts：允许客户端申请的远端端口白名单
// ---------------------------------------------------------------------------

/// `allowPorts` 里的一条端口区间，对应官方 `pkg/config/types.PortsRange`。
///
/// 官方把它设计成"单端口 / 区间"两个可选字段：
///
/// ```toml
/// allowPorts = [
///   { start = 2000, end = 3000 },
///   { single = 3001 },
///   { start = 4000, end = 5000 },
/// ]
/// ```
///
/// 内部统一成闭区间 `[start, end]`（单端口就是 `start == end`），
/// 判断"端口是否被允许"只需一次比较。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PortRange {
    pub start: u16,
    pub end: u16,
}

impl PortRange {
    /// 单个端口。
    pub fn single(port: u16) -> Self {
        Self {
            start: port,
            end: port,
        }
    }

    /// 闭区间；`end < start` 时自动交换，调用方不用先排好序。
    pub fn new(a: u16, b: u16) -> Self {
        if a <= b {
            Self { start: a, end: b }
        } else {
            Self { start: b, end: a }
        }
    }

    pub fn contains(&self, port: u16) -> bool {
        self.start <= port && port <= self.end
    }
}

impl std::fmt::Display for PortRange {
    /// 与官方 `PortsRangeSlice.String()` 一致：单端口写 `3000`，区间写 `1000-2000`。
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.start == self.end {
            write!(f, "{}", self.start)
        } else {
            write!(f, "{}-{}", self.start, self.end)
        }
    }
}

/// 反序列化 `allowPorts`：每一项可以是官方那种表，也可以直接写字符串。
///
/// 官方 TOML 只认表（`{ start = …, end = … }`），字符串写法只在 legacy INI /
/// 命令行 `--allow_ports` 里出现。这里两种都收 —— 用户把
/// `allow_ports = 1000-2000,3000` 从 frps.ini 抄到 frps.toml 时不会撞墙。
///
/// ★ 每一项用 [`PortSpec`]（自己实现 `deserialize_any`）而**不是**
///   `#[serde(untagged)]`：untagged 会把内层错误整个吞掉，只留下一句
///   "data did not match any variant"，于是"区间反了"这种能一句话说清的
///   配置错误，用户要查半天。自实现 visitor 后错误信息可以原样透出。
fn de_port_ranges<'de, D>(d: D) -> std::result::Result<Vec<PortRange>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let specs: Vec<PortSpec> = Vec::deserialize(d)?;
    Ok(specs.into_iter().flat_map(|s| s.0).collect())
}

/// `allowPorts` 数组里的一项：表 **或** 字符串。
///
/// 字符串可以带逗号（`"1000-2000,3000"`），所以一项可能展开成多条区间 ——
/// 这也是它不叫 `PortRange` 的原因。
struct PortSpec(Vec<PortRange>);

impl<'de> Deserialize<'de> for PortSpec {
    fn deserialize<D>(d: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct V;
        impl<'de> serde::de::Visitor<'de> for V {
            type Value = PortSpec;

            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str(
                    "allowPorts 的每一项：{ start = …, end = … } / { single = … }，\
                     或 \"1000-2000,3000\" 这样的字符串",
                )
            }

            fn visit_str<E: serde::de::Error>(self, s: &str) -> std::result::Result<PortSpec, E> {
                parse_port_ranges(s).map(PortSpec).map_err(E::custom)
            }

            fn visit_map<A>(self, mut map: A) -> std::result::Result<PortSpec, A::Error>
            where
                A: serde::de::MapAccess<'de>,
            {
                use serde::de::Error as _;
                let (mut start, mut end, mut single) = (None, None, None);
                while let Some(key) = map.next_key::<String>()? {
                    match key.as_str() {
                        "start" => start = Some(map.next_value::<u16>()?),
                        "end" => end = Some(map.next_value::<u16>()?),
                        "single" => single = Some(map.next_value::<u16>()?),
                        // 官方走 Go 的 encoding/json，未知键是**忽略**的，这里照做
                        // （但必须把值消费掉，否则 map 走不下去）。
                        _ => {
                            let _ = map.next_value::<serde::de::IgnoredAny>()?;
                        }
                    }
                }
                match (single, start, end) {
                    (Some(s), None, None) => Ok(PortSpec(vec![PortRange::single(s)])),
                    // `{ start = 1000 }`（官方没这么写，但语义无歧义）
                    (None, Some(a), None) => Ok(PortSpec(vec![PortRange::single(a)])),
                    (None, Some(a), Some(b)) => {
                        if b < a {
                            Err(A::Error::custom(format!(
                                "allowPorts 区间反了：start={a} end={b}"
                            )))
                        } else {
                            Ok(PortSpec(vec![PortRange::new(a, b)]))
                        }
                    }
                    _ => Err(A::Error::custom(
                        "allowPorts 每一项要么是 { start = …, end = … }，要么是 { single = … }",
                    )),
                }
            }
        }
        d.deserialize_any(V)
    }
}

/// 解析 `"1000-2000,3000,4000-5000"` 这种逗号分隔的端口列表。
///
/// 逐条对齐官方 `types.NewPortsRangeSliceFromString`：按 `,` 切、每项按 `-` 切，
/// 切成 1 段当单端口、2 段当区间、其它段数报错；区间反过来（`2000-1000`）也报错。
pub fn parse_port_ranges(s: &str) -> std::result::Result<Vec<PortRange>, String> {
    let mut out = Vec::new();
    let trimmed = s.trim();
    if trimmed.is_empty() {
        return Ok(out);
    }
    for item in trimmed.split(',') {
        let item = item.trim();
        let parts: Vec<&str> = item.split('-').collect();
        let num = |t: &str| -> std::result::Result<u16, String> {
            t.trim()
                .parse::<u16>()
                .map_err(|_| format!("allowPorts 里的数字非法：{t:?}"))
        };
        match parts.len() {
            1 => out.push(PortRange::single(num(parts[0])?)),
            2 => {
                let a = num(parts[0])?;
                let b = num(parts[1])?;
                if b < a {
                    return Err(format!("allowPorts 区间反了：{item}"));
                }
                out.push(PortRange::new(a, b));
            }
            _ => return Err(format!("allowPorts 的分段数非法：{item}")),
        }
    }
    Ok(out)
}

/// 反向格式化（官方 `PortsRangeSlice.String()`），给面板 / API 展示用。
pub fn format_port_ranges(rs: &[PortRange]) -> String {
    rs.iter()
        .map(|r| r.to_string())
        .collect::<Vec<_>>()
        .join(",")
}

impl Serialize for PortRange {
    fn serialize<S: serde::Serializer>(&self, s: S) -> std::result::Result<S::Ok, S::Error> {
        use serde::ser::SerializeStruct as _;
        if self.start == self.end {
            // 官方单端口的写法是 `{ single = 3000 }`
            let mut st = s.serialize_struct("PortsRange", 1)?;
            st.serialize_field("single", &self.start)?;
            st.end()
        } else {
            let mut st = s.serialize_struct("PortsRange", 2)?;
            st.serialize_field("start", &self.start)?;
            st.serialize_field("end", &self.end)?;
            st.end()
        }
    }
}

/// 端口是否落在白名单里。
///
/// `allow_ports` 为空 = **不限制**（与官方 `ports.Manager` 在
/// `len(allowPorts) == 0` 时把 1..65535 全放进 freePorts 一致）。
pub fn port_allowed(allow: &[PortRange], port: u16) -> bool {
    allow.is_empty() || allow.iter().any(|r| r.contains(port))
}

// ---------------------------------------------------------------------------
// 服务端配置
// ---------------------------------------------------------------------------

/// 服务端配置，对应 `server.toml`。
///
/// ★ v0.5.3：手工实现 `Debug`（见文件下方），`token` 与 `dashboard_pwd`
/// 一律脱敏，避免任何调试打印把密钥写进日志。
#[derive(Clone, Serialize, Deserialize)]
pub struct ServerConfig {
    /// 监听地址，`0.0.0.0` 表示所有网卡。
    #[serde(default = "default_bind_addr")]
    pub bind_addr: String,

    /// ★ 用户是否**显式写过** `bind_addr`（v0.5.4，配合 M4 的判定）。
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
    /// 面板用户名（留空表示**不做鉴权**）。
    ///
    /// ★ 留空只在 `bind_addr` 是回环时被接受（本机自用）。配了
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
    /// 明确同意"**服务端不做认证**且对外监听"（v0.5.4 新增，修 M4）。
    ///
    /// 背景：`token` 留空时认证被完全跳过（与官方 frps 一致，靠网络隔离兜底）。
    /// 但"留空 + 绑 0.0.0.0"等于对外开放一个**任何人都能用**的 frps ——
    /// 谁都能注册代理、申请公网端口，把服务器变成公共内网穿透节点。
    ///
    /// 原先这种组合只打一条 `warn!` 就放行，而**同一个风险在面板路径上
    /// 是硬性 `ensure!` 拒绝启动的** —— 两种标准。现在统一：
    /// 默认 `false` ⇒ 拒绝启动；确实需要（比如纯内网lab）显式置 `true`。
    ///
    /// ★ 为什么不干脆禁止：官方 frp 允许空 token，而且确实有大量内网部署
    /// 这么跑。直接砍掉会破坏兼容性；"拒绝启动 + 显式逃生开关"既堵住了
    /// 无意的误配置（把空 token 部署到公网），又保留了知情选择。
    #[serde(default)]
    pub allow_insecure_no_auth: bool,
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

    /// 解析时发现的、**官方 frps 支持但 NFrp 未实现**的字段名。
    ///
    /// 纯诊断用（`#[serde(skip)]`）：官方 frps 配置里的 `allowPorts` 这类项
    /// 会被静默忽略，启动日志据此明说。填值见
    /// [`crate::frp_config::unsupported_server_fields`]。
    #[serde(skip)]
    pub unsupported_fields: Vec<String>,
}

impl std::fmt::Debug for ServerConfig {
    /// ★ v0.5.3：`token` / `dashboard_pwd` 永不进日志。
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
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            bind_addr: default_bind_addr(),
            // 默认（没从文件读过）⇒ 视为"用户没显式写过"
            bind_addr_explicitly_set: false,
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
            tcpmux_http_connect_port: None,
            tcpmux_passthrough: false,
            vhost_http_timeout: default_vhost_http_timeout(),
            custom_404_page: String::new(),
            subdomain_host: String::new(),
            log_level: default_log_level(),
            log_to: String::new(),
            max_days: default_log_max_days(),
            transport_protocol: default_transport_protocol(),
            kcp_bind_port: None,
            max_total_conns: 0,
            max_clients: 0,
            max_conns_per_client: 0,
            max_pending_per_client: 0,
            max_proxies_per_client: 0,
            allow_ports: Vec::new(),
            max_ports_per_client: 0,
            detailed_errors_to_client: true,
            p2p_port: None,
            dashboard_port: None,
            dashboard_user: String::new(),
            dashboard_pwd: String::new(),
            allow_insecure_dashboard: false,
            allow_insecure_no_auth: false,
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
    /// 按 HTTP Basic Auth 的**用户名**路由（官方 `routeByHTTPUser`）。
    ///
    /// 作用：让多条代理共用一个域名 + 路径，只按访问者用的用户名区分。
    /// http / https / tcpmux 都用得上 —— tcpmux 那个 CONNECT 复用器尤其依赖它，
    /// 因为 CONNECT 请求没有路径，域名撞车时只剩用户名这一个区分维度。
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub route_by_http_user: String,

    // ---- tcpmux 专用 ----
    /// 多路复用器类型（官方 `multiplexer`）。官方只有 `httpconnect` 一种。
    ///
    /// `tcpmux` 代理不绑端口：若干条 tcpmux 代理共用服务端的
    /// `tcpmuxHTTPConnectPort`，靠 CONNECT 请求里的 host 分发。所以这个字段
    /// **是必填的**，留空服务端会报 `unknown multiplexer`。
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub multiplexer: String,

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
    /// 插件的**上游地址**（官方 `plugin.localAddr`）。
    ///
    /// `http2http` / `http2https` / `https2http` / `https2https` / `tls2raw` 用它，
    /// 与 [`Self::local_addr`] 的区别是：配了插件之后工作连接不再直连 `local_addr`，
    /// 由插件自己去连 `plugin_local_addr`。两者都留着是有意的 —— 用户把插件删掉时
    /// `local_addr` 还在，不用重新填一遍。
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub plugin_local_addr: String,
    /// `https2http` / `https2https` / `tls2raw`：frpc 侧**终止** TLS 用的证书链。
    ///
    /// 注意这与 https 代理相反 —— 那种是服务端只嗅探 SNI、不终止 TLS。
    /// 这三个插件是 frpc 自己当 TLS 服务端，所以证书得由用户给。
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub plugin_crt_path: String,
    /// 与 [`Self::plugin_crt_path`] 配套的私钥。
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub plugin_key_path: String,
    /// 回源时把 `Host` 改写成什么（官方 `plugin.hostHeaderRewrite`）。
    ///
    /// 留空 = 原样透传客户端发来的 `Host`（与官方一致）。
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub plugin_host_header_rewrite: String,
    /// 回源时额外设置/覆盖的请求头（官方 `requestHeaders.set`）。
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub plugin_request_headers: BTreeMap<String, String>,

    // ---- stcp / xtcp 专用 ----
    /// 共享密钥（frpc 里叫 `secretKey`）。provider 与 visitor 必须一致。
    ///
    /// `sk` 是官方 INI 配置里的写法，这里一并接受：TOML 下 serde **不拒绝未知字段**，
    /// 用户照 INI 习惯写 `sk` 会被静默忽略，`secret_key` 于是为空，
    /// 直到服务端报「必须配置 secret_key」才暴露 —— 加个别名就消掉了这个静默失败。
    #[serde(
        default,
        alias = "secretKey",
        alias = "sk",
        skip_serializing_if = "String::is_empty"
    )]
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
    ///
    /// 同 [`ProxyConfig::secret_key`]：`sk`（官方 INI 写法）一并接受，
    /// 否则它会被 serde 静默忽略，表现为"密钥永远对不上"。
    #[serde(default, alias = "secretKey", alias = "sk")]
    pub secret_key: String,
    /// 本地监听地址。
    #[serde(default = "default_bind_addr")]
    pub bind_addr: String,
    /// 本地监听端口。
    ///
    /// **`<= 0` 表示不监听本地端口**（仅用于给别的 visitor 做 fallback 目标）。
    ///
    /// ★ 这里必须是**有符号**类型。官方 frp 的文档与自带示例都用 `-1` 表达同一件事
    /// （`conf/frpc_full_example.toml` 的 `vnet-visitor` 就是 `bindPort = -1`），
    /// 官方代码的判据是 `if cfg.BindPort > 0 { listen }` —— 写成 `u16` 会让整份
    /// 官方配置在解析阶段就 `invalid value: integer -1, expected u16` 直接失败。
    #[serde(default, alias = "bindPort")]
    pub bind_port: i32,
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
///
/// ★ v0.5.3：手工实现 `Debug`（见文件下方），`token` 与各代理的
/// `secret_key` / `http_pwd` 一律脱敏。
#[derive(Clone, Serialize, Deserialize)]
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

    /// 日志落盘路径（对应 frp `log.to`）。空 / `console` = 写标准输出（默认）。
    ///
    /// 注意：**配了文件之后 stdout 就没有日志了**（与官方 frpc 一样是
    /// "控制台**或**文件"）。第三方启动器（NetTool 之类）是按行读 stdout 的，
    /// 配了它面板上会看不到日志 —— 这是官方语义，不是 bug。
    #[serde(default)]
    pub log_to: String,

    /// 日志保留天数（对应 frp `log.maxDays`，默认 3；`<= 0` = 不清理）。
    #[serde(default = "default_log_max_days")]
    pub max_days: i64,

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

    /// 是否在 `Login` 里声明 NFrp 私有能力（默认开）。
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

    /// 解析时发现的、**官方 frp 支持但 NFrp 未实现**的字段名。
    ///
    /// 纯诊断用（`#[serde(skip)]`，不参与序列化/反序列化）：官方 frp 默认
    /// `--strict-config=true`，未知字段**直接报错**；NFrp 的 serde 不拒绝未知
    /// 字段，于是用户照官方文档写的 `useEncryption = true` 会**无声失效** ——
    /// 以为加密了，实际是明文。把名字记下来，让启动日志能明确告知。
    ///
    /// 填值见 [`crate::frp_config::unsupported_fields`]。
    #[serde(skip)]
    pub unsupported_fields: Vec<String>,
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
            log_to: String::new(),
            max_days: default_log_max_days(),
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
            unsupported_fields: Vec::new(),
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
    /// 目录会自动创建。文件内容是 JSON，与 NFrp 自己的格式兼容；
    /// **官方 frp 的 store 是另一套结构**（Go 的 `configmgmt` 序列化），
    /// 两者不通用 —— 换实现时需要重新加一遍代理，这一点在 README 里写明了。
    pub path: String,
}

/// 客户端 Web 管理界面配置（`[webServer]`）。
///
/// 官方 frpc 也有同名段落，字段名保持一致（`addr` / `port` / `user` / `password`）。
#[derive(Clone, Serialize, Deserialize)]
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

    /// 明确同意"管理界面不鉴权且对外监听"。
    ///
    /// 默认 `false` ⇒ 非回环地址 + 无凭据的组合会让客户端**拒绝启动**。
    /// 那条组合下任何能访问该端口的人都能增删隧道、直接停止客户端，
    /// 而原先只打一条 warn 就放行。置 `true` 表示知情自担风险。
    #[serde(default)]
    pub allow_insecure_remote: bool,

    /// 静态资源目录（官方 frpc 的 `webServer.assetsDir`）。
    ///
    /// ★ 官方支持、nfrp **未实现**：声明它只是为了"官方配置能解析通过"——
    /// 本结构开了 `deny_unknown_fields`，不声明的话官方配置会**直接解析失败**。
    /// 值不会被使用（NFrp 用内置页面），启动时会明确告警。
    #[serde(default, alias = "assetsDir")]
    pub assets_dir: String,

    /// pprof 性能分析开关（官方 frpc 的 `webServer.pprofEnable`）。★ 同上：不生效。
    #[serde(default, alias = "pprofEnable")]
    pub pprof_enable: bool,
}

fn default_webserver_addr() -> String {
    "127.0.0.1".into()
}

impl std::fmt::Debug for WebServerConfig {
    /// ★ v0.5.3：`password` 脱敏（本地管理界面的 Basic Auth 口令）。
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let pwd = if self.password.is_empty() {
            "<empty>".to_string()
        } else {
            format!("<redacted:{} chars>", self.password.chars().count())
        };
        f.debug_struct("WebServerConfig")
            .field("addr", &self.addr)
            .field("port", &self.port)
            .field("user", &self.user)
            .field("password", &pwd)
            .field("allow_insecure_remote", &self.allow_insecure_remote)
            .field("assets_dir", &self.assets_dir)
            .finish_non_exhaustive()
    }
}

impl Default for WebServerConfig {
    fn default() -> Self {
        Self {
            addr: default_webserver_addr(),
            port: 0,
            user: String::new(),
            password: String::new(),
            allow_insecure_remote: false,
            assets_dir: String::new(),
            pprof_enable: false,
        }
    }
}

impl WebServerConfig {
    pub fn is_enabled(&self) -> bool {
        self.port != 0
    }
}

impl std::fmt::Debug for ClientConfig {
    /// ★ v0.5.3：所有凭据字段脱敏。
    ///
    /// 客户端配置里含 `token`（顶层）、`webServer.password`，
    /// 以及每条代理的 `secret_key` / `http_pwd`。原来 `#[derive(Debug)]`
    /// 会把它们原样打出来。
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        fn redact(s: &str) -> String {
            if s.is_empty() {
                "<empty>".to_string()
            } else {
                format!("<redacted:{} chars>", s.chars().count())
            }
        }
        f.debug_struct("ClientConfig")
            .field("server_addr", &self.server_addr)
            .field("server_port", &self.server_port)
            .field("token", &redact(&self.token))
            .field("proxies", &self.proxies.len())
            .field("visitors", &self.visitors.len())
            .field("web_server", &self.web_server)
            .field("log_level", &self.log_level)
            .field("login_fail_exit", &self.login_fail_exit)
            .field("auth", &self.auth)
            .finish_non_exhaustive()
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
        r##"# nfrp-client 示例配置
# 用法：nfrp-client -c client.toml
# 生成：nfrp-client --gen-config client.toml

server_addr = "1.2.3.4"
server_port = 7000
token = "your_secret_token"
user = "alice"          # stcp / xtcp 的 allow_users 比对的就是它
log_level = "info"

# ---- 日志落盘（可选）----
# 默认写标准输出；配了 to 就写文件，按天轮转、按 maxDays 清理老备份。
# ★ 配了它之后 stdout 上**就没有日志了**（与官方 frpc 一样是"控制台或文件"），
#   NetTool 这类按行读 stdout 的启动器面板上会看不到日志。
# [log]
# to = "frpc.log"
# maxDays = 3

# ---- 线协议（对应原版 frp 的 `transport.wireProtocol`，默认就是 v1）----
# v1：原版 frp 至今的默认协议，无魔术字、消息体是裸 JSON、登录后套 AES-128-CFB。
#     樱花 / 各类第三方 frps 分支基本只认它 —— 这也是 NFrp 的默认值。
# v2：v0.70 引入的新协议，魔术字 + Hello 协商 + AES-256-GCM AEAD 帧流，
#     需要服务端也支持（nfrp-server 会自动识别，无需配置）。
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
fn default_log_max_days() -> i64 {
    DEFAULT_LOG_MAX_DAYS
}
fn default_vhost_http_timeout() -> u64 {
    DEFAULT_VHOST_HTTP_TIMEOUT
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
    let mut cfg = if crate::frp_legacy::is_legacy_ini(raw) {
        let value = crate::frp_legacy::legacy_client_to_value(raw)?;
        // 扫**原文**：`legacy_client_to_value` 只搬认识的键，不认识的丢掉了。
        let unsupported = crate::frp_config::unsupported_fields_ini(raw);
        let mut cfg: ClientConfig = value.try_into()?;
        cfg.unsupported_fields = unsupported;
        cfg
    } else {
        parse_client_toml(raw)?
    };
    reject_unimplemented_types(&cfg)?;
    // 逐条把"官方有、NFrp 没实现"的字段名打到日志上（见 UNSUPPORTED_CLIENT_FIELDS）。
    // 这里只是**采集**，打日志交给调用方（库层不该直接往 stdout 写）。
    cfg.unsupported_fields.sort();
    cfg.unsupported_fields.dedup();
    Ok(cfg)
}

/// 解析服务端配置文本，自动识别 TOML / legacy INI。规则同 [`parse_client`]。
pub fn parse_server(raw: &str) -> Result<ServerConfig> {
    if crate::frp_legacy::is_legacy_ini(raw) {
        let value = crate::frp_legacy::legacy_server_to_value(raw)?;
        let mut cfg: ServerConfig = value.try_into()?;
        // INI 同样要扫**原文**（转换后的 value 里只剩认识的键）。
        cfg.unsupported_fields = crate::frp_config::unsupported_server_fields_ini(raw);
        return Ok(cfg);
    }
    parse_server_toml(raw)
}

/// NFrp 真正实现的代理 / 访客类型。
///
/// 原版 frp 还认 `tcpmux`，NFrp 没实现。**宁可在这里报错，
/// 也不能静默当成 tcp 放过去** —— 静默降级会"看起来连上了"，实际按错的语义
/// 转发用户流量，比启动阶段报一句清楚的话危险得多。
///
/// （官方 frp 对未知 `type` 同样是在解码阶段直接报错，所以这也不算额外收紧。）
///
/// `sudp`（秘密 UDP，SUDP）和 stcp 同一套 `secret_key` / `allow_users` 鉴权，
/// 区别只是数据面是 UDP：provider 侧把一条工作连接桥到本地 UDP 服务，
/// visitor 侧把本地 UDP socket 转发到 secret UDP 通道。
const SUPPORTED_PROXY_TYPES: &[&str] = &[
    "tcp", "udp", "http", "https", "tcpmux", "stcp", "xtcp", "sudp",
];
const SUPPORTED_VISITOR_TYPES: &[&str] = &["stcp", "xtcp", "sudp"];

/// 官方 frp 的客户端插件类型全集（`pkg/config/v1/plugin.go` 的 `UnmarshalJSON` 分支）。
///
/// 放在这里是为了让「支持清单」与「官方全集」的差集能被**自动算出来**：
/// 以后补实现时只改 [`SUPPORTED_PLUGIN_TYPES`]，报错文案和自检结果跟着走，
/// 不会出现"代码支持了但提示还写着不支持"的漂移。
pub const OFFICIAL_PLUGIN_TYPES: &[&str] = &[
    "http_proxy",
    "socks5",
    "static_file",
    "unix_domain_socket",
    "http2http",
    "http2https",
    "https2http",
    "https2https",
    "tls2raw",
];

/// NFrp 真正实现的客户端插件类型。
pub const SUPPORTED_PLUGIN_TYPES: &[&str] = &[
    "http_proxy",
    "socks5",
    "static_file",
    "unix_domain_socket",
    "http2http",
    "http2https",
    "https2http",
    "https2https",
    "tls2raw",
];

/// 插件类型名的归一化键：小写 + 去下划线。
///
/// 官方的类型名只认下划线写法，但 NFrp 历来也认 `staticfile` 这类紧凑写法
/// （见 `client/src/plugin.rs`）。把归一化放在公共层，**列表与匹配用同一个键**，
/// 省得两处各写一套等价判断、慢慢长歪。
fn plugin_key(raw: &str) -> String {
    raw.trim().to_ascii_lowercase().replace('_', "")
}

/// 这个插件类型 NFrp 实现了吗。
pub fn plugin_type_supported(raw: &str) -> bool {
    let k = plugin_key(raw);
    SUPPORTED_PLUGIN_TYPES.iter().any(|t| plugin_key(t) == k)
}

/// 「官方有、NFrp 没有」的插件类型（用于把报错话说全）。
pub fn unimplemented_plugin_types() -> Vec<&'static str> {
    OFFICIAL_PLUGIN_TYPES
        .iter()
        .copied()
        .filter(|t| !plugin_type_supported(t))
        .collect()
}

/// 单条代理的类型 + 插件 + tcpmux 自检（配置文件与远程下发共用）。
fn reject_bad_proxy(p: &ProxyConfig) -> Result<()> {
    if !SUPPORTED_PROXY_TYPES.contains(&p.proxy_type.as_str()) {
        return Err(crate::error::Error::Protocol(format!(
            "代理 [{}] 的类型 {:?} 不受支持（NFrp 实现了 {}）",
            p.name,
            p.proxy_type,
            SUPPORTED_PROXY_TYPES.join(" / ")
        )));
    }
    reject_unimplemented_plugin(p)?;
    reject_bad_tcpmux(p)
}

fn reject_unimplemented_types(cfg: &ClientConfig) -> Result<()> {
    for p in &cfg.proxies {
        reject_bad_proxy(p)?;
    }
    for v in &cfg.visitors {
        if !SUPPORTED_VISITOR_TYPES.contains(&v.visitor_type.as_str()) {
            return Err(crate::error::Error::Protocol(format!(
                "访客 [{}] 的类型 {:?} 不受支持（NFrp 实现了 {}）",
                v.name,
                v.visitor_type,
                SUPPORTED_VISITOR_TYPES.join(" / ")
            )));
        }
    }
    Ok(())
}

/// 单条代理的插件类型自检。
///
/// # 为什么必须在**解析阶段**就报错
///
/// 插件类型的匹配原先只发生在**客户端** `plugin::Plugin::from_proxy` —— 那是
/// **每条工作连接**到来时才走的路径。于是 `frpc verify` 对着一份
/// `plugin.type = "tls2raw"` 的配置会回**「配置校验通过」**，用户拿着这个绿灯去上线，
/// 全量连接才逐个失败。绿灯是假的，比红灯危险得多。
///
/// 官方 frp 对未知插件类型是在**解码阶段**直接 `unknown plugin type: %s`
/// （`pkg/config/v1/decode.go:115`）—— 这里对齐它的时机。
fn reject_unimplemented_plugin(p: &ProxyConfig) -> Result<()> {
    let kind = p.plugin.trim();
    if kind.is_empty() {
        return Ok(());
    }
    if plugin_type_supported(kind) {
        return Ok(());
    }
    let missing = unimplemented_plugin_types();
    // 分两种情况说清楚，别让用户拿"支持的清单"去猜自己是拼错了还是官方有而这里没有。
    if missing.iter().any(|t| plugin_key(t) == plugin_key(kind)) {
        return Err(crate::error::Error::Protocol(format!(
            "代理 [{}] 的插件 {:?} 是官方 frp 有、但 NFrp **尚未实现**的插件 —— \
             现在放行只会让每条连接在运行期逐个失败，所以在这里直接拒绝。\n\
             官方有而 NFrp 没有的插件：{}",
            p.name,
            kind,
            missing.join(" / ")
        )));
    }
    Err(crate::error::Error::Protocol(format!(
        "代理 [{}] 的插件 {:?} 不认识（NFrp 实现了 {}）",
        p.name,
        kind,
        SUPPORTED_PLUGIN_TYPES.join(" / ")
    )))
}

/// 校验**远程下发**的代理配置（`ServerCmd` / 客户端 Web API 两条入口共用）。
///
/// # 为什么必须有这个函数
///
/// 走**配置文件**的代理要过三道关（[`reject_unimplemented_types`] /
/// [`reject_unimplemented_plugin`] / [`reject_bad_tcpmux`]），但走
/// **服务端 `ServerCmd`** 和**客户端本地 Web API** 的代理**一道都不过** ——
/// 那两条路径原先只检查 `name` / `type` 非空。
///
/// 后果不是理论上的：`ProxyConfig` 里混着两类字段 ——
///
/// * **代理语义字段**（`name` / `type` / `remote_port` / `custom_domains`…），
///   服务端下发了没问题，这正是"面板增删代理"功能要的；
/// * **本机资源字段**（`plugin_local_path` / `plugin_local_addr` /
///   `plugin_crt_path` / `plugin_key_path`），**只有本机用户才有资格决定**。
///
/// 服务端能把第二类一起下发，就等于让它指定客户端**读哪个文件**、
/// **连哪个内网地址**（`plugin = "static_file"` + `local_path = "/etc"` 配
/// 一个公网域名，就是可读的任意文件服务；`plugin_local_addr` 则是内网 SSRF）。
///
/// 所以这里的策略是：**远程来源一律不许携带任何本机资源字段**，
/// 且代理类型 / 插件类型 / tcpmux 约束仍要照常过。
///
/// # 参数
///
/// `is_remote` 为 `true` 时启用"禁止本机资源字段"这条。配置文件路径传
/// `false`（它本来就走完整校验，这里只是复用类型检查）。
pub fn validate_remote_proxy(p: &ProxyConfig, is_remote: bool) -> Result<()> {
    if is_remote {
        // 一条代理里只要沾了本机资源字段就整条拒绝 —— 不做"悄悄丢弃该字段"，
        // 那样服务端以为自己下发成功了，用户却拿到一条行为不同的代理。
        let mut offending: Vec<&str> = Vec::new();
        if !p.plugin_local_path.trim().is_empty() {
            offending.push("pluginLocalPath");
        }
        if !p.plugin_local_addr.trim().is_empty() {
            offending.push("pluginLocalAddr");
        }
        if !p.plugin_crt_path.trim().is_empty() {
            offending.push("pluginCrtPath");
        }
        if !p.plugin_key_path.trim().is_empty() {
            offending.push("pluginKeyPath");
        }
        if !offending.is_empty() {
            return Err(crate::error::Error::Protocol(format!(
                "代理 [{}] 来自远程下发，不允许携带本机资源字段（{}）—— \
                 这些字段决定读哪个文件、连哪个内网地址，只能由本机配置文件指定。",
                p.name,
                offending.join(" / ")
            )));
        }

        // ★★ v0.5.4 修 H4：`local_addr` 必须**只允许回环**。
        //
        // 为什么这是必需的：`local_addr` 决定客户端**往哪里连**
        // （`client/src/main.rs` 里每个工作连接都会 `TcpStream::connect(local)`）。
        // 它原先**不在**上面那份黑名单里，于是一个不可信的服务端
        // （或能下发 `ServerCmd` 的面板）只要下发
        // `local_addr = "169.254.169.254:80"`，就能让客户端去连**云元数据服务** ——
        // 这就是服务端可控的 SSRF。同理 `10.0.0.5:6379` 可做内网横向。
        //
        // ★ 这里刻意**反过来用允许清单**（默认拒绝），而不是继续往黑名单里加一条。
        //   H3 与 H4 是同一类错误的两个实例：「防线写对了，但没铺满它声称要保护的
        //   字段/路径」。黑名单每漏一个字段就是一次漏洞；允许清单漏一个字段
        //   只是"少支持一个场景"。远程下发**本来就不该**决定客户端连哪里。
        //
        // 兼容性说明：远程下发通常来自面板的"添加代理"功能，而面板自己填的
        // `local_addr` 本来就是内网服务地址（`127.0.0.1:xxxx` 最常见）。
        // 真有跨机场景的，应当由本机配置文件写死，而不是让服务端远程指定。
        if !p.local_addr.trim().is_empty() {
            let host = local_addr_host(&p.local_addr);
            if !is_loopback_host(host) {
                return Err(crate::error::Error::Protocol(format!(
                    "代理 [{}] 来自远程下发，`local_addr` 只能指向本机回环地址，\
                     收到 {:?}（主机部分 {:?}）—— 远程下发不该决定客户端往哪里连。\
                     若确实需要连别的地址，请写在本机配置文件里。",
                    p.name, p.local_addr, host
                )));
            }
        }
    }
    reject_bad_proxy(p)
}

/// 从 `host:port` 里切出主机部分（兼容 `[::1]:80` 这种带方括号的 IPv6）。
///
/// 单独抽出来是因为 `rsplit_once(':')` 对 IPv6 是错的：
/// `[::1]:80` 会切成 `[:`，`::1` 会切成 `:`。项目里 `canonical_host`
/// 已经在处理同类问题，这里保持一致的口径。
fn local_addr_host(addr: &str) -> &str {
    let a = addr.trim();
    if let Some(rest) = a.strip_prefix('[') {
        // `[::1]:80` -> `::1`
        return rest.split(']').next().unwrap_or(rest);
    }
    // ★ 无方括号时的关键判断：冒号**只有一个**才可能是 `host:port`。
    //
    // 裸 IPv6（`::1`、`fd00::1`）有多个冒号，按 `rsplit_once(':')` 切会得到
    // `":"` 这种垃圾 —— 而那会让**合法的 `::1` 被误拒**（诊断时实测踩到）。
    // 所以先数冒号：多于一个就整串当主机。
    if a.matches(':').count() != 1 {
        return a;
    }
    match a.rsplit_once(':') {
        Some((h, port)) if !port.is_empty() && port.bytes().all(|b| b.is_ascii_digit()) => h,
        _ => a,
    }
}

/// 这个主机名/地址是不是"只有本机"。
///
/// 接受 `127.0.0.0/8`、`::1`、`localhost`。**不接受** `0.0.0.0`（那是"监听全部"，
/// 不是"连本机"），也不接受任何解析不出 IP 的域名 —— 域名可能解析到任意地址，
/// 而且解析结果在连接时才确定，判据不能靠它。
fn is_loopback_host(host: &str) -> bool {
    let h = host.trim();
    if h.eq_ignore_ascii_case("localhost") {
        return true;
    }
    match h.parse::<std::net::IpAddr>() {
        Ok(std::net::IpAddr::V4(v4)) => v4.is_loopback(),
        Ok(std::net::IpAddr::V6(v6)) => v6.is_loopback(),
        // 解析不出（域名等）⇒ 从严当作"非本机"
        Err(_) => false,
    }
}

/// `tcpmux` 的两条必填约束，对齐官方 `validateTCPMuxProxyConfigForClient`。
/// 1. `multiplexer` 只认 `httpconnect`（官方报 `not support multiplexer: %s`）。
///    留空也算不认识 —— 官方那边空串同样过不了 `slices.Contains`。
/// 2. 必须配 `customDomains` 或 `subdomain`。tcpmux **不绑端口**，全靠 CONNECT
///    请求里的域名分发，没有域名就等于这条代理没有任何入口。
///
/// 两条都放在**解析阶段**：不然 `frpc verify` 回绿灯，用户拿去上线才发现服务端
/// 拒绝 —— 和之前那批"假绿灯"是同一个坑（见 [`reject_unimplemented_plugin`]）。
fn reject_bad_tcpmux(p: &ProxyConfig) -> Result<()> {
    if p.proxy_type != "tcpmux" {
        return Ok(());
    }
    if p.multiplexer != "httpconnect" {
        return Err(crate::error::Error::Protocol(format!(
            "代理 [{}] 的 multiplexer 是 {:?}，只支持 \"httpconnect\"（官方也只有这一种）",
            p.name, p.multiplexer
        )));
    }
    let no_domain = p.custom_domains.iter().all(|d| d.trim().is_empty());
    if no_domain && p.subdomain.trim().is_empty() {
        return Err(crate::error::Error::Protocol(format!(
            "代理 [{}] 是 tcpmux：它不绑端口、只按 CONNECT 请求里的域名分发，\
             所以 customDomains 和 subdomain 至少要配一个",
            p.name
        )));
    }
    Ok(())
}

/// 解析客户端配置文本（**仅 TOML**）。
///
/// 解析前先过一遍 [`crate::frp_config::normalize_client`]，所以**原版 frpc 的
/// 配置可以直接拿来用**（`serverAddr` / `localIP` / `localPort` / `auth.token` /
/// 顶层 `[metadatas]` ...）。NFrp 自己的写法同时有效，两种写法混用时原生字段优先。
///
/// 需要"连 legacy INI 一起认"时用 [`parse_client`]（`ClientConfig::load` 走的那个）。
pub fn parse_client_toml(raw: &str) -> Result<ClientConfig> {
    let mut value: toml::Value = toml::from_str(raw)?;
    // 必须在 normalize **之前**扫描：normalize 会按搬家表改键名
    // （`poolCount` → `pool_count` 之类），拿原始键名对照清单才准。
    let unsupported = crate::frp_config::unsupported_fields(&value);
    crate::frp_config::normalize_client(&mut value);
    let mut cfg: ClientConfig = value.try_into()?;
    cfg.unsupported_fields = unsupported;
    Ok(cfg)
}

/// 解析服务端配置文本（**仅 TOML**）。同 [`parse_client_toml`]，兼容原版 `frps.toml` 的字段名。
pub fn parse_server_toml(raw: &str) -> Result<ServerConfig> {
    let mut value: toml::Value = toml::from_str(raw)?;
    // 与客户端同理：必须在 normalize **之前**扫（normalize 会改键名）。
    let unsupported = crate::frp_config::unsupported_server_fields(&value);
    // ★ v0.5.4（M4）：在 normalize **之前**记录"用户有没有显式写过 bind_addr"。
    //
    // normalize 会把官方键名（`bindAddr` 之类）搬成规范名，所以要在它之前看。
    // 两种写法都算"显式写过"。
    let bind_addr_explicit = value
        .as_table()
        .map(|t| {
            t.keys()
                .any(|k| k.eq_ignore_ascii_case("bind_addr") || k.eq_ignore_ascii_case("bindAddr"))
        })
        .unwrap_or(false);
    crate::frp_config::normalize_server(&mut value);
    let mut cfg: ServerConfig = value.try_into()?;
    cfg.unsupported_fields = unsupported;
    cfg.bind_addr_explicitly_set = bind_addr_explicit;
    Ok(cfg)
}

#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // Debug 脱敏（v0.5.3）
    // -----------------------------------------------------------------------

    /// ★★ 密钥绝不能通过 `Debug` 泄漏 —— 这是"等着被踩"的坑的锁定测试。
    ///
    /// 项目里眼下没有 `println!("{cfg:?}")`，但配置结构被到处传递，
    /// 只要有人加一句调试打印，明文 token / 口令 / secret_key 就会进日志。
    /// 这条测试保证：**即使有人这么写，也打不出密钥**。
    #[test]
    fn debug_输出不得泄漏服务端密钥() {
        let c = ServerConfig {
            token: "SUPER-SECRET-TOKEN-XYZ".into(),
            dashboard_user: "admin".into(),
            dashboard_pwd: "PANEL-PASSWORD-123".into(),
            ..Default::default()
        };

        let s = format!("{c:?}");
        assert!(!s.contains("SUPER-SECRET-TOKEN-XYZ"), "token 泄漏了：{s}");
        assert!(!s.contains("PANEL-PASSWORD-123"), "面板口令泄漏了：{s}");
        // 但应当看得出"配了多长"，便于排障
        assert!(s.contains("redacted"), "应当保留可排障的脱敏标记：{s}");
        // 用户名这类非机密信息可以保留
        assert!(s.contains("admin"));
    }

    /// 认证子结构的 Debug 也必须脱敏。
    #[test]
    fn debug_输出不得泄漏认证配置的密钥() {
        let a = crate::security::ServerAuthConfig {
            token: "AUTH-SECTION-TOKEN".into(),
            ..Default::default()
        };
        let s = format!("{a:?}");
        assert!(!s.contains("AUTH-SECTION-TOKEN"), "token 泄漏了：{s}");
        assert!(s.contains("redacted"));
    }

    /// 客户端配置里的 token / webServer 口令 / 代理 secret_key 都要脱敏。
    #[test]
    fn debug_输出不得泄漏客户端密钥() {
        let c = ClientConfig {
            token: "CLIENT-TOKEN-ABC".into(),
            web_server: WebServerConfig {
                password: "WEB-PASSWORD-456".into(),
                ..Default::default()
            },
            proxies: vec![ProxyConfig {
                name: "p1".into(),
                proxy_type: "stcp".into(),
                secret_key: "PROXY-SECRET-KEY".into(),
                ..Default::default()
            }],
            ..Default::default()
        };

        let s = format!("{c:?}");
        assert!(!s.contains("CLIENT-TOKEN-ABC"), "客户端 token 泄漏了：{s}");
        assert!(!s.contains("WEB-PASSWORD-456"), "Web 口令泄漏了：{s}");
        // 代理是按数量展示的，不会展开 secret_key
        assert!(s.contains("proxies"), "{s}");
    }

    /// 序列化（serde）**不受影响** —— 脱敏只针对 Debug 输出。
    ///
    /// 这条很重要：如果为了"脱敏"把 serde 也改了，`--gen-config` 之类的
    /// 功能就会输出假的密钥，那是另一种破坏。
    #[test]
    fn 脱敏不影响_serde_序列化() {
        let c = ServerConfig {
            token: "ROUNDTRIP-TOKEN".into(),
            ..Default::default()
        };
        let text = toml::to_string(&c).unwrap();
        assert!(
            text.contains("ROUNDTRIP-TOKEN"),
            "序列化必须保留真实 token：{text}"
        );
    }

    // -----------------------------------------------------------------------
    // allowPorts（PortRange / parse_port_ranges / port_allowed）
    // -----------------------------------------------------------------------

    #[test]
    fn 端口列表解析对齐官方的逗号串写法() {
        let rs = parse_port_ranges("1000-2000,3000,4000-5000").unwrap();
        assert_eq!(rs.len(), 3);
        assert_eq!(rs[0], PortRange::new(1000, 2000));
        assert_eq!(rs[1], PortRange::single(3000));
        assert_eq!(rs[2], PortRange::new(4000, 5000));
        assert_eq!(format_port_ranges(&rs), "1000-2000,3000,4000-5000");
        // 允许空格（官方 `strings.TrimSpace` 每段都 trim）
        assert_eq!(
            format_port_ranges(&parse_port_ranges(" 1000 - 2000 , 3000 ").unwrap()),
            "1000-2000,3000"
        );
        // 空串 = 空列表（不是错误）
        assert!(parse_port_ranges("   ").unwrap().is_empty());
    }

    #[test]
    fn 端口列表的非法写法要报错() {
        // 区间反了：官方 `NewPortsRangeSliceFromString` 也报错
        assert!(parse_port_ranges("3000-2000").is_err());
        // 不是数字
        assert!(parse_port_ranges("abc").is_err());
        // 超出 u16
        assert!(parse_port_ranges("70000").is_err());
        // 三段（`1-2-3`）
        assert!(parse_port_ranges("1-2-3").is_err());
        // 半截区间
        assert!(parse_port_ranges("1000-").is_err());
    }

    #[test]
    fn 端口白名单为空等于不限制() {
        assert!(port_allowed(&[], 22));
        assert!(port_allowed(&[], 65535));
        let only = parse_port_ranges("8000-9000").unwrap();
        assert!(port_allowed(&only, 8000));
        assert!(port_allowed(&only, 9000));
        assert!(!port_allowed(&only, 7999));
        assert!(!port_allowed(&only, 9001));
    }

    /// 官方 TOML 的 `{ start = …, end = … }` / `{ single = … }` 两种表都要认。
    #[test]
    fn 官方表写法的_allow_ports_能读进来() {
        let raw = r#"
bindPort = 7000
allowPorts = [
  { start = 2000, end = 3000 },
  { single = 3001 },
  { start = 4000, end = 5000 },
]
"#;
        let cfg = parse_server_toml(raw).unwrap();
        assert_eq!(cfg.allow_ports.len(), 3);
        assert_eq!(
            format_port_ranges(&cfg.allow_ports),
            "2000-3000,3001,4000-5000"
        );
        assert!(cfg.port_allowed(3001));
        assert!(!cfg.port_allowed(3999));
    }

    /// 字符串写法（legacy INI / 官方 `--allow_ports`）也要认，元素里还能带逗号。
    #[test]
    fn 字符串写法的_allow_ports_能读进来() {
        let cfg = parse_server_toml("allowPorts = [\"1000-2000,3000\"]\n").unwrap();
        assert_eq!(format_port_ranges(&cfg.allow_ports), "1000-2000,3000");
        assert!(cfg.port_allowed(1500));
        assert!(!cfg.port_allowed(3001));
    }

    #[test]
    fn 区间反了的_allow_ports_要在解析阶段报错() {
        let err = parse_server_toml("allowPorts = [{ start = 3000, end = 2000 }]\n")
            .unwrap_err()
            .to_string();
        assert!(err.contains("区间反了"), "{err}");
        // 表里既没有 start 也没有 single
        assert!(parse_server_toml("allowPorts = [{ foo = 1 }]\n").is_err());
    }

    #[test]
    fn 序列化回官方表写法() {
        #[derive(Serialize)]
        struct W {
            allow_ports: Vec<PortRange>,
        }
        let w = W {
            allow_ports: vec![PortRange::single(8443), PortRange::new(20000, 30000)],
        };
        let s = toml::to_string(&w).unwrap();
        assert!(s.contains("single = 8443"), "{s}");
        assert!(s.contains("start = 20000"), "{s}");
        assert!(s.contains("end = 30000"), "{s}");
        // 写出去的东西必须还能读回来（`--gen-config` 之后手改再加载）
        let back = parse_server_toml(&s).unwrap();
        assert_eq!(back.allow_ports, w.allow_ports);
    }

    // -----------------------------------------------------------------------
    // 新增字段的默认值与解析
    // -----------------------------------------------------------------------

    #[test]
    fn 安全相关字段的默认值对齐官方() {
        let cfg = ServerConfig::default();
        assert!(cfg.allow_ports.is_empty(), "空 = 不限制（官方语义）");
        assert_eq!(cfg.max_ports_per_client, 0, "0 = 不限");
        assert!(
            cfg.detailed_errors_to_client,
            "官方 `Complete()` 里 EmptyOr(…, true)"
        );
        assert_eq!(cfg.vhost_http_timeout, 60, "官方 EmptyOr(…, 60)");
        assert_eq!(cfg.max_days, 3, "官方 LogConfig.Complete 里 EmptyOr(…, 3)");
        assert!(cfg.custom_404_page.is_empty());
        assert_eq!(cfg.log_to, "");
        assert!(cfg.vhost_http_timeout().is_some());
        assert!(ServerConfig {
            vhost_http_timeout: 0,
            ..Default::default()
        }
        .vhost_http_timeout()
        .is_none());
    }

    #[test]
    fn 服务端的日志与虚拟主机字段能读进来() {
        let raw = r#"
bindPort = 7000
vhostHTTPTimeout = 12
custom404Page = "/etc/frps/404.html"
detailedErrorsToClient = false
maxPortsPerClient = 8

[log]
to = "/var/log/frps.log"
level = "debug"
maxDays = 7
"#;
        let cfg = parse_server_toml(raw).unwrap();
        assert_eq!(cfg.vhost_http_timeout, 12);
        assert_eq!(cfg.custom_404_page, "/etc/frps/404.html");
        assert!(!cfg.detailed_errors_to_client);
        assert_eq!(cfg.max_ports_per_client, 8);
        assert_eq!(cfg.log_to, "/var/log/frps.log");
        assert_eq!(cfg.log_level, "debug");
        assert_eq!(cfg.max_days, 7);
        assert!(
            cfg.unsupported_fields.is_empty(),
            "这几项都已实现，不该再报未实现：{:?}",
            cfg.unsupported_fields
        );
    }

    #[test]
    fn 客户端的日志字段能读进来() {
        let raw = r#"
serverAddr = "1.2.3.4"
serverPort = 7000

[log]
to = "frpc.log"
maxDays = 5
"#;
        let cfg = parse_client_toml(raw).unwrap();
        assert_eq!(cfg.log_to, "frpc.log");
        assert_eq!(cfg.max_days, 5);
    }

    /// `sk` 是官方 INI 里 `secret_key` 的写法，TOML 下也必须接受。
    ///
    /// serde **不拒绝未知字段**，漏了这个别名的话用户照 INI 习惯写 `sk`
    /// 会被静默忽略 —— 注册时才报「必须配置 secret_key」，排查成本很高。
    #[test]
    fn sk_别名必须等价于_secret_key() {
        let toml_str = r#"
server_addr = "127.0.0.1"
server_port = 17000

[[proxies]]
name = "p"
type = "sudp"
localIP = "127.0.0.1"
localPort = 1234
sk = "abc"
allowUsers = ["dave"]

[[visitors]]
name = "v"
type = "sudp"
serverName = "p"
serverUser = "carol"
sk = "abc"
bindPort = 2222
"#;
        // 走 `parse_client`（也就是 `ClientConfig::load` 的真实路径），
        // 顺带覆盖 `localIP` + `localPort` → `local_addr` 的原版写法。
        let cfg: ClientConfig = parse_client(toml_str).expect("sk 必须能解析");
        assert_eq!(cfg.proxies[0].secret_key, "abc", "proxy 的 sk → secret_key");
        assert_eq!(
            cfg.visitors[0].secret_key, "abc",
            "visitor 的 sk → secret_key"
        );
        assert_eq!(cfg.proxies[0].allow_users, vec!["dave".to_string()]);
    }

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
        // 示例里必须示范**安全相关**的那几项，否则用户根本不知道它们存在
        assert_eq!(cfg.allow_ports.len(), 1, "示例要示范端口白名单");
        assert!(cfg.port_allowed(25000));
        assert!(!cfg.port_allowed(22), "22 不该在白名单里");
        assert_eq!(cfg.max_ports_per_client, 20);
        assert_eq!(cfg.vhost_http_timeout, 60);
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

    /// ★ 回归：`verify` 曾经对未实现的插件类型回「配置校验通过」。
    ///
    /// 官方 frp 对未知插件是**解码阶段**就报 `unknown plugin type`
    /// （`pkg/config/v1/decode.go:115`），所以这里也在解析阶段拒绝。
    ///
    /// 官方 0.71 的 9 个插件现已**全部实现**，所以「尚未实现」那条分支目前走不到。
    /// 这条断言留在这是给以后的自己看的：哪天官方新增插件类型，把
    /// [`OFFICIAL_PLUGIN_TYPES`] 补上之后它会立刻变红，提醒你那条分支要开始工作了。
    #[test]
    fn 官方插件现在全部实现() {
        let missing = unimplemented_plugin_types();
        assert!(
            missing.is_empty(),
            "以下插件没实现，解析阶段会拒绝它们：{missing:?}"
        );
    }

    /// 官方的 9 个插件类型全部能过解析阶段 —— 一个都不能被这条校验误伤。
    #[test]
    fn 官方九个插件都能过解析阶段() {
        for kind in OFFICIAL_PLUGIN_TYPES {
            let cfg_text = format!(
                r#"
server_addr = "127.0.0.1"
server_port = 7000

[[proxies]]
name = "p"
type = "tcp"
localIP = "127.0.0.1"
localPort = 80
remote_port = 6000

[proxies.plugin]
type = "{kind}"
localAddr = "127.0.0.1:9000"
localPath = "/tmp/x"
crtPath = "/tmp/x.crt"
keyPath = "/tmp/x.key"
"#
            );
            assert!(parse_client(&cfg_text).is_ok(), "官方的 {kind} 被误伤了");
        }
    }

    /// 拼错的插件名与「官方有但没有」要报不同的错 —— 否则用户没法判断该改拼写还是该换方案。
    #[test]
    fn 拼错的插件名要报不认识而不是没实现() {
        let cfg_text = r#"
server_addr = "127.0.0.1"
server_port = 7000

[[proxies]]
name = "p"
type = "tcp"
localIP = "127.0.0.1"
localPort = 80
remote_port = 6000

[proxies.plugin]
type = "magic_proxy"
"#;
        let err = parse_client(cfg_text).expect_err("不认识的插件必须被拒");
        let msg = format!("{err:#}");
        assert!(msg.contains("不认识"), "{msg}");
        assert!(!msg.contains("尚未实现"), "不能把拼错说成没实现：{msg}");
    }

    // ---- tcpmux ----

    /// 官方 `frpc_full_example.toml` 里 tcpmux 那一段（含 camelCase 字段名）。
    #[test]
    fn 官方示例里的_tcpmux_段能整体解析() {
        let cfg_text = r#"
serverAddr = "127.0.0.1"
serverPort = 7000

[[proxies]]
name = "tcpmuxhttpconnect"
type = "tcpmux"
multiplexer = "httpconnect"
localIP = "127.0.0.1"
localPort = 10701
customDomains = ["tunnel1"]
routeByHTTPUser = "user1"
"#;
        let c = parse_client(cfg_text).expect("官方 tcpmux 写法必须能解析");
        let p = &c.proxies[0];
        assert_eq!(p.proxy_type, "tcpmux");
        assert_eq!(p.multiplexer, "httpconnect");
        assert_eq!(p.route_by_http_user, "user1");
        assert_eq!(p.local_addr, "127.0.0.1:10701");
    }

    /// tcpmux 的三条必填约束都要在**解析阶段**拦下 —— 不然 `frpc verify` 回绿灯，
    /// 用户拿去上线才发现服务端拒绝（这就是之前那批"假绿灯"的同一个坑）。
    #[test]
    fn tcpmux_缺字段或缺域名要在解析阶段就报错() {
        let base = |extra: &str| {
            format!(
                r#"
server_addr = "127.0.0.1"
server_port = 7000

[[proxies]]
name = "mux"
type = "tcpmux"
localIP = "127.0.0.1"
localPort = 10701
{extra}
"#
            )
        };

        // ① 没写 multiplexer
        let err =
            parse_client(&base("customDomains = [\"a.b\"]")).expect_err("缺 multiplexer 该报错");
        let msg = format!("{err:#}");
        assert!(msg.contains("multiplexer"), "{msg}");

        // ② multiplexer 拼错 / 用了官方没有的值
        let err = parse_client(&base(
            "multiplexer = \"httpconnectt\"\ncustomDomains = [\"a.b\"]",
        ))
        .expect_err("未知 multiplexer 该报错");
        assert!(format!("{err:#}").contains("multiplexer"), "{err:#}");

        // ③ 一个域名都没有：tcpmux 不绑端口，没有域名就等于没有入口
        let err = parse_client(&base("multiplexer = \"httpconnect\"")).expect_err("没有域名该报错");
        let msg = format!("{err:#}");
        assert!(
            msg.contains("customDomains") || msg.contains("subdomain"),
            "{msg}"
        );

        // 配齐了就该过
        assert!(parse_client(&base(
            "multiplexer = \"httpconnect\"\ncustomDomains = [\"a.b\"]"
        ))
        .is_ok());
    }

    /// 服务端两个新字段：`tcpmuxHTTPConnectPort` / `tcpmuxPassthrough`。
    #[test]
    fn 服务端的_tcpmux_配置项能读进来() {
        // 走 parse_server（含 frp camelCase 归一化）—— 直接 toml::from_str 是
        // 不认 `tcpmuxHTTPConnectPort` 的，那样测不出"官方配置能不能直接喂进来"
        let s = parse_server_toml(
            r#"
tcpmuxHTTPConnectPort = 1337
tcpmuxPassthrough = true
"#,
        )
        .expect("官方写法必须能解析");
        assert_eq!(s.tcpmux_http_connect_port, Some(1337));
        assert!(s.tcpmux_passthrough);

        // 不配就是"不启用"
        let d = ServerConfig::default();
        assert!(d.tcpmux_http_connect_port.is_none());
        assert!(!d.tcpmux_passthrough);
    }
}
