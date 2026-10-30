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
/// ★ v0.5.3：手工实现 `Debug`（见文件下方），`token` 与 `dashboard_pwd`
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
    /// ★ 与官方的默认值 5 **不同**：官方不写就是 5（+10 余量），nfrp 不写
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
    /// `0` 表示**关闭看门狗**（行为回到 v0.5.10 基线）—— 项目约定
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
    /// 官方 frpc 默认不带客户端证书，因此这条路径主要给"NFRP 客户端 + NFRP 服务端"
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

    /// group 负载均衡策略（**Nfrp 扩展**，官方 frp 没有这个配置项）。
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

    /// KCP 会话表条数上限（**Nfrp 扩展**，默认 1024）。
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
    /// ★ 超大规模部署的正确做法**不是无限调大**，而是：
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
    /// ★ v0.6.5：配了它之后，QUIC 监听**只**在这个端口上开，**不再**顺带占用
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
    /// NFRp 历史上使用 `dashboard_port` / `dashboard_user` / `dashboard_pwd`。
    /// 现在同时接受官方写法：`[webServer] port` 作为 dashboard 端口的备用值，
    /// `user` / `password` 作为 dashboard 凭据的备用值，`[webServer.tls]`
    /// 用于面板 HTTPS。两者都写时显式的 `dashboard_*` 优先。
    #[serde(default, rename = "webServer")]
    pub web_server: WebServerConfig,

    /// 是否在面板端口上导出 Prometheus 指标（官方 frps 的 `enablePrometheus`）。
    ///
    /// ★ v0.6.5：**默认关闭**，与官方一致。此前是无条件开放 `/metrics`。
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
    /// ★ v0.6.6：官方默认 **1500**，而 NFRP 一直用 **65507**（UDP 协议上限）。
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
    /// ★ v0.6.6：配了它之后，面板的 `/` 与其它路径会**优先从这个目录读文件**，
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
    /// ★ v0.6.6：默认关闭。与 `enablePrometheus` 同口径 —— 诊断端点不该在
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
    /// 官方默认 168（7 天）。NFRp 目前只实现 mode 0，因此这里的记录用于
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
    /// 登录时间戳允许的偏差（秒），v0.5.6 修审计总报告 M3。
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
    /// ★ 与官方 frp 的默认值不同：官方**完全不校验**。对需要与
    ///   时钟严重不准的官方客户端互通的场景，把它设为 0 即可。
    #[serde(default = "default_max_clock_skew")]
    pub max_clock_skew_secs: u64,
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

/// **唯一判据**：这对面板 / 管理界面凭据能不能用来鉴权（v0.5.6 修审计总报告 H1）。
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
///   字面量 `" admin "`（第八轮审计 F8-L3 实测确认）。原先这里的注释写成
///   "用户名惯例允许两侧空白"，与实现不符，会给排障指错方向。
pub fn has_dashboard_creds(user: &str, pwd: &str) -> bool {
    !user.trim().is_empty() && !pwd.is_empty()
}

#[cfg(test)]
mod has_no_auth_tests {
    use super::*;
    use crate::security::ServerAuthConfig;

    /// ★★ M6 + L11 回归：**纯 OIDC 部署不得被判为"没有认证"**。
    ///
    /// 这两条是同一个根因的两个表现（审计报告分列在 M6 与 L11）：
    /// * M6：`main.rs` 用裸 `cfg.token`，与 `guard.rs` 的 `effective_auth()` 两套口径；
    /// * L11：结果是纯 OIDC 部署被打出"未配置 token —— 任何人都能连上来"，
    ///   而**事实完全相反**。报告还点出一个二级危害：这个假告警会诱导用户
    ///   加 `allow_insecure_no_auth = true` 去"消掉它" —— 那**真的**把认证关了。
    #[test]
    fn 纯_oidc_部署不算没有认证() {
        use crate::security::AuthMethod;

        // 纯 OIDC：method=oidc、无 token ⇒ **有认证**，不该告警
        let c = ServerConfig {
            auth: ServerAuthConfig {
                method: AuthMethod::Oidc,
                ..Default::default()
            },
            token: String::new(),
            ..Default::default()
        };
        assert!(
            !c.has_no_auth(),
            "OIDC 模式没有 token 是**正常配置**，不得判为无认证"
        );

        // token 模式 + 无 token ⇒ 真的没有认证
        let c = ServerConfig {
            auth: ServerAuthConfig {
                method: AuthMethod::Token,
                ..Default::default()
            },
            token: String::new(),
            ..Default::default()
        };
        assert!(c.has_no_auth(), "token 模式无 token ⇒ 确实没有认证");

        // token 模式 + 有 token ⇒ 有认证
        let c = ServerConfig {
            auth: ServerAuthConfig {
                method: AuthMethod::Token,
                ..Default::default()
            },
            token: "s3cret".into(),
            ..Default::default()
        };
        assert!(!c.has_no_auth());
    }

    /// `effective_auth()` 的**字段合并**语义必须被继承：
    /// `[auth] token` 为空时回落到顶层 `token`。
    ///
    /// ★ 这正是不能直接读 `self.token` 的原因 —— 只看顶层会把
    /// `[auth] token = "x"` 这种写法误判成"没有认证"。
    #[test]
    fn 判据必须走_effective_auth_的字段合并() {
        use crate::security::AuthMethod;

        // 凭据写在 [auth] 段里、顶层为空 ⇒ 仍然是"有认证"
        let c = ServerConfig {
            auth: ServerAuthConfig {
                method: AuthMethod::Token,
                token: "from-auth-section".into(),
                ..Default::default()
            },
            token: String::new(),
            ..Default::default()
        };
        assert!(
            !c.has_no_auth(),
            "顶层 token 为空但 [auth] token 有值 ⇒ 有认证（合并语义）"
        );
    }
}

impl ServerConfig {
    /// **唯一判据**：本服务端是不是处于"**没有任何认证**"的状态
    /// （v0.5.6 修审计总报告 M6）。
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
    /// ★ `effective_auth()` 会做字段合并（`[auth] token` 为空时回落到顶层
    ///   `token`），所以判据必须用它，而不是直接读 `self.token`。
    /// ★ 必须同时判 `method`：OIDC 模式下没有 token 是**正常**的。
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
            // v0.5.6（M3）：默认 ±300 秒的登录时间戳窗口（0 = 关闭）
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

// ---------------------------------------------------------------------------
// 客户端配置
// ---------------------------------------------------------------------------

/// 一个 HTTP 请求头键值对，用于健康检查探测。
///
/// 对应官方 frp 的 `pkg/config/v1/proxy.go`：
///
/// ```go
/// type HTTPHeader struct {
///     Name  string `json:"name"`
///     Value string `json:"value"`
/// }
/// ```
///
/// 字段名保持一致（`name` / `value`），所以官方配置可以直接搬过来。
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct HttpHeader {
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub value: String,
}

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
    /// 数据面加密（官方 transport.useEncryption）。配了之后这条代理的业务
    /// 数据会套一层 AES-128-CFB（密钥由 token 派生，与控制通道同一套 pbkdf2）。
    /// 格式与官方逐字节对齐（16 字节明文 IV + CFB 流），所以两端必须一致。
    #[serde(default, rename = "useEncryption", alias = "use_encryption")]
    pub use_encryption: bool,

    /// 数据面压缩（官方 transport.useCompression）。Snappy **framing** 格式，
    /// 位于加密的外层（写：先压缩再加密；读：先解密再解压）。默认关闭。
    #[serde(default, rename = "useCompression", alias = "use_compression")]
    pub use_compression: bool,

    /// 改写发给内网服务的 Host 头。
    #[serde(default)]
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

    // ---- 启用开关 / 注解（frp 0.71 的 ProxyBaseConfig）----
    /// 是否启用这条代理（对应 frp `enabled`；`None` / `true` = 启用，`false` = 禁用）。
    ///
    /// 官方语义（`pkg/config/load.go` 的 `FilterClientConfigurers`）：`enabled = false`
    /// 的代理 / 访客在**加载期**就被摘掉，之后完全等同于"没配" —— 不注册、
    /// 不进本地表、不进面板。nfrp 在 [`parse_client`] 里做同一件事。
    ///
    /// 用 `Option<bool>` 而不是 `bool` + `serde(default = "true")`：
    /// `ProxyConfig` 有 `#[derive(Default)]`，bool 版本会让"程序内构造"与
    /// "从配置反序列化"得到**两个不同的默认值**（v0.5.6 修 L1 的教训）。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enabled: Option<bool>,

    /// 注解键值对（对应 frp `annotations`）。
    ///
    /// 官方语义：随 `NewProxy` 消息带给服务端（`m.Annotations = c.Annotations`，
    /// `pkg/config/v1/proxy.go:176`），官方 frps 0.71 只把它存进代理对象、
    /// **不做任何解读**（`server/` 下没有任何读取点）。
    /// 客户端侧做与官方 [`crate::config`] 内同款校验（Kubernetes 风格键名 +
    /// 总大小 ≤256 KiB，见 `reject_bad_annotations`）。
    #[serde(default, skip_serializing_if = "std::collections::HashMap::is_empty")]
    pub annotations: std::collections::HashMap<String, String>,

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
    /// `http` 检查时额外发送的请求头（对应官方 `healthCheck.httpHeaders`）。
    ///
    /// 官方 `pkg/config/v1/proxy.go` 的 `HealthCheckConfig.HTTPHeaders` 就是
    /// 这个字段。需要鉴权的健康检查端点（带 `Authorization`、内部
    /// `X-Health-Token` 等）靠它才能探测通。
    ///
    /// ```toml
    /// [[proxies.healthCheck.httpHeaders]]
    /// name = "Authorization"
    /// value = "Bearer xxx"
    /// ```
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub health_check_http_headers: Vec<HttpHeader>,

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
    ///
    /// ★★ v0.5.6 修（审计总报告 L1，低危）：默认值改为 **`127.0.0.1`**。
    ///
    /// 原先这里复用了服务端的 `DEFAULT_BIND_ADDR`（`"0.0.0.0"`），
    /// 于是同一份配置出现**三个口径、两个答案**：
    ///
    /// | 来源 | 默认 `bind_addr` |
    /// |---|---|
    /// | TOML 解析路径（本行，原样） | **`0.0.0.0`** |
    /// | INI 解析路径（`frp_legacy.rs`，有锁定测试） | `127.0.0.1` |
    /// | 官方示例配置里写的 | `127.0.0.1` |
    ///
    /// **根因**是复用了一个语义不同的常量：服务端的 `0.0.0.0` 是
    /// "对外提供服务"（正确），而 visitor 的监听口是**本机入口**，
    /// 默认对外没有任何理由。
    ///
    /// 为什么是 Low：`VisitorConfig` 强制要求 `secret_key`，且每条连接
    /// 都要过服务端签名校验 ⇒ 未持密钥者用不了这条隧道。
    /// 残余风险是"不必要地暴露端口 + 可被指纹识别 + DoS 面"。
    ///
    /// ★ 与 INI 路径对齐后，"TOML 不写 bind_addr"与"INI 不写"行为一致。
    #[serde(default = "default_visitor_bind_addr")]
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

    /// 是否启用这个 visitor（对应 frp `enabled`；`None` / `true` = 启用）。
    ///
    /// 语义与 [`ProxyConfig::enabled`] 相同：官方 `FilterClientConfigurers`
    /// 对访客同样过滤，禁用条目在加载期直接摘掉。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enabled: Option<bool>,
}

impl Default for VisitorConfig {
    fn default() -> Self {
        Self {
            name: String::new(),
            visitor_type: default_visitor_type(),
            server_name: String::new(),
            server_user: String::new(),
            secret_key: String::new(),
            // ★ v0.5.6（L1）：与 serde 的 `#[serde(default)]` 保持一致 ——
            //   两处都必须用 visitor 专用的默认值，否则"不写 bind_addr"
            //   在 `Default::default()` 与反序列化两条路径下会得到不同结果。
            bind_addr: default_visitor_bind_addr(),
            bind_port: 0,
            // 与 serde 保持一致：`None` / `true` = 启用
            enabled: None,
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

    /// NLink v1 扩展层（默认关闭）。
    #[serde(default)]
    pub nlink: crate::nlink::ClientNLinkConfig,

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
    ///
    /// ★★ v0.5.8 修（第七轮审计 **B-2**，中危）：**加 `tlsEnable` 别名。**
    ///
    /// # 原先为什么是个陷阱
    ///
    /// 这个字段**没有** `rename`，所以 TOML 里只能写 `tls_enable`；
    /// 而**同一个结构体**里紧挨着的两个字段用的是**驼峰**：
    /// `verifyServerCert`（`:1529`）与 `trustedCaFile`（`:1535`）。
    ///
    /// ⇒ 用户照着同一段配置里的风格写 `tlsEnable = true`，
    ///   **serde 静默丢弃**（`deny_unknown_fields` 没开）⇒ `tls_enable` 保持 false
    ///   ⇒ TLS 压根没开。更糟的是它还会让 `verifyServerCert = true` **一起失效**：
    ///   `tls::connect_client` 在 `enable == false` 时**第一行就返回**，
    ///   `verify` 参数被完全忽略。
    ///
    /// # 实测（`tmp/audit7/b_independent/repro_b2_tls.py`，4/4）
    ///
    /// 抓链路首字节：
    ///
    /// | 配置 | 首字节 | 结论 |
    /// |---|---|---|
    /// | `[transport.tls] enable = true` | `17 16 03 01 …` | TLS ✓ |
    /// | **`tlsEnable = true` + `verifyServerCert = true`** | `00 02 …` | **明文** ✗ |
    /// | **只写 `verifyServerCert = true`** | `00 02 …` | **明文** ✗ |
    ///
    /// 明文里直接可见：
    /// ```text
    /// "privilege_key":"35a8601c28fa58a4fdb819c451100ae6"
    /// ```
    /// 而 `privilege_key = md5(token + timestamp)` ⇒ **可直接重放登录**。
    ///
    /// # 修法
    ///
    /// 加 `alias = "tlsEnable"` —— **只放宽、不收紧**：
    /// 原来正确的 `tls_enable` 照常工作，写驼峰的也能生效（并因此真正开启 TLS）。
    /// 这是纯增量的兼容改进，不改变任何既有配置的含义。
    #[serde(default, alias = "tlsEnable")]
    pub tls_enable: bool,

    /// TLS 的 SNI / 证书校验用的主机名，留空则用 `server_addr`。
    #[serde(default)]
    pub tls_server_name: String,

    /// 是否**校验服务端证书**（v0.5.6 修审计总报告 L16，低危）。
    ///
    /// 默认 **false** —— 与官方 frp 一致（`InsecureSkipVerify = true`），
    /// 改默认会破坏"官方 frpc 零配置直连"这条承诺。
    ///
    /// # 为什么提供这个开关
    ///
    /// 原先的问题不是"默认不安全"，而是**用户没有选择**：想校验也做不到。
    /// 同仓库的 `httpc`（OIDC 那边）默认就是校验的 —— 两套默认，
    /// 而其中最需要保护的那条（控制通道）反而无法切换。
    ///
    /// # 开启后要注意
    ///
    /// * 服务端用**公开 CA 签发的证书** ⇒ 直接可用；
    /// * 服务端用**自签证书** ⇒ 必须同时把该证书填进 `trustedCaFile`，
    ///   并让 `tlsServerName` 能对上证书里的名字；
    /// * **官方 frpc 不受影响**（它自己那个 `tls.enable` 不带这个字段）——
    ///   但反过来，你开了校验之后，**官方客户端连不上你的服务端**时
    ///   那不是 bug，是它不提供证书。
    #[serde(default, rename = "verifyServerCert")]
    pub tls_verify_server_cert: bool,

    /// 额外信任的 CA（PEM 路径），配合 `verifyServerCert = true` 用。
    ///
    /// 与官方 frp 的 `transport.tls.trustedCaFile` 同名同义。
    #[serde(default, rename = "trustedCaFile")]
    pub tls_trusted_ca_file: String,

    /// 客户端 TLS 证书（PEM，对应官方 `transport.tls.certFile`）。
    ///
    /// 仅用于服务端开启 `trustedCaFile`（mTLS）时出示身份。
    /// 与 `tls_key_file` 必须同时配置。
    #[serde(default, rename = "certFile")]
    pub tls_cert_file: String,

    /// 客户端 TLS 私钥（PEM，对应官方 `transport.tls.keyFile`）。
    #[serde(default, rename = "keyFile")]
    pub tls_key_file: String,

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

    /// 禁用控制台日志的 ANSI 颜色（对应 frp `log.disablePrintColor`）。
    ///
    /// 默认 false = 跟随官方行为（输出到**终端**才上色，写文件本来就不上色）；
    /// 置 true 后即使输出是终端也不上色。
    #[serde(default)]
    pub disable_print_color: bool,

    // ---- 传输层 ----
    /// 与服务端之间的传输协议：`tcp`（默认）或 `quic`，需与服务端一致。
    #[serde(default = "default_transport_protocol")]
    pub transport_protocol: String,
    /// 数据面加密（官方客户端级 `[transport].useEncryption`）。
    ///
    /// ★ 官方 `GetRealConn` 读的是 `pxy.baseCfg.Transport.UseEncryption`，
    /// `baseCfg` 就是 `ClientCommonConfig` —— 所以这个开关在**客户端级**，
    /// 作用于该客户端的**所有**代理。这一点用真实 e2e 验证过：
    /// 官方 frpc 0.71 只有写在 `[transport]` 下才真的加密数据面。
    #[serde(default, rename = "useEncryption", alias = "use_encryption")]
    pub use_encryption: bool,

    /// 数据面压缩（官方客户端级 `[transport].useCompression`）。同上。
    #[serde(default, rename = "useCompression", alias = "use_compression")]
    pub use_compression: bool,

    /// 连接服务端的超时（秒，对应 frp `dialServerTimeout`，官方默认 10）。
    ///
    /// 控制连接、以及 `tcpMux = false` 时每条新拨的工作连接都走它
    /// （官方 connector 的 `WithTimeout` 对两者同样生效）。
    /// KCP / QUIC 是另一条路，不受它影响（官方同）。
    ///
    /// `0` = 不限（跟随系统默认超时）—— 与项目其它超时项"0 = 关掉这项"
    /// 的约定一致。注意官方把 0 折算成默认 10（`EmptyOr`），这里不复刻该
    /// 折算：写 0 的意图就是明确关掉。
    #[serde(default = "default_dial_server_timeout")]
    pub dial_server_timeout: u64,

    /// 连接服务端时绑定的本地 IP（对应 frp `connectServerLocalIP`）。
    ///
    /// 多网卡 / 多出口的机器用它指定走哪块网卡。可以只写 IP
    /// （本地端口自动取 0），也可以写 `IP:端口`。官方注释：仅 TCP /
    /// WebSocket 协议有效、KCP 不支持 —— nfrp 同样只在 TCP 拨号路径生效。
    #[serde(default)]
    pub connect_server_local_ip: String,

    /// 到服务端的 TCP 连接的 keepalive 空闲时长（秒，对应 frp
    /// `dialServerKeepalive`，官方默认 7200）。
    ///
    /// 官方把它挂在拨号器上（`libnet.WithKeepAlive`），**控制连接与每条新拨的
    /// 工作连接**都生效（`tcp_mux = true` 时只有一条 yamux 载体）。nfrp 在
    /// 客户端 `dial_server`（main.rs）建连成功后给 socket 打开 `SO_KEEPALIVE`
    /// 并把空闲时长设为该值 —— 连接空闲这么久后内核开始探活，对端无响应则由
    /// 内核断开。
    ///
    /// `0` 表示**不打开**（内核默认行为）—— 项目约定"0 = 关掉这项"；
    /// 官方把 0 折算成 7200，这里不复刻。
    ///
    /// 只对 TCP / WebSocket 拨号生效；KCP / QUIC 是 UDP，没有 TCP keepalive。
    #[serde(default = "default_dial_server_keepalive")]
    pub dial_server_keepalive: u64,

    /// yamux 会话的保活间隔（秒，对应 frp `tcpMuxKeepaliveInterval`，官方默认 30）。
    ///
    /// 语义与落法见服务端 [`ServerConfig::tcp_mux_keepalive_interval`] 的说明
    /// （两边同源：官方在 client connector 与 server service 上设置同一个值）。
    /// 客户端侧的不同点：`tcp_mux = false` 时没有 yamux 会话，这一项无意义。
    ///
    /// `0` = 关闭看门狗（行为回到 v0.5.10 基线）。
    #[serde(default = "default_tcp_mux_keepalive_interval")]
    pub tcp_mux_keepalive_interval: u64,

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

    /// 额外配置文件（官方 frpc 的 `includes`）。
    ///
    /// # 官方语义（`pkg/config/load.go` 的 `LoadAdditionalClientConfigs`）
    ///
    /// 每一项是一个**路径或 glob 模式**。加载时逐个处理：
    ///
    /// 1. 取该路径的**目录**，遍历目录下所有普通文件；
    /// 2. 用 `filepath.Match` 拿「目录 + basename」与候选文件比对；
    /// 3. 命中的文件当作一份完整 frpc 配置解析，**只取它的 `proxies` 与
    ///    `visitors`**，追加到主配置的对应列表；
    /// 4. 各文件的其它字段（`serverAddr` / `token`…）**一律忽略**。
    ///
    /// ★ 第 4 点最容易误解：`includes` 不是"配置继承/覆盖"，而是**批量追加
    ///   代理定义**。用一个 `[proxies]` 都没写的文件配进 includes 等于什么也
    ///   不做。
    ///
    /// ```toml
    /// includes = ["conf.d/*.toml"]
    /// ```
    ///
    /// 相对路径按**主配置文件所在目录**解析 —— 官方用的是 `filepath.Dir(path)`，
    /// 这样 `--config /etc/nfrp/frpc.toml` 里的相对 includes 会落在
    /// `/etc/nfrp/` 下，符合直觉。
    #[serde(default, alias = "include", alias = "IncludeConfigFiles")]
    pub includes: Vec<String>,

    /// xtcp 打洞前用来探测公网映射地址的 STUN 服务器（官方 frpc 的
    /// `natHoleStunServer`）。
    ///
    /// ★ v0.6.6：官方先做 `nathole.Prepare([stun], ...)` 拿到自己的
    /// `XOR-MAPPED-ADDRESS`，再把它填进 `NatHoleVisitor.mapped_addrs`
    /// 交给服务端撮合。没有它只能靠"服务端看到的源地址"猜映射 —
    /// 锥形 NAT 下够用，对称 NAT / 多出口时会给错地址，打洞必然失败。
    ///
    /// ```toml
    /// natHoleStunServer = "stun.easyvoip.com:3478"
    /// ```
    ///
    /// 多个用逗号分隔，逐个尝试。留空 = 不做 STUN 探测（行为与之前一致）。
    #[serde(default, rename = "natHoleStunServer", alias = "nat_hole_stun_server")]
    pub nat_hole_stun_server: String,

    /// 解析服务端域名时用的 DNS 服务器（官方 frpc 的 `dnsServer`）。
    ///
    /// ★ v0.6.6：只影响**本进程**解析服务端地址时用哪个 DNS，
    /// 不动系统设置（官方注释："If this value is empty, the system default
    /// will be used"）。
    ///
    /// 典型场景：服务端域名只在内网 DNS 里有记录，而系统 resolver 指向公网。
    ///
    /// ```toml
    /// dnsServer = "10.0.0.2"        # 端口默认 53
    /// ```
    ///
    /// 必须是 **IP**（可带端口）。用主机名指 DNS 服务器需要先解析它 ——
    /// 那是鸡生蛋问题，这里直接拒绝而不是默默失败。
    #[serde(default, alias = "dnsServer", alias = "dns_server")]
    pub dns_server: String,

    /// 连服务端时走的出站代理（官方 frpc 的 `transport.proxyURL`）。
    ///
    /// ★ v0.6.6：支持 `http://` / `https://` / `socks5://` / `socks5h://`，
    /// 可带 `user:pass@`（HTTP Basic 或 SOCKS5 用户名密码）。
    ///
    /// 作用于**客户端 → 服务端**方向（控制连接与每条工作连接）——
    /// 出网受限、必须经公司代理才能出站的环境靠它。
    ///
    /// ```toml
    /// proxyURL = "socks5://user:pass@10.0.0.1:1080"
    /// ```
    ///
    /// 留空 = 直连（默认，行为与之前完全一致）。
    ///
    /// ⚠ KCP / QUIC 走 UDP，**不经过**这个代理（官方同样如此）——
    /// HTTP CONNECT / SOCKS5 是 TCP 隧道，接不住 UDP 报文。
    #[serde(default, alias = "proxyURL", alias = "proxy_url")]
    pub proxy_url: String,

    /// UDP 转发的单报文缓冲上限（官方 frpc 的 `udpPacketSize`）。
    ///
    /// 与服务端同名字段同义、同默认（65507，官方默认 1500 但要保持现状
    /// 以免截断现有用户的大报文）。详见 `ServerConfig::udp_packet_size`。
    #[serde(
        default = "default_udp_packet_size",
        rename = "udpPacketSize",
        alias = "udp_packet_size"
    )]
    pub udp_packet_size: usize,

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
            nlink: crate::nlink::ClientNLinkConfig::default(),
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
            // ★ v0.5.6（L16）：默认**不校验**（与官方 frp 一致，保互通）；
            //   想要校验的用户显式开 verifyServerCert。
            tls_verify_server_cert: false,
            tls_trusted_ca_file: String::new(),
            tls_cert_file: String::new(),
            tls_key_file: String::new(),
            tls_custom_first_byte: true,
            log_level: default_log_level(),
            log_to: String::new(),
            max_days: default_log_max_days(),
            disable_print_color: false,
            transport_protocol: default_transport_protocol(),
            dial_server_timeout: default_dial_server_timeout(),
            connect_server_local_ip: String::new(),
            dial_server_keepalive: default_dial_server_keepalive(),
            tcp_mux_keepalive_interval: default_tcp_mux_keepalive_interval(),
            p2p_port: None,
            p2p_enable: true,
            xtcp_transport: default_xtcp_transport(),
            xtcp_port_predict: true,
            xtcp_predict_window: default_predict_window(),
            private_caps: true,
            proxies: Vec::new(),
            visitors: Vec::new(),
            includes: Vec::new(),
            udp_packet_size: default_udp_packet_size(),
            proxy_url: String::new(),
            dns_server: String::new(),
            use_encryption: false,
            use_compression: false,
            nat_hole_stun_server: String::new(),
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

/// Web 管理界面 TLS 配置（`[webServer.tls]`）。
///
/// 官方 frp 在服务端面板（frps `webServer`）和客户端本地面板（frpc
/// `webServer`）都接受同一组字段。NFrp 旧版只识别但明确报“未实现”；从
/// v0.6.7 起真正加载证书并启动 HTTPS listener。
///
/// `trustedCaFile` / `serverName` 也一并接受，保证官方 TOML 能直接解析；
/// 当前 Web 面板不做客户端证书认证，因此这两个字段不参与服务端监听。
#[derive(Clone, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct WebTlsConfig {
    /// PEM 证书链文件。
    #[serde(rename = "certFile", alias = "cert_file")]
    pub cert_file: String,

    /// PEM 私钥文件（PKCS#8 / PKCS#1 / SEC1）。
    #[serde(rename = "keyFile", alias = "key_file")]
    pub key_file: String,

    /// 可选 CA；仅为官方配置兼容保留。
    #[serde(rename = "trustedCaFile", alias = "trusted_ca_file")]
    pub trusted_ca_file: String,

    /// 可选证书名；仅为官方配置兼容保留。
    #[serde(rename = "serverName", alias = "server_name")]
    pub server_name: String,
}

impl WebTlsConfig {
    /// 是否配置了 HTTPS。只有 cert/key 都非空才算启用。
    pub fn is_enabled(&self) -> bool {
        !self.cert_file.trim().is_empty() || !self.key_file.trim().is_empty()
    }

    /// 校验 cert/key 必须成对出现。返回 `(cert, key)` 供加载器直接使用。
    pub fn files(&self) -> Result<Option<(&str, &str)>> {
        let cert = self.cert_file.trim();
        let key = self.key_file.trim();
        match (cert.is_empty(), key.is_empty()) {
            (true, true) => Ok(None),
            (false, false) => Ok(Some((cert, key))),
            _ => Err(crate::error::Error::Protocol(
                "webServer.tls.certFile 与 webServer.tls.keyFile 必须同时配置；\
                 当前只配置了其中一个"
                    .to_string(),
            )),
        }
    }
}

impl std::fmt::Debug for WebTlsConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WebTlsConfig")
            .field("cert_file", &self.cert_file)
            .field("key_file", &self.key_file)
            .field("trusted_ca_file", &self.trusted_ca_file)
            .field("server_name", &self.server_name)
            .finish()
    }
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
    #[serde(default, alias = "assetsDir", alias = "AssetsDir", alias = "ASSETSDIR")]
    pub assets_dir: String,

    /// pprof 性能分析开关（官方 frpc 的 `webServer.pprofEnable`）。
    ///
    /// 与官方路径一致：`/debug/pprof/profile?seconds=N`。实现是 Unix-only
    /// （pprof-rs 依赖 perf 信号与 `ucontext_t`）；Windows 上端点存在但明确
    /// 返回 501，不会静默成功或拖垮整个客户端构建。
    #[serde(
        default,
        alias = "pprofEnable",
        alias = "PprofEnable",
        alias = "PPROFENABLE",
        alias = "pprof_enable"
    )]
    pub pprof_enable: bool,

    /// 面板 HTTPS（官方 frps / frpc 的 `webServer.tls`）。
    ///
    /// 配置 `certFile` + `keyFile` 后，面板直接以 TLS 监听；HTTP 不再被
    /// 接受。客户端本地 Web 和 frps dashboard 共用这一份配置。
    #[serde(default)]
    pub tls: WebTlsConfig,
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
            .field("tls", &self.tls)
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
            tls: WebTlsConfig::default(),
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
        let mut cfg = parse_client(&raw)?;
        // ★ v0.6.5：`includes` 合并（官方 `LoadAdditionalClientConfigs`）
        cfg.merge_includes(path.as_ref())?;
        Ok(cfg)
    }

    /// 把 `includes` 里各文件的 `proxies` / `visitors` 追加进本配置。
    ///
    /// 语义严格对齐官方 `pkg/config/load.go`：
    /// * 每项是路径或 glob（`*` / `?` 由 [`glob_match`] 处理）；
    /// * 只取**目录**下的普通文件参与匹配；
    /// * 命中文件只贡献 `proxies` 与 `visitors`，其它字段全部忽略；
    /// * 相对路径以**主配置文件所在目录**为基准。
    ///
    /// 空列表时直接返回，不碰文件系统 —— 绝大多数部署不走这个分支。
    pub fn merge_includes(&mut self, main_path: &Path) -> Result<()> {
        if self.includes.is_empty() {
            return Ok(());
        }

        // 主配置所在目录；拿不到就用当前目录（比如传的是相对文件名）
        let base = main_path
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .map(|p| p.to_path_buf())
            .unwrap_or_else(|| PathBuf::from("."));

        // 收集所有待追加的代理 / 访客
        let mut extra_proxies: Vec<ProxyConfig> = Vec::new();
        let mut extra_visitors: Vec<VisitorConfig> = Vec::new();

        for pattern in &self.includes {
            let full = if Path::new(pattern).is_absolute() {
                PathBuf::from(pattern)
            } else {
                base.join(pattern)
            };

            // 目录与 basename（glob 只作用在文件名上，与官方 filepath.Match 一致）
            let dir = full
                .parent()
                .filter(|p| !p.as_os_str().is_empty())
                .map(|p| p.to_path_buf())
                .unwrap_or_else(|| base.clone());
            let name_pat = full
                .file_name()
                .map(|s| s.to_string_lossy().into_owned())
                .unwrap_or_default();

            if name_pat.is_empty() {
                return Err(crate::error::Error::Protocol(format!(
                    "includes 里的 [{pattern}] 没有文件名部分"
                )));
            }

            let rd = match std::fs::read_dir(&dir) {
                Ok(r) => r,
                Err(e) => {
                    return Err(crate::error::Error::Protocol(format!(
                        "includes 里的 [{pattern}] 打不开目录 {}：{e}",
                        dir.display()
                    )))
                }
            };

            // 目录内容排序后处理：让"哪个文件先加载"是确定的，
            // 否则两台机器上同名代理的报错顺序都可能不同。
            let mut names: Vec<String> = Vec::new();
            for ent in rd.flatten() {
                if ent.path().is_file() {
                    names.push(ent.file_name().to_string_lossy().into_owned());
                }
            }
            names.sort();

            for fname in names {
                if !glob_match(&name_pat, &fname) {
                    continue;
                }
                let fpath = dir.join(&fname);
                let raw = std::fs::read_to_string(&fpath).map_err(|e| {
                    crate::error::Error::Protocol(format!(
                        "读取 includes 文件 {} 失败：{e}",
                        fpath.display()
                    ))
                })?;
                let sub = parse_include_file(&raw).map_err(|e| {
                    crate::error::Error::Protocol(format!(
                        "解析 includes 文件 {} 失败：{e}",
                        fpath.display()
                    ))
                })?;
                extra_proxies.extend(sub.proxies);
                extra_visitors.extend(sub.visitors);
            }
        }

        self.proxies.append(&mut extra_proxies);
        self.visitors.append(&mut extra_visitors);

        // 名字必须唯一 —— 服务端按 name 定位代理，重名会让"踢掉一个"
        // 变成"随机踢掉其中一个"，排查起来极其费劲。
        let mut seen: std::collections::HashSet<&str> = std::collections::HashSet::new();
        for p in &self.proxies {
            if !seen.insert(p.name.as_str()) {
                return Err(crate::error::Error::Protocol(format!(
                    "代理名 [{}] 重复（主配置与 includes 合并后）",
                    p.name
                )));
            }
        }
        let mut seen_v: std::collections::HashSet<&str> = std::collections::HashSet::new();
        for v in &self.visitors {
            if !seen_v.insert(v.name.as_str()) {
                return Err(crate::error::Error::Protocol(format!(
                    "访客名 [{}] 重复（主配置与 includes 合并后）",
                    v.name
                )));
            }
        }

        Ok(())
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

/// UDP 单报文缓冲的默认上限：65507（UDP over IPv4 的最大载荷）。
///
/// 官方 frp 默认 1500，这里**故意不同** —— 见字段文档里"为什么默认不同"。
pub const MAX_UDP_PACKET_SIZE: usize = 65507;

fn default_udp_packet_size() -> usize {
    MAX_UDP_PACKET_SIZE
}

/// 官方 frps 的默认值：168 小时（7 天）。
fn default_nathole_analysis_reserve_hours() -> u64 {
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

/// visitor 本地监听口的默认绑定地址（v0.5.6 修审计总报告 L1）。
///
/// 与**服务端**的 [`DEFAULT_BIND_ADDR`]（`0.0.0.0`）刻意不同：
/// 服务端是"对外提供服务"，默认全网卡有道理；而 visitor 的监听口是
/// **本机入口**，默认对外没有必要。
///
/// 这个值同时与 INI 解析路径（`frp_legacy.rs`）和官方示例配置保持一致 ——
/// 在此之前 TOML 路径用的是 `0.0.0.0`，导致同一份配置在两个解析路径下
/// 得到不同的监听范围。
fn default_visitor_bind_addr() -> String {
    "127.0.0.1".to_string()
}

/// 登录时间戳默认允许的偏差（秒），v0.5.6 修审计总报告 M3。
/// 300 秒足够容纳常见的时钟漂移与网络延迟，同时把"录下一条 Login 报文
/// 就能无限期重放"压到 5 分钟窗口。官方 frpc 发的是当前时间，**零感知**。
fn default_max_clock_skew() -> u64 {
    300
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
/// 客户端连接服务端的默认超时（官方 `dialServerTimeout` 默认 10 秒）。
fn default_dial_server_timeout() -> u64 {
    10
}
/// 服务端等"用户连接配工作连接"的默认超时（官方 `userConnTimeout` 默认 10 秒）。
fn default_user_conn_timeout() -> u64 {
    10
}
/// 客户端拨号 TCP 连接的 keepalive 空闲时长（官方 `dialServerKeepalive` 默认 7200 秒）。
fn default_dial_server_keepalive() -> u64 {
    7200
}
/// yamux 会话保活间隔（官方 `tcpMuxKeepaliveInterval` 默认 30 秒）。
fn default_tcp_mux_keepalive_interval() -> u64 {
    30
}
/// 服务端主端口 TCP 连接的 keepalive 空闲时长（官方 `tcpKeepalive` 默认 7200 秒）。
fn default_tcp_keepalive() -> u64 {
    7200
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
///
/// ---
///
/// shell 风格的通配匹配，语义对齐 Go 的 `filepath.Match`（只处理文件名，不含路径）。
///
/// 支持：
/// * `*` —— 匹配任意长度（含空）的字符序列，**不跨** `/`（这里只看文件名，不含 `/`）；
/// * `?` —— 匹配恰好一个字符；
/// * `[...]` —— 字符集（`[abc]` / `[a-z]` / `[^abc]`），与 Go 一致；
/// * 其余字符按字面匹配。
///
/// 为什么不引 `glob` crate：这里只需要"文件名级"匹配（官方也是
/// `filepath.Match(目录+basename, 候选文件)`，跨目录的递归由调用方遍历完成），
/// 为了这一个函数拉一个新依赖不划算 —— 而且自己写才能精确复刻 Go 的边界行为
/// （比如 `*` 不匹配 `/`、`[` 未闭合时按字面处理）。
fn glob_match(pattern: &str, name: &str) -> bool {
    let p: Vec<char> = pattern.chars().collect();
    let n: Vec<char> = name.chars().collect();
    glob_inner(&p, &n)
}

/// 解析一份 `includes` 引用的配置文件。
///
/// # 为什么不能直接用 [`parse_client`]
///
/// `parse_client` 对主配置要求 `serverAddr` 必填（合理的：客户端总得知道连
/// 哪儿）。但 `includes` 文件**通常只写 `[[proxies]]`** —— 按官方语义它的
/// 其它字段本来就该被忽略（`LoadAdditionalClientConfigs` 只取
/// `cfg.Proxies` / `cfg.Visitors`）。
///
/// 所以这里先补一个占位 `serverAddr` 再走正常解析，解析完把占位值连同
/// 其它字段一起丢掉 —— 调用方只取 `proxies` / `visitors`。
///
/// 用"补占位"而不是"另写一套宽松解析器"：`parse_client` 里还有
/// `enabled` 过滤、未实现类型拒绝、结构化校验等一整套逻辑，
/// 复制一份迟早两边走偏（本项目已经吃过"同一语义写两遍只加固一遍"的亏）。
fn parse_include_file(raw: &str) -> Result<ClientConfig> {
    // legacy INI 的 includes 由它自己的 `[common]` 段承载，这里只处理 TOML。
    if crate::frp_legacy::is_legacy_ini(raw) {
        return parse_client(raw);
    }

    let mut value: toml::Value = toml::from_str(raw)?;
    let has_server = value.as_table().is_some_and(|t| {
        t.keys()
            .any(|k| k.eq_ignore_ascii_case("server_addr") || k.eq_ignore_ascii_case("serverAddr"))
    });
    if !has_server {
        if let Some(t) = value.as_table_mut() {
            // 占位值只为过 serde 的必填校验，解析完不会有人用它
            t.insert(
                "server_addr".to_string(),
                toml::Value::String("include-placeholder".to_string()),
            );
        }
    }
    let text = toml::to_string(&value)?;
    parse_client(&text)
}

fn glob_inner(p: &[char], n: &[char]) -> bool {
    let (mut pi, mut ni) = (0usize, 0usize);
    // 记录最近一个 `*` 的位置，用于失配回溯
    let mut star: Option<(usize, usize)> = None;

    while ni < n.len() {
        if pi < p.len() {
            match p[pi] {
                '*' => {
                    // 连续的多个 `*` 视同一个
                    while pi + 1 < p.len() && p[pi + 1] == '*' {
                        pi += 1;
                    }
                    star = Some((pi, ni));
                    pi += 1;
                    continue;
                }
                '?' => {
                    pi += 1;
                    ni += 1;
                    continue;
                }
                '[' => {
                    if let Some((matched, next_pi)) = match_class(p, pi, n[ni]) {
                        if matched {
                            pi = next_pi;
                            ni += 1;
                            continue;
                        }
                    } else if p[pi] == n[ni] {
                        // `[` 未闭合：Go 报 ErrBadPattern，这里按字面处理（更宽容）
                        pi += 1;
                        ni += 1;
                        continue;
                    }
                }
                c => {
                    if c == n[ni] {
                        pi += 1;
                        ni += 1;
                        continue;
                    }
                }
            }
        }

        // 走到这里说明当前字符不匹配：回溯到上一个 `*`，让它多吃一个字符
        match star {
            Some((sp, sn)) => {
                pi = sp + 1;
                ni = sn + 1;
                star = Some((sp, sn + 1));
            }
            None => return false,
        }
    }

    // 名字吃完后，模式剩下的必须全是 `*`
    while pi < p.len() && p[pi] == '*' {
        pi += 1;
    }
    pi == p.len()
}

/// 尝试匹配一个 `[...]` 字符集。
///
/// 返回 `Some((是否匹配, 字符集之后的模式下标))`；
/// 返回 `None` 表示这个 `[` 没有闭合（调用方按字面处理）。
fn match_class(p: &[char], start: usize, c: char) -> Option<(bool, usize)> {
    debug_assert_eq!(p[start], '[');
    let mut i = start + 1;
    let negate = i < p.len() && (p[i] == '^' || p[i] == '!');
    if negate {
        i += 1;
    }
    let mut hit = false;
    let mut first = true;
    while i < p.len() {
        // `]` 作为字符集第一个字符时是字面量（Go 的行为）
        if p[i] == ']' && !first {
            return Some((hit != negate, i + 1));
        }
        first = false;

        // 区间 a-z
        if i + 2 < p.len() && p[i + 1] == '-' && p[i + 2] != ']' {
            let (lo, hi) = (p[i], p[i + 2]);
            if lo <= c && c <= hi {
                hit = true;
            }
            i += 3;
            continue;
        }
        if p[i] == c {
            hit = true;
        }
        i += 1;
    }
    None
}
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
    // ① 解码类检查（官方在解码阶段就报错的项）：必须跑在 enabled 过滤**之前**
    //    —— `enabled = false` 不能把未知类型变成合法（官方同样如此）。
    reject_unimplemented_types(&cfg)?;
    // ② `enabled = false` 的代理 / 访客在这里摘掉，之后完全等同于"没配"
    //    （官方 `pkg/config/load.go` 的 `FilterClientConfigurers`，对代理和
    //    访客都过滤）。INI 路径没有 enabled 键，这两行是无操作。
    cfg.proxies.retain(|p| p.enabled.unwrap_or(true));
    cfg.visitors.retain(|v| v.enabled.unwrap_or(true));
    // ③ 结构化校验（官方在过滤**之后**做）：tcpmux 约束 + `annotations`。
    //    放这里而不是 ① 里，是为了让"先禁用、之后再补全"的配置块能留在文件里。
    for p in &cfg.proxies {
        reject_structured_proxy(p)?;
    }
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
/// 访客类代理的类型清单（**唯一真源** —— 判定请用 [`is_visitor_type`]）。
pub const SUPPORTED_VISITOR_TYPES: &[&str] = &["stcp", "xtcp", "sudp"];

/// **唯一真源**：这个代理类型是不是"访客类"（v0.5.6 修审计总报告 H3）。
///
/// # 为什么必须抽出来
///
/// `sudp` 与 `stcp` 走**同一条 visitor 注册路径**，项目在**三处**都把它
/// 归为访客类：
///
/// | 位置 | 定义 |
/// |---|---|
/// | 本文件的 [`SUPPORTED_VISITOR_TYPES`] | `["stcp","xtcp","sudp"]` |
/// | `frp_legacy.rs` 的 `LEGACY_VISITOR_TYPES` | `["stcp","xtcp","sudp"]` |
/// | `server/src/serve.rs` 的注册分派 | `"sudp" => register_visitor_proxy(...)` |
///
/// 但 RBAC 的 `allowVisitors` 判定**就地硬编码了 `"stcp" | "xtcp"`、漏了 `sudp`**
/// ⇒ 管理员配 `allowVisitors = false` 之后，攻击者把 `type` 换成 `"sudp"`
/// 即可完整绕过该限制。
///
/// 而且危害被放大：`sudp` **不占公网端口**，因此不受 `allowPorts` /
/// `portRange` 约束 ⇒ `allowVisitors` 是管理员**唯一**能关掉它的开关。
///
/// ⇒ 与 `has_dashboard_creds` 同理：**同一判定各写一遍，就一定会漂移**。
///   凡是"某类型属不属于某集合"的判断，一律走这里。
pub fn is_visitor_type(ty: &str) -> bool {
    let t = ty.trim().to_ascii_lowercase();
    SUPPORTED_VISITOR_TYPES.iter().any(|v| *v == t)
}

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

/// 单条代理的**解码类**自检：类型 + 插件。
///
/// "解码类" = 官方在 JSON 解码阶段就会报错的项（`pkg/config/v1/decode.go` 的
/// `unknown proxy type` / `unknown plugin type`）。因此它在 [`parse_client`] 里
/// 必须跑在 `enabled = false` **过滤之前** —— 官方同样如此：解码先于
/// `FilterClientConfigurers`，`enabled = false` 不能把未知类型变成合法。
fn reject_decoded_proxy(p: &ProxyConfig) -> Result<()> {
    if !SUPPORTED_PROXY_TYPES.contains(&p.proxy_type.as_str()) {
        return Err(crate::error::Error::Protocol(format!(
            "代理 [{}] 的类型 {:?} 不受支持（NFrp 实现了 {}）",
            p.name,
            p.proxy_type,
            SUPPORTED_PROXY_TYPES.join(" / ")
        )));
    }
    reject_unimplemented_plugin(p)
}

/// 单条代理的**结构化**校验：tcpmux 约束 + 注解。
///
/// 与 [`reject_decoded_proxy`] 分开是因为二者在官方流程里的**时机不同**：
/// 解码检查在 enabled 过滤**前**，结构化校验（`ValidateClientConfig` 一族）
/// 在过滤**后** —— 所以"禁用但暂时不完整"的配置块不该被这两项拦住。
/// 见 [`parse_client`] 里的执行顺序。
fn reject_structured_proxy(p: &ProxyConfig) -> Result<()> {
    reject_bad_tcpmux(p)?;
    reject_bad_annotations(p)
}

/// 单条代理的完整自检（类型 + 插件 + tcpmux + 注解），远程下发路径共用。
fn reject_bad_proxy(p: &ProxyConfig) -> Result<()> {
    reject_decoded_proxy(p)?;
    reject_structured_proxy(p)
}

/// 解析路径的**解码类**检查（未知代理 / 访客 / 插件类型）。
fn reject_unimplemented_types(cfg: &ClientConfig) -> Result<()> {
    for p in &cfg.proxies {
        reject_decoded_proxy(p)?;
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

        // ★★ v0.5.5 修（第四轮 F1）：**远程下发一律不允许携带插件**。
        //
        // 这是上面那条回环检查的**完整绕过**，而且是第四轮实测打出来的：
        //
        // * 上面的检查有个前提 —— `local_addr` 非空。而插件路径**根本不需要
        //   `local_addr`**：`local_addr=""` + `plugin="http_proxy"` 时，
        //   那段回环检查被 `if !p.local_addr.trim().is_empty()` 整个跳过；
        // * 黑名单只列了 4 个 `plugin_local_*` 字段，**`plugin` 这个能力开关
        //   本身没进判定**，`plugin_user` / `plugin_passwd` 也没管。
        //
        // 净效果：服务端（或任何能调面板 `/api/proxies/add` 的人）下发一条
        // `plugin="http_proxy"` / `"socks5"` 的代理，客户端就把那个公网端口
        // 变成**开放正向代理** —— 攻击者可现指定任意目标，既能内网横向，
        // 也能拿客户端当跳板隐藏来源（出站源 IP 是客户端）。
        //
        // 实测对照（`tmp/audit4-verify-F1b.py`，目标 192.168.3.15:17912）：
        //
        // | 下发形态 | 结果 | 可达 |
        // |---|---|---|
        // | 普通 tcp + `local_addr=192.168.3.15:17912` | HTTP 400 拒绝 | 不可达 |
        // | `plugin=http_proxy` + `local_addr=""` | HTTP 200 放行 | **读到数据** |
        // | `plugin=socks5` + `local_addr=""` | HTTP 200 放行 | **读到数据** |
        //
        // ★ 为什么是"一律拒绝"而不是"只拒绝无鉴权的插件"：
        //   插件的正当用途是**本机用户自己**决定"这台机器要对外提供什么能力"
        //   （静态站点、SOCKS 代理、TLS 终结……）。这是**知情选择**，
        //   本机配置文件里照旧完全可用。但**服务端不该能远程改变客户端的性质**
        //   —— 这与 `local_addr` 是同一个理由，而且更强：`local_addr` 只是
        //   "连哪里"，`plugin` 是"变成什么"。
        //
        // ★ 沿用 H4 的教训：**用允许清单，不继续扩黑名单**（黑名单必然漏下一个字段）。
        //
        // ★★ v0.5.6 修（审计总报告 L6，低危）：**补上 `plugin_request_headers`**。
        //
        // 上面这段注释写着"用允许清单、不继续扩黑名单"，但代码实际是一个
        // **5 字段枚举** —— 恰好漏了 `plugin_request_headers`
        // （一个 `BTreeMap<String,String>`，可注入任意请求头 + CRLF）。
        //
        // ★ 与"注释声称用允许清单、实际是枚举"这个不符同时出现 ——
        //   审计报告把"注释与实现不符"列为**高效漏洞信号源**，这里正是一例。
        //
        // ★ 可利用性：`http_relay.rs` 的 `strip_crlf` 对键和值都做了过滤
        //   （注释也点明了该字段远程可控），所以**不能注入 CRLF**；
        //   残余能力是"给内网服务加任意请求头"（如 `X-Forwarded-For` 伪造、
        //   绕过后端的 IP 白名单）。危害低于 F1，故定 Low —— 但它
        //   **仍然属于"服务端不该能远程改变客户端行为"**的同一类，
        //   且既然这段代码的意图是"一律拒绝插件相关字段"，漏一个就是漏。
        let mut caps: Vec<&str> = Vec::new();
        if !p.plugin.trim().is_empty() {
            caps.push("plugin");
        }
        if !p.plugin_user.trim().is_empty() {
            caps.push("pluginUser");
        }
        if !p.plugin_passwd.trim().is_empty() {
            caps.push("pluginPasswd");
        }
        if !p.plugin_host_header_rewrite.trim().is_empty() {
            caps.push("pluginHostHeaderRewrite");
        }
        if !p.plugin_strip_prefix.trim().is_empty() {
            caps.push("pluginStripPrefix");
        }
        // ★ v0.5.6（L6）：这一项原先漏了
        if !p.plugin_request_headers.is_empty() {
            caps.push("pluginRequestHeaders");
        }
        if !caps.is_empty() {
            return Err(crate::error::Error::Protocol(format!(
                "代理 [{}] 来自远程下发，不允许携带插件相关字段（{}）—— \
                 插件决定客户端**变成什么**（本地文件服务 / 正向代理 / 私钥终结），\
                 只能由本机配置文件指定。远程下发要连内网服务，请用普通 tcp/http 代理。",
                p.name,
                caps.join(" / ")
            )));
        }

        // ★★ v0.5.8 修（第七轮审计 **E7 附带发现**，低危）：**非插件代理的
        //    `local_addr` 不能为空**。
        //
        // # 原先为什么是个"假绿灯"
        //
        // 上面那段回环检查有个前提 —— `if !p.local_addr.trim().is_empty()`。
        // 而 `ProxyConfig` 里**没有** `localIP` / `localPort` 字段
        // （只有合并式的 `local_addr`），所以两段式写法会被 serde **静默丢弃**。
        // ⇒ 下发 `{"local_addr":"", "localIP":"10.0.0.5", "localPort":80}`
        //   可以通过回环检查（因为 `local_addr` 是空串），
        //   面板回 **200「代理已生效」**、公网端口**真的被占上**、
        //   `/api/status` 里也显示"已生效"……
        //   **但 `local_addr` 为空 ⇒ 这条代理连不上任何地方，每条连接必然失败。**
        //
        // 实测（`tmp/audit7/e/localip_bypass_probe.py`）：
        // * `localIP`+`localPort`（**无** `local_addr`）⇒ 400「missing field local_addr」
        //   （serde 的 required 检查挡住了）
        // * **`local_addr:""` + `localIP`+`localPort`** ⇒ **200 已生效**，但代理不可用
        //
        // 而且我用**诱饵服务**做过决定性判定（`tmp/audit7/e/e71_verify_bypass.py`）：
        // 两段式字段确实被丢弃、**没有**真的去连 `10.0.0.5` ——
        // 所以这**不是 SSRF**，只是"**假绿灯**"：面板说成功，实际拿到的是一条
        // 必然失败的隧道。
        //
        // ★ 与第六轮 F-1 的「`--check` / `frpc verify` 假绿灯」是**同一族问题**，
        //   只是这次发生在**运行期**（面板写接口返回成功）而不是预检期。
        //
        // # 为什么现在才补
        //
        // 插件代理**不看** `local_addr`（工作连接交给插件），所以不能一刀切
        // —— 那会把正当的插件用法（虽然远程下发已禁插件，但本机配置仍需放行）
        // 一起拒掉。这里显式排除插件情形。
        if p.plugin.trim().is_empty() && p.local_addr.trim().is_empty() {
            return Err(crate::error::Error::Protocol(format!(
                "代理 [{}] 来自远程下发，但 `local_addr` 是空的 —— \
                 这条代理连不上任何地方，客户端会把它注册上去（面板显示「已生效」）\
                 然后每条连接都失败。请填上内网服务地址（如 `127.0.0.1:8080`）。\
                 ★ 注意字段名是**合并式**的 `local_addr`（`ip:port`）：\
                 官方的 `localIP` + `localPort` 两段式在**远程下发**里不被接受，\
                 写了也会被静默丢弃。",
                p.name
            )));
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
        // ★★ v0.5.8 修（第七轮审计 **E-2**，中危）：**方括号必须紧跟着 port 冒号**，
        //    不能"取第一个 `]` 之前就算主机"。
        //
        // # 原先为什么错了（check-vs-use）
        //
        // 原先写的是 `rest.split(']').next()` —— 对 `[::1].evil.com:PORT`
        // 会取到 `::1`，于是：
        //   * **判据**看到 `::1` ⇒ `is_loopback_host` 为真 ⇒ **放行**；
        //   * **实际连接**（`client/src/main.rs:1472`）用的却是**原始串**
        //     `resolve_addr("[::1].evil.com:PORT")` ⇒ **走 DNS**。
        //
        // ⇒ 校验器看的是 A 串、实际连的是 B 串。域名一旦可解析，
        //   连到哪里就由**域名持有者**决定 —— 这正是 H4 要封的服务端可控 SSRF。
        //
        // # 实测（`tmp/audit7/e_independent/repro_e2_decisive.py`，7/7）
        //
        // 用 v6 诱饵 + 一个 DNS 查不到的名字做区分：
        //
        // | 下发值 | 判据 | 实际转发 |
        // |---|---|---|
        // | `[::1]:<P>` | 接受 | **成功**（收到 `V6-DECOY`）|
        // | **`[::1].nonexistent-….local:<P>`** | **接受** | **失败**（v6 命中 0）|
        //
        // 若连接用的也是切片后的 `::1`，第二条**必应成功** —— 差异即是铁证。
        // 客户端日志同时给出直接证据：
        // `解析内网地址 [::1].nonexistent-nfrp-e2-probe.local:50458 失败`。
        //
        // # 修法
        //
        // **方括号形式必须整段就是 `[host]:port`**：`]` 之后只能是
        // 「空」或「:数字端口」。否则**不认这种写法**，整串当主机
        // ⇒ 解析不出 IP ⇒ `is_loopback_host` 从严判 `false` ⇒ 拒绝。
        //
        // 这样"判据看到的主机"与"连接用的主机"**强制一致**：
        // 要么整串被认作 `[host]:port`（那就连 host），要么整串当主机（那就拒）。
        let (host, after) = match rest.split_once(']') {
            Some(v) => v,
            // 有 `[` 没有 `]` ⇒ 不是合法的 `[host]:port` ⇒ 整串当主机（从严）
            None => return a,
        };
        let tail_ok = after.is_empty()
            || (after.starts_with(':')
                && after[1..].bytes().all(|b| b.is_ascii_digit())
                && !after[1..].is_empty());
        if tail_ok {
            return host;
        }
        // `]` 之后还有别的东西（如 `[::1].evil.com:80`）⇒ 不是回环写法，从严
        return a;
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
/// 接受 `127.0.0.0/8`、`::1`。**不接受** `0.0.0.0`（那是"监听全部"，
/// 不是"连本机"），也不接受任何解析不出 IP 的名字 —— 名字解析到哪个地址
/// 取决于本机 hosts 与 DNS，而且解析结果在连接时才确定，判据不能靠它。
///
/// ★★ v0.5.8 修（第七轮审计 **E-1**，高危）：**不再无条件放行 `localhost`**。
///
/// # 原先为什么错了
///
/// 这个函数原先在 IP 解析**之前**无条件返回 true：
///
/// ```ignore
/// if h.eq_ignore_ascii_case("localhost") {
///     return true;          // ← 先于 IP 解析，无条件放行
/// }
/// ```
///
/// 而**同一个仓库**里 `common/src/util.rs:535` 的 `is_loopback_addr()`
/// 对 `localhost` 的结论**正好相反**，注释还写明了理由：
///
/// > `localhost` 也按**非回环**处理：它解析到哪个地址取决于本机 hosts 与 DNS，
/// > 解析到非回环地址时就是一个对外端口，**不能靠名字赌**。
///
/// ⇒ **同一语义、两套结论相反的实现**，而守卫**远程下发白名单**
/// （见本文件 `validate_remote_proxy` 里的 H4 检查）的是**弱的那套**。
///
/// # 实测后果（`tmp/audit7/e_independent/repro_e1_localhost.py`，9/9）
///
/// 在 `127.0.0.1:<P>` 与 `[::1]:<P>` 上各起一个 banner 诱饵（同端口号），
/// 再远程下发三种 `local_addr`：
///
/// | 下发值 | 面板响应 | 实际命中 |
/// |---|---|---|
/// | `127.0.0.1:<P>` | 200 接受 | **v4** 诱饵 ✓（正对照） |
/// | `10.0.0.5:<P>` | **400 拒绝** | —（H4 生效） |
/// | **`localhost:<P>`** | **200 接受** | **v4=0 / v6=1** ⇒ 命中了 **v6** 端点 |
///
/// ⇒ 用户配的是"连本机 v4 服务"，实际流量送到了**另一个地址族**的端点。
/// 这证明判据**放行了一个它无法保证指向的名字** —— 只要本机 hosts 或 DNS
/// 把 `localhost` 指到别处，流量就跟着去别处。这正是 H4 要封的
/// 「服务端可控 SSRF」：`local_addr` 决定客户端**往哪里连**。
///
/// # 修法
///
/// 与 `util.rs` 的口径**统一**：`localhost` 一律当作**非回环**（从严）。
/// 想连本机就写 `127.0.0.1` 或 `::1` —— 那是**明确的、不受 hosts/DNS 影响**的写法。
///
/// ★ 兼容性：远程下发（面板"添加代理"）的正常用法本来就是填 `127.0.0.1:xxxx`；
///   写 `localhost` 的人需要改成 `127.0.0.1`。本机配置文件里的 `localhost`
///   **不受影响**（这条检查只作用于远程下发路径）。
fn is_loopback_host(host: &str) -> bool {
    let h = host.trim();
    // ★ E-1：`localhost` 从严处理 —— 解析结果不受控，不能靠名字赌。
    //   （原先这里无条件 return true，与 `util::is_loopback_addr` 的结论相反。）
    match h.parse::<std::net::IpAddr>() {
        Ok(std::net::IpAddr::V4(v4)) => v4.is_loopback(),
        Ok(std::net::IpAddr::V6(v6)) => v6.is_loopback(),
        // 解析不出（域名，含 `localhost`）⇒ 从严当作"非本机"
        Err(_) => false,
    }
}

/// `annotations` 校验，对齐官方 `ValidateAnnotations`（`pkg/config/v1/validation/proxy.go:243`）。
///
/// 规则（与官方逐条对应）：
/// 1. 键先**整体转小写**再校验（官方 `validation.IsQualifiedName(strings.ToLower(k))`），
///    所以键里写大写字母不会报错；
/// 2. 键是 Kubernetes 风格的 qualified name：`[前缀/]名字` —— 前缀（可选）是
///    ≤253 字符的 DNS 子域，名字 ≤63 字符、以字母数字开头结尾、中间可含 `- _ .`；
///    多于一个 `/` 不合法；
/// 3. 全部键值对的**总字节数**（键 + 值）不超过 256 KiB（官方
///    `TotalAnnotationSizeLimitB = 256 * (1 << 10)`）。
///
/// 官方 frps 对随 `NewProxy` 收到的注解只存不查（`server/` 下没有任何读取点，
/// 0.71 实测），所以只需要管客户端侧这一遍。
fn reject_bad_annotations(p: &ProxyConfig) -> Result<()> {
    if p.annotations.is_empty() {
        return Ok(());
    }
    let mut total: usize = 0;
    for (k, v) in &p.annotations {
        total = total.saturating_add(k.len()).saturating_add(v.len());
        if let Some(reason) = annotation_key_error(k) {
            return Err(crate::error::Error::Protocol(format!(
                "代理 [{}] 的注解键 {k:?} 不合法：{reason}",
                p.name
            )));
        }
    }
    /// 与官方 `TotalAnnotationSizeLimitB` 一致：256 KiB。
    const ANNOTATION_SIZE_LIMIT: usize = 256 * (1 << 10);
    if total > ANNOTATION_SIZE_LIMIT {
        return Err(crate::error::Error::Protocol(format!(
            "代理 [{}] 的 annotations 总大小 {total} 字节，超过官方上限 256 KiB（{ANNOTATION_SIZE_LIMIT} 字节）",
            p.name
        )));
    }
    Ok(())
}

/// 单个注解键的合格性检查，返回 `Some(原因)` 表示不合格。
///
/// 逐条对齐 Kubernetes `validation.IsQualifiedName`（官方直接调用它，且
/// **先做 `strings.ToLower`**）：格式为 `[前缀/]名字`。
fn annotation_key_error(key: &str) -> Option<String> {
    let lower = key.to_lowercase();
    let parts: Vec<&str> = lower.split('/').collect();
    let name = match parts.as_slice() {
        [name] => *name,
        [prefix, name] => {
            if prefix.is_empty() {
                return Some("`/` 前面不能为空".to_string());
            }
            if !is_dns1123_subdomain(prefix) {
                return Some(format!(
                    "前缀 {prefix:?} 不是合法的 DNS 子域（小写字母数字与 `-`、`.`，\
                     每段以字母数字开头结尾且 ≤63 字符，总长 ≤253）"
                ));
            }
            *name
        }
        _ => return Some("最多只能有一个 `/`（格式 `前缀/名字`）".to_string()),
    };
    if !is_qualified_name_part(name) {
        return Some(format!(
            "名字 {name:?} 不合法（字母数字开头结尾，中间可含 `- _ .`，长度 ≤63）"
        ));
    }
    None
}

/// DNS-1123 子域：点分标签，每个标签是 DNS-1123 label，总长 ≤253。
fn is_dns1123_subdomain(s: &str) -> bool {
    if s.is_empty() || s.len() > 253 {
        return false;
    }
    s.split('.').all(is_dns1123_label)
}

/// DNS-1123 label：`[a-z0-9]` 开头结尾，中间可含 `-`，长度 ≤63。
fn is_dns1123_label(s: &str) -> bool {
    if s.is_empty() || s.len() > 63 {
        return false;
    }
    let b = s.as_bytes();
    let edge = |c: u8| c.is_ascii_lowercase() || c.is_ascii_digit();
    edge(b[0]) && edge(b[b.len() - 1]) && b.iter().all(|&c| edge(c) || c == b'-')
}

/// Kubernetes qualified-name 的"名字"部分（不含前缀）：
/// 字母数字开头结尾、中间可含 `[-_.]`，长度 ≤63。
///
/// 注意名字部分**不是** DNS label —— 它允许大写、`_` 和 `.`
/// （官方先整体小写，所以实践上等效于允许 `[a-z0-9._-]` 这些字符）。
fn is_qualified_name_part(s: &str) -> bool {
    if s.is_empty() || s.len() > 63 {
        return false;
    }
    let b = s.as_bytes();
    let alnum = |c: u8| c.is_ascii_alphanumeric();
    let mid = |c: u8| c.is_ascii_alphanumeric() || matches!(c, b'-' | b'_' | b'.');
    alnum(b[0]) && alnum(b[b.len() - 1]) && b.iter().all(|&c| mid(c))
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
    /// 官方 `[webServer]` + `[webServer.tls]` 必须能直接解析，且 TLS
    /// cert/key 必须成对；`dashboard_port` 显式值优先。
    #[test]
    fn web_server_tls_解析与优先级() {
        let raw = r#"
bind_port = 27000
[webServer]
addr = "127.0.0.1"
port = 27010
user = "admin"
password = "pw"
assetsDir = "/srv/assets"
pprofEnable = true
[webServer.tls]
certFile = "/etc/nfrp/cert.pem"
keyFile = "/etc/nfrp/key.pem"
trustedCaFile = "/etc/nfrp/ca.pem"
serverName = "dashboard.example.com"
"#;
        let cfg = parse_server_toml(raw).expect("官方 webServer 写法应能解析");
        assert_eq!(cfg.effective_dashboard_port(), Some(27010));
        assert_eq!(
            cfg.effective_dashboard_creds(),
            ("admin".to_string(), "pw".to_string())
        );
        assert_eq!(cfg.effective_assets_dir(), "/srv/assets");
        assert!(cfg.effective_pprof_enable());
        let (cert, key) = cfg.web_tls().files().unwrap().expect("cert/key 成对");
        assert_eq!(cert, "/etc/nfrp/cert.pem");
        assert_eq!(key, "/etc/nfrp/key.pem");

        // 显式 dashboard_port 优先于 webServer.port
        let cfg2 = parse_server_toml(
            "bind_port = 27000\ndashboard_port = 27011\n[webServer]\nport = 27010\n",
        )
        .unwrap();
        assert_eq!(cfg2.effective_dashboard_port(), Some(27011));

        // 只配一半必须报错，不能静默退回 HTTP
        let bad = r#"
bind_port = 27000
[webServer.tls]
certFile = "/tmp/cert.pem"
"#;
        let cfg3 = parse_server_toml(bad).expect("语法本身合法");
        assert!(cfg3.web_tls().files().is_err(), "缺 keyFile 必须拒绝");
    }

    #[test]
    fn web_server_tls_客户端解析() {
        let raw = r#"
serverAddr = "127.0.0.1"
serverPort = 27000
[webServer]
addr = "127.0.0.1"
port = 7400
user = "u"
password = "p"
[webServer.tls]
certFile = "cert.pem"
keyFile = "key.pem"
"#;
        let cfg = parse_client_toml(raw).expect("客户端 webServer.tls 应能解析");
        assert_eq!(cfg.web_server.port, 7400);
        assert!(cfg.web_server.tls.is_enabled());
        assert_eq!(
            cfg.web_server.tls.files().unwrap(),
            Some(("cert.pem", "key.pem"))
        );
    }

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

    // -----------------------------------------------------------------------
    // 第七轮审计 E-1：远程下发的回环白名单不得接受 `localhost`
    // -----------------------------------------------------------------------

    /// ★★ v0.5.8 回归（第七轮审计 **E-1**，高危）：
    /// **远程下发的 `local_addr` 回环白名单不得接受 `localhost`。**
    ///
    /// # 原先的漏洞
    ///
    /// `is_loopback_host()` 在 IP 解析**之前**无条件放行 `localhost`，
    /// 而**同仓库** `util::is_loopback_addr()` 的结论**正好相反**
    /// （注释写明"解析结果取决于 hosts 与 DNS，不能靠名字赌"）。
    /// 守卫远程下发路径的是**弱的那套**。
    ///
    /// 实测（`tmp/audit7/e_independent/repro_e1_localhost.py`，9/9）：
    /// 在 `127.0.0.1:<P>` 与 `[::1]:<P>` 各起一个诱饵，下发 `localhost:<P>`
    /// ⇒ **被接受**（200），且流量命中 **v6** 诱饵（v4=0 / v6=1）
    /// ⇒ 用户配的"本机 v4 服务"被绕过，送到了另一个地址族。
    ///
    /// # 这条测试测什么
    ///
    /// 1. **`localhost` 必须被拒**（核心）；
    /// 2. **明确的回环写法必须仍然放行**（`127.0.0.1` / `::1` / `127.x.x.x`）
    ///    —— 不能"修得过头把合法的也拒了"（第四轮犯过这个错）；
    /// 3. **非回环必须仍然被拒**（H4 的原有意图不能丢）。
    ///
    /// ★ 另外锁住一条**跨模块一致性**：`config::is_loopback_host` 与
    ///   `util::is_loopback_addr` 对 `localhost` 的结论**必须一致** ——
    ///   E-1 的根因就是"同一语义两套相反实现"，这条断言防它再漂移。
    #[test]
    fn 远程下发不得接受_localhost_作回环地址() {
        let with_addr = |addr: &str| ProxyConfig {
            name: "p".into(),
            proxy_type: "tcp".into(),
            local_addr: addr.into(),
            remote_port: 6000,
            ..Default::default()
        };

        // ---- ① 核心：localhost 必须被拒 ----
        for addr in ["localhost:8000", "LocalHost:8000", "LOCALHOST:8000"] {
            assert!(
                validate_remote_proxy(&with_addr(addr), true).is_err(),
                "远程下发的 {addr:?} **必须被拒** —— \
                 `localhost` 的解析结果取决于本机 hosts 与 DNS，判据不能靠名字赌（E-1）"
            );
        }

        // ---- ② 明确的回环写法必须仍然放行（不能修得过头）----
        for addr in [
            "127.0.0.1:8000",
            "127.1.2.3:8000", // 整个 127/8 都是回环
            "[::1]:8000",     // ★ IPv6 必须带方括号（无括号的 `::1:8000` 有二义性）
        ] {
            assert!(
                validate_remote_proxy(&with_addr(addr), true).is_ok(),
                "{addr:?} 是明确的回环地址，**必须放行** —— \
                 把合法的也拒掉是把'修漏洞'变成'制造不兼容'"
            );
        }

        // ★ 顺带锁住一条**已知且有意**的解析行为：无方括号的 `::1:8000` 有二义性
        //   （`::1` 自己就带冒号），`local_addr_host` 会整串当主机 ⇒ 解析不出 IP
        //   ⇒ 从严拒绝。这是**正确**的（宁可拒也不猜），写在这里免得后人误当 bug。
        assert!(
            validate_remote_proxy(&with_addr("::1:8000"), true).is_err(),
            "无方括号的 IPv6 + 端口有二义性，从严拒绝是**有意行为**；\
             要写 IPv6 请用 [::1]:8000"
        );
        // 而裸的 `::1`（不带端口）本身是合法主机 ⇒ 应当放行
        assert!(
            is_loopback_host("::1"),
            "裸 ::1 是明确回环（`local_addr_host` 对多冒号串整串当主机）"
        );

        // ---- ③ 非回环必须仍然被拒（H4 的原意）----
        for addr in [
            "169.254.169.254:80", // 云元数据服务（H4 的原始动机）
            "10.0.0.5:6379",
            "0.0.0.0:8000",
            "evil.example.com:80", // 域名同样不可信
        ] {
            assert!(
                validate_remote_proxy(&with_addr(addr), true).is_err(),
                "远程下发的 {addr:?} 必须被拒（H4）"
            );
        }

        // ---- ④ 本机配置文件路径不受这条限制（只作用于远程下发）----
        assert!(
            validate_remote_proxy(&with_addr("localhost:8000"), false).is_ok(),
            "本机配置文件里的 localhost 不受影响 —— 这条检查只针对远程下发"
        );

        // ---- ⑤ 跨模块一致性：两个 is_loopback 实现对 localhost 必须同结论 ----
        for name in ["localhost", "LocalHost", "LOCALHOST"] {
            assert_eq!(
                is_loopback_host(name),
                crate::util::is_loopback_addr(name),
                "{name:?} 在两个实现里的结论必须一致 —— \
                 E-1 的根因正是『同一语义两套相反实现』，这条防它再次漂移"
            );
        }
    }

    // -----------------------------------------------------------------------
    // 第七轮审计 E7（附带发现）：远程下发不得接受空 `local_addr`（假绿灯）
    // -----------------------------------------------------------------------

    /// ★★ v0.5.8 回归（第七轮审计 **E7 附带发现**，低危）：
    /// **远程下发的非插件代理，`local_addr` 不能为空。**
    ///
    /// # 原先的"假绿灯"
    ///
    /// 回环检查写的是 `if !p.local_addr.trim().is_empty()` ——
    /// 空串**整个跳过**检查。而 `ProxyConfig` 里**没有** `localIP`/`localPort`
    /// 字段，所以两段式写法被 serde **静默丢弃** ⇒ `local_addr` 保持空。
    ///
    /// 净效果：面板回 **200「已生效」**、公网端口**真的被占上**、
    /// `/api/status` 显示"已生效"，**但每条连接必然失败**
    /// （客户端拿空地址去 `resolve_addr`）。
    ///
    /// 实测（`tmp/audit7/e/localip_bypass_probe.py`）：
    /// * `localIP`+`localPort`（无 local_addr）⇒ 400（serde required 挡住）
    /// * **`local_addr:""` + 两段式** ⇒ **修复前 200 / 修复后 400**
    ///
    /// ★ 用**诱饵服务**做过决定性判定（`tmp/audit7/e/e71_verify_bypass.py`）：
    ///   两段式字段确实被丢弃、**没有**去连 `10.0.0.5`
    ///   ⇒ 这**不是 SSRF**，只是"面板说成功、实际不可用"的**假绿灯**。
    ///   与第六轮 F-1（`--check`/`verify` 假绿灯）同族，只是发生在**运行期**。
    ///
    /// # 这条测试测什么
    ///
    /// 1. **空 `local_addr` + 非插件 ⇒ 拒绝**（核心）；
    /// 2. **填了合法回环地址 ⇒ 仍然放行**（不能修得过头）；
    /// 3. **本机配置文件路径不受影响**（这条检查只针对远程下发）；
    /// 4. 插件代理的空 `local_addr` **不因这条而报"空地址"错**
    ///    （插件路径本来就不看 `local_addr`；远程下发里它会被**插件检查**先拒）。
    #[test]
    fn 远程下发不得接受空_local_addr() {
        let mk = |addr: &str, plugin: &str| ProxyConfig {
            name: "p".into(),
            proxy_type: "tcp".into(),
            local_addr: addr.into(),
            plugin: plugin.into(),
            remote_port: 6000,
            ..Default::default()
        };

        // ---- ① 核心：空 local_addr + 非插件 ⇒ 必须拒 ----
        for empty in ["", "   ", "\t"] {
            let e = validate_remote_proxy(&mk(empty, ""), true).expect_err(&format!(
                "空 local_addr（{empty:?}）必须被拒 —— 它是条必然失败的代理"
            ));
            let msg = e.to_string();
            assert!(
                msg.contains("local_addr"),
                "错误里要点名 local_addr，便于排障：{msg}"
            );
            assert!(
                msg.contains("两段式") || msg.contains("localIP"),
                "★ 错误里应当提醒『两段式在远程下发里不被接受』—— \
                 这正是使用者踩坑的地方（写了 localIP/localPort 却被静默丢弃）：{msg}"
            );
        }

        // ---- ② 填了合法回环 ⇒ 仍然放行（不能修得过头）----
        for ok in ["127.0.0.1:8080", "[::1]:8080", "127.0.0.2:9000"] {
            assert!(
                validate_remote_proxy(&mk(ok, ""), true).is_ok(),
                "{ok:?} 是合法的远程下发地址，必须放行"
            );
        }

        // ---- ③ 本机配置路径不受这条影响 ----
        //
        // （本机配置的空 local_addr 是用户自己配错，且 `reject_bad_proxy`
        //   那一侧有自己的口径；这条检查**只针对远程下发**。）
        assert!(
            validate_remote_proxy(&mk("", ""), false).is_ok(),
            "本机配置文件路径不该被这条远程检查影响"
        );

        // ---- ④ 插件代理不因这条报"空地址"（它有自己的一道闸）----
        let e2 = validate_remote_proxy(&mk("", "static_file"), true)
            .expect_err("远程下发带插件本来就该被拒");
        let msg2 = e2.to_string();
        assert!(
            msg2.contains("插件"),
            "★ 插件代理应当被**插件检查**拒掉（而不是被新的空地址检查拒）—— \
             否则错误信息会误导使用者去填 local_addr，而真正的问题是插件。实际：{msg2}"
        );
    }

    // -----------------------------------------------------------------------
    // 第七轮审计 B-2：`tlsEnable` 驼峰写法必须生效
    // -----------------------------------------------------------------------

    /// ★★ v0.5.8 回归（第七轮审计 **E-2**，中危）：
    /// **方括号形式必须整段就是 `[host]:port`** —— 否则"判据看到的主机"
    /// 与"实际连接用的主机"会不一致（check-vs-use）。
    ///
    /// # 原先的洞
    ///
    /// `local_addr_host` 用 `rest.split(']').next()` 取**第一个** `]` 之前的内容。
    /// 对 `[::1].evil.com:PORT` 它取到 `::1` ⇒ 判为回环 ⇒ **放行**；
    /// 而实际连接用的是**原始串**（`main.rs:1472` 的 `resolve_addr`）⇒ **走 DNS**。
    ///
    /// # 实测（`tmp/audit7/e_independent/repro_e2_decisive.py`，7/7）
    ///
    /// | 下发值 | 判据 | 实际转发 |
    /// |---|---|---|
    /// | `[::1]:<P>` | 接受 | **成功**（v6 诱饵命中）|
    /// | **`[::1].nonexistent-….local:<P>`** | **接受** | **失败** |
    ///
    /// 若连接用的也是切片后的 `::1`，第二条必应成功 —— 差异即铁证。
    ///
    /// # 这条测试测什么
    ///
    /// 1. **`[host]` 后面还有内容的必须被拒**（核心）；
    /// 2. **合法的 `[::1]:port` 必须仍然放行**（不能修得过头）；
    /// 3. 无方括号的形式不受影响（既有行为）。
    #[test]
    fn 方括号写法必须整段合法否则从严拒绝() {
        // ---- ① 核心：`]` 之后还有内容 ⇒ 必须被拒 ----
        //
        // 这些的"切片结果"都是回环（`::1`），但**整串不是**合法的 `[host]:port`。
        // 修复前它们会被放行，而连接时走 DNS ⇒ SSRF 面。
        for bad in [
            "[::1].evil.com:8000",
            "[::1].evil.com",
            "[127.0.0.1].evil.com:8000",
            "[::1]extra:8000",
            "[::1]x",
        ] {
            assert!(
                !is_loopback_host(local_addr_host(bad)),
                "★ {bad:?} 必须被判为**非回环** —— \
                 修复前 `split(']').next()` 会取到 `::1` 而放行，\
                 但实际连接用的是整个串（走 DNS）⇒ 判据与连接不一致（E-2）"
            );
        }

        // ---- ② 合法的 `[host]:port` 必须仍然放行 ----
        for ok in [
            "[::1]:8000",
            "[::1]",
            "[127.0.0.1]:8000",
            "[0:0:0:0:0:0:0:1]:80",
        ] {
            assert!(
                is_loopback_host(local_addr_host(ok)),
                "{ok:?} 是合法的回环写法，必须放行（不能修得过头）"
            );
        }

        // ---- ③ `]` 后跟非数字端口同样从严 ----
        for bad in ["[::1]:abc", "[::1]:", "[::1]:80x"] {
            let h = local_addr_host(bad);
            assert!(
                !is_loopback_host(h) || h == "[::1]:abc",
                "{bad:?} 不是合法的 `[host]:port`，不应当被当成回环而放行"
            );
        }

        // ---- ④ 无方括号的形式不受影响（既有行为保持不变）----
        for ok in ["127.0.0.1:8000", "127.1.2.3:8000"] {
            assert!(
                is_loopback_host(local_addr_host(ok)),
                "{ok:?} 的既有行为不能变"
            );
        }
    }

    // -----------------------------------------------------------------------
    // 第七轮审计 B-2：`tlsEnable` 驼峰写法必须生效
    // -----------------------------------------------------------------------

    /// ★★ v0.5.8 回归（第七轮审计 **B-2**，中危）：
    /// **`tlsEnable`（驼峰）与 `tls_enable`（下划线）必须都能开启 TLS。**
    ///
    /// # 原先的陷阱
    ///
    /// `ClientConfig` 里**命名风格混用**：
    /// * `tls_verify_server_cert` → serde 名是驼峰 `verifyServerCert`
    /// * `tls_trusted_ca_file` → 驼峰 `trustedCaFile`
    /// * 而 `tls_enable` → **没有 rename**（只能是 `tls_enable`）
    ///
    /// ⇒ 用户照同一段配置里的风格写 `tlsEnable = true`，**serde 静默丢弃**
    /// ⇒ TLS 没开。更糟的是它会让 `verifyServerCert = true` **一起失效**：
    /// `tls::connect_client` 在 `enable == false` 时**第一行就返回**，
    /// `verify` 参数被完全忽略 ⇒ **既不加密也不校验，且无告警**。
    ///
    /// 实测（`tmp/audit7/b_independent/repro_b2_tls.py`）：明文链路里
    /// 直接可见 `"privilege_key":"35a8601c…"` —— 它等于 `md5(token+ts)`，
    /// **可以直接重放登录**。
    ///
    /// # 这条测试测什么
    ///
    /// 1. **驼峰 `tlsEnable = true` 必须真的把 `tls_enable` 置为 true**（核心）；
    /// 2. **下划线写法照常工作**（纯增量，不能破坏既有配置）；
    /// 3. 官方 `[transport.tls] enable = true` 写法也仍然工作。
    #[test]
    fn tls_开关的驼峰写法必须生效() {
        let parse = |body: &str| {
            parse_client(&format!(
                "server_addr = \"127.0.0.1\"\nserver_port = 7000\n{body}"
            ))
            .expect("配置应能解析")
        };

        // ---- ① 驼峰写法（B-2 的核心）----
        let c = parse("tlsEnable = true\nverifyServerCert = true\n");
        assert!(
            c.tls_enable,
            "★ 驼峰 `tlsEnable = true` 必须真的开启 TLS —— \
             原先 serde 静默丢弃它，导致 TLS 与证书校验**双双失效**且无告警（B-2）"
        );
        assert!(c.tls_verify_server_cert, "verifyServerCert 也应生效");

        // ---- ② 下划线写法照常工作（不能破坏既有配置）----
        let c2 = parse("tls_enable = true\nverifyServerCert = true\n");
        assert!(c2.tls_enable, "下划线 `tls_enable` 必须继续有效");
        assert!(c2.tls_verify_server_cert);

        // ---- ③ 官方段落写法（`[transport.tls] enable`）----
        //
        // ★ 注意：官方 0.71 的 `[transport.tls]` 段包含 `enable` /
        //   `certFile` / `keyFile` / `trustedCaFile` / `serverName` /
        //   `disableCustomTLSFirstByte`（见官方 frpc_full_example.toml）。
        //   NFRp 的 `verifyServerCert` 仍是顶层键，所以这里分开断言。
        let c3 = parse("[transport.tls]\nenable = true\n");
        assert!(c3.tls_enable, "官方 `[transport.tls] enable` 写法必须有效");

        // 顶层的 `verifyServerCert` 与段内的 `enable` 组合是最常见的写法
        let c3b = parse("verifyServerCert = true\n[transport.tls]\nenable = true\n");
        assert!(c3b.tls_enable, "段内 enable 应生效");
        assert!(
            c3b.tls_verify_server_cert,
            "顶层 verifyServerCert 应生效（官方 schema 里它就是顶层键）"
        );

        // ---- ④ 不配就是不开（默认值不变，保持互通）----
        let c4 = parse("token = \"t\"\n");
        assert!(
            !c4.tls_enable,
            "默认必须是不开 TLS（与官方 frp 一致，保互通）"
        );
        assert!(
            !c4.tls_verify_server_cert,
            "默认必须是不校验（改默认会破坏『官方 frpc 零配置直连』）"
        );

        // ---- ⑤ 只写 verifyServerCert（漏 enable）⇒ 两个字段状态要如实反映 ----
        //
        // 这种情况**仍然是不安全的**（客户端会打显著 WARN，见 `main.rs`），
        // 这里只锁住"解析结果如实" —— 修复是**告警**而不是替用户开 TLS
        // （替用户开 TLS 会改变他配置的语义，那是另一种越界）。
        let c5 = parse("verifyServerCert = true\n");
        assert!(
            !c5.tls_enable,
            "只写 verifyServerCert 不该被推断成开了 TLS —— \
             我们只**告警**，不替用户改语义"
        );
        assert!(c5.tls_verify_server_cert, "该字段本身要如实解析");
    }

    // ==================================================================
    // v0.6.5：`includes`（客户端配置包含）与 `glob_match`
    // ==================================================================

    #[test]
    fn glob_匹配语义对齐_go_filepath_match() {
        // `*` 匹配任意长度（含空）
        assert!(glob_match("*.toml", "a.toml"));
        assert!(glob_match("*.toml", ".toml"), "`*` 要能匹配空串");
        assert!(!glob_match("*.toml", "a.yaml"));
        assert!(glob_match("a*", "abc"));
        assert!(glob_match("*", "anything"));

        // `?` 恰好一个字符
        assert!(glob_match("a?c", "abc"));
        assert!(!glob_match("a?c", "ac"), "`?` 不能匹配空");
        assert!(!glob_match("a?c", "abbc"));

        // 字符集
        assert!(glob_match("a[bc]d", "abd"));
        assert!(glob_match("a[bc]d", "acd"));
        assert!(!glob_match("a[bc]d", "aed"));
        assert!(glob_match("a[a-c]d", "abd"), "区间要生效");
        assert!(!glob_match("a[a-c]d", "azd"));
        assert!(glob_match("a[^bc]d", "aed"), "^ 取反");
        assert!(!glob_match("a[^bc]d", "abd"));

        // `[` 未闭合：按字面处理（比 Go 的报错更宽容，不会让配置直接失败）
        assert!(glob_match("a[b", "a[b"));

        // 字面量
        assert!(glob_match("frpc.toml", "frpc.toml"));
        assert!(!glob_match("frpc.toml", "frpc.toml.bak"));

        // 多个 `*` 与回溯：a*b*c 要能匹配 aXXbYYc
        assert!(glob_match("a*b*c", "aXXbYYc"));
        assert!(!glob_match("a*b*c", "aXXbYY"));
    }

    /// 造一个临时目录；返回目录路径。
    fn tmp_dir(tag: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("nfrp-inc-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    /// ★ includes：命中文件的 `proxies` 要真的追加进来。
    #[test]
    fn includes_会合并_proxies() {
        let d = tmp_dir("merge");
        std::fs::write(
            d.join("frpc.toml"),
            "serverAddr = \"example.com\"\nincludes = [\"conf.d/*.toml\"]\n\
             [[proxies]]\nname = \"main\"\ntype = \"tcp\"\nlocalPort = 1000\n",
        )
        .unwrap();
        std::fs::create_dir_all(d.join("conf.d")).unwrap();
        std::fs::write(
            d.join("conf.d/a.toml"),
            "[[proxies]]\nname = \"extra-a\"\ntype = \"tcp\"\nlocalPort = 2001\n",
        )
        .unwrap();
        std::fs::write(
            d.join("conf.d/b.toml"),
            "[[proxies]]\nname = \"extra-b\"\ntype = \"udp\"\nlocalPort = 2002\n",
        )
        .unwrap();
        // 不匹配扩展名的文件不能被加载
        std::fs::write(
            d.join("conf.d/c.yaml"),
            "[[proxies]]\nname = \"should-not-load\"\ntype = \"tcp\"\nlocalPort = 2003\n",
        )
        .unwrap();

        let cfg = ClientConfig::load(d.join("frpc.toml")).unwrap();
        let names: Vec<&str> = cfg.proxies.iter().map(|p| p.name.as_str()).collect();
        assert_eq!(
            names,
            vec!["main", "extra-a", "extra-b"],
            "主配置在前，includes 按文件名排序追加；c.yaml 不该被加载"
        );
        // 只取 proxies —— includes 文件里的 serverAddr 不能覆盖主配置
        assert_eq!(cfg.server_addr, "example.com");

        let _ = std::fs::remove_dir_all(&d);
    }

    /// includes 里各文件的**其它字段一律忽略**（不是配置继承）。
    #[test]
    fn includes_不覆盖主配置的其它字段() {
        let d = tmp_dir("noovr");
        std::fs::write(
            d.join("frpc.toml"),
            "serverAddr = \"main.example\"\nserverPort = 7000\nincludes = [\"*.toml\"]\n",
        )
        .unwrap();
        std::fs::write(
            d.join("extra.toml"),
            "serverAddr = \"evil.example\"\nserverPort = 9999\ntoken = \"hacked\"\n\
             [[proxies]]\nname = \"p1\"\ntype = \"tcp\"\nlocalPort = 3000\n",
        )
        .unwrap();

        let cfg = ClientConfig::load(d.join("frpc.toml")).unwrap();
        assert_eq!(
            cfg.server_addr, "main.example",
            "includes 不能覆盖 serverAddr"
        );
        assert_eq!(cfg.server_port, 7000, "includes 不能覆盖 serverPort");
        assert_eq!(cfg.token, "", "includes 不能覆盖 token");
        assert_eq!(cfg.proxies.len(), 1, "只取 proxies");

        let _ = std::fs::remove_dir_all(&d);
    }

    /// 合并后重名要**明确报错**，不能静默放过。
    #[test]
    fn includes_重名代理必须报错() {
        let d = tmp_dir("dup");
        std::fs::write(
            d.join("frpc.toml"),
            "serverAddr = \"x\"\nincludes = [\"*.toml\"]\n\
             [[proxies]]\nname = \"same\"\ntype = \"tcp\"\nlocalPort = 1\n",
        )
        .unwrap();
        std::fs::write(
            d.join("dup.toml"),
            "[[proxies]]\nname = \"same\"\ntype = \"tcp\"\nlocalPort = 2\n",
        )
        .unwrap();

        let err = ClientConfig::load(d.join("frpc.toml")).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("same"), "错误里要指出哪个名字：{msg}");
        assert!(msg.contains("重复"), "要说清是重名：{msg}");

        let _ = std::fs::remove_dir_all(&d);
    }

    /// 目录不存在时要报错，且回显用户写的那条模式。
    #[test]
    fn includes_目录不存在时报错() {
        let d = tmp_dir("nodir");
        std::fs::write(
            d.join("frpc.toml"),
            "serverAddr = \"x\"\nincludes = [\"missing_dir/*.toml\"]\n",
        )
        .unwrap();

        let err = ClientConfig::load(d.join("frpc.toml")).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("missing_dir"),
            "要回显用户写的 includes：{msg}"
        );

        let _ = std::fs::remove_dir_all(&d);
    }

    // ==================================================================
    // v0.6.6：`udpPacketSize`（两端）
    // ==================================================================

    /// 默认是 65507（NFRP 一直用的值），**不是**官方的 1500。
    ///
    /// 这条锁住"默认不被改成 1500" —— 改了会截断现有用户的大 UDP 报文，
    /// 而且是静默截断（收得到包、内容少一截），比报错难查得多。
    #[test]
    fn udp_packet_size_默认是_65507() {
        assert_eq!(ServerConfig::default().udp_packet_size, MAX_UDP_PACKET_SIZE);
        assert_eq!(ClientConfig::default().udp_packet_size, MAX_UDP_PACKET_SIZE);
        assert_eq!(MAX_UDP_PACKET_SIZE, 65507);
    }

    /// 两端都能读（官方 camelCase 与 NFRP snake_case 都认）。
    #[test]
    fn udp_packet_size_两端都能读() {
        let sv = parse_server_toml("bind_port = 7000\nudpPacketSize = 1500\n").unwrap();
        assert_eq!(sv.udp_packet_size, 1500, "服务端 camelCase");

        let sv2 = parse_server_toml("bind_port = 7000\nudp_packet_size = 1400\n").unwrap();
        assert_eq!(sv2.udp_packet_size, 1400, "服务端 snake_case");

        let cl = parse_client_toml("serverAddr = \"x\"\nudpPacketSize = 1200\n").unwrap();
        assert_eq!(cl.udp_packet_size, 1200, "客户端 camelCase");

        let cl2 = parse_client_toml("server_addr = \"x\"\nudp_packet_size = 1100\n").unwrap();
        assert_eq!(cl2.udp_packet_size, 1100, "客户端 snake_case");
    }

    /// 夹紧：0 退回默认，超上限夹到 65507。
    #[test]
    fn udp_packet_size_会夹紧到有意义范围() {
        assert_eq!(clamp_udp_packet_size(0), MAX_UDP_PACKET_SIZE, "0 没意义");
        assert_eq!(clamp_udp_packet_size(1), 1, "1 是合法的最小值");
        assert_eq!(clamp_udp_packet_size(1500), 1500);
        assert_eq!(
            clamp_udp_packet_size(70_000),
            MAX_UDP_PACKET_SIZE,
            "超过 UDP 协议上限要夹住"
        );
        assert_eq!(
            clamp_udp_packet_size(MAX_UDP_PACKET_SIZE),
            MAX_UDP_PACKET_SIZE
        );
    }

    /// 实现了就不能再出现在"未实现字段"清单里（否则是反向假警报）。
    #[test]
    fn udp_packet_size_不再被报未实现() {
        let sv = parse_server_toml("bind_port = 7000\nudpPacketSize = 1500\n").unwrap();
        assert!(
            sv.unsupported_fields.is_empty(),
            "服务端不该再报：{:?}",
            sv.unsupported_fields
        );

        let cl = parse_client_toml("serverAddr = \"x\"\nudpPacketSize = 1500\n").unwrap();
        assert!(
            cl.unsupported_fields.is_empty(),
            "客户端不该再报：{:?}",
            cl.unsupported_fields
        );
    }

    /// 没配 includes 时**不碰文件系统**（走老路径，行为完全不变）。
    #[test]
    fn 没配_includes_时行为不变() {
        let cfg = parse_client(
            "serverAddr = \"x\"\n[[proxies]]\nname = \"a\"\ntype = \"tcp\"\nlocalPort = 1\n",
        )
        .unwrap();
        assert!(cfg.includes.is_empty());
        assert_eq!(cfg.proxies.len(), 1);
    }
}
