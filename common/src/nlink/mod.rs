//! NLink v1：在 frp 线协议之上叠一层**可协商、可回退、零额外往返**的扩展层。
//!
//! # 为什么是"叠一层"而不是"改协议"
//!
//! 这个项目的首要约束是与官方 frp 双向互通（README 有专门一节）。所以 NLink
//! 的每一部分都遵守两条铁律：
//!
//! 1. **标准帧一个字节都不动**。扩展能力走独立命名空间（专用帧类型 / 专用
//!    消息类型字节 / 专用 TLV 编号段），官方 frp 永远看不到这些字节；
//! 2. **没协商成功就当它不存在**。能力必须双方都声明、且由服务端回显才算数；
//!    任何一端不支持，行为与 0.6.x 完全一致。
//!
//! # 零额外往返怎么做到
//!
//! 官方 frp 的握手本身就有"客户端先说话、服务端再回话"的往返：
//! v2 是 `ClientHello → ServerHello → Login → LoginResp`，v1 是
//! `Login → LoginResp`。NLink 只做两件事：
//!
//! * 客户端在**第一条协议消息之前**塞一段 8 字节魔术字打头的 **preamble**
//!   （纯单向，不等回复）；
//! * 服务端把**协商结果挂在 `LoginResp` 的 `_nlink` 字段里**一起回去。
//!
//! 也就是说协商信息是**搭车**的，没有新增任何一次"发出去等回来"。见
//! [`preamble`](crate::nlink::frame::Preamble) 与 `frp::conn` 的握手实现。
//!
//! # 两层开关
//!
//! * 编译期：crate feature `nlink`。关掉时 `Login` / `LoginResp` 里连字段都
//!   不存在（`#[cfg(feature = "nlink")]`），报文长度与 0.6.x 逐字节一致；
//! * 运行期：配置里的 `nlink.enable`，默认 `false`。关掉时客户端连 preamble
//!   都不发，服务端收到 preamble 也会当作"对端走错协议"直接按标准流程解析
//!   —— 但因为有魔术字保护，这种情况只会发生在别人手动构造报文时。
//!
//! 两层都打开才真正启用；只开一层等于没开（见 [`FeatureSet::active`]）。

pub mod frame;
pub mod knock;
pub mod policy;
pub mod ratelimit;
pub mod session;

use serde::{Deserialize, Serialize};

pub use frame::{Frame, FrameKind, Preamble, Tlv, TlvMap};
pub use session::{ConnectionId, ResumeEntry, ResumeRegistry, TraceId};

/// 线协议版本。TLV / 帧格式变化时 +1，旧版本对端看到不认识的版本必须**忽略**
/// 而不是报错（前向兼容），并在 `LoginResp` 里回自己支持的最高版本。
pub const PROTOCOL_VERSION: u8 = 1;

/// preamble 魔术字。
///
/// 8 字节全部用掉，是为了和 v2 的 `FRP\x00\x02\r\n` 保持同样的"读满 8 字节
/// 再判断"的处理方式（`FrpConn::detect_version` 本来就先读 8 字节）。
///
/// 选 `NFRPLNK1` 的理由：
/// * 官方 v1 的第一条消息是 JSON，首字节一定是 `{`（0x7B）；
/// * 官方 v2 的首字节是 `F`（0x46），TLS 的首字节是 0x16；
/// * 三者都不可能等于 `N`（0x4E），所以"首字节是 N 且后 7 字节匹配"这件事
///   标准 frp 永远不会产生 —— 这就是双栈共存的识别依据。
pub const MAGIC: [u8; 8] = *b"NFRPLNK1";

/// v2 下承载扩展帧的**帧类型**（与消息帧 `FRAME_MESSAGE = 16` 并列）。
///
/// 用 0x4E（ASCII `N`）而不是 17、18 这种小数字，是为了离官方已用的帧类型
/// 远一点：将来官方如果新增 17/18，我们不会撞号。
pub const V2_FRAME_TYPE: u16 = 0x4E;

/// v1 下承载扩展帧的**消息类型字节**。
///
/// 官方到 v0.71.0 为止只用小写字母和数字；本项目已用 `Z` / `Y` 承载管理命令。
/// 0x7F 既不是字母也不是数字，且离可打印 ASCII 段很远，撞号概率最低。
pub const V1_TYPE_BYTE: u8 = 0x7F;

/// NLink QUIC 的 ALPN。
///
/// 与标准 QUIC 传输的 `b"nfrp-frp"` 分开，是为了让**同一个 UDP 端口**
/// 能同时服务两种客户端：ALPN 在 TLS 握手里协商，不匹配就握不上手。
pub const ALPN: &[u8] = b"nfrp-nlink";

// ---------------------------------------------------------------------------
// 能力位图
// ---------------------------------------------------------------------------

/// 能力位：原生 QUIC 传输（多路复用 + 连接迁移）。
pub const CAP_QUIC: u64 = 1 << 0;
/// 能力位：QUIC 连接迁移（依赖 [`CAP_QUIC`]）。
pub const CAP_QUIC_MIGRATION: u64 = 1 << 1;
/// 能力位：P2P 打洞信令增强（TTL 阶梯、双向探测、失败原因码）。
pub const CAP_NAT_ADAPTIVE: u64 = 1 << 2;
/// 能力位：零信任身份（每会话短时令牌，工作连接必须出示）。
pub const CAP_IDENTITY: u64 = 1 << 3;
/// 能力位：细粒度限流（按代理 / 用户 / 请求维度，令牌桶）。
pub const CAP_RATE_LIMIT: u64 = 1 << 4;
/// 能力位：端到端 trace（控制连接与数据面共享 trace id）。
pub const CAP_TRACE: u64 = 1 << 5;
/// 能力位：批量申请工作连接（一条扩展帧换 N 条工作连接）。
pub const CAP_BATCH_WORK: u64 = 1 << 6;
/// 能力位：断线续传（connection id + 服务端状态保留）。
pub const CAP_RESUME: u64 = 1 << 7;
/// 能力位：端口敲门（默认不可见，敲门后临时放行）。
pub const CAP_PORT_KNOCK: u64 = 1 << 8;
/// 能力位：XTCP 混合版本直连策略。
pub const CAP_XTCP_POLICY: u64 = 1 << 9;
/// 能力位：兼容性边界探测（服务端回报"官方会忽略 / 官方会报错"清单）。
pub const CAP_COMPAT_PROBE: u64 = 1 << 10;

/// 本版本实现的全部能力。
pub const ALL_CAPS: u64 = CAP_QUIC
    | CAP_QUIC_MIGRATION
    | CAP_NAT_ADAPTIVE
    | CAP_IDENTITY
    | CAP_RATE_LIMIT
    | CAP_TRACE
    | CAP_BATCH_WORK
    | CAP_RESUME
    | CAP_PORT_KNOCK
    | CAP_XTCP_POLICY
    | CAP_COMPAT_PROBE;

/// 能力位图。未知位一律忽略（前向兼容）。
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Caps(pub u64);

impl Caps {
    pub const EMPTY: Caps = Caps(0);
    pub const ALL: Caps = Caps(ALL_CAPS);

    pub fn new(bits: u64) -> Self {
        Caps(bits & ALL_CAPS)
    }

    pub fn bits(self) -> u64 {
        self.0
    }

    pub fn contains(self, bit: u64) -> bool {
        self.0 & bit != 0
    }

    pub fn any(self) -> bool {
        self.0 != 0
    }

    /// 双方能力的交集，再加上"本端运行时显式启用"的掩码。
    ///
    /// 三个条件缺一不可：
    /// * 对端声明了（`theirs`）；
    /// * 本端实现了（`ours`）；
    /// * 本端运行时允许（`enabled`）—— 默认全关，只协商不启用。
    pub fn agree(ours: Caps, theirs: Caps, enabled: Caps) -> Caps {
        Caps(ours.0 & theirs.0 & enabled.0)
    }

    /// 把位图渲染成稳定顺序的英文短名，用于日志与自检输出。
    pub fn names(self) -> Vec<&'static str> {
        const TABLE: &[(u64, &str)] = &[
            (CAP_QUIC, "quic"),
            (CAP_QUIC_MIGRATION, "quic-migration"),
            (CAP_NAT_ADAPTIVE, "nat-adaptive"),
            (CAP_IDENTITY, "identity"),
            (CAP_RATE_LIMIT, "rate-limit"),
            (CAP_TRACE, "trace"),
            (CAP_BATCH_WORK, "batch-work-conn"),
            (CAP_RESUME, "resume"),
            (CAP_PORT_KNOCK, "port-knock"),
            (CAP_XTCP_POLICY, "xtcp-policy"),
            (CAP_COMPAT_PROBE, "compat-probe"),
        ];
        TABLE
            .iter()
            .filter(|(bit, _)| self.contains(*bit))
            .map(|(_, name)| *name)
            .collect()
    }
}

impl std::fmt::Display for Caps {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let names = self.names();
        if names.is_empty() {
            write!(f, "none")
        } else {
            write!(f, "{}", names.join(","))
        }
    }
}

// ---------------------------------------------------------------------------
// 两层开关
// ---------------------------------------------------------------------------

/// 一次协商的最终状态。
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct FeatureSet {
    /// 编译期实现的能力（`--no-default-features` 关掉 `nlink` 时是空集）。
    pub compiled: Caps,
    /// 运行期允许启用的能力（配置里 `nlink.features` 显式列出）。
    pub enabled: Caps,
}

impl FeatureSet {
    /// 编译期实现 + 运行期开启 = 本端真正能用的。
    pub fn active(&self) -> Caps {
        Caps(self.compiled.0 & self.enabled.0)
    }

    /// 对方声明的能力与本地可用能力的交集。
    pub fn agree(&self, theirs: Caps) -> Caps {
        Caps::agree(self.compiled, theirs, self.enabled)
    }
}

/// 编译期是否带 NLink。
pub const fn compiled_in() -> bool {
    cfg!(feature = "nlink")
}

/// 编译期实现的能力集。
pub fn compiled_caps() -> Caps {
    #[cfg(feature = "nlink")]
    {
        Caps::ALL
    }
    #[cfg(not(feature = "nlink"))]
    {
        Caps::EMPTY
    }
}

/// 服务端在 `LoginResp` 里回显的协商结果（`_nlink` 字段）。
///
/// 为什么挂在 `LoginResp` 而不是单独一条消息：约束 1 要求"不额外增加往返"。
/// 客户端把能力声明搭在 preamble 上送去，服务端把确认结果搭在本来就要发的
/// `LoginResp` 上带回 —— 全程零新增往返。
///
/// 官方 frpc 解析 `LoginResp` 用 Go 的 `encoding/json`，**未知字段直接忽略**，
/// 所以多挂这个键对它零影响；反过来，官方 frps 不会回这个字段，
/// 客户端拿不到就**不启用**（见 `FeatureSet::agree`）。
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct LoginAck {
    /// 服务端支持的扩展协议版本。
    #[serde(default)]
    pub version: u8,
    /// 双方确认启用的能力位（交集）。
    #[serde(default)]
    pub caps: u64,
    /// 本次连接的 trace id（十六进制）。客户端据此把日志串起来。
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub trace_id: String,
    /// 服务端看到的 connection id（回显，便于对账）。
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub session: String,
}

impl LoginAck {
    pub fn caps(&self) -> Caps {
        Caps::new(self.caps)
    }
}

// ---------------------------------------------------------------------------
// 配置
// ---------------------------------------------------------------------------

/// 客户端 `[nlink]` 配置。
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct ClientNLinkConfig {
    /// 总开关。默认关闭：关闭时**连 preamble 都不发**，报文与 0.6.x 一致。
    #[serde(default)]
    pub enable: bool,
    /// 显式启用的能力名（`quic` / `resume` / `trace` / `batch-work-conn` …）。
    ///
    /// 留空 = 只声明、不启用任何一项（"仅协商不启用"）。
    #[serde(default)]
    pub features: Vec<String>,
    /// 批量申请工作连接的条数（0 = 关闭）。开启后服务端一次要 N 条。
    #[serde(default)]
    pub batch_work_conn: usize,
    /// 断线后用同一个 connection id 续传（需要服务端也开启）。
    #[serde(default)]
    pub resume: bool,
    /// XTCP 直连策略：`auto` / `prefer-direct` / `direct-only` / `relay-only`。
    #[serde(default)]
    pub xtcp_policy: String,
    /// 走 QUIC 连服务端（需要服务端开 `[nlink] quic_listen`）。
    #[serde(default)]
    pub quic: bool,
    /// NLink QUIC 的服务端地址（`host:port`，UDP）。
    ///
    /// 留空时用 `server_addr:server_port` —— 仅当服务端 `quic_listen` 的
    /// 端口与 `bind_port` 相同时才连得上（同一个端口号、不同协议是允许的）。
    #[serde(default)]
    pub quic_addr: String,
    /// 网络切换时自动迁移 QUIC 连接（只对 `quic = true` 生效）。
    #[serde(default)]
    pub quic_migrate: bool,
    /// 端口敲门的共享密钥（客户端作为敲门方时用）。
    #[serde(default)]
    pub knock_secret: String,
}

impl ClientNLinkConfig {
    pub fn features(&self) -> FeatureSet {
        FeatureSet {
            compiled: compiled_caps(),
            enabled: parse_features(&self.features).0,
        }
    }
}

/// 服务端 `[nlink]` 配置。
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ServerNLinkConfig {
    /// 总开关。默认关闭。
    #[serde(default)]
    pub enable: bool,
    /// 显式启用的能力名，语义同客户端。
    #[serde(default)]
    pub features: Vec<String>,
    /// 断线续传时服务端保留代理状态的时间（秒）。0 折算默认 30。
    #[serde(default = "default_resume_ttl")]
    pub resume_ttl: u64,
    /// QUIC 监听地址（如 `0.0.0.0:7000`）。留空 = 不开 QUIC。
    #[serde(default)]
    pub quic_listen: String,
    /// 单个批量请求最多向客户端要多少条工作连接（0 = 不做批量）。
    ///
    /// 只在客户端也协商了 `batch-work-conn` 时生效：服务端一次发一条
    /// `BatchReq`，客户端据此建 N 条。并发用户越多，省下的往返越多。
    #[serde(default = "default_batch_work_conn")]
    pub batch_work_conn: usize,
    /// 端口敲门规则。
    #[serde(default)]
    pub knock: Vec<knock::KnockRule>,
    /// 细粒度限流规则。
    #[serde(default)]
    pub limits: Vec<ratelimit::RateLimitRule>,
    /// 每会话身份令牌的有效期（秒）。0 折算默认 300。
    #[serde(default = "default_identity_ttl")]
    pub identity_ttl: u64,
}

fn default_resume_ttl() -> u64 {
    30
}
fn default_batch_work_conn() -> usize {
    8
}
fn default_identity_ttl() -> u64 {
    300
}

impl Default for ServerNLinkConfig {
    fn default() -> Self {
        Self {
            enable: false,
            features: Vec::new(),
            resume_ttl: default_resume_ttl(),
            quic_listen: String::new(),
            batch_work_conn: default_batch_work_conn(),
            knock: Vec::new(),
            limits: Vec::new(),
            identity_ttl: default_identity_ttl(),
        }
    }
}

impl ServerNLinkConfig {
    pub fn features(&self) -> FeatureSet {
        FeatureSet {
            compiled: compiled_caps(),
            enabled: parse_features(&self.features).0,
        }
    }
}

/// 把能力名解析成位图。
///
/// 返回 `(位图, 不认识的名字)`。不认识的名字**不报错**，只记下来让上层打一条
/// 警告 —— 新旧版本混跑时，"配置里写了个未来能力"不应该让服务起不来。
pub fn parse_features(names: &[String]) -> (Caps, Vec<String>) {
    let table: &[(&str, u64)] = &[
        ("quic", CAP_QUIC),
        ("quic-migration", CAP_QUIC_MIGRATION),
        ("nat-adaptive", CAP_NAT_ADAPTIVE),
        ("identity", CAP_IDENTITY),
        ("rate-limit", CAP_RATE_LIMIT),
        ("trace", CAP_TRACE),
        ("batch-work-conn", CAP_BATCH_WORK),
        ("resume", CAP_RESUME),
        ("port-knock", CAP_PORT_KNOCK),
        ("xtcp-policy", CAP_XTCP_POLICY),
        ("compat-probe", CAP_COMPAT_PROBE),
        ("all", ALL_CAPS),
    ];
    let mut bits = 0u64;
    let mut unknown = Vec::new();
    for name in names {
        match table.iter().find(|(n, _)| *n == name.trim()) {
            Some((_, b)) => bits |= *b,
            None => unknown.push(name.clone()),
        }
    }
    (Caps(bits & ALL_CAPS), unknown)
}

/// preamble 的固定标志位（preamble 里的 `flags` 字节，`u8`）。
pub const FLAG_ENABLED: u8 = 1 << 0;
pub const FLAG_RESUME: u8 = 1 << 1;
pub const FLAG_QUIC: u8 = 1 << 2;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn 能力名字与位图互相一致() {
        // 每一项都要能解析回自己：防止"加了能力位却忘了加名字"。
        let (caps, unknown) = parse_features(&[
            "quic".into(),
            "quic-migration".into(),
            "nat-adaptive".into(),
            "identity".into(),
            "rate-limit".into(),
            "trace".into(),
            "batch-work-conn".into(),
            "resume".into(),
            "port-knock".into(),
            "xtcp-policy".into(),
            "compat-probe".into(),
        ]);
        assert!(unknown.is_empty());
        assert_eq!(caps.bits(), ALL_CAPS);
        assert_eq!(caps.names().len(), 11);
    }

    #[test]
    fn 不认识的能力名不报错() {
        let (caps, unknown) = parse_features(&["quic".into(), "--future--".into()]);
        assert_eq!(caps, Caps(CAP_QUIC));
        assert_eq!(unknown, vec!["--future--".to_string()]);
    }

    #[test]
    fn 交集必须三方同时成立() {
        let ours = Caps(CAP_QUIC | CAP_TRACE | CAP_RESUME);
        let theirs = Caps(CAP_TRACE | CAP_RESUME | CAP_PORT_KNOCK);
        // 运行期只开了 trace：结果只能是 trace
        let enabled = Caps(CAP_TRACE | CAP_IDENTITY);
        assert_eq!(
            Caps::agree(ours, theirs, enabled),
            Caps(CAP_TRACE),
            "交集必须同时受实现、对端、运行期开关三者限制"
        );
    }

    #[test]
    fn 未知位在解析时被丢弃() {
        let (caps, _) = parse_features(&[]);
        assert_eq!(caps, Caps::EMPTY);
        // 位图里塞一个未来才有的位：new 之后必须不存在
        assert_eq!(Caps::new(1u64 << 40).bits(), 0);
    }

    #[test]
    fn 编译期能力位可查询() {
        // 默认 feature 下应当全部可见；关闭时要变成空集（由 CI 的另一条命令验证）。
        if cfg!(feature = "nlink") {
            assert!(compiled_caps().any());
            assert!(compiled_caps().contains(CAP_QUIC));
        } else {
            assert!(!compiled_caps().any());
        }
    }
}
