//! 客户端配置结构。
//!
//! 职责：定义 `ClientConfig`、`StoreConfig`、`WebTlsConfig`、`WebServerConfig` 及其 Default/有效值/示例与 `includes` 合并。
//! 并发/所有权契约：配置在解析后只读，无锁、无共享可变状态；`load` / `merge_includes` 只读文件系统。
//! 不变量：serde 默认值只由 `defaults` 模块定义；`token` / `password` / `secret_key` 在 Debug 中必须脱敏。

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::error::Result;

use super::defaults::{
    default_client_id, default_control_port, default_dial_server_keepalive,
    default_dial_server_timeout, default_heartbeat_interval, default_heartbeat_timeout,
    default_log_level, default_log_max_days, default_pool_count, default_predict_window,
    default_reconnect_interval, default_tcp_mux_keepalive_interval, default_transport_protocol,
    default_true, default_udp_packet_size, default_webserver_addr, default_xtcp_transport,
    is_websocket, is_wss,
};
use super::parse::{glob_match, parse_client, parse_include_file};
use super::protocol::Protocol;
use super::proxy::{ProxyConfig, VisitorConfig};

// ---------------------------------------------------------------------------
// 客户端配置
// ---------------------------------------------------------------------------

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

    /// **首次**登录被服务端**明确拒绝**后是否直接退出（对应 frp 的 `loginFailExit`，默认 `true`）。
    ///
    /// # 与官方 0.71 的差异（v0.7.5 起，针对开机自启）
    ///
    /// 官方实现里"连不上"和"认证被拒"都算登录失败，`loginFailExit = true` 时
    /// 第一次失败就退出。开机自启时网络、`proxyURL` 代理、KCP(UDP) 通道往往比
    /// frpc 晚就绪几秒，官方这种一刀切会让进程直接消失且**不再恢复**。
    ///
    /// 所以本项现在**只**管"服务端明确拒绝"（`LoginResp.error` /
    /// `ServerHello.error`：令牌错、用户被禁用、协议不兼容…）。"连不上"
    /// （拨号失败、DNS 未就绪、代理/KCP 通道未起、等待 LoginResp 超时）
    /// 一律按 1/2/4/8/10 秒退避**持续重试**，并在日志里逐次报出真实错误。
    ///
    /// **成功登录过之后**断线仍按 `reconnect_interval` 无限重连，不受本项影响。
    ///
    /// 想让"被拒"时也无限重试就写 `loginFailExit = false`。
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
# true：**首次**登录被服务端**明确拒绝**（令牌错 / 用户被禁用 / 协议不兼容）
#       时退出（退出码非 0），让启动器把配置错误如实报出来。
#       注意：**连不上**（网络未就绪、proxyURL / KCP(UDP) 通道还没起）不算在内，
#       会自动按 1/2/4/8/10 秒退避持续重试 —— 开机自启不再"10 秒后进程消失"。
# false：被拒绝时也无脑一直重试。手机热点 / 隧道机房抖动等场景更耐操。
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
