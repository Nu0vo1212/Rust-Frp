//! 代理与访客配置结构。
//!
//! 职责：定义 `HttpHeader`、`ProxyTransportConfig`、`ProxyConfig`、`VisitorConfig` 及其 Default/有效值方法。
//! 并发/所有权契约：配置在解析后只读，无锁、无共享可变状态；无 I/O。
//! 不变量：serde 默认值只由 `defaults` 模块定义；`Default::default()` 与反序列化必须得到同一组默认值。

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use super::defaults::{
    default_health_interval, default_health_max_failed, default_health_timeout, default_proxy_type,
    default_visitor_bind_addr, default_visitor_type,
};

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
