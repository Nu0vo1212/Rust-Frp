//! 配置解析入口与 frp 兼容层。
//!
//! 职责：`default_config_path`、glob 匹配、`includes` 单文件解析，以及 `parse_client` / `parse_server` / `parse_client_toml` / `parse_server_toml` 与插件类型清单。
//! 并发/所有权契约：纯解析函数，无锁、无共享可变状态；只读传入的文本，不写文件、不改全局状态。
//! 不变量：支持清单与插件判定**只在本模块定义**（`SUPPORTED_*` / `plugin_key`），其他模块必须复用而不是另写一套。

use std::path::{Path, PathBuf};

use crate::error::Result;

use super::client::ClientConfig;
use super::server::ServerConfig;
use super::validate::{reject_structured_proxy, reject_unimplemented_types};

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
pub(super) fn glob_match(pattern: &str, name: &str) -> bool {
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
pub(super) fn parse_include_file(raw: &str) -> Result<ClientConfig> {
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
pub(super) const SUPPORTED_PROXY_TYPES: &[&str] = &[
    "tcp", "udp", "http", "https", "tcpmux", "stcp", "xtcp", "sudp",
];
/// 访客类代理的类型清单（**唯一真源** —— 判定请用 [`is_visitor_type`]）。
pub const SUPPORTED_VISITOR_TYPES: &[&str] = &["stcp", "xtcp", "sudp"];

/// **唯一真源**：这个代理类型是不是"访客类"。
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
pub(super) fn plugin_key(raw: &str) -> String {
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
    // 在 normalize **之前**记录"用户有没有显式写过 bind_addr"。
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
