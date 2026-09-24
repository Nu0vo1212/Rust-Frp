//! 原版 frp 的 **legacy INI** 配置格式兼容层（`frpc.ini` / `frps.ini`）。
//!
//! # 为什么还要支持 INI
//!
//! frp 从 0.52 起主推 TOML，但 **INI 从来没有被删掉** —— 官方 frpc 至今仍然
//! 先做一次「内容嗅探」：只要文件里能解析出 `[common]` 段，就按 INI 走
//! （`pkg/config/load.go` 的 `DetectLegacyINIFormat`）。这不是历史包袱，
//! 而是**平台生态的现实**：
//!
//! * 各种 frp 面板 / 启动器会拿 `frpc -v` 的结果去问服务端"要哪种格式的配置"；
//!   NetTool 里樱花（SakuraFrp）就是这么协商的 —— 报告老版本就下发 INI，
//!   报告 0.52+ 才给 TOML；
//! * 存量用户的机器上到处都是 `frpc.ini`。
//!
//! rustunnel 之前只认 TOML，于是 Sakura 那条路会直接死在解析阶段，报错还
//! 完全看不出原因：
//!
//! ```text
//! Error: 读取配置 29104209.ini 失败
//! Caused by: toml error: TOML parse error at line 2, column 8
//!   2 | user = 2ko6vise7hy1nyuyyekm4ek5t75a0pc5
//!     |        ^
//!   expected newline, `#`
//! ```
//!
//! （INI 的 `user = <裸值>` 不带引号，TOML 解析器把 `2` 当数字读完之后就撞上了
//! `k`，于是抱怨"期望换行"。）
//!
//! # 做法：按 Go 源码逐条搬，不做"看起来差不多"的猜测
//!
//! 对应 `pkg/config/legacy/`：
//!
//! | 官方文件 | 这里对应的部分 |
//! |---|---|
//! | `load.go: DetectLegacyINIFormat` | [`is_legacy_ini`] |
//! | `legacy/client.go: ClientCommonConf` | [`common_section_to_table`] |
//! | `legacy/client.go: LoadAllProxyConfsFromIni` | [`legacy_client_to_toml`] |
//! | `legacy/proxy.go: NewProxyConfFromIni` / `decorate` | [`proxy_section_to_table`] |
//! | `legacy/visitor.go: BaseVisitorConf` | [`visitor_section_to_table`] |
//! | `legacy/client.go: renderRangeProxyTemplates` | [`expand_range_sections`] |
//! | `util.ParseRangeNumbers` | [`parse_range_numbers`] |
//! | `legacy/conversion.go: Convert_*_To_v1` | 全部键名映射（见下） |
//!
//! 中间产物是一棵 **rustunnel 原生键名**的 [`toml::Value`] 值树，再交给
//! `config::ClientConfig` 反序列化 —— 这样 INI 与 TOML 两条路最终汇进同一个结构体，
//! 不会出现"两条路行为不一致"的漂移。
//!
//! # 几处**必须显式写默认值**的地方（照抄 frp 的默认值，别跟着 rustunnel 走）
//!
//! frp 的 legacy 路径是「先用 [`GetDefaultClientConf`] 填默认值，再把 INI 覆盖上去」，
//! 而 rustunnel 自己的默认值有几处和它**不一致甚至相反**：
//!
//! | 配置项 | frp legacy 默认 | rustunnel 自身默认 | 处理 |
//! |---|---|---|---|
//! | `tls_enable` | **true**（v0.50 起） | false | 缺省时显式补 true |
//! | `disable_custom_tls_first_byte` | **true** | `tls_custom_first_byte = true`（语义相反） | 缺省时显式补 `!true` |
//! | `login_fail_exit` | true | true | 显式写一遍，免得以后漂 |
//! | `local_ip` | 空 → `Complete()` 补 `127.0.0.1` | — | 合并 `local_addr` 时补 |
//!
//! 漏掉前两条的后果很具体：樱花那种不给 `tls_enable` 的 INI，官方 frpc 是**带 TLS**
//! 去握手的，我们要是不补就成了明文握手 —— 服务端直接不认。

use std::collections::HashSet;

use toml::Value;

use crate::error::{Error, Result};

// ---------------------------------------------------------------------------
// 极简 INI 解析器
// ---------------------------------------------------------------------------

/// 一个 INI 文件（保序）。
///
/// 只实现 `gopkg.in/ini.v1` 在 frp 这条链路里**真正用到**的行为，不追求全兼容：
///
/// * `Insensitive: false` —— 键名与段名**大小写敏感**；
/// * `IgnoreInlineComment: true` —— **不**剥行内注释（`a = b # c` 的值就是 `b # c`）；
/// * 段前的裸键归 `DEFAULT` 段（对齐 ini.v1），而 `DEFAULT` 段会被当成"不是代理"跳过；
/// * 同名段/键重复出现时**合并/覆盖**（取最后一个），与 ini.v1 的 `KeysHash()` 一致。
#[derive(Debug, Clone, Default)]
pub struct Ini {
    sections: Vec<IniSection>,
}

/// INI 里的一个 `[section]`。
#[derive(Debug, Clone)]
pub struct IniSection {
    /// 段名（不含方括号）。
    pub name: String,
    /// `(键, 值)`，保序；值已 trim。
    keys: Vec<(String, String)>,
}

impl IniSection {
    /// 取键值（不存在返回 `None`）。
    pub fn get(&self, key: &str) -> Option<&str> {
        self.keys
            .iter()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v.as_str())
    }

    /// 取**非空**键值 —— frp 里大量出现 `if v == "" 就当没配` 的判断，
    /// 统一走这里，免得每处都写一遍 `filter(|s| !s.is_empty())`。
    fn non_empty(&self, key: &str) -> Option<&str> {
        self.get(key).map(str::trim).filter(|s| !s.is_empty())
    }

    /// 写/改一个键（`range:` 模板展开用）。
    fn set(&mut self, key: &str, value: String) {
        if let Some(slot) = self.keys.iter_mut().find(|(k, _)| k == key) {
            slot.1 = value;
        } else {
            self.keys.push((key.to_string(), value));
        }
    }

    /// 所有以 `prefix` 开头的键，返回**去掉前缀**后的 `(键, 值)`。
    ///
    /// 对应 frp 的 `GetMapWithoutPrefix` / `GetMapByPrefix`（`meta_xxx`、`plugin_xxx`）。
    fn with_prefix(&self, prefix: &str) -> Vec<(String, String)> {
        self.keys
            .iter()
            .filter_map(|(k, v)| {
                k.strip_prefix(prefix)
                    .filter(|rest| !rest.is_empty())
                    .map(|rest| (rest.to_string(), v.clone()))
            })
            .collect()
    }
}

impl Ini {
    /// 取段。
    pub fn section(&self, name: &str) -> Option<&IniSection> {
        self.sections.iter().find(|s| s.name == name)
    }

    /// 全部段（保序）。
    pub fn sections(&self) -> &[IniSection] {
        &self.sections
    }
}

/// 拆 `key = value` 或 `key : value`（以先出现的那个分隔符为准）。
///
/// 值**不做行内注释剥离** —— frp 用的是 `IgnoreInlineComment: true`。
fn split_key_value(line: &str) -> Option<(&str, &str)> {
    let eq = line.find('=');
    let colon = line.find(':');
    let pos = match (eq, colon) {
        (Some(a), Some(b)) => a.min(b),
        (Some(a), None) => a,
        (None, Some(b)) => b,
        (None, None) => return None,
    };
    let (k, v) = line.split_at(pos);
    Some((k.trim(), v[1..].trim()))
}

// ---------------------------------------------------------------------------
// 内容嗅探
// ---------------------------------------------------------------------------

/// 这份文本是不是原版 frp 的 legacy INI 配置。
///
/// 判定规则与 `pkg/config/load.go: DetectLegacyINIFormat` **完全一致**：
/// 能被 INI 解析，且存在 `[common]` 段。
///
/// ★ 注意官方是**先嗅探 INI、再考虑 TOML**（`LoadClientConfigResult` 里第一个分支
/// 就是它），所以一份"恰好有 `[common]` 段"的 TOML 也会被当成 INI —— 我们保持
/// 同样的顺序，不做"更聪明"的判断，否则两边行为会分叉。
pub fn is_legacy_ini(text: &str) -> bool {
    parse_ini(text)
        .map(|i| i.section("common").is_some())
        .unwrap_or(false)
}

/// 解析 INI（内部入口，带游标实现）。
pub fn parse_ini(text: &str) -> Option<Ini> {
    let mut sections: Vec<IniSection> = Vec::new();
    let mut cur: Option<usize> = None;

    for raw in text.lines() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with(';') || line.starts_with('#') {
            continue;
        }

        if let Some(rest) = line.strip_prefix('[') {
            let name = rest.rsplit_once(']')?.0.trim().to_string();
            if name.is_empty() {
                return None;
            }
            cur = Some(match sections.iter().position(|s| s.name == name) {
                Some(i) => i,
                None => {
                    sections.push(IniSection {
                        name,
                        keys: Vec::new(),
                    });
                    sections.len() - 1
                }
            });
            continue;
        }

        let (key, value) = split_key_value(line)?;
        if key.is_empty() {
            return None;
        }

        // 段前内容归 DEFAULT 段（ini.v1 语义），它不会被当作代理
        let idx = match cur {
            Some(i) => i,
            None => {
                let i = sections.len();
                sections.push(IniSection {
                    name: "DEFAULT".to_string(),
                    keys: Vec::new(),
                });
                cur = Some(i);
                i
            }
        };
        let sec = &mut sections[idx];
        if let Some(slot) = sec.keys.iter_mut().find(|(k, _)| *k == key) {
            slot.1 = value.to_string(); // 键重复 → 取最后一个
        } else {
            sec.keys.push((key.to_string(), value.to_string()));
        }
    }

    Some(Ini { sections })
}

// ---------------------------------------------------------------------------
// 取值助手
// ---------------------------------------------------------------------------

fn parse_bool(s: &str) -> Option<bool> {
    match s.trim().to_ascii_lowercase().as_str() {
        "1" | "t" | "true" | "yes" | "y" | "on" => Some(true),
        "0" | "f" | "false" | "no" | "n" | "off" => Some(false),
        _ => None,
    }
}

fn err(section: &str, key: &str, why: &str) -> Error {
    Error::Protocol(format!("ini 配置 [{section}] 的 {key} {why}"))
}

/// 字符串键：非空才写入。
fn put_str(out: &mut toml::Table, sec: &IniSection, ini_key: &str, native: &str) {
    if let Some(v) = sec.non_empty(ini_key) {
        out.insert(native.to_string(), Value::String(v.to_string()));
    }
}

/// 整数键：非空才写入，写不进去就报错（对齐 ini 的 `MapTo` 行为：
/// 类型不对是**错误**，不是静默忽略）。
fn put_int(out: &mut toml::Table, sec: &IniSection, ini_key: &str, native: &str) -> Result<()> {
    let Some(raw) = sec.non_empty(ini_key) else {
        return Ok(());
    };
    let n: i64 = raw
        .parse()
        .map_err(|_| err(&sec.name, ini_key, &format!("需要整数，实际是 {raw:?}")))?;
    out.insert(native.to_string(), Value::Integer(n));
    Ok(())
}

/// 布尔键：非空才写入。
fn put_bool(out: &mut toml::Table, sec: &IniSection, ini_key: &str, native: &str) -> Result<()> {
    let Some(raw) = sec.non_empty(ini_key) else {
        return Ok(());
    };
    let b =
        parse_bool(raw).ok_or_else(|| err(&sec.name, ini_key, &format!("不是布尔值：{raw:?}")))?;
    out.insert(native.to_string(), Value::Boolean(b));
    Ok(())
}

/// 取布尔键，缺省时用 `default` —— 给"frp 默认值与 rustunnel 不同"的几项用。
fn bool_or(sec: &IniSection, ini_key: &str, default: bool) -> Result<bool> {
    match sec.non_empty(ini_key) {
        Some(raw) => {
            parse_bool(raw).ok_or_else(|| err(&sec.name, ini_key, &format!("不是布尔值：{raw:?}")))
        }
        None => Ok(default),
    }
}

/// 逗号分隔列表（对齐 ini.v1 把 `[]string` 按 `,` 切开的行为）。
fn split_list(raw: &str) -> Vec<String> {
    raw.split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .collect()
}

/// 取逗号分隔列表键。
fn put_list(out: &mut toml::Table, sec: &IniSection, ini_key: &str, native: &str) {
    if let Some(raw) = sec.non_empty(ini_key) {
        let items = split_list(raw);
        if !items.is_empty() {
            out.insert(
                native.to_string(),
                Value::Array(items.into_iter().map(Value::String).collect()),
            );
        }
    }
}

/// 取 `前缀_xxx` 形式的键，产出一张子表（`meta_*` / `plugin_*`）。
fn collect_prefixed(sec: &IniSection, prefix: &str) -> toml::Table {
    sec.with_prefix(prefix)
        .into_iter()
        .map(|(k, v)| (k, Value::String(v)))
        .collect()
}

/// IPv6 字面量必须带方括号（`::1` + `22` → `[::1]:22`）。
fn join_host_port(host: &str, port: i64) -> String {
    let h = host.trim();
    if h.contains(':') && !h.starts_with('[') {
        format!("[{h}]:{port}")
    } else {
        format!("{h}:{port}")
    }
}

// ---------------------------------------------------------------------------
// [common] → rustunnel 原生顶层配置
// ---------------------------------------------------------------------------

/// 把 `[common]` 段搬成 rustunnel 原生的客户端顶层键。
///
/// 对应 `legacy.ClientCommonConf` + `Convert_ClientCommonConf_To_v1`，**只搬
/// rustunnel 真正有对应字段的部分**；剩下的（`admin_*` 面板、`dns_server`、
/// `includes`、`start`、`quic_*`、`*_oidc_*` 之类）按 frp 的 `strict=false` 语义忽略。
///
/// 专门说明两个**不能照搬 rustunnel 默认值**的项，理由见模块文档。
fn common_section_to_table(sec: &IniSection, out: &mut toml::Table) -> Result<()> {
    put_str(out, sec, "server_addr", "server_addr");
    put_int(out, sec, "server_port", "server_port")?;
    put_str(out, sec, "user", "user");
    // `authentication_method` 只支持默认的 token（rustunnel 没实现 OIDC）；
    // 老配置里的 `token` 就是它。
    put_str(out, sec, "token", "token");

    put_int(out, sec, "heartbeat_interval", "heartbeat_interval")?;
    put_int(out, sec, "heartbeat_timeout", "heartbeat_timeout")?;
    put_int(out, sec, "reconnect_interval", "reconnect_interval")?;
    put_int(out, sec, "pool_count", "pool_count")?;
    put_bool(out, sec, "tcp_mux", "tcp_mux")?;
    put_str(out, sec, "log_level", "log_level");
    put_str(out, sec, "tls_server_name", "tls_server_name");

    // 传输协议：INI 里叫 `protocol`（tcp / kcp / quic / websocket / wss），
    // rustunnel 叫 `transport_protocol`（只实现了 tcp / quic）。
    put_str(out, sec, "protocol", "transport_protocol");

    // ★ frp legacy 的 `tls_enable` 默认 **true**（v0.50 起），rustunnel 自身默认 false。
    //   缺省时必须显式补 true，否则樱花那种不写 tls_enable 的配置会变成明文握手。
    let tls_enable = bool_or(sec, "tls_enable", true)?;
    out.insert("tls_enable".to_string(), Value::Boolean(tls_enable));

    // ★ `disable_custom_tls_first_byte` 默认 true，而 rustunnel 的
    //   `tls_custom_first_byte` **语义相反**，所以取反后写。
    let disable_first_byte = bool_or(sec, "disable_custom_tls_first_byte", true)?;
    out.insert(
        "tls_custom_first_byte".to_string(),
        Value::Boolean(!disable_first_byte),
    );

    // `login_fail_exit` 两边默认值恰好都是 true，但仍显式写一遍，
    // 免得将来某一边改了默认值就悄悄漂掉。
    let login_fail_exit = bool_or(sec, "login_fail_exit", true)?;
    out.insert(
        "login_fail_exit".to_string(),
        Value::Boolean(login_fail_exit),
    );

    // `meta_xxx` → Login.metas（frp 的 `GetMapWithoutPrefix(keys, "meta_")`）
    let metas = collect_prefixed(sec, "meta_");
    if !metas.is_empty() {
        out.insert("metas".to_string(), Value::Table(metas));
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// 代理段 → rustunnel 原生 [[proxies]]
// ---------------------------------------------------------------------------

/// 官方 `legacy.proxyConfTypeMap` 里承认的代理类型。
const LEGACY_PROXY_TYPES: &[&str] = &[
    "tcp", "udp", "tcpmux", "http", "https", "stcp", "xtcp", "sudp",
];

/// 把一条代理段搬成 rustunnel 原生的 `[[proxies]]` 记录。
///
/// 对应 `legacy.NewProxyConfFromIni` + `BaseProxyConf.decorate` +
/// `Convert_ProxyConf_To_v1`。要点：
///
/// * 段名就是代理名（`decorate` 里的 `cfg.ProxyName = name`）；
/// * `type` 缺省是 **tcp**（不是 rustunnel 的"必填"）；
/// * `local_ip` + `local_port` 两段 → `local_addr = "ip:port"`；
///   `local_ip` 缺省补 `127.0.0.1`（对齐 v1 的 `Complete()`）；
/// * `meta_xxx` → 代理级 `metas`（进 `NewProxy.metas`，**不是**登录 metas）；
/// * `plugin_xxx` → rustunnel 的 `plugin_*` 平铺字段。
fn proxy_section_to_table(sec: &IniSection) -> Result<toml::Table> {
    let mut t = toml::Table::new();

    t.insert("name".to_string(), Value::String(sec.name.clone()));

    // `type` 缺省按 frp 取 tcp
    let ty = sec.non_empty("type").unwrap_or("tcp").to_ascii_lowercase();
    if !LEGACY_PROXY_TYPES.contains(&ty.as_str()) {
        return Err(err(
            &sec.name,
            "type",
            &format!("不是合法的代理类型：{ty:?}"),
        ));
    }
    // rustunnel 真正实现了 tcp / udp / http / https / stcp / sudp / xtcp；
    // 仅 tcpmux 没实现。**宁可报错也不静默当成 tcp** ——
    // 静默降级会"看起来跑通了"，实际把用户的流量按错的语义转发，
    // 比在启动阶段报一句清楚的话危险得多。
    if ty == "tcpmux" {
        return Err(Error::Protocol(format!(
            "代理 [{}] 的类型 {ty} 是原版 frp 的类型，rustunnel 尚未实现；\
             请改用 tcp/udp/http/https/stcp/sudp/xtcp，或在原版 frpc 上运行",
            sec.name
        )));
    }
    t.insert("type".to_string(), Value::String(ty));

    // 本机地址：两段合并成一段。`local_port` 缺省按 0（插件代理用不到它）。
    let host = sec.non_empty("local_ip").unwrap_or("127.0.0.1");
    let port: i64 = match sec.non_empty("local_port") {
        Some(raw) => raw.parse().map_err(|_| {
            err(
                &sec.name,
                "local_port",
                &format!("需要整数，实际是 {raw:?}"),
            )
        })?,
        None => 0,
    };
    t.insert(
        "local_addr".to_string(),
        Value::String(join_host_port(host, port)),
    );

    put_int(&mut t, sec, "remote_port", "remote_port")?;
    put_list(&mut t, sec, "custom_domains", "custom_domains");
    put_str(&mut t, sec, "subdomain", "subdomain");
    put_list(&mut t, sec, "locations", "locations");
    put_str(&mut t, sec, "http_user", "http_user");
    put_str(&mut t, sec, "http_pwd", "http_pwd");
    put_str(&mut t, sec, "host_header_rewrite", "host_header_rewrite");

    put_str(&mut t, sec, "group", "group");
    put_str(&mut t, sec, "group_key", "group_key");

    put_str(&mut t, sec, "bandwidth_limit", "bandwidth_limit");
    put_str(&mut t, sec, "bandwidth_limit_mode", "bandwidth_limit_mode");

    put_str(&mut t, sec, "health_check_type", "health_check_type");
    put_int(
        &mut t,
        sec,
        "health_check_timeout_s",
        "health_check_timeout_s",
    )?;
    put_int(
        &mut t,
        sec,
        "health_check_max_failed",
        "health_check_max_failed",
    )?;
    put_int(
        &mut t,
        sec,
        "health_check_interval_s",
        "health_check_interval_s",
    )?;
    put_str(&mut t, sec, "health_check_url", "health_check_url");

    // stcp / xtcp：`sk` → `secret_key`，`allow_users` 是逗号分隔
    put_str(&mut t, sec, "sk", "secret_key");
    put_list(&mut t, sec, "allow_users", "allow_users");

    // 代理级 metas（`meta_xxx`，进 NewProxy.metas）
    let metas = collect_prefixed(sec, "meta_");
    if !metas.is_empty() {
        t.insert("metas".to_string(), Value::Table(metas));
    }

    // 插件：`plugin = socks5` + `plugin_xxx` 参数。
    // rustunnel 的插件字段是平铺的，所以要把 frp 那套按插件不同的参数名
    // （socks5 用 plugin_user / http_proxy 用 plugin_http_user）归一到同一组字段。
    put_str(&mut t, sec, "plugin", "plugin");
    if let Some(v) = sec.non_empty("plugin_local_path") {
        t.insert(
            "plugin_local_path".to_string(),
            Value::String(v.to_string()),
        );
    }
    if let Some(v) = sec.non_empty("plugin_strip_prefix") {
        t.insert(
            "plugin_strip_prefix".to_string(),
            Value::String(v.to_string()),
        );
    }
    // unix_domain_socket 插件用 plugin_unix_path 指套接字
    if !t.contains_key("plugin_local_path") {
        if let Some(v) = sec.non_empty("plugin_unix_path") {
            t.insert(
                "plugin_local_path".to_string(),
                Value::String(v.to_string()),
            );
        }
    }
    // 用户名/密码：优先 socks5 的 `plugin_user`，退回 http_proxy / static_file 的 `plugin_http_user`
    if let Some(v) = sec
        .non_empty("plugin_user")
        .or_else(|| sec.non_empty("plugin_http_user"))
    {
        t.insert("plugin_user".to_string(), Value::String(v.to_string()));
    }
    if let Some(v) = sec
        .non_empty("plugin_passwd")
        .or_else(|| sec.non_empty("plugin_http_passwd"))
    {
        t.insert("plugin_passwd".to_string(), Value::String(v.to_string()));
    }

    Ok(t)
}

// ---------------------------------------------------------------------------
// 访客段 → rustunnel 原生 [[visitors]]
// ---------------------------------------------------------------------------

/// 官方 `legacy.visitorConfTypeMap` 里承认的访客类型。
const LEGACY_VISITOR_TYPES: &[&str] = &["stcp", "xtcp", "sudp"];

/// 把一条 `role = visitor` 的段搬成 `[[visitors]]`。
///
/// 对应 `legacy.BaseVisitorConf` + `Convert_VisitorConf_To_v1`。
/// `bind_addr` 缺省补 `127.0.0.1`（frp 的 `unmarshalFromIni` 就是这么干的）。
fn visitor_section_to_table(sec: &IniSection) -> Result<toml::Table> {
    let mut t = toml::Table::new();

    t.insert("name".to_string(), Value::String(sec.name.clone()));

    let ty = sec.non_empty("type").unwrap_or("").to_ascii_lowercase();
    if !LEGACY_VISITOR_TYPES.contains(&ty.as_str()) {
        return Err(err(
            &sec.name,
            "type",
            &format!("不是合法的访客类型（stcp/xtcp/sudp）：{ty:?}"),
        ));
    }
    t.insert("type".to_string(), Value::String(ty));

    put_str(&mut t, sec, "server_name", "server_name");
    put_str(&mut t, sec, "server_user", "server_user");
    put_str(&mut t, sec, "sk", "secret_key");
    put_int(&mut t, sec, "bind_port", "bind_port")?;

    let bind_addr = sec.non_empty("bind_addr").unwrap_or("127.0.0.1");
    t.insert(
        "bind_addr".to_string(),
        Value::String(bind_addr.to_string()),
    );

    Ok(t)
}

// ---------------------------------------------------------------------------
// range: 模板
// ---------------------------------------------------------------------------

/// 解析端口区间串：`6000`、`6000-6005`、`6000-6005,7000`。
///
/// 迁移自 `pkg/util/util.ParseRangeNumbers`，行为逐条对齐：
/// 以 `,` 分段、每段再以 `-` 切 1 或 2 个数、区间为闭区间、`max < min` 视为非法。
pub fn parse_range_numbers(range_str: &str) -> Result<Vec<i64>> {
    let mut numbers = Vec::new();
    for num_range in range_str.trim().split(',') {
        let parts: Vec<&str> = num_range.split('-').collect();
        match parts.len() {
            1 => {
                let n: i64 = parts[0]
                    .trim()
                    .parse()
                    .map_err(|_| Error::Protocol(format!("端口区间非法：{num_range:?}")))?;
                numbers.push(n);
            }
            2 => {
                let min: i64 = parts[0]
                    .trim()
                    .parse()
                    .map_err(|_| Error::Protocol(format!("端口区间非法：{num_range:?}")))?;
                let max: i64 = parts[1]
                    .trim()
                    .parse()
                    .map_err(|_| Error::Protocol(format!("端口区间非法：{num_range:?}")))?;
                if max < min {
                    return Err(Error::Protocol(format!(
                        "端口区间非法（上界小于下界）：{num_range:?}"
                    )));
                }
                numbers.extend(min..=max);
            }
            _ => {
                return Err(Error::Protocol(format!("端口区间非法：{num_range:?}")));
            }
        }
    }
    Ok(numbers)
}

/// 展开 `[range:名字]` 模板段。
///
/// 迁移自 `legacy.renderRangeProxyTemplates`：把 `local_port` / `remote_port`
/// 的区间**按位配对**，生成 `名字_0`、`名字_1`… 这些新段（追加在文件末尾，
/// 与官方的 `f.NewSection` 一致），原 `range:` 段本身不参与后续遍历。
fn expand_range_sections(ini: &Ini) -> Result<Vec<IniSection>> {
    let mut out: Vec<IniSection> = ini.sections().to_vec();

    for sec in ini
        .sections()
        .iter()
        .filter(|s| s.name.starts_with("range:"))
    {
        let local_raw = sec.non_empty("local_port").unwrap_or("");
        let remote_raw = sec.non_empty("remote_port").unwrap_or("");
        if local_raw.is_empty() || remote_raw.is_empty() {
            return Err(Error::Protocol(format!(
                "[{}] 的 local_port 或 remote_port 为空，range 模板必须两个都给",
                sec.name
            )));
        }

        let locals = parse_range_numbers(local_raw)?;
        let remotes = parse_range_numbers(remote_raw)?;
        if locals.len() != remotes.len() {
            return Err(Error::Protocol(format!(
                "[{}] 的 local_port 与 remote_port 数量不一致（{} vs {}）",
                sec.name,
                locals.len(),
                remotes.len()
            )));
        }
        if locals.is_empty() {
            return Err(Error::Protocol(format!(
                "[{}] 的 local_port / remote_port 为空区间",
                sec.name
            )));
        }

        let prefix = sec.name.trim_start_matches("range:").trim().to_string();
        for i in 0..locals.len() {
            let mut t = sec.clone();
            t.name = format!("{prefix}_{i}");
            t.set("local_port", locals[i].to_string());
            t.set("remote_port", remotes[i].to_string());
            out.push(t);
        }
    }

    Ok(out)
}

// ---------------------------------------------------------------------------
// 入口：INI 文本 → 原生值树
// ---------------------------------------------------------------------------

/// 一份 legacy INI 客户端配置 → rustunnel 原生键名的 [`toml::Value`]。
///
/// 对应 `legacy.ParseClientConfig` → `Convert_*_To_v1` 的整条链路。
pub fn legacy_client_to_value(text: &str) -> Result<Value> {
    let ini = parse_ini(text)
        .ok_or_else(|| Error::Protocol("不是合法的 ini 配置（存在无法解析的行）".to_string()))?;
    let common = ini
        .section("common")
        .ok_or_else(|| Error::Protocol("配置里找不到 [common] 段".to_string()))?;

    let mut root = toml::Table::new();
    common_section_to_table(common, &mut root)?;

    let sections = expand_range_sections(&ini)?;

    let mut proxies: Vec<Value> = Vec::new();
    let mut visitors: Vec<Value> = Vec::new();
    let mut seen: HashSet<String> = HashSet::new();

    for sec in &sections {
        // `DEFAULT`（段前裸键）与 `common` 不是代理；`range:` 已被展开
        if sec.name == "common" || sec.name == "DEFAULT" || sec.name.starts_with("range:") {
            continue;
        }

        // 对齐官方 `validateNoDuplicateNames`：同名代理会被静默覆盖、
        // 永远不启动，所以宁可报错。
        if !seen.insert(sec.name.clone()) {
            return Err(Error::Protocol(format!(
                "代理名 [{}] 重复（原版 frp 会拒绝这种配置）",
                sec.name
            )));
        }

        // `role` 缺省是 server（= 代理）
        match sec.non_empty("role").unwrap_or("server") {
            "server" => proxies.push(Value::Table(proxy_section_to_table(sec)?)),
            "visitor" => visitors.push(Value::Table(visitor_section_to_table(sec)?)),
            other => {
                return Err(Error::Protocol(format!(
                    "[{}] 的 role 只能是 server 或 visitor，实际是 {other:?}",
                    sec.name
                )))
            }
        }
    }

    if !proxies.is_empty() {
        root.insert("proxies".to_string(), Value::Array(proxies));
    }
    if !visitors.is_empty() {
        root.insert("visitors".to_string(), Value::Array(visitors));
    }

    Ok(Value::Table(root))
}

/// 一份 legacy INI 服务端配置 → rustunnel 原生键名的 [`toml::Value`]。
///
/// 对应 `legacy.ServerCommonConf` + `Convert_ServerCommonConf_To_v1`。
/// 同样只搬 rustunnel 有对应字段的部分。
pub fn legacy_server_to_value(text: &str) -> Result<Value> {
    let ini = parse_ini(text)
        .ok_or_else(|| Error::Protocol("不是合法的 ini 配置（存在无法解析的行）".to_string()))?;
    let common = ini
        .section("common")
        .ok_or_else(|| Error::Protocol("配置里找不到 [common] 段".to_string()))?;

    let mut root = toml::Table::new();
    let out = &mut root;

    put_str(out, common, "bind_addr", "bind_addr");
    put_int(out, common, "bind_port", "bind_port")?;
    put_str(out, common, "token", "token");
    put_str(out, common, "log_level", "log_level");
    put_int(out, common, "vhost_http_port", "vhost_http_port")?;
    put_int(out, common, "vhost_https_port", "vhost_https_port")?;
    put_str(out, common, "subdomain_host", "subdomain_host");
    put_bool(out, common, "tcp_mux", "tcp_mux")?;
    put_int(out, common, "heartbeat_timeout", "heartbeat_timeout")?;
    // frp 的 `tls_only`（强制客户端走 TLS）对应 rustunnel 的 `tls_force`
    put_bool(out, common, "tls_only", "tls_force")?;

    // 内置面板：frp 叫 dashboard_*，rustunnel 也叫 dashboard_*
    put_int(out, common, "dashboard_port", "dashboard_port")?;
    put_str(out, common, "dashboard_user", "dashboard_user");
    put_str(out, common, "dashboard_pwd", "dashboard_pwd");

    // 传输协议：INI 里没有 `protocol`，但老配置有 `kcp_bind_port` / `quic_bind_port`
    // 这类"用端口开协议"的写法。rustunnel 只实现了 tcp/quic，这里只在
    // 明确开了 quic 端口时映射，其余保持默认。
    if common
        .non_empty("quic_bind_port")
        .and_then(|s| s.parse::<u16>().ok())
        .is_some_and(|p| p != 0)
    {
        out.insert(
            "transport_protocol".to_string(),
            Value::String("quic".to_string()),
        );
    }

    Ok(Value::Table(root))
}

// ---------------------------------------------------------------------------
// 测试
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{parse_client, parse_client_toml, parse_server};

    /// 樱花（SakuraFrp）真实下发的 INI —— 结构与线上那份**逐字一致**，
    /// 只把 token 换成了占位值。
    ///
    /// 这份就是报 `line 2, column 8 / expected newline` 的元凶。
    const SAKURA_INI: &str = r#"[common]
user = 2ko6vise7hy1nyuyyekm4ek5t75a0pc5

sakura_mode = true
login_fail_exit = false

server_addr = frp-gap.com
server_port = 8088

[MCCC]
# id = 29104209
type = tcp
local_ip = 127.0.0.1
local_port = 25565
remote_port = 27064
"#;

    #[test]
    fn 樱花下发的_ini_能被识别并解析() {
        assert!(
            is_legacy_ini(SAKURA_INI),
            "有 [common] 段 → 判定为 legacy ini"
        );
        assert!(
            !is_legacy_ini("serverAddr = \"x\"\n"),
            "TOML 不该被认成 ini"
        );

        let cfg = parse_client(SAKURA_INI).unwrap();
        assert_eq!(cfg.server_addr, "frp-gap.com");
        assert_eq!(cfg.server_port, 8088);
        assert_eq!(cfg.user, "2ko6vise7hy1nyuyyekm4ek5t75a0pc5");
        // 樱花把凭证放在 user 里，token 没有 → 不能凭空造一个
        assert!(cfg.token.is_empty());
        // `login_fail_exit = false` 必须被读到（否则启动器会误判隧道已起）
        assert!(!cfg.login_fail_exit);

        assert_eq!(cfg.proxies.len(), 1);
        let p = &cfg.proxies[0];
        assert_eq!(p.name, "MCCC", "段名就是代理名");
        assert_eq!(p.proxy_type, "tcp");
        assert_eq!(p.local_addr, "127.0.0.1:25565");
        assert_eq!(p.remote_port, 27064);
    }

    /// ★ 关键默认值：INI 不写 `tls_enable` 时，官方 frpc 是**开 TLS** 的
    /// （v0.50 起默认 true），而 rustunnel 自身默认 false。
    /// 不显式补这一项，樱花这种配置就会明文握手、被服务端拒掉。
    #[test]
    fn ini_缺省_tls_enable_时按官方默认开_tls() {
        let cfg = parse_client(SAKURA_INI).unwrap();
        assert!(cfg.tls_enable, "legacy ini 缺省 tls_enable = true");
        // rustunnel 的 `tls_custom_first_byte` 与 frp 的 `disable_custom_tls_first_byte` 相反；
        // frp 默认 disable=true → 我们应为 false
        assert!(
            !cfg.tls_custom_first_byte,
            "legacy ini 缺省 disable_custom_tls_first_byte = true，取反后应是 false"
        );

        // 显式写 false 时要能覆盖
        let off = parse_client("[common]\nserver_addr = x\ntls_enable = false\n").unwrap();
        assert!(!off.tls_enable);

        // 显式写 disable=true/false 也都要对
        let d1 = parse_client("[common]\nserver_addr = x\ndisable_custom_tls_first_byte = false\n")
            .unwrap();
        assert!(d1.tls_custom_first_byte);
    }

    /// 老配置里没有 `type` 时默认 tcp（对齐 `NewProxyConfFromIni`）。
    #[test]
    fn ini_缺省_type_按官方默认取_tcp() {
        let cfg = parse_client(
            "[common]\nserver_addr = x\n\n[web]\nlocal_port = 80\nremote_port = 6000\n",
        )
        .unwrap();
        assert_eq!(cfg.proxies[0].proxy_type, "tcp");
        // local_ip 缺省补 127.0.0.1（对齐 v1 的 Complete()）
        assert_eq!(cfg.proxies[0].local_addr, "127.0.0.1:80");
    }

    /// `meta_xxx` 进 Login.metas；代理段里的 `meta_xxx` 进 NewProxy.metas。
    /// 两者不能串台（线上就是靠它认隧道）。
    #[test]
    fn ini_的_meta_前缀分顶层与代理级() {
        let text = r#"
[common]
server_addr = x
meta_token = login-token

[web]
type = tcp
local_port = 80
remote_port = 6000
meta_role = proxy-role
"#;
        let cfg = parse_client(text).unwrap();
        assert_eq!(
            cfg.metas.get("token").map(String::as_str),
            Some("login-token")
        );
        assert_eq!(
            cfg.proxies[0].metas.get("role").map(String::as_str),
            Some("proxy-role")
        );
        assert!(!cfg.metas.contains_key("role"));
        assert!(!cfg.proxies[0].metas.contains_key("token"));
    }

    /// 插件：`plugin_*` 前缀参数要归一到 rustunnel 的平铺字段；
    /// socks5 用 `plugin_user`、http_proxy/static_file 用 `plugin_http_user`。
    #[test]
    fn ini_的插件参数要归一化() {
        let socks = parse_client(
            "[common]\nserver_addr = x\n\n[p]\ntype = tcp\nremote_port = 1080\nplugin = socks5\nplugin_user = u\nplugin_passwd = p\n",
        )
        .unwrap();
        assert_eq!(socks.proxies[0].plugin, "socks5");
        assert_eq!(socks.proxies[0].plugin_user, "u");
        assert_eq!(socks.proxies[0].plugin_passwd, "p");

        let stat = parse_client(
            "[common]\nserver_addr = x\n\n[p]\ntype = tcp\nremote_port = 8080\nplugin = static_file\nplugin_local_path = /srv/www\nplugin_strip_prefix = /static\nplugin_http_user = hu\nplugin_http_passwd = hp\n",
        )
        .unwrap();
        let p = &stat.proxies[0];
        assert_eq!(p.plugin_local_path, "/srv/www");
        assert_eq!(p.plugin_strip_prefix, "/static");
        assert_eq!(p.plugin_user, "hu");
        assert_eq!(p.plugin_passwd, "hp");
    }

    /// http 代理的路由类字段 + 逗号分隔列表。
    #[test]
    fn ini_的_http_代理字段() {
        let cfg = parse_client(
            r#"
[common]
server_addr = x

[web]
type = http
local_port = 8080
custom_domains = a.example.com, b.example.com
subdomain = sub
locations = /api, /v2
http_user = u
http_pwd = p
host_header_rewrite = backend.internal
group = g1
group_key = k1
health_check_type = http
health_check_url = /healthz
bandwidth_limit = 25MB
bandwidth_limit_mode = server
"#,
        )
        .unwrap();
        let p = &cfg.proxies[0];
        assert_eq!(p.proxy_type, "http");
        assert_eq!(p.custom_domains, vec!["a.example.com", "b.example.com"]);
        assert_eq!(p.subdomain, "sub");
        assert_eq!(p.locations, vec!["/api", "/v2"]);
        assert_eq!(p.http_user, "u");
        assert_eq!(p.http_pwd, "p");
        assert_eq!(p.host_header_rewrite, "backend.internal");
        assert_eq!(p.group, "g1");
        assert_eq!(p.group_key, "k1");
        assert_eq!(p.health_check_type, "http");
        assert_eq!(p.health_check_url, "/healthz");
        assert_eq!(p.bandwidth_limit, "25MB");
        assert_eq!(p.bandwidth_limit_mode, "server");
    }

    /// sudp：与 stcp 同一套鉴权（`sk` / `allow_users`），但没有公网端口。
    ///
    /// 真机验证抓到的回归：sudp 是后加的类型，凡是"按类型分派"的地方都要
    /// 记得把它带上 —— 漏了的特征是**配置能解析、注册却被拒**（服务端报
    /// "必须配置 secret_key"），只在真跑一遍时才暴露。
    #[test]
    fn ini_的_sudp() {
        let cfg = parse_client(
            r#"
[common]
server_addr = x
user = alice

[p]
type = sudp
local_ip = 127.0.0.1
local_port = 18089
sk = s3cret
allow_users = bob

[v]
type = sudp
role = visitor
server_name = p
sk = s3cret
bind_addr = 127.0.0.1
bind_port = 19088
"#,
        )
        .unwrap();

        assert_eq!(cfg.proxies.len(), 1);
        assert_eq!(cfg.proxies[0].proxy_type, "sudp");
        assert_eq!(cfg.proxies[0].secret_key, "s3cret");
        assert_eq!(cfg.proxies[0].allow_users, vec!["bob"]);

        assert_eq!(cfg.visitors.len(), 1);
        assert_eq!(cfg.visitors[0].visitor_type, "sudp");
        assert_eq!(cfg.visitors[0].secret_key, "s3cret");
    }

    /// stcp / xtcp：`sk` → `secret_key`，`allow_users` 逗号分隔。
    #[test]
    fn ini_的_stcp_与_xtcp() {
        let cfg = parse_client(
            r#"
[common]
server_addr = x
user = alice

[secret]
type = stcp
local_port = 22
sk = s3cret
allow_users = bob, carol

[vis]
type = stcp
role = visitor
server_name = secret
server_user = alice
sk = s3cret
bind_addr = 127.0.0.1
bind_port = 9001
"#,
        )
        .unwrap();

        assert_eq!(cfg.proxies.len(), 1);
        assert_eq!(cfg.proxies[0].secret_key, "s3cret");
        assert_eq!(cfg.proxies[0].allow_users, vec!["bob", "carol"]);

        assert_eq!(cfg.visitors.len(), 1);
        let v = &cfg.visitors[0];
        assert_eq!(v.visitor_type, "stcp");
        assert_eq!(v.server_name, "secret");
        assert_eq!(v.server_user, "alice");
        assert_eq!(v.secret_key, "s3cret");
        assert_eq!(v.bind_port, 9001);
    }

    /// 访客的 `bind_addr` 缺省补 127.0.0.1（对齐 frp 的 `unmarshalFromIni`）。
    #[test]
    fn ini_访客缺省_bind_addr() {
        let cfg = parse_client(
            "[common]\nserver_addr = x\n\n[v]\ntype = stcp\nrole = visitor\nserver_name = p\nbind_port = 9001\n",
        )
        .unwrap();
        assert_eq!(cfg.visitors[0].bind_addr, "127.0.0.1");
    }

    /// `[range:名字]` 模板：按位配对展开成 `名字_0` / `名字_1`…
    /// （迁移自 `renderRangeProxyTemplates`）
    #[test]
    fn ini_的_range_模板要展开() {
        let cfg = parse_client(
            r#"
[common]
server_addr = x

[range:web]
type = tcp
local_port = 8000-8002
remote_port = 6000,7000,8000
"#,
        )
        .unwrap();

        assert_eq!(cfg.proxies.len(), 3);
        assert_eq!(cfg.proxies[0].name, "web_0");
        assert_eq!(cfg.proxies[0].local_addr, "127.0.0.1:8000");
        assert_eq!(cfg.proxies[0].remote_port, 6000);
        assert_eq!(cfg.proxies[1].name, "web_1");
        assert_eq!(cfg.proxies[1].local_addr, "127.0.0.1:8001");
        assert_eq!(cfg.proxies[1].remote_port, 7000);
        assert_eq!(cfg.proxies[2].name, "web_2");
        assert_eq!(cfg.proxies[2].remote_port, 8000);
    }

    #[test]
    fn range_端口区间解析对齐官方() {
        assert_eq!(parse_range_numbers("6000").unwrap(), vec![6000]);
        assert_eq!(
            parse_range_numbers("6000-6002").unwrap(),
            vec![6000, 6001, 6002]
        );
        assert_eq!(
            parse_range_numbers("1000-1001,2000").unwrap(),
            vec![1000, 1001, 2000]
        );
        // 上界小于下界 → 官方也是报错
        assert!(parse_range_numbers("6002-6000").is_err());
        assert!(parse_range_numbers("abc").is_err());
    }

    /// range 模板两段数量不一致要报错（官方：`local ports number should be same...`）
    #[test]
    fn range_模板数量不一致要报错() {
        let e = parse_client(
            "[common]\nserver_addr = x\n\n[range:web]\nlocal_port = 8000-8002\nremote_port = 6000\n",
        )
        .unwrap_err();
        assert!(format!("{e:#}").contains("数量不一致"), "实际报错：{e:#}");
    }

    /// INI 的行内注释**不剥离**（frp 用的是 `IgnoreInlineComment: true`），
    /// 而整行注释要跳过。这条容易"顺手做对"却和官方行为分叉，
    /// 所以直接断言原始值长什么样。
    #[test]
    fn ini_的行内注释不剥离而整行注释跳过() {
        let ini = parse_ini(
            "[common]\n; 整行注释\n# 也是整行注释\nserver_addr = x\n\n[web]\nremote_port = 6000 # 注释是值的一部分\n",
        )
        .unwrap();

        assert_eq!(ini.section("common").unwrap().get("server_addr"), Some("x"));
        assert_eq!(
            ini.section("web").unwrap().get("remote_port"),
            Some("6000 # 注释是值的一部分"),
            "行内注释必须原样留在值里，与 frp 的 IgnoreInlineComment 一致"
        );
    }

    /// `local_port = 80 # 注释` 在官方 INI 下值就是 `80 # 注释`，解析成整数会失败。
    /// 这里确认我们会报出**看得懂**的错误，而不是悄悄当成 0。
    #[test]
    fn ini_端口值带注释时报错要看得懂() {
        let e = parse_client(
            "[common]\nserver_addr = x\n\n[web]\ntype = tcp\nlocal_port = 80 # c\nremote_port = 6000\n",
        )
        .unwrap_err();
        assert!(format!("{e:#}").contains("local_port"), "实际报错：{e:#}");
    }

    /// 官方不认的类型要报错；官方认但 rustunnel 没实现的类型也要报错
    /// （**不能**静默当成 tcp，那会让隧道"看起来通了"但语义是错的）。
    #[test]
    fn ini_类型校验() {
        let bad =
            parse_client("[common]\nserver_addr = x\n\n[p]\ntype = nonsense\nlocal_port = 1\n");
        assert!(bad.is_err());

        let tcpmux =
            parse_client("[common]\nserver_addr = x\n\n[p]\ntype = tcpmux\nlocal_port = 1\n")
                .unwrap_err();
        assert!(format!("{tcpmux:#}").contains("尚未实现"));

        let bad_role = parse_client(
            "[common]\nserver_addr = x\n\n[p]\ntype = tcp\nrole = neither\nlocal_port = 1\n",
        )
        .unwrap_err();
        assert!(format!("{bad_role:#}").contains("role"));
    }

    /// 整数键写错必须**报错**，绝不能静默退回默认值。
    ///
    /// 这条测试是有来历的：`put_int` 一开始漏了 `?`，于是 `server_port = abc`
    /// 会被悄悄忽略、继续用默认的 7000 去连 —— 表面"能起来"，实际连到了别的
    /// 端口。表驱动地把每个整数键都点一遍，以后新增字段忘了处理也会红。
    #[test]
    fn ini_整数键写错要报错不能静默用默认值() {
        // 顶层 [common]
        for key in [
            "server_port",
            "heartbeat_interval",
            "heartbeat_timeout",
            "pool_count",
        ] {
            let text = format!("[common]\nserver_addr = x\n{key} = abc\n");
            let e = parse_client(&text)
                .map_err(|e| format!("{e:#}"))
                .expect_err(&format!("[{key}] 写错必须报错，不能静默用默认值"));
            assert!(e.contains("整数"), "[{key}] 的报错要说得清：{e}");
        }

        // 代理段
        for key in ["local_port", "remote_port"] {
            let text = format!("[common]\nserver_addr = x\n\n[p]\ntype = tcp\n{key} = abc\n");
            let e = parse_client(&text)
                .map_err(|e| format!("{e:#}"))
                .expect_err(&format!("[p] {key} 写错必须报错"));
            assert!(e.contains("整数"), "[p] {key} 的报错要说得清：{e}");
        }

        // 布尔键同样不能静默
        let e = parse_client("[common]\nserver_addr = x\ntls_enable = maybe\n").unwrap_err();
        assert!(format!("{e:#}").contains("布尔"), "实际报错：{e:#}");

        // 服务端也点一遍
        let e = parse_server("[common]\nbind_port = abc\n").unwrap_err();
        assert!(format!("{e:#}").contains("整数"), "实际报错：{e:#}");
    }

    /// 正方向检查：这些键**确实写进去了**（和上面那条互为补集，
    /// 光有"写错报错"是发现不了"整项被跳过"的）。
    #[test]
    fn ini_的整数与布尔键真的生效() {
        let cfg = parse_client(
            "[common]\nserver_addr = x\nserver_port = 8088\nheartbeat_interval = 11\nheartbeat_timeout = 33\npool_count = 4\ntcp_mux = false\n",
        )
        .unwrap();
        assert_eq!(cfg.server_port, 8088);
        assert_eq!(cfg.heartbeat_interval, 11);
        assert_eq!(cfg.heartbeat_timeout, 33);
        assert_eq!(cfg.pool_count, 4);
        assert!(!cfg.tcp_mux);
    }

    /// 没有 `[common]` 段 → 不是 legacy ini，退回 TOML 解析（对齐官方嗅探顺序）
    #[test]
    fn 没有_common_段的文本不当_ini() {
        assert!(!is_legacy_ini("[web]\ntype = tcp\n"));
        // 于是这份文本会走 TOML 路径并失败（TOML 里 `[web]` 是合法表，
        // 但没有 `server_addr` → 缺字段报错）
        assert!(parse_client("[web]\ntype = tcp\n").is_err());
    }

    /// 同名段/键重复：段合并、键取最后一个（对齐 ini.v1 的 `KeysHash()`）
    #[test]
    fn ini_重复段与重复键() {
        let ini = parse_ini("[common]\nserver_addr = a\nserver_addr = b\n[web]\ntype = tcp\n[web]\nlocal_port = 80\n").unwrap();
        let common = ini.section("common").unwrap();
        assert_eq!(common.get("server_addr"), Some("b"));
        let web = ini.section("web").unwrap();
        assert_eq!(web.get("type"), Some("tcp"));
        assert_eq!(web.get("local_port"), Some("80"));
    }

    /// `key : value` 也是合法分隔符（ini.v1 支持冒号）
    #[test]
    fn ini_支持冒号分隔() {
        let cfg = parse_client("[common]\nserver_addr : x\nserver_port : 7000\n").unwrap();
        assert_eq!(cfg.server_addr, "x");
        assert_eq!(cfg.server_port, 7000);
    }

    /// 段前的裸键归 DEFAULT 段，且**不会**被当成代理。
    #[test]
    fn ini_段前内容不会变成代理() {
        let cfg = parse_client("loose = 1\n\n[common]\nserver_addr = x\n").unwrap();
        assert!(cfg.proxies.is_empty(), "DEFAULT 段不该产出代理");
    }

    /// rustunnel 原生 TOML 完全不受影响（两条入口各走各的）
    #[test]
    fn 原生_toml_仍走_toml_路径() {
        let cfg = parse_client_toml(
            "server_addr = \"127.0.0.1\"\nserver_port = 17000\n\n[[proxies]]\nname = \"ssh\"\ntype = \"tcp\"\nlocal_addr = \"127.0.0.1:22\"\nremote_port = 6000\n",
        )
        .unwrap();
        assert_eq!(cfg.server_port, 17000);
        assert_eq!(cfg.proxies[0].local_addr, "127.0.0.1:22");
    }

    /// 原版 frps 的 ini 也要能认
    #[test]
    fn ini_服务端配置() {
        let cfg = parse_server(
            r#"
[common]
bind_addr = 0.0.0.0
bind_port = 7000
vhost_http_port = 8080
subdomain_host = example.com
token = st
log_level = info
tls_only = true

dashboard_addr = 0.0.0.0
dashboard_port = 7500
dashboard_user = admin
dashboard_pwd = pw
"#,
        )
        .unwrap();
        assert_eq!(cfg.bind_addr, "0.0.0.0");
        assert_eq!(cfg.bind_port, Some(7000));
        assert_eq!(cfg.vhost_http_port, Some(8080));
        assert_eq!(cfg.subdomain_host, "example.com");
        assert_eq!(cfg.token, "st");
        assert!(cfg.tls_force);
        assert_eq!(cfg.dashboard_port, Some(7500));
        assert_eq!(cfg.dashboard_user, "admin");
        assert_eq!(cfg.dashboard_pwd, "pw");
    }

    /// IPv6 的 local_ip 合并要带方括号
    #[test]
    fn ini_ipv6_本机地址() {
        let cfg = parse_client(
            "[common]\nserver_addr = x\n\n[v6]\ntype = tcp\nlocal_ip = ::1\nlocal_port = 22\nremote_port = 6000\n",
        )
        .unwrap();
        assert_eq!(cfg.proxies[0].local_addr, "[::1]:22");
    }

    /// 未实现的键（面板、`start`、`includes`、OIDC…）按 frp 的 `strict=false` 忽略，
    /// 不能把整份配置弄挂。
    #[test]
    fn ini_未知键要忽略() {
        let cfg = parse_client(
            r#"
[common]
server_addr = x
sakura_mode = true
dns_server = 8.8.8.8
admin_port = 7400
authentication_method = oidc
start = web
udp_packet_size = 1500
"#,
        )
        .unwrap();
        assert_eq!(cfg.server_addr, "x");
    }
}
