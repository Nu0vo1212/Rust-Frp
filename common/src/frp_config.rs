//! 原版 frp（Go 版）TOML 配置兼容层。
//!
//! # 为什么需要
//!
//! rustunnel 的目标之一是**能直接顶替原版 frpc / frps**：机器上原来跑的是
//! `frpc -c frpc.toml`，换成 rustunnel 之后最好连配置都不用改。但两边的字段名
//! 并不一样：
//!
//! | 语义 | 原版 frp | rustunnel |
//! |---|---|---|
//! | 服务端地址 | `serverAddr` / `serverPort` | `server_addr` / `server_port` |
//! | 内网服务 | `localIP` + `localPort`（两段） | `local_addr = "ip:port"`（合并） |
//! | 公网端口 | `remotePort` | `remote_port` |
//! | 认证令牌 | `auth.token`（老写法 `[common] token`） | `token` |
//! | 附加信息 | `[metadatas]`（顶层） / `[proxies.metadatas]`（代理级） | `metas` |
//! | 带宽限流 | `[proxies.transport] bandwidthLimit` | `bandwidth_limit` |
//! | 负载均衡 | `[proxies.loadBalancer] group` | `group` |
//! | 健康检查 | `[proxies.healthCheck] type/path/...` | `health_check_type/...` |
//!
//! 照抄一份 frp 配置过来，rustunnel 会在**解析阶段**直接退出，而且报错看不出
//! 「其实是字段名不一样」：
//!
//! ```text
//! Error: 读取配置 frpc.toml 失败
//! Caused by: toml error: TOML parse error at line 8, column 1
//!   8 | [[proxies]]
//!     | ^^^^^^^^^^^
//!   missing field `local_addr`
//! ```
//!
//! 真实现场：NetTool 的「LoliaFRP 本地开启」会把 Lolia 平台（`api.lolia.link`）
//! 下发的 `config` 原样写盘、再拉起 frpc。平台给的就是标准 frp 写法，所以换成
//! rustunnel 的 frpc 必然报上面这个错（原版 frpc 则一切正常）。
//!
//! # 做法
//!
//! 解析拆成两步：先把文本读成 [`toml::Value`] 这棵「值树」，把 frp 风格的键
//! **搬到** rustunnel 的键名上，再转成结构体。
//!
//! 唯一的原则是 **只补不覆盖**：目标键已经存在（说明写的是 rustunnel 原生写法）
//! 就保留原值。于是两种写法可以在同一份文件里混用，rustunnel 自己的配置语义
//! 完全不受影响。

use toml::Value;

/// 键名搬家表：`(frp 的键, rustunnel 的键)`。
type Renames = &'static [(&'static str, &'static str)];

// ---------------------------------------------------------------------------
// 基础操作
// ---------------------------------------------------------------------------

/// 把 `from` 的值搬到 `to`。
///
/// 目标已存在时**保留目标值**（rustunnel 原生写法优先），并丢弃来源键 ——
/// 否则两套写法同时出现会让 serde 撞上 "duplicate field"。
fn rename(t: &mut toml::Table, from: &str, to: &str) {
    if from == to {
        return;
    }
    if t.contains_key(to) {
        t.remove(from);
        return;
    }
    if let Some(v) = t.remove(from) {
        t.insert(to.to_string(), v);
    }
}

/// 批量搬家。
fn rename_all(t: &mut toml::Table, pairs: Renames) {
    for (from, to) in pairs {
        rename(t, from, to);
    }
}

/// 沿 `path` 逐段下钻取一张子表。
fn sub_table_at<'a>(t: &'a toml::Table, path: &[&str]) -> Option<&'a toml::Table> {
    let mut node = t.get(*path.first()?)?;
    for seg in &path[1..] {
        node = node.get(*seg)?;
    }
    node.as_table()
}

/// 沿 `path` 找到一张子表，把其中 `pairs` 列出的键搬到 `t` 上（不覆盖已有键）。
///
/// 用于 `[proxies.transport]` / `[proxies.healthCheck]` 这类"frp 分子表、
/// rustunnel 平铺字段"的差异。任一路径段不存在或不是表则什么都不做。
fn hoist(t: &mut toml::Table, path: &[&str], pairs: Renames) {
    // 先把值 clone 出来，块结束后对 t 的可变借用才不会被读取时的借用挡住
    let picked: Vec<(&'static str, Value)> = match sub_table_at(t, path) {
        Some(sub) => pairs
            .iter()
            .filter_map(|(from, to)| sub.get(*from).map(|v| (*to, v.clone())))
            .collect(),
        None => return,
    };
    for (to, v) in picked {
        if !t.contains_key(to) {
            t.insert(to.to_string(), v);
        }
    }
}

/// 与 [`hoist`] 同款，但搬运的布尔值要**取反** —— 用于 `disableCustomTLSFirstByte`
/// 这种"frp 说禁用、rustunnel 说启用"的反义键。
fn hoist_inverted_bool(t: &mut toml::Table, path: &[&str], from: &str, to: &str) {
    let v = sub_table_at(t, path)
        .and_then(|sub| sub.get(from))
        .and_then(|v| v.as_bool());
    if let Some(b) = v {
        if !t.contains_key(to) {
            t.insert(to.to_string(), Value::Boolean(!b));
        }
    }
}

/// 遍历根表下某个数组表（`[[proxies]]` / `[[visitors]]`）里的每条记录。
fn for_each_record(root: &mut toml::Value, key: &str, f: impl Fn(&mut toml::Table)) {
    let Some(Value::Array(items)) = root.get_mut(key) else {
        return;
    };
    for item in items.iter_mut() {
        if let Value::Table(t) = item {
            f(t);
        }
    }
}

/// 把整数或数字字符串统一成端口号的十进制写法。
fn port_text(v: &Value) -> Option<String> {
    if let Some(i) = v.as_integer() {
        return Some(i.to_string());
    }
    v.as_str().map(|s| s.trim().to_string())
}

/// IPv6 字面量必须带方括号，否则 `::1` + `22` 拼出来的 `::1:22` 没法解析。
fn bracket_if_v6(host: &str) -> String {
    if host.contains(':') && !host.starts_with('[') {
        format!("[{}]", host)
    } else {
        host.to_string()
    }
}

/// `localIP` + `localPort` 两段式 → rustunnel 的 `local_addr = "ip:port"` 合并式。
///
/// 只补不覆盖：`local_addr` 已经写了就原样保留（顺手清掉那两个 frp 键，免得留冗余）。
fn merge_local_addr(p: &mut toml::Table) {
    if p.contains_key("local_addr") {
        p.remove("local_ip");
        p.remove("local_port");
        return;
    }
    let ip = p.remove("local_ip");
    let port = p.remove("local_port");

    let addr = match (ip, port) {
        (Some(ip_v), Some(port_v)) => {
            let host = ip_v.as_str().unwrap_or("").trim().to_string();
            match port_text(&port_v) {
                Some(pt) if host.is_empty() => format!("127.0.0.1:{}", pt),
                Some(pt) => format!("{}:{}", bracket_if_v6(&host), pt),
                None if !host.is_empty() => host,
                None => return,
            }
        }
        // 只给 localIP：原样留着当地址，让下游解析给出明确的错误
        (Some(ip_v), None) => match ip_v.as_str() {
            Some(s) if !s.trim().is_empty() => s.trim().to_string(),
            _ => return,
        },
        // frp 的 localIP/localPort 都带默认值，可以全省略 —— 那种写法只在插件
        // 代理上成立（插件本身就是本地服务）。按 frp 的默认值补齐，免得用户从
        // frp 搬过来的插件配置直接死在 "missing field local_addr" 上。
        (None, None) => {
            if p.contains_key("plugin") {
                "127.0.0.1:0".to_string()
            } else {
                return;
            }
        }
        (None, Some(port_v)) => match port_text(&port_v) {
            Some(pt) => format!("127.0.0.1:{}", pt),
            None => return,
        },
    };

    p.insert("local_addr".to_string(), Value::String(addr));
}

// ---------------------------------------------------------------------------
// 客户端
// ---------------------------------------------------------------------------

/// 客户端配置的顶层键名映射。
const CLIENT_TOP: Renames = &[
    ("serverAddr", "server_addr"),
    ("serverPort", "server_port"),
    ("serverWorkPort", "server_work_port"),
    ("clientID", "client_id"),
    ("clientId", "client_id"),
    ("logLevel", "log_level"),
    ("transportProtocol", "transport_protocol"),
    ("heartbeatInterval", "heartbeat_interval"),
    ("heartbeatTimeout", "heartbeat_timeout"),
    ("reconnectInterval", "reconnect_interval"),
    ("loginFailExit", "login_fail_exit"),
    ("poolCount", "pool_count"),
    ("tcpMux", "tcp_mux"),
    ("p2pPort", "p2p_port"),
    ("p2pEnable", "p2p_enable"),
];

/// `[[proxies]]` 一条记录里的键名映射。
const PROXY_FIELDS: Renames = &[
    ("localIP", "local_ip"),
    ("localPort", "local_port"),
    ("remotePort", "remote_port"),
    ("customDomains", "custom_domains"),
    ("httpUser", "http_user"),
    ("httpPwd", "http_pwd"),
    ("httpPassword", "http_pwd"),
    ("hostHeaderRewrite", "host_header_rewrite"),
    ("secretKey", "secret_key"),
    ("allowUsers", "allow_users"),
];

/// `[[visitors]]` 一条记录里的键名映射。
const VISITOR_FIELDS: Renames = &[
    ("serverName", "server_name"),
    ("bindAddr", "bind_addr"),
    ("bindPort", "bind_port"),
];

/// frp 用 `[proxies.plugin]` **子表**描述客户端插件，rustunnel 却用平铺的
/// `plugin` **字符串**字段 —— 键名正好撞车，所以不能走 [`hoist`]（目标键已存在
/// 会被判成"保留原生值"而跳过）。这里单独处理：先把子表整个摘下来，再逐键提上去。
fn extract_plugin(p: &mut toml::Table) {
    // 原生写法（`plugin = "socks5"` 已是字符串）就什么都不做
    if !matches!(p.get("plugin"), Some(Value::Table(_))) {
        return;
    }
    let Some(Value::Table(mut sub)) = p.remove("plugin") else {
        return;
    };
    let pairs: Renames = &[
        ("type", "plugin"),
        ("localPath", "plugin_local_path"),
        ("stripPrefix", "plugin_strip_prefix"),
        ("username", "plugin_user"),
        ("password", "plugin_passwd"),
    ];
    for (from, to) in pairs {
        if let Some(v) = sub.remove(*from) {
            if !p.contains_key(*to) {
                p.insert((*to).to_string(), v);
            }
        }
    }
}

/// 把一份客户端配置的键名从 frp 风格规范化成 rustunnel 风格（原地修改）。
pub fn normalize_client(root: &mut toml::Value) {
    let Some(t) = root.as_table_mut() else {
        return;
    };

    rename_all(t, CLIENT_TOP);

    // `[transport]`：frp 把多路复用 / 心跳 / 传输协议都塞在这里，rustunnel 是平铺字段
    hoist(
        t,
        &["transport"],
        &[
            ("poolCount", "pool_count"),
            ("tcpMux", "tcp_mux"),
            ("protocol", "transport_protocol"),
            // frp 的线协议版本（`"v1"` / `"v2"`，默认 `"v1"`）。
            // rustunnel 里就叫 `protocol`，取值也兼容 `"v1"` / `"v2"` 的裸写法。
            ("wireProtocol", "protocol"),
            ("heartbeatInterval", "heartbeat_interval"),
            ("heartbeatTimeout", "heartbeat_timeout"),
        ],
    );
    hoist(
        t,
        &["transport", "tls"],
        &[("enable", "tls_enable"), ("serverName", "tls_server_name")],
    );
    hoist_inverted_bool(
        t,
        &["transport", "tls"],
        "disableCustomTLSFirstByte",
        "tls_custom_first_byte",
    );

    // 认证令牌：frp 新写法 `auth.token`，老写法 `[common] token`。
    // rustunnel 只有顶层 `token` 一个。
    hoist(t, &["auth"], &[("token", "token")]);

    // `[metadatas]` 要**整表透传**（→ `metas` → `Login.metas`）：LoliaFRP 这类
    // 平台就是靠 `metas["token"]` 认出隧道的，丢了它服务端只会回一句
    // 「FRPC 配置文件错误」。
    //
    // 注意这是**顶层**的 `[metadatas]`，只进登录消息；`[[proxies]]` 里那份
    // `[proxies.metadatas]` 是另一回事（进 `NewProxy.metas`），在下面单独搬。
    //
    // ★ 千万别顺手把 `metadatas.token` 当成本地认证 token —— 实测反过来：
    //   frp 里 `metadatas` 只是"随消息带过去的附加信息"，**不参与认证**。
    //   平台给的这份配置没有 `auth.token`，服务端的全局 token 也是空的，
    //   于是官方 frpc 发的是 `md5("" + timestamp)`。我们若拿 `metadatas.token`
    //   去算 privilege_key，服务端会直接回
    //   「token in login doesn't match token from configuration」。
    rename(t, "metadatas", "metas");

    // 日志：`[log] level` 与顶层 `logLevel` 等价
    hoist(t, &["log"], &[("level", "log_level")]);

    for_each_record(root, "proxies", |p| {
        rename_all(p, PROXY_FIELDS);

        hoist(
            p,
            &["transport"],
            &[
                ("bandwidthLimit", "bandwidth_limit"),
                ("bandwidthLimitMode", "bandwidth_limit_mode"),
            ],
        );
        hoist(
            p,
            &["loadBalancer"],
            &[("group", "group"), ("groupKey", "group_key")],
        );
        hoist(
            p,
            &["healthCheck"],
            &[
                ("type", "health_check_type"),
                ("timeoutSeconds", "health_check_timeout_s"),
                ("maxFailed", "health_check_max_failed"),
                ("intervalSeconds", "health_check_interval_s"),
                ("path", "health_check_url"),
            ],
        );

        extract_plugin(p);

        // 代理级 `[proxies.metadatas]` → `metas`（会随 `NewProxy` 上报）。
        // 注意这和顶层的 `[metadatas]`（→ `Login.metas`）是两份东西，
        // 官方 frpc 也是分开的：顶层进 `Login.Metas`，这一份进 `NewProxy.Metas`。
        rename(p, "metadatas", "metas");

        merge_local_addr(p);
    });

    for_each_record(root, "visitors", |v| {
        rename_all(v, VISITOR_FIELDS);
    });
}

// ---------------------------------------------------------------------------
// 服务端
// ---------------------------------------------------------------------------

/// 服务端配置的顶层键名映射。
const SERVER_TOP: Renames = &[
    ("bindAddr", "bind_addr"),
    ("bindPort", "bind_port"),
    ("logLevel", "log_level"),
    ("vhostHTTPPort", "vhost_http_port"),
    ("vhostHTTPSPort", "vhost_https_port"),
    ("subdomainHost", "subdomain_host"),
    ("transportProtocol", "transport_protocol"),
];

/// 把一份服务端配置的键名从 frp 风格规范化成 rustunnel 风格（原地修改）。
pub fn normalize_server(root: &mut toml::Value) {
    let Some(t) = root.as_table_mut() else {
        return;
    };

    rename_all(t, SERVER_TOP);

    // frp 的 `bindPort` 表示"控制连接与工作连接共用同一个端口"，rustunnel 用
    // `bind_port` 表示同一件事；另外还认一下更老的 `controlPort`。
    if !t.contains_key("bind_port") {
        if let Some(v) = t.remove("controlPort") {
            t.insert("bind_port".to_string(), v);
        }
    }

    hoist(
        t,
        &["transport"],
        &[
            ("tcpMux", "tcp_mux"),
            ("protocol", "transport_protocol"),
            // frp 的线协议版本。服务端**按魔术字自动识别**对端走 v1 还是 v2
            // （与官方 frps 的 `wire.CheckMagic` 一致），这一项只是为了
            // "原版 frps 配置能直接喂进来"而接受它。
            ("wireProtocol", "protocol"),
            ("heartbeatTimeout", "heartbeat_timeout"),
        ],
    );
    hoist(t, &["transport", "tls"], &[("force", "tls_force")]);

    hoist(t, &["auth"], &[("token", "token")]);
    hoist(t, &["log"], &[("level", "log_level")]);

    // 内置面板：frp 放在 `[webServer]`
    hoist(
        t,
        &["webServer"],
        &[
            ("port", "dashboard_port"),
            ("user", "dashboard_user"),
            ("password", "dashboard_pwd"),
        ],
    );
}

// ---------------------------------------------------------------------------
// 测试
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use crate::config::{parse_client_toml, parse_server_toml};

    /// LoliaFRP 平台真实下发的配置（`GET /user/frpc/config`，Base64 解出来的原文）。
    /// 这份就是线上报 `missing field local_addr` 的那一份，一字未改。
    const LOLIA_FRPC: &str = r#"
serverAddr = 'cn-hz-2.qwq.fan'
serverPort = 30000
user = '2569'

[metadatas]
token = 'x8p5mo0u8ips3lmohc67r58mejp7uthf'

[[proxies]]
name = 'c0462d9ce7e44bce97e626c4ae880905'
type = 'tcp'
localIP = '127.0.0.1'
localPort = 25565
remotePort = 38725

[proxies.transport]
bandwidthLimit = '25MB'
bandwidthLimitMode = 'server'
"#;

    #[test]
    fn 原版_frp_配置应当可以直接解析() {
        let cfg = parse_client_toml(LOLIA_FRPC).unwrap();

        assert_eq!(cfg.server_addr, "cn-hz-2.qwq.fan");
        assert_eq!(cfg.server_port, 30000);
        assert_eq!(cfg.user, "2569");
        // `[metadatas]` 里的 token 不是认证 token（frp 语义：它只随消息带给服务端）
        assert!(cfg.token.is_empty(), "metadatas.token 不该被当成认证 token");
        // ★ 关键：`[metadatas]` 必须原样进 Login.metas / NewProxy.metas，
        //   否则服务端认不出隧道，只会回「FRPC 配置文件错误」
        assert_eq!(
            cfg.metas.get("token").map(String::as_str),
            Some("x8p5mo0u8ips3lmohc67r58mejp7uthf")
        );

        assert_eq!(cfg.proxies.len(), 1);
        let p = &cfg.proxies[0];
        assert_eq!(p.name, "c0462d9ce7e44bce97e626c4ae880905");
        assert_eq!(p.proxy_type, "tcp");
        // 两段式 localIP/localPort 合并成一段
        assert_eq!(p.local_addr, "127.0.0.1:25565");
        assert_eq!(p.remote_port, 38725);
        // [proxies.transport] bandwidthLimit → 平铺的 bandwidth_limit
        assert_eq!(p.bandwidth_limit, "25MB");
        assert_eq!(p.bandwidth_limit_mode, "server");
        // 代理级 metadatas：这份 Lolia 配置里没有，就该是空的（顶层那份不算）
        assert!(
            p.metas.is_empty(),
            "顶层 [metadatas] 不该跑到代理级 metas 里"
        );
    }

    /// 原版 frp 的 `loginFailExit` 也要认，默认值跟随官方取 `true`。
    ///
    /// 这一项直接决定"启动器能不能看出隧道没起来"，见 `ClientConfig::login_fail_exit`。
    #[test]
    fn login_fail_exit_默认跟随官方取_true() {
        // 没写 → 默认 true（官方 `util.EmptyOr(..., lo.ToPtr(true))`）
        assert!(
            parse_client_toml("server_addr = \"x\"")
                .unwrap()
                .login_fail_exit
        );

        // 原版 frp 写法
        let off = parse_client_toml("server_addr = \"x\"\nloginFailExit = false").unwrap();
        assert!(!off.login_fail_exit);

        // rustunnel 原生写法，以及"原生优先"规则
        let native = parse_client_toml("server_addr = \"x\"\nlogin_fail_exit = false").unwrap();
        assert!(!native.login_fail_exit);
        let both =
            parse_client_toml("server_addr = \"x\"\nloginFailExit = true\nlogin_fail_exit = false")
                .unwrap();
        assert!(!both.login_fail_exit, "两种写法混用时应以原生字段为准");
    }

    /// 代理级 `[proxies.metadatas]` 与顶层 `[metadatas]` 是两份互不干扰的数据。
    #[test]
    fn 顶层与代理级_metadatas_各归各的() {
        let text = r#"
serverAddr = "x"
user = "alice"

[metadatas]
token = "login-token"

[[proxies]]
name = "p"
type = "tcp"
localIP = "127.0.0.1"
localPort = 1
remotePort = 2

[proxies.metadatas]
role = "proxy-role"
"#;
        let cfg = parse_client_toml(text).unwrap();
        assert_eq!(
            cfg.metas.get("token").map(String::as_str),
            Some("login-token")
        );
        assert_eq!(
            cfg.proxies[0].metas.get("role").map(String::as_str),
            Some("proxy-role")
        );
        // 不能互相串台
        assert!(!cfg.proxies[0].metas.contains_key("token"));
        assert!(!cfg.metas.contains_key("role"));
    }

    #[test]
    fn frp_现代写法的_auth_与_transport_子表也要认() {
        let text = r#"
serverAddr = "example.com"
serverPort = 7000
logLevel = "debug"

[auth]
token = "s3cret"

[transport]
poolCount = 4
tcpMux = false
protocol = "quic"

[transport.tls]
enable = true
serverName = "example.com"
disableCustomTLSFirstByte = true

[[proxies]]
name = "web"
type = "http"
localIP = "10.0.0.5"
localPort = 8080
customDomains = ["a.example.com", "b.example.com"]
httpUser = "u"
httpPwd = "p"
hostHeaderRewrite = "backend"

[proxies.loadBalancer]
group = "g1"
groupKey = "k1"

[proxies.healthCheck]
type = "http"
path = "/healthz"
timeoutSeconds = 5
maxFailed = 2
intervalSeconds = 7
"#;
        let cfg = parse_client_toml(text).unwrap();

        assert_eq!(cfg.token, "s3cret");
        assert_eq!(cfg.log_level, "debug");
        assert_eq!(cfg.pool_count, 4);
        assert!(!cfg.tcp_mux);
        assert_eq!(cfg.transport_protocol, "quic");
        assert!(cfg.tls_enable);
        assert_eq!(cfg.tls_server_name, "example.com");
        // frp 说的是"禁用自定义首字节"，rustunnel 说的是"启用" —— 语义相反
        assert!(!cfg.tls_custom_first_byte);

        let p = &cfg.proxies[0];
        assert_eq!(p.local_addr, "10.0.0.5:8080");
        assert_eq!(p.custom_domains, vec!["a.example.com", "b.example.com"]);
        assert_eq!(p.http_user, "u");
        assert_eq!(p.http_pwd, "p");
        assert_eq!(p.host_header_rewrite, "backend");
        assert_eq!(p.group, "g1");
        assert_eq!(p.group_key, "k1");
        assert_eq!(p.health_check_type, "http");
        assert_eq!(p.health_check_url, "/healthz");
        assert_eq!(p.health_check_timeout_s, 5);
        assert_eq!(p.health_check_max_failed, 2);
        assert_eq!(p.health_check_interval_s, 7);
    }

    #[test]
    fn rustunnel_原生写法完全不受影响() {
        let text = r#"
server_addr = "127.0.0.1"
server_port = 17000
token = "t"

[[proxies]]
name = "ssh"
type = "tcp"
local_addr = "127.0.0.1:22"
remote_port = 6000
"#;
        let cfg = parse_client_toml(text).unwrap();
        assert_eq!(cfg.server_addr, "127.0.0.1");
        assert_eq!(cfg.proxies[0].local_addr, "127.0.0.1:22");
    }

    #[test]
    fn 两种写法混用时以_rustunnel_原生字段为准() {
        let text = r#"
serverAddr = "frp.example.com"
server_addr = "native.example.com"
serverPort = 7000

[[proxies]]
name = "mix"
type = "tcp"
local_addr = "1.1.1.1:11"
localIP = "2.2.2.2"
localPort = 22
"#;
        let cfg = parse_client_toml(text).unwrap();
        // `server_addr` 已存在 → 保留原生值，丢弃 serverAddr
        assert_eq!(cfg.server_addr, "native.example.com");
        // `local_addr` 已存在 → 保留原生值，忽略 localIP/localPort
        assert_eq!(cfg.proxies[0].local_addr, "1.1.1.1:11");
    }

    #[test]
    fn ipv6_地址合并要加方括号() {
        let text = r#"
server_addr = "x"
[[proxies]]
name = "v6"
type = "tcp"
localIP = "::1"
localPort = 22
remote_port = 1
"#;
        let cfg = parse_client_toml(text).unwrap();
        assert_eq!(cfg.proxies[0].local_addr, "[::1]:22");
    }

    #[test]
    fn visitors_里的_frp_键名也能认() {
        let text = r#"
server_addr = "x"
[[visitors]]
name = "v"
type = "xtcp"
serverName = "p2p-echo"
serverUser = "alice"
secretKey = "sk"
bindAddr = "127.0.0.1"
bindPort = 9001
"#;
        let cfg = parse_client_toml(text).unwrap();
        let v = &cfg.visitors[0];
        assert_eq!(v.server_name, "p2p-echo");
        assert_eq!(v.server_user, "alice");
        assert_eq!(v.secret_key, "sk");
        assert_eq!(v.bind_addr, "127.0.0.1");
        assert_eq!(v.bind_port, 9001);
    }

    #[test]
    fn 插件代理省略本机地址时按_frp_默认值补齐() {
        let text = r#"
server_addr = "x"
[[proxies]]
name = "socks"
type = "tcp"
remote_port = 1080
[proxies.plugin]
type = "socks5"
"#;
        let cfg = parse_client_toml(text).unwrap();
        assert_eq!(cfg.proxies[0].plugin, "socks5");
        assert_eq!(cfg.proxies[0].local_addr, "127.0.0.1:0");
    }

    #[test]
    fn 原版_frps_配置的默认写法也要能解析() {
        let text = r#"
bindAddr = "0.0.0.0"
bindPort = 7000
logLevel = "info"
vhostHTTPPort = 8080
subdomainHost = "example.com"

[auth]
token = "st"

[transport.tls]
force = true

[webServer]
port = 7500
user = "admin"
password = "pw"
"#;
        let cfg = parse_server_toml(text).unwrap();
        assert_eq!(cfg.bind_addr, "0.0.0.0");
        // frp 的 bindPort 是"控制+工作同端口"，对应 rustunnel 的 bind_port
        assert_eq!(cfg.bind_port, Some(7000));
        assert_eq!(cfg.token, "st");
        assert_eq!(cfg.vhost_http_port, Some(8080));
        assert_eq!(cfg.subdomain_host, "example.com");
        assert!(cfg.tls_force);
        assert_eq!(cfg.dashboard_port, Some(7500));
        assert_eq!(cfg.dashboard_user, "admin");
        assert_eq!(cfg.dashboard_pwd, "pw");
    }
}
