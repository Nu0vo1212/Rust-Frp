//! `config` 模块内嵌测试。
//!
//! 职责：锁定 Debug 脱敏、`allowPorts`、默认值、示例配置、tcpmux、远程下发校验、glob 与 `includes` 等既有语义。
//! 并发/所有权契约：测试各自构造独立配置，无锁、无共享可变状态；涉及文件的用例只用进程独立的临时目录。
//! 不变量：测试名与断言必须与拆分前逐字一致，本文件只做 `use super::*` 适配。

use super::*;
use serde::Serialize;

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
    let cfg2 =
        parse_server_toml("bind_port = 27000\ndashboard_port = 27011\n[webServer]\nport = 27010\n")
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

    let c: ClientConfig = toml::from_str("server_addr = \"127.0.0.1\"").expect("最小客户端配置");
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
    let err = parse_client(&base("customDomains = [\"a.b\"]")).expect_err("缺 multiplexer 该报错");
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
    //   NFrp 的 `verifyServerCert` 仍是顶层键，所以这里分开断言。
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

/// 默认是 65507（NFrp 一直用的值），**不是**官方的 1500。
///
/// 这条锁住"默认不被改成 1500" —— 改了会截断现有用户的大 UDP 报文，
/// 而且是静默截断（收得到包、内容少一截），比报错难查得多。
#[test]
fn udp_packet_size_默认是_65507() {
    assert_eq!(ServerConfig::default().udp_packet_size, MAX_UDP_PACKET_SIZE);
    assert_eq!(ClientConfig::default().udp_packet_size, MAX_UDP_PACKET_SIZE);
    assert_eq!(MAX_UDP_PACKET_SIZE, 65507);
}

/// 两端都能读（官方 camelCase 与 NFrp snake_case 都认）。
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
