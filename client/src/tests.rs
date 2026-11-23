//! 跨模块共享的报文映射测试（`ProxyConfig` -> `NewProxy`）。
//!
//! 职责：校验注册报文字段搬运与官方 frpc 抓包逐字节一致；同时提供
//! `full_tcp_config` / `USER` 给各子模块测试复用。
//! 并发/所有权契约：仅测试代码，无任务、通道或原子计数。
//! 不变量：`NewProxy` 的字段顺序 = serde 序列化顺序，改动字段顺序会同时打破
//! "与官方 frpc 抓包逐字节一致"这条断言。

use nfrp_common::config::ProxyConfig;
use nfrp_common::frp::msg::NewProxy;

/// 测试里统一用的 `user`（真实场景就是 Lolia 那份配置里的 `user = '2569'`）。
pub(crate) const USER: &str = "alice";

/// 一个所有字段都填满独特值的 tcp 代理配置。
pub(crate) fn full_tcp_config() -> ProxyConfig {
    ProxyConfig {
        proxy_protocol_version: "v2".into(),
        transport: Default::default(),
        use_encryption: false,
        use_compression: false,
        name: "web-a".into(),
        proxy_type: "tcp".into(),
        local_addr: "127.0.0.1:8080".into(),
        remote_port: 6100,
        custom_domains: vec!["a.example.com".into()],
        subdomain: "sub".into(),
        locations: vec!["/api".into()],
        http_user: "hu".into(),
        http_pwd: "hp".into(),
        host_header_rewrite: "backend.internal".into(),
        route_by_http_user: "hu-route".into(),
        multiplexer: "httpconnect".into(),
        bandwidth_limit: "1MB".into(),
        bandwidth_limit_mode: "server".into(),
        metas: [("pk".to_string(), "pv".to_string())].into_iter().collect(),
        // 限制①批次1：注解要随 NewProxy 透传（官方 `m.Annotations = c.Annotations`）
        annotations: [("example.com/team".to_string(), "infra".to_string())]
            .into_iter()
            .collect(),
        // `enabled` 不参与注册报文：`Some(false)` 的条目在解析期就被摘掉了
        //（官方 FilterClientConfigurers），注册时恒为 None。
        enabled: None,
        group: "web".into(),
        group_key: "gk".into(),
        health_check_type: "http".into(),
        health_check_timeout_s: 7,
        health_check_max_failed: 5,
        health_check_interval_s: 11,
        health_check_url: "/healthz".into(),
        health_check_http_headers: vec![nfrp_common::config::HttpHeader {
            name: "Authorization".into(),
            value: "Bearer x".into(),
        }],
        plugin: "http_proxy".into(),
        plugin_local_path: "/tmp/x".into(),
        plugin_strip_prefix: "/p".into(),
        plugin_user: "pu".into(),
        plugin_passwd: "pp".into(),
        plugin_local_addr: "127.0.0.1:9000".into(),
        plugin_crt_path: "/tmp/c.crt".into(),
        plugin_key_path: "/tmp/c.key".into(),
        plugin_host_header_rewrite: "plugin.internal".into(),
        plugin_request_headers: [("X-Plugin".to_string(), "yes".to_string())]
            .into_iter()
            .collect(),
        secret_key: "sk".into(),
        allow_users: vec!["alice".into()],
    }
}

#[test]
fn proxy_protocol_版本解析_两种写法都认() {
    // 官方写法：[proxies.transport] proxyProtocolVersion = "v2"
    let official = ProxyConfig {
        proxy_protocol_version: String::new(),
        transport: nfrp_common::config::ProxyTransportConfig {
            proxy_protocol_version: "v2".into(),
        },
        ..full_tcp_config()
    };
    assert_eq!(official.proxy_protocol_version(), Some("v2"));

    // 老式 INI / 早期 TOML 写法：代理顶层的 proxy_protocol_version
    let legacy = ProxyConfig {
        proxy_protocol_version: "v1".into(),
        transport: Default::default(),
        ..full_tcp_config()
    };
    assert_eq!(legacy.proxy_protocol_version(), Some("v1"));

    // 两处都写：transport 优先
    let both = ProxyConfig {
        proxy_protocol_version: "v1".into(),
        transport: nfrp_common::config::ProxyTransportConfig {
            proxy_protocol_version: "v2".into(),
        },
        ..full_tcp_config()
    };
    assert_eq!(both.proxy_protocol_version(), Some("v2"));
}

/// 写错的值（大小写、`"2"`、`"v3"`）**必须当作不启用**，而不是"非 v1 即 v2"。
///
/// 官方是 `if version != "v1" { use v2 }` 的写法，于是 `"V2"` 这种大小写
/// 差一个字母的配置会往用户后端灌一段二进制垃圾 —— 后端把它当业务数据，
/// 报出来的是"协议错误"，没人会想到是 frpc 的配置拼错了。
#[test]
fn proxy_protocol_写错的值宁可不生效() {
    for bad in ["false", "2", "v3", "yes"] {
        let c = ProxyConfig {
            proxy_protocol_version: bad.into(),
            ..full_tcp_config()
        };
        assert_eq!(
            c.proxy_protocol_version(),
            None,
            "{bad:?} 不该被当成任何一版 PROXY 协议"
        );
        assert_eq!(c.has_invalid_proxy_protocol_version(), Some(bad.trim()));
    }
    // 大小写宽容：跑完 to_ascii_lowercase 之后能认
    let c = ProxyConfig {
        proxy_protocol_version: "V2".into(),
        ..full_tcp_config()
    };
    assert_eq!(c.proxy_protocol_version(), Some("v2"));

    // 空串 = 不启用，也不算"写错了"
    let c = ProxyConfig {
        proxy_protocol_version: String::new(),
        ..full_tcp_config()
    };
    assert_eq!(c.proxy_protocol_version(), None);
    assert_eq!(c.has_invalid_proxy_protocol_version(), None);
}

#[test]
fn tcp_carries_port_and_group() {
    let c = full_tcp_config();
    let m = NewProxy::from_config(&c, USER);
    assert_eq!(
        m.proxy_name, "alice.web-a",
        "线协议名必须带 `{{user}}.` 前缀 —— 官方 frpc 的 wireName 就是这么算的，\
             少了前缀第三方平台按名字查不到隧道"
    );
    assert_eq!(m.proxy_type, "tcp");
    assert_eq!(m.remote_port, 6100);
    assert_eq!(m.group, "web", "group 没搬过去的话负载均衡等于没配");
    assert_eq!(m.group_key, "gk");
    // tcp 不该带 http / stcp 的东西
    assert!(m.custom_domains.is_empty());
    assert!(m.sk.is_empty());
}

#[test]
fn http_carries_routing_fields() {
    let c = ProxyConfig {
        proxy_type: "http".into(),
        ..full_tcp_config()
    };
    let m = NewProxy::from_config(&c, USER);
    assert_eq!(m.proxy_name, "alice.web-a");
    assert_eq!(m.custom_domains, vec!["a.example.com".to_string()]);
    assert_eq!(m.subdomain, "sub");
    assert_eq!(m.locations, vec!["/api".to_string()]);
    assert_eq!(m.http_user, "hu");
    assert_eq!(m.http_pwd, "hp");
    assert_eq!(m.host_header_rewrite, "backend.internal");
    assert_eq!(m.group, "web", "http 也应当带上 group");
    // http 不用 remote_port
    assert_eq!(m.remote_port, 0);
}

#[test]
fn stcp_carries_secret_and_allow_list_only() {
    let c = ProxyConfig {
        proxy_type: "stcp".into(),
        ..full_tcp_config()
    };
    let m = NewProxy::from_config(&c, USER);
    assert_eq!(m.proxy_name, "alice.web-a");
    assert_eq!(m.sk, "sk");
    assert_eq!(m.allow_users, vec!["alice".to_string()]);
    // stcp / xtcp 不占公网端口，带上 remote_port 会让服务端误判
    assert_eq!(m.remote_port, 0);
    assert!(m.group.is_empty(), "stcp 不走端口组，不该带 group");
}

/// tcpmux 上报的字段对齐官方 `TCPMuxProxyConfig.MarshalToMsg`：
/// `customDomains` / `subdomain` / `multiplexer` / `httpUser` / `httpPwd` /
/// `routeByHTTPUser` —— **不带 `locations`**（官方那个结构体里没有这个字段）。
#[test]
fn tcpmux_carries_multiplexer_and_domain_routing() {
    let c = ProxyConfig {
        proxy_type: "tcpmux".into(),
        ..full_tcp_config()
    };
    let m = NewProxy::from_config(&c, USER);
    assert_eq!(m.proxy_name, "alice.web-a");
    assert_eq!(m.multiplexer, "httpconnect");
    assert_eq!(m.custom_domains, vec!["a.example.com".to_string()]);
    assert_eq!(m.subdomain, "sub");
    assert_eq!(m.http_user, "hu");
    assert_eq!(m.http_pwd, "hp");
    assert_eq!(m.route_by_http_user, "hu-route");
    // 不占端口、也没有路径前缀
    assert_eq!(m.remote_port, 0);
    assert!(
        m.locations.is_empty(),
        "官方 tcpmux 没有 locations，不能多发"
    );
}

/// **金标准测试**：报文必须和官方 frpc v0.71.0 抓到的那一帧**逐字节一致**。
///
/// 下面这串 JSON 是从
/// `cargo run -p nfrp-server --example dump_frpc -- 17777`
/// 抓到的原文（Lolia 下发的那份配置，一字未改）：
///
/// ```text
/// [msg_type=3 NewProxy] {"proxy_name":"2569.c0462d9ce7e44bce97e626c4ae880905",
///  "proxy_type":"tcp","bandwidth_limit":"25MB","bandwidth_limit_mode":"server",
///  "remote_port":38725}
/// ```
///
/// 之所以按**字符串**比而不是逐字段比：`NewProxy` 的字段顺序 = serde 的
/// 序列化顺序 = 结构体声明顺序，所以字符串相同就意味着连字段顺序都对上了。
/// 谁把字段顺序挪了、漏了、多发了，这条都会红。
#[test]
fn 与官方_frpc_抓包逐字节一致() {
    let cfg = nfrp_common::config::parse_client_toml(LOLIA_FRPC).unwrap();
    let m = NewProxy::from_config(&cfg.proxies[0], &cfg.user);

    assert_eq!(
        serde_json::to_string(&m).unwrap(),
        concat!(
            r#"{"proxy_name":"2569.c0462d9ce7e44bce97e626c4ae880905","#,
            r#""proxy_type":"tcp","#,
            r#""bandwidth_limit":"25MB","#,
            r#""bandwidth_limit_mode":"server","#,
            r#""remote_port":38725}"#,
        )
    );
}

/// LoliaFRP 平台真实下发的配置（`GET /user/frpc/config`，Base64 解出来的原文）。
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

/// 没配 `user` 时不该凭空造出一个 `.` 前缀。
#[test]
fn 空_user_不加前缀() {
    let m = NewProxy::from_config(&full_tcp_config(), "");
    assert_eq!(m.proxy_name, "web-a");
}

/// `bandwidth_limit_mode` 默认值 `client` 要**省略**。
///
/// 官方 frpc 的 `MarshalToMsg` 只在值不等于 `client` 时才发这个字段
/// （`if c.Transport.BandwidthLimitMode != "client"`），我们多发一个
/// `"bandwidth_limit_mode":"client"` 就和官方报文对不上了。
#[test]
fn 默认限流模式不上报() {
    for raw in ["", "client", "CLIENT"] {
        let c = ProxyConfig {
            bandwidth_limit_mode: raw.into(),
            ..full_tcp_config()
        };
        assert!(
            NewProxy::from_config(&c, USER)
                .bandwidth_limit_mode
                .is_empty(),
            "值 {raw:?} 应当被归一化成空串（即不发送）"
        );
    }
    // 非默认值要原样上报
    let c = ProxyConfig {
        bandwidth_limit_mode: "server".into(),
        ..full_tcp_config()
    };
    assert_eq!(
        NewProxy::from_config(&c, USER).bandwidth_limit_mode,
        "server"
    );
}

/// `NewProxy.metas` 装的是**代理级** `[proxies.metadatas]`，不是顶层 `[metadatas]`。
///
/// 搞混的后果：报文里会多出一个官方 frpc 不会发的 `token` 字段，
/// 平台一旦校验就报错，而且很难看出是"多发了一个键"。
#[test]
fn 代理级_metas_才上进注册报文() {
    let cfg = nfrp_common::config::parse_client_toml(LOLIA_FRPC).unwrap();
    // 登录 metas 里有 token
    assert_eq!(
        cfg.metas.get("token").map(String::as_str),
        Some("x8p5mo0u8ips3lmohc67r58mejp7uthf")
    );
    // 但代理级没有 → 注册报文里也不该有
    let m = NewProxy::from_config(&cfg.proxies[0], &cfg.user);
    assert!(
        m.metas.is_empty(),
        "顶层 [metadatas] 只进登录消息，不该出现在 NewProxy 里"
    );
}

/// 没配 group 时必须原样为空 —— 服务端把空 group 当「独占端口」，
/// 凭空塞个默认值会让所有代理挤进同一组、端口冲突检测直接失效。
#[test]
fn absent_group_stays_empty() {
    let c = ProxyConfig {
        group: String::new(),
        group_key: String::new(),
        ..full_tcp_config()
    };
    let m = NewProxy::from_config(&c, USER);
    assert!(m.group.is_empty());
    assert!(m.group_key.is_empty());
}

/// 防漂移：`ProxyConfig` 里凡是和 `NewProxy` 同名同义、应当下发的字段，
/// 都在这里被点名检查一遍。以后再加字段，忘了搬就会红。
#[test]
fn every_shareable_field_is_carried() {
    let c = full_tcp_config();
    // 用 tcp 分支检查「端口类」字段
    let tcp = NewProxy::from_config(&c, USER);
    assert_eq!(tcp.remote_port, c.remote_port);
    assert_eq!(tcp.group, c.group);
    assert_eq!(tcp.group_key, c.group_key);
    assert_eq!(tcp.bandwidth_limit, c.bandwidth_limit);
    assert_eq!(tcp.bandwidth_limit_mode, c.bandwidth_limit_mode);
    assert_eq!(tcp.metas, c.metas);
    // 限制①批次1：注解必须跟着走（服务端只存不查，但报文要逐字段对齐官方）
    assert_eq!(tcp.annotations, c.annotations);

    // 用 http 分支检查「路由类」字段
    let http = NewProxy::from_config(
        &ProxyConfig {
            proxy_type: "http".into(),
            ..c.clone()
        },
        USER,
    );
    assert_eq!(http.custom_domains, c.custom_domains);
    assert_eq!(http.subdomain, c.subdomain);
    assert_eq!(http.locations, c.locations);
    assert_eq!(http.http_user, c.http_user);
    assert_eq!(http.http_pwd, c.http_pwd);
    assert_eq!(http.host_header_rewrite, c.host_header_rewrite);

    // 用 stcp 分支检查「私密隧道类」字段
    let stcp = NewProxy::from_config(
        &ProxyConfig {
            proxy_type: "stcp".into(),
            ..c.clone()
        },
        USER,
    );
    assert_eq!(stcp.sk, c.secret_key);
    assert_eq!(stcp.allow_users, c.allow_users);
}
