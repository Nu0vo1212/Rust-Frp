#![no_main]

//! 配置解析 fuzz：`parse_server` / `parse_client` / `parse_server_toml` / `parse_client_toml`。
//!
//! 只调用纯函数，不读文件、不建连接。解析成功的配置再做一次
//! `toml::to_string` → 重新解析，断言关键字段稳定（不断言 token 等动态值）。

use libfuzzer_sys::fuzz_target;
use nfrp_common::config::{parse_client, parse_client_toml, parse_server, parse_server_toml};
use std::sync::Once;

static BASELINE: Once = Once::new();

fn server_roundtrip(raw: &str) {
    let Ok(first) = parse_server_toml(raw) else {
        return;
    };
    // 个别配置可能因为 TOML 序列化限制无法编码；那属于"没观察到"，不算 panic。
    let Ok(encoded) = toml::to_string(&first) else {
        return;
    };
    let second = parse_server_toml(&encoded).expect("服务端配置序列化后必须能再次解析");
    assert_eq!(first.control_port, second.control_port);
    assert_eq!(first.work_port, second.work_port);
    assert_eq!(first.bind_addr, second.bind_addr);
    assert_eq!(first.tcp_mux, second.tcp_mux);
    assert_eq!(first.vhost_http_port, second.vhost_http_port);
    assert_eq!(first.allow_ports, second.allow_ports);
}

fn client_roundtrip(raw: &str) {
    let Ok(first) = parse_client_toml(raw) else {
        return;
    };
    let Ok(encoded) = toml::to_string(&first) else {
        return;
    };
    let second = parse_client_toml(&encoded).expect("客户端配置序列化后必须能再次解析");
    assert_eq!(first.server_addr, second.server_addr);
    assert_eq!(first.server_port, second.server_port);
    assert_eq!(first.tcp_mux, second.tcp_mux);
    assert_eq!(first.login_fail_exit, second.login_fail_exit);
    assert_eq!(first.proxies.len(), second.proxies.len());
    assert_eq!(first.visitors.len(), second.visitors.len());
}

fuzz_target!(|data: &[u8]| {
    // 固定的最小合法配置：保证"序列化 → 再解析"这条路径至少被真实跑过一次。
    BASELINE.call_once(|| {
        let server = "bind_port = 7000\ntoken = \"test-token\"\n";
        let a = parse_server_toml(server).expect("基线服务端配置必须解析成功");
        let encoded = toml::to_string(&a).expect("ServerConfig 必须可序列化");
        let b = parse_server_toml(&encoded).expect("序列化后的服务端配置必须能再解析");
        assert_eq!(a.control_port, b.control_port);
        assert_eq!(a.bind_addr, b.bind_addr);

        let client = "serverAddr = \"127.0.0.1\"\nserverPort = 7000\n";
        let a = parse_client_toml(client).expect("基线客户端配置必须解析成功");
        let encoded = toml::to_string(&a).expect("ClientConfig 必须可序列化");
        let b = parse_client_toml(&encoded).expect("序列化后的客户端配置必须能再解析");
        assert_eq!(a.server_addr, b.server_addr);
        assert_eq!(a.server_port, b.server_port);
    });

    // 任意字节：只接受合法 UTF-8（配置文本必须是 UTF-8）。
    let Ok(raw) = std::str::from_utf8(data) else {
        return;
    };

    let _ = parse_server(raw);
    let _ = parse_client(raw);
    server_roundtrip(raw);
    client_roundtrip(raw);
});
