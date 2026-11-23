//! TOML 配置结构与示例模板。
//!
//! 所有路径相关参数统一使用 [`std::path::PathBuf`]，不在代码中硬编码路径分隔符。
//!
//! 本模块按职责拆分：`protocol`（线协议）、`ports`（端口白名单）、
//! `server` / `client` / `proxy`（三类配置结构）、`defaults`（serde 默认值）、
//! `parse`（解析入口与 frp 兼容）、`validate`（配置校验）。
//! 所有公开项都在本文件用 `pub use` 原样导出，`nfrp_common::config::Xxx` 路径不变。
//!
//! 职责：模块入口，声明子模块并原样 re-export 全部公开项与公开解析入口。
//! 并发/所有权契约：本文件不含逻辑，无锁、无共享可变状态；配置解析得到的所有权归调用方。
//! 不变量：`nfrp_common::config::Xxx` 的公开路径不得变化；serde 默认值只由 `defaults` 定义。

mod client;
mod defaults;
mod parse;
mod ports;
mod protocol;
mod proxy;
mod server;
mod validate;

#[cfg(test)]
mod tests;

pub use self::client::{ClientConfig, StoreConfig, WebServerConfig, WebTlsConfig};
pub use self::defaults::{
    clamp_udp_packet_size, is_kcp, is_quic, is_websocket, is_wss, DEFAULT_BIND_ADDR,
    DEFAULT_CONTROL_PORT, DEFAULT_HEARTBEAT_INTERVAL, DEFAULT_HEARTBEAT_TIMEOUT, DEFAULT_LOG_LEVEL,
    DEFAULT_LOG_MAX_DAYS, DEFAULT_RECONNECT_INTERVAL, DEFAULT_VHOST_HTTP_TIMEOUT,
    DEFAULT_WORK_CONN_IDLE_TIMEOUT, DEFAULT_WORK_PORT, MAX_UDP_PACKET_SIZE,
};
pub use self::parse::{
    default_config_path, is_visitor_type, parse_client, parse_client_toml, parse_server,
    parse_server_toml, plugin_type_supported, unimplemented_plugin_types, OFFICIAL_PLUGIN_TYPES,
    SUPPORTED_PLUGIN_TYPES, SUPPORTED_VISITOR_TYPES,
};
pub use self::ports::{format_port_ranges, parse_port_ranges, port_allowed, PortRange};
pub use self::protocol::Protocol;
pub use self::proxy::{HttpHeader, ProxyConfig, ProxyTransportConfig, VisitorConfig};
pub use self::server::{
    has_dashboard_creds, HttpPluginConfig, ServerConfig, SshTunnelGatewayConfig,
};
pub use self::validate::validate_remote_proxy;

#[cfg(test)]
use self::parse::glob_match;
#[cfg(test)]
use self::validate::{is_loopback_host, local_addr_host};
