//! `nfrp-common`：服务端与客户端共享的公共库。
//!
//! 包含八部分：
//! - [`protocol`]：NFrp 原生线协议（4 字节大端长度前缀 + JSON）；
//! - [`frp`]：**Go 版 frp wire protocol v2** 的完整实现，用于与原版 frpc/frps 互通；
//! - [`config`]：TOML 配置结构与示例模板；
//! - [`frp_config`]：原版 frp 的 TOML **字段名**兼容层（`serverAddr` / `localIP` 等）；
//! - [`frp_legacy`]：原版 frp 的 **legacy INI 配置格式**兼容层（`frpc.ini` / `frps.ini`）；
//! - [`transport`]：传输层抽象（MVP 明文，后续可换 rustls / snow）；
//! - [`util`]：地址解析、日志初始化、连接桥接等跨平台工具；
//! - [`error`]：统一错误类型。
//!
//! 本 crate 不含任何平台特定代码，Windows / Linux 行为一致。
//!
//! # 作为库使用（不跑 nfrp 的二进制）
//!
//! 整个项目是「`nfrp-server` / `nfrp-client` 两个可执行文件 + 本库」。
//! **只想用协议 / 配置 / 加密，不想跑穿透服务**时，直接依赖本 crate 即可：
//!
//! ```toml
//! [dependencies]
//! nfrp-common = "0.6"
//! ```
//!
//! ## 你大概想要哪一块
//!
//! | 需求 | 从哪里入手 |
//! |---|---|
//! | 读/写 frp 的 TOML 配置（含字段名兼容） | [`config`] · [`frp_config`] |
//! | 读老式 `frpc.ini` / `frps.ini` | [`frp_legacy`] |
//! | 自己实现一个 frp 客户端或服务端 | [`frp`]（v2 帧 + v1 兼容） · [`frp::msg`] |
//! | 只做加密（AEAD / v1 CFB） | [`frp::crypto`] · [`frp::v1`] · [`frp::tls`] |
//! | HTTP 请求解析 / 转发（无 Web 框架） | [`http1`] · [`http_relay`] |
//! | IP 白黑名单 / RBAC / 审计 | [`security`] |
//! | 日志按天轮转 | [`logfile`] |
//! | PROXY protocol v1/v2 | [`proxy_protocol`] |
//! | KCP / QUIC / WebSocket 传输 | [`frp::kcp`] · [`frp::quic`] · [`ws`] |
//!
//! ## 示例：解析一份 frps 配置
//!
//! ★ `ServerConfig` 用的是 **snake_case**（`bind_port`），与原版 frp 的
//!   `bindPort` 不同 —— 后者由 [`frp_config`] 那一层负责兼容。
//!
//! ```
//! use nfrp_common::config::ServerConfig;
//!
//! let cfg: ServerConfig = toml::from_str(r#"
//!     bind_port = 7000
//!     [auth]
//!     token = "secret"
//! "#).unwrap();
//! assert_eq!(cfg.bind_port, Some(7000)); // 注意：Option<u16>
//! // `effective_auth()` 是 token 的**唯一真源**：
//! // 新写法 `[auth] token` 优先，回落到旧式顶层 `token`
//! assert_eq!(cfg.effective_auth().token, "secret");
//! ```
//!
//! ## 示例：v1 控制通道的密钥派生（与官方 frp 字节级一致）
//!
//! ```
//! use nfrp_common::frp::v1::derive_key;
//!
//! let key = derive_key(b"my-token");
//! assert_eq!(key.len(), 16); // AES-128
//! ```
//!
//! # 版本与兼容
//!
//! * 本 crate 的版本**跟随整体项目**（[`PROTOCOL_VERSION`] 另有所指）；
//! * 线协议与官方 frp **0.71.0** 实测互通；
//! * `cargo audit` 在 CI 里作为门禁，依赖 CVE 会被拦下。
//!
//! # 安全说明（用之前请读）
//!
//! 本库忠实实现 frp 协议，因此**保留了协议本身的历史设计**：
//!
//! * v1 通道用 `PBKDF2-HMAC-SHA1(…, 64 轮) + AES-128-CFB` —— 弱，但官方就是它；
//! * v1 的凭证是 `md5(token + timestamp)` —— 这是**线路格式**，不是可选项；
//! * 客户端 TLS **默认不校验服务端证书**（与官方 frpc 一致）；
//!   需要校验时用 [`frp::tls::client_config_verifying`]。
//!
//! 新部署建议走 **v2**（AES-256-GCM + HKDF-SHA256 + transcript 链）。
//! 详见仓库里的 `SECURITY-FIXES*.md`。

pub mod auth;
pub mod compat;
pub mod config;
pub mod dns;
pub mod error;
pub mod frp;
pub mod frp_config;
pub mod frp_legacy;
pub mod http1;
pub mod http_relay;
pub mod httpc;
pub mod logfile;
pub mod net_proxy;
/// NLink v1：可协商、可回退、零额外往返的扩展层。
///
/// 模块本身始终编译（它只是一组纯函数与结构体）；真正**上线**的部分由
/// crate feature `nlink` 控制：关掉后 `LoginResp` 里连扩展字段都不存在，
/// 客户端也不会发 preamble，报文与 0.6.x 逐字节一致。
pub mod nlink;
pub mod p2p;
pub mod plugin;
pub mod pprof_http;
pub mod protocol;
pub mod proxy_protocol;
pub mod security;
pub mod stun;
pub mod throttle;
pub mod transport;
pub mod util;
pub mod vnet;
pub mod ws;

pub use error::{Error, Result};
pub use protocol::ControlMessage;
pub use transport::{PlainTransport, Transport, TunnelIo, TunnelStream};

/// 当前实现的协议版本号（用于日志与后续协商）。
pub const PROTOCOL_VERSION: u32 = protocol::PROTOCOL_VERSION;
