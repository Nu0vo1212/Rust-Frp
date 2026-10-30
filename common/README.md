# nfrp-common

> NFrp 的公共库：frp 协议（v1 / v2）、配置、加密、ACL/RBAC、日志、传输层抽象。
> 这是 [NFrp](https://github.com/Nu0vo1212/Rust-Frp) 三个 crate 里**唯一可以当库用**的那个 ——
> 不跑穿透服务也能直接用它的协议与加密实现。

[![crates.io](https://img.shields.io/crates/v/nfrp-common.svg)](https://crates.io/crates/nfrp-common)
[![docs.rs](https://docs.rs/nfrp-common/badge.svg)](https://docs.rs/nfrp-common)
[![license](https://img.shields.io/badge/license-Apache--2.0-green)](https://github.com/Nu0vo1212/Rust-Frp/blob/main/LICENSE)

## 这是什么

[NFrp](https://github.com/Nu0vo1212/Rust-Frp) 是 [fatedier/frp](https://github.com/fatedier/frp)
的 Rust 重实现，**完整兼容官方 wire protocol v1 与 v2**
（与官方 `frps` / `frpc` v0.71.0 实测互通）。

整个项目由两个可执行文件 + 本库组成：

| crate | 用途 |
|---|---|
| **nfrp-common**（本 crate） | 协议 / 配置 / 加密 / 工具库 |
| [nfrp-server](https://crates.io/crates/nfrp-server) | 服务端可执行文件（等价 `frps`） |
| [nfrp-client](https://crates.io/crates/nfrp-client) | 客户端可执行文件（等价 `frpc`） |

## 安装

```toml
[dependencies]
nfrp-common = "0.6"
```

## 模块导览

| 需求 | 从哪里入手 |
|---|---|
| 读/写 frp 的 TOML 配置（含字段名兼容） | `config` · `frp_config` |
| 读老式 `frpc.ini` / `frps.ini` | `frp_legacy` |
| 自己实现 frp 客户端或服务端 | `frp` · `frp::msg` |
| 只做加密（AEAD / v1 CFB） | `frp::crypto` · `frp::v1` · `frp::tls` |
| HTTP 请求解析 / 转发（无 Web 框架） | `http1` · `http_relay` |
| IP 白黑名单 / RBAC / 审计 | `security` |
| 日志按天轮转 | `logfile` |
| PROXY protocol v1/v2 | `proxy_protocol` |
| KCP / QUIC / WebSocket 传输 | `frp::kcp` · `frp::quic` · `ws` |
| VirtualNet（TUN 设备） | `vnet` |

## 快速上手

### 解析一份 frps 配置

```rust
use nfrp_common::config::ServerConfig;

let cfg: ServerConfig = toml::from_str(r#"
    bind_port = 7000
    [auth]
    token = "secret"
"#).unwrap();

assert_eq!(cfg.bind_port, Some(7000));      // 注意：Option<u16>
// `effective_auth()` 是 token 的**唯一真源**：
// 新写法 `[auth] token` 优先，回落到旧式顶层 `token`
assert_eq!(cfg.effective_auth().token, "secret");
```

★ 本 crate 用 **snake_case**（`bind_port`），与原版 frp 的 `bindPort` 不同 ——
后者由 `frp_config` 那一层负责兼容。

### v1 控制通道的密钥派生（与官方 frp 字节级一致）

```rust
use nfrp_common::frp::v1::derive_key;

let key = derive_key(b"my-token");
assert_eq!(key.len(), 16); // AES-128
```

## 安全说明（用之前请读）

本库忠实实现 frp 协议，因此**保留了协议本身的历史设计**：

| 项 | 现状 | 说明 |
|---|---|---|
| v1 通道加密 | `PBKDF2-HMAC-SHA1(…, 64 轮) + AES-128-CFB` | 弱，但官方就是它；改了就不通 |
| v1 凭证 | `md5(token + timestamp)` | 这是**线路格式**，不是可选项 |
| 客户端 TLS | **默认不校验服务端证书** | 与官方 frpc 一致；要校验用 `frp::tls::client_config_verifying` |
| v2 通道加密 | **AES-256-GCM + HKDF-SHA256 + transcript 链** | 强，新部署建议走 v2 |

项目已做过十轮安全审计（累计 140 项修复，全部带回归测试），
记录在仓库的 `SECURITY-FIXES*.md` 里。

## 兼容性

* 与官方 frp **0.71.0** 实测互通（v1 / v2 双版本）
* Windows / Linux 行为一致（平台特定代码全部在 `cfg` 之下）
* MSRV：**1.75**
* CI 里 `cargo audit` 作为门禁，依赖 CVE 会被拦下

## 许可

Apache-2.0

## 链接

* 仓库：<https://github.com/Nu0vo1212/Rust-Frp>
* 问题反馈：<https://github.com/Nu0vo1212/Rust-Frp/issues>
* 发布包：<https://github.com/Nu0vo1212/Rust-Frp/releases>
