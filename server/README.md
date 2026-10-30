# nfrp-server

> NFrp 服务端可执行文件 —— 等价官方 `frps`。
> 用 `cargo install nfrp-server` 安装，或从
> [Releases](https://github.com/Nu0vo1212/Rust-Frp/releases) 下载预编译包。

[![crates.io](https://img.shields.io/crates/v/nfrp-server.svg)](https://crates.io/crates/nfrp-server)
[![license](https://img.shields.io/badge/license-Apache--2.0-green)](https://github.com/Nu0vo1212/Rust-Frp/blob/main/LICENSE)

## 这是什么

[NFrp](https://github.com/Nu0vo1212/Rust-Frp) 是 [fatedier/frp](https://github.com/fatedier/frp)
的 Rust 重实现，**完整兼容官方 wire protocol v1 与 v2**。

本 crate 提供服务端二进制 `nfrp-server`：

* **可与官方 `frpc` 直接互通**（frp 0.71.0 实测）—— 客户端不用改任何配置
* **可直接替换官方 `frps`** —— 配置键名镜像 frp
* 常驻内存约 **3.5 MB**（同负载下 Go 版 frps 为 28.8~31.8 MB）

| crate | 用途 |
|---|---|
| [nfrp-common](https://crates.io/crates/nfrp-common) | 协议 / 配置 / 加密库（可单独当库用） |
| **nfrp-server**（本 crate） | 服务端可执行文件（等价 `frps`） |
| [nfrp-client](https://crates.io/crates/nfrp-client) | 客户端可执行文件（等价 `frpc`） |

## 安装

```bash
cargo install nfrp-server
```

或者直接下预编译二进制（Windows / Linux amd64 / Linux arm64 / Android）：
<https://github.com/Nu0vo1212/Rust-Frp/releases>

## 快速开始

```bash
# 生成一份最小配置
cat > frps.toml <<'EOF'
bind_addr = "0.0.0.0"
bind_port = 7000

[auth]
token = "换成你自己的强口令"
EOF

nfrp-server -c frps.toml
```

带管理面板：

```toml
dashboard_addr = "127.0.0.1"
dashboard_port = 7500
dashboard_user = "admin"
dashboard_pwd = "换成强口令"
```

★ 面板绑在非回环地址时**必须**配账号密码，否则服务端拒绝启动。

## 主要能力

| 能力 | 说明 |
|---|---|
| 代理类型 | `tcp` / `udp` / `http` / `https` / `tcpmux` / `stcp` / `sudp` / `xtcp`（与官方清单一致） |
| 传输层 | TCP / KCP / QUIC / WebSocket，外加 TLS 封装 |
| 访问控制 | `[acl]` IP 白黑名单（CIDR / IPv6），在**认证之前**执行 |
| 鉴权 | token（v1/v2）· **OIDC**（JWKS 验签 + subject 绑定到会话） |
| RBAC | 按用户分配角色，限制代理类型 / 端口范围 / 代理数 / 是否可被管理 |
| 审计 | `[audit]` 独立 JSONL，含管理操作（增 / 删 / 踢） |
| 面板 | 内置 Web 面板 + `/metrics` + v2 API（`/api/v2/...`） |
| 热重载 | 改配置不用重启（部分字段） |

## 兼容性

* 官方 frp **0.71.0** 实测互通
* `nfrp-server -v` 输出裸 `0.71.0`（与官方一致，便于按版本号判断的客户端/面板）
* `nfrp-server -V` 输出 `nfrp-server 0.6.1`
* 配置键名镜像 frp，`frps.toml` 基本可直接用

## 安全

项目已做过十轮安全审计（累计 140 项修复，全部带回归测试）。
用之前建议至少做两件事：

1. **一定配 `auth.token`** —— 无 token + 绑对外地址会被拒绝启动；
2. 跨公网部署时开 `transport.tls.force = true`。

细节见仓库的 `SECURITY-FIXES*.md`。

## 许可

Apache-2.0

## 链接

* 仓库：<https://github.com/Nu0vo1212/Rust-Frp>
* 问题反馈：<https://github.com/Nu0vo1212/Rust-Frp/issues>
