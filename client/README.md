# nfrp-client

> NFrp 客户端可执行文件 —— 等价官方 `frpc`。
> 用 `cargo install nfrp-client` 安装，或从
> [Releases](https://github.com/Nu0vo1212/Rust-Frp/releases) 下载预编译包。

[![crates.io](https://img.shields.io/crates/v/nfrp-client.svg)](https://crates.io/crates/nfrp-client)
[![license](https://img.shields.io/badge/license-Apache--2.0-green)](https://github.com/Nu0vo1212/Rust-Frp/blob/main/LICENSE)

## 这是什么

[NFrp](https://github.com/Nu0vo1212/Rust-Frp) 是 [fatedier/frp](https://github.com/fatedier/frp)
的 Rust 重实现，**完整兼容官方 wire protocol v1 与 v2**。

本 crate 提供客户端二进制 `nfrp-client`：

* **可连官方 `frps`**（frp 0.71.0 实测）—— 服务端不用改任何配置
* **可直接替换官方 `frpc`** —— 配置键名镜像 frp，`frpc.toml` 基本可直接用
* 单文件部署，无运行时依赖

| crate | 用途 |
|---|---|
| [nfrp-common](https://crates.io/crates/nfrp-common) | 协议 / 配置 / 加密库（可单独当库用） |
| [nfrp-server](https://crates.io/crates/nfrp-server) | 服务端可执行文件（等价 `frps`） |
| **nfrp-client**（本 crate） | 客户端可执行文件（等价 `frpc`） |

## 安装

```bash
cargo install nfrp-client
```

或者直接下预编译二进制（Windows / Linux amd64 / arm64 / Android）：
<https://github.com/Nu0vo1212/Rust-Frp/releases>

## 快速开始

```bash
cat > frpc.toml <<'EOF'
server_addr = "你的服务器地址"
server_port = 7000

[auth]
token = "与服务端一致的口令"

# 把内网的 22 端口映射到服务端的 6000
[[proxies]]
name = "ssh"
type = "tcp"
local_ip = "127.0.0.1"
local_port = 22
remote_port = 6000
EOF

nfrp-client -c frpc.toml
```

## 主要能力

| 能力 | 说明 |
|---|---|
| 代理类型 | `tcp` / `udp` / `http` / `https` / `tcpmux` / `stcp` / `sudp` / `xtcp` |
| 传输层 | TCP / KCP / QUIC / WebSocket，外加 TLS 封装 |
| **插件** | `http2http` · `http2https` · `https2http` · `https2https` · `tls2raw` · `static_file` · `unix_domain_socket` |
| **本地界面** | `[webServer]` 浏览器里动态增删隧道（带 CSRF 防护） |
| **动态隧道** | `[store]` 落盘，重启自动恢复 |
| 鉴权 | token（v1/v2）· **OIDC**（支持自动刷新） |
| xtcp | UDP 打洞 + QUIC/KCP 直连，打不通自动回退中继 |

## 命令行

```bash
nfrp-client -c frpc.toml        # 启动
nfrp-client verify -c frpc.toml # 只校验配置
nfrp-client reload              # 让运行中的实例重载配置
nfrp-client status              # 查状态
nfrp-client stop                # 停掉运行中的实例
```

## 安全说明

* 客户端连服务端的 TLS **默认不校验服务端证书** —— 与官方 frpc 一致
  （否则官方 frps 全连不上）。要校验请配 `transport.tls.verifyServerCert = true`
  并给出 `trustedCaFile`。
* 服务端通过面板下发的"新增代理"**会被强制校验**：不允许任何 `plugin*` 字段，
  且 `local_addr` 必须是回环地址 —— 防止服务端把客户端变成开放代理。

细节见仓库的 `SECURITY-FIXES*.md`（十轮审计，累计 140 项修复）。

## 兼容性

* 官方 frp **0.71.0** 实测互通
* `nfrp-client -v` 输出裸 `0.71.0`；`-V` 输出 `nfrp-client 0.6.1`
* 支持老式 `frpc.ini`（自动识别）

## 许可

Apache-2.0

## 链接

* 仓库：<https://github.com/Nu0vo1212/Rust-Frp>
* 问题反馈：<https://github.com/Nu0vo1212/Rust-Frp/issues>
