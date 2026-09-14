# rustunnel

用 Rust 实现的内网穿透工具，**完整兼容 [fatedier/frp](https://github.com/fatedier/frp) 的 wire protocol v2**，可以和官方 `frps` / `frpc`（v0.71.0 实测）直接互通。

以极小的资源占用换取同等的核心能力：服务端常驻内存约 **3.5 MB**（同负载下 Go 版 frps 为 28.8~31.8 MB），单文件部署，无任何运行时依赖。

## 特性

- ✅ **frp v2 线协议兼容** — 与官方 frp 互相连接（官方客户端需指定 `transport.wireProtocol = "v2"`）
- ✅ **TCP 代理** — `[[proxies]]` 段配置，多代理同时工作
- ✅ **yamux 多路复用** — 对应 frp `transport.tcpMux`，控制连接与工作连接复用一条 TCP
- ✅ **TLS 加密** — 对应 frp `transport.tls`，含 frp 自定义首字节 `0x17` 伪装，服务端自动生成自签名证书
- ✅ **极低资源占用** — release profile 体积优先编译（`opt-level="s"` + 全量 LTO + `panic="abort"` + strip）
- ✅ **跨平台** — Windows / Linux amd64 / Linux arm64（arm64 可全静态链接，无 glibc 依赖）
- ✅ **心跳保活** — 与 frp 一致的心跳超时机制

## 架构

```
rustunnel/
├── common/            # 公共库（协议实现核心）
│   └── src/frp/
│       ├── wire.rs    #   v2 线协议：magic 前缀、帧编解码
│       ├── crypto.rs  #   控制通道加密：HKDF-SHA256 + AES-256-GCM
│       ├── msg.rs     #   JSON 消息：Login/NewProxy/ReqWorkConn/...
│       ├── conn.rs    #   加密连接的读写封装
│       ├── tls.rs     #   frp 自定义 TLS（自签证书 + 0x17 首字节）
│       ├── mux.rs     #   yamux 会话封装
│       └── stream.rs  #   统一流抽象 BoxStream
├── server/            # frps 等价服务端
└── client/            # frpc 等价客户端
```

传输层次：

```
TCP → [TLS] → [yamux] → frp v2 连接
```

TLS 与 yamux 均为可选，由配置决定。服务端通过**首字节探测**自动识别：
`0x00` = yamux 帧、`0x17`/`0x16` = TLS、`'F'` = frp v2 magic，
因此开启 `tcp_mux` 后仍可同时服务 `tcpMux = false` 的旧客户端。

## 快速开始

### 从源码构建

```bash
git clone https://github.com/<you>/rustunnel.git
cd rustunnel
cargo build --release
# 产物：target/release/rustunnel-server（frps）、target/release/rustunnel-client（frpc）
```

Rust 1.75+。Windows 用 MSVC toolchain；Linux arm64 静态编译见下文。

### 启动服务端（公网机器）

```toml
# frps.toml
bind_addr = "0.0.0.0"
bind_port = 7000
token = "your_secret_token"
tcp_mux = true
tls_force = false
```

```bash
./rustunnel-server -c frps.toml
```

### 启动客户端（内网机器）

```toml
# frpc.toml
server_addr = "your.server.com"
server_port = 7000
token = "your_secret_token"
tcp_mux = true
tls_enable = false

[[proxies]]
name = "ssh"
local_addr = "127.0.0.1:22"
remote_port = 6000
```

```bash
./rustunnel-client -c frpc.toml
```

之后 `your.server.com:6000` 即映射到内网机器的 22 端口。

### 与官方 frp 互通

rustunnel 可运行在官方 frp 的任一侧：

| 服务端 | 客户端 | 状态 |
|---|---|---|
| rustunnel frps | 官方 frpc（tcpMux on/off、TLS on） | ✅ 实测通过 |
| 官方 frps | rustunnel frpc（tcp_mux on、TLS on） | ✅ 实测通过 |
| rustunnel frps | rustunnel frpc | ✅ 实测通过 |

官方客户端需显式指定 v2 协议：

```toml
# 官方 frpc 侧
transport.wireProtocol = "v2"
```

## 配置参考

### 服务端（rustunnel-server）

| 项 | 说明 | 默认 |
|---|---|---|
| `bind_addr` | 监听地址 | `0.0.0.0` |
| `bind_port` | 控制与工作连接共用端口（与 frp 一致） | `7000` |
| `token` | 认证 token，客户端必须一致 | 必填 |
| `tcp_mux` | 允许 yamux 多路复用（自动探测，不影响非 mux 客户端） | `true` |
| `tls_force` | 强制客户端使用 TLS | `false` |
| `heartbeat_timeout` | 心跳超时（秒） | `90` |
| `log_level` | `error`/`warn`/`info`/`debug`/`trace` | `info` |

### 客户端（rustunnel-client）

| 项 | 说明 | 默认 |
|---|---|---|
| `server_addr` | 服务端地址 | 必填 |
| `server_port` | 服务端端口 | `7000` |
| `token` | 认证 token | 必填 |
| `tcp_mux` | 使用 yamux 多路复用 | `true` |
| `tls_enable` | TLS 加密（不校验服务端证书，与 frpc 默认一致） | `false` |
| `tls_server_name` | TLS SNI，留空用 `server_addr` | 空 |
| `tls_custom_first_byte` | TLS 握手前发送 frp 伪装字节 `0x17` | `true` |
| `pool_count` | 预建工作连接数（0 = 按需） | `1` |
| `[[proxies]]` | TCP 代理：`name` / `local_addr` / `remote_port` | - |

## 性能

同一转发负载下的常驻内存（RSS）：

| 实现 | 常驻内存 |
|---|---|
| Go 官方 frps（默认） | 31.8 MB |
| Go 官方 frps（GOGC/GOMEMLIMIT 调优后） | 28.8 MB |
| **rustunnel-server（Rust）** | **~3.5 MB** |

客户端二进制约 1.3 MB（Windows），服务端约 2.2 MB（Linux，静态）。

## 交叉编译（Linux ARM64 静态链接）

在 x86_64 Linux 主机上（以 RHEL/AlmaLinux 8 为例）：

```bash
rustup target add aarch64-unknown-linux-gnu
dnf install -y gcc-aarch64-linux-gnu
# 补 aarch64 glibc 头文件与静态库（el8 无现成交叉 libc 包）：
dnf download --forcearch=aarch64 glibc-devel glibc kernel-headers glibc-static
# rpm2cpio 解包后，将 usr/include 拷入 /usr/aarch64-linux-gnu/include，
# usr/lib64 拷入 /usr/aarch64-linux-gnu/lib{,64}，并 sed 修正 .so 链接脚本内的 /lib64 路径
ln -sf libgcc.a /usr/lib/gcc/aarch64-linux-gnu/12/libgcc_eh.a

export CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER=aarch64-linux-gnu-gcc
export CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_RUSTFLAGS="-C target-feature=+crt-static"
cargo build --release --target aarch64-unknown-linux-gnu
```

产物为全静态二进制，可直接运行于任意 ARM64 Linux。

## 当前限制

- 仅支持 **TCP** 代理（不支持 UDP / HTTP / HTTPS / STCP / XTCP）
- 未实现 QUIC、websocket 传输层
- 未实现 frp v1 线协议（官方 v0.78 起也已移除 v1）

## License

MIT
