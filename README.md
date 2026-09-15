# rustunnel

用 Rust 实现的内网穿透工具，**完整兼容 [fatedier/frp](https://github.com/fatedier/frp) 的 wire protocol v2**，可以和官方 `frps` / `frpc`（v0.71.0 实测）直接互通。

以极小的资源占用换取同等的核心能力：服务端常驻内存约 **3.5 MB**（同负载下 Go 版 frps 为 28.8~31.8 MB），单文件部署，无任何运行时依赖。

## 特性

- ✅ **frp v2 线协议兼容** — 与官方 frp 互相连接（官方客户端需指定 `transport.wireProtocol = "v2"`）
- ✅ **六种代理类型** — `tcp` / `udp` / `http` / `https` / `stcp` / `xtcp`，多代理同时工作
- ✅ **UDP 转发** — 每个 UDP 代理只占一条工作连接，靠访客地址区分会话
- ✅ **HTTP 反向代理** — 按域名路由，支持 `locations` 前缀、Basic Auth、Host 改写、自定义请求/响应头
- ✅ **HTTPS SNI 透传** — 只嗅探 ClientHello 里的 SNI 做路由，不终止 TLS，证书仍由内网服务提供
- ✅ **stcp 私密隧道** — 服务端不开放公网端口，需 `sk` 校验 + 提供者端 `allow_users` 白名单（空 = 只允许同 user），与官方 frp 互通
- ✅ **xtcp 兼容** — 官方 xtcp 访客可连接并收到明确的「不支持打洞」错误，快速失败而非挂起
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
│       ├── sni.rs     #   TLS ClientHello / SNI 嗅探
│       └── stream.rs  #   统一流抽象 BoxStream
├── server/            # frps 等价服务端
│   ├── udp_proxy.rs   #   UDP：公网 socket ⇄ 专用工作连接
│   ├── visitor.rs     #   stcp/xtcp：访客注册表（sk 校验 + allow_users 白名单）
│   └── vhost.rs       #   HTTP/HTTPS 虚拟主机路由与反向代理
└── client/            # frpc 等价客户端
    ├── udp_proxy.rs   #   UDP：每个访客一个本地 socket
    └── visitor.rs     #   stcp/xtcp：本地监听 → 经工作连接回源
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
| 官方 frps | rustunnel frpc（tcp_mux on/off、TLS on） | ✅ 实测通过 |
| rustunnel frps | 官方 frpc（udp / http / https 代理） | ✅ 实测通过 |
| 官方 frps | rustunnel frpc（udp / http / https 代理） | ✅ 实测通过 |
| rustunnel frps | 官方 frpc（stcp 提供者 / 访客，tcpMux on/off、TLS on） | ✅ 实测通过 |
| rustunnel frps | 官方 frpc（stcp `allow_users`：`user=alice` 放行 / `user=mallory` 被拒，错误文本可回传） | ✅ 实测通过 |
| 官方 frps | rustunnel frpc（stcp 提供者 / 访客，tcp_mux on/off、TLS on） | ✅ 实测通过 |
| 官方 frps | rustunnel frpc（stcp `allow_users=["alice"]`，`user=alice` 放行） | ✅ 实测通过 |
| rustunnel frps | rustunnel frpc（含 TLS、关 yamux 组合、stcp / xtcp、`allow_users` 空/名单/`*` 三种语义） | ✅ 实测通过 |

官方客户端需显式指定 v2 协议：

```toml
# 官方 frpc 侧
transport.wireProtocol = "v2"
```

## 代理类型

| 类型 | 公网入口 | 说明 |
|---|---|---|
| `tcp` | `remote_port` | 每条访客连接一条工作连接 |
| `udp` | `remote_port` | 每个代理一条专用工作连接，报文带访客地址；会话 30s 空闲回收 |
| `http` | 服务端 `vhost_http_port` | 按 `Host` 路由，支持 `custom_domains` / `subdomain` / `locations` / `http_user` / `host_header_rewrite` |
| `https` | 服务端 `vhost_https_port` | 按 TLS SNI 路由后原样透传（不终止 TLS） |
| `stcp` | 无（不占公网端口） | 私密隧道：由访客端在本地起监听，凭 `sk` + `allow_users` 鉴权后才能连到提供者 |
| `xtcp` | 无（不占公网端口） | 兼容官方 xtcp 访客；rustunnel **走服务端中转**（不做 UDP 打洞），官方访客会收到明确错误后快速失败 |

UDP 报文有两种编码：**二进制**（`type=19`，与官方 frp 默认一致）和 JSON（base64 载荷）。
握手时由服务端在 ServerHello 里选定，客户端自动适配，两边都不支持二进制时退回 JSON。

### stcp（私密隧道）

`stcp` 让**提供者**（内网服务方）不占用任何公网端口，只有持相同 `sk` 且在白名单里的**访客**才能连上。

提供者（内网机器）—— 与普通代理同处 `[[proxies]]`，但用 `secret_key` 代替 `remote_port`：

```toml
# frpc.toml（提供者）
[[proxies]]
name = "secret-ssh"
type = "stcp"
local_addr = "127.0.0.1:22"
secret_key = "abcdefg"          # 也叫 sk，双方必须一致
allow_users = ["alice"]         # 见下表；留空 = 只允许同 user
```

访客（另一台机器）—— 用 `[[visitors]]`，在本地监听一个端口：

```toml
# frpc.toml（访客）
user = "alice"                  # ← allow_users 比对的是这里，不是 visitor 的 name
server_addr = "your.server.com"
server_port = 7000
token = "your_secret_token"

[[visitors]]
name = "alice-local"            # 访客的本地标识，随便起
type = "stcp"
server_name = "secret-ssh"      # 提供者注册的代理名
server_user = "alice"           # 目标 provider 所属客户端的 user（省略则用本客户端的 user）
secret_key = "abcdefg"          # 必须与提供者一致
bind_addr = "127.0.0.1"
bind_port = 9000                # 本机 9000 即可访问到提供者的 22
```

`allow_users` 的语义与官方 frp 完全一致（对应 `server/visitor.Manager.NewConn`）：

| `allow_users` | 允许谁接入 |
|---|---|
| 未配置 / 空 | 只允许**与 provider 同一 user** 的访客 |
| `["*"]` | 所有访客 |
| `["alice", "bob"]` | 顶层 `user` 为 alice 或 bob 的访客 |

还有两个容易踩的点：

1. 比对的是**访问方 frpc 在 `Login` 里声明的顶层 `user`**，不是 `[[visitors]]` 的 `name`。
   访客写错会收到 `user [x] not allowed` 并被断开（不会静默超时）。
2. 代理名在协议层带 user 前缀（官方 `naming.AddUserPrefix`）：`user` 非空时线协议名是
   `"{user}.{name}"`。所以**访客要访问别人的 provider，必须把 `server_user` 写成对方的 user**，
   否则会得到 `listener doesn't exist`。

之后在访客机器上 `ssh -p 9000 127.0.0.1` 即可。服务端只做**中转配对**：把访客连接和提供者的工作连接对接起来，字节流不经过服务端解析。

### xtcp

rustunnel 不实现 UDP 打洞（需要 QUIC/KCP 与 NAT 类型探测，暂未纳入），
因此 `type = "xtcp"` 的**提供者**在 rustunnel 侧按 `stcp` 的中转路径工作；
**官方 frpc 的 xtcp 访客**连上后会立即收到 `nat hole is not supported by rustunnel-server` 并失败退出，
而不会像官方那样卡在打洞超时。若要真正的 P2P，请用官方 `frps` + 官方 `frpc`。

## 配置参考

### 服务端（rustunnel-server）

| 项 | 说明 | 默认 |
|---|---|---|
| `bind_addr` | 监听地址 | `0.0.0.0` |
| `bind_port` | 控制与工作连接共用端口（与 frp 一致） | `7000` |
| `token` | 认证 token，客户端必须一致 | 必填 |
| `tcp_mux` | 允许 yamux 多路复用（自动探测，不影响非 mux 客户端） | `true` |
| `tls_force` | 强制客户端使用 TLS | `false` |
| `vhost_http_port` | HTTP 代理入口端口（不配则拒绝 http 代理） | 空 |
| `vhost_https_port` | HTTPS 代理入口端口 | 空 |
| `subdomain_host` | 泛域名后缀，配合客户端 `subdomain` | 空 |
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
| `user` | 客户端用户名（frp 顶层 `user`），stcp/xtcp 的 `allow_users` 就是比对它 | 空 |
| `[[proxies]]` | 代理列表，字段见下 | - |
| `[[visitors]]` | stcp / xtcp 访客列表，字段见下 | - |

`[[proxies]]` 字段：

| 字段 | 说明 |
|---|---|
| `name` | 代理名，全局唯一 |
| `type` | `tcp` / `udp` / `http` / `https` / `stcp` / `xtcp` |
| `local_addr` | 内网服务地址，如 `127.0.0.1:53` |
| `remote_port` | tcp / udp 的公网端口 |
| `custom_domains` | http / https 的域名列表（支持 `*.example.com`） |
| `subdomain` | 配合服务端 `subdomain_host` |
| `locations` | http 路径前缀，留空等价 `/` |
| `http_user` / `http_pwd` | http 基本认证 |
| `host_header_rewrite` | 转发时改写的 Host |
| `secret_key` | stcp / xtcp 的共享密钥（别名 `secretKey`） |
| `allow_users` | stcp / xtcp 允许的**访客客户端 `user`** 白名单（别名 `allowUsers`）；**留空 = 只允许与 provider 同一 user**，`["*"]` = 全部放行 |

`[[visitors]]` 字段：

| 字段 | 说明 |
|---|---|
| `name` | 访客的本地标识（`allow_users` 不比对它，比对的是顶层 `user`） |
| `type` | `stcp` / `xtcp`，默认 `stcp` |
| `server_name` | 要连接的提供者代理名（别名 `serverName`） |
| `server_user` | 目标 provider 所属客户端的 `user`（别名 `serverUser`）；留空用本客户端的 `user` |
| `secret_key` | 共享密钥，必须与提供者一致（别名 `secretKey`） |
| `bind_addr` | 本地监听地址，默认 `0.0.0.0` |
| `bind_port` | 本地监听端口，为 0 时不监听（别名 `bindPort`） |

## 性能

同一转发负载下的常驻内存（RSS）：

| 实现 | 常驻内存 |
|---|---|
| Go 官方 frps（默认） | 31.8 MB |
| Go 官方 frps（GOGC/GOMEMLIMIT 调优后） | 28.8 MB |
| **rustunnel-server（Rust）** | **~3.5 MB** |

客户端二进制约 1.3 MB（Windows），服务端约 2.2 MB（Linux，静态）。

### 吞吐实测（iperf3）

**① 本机回环**（排除公网因素，单看代理本身的转发开销）

`127.0.0.1` 上跑 iperf3 服务端，两种实现各自把 `5201` 投放到远端端口，再从同一台机器连过去，
即数据全程不出本机 —— 测的是代理链路的纯开销。单位 Mbps，5 次取**中位数**，括号内为最好值：

| 场景 | 直连（无隧道） | 官方 frp 0.71.0 | rustunnel |
|---|---|---|---|
| yamux，单流 `-P1`，客户端→服务端 | 17813.0 (21956.9) | 1053.3 (1130.0) | **2034.6** (3941.1) |
| yamux，单流 `-P1`，服务端→客户端 `-R` | 20417.8 (21674.3) | 1154.6 (1456.3) | 1090.5 (1097.8) |
| yamux，4 流 `-P4`，客户端→服务端 | 73594.0 (74291.2) | 3303.1 (3342.5) | **12621.9** (13341.7) |
| yamux，4 流 `-P4`，服务端→客户端 `-R` | 73332.7 (73855.3) | 3314.8 (3338.7) | **13185.6** (13407.4) |
| 关闭 yamux，单流 `-P1`，客户端→服务端 | 25886.3 (26113.4) | 412.6 (441.2) | **1388.9** (1424.3) |
| 关闭 yamux，单流 `-P1`，服务端→客户端 `-R` | 25430.2 (26085.6) | 415.1 (432.6) | **1390.5** (1471.7) |

结论：**多流场景（`-P4`）rustunnel 是官方 frp 的约 3.8~4 倍**（12.6 Gbps vs 3.3 Gbps）；
单流场景两者同一量级（rustunnel 单向量测波动较大，中位数略优于官方）；
关闭 yamux 时 rustunnel 约 1.39 Gbps，是官方（约 0.41 Gbps）的 **3.4 倍**。

> 这一版把 yamux 的 `split_send_size` 从默认 16 KiB 提到 **128 KiB**、并把转发缓冲区从 tokio 默认的
> 8 KiB 提到 **128 KiB**（`RELAY_BUF`）。前者是单流吞吐的主要瓶颈，这正是这里拉开差距的原因。
> 上表用最终发布版二进制实测。

**② 广域网**（家庭宽带 ↔ 阿里云轻量服务器，真实公网链路）

本机 iperf3 服务端 → 本机客户端 → 云端服务端 → 云端 iperf3 客户端，每档 3 次 × 10s 取最好值。
**跑了两次**，下表两个数字分别是两次的结果：

| 方向 | 官方 frp 0.71.0 | rustunnel |
|---|---|---|
| 云端→本机（下行） | 222.8 / 210.0 Mbps | 223.8 / 205.9 Mbps |
| 本机→云端（上行 `-R`） | 51.6 / 51.7 Mbps | 52.3 / 52.0 Mbps |

**结论要说实话：两次跑各有胜负（第一次 rustunnel 略高、第二次官方略高），差值都在 2% 以内，
属于链路抖动。** 真实公共链路的瓶颈是家庭宽带本身（下行约 200~220 Mbps、上行约 50 Mbps），
两种实现都能跑满，说明协议开销在公网上可忽略 —— 差距只在回环（本机内）场景才看得出来。

> 数据来源：`tmp/bench_loopback.py`（回环）、`tmp/bench_wan.py`（广域网）与 `tmp/wan_e2e.py`（端到端）实测，
> 原始日志 `tmp/bench_loopback_final.log`、`tmp/bench_wan_final.log`、`tmp/wan-e2e/`。

### 真机端到端验证（v0.2.0 发布版二进制，真实公网链路）

家用 Windows 机器（家庭宽带）跑客户端，阿里云轻量（`118.178.189.143`）跑服务端，
**两端都用发布包里那份二进制**，直接跨公网跑四种用法：

| 用例 | 链路 | 结果 |
|---|---|---|
| `tcp` | 云端连 `127.0.0.1:15201` → 公网隧道 → 本机 `16101` 回显服务 | ✅ 收到 `ECHO:wan-tcp` |
| `http` | 云端 `curl -H 'Host: e2e.test' http://127.0.0.1:15280/` → 公网 → 本机 `16111` | ✅ 返回本机静态服务目录页 |
| `stcp` | 本机访客 `16102` → 公网服务端中转配对 → 本机 provider `16101` | ✅ 收到 `ECHO:wan-stcp` |
| `stcp` 白名单 | 访客 `user=mallory`（借 `server_user=alice` 定位 provider） | ✅ 被拒：服务端 `WARN visitor 用户不在 allow_users 白名单内`，访客端读到 `visitor connection of [alice.secret] user [mallory] not allowed` |

4/4 通过 —— 说明 tcp / http / stcp 三条链路在真实公网环境下（含 NAT、跨运营商）都能正常工作，
白名单拒绝不只是「连不上」，而是服务端明确鉴权后的拒绝。复现脚本：`tmp/wan_e2e.py`。

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

- `stcp` 已完整实现；`xtcp` 只做**服务端中转**（等价于 stcp），**未实现 UDP 打洞**，因此没有 P2P 直连收益
- 未实现 QUIC、websocket 传输层
- 未实现 frp v1 线协议（官方 v0.78 起也已移除 v1）

## License

MIT
