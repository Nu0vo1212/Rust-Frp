# rustunnel

用 Rust 实现的内网穿透工具，**完整兼容 [fatedier/frp](https://github.com/fatedier/frp) 的 wire protocol v1 与 v2**，可以和官方 `frps` / `frpc`（v0.71.0 实测）直接互通。

**默认就走 v1** —— 与官方 frp 的默认值一致，所以官方客户端 / 服务端**不需要改任何配置**就能连上；v1 覆盖官方源码里的全部算法（帧编码、AES-128-CFB 控制通道加密、yamux 复用、打洞报文），第三方 frp 平台下发的配置也能直接用。

以极小的资源占用换取同等甚至更好的核心能力：服务端常驻内存约 **3.5 MB**（同负载下 Go 版 frps 为 28.8~31.8 MB），单文件部署，无任何运行时依赖。

## 特性

### 代理与传输

- ✅ **frp v1 / v2 双线协议** — **默认 v1**（与官方默认值相同），官方 frpc / frps **零配置直连**；需要时可用 `transport.wireProtocol = "v2"` 显式启用 v2
- ✅ **原版配置直接可用** — 原版 frpc / 第三方 frp 平台下发的配置（camelCase、`[[proxies]]`、`localIP`+`localPort`、`[metadatas]`）无需改写即可运行
- ✅ **六种代理类型** — `tcp` / `udp` / `http` / `https` / `stcp` / `xtcp`，多代理同时工作
- ✅ **UDP 转发** — 每个 UDP 代理只占一条工作连接，靠访客地址区分会话
- ✅ **HTTP 反向代理** — 按域名路由，支持 `locations` 前缀、Basic Auth、Host 改写、自定义请求/响应头
- ✅ **HTTPS SNI 透传** — 只嗅探 ClientHello 里的 SNI 做路由，不终止 TLS，证书仍由内网服务提供
- ✅ **stcp 私密隧道** — 服务端不开放公网端口，需 `secret_key` 校验 + 提供者端 `allow_users` 白名单，与官方 frp 互通
- ✅ **xtcp 真 P2P** — UDP 打洞 + QUIC / KCP 直连，数据不经服务端；打不通自动回退中继，不会比 stcp 更差
- ✅ **对称 NAT 端口预测** — 靠多次观测推端口步长，锥型之外的对称 NAT 也有机会打洞成功
- ✅ **KCP 弱网通道** — `xtcp_transport = "kcp"`，丢包环境下靠重传换来更低延迟
- ✅ **QUIC 传输** — `transport_protocol = "quic"`，1-RTT 握手、流级多路复用、丢包不阻塞其它流
- ✅ **yamux 多路复用** — 对应 frp `transport.tcpMux`，控制连接与工作连接复用一条 TCP
- ✅ **TLS 加密** — 对应 frp `transport.tls`，含 frp 自定义首字节 `0x17` 伪装，服务端自动生成自签名证书

### 运维与调度

- ✅ **group 负载均衡** — 同 `group` 的多个代理共享一个 `remote_port`，服务端按**最小连接数**分摊
- ✅ **健康检查** — `tcp` / `http` 探测，连续失败自动摘除后端，恢复后自动回归
- ✅ **客户端插件** — `http_proxy` / `socks5` / `static_file` / `unix_domain_socket`，frpc 本身即正向代理或静态站点
- ✅ **带宽限流** — 每个代理可配 `bandwidth_limit`（如 `1MB`），令牌桶精确限速
- ✅ **资源上限** — 客户端数 / 代理数 / 转发连接数 / 待处理队列，五个维度全部可限并计入指标
- ✅ **可观测性** — 内置 Web 面板 + Prometheus `/metrics` + 健康检查端点，支持 Basic Auth
- ✅ **面板可写** — 在面板上直接增删代理、踢掉客户端，无需改配置重启（`/api/proxies/add` 等）
- ✅ **配置热重载** — 改 `log_level` / 面板密码无需重启，静态项变更会明确提示需重启

### 工程质量

- ✅ **282 个自动化测试** — 含真实 QUIC 栈握手、口令正反用例、端到端集成测试、**与官方 frpc/frps 真实抓包密文的解密回归**
- ✅ **CI 流水线** — `fmt` / `clippy` / 测试 / 四目标构建 / 冒烟，PR 必过
- ✅ **发布可验真** — `SHA256SUMS` + 可选 Ed25519 分离签名与本地验签脚本
- ✅ **容器就绪** — 多阶段 `Dockerfile`（musl 静态）+ `docker-compose.yml`
- ✅ **跨平台** — Windows / Linux amd64 / Linux arm64（arm64 全静态链接，无 glibc 依赖）

## 架构

```
rustunnel/
├── common/                    # 公共库（协议实现核心）
│   └── src/
│       ├── frp/
│       │   ├── v1.rs          #   v1 线协议（官方默认）：消息类型字节、帧编解码、
│       │   │                  #     AES-128-CFB 控制通道加密（PBKDF2 salt = "frp"）
│       │   ├── wire.rs        #   v2 线协议：magic 前缀、帧编解码、握手协商
│       │   ├── crypto.rs      #   v2 控制通道加密：HKDF-SHA256 + AES-256-GCM
│       │   ├── msg.rs         #   JSON 消息：Login/NewProxy/ReqWorkConn/NatHole*（v1/v2 共用）
│       │   ├── conn.rs        #   加密连接的读写封装 + 版本自动识别（服务端）
│       │   ├── tls.rs         #   frp 自定义 TLS（自签证书 + 0x17 首字节）
│       │   ├── quic.rs        #   QUIC 传输（quinn），一条双向流 = 一条 frp 连接
│       │   ├── mux.rs         #   yamux 会话封装
│       │   ├── sni.rs         #   TLS ClientHello / SNI 嗅探
│       │   └── stream.rs      #   统一流抽象 BoxStream
│       ├── p2p.rs             #   xtcp 打洞：报文字典、口令、ALPN、角色
│       ├── throttle.rs        #   令牌桶带宽限流
│       ├── config.rs          #   两端配置结构与示例生成
│       └── util.rs            #   地址解析、转发、run_id、日志热重载
├── server/                    # frps 等价服务端
│   └── src/
│       ├── serve.rs           #   入口分层：TCP / QUIC / vhost / 代理注册
│       ├── registry.rs        #   全局状态：客户端表、端口组（group 负载均衡）
│       ├── pool.rs            #   工作连接池：配对、排队、回收、配额
│       ├── limits.rs          #   信号量资源上限
│       ├── observability.rs   #   指标计数器与 Prometheus / JSON 编码
│       ├── dashboard.rs       #   内置面板 + /metrics + /api/status
│       ├── reload.rs          #   配置热重载（mtime 轮询 + 字段差异判定）
│       ├── p2p.rs             #   xtcp 牵线中心（UDP rendezvous）
│       ├── vhost.rs           #   HTTP/HTTPS 虚拟主机路由与反向代理
│       ├── visitor.rs         #   stcp/xtcp 访客注册表
│       └── udp_proxy.rs       #   UDP：公网 socket ⇄ 专用工作连接
└── client/                    # frpc 等价客户端
    └── src/
        ├── main.rs            #   会话主循环、ServerLink、工作连接
        ├── p2p.rs             #   xtcp 打洞（QUIC 建连 + 口令握手）
        ├── health.rs          #   健康检查监视器（进程级）
        ├── plugin.rs          #   四类客户端插件
        ├── visitor.rs         #   stcp/xtcp：本地监听 → 回源
        └── udp_proxy.rs       #   UDP：每个访客一个本地 socket
```

传输层次：

```
TCP  → [TLS] → [yamux] → frp v2 连接
UDP  → QUIC（自带 TLS1.3 + 流多路复用）→ frp v2 连接
```

TLS 与 yamux 均为可选，由配置决定。服务端通过**首字节探测**自动识别：
`0x00` = yamux 帧、`0x17`/`0x16` = TLS、`'F'` = frp v2 magic，
因此开启 `tcp_mux` 后仍可同时服务 `tcpMux = false` 的旧客户端。

QUIC 模式下服务端会在**同一个端口号**上额外监听 UDP，TCP 监听保持不动——
所以切换 `transport_protocol` 不会一刀切，老客户端照旧能连。

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

# 可选：xtcp 真 P2P 的牵线端口（需放行 UDP）
p2p_port = 7002

# 可选：内置面板 + Prometheus 指标
dashboard_port = 7500
dashboard_user = "admin"
dashboard_pwd = "change_me"

# 可选：改 log_level / 面板密码不用重启
hot_reload = true
```

```bash
./rustunnel-server -c frps.toml
# 也可以直接生成带注释的示例配置：
./rustunnel-server --gen-config frps.toml
```

### 启动客户端（内网机器）

```toml
# frpc.toml
server_addr = "your.server.com"
server_port = 7000
token = "your_secret_token"
tcp_mux = true
tls_enable = false
# protocol = "frp-v1"      # 默认就是 v1（与官方默认值一致），不用写

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
| 第三方 frp 平台（LoliaFRP） | rustunnel frpc（用平台下发的**原版配置**直接启动） | ✅ 实测通过（v0.3.1） |
| 官方 frps v0.71.0 | rustunnel frpc（**v1，零配置**） | ✅ 实测通过（v0.3.3） |
| rustunnel frps | 官方 frpc v0.71.0（**v1，零配置**） | ✅ 实测通过（v0.3.3） |

### 线协议：默认 v1，和官方一致（v0.3.2 起）

官方 frp 的 `transport.wireProtocol` **缺省值就是 `v1`**（见 `pkg/config/v1/client.go`），
v2 只有显式配置才会启用。所以"兼容 frp"的实现必须以 v1 为默认 —— v0.3.2 起 rustunnel
也照此默认，**官方 frpc / frps 不需要改任何配置**就能互通：

```toml
# 官方 frpc 侧 —— 什么都不用写，这就是默认值
```

想用 v2 时就显式打开（两端都要）：

```toml
# 官方 frpc 侧 / rustunnel 侧均可
transport.wireProtocol = "v2"
```

rustunnel 服务端**不需要预先知道对端用哪个版本**：它读满 8 字节与 v2 的魔术字逐字节比较
（`pkg/proto/wire/wire.go` 的 `CheckMagic` 语义），相同就走 v2，不同就**把这 8 字节原样留在
缓冲区里**按 v1 解析 —— 那 8 字节本来就是 v1 的类型字节 + 长度前缀。所以同一个端口
同时接待 v1 与 v2 客户端。

> **注意**：官方 frp 没有 QUIC 传输（只有 TCP/KCP/QUIC 三选一的 `transport.protocol`），
> 所以 `transport_protocol = "quic"` 只在 rustunnel 两端之间可用；
> 与官方互通时请保持 `tcp`。

### 直接使用原版 frp 的配置文件（v0.3.1 起）

原版 frp 的配置**不需要改写**就能直接喂给这个 `frpc` —— 第三方 frp 平台
（LoliaFRP / OpenFrp / SakuraFrp 等）下发的就是这种格式，拷过来即可运行。

解析前会过一遍 `common/src/frp_config.rs` 的兼容层，把原版字段名规范化成 rustunnel 风格：

| 原版 frp 写法 | 归一化成 |
|---|---|
| `serverAddr` / `serverPort` | `server_addr` / `server_port` |
| `localIP` + `localPort`（两段） | `local_addr = "ip:port"`（IPv6 自动加方括号） |
| `auth.token` | `token` |
| `[metadatas]` | `metas`（整表透传） |
| `[proxies.transport] bandwidthLimit` | `bandwidth_limit` |
| `[proxies.transport] bandwidthLimitMode` | `bandwidth_limit_mode` |
| `[proxies.healthCheck]` 子表 | `health_check_*` 平铺 |
| `[proxies.plugin]` 子表 | `plugin` / `plugin_local_path` / `plugin_strip_prefix` / … |

原则是「只补不覆盖」：rustunnel 自己的写法同时有效，两种写法混用时**原生字段优先**。

两个容易搞反的地方：

- **`[metadatas]` 不参与认证**，认证用顶层 `token`。它只是"随消息带给服务端的附加信息"，
  整表透传（登录时进 `Login.metas`，代理级的 `[proxies.metadatas]` 进 `NewProxy.metas`）。
  平台常把隧道凭证塞在这里 —— 删了登录不上；但把它当本地认证 token 也是错的
  （会导致服务端回 `token in login doesn't match token from configuration`）。
- **代理名的 `{user}.` 前缀由客户端加上**（对应官方 `naming.AddUserPrefix`），
  且服务端保持幂等。注意官方 frpc 的日志 `proxy added: [xxx]` 打的是**配置里的原始名**，
  很容易据此以为线上也不带前缀 —— 别信日志，要抓包看 `NewProxy.proxy_name`。

## 代理类型

| 类型 | 公网入口 | 说明 |
|---|---|---|
| `tcp` | `remote_port` | 每条访客连接一条工作连接 |
| `udp` | `remote_port` | 每个代理一条专用工作连接，报文带访客地址；会话 30s 空闲回收 |
| `http` | 服务端 `vhost_http_port` | 按 `Host` 路由，支持 `custom_domains` / `subdomain` / `locations` / `http_user` / `host_header_rewrite` |
| `https` | 服务端 `vhost_https_port` | 按 TLS SNI 路由后原样透传（不终止 TLS） |
| `stcp` | 无（不占公网端口） | 私密隧道：由访客端在本地起监听，凭 `secret_key` + `allow_users` 鉴权后经服务端配对 |
| `xtcp` | 无（不占公网端口） | 先试 **UDP 打洞 + QUIC 直连**；打不通自动回退服务端中继 |

UDP 报文有两种编码：**二进制**（`type=19`，与官方 frp 默认一致）和 JSON（base64 载荷）。
握手时由服务端在 ServerHello 里选定，客户端自动适配，两边都不支持二进制时退回 JSON。

### stcp（私密隧道）

`stcp` 让**提供者**（内网服务方）不占用任何公网端口，只有持相同 `secret_key` 且在白名单里的**访客**才能连上。

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

### xtcp（真 P2P）

`xtcp` 在提供者与访客之间尝试建立**直连**，打通后流量完全不经服务端，带宽不再受服务端限制。
整个流程分三步：

```
1. 牵线     访客在控制连接上发 NatHoleVisitor{proxy_name, sign_key, timestamp}
            服务端校验 sk 后建会话、回 NatHoleResp{sid}，同时给提供者推 NatHoleClient{sid}
2. 打洞     两端各自从「牵线用的那个 UDP socket」向服务端索要对方公网地址
            （Hello{sid, role} → Peer{sid, addr}），SNAT 因此被提前建立
3. 直连     两端用**同一个 socket** 对打 QUIC；谁先握上谁当服务端
            连上后立刻做一次口令握手（HMAC-SHA256(secret_key, sid)），
            不对就断开 —— 防止 NAT 外任意主机连进来
```

配置只需两端都写上同一个 `p2p_port`：

```toml
# frps.toml
p2p_port = 7002          # 注意：防火墙 / 安全组要放行这个 UDP 端口

# frpc.toml（提供者与访客都加）
p2p_port = 7002
p2p_enable = true        # 默认 true；设 false 就永远走中继
```

```toml
# 提供者
[[proxies]]
name = "p2p-ssh"
type = "xtcp"
local_addr = "127.0.0.1:22"
secret_key = "abcdefg"

# 访客
[[visitors]]
name = "p2p-local"
type = "xtcp"
server_name = "p2p-ssh"
secret_key = "abcdefg"
bind_port = 9002
```

**回退是自动且静默的**：对称 NAT、UDP 被封、`p2p_port` 没配、打洞超时……
任一环节失败都会退回 stcp 那条中继路径，只是日志里会记一行 `P2P 打洞失败，回退中继`。
所以 xtcp 在任何网络环境下都不会比 stcp 更差。

> 服务端如果没配 `p2p_port`，会明确拒绝 `NatHoleVisitor` 并回 `nat hole not enabled`，
> 而不是让访客干等超时 —— 官方 frpc 的 xtcp 访客也会因此**快速失败**而不是挂起。

## 传输层

### QUIC

```toml
# 两端都要配成 quic
transport_protocol = "quic"
```

选 QUIC 的收益：

| 维度 | TCP + yamux | QUIC |
|---|---|---|
| 建连 | TCP 三次握手 + TLS 握手 | 1-RTT（会话复用可 0-RTT） |
| 队头阻塞 | 一条流丢包，ymax 上其它流一起等 | 流间完全独立 |
| 加密 | 需要额外套 TLS | 内置 TLS 1.3 |
| 多路复用 | yamux 用户态分帧 | 协议原生，每条双向流即一条 frp 连接 |
| NAT 友好 | 走 TCP | 需要放行 UDP |

实现要点：

- QUIC 模式下**跳过** TLS 与 yamux 两层（QUIC 自带加密与多路复用），
  每条双向流直接当作一条 frp 连接处理，控制 / 工作 / visitor 都走这里；
- 服务端在同一端口号上额外监听 UDP，TCP 监听保留，便于灰度；
- 客户端 `ServerLink` 会同时持有 `Endpoint` 与 `Connection`——
  quinn 的 `Endpoint` 一旦 drop，上面的连接会立刻断开，只留 `Connection` 是不够的。

### TLS / yamux

`tls_enable` / `tls_force` / `tcp_mux` 与官方 frp 语义一致，且服务端支持自动探测，
能同时服务开了与没开这些选项的客户端。

## 负载均衡与服务发现

### group：多后端共享一个端口

同名 `group` 的多个代理可以**注册同一个 `remote_port`**，服务端为这个端口维护一组后端，
每条新连接按**最小连接数**选一个（各后端在途连接数相等时退化为轮流）：

```toml
# 机器 A
[[proxies]]
name = "web-a"
type = "tcp"
local_addr = "127.0.0.1:8080"
remote_port = 6100
group = "web"                 # 同组
group_key = "shared_secret"   # 组密钥，同组保持一致即可

# 机器 B（同样的 remote_port 和 group）
[[proxies]]
name = "web-b"
type = "tcp"
local_addr = "127.0.0.1:8080"
remote_port = 6100
group = "web"
```

规则：

- 组名相同 → 加入同一组（共享端口）；组名不同 → 冲突，注册失败并回明确错误；
- **没配 `group` 的代理视为独占端口**，别人不能共享它，它也不能加入别人的组；
- 组内最后一个后端掉线时端口才真正释放；客户端断线时它占的端口会被一次性收回。

调度按**在途连接数**（不是 CPU / 内存这类需要后端上报的指标），所以既有"慢后端自动少接活"的
弹性，又不给客户端增加任何上报负担；空闲时它等同于轮询，行为可预期。

### 健康检查

配了健康检查的代理，在探测不通过时会**拒绝新的工作连接**（表现为该后端临时不可用），
配合 `group` 就实现了自动摘除/回归：

```toml
[[proxies]]
name = "web-a"
type = "tcp"
local_addr = "127.0.0.1:8080"
remote_port = 6100
group = "web"

health_check_type = "http"        # tcp / http，留空 = 不检查
health_check_url = "/healthz"     # http 检查的路径，留空用 /
health_check_interval_s = 10      # 探测间隔（秒）
health_check_timeout_s = 3        # 单次超时（秒）
health_check_max_failed = 3       # 连续失败几次判定不健康
```

探测是**进程级**的：跨重连持续运行，状态不会因为会话重建而丢失；
用 `health_check_max_failed` 而不是"一次失败就下线"，是为了不被瞬时抖动误伤。

## 客户端插件

`plugin` 字段让工作连接不再连 `local_addr`，而是接到插件上——
于是 frpc 本身就能当正向代理或静态站点服务器用：

| `plugin` | 说明 | 需要的字段 |
|---|---|---|
| `http_proxy` | HTTP 正向代理，支持 `CONNECT` 隧道 | 可选 `plugin_user` / `plugin_passwd` |
| `socks5` | SOCKS5 代理（无认证 / 用户名密码） | 可选 `plugin_user` / `plugin_passwd` |
| `static_file` | 直接把一个目录当静态站点服务 | 必填 `plugin_local_path`，可选 `plugin_strip_prefix` |
| `unix_domain_socket` | 转发到本地 Unix 套接字 | 必填 `plugin_local_path`（仅 Unix） |

```toml
[[proxies]]
name = "proxy"
type = "tcp"
remote_port = 6200
plugin = "http_proxy"
plugin_user = "u"
plugin_passwd = "p"
```

## 带宽限流

给单个代理配 `bandwidth_limit` 就能限制它的吞吐，防止某条代理把整条上行链路吃满：

```toml
[[proxies]]
name = "backup"
type = "tcp"
local_addr = "127.0.0.1:22"
remote_port = 6300
bandwidth_limit = "1MB"      # 单位：字节/秒；KB = 1000，KiB = 1024；不填或 0 = 不限
```

实现是标准**令牌桶**（`common/src/throttle.rs`），上下行各自限速，空闲时会累积额度、
突发流量不会被硬砍。没配这个字段时代码走的就是原来的 `relay_between`，行为完全不变。

## 可观测性

```toml
# frps.toml
dashboard_port = 7500
dashboard_user = "admin"
dashboard_pwd = "change_me"
```

| 端点 | 说明 |
|---|---|
| `GET /` | 内置 HTML 面板：在线客户端、代理、访客、占用端口、实时指标（5 秒自动刷新） |
| `GET /metrics` | Prometheus exposition format，可直接被 Prometheus / VictoriaMetrics 抓取 |
| `GET /api/status` | 与面板同源的 JSON 快照 |
| `GET /api/healthz` | 存活探针，返回 `ok`（不带鉴权，供 k8s / 负载均衡器使用） |
| `POST /api/proxies/add` | 给指定客户端动态加一条代理（JSON：`run_id` + `proxy`），成功即端口已就绪 |
| `POST /api/proxies/remove` | 移除客户端上的一条代理（`run_id` + `name`），端口随即收回 |
| `POST /api/clients/kick` | 断开指定客户端（`run_id`） |

写接口一律需要 Basic Auth（未鉴权返回 401），执行顺序是先问客户端、后动服务端状态：
新增时客户端拒绝就回滚，不会留下"面板显示成功但没人干活"的端口。

```bash
curl -u admin:pwd -H 'Content-Type: application/json' \
  -d '{"run_id":"<面板里的 run_id>","proxy":{"name":"web","type":"tcp","local_addr":"127.0.0.1:8080","remote_port":6100}}' \
  http://127.0.0.1:7500/api/proxies/add
```

> 动态管理走 rustunnel 两端之间的私有消息，**客户端先是 rustunnel frpc 才支持**
> （官方 frpc 连上来时面板会把它标为不可管理的，对应接口返回明确错误）。

指标（前缀 `rustunnel_`）：

| 指标 | 类型 | 含义 |
|---|---|---|
| `clients_total` / `clients_active` / `clients_rejected` | counter / gauge / counter | 登录过的 / 在线的 / 被拒的客户端 |
| `proxies_total` / `proxies_active` / `proxy_failures` | counter / gauge / counter | 注册过的 / 生效的 / 注册失败的代理 |
| `conns_total` / `conns_active` / `conns_rejected` | counter / gauge / counter | 转发连接数（含因上限被拒的） |
| `bytes_up_total` / `bytes_down_total` | counter | 上下行累计字节 |
| `http_requests_total` / `https_conns_total` | counter | 虚拟主机处理的请求 / 透传连接 |
| `visitor_conns_total` / `visitor_rejected_total` | counter | stcp/xtcp 访客接入与被拒次数 |
| `p2p_success_total` / `p2p_failed_total` | counter | xtcp 打洞成功 / 失败回退次数 |
| `uptime_seconds` | gauge | 服务端已运行秒数 |

配置了 `dashboard_user` 后 `/`、`/metrics`、`/api/status` 需要 HTTP Basic Auth
（`/api/healthz` 始终免鉴权）。鉴权用常量时间比较，只接受完整的 `user:password`。

### 配置热重载

```toml
hot_reload = true    # 需要配合 -c 指定配置文件（服务端会监视它的 mtime）
```

| 字段 | 行为 |
|---|---|
| `log_level` | **热生效**，立即切换日志过滤器 |
| `dashboard_user` / `dashboard_pwd` | **热生效**，面板鉴权立即更新 |
| 其余字段 | 记一条 WARN，提示这些项需要重启才能生效（不会静默忽略） |

## 资源上限

全部可配，`0` 或不填 = 不限。超限时拒绝**并计数**（对应 `clients_rejected` / `conns_rejected` / `proxy_failures`），
不会静默丢弃：

```toml
# frps.toml
max_clients = 100            # 同时在线的客户端数
max_proxies_per_client = 50  # 单个客户端可注册的代理数
max_conns_per_client = 200   # 单个客户端同时转发的连接数
max_total_conns = 5000       # 全局同时转发的连接数
max_pending_per_client = 64  # 单个客户端排队等工作连接的请求数
```

实现细节：用 `tokio::sync::Semaphore` 的 owned permit 做 RAII 配额，
**配额令牌随连接/代理的生命周期存活**（而不是"检查一下就算过"），
所以不会出现"上限配了但没生效"或"名额泄漏后越用越少"这两类问题。

## 配置参考

### 服务端（rustunnel-server）

| 项 | 说明 | 默认 |
|---|---|---|
| `bind_addr` | 监听地址 | `0.0.0.0` |
| `bind_port` | 控制与工作连接共用端口（与 frp 一致） | `7000` |
| `token` | 认证 token，客户端必须一致 | 必填 |
| `tcp_mux` | 允许 yamux 多路复用（自动探测，不影响非 mux 客户端） | `true` |
| `tls_force` | 强制客户端使用 TLS | `false` |
| `transport_protocol` | `tcp` 或 `quic`（需客户端一致） | `tcp` |
| `vhost_http_port` | HTTP 代理入口端口（不配则拒绝 http 代理） | 空 |
| `vhost_https_port` | HTTPS 代理入口端口 | 空 |
| `subdomain_host` | 泛域名后缀，配合客户端 `subdomain` | 空 |
| `p2p_port` | xtcp 打洞牵线的 UDP 端口（不配则 xtcp 只走中继） | 空 |
| `dashboard_port` | 内置面板 / 指标端口 | 空 |
| `dashboard_user` / `dashboard_pwd` | 面板 Basic Auth（用户名留空 = 不鉴权） | 空 |
| `hot_reload` | 监视配置文件 mtime 并热应用动态项 | `false` |
| `max_clients` | 同时在线的客户端数上限 | `0`（不限） |
| `max_proxies_per_client` | 单客户端代理数上限 | `0` |
| `max_conns_per_client` | 单客户端转发连接数上限 | `0` |
| `max_total_conns` | 全局转发连接数上限 | `0` |
| `max_pending_per_client` | 单客户端排队请求数上限 | `0` |
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
| `transport_protocol` | `tcp` 或 `quic`（需服务端一致） | `tcp` |
| `p2p_port` | 服务端 xtcp 牵线端口，需与服务端 `p2p_port` 一致 | 空 |
| `p2p_enable` | 是否允许 xtcp 尝试 P2P（失败自动回退中继） | `true` |
| `pool_count` | 预建工作连接数（0 = 按需） | `1` |
| `login_fail_exit` | 首次登录失败就退出（对齐官方 `loginFailExit`）。成功登录过之后断线仍无限重连 | `true` |
| `reconnect_interval` | 断线重连间隔（秒），对齐官方 `reconnectInterval` | `10` |
| `user` | 客户端用户名（frp 顶层 `user`），stcp/xtcp 的 `allow_users` 就是比对它 | 空 |
| `[[proxies]]` | 代理列表，字段见下 | - |
| `[[visitors]]` | stcp / xtcp 访客列表，字段见下 | - |

`[[proxies]]` 字段：

| 字段 | 说明 |
|---|---|
| `name` | 代理名，全局唯一 |
| `type` | `tcp` / `udp` / `http` / `https` / `stcp` / `xtcp` |
| `local_addr` | 内网服务地址，如 `127.0.0.1:53` |
| `remote_port` | tcp / udp 的公网端口（同 `group` 可与他人共享） |
| `custom_domains` | http / https 的域名列表（支持 `*.example.com`） |
| `subdomain` | 配合服务端 `subdomain_host` |
| `locations` | http 路径前缀，留空等价 `/` |
| `http_user` / `http_pwd` | http 基本认证 |
| `host_header_rewrite` | 转发时改写的 Host |
| `bandwidth_limit` | 带宽上限，如 `1MB`（`KB`=1000、`KiB`=1024）；留空 = 不限 |
| `group` / `group_key` | 负载均衡组名与组密钥；同名组共享 `remote_port` |
| `health_check_type` | `tcp` / `http`；留空 = 不检查 |
| `health_check_url` | http 检查路径，留空用 `/` |
| `health_check_interval_s` | 探测间隔（秒），默认 `10` |
| `health_check_timeout_s` | 单次超时（秒），默认 `3` |
| `health_check_max_failed` | 连续失败几次判定不健康，默认 `3` |
| `plugin` | `http_proxy` / `socks5` / `static_file` / `unix_domain_socket` |
| `plugin_local_path` | `static_file` 的目录 / `unix_domain_socket` 的套接字路径 |
| `plugin_strip_prefix` | `static_file` 回源时剥掉的路径前缀 |
| `plugin_user` / `plugin_passwd` | `http_proxy` / `socks5` 的认证 |
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

> 数据来源：`tmp/bench_loopback.py`（回环）、`tmp/bench_wan.py`（广域网）与 `tmp/wan_e2e.py`（端到端）实测。

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

> v0.3.0 的新增能力（xtcp P2P、QUIC、插件、group、健康检查、限流）由自动化测试覆盖，
> 其中包含**真实 QUIC 栈**的握手与数据往返、打洞口令正反用例、以及端到端集成测试；
> 跨公网的真机复测见 v0.3.0 发布说明。
>
> v0.3.1 是一个**第三方平台兼容性补丁**：`frpc` 现在能直接吃下原版 frp 平台下发的配置
> （camelCase 字段名、`[[proxies]]` 分段、`localIP` + `localPort`），并且**线协议行为与官方
> frpc 逐字节对齐**（`proxy_name` 带 `{user}.` 前缀、`bandwidthLimitMode` 字段）。
> 已用 LoliaFRP 真实服务端跑通端到端隧道（公网端口 → 平台 → rustunnel → 本地服务）。
> 同版还修掉一个 xtcp 回归：provider 侧漏剥 `{user}.` 前缀，导致打洞通知被当「未知代理」
> 忽略、P2P 静默退化成中继（本机冒烟 12/12 已覆盖"是否真走直连"）。
>
> v0.3.2 补上了**官方默认的 v1 线协议**：在此之前 rustunnel 只讲 v2，官方客户端必须显式
> 写 `transport.wireProtocol = "v2"` 才能连 —— 而第三方 frp 平台一律走 v1，这正是上一版
> 在樱花上失败的原因。现在 v1 是默认，官方 frpc / frps 零配置直连，服务端还能在同一个
> 端口上同时接待 v1 与 v2。踩过的最大的坑写进了源码注释：**v1 控制通道的 PBKDF2 盐是
> `"frp"` 而不是 golib master 里的 `"crypto"`**（frp 0.71.0 锁的是 golib v0.8.2）——
> 照着 master 写会得到一个"自加密自解密全对、一接官方 frps 就连上即断"的实现。
> 已用官方 frps / frpc v0.71.0 双向实测，并把**官方抓包的真实密文**做成回归用例锁死。
>
> v0.3.3 把上一版列在「已知限制」里的四条短板一次性补掉：**xtcp 对称 NAT 端口预测**
> （按观测端口的步长推候选，不再一击不中就回退中继）、**KCP 弱设备通道**
> （`xtcp_transport = "kcp"`，自研 ikcp，30% 丢包下 20KB 仍可靠送达）、
> **面板可写**（动态增删代理 / 踢客户端，私有消息 + 能力协商，对官方 frpc 零影响）、
> **group 改最小连接数调度**（平局退化为轮询）。顺带修掉两个真 bug：
> QUIC `Endpoint` 被提前 drop 导致 P2P 刚握完手就 `closed by peer: 0`、
> 面板不读请求体导致跨 TCP 段的 POST 被截断。

## 质量保障

```bash
cargo fmt --all -- --check          # 格式
cargo clippy --workspace --all-targets   # 静态检查（当前 0 告警）
cargo test --workspace              # 282 个测试
```

测试分布：

| 目标 | 数量 | 覆盖重点 |
|---|---|---|
| `common` 单元测试 | 119 | **v1 线协议**（消息类型字节、帧编解码、AES-128-CFB 密钥派生与流式状态机、**官方抓包密文解密回归**）、v2 线协议编解码、加密、配置解析、**原版 frp 配置兼容层**、打洞报文/口令/端口预测、**KCP（含 30% 丢包下的可靠传输）**、令牌桶、示例配置可加载 |
| `server` 单元测试（lib） | 100 | 虚拟主机路由表与优先级、chunked 解析、Basic Auth、连接池配对与回收、**端口组最小连接数调度**、资源配额、指标编码、面板鉴权与**写接口**、热重载字段判定、打洞会话 |
| `server` 单元测试（bin） | 5 | 命令行与配置装载 |
| `client` 单元测试 | 46 | QUIC 建连与口令握手、插件（http_proxy / socks5 / static_file）、健康检查状态机、打洞编排、`NewProxy` 字段映射（含与官方 frpc 抓包逐字节对拍）、服务端下发名 → 本地代理的翻译（`resolve_uploaded_proxy`）、**动态代理表** |
| `server` 端到端集成测试 | 12 | 真握手 + 真转发的 TCP / HTTP / stcp / QUIC 链路、**v1 与 v2 双协议握手**、group 负载均衡、面板鉴权边界 |

CI（`.github/workflows/ci.yml`）在每次 push / PR 上跑：`fmt` → `clippy` → 测试 →
四个目标（windows-msvc / linux-musl / linux-gnu / linux-arm64）构建 → 端到端冒烟。

## 发布与部署

### 发布包自带校验

```bash
# 打三平台包（包内统一命名 frps / frpc，附示例配置与 README）
python scripts/release.py pack --target windows-amd64:target/release \
                               --target linux-amd64:/path/to/amd64 \
                               --target linux-arm64:/path/to/arm64 \
                               --out dist/release

# 生成 SHA256SUMS（加 --sign 还会产出 ed25519 分离签名）
python scripts/release.py checksum --dir dist/release --sign

# 本地验签 + 校验
python scripts/release.py verify --dir dist/release
```

`SHA256SUMS` 用标准 `sha256sum -c` 格式，供下载者独立验证；
签名私钥若存在（`release.key`）则自动做 Ed25519 分离签名，公钥 `release.pub` 可随包分发。

### Docker

```bash
docker build -t rustunnel .                # 多阶段构建，产物是 musl 静态二进制
docker compose up -d                       # 或直接用 compose（含配置挂载与端口映射）
```

### crates.io

三个 crate 的 `description` / `license` / `repository` / `keywords` / `categories` 元数据已就位，
`LICENSE`（Apache License 2.0）与 `NOTICE`（版权声明 + 第三方组件许可）随源码树分发。
发布前把 `Cargo.toml` 里的 `repository` / `homepage`
从占位地址改成你自己的仓库地址即可：

```bash
cargo publish -p rustunnel-common
cargo publish -p rustunnel-server
cargo publish -p rustunnel-client
```

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

- `xtcp` 已实现 UDP 打洞 + QUIC / KCP 直连，并对**对称 NAT 做端口预测**，但仍有一类
  严格对称 NAT（每次分配完全随机、无步长可推）打不通，此时照旧回退中继；
  `p2p_port` 需要放行 UDP，否则只能走中继；
- **QUIC 传输仅限 rustunnel 两端之间** —— 官方 frp 的 `transport.protocol` 语义不同，互通时用 `tcp`；
- 面板的动态管理（增删代理 / 踢人）需要**对端也是 rustunnel frpc**：官方 frpc 不支持这套
  私有消息，面板会把它标为不可管理，其余功能不受影响；
- v1 线协议已完整实现并且是**默认**（与官方一致）；官方 v2 专有的 **UDP 二进制报文编码**
  （`V2BinaryUDPPacketReadWriter`）在 rustunnel 两端之间 v1/v2 都启用，与官方互通时走 JSON —— 功能等价，仅包体略大。

## License

Copyright 2026 rustunnel contributors

遵循 **Apache License 2.0**，全文见 [`LICENSE`](LICENSE)，版权与第三方组件许可见 [`NOTICE`](NOTICE)。

选择 Apache-2.0 而不是 MIT 的原因：它带**显式专利授权**（第 3 节）。
内网穿透是网络基础设施里被大量商用的东西，使用者需要这份明确性 ——
MIT 对专利只字未提，企业法务通常要额外确认一轮。

与官方 frp（Apache-2.0）也更省事：两边许可一致，`frp v1 / v2` 协议的互操作说明不需要再夹一层许可解释。
