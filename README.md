<div align="center">
  <img src="assets/icons/nfrp-icon-256.png" alt="NFrp Logo" width="120">
  <h1>NFrp</h1>
  <p><b>Rust 实现的内网穿透工具，兼容官方 frp 协议</b></p>
</div>

<p align="center">
  <img src="https://img.shields.io/badge/version-0.7.0-blue" alt="Version">
  <img src="https://img.shields.io/badge/protocol-frp%20v1%20%2F%20v2-orange" alt="Protocol">
  <img src="https://img.shields.io/badge/platform-Windows%20%7C%20Linux-lightgrey" alt="Platform">
  <img src="https://img.shields.io/badge/license-Apache--2.0-green" alt="License">
</p>

<p align="center">
  <a href="https://crates.io/crates/nfrp-common"><img src="https://img.shields.io/crates/v/nfrp-common.svg?label=nfrp-common" alt="nfrp-common"></a>
  <a href="https://crates.io/crates/nfrp-server"><img src="https://img.shields.io/crates/v/nfrp-server.svg?label=nfrp-server" alt="nfrp-server"></a>
  <a href="https://crates.io/crates/nfrp-client"><img src="https://img.shields.io/crates/v/nfrp-client.svg?label=nfrp-client" alt="nfrp-client"></a>
  <a href="https://docs.rs/nfrp-common"><img src="https://docs.rs/nfrp-common/badge.svg" alt="docs.rs"></a>
</p>

---

NFrp 是 [fatedier/frp](https://github.com/fatedier/frp) 的 Rust 重实现，**完整兼容官方 wire protocol v1 与 v2**，可与官方 `frps` / `frpc`（v0.71.0 实测）直接互通，第三方 frp 平台下发的配置也能直接用。

默认走 **v1**，与官方 frp 的默认值一致 —— 所以官方客户端 / 服务端**不需要改任何配置**就能连上。

资源占用很小：服务端常驻内存约 3.5 MB（同负载下 Go 版 frps 为 28.8~31.8 MB），单文件部署，无运行时依赖。

另有一层可选的扩展协议 **NLink v1**（QUIC 传输与连接迁移、断线续传、零信任身份、
细粒度限流、端口敲门等），**默认关闭**，开启后仍是双方可协商、可回退的，
对官方 frp 零影响。见下方[「NLink v1」](#nlink-v1可协商的扩展层默认关闭)。

> **完整文档**：<https://nu0vo1212.github.io/Rust-Frp/>
> 涵盖安装、全部配置项、八种代理类型、线协议（v1 / v2）详解、ACL / RBAC、审计日志、HTTP API 与安全修复史。
> 源文件在 [`docs/`](docs/)，本地预览：`python -m http.server -d docs 8899`
>
> **质量与发版**：[QUALITY.md](QUALITY.md) —— 测试分布、CI 矩阵、依赖安全做到哪一步、
> 发版闸门与人工核对清单。

## 安装

### 方式一：crates.io（推荐 Rust 用户）

三个 crate 都已发布，也可以直接依赖协议库而**不跑穿透服务**：

```bash
# 装两个可执行文件
cargo install nfrp-server nfrp-client
```

```toml
# 或者：只把协议 / 配置 / 加密当库用
[dependencies]
nfrp-common = "0.6"
```

| crate | 用途 | 链接 |
|---|---|---|
| **nfrp-common** | 协议、配置、加密、ACL/RBAC、日志、传输层抽象 | [crates.io](https://crates.io/crates/nfrp-common) · [docs.rs](https://docs.rs/nfrp-common) |
| **nfrp-server** | 服务端可执行文件（等价官方 `frps`） | [crates.io](https://crates.io/crates/nfrp-server) |
| **nfrp-client** | 客户端可执行文件（等价官方 `frpc`） | [crates.io](https://crates.io/crates/nfrp-client) |

> **关于版本号**：crates.io 上的版本与本页 Release 的版本**相互独立**。
> 例如 Release 为 `v0.6.1` 时，crates.io 上可能是 `0.6.2` ——
> 因为 crates.io 不允许重发同一版本号（修个 README 也得升版本）。
> **看代码功能以 Release 为准**；`cargo install` 拿到的始终是该 crate 的最新发布版。
>
> ★ **`cargo install` 拿到的二进制与 Release 里的同版本二进制不是同一次构建。**
> 以 `0.6.6` 为例：crates.io 上的 0.6.6 是在 Release 之前打的，之后又改了几处
> 才发出 `v0.6.6` 的包（版本号已占用，不能再发一次）。因此
> **`cargo install nfrp-server@0.6.6` 与 Release 包里的 `frps` 行为可能不同**。
> 要可复现、可对照 issue 的产物，请用[方式二：下载二进制](#方式二下载二进制)。
> 后续版本起，发版顺序固定为「先发 crates.io，再用**同一次构建**打包 Release」。

`nfrp-common` 的模块导览：

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

### 方式二：下载二进制

从 [Releases](https://github.com/Nu0vo1212/Rust-Frp/releases) 取对应平台的包
（Windows / Linux amd64 / Linux arm64 / Android，另附源码包）。

## 功能特性

### 代理类型

八种，与官方 frp 的类型清单完全一致：

| 类型 | 说明 |
|---|---|
| `tcp` | 最常用的端口转发 |
| `udp` | UDP 转发，每个代理只占一条工作连接，靠访客地址区分会话 |
| `http` | 按域名路由，支持 `locations` 前缀、Basic Auth、Host 改写、自定义请求/响应头 |
| `https` | 只嗅探 ClientHello 的 SNI 做路由，不终止 TLS，证书仍由内网服务提供 |
| `tcpmux` | HTTP CONNECT 复用，多条代理共用一个服务端端口，支持 `routeByHTTPUser` 二级路由 |
| `stcp` | 私密隧道，服务端不开公网端口，`secret_key` 校验 + `allow_users` 白名单 |
| `sudp` | 与 stcp 同一套鉴权，数据面为 UDP，同样不占公网端口 |
| `xtcp` | UDP 打洞 + QUIC / KCP 直连，数据不经服务端；打不通自动回退中继。v0.5.8 起 P2P 握手加两层校验（provider 回**派生应答口令** + 服务端把牵线 HELLO 绑定到控制连接来源 IP） |

### 传输层

- frp v1 / v2 双线协议，默认 v1，可用 `transport.wireProtocol = "v2"` 显式启用
- QUIC 传输（`transport_protocol = "quic"`）：1-RTT 握手、流级多路复用
- KCP 弱网通道：既可作为 xtcp 直连通道，也可作为独立传输协议（`kcp_bind_port`）
- yamux 多路复用（`transport.tcpMux`），控制连接与工作连接复用一条 TCP
- TLS 加密（`transport.tls`），含官方自定义首字节伪装；服务端默认自动生成自签名证书，也支持 `certFile` / `keyFile` 自定义证书，以及 `trustedCaFile` 开启客户端证书（mTLS）；客户端可配 `certFile` / `keyFile` 出示身份
- WebSocket / WSS（`websocket = true`），同一端口按路径自动识别，可穿透只放行 HTTP 的防火墙
- Proxy Protocol v1 / v2，把真实客户端 IP 透传给 Nginx / HAProxy / 后端应用

### 客户端插件

官方 9 种全部实现：`http_proxy` / `socks5` / `static_file` / `unix_domain_socket` / `http2http` / `http2https` / `https2http` / `https2https` / `tls2raw`。frpc 本身即可作为正向代理、静态站点或 TLS 终结器。

### 安全与访问控制

- OIDC 认证（`auth.method = "oidc"`），对接 Keycloak / Google / Azure AD 等任意标准 IdP；客户端走 Client Credentials Grant，服务端验签 JWKS（RS256 / PS256 / ES256）
- RBAC 角色权限表（`[[roles]]`），按序匹配 + `deny_unknown` / `default_role` 兜底
- IP 白 / 黑名单（`[acl]`），CIDR 语法，`deny` 优先；**v0.5.9 起铺满全部数据面入口**（TCP / UDP 代理、vhost、VNet、xtcp 牵线、管理面板）
- 审计日志（`[audit]`），JSONL 追加写 + 内存环形缓冲；关闭时零开销。**v0.5.9 起支持 `maxFileMB` 轮转**（默认 64，单份 `.1` 备份）
- 凭据比较统一走常量时间；HTTP 转发做逐跳头剥离、`Host` 规范化、CL+TE 走私拒绝
- 面板与客户端本地界面**绑非回环地址却没有凭据时拒绝启动**（逃生开关 `allow_insecure_dashboard` / `allowInsecureRemote`）

所有安全修复已整合为一份文档（按日期编排、各轮原文完整收录）：

**[SECURITY-ALL-FIXES.md](SECURITY-ALL-FIXES.md)** —— 第一 ~ 第十六轮，2026-10-04 至 2026-10-25

各轮原始报告仍保留（SECURITY-FIXES-ROUND4..16.md），作为证据链引用；
总文档里每一轮都标了日期与结论，并保留「实测复现 / 修复方式 / 回归测试」。
。

### 运维与调度

- group 负载均衡：同 `group` 的多个代理共享一个 `remote_port`，按最小连接数分摊
- 健康检查：`tcp` / `http` 探测，连续失败自动摘除后端，恢复后自动回归
- 带宽限流：每个代理可配 `bandwidth_limit`（如 `1MB`），令牌桶精确限速
- 资源上限：客户端数 / 代理数 / 转发连接数 / 待处理队列，五个维度全部可限并计入指标
- 端口白名单：`allowPorts` + `maxPortsPerClient`
- 日志落盘与轮转：`log.to` + `log.maxDays`，按天切分与清理
- 客户端 Store 持久化：动态添加的代理落盘，重启自动恢复
- 配置热重载：改 `log_level` / 面板密码无需重启

### 可观测性与管理

- 内置 Web 面板 + Prometheus `/metrics`（需配 `enablePrometheus = true`，默认关闭）+ 免鉴权健康检查端点，支持 Basic Auth
- 面板可直接增删代理、踢掉客户端，无需改配置重启
- Dashboard API v2（`/api/v2/*`）：统一错误信封 + 分页 + 稳定排序；v1 接口行为不变
- 客户端本地 Web UI / API（`[webServer] port = 7400`）：查看隧道 / 连接 / 流量，并可增删代理
- CPU profile：`pprofEnable = true` 后，服务端面板与客户端本地 Web 都提供
  `GET /debug/pprof/profile?seconds=N`（默认 10 秒、上限 60 秒）；Unix 返回
  protobuf，Windows 明确 501（Rust `pprof` 依赖 perf signal / `ucontext_t`）
- SSH 隧道网关（`sshTunnelGateway`）：服务端内嵌 SSH 服务器，OpenSSH 的
  `ssh -R` 可直接注册 `tcp` / `http` / `https` / `tcpmux` / `stcp` 代理，
  数据面复用普通工作连接；`authorizedKeysFile` 非空时只接受文件内公钥，
  公钥注释就是 frp 用户名
- HTTP 插件（`httpPlugins`）：服务端在 `Login` / `NewProxy` / `CloseProxy` /
  `Ping` / `NewWorkConn` / `NewUserConn` 时回调外部 HTTP 服务，支持拒绝、
  改写登录内容和代理名/metas；每次请求 10 秒超时

### NLink v1：可协商的扩展层（默认关闭）

标准 frp 协议把传输、会话、鉴权、调度都固定死了。有些需求不是"实现得不好"，
而是**协议里没有承载位置**——比如连接迁移需要传输层有独立的连接标识，而 frp 是
在 TCP/TLS 之上套 yamux，这个位置不存在。

NLink 就是在标准 frp 线协议之上叠的一层扩展，两条铁律贯穿始终：

1. **标准帧一个字节都不动** —— 扩展走独立命名空间，官方 frp 永远看不到这些字节；
2. **没协商成功就当它不存在** —— 任何一端不支持，行为与 0.6.x 完全一致。

**零额外往返。** 客户端把能力声明搭车在第一条消息之前（`NFRPLNK1` preamble），
服务端把确认结果搭车在本就要发的 `LoginResp._nlink` 上带回。识别只依赖首字节
——`NFRPLNK1`、`FRP\0\x02\r\n`、`{` 三者互不重叠，不会误判。

| 能力 | 说明 |
|---|---|
| QUIC 传输与连接迁移 | 独立 ALPN `nfrp-nlink`，与标准 QUIC 分桶互不串味 |
| 断线续传 | 进程级 `ConnectionId` 不变，服务端保留代理名单 `resume_ttl` 秒 |
| 零信任身份 | 每条工作连接带 `v1.<exp>.<hmac>` 令牌，绑定 `run_id + user + 过期时间` |
| 细粒度限流 | 按「用户 × 代理」的令牌桶，支持突发 |
| 端口敲门 | 端口默认不可见，敲对序列后按 IP 临时放行 |
| 批量工作连接 | 一条 `BatchReq` 换 N 条连接，省掉逐条往返 |
| 端到端 trace | 控制连接与数据面共享同一个 trace id |

**默认关闭**，两端都要显式开：

```toml
# frps.toml
[nlink]
enable = true
quic_listen = "0.0.0.0:7000"   # 留空 = 不开 QUIC
resume_ttl = 30

# frpc.toml
[nlink]
enable = true
resume = true
quic = true
```

**与官方 frp 共存**：官方 frps 不认 preamble，会把它当 v1 消息头报错。客户端捕获
这种失败后**自动回退标准模式并只重试一次**，日志留一行 warn，隧道照常工作。

| 组合 | 行为 |
|---|---|
| NFrp × NFRp | 按协商结果启用 |
| NFrp × 官方 frp | 回退标准模式，功能降级但**不影响连通** |
| 官方 × 官方 | 完全不受影响 |

编译期用 `--no-default-features` 可把扩展字段整个摘掉，此时报文与 0.6.x 逐字节一致。

> 握手时序图、TLV 帧格式、各能力的承载方式、兼容性矩阵与设计约束，见
> [文档站 NLink 页](https://nu0vo1212.github.io/Rust-Frp/#/nlink)。


### 工程质量

956 个自动化测试，含真实 QUIC 栈握手、端到端集成、官方抓包密文解密回归；
`cargo audit` 0 命中；发布产物附 `SHA256SUMS` + Ed25519 签名。

测试分布、CI 矩阵、依赖安全做到哪一步、发版闸门与人工核对清单，
统一放在 **[QUALITY.md](QUALITY.md)**。

## 快速开始

### 构建

```bash
cargo build --release
# 产物：<target_directory>/release/nfrp-server（frps）、<target_directory>/release/nfrp-client（frpc）
# target_directory 以 `cargo metadata` 为准：设了 CARGO_TARGET_DIR 或本机
# `.cargo/config.toml` 时，产物就不在 ./target 下
```

需要 Rust 1.75+。Windows 用 MSVC toolchain。

也可以直接下载发布包，包内二进制名为 `frps` / `frpc`（与官方一致）。

### 服务端（公网机器）

```toml
# frps.toml
bind_addr = "0.0.0.0"
bind_port = 7000
token = "换成一个足够随机的口令"

# 可选：xtcp 真 P2P 的牵线端口（需放行 UDP）
p2p_port = 7002

# 可选：内置面板（另可配 enablePrometheus = true 打开 /metrics）
dashboard_port = 7500
dashboard_user = "admin"
dashboard_pwd = "换成一个强口令"
```

```bash
./nfrp-server -c frps.toml
# 生成带注释的完整示例配置：
./nfrp-server --gen-config frps.toml
```

### 客户端（内网机器）

```toml
# frpc.toml
server_addr = "your.server.com"
server_port = 7000
token = "与服务端一致的口令"

[[proxies]]
name = "ssh"
type = "tcp"
local_addr = "127.0.0.1:22"
remote_port = 6000
```

```bash
./nfrp-client -c frpc.toml
```

之后 `your.server.com:6000` 即映射到内网机器的 22 端口。

### 与官方 frp 互通

NFrp 可运行在官方 frp 的任一侧，双向实测通过：

| 服务端 | 客户端 | 状态 |
|---|---|---|
| nfrp frps | 官方 frpc（tcpMux on/off、TLS on、各类代理） | 通过 |
| 官方 frps | nfrp frpc（tcp_mux on/off、TLS on、各类代理） | 通过 |
| nfrp frps | 官方 frpc（stcp 提供者 / 访客） | 通过 |

**兼容标识不可更改**：`frpc -v` 仍输出裸 `0.71.0`，线协议魔术字与版本串、包内 `frps` / `frpc` 命名全部保持。改动这三样会立刻破坏与官方 frp 及第三方平台的互通。

## 配置

配置字段与官方 frp 对齐，**原版 `frps.toml` / `frpc.toml` 可以直接使用**（支持 camelCase、`localIP` + `localPort` 两段式写法、`[metadatas]` 等）。

两处**有意偏离**官方，都需要注意：

- `local_addr` 是合并式 `ip:port`（`127.0.0.1:8080`），不像官方分成 `localIP` + `localPort`。官方两段式也认，但两种写法**不要混用**。
- 日志轮转按 **UTC** 零点切分（官方按本地时间），因为日志时间戳本身就是 UTC。

完整的带注释示例见仓库内 [`assets/frps.toml`](assets/frps.toml) 与 [`assets/frpc.toml`](assets/frpc.toml)，也可以用 `--gen-config` 生成。

## 升级注意

0.5.2 起有几处**行为变更**，升级前请确认：

| 变更 | 影响 | 处理 |
|---|---|---|
| 面板绑非回环地址且无 `dashboard_user` | 拒绝启动 | 配凭据 / 改 `bind_addr = "127.0.0.1"` / 显式写 `allow_insecure_dashboard = true` |
| 客户端 `[webServer]` 绑非回环且无凭据 | 拒绝启动 | 逃生开关 `allowInsecureRemote = true` |
| 本地界面写接口 | 需要 `X-Nfrp-Client: 1` 头 | 调写接口的脚本要加上 |
| 空 token 且**显式**绑对外地址 | 拒绝启动 | 配 token / 绑回环 / 显式写 `allow_insecure_no_auth = true` |
| `[acl]` 段拼错的键名 | 现在会报错（原先静默失效） | 检查拼写 |

**0.5.5 起追加三处**（都是安全修复的必然结果）：

| 变更 | 影响 | 处理 |
|---|---|---|
| 远程下发**不再允许携带插件**（`plugin` / `pluginUser` / `pluginPasswd` / `pluginHostHeaderRewrite` / `pluginStripPrefix`） | 面板下发的代理若带插件会被拒 | 插件只能写在**本机配置文件**里（它决定客户端"变成什么"，不该由服务端远程指定）。要连内网服务请用普通 tcp/http 代理 |
| 远程下发**不能删/覆盖配置文件里定义的代理** | 面板对这些代理的增删会返回明确错误 | 改本机配置文件；面板只管理它自己加的（以及 store 恢复的）动态代理 |
| 工作连接需要凭证 | **对官方 frpc 无影响**（官方默认不带凭证，服务端退回"源 IP 一致"校验） | 无需处理。NFrp ≥ 0.5.5 客户端会自动声明并携带 |

**0.5.6 起追加三处**（都有意的行为变更，见 `第 5 轮`）：

| 变更 | 影响 | 处理 |
|---|---|---|
| **INI 的段名与键名统一小写** | 代理名会小写化（`[MCCC]` → `mccc`） | **这是修正为与官方一致** —— 官方 `go-ini` 同样小写化，原先两边会产生不同的代理名。如果你的脚本按大写名引用代理，改成小写 |
| **跨租户不得靠 `routeByHTTPUser` 共用域名 + 路径** | 跨租户的多作用域注册会被拒（返回"路径已被占用"） | 服务端分辨不出"合法的多作用域"与"寄生劫持"，而后者能直接收割 Basic 凭据，故收紧。**同租户**的多作用域拓扑（官方 tcpmux 文档的用法）不受影响 |
| **UDP 回写限"真的发过包的访客 IP"** | 客户端无法让服务端向未通信过的 IP 发 UDP | 防 frps 被当作 UDP 反射跳板。诚实客户端零影响；TFTP 那类"换端口回包"的协议**不受影响**（只限 IP、不限端口） |

**0.5.7 起追加三处**（见 `第 6 轮`）：

| 变更 | 影响 | 处理 |
|---|---|---|
| **凭证新鲜性校验铺满全部 6 个入口** | 时间戳超出 `maxClockSkewSecs`（默认 ±300 秒）的登录 / 工作连接 / vnet 注册 / visitor 签名 / p2p 打洞签名**一律拒绝** | **对官方 frpc 无影响**（官方本来就用当前时间，已实测互通）。只有**两端时钟偏差超过 5 分钟**时才会失败 —— 症状是"能连上控制端口但登录被拒"，错误里会写明偏差多少秒。校准时钟，或把 `maxClockSkewSecs` 调大（`0` = 关闭校验） |
| **跨租户不能用同组名共享公网端口** | 不同 `user` 的客户端即使组名与 `groupKey` 都相同也**不能**共享端口 | 这是堵一个实测打出来的劫持（攻击者能分走一半用户流量）。**同一租户**的多个 frpc（重连、多开、一份配置多条 `[[proxies]]`）照常成组，官方"一个运维跑多个冗余后端"的用法**不受影响** |
| **visitor 的 `run_id` 不能留空** | 用 `run_id = ""` 的 visitor 连接会被拒 | 官方 frpc 的 visitor **一定**带自己的 `run_id`，所以零影响。原先空值会绕过会话校验（实测匿名连接能把数据送进别人的隧道） |

**0.5.8 起追加四处**（第七 / 八轮；详单见 `第 7 轮` 与 `第 8 轮`）：

| 变更 | 影响 | 处理 |
|---|---|---|
| **xtcp 牵线加两层校验**：服务端把牵线 HELLO 的来源 IP 绑定到该 session 的控制连接 IP；provider 回**按 `secret_key`+`sid` 派生的应答口令**（替代固定 `"RTNL-OK"`），visitor 定长比较 | 修复"在途读到明文 HELLO（sid 泄露）⇒ 冒充 provider 劫持 P2P 会话"（第八轮 B-1，实测可拿到用户明文数据）。**混合版本时 P2P 直连会失败并自动回退中继**（新↔旧任意组合）：功能不受影响，只是少一层直连加速 | 两端都升到 0.5.8+ 才建立 P2P 直连；单边升级**不会**让连接失败，打洞窗口（8 秒）过后自动走中继。注意同一 NAT 后仍可能被同 IP 的观察者登记（第二层口令会拦住数据） |
| **面板解析卫生 + 全名删除**：`Authorization` 只从请求**头区**解析（请求体里同形状的行不再"误投"）；面板列表展示的**线上全名**（`user.proxy`）可直接用于"移除代理" | ① 修复前，body 里带 `Authorization: Basic ...` 的请求能通过面板鉴权（与上游反代/WAF 口径不一致，属解析卫生）；② 修复前按列表全名删除会得到 502/400 且**两端状态分裂**（服务端已摘、客户端报"本地没有"） | 正常用法无感知；②修复后控制台/脚本从列表复制的名字（全名或短名）都能删 |
| **`https2http` / `https2https` 上游收尾**：访问方断开时立刻放弃等待上游并释放上游连接；上游 connect / TLS 握手加 10 秒超时 | 修复前上游 accept 后悬挂时，每轮访问（连接→发请求→撤离）会留下一条永不释放的上游连接（可被公开访问方反复放大）；"等响应头"阶段仍然**没有**人为超时，长轮询 / SSE 不受影响 | 行为对齐官方 frpc（Go `http.Server` 在客户端断开时取消请求上下文）。上游就是慢（正常出数据）的场景不受影响，已实测 |
| **`[acl]` 开始真正作用于数据面**（第七轮 F7-1）：公网 **TCP 代理端口**与 **HTTP/HTTPS vhost** 的 accept 现在过 IP 白/黑名单（修复前只挡控制连接） | 被你 `deny` 挡掉的来源此前"居然一直能访问"，本版起被拒（静默关连接 + 审计事件）；用白名单模式（`allow`）的部署尤其要注意：此前它对数据面形同虚设，本版起**按白名单收紧** | **UDP 代理端口与 xtcp 牵线（p2p）UDP 仍不在 `[acl]` 范围内**（面板另有自身鉴权）—— 如实记录在 `第 7 轮`。需要挡 UDP 来源请用防火墙（**v0.5.9 起 UDP 代理端口 / 牵线 / 面板也已纳入 ACL**，见下） |

**0.5.9 起追加六处**（第九轮；详单见 `第 9 轮`）：

| 变更 | 影响 | 处理 |
|---|---|---|
| **`[acl]` 覆盖面补齐**（E9-0 / E9-1 / E9-2）：**UDP 代理端口**、**xtcp 牵线 UDP**、**管理面板**从此也过 IP 白 / 黑名单 | 修复前 UDP 代理端口**完全不遵守** `[acl]`（无需任何凭据即可把 UDP 包送进内网服务）；牵线与面板同样漏过（面板另有独立 Basic Auth，属纵深防御缺失） | 用白名单（`allow`）模式的部署请确认放行面；只想挡 UDP 来源也可以继续用防火墙。升级后来源突然被拦属于配置本意（此前是静默失效） |
| **未认证连接的时间上界 + 全局闸门**（C9-3 / C9-4）：TLS 握手 30s 超时、yamux 空转会话看门狗（30s）、未认证握手全局并发闸（2048，排队 5s）；`0x00` / `0x16` / `0x17` 单字节后静默的连接不再永久驻留 | 修复前"发一个字节然后静默"即可无限挂住连接（实测 500 条 `0x00` 占 500 fd + 6.4 MB）；未认证开流可放大 **≈800×**（12 字节换 9.5 KB） | 常规流量零感知。**极端饱和**（同时 >2048 个未认证握手）时新连接排队 5 秒后被拒 —— 已有会话与合法工作流不受影响，含合法客户端重新登录 |
| **审计日志轮转 `maxFileMB`**（A9-3，默认 64；`0` = 不轮转） | 修复前审计文件可被公开流量灌到任意大（实测 ~1000 条/秒、37 MB/h 起、无上界，还会挤掉环形缓冲里的真实事件） | 轮转保留单份 `<path>.1` 备份，总占用 ≈ 2× 阈值；需要更长历史请自行归档 `.1`。要恢复旧的无限增长行为设 `maxFileMB = 0` |
| **stcp / xtcp visitor 默认配置恢复可用**（A9-5，修 0.5.7 / 0.5.8 的功能回归） | 双方都未配 `user` 时（官方默认语义 `"" == ""`），0.5.7 / 0.5.8 会"能登录、能配对、但数据永远不通" | 配了 `allow_users` 的部署行为不变；若你此前为绕开问题给双方硬配了 `user`，本版起可以去掉 |
| **KCP 会话表封顶 1024**（C9-1，仅启用 `kcp_bind_port` 时）：同时最多 1024 条 KCP 会话，超出丢弃新会话（不回包，**已有会话不受影响**） | 修复前 25 字节的 UDP 包可换 ≈15 KB 内存（**放大 312×**，实测 757 KB 上行把内存推高到 238 MB） | 未启用 KCP 的部署不受影响；单实例 KCP 会话数持续 >1024 的部署请拆分实例 |
| **客户端启动即点名插件配置错误**（D9-7）：原先 Windows 上 `unix_domain_socket` 配置错误仅 DEBUG 一行，默认级别完全静默 | 影响面很小（配置错误本来就不工作），只是从"看不见"变成"一眼看见" | 无 —— 看到 WARN 按提示修配置即可 |

其余需注意：

- **OIDC 部署必须配 TLS**。OIDC 的 `privilege_key` 是原样的 access token，会明文出现在登录报文里；不加密链路上任何被动抓包的人都能拿走它。
- **客户端 `transport.tls` 只加密、不校验对端证书**（与官方 frp 行为一致）。它防被动偷看，不防中间人；跨公网直连且需要防 MITM 时请在**外层**再套一层 TLS。
- **v1 的登录凭据强度完全取决于 token**。v0.5.7 起服务端**校验时间戳新鲜性**（默认 ±300 秒窗口，见上表），把重放面从"无限期"压到"5 分钟"；但窗口内仍可重放，且**离线枚举 token 的成本与时间窗口无关** ⇒ 跨公网部署请用足够随机的 token，并优先 v2 / OIDC。
- **`user` 是客户端自报字段，服务端无法验证**。未配 `[[roles]]` 时它只是标签；**配了 `[[roles]]` 之后也一样** —— 任何持有共享 token 的人都能把自己报成别人的 `user` 从而拿到那个人的角色。⇒ `[[roles]]` **不是租户隔离**，只是一层防误操作（v0.5.7 起服务端会就此打启动告警）。需要真正的隔离请用 OIDC（身份来自验签过的 `sub`），或给每租户发独立 token 并分实例部署。
- **xtcp 的"数据不经服务端"不包含"防服务端"**：服务端持有 `secret_key` 且自行生成 `sid`，理论上能算出 P2P 口令。它防的是**路径上的第三方**，不是服务端本身。
- 对手不想暴露内部细节时，可设 `detailed_errors_to_client = false`（默认与官方一致为 `true`）：它会把发给客户端的错误换成统一短句，顺带收掉 stcp/xtcp 隧道名的枚举面。
- **UDP 代理的回写目标受限**（v0.5.6 起）：服务端只向"最近真的给该端口发过包的访客 IP"回写 UDP 报文。这是防 frps 被当成 UDP 反射跳板 —— 正常客户端本来就只回写给刚收到包的地址，**不会感知**。
- 示例配置里默认**不包含**任何代理，需要什么自己打开对应的注释段。示例不再默认暴露 SSH。

## 质量保障

```bash
cargo fmt --all -- --check                              # 格式
cargo clippy --workspace --all-targets -- -D warnings   # 静态检查，0 告警
cargo test --workspace                                  # 956 通过 / 0 失败 / 13 ignored
```

那 13 条 `#[ignore]` 全是**需要真机硬件或管理员权限**的设备面测试
（Windows Wintun 网卡、Linux TUN 设备），不是被跳过的问题测试。

CI 在每次 push / PR 上跑同样的三道门，外加三系统全量测试、两个 musl 目标交叉构建
与端到端冒烟。

**完整细节见 [QUALITY.md](QUALITY.md)**：测试分布明细、CI 矩阵、依赖安全做到哪一步
（`cargo audit` / `deny` / `vet` 各自的真实含义）、发版闸门、人工核对清单。

## 发布与部署

### Docker

```bash
docker build -t nfrp .
docker run --rm -p 17000:17000 -p 17002:17002/udp \
  -v $PWD/frps.toml:/etc/nfrp/frps.toml nfrp
```

镜像以非 root 用户运行，多阶段构建（musl 静态），最终镜像只含两个二进制与示例配置。

### 自己打包

打包、签名、跨平台交叉编译（含 Android NDK 环境变量）与发版闸门的完整命令，
见 **[QUALITY.md](QUALITY.md#六发布产物校验)**。

一句话概括：`release.py pack` 打完包会自动解包，把包内 `frps`/`frpc` 与源产物
逐个 sha256 比对，不一致直接非零退出。这一步不是可选的——历史上真的出现过
"包名和版本号都对，但里面的二进制是上一版"。

`Dockerfile` **有意不加 `HEALTHCHECK`**：唯一合适的探针 `- /api/healthz` 挂在面板端口上，而示例配置里 `dashboard_port` 默认是注释掉的，写死探针会让容器一直显示 `unhealthy`。理由已写在文件里。

## 当前限制

- **VirtualNet 的 TUN 设备**：Linux 用 `/dev/net/tun`（需 root 或 `CAP_NET_ADMIN`）；
  **Windows 用 Wintun**（v0.6.6 起支持，需管理员权限 + 自行下载 `wintun.dll`；
  仓库含 `#[ignore]` 的真机网卡和双向 ping 数据面测试，需管理员权限手动执行；
  非管理员会话已验证缺 DLL / 拒绝访问的错误路径，但本轮没有重跑真机数据面）；
  macOS 未实现，配置了会明确报错而不是静默失败
- 与官方 0.71 的配置字段对齐情况：

  **已实现**：TLS 证书组（`transport.tls.certFile` / `keyFile` / `trustedCaFile`，
  含服务端 mTLS 与客户端证书）、`auth.tokenSource`（文件 / 外部命令，客户端与服务端）、
  `includes`（客户端配置包含）、`quicBindPort`、`enablePrometheus`、
  `udpPacketSize`（两端；默认 65507 而非官方的 1500 —— 见下）、
  客户端 `useEncryption` / `useCompression`（按官方 golib 的 AES-128-CFB + snappy
  流实现，单测/内存双端通过；未做官方 frpc 组合 e2e）、
  `proxyURL`（HTTP CONNECT / SOCKS5 出站代理）、
  `dnsServer`（A/AAAA 查询走自定义 UDP DNS）、`natHoleStunServer`（RFC 5389
  探测公网映射）、`pprofEnable`（Unix CPU profile，Windows 明确 501）、
  `assetsDir`（面板静态资源目录）、`natholeAnalysisDataReserveHours`
  （NatHole 分析记录保留期，0 = 不保留）、`httpPlugins`（服务端登录/代理/
  工作连接回调）、`sshTunnelGateway`（OpenSSH `ssh -R` 隧道网关）。

  **官方 NatHole / xtcp**：已实现官方控制器协议，并用官方 `frpc 0.71.0`
  做过真实 e2e（provider/visitor 经 `NatHoleSid` 工作连接、`NatHoleClient`、
  `NatHoleResp` 完成 UDP 打洞，访问成功）。当前覆盖 EasyNAT / 公网直连的
  mode 0 场景；HardNAT、端口预测、多 STUN 地址与 TTL 探测等完整 NAT 分类
  尚未实现，极端 NAT 组合下可能打洞失败后由客户端回退中继。

  **仍未做**：真实外部 IdP（Keycloak / Azure AD 等）上的 OIDC 互操作 e2e
  （目前是对本地 mock IdP 跑 9 条）。SSH 网关的 tcpmux / stcp 只验到注册与清理，
  **数据面没有 e2e**。

  > ~~`webServer.tls.certFile` / `webServer.tls.keyFile`（面板 HTTPS）未实现~~
  > —— **这条更正**：面板 HTTPS 自 v0.6.x 起已实现并有真实 HTTPS + HSTS 回归
  > （`server/src/dashboard.rs::web_server_tls_真实_https_和_hsts`）。原文保留
  > 是为了不改写历史记录，当前状态以本行为准。

  > `udpPacketSize` 的默认值**故意与官方不同**：官方默认 1500，NFRP 一直用
  > 65507（UDP 协议上限）。改成 1500 会**静默截断**现有用户的大 UDP 报文
  > （收得到包、内容少一截），比报错难查得多。想对齐官方行为的部署，
  > 显式配 `udpPacketSize = 1500` 即可。


## License

本项目基于 [Apache License 2.0](LICENSE) 发布。

```
Copyright 2026 nfrp contributors
```

---

<p align="center">
  Made by <a href="AUTHOR.md">Nu0vo1212</a> ·
  <a href="https://nu0vo.xyz">nu0vo.xyz</a>
</p>
