<div align="center">
  <h1>NFrp</h1>
  <p><b>Rust 实现的内网穿透工具，兼容官方 frp 协议</b></p>
</div>

<p align="center">
  <img src="https://img.shields.io/badge/version-0.5.4-blue" alt="Version">
  <img src="https://img.shields.io/badge/protocol-frp%20v1%20%2F%20v2-orange" alt="Protocol">
  <img src="https://img.shields.io/badge/platform-Windows%20%7C%20Linux-lightgrey" alt="Platform">
  <img src="https://img.shields.io/badge/license-Apache--2.0-green" alt="License">
</p>

---

NFrp 是 [fatedier/frp](https://github.com/fatedier/frp) 的 Rust 重实现，**完整兼容官方 wire protocol v1 与 v2**，可与官方 `frps` / `frpc`（v0.71.0 实测）直接互通，第三方 frp 平台下发的配置也能直接用。

默认走 **v1**，与官方 frp 的默认值一致 —— 所以官方客户端 / 服务端**不需要改任何配置**就能连上。

资源占用很小：服务端常驻内存约 3.5 MB（同负载下 Go 版 frps 为 28.8~31.8 MB），单文件部署，无运行时依赖。

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
| `xtcp` | UDP 打洞 + QUIC / KCP 直连，数据不经服务端；打不通自动回退中继 |

### 传输层

- frp v1 / v2 双线协议，默认 v1，可用 `transport.wireProtocol = "v2"` 显式启用
- QUIC 传输（`transport_protocol = "quic"`）：1-RTT 握手、流级多路复用
- KCP 弱网通道：既可作为 xtcp 直连通道，也可作为独立传输协议（`kcp_bind_port`）
- yamux 多路复用（`transport.tcpMux`），控制连接与工作连接复用一条 TCP
- TLS 加密（`transport.tls`），含官方自定义首字节伪装，服务端自动生成自签名证书
- WebSocket / WSS（`websocket = true`），同一端口按路径自动识别，可穿透只放行 HTTP 的防火墙
- Proxy Protocol v1 / v2，把真实客户端 IP 透传给 Nginx / HAProxy / 后端应用

### 客户端插件

官方 9 种全部实现：`http_proxy` / `socks5` / `static_file` / `unix_domain_socket` / `http2http` / `http2https` / `https2http` / `https2https` / `tls2raw`。frpc 本身即可作为正向代理、静态站点或 TLS 终结器。

### 安全与访问控制

- OIDC 认证（`auth.method = "oidc"`），对接 Keycloak / Google / Azure AD 等任意标准 IdP；客户端走 Client Credentials Grant，服务端验签 JWKS（RS256 / PS256 / ES256）
- RBAC 角色权限表（`[[roles]]`），按序匹配 + `deny_unknown` / `default_role` 兜底
- IP 白 / 黑名单（`[acl]`），CIDR 语法，`deny` 优先
- 审计日志（`[audit]`），JSONL 追加写 + 内存环形缓冲；关闭时零开销
- 凭据比较统一走常量时间；HTTP 转发做逐跳头剥离、`Host` 规范化、CL+TE 走私拒绝
- 面板与客户端本地界面**绑非回环地址却没有凭据时拒绝启动**（逃生开关 `allow_insecure_dashboard` / `allowInsecureRemote`）

完整修复清单见 [SECURITY-FIXES.md](SECURITY-FIXES.md)。

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

- 内置 Web 面板 + Prometheus `/metrics` + 免鉴权健康检查端点，支持 Basic Auth
- 面板可直接增删代理、踢掉客户端，无需改配置重启
- Dashboard API v2（`/api/v2/*`）：统一错误信封 + 分页 + 稳定排序；v1 接口行为不变
- 客户端本地 Web UI / API（`[webServer] port = 7400`）：查看隧道 / 连接 / 流量，并可增删代理

### 工程质量

- 612 个自动化测试，含真实 QUIC 栈握手、端到端集成测试、与官方 frpc/frps 真实抓包密文的解密回归
- CI 跑 `fmt` / `clippy` / 三系统全量测试 / 两个 musl 目标交叉构建 / 端到端冒烟
- 第三方 GitHub Action 全部 pin 到 commit SHA；cosign 签名失败即红灯
- 发布产物附 `SHA256SUMS` + Ed25519 分离签名

## 快速开始

### 构建

```bash
cargo build --release
# 产物：target/release/nfrp-server（frps）、target/release/nfrp-client（frpc）
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

# 可选：内置面板 + Prometheus 指标
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

其余需注意：

- **OIDC 部署必须配 TLS**。OIDC 的 `privilege_key` 是原样的 access token，会明文出现在登录报文里；不加密链路上任何被动抓包的人都能拿走它。
- **客户端 `transport.tls` 只加密、不校验对端证书**（与官方 frp 行为一致）。它防被动偷看，不防中间人；跨公网直连且需要防 MITM 时请在**外层**再套一层 TLS。
- 示例配置里默认**不包含**任何代理，需要什么自己打开对应的注释段。示例不再默认暴露 SSH。

## 质量保障

```bash
cargo fmt --all -- --check                # 格式
cargo clippy --workspace --all-targets    # 静态检查（当前 0 告警）
cargo test --workspace                    # 612 个测试
```

测试分布：

| 目标 | 数量 |
|---|---|
| `common` 单元测试 | 300 |
| `server` 单元测试（lib） | 181 |
| `server` 单元测试（bin） | 16 |
| `client` 单元测试 | 97 |
| `server` 端到端集成测试 | 18 |

CI（`.github/workflows/ci.yml`）在每次 push / PR 上跑 `fmt --check` + `clippy -D warnings`，然后在 Linux / Windows / macOS 上跑全量测试，再做两个 musl 目标的交叉构建与端到端冒烟。

## 发布与部署

### 打包

```bash
# 打三平台包（包内统一命名 frps / frpc，附示例配置与 README）
python scripts/release.py pack \
  --target windows-amd64:target/release \
  --target linux-amd64:/path/to/amd64 \
  --target linux-arm64:/path/to/arm64 \
  --out dist/release

# 生成 SHA256SUMS（--sign 还会产出 Ed25519 分离签名）
python scripts/release.py checksum --dir dist/release --sign

# 本地验签 + 校验
python scripts/release.py verify --dir dist/release
```

Linux 包在云端交叉编译（本机没有 Linux C 工具链，`ring` 需要编译 C）。arm64 走 `+crt-static` 全静态链接，无 glibc 依赖。

`release.py` 不依赖任何第三方 Python 包，也不依赖 Rust 工具链。签名缺失或失败会**非零退出**；确实要发未签名制品需显式加 `--allow-unsigned`。

### Docker

```bash
docker build -t nfrp .
docker run --rm -p 17000:17000 -p 17002:17002/udp \
  -v $PWD/frps.toml:/etc/nfrp/frps.toml nfrp
```

镜像以非 root 用户运行，多阶段构建（musl 静态），最终镜像只含两个二进制与示例配置。

`Dockerfile` **有意不加 `HEALTHCHECK`**：唯一合适的探针 `- /api/healthz` 挂在面板端口上，而示例配置里 `dashboard_port` 默认是注释掉的，写死探针会让容器一直显示 `unhealthy`。理由已写在文件里。

## 当前限制

- **VirtualNet 在 Windows 上未实现**（需要 TUN 设备），Linux 与 Android 上可用；配置了会明确报错而不是静默失败
- 官方 frp 的 xtcp NatHole UDP 地址交换协议未实现，所以**官方 frpc 的 xtcp visitor 打不了洞**；服务端会明确拒绝并让官方客户端立刻转走它自己的 `fallbackTo` 中继
- 与官方 0.71 相比仍有部分配置字段未实现，启动日志会逐条列出「配了但不会生效」的字段

## License

本项目基于 [Apache License 2.0](LICENSE) 发布。

```
Copyright 2026 nfrp contributors
```

---

<p align="center">
  Made by Nu0vo1212
</p>
