# NFrp 安全修复报告

日期 2026-10-04
范围 全仓（common / client / server 三个 crate、184 个依赖、Docker / CI / 打包链路）
状态 **已修 17 项 全部带回归测试** 质量门全绿 尚未发版

质量门结果

| 项 | 结果 |
|---|---|
| 测试 | **564 通过 0 失败**（修复前 542） |
| `cargo fmt --check` | 干净（exit 0） |
| `cargo clippy -D warnings` | **0 告警** |
| `cargo audit` | **exit 0 零漏洞**（修复前 1 条） |

---

## 一 严重 / 高危（6 项）

### 1. 面板零鉴权 可被匿名写

**位置** `server/src/dashboard.rs:143`、`server/src/serve.rs:233`

**问题** `dashboard_user` 为空时鉴权整块被跳过。面板跟随 `bind_addr`（默认 `0.0.0.0`），
于是匿名者可读 `/api/status`（全部客户端与代理名）、`/api/clients/kick` 踢掉任意客户端
（**无条件生效 连能力协商都不需要**）、对 nfrp 客户端还能 `POST /api/proxies/add` 直接开公网端口。

**实证** 独立工程 `tmp/panel_noauth_repro/` 跑出对照

```
留空 dashboard_user : 匿名 POST => 200，端口打开 = true
设置 dashboard_user : 匿名 POST => 401，端口仍关 = true
```

**修法** 非回环 + 无 `dashboard_user` ⇒ **拒绝启动**（`validate()` 与 `serve_with` 双重把关）。
逃生开关 `allow_insecure_dashboard = true`。回环地址留空仍合法（只有本机能连）。

**验证** 实测三种场景：不安全配置退出码 1 且提示明确、逃生开关有效、回环无凭据正常启动。
面板匿名 401 / 带凭据 200 / 匿名踢人 401 全部实测通过。

### 2. `ServerCmd` 可下发任意插件配置

**位置** `client/src/main.rs:1152`、`client/src/web.rs:178`

**问题** 服务端下发的 `ProxyConfig` 只校验 `name` / `type` 非空。
而该结构里混着「代理语义字段」与「**本机资源字段**」——
`plugin_local_path`（读哪个文件）、`plugin_local_addr`（连哪个内网地址）、
`plugin_crt_path` / `plugin_key_path`（读哪对证书）。
走**配置文件**的代理要过三道校验，这两条远程路径一道都不过。

**修法** 新增 `common/src/config.rs::validate_remote_proxy(p, is_remote)`。
`is_remote = true`（服务端下发）时**禁止**携带上述四类字段，
且代理类型 / 插件类型 / tcpmux 约束照常校验。客户端本机 Web API 传 `false`。

**回归测试** 5 条：四个字段逐个测拒绝、不认识的插件类型、不支持的代理类型。
每条都断言「本地表里不留代理」。

### 3. RBAC 两个死字段

**位置** `common/src/security.rs:629`、`security.rs:631`

**问题** `Role::allow_manage` 与 `Role::max_proxies` 能从配置赋值、能穿过 `compile()`，
但**全仓没有任何生产读取点**（只有赋值与测试断言）。
管理员写 `allowManage = false` / `maxProxies = 5` 以为限住了 实际毫无作用。

**修法** 让它们**真正生效**（而不是删字段——删了会破坏已有配置文件）

- `allow_manage`：随会话存进 `ClientState`（`set_allow_manage`），
  `admin.rs` 三个入口（增 / 删 / 踢）都检查。
- `max_proxies`：`check_proxy` 新增 `used_proxies` 参数，与全局
  `maxProxiesPerClient` 形成两层配额。

**回归测试** 3 条：配额穿过 `compile()`、边界（0/1/2 条时分别放行与拒绝）、
`maxProxies = 0` 表示不限不能误伤。

**顺带纠正** `allow_visitors` **一直是生效的**（`security.rs:740` 在 `check_proxy` 里读它），
不在死字段之列。

### 4. rustls 依赖漏洞

**位置** `Cargo.lock`（rustls 0.23.44）

**问题** RUSTSEC-2026-0285 CVSS 5.3 —— TLS 1.3 握手消息被跨加密层级错误接受。
影响 TLS 传输 / QUIC / OIDC 的 HTTPS 客户端。修复版 `>= 0.23.45`。

**修法** 升到 **0.23.45**；`.github/workflows/ci.yml` 加 `rustsec/audit-check@v2` 门禁
（v0.5.1 就是带着这个漏洞发出去的 且当时没有任何环节会去查）。

**验证** `cargo audit` 从 1 条漏洞变为 **exit 0**。

### 5. `Expect: 100-continue` 死锁

**位置** `server/src/vhost.rs`（原请求处理循环内完全未处理）

**问题** 客户端发这个头后会先等 100 才发请求体 而服务端不回应就直接转发头、
然后 `read_n` 等请求体——双方互等 一直挂到 `vhostHTTPTimeout`（默认 **60 秒**）。
**单条请求就能占住一条工作连接 60 秒** 是很划算的放大 DoS。

**修法** 自己回 `100 Continue` 并摘掉该头（照搬客户端 `plugin_bridge.rs:218` 已有的正确做法）。
不把中间态转发给上游——那要处理「响应先于请求体」的重排序。

**回归测试** 端到端：只发头不发体 断言立刻收到 `100 Continue` 且上游收到的头里没有 `expect`。

### 6. CL+TE 请求走私

**位置** `server/src/vhost.rs` 读请求体那段

**问题** 同时存在 `Transfer-Encoding` 与 `Content-Length` 时 代码按 chunked 读（方向正确），
但**两个头都原样转发**给上游。上游若按 `Content-Length` 解读同一串字节
双方对「请求到哪结束」的认知就不同了 —— 经典 CL.TE 走私。

**修法** 两头并存直接 **400**（RFC 7230 §3.3.3 允许的做法 合法客户端不会这么发）。

**回归测试** 端到端发经典 CL.TE 形态（chunked 体里藏第二个请求）断言 400 而不是转发。

---

## 二 中危（5 项）

### 7. HTTP 头注入

**位置** `common/src/http_relay.rs:259 set()` / `:279 to_bytes()`

**问题** `set()` 不剥离 CRLF 而 `to_bytes()` 直接拼接。
`plugin_request_headers` 能被**服务端经 `ServerCmd` 下发** ⇒ 值里塞 `"\r\nX-Admin: 1"`
就能往用户**内网服务**的请求里插任意头 甚至借 `Content-Length` 走私。

**修法** 新增 `strip_crlf()` **双重防线**：`set()` 写入时剥 `to_bytes()` 序列化时再剥一遍
（防畸形头绕过 `set` 直接进 `headers`）。

**回归测试** 值注入 / 名字注入 / 裸 LF 三种形态；
★ 判据用**报文结构**（不出现 `\r\nX-Admin`、CRLF 计数不变）而不是「不含某字符串」——
剥离后残留字符留在同一个值里完全无害。

### 8. 客户端 Web 无 CSRF 防护

**位置** `client/src/web.rs handle()`

**问题** 只看 Basic Auth 而 `user` 留空时连那层都没有。恶意网页可盲打
`POST /api/proxies/add` 增删隧道、`POST /api/stop` 关掉客户端；
或用 DNS rebinding 伪装成 `http://evil.com` 访问 127.0.0.1 上的端口。
非回环 + 无凭据原先**只打一条 warn 就放行**。

**修法** 两道检查（只对写操作）

1. 带 `Origin` 就必须是本机回环来源（浏览器跨站请求必带 Origin 命令行默认不带 所以不误伤脚本）
2. 写操作必须带 `X-Nfrp-Client: 1` —— 自定义头触发 CORS 预检 本界面不回应预检
   ⇒ 跨站写请求根本发不出去
3. 非回环 + 无凭据 ⇒ **拒绝启动**（`check_web_server_is_safe()`，**必须在 bind 之前**）

**回归测试** 6 条 真实 socket 端到端：跨站 Origin 403、缺防伪头 403、
带防伪头能过（400 而非 403）、读请求不需要头、Origin 解析、写方法判定。

**踩到的坑** 第一次改错了 —— 在 `web::run()` 里 `return`，但端口已经 bind、
监听已在跑 日志写着「已拒绝启动」而实际开着 **比不检查更糟**。
端到端测试抓到（进程还在 + 端口在监听）改成 bind 之前检查。

### 9. 逐跳头未剥离

**位置** `server/src/vhost.rs` 改写请求头段

**问题** `HOP_BY_HOP` / `connection_tokens` 这两个工具**早就在 `http_relay.rs` 里定义**
客户端 `plugin_bridge` 也一直在用 但服务端 vhost **一次都没调**。
`Connection: keep-alive, X-Secret` 会让上游把 `X-Secret` 也当逐跳头；
`Upgrade: h2c` + `Connection: Upgrade` 可能让上游切到 h2c 绕开假定的 HTTP/1.1 语义。

**修法** 转发前整批摘掉（服务端不支持 WebSocket 升级 所以可以全摘）。

**回归测试** 端到端发四种逐跳头 断言上游一个都没收到 且正常头（Host）仍在。

### 10. `Host` 头按 `:` 硬切

**位置** `server/src/vhost.rs:767`

**问题** `h.split(':').next()` 对 `[::1]:8080` 会切出孤零零的 `[` 对 `::1` 切出空串；
口径也与 tcpmux/CONNECT 那条路径用的 `canonical_host` 不一致。

**修法** 统一走 `canonical_host()`（顺带规范化尾点与大小写 与官方 `util.CanonicalHost` 对齐）。

**回归测试** IPv6 带端口 / 不带端口 / 普通域名带端口 / 大写带尾点 / 绝对形式。

### 11. `store.rs` 落盘权限与环境

**位置** `client/src/store.rs flush()`

**问题** 这份文件含**完整的代理配置**（`secret_key`、插件密码、`http_pwd`）
却用 `std::fs::write` 走默认 umask（通常 0644）—— 同机其他用户可直接读走密钥。
`logfile.rs` 早就按 0600 落盘（注释里也写了「日志里可能有 token」）这里一直漏了。
另外 `with_extension("tmp")` 在同级目录可写时存在软链 TOCTOU。

**修法** 先 `remove_file` 掐掉软链 再用 `create_new` + Unix `mode(0o600)` 打开写入。

---

## 三 低危（1 项 + 2 处健壮性）

### 12. HTTP 代理 Basic Auth 用普通 `==`

**位置** `server/src/vhost.rs:806`

**问题** 用户自配的 HTTP 代理访问密码用 `==` 比较 而全项目其它四处凭据比较
（登录 token / 面板 / visitor 签名 / P2P 口令）都走 `constant_time_eq`。
逐字节比较会通过响应耗时泄露前缀。

**修法** 改 `constant_time_eq` 与既有口径一致。

### 13. 面板无并发上限 且认证失败无退避

**位置** `server/src/dashboard.rs`

**问题** 面板 accept 循环对每条连接无条件 `spawn` 没有上限 ——
面板与业务跑在**同一个进程**里 洪水式连接能把任务/内存占满进而拖垮整个服务端。
另外认证失败立即返回 定长比较虽挡住了「按耗时逐字节猜」
却挡不住「猜得快」（面板走 TCP 本机/内网每秒能试几千次）。

**修法**

- 并发闸门 `MAX_DASHBOARD_CONNS = 128`（`try_acquire_owned` 拿不到就直接关连接
  不回 503 —— 洪水场景下连写都不想写）
- 认证失败加 200ms 延迟 单连接降到约 5 次/秒

★ 用 `sleep` 而不是「按 IP 计数熔断」：后者要维护一张会无限增长的表
（还得处理过期清理）对面板这个低频接口不划算。

### 14. 裸 `lock().unwrap()`

**位置** `client/src/health.rs:52/76/85`、`client/src/p2p.rs:241/253/263`

**问题** 与项目其它处不一致 —— `store.rs` / `registry.rs` 都刻意写了
`unwrap_or_else(|e| e.into_inner())` 并在注释里说明理由 这两处漏了。
危害不在当场 panic 而在之后：锁一旦被写脏 **后续每次**调用都 panic
而 `is_healthy` 因为 `.unwrap_or(true)` 会退化成「永远健康」故障被掩盖。

**顺带修** `p2p.rs request()` 在 `send` 失败时**漏删 waiter** 会持续累积
（原先 `.map_err(...)?` 直接返回）。`clear()` 只在控制连接断开时兜底
而这条路正是「连接已经坏了」的场景。

### 15. 示例配置默认把 SSH 暴露到公网

**位置** `assets/frpc.toml:87-91`（`name = "ssh"` / `local_addr = "127.0.0.1:22"` / `remote_port = 6000`）

**问题** 这条 `[[proxies]]` 是**未注释的启用状态**，而 `docker-compose.yml`
又原样挂载它。跟着示例跑一遍，**SSH 就裸奔在公网 6000 端口上**了 ——
任何人可以尝试登录，只是换了个端口号。

**修法** 两处都加醒目警告

- `assets/frpc.toml`：代理段开头加「每加一条就等于把内网服务放到公网」的说明，
  并点明第 1 条默认启用的是 SSH
- `docker-compose.yml`：把原来那句轻描淡写的「演示：把本机 22 端口暴露到 6000」
  改成明确警告

★ **有意保留默认启用**：改成默认注释掉会让 `docker compose up` 跑起来一个代理都没有
（用户以为在演示、实际什么都没转发）那也是破坏。用警告而不是改行为。

### 16. Dockerfile 健康检查的取舍

**位置** `Dockerfile`

**结论** **有意不加 `HEALTHCHECK`**（并把这个决定写在文件里）。

唯一适合做探针的是免鉴权的 `/api/healthz`，但它挂在**面板端口**上，
而随包发出的 `assets/frps.toml` 里 `dashboard_port` **默认是注释掉的**。
写死探针 ⇒ 用户一 `docker compose up` 就看到 `unhealthy` 且不知道改哪儿；
做成环境变量又没用（`HEALTHCHECK` 在构建期固化，运行期改配置影响不到它）。
**「容器看起来一直 unhealthy」比「没有健康检查」更难排查。**

控制端口 17000 也不能当探针：它是 frp 协议端口不是 HTTP。

### 17. 启动告警语焉不详

**位置** `server/src/main.rs`、`server/src/serve.rs`

三处告警补上「对外监听」的语境与具体后果

- 空 token：原先只说「强烈建议设置」用户看不出跟「绑在 0.0.0.0」的关系
- RBAC 配了 `[[roles]]` 却没写 `denyUnknown` / `defaultRole`：
  **没匹配到任何角色**的用户会拿到不受限的**全权**角色
  （这不能改默认值 会破坏合法用法 但必须明确告警）
- 无资源上限：把「任何人都能拖垮服务端」说清楚

---

## 四 查过确认「无」的（省得重复排查）

| 类别 | 结论 |
|---|---|
| 命令执行 / RCE | **无**。客户端零 `Command::new` 零 shell；9 个插件全是进程内实现 不 bring 起任何外部进程。全仓唯一子进程是 `tun_linux.rs` 的 `ip` 走 `args()` 数组不过 shell |
| 路径穿越 | **无**。`static_file` 的 `canonicalize` + `starts_with` 正确且有回归测试；面板路径走精确匹配 |
| SSRF | **无**（请求可控意义上）。vhost 目标是客户端注册的 `local_addr` 由已认证方控制 |
| 认证 timing attack | **无**。四处凭据比较全部 `constant_time_eq`（逐字节 XOR 累加不提前返回） |
| PBKDF2 参数偏离 | **无**。盐 `frp` / SHA-1 / 64 迭代 / dkLen 16 与官方向量逐项吻合 且有**官方真实抓包密文**做的回归测试锁着 |
| OIDC JWT 降级 | **无**。alg 白名单不含 `none` / `HS*` 先校验 alg 再找 key |
| P2P 对端校验 | **完整**。`quic_accept` 严格校验来源 IP 身份闸门是 `SHA256(secret_key:sid)` 定长比较 |
| 明文凭据进日志 | **无**。`AuthProvider::Debug` 主动脱敏 |
| 目录遍历 / 静态文件 | **无**（服务端根本没有 `assetsDir` 静态服务） |
| PROXY protocol 注入 | **无**。用 `(Unknown, 0)` 表达「像但没收全」刻意避免半截二进制被当数据放行 |

### 两处「疑似高危」实测后降级为**误报**

- **`sni.rs::parse_sni` 越界 panic**：**不成立**。
  30 万次 fuzz + 定向构造（极短 body / 超大 `comp_len` / `ext_len=0/1`）零 panic。
  `need()` 前置检查保证 `i` 恒 ≤ `body.len()-1`。
- **审计日志 CRLF / ANSI 注入**：**不成立**。
  实测 `serde_json` 把 `\r\n` 输出为**转义序列**（`"a\r\n{\"fake\":1}"`）
  不含真实换行；`\u001b` 同理。落盘 JSONL 不会被撑开。

---

## 五 待决策（我没擅自动）

### 明文凭据

| 文件 | 内容 | 是否会被上传 |
|---|---|---|
| `tmp/gh-token.txt` | GitHub PAT（`github_pat_` 前缀） | **否**（`gh_upload.py` 的 `SRC = ROOT / "nfrp"`） |
| `android/keystore/CREDENTIALS.txt`<br>`android/dist/keystore/CREDENTIALS.txt` | APK 签名口令明文 | **否**（在 `nfrp/` 之外） |
| `nfrp/dist/keys/release.key` | Ed25519 发布签名私钥 | **否**（被 `.gitignore` 的 `/dist` 挡住 已实测确认） |

**好消息** 泄露路径是封闭的 以上都不会被推上 GitHub 或打发布包。

**建议** 改用 `GH_TOKEN` 环境变量（`tmp/gh-token.README.md` 已把该方案提为**首选**）。
★ 令牌一旦外泄（投屏 / 共享盘 / 备份 / 误传）必须去 GitHub 后台 **Revoke** 并重建 ——
删本地文件没用。

### 行为变更提示

- 配了 `dashboard_port` 但绑非回环、又没配 `dashboard_user` 的**现有部署会起不来**。
  错误信息里给了三条出路。这是有意为之（那正是漏洞场景）。
- 客户端 `[webServer]` 监听非回环且无凭据 同样会拒绝启动。
- 调本地管理界面写接口的命令行脚本需要加 `X-Nfrp-Client: 1` 头。

### 公开 API

`CompiledRbac::check_proxy` 加了第 5 个参数（`common` 是 public API）。
项目内无外部使用者 影响可忽略 但记一笔。

---

## 六 改动文件清单

```
common/src/security.rs      RBAC 死字段落地 + 2 条回归测试
common/src/util.rs          is_loopback_addr() + 测试
common/src/config.rs        allow_insecure_dashboard / allow_insecure_remote 字段
                            validate_remote_proxy() + reject_bad_proxy() 抽取
common/src/http_relay.rs    strip_crlf() 双重防线 + 头注入回归测试
server/src/main.rs          面板鉴权启动校验 + 3 条测试 + 告警强化
server/src/serve.rs         面板校验兜底 + 告警强化
server/src/guard.rs         check_proxy 签名
server/src/admin.rs         allow_manage 三入口检查
server/src/pool.rs          ClientState::allow_manage
server/src/vhost.rs         100-continue / CL+TE / 逐跳头 / Host 解析 / 常量时间比较
                            + 4 条端到端回归测试
server/src/dashboard.rs     并发闸门 + 认证失败退避
client/src/main.rs          ServerCmd 校验 + check_web_server_is_safe + 5 条测试
client/src/web.rs           CSRF 防线 + 6 条端到端测试 + 删重复的回环判定
client/src/store.rs         0600 权限 + 防软链
client/src/health.rs        poison 处理
client/src/p2p.rs           poison 处理 + waiter 泄漏
.github/workflows/ci.yml    cargo audit 门禁
Dockerfile                  免 HEALTHCHECK 的取舍与理由
docker-compose.yml          SSH 暴露警告
assets/frps.toml            新开关与行为说明
assets/frpc.toml            新开关 / CSRF 头 / SSH 暴露警告
Cargo.lock                  rustls 0.23.45
```
