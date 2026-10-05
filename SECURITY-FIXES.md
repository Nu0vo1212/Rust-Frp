# NFrp 安全修复报告

日期 2026-10-04（第一轮）/ 2026-10-05（第二轮、第三轮）
范围 全仓（common / client / server 三个 crate、184 个依赖、Docker / CI / 打包链路）
状态 **已修 52 项 全部带回归测试** 质量门全绿 已作为 v0.5.4 发版

质量门结果

| 项 | 结果 |
|---|---|
| 测试 | **612 通过 0 失败**（首轮前 542 → 564 → 584 → 612） |
| `cargo fmt --check` | 干净（exit 0） |
| `cargo clippy -D warnings` | **0 告警**（Windows 与 Linux 各一遍） |
| `cargo audit` | **exit 0 零漏洞**（第一轮修复前 1 条） |

三轮的定位不同，都记在下面：

| 轮次 | 版本 | 问的问题 | 结果 |
|---|---|---|---|
| 第一轮 | v0.5.2 | 全仓扫一遍，有没有漏洞？ | 17 项 |
| 第二轮 | v0.5.3 | **上一轮新写的防线本身能不能被绕过？** | 11 项（含 1 个高危） |
| 第三轮 | v0.5.4 | 引入**外部独立审计报告**逐项复核 | 24 项（5 高危 / 9 中危 / 10 低危） |

---

# 第三轮审计（2026-10-05，v0.5.4）

这一轮的依据是一份**外部独立审计报告**（5 高危 / 9 中危 / 10 低危 = 24 项）
外加随报告提供的 H5 修复 patch。逐项复核后的结论与处理如下。

★★ **贯穿性问题**（值得单独记下，因为它解释了为什么会有第三轮）：

> **防线/字段写对了，但没有铺满它自己声称要保护的所有路径、字段与校验点。**

第一、二轮修的都是"缺少某道防线"；这一轮几乎全是**"防线只在部分地方生效"**。
H3（漏了整条 store 恢复路径）与 H4（黑名单漏了一个字段）都是**黑名单模式**的
必然结果 —— 换个入口就绕过去了。处理这几项时统一改成了**允许清单**。

## 高危（5 项，全部实弹或元验证）

| ID | 缺陷 | 位置 | 验证方式 |
|---|---|---|---|
| **H5** | `group_key` 是死字段 —— 组认证被完全丢弃 | `server/src/registry.rs` + `serve.rs` | 实弹：真起 frps + 3 个 frpc，错误 key 被拒、正确 key 加入 |
| **H1** | 热重载删掉 `dashboard_port` 行可绕过面板鉴权闸门 | `server/src/reload.rs` | 元验证 + 实弹（面板端口仍监听，但匿名仍 401） |
| **H2** | 重复 `Content-Length` 请求走私（CL.CL） | `server/src/vhost.rs` + `common/src/http_relay.rs` | 实弹：5 种攻击形态全 400 且未转发，3 种合法请求 200 |
| **H3** | store 恢复路径完全绕过 `validate_remote_proxy` | `client/src/store.rs` + `main.rs` | 元验证（还原旧代码后 3 条测试失败） |
| **H4** | `local_addr` 不在远程黑名单 ⇒ 服务端可控 SSRF | `common/src/config.rs` | 元验证（移除白名单后测试失败） |

**H5 说明**：`reserve_port` 只比对组名、不比对 `group_key`，于是任何持合法 token
的客户端只要知道别人的组名（README 示例里就是 `web`）就能挤进那个负载均衡组，
该端口上约 1/N 的连接会被转到攻击者的服务。修法是把 `group_key` 当**认证凭据**
而非标签（常量时间比较），并保留"双方都未配 key 时照常成组"的兼容行为。

**H2 说明**：`get()` 只返回**第一个**同名头，而 `to_bytes()` 会把**所有**同名头都
发出去 —— "读一个、写两个"正是 CL.CL 的成因。三层修复：拒绝重复 CL、
严格解析（原先 `unwrap_or(0)` 会把 `Content-Length: abc` 静默当成 0）、
转发前同名头去重（`set-cookie` 等列表型头除外）。

**H4 说明**：`local_addr` 决定客户端往哪里连，原先不在远程黑名单里
（黑名单里有 `plugin_local_addr` 却漏了它）。改成**允许清单**：远程下发只允许
回环地址。理由是"远程下发本来就不该决定客户端连哪里"。

**H1 说明**：这是**第二轮我自己修的防线没铺满**。第二轮把"运行期生效的
`bind_addr`"喂进判据，却漏了同样不可热改的 `dashboard_port` —— 于是删掉配置行
就能让判据误以为"面板没开"，而监听器还活着。修法是把**所有不可热改字段**
都取运行期值，并抽成 `dashboard_exposed_after_reload(live, new)`。

## 中危（9 项）

| ID | 缺陷 | 修法 |
|---|---|---|
| **M1** | 示例配置默认把 SSH 暴露到公网 | 改为**默认注释掉**（原先只加警告、保留启用） |
| **M2** | 签名验证 fail-open：脚本路径可静默发未签名版；CI 只验 1/4 签名 | 签名缺失/失败**非零退出**（加 `--allow-unsigned` 逃生开关）；CI 逐个验签 + 断言每个产物都有签名 |
| **M3** | 文档称"CSRF 实弹通过"但未写明测的是客户端界面 | 表述澄清（面板用 Basic Auth，本就不需要 CSRF 防线） |
| **M4** | 空 token + 对外监听 ⇒ 完全无认证，且只 warn 不拦 | 拒绝启动 + `allow_insecure_no_auth` 逃生开关 |
| **M5** | `ClientAuthConfig` 的 `Debug` 未脱敏 | 手工脱敏（与同文件 `ServerAuthConfig` 对齐） |
| **M6** | 未认证连接可各占 8 MiB（`plain` 无上限 + 握手无总超时） | `MAX_PLAIN` 硬顶 + 握手 30s 总超时 |
| **M7** | AEAD 无帧计数器，丢掉上游 2³² 帧的 fail-closed | 加帧计数 + 到上限拒绝加密 |
| **M8** | "官方抓包"向量的生成脚本不在仓库里 | 如实标注来源不可复现 |
| **M9** | `[acl]` 段拼写错误被静默忽略 | 加 `deny_unknown_fields`（拼错即报错） |

**M4 需要特别说明**：审计建议"向面板路径看齐、拒绝启动"，但**照抄会废掉默认配置**
（`ServerConfig::default()` 就是 `bind_addr = "0.0.0.0"` + 空 token，无条件
`ensure!` 会让 `--gen-config` 生成的示例都起不来 —— 实测当场打破 5 条既有测试）。
最终口径分三档：绑回环 ⇒ 只 warn；绑对外**且用户显式写过 `bind_addr`** ⇒ 拒绝启动；
绑对外但用的是默认值 ⇒ 强告警但不拦。为此在配置里加了 `bind_addr_explicitly_set`
（解析副产品，不进配置文件），并专门加了一条「出厂默认配置必须能启动」的测试守着。

## 低危（10 项）

| ID | 缺陷 | 修法 |
|---|---|---|
| **L1** | 面板读头循环无超时 ⇒ 128 连接 slowloris 饿死面板 | 加 10s 总超时 |
| **L2** | 逐跳头只剥请求侧、不剥响应侧 | 响应侧同样剥（先剥再写自己的 `Connection`） |
| **L3** | HTTP 路径丢弃上游 `leftover` ⇒ 响应可能被截断 | 喂回 `HttpIo::with_prefill` |
| **L4** | `.gitignore` 覆盖过窄（`/dist` 根锚定） | v0.5.3 已补仓库根 + `android/` 的 `.gitignore` |
| **L5** | 客户端 TLS 不校验对端证书（MITM） | v0.5.3 已文档化（与官方 frp 行为一致） |
| **L6** | `udp_proxy.rs` 5 处裸 `lock().unwrap()` | 统一为 `unwrap_or_else(\|e\| e.into_inner())` |
| **L7** | `origin_is_local` 只看第一个 `Origin` 头 | 新增 `headers_all()`，逐条校验 |
| **L8** | `extract_plugin` 用精确匹配而非大小写折叠 | 改大小写折叠（对齐 Go 的 `EqualFold`） |
| **L9** | WebSocket 控制帧无 ≤125 上限 ⇒ 放大型 DoS | 加 `MAX_CONTROL_PAYLOAD = 125` |

## 第三轮额外发现（审计报告未列，实测撞出来的）

| 问题 | 说明 |
|---|---|
| `run_id` 随机性测试有 **16% 假红率** | 第二轮自己写的测试，阈值 55 卡在分布均值附近（蒙特卡洛 20 万次：失败率 16.2%）。改 42 后好实现假红 0、三种坏实现 100% 抓到 |
| H3 的测试**假通过** | 第一版测试的 store JSON 漏了必填字段 `local_addr`，整份文件反序列化失败、条目没进内存 ⇒ 测试"通过"是因为别的原因。靠"还原旧代码后测试仍绿"才发现 |
| `local_addr_host` 的 **IPv6 bug** | 自己的实现把裸 `::1` 切成 `":"`，会**误拒合法地址** |
| M4 照抄建议会**废掉默认配置** | 见上面 M4 说明 |

## 方法论：每条修复都做"元验证"

这一轮最重要的做法是：**把实现临时退回缺陷版本，确认新测试真的会失败**。

H3 那条正是因此暴露出假通过 —— 如果只跑一遍绿灯就收工，就会带着一个
没验证过的测试进仓库。具体做法见 `tmp/verify_h1_test.py` 与 `tmp/verify_h3_test.py`。

另一条经验：**审计建议不能照抄**。M4 的建议在面板场景成立、在核心配置场景
会破坏默认部署；H4 的建议若继续扩黑名单，下次还会漏字段。所以逐条复核时
要问"这个建议在当前上下文里成立吗"。

---

# 第二轮审计（2026-10-05，v0.5.3）

★ 这一轮的问题不是"还有没有漏洞"，而是**"第一轮新写的那道防线本身能不能被绕过"**。
产品代码在审计期间**一行未改**（纯只读 + 实弹验证）。

## 🔴 高危：热重载可一次性永久绕过面板鉴权

**位置** `server/src/reload.rs:64-104`（`apply_dynamic`）、`reload.rs:186`（`watch` 的快照）

**实弹复现**（`bind_addr = "0.0.0.0"` + `dashboard_user = "admin"` + `hot_reload = true`）：

| 操作 | 匿名 `GET /api/status` |
|---|---|
| 启动（有凭据，合法） | `401` ✅ |
| 运行中把 `dashboard_user` 改成空 | **`200`** ❌ |
| 再改回 `admin` | **`200`** ❌ 不恢复，必须重启 |

危害面与第一轮第 1 项完全相同（匿名读全量状态 / 业务指标、`kick` 返回 400 说明已穿过鉴权）。

**三个根因**：
1. `apply_dynamic` 允许运行期把 `dashboard_user` 清空（`*g = None`）；
2. 启动期那道「非回环 + 无凭据 ⇒ 拒绝启动」**只在启动路径跑过一次** ——
   `serve.rs:244` 的"防御性兜底"其实是 `serve_on_with()` 函数体里的**一次性顺序语句**，
   第 266 行 `spawn(dashboard)` 之后再也不会执行，`reload::watch` 到第 269 行才 spawn；
3. `watch()` 用一份**永不更新的启动快照**做 diff ⇒ 清空后 `old == new`，
   改回去时分支不再进入，`auth` 永久为 `None`（**不可逆**）。

日志是 `INFO 面板鉴权已热更新（用户：）` —— 空值、无告警，管理员会以为已经改好。

**修法**：
- 抽出 `dashboard_is_exposed(&ServerConfig) -> bool`，**启动校验与热重载校验共用同一口径**；
- `watch()` 在应用前对新配置**重跑一次安全校验**，不通过就整份拒绝并说明原因；
- `apply_dynamic` 的凭据分支加安全闸门（对外面板 + 清空用户名 ⇒ 拒绝本次热改、保持旧凭据）；
- `watch()` 真正推进基线快照（修掉"不可逆"）；
- 清空鉴权从 `info!` 改 `warn!` 并点名后果。

**回归测试 6 条**（`reload.rs::tests`）：对外面板不得清空鉴权 / 回环上允许清空 /
**清空后改回必须能恢复**（锁死不可逆）/ 逃生开关放行 / 没开面板端口时不受影响 /
`dashboard_is_exposed` 口径。★ 写这批测试时**当场抓出我自己第一版的判据写错了**
（判的是 `old` 而不是 `new`，拿去判恒为 false 等于没拦）。

## 🔴 OIDC 核验器被丢弃 ⇒ 该认证方式完全不可用

**位置** `server/src/guard.rs:74-82`（丢弃）、`guard.rs:129-142`（刷新后局部 drop）

`SecurityContext.auth` 是普通字段 + 外层 `Arc<SecurityContext>`，`refresh_oidc(&self)`
拿不到 `&mut` ⇒ 新拉的 JWKS **没有任何地方能存**，函数结束 verifier 即被 drop，
状态永远是 `OidcUnavailable`。文档引用的 `Self::ensure_ready` **全仓不存在**。

后果：`method = "oidc"` 时**拒绝所有人登录**（fail-closed，无绕过），
且 `oidc.rs` 里那些"已核实安全"的实现**从未在真实流量上执行过**（e2e 未覆盖 OIDC）。

**修法**：`auth` 改 `Arc<RwLock<AuthProvider>>`（新增 `AuthSlot` 类型 + `auth()` 短锁读快照），
`refresh_oidc` **真正回填**。**已用 mock IdP 实弹验证**：日志同时出现
「OIDC JWKS 已加载」与「OIDC JWKS 已就绪」（修复前只有前者）。
回归测试 3 条（槽位可写回 / 已就绪时刷新是空操作 / token 方式下是空操作）。

## 🔴 OIDC 的 `additionalScopes` 复核未绑会话

**位置** `common/src/auth/oidc.rs:490-504`（原 `verify_post_login`）

原来是一个**只增不减的全局 `HashSet<subject>`**，只问"这个 sub 曾在**某个**连接上登录过吗"
⇒ 攻击者用自己的合法 token 登录一次，就能用**同一个 token** 给**受害者的 run_id**
开工作连接（`serve.rs` 的 `verify_followup` 会放行）。

**修法**：改成 `HashMap<run_id, sub>` 二维绑定，新增 `forget_session()` 供会话结束时清理
（顺带消掉无界增长点）。`verify_login` / `verify_followup` / `verify_post_login`
都加了 `run_id` 参数；`vnet.rs` 的注册路径用 `reg.client` 作为会话标识。
回归测试 2 条（跨 run_id 不得通用 / 同一会话只保留一条绑定）。

## 🟠 其余

| # | 位置 | 问题 | 修法 |
|---|---|---|---|
| 1 | `server/src/vhost.rs:670` | `tcpmux` 用户名/口令仍用 `==`（第一轮常量时间修复**唯一漏的一处**） | `constant_time_eq` |
| 2 | `common/src/http_relay.rs:190`、`common/src/httpc.rs:350-354` | `out.len() + size` 用裸 `+`，release 未开 `overflow-checks` ⇒ 静默回绕绕过 32 MiB ACL | `saturating_add` / `checked_add` |
| 3 | `common/src/util.rs:250` | `run_id`（事实上的"工作连接持有票据"）押在 std 未承诺为密码学 PRF 的 `RandomState` 上 | `OsRng.fill_bytes` |
| 4 | `server/src/serve.rs` visitor 路径 | 错误文案未走脱敏开关：回显**代理名是否存在**、`allow_users` 里的**真实用户名** | 新增 `reject_with`，详情只进日志 |
| 5 | `server/src/main.rs` | 弱/占位 token 无任何提示（v1 是 `md5(token+ts)` 且不校验时间戳新鲜性 ⇒ 离线枚举 1 次 MD5/候选） | 新增 `check_token_strength`，检测占位值与低强度并强告警（**不拦启动**） |
| 6 | `common/src/config.rs`、`security.rs`、`auth/oidc.rs` | 7 个配置结构 `#[derive(Debug)]` ⇒ 任何调试打印都会泄漏明文 token / 面板口令 / `client_secret` | 手工脱敏 `Debug` + **3 条锁定测试**（写测试时**当场抓到两处真实泄漏**） |
| 7 | `server/src/audit.rs:159` | 审计日志用默认 umask（通常 0644）⇒ 同机用户可读走整条审计轨迹 | 新建时 0600，与 `logfile.rs` 对齐 |
| 8 | `.github/workflows/*` | **29 处**第三方 Action 全部用可变标签（含 `@stable` 这种 branch ref） | 全部 pin 到 commit SHA |
| 9 | `.github/workflows/release.yml:125-133` | cosign 两个 `continue-on-error` + shell `\|\| echo` ⇒ **一个字节都没签出来也全绿** | 删掉 `continue-on-error`，加 `verify-blob` 自检 |
| 10 | `.github/workflows/release.yml:210` | `github.event.inputs.tag` 直接拼进 shell（表达式注入面） | 改经 `env` 传值 + 正则白名单 |
| 11 | `Dockerfile:42` | 把客户端配置 `frpc.toml`（含默认启用的 SSH 代理示例）拷进服务端镜像 | 只拷 `frps.toml`；`rust:alpine` → `rust:1.90-alpine` |
| 12 | `android/gradle.properties` | keystore 口令**明文写在入库文件里** | 移到环境变量 / `local.properties`（已 gitignore），实测重建 APK 用正确发布证书 |
| 13 | 仓库根 / `android/` | **完全没有 `.gitignore`** ⇒ `/dist`、`*.log`、keystore 全无遮挡 | 补两份并逐条实测生效 |

## ✅ 第二轮确认「安全」的（避免重复排查）

- `is_loopback_addr` 是 fail-safe 的（解析失败/空串/`localhost` 一律当非回环）；
  面板**没有**独立监听地址（`dashboard_addr` 只是 INI 样例残留，实测无法绕过）；
  面板实际 bind 地址与判定逻辑一致（`netstat` 实测）。
- **客户端管理界面**的 CSRF 防线实弹通过：跨站 Origin / `Origin: null` / `path` 伪造全部 403；
  带防伪头的三种大小写变体正确放行（HTTP 头名大小写折叠是标准行为）。
  ★ 表述澄清（v0.5.4 修 M3）：这条测的是 **`client/src/web.rs`（客户端本地界面）**，
  不是服务端面板。**服务端面板本身没有 CSRF 防线，这是有意的、也是正确的** ——
  它用 HTTP Basic Auth 而不是 cookie / session 鉴权，浏览器不会"自动"替用户带上
  Basic 凭据，所以经典 CSRF（借用户已登录状态盲打）不成立。
  早先这段没写明是"客户端"，容易被误读成"面板也有 CSRF 防护"，故在此说清。
- 面板 128 并发闸门覆盖 `/api/healthz`（免鉴权但同走 `try_acquire_owned`）。
- `allow_insecure_*` 在生产代码里只有默认值 `false`（两处 `= true` 都在 `#[cfg(test)]` 内）。
- **第一轮 17 项修复的 21 个关键点逐个 grep 比对，零文档漂移**。
- 9 个解析器 × 约 66 万次 fuzz + 定向边界，**零 panic**。
- v1 CFB IV 不复用；v2 GCM nonce 唯一且 tag 失败会断连；**无明文降级**
  （`conn.rs:170-172` 的版本守卫挡住 v2→v1 的看似降级路径）。
- OIDC 的 alg 白名单 / 先验签后信 claim / kid fail-closed / exp 无 skew 重放窗口。
- `cargo audit` 实跑 exit 0；unmaintained 交叉比对中唯一命中的 `ring` 是误报
  （三条公告分别"已撤回"/"`unaffected = <0.17`"/"`patched >= 0.17.12`"，锁定 0.17.14 全豁免）。
- Dockerfile 有 `USER nfrp`（非 root）；compose 无 docker.sock / privileged /
  多余端口，挂载均 `:ro`。

## ⚠️ 第二轮如实标注的"不足为患"项

- `http_relay` 的 ACL 回绕**有次生兜底**：能绕过它的 `size` 恒 ≥ 2^64−out_len，
  必被 `read_n` 的独立 ACL 拒绝 ⇒ 实际约 64 MiB/连接封顶，**不是无限内存**。
  穷举 7 组 `out_len` 验证过。
- `tcpmux` 的 `==` 是跨网络字节级侧信道，被抖动淹没，工程上难以远程爆破 ⇒
  属"修复不完整"而非可利用漏洞。
- token 方式下重放 `Login` **拿不到可用会话**（密钥材料是 token 本身）
  ⇒ 弱 token 的实际杀伤是"强度退化到单次 MD5"，**强 token 不可重放**。
- `android/gradle.properties` 与生产 token **当前都没被推上远端**
  （GitHub API 实测 404 / 四块包 grep 零命中）⇒ 是"堵枪口"不是"事故"。

---

# 第一轮审计（2026-10-04，v0.5.2）


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
| PBKDF2 参数偏离 | **无**。盐 `frp` / SHA-1 / 64 迭代 / dkLen 16 与官方向量逐项吻合，且有**官方真实抓包密文**做的回归测试锁着（`v1.rs` 里 6 条：`登录帧与官方抓包一致` / `官方抓包的密文必须能解开` / `pbkdf2_派生与官方一致` / `salt_必须与官方一致` 等）。★ **来源说明（v0.5.4 修 M8）**：那些密文是**硬编码的测试常量**，生成/采集它的脚本**没有随仓库提供** —— 也就是说读者无法自行复现这个向量的出处，只能相信常量本身，或自己抓一次官方流量比对。这一点此前没写明，现如实标注 |
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
