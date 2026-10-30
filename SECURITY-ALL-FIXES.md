# NFrp 安全修复总文档（全部轮次整合）

**整合日期** 2026-10-25（2026-10-29 增补：总览表重写、发布通道收口）  
**覆盖轮次** 第一轮 ~ 第十七轮（共 14 份报告 + 第十七轮 + 发布通道）  
**文档体量** 约 274 KB（各轮原文完整收录）  
**适用版本** v0.5.5 ~ v0.6.6  

> 这份文档是**索引 + 全文**的合订本：先看下面的总览表定位问题，
> 再按轮次跳到正文查看「实测复现 / 修复方式 / 回归测试」。
> 各轮原文一字未改，只在最前面统一加了日期标头。

---

## 总览（按时间顺序）

> 这张表给"第一次打开这份文档的人"看：一行一轮，能直接判断"哪轮在打什么、
> 结论是什么"。正文各轮一字未改（历史记录），所以细节与措辞以各轮正文为准。
> 表里的版本号对应 crates.io 的发布时间，用于把轮次和产物对上。

| 日期 | 轮次 | 版本 | 主题 | 结论 |
|---|---|---|---|---|
| 2026-10-04 ~ 10-05 | 第一 ~ 三轮 | 0.5.2 → 0.5.4 | 基础审计：面板鉴权、`ServerCmd` 下发、ACL、端口管控、请求走私 | 17 项 + 5 处健壮性；两处"疑似高危"实测为误报，已写入排除清单 |
| 2026-10-13 | 第 4 轮 | 0.5.5 | 全仓审计；域名路由跨租户劫持、token 模式工作连接不校验 `privilege_key` | 13 项修完；首次确立「退掉→红、还原→绿」的退回验证 |
| 2026-10-15 | 第 5 轮 | 0.5.6 | 外部审计 39 条 + 热重载 / RBAC / 面板 XSS | 4 高 / 16 中 / 19 低全部处理；L17 评估后**明确不采纳**并记录理由 |
| 2026-10-15 | 第 6 轮 | 0.5.7 | 专打前五轮没碰过的面 | 8 项（3 高）：凭证重放只铺了 1/6 条路径，构成完整双向中间人 |
| 2026-10-17 | 第 7 轮 | 0.5.8 | 响应侧 framing、VNet 转发键、ACL 覆盖面 | 13 项（2 高）：响应走私成立；ACL 从未覆盖数据面 |
| 2026-10-17 | 第 8 轮 | 0.5.8 | xtcp 牵线、面板鉴权矩阵（421 探针）、TLS 插件 | 5 项（1 高）：牵线 HELLO 无鉴权可劫持，用来源绑定 + 派生口令双层修复 |
| 2026-10-17 | 第 9 轮 | 0.5.9 | ACL 三条漏网路径、资源耗尽、时间上界 | 9 项：≈800× 内存放大；时间上界可被单字节绕过 |
| 2026-10-17 ~ 10-18 | 第 10 轮 | 0.5.10 | 已发布二进制全量复扫 + Miri / ASan 新维度 | **无新漏洞**；8 个变红点位全部是探针自身缺陷，逐一修好后重跑全绿 |
| 2026-10-18 | 第 11 轮 | 0.6.0 | 云端 Linux 测试失败分诊 | 4 项修复，**全是测试自身缺陷、无产品缺陷**；HTTP 测试改为纯逻辑（照官方） |
| 2026-10-20 | 第 12 轮 | 0.6.1 | Shannon（AI 渗透器）审计核对 | 13 条：10 条无需改动、3 条真新发现并全修 |
| 2026-10-20 | 第 13 轮 | 0.6.2 | 负载均衡 / KCP 上限 / 健康检查对齐官方 | 官方是**轮询**不是最小连接；顺带修 1 个真实缺陷 |
| 2026-10-24 | 第 14 轮 | 0.6.3 / 0.6.4 | e2e 端口竞态 + 渗透低危（HEAD 带体、只读端点收 POST、安全响应头） | 3 项退回验证全有效；`plugin_bridge` 竞态两次修复失败，如实回滚 |
| 2026-10-24 | 第 15 轮 | 0.6.5 | 补齐未实现配置项 | 修掉 **OIDC ES256 验签格式**致命 bug；新增 9 条真实 IdP e2e |
| 2026-10-25 | 第 16 轮 | 0.6.6 | 官方 0.71 兼容收尾（NatHole/xtcp、SSH 网关、pprof、Windows VNet） | 真实 e2e 通过；修掉 SSH 网关指标 bug；Windows VirtualNet 真机验证 |
| 2026-10-26 | 第 17 轮 | 0.6.6 | 本地复现报告驱动的 5 项 | 4 条实弹复现全修；依赖漏洞清零（`cargo audit` 0 / 330 crates） |
| 2026-10-29 | 发布通道 | 0.6.6 | CI 唯一红灯：aarch64 musl 交叉编译 | 根因是 rust-cache 缓存串台（不是镜像旧），已修，见文末「发布通道」一节 |

---

## 逐轮正文



<!-- ===== 1/14 第一 ~ 三轮 ===== -->

> **日期：2026-10-04 ~ 2026-10-17** · **轮次：第一 ~ 三轮**

---

# NFrp 安全修复报告

日期 2026-10-04（一）/ 10-05（二、三）/ 10-13（四）/ 10-15（五）/ 10-16（六）/ 10-17（七、八、九）
范围 全仓（common / client / server 三个 crate、184 个依赖、Docker / CI / 打包链路）
状态 **已修 137 项 全部带回归测试** 质量门全绿 已作为 **v0.5.9** 发版

质量门结果

| 项 | 结果 |
|---|---|
| 测试 | **732 通过 0 失败**（542 → 564 → 584 → 612 → 646 → 692 → 699 → 725 → **732**） |
| `cargo fmt --check` | 干净（exit 0） |
| `cargo clippy -D warnings` | **0 告警**（Windows 与云端 Linux 各一遍） |
| `cargo audit` | **exit 0 零漏洞** |
| 元验证 | 第九轮：**9 条成立项全部重跑全绿**（c9_3 9/9、c9_4 15/15、a9_3b 20/20、a9_5 11/11、a9_7 10/10、d9_7b 6/6；E9-0 12/12、E9-1 6/6、E9-2 8/8、C9-1 238→23.7 MB）；**退回验证 11 个点位**全部"退掉→红、还原→绿"（6 文件 7 处反向改动，含 1 处测试挂死的独立证据）。第七 / 八轮记录见 ROUND7 / ROUND8 文档 |
| 端到端冒烟 | **28 / 28** |
| 官方 frpc 互通 | **实测通过**（0.71.0，全部改动生效后复测） |

★ **第九轮的完整报告见 第 9 轮** ——
9 条（4 中危：UDP 端口不受 ACL / KCP 会话表无上限（放大 312×）/ 未认证开流（放大 ≈800×）/
时间上界被单字节绕过；1 条中危功能回归：visitor 空 user 被误拒；4 低危），
另有 1 条预防性加固与 9 条排除（附实测反证），
含两次"元验证打醒修复本身"与探针缺陷 3 条的如实记录。

★ **第八轮的完整报告见 第 8 轮** ——
5 项（1 高危：xtcp 牵线劫持；4 低危：面板解析 / 全名删除 / 注释与实现不符 / `https2*` 上游收尾），
附逐条独立复现、交叉验证，以及两处装置修正（抓包盲区、隔离副本陈旧）的如实记录。

★ **第七轮的完整报告见 第 7 轮** ——
13 项（2 高危 / 7 中危 / 4 低危）的根因、实弹证据、修法与守卫，
含"测试测错了对象""修复返工"等如实记录。

★ **第六轮的完整报告见 第 6 轮** ——
8 项（3 高危 / 4 中危 / 1 低危）+ **13 条被排除的线索（附反证）**，
以及**如实记录的未覆盖面**（7 个分工组有 6 组在实证阶段中断）。

★ **第五轮的完整报告见 第 5 轮** ——
39 项（4 高危 / 16 中危 / 19 低危）的根因、实弹证据、修法、元验证、
**以及三处诚实记录的覆盖缺口**都在那里。

★ **第四轮的完整报告见 第 4 轮** ——
11 项（5 高危 / 5 中危 / 1 低危）。

本文只保留前三轮。

九轮的定位不同，都记在下面：

| 轮次 | 版本 | 问的问题 | 结果 |
|---|---|---|---|
| 第一轮 | v0.5.2 | 全仓扫一遍，有没有漏洞？ | 17 项 |
| 第二轮 | v0.5.3 | **上一轮新写的防线本身能不能被绕过？** | 11 项（含 1 个高危） |
| 第三轮 | v0.5.4 | 引入**外部独立审计报告**逐项复核 | 24 项（5 高危 / 9 中危 / 10 低危） |
| 第四轮 | v0.5.5 | 按漏洞类别并行深挖 + 每个发现必须打出真实利用 | 11 项 |
| 第五轮 | v0.5.6 | 外部审计总报告（39 条）逐项核实 + 修复 | 39 项 |
| 第六轮 | v0.5.7 | **只打前五轮没碰过的面**（渗透视角） | 8 项（3 高危） |
| 第七轮 | v0.5.8 | 前六轮没碰过的面（HTTP 响应侧 / VNet 键 / 空闲池 / 日志放大 / 远程下发 / ACL 覆盖面） | 13 项（2 高危） |
| 第八轮 | v0.5.8 | 收尾第七轮遗留：xtcp 牵线 / 面板鉴权矩阵 / TLS 入站插件 | 5 项（1 高危） |
| 第九轮 | v0.5.9 | 覆盖 v0.5.8 自述未审计的面：ACL 三条缺口 / KCP / 资源耗尽 / 并发 / 客户端入口 / 传输层数据面 | 9 项（4 中危 + 1 功能回归 + 4 低危）+ 1 加固 |

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


<!-- ===== 2/14 第 4 轮 ===== -->

> **日期：2026-10-13** · **轮次：第 4 轮**

---

# NFrp 第四轮安全修复报告（v0.5.5）

日期 2026-10-13
范围 全仓（common / server / client 三个 crate、打包与发布链路）
方法论 参考 [KeygraphHQ/shannon](https://github.com/KeygraphHQ/shannon)：
分阶段流水线 + 按漏洞类别并行分工 + **每个发现必须打出真实利用**
状态 **已修 11 项**（5 高危 / 5 中危 / 1 低危）全部带回归测试 + 元验证
基线 v0.5.4 · 本版 v0.5.5

质量门

| 项 | 结果 |
|---|---|
| 测试 | **646 通过 0 失败**（v0.5.4 是 612，本版 +34） |
| `cargo fmt --check` | 干净（exit 0） |
| `cargo clippy -D warnings` | **0 告警**（Windows 与云端 Linux 各一遍） |
| 元验证 | **11 项全部合格**（退回缺陷后对应测试确实变红） |
| 官方 frpc 互通 | **实测通过**（0.71.0，v1 协议，tcp 代理转发成功） |

---

## 一、本轮与前三轮的区别

| 轮次 | 版本 | 问的问题 | 结果 |
|---|---|---|---|
| 第一轮 | v0.5.2 | 全仓扫一遍，有没有漏洞？ | 17 项 |
| 第二轮 | v0.5.3 | 上一轮新写的防线能不能被绕过？ | 11 项 |
| 第三轮 | v0.5.4 | 外部审计报告逐项复核 | 24 项 |
| **第四轮** | **v0.5.5** | **按漏洞类别并行深挖 + 每个发现必须打出真实利用** | **11 项** |

★★ **贯穿性结论（第四轮第四次复现同一个模式）**：

> **防线/字段写对了，但没有铺满它自己声称保护的所有路径、字段与校验点。**

本轮 11 项里有 **7 项**都是这个模式的实例：

| 发现 | "写对了的地方" | "漏掉的地方" |
|---|---|---|
| H1 | `registry.rs` 用了 `same_client && name` | vhost 三处只比名字 |
| B-1 | vhost 已在 H1 里补上客户端身份 | `visitors.remove` 漏了 |
| F1 | H4 给 `local_addr` 用了允许清单 | `plugin` 这个能力开关从没进判定 |
| A-1 | 注释写清了意图 | 实现只在 OIDC 下生效 |
| D-02 | 客户端路径调用 `check_proxy` | 面板路径没有 |
| C-1 | H2 修了 CL 侧 | TE 侧没修 |
| A-3 | `reject()` 路径过了脱敏 | `client_msg` 路径没有 |

**建议的下轮自动化检查**：凡是"安全字段 / 安全开关"，
都必须有一条测试断言"它在读取路径上**真的被使用了**"，而不是只断言"它存在"。

---

## 二、高危（5 项）

### H1 · HTTP/tcpmux 域名路由可被跨租户劫持

**位置**：`server/src/vhost.rs` 的 `register` / `remove_proxy`

**根因**：`VhostTable` 的归属判定**只用客户端可自报的 wire name**
（`{user}.{name}`），没带不可伪造的连接身份。而 `user` 来自登录报文
（`serve.rs` 的 `login.user`），默认配置（无 `[[roles]]`）下 `role_for`
对任何用户名都返回 `unrestricted`。于是两个租户声明同一 `user`
就得到同一 wire name，`same_proxy` 判真 ⇒ 跳过冲突检查 ⇒
`retain` 删掉**对方**的路由。

**实弹**（`tmp/audit4-probe-vhost-hijack.py`）：

```
受害者注册后访问 -> 'I-AM-VICTIM'
攻击者注册后访问 -> 'I-AM-ATTACKER'      ← 域名被顶掉
attacker 日志：INFO 代理注册成功 proxy=web remote=web.test:17801
```

**冒烟枪**：同一个仓库里 `registry.rs` 已经写对了
（`same_client(&b.client,&client) && name`），vhost 三处漏了那半截。
**同根因第二面**：`remove_proxy` 也只比名字 ⇒ A 能靠 `CloseProxy`
摘掉 B 的路由（跨租户 DoS）。

**修法**：引入 `same_owner()`（`Arc::ptr_eq` 比连接身份），三处判定全带上客户端。

**复测**：攻击者注册被拒（`域名 web.test 的路径已被代理 victim.web 占用`），
域名仍归受害者。2 条回归测试 + 元验证合格。

---

### F1 · 远程下发 `plugin` ⇒ 客户端变开放代理（完整绕开 H4）

**位置**：`common/src/config.rs` 的 `validate_remote_proxy`

**根因**：两处不完整叠加：
1. 回环检查在 `local_addr` 为空时被**整个跳过**；
2. 黑名单只列了 4 个 `plugin_local_*` 字段，**`plugin` 能力开关从没进判定**。

而插件路径**根本不需要 `local_addr`**。

**实弹**（`tmp/audit4-verify-F1b.py`，目标 `192.168.3.15:17912` 非回环）：

| 实验 | 下发结果 | 实际可达 |
|---|---|---|
| A 普通 tcp 代理 | **400 拒绝** | 不可达 |
| B `plugin=http_proxy` | **200 放行** | **读到 SECRET** |
| C `plugin=socks5` | **200 放行** | **读到 SECRET** |

**影响**：比原 H4 更严重 —— 攻击者可现指定**任意**目标（通用正向代理）、
可当跳板隐藏来源（出站源 IP 是客户端）。

**修法**：远程下发**一律拒绝** `plugin` / `pluginUser` / `pluginPasswd` /
`pluginHostHeaderRewrite` / `pluginStripPrefix`（允许清单，不继续扩黑名单）。

**复测**：三条路径全部 400，错误点名 `不允许携带插件相关字段（plugin）`。

---

### A-1 · token 模式下工作连接不校验 `privilege_key` ⇒ 隧道被劫持

**位置**：`server/src/serve.rs` 的 `handle_work`

**根因**：凭证复核被 `auth_method() == Oidc` 门住 ⇒ **token 模式（默认）下
`privilege_key` / `timestamp` 从头到尾没被读**，`run_id` 成了唯一门槛。
而 `run_id` 是在 v1 的 `LoginResp` 里**明文**下发的。
代码上方注释写着"这条挡的是：拿到 run_id 的人自己新建一条工作连接"
—— **注释描述的那道防线在默认模式下并不存在**。

**实弹（修复前）**：四种凭证形态（空 / 错误 / 垃圾 / `ts=-1`）**全部被接受**
并进入受害者的空闲工作连接池；随后用户流量被中继到攻击者连接
（完整 MITM，A 组独立复现 6/6 用户连接被劫持）。

★★ **修这个洞踩了一个大坑，值得记下来**：

第一版修法是"**所有**认证方式都要求凭证必须正确"。结果**破坏了与官方 frpc 的互通** ——
官方 `pkg/auth/token.go` 的 `SetNewWorkConn` 在未配
`additionalScopes = ["NewWorkConns"]` 时**直接 `return nil`，不放凭证**。
实测（`tmp/audit4-a1-diag.py`）：

```
DEBUG yamux stream 结束：工作连接凭证不符（privilege_key 不是本会话 token 派生的）
→ 官方 frpc 的 tcp 代理完全不通（用户连接超时）
```

而 README 明确承诺"官方客户端不需要改任何配置就能连上"，**不能这么修**。

**最终方案（既不破坏互通、又堵住劫持）**：新增能力位 `NfrpCaps::work_conn_cred`：

| 客户端 | 服务端的处理 |
|---|---|
| **声明了**该能力（NFrp ≥ 0.5.5 恒声明） | 工作连接**必须**带正确凭证，**空凭证也拒** |
| **没声明**（官方 frpc、老版 NFrp） | 退回"要求源 IP 与控制连接一致" |

★ 关键洞察：这个能力位是**受害者自己**在登录时声明的，**攻击者改不了**。
所以"拿 run_id 冒充"在这条路径上彻底断了 —— 而且**同 IP 也拦得住**
（本地实测四种伪造形态全拒，攻击者与受害者都是 127.0.0.1 也拦住了）。

**复测**：
- 官方 frpc 0.71.0 经本服务端 **转发成功**（互通保住，`tmp/audit4-interop-a1.py`）
- NFrp 客户端的四种伪造形态**全部被拒**（`tmp/audit4-verify-A2b.py`），
  日志分别是 `该会话声明了工作连接凭证能力，但本次工作连接未携带凭证`
  与 `工作连接凭证不符`
- 646 条测试全绿（含 18 条 e2e）

---

### D-02 · 面板写接口绕开 RBAC 的角色限制

**位置**：`server/src/admin.rs` 的 `add_proxy`

**根因**：`sec.check_proxy()`（角色的代理类型 / 端口范围 / maxProxies）
全仓**唯一**调用点在客户端发 `NewProxy` 的那条路上。面板路径只查了
`allow_manage` —— 那有用，但不是类型/端口/配额限制。

**实弹**（`tmp/audit4-verify-D2.py`，角色 `guest` 限 http / 30000-30010 / maxProxies=1）：
- 客户端路径发 `tcp:30005` → **被拒**（`角色 "guest" 不允许注册 tcp 类型代理`）✅
- 面板路径发 `tcp:12347/12348/12349`（范围外）→ **三条全部生效**

**修法**：`admin::add_proxy` 补 `sec.check_proxy()`（放在问客户端之前，
避免"客户端已认下、服务端却拒绝"的半成品状态）。

**复测**：三条全部 `面板下发被权限模型拒绝：角色 "guest" 不允许注册 tcp 类型代理`，
端口均未监听。2 条回归测试合格。

---

### C-1 · TE.TE 请求走私（H2 只修了 CL 侧）

**位置**：`common/src/http_relay.rs` 的 `is_chunked`

**根因**：用 `contains("chunked")` —— **只要串里出现就按 chunked 解帧**；
而 RFC 7230 §3.3.3 规定看**最后一个** token。转发时 `Transfer-Encoding`
又**原样**搬给上游 ⇒ 两边口径不一致。

**实弹**（`tmp/c6_desync_proof.py`，含对照/攻击/对照三段）：

| 报头 | 修复前 | 后端解析出 |
|---|---|---|
| `chunked`（对照） | 200 | 1 个请求 |
| **`chunked, identity`** | 200 | **2 个请求**（第 2 个是注入的） |
| **`xchunked`** | 200 | **2 个请求** |
| **`chunked, gzip`** | 200 | **2 个请求** |
| `identity, chunked`（对照） | 200 | 1 个请求 |

**修法**：新增 `transfer_encoding_tokens()` / `transfer_encoding_is_unsupported()`，
按 RFC 判定（末尾是 `chunked` 且前面只有 `identity`），其余一律 400。

**复测**：三种攻击全 400 且后端看到 **0 个请求**；**两个合法对照组仍 200**。

★ 修的过程中**第一版修过头了**：要求"恰好一个 chunked"，把 RFC 合法的
`identity, chunked` 也 400 了 —— **C 组的对照组脚本立刻把它暴露出来**。
已改成"末尾是 chunked 且前面只有 identity"。**这就是有对照组的价值。**

---

## 三、中危（5 项）

### B-1 · `visitors.remove` 只按名字（H1 的同一根因）

**位置**：`server/src/serve.rs`（`CloseProxy` 处理）、`server/src/visitor.rs`

紧邻的 vhost 那行已在 H1 修复里补上了客户端身份，**visitors 这一行漏了**。
客户端 A 发一条 `CloseProxy("{victim}.{name}")` 就能摘掉受害者 B 的
stcp/xtcp 注册记录 ⇒ B 的私密隧道对新 visitor 立即失效；而且
`register` 只在重名时失败，摘掉之后攻击者还能把自己的记录注册到那个名字上。

**修法**：`VisitorTable::remove` 带上 `client`，只允许摘自己的。
**复测**：3 条回归测试 + 元验证合格。

### G-1 / G-3 · v1 登录凭据：可离线爆破 + 无新鲜性 + 无限重放

**位置**：`common/src/security.rs` 的 `verify_login`

**实弹**：
- timestamp `0` / `-1` / `-2^40` / `i64::MAX` / `i64::MIN` / 未来 100 年 /
  过去 100 年 / **字段缺失** —— **全部登录成功**
- 同一条抓到的 Login 报文原样重发 3 次全部成功
- 空 token 时 `md5(""+ts)` 完全可预测 ⇒ 未持任何凭据拿到完整控制会话

★★ **必须诚实说明**：**官方 frp 的 `VerifyLogin` 也完全不做时间戳新鲜性校验**

```go
func (auth *TokenAuthSetterVerifier) VerifyLogin(m *msg.Login) error {
	if !util.ConstantTimeEqString(util.GetAuthKey(auth.token, m.Timestamp), m.PrivilegeKey) {
		return fmt.Errorf("token in login doesn't match token from configuration")
	}
	return nil
}
```

（源码：`pkg/auth/token.go`，本轮已核对。）**所以这是继承的协议设计，不是 NFrp 独有缺陷。**

**处理**：
- 加**窗口校验**会拒绝重放，但需要权衡"时钟偏差的客户端"——
  本轮**未改**，因为它会改变与官方 frpc 的行为契约；
- 已做的是 v0.5.4 的"空 token + 显式对外地址 ⇒ 拒绝启动"；
- **文档明说**：v1 的凭据强度**完全取决于 token 强度**，且凭据可无限期重放。
  跨公网部署请用强 token，并优先 v2 / OIDC。

### G-2 · OIDC 验签恒失败（SPKI / PKCS#1 格式不匹配）

**位置**：`common/src/auth/oidc.rs`

**根因**：`jwk_to_spki()` 构造的是 **SPKI**（外面套了
`AlgorithmIdentifier` + `BIT STRING`），而 `UnparsedPublicKey` 配
`RSA_PKCS1_2048_8192_SHA256` 要的是**裸 PKCS#1**。EC 同理要裸点。

**实弹**（真 RSA-2048 密钥 + 真签名，`tmp/audit4-verify-G2.py`）：

```
--- RSA_PKCS1_2048_8192_SHA256 ---
SPKI   (仓库原先给的格式): ring 拒绝 -> Unspecified
PKCS#1 (ring 期望的格式)  : 被 ring 接受（且签名有效）
```

**影响**：**OIDC 认证功能完全不可用**（RS256/384/512 全线）。

★ 它**偶然挡住**了 G-8 —— 修验签必须**同时**修 G-8，否则一修就变成
可利用的认证绕过。两者在同一个提交里。

**修法**：函数改名 `jwk_to_ring_key`（原名是误称），RSA 返回裸 PKCS#1、
EC 返回裸未压缩点；删掉只服务于 SPKI 的死代码。

**补上的关键测试**：8 条，含 **3 条"真签名必须验得过"的正向用例**
（RS256 / ES256 / ES384）—— 原先**只有"验不过要拒绝"的方向**，
所以这个 bug 一直没被发现（典型的"绿得不真实"）。

### G-8 · OIDC claims 校验 5 处缺口

**根因**：`payload.get("exp").and_then(|x| x.as_i64())` 把
**"字段不存在"**和**"类型不对"**都变成 `None` ⇒ 整个时间校验**静默跳过**。

| 用例 | 修复前 | 修复后 |
|---|---|---|
| 完全没有 `exp`（永不过期） | 接受 | **拒绝** |
| `exp` 是字符串 `"1"` | 接受 | **拒绝** |
| `exp` 是 `null` / 数组 / 布尔 | 接受 | **拒绝** |
| `nbf` 是字符串（未来时间） | 接受 | **拒绝** |

**修法**：区分"缺失"与"类型不对" —— `exp` 必填且必须是数值；
`nbf` 可选，但出现就必须是数值。

**测试**：5 条新用例（含"合法数值必须通过"的反向保护）。

### F2 / F3 · 面板能删 / 覆盖配置文件里的代理

**位置**：`client/src/registry.rs`（`ProxyTable`）、`client/src/main.rs`

**F2 实弹**（`tmp/f2_remove_config_proxy.py`）：配置里写着 `victim-ssh`
（占端口 18002），面板下发 remove →
`HTTP 200 代理 [victim-ssh] 已移除`，端口立刻连不上，
日志 `按服务端命令移除代理 proxy=victim-ssh total=0`。

**F3 实弹**（`tmp/f3b_rollback_kills_config_proxy.py`）—— 一个"双杀"：
1. 服务端下发同名 `add_proxy`（用户配置里已有 `my-web`）；
2. 客户端 `insert` **覆盖** ⇒ 用户那条此刻已经没了；
3. 服务端因端口冲突失败 ⇒ 回滚，下发 `remove_proxy("my-web")`；
4. 客户端按名删 ⇒ 删掉的是刚覆盖进去的那条，**用户配置永不恢复**。

⇒ 一条服务端**自己都判为失败**（HTTP 400 "已回滚"）的命令，
把用户的隧道永久打掉。

**修法**：`ProxyTable` 给每条代理记**来源标记**（`Config` / `Dynamic`），
远程下发的 `add` / `remove` **只允许操作 `Dynamic`**；覆盖/删除配置代理
明确拒绝并告诉调用方"请改本机配置文件"。store 恢复的算 `Dynamic`。

**顺带修正**：客户端本地界面的 `dynamic` 字段原先从 store 名字列表**间接推断**
（store 没配时恒为空 ⇒ 面板加的代理显示成非动态，用户以为删不掉），
现在直接问表里的来源标记 —— 与"面板能不能删它"用**同一份事实**。

**测试**：4 条新的（含 1 条把既有测试里**无意中断言了 F2 漏洞**的用例改正）。

---

## 四、低危（1 项）

### C-2 · `MAX_HEAD` 声称 64 KiB，实际可达约 80 KiB

**位置**：`common/src/http_relay.rs` 的 `read_head_raw`

**根因**：检查顺序是"**先找结束符、再查大小**"，于是找到结束符就直接返回、
尺寸检查根本没跑；又因为 `>` 是严格大于，`available == 65536` 恰好通过，
再 `fill()` 一次（每次最多 16 KiB）就到约 80 KiB。

**实弹**：C 组实测 **70048 字节的请求头被完整转发**。

**修法**：在**返回分支**里按实际头部长度判定（`end - self.pos > MAX_HEAD` ⇒ 报错），
并把"没找到结束符"那支改成 `>=`。

---

### 另外两项一并修了

**F4 · VNet 不校验源地址**（`server/src/vnet.rs` 的 `route()`）
原先**只读 `h.dst`，从不读 `h.src`**（全文件 `src` 只出现在一处测试断言里）。
成员 A 可以发出 `src = 其他成员` 甚至 `src = 网关` 的包，而 B 照收。
修法：`h.src` 必须属于发送者（`Switch::ips_of`），否则丢弃并计入
新增的 `dropped_spoofed` 指标 —— 那是"有人在冒充别人"的**唯一可观测信号**。
3 条回归测试 + 元验证合格。

**A-3 · 未认证 visitor 是 run_id 预言机**（`server/src/serve.rs` 的 `handle_visitor`）
三条不需要任何凭据的 visitor 连接返回三种**可区分**的错误文本，
其中"run_id 在不在线"是真正的预言机。
**定向修复**：那一条**无论如何都回通用文案**，不受 `detailed_errors_to_client`
影响 —— 因为 `run_id` 是服务端/客户端内部生成的，合法 visitor
从不需要这个细节，脱敏**不损失可用性**。
（另两条关于代理名的错误仍走那个开关：它默认 `true`、与官方一致，
且对**合法** visitor 排查自己的配置有用。要关掉枚举面可以设
`detailed_errors_to_client = false`。）

**G-7 · WebSocket 不校验掩码位**（`common/src/ws.rs`）
RFC 6455 §5.1 的两个 MUST 都没做：未掩码的**客户端**帧被照常处理
（实弹：发未掩码的 Login 帧，服务端照回 `LoginResp`）。
修法：`take_frame` 增加方向参数，两个方向都按 RFC 校验。

**A-5 · `clientRandom` 不做 base64 校验**（`common/src/frp/wire.rs`）
原先只查非空，`"!!!"` 也能通过协商。修法：校验是合法 base64
（标准/URL-safe、带不带填充都认）且解码后 ≥16 字节 ——
口径刻意宽松，不卡精确长度以免有互通风险。

---

## 五、确认"未能利用"的（有反证，非含糊结论）

| 面 | 结论 |
|---|---|
| H2 的 CL.CL 修复 | ✅ **彻底**（各路径逐条验过，重复/非数字/带符号 CL 全 400 且零转发） |
| H3 store 绕过 | ✅ **彻底**（`from_config` 与 `merge_initial` 两处都校验，未找到绕过） |
| H4 `local_addr` | ✅ 实现本身正确（域名/内网 IP 均被拒），**但同一能力可经 `plugin` 获得**（见 F1） |
| v2 AES-GCM nonce 重用 | 未能利用 |
| v1 AES-CFB IV 重用 | 未能利用 |
| `constant_time_eq` 时序 | 未能利用（实测失败路径 σ≈8ms，差异远低于噪声） |
| `run_id` 可预测 | 未能利用（16 字节 `OsRng`） |
| v2 → v1 降级 | 未能利用（但机制上有话可说） |
| CRLF 头注入 | 未能利用（`strip_crlf` 双重生效） |
| 客户端本地界面跨站 | 未能利用（Origin/防伪头/Basic Auth/重复 Origin/OPTIONS 全部拦住） |
| `health_check` 第二条 SSRF | **不成立**（探测目标就是 `local_addr`，且动态代理没有探测任务） |
| 解析层 fuzz | ~200 条语义定向用例 + 上轮 66 万次随机 fuzz，**零 panic / 零越界** |

---

## 六、记录在案、**建议不改**的（设计取舍 / 与官方一致）

| 编号 | 内容 | 为什么不改 |
|---|---|---|
| G-4 | TLS 中间人可完整剥穿（客户端不校验对端证书） | **与官方 frp 一致**。防被动偷看、不防中间人。正确做法是外层再套 TLS |
| G-5 | 工作连接全程明文 | 与官方一致，v1 协议本身的属性 |
| G-6 | KCP P2P 无认证无加密、口令明文 | P2P 直连的属性。**文档明确**而非改协议 |
| F8 | 服务端持有 `secret_key` 且自生成 `sid` ⇒ 能算 P2P 口令 | **设计性**：口令的两个输入服务端都知道 |
| G-9 | v1 的 KDF 弱（PBKDF2-SHA1 / 64 迭代 / 固定盐 `frp`） | **必须与官方一致**才能互通。只能靠强 token + 优先 v2/OIDC 缓解 |
| G-10 | `AeadReader` 无帧数计数 | **不建议改**：读方向 nonce 由对端定，本地计数器无安全意义 |
| G-11 | 自签证书有效期 2121 年 / SAN 恒为 `frp` | 客户端本来就不校验，无实际影响 |
| A-2 | v2 跳过 ClientHello 直接 Login | 实测**不构成越权**（该 run_id 从未进 registry） |
| A-6 | 未认证 KCP 24 字节即建会话 | 实测 20 秒回收，无泄漏 |
| G-1/G-3 | v1 凭据可重放、空 token 即匿名 | **官方同款行为**（已核对源码），改了就破坏互通 ⇒ 只做文档与启动告警 |

### 一条必须写进文档的兼容性约束

**G-4 / G-5 / G-6 / G-9 / F8 / G-1 都不能靠改代码修** —— 它们要么是官方协议的一部分
（改了破坏互通），要么是产品定位使然。正确做法是在 README 与启动日志里**明确说清**：

- 跨公网传敏感数据 ⇒ 必须在外层加 TLS（或改用 v2 + OIDC）
- 服务端必须可信 ⇒ xtcp 的"数据不经服务端"**不包含**"防服务端"
- token 必须足够强 ⇒ v1 的凭据强度**完全取决于** token，且凭据可无限期重放
- 多租户隔离要靠 `[[roles]]` ⇒ 未配 RBAC 时 `user` 只是**自报标签**，不是身份

---

## 七、元验证记录（本轮的做法）

**每一项修复都做了"退回缺陷 ⇒ 对应测试必须变红"**。

| 修复项 | 元验证方式 | 结果 |
|---|---|---|
| H1 | `tmp/verify_h1_r4_test.py` | ✅ 2 条测试变红 |
| F1 | `tmp/verify_f1_test.py` | ✅ 2 条测试变红 |
| B-1 / F2 / F3 / F4 / G-7 / A-5 | `tmp/verify_round4_meta.py` | ✅ 6/6 全部变红 |
| G-2 / G-8 | `tmp/verify_oidc_meta.py` | ✅ 3/3 全部变红 |
| A-1 | 端到端实弹（四种伪造形态全拒 + 官方 frpc 转发成功） | ✅ |
| D-02 | 端到端实弹（三条越权下发全被权限模型拒绝） | ✅ |
| C-1 | 端到端实弹（三种攻击全 400、两个合法对照仍 200） | ✅ |

★ **G-2 的元验证第一版是"假合格"**：我把退回版写成了
"给 PKCS#1 起个变量名再返回"——**与修复版完全一样**，于是测试当然全绿。
发现后改成真正构造 SPKI，才正确变红。**这是元验证脚本自身的 bug，
不是覆盖不足** —— 说明"元验证也要被审视"。

---

## 八、本轮的三次自我纠错（方法论记录）

1. **F1 探针**：第一版把 `proxy` 参数**发平了**（面板要 `{"run_id":..,"proxy":{..}}`），
   被面板以"缺少 run_id"挡在门口 ⇒ 我一度打印"未复现"。修正后立刻复现。
2. **A-1 探针**：第一版用了**假 `run_id`**，服务端在 `handle_work` 第一行就
   正确拒绝了 —— 那是**正确行为**。换成真 `run_id` 后立刻复现。
3. **C-1 修得过头**：第一版要求"恰好一个 chunked"，把 RFC 合法的
   `identity, chunked` 也 400 了 —— **C 组的对照组脚本立刻把它暴露出来**。

⇒ 规矩：**探针返回"被拒"时，必须先确认它真的走到了被检查的那一行**
（看服务端日志 / 加诊断输出），再下"未复现"的结论。
**探针失败 ≠ 漏洞不存在。**

★ 另外本轮第 4 次自我纠错：**A-1 的第一版修复破坏了官方互通** ——
如果不是我主动做互通实测（而不是只看单元测试绿），这个回归会随版本发出去。
**教训：改了协议相关的东西，必须跑真实官方二进制。**

---

## 九、附：本轮分工与产出

| 分组 | 范围 | 产出 |
|---|---|---|
| A | 协议解析与内存安全 | 报告交付（716 行），6 条发现；解析层零收获（有数据） |
| B | 多租户隔离 | 中途阵亡，留 12 个实弹脚本；`visitors.remove` 线索由我复核确认并修复 |
| C | HTTP/vhost 与走私 | 中途阵亡；**TE.TE 走私已实弹证成**（含对照/攻击/对照），另有 `MAX_HEAD` 线索 |
| D | 认证与授权 | 中途阵亡；2 条高危已复核（D-02 已修），时序侧信道已排除 |
| E | 资源耗尽与 DoS | **无产出（该面本轮未覆盖，建议下轮补）** |
| F | 服务端→客户端 & SSRF | 报告交付（786 行），5 条实弹发现 |
| G | 密码学与降级 | 报告交付（976 行），11 条发现 + 5 类排除 |

**特别记一笔**：A 组主动**反驳了自己**的"A-2 + A-1 = 无凭据攻击链"升级路径
（实测 A-2 的 `run_id` 从未进 registry），并**记录更正了一个假阳性**
（一度以为能打崩服务端，严格隔离后确认是自己的脚手架竞态）。
这种自我纠错正是本轮要的。

---

## 十、未覆盖 / 建议下轮补做

- **E 组（资源耗尽与 DoS）完全未产出** —— 慢速攻击的超时矩阵、
  UDP 放大、指标标签爆炸、配额逃逸都需要补做。
- **B 组未完成的部分** —— group 负载均衡的 `group_key` 复核（第三轮 H5 的加固）、
  visitor 跨用户、控制命令越权。
- **C 组未完成的部分** —— tcpmux CONNECT 滥用、SNI 混淆、响应拆分、
  PROXY protocol 注入。
- **D 组未完成的部分** —— ACL/CIDR 边界（IPv4-mapped IPv6 绕过）、面板鉴权矩阵。
- **P2P / xtcp** —— F8 那份"服务端持有 secret_key"的设计性问题值得单独设计一轮。


<!-- ===== 3/14 第 5 轮 ===== -->

> **日期：2026-10-15** · **轮次：第 5 轮**

---

# NFrp 安全修复报告 · 第五轮（v0.5.6）

日期 2026-10-15
范围 全仓（common / server / client 三个 crate、配置解析、UDP/TLS 传输、打包链路）
来源 `<桌面>`（外部审计，三轮共 39 条）
状态 **39 条全部处理完毕**（4 高危 / 16 中危 / 19 低危）——
**32 条代码修复**、**1 条评估后明确不采纳**（L17，见第五节）、**6 条经核实为设计取舍或已正确处理**
基线 v0.5.5 · 本版 v0.5.6

质量门

| 项 | 结果 |
|---|---|
| 测试 | **699 通过 0 失败**（v0.5.5 是 646，本版 +53） |
| `cargo fmt --check` | 干净（exit 0） |
| `cargo clippy -D warnings` | **0 告警** |
| `cargo audit` | **exit 0 零漏洞** |
| 元验证 | **12 项函数体退回全部合格** + 4 项用端到端/对照实验另证 |
| 端到端冒烟 | **18 / 18** |
| 官方 frpc 互通 | **实测通过**（0.71.0，全部改动生效后复测） |

---

## 一、五轮的位置

| 轮次 | 版本 | 问的问题 | 结果 |
|---|---|---|---|
| 第一轮 | v0.5.2 | 全仓扫一遍，有没有漏洞？ | 17 项 |
| 第二轮 | v0.5.3 | 上一轮新写的防线能不能被绕过？ | 11 项 |
| 第三轮 | v0.5.4 | 外部审计报告逐项复核 | 24 项 |
| 第四轮 | v0.5.5 | 按漏洞类别并行深挖 + 每个发现必须打出真实利用 | 11 项 |
| **第五轮** | **v0.5.6** | **外部审计第二轮（39 条）逐项核实 + 修复** | **39 项** |

**累计修复 102 项。**

★★ **同一模式第五次出现**：

> **防线写对了，但没有铺满它自己声称保护的所有字段 / 路径 / 校验点。**

本轮 39 条里，**20 条**属于这个模式（审计报告自己也统计出了这个数并列为头号根因）。
它已经连续五轮出现，所以本版除了逐条修，还**把几组"同一判定散在多处"收敛成了唯一函数**：

| 新抽出的唯一真源 | 原先散在 |
|---|---|
| `has_dashboard_creds()` | 面板凭据判定（**5 处**，审计只找到 4 处） |
| `is_visitor_type()` | 访客类代理类型集合（4 处） |
| `has_no_auth()` | "有没有认证"（2 处，两套口径） |
| `canonical_wire_name()` | 线上全名拼装（2 处，一处漏 strip） |
| `validate_request_framing()` | 请求 framing 校验（服务端有、客户端无） |
| `strip_hop_by_hop()` | 逐跳头剥离（同上，客户端只处理 1 个头） |
| `to_metric_u64()` | u64→i64 计数转换（16 处） |
| `http1::MAX_HEAD` | 头长度上限（2 处取值不同） |

---

## 二、高危（4 条）—— 全部实弹/实证

### H1 · 「有用户名 + 空密码」通过全部校验

**根因**：面板鉴权判定**只判用户名、从不判密码**，而鉴权处把两者拼成
`"user:pwd"` 去比 Basic 头 ⇒ 密码为空时期望值是 `"admin:"`，
**攻击者随手可构造** ⇒ 鉴权退化成"知道用户名就能进"。

**攻击链（热重载那处是攻击者主动可触发，最危险）**：

```toml
# ① 正常运行（安全）
dashboard_user = "admin"; dashboard_pwd = "s3cret"

# ② 攻击者热重载，只清空密码
dashboard_pwd = ""          # 用户名保持 "admin"
```
判据 `clears_creds = "admin".is_empty()` = **false** ⇒ 闸门不拦
⇒ `auth = Some(("admin", ""))` ⇒ 匿名者用 `admin:` 进面板拿到**全部写权限**
（开公网端口、踢人、读全平台）。

**审计列了 4 处，我实测发现第 5 处**：`serve.rs` 里 `DashboardAuth` 的初始化
（`if cfg.dashboard_user.is_empty()`）。审计报告漏列了它。

**修法（五处共用唯一真源）**：

```rust
pub fn has_dashboard_creds(user: &str, pwd: &str) -> bool {
    !user.trim().is_empty() && !pwd.is_empty()
}
```

| 位置 | 用途 |
|---|---|
| `reload.rs` 的 `clears_creds` | 热重载闸门 |
| `reload.rs` 的 `dashboard_is_exposed` | 暴露判定 |
| `server/main.rs` 启动校验 | 拒绝启动 |
| `client/main.rs` 的 `check_web_server_is_safe` | 客户端界面拒绝启动 |
| **`serve.rs` 的 `DashboardAuth` 初始化** | **审计漏列的第 5 处** |

外加**鉴权侧纵深防御**（`dashboard.rs`）：用户名非空但密码为空时，
`expected` 直接视为 `None` ⇒ 走拒绝分支。理由：`serve_with` 可被别的宿主
直接调用，鉴权点是"最后一米"，不能假设上游永远拦住了。

★ **为什么既有测试全绿也没暴露**：原有 H1 回归测试用的是
`c.user.clear(); c.pwd.clear();`（**同时清两个**）—— 恰好绕过了"只清密码"
这种组合，**而那正是攻击者实际会用的手法**。
判据只认 user、测试也只喂 user，两者互相印证形成**闭环盲区**。

**回归测试**：`热重载只清空密码不得降级鉴权`、`热重载只清空用户名同样被拦`、
`对外面板判定的口径`（补"只有用户名不算有凭据"）、`回环上清空凭据仍然允许`（反向）。

---

### H2 · 热重载靠打开逃生开关绕过闸门

**根因**：`dashboard_exposed_after_reload` 只把 `bind_addr` / `dashboard_port`
取运行期（live）值，而 `allow_insecure_dashboard` **取的是新配置**——
但那个字段**只在启动期被读**（`serve.rs` bind 前兜底检查），运行期改它**不生效**。

**攻击链**：

```toml
# 热重载时同时写：
dashboard_user = ""              # 清空凭据 —— 闸门本该拦这里
allow_insecure_dashboard = true  # ← 让闸门判据失效（取 new = true）
```
判据看到 `!allow_insecure_dashboard` 为 false ⇒ 返回"没暴露" ⇒ 闸门放行
⇒ 鉴权被清空 ⇒ `0.0.0.0:7500` 面板**匿名可读写**。
而那个开关**当次并没真的生效** ⇒ 攻击者既绕过闸门、又没留下开关被打开的痕迹。

★ **与原代码注释直接矛盾**：注释把 `allow_insecure_dashboard` 归为
"真正的可热改字段"，并把它与 `dashboard_user`/`dashboard_pwd` 并列。
**代码错了，注释也错了，两边错得一致** —— 所以读代码时看不出来。

★ **反向印证**：`allow_insecure_no_auth`（另一个逃生开关）**绕不过去** ——
因为它的触发字段 `token` 需要重启、不可热改。
两者唯一的区别就是"触发条件能不能在运行期改"。

**修法**：抽 `live_view()`，凡"需重启"字段一律取 live；
并加**不变量测试** `判据用到的不可热改字段必须取运行期值` ——
将来有人新增"需重启"字段却忘了同步，测试会红。

**回归测试**：`热重载不得靠打开逃生开关绕过闸门`。

---

### H3 · RBAC `allowVisitors` 漏判 `sudp`

**根因**：判据是就地硬编码的 `matches!(ty, "stcp" | "xtcp")` —— **漏了 `sudp`**。
而项目自己在**三处**都把 `sudp` 定义为访客类：

| 位置 | 定义 |
|---|---|
| `config.rs` 的 `SUPPORTED_VISITOR_TYPES` | `["stcp","xtcp","sudp"]` |
| `frp_legacy.rs` 的 `LEGACY_VISITOR_TYPES` | `["stcp","xtcp","sudp"]` |
| `serve.rs` 的注册分派 | `"sudp" => register_visitor_proxy(...)` |

**唯独 RBAC 这一处漏了。**

★ **危害被放大**：`sudp` **不占公网端口**，因此不受 `allowPorts` / `portRange`
约束（端口检查只对 `tcp|udp` 生效）⇒ **`allowVisitors` 是管理员唯一能关掉
访客类代理的开关**，而它恰恰漏了 `sudp`。

**修法**：抽 `is_visitor_type()` 唯一真源。

**回归测试**：`allow_visitors_必须覆盖全部访客类型`（三种类型逐一验 +
大小写不敏感 + 非访客类型仍放行）、`访客类型唯一真源与支持清单一致`。

---

### H4 · 面板 `table()` 未转义 → 存储型 XSS

**根因**：`table()` 直接 `<td>${c}</td>` 插值，而单元格里装着**攻击者可控**的字符串。

**攻击链**：低权限客户端注册一个名字为 `<img src=x onerror=...>` 的代理
⇒ 管理员一打开面板，脚本就在**管理员会话**里执行
⇒ 越权调用 `/api/*`（踢人、增删代理、开公网端口）。

数据来源全部可控（`/api/status`）：`clients[].client_id` / `user` /
`proxies[]`（代理名）、`visitors[].proxy_name` / `type` / `provider_user` /
`allow_users`。

★ **`esc()` 本来就存在、也在同一文件里被正确用过**（`c.run_id`、下拉框每个字段）
—— **唯独 `table()` 这条路径漏了**。客户端 `web.rs` 的实现一直是对的
（`card()` 内部自己转义），是现成的正确模板。

**修法**：`table()` 默认走 `cell()`（内部 `esc()`），需要嵌 HTML 的用
`raw()` **显式**标记（只有"踢出"按钮一处）；`card()` 也一并转义。

**回归测试**：`面板表格必须转义单元格`（断言接线 + 反向断言不得残留裸插值）。

---

## 三、中危（16 条）

### M1 · 跨租户靠 `route_by_http_user` 寄生域名路由

**根因**：冲突判据是 `duplicate && same_scope`，而 `same_scope` 只比
`route_by_http_user` 字符串。该字段**完全由客户端自报、注册时全仓无校验**。

**攻击链**：受害者注册 `web.test` + `/`（无 `routeByHTTPUser`）→
攻击者注册**同样域名与路径**但带 `routeByHTTPUser="alice"` →
`same_scope=false` ⇒ 冲突检查跳过 ⇒ 攻击者路由入表且**返回注册成功、无告警**
⇒ 之后**带 `Authorization: Basic alice:...` 的访客请求**在第 1 轮匹配
命中攻击者路由 ⇒ 流量与**凭据一起被收割**。

★★ **审计报告给的修法是错的，我没有照抄。**

报告建议 `same_scope = same_owner(...) && (作用域相等)`。我实测核对后发现：

- 跨租户攻击时 `same_owner` **本来就是 false**，改完 `same_scope` 仍是 false
  ⇒ 结论**完全不变** ⇒ **对攻击无效**；
- 反而在"跨租户 + 作用域**相同**"时，把原本生效的冲突检查**关掉**了
  ⇒ **新开一个洞**。

**正确判据（自行推导 + 加测试盯住那个错误修法）**：

```
同租户 + 作用域不同 → 共存（自己的二级路由，官方 tcpmux 拓扑）
同租户 + 作用域相同 → 冲突
跨租户              → 一律冲突        ← 关键
```

**有意的行为收紧**：跨租户共用域名+路径靠 `routeByHTTPUser` 区分，从本版起
不再允许（服务端分辨不出"合法多作用域"与"寄生劫持"，而后者能直接收割凭据）。
同租户的多作用域拓扑**不受影响**。

**回归测试**：`跨租户不得靠_route_by_http_user_寄生`、
`跨租户同作用域必须冲突`（专门盯报告那个错误修法）、
`route_by_http_user_filters_candidates`（改用共享 client，反映真实拓扑）、
`tcpmux_兜底路由不能盖掉精确用户名路由`（同上）。

★ **方法论收获**：第四轮 H1 的系统性排查按**"操作类型"**搜索
（所有"按名字摘/删/注销"的地方都修了），而这一处是**"判定类型"**
（对归属作出结论的布尔表达式）。
⇒ **排查不能只按"操作类型"搜，还要按"判定类型"搜。**

---

### M2 · 客户端 `plugin_bridge` 缺失服务端已有的多层防护

**根因**：同一语义写了两遍、只加固了一遍。

| 面 | 服务端 `vhost.rs` | 客户端 `plugin_bridge.rs`（原状） |
|---|---|---|
| 请求 framing 校验（TE+CL / 重复 CL / 不支持 TE） | 全有 | **一项都没有** |
| 响应侧剥逐跳头 | `HOP_BY_HOP + connection_tokens` 全量 | **只处理 `connection` 一个头** |

**实测泄漏**：内网服务回 `Connection: keep-alive, x-secret` + `x-secret`
+ `upgrade` + `keep-alive`，服务端全部吸收，而客户端把 `x-secret`
（内部令牌）等**原样泄漏给公网访客**。

**修法**：抽 `validate_request_framing()` / `strip_hop_by_hop()` 两个公共函数，
服务端与客户端共用。

★ **可利用性前提如实说明**：服务端不解析 plugin 路径的 HTTP（plugin 走 TCP 透传），
所以要触发得**本机用户主动**配 `plugin = "http_proxy"` 之类
（v0.5.5 的 F1 修复已禁止服务端远程下发 plugin）。定级因此是 Medium 而非 High。

**回归测试**：`客户端插件路径必须做请求_framing_校验`、
`客户端响应侧必须剥掉全部逐跳头`。

---

### M3 · 登录凭证可无限期重放

**根因**：v1 凭证是 `md5(token + timestamp)`，服务端**只用报文自报的 ts
重算比对、不做新鲜性校验**；而 `Login` 在**加密建立之前明文发送**。
⇒ 嗅探到一条 Login 即可**原样重放**拿到完整会话。

**实测（修复前，审计报告给的）**：`ts = 0 / -1 / -2^40 / i64::MAX / i64::MIN`、
未来 100 年、过去 100 年 —— **全部登录成功**。

★★ **这推翻了我在第四轮下的结论。** 当时判"v1 时间戳是协议层面的，
没有补救空间"。这轮想清楚了：

> **不改线协议格式 ≠ 不能加强安全语义。**

加时间窗口**零协议改动**：官方 frpc 的 `Login.Timestamp` 就是发报文时的
unix 时间，宽窗口下**零感知**。

**修法**：`check_timestamp(ts, skew)`，默认 **±300 秒**
（`maxClockSkewSecs`，0 = 关闭，给时钟严重不准的嵌入式设备留逃生口）。
用 `saturating_sub/saturating_abs` 避免 `i64::MIN` 溢出。

★ **诚实边界**：这**不是**完整防重放（窗口内仍可重放）。完整的做法要维护
"已用过的 (run_id, ts)" 集合，引入一张会增长的表 + 过期清理 ——
对登录这种低频事件收益不划算。窗口把攻击面从"永久"压到"5 分钟"，
且**零互通代价**。

**回归测试**：3 条（函数级）+ **2 条调用点 e2e**
（`login_with_stale_timestamp_is_rejected` / `login_within_clock_skew_is_accepted`）。

★ 加调用点测试的原因：函数级单测**测不到调用被删** ——
若 `conn.rs` 里那处调用没了，函数级测试仍然全绿，而真正的防线就在那处调用上。

---

### M4 · INI 大小写敏感 → 安全键静默失效

**根因**：INI 解析严格区分大小写，而官方 frp 用 `go-ini`，对段名与键名
都做 `strings.ToLower`。

**后果是静默失效**（不是报错）：`authentication_method` / `privilege_token` /
`tls_enable` 这些**安全键**写错大小写时取值返回 `None` ⇒ 落到默认值
⇒ **安全配置静默失效，而配置看起来"配了"**。

这与 TOML 路径的 `deny_unknown_fields`（拼错就报错）形成鲜明对比 ——
INI 路径既大小写敏感、又不报未知键，**两个特性叠加成了"静默失效"的温床**。

**修法**：段名与键名统一小写（**修正为与官方一致**）。

★ **顺带发现一处连带影响**：`sec.name == "DEFAULT"` 那处跳过判断必须改成
`"default"`，否则段前的裸键会被**当成一个代理**去加载。
（这正是"改了 A 忘了 B"的模式，改动时主动搜了所有段名引用。）

★ **一条既有测试的预期本身不符官方行为**：`SAKURA_INI` 里写的是 `[MCCC]`，
原测试断言代理名是 `"MCCC"`；而官方 `go-ini` 的 `SectionStrings()` 返回小写名、
官方 `Name: name` 也得到 `mccc` ⇒ 同一份配置在两个实现里产生**不同代理名**。
改后两边一致。

**回归测试**：`ini_的段名与键名必须大小写不敏感`（键名 4 种变体 + 段名 3 种
+ 安全键 + 反向验裸键不产代理 + 一份"大小写混写"的完整配置端到端可用）。

---

### M5 · 面板 `remove_proxy` 前缀叠加 → 资源泄漏

**根因**：面板传进来的是**线上全名**（带 `{user}.` 前缀，因为从 `/api/status`
读出来），而 `admin.rs` 直接 `add_user_prefix(&client.user, name)`
⇒ 得到 **`"alice.alice.web"`**。

**后果（逐条可观测）**：
- `stop_proxy("alice.alice.web")` → `None` ⇒ **端口不归还、域名不释放**
  ⇒ 持续泄漏，可反复触发形成**跨租户 DoS**；
- 但**客户端侧**用的是原始名 ⇒ 客户端**真的删成功了** ⇒ 返回文案"已移除"
  与真实状态不符（最难排查的那种不一致）。

★ 服务端直连那条路径**一直是** `add_user_prefix(user, strip_user_prefix(...))`
的幂等写法 —— **面板这条路漏了那半截**。

**修法**：抽 `canonical_wire_name()` 让两处共用。

---

### M6 · 认证判据分裂

| 位置 | 口径 |
|---|---|
| `guard.rs` | `auth.method() == Token && effective_auth().token.is_empty()` |
| `main.rs` | `cfg.token.is_empty()` —— **只看顶层字段，且不看 method** |

**后果**：**纯 OIDC 部署**（`method = "oidc"` + `issuer`，**不配 token ——
这是完全正确的配置**）下 `cfg.token` 为空 ⇒ 打出
"未配置 token 且正在监听对外地址 —— **任何人**都能连上来注册代理"。
**而事实是 OIDC 认证已正确启用，告警与事实完全相反。**

★ 二级危害：这类"狼来了"告警会训练管理员忽略同类告警，
或者为了"消掉告警"随手塞一个多余 token —— **后者会改变认证语义**。

★ **审计报告的定位偏了**：它说 `guard.rs` 会误报。但 `guard.rs` 检查了
`method`、本来就是对的；真正误报的是 `main.rs`。我按实际情况修了两处。

**修法**：抽 `ServerConfig::has_no_auth()`，两处共用（走 `effective_auth()`
的字段合并语义）。

**回归测试**：`纯_oidc_部署不算没有认证`、`判据必须走_effective_auth_的字段合并`。

---

### M7 · `conns_active` 计数错误（审计列了四处）

| 位置 | 问题 |
|---|---|
| `admit_user` + `handle_work` | **重复 inc**（用户先到 + 工作后到 ⇒ +2 只 -1） |
| `CloseProxy` 分支 | 无条件 dec（对不存在的名字也减）—— 即 M8 |
| `bridge` 里两处 `?` | 提前返回**漏 dec** |
| `sudp_bridge` 里两处 `?` | 同上 |

**攻击**：持合法凭证反复"建连接 → 立刻断开"，让 `conns_active` **单调上涨**
（指标不可信，削弱管理员发现异常的能力；**不构成配额绕过**，配额走信号量）。

★ **关键洞察：这四处不是四个 bug，是同一个 bug 的四个表现** ——
"配对的 +1 与结束的 -1 分散在两处，中间任何提前返回都会漏掉 -1"。
手工在每个返回点补 `dec()` 只会把"四处"变成"更多处"，下次加一个 `?` 又漏。

**修法**：**RAII 守卫**（审计报告的建议，这条是对的）——
用 `Drop` 把 -1 绑到作用域上，物理上不可能漏。

**回归测试**：`连接守卫必须收支平衡`、`提前返回也要归还计数`（M7 的核心）、
`守卫要记账流量`。

---

### M8 · `proxies_active` 无条件 dec

客户端反复发 `CloseProxy`（名字拼错/重复/别人的），`stop_proxy` 返回 `None`
⇒ 什么都没清理，gauge 却已减 1 ⇒ 变成负数并持续走低，
面板显示"生效代理 -37"。

**修法**：改成"确实摘掉了才减"，与 `admin.rs` 那条对齐。

---

### M9 · URL 不拒控制字符

**根因**：`Url::parse` 的 path **原样保留**，而它随后被直接拼进请求报文
⇒ URL 里的 `\r\n` 会**注入任意请求头、甚至切出第二个请求**。

**实测（审计报告给的 PoC）**：
`http://idp.example.com/a HTTP/1.1\r\nX-Injected: 1\r\n\r\nGET /b`
⇒ CRLF 原样存活。

★ **危害的诚实定位（不夸大）**：`issuer` 来自**本地配置**，不是攻击者直接输入；
要利用得先控制/劫持 IdP（`discovery` 里的 `jwks_uri` 会被原样信任）。
所以它**不是**"未认证攻击者直达内网"，而是"远端可控输入缺少校验"；
也**不构成经典请求走私**（这是对 IdP 的单向 GET、固定 `Connection: close`）。

★ 但仍然修了：这一层是**通用 URL 解析器**，将来接别的调用方时不该继承这个坑。

**修法**：① `httpc` 解析前拒所有控制字符（含 DEL）；
② **纵深防御**：OIDC 取到 `jwks_uri` 后要求必须 `https://`
（新增 `allowInsecureIssuer` 逃生开关给本地开发用）。

**回归测试**：`url_必须拒绝控制字符`（含报告原始 PoC + 5 种控制字符 +
反向验 3 种正常 URL 不被误拒）。

---

### M10 · KCP 接收侧无消息大小上限

**根因**：**发送侧有上限、接收侧没有** —— 又一处"只加固了一半"。
`rcv_queue` 段数受 `rcv_wnd(128)` 约束、单段受实际 UDP 数据报约束（≈65507）
⇒ 单会话累计 ≈ **8 MB**，`Vec::with_capacity` 再复制一份 ⇒ 峰值约 2×。
而 `KcpListener::accept` 对**任意源地址**无条件建会话。

★ **为什么是 Medium 而非 High（同意审计报告的下调）**：
① **1:1 占用，非放大**（装的是实际收到的数据）；
② **KCP 默认不启用**（需显式配 `kcpBindPort`）。

**修法（两层）**：① `decode_segs` 拒绝 `len > MTU`（挡巨段）；
② `recv()` 拼接超 64 KiB 时清空队列并丢弃（挡"很多正常段拼成巨消息"）。

**回归测试**：3 条（解码层拒超 MTU / 拼接超限清空 / 正常消息仍收得到）。

---

### M11 · `rustls 0.23.45` 的 4 个 RUSTSEC 漏洞

`cargo update -p rustls --precise 0.23.46` —— **零代码改动**，
`cargo audit` **exit 0**。

★ 关于 RUSTSEC-2026-0346（`Debug` 暴露 TLS 会话密钥）的可达性：
需 `Debug` 打印 TLS 会话对象才可触发。**已全项目检索确认当前不可达**
（无 `tracing::debug!` 打印会话对象）。仍升级。

---

### M12 · `store.rs` Windows 分支落盘无权限收紧

**根因**：Unix 分支显式 `mode(0o600)`，Windows 分支只是 `create_new`，
注释说"靠父目录 ACL"—— **这个假设不成立**：文件默认继承父目录的继承 ACE，
而用户目录（`C:\Users\X`）的 ACL 里含 `Users`（所有本地用户）与
`Authenticated Users` ⇒ 同机**任何其他用户**都能读走这份
`secret_key` / 插件密码 / `http_pwd`。

**修法**：`icacls /inheritance:r /grant:r "<user>:F"` 把继承断开、只留当前用户。
失败**不阻断落盘**（落盘是功能、收紧是加固），但 warn。

★ 为什么用 `icacls` 而不是 `SetSecurityInfo`：后者要引 `windows-sys`
并手写 ACL 结构（几十行 unsafe），而 `icacls` 是每台 Windows 都有的系统命令、
语义明确、失败可见。这是**低频**操作（只在 store 变化时落盘），开销可忽略。

---

### M13 · `api_v2` 读接口无租户边界

**根因**：`/clients`、`/proxies`、`/visitors`、`/audit` 在不传 `user` 时
**返回全平台数据**，而 `run_id` / 代理名正是写接口
（`POST /clients/kick`、`/proxies/remove`）的**主键**
⇒ **读接口直接喂出了写接口所需的全部标识**。

★ **影响（诚实定位）**：写接口仍受 `allow_manage`（RBAC）拦截
⇒ **配了 `[[roles]]` 的部署下不构成越权**；但**默认配置（无 roles）**下
`role_for` 对任何用户返回 `unrestricted` ⇒ **面板凭据即全平台管理权**。
另需明确：`api_v2` 挂在面板之下、**需要面板 Basic 凭据**，
所以这不是"匿名可达"，而是"面板凭据的权限边界比使用者以为的更宽"。

**修法**：全量枚举必须显式 `?all=1`（或给任一过滤条件）。
`/status`、`/version`、`/ports` 只回聚合计数、不含租户标识 ⇒ **豁免**。

★ **修法的局限如实说明**：这**不能阻止**持有面板凭据的人枚举，
但能让"全量导出"成为**有意识的选择**而非默认行为，
并在日志里可见。根本解法是给面板引入**只读角色** ——
那是一次接口与配置扩展，不在本轮范围。

**回归测试**：`读接口不得默认全量枚举`、`all_参数的取值容错`。

---

### M14 · 工作连接回退分支零审计

**根因**：三条**拒绝**路径全都记了审计事件，唯独**真正放行**的
"无凭证 + 同源 IP"这条**什么都没记**。

★ **为什么这条特别值得记**：它正是 A-1 修复的**兼容回退**分支，
也是**最弱**的一条认证路径 —— 只靠源 IP 判断。
攻击者若与受害者在同一出口 IP（同 NAT、同办公网、云上同 VPC），
这里就是唯一还能拦住他的地方，而它**原本在日志里完全不可见**。
事后审计时，"哪些工作连接是靠最弱判据放行的"必须可回答。

**修法**：放行分支也记审计（用 `detail` 而不新增事件类型，避免打乱下游解析器）。

---

### M15 · `work_conn_idle_timeout` 只有下界、无上界

原先只有 `.max(5)`（挡 0），**没有上界** ⇒ 配一个极大值就让空闲工作连接
**永不回收**，`idle_work_conns` 持续累积、fd/内存缓慢增长，
且它**不由攻击流量触发**，运维很难把它和配置项联系起来。

**修法**：`clamp(5, 3600)`，超范围打 warn。

---

### M16 · `UdpAddr::key()` 的 IPv6 歧义

**根因**：`format!("{}:{}", ip, port)` —— IPv6 地址**自身就含冒号** ⇒ 表示不唯一。

| 地址 | 拼接结果 |
|---|---|
| `::1` + 8080 | `::1:8080` |
| `::1:8080` + 0 | `::1:8080` ← **撞了** |

**两个后果**：**会话串访客**（不同 (ip,port) 得到同一 key ⇒ UDP 响应写回错误对端）；
**会话爆炸**（同一对端多种表示 ⇒ 每个建独立 socket，绕过 `max_conns` 计数）。

**修法**：IPv6 一律加方括号（RFC 3986 写法）并带 zone。
**IPv4 保持原样** —— 它本就无歧义，且不改才能与既有 map 语义、
以及官方 frp 的 v4 行为完全一致。

**回归测试**：`udp_addr_key_不得有_ipv6_歧义`、`udp_addr_ipv6_往返一致`。

---

## 四、低危（19 条）

| # | 内容 | 处理 |
|---|---|---|
| L1 | `VisitorConfig::bind_addr` 默认值三处两个答案 | **修**：抽 `default_visitor_bind_addr()` = `127.0.0.1`（与 INI 路径、官方示例一致）+ 非回环监听告警 |
| L2 | 端口冲突检查漏 `kcp_bind_port` / `vnet_port` | **修**：用同一个循环处理三个 UDP 口，避免下次再加又漏 |
| L3 | `allowPorts` 为空时静默 | **修**：补 `else` 告警（只 warn 不拒绝，否则出厂配置起不来） |
| L4 | 控制通道明文零告警 | **修**：补 warn（不拒绝，否则破坏官方互通） |
| L5 | 混合传输下"同源 IP"可能误拒 | **修**：不放宽判据（放宽等于让"拿 run_id 冒充"重新变容易），但补足诊断 —— 把"多网卡/NAT 池/TCP vs QUIC 出口不同"和"升级客户端可改用凭证校验"说清楚 |
| L6 | 插件黑名单漏 `plugin_request_headers` | **修**：补上。★ 注释写着"用允许清单、不继续扩黑名单"，代码却是 5 字段枚举 —— **注释与实现不符**这一高效信号源的又一例 |
| L7 | 最高危修复 A-1 仓库内**零回归测试** | **修**：补 3 条 e2e（见下） |
| L8 | `MAX_HEAD` 两处取值不同（32K vs 64K） | **修**：统一到 `http_relay::MAX_HEAD` + 不变量测试 |
| L9 | `Login` 携带凭证却 `derive(Debug)` | **修**：手工 `Debug`，`privilege_key` 打码（同类坑第三处） |
| L10 | OIDC JWKS 永不刷新 + 注释失实 | **修**：登录失败时重试拉取。原先 IdP 启动时不可达 ⇒ **永远拒绝登录、且不自愈**，即使 IdP 几秒后恢复也必须重启 |
| L11 | OIDC 模式下空 token 误拦启动 | **修**：与 M6 同一根因，`has_no_auth()` 一并解决 |
| L12 | vnet 身份键用客户端自报字符串 | **修**：会话键改为服务端生成（`new_run_id()`），`reg.client` 降级为显示名 |
| L13 | 管理接口错误未走 `detailedErrorsToClient` | **修**：`to_json_redacted()`。默认（true，与官方一致）**逐字不变** |
| L14 | `reserve_port` 错误构成组名枚举预言机 | **修**：四种文案统一成一条，细节只进服务端日志。★ 与 `constant_time_eq` 的意图自相矛盾 —— 定长比较挡住逐字节试探，**却用错误文案把整个组名送出去** |
| L15 | `observability` u64→i64 有符号转换 | **修**：`to_metric_u64()` 饱和。直接 `as i64` 会回绕成负数，Prometheus 的 counter 语义要求单调，负值会被判定为"计数器重置"，`rate()` 算出离谱值 ⇒ 告警与容量规划同时失真 |
| L16 | FRP 控制通道 TLS 无条件跳过证书校验 | **修**：保留默认（与官方一致，保互通），**新增** `verifyServerCert` + `trustedCaFile` 选项。原先问题不是"默认不安全"，而是**用户没有选择** —— 同仓库 `httpc` 默认校验，而最需要保护的控制通道反而无法切换 |
| L17 | `panic = "abort"` 放大 panic 影响面 | **评估后不采纳**：实测换 unwind 要 **+49~51% 体积**，而触发点不可证实、且「体积优先」是本项目的明确设计目标 ⇒ **保留 abort**，把数据与翻转方法写进 `Cargo.toml` 注释 |
| L18 | UDP 转发按报文自报的 `remote_addr` 投递 | **修**（**我不同意报告的"完全不可利用"裁定**，见下） |
| L19 | 未实现字段的兼容性残留 | **已正确处理，不改**：项目早有 `unsupported_fields` 机制并在启动时明确告警、专门点名 `useEncryption`/`useCompression` ⇒ **不存在静默失效** |

### L7 的细节（补 e2e 时发现的有价值事实）

报告指出 A-1 在 `e2e.rs` 里**零回归测试**。补测时发现：测试客户端原先
**不声明** `work_conn_cred` 能力位，**行为等价于官方 frpc** ——
走的是"源 IP 一致"那条兼容回退分支。所以我加了两个登录辅助，
把**两条分支都**锁住：

- **声明了**能力位 → 空凭证**被拒**、伪造凭证（4 种形态）**被拒** ✓
- **没声明**（官方路径）→ 退回源 IP 校验（互通所必需）✓

还踩到一个真实的顺序问题：工作连接的**线协议必须与控制连接一致**，
我一开始用 V1 建工作连接、用 V2 登录，被服务端**正确拒掉**了
（那是另一个测试 `work_conn_wire_protocol_mismatch_is_rejected` 覆盖的事）。

★ **判据不能用"有没有回 `StartWorkConn`"**（这是读 `handle_work` 得出的）：

| 服务端行为 | 连接状态 |
|---|---|
| 凭证通过 ⇒ 进**空闲池**等配对 | **保持打开**，且**不回**任何消息 |
| 凭证被拒 ⇒ `bail!` | **被关闭** |

### L17 的实测与**最终决策：评估后不采纳**

`panic = "abort"` 意味着**任何一个连接任务 panic 都会杀死整个服务端进程**
（而 unwind 下 tokio 只让那个任务死）。这一点用对照实验确认过
（`server/examples/panic_isolation.rs`，release 构建）：

| 配置 | 结果 |
|---|---|
| `panic = "abort"` | 进程退出码 **3221226505**（`0xC0000409`）—— **被杀** |
| 移除（默认 unwind） | 任务 panic 被 tokio 捕获（`JoinError::is_panic`），**进程与其余任务存活** |

**但最终的体积代价让这个改动不划算**（同一份源码、只切 panic 策略）：

| 策略 | nfrp-server | nfrp-client | 代价 |
|---|---|---|---|
| `abort`（**本版采用**） | 3,780,096 B | 3,845,632 B | — |
| `unwind` | 5,637,632 B | 5,792,256 B | **+49.1% / +50.6%** |

**决策：保留 `panic = "abort"`**，理由三条：

1. **收益无可证实的触发点** —— 审计报告自己写的是"未发现可远程触发的
   panic 点，防御性建议"；本项目 66 万条随机输入的 fuzz 同样**零 panic**；
2. 项目把该 profile 的注释写成"**体积优先**"，这是**有意的产品目标** ——
   本工具分发到 Android / 云手机，体积对用户是实打实的成本；
3. 代码里没有裸 `unwrap()` 的输入路径（互斥锁一律
   `unwrap_or_else(|e| e.into_inner())`，锁中毒不会 panic）。

★ 取舍的**完整数据与翻转方法**已写进 `Cargo.toml` 的注释 ——
下一个人若**能**找到一条可远程触发的 panic 路径，删掉那一行即可
（默认就是 unwind），那时 50% 体积换"不全服宕机"是划算的。

★★ **这里记录一次我自己的测量错误**：第一版我量出"两种配置体积**逐字节相同**"，
并据此写了"差异被 strip+LTO 吃掉"。**那个结论是错的** —— 本机设了
`CARGO_TARGET_DIR=<构建目录>`，而我两次都在读
`nfrp/target/release/` 里**同一个上一次发版的旧文件**。
用 `cargo metadata` 确认真实 target 目录后重测，才得到上面 +50% 的真实数字。

⇒ **"测量结果反直觉"时，先怀疑测量本身，尤其要确认自己读的是不是刚产出的那个文件。**

### L18 的细节（我不同意报告的裁定）

报告的论证是"provider 客户端只是原样回填服务端下发的地址 ⇒ 不可利用"。
**那对诚实的 frpc 成立，但漏了一点**：

> **恶意/被控的客户端可以直接指定任意 `remote_addr`**，
> 从而让 frps 向**从未给 frps 发过包**的地址发 UDP。

正常路径下 frps 只向"刚给它发过包"的地址回包（`recv_from` 拿到的 `src`）；
恶意客户端可以打破这个约束 ⇒ **frps 变成"无需请求的 UDP 发射源"**，
可被用作 UDP 反射/放大的跳板（把源 IP 指向受害者，流量从 frps 的 IP 发出）。

报告说的"他本来就能转发任意内容"是对的，但那要求**先有访客发包**；
多出来的能力是"**无需访客、直接指定目标**"。

**修法：IP 级白名单（端口无关）** —— 只允许回写给"最近真的发过包的访客 IP"。
**刻意不校验端口**：TFTP 之类协议会**换端口**回包，卡死端口会误伤它们；
而反射/放大必须跨 **IP**（把响应打给受害者），所以按 IP 收紧就够，
兼容风险极小。

★ 这不是"把客户端当敌人"：客户端是**租户自己的**代码，frps 不该无条件信任
它指定的任意目标 —— 尤其 frps 是**多租户**的：一个租户恶意，
受害的是 frps 的 IP 声誉和链路上的第三方。

★ 锁中毒时**放行**：UDP 代理断掉是**确定的**服务中断，漏拦一个回包只是少一层加固。

**回归测试**：5 条（未见过包的 IP 不许回写 / 同 IP 换端口仍放行 /
v4 与 v6 互不放行 / 超上限清空 / 并发安全）。

---

## 五、元验证

### 12 项函数体退回 —— 全部合格

把实现**退回缺陷版本**，确认对应测试**变红**：

| 编号 | 结论 |
|---|---|
| H1 空密码算无凭据 | 变红 ✓ |
| H2 逃生开关取 live | 变红 ✓ |
| H3 sudp 算访客类 | 变红 ✓ |
| H4 表格转义 | 变红 ✓ |
| M1 跨租户不得寄生 | 变红 ✓ |
| M4 INI 键名小写 | 变红 ✓ |
| M13 枚举门槛 | 变红 ✓ |
| M16 IPv6 key 加括号 | 变红 ✓ |
| L8 统一 MAX_HEAD | 变红 ✓ |
| L14 端口错误不泄露组名 | 变红 ✓ |
| L15 计数器饱和 | 变红 ✓ |
| L18 UDP 回写白名单 | 变红 ✓ |

### 4 项用别的方式验证

| 编号 | 方式 |
|---|---|
| M3 | 专门的**调用点** e2e（`login_with_stale_timestamp_is_rejected`）—— 函数级单测测不到"调用被删" |
| L7 | 测试本身就是交付物（3 条 e2e 覆盖两条分支） |
| L17 | `abort` / `unwind` **对照实验**，退出码可观测差异；再量真实体积代价 ⇒ **据此决定不采纳** |
| M7 | `ConnGuard` 的 3 条测试（收支平衡 / 提前返回 / 流量记账） |

### 元验证过程中的两次自我纠错

1. **L8 第一版"仍然全绿"** —— 我退回的是 `http1::MAX_HEAD` 的值，
   但**当时没有任何测试断言这两个常量同源** ⇒ 说明覆盖不足。
   ⇒ 补了 `max_head_必须与_http_relay_同源`，再跑才变红。
   **"元验证报全绿"有两种可能：修复没生效，或覆盖不足 —— 必须先分清是哪种。**
2. **L18 第一版"仍然全绿"** —— 我退回的是**调用点**（`if false`），
   而测试测的是 `SeenVisitorIps` 的**逻辑**。两者不是一回事。
   ⇒ 把退回点改成 `allows()` 内部，才正确变红。

### 诚实记录的**覆盖缺口**（不是"已覆盖"）

以下修复的**逻辑**有测试，但**调用点**没有自动化覆盖：

| 修复 | 逻辑测试 | 调用点覆盖 |
|---|---|---|
| M2 | `validate_request_framing` / `strip_hop_by_hop` 各有测试 | **无** —— 删掉 `plugin_bridge` 里那两处调用，测试仍绿 |
| L18 | `SeenVisitorIps` 5 条测试 | **无** —— 删掉 `udp_proxy` 里那处判断，测试仍绿 |
| M14 | — | **无** —— 没有测试断言审计事件被写入 |

⇒ 这三处目前靠**人工复核 + 代码注释**保证。下轮建议给
`plugin_bridge` 与 `udp_proxy` 补端到端测试，把调用点也纳入。

---

## 六、记录在案、**建议不改**的

| 项 | 为什么 |
|---|---|
| L16 默认不校验对端证书 | **与官方 frp 一致**（`InsecureSkipVerify = true`）。改默认会破坏"官方 frpc 零配置直连"这条承诺 —— 已改为**提供选项**而非改默认 |
| L19 未实现字段 | 项目早有 `unsupported_fields` + 启动告警机制，**不存在静默失效**，是**正确处理**而非遗漏 |
| G-4 / G-5 / G-6 / G-9（第四轮） | 官方协议属性或产品定位，改了破坏互通。已在 README 写明 |
| v1 凭据窗口内的重放 | 见 M3 的"诚实边界" |

---

## 七、本轮的方法论收获

### 1. 审计给的修法**不能照抄**

M1 的建议（`same_scope = same_owner && ...`）对攻击**完全无效**，
还会**新开一个洞**。我实测核对后自行推导了正确判据，
并**专门加了一条测试盯住那个错误修法**（`跨租户同作用域必须冲突`）。

⇒ **对每条审计建议，先问"退回缺陷后这个改动真的让测试变红吗"**。

### 2. 排查要按"操作类型"**和**"判定类型"两条线

第四轮按"操作类型"（摘/删/注销）搜全了，漏了 M1 这个"判定类型"。
**对归属/权限作出结论的布尔表达式**是独立的一条搜索线。

### 3. "注释与实现不符"是高效信号源，但**注释也可能两边一起错**

H2 里注释与代码**错得一致**（都把 `allow_insecure_dashboard` 当可热改字段），
所以单看代码或单看注释都发现不了 —— 必须**用运行时事实去校验**
（它到底在哪些地方被读）。

### 4. 元验证报"全绿"要先分清是"修复没生效"还是"覆盖不足"

L8 与 L18 两次都报了"仍全绿"，原因各不相同（前者覆盖不足、后者退回点选错）。
**盲目宣布"元验证通过"会把覆盖缺口当成合格。**

### 5. 改动连带影响要主动搜

M4 改段名小写后，`sec.name == "DEFAULT"` 那处判断必须同步改 ——
否则段前裸键会被当成代理。**改一处语义时，主动 grep 该语义的所有引用点。**

---

## 八、工具链事故记录（本次唯一一次数据损坏）

用 PowerShell 的 `Set-Content` 做"临时加回 `panic = "abort"`"的对照实验时，
**把 `Cargo.toml` 的 UTF-8 编码写坏了**（中文注释变成 `?`，多字节序列断裂）。

- **恢复方式**：`tmp/gh-export/Cargo.toml` 是上次推 GitHub 时的干净副本
  （3151 B / 98 行 / UTF-8 完好），从它恢复后重新施加 L17 改动。
- **教训**（本项目已记录过一次同类事故）：**绝不用 PowerShell 的
  `Set-Content` / `Get-Content -Raw` 往返读写含中文的 UTF-8 文件** ——
  一律用 Python 显式 `encoding="utf-8"`。
- 损坏版本保留在 `nfrp/Cargo.toml.corrupted` 供对照，可安全删除。

---

## 九、兼容性声明

本版有**三处有意的行为变更**，已在 README 写明：

| 变更 | 影响 | 处理 |
|---|---|---|
| **INI 的段名与键名统一小写** | 代理名会小写化（`[MCCC]` → `mccc`） | **与官方 `go-ini` 一致**（原先两边不同）；同一份配置现在产生相同代理名 |
| **跨租户不得靠 `routeByHTTPUser` 共用域名+路径** | 跨租户多作用域被拒 | 同租户的多作用域拓扑（官方 tcpmux 文档用法）**不受影响** |
| **UDP 回写限"发过包的访客 IP"** | 客户端无法向未通信过的 IP 发 UDP | 诚实客户端零影响；换端口回包（TFTP 类）**不受影响** |

其余改动均**不改变线协议格式**，官方 frpc 0.71.0 互通**已实测通过**。

---

## 十、下轮建议

1. **补调用点端到端测试**（M2 / L18 / M14 的覆盖缺口，见第五节）。
2. **给面板引入只读角色** —— M13 的根本解法。
3. **把"同一判定收敛为唯一函数"做成自动化检查** ——
   本项目已连续五轮出现该模式。可考虑：对每个 `pub fn` 形态的判定函数，
   检查是否有"语义等价的内联实现"散落在别处。
4. **第四轮遗留的未覆盖面**（E 组资源耗尽、B 组 group/visitor 跨用户、
   C 组 tcpmux/SNI、D 组 ACL/内网段）仍未系统覆盖。


<!-- ===== 4/14 第 6 轮 ===== -->

> **日期：2026-10-15** · **轮次：第 6 轮**

---

# NFrp v0.5.7 安全修复报告（第六轮）

日期 2026-10-15
来源 第六轮安全审计（渗透视角，参考 [KeygraphHQ/shannon](https://github.com/KeygraphHQ/shannon) 方法论）
范围 历史上**从未被系统审计过**的面 —— 不是复核前五轮的修复
结果 **8 条成立**（3 高危 / 4 中危 / 1 低危），全部已修并附回归测试
另有 **13 条线索被排除**（附反证）

---

## 〇、一句话概括

这轮换了打法：不看我上一轮修了什么，而是去**前五轮没碰过的面**里找新洞。
找到 8 条，其中 3 条高危。最严重的一条是 ——
**上一轮修的"凭证重放"只铺了 1 条路径，另外 5 条全是敞的**，
实测可以打通**完整双向中间人**（用户的明文落到攻击者手里、回包由攻击者伪造）。

而这条恰好是**我在上一轮修 M3 时自己漏的**。

---

## 一、质量门

| 项 | 结果 |
|---|---|
| 测试 | **699 通过 0 失败**（本轮 **+7**） |
| `cargo fmt --check` | 干净 |
| `cargo clippy --workspace --all-targets -- -D warnings` | **0 告警** |
| `cargo audit` | **exit 0 零漏洞** |
| 端到端冒烟 | **28 / 28** |
| 官方 frpc 0.71.0 互通 | **实测通过**（登录 + 注册 + 转发） |
| 兼容标记 | `frps -v` / `frpc -v` 都输出裸 `0.71.0` |
| 元验证 | **8 条发现全部重跑原始攻击脚本 → 打不通**；另有 **退回验证 5/5** |

---

## 二、高危（3 条）

### G-1 凭证重放：M3 的时间戳窗口只铺了 1 条路径，另有 5 条完全没有

#### 覆盖面证明：凭证入口共 6 个，已穷尽

把**所有携带凭证的协议消息**列了出来（`common/src/frp/msg.rs` 里含
`privilege_key` / `sign_key` 的结构体 + vnet 的 JSON 注册）：

| # | 消息 | 凭据字段 | 校验点 | 修复前的新鲜性校验 |
|---|---|---|---|---|
| 1 | `Login` | `privilege_key` | `conn.rs` | ✅ 有（M3 加的） |
| 2 | `NewWorkConn` | `privilege_key` | `serve.rs` | ❌ **没有** |
| 3 | `NewVisitorConn` | `sign_key` | `serve.rs` | ❌ **没有** |
| 4 | `NatHoleVisitor` | `sign_key` | `p2p.rs` | ❌ **没有** |
| 5 | vnet 注册（一行 JSON） | `token` | `vnet.rs` | ❌ **没有** |
| 6 | `Ping` | `privilege_key` | `serve.rs` | token 模式不复核（与官方一致，**非缺陷**） |

⇒ **6 个入口里只有主登录做了检查**，其余 4 个全部可重放。**没有第五处遗漏。**

#### 实弹

**vnet 注册路径**（`tmp/audit6-g1/vnet_replay_poc.py`）

```
实验组 A：当前时间（基线）      ts=1792073618  ⇒ 接受 ✓
实验组 B：1 小时前（重放）      ts=1792070018  ⇒ 接受
实验组 C：1 年前（极端）        ts=1760537618  ⇒ 接受
```

**工作连接路径**（`tmp/audit6-g1/workconn_replay_poc.py`）

```
当前时间（基线，应当接受）      ⇒ 接受（进空闲池，安静挂着）
1 小时前 / 1 天前 / 1 年前      ⇒ 全部 接受
负对照：**错误的**凭证          ⇒ **拒绝**（证明服务端确实在校验凭证内容）
```

**完整双向 MITM**（`tmp/audit6-g1/mitm_full_poc.py`）—— 这是最强的一条证据：

```
攻击者用**一年前**的凭证开工作连接 ⇒ 服务端回了 StartWorkConn
真实用户发 HELLO-FROM-USER …

  攻击者收到的用户数据 : b'HELLO-FROM-USER'      ← 用户明文到了攻击者手里
  受害者内网服务收到   : None                    ← 完全被旁路
  用户实际收到的回包   : b'I-AM-ATTACKER'        ← 用户在跟攻击者说话
```

★ **关键补充**：`client_work_conn` **完全没有调用 `enable_v1_crypto`**
（全仓只有 2 处调用，都不在工作连接路径上）⇒ `NewWorkConn`（含
`run_id` + `privilege_key` + `timestamp`）**明文传输** ⇒ 嗅探门槛很低。

#### 根因：判据没有收敛，调用方可以忘

上一轮修 M3 时，我把新鲜性做成了**独立的** `check_timestamp`，
并在注释里解释了理由：

> 「单独成函数而不是塞进 `verify_login`：**必须在算 `auth_key` 之前调用** ——
>   先判时间成本更低，而且能让"过期"与"凭证错"两种失败在日志里分开」

那个理由本身成立，**但代价是调用方可以忘** —— 而实际有 4 处忘了。

#### 修法：把校验变成不可能跳过

1. **`verify_login` 的 `skew` 成为必需参数** —— 校验新鲜性**嵌在函数体里**，
   没有"只校验凭证"的入口可以误用。两种失败在日志里**仍然分得开**
   （错误文案不同），所以原设计的收益没丢。
2. **新增 `verify_shared_secret_proof(secret, given, ts, skew, what)`**
   —— visitor / p2p 走共享密钥、不经过 `AuthProvider`，所以给它们同一份判据。
   `VisitorEntry::check_sign` 签名改为**必须**传 `skew`。
3. **工作连接改调 `sec.verify_login(...)`**，删掉那处手写的
   `auth_key` 比对（它正是"不知道有新鲜性这回事"的来源）。
4. **vnet 那处本来就走 `verify_login`** ⇒ 改完自动生效，无需改动。

★ 教训：本项目**连续六轮**出现同一个模式
**"防线写对了，但没铺满它声称保护的所有路径"**。
本轮的治本做法不是"再去四个地方各补一次调用"（那就会出现第五处），
而是**让"想校验凭证就必须提供时间窗口"成为类型/签名层面的约束**。

---

### D-1 group 负载均衡跨租户劫持他人公网端口流量

#### 根因

`PortGroup` 只有 `name` / `key` / `members` / `cursor` / `handle` ——
**没有任何"归属租户"的概念**。加入判定只看 **(组名, group_key)**，不看 `client.user`。

**最危险的形态是双方都不配 `group_key`**（官方 frp 里 `groupKey` 可选，
只配 `group` 做负载均衡是标准写法）⇒ `constant_time_eq("", "")` 为真
⇒ **组名是唯一凭据，且不需要任何密钥**。

而本结构体上方的注释原话就把 `group_key` 称作
**"认证凭据……只比对组名会让任何知道组名的客户端混入他人的负载均衡组、
分走该端口的流量份额（跨租户流量劫持）"** ——
**既然已承认它是跨租户安全边界，就不能只在"双方都配了非空 key"时才成立。**

#### 实弹（`tmp/audit6-d/d01d_group_e2e.py`，两租户各跑真实内网服务）

| 场景 | 修复前 | 修复后 |
|---|---|---|
| A：不知道组名 | 0/12 (0%) ✓ | 0/12 ✓ |
| B：知道组名 + key | **6/12 (50%) 劫持** | **0/12** ✓ |
| C：双方 key 都为空（只需组名） | **6/12 (50%) 劫持** | **0/12** ✓ |

修复前 banner 明确显示 `ATTACKER-BACKDOOR` ⇒ 用户流量真的进了攻击者的内网服务
（凭证收割 + 响应伪造）。服务端日志把这次加入记为**正常的负载均衡扩容**，无告警。

#### 修法

`PortGroup` 新增 `owner_user`，加入分支加一条跨租户拒绝。

★ **放行规则按"同一租户"而不是"同一 `run_id`"**：同租户的多个 frpc
（重连、多开、一份配置多条 `[[proxies]]`）共用同一个 `user`，而 `run_id`
每次重连都变 —— 用 `run_id` 判会把**合法的负载均衡打成不通**。
新增 `同租户重连后仍能加入负载均衡组` 专门盯住这一点。

#### 诚实说明残留风险

`user` 是自报字段（见 D-5），所以**伪造 `user` 仍可混入**。
本修复挡住的是"用自己真实身份 + 知道组名"这条路径（即实测打出的那条）。
要彻底解决需**每租户独立凭据**（见 D-5 的修法）。

---

### D-5 自报 `user` ⇒ RBAC 整体分权可伪造

#### 根因

角色解析的输入是登录报文里的 `Login.user`，由客户端**自报**、服务端不验任何东西：

```rust
if let Some(r) = self.roles.iter().find(|r| r.matches_user(user)) {
    return Ok(r.clone());
}
```

⇒ 任何**持有 token** 的人把 `user` 写成 `"bob"`，就拿到 bob 的全部角色：
`portRange`、`allowProxyTypes`、`maxProxies`、`allowManage`，以及
`allow_users` 白名单里的身份。

#### 为什么这不是"已知设计"

审计任务书提示"默认无 RBAC 时 `user` 只是自报标签是已知设计"——**这一条不是那个**：

1. 管理员写了 `[[roles]]`，已经**明确表达**了"alice 只能占 A 段 / bob 只能占 B 段"
2. frp 的 `token` 是**服务端级共享凭据**，而 `[[roles]]` 存在的理由
   **恰恰就是在共享 token 之上用 user 再分权**
3. ⇒ 该字段不可验证使这个意图**完全无法落地**（**假安全比不配更危险**）

#### 实弹（`tmp/audit6-d/d05_identity.py`）

| 观测 | 结果 |
|---|---|
| 真 alice / 真 bob 各占自己段 | ✓ 成功（对照） |
| **冒充者(user=bob) 占 bob 段空闲端口** | **✓ 成功拿到** |
| 冒充者以 bob 身份占 alice 段 | ✗ 被正确拒绝（证明 RBAC 逻辑本身在工作） |
| 冒充者注册 `bob.sec` | 撞上真 bob 的名字（**同一命名空间**） |
| **冒充者进 `allow_users=["bob"]` 的隧道** | **✓ 成功** |
| 面板视角 | **两个 `user=bob`，管理员无法区分** |

#### 修法（本版做了诚实告警，架构级改动留给下一版）

新增 `rbac_identity_is_unverifiable(cfg)`：**`roles` 非空 + 共享 token 非空**
时打一条显著 WARN，明说"这里的角色划分不是租户隔离，只是一层防误操作"。

**为什么不在这个版本里直接改成按 token 指纹匹配角色**：那会**改变 `[[roles]]`
的语义** —— 既有配置里 `users = ["alice"]` 是按用户名匹配的，改成按凭据指纹匹配
会让所有既有部署**静默失效**（所有人都匹配不上角色）。正确做法是新增一种匹配方式
并让两者共存、文档说明迁移路径 —— 那是独立的架构改动，不该塞进安全修复版本。

---

## 三、中危（4 条）

### D-4 visitor 代理名枚举预言机（**未认证**可用）

#### 根因：**同一文件里同类问题的两种处理方式**

```rust
// run_id 预言机（上一轮 A-3 修的）—— 做对了
// 注释："这一条无论如何都只回通用文案，不受 detailed_errors_to_client 影响"
Some("visitor connection failed".to_string())     // ← 硬编码，不经过开关 ✓

// 代理名预言机 —— 做错了
// 注释："短句与密钥不对保持同一形态，攻击者无法据此区分"
Some(cfg.error_to_client("visitor connection failed",
    &format!("custom listener for [{proxy_name}] doesn't exist")))   // ← 经过开关 ✗
```

两条拒绝路径文案**结构完全不同**，且走的开关 `detailed_errors_to_client`
**默认为 `true`** ⇒ 注释声称的"无法区分"**不成立**。

#### 实弹（`tmp/audit6-d/d06c_oracle.py`）

修复前：4/4 真实隧道名被识别为"存在"、3/3 假名被排除，**准确率 100%**，
且**完全不需要登录 / token / run_id**。修复后：**全部返回同一条
`visitor connection failed`** ⇒ 预言机堵死。

---

### D-2 visitor 空 `run_id` 绕过准入，匿名数据进他人隧道

#### 根因

```rust
// run_id 为空时整条判断被**短路**
if !msg.run_id.is_empty() && registry.get(&msg.run_id).is_none() { reject }

// 空 run_id ⇒ get("") ⇒ None ⇒ visitor_user = ""
let visitor_user = registry.get(&msg.run_id).map(|c| c.user.clone())
                          .unwrap_or_default();

// visitor.rs —— 空串命中 "*" ⇒ **通过**
self.allow_users.iter().any(|u| u == "*" || u == visitor_user)
```

⇒ 隧道配了 `allow_users = ["*"]` 时，**一条完全没有登录、没有 token、
没有 run_id 的连接**会被判为合法访客。

★ **同一份代码在"私密"方向是对的**：`allow_users` 为空时
`provider_user == ""` 为假，空 run_id 进不去。出问题的只有 `"*"` 那条。
但**机制是错的**：认证路径上"字段缺失 ⇒ 跳过校验"是危险模式。

#### 实弹（`tmp/audit6-d/_repro_d2_anon.py`，端到端）

修复前：`{"proxy_name": "alice.anon"}`（准入通过），
alice 的工作连接**真的收到** `b'ANON-PAYLOAD-FROM-NOBODY'`。
修复后：`{"proxy_name": "alice.anon", "error": "visitor connection failed"}`，
工作连接收到 `None`。

#### 修法（**三层**）

1. `serve.rs`：**空 `run_id` 一律拒绝**（与 A-3 的通用文案一致，不新增可区分信息）
2. `serve.rs`：`visitor_user` 从**已取到的会话**直接拿，不再 `unwrap_or_default()`
3. `visitor.rs`：`check_user` **空串显式判 false**（纵深防御）

★ 第 3 层是**退回验证发现的**：退回它时原有测试**全绿** ——
因为第 1 层已经让空串走不到那里。⇒ **纵深防御层必须有独立测试**，
否则它只是个没人验证的注释。补了 `空身份不能匹配星号白名单`。

---

### F-1 `frps --check` / `frpc verify` 预检假绿灯

#### 服务端

`--check` 只调 `validate(&cfg)` 就返回，而真正启动走的
`SecurityContext::from_config` 有一整块**只在启动时**才跑的校验。
实测**放过 5/7 条"启动必然失败"的配置**：

| 配置 | 修复前 `--check` | 修复后 `--check` |
|---|---|---|
| 对照：合法配置 | 通过 | 通过 ✓ |
| ACL：`deny = ["10.0.0.1/33"]` | **通过（假绿灯）** | **报错** ✓ |
| ACL：`deny = ["999.1.1.1"]` | **通过** | **报错** ✓ |
| RBAC：`portRange = "abc"` | **通过** | **报错** ✓ |
| RBAC：`portRange = "70000-80000"` | **通过** | **报错** ✓ |
| RBAC：`portRange = "30000-20000"` | **通过** | **报错** ✓ |

而 `guard.rs` 的注释原话是：
> 「任何一处配置写错都**在启动时报错**……尤其是 **CIDR / 端口范围这类字符串**，
>   写错了没人会主动去发现。」

—— 这句话描述的**正是** `--check` 应该覆盖的东西，而它恰恰漏了。

**修法**：新增 `serve::preflight(cfg)`（与 `serve_with` 同一份校验，
只是不绑端口、不拉 JWKS），`--check` 走它。

#### 客户端

`frpc verify` 同样只做 `parse_client`。实测：

| 配置 | 修复前 `verify` | 修复后 `verify` |
|---|---|---|
| **`[webServer]` 绑对外 + 无凭据** | **通过（假绿灯）** | **报错** ✓ |

**修法**：在打印"配置校验通过"**之前**跑 `check_web_server_is_safe`。
要点不是"多跑一个检查"，而是**"通过"这两个字必须只在校验全过之后才出现**。

#### 为什么不是小事

`--check` 的 help 写着用途是「systemd reload 前的预检 / CI」。
拿绿灯去上线 ⇒ **服务起不来**；更糟的是它**恰好覆盖安全相关配置**，
绿灯会让人**不去检查**这些"写错了没人会主动发现"的部分。
本项目**此前已因"假绿灯"栽过一次**（`reject_unimplemented_plugin` 注释里
记着 `frpc verify` 对着未实现的插件回"配置校验通过"）
⇒ **同一类问题的第二次出现**。

---

### G-2 `http_proxy` 插件配了用户名密码就**恒 407**

#### 根因（已核实源码）

```rust
// client/src/plugin.rs:279 —— 头的值被**整体小写化**
if let Some(v) = l.to_ascii_lowercase().strip_prefix("proxy-authorization:") {
    proxy_auth = Some(v.trim().to_string());     // ← v 已小写化
}
// client/src/plugin.rs:237 —— 匹配**大小写敏感**
let Some(encoded) = v.strip_prefix("Basic ") else { return false; };
```

⇒ 小写化后的 `"basic amc6amc="` **永远比不上** `"Basic "`
⇒ `basic_ok()` 恒返回 false ⇒ **只要配了 `pluginUser` 就恒 407，功能完全不可用**。

#### 实弹（`tmp/audit6-g/t11_auth_final.py`）

| 凭证形态 | 修复前 | 修复后 |
|---|---|---|
| 不带头 | 407 | 407 ✓ |
| **`Basic <配置里正确的>`** | **407（功能不可用）** | **200 OK** ✓ |
| 无关值 | 407 | 407 ✓ |

对照：同一份配置**去掉** username 立刻 `200 OK`（证明通道本身是通的）；
横向对照 `socks5`（另一条代码路径、无小写化）认证正常 ⇒ 这是 `http_proxy` 独有的 bug。

#### 修法

头名本来就**大小写不敏感**（RFC 7230 §3.2），所以拿小写副本去**匹配头名**
是对的；错的是从那个小写副本里**取值**。现在按小写副本判断"是不是这个头"，
再从**原行**上切出值。抽出 `proxy_auth_from_line()` 以便单测覆盖。

★ **原测试为什么没抓住**：`basic_auth_rules` 直接调 `basic_ok`，
**绕过了**出 bug 的头部解析。⇒ **只测了一半的链路 = 没测**。
本轮补的 `代理认证的头部解析必须保留大小写` 把两半串起来测。

★ 与审计总报告 M4（INI 段名/键名大小写）属**同一类**"大小写处理不一致"：
一个把该敏感的弄成不敏感，一个把该保留原样的弄成了小写。

---

## 四、低危（1 条）

### D-3 域名冲突文案泄露他人代理名

`server/src/vhost.rs` 原先把 `existing.proxy_name` 写进错误文案：

```json
{"error":"域名 alice-internal.corp.local 的路径已被代理 alice.site 占用"}
```

★ **同轮的 `reserve_port` 已被刻意统一成不含占用者的文案，这条漏了** ——
又一次"防线没铺满"。它把别人的代理名送出来，而代理名正是 D-4/D-2 那类
攻击所需的"别家租户的名字"。

**修法**：照搬 `registry.rs` 的做法 —— 回固定文案，细节走 `debug!`。
注意**保留 `route.domain`**：它是**调用方自己请求的**域名，回显它有助于排查。

---

## 五、已排除的线索（13 条，附反证）

| 面 | 结论 | 证据 |
|---|---|---|
| **ACL 畸形规则"静默接受"** | ❌ 不成立 | `Cidr::parse` 校验完整（有单测）；真启动**确实拒绝**（`--check` 那 40 条 `accepted` 是**探针判据**问题） |
| `allowProxyTypes` 非法类型名 | ❌ 不构成漏洞 | 效果是**全拒**（失败关闭，安全方向），管理员会立刻发现 |
| `frpc verify` "假红灯"（不认驼峰） | ❌ 不成立 | 是我**混用**了驼峰名 + 合并式值；两种**正确**写法 verify 都通过 ⇒ 兼容层生效 |
| **v4-mapped IPv6 绕过 ACL** | ❌ 不存在 | `deny=[::/0]` 对 `1.2.3.4` 不命中、`allow=[::/0]` 对 v4 拒绝 ⇒ 跨地址族不匹配是**正确设计** |
| `static_file` 路径穿越 | ❌ 防护有效 | `../`、`..%2f`、双斜杠、前缀绕过、符号链接 —— 越界一律 **403** |
| v2 跳过 ClientHello ⇒ 降级 | ❌ 不成立 | 登录确实成功（认证走完），但建加密时被拒断开 |
| 僵尸连接耗尽配额 | ❌ 无残留 | 30 次"跳过 ClientHello"后 `clients_active` 0→0→0 |
| 面板免鉴权路径 | ❌ 未发现 | `/`、`/index.html` 均 no-auth=401 / bad-auth=401 / good-auth=200 |
| RBAC 覆盖面 | ❌ 完整 | 客户端直连 + 面板写接口全部受约束（逐项验过） |
| `CloseProxy` 跨租户 | ❌ 不能 | 六种变体（全名/裸名/run_id 前缀…）均无法影响他人 |
| `ServerCmd` 从客户端方向 | ❌ 被安全忽略 | `serve.rs` |
| `allow_users` 语义 | ❌ 正确 | 三条语义全对，且 `visitor_user` 是从 registry 按 run_id **反查**（不是自报字段）——这点做对了 |
| xtcp 打洞跨租户 | ❌ 未发现越权 | `p2p.rs` |

---

## 六、方法论记录

### 1. 探针"被拒"≠ 漏洞不存在 —— 本轮踩了 4 次

| 次 | 现象 | 真因 |
|---|---|---|
| 1 | 工作连接探针**四个用例（含基线）全被拒** | **脚本 bug**：我把控制连接关了，客户端从注册表移除 |
| 2 | v2 跳过 ClientHello 探针两条都被拒 | 用了 v1 的类型字节 `111` 当 v2 的消息号（应为 `1`） |
| 3 | 僵尸连接探针「登录成功 0 次」 | 发完只等 0.3 秒就关，**没走到"登录成功"那一步** |
| 4 | D-2 首跑「匿名 visitor 被拒绝」 | `connect_visitor()` 少传一个参数 |

★ **"基线也必须通过"这个设计救了第一次误判** ——
基线没过就说明探针有问题，而不是"没有漏洞"。**对照组救了一次误判。**

### 2. 并行审计的**端口冲突**会产出假数据

- D 组最初用**固定端口**，与并行会话抢端口 ⇒ 面板大量 502，
  并一度误判"客户端发 `ServerCmd` 能删别人的代理"
- F 组的面板鉴权矩阵**一半是 `CONNECT-FAIL`** ⇒ 那部分结论无效
- ⇒ **规矩：一律用动态端口**

### 3. 独立复现是必须的

本报告 8 条成立发现，**全部由主审独立跑过一遍**（不直接采信分工组的结论）。
其中 D-2 的原脚本因 harness 改成动态端口而失效，由主审**重写**后才复现成功。

### 4. **退回验证**抓到了一个覆盖缺口

8 条发现里 6 条做了"重跑攻击脚本"这种最强形式的元验证。
剩下 2 条（D-3 / D-5）只有单测，所以额外做了**退回验证**：把修复退掉，
测试必须变红 —— 用来自证"新写的断言真的在测那件事"，而不是个恒真的假测试。

顺带把 D-1 / D-2 / G-2 也一起退了，结果是 **5/5 中 4 条变红、D-2 仍绿**。
查出真因：D-2 有**两层**修复，第 1 层已让空串走不到第 2 层，
所以第 2 层（纵深防御）**没有独立测试**。补测后 **5/5 全红**。

⇒ **"退回后测试仍绿"要先分清"修复无效"还是"测试不足"。** 这次是后者。

### 5. 冒烟脚本也会过时

`smoke_034.py`（28 项）在 v2 读接口上报了 4 个 FAIL。
**先确认是设计变更还是回归**（而不是"改到绿为止"）：
直接观测 `/api/v2/clients` 带/不带 `all=1` 的响应，
确认"不带 ⇒ 400、带 ⇒ 200"⇒ 是 v0.5.6 的 M13 有意行为，**不是回归**。
然后更新脚本（测试工件跟上被测行为是正确做法）。

★ 这同时暴露一个**真实的冒烟覆盖缺口**：v0.5.6 引入 M13 行为变更时，
那个版本用的冒烟脚本**没覆盖 v2 读接口**，所以没发现。
本轮的 28 项脚本更全，正好抓出来了（**28/28** 比原先的 18/18 覆盖面更大）。

---

## 七、修复清单

| 优先级 | 发现 | 修法 | 回归测试 |
|---|---|---|---|
| **P0** | G-1 凭证重放 | 新鲜性并入 `verify_login` / `verify_shared_secret_proof`；`skew` 成为必需参数 | 4 条（vnet/workconn/mitm + 单测） |
| **P0** | D-1 group 跨租户 | `PortGroup.owner_user`，**按租户**判 | 3 条（含"重连后仍能加入"） |
| **P0** | D-5 自报 user | 启动显著 WARN（架构级改动留下一版） | 1 条 |
| **P1** | D-4 代理名预言机 | 两条路径共用固定文案，**不过开关** | 由 D-2/D-4 实弹覆盖 |
| **P1** | D-2 空 run_id | 空 run_id 一律拒 + 会话反查 + `check_user` 空串判 false | 2 条（e2e + 单测） |
| **P1** | F-1 预检假绿灯 | `serve::preflight()`；`verify` 在打印"通过"前跑安全检查 | 由实弹覆盖 |
| **P1** | G-2 http_proxy 407 | 只小写化**头名**，值保持原样 | 1 条（串起两半链路） |
| **P2** | D-3 域名文案 | 照搬 `registry.rs` 统一文案 | 2 条（原断言改为"不含占用者"） |

---

## 八、已知未覆盖面（如实记录）

本轮的 7 个分工组里有 6 组在**实证阶段中断**（A 组资源耗尽/DoS、
B 组传输层 KCP/QUIC/WS、C 组并发竞态、E 组 HTTP/tcpmux/SNI、
F 组 ACL/面板矩阵、G 组客户端），只留下了脚本与部分中间结果。
**只有 D 组交付了完整报告。**

⇒ 以下面**本轮没有系统覆盖**，不要当成"已审计通过"：

| 面 | 状态 |
|---|---|
| 资源耗尽与 DoS（慢速攻击 / 放大 / 配额逃逸） | ⏳ 未完成 |
| 传输层（KCP / QUIC / WebSocket / p2p / vnet 的数据面） | ⏳ 未完成 |
| 并发 / 竞态 / 状态机 / TOCTOU | ⏳ 未完成 |
| HTTP / tcpmux / SNI / 响应拆分 / PROXY protocol | ⏳ 未完成（部分中间结果未见异常，但未系统化） |
| 客户端侧（本地 UI / 插件 / store） | ⏳ 仅 G-2 一条，其余未完成 |
| ACL / CIDR 边界、面板鉴权矩阵 | ⏳ 部分（v4-mapped 已排除、面板矩阵一半因端口冲突无效） |

下一轮建议优先补这几块。


<!-- ===== 5/14 第 7 轮 ===== -->

> **日期：2026-10-17** · **轮次：第 7 轮**

---

# NFrp v0.5.8 安全修复报告（第七轮）

日期 2026-10-17
来源 第七轮安全审计（分组并行：A 资源耗尽 / B 传输数据面 / C 并发状态 / D HTTP / E 客户端 / F ACL 与面板）
范围 前六轮之外的面（HTTP 响应侧、VNet 转发键、空闲池、日志放大、远程下发校验、ACL 覆盖面）
结果 **13 条成立**（2 高危 / 7 中危 / 4 低危），全部已修并附回归测试
另有 **B-1（xtcp 牵线劫持）**在第七轮登记、第八轮完成实弹复现与修复 —— 见
第 8 轮

---

## 〇、一句话概括

这轮 13 条里最有代表性的是两条"**一侧修了、另一侧没修**"：

- **D7-1**：HTTP 请求侧早就改用 RFC 口径判 `Transfer-Encoding`，
  **响应侧还留着第四轮废弃的 `contains("chunked")`** ⇒ 实测响应走私
  （Alice 能读到 Bob 的响应体）；
- **F7-1**：IP 白/黑名单只铺在**控制连接**上，真正跑用户流量的
  **公网代理端口一个都没有** ⇒ 管理员以为封了，实际全敞。

加上 B-2（`verifyServerCert = true` 静默失效、链路实际明文）、
E-1（回环白名单无条件放行字面量 `localhost`）、C-1（VNet 转发用了显示名
而不是会话键，整条转发全死）—— 13 条全部修复并逐条做了元验证 / 退回验证。

---

## 一、质量门

本节数字为 v0.5.8 发布时的最终质量门（这 13 条修复随 v0.5.8 发布，
与第八轮修复共同验收）：

| 项 | 结果 |
|---|---|
| 测试 | 见 （已并入本文档）（workspace 全绿） |
| `cargo fmt --check` | 干净 |
| `cargo clippy --workspace --all-targets -- -D warnings` | 0 告警 |
| `cargo audit` | exit 0 零漏洞 |
| 每条修复的回归测试 | ✅ 13/13（含退回验证，见各条"守卫"） |
| 元验证 / 退回验证 | ✅ 9 条有实弹元验证；4 条低危以单测 + 交叉复现验收 |
| 兼容标记 | `frps -v` / `frpc -v` 输出裸 `0.71.0`（未动） |
| 官方 frp 互通 | v1/v2 登录 + 注册 + 转发实测通过 |

---

## 二、高危（2 条）

### D7-1 响应侧 `Transfer-Encoding` 判定用废弃写法 ⇒ 响应走私

- **根因**：同一链路两套口径 —— 请求侧（`vhost.rs:1061/1075`）已改用
  `http_relay::transfer_encoding_is_unsupported` / `is_chunked`；
  响应侧（`vhost.rs:1254/1274`）仍是 `te.to_ascii_lowercase().contains("chunked")`。
  而 `http_relay.rs` 的注释**自述** `contains("chunked")` 正是第四轮修掉的走私写法。
- **实测**（`tmp/audit7/d_independent/repro_d71_smuggle.py`，**9/9**）：
  后端回 `TE: chunked, identity`，两个域名同连接 pipeline ⇒ 严格下游只解析出
  **1 条**响应，Bob 的响应体混进 Alice 的响应 —— **跨用户响应走私**。
- **修复**：响应侧两处统一改用 `nfrp_common::http_relay::is_chunked(&resp)`
  并共用同一变量；不支持的 TE ⇒ `framed=false` ⇒ `Connection: close` 安全失败。
- **守卫**：端到端脚本（9/9）。⚠ 诚实记录：配套单测守的是 helper
  （本来没坏的那个），退掉修复仍全绿 —— 属"**测试测错了对象**"；
  已保留单测并标注"有效守卫是端到端脚本"。
- **元验证**：修复后 `connection: close`、body 止于 `0\r\n\r\n`、
  Bob 内容不再混入；**退回验证**：退掉修复 ⇒ 走私**重现**（9/9）。

### E-1 远程下发的回环白名单**无条件放行 `localhost`**

- **根因**：`common/src/config.rs` 的 `is_loopback_host()` 在 IP 解析**之前**
  无条件放行字面量 `localhost`；而同仓库 `util.rs` 的 `is_loopback_addr()`
  **显式拒绝** localhost（注释写明"解析到哪个地址取决于本机 hosts/DNS，
  不能靠名字赌"）—— **同一语义两套相反实现，弱的那套在守关键路径**。
- **实测**（后端同时监听 `127.0.0.1` 与 `[::1]`）：

  | 下发值 | 结果 | 命中 |
  |---|---|---|
  | `127.0.0.1:P` | 200 已生效 | v4=1 / v6=0 |
  | **`localhost:P`** | **200 已生效** | v4=0 / **v6=6** |
  | `10.0.0.5:P`（对照） | 400 被拒 | — |

  同款在 **store 恢复路径**复现（写 `localhost` 被恢复且零告警）——
  两条远程路径同时漏。远程下发的 `local_addr` 会被实际用于工作连接
  ⇒ 服务端可控的**回环 SSRF**（打本机管理面）。
- **修复**：`is_loopback_host()` 不再放行 `localhost`（#14/白名单收敛），
  `client/src/main.rs` 侧同步修正。回归单测：远程下发 `localhost` 必须被拒。
- **守卫**：单测 + 端到端（localhost 被拒、127.0.0.1 仍放行）。

---

## 三、中危（7 条）

### A-1 未认证日志放大 ⇒ 磁盘可被打满（125×）

- **根因**：`server/src/serve.rs` accept 循环对**认证之前**的每条连接失败写
  WARN 且无限流；日志轮转按天、无大小上限。触发成本：连上端口发 1 个非法字节。
- **实测**：200 B 上行 ⇒ 25 000 B 日志（**放大 125.0×**，主审独立复算一致），
  四轮恒定 ⇒ 无退避；外推 **859 MiB/天**。服务端不崩溃 ⇒ 极易被忽视。
- **修复两次返工**（最有价值的部分）：
  1. v1 速率限制（20 条/秒）⇒ **慢速打绕过**，仍有 12.5×；
  2. v2 按窗口折叠 ⇒ 窗口边界被调用节奏决定，**50 次调用写 50 条**；
  3. v3 最终：**按消息指纹折叠 + 令牌桶（容量由真实流逝时间决定）** ⇒
     放大 **1.2×**、稳态 155 B/s、外推 **0.5 MiB/小时**。
- **修复只折叠日志、不改行为**：连接照常拒绝、首次必写完整消息、
  折叠条数会汇总报告（运维不会"看起来风平浪静"）。
- **守卫**：单测 `日志折叠_同类消息每窗口最多两条`（4 条判据，含专门针对
  前两次返工的"慢打也被桶约束""快慢写出条数接近"）。

### B-2 `verifyServerCert = true` 静默失效，链路实际是明文

- **根因**（两层）：
  1. `tls::connect_client` 在 `enable == false` 时**直接返回、完全忽略
     `verify` 参数且无任何告警**；
  2. 命名风格混用：`tls_enable`（下划线）与 `verifyServerCert`（驼峰）
     同字段风格不一致 ⇒ 写 `tlsEnable = true` **不被 serde 接受**、静默为 false。
- **实测**（关 tcp_mux 抓字节）：

  | 配置 | 结果 | 链路 |
  |---|---|---|
  | `enable=true` + `verifyServerCert=true`（官方写法） | 登录失败(UnknownIssuer) ✅ | TLS |
  | `tls_enable=true` + verify + CA（正确写法） | 登录成功 ✅ | TLS |
  | **`tlsEnable=true` + verify（驼峰）** | **登录成功** | **明文** ❌ |
  | **只写 `verifyServerCert=true`** | **登录成功** | **明文** ❌ |

  决定性证据：明文可见 `privilege_key = md5(token+ts)`（**可直接重放登录**）。
  "安全配置静默失效"比"没有这个功能"更危险。
- **修复**：`tlsEnable` 增加 serde 别名（与 `verifyServerCert` 风格一致）；
  `verifyServerCert && !tls_enable` 时启动打显著 WARN 说明链路为明文。
- **守卫**：单测 `tlsEnable 驼峰写法必须生效` + WARN 行为测试。

### C-1 VNet 转发路径用了**显示名**而不是**会话键** ⇒ 转发全死 + 告警失真

- **根因**（一行实参）：`vnet.rs` 建立身份用 `session_key = "{client}-{run_id}"`，
  转发调用却传 `&reg.client`（少了 `-<hex>` 后缀）⇒ `ips_of` 精确匹配恒不匹配
  ⇒ **每个包（包括合法客户端自己的）都在源校验处被丢弃**：
  - 功能面：广播、网关 ICMP、单播 A→B 全部不可达；
  - 可观测性面：`dropped_spoofed`（防冒充唯一信号）对每个合法包自增 ⇒ 失去判别力；
  - 安全姿态：fail-closed（拒绝一切），**不构成越权/泄露**。
- **修复**：传 `session_key`；**治本**：新增 `SessionKey` newtype，
  `route()/join()/leave()` 只接受它。
- **守卫**：单测 `转发必须用会话键而不是显示名`（功能 + 指标两层面）。
  **退回验证 = 最强形式**：把实参改回 `&reg.client` 后 **直接编译失败**
  （`expected &SessionKey, found &String`）—— 该 bug 无法被重新引入。
- ⚠ 诚实记录：最初的单测在退掉修复后仍全绿（它直接调 `route()`、
  绕过了传参点）—— 同样属"测试测错了对象"；真正的锁是类型系统。

### C-2 空闲工作连接池**无上界** ⇒ 句柄/内存被存量式占满

- **根因**：服务端预开的工作连接池没有上限；空闲连接可被反复灌入并长期占用。
- **实测**：200 条全部接受；推到 **6000 条**仍线性不降级；
  量化代价 **@2000：+2066 句柄、+3.3 MB；@4000：+4129 句柄、+6.5 MB**。
- **修复**：池上限封顶 + 每条空闲连接登记**配额凭证**（与 `conns_active`
  同一套口径），超限时新预开请求被拒而不是无界吞噬。
- **守卫**：单测（回到上限以内立即恢复）+ 端到端（200/6000 规模）。

### D7-2 响应侧**完全没有** framing 校验

- **根因**：请求侧早有 `validate_request_framing`（TE+CL / 重复 CL / 不支持 TE
  三项全 400），**响应侧一项都没有** —— 重复 CL、CL+TE、`xchunked`
  全部原样透传给公网访客。与 D7-1 是同一条链路上的两个洞
  （一个口径不一致、一个根本没有）。
- **修复**：新增 `http_relay::validate_response_framing()`（与请求侧同策略、
  **失败关闭**），在 vhost 响应路径**剥逐跳头之前**调用；不合法 ⇒ **502**
  （`内网服务返回的响应报头不合法（framing 走私风险）`）。
- **守卫**：单测 `响应侧_framing_校验必须与请求侧同样严格`
  （3 拒 + 4 放行的对照，含 `identity, chunked` 合法形态不误伤）。
  **退回验证**：退掉校验后测试**准确变红** ⇒ 这条单测真的守住了修复点。
- **正面副作用**：D7-1 的走私形态在多数场景被 502 提前显式拒绝
  （比"安全失败转发"更严格）；两条基线仍全过。

### E-2 `local_addr_host()` 判据串 ≠ 实际连接串（check-vs-use）

- **根因**：校验器对带方括号输入取 `[` 与 `]` 之间的内容判回环白名单
  （`[::1].evil.com:PORT` → 判 `::1` ⇒ **放行**）；而工作连接实际用**原始串**
  `resolve_addr("[::1].evil.com:PORT")` ⇒ **走 DNS**（判 A 用 B）。
- **实测**：下发 `[::1].evil.com:P` → 200「已生效」；客户端日志
  `解析内网地址 [::1].evil.com:57472 失败: cannot resolve address`。
  对照 `[evil.com]` / `[10.0.0.5]` / `[0.0.0.0]` 均被正确拒绝。
- **修复**：方括号必须**紧贴 port 冒号**（`[v6]:port` 之外的任何形态拒绝）。
- **守卫**：单测（4 组拒绝 + 合法 v6 形式放行）。

### F7-1 ACL **未覆盖数据面**（公网代理端口）

- **根因**：ACL 唯一入口 `SecurityContext::check_ip` 全仓仅 2 处调用
  （控制连接握手、VNet 注册）。公网 TCP 代理端口、UDP 代理、HTTP/HTTPS vhost、
  tcpmux、p2p 打洞端口**全部没有** —— 管理员用 `[acl]` 表达"只允许某些来源
  访问我的服务"，真正承载用户流量的路径上没有这道闸。
- **实测**（`acl_dataplane_v3.py`，**9/9** 含 4 条基线对照）：
  `deny = ["127.0.0.1"]` 时，从被 deny 的来源连公网端口照样拿到
  `ACL-BACKEND-OK`。
- **修复**：`serve.rs::proxy_accept_loop` 与 `vhost.rs::run_vhost` 两处
  accept 分支加 ACL 判定（**失败关闭**：被拒连接立刻关闭）。
- **守卫**：回归测试 3 条（`vhost_数据面必须过_ip_白黑名单` + 对照）。
  **元验证**：重跑攻击脚本 ⇒ `got=b''`。**退回验证**：退掉修复后测试变红，
  且证据精确 —— 连接从"立刻 EOF"变成"保持打开 415ms 直到超时"
  （= 连接被交给了 HTTP 处理）。
- **本版 ACL 的边界（诚实说明）**：`[acl]` 覆盖面 = **控制连接握手 +
  VNet 注册 + TCP 代理 accept + vhost accept（HTTP/HTTPS/tcpmux 同一个
  vhost 入口）**，共 4 处。以下三处**仍不在** `[acl]` 范围内：
  ① **UDP 代理端口** —— 0.5.6 起有"只回写给真的发过包的访客 IP"的反射
  防护（L18），但它防的是 frps 被当反射跳板，**不是**管理员来源管控；
  任意来源的 UDP 仍会被接收并转发。
  ② **xtcp/p2p 牵线 UDP 端口** —— 不受 `[acl]` 约束。
  ③ **管理面板** —— 不走 `[acl]`，它有独立的登录认证与绑定地址控制。
  即：UDP 路径的来源管控本版未做，别把 `[acl]` 当成"已全覆盖"。

---

## 四、低危（4 条）

### D7-3 响应侧逐跳头漏剥 `Proxy-Connection`

- 其余 6 个逐跳头（含 `Connection` 点名的）都正确剥掉，唯独这个漏了。
- **修复**：`HOP_BY_HOP` 表补上 `proxy-connection`。（响应走私的潜在辅助载体。）

### D7-4 `static_file` 允许读 NTFS 备用数据流（ADS）

- **实测**：`/data.txt::$DATA` → 200 读出同文件内容。
  **不是目录穿越**（root 外文件用任何 ADS 变体都 403 —— E 组 31 个
  Windows 穿越向量独立交叉一致，全 403）。
- **修复**：拒绝含 ADS 形态的路径（`plugin.rs`）。
- 顺带说明：文件不存在时回 403 而非 404（失败关闭是安全方向，见 README
  "当前限制"无变化）。

### E-3 `http2http` 剥离集合与官方一致（3 个 `X-Forwarded-*`），
注释却声称"防伪造"

- **根因**：与官方 frp 行为相同（官方 `ReverseProxy.Rewrite` 删的正是同样 3 个），
  非 NFrp 回归；但头注释把语义描述成"防伪造"，与实现有落差。
- **修复**：补上 `Forwarded` 的剥离；注释收敛为"对齐官方口径，
  其余头为业务可能需要而保留"。

### E7 附带发现 空 `local_addr` 假绿灯（远程下发）

- **背景**：E7 原始假设（`localIP`+`localPort` 两段式绕过回环白名单）
  已用**诱饵服务**判定**不成立**（两段式字段被 serde 静默丢弃，诱饵零流量）。
- **附带发现（成立）**：`local_addr = ""` + 无关字段仍被面板 **200 接受**、
  占用公网端口、`/api/status` 显示"已生效"，但**连不上任何地方** ——
  运行期"假绿灯"（与第六轮 F-1 同族、换在运行期）。
- **修复**：**非插件代理**必须给合法 `local_addr`，空值直接 400
  （插件代理不需要 `local_addr`，不受影响）。
- **守卫**：单测（空值被拒）+ 端到端（200 → 400）。

---

## 五、被排除的线索（各组反证摘要）

| 组 | 排除 | 代表条目 |
|---|---|---|
| A | 13 条（**含主动作废 2 条假阳性**） | "slowloris 打崩"实为别组误杀（`HANDSHAKE_TIMEOUT=30s` 实测有效）；"1000 条 allowPorts 挂死"为并行负载假阳性（单独连测 12 次全过） |
| B | 多条 | yamux 8/8（3000 流、错 token 被拒、畸形帧安全）；QUIC 8/8（垃圾/500 伪造 Initial 全安全）；TLS 记录层畸形全被 rustls 拒绝；vnet token 全拒；WebSocket 精确前 10 字节判据（鉴权未被绕过） |
| C | 多条 | 端口/域名 TOCTOU 40 轮 0 双成功；配额 churn 无泄漏（`conns_active` 恒回落）；状态机 16/16 不崩无越权；热重载 ~28000 请求 0 全断窗口；面板并发写 12/12 恰好 1 条成功 |
| D | 25 条 | PROXY protocol 伪造源 IP **不存在**（服务端根本不解析入站 PROXY 头）；tcpmux 21+17 畸形无打错后端；SNI 37 种畸形失败关闭；面板 23 种畸形请求行全 401 |
| E | 24 条 | `X-Nfrp-Client` 大小写穷举 2048 种全部正确判等；DNS rebinding 排除；static_file 31 向量全 403；第六轮遗留 health_check SSRF 哨兵零命中 |
| F | 多项 | 面板鉴权矩阵 421 条探针零高/零中（3 条低危见第八轮 F8-L1/L2/L3） |

---

## 六、跨轮模式与教训（写给未来的自己）

1. **"一侧修了、另一侧没修"连续第七轮出现**：D7-1（请求侧 vs 响应侧）、
   B-2（enable vs verify）、C-1（建立 vs 查找）、F7-1（控制面 vs 数据面）。
   结论不变：**同一语义只允许一处实现，其余全部从它派生**；
   更强的形式是**类型/编译期锁**（C-1 的 `SessionKey`）。
2. **"测试测错了对象"**（D7-1 的 helper 单测、C-1 绕过传参点的单测）：
   退掉修复仍全绿。**能守住修复的守卫是端到端实弹**，单测只守语义。
   本轮起每条修复的文档里必须写清："守卫是哪一条"。
3. **修复本身要过元验证**：A-1 的 v1/v2 两次返工说明"看起来合理的修法"
   可能结构性无效 —— 每条修复都要拿**原始攻击脚本**重跑一遍才算完。
4. **数字要能外推**：A-1 的"125× / 859 MiB/天"与 C-2 的"6000 条 / +4129 句柄"
   比"有放大""无上界"更能驱动修复优先级。


<!-- ===== 6/14 第 8 轮 ===== -->

> **日期：2026-10-17** · **轮次：第 8 轮**

---

# NFrp v0.5.8 安全修复报告（第八轮）

日期 2026-10-17
来源 第八轮安全审计（收尾轮：第七轮遗留 B-1 实弹复现 + 面板鉴权矩阵复建 + TLS 入站插件数据面）
范围 xtcp 牵线（p2p）· 面板鉴权矩阵（421 条探针）· `https2http` / `https2https` 插件
结果 **5 条成立**（1 高危 / 0 中危 / 4 低危），全部已修并附回归测试
     与第七轮（13 条）共同随 **v0.5.8** 发布

---

## 〇、一句话概括

本轮的主角是 **B-1（xtcp 牵线可劫持）** —— 第七轮就登记，但当时没有实弹复现链；
本轮把复现链打通后**确凿成立且为高危**：牵线 HELLO 无鉴权、provider 应答是固定常量
`RTNL-OK`，链路上任何能看到一次明文 HELLO 的人都能**冒充 provider 拿走用户的明文数据**，
而真实后端 0 字节。修复用了**两层独立防线**（服务端来源 IP 绑定 + 派生应答口令），
两层的拦截各自都被单独证明（不同 IP / 同 IP 两种攻击矩阵）。

另外 4 条低危来自面板鉴权矩阵与插件数据面：**请求体里的 `Authorization` 行参与面板
鉴权**（解析卫生）、**按面板列表的全名删代理 ⇒ 502 + 两端状态分裂**、
**注释声称 trim 实际逐字比对**、**插件等上游悬挂时访问方撤离不释放上游连接**。

---

## 一、质量门（v0.5.8 发布时的最终数字）

| 项 | 结果 |
|---|---|
| 测试 | **725 通过 0 失败**（client 115 / common 340 / server-lib 229 / server-bin 17 / e2e 24；另 doctest 2×5 忽略） |
| `cargo fmt --check` | 干净 |
| `cargo clippy --workspace --all-targets -- -D warnings` | **0 告警** |
| `cargo audit` | exit 0 **零漏洞**（184 crates 扫描） |
| 端到端冒烟 | **28 / 28** |
| 元验证（攻击脚本重跑） | B-1 blocked **12/12** · sameip **11/11** · F8 **13/13** · 悬挂 **17/17** |
| 退回验证 | B-1 退回后 **12/12 重现漏洞**；F8T-1 退回后测试变红 |
| 交叉验证（子代理原始套件） | F8 三脚本 → 全绿；t3 **53/53**（修复前 51/53） |
| 兼容标记 | `frps -v` / `frpc -v` 输出裸 `0.71.0`（未动） |
| 官方 frp 互通 | v1/v2 登录 + 注册 + 转发实测通过 |

---

## 二、高危（1 条）

### B-1 xtcp 牵线可劫持 —— 无鉴权 HELLO + 固定应答口令

- **攻击链（三步，全部实测打通）**：
  1. 牵线 HELLO 是**明文 UDP**（`RTNL` 魔数 + 版本 + sid），在链路上读一次即得 sid；
  2. 向牵线端口发同样格式的 HELLO **冒充 provider** —— 旧代码对 HELLO
     **零校验**（不验来源、不验身份），服务端回 `PEERS` 把 visitor 的地址交出去；
  3. visitor 打洞后主动连上攻击者，递交 `handshake_token`；攻击者**不需要知道
     `secret_key`**（token 是 visitor 送来的），回旧的固定 8 字节 `RTNL-OK`
     即被当作握手成功。随后用户明文数据抵达攻击者、伪造回包被用户接受、
     **真实后端 0 字节**，而 visitor 日志写的是"P2P 直连已建立"。
- **定级**：高危（完整性 + 机密性；门槛仅为"链路上看到一次 UDP HELLO"）。
- **修复（两层独立防线）**：
  1. **服务端来源绑定**：`P2PHub::create(sid, visitor_ip, provider_ip)` 记录两端
     **各自控制连接**的来源 IP；HELLO 来源与对应侧控制连接 IP 不一致
     ⇒ `RegisterOutcome::IpMismatch` **拒绝登记**。`same_host()` 做
     v4-mapped（`::ffff:127.0.0.1` ↔ `127.0.0.1`）归一化，双栈不误杀。
  2. **派生应答口令**：删除 `HANDSHAKE_OK`（固定 `RTNL-OK`），改为
     `handshake_ack(secret_key, sid) = hex(sha256("ack:" + secret_key + ":" + sid))`
     —— 与 `handshake_token`（`sha256(secret_key + ":" + sid)`）**域分离**；
     visitor 读 64 字节并以**定长比较**校验，不等即判失败 → **回退 stcp 中继**。
- **验证矩阵（全部实跑）**：

  | 场景 | 期望 | 结果 |
  |---|---|---|
  | 基线（无攻击者） | 用户数据到达真实后端 | ✅ 4/4 |
  | 攻击（不同 IP）· 修复前 | 劫持成立 | ✅ **12/12 漏洞**（3 次独立复现） |
  | 攻击（不同 IP）· 修复后 | 服务端拒绝登记，用户走中继 | ✅ **12/12 拦截** |
  | 攻击（同 IP）· 修复后 | IP 层拦不住同 NAT，第 2 层拦截 | ✅ **11/11 拦截** |
  | **退回元验证** | 用修复前二进制重现漏洞 | ✅ **12/12 重现** |

- **残余风险（如实）**：同 NAT 的观察者仍可登记并且能拿到 `handshake_token`，
  **但拿不到任何用户数据**（第 2 层拦截；token 是 visitor→provider 单向口令，
  单独泄露无独立危害）。HELLO 仍明文、sid 仍可被读到 —— 但 sid 单独
  已不足以冒用（还需同侧 IP + 派生应答）。
- **兼容性**：新旧版本任意混合 ⇒ P2P 握手失败 ⇒ 打洞窗口后**自动回退中继**，
  功能不受影响（README 已注明）。

---

## 三、低危（4 条）

### F8-L1 请求体里的 `Authorization` 行参与面板鉴权

- **根因**：`server/src/dashboard.rs::header_value` 在整个已读缓冲里找
  `Authorization:` 行 —— **请求头区之后**的 body 行也会"误投"。
- **实测**：对照（无头）401；**body 变体 200**；`Content-Length: 0` + 同段
  body 行 200。与上游反代 / WAF 的口径不一致（属解析卫生缺陷，各层对同一
  请求的判断出现分歧面）。
- **修复**：`header_value` 只看头区（第一个 `\r\n\r\n` 之前），单测
  `header_lookup_must_ignore_body_lines`。修复后三个变体全部 **401**。
- **交叉验证**：子代理 `verify_b.py` / `verify_b2.py` 重跑 —— body 变体与
  CL:0 变体全部 401 ✓（含"真头错 + body 对"对照 401）。

### F8-L2 按面板列表的**线上全名**删代理 ⇒ 502 + 两端状态分裂

- **根因**：面板列表展示的是线上全名（`user.proxy`），用户按列表名删除时：
  服务端 `canonical_wire_name` 幂等处理**真的删了**；但转发给客户端的
  `CMD_REMOVE_PROXY` 用**原样全名** ⇒ 客户端按本地名查表找不到 ⇒ 502。
  结果"服务端已摘 / 客户端还挂着"—— 端口与域名泄漏 + 文案与真实状态不符。
- **实测**：全名删除 502（`服务端已移除，但客户端侧失败`）、客户端日志
  `本地没有名为 [probeuser.web]`；短名对照 200。
- **修复（两层）**：① `server/src/admin.rs` 下发给客户端改成本地名
  （`strip_user_prefix`）；② `client/src/main.rs` 容忍全名（剥本端 user 前缀
  兜底）—— 覆盖**滚动升级**（新服务端 + 旧客户端）。修复后全名删除 **200**、
  端口释放、客户端日志 `proxy=web`（本地名）✓。

### F8-L3 `dashboard_user` 空白注释与实际行为不符

- **根因**：`common/src/config.rs` 注释声称两侧空白会被 trim，实际**逐字比对**
  （与官方 frp 一致）。属注释与实现不符。
- **实测**：配置 `dashboard_user = " admin "` 时，发 `admin:` 401、
  发 `" admin "` 字面量 200。
- **修复**：**只改注释**（明确"逐字比对、不 trim，与官方一致"），无行为变更
  —— 这是有意保留的兼容行为。

### F8T-1 `https2http` / `https2https` 上游悬挂时访问方撤离不释放上游连接

- **根因**（`client/src/plugin_bridge.rs`）：等上游响应头阶段只读上游、
  **不感知访问侧**（访问方 FIN/close_notify 离开后插件替它继续等，上游连接
  永不释放）；连上游 / 上游 TLS 握手两处 `await` **都没有超时**。
- **危害**：任何能访问该 `remote_port` 的人可"连接 → 发请求 → 撤离"反复
  留下 ESTABLISHED 上游连接（上游永久沉默则无上界）—— 资源耗尽型。
- **实测（修复前）**：https2http/https2https 各 3 轮撤离留下 **3 条
  ESTABLISHED**；`https2https` 无超时 4s 后仍悬挂；plain tcp 中继对照 0 条。
- **修复（两道互补防线）**：① `common/src/http_relay.rs` 新增
  `HttpIo::watch_closed()` + `plugin_bridge.rs` 新增 `wait_upstream()`：
  连上游与等响应头两段都 `select!` 盯着访问侧 —— 访问方撤离**立刻收尾**，
  上游连接随 `up` 的 drop 释放（对齐官方 frpc 的请求上下文取消语义）。
  ② `UPSTREAM_DIAL_TIMEOUT = 10s` 套住连接与上游 TLS 握手；"等响应头"阶段
  **故意无超时**（长轮询 / SSE 不受影响）。单测 4 条（含"慢响应上游
  2s 后回不被误伤"）。
- **修复后**：`--expect fixed` **17/17**（两插件 3 轮后 0 条；plain 对照 0；
  慢上游完整送达）；子代理 t3 套件 **53/53**（修复前 51/53，两条 FAIL
  正是本发现）。边界观察（非缺陷）：`park` 型后端（完全不读不写）会留下
  FIN_WAIT2 内核态记录 —— 属 TCP 半关语义固有上界，普通中继同样如此。

---

## 四、装置修正（审计脚本自身的返工，如实记录）

本轮的价值有一半在这些"差点让我们自己信错"的地方：

1. **抓包窗口盲区**：tshark 报 "Capturing" 后仍有最初 ~1 秒抓不到包的盲区，
   同 IP 模式连续两次把一次性 HELLO 突发整段漏掉。修法：`warm_up()` 用垃圾包
   踩掉盲区 + 抓不到时换新用户连接重试；**抓不到 HELLO 直接 exit 3 作废本轮**，
   绝不允许拿上一轮证据判分（曾因 stale evidence 得到一串假通过）。
2. **隔离副本陈旧**：泄漏进程占用 `_work/_bin` 副本时覆盖失败被
   `except OSError: pass` 静默吞掉 ⇒ 验证跑了旧二进制（首轮 F8 复验因此
   误报"修复无效"）。修法：验证前杀泄漏进程 + 比对副本哈希与源一致再跑。
3. **验证先于结论**：B-1 same-IP 11/11 与 blocked 12/12 均为**新开用户连接、
   全新端口与 token** 的独立运行。

---

## 五、本轮**没有**覆盖的面（继承第七轮声明）

第七轮说明列的未覆盖面（资源耗尽与 DoS、并发竞态全矩阵、KCP/QUIC/WebSocket
数据面、客户端本地界面与 store、**UDP 路径的 ACL 来源管控**等）本版**仍未系统
审计**，不要当成"已通过"。其中 `[acl]` 的覆盖面本版已如实标注：
**控制连接 + VNet + TCP 代理 accept + vhost accept（HTTP/HTTPS/tcpmux）**，
**UDP 代理端口 / xtcp 牵线 UDP / 面板不在内**（详见 （已并入本文档）
F7-1 的"边界"段）。

---

## 六、第 7 / 8 两轮的策略总结

- **登记不等于定论**：B-1 第七轮被登记为"疑似"（没有实弹链），第八轮打通后
  确认高危 —— 于是它从"一条待办"变成"最重的一条修复"。
- **两侧必须对齐**：F8-L1（头区 vs 全文）、F8-L2（服务端全名 vs 客户端本地名）
  都是"同一件事两处口径不同"，与第七轮 D7-1 / F7-1 同类。
- **注释也是产品**：F8-L3 的实现是对的，错的是注释 —— 用户按注释配就会 401，
  "文档里的行为"必须与代码一致。
- **撤离也要管**：F8T-1 提醒"访问方走了之后"同样是数据面的一部分，
  半开连接的释放语义要有明确上界。


<!-- ===== 7/14 第 9 轮 ===== -->

> **日期：2026-10-17** · **轮次：第 9 轮**

---

# NFrp v0.5.9 安全修复报告（第九轮）

日期 2026-10-17
来源 第九轮安全审计 —— 覆盖 v0.5.8 发版总结**逐字声明"仍需系统审计"**的面
范围 ACL 覆盖面（UDP / xtcp 牵线 / 管理面板）· KCP 会话表 · 资源耗尽 · 并发竞态 · 客户端入口 · 传输层数据面
结果 **9 条成立**（4 中危 + 1 中危·功能回归 + 4 低危），全部已修、全部有回归测试
另有 **1 条预防性加固**、**9 条排除**（附实测反证）与如实记录的残余边界

---

## 〇、一句话概括

v0.5.8 的发版总结第七节自己写着：

> `[acl]` 覆盖面：**控制连接 + VNet 注册 + TCP 代理 accept + vhost accept**；
> **UDP 代理端口、xtcp 牵线 UDP、管理面板不在内**。

本轮把它当任务书：**三条"不在内"的路径全部实测确认、全部修好**。
随后把"资源耗尽 / 并发 / 传输层 / 客户端入口"逐面打穿，又打出 5 条成立项 ——
包括 **≈800× 的内存放大**（12 字节换 9.5 KB）与**时间上界被单字节绕过**（首字节后静默即永久悬挂）。
元验证还**两次打红了"已完成"的修复本身**（闸门位置放错、`None` 双关错杀合法流量）。
v0.5.8 声明未审计的 6 个面，本轮**全部系统覆盖**。

---

## 一、质量门（发布时的最终数字）

| 项 | 结果 |
|---|---|
| `cargo test --workspace`（**串行**） | ✅ **732 通过 0 失败**（v0.5.8 基线 725，本轮净 +7） |
| `cargo fmt --all -- --check` | ✅ 干净 |
| `cargo clippy --workspace --all-targets -- -D warnings` | ✅ **0 告警** |
| `cargo audit --no-fetch` | ✅ **exit 0 零漏洞**（184 crates / 1329 advisories） |
| 端到端冒烟 | ✅ **28 / 28** |
| 元验证 | ✅ 全部重跑：c9_3 **9/9**、c9_4 **15/15**、a9_3b **20/20**、a9_5 **11/11**、a9_7 **10/10**、d9_7b **6/6**；E9-0 12/12、E9-1 6/6、E9-2 8/8、C9-1 238→23.7 MB |
| 退回验证 | ✅ **11 个点位**全部退掉后变红、还原后复绿（含 1 处测试**挂死**的独立证据） |

**测试分布**：client 115 / common 344 / server-lib 232 / server-main 17 / e2e 24 = **732**

★ 本轮为 8 条修复 + 1 条加固改动了十余个源文件（含 **6 处函数签名**）
（`udp_proxy::spawn` / `run_session`、`p2p::run_rendezvous`、`dashboard::run`、
`KcpListener`、`quic::server_config` …）⇒ **没有破坏任何既有行为**
（净 +7 条新测试、冒烟 28/28 佐证）。

---

## 二、中危（5 条）

### E9-0 UDP 代理端口不受 `[acl]` 约束

#### 根因

`SecurityContext::check_ip`（ACL 唯一判定入口）在 v0.5.8 里只有 **4 处**调用：

| # | 位置 | 路径 |
|---|---|---|
| 1 | `serve.rs:737` | 控制连接握手 |
| 2 | `serve.rs:1572` | TCP 代理 accept（第七轮 F7-1 加的） |
| 3 | `vhost.rs:478` | vhost accept（第七轮加的） |
| 4 | `vnet.rs:489` | VNet 注册 |

而 `server/src/udp_proxy.rs` **零 `check_ip`**。

#### 实测（`tmp/audit9/_indep/verify_udp_acl.py`，**12/12 判据全过**）

服务端绑 `0.0.0.0`、`[acl] deny = ["<LAN>"]`，**只改源地址**：

| 场景 | 结果 |
|---|---|
| 不配 ACL，从 LAN 发 UDP | ✅ 通（`UDP-REPLY-HELLO-UDP`） |
| **同一条 ACL ⇒ 控制面登录** | ✅ **被拒**（证明 ACL 在起作用） |
| 从 `127.0.0.1`（放行）发 UDP | ✅ 通（正对照） |
| **从 LAN（被 deny）发 UDP** | ❌ **仍被转发**（内网服务收到包数 **1 → 2**） |

★ **唯一变量是源地址**，服务端与配置完全相同 ⇒ 铁证。

#### 影响

* **无需任何凭据**：任何能访问公网 UDP 端口的人都能把包送进内网服务；
* 管理员用 `[acl]` 表达"只允许某些来源"时，**UDP 代理完全不遵守**（静默失效）；
* UDP 无连接 ⇒ 内网服务收到的是**无来源校验的报文**；
* ★ **UDP 代理没有别的防线**（不需要认证），ACL 是**唯一**的来源管控手段。

#### 修法

`run_session` 新增 `sec` 参数，`recv_from` 后、转发前 `check_ip`；
拒绝时**静默丢弃**（不回包，也**不记 `seen_ips`** —— 被拒的 IP 不该获得回写资格）。

---

### C9-1 KCP 会话表无上限 —— 25 字节的 UDP 包换 15 KB 内存（放大 312×）

#### 根因

`common/src/frp/kcp.rs` 的 `accept()`：

```rust
// 新会话：conv 由发起方定，从报文头读出来照抄即可
let conv = u32::from_le_bytes(...);
let (tx, rx) = mpsc::unbounded_channel();
g.insert(from, tx);            // ← 键是源 SocketAddr（含端口），无条数上限
KcpStream::spawn_served(...)   // ← 每条会话 spawn 一个 task + 一个 channel
```

⇒ **对任意 UDP 源地址/端口无条件建会话**，且**没有条数上限**。

#### ★ 代码注释的定级依据是**错的**

`kcp.rs` 原注释写着：

> **1:1 占用，非放大** —— `rcv_queue` 装的是实际收到的数据，
> 攻击者要占用 8MB 就得真的发 8MB。

那个算法只算了"会话里堆的数据"（确实是 1:1），
**漏掉了会话本身的开销**（HashMap 条目 + tokio task + channel + 缓冲）。

#### 实测

**成本曲线**（`c/c9_1b_kcp_cost.py`）：

| 会话数 | 峰值内存 | 每会话 |
|---|---|---|
| 1000 | 23.4 MB | 16.6 KB |
| 5000 | 82.7 MB | 15.5 KB |
| 15080 | **233.2 MB** | 15.3 KB |

**严格线性、无拐点**。

**决定性判定**（`c/c9_1c_decisive.py`，4/4）—— 持续灌 20 秒，每包 **25 字节**：

```text
上行 757 KB（31000 个包）⇒ 内存峰值 238.0 MB（增量 +230.7 MB）
★ 放大比 = 312×（1 字节上行 → 312 字节内存）
服务端 alive=True（危害是内存，不是崩溃）
```

#### 影响

* **无需任何凭据**；
* **放大 312×**：757 KB 上行把内存推到 238 MB；
* 灌入 > 15 秒时内存维持在数百 MB 高位（回收赶不上灌入）；
* **KCP 默认不启用**（需显式配 `kcpBindPort`）—— 这是它不到高危的真实原因。

#### 修法

新增 `MAX_KCP_SESSIONS = 1024`，超限时**丢弃新会话**（不回包，让发起方按 KCP 重传超时放弃）：
* **不动已有会话** —— 上限满了不影响正在服务的连接；
* **不按源 IP 限** —— 同一 NAT 后可能有多个合法客户端，按 IP 会误伤；
* **丢弃日志走 `RateLimited` 折叠**（5 条 / 10s + 压制计数汇总）—— 该分支按
  **被丢弃的数据报数**触发、与上限无关，不折叠就能被未认证对手无限刷日志
  （发布前订正了一处"日志量受 `max_sessions` 约束"的错误自注）。

**元验证**：灌 964 KB（**比修复前更多**）⇒ 内存峰值 **238 MB → 23.7 MB**，放大比 **312× → 17×**。

---

### C9-3 未认证 yamux 凭空开流 —— 12 字节换 9.5 KB（放大 ≈800×）

#### 根因

未认证连接进入 yamux 分支后，mux accept 循环**对每条流无条件 spawn 一个任务**；
每条任务在 spawn 那一刻就按 future 大小立即分配 ~9 KiB；
而 yamux 本身**没有"每会话流上限"**（超过 512 只回 GoAway、**不关闭会话**）。

#### 实测（`c/c9_3_yamux_flood.py`，**13/13 判据全过**）

| 观测 | 数据 |
|---|---|
| 单会话 500 流 | +4.5 MB（≈9.2 KB/流），会话保持 |
| 22 会话 / 11030 流 | **+100.0 MB（9504 B/流）** |
| 攻击者成本 | **129.3 KB + 22 fd** ⇒ **≈800×** |
| 每流一个任务 | 日志 `yamux stream 结束` 恰 **11012** 条（与预期吻合） |
| >512 流/会话 | 只回 GoAway、会话不关（攻击者不配合可继续占 fd） |
| 风暴期间正常转发 | ✅ 可用 |
| 断开回收 | 峰值 +100.0 MB → **+3.4 MB** |

#### 修法与两次"元验证打醒修复本身"

1. **初版闸门放在任务体内**（`handle_frp_stream` 里）→ 元验证 6/9 当场打红：
   11264 条流**仍然全量 spawn**，峰值 **+97.2 MB ≈ 未修复**
   （11264 × 9 KiB，闸门只限住了握手 CPU，没限内存）。
   → 补强：**闸门前移到 mux accept 循环、spawn 之前**（取不到名额丢这条流、
   会话保留）；**mux 通道 64 → 8** 形成反压（停滞会话最多囤 ~9 条流对象）。
2. 复跑 7/9 又抓出补强自身的语义缺陷：**`Option<Permit>` 的 `None` 双关**
   —— "没预取" 与 "免闸门" 共用同一个值，闸门满载时把**合法工作流**错杀。
   日志取证：16/20/25s 各 1 条**孤立**拒绝，peer 是合法客户端会话的端口
   （不在攻击端口段内），变体是"…**断开**"（任务体自取失败）而非循环里的
   "丢弃该流"。→ 改为三态枚举
   **`PreauthSlot::{Deferred, Preacquired, Bypassed}`**，语义唯一。

#### 终版元验证（`c/c9_3_verify_fixed.py`，**9/9**）

内存 **+17.0 MB** ✅、攻击期间/之后转发 ✅（工作流毫秒级完成，闸门拒绝
117 条**全部来自攻击流**）、停止后回收 +1.9 MB / 句柄 delta=17 ✅、无 panic ✅。

#### 遗留边界（如实记录）

持续满饱和时，**新的未认证握手（含合法客户端的重新登录）**仍需排 5s 队、
超时即拒；**已有会话及其工作流不受影响**。这是"全局 FIFO 名额"的固有代价。

---

### C9-4 未认证连接的时间上界可被单字节绕过

#### 根因

三条首字节路径没有时间上界：

* `0x00`（yamux 探测字节）后静默 —— **yamux 无 keepalive**；
* `0x16` / `0x17`（TLS 首字节）后静默 —— **rustls 自身不做握手超时**。

对照（有上界的两条）：不发任何字节 10s 被 `PROBE_TIMEOUT` 清掉；
明文 `'F'` 30s 被 `HANDSHAKE_TIMEOUT` 清掉。

#### 实测（`c/c9_4_timeouts_tls.py`，**11/11 判据全过**）

| 观测 | 数据 |
|---|---|
| `0x00` / `0x16` / `0x17` 单字节后静默 | t=12s / 33s / **50s 全部存活**（没有任何超时路径会碰它） |
| 500 条 `0x00` 静默 33s | **500/500 仍持**：句柄 +515 / 内存 **+6.4 MB**（无一被清理） |
| 囤积期间正常转发 | ✅ 仍可用（纯粹资源占用，不断服务） |

⇒ 与 C9-3 同源：没有时间上界 + 没有并发上限的驻留型占用。

#### 修法

* **TLS**：`TLS_HANDSHAKE_TIMEOUT = 30s`（`0x17` 与 `0x16` 两个分支都包）；
* **yamux**：**会话空闲看门狗** —— `SessionState{active, last_open}` +
  `CountedStream`（Drop 递减）+ `select!`(poll_next_inbound / 2s tick)：
  **活跃流为 0 且 ≥30s** 才关会话。合法 frpc 控制流全程活着（active≥1）⇒
  不误杀；"开一条注定超时的流再闲置"也被回收。

#### 元验证（**15/15**，两次回归复跑仍 15/15）

t=46s 探针全部 `closed`；囤积 40s 后 **0/300 存活**、句柄 delta=12；
看门狗日志 301 条 / TLS 超时 2 条；无 panic。

★ **探针缺陷 #2**：初版 `is_open` 被 rust-yamux 的 **RTT Ping**
（12 字节，10s 间隔，服务端会话建立即发）掩蔽 —— `recv(1)` 先摸到 Ping
首字节，把"已关"误判"仍开"（netstat/句柄/阻塞 recv 交叉钉死）。
改为"**先排干缓冲、再判 FIN**"后复跑全绿。

---

### A9-5 stcp/xtcp visitor 在"双方都没配 user"时被误拒（v0.5.7 引入的功能回归）

**脚本**：`a/a9_5_visitor_flood.py`（初测 6/11，失败项全同源）· 调试：`a/a9_5_debug.py`

* 基线：provider（stcp + `secret_key`）与 visitor 客户端**都登录成功**，
  但 visitor 本地端口配对后 echo 永远空（`b''`）；错误密钥的 12 次尝试
  **都被拒且有日志**（`visitor 密钥校验失败`）⇒ 流程本身走到了服务端校验；
* 根因（源码）：`visitor.rs::check_user` 在 v0.5.7（第六轮 D-2）加了一行
  `if visitor_user.is_empty() { return false; }` —— 而 **`user` 本来就是可选项**：
  双方都不配时官方 frps 走"空 `allow_users` ⇒ 只允许 provider 自己的 user"
  ⇒ `"" == ""` 放行。nfrp 把这条**合法默认路径**一并拒了
  ⇒ **默认配置下 stcp/xtcp visitor 完全不可用**。
* 旁证：同一 `check_user` 的既有测试注释自己写着"（除非 provider_user 本身
  是空）"——与实现矛盾。

**修复**：`allow_users` 为空时恢复官方语义 `provider_user == visitor_user`
（`"" == ""` 合法）；空身份**只在命中白名单的方向**被拒（`"*"` / 具名）。
安全语义不变：D-2 堵的是"空身份命中 `*`"，而登录已完成认证
⇒ 空 == 空 比的是"身份相同"，不是"匹配任意"。

**元验证**（**11/11**）：配对后 echo `b'ALIVE'` ✅；沉默 100/100 保持 ✅；
断开后 +25.6 MB → **+0.3 MB 完全回收** ✅；错密钥 12/12 拒 ✅。

---

## 三、低危（4 条）

### E9-1 xtcp 牵线 UDP 不受 `[acl]` 约束（纵深防御缺失）

* `p2p.rs` **零 `check_ip`**。牵线唯一的来源判定是第八轮 B-1 加的
  "与控制连接 IP 同源"（`same_host`）—— 那拦的是**冒充**，**不读 `[acl]`**。
* **实测**：`[acl] deny` 下，从被 deny 的地址发 HELLO，服务端日志照样
  `收到 HELLO peer=192.168.56.1:52673`，**没有任何 ACL 拒绝**。
* **为什么只定低危**：`hub.register` 要求 sid 对应的会话**已存在**，
  而会话由**已认证的控制通道**创建，控制通道**受 ACL 约束**
  ⇒ 攻击者进不来就没有 sid ⇒ 这是"如果将来某条路径能拿到 sid，ACL 不会兜底"的
  **纵深防御缺口**，不是当下可打的漏洞。
* **修法**：`run_rendezvous` 新增 `sec`，在**解析报文之前**判 ACL。

### E9-2 管理面板不受 `[acl]` 约束（纵深防御缺失，**非**认证绕过）

* **文档依据**（这是判定的关键，不是想当然）：
  * `security.rs:3` 把 ACL 定义为"**谁能连上来**"；
  * `assets/frps.toml` 写"`[acl]` **在认证之前执行**，被拒的连接连 token 都不用发"。
  * **两条都没把面板排除在外。**
* **实测**（`[acl] deny = ["127.0.0.1"]`）：

| 端点 | 无凭据 | 错凭据 | **正确凭据** |
|---|---|---|---|
| `/` | 401 | 401 | **200** |
| `/api/status` | 401 | 401 | **200** |
| `/metrics` | 401 | 401 | **200** |
| `/api/healthz` | **200** | 200 | 200 |

  而**同一条 ACL 让控制面登录被拒** ⇒ 证明 ACL 有效，只是没覆盖面板。
* **定性**：面板**有独立 Basic Auth**（无/错凭据一律 401）
  ⇒ 这是**纵深防御缺失**，不是认证绕过。
  ★ 与 E9-0 的关键区别：**UDP 没有别的防线，面板有**。
* **修法**：`dashboard.rs` 的 `accept` 后判 ACL；拒绝时 `drop(stream)`。
  `/api/healthz` **一视同仁** —— ACL 的语义是来源管控，不该有"某些端点例外"的隐含规则。

### A9-3 审计日志无轮转：1000 条/秒即可任意增长（仅 `[audit] enable=true` 时）

* **实测**（`a/a9_3_audit_growth.py`，11/11）：静默连接 0 审计行；
  ACL 拒绝**每连接恰 1 行**（~109 B）；8 线程灌 2s ⇒ **+11184 行（~1000 行/s）**；
  无任何轮转产物；100 行/s 推算 **37.4 MB/h 无上界**，且会挤爆 1000 条
  环形缓冲**淹没真实事件**。
* **修法**：`maxFileMB`（默认 64，**0 = 不轮转**）+ 单备份 `<path>.1`；
  **先释放文件锁再 rotate**（防死锁）；`written` 初值 = 既有文件大小
  （**重启不绕过阈值**）。
* **元验证**（`a/a9_3b_rotation.py`，**20/20**）：主文件 659 KB（≤1.1 MB）、
  备份 1048 KB、目录仅主 + 单备份、**备份末行完整 JSON**（轮转不切碎行）、
  轮转后继续可写；对照 `maxFileMB=0` 线性增长（1351 KB）；两阶段均无 panic。

### D9-7 Windows 上 uds 插件配置错误仅 DEBUG 可见（低危观察）

* **观察**：`unix_domain_socket` 插件配置在 Windows 上：**仅 DEBUG 级**一行
  「插件配置有误…只能在 Unix/Linux/macOS 上使用」；默认 info 级完全静默、
  无重试风暴、tcp 代理不受影响。
* **修法**：客户端**启动时**逐条预检 `Plugin::from_proxy`，配置错立即
  `warn` 点名（原先只在工作连接收尾以 debug 留一句，默认看不见）。
* **元验证**（`d/d9_7b_startup_warn.py`，**6/6**）：启动即 WARN
  （点名 `bad-uds` + 原因"只能在 Unix/Linux/macOS 使用（当前为 Windows）"）；
  正常代理登录 + 转发可用（故障隔离）；进程存活。

---

## 四、ACL 覆盖面总表（本轮核心产出）

| 路径 | ACL | 其它防线 | 结论 |
|---|---|---|---|
| 控制连接 | ✅ | 认证 | — |
| TCP 代理端口 | ✅（第七轮） | 无 | — |
| vhost（HTTP/HTTPS/tcpmux） | ✅（第七轮） | 部分有 Basic Auth | — |
| VNet 注册 | ✅ | token | — |
| **UDP 代理端口** | ❌ → ✅ | **无** | **E9-0（中危）** |
| **xtcp 牵线 UDP** | ❌ → ✅ | B-1 来源绑定（间接） | **E9-1** |
| **管理面板** | ❌ → ✅ | Basic Auth | **E9-2** |

### 回归测试：**结构不变量**（比功能测试更强）

新增 `vhost::tests::acl_必须铺满全部数据面入口`：

```rust
const MUST_HAVE_ACL: &[&str] = &[
    "serve.rs", "vhost.rs", "vnet.rs",
    "udp_proxy.rs", "p2p.rs", "dashboard.rs",
];
```

它守的是一个**结构不变量**：`server/src` 下每个接收外部连接的文件
都必须出现**真的在调用**的 `check_ip`。

★ 为什么用源码扫描而不是功能测试：功能测试只能覆盖"我已经想到的路径"，
而这一族缺陷的本质是「**新增了一条路径，忘了加 ACL**」——
**只有枚举文件才能防住它**。

---

## 五、已排除（9 条，都有实测反证）

| # | 线索 | 反证 |
|---|---|---|
| **A9-1** | 未认证连接打满 fd / 拖垮服务 | `HANDSHAKE_TIMEOUT=30s` 让连接**无法积攒**：灌 10000 条时服务端句柄恒 **~1.8k**（**8238 条已被超时清掉**），攻击期间正常转发与新登录均可用 |
| **A9-2** | 面板被规模拖垮 | 1200 条代理记录时 `/api/status` 仍 **1 ms**；并发 64 个 **20 ms 全成功**；期间业务转发不受影响 |
| **A9-6** | 万级配置 / 代理规模拖垮启动 | 420 ms 启动、7.6 MB 内存；**2000 客户端登录 0.52 s** |
| **B9-1** | `store` 并发 flush 丢数据 | **200 并发 × 5 轮 = 999 次写，零丢失**，JSON 始终合法 |
| **D9-1** | 三个 TLS 入站插件被畸形握手打崩 | **11 种畸形 ClientHello**（截断头/非法 content-type/SSLv2 风格/超长 SNI/非法版本…）后：客户端 **alive=True**、句柄 **+1**、攻击后正常握手仍成功 |
| **D9-2** | `store` 路径可被远程控制 | `ServerCmd`（`msg.rs:511`）字段只有 `id/op/proxy_name/proxy/reason` —— **协议里就没有 store 路径** |
| **D9-3** | v1 AES-128-CFB 的 IV 复用/可预测 | IV 用 **`OsRng`** 每次连接独立生成（`v1.rs:379`）；CFB 实现加密/解密都填**密文**（正确），有跨块边界测试 |
| **W9-1** | WebSocket 帧的 mask 位 / RSV 位 | **第四轮已修**：`ws.rs:409-426` 有**双向**校验（客户端帧必须带掩码、服务端帧不得带掩码、RSV 置位即拒）；`MAX_FRAME` / `MAX_CONTROL_PAYLOAD` 也都有上限 |
| **Q9-1** | QUIC 连接迁移 / 0-RTT | 用 quinn 默认（迁移启用、0-RTT 默认关闭）；ALPN 两端必须一致否则握手直接失败；证书策略与文档一致（只加密不验证） |

> ★ 命名说明：WebSocket 与 QUIC 这两条在早期草稿里曾占用 `C9-3` / `C9-4`
> 编号；本轮后半程发现的 **C9-3（未认证开流）/ C9-4（时间上界）** 是另外
> 两条中危，正式编号以本报告为准，旧编号作废（表中已改 `W9-1` / `Q9-1`）。

★ **D9-1 在 `panic = "abort"` 前提下尤其有价值** ——
  说明 rustls 的边界检查确实靠得住，没把客户端进程带下去。

**另有一批"正测通过"的防回归带**（不是排除线索，是主动攻过没打穿）：
B9-2 重连 10/10（服务端重启 0.3s 自动重连、连转 3 次）、B9-3 热重载 21/21
（含万级配置成本）、B9-4 端口砖化 6/6（60 轮同端口抢占 60/60 成功）、
D9-4 畸形 ClientHello ×2 轮 11/11、D9-5 `close_notify` 截断 25/25、
D9-6 本地面板并发一致性 20/20、A9-7 高速率未认证连接成本有界 10/10。

---

## 六、预防性加固（1 条，**当前不是漏洞**）

### C9-2 `quic::server_config(alpn)` 的缓存会忽略后续传入的 ALPN

#### 现象

```rust
static SERVER_CFG: OnceLock<quinn::ServerConfig> = OnceLock::new();

pub fn server_config(alpn: &[u8]) -> Result<quinn::ServerConfig> {
    if let Some(c) = SERVER_CFG.get() {
        return Ok(c.clone());          // ← 忽略本次传入的 alpn
    }
    tls.alpn_protocols = vec![alpn.to_vec()];   // ← 只有第一次生效
```

#### 为什么**当前不是漏洞**（必须精确，不能虚报）

全仓确实有**两个不同的 ALPN**：

| 常量 | 值 | 位置 |
|---|---|---|
| `frp::quic::ALPN` | `b"nfrp-frp"` | `quic.rs:32` |
| `p2p::ALPN` | **`b"nfrp-xtcp"`** | `p2p.rs:166` |

但 **`quic::server_config` 只有 2 处调用**（`quic.rs:143` / `:354`），**都传 `ALPN`**；
而 xtcp 的 `b"nfrp-xtcp"` 走的是 `client/src/p2p.rs:778` 里**独立的 `SERVER_CFG`**，
**不共用这个缓存** ⇒ 实际不存在串 ALPN。

⇒ **这是「靠巧合安全」**，不是当下可利用的缺陷。

#### 仍然加固的理由

它是个**等待被踩的坑**：将来若有人加第三个 ALPN 并复用 `quic::server_config`，
第二次调用会**静默拿到错误 ALPN 的配置**，症状是
`peer doesn't support any known protocol` 这种**极难排查**的握手失败
（错误信息完全指不到真正的原因）。

#### 修法

新增 `CACHED_ALPN`，缓存命中时**校验 ALPN 一致性**，不一致直接报错
（错误信息指明"不同 ALPN 需要各自独立缓存，参考 `client/src/p2p.rs` 的做法"）。

**元验证 / 退回验证**：新增测试 `缓存不能跨_alpn_复用`；
退回守卫后测试变红、还原后绿、sha256 一致。

---

## 七、方法论：元验证 + 退回验证抓到的失效

第七轮识别出「修复无效」「测试不足」之外的**第三种失效：测试测错了对象**。
本轮又抓到 **5 次**：

| 发现 | 测试为什么无效 | 靠什么修好 |
|---|---|---|
| **ACL 不变量测试** | 只做 `prod.contains("check_ip")` —— **把调用注释掉，字符串还在** ⇒ 测试照样通过 | 改 `has_real_check_ip()`（**排除注释行**） |
| **ACL 退回脚本 v1** | 注释掉 `if let Err(...) {` 一行 ⇒ **花括号失配、编译失败**；而脚本只看 `"FAILED"` ⇒ **误判"没红"** | 改**整块删除**（花括号配对计数）+ **三态判定**（红 / 编译失败 / 仍绿） |
| **C9-1 测试** | 逐轮 accept 但**丢掉了返回的 `KcpStream`** ⇒ 它的 Drop 立刻摘掉会话（诊断 `established=24 sessions_len=0`）⇒ **永远观察不到会话表** | **持有所有 `KcpStream`** |
| **A9-7 高压转发检查** | 按"尝试次数 == rate×15"触发；高压下实际只跑到 2750 次 ⇒ **检查从未执行**，`bool(None)=False` ⇒ 误判"转发挂掉" | 改**按时间**触发（`check_at = t_start + 5s`） |
| **C9-4 `is_open`** | 看门狗关闭后探针缓冲里是 `[12B yamux RTT Ping][FIN]`；`recv(1)` 先摸到 Ping 首字节 ⇒ "已关"误判"仍开"（netstat / 句柄 / 阻塞 recv 交叉钉死） | 探针改**先排干缓冲、再判 FIN**（`peer_status`） |

### 探针缺陷（3 条，全部先修探针、未据此下结论）

* **#1 A9-7 触发条件**：按"尝试次数"触发 ⇒ 高压下检查从未执行
  （已改按时间触发，复跑 10/10）。
* **#2 C9-4 `is_open`**：被 yamux **RTT Ping** 的 12 字节掩蔽（见上表）。
* **#3 A9-5 `dutil` 的 echo 从不关闭连接**：`Upstream._loop` 把每条 accept
  的 conn 塞进 `self.holds` 永久引用；echo 分支收到 EOF 只 `break`、
  **socket 从未真正关闭** ⇒ provider 中继按"本地对端还没关"的**正直半开
  语义**等待 ⇒ 服务端中继也等。表现是"断开后内存不回收（+14.0 MB，两次
  运行逐位相同）"，多波线性累积（+14.5 → +29.2 → +41.7 MB），第 6 波
  伴随**会话整体重连**（yamux 流上限）——全是探针伪象。
  判据实验（`a/_diag_closing_echo.py`，自带"EOF 即真正 close"的 echo）：
  3 波全部完美回收、日志 **300/300 条"转发结束"** ⇒ 服务端没有任何泄漏。
  **修探针**：`socket.timeout` ⇒ **continue（静默保持）**；EOF ⇒
  `finally close()`。（中间插曲：第一版直接 `finally close` 把"3s 静默
  读超时"也当退出路径 —— a9_5 复跑当场把"沉默连接被保持"判据打红
  （仍挂 0/100），随即修正为**仅 EOF 关闭**。**这正说明每条元验证判据
  都在真实起约束作用**。）

★ 另有**两次工具/环境**问题（不是结论问题）：
* **保留 mtime 会让 cargo 不重编** —— 本轮**两次踩到同一个坑**：
  早期 `shutil.copy2`（复原源码后增量编译读到退回版产物）、
  还原阶段 PowerShell `Copy-Item`（保留快照旧 mtime ⇒ 0.23s 空转、
  产物仍是退回版）。修法：复制后显式刷新 mtime 再构建。
  **验证判据**：release 构建若 0.2s 内 "Finished" 且警告仍含
  `Preacquired never constructed` ⇒ 产物还是退回版。
* 测试时序抖动（200 ms 超时不够，同一份代码 4.0s 过 / 0.75s 挂）
  ⇒ 给到 1 s + 减少发送数。

### 探针基线失败 6 次（全部先修探针，未据此下结论）

405 路径猜错 → 400 缺 `remote_port` → 端口冲突 → 时序抖动 →
store 文件初始不存在 → 无 openssl。

### ★ 元验证不是走过场：两次打红"已完成"的修复

C9-3 的修复**被元验证连续打红两次**（闸门放在 spawn 之后 ⇒ 内存不受限；
`None` 双关 ⇒ 错杀合法工作流），最终版本（`PreauthSlot` 三态 + spawn
前取额 + 已认证放行 + 通道反压）才通过 9/9。
**修复写完 ≠ 修复完成；只有元验证能证明修复完整。**

### 退回验证（11 个点位，全部"退掉→红，还原→绿"）

| # | 点位 | 退掉后的红证据 |
|---|---|---|
| 1 | `udp_proxy.rs`（E9-0） | ACL 不变量测试点红 `["udp_proxy.rs"]` |
| 2 | `p2p.rs`（E9-1） | 同上 `["p2p.rs"]` |
| 3 | `dashboard.rs`（E9-2） | 同上 `["dashboard.rs"]` |
| 4 | `kcp.rs`（C9-1） | 会话上限测试变红 |
| 5 | `quic.rs`（C9-2） | `缓存不能跨_alpn_复用` 变红 |
| 6 | `serve.rs` 闸门（C9-3） | c9_3 **8/9**：峰值内存 **+95.9 MB**（≈未修复） |
| 7 | `mux.rs` 看门狗（C9-4） | c9_4 **8/15**：0x00/0x16/0x17 探针 46s 全在线、300 囤积 0 清理、日志 0 条；单测 `活跃流结束后会话被回收` **FAILED** + `空转会话被空闲看门狗关闭` **挂死**（进程空转 ≥3 分钟，按 PID 结束，`test_rc=-1`） |
| 8 | `tls.rs` 超时（C9-4） | c9_4 的 TLS 两项 + 超时日志项全红 |
| 9 | `audit.rs` 轮转（A9-3） | a9_3b **12/20**：重启不计阈、无 `.1` 备份、主文件 2.88 MB 任意增长 |
| 10 | `visitor.rs` 身份（A9-5） | a9_5 **6/11**：基线配对即败（空身份被拒 `b''`）；单测 `空身份不能匹配星号白名单` **FAILED** |
| 11 | `client/src/main.rs` 预检（D9-7） | d9_7b **4/6**：启动告警缺失（`has_warn=False`） |

**完整红测试**（`--no-fail-fast`，跳挂死用例）：common **342 ok + 1 FAILED**、
server-lib **230 ok + 2 FAILED**（audit 轮转、visitor 空身份）、
client 115 ok、server-main 17 ok、e2e 24 ok。
还原后全量复跑：**732 / 0**，6 个元验证脚本全部回到全绿。

---

## 八、**没有**覆盖的面（如实记录）

v0.5.8 声明未审计的 6 个面，本轮**全部系统覆盖**：

| 面 | 状态 | 残余边界 |
|---|---|---|
| ① 资源耗尽与 DoS | ✅ **完成**（A9-1/A9-2/A9-6 排除；A9-3/A9-5/A9-7/C9-3/C9-4 成立修复） | 半开语义边界（下详）；满饱和时新未认证握手排队；KCP 需显式启用；未做递进速率梯度扫描 |
| ② 并发/竞态 | ✅ **完成**（B9-1 排除；B9-2 10/10、B9-3 21/21、B9-4 6/6 通过） | yamux 状态机深处、重连状态机细节、热重载其余字段 |
| ③ 传输层数据面 | ✅ **完成**（C9-1/C9-3/C9-4 成立修复；C9-2 加固；WS/QUIC 复核排除） | TLS 首字节被动指纹（未做流量分析） |
| ④ 客户端入口 | ✅ **完成**（d9_1/d9_4/d9_5/d9_6 通过；D9-7 修复） | Windows 上 uds 只有配置面预检（无法功能实测） |
| ⑤ UDP + xtcp ACL | ✅ **完成**（E9-0 / E9-1 成立并修复） | — |
| ⑥ 管理面板 ACL | ✅ **完成**（E9-2 成立并修复） | — |

**另有几点必须说明**：

1. **半开语义边界（探针缺陷 #3 的结论，照实收录）**：若真实目标应用在
   EOF 后**不主动关闭连接**，服务端按**正直半开语义**保持中继
   （fd 1 + 中继缓冲 ≈147 KB/条），上界 ≈ yamux 会话流上限
   （默认 512，量级 ~70 MB/会话），**会话重连即整体清零**。
   这与官方 frp 行为一致、**非服务端缺陷**；探针第一版正是错在
   "echo 从不关连接"，修好后 300/300 全回收。
2. **满饱和时的排队窗口**：C9-3 的全局闸门在持续满饱和时会让**新的未认证
   握手（含合法客户端重新登录）**排 5 s 队、超时即拒；已有会话及其工作流
   不受影响。这是"全局 FIFO 名额"的固有代价，发布说明中同样写明。
3. **KCP 那条的前提**：需服务端**显式启用 `kcpBindPort`**。
   未启用 KCP 的部署**不受影响**。
4. **六组并行审计因上下文耗尽全部中断**，只留下脚本骨架。本报告的所有结论
   **都是主审自己逐个面打出来的**（没有采信分工组结论）。


<!-- ===== 8/14 第 10 轮 ===== -->

> **日期：2026-10-17 ~ 2026-10-18** · **轮次：第 10 轮**

---

# NFrp 安全审计报告 · 第十轮（第 N 轮）

本文件是第十轮审计的完整记录，含两部分：

- **第一部分** · v0.5.10 发布复扫报告（2026-10-17）—— v0.5.10 发布正文引用的那一份（内容未改）；
- **第二部分** · 新维度深挖审计（2026-10-18 起）：Miri / ASan / TSan /
  cargo-vet + cargo-deny / PSF 状态机 / Phaedra 字段 fuzz / OIDC 核查。
  **2026-10-25 状态**：已完成部分见本文件；官方 0.71 兼容、NatHole、SSH 网关、
  pprof、HTTP 插件等收尾见 第 16 轮。
  仍未完成的 TSan / Linux TUN Miri / 真实 IdP e2e 等也在 ROUND16 末尾列明，
  不要把它们误读成“已通过”。

---

# 第一部分 · NFrp v0.5.10 安全复扫报告（2026-10-17）

日期 2026-10-17
来源 第十轮安全审计 —— 对 **v0.5.9 正式发布产物**做全量复扫（第四~九轮全部电池逐项重跑 + 质量门）
结果 **0 条新增产品漏洞**；修复 **8 个点位**的审计探针/编排器自身缺陷（修复后全部重跑变绿）
另有 12 变体体积实验与性能基准 —— 所有**有行为代价**的体积优化经裁定不采用；性能采用行为中性 `TCP_NODELAY`

---

## 〇、一句话概括

本轮任务书是对已发布的 v0.5.9 二进制做全量复扫。约 100 项电池逐项重跑、质量门全绿：
**没有打出任何新的产品漏洞**。过程中变红的 8 个点位（r6-web-b0、webauth/e1、healthssrf/e8、
rebind/c03、r6-e2e、r5-h1、r5-h3）全部分诊为**探针自身的问题**（误杀规则、判据校准、
锚点过期、编排器缺口），逐条修复后重跑全绿 —— 这些修复让以后每一轮电池的证据链更可信。

---

## 一、复扫范围与方法

- 复扫对象 = `<构建目录>\release`（与 v0.5.9 发布包逐字节一致，已另存快照防覆盖）。
- 电池分两批：主批约 100 项逐项分诊复跑 + 收尾批 40 项覆盖点验。
- 方法学：动态端口、逐项独立日志留档、只清自己的进程（精确到 PID/名）、
  失败项一律"修复 + 重跑"不豁免、Python 侧统一 UTF-8。
- 质量门：`build` / `fmt --check` / `clippy -D warnings` / `test --workspace` / `audit`（见第四节）。

## 二、探针/编排器缺陷与修复（8 个点位）

1. **`cleanup_mine.py` 宽泛子串误杀**（r6-web-b0 假红）：清理规则按命令行子串匹配，
   连同主脚本一起杀掉；根因还叠加 Windows workbuddy venv 的 `python.exe` 是
   redirector（`getppid()` 不指向直接调用者，按父进程跳过无效）。
   修：规则收窄为 `nfrp-client` / `nfrp-server` / `fake_frps.py` 三个精确目标。
2. **e1 CSRF 判据拆两组**（webauth）：「缺头 / 头名不等价」必须 403；
   「值任意 / 头名大小写等价」不得按 403 处理（与第九轮排除 #2 的"只判存在性"结论对齐）。
3. **e1 Basic 认证判据**（webauth）：RFC 7235 允许的 scheme 大小写 / 多空格形式放行（200）；
   缺头 / 空密码 / 错密码一律 401（与第九轮排除 #9 的 `constant_time_eq` 语义对齐）。
4. **e8 独立哨兵**（healthssrf）：改用专用哨兵串 `RPROBE` + C 段
   "E-1 拒绝语义"断言（对 `localhost:` / 内网地址下发断言拒绝），消除锚点词误判。
5. **c03 判据翻转**（rebind）：J4/J5 按修复后语义翻转为正向断言；
   新增 J6 会话键格式判据（`-[0-9a-f]{8,}$`）覆盖第九轮 D9 修复。
6. **r6-e2e 编排器重写**：电池原指向半成品辅助脚本（裸跑必然 `IndexError`）。
   新编排器完成**真正的 KCP 端到端**：服务端开 `kcp_bind_port`、客户端
   `[transport] protocol="kcp"`、代理 → 回显后端，判据 6/6
   （KCP 链路建立 → 登录成功 → 代理注册成功 → 经 remotePort 的 1020B 原样回显）。
   ★ 附带纠正一条**工具层面的假基线**：历轮 KCP 测试里"客户端连上"实际只建立了
   本地套接字（拨号指向 TCP 口、未完成登录）——**产品行为正确**，属测试编排问题；
   本编排器是第一份真正完成 KCP 登录的端到端证据。
7. **r5-h1 / r5-h3 元验证锚点过期**：两个"退掉修复 ⇒ 测试必须变红"脚本的锚点
   与 v0.5.6 重构后的源码文本不一致（**保护本身都在**：`dashboard_exposed_after_reload`
   仍取运行期 `live_view`；`store.rs` 两处 `validate_remote_proxy` 仍拦）。
   修：锚点更新为当前文本；并补上**严格退出码** —— 此前两脚本即使"没抓到缺陷"
   也恒返回 0（静默假绿），现在未抓到缺陷即非零退出。
   （重跑证据：h1 退掉后 2 条测试红、h3 退掉后 3 条测试红，源码随后按字节还原。）

## 三、复扫结论

- **无新增产品漏洞**；v0.5.9 的 9 条修复 + 1 条加固在复扫中全部保持生效。
- 唯一实质性"发现"在工具链层面（KCP 假基线），已在第二节第 6 条记录。

## 四、质量门（发布时最终数字）

| 项 | 结果 |
|---|---|
| `cargo test --workspace` | ✅ **732 通过 0 失败**（7 个 target；与 v0.5.9 相同 —— 本版未新增/修改测试） |
| `cargo fmt --all -- --check` | ✅ 干净 |
| `cargo clippy --workspace --all-targets -- -D warnings` | ✅ **0 告警** |
| `cargo audit` | ✅ exit 0 |
| 全量复扫电池 | ✅ 约 100 项全绿（含本报告修复后的 8 个点位重跑） |
| 元验证（退回 + 还原） | ✅ h1 抓到 2 红 / h3 抓到 3 红，均按字节还原 |

## 五、体积与性能（实验记录）

- **体积**：12 变体实验（源码副本，绝不触碰本体）。最大无损候选 combo2
  （clapmin + envstub2）= **−8.62% / −8.41%**；因**有行为代价**
  （日志"模块定向语法"失效 / CLI 无颜色与拼写建议）经裁定**全部不采用**。
  其它：lld −0.12%、webpki1 ±0、noeh/lld_noeh 在 Windows 编不出、
  hot3/hotc 反而 **+8~10%**、buf512 ±0。
- **性能**：hot3 / hotc / buf512 在交错复测下无稳定收益（机器背景负载 ~35%，噪声 ±20%）⇒ 不采用。
  唯一采用：数据面 accept 入口补 `TCP_NODELAY`（行为中性，与 vhost / vnet 口径一致）。
- ⇒ **0.5.10 二进制尺寸与 v0.5.9 完全相同**（3,439,104 / 3,494,400 B）。

## 六、兼容性

- 无配置文件变更、无行为变更（除 TCP 套接字选项）。
- `frps -v` / `frpc -v` 仍输出裸 `0.71.0`；与官方 frpc 0.71.0 互通不变。

---

# 第二部分 · 新维度深挖审计（2026-10-18 起）

> 覆盖前九轮未覆盖的面：**Miri / ASan / TSan / cargo-vet + cargo-deny / PSF 状态机 /
> Phaedra 字段 fuzz / OIDC 核查**。纪律：生产代码默认只读，只有可复现证据才允许最小补丁
> （含"退掉补丁 ⇒ 测试变红"元验证）；逐 Stage 落盘；未执行项如实记录原因。

## Stage 0 · 环境、基线质量门与靶点清单

### 0.1 审计对象与身份链

- 源码 = `<工作区>\nfrp`（0.5.10）。与 v0.5.10 源码快照 `tmp\nfrp-src-0510.tar.gz`
  逐文件 SHA256 比对：**101 相同 / 0 内容不同 / 0 仅快照有 / 8 仅本体有（全部 `dist\*` 发布产物）**
  ⇒ 当前源码与发布快照逐字节一致（证据：`tmp\audit-r10\diff_snap.py`）。
- 发布件链（发布日已逐字节核验）：`release\nfrp-server.exe`（`BF9C7D99DA7DF82B…`）、
  `release\nfrp-client.exe`（`1126777622078928…`）= dist zip 内容 = GitHub 发布资产。
  尺寸 3,439,104 / 3,494,400 B。今日复核：该批 release 产物未被触碰（mtime 仍 2026-10-17 23:01）。

### 0.2 环境

| 项 | 值 |
|---|---|
| OS | Windows 11 10.0.26200，12 逻辑核 |
| rustc / cargo | 1.98.1（x86_64-pc-windows-msvc，default；另装 gnu） |
| 已装 target | linux-gnu / linux-musl / aarch64-linux-musl / android ×2 / windows-gnu |
| Python | 3.13.15 |
| CARGO_HOME / CARGO_TARGET_DIR | `<CARGO_HOME>` / `<构建目录>` |

日志：`tmp\audit-r10\gates\environment.txt`。

### 0.3 基线质量门（当前源码全量重建后 —— 全绿）

| 门 | 命令 | rc |
|---|---|---|
| build | `cargo build --release -p nfrp-server -p nfrp-client` | 0 |
| fmt | `cargo fmt --all --check` | 0 |
| clippy | `cargo clippy --workspace --all-targets -- -D warnings` | 0（0 告警） |
| test | `cargo test --workspace` | 0 —— **732 通过 / 0 失败**（7 个 target，与发布时一致） |
| audit | `cargo audit` | 0 |

日志目录：`tmp\audit-r10\gates\`。

### 0.4 ⚠ 环境事件：共享 target 目录里其他 Agent 的陈旧产物（假红，已排除）

- 首跑 `cargo test` rc=101：3 个 client `store` 安全测试红
  （`merge_initial_也要挡住危险条目` / `store_里四种本机资源字段都要拦` /
  `store_里的危险字段必须在恢复时被拦下`），且 cargo 认为"无需重编"。
- 定位证据：该测试二进制 `debug\deps\nfrp_client-e51a…exe` mtime = **2026-10-17 23:37**
  （另一 Agent 时段）；panic 行号 496/538/585 对当前源码 516/558/603（差 20/20/18 行）；
  server 侧 replay 出 `live_view` never used 伪警（当前源码 `reload.rs:309` 正在使用它）
  ⇒ **二进制来自另一棵源码树**，与当前源码无关。
- 处置：备份该产物与哈希（`tmp\audit-r10\backup-20261018\`）→ `cargo clean -p`（dev 档）
  → 当前源码全量重建 → 732/0 全绿，3 个原红测试全部 ok、伪警消失
  （测试二进制 mtime 更新为 2026-10-18 11:02）。
- 结论：**产品源码基线干净**。运维注：共享 `CARGO_TARGET_DIR` 的多人/多 Agent 场景，
  跑门前先 `cargo clean -p`。

### 0.5 靶点清单（后续 Stage 的目标面）

- **unsafe**：命中 10 行，其中 9 处真实 `unsafe` 全部在 `common\src\vnet\tun_linux.rs`
  （close/open/ioctl ×5、read/write ×2、fcntl ×2；非 Linux 编译不到），
  另 1 行为 `client\src\store.rs` 注释提及。⇒ Miri 的 unsafe 可达面小。
- **并发原语**（`tmp\audit-r10\inventory.out.txt`，35 个文件）：spawn 93 / Mutex 69 / mpsc 48 /
  Atomic 43 / RwLock 36 / OnceLock 15 / watch 14 / Semaphore 11 / static 7 / Notify 4。
  高密度点：`server\src\serve.rs`（spawn 16、Semaphore 6）、`client\src\plugin_bridge.rs`
  （spawn 10）、`server\src\registry.rs`（Mutex 14）、`server\src\reload.rs`（RwLock 15）、
  `server\src\pool.rs`（Mutex 5 + Notify 2）、`common\src\frp\mux.rs`、`common\src\frp\kcp.rs`。
- **既有缺口（沿基线口径）**：OIDC 无 e2e；官方抓包向量不可复现。

### 0.6 Stage 计划与状态

| Stage | 内容 | 状态 |
|---|---|---|
| 1 | Miri（nightly；可编译测试子集；并发项 many-seeds） | **部分完成**：编译 362 测试；`frp_config` 38/38 + WS 纯函数 1/1 通过；tokio/mio Windows IOCP 不可执行；Linux TUN 未覆盖（详见文末 Stage 1 节） |
| 2 | ASan / TSan（Windows MSVC 先试；TSan 走云端 Linux 或如实记未执行） | **部分完成**：ASan 下 `nfrp-common` 371/371、`nfrp-server` 238/238 通过；TSan 在 Windows MSVC 不可用，未执行 |
| 3 | cargo-vet + cargo-deny（供应链） | **部分完成**：`cargo deny check` 四项全绿；`cargo audit` 修复 3 条通告后清零；`cargo vet` 仅初始化 184 条 exemption，**不等于已审计** |
| 4 | PSF 状态机（不可得则降级手工状态探针） | **降级完成**：新增真实 e2e 乱序消息探针，服务端不崩且后续合法注册成功 |
| 5 | Phaedra 字段 fuzz（不可得则降级定向变异） | **降级完成**：1200 次确定性 TOML 变异，解析器未 panic |
| 6 | OIDC 核查（代码路径实测） | **部分完成**：27 个 OIDC 单测全过（JWT/JWKS/claims/subject 绑定）；无真实 IdP 端到端 |

（本报告为**进行中**状态，后续 Stage 逐段补充。）

---

## 附记 · 发布通道维护（2026-10-18，非审计 Stage）

- **源码同步**：GitHub `main` 由 `26a7cea`（0.5.9 源码）推进到 `c72d61d` —— 提交
  `sync v0.5.10 source (TCP_NODELAY + version bump)`，5 文件（Cargo.toml / Cargo.lock / README.md /
  server/src/serve.rs / 第 10 轮）。其中 ROUND10.md 采用**发布日快照版**
  （`080D93855C3B661E…`），使该提交树与 v0.5.10 源码快照逐字节一致；本地续写版（本文件当前内容）
  待本轮结束后再推送。tag `v0.5.10` 强移至 `c72d61d`（原先误指 0.5.9 源码）；tag `v0.5.9` 不动。
  推送后独立核验 7/7 通过（`tmp\audit-r10\ghsync\verify_sync_0510.py`）。
- **发布正文占位符回填**：Release v0.5.10 正文与 `dist\RELEASE_v0.5.10.md` 中残留的
  `BENCH_LINE_PLACEHOLDER` 已补为终版同机对照实测：中位吞吐 **453（0.5.9）vs 482（0.5.10）MB/s**、
  16B 往返 p50 均 0.13~0.22 ms（交错 4 轮 × 4 迭代；原始数据 `tmp\audit10\bench-final-*.json`、
  统计脚本 `tmp\audit-r10\ghsync\bench_stats.py`）——差异处于本机噪声带（±20~40%）内，**无可靠差异**。
  GitHub 正文 PATCH 后与本地文件逐字节一致（2689 字符）。
- **发布后全量复核**（c 版脚本，抗网络抖动）：7 个资产全部重新下载成功；SHA256 与
  `SHA256SUMS.txt` 一致；与本地原件逐字节一致；Ed25519 验签双路通过（release.py rc=0；OpenSSL
  「Signature Verified Successfully」；公钥指纹 `763896b5d759c6cbe1f208c3c35c9f71`）。
- **CI 现状（既有，非本次引入）**：GitHub Actions 自引入（2026-09-25）至今共 239 个 run，
  仅 1 次全绿（9/25 `b68f48c`，当日修 musl 后）；10 月起全部失败，形状稳定 ——
  `unit tests (ubuntu/macOS)` 与 `fmt / clippy` 红，**Windows 单测 / e2e 冒烟 / 两条 musl 交叉编译绿**。
  本机质量门（fmt / clippy 0 告警 / 732 通过）不受影响；Linux/macOS 单测通道与 clippy 通道
  当前不可用，记为**待专项**。

---

# 第二部分 · Stage 1「Miri」实跑记录（2026-10-24）

> 本节只记录**实际执行**的内容与硬限制；没有跑到的部分明确写“未执行”，不把
> “Miri 能编译”当成“内存安全已证明”。

## 1.1 环境

| 项 | 值 |
|---|---|
| 主机 | Windows 11 10.0.26200（本地） |
| rustc | `1.101.0-nightly (8006091eb 2026-10-17)` |
| cargo-miri | `miri 0.1.0 (8006091eb7 2026-10-17)` |
| target | `x86_64-pc-windows-msvc`（nightly 仅装此 target） |
| Miri flags | `-Zmiri-disable-isolation -Zmiri-strict-provenance` |
| CARGO_TARGET_DIR | `D:\cargo-target-miri`（与正常构建隔离） |

## 1.2 编译门

命令：

```text
cargo +nightly miri test -p nfrp-common --lib --no-run
```

结果：**成功**。`nfrp-common` 及其依赖（tokio、rustls、ring 相关构建脚本等）在
Miri sysroot 下编译通过；证据 `tmp\miri_common_compile.txt`。
测试清单共 **362** 个（`tmp\miri_common_list.txt`，`-- --list`）。

## 1.3 已实际跑通的子集

### A. 配置解析/兼容层（38/38 通过）

```text
cargo +nightly miri test -p nfrp-common --lib frp_config:: -- --test-threads=1
```

结果：

```text
running 38 tests
...
test result: ok. 38 passed; 0 failed; 0 ignored; 0 measured;
324 filtered out; finished in 423.70s
```

证据：`tmp\miri_frp_config.txt`。

覆盖点包括：TOML/INI 的未实现字段识别与大小写折叠、`auth`/`transport` 子表、
`visitors`、`allow_ports`、`subdomain_host`、`healthcheck.httpHeaders`、
`metadatas`、示例配置加载、字段优先级等。**未发现 Miri UB/越界/未初始化读。**

### B. WebSocket 纯函数（1/1 通过）

```text
cargo +nightly miri test -p nfrp-common --lib ws::tests::accept_key_matches_rfc_vector -- --test-threads=1
```

结果：`1 passed; 0 failed; ... finished in 0.46s`；证据 `tmp\miri_ws_one.txt`。

## 1.4 未能执行的子集（硬限制）

对 `ws::` 整个模块执行时，第 2 个测试
`ws::tests::binary_payload_survives_including_invalid_utf8` 在 Miri 下直接报：

```text
error: unsupported operation: can't call foreign function `CreateIoCompletionPort`
on OS `windows`
  --> mio-1.2.3/src/sys/windows/iocp.rs:57:28
```

根因：该测试用 `#[tokio::test]`，tokio 的 Windows IO driver 初始化 `mio` 的
IOCP；Miri 不支持这个 Windows FFI。**不是 nfrp 的 UB**，是 Miri/Windows 运行时限制。
证据：`tmp\miri_ws.txt`（16 个 ws 测试，第 1 个通过后中止）。

尝试补 `x86_64-unknown-linux-gnu` nightly target（让 mio 走 epoll）时，
`rustup +nightly target add` 在 300 秒内未完成，target 仍未安装；为避免把
网络等待写成“已执行”，本节不声称 Linux target 已跑。

另外：本仓库唯一的真实 `unsafe`（TUN 设备）在 `#[cfg(target_os = "linux")]`
下编译，Windows 的 Miri 根本不会实例化它；因此 **Stage 1 没有覆盖 Linux TUN 的
unsafe 路径**。要完整覆盖，需在 Linux 主机装 nightly + miri + rust-src 后重跑
（云端旧机内存/时间未在本轮尝试）。

## 1.5 Stage 1 结论

- 可编译性：**通过**（362 个测试的 Miri 构建）。
- 纯 Rust 配置解析子集：**38/38 通过**，无 Miri 报错。
- WebSocket 纯函数：**1/1 通过**。
- tokio/mio 网络测试：**Windows Miri 不可执行**（IOCP FFI），未用“跳过”伪装成全绿。
- Linux TUN unsafe：**未覆盖**。
- 因此 Stage 1 状态记为 **部分完成（partial）**，不能写成“Miri 全量通过”。

后续补齐命令（Linux）：

```bash
rustup toolchain install nightly --component miri rust-src
rustup +nightly target add x86_64-unknown-linux-gnu
MIRIFLAGS="-Zmiri-disable-isolation -Zmiri-strict-provenance" \
  cargo +nightly miri test -p nfrp-common --lib -- --test-threads=1
```

（在 Linux 上还要单独对 `common/src/vnet/tun_linux.rs` 的 unsafe 路径做定向测试。）

---

# 第三部分 · Stage 2–6 实跑记录（2026-10-24，OpenCode）

> 本节只写**实际执行**的命令与结果；不可用的工具/平台明确写“未执行”，
> 不把“能编译”“初始化了配置文件”当成“已证明安全”。

## 2.1 Stage 2：ASan / TSan

### ASan（实际通过）

环境：Windows 11，`rustc 1.101.0-nightly`，target `x86_64-pc-windows-msvc`，
`rust-src` 已安装，`RUSTFLAGS=-Zsanitizer=address`，`-Zbuild-std`。

```text
cargo +nightly test -p nfrp-common --lib -Zbuild-std \
  --target x86_64-pc-windows-msvc -- --test-threads=1
# test result: ok. 371 passed; 0 failed; ... finished in 17.15s

cargo +nightly test -p nfrp-server -p nfrp-client --lib -Zbuild-std \
  --target x86_64-pc-windows-msvc -- --test-threads=1
# test result: ok. 238 passed; 0 failed; ... finished in 14.43s
```

另外对 `frp_config::` 38 个测试单独跑过 ASan，全部通过。
没有出现 `ERROR: AddressSanitizer` / `SUMMARY: AddressSanitizer`。
证据：`tmp\asan_common_final2.txt`、`tmp\asan_server_client.txt`、`tmp\asan_common_frp_config.txt`。

### TSan（未执行）

Windows MSVC 的 Rust TSan 不受支持；本轮没有 Linux 构建机可用，
因此**没有**运行 TSan，也没有用 ASan 的结果替代 TSan 结论。
遗留并发风险仍需 Linux + nightly TSan 定向跑 `server\src\serve.rs`、
`server\src\pool.rs`、`common\src\frp\mux.rs`。

## 2.2 Stage 3：供应链

### 实际发现并修复（有通告 ID）

`cargo audit` 首次运行命中：

| 组件 | 版本 | 通告 | 处理 |
|---|---|---|---|
| `rustls-webpki` | 0.103.15 | RUSTSEC-2026-0382（证书链可能接受不受信中间 CA） | 升到 0.103.16 |
| `webpki-roots` | 1.0.9 | RUSTSEC-2026-0381（内置根含不受信 emSign 中间 CA） | 升到 1.0.10 |
| `tokio` | 1.53.1 | RUSTSEC-2026-0386（`AsyncFd` I/O safety，unsound） | 升到 1.54.1 |

升级后 `cargo audit` 输出为空（0 vulnerabilities / 0 warnings）。
证据：`tmp\cargo_audit.txt`（修复前）、`tmp\cargo_audit_final.txt`（修复后）。

### cargo-deny

新增 `nfrp\deny.toml`（许可证白名单、禁用 wildcard、未知 registry/git 源、
RustSec advisory 数据库）。最终：

```text
advisories ok, bans ok, licenses ok, sources ok
```

证据：`tmp\cargo_deny_final.txt`。许可证为常见宽松/弱 copyleft 组合，
`webpki-roots` 的 `CDLA-Permissive-2.0` 已显式列入。

### cargo-vet（仅基线，不是审计）

`cargo vet init` 生成 `nfrp\supply-chain\{config.toml,audits.toml,imports.lock}`，
`cargo vet` 输出：

```text
Vetting Succeeded (184 exempted)
```

**184 条全部是 exemption，不是人工审计结论。** 这一步只证明工具链能跑、
依赖树能锁定；后续要么补真实 audit，要么引入可信 imports 后删除 exemption。
证据：`tmp\cargo_vet.txt`、`tmp\cargo_vet_final.txt`。

## 2.3 Stage 4：PSF 降级（手工状态探针）

PSF 工具本轮不可得，降级为真实服务端 e2e 探针：
登录后把 `NewWorkConn` / `NewVisitorConn` 误发到**控制连接**，随后做一次
合法 `NewProxy` 注册。结果：服务端不崩、不断线，合法注册成功。

```text
cargo test -p nfrp-server --test e2e \
  out_of_state_messages_do_not_kill_control_session -- --nocapture
# 1 passed
```

证据：`tmp\stage4_state_test.txt`；代码在 `server\tests\e2e.rs`。

**未覆盖**：完整状态机枚举（登录前/后、代理注册中、关闭中、心跳超时交叉）、
并发多连接状态竞争；这些仍需 PSF 或自建状态模型。

## 2.4 Stage 5：Phaedra 降级（定向变异）

Phaedra 不可得，降级为确定性 TOML 定向变异：3 个种子 × 400 次
（替换/删除/插入），共 1200 次，分别喂给客户端和服务端解析器；
`Ok`/`Err` 都接受，**panic 即失败**。

```text
cargo test -p nfrp-common --lib \
  frp_config::tests::定向变异配置不应_panic
# 1 passed
```

证据：`tmp\fuzz_mutation_test.txt`；代码在 `common\src\frp_config.rs`。
这不是覆盖率 fuzz，没有发现新漏洞；只证明这 1200 个变异没有把解析器带崩。

## 2.5 Stage 6：OIDC 核查

实际执行：

```text
cargo test -p nfrp-common --lib auth::oidc:: -- --test-threads=1
# test result: ok. 27 passed; 0 failed
```

覆盖：JWT 分段解析、base64url、`exp`/`nbf`/`iss`/`aud`、`alg=none` 拒绝、
RSA/ES256/ES384 验签、JWKS key 解析、`skip` 语义、subject 与会话 `run_id` 绑定。

**未覆盖**：真实 IdP 的 discovery + JWKS 拉取 e2e、密钥轮换、网络错误/超时、
恶意 JWKS（超大 key、重复 kid、非预期 alg）。代码路径只做了单元级验证。

## 2.6 Stage 2–6 结论

- 真实执行：ASan、cargo-deny、cargo-audit、cargo-vet（基线）、e2e 状态探针、
  定向变异、OIDC 单测。
- 明确未执行：TSan、完整 PSF、Phaedra、真实 IdP e2e、Linux TUN Miri。
- 真实修复：3 条 RustSec 依赖通告；没有把它们写成“0day 已修”。
- 新增质量门：`deny.toml`、ASan 可重复命令、1200 次变异测试、乱序状态 e2e。

---

# 第四部分 · README 限制①批次3：TLS 证书组（2026-10-24）

实现范围：官方 0.71 的 `[transport.tls]` 证书组。

- 服务端：`certFile` / `keyFile` 自定义证书；`trustedCaFile` 启用 mTLS。
- 客户端：`certFile` / `keyFile` 在 TLS 握手时出示客户端证书。
- 三者为空时保持官方默认（自签名、不校验客户端）。
- 只配 cert 或只配 key：启动与 `--check` 都明确报错，不静默退回自签名。

关键代码：

| 文件 | 内容 |
|---|---|
| `common\src\config.rs` | 5 个字段 + 默认值 |
| `common\src\frp_config.rs` | `[transport.tls]` hoist；从 unsupported 清单移除；`webServer.tls.*` 按路径补扫，避免同名误洗白 |
| `common\src\frp\tls.rs` | PEM helper、`server_config_from_pem_with_ca`、`configure_server_tls`、`validate_server_tls_files`、客户端身份、`ClientTlsOptions` |
| `client\src\main.rs` | 传入客户端证书/私钥 |
| `server\src\serve.rs` | accept 前安装证书；预检校验 |
| `common\src\config.rs` 测试 | 官方段写法的解析断言 |

验证：

```text
cargo test -p nfrp-common --lib
# 371 passed（新增 TLS 配置/装载/半配置报错/变异测试）

cargo test --workspace -j 2 -- --test-threads=1
# 123 + 371 + 238 + 17 + 25 + 2 passed；0 failed；5 ignored

cargo clippy --workspace --all-targets
# 0 warning
```

证据：`tmp\test_final5.txt`、`tmp\clippy_final5.txt`、`tmp\webserver_tls_test.txt`。

mTLS 已做内存双端真实握手：合法客户端证书通过；不带证书拒绝；错误 CA 签发拒绝。
证据：`tmp\mtls_handshake_test2.txt`。同一份 TLS 配置重复安装是幂等的；换另一组文件
会明确报错（`configure_tls_is_idempotent_for_same_files`）。


> 注：以下清单是**当轮**的状态记录。若与当前代码不符，以 `README.md` 与实测为准（例如 `webServer.tls.*` 已于 0.6.6 实现）。
仍未实现：`webServer.tls.*`（面板 HTTPS）、Windows VirtualNet、官方 xtcp NatHole，
以及 README 限制③列出的其余字段。


<!-- ===== 9/14 第 11 轮 ===== -->

> **日期：2026-10-18** · **轮次：第 11 轮**

---

# NFrp v0.6.0 修复报告（第十一轮）

日期 2026-10-18
来源 云端 Linux 测试分诊 —— 修复跨平台测试缺陷 + **照官方 frp 做法重构测试结构**
结论 **4 项修复**（1 项结构性重构 + 3 项测试 bug）；**无产品安全缺陷**；质量门全绿

---

## 〇、一句话概括

本轮的起点是"云端 Linux 上 `cargo test` 有一批失败"。逐层分诊后发现：
**它们几乎全部是测试自身的问题**，其中最有价值的一条是 ——
我们的 HTTP 测试**开了真实 socket**，而官方 frp 从不开。

修复后：`web::tests` 在云端从 **0/6 → 8/8**。

---

## 一、核心修复：`web.rs` 测试改为"纯逻辑"（照官方 frp）

### 1.1 问题

`client/src/web.rs` 的测试辅助函数 `handle_over_socket`：

```rust
let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
let srv = tokio::spawn(async move {
    let (stream, peer) = listener.accept().await.unwrap();
    let _ = handle(stream, peer, h).await;
});
let mut cli = TcpStream::connect(addr).await.unwrap();
```

**自己造了一个竞态**。云端 Linux 上的实测：

| 跑法 | 结果 |
|---|---|
| 全量串行 6 次 | **0/6 通过** |
| 4 个用它的测试单独跑 | **全部失败**，每次卡满 5.00s |
| 2 个不用它的测试 | 全绿 0.00s |

时间线插桩（毫秒级）证据：

```
TL S1 accept 等 @162µs
TL C3 write+flush 完成（45 字节）@1.08ms
（TL S2 accept 返回 —— 永不出现）
```

⇒ `listener.accept().await` **永不返回**，`handle()` 从未被调用。

而同一份代码在 **Windows 上 17/17 全绿**；**双进程**（真实的服务端进程 + 客户端进程）
在 Linux 上实测 `ok=100 fails=0`。

⇒ **产品没问题，是测试写法在 Linux 上引入了竞态。**

### 1.2 官方 frp 怎么做（关键参考）

`tmp/frp-0.71.0/server/http/controller_v2_test.go`：

```go
resp := httptest.NewRecorder()
handler.ServeHTTP(resp, req)          // 直接调 handler，内存 recorder
```

`pkg/plugin/client/http_proxy_test.go` 更彻底：

```go
clientConn, serverConn := net.Pipe()  // 纯内存管道，无 socket
```

**官方测 HTTP 处理器时从不开 socket。**

### 1.3 修法

把 `handle` 里与 socket 无关的判定逻辑抽成纯函数：

```rust
pub(crate) struct Decision {
    pub code: u16,
    pub ctype: &'static str,
    pub body: String,
}

async fn decide(hub: &Arc<Hub>, req: &http1::Request, peer: SocketAddr) -> Decision
```

`handle` 缩成三步：

```rust
async fn handle(mut stream: TcpStream, peer: SocketAddr, hub: Arc<Hub>) -> anyhow::Result<()> {
    let req = http1::read_request(&mut stream).await?;
    let d = decide(&hub, &req, peer).await;
    http1::send(&mut stream, d.code, d.ctype, d.body.as_bytes(), &[]).await?;
    Ok(())
}
```

测试改成 `decide_over_raw()` —— 解析请求 → 调 `decide()` → 拼响应文本。
**完全不碰 socket**，与官方 `ServeHTTP(resp, req)` 同构。

### 1.4 安全性（判定逻辑逐字未变）

判定顺序与内容**完全保留**：

1. `/api/healthz` 免鉴权（容器探针用，只回 `ok`）
2. Basic Auth 失败 → **401**
3. 写操作：任何一条 `Origin` 非本机 → **403**
4. 写操作：缺 `X-Nfrp-Client` 头 → **403**
5. 其余交给 `route()`

这只是**搬家**，不是改语义。

### 1.5 效果（云端 Linux）

| 指标 | 修复前 | 修复后 |
|---|---|---|
| `web::tests` 连跑 8 次 | **0/6** | ✅ **8/8** |
| 4 个关键测试单独跑 | 全红，各 5.00s | ✅ **全绿，各 0.00s** |

---

## 二、其余 3 项修复

### 2.1 `logfile` 测试用了 Windows 专有的"打不开的路径"

**根因**：测试用 `Z:/nfrp-no-such-drive/x.log` 构造错误路径。

* Windows：盘符不存在 ⇒ 打不开 ✓（所以本地一直绿）
* **Linux：`Z:/...` 是合法的相对路径**（名为 `Z:` 的目录）⇒
  `create_dir_all` 会真的建目录成功 ⇒ 断言失败

**修复**：改成「父路径是一个已存在的**文件**」—— 两个平台都必然 `ENOTDIR`。

**云端验证**：该测试不再失败。

### 2.2 `tun_linux` 测试缺 tokio runtime

**根因**：`#[test]` 下调用 `Tun::create`，在有权限环境（云端 root + `/dev/net/tun`）
会走到 `AsyncFd::new`，**没有 reactor 时 panic**（`no reactor running`）。

**修复**：`#[test]` → `#[tokio::test]`。

**云端验证**：该测试不再失败（`3 passed`）。

### 2.3 `dial_server` 测试的 accept 只等一次

**根因**：

```rust
tokio::spawn(async move { let _ = l.accept().await; });   // ← 只 accept 一次
let s  = dial_server(&cfg,  addr)...;   // 第 1 次 OK
let s2 = dial_server(&cfg0, addr)...;   // 第 2 次：listener 已 drop ⇒ ECONNREFUSED
```

Windows 上第 2 次连接恰好在 listener 回收前完成握手；Linux 上端口立即失效。

**修复**：改成常驻 accept 循环（与产品 `web::run` / `serve.rs` 一致）。

**云端验证**：**3/3 通过**。

### 2.4 附带：`handle_over_socket` 不再吞掉 panic

原先：

```rust
let _ = tokio::time::timeout(Duration::from_secs(2), srv).await;   // ← JoinError 被丢弃
```

服务端 task 若 panic，测试只表现为"响应为空"，**看不到任何线索**。

改后：区分"服务端 task 异常结束 / 超时 / 读取超时"三种情况并给出明确信息。

---

## 三、如实记录：未解决的 6 项

| 测试 | current_thread | multi_thread | 判定 |
|---|---|---|---|
| `plugin_bridge::端到端_http2http_…` | 3/5 | 2/5 | 环境敏感 |
| `plugin_bridge::端到端_http2https_…` | 1/5 | 2/5 | 环境敏感 |
| `plugin_bridge::端到端_https2https_…` | 4/5 | 4/5 | 环境敏感 |
| `plugin_bridge::上游悬挂时…` | 3/5 | 3/5 | 环境敏感 |
| `p2p::full_p2p_over_rendezvous` | 8/10 | — | 环境敏感 |
| `p2p::fake_provider_without_secret_is_rejected` | 偶发 | — | 环境敏感 |

### 为什么不再强行改

这些测试**必须依赖真实 socket**：

* `plugin_bridge`：`dial_upstream()` 硬编码 `TcpStream::connect(self.local_addr)`
  —— 上游是真实地址，无法用内存管道替换（除非改产品代码，属过度改动）
* `p2p`：QUIC/KCP 打洞本质就是 UDP socket 交互

官方 `net.Pipe()` 只适用于"处理器 + 客户端"这一类，**套不到"必须连真实上游"**。

### 尝试过并失败的方案

| 方案 | 结果 |
|---|---|
| 把 `mini_rendezvous` 改成常驻循环 | **A/B 对照：0/5 → 1/5**，无实质改善，**已回滚** |
| 全部改 `multi_thread` runtime | 无改善（见上表） |
| 加 `yield_now()` | 无改善 |
| 去掉 `cli.shutdown()` | 只修好一半 |

### 一条只记录、不改码的产品观察

p2p 打洞对 `window`（端口预测）参数敏感（云端各 10 次）：

| window | QUIC | KCP |
|---|---|---|
| 4（开端口预测） | 8/10 | **3/10** |
| 0（关端口预测） | **10/10** | **10/10** |

⇒ 端口预测显著影响打洞成功率。但**没有足够证据判定是产品缺陷**
（也可能是测试替身 `mini_rendezvous` 的行为差异），故只记录。

---

## 四、方法论收获

### 4.1「两轮对照」不足以判定确定性

`plugin_bridge` 两个测试**全量跑两轮都红**，但**单独跑变绿**
⇒ 稳定复现的**并发竞争**，不是确定性缺陷。

| 全量 | 单独 | 判定 |
|---|---|---|
| 红 | 绿 | 并发竞争 |
| 红 | 红 | 真确定性失败 |

### 4.2 测试能不用 socket 就不用

向官方 frp 学习：`httptest.NewRecorder` / `net.Pipe()`。
只有被测对象**本质需要真实网络**时才用 socket，并接受其环境敏感性。

### 4.3 `strace` 会掩盖竞态

`strace` 下同一个必失败的测试变绿（0.01s）——
因为每次系统调用都陷入内核，**改变了调度时序**。
⇒ 别用 strace 判断"是否能通过"。

### 4.4 本轮我自己的失误（8 次，全部差点误判）

1. `./$CARGO_TARGET_DIR` 路径拼错 → 程序没跑（exit 127）→ 险些读成"资源耗尽"
2. 生成的脚本没校验 → 跑的是旧版本，输出被误读
3. Python 用 `threading` 测 loopback → 51% 失败是**我代码的线程时序**
4. `tokio::join!(accept, client)` 结构 ≠ 产品
5. `stop.notify_one()` 没停干净 → 程序挂死（exit 124）→ 读成"瞬间全挂"
6. `swap` 补丁编译失败
7. 回滚 `mini_rendezvous` 时漏掉配对大括号
8. `heredoc` 里的三引号把外层字符串截断

**共同教训**：任何"实验结论"必须先验证实验本身跑通
（看 exit code、看锚点、看日志真的出现）。

---

## 五、质量门

| 项 | 结果 |
|---|---|
| `cargo test --workspace`（本地串行） | ✅ **751 通过 0 失败** |
| `cargo fmt --all -- --check` | ✅ 干净 |
| `cargo clippy --workspace --all-targets -- -D warnings` | ✅ **0 告警** |
| `cargo audit` | ✅ exit 0 |
| 云端 `web::tests` × 8 | ✅ **8/8** |
| 云端 `logfile` / `tun_linux` / `dial_server` | ✅ 12 / 3 / **3-of-3** |

---

## 六、改动清单

| 文件 | 改动性质 |
|---|---|
| `client/src/web.rs` | 抽出 `Decision` + `decide()`；`handle` 精简；测试改 `decide_over_raw()` |
| `client/src/main.rs` | `dial_server_按配置开_keepalive`：accept 改常驻循环 |
| `common/src/logfile.rs` | 测试改用"父路径是文件"构造错误路径 |
| `common/src/vnet/tun_linux.rs` | `#[test]` → `#[tokio::test]` |

**产品行为无变更**（`decide` 只是把 `handle` 里的判定逻辑原样搬出）。

---

## 七、兼容性

* **无配置文件变更**
* **无协议变更**
* **无行为变更**
* `frps -v` / `frpc -v` 仍输出裸 `0.71.0`
* 与官方 frpc 0.71.0 互通不变
* **直接替换二进制即可升级**


<!-- ===== 10/14 第 12 轮 ===== -->

> **日期：2026-10-20** · **轮次：第 12 轮**

---

# NFrp v0.6.1 修复报告（Shannon 渗透测试轮）

日期 2026-10-20
来源 **Shannon**（KeygraphHQ 自主 AI 渗透测试器）对本项目的源码 + 运行时审计
结论 **核对 13 条发现：10 条无需改动（已修过 / 为对齐官方故意保留），3 条是真新发现，全部修复**
质量门全绿

---

## 〇、这一轮的方法与你的要求

> **获得日志之后一定要查之前的记录，是不是有原因不修的还是为了对齐不修的**

所以每一条发现都按三类归档：

| 类别 | 含义 | 处置 |
|---|---|---|
| **A 已修过** | 历史记录里有修复 + 回归测试 | 不动 |
| **B 故意不修** | 记录里写明"为对齐官方 frp 而保留" | 不动，注明原因 |
| **C 新发现** | 两者都不是 | 修 |

---

## 一、Shannon 环境（顺带记录，方便复现）

Shannon 是 **Keygraph** 的自主 AI 渗透器，核心承诺是 **"No exploit, no report"**。

| 项 | 情况 |
|---|---|
| 平台要求 | **不支持原生 Windows**，必须在 WSL2 里跑 |
| 还要求 | **非 root 用户** + 无 sudo 可用 docker |
| 本机落地 | Docker Desktop + WSL2 内装 Docker Engine 29.9.1（阿里云源） |
| 模型 | `agnes-3.0-flash`（OpenAI 兼容端点，用 `--models-config` 描述） |
| 关键坑 | **源码放在 `/mnt/e`（Windows 挂载）会让容器内 grep 一次耗时 2 分钟**；复制到 WSL 原生盘后 **0.003s**（快 4 万倍） |
| 完整跑完 | **未成功** —— 13 阶段的连续模型调用会被限流打断（`AGENT_EXECUTION_FAILED`） |

已获得的产物：

* `pre_recon_deliverable.md`（39 KB，架构 / 信任边界 / 全部入口清单）
* `nfrp_security_report.md`（10 KB）
* 两轮 agent 日志（259 KB）

---

## 二、13 条发现逐条核对

### A 类：已修过（7 条）

| # | Shannon 的发现 | 历史依据 | 结论 |
|---|---|---|---|
| 1 | **空 token = 匿名控制面**（它判 HIGH） | v0.5.6 修（审计总报告 M6）：无认证 + 绑**对外**地址**拒绝启动**；只有"默认配置"才强告警放行 | Shannon 没看到 `validate()` 的三层判定，**误报** |
| 5 | work_conn 的"空凭据 + 源 IP 相同"回退 | v0.5.5 A-1 | 有更强防线：会话声明的 `work_conn_cred` 会让空凭据**直接被拒**，注释明说"不必依赖源 IP" |
| 6 | 未配证书时自动生成自签证书 | 设计如此 | 自签是"开箱可用"的必要条件，且客户端默认不校验（见下） |
| 7 | 面板 XSS / `esc()` | **第五轮 H4** | `table()` / `card()` 已全部转义，并有反向断言 |
| 8 | `sudp` 反射到客户端自报地址 | **L18 / E9-0** | `SeenVisitorIps` IP 级白名单 + 每包 ACL，已关闭 |
| 9 | 服务端可把客户端变成开放代理 | **H4 / F1** | `validate_remote_proxy` 拒绝任何 `plugin*` 字段，且 `local_addr` 限制回环 |
| 10 | P2P 能否被指到任意 IP | **B-1 / E9-1** | `Session.expected_ip` 绑定控制连接源 IP + 每包 ACL；候选地址**只换端口不换 IP** |

### B 类：为对齐官方而故意保留（3 条）

| # | Shannon 的发现（它判 HIGH/MEDIUM） | 为什么**不能**改 |
|---|---|---|
| 2 | 客户端 TLS **默认跳过**服务端证书校验 | **官方 frpc 就是 `InsecureSkipVerify`**（frp 的控制通道默认是明文 v1，TLS 是可选层）。改成默认校验 ⇒ **官方 frpc 全部连不上**，直接毁掉项目的存在意义。代码注释已写明这是"自有客户端 + 自有服务端"场景才开的开关 |
| 3 | v1 通道 PBKDF2-HMAC-SHA1 **只有 64 轮** | 官方 `golib v0.8.2` 的固定值。注释特别记了一笔：**golib master 分支后来把盐从 `frp` 改成了 `crypto`，照 master 写会得到一个"自洽但跟官方不通"的实现** |
| 4 | v1 的 token 证明用 **MD5** | frp 协议规定 `privilege_key = md5(token + timestamp)`。这是**线路格式**，不是设计选择 |

★ 这三条的共同点：**Shannon 看不到"必须与官方互通"这个约束**，
所以把协议兼容必需的设计当成缺陷报了出来。

### C 类：真新发现（3 条，全部已修）

#### C-1 · 面板管理操作**完全没有审计记录**（低危）

**Shannon 的原话**：
> `kick` emits only a tracing line, not an `ADMIN_ACTION` audit event.

**我核对时发现比它说的更严重**：

```bash
$ grep -rn "ADMIN_ACTION" server/src/
audit.rs:56: pub const ADMIN_ACTION: &str = "admin_action";   # ← 定义了
# 没有任何使用点
```

**`ADMIN_ACTION` 这个常量定义了，但全仓零使用** ——
也就是说面板的**增 / 删 / 踢三个操作一条审计都没记**，
而 `PROXY_ADD` / `PROXY_REMOVE` 只在 `serve.rs`（客户端自己注册那条路）记录。

审计和日志是**两条不同的链**：日志会轮转/被删，`[audit]` 的 JSONL 才是事后追责用的。
踢人是**不可回滚**的操作（客户端所有隧道立刻失效），只留日志等于查不到谁在什么时候踢了谁。

**修法**：`add_proxy` / `remove_proxy` / `kick` 三处都补 `ADMIN_ACTION`。

**回归测试**：`admin::tests::kick_必须写审计` —— 断言审计条目增加 + `target` 是 run_id + `detail` 含操作类型与理由。

★ 写测试时踩了一个坑：`AuditLog::record()` 在 `enabled == false` 时**直接 return**，
而 `Registry::unlimited()` 默认不启用审计 ⇒ 测试会因"审计没开"失败而不是"代码没写"。
已换成开启审计的安全上下文，并加了**前置自检**（先记一条 `selftest` 确认审计真的在记）。

#### C-2 · `forget_session` 写好了但**没接上**（低危）

**Shannon 的原话**：
> OIDC `subjects` map has no wired `forget_session` on teardown (per-session leak until restart).

**核对属实**：

```bash
$ grep -rn "forget_session" --include=*.rs
common/src/security.rs:505  pub fn forget_session(...)   # 定义
server/src/guard.rs:263     pub fn forget_session(...)   # 转发
common/src/auth/oidc.rs:608 pub fn forget_session(...)   # 实现
common/src/auth/oidc.rs:1260  v.forget_session("run-A"); # ← 只有单测调用
# 生产代码：零调用
```

⇒ `OidcVerifier::subjects`（`run_id -> sub` 表）**每个 OIDC 会话泄漏一条，直到进程重启**。

**修法**：在 `ClientGuard::drop` 里调用（与 `registry.remove()` 同一个位置）。
放在 `Drop` 是为了**覆盖所有退出路径**（正常断开、被踢、panic 展开），不会漏。

**回归测试**：`registry::tests::控制连接退出必须清掉_oidc_subject_绑定` ——
造真 OIDC 上下文、塞一条绑定、drop `ClientGuard`、断言表清空。

★ 没有用 `SecurityContext::from_config`：那条路径在 JWKS 未拉取时会把认证换成
`OidcUnavailable`，`forget_session` 变成空操作，**测不到修复点**。

#### C-3 · 面板 `catch` 分支的 `innerHTML` 没转义（加固）

**Shannon 的原话**：
> `innerHTML` at `dashboard.rs:779` — catch 分支写 `innerHTML = '...'+e` 没有 `esc(e)`。
> **当前安全**……**加固提示**：如果将来 fetch 错误携带了响应文本，这会变成 stored-XSS 向量。

**核对属实，且它准确指出了"今天不可利用"**：

```javascript
} catch(e) {
    document.getElementById('cards').innerHTML = '<div class="empty">读取状态失败：'+e+'</div>';
}
```

`e` 是本地 JS 的 `Error`（`fetch` 或 `JSON.parse` 失败），**不是服务端文本**，
内容由浏览器生成、攻击者控制不了。

**但这是第五轮 H4 漏掉的路径** —— 那一轮修了 `table()` / `card()`，
**唯独没覆盖这条 catch 分支**。又是"防线没铺满"那个模式。

**修法**：`esc(e)`。

**回归测试**：加进现有的 `面板表格必须转义单元格` ——
正向断言 `esc(e)` 存在 + **反向断言**不得残留裸 `'+e+'`。

---

## 三、三条修复的退回验证（3/3 有效）

| # | 修复 | 退回方式 | 结果 |
|---|---|---|---|
| C-1 | kick 审计 | 整条 `.record(...)` 语句删除 | ✅ 测试变红 |
| C-2 | `forget_session` | 整行删除 | ✅ 测试变红 |
| C-3 | `esc(e)` | 还原成裸 `e` | ✅ 测试变红 |

★ ① 的退回方式返工了 **3 次**：
v1 按分号截断 ⇒ 花括号失配；
v2 按括号配对删 `AuditEvent::new(...)` ⇒ `.record()` 少参数（E0061）；
v3 从 `registry.audit().record(` 起删到配对右括号 + 分号 ⇒ 语法合法。

★ ②③ 第一版退回时**仍是绿的** —— 因为它们**当时还没有测试**。
补了测试之后才真正被守住。这印证了一贯的标准：**没有守卫的修复不算修完**。

---

## 四、质量门

| 项 | 结果 |
|---|---|
| `cargo test --workspace`（串行） | ✅ **753 通过 0 失败**（v0.6.0 → 753，本版 +2 条测试） |
| `cargo fmt --all -- --check` | ✅ 干净 |
| `cargo clippy --workspace --all-targets -- -D warnings` | ✅ **0 告警** |
| `cargo audit` | ✅ exit 0（184 crates） |
| 端到端冒烟 | ✅ **28 / 28** |
| 退回验证 | ✅ **3 / 3** |

---

## 五、改动清单

| 文件 | 改动 |
|---|---|
| `server/src/admin.rs` | `add_proxy` / `remove_proxy` / `kick` 补 `ADMIN_ACTION` 审计；新增 `kick_必须写审计` 测试 |
| `server/src/registry.rs` | `ClientGuard::drop` 调 `forget_session`；新增 `控制连接退出必须清掉_oidc_subject_绑定` 测试 |
| `server/src/dashboard.rs` | catch 分支 `esc(e)`；既有转义测试补正/反向断言 |
| `common/src/auth/oidc.rs` | 新增 `bind_subject_for_test()`（测试用后门，名字标明意图） |

**产品行为无变更**：只补了审计记录、会话清理与一处 HTML 转义。

---

## 六、兼容性

* 无配置文件变更
* 无协议变更
* 无行为变更（审计**未启用时**这些代码不产生任何输出）
* `frps -v` / `frpc -v` 仍输出裸 `0.71.0`
* 与官方 frpc 0.71.0 互通不变
* **直接替换二进制即可升级**


<!-- ===== 11/14 第 13 轮 ===== -->

> **日期：2026-10-20** · **轮次：第 13 轮**

---

# NFrp 第十三轮：负载均衡 / KCP / 健康检查与官方 frp 对齐

日期 2026-10-20
本轮性质 **特性对齐 + 缺陷修复**，不是安全审计
质量门 766 通过 / fmt 干净 / clippy 0 告警 / audit 零漏洞 / 冒烟 28/28

---

## 〇、这轮在解决什么

用户指出的问题很具体：

> 功能列表里有负载均衡和健康检查，但官方 frp 在这些特性的策略丰富度和边缘场景
> 处理上经过了更长时间的迭代。例如 group 负载均衡采用"最小连接数"分摊，
> 而官方 frp 在长连接、突发流量下的具体表现和调优参数，可能积累了更多实践细节。
> 此外，像 KCP 会话表封顶 1024 这类资源上限，在超大规模部署时可能需要拆分实例来规避。

于是这轮逐项去读官方 0.71.0 的实现，对照差异，该改的改，该保留的说明理由。

---

## 一、最重要的发现：官方用的是**轮询**，不是最少连接

### 官方怎么做的

`server/group/base.go` 的 `worker`：

```go
func (bg *baseGroup) worker(realLn net.Listener, acceptCh chan<- net.Conn) {
    for {
        c, err := realLn.Accept()
        if err != nil {
            return
        }
        err = gerr.PanicToError(func() {
            acceptCh <- c        // ← 丢进共享 channel
        })
        ...
    }
}
```

`server/group/listener.go` 里每个代理各自 `Accept()` 同一个 `acceptCh`：

```go
func (ln *Listener) Accept() (net.Conn, error) {
    select {
    case <-ln.closeCh:
        return nil, ErrListenerClosed
    case c, ok := <-ln.acceptCh:   // ← 谁先抢到谁拿到
        ...
    }
}
```

**这就是无状态轮询**：连接按到达顺序被某个代理取走，与后端当前有多忙无关。

### 我们原来怎么做的

`registry.rs` 的 `PortGroup::pick` 用的是**最少连接数**，代码注释还专门论证了
"纯轮询会把慢的后端压死"。推理没错，但它**和官方行为不一致**。

### 怎么处理的

引入 [`LbPolicy`]，两种策略都保留：

| 值 | 行为 |
|---|---|
| `roundrobin`（**新默认**） | 严格 1/N 均分，**与官方一致** |
| `leastconn` | 在途连接最少的优先，能力不均时更优 |

默认改成 `roundrobin` —— **对齐优先**。`leastconn` 作为可选的超集能力保留：
调度完全发生在服务端内部，开它不影响与官方客户端的互通。

---

## 二、顺带抓到的一个真实缺陷

改造 `pick` 时发现旧实现有**系统性偏袒**：

```rust
// 旧代码
let mut best_load = self.members[0].inflight();   // ← 固定从 0 号初始化
let start = self.cursor.fetch_add(1, Ordering::Relaxed) % n;
for k in 1..n {
    let i = (start + k) % n;                      // ← 从 start+1 扫，跳过 start
    ...
}
let start_load = self.members[start].inflight();  // ← 事后补判 start
```

问题：`best_load` 初值是 `members[0]`，但循环从 `start+1` 开始。
当 `start != 0` 时：

* `members[0]` 的负载被当成初值参与比较，**但循环里会再访问一次其他成员**；
* `start` 那个成员要等到最后才补判，且判据是 `<=`（非严格小于）。

结果是**部分后端被系统性偏袒**，在 `n >= 3` 时表现为分配不均。

**修法**：从 `start` 起扫满一整圈，初值就取 `members[start]`：

```rust
let mut best = start;
let mut best_load = self.members[start].inflight();
for k in 1..n {
    let i = (start + k) % n;
    ...
}
```

这条修改对两种策略都正确，且不影响官方行为（轮询根本不看负载）。

---

## 三、KCP 会话上限：加了安全下限，并做成可配

### 用户提的点

> KCP 会话表封顶 1024 这类资源上限，在超大规模部署时可能需要拆分实例来规避。

### 实际情况

`max_sessions` 本来就是字段，但**默认值硬编码**，用户改不了。

### 改了什么

1. 新增配置项 `kcp_max_sessions`（0 或不填 = 用默认 1024）
2. 新增**安全下限** `MIN_KCP_SESSIONS = 64`

下限的理由：这个值直接决定内存上界（`值 × 15.3 KB`）。如果允许配 0 并照用，
表现是"第 1 条连接就被丢弃" —— **KCP 完全不可用，而进程不报错**。
那种静默失效比拒绝启动更难排查。

3. 启动日志会打出实际生效的上限，配置错时能看到

### 关于"超大规模"

正确的做法**不是无限调大**，而是：

1. 用 TCP / QUIC 承载控制连接（KCP 只在两者都走不通时才需要）
2. 或在前面挂负载均衡，把客户端拆到多个 frps 实例

这一点已经写进 `assets/frps.toml` 的注释里，避免用户以为"调大就好"。

---

## 四、健康检查：三处对齐官方

### ① HTTP 探测改成**严格 2xx**

官方 `client/health/health.go` 的 `doHTTPCheck`：

```go
if resp.StatusCode/100 != 2 {
    return fmt.Errorf("do http health check, StatusCode is [%d] not 2xx", resp.StatusCode)
}
```

我们原来是 `code < 400`，把 3xx / 404 都算健康。差别在真实场景里很明显：

* 服务配了强制 HTTPS 跳转（301/302）⇒ 探测永远拿到 301 ⇒ 旧判据认为它**一直健康**，
  但那个端口其实没在提供内容
* 反向代理返回 404 时同理

改成严格 2xx 后，这类部署需要把 `healthCheckPath` 指到真的返回 2xx 的路径 ——
这正是官方文档要求的行为。

### ② 新增 `httpHeaders` 支持

官方 `pkg/config/v1/proxy.go`：

```go
HTTPHeaders []HTTPHeader `json:"httpHeaders,omitempty"`
```

用于需要鉴权的健康检查端点（带 `Authorization`、内部 `X-Health-Token` 等）。
不支持时这类端点**一律探测失败** —— 表现为"服务明明活着，客户端却判定它不健康、
把流量摘掉"。

现在支持官方写法：

```toml
[[proxies.healthCheck.httpHeaders]]
name = "Authorization"
value = "Bearer secret-token"
```

### ③ `Host` 头语义对齐

官方在 `doHTTPCheck` 里：

```go
req.Header = monitor.header
req.Host = monitor.header.Get("Host")
```

即**配置里的 Host 覆盖默认值**。我们照做：配了 `Host` 就用它，没配才用兜底值。

### ④ 顺带做的加固：HTTP 头注入防护

官方用 Go 的 `http.Header`，库本身会拒绝非法头值。
我们是**手写 HTTP 请求**，必须自己挡 —— 否则配一个含 `\r\n` 的值就能往探测请求里
插入任意额外的头，甚至拼出第二条请求（请求走私）。

实现：头名与头值里的 CR/LF 全部剥掉。

---

## 五、测试

| 测试 | 验证什么 |
|---|---|
| `default_policy_is_round_robin_like_official` | 默认必须是轮询；负载不均时照样均分 |
| `pick_prefers_the_least_loaded_backend` | 显式设 `LeastConn` 时确实倾斜 |
| `lb_policy_parsing` | 认得 `rr` / `lc` / 大小写 / 连字符；认不出回落默认 |
| `kcp_session_cap_has_a_floor` | 配 0 抬到下限、正常值不动 |
| `kcp_会话表必须有上限` | 超额会话确实被丢弃（改用 `force_max_sessions_for_test` 绕开下限） |
| `官方的_healthcheck_httpheaders_能被解析` | 官方 `[[proxies.healthCheck.httpHeaders]]` 能读进来 |
| `没配_httpheaders_时是空表` | 不配时不报错 |
| `probe_request_includes_configured_headers` | 配置的头全部出现在请求里 |
| `probe_request_honours_configured_host` | 配了 Host 就用它，且只有一个 Host 行 |
| `probe_request_strips_crlf_from_values` | **头注入**被挡住 |
| `probe_request_strips_crlf_from_names` | 头名里的注入同样挡住 |
| `probe_request_skips_empty_names` | 空头名不产出非法行 |

★ 头注入那条测试第一版写错了判据：它断言"`X-Injected` 这个字符串不应出现在请求里"。
实际 CR/LF 剥掉后内容被压进上一个头的值，字符串仍在但**不构成独立头行** ——
那是安全的。改成验证"请求行结构"（每行必须以已知头名开头、不能拼出第二条请求、
只能有一个空行）才测到点子上。

---

## 六、质量门

| 项 | 结果 |
|---|---|
| `cargo test --workspace`（串行） | ✅ **766 通过 0 失败**（上轮 757，本轮 +9） |
| `cargo fmt --all -- --check` | ✅ 干净 |
| `cargo clippy --workspace --all-targets -D warnings` | ✅ 0 告警 |
| `cargo audit` | ✅ exit 0（184 crates） |
| 端到端冒烟 | ✅ **28 / 28** |

---

## 七、改动清单

| 文件 | 改动 |
|---|---|
| `server/src/registry.rs` | 新增 `LbPolicy`；修 `pick` 偏袒缺陷；`Registry` 加 `lb_policy` 原子字段 |
| `server/src/serve.rs` | 装载 `lb_policy`；KCP 上限接配置并打日志 |
| `common/src/config.rs` | 新增 `lb_policy` / `kcp_max_sessions` / `HttpHeader` / `health_check_http_headers` |
| `common/src/frp_config.rs` | 映射官方 `healthCheck.httpHeaders` |
| `common/src/frp/kcp.rs` | `MIN_KCP_SESSIONS`；`with_max_sessions` 加下限；新增 `max_sessions()` 与测试用 `force_max_sessions_for_test` |
| `client/src/health.rs` | HTTP 探测严格 2xx；支持自定义头；Host 语义对齐；抽 `build_probe_request` + 头注入防护 |
| `assets/frps.toml` | 补 `lb_policy` / `kcp_max_sessions` 配置说明 |

---

## 八、兼容性

* **无破坏性变更**：所有新配置项都有默认值，老配置文件一个字节不用改
* **协议零变更**：与官方 frp 0.71.0 互通不受影响
* **默认行为变化一处**：group 负载均衡从「最少连接」改为「轮询」，
  这是**向官方对齐**。依赖旧行为的部署可显式配 `lb_policy = "leastconn"`
* 租户隔离（第六轮 D-1）完整保留，不因这轮改动而放松


<!-- ===== 12/14 第 14 轮 ===== -->

> **日期：2026-10-24** · **轮次：第 14 轮**

---

# NFrp 第十四轮：测试 flake 消除 + 渗透低危项修复

日期 2026-10-24
上游来源 **OpenCode** 的渗透测试（`tmp/pentest_round/PENTEST-REPORT.md`）与交接清单
本轮处理 交接清单的 **P0** 与 **P5**
质量门 785 通过 / fmt 干净 / clippy 0 告警 / audit 零漏洞 / 冒烟 28/28

---

## 〇、先看 OpenCode 做了什么

接手前先核实了他的报告，逐条验证而不是照抄。

### 已验证属实的

| 项 | 核查结果 |
|---|---|
| `deny.toml` 存在（1026 B） | ✅ |
| `supply-chain/` 三个文件 | ✅ |
| `tls_cert_file` / `tls_key_file` / `tls_trusted_ca_file` 字段 | ✅ 已实现 |
| `tokio` 升到 1.54.1 | ✅ |
| `rustls-webpki` 升到 0.103.16 | ✅ |
| `cargo audit` 零漏洞 | ✅ 复跑确认为 0 |
| 测试全绿（当时 776） | ✅ 复跑确认 |

### 一处表述不准确

他说 `webpki-roots` 「升到 1.0.10」。实际 **`Cargo.lock` 里有两个版本并存**：

```
webpki-roots  0.26.11
webpki-roots  1.0.10
```

这是依赖树里不同 crate 要求不同大版本导致的，**不是问题**（各自用各自的），
但「升到 1.0.10」这个说法容易让人以为只有一个。记录在此以免后续误判。

### 他那轮的实质成果（值得肯定）

- **TLS 证书组真正写完**：不只是侦察。服务端自定义证书、客户端证书（mTLS）、
  只配 cert 不配 key 时明确报错而不是静默退回自签名。**mTLS 还做了内存双端真实握手测试**。
- **3 条 RustSec 通告真实修复**（rustls-webpki / webpki-roots / tokio）
- **ASan 全量跑通**：common 371 + server 238，无 `AddressSanitizer` 报错
- **Miri 部分跑通**：`frp_config` 38/38
- **cargo-deny 基线建立**

### 他诚实标注的未完成（我认同）

- TSan 未跑（Windows MSVC 不支持）
- `cargo vet` 只有 184 条 exemption，**不是人工审计**
- Windows VirtualNet、官方 xtcp NatHole、剩余配置字段都没做

---

## 一、P0：消除 e2e 测试的端口竞态

### 问题

`server/tests/e2e.rs` 的 `free_port_both()`：

```rust
fn free_port_both() -> u16 {
    for _ in 0..64 {
        let p = free_port();                              // ← TCP listener 已 drop
        if UdpSocket::bind(("127.0.0.1", p)).is_ok() {    // ← 中间有空窗
            return p;
        }
    }
    panic!("试了 64 次都没拿到 TCP/UDP 都能 bind 的端口")
}
```

**两次 bind 之间没有任何保护**。并行测试时另一个线程可能正好抢走这个号，
于是 64 次全撞车并 panic。这是**真实存在**的 flake，不是"偶发环境问题"。

### 修法

```rust
fn free_port_both() -> u16 {
    for _ in 0..128 {
        let tcp = TcpListener::bind("127.0.0.1:0")?;   // listener **不 drop**
        let p = tcp.local_addr()?.port();
        let udp = UdpSocket::bind(("127.0.0.1", p))?;  // TCP 仍持有时试 UDP
        // 两个都绑上 ⇒ 这个号真的可用
        if !claimed.insert(p) { continue; }            // 本进程内去重
        drop(tcp); drop(udp);                          // 登记后再交给被测服务端
        return p;
    }
    panic!(...)
}
```

三点改进：

1. **TCP 与 UDP 同时持有**，两个都绑上才算数
2. **校验期间 socket 一直活着**，别的测试拿不到
3. 校验通过后**先登记再释放**，进程内不再发出去

### 验收

```
跑 5 次 cargo test --workspace -j 2：
  第 1 次: OK   第 2 次: OK   第 3 次: OK   第 4 次: OK   第 5 次: OK
失败次数: 0 / 5
```

---

## 二、P5：渗透测试的三个低危项

### PT-03 · `HEAD` 仍返回响应体

**证据**：`HEAD /api/status` → 200 + 659 B；`HEAD /` → 200 + 10368 B HTML。

**问题**：RFC 9110 §9.3.2 要求 HEAD **只回头、不回头**。
危害有限（不是漏洞，是协议违规），但会带来实际麻烦：

- 用 HEAD 做健康检查的监控会白白拉一遍完整页面
- 某些缓存 / 代理对 HEAD 的 body 处理不一致，可能污染缓存

**修法**：给 `send()` 加 `head_only` 参数，`HEAD` 时不写 body，
但 **`Content-Length` 仍按真实长度发送** —— 那正是 HEAD 的语义。

### PT-07 · 只读端点接受 POST

**证据**：`POST /api/status` → 200 + 完整状态 JSON。

**根因**：未匹配 `ADMIN_PATHS` 的 POST 会落进 `match path` 的只读分支，
于是被当成普通路径处理、返回 200。

**修法**：**未匹配的 POST 一律 405**，并带 `Allow: GET, HEAD`。

用 405 而不是 404：路径确实存在，只是方法不对 —— 这是 HTTP 语义要求，
顺带告诉调用方该用什么方法。

### PT-05 · 没有任何安全响应头

**证据**：面板响应里没有 CSP / X-Frame-Options / X-Content-Type-Options。

**修法**：所有响应统一加：

| 头 | 作用 |
|---|---|
| `X-Content-Type-Options: nosniff` | 禁止 MIME 嗅探 |
| `X-Frame-Options: DENY` | 挡点击劫持（把面板套进攻击者页面诱导管理员点"踢出"） |
| `Referrer-Policy: no-referrer` | 面板 URL 不通过 Referer 泄露 |
| `Content-Security-Policy` | `default-src 'none'` + 内联脚本样式 + `frame-ancestors 'none'` |

#### 为什么**不用** HSTS

面板默认是**明文 HTTP**。对明文响应发 `Strict-Transport-Security` 会被浏览器
**直接忽略**（RFC 6797 §7.2），发了也没用；更糟的是会让人误以为"已经上 HTTPS 了"。
等面板自己支持 TLS 之后再按需加。

#### CSP 里 `'unsafe-inline'` 的取舍

面板 HTML 的脚本与样式都是内联的（`html_page()` 单文件），所以
`script-src` / `style-src` 必须允许 `'unsafe-inline'`。

这不是疏忽 —— 在自包含页面上，能挡的部分是 `default-src 'none'`
（禁止一切外域请求、图片、字体、frame），而那正好是最有价值的部分。

### 实现细节：为什么不用运行时拼接

第一版写了个 `with_sec_headers(own) -> Vec<...>` 在运行时合并。
编译失败：`send()` 收的是 `&[(&str, &str)]`，`&with_sec_headers(...)`
会产生临时值、活不过调用表达式。

改成两个 `static` 数组在**编译期**用 `const fn` 拼好：

```rust
static SEC_HEADERS_WITH_AUTH: [(&str, &str); SEC_HEADERS.len() + 1] = concat_headers_auth();
```

零运行时开销、零生命周期问题。

---

## 三、测试

新增 6 条，全部走**真实 socket + 真实 HTTP**（不是只测纯函数）：

| 测试 | 验证什么 |
|---|---|
| `head_returns_headers_without_body` | 四个路径的 HEAD 都不回 body，但仍有 Content-Length |
| `get_still_returns_body` | **对照**：GET 照常回 body（防"把修法扩到 GET"把面板变空白） |
| `post_to_readonly_endpoint_is_405` | 三个只读端点 POST 都 405 且带 Allow；真正写接口不受影响 |
| `security_headers_on_every_response` | 成功 / 401 / 405 / 免鉴权四类响应都带四个安全头 |
| `unauthorized_still_carries_www_authenticate` | 401 的 WWW-Authenticate 没被安全头挤掉 |
| `sec_headers_are_sane` | 常量本身：非空、无重名、合并数组后半段就是 SEC_HEADERS |

---

## 四、退回验证 3/3

| 修复 | 退回方式 | 结果 |
|---|---|---|
| PT-03 HEAD | `if !head_only` → `if true` | ✅ 测试变红 |
| PT-07 POST | 删掉新增的 405 分支 | ✅ 测试变红 |
| PT-05 安全头 | `SEC_HEADERS` 改成空数组 | ✅ 测试变红 |

★ 这一步不能省。本项目第十二轮吃过亏：两条修复的第一版退回**仍是绿的**，
因为它们当时压根没有测试 —— 补了测试才真正被守住。

---

## 五、顺带修的一个 clippy 告警

`server/src/nathole_official.rs` 里有一处多余的 `..Default::default()`：
所有字段都已显式指定，结构体更新没有效果。clippy 在 `-D warnings` 下报错。
删掉即可 —— 是 OpenCode 那轮遗留的，无行为影响。

---

## 六、质量门

| 项 | 结果 |
|---|---|
| `cargo test --workspace`（串行） | ✅ **785 通过 0 失败**（上轮 779，本轮 +6） |
| `cargo test --workspace -j 2` × 5 次 | ✅ **5/5 全绿**（flake 已消除） |
| `cargo fmt --all -- --check` | ✅ 干净 |
| `cargo clippy --workspace --all-targets -D warnings` | ✅ 0 告警 |
| `cargo audit` | ✅ exit 0（184 crates） |
| `cargo deny check` | ✅ advisories / bans / licenses / sources 全 ok |
| 端到端冒烟 | ✅ **28 / 28** |
| 退回验证 | ✅ **3 / 3** |

---

## 七、本轮**未做**的（诚实清单）

交接清单里还有这些没动，不能算完成：

| 项 | 状态 |
|---|---|
| **P1 Windows VirtualNet** | 未做。需要 Wintun/TAP 驱动 + 管理员权限 + 网卡配置，且**必须在真机验证** |
| **P2 官方 xtcp NatHole** | 未做。OpenCode 已有 `server/src/nathole_official.rs`（16 KB），但没接进实际链路 |
| **P3 剩余配置字段** | 未做（`useEncryption` / `useCompression` / `tokenSource` / `includes` / `quicBindPort` 等） |
| **P4 审计补跑** | 未做（TSan / 完整 PSF / Phaedra / 真实 IdP e2e / Linux TUN Miri） |
| **PT-04 重复 Authorization** | 未修 —— 判定为「设计」，取第一个是多数代理的行为 |
| **PT-10 控制面 yamux/frp v2** | 未测 —— 覆盖缺口，需另开授权测试 |

---

## 八、一次失败的修复尝试（必须记录）

### 发现的真问题

在云端跑全量测试时，`plugin_bridge` 有 **6 个测试失败**。排查后确认这是
**产品代码的真实竞态**，不是测试问题：

**证据 1**：同一测试在 Linux 上连跑 10 次 —— **5 通过 / 5 次 5 秒超时**。
通过时耗时 0.01 秒，失败时正好卡满超时。这是竞态的标准特征。

**证据 2**：绕过测试辅助函数、用**真实 TCP 连接**复现，同样挂住：
```
[diag2] read_to_end = Err(Elapsed(()))
[diag2] serve = Err(Elapsed(()))
[diag2] upstream got = Err(Elapsed(()))
```
插件收到连接，但**请求从未转给上游**。

**根因**：`HttpIo::watch_closed()` 用 `read(&mut chunk)` 读进**局部数组**。
这个 future 在 `wait_upstream` 的 `select!` 里被另一支抢先完成而 drop 时，
已经 `poll_read` 进来的字节随局部变量一起消失。丢掉的可能正是请求体开头。

原代码注释里写着「取消安全：tokio 的 `AsyncRead::read` 在取消时不消费数据」
—— **那句话是错的**。

### 两次修复尝试都失败了

**第一版**：把 `watch_closed` 改成 `read_buf` 直接读进 `self.buf`
（它属于 `self`，取消不丢），并在"缓冲非空时立即返回 `Ok(false)`"。

后果：调用方是 `loop { select! }`，立即返回让它变成 **100% CPU 忙等死循环**。
- 云端：4 个测试进程各烧掉 **20 分钟** CPU，负载 12.5
- 本地：单进程烧掉 **1288 秒** CPU

**第二版**：在循环里加 `if io.available() > 0 { return Ok(fut.await) }`，
想让缓冲有数据时只等上游。

后果：仍然空转 —— 因为 `read_buf` 已经把数据吸进缓冲，`available()` 恒 > 0。

### 最终处理：回退，如实记录

两处代码都回到原样，并在注释里写清：

- 缺陷是什么、怎么复现
- 两次修复为什么失败（附实测数字）
- **正确方向**：让"读"只有一个所有者 —— 单独一个读协程独占 `stream`，
  把字节推进共享队列，`wait_upstream` 只等队列信号。这样两个 future
  不会抢同一个 stream。这需要重构 `HttpIo` 的所有权结构。

**判断依据**：宁可保留一个已知的、只在 Linux 上间歇出现的缺陷，
也不能引入一个会让 CPU 跑满的死循环。后者影响面大得多。

### 影响面（如实说明）

- **Windows**：21/21 稳定通过，产品不受影响
- **Linux**：`http2*` / `https2*` 的**端到端用例**间歇失败；
  真实使用中若命中该竞态，表现为插件处理偶发挂起（5 秒超时后释放）
- 其余 780 个测试与 28 项冒烟全部正常

---

## 九、改动清单

| 文件 | 改动 |
|---|---|
| `server/tests/e2e.rs` | `free_port_both()` 重写，消除端口竞态 |
| `server/src/dashboard.rs` | `send()` 加 `head_only`；`SEC_HEADERS` 常量；`SEC_HEADERS_WITH_AUTH/ALLOW`；POST 未匹配 → 405；6 条新测试 |
| `server/src/nathole_official.rs` | 删一处多余的 `..Default::default()` |

---

## 九、兼容性

- **无配置变更**：本轮不涉及任何配置项
- **协议零变更**：与官方 frp 0.71.0 互通不受影响
- **HTTP 行为变化两处**（都是修正，符合 RFC）：
  - `HEAD` 不再返回 body
  - 只读端点的 POST 从 200 变成 405
- 若有用例依赖「POST /api/status 返回 200」，需改用 GET（这是正确做法）


<!-- ===== 13/14 第 15 轮 ===== -->

> **日期：2026-10-24** · **轮次：第 15 轮**

---

# NFrp 第十五轮：补齐未实现项 + 发现并修掉 OIDC 的 ES256 致命 bug

日期 2026-10-24
来源 第十四轮遗留清单
本轮性质 **特性对齐 + 缺陷修复**（不是安全审计）
质量门 **814 通过 / 0 失败**（+3 条 Windows 真机测试） · clippy 0 告警 · audit 零漏洞

## 版本划分

本轮内容分两批发布（因为第一批已经上线后才发现 Windows VNet 可以做真机验证）：

| 版本 | 内容 |
|---|---|
| **v0.6.5** | ES256 致命 bug 修复 · 真实 IdP e2e · 完整 PSF · 四个配置字段 |
| **v0.6.6** | **Windows VirtualNet（Wintun）实现 + 真机数据面验证** |

下面各章分别标注属于哪一批。

---

## 一、最重要的发现：ES256 验签用了错误的签名格式（致命）

### 现象

写"真实 IdP"端到端测试时，用**真 ECDSA P-256 密钥 + 真签名**验证，结果：

```
真实签名必须验证通过: 签名不匹配
```

### 根因

`common/src/auth/oidc.rs` 的 `pick_algorithm`：

```rust
("EC", "ES256") => &s::ECDSA_P256_SHA256_ASN1,   // ← 期望 DER
("EC", "ES384") => &s::ECDSA_P384_SHA384_ASN1,   // ← 期望 DER
```

但 **JWS 的 ES256 签名不是 DER**。RFC 7518 §3.4 原文：

> Turn R and S into octet sequences in big-endian order…
> Concatenate the two octet sequences in the order R and then S.
> **The resulting 64-octet sequence is the JWS Signature value.**

验证侧同样强制：

> The JWS Signature value **MUST be a 64-octet sequence**.
> If it is not a 64-octet sequence, the validation has failed.

也就是说 ES256 的签名是 **64 字节裸 `r‖s`**，不是 `SEQUENCE{r INTEGER, s INTEGER}`。

### 影响

**任何真实 IdP 签发的 ES256 token 都会验签失败** —— 而 ES256 恰恰是
Keycloak / Auth0 / Azure AD 的**默认算法**。

换句话说：**OIDC 认证在生产环境基本不可用**。

### 为什么之前 27 条 OIDC 单测没抓到

因为有一条**测试向量本身是错的**：

```rust
const VEC_EC_SIG: &[u8] = &[
    0x30, 0x44, 0x02, 0x20, ...   // 0x30 = DER SEQUENCE
];
```

这个向量当初是用 openssl 生成的，而**openssl 的默认输出就是 DER**。
于是「错误的实现 + 错误的向量」**一起错**，测试全绿、线上全挂。

> **教训**：自造测试向量只能证明"实现和向量一致"，证明不了"和标准一致"。
> 能抄标准（RFC 附录）就别自己编。

### 修复

```rust
("EC", "ES256") => &s::ECDSA_P256_SHA256_FIXED,   // r‖s，64 字节
("EC", "ES384") => &s::ECDSA_P384_SHA384_FIXED,   // r‖s，96 字节
```

### 测试

| 测试 | 作用 |
|---|---|
| `es256_rfc7515_官方向量必须验得过` | 用 **RFC 7515 附录 A.3** 的权威向量验签通过 |
| `es256_der_编码的签名必须验不过` | **反向门**：锁住"不再接受 DER" |
| `es384_签名长度必须是_96_字节` | 长度约束（64 字节不能当 ES384 用） |

同时**删掉**了那两个错误的 DER 向量常量，并在原处留注释说明"这里曾经有个错向量，
别再照着 openssl 默认输出造 EC 签名向量"。

### 退回验证 ✅

把 `FIXED` 改回 `ASN1` ⇒ 测试**变红**；还原 ⇒ 变绿；文件 sha256 一致。

---

## 二、真实 IdP 端到端测试（新增 9 条）

`common/tests/oidc_idp_e2e.rs` —— 在本机起一个**最小 HTTP server** 扮演 IdP，
提供 `/.well-known/openid-configuration` 与 `/jwks`，并用**真实的 ECDSA P-256
密钥**签发 JWT。整条链路（HTTP → JSON → JWKS → ring 验签）都真跑一遍。

| 测试 | 覆盖 |
|---|---|
| `真实_idp_discovery_与_jwks_与_es256_端到端` | 主干：discovery → JWKS → 真签名验签 |
| `真实_idp_密钥轮换后仍能验证` | IdP 换密钥后 `refresh()` 能拉到新的 |
| `未知_kid_必须拒绝` | 找不到 key 不能"放行" |
| `签名被篡改必须拒绝` | 改一个字符就拒 |
| `恶意_jwks_空密钥集要报错` | `{"keys":[]}` 不能当"没有密钥于是全放行" |
| `恶意_jwks_畸形_json_要报错` | 非 JSON |
| `恶意_jwks_垃圾坐标不崩溃` | `x`/`y` 是垃圾 base64 时不 panic |
| `discovery_缺_jwks_uri_要报错` | 没有 jwks_uri |
| `明文_jwks_uri_默认必须拒绝` | M9 修复的回归门（公钥走明文 = 认证可被绕过） |

---

## 三、完整的 PSF 状态机枚举（替代降级探针）

上一轮只有"降级探针"：喂 2 条跨状态消息看服务端不崩。那不算状态机覆盖。

现在做**真正的枚举**：`3 个协议阶段 × 20 条消息 = 60 个组合`，
每条都喂给真实服务端，断言三件事：

1. **不崩** —— 每次之后都能用新连接正常登录并注册代理；
2. **不挂住** —— 控制连接必须"要么还活、要么已被关闭"，**不能既不响应也不断**
   （那种会话会永久占住服务端槽位，是最难靠单测发现的问题）；
3. **不泄漏** —— 断开后该端口上的后端计数必须归零。

阶段：`PreLogin`（未登录）/ `PostLogin`（已登录未注册）/ `Registered`（已注册）。
消息：覆盖 `FrpMessage` **全部 20 个变体**，含服务端→客户端方向的那些
（客户端发它们就是协议方向违例，正是要测的输入）。

---

## 四、四个配置字段真正实现

之前它们只在 `UNSUPPORTED_*_FIELDS` 里**识别 + 告警**，现在都真正生效。

### 1. `quicBindPort`（服务端）

官方语义：**配了就开**一个独立 UDP 端口，与 `bindPort` 无关。

* 配了 ⇒ 只在那个端口开 UDP，**不再**顺带占 `bindPort/udp`
  （旧行为是隐式副作用，会让"我配了 7101，为什么 7000/udp 也被占"变成谜）；
* 没配且 `transport_protocol = "quic"` ⇒ 退回旧行为，老部署不变；
* 两种情况都保留 TCP 监听。

### 2. `includes`（客户端）

官方 `LoadAdditionalClientConfigs` 的语义：

1. 每项是路径或 **glob**；
2. 取目录、遍历普通文件、按文件名匹配；
3. 命中文件**只取 `proxies` 与 `visitors`** 追加；
4. 各文件的其它字段（`serverAddr`/`token`…）**一律忽略**。

★ 第 4 点最容易误解：`includes` 不是配置继承，而是**批量追加代理定义**。

实现细节：
* 自己写 `glob_match`，语义对齐 Go `filepath.Match`（`*`/`?`/`[a-z]`/`[^...]`）；
* 相对路径以**主配置所在目录**为基准；
* 目录内容**排序后**加载，保证确定性；
* 合并后重名 ⇒ **明确报错**（服务端按 name 定位代理，重名会让"踢一个"变成"随机踢"）；
* includes 文件通常不写 `serverAddr`，而 `parse_client` 要求必填 ⇒
  用 `parse_include_file` 补占位再解析，**不**另写一套宽松解析器
  （本项目吃过"同一语义写两遍只加固一遍"的亏）。

### 3. `tokenSource`（客户端 + 服务端）

官方 `ValueSource`：`type = "file"` 或 `"exec"`。

* `file` —— 读文件，**去首尾空白**（官方明确写过：文件末尾的换行不 trim 就对不上）；
* `exec` —— 跑子进程取 stdout，同样 trim。

优先级：**命令行 `-t` > `tokenSource` > `token`**（官方注释："mutually exclusive with Token field"）。

**安全处理（`exec`）**：
* **不经 shell**：`command` 与 `args` 分开传，不会被解释成 shell 语法；
* **10 秒超时**后强杀 —— 官方跟着 ctx 走没有上限，这里必须有，
  否则一个卡住的子进程会让客户端**永远起不来**；
* 启动日志明确打出令牌来源，便于审计；
* 取到的值只用于登录，**绝不进日志**（`Debug` 只输出路径/命令名）。

**位置（服务端）**：必须在 `check_token_strength` **之前**解析 ——
那个检查看的是实际生效的 token，先检查后解析等于检查空字符串（会误报"token 太弱"）。

### 4. `enablePrometheus`（服务端）

官方默认**不开** `/metrics`，配了才导出。我们之前**无条件开放**。

改成默认关闭，两处理由：
* 与官方默认不一致，照官方文档部署的人会以为它关着；
* 指标含业务信息（在线客户端数、代理名、流量字节），
  "只想开个面板"的部署等于**默认多暴露一份数据面**。

`/api/healthz` **不受影响** —— 健康探针永远可用，否则容器会被反复重启。

---

## 五、清单同步（防反向假警报）

实现归实现，`UNSUPPORTED_*_FIELDS` 也必须跟着改，否则会出现
**"说没实现而实际能用"** 的反向误导 —— 那比沉默更害人。

| 清单 | 本轮移除 |
|---|---|
| `UNSUPPORTED_CLIENT_FIELDS` | `includes`、`tokenSource` |
| `UNSUPPORTED_SERVER_FIELDS` | `quicBindPort`、`tokenSource`、`enablePrometheus` |

---

## 六、质量门

| 项 | 结果 |
|---|---|
| `cargo test --workspace -j 1`（串行） | ✅ **814 通过 / 0 失败**（上轮 785，+29） |
| `cargo fmt --all -- --check` | ✅ 干净 |
| `cargo clippy --workspace --all-targets -D warnings` | ✅ 0 告警 |
| `cargo audit` | ✅ exit 0 零漏洞（184 crates） |
| 退回验证（ES256） | ✅ 退回变红 / 还原变绿 / 文件干净 |

测试分布：123 + 386 + 9 + 251 + 17 + 26 + 2 = **814**（另有 3 条 Windows 真机测试标 #[ignore]，手动跑 3/3 通过）

---

## 七、Windows VirtualNet **已实现并真机验证**

### 实现

新增 `common/src/vnet/tun_windows.rs`（约 990 行），基于 **Wintun**
（WireGuard 项目的开源 TUN 驱动，Apache-2.0/GPLv2 双许可）。

选 Wintun 而不是 TAP-Windows 的理由：内核态驱动、只做 L3（正好是 VirtualNet
需要的）、WireGuard for Windows 生产在用、运行时无需静态链接。

**动态加载**：全部通过 `LoadLibraryExW` + `GetProcAddress`，**不在链接期依赖
wintun.dll** —— 没装驱动的机器程序照常启动，只有用到 VirtualNet 时才报错。
查找顺序：`NFRP_WINTUN_DLL` → exe 目录 → 当前目录 → 系统路径。
全都找不到时报错**可操作**（含下载地址、架构要求、放置位置）。

### 为什么用"后台线程 + 通道"而不是接 reactor

Wintun 的读接口是"事件 + 非阻塞取包"，那个 `HANDLE` 事件**没法直接接进 tokio
的 reactor**（`AsyncFd` 只在 unix 上有）。硬接要自己写 `Registration` + IOCP
集成，出错面大得多。

所以用最稳的：**一个专用阻塞线程**跑 `WaitForMultipleObjectsEx` + 取包，
推进 `tokio::sync::mpsc`，async 侧只收通道；写方向不需要等待，同步写。
代价是每条 TUN 多一个线程 —— 每个进程只有**一个** TUN，可接受。

### 三个真机验证（`#[ignore]`，用 `--ignored` 手动跑）

| 测试 | 证明什么 |
|---|---|
| `真机_创建网卡_配地址_再回收` | 驱动加载 / 适配器创建 / 会话启动 / IP 配置 / Drop 后网卡消失 |
| `真机_数据面_ping_由我们应答` | **IP 包双向流动**：内核 → TUN → 我们 → TUN → 内核 |
| `真机_非法地址前缀要报错` | 非法输入明确拒绝 |

**连跑 3 次全通过。**

### 踩到的三个坑（都写进代码注释了）

**① `netsh interface ipv4 set address` 对 Wintun 无效。**
实测：命令返回成功，但 `show addresses` 里只有 `DHCP enabled: No`，没有 IP。
原因是 Wintun 建的是 **L3 隧道适配器**，`netsh` 那条老路径对它不生效。
必须用 **IP Helper API** —— 这里经 `New-NetIPAddress`（就是它的封装）。

**② IP 地址偏移写错（最隐蔽）。**
交换源/目的地址时写成了 `(4, 16)` —— **offset 4 是 IP ID 字段**，不是源地址
（源地址在 **12**）。后果：ID/flags 和目的地址被对调、源地址原地不动，
内核收到直接丢。表现是"读方向通、写方向不通"，**没有任何报错**。
是 hex dump 才看出来的：

```
请求  45 00 00 3c d0 0f 00 00 80 01 db af 64 7f 63 01 64 7f 63 02
应答  45 00 00 3c 64 7f 63 02 40 01 1b b0 64 7f 63 01 d0 0f 00 00
      版本/len    ↑ID 被写坏     TTL/proto/ck  src 没交换    ↑ID 跑到这
```

**③ "加打印就好了"是假象。**
首次带诊断打印的版本"恰好"通过，因为 `eprintln` 拖了几秒 ——
而**网卡建卡后路由表要过一会儿才生效**，这期间 ping 的包根本不会进 TUN。
解法不是加打印，而是**多轮重试**（最多 3 轮，每轮起一次 ping）。

---

## 八、本轮**未完成**的（如实清单）

| 项 | 状态与原因 |
|---|---|
| **TSan** | ❌ 未完成。云端 nightly **下载了两小时仍未完成**（网络问题）。**没有结果就不报结果** |
| **Linux TUN Miri** | ❌ 未做。与 TSan 争同一个 nightly 安装 |
| **`plugin_bridge` Linux 竞态** | ❌ 未修好。上轮两次尝试都引入忙等死循环（云端 4 进程各烧 20 分钟 CPU），已回退并记录正确方向（让"读"只有一个所有者，需重构 `HttpIO` 所有权） |
| **剩余配置字段** | ❌ 未做：`useEncryption` / `useCompression`（数据面加密压缩，协议级改动）、`udpPacketSize`、`natHoleStunServer`、`dnsServer`、`proxyURL`、`pprofEnable`、`assetsDir`、`sshTunnelGateway`、`httpPlugins`、`natholeAnalysisDataReserveHours` |

### 关于 `plugin_bridge` 竞态（已确认是真 bug）

实测证据：同一测试在 Linux 上连跑 10 次 → **5 通过 / 5 次 5 秒超时**；
真实 TCP 链路也能复现（插件收到连接但请求从未转给上游）。
根因是 `HttpIo::watch_closed()` 用 `read(&mut chunk)` 读进局部数组，
future 被 `select!` 取消时那批字节消失。

**两次修复都失败**（都引入 100% CPU 忙等），已回退。正确方向已写进代码注释。

---

## 九、改动清单

| 文件 | 改动 |
|---|---|
| `common/src/auth/oidc.rs` | **ES256/ES384 从 ASN1 改为 FIXED**（核心修复）；删除两个错误的 DER 向量常量；新增 RFC 7515 官方向量与 DER 反向门 |
| `common/tests/oidc_idp_e2e.rs` | **新增**：真实 IdP 端到端测试 9 条 |
| `server/tests/e2e.rs` | **新增**：完整 PSF 状态机枚举（3 阶段 × 20 消息） |
| `common/src/config.rs` | `ServerConfig.quic_bind_port` / `enable_prometheus`；`ClientConfig.includes` + `merge_includes()` + `glob_match` 家族 + `parse_include_file` |
| `common/src/security.rs` | `ValueSource` / `FileSource` / `ExecSource` / `ExecEnvVar` + `validate` / `resolve` / `run_exec`；两端 `token_source` 结构化 |
| `common/src/frp_config.rs` | 两份清单各移除已实现项 |
| `server/src/serve.rs` | QUIC 监听改用 `quic_bind_port` |
| `server/src/dashboard.rs` | `/metrics` 受 `enable_prometheus` 控制；新增 4 条测试 |
| `server/src/main.rs`、`client/src/main.rs` | 启动时解析 `tokenSource` |
| `assets/frps.toml`、`assets/frpc.toml` | 新配置项说明 |

---

## 十、兼容性

* **协议零变更**：与官方 frp 0.71.0 互通不受影响；
* **OIDC 修复是纯增益**：以前 ES256 完全不能用，现在能用（RS256 不受影响）；
* **两处行为变更**（都向官方对齐，已在示例配置里写明）：
  1. `/metrics` 默认关闭 —— 要采集需配 `enablePrometheus = true`；
  2. 配了 `quicBindPort` 后不再占用 `bindPort/udp`；
* 其余新配置项都是"配了才生效"，不配时行为与之前完全一致。


<!-- ===== 14/14 第 16 轮 ===== -->

> **日期：2026-10-25** · **轮次：第 16 轮**

---

# NFrp 第十六轮 · 官方 0.71 兼容收尾与真实 e2e（2026-10-25）

本文件记录第十轮/第十五轮交接后，对 **官方 frp 0.71 剩余兼容项**、**官方 NatHole / xtcp**、
**SSH 隧道网关**、**HTTP 插件**、**pprof** 和 **Windows VirtualNet** 的收尾结果。

版本基线是工作区 `0.6.6`，未 commit / 未推送 / 未发版 / 未上传发布物。

---

## 1. 结论先说

- 官方 Windows `frpc.exe 0.71.0` 已与 NFrp 服务端完成**真实 xtcp / NatHole UDP 打洞**，
  visitor 访问成功；不是只看代码或只测登录。
- 官方 0.71 的控制连接、代理注册、`sshTunnelGateway`、`httpPlugins`、`pprof`、
  `useEncryption` / `useCompression`、`proxyURL`、`dnsServer`、`natHoleStunServer`
  均已有实现或真实测试；仍缺的是 `webServer.tls.*` 面板 HTTPS 和完整 HardNAT 分类。
- 收尾过程中真实抓到并修复 4 个问题：
  1. NatHole 把 `NatHoleSid` 直接写到控制连接 / 未先写 `StartWorkConn`；
  2. 工作连接池 `notify_waiters()` 丢失许可的竞态；
  3. SSH 网关代理指标只减不加，三条 SSH 代理断开后 `proxies_active = -3`；
  4. Linux `pprof::protos::Message` 导入路径错误（Windows 不编译该模块，差点漏到发布）。
- 本地全量 **867 passed / 0 failed**（3+5 ignored），`clippy -D warnings`、`fmt --check` 全绿。

---

## 2. 官方 NatHole / xtcp 真实 e2e

### 2.1 修复前的错误

官方 frps 的 xtcp 流程不是把 `NatHoleClient` 直接投到 provider 控制连接。实际顺序是：

1. visitor 发 `NatHoleVisitor`；
2. 服务端向 provider 申请一条**工作连接**；
3. 服务端先在这条工作连接上写 `StartWorkConn{proxy_name}`；
4. 再写 `NatHoleSid{sid}`；
5. provider 在 `InWorkConn()` 读到 Sid 后，用控制连接回 `NatHoleClient`；
6. 服务端回 `NatHoleResp`，双方 UDP 打洞。

先前实现漏了第 3 步，并且把 Sid 放到控制连接。官方 frpc 的 `handleReqWorkConn`
用 `StartWorkConn` 做类型/代理分发，收到 `NatHoleSid` 后按空代理名处理，连接被丢弃；
表现为 visitor 5 秒 `context deadline exceeded`、服务端 10 秒等 provider 超时。

### 2.2 修复

- `server/src/nathole_official.rs`：`start_session` 在独立任务里
  `acquire_work_conn_within(5s)`，成功后先写 `StartWorkConn`，再写 `NatHoleSid`；
  任一步失败就移除会话并把明确错误回给 visitor。
- `server/src/pool.rs`：`submit_work` 从 `notify_waiters()` 改 `notify_one()`。
  `notify_waiters()` 不保存许可；工作连接在等待者尚未 `await notified()` 时到达，
  通知会丢，连接留在池里，等待者超时。真实 e2e 命中了这个窗口。
- 单测同步改为先断言 `StartWorkConn.proxy_name`，再断言 `NatHoleSid.sid`。

### 2.3 真实结果

- 服务端：本地 `nfrp-server`，控制 `28100`；
- provider / visitor：官方 `frpc 0.71.0`；
- visitor 本地 `28098`，后端 HTTP `28099`。

visitor 日志：

```text
nathole prepare success, nat type: EasyNAT, behavior: BehaviorNoChange
get natHoleRespMsg, sid [...]
```

`Invoke-WebRequest http://127.0.0.1:28098/` 返回 `HTTP 200` 和真实 HTML。

证据目录：`tmp/final-handover/official_nathole_071/`
（`server.toml`、`provider.toml`、`visitor.toml`、两轮三端日志、
`visitor_http_200.txt`）。

**边界**：当前只覆盖 mode 0 / EasyNAT / 公网直连；HardNAT、端口预测、
多 STUN 地址、TTL 探测未实现，不能把“EasyNAT 通”写成“所有 NAT 都通”。

---

## 3. SSH 隧道网关

实现文件 `server/src/ssh_gateway.rs`，使用 `russh 0.54`（`ring` 后端，关闭
`aws-lc-rs`，启用 `rsa`）。

支持：

- `authorizedKeysFile` 非空时只接受文件内公钥，**公钥注释即 frp 用户名**；
  文件为空则不校验 SSH 公钥，但虚拟客户端仍必须用 `--token` 过 frps 认证；
- 命令行：`tcp` / `http` / `https` / `tcpmux` / `stcp`，参数支持 `--remote_port`、
  `--custom_domain`、`--subdomain`、`--proxy_name`、`--sk`、`--allow_users` 等；
- OpenSSH `ssh -R` 注册 `tcpip-forward`；真实用户连接通过 `forwarded-tcpip` 承载；
- 每条 SSH 连接注册为虚拟 `ClientState`，数据面复用 `spawn_bridge`；
- OpenSSH `-R` 不会消费 frp 帧，因此工作连接先用内存 duplex 模拟最小 frpc
  读掉 `StartWorkConn`，之后裸字节 relay；
- 监听在启动阶段同步绑定，端口占用会让启动失败，不在后台静默失败。

### 3.1 真实 e2e

`authorizedKeysFile` 带 options 前缀（`command="...",no-pty,...`）时：

- `tcp -R 0.0.0.0:27911:127.0.0.1:27999` 访问返回 200；
- `tcpmux --custom_domain tcp.example.com` 注册成功；
- `stcp --sk ...` 注册成功，面板 visitors 出现 `stcp`；
- 三条 SSH 全断开后：`clients_active=0`、`proxies_active=0`、`ports=[]`，
  端口 `27911` 立即 502（已释放），无幽灵客户端。

### 3.2 收尾中发现的指标 bug

首次 e2e 断开后面板显示：

```json
"proxies_total": 0, "proxies_active": -3
```

原因：普通 frpc 的 `NewProxy` 分支在 `register_proxy` 成功后自己给
`proxies_total/proxies_active` 加一；SSH 网关走同一个 `register_proxy`，却绕过了
那段分支，断开时 `Registry::remove()` 仍按代理数减一，于是负数。

修复：SSH 注册成功后补 `inc()`。修复后同场景：

```json
"proxies_total": 3, "proxies_active": 3
...
"proxies_active": 0
```

**边界**：TCP 数据面真实打通；`tcpmux` / `stcp` 只验证到注册与面板状态，
未构造 tcpmux HTTP CONNECT 访客和 stcp visitor 的完整数据面。

证据目录：`tmp/final-handover/sshgw_current/`
（配置、`authorized_keys`、`status_before/connected/after.json`、TCP 200 与服务器日志）。

---

## 4. pprof

- 实现移到 `common/src/pprof_http.rs`，Unix-only；服务端面板与客户端本地 Web
  共用；同一时刻只允许一个 CPU profile（`try_lock`）。
- 服务端路由：`/debug/pprof`、`/debug/pprof/`、
  `/debug/pprof/profile?seconds=N`；默认 10 秒、上限 60 秒、99Hz；
- 未启用 404；Windows 明确 501；其他采集错误 500。
- Linux release 真实请求：

```text
code=200 size=83
profile bytes: 0a 04 08 03 10 02 0a 04 08 01 10 04 ...
```

- 修复 Linux 编译：`use pprof::protos::Message as _;`；此前写成
  `use pprof::Message as _;`，Windows 因 `cfg(unix)` 不编译，云端 release 直接失败。
- 证据：`tmp/final-handover/pprof_linux_profile.pb`、`pprof_linux_server.log`。

Windows 只验证 404 / 501（没有 perf signal / `ucontext_t`），不能声称 Windows
能抓 profile。

---

## 5. HTTP 插件 / 数据面加密压缩 / 出站代理 / DNS / STUN

| 配置 | 实现 | 验证 |
|---|---|---|
| `httpPlugins` | `common/src/plugin.rs`，`Login` / `NewProxy` / `CloseProxy` / `Ping` / `NewWorkConn` / `NewUserConn`，URL `version=0.1.0&op=...`、`X-Frp-Reqid`、10 秒超时 | 本地插件 + 服务端 + 客户端真实 e2e；拒绝 `blocked-user` / `blocked-web`，改写 metas 被接受。证据 `tmp/final-handover/plugin_e2e/`；`CloseProxy` 本次未稳定抓到，只有代码路径覆盖 |
| `useEncryption` / `useCompression` | `ProxyStream` 包装 AES-128-CFB + snappy；服务端 `PendingUser` 携带 flags/token | 6 条单测/内存双端；未用官方 frpc 做该组合 e2e |
| `proxyURL` | `common/src/net_proxy.rs`，HTTP CONNECT + SOCKS5 | 已接入 `dial_server`；未对真实代理做 e2e |
| `dnsServer` | `common/src/dns.rs`，A/AAAA、UDP、手写 DNS 报文 | 5 条单测 |
| `natHoleStunServer` | `common/src/stun.rs`，RFC 5389 Binding Request | 6 条单测；客户端官方 xtcp 路径填 `mapped_addrs` |

官方 NatHole 分析记录：

- `natholeAnalysisDataReserveHours` 在 `serve_with` 前安装；
- 每次 NatHole 尝试/成功写记录，按保留期清理；
- `0` 小时 = 不保留；记录上限 8192；
- 补了保留期与 0 开关单测。

---

## 6. Windows VirtualNet

- `common/src/vnet/tun_windows.rs` 已有 Wintun 实现（适配器、会话、读写环形缓冲、
  IP 配置、Drop 回收），并有 `#[ignore]` 的真机网卡/数据面测试。
- 本次在非管理员会话新增可重复测试 `非管理员创建网卡要给提权提示`：
  有测试用 `wintun.dll` 时真实调用 `WintunCreateAdapter`，断言错误包含
  “拒绝访问”和“管理员”；管理员环境建完即删；无 DLL 时跳过。
- 缺失 DLL 错误仍由 `缺少_dll_时报错要可操作` 覆盖（含 `wintun.net` 与
  `NFRP_WINTUN_DLL`）。
- **未完成**：本次会话 `admin=False`，真实 Wintun 数据面（ping 双向）需提权后跑
  `cargo test -p nfrp-common -- --ignored 真机`。

---

## 7. 测试与质量门

```text
cargo test --workspace
125 + 422 + 9 + 266 + 17 + 26 + 2 = 867 passed, 0 failed
（common 3 ignored、doc-tests 5 ignored）

cargo clippy --workspace --all-targets --all-features -- -D warnings
Finished，0 warning（仅 russh future-incompat 提示）

cargo fmt --all -- --check
FMT_OK
```

证据：`tmp/final-handover/workspace-test-2.log`、`clippy3.log`。

云端 Linux release（`CARGO_BUILD_JOBS=2`）已成功编译 `nfrp-server` / `nfrp-client`；
pprof 端点真实 200。

---

## 8. 渗透复核修正

在 `tmp/pentest_round/PENTEST-REPORT.md` 第 12 节补充：

- v2 合法握手、非法 codec、65537 字节超长帧均真实执行；
- `POST /api/status` 在 0.6.3 返回 200，是真实低危问题；0.6.6 工作区已 405；
- 140 条空闲控制连接全部建立，约 11 秒回收；**控制面没有 128 上限**，
  `MAX_DASHBOARD_CONNS = 128` 是面板常量，不能混写；
- 0.6.3 仍有重复 `Authorization` first-wins、缺安全响应头、`/api/healthz`
  免鉴权；0.6.6 已补 XCTO/XFO/Referrer/CSP，HSTS 仍应由 TLS 终结层负责。

---

## 9. 仍未完成 / 不要误报

- ~~`webServer.tls.*` 面板 HTTPS：未实现，配置会明确报错。~~
  **这条已过时（2026-10-26 更正）**：`webServer.tls.certFile` / `keyFile` 早已实现
  —— rustls 包装面板与客户端 web 的监听器，只接受 HTTPS，并在响应上带
  `Strict-Transport-Security: max-age=31536000; includeSubDomains`。
  实测：HTTPS 200 正常取页面，明文 HTTP 被拒。
  上面保留原文是为了不改写历史记录，但**当前状态以本行为准**。
- 官方 NatHole 完整 NAT 分类：只做 mode 0 / EasyNAT。
- TSan、Linux TUN Miri、完整 PSF、Phaedra、真实 IdP OIDC e2e：环境/工具限制，
  不是“已通过”。
- `cargo vet` 的 184 条是 exemption，不是人工审计。
- SSH 的 tcpmux/stcp 完整数据面、官方 frpc 的加密+压缩组合、真实外部代理、
  真实 DNS 服务器未做 e2e。
- Windows Wintun 真实数据面需要管理员权限。

---

# 2026-10-26 · 第十七轮（本地复现报告驱动的 5 项修复）

本轮不是安全审计，而是**外部复现报告的闭环**。报告来自
《NFrp 本地复现与待修清单-2026-10-26》：在 commit `c7214ab`（0.6.6）上
**实弹复现**了 4 条问题（其中 3 条仓库从未记录、1 条记录过但没修），另指出
2 条工程项。全部处理完毕。

| 编号 | 问题 | 严重度 | 状态 |
|---|---|---|---|
| NFRP-05 | `/api/status` 手工拼 JSON，控制字符产生非法 JSON | 高（管理面可用性） | 已修 |
| NFRP-13 | 重复 `Authorization` 取第一个（first-wins） | 中（鉴权差异前置条件） | 已修 |
| NFRP-07 | `client_id` 换行注入，可伪造日志行 | 中（日志完整性） | 已修 |
| NFRP-06 | `locations` 前缀匹配被 dot-segment 绕过 | 中（当 ACL 用时无边界） | 已修 |
| NFRP-09 | 文档称"面板 TLS 未实现"，与代码不符 | 低（文档滞后） | 已修 |
| 依赖漏洞 | `cargo audit` 报 4 条 RUSTSEC 公告 | 中 | 已清零 |

## NFRP-05　`/api/status` 返回非法 JSON

**根因**：`status_json()` 用 `format!("{{... {:?} ...}}")` 拼 JSON。Rust 的
`Debug` 对控制字符输出 `\u{1}`（Rust 语法），JSON 只接受 `\u0001`。

**影响**：`client_id` / 代理名 / `user` **全部由远端客户端提供**。任意一个已
注册客户端（共享 frps 场景）塞一个 `\u0001` 就能让 `/api/status` 变成非法
JSON —— 面板 `JSON.parse` 白屏、外部采集器与告警全挂。等效于"让管理员看不见我"。

> 注意：**不是** JSON 结构注入 —— 引号会被正确转义，无法伪造字段。

**修复**：整段改用 `serde_json::json!`，转义交给库。

**验收**：真实 frps + 恶意 `client_id`，`/api/status` 被 Python 与 PowerShell
两个独立解析器成功解析，且响应里出现 `\u0001`。

**回归测试**：`status_json_对控制字符仍然合法`、`status_json_字段齐全`。

## NFRP-13　重复 `Authorization` 头取第一个

**根因**：`header_value()` 命中第一个同名头就 `return`。

**风险**：单独看不构成绕过（仍需密码）。风险在部署形态：面板前置
Nginx / WAF / SSO 网关时，上游与 NFrp 对"哪个 `Authorization` 生效"的理解
一旦相反，就是鉴权差异 —— 请求走私类问题的经典前置条件。

**修复**：新增 `unique_header()`，同名安全头出现两次及以上一律 400。

**验收**：两个 `Authorization`（任意顺序）→ **都是 400**（修复前是 401 / 200 随顺序翻转）。

**回归测试**：`重复_authorization_被判为畸形`、`重复_authorization_返回_400`。

## NFRP-07　`client_id` 换行注入日志

**根因**：`info!(%client_id, ...)` 走 `Display`，原样写入，不转义控制字符。

**影响**：带 `\n` 的值能凭空多出一行**与真实格式完全一致**的日志（实测已复现），
`grep` / SIEM / 人工排查都区分不出来；带 `\u001b[2J` 还能清屏，甚至触发
OSC 52 剪贴板写入。

**修复**：新增 `common::util::LogSafe`，把控制字符转成可见的 `\u{X}`。
已覆盖 `client_id`（4 处）、SNI（3 处）、`Host`（1 处）。
`audit.rs` 那条路本来就过 `serde_json`，无需改。

**验收**：日志里**不再出现**伪造行，控制字符显示为 `\u{1}` / `\u{a}`。

**回归测试**：`log_safe_转义控制字符`。

## NFRP-06　`locations` 前缀匹配被 dot-segment 绕过

**根因**：`match_location()` 用 `path.starts_with(loc)`，而 `path` 是请求行原文，
未做百分号解码、未做 dot-segment 归一化，命中后又原样转发。

**复现**：后端会做归一化（nginx / IIS / Apache 默认行为），于是
`/public/../admin` 在 NFrp 这边命中 `/public`、到后端变成 `/admin`。

**诚实定性**：上游 `fatedier/frp` 的 `pkg/util/vhost/router.go` 同样是
`strings.HasPrefix` —— 所以**这不是 NFrp 引入的**，是"对齐上游"的结果。
但很多用户把 `locations` 当路径级 ACL 用（"只暴露 /public"），实际它不是安全边界。

**修复**：选最保守的方案 —— 请求目标含 dot-segment（`.` / `..`，含 `%2e` /
`%2E` 编码）一律 400，不做"规范化后转发"（不猜客户端意图）。

**验收**：`/public/../admin` 与 `/public/%2e%2e/admin` 都是 400；
`/public/hello` 正常 200。**不再泄露 `ADMIN-SECRET`**。

**回归测试**：`dot_segment_能识别`、`locations_前缀匹配会被_dot_segment_绕过`。

## NFRP-09　文档更正

`SECURITY-ALL-FIXES.md` 里"`webServer.tls.*` 面板 HTTPS 未实现"的表述已过时
（该功能早已实现并有实测），已在原处加**更正说明**并保留原文（不改写历史），
另外在若干历史清单前加了"以当前代码/实测为准"的时效提示。

## 依赖漏洞（`cargo audit` 清零）

CI 的 `rustsec/audit-check` 报出 4 条公告，全部来自 SSH 网关的 `russh` 依赖链：

| 公告 | crate | 处理 |
|---|---|---|
| RUSTSEC-2026-0154 | russh 0.54.5（无界 32 位分配） | 升级（需 ≥0.60.3） |
| RUSTSEC-2026-0153 | russh-cryptovec 0.52.0 | 同上 |
| RUSTSEC-2023-0071 | rsa 0.9.10（Marvin Attack，**上游无修复**） | 见下 |
| RUSTSEC-2026-0387 | crypto-bigint 0.5.5（常量时间问题） | 见下 |

**关键发现**：升到 `russh 0.60` 后 `rsa` 仍是**硬依赖**
（`internal-russh-forked-ssh-key` 无条件依赖），关 feature 也去不掉；
而 `russh 0.65` 把 rsa 改成了 **feature**（`rsa = ["ssh-key/rsa"]`）——
不开它，`rsa` 与 `crypto-bigint` 就彻底不进依赖树。

**处置**：升到 `russh 0.65` 且**不开 `rsa` feature**，并适配 4 处 API 变化：
`auth_publickey_offered(PublicKeyOffer)`、`auth_publickey(VerifiedPublicKey)`、
`channel_open_session(ChannelOpenHandle) -> Result<()>`、`Comment::as_str()`。

**代价（已写入 Cargo.toml 注释）**：SSH 网关不再支持 **RSA 客户端证书认证**，
ed25519 / ECDSA 照常。鉴于 ed25519 是现代默认、且 RSA 那条路带着一个
**上游明确声明无法修复**的侧信道漏洞，这个取舍是明确的。

**结果**：`cargo audit` **0 漏洞**（330 个依赖）。

## 质量门（本轮结束）

- **887 项测试通过 / 0 失败**
- clippy（`-D warnings`）0 告警；fmt 干净
- `cargo audit` **0 漏洞**
- 真实服务验收：**4/4 通过**（PoC1 合法 JSON + `\u0001`、PoC2 双 400、
  PoC3 双 400 且无泄露、PoC4 无伪造日志行）

## 附：CI 的两处修复

1. `clippy` 在 CI（最新 stable）上因 `AtomicU64::fetch_update` 被标记 deprecated
   而失败 —— 本地 1.98.1 还没有 `try_update`，两边都要能编，故加
   `#[allow(deprecated)]` 并注释说明。
2. `cross build aarch64-unknown-linux-musl` 失败于
   `weak version GLIBC_2.29 not found` + `symbol gettid` relocation ——
   是 cross 默认镜像的基础 glibc 太旧（报错发生在 build script 阶段，
   与本项目代码无关），已把 CI 的 cross 切到 `edge` 镜像。

---

# 2026-10-29 · 发布通道：CI 从"长期红"到全绿

> 这一节不属于安全审计，是**工程收口**。放在这里是因为它直接决定第 8、9 条铁律
> （`cfg(linux)` / `cfg(unix)` 的代码）有没有执行通道。

## 一、先纠正上一节的记录

第十七轮文末写着「已把 CI 的 cross 切到 `edge` 镜像」。**这条不成立**：
当时的改动只是加了一句 `docker pull ghcr.io/cross-rs/<target>:edge || true`，
而 `cross` **不读这条命令的结果** —— 它的镜像名来自自己的配置，实际仍然拉
`0.2.5`。日志里两行 Pull 挨着出现，前一行是那次白拉的：

```
cross-rs/x86_64-unknown-linux-musl:edge        ← 白拉的那次
cross-rs/x86_64-unknown-linux-musl:0.2.5       ← cross 真正用的
```

## 二、分诊（这次拿到了真实日志）

拉取 run `40858106143`（2026-10-29，commit `fa870180`）的完整日志，
落在 `tmp/ci-triage/`（`tmp/` 不入库）。**七个 job 的结论是：**

| job | 结论 |
|---|---|
| fmt / clippy（含 `cargo audit`） | 绿 |
| unit tests (ubuntu-latest) | 绿 |
| unit tests (windows-latest) | 绿 |
| unit tests (macos-latest) | 绿 |
| cross build x86_64-unknown-linux-musl | 绿 |
| cross build aarch64-unknown-linux-musl | **红** |
| e2e smoke | 绿 |

再往前抽查 run `40493253116` / `40493212889` / `40490696089` / `40338921657`
（2026-10-26 ~ 10-27），**形状完全一致：只有 aarch64 musl 红**。

⇒ 「ubuntu / macOS 单测红、clippy 红」的记录已经过期。真正待修的只有一项，
且它属于分诊表里的**类型③（环境/工具链漂移）**，不是产品缺陷。

## 三、根因：`rust-cache` 的缓存串台，不是镜像太旧

报错原文：

```
error: failed to run custom build command for `libc v0.2.189`
  /target/release/build/libc-6063b2c310dd0a59/build-script-build:
  /lib/x86_64-linux-gnu/libc.so.6: weak version `GLIBC_2.28' not found
  ... `GLIBC_2.29' ... `GLIBC_2.30' ...
  relocation error: ... symbol gettid version GLIBC_2.30 not defined
```

三个关键事实拼起来就能定性：

1. **报错发生在 `libc` 的 build script 上**，还没编到本项目任何一行代码；
2. `build-script-build` 的路径是 `/target/release/build/...` ——
   **没有 target triple 这一段**，说明它是**宿主**（x86_64 gnu）产物；
3. `Swatinem/rust-cache` 的默认 key 是 `v0-rust-${job}-${os}-...`，
   矩阵里两个 target 的 `job` 名都叫 **`cross-build`** ⇒ **共用一个 key**
   （日志：`Cache hit for: v0-rust-cross-build-Linux-x64-2d46f225-899c067c`）。

于是：x86_64 任务在容器里编出的宿主 build script 被存进缓存 →
aarch64 任务把它还原出来、放进**自己那个基础镜像更老的容器**里执行 →
宿主二进制要求的 glibc 版本比容器里的新 ⇒ 上面那串报错。

这也解释了为什么**只有 aarch64 红**：两个镜像的基础系统不是一个年代，
而缓存是共用的。

## 四、修法（只改 CI，不碰产品代码）

```yaml
- uses: Swatinem/rust-cache@...
  with:
    key: cross-${{ matrix.target }}      # 两个 target 不再互相还原
    workspaces: ". -> target-cross"      # 产物与宿主的 build script 隔离

- name: build --release
  env:
    CARGO_TARGET_DIR: target-cross
    CROSS_CONTAINER_OPTS: --platform linux/amd64
  run: cross build --release --workspace --target ${{ matrix.target }}
```

同时删掉那条白拉的 `docker pull ...:edge`，并把过时的注释改成真实原因。

★ 没有做的事（守第十七轮的口径）：**没有**给任何测试加 `#[ignore]`、
**没有**加 `allow`、**没有**改编译参数。

## 五、验收

| 项 | 结果 |
|---|---|
| 推送后首个 run `40866116928`（commit `b20e7a53`） | **7/7 全绿**（含 aarch64） |
| 连续 3 次 push 全绿 | **进行中**：第 1 次已绿，第 2、3 次在后续两次推送后回填（本表随进度更新，不预先断言） |
| 失败日志存档 | `tmp/ci-triage/`（7 个 job 全文） |
| 分诊结论落表 | 本节第二节 |

**连续性**：`40866116928`（b20e7a53）是第一次全绿 —— 它证伪了第十七轮"edge 镜像已修好"
的说法，也证明缓存串台就是根因。**只绿一次不算数**（可能是缓存刚好没串台），
所以本轮要求再连续两次推送同样全绿，才把"第 8、9 条铁律恢复执行通道"写成结论。
在两次都绿之前，这里只写"第 1 次绿"，不写"已经稳定"。

## 六、顺带收口的产物链路（同一天）

| 问题 | 处理 |
|---|---|
| 构建目录靠环境变量 `CARGO_TARGET_DIR=D:\cargo-target`，而该目录已被删 | 固定到 `D:\cargo-target-nfrp`，写进 `nfrp/.cargo/config.toml`（本机文件，不入库）；仓库里那份 2026-10-13 的旧 `target/` 归档到 `tmp/target-legacy-20261013/` |
| 打包脚本可能读到旧产物 | `release.py pack` 支持 `平台:@release`（从 `cargo metadata` 的 `target_directory` 推导），并在打包后**解包做 sha256 自检**，不一致非零退出 |
| `dist/release` 只有 3 个包，Release 有 8 个资产 | 补齐（安卓包 + 源码包），并新增 `scripts/verify_dist_matches_release.py` 作为发版闸门 |
| `dist/android` 并存 0.5.3 ~ 0.6.6 十四份 | 只留当前版本，其余移入 `dist/android/backup/` |
| crates.io 的 0.6.6 ≠ Release 的 0.6.6，但没人告诉用户 | README 明确写出，并定下"下个版本起先发 crate、再用同一次构建打包 Release" |
| `nfrp/dist/release` 里还有一份**更早的** 0.6.6（与 Release 字节不同） | 归档为 `nfrp/dist/.legacy-release-20261029/`，交付目录只认仓库上一层 `dist/` |
| `release.py` 在中文路径下直接崩 | `cargo metadata` 的输出是 UTF-8，而 `text=True` 在简体中文 Windows 上用 GBK 解码 ⇒ 读取线程抛 `UnicodeDecodeError`、`stdout` 变成 `None` ⇒ 报 `TypeError: ... not NoneType`。现在显式 `encoding="utf-8"`，并把"什么都没输出"单独报成一句人话（gpg 的两处调用一并加固） |

## 七、这一轮的教训

1. **"记忆里的现状"必须复核**：文档说"CI 全面红"，实测只剩一个 job 红；
   文档说"已切 edge 镜像"，实际那条命令是空转。两处都差一点让人去修不存在的问题。
2. **缓存也是一种输入**：跨平台/跨容器的产物缓存，key 里必须带 target triple。
   同一份代码在两种环境里"一个绿一个红"，先怀疑共用的中间产物。
3. **收口要有闸门**：这轮加的"打包后 sha256 自检"和"dist 与 Release 比对"
   都不是为了这一次，是为了下一次不用靠人记得。

---

## v0.7.1 发布记录（2026-10-29）

Release id 427869196，tag 0.7.1，指向 2fb1ffa9。

### CI：连续 3 次全绿

| # | run | 提交 | 结果 |
|---|---|---|---|
| 1 | 40866116928 | 20e7a53（只改 CI） | 7/7 绿 |
| 2 | 40873116721 | 1e21ddaa（C 组修复 + 版本号） | 7/7 绿 |
| 3 | 40874794218 | 2fb1ffa9（发版脚本进仓库 + README 对齐） | 7/7 绿 |

### 8 个资产（sha256 取自 SHA256SUMS.txt）

| 资产 | 大小 | sha256（前 16 位） |
|---|---|---|
| 
frp-windows-amd64.zip | 4.32 MB | c7db7fb5b089abda |
| 
frp-linux-amd64.tar.gz | 5.03 MB | 8dcd68f8070ada45 |
| 
frp-linux-arm64.tar.gz | 5.64 MB | 701279545115c8a6 |
| 
frp-android-v0.7.1.zip | 9.28 MB | 6247308907774dce |
| 
frp-src-067.tar.gz | 1.19 MB | 5818d8e4d7259e1 |
| SHA256SUMS.txt / .sig / 
elease.pub | — | Ed25519 指纹 763896b5…（与 0.6.6 同一把钥匙） |

闸门实测：erify_dist_matches_release.py --check-android → 8/8 名称与 sha256 全部一致。

### 各产物在哪编（下次照着做）

| 产物 | 位置 | 命令要点 |
|---|---|---|
| windows-amd64 | 本机 | cargo build --release --workspace |
| linux-amd64 | 云服务器 | cargo build --release（glibc 动态，形状与 0.6.6 一致） |
| linux-arm64 | **本机 WSL Ubuntu 24.04** | pt install gcc-aarch64-linux-gnu；RUSTFLAGS="-C target-feature=+crt-static"；CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER=aarch64-linux-gnu-gcc |
| android ×2 | 本机 | NDK 30 的 arch64/x86_64-linux-android26-clang，见 README「发布与部署 › 打包」一节的安卓编译命令 |

### 两个真实踩到的坑

1. **云服务器编 arm64 被 OOM 杀**。机器只有 1.8 GB 内存，release profile 是
   lto + codegen-units=1 + opt-level=z，两个 bin 同时链接时 rustc 峰值顶穿内存，
   内核直接 SIGKILL（日志里是 rror: could not compile ... (signal: 9)）。
   结论：**在内存小的机器上编就加 -j 1**，一个 bin 一个 bin 来。
   （清理服务器时顺带删掉了那棵树留下的 9.6 GB 构建缓存，见桌面清理记录。）
2. **WSL 里没法直接 cargo build**：static.rust-lang.org 不通（用中科大镜像装 rustup），
   crates.io 索引只有 68 B/s（cargo vendor 跑十几分钟一个文件都没写）。
   最终做法：从 Cargo.lock 取每个 crate 的 checksum，为 Windows 上已解压的
   
egistry/src/<crate> 目录补一个 .cargo-checksum.json（iles 留空），
   再用 [source.crates-io] replace-with 指过去，CARGO_NET_OFFLINE=true 编译。
   —— 记在这里，是为了下次不用再试一遍。

### 安卓包的位置约定（这轮补的）

pack_android.py 现在把 zip 同时写到 dist/android（当前版本核对用）和
dist/release（Release 资产目录）。只写前者的话，发版闸门会报
“Release 里有、本地 dist/release 没有”。
