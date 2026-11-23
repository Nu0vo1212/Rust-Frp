# 修复编年史（从代码注释迁出）

本文件承接从代码注释迁出的版本编年史。代码里只保留面向未来的「为什么这样写 / 改回去会怎样 / 协议依据」，不再保留「哪一版修的」这类历史标记。

> 说明：日期、回归测试名均来自原注释；原注释未写的一律标记为「未标注」，未做推断。

> 若原注释只有一条陈述，问题与结论列会给出同一段原文的技术表述，不做二次演绎。

> 文件路径为迁移后的真实路径；`行号` 指迁移前原注释在文件中的起始行。


## v0.7.x

| 文件 | 行号 | 日期 | 问题 | 结论（代码保留的技术说明） | 回归测试 | 原文摘录 |
|---|---|---|---|---|---|---|
| `client/src/main.rs` | 416 | 未标注 | 把失败原因也写进本地面板。 | 把失败原因也写进本地面板。 | 未标注 | ★ v0.7.6：把失败原因也写进本地面板。 |
| `client/src/visitor.rs` | 311 | 未标注 | 能不能直连由 `nlink:policy:decide_direct` **唯一**决定 | 能不能直连由 `nlink:policy:decide_direct` **唯一**决定 | 未标注 | ★ v0.7.0：能不能直连由 `nlink::policy::decide_direct` **唯一**决定<br>（服务端、客户端、测试共用同一份判断）。三种结果：<br>* Direct —— 试打洞，失败按策略回退（`direct-only` 不回退，直接报错）；<br>* Relay  —— 一开始就不试（`relay-only`，或明确不可能成功）；<br>* Fail   —— 策略要求直连但条件不满足：**必须报错**，不能静默降级。 |
| `client/src/web.rs` | 114 | 未标注 | 自启动场景（`frpc.vbs` 隐藏窗口）下没有控制台，进程又按 | 自启动场景（`frpc.vbs` 隐藏窗口）下没有控制台，进程又按 | 未标注 | ★ v0.7.6：自启动场景（`frpc.vbs` 隐藏窗口）下没有控制台，进程又按<br>退避策略**不再退出**，于是失败会完全静默 —— 用户只看到面板里的空列表。<br>这里把最后一次错误留在内存里，由 `/api/status` 与页面直接展示。 |
| `client/src/web.rs` | 848 | 未标注 | 最近一次失败原因。自启动（隐藏窗口）时这是唯一能看到 | 最近一次失败原因。自启动（隐藏窗口）时这是唯一能看到 | 未标注 | ★ v0.7.6：最近一次失败原因。自启动（隐藏窗口）时这是唯一能看到<br>"为什么列表是空的"的地方。 |
| `client/src/web.rs` | 912 | 未标注 | 注册结果。`registered = false && error 空` 表示"还没收到 | 注册结果。`registered = false && error 空` 表示"还没收到 | 未标注 | ★ v0.7.6：注册结果。`registered = false && error 空` 表示"还没收到<br>服务端回应"（注册中 / 控制连接刚断），面板据此区分三种状态。 |
| `client/src/web.rs` | 1554 | 未标注 | 面板必须能看到「为什么列表是空的」。 | 面板必须能看到「为什么列表是空的」。 | `面板暴露最近失败原因与代理注册结果` | ★★ v0.7.6 回归：面板必须能看到「为什么列表是空的」。 |
| `common/src/config/client.rs` | 93 | 未标注 | # 与官方 0.71 的差异 | # 与官方 0.71 的差异 | 未标注 | # 与官方 0.71 的差异（v0.7.5 起，针对开机自启） |
| `common/src/frp/quic.rs` | 50 | 未标注 | 缓存按 **ALPN 分桶**。 | 缓存按 **ALPN 分桶**。 | 未标注 | ★ v0.7.0：缓存按 **ALPN 分桶**。 |
| `common/src/frp/quic.rs` | 468 | 未标注 | 缓存**按 ALPN 分桶**。 | 缓存**按 ALPN 分桶**。 | `不同_alpn_各自独立且能同时服务` | ★ v0.7.0：缓存**按 ALPN 分桶**。 |
| `server/src/serve/register.rs` | 318 | 未标注 | udp 此前漏记数据面标志与代理类型。 | udp 此前漏记数据面标志与代理类型。 | 未标注 | ★ v0.7.6 修：udp 此前漏记数据面标志与代理类型。 |
| `server/src/serve/register.rs` | 415 | 未标注 | vhost（http / https / tcpmux）此前**既没记类型，也没记 | vhost（http / https / tcpmux）此前**既没记类型，也没记 | 未标注 | ★ v0.7.6 修：vhost（http / https / tcpmux）此前**既没记类型，也没记<br>加密/压缩标志** —— tcp / stcp / xtcp 都记了，只有这三条漏了。 |
| `server/src/vhost/conn.rs` | 29 | 未标注 | vhost 的三条转发路径（http / https / tcpmux）此前都是**直接对 | vhost 的三条转发路径（http / https / tcpmux）此前都是**直接对 | 未标注 | ★ v0.7.6 修：vhost 的三条转发路径（http / https / tcpmux）此前都是**直接对<br>原始工作连接做中继**，`useEncryption` / `useCompression` 被完全忽略。<br>客户端开了加密时，服务端把密文当成明文透传 —— 隧道能建立、握手也可能过，<br>但数据全乱或直接超时，而日志里没有任何报错。 |
| `server/src/vhost/conn.rs` | 152 | 未标注 | vhost 工作连接必须按代理的加密/压缩标志包装。 | vhost 工作连接必须按代理的加密/压缩标志包装。 | `vhost_工作连接必须按加密压缩标志包装` | ★★ v0.7.6 回归：vhost 工作连接必须按代理的加密/压缩标志包装。 |
| `server/src/vhost/http.rs` | 557 | 未标注 | `leftover` 已经由 `wrap_work_stream` 挂成流的**读前缀**， | `leftover` 已经由 `wrap_work_stream` 挂成流的**读前缀**， | 未标注 | ★ v0.7.6：`leftover` 已经由 `wrap_work_stream` 挂成流的**读前缀**，<br>这里传空缓冲即可 —— 再传一次会重复消费。 |

## v0.6.x

| 文件 | 行号 | 日期 | 问题 | 结论（代码保留的技术说明） | 回归测试 | 原文摘录 |
|---|---|---|---|---|---|---|
| `client/src/dial.rs` | 163 | 未标注 | 配了 `dnsServer` 就用它解析服务端域名； | 配了 `dnsServer` 就用它解析服务端域名； | 未标注 | ★ v0.6.6：配了 `dnsServer` 就用它解析服务端域名；<br>没配就走系统 resolver（原路径，行为不变）。 |
| `client/src/dial.rs` | 179 | 未标注 | `transport.proxyURL` —— 走出站代理时直接拿到一条已建好的隧道流； | `transport.proxyURL` —— 走出站代理时直接拿到一条已建好的隧道流； | 未标注 | ★ v0.6.6：`transport.proxyURL` —— 走出站代理时直接拿到一条已建好的隧道流；<br>不走代理时保持原样（TcpStream + nodelay）——零回归。 |
| `client/src/health.rs` | 138 | 未标注 | 官方：官方 `client/health/health.go` 的 `doHTTPCheck` 用的是 | 官方：官方 `client/health/health.go` 的 `doHTTPCheck` 用的是 | 未标注 | ★ v0.6.2 对齐官方：官方 `client/health/health.go` 的 `doHTTPCheck` 用的是<br>`if resp.StatusCode/100 != 2 { return error }` —— **严格 2xx**。 |
| `client/src/health.rs` | 178 | 未标注 | 官方在 `doHTTPCheck` 里把配置的 header 全设进 `req.Header`，再用 | 官方在 `doHTTPCheck` 里把配置的 header 全设进 `req.Header`，再用 | 未标注 | ★ v0.6.3（对齐官方 `HealthCheckConfig.HTTPHeaders`）：<br>官方在 `doHTTPCheck` 里把配置的 header 全设进 `req.Header`，再用<br>`req.Host = header.Get("Host")` 单独覆盖 Host。这里照做：<br>配置里有 `Host` 就用它，没有才用兜底值 `healthcheck`。 |
| `client/src/health.rs` | 220 | 未标注 | 探测请求构造（对齐官方 HTTPHeaders） | 探测请求构造（对齐官方 HTTPHeaders） | 未标注 | ------------------------------------------------------------------<br>v0.6.3：探测请求构造（对齐官方 HTTPHeaders）<br>------------------------------------------------------------------ |
| `client/src/main.rs` | 117 | 未标注 | `auth.tokenSource` —— 从文件 / 外部命令取 token。 | `auth.tokenSource` —— 从文件 / 外部命令取 token。 | 未标注 | ★ v0.6.5：`auth.tokenSource` —— 从文件 / 外部命令取 token。 |
| `client/src/p2p.rs` | 300 | 未标注 | 从 `ClientConfig` 在 [`setup`] 时拷贝过来 —— 这里不持 `&ClientConfig` | 从 `ClientConfig` 在 [`setup`] 时拷贝过来 —— 这里不持 `&ClientConfig` | 未标注 | ★ v0.6.6：从 `ClientConfig` 在 [`setup`] 时拷贝过来 —— 这里不持 `&ClientConfig`<br>是因为它要跨 task 共享（引用活不了那么久）。<br>空字符串 = 不做 STUN 探测。 |
| `client/src/p2p.rs` | 405 | 未标注 | 配了 `natHoleStunServer` 就先探一下自己的公网映射地址。 | 配了 `natHoleStunServer` 就先探一下自己的公网映射地址。 | 未标注 | ★ v0.6.6：配了 `natHoleStunServer` 就先探一下自己的公网映射地址。 |
| `client/src/plugin_bridge.rs` | 222 | 未标注 | 这里修好了 记录的那个 Linux 竞态 | 这里修好了 记录的那个 Linux 竞态 | 未标注 | # ★★ v0.6.7：这里修好了 v0.6.4 记录的那个 Linux 竞态 |
| `client/src/plugin_bridge.rs` | 251 | 未标注 | 关键顺序：先看缓冲，再进 select!。 | 关键顺序：先看缓冲，再进 select!。 | 未标注 | ★ 关键顺序：先看缓冲，再进 select!（见上面 v0.6.7 说明）。<br>缓冲里有数据说明对端活着、且那批字节已经安全落在 io.buf 里，<br>继续 select! 只会让 watch_closed 立刻返回 ⇒ 忙等。 |
| `client/src/plugin_bridge.rs` | 1180 | 未标注 | 的「关门测试」：`wait_upstream` **不许忙等**。 | 的「关门测试」：`wait_upstream` **不许忙等**。 | `wait_upstream_不许忙等` | ★★★ v0.6.7 的「关门测试」：`wait_upstream` **不许忙等**。 |
| `client/src/plugin_bridge.rs` | 1238 | 未标注 | 修之前这条路径在 Linux 上 10 次跑出 5 次 5 秒超时 | 修之前这条路径在 Linux 上 10 次跑出 5 次 5 秒超时 | `端到端_http2http_连跑20次不许偶发挂住` | ★★ v0.6.7 回归：修之前这条路径在 Linux 上 10 次跑出 5 次 5 秒超时<br>（"插件收到连接却从未把请求转给上游"）。单跑一次抓不住竞态，<br>所以连跑 20 次 —— 单次失败概率 50% 时，20 次全过的概率是 1e-6。 |
| `client/src/udp_proxy.rs` | 45 | 未标注 | 单报文缓冲上限（官方 frpc 的 `udpPacketSize`） | 单报文缓冲上限（官方 frpc 的 `udpPacketSize`） | 未标注 | ★ v0.6.6：单报文缓冲上限（官方 frpc 的 `udpPacketSize`） |
| `client/src/udp_proxy.rs` | 114 | 未标注 | 单报文缓冲上限（官方 frpc 的 `udpPacketSize`） | 单报文缓冲上限（官方 frpc 的 `udpPacketSize`） | 未标注 | ★ v0.6.6：单报文缓冲上限（官方 frpc 的 `udpPacketSize`） |
| `client/src/work_conn.rs` | 210 | 未标注 | 数据面加密 / 压缩（官方 transport.useEncryption / useCompression） | 数据面加密 / 压缩（官方 transport.useEncryption / useCompression） | 未标注 | ★ v0.6.6：数据面加密 / 压缩（官方 transport.useEncryption / useCompression） |
| `common/src/auth/oidc.rs` | 613 | 未标注 | **仅测试用** —— 直接往绑定表里塞一条，模拟"该会话登录成功过"。 | **仅测试用** —— 直接往绑定表里塞一条，模拟"该会话登录成功过"。 | 未标注 | ★ v0.6.1：**仅测试用** —— 直接往绑定表里塞一条，模拟"该会话登录成功过"。 |
| `common/src/auth/oidc.rs` | 764 | 未标注 | ES256 / ES384 原先用 `*_ASN1`，而 JWS 的签名格式**不是 DER**。 | ES256 / ES384 原先用 `*_ASN1`，而 JWS 的签名格式**不是 DER**。 | 未标注 | ★★ v0.6.5 修（真实 IdP e2e 发现，**高危可用性**）：<br>ES256 / ES384 原先用 `*_ASN1`，而 JWS 的签名格式**不是 DER**。 |
| `common/src/auth/oidc.rs` | 1358 | 未标注 | 原 `VEC_EC_SIG` 已删除。 | 原 `VEC_EC_SIG` 已删除。 | 未标注 | ★ v0.6.5：原 `VEC_EC_SIG` 已删除。 |
| `common/src/auth/oidc.rs` | 1425 | 未标注 | **改用 RFC 7515 附录 A.3 的官方测试向量**。 | **改用 RFC 7515 附录 A.3 的官方测试向量**。 | `es256_rfc7515_官方向量必须验得过` | ★★ v0.6.5：**改用 RFC 7515 附录 A.3 的官方测试向量**。 |
| `common/src/config/client.rs` | 385 | 未标注 | 官方先做 `nathole.Prepare([stun], ...)` 拿到自己的 | 官方先做 `nathole.Prepare([stun], ...)` 拿到自己的 | 未标注 | ★ v0.6.6：官方先做 `nathole.Prepare([stun], ...)` 拿到自己的<br>`XOR-MAPPED-ADDRESS`，再把它填进 `NatHoleVisitor.mapped_addrs`<br>交给服务端撮合。没有它只能靠"服务端看到的源地址"猜映射 —<br>锥形 NAT 下够用，对称 NAT / 多出口时会给错地址，打洞必然失败。 |
| `common/src/config/client.rs` | 400 | 未标注 | 只影响**本进程**解析服务端地址时用哪个 DNS， | 只影响**本进程**解析服务端地址时用哪个 DNS， | 未标注 | ★ v0.6.6：只影响**本进程**解析服务端地址时用哪个 DNS，<br>不动系统设置（官方注释："If this value is empty, the system default<br>will be used"）。 |
| `common/src/config/client.rs` | 417 | 未标注 | 支持 `http://` / `https://` / `socks5://` / `socks5h://`， | 支持 `http://` / `https://` / `socks5://` / `socks5h://`， | 未标注 | ★ v0.6.6：支持 `http://` / `https://` / `socks5://` / `socks5h://`，<br>可带 `user:pass@`（HTTP Basic 或 SOCKS5 用户名密码）。 |
| `common/src/config/client.rs` | 570 | 未标注 | 官方 frp 在服务端面板（frps `webServer`）和客户端本地面板（frpc | 真正加载证书并启动 HTTPS listener。 | 未标注 | 官方 frp 在服务端面板（frps `webServer`）和客户端本地面板（frpc<br>`webServer`）都接受同一组字段。NFrp 旧版只识别但明确报“未实现”；从<br>v0.6.7 起真正加载证书并启动 HTTPS listener。 |
| `common/src/config/client.rs` | 790 | 未标注 | `includes` 合并（官方 `LoadAdditionalClientConfigs`） | `includes` 合并（官方 `LoadAdditionalClientConfigs`） | 未标注 | ★ v0.6.5：`includes` 合并（官方 `LoadAdditionalClientConfigs`） |
| `common/src/config/server.rs` | 471 | 未标注 | 配了它之后，QUIC 监听**只**在这个端口上开，**不再**顺带占用 | 配了它之后，QUIC 监听**只**在这个端口上开，**不再**顺带占用 | 未标注 | ★ v0.6.5：配了它之后，QUIC 监听**只**在这个端口上开，**不再**顺带占用<br>`bindPort` 的同名 UDP 端口。那是旧行为的隐式副作用，会让<br>"我明明配了 quicBindPort=7101，为什么 7000/udp 也被占了" 变成谜。 |
| `common/src/config/server.rs` | 505 | 未标注 | **默认关闭**，与官方一致。此前是无条件开放 `/metrics`。 | **默认关闭**，与官方一致。此前是无条件开放 `/metrics`。 | 未标注 | ★ v0.6.5：**默认关闭**，与官方一致。此前是无条件开放 `/metrics`。 |
| `common/src/config/server.rs` | 526 | 未标注 | 官方默认 **1500**，而 NFrp 一直用 **65507**（UDP 协议上限）。 | 官方默认 **1500**，而 NFrp 一直用 **65507**（UDP 协议上限）。 | 未标注 | ★ v0.6.6：官方默认 **1500**，而 NFrp 一直用 **65507**（UDP 协议上限）。 |
| `common/src/config/server.rs` | 544 | 未标注 | 配了它之后，面板的 `/` 与其它路径会**优先从这个目录读文件**， | 配了它之后，面板的 `/` 与其它路径会**优先从这个目录读文件**， | 未标注 | ★ v0.6.6：配了它之后，面板的 `/` 与其它路径会**优先从这个目录读文件**，<br>而不是用内嵌的那份 HTML。这样可以把面板换成自己的页面（换 logo、<br>加公司信息之类），不用改二进制。 |
| `common/src/config/server.rs` | 559 | 未标注 | 默认关闭。与 `enablePrometheus` 同口径 —— 诊断端点不该在 | 默认关闭。与 `enablePrometheus` 同口径 —— 诊断端点不该在 | 未标注 | ★ v0.6.6：默认关闭。与 `enablePrometheus` 同口径 —— 诊断端点不该在<br>"只想开个面板"的部署里默认暴露。 |
| `common/src/config/tests.rs` | 1041 | 未标注 | `includes`（客户端配置包含）与 `glob_match` | `includes`（客户端配置包含）与 `glob_match` | `glob_匹配语义对齐_go_filepath_match` | ==================================================================<br>v0.6.5：`includes`（客户端配置包含）与 `glob_match`<br>================================================================== |
| `common/src/config/tests.rs` | 1201 | 未标注 | `udpPacketSize`（两端） | `udpPacketSize`（两端） | `udp_packet_size_默认是_65507` | ==================================================================<br>v0.6.6：`udpPacketSize`（两端）<br>================================================================== |
| `common/src/frp/kcp.rs` | 1074 | 未标注 | 加**安全下限**。这个值直接决定内存上界 | 加**安全下限**。这个值直接决定内存上界 | 未标注 | ★ v0.6.2：加**安全下限**。这个值直接决定内存上界<br>（`max × 15.3 KB`），配成 0 或极小值会让 KCP 完全不可用 ——<br>那是"服务静默失效"，比拒绝启动更危险。<br>低于 [`MIN_KCP_SESSIONS`] 时抬到下限并告警，而不是照用。 |
| `common/src/frp/kcp.rs` | 1529 | 未标注 | 用 force_* 绕开安全下限。 | 用 force_* 绕开安全下限。 | 未标注 | ★ v0.6.2：用 force_* 绕开安全下限。<br>with_max_sessions 会把 8 抬到 MIN_KCP_SESSIONS=64，<br>那样这条测试永远造不满会话表，也就测不到<br>"超额会被丢弃"这个核心行为。 |
| `common/src/frp/kcp.rs` | 1600 | 未标注 | 会话上限有**安全下限**，配成 0 不会把 KCP 关掉。 | 会话上限有**安全下限**，配成 0 不会把 KCP 关掉。 | `kcp_session_cap_has_a_floor` | ★ v0.6.2 回归：会话上限有**安全下限**，配成 0 不会把 KCP 关掉。 |
| `common/src/frp_config.rs` | 264 | 未标注 | 官方 0.71 的客户端顶层 / 代理 / visitor 字段已全部落地。 | 官方 0.71 的客户端顶层 / 代理 / visitor 字段已全部落地。 | 未标注 | v0.6.6：官方 0.71 的客户端顶层 / 代理 / visitor 字段已全部落地。<br>useEncryption、useCompression、proxyURL、tokenSource、udpPacketSize、<br>natHoleStunServer、dnsServer、includes、pprofEnable、assetsDir 均已在<br>配置层与实际执行路径接通。 |
| `common/src/frp_config.rs` | 293 | 未标注 | 官方 0.71 的 frps 顶层字段已全部落地。 | 官方 0.71 的 frps 顶层字段已全部落地。 | 未标注 | v0.6.6：官方 0.71 的 frps 顶层字段已全部落地。<br>pprofEnable、natholeAnalysisDataReserveHours、sshTunnelGateway、<br>httpPlugins 均已在配置层与执行路径接通。<br>唯一仍单独检测的是 `webServer.tls.*`（面板 HTTPS），见下方路径扫描。 |
| `common/src/frp_config.rs` | 546 | 未标注 | 数据面加密/压缩、出站代理、自定义 DNS。 | 数据面加密/压缩、出站代理、自定义 DNS。 | 未标注 | ★ v0.6.6：数据面加密/压缩、出站代理、自定义 DNS。<br>官方 GetRealConn 读的是 pxy.baseCfg.Transport.*（客户端级），<br>所以这几项必须从 [transport] 提升到顶层，否则配了也不生效。 |
| `common/src/frp_config.rs` | 618 | 未标注 | 数据面加密/压缩在官方的 [proxies.transport] 段里 | 数据面加密/压缩在官方的 [proxies.transport] 段里 | 未标注 | ★ v0.6.6：数据面加密/压缩在官方的 [proxies.transport] 段里 |
| `common/src/frp_config.rs` | 637 | 未标注 | 官方 `healthCheck.httpHeaders` —— | 官方 `healthCheck.httpHeaders` —— | 未标注 | ★ v0.6.3：官方 `healthCheck.httpHeaders` ——<br>`[{ name = "Authorization", value = "Bearer x" }]`<br>整个数组搬过来，serde 按 `Vec<HttpHeader>` 解析。 |
| `common/src/frp_config.rs` | 812 | 未标注 | `useEncryption` / `useCompression` 已经真正实现了 | `useEncryption` / `useCompression` 已经真正实现了 | `ini_里_use_encryption_已经实现所以不再报未实现` | ★ v0.6.6：`useEncryption` / `useCompression` 已经真正实现了<br>（数据面 AES-128-CFB + Snappy framing），所以它们**不该**再出现在<br>"未实现字段"清单里 —— 否则会出现"说没实现而实际能用"的反向假警报。 |
| `common/src/frp_config.rs` | 1194 | 未标注 | 官方：`healthCheck.httpHeaders` 必须被识别。 | 官方：`healthCheck.httpHeaders` 必须被识别。 | `官方的_healthcheck_httpheaders_能被解析` | ★ v0.6.3 对齐官方：`healthCheck.httpHeaders` 必须被识别。 |
| `common/src/frp_config.rs` | 1512 | 未标注 | `quicBindPort` 已实现 —— 必须能真正读进来， | `quicBindPort` 已实现 —— 必须能真正读进来， | `quicbindport_已实现且能读进来` | ★ v0.6.5：`quicBindPort` 已实现 —— 必须能真正读进来，<br>且**不再**出现在"未实现"清单里。 |
| `common/src/frp_config.rs` | 1867 | 未标注 | `webServer.tls.certFile` / `keyFile` 已经真正实现了 | `webServer.tls.certFile` / `keyFile` 已经真正实现了 | 未标注 | ★ v0.6.6：`webServer.tls.certFile` / `keyFile` 已经真正实现了<br>（面板 HTTPS：rustls 包装 dashboard / client web 的监听器，<br>并在 HTTPS 响应上带 HSTS）。 |
| `common/src/http_relay.rs` | 89 | 未标注 | # 取消安全 | # 取消安全 | 未标注 | # 取消安全（v0.6.7 重构的关键） |
| `common/src/http_relay.rs` | 118 | 未标注 | # 取消安全 | # 取消安全 | 未标注 | # 取消安全（v0.6.7 修好了，第十五 / 十七轮的已知缺陷已关闭） |
| `common/src/http_relay.rs` | 130 | 未标注 | 的修法（两处一起改才成立）： | 的修法（两处一起改才成立）： | 未标注 | v0.6.7 的修法（两处一起改才成立）：<br>* 本函数改用 [`Self::fill`]（`read_buf` 写进 `self.buf`）⇒ 取消不丢字节；<br>* **调用方**在 `select!` **之前**先看 `available()`：缓冲里有字节就直接<br>`fut.await`，不再进 `select!` ⇒ 没有任何一路会"永远就绪"。 |
| `common/src/http_relay.rs` | 1150 | 未标注 | 语义补一条：**缓冲里还有数据时返回 `Ok(false)`** —— | 语义补一条：**缓冲里还有数据时返回 `Ok(false)`** —— | `watch_closed_识别_eof_且不丢字节` | ★ v0.6.7 起语义补一条：**缓冲里还有数据时返回 `Ok(false)`** ——<br>不读就无法观测 EOF，硬读又会把字节藏进缓冲。调用方契约是<br>"先看 `available()`、有数据就先消费"，`wait_upstream` 已按此写。 |
| `common/src/http_relay.rs` | 1181 | 未标注 | `watch_closed` 被 `select!` 取消后，字节必须还在。 | `watch_closed` 被 `select!` 取消后，字节必须还在。 | `watch_closed_被取消时不丢字节` | ★★ v0.6.7：`watch_closed` 被 `select!` 取消后，字节必须还在。 |
| `common/src/security.rs` | 85 | 未标注 | 已**真正实现**（此前只是"声明以便官方配置能解析通过"）。 | 已**真正实现**（此前只是"声明以便官方配置能解析通过"）。 | 未标注 | ★ v0.6.5 已**真正实现**（此前只是"声明以便官方配置能解析通过"）。 |
| `common/src/security.rs` | 186 | 未标注 | 已**真正实现**（此前只是"声明以便官方配置能解析通过"）。 | 已**真正实现**（此前只是"声明以便官方配置能解析通过"）。 | 未标注 | ★ v0.6.5 已**真正实现**（此前只是"声明以便官方配置能解析通过"）。 |
| `common/src/security.rs` | 1920 | 未标注 | tokenSource（官方 ValueSource） | tokenSource（官方 ValueSource） | `tokensource_能解析官方写法` | ==================================================================<br>v0.6.5：tokenSource（官方 ValueSource）<br>================================================================== |
| `common/src/vnet.rs` | 37 | 未标注 | \| 平台 \| TUN 后端 \| 要求 \| | \| Windows \| **Wintun** \| 管理员权限 + `wintun.dll` \| | 未标注 | \| 平台 \| TUN 后端 \| 要求 \|<br>\|---\|---\|---\|<br>\| Linux \| `/dev/net/tun` \| root 或 `CAP_NET_ADMIN` \|<br>\| Windows \| **Wintun**（v0.6.6 起） \| 管理员权限 + `wintun.dll` \|<br>\| macOS \| 未实现 \| 会**明确报错**，不假装成功 \| |
| `common/src/vnet.rs` | 689 | 未标注 | Windows 用 Wintun（WireGuard 项目的开源 TUN 驱动）。 | Windows 用 Wintun（WireGuard 项目的开源 TUN 驱动）。 | 未标注 | ★ v0.6.6：Windows 用 Wintun（WireGuard 项目的开源 TUN 驱动）。 |
| `common/src/vnet/tun_linux.rs` | 163 | 未标注 | `AsyncFd:new` 在 tokio 1.54 起被标记为 **deprecated**， | `AsyncFd:new` 在 tokio 1.54 起被标记为 **deprecated**， | 未标注 | ★ v0.6.4：`AsyncFd::new` 在 tokio 1.54 起被标记为 **deprecated**，<br>理由是「unsound due to lack of I/O safety」（tokio PR #8587）。 |
| `server/src/admin.rs` | 124 | 未标注 | **面板下发的增删也要进审计链**。 | **面板下发的增删也要进审计链**。 | 未标注 | ★★ v0.6.1 修（Shannon 审计）：**面板下发的增删也要进审计链**。<br>原先只有 `serve.rs` 里"客户端自己注册"那条记 `PROXY_ADD`，<br>面板这条路（走 `ServerCmd`）一条都没记 —— 审计里看不到管理操作。 |
| `server/src/admin.rs` | 241 | 未标注 | 面板下发的删除也进审计链（同上）。 | 面板下发的删除也进审计链（同上）。 | 未标注 | ★★ v0.6.1 修（Shannon 审计）：面板下发的删除也进审计链（同上）。 |
| `server/src/admin.rs` | 280 | 未标注 | **踢人必须进审计链**。 | **踢人必须进审计链**。 | 未标注 | ★★ v0.6.1 修（Shannon 审计，低危）：**踢人必须进审计链**。 |
| `server/src/admin.rs` | 406 | 未标注 | **踢人必须写进审计链。** | **踢人必须写进审计链。** | `kick_必须写审计` | ★★ v0.6.1 回归（Shannon 审计，低危）：**踢人必须写进审计链。** |
| `server/src/dashboard.rs` | 40 | 未标注 | 面板所有响应都会带的**安全响应头**。 | 面板所有响应都会带的**安全响应头**。 | 未标注 | 面板所有响应都会带的**安全响应头**（v0.6.4，渗透测试 PT-05）。 |
| `server/src/dashboard.rs` | 290 | 未标注 | `HEAD` 只回响应头，不回 body。 | `HEAD` 只回响应头，不回 body。 | 未标注 | v0.6.4（渗透测试 PT-03）：`HEAD` 只回响应头，不回 body。<br>见 [`send`] 的 `head_only` 参数说明。 |
| `server/src/dashboard.rs` | 457 | 未标注 | **未匹配的 POST 一律 405**。 | **未匹配的 POST 一律 405**。 | 未标注 | ★ v0.6.4（渗透测试 PT-07）：**未匹配的 POST 一律 405**。 |
| `server/src/dashboard.rs` | 569 | 未标注 | 官方默认**不开**这个端点，配了 `enablePrometheus = true` 才有 | 官方默认**不开**这个端点，配了 `enablePrometheus = true` 才有 | 未标注 | ★ v0.6.5（对齐官方 frps 的 `enablePrometheus`）：<br>官方默认**不开**这个端点，配了 `enablePrometheus = true` 才有<br>（`server.go`："EnablePrometheus will export prometheus metrics<br>on {dashboard_addr}:{dashboard_port}"）。 |
| `server/src/dashboard.rs` | 617 | 未标注 | 配了目录就优先用里面的 index.html，否则用内嵌的那份。 | 配了目录就优先用里面的 index.html，否则用内嵌的那份。 | 未标注 | ★ v0.6.6（对齐官方 frps 的 `webServer.assetsDir`）：<br>配了目录就优先用里面的 index.html，否则用内嵌的那份。 |
| `server/src/dashboard.rs` | 867 | 未标注 | # `head_only` | # `head_only` | 未标注 | # `head_only`（v0.6.4，渗透测试 PT-03） |
| `server/src/dashboard.rs` | 1218 | 未标注 | `e` 也要过 `esc()`。 | `e` 也要过 `esc()`。 | 未标注 | ★★ v0.6.1 修（Shannon 审计，加固）：`e` 也要过 `esc()`。 |
| `server/src/dashboard.rs` | 1313 | 未标注 | 通用请求：可以指定方法，用于测 HEAD / POST 的语义。 | 通用请求：可以指定方法，用于测 HEAD / POST 的语义。 | 未标注 | 通用请求（v0.6.4）：可以指定方法，用于测 HEAD / POST 的语义。 |
| `server/src/dashboard.rs` | 1577 | 未标注 | **catch 分支里的 `e` 也必须转义**。 | **catch 分支里的 `e` 也必须转义**。 | 未标注 | ★★ v0.6.1（Shannon 审计，加固）：**catch 分支里的 `e` 也必须转义**。 |
| `server/src/dashboard.rs` | 1612 | 未标注 | `enablePrometheus` **默认关闭**（对齐官方 frps）。 | `enablePrometheus` **默认关闭**（对齐官方 frps）。 | `enable_prometheus_默认关闭` | ★ v0.6.5：`enablePrometheus` **默认关闭**（对齐官方 frps）。 |
| `server/src/dashboard.rs` | 1642 | 未标注 | HTTP 语义与安全响应头 | HTTP 语义与安全响应头 | 未标注 | ==================================================================<br>v0.6.4（渗透测试 PT-03 / PT-05 / PT-07）：HTTP 语义与安全响应头<br>================================================================== |
| `server/src/dashboard.rs` | 1651 | 未标注 | 同上，但可以指定 `enable_prometheus`。 | 同上，但可以指定 `enable_prometheus`。 | 未标注 | 同上，但可以指定 `enable_prometheus`（v0.6.5）。 |
| `server/src/dashboard.rs` | 1660 | 未标注 | 起一个配了 `assets_dir` 的面板。 | 起一个配了 `assets_dir` 的面板。 | 未标注 | 起一个配了 `assets_dir` 的面板（v0.6.6）。 |
| `server/src/dashboard.rs` | 1856 | 未标注 | `assetsDir`（面板静态资源目录） | `assetsDir`（面板静态资源目录） | 未标注 | ==================================================================<br>v0.6.6：`assetsDir`（面板静态资源目录）<br>================================================================== |
| `server/src/dashboard.rs` | 1965 | 未标注 | `/metrics` 默认关闭时返回 404，并提示怎么开。 | `/metrics` 默认关闭时返回 404，并提示怎么开。 | `metrics_default_is_disabled` | ★ v0.6.5：`/metrics` 默认关闭时返回 404，并提示怎么开。 |
| `server/src/dashboard.rs` | 2012 | 未标注 | `/metrics` 已改为默认关闭（`enablePrometheus`）， | `/metrics` 已改为默认关闭（`enablePrometheus`）， | 未标注 | ★ v0.6.5：`/metrics` 已改为默认关闭（`enablePrometheus`），<br>spawn_dashboard() 用的是默认配置，所以这里不能再断言它 200。<br>它的 HEAD 语义由 `head_works_on_metrics_when_enabled` 覆盖。 |
| `server/src/main.rs` | 107 | 未标注 | `auth.tokenSource` —— 服务端的**期望 token** 也能来自外部源。 | `auth.tokenSource` —— 服务端的**期望 token** 也能来自外部源。 | 未标注 | ★ v0.6.5：`auth.tokenSource` —— 服务端的**期望 token** 也能来自外部源。 |
| `server/src/pool.rs` | 106 | 未标注 | 随用户连接一起带下来，因为真正做 relay 的 | 随用户连接一起带下来，因为真正做 relay 的 | 未标注 | ★ v0.6.6：随用户连接一起带下来，因为真正做 relay 的<br>[`crate::serve::bridge`] 拿不到 `ClientState` / `SecurityContext`。 |
| `server/src/pool.rs` | 175 | 未标注 | 服务端必须知道它，否则工作连接的另一端不知道要解密 —— | 服务端必须知道它，否则工作连接的另一端不知道要解密 —— | 未标注 | ★ v0.6.6：服务端必须知道它，否则工作连接的另一端不知道要解密 ——<br>客户端加密、服务端明文透传，用户会得到"能连上、数据全乱"。 |
| `server/src/registry.rs` | 1033 | 未标注 | **会话结束时清掉 OIDC 的 subject 绑定**。 | **会话结束时清掉 OIDC 的 subject 绑定**。 | 未标注 | ★★ v0.6.1 修（Shannon 审计，低危）：**会话结束时清掉 OIDC 的 subject 绑定**。 |
| `server/src/registry.rs` | 1057 | 未标注 | **控制连接退出时必须清掉 OIDC 的 subject 绑定。** | **控制连接退出时必须清掉 OIDC 的 subject 绑定。** | `控制连接退出必须清掉_oidc_subject_绑定` | ★★ v0.6.1 回归（Shannon 审计，低危）：**控制连接退出时必须清掉 OIDC 的 subject 绑定。** |
| `server/src/registry.rs` | 1560 | 未标注 | 这条测试现在**显式把策略设成 LeastConn**。 | 这条测试现在**显式把策略设成 LeastConn**。 | `pick_prefers_the_least_loaded_backend` | ★ v0.6.2：这条测试现在**显式把策略设成 LeastConn**。<br>默认策略已改为 RoundRobin（对齐官方 frp），不再默认倾斜。 |
| `server/src/registry.rs` | 1588 | 未标注 | **默认策略必须是轮询**，与官方 frp 的 group 行为一致。 | **默认策略必须是轮询**，与官方 frp 的 group 行为一致。 | `default_policy_is_round_robin_like_official` | ★ v0.6.2 回归：**默认策略必须是轮询**，与官方 frp 的 group 行为一致。 |
| `server/src/serve/bridge.rs` | 182 | 未标注 | 无论成功、失败、还是上面某个 `?` 提前返回，`guard` 都会在作用域结束时 | 数据面解密 / 解压（官方 transport.useEncryption / useCompression） | 未标注 | 无论成功、失败、还是上面某个 `?` 提前返回，`guard` 都会在作用域结束时<br>归还计数 —— 这就是 RAII 修法的全部价值。<br>★ v0.6.6：数据面解密 / 解压（官方 transport.useEncryption / useCompression） |
| `server/src/serve/register.rs` | 202 | 未标注 | 把数据面标志记下来，工作连接那一侧要用它决定是否解密/解压 | 把数据面标志记下来，工作连接那一侧要用它决定是否解密/解压 | 未标注 | ★ v0.6.6：把数据面标志记下来，工作连接那一侧要用它决定是否解密/解压 |
| `server/src/serve/register.rs` | 522 | 未标注 | 数据面标志随用户连接带下去 | 数据面标志随用户连接带下去 | 未标注 | ★ v0.6.6：数据面标志随用户连接带下去 |
| `server/src/serve/startup.rs` | 525 | 未标注 | **优先用独立的 `quicBindPort`**（对齐官方 frps 语义）。 | **优先用独立的 `quicBindPort`**（对齐官方 frps 语义）。 | 未标注 | ★ v0.6.5：**优先用独立的 `quicBindPort`**（对齐官方 frps 语义）。 |
| `server/src/serve/startup.rs` | 611 | 未标注 | 会话上限可配（默认 1024，约 15 MB 峰值）。 | 会话上限可配（默认 1024，约 15 MB 峰值）。 | 未标注 | ★ v0.6.2：会话上限可配（默认 1024，约 15 MB 峰值）。 |
| `server/src/udp_proxy.rs` | 112 | 未标注 | 单报文缓冲上限（官方 frps 的 `udpPacketSize`）。 | 单报文缓冲上限（官方 frps 的 `udpPacketSize`）。 | 未标注 | ★ v0.6.6：单报文缓冲上限（官方 frps 的 `udpPacketSize`）。<br>由配置传入而不是写死常量 —— 见 `ServerConfig::udp_packet_size` 的说明。 |

## v0.5.x

| 文件 | 行号 | 日期 | 问题 | 结论（代码保留的技术说明） | 回归测试 | 原文摘录 |
|---|---|---|---|---|---|---|
| `Cargo.toml` | 126 | 未标注 | opt-level 由 "s" 改为 "z"（第七轮，纯体积优化）。 | opt-level="z" 比 "s" 实测小约 9.5%，fat LTO + strip 保留；改回去体积会显著变大。历史实测与取舍见上方原文。 | 未标注 | ★★ v0.5.8：`opt-level` 由 `"s"` 改为 `"z"`（第七轮，**纯体积优化**）<br>\| 配置 \| nfrp-server \| 变化 \| nfrp-client \| 变化 \|<br>\|---\|---\|---\|---\|---\|<br>\| 原 `opt-level="s"`（基线） \| 3,785,728 B \| — \| 3,846,144 B \| — \|<br>\| **`opt-level="z"`（本版采用）** \| **3,417,600 B** \| **−9.72%** \| **3,488,768 B** \| **−9.29%** \|<br>\| `opt-level="z"` + `lto="thin"`（对照） \| 3,738,112 B \| −1.26% \| 3,774,464 B \| −1.86% \|<br>也试过但无效：`/OPT:REF`、`/OPT:ICF` 均 0.00%（MSVC release 已默认开启；COMDAT 无可折叠函数体）。 |
| `client/src/admin.rs` | 20 | 未标注 | **必须跑完整启动校验，不能只解析配置**。 | **必须跑完整启动校验，不能只解析配置**。 | 未标注 | ★★ v0.5.7 修（第六轮审计 F-1，中危）：**必须跑完整启动校验，不能只解析配置**。 |
| `client/src/admin.rs` | 60 | 未标注 | 与启动同口径的启动期校验。 | 与启动同口径的启动期校验。 | 未标注 | ★ v0.5.7（F-1）：与启动同口径的启动期校验。 |
| `client/src/admin.rs` | 129 | 未标注 | 判据同时看 `user` **与** `password`。 | 判据同时看 `user` **与** `password`。 | 未标注 | ★★ v0.5.6 修（审计总报告 H1，高危）：判据同时看 `user` **与** `password`。 |
| `client/src/commands.rs` | 41 | 未标注 | **只许删动态代理，不许删配置里的**。 | **只许删动态代理，不许删配置里的**。 | 未标注 | ★★ v0.5.5（第四轮 F2）：**只许删动态代理，不许删配置里的**。 |
| `client/src/commands.rs` | 50 | 未标注 | **列表名字必须能直接删**。 | **列表名字必须能直接删**。 | 未标注 | ★ v0.5.8 修（第八轮审计 F8-L2，低危）：**列表名字必须能直接删**。 |
| `client/src/commands.rs` | 52 | 未标注 | 面板列表展示的是线上全名 `{user}.{name}`；服务端 | 面板列表展示的是线上全名 `{user}.{name}`；服务端 | 未标注 | 面板列表展示的是线上全名 `{user}.{name}`；v0.5.8 起服务端<br>下发的已是本地名，这里再兜一层：原样查不到时，剥掉本客户端<br>`user` 前缀再查 —— 覆盖"客户端先升级、服务端还是旧版"的<br>滚动升级窗口（旧服务端转发的就是面板给的全名）。<br>修复前客户端拿全名查本地表 ⇒ 拒删，而服务端侧已经摘干净 ⇒<br>两端状态分裂、接口回 502 把"半成功"表达成失败。 |
| `client/src/commands.rs` | 143 | 未标注 | **远程下发不许覆盖配置文件里的代理**。 | **远程下发不许覆盖配置文件里的代理**。 | 未标注 | ★★ v0.5.5（第四轮 F3）：**远程下发不许覆盖配置文件里的代理**。 |
| `client/src/commands.rs` | 199 | 未标注 | **必须给一个合法的 local_addr**。 | **必须给一个合法的 local_addr**。 | 未标注 | ★ v0.5.8（第七轮审计 E7 附带发现）：**必须给一个合法的 local_addr**。 |
| `client/src/commands.rs` | 201 | 未标注 | 原先这里是 `..Default:default()`（`local_addr` = 空串）， | 属于"假绿灯"。远程下发**拒绝**空 `local_addr`。 | 未标注 | 原先这里是 `..Default::default()`（`local_addr` = 空串），<br>于是这些用例**意外依赖了"空地址也会被接受"**这个行为。<br>而空地址的 tcp 代理**必然连不上任何地方** ——<br>面板却回「已生效」（实测见 `tmp/audit7/e/localip_bypass_probe.py`），<br>属于"假绿灯"。v0.5.8 起远程下发**拒绝**空 `local_addr`。 |
| `client/src/commands.rs` | 304 | 未标注 | （H4）：服务端下发的 `local_addr` **只能指向本机回环**。 | （H4）：服务端下发的 `local_addr` **只能指向本机回环**。 | `远程下发的_local_addr_只能指向本机` | ★★ v0.5.4 回归（H4）：服务端下发的 `local_addr` **只能指向本机回环**。 |
| `client/src/commands.rs` | 336 | 未标注 | 正：**`localhost` 从这份白名单里去掉了。** | 正：**`localhost` 从这份白名单里去掉了。** | 未标注 | ★★ v0.5.8（第七轮审计 **E-1**）修正：**`localhost` 从这份白名单里去掉了。** |
| `client/src/commands.rs` | 480 | 未标注 | 调整：现在**任何**插件都不许远程下发， | 调整：现在**任何**插件都不许远程下发， | `不认识插件类型在解析阶段被拒` | ★ v0.5.5（第四轮 F1）调整：现在**任何**插件都不许远程下发，<br>所以这条用例改到**配置文件**路径去验证（`is_remote = false`）——<br>"拼错的插件名要被解析阶段拦住"这个不变量本身仍然有效，<br>只是它的适用场景从"远程下发"变成了"本机配置"。 |
| `client/src/commands.rs` | 593 | 未标注 | 调整：原来这条用例删的是 `from_iter` 建进来的 | 调整：原来这条用例删的是 `from_iter` 建进来的 | `管理命令_先加后删` | ★ v0.5.5（第四轮 F2）调整：原来这条用例删的是 `from_iter` 建进来的<br>`"old"` —— 那是**配置来源**的代理，现在远程 `remove` 会（正确地）拒绝它。<br>也就是说这条测试原先在无意中**断言了 F2 那个漏洞**（面板能删配置代理）。<br>现在改成"加一条动态的、再删那条动态的"，生命周期照样闭环，<br>而配置代理必须原样留着 —— 下面多加了断言把这个不变量钉住。 |
| `client/src/commands.rs` | 694 | 未标注 | 面板列表里的**线上全名** | 面板列表里的**线上全名** | `用线上全名也能删除动态代理` | ★ v0.5.8（第八轮审计 F8-L2，低危）回归：面板列表里的**线上全名**<br>也要能直接删掉。 |
| `client/src/commands.rs` | 697 | 未标注 | 服务端 下发的已是本地名（`admin.rs` 剥了前缀）；这里覆盖 | 服务端 下发的已是本地名（`admin.rs` 剥了前缀）；这里覆盖 | `用线上全名也能删除动态代理` | 服务端 v0.5.8 起下发的已是本地名（`admin.rs` 剥了前缀）；这里覆盖<br>"客户端先升级、服务端仍是旧版"的滚动升级窗口 —— 旧服务端转发的就是<br>面板给的全名。修复前客户端拿全名查本地表 ⇒ 拒删 ⇒ 服务端已摘、<br>客户端留条目（两端状态分裂，v2 回 502）。 |
| `client/src/commands.rs` | 731 | 未标注 | ② 对照：下发本地名 | ② 对照：下发本地名 | 未标注 | ② 对照：下发本地名（v0.5.8 服务端的正常契约） |
| `client/src/dial.rs` | 215 | 未标注 | **`verifyServerCert = true` | **`verifyServerCert = true` | 未标注 | ★★ v0.5.8 修（第七轮审计 **B-2**，中危）：**`verifyServerCert = true`<br>但 TLS 没开时必须显著告警** —— 否则这是"安全配置静默失效"。 |
| `client/src/dial.rs` | 256 | 未标注 | `verifyServerCert = true` 时**真正校验**对端证书。 | `verifyServerCert = true` 时**真正校验**对端证书。 | 未标注 | ★ v0.5.6（L16）：`verifyServerCert = true` 时**真正校验**对端证书。<br>默认 false ⇒ 与官方 frp 一致（`InsecureSkipVerify = true`），保互通。 |
| `client/src/dial.rs` | 345 | 未标注 | `）： | `）： | `dial_server_按配置开_keepalive` | ★★ v0.5.10 修（云端 Linux 实测 `Connection refused (os error 111)`）：<br>原先的 accept task **只等一次连接就结束** —— |
| `client/src/main.rs` | 222 | 未标注 | 记住**哪些名字来自配置文件**。 | 记住**哪些名字来自配置文件**。 | 未标注 | ★ v0.5.5（第四轮 F2/F3）：记住**哪些名字来自配置文件**。 |
| `client/src/main.rs` | 294 | 未标注 | 各建一张的话，"刚在界面上加的代理"要等下次重连才会被会话看见 —— | 配置来源的先建表，**store 恢复的再作为动态并入**。 | 未标注 | 各建一张的话，"刚在界面上加的代理"要等下次重连才会被会话看见 ——<br>而那期间界面显示"已添加"、流量却进不来。<br>★ v0.5.5（第四轮 F2/F3）：配置来源的先建表，**store 恢复的再作为动态并入**。 |
| `client/src/main.rs` | 313 | 未标注 | 启动时**预检插件配置**。 | 启动时**预检插件配置**。 | 未标注 | ★ v0.5.9 修（第九轮 D9-7，低危）：启动时**预检插件配置**。 |
| `client/src/p2p.rs` | 743 | 未标注 | 旧协议只校验"对方回没回固定的 | 旧协议只校验"对方回没回固定的 | 未标注 | ★ v0.5.8 修（第八轮审计 B-1，高危）：旧协议只校验"对方回没回固定的<br>`RTNL-OK`"。牵线 HELLO 无鉴权且 sid 明文，攻击者冒充 provider 时事<br>实上不需要任何秘密就能被接受 —— visitor 会把用户流量交给它。<br>现在校验的应答由 `handshake_ack(secret_key, sid)` 派生，攻击者不知道<br>`secret_key` 就答不上来；答不上来时这里直接失败，调用方按既有逻辑<br>回退 stcp 中继。 |
| `client/src/p2p.rs` | 785 | 未标注 | 应答同样派生自 secret_key， | 应答同样派生自 secret_key， | 未标注 | ★ v0.5.8 修（第八轮审计 B-1）：应答同样派生自 secret_key，<br>让 visitor 能反向确认"对面真的持有 secret_key"。 |
| `client/src/p2p.rs` | 1175 | 未标注 | 注：这个替身**只服务一轮**就 `return`。 | 本轮曾试着改成常驻循环，A/B 对照（各 5 次全组） | 未标注 | ★ 注：这个替身**只服务一轮**就 `return`。<br>本轮（v0.5.10）曾试着改成常驻循环，A/B 对照（各 5 次全组）<br>显示**无实质改善**（0/5 → 1/5，属噪声），已回滚。<br>真正的偶发失败原因（云端 Linux 上 p2p 全组 0/5）**尚未定位**，<br>见 `tmp/TRIAGE-2026-10-18.md`。 |
| `client/src/p2p.rs` | 1349 | 未标注 | 假 provider **不知道 secret_key**， | 假 provider **不知道 secret_key**， | `fake_provider_without_secret_is_rejected` | ★ v0.5.8（第八轮审计 B-1，高危）回归：假 provider **不知道 secret_key**，<br>它能读到 visitor 递出的口令（口令是 visitor 先发的），然后模仿旧协议<br>回固定 `RTNL-OK`，或回一个内容错误 / 密钥猜错的应答。 |
| `client/src/plugin.rs` | 231 | 未标注 | **只按小写比对头名，值保持原样**。 | **只按小写比对头名，值保持原样**。 | 未标注 | ★★ v0.5.7 修（第六轮审计 G-2）：**只按小写比对头名，值保持原样**。 |
| `client/src/plugin.rs` | 573 | 未标注 | **拒绝 NTFS 备用数据流（ADS）**。 | **拒绝 NTFS 备用数据流（ADS）**。 | 未标注 | ★★ v0.5.8 修（第七轮审计 **D7-4**，低危）：**拒绝 NTFS 备用数据流（ADS）**。 |
| `client/src/plugin.rs` | 797 | 未标注 | **头部解析 + 认证必须端到端串起来测**。 | **头部解析 + 认证必须端到端串起来测**。 | `代理认证的头部解析必须保留大小写` | ★★ v0.5.7 新增（第六轮审计 G-2）：**头部解析 + 认证必须端到端串起来测**。 |
| `client/src/plugin.rs` | 909 | 未标注 | **`static_file` 必须拒绝 NTFS 备用数据流（ADS）写法。** | **`static_file` 必须拒绝 NTFS 备用数据流（ADS）写法。** | `static_file_rejects_ntfs_ads` | ★★ v0.5.8 回归（第七轮审计 **D7-4**，低危）：<br>**`static_file` 必须拒绝 NTFS 备用数据流（ADS）写法。** |
| `client/src/plugin_bridge.rs` | 60 | 未标注 | 原先这两个 `await` 都没有 | 原先这两个 `await` 都没有 | 未标注 | ★ v0.5.8 修（第八轮审计 **F8T-1**，低危）：原先这两个 `await` 都没有<br>时限 —— 上游 accept 后保持沉默时，`https2https` 会**永久**卡在上游 TLS<br>握手上（实测：后端收了 216B ClientHello 后再无动静，frpc 侧 ESTABLISHED<br>永不释放，每轮访问留一条、无上界）。 |
| `client/src/plugin_bridge.rs` | 211 | 未标注 | 上游 accept 后保持沉默时， | 上游 accept 后保持沉默时， | 未标注 | ★ v0.5.8 修（第八轮审计 **F8T-1**，低危）：上游 accept 后保持沉默时，<br>原实现只读上游、不感知访问侧 —— 访问方连上来、把请求发完就撤离<br>（TCP FIN + TLS close_notify）也会被无视，插件替一个已经离开的访问者<br>继续等，上游连接**永不释放**；任何能访问该 `remote_port` 的人都可以<br>"连接 → 发请求 → 撤离"反复放大（每轮留 1 条 ESTABLISHED，上游永久<br>沉默则无上界）。官方 frpc 基于 Go `http.Server` —— 客户端连接关闭会<br>取消请求上下文、中止上游请求；这里对齐该语义。 |
| `client/src/plugin_bridge.rs` | 295 | 未标注 | **请求侧 framing 校验**。 | **请求侧 framing 校验**。 | 未标注 | ★★ v0.5.6 修（审计总报告 M2，中危）：**请求侧 framing 校验**。 |
| `client/src/plugin_bridge.rs` | 301 | 未标注 | 危害：`relay_request_body` 用的是弱判据 `body_length()` | （的 H2 已经把它判定为不够用：只取第一个同名头、 | 未标注 | 危害：`relay_request_body` 用的是弱判据 `body_length()`<br>（v0.5.4 的 H2 已经把它判定为不够用：只取第一个同名头、<br>垃圾值静默变 None）⇒ 客户端与上游对"请求体到哪结束"的认知可能<br>不一致 ⇒ **请求走私**。 |
| `client/src/plugin_bridge.rs` | 306 | 未标注 | ⚠️ 可利用性前提（如实说明，不夸大）：服务端**不解析** plugin 路径的 | 。 | 未标注 | ⚠️ 可利用性前提（如实说明，不夸大）：服务端**不解析** plugin 路径的<br>HTTP（plugin 类型走 TCP 透传），所以服务端不会替这里把关；<br>但要触发它，本机用户得**主动**配 `plugin = "http_proxy"` 之类<br>（v0.5.5 的 F1 修复已禁止服务端远程下发 plugin，攻击者无法自行制造）。<br>定级因此是 Medium 而非 High。 |
| `client/src/plugin_bridge.rs` | 345 | 未标注 | 连上游、等上游响应这两段 | 连上游、等上游响应这两段 | 未标注 | ★ v0.5.8 修（第八轮审计 F8T-1，低危）：连上游、等上游响应这两段<br>都**同时盯着访问侧**（见 `wait_upstream` 的说明）——上游悬挂时<br>访问方撤离，插件必须立刻收尾，而不是替已经离开的访问者继续等。 |
| `client/src/plugin_bridge.rs` | 379 | 未标注 | **响应侧剥逐跳头**。 | **响应侧剥逐跳头**。 | 未标注 | ★★ v0.5.6 修（审计总报告 M2，中危）：**响应侧剥逐跳头**。 |
| `client/src/plugin_bridge.rs` | 416 | 未标注 | 连接与**上游 TLS 握手**都套 | 连接与**上游 TLS 握手**都套 | 未标注 | ★ v0.5.8 修（第八轮审计 F8T-1，低危）：连接与**上游 TLS 握手**都套<br>`UPSTREAM_DIAL_TIMEOUT` —— 悬挂的上游不能把插件永久卡在这里（访问侧<br>撤离的即时收尾另由 `wait_upstream` 负责，两道防线互补）。 |
| `client/src/plugin_bridge.rs` | 499 | 未标注 | **补上 `Forwarded`**。 | **补上 `Forwarded`**。 | 未标注 | ★★ v0.5.8 修（第七轮审计 **E-3**，低危）：**补上 `Forwarded`**。 |
| `client/src/plugin_bridge.rs` | 684 | 未标注 | 客户端插件路径补齐服务端已有的防护 | 客户端插件路径补齐服务端已有的防护 | `客户端插件路径必须做请求_framing_校验` | ==================================================================<br>v0.5.6 回归（审计总报告 M2）：客户端插件路径补齐服务端已有的防护 |
| `client/src/plugin_bridge.rs` | 820 | 未标注 | **`http2http` 必须删掉官方删除的完整 4 个头 —— 含 `Forwarded`。** | **`http2http` 必须删掉官方删除的完整 4 个头 —— 含 `Forwarded`。** | `http2http_要删掉官方清单里的全部四个头` | ★★ v0.5.8 回归（第七轮审计 **E-3**，低危）：<br>**`http2http` 必须删掉官方删除的完整 4 个头 —— 含 `Forwarded`。** |
| `client/src/plugin_bridge.rs` | 1154 | 未标注 | 上游 accept 后悬挂、 | 上游 accept 后悬挂、 | `上游悬挂时访问方撤离必须释放上游连接` | ★ v0.5.8（第八轮审计 **F8T-1**，低危）回归：上游 accept 后悬挂、<br>访问方撤离（FIN），插件必须**立刻**释放上游连接 —— 而不是像修复前<br>那样替一个已经离开的访问者一直等响应（每轮访问留 1 条 ESTABLISHED，<br>公开访问方可反复放大）。 |
| `client/src/plugin_bridge.rs` | 1269 | 未标注 | （上游 TLS 握手悬挂）：`https2https` | （上游 TLS 握手悬挂）：`https2https` | `上游tls握手悬挂时访问方撤离必须释放连接` | ★ v0.5.8（第八轮审计 **F8T-1**）回归（上游 TLS 握手悬挂）：`https2https`<br>卡在"与上游握手"时访问方撤离，同样必须**立刻**放弃并释放那条 TCP 连接。 |
| `client/src/plugin_bridge.rs` | 1293 | 未标注 | （上游 TLS 握手无超时）：访问方 | （上游 TLS 握手无超时）：访问方 | `上游tls握手沉默时有界失败` | ★ v0.5.8（第八轮审计 **F8T-1**）回归（上游 TLS 握手无超时）：访问方<br>还活着、上游 accept 后沉默时，上游 TLS 握手必须**有界**失败 ——<br>修复前会永久卡住（连接永不释放）。测试用缩短的超时（800ms）。 |
| `client/src/registry.rs` | 12 | 未标注 | 表里每条都带**来源标记** [`ProxyOrigin`]， | 表里每条都带**来源标记** [`ProxyOrigin`]， | 未标注 | ★★ v0.5.5（第四轮 F2/F3）：表里每条都带**来源标记** [`ProxyOrigin`]，<br>远程下发只许操作 `Dynamic` 那批。详见这两个 enum 的注释。 |
| `client/src/registry.rs` | 22 | 未标注 | 一条代理的**来源**。 | 一条代理的**来源**。 | 未标注 | 一条代理的**来源**（v0.5.5，第四轮 F2/F3）。 |
| `client/src/session.rs` | 238 | 未标注 | **无条件**声明"我的工作连接会带凭证"。 | **无条件**声明"我的工作连接会带凭证"。 | 未标注 | ★ v0.5.5（第四轮 A-1）：**无条件**声明"我的工作连接会带凭证"。 |
| `client/src/store.rs` | 99 | 未标注 | store 里的内容**同样不可信**， | store 里的内容**同样不可信**， | 未标注 | ★★ v0.5.4 修 H3：store 里的内容**同样不可信**，<br>必须与 `ServerCmd` 路径跑同一道闸门。 |
| `client/src/store.rs` | 232 | 未标注 | **Windows 也要收紧权限**。 | **Windows 也要收紧权限**。 | 未标注 | ★★ v0.5.6 修（审计总报告 M12，中危）：**Windows 也要收紧权限**。 |
| `client/src/store.rs` | 272 | 未标注 | Windows 上断开继承、只留当前用户。 | Windows 上断开继承、只留当前用户。 | 未标注 | ★ v0.5.6（M12）：Windows 上断开继承、只留当前用户。 |
| `client/src/store.rs` | 335 | 未标注 | 这里对 `stored` 再做一遍 `validate_remote_proxy`。 | 这里对 `stored` 再做一遍 `validate_remote_proxy`。 | 未标注 | ★ v0.5.4（H3 纵深防御）：这里对 `stored` 再做一遍 `validate_remote_proxy`。<br>`Store::from_config` 才是主入口（已经拦了），但本函数是 public 的、<br>也是"配置 + 动态"合流的唯一汇聚点 —— 在这儿再挡一次，<br>保证**任何**未来新增的调用点都不会把未校验的条目送进运行态。 |
| `client/src/store.rs` | 470 | 未标注 | H3：store 恢复路径必须走 validate_remote_proxy | H3：store 恢复路径必须走 validate_remote_proxy | `store_里的危险字段必须在恢复时被拦下` | ------------------------------------------------------------------<br>H3（v0.5.4）：store 恢复路径必须走 validate_remote_proxy<br>------------------------------------------------------------------ |
| `client/src/visitor.rs` | 106 | 未标注 | **非回环监听要告警**。 | **非回环监听要告警**。 | 未标注 | ★★ v0.5.6 修（审计总报告 L1 后半，低危）：**非回环监听要告警**。 |
| `client/src/web.rs` | 380 | 未标注 | 把 `handle` 里**与 socket 无关**的 | 把 `handle` 里**与 socket 无关**的 | 未标注 | ★ v0.5.10（照官方 frp 的做法重构）：把 `handle` 里**与 socket 无关**的<br>判定逻辑抽出来，让测试可以直接调它 —— 与官方<br>`frp-0.71.0/server/http/controller_v2_test.go` 里的<br>`resp := httptest.NewRecorder(); handler.ServeHTTP(resp, req)` 同构。 |
| `client/src/web.rs` | 462 | 未标注 | 检查**所有** `Origin` 头，而不是只看第一个。 | 检查**所有** `Origin` 头，而不是只看第一个。 | 未标注 | ★ v0.5.4 修（L7）：检查**所有** `Origin` 头，而不是只看第一个。 |
| `client/src/web.rs` | 881 | 未标注 | `dynamic` 改用**代理表自己的来源标记**， | `dynamic` 改用**代理表自己的来源标记**， | 未标注 | ★ v0.5.5（第四轮 F2/F3）：`dynamic` 改用**代理表自己的来源标记**，<br>而不是从 store 的名字列表间接推断。 |
| `client/src/web.rs` | 1072 | 未标注 | **不要在读完响应之前 | **不要在读完响应之前 | 未标注 | ★★ v0.5.10 修（云端 Linux 实测，**测试侧**）：**不要在读完响应之前<br>`shutdown()` 写方向**。 |
| `client/src/web.rs` | 1116 | 未标注 | 原先是 `handle_over_socket` —— | 原先是 `handle_over_socket` —— | 未标注 | ★★ v0.5.10 重构（照官方 frp 的做法）：原先是 `handle_over_socket` ——<br>开真 `TcpListener`、`tokio::spawn` 服务端、客户端再 `connect` 过去。 |
| `common/src/auth/oidc.rs` | 71 | 未标注 | 允许 `jwks_uri` 使用明文 http。 | 允许 `jwks_uri` 使用明文 http。 | 未标注 | 允许 `jwks_uri` 使用明文 http（v0.5.6 修审计总报告 M9，纵深防御）。 |
| `common/src/auth/oidc.rs` | 83 | 未标注 | 手工实现 `Debug`（见下方），`client_secret` 不进日志。 | 手工实现 `Debug`（见下方），`client_secret` 不进日志。 | 未标注 | ★ v0.5.3：手工实现 `Debug`（见下方），`client_secret` 不进日志。 |
| `common/src/auth/oidc.rs` | 109 | 未标注 | `client_secret` 永不进日志。 | `client_secret` 永不进日志。 | 未标注 | ★ v0.5.3：`client_secret` 永不进日志。 |
| `common/src/auth/oidc.rs` | 304 | 未标注 | 登录成功过的 **subject → run_id** 绑定表。 | 登录成功过的 **subject → run_id** 绑定表。 | 未标注 | ★ v0.5.3：登录成功过的 **subject → run_id** 绑定表。 |
| `common/src/auth/oidc.rs` | 385 | 未标注 | `jwks_uri` | `jwks_uri` | 未标注 | ★★ v0.5.6 修（审计总报告 M9，纵深防御）：`jwks_uri`<br>是从**远端文档**里读来的，原先**原样信任、无 scheme 校验**。 |
| `common/src/auth/oidc.rs` | 502 | 未标注 | 原先时间字段的写法是 | 原先时间字段的写法是 | 未标注 | ★★ v0.5.5 修（第四轮 G-8）：原先时间字段的写法是 |
| `common/src/auth/oidc.rs` | 630 | 未标注 | 判据从"全局 subject 集合里有没有"改成 | 判据从"全局 subject 集合里有没有"改成 | 未标注 | ★ v0.5.3：判据从"全局 subject 集合里有没有"改成<br>"**这个 run_id 绑定的 subject** 是否等于 token 里的 sub"。<br>旧写法让"曾在任意连接上登录过的 sub"可以给任何 run_id 开工作连接。 |
| `common/src/auth/oidc.rs` | 744 | 未标注 | **这些算法要的密钥编码各有不同**， | **这些算法要的密钥编码各有不同**， | 未标注 | ★★ v0.5.5（第四轮 G-2）：**这些算法要的密钥编码各有不同**，<br>必须与 [`jwk_to_ring_key`] 产出的格式严格配对，否则验签**恒失败**： |
| `common/src/auth/oidc.rs` | 793 | 未标注 | 本函数原名叫 `jwk_to_spki`， | 本函数原名叫 `jwk_to_spki`， | 未标注 | ★★ v0.5.5 修（第四轮 G-2，高危可用性）：本函数原名叫 `jwk_to_spki`，<br>**注释还写着"ring 需要这个格式"，但对 RSA 恰恰相反** ——<br>ring 的 `RSA_PKCS1_2048_8192_SHA256`（以及 `RSA_PSS_*`）要的是<br>**裸的 PKCS#1 `RSAPublicKey`**，而不是外面又包了一层 `AlgorithmIdentifier`<br>的 `SubjectPublicKeyInfo`。EC 同理：`ECDSA_P256_SHA256_ASN1` 要的是<br>**裸的未压缩点**，不是 SPKI。 |
| `common/src/auth/oidc.rs` | 898 | 未标注 | 修完 SPKI/PKCS#1 的格式错配后，生产路径**不再构造 | 修完 SPKI/PKCS#1 的格式错配后，生产路径**不再构造 | 未标注 | ★ v0.5.5（G-2）：修完 SPKI/PKCS#1 的格式错配后，生产路径**不再构造<br>SPKI**，于是本函数只被它自己的编码测试用到。留着是为了那个"DER 编码<br>是否正确"的回归价值（将来若有人真要拼 SPKI，别再踩一遍）；<br>用 `#[cfg(test)]` 明确标注它不在生产路径上，避免又变成"看起来在用"的死代码。 |
| `common/src/auth/oidc.rs` | 1067 | 未标注 | G-8 回归：时间字段的**缺失**与**类型不对**都必须拒绝 | G-8 回归：时间字段的**缺失**与**类型不对**都必须拒绝 | 未标注 | ==================================================================<br>G-8 回归（v0.5.5）：时间字段的**缺失**与**类型不对**都必须拒绝 |
| `common/src/auth/oidc.rs` | 1264 | 未标注 | **subject 必须绑定到会话**，不能"登录过一次就到处通用"。 | **subject 必须绑定到会话**，不能"登录过一次就到处通用"。 | `subject_必须绑定到会话_不能跨_run_id_通用` | ★★ v0.5.3 回归：**subject 必须绑定到会话**，不能"登录过一次就到处通用"。 |
| `common/src/auth/oidc.rs` | 1316 | 未标注 | G-2 回归：**合法的签名必须验得过** | G-2 回归：**合法的签名必须验得过** | 未标注 | ==================================================================<br>G-2 回归（v0.5.5）：**合法的签名必须验得过** |
| `common/src/config/client.rs` | 31 | 未标注 | 手工实现 `Debug`（见文件下方），`token` 与各代理的 | 手工实现 `Debug`（见文件下方），`token` 与各代理的 | 未标注 | ★ v0.5.3：手工实现 `Debug`（见文件下方），`token` 与各代理的<br>`secret_key` / `http_pwd` 一律脱敏。 |
| `common/src/config/client.rs` | 130 | 未标注 | **加 `tlsEnable` 别名。** | **加 `tlsEnable` 别名。** | 未标注 | ★★ v0.5.8 修（第七轮审计 **B-2**，中危）：**加 `tlsEnable` 别名。** |
| `common/src/config/client.rs` | 172 | 未标注 | 是否**校验服务端证书**。 | 是否**校验服务端证书**。 | 未标注 | 是否**校验服务端证书**（v0.5.6 修审计总报告 L16，低危）。 |
| `common/src/config/client.rs` | 298 | 未标注 | `0` = 关闭看门狗。 | `0` = 关闭看门狗。 | 未标注 | `0` = 关闭看门狗（行为回到 v0.5.10 基线）。 |
| `common/src/config/client.rs` | 510 | 未标注 | 默认**不校验**（与官方 frp 一致，保互通）； | 默认**不校验**（与官方 frp 一致，保互通）； | 未标注 | ★ v0.5.6（L16）：默认**不校验**（与官方 frp 一致，保互通）；<br>想要校验的用户显式开 verifyServerCert。 |
| `common/src/config/client.rs` | 685 | 未标注 | `password` 脱敏（本地管理界面的 Basic Auth 口令）。 | `password` 脱敏（本地管理界面的 Basic Auth 口令）。 | 未标注 | ★ v0.5.3：`password` 脱敏（本地管理界面的 Basic Auth 口令）。 |
| `common/src/config/client.rs` | 726 | 未标注 | 所有凭据字段脱敏。 | 所有凭据字段脱敏。 | 未标注 | ★ v0.5.3：所有凭据字段脱敏。 |
| `common/src/config/defaults.rs` | 111 | 未标注 | visitor 本地监听口的默认绑定地址。 | visitor 本地监听口的默认绑定地址。 | 未标注 | visitor 本地监听口的默认绑定地址（v0.5.6 修审计总报告 L1）。 |
| `common/src/config/defaults.rs` | 124 | 未标注 | 登录时间戳默认允许的偏差（秒）， | 登录时间戳默认允许的偏差（秒）， | 未标注 | 登录时间戳默认允许的偏差（秒），v0.5.6 修审计总报告 M3。<br>300 秒足够容纳常见的时钟漂移与网络延迟，同时把"录下一条 Login 报文<br>就能无限期重放"压到 5 分钟窗口。官方 frpc 发的是当前时间，**零感知**。 |
| `common/src/config/parse.rs` | 257 | 未标注 | **唯一真源**：这个代理类型是不是"访客类"。 | **唯一真源**：这个代理类型是不是"访客类"。 | 未标注 | **唯一真源**：这个代理类型是不是"访客类"（v0.5.6 修审计总报告 H3）。 |
| `common/src/config/parse.rs` | 361 | 未标注 | 在 normalize **之前**记录"用户有没有显式写过 bind_addr"。 | 在 normalize **之前**记录"用户有没有显式写过 bind_addr"。 | 未标注 | ★ v0.5.4（M4）：在 normalize **之前**记录"用户有没有显式写过 bind_addr"。 |
| `common/src/config/proxy.rs` | 147 | 未标注 | 用 `Option<bool>` 而不是 `bool` + `serde(default = "true")`： | "从配置反序列化"得到**两个不同的默认值**。 | 未标注 | 用 `Option<bool>` 而不是 `bool` + `serde(default = "true")`：<br>`ProxyConfig` 有 `#[derive(Default)]`，bool 版本会让"程序内构造"与<br>"从配置反序列化"得到**两个不同的默认值**（v0.5.6 修 L1 的教训）。 |
| `common/src/config/proxy.rs` | 365 | 未标注 | 默认值改为 **`127.0.0.1`**。 | 默认值改为 **`127.0.0.1`**。 | 未标注 | ★★ v0.5.6 修（审计总报告 L1，低危）：默认值改为 **`127.0.0.1`**。 |
| `common/src/config/proxy.rs` | 414 | 未标注 | 与 serde 的 `#[serde(default)]` 保持一致 —— | 与 serde 的 `#[serde(default)]` 保持一致 —— | 未标注 | ★ v0.5.6（L1）：与 serde 的 `#[serde(default)]` 保持一致 ——<br>两处都必须用 visitor 专用的默认值，否则"不写 bind_addr"<br>在 `Default::default()` 与反序列化两条路径下会得到不同结果。 |
| `common/src/config/server.rs` | 106 | 未标注 | 手工实现 `Debug`（见文件下方），`token` 与 `dashboard_pwd` | 手工实现 `Debug`（见文件下方），`token` 与 `dashboard_pwd` | 未标注 | ★ v0.5.3：手工实现 `Debug`（见文件下方），`token` 与 `dashboard_pwd`<br>一律脱敏，避免任何调试打印把密钥写进日志。 |
| `common/src/config/server.rs` | 121 | 未标注 | 用户是否**显式写过** `bind_addr`。 | 用户是否**显式写过** `bind_addr`。 | 未标注 | ★ 用户是否**显式写过** `bind_addr`（v0.5.4，配合 M4 的判定）。 |
| `common/src/config/server.rs` | 208 | 未标注 | `0` 表示**关闭看门狗**—— 项目约定 | `0` 表示**关闭看门狗**—— 项目约定 | 未标注 | `0` 表示**关闭看门狗**（行为回到 v0.5.10 基线）—— 项目约定<br>"0 = 关掉这项"；官方把 0 折算成 30，这里不复刻。 |
| `common/src/config/server.rs` | 609 | 未标注 | 明确同意"**服务端不做认证**且对外监听"。 | 明确同意"**服务端不做认证**且对外监听"。 | 未标注 | 明确同意"**服务端不做认证**且对外监听"（v0.5.4 新增，修 M4）。 |
| `common/src/config/server.rs` | 624 | 未标注 | 登录时间戳允许的偏差（秒）， | 登录时间戳允许的偏差（秒）， | 未标注 | 登录时间戳允许的偏差（秒），v0.5.6 修审计总报告 M3。 |
| `common/src/config/server.rs` | 729 | 未标注 | `token` / `dashboard_pwd` 永不进日志。 | `token` / `dashboard_pwd` 永不进日志。 | 未标注 | ★ v0.5.3：`token` / `dashboard_pwd` 永不进日志。 |
| `common/src/config/server.rs` | 907 | 未标注 | **唯一判据**：这对面板 / 管理界面凭据能不能用来鉴权。 | **唯一判据**：这对面板 / 管理界面凭据能不能用来鉴权。 | 未标注 | **唯一判据**：这对面板 / 管理界面凭据能不能用来鉴权（v0.5.6 修审计总报告 H1）。 |
| `common/src/config/server.rs` | 951 | 未标注 | **唯一判据**：本服务端是不是处于"**没有任何认证**"的状态 | 。 | 未标注 | **唯一判据**：本服务端是不是处于"**没有任何认证**"的状态<br>（v0.5.6 修审计总报告 M6）。 |
| `common/src/config/server.rs` | 1047 | 未标注 | 默认 ±300 秒的登录时间戳窗口（0 = 关闭） | 默认 ±300 秒的登录时间戳窗口（0 = 关闭） | 未标注 | v0.5.6（M3）：默认 ±300 秒的登录时间戳窗口（0 = 关闭） |
| `common/src/config/tests.rs` | 89 | 未标注 | Debug 脱敏 | Debug 脱敏 | `debug_输出不得泄漏服务端密钥` | -----------------------------------------------------------------------<br>Debug 脱敏（v0.5.3）<br>----------------------------------------------------------------------- |
| `common/src/config/tests.rs` | 678 | 未标注 | **远程下发的 `local_addr` 回环白名单不得接受 `localhost`。** | **远程下发的 `local_addr` 回环白名单不得接受 `localhost`。** | `远程下发不得接受_localhost_作回环地址` | ★★ v0.5.8 回归（第七轮审计 **E-1**，高危）：<br>**远程下发的 `local_addr` 回环白名单不得接受 `localhost`。** |
| `common/src/config/tests.rs` | 783 | 未标注 | **远程下发的非插件代理，`local_addr` 不能为空。** | **远程下发的非插件代理，`local_addr` 不能为空。** | 未标注 | ★★ v0.5.8 回归（第七轮审计 **E7 附带发现**，低危）：<br>**远程下发的非插件代理，`local_addr` 不能为空。** |
| `common/src/config/tests.rs` | 872 | 未标注 | **方括号形式必须整段就是 `[host]:port`** —— 否则"判据看到的主机" | **方括号形式必须整段就是 `[host]:port`** —— 否则"判据看到的主机" | `方括号写法必须整段合法否则从严拒绝` | ★★ v0.5.8 回归（第七轮审计 **E-2**，中危）：<br>**方括号形式必须整段就是 `[host]:port`** —— 否则"判据看到的主机"<br>与"实际连接用的主机"会不一致（check-vs-use）。 |
| `common/src/config/tests.rs` | 952 | 未标注 | **`tlsEnable`（驼峰）与 `tls_enable`（下划线）必须都能开启 TLS。** | **`tlsEnable`（驼峰）与 `tls_enable`（下划线）必须都能开启 TLS。** | `tls_开关的驼峰写法必须生效` | ★★ v0.5.8 回归（第七轮审计 **B-2**，中危）：<br>**`tlsEnable`（驼峰）与 `tls_enable`（下划线）必须都能开启 TLS。** |
| `common/src/config/validate.rs` | 161 | 未标注 | `local_addr` 必须**只允许回环**。 | `local_addr` 必须**只允许回环**。 | 未标注 | ★★ v0.5.4 修 H4：`local_addr` 必须**只允许回环**。 |
| `common/src/config/validate.rs` | 190 | 未标注 | **远程下发一律不允许携带插件**。 | **远程下发一律不允许携带插件**。 | 未标注 | ★★ v0.5.5 修（第四轮 F1）：**远程下发一律不允许携带插件**。 |
| `common/src/config/validate.rs` | 222 | 未标注 | **补上 `plugin_request_headers`**。 | **补上 `plugin_request_headers`**。 | 未标注 | ★★ v0.5.6 修（审计总报告 L6，低危）：**补上 `plugin_request_headers`**。 |
| `common/src/config/validate.rs` | 253 | 未标注 | 这一项原先漏了 | 这一项原先漏了 | 未标注 | ★ v0.5.6（L6）：这一项原先漏了 |
| `common/src/config/validate.rs` | 267 | 未标注 | **非插件代理的 | **非插件代理的 | 未标注 | ★★ v0.5.8 修（第七轮审计 **E7 附带发现**，低危）：**非插件代理的<br>`local_addr` 不能为空**。 |
| `common/src/config/validate.rs` | 322 | 未标注 | **方括号必须紧跟着 port 冒号**， | **方括号必须紧跟着 port 冒号**， | 未标注 | ★★ v0.5.8 修（第七轮审计 **E-2**，中危）：**方括号必须紧跟着 port 冒号**，<br>不能"取第一个 `]` 之前就算主机"。 |
| `common/src/config/validate.rs` | 392 | 未标注 | **不再无条件放行 `localhost`**。 | **不再无条件放行 `localhost`**。 | 未标注 | ★★ v0.5.8 修（第七轮审计 **E-1**，高危）：**不再无条件放行 `localhost`**。 |
| `common/src/frp/conn.rs` | 40 | 未标注 | 解密后明文的缓冲上限。 | 解密后明文的缓冲上限。 | 未标注 | 解密后明文的缓冲上限（v0.5.4，M6）。 |
| `common/src/frp/conn.rs` | 388 | 未标注 | `plain` 也必须有自己的硬顶。 | `plain` 也必须有自己的硬顶。 | 未标注 | ★★ v0.5.4 修 M6：`plain` 也必须有自己的硬顶。 |
| `common/src/frp/conn.rs` | 992 | 未标注 | * `run_id` —— 本次会话的标识，会写进 LoginResp 下发给客户端。 | * `max_clock_skew_secs` —— 登录时间戳允许的偏差。 | 未标注 | * `run_id` —— 本次会话的标识，会写进 LoginResp 下发给客户端。<br>* `max_clock_skew_secs` —— 登录时间戳允许的偏差（0 = 不校验，v0.5.6 M3）。 |
| `common/src/frp/conn.rs` | 1222 | 未标注 | **先校验时间戳新鲜性**， | **先校验时间戳新鲜性**， | 未标注 | ★★ v0.5.6 修（审计总报告 M3，中危）：**先校验时间戳新鲜性**，<br>再比凭证。 |
| `common/src/frp/conn.rs` | 1237 | 未标注 | **这一步不再单独调用** —— | **这一步不再单独调用** —— | 未标注 | ★★ v0.5.7（第六轮审计 G-1，高危）：**这一步不再单独调用** ——<br>新鲜性校验已经并进 `verify_login` 内部（见那里的长注释）。 |
| `common/src/frp/conn.rs` | 1295 | 未标注 | 回显"工作连接必须带凭证"。 | 回显"工作连接必须带凭证"。 | 未标注 | ★ v0.5.5（第四轮 A-1）：回显"工作连接必须带凭证"。 |
| `common/src/frp/conn.rs` | 1974 | 未标注 | （M6）：解密缓冲（`plain`）必须有硬顶。 | （M6）：解密缓冲（`plain`）必须有硬顶。 | `解密缓冲上限的口径` | ★★ v0.5.4 回归（M6）：解密缓冲（`plain`）必须有硬顶。 |
| `common/src/frp/crypto.rs` | 88 | 未标注 | 已发帧数。 | 已发帧数。 | 未标注 | 已发帧数（v0.5.4，M7）。 |
| `common/src/frp/crypto.rs` | 127 | 未标注 | 帧数逼近 nonce 空间上限时 **fail-closed**。 | 帧数逼近 nonce 空间上限时 **fail-closed**。 | 未标注 | ★ v0.5.4（M7）：帧数逼近 nonce 空间上限时 **fail-closed**。<br>与上游一致：宁可断开，也不能冒 nonce 重用的风险。 |
| `common/src/frp/crypto.rs` | 276 | 未标注 | （M7）：AEAD 必须记帧数，并在逼近 2³² 时 **fail-closed**。 | （M7）：AEAD 必须记帧数，并在逼近 2³² 时 **fail-closed**。 | `aead_帧计数与上限` | ★★ v0.5.4 回归（M7）：AEAD 必须记帧数，并在逼近 2³² 时 **fail-closed**。 |
| `common/src/frp/kcp.rs` | 69 | 未标注 | KCP **接收侧**单条消息的大小上限。 | KCP **接收侧**单条消息的大小上限。 | 未标注 | KCP **接收侧**单条消息的大小上限（v0.5.6 修审计总报告 M10）。 |
| `common/src/frp/kcp.rs` | 154 | 未标注 | **单段数据长度不得超过 MTU**。 | **单段数据长度不得超过 MTU**。 | 未标注 | ★ v0.5.6（M10）：**单段数据长度不得超过 MTU**。 |
| `common/src/frp/kcp.rs` | 197 | 未标注 | 单段数据长度超过 MTU 上限。 | 单段数据长度超过 MTU 上限。 | 未标注 | v0.5.6（M10）：单段数据长度超过 MTU 上限。 |
| `common/src/frp/kcp.rs` | 395 | 未标注 | **接收侧补上消息大小上限**。 | **接收侧补上消息大小上限**。 | 未标注 | ★★ v0.5.6 修（审计总报告 M10，中危）：**接收侧补上消息大小上限**。 |
| `common/src/frp/kcp.rs` | 450 | 未标注 | 超限即丢弃整条流，绝不为它分配内存。 | 超限即丢弃整条流，绝不为它分配内存。 | 未标注 | ★ v0.5.6（M10）：超限即丢弃整条流，绝不为它分配内存。 |
| `common/src/frp/kcp.rs` | 990 | 未标注 | **KCP 会话表的条数上限**。 | **KCP 会话表的条数上限**。 | 未标注 | ★★ v0.5.9 新增（第九轮审计 **C9-1**，中危）：**KCP 会话表的条数上限**。 |
| `common/src/frp/kcp.rs` | 1047 | 未标注 | 会话表打满后"丢弃新会话"日志的折叠器。 | 会话表打满后"丢弃新会话"日志的折叠器。 | 未标注 | ★ v0.5.9 收尾（C9-1）：会话表打满后"丢弃新会话"日志的折叠器。 |
| `common/src/frp/kcp.rs` | 1072 | 未标注 | 覆盖会话数上限（测试与特殊部署用）。 | 覆盖会话数上限（测试与特殊部署用）。 | 未标注 | ★ v0.5.9（C9-1）：覆盖会话数上限（测试与特殊部署用）。 |
| `common/src/frp/kcp.rs` | 1142 | 未标注 | **会话表必须封顶**。 | **会话表必须封顶**。 | 未标注 | ★★ v0.5.9 修（第九轮审计 **C9-1**，中危）：**会话表必须封顶**。 |
| `common/src/frp/kcp.rs` | 1154 | 未标注 | 这条路径**按被丢弃的数据报数触发**、与 | 这条路径**按被丢弃的数据报数触发**、与 | 未标注 | ★ v0.5.9 订正：这条路径**按被丢弃的数据报数触发**、与<br>`max_sessions` 无关 —— 原先自注"日志量受 max_sessions<br>约束"不成立，未认证对手保持灌包就能无限刷 debug 日志。<br>已改用 `RateLimited` 折叠（配额 + 压制计数汇总）。 |
| `common/src/frp/kcp.rs` | 1493 | 未标注 | **KCP 会话表必须封顶。** | **KCP 会话表必须封顶。** | `kcp_会话表必须有上限` | ★★ v0.5.9 回归（第九轮审计 **C9-1**，中危）：**KCP 会话表必须封顶。** |
| `common/src/frp/kcp.rs` | 1726 | 未标注 | 接收侧消息大小上限 | 接收侧消息大小上限 | 未标注 | ------------------------------------------------------------------<br>v0.5.6 回归（审计总报告 M10）：接收侧消息大小上限<br>------------------------------------------------------------------ |
| `common/src/frp/msg.rs` | 65 | 未标注 | **手工实现 `Debug`，`privilege_key` 打码**。 | **手工实现 `Debug`，`privilege_key` 打码**。 | 未标注 | ★★ v0.5.6 修（审计总报告 L9，低危）：**手工实现 `Debug`，`privilege_key` 打码**。 |
| `common/src/frp/msg.rs` | 119 | 未标注 | 凭据**绝不**进日志。空/非空也区分显示 —— | 凭据**绝不**进日志。空/非空也区分显示 —— | 未标注 | ★ v0.5.6（L9）：凭据**绝不**进日志。空/非空也区分显示 ——<br>长度本身是可用信息（能区分"没带凭证"与"带了错的"），<br>所以只区分"空"与"非空"，不暴露长度。 |
| `common/src/frp/msg.rs` | 167 | 未标注 | 本客户端会在**工作连接**上携带 `privilege_key`。 | 本客户端会在**工作连接**上携带 `privilege_key`。 | 未标注 | ★ v0.5.5：本客户端会在**工作连接**上携带 `privilege_key`。 |
| `common/src/frp/msg.rs` | 734 | 未标注 | **必须消掉 IPv6 的歧义**。 | **必须消掉 IPv6 的歧义**。 | 未标注 | ★★ v0.5.6 修（审计总报告 M16，中危）：**必须消掉 IPv6 的歧义**。 |
| `common/src/frp/msg.rs` | 1404 | 未标注 | UdpAddr:key() 的 IPv6 歧义 | UdpAddr:key() 的 IPv6 歧义 | `udp_addr_key_不得有_ipv6_歧义` | ------------------------------------------------------------------<br>v0.5.6 回归（审计总报告 M16）：UdpAddr::key() 的 IPv6 歧义<br>------------------------------------------------------------------ |
| `common/src/frp/mux.rs` | 589 | 未标注 | `tcpMuxKeepaliveInterval = 0`（折算 `None`）时不做任何静默判定 —— | 行为回到 基线。 | `保活关闭时不判定静默` | `tcpMuxKeepaliveInterval = 0`（折算 `None`）时不做任何静默判定 ——<br>行为回到 v0.5.10 基线。 |
| `common/src/frp/tls.rs` | 145 | 未标注 | 保留这个默认，但**新增** | 保留这个默认，但**新增** | 未标注 | ★★ v0.5.6（审计总报告 L16，低危）：保留这个默认，但**新增**<br>[`client_config_verifying`] 提供"真正校验"的可选路径。 |
| `common/src/frp/tls.rs` | 170 | 未标注 | 客户端 TLS 配置：**校验服务端证书**。 | 客户端 TLS 配置：**校验服务端证书**。 | 未标注 | 客户端 TLS 配置：**校验服务端证书**（v0.5.6，L16）。 |
| `common/src/frp/tls.rs` | 493 | 未标注 | `verify = false` 走与官方一致的"不校验"（保互通）， | `verify = false` 走与官方一致的"不校验"（保互通）， | 未标注 | ★ v0.5.6（L16）：`verify = false` 走与官方一致的"不校验"（保互通），<br>`true` 走真正校验（需要 `trustedCaFile` 配合自签场景）。 |
| `common/src/frp/wire.rs` | 175 | 未标注 | `clientRandom` 补上 **base64 形态与长度**校验。 | `clientRandom` 补上 **base64 形态与长度**校验。 | 未标注 | ★ v0.5.5 修（第四轮 A-5）：`clientRandom` 补上 **base64 形态与长度**校验。 |
| `common/src/frp/wire.rs` | 302 | 未标注 | A-5 回归：`clientRandom` 必须是合法 base64。 | A-5 回归：`clientRandom` 必须是合法 base64。 | `client_random_必须是合法_base64` | ★★ A-5 回归（v0.5.5）：`clientRandom` 必须是合法 base64。 |
| `common/src/frp_config.rs` | 480 | 未标注 | 用**大小写折叠**查找，而不是精确匹配。 | 用**大小写折叠**查找，而不是精确匹配。 | 未标注 | ★ v0.5.4 修（L8）：用**大小写折叠**查找，而不是精确匹配。 |
| `common/src/frp_legacy.rs` | 196 | 未标注 | **段名统一小写**。 | **段名统一小写**。 | 未标注 | ★★ v0.5.6 修（审计总报告 M4，中危）：**段名统一小写**。 |
| `common/src/frp_legacy.rs` | 224 | 未标注 | **键名统一小写**。 | **键名统一小写**。 | 未标注 | ★★ v0.5.6 修（审计总报告 M4，中危）：**键名统一小写**。 |
| `common/src/frp_legacy.rs` | 769 | 未标注 | 段名从本版起统一小写，所以这里必须用小写的 | 段名从本版起统一小写，所以这里必须用小写的 | 未标注 | ★ v0.5.6（M4）：段名从本版起统一小写，所以这里必须用小写的<br>`"default"` —— 否则段前的裸键会被**当成一个代理**去加载。 |
| `common/src/frp_legacy.rs` | 1033 | 未标注 | 段名现在**统一小写**。 | 段名现在**统一小写**。 | `ini_的段名与键名必须大小写不敏感` | ★ v0.5.6（审计总报告 M4）：段名现在**统一小写**。 |
| `common/src/frp_legacy.rs` | 1047 | 未标注 | INI 的**段名与键名必须大小写不敏感**。 | INI 的**段名与键名必须大小写不敏感**。 | `ini_的段名与键名必须大小写不敏感` | ★★ v0.5.6 回归（审计总报告 M4）：INI 的**段名与键名必须大小写不敏感**。 |
| `common/src/http1.rs` | 29 | 未标注 | **不再单独定义**，改为复用 | **不再单独定义**，改为复用 | 未标注 | ★★ v0.5.6 修（审计总报告 L8，低危）：**不再单独定义**，改为复用<br>[`crate::http_relay::MAX_HEAD`]。 |
| `common/src/http1.rs` | 66 | 未标注 | 取某个头的**全部**同名值。 | 取某个头的**全部**同名值。 | 未标注 | 取某个头的**全部**同名值（v0.5.4，L7）。 |
| `common/src/http1.rs` | 101 | 未标注 | 取某个头的**全部**同名值。顺序与报文中出现的一致。 | 取某个头的**全部**同名值。顺序与报文中出现的一致。 | 未标注 | 取某个头的**全部**同名值（v0.5.4，L7）。顺序与报文中出现的一致。 |
| `common/src/http1.rs` | 494 | 未标注 | （L7）：必须能枚举**全部**同名头。 | （L7）：必须能枚举**全部**同名头。 | `同名头必须能完整枚举` | ★★ v0.5.4 回归（L7）：必须能枚举**全部**同名头。 |
| `common/src/http1.rs` | 539 | 未标注 | `MAX_HEAD` **只能有一个真源**。 | `MAX_HEAD` **只能有一个真源**。 | `max_head_必须与_http_relay_同源` | ★★ v0.5.6 回归（审计总报告 L8）：`MAX_HEAD` **只能有一个真源**。 |
| `common/src/http_relay.rs` | 113 | 未标注 | 用途：等待上游（响应头、上游 TLS 握手）时用 `tokio:select!` 同时轮询 | （ 第八轮审计 **F8T-1**：`https2*` 悬挂上游 + 访问方撤离， | 未标注 | 用途：等待上游（响应头、上游 TLS 握手）时用 `tokio::select!` 同时轮询<br>这里 —— 对端撤离后立刻结束等待，别替一个已经离开的访问者继续等<br>（★ v0.5.8，第八轮审计 **F8T-1**：`https2*` 悬挂上游 + 访问方撤离，<br>上游连接原先永不释放）。 |
| `common/src/http_relay.rs` | 164 | 未标注 | **上限必须真的生效**。 | **上限必须真的生效**。 | 未标注 | ★★ v0.5.5 修（第四轮 C-2）：**上限必须真的生效**。 |
| `common/src/http_relay.rs` | 275 | 未标注 | 必须用 `saturating_add`。 | 必须用 `saturating_add`。 | 未标注 | ★ 必须用 `saturating_add`（v0.5.3 修）。 |
| `common/src/http_relay.rs` | 354 | 未标注 | 为什么必须有它：`get()` 只返回**第一个**， | 为什么必须有它：`get()` 只返回**第一个**， | 未标注 | ★ v0.5.4 新增（H2）。为什么必须有它：`get()` 只返回**第一个**，<br>而 `to_bytes()` 会把 `headers` 里的**所有**同名头都序列化出去 ——<br>"读只读第一个、写却写出去两个"正是 CL.CL 请求走私的温床。<br>任何需要判断"这个头出现了几次"的地方都要用它，不要用 `get().is_some()`。 |
| `common/src/http_relay.rs` | 384 | 未标注 | 剥掉而不是报错：调用方遍布转发热路径，逐处处理 `Result` 不值得； | 严格解析 `Content-Length`。 | 未标注 | 剥掉而不是报错：调用方遍布转发热路径，逐处处理 `Result` 不值得；<br>而且 HTTP 头的名字/值本来就不允许含 CRLF，剥掉等于"按规范收敛"。<br>严格解析 `Content-Length`（v0.5.4，H2）。 |
| `common/src/http_relay.rs` | 421 | 未标注 | 同名头去重。 | 同名头去重。 | 未标注 | 同名头去重（v0.5.4，H2 的第三层纵深防御）。 |
| `common/src/http_relay.rs` | 544 | 未标注 | 按 **RFC 7230 §3.3.3** 判定 —— | 按 **RFC 7230 §3.3.3** 判定 —— | 未标注 | ★★ v0.5.5 修（第四轮 C 组 TE.TE 走私）：按 **RFC 7230 §3.3.3** 判定 ——<br>传输编码是一串**按顺序应用**的编码，`chunked` 必须是**最后一个**令牌<br>才算"按 chunked 分帧"。 |
| `common/src/http_relay.rs` | 748 | 未标注 | 加入 `proxy-connection`。 | 加入 `proxy-connection`。 | 未标注 | ★★ v0.5.8 补（第七轮审计 **D7-3**，低危）：加入 `proxy-connection`。 |
| `common/src/http_relay.rs` | 782 | 未标注 | **请求 framing 校验**。 | **请求 framing 校验**。 | 未标注 | **请求 framing 校验**（v0.5.6 修审计总报告 M2）。 |
| `common/src/http_relay.rs` | 812 | 未标注 | **响应侧的 framing 校验**。 | **响应侧的 framing 校验**。 | 未标注 | ★★ v0.5.8 新增（第七轮审计 **D7-2**，中危）：**响应侧的 framing 校验**。 |
| `common/src/http_relay.rs` | 864 | 未标注 | **剥掉逐跳头**。 | **剥掉逐跳头**。 | 未标注 | **剥掉逐跳头**（v0.5.6 修审计总报告 M2）。 |
| `common/src/http_relay.rs` | 961 | 未标注 | H2：重复 Content-Length / 同名头去重 | H2：重复 Content-Length / 同名头去重 | `同名头必须能被完整枚举` | ------------------------------------------------------------------<br>H2（v0.5.4）：重复 Content-Length / 同名头去重<br>------------------------------------------------------------------ |
| `common/src/http_relay.rs` | 1147 | 未标注 | 配套：`watch_closed` 要能识别 EOF， | 配套：`watch_closed` 要能识别 EOF， | `watch_closed_识别_eof_且不丢字节` | ★ v0.5.8（第八轮审计 F8T-1，低危）配套：`watch_closed` 要能识别 EOF，<br>且**读到的字节不会丢**（存进缓冲，后续照常消费）。 |
| `common/src/http_relay.rs` | 1242 | 未标注 | chunk 长度大到能让 `len + size` **算术回绕**时， | chunk 长度大到能让 `len + size` **算术回绕**时， | `chunked_长度回绕不能绕过体积上限` | ★★ v0.5.3 回归：chunk 长度大到能让 `len + size` **算术回绕**时，<br>ACL 必须照常拒绝（而不是因为回绕成小值而"通过"）。 |
| `common/src/http_relay.rs` | 1307 | 未标注 | **响应侧也要做 framing 校验**。 | **响应侧也要做 framing 校验**。 | `响应侧_framing_校验必须与请求侧同样严格` | ★★ v0.5.8 回归（第七轮审计 **D7-2**，中危）：**响应侧也要做 framing 校验**。 |
| `common/src/httpc.rs` | 350 | 未标注 | 全部改 `checked_add` / `saturating_add`。 | 全部改 `checked_add` / `saturating_add`。 | 未标注 | ★ 全部改 `checked_add` / `saturating_add`（v0.5.3 修）。 |
| `common/src/httpc.rs` | 393 | 未标注 | **先拒控制字符**。 | **先拒控制字符**。 | 未标注 | ★★ v0.5.6 修（审计总报告 M9，中危）：**先拒控制字符**。 |
| `common/src/httpc.rs` | 639 | 未标注 | chunk 长度导致 `i + size` / `i += size + 2` 算术回绕。 | chunk 长度导致 `i + size` / `i += size + 2` 算术回绕。 | `chunked_长度回绕不能绕过截断检查` | ★★ v0.5.3 回归：chunk 长度导致 `i + size` / `i += size + 2` 算术回绕。 |
| `common/src/httpc.rs` | 666 | 未标注 | URL 不得含控制字符 | URL 不得含控制字符 | `url_必须拒绝控制字符` | ------------------------------------------------------------------<br>v0.5.6 回归（审计总报告 M9）：URL 不得含控制字符<br>------------------------------------------------------------------ |
| `common/src/p2p.rs` | 188 | 未标注 | 旧协议里 provider 校验完口令后 | 旧协议里 provider 校验完口令后 | 未标注 | ★ v0.5.8 修（第八轮审计 B-1，高危）：旧协议里 provider 校验完口令后<br>只回一个**固定**的 8 字节 `RTNL-OK`，visitor 收到它就认为握手成功。<br>而牵线用的 UDP HELLO 既没有鉴权、`sid` 又在报文里明文携带，<br>攻击者只要在链路上读到一次 HELLO，就能以 provider 身份抢先登记：<br>服务端会把 visitor 的地址发给它，visitor 还会主动连过去并把<br>**用户的明文流量**交给这个假 provider（会话劫持）。 |
| `common/src/p2p.rs` | 683 | 未标注 | 应答口令同样绑定 `secret_key`/`sid`， | 应答口令同样绑定 `secret_key`/`sid`， | `handshake_ack_binds_secret_and_session` | ★ v0.5.8（第八轮审计 B-1，高危）：应答口令同样绑定 `secret_key`/`sid`，<br>且与请求口令**域分离** —— 两者一旦相等，攻击者把读到的 visitor 口令<br>原样回过去就能过，等于没修。 |
| `common/src/security.rs` | 53 | 未标注 | **手工实现 `Debug`**，`token` 一律脱敏。 | **手工实现 `Debug`**，`token` 一律脱敏。 | 未标注 | ★ v0.5.3：**手工实现 `Debug`**，`token` 一律脱敏。 |
| `common/src/security.rs` | 106 | 未标注 | `token` 永不进日志。 | `token` 永不进日志。 | 未标注 | ★ v0.5.3：`token` 永不进日志。 |
| `common/src/security.rs` | 162 | 未标注 | **手工实现 `Debug`**，`token` 必须脱敏。 | **手工实现 `Debug`**，`token` 必须脱敏。 | 未标注 | ★ v0.5.4 修（M5）：**手工实现 `Debug`**，`token` 必须脱敏。 |
| `common/src/security.rs` | 207 | 未标注 | `token` 永不进日志，与 `ServerAuthConfig:Debug` 同口径。 | `token` 永不进日志，与 `ServerAuthConfig:Debug` 同口径。 | 未标注 | ★ v0.5.4（M5）：`token` 永不进日志，与 `ServerAuthConfig::Debug` 同口径。 |
| `common/src/security.rs` | 539 | 未标注 | （仅含历史标记，已删除） | （仅含历史标记，已删除） | 未标注 | ★★ v0.5.7 新增（第六轮审计 G-1，高危）。 |
| `common/src/security.rs` | 583 | 未标注 | `run_id` 用于把 OIDC 的 subject **绑定到本次会话**。 | `run_id` 用于把 OIDC 的 subject **绑定到本次会话**。 | 未标注 | `run_id` 用于把 OIDC 的 subject **绑定到本次会话**（v0.5.3 起）。 |
| `common/src/security.rs` | 585 | 未标注 | token 模式增加 **timestamp 新鲜性窗口**。 | token 模式增加 **timestamp 新鲜性窗口**。 | 未标注 | ★★ v0.5.6 修（审计总报告 M3，中危）：token 模式增加 **timestamp 新鲜性窗口**。 |
| `common/src/security.rs` | 620 | 未标注 | **把新鲜性校验并进来**。 | **把新鲜性校验并进来**。 | 未标注 | ★★ v0.5.7 修（第六轮审计 G-1，高危）：**把新鲜性校验并进来**。 |
| `common/src/security.rs` | 707 | 未标注 | 登录时间戳的新鲜性校验。 | 登录时间戳的新鲜性校验。 | 未标注 | 登录时间戳的新鲜性校验（v0.5.6，M3）。 |
| `common/src/security.rs` | 709 | 未标注 | **已经由 [`Self:verify_login`] 内部调用**， | **已经由 [`Self:verify_login`] 内部调用**， | 未标注 | ★ v0.5.7：**已经由 [`Self::verify_login`] 内部调用**，<br>不再需要调用方自己记得调。独立保留是为了：<br>* 让 [`verify_shared_secret_proof`] 复用同一份实现；<br>* 错误文案可区分（"过期" vs "凭证错"），运维能一眼看出是时钟问题还是配置问题。 |
| `common/src/security.rs` | 725 | 未标注 | `run_id` 是必需的：旧实现只查一个全局 subject 集合， | `run_id` 是必需的：旧实现只查一个全局 subject 集合， | 未标注 | `run_id` 是必需的（v0.5.3）：旧实现只查一个全局 subject 集合，<br>于是"自己登录过一次"就能给**别人的** run_id 背书。 |
| `common/src/security.rs` | 868 | 未标注 | 加 `deny_unknown_fields`。 | 加 `deny_unknown_fields`。 | 未标注 | ★★ v0.5.4 修（M9）：加 `deny_unknown_fields`。 |
| `common/src/security.rs` | 1225 | 未标注 | **判据必须走唯一真源**。 | **判据必须走唯一真源**。 | 未标注 | ★★ v0.5.6 修（审计总报告 H3，高危）：**判据必须走唯一真源**。 |
| `common/src/security.rs` | 1280 | 未标注 | 原先只有内存环形上限，审计文件**无上界** —— | 原先只有内存环形上限，审计文件**无上界** —— | 未标注 | ★ v0.5.9（第九轮 A9-3）：原先只有内存环形上限，审计文件**无上界** ——<br>实测 ~1000 行/s、约 37 MB/h 可持续增长，这是一条可被利用的磁盘<br>耗尽路径（审计默认关闭，但开启后就再无保护）。有了默认上限后<br>占用可预期，且**事件不丢**（旧内容在 `.1` 里）。 |
| `common/src/security.rs` | 1526 | 未标注 | allowVisitors 必须覆盖全部访客类型 | allowVisitors 必须覆盖全部访客类型 | `allow_visitors_必须覆盖全部访客类型` | ------------------------------------------------------------------<br>v0.5.6 回归（审计总报告 H3）：allowVisitors 必须覆盖全部访客类型<br>------------------------------------------------------------------ |
| `common/src/security.rs` | 1752 | 未标注 | M5：ClientAuthConfig 的 Debug 必须脱敏 | M5：ClientAuthConfig 的 Debug 必须脱敏 | `client_auth_debug_不得泄漏_token` | ------------------------------------------------------------------<br>M5（v0.5.4）：ClientAuthConfig 的 Debug 必须脱敏<br>------------------------------------------------------------------ |
| `common/src/security.rs` | 1790 | 未标注 | 登录时间戳新鲜性窗口 | 登录时间戳新鲜性窗口 | 未标注 | ------------------------------------------------------------------<br>v0.5.6 回归（审计总报告 M3）：登录时间戳新鲜性窗口<br>------------------------------------------------------------------ |
| `common/src/security.rs` | 1875 | 未标注 | M9：[acl] 拼写错误必须报错，而不是静默失效 | M9：[acl] 拼写错误必须报错，而不是静默失效 | `acl_拼错的键名必须报错而不是静默失效` | ------------------------------------------------------------------<br>M9（v0.5.4）：[acl] 拼写错误必须报错，而不是静默失效<br>------------------------------------------------------------------ |
| `common/src/util.rs` | 26 | 未标注 | **速率受限的日志开关**。 | **速率受限的日志开关**。 | 未标注 | ★★ v0.5.8 新增（第七轮审计 **A-1**，中危）：**速率受限的日志开关**。 |
| `common/src/util.rs` | 159 | 未标注 | **按"消息指纹"折叠重复日志**。 | **按"消息指纹"折叠重复日志**。 | 未标注 | ★★ v0.5.8 新增（第七轮审计 **A-1** 的第二版修法）：**按"消息指纹"折叠重复日志**。 |
| `common/src/util.rs` | 476 | 未标注 | **规范的线上全名**：`{user}.{原始名}`，且**幂等**。 | **规范的线上全名**：`{user}.{原始名}`，且**幂等**。 | 未标注 | **规范的线上全名**：`{user}.{原始名}`，且**幂等**（v0.5.6 修审计总报告 M5）。 |
| `common/src/util.rs` | 613 | 未标注 | `OsRng`（与 v1 IV / v2 nonce / Hello random 同一个源）。 | `OsRng`（与 v1 IV / v2 nonce / Hello random 同一个源）。 | 未标注 | ★ v0.5.3 改用 `OsRng`（与 v1 IV / v2 nonce / Hello random 同一个源）。 |
| `common/src/util.rs` | 725 | 未标注 | run_id 必须来自**密码学随机源**，不能只是"看起来随机"。 | run_id 必须来自**密码学随机源**，不能只是"看起来随机"。 | `run_id_comes_from_a_real_random_source` | ★ v0.5.3：run_id 必须来自**密码学随机源**，不能只是"看起来随机"。 |
| `common/src/util.rs` | 732 | 未标注 | 第 2 条的阈值原来写的是「64 个样本里至少 55 个不同」， | 第 2 条的阈值原来写的是「64 个样本里至少 55 个不同」， | `run_id_comes_from_a_real_random_source` | ★★ v0.5.4 修：第 2 条的阈值原来写的是「64 个样本里至少 55 个不同」，<br>**失败概率高达 16%**（每跑 6 次就红一次）—— 这是个会污染 CI 的假失败。 |
| `common/src/util.rs` | 803 | 未标注 | **同类日志必须被折叠**。 | **同类日志必须被折叠**。 | `日志折叠_同类消息每窗口最多两条` | ★★ v0.5.8 回归（第七轮审计 **A-1**，中危）：**同类日志必须被折叠**。 |
| `common/src/ws.rs` | 76 | 未标注 | 控制帧（ping / pong / close）的载荷上限。 | 控制帧（ping / pong / close）的载荷上限。 | 未标注 | 控制帧（ping / pong / close）的载荷上限（v0.5.4，L9）。 |
| `common/src/ws.rs` | 391 | 未标注 | 原先只读掩码位用于"要不要异或"， | 原先只读掩码位用于"要不要异或"， | 未标注 | ★★ v0.5.5 修（第四轮 G-7）：原先只读掩码位用于"要不要异或"，<br>**从不校验它**，于是未掩码的客户端帧被照常处理（实弹 `tmp/audit4g/g8_ws_mask.py`：<br>发一个 `masked=False` 的 Login 帧，服务端照回 `LoginResp`）。 |
| `common/src/ws.rs` | 456 | 未标注 | **控制帧载荷不得超过 125 字节**（RFC 6455 §5.5）。 | **控制帧载荷不得超过 125 字节**（RFC 6455 §5.5）。 | 未标注 | ★★ v0.5.4 修（L9）：**控制帧载荷不得超过 125 字节**（RFC 6455 §5.5）。 |
| `common/src/ws.rs` | 760 | 未标注 | 构造的帧要带**客户端掩码** —— 现在服务端视角会 | 构造的帧要带**客户端掩码** —— 现在服务端视角会 | `partial_frame_waits_for_the_rest` | ★ v0.5.5（G-7）：构造的帧要带**客户端掩码** —— 现在服务端视角会<br>按 RFC 校验掩码位，未掩码的帧已经不合规了。 |
| `common/src/ws.rs` | 779 | 未标注 | 同上，用带掩码的客户端帧。 | 同上，用带掩码的客户端帧。 | `multiple_frames_in_one_buffer` | ★ v0.5.5（G-7）：同上，用带掩码的客户端帧。 |
| `common/src/ws.rs` | 947 | 未标注 | （L9）：控制帧载荷必须 ≤125 字节（RFC 6455 §5.5）。 | （L9）：控制帧载荷必须 ≤125 字节（RFC 6455 §5.5）。 | `控制帧载荷不得超过_125` | ★★ v0.5.4 回归（L9）：控制帧载荷必须 ≤125 字节（RFC 6455 §5.5）。 |
| `server/src/admin.rs` | 66 | 未标注 | **面板路径也必须过 RBAC 的逐条代理检查**。 | **面板路径也必须过 RBAC 的逐条代理检查**。 | 未标注 | ★★ v0.5.5 修（第四轮 D-AUTH-02）：**面板路径也必须过 RBAC 的逐条代理检查**。 |
| `server/src/admin.rs` | 172 | 未标注 | **前缀必须幂等**（strip 再 add）。 | **前缀必须幂等**（strip 再 add）。 | 未标注 | ★★ v0.5.6 修（审计总报告 M5，中危）：**前缀必须幂等**（strip 再 add）。 |
| `server/src/admin.rs` | 191 | 未标注 | 同样带上归属，避免误删其它租户的同名 visitor 记录。 | 同样带上归属，避免误删其它租户的同名 visitor 记录。 | 未标注 | ★ v0.5.5（第四轮 B-1）：同样带上归属，避免误删其它租户的同名 visitor 记录。 |
| `server/src/admin.rs` | 194 | 未标注 | 带上是**哪个客户端**的代理 —— | 带上是**哪个客户端**的代理 —— | 未标注 | ★ v0.5.5（第四轮 H1）：带上是**哪个客户端**的代理 ——<br>只按名字摘会误删其它租户的同名路由。 |
| `server/src/admin.rs` | 198 | 未标注 | `proxies_active.dec()` 必须**只在本客户端 | `proxies_active.dec()` 必须**只在本客户端 | 未标注 | ★★ v0.5.6 修（审计总报告 M8，中危）：`proxies_active.dec()` 必须**只在本客户端<br>确实持有这条代理时**执行。 |
| `server/src/admin.rs` | 214 | 未标注 | 下发给客户端的是**本地名**。 | 下发给客户端的是**本地名**。 | 未标注 | ★ v0.5.8 修（第八轮审计 F8-L2，低危）：下发给客户端的是**本地名**。 |
| `server/src/admin.rs` | 547 | 未标注 | 面板传**线上全名**时， | 面板传**线上全名**时， | `面板传全名时下发给客户端的是本地名` | ★ v0.5.8（第八轮审计 F8-L2，低危）回归：面板传**线上全名**时，<br>下发给客户端的必须剥成**本地名**。 |
| `server/src/api_v2.rs` | 135 | 未标注 | 按 `detailedErrorsToClient` 决定是否脱敏。 | 按 `detailedErrorsToClient` 决定是否脱敏。 | 未标注 | 按 `detailedErrorsToClient` 决定是否脱敏（v0.5.6 修审计总报告 L13）。 |
| `server/src/api_v2.rs` | 277 | 未标注 | **走 `detailedErrorsToClient` 脱敏**。 | **走 `detailedErrorsToClient` 脱敏**。 | 未标注 | ★★ v0.5.6 修（审计总报告 L13，低危）：**走 `detailedErrorsToClient` 脱敏**。 |
| `server/src/api_v2.rs` | 414 | 未标注 | 不带过滤条件即全平台枚举 ⇒ 必须显式 ?all=1 | 不带过滤条件即全平台枚举 ⇒ 必须显式 ?all=1 | 未标注 | ★ v0.5.6（M13）：不带过滤条件即全平台枚举 ⇒ 必须显式 ?all=1 |
| `server/src/api_v2.rs` | 464 | 未标注 | **枚举门槛**：不带任何过滤条件时，必须显式写 `?all=1` | 。 | 未标注 | **枚举门槛**：不带任何过滤条件时，必须显式写 `?all=1`<br>（v0.5.6 修审计总报告 M13，中危）。 |
| `server/src/api_v2.rs` | 526 | 未标注 | 全量枚举要显式确认 | 全量枚举要显式确认 | 未标注 | ★ v0.5.6（M13）：全量枚举要显式确认 |
| `server/src/api_v2.rs` | 575 | 未标注 | 全量枚举要显式确认 | 全量枚举要显式确认 | 未标注 | ★ v0.5.6（M13）：全量枚举要显式确认 |
| `server/src/api_v2.rs` | 634 | 未标注 | 审计日志含全部租户的 run_id / user / IP ⇒ 全量枚举要显式确认 | 审计日志含全部租户的 run_id / user / IP ⇒ 全量枚举要显式确认 | 未标注 | ★ v0.5.6（M13）：审计日志含全部租户的 run_id / user / IP ⇒ 全量枚举要显式确认 |
| `server/src/api_v2.rs` | 818 | 未标注 | 全量枚举现在要显式 ?all=1 | 全量枚举现在要显式 ?all=1 | `未知路径是_404_且带错误码` | ★ v0.5.6（M13）：全量枚举现在要显式 ?all=1 |
| `server/src/api_v2.rs` | 1004 | 未标注 | 审计日志含全部租户信息，全量枚举要显式确认 | 审计日志含全部租户信息，全量枚举要显式确认 | `读接口不得默认全量枚举` | ★ v0.5.6（M13）：审计日志含全部租户信息，全量枚举要显式确认 |
| `server/src/api_v2.rs` | 1014 | 未标注 | 读接口不得默认全量枚举 | 读接口不得默认全量枚举 | `读接口不得默认全量枚举` | ------------------------------------------------------------------<br>v0.5.6 回归（审计总报告 M13）：读接口不得默认全量枚举<br>------------------------------------------------------------------ |
| `server/src/api_v2.rs` | 1101 | 未标注 | v2 错误文案必须可脱敏 | v2 错误文案必须可脱敏 | `关掉详细错误后_v2_不回显租户信息` | ------------------------------------------------------------------<br>v0.5.6 回归（审计总报告 L13）：v2 错误文案必须可脱敏<br>------------------------------------------------------------------ |
| `server/src/audit.rs` | 27 | 未标注 | 原先只有内存环形上限，文件**无上界** —— | 原先只有内存环形上限，文件**无上界** —— | 未标注 | ★ v0.5.9（第九轮 A9-3）：原先只有内存环形上限，文件**无上界** ——<br>实测 ~1000 行/s 可持续增长（约 37 MB/h），这是一条可被利用的<br>磁盘耗尽路径；有了默认上限后占用可预期。`maxFileMB = 0` 关闭轮转。 |
| `server/src/audit.rs` | 162 | 未标注 | 审计日志落盘用 0600（新建时），与 `logfile.rs` 口径一致。 | 审计日志落盘用 0600（新建时），与 `logfile.rs` 口径一致。 | 未标注 | ★ v0.5.3：审计日志落盘用 0600（新建时），与 `logfile.rs` 口径一致。 |
| `server/src/audit.rs` | 311 | 未标注 | 原先文件无上界（实测 ~1000 行/s、 | 原先文件无上界（实测 ~1000 行/s、 | 未标注 | ★ v0.5.9（第九轮 A9-3）：原先文件无上界（实测 ~1000 行/s、<br>约 37 MB/h 可持续增长），这条路径可被未认证流量利用来耗尽磁盘。<br>轮转失败不致命：改名失败就继续写原文件（下一轮再试），<br>重新打开失败则退化成"只留内存"，与写失败的处理口径一致。 |
| `server/src/audit.rs` | 660 | 未标注 | 到达阈值后**轮转** —— | 到达阈值后**轮转** —— | `到达阈值后轮转到备份文件` | ★ v0.5.9（第九轮 A9-3）新增：到达阈值后**轮转** ——<br>主文件有上界、旧内容进 `<path>.1`、新文件继续可写、备份只留一份。 |
| `server/src/dashboard.rs` | 94 | 未标注 | 读完整请求头的总超时。 | 读完整请求头的总超时。 | 未标注 | 读完整请求头的总超时（v0.5.4，L1）。 |
| `server/src/dashboard.rs` | 130 | 未标注 | **面板也要过 ACL**。 | **面板也要过 ACL**。 | 未标注 | ★★ v0.5.9 修（第九轮审计 **E9-2**，低危）：**面板也要过 ACL**。 |
| `server/src/dashboard.rs` | 246 | 未标注 | 读头阶段加**整体超时**。 | 读头阶段加**整体超时**。 | 未标注 | ★★ v0.5.4 修（L1）：读头阶段加**整体超时**。 |
| `server/src/dashboard.rs` | 347 | 未标注 | **用户名非空但密码为空 | **用户名非空但密码为空 | 未标注 | ★★ v0.5.6 修（审计总报告 H1，纵深防御）：**用户名非空但密码为空<br>一律按"没有凭据"处理**（`expected` 视为 None）⇒ 走下面的拒绝分支。 |
| `server/src/dashboard.rs` | 771 | 未标注 | 只看**头区**，body 行不得参与解析。 | 只看**头区**，body 行不得参与解析。 | 未标注 | ★ v0.5.8 修（第八轮审计 F8-L1，低危）：只看**头区**，body 行不得参与解析。 |
| `server/src/dashboard.rs` | 1159 | 未标注 | `table()` 原先**直接插值单元格**，而单元格里装着攻击者可控的字符串 —— | `table()` 原先**直接插值单元格**，而单元格里装着攻击者可控的字符串 —— | 未标注 | ★★ v0.5.6 修（审计总报告 H4，高危 · 存储型 XSS）：<br>`table()` 原先**直接插值单元格**，而单元格里装着攻击者可控的字符串 ——<br>低权限客户端注册一个名字为 `<img src=x onerror=...>` 的代理，<br>管理员一打开面板就在**管理员会话**里执行攻击者的脚本<br>⇒ 越权调用 /api/*（踢人、增删代理、开公网端口）。 |
| `server/src/dashboard.rs` | 1419 | 未标注 | **body 行不得参与头解析/鉴权**。 | **body 行不得参与头解析/鉴权**。 | `header_lookup_must_ignore_body_lines` | ★ v0.5.8（第八轮审计 F8-L1，低危）回归：**body 行不得参与头解析/鉴权**。 |
| `server/src/dashboard.rs` | 1528 | 未标注 | 面板表格必须转义单元格 | 面板表格必须转义单元格 | `面板表格必须转义单元格` | ==================================================================<br>v0.5.6 回归（审计总报告 H4）：面板表格必须转义单元格<br>================================================================== |
| `server/src/guard.rs` | 33 | 未标注 | 这里原来是裸的 `AuthProvider`（普通字段 + 外层 `Arc<SecurityContext>`）， | 这里原来是裸的 `AuthProvider`（普通字段 + 外层 `Arc<SecurityContext>`）， | 未标注 | ★ v0.5.3 修：这里原来是裸的 `AuthProvider`（普通字段 + 外层 `Arc<SecurityContext>`），<br>于是 `refresh_oidc(&self)` 拿不到 `&mut`，**拉到的 JWKS 根本没法回填** ——<br>旧代码在 `refresh_oidc` 里新建一个 verifier、拉完就让它随函数结束被 drop，<br>`self.auth` 永远是 `OidcUnavailable`。后果是配了 `method = "oidc"` 的服务端<br>**拒绝所有人登录**（fail-closed，无绕过，但功能是死的）。<br>换成 `Arc<RwLock<...>>` 之后刷新才能真正生效。 |
| `server/src/guard.rs` | 53 | 未标注 | 放在这里而不是每个调用点各传一次 —— | 放在这里而不是每个调用点各传一次 —— | 未标注 | ★ v0.5.7（第六轮审计 G-1）：放在这里而不是每个调用点各传一次 ——<br>让"校验凭证"与"查新鲜性"用**同一个**来源，调用方没有机会漏。 |
| `server/src/guard.rs` | 141 | 未标注 | 改用唯一真源 `ServerConfig:has_no_auth()`。 | 改用唯一真源 `ServerConfig:has_no_auth()`。 | 未标注 | ★ v0.5.6（审计总报告 M6）：改用唯一真源 `ServerConfig::has_no_auth()`。<br>原先这里是就地写的一套口径（`auth.method() == Token &&<br>cfg.effective_auth().token.is_empty()`），而 `main.rs` 那边用的是<br>裸的 `cfg.token.is_empty()` —— **两套口径必然漂移一处**：<br>纯 OIDC 部署会被 main.rs 误报成"没有认证，任何人都能连"。<br>本处的口径本来就是对的，收进 `has_no_auth()` 让两处共用。 |
| `server/src/guard.rs` | 172 | 未标注 | （仅含历史标记，已删除） | （仅含历史标记，已删除） | 未标注 | ★★ v0.5.3 修（这是一个真实的功能性缺陷）： |
| `server/src/guard.rs` | 229 | 未标注 | `run_id` 会把 OIDC 的 subject 绑定到本会话。 | `run_id` 会把 OIDC 的 subject 绑定到本会话。 | 未标注 | `run_id` 会把 OIDC 的 subject 绑定到本会话（v0.5.3）。 |
| `server/src/guard.rs` | 329 | 未标注 | 时间戳要用**当前时间** —— `verify_login` 现在自带 | 时间戳要用**当前时间** —— `verify_login` 现在自带 | `acl_在构造期就校验格式` | ★ v0.5.7：时间戳要用**当前时间** —— `verify_login` 现在自带<br>新鲜性校验（G-1 修复），传 0（1970）会被窗口先拦下，<br>那样就测不到"空 token 不校验凭证"这件事了。 |
| `server/src/guard.rs` | 397 | 未标注 | 用**当前时间**（原先写死 1700000000 = 2023-11-14）。 | 用**当前时间**（原先写死 1700000000 = 2023-11-14）。 | `oidc_未就绪时拒绝登录而不是放行` | ★ v0.5.7：用**当前时间**（原先写死 1700000000 = 2023-11-14）。<br>`verify_login` 现在自带新鲜性校验，写死的时间戳会被窗口拦下，<br>于是这条测试会"因为过期而失败"而不是"因为凭证对而通过"。 |
| `server/src/guard.rs` | 436 | 未标注 | 时间戳要用当前时间 —— `verify_login` 现在先判新鲜性， | 时间戳要用当前时间 —— `verify_login` 现在先判新鲜性， | `认证槽可写回_否则_oidc_永久不可用` | ★ v0.5.7：时间戳要用当前时间 —— `verify_login` 现在先判新鲜性，<br>传 0 会先撞上"时间戳超出偏差"，就测不到"OIDC 未就绪必须拒绝"了。<br>两种失败**都拒绝**（都是 fail-closed），但这条测试要盯的是后者。 |
| `server/src/guard.rs` | 451 | 未标注 | **认证槽必须可被写回** —— 这是 C 那个缺陷的锁定测试。 | **认证槽必须可被写回** —— 这是 C 那个缺陷的锁定测试。 | `认证槽可写回_否则_oidc_永久不可用` | ★★ v0.5.3 回归：**认证槽必须可被写回** —— 这是 C 那个缺陷的锁定测试。 |
| `server/src/main.rs` | 138 | 未标注 | 弱/占位 token 的强告警。 | 弱/占位 token 的强告警。 | 未标注 | ★ v0.5.3：弱/占位 token 的强告警。 |
| `server/src/main.rs` | 207 | 未标注 | **明文控制通道也要告警**。 | **明文控制通道也要告警**。 | 未标注 | ★★ v0.5.6 修（审计总报告 L4，低危）：**明文控制通道也要告警**。 |
| `server/src/main.rs` | 235 | 未标注 | **空白名单必须告警**。 | **空白名单必须告警**。 | 未标注 | ★★ v0.5.6 修（审计总报告 L3，低危）：**空白名单必须告警**。 |
| `server/src/main.rs` | 278 | 未标注 | **配了 [[roles]] 但用共享 token | **配了 [[roles]] 但用共享 token | 未标注 | ★★ v0.5.7 新增（第六轮审计 D-5，**高危**）：**配了 [[roles]] 但用共享 token<br>⇒ 整套分权可以被伪造**。 |
| `server/src/main.rs` | 310 | 未标注 | **预检必须与启动同口径**。 | **预检必须与启动同口径**。 | 未标注 | ★★ v0.5.7 修（第六轮审计 F-1，中危）：**预检必须与启动同口径**。 |
| `server/src/main.rs` | 340 | 未标注 | （仅含历史标记，已删除） | （仅含历史标记，已删除） | 未标注 | ★★ v0.5.7 新增（第六轮审计 D-5，**高危**）。 |
| `server/src/main.rs` | 382 | 未标注 | 弱 token 检测。 | 弱 token 检测。 | 未标注 | 弱 token 检测（v0.5.3）。<br>为什么值得单独做一件事：v1 的登录凭证是 `md5(token + timestamp)`，<br>抓到一条 Login 之后离线枚举一条候选只要 1 次 MD5。token 的强度<br>**完全取决于它自身的随机性**，协议层面没有补救空间<br>（PBKDF2 的 64 次迭代是官方 golib 的硬编码值）。 |
| `server/src/main.rs` | 388 | 未标注 | 更正：本注释原先写"服务端对 `timestamp` **没有新鲜性校验**"， | 更正：本注释原先写"服务端对 `timestamp` **没有新鲜性校验**"， | 未标注 | ★ v0.5.7 更正：本注释原先写"服务端对 `timestamp` **没有新鲜性校验**"，<br>那句已经**过时** —— M3（v0.5.6）给主登录加了 ±300 秒窗口，<br>G-1（v0.5.7）把它铺到了全部 6 个凭证入口。<br>但**弱 token 依然是问题**：窗口只把重放面从"永久"压到 5 分钟，<br>攻击者在窗口内抓到一条 Login 仍然能离线枚举 token<br>（枚举成本与时间窗口无关）。所以这条检测继续保留。 |
| `server/src/main.rs` | 460 | 未标注 | **另外两个 UDP 监听口也要查**。 | **另外两个 UDP 监听口也要查**。 | 未标注 | ★★ v0.5.6 修（审计总报告 L2，低危）：**另外两个 UDP 监听口也要查**。 |
| `server/src/main.rs` | 535 | 未标注 | 判据同时看**用户名与密码**。 | 判据同时看**用户名与密码**。 | 未标注 | ★★ v0.5.6 修（审计总报告 H1，高危）：判据同时看**用户名与密码**。 |
| `server/src/main.rs` | 571 | 未标注 | ---- 认证：空 token + 显式对外监听 ⇒ **拒绝启动**---- | ---- 认证：空 token + 显式对外监听 ⇒ **拒绝启动**---- | 未标注 | ---- 认证：空 token + 显式对外监听 ⇒ **拒绝启动**（v0.5.4 修 M4）---- |
| `server/src/main.rs` | 584 | 未标注 | 所以口径分三档： | 判据改用**唯一真源** `has_no_auth()`。 | 未标注 | 所以口径分三档：<br>* 绑**回环** ⇒ 合法（只有本机能连），只 warn；<br>* 绑**对外** + 用户**显式写过** `bind_addr` ⇒ 拒绝启动，<br>除非显式 `allow_insecure_no_auth = true`（知情选择）；<br>* 绑**对外** + `bind_addr` 是**默认值**（用户没写过）⇒<br>不拒绝启动（否则默认配置废掉），但给出可操作的强告警。<br>★★ v0.5.6 修（审计总报告 M6，中危）：判据改用**唯一真源** `has_no_auth()`。 |
| `server/src/main.rs` | 733 | 未标注 | `[[roles]]` + 共享 token | `[[roles]]` + 共享 token | `配了角色表又用共享token时必须告警` | ★★ v0.5.7 新增（第六轮审计 D-5，**高危**）：`[[roles]]` + 共享 token<br>⇒ 身份不可验证，必须告警。 |
| `server/src/main.rs` | 813 | 未标注 | M4：空 token + **显式**对外监听必须拒绝启动 | M4：空 token + **显式**对外监听必须拒绝启动 | `空token且显式对外监听必须拒绝启动` | ------------------------------------------------------------------<br>M4（v0.5.4）：空 token + **显式**对外监听必须拒绝启动<br>------------------------------------------------------------------ |
| `server/src/observability.rs` | 213 | 未标注 | `u64` 计数器 → Prometheus 用的 `i64`。 | `u64` 计数器 → Prometheus 用的 `i64`。 | 未标注 | `u64` 计数器 → Prometheus 用的 `i64`（v0.5.6 修审计总报告 L15，低危）。 |
| `server/src/observability.rs` | 465 | 未标注 | u64 → i64 不得回绕成负数 | u64 → i64 不得回绕成负数 | `越界计数器必须饱和不得回绕` | ------------------------------------------------------------------<br>v0.5.6 回归（审计总报告 L15）：u64 → i64 不得回绕成负数<br>------------------------------------------------------------------ |
| `server/src/p2p.rs` | 57 | 未标注 | 两个角色在**控制连接**上的源 IP。 | 两个角色在**控制连接**上的源 IP。 | 未标注 | ★ v0.5.8 修（第八轮审计 B-1，高危）：两个角色在**控制连接**上的源 IP。 |
| `server/src/p2p.rs` | 205 | 未标注 | 角色来源必须与控制连接同主机。 | 角色来源必须与控制连接同主机。 | 未标注 | ★ v0.5.8 修（第八轮审计 B-1，高危）：角色来源必须与控制连接同主机。<br>注册在会话上的 IP 来自过了 token 鉴权的 TCP 控制连接，攻击者<br>伪造不了 —— 于是"随便谁先发 HELLO 谁就是这个角色"的窗口关死。 |
| `server/src/p2p.rs` | 258 | 未标注 | 新增 `sec`，让牵线 UDP 也过 ACL。 | 新增 `sec`，让牵线 UDP 也过 ACL。 | 未标注 | ★★ v0.5.9 修（第九轮审计 **E9-1**，低危）：新增 `sec`，让牵线 UDP 也过 ACL。 |
| `server/src/p2p.rs` | 336 | 未标注 | 可能有人在冒名登记， | 可能有人在冒名登记， | 未标注 | ★ v0.5.8 修（第八轮审计 B-1）：可能有人在冒名登记，<br>也可能只是多宿主 / 双栈解析差异 —— 两种都拒绝，<br>由客户端按既有逻辑回退中继（打洞失败本来就有兜底）。 |
| `server/src/p2p.rs` | 431 | 未标注 | 把时钟窗口传进去 —— | 把时钟窗口传进去 —— | 未标注 | ★ v0.5.7（第六轮审计 G-1，高危）：把时钟窗口传进去 ——<br>新鲜性校验在 `check_sign` 内部，不是可选项。<br>原先这里只比内容不看新旧 ⇒ 嗅探到一条 `NatHoleVisitor` 即可无限期重放。 |
| `server/src/p2p.rs` | 482 | 未标注 | 把两个角色的 HELLO 来源钉在各自的 | 把两个角色的 HELLO 来源钉在各自的 | 未标注 | ★ v0.5.8 修（第八轮审计 B-1）：把两个角色的 HELLO 来源钉在各自的<br>控制连接 IP 上（控制连接过了 token 鉴权，伪造不了）。 |
| `server/src/p2p.rs` | 547 | 未标注 | 原先这里要调用方传一个**写死的** `ts` | 原先这里要调用方传一个**写死的** `ts` | 未标注 | ★ v0.5.7（第六轮审计 G-1）：原先这里要调用方传一个**写死的** `ts`<br>（1 / 123 / 456 / 9 / 11…）。`check_sign` 现在自带新鲜性校验之后，<br>那些写死的时间戳全都会**因为过期**而被拒 —— 测试会"因为时间错"而失败，<br>而不是因为它本来要测的那件事。所以默认用当前时间。 |
| `server/src/p2p.rs` | 605 | 未标注 | HELLO 的来源 IP 必须与该角色 | HELLO 的来源 IP 必须与该角色 | `hello_from_wrong_ip_is_rejected` | ★ v0.5.8（第八轮审计 B-1，高危）回归：HELLO 的来源 IP 必须与该角色<br>**控制连接**的 IP 一致。修复前牵线端口对 HELLO 零鉴权 —— 攻击者从<br>任意地址抢先登记为 provider，就能把 visitor 引到自己的地址上。 |
| `server/src/p2p.rs` | 708 | 未标注 | **过期的签名必须被拒**。 | **过期的签名必须被拒**。 | `过期的打洞签名必须被拒而新鲜的通过` | ★★ v0.5.7 新增（第六轮审计 G-1，高危）：**过期的签名必须被拒**。 |
| `server/src/pool.rs` | 61 | 未标注 | 这条空闲工作连接占的配额凭证。 | 这条空闲工作连接占的配额凭证。 | 未标注 | ★★ v0.5.8（第七轮审计 **C-2**）：这条空闲工作连接占的配额凭证。 |
| `server/src/pool.rs` | 72 | 未标注 | 新增构造入口。 | 新增构造入口。 | 未标注 | ★ v0.5.8（C-2）：新增构造入口。 |
| `server/src/pool.rs` | 304 | 未标注 | **空闲工作连接池的上限**。 | **空闲工作连接池的上限**。 | 未标注 | ★★ v0.5.8 新增（第七轮审计 **C-2**，中危）：**空闲工作连接池的上限**。 |
| `server/src/pool.rs` | 363 | 未标注 | 控制连接的**源 IP**。 | 控制连接的**源 IP**。 | 未标注 | 控制连接的**源 IP**（v0.5.5，配合 A-1 的互通安全回退）。 |
| `server/src/pool.rs` | 901 | 未标注 | **空闲池必须封顶。** | **空闲池必须封顶。** | 未标注 | ★★ v0.5.8 修（第七轮审计 **C-2**，中危）：**空闲池必须封顶。** |
| `server/src/pool.rs` | 1306 | 未标注 | **空闲工作连接池必须封顶**，否则单个合法客户端能刷爆服务端 fd。 | **空闲工作连接池必须封顶**，否则单个合法客户端能刷爆服务端 fd。 | `空闲工作连接池必须有上界` | ★★ v0.5.8 回归（第七轮审计 **C-2**，中危）：<br>**空闲工作连接池必须封顶**，否则单个合法客户端能刷爆服务端 fd。 |
| `server/src/registry.rs` | 453 | 未标注 | **错误文案统一，不再区分原因**。 | **错误文案统一，不再区分原因**。 | 未标注 | ★★ v0.5.6 修（审计总报告 L14，低危）：**错误文案统一，不再区分原因**。 |
| `server/src/registry.rs` | 482 | 未标注 | **跨租户一律拒绝**。 | **跨租户一律拒绝**。 | 未标注 | ★★ v0.5.7 修（第六轮审计 D-1，高危）：**跨租户一律拒绝**。 |
| `server/src/registry.rs` | 776 | 未标注 | （仅含历史标记，已删除） | （仅含历史标记，已删除） | 未标注 | v0.5.7 新增（第六轮审计 D-1，高危）。 |
| `server/src/registry.rs` | 1116 | 未标注 | `PortGroup` 现在带 `owner_user`， | `PortGroup` 现在带 `owner_user`， | 未标注 | ★ v0.5.7（第六轮审计 D-1）：`PortGroup` 现在带 `owner_user`，<br>跨租户共享端口会被拒 —— 测这条边界需要一个能设 `user` 的构造器。<br>注意上面的 [`client`] 传的是**空 user**，所以既有的组测试<br>（都视为同一租户）行为不变。 |
| `server/src/registry.rs` | 1369 | 未标注 | **这条兼容性仍然保留，但多了"同租户"前提**。 | **这条兼容性仍然保留，但多了"同租户"前提**。 | `same_group_with_both_keys_empty_still_joins` | ★ v0.5.7（第六轮审计 D-1）：**这条兼容性仍然保留，但多了"同租户"前提**。<br>两个成员都不写 `group_key` 时**照常成组**（本测试锁定这一点），<br>但它们必须属于**同一租户**（同 `user`）—— 跨租户见<br>[`跨租户不能靠组名寄生到别人的公网端口`]。 |
| `server/src/registry.rs` | 1393 | 未标注 | **跨租户不得靠组名寄生**。 | **跨租户不得靠组名寄生**。 | `跨租户不能靠组名寄生到别人的公网端口` | ★★ v0.5.7 新增（第六轮审计 D-1，高危）：**跨租户不得靠组名寄生**。 |
| `server/src/registry.rs` | 1502 | 未标注 | **错误文案不得泄露任何组名**。 | **错误文案不得泄露任何组名**。 | `pick_round_robins_over_group_members` | ★★ v0.5.6 修（审计总报告 L14）：**错误文案不得泄露任何组名**。 |
| `server/src/reload.rs` | 65 | 未标注 | 安全闸门：**绝不能**在热重载里把鉴权改成"无"， | 安全闸门：**绝不能**在热重载里把鉴权改成"无"， | 未标注 | ★★ 安全闸门（v0.5.3 修，v0.5.6 补 H1）：**绝不能**在热重载里把鉴权改成"无"，<br>只要面板监听在非回环地址上。 |
| `server/src/reload.rs` | 82 | 未标注 | **判据必须同时看用户名和密码**。 | **判据必须同时看用户名和密码**。 | 未标注 | ★★ v0.5.6 修（审计总报告 H1，高危）：**判据必须同时看用户名和密码**。 |
| `server/src/reload.rs` | 245 | 未标注 | 抽成公共函数是为了让「启动校验」与「热重载校验」用同一段逻辑， | **唯一判据**：这对面板凭据能不能用来鉴权。 | 未标注 | 抽成公共函数是为了让「启动校验」与「热重载校验」用同一段逻辑，<br>免得两处口径漂移 —— 早先的 bug 正是「只在启动时校验过一次」。<br>**唯一判据**：这对面板凭据能不能用来鉴权（v0.5.6 修 H1）。 |
| `server/src/reload.rs` | 275 | 未标注 | 同时看用户名与密码，不再只看用户名。 | 同时看用户名与密码，不再只看用户名。 | 未标注 | ★ v0.5.6 修（H1）：同时看用户名与密码，不再只看用户名。 |
| `server/src/reload.rs` | 281 | 未标注 | 热重载场景下的判据：**所有"不可热改"的字段都必须取运行期那份**。 | 热重载场景下的判据：**所有"不可热改"的字段都必须取运行期那份**。 | 未标注 | ★★ 热重载场景下的判据（v0.5.4 修 H1）：**所有"不可热改"的字段都必须取运行期那份**。 |
| `server/src/reload.rs` | 283 | 未标注 | 上一版这里只把 `bind_addr` 换成了 `live` 的值，却漏了 | 上一版这里只把 `bind_addr` 换成了 `live` 的值，却漏了 | 未标注 | 上一版（v0.5.3）这里只把 `bind_addr` 换成了 `live` 的值，却漏了<br>`dashboard_port` —— 于是存在一条绕过： |
| `server/src/reload.rs` | 299 | 未标注 | **`allow_insecure_dashboard` 也必须取 live**。 | **`allow_insecure_dashboard` 也必须取 live**。 | 未标注 | ★★ v0.5.6 修（审计总报告 H2，高危）：**`allow_insecure_dashboard` 也必须取 live**。 |
| `server/src/reload.rs` | 335 | 未标注 | 把"运行期实际生效的配置"和"新配置"合成一份**判据用视图**。 | 把"运行期实际生效的配置"和"新配置"合成一份**判据用视图**。 | 未标注 | 把"运行期实际生效的配置"和"新配置"合成一份**判据用视图**（v0.5.6 修 H2）。 |
| `server/src/reload.rs` | 340 | 未标注 | 为什么这么写而不是继续手工列举：手工列举漏一个字段就是一次漏洞 —— | 漏了 `dashboard_port`，补上了它却漏了 | 未标注 | ★ 为什么这么写而不是继续手工列举：手工列举漏一个字段就是一次漏洞 ——<br>v0.5.3 漏了 `dashboard_port`（第一轮的 H1），v0.5.4 补上了它却漏了<br>`allow_insecure_dashboard`（本次的 H2）。**两次都是"清单不全"**。 |
| `server/src/reload.rs` | 353 | 未标注 | 它只在启动期被读，属"需重启"，取 new 会被绕过。 | 它只在启动期被读，属"需重启"，取 new 会被绕过。 | 未标注 | ★ v0.5.6（H2）：它只在启动期被读，属"需重启"，取 new 会被绕过。 |
| `server/src/reload.rs` | 369 | 未标注 | `current` 是 `&mut Arc<ServerConfig>`：应用成功后**必须**把 | `current` 是 `&mut Arc<ServerConfig>`：应用成功后**必须**把 | 未标注 | ★ `current` 是 `&mut Arc<ServerConfig>`（v0.5.3 起）：应用成功后**必须**把<br>它换成新配置，否则会出现「清空了凭据 → 再改回来 old == new → 分支不再进入<br>→ 鉴权永远停在 None」这种**不可逆**的状态（实测复现过）。<br>旧签名是 `Arc<ServerConfig>`，等于拿一份永不更新的启动快照做 diff。 |
| `server/src/reload.rs` | 398 | 未标注 | 安全校验重跑一次。启动时那道（main.rs:validate / serve.rs 兜底） | 只在启动路径跑过，对"运行期漂移"完全无效 —— 这正是 那个 | 未标注 | ★ 安全校验重跑一次。启动时那道（main.rs::validate / serve.rs 兜底）<br>只在启动路径跑过，对"运行期漂移"完全无效 —— 这正是 v0.5.2 那个<br>高危漏洞的成因。这里对新配置**照同样口径**再判一次，不通过就整份拒绝。 |
| `server/src/reload.rs` | 402 | 未标注 | 判据里 `bind_addr` 与 `dashboard_port` 都取 `current`（运行期已生效那份）： | 。 | 未标注 | ★ 判据里 `bind_addr` 与 `dashboard_port` 都取 `current`（运行期已生效那份）：<br>两者都不可热改，新配置里那个值本次并不生效。**只换 bind_addr 是不够的** ——<br>删掉 `dashboard_port` 那一行同样能让判据误以为"面板没开"，而监听器还活着<br>（这就是 v0.5.3 漏掉的 H1 绕过点）。 |
| `server/src/reload.rs` | 480 | 未标注 | **对外地址上绝不允许通过热重载清空面板鉴权**。 | **对外地址上绝不允许通过热重载清空面板鉴权**。 | `热重载不得清空对外面板的鉴权` | ★★ v0.5.3 回归：**对外地址上绝不允许通过热重载清空面板鉴权**。 |
| `server/src/reload.rs` | 482 | 未标注 | 这是 那个高危漏洞的锁定测试。复现步骤（实测过）： | 这是 那个高危漏洞的锁定测试。复现步骤（实测过）： | `热重载不得清空对外面板的鉴权` | 这是 v0.5.2 那个高危漏洞的锁定测试。复现步骤（实测过）：<br>`bind_addr=0.0.0.0` + `dashboard_user=admin` 启动（合法）→<br>编辑配置清空用户名 → 面板变匿名可写（`/api/status` 从 401 变 200）。 |
| `server/src/reload.rs` | 513 | 未标注 | **不可逆 bug** —— 改回去必须能恢复鉴权。 | **不可逆 bug** —— 改回去必须能恢复鉴权。 | `清空后改回鉴权必须能恢复` | ★★ v0.5.3 回归：**不可逆 bug** —— 改回去必须能恢复鉴权。 |
| `server/src/reload.rs` | 605 | 未标注 | （H1）：**运行期已绑定面板，配置里删掉 `dashboard_port` 行， | （H1）：**运行期已绑定面板，配置里删掉 `dashboard_port` 行， | `已绑定面板后删掉端口行仍应被视为暴露` | ★★ v0.5.4 回归（H1）：**运行期已绑定面板，配置里删掉 `dashboard_port` 行，<br>仍然必须被视为"暴露"**。 |
| `server/src/reload.rs` | 608 | 未标注 | 这是 漏掉的绕过点，根因是拿"配置里写没写"代表"运行期有没有在监听"： | 这是 漏掉的绕过点，根因是拿"配置里写没写"代表"运行期有没有在监听"： | `已绑定面板后删掉端口行仍应被视为暴露` | 这是 v0.5.3 漏掉的绕过点，根因是拿"配置里写没写"代表"运行期有没有在监听"： |
| `server/src/reload.rs` | 709 | 未标注 | **只配用户名、不配密码 ≠ 有凭据**。 | **只配用户名、不配密码 ≠ 有凭据**。 | 未标注 | ★★ v0.5.6（审计总报告 H1）：**只配用户名、不配密码 ≠ 有凭据**。 |
| `server/src/reload.rs` | 766 | 未标注 | （仅含历史标记，已删除） | （仅含历史标记，已删除） | 未标注 | ==================================================================<br>v0.5.6 回归（审计总报告 H1 / H2） |
| `server/src/serve/bridge.rs` | 31 | 未标注 | 活跃转发连接的**计数守卫**。 | 活跃转发连接的**计数守卫**。 | 未标注 | 活跃转发连接的**计数守卫**（v0.5.6 修审计总报告 M7）。 |
| `server/src/serve/bridge.rs` | 141 | 未标注 | **配对成功这一刻**建守卫 ⇒ +1，且保证**只有一次**。 | **配对成功这一刻**建守卫 ⇒ +1，且保证**只有一次**。 | 未标注 | ★★ v0.5.6（M7）：**配对成功这一刻**建守卫 ⇒ +1，且保证**只有一次**。<br>于是 `admit_user` 与 `handle_work` 里那两处 inc 都不需要了<br>（它们分别在"用户到达"和"工作连接配对"时各加一次，导致 +2/-1）。 |
| `server/src/serve/bridge.rs` | 271 | 未标注 | 配对成功这一刻建守卫 ⇒ +1，且离开作用域必然 -1。 | 配对成功这一刻建守卫 ⇒ +1，且离开作用域必然 -1。 | 未标注 | ★★ v0.5.6（M7）：配对成功这一刻建守卫 ⇒ +1，且离开作用域必然 -1。<br>原先 `finish_conn` 只在最后一行调用，而下面 `?` 提前返回时会漏掉<br>（审计报告指出的 `:1905` / `:1913` 两处）。 |
| `server/src/serve/conn.rs` | 51 | 未标注 | **整个登录握手**的总超时。 | **整个登录握手**的总超时。 | 未标注 | **整个登录握手**的总超时（v0.5.4，M6）。 |
| `server/src/serve/conn.rs` | 327 | 未标注 | 给**整个握手**加总超时，而不只是探测阶段。 | 给**整个握手**加总超时，而不只是探测阶段。 | 未标注 | ★★ v0.5.4 修 M6：给**整个握手**加总超时，而不只是探测阶段。 |
| `server/src/serve/conn.rs` | 335 | 未标注 | 取 30s：正常客户端握手是毫秒级（本地实测 ~2ms），30s 足够覆盖 | 把登录时间戳窗口传进握手（0 = 关闭校验）。 | 未标注 | 取 30s：正常客户端握手是毫秒级（本地实测 ~2ms），30s 足够覆盖<br>高延迟链路 + OIDC 首次验签（JWKS 已在启动时预热）。超时即断开，<br>对合法用户无任何可感知影响。<br>★ v0.5.6（M3）：把登录时间戳窗口传进握手（0 = 关闭校验）。 |
| `server/src/serve/conn.rs` | 428 | 未标注 | **登录失败时重试拉 JWKS**。 | **登录失败时重试拉 JWKS**。 | 未标注 | ★★ v0.5.6 修（审计总报告 L10，低危）：**登录失败时重试拉 JWKS**。 |
| `server/src/serve/control.rs` | 68 | 未标注 | **补上上界钳制**。 | **补上上界钳制**。 | 未标注 | ★★ v0.5.6 修（审计总报告 M15，中危）：**补上上界钳制**。 |
| `server/src/serve/control.rs` | 647 | 未标注 | 之所以要兜这一层：早期判断反了 —— 以为客户端该发原始名， | 抽成 `canonical_wire_name()`，与面板管理 | 未标注 | 之所以要兜这一层：早期判断反了 —— 以为客户端该发原始名，<br>结果第三方 frps（LoliaFRP）按全名查隧道，查不到就回<br>「FRPC 配置文件错误,请检查后重试」。<br>★ v0.5.6（M5）：抽成 `canonical_wire_name()`，与面板管理<br>路径（`admin.rs`）共用 —— 原先面板那条漏了 strip，<br>于是全名会被叠成 `alice.alice.web`（端口/域名泄漏）。 |
| `server/src/serve/control.rs` | 840 | 未标注 | `proxies_active.dec()` | `proxies_active.dec()` | 未标注 | ★★ v0.5.6 修（审计总报告 M8，中危）：`proxies_active.dec()`<br>**不能无条件执行**。 |
| `server/src/serve/control.rs` | 862 | 未标注 | 同样必须带上发起方的 client —— | 同样必须带上发起方的 client —— | 未标注 | ★ v0.5.5（第四轮 B-1）：同样必须带上发起方的 client ——<br>只按名字摘会摘掉别的租户的同名 visitor 记录（跨租户 DoS）。<br>这是 H1 修复漏掉的第二处（同一根因）。 |
| `server/src/serve/control.rs` | 869 | 未标注 | 必须带上**发起方**的 client —— | 必须带上**发起方**的 client —— | 未标注 | ★ v0.5.5（第四轮 H1）：必须带上**发起方**的 client ——<br>只按名字摘会把别的租户的同名路由一起摘掉（跨租户 DoS）。 |
| `server/src/serve/control.rs` | 877 | 未标注 | `dec()` 挪到这里 —— **确实摘掉了才减**。 | `dec()` 挪到这里 —— **确实摘掉了才减**。 | 未标注 | ★ v0.5.6（M8）：`dec()` 挪到这里 —— **确实摘掉了才减**。 |
| `server/src/serve/register.rs` | 308 | 未标注 | 把安全上下文传进去，让 UDP 数据面也过 ACL。 | 把安全上下文传进去，让 UDP 数据面也过 ACL。 | 未标注 | ★ v0.5.9（第九轮审计 E9-0）：把安全上下文传进去，让 UDP 数据面也过 ACL。 |
| `server/src/serve/register.rs` | 434 | 未标注 | **数据面也要过 ACL**。 | **数据面也要过 ACL**。 | 未标注 | ★★ v0.5.8 修（第七轮审计 F7-1，中危）：**数据面也要过 ACL**。 |
| `server/src/serve/startup.rs` | 41 | 未标注 | **认证前连接失败日志的折叠器**。 | **认证前连接失败日志的折叠器**。 | 未标注 | ★★ v0.5.8（第七轮审计 A-1）：**认证前连接失败日志的折叠器**。 |
| `server/src/serve/startup.rs` | 91 | 未标注 | **预检必须与启动同口径**。 | **预检必须与启动同口径**。 | 未标注 | ★★ v0.5.7 修（第六轮审计 F-1，中危）：**预检必须与启动同口径**。 |
| `server/src/serve/startup.rs` | 429 | 未标注 | 牵线 UDP 也过 ACL（纵深防御，口径统一）。 | 牵线 UDP 也过 ACL（纵深防御，口径统一）。 | 未标注 | ★ v0.5.9（第九轮审计 E9-1）：牵线 UDP 也过 ACL（纵深防御，口径统一）。 |
| `server/src/serve/startup.rs` | 435 | 未标注 | 这是同一判定的**第五处**（审计报告漏列了它）， | 这是同一判定的**第五处**（审计报告漏列了它）， | 未标注 | ★ v0.5.6 修（审计总报告 H1）：这是同一判定的**第五处**（审计报告漏列了它），<br>原先同样只判 `dashboard_user.is_empty()`。必须用唯一真源，<br>否则"用户名非空 + 密码为空"会初始化出 `Some(("admin", ""))`，<br>而 `dashboard.rs` 会拿它去比 `"admin:"` —— 鉴权形同虚设。 |
| `server/src/serve/startup.rs` | 447 | 未标注 | 防御性兜底：`validate()` 已经在启动路径上拦过一次，但这里再挡一次 —— | 同样要判**密码**，不能只看用户名。 | 未标注 | 防御性兜底：`validate()` 已经在启动路径上拦过一次，但这里再挡一次 ——<br>`serve_with` 是所有启动方式的必经之地（包括将来新加的加载路径、<br>以及嵌进别的宿主程序时直接调它的场景）。面板无鉴权 + 非回环 =<br>匿名者可写，这条不能只靠上游校验。<br>★ v0.5.6（H1）：同样要判**密码**，不能只看用户名。 |
| `server/src/serve/startup.rs` | 492 | 未标注 | watch 持有这份快照的**所有权**（`Arc<ServerConfig>` 按值传入， | 关键点是它**内部会更新自己那份**，不再像 那样拿一份永不 | 未标注 | ★ watch 持有这份快照的**所有权**（`Arc<ServerConfig>` 按值传入，<br>由它自己 `current = Arc::new(new)` 更新），所以这里给它一份克隆。<br>关键点是它**内部会更新自己那份**，不再像 v0.5.2 那样拿一份永不<br>更新的启动快照做 diff（那会导致「改回去不生效」的不可逆状态）。 |
| `server/src/serve/startup.rs` | 679 | 未标注 | **限流这条 WARN**。 | **限流这条 WARN**。 | 未标注 | ★★ v0.5.8 修（第七轮审计 **A-1**，中危）：**限流这条 WARN**。 |
| `server/src/serve/tests.rs` | 466 | 未标注 | 活跃连接计数必须收支平衡 | 活跃连接计数必须收支平衡 | `连接守卫必须收支平衡` | ==================================================================<br>v0.5.6 回归（审计总报告 M7）：活跃连接计数必须收支平衡 |
| `server/src/serve/work.rs` | 53 | 未标注 | `conns_active.inc()` **不在这里**。 | `conns_active.inc()` **不在这里**。 | 未标注 | ★★ v0.5.6 修（审计总报告 M7）：`conns_active.inc()` **不在这里**。 |
| `server/src/serve/work.rs` | 133 | 未标注 | 工作连接必须绑定到**发起它的那个客户端**。 | 工作连接必须绑定到**发起它的那个客户端**。 | 未标注 | ★★ v0.5.5 修（第四轮 A-1，高危）：工作连接必须绑定到**发起它的那个客户端**。 |
| `server/src/serve/work.rs` | 228 | 未标注 | **改调 `verify_login`**。 | **改调 `verify_login`**。 | 未标注 | ★★ v0.5.7 修（第六轮审计 G-1，高危）：**改调 `verify_login`**。 |
| `server/src/serve/work.rs` | 270 | 未标注 | **把"可能是误拒"说清楚**。 | **把"可能是误拒"说清楚**。 | 未标注 | ★★ v0.5.6 修（审计总报告 L5，低危）：**把"可能是误拒"说清楚**。 |
| `server/src/serve/work.rs` | 315 | 未标注 | **放行分支也必须审计**。 | **放行分支也必须审计**。 | 未标注 | ★★ v0.5.6 修（审计总报告 M14，中危）：**放行分支也必须审计**。 |
| `server/src/serve/work.rs` | 359 | 未标注 | 这里**不再** inc —— 计数收敛到 `bridge` 的 | 这里**不再** inc —— 计数收敛到 `bridge` 的 | 未标注 | ★★ v0.5.6（M7）：这里**不再** inc —— 计数收敛到 `bridge` 的<br>`ConnGuard`（配对成功那一刻 +1，作用域结束 -1）。<br>原先这里与 `admit_user` 各加一次，于是 +2/-1 虚高。 |
| `server/src/serve/work.rs` | 385 | 未标注 | visitor 这条路径原来**完全没走** `detailed_errors_to_client` | visitor 这条路径原来**完全没走** `detailed_errors_to_client` | 未标注 | ★ v0.5.3 修：visitor 这条路径原来**完全没走** `detailed_errors_to_client`<br>开关，把内部细节原样回给了**尚未通过任何认证**的来访者，包括： |
| `server/src/serve/work.rs` | 428 | 未标注 | **空 `run_id` 不再被放行**。 | **空 `run_id` 不再被放行**。 | 未标注 | ★★ v0.5.7 修（第六轮审计 D-2，中危）：**空 `run_id` 不再被放行**。 |
| `server/src/serve/work.rs` | 452 | 未标注 | **这一条无论如何都只回通用文案**， | **这一条无论如何都只回通用文案**， | 未标注 | ★★ v0.5.5 修（第四轮 A-3）：**这一条无论如何都只回通用文案**，<br>不受 `detailed_errors_to_client` 影响。 |
| `server/src/serve/work.rs` | 483 | 未标注 | **两条拒绝路径共用同一条文案**。 | **两条拒绝路径共用同一条文案**。 | 未标注 | ★★ v0.5.7 修（第六轮审计 D-4，中危）：**两条拒绝路径共用同一条文案**。 |
| `server/src/serve/work.rs` | 519 | 未标注 | 把 `registry` 的时钟窗口传进去 —— | 把 `registry` 的时钟窗口传进去 —— | 未标注 | ★ v0.5.7（第六轮审计 G-1）：把 `registry` 的时钟窗口传进去 ——<br>新鲜性校验在 `check_sign` 内部，不是可选项。 |
| `server/src/serve/work.rs` | 527 | 未标注 | 文案与"代理名不存在"那条**逐字一致**， | 文案与"代理名不存在"那条**逐字一致**， | 未标注 | ★ v0.5.7（第六轮审计 D-4）：文案与"代理名不存在"那条**逐字一致**，<br>且不经过 `detailed_errors_to_client`（那个开关默认 true，<br>经过它就等于把"名字对不对"送出去）。<br>排查信息进服务端日志，不回给未认证的对端。 |
| `server/src/serve/work.rs` | 546 | 未标注 | **从上面已经取到的 `session` 直接拿**， | **从上面已经取到的 `session` 直接拿**， | 未标注 | ★★ v0.5.7 修（第六轮审计 D-2）：**从上面已经取到的 `session` 直接拿**，<br>不再 `registry.get(&msg.run_id).unwrap_or_default()`。 |
| `server/src/serve/work.rs` | 593 | 未标注 | 这里**不再** inc —— `bridge` / `spawn_sudp_bridge` | 这里**不再** inc —— `bridge` / `spawn_sudp_bridge` | 未标注 | ★★ v0.5.6（M7）：这里**不再** inc —— `bridge` / `spawn_sudp_bridge`<br>里的守卫会各自在配对成功那一刻 +1，并在离开作用域时 -1。<br>原先这里 inc + `acquire_work_conn` 失败时手工 dec，是"配对前就加、<br>失败要手工回滚"的脆弱写法。 |
| `server/src/udp_proxy.rs` | 27 | 未标注 | "最近见过的访客 IP"集合上限。 | "最近见过的访客 IP"集合上限。 | 未标注 | "最近见过的访客 IP"集合上限（v0.5.6 修审计总报告 L18）。 |
| `server/src/udp_proxy.rs` | 33 | 未标注 | "最近见过的访客 IP"集合。 | "最近见过的访客 IP"集合。 | 未标注 | "最近见过的访客 IP"集合（v0.5.6 修审计总报告 L18）。 |
| `server/src/udp_proxy.rs` | 82 | 未标注 | 新增 `sec` 参数。 | 新增 `sec` 参数。 | 未标注 | ★★ v0.5.9 修（第九轮审计 **E9-0**，中危）：新增 `sec` 参数。 |
| `server/src/udp_proxy.rs` | 86 | 未标注 | `[acl]`（IP 白/黑名单）的唯一判定入口 `SecurityContext:check_ip` | 在 里只有 **4 处**调用（控制面 / TCP 代理 / vhost / VNet）， | 未标注 | `[acl]`（IP 白/黑名单）的唯一判定入口 `SecurityContext::check_ip`<br>在 v0.5.8 里只有 **4 处**调用（控制面 / TCP 代理 / vhost / VNet），<br>**UDP 代理端口一处都没有** ⇒ 管理员用 `[acl]` 表达"只允许某些来源"时，<br>**UDP 代理完全不遵守**（静默失效）。 |
| `server/src/udp_proxy.rs` | 153 | 未标注 | 新增 `sec`，用于在**每个数据报**上做 ACL 判定。 | 新增 `sec`，用于在**每个数据报**上做 ACL 判定。 | 未标注 | ★ v0.5.9（第九轮审计 E9-0）：新增 `sec`，用于在**每个数据报**上做 ACL 判定。 |
| `server/src/udp_proxy.rs` | 172 | 未标注 | **记录"真的给我们发过包的访客 IP"**。 | **记录"真的给我们发过包的访客 IP"**。 | 未标注 | ★★ v0.5.6 修（审计总报告 L18，低危）：**记录"真的给我们发过包的访客 IP"**。 |
| `server/src/udp_proxy.rs` | 216 | 未标注 | **UDP 数据面也要过 ACL**。 | **UDP 数据面也要过 ACL**。 | 未标注 | ★★ v0.5.9 修（第九轮审计 **E9-0**，中危）：<br>**UDP 数据面也要过 ACL**。 |
| `server/src/udp_proxy.rs` | 255 | 未标注 | 越界回写只 warn 一次，之后降 debug（防日志刷屏） | 越界回写只 warn 一次，之后降 debug（防日志刷屏） | 未标注 | ★ v0.5.6（L18）：越界回写只 warn 一次，之后降 debug（防日志刷屏） |
| `server/src/udp_proxy.rs` | 266 | 未标注 | 只回写给"真的给我们发过包的访客 IP"。 | 只回写给"真的给我们发过包的访客 IP"。 | 未标注 | ★ v0.5.6（L18）：只回写给"真的给我们发过包的访客 IP"。 |
| `server/src/vhost/http.rs` | 329 | 未标注 | `get()` 只返回**第一个**同名头，而 `to_bytes()` 会把 | `get()` 只返回**第一个**同名头，而 `to_bytes()` 会把 | 未标注 | ★ v0.5.4（H2）：`get()` 只返回**第一个**同名头，而 `to_bytes()` 会把<br>`headers` 里的**所有**同名头都转发出去 —— "读一个、写两个"正是<br>CL.CL 请求走私的成因。所以这里用 `count()` 判"有没有/有几个"，<br>而不是 `get().is_some()`。 |
| `server/src/vhost/http.rs` | 345 | 未标注 | **重复的 Content-Length 一律拒绝**。 | **重复的 Content-Length 一律拒绝**。 | 未标注 | ★ v0.5.4（H2）：**重复的 Content-Length 一律拒绝**。 |
| `server/src/vhost/http.rs` | 362 | 未标注 | **只接受"唯一的 chunked"**。 | **只接受"唯一的 chunked"**。 | 未标注 | ★★ v0.5.5 修（第四轮 C 组 TE.TE 走私）：**只接受"唯一的 chunked"**。 |
| `server/src/vhost/http.rs` | 402 | 未标注 | 严格解析。原先是 `cl.trim().parse().unwrap_or(0)` | 严格解析。原先是 `cl.trim().parse().unwrap_or(0)` | 未标注 | ★ v0.5.4（H2）：严格解析。原先是 `cl.trim().parse().unwrap_or(0)`<br>—— **垃圾值静默变 0**（`Content-Length: abc` 被当成"没有请求体"，<br>而同一个头又原样转发给上游）。现在非法值一律 400。 |
| `server/src/vhost/http.rs` | 446 | 未标注 | **同名头去重**。 | **同名头去重**。 | 未标注 | ★ v0.5.4（H2 第三层，纵深防御）：**同名头去重**。 |
| `server/src/vhost/http.rs` | 550 | 未标注 | 把 `leftover` 喂回预读缓冲，**不要丢掉**。 | 把 `leftover` 喂回预读缓冲，**不要丢掉**。 | 未标注 | ★ v0.5.4 修（L3）：把 `leftover` 喂回预读缓冲，**不要丢掉**。 |
| `server/src/vhost/http.rs` | 588 | 未标注 | **响应侧的 framing 校验**。 | **响应侧的 framing 校验**。 | 未标注 | ★★ v0.5.8 修（第七轮审计 D7-2，中危）：**响应侧的 framing 校验**。 |
| `server/src/vhost/http.rs` | 613 | 未标注 | **响应侧也要剥逐跳头**。 | **响应侧也要剥逐跳头**。 | 未标注 | ★★ v0.5.4 修（L2）：**响应侧也要剥逐跳头**。 |
| `server/src/vhost/http.rs` | 635 | 未标注 | **响应侧必须用与请求侧同一套 | **响应侧必须用与请求侧同一套 | 未标注 | ★★ v0.5.8 修（第七轮审计 D7-1，高危）：**响应侧必须用与请求侧同一套<br>RFC 口径判 `Transfer-Encoding`。** |
| `server/src/vhost/http.rs` | 705 | 未标注 | 与上面 `framed` 用**同一个** | 与上面 `framed` 用**同一个** | 未标注 | ★★ v0.5.8 修（第七轮审计 D7-1，高危）：与上面 `framed` 用**同一个**<br>判定（`resp_te_chunked`），而不是再写一次 `contains("chunked")`。 |
| `server/src/vhost/http.rs` | 1623 | 未标注 | 响应侧必须用**与请求侧同一套**判定，且 `chunked, identity` 必须**不被当作 chunked**。 | 响应侧必须用**与请求侧同一套**判定，且 `chunked, identity` 必须**不被当作 chunked**。 | `响应侧_te_判定必须与请求侧同口径` | ★★ v0.5.8 回归（第七轮审计 D7-1，**高危**）：<br>响应侧必须用**与请求侧同一套**判定，且 `chunked, identity` 必须**不被当作 chunked**。 |
| `server/src/vhost/listen.rs` | 93 | 未标注 | **数据面也要过 ACL**。 | **数据面也要过 ACL**。 | 未标注 | ★★ v0.5.8 修（第七轮审计 F7-1，中危）：**数据面也要过 ACL**。 |
| `server/src/vhost/listen.rs` | 159 | 未标注 | **vhost 端口（http / https / tcpmux）必须做 IP 白/黑名单判定。** | **vhost 端口（http / https / tcpmux）必须做 IP 白/黑名单判定。** | `vhost_数据面必须过_ip_白黑名单` | ★★ v0.5.8 回归（第七轮审计 F7-1，中危）：<br>**vhost 端口（http / https / tcpmux）必须做 IP 白/黑名单判定。** |
| `server/src/vhost/router.rs` | 120 | 未标注 | **"这条路由是不是我的"必须同时比客户端身份， | **"这条路由是不是我的"必须同时比客户端身份， | 未标注 | ★★ v0.5.5 修（第四轮 H1）：**"这条路由是不是我的"必须同时比客户端身份，<br>不能只比代理名。** |
| `server/src/vhost/router.rs` | 171 | 未标注 | **跨租户一律算冲突**， | **跨租户一律算冲突**， | 未标注 | ★★ v0.5.6 修（审计总报告 M1，中危）：**跨租户一律算冲突**，<br>不许用 `route_by_http_user` 逃逸归属判定。 |
| `server/src/vhost/router.rs` | 214 | 未标注 | **文案不再回显占用者的代理名**。 | **文案不再回显占用者的代理名**。 | 未标注 | ★★ v0.5.7 修（第六轮审计 D-3，低危）：**文案不再回显占用者的代理名**。 |
| `server/src/vhost/router.rs` | 261 | 未标注 | 本函数原先也**只比名字**， | 本函数原先也**只比名字**， | 未标注 | ★★ v0.5.5 修（第四轮 H1，同一根因的第二个面）：本函数原先也**只比名字**，<br>于是客户端 A 对 `"victim.web"` 调一次 `CloseProxy`，就能把**受害者 B**<br>的路由一起摘掉 —— 一次不需要任何权限的拒绝服务（B 的隧道在自己的客户端<br>还活着的情况下对外静默失效）。现在必须带客户端身份。 |
| `server/src/vhost/router.rs` | 546 | 未标注 | 这些路由必须来自**同一个客户端** —— | 这些路由必须来自**同一个客户端** —— | `route_by_http_user_filters_candidates` | ★ v0.5.6（审计总报告 M1）：这些路由必须来自**同一个客户端** ——<br>跨租户的"多作用域"现在一律算冲突（服务端无法分辨合法的多作用域<br>与寄生劫持，而后者能直接收割凭据）。原先用 `route()` 辅助函数<br>逐个新建客户端，恰好把"跨租户"这个语义喂了进去。 |
| `server/src/vhost/router.rs` | 584 | 未标注 | **跨租户**不得靠 `route_by_http_user` | **跨租户**不得靠 `route_by_http_user` | `跨租户不得靠_route_by_http_user_寄生` | ★★ v0.5.6 回归（审计总报告 M1）：**跨租户**不得靠 `route_by_http_user`<br>在同一个域名 + 路径上寄生。 |
| `server/src/vhost/router.rs` | 606 | 未标注 | 文案改为"已被占用"，**不再回显占用者**。 | 文案改为"已被占用"，**不再回显占用者**。 | `跨租户同作用域必须冲突` | ★ v0.5.7（第六轮审计 D-3）：文案改为"已被占用"，**不再回显占用者**。<br>同时断言它**不泄露**别人的代理名。 |
| `server/src/vhost/router.rs` | 681 | 未标注 | 这个用例现在必须显式用**同一个** client —— | 这个用例现在必须显式用**同一个** client —— | `same_proxy_reregistration_replaces_old_route` | ★ v0.5.5（第四轮 H1）：这个用例现在必须显式用**同一个** client ——<br>原先 `route()` 每次都新建 Arc，两个路由其实属于不同租户，<br>恰好因为修复前的代码"只比名字"才通过。修复后它正确地判成了冲突，<br>于是这条测试暴露了自己在无意中依赖了那个 bug（见下面的 H1 用例）。 |
| `server/src/vhost/router.rs` | 728 | 未标注 | 文案改为"已被占用"，**不再回显占用者**。 | 文案改为"已被占用"，**不再回显占用者**。 | `跨租户不得靠关代理摘掉别人的域名路由` | ★ v0.5.7（第六轮审计 D-3）：文案改为"已被占用"，**不再回显占用者**。 |
| `server/src/vhost/tcpmux.rs` | 144 | 未标注 | 常量时间比较。 | 常量时间比较。 | 未标注 | ★ 常量时间比较（v0.5.3 修）。 |
| `server/src/vhost/tcpmux.rs` | 260 | 未标注 | 三条路由必须同属**一个客户端** —— | 三条路由必须同属**一个客户端** —— | `tcpmux_兜底路由不能盖掉精确用户名路由` | ★ v0.5.6（审计总报告 M1）：三条路由必须同属**一个客户端** ——<br>跨租户的多作用域现在一律算冲突（服务端分辨不出合法多作用域与寄生劫持）。 |
| `server/src/vhost/tests.rs` | 16 | 未标注 | **`[acl]` 必须铺满所有数据面入口。** | **`[acl]` 必须铺满所有数据面入口。** | 未标注 | ★★ v0.5.9 回归（第九轮审计 **E9-0 / E9-1 / E9-2**）：<br>**`[acl]` 必须铺满所有数据面入口。** |
| `server/src/vhost/tests.rs` | 38 | 未标注 | 里 `SecurityContext:check_ip` 只有 **4 处**调用 | 里 `SecurityContext:check_ip` 只有 **4 处**调用 | `acl_必须铺满全部数据面入口` | v0.5.8 里 `SecurityContext::check_ip` 只有 **4 处**调用<br>（控制面 / TCP 代理 / vhost / VNet），而下面三条路径**一处都没有**： |
| `server/src/visitor.rs` | 34 | 未标注 | **`skew` 是必需参数， | **`skew` 是必需参数， | 未标注 | ★★ v0.5.7 修（第六轮审计 G-1，高危）：**`skew` 是必需参数，<br>新鲜性校验就嵌在函数体里**。 |
| `server/src/visitor.rs` | 72 | 未标注 | **空串显式判 false**（纵深防御）。 | **空串显式判 false**（纵深防御）。 | 未标注 | ★★ v0.5.7 修（第六轮审计 D-2，中危）：**空串显式判 false**（纵深防御）。 |
| `server/src/visitor.rs` | 151 | 未标注 | **必须同时比客户端身份，不能只比名字**。 | **必须同时比客户端身份，不能只比名字**。 | 未标注 | ★★ v0.5.5 修（第四轮 B-1）：**必须同时比客户端身份，不能只比名字**。 |
| `server/src/visitor.rs` | 225 | 未标注 | **空串身份不是"匹配任意"**。 | **空串身份不是"匹配任意"**。 | `空身份不能匹配星号白名单` | ★★ v0.5.7 新增（第六轮审计 D-2，中危）：**空串身份不是"匹配任意"**。 |
| `server/src/vnet.rs` | 59 | 未标注 | **VirtualNet 的会话键**。 | **VirtualNet 的会话键**。 | 未标注 | ★★ v0.5.8 新增（第七轮审计 **C-1**）：**VirtualNet 的会话键**。 |
| `server/src/vnet.rs` | 137 | 未标注 | 统计：**源地址不属于发送者**而被丢弃的包。 | 统计：**源地址不属于发送者**而被丢弃的包。 | 未标注 | 统计：**源地址不属于发送者**而被丢弃的包（v0.5.5，第四轮 F4）。 |
| `server/src/vnet.rs` | 230 | 未标注 | `client` 参数是 [`SessionKey`] 而不是 `&str` —— | `client` 参数是 [`SessionKey`] 而不是 `&str` —— | 未标注 | ★ v0.5.8（C-1）：`client` 参数是 [`SessionKey`] 而不是 `&str` ——<br>加入、路由、离开三处**必须用同一个键**，用类型把它锁住。 |
| `server/src/vnet.rs` | 322 | 未标注 | **必须校验源地址**。 | **必须校验源地址**。 | 未标注 | ★★ v0.5.5 修（第四轮 F4）：**必须校验源地址**。 |
| `server/src/vnet.rs` | 334 | 未标注 | 参数改成 [`SessionKey`]， | 参数改成 [`SessionKey`]， | 未标注 | ★★ v0.5.8 修（第七轮审计 **C-1**）：参数改成 [`SessionKey`]，<br>**从类型上杜绝**"把显示名传进来"。 |
| `server/src/vnet.rs` | 551 | 未标注 | 这里把 OIDC 的 subject 绑定到 `reg.client`（VirtualNet 的会话标识）， | 这里把 OIDC 的 subject 绑定到 `reg.client`（VirtualNet 的会话标识）， | 未标注 | ★ v0.5.3：这里把 OIDC 的 subject 绑定到 `reg.client`（VirtualNet 的会话标识），<br>与普通控制连接绑定到 run_id 是同一个道理 —— 不能让"曾在别处登录过的<br>subject"给本次注册背书。 |
| `server/src/vnet.rs` | 584 | 未标注 | **身份键不再用客户端自报的字符串**。 | **身份键不再用客户端自报的字符串**。 | 未标注 | ★★ v0.5.6 修（审计总报告 L12，低危）：**身份键不再用客户端自报的字符串**。 |
| `server/src/vnet.rs` | 613 | 未标注 | 兼容性：`reg.client` 仍然照原样用于**日志与审计**， | 改用 [`SessionKey`] 类型。 | 未标注 | ★ 兼容性：`reg.client` 仍然照原样用于**日志与审计**，<br>客户端侧看不到任何变化（响应里从来不含这个键）。<br>代价是"同名重连时自动顶掉旧连接"这个便利没了 ——<br>但那正是漏洞本身，去掉是对的；旧连接会由 `JoinGuard` / 读写超时回收。<br>★ 会话键用项目自己的随机 ID 生成器（`OsRng` 支撑，16 字节十六进制）。<br>不引新依赖 —— `util::new_run_id()` 就是为这类场景写的。<br>★★ v0.5.8（第七轮审计 C-1）：改用 [`SessionKey`] 类型。<br>以前是裸 `String`，于是转发路径**误传了显示名**而编译器毫无反应<br>⇒ 每个包都被判成冒充。现在两者是不同类型，传错**编译不过**。 |
| `server/src/vnet.rs` | 695 | 未标注 | 这里原先传的是 | 这里原先传的是 | 未标注 | ★★ v0.5.8 修（第七轮审计 **C-1**）：这里原先传的是<br>`&reg.client`（**显示名**），而身份建立时用的是<br>`session_key`（`"{client}-{run_id}"`，见上面 `:510`）。 |
| `server/src/vnet.rs` | 748 | 未标注 | 持有的必须是 [`SessionKey`]（而不是裸 `String`）—— | 持有的必须是 [`SessionKey`]（而不是裸 `String`）—— | 未标注 | ★ v0.5.8（C-1）：持有的必须是 [`SessionKey`]（而不是裸 `String`）——<br>这样 `hub.leave()` 才能编译通过，同时保证**离开用的键与加入用的键同源**。 |
| `server/src/vnet.rs` | 808 | 未标注 | 测试里构造会话键。 | 测试里构造会话键。 | 未标注 | ★ v0.5.8（C-1）：测试里构造会话键。 |
| `server/src/vnet.rs` | 883 | 未标注 | 发送者必须是一个**真的注册过、且拥有该源地址** | 发送者必须是一个**真的注册过、且拥有该源地址** | `点对点转发` | ★ v0.5.5（第四轮 F4）：发送者必须是一个**真的注册过、且拥有该源地址**<br>的客户端 —— 源地址校验上线后，原来那个虚构的 `"someone"` 会被<br>正确地拒掉（它不拥有 `100.64.0.200`）。这里改成让 s 真加入。 |
| `server/src/vnet.rs` | 1061 | 未标注 | 身份键不得用客户端自报字符串 | 身份键不得用客户端自报字符串 | `同名会话必须是独立身份` | ------------------------------------------------------------------<br>v0.5.6 回归（审计总报告 L12）：身份键不得用客户端自报字符串<br>------------------------------------------------------------------ |
| `server/src/vnet.rs` | 1102 | 未标注 | **转发路径传的身份键必须与建立时一致（会话键），否则一切包都被判成冒充。** | **转发路径传的身份键必须与建立时一致（会话键），否则一切包都被判成冒充。** | `转发必须用会话键而不是显示名` | ★★ v0.5.8 回归（第七轮审计 **C-1**，中危）：<br>**转发路径传的身份键必须与建立时一致（会话键），否则一切包都被判成冒充。** |

## v0.3.x

| 文件 | 行号 | 日期 | 问题 | 结论（代码保留的技术说明） | 回归测试 | 原文摘录 |
|---|---|---|---|---|---|---|
| `common/src/config/client.rs` | 445 | 未标注 | 原分节标题：`以下为 v0.3.4 新增`（只有版本标记，无技术内容）。 | 分节标题改为 `================= 扩展配置 =================`。 | 未标注 | ================= 以下为 v0.3.4 新增 =================<br>同样全部默认关闭，老的 client.toml 行为不变。<br>认证配置（`[auth]`）：`method = "token" \| "oidc"` + `auth.oidc.*`。 |
| `common/src/config/server.rs` | 655 | 未标注 | 原分节标题：`以下为 v0.3.4 新增`（只有版本标记，无技术内容）。 | 分节标题改为 `================= 扩展配置 =================`。 | 未标注 | ================= 以下为 v0.3.4 新增 =================<br>全部 `#[serde(default)]`，且默认值都等价于"不启用"——<br>老的 server.toml 一个字节都不用改就能继续跑。<br>认证配置（`[auth]`）：`method = "token" \| "oidc"` + `auth.oidc.*`。 |

## 未标注版本

| 文件 | 行号 | 日期 | 问题 | 结论（代码保留的技术说明） | 回归测试 | 原文摘录 |
|---|---|---|---|---|---|---|
| `Cargo.toml` | 161 | 未标注 | 关于 `panic = "abort"`（审计总报告 L17，低危）——评估后有意保留。 | 保留 abort：单个任务 panic 会终止整个进程，但比 unwind 省约 50% 体积；这是有意的产品取舍。 | 未标注 | ★★ 关于 `panic = "abort"`（审计总报告 L17，低危）——**评估后有意保留**<br>\| 策略 \| nfrp-server \| nfrp-client \| 单个任务 panic 时 \|<br>\|---\|---\|---\|---\|<br>\| `abort`（本版采用） \| 3,780,096 B \| 3,845,632 B \| **整个进程终止** \|<br>\| `unwind`（默认） \| 5,637,632 B \| 5,792,256 B \| 只有那条连接死 \|<br>⇒ 换用 `unwind` 的代价是 **+49.1% / +50.6% 体积**。<br>怎么翻转：删掉 `panic = "abort"` 即可（默认就是 unwind）；若能找到可远程触发的 panic 路径，应立刻删掉并补回归测试。 |
| `client/src/commands.rs` | 207 | 未标注 | ⇒ 这是**有意的行为收紧**，测试数据跟上被测行为是正确的处置 | （与第六轮"冒烟脚本过时"同一处理原则：先分清是设计变更还是回归， | 未标注 | ⇒ 这是**有意的行为收紧**，测试数据跟上被测行为是正确的处置<br>（与第六轮"冒烟脚本过时"同一处理原则：先分清是设计变更还是回归，<br>确认是前者后再更新测试工件）。 |
| `client/src/commands.rs` | 385 | 未标注 | 插件路径绕过 H4（远程下发开放代理） | 插件路径绕过 H4（远程下发开放代理） | `远程下发不得携带插件字段` | ------------------------------------------------------------------<br>第四轮 F1：插件路径绕过 H4（远程下发开放代理）<br>------------------------------------------------------------------ |
| `client/src/commands.rs` | 391 | 未标注 | 这是第四轮实弹打出来的高危（`tmp/audit4-verify-F1b.py`）： | 这是第四轮实弹打出来的高危（`tmp/audit4-verify-F1b.py`）： | `远程下发不得携带插件字段` | 这是第四轮实弹打出来的高危（`tmp/audit4-verify-F1b.py`）： |
| `client/src/dial.rs` | 57 | 未标注 | 带 `dialServerTimeout` / `connectServerLocalIP` 的拨号。 | 带 `dialServerTimeout` / `connectServerLocalIP` 的拨号。 | 未标注 | 带 `dialServerTimeout` / `connectServerLocalIP` 的拨号（限制①批次1）。 |
| `client/src/dial.rs` | 102 | 未标注 | TCP keepalive：官方挂在拨号器 | TCP keepalive：官方挂在拨号器 | 未标注 | TCP keepalive（限制①批次2，官方 `dialServerKeepalive`）：官方挂在拨号器<br>（`libnet.WithKeepAlive`）上，控制连接与每条新拨的工作连接都过这里，<br>所以放在 `dial_server` 出口处一次覆盖。`0` = 不打开（项目约定）。 |
| `client/src/dial.rs` | 342 | 未标注 | `dialServerKeepalive > 0` 时拨号成功返回的 socket 必须真的 | `dialServerKeepalive > 0` 时拨号成功返回的 socket 必须真的 | `dial_server_按配置开_keepalive` | 限制①批次2：`dialServerKeepalive > 0` 时拨号成功返回的 socket 必须真的<br>开上 TCP keepalive；`0` 时保持内核默认（不开）。 |
| `client/src/dial.rs` | 400 | 未标注 | `connectServerLocalIP` 的解析：`IP`、`IP:端口`、带方括号的 IPv6 都要认， | 垃圾输入要明确报错。 | `connect_server_local_ip_解析` | `connectServerLocalIP` 的解析：`IP`、`IP:端口`、带方括号的 IPv6 都要认，<br>垃圾输入要明确报错（限制①批次1）。 |
| `client/src/link.rs` | 123 | 未标注 | yamux 保活： | yamux 保活： | 未标注 | yamux 保活（限制①批次2，官方 `tcpMuxKeepaliveInterval`）：<br>0 = 关闭看门狗（None），默认 30 秒。 |
| `client/src/plugin.rs` | 258 | 未标注 | 这与审计总报告 M4（INI 段名/键名大小写）属**同一类** | 这与审计总报告 M4（INI 段名/键名大小写）属**同一类** | 未标注 | ★ 这与审计总报告 M4（INI 段名/键名大小写）属**同一类**<br>"大小写处理不一致"：一个把该敏感的弄成不敏感，<br>一个把该保留原样的弄成了小写。 |
| `client/src/plugin_bridge.rs` | 224 | 未标注 | 历史：第十五轮实测同一测试在 Linux 上 10 次跑出 **5 通过 / 5 次超时**， | 历史：第十五轮实测同一测试在 Linux 上 10 次跑出 **5 通过 / 5 次超时**， | 未标注 | 历史：第十五轮实测同一测试在 Linux 上 10 次跑出 **5 通过 / 5 次超时**，<br>超时表现为"插件收到连接却从未把请求转给上游"。根因是 `watch_closed`<br>用 `read(&mut chunk)` 读进局部数组，被 `select!` 取消时那批字节消失，<br>丢的正是请求体开头。 |
| `client/src/plugin_bridge.rs` | 536 | 未标注 | `X-Real-IP` / `X-Client-IP` / `X-Originating-IP` / `X-Remote-IP` / | 已经因为"修得过头把合法的也拒了"返工过一次，不再犯。 | 未标注 | `X-Real-IP` / `X-Client-IP` / `X-Originating-IP` / `X-Remote-IP` /<br>`X-Remote-Addr` / `True-Client-IP` / `CF-Connecting-IP` / `X-ProxyUser-Ip`<br>—— 这 8 个**官方也不删**（它们不在 Go 的那份清单里）。<br>删它们会**偏离官方语义**：用户的后端/中间件可能正依赖这些头，<br>而官方 frp 会把它们透传过去。**那是"修得过头"** ——<br>第四轮已经因为"修得过头把合法的也拒了"返工过一次，不再犯。 |
| `client/src/plugin_bridge.rs` | 838 | 未标注 | `X-Real-IP` / `X-Client-IP` / `CF-Connecting-IP` 等 8 个"客户端 IP 类"头 | 已经因为"修得过头把合法的也拒了"返工过一次。 | `http2http_要删掉官方清单里的全部四个头` | `X-Real-IP` / `X-Client-IP` / `CF-Connecting-IP` 等 8 个"客户端 IP 类"头<br>**官方也不删**（不在那份清单里）。删它们会偏离官方语义、<br>破坏依赖这些头的后端 —— 那是"**修得过头**"，<br>第四轮已经因为"修得过头把合法的也拒了"返工过一次。 |
| `client/src/registry.rs` | 249 | 未标注 | /F3：远程下发不得动配置里的代理 | /F3：远程下发不得动配置里的代理 | `远程删除不得动配置里的代理` | ------------------------------------------------------------------<br>第四轮 F2/F3：远程下发不得动配置里的代理<br>------------------------------------------------------------------ |
| `client/src/store.rs` | 107 | 未标注 | 有人在 store 里写入 | 。 | 未标注 | 有人在 store 里写入<br>{"plugin":"static_file","plugin_local_path":"/etc"}<br>重启后**直接生效** ⇒ 任意文件读取，<br>而且绕过了为拦截它专门写的那道 `validate_remote_proxy`<br>（威胁模型与第一轮修复 #2 完全相同，只是换了扇门进来）。 |
| `client/src/store.rs` | 476 | 未标注 | 威胁模型：store 文件的用途是持久化"服务端面板增删过的代理"， | 重启后直接生效 ⇒ 任意文件读取，且绕过了第一轮专门为此写的闸门。 | `store_里的危险字段必须在恢复时被拦下` | 威胁模型：store 文件的用途是持久化"服务端面板增删过的代理"，<br>所以它的内容与服务端下发的 ServerCmd 属于**同一信任级别**。<br>早先这里只查 `name` 非空，于是一份写着<br>`{"plugin":"static_file","plugin_local_path":"/etc"}` 的 store 文件<br>重启后直接生效 ⇒ 任意文件读取，且绕过了第一轮专门为此写的闸门。 |
| `client/src/tests.rs` | 37 | 未标注 | 注解要随 NewProxy 透传（官方 `m.Annotations = c.Annotations`） | 注解要随 NewProxy 透传（官方 `m.Annotations = c.Annotations`） | 未标注 | 限制①批次1：注解要随 NewProxy 透传（官方 `m.Annotations = c.Annotations`） |
| `client/src/tests.rs` | 352 | 未标注 | 注解必须跟着走（服务端只存不查，但报文要逐字段对齐官方） | 注解必须跟着走（服务端只存不查，但报文要逐字段对齐官方） | 未标注 | 限制①批次1：注解必须跟着走（服务端只存不查，但报文要逐字段对齐官方） |
| `common/src/config/server.rs` | 943 | 未标注 | ⇒ `dashboard_user = " admin "` 的部署**不能**用 `admin` 登录，必须发 | 字面量 `" admin "`。原先这里的注释写成 | 未标注 | ⇒ `dashboard_user = " admin "` 的部署**不能**用 `admin` 登录，必须发<br>字面量 `" admin "`（第八轮审计 F8-L3 实测确认）。原先这里的注释写成<br>"用户名惯例允许两侧空白"，与实现不符，会给排障指错方向。 |
| `common/src/config/tests.rs` | 674 | 未标注 | 远程下发的回环白名单不得接受 `localhost` | 远程下发的回环白名单不得接受 `localhost` | 未标注 | -----------------------------------------------------------------------<br>第七轮审计 E-1：远程下发的回环白名单不得接受 `localhost`<br>----------------------------------------------------------------------- |
| `common/src/config/tests.rs` | 695 | 未标注 | 1. **`localhost` 必须被拒**（核心）； | —— 不能"修得过头把合法的也拒了"； | `远程下发不得接受_localhost_作回环地址` | 1. **`localhost` 必须被拒**（核心）；<br>2. **明确的回环写法必须仍然放行**（`127.0.0.1` / `::1` / `127.x.x.x`）<br>—— 不能"修得过头把合法的也拒了"（第四轮犯过这个错）；<br>3. **非回环必须仍然被拒**（H4 的原有意图不能丢）。 |
| `common/src/config/tests.rs` | 779 | 未标注 | （附带发现）：远程下发不得接受空 `local_addr`（假绿灯） | （附带发现）：远程下发不得接受空 `local_addr`（假绿灯） | 未标注 | -----------------------------------------------------------------------<br>第七轮审计 E7（附带发现）：远程下发不得接受空 `local_addr`（假绿灯）<br>----------------------------------------------------------------------- |
| `common/src/config/tests.rs` | 800 | 未标注 | 用**诱饵服务**做过决定性判定（`tmp/audit7/e/e71_verify_bypass.py`）： | 与第六轮 F-1（`--check`/`verify` 假绿灯）同族，只是发生在**运行期**。 | `远程下发不得接受空_local_addr` | ★ 用**诱饵服务**做过决定性判定（`tmp/audit7/e/e71_verify_bypass.py`）：<br>两段式字段确实被丢弃、**没有**去连 `10.0.0.5`<br>⇒ 这**不是 SSRF**，只是"面板说成功、实际不可用"的**假绿灯**。<br>与第六轮 F-1（`--check`/`verify` 假绿灯）同族，只是发生在**运行期**。 |
| `common/src/config/tests.rs` | 868 | 未标注 | `tlsEnable` 驼峰写法必须生效 | `tlsEnable` 驼峰写法必须生效 | 未标注 | -----------------------------------------------------------------------<br>第七轮审计 B-2：`tlsEnable` 驼峰写法必须生效<br>----------------------------------------------------------------------- |
| `common/src/config/tests.rs` | 948 | 未标注 | `tlsEnable` 驼峰写法必须生效 | `tlsEnable` 驼峰写法必须生效 | 未标注 | -----------------------------------------------------------------------<br>第七轮审计 B-2：`tlsEnable` 驼峰写法必须生效<br>----------------------------------------------------------------------- |
| `common/src/config/validate.rs` | 192 | 未标注 | 这是上面那条回环检查的**完整绕过**，而且是第四轮实测打出来的： | 这是上面那条回环检查的**完整绕过**，而且是第四轮实测打出来的： | 未标注 | 这是上面那条回环检查的**完整绕过**，而且是第四轮实测打出来的： |
| `common/src/config/validate.rs` | 291 | 未标注 | 与第六轮 F-1 的「`--check` / `frpc verify` 假绿灯」是**同一族问题**， | 与第六轮 F-1 的「`--check` / `frpc verify` 假绿灯」是**同一族问题**， | 未标注 | ★ 与第六轮 F-1 的「`--check` / `frpc verify` 假绿灯」是**同一族问题**，<br>只是这次发生在**运行期**（面板写接口返回成功）而不是预检期。 |
| `common/src/frp/msg.rs` | 169 | 未标注 | 为什么需要这个能力位：工作连接原先只凭 `run_id` 接入 | 为什么需要这个能力位：工作连接原先只凭 `run_id` 接入 | 未标注 | 为什么需要这个能力位（第四轮 A-1）：工作连接原先只凭 `run_id` 接入<br>（`run_id` 还是明文 `LoginResp` 下发的），于是拿到它的人可以往<br>受害者的空闲工作连接池里灌自己的连接 ⇒ 用户流量被中继到攻击者（MITM）。 |
| `common/src/frp/mux.rs` | 53 | 未标注 | **没有任何活跃流**的会话在此期限后被关闭。 | **没有任何活跃流**的会话在此期限后被关闭。 | 未标注 | **没有任何活跃流**的会话在此期限后被关闭（第九轮 C9-4/C9-3 修复）。 |
| `common/src/frp/mux.rs` | 57 | 未标注 | yamux 会话本身没有任何时间上界：crate 不设 keepalive，frp 侧原先也没设。 | 握手超时的流（12 字节），会话就能被**无限期**挂住 —— 第九轮实测量化： | 未标注 | yamux 会话本身没有任何时间上界：crate 不设 keepalive，frp 侧原先也没设。<br>攻击者只发一个 `0x00`（让服务端建立会话）后静默，或只开一条注定<br>握手超时的流（12 字节），会话就能被**无限期**挂住 —— 第九轮实测量化：<br>① 只发 0x00 的连接 50s 后仍存活，500 条可线性囤积（+515 句柄 / +6.4MB）；<br>② 未认证开流 ≈9.5 KiB/条、单会话上限 512 条、跨会话无全局上限，<br>攻击者 129 KB 流量 + 22 个 fd 就能把服务端内存抬 +100 MB。 |
| `common/src/frp/mux.rs` | 72 | 未标注 | yamux 会话保活参数。 | yamux 会话保活参数。 | 未标注 | yamux 会话保活参数（限制①批次2，对应 frp `tcpMuxKeepaliveInterval`）。 |
| `common/src/frp/mux.rs` | 254 | 未标注 | 保活看门狗：静默超过判定线 = 会话已死。 | 保活看门狗：静默超过判定线 = 会话已死。 | 未标注 | 保活看门狗（限制①批次2）：静默超过判定线 = 会话已死。 |
| `common/src/frp/mux.rs` | 415 | 未标注 | 保活看门狗：静默超过判定线 = 会话已死。 | 保活看门狗：静默超过判定线 = 会话已死。 | 未标注 | 保活看门狗（限制①批次2）：静默超过判定线 = 会话已死。 |
| `common/src/frp/mux.rs` | 527 | 未标注 | 保活看门狗：对端"TCP 活着但一声不吭"超过判定线， | 保活看门狗：对端"TCP 活着但一声不吭"超过判定线， | `保活看门狗关闭静默会话` | 保活看门狗（限制①批次2）：对端"TCP 活着但一声不吭"超过判定线，<br>会话必须被关闭（accept 返回 None），且不能一上来就杀。 |
| `common/src/frp/tls.rs` | 35 | 未标注 | TLS 握手阶段的总超时。 | TLS 握手阶段的总超时。 | 未标注 | TLS 握手阶段的总超时（第九轮 C9-4 修复）。 |
| `common/src/frp/tls.rs` | 37 | 未标注 | 原先 `accept_server` 对 rustls 握手**没有任何时限**：只发一个 `0x16` | 实测（`tmp/audit9/c/c9_4_timeouts_tls.py`）：50s 后仍被挂住， | 未标注 | 原先 `accept_server` 对 rustls 握手**没有任何时限**：只发一个 `0x16`<br>（或 `0x17`）字节后静默，`TlsAcceptor::accept` 会永远等下去 ——<br>第九轮实测（`tmp/audit9/c/c9_4_timeouts_tls.py`）：50s 后仍被挂住，<br>且可线性囤积（500 条连接 +515 句柄 / +6.4MB，无一被清理）。<br>rustls 自己不做握手超时（协议层允许任意慢的来包），必须在调用侧加。 |
| `common/src/frp_config.rs` | 538 | 未标注 | 连接服务端的超时 / 本机出口绑定（语义对齐官方 | 连接服务端的超时 / 本机出口绑定（语义对齐官方 | 未标注 | 连接服务端的超时 / 本机出口绑定（限制①批次1 实现，语义对齐官方<br>`connector.go`：仅走 TCP 拨号路径，KCP 不适用）。 |
| `common/src/frp_config.rs` | 542 | 未标注 | TCP keepalive / yamux 保活（官方同名键， | TCP keepalive / yamux 保活（官方同名键， | 未标注 | TCP keepalive / yamux 保活（限制①批次2 实现，官方同名键，<br>语义与落法见 config.rs 对应字段的文档）。 |
| `common/src/frp_config.rs` | 562 | 未标注 | mTLS / 自定义证书。官方把这几项放在 | mTLS / 自定义证书。官方把这几项放在 | 未标注 | 限制①批次3：mTLS / 自定义证书。官方把这几项放在<br>`[transport.tls]`，NFrp 结构体是平铺字段，必须 hoist 才生效。<br>目标键保持官方 camelCase —— 结构体字段带 `rename`，serde 认的是它。 |
| `common/src/frp_config.rs` | 685 | 未标注 | 数据面监听地址与"等用户连接配工作连接"的超时（官方顶层键）。 | 数据面监听地址与"等用户连接配工作连接"的超时（官方顶层键）。 | 未标注 | 限制①批次1：数据面监听地址与"等用户连接配工作连接"的超时（官方顶层键）。 |
| `common/src/frp_config.rs` | 727 | 未标注 | 空闲工作连接池上限。 | 空闲工作连接池上限。 | 未标注 | 空闲工作连接池上限（限制①批次1 实现；官方默认 5，nfrp 默认 0 = 不限）。 |
| `common/src/frp_config.rs` | 729 | 未标注 | yamux 保活间隔 + 主端口 TCP keepalive。 | yamux 保活间隔 + 主端口 TCP keepalive。 | 未标注 | yamux 保活间隔 + 主端口 TCP keepalive（限制①批次2 实现）。 |
| `common/src/frp_config.rs` | 739 | 未标注 | 服务端自定义证书 + mTLS。 | 服务端自定义证书 + mTLS。 | 未标注 | 限制①批次3：服务端自定义证书 + mTLS。 |
| `common/src/frp_config.rs` | 1540 | 未标注 | 这批客户端字段已实现 —— 既不能再被报"未实现"， | 这批客户端字段已实现 —— 既不能再被报"未实现"， | `批次1客户端字段读到值且不再报未实现` | 限制①批次1：这批客户端字段已实现 —— 既不能再被报"未实现"，<br>值也要真的落到配置里（含官方 camelCase 写法）。 |
| `common/src/frp_config.rs` | 1600 | 未标注 | 服务端四个字段（proxyBindAddr / userConnTimeout / | 服务端四个字段（proxyBindAddr / userConnTimeout / | `批次1服务端字段读到值且不再报未实现` | 限制①批次1：服务端四个字段（proxyBindAddr / userConnTimeout /<br>maxPoolCount / disablePrintColor）同样要读进来且不报未实现。 |
| `common/src/frp_config.rs` | 1629 | 未标注 | keepalive 组四个字段（客户端 `dialServerKeepalive` / | keepalive 组四个字段（客户端 `dialServerKeepalive` / | `批次2keepalive字段读到值且不再报未实现` | 限制①批次2：keepalive 组四个字段（客户端 `dialServerKeepalive` /<br>`tcpMuxKeepaliveInterval`，服务端 `tcpMuxKeepaliveInterval` /<br>`tcpKeepalive`）既能读官方 camelCase 写法，也不再被报"未实现"。 |
| `common/src/frp_config.rs` | 1669 | 未标注 | 默认值取官方（7200 / 30 / 30 / 7200），不写就是这四档； | 默认值取官方（7200 / 30 / 30 / 7200），不写就是这四档； | `批次2keepalive默认值与零语义` | 限制①批次2：默认值取官方（7200 / 30 / 30 / 7200），不写就是这四档；<br>显式写 `0` 保持"关闭"的原意，不被折算成官方默认。 |
| `common/src/frp_legacy.rs` | 385 | 未标注 | 连接服务端的超时与本机出口绑定（官方 legacy 同名键， | 连接服务端的超时与本机出口绑定（官方 legacy 同名键， | 未标注 | 连接服务端的超时与本机出口绑定（限制①批次1 实现；官方 legacy 同名键，<br>见 `legacy/conversion.go` 的 `out.Transport.DialServerTimeout` /<br>`ConnectServerLocalIP` 两行）。 |
| `common/src/frp_legacy.rs` | 395 | 未标注 | TCP keepalive / yamux 保活（官方 legacy 同名键， | TCP keepalive / yamux 保活（官方 legacy 同名键， | 未标注 | TCP keepalive / yamux 保活（限制①批次2 实现；官方 legacy 同名键，<br>见 `legacy/conversion.go` 的 `out.Transport.DialServerKeepAlive` /<br>`TCPMuxKeepaliveInterval` 两行）。 |
| `common/src/frp_legacy.rs` | 822 | 未标注 | 数据面监听地址（官方 `conversion.go:111`： | 数据面监听地址（官方 `conversion.go:111`： | 未标注 | 数据面监听地址（限制①批次1；官方 `conversion.go:111`：<br>`out.ProxyBindAddr = conf.ProxyBindAddr`）。 |
| `common/src/frp_legacy.rs` | 833 | 未标注 | 等用户连接配工作连接的超时 + 单客户端空闲池上限（ | 等用户连接配工作连接的超时 + 单客户端空闲池上限（ | 未标注 | 等用户连接配工作连接的超时 + 单客户端空闲池上限（限制①批次1；<br>官方 `conversion.go:140/147`）。 |
| `common/src/frp_legacy.rs` | 837 | 未标注 | yamux 保活间隔 + 主端口 TCP keepalive（ | yamux 保活间隔 + 主端口 TCP keepalive（ | 未标注 | yamux 保活间隔 + 主端口 TCP keepalive（限制①批次2；<br>官方 `conversion.go:145/146`）。 |
| `common/src/frp_legacy.rs` | 933 | 未标注 | legacy INI 里的新字段（官方同名键）要能搬进来 —— | legacy INI 里的新字段（官方同名键）要能搬进来 —— | `ini_批次1字段映射到位` | 限制①批次1：legacy INI 里的新字段（官方同名键）要能搬进来 ——<br>客户端 `dial_server_timeout` / `connect_server_local_ip` /<br>`disable_log_color`，服务端 `proxy_bind_addr` / `user_conn_timeout` /<br>`max_pool_count` / `disable_log_color`。 |
| `common/src/frp_legacy.rs` | 965 | 未标注 | keepalive 组在 legacy INI 里的同名键也要能搬进来 —— | keepalive 组在 legacy INI 里的同名键也要能搬进来 —— | `ini_批次2字段映射到位` | 限制①批次2：keepalive 组在 legacy INI 里的同名键也要能搬进来 ——<br>客户端 `dial_server_keepalive` / `tcp_mux_keepalive_interval`，<br>服务端 `tcp_mux_keepalive_interval` / `tcp_keepalive`。 |
| `common/src/http_relay.rs` | 98 | 未标注 | 这正是 `plugin_bridge` 那个"Linux 上 5/10 超时、请求从未转给上游" | 的根因。现在补上。 | 未标注 | 这正是 `plugin_bridge` 那个"Linux 上 5/10 超时、请求从未转给上游"<br>的根因（第十五轮记录、第十七轮仍未修）。现在补上。 |
| `common/src/http_relay.rs` | 120 | 未标注 | 实测：同一测试在 Linux 上 10 次里 5 次 5 秒超时，表现是 | 实测：同一测试在 Linux 上 10 次里 5 次 5 秒超时，表现是 | 未标注 | 第十五轮实测：同一测试在 Linux 上 10 次里 5 次 5 秒超时，表现是<br>"插件收到连接却从未把请求转给上游"。根因是旧实现 `read(&mut chunk)`<br>读进**局部数组**，future 被 `select!` 取消时那批字节随局部变量一起消失。 |
| `common/src/http_relay.rs` | 820 | 未标注 | 这正是第七轮 **D7-1** 的同一条链路上的第二个洞： | 这正是第七轮 **D7-1** 的同一条链路上的第二个洞： | 未标注 | 这正是第七轮 **D7-1** 的同一条链路上的第二个洞：<br>D7-1 修的是"响应侧**判定口径**与请求侧不一致"，<br>这一条修的是"响应侧**根本没有校验**"。 |
| `common/src/http_relay.rs` | 1186 | 未标注 | 如实标注这条测试的边界：它**证明不了**第十五轮那个 Linux 竞态已经消失 | 如实标注这条测试的边界：它**证明不了**第十五轮那个 Linux 竞态已经消失 | `watch_closed_被取消时不丢字节` | ★ 如实标注这条测试的边界：它**证明不了**第十五轮那个 Linux 竞态已经消失<br>—— 那是时序相关的，Windows 上 21/21 都复现不出来。这里能做的是<br>"取消一次 → 字节一个不少 → 之后再读还能读全"这条确定性检查；<br>真正盯住 Linux 的闸门是 CI 上 `http2*` / `https2*` 用例连跑，<br>以及同一文件里的 `wait_upstream_不许忙等`（防第三次忙等回滚）。 |
| `common/src/util.rs` | 96 | 未标注 | ## 为什么光有速率限制不够 | ## 为什么光有速率限制不够 | 未标注 | ## 为什么光有速率限制不够（第七轮 A-1 的复现教训） |
| `common/src/util.rs` | 366 | 未标注 | `disable_print_color`在终端 | `disable_print_color`在终端 | 未标注 | `disable_print_color`（官方 `log.disablePrintColor`，限制①批次1）在终端<br>场景下强制关闭 ANSI 颜色；写文件场景它没有可观察影响。 |
| `common/src/util.rs` | 573 | 未标注 | # 为什么需要它 | # 为什么需要它 | 未标注 | # 为什么需要它（NFRP-07） |
| `common/src/util.rs` | 669 | 未标注 | 的两个配置项都落到这里： | 的两个配置项都落到这里： | 未标注 | 限制①批次2 的两个配置项都落到这里：<br>- 客户端 `dialServerKeepalive`（官方拨号器 `libnet.WithKeepAlive`，作用于<br>控制连接与每条新拨的工作连接）；<br>- 服务端 `tcpKeepalive`（官方在 `bind_port` 主监听器 `SetKeepAlive`，<br>作用于所有从主端口接下的 TCP 连接）。 |
| `common/src/util.rs` | 699 | 未标注 | 日志字段里的控制字符必须被转义，不能产生真实换行/ESC。 | 日志字段里的控制字符必须被转义，不能产生真实换行/ESC。 | `log_safe_转义控制字符` | NFRP-07：日志字段里的控制字符必须被转义，不能产生真实换行/ESC。 |
| `common/src/util.rs` | 799 | 未标注 | 日志放大（折叠） | 日志放大（折叠） | `日志折叠_同类消息每窗口最多两条` | -------------------------------------------------------------------<br>第七轮审计 A-1：日志放大（折叠）<br>------------------------------------------------------------------- |
| `common/src/util.rs` | 905 | 未标注 | TCP keepalive 设置后必须真的落到 socket 上。 | TCP keepalive 设置后必须真的落到 socket 上。 | `tcp_keepalive_能设置并读回` | 限制①批次2：TCP keepalive 设置后必须真的落到 socket 上。 |
| `common/src/ws.rs` | 1005 | 未标注 | 掩码位的方向性校验（RFC 6455 §5.1 两个 MUST） | 掩码位的方向性校验（RFC 6455 §5.1 两个 MUST） | 未标注 | ------------------------------------------------------------------<br>第四轮 G-7：掩码位的方向性校验（RFC 6455 §5.1 两个 MUST）<br>------------------------------------------------------------------ |
| `server/src/admin.rs` | 80 | 未标注 | 这与第四轮 H1 是**同一类**：同一个语义（"这个客户端能不能注册这条代理"） | 这与第四轮 H1 是**同一类**：同一个语义（"这个客户端能不能注册这条代理"） | 未标注 | 这与第四轮 H1 是**同一类**：同一个语义（"这个客户端能不能注册这条代理"）<br>在两条路径上用了两套规则。修法就是把闸门补到这条路径上。 |
| `server/src/admin.rs` | 474 | 未标注 | -02：面板路径也要过 RBAC | -02：面板路径也要过 RBAC | 未标注 | ------------------------------------------------------------------<br>第四轮 D-AUTH-02：面板路径也要过 RBAC<br>------------------------------------------------------------------ |
| `server/src/dashboard.rs` | 294 | 未标注 | 安全相关头必须唯一。出现两个以上 Authorization | 安全相关头必须唯一。出现两个以上 Authorization | 未标注 | ★ NFRP-13：安全相关头必须唯一。出现两个以上 Authorization<br>直接当畸形请求拒掉，而不是“取第一个”——否则与前置代理 / WAF 的<br>取值口径一旦相反，就是鉴权差异（请求走私类问题的典型前提）。 |
| `server/src/dashboard.rs` | 773 | 未标注 | `req` 是整个读缓冲的转码（见 `handle` 里的读循环）—— 与请求头同一批 | `Authorization: Basic ...` 会被当成头参与鉴权（第八轮实测：同段发送 | 未标注 | `req` 是整个读缓冲的转码（见 `handle` 里的读循环）—— 与请求头同一批<br>到达的请求体字节也在里面。原先逐行扫描整个缓冲，于是写在 body 里的<br>`Authorization: Basic ...` 会被当成头参与鉴权（第八轮实测：同段发送<br>时 control=401 / body 行=200）。这与标准 HTTP 语义、以及上游中间件<br>（反代/WAF/网关只按头区判定）的口径不一致，属解析卫生问题；<br>按纵深防御收紧到头区（`\r\n\r\n` 之前）。 |
| `server/src/dashboard.rs` | 790 | 未标注 | 安全相关头：**必须唯一**。重复即为畸形请求。 | 安全相关头：**必须唯一**。重复即为畸形请求。 | 未标注 | 安全相关头：**必须唯一**。重复即为畸形请求（NFRP-13）。 |
| `server/src/dashboard.rs` | 928 | 未标注 | （P0）：不能用 `format!` + `{:?}` 拼 JSON。 | （P0）：不能用 `format!` + `{:?}` 拼 JSON。 | 未标注 | ★★ NFRP-05（P0）：不能用 `format!` + `{:?}` 拼 JSON。 |
| `server/src/dashboard.rs` | 1220 | 未标注 | 修了 `table()` / `card()` 的转义，**唯独漏了这条 catch 分支** | 修了 `table()` / `card()` 的转义，**唯独漏了这条 catch 分支** | 未标注 | 第五轮 H4 修了 `table()` / `card()` 的转义，**唯独漏了这条 catch 分支**<br>—— 又是"防线没铺满"那个模式。 |
| `server/src/dashboard.rs` | 1579 | 未标注 | 修了 `table()` / `card()`，**唯独漏了这条 catch 分支** —— | 修了 `table()` / `card()`，**唯独漏了这条 catch 分支** —— | `metrics_endpoint_output_is_prometheus_shaped` | 第五轮 H4 修了 `table()` / `card()`，**唯独漏了这条 catch 分支** ——<br>又是"防线没铺满"那个模式。 |
| `server/src/dashboard.rs` | 1744 | 未标注 | `/api/status` 必须是合法 JSON | `/api/status` 必须是合法 JSON | `status_json_对控制字符仍然合法` | ==================================================================<br>NFRP-05：`/api/status` 必须是合法 JSON<br>================================================================== |
| `server/src/dashboard.rs` | 1796 | 未标注 | 重复 Authorization 必须拒绝 | 重复 Authorization 必须拒绝 | `重复_authorization_被判为畸形` | ==================================================================<br>NFRP-13：重复 Authorization 必须拒绝<br>================================================================== |
| `server/src/main.rs` | 140 | 未标注 | 背景：v1 控制通道的登录凭证是 | 背景：v1 控制通道的登录凭证是 | 未标注 | 背景（第二轮审计的 B 项）：v1 控制通道的登录凭证是<br>`md5(token + timestamp)`，而且服务端**对 timestamp 不做新鲜性校验**<br>（只用报文自报的 ts 重算比对）。攻击者抓到**一条** Login 报文后，<br>枚举一个候选 token 只需要 **1 次 MD5** —— 也就是说 token 的实际强度<br>取决于它自己够不够随机，PBKDF2 那 64 次迭代帮不上忙（那个参数是<br>官方 golib 硬编码的，改了就跟官方断互通，**不能改**）。 |
| `server/src/p2p.rs` | 262 | 未标注 | `p2p.rs` 里**没有 `check_ip` 调用**。 | `p2p.rs` 里**没有 `check_ip` 调用**。 | 未标注 | `p2p.rs` 里**没有 `check_ip` 调用**（第九轮 grep 零命中）。<br>牵线唯一的来源判定是第八轮 B-1 加的"与控制连接 IP 同源"<br>（`register` 里的 `same_host` 检查）—— 那拦的是"**冒充别人**"，<br>**不读 `[acl]`**，两者不等价。 |
| `server/src/pool.rs` | 223 | 未标注 | 两个超时是**两个不同的量**： | 两个超时是**两个不同的量**： | 未标注 | 两个超时是**两个不同的量**（限制①批次1 起拆分）：<br>* `work_timeout`（`work_conn_idle_timeout`，nfrp 自有字段）：空闲工作<br>连接在池里能躺多久 —— 躺太久说明客户端预建的连接早已失效；<br>* `user_timeout`（`userConnTimeout`，对齐官方 `GetWorkConn()` 默认 10 秒）：<br>排队用户等多久配不到工作连接就放弃。 |
| `server/src/pool.rs` | 296 | 未标注 | 替掉三处硬编码 —— visitor 路径等 10s、vhost / UDP 路径 | 替掉三处硬编码 —— visitor 路径等 10s、vhost / UDP 路径 | 未标注 | ★ 限制①批次1：替掉三处硬编码 —— visitor 路径等 10s、vhost / UDP 路径<br>等 15s、排队用户由 `idle_timeout`（默认 60s）兜底。全部统一到本字段，<br>与官方 `GetWorkConn()` 的语义对齐（等不到工作连接就放弃这条用户连接）。 |
| `server/src/pool.rs` | 336 | 未标注 | 曾写下"`idle_work_conns` 持续累积、fd/内存缓慢增长" | 曾写下"`idle_work_conns` 持续累积、fd/内存缓慢增长" | 未标注 | ★ 第五轮 M15 曾写下"`idle_work_conns` 持续累积、fd/内存缓慢增长"<br>这句话，但**只修了超时的上界**（`clamp(5,3600)`），<br>**从未加过数量上界** ⇒ 该面从未被真正修过。 |
| `server/src/pool.rs` | 346 | 未标注 | 再叠加官方 `maxPoolCount`（`ServerConfig:max_pool_count`）， | 再叠加官方 `maxPoolCount`（`ServerConfig:max_pool_count`）， | 未标注 | ★ 限制①批次1：再叠加官方 `maxPoolCount`（`ServerConfig::max_pool_count`），<br>两者**取更小**（任一为 0 = 该侧不设限；两侧都 0 = 不限制）。官方口径是<br>"池容量 = min(客户端 poolCount, maxPoolCount) + 10 余量"，这里映射成<br>空闲池闸门 —— 默认（都没配）时与原行为完全一致。 |
| `server/src/pool.rs` | 427 | 未标注 | 再叠加官方 `maxPoolCount` —— 两个上限**取更小**； | 再叠加官方 `maxPoolCount` —— 两个上限**取更小**； | 未标注 | ★ 限制①批次1：再叠加官方 `maxPoolCount` —— 两个上限**取更小**；<br>任一为 0（该侧不设限）就取另一个；都为 0 = 不限制。 |
| `server/src/pool.rs` | 1203 | 未标注 | `maxPoolCount` 给空闲池封顶 —— 第二条空闲工作连接被拒， | `maxPoolCount` 给空闲池封顶 —— 第二条空闲工作连接被拒， | `max_pool_count_给空闲池封顶` | 限制①批次1：`maxPoolCount` 给空闲池封顶 —— 第二条空闲工作连接被拒，<br>池里的数量保持在 1（不配上限时它会是 2）。 |
| `server/src/pool.rs` | 1238 | 未标注 | 排队用户按 `userConnTimeout` 回收，与工作连接侧的超时分开。 | 排队用户按 `userConnTimeout` 回收，与工作连接侧的超时分开。 | `排队用户按_user_conn_timeout_回收` | 限制①批次1：排队用户按 `userConnTimeout` 回收，与工作连接侧的超时分开。 |
| `server/src/pool.rs` | 1302 | 未标注 | 空闲工作连接池必须有上界 | 空闲工作连接池必须有上界 | `空闲工作连接池必须有上界` | -----------------------------------------------------------------------<br>第七轮审计 C-2：空闲工作连接池必须有上界<br>----------------------------------------------------------------------- |
| `server/src/reload.rs` | 140 | 未标注 | 数据面监听地址 + 用户连接超时 + 空闲池上限：三者都固化在 | 数据面监听地址 + 用户连接超时 + 空闲池上限：三者都固化在 | 未标注 | 数据面监听地址 + 用户连接超时 + 空闲池上限（限制①批次1）：三者都固化在<br>每个 `ClientState` / 监听器里，热改没法让已建立的会话回头生效。 |
| `server/src/reload.rs` | 151 | 未标注 | TCP keepalive / yamux 保活：都固化在监听器与已建会话上， | TCP keepalive / yamux 保活：都固化在监听器与已建会话上， | 未标注 | TCP keepalive / yamux 保活（限制①批次2）：都固化在监听器与已建会话上，<br>热改没法回头生效。 |
| `server/src/reload.rs` | 224 | 未标注 | `disablePrintColor` 同属日志订阅者，只能启动时固化。 | `disablePrintColor` 同属日志订阅者，只能启动时固化。 | 未标注 | `disablePrintColor` 同属日志订阅者，只能启动时固化（限制①批次1 实现）。 |
| `server/src/reload.rs` | 253 | 未标注 | 为什么必须抽成一个函数：审计总报告 H1 的根因是"同一判定在四处各写了一遍， | 为什么必须抽成一个函数：审计总报告 H1 的根因是"同一判定在四处各写了一遍， | 未标注 | ★ 为什么必须抽成一个函数：审计总报告 H1 的根因是"同一判定在四处各写了一遍，<br>每处都只判了 `user`"。四处分别是： |
| `server/src/reload.rs` | 271 | 未标注 | 四个条件全部要正确取到"运行期真实值"才算对 —— H2就是 | 四个条件全部要正确取到"运行期真实值"才算对 —— H2就是 | 未标注 | ★ 四个条件全部要正确取到"运行期真实值"才算对 —— H2（审计总报告）就是<br>其中第三个条件取错了来源。 |
| `server/src/serve/conn.rs` | 191 | 未标注 | yamux 保活：0 = 关闭。 | yamux 保活：0 = 关闭。 | 未标注 | yamux 保活（限制①批次2，官方 `tcpMuxKeepaliveInterval`）：0 = 关闭。 |
| `server/src/serve/conn.rs` | 287 | 未标注 | (1.5) 未认证握手的全局并发闸。 | (1.5) 未认证握手的全局并发闸。 | 未标注 | (1.5) 未认证握手的全局并发闸（第九轮 C9-3）。 |
| `server/src/serve/control.rs` | 74 | 未标注 | * 每个客户端还能预建多条代理的空闲工作连接（官方 `maxPoolCount` | 默认 5；NFrp 同样支持该项，默认 0 = 不限）； | 未标注 | * 每个客户端还能预建多条代理的空闲工作连接（官方 `maxPoolCount`<br>默认 5；限制①批次1 起 NFrp 同样支持该项，默认 0 = 不限）；<br>* 客户端重连后旧连接不会被及时清掉 ⇒ `idle_work_conns` 持续累积<br>⇒ fd / 内存缓慢增长，且它**不是**由攻击流量触发的，<br>运维很难把它和配置项联系起来。 |
| `server/src/serve/control.rs` | 96 | 未标注 | 用户连接等配工作连接的超时：官方语义是 | 用户连接等配工作连接的超时：官方语义是 | 未标注 | 用户连接等配工作连接的超时（`userConnTimeout`，限制①批次1）：官方语义是<br>"等不到工作连接就放弃这条用户连接"，默认 10 秒；配 0 折算默认<br>（官方 `EmptyOr` 口径），不会变成"无限等"。 |
| `server/src/serve/preauth.rs` | 16 | 未标注 | 未认证握手的**全局**并发上限。 | 未认证握手的**全局**并发上限。 | 未标注 | 未认证握手的**全局**并发上限（第九轮 C9-3 修复）。 |
| `server/src/serve/preauth.rs` | 20 | 未标注 | 每条未认证的 frp 握手（明文连接或 yamux 子流）在认证完成前要占住一个 | 任务和一份读缓冲。第九轮实测（`tmp/audit9/c/c9_3_yamux_flood.py`）： | 未标注 | 每条未认证的 frp 握手（明文连接或 yamux 子流）在认证完成前要占住一个<br>任务和一份读缓冲。第九轮实测（`tmp/audit9/c/c9_3_yamux_flood.py`）：<br>yamux 未认证开流每条 ≈9.5 KiB、单会话上限 512 条、跨会话**没有**全局<br>上限 —— 攻击者 129 KB 流量 + 22 个 fd 就把服务端内存抬到 +100 MB。 |
| `server/src/serve/register.rs` | 220 | 未标注 | 数据面端口跟随 `proxyBindAddr`（官方 | 数据面端口跟随 `proxyBindAddr`（官方 | 未标注 | ★ 限制①批次1：数据面端口跟随 `proxyBindAddr`（官方<br>`ports.NewManager("tcp", cfg.ProxyBindAddr, ...)` 与 tcp.go 的<br>`net.Listen(..., ProxyBindAddr, ...)`；留空 = `bindAddr`）。 |
| `server/src/serve/register.rs` | 275 | 未标注 | 数据面端口跟随 `proxyBindAddr`（官方 udp.go： | 数据面端口跟随 `proxyBindAddr`（官方 udp.go： | 未标注 | ★ 限制①批次1：数据面端口跟随 `proxyBindAddr`（官方 udp.go：<br>`ResolveUDPAddr(..., ProxyBindAddr, ...)`；留空 = `bindAddr`）。 |
| `server/src/serve/startup.rs` | 133 | 未标注 | 证书/私钥/CA 能否装载，必须在 --check 阶段就暴露， | 证书/私钥/CA 能否装载，必须在 --check 阶段就暴露， | 未标注 | 限制①批次3：证书/私钥/CA 能否装载，必须在 --check 阶段就暴露，<br>不能等到真正 TLS 握手时才报错。 |
| `server/src/serve/startup.rs` | 196 | 未标注 | 自定义证书 / mTLS。必须在任何 accept_server 之前安装。 | 自定义证书 / mTLS。必须在任何 accept_server 之前安装。 | 未标注 | 限制①批次3：自定义证书 / mTLS。必须在任何 accept_server 之前安装。 |
| `server/src/serve/startup.rs` | 382 | 未标注 | vhost 的 HTTP/HTTPS/tcpmux 监听跟随 `proxyBindAddr` | vhost 的 HTTP/HTTPS/tcpmux 监听跟随 `proxyBindAddr` | 未标注 | ★ 限制①批次1：vhost 的 HTTP/HTTPS/tcpmux 监听跟随 `proxyBindAddr`<br>（官方 `ProxyBindAddr` 的作用范围之一就是 vhost 端口；留空时<br>= `bindAddr`，行为与老版本一致）。 |
| `server/src/serve/startup.rs` | 663 | 未标注 | 主端口 TCP keepalive（官方 `tcpKeepalive`： | 主端口 TCP keepalive（官方 `tcpKeepalive`： | 未标注 | 主端口 TCP keepalive（限制①批次2，官方 `tcpKeepalive`：<br>官方在 `bind_port` 主监听器上 `SetKeepAlive`，作用范围一致）。<br>`0` = 不打开（项目约定）。 |
| `server/src/udp_proxy.rs` | 102 | 未标注 | ⇒ 与第七轮 F7-1（TCP 数据面未过 ACL）**完全同型**： | ⇒ 与第七轮 F7-1（TCP 数据面未过 ACL）**完全同型**： | 未标注 | ⇒ 与第七轮 F7-1（TCP 数据面未过 ACL）**完全同型**：<br>第七轮补了 TCP，**UDP 被漏掉了**。 |
| `server/src/vhost/http.rs` | 40 | 未标注 | 路径校验 | 路径校验 | 未标注 | ---------------------------------------------------------------------------<br>路径校验（NFRP-06）<br>---------------------------------------------------------------------------<br>请求目标里是否含 `.` / `..` 段（含 `%2e` 编码）。 |
| `server/src/vhost/http.rs` | 45 | 未标注 | # 为什么要拒绝它 | # 为什么要拒绝它 | 未标注 | # 为什么要拒绝它（NFRP-06） |
| `server/src/vhost/http.rs` | 209 | 未标注 | 带 dot-segment 的路径直接拒绝。 | 带 dot-segment 的路径直接拒绝。 | 未标注 | ★ NFRP-06：带 dot-segment 的路径直接拒绝。 |
| `server/src/vhost/http.rs` | 640 | 未标注 | 这里（以及下面转发响应体那处）用的是 | 正是第四轮 C 组修掉的走私写法。 | 未标注 | 这里（以及下面转发响应体那处）用的是<br>`te.to_ascii_lowercase().contains("chunked")` —— 而**同一个文件**的<br>请求侧（`:1061`/`:1075`）早就改成了 RFC 口径的<br>[`http_relay::is_chunked`] / [`http_relay::transfer_encoding_is_unsupported`]，<br>`client/src/plugin_bridge.rs` 也用 `is_chunked`。<br>`http_relay.rs:500-522` 的注释里**明确写着** `contains("chunked")`<br>正是第四轮 C 组修掉的走私写法。 |
| `server/src/vhost/http.rs` | 675 | 未标注 | 与请求侧**共用同一个判定函数**，而不是在这里再手写一遍 —— | 。 | 未标注 | 与请求侧**共用同一个判定函数**，而不是在这里再手写一遍 ——<br>手写就会再次漂移。`is_chunked` 的口径是"最后一个 token 是 chunked<br>且前面只有 identity"，`identity, chunked` 这种 RFC 合法形态仍被接受<br>（第四轮专门修过"修得过头把合法的也拒了"）。 |
| `server/src/vhost/http.rs` | 756 | 未标注 | dot-segment 必须被拒 | dot-segment 必须被拒 | `dot_segment_能识别` | ==================================================================<br>NFRP-06：dot-segment 必须被拒<br>================================================================== |
| `server/src/vhost/http.rs` | 1619 | 未标注 | -1：响应侧 TE 判定必须与请求侧同口径 | -1：响应侧 TE 判定必须与请求侧同口径 | `响应侧_te_判定必须与请求侧同口径` | -----------------------------------------------------------------------<br>第七轮审计 D7-1：响应侧 TE 判定必须与请求侧同口径<br>----------------------------------------------------------------------- |
| `server/src/vhost/http.rs` | 1648 | 未标注 | 这就是**生产代码里**用来定界响应体的那个表达式 | -1 之前它是 `te.contains("chunked")`，之后是 `is_chunked`。 | 未标注 | ★★★ 这就是**生产代码里**用来定界响应体的那个表达式<br>（`vhost.rs` 的 `let resp_te_chunked = ...`）。<br>第七轮 D7-1 之前它是 `te.contains("chunked")`，之后是 `is_chunked`。<br>断言写在这个表达式上，才能真正守住"用的是 RFC 口径"这件事。 |
| `server/src/vhost/http.rs` | 1692 | 未标注 | 而 RFC 合法的 `identity, chunked` **不能**被拒 | 而 RFC 合法的 `identity, chunked` **不能**被拒 | 未标注 | 而 RFC 合法的 `identity, chunked` **不能**被拒（第四轮修过"修得过头"） |
| `server/src/vhost/http.rs` | 1715 | 未标注 | -1 的**行为级**回归：真实起 vhost，把"走私会不会发生"打出来。 | -1 的**行为级**回归：真实起 vhost，把"走私会不会发生"打出来。 | `响应侧_chunked_identity_不得被判为可安全分帧` | ★★ 第七轮 D7-1 的**行为级**回归：真实起 vhost，把"走私会不会发生"打出来。 |
| `server/src/vhost/listen.rs` | 155 | 未标注 | -1：数据面也要过 ACL | -1：数据面也要过 ACL | `vhost_数据面必须过_ip_白黑名单` | -----------------------------------------------------------------------<br>第七轮审计 F7-1：数据面也要过 ACL<br>----------------------------------------------------------------------- |
| `server/src/vhost/router.rs` | 108 | 未标注 | "这两条路由属于同一个客户端吗"。 | "这两条路由属于同一个客户端吗"。 | 未标注 | "这两条路由属于同一个客户端吗"（第四轮 H1）。 |
| `server/src/vhost/router.rs` | 421 | 未标注 | 用**指定的**客户端构造路由。 | 用**指定的**客户端构造路由。 | 未标注 | 用**指定的**客户端构造路由（第四轮 H1 的测试要用它来区分租户）。 |
| `server/src/vhost/router.rs` | 698 | 未标注 | 跨租户的域名路由劫持 | 跨租户的域名路由劫持 | `跨租户同名代理不得顶掉别人的域名路由` | ------------------------------------------------------------------<br>第四轮 H1：跨租户的域名路由劫持<br>------------------------------------------------------------------ |
| `server/src/vhost/tests.rs` | 12 | 未标注 | -0/E9-1/E9-2：ACL 必须铺满**全部**数据面入口 | -0/E9-1/E9-2：ACL 必须铺满**全部**数据面入口 | 未标注 | -----------------------------------------------------------------------<br>第九轮审计 E9-0/E9-1/E9-2：ACL 必须铺满**全部**数据面入口<br>----------------------------------------------------------------------- |
| `server/src/vhost/tests.rs` | 41 | 未标注 | \| 路径 \| 文件 \| 第九轮定级 \| | \| 路径 \| 文件 \| 第九轮定级 \| | `acl_必须铺满全部数据面入口` | \| 路径 \| 文件 \| 第九轮定级 \|<br>\|---\|---\|---\|<br>\| **UDP 代理端口** \| `udp_proxy.rs` \| **中危**（无其它防线） \|<br>\| **xtcp 牵线 UDP** \| `p2p.rs` \| 低危（B-1 来源绑定间接生效） \|<br>\| **管理面板** \| `dashboard.rs` \| 低危（有 Basic Auth） \| |
| `server/src/visitor.rs` | 43 | 未标注 | 这与 M3 修过的"登录凭证重放"是**同一个洞的另一条路径** —— | 。 | 未标注 | 这与 M3 修过的"登录凭证重放"是**同一个洞的另一条路径** ——<br>M3 只铺了主登录一处，而凭证入口一共有 6 个<br>（见第六轮审计报告 G-1 的覆盖面表）。 |
| `server/src/visitor.rs` | 87 | 未标注 | -5 修正（功能回归）：上面那句"即使传了空串也不匹配任意" | -5 修正（功能回归）：上面那句"即使传了空串也不匹配任意" | 未标注 | ★★ 第九轮 A9-5 修正（功能回归）：上面那句"即使传了空串也不匹配任意"<br>原先实现成 **空串一律 false** —— 但空 `user` 不是攻击者的专利：<br>双方都没配 `user`（配置里的默认值就是空）时，官方 frps 走<br>"空 `allow_users` ⇒ 只允许 provider 自己的 user" ⇒ `"" == ""` 放行。<br>实测该组合下 stcp visitor **完全无法配对**（A9-5 调试：<br>服务端打 `visitor 用户不在 allow_users 白名单内`）。<br>现在只在**命中白名单**的方向上堵空串；`allow_users` 为空时恢复官方语义。 |
| `server/src/visitor.rs` | 153 | 未标注 | 这是第四轮 H1 的**同一个根因、漏掉的第二处**： | 这是第四轮 H1 的**同一个根因、漏掉的第二处**： | 未标注 | 这是第四轮 H1 的**同一个根因、漏掉的第二处**：<br>vhost 的三处判定在 H1 里补上了客户端身份，而本函数漏了。<br>注意**同一个文件里** `unregister_client`（下面）一直是对的<br>—— 用的是 `Arc::ptr_eq(&e.client, client)`。 |
| `server/src/visitor.rs` | 259 | 未标注 | -5：provider 自己也是空 user（默认场景）时， | -5：provider 自己也是空 user（默认场景）时， | 未标注 | ★ 第九轮 A9-5：provider 自己也是空 user（默认场景）时，<br>空身份 == 空 provider_user 必须放行（否则 visitor 功能不可用）。 |
| `server/src/vnet.rs` | 157 | 未标注 | 源地址伪造而被丢弃的包数。非零 = 有人在冒充别人。 | 源地址伪造而被丢弃的包数。非零 = 有人在冒充别人。 | 未标注 | 源地址伪造而被丢弃的包数（第四轮 F4）。非零 = 有人在冒充别人。 |
| `server/src/vnet.rs` | 723 | 未标注 | 1. **功能面**：广播 / 网关 ICMP / 单播 A→B **全部不可达** | 2. **可观测性面**：`dropped_spoofed` 是第四轮 F4 之后 | 未标注 | 1. **功能面**：广播 / 网关 ICMP / 单播 A→B **全部不可达**<br>—— VNet 转发整条失效。<br>2. **可观测性面**：`dropped_spoofed` 是第四轮 F4 之后<br>"有人在冒充"的**唯一信号**，现在对**每个合法包**都自增<br>⇒ 真实的冒充告警被噪音淹没，指标**失去判别力**。 |
| `server/src/vnet.rs` | 731 | 未标注 | `session_key` 是第四轮修 F4（同名客户端互相踢掉）时引入的， | `session_key` 是第四轮修 F4（同名客户端互相踢掉）时引入的， | 未标注 | `session_key` 是第四轮修 F4（同名客户端互相踢掉）时引入的，<br>但**只改了建立侧**，查找侧（这条转发路径）漏改了。<br>⇒ "引入一个新的键"时必须把它**所有**使用点一起改，<br>否则就会出现这种"一半新键、一半旧名"的错配。 |
| `server/src/vnet.rs` | 971 | 未标注 | 源地址伪造必须被拦 | 源地址伪造必须被拦 | `冒充他人源地址必须被丢弃` | ------------------------------------------------------------------<br>第四轮 F4：源地址伪造必须被拦<br>------------------------------------------------------------------ |
| `server/src/vnet.rs` | 1098 | 未标注 | 转发路径必须用**会话键**，不能用显示名 | 转发路径必须用**会话键**，不能用显示名 | `转发必须用会话键而不是显示名` | ------------------------------------------------------------------<br>第七轮审计 C-1：转发路径必须用**会话键**，不能用显示名<br>------------------------------------------------------------------ |

---

共 622 条，5 个版本节。
