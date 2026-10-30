/* ===========================================================================
   NFrp 文档 · 中文内容页
   ---------------------------------------------------------------------------
   与 pages.en.js 一一对应（同样的 16 个键）。
   app.js 按当前语言把 PAGES_I18N[lang] 注入 #dynamicPages。
   这里的技术数据全部来自真实源码与审计记录。
   =========================================================================== */

const PAGES_ZH = {};

/* ======================== 服务端配置 ======================== */
PAGES_ZH['config-server'] = `
<h1>服务端配置</h1>
<p class="lead">frps 的 <code>frps.toml</code> 全部配置项。键名镜像官方 frp，官方配置基本可直接用。</p>

<h2>最小可用配置</h2>
<pre><code>bind_addr = "0.0.0.0"
bind_port = 7000

[auth]
token = "至少 16 位的随机口令"</code></pre>

<h2>核心项</h2>
<div class="table-wrap">
<table>
<thead><tr><th>配置项</th><th>类型</th><th>默认</th><th>说明</th></tr></thead>
<tbody>
<tr><td><code>bind_addr</code></td><td>string</td><td><code>0.0.0.0</code></td><td>控制连接监听地址</td></tr>
<tr><td><code>bind_port</code></td><td>u16</td><td><code>7000</code></td><td>控制连接端口，工作连接复用它</td></tr>
<tr><td><code>log_level</code></td><td>string</td><td><code>info</code></td><td>trace / debug / info / warn / error</td></tr>
<tr><td><code>log_to</code></td><td>string</td><td>空</td><td>日志目录，留空走控制台；按天轮转</td></tr>
<tr><td><code>log_max_days</code></td><td>u32</td><td><code>3</code></td><td>日志保留天数</td></tr>
<tr><td><code>allow_insecure_no_auth</code></td><td>bool</td><td><code>false</code></td><td>无 token 加绑对外地址时必须显式置 true，否则拒绝启动</td></tr>
</tbody>
</table>
</div>

<h2>认证</h2>
<pre><code>[auth]
method = "token"          # token | oidc
token = "共享口令"

# OIDC 模式下：
# issuer = "https://idp.example.com"
# audience = "nfrp"
# additionalScopes = ["groups"]</code></pre>

<div class="callout">
<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><path d="M12 16v-4M12 8h.01"/></svg>
<div>
<strong>token 的唯一真源是 <code>effective_auth()</code></strong>
<p>新写法 <code>[auth] token</code> 优先，回落到旧式顶层 <code>token</code>。全代码只有这一处判定，避免历史上"两处各判一次、判反了"的问题。</p>
</div>
</div>

<h2>管理面板</h2>
<pre><code>dashboard_addr = "127.0.0.1"   # 只让本机访问
dashboard_port = 7500
dashboard_user = "admin"
dashboard_pwd  = "换成强口令"</code></pre>

<div class="callout warn">
<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M10.29 3.86 1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><path d="M12 9v4M12 17h.01"/></svg>
<div>
<strong>面板绑非回环地址时必须有账号密码</strong>
<p><code>dashboard_user</code> 与 <code>dashboard_pwd</code> <strong>都非空</strong>才算"有凭据"。任何一个为空，绑对外地址会被拒绝启动。</p>
</div>
</div>

<p>面板提供：<code>/</code> 网页、<code>/api/status</code> 状态、<code>/metrics</code> Prometheus 指标、<code>/api/healthz</code> 免鉴权探针、<code>/api/v2/*</code> 管理 API。</p>

<h2>访问控制（ACL）</h2>
<pre><code>[acl]
allow = ["10.0.0.0/8", "192.168.0.0/16", "2001:db8::/32"]
deny  = ["10.1.2.3"]</code></pre>
<p>在<strong>认证之前</strong>执行，被拒的连接连 token 都不用发。deny 优先于 allow。详见 <a href="#/acl-and-rbac">ACL 与 RBAC</a>。</p>

<h2>角色与权限（RBAC）</h2>
<pre><code>defaultRole = "guest"
denyUnknown = true

[[roles]]
name = "operator"
users = ["alice"]
allowManage = true          # 允许被面板管理（增删代理、踢出）
allowProxyTypes = ["tcp", "http", "https"]
portRange = "20000-30000"
maxProxies = 50</code></pre>
<p>按<strong>顺序</strong>匹配，先命中先用，所以最具体的角色写在前面。</p>

<h2>审计日志</h2>
<pre><code>[audit]
enable = true
path = "/var/log/nfrp/audit.jsonl"
maxEntries = 1000
maxFileMB = 64</code></pre>
<p>默认<strong>关闭</strong>。开启后记录登录、代理注册、管理操作（增 / 删 / 踢）、配置重载、VNet 事件。详见 <a href="#/audit-log">审计日志</a>。</p>

<h2>传输层</h2>
<pre><code>[transport]
# TLS 封装
tls.force = true
tls.certFile = "/etc/nfrp/server.crt"
tls.keyFile  = "/etc/nfrp/server.key"

# 额外监听端口
kcpBindPort = 7000      # KCP（UDP）
quicBindPort = 7001     # QUIC
vhostHTTPSPort = 443    # https 代理入口</code></pre>

<h2>资源上限</h2>
<div class="table-wrap">
<table>
<thead><tr><th>配置项</th><th>说明</th></tr></thead>
<tbody>
<tr><td><code>max_clients</code></td><td>同时在线客户端上限</td></tr>
<tr><td><code>max_total_conns</code></td><td>全局用户连接上限</td></tr>
<tr><td><code>max_conns_per_client</code></td><td>单客户端连接上限</td></tr>
<tr><td><code>max_proxies_per_client</code></td><td>单客户端代理数上限</td></tr>
<tr><td><code>allow_ports</code></td><td>允许申请的远端端口范围，如 <code>["20000-30000"]</code></td></tr>
<tr><td><code>kcp_max_sessions</code></td><td>KCP 会话表上限，默认 1024（约 15 MB 峰值）</td></tr>
</tbody>
</table>
</div>

<h2>group 负载均衡策略</h2>
<p>同 <code>group</code> 的多个代理共享一个公网端口，用户连接在它们之间分摊。策略由 <code>lb_policy</code> 决定：</p>
<pre><code>lb_policy = "roundrobin"   # 默认</code></pre>
<div class="table-wrap">
<table>
<thead><tr><th>值</th><th>行为</th></tr></thead>
<tbody>
<tr><td><code>roundrobin</code>（默认）</td><td>严格 1/N 轮询，<strong>与官方 frp 一致</strong></td></tr>
<tr><td><code>leastconn</code></td><td>优先给在途连接最少的后端，能力不均时更优</td></tr>
</tbody>
</table>
</div>
<div class="callout">
<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><path d="M12 16v-4M12 8h.01"/></svg>
<div>
<strong>为什么默认是轮询</strong>
<p>官方 <code>server/group/*.go</code> 用 channel fan-out 实现：真实监听器把连接丢进共享 <code>acceptCh</code>，哪个代理先 <code>Accept()</code> 谁拿到，效果就是无状态轮询。它行为可预测，把"谁不健康"交给健康检查去处理，而不是让调度器猜。</p>
<p><code>leastconn</code> 是本项目的超集能力，调度完全发生在服务端内部，开它不影响与官方客户端的互通。</p>
</div>
</div>

<h2>KCP 会话上限</h2>
<pre><code>kcp_max_sessions = 1024   # 默认</code></pre>
<p>KCP 是"每个 UDP 源端口一个会话"的模型，每会话约占 15.3 KB。<strong>这个值直接决定内存上界</strong>：值 × 15.3 KB。</p>
<div class="table-wrap">
<table>
<thead><tr><th>值</th><th>峰值内存</th><th>适用</th></tr></thead>
<tbody>
<tr><td>1024（默认）</td><td>≈ 15 MB</td><td>绝大多数部署</td></tr>
<tr><td>4096</td><td>≈ 62 MB</td><td>数千客户端的单实例</td></tr>
<tr><td>16384</td><td>≈ 250 MB</td><td>需确认内存充足</td></tr>
</tbody>
</table>
</div>
<div class="callout warn">
<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M10.29 3.86 1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><path d="M12 9v4M12 17h.01"/></svg>
<div>
<strong>超大规模不要靠调大这个值</strong>
<p>正确做法是：① 用 TCP 或 QUIC 承载控制连接（KCP 只在两者都走不通时才需要）；② 或在前面挂负载均衡，把客户端拆到多个 frps 实例上。</p>
<p>低于 64 会被自动抬到安全下限 —— 配成 0 等于关掉 KCP，那属于静默失效，比拒绝启动更难排查。</p>
</div>
</div>

<h2>VirtualNet 与 xtcp</h2>
<pre><code>p2p_port = 7002          # xtcp 牵线用 UDP 端口；不配则 xtcp 退化为中继

[vnet]
bindPort = 7003</code></pre>
`;

/* ======================== 客户端配置 ======================== */
PAGES_ZH['config-client'] = `
<h1>客户端配置</h1>
<p class="lead">frpc 的 <code>frpc.toml</code>。与官方 frp 键名一致，也支持老式 <code>frpc.ini</code>。</p>

<h2>最小可用配置</h2>
<pre><code>server_addr = "服务器地址"
server_port = 7000

[auth]
token = "与服务端一致"

[[proxies]]
name = "ssh"
type = "tcp"
local_ip = "127.0.0.1"
local_port = 22
remote_port = 6000</code></pre>

<h2>核心项</h2>
<div class="table-wrap">
<table>
<thead><tr><th>配置项</th><th>默认</th><th>说明</th></tr></thead>
<tbody>
<tr><td><code>server_addr</code></td><td>必填</td><td>服务端地址</td></tr>
<tr><td><code>server_port</code></td><td><code>7000</code></td><td>服务端控制端口</td></tr>
<tr><td><code>user</code></td><td>空</td><td>租户名。代理对外用 <code>{user}.{name}</code> 做命名空间隔离</td></tr>
<tr><td><code>login_fail_exit</code></td><td><code>true</code></td><td>首次登录失败是否退出进程</td></tr>
<tr><td><code>dial_server_timeout</code></td><td><code>10</code></td><td>拨号超时（秒）</td></tr>
<tr><td><code>dial_server_keepalive</code></td><td><code>0</code></td><td>TCP keepalive 空闲秒数，0 表示不开</td></tr>
</tbody>
</table>
</div>

<h2>传输层</h2>
<pre><code>[transport]
protocol = "tcp"           # tcp | kcp | quic | websocket

[transport.tls]
enable = true
# verifyServerCert = true  # 默认 false，与官方 frpc 一致
# trustedCaFile = "/etc/nfrp/ca.crt"</code></pre>

<div class="callout warn">
<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M10.29 3.86 1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><path d="M12 9v4M12 17h.01"/></svg>
<div>
<strong>客户端默认不校验服务端证书</strong>
<p>这是与官方 frpc 对齐的行为（官方就是 <code>InsecureSkipVerify</code>）。否则官方 frps 全连不上。<br>
<strong>自有服务端建议开校验</strong>：置 <code>verifyServerCert = true</code> 并给出 <code>trustedCaFile</code>。注意开了校验后官方 frpc 默认连不上，属于"自有客户端 + 自有服务端"场景。</p>
</div>
</div>

<h2>代理定义</h2>
<pre><code>[[proxies]]
name = "web"
type = "http"
local_port = 8080
custom_domains = ["app.example.com"]
# locations = ["/api"]
# http_user = "u"
# http_pwd  = "p"

[[proxies]]
name = "dns"
type = "udp"
local_ip = "127.0.0.1"
local_port = 53
remote_port = 6053</code></pre>
<p>八种类型的完整字段见 <a href="#/proxy-types">代理类型</a>。</p>

<h2>本地管理界面</h2>
<pre><code>[webServer]
addr = "127.0.0.1"
port = 7400
user = "admin"
password = "强口令"</code></pre>
<p>浏览器打开 <code>http://127.0.0.1:7400</code>，可动态增删隧道。写接口需要自定义头 <code>X-Nfrp-Client: 1</code>（防 CSRF 盲打），且 <code>Origin</code> 必须是本机来源。</p>

<div class="callout warn">
<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M10.29 3.86 1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><path d="M12 9v4M12 17h.01"/></svg>
<div>
<strong>本地界面绑非回环地址必须设密码</strong>
<p>与面板同理，<code>addr</code> 不是回环且没配密码会被拒绝启动。</p>
</div>
</div>

<h2>动态隧道持久化</h2>
<pre><code>[store]
path = "/var/lib/nfrp/proxies.json"</code></pre>
<p>本地界面加的隧道会落盘，重启自动恢复。<strong>路径来自配置文件，不可被服务端远程控制</strong>。恢复时会校验危险字段（插件参数、本机资源路径等），危险条目直接丢弃。</p>

<h2>命令行</h2>
<div class="table-wrap">
<table>
<thead><tr><th>命令</th><th>作用</th></tr></thead>
<tbody>
<tr><td><code>nfrp-client -c frpc.toml</code></td><td>启动</td></tr>
<tr><td><code>nfrp-client verify -c frpc.toml</code></td><td>只校验配置，不启动</td></tr>
<tr><td><code>nfrp-client reload</code></td><td>让运行中的实例重载配置</td></tr>
<tr><td><code>nfrp-client status</code></td><td>查运行状态</td></tr>
<tr><td><code>nfrp-client stop</code></td><td>停掉运行中的实例</td></tr>
</tbody>
</table>
</div>
`;

/* ======================== 代理类型 ======================== */
PAGES_ZH['proxies'] = `
<h1>代理类型</h1>
<p class="lead">八种，与官方 frp 的类型清单完全一致。每种的数据流向不同。</p>

<h2>一览</h2>
<div class="table-wrap">
<table>
<thead><tr><th>类型</th><th>占用公网端口</th><th>数据经服务端</th><th>典型用途</th></tr></thead>
<tbody>
<tr><td><code>tcp</code></td><td>是</td><td>是</td><td>SSH、数据库、任意 TCP 服务</td></tr>
<tr><td><code>udp</code></td><td>是</td><td>是</td><td>DNS、游戏、任意 UDP 服务</td></tr>
<tr><td><code>http</code></td><td>共用 vhost 端口</td><td>是</td><td>按域名路由的网站</td></tr>
<tr><td><code>https</code></td><td>共用 vhost 端口</td><td>是</td><td>只嗅探 SNI 路由，不终止 TLS</td></tr>
<tr><td><code>tcpmux</code></td><td>共用 vhost 端口</td><td>是</td><td>HTTP CONNECT 复用，多代理共用端口</td></tr>
<tr><td><code>stcp</code></td><td>否</td><td>是（加密中继）</td><td>私密服务，不暴露公网端口</td></tr>
<tr><td><code>sudp</code></td><td>否</td><td>是（加密中继）</td><td>私密 UDP 服务</td></tr>
<tr><td><code>xtcp</code></td><td>否</td><td><strong>否</strong>（打洞直连）</td><td>点对点大流量，不经服务端</td></tr>
</tbody>
</table>
</div>

<h2>tcp</h2>
<pre><code>[[proxies]]
name = "ssh"
type = "tcp"
local_ip = "127.0.0.1"
local_port = 22
remote_port = 6000</code></pre>
<p>最简单的一种。服务端在 <code>0.0.0.0:6000</code> 开监听，访客连上来后服务端向客户端索要一条工作连接，两端对接。</p>

<h2>udp</h2>
<pre><code>[[proxies]]
name = "dns"
type = "udp"
local_ip = "127.0.0.1"
local_port = 53
remote_port = 6053</code></pre>
<p>一个 udp 代理只占<strong>一条</strong>工作连接，靠访客地址区分会话。</p>

<div class="callout">
<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><path d="M12 16v-4M12 8h.01"/></svg>
<div>
<strong>udp 也受 ACL 约束</strong>
<p>v0.5.9 之前 <code>[acl]</code> 不覆盖 UDP 数据面，任何人发来的 UDP 包都会转给内网服务。第九轮审计修复，现在每个数据报都过 ACL。</p>
</div>
</div>

<h2>http</h2>
<pre><code>[[proxies]]
name = "website"
type = "http"
local_port = 8080
custom_domains = ["app.example.com"]
locations = ["/api", "/static"]
http_user = "visitor"
http_pwd  = "secret"
host_header_rewrite = "127.0.0.1:8080"
request_headers.set = { X-From = "nfrp" }
response_headers.set = { X-Frame-Options = "DENY" }</code></pre>
<p>按域名的 <code>Host</code> 头路由。同一个域名下可以用 <code>locations</code> 做前缀分流。</p>

<h2>https</h2>
<pre><code>[[proxies]]
name = "secure-site"
type = "https"
local_port = 8443
custom_domains = ["secure.example.com"]</code></pre>
<p><strong>只读取 ClientHello 里的 SNI 做路由，不终止 TLS</strong>，证书仍然由内网服务自己提供，服务端全程看不到明文。</p>

<h2>tcpmux</h2>
<pre><code>[[proxies]]
name = "web-tunnel"
type = "tcpmux"
multiplexer = "httpconnect"
custom_domains = ["mux.example.com"]
route_by_http_user = "alice"
local_port = 8080</code></pre>
<p>用 HTTP CONNECT 把多条代理复用到同一个服务端端口上。<code>route_by_http_user</code> 做二级路由（先看域名、再看 <code>Proxy-Authorization</code> 里的用户名）。</p>

<h2>stcp</h2>
<p>私密隧道，服务端<strong>不开任何公网端口</strong>。需要两个客户端配合：provider（在内网提供服务）和 visitor（在外部发起访问）。</p>
<pre><code># provider 侧
[[proxies]]
name = "secret-ssh"
type = "stcp"
secret_key = "长随机串"
allow_users = ["alice"]
local_port = 22

# visitor 侧（另一台机器）
[[visitors]]
name = "visit-secret-ssh"
type = "stcp"
server_name = "secret-ssh"
secret_key = "长随机串"
bind_addr = "127.0.0.1"
bind_port = 6000</code></pre>

<h2>sudp</h2>
<p>与 stcp 同一套鉴权（<code>secret_key</code> + <code>allow_users</code>），数据面换成 UDP。</p>

<h2>xtcp</h2>
<p>先通过服务端交换公网地址（牵线路由），然后两端<strong>直接 UDP 打洞</strong>，数据用 QUIC 或 KCP 直连，<strong>不再经过服务端</strong>。打不通会自动回退成中继。</p>
<pre><code># provider 侧
[[proxies]]
name = "p2p-files"
type = "xtcp"
secret_key = "长随机串"
local_port = 445

# visitor 侧
[[visitors]]
name = "visit-p2p-files"
type = "xtcp"
server_name = "p2p-files"
secret_key = "长随机串"
bind_addr = "127.0.0.1"
bind_port = 4450</code></pre>

<div class="callout">
<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><path d="M12 16v-4M12 8h.01"/></svg>
<div>
<strong>xtcp 需要服务端配 <code>p2p_port</code></strong>
<p>不配就退化成一律走中继（功能正常，只是不经直连）。牵线用的 UDP 端口也要在防火墙上放行。</p>
</div>
</div>
`;

/* ======================== 插件 ======================== */
PAGES_ZH['plugins'] = `
<h1>插件</h1>
<p class="lead">插件让 frpc 本身变成一个 HTTP 转发器或 TLS 终止点，不需要在内网再跑一个完整服务。</p>

<h2>清单</h2>
<div class="table-wrap">
<table>
<thead><tr><th>插件</th><th>入站</th><th>出站</th><th>说明</th></tr></thead>
<tbody>
<tr><td><code>http2http</code></td><td>明文</td><td>明文</td><td>纯 HTTP 转发，补 X-Forwarded-For</td></tr>
<tr><td><code>http2https</code></td><td>明文</td><td>TLS</td><td>内网服务是 HTTPS 时用</td></tr>
<tr><td><code>https2http</code></td><td><strong>TLS</strong></td><td>明文</td><td>frpc 自己当 TLS 服务端，需要证书</td></tr>
<tr><td><code>https2https</code></td><td><strong>TLS</strong></td><td>TLS</td><td>两端都加密</td></tr>
<tr><td><code>tls2raw</code></td><td><strong>TLS</strong></td><td>裸字节</td><td>握手完直接对拷，不解析 HTTP</td></tr>
<tr><td><code>static_file</code></td><td>明文</td><td>本地文件</td><td>直接返回一个目录或文件</td></tr>
<tr><td><code>unix_domain_socket</code></td><td>明文</td><td>UDS</td><td>转发到 Unix socket（Linux）</td></tr>
<tr><td><code>socks5</code></td><td>明文</td><td>SOCKS5</td><td>走上游 SOCKS5 代理</td></tr>
</tbody>
</table>
</div>

<h2>配置示例</h2>
<pre><code>[[proxies]]
name = "my-site"
type = "tcp"
remote_port = 8080
plugin = "https2http"
plugin_local_addr = "127.0.0.1:8080"
plugin_crt_path = "/etc/nfrp/site.crt"
plugin_key_path = "/etc/nfrp/site.key"
plugin_host_header_rewrite = "127.0.0.1:8080"</code></pre>

<h2>安全约束</h2>
<div class="callout danger">
<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><path d="M15 9l-6 6M9 9l6 6"/></svg>
<div>
<strong>服务端下发的代理不允许带插件</strong>
<p>面板（或任何服务端）远程给客户端新增代理时，<code>validate_remote_proxy</code> 会<strong>拒绝任何 <code>plugin*</code> 字段</strong>，并把 <code>local_addr</code> 强制限制为回环地址。<br>
为什么：插件加任意 <code>local_addr</code> 等于让服务端把客户端变成一个通用正向代理，那是第四轮审计的 F1（高危）。</p>
</div>
</div>

<h2>TLS 插件的已知行为</h2>
<ul>
<li><code>https2http</code> / <code>https2https</code> / <code>tls2raw</code> 是 <strong>frpc 自己当 TLS 服务端</strong>，必须给 <code>plugin_crt_path</code> 与 <code>plugin_key_path</code>；不给就拒绝启动，不会静默降级成明文。</li>
<li>收尾会显式发 <code>close_notify</code>，避免对端把截断当成正常结束。</li>
<li>已测过 11 种畸形 ClientHello（截断头、非法 content-type、SSLv2 风格、超长 SNI 等），全部干净拒绝，不会让客户端进程崩掉。</li>
</ul>
`;

/* ======================== 传输层 ======================== */
PAGES_ZH['transports'] = `
<h1>传输层</h1>
<p class="lead">控制连接可以用四种方式承载。选哪种取决于你的网络环境，不取决于功能。</p>

<h2>对比</h2>
<div class="table-wrap">
<table>
<thead><tr><th>传输</th><th>协议</th><th>适合</th><th>代价</th></tr></thead>
<tbody>
<tr><td><code>tcp</code></td><td>TCP</td><td>默认，最稳</td><td>握手特征明显</td></tr>
<tr><td><code>kcp</code></td><td>UDP</td><td>弱网、高丢包</td><td>费流量，有放大风险（见下）</td></tr>
<tr><td><code>quic</code></td><td>UDP + TLS1.3</td><td>移动网络、频繁切换</td><td>需要 UDP 放行</td></tr>
<tr><td><code>websocket</code></td><td>TCP + HTTP/1.1 升级</td><td>过 HTTP 代理 / CDN</td><td>多一层封装</td></tr>
</tbody>
</table>
</div>

<h2>配置</h2>
<pre><code># 客户端
[transport]
protocol = "kcp"

# 服务端要开对应端口
kcpBindPort = 7000
quicBindPort = 7001</code></pre>

<h2>TLS 封装</h2>
<p>TLS 是叠在上面的可选层，四种传输都可以套：</p>
<pre><code>[transport.tls]
enable = true
# 服务端还要：certFile / keyFile
# 客户端校验：verifyServerCert = true + trustedCaFile</code></pre>

<div class="callout warn">
<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M10.29 3.86 1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><path d="M12 9v4M12 17h.01"/></svg>
<div>
<strong>KCP 端口有内存放大的风险</strong>
<p>KCP 是"每个 UDP 源端口一个会话"的模型。第九轮审计发现：<strong>一个 25 字节的包能占 15 KB 内存，放大 312 倍</strong>；3.5 秒发 1.5 万个包就能把内存推到 233 MB。</p>
<p>v0.5.9 已加 <code>MAX_KCP_SESSIONS = 1024</code> 的上限，超出直接丢弃新会话。但<strong>仍然建议不要直接把 KCP 端口敞开在公网</strong>，或者配合 <code>[acl]</code> 限源。</p>
</div>
</div>

<h2>PROXY Protocol</h2>
<p>需要保留真实访客 IP 时，可以在 vhost 入口前挂一层四层负载均衡，并开启 PROXY protocol：</p>
<pre><code>[transport]
proxyProtocolVersion = "v2"   # v1 | v2</code></pre>
<p>v1 是文本头，v2 是二进制头，两者都已实现并测过。</p>
`;

/* ======================== 线协议总览 ======================== */
PAGES_ZH['protocol'] = `
<h1>线协议总览</h1>
<p class="lead">Nfrp 与官方 frp 说同一种语言。这一节讲清它在线上到底发什么、怎么识别版本。</p>

<h2>两条通道</h2>
<div class="cards">
<div class="card">
<div class="card-icon"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M5 12h14M12 5l7 7-7 7"/></svg></div>
<h4>控制连接</h4>
<p>客户端登录后长期保持。承载登录、代理注册、心跳、牵线指令。一条客户端一条。</p>
</div>
<div class="card">
<div class="card-icon"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M8 3v18M16 3v18M3 8h18M3 16h18"/></svg></div>
<h4>工作连接</h4>
<p>访客来了才建，按需索取。承载真正的业务字节。TCP 类代理每个访客一条；UDP 代理复用一条。</p>
</div>
</div>

<h2>版本识别：看首字节</h2>
<p>服务端<strong>不需要预先知道</strong>对端是 v1 还是 v2，它靠首字节自动识别：</p>
<div class="table-wrap">
<table>
<thead><tr><th>首字节</th><th>判定</th><th>后续</th></tr></thead>
<tbody>
<tr><td><code>0x17</code></td><td><strong>v2</strong></td><td>紧接着的魔术字是 <code>FRP\\x00\\x02\\r\\n</code></td></tr>
<tr><td><code>0x12</code></td><td><strong>v1 + TLS</strong></td><td>TLS 握手的第一字节（ClientHello）</td></tr>
<tr><td>其它</td><td><strong>v1 明文</strong></td><td>直接当 <code>[1 字节类型][8 字节大端长度][JSON]</code> 解析</td></tr>
</tbody>
</table>
</div>

<h2>v2 魔术字</h2>
<pre><code>FRP\\x00\\x02\\r\\n</code></pre>
<p>这 8 个字节既能被 v1 实现安全忽略（不会误判成合法长度），也便于抓包快速识别。</p>

<h2>帧格式</h2>
<h3>v1</h3>
<pre><code>[1 字节 type][8 字节 big-endian 长度][payload]
                                   payload 在 v1 是 JSON，或加密载荷</code></pre>

<h3>v2</h3>
<pre><code>[u16 type][u32 big-endian 长度][payload]
           单帧载荷上限 64 KiB，与官方 DefaultMaxFramePayloadSize 一致</code></pre>

<h2>一次典型交互</h2>
<pre><code>客户端                                  服务端
  |--- TCP 连接 ----------------------->|
  |                                     | ACL 判定（认证之前）
  |--- [Login: token + 时间戳] -------->| 验凭证 + 时间窗口
  |&lt;-- [LoginResp: run_id] --------------|
  |--- [NewProxy: 我要 6000 端口] ------>| 开监听
  |&lt;-- [NewProxyResp: ok] ---------------|
  |                                     |
  |        （访客连上 6000）             |
  |&lt;-- [ReqWorkConn] --------------------|
  |--- 新建连接 ------------------------>|
  |--- [NewWorkConn: run_id + 凭证] ---->| 核对来源
  |                                     |
  |&lt;========= 业务字节双向对拷 =========&gt;|
  |                                     |
  |--- [Ping] -------------------------->|
  |&lt;-- [Pong] ---------------------------|</code></pre>

<h2>超时与心跳</h2>
<div class="table-wrap">
<table>
<thead><tr><th>项</th><th>值</th><th>作用</th></tr></thead>
<tbody>
<tr><td>握手超时</td><td>30 秒</td><td>连接建立后必须在 30 秒内完成登录，否则断开</td></tr>
<tr><td>心跳</td><td>30 秒</td><td>控制连接保活</td></tr>
<tr><td>凭证时间窗口</td><td>60 秒</td><td>登录凭证里时间戳允许的偏差，防重放</td></tr>
</tbody>
</table>
</div>

<div class="callout">
<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><path d="M12 16v-4M12 8h.01"/></svg>
<div>
<strong>30 秒握手超时是对抗资源耗尽的第一道防线</strong>
<p>实测灌 10000 条未认证连接时，服务端句柄稳定在约 1.8k，因为超过 30 秒的会被超时清掉，攻击者无法靠"慢慢攒"把连接堆起来。</p>
</div>
</div>
`;

/* ======================== v1 ======================== */
PAGES_ZH['protocol-v1'] = `
<h1>v1 协议与加密</h1>
<p class="lead">v1 是官方 frp 的默认协议。Nfrp 完整实现它，包括那套必须逐字节对齐的加密。</p>

<h2>登录凭证：MD5(token + timestamp)</h2>
<p>客户端不发送明文 token，而是发送：</p>
<pre><code>privilege_key = base64( MD5(token + timestamp_as_u64_le) )</code></pre>
<p>服务端用自己知道的 token 算一遍，再<strong>常量时间比较</strong>。</p>

<div class="callout warn">
<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M10.29 3.86 1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><path d="M12 9v4M12 17h.01"/></svg>
<div>
<strong>MD5 不是我们能选的</strong>
<p>这是 frp 的<strong>线路格式</strong>。改成更强的摘要，官方 frpc 立刻连不上。风险由"时间窗口 + 来源 IP 绑定"来缓解，不是靠换摘要算法。</p>
</div>
</div>

<h2>控制通道加密：PBKDF2 + AES-128-CFB</h2>
<p>密钥派生完全照官方 <code>golib v0.8.2</code>：</p>
<pre><code>pbkdf2.Key(token, []byte("frp"), 64, 16, sha1.New)</code></pre>
<div class="table-wrap">
<table>
<thead><tr><th>参数</th><th>值</th><th>说明</th></tr></thead>
<tbody>
<tr><td>KDF</td><td>PBKDF2-HMAC-SHA1</td><td>无</td></tr>
<tr><td>盐</td><td><code>"frp"</code></td><td><strong>必须是 frp</strong>，见下</td></tr>
<tr><td>迭代</td><td><code>64</code></td><td>官方固定值</td></tr>
<tr><td>派生长度</td><td><code>16</code> 字节</td><td>等于 AES-128 密钥</td></tr>
<tr><td>密码</td><td>AES-128-CFB128</td><td>流密码，无 AEAD</td></tr>
<tr><td>IV</td><td>16 字节 <code>OsRng</code></td><td>每次连接独立随机</td></tr>
</tbody>
</table>
</div>

<div class="callout danger">
<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><path d="M15 9l-6 6M9 9l6 6"/></svg>
<div>
<strong>盐写成 <code>"crypto"</code> 会得到一个"自洽但跟官方不通"的实现</strong>
<p>官方 <code>golib</code> 的 <strong>master 分支</strong>把盐改成了 <code>crypto</code>，但 frp 0.71.0 锁的 <code>golib v0.8.2</code> 用的还是 <code>frp</code>。照 master 写，自己的客户端和服务端能通，但和官方不通，而且很难查。</p>
</div>
</div>

<h2>CFB 实现的一个坑</h2>
<p>加密和解密时，反馈寄存器<strong>都必须填密文</strong>。如果写成"就地翻转、反馈填输出"，解密时会把<strong>明文</strong>喂回寄存器：</p>
<ul>
<li>前 16 字节完全正常（第一个密钥流块来自 IV）</li>
<li>从第 17 字节起整段乱掉</li>
</ul>
<p>症状极像"网络问题"，实际是密码学实现错了。Nfrp 的实现有跨块边界的分段向量测试盯着这一点。</p>

<h2>IV 的安全性</h2>
<p>IV 用 <code>OsRng</code> 生成，每次连接独立，<strong>不存在密钥流复用</strong>。</p>
<p>但 CFB 只提供机密性，<strong>不提供完整性</strong>。所以上层还需要时间戳窗口防重放（见 <a href="#/wire-protocol">线协议总览</a>）。</p>

<h2>什么时候该用 v2</h2>
<p>如果两端都是 Nfrp（或者都支持 v2），<strong>用 v2</strong>。v1 的存在意义是与官方 frp 互通，不是因为它安全。</p>
`;

/* ======================== v2 ======================== */
PAGES_ZH['protocol-v2'] = `
<h1>v2 协议与 AEAD</h1>
<p class="lead">v2 是官方 frp 新增的加密协议。这一层没有历史包袱，用的是现代密码学。</p>

<h2>握手：魔术字 + Hello 交换</h2>
<pre><code>客户端 --- FRP\\x00\\x02\\r\\n ---------------&gt; 服务端
       --- [u16=1 ClientHello] -------------&gt;   算法列表、32 字节随机数
       &lt;-- [u16=2 ServerHello] -------------   选定算法
       &lt;-- [u16=16 Message...] -------------   加密的消息流</code></pre>

<h2>密钥派生</h2>
<pre><code>HKDF-SHA256(
    ikm  = token,
    salt = transcript_hash,
    info = "frp wire v2 crypto transcript"
)</code></pre>
<p><code>transcript_hash</code> 是<strong>之前所有密文的 SHA-256 链</strong>：握手内容被绑进密钥，篡改任何一帧都会导致后续密钥不对。</p>

<h2>帧加密</h2>
<pre><code>stream_nonce (12 字节明文)
  || 每帧：[u32 BE 密文长度][AES-256-GCM 密文 + 16 字节 tag]</code></pre>
<div class="table-wrap">
<table>
<thead><tr><th>项</th><th>值</th></tr></thead>
<tbody>
<tr><td>AEAD</td><td>AES-256-GCM（官方还支持 XChaCha20-Poly1305）</td></tr>
<tr><td>nonce</td><td>12 字节，每帧按大端 +1</td></tr>
<tr><td>AAD</td><td><code>stream_nonce || 长度头</code>，长度字段也被认证</td></tr>
<tr><td>完整性</td><td>每帧 16 字节 tag</td></tr>
</tbody>
</table>
</div>

<h2>相比 v1 好在哪</h2>
<div class="cards">
<div class="card"><div class="card-icon"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M20 6L9 17l-5-5"/></svg></div><h4>真的有完整性</h4><p>AEAD 意味着密文被改一个比特就对不上 tag，不用靠上层猜。</p></div>
<div class="card"><div class="card-icon"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M20 6L9 17l-5-5"/></svg></div><h4>密钥绑定握手</h4><p>transcript 链让中间人改一帧就前功尽弃。</p></div>
<div class="card"><div class="card-icon"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M20 6L9 17l-5-5"/></svg></div><h4>没有弱 KDF</h4><p>HKDF-SHA256，不是 64 轮 PBKDF2-HMAC-SHA1。</p></div>
<div class="card"><div class="card-icon"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M20 6L9 17l-5-5"/></svg></div><h4>帧长有上限</h4><p>单帧 64 KiB，与官方 <code>DefaultMaxFramePayloadSize</code> 一致，避免超大帧撑内存。</p></div>
</div>

<h2>怎么选版本</h2>
<p>服务端<strong>不需要配</strong>版本，靠首字节自动识别，同一端口可以同时接 v1 和 v2 客户端。客户端侧由 <code>[transport]</code> 与实现能力决定，默认走 v1 以兼容官方。</p>
`;

/* ======================== 消息类型 ======================== */
PAGES_ZH['messages'] = `
<h1>消息类型</h1>
<p class="lead">控制通道上跑的全部消息。类型号与官方 frp 一致。</p>

<h2>登录与代理</h2>
<div class="table-wrap">
<table>
<thead><tr><th>值</th><th>名称</th><th>方向</th><th>说明</th></tr></thead>
<tbody>
<tr><td>1</td><td><code>TYPE_LOGIN</code></td><td>C → S</td><td>登录。含 user、privilege_key、timestamp、run_id</td></tr>
<tr><td>2</td><td><code>TYPE_LOGIN_RESP</code></td><td>S → C</td><td>含服务端签发的 run_id、可用能力</td></tr>
<tr><td>3</td><td><code>TYPE_NEW_PROXY</code></td><td>C → S</td><td>注册一个代理</td></tr>
<tr><td>4</td><td><code>TYPE_NEW_PROXY_RESP</code></td><td>S → C</td><td>注册结果（成功给 remote_addr，失败给原因）</td></tr>
<tr><td>5</td><td><code>TYPE_CLOSE_PROXY</code></td><td>C → S</td><td>关闭代理，收回端口</td></tr>
</tbody>
</table>
</div>

<h2>工作连接</h2>
<div class="table-wrap">
<table>
<thead><tr><th>值</th><th>名称</th><th>方向</th><th>说明</th></tr></thead>
<tbody>
<tr><td>6</td><td><code>TYPE_NEW_WORK_CONN</code></td><td>C → S</td><td>工作连接建立后先发这条，带 run_id 与凭证</td></tr>
<tr><td>7</td><td><code>TYPE_REQ_WORK_CONN</code></td><td>S → C</td><td>请求客户端为某个代理开一条工作连接</td></tr>
<tr><td>8</td><td><code>TYPE_START_WORK_CONN</code></td><td>C → S</td><td>这条工作连接开始工作</td></tr>
</tbody>
</table>
</div>

<h2>访客（stcp / sudp / xtcp）</h2>
<div class="table-wrap">
<table>
<thead><tr><th>值</th><th>名称</th><th>说明</th></tr></thead>
<tbody>
<tr><td>9</td><td><code>TYPE_NEW_VISITOR_CONN</code></td><td>visitor 请求连到某个 provider 代理</td></tr>
<tr><td>10</td><td><code>TYPE_NEW_VISITOR_CONN_RESP</code></td><td>服务端回应；拒绝时通常不区分"没这个代理"和"secret_key 错"</td></tr>
</tbody>
</table>
</div>

<h2>心跳与 UDP</h2>
<div class="table-wrap">
<table>
<thead><tr><th>值</th><th>名称</th><th>说明</th></tr></thead>
<tbody>
<tr><td>11</td><td><code>TYPE_PING</code></td><td>心跳，同时触发服务端复核凭证新鲜性</td></tr>
<tr><td>12</td><td><code>TYPE_PONG</code></td><td>心跳回应</td></tr>
<tr><td>13</td><td><code>TYPE_UDP_PACKET</code></td><td>UDP 报文（JSON 编码）</td></tr>
<tr><td>19</td><td><code>TYPE_UDP_PACKET_BINARY</code></td><td>UDP 报文（二进制编码，省带宽）</td></tr>
</tbody>
</table>
</div>

<h2>xtcp 打洞</h2>
<div class="table-wrap">
<table>
<thead><tr><th>值</th><th>名称</th><th>说明</th></tr></thead>
<tbody>
<tr><td>14</td><td><code>TYPE_NAT_HOLE_VISITOR</code></td><td>visitor 请求打洞</td></tr>
<tr><td>15</td><td><code>TYPE_NAT_HOLE_CLIENT</code></td><td>通知 provider 准备打洞</td></tr>
<tr><td>16</td><td><code>TYPE_NAT_HOLE_RESP</code></td><td>打洞结果</td></tr>
<tr><td>17</td><td><code>TYPE_NAT_HOLE_SID</code></td><td>下发会话 id</td></tr>
<tr><td>18</td><td><code>TYPE_NAT_HOLE_REPORT</code></td><td>上报观察到的地址</td></tr>
</tbody>
</table>
</div>

<h2>私有扩展</h2>
<div class="table-wrap">
<table>
<thead><tr><th>值</th><th>名称</th><th>说明</th></tr></thead>
<tbody>
<tr><td>100</td><td><code>TYPE_SERVER_CMD</code></td><td>服务端下发的管理命令（增 / 删代理）。<strong>只有客户端在 LoginResp 里声明能力后才发</strong></td></tr>
<tr><td>101</td><td><code>TYPE_SERVER_CMD_RESP</code></td><td>命令回执</td></tr>
</tbody>
</table>
</div>

<div class="callout">
<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><path d="M12 16v-4M12 8h.01"/></svg>
<div>
<strong>100 / 101 是 Nfrp 私有能力</strong>
<p>官方 frp 没有这两个类型。连着官方 frpc 时这个能力不开启，面板会直接回一句人话错误，而不是干等到超时。</p>
</div>
</div>
`;

/* ======================== 安全模型 ======================== */
PAGES_ZH['security'] = `
<h1>安全模型</h1>
<p class="lead">谁信任谁、在哪一层强制、哪些路径不经认证。这一节是理解其余安全配置的前提。</p>

<h2>五个面</h2>
<div class="table-wrap">
<table>
<thead><tr><th>面</th><th>信任什么</th><th>强制在哪</th><th>未认证路径</th></tr></thead>
<tbody>
<tr><td>控制连接</td><td><code>client_id</code> / <code>user</code> 由客户端自报</td><td>ACL（认证前）+ token / OIDC</td><td>无 token 模式下任何客户端都能登录</td></tr>
<tr><td>工作连接</td><td><code>run_id</code> + 凭证 / 来源 IP</td><td>会话声明的 <code>work_conn_cred</code> 能力 + 来源 IP</td><td>见下</td></tr>
<tr><td>管理面板</td><td>Basic 账号密码</td><td>ACL + 常量时间比较 + 200ms 失败延迟</td><td><code>/api/healthz</code> 按设计免鉴权</td></tr>
<tr><td>xtcp P2P</td><td>visitor 的 secret_key</td><td>派生应答口令 + 来源 IP 绑定</td><td>空 <code>secret_key</code> 直接拒绝</td></tr>
<tr><td>VirtualNet</td><td>客户端名</td><td>注册 token + ACL</td><td>无 token 模式下例外</td></tr>
</tbody>
</table>
</div>

<h2>执行顺序</h2>
<pre><code>ACL  ---&gt;  TLS / v1-v2 握手  ---&gt;  token / OIDC 校验（+ 新鲜性）
  ---&gt;  注册  ---&gt;  按代理的 ACL / RBAC  ---&gt;  数据</code></pre>
<p><strong>ACL 在最前面</strong>，被拒的 IP 连握手都不用花。</p>

<h2>ACL 覆盖的全部数据面入口</h2>
<p>这是十轮审计里反复出问题的地方。当前状态：</p>
<div class="table-wrap">
<table>
<thead><tr><th>入口</th><th>ACL</th><th>何时补的</th></tr></thead>
<tbody>
<tr><td>控制连接</td><td>是</td><td>原始</td></tr>
<tr><td>VNet 注册</td><td>是</td><td>原始</td></tr>
<tr><td>TCP 代理端口</td><td>是</td><td>第七轮（F7-1）</td></tr>
<tr><td>vhost（HTTP / HTTPS / tcpmux）</td><td>是</td><td>第七轮（F7-1）</td></tr>
<tr><td><strong>UDP 代理端口</strong></td><td>是</td><td><strong>第九轮（E9-0，中危）</strong></td></tr>
<tr><td><strong>xtcp 牵线 UDP</strong></td><td>是</td><td><strong>第九轮（E9-1）</strong></td></tr>
<tr><td><strong>管理面板</strong></td><td>是</td><td><strong>第九轮（E9-2）</strong></td></tr>
</tbody>
</table>
</div>
<p>并且有一条<strong>结构不变量测试</strong>守着这件事：<code>server/src</code> 下每个接收外部连接的文件都必须出现真的在调用的 <code>check_ip</code>。将来新增数据面文件却忘了加 ACL，这条测试会直接变红。</p>

<h2>工作连接的凭证</h2>
<p>工作连接每一条都必须证明自己属于某个已登录会话。服务端检查：</p>
<ol>
<li>会话<strong>自己声明过</strong> <code>work_conn_cred</code> 能力，则必须带凭证，<strong>空凭证也拒</strong>。这个声明是客户端登录时写的，攻击者改不了。</li>
<li>没声明能力的旧客户端，退化为"来源 IP 必须等于控制连接的 IP"。</li>
<li>凭证本身还要过时间窗口（60 秒）防重放。</li>
</ol>

<h2>xtcp 打洞的两层校验</h2>
<ol>
<li><strong>派生应答口令</strong>：provider 不用固定的 <code>RTNL-OK</code>，而是从 sid 派生的 64 字节 token。</li>
<li><strong>来源 IP 绑定</strong>：服务端把牵线 HELLO 的来源 IP 与该角色控制连接的 IP 比对，不同就拒绝。</li>
</ol>
<p>这两层是第八轮审计 B-1（高危：牵线劫持）的修复。</p>

<h2>已知的边界（诚实说明）</h2>
<div class="callout warn">
<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M10.29 3.86 1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><path d="M12 9v4M12 17h.01"/></svg>
<div>
<strong>为对齐官方 frp 而保留的设计</strong>
<p>下面这些不是"没修"，是<strong>改了就不通</strong>：</p>
<ul>
<li>v1 用 MD5 做登录凭证，frp 的线路格式</li>
<li>v1 用 64 轮 PBKDF2-HMAC-SHA1 + AES-128-CFB，官方 <code>golib v0.8.2</code> 固定值</li>
<li>客户端 TLS 默认不校验服务端证书，官方 frpc 就是 <code>InsecureSkipVerify</code></li>
<li>xtcp 混合版本时回退到 stcp 中继</li>
</ul>
</div>
</div>
`;

/* ======================== ACL 与 RBAC ======================== */
PAGES_ZH['acl-rbac'] = `
<h1>ACL 与 RBAC</h1>
<p class="lead">ACL 管"谁能连上来"，RBAC 管"连上来的人能做什么"。两者是串行的。</p>

<h2>ACL：IP 白黑名单</h2>
<pre><code>[acl]
allow = ["10.0.0.0/8", "192.168.0.0/16", "2001:db8::/32"]
deny  = ["10.1.2.3"]</code></pre>
<div class="table-wrap">
<table>
<thead><tr><th>规则</th><th>行为</th></tr></thead>
<tbody>
<tr><td>只配 <code>allow</code></td><td>白名单：不在名单里的一律拒</td></tr>
<tr><td>只配 <code>deny</code></td><td>黑名单：名单里的拒，其它放行</td></tr>
<tr><td>两边都配</td><td><strong>deny 优先</strong></td></tr>
<tr><td>都不配</td><td>不限制</td></tr>
</tbody>
</table>
</div>
<p>支持单个 IP 与 CIDR，IPv4 / IPv6 都可以。<strong>在认证之前执行</strong>。</p>

<div class="callout">
<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><path d="M12 16v-4M12 8h.01"/></svg>
<div>
<strong>ACL 覆盖全部数据面，不只是控制面</strong>
<p>第九轮审计之前，<code>[acl]</code> 只保护控制连接、TCP 代理和 vhost，<strong>UDP 代理端口、xtcp 牵线、管理面板都不在内</strong>。也就是说配了 ACL 以为限制了来源，那三个入口其实一直敞开。</p>
<p>现在七个入口全部覆盖，并由一条结构不变量测试守着。</p>
</div>
</div>

<h2>RBAC：角色与权限</h2>
<pre><code>defaultRole = "guest"     # 没有角色匹配时套用
denyUnknown = true        # 或者：直接拒绝

[[roles]]
name = "operator"
users = ["alice", "bob"]
allowManage = true        # 允许被面板管理（增删代理、踢出）
allowVisitors = true      # 允许访问 stcp/xtcp 的 visitor
allowProxyTypes = ["tcp", "http", "https"]
portRange = "20000-30000"
maxProxies = 50</code></pre>

<div class="table-wrap">
<table>
<thead><tr><th>字段</th><th>作用</th></tr></thead>
<tbody>
<tr><td><code>name</code></td><td>角色名</td></tr>
<tr><td><code>users</code></td><td>匹配哪些客户端（任意一个匹配即命中）</td></tr>
<tr><td><code>allowManage</code></td><td>是否允许被面板增删代理、踢出</td></tr>
<tr><td><code>allowVisitors</code></td><td>是否允许作为 visitor 访问私密隧道</td></tr>
<tr><td><code>allowProxyTypes</code></td><td>允许注册的代理类型白名单</td></tr>
<tr><td><code>portRange</code></td><td>允许申请的远端端口范围</td></tr>
<tr><td><code>maxProxies</code></td><td>最多几个代理</td></tr>
</tbody>
</table>
</div>
<p><strong>按顺序匹配，先命中先用</strong>，所以把最具体的角色写在前面。</p>

<h2>两级私密隧道白名单</h2>
<p>stcp / sudp / xtcp 除了 <code>secret_key</code>，还有一层 <code>allow_users</code>：</p>
<pre><code>[[proxies]]
name = "secret-ssh"
type = "stcp"
secret_key = "长随机串"
allow_users = ["alice"]   # 只有 alice 能作为 visitor 连</code></pre>

<h2>为什么 ACL 判定要"常量时间"</h2>
<p>面板 Basic Auth 的比较用的是常量时间比较。普通的 <code>==</code> 会在第一个不同字节处提前返回，攻击者能靠计时差异逐字节猜出密码。</p>
<p>失败时还会额外等 200ms，进一步模糊时序信号。</p>
`;

/* ======================== 审计日志 ======================== */
PAGES_ZH['audit'] = `
<h1>审计日志</h1>
<p class="lead">与普通日志是两条链。普通日志会轮转、会被删；审计是独立的 JSONL，用于事后追责。</p>

<h2>开启</h2>
<pre><code>[audit]
enable = true
path = "/var/log/nfrp/audit.jsonl"
maxEntries = 1000      # 内存里保留多少条（面板可查）
maxFileMB = 64         # 文件轮转阈值，0 表示不轮转</code></pre>
<p>默认<strong>关闭</strong>。不开的时候这些代码不产生任何输出。</p>

<h2>记录哪些事件</h2>
<div class="table-wrap">
<table>
<thead><tr><th>类型</th><th>触发</th></tr></thead>
<tbody>
<tr><td><code>login</code></td><td>客户端登录成功</td></tr>
<tr><td><code>login_denied</code></td><td>登录被拒（凭证错、ACL 拒、时间戳过期、面板 ACL 拒）</td></tr>
<tr><td><code>logout</code></td><td>客户端主动退出</td></tr>
<tr><td><code>proxy_add</code></td><td>代理注册成功（含客户端自己注册的）</td></tr>
<tr><td><code>proxy_remove</code></td><td>代理移除</td></tr>
<tr><td><code>proxy_rejected</code></td><td>代理注册被拒</td></tr>
<tr><td><code>admin_action</code></td><td><strong>面板下发的增 / 删 / 踢</strong></td></tr>
<tr><td><code>config_reload</code></td><td>配置热重载</td></tr>
<tr><td><code>vnet_join</code> / <code>vnet_leave</code></td><td>VirtualNet 加入 / 离开</td></tr>
</tbody>
</table>
</div>

<h2>一条审计记录长什么样</h2>
<pre><code>{
  "ts": 1792415586,
  "kind": "admin_action",
  "ok": true,
  "client": "a1b2c3d4e5f6...",
  "user": "",
  "ip": "",
  "target": "a1b2c3d4e5f6...",
  "detail": "kick: 违规使用"
}</code></pre>

<div class="callout">
<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><path d="M12 16v-4M12 8h.01"/></svg>
<div>
<strong><code>admin_action</code> 是最近才补上的</strong>
<p>在 v0.6.1 之前，<code>admin_action</code> 这个类型常量<strong>定义了但全仓零使用</strong>：面板的增 / 删 / 踢三个操作一条审计都没记，只有普通日志。</p>
<p>踢人是<strong>不可回滚</strong>的操作（客户端所有隧道立刻失效），只留日志等于"查不到谁在什么时候踢了谁"。v0.6.1 修好了，并加了回归测试。</p>
</div>
</div>

<h2>查询</h2>
<p>面板的 v2 API 可以查：</p>
<pre><code>curl -u admin:口令 'http://127.0.0.1:7500/api/v2/audit?kind=admin_action&amp;limit=50'</code></pre>

<h2>轮转</h2>
<p>按大小轮转：超过 <code>maxFileMB</code> 就换文件，保留<strong>上一份</strong>备份（<code>&lt;path&gt;.1</code>），磁盘占用上界约 2 倍。</p>
`;

/* ======================== 安全修复史 ======================== */
PAGES_ZH['changes'] = `
<h1>安全修复史</h1>
<p class="lead">十轮审计、140 项修复、每项都带回归测试与退回验证。这里按轮次列。</p>

<div class="stats">
<div class="stat"><div class="stat-value">10</div><div class="stat-label">轮审计</div></div>
<div class="stat"><div class="stat-value">140</div><div class="stat-label">修复项</div></div>
<div class="stat"><div class="stat-value">785</div><div class="stat-label">测试</div></div>
<div class="stat"><div class="stat-value">0</div><div class="stat-label">未修复高危</div></div>
</div>

<h2>每轮问的问题不一样</h2>
<div class="table-wrap">
<table>
<thead><tr><th>轮次</th><th>版本</th><th>这一轮在问什么</th><th>结果</th></tr></thead>
<tbody>
<tr><td>一</td><td>v0.5.2</td><td>全仓扫一遍，有没有漏洞？</td><td>17 项</td></tr>
<tr><td>二</td><td>v0.5.3</td><td><strong>上一轮新写的防线本身能不能被绕过？</strong></td><td>11 项（含 1 高危）</td></tr>
<tr><td>三</td><td>v0.5.4</td><td>引入外部独立审计报告逐项复核</td><td>24 项（5 高危）</td></tr>
<tr><td>四</td><td>v0.5.5</td><td>按漏洞类别并行深挖 + <strong>每个发现必须打出真实利用</strong></td><td>11 项</td></tr>
<tr><td>五</td><td>v0.5.6</td><td>外部审计总报告（39 条）逐项核实</td><td>39 项</td></tr>
<tr><td>六</td><td>v0.5.7</td><td>只打前五轮没碰过的面（渗透视角）</td><td>8 项（3 高危）</td></tr>
<tr><td>七</td><td>v0.5.8</td><td>HTTP 响应侧 / VNet 键 / 空闲池 / 日志放大 / ACL 覆盖面</td><td>13 项（2 高危）</td></tr>
<tr><td>八</td><td>v0.5.8</td><td>收尾第七轮遗留：xtcp 牵线 / 面板鉴权 / TLS 入站插件</td><td>5 项（1 高危）</td></tr>
<tr><td>九</td><td>v0.5.9</td><td><strong>拿上一版自己写的"未覆盖面"当任务书</strong></td><td>9 项（4 中危）+ 1 加固</td></tr>
<tr><td>十</td><td>v0.5.10</td><td>对已发布产物做全量复扫</td><td>0 新漏洞 / 8 处测试缺陷</td></tr>
<tr><td>十一</td><td>v0.6.0</td><td>引入 Shannon 自主渗透测试器做外部复核</td><td>3 项（其余为对齐官方而保留）</td></tr>
<tr><td>十二</td><td>v0.6.1</td><td>补齐面板管理操作的审计链</td><td>3 项</td></tr>
<tr><td>十三</td><td>v0.6.4</td><td><strong>负载均衡 / KCP / 健康检查与官方 frp 对齐</strong></td><td>特性对齐 + 1 处调度缺陷</td></tr>
<tr><td>十四</td><td>v0.6.4</td><td>外部渗透测试复核：HTTP 语义与安全响应头</td><td>3 项 + 1 处测试 flake</td></tr>
</tbody>
</table>
</div>

<h2>几个值得看的</h2>
<h3>第八轮：xtcp 牵线劫持（高危）</h3>
<p>xtcp 打洞前要先通过服务端交换地址。这个过程原本可以被劫持，攻击者插进牵线流程冒充其中一方。<br>
修复是两层：provider 回<strong>派生应答口令</strong>（不再是固定的 <code>RTNL-OK</code>），服务端把 HELLO 的<strong>来源 IP 绑定到控制连接</strong>。</p>

<h3>第九轮：ACL 的三条缺口（中危）</h3>
<p>上一版的发版总结自己写着"UDP 代理端口、xtcp 牵线 UDP、管理面板不在 ACL 内"。第九轮就把这三条全修了，实测证据是"只改源地址，配置完全相同"的对照实验。</p>

<h3>第九轮：KCP 放大 312 倍（中危）</h3>
<p>代码注释原本写着"1:1 占用，非放大"。实测发现那个算法<strong>只算了会话里堆的数据，漏掉了会话本身的开销</strong>：785 KB 上行能让内存涨 238 MB。<br>
修法是给会话表加 1024 条上限。真正让它不到高危的理由是 KCP 默认不启用。</p>

<h3>第十一轮：三条真发现</h3>
<ul>
<li><strong>面板管理操作零审计</strong>：<code>admin_action</code> 常量定义了但全仓没用</li>
<li><strong><code>forget_session</code> 写好了没接上</strong>：OIDC 的 subject 绑定每个会话泄漏一条</li>
<li><strong>面板 catch 分支没转义</strong>：第五轮 H4 漏掉的路径</li>
</ul>

<h2>方法论：退回验证</h2>
<p>每条修复都做两件事：</p>
<ol>
<li><strong>元验证</strong>：退掉修复，测试必须变红</li>
<li><strong>还原核对</strong>：源码必须按字节还原（sha256 比对）</li>
</ol>
<p>这抓出了一类比"修复无效"更隐蔽的问题：<strong>测试测错了对象</strong>。比如测试丢掉了关键对象的句柄导致永远观察不到目标状态，或退掉修复后因为花括号失配编译失败而被误判成"通过"。</p>

<h2>完整记录</h2>
<p>仓库根目录有全部原始报告：</p>
<ul>
<li><code>SECURITY-FIXES.md</code>，第一到三轮汇总</li>
<li><code>SECURITY-FIXES-ROUND4.md</code> 到 <code>ROUND12.md</code>，各轮独立报告</li>
</ul>
<p><a href="https://github.com/Nu0vo1212/Rust-Frp" target="_blank" rel="noopener">在 GitHub 上查看</a></p>
`;

/* ======================== HTTP API ======================== */
PAGES_ZH['api'] = `
<h1>HTTP API</h1>
<p class="lead">服务端面板与客户端本地界面各有一套 HTTP 接口。</p>

<h2>服务端面板</h2>
<p>默认端口 <code>dashboard_port</code>，Basic Auth 鉴权。</p>
<div class="table-wrap">
<table>
<thead><tr><th>方法</th><th>路径</th><th>鉴权</th><th>说明</th></tr></thead>
<tbody>
<tr><td>GET</td><td><code>/</code></td><td>是</td><td>网页面板</td></tr>
<tr><td>GET</td><td><code>/api/status</code></td><td>是</td><td>完整状态（客户端、代理、访客、端口）</td></tr>
<tr><td>GET</td><td><code>/metrics</code></td><td>是</td><td>Prometheus 指标</td></tr>
<tr><td>GET</td><td><code>/api/healthz</code></td><td><strong>否</strong></td><td>探针，只回 <code>ok</code></td></tr>
<tr><td>POST</td><td><code>/api/proxies/add</code></td><td>是</td><td>给某客户端新增代理</td></tr>
<tr><td>POST</td><td><code>/api/proxies/remove</code></td><td>是</td><td>移除代理</td></tr>
<tr><td>POST</td><td><code>/api/clients/kick</code></td><td>是</td><td>踢出客户端</td></tr>
</tbody>
</table>
</div>

<h2>v2 API</h2>
<p>前缀 <code>/api/v2</code>，统一响应信封。</p>
<pre><code>curl -u admin:口令 http://127.0.0.1:7500/api/v2/status

{
  "api": "v2",
  "data": { ... }
}</code></pre>
<div class="table-wrap">
<table>
<thead><tr><th>路径</th><th>说明</th></tr></thead>
<tbody>
<tr><td><code>/api/v2/status</code></td><td>状态摘要</td></tr>
<tr><td><code>/api/v2/proxies</code></td><td>代理列表（全量列举需显式确认参数）</td></tr>
<tr><td><code>/api/v2/audit</code></td><td>审计事件查询</td></tr>
</tbody>
</table>
</div>

<div class="callout">
<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><path d="M12 16v-4M12 8h.01"/></svg>
<div>
<strong>错误信封是统一的</strong>
<p>所有错误都是 <code>{"error":{"code":"...","message":"..."}}</code>，v2 额外带 <code>"api":"v2"</code> 字段。面板页面本身也能被 ACL 拒绝，被拒时连不上，不是回 403。</p>
</div>
</div>

<h2>客户端本地界面</h2>
<p>由 <code>[webServer]</code> 开启，默认无鉴权时只能绑回环地址。</p>
<div class="table-wrap">
<table>
<thead><tr><th>方法</th><th>路径</th><th>说明</th></tr></thead>
<tbody>
<tr><td>GET</td><td><code>/</code></td><td>网页</td></tr>
<tr><td>GET</td><td><code>/api/status</code></td><td>连接状态与代理列表</td></tr>
<tr><td>GET</td><td><code>/api/proxies</code></td><td>当前隧道</td></tr>
<tr><td>POST</td><td><code>/api/proxies/add</code></td><td>新增（body 是代理 JSON）</td></tr>
<tr><td>POST</td><td><code>/api/proxies/remove</code></td><td>移除（body 是代理名）</td></tr>
<tr><td>POST</td><td><code>/api/stop</code></td><td>停掉客户端</td></tr>
</tbody>
</table>
</div>

<h2>写接口的两道防 CSRF 检查</h2>
<pre><code>curl -u admin:口令 -X POST http://127.0.0.1:7400/api/proxies/add \\
  -H 'X-Nfrp-Client: 1' \\
  -H 'Content-Type: application/json' \\
  -d '{"name":"web","type":"tcp","local_addr":"127.0.0.1:8080","remote_port":6000}'</code></pre>
<div class="table-wrap">
<table>
<thead><tr><th>检查</th><th>规则</th><th>为什么</th></tr></thead>
<tbody>
<tr><td><code>Origin</code></td><td>带了就必须是回环来源，<strong>检查所有同名头</strong></td><td>挡住恶意网页盲打本地接口、DNS rebinding</td></tr>
<tr><td><code>X-Nfrp-Client</code></td><td>写操作必须带（值任意）</td><td>自定义头触发 CORS 预检，本界面不回应预检，跨站写请求发不出来</td></tr>
</tbody>
</table>
</div>
<p>读接口（GET）不受这两条限制，它们没有副作用。</p>
`;

/* ======================== 作为库使用 ======================== */
PAGES_ZH['library'] = `
<h1>作为库使用</h1>
<p class="lead">不跑穿透服务，只用它的协议、配置或加密实现。</p>

<h2>三个 crate</h2>
<div class="table-wrap">
<table>
<thead><tr><th>crate</th><th>用途</th></tr></thead>
<tbody>
<tr><td><code>nfrp-common</code></td><td><strong>协议 / 配置 / 加密 / ACL / 日志</strong>，可当库用</td></tr>
<tr><td><code>nfrp-server</code></td><td>服务端可执行文件</td></tr>
<tr><td><code>nfrp-client</code></td><td>客户端可执行文件</td></tr>
</tbody>
</table>
</div>

<h2>安装</h2>
<pre><code>[dependencies]
nfrp-common = "0.6"</code></pre>

<h2>模块导览</h2>
<div class="table-wrap">
<table>
<thead><tr><th>需求</th><th>模块</th></tr></thead>
<tbody>
<tr><td>读 / 写 frp 的 TOML 配置（含字段名兼容）</td><td><code>config</code> 和 <code>frp_config</code></td></tr>
<tr><td>读老式 <code>frpc.ini</code> / <code>frps.ini</code></td><td><code>frp_legacy</code></td></tr>
<tr><td>自己实现 frp 客户端或服务端</td><td><code>frp</code> 和 <code>frp::msg</code></td></tr>
<tr><td>只做加密</td><td><code>frp::crypto</code>、<code>frp::v1</code>、<code>frp::tls</code></td></tr>
<tr><td>HTTP 请求解析 / 转发（无 Web 框架）</td><td><code>http1</code> 和 <code>http_relay</code></td></tr>
<tr><td>IP 白黑名单 / RBAC / 审计</td><td><code>security</code></td></tr>
<tr><td>日志按天轮转</td><td><code>logfile</code></td></tr>
<tr><td>PROXY protocol v1/v2</td><td><code>proxy_protocol</code></td></tr>
<tr><td>KCP / QUIC / WebSocket 传输</td><td><code>frp::kcp</code>、<code>frp::quic</code>、<code>ws</code></td></tr>
<tr><td>VirtualNet（TUN 设备）</td><td><code>vnet</code></td></tr>
</tbody>
</table>
</div>

<h2>示例：解析一份 frps 配置</h2>
<pre><code>use nfrp_common::config::ServerConfig;

let cfg: ServerConfig = toml::from_str(r#"
    bind_port = 7000
    [auth]
    token = "secret"
"#).unwrap();

assert_eq!(cfg.bind_port, Some(7000));   // 注意：Option&lt;u16&gt;
assert_eq!(cfg.effective_auth().token, "secret");</code></pre>

<div class="callout">
<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><path d="M12 16v-4M12 8h.01"/></svg>
<div>
<strong>字段名是 snake_case</strong>
<p><code>ServerConfig</code> 用 <code>bind_port</code>，不是原版 frp 的 <code>bindPort</code>。后者由 <code>frp_config</code> 那一层负责兼容。</p>
</div>
</div>

<h2>示例：v1 密钥派生（与官方字节级一致）</h2>
<pre><code>use nfrp_common::frp::v1::derive_key;

let key = derive_key(b"my-token");
assert_eq!(key.len(), 16);   // AES-128</code></pre>

<h2>示例：ACL 判定</h2>
<pre><code>use nfrp_common::security::AclConfig;

// 编译后的 ACL 判定是一次遍历
let acl = AclConfig {
    allow: vec!["10.0.0.0/8".into()],
    deny: vec![],
};
// 具体用法见 security 模块文档</code></pre>

<h2>安全说明</h2>
<p>本库忠实实现 frp 协议，因此保留了协议本身的历史设计（v1 的 MD5 凭证、64 轮 PBKDF2 等）。<strong>新代码建议走 v2</strong>。详见 <a href="#/security-model">安全模型</a>。</p>

<h2>链接</h2>
<ul>
<li><a href="https://crates.io/crates/nfrp-common" target="_blank" rel="noopener">crates.io</a></li>
<li><a href="https://docs.rs/nfrp-common" target="_blank" rel="noopener">docs.rs</a>，完整 API 文档</li>
</ul>
`;

/* ======================== 与官方 frp 互通 ======================== */
PAGES_ZH['compat'] = `
<h1>与官方 frp 互通</h1>
<p class="lead">这是这个项目存在的意义。所有设计取舍都围绕它。</p>

<h2>实测矩阵</h2>
<div class="table-wrap">
<table>
<thead><tr><th>组合</th><th>状态</th><th>说明</th></tr></thead>
<tbody>
<tr><td>官方 frpc 连 Nfrp frps</td><td>可用</td><td>默认走 v1，无需改配置</td></tr>
<tr><td>Nfrp frpc 连官方 frps</td><td>可用</td><td>配置键名镜像 frp</td></tr>
<tr><td>Nfrp 两端</td><td>可用</td><td>可选 v2 强加密</td></tr>
</tbody>
</table>
</div>
<p>测试基准：官方 frp <strong>0.71.0</strong>。</p>

<h2>键名映射</h2>
<p>Nfrp 的 <code>ServerConfig</code> / <code>ClientConfig</code> 用 snake_case，官方用 camelCase。兼容层负责桥接：</p>
<div class="table-wrap">
<table>
<thead><tr><th>官方 frp</th><th>Nfrp 原生</th></tr></thead>
<tbody>
<tr><td><code>bindPort</code></td><td><code>bind_port</code></td></tr>
<tr><td><code>serverAddr</code></td><td><code>server_addr</code></td></tr>
<tr><td><code>localIP</code></td><td><code>local_ip</code></td></tr>
<tr><td><code>customDomains</code></td><td><code>custom_domains</code></td></tr>
</tbody>
</table>
</div>
<p>用配置文件时两者都能读（<code>frp_config</code> 层），用库 API 时是 snake_case。</p>

<h2>老式 INI 配置</h2>
<p><code>frpc.ini</code> / <code>frps.ini</code> 也能直接读，由 <code>frp_legacy</code> 模块负责。</p>

<h2>为互通而保留的设计</h2>
<p>下面这些在安全审计里被反复提到，但<strong>改了就不通</strong>：</p>
<div class="table-wrap">
<table>
<thead><tr><th>项</th><th>为什么保留</th></tr></thead>
<tbody>
<tr><td>v1 用 MD5 做凭证</td><td>frp 的线路格式</td></tr>
<tr><td>v1 用 PBKDF2-HMAC-SHA1 64 轮</td><td>官方 <code>golib v0.8.2</code> 固定值；master 分支改过盐，照 master 写会和官方不通</td></tr>
<tr><td>v1 用 AES-128-CFB</td><td>同上</td></tr>
<tr><td>客户端 TLS 默认不校验证书</td><td>官方 frpc 就是 <code>InsecureSkipVerify</code></td></tr>
<tr><td><code>-v</code> 输出 <code>0.71.0</code></td><td>管理面板按版本号判断对端</td></tr>
</tbody>
</table>
</div>

<h2>版本协商</h2>
<p>服务端<strong>不需要配置版本</strong>，靠首字节自动识别 v1 / v2，同一端口同时接两种客户端。</p>

<h2>不支持 / 差异</h2>
<div class="callout warn">
<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M10.29 3.86 1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><path d="M12 9v4M12 17h.01"/></svg>
<div>
<strong>几处诚实的差异</strong>
<ul>
<li><strong>未实现端口敲门</strong>：官方有 knock 特性，Nfrp 没有。</li>
<li><strong>xtcp 混合版本</strong>：两端版本不一致时自动回退成 stcp 中继（功能正常，只是不经直连）。</li>
<li><strong><code>TYPE_SERVER_CMD</code>（100 / 101）是私有扩展</strong>：连着官方 frpc 时该能力不开启，面板会直接报错而不是卡到超时。</li>
</ul>
</div>
</div>
`;

<!-- BEGIN nlink (generated from docs/nlink.md, do not edit) -->
PAGES_ZH['nlink'] = `
<p class="lead" data-i18n="nlink-lead">NLink 是 NFRp 在标准 frp 协议之外的扩展层。它只承载那些 <strong>frp 协议本身没有位置表达</strong>、且 <strong>确实有用户被卡住</strong> 的能力。</p>
<div class="callout">
  <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><path d="M12 16v-4M12 8h.01"/></svg>
  <div>
    <strong>当前状态：已实现（v0.7.0 起，默认关闭）</strong>
    <p>下面列出的能力<strong>均已实现并通过测试</strong>（<code>server/tests/nlink_e2e.rs</code> 的 11 条端到端用例逐项覆盖）。 但 NLink <strong>默认关闭</strong>：服务端与客户端都要显式写 <code>[nlink] enable = true</code> 才生效。 不开启时，行为与 0.6.x 完全一致。</p>
  </div>
</div>
<h2 data-i18n="nlink-s1-h">怎么开启</h2>
<pre class="code-block"><code class="language-toml"># frps 端
[nlink]
enable = true
# features = ["quic", "resume", "trace"]   # 留空 = 只协商、不启用任何一项
quic_listen = "0.0.0.0:7000"               # 留空 = 不开 QUIC
resume_ttl = 30                            # 断线续传保留时长（秒）</code></pre>
<pre class="code-block"><code class="language-toml"># frpc 端
[nlink]
enable = true
resume = true      # 断线后用同一个 connection id 续传
quic = true        # 走 QUIC 连服务端（需服务端开 quic_listen）</code></pre>
<p>官方面（官方 frpc/frps）不认 preamble，会把首字节当成 v1 消息头报错。 客户端捕获到这种失败后<strong>自动回退标准模式并只重试一次</strong>，日志里留一行 warn，隧道照常工作。</p>
<h2 data-i18n="nlink-s2-h">为什么需要扩展层</h2>
<p>frp 的协议是够用的，但它把「传输、会话、鉴权、调度」都固定死了。有些问题不是"实现得不好"，而是 <strong>协议里根本没有承载位置</strong> —— 比如连接迁移需要传输层有独立的连接标识，而 frp 是在 TCP/TLS 之上套 yamux，这个位置不存在。</p>
<h2 data-i18n="nlink-s3-h">准入判断：四个门槛必须同时成立</h2>
<div class="table-wrap">
<table>
<thead><tr>
<th>门槛</th>
<th>含义</th>
</tr></thead>
<tbody>
<tr>
<td><strong>① 协议层无解</strong></td>
<td>不是"frp 实现得差"，而是 <strong>协议本身</strong> 没有字段、没有流程、没有语义可以承载</td>
</tr>
<tr>
<td><strong>② 有明确需求</strong></td>
<td>能说清"谁在什么场景被卡住"，而不是"技术上可以做"</td>
</tr>
<tr>
<td><strong>③ 必须双端</strong></td>
<td>单端升级做不到，或单端做出来是残缺的</td>
</tr>
<tr>
<td><strong>④ 可回退</strong></td>
<td>对端不支持时必须能 <strong>无损退回</strong> 标准 frp</td>
</tr>
</tbody>
</table>
</div>
<p>第 ④ 条是硬门槛。做不到可回退的，不进 NLink。</p>
<h2 data-i18n="nlink-s4-h">候选清单</h2>
<div class="table-wrap">
<table>
<thead><tr>
<th>#</th>
<th>功能</th>
<th>为什么 frp 协议根本解决不了</th>
<th>用户需求场景</th>
</tr></thead>
<tbody>
<tr>
<td>1</td>
<td><strong>原生 QUIC / 多路复用与连接迁移</strong></td>
<td>frp 的传输层是「先建 TCP/TLS，再套 yamux」。连接迁移要求 <strong>连接标识与四元组解耦</strong>，这是传输层语义，在 yamux 之上做不了。QUIC 的 <code>connection_id</code> 在 frp 里没有承载位置。</td>
<td>移动网络切换 Wi-Fi↔4G 时连接全断；弱网下 TCP 队头阻塞导致所有隧道一起卡。</td>
</tr>
<tr>
<td>2</td>
<td><strong>更强的 P2P 打洞信令与 NAT 类型自适应</strong></td>
<td>官方 <code>NatHoleVisitor</code> / <code>NatHoleResp</code> 只承载「行为模式 0~4 + 地址列表」，<strong>没有</strong> 双向持续探测、没有 TTL 探测结果回传、没有失败原因码。打洞失败只能重试或退回中继。</td>
<td>对称 NAT / 双防火墙下的打洞成功率；现在只能"试不成拉倒"。</td>
</tr>
<tr>
<td>3</td>
<td><strong>零信任身份、细粒度流控、端到端可观测性</strong></td>
<td>鉴权是 <strong>连接级一次性</strong>（token / OIDC 登录），没有每请求身份；流控只有 <code>bandwidthLimit</code> 粗粒度；追踪信息不跨段透传。</td>
<td>多租户场景要按代理 / 用户 / 请求维度限流与审计；排障要端到端 trace。</td>
</tr>
<tr>
<td>4</td>
<td><strong>大规模海量连接下的头部开销与调度模型</strong></td>
<td>每条工作连接都要走一次 <code>StartWorkConn</code> JSON 握手。协议里没有 <strong>「批量申请工作连接」</strong> 的语义。</td>
<td>单 frps 承载 5 万+ 连接时，连接建立延迟与内存开销明显。</td>
</tr>
<tr>
<td>5</td>
<td><strong>移动端弱网切换、断线续传</strong></td>
<td>断线后只能 <strong>重连重建代理</strong>，没有「会话恢复」语义（<code>run_id</code> 是登录期生成的，工作连接无法跨断线复用）。续传需要可恢复的流标识 + 服务端保留状态，协议层没有。</td>
<td>地铁 / 电梯 / 切网掉线后，所有隧道重建、长连接业务全断。</td>
</tr>
</tbody>
</table>
</div>
<h2 data-i18n="nlink-s5-h">附带补齐</h2>
<p>下面三项性质与上面五条 <strong>不同</strong>：它们不是"协议无解"，而是需求或兼容性缺口。列出来是为了完整，但按 ① 号门槛严格说，它们不满足"根本解决不了"。</p>
<div class="table-wrap">
<table>
<thead><tr>
<th>项</th>
<th>性质</th>
<th>说明</th>
</tr></thead>
<tbody>
<tr>
<td><strong>端口敲门</strong></td>
<td>需求驱动，<em>非协议无解</em></td>
<td>frp 的端口一旦开放就对外可见，扫描器能发现。敲门是「先敲门再开放」的访问控制模式，可用扩展帧承载敲门序列，通过后临时放行。</td>
</tr>
<tr>
<td><strong>XTCP 混合版本直连策略</strong></td>
<td>兼容性缺口</td>
<td>官方 frpc 与我们并存时，直连能力协商不一致会导致「一方以为能打洞、另一方在等中继」。需要显式的版本 / 能力交集策略。</td>
</tr>
<tr>
<td><strong>与官方双向兼容的边界行为</strong></td>
<td>兼容性澄清</td>
<td>明确列出「官方会忽略哪些字段」「官方会报错哪些」「哪些情况我们比官方更严」，形成可测试的边界用例集。</td>
</tr>
</tbody>
</table>
</div>
<h2 data-i18n="nlink-s6-h">五条硬性工程约束</h2>
<p>这五条是 NLink v1 的设计底线，任何一条不满足就不合入。</p>
<h3 data-i18n="nlink-c1-h">1. 握手期能力协商</h3>
<p>握手阶段交换 capabilities，<strong>双方都支持才启用扩展</strong>，否则自动回退标准 frp 行为。协商在登录 / 握手阶段完成，不额外增加往返；能力用位图 + 版本号表示，<strong>未知位一律忽略</strong>（前向兼容）；协商结果决定本次连接的全部行为，中途不改。</p>
<h3 data-i18n="nlink-c2-h">2. 版本化 TLV / 扩展帧</h3>
<p>扩展帧放在 <strong>独立命名空间</strong>（专用消息类型 / 专用 TLV 编号段），<strong>绝不改变标准帧语义</strong> —— 标准帧的字段、顺序、含义一律不动。TLV 带版本号，对方不认识的 TLV 必须 <strong>跳过而非报错</strong>。扩展帧长度必须自描述，便于跳过。</p>
<h3 data-i18n="nlink-c3-h">3. Feature flag</h3>
<p>默认 <strong>关闭</strong>，或默认 <strong>「仅协商不启用」</strong>（会声明能力、但只在显式开启时才真正使用）。编译期 flag（<code>--features</code>）与运行期开关两层都要有。<strong>关闭时零开销</strong>：不产生额外字段、不改变报文长度。</p>
<h3 data-i18n="nlink-c4-h">4. 双栈共存</h3>
<p><strong>同一端口</strong> 能识别标准 frp 握手与扩展握手；识别依据只能是「标准 frp 不会产生的特征」（首字节 / 魔术字）。扩展握手失败 ⇒ <strong>自动 fallback</strong> 到标准流程，用户无感。</p>
<h3 data-i18n="nlink-c5-h">5. 迁移工具与兼容性矩阵</h3>
<p>提供迁移工具（配置转换、能力检测、兼容性自检），并维护兼容性矩阵，明确标注每个功能的支持情况。矩阵必须 <strong>可测试</strong>：每一行都要有对应的 e2e 用例。</p>
<h2 data-i18n="nlink-s7-h">兼容性矩阵</h2>
<div class="table-wrap">
<table>
<thead><tr>
<th>功能</th>
<th>NFrp × NFrp</th>
<th>NFrp × 官方 frp</th>
<th>官方 × 官方</th>
</tr></thead>
<tbody>
<tr>
<td>原生 QUIC / 连接迁移</td>
<td>支持</td>
<td>回退 TCP</td>
<td>不支持</td>
</tr>
<tr>
<td>增强打洞信令</td>
<td>支持</td>
<td>降级为官方 NatHole</td>
<td>官方行为</td>
</tr>
<tr>
<td>零信任身份 / 细粒度流控</td>
<td>支持</td>
<td>仅 metadata 透传</td>
<td>不支持</td>
</tr>
<tr>
<td>批量工作连接</td>
<td>支持</td>
<td>逐条建</td>
<td>不支持</td>
</tr>
<tr>
<td>断线续传</td>
<td>支持</td>
<td>重连重建</td>
<td>不支持</td>
</tr>
<tr>
<td>端口敲门</td>
<td>支持</td>
<td>不支持</td>
<td>不支持</td>
</tr>
<tr>
<td>XTCP 混合版本直连</td>
<td>支持</td>
<td>需显式策略</td>
<td>官方行为</td>
</tr>
</tbody>
</table>
</div>
<h2 data-i18n="nlink-s8-h">建议的实施顺序</h2>
<p>按「依赖关系 + 风险从低到高」排：</p>
<div class="table-wrap">
<table>
<thead><tr>
<th>阶段</th>
<th>内容</th>
<th>理由</th>
</tr></thead>
<tbody>
<tr>
<td><strong>0. 地基</strong></td>
<td>能力协商 + TLV 框架 + 双栈识别 + feature flag</td>
<td>后面所有功能都挂在这套地基上，必须先做且做对</td>
</tr>
<tr>
<td><strong>1. 低风险</strong></td>
<td>XTCP 混合版本策略、兼容性矩阵与边界用例集</td>
<td>纯策略与测试，不改协议核心，先把兼容性说清楚</td>
</tr>
<tr>
<td><strong>2. 独立</strong></td>
<td>端口敲门、批量工作连接</td>
<td>各自独立、互不依赖，可并行</td>
</tr>
<tr>
<td><strong>3. 打洞</strong></td>
<td>增强信令 + NAT 自适应</td>
<td>依赖打洞实测环境（多网卡 / 可控 NAT）</td>
</tr>
<tr>
<td><strong>4. 传输层</strong></td>
<td>原生 QUIC + 连接迁移</td>
<td>改动最大，地基要稳</td>
</tr>
<tr>
<td><strong>5. 会话</strong></td>
<td>断线续传</td>
<td>依赖服务端保留状态，必须最后做</td>
</tr>
<tr>
<td><strong>6. 可观测</strong></td>
<td>零信任身份 + 细粒度流控 + 端到端 trace</td>
<td>横切面，等前面稳定后再加</td>
</tr>
</tbody>
</table>
</div>
<h2 data-i18n="nlink-s9-h">明确不做</h2>
<div class="table-wrap">
<table>
<thead><tr>
<th>想法</th>
<th>为什么不做</th>
</tr></thead>
<tbody>
<tr>
<td>改标准帧的字段含义</td>
<td>破坏与官方的兼容，违反约束 2</td>
</tr>
<tr>
<td>让扩展成为默认</td>
<td>风险不可控，违反约束 3</td>
</tr>
<tr>
<td>在 yamux 之上模拟连接迁移</td>
<td>语义错了 —— 迁移必须在传输层；模拟出来的东西不解决问题</td>
</tr>
<tr>
<td>把鉴权从「连接级」改成「每帧」</td>
<td>会对不支持的对端产生不兼容；应做成可选扩展</td>
</tr>
<tr>
<td>自定义压缩 / 加密算法</td>
<td>已有 <code>useCompression</code> / <code>useEncryption</code> 与官方逐字节对齐，改算法只会破坏互通</td>
</tr>
</tbody>
</table>
</div>
<h2 data-i18n="nlink-s10-h">每个功能立项时必须回答的问题</h2>
<p>避免做成「技术上很酷但没人用」：</p>
<ol>
<li>现在的 frp 具体卡在哪一步？（要能指到协议字段 / 流程）</li>
<li>谁在什么规模下遇到？（用户画像 + 量化场景）</li>
<li>不做会怎样？（绕路方案的成本）</li>
<li>双端升级的实际成本？（老客户端留存率）</li>
<li>回退路径是什么？回退后功能残缺到什么程度？</li>
<li>怎么证明做成了？（可测试的验收标准）</li>
<li>对官方 frpc 的兼容性影响？（必须是「零影响」或「可协商降级」）</li>
</ol>
`;
<!-- END nlink -->
