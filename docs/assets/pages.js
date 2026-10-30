/* ===========================================================================
   NFrp Docs · Content pages
   ---------------------------------------------------------------------------
   Injected as HTML by app.js instead of being inlined in index.html,
   so index.html stays readable.

   All figures here come from the actual source and audit records,
   not from guesswork.
   =========================================================================== */

const PAGES = {};

/* ======================== Server configuration ======================== */
PAGES['config-server'] = `
<h1>Server configuration</h1>
<p class="lead">Every field in the frps <code>frps.toml</code>. Key names mirror the official frp, so an official config usually works as-is.</p>

<h2>Minimal working config</h2>
<pre><code>bind_addr = "0.0.0.0"
bind_port = 7000

[auth]
token = "at least 16 random characters"</code></pre>

<h2>Core fields</h2>
<div class="table-wrap">
<table>
<thead><tr><th>Field</th><th>Type</th><th>Default</th><th>Notes</th></tr></thead>
<tbody>
<tr><td><code>bind_addr</code></td><td>string</td><td><code>0.0.0.0</code></td><td>Control connection listen address</td></tr>
<tr><td><code>bind_port</code></td><td>u16</td><td><code>7000</code></td><td>Control port; work connections reuse it</td></tr>
<tr><td><code>log_level</code></td><td>string</td><td><code>info</code></td><td>trace, debug, info, warn, error</td></tr>
<tr><td><code>log_to</code></td><td>string</td><td>empty</td><td>Log directory; empty means stdout. Rotates daily</td></tr>
<tr><td><code>log_max_days</code></td><td>u32</td><td><code>3</code></td><td>Days to keep logs</td></tr>
<tr><td><code>allow_insecure_no_auth</code></td><td>bool</td><td><code>false</code></td><td>Must be set explicitly to allow no token on a public bind address</td></tr>
</tbody>
</table>
</div>

<h2>Authentication</h2>
<pre><code>[auth]
method = "token"          # token | oidc
token = "shared secret"

# In OIDC mode:
# issuer = "https://idp.example.com"
# audience = "nfrp"
# additionalScopes = ["groups"]</code></pre>

<div class="callout">
<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><path d="M12 16v-4M12 8h.01"/></svg>
<div>
<strong>The single source of truth for the token is <code>effective_auth()</code></strong>
<p>The modern <code>[auth] token</code> wins, falling back to the legacy top-level <code>token</code>. Only one place in the code decides this, which avoids the historical bug of two places disagreeing.</p>
</div>
</div>

<h2>Admin dashboard</h2>
<pre><code>dashboard_addr = "127.0.0.1"   # loopback only
dashboard_port = 7500
dashboard_user = "admin"
dashboard_pwd  = "use-a-strong-password"</code></pre>

<div class="callout warn">
<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M10.29 3.86 1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><path d="M12 9v4M12 17h.01"/></svg>
<div>
<strong>A non-loopback dashboard requires credentials</strong>
<p>Both <code>dashboard_user</code> and <code>dashboard_pwd</code> must be non-empty to count as having credentials. If either is empty and the bind address is public, the server refuses to start.</p>
</div>
</div>

<p>The dashboard exposes <code>/</code> for the web UI, <code>/api/status</code>, <code>/metrics</code> for Prometheus, <code>/api/healthz</code> as an unauthenticated probe, and <code>/api/v2/*</code> for management.</p>

<h2>Access control (ACL)</h2>
<pre><code>[acl]
allow = ["10.0.0.0/8", "192.168.0.0/16", "2001:db8::/32"]
deny  = ["10.1.2.3"]</code></pre>
<p>Evaluated <strong>before authentication</strong>, so a denied address never even sends a token. deny beats allow. See <a href="#/acl-rbac">ACL and RBAC</a>.</p>

<h2>Roles and permissions (RBAC)</h2>
<pre><code>defaultRole = "guest"
denyUnknown = true

[[roles]]
name = "operator"
users = ["alice"]
allowManage = true          # may be managed from the dashboard
allowProxyTypes = ["tcp", "http", "https"]
portRange = "20000-30000"
maxProxies = 50</code></pre>
<p>Roles match <strong>in order</strong>, first hit wins, so put the most specific role first.</p>

<h2>Audit log</h2>
<pre><code>[audit]
enable = true
path = "/var/log/nfrp/audit.jsonl"
maxEntries = 1000
maxFileMB = 64</code></pre>
<p>Off by default. When enabled it records logins, proxy registration, admin actions (add, remove, kick), config reloads and VNet events. See <a href="#/audit">Audit log</a>.</p>

<h2>Transports</h2>
<pre><code>[transport]
# TLS wrapper
tls.force = true
tls.certFile = "/etc/nfrp/server.crt"
tls.keyFile  = "/etc/nfrp/server.key"

# Additional listeners
kcpBindPort = 7000      # KCP over UDP
quicBindPort = 7001     # QUIC
vhostHTTPSPort = 443    # https proxy entry</code></pre>

<h2>Resource limits</h2>
<div class="table-wrap">
<table>
<thead><tr><th>Field</th><th>Notes</th></tr></thead>
<tbody>
<tr><td><code>max_clients</code></td><td>Maximum concurrent clients</td></tr>
<tr><td><code>max_total_conns</code></td><td>Global user connection cap</td></tr>
<tr><td><code>max_conns_per_client</code></td><td>Per-client connection cap</td></tr>
<tr><td><code>max_proxies_per_client</code></td><td>Per-client proxy cap</td></tr>
<tr><td><code>allow_ports</code></td><td>Allowed remote port ranges, e.g. <code>["20000-30000"]</code></td></tr>
</tbody>
</table>
</div>

<h2>VirtualNet and xtcp</h2>
<pre><code>p2p_port = 7002          # UDP port for xtcp rendezvous; omit to force relay

[vnet]
bindPort = 7003</code></pre>
`;

/* ======================== Client configuration ======================== */
PAGES['config-client'] = `
<h1>Client configuration</h1>
<p class="lead">The frpc <code>frpc.toml</code>. Key names match the official frp, and the legacy <code>frpc.ini</code> is also accepted.</p>

<h2>Minimal working config</h2>
<pre><code>server_addr = "server-address"
server_port = 7000

[auth]
token = "same as the server"

[[proxies]]
name = "ssh"
type = "tcp"
local_ip = "127.0.0.1"
local_port = 22
remote_port = 6000</code></pre>

<h2>Core fields</h2>
<div class="table-wrap">
<table>
<thead><tr><th>Field</th><th>Default</th><th>Notes</th></tr></thead>
<tbody>
<tr><td><code>server_addr</code></td><td>required</td><td>Server address</td></tr>
<tr><td><code>server_port</code></td><td><code>7000</code></td><td>Server control port</td></tr>
<tr><td><code>user</code></td><td>empty</td><td>Tenant name. Proxies are namespaced as <code>{user}.{name}</code></td></tr>
<tr><td><code>login_fail_exit</code></td><td><code>true</code></td><td>Exit the process when the first login fails</td></tr>
<tr><td><code>dial_server_timeout</code></td><td><code>10</code></td><td>Dial timeout in seconds</td></tr>
<tr><td><code>dial_server_keepalive</code></td><td><code>0</code></td><td>TCP keepalive idle seconds; 0 disables</td></tr>
</tbody>
</table>
</div>

<h2>Transports</h2>
<pre><code>[transport]
protocol = "tcp"           # tcp | kcp | quic | websocket

[transport.tls]
enable = true
# verifyServerCert = true  # defaults to false, same as the official frpc
# trustedCaFile = "/etc/nfrp/ca.crt"</code></pre>

<div class="callout warn">
<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M10.29 3.86 1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><path d="M12 9v4M12 17h.01"/></svg>
<div>
<strong>The client does not verify the server certificate by default</strong>
<p>This matches the official frpc, which is <code>InsecureSkipVerify</code>. Verifying by default would break every official frps.<br>
<strong>For your own server, turn verification on</strong>: set <code>verifyServerCert = true</code> and provide <code>trustedCaFile</code>. Note that an official frpc cannot connect once verification is on, which is why this is a self-client plus self-server scenario.</p>
</div>
</div>

<h2>Proxy definitions</h2>
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
<p>Full field list for all eight types: <a href="#/proxies">Proxy types</a>.</p>

<h2>Local admin UI</h2>
<pre><code>[webServer]
addr = "127.0.0.1"
port = 7400
user = "admin"
password = "strong password"</code></pre>
<p>Open <code>http://127.0.0.1:7400</code> to add and remove tunnels at runtime. Write calls require the custom header <code>X-Nfrp-Client: 1</code> (CSRF protection), and <code>Origin</code> must be a loopback origin.</p>

<div class="callout warn">
<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M10.29 3.86 1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><path d="M12 9v4M12 17h.01"/></svg>
<div>
<strong>A non-loopback local UI requires a password</strong>
<p>Same rule as the dashboard: if <code>addr</code> is not loopback and no password is set, the client refuses to start.</p>
</div>
</div>

<h2>Persisting dynamic tunnels</h2>
<pre><code>[store]
path = "/var/lib/nfrp/proxies.json"</code></pre>
<p>Tunnels added from the local UI are stored on disk and restored on restart. <strong>The path comes from the config file and cannot be set remotely by the server</strong>. On restore, dangerous fields (plugin arguments, local resource paths) are validated and offending entries are dropped.</p>

<h2>Command line</h2>
<div class="table-wrap">
<table>
<thead><tr><th>Command</th><th>Effect</th></tr></thead>
<tbody>
<tr><td><code>nfrp-client -c frpc.toml</code></td><td>Start</td></tr>
<tr><td><code>nfrp-client verify -c frpc.toml</code></td><td>Validate the config without starting</td></tr>
<tr><td><code>nfrp-client reload</code></td><td>Reload config in a running instance</td></tr>
<tr><td><code>nfrp-client status</code></td><td>Query runtime status</td></tr>
<tr><td><code>nfrp-client stop</code></td><td>Stop the running instance</td></tr>
</tbody>
</table>
</div>
`;

/* ======================== Proxy types ======================== */
PAGES['proxies'] = `
<h1>Proxy types</h1>
<p class="lead">Eight of them, matching the official frp list exactly. Each moves data differently.</p>

<h2>At a glance</h2>
<div class="table-wrap">
<table>
<thead><tr><th>Type</th><th>Public port</th><th>Traffic via server</th><th>Typical use</th></tr></thead>
<tbody>
<tr><td><code>tcp</code></td><td>yes</td><td>yes</td><td>SSH, databases, any TCP service</td></tr>
<tr><td><code>udp</code></td><td>yes</td><td>yes</td><td>DNS, games, any UDP service</td></tr>
<tr><td><code>http</code></td><td>shared vhost port</td><td>yes</td><td>Websites routed by domain</td></tr>
<tr><td><code>https</code></td><td>shared vhost port</td><td>yes</td><td>Routes on SNI without terminating TLS</td></tr>
<tr><td><code>tcpmux</code></td><td>shared vhost port</td><td>yes</td><td>HTTP CONNECT multiplexing, many proxies, one port</td></tr>
<tr><td><code>stcp</code></td><td>no</td><td>yes (encrypted relay)</td><td>Private services with no public port</td></tr>
<tr><td><code>sudp</code></td><td>no</td><td>yes (encrypted relay)</td><td>Private UDP services</td></tr>
<tr><td><code>xtcp</code></td><td>no</td><td><strong>no</strong> (hole punched)</td><td>Peer-to-peer bulk traffic</td></tr>
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
<p>The simplest one. The server listens on <code>0.0.0.0:6000</code>; when a visitor connects it asks the client for a work connection and splices the two together.</p>

<h2>udp</h2>
<pre><code>[[proxies]]
name = "dns"
type = "udp"
local_ip = "127.0.0.1"
local_port = 53
remote_port = 6053</code></pre>
<p>A udp proxy uses exactly <strong>one</strong> work connection and separates sessions by visitor address.</p>

<div class="callout">
<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><path d="M12 16v-4M12 8h.01"/></svg>
<div>
<strong>udp is subject to ACL too</strong>
<p>Before v0.5.9 the <code>[acl]</code> block did not cover the UDP data plane, so UDP packets from anyone were forwarded to the internal service. Fixed in round nine; every datagram now passes the ACL check.</p>
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
<p>Routes on the <code>Host</code> header. Under one domain, <code>locations</code> splits traffic by prefix.</p>

<h2>https</h2>
<pre><code>[[proxies]]
name = "secure-site"
type = "https"
local_port = 8443
custom_domains = ["secure.example.com"]</code></pre>
<p><strong>Only reads the SNI from ClientHello to route; TLS is never terminated</strong>, so the internal service keeps serving its own certificate and the server never sees plaintext.</p>

<h2>tcpmux</h2>
<pre><code>[[proxies]]
name = "web-tunnel"
type = "tcpmux"
multiplexer = "httpconnect"
custom_domains = ["mux.example.com"]
route_by_http_user = "alice"
local_port = 8080</code></pre>
<p>Multiplexes several proxies onto a single server port using HTTP CONNECT. <code>route_by_http_user</code> adds a second routing level based on the username in <code>Proxy-Authorization</code>.</p>

<h2>stcp</h2>
<p>A private tunnel: the server <strong>opens no public port</strong>. Two clients cooperate, a provider inside the network and a visitor outside.</p>
<pre><code># provider side
[[proxies]]
name = "secret-ssh"
type = "stcp"
secret_key = "long random string"
allow_users = ["alice"]
local_port = 22

# visitor side (another machine)
[[visitors]]
name = "visit-secret-ssh"
type = "stcp"
server_name = "secret-ssh"
secret_key = "long random string"
bind_addr = "127.0.0.1"
bind_port = 6000</code></pre>

<h2>sudp</h2>
<p>Same authentication as stcp (<code>secret_key</code> plus <code>allow_users</code>), with UDP on the data plane.</p>

<h2>xtcp</h2>
<p>Both sides first exchange public addresses through the server (rendezvous), then <strong>punch a UDP hole directly</strong> and carry data over QUIC or KCP <strong>without touching the server</strong>. If punching fails it falls back to a relay automatically.</p>
<pre><code># provider side
[[proxies]]
name = "p2p-files"
type = "xtcp"
secret_key = "long random string"
local_port = 445

# visitor side
[[visitors]]
name = "visit-p2p-files"
type = "xtcp"
server_name = "p2p-files"
secret_key = "long random string"
bind_addr = "127.0.0.1"
bind_port = 4450</code></pre>

<div class="callout">
<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><path d="M12 16v-4M12 8h.01"/></svg>
<div>
<strong>xtcp needs <code>p2p_port</code> on the server</strong>
<p>Without it, xtcp silently degrades to pure relay. The feature works, it just never goes direct. Open that UDP port in your firewall as well.</p>
</div>
</div>
`;

/* ======================== Plugins ======================== */
PAGES['plugins'] = `
<h1>Plugins</h1>
<p class="lead">Plugins turn frpc itself into an HTTP forwarder or a TLS terminator, so you do not need another full service inside the network.</p>

<h2>Available plugins</h2>
<div class="table-wrap">
<table>
<thead><tr><th>Plugin</th><th>Inbound</th><th>Outbound</th><th>Notes</th></tr></thead>
<tbody>
<tr><td><code>http2http</code></td><td>plain</td><td>plain</td><td>Plain HTTP forwarding, adds X-Forwarded-For</td></tr>
<tr><td><code>http2https</code></td><td>plain</td><td>TLS</td><td>For internal services served over HTTPS</td></tr>
<tr><td><code>https2http</code></td><td><strong>TLS</strong></td><td>plain</td><td>frpc is the TLS server; needs a certificate</td></tr>
<tr><td><code>https2https</code></td><td><strong>TLS</strong></td><td>TLS</td><td>Encrypted on both sides</td></tr>
<tr><td><code>tls2raw</code></td><td><strong>TLS</strong></td><td>raw bytes</td><td>Copies bytes after the handshake, no HTTP parsing</td></tr>
<tr><td><code>static_file</code></td><td>plain</td><td>local file</td><td>Serves a directory or a single file</td></tr>
<tr><td><code>unix_domain_socket</code></td><td>plain</td><td>UDS</td><td>Forwards to a Unix socket (Linux)</td></tr>
<tr><td><code>socks5</code></td><td>plain</td><td>SOCKS5</td><td>Goes out through an upstream SOCKS5 proxy</td></tr>
</tbody>
</table>
</div>

<h2>Example</h2>
<pre><code>[[proxies]]
name = "my-site"
type = "tcp"
remote_port = 8080
plugin = "https2http"
plugin_local_addr = "127.0.0.1:8080"
plugin_crt_path = "/etc/nfrp/site.crt"
plugin_key_path = "/etc/nfrp/site.key"
plugin_host_header_rewrite = "127.0.0.1:8080"</code></pre>

<h2>Security constraint</h2>
<div class="callout danger">
<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><path d="M15 9l-6 6M9 9l6 6"/></svg>
<div>
<strong>Server-issued proxies may not carry plugins</strong>
<p>When the dashboard, or any server, adds a proxy to a client remotely, <code>validate_remote_proxy</code> <strong>rejects every <code>plugin*</code> field</strong> and forces <code>local_addr</code> to loopback.<br>
Why: plugin plus an arbitrary <code>local_addr</code> turns the client into a general-purpose forward proxy controlled by the server. That was finding F1 in round four, rated high.</p>
</div>
</div>

<h2>Known TLS plugin behaviour</h2>
<ul>
<li><code>https2http</code>, <code>https2https</code> and <code>tls2raw</code> make <strong>frpc the TLS server</strong> itself, so <code>plugin_crt_path</code> and <code>plugin_key_path</code> are mandatory. Without them the client refuses to start rather than silently degrading to plaintext.</li>
<li>A <code>close_notify</code> is sent explicitly on teardown so the peer does not mistake a truncation for a clean end.</li>
<li>Eleven malformed ClientHello variants (truncated header, bad content type, SSLv2 style, oversized SNI and others) have been tested; all are rejected cleanly without crashing the client.</li>
</ul>
`;

/* ======================== Transports ======================== */
PAGES['transports'] = `
<h1>Transports</h1>
<p class="lead">The control connection can ride on four transports. Which one you pick depends on your network, not on features.</p>

<h2>Comparison</h2>
<div class="table-wrap">
<table>
<thead><tr><th>Transport</th><th>Protocol</th><th>Suited to</th><th>Cost</th></tr></thead>
<tbody>
<tr><td><code>tcp</code></td><td>TCP</td><td>Default, most reliable</td><td>Recognisable handshake</td></tr>
<tr><td><code>kcp</code></td><td>UDP</td><td>Lossy links, high packet loss</td><td>Bandwidth heavy, amplification risk (see below)</td></tr>
<tr><td><code>quic</code></td><td>UDP plus TLS 1.3</td><td>Mobile networks, frequent switching</td><td>Needs UDP open</td></tr>
<tr><td><code>websocket</code></td><td>TCP plus HTTP/1.1 upgrade</td><td>Through HTTP proxies or CDNs</td><td>One more layer</td></tr>
</tbody>
</table>
</div>

<h2>Configuration</h2>
<pre><code># client
[transport]
protocol = "kcp"

# server must listen too
kcpBindPort = 7000
quicBindPort = 7001</code></pre>

<h2>TLS wrapper</h2>
<p>TLS is an optional layer on top and works with all four transports:</p>
<pre><code>[transport.tls]
enable = true
# server also needs certFile / keyFile
# client verification: verifyServerCert = true plus trustedCaFile</code></pre>

<div class="callout warn">
<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M10.29 3.86 1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><path d="M12 9v4M12 17h.01"/></svg>
<div>
<strong>The KCP port carries memory amplification risk</strong>
<p>KCP keeps one session per UDP source port. Round nine measured that <strong>a 25 byte packet can hold 15 KB of memory, a 312x amplification</strong>; 15,000 packets in 3.5 seconds pushed memory to 233 MB.</p>
<p>v0.5.9 added <code>MAX_KCP_SESSIONS = 1024</code>, dropping new sessions beyond that. Even so, <strong>do not expose the KCP port directly to the internet</strong> without something in front of it or an <code>[acl]</code> rule.</p>
</div>
</div>

<h2>PROXY protocol</h2>
<p>When you need the real visitor IP behind a layer-4 load balancer, enable PROXY protocol on the vhost entry:</p>
<pre><code>[transport]
proxyProtocolVersion = "v2"   # v1 | v2</code></pre>
<p>v1 is the text header, v2 the binary one. Both are implemented and tested.</p>
`;

/* ======================== Wire protocol ======================== */
PAGES['protocol'] = `
<h1>Wire protocol</h1>
<p class="lead">NFrp speaks the same language as the official frp. This section covers exactly what goes on the wire and how versions are detected.</p>

<h2>Two kinds of connection</h2>
<div class="cards">
<div class="card">
<div class="card-icon"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M5 12h14M12 5l7 7-7 7"/></svg></div>
<h4>Control connection</h4>
<p>Long lived, opened after login. Carries login, proxy registration, heartbeats and rendezvous commands. One per client.</p>
</div>
<div class="card">
<div class="card-icon"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M8 3v18M16 3v18M3 8h18M3 16h18"/></svg></div>
<h4>Work connection</h4>
<p>Created on demand when a visitor arrives. Carries the actual payload. One per visitor for TCP proxies, reused for UDP.</p>
</div>
</div>

<h2>Version detection: look at the first byte</h2>
<p>The server <strong>does not need to know in advance</strong> whether the peer speaks v1 or v2. It decides from the first byte:</p>
<div class="table-wrap">
<table>
<thead><tr><th>First byte</th><th>Verdict</th><th>What follows</th></tr></thead>
<tbody>
<tr><td><code>0x17</code></td><td><strong>v2</strong></td><td>The magic string <code>FRP\\x00\\x02\\r\\n</code></td></tr>
<tr><td><code>0x12</code></td><td><strong>v1 with TLS</strong></td><td>First byte of a TLS ClientHello</td></tr>
<tr><td>anything else</td><td><strong>v1 plaintext</strong></td><td>Parsed as <code>[1 byte type][8 byte big-endian length][JSON]</code></td></tr>
</tbody>
</table>
</div>

<h2>The v2 magic string</h2>
<pre><code>FRP\\x00\\x02\\r\\n</code></pre>
<p>Those eight bytes are chosen so that a v1 implementation ignores them safely rather than mistaking them for a length, and so packet captures are easy to recognise.</p>

<h2>Frame format</h2>
<h3>v1</h3>
<pre><code>[1 byte type][8 byte big-endian length][payload]
                                   the payload is JSON in v1, or an encrypted blob</code></pre>

<h3>v2</h3>
<pre><code>[u16 type][u32 big-endian length][payload]
           payload capped at 64 KiB per frame, matching DefaultMaxFramePayloadSize</code></pre>

<h2>A typical exchange</h2>
<pre><code>client                                  server
  |--- TCP connect --------------------->|
  |                                      | ACL check (before auth)
  |--- [Login: token + timestamp] ------>| verify credential + time window
  |&lt;-- [LoginResp: run_id] --------------|
  |--- [NewProxy: I want port 6000] ---->| open listener
  |&lt;-- [NewProxyResp: ok] ---------------|
  |                                      |
  |        (a visitor connects to 6000)   |
  |&lt;-- [ReqWorkConn] --------------------|
  |--- new connection ------------------>|
  |--- [NewWorkConn: run_id + cred] ---->| verify source
  |                                      |
  |&lt;========= payload copied both ways ==>|
  |                                      |
  |--- [Ping] -------------------------->|
  |&lt;-- [Pong] ---------------------------|</code></pre>

<h2>Timeouts and heartbeats</h2>
<div class="table-wrap">
<table>
<thead><tr><th>Item</th><th>Value</th><th>Purpose</th></tr></thead>
<tbody>
<tr><td>Handshake timeout</td><td>30 s</td><td>Login must complete within 30 seconds of connecting, otherwise the socket is dropped</td></tr>
<tr><td>Heartbeat</td><td>30 s</td><td>Keeps the control connection alive</td></tr>
<tr><td>Credential window</td><td>60 s</td><td>Allowed clock skew on the login timestamp, prevents replay</td></tr>
</tbody>
</table>
</div>

<div class="callout">
<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><path d="M12 16v-4M12 8h.01"/></svg>
<div>
<strong>The 30 second handshake timeout is the first line of defence against resource exhaustion</strong>
<p>With 10,000 unauthenticated connections poured in, the server held steady at roughly 1,800 handles, because anything older than 30 seconds is reaped. An attacker cannot simply accumulate connections over time.</p>
</div>
</div>
`;

/* ======================== v1 ======================== */
PAGES['protocol-v1'] = `
<h1>v1 protocol and crypto</h1>
<p class="lead">v1 is the official frp default. NFrp implements it completely, including the crypto that must match byte for byte.</p>

<h2>Login credential: MD5(token + timestamp)</h2>
<p>The client never sends the raw token. It sends:</p>
<pre><code>privilege_key = base64( MD5(token + timestamp_as_u64_le) )</code></pre>
<p>The server recomputes it from its own token and compares in <strong>constant time</strong>.</p>

<div class="callout warn">
<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M10.29 3.86 1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><path d="M12 9v4M12 17h.01"/></svg>
<div>
<strong>MD5 is not our choice</strong>
<p>It is the frp <strong>wire format</strong>. Swapping in a stronger digest immediately breaks every official frpc. The risk is mitigated by the time window and source address binding, not by changing the digest.</p>
</div>
</div>

<h2>Control channel crypto: PBKDF2 with AES-128-CFB</h2>
<p>Key derivation follows official <code>golib v0.8.2</code> exactly:</p>
<pre><code>pbkdf2.Key(token, []byte("frp"), 64, 16, sha1.New)</code></pre>
<div class="table-wrap">
<table>
<thead><tr><th>Parameter</th><th>Value</th><th>Notes</th></tr></thead>
<tbody>
<tr><td>KDF</td><td>PBKDF2-HMAC-SHA1</td><td>None</td></tr>
<tr><td>Salt</td><td><code>"frp"</code></td><td><strong>Must be frp</strong>, see below</td></tr>
<tr><td>Iterations</td><td><code>64</code></td><td>Fixed by the official implementation</td></tr>
<tr><td>Derived length</td><td><code>16</code> bytes</td><td>An AES-128 key</td></tr>
<tr><td>Cipher</td><td>AES-128-CFB128</td><td>Stream mode, no AEAD</td></tr>
<tr><td>IV</td><td>16 bytes from <code>OsRng</code></td><td>Fresh per connection</td></tr>
</tbody>
</table>
</div>

<div class="callout danger">
<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><path d="M15 9l-6 6M9 9l6 6"/></svg>
<div>
<strong>Using the salt <code>"crypto"</code> produces a self-consistent implementation that cannot talk to the official one</strong>
<p>The <strong>master branch</strong> of the official <code>golib</code> changed the salt to <code>crypto</code>, but frp 0.71.0 pins <code>golib v0.8.2</code>, which still uses <code>frp</code>. Following master gives you a client and server that talk to each other but never to the official frp, and the failure is very hard to diagnose.</p>
</div>
</div>

<h2>A trap in the CFB implementation</h2>
<p>Both encryption and decryption must feed <strong>ciphertext</strong> into the feedback register. If you write it as an in-place flip and feed the output back, decryption feeds <strong>plaintext</strong> into the register and:</p>
<ul>
<li>the first 16 bytes are perfectly correct, since the first keystream block comes from the IV;</li>
<li>everything from byte 17 onward is garbage.</li>
</ul>
<p>The symptom looks exactly like a network problem, but the bug is in the crypto. Nrp's implementation has segment vectors that cross block boundaries specifically to catch this.</p>

<h2>IV safety</h2>
<p>The IV comes from <code>OsRng</code> and is unique per connection, so <strong>keystream reuse does not occur</strong>.</p>
<p>CFB provides confidentiality only, <strong>not integrity</strong>. Anti-replay therefore relies on the timestamp window at the layer above, see <a href="#/protocol">Wire protocol</a>.</p>

<h2>When to prefer v2</h2>
<p>If both ends are NFrp, or both support v2, <strong>use v2</strong>. v1 exists for interoperability with the official frp, not because it is secure.</p>
`;

/* ======================== v2 ======================== */
PAGES['protocol-v2'] = `
<h1>v2 protocol and AEAD</h1>
<p class="lead">v2 is the newer encrypted protocol from the official frp. This layer has no legacy baggage and uses modern cryptography.</p>

<h2>Handshake: magic string then hello exchange</h2>
<pre><code>client --- FRP\\x00\\x02\\r\\n ----------------> server
       --- [u16=1 ClientHello] -------------->   algorithm list, 32 random bytes
       &lt;-- [u16=2 ServerHello] --------------   chosen algorithm
       &lt;-- [u16=16 Message...] --------------   encrypted message stream</code></pre>

<h2>Key derivation</h2>
<pre><code>HKDF-SHA256(
    ikm  = token,
    salt = transcript_hash,
    info = "frp wire v2 crypto transcript"
)</code></pre>
<p><code>transcript_hash</code> is the <strong>SHA-256 chain over all preceding ciphertext</strong>, which binds the handshake into the key. Tampering with any frame makes every subsequent key wrong.</p>

<h2>Frame encryption</h2>
<pre><code>stream_nonce (12 bytes, plaintext)
  || per frame: [u32 BE ciphertext length][AES-256-GCM ciphertext + 16 byte tag]</code></pre>
<div class="table-wrap">
<table>
<thead><tr><th>Item</th><th>Value</th></tr></thead>
<tbody>
<tr><td>AEAD</td><td>AES-256-GCM (the official one also supports XChaCha20-Poly1305)</td></tr>
<tr><td>nonce</td><td>12 bytes, incremented big-endian per frame</td></tr>
<tr><td>AAD</td><td><code>stream_nonce || length header</code>, so the length field is authenticated too</td></tr>
<tr><td>Integrity</td><td>16 byte tag per frame</td></tr>
</tbody>
</table>
</div>

<h2>How it improves on v1</h2>
<div class="cards">
<div class="card"><div class="card-icon"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M20 6L9 17l-5-5"/></svg></div><h4>Real integrity</h4><p>With AEAD, flipping one bit of ciphertext breaks the tag. No guessing at the layer above.</p></div>
<div class="card"><div class="card-icon"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M20 6L9 17l-5-5"/></svg></div><h4>Keys bound to the handshake</h4><p>The transcript chain means one modified frame invalidates everything after it.</p></div>
<div class="card"><div class="card-icon"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M20 6L9 17l-5-5"/></svg></div><h4>No weak KDF</h4><p>HKDF-SHA256 instead of 64 rounds of PBKDF2-HMAC-SHA1.</p></div>
<div class="card"><div class="card-icon"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M20 6L9 17l-5-5"/></svg></div><h4>Bounded frames</h4><p>64 KiB per frame, matching DefaultMaxFramePayloadSize, so an oversized frame cannot balloon memory.</p></div>
</div>

<h2>Choosing a version</h2>
<p>The server needs <strong>no configuration</strong>. It detects v1 or v2 from the first byte and can serve both on the same port. Client behaviour follows <code>[transport]</code> and implementation capabilities; the default is v1 for official compatibility.</p>
`;

/* ======================== Message types ======================== */
PAGES['messages'] = `
<h1>Message types</h1>
<p class="lead">Every message on the control channel. Type numbers match the official frp.</p>

<h2>Login and proxies</h2>
<div class="table-wrap">
<table>
<thead><tr><th>Value</th><th>Name</th><th>Direction</th><th>Notes</th></tr></thead>
<tbody>
<tr><td>1</td><td><code>TYPE_LOGIN</code></td><td>C to S</td><td>Login with user, privilege_key, timestamp and run_id</td></tr>
<tr><td>2</td><td><code>TYPE_LOGIN_RESP</code></td><td>S to C</td><td>Server issued run_id and available capabilities</td></tr>
<tr><td>3</td><td><code>TYPE_NEW_PROXY</code></td><td>C to S</td><td>Register a proxy</td></tr>
<tr><td>4</td><td><code>TYPE_NEW_PROXY_RESP</code></td><td>S to C</td><td>Result, either remote_addr or a reason</td></tr>
<tr><td>5</td><td><code>TYPE_CLOSE_PROXY</code></td><td>C to S</td><td>Close a proxy and release the port</td></tr>
</tbody>
</table>
</div>

<h2>Work connections</h2>
<div class="table-wrap">
<table>
<thead><tr><th>Value</th><th>Name</th><th>Direction</th><th>Notes</th></tr></thead>
<tbody>
<tr><td>6</td><td><code>TYPE_NEW_WORK_CONN</code></td><td>C to S</td><td>First message on a work connection, carries run_id and credential</td></tr>
<tr><td>7</td><td><code>TYPE_REQ_WORK_CONN</code></td><td>S to C</td><td>Asks the client to open a work connection for a proxy</td></tr>
<tr><td>8</td><td><code>TYPE_START_WORK_CONN</code></td><td>C to S</td><td>The work connection starts carrying traffic</td></tr>
</tbody>
</table>
</div>

<h2>Visitors (stcp, sudp, xtcp)</h2>
<div class="table-wrap">
<table>
<thead><tr><th>Value</th><th>Name</th><th>Notes</th></tr></thead>
<tbody>
<tr><td>9</td><td><code>TYPE_NEW_VISITOR_CONN</code></td><td>A visitor asks to reach a provider proxy</td></tr>
<tr><td>10</td><td><code>TYPE_NEW_VISITOR_CONN_RESP</code></td><td>Server response; refusals do not distinguish missing proxy from wrong secret_key</td></tr>
</tbody>
</table>
</div>

<h2>Heartbeat and UDP</h2>
<div class="table-wrap">
<table>
<thead><tr><th>Value</th><th>Name</th><th>Notes</th></tr></thead>
<tbody>
<tr><td>11</td><td><code>TYPE_PING</code></td><td>Heartbeat, also triggers a credential freshness check</td></tr>
<tr><td>12</td><td><code>TYPE_PONG</code></td><td>Heartbeat reply</td></tr>
<tr><td>13</td><td><code>TYPE_UDP_PACKET</code></td><td>UDP datagram, JSON encoded</td></tr>
<tr><td>19</td><td><code>TYPE_UDP_PACKET_BINARY</code></td><td>UDP datagram, binary encoded to save bandwidth</td></tr>
</tbody>
</table>
</div>

<h2>xtcp hole punching</h2>
<div class="table-wrap">
<table>
<thead><tr><th>Value</th><th>Name</th><th>Notes</th></tr></thead>
<tbody>
<tr><td>14</td><td><code>TYPE_NAT_HOLE_VISITOR</code></td><td>Visitor requests hole punching</td></tr>
<tr><td>15</td><td><code>TYPE_NAT_HOLE_CLIENT</code></td><td>Provider is told to get ready</td></tr>
<tr><td>16</td><td><code>TYPE_NAT_HOLE_RESP</code></td><td>Punching result</td></tr>
<tr><td>17</td><td><code>TYPE_NAT_HOLE_SID</code></td><td>Session id assignment</td></tr>
<tr><td>18</td><td><code>TYPE_NAT_HOLE_REPORT</code></td><td>Reports the observed address</td></tr>
</tbody>
</table>
</div>

<h2>Private extensions</h2>
<div class="table-wrap">
<table>
<thead><tr><th>Value</th><th>Name</th><th>Notes</th></tr></thead>
<tbody>
<tr><td>100</td><td><code>TYPE_SERVER_CMD</code></td><td>Admin command from the server (add or remove a proxy). <strong>Only sent when the client advertised the capability in LoginResp</strong></td></tr>
<tr><td>101</td><td><code>TYPE_SERVER_CMD_RESP</code></td><td>Command acknowledgement</td></tr>
</tbody>
</table>
</div>

<div class="callout">
<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><path d="M12 16v-4M12 8h.01"/></svg>
<div>
<strong>100 and 101 are NFrp-private</strong>
<p>The official frp has no such types. When connected to an official frpc the capability stays off, and the dashboard returns a plain error instead of hanging until timeout.</p>
</div>
</div>
`;

/* ======================== Security model ======================== */
PAGES['security'] = `
<h1>Security model</h1>
<p class="lead">Who trusts whom, where enforcement happens, and which paths skip authentication. This section is the prerequisite for every other security setting.</p>

<h2>The five surfaces</h2>
<div class="table-wrap">
<table>
<thead><tr><th>Surface</th><th>What is trusted</th><th>Enforced at</th><th>Unauthenticated path</th></tr></thead>
<tbody>
<tr><td>Control connection</td><td><code>client_id</code> and <code>user</code>, self asserted</td><td>ACL (pre-auth) plus token or OIDC</td><td>In no-token mode any client can log in</td></tr>
<tr><td>Work connections</td><td><code>run_id</code> plus credential or source IP</td><td>The <code>work_conn_cred</code> capability declared by the session, plus source IP</td><td>See below</td></tr>
<tr><td>Admin dashboard</td><td>HTTP Basic credentials</td><td>ACL, constant-time compare, 200 ms failure delay</td><td><code>/api/healthz</code> is unauthenticated by design</td></tr>
<tr><td>xtcp P2P</td><td>Visitor secret_key</td><td>Derived response token plus source IP binding</td><td>An empty <code>secret_key</code> is rejected</td></tr>
<tr><td>VirtualNet</td><td>Client name</td><td>Registration token plus ACL</td><td>Except in no-token mode</td></tr>
</tbody>
</table>
</div>

<h2>Enforcement order</h2>
<pre><code>ACL  ---->  TLS / v1-v2 handshake  ---->  token / OIDC check (+ freshness)
  ---->  registration  ---->  per-proxy ACL / RBAC  ---->  data</code></pre>
<p><strong>ACL comes first</strong>, so a denied address never spends a handshake.</p>

<h2>Every data-plane entry covered by ACL</h2>
<p>This is where ten rounds of auditing kept finding problems. Current state:</p>
<div class="table-wrap">
<table>
<thead><tr><th>Entry point</th><th>ACL</th><th>When added</th></tr></thead>
<tbody>
<tr><td>Control connection</td><td>yes</td><td>original</td></tr>
<tr><td>VNet registration</td><td>yes</td><td>original</td></tr>
<tr><td>TCP proxy ports</td><td>yes</td><td>round seven (F7-1)</td></tr>
<tr><td>vhost (HTTP, HTTPS, tcpmux)</td><td>yes</td><td>round seven (F7-1)</td></tr>
<tr><td><strong>UDP proxy ports</strong></td><td>yes</td><td><strong>round nine (E9-0, medium)</strong></td></tr>
<tr><td><strong>xtcp rendezvous UDP</strong></td><td>yes</td><td><strong>round nine (E9-1)</strong></td></tr>
<tr><td><strong>Admin dashboard</strong></td><td>yes</td><td><strong>round nine (E9-2)</strong></td></tr>
</tbody>
</table>
</div>
<p>A <strong>structural invariant test</strong> guards this: every file under <code>server/src</code> that accepts external connections must contain an actual call to <code>check_ip</code>. If someone adds a data-plane file without ACL later, that test turns red immediately.</p>

<h2>Work connection credentials</h2>
<p>Every work connection must prove it belongs to a logged-in session. The server checks:</p>
<ol>
<li>If the session <strong>itself declared</strong> the <code>work_conn_cred</code> capability, a credential is mandatory and <strong>an empty one is rejected</strong>. That declaration was written at login and cannot be altered by an attacker.</li>
<li>Older clients without the capability fall back to requiring the source IP to equal the control connection IP.</li>
<li>The credential itself must also pass the 60 second time window, preventing replay.</li>
</ol>

<h2>Two layers of xtcp verification</h2>
<ol>
<li><strong>Derived response token</strong>: the provider does not answer with the fixed <code>RTNL-OK</code> but with a 64 byte token derived from the session id.</li>
<li><strong>Source IP binding</strong>: the server compares the rendezvous HELLO source IP against that role's control connection IP and refuses on mismatch.</li>
</ol>
<p>These two layers are the fix for round eight finding B-1, high severity rendezvous hijacking.</p>

<h2>Known boundaries, stated honestly</h2>
<div class="callout warn">
<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M10.29 3.86 1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><path d="M12 9v4M12 17h.01"/></svg>
<div>
<strong>Designs kept for official frp compatibility</strong>
<p>These are not unfixed bugs. Changing them breaks interoperability:</p>
<ul>
<li>v1 uses MD5 for the login credential, which is the frp wire format</li>
<li>v1 uses 64 rounds of PBKDF2-HMAC-SHA1 with AES-128-CFB, fixed by <code>golib v0.8.2</code></li>
<li>The client does not verify the server certificate by default, matching the official frpc</li>
<li>Mixed xtcp versions fall back to stcp relay</li>
</ul>
</div>
</div>
`;

/* ======================== ACL and RBAC ======================== */
PAGES['acl-rbac'] = `
<h1>ACL and RBAC</h1>
<p class="lead">ACL governs who may connect. RBAC governs what a connected client may do. They run in sequence.</p>

<h2>ACL: IP allow and deny lists</h2>
<pre><code>[acl]
allow = ["10.0.0.0/8", "192.168.0.0/16", "2001:db8::/32"]
deny  = ["10.1.2.3"]</code></pre>
<div class="table-wrap">
<table>
<thead><tr><th>Configuration</th><th>Behaviour</th></tr></thead>
<tbody>
<tr><td>Only <code>allow</code></td><td>Allow list: anything not listed is refused</td></tr>
<tr><td>Only <code>deny</code></td><td>Deny list: listed addresses refused, others allowed</td></tr>
<tr><td>Both</td><td><strong>deny wins</strong></td></tr>
<tr><td>Neither</td><td>No restriction</td></tr>
</tbody>
</table>
</div>
<p>Single addresses and CIDR ranges are supported, for IPv4 and IPv6. <strong>Evaluated before authentication.</strong></p>

<div class="callout">
<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><path d="M12 16v-4M12 8h.01"/></svg>
<div>
<strong>ACL covers the whole data plane, not just the control plane</strong>
<p>Before round nine, <code>[acl]</code> only protected the control connection, TCP proxies and vhost, while <strong>UDP proxy ports, xtcp rendezvous and the admin dashboard were outside it</strong>. Operators configured ACL believing they had restricted access, when those three entry points were wide open the whole time.</p>
<p>All seven entries are covered now, and a structural invariant test keeps it that way.</p>
</div>
</div>

<h2>RBAC: roles and permissions</h2>
<pre><code>defaultRole = "guest"     # applied when no role matches
denyUnknown = true        # or reject outright

[[roles]]
name = "operator"
users = ["alice", "bob"]
allowManage = true        # may be managed from the dashboard
allowVisitors = true      # may act as a visitor for stcp and xtcp
allowProxyTypes = ["tcp", "http", "https"]
portRange = "20000-30000"
maxProxies = 50</code></pre>

<div class="table-wrap">
<table>
<thead><tr><th>Field</th><th>Purpose</th></tr></thead>
<tbody>
<tr><td><code>name</code></td><td>Role name</td></tr>
<tr><td><code>users</code></td><td>Which clients match; any single match is enough</td></tr>
<tr><td><code>allowManage</code></td><td>Whether the dashboard may add, remove proxies or kick this client</td></tr>
<tr><td><code>allowVisitors</code></td><td>Whether the client may act as a visitor on private tunnels</td></tr>
<tr><td><code>allowProxyTypes</code></td><td>Allow list of proxy types the client may register</td></tr>
<tr><td><code>portRange</code></td><td>Allowed remote port range</td></tr>
<tr><td><code>maxProxies</code></td><td>Maximum number of proxies</td></tr>
</tbody>
</table>
</div>
<p><strong>Roles match in order, first hit wins</strong>, so list the most specific role first.</p>

<h2>Two-level allow list for private tunnels</h2>
<p>stcp, sudp and xtcp have <code>allow_users</code> on top of <code>secret_key</code>:</p>
<pre><code>[[proxies]]
name = "secret-ssh"
type = "stcp"
secret_key = "long random string"
allow_users = ["alice"]   # only alice may connect as a visitor</code></pre>

<h2>Why ACL comparisons are constant time</h2>
<p>Dashboard Basic Auth uses a constant-time comparison. A plain <code>==</code> returns early at the first differing byte, letting an attacker recover the password byte by byte from timing differences.</p>
<p>On failure the handler also waits an additional 200 ms, further blurring the timing signal.</p>
`;

/* ======================== Audit log ======================== */
PAGES['audit'] = `
<h1>Audit log</h1>
<p class="lead">Separate from normal logging. Normal logs rotate and get deleted; the audit trail is an independent JSONL stream for accountability.</p>

<h2>Enabling it</h2>
<pre><code>[audit]
enable = true
path = "/var/log/nfrp/audit.jsonl"
maxEntries = 1000      # entries kept in memory for dashboard queries
maxFileMB = 64         # rotation threshold, 0 disables</code></pre>
<p>Off by default. When it is off, none of this code produces any output.</p>

<h2>What gets recorded</h2>
<div class="table-wrap">
<table>
<thead><tr><th>Kind</th><th>Trigger</th></tr></thead>
<tbody>
<tr><td><code>login</code></td><td>A client logged in successfully</td></tr>
<tr><td><code>login_denied</code></td><td>Login refused: bad credential, ACL, stale timestamp, dashboard ACL</td></tr>
<tr><td><code>logout</code></td><td>Client disconnected itself</td></tr>
<tr><td><code>proxy_add</code></td><td>Proxy registered, including client-initiated ones</td></tr>
<tr><td><code>proxy_remove</code></td><td>Proxy removed</td></tr>
<tr><td><code>proxy_rejected</code></td><td>Proxy registration refused</td></tr>
<tr><td><code>admin_action</code></td><td><strong>Dashboard add, remove and kick</strong></td></tr>
<tr><td><code>config_reload</code></td><td>Configuration hot reload</td></tr>
<tr><td><code>vnet_join</code> / <code>vnet_leave</code></td><td>VirtualNet join and leave</td></tr>
</tbody>
</table>
</div>

<h2>What a record looks like</h2>
<pre><code>{
  "ts": 1792415586,
  "kind": "admin_action",
  "ok": true,
  "client": "a1b2c3d4e5f6...",
  "user": "",
  "ip": "",
  "target": "a1b2c3d4e5f6...",
  "detail": "kick: policy violation"
}</code></pre>

<div class="callout">
<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><path d="M12 16v-4M12 8h.01"/></svg>
<div>
<strong><code>admin_action</code> is a recent addition</strong>
<p>Before v0.6.1 the <code>admin_action</code> kind constant <strong>existed but was used nowhere in the codebase</strong>. Dashboard add, remove and kick recorded nothing in the audit trail at all, only ordinary logs.</p>
<p>Kicking is <strong>irreversible</strong>, it instantly kills every tunnel the client owns, so leaving only a log entry means you cannot answer who kicked whom and when. Fixed in v0.6.1, with a regression test.</p>
</div>
</div>

<h2>Querying</h2>
<p>The dashboard v2 API can query it:</p>
<pre><code>curl -u admin:password 'http://127.0.0.1:7500/api/v2/audit?kind=admin_action&amp;limit=50'</code></pre>

<h2>Rotation</h2>
<p>Size based: once <code>maxFileMB</code> is exceeded the file is rolled, keeping <strong>one</strong> previous copy (<code>&lt;path&gt;.1</code>), so disk usage is bounded at roughly twice the threshold.</p>
`;

/* ======================== Security history ======================== */
PAGES['changes'] = `
<h1>Security history</h1>
<p class="lead">Ten rounds of auditing, 140 fixes, each with a regression test and a revert check. Listed by round.</p>

<div class="stats">
<div class="stat"><div class="stat-value">10</div><div class="stat-label">Audit rounds</div></div>
<div class="stat"><div class="stat-value">140</div><div class="stat-label">Fixes</div></div>
<div class="stat"><div class="stat-value">757</div><div class="stat-label">Tests</div></div>
<div class="stat"><div class="stat-value">0</div><div class="stat-label">Open high severity</div></div>
</div>

<h2>Each round asked a different question</h2>
<div class="table-wrap">
<table>
<thead><tr><th>Round</th><th>Version</th><th>The question it asked</th><th>Result</th></tr></thead>
<tbody>
<tr><td>1</td><td>v0.5.2</td><td>Sweep the repo, are there vulnerabilities?</td><td>17 items</td></tr>
<tr><td>2</td><td>v0.5.3</td><td><strong>Can the defences written in the previous round be bypassed?</strong></td><td>11 items (1 high)</td></tr>
<tr><td>3</td><td>v0.5.4</td><td>Verify an external audit report item by item</td><td>24 items (5 high)</td></tr>
<tr><td>4</td><td>v0.5.5</td><td>Parallel deep dives by vulnerability class, <strong>every finding needed a real exploit</strong></td><td>11 items</td></tr>
<tr><td>5</td><td>v0.5.6</td><td>Reconcile an external summary of 39 findings</td><td>39 items</td></tr>
<tr><td>6</td><td>v0.5.7</td><td>Only attack surfaces untouched by rounds one to five</td><td>8 items (3 high)</td></tr>
<tr><td>7</td><td>v0.5.8</td><td>HTTP response side, VNet keys, idle pool, log amplification, ACL coverage</td><td>13 items (2 high)</td></tr>
<tr><td>8</td><td>v0.5.8</td><td>Close out round seven leftovers: xtcp rendezvous, dashboard auth, TLS inbound plugins</td><td>5 items (1 high)</td></tr>
<tr><td>9</td><td>v0.5.9</td><td><strong>Treat the previous version's own uncovered-areas list as the task sheet</strong></td><td>9 items (4 medium) plus 1 hardening</td></tr>
<tr><td>10</td><td>v0.5.10</td><td>Full rescan of the shipped artifacts</td><td>0 new vulnerabilities, 8 test defects</td></tr>
</tbody>
</table>
</div>

<h2>A few worth reading</h2>
<h3>Round 8: xtcp rendezvous hijacking (high)</h3>
<p>Before punching a hole, xtcp exchanges addresses through the server. That exchange could be hijacked, letting an attacker insert themselves and impersonate one side.<br>
The fix has two layers: the provider answers with a <strong>derived response token</strong> instead of the fixed <code>RTNL-OK</code>, and the server <strong>binds the HELLO source IP to the control connection</strong>.</p>

<h3>Round 9: three ACL gaps (medium)</h3>
<p>The previous release notes admitted that UDP proxy ports, xtcp rendezvous UDP and the admin dashboard sat outside ACL. Round nine fixed all three, with evidence from a controlled experiment holding the config identical and changing only the source address.</p>

<h3>Round 9: KCP amplification of 312x (medium)</h3>
<p>A code comment claimed one-to-one memory use and no amplification. Measurement showed the calculation <strong>counted only data queued inside a session and missed the session overhead itself</strong>: 757 KB of upstream traffic grew memory by 238 MB.<br>
The fix caps the session table at 1024 entries. What kept this from being high severity is that KCP is not enabled by default.</p>

<h3>Round 11: three genuine findings</h3>
<ul>
<li><strong>Zero audit coverage for admin actions</strong>: the <code>admin_action</code> kind existed but was never used</li>
<li><strong><code>forget_session</code> implemented but never wired up</strong>: OIDC subject bindings leaked one entry per session</li>
<li><strong>Unescaped dashboard catch branch</strong>: a path round five's H4 fix missed</li>
</ul>

<h2>Methodology: revert verification</h2>
<p>Every fix does two things:</p>
<ol>
<li><strong>Meta-verification</strong>: remove the fix, the test must turn red</li>
<li><strong>Restore check</strong>: the source must come back byte for byte (sha256 compared)</li>
</ol>
<p>This caught a class of problem more insidious than an ineffective fix: <strong>a test that measures the wrong thing</strong>. For example a test dropping the handle of the very object it needed to observe, or a revert that failed to compile due to a brace mismatch and was misread as a pass.</p>

<h2>Full records</h2>
<p>The raw reports live in the repository root:</p>
<ul>
<li><code>SECURITY-FIXES.md</code> for rounds one to three</li>
<li><code>SECURITY-FIXES-ROUND4.md</code> through <code>ROUND12.md</code> for the rest</li>
</ul>
<p><a href="https://github.com/Nu0vo1212/Rust-Frp" target="_blank" rel="noopener">View on GitHub</a></p>
`;

/* ======================== HTTP API ======================== */
PAGES['api'] = `
<h1>HTTP API</h1>
<p class="lead">The server dashboard and the client local UI each expose their own HTTP surface.</p>

<h2>Server dashboard</h2>
<p>Listens on <code>dashboard_port</code>, uses HTTP Basic auth.</p>
<div class="table-wrap">
<table>
<thead><tr><th>Method</th><th>Path</th><th>Auth</th><th>Notes</th></tr></thead>
<tbody>
<tr><td>GET</td><td><code>/</code></td><td>yes</td><td>Web dashboard</td></tr>
<tr><td>GET</td><td><code>/api/status</code></td><td>yes</td><td>Full state: clients, proxies, visitors, ports</td></tr>
<tr><td>GET</td><td><code>/metrics</code></td><td>yes</td><td>Prometheus metrics</td></tr>
<tr><td>GET</td><td><code>/api/healthz</code></td><td><strong>no</strong></td><td>Probe, returns <code>ok</code></td></tr>
<tr><td>POST</td><td><code>/api/proxies/add</code></td><td>yes</td><td>Add a proxy to a client</td></tr>
<tr><td>POST</td><td><code>/api/proxies/remove</code></td><td>yes</td><td>Remove a proxy</td></tr>
<tr><td>POST</td><td><code>/api/clients/kick</code></td><td>yes</td><td>Kick a client</td></tr>
</tbody>
</table>
</div>

<h2>v2 API</h2>
<p>Prefixed with <code>/api/v2</code>, with a uniform response envelope.</p>
<pre><code>curl -u admin:password http://127.0.0.1:7500/api/v2/status

{
  "api": "v2",
  "data": { ... }
}</code></pre>
<div class="table-wrap">
<table>
<thead><tr><th>Path</th><th>Notes</th></tr></thead>
<tbody>
<tr><td><code>/api/v2/status</code></td><td>State summary</td></tr>
<tr><td><code>/api/v2/proxies</code></td><td>Proxy listing; a full enumeration requires an explicit confirmation parameter</td></tr>
<tr><td><code>/api/v2/audit</code></td><td>Audit event queries</td></tr>
</tbody>
</table>
</div>

<div class="callout">
<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><path d="M12 16v-4M12 8h.01"/></svg>
<div>
<strong>Errors share one envelope</strong>
<p>Every error is <code>{"error":{"code":"...","message":"..."}}</code>, with v2 adding an <code>"api":"v2"</code> field. The dashboard itself is also subject to ACL: a denied address cannot connect at all rather than receiving a 403.</p>
</div>
</div>

<h2>Client local UI</h2>
<p>Enabled by <code>[webServer]</code>. Without a password it can only bind to loopback.</p>
<div class="table-wrap">
<table>
<thead><tr><th>Method</th><th>Path</th><th>Notes</th></tr></thead>
<tbody>
<tr><td>GET</td><td><code>/</code></td><td>Web page</td></tr>
<tr><td>GET</td><td><code>/api/status</code></td><td>Connection state and proxy list</td></tr>
<tr><td>GET</td><td><code>/api/proxies</code></td><td>Current tunnels</td></tr>
<tr><td>POST</td><td><code>/api/proxies/add</code></td><td>Add, body is the proxy JSON</td></tr>
<tr><td>POST</td><td><code>/api/proxies/remove</code></td><td>Remove, body is the proxy name</td></tr>
<tr><td>POST</td><td><code>/api/stop</code></td><td>Stop the client</td></tr>
</tbody>
</table>
</div>

<h2>Two CSRF checks on write endpoints</h2>
<pre><code>curl -u admin:password -X POST http://127.0.0.1:7400/api/proxies/add \\
  -H 'X-Nfrp-Client: 1' \\
  -H 'Content-Type: application/json' \\
  -d '{"name":"web","type":"tcp","local_addr":"127.0.0.1:8080","remote_port":6000}'</code></pre>
<div class="table-wrap">
<table>
<thead><tr><th>Check</th><th>Rule</th><th>Why</th></tr></thead>
<tbody>
<tr><td><code>Origin</code></td><td>If present it must be a loopback origin; <strong>all headers of that name are inspected</strong></td><td>Blocks a malicious page blind-firing the local API, and DNS rebinding</td></tr>
<tr><td><code>X-Nfrp-Client</code></td><td>Required on writes, any value</td><td>A custom header forces a CORS preflight, which this UI never answers, so cross-site writes cannot be sent</td></tr>
</tbody>
</table>
</div>
<p>Read endpoints are not subject to these two checks, since they have no side effects.</p>
`;

/* ======================== Library ======================== */
PAGES['library'] = `
<h1>Use as a library</h1>
<p class="lead">Skip the tunnel service and use only the protocol, config or crypto implementation.</p>

<h2>The three crates</h2>
<div class="table-wrap">
<table>
<thead><tr><th>crate</th><th>Purpose</th></tr></thead>
<tbody>
<tr><td><code>nfrp-common</code></td><td><strong>Protocol, config, crypto, ACL, logging</strong>, usable as a library</td></tr>
<tr><td><code>nfrp-server</code></td><td>Server executable</td></tr>
<tr><td><code>nfrp-client</code></td><td>Client executable</td></tr>
</tbody>
</table>
</div>

<h2>Installation</h2>
<pre><code>[dependencies]
nfrp-common = "0.6"</code></pre>

<h2>Module guide</h2>
<div class="table-wrap">
<table>
<thead><tr><th>Need</th><th>Module</th></tr></thead>
<tbody>
<tr><td>Read and write frp TOML configs, including key-name compatibility</td><td><code>config</code> and <code>frp_config</code></td></tr>
<tr><td>Parse legacy <code>frpc.ini</code> and <code>frps.ini</code></td><td><code>frp_legacy</code></td></tr>
<tr><td>Build your own frp client or server</td><td><code>frp</code> and <code>frp::msg</code></td></tr>
<tr><td>Crypto only</td><td><code>frp::crypto</code>, <code>frp::v1</code>, <code>frp::tls</code></td></tr>
<tr><td>HTTP request parsing and forwarding, no web framework</td><td><code>http1</code> and <code>http_relay</code></td></tr>
<tr><td>IP allow and deny lists, RBAC, audit</td><td><code>security</code></td></tr>
<tr><td>Daily rotating logs</td><td><code>logfile</code></td></tr>
<tr><td>PROXY protocol v1 and v2</td><td><code>proxy_protocol</code></td></tr>
<tr><td>KCP, QUIC and WebSocket transports</td><td><code>frp::kcp</code>, <code>frp::quic</code>, <code>ws</code></td></tr>
<tr><td>VirtualNet (TUN device)</td><td><code>vnet</code></td></tr>
</tbody>
</table>
</div>

<h2>Example: parse an frps config</h2>
<pre><code>use nfrp_common::config::ServerConfig;

let cfg: ServerConfig = toml::from_str(r#"
    bind_port = 7000
    [auth]
    token = "secret"
"#).unwrap();

assert_eq!(cfg.bind_port, Some(7000));   // note: Option&lt;u16&gt;
assert_eq!(cfg.effective_auth().token, "secret");</code></pre>

<div class="callout">
<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><path d="M12 16v-4M12 8h.01"/></svg>
<div>
<strong>Field names are snake_case</strong>
<p><code>ServerConfig</code> uses <code>bind_port</code>, not the official <code>bindPort</code>. The latter is handled by the <code>frp_config</code> compatibility layer.</p>
</div>
</div>

<h2>Example: v1 key derivation, byte-identical to the official one</h2>
<pre><code>use nfrp_common::frp::v1::derive_key;

let key = derive_key(b"my-token");
assert_eq!(key.len(), 16);   // AES-128</code></pre>

<h2>Example: ACL evaluation</h2>
<pre><code>use nfrp_common::security::AclConfig;

// A compiled ACL evaluates in a single pass
let acl = AclConfig {
    allow: vec!["10.0.0.0/8".into()],
    deny: vec![],
};
// see the security module docs for the full API</code></pre>

<h2>Security note</h2>
<p>This library faithfully implements the frp protocol and therefore preserves its historical designs, such as the v1 MD5 credential and 64 round PBKDF2. <strong>Prefer v2 for new code.</strong> See <a href="#/security">Security model</a>.</p>

<h2>Links</h2>
<ul>
<li><a href="https://crates.io/crates/nfrp-common" target="_blank" rel="noopener">crates.io</a></li>
<li><a href="https://docs.rs/nfrp-common" target="_blank" rel="noopener">docs.rs</a> for the full API reference</li>
</ul>
`;

/* ======================== frp interoperability ======================== */
PAGES['compat'] = `
<h1>frp interoperability</h1>
<p class="lead">This is the reason the project exists. Every design trade-off orbits it.</p>

<h2>Tested matrix</h2>
<div class="table-wrap">
<table>
<thead><tr><th>Combination</th><th>Status</th><th>Notes</th></tr></thead>
<tbody>
<tr><td>Official frpc to NFrp frps</td><td>works</td><td>v1 by default, no config change needed</td></tr>
<tr><td>NFrp frpc to official frps</td><td>works</td><td>Key names mirror frp</td></tr>
<tr><td>NFrp on both ends</td><td>works</td><td>Optionally v2 with strong encryption</td></tr>
</tbody>
</table>
</div>
<p>Baseline: official frp <strong>0.71.0</strong>.</p>

<h2>Key name mapping</h2>
<p>NFrp's <code>ServerConfig</code> and <code>ClientConfig</code> use snake_case while the official configs use camelCase. A compatibility layer bridges the two:</p>
<div class="table-wrap">
<table>
<thead><tr><th>Official frp</th><th>NFrp native</th></tr></thead>
<tbody>
<tr><td><code>bindPort</code></td><td><code>bind_port</code></td></tr>
<tr><td><code>serverAddr</code></td><td><code>server_addr</code></td></tr>
<tr><td><code>localIP</code></td><td><code>local_ip</code></td></tr>
<tr><td><code>customDomains</code></td><td><code>custom_domains</code></td></tr>
</tbody>
</table>
</div>
<p>Config files accept both spellings through the <code>frp_config</code> layer; the library API is snake_case only.</p>

<h2>Legacy INI configs</h2>
<p><code>frpc.ini</code> and <code>frps.ini</code> are read directly by the <code>frp_legacy</code> module.</p>

<h2>Designs kept for interoperability</h2>
<p>These come up repeatedly during security audits but <strong>cannot change without breaking compatibility</strong>:</p>
<div class="table-wrap">
<table>
<thead><tr><th>Item</th><th>Why it stays</th></tr></thead>
<tbody>
<tr><td>v1 uses MD5 for the credential</td><td>It is the frp wire format</td></tr>
<tr><td>v1 uses 64 round PBKDF2-HMAC-SHA1</td><td>Fixed by official <code>golib v0.8.2</code>; the master branch changed the salt, and following master breaks official compatibility</td></tr>
<tr><td>v1 uses AES-128-CFB</td><td>Same reason</td></tr>
<tr><td>Client does not verify the server certificate by default</td><td>The official frpc is <code>InsecureSkipVerify</code></td></tr>
<tr><td><code>-v</code> prints <code>0.71.0</code></td><td>Admin panels judge the peer by version string</td></tr>
</tbody>
</table>
</div>

<h2>Version negotiation</h2>
<p>The server needs <strong>no version configuration</strong>. It detects v1 or v2 from the first byte and serves both on the same port.</p>

<h2>Not supported, and known differences</h2>
<div class="callout warn">
<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M10.29 3.86 1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><path d="M12 9v4M12 17h.01"/></svg>
<div>
<strong>Honest differences</strong>
<ul>
<li><strong>Port knocking is not implemented.</strong> The official frp has a knock feature; NFrp does not.</li>
<li><strong>Mixed xtcp versions</strong> fall back to stcp relay automatically. It works, it just never goes direct.</li>
<li><strong><code>TYPE_SERVER_CMD</code> (100 and 101) is a private extension.</strong> With an official frpc the capability stays off, and the dashboard reports an error rather than hanging until timeout.</li>
</ul>
</div>
</div>
`;
