<div align="center">
  <img src="assets/icons/nfrp-icon-256.png" alt="NFrp Logo" width="120">
  <h1>NFrp</h1>
  <p><b>A Rust reimplementation of frp, wire-compatible with upstream</b></p>
</div>

<!-- lang-switch -->
<p align="center">
  **English** &nbsp;·&nbsp; [简体中文](README.zh-CN.md) &nbsp;·&nbsp; [日本語](README.ja.md) &nbsp;·&nbsp; [Русский](README.ru.md)
</p>
<!-- /lang-switch -->

<p align="center">
  <img src="https://img.shields.io/badge/version-0.7.3-blue" alt="Version">
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

NFrp is a Rust reimplementation of [fatedier/frp](https://github.com/fatedier/frp).
It is **fully compatible with the upstream wire protocol, both v1 and v2**, and
interoperates directly with official `frps` / `frpc` (verified against v0.71.0).
Configurations pushed by third-party frp providers work as-is.

The default is **v1**, matching upstream's default — so official clients and
servers **need no configuration changes** to connect.

Memory footprint is small: about 3.5 MB resident for the server, versus
28.8–31.8 MB for the Go frps under the same load. Single binary, no runtime
dependencies.

There is also an optional extension layer, **NLink v1** (QUIC transport and
connection migration, session resumption, zero-trust identity, fine-grained
rate limiting, port knocking). It is **disabled by default**, negotiated
bilaterally, and fully reversible — zero impact on official frp. See
[NLink v1](#nlink-v1-negotiated-extension-layer-disabled-by-default).

> **Full documentation**: <https://nu0vo1212.github.io/Rust-Frp/>
> Covers installation, every configuration key, the eight proxy types, the
> v1/v2 wire protocols, ACL / RBAC, audit logging, the HTTP API, and the
> security fix history. Sources live in [`docs/`](docs/); preview locally with
> `python -m http.server -d docs 8899`
>
> **Quality and releases**: [QUALITY.md](QUALITY.md) — test distribution,
> CI matrix, what dependency security actually covers, release gates, and the
> manual checklist.

## Installation

### Option 1: crates.io (recommended for Rust users)

All three crates are published. You can also depend on the protocol library
alone and **skip the tunnel server entirely**:

```bash
# Install both executables
cargo install nfrp-server nfrp-client
```

```toml
# Or: use protocol / config / crypto as a library
[dependencies]
nfrp-common = "0.7"
```

| crate | Purpose | Links |
|---|---|---|
| **nfrp-common** | Protocol, config, crypto, ACL/RBAC, logging, transport abstractions | [crates.io](https://crates.io/crates/nfrp-common) · [docs.rs](https://docs.rs/nfrp-common) |
| **nfrp-server** | Server executable (equivalent to official `frps`) | [crates.io](https://crates.io/crates/nfrp-server) |
| **nfrp-client** | Client executable (equivalent to official `frpc`) | [crates.io](https://crates.io/crates/nfrp-client) |

> **About version numbers**: crates.io versions and the Release versions on
> this page are **independent**. For example, a Release might be `v0.7.1`
> while crates.io is already `0.7.2` — crates.io does not allow republishing
> the same version number, so even a README fix forces a version bump.
> **Use the Release as the reference for code behaviour**; `cargo install`
> always gives you the latest published version of that crate.
>
> ★ **A binary from `cargo install` is not the same build as the same version
> in a Release.** Take `0.6.6`: the crates.io build was cut before the Release,
> and a few more changes landed before `v0.6.6` was tagged (the version number
> was already taken, so it could not be re-published). So
> **`cargo install nfrp-server@0.6.6` and the `frps` in the Release package may
> behave differently**. For reproducible artifacts you can cite in an issue,
> use [Option 2: download binaries](#option-2-download-binaries).
> From later versions on, the release order is fixed: **publish to crates.io
> first, then package the Release from that same build**.

Module map for `nfrp-common`:

| You want to | Start from |
|---|---|
| Read/write frp TOML config (with key-name compatibility) | `config` · `frp_config` |
| Parse legacy `frpc.ini` / `frps.ini` | `frp_legacy` |
| Implement your own frp client or server | `frp` · `frp::msg` |
| Only the crypto (AEAD / v1 CFB) | `frp::crypto` · `frp::v1` · `frp::tls` |
| HTTP request parsing / relay (no web framework) | `http1` · `http_relay` |
| IP allow/deny, RBAC, audit | `security` |
| Daily log rotation | `logfile` |
| PROXY protocol v1/v2 | `proxy_protocol` |
| KCP / QUIC / WebSocket transports | `frp::kcp` · `frp::quic` · `ws` |

### Option 2: download binaries

Grab the package for your platform from
[Releases](https://github.com/Nu0vo1212/Rust-Frp/releases)
(Windows / Linux amd64 / Linux arm64 / Android, plus a source tarball).

## Features

### Proxy types

Eight, exactly matching upstream frp's list:

| Type | Description |
|---|---|
| `tcp` | The most common port forwarding |
| `udp` | UDP forwarding; each proxy uses a single work connection, sessions are distinguished by visitor address |
| `http` | Domain-based routing with `locations` prefixes, Basic Auth, Host rewriting, custom request/response headers |
| `https` | Routes by sniffing only the SNI in ClientHello; TLS is not terminated, certificates stay on the internal service |
| `tcpmux` | HTTP CONNECT multiplexing; several proxies share one server port, with `routeByHTTPUser` for second-level routing |
| `stcp` | Private tunnel; the server opens no public port, `secret_key` plus an `allow_users` allowlist |
| `sudp` | Same auth model as stcp with a UDP data plane, also no public port |
| `xtcp` | UDP hole punching with QUIC / KCP direct connections; data bypasses the server. Falls back to relay automatically. Since v0.5.8 the P2P handshake has two extra checks: the provider returns a **derived response secret**, and the server binds the rendezvous HELLO to the control connection's source IP |

### Transports

- frp v1 / v2 dual wire protocol; v1 by default, opt into v2 with `transport.wireProtocol = "v2"`
- QUIC transport (`transport_protocol = "quic"`): 1-RTT handshake, per-stream multiplexing
- KCP for lossy networks: usable as an xtcp direct-connect channel or as a standalone transport (`kcp_bind_port`)
- yamux multiplexing (`transport.tcpMux`); control and work connections share one TCP connection
- TLS (`transport.tls`) with upstream's custom-first-byte disguise. The server auto-generates a self-signed certificate, or you can supply `certFile` / `keyFile`; `trustedCaFile` enables client certificates (mTLS). The client can present its own identity via `certFile` / `keyFile`
- WebSocket / WSS (`websocket = true`), auto-detected by path on the same port — gets through firewalls that only allow HTTP
- Proxy Protocol v1 / v2 to pass the real client IP to Nginx / HAProxy / backend apps

### Client plugins

All nine upstream plugins are implemented: `http_proxy` / `socks5` /
`static_file` / `unix_domain_socket` / `http2http` / `http2https` /
`https2http` / `https2https` / `tls2raw`. frpc alone can act as a forward
proxy, a static site, or a TLS terminator.

### Security and access control

- OIDC authentication (`auth.method = "oidc"`) against any standards-compliant IdP (Keycloak, Google, Azure AD, …). The client uses the Client Credentials grant; the server verifies JWKS signatures (RS256 / PS256 / ES256)
- RBAC role table (`[[roles]]`) matched in order, with `deny_unknown` / `default_role` fallbacks
- IP allow/deny lists (`[acl]`) with CIDR syntax, `deny` wins. **Since v0.5.9 they cover every data-plane entry point** (TCP / UDP proxies, vhost, VNet, xtcp rendezvous, dashboard)
- Audit log (`[audit]`): append-only JSONL plus an in-memory ring buffer; zero overhead when disabled. **Since v0.5.9, `maxFileMB` rotation** (default 64, one `.1` backup)
- Credential comparison is always constant-time; HTTP relay strips hop-by-hop headers, normalizes `Host`, and rejects CL+TE smuggling
- The dashboard and the client's local UI **refuse to start if bound to a non-loopback address without credentials** (escape hatches: `allow_insecure_dashboard` / `allowInsecureRemote`)

All security fixes are consolidated into one document (chronological, with each
round's original text preserved):

**[SECURITY-ALL-FIXES.md](SECURITY-ALL-FIXES.md)** — rounds 1 through 16, 2026-10-04 to 2026-10-25

The per-round originals (SECURITY-FIXES-ROUND4..16.md) are kept as a chain of
evidence; the consolidated document records the date and conclusion of each
round together with reproduction, fix, and regression test.

### Operations and scheduling

- Group load balancing: several proxies sharing a `group` and a `remote_port`, distributed by least-connections
- Health checks: `tcp` / `http` probes; failing backends are removed and re-added automatically once healthy
- Bandwidth limiting: per-proxy `bandwidth_limit` (e.g. `1MB`) enforced by a token bucket
- Resource caps on five dimensions (clients / proxies / relayed connections / pending queues), all exported as metrics
- Port allowlist: `allowPorts` + `maxPortsPerClient`
- Log rotation: `log.to` + `log.maxDays`, split and cleaned daily
- Client store persistence: dynamically added proxies survive restarts
- Config hot reload: change `log_level` or the dashboard password without a restart

### Observability and management

- Built-in web dashboard, Prometheus `/metrics` (opt-in via `enablePrometheus = true`), and an unauthenticated health endpoint; Basic Auth supported
- Add or remove proxies and kick clients from the dashboard, no config edit or restart needed
- Dashboard API v2 (`/api/v2/*`): uniform error envelope, pagination, stable ordering; v1 endpoints are unchanged
- Client local web UI / API (`[webServer] port = 7400`): inspect tunnels, connections, and traffic, and add or remove proxies
- CPU profiling: with `pprofEnable = true`, exposed by both the server dashboard and the client web UI as `GET /debug/pprof/profile?seconds=N` (default 10 s, max 60 s). Returns protobuf on Unix; explicitly 501 on Windows (Rust's `pprof` needs perf signals / `ucontext_t`)
- SSH tunnel gateway (`sshTunnelGateway`): an SSH server embedded in frps, so OpenSSH's `ssh -R` can register `tcp` / `http` / `https` / `tcpmux` / `stcp` proxies; the data plane reuses ordinary work connections. When `authorizedKeysFile` is non-empty only keys from that file are accepted, and the key comment is the frp user name
- HTTP plugins (`httpPlugins`): the server calls out to an external HTTP service on `Login` / `NewProxy` / `CloseProxy` / `Ping` / `NewWorkConn` / `NewUserConn`, and can reject or rewrite the login content and proxy name/metas; 10 s timeout per request

### NLink v1: negotiated extension layer (disabled by default)

The standard frp protocol fixes its transport, session, authentication, and
scheduling model. Some needs are not cases of "implemented poorly" but of
**the protocol having no place to carry the information** — for example,
connection migration needs a transport-level connection identity, and frp
layers yamux over TCP/TLS, so that slot does not exist.

NLink is a layer stacked on top of the standard frp wire protocol. Two rules
govern everything:

1. **Not a single byte of the standard frames changes** — extensions live in a
   separate namespace, so official frp never sees them;
2. **If it was not negotiated, it does not exist** — if either side lacks
   support, behaviour is identical to 0.6.x.

**Zero extra round trips.** The client piggybacks its capability declaration
ahead of the first protocol message (the `NFRPLNK1` preamble), and the server
piggybacks its confirmation onto the `LoginResp._nlink` it was sending anyway.
Detection relies only on the first byte — `NFRPLNK1`, `FRP\0\x02\r\n`, and `{`
do not overlap, so there is no ambiguity.

| Capability | Description |
|---|---|
| QUIC transport and connection migration | Dedicated ALPN `nfrp-nlink`, bucketed separately from standard QUIC |
| Session resumption | The process-wide `ConnectionId` stays the same; the server keeps the proxy listeners / ports / vhost routes as-is for `resume_ttl` seconds |
| Zero-trust identity | Every work connection carries a `v1.<exp>.<hmac>` token bound to `run_id + user + expiry` |
| Fine-grained rate limiting | Token buckets per user × proxy, with burst support |
| Port knocking | Ports are invisible by default; the right knock sequence opens them for that IP temporarily |
| Batched work connections | One `BatchReq` returns N connections, removing per-connection round trips |
| End-to-end trace | Control and data planes share one trace id |

**Disabled by default**; both ends must opt in:

```toml
# frps.toml
[nlink]
enable = true
quic_listen = "0.0.0.0:7000"   # leave empty to disable QUIC
resume_ttl = 30

# frpc.toml
[nlink]
enable = true
resume = true
quic = true
```

**Coexisting with upstream frp**: official frps does not understand the
preamble and will reject it as a v1 message header. The client catches that
failure and **automatically falls back to standard mode, retrying once**, with
a single warning in the log. Tunnels keep working.

| Combination | Behaviour |
|---|---|
| NFrp × NFrp | Enabled as negotiated |
| NFrp × official frp | Falls back to standard mode; features degrade but **connectivity is unaffected** |
| official × official | Completely unaffected |

Compiling with `--no-default-features` drops the extension fields entirely; the
wire format is then byte-for-byte identical to 0.6.x.

> For the handshake diagram, TLV framing, how each capability is carried, the
> compatibility matrix, and the design constraints, see the
> [NLink page on the docs site](https://nu0vo1212.github.io/Rust-Frp/#/nlink).

### Engineering quality

989 automated tests, including real QUIC stack handshakes, end-to-end
integration, and decryption regressions against ciphertext captured from
official frpc/frps; `cargo audit` reports zero hits; release artifacts ship
with `SHA256SUMS` and an Ed25519 signature.

Test distribution, the CI matrix, exactly what dependency security covers, the
release gate, and the manual checklist all live in **[QUALITY.md](QUALITY.md)**.

## Quick start

### Build

```bash
cargo build --release
# Artifacts: <target_directory>/release/nfrp-server (frps), <target_directory>/release/nfrp-client (frpc)
# target_directory follows `cargo metadata`: if CARGO_TARGET_DIR or a local
# `.cargo/config.toml` is set, artifacts are not under ./target
```

Requires Rust 1.75+. Windows uses the MSVC toolchain.

You can also download a release package; the binaries inside are named `frps` /
`frpc`, matching upstream.

### Server (public host)

```toml
# frps.toml
bind_addr = "0.0.0.0"
bind_port = 7000
token = "replace with a sufficiently random secret"

# Optional: rendezvous port for real P2P xtcp (open UDP for it)
p2p_port = 7002

# Optional: built-in dashboard (add enablePrometheus = true for /metrics)
dashboard_port = 7500
dashboard_user = "admin"
dashboard_pwd = "replace with a strong password"
```

```bash
./nfrp-server -c frps.toml
# Generate a fully commented example config:
./nfrp-server --gen-config frps.toml
```

### Client (internal host)

```toml
# frpc.toml
server_addr = "your.server.com"
server_port = 7000
token = "same secret as the server"

[[proxies]]
name = "ssh"
type = "tcp"
local_addr = "127.0.0.1:22"
remote_port = 6000
```

```bash
./nfrp-client -c frpc.toml
```

After that, `your.server.com:6000` maps to port 22 on the internal host.

### Interoperability with official frp

NFrp runs on either side of an official frp deployment; both directions are
verified in practice:

| Server | Client | Status |
|---|---|---|
| nfrp frps | official frpc (tcpMux on/off, TLS on, various proxy types) | Pass |
| official frps | nfrp frpc (tcp_mux on/off, TLS on, various proxy types) | Pass |
| nfrp frps | official frpc (stcp provider / visitor) | Pass |

**Compatibility markers must not change**: `frpc -v` still prints a bare
`0.71.0`, the wire magic and version string are preserved, and the packaged
binaries are still named `frps` / `frpc`. Changing any of these immediately
breaks interoperability with official frp and third-party platforms.

## Configuration

Configuration keys align with upstream frp, so **an unmodified
`frps.toml` / `frpc.toml` works** (camelCase, the two-part `localIP` +
`localPort` form, `[metadatas]`, and so on are all accepted).

Two places **deliberately diverge** from upstream, and both matter:

- `local_addr` is the merged `ip:port` form (`127.0.0.1:8080`), not upstream's
  separate `localIP` + `localPort`. The two-part form is also accepted, but do
  not mix the two styles in one file.
- Log rotation happens at **UTC** midnight (upstream uses local time), because
  the log timestamps themselves are UTC.

Fully commented examples are in [`assets/frps.toml`](assets/frps.toml) and
[`assets/frpc.toml`](assets/frpc.toml), or generate one with `--gen-config`.

## Upgrade notes

Since 0.5.2 there are several **behaviour changes** to check before upgrading:

| Change | Impact | What to do |
|---|---|---|
| Dashboard bound to a non-loopback address without `dashboard_user` | Refuses to start | Set credentials / set `bind_addr = "127.0.0.1"` / explicitly set `allow_insecure_dashboard = true` |
| Client `[webServer]` bound to non-loopback without credentials | Refuses to start | Escape hatch: `allowInsecureRemote = true` |
| Local UI write endpoints | Require an `X-Nfrp-Client: 1` header | Add it to any script calling write endpoints |
| Empty token with an **explicit** external bind | Refuses to start | Set a token / bind loopback / explicitly set `allow_insecure_no_auth = true` |
| Misspelled keys in `[acl]` | Now an error (previously silently ignored) | Fix the spelling |

**Three more since 0.5.5** (all consequences of security fixes):

| Change | Impact | What to do |
|---|---|---|
| Remotely pushed proxies **may no longer carry plugins** (`plugin` / `pluginUser` / `pluginPasswd` / `pluginHostHeaderRewrite` / `pluginStripPrefix`) | Proxies pushed from the dashboard with a plugin are rejected | Plugins may only be set in the **local config file** (a plugin decides what the client *becomes*, which the server must not choose remotely). To reach internal services, use a plain tcp/http proxy |
| Remote pushes **cannot delete or override proxies defined in the config file** | Dashboard add/remove for those proxies returns an explicit error | Edit the local config; the dashboard only manages the dynamic proxies it created (and those restored from the store) |
| Work connections require credentials | **No impact on official frpc** (it sends none by default, so the server falls back to "same source IP") | Nothing. NFrp ≥ 0.5.5 clients declare and send them automatically |

**Three more since 0.5.6** (intentional behaviour changes; see round 5):

| Change | Impact | What to do |
|---|---|---|
| **INI section and key names are lowercased** | Proxy names are lowercased (`[MCCC]` → `mccc`) | **This is a fix for upstream parity** — Go's `go-ini` lowercases too, and previously the two sides produced different names. If your scripts reference proxies by an uppercase name, switch to lowercase |
| **Cross-tenant sharing of a domain + path via `routeByHTTPUser` is no longer allowed** | Cross-tenant multi-scope registrations are rejected ("path already in use") | The server cannot distinguish a legitimate multi-scope setup from parasitic hijacking, and the latter harvests Basic credentials outright, so it was tightened. **Same-tenant** multi-scope topologies (the usage in upstream's tcpmux docs) are unaffected |
| **UDP replies are limited to visitor IPs that actually sent packets** | The client cannot make the server send UDP to an IP that never communicated | Prevents frps from being used as a UDP reflector. Honest clients see zero impact; protocols that reply from a different port (like TFTP) are **unaffected** (the limit is on IP, not port) |

**Three more since 0.5.7** (see round 6):

| Change | Impact | What to do |
|---|---|---|
| **Credential freshness checks cover all six entry points** | Logins, work connections, vnet registrations, visitor signatures, and p2p hole-punch signatures whose timestamp is outside `maxClockSkewSecs` (default ±300 s) are **rejected outright** | **No impact on official frpc** (it already uses the current time; interop is verified). Only fails when the two clocks differ by more than 5 minutes — the symptom is "control port connects but login is rejected", and the error states the skew in seconds. Sync the clocks, or raise `maxClockSkewSecs` (`0` disables the check) |
| **Cross-tenant port sharing by group name is no longer allowed** | Clients under different `user` values cannot share a port even with the same group name and `groupKey` | This closes a hijack reproduced in testing (an attacker could divert half the traffic). Multiple frpc instances **under the same tenant** (reconnects, multiple instances, several `[[proxies]]` in one config) still group normally; upstream's "one operator, several redundant backends" usage is unaffected |
| **A visitor's `run_id` cannot be empty** | Visitor connections with `run_id = ""` are rejected | Official frpc visitors **always** carry their own `run_id`, so zero impact. Previously an empty value bypassed session validation (an anonymous connection was observed pushing data into someone else's tunnel) |

**Four more since 0.5.8** (rounds 7 and 8; details there):

| Change | Impact | What to do |
|---|---|---|
| **xtcp rendezvous gains two checks**: the server binds the HELLO's source IP to the session's control-connection IP, and the provider returns a **response secret derived from `secret_key` + `sid`** (replacing the fixed `"RTNL-OK"`), compared in constant time | Fixes "read the plaintext HELLO in flight (sid leaks) ⇒ impersonate the provider and hijack the P2P session" (round 8, B-1; user plaintext was recoverable in practice). **In mixed-version setups P2P direct connect fails and falls back to relay automatically** (any new↔old combination): functionality is unaffected, you just lose the direct-connect speedup | Both ends must be 0.5.8+ to establish P2P. A one-sided upgrade **will not** break the connection; after the hole-punch window (8 s) it relays. Note that behind the same NAT an observer on the same IP may still register (the second-layer secret blocks the data) |
| **Dashboard parsing hygiene and delete-by-full-name**: `Authorization` is parsed only from the request **head** (similarly shaped lines in the body no longer "leak in"); the **wire full name** (`user.proxy`) shown in the list can be used directly for "remove proxy" | ① Before the fix, a request with `Authorization: Basic ...` in the body passed dashboard auth (inconsistent with upstream proxies/WAFs — a parsing hygiene issue); ② beforehand, deleting by the full name from the list returned 502/400 **and split the two sides' state** (the server had removed it, the client reported "not present locally") | Normal usage sees no change; after ②, names copied from the list (full or short) both delete correctly |
| **`https2http` / `https2https` upstream cleanup**: when the visitor disconnects, stop waiting on the upstream and release it immediately; connect / TLS handshake get a 10 s timeout | Before the fix, an upstream that accepted and then hung left one never-released upstream connection per visit (connection → request → leave), amplifiable by any public visitor. Waiting for response headers still has **no** artificial timeout, so long polling / SSE are unaffected | Behaviour now matches official frpc (Go's `http.Server` cancels the request context on client disconnect). Genuinely slow upstreams (that do produce data) are unaffected; this was measured |
| **`[acl]` now actually applies to the data plane** (round 7, F7-1): accepts on public **TCP proxy ports** and **HTTP/HTTPS vhost** now go through the IP allow/deny lists (before, only control connections did) | Sources you had `deny`ed "had been getting through all along"; from this version they are rejected (connection closed silently + audit event). Deployments using allowlist mode (`allow`) should take particular note: previously it was a no-op for the data plane, and from this version it **tightens to the allowlist** | **UDP proxy ports and xtcp rendezvous (p2p) UDP are still outside `[acl]`** (the dashboard has its own auth) — recorded honestly in round 7. To block UDP sources, use a firewall (**since v0.5.9, UDP proxy ports / rendezvous / dashboard are also covered by ACL**, see below) |

**Six more since 0.5.9** (round 9; details there):

| Change | Impact | What to do |
|---|---|---|
| **`[acl]` coverage completed** (E9-0 / E9-1 / E9-2): **UDP proxy ports**, **xtcp rendezvous UDP**, and the **dashboard** now also go through the IP allow/deny lists | Before the fix, UDP proxy ports **completely ignored** `[acl]` (UDP packets could reach internal services without any credentials); rendezvous and the dashboard leaked similarly (the dashboard has separate Basic Auth, so it was a defence-in-depth gap) | Deployments in allowlist (`allow`) mode should confirm what is permitted; to block only UDP sources you can still use a firewall. Sources suddenly being blocked after the upgrade is the config working as intended (it was silently ineffective before) |
| **Time bounds on unauthenticated connections plus a global gate** (C9-3 / C9-4): 30 s TLS handshake timeout, a yamux idle-session watchdog (30 s), a global concurrency gate for unauthenticated handshakes (2048, 5 s queue), and connections that go silent after a single `0x00` / `0x16` / `0x17` byte no longer linger forever | Before the fix, sending one byte and then going silent could pin a connection indefinitely (500 `0x00` connections were measured holding 500 fds and 6.4 MB); unauthenticated stream opening could be amplified **≈800×** (12 bytes for 9.5 KB) | Normal traffic notices nothing. Under **extreme saturation** (more than 2048 concurrent unauthenticated handshakes) new connections queue for 5 s and are then rejected — existing sessions and legitimate work streams are unaffected, including legitimate clients logging back in |
| **Audit log rotation `maxFileMB`** (A9-3; default 64, `0` disables) | Before the fix the audit file could be grown arbitrarily by public traffic (~1000 entries/s, from 37 MB/h, unbounded, also evicting real events from the ring buffer) | Rotation keeps a single `<path>.1` backup, so total usage is roughly 2× the threshold; archive `.1` yourself if you need longer history. To restore the old unbounded behaviour set `maxFileMB = 0` |
| **stcp / xtcp visitor default config works again** (A9-5; regression fix for 0.5.7 / 0.5.8) | When neither side sets `user` (upstream's default semantics, `"" == ""`), 0.5.7 / 0.5.8 could "log in, pair up, but never pass data" | Deployments with `allow_users` are unchanged; if you hard-set a `user` on both sides to work around this, you can drop it from this version on |
| **KCP session table capped at 1024** (C9-1; only when `kcp_bind_port` is enabled): at most 1024 concurrent KCP sessions, new ones are dropped (no reply, **existing sessions unaffected**) | Before the fix a 25-byte UDP packet could pin ≈15 KB of memory (**312× amplification**; 757 KB of upstream traffic pushed memory to 238 MB) | Deployments without KCP are unaffected; if a single instance consistently exceeds 1024 KCP sessions, split it |
| **Client reports plugin config errors at startup** (D9-7): on Windows a bad `unix_domain_socket` config used to be a single DEBUG line, silent at default level | Small impact (a broken config was already not working); it just goes from invisible to obvious | Nothing — read the WARN and fix the config |

Other things to note:

- **OIDC deployments must use TLS.** The OIDC `privilege_key` is the raw access
  token and appears in clear text in the login message; anyone passively
  capturing on an unencrypted link can take it.
- **The client's `transport.tls` encrypts but does not verify the peer
  certificate** (same as upstream frp). It protects against passive snooping,
  not man-in-the-middle; if you need MITM protection on a direct public
  connection, wrap it in another layer of TLS **outside**.
- **v1 login credential strength depends entirely on the token.** Since v0.5.7
  the server **checks timestamp freshness** (default ±300 s window, see the
  table above), reducing the replay window from "indefinite" to "5 minutes";
  replay is still possible within that window, and **the cost of offline token
  enumeration is unrelated to the time window** ⇒ for public deployments use a
  sufficiently random token, and prefer v2 / OIDC.
- **`user` is self-reported by the client and cannot be verified by the
  server.** Without `[[roles]]` it is just a label; and **that stays true even
  with `[[roles]]` configured** — anyone holding the shared token can claim
  someone else's `user` and obtain their role. ⇒ `[[roles]]` **is not tenant
  isolation**, only a guard against mistakes (since v0.5.7 the server logs a
  startup warning about this). For real isolation use OIDC (identity comes from
  a verified `sub`), or issue a separate token per tenant and deploy separate
  instances.
- **xtcp's "data bypasses the server" does not mean "secure against the
  server"**: the server holds `secret_key` and generates `sid` itself, so in
  theory it can derive the P2P secret. It protects against **third parties
  along the path**, not against the server.
- If you would rather not expose internal details, set
  `detailed_errors_to_client = false` (default `true`, matching upstream): it
  replaces errors sent to clients with a uniform generic message, which also
  reduces the enumeration surface for stcp/xtcp tunnel names.
- **UDP proxy replies are restricted** (since v0.5.6): the server only sends
  UDP to visitor IPs that recently sent packets to that port. This prevents
  frps from being used as a UDP reflector — normal clients only ever reply to
  the address they just received from, so they **notice nothing**.
- The example configs contain **no** proxies by default; uncomment what you
  need. SSH is no longer exposed by default.

## Quality assurance

```bash
cargo fmt --all -- --check                              # formatting
cargo clippy --workspace --all-targets -- -D warnings   # static analysis, 0 warnings
cargo test --workspace                                  # 989 passed / 0 failed / 13 ignored
```

The 13 `#[ignore]`d tests all **need real hardware or administrator
privileges** (Windows Wintun adapters, Linux TUN devices); they are not broken
tests that were skipped.

CI runs the same three gates on every push / PR, plus the full test suite on
three operating systems, cross-builds for two musl targets, and an end-to-end
smoke test.

**Full details in [QUALITY.md](QUALITY.md)**: the per-target test table, the CI
matrix, what dependency security actually covers (`cargo audit` / `deny` /
`vet` each mean something different), release gates, and the manual checklist.

## Release and deployment

### Docker

```bash
docker build -t nfrp .
docker run --rm -p 17000:17000 -p 17002:17002/udp \
  -v $PWD/frps.toml:/etc/nfrp/frps.toml nfrp
```

The image runs as a non-root user, uses a multi-stage musl build, and the final
image contains only the two binaries and example configs.

### Building packages yourself

The full commands for packaging, signing, cross-compilation (including the
Android NDK environment variables), and the release gate are in
**[QUALITY.md](QUALITY.md)**.

In short: `release.py pack` unpacks what it just built and compares the `frps` /
`frpc` inside against the source artifacts by sha256, exiting non-zero on any
mismatch. That step is not optional — there really have been releases where
"the package name and version were right but the binary inside was the previous
version".

## Current limitations

See **[QUALITY.md](QUALITY.md)** and the
[docs site](https://nu0vo1212.github.io/Rust-Frp/) for the up-to-date list.
Things that are **not** done, stated plainly rather than checked off for
appearance:

- `tcpmux` proxy type is not implemented (upstream has it)
- Some upstream plugins and fields are parsed only to keep configs from failing,
  and are explicitly reported as unsupported at startup
- **NLink v1 session resumption is a bearer-session design**; with
  `transport.tls.force = false` (the default) the token travels in clear text.
  Use TLS in production — see the [NLink page](https://nu0vo1212.github.io/Rust-Frp/#/nlink)
- NatHole implements upstream's modes 0–4, but whether a hole is actually
  punched still depends on the NAT devices on both ends; HardNAT failures fall
  back to relay by design
- The SSH gateway data plane and the Windows Wintun / Linux TUN data planes have
  no real-hardware end-to-end tests in CI (they require administrator
  privileges or specific hardware)

## License

Apache-2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).

Copyright 2026 nfrp contributors
