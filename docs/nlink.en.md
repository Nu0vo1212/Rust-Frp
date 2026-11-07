# NLink v1: the NFrp extension protocol

> This file is the **single source for the English NLink page**.
> `docs/assets/pages.en.js` and `memory/NLINK-V1-EVALUATION.md` are generated
> from `docs/nlink.md` / this file — **do not edit the generated output**.
>
> After editing, run:
> ```powershell
> python scripts/sync_nlink_doc.py
> ```
> To only check for drift (CI / before commit):
> ```powershell
> python scripts/sync_nlink_doc.py --check
> ```

NLink is an extension layer that NFrp defines on top of the standard frp wire protocol. It carries capabilities that the standard protocol has no place to express. It shares the same connection as v1 and v2: it does not change the fields, ordering, or semantics of standard frames, and it does not require the peer to implement it.

:::callout Status: available since v0.7.4, disabled by default
Every capability is implemented and covered by the 16 end-to-end cases in `server/tests/nlink_e2e.rs`. Both the server and the client must set `[nlink] enable = true` explicitly. When disabled, behaviour is identical to 0.6.x.
:::

## Scope

NLink addresses one class of problem only: the requirement is legitimate, but the standard frp protocol has no place to carry it. The clearest example is connection migration, which requires a connection identifier at the transport layer. Standard frp stacks yamux over TCP/TLS, so that position does not exist.

The boundary is therefore fixed:

- no standard frame field changes meaning;
- the standard handshake keeps its exact shape;
- if either side does not advertise a capability, behaviour falls back to the standard protocol;
- when disabled, the cost is zero and the code is not compiled in.

## Version detection

The server distinguishes four handshakes on the same port, using the first byte only:

| First byte | Verdict | Basis |
|---|---|---|
| `0x4E` (`N`) | **NLink** | magic `NFRPLNK1` |
| `0x46` (`F`) | **v2** | magic `FRP\0\x02\r\n` |
| `0x16` | **v1 over TLS** | first byte of a TLS ClientHello |
| anything else | **v1 plaintext** | parsed as `[1 byte type][8 byte big-endian length][JSON]` |

The three constants never overlap: v1 JSON starts with `{`, v2 starts with `F`, NLink starts with `N`. Detection involves no heuristic.

The probe always reads **8 bytes** (`max(NLink magic, v2 magic)`). An earlier implementation filled only 7 bytes (the v2 magic length) and then sliced to 8, so a client that sent 7 bytes and stopped could trigger an out-of-bounds panic. That bug is fixed and covered by the regression test `首帧不足时_detect_version_报错而不是_panic`.

## Handshake and capability negotiation

The capability declaration rides in front of the first standard message, and the result rides back on the `LoginResp` that would be sent anyway. No additional round trip is introduced:

```text
frpc                                             frps
 │                                                │
 ├─ [8]  NFRPLNK1      magic                      │
 ├─ [1]  ver = 1       extension version          │
 ├─ [8]  caps          capability bitmap (u64 BE) │
 ├─ [16] session_id    process-level connection id│
 ├─ [8]  trace_id      end-to-end trace           │
 ├─ standard v1/v2 handshake ───────────────────▶ │
 │                                                ├─ parse preamble
 │                                                ├─ result =
 │                                                │    compiled ∩ peer caps
 │                             ◀───────────────── ┤    ∩ runtime allowed
 │  LoginResp { _nlink: { caps, session, ... } }   │
 │                                                │
 ├─ later extension frames (same stream, same ciphertext) │
```

The negotiated result defines this connection for its whole lifetime and never changes mid-session. Unknown capability bits are ignored, which is the precondition for forward compatibility.

## Extension frame format

Extension frames use versioned TLVs with self-describing lengths, so unknown content can be skipped safely:

```text
u8   version    extension frame version (currently 1)
u8   kind       frame kind
u16  flags      reserved, must be 0
TLV*            each: u16 tag + u32 len + len bytes
```

Carrier positions:

- v2: dedicated frame type `0x4E`;
- v1: dedicated message type byte `0x7F`.

Neither value is used by the official implementation up to v0.71.0 (official v1 type bytes are all printable ASCII), so no numbering conflict exists.

A peer that does not recognise a `kind` or `tag` must skip it rather than fail. Failing would break forward compatibility.

## Capabilities and carriers

| Capability | Carrier | Notes |
|---|---|---|
| Native QUIC transport and connection migration | separate ALPN `nfrp-nlink` | bucketed apart from standard frp `nfrp-frp`; both can share one UDP port |
| Multiplexing | QUIC streams | one QUIC connection carries several tunnels, free of TCP head-of-line blocking |
| Session resume | `session_id` + one-time token + server-side table | keeps entries for `resume_ttl` seconds (default 30), restoring listeners, ports, vhosts and visitors |
| Zero-trust identity | `NewWorkConn._nlink` token | form `v1.<exp>.<hmac>`, bound to `run_id + user + expiry` |
| Fine-grained rate limiting | bridge token bucket | per user × proxy, burst-friendly; relay chunks shrink automatically at low rates |
| Port knocking | 33-byte data-plane sequence | the port stays invisible until a correct knock grants a temporary per-IP allowance |
| Batched work connections | `BatchReq` frame | one frame obtains N connections instead of N `StartWorkConn` round trips |
| End-to-end trace | `trace_id` | shared by the control connection and the data plane |

The XTCP mixed-version direct-connect policy, together with the bidirectional compatibility boundary cases, has also landed; see the compatibility matrix below.

## Session resume

### What is preserved

Resume preserves the session identity, listeners, ports, vhosts and visitors — not merely a list of names. A reconnect succeeds only when the `session_id` and the server-issued one-time token are both valid.

### Proxy reconciliation

A client may change its configuration while disconnected. After a successful resume it must report the proxies that still exist, and the server reclaims everything not mentioned. The frame is `ResumeCommit`, carrying proxy names in `TAG_DETAIL` separated by newlines.

### Automatic chunking

A single frame is capped at 8192 bytes. With many proxies the list does not fit, so implementations before 0.7.2 could only refuse to send and log it, silently downgrading "reclaim deleted proxies immediately" to a 10-second grace period.

The client now chunks automatically: each chunk carries `TAG_CHUNK` (index) and `TAG_CHUNKS` (total), and the server settles only once all chunks have arrived.

- a single chunk carries no chunk markers, so the wire format matches 0.7.1 exactly;
- chunks are cut on proxy-name boundaries and never split a name;
- out-of-order arrival reassembles correctly, duplicates are not double-counted, and a new round resets old state.

### Limits

| Limit | Value | Notes |
|---|---|---|
| Total list bytes | 8 MiB | about 200,000 names at 40 bytes each, far beyond what a single node realistically serves |
| Chunk count | derived from the byte budget (about 1100) | `TAG_CHUNKS` is u16 and cannot overflow |

Both limits are defensive: without them a client could keep sending chunks and force unbounded memory allocation, or claim a huge chunk count and never finish. Exceeding the budget is rejected with a warn log and does not affect the session itself.

## Authentication boundary of resume

A resume must present a **one-time token issued by the server**; holding only the `session_id` is no longer sufficient.

The token has the form `r1.<exp>.<nonce>.<sig>`, uses HMAC-SHA256, and is bound to `session + user + client_id + expiry + random nonce`. The random nonce makes tokens issued repeatedly for the same session distinct. The token is registered in a pending table and **is invalidated on first use**; verification and deletion happen in one step to avoid a race.

The token is delivered in `ResumeResp` at login time. At the moment the connection drops, nothing can be sent any more, so it must be provided in advance.

One boundary still requires the operator's judgement: with `transport.tls.force = false` (the default), an observer on the path can steal the token and consume it first. The real client then fails to resume and raises an alert — detectable, but not preventable.

Mitigations:

- the server logs a warning at startup when resume is enabled without forced TLS;
- this document records the boundary;
- **production deployments should enable `transport.tls.force = true`** so the token itself travels inside the encrypted channel.

## Enabling it

```toml
# frps
[nlink]
enable = true
# features = ["quic", "resume", "trace"]   # empty = negotiate only, enable nothing
quic_listen = "0.0.0.0:7000"               # empty = no QUIC listener
resume_ttl = 30                            # resume retention in seconds
```

```toml
# frpc
[nlink]
enable = true
resume = true      # resume with the same connection id after a drop
quic = true        # connect to the server over QUIC (requires quic_listen)
```

Official frpc / frps do not recognise the preamble and will treat the first byte as a v1 message header, then fail. The client catches that failure, falls back to standard mode, retries exactly once, logs one warning, and the tunnel keeps working.

## P2P hole punching: six NatHole combinations

The server implements the complete behaviour selection of the official `pkg/nathole/{classify,analysis}.go`, with modes 0–4 all present rather than only EasyNAT mode 0.

The decision uses three counters describing both NATs: `easyCount`, `hardCount`, and `portsChangedRegularCount`.

| Condition | Preferred mode | Meaning |
|---|---|---|
| both EasyNAT | mode 0 | stable mapping; send directly |
| one HardNAT, regular port changes | mode 1 | predict and scan a port range |
| one HardNAT, irregular ports | mode 2 | TTL control plus repeated rounds |
| both HardNAT, both regular | mode 3 | two-sided prediction plus random listening ports |
| both HardNAT, one regular | mode 4 | one-sided prediction plus random listening ports |
| both HardNAT, both irregular | mode 0 (score 1) | hardest case; still attempted as mode 0 |

Each behaviour table is ranked by historical success: resume and retry prefer a previously successful mode and index, a success adds 2 points (capped at 10), and the client reports results via `NatHoleReport`.

The tables ship with parameters `portsRangeNumber`, `portsRandomNumber`, `listenRandomPorts`, `ttl`, `sendDelayMs`, `readTimeoutMs`, and all STUN candidates in `candidateAddrs`.

These are protocol-level capabilities. Whether punching succeeds ultimately depends on the two NAT devices. When a HardNAT case fails, `fallbackTo` returns to relaying — a designed degradation path, not a defect.

## Compatibility with official frp

| Feature | NFrp × NFrp | NFrp × official frp | official × official |
|---|---|---|---|
| QUIC transport / migration | supported | falls back to TCP | unsupported |
| Session resume | supported | reconnect from scratch | unsupported |
| Zero-trust identity | supported | not enabled (token absent) | unsupported |
| Fine-grained rate limiting | supported | not enabled | unsupported |
| Batched work connections | supported | one per connection | unsupported |
| Port knocking | supported | unsupported | unsupported |
| End-to-end trace | supported | not enabled | unsupported |
| XTCP mixed-version direct | supported | requires explicit policy | official behaviour |

Every interaction with official frp lands on "not enabled" and does not affect connectivity. The only special case is the preamble: an official frps treats it as a v1 message header and fails, after which the client falls back to standard mode and retries once.

## Design constraints

The five rules below are hard requirements. A change that violates one is not merged; they are what makes this extension safe to enable.

### 1. Negotiation at handshake time

Both sides must advertise; if either side is missing, behaviour falls back to standard frp. The negotiated result governs the whole connection and never changes afterwards. Capabilities are expressed as a bitmap plus a version, and unknown bits are ignored.

### 2. Versioned TLV in a separate namespace

Extension frames live in their own namespace and never change standard frame semantics. Fields, ordering, and meaning stay untouched. An unrecognised TLV must be skipped rather than rejected, and self-describing lengths make skipping safe.

### 3. Two layers of switches, zero cost when off

A compile-time `nlink` feature (on by default) plus a runtime `[nlink] enable` (false by default).

With `--no-default-features`, the `_nlink` key is **absent** from `LoginResp` and `NewWorkConn`, so packets are byte-identical to 0.6.x. This was verified: such a build has no nlink in `cargo tree --no-default-features`.

### 4. Dual-stack coexistence

Two handshakes are recognised on the same port using only the first byte: `NFRPLNK1`, `FRP\0\x02\r\n`, and `{` never overlap. If the extension handshake fails, the client falls back transparently.

### 5. Testability

Every row of the compatibility matrix has a matching end-to-end case. There are 16 NLink cases covering resume, identity, knocking, rate limiting, QUIC, gating, and old-client fallback. The matrix itself is checked by a test: a case-name mismatch fails CI.

## Explicitly out of scope

| Idea | Why it is rejected |
|---|---|
| Change the meaning of standard frame fields | breaks compatibility with official implementations; violates constraint 2 |
| Enable the extension by default | unacceptable risk; violates constraint 3 |
| Emulate connection migration above yamux | semantically wrong: migration must happen at the transport layer, and an emulation solves nothing |
| Make authentication per-frame instead of per-connection | incompatible with peers that do not support it; belongs in an optional extension |
| Invent new compression or cipher algorithms | `useCompression` and `useEncryption` already match the official implementation byte for byte; new algorithms only break interoperability |
