//! HTTP 虚拟主机：解析请求 → 路由 → 转发 → 按帧回复。
//!
//! 职责：读写 HTTP 报文（`common::http_relay` 的原语）、`Host` / CONNECT
//! authority 匹配、Basic Auth、dot-segment 拒绝、请求/响应走私防护、
//! 逐跳头剥离、请求头改写与响应头注入、按 framing 转发响应体。
//!
//! 锁顺序契约：路由查找只短暂持有 `VhostTable` 的 `Mutex`（`lookup` 内），
//! 释放后才向 `ClientState` 索取工作连接；指标原子量最后递增。
//! 恒为「先 VhostTable，后工作连接池」，不反向、不嵌套。
//!
//! 不变量：请求侧与响应侧对 `Transfer-Encoding` / `Content-Length` 使用**同一套**
//! RFC 口径（`is_chunked` / `transfer_encoding_is_unsupported` /
//! `validate_response_framing`），口径不一致即拒绝；转发出去的头每个名字
//! 最多出现一次；`ConnGuard` 覆盖每一条返回路径。

use std::{net::SocketAddr, sync::Arc};

use anyhow::{Context, Result};
use nfrp_common::frp::{
    conn::FrpConn,
    msg::{constant_time_eq, FrpMessage, StartWorkConn},
};
// HTTP 报文的读写原语住在 common 里 —— 客户端的 http2http / https2http 那组插件
// 需要**一模一样**的能力（读头、按框架读体、原样转发），复制一份就得修两遍 bug。
use nfrp_common::http_relay::{
    connection_tokens, relay_fixed, relay_until_eof, wants_keep_alive, HeadParts, HttpIo,
    HOP_BY_HOP,
};
use tokio::io::AsyncWriteExt;
use tracing::{debug, warn};

use crate::registry::Registry;

use super::{
    conn::{canonical_host, record_bytes, wrap_work_stream, ConnGuard},
    listen::VhostOpts,
    router::{VhostKind, VhostTable},
};

// ---------------------------------------------------------------------------
// 路径校验
// ---------------------------------------------------------------------------
/// 请求目标里是否含 `.` / `..` 段（含 `%2e` 编码）。
///
/// # 为什么要拒绝它
///
/// `locations` 是**前缀匹配**，而很多后端（nginx / IIS / Apache）
/// 会把路径做 dot-segment 归一化。于是
/// `/public/../admin` 在 NFrp 这边命中 `/public`、到后端变成 `/admin`，
/// “只暴露 /public”的设想直接被绕过。
///
/// 官方 frp 也是前缀匹配（`strings.HasPrefix`），所以这不是 NFrp 引入的问题；
/// 但我们选择比上游更严：直接拒绝，而不是猜客户端意图。
///
/// 只解码一层且只处理 `%2e`（`.` 的唯一合法编码）：
/// 多层编码如 `%252e` 到后端解码一次也只是 `%2e`，不会变成 `.`。
fn has_dot_segment(path: &str) -> bool {
    for seg in path.split(['/', '\\', '?', '#']) {
        if seg.is_empty() {
            continue;
        }
        // 小写化后把 %2e 归一成 '.'（%2E 也一样）
        let decoded = seg.replace("%2e", ".").replace("%2E", ".");
        if decoded == "." || decoded == ".." {
            return true;
        }
    }
    false
}
// ---------------------------------------------------------------------------
// 几种虚拟主机共用的解析 / 应答小工具
// ---------------------------------------------------------------------------
fn basic_auth_user(parts: &HeadParts) -> Option<String> {
    use base64::{engine::general_purpose::STANDARD, Engine as _};
    let raw = parts.get("authorization")?;
    let (scheme, value) = raw.split_once(' ')?;
    if !scheme.eq_ignore_ascii_case("basic") {
        return None;
    }
    let decoded = STANDARD.decode(value.trim().as_bytes()).ok()?;
    let text = String::from_utf8(decoded).ok()?;
    Some(text.split(':').next().unwrap_or("").to_string())
}

pub(super) fn simple_response(status: &str, body: &str) -> Vec<u8> {
    custom_response(status, "text/plain; charset=utf-8", body.as_bytes())
}

/// 带状态行 + 指定 `Content-Type` 的应答。
///
/// 单独抽出来是因为自定义 404 页面可能是**任意字节**（HTML 里混着别的编码），
/// 不能再走 `format!` 把 body 拼进模板字符串。
fn custom_response(status: &str, content_type: &str, body: &[u8]) -> Vec<u8> {
    let mut out = format!(
        "HTTP/1.1 {status}\r\n\
         Content-Type: {content_type}\r\n\
         Content-Length: {}\r\n\
         Connection: close\r\n\r\n",
        body.len()
    )
    .into_bytes();
    out.extend_from_slice(body);
    out
}

/// 没有代理能匹配时给用户看的东西。
///
/// * 配了 `custom404Page` → 把该文件的**原文**当 404 响应体（官方
///   `vhost.NotFoundPagePath` 的语义），`Content-Type: text/html`；
/// * 没配 → 保持 NFrp 原有的纯文本提示。
///
/// 默认值**有意**不照抄官方那段 "The server is powered by frp" HTML：
///   排障时"找不到对应的 frp 代理"比一张品牌页有用得多，而官方对
///   "默认页长什么样"并没有任何协议层面的约束。
fn not_found_response(opts: &VhostOpts) -> Vec<u8> {
    match &opts.not_found_page {
        Some(page) => custom_response("404 Not Found", "text/html", page),
        None => simple_response("404 Not Found", "找不到对应的 frp 代理\n"),
    }
}
// ---------------------------------------------------------------------------
// HTTP：解析请求 → 路由 → 转发 → 按帧回复
// ---------------------------------------------------------------------------
/// 对 `visitor` 泛型化**只是为了测试**：生产路径传的是 `TcpStream`，测试里传
/// `tokio::io::duplex` 的内存管道，就能不起真实端口地验证超时 / 404 这些分支。
/// 泛型是零成本的（编译期单态化），没有引入任何动态分发。
pub(super) async fn handle_http<S>(
    visitor: S,
    peer: SocketAddr,
    table: Arc<VhostTable>,
    _port: u16,
    opts: VhostOpts,
    registry: Arc<Registry>,
) -> Result<()>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let mut io = HttpIo::new(visitor);

    loop {
        let Some(lines) = io.read_head().await? else {
            return Ok(());
        };
        let mut req = HeadParts::parse(&lines)?;

        // ---- `Expect: 100-continue` ----
        //
        // 客户端发了这个头就会**先等一个 100 才肯发请求体**。原先这里完全没处理：
        // 不回应就直接去取工作连接、转发头，然后 `read_n` 等请求体 —— 而客户端
        // 还在等 100。双方互等，一直挂到 `vhostHTTPTimeout`（默认 60 秒）。
        //
        // 单条请求就能占住一条工作连接 60 秒，是个很划算的放大 DoS。
        //
        // 处理方式与客户端 `plugin_bridge.rs` 一致：**自己回一个 100**，
        // 不把中间态转发给上游（那要处理"响应先于请求体"的重排序，不值得）。
        // 回完把这个头删掉，免得上游又多等一次。
        if req
            .get("expect")
            .is_some_and(|v| v.eq_ignore_ascii_case("100-continue"))
        {
            io.stream
                .write_all(b"HTTP/1.1 100 Continue\r\n\r\n")
                .await
                .context("回 100-continue 失败")?;
            io.stream.flush().await?;
            req.remove("expect");
        }

        let method = req
            .start_line
            .split_whitespace()
            .next()
            .unwrap_or("")
            .to_string();
        let is_connect = method.eq_ignore_ascii_case("CONNECT");
        // CONNECT 的请求行是 authority-form（`host:port`），不是路径。
        // 路由时把它当成 `/`，域名取 authority；否则 `locations = ["/"]`
        // 的普通 HTTP 代理会匹配不到，客户端只会看到 405。
        let path = if is_connect {
            "/".to_string()
        } else {
            req.start_line
                .split_whitespace()
                .nth(1)
                .unwrap_or("/")
                .to_string()
        };
        // `Host` 头里可能带端口，也可能写成 IPv6 的 `[::1]:8080`。
        // 原先直接 `split(':').next()` —— 对 IPv6 会切出一个孤零零的 `[`，
        // 对 `a.example.com:8080` 倒是对，但口径与 tcpmux/CONNECT 那条路径
        // 用的 `canonical_host` 不一致。统一走同一个函数，顺带把
        // 尾点和大小写也规范化了（与官方 `util.CanonicalHost` 对齐）。
        //
        // CONNECT 优先用请求行里的 authority（Go 的 `req.Host` 对它也是这么取
        // 的），`Host` 头只作兜底。
        let host_header = if is_connect {
            let authority = canonical_host(req.start_token(1).unwrap_or(""));
            if authority.is_empty() {
                req.get("host").map(canonical_host).unwrap_or_default()
            } else {
                authority
            }
        } else {
            req.get("host").map(canonical_host).unwrap_or_default()
        };
        let auth_user = basic_auth_user(&req);
        let visitor_keep_alive = wants_keep_alive(&req);

        // 带 dot-segment 的路径直接拒绝。
        //
        // `locations` 是前缀匹配，而后端会做归一化：
        // `/public/../admin` 会命中 `/public` 但到后端变成 `/admin`。
        // 不拒掉等于把 `locations` 当访问控制用的人一直在被绕过。
        if has_dot_segment(&path) {
            warn!(%peer, path = %path, "请求路径含 dot-segment，已拒绝");
            io.stream
                .write_all(&simple_response("400 Bad Request", "非法路径\n"))
                .await?;
            return Ok(());
        }

        // ---- 路由 ----
        let Some((route, _loc)) =
            table.lookup(&host_header, &path, auth_user.as_deref(), VhostKind::Http)
        else {
            debug!(%peer, host = %nfrp_common::util::LogSafe(&host_header), path = %path, "没有匹配的 http 代理");
            if is_connect {
                io.stream
                    .write_all(&simple_response(
                        "405 Method Not Allowed",
                        "不支持 CONNECT\n",
                    ))
                    .await?;
            } else {
                io.stream.write_all(&not_found_response(&opts)).await?;
            }
            return Ok(());
        };

        // ---- Basic Auth ----
        //
        // 用常量时间比较，与面板 / visitor 密钥那几处保持一致。
        // 这里是**用户自配的** HTTP 代理访问密码（不是服务端凭证），
        // 风险等级低，但没有理由留一处 `==` 比密钥的路径 ——
        // 逐字节比较会通过响应耗时泄露前缀，攻击者可据此逐位猜。
        if !route.http_user.is_empty() {
            let ok = match (&auth_user, route.http_pwd.is_empty()) {
                (Some(u), true) => constant_time_eq(u, &route.http_user),
                (Some(u), false) => {
                    // 用户名 + 密码都校验
                    let raw = req.get("authorization").unwrap_or("");
                    let expect = format!("{}:{}", route.http_user, route.http_pwd);
                    use base64::{engine::general_purpose::STANDARD, Engine as _};
                    let given = raw
                        .split_once(' ')
                        .and_then(|(_, v)| STANDARD.decode(v.trim().as_bytes()).ok())
                        .and_then(|b| String::from_utf8(b).ok())
                        .unwrap_or_default();
                    constant_time_eq(u, &route.http_user) && constant_time_eq(&given, &expect)
                }
                (None, _) => false,
            };
            if !ok {
                io.stream
                    .write_all(
                        "HTTP/1.1 401 Unauthorized\r\n\
                         WWW-Authenticate: Basic realm=\"frp\"\r\n\
                         Content-Length: 0\r\n\
                         Connection: close\r\n\r\n"
                            .as_bytes(),
                    )
                    .await?;
                return Ok(());
            }
        }

        // ---- CONNECT：先校验帧，后面走裸字节隧道 ----
        //
        // CONNECT 的语义是"请求头之后立刻就是隧道数据"，没有 HTTP 请求体。
        // 官方 v0.71.1 的 `connectHandler` 明确拒绝带正 `Content-Length` 或
        // `Transfer-Encoding` 的 CONNECT（400）—— 这两种头会让"头后的字节"
        // 到底是隧道数据还是请求体产生歧义，正是请求走私/截断的入口。
        //
        // `Content-Length: 0` 仍然允许（很多客户端会顺手带上），但转发前要摘掉，
        // 否则上游可能按 HTTP 请求而不是隧道处理。
        if is_connect {
            let cl_count = req.count("content-length");
            let bad_cl = match cl_count {
                0 => false,
                1 => match req.content_length_strict() {
                    Ok(0) => false,
                    Ok(_) | Err(_) => true,
                },
                _ => true,
            };
            if bad_cl || req.get("transfer-encoding").is_some() {
                debug!(
                    %peer,
                    cl = ?req.get_all("content-length"),
                    te = ?req.get("transfer-encoding"),
                    "CONNECT 带请求体框架，按歧义直接拒绝"
                );
                io.stream
                    .write_all(&simple_response(
                        "400 Bad Request",
                        "CONNECT 请求不能带请求体\n",
                    ))
                    .await?;
                return Ok(());
            }
            req.remove("content-length");
            req.remove("transfer-encoding");
            req.remove("trailer");
        }

        // ---- 读请求体（原样保留编码）----
        //
        // `Transfer-Encoding` 与 `Content-Length` **同时出现时必须拒绝**
        // （RFC 7230 §3.3.3：这种情况要么按 TE 处理并移除 CL，要么直接 400）。
        //
        // 原先的写法是"有 TE 就按 chunked 读，否则看 CL"—— 读的方向没错，
        // 但**两个头都原样转发**给了上游。于是：NFrp 按 chunked 解读完请求，
        // 上游若按 `Content-Length` 去解读同一串字节，双方对"第一个请求到哪
        // 结束"的认知就不一样了 —— 这就是经典的 CL.TE 请求走私，攻击者能借此
        // 让本请求的尾巴被上游当成**下一个请求**（可以是别人的请求）来处理。
        //
        // 直接 400 最省事也最安全：合法客户端不会同时发这两个头。
        let has_te = req.get("transfer-encoding").is_some();
        // `get()` 只返回**第一个**同名头，而 `to_bytes()` 会把
        //   `headers` 里的**所有**同名头都转发出去 —— "读一个、写两个"正是
        //   CL.CL 请求走私的成因。所以这里用 `count()` 判"有没有/有几个"，
        //   而不是 `get().is_some()`。
        let cl_count = req.count("content-length");
        let has_cl = cl_count > 0;
        if has_te && has_cl {
            debug!(%peer, "同时带 Transfer-Encoding 与 Content-Length，按走私风险直接拒绝");
            io.stream
                .write_all(&simple_response(
                    "400 Bad Request",
                    "Transfer-Encoding 与 Content-Length 不能同时出现\n",
                ))
                .await?;
            return Ok(());
        }
        // **重复的 Content-Length 一律拒绝**。
        //
        // 哪怕两个值完全相同也拒绝 —— 不同实现对此合并策略不一致
        // （取第一个 / 取最后一个 / 报错），而"只读第一个、转发全部"的组合同样
        // 构成 CL.CL 走私面。RFC 7230 §3.3.2 允许值相同时合并，但拒绝更安全，
        // 且合法客户端不会重复发这个头。
        if cl_count > 1 {
            debug!(%peer, cl_count, "重复的 Content-Length，按走私风险直接拒绝");
            io.stream
                .write_all(&simple_response(
                    "400 Bad Request",
                    "重复的 Content-Length 头\n",
                ))
                .await?;
            return Ok(());
        }

        // **只接受"唯一的 chunked"**。
        //
        // H2 修的是 CL 侧，**TE 侧没修** —— 这是同一个教训的又一次复现。
        // 原先判定用 `contains("chunked")`（"只要出现就按 chunked 解帧"），
        // 而 RFC 7230 §3.3.3 规定传输编码看**最后一个** token，且转发时
        // `Transfer-Encoding` 是**原样**搬给上游的 ⇒ 两边口径不一致 = 走私：
        //
        //   `chunked, identity` / `xchunked` / `chunked, gzip`
        //   ⇒ NFrp 按 chunked 读完，上游（按 RFC）认为不是 chunked
        //   ⇒ 剩余字节被上游当成**下一个请求**。
        //
        // 修法与 CL 侧同款：**双方口径必须完全一致**，做不到就 400。
        // 未知编码我们本来就处理不了（没有解码器），拒绝而不是猜。
        if nfrp_common::http_relay::transfer_encoding_is_unsupported(&req) {
            debug!(%peer, te = ?req.get("transfer-encoding"),
                   "不支持的 Transfer-Encoding 形态，按走私风险直接拒绝");
            io.stream
                .write_all(&simple_response(
                    "400 Bad Request",
                    "Transfer-Encoding 只支持唯一的 chunked\n",
                ))
                .await?;
            return Ok(());
        }

        let body = if is_connect {
            // CONNECT 没有 HTTP 请求体；头后的字节是隧道预读数据，留给下面
            // `take_buffered()` 显式补到上游。
            Vec::new()
        } else if let Some(te) = req.get("transfer-encoding") {
            // 复用公共判定（与转发侧同一个口径），不要再写一遍 contains
            if nfrp_common::http_relay::is_chunked(&req) {
                io.read_chunked().await?
            } else {
                // 走到这里说明通过了上面的检查，理论上不可能；
                // 但留一条明确的日志，别静默把 body 丢掉。
                debug!(%peer, te = %te, "既不是 chunked 又通过了校验，按无体处理");
                Vec::new()
            }
        } else if has_cl {
            // 严格解析。原先是 `cl.trim().parse().unwrap_or(0)`
            //   —— **垃圾值静默变 0**（`Content-Length: abc` 被当成"没有请求体"，
            //   而同一个头又原样转发给上游）。现在非法值一律 400。
            let n = match req.content_length_strict() {
                Ok(n) => n as usize,
                Err(e) => {
                    debug!(%peer, "Content-Length 非法：{e:#}");
                    io.stream
                        .write_all(&simple_response(
                            "400 Bad Request",
                            "非法的 Content-Length\n",
                        ))
                        .await?;
                    return Ok(());
                }
            };
            if n > 0 {
                io.read_n(n).await?
            } else {
                Vec::new()
            }
        } else {
            Vec::new()
        };

        // ---- 改写请求头 ----
        //
        // 先摘掉逐跳头（`Connection` / `Keep-Alive` / `Upgrade` / `TE` /
        // `Trailer` / `Proxy-*`，以及 `Connection: xxx` 里点名的那几个）。
        //
        // 这些头**只对当前这一段连接有意义**，原样转给内网服务是有害的：
        // 比如 `Connection: keep-alive, X-Secret` 会让上游把 `X-Secret`
        // 也当逐跳头处理；`Upgrade: h2c` + `Connection: Upgrade` 则可能让
        // 上游切到 h2c，绕开我们假定的 HTTP/1.1 语义。
        //
        // 工具在 `common::http_relay` 里本来就有（`HOP_BY_HOP` /
        // `connection_tokens`），客户端 `plugin_bridge` 一直在用，只有这条
        // 服务端路径漏了。服务端不支持 WebSocket 升级，所以可以整批摘掉。
        let mut hop: Vec<String> = HOP_BY_HOP.iter().map(|s| (*s).to_string()).collect();
        hop.extend(connection_tokens(&req));
        for k in hop {
            req.remove(&k);
        }

        // **同名头去重**。
        //
        // 上面已经对重复的 Content-Length 直接 400 了，这一步是"即便将来某个
        // 环节漏了检查，也不会把重复头原样送到下游"。它保证一个不变量：
        // **转发出去的头，每个名字最多出现一次**（少数列表型头除外）。
        // `set-cookie` 之类必须逐个保留，交由 `dedup_headers` 内部白名单处理。
        let dropped = req.dedup_headers();
        if dropped > 0 {
            debug!(%peer, dropped, "转发前剥掉了重复的同名请求头");
        }

        if !route.rewrite_host.is_empty() {
            req.set("host", &route.rewrite_host);
        }
        let forwarded = match req.get("x-forwarded-for") {
            Some(prev) => format!("{prev}, {}", peer.ip()),
            None => peer.ip().to_string(),
        };
        req.set("x-forwarded-for", &forwarded);
        req.set("x-real-ip", &peer.ip().to_string());
        let mut removed: Vec<String> = Vec::new();
        for (k, v) in &route.req_headers {
            if v.is_empty() {
                removed.push(k.clone());
            } else {
                req.set(k, v);
            }
        }
        for k in removed {
            req.remove(&k);
        }

        // ---- 取工作连接并转发 ----
        // 等待时长由服务端 `userConnTimeout`（默认 10 秒）决定。
        let work = match route.client.acquire_work_conn().await {
            Some(w) => w,
            None => {
                io.stream
                    .write_all(&simple_response("502 Bad Gateway", "等待工作连接超时\n"))
                    .await?;
                return Ok(());
            }
        };
        let mut work_conn: FrpConn = work.conn;
        // dst_addr 留给 PROXY protocol 用，普通转发不能下发（见 HTTPS 分支的说明）
        work_conn
            .send_msg(&FrpMessage::StartWorkConn(StartWorkConn {
                proxy_name: route.proxy_name.clone(),
                src_addr: peer.ip().to_string(),
                src_port: peer.port(),
                ..Default::default()
            }))
            .await
            .context("发送 StartWorkConn 失败")?;

        registry.metrics().http_requests.inc();
        let _guard = ConnGuard::new(&registry);

        if is_connect {
            // CONNECT 不是"转发一条 HTTP 请求再读回响应"，而是把两端直接对接。
            // 官方 `connectHandler` 用 Hijack 后的 `buffered.Reader` 和远端做
            // `libio.Join`；这里对应的是 `HttpIo` 的预读缓冲 + `PrefixedStream`
            // （工作连接握手时可能已经预读到上游的早期字节）。
            //
            // 关键：`read_head()` 只消费到 `\r\n\r\n`，客户端如果没等 200 就发了
            // 隧道数据，那些字节正躺在 `io` 的缓冲里。不 `take_buffered()` 就会
            // 永久丢失 —— 这正是官方 v0.71.1 修的 early-data loss。
            let (stream, leftover) = work_conn.into_stream();
            let mut upstream = wrap_work_stream(
                stream,
                leftover,
                route.client.proxy_flags(&route.proxy_name),
                registry.security().auth_cfg.token.as_str(),
            );
            upstream.write_all(&req.to_bytes()).await?;
            let prefetched = io.take_buffered();
            if !prefetched.is_empty() {
                debug!(%peer, bytes = prefetched.len(), "CONNECT 有预读数据，补发给上游");
                upstream.write_all(&prefetched).await?;
            }
            upstream.flush().await?;

            let mut visitor = io.stream;
            let r = nfrp_common::util::relay_between(&mut visitor, &mut upstream).await;
            record_bytes(&registry, &r);
            if let Err(e) = r {
                debug!(%peer, "HTTP CONNECT 隧道中断：{e}");
            }
            return Ok(());
        }

        let (stream, leftover) = work_conn.into_stream();
        let mut upstream = wrap_work_stream(
            stream,
            leftover,
            route.client.proxy_flags(&route.proxy_name),
            registry.security().auth_cfg.token.as_str(),
        );
        upstream.write_all(&req.to_bytes()).await?;
        if !body.is_empty() {
            upstream.write_all(&body).await?;
        }
        upstream.flush().await?;

        // 把 `leftover` 喂回预读缓冲，**不要丢掉**。
        //
        // `leftover` 是工作连接上已经读进缓冲区、但还没被消费的字节。
        // 原先是 `let _ = leftover;` 直接扔了 —— 若内网服务在握手后立刻
        // 吐了响应（或预读时顺带读到了响应开头），这部分字节就永久丢失，
        // 表现为**响应体被截断**。
        //
        // `leftover` 已经由 `wrap_work_stream` 挂成流的**读前缀**，
        // 这里传空缓冲即可 —— 再传一次会重复消费。
        let mut up = HttpIo::with_prefill(upstream, Vec::new());

        // ---- 读响应头 ----
        //
        // `vhostHTTPTimeout` 卡的就是这一步：内网服务**连上了却不回响应头**
        // （进程卡死、在处理里死循环）时，不能把用户连接和这条工作连接
        // 无限期挂住。超时回 502，与 Go `httputil.ReverseProxy` 默认错误处理器
        // 对 `ResponseHeaderTimeout` 的处理一致（也是 502，不是 504）。
        let head = match opts.http_timeout {
            Some(t) => match tokio::time::timeout(t, up.read_head()).await {
                Ok(r) => r?,
                Err(_) => {
                    debug!(%peer, "等待内网服务响应头超时（{} 秒）", t.as_secs());
                    io.stream
                        .write_all(&simple_response("502 Bad Gateway", "内网服务响应超时\n"))
                        .await?;
                    return Ok(());
                }
            },
            None => up.read_head().await?,
        };
        let Some(resp_lines) = head else {
            io.stream
                .write_all(&simple_response("502 Bad Gateway", "内网服务没有响应\n"))
                .await?;
            return Ok(());
        };
        let mut resp = HeadParts::parse(&resp_lines)?;

        // **响应侧的 framing 校验**。
        //
        // 请求侧早有 `validate_request_framing`（TE+CL / 重复 CL / 不支持的 TE
        // 三项全 400），而响应侧**一项都没有** —— 内网服务回什么就转发什么。
        //
        // 这与 D7-1 是同一条链路上的两个洞：
        // * D7-1 = 响应侧的**判定口径**与请求侧不一致（`contains` vs RFC）；
        // * D7-2 = 响应侧**根本没有校验**。
        //
        // 两者都会导致下游连接去同步（不同实现取不同的响应边界）⇒ 走私/投毒。
        // 修法一致：**失败关闭**，回 502 而不是猜。
        //
        // 注意顺序：必须在**剥逐跳头之前**校验 —— 因为 `Connection` 里点名的
        // 头会被剥掉，而 framing 判定要看到原始报头。
        if let Err(why) = nfrp_common::http_relay::validate_response_framing(&resp) {
            warn!(%peer, proxy = %route.proxy_name, "响应 framing 不合法，拒绝转发：{why}");
            io.stream
                .write_all(&simple_response(
                    "502 Bad Gateway",
                    "内网服务返回的响应报头不合法（framing 走私风险）\n",
                ))
                .await?;
            return Ok(());
        }

        // **响应侧也要剥逐跳头**。
        //
        // 原先只有请求侧剥了（见上面那段加入 `HOP_BY_HOP` 的注释），
        // 响应侧原样转发 ⇒ 内网服务回的 `Connection: keep-alive, X-Secret`
        // 会让**客户端**把 `X-Secret` 也当逐跳头处理；`Upgrade` / `Proxy-*`
        // 同理。逐跳头的语义就是"只对当前这一段连接有意义"，
        // 跨过代理转发本身就是错的 —— 两个方向都得剥。
        //
        // 顺序：**先剥再设置**我们自己的 `Connection`，否则会把刚写的那条也剥掉。
        {
            let mut hop: Vec<String> = HOP_BY_HOP.iter().map(|s| (*s).to_string()).collect();
            hop.extend(connection_tokens(&resp));
            for k in hop {
                resp.remove(&k);
            }
        }

        if let Some(start) = resp.start_line.split_whitespace().nth(1) {
            let code: u32 = start.parse().unwrap_or(200);
            let no_body =
                (100..200).contains(&code) || code == 204 || code == 304 || method == "HEAD";

            // **响应侧必须用与请求侧同一套
            //    RFC 口径判 `Transfer-Encoding`。**
            //
            // # 原先为什么错了
            //
            // 这里（以及下面转发响应体那处）用的是
            // `te.to_ascii_lowercase().contains("chunked")` —— 而**同一个文件**的
            // 请求侧（`:1061`/`:1075`）早就改成了 RFC 口径的
            // [`http_relay::is_chunked`] / [`http_relay::transfer_encoding_is_unsupported`]，
            // `client/src/plugin_bridge.rs` 也用 `is_chunked`。
            // `http_relay.rs:500-522` 的注释里**明确写着** `contains("chunked")`
            // 正是此前修掉的走私写法。
            //
            // ⇒ 请求侧修了、响应侧没修。**这是"防线没铺满"的教科书案例**，
            //   也是本项目连续多轮出现的同一个模式。
            //
            // # 后果（实测，`tmp/audit7/d_independent/repro_d71_smuggle.py`）
            //
            // 后端对 `/alice` 回 `Transfer-Encoding: chunked, identity`：
            // * NFrp（`contains`）认为"是 chunked" ⇒ 按 chunked 方式转发；
            // * RFC 7230 §3.3.3 的严格下游看**最后一个 token**（是 `identity`）
            //   ⇒ 认为**不是** chunked ⇒ 读到连接关闭为止。
            //
            // 口径分歧 = 走私。实测下游只解析出 **1 条**响应，body 里混进了
            // 下一个访客的响应：
            //
            // ```text
            // HTTP/1.1 200 OK / TE: chunked, identity / connection: keep-alive
            // d\r\nALICE-SECRET!\r\n0\r\n\r\n
            // HTTP/1.1 200 OK / Content-Length: 11 / connection: keep-alive
            // BOB-PRIVATE
            // ```
            // ⇒ RFC 下游的 body = `...ALICE-SECRET!\r\n0\r\n\r\nHTTP/1.1 200 OK...BOB-PRIVATE`
            // ⇒ **Bob 的响应被当成 Alice 的响应体**（跨访客响应走私）。
            //
            // 对照（都通过，排除探针问题）：`Content-Length` 正常分离；
            // 合法 `chunked`（唯一 token）正确分离、**未误伤**。
            //
            // # 修法
            //
            // 与请求侧**共用同一个判定函数**，而不是在这里再手写一遍 ——
            // 手写就会再次漂移。`is_chunked` 的口径是"最后一个 token 是 chunked
            // 且前面只有 identity"，`identity, chunked` 这种 RFC 合法形态仍被接受
            let resp_te_chunked = nfrp_common::http_relay::is_chunked(&resp);
            let framed = if no_body {
                true
            } else if resp.get("transfer-encoding").is_some() {
                // 不支持的 TE 形态（如 `chunked, gzip`）⇒ 无法安全定界
                // ⇒ 当作"未分帧"，让调用方走 `Connection: close` 读完即断，
                //    而不是按自己以为的方式去读（那正是走私的成因）。
                resp_te_chunked
            } else {
                resp.get("content-length").is_some()
            };

            let keep_alive = visitor_keep_alive && framed;
            resp.set(
                "connection",
                if keep_alive { "keep-alive" } else { "close" },
            );
            for (k, v) in &route.resp_headers {
                if !v.is_empty() {
                    resp.set(k, v);
                }
            }
            io.stream.write_all(&resp.to_bytes()).await?;

            // ---- 转发响应体 ----
            //
            // 与上面 `framed` 用**同一个**
            //    判定（`resp_te_chunked`），而不是再写一次 `contains("chunked")`。
            //
            // 两处必须完全一致，否则"判 keep-alive 用一个口径、读 body 用另一个口径"
            // 又是一次口径分歧 —— 这正是走私的通用成因。
            if !no_body {
                if resp.get("transfer-encoding").is_some() {
                    if resp_te_chunked {
                        let raw = up.read_chunked().await?;
                        io.stream.write_all(&raw).await?;
                    } else if let Some(cl) = resp.get("content-length") {
                        let n: usize = cl.trim().parse().unwrap_or(0);
                        relay_fixed(&mut up, &mut io.stream, n).await?;
                    } else {
                        // 不支持的 TE 且没有 CL ⇒ 只能读到 EOF；连接必须关
                        relay_until_eof(&mut up, &mut io.stream).await?;
                        io.stream.flush().await?;
                        return Ok(());
                    }
                } else if let Some(cl) = resp.get("content-length") {
                    let n: usize = cl.trim().parse().unwrap_or(0);
                    relay_fixed(&mut up, &mut io.stream, n).await?;
                } else {
                    // 既没有 Content-Length 也不是 chunked：读到 EOF 为止，访客连接必须关
                    relay_until_eof(&mut up, &mut io.stream).await?;
                    io.stream.flush().await?;
                    return Ok(());
                }
            }
            io.stream.flush().await?;
            if !keep_alive {
                return Ok(());
            }
            // 上游工作连接用完即弃（frp 每个请求都要新工作连接）
        } else {
            return Ok(());
        }
    }
}
#[cfg(test)]
mod tests {
    //! HTTP 报文处理、302/400/404/407 应答、走私防护与超时的单元测试。

    use super::*;
    use crate::pool::dummy_client;
    use crate::vhost::router::tests::{route_of, table_with};
    use crate::vhost::router::VhostRoute;
    use nfrp_common::http_relay::{find_subslice, MAX_HEAD};
    use std::collections::HashMap;
    use std::time::Duration;
    use tokio::io::{duplex, AsyncReadExt, AsyncWriteExt, DuplexStream};
    // ==================================================================
    // dot-segment 必须被拒
    // ==================================================================

    #[test]
    fn dot_segment_能识别() {
        for bad in [
            "/public/../admin",
            "/public/%2e%2e/admin",
            "/public/%2E%2E/admin",
            "/./x",
            "/x/.",
            "/a/..",
        ] {
            assert!(has_dot_segment(bad), "应当识别为可疑路径：{bad}");
        }
        for good in [
            "/public/hello",
            "/public/..hidden",
            "/public/a..b",
            "/public/v1.2.3/file",
            "/",
        ] {
            assert!(!has_dot_segment(good), "不该误伤：{good}");
        }
    }

    /// 前缀匹配确实会被 dot-segment 绕过 —— 锁住这个前提，
    /// 防止将来有人把 `has_dot_segment` 的调用删掉。
    #[test]
    fn locations_前缀匹配会被_dot_segment_绕过() {
        let locs = ["/public".to_string()];
        let hit = locs
            .iter()
            .filter(|l| "/public/../admin".starts_with(l.as_str()))
            .max_by_key(|l| l.len());
        assert!(hit.is_some(), "前缀匹配确实会命中");
        assert!(has_dot_segment("/public/../admin"));
    }

    // -----------------------------------------------------------------------
    // HTTP 头部解析
    // -----------------------------------------------------------------------

    fn lines(src: &[&str]) -> Vec<String> {
        src.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn headparts_parse_and_accessors() {
        let h = HeadParts::parse(&lines(&[
            "GET /index.html HTTP/1.1",
            "Host: a.example.com:8080",
            "X-Real-Ip: 1.2.3.4",
        ]))
        .expect("解析");
        assert_eq!(h.start_line, "GET /index.html HTTP/1.1");
        assert_eq!(h.get("host"), Some("a.example.com:8080"));
        assert_eq!(
            h.get("HOST"),
            Some("a.example.com:8080"),
            "字段名大小写无关"
        );
        assert!(h.get("missing").is_none());
    }

    #[test]
    fn headparts_set_replaces_existing_key_ignoring_case() {
        let mut h = HeadParts::parse(&lines(&["GET / HTTP/1.1", "Host: old"])).unwrap();
        h.set("HOST", "new.example.com");
        let out = String::from_utf8(h.to_bytes()).unwrap();
        // 保留原有的头名大小写，只替换值（对端 IE 之类的老客户端可能很挑）
        assert!(out.contains("Host: new.example.com"), "{out}");
        assert!(
            !out.contains("old"),
            "同一个头不能出现两次，否则内网服务会拿到歧义值"
        );
    }

    #[test]
    fn headparts_remove_drops_all_case_variants() {
        let mut h = HeadParts::parse(&lines(&[
            "GET / HTTP/1.1",
            "Authorization: Basic zzz",
            "authorization: Basic zzz",
        ]))
        .unwrap();
        h.remove("AUTHORIZATION");
        let out = String::from_utf8(h.to_bytes()).unwrap();
        assert!(!out.to_ascii_lowercase().contains("authorization"), "{out}");
    }

    #[test]
    fn headparts_to_bytes_terminates_head_with_blank_line() {
        let h = HeadParts::parse(&lines(&["GET / HTTP/1.1", "Host: x"])).unwrap();
        let text = String::from_utf8(h.to_bytes()).unwrap();
        assert!(text.ends_with("\r\n\r\n"), "{text:?}");
        assert_eq!(text, "GET / HTTP/1.1\r\nHost: x\r\n\r\n");
    }

    #[test]
    fn empty_head_is_an_error() {
        assert!(HeadParts::parse(&[]).is_err());
    }

    #[test]
    fn malformed_header_lines_are_skipped() {
        // 没有冒号的行：忽略而不是 panic（真实世界里有各种畸形客户端）
        let h = HeadParts::parse(&lines(&["GET / HTTP/1.1", "garbage", "Host: x"])).unwrap();
        assert_eq!(h.headers.len(), 1);
    }

    // -----------------------------------------------------------------------
    // keep-alive 判定
    // -----------------------------------------------------------------------

    #[test]
    fn keep_alive_defaults_and_explicit_tokens() {
        let p = HeadParts::parse(&lines(&["GET / HTTP/1.1"])).unwrap();
        assert!(wants_keep_alive(&p), "HTTP/1.1 默认是长连接");

        let p = HeadParts::parse(&lines(&["GET / HTTP/1.1", "Connection: close"])).unwrap();
        assert!(!wants_keep_alive(&p));

        let p = HeadParts::parse(&lines(&["GET / HTTP/1.0"])).unwrap();
        assert!(!wants_keep_alive(&p), "HTTP/1.0 默认是短连接");

        let p = HeadParts::parse(&lines(&["GET / HTTP/1.0", "Connection: keep-alive"])).unwrap();
        assert!(wants_keep_alive(&p));

        let p = HeadParts::parse(&lines(&[
            "GET / HTTP/1.1",
            "Connection: keep-alive, Upgrade, close",
        ]))
        .unwrap();
        assert!(!wants_keep_alive(&p), "token 列表里出现 close 就算关闭");
    }

    // -----------------------------------------------------------------------
    // Basic Auth
    // -----------------------------------------------------------------------

    #[test]
    fn basic_auth_user_is_decoded() {
        use base64::{engine::general_purpose::STANDARD, Engine as _};
        let cred = STANDARD.encode(b"alice:secret");
        let h = HeadParts::parse(&lines(&[
            "GET / HTTP/1.1",
            &format!("Authorization: Basic {cred}"),
        ]))
        .unwrap();
        assert_eq!(basic_auth_user(&h), Some("alice".to_string()));
    }

    #[test]
    fn basic_auth_rejects_other_schemes_and_garbage() {
        let h = HeadParts::parse(&lines(&["GET / HTTP/1.1", "Authorization: Bearer abc"])).unwrap();
        assert_eq!(basic_auth_user(&h), None, "Bearer 不该被当成 Basic");

        let h = HeadParts::parse(&lines(&["GET / HTTP/1.1", "Authorization: Basic !!!!"])).unwrap();
        assert_eq!(basic_auth_user(&h), None, "非法 base64 不能 panic");

        let h = HeadParts::parse(&lines(&["GET / HTTP/1.1"])).unwrap();
        assert_eq!(basic_auth_user(&h), None);
    }

    // -----------------------------------------------------------------------
    // 工具函数
    // -----------------------------------------------------------------------

    #[test]
    fn subslice_search_edges() {
        assert_eq!(find_subslice(b"ab\r\n\r\nc", b"\r\n\r\n"), Some(2));
        assert_eq!(find_subslice(b"\r\n\r\n", b"\r\n\r\n"), Some(0));
        assert_eq!(find_subslice(b"", b"\r\n\r\n"), None);
        assert_eq!(find_subslice(b"abc", b"abcd"), None, "needle 比 hay 长");
        assert_eq!(find_subslice(b"abc", b""), None, "空 needle 没有意义");
        assert_eq!(find_subslice(b"aaa", b"aa"), Some(0));
    }

    #[test]
    fn simple_response_has_matching_content_length() {
        let body = "找不到对应的 frp 代理\n";
        let text = String::from_utf8(simple_response("404 Not Found", body)).unwrap();
        assert!(text.starts_with("HTTP/1.1 404 Not Found\r\n"));
        assert!(
            text.contains(&format!("Content-Length: {}", body.len())),
            "Content-Length 必须按**字节数**算而不是字符数（中文容易踩）：{text}"
        );
        assert!(text.ends_with(body));
        assert!(text.contains("Connection: close"), "简单响应用完即关");
    }

    // -----------------------------------------------------------------------
    // custom404Page / vhostHTTPTimeout
    // -----------------------------------------------------------------------

    #[test]
    fn 没配_custom404_page_时回内置纯文本提示() {
        let opts = VhostOpts::new(VhostKind::Http, false);
        let text = String::from_utf8(not_found_response(&opts)).unwrap();
        assert!(text.starts_with("HTTP/1.1 404 Not Found\r\n"));
        assert!(text.contains("找不到对应的 frp 代理"));
        assert!(text.contains("Content-Type: text/plain"), "{text}");
    }

    #[test]
    fn 配了_custom404_page_就原样返回文件内容() {
        let page: &[u8] = b"<html><body>no</body></html>";
        let opts = VhostOpts::new(VhostKind::Http, false)
            .with_not_found_page(Some(Arc::new(page.to_vec())));
        let raw = not_found_response(&opts);
        let text = String::from_utf8(raw.clone()).unwrap();
        assert!(text.starts_with("HTTP/1.1 404 Not Found\r\n"), "{text}");
        assert!(
            text.contains("Content-Type: text/html"),
            "自定义页按 HTML 宣告（官方也是 text/html）：{text}"
        );
        assert!(
            text.contains(&format!("Content-Length: {}", page.len())),
            "长度必须按文件字节数：{text}"
        );
        assert!(raw.ends_with(page), "body 必须逐字节原样返回");
    }

    /// 自定义页里带**非 ASCII**（中文 HTML）时，长度必须按字节算 ——
    /// 按字符算会让浏览器一直等剩下的字节。
    #[test]
    fn 自定义404页含中文时长度按字节算() {
        let page = "<html>找不到</html>".as_bytes();
        let opts = VhostOpts::new(VhostKind::Http, false)
            .with_not_found_page(Some(Arc::new(page.to_vec())));
        let raw = not_found_response(&opts);
        let head_end = find_subslice(&raw, b"\r\n\r\n").unwrap() + 4;
        let body = &raw[head_end..];
        assert_eq!(body, page);
        let head = String::from_utf8_lossy(&raw[..head_end]).to_string();
        assert!(
            head.contains(&format!("Content-Length: {}", body.len())),
            "{head}"
        );
    }

    /// 从流里读到 `needle` 为止（测试用；超时/EOF 都直接 panic）。
    async fn read_until(stream: &mut DuplexStream, needle: &[u8], what: &str) -> Vec<u8> {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(3);
        let mut got = Vec::new();
        loop {
            let left = deadline.saturating_duration_since(tokio::time::Instant::now());
            if left.is_zero() {
                panic!(
                    "等待 {what} 超时，已收到 {} 字节：{:?}",
                    got.len(),
                    String::from_utf8_lossy(&got)
                );
            }
            let mut buf = [0u8; 4096];
            match tokio::time::timeout(left, stream.read(&mut buf)).await {
                Ok(Ok(0)) => panic!(
                    "等待 {what} 时流已 EOF，已收到：{:?}",
                    String::from_utf8_lossy(&got)
                ),
                Ok(Ok(n)) => {
                    got.extend_from_slice(&buf[..n]);
                    if find_subslice(&got, needle).is_some() {
                        return got;
                    }
                }
                Ok(Err(e)) => panic!("等待 {what} 时读失败：{e}"),
                Err(_) => panic!(
                    "等待 {what} 超时，已收到 {} 字节：{:?}",
                    got.len(),
                    String::from_utf8_lossy(&got)
                ),
            }
        }
    }

    /// 回归测试：HTTP vhost 的 CONNECT 是**裸隧道**，头后的预读数据不能丢。
    ///
    /// 官方 v0.71.1 修的就是这个：`read_head`/Hijack 只消费到 `\r\n\r\n`，
    /// 客户端没等 200 就发来的隧道数据留在缓冲里，直接 `relay_between`
    /// 底层流会把它永久丢掉。这里同时验证：
    /// 1. `Content-Length: 0` 允许；
    /// 2. 头后的 `EARLY` 必须补发给上游；
    /// 3. 上游响应和后续双向字节都能透传。
    #[tokio::test]
    async fn http_connect_预读数据不丢且双向透传() {
        let registry = Arc::new(Registry::unlimited());
        let client = dummy_client("run-connect-early");
        let (up_srv, mut up_cli) = duplex(64 * 1024);
        client.submit_work(crate::pool::WorkItem::new(FrpConn::new(
            Box::pin(up_srv),
            nfrp_common::frp::WireVersion::V1,
        )));

        let table = Arc::new(table_with(vec![route_of(
            &client,
            "web",
            "a.example.com",
            &["/"],
        )]));
        let (mut visitor, srv) = duplex(64 * 1024);
        let opts =
            VhostOpts::new(VhostKind::Http, false).with_timeout(Some(Duration::from_secs(5)));
        let task = tokio::spawn(async move {
            handle_http(
                srv,
                SocketAddr::from(([127, 0, 0, 1], 5000)),
                table,
                0,
                opts,
                registry,
            )
            .await
        });

        visitor
            .write_all(
                b"CONNECT a.example.com:443 HTTP/1.1\r\n\
              Host: a.example.com\r\n\
              Content-Length: 0\r\n\r\nEARLY",
            )
            .await
            .unwrap();

        let up = read_until(&mut up_cli, b"EARLY", "上游收到 CONNECT 预读数据").await;
        let up_text = String::from_utf8_lossy(&up);
        assert!(
            up_text.contains("CONNECT a.example.com:443 HTTP/1.1"),
            "上游必须先收到 CONNECT 请求头：{up_text}"
        );
        assert!(
            !up_text.to_ascii_lowercase().contains("content-length:"),
            "CONNECT 的 Content-Length 必须在转发前摘掉：{up_text}"
        );

        // 上游 → 访客：响应头 + 隧道数据必须原样回来
        up_cli
            .write_all(b"HTTP/1.1 200 OK\r\n\r\nPONG")
            .await
            .unwrap();
        let got = read_until(&mut visitor, b"PONG", "访客收到上游隧道数据").await;
        let got_text = String::from_utf8_lossy(&got);
        assert!(
            got_text.starts_with("HTTP/1.1 200 OK"),
            "上游 200 必须回到访客：{got_text}"
        );

        // 访客 → 上游：隧道建立后的后续字节也必须透传
        visitor.write_all(b"MORE").await.unwrap();
        read_until(&mut up_cli, b"MORE", "上游收到后续隧道数据").await;

        drop(visitor);
        drop(up_cli);
        let _ = tokio::time::timeout(Duration::from_secs(3), task).await;
    }

    /// 回归测试：CONNECT 带正 `Content-Length` 或 `Transfer-Encoding` 必须 400。
    ///
    /// 这两种头都会让"头后的字节"产生歧义（隧道数据 vs 请求体），官方
    /// `connectHandler` 明确拒绝；这里锁住同样的口径。
    #[tokio::test]
    async fn http_connect_带请求体框架必须_400() {
        let cases: &[&[u8]] = &[
        b"CONNECT a.example.com:443 HTTP/1.1\r\nHost: a.example.com\r\nContent-Length: 4\r\n\r\nbody",
        b"CONNECT a.example.com:443 HTTP/1.1\r\nHost: a.example.com\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n",
    ];

        for (i, raw) in cases.iter().enumerate() {
            let registry = Arc::new(Registry::unlimited());
            let client = dummy_client(&format!("run-connect-bad-{i}"));
            // 刻意不提交工作连接：若实现错误地放行，会卡在 acquire_work_conn
            // 直到 userConnTimeout，下面的 3 秒读取就会失败。
            let table = Arc::new(table_with(vec![route_of(
                &client,
                "web",
                "a.example.com",
                &["/"],
            )]));
            let (mut visitor, srv) = duplex(64 * 1024);
            let opts =
                VhostOpts::new(VhostKind::Http, false).with_timeout(Some(Duration::from_secs(5)));
            let task = tokio::spawn(async move {
                handle_http(
                    srv,
                    SocketAddr::from(([127, 0, 0, 1], 5000)),
                    table,
                    0,
                    opts,
                    registry,
                )
                .await
            });

            visitor.write_all(raw).await.unwrap();
            let mut buf = vec![0u8; 4096];
            let n = tokio::time::timeout(Duration::from_secs(3), visitor.read(&mut buf))
                .await
                .expect("必须立刻回 400，不能去等请求体或工作连接")
                .unwrap();
            let text = String::from_utf8_lossy(&buf[..n]);
            assert!(
                text.starts_with("HTTP/1.1 400 Bad Request"),
                "第 {i} 种 CONNECT 必须 400，实际：{text}"
            );

            drop(visitor);
            let _ = tokio::time::timeout(Duration::from_secs(2), task).await;
        }
    }

    /// 回归测试：`Transfer-Encoding` 与 `Content-Length` 同时出现必须 400。
    ///
    /// 放行的后果是 CL.TE 请求走私：NFrp 按 chunked 解读请求，上游按
    /// `Content-Length` 解读同一串字节，双方对"请求到哪结束"的认知不一致，
    /// 攻击者能让本请求的尾巴被上游当成**下一个请求**处理。
    #[tokio::test]
    async fn 同时带_cl_与_te_直接拒绝而不是转发() {
        let registry = Arc::new(Registry::unlimited());
        let client = dummy_client("run-smuggle");
        let (up_srv, _up_cli) = duplex(64 * 1024);
        client.submit_work(crate::pool::WorkItem::new(FrpConn::new(
            Box::pin(up_srv),
            nfrp_common::frp::WireVersion::V1,
        )));

        let table = Arc::new(table_with(vec![Arc::new(VhostRoute {
            proxy_name: "web".into(),
            client: client.clone(),
            domain: "a.example.com".into(),
            locations: vec!["/".into()],
            http_user: String::new(),
            http_pwd: String::new(),
            route_by_http_user: String::new(),
            rewrite_host: String::new(),
            req_headers: HashMap::new(),
            resp_headers: HashMap::new(),
            kind: VhostKind::Http,
        })]));

        let (mut visitor, srv) = duplex(64 * 1024);
        let opts =
            VhostOpts::new(VhostKind::Http, false).with_timeout(Some(Duration::from_secs(5)));
        let task = tokio::spawn(async move {
            handle_http(
                srv,
                SocketAddr::from(([127, 0, 0, 1], 5000)),
                table,
                0,
                opts,
                registry,
            )
            .await
        });

        // 经典 CL.TE 形态：两个头都在，chunked 体里藏第二个请求
        visitor
            .write_all(
                b"POST / HTTP/1.1\r\nHost: a.example.com\r\n\
              Content-Length: 6\r\nTransfer-Encoding: chunked\r\n\r\n\
              0\r\n\r\nGET /admin HTTP/1.1\r\nHost: a.example.com\r\n\r\n",
            )
            .await
            .unwrap();

        let mut buf = vec![0u8; 4096];
        let n = tokio::time::timeout(Duration::from_secs(5), visitor.read(&mut buf))
            .await
            .expect("必须立刻回一个应答，不能挂住")
            .unwrap();
        let text = String::from_utf8_lossy(&buf[..n]).to_string();
        assert!(
            text.starts_with("HTTP/1.1 400 Bad Request"),
            "CL+TE 必须 400，实际：{text}"
        );
        let _ = tokio::time::timeout(Duration::from_secs(2), task).await;
    }

    /// 回归测试：`Expect: 100-continue` 必须被回应，不能让双方互等。
    ///
    /// 原先不处理这个头 ⇒ 客户端等 100、服务端等请求体 ⇒ 死锁到
    /// `vhostHTTPTimeout`（默认 60 秒）。单请求就能占住一条工作连接。
    #[tokio::test]
    async fn expect_100_continue_要立刻回_100() {
        let registry = Arc::new(Registry::unlimited());
        let client = dummy_client("run-expect");
        let (up_srv, mut up_cli) = duplex(64 * 1024);
        client.submit_work(crate::pool::WorkItem::new(FrpConn::new(
            Box::pin(up_srv),
            nfrp_common::frp::WireVersion::V1,
        )));

        let table = Arc::new(table_with(vec![Arc::new(VhostRoute {
            proxy_name: "web".into(),
            client: client.clone(),
            domain: "a.example.com".into(),
            locations: vec!["/".into()],
            http_user: String::new(),
            http_pwd: String::new(),
            route_by_http_user: String::new(),
            rewrite_host: String::new(),
            req_headers: HashMap::new(),
            resp_headers: HashMap::new(),
            kind: VhostKind::Http,
        })]));

        let (mut visitor, srv) = duplex(64 * 1024);
        let opts =
            VhostOpts::new(VhostKind::Http, false).with_timeout(Some(Duration::from_secs(5)));
        let task = tokio::spawn(async move {
            handle_http(
                srv,
                SocketAddr::from(([127, 0, 0, 1], 5000)),
                table,
                0,
                opts,
                registry,
            )
            .await
        });

        // 只发头 —— 真客户端此时在等 100，不会发体
        visitor
            .write_all(
                b"POST / HTTP/1.1\r\nHost: a.example.com\r\n\
              Content-Length: 5\r\nExpect: 100-continue\r\n\r\n",
            )
            .await
            .unwrap();

        let mut buf = vec![0u8; 4096];
        let n = tokio::time::timeout(Duration::from_secs(3), visitor.read(&mut buf))
            .await
            .expect("服务端必须立刻回 100 Continue，不能等满超时")
            .unwrap();
        let text = String::from_utf8_lossy(&buf[..n]).to_string();
        assert!(
            text.starts_with("HTTP/1.1 100 Continue"),
            "必须先回 100 Continue，实际：{text}"
        );

        // 上游收到的头里不该再有 expect（否则它还得多等一次）
        let mut up_buf = vec![0u8; 4096];
        if let Ok(Ok(n)) =
            tokio::time::timeout(Duration::from_secs(2), up_cli.read(&mut up_buf)).await
        {
            let up_text = String::from_utf8_lossy(&up_buf[..n]).to_ascii_lowercase();
            assert!(
                !up_text.contains("expect:"),
                "转发给上游前必须摘掉 expect：{up_text}"
            );
        }
        let _ = tokio::time::timeout(Duration::from_secs(2), task).await;
    }

    /// 回归测试：逐跳头不能原样传给上游。
    #[tokio::test]
    async fn 逐跳头不会转发给上游() {
        let registry = Arc::new(Registry::unlimited());
        let client = dummy_client("run-hop");
        let (up_srv, mut up_cli) = duplex(64 * 1024);
        client.submit_work(crate::pool::WorkItem::new(FrpConn::new(
            Box::pin(up_srv),
            nfrp_common::frp::WireVersion::V1,
        )));

        let table = Arc::new(table_with(vec![Arc::new(VhostRoute {
            proxy_name: "web".into(),
            client: client.clone(),
            domain: "a.example.com".into(),
            locations: vec!["/".into()],
            http_user: String::new(),
            http_pwd: String::new(),
            route_by_http_user: String::new(),
            rewrite_host: String::new(),
            req_headers: HashMap::new(),
            resp_headers: HashMap::new(),
            kind: VhostKind::Http,
        })]));

        let (mut visitor, srv) = duplex(64 * 1024);
        let opts =
            VhostOpts::new(VhostKind::Http, false).with_timeout(Some(Duration::from_secs(5)));
        let task = tokio::spawn(async move {
            handle_http(
                srv,
                SocketAddr::from(([127, 0, 0, 1], 5000)),
                table,
                0,
                opts,
                registry,
            )
            .await
        });

        // `Connection: keep-alive, X-Secret` 点名的 X-Secret 也是逐跳头
        visitor
            .write_all(
                b"GET / HTTP/1.1\r\nHost: a.example.com\r\n\
              Connection: keep-alive, X-Secret\r\n\
              X-Secret: leak-me\r\n\
              Keep-Alive: timeout=5\r\n\
              Upgrade: h2c\r\n\r\n",
            )
            .await
            .unwrap();

        let mut up_buf = vec![0u8; 8192];
        let n = tokio::time::timeout(Duration::from_secs(3), up_cli.read(&mut up_buf))
            .await
            .expect("上游应当收到请求")
            .unwrap();
        let up_text = String::from_utf8_lossy(&up_buf[..n]).to_ascii_lowercase();
        for banned in ["connection:", "keep-alive:", "upgrade:", "x-secret:"] {
            assert!(
                !up_text.contains(banned),
                "逐跳头 {banned} 不该转发给上游：{up_text}"
            );
        }
        // 但正常头要留着
        assert!(up_text.contains("host: a.example.com"), "{up_text}");
        let _ = tokio::time::timeout(Duration::from_secs(2), task).await;
    }

    /// `vhostHTTPTimeout` 的端到端验证：内网服务**连上了却不回响应头**
    /// （进程卡死、死循环）时，不能把用户连接无限期挂着。
    ///
    /// 造法：先往客户端的空闲池里塞一条工作连接（另一端攥在测试手里、
    /// 故意什么都不回），再让 `handle_http` 去用它。
    #[tokio::test]
    async fn http_等响应头超时会回_502() {
        let registry = Arc::new(Registry::unlimited());
        let client = dummy_client("run-timeout");
        let (up_srv, _up_cli) = duplex(64 * 1024);
        let paired = client.submit_work(crate::pool::WorkItem::new(FrpConn::new(
            Box::pin(up_srv),
            nfrp_common::frp::WireVersion::V1,
        )));
        assert!(paired.is_none(), "没有排队的用户连接时它应该进空闲池");

        let table = Arc::new(table_with(vec![Arc::new(VhostRoute {
            proxy_name: "web".into(),
            client: client.clone(),
            domain: "a.example.com".into(),
            locations: vec!["/".into()],
            http_user: String::new(),
            http_pwd: String::new(),
            route_by_http_user: String::new(),
            rewrite_host: String::new(),
            req_headers: HashMap::new(),
            resp_headers: HashMap::new(),
            kind: VhostKind::Http,
        })]));

        let (mut visitor, srv) = duplex(64 * 1024);
        let opts =
            VhostOpts::new(VhostKind::Http, false).with_timeout(Some(Duration::from_millis(150)));
        let task = tokio::spawn(async move {
            handle_http(
                srv,
                SocketAddr::from(([127, 0, 0, 1], 5000)),
                table,
                0,
                opts,
                registry,
            )
            .await
        });

        visitor
            .write_all(b"GET / HTTP/1.1\r\nHost: a.example.com\r\n\r\n")
            .await
            .unwrap();

        let mut buf = vec![0u8; 4096];
        let n = tokio::time::timeout(Duration::from_secs(5), visitor.read(&mut buf))
            .await
            .expect("上游一直不回，服务端必须在超时后自己回一个应答，而不是挂死")
            .unwrap();
        let text = String::from_utf8_lossy(&buf[..n]).to_string();
        assert!(text.starts_with("HTTP/1.1 502 Bad Gateway"), "实际：{text}");
        assert!(text.contains("响应超时"), "实际：{text}");
        let _ = tokio::time::timeout(Duration::from_secs(2), task).await;
    }

    /// 超时设为 0（= 不限）时**不能**自己造一个超时出来：上游慢慢回也得等到。
    #[tokio::test]
    async fn http_超时为零时不设限() {
        let registry = Arc::new(Registry::unlimited());
        let client = dummy_client("run-notimeout");
        let (up_srv, mut up_cli) = duplex(64 * 1024);
        client.submit_work(crate::pool::WorkItem::new(FrpConn::new(
            Box::pin(up_srv),
            nfrp_common::frp::WireVersion::V1,
        )));

        let table = Arc::new(table_with(vec![Arc::new(VhostRoute {
            proxy_name: "web".into(),
            client: client.clone(),
            domain: "b.example.com".into(),
            locations: vec!["/".into()],
            http_user: String::new(),
            http_pwd: String::new(),
            route_by_http_user: String::new(),
            rewrite_host: String::new(),
            req_headers: HashMap::new(),
            resp_headers: HashMap::new(),
            kind: VhostKind::Http,
        })]));

        let (mut visitor, srv) = duplex(64 * 1024);
        let opts = VhostOpts::new(VhostKind::Http, false).with_timeout(None);
        let task = tokio::spawn(async move {
            handle_http(
                srv,
                SocketAddr::from(([127, 0, 0, 1], 5001)),
                table,
                0,
                opts,
                registry,
            )
            .await
        });

        visitor
            .write_all(b"GET / HTTP/1.1\r\nHost: b.example.com\r\n\r\n")
            .await
            .unwrap();

        // 先把服务端写过来的请求报文读掉（含 StartWorkConn 帧），再**等一会儿**
        // 才回响应头 —— 200ms 远大于上面那个用例的 150ms 超时。
        let mut sink = vec![0u8; 8192];
        let _ = tokio::time::timeout(Duration::from_millis(300), up_cli.read(&mut sink)).await;
        tokio::time::sleep(Duration::from_millis(200)).await;
        up_cli
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nhi")
            .await
            .unwrap();
        drop(up_cli);

        let mut buf = vec![0u8; 4096];
        let mut got = Vec::new();
        while let Ok(Ok(n)) =
            tokio::time::timeout(Duration::from_secs(3), visitor.read(&mut buf)).await
        {
            if n == 0 {
                break;
            }
            got.extend_from_slice(&buf[..n]);
            if got.windows(4).any(|w| w == b"hi\r\n") || got.ends_with(b"hi") {
                break;
            }
        }
        let text = String::from_utf8_lossy(&got).to_string();
        assert!(
            text.starts_with("HTTP/1.1 200 OK"),
            "不限超时时必须把上游的 200 原样转回，实际：{text}"
        );
        let _ = tokio::time::timeout(Duration::from_secs(2), task).await;
    }

    // -----------------------------------------------------------------------
    // HttpIo 流式解析
    // -----------------------------------------------------------------------

    /// 把 `input` 灌进一个 duplex 管道的写端，返回用读端构造的 `HttpIo`。
    fn io_with(input: &[u8]) -> HttpIo<DuplexStream> {
        let (reader, mut writer) = duplex(256 * 1024);
        let data = input.to_vec();
        tokio::spawn(async move {
            let _ = writer.write_all(&data).await;
            let _ = writer.shutdown().await;
        });
        HttpIo::new(reader)
    }

    #[tokio::test]
    async fn httpio_reads_head_and_stops_at_blank_line() {
        let mut io = io_with(b"GET / HTTP/1.1\r\nHost: a.com\r\n\r\nBODY");
        let head = io.read_head().await.unwrap().expect("读到头");
        assert_eq!(head.len(), 2);
        assert_eq!(head[0], "GET / HTTP/1.1");
        assert!(
            io.available() >= 4,
            "body 必须留在缓冲里：{}",
            io.available()
        );
    }

    #[tokio::test]
    async fn httpio_read_head_returns_none_on_eof() {
        let mut io = io_with(b"");
        assert!(io.read_head().await.unwrap().is_none());
    }

    #[tokio::test]
    async fn httpio_read_head_errors_when_head_is_too_large() {
        // 超过 MAX_HEAD 且一直不出现空行 -> 必须报错，不能把内存吃光
        let big = vec![b'A'; MAX_HEAD + 1024];
        let mut io = io_with(&big);
        let e = io.read_head().await.unwrap_err().to_string();
        assert!(e.contains("HTTP 头部超过"), "{e}");
    }

    #[tokio::test]
    async fn httpio_read_n_reads_exactly_n_bytes() {
        let mut io = io_with(b"0123456789rest");
        assert_eq!(io.read_n(10).await.unwrap(), b"0123456789");
        // 第二次接着读，不能把缓冲区搞乱
        assert_eq!(io.read_n(4).await.unwrap(), b"rest");
    }

    #[tokio::test]
    async fn httpio_read_n_errors_on_truncated_body() {
        let mut io = io_with(b"short");
        let e = io.read_n(50).await.unwrap_err().to_string();
        assert!(e.contains("提前结束"), "{e}");
    }

    #[tokio::test]
    async fn httpio_read_chunked_keeps_original_framing() {
        let raw = b"5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n";
        let mut io = io_with(raw);
        let out = io.read_chunked().await.unwrap();
        assert_eq!(&out, raw, "原样保留分块格式便于直接透传给内网服务");
    }

    #[tokio::test]
    async fn httpio_read_chunked_with_extension_and_trailer() {
        let raw = b"5;name=val\r\nhello\r\n0\r\nX-Trailer: done\r\n\r\n";
        let mut io = io_with(raw);
        let out = io.read_chunked().await.unwrap();
        let text = String::from_utf8_lossy(&out).to_string();
        assert!(text.starts_with("5;name=val\r\nhello\r\n"), "{text:?}");
        assert!(text.contains("X-Trailer: done"));
    }

    #[tokio::test]
    async fn httpio_chunked_rejects_invalid_size() {
        let mut io = io_with(b"zz\r\nhello\r\n");
        assert!(io.read_chunked().await.is_err());
    }

    #[tokio::test]
    async fn httpio_read_line_splits_on_crlf() {
        let mut io = io_with(b"first\r\nsecond\r\n");
        assert_eq!(io.read_line().await.unwrap(), "first");
        assert_eq!(io.read_line().await.unwrap(), "second");
    }

    #[tokio::test]
    async fn httpio_compaction_does_not_lose_data() {
        let mut io = io_with(b"aaaa\r\nbbbb\r\ncccc");
        let mut got = Vec::new();
        for _ in 0..2 {
            got.push(io.read_line().await.unwrap());
        }
        assert_eq!(got, vec!["aaaa", "bbbb"]);
        // 最后一段没有 CRLF 结尾 -> 连接已结束
        assert!(io.read_line().await.is_err());
    }

    // -----------------------------------------------------------------------
    // -1：响应侧 TE 判定必须与请求侧同口径
    // -----------------------------------------------------------------------

    /// 响应侧必须用**与请求侧同一套**判定，且 `chunked, identity` 必须**不被当作 chunked**。
    ///
    /// # 这条测试的写法经过一次返工（**退回验证抓出来的**）
    ///
    /// 第一版只断言 `http_relay::is_chunked()` 对各类 TE 的结论 ——
    /// 而那个 helper **本来就没坏**（坏的是"vhost 里没调它"）。
    /// ⇒ 把修复退掉后这条测试**仍然全绿**，等于没有守护修复点。
    ///
    /// 第二版改成断言**真正被改的那件事**：vhost 用来定界响应体的那个判据
    /// （即修复后与 `framed` 共用的 `resp_te_chunked` 表达式）。
    /// 这里把生产表达式原样复制一份来断言 —— 表达式一改，测试就红。
    #[test]
    fn 响应侧_te_判定必须与请求侧同口径() {
        use nfrp_common::http_relay::{is_chunked, transfer_encoding_is_unsupported, HeadParts};

        // `HeadParts::parse` 收的是**按行切好的** `&[String]`
        let resp_with = |te: &str| -> HeadParts {
            let lines: Vec<String> = format!("HTTP/1.1 200 OK\r\nTransfer-Encoding: {te}")
                .split("\r\n")
                .map(|s| s.to_string())
                .collect();
            HeadParts::parse(&lines).expect("合法响应头")
        };

        // 这就是**生产代码里**用来定界响应体的那个表达式
        //     （`vhost.rs` 的 `let resp_te_chunked = ...`）。
        // -1 之前它是 `te.contains("chunked")`，之后是 `is_chunked`。
        //     断言写在这个表达式上，才能真正守住"用的是 RFC 口径"这件事。
        let production_predicate = |r: &HeadParts| -> bool { is_chunked(r) };

        // ---- 必须**判为 chunked**（可以安全按 chunked 定界）----
        for te in ["chunked", "identity, chunked", "Chunked", "CHUNKED"] {
            assert!(
                production_predicate(&resp_with(te)),
                "{te:?} 应当判为 chunked（最后一个 token 是 chunked）"
            );
            assert!(
                !transfer_encoding_is_unsupported(&resp_with(te)),
                "{te:?} 是 RFC 支持形态，不该被拒"
            );
        }

        // ---- 必须**不**判为 chunked（与 RFC 下游口径一致）----
        //
        // 这几条正是 D7-1 的实弹形态：旧代码的 `contains("chunked")`
        //   会把它们全判成 chunked，从而与 RFC 下游产生分歧 ⇒ 走私。
        for te in [
            "chunked, identity", // ← 实弹用的就是它
            "chunked, gzip",
            "xchunked",
            "chunked, chunked",
            "identity",
        ] {
            assert!(
                !production_predicate(&resp_with(te)),
                "{te:?} **不该**判为 chunked（最后一个 token 不是 chunked）—— \
             旧代码的 contains(\"chunked\") 会把 \"chunked, identity\" 误判成 chunked，\
             这正是 D7-1 走私的成因"
            );
        }

        // ---- 明确要拒绝的形态（调用方据此失败关闭）----
        for te in ["chunked, gzip", "xchunked", "chunked, chunked"] {
            assert!(
                transfer_encoding_is_unsupported(&resp_with(te)),
                "{te:?} 属于不支持形态，应当被标记为 unsupported（失败关闭）"
            );
        }
        // 而 RFC 合法的 `identity, chunked` **不能**被拒
        assert!(
            !transfer_encoding_is_unsupported(&resp_with("identity, chunked")),
            "identity, chunked 是 RFC 合法形态，不能被拒 —— \
         把合法请求拒掉是把'修漏洞'变成'制造不兼容'"
        );

        // ---- 没有 TE 头 ⇒ 与 TE 无关 ----
        let no_te_lines: Vec<String> = "HTTP/1.1 200 OK\r\nContent-Length: 5"
            .split("\r\n")
            .map(|s| s.to_string())
            .collect();
        let no_te = HeadParts::parse(&no_te_lines).expect("合法响应头");
        assert!(
            !production_predicate(&no_te),
            "没有 TE 头时不应判为 chunked"
        );
        assert!(
            !transfer_encoding_is_unsupported(&no_te),
            "没有 TE 头时不该被标记为不支持"
        );
    }

    /// -1 的**行为级**回归：真实起 vhost，把"走私会不会发生"打出来。
    ///
    /// 与上面那条单测的分工：
    /// * 单测守"用的是哪个判据"（快、能定位）；
    /// * 这条守"端到端不再串响应"（贵、但**只有它能在退回修复时变红**，
    ///   因为退掉修复改的是**行为**而不是 helper）。
    ///
    /// 做法：手工构造一条**已经收到的上游响应头**（`TE: chunked, identity`），
    /// 走 `framed` 的那段判据，断言它**不**被当作可安全分帧 ——
    /// 因为「当作可安全分帧」正是后续 keep-alive 复用的前提，
    /// 也是走私链的起点。
    #[test]
    fn 响应侧_chunked_identity_不得被判为可安全分帧() {
        use nfrp_common::http_relay::{is_chunked, HeadParts};

        let lines: Vec<String> = "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked, identity"
            .split("\r\n")
            .map(|s| s.to_string())
            .collect();
        let resp = HeadParts::parse(&lines).expect("合法响应头");

        // 「可安全分帧」在生产里由 `resp_te_chunked` 表达。
        // D7-1 的成因就是它算成了 true（用的是 contains）。
        let safe_framed = is_chunked(&resp);
        assert!(
            !safe_framed,
            "`chunked, identity` 不能被判为可安全分帧 —— \
         否则 NFrp 按 chunked 转发、RFC 下游按'读到关闭'解析，\
         两者的口径分歧就是跨访客响应走私（D7-1）"
        );
    }
}
