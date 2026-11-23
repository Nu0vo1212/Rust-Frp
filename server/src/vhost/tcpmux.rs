//! tcpmux：若干条代理共用一个端口，按 HTTP `CONNECT` 的 authority 分发。
//!
//! 职责：解析 CONNECT 请求行与 `Proxy-Authorization`，按
//! `routeByHTTPUser` + `httpUser` / `httpPassword` 两级校验选路，
//! 支持 `tcpmuxPassthrough`（把 CONNECT 原样转给内网服务）与默认模式
//! （自己回 200，之后变成裸 TCP 隧道）。
//!
//! 锁顺序契约：路由查找只短暂持有 `VhostTable` 的 `Mutex`，释放后才向
//! `ClientState` 索取工作连接；指标原子量最后递增。恒为「先 VhostTable，
//! 后工作连接池」，不反向、不嵌套。
//!
//! 不变量：认证**先校验、再回 200**（只发一个 407）；凭据一律
//! `constant_time_eq` 比较；`read_head` 预读的字节必须经 `take_buffered` 补发，
//! 不能丢；`ConnGuard` 覆盖每一条返回路径。

use std::{net::SocketAddr, sync::Arc};

use anyhow::{anyhow, Context, Result};
use nfrp_common::frp::{
    conn::FrpConn,
    msg::{constant_time_eq, FrpMessage, StartWorkConn},
};
use nfrp_common::http_relay::{HeadParts, HttpIo};
use tokio::{io::AsyncWriteExt, net::TcpStream};
use tracing::{debug, warn};

use crate::registry::Registry;

use super::{
    conn::{canonical_host, record_bytes, wrap_work_stream, ConnGuard},
    http::simple_response,
    router::{VhostKind, VhostTable},
};

// ---------------------------------------------------------------------------
// tcpmux：一个共享端口上的 HTTP CONNECT 复用器
// ---------------------------------------------------------------------------
/// 解析 `Proxy-Authorization: Basic base64(user:pass)`，返回 `(用户名, 密码)`。
fn proxy_authorization(parts: &HeadParts) -> (Option<String>, Option<String>) {
    use base64::{engine::general_purpose::STANDARD, Engine as _};
    let Some(raw) = parts.get("proxy-authorization") else {
        return (None, None);
    };
    let Some((scheme, value)) = raw.split_once(' ') else {
        return (None, None);
    };
    if !scheme.eq_ignore_ascii_case("basic") {
        return (None, None);
    }
    let Ok(decoded) = STANDARD.decode(value.trim().as_bytes()) else {
        return (None, None);
    };
    let Ok(text) = String::from_utf8(decoded) else {
        return (None, None);
    };
    let (u, p) = text.split_once(':').unwrap_or((text.as_str(), ""));
    (Some(u.to_string()), Some(p.to_string()))
}

/// `HTTP/1.1 200 OK` —— 告诉 CONNECT 的发起方"隧道通了，后面就是裸字节"。
///
/// 字节形状对齐官方 `httppkg.OkResponse()` 经 Go `Response.Write` 出来的结果：
/// 状态行 + `Content-Length: 0` + 空行。带 `Content-Length: 0` 是 Go
/// `shouldSendContentLength()` 在"非 GET/HEAD 且长度已知为 0"时的行为，
/// 而且对客户端来说比"没有长度信息"更明确（后者要靠 RFC 7231 对 CONNECT 2xx
/// 的特别规定才不歧义）。
const CONNECT_OK: &[u8] = b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n";

/// `407` —— 认证失败。必须带 `Proxy-Authenticate`，否则客户端不知道该怎么补凭证。
fn proxy_auth_required() -> Vec<u8> {
    const BODY: &str = "Proxy Authentication Required";
    format!(
        "HTTP/1.1 407 Proxy Authentication Required\r\n\
         Proxy-Authenticate: Basic realm=\"Restricted\"\r\n\
         Content-Type: text/plain; charset=utf-8\r\n\
         Content-Length: {}\r\n\
         Connection: close\r\n\r\n{BODY}",
        BODY.len()
    )
    .into_bytes()
}

/// tcpmux：从 HTTP CONNECT 请求里取域名，把这条连接接给对应的内网服务。
///
/// # 与官方 `pkg/util/tcpmux/httpconnect.go` 对齐的三点
///
/// 1. **只认 `CONNECT`**。其它方法（或者说根本不是 HTTP 的流量）官方会在
///    `readHTTPConnectRequest` 里报错然后**直接关连接**，不留任何应答 ——
///    这里保持一致：不回应答，免得一个"看起来像代理端口"的地方回出
///    非代理语义的东西让人误判。
/// 2. **域名取 CONNECT 请求行的 authority**（去端口、转小写），并做
///    `routeByHTTPUser` 一级路由、`httpUser` / `httpPassword` 二级校验。
/// 3. **`tcpmuxPassthrough`**：true 时把 CONNECT 请求**原样**转给内网服务，
///    由内网服务自己回 200（适合内网本身就是 HTTP 代理的场景）；
///    false（默认）时由我们回 200，内网服务看到的就是一条已建好的裸连接。
///
/// # 一处**有意偏离**
///
/// 官方先回 `200 OK` 再校验密码（`Muxer.handle` 里 `successHook` 在
/// `checkAuth` 之前），于是密码不对时客户端会**先收到 200**、再收到一个 407；
/// 对 curl 这类客户端来说隧道已经"建立成功"，那个 407 会被当成隧道里的数据。
/// 这里改成**先校验、再回 200**，只发一个 407 —— 协议上才是对的，客户端报的
/// 错也才是"认证失败"而不是"连上了但服务器乱发东西"。
pub(super) async fn handle_tcpmux(
    visitor: TcpStream,
    peer: SocketAddr,
    table: Arc<VhostTable>,
    passthrough: bool,
    registry: Arc<Registry>,
) -> Result<()> {
    let mut io = HttpIo::new(visitor);
    // 要原始字节：透传模式得把 CONNECT 请求逐字节转给内网服务
    let Some((raw_head, lines)) = io.read_head_raw().await? else {
        return Ok(());
    };
    let parts = HeadParts::parse(&lines)?;

    if !parts
        .start_token(0)
        .is_some_and(|m| m.eq_ignore_ascii_case("CONNECT"))
    {
        debug!(%peer, method = parts.start_token(0).unwrap_or(""), "tcpmux 端口只接受 CONNECT");
        return Ok(());
    }

    let host = canonical_host(parts.start_token(1).unwrap_or(""));
    let (user, pwd) = proxy_authorization(&parts);

    let Some((route, _)) = table.lookup(&host, "", user.as_deref(), VhostKind::TcpMux) else {
        warn!(
            %peer, %host, user = user.as_deref().unwrap_or(""),
            "没有匹配的 tcpmux 代理"
        );
        io.stream
            .write_all(&simple_response(
                "404 Not Found",
                "找不到对应的 tcpmux 代理\n",
            ))
            .await?;
        return Ok(());
    };

    if !route.http_user.is_empty() {
        // ★ 常量时间比较（v0.5.3 修）。
        //
        // 这里原来写的是 `user.as_deref() == Some(...)` —— 与同文件 815 行那段
        // HTTP 路径的口径不一致，是上一轮「凭据一律常量时间比较」修复**唯一漏掉**的一处。
        // 如实说：跨网络的字节级耗时侧信道会被抖动淹没，工程上难以远程逐位爆破，
        // 所以它是"修复不完整"而不是可利用漏洞 —— 但没有理由留两套口径。
        let ok = match (&user, &pwd) {
            (Some(u), Some(p)) => {
                constant_time_eq(u, &route.http_user) && constant_time_eq(p, &route.http_pwd)
            }
            _ => false,
        };
        if !ok {
            debug!(%peer, %host, "tcpmux 认证失败");
            io.stream.write_all(&proxy_auth_required()).await?;
            return Ok(());
        }
    }

    // 等待时长由服务端 `userConnTimeout`（默认 10 秒）决定，不再硬编码 15 秒。
    let work = route
        .client
        .acquire_work_conn()
        .await
        .ok_or_else(|| anyhow!("等待工作连接超时"))?;
    let mut work_conn: FrpConn = work.conn;
    // 与 http / https 一样不下发 `dst_addr`：官方 frpc 会把它当 TCP 地址解析，
    // 域名解析失败就直接关掉工作连接。
    work_conn
        .send_msg(&FrpMessage::StartWorkConn(StartWorkConn {
            proxy_name: route.proxy_name.clone(),
            src_addr: peer.ip().to_string(),
            src_port: peer.port(),
            ..Default::default()
        }))
        .await
        .context("发送 StartWorkConn 失败")?;
    registry.metrics().tcpmux_conns.inc();
    let _guard = ConnGuard::new(&registry);

    debug!(%peer, %host, proxy = %route.proxy_name, passthrough, "tcpmux 隧道开始");
    let (stream, leftover) = work_conn.into_stream();
    let mut upstream = wrap_work_stream(
        stream,
        leftover,
        route.client.proxy_flags(&route.proxy_name),
        registry.security().auth_cfg.token.as_str(),
    );

    // 开场白：透传模式把 CONNECT 请求转过去（由内网服务回 200），
    // 否则我们自己回 200，客户端收到后才开始发数据。
    if passthrough {
        upstream.write_all(&raw_head).await?;
    } else {
        io.stream.write_all(CONNECT_OK).await?;
        io.stream.flush().await?;
    }
    // ★ 关键：客户端**没等 200 就把数据发过来**时（curl 之外不少客户端会这样），
    //   这些字节已经被 `read_head` 预读进缓冲了。下一步是直接对着底层流对拷，
    //   不会再经过缓冲，所以必须显式补到上游 —— 官方在非透传模式下会丢掉它们。
    let prefetched = io.take_buffered();
    if !prefetched.is_empty() {
        upstream.write_all(&prefetched).await?;
    }
    upstream.flush().await?;

    let mut visitor = io.stream;
    let r = nfrp_common::util::relay_between(&mut visitor, &mut upstream).await;
    record_bytes(&registry, &r);
    if let Err(e) = r {
        debug!(%peer, %host, "tcpmux 隧道中断：{e}");
    }
    Ok(())
}
#[cfg(test)]
mod tests {
    //! tcpmux 的凭据解析与按用户名路由的单元测试（选路语义在 `router` 里）。

    use super::*;
    use crate::pool::dummy_client;
    use crate::vhost::router::tests::{route, route_of, table_with};
    #[test]
    fn proxy_authorization_解析_basic() {
        fn parts(v: &[&str]) -> HeadParts {
            HeadParts::parse(&v.iter().map(|s| s.to_string()).collect::<Vec<_>>()).unwrap()
        }
        let p = |v: &str| parts(&["CONNECT a.b:80 HTTP/1.1", v]);
        // base64("test:test")
        let (u, pw) = proxy_authorization(&p("Proxy-Authorization: Basic dGVzdDp0ZXN0"));
        assert_eq!(u.as_deref(), Some("test"));
        assert_eq!(pw.as_deref(), Some("test"));
        // 只有用户名（cURL 的 `user:@` 写法）
        let (u, pw) = proxy_authorization(&p("Proxy-Authorization: Basic dXNlcjE6"));
        assert_eq!(u.as_deref(), Some("user1"));
        assert_eq!(pw.as_deref(), Some(""));
        // 没有头 / 不是 Basic / base64 坏了：都不能 panic，也不该凭空造出用户名
        assert_eq!(
            proxy_authorization(&parts(&["CONNECT a.b:80 HTTP/1.1"])).0,
            None
        );
        assert_eq!(
            proxy_authorization(&p("Proxy-Authorization: Bearer x")).0,
            None
        );
        assert_eq!(
            proxy_authorization(&p("Proxy-Authorization: Basic !!!")).0,
            None
        );
    }

    /// ★ 回归：兜底路由（没配 `routeByHTTPUser`）不能盖掉精确用户名匹配的路由。
    ///
    /// 官方 tcpmux 的 "Route by HTTP user" 用例就是这个拓扑：同一个域名上挂
    /// `user1` / `user2` 两条精确路由 + 一条兜底路由。早先 `lookup` 只按
    /// "最长前缀、平手取先注册" 选，兜底路由只要先注册就会把两条精确路由全吃掉。
    ///
    /// ★ v0.5.6（审计总报告 M1）：三条路由必须同属**一个客户端** ——
    ///   跨租户的多作用域现在一律算冲突（服务端分辨不出合法多作用域与寄生劫持）。
    #[test]
    fn tcpmux_兜底路由不能盖掉精确用户名路由() {
        let me = dummy_client("me");
        let mk = |name: &str, user: &str| {
            let mut r = route_of(&me, name, "normal.example.com", &[""]);
            Arc::get_mut(&mut r).unwrap().kind = VhostKind::TcpMux;
            Arc::get_mut(&mut r).unwrap().route_by_http_user = user.to_string();
            r
        };
        // 故意把兜底那条**先**注册，把顺序依赖暴露出来
        let t = table_with(vec![
            mk("catch-all", ""),
            mk("foo", "user1"),
            mk("bar", "user2"),
        ]);

        let pick = |u: Option<&str>| {
            t.lookup("normal.example.com", "", u, VhostKind::TcpMux)
                .map(|(r, _)| r.proxy_name.clone())
        };
        assert_eq!(pick(Some("user1")).as_deref(), Some("foo"));
        assert_eq!(pick(Some("user2")).as_deref(), Some("bar"));
        // 没带用户名 / 带一个没注册过的用户名 -> 落到兜底
        assert_eq!(pick(Some("user3")).as_deref(), Some("catch-all"));
        assert_eq!(pick(None).as_deref(), Some("catch-all"));
    }

    #[test]
    fn tcpmux_与_http_路由互不串门() {
        let t = table_with(vec![
            route("web", "x.com", &["/"], VhostKind::Http),
            route("mux", "x.com", &[""], VhostKind::TcpMux),
        ]);
        let names = |kind| {
            t.lookup("x.com", "/", None, kind)
                .map(|(r, _)| r.proxy_name.clone())
        };
        assert_eq!(names(VhostKind::Http).as_deref(), Some("web"));
        assert_eq!(names(VhostKind::TcpMux).as_deref(), Some("mux"));
    }
}
