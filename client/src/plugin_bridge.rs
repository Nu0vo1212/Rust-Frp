//! HTTP 桥接插件：`http2http` / `http2https` / `https2http` / `https2https` / `tls2raw`。
//!
//! 官方 frp 这 5 个插件的实现（`pkg/plugin/client/http_common.go` 等）走的是
//! Go 标准库那套：把工作连接塞进一个假 listener，挂一个 `http.Server`，
//! 再用 `httputil.ReverseProxy` 转发。NFrp 没有现成的 HTTP 服务端框架，
//! 这里按同样的语义手写：**读一条请求 → 改写头 → 转发到上游 → 把响应搬回来**。
//!
//! # 五个插件的差别只有三个开关
//!
//! | 插件 | 入站 TLS | 出站 TLS | 备注 |
//! |---|---|---|---|
//! | `http2http`  | 否 | 否 | |
//! | `http2https` | 否 | 是 | 上游证书不校验（官方 `InsecureSkipVerify`） |
//! | `https2http` | 是 | 否 | frpc 侧终止 TLS，需要 `crtPath` / `keyPath` |
//! | `https2https`| 是 | 是 | 同上 |
//! | `tls2raw`    | 是 | —  | **不解析 HTTP**，握手完直接裸对流拷 |
//!
//! 注意 `https2*` 与 **https 代理**是两码事：https 代理在服务端只嗅探 SNI、
//! 不终止 TLS、证书由内网服务自己出；而 `https2http` 是 frpc 自己当 TLS 服务端，
//! 所以证书得用户给。
//!
//! # 三条踩上去很难查的坑（都在下面代码里落实了）
//!
//! 1. **`X-Forwarded-*` 不能瞎补**。官方 `http2http` 是**删掉**它（Go 的
//!    `Rewrite` 语义：防伪造），`http2https` 是**原样透传**客户端那几行，
//!    只有 `https2*` 才调 `SetXForwarded()` 补上。而且它补的时候，
//!    `X-Forwarded-For` 追加的必须是**真实客户端 IP**（来自服务端下发的
//!    `StartWorkConn.src_addr`），不是工作连接的对端 —— 那是 frps 自己，
//!    填进去会让后端看到一屋子 `127.0.0.1`，按 IP 做的风控全部失效。
//! 2. **请求体没有"读到 EOF"这一说**（用 [`relay_request_body`]）。请求既没有
//!    `Content-Length` 也没有 chunked，就是没有体；当成读到 EOF 会死等客户端关连接，
//!    而客户端正等响应 —— 直接死锁。
//! 3. **响应没有框架信息时必须回 `Connection: close`**。否则客户端不知道响应体
//!    到哪结束，只能一直等。
//! 4. **收尾要发 `close_notify`**。`https2*` / `tls2raw` 是 frpc 自己当 TLS 服务端，
//!    处理完直接 drop 只发 FIN、不发 `close_notify`；严格一点的客户端会把它判成
//!    "连接被截断"。所以走 [`Bridge::run`]，无论成败都显式 `shutdown`。

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};
use nfrp_common::frp::stream::{BoxStream, PrefixedStream};
use nfrp_common::frp::tls::{client_config, server_config_from_pem};
use nfrp_common::http_relay::{
    body_length, connection_tokens, has_no_body, is_chunked, relay_body, relay_request_body,
    wants_keep_alive, wants_upgrade, HeadParts, HttpIo, HOP_BY_HOP,
};
use nfrp_common::util;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::{TlsAcceptor, TlsConnector};
use tracing::{debug, warn};

use crate::plugin::Ctx;

/// 连接上游 / 与上游做 TLS 握手的超时。
///
/// ★ v0.5.8 修（第八轮审计 **F8T-1**，低危）：原先这两个 `await` 都没有
/// 时限 —— 上游 accept 后保持沉默时，`https2https` 会**永久**卡在上游 TLS
/// 握手上（实测：后端收了 216B ClientHello 后再无动静，frpc 侧 ESTABLISHED
/// 永不释放，每轮访问留一条、无上界）。
///
/// 注意：**"等响应头"阶段故意不加超时** —— 长轮询 / SSE / WebSocket 的上游
/// 合法地可能几分钟才出第一个字节，人为上限会伤到正常业务；那一段的收尾由
/// `wait_upstream` 盯着访问侧负责（访问方撤离 → 立刻放弃）。
#[cfg(not(test))]
const UPSTREAM_DIAL_TIMEOUT: Duration = Duration::from_secs(10);
/// 测试用小值：用例不必真的等 10 秒（超时机制本身照样走同一段代码）。
#[cfg(test)]
const UPSTREAM_DIAL_TIMEOUT: Duration = Duration::from_millis(800);

/// 5 个桥接插件共用的实现。
pub struct Bridge {
    /// 入站是否终止 TLS。`Some` 表示 `https2http` / `https2https` / `tls2raw`。
    in_tls: Option<Arc<rustls::ServerConfig>>,
    /// 出站是否走 TLS（`http2https` / `https2https`）。
    out_tls: bool,
    /// `tls2raw`：入站 TLS 终止后不做 HTTP 解析，直接对拷。
    raw: bool,
    /// 上游地址（官方 `plugin.localAddr`）。
    local_addr: String,
    /// 回源时改写的 `Host`；留空 = 透传客户端原值（与官方一致）。
    host_rewrite: String,
    /// 回源时额外设置/覆盖的请求头（官方 `requestHeaders.set`）。
    extra_headers: BTreeMap<String, String>,
    /// 是否按官方的 `SetXForwarded` 补 `X-Forwarded-*`（只有 `https2*` 会）。
    set_x_forwarded: bool,
}

/// 插件通用配置：从 `ProxyConfig` 里取，构造时校验一次。
pub struct BridgeConfig {
    pub local_addr: String,
    pub host_rewrite: String,
    pub extra_headers: BTreeMap<String, String>,
    pub crt_path: String,
    pub key_path: String,
}

impl Bridge {
    /// `http2http`：明文进、明文出。
    pub fn http2http(c: BridgeConfig) -> Result<Self> {
        Ok(Self::plain(c, false, false))
    }

    /// `http2https`：明文进、TLS 出。
    pub fn http2https(c: BridgeConfig) -> Result<Self> {
        Ok(Self::plain(c, false, true))
    }

    /// `https2http`：TLS 进（本端终止）、明文出。
    pub fn https2http(c: BridgeConfig) -> Result<Self> {
        let tls = load_inbound_tls("https2http", &c)?;
        Ok(Self {
            in_tls: Some(tls),
            ..Self::plain(c, true, false)
        })
    }

    /// `https2https`：TLS 进、TLS 出。
    pub fn https2https(c: BridgeConfig) -> Result<Self> {
        let tls = load_inbound_tls("https2https", &c)?;
        Ok(Self {
            in_tls: Some(tls),
            ..Self::plain(c, true, true)
        })
    }

    /// `tls2raw`：TLS 进，握手完把**明文**原样交给上游（不解析 HTTP）。
    pub fn tls2raw(c: BridgeConfig) -> Result<Self> {
        let tls = load_inbound_tls("tls2raw", &c)?;
        Ok(Self {
            in_tls: Some(tls),
            raw: true,
            set_x_forwarded: false,
            ..Self::plain(c, true, false)
        })
    }

    fn plain(c: BridgeConfig, x_forwarded: bool, out_tls: bool) -> Self {
        Self {
            in_tls: None,
            out_tls,
            raw: false,
            local_addr: c.local_addr,
            host_rewrite: c.host_rewrite,
            extra_headers: c.extra_headers,
            set_x_forwarded: x_forwarded,
        }
    }

    /// 跑一条工作连接。
    pub async fn serve(self, stream: BoxStream, leftover: Vec<u8>, ctx: &Ctx<'_>) -> Result<()> {
        if self.local_addr.trim().is_empty() {
            bail!("插件必须配置 localAddr（要转发的上游地址）");
        }
        // 握手时可能已经把紧随其后的数据读进了缓冲区（`leftover`）：
        // 对 `https2*` / `tls2raw` 来说那是 TLS ClientHello 的开头，
        // 丢了握手必然失败；对 `http2*` 来说是 HTTP 请求的开头。
        // 所以统一**先塞回去**，再决定要不要终止 TLS。
        let stream: BoxStream = if leftover.is_empty() {
            stream
        } else {
            Box::pin(PrefixedStream::new(leftover, stream))
        };
        match self.in_tls.clone() {
            None => self.run(stream, ctx).await,
            Some(cfg) => {
                let accepted = TlsAcceptor::from(cfg)
                    .accept(stream)
                    .await
                    .with_context(|| {
                        format!(
                            "代理 [{}] 的入站 TLS 握手失败（客户端是不是没按 TLS 连？）",
                            ctx.proxy_name
                        )
                    })?;
                self.run(accepted, ctx).await
            }
        }
    }

    /// 跑一条"底层已经就绪"的连接（TLS 已终止，或本来就没有 TLS），收尾补优雅关闭。
    ///
    /// ★ **收尾必须显式 `shutdown`**：`https2*` / `tls2raw` 是 frpc 自己当 TLS 服务端，
    /// 处理完直接 drop 掉 rustls 流只会发一个 FIN —— **close_notify 永远发不出去**。
    /// 严格一点的客户端（rustls、Go、node 的 undici）会把这种"没有 close_notify 的
    /// EOF"判成连接被截断，报 `peer closed connection without sending TLS close_notify`；
    /// 用户看到的就是"这个 https 代理时好时坏"。官方 frpc 走 Go 的 `http.Server` +
    /// `tls.Conn`，`Close()` 是带 close_notify 的，行为必须对齐。
    async fn run<S>(self, mut stream: S, ctx: &Ctx<'_>) -> Result<()>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        let r = if self.raw {
            self.serve_raw(&mut stream, ctx).await
        } else {
            self.serve_http(&mut stream, ctx).await
        };
        // 失败也要关：让对端拿到明确的结束信号，而不是一条半截连接。
        let _ = stream.shutdown().await;
        r
    }

    /// 等一个"上游侧"的步骤完成，同时盯着访问侧是否撤离。
    ///
    /// 返回 `Ok(None)` = 访问侧读到 EOF/出错（访问方走了，别再替它等）；
    /// 返回 `Ok(Some(t))` = 步骤正常完成；步骤自身的错误照常 `Err` 上抛。
    ///
    /// ★ v0.5.8 修（第八轮审计 **F8T-1**，低危）：上游 accept 后保持沉默时，
    /// 原实现只读上游、不感知访问侧 —— 访问方连上来、把请求发完就撤离
    /// （TCP FIN + TLS close_notify）也会被无视，插件替一个已经离开的访问者
    /// 继续等，上游连接**永不释放**；任何能访问该 `remote_port` 的人都可以
    /// "连接 → 发请求 → 撤离"反复放大（每轮留 1 条 ESTABLISHED，上游永久
    /// 沉默则无上界）。官方 frpc 基于 Go `http.Server` —— 客户端连接关闭会
    /// 取消请求上下文、中止上游请求；这里对齐该语义。
    ///
    /// 访问侧在此期间读到的字节由 `HttpIo::watch_closed` 存入缓冲，不会丢
    /// （管道化的下一条请求照常处理）；被 `select!` 取消的那支是取消安全的。
    ///
    /// # ★★ v0.6.7：这里修好了 v0.6.4 记录的那个 Linux 竞态
    ///
    /// 历史：第十五轮实测同一测试在 Linux 上 10 次跑出 **5 通过 / 5 次超时**，
    /// 超时表现为"插件收到连接却从未把请求转给上游"。根因是 `watch_closed`
    /// 用 `read(&mut chunk)` 读进局部数组，被 `select!` 取消时那批字节消失，
    /// 丢的正是请求体开头。
    ///
    /// 两次失败尝试的共同点：都在"每一次 `select!` 都有一路立刻就绪"上翻车
    /// ⇒ 100% CPU 忙等（云端 4 进程各烧 20 分钟 CPU）。
    ///
    /// 现在的写法（两处一起改）：
    /// 1. `HttpIo::watch_closed` 内部走 `read_buf` 写进 `self.buf`，取消不丢字节；
    /// 2. **本函数在进 `select!` 之前**先看 `io.available()`：缓冲里已有数据就
    ///    直接 `fut.await`，根本不再进 `select!`。
    ///
    /// 于是 `select!` 的两路都只会在真正"没事可做"时挂起 —— 没有一路是
    /// 永远就绪的。回归测试：`wait_upstream_不许忙等`（数 poll 次数，不是看时间）。
    ///
    /// 影响面：仅 Linux 上 `http2*` / `https2*` 插件的端到端用例会间歇失败；
    /// Windows 上 21/21 稳定通过。
    async fn wait_upstream<T, S>(
        io: &mut HttpIo<&mut S>,
        fut: impl std::future::Future<Output = Result<T>>,
    ) -> Result<Option<T>>
    where
        S: AsyncRead + Unpin,
    {
        let mut fut = std::pin::pin!(fut);
        loop {
            // ★ 关键顺序：先看缓冲，再进 select!（见上面 v0.6.7 说明）。
            //   缓冲里有数据说明对端活着、且那批字节已经安全落在 io.buf 里，
            //   继续 select! 只会让 watch_closed 立刻返回 ⇒ 忙等。
            if io.available() > 0 {
                return Ok(Some(fut.await?));
            }
            tokio::select! {
                r = &mut fut => return Ok(Some(r?)),
                closed = io.watch_closed() => {
                    if closed? {
                        return Ok(None);
                    }
                    // 读到了数据：已在 io.buf 里，下一轮走上面那个分支。
                }
            }
        }
    }

    /// `tls2raw`：TLS 已经终止，剩下的是明文裸字节，直接和上游对拷。
    async fn serve_raw<S>(&self, stream: &mut S, ctx: &Ctx<'_>) -> Result<()>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        let mut up = self.dial_upstream().await?;
        debug!(proxy = %ctx.proxy_name, upstream = %self.local_addr, "tls2raw：TLS 已终止，开始裸对流拷");
        util::relay_between(stream, &mut up).await?;
        Ok(())
    }

    /// 读一条请求 → 改写 → 转发 → 把响应搬回来，直到任一端要求关闭。
    async fn serve_http<S>(&self, stream: &mut S, ctx: &Ctx<'_>) -> Result<()>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        let mut io: HttpIo<&mut S> = HttpIo::new(stream);
        loop {
            let Some(lines) = io.read_head().await? else {
                // 对端干净地关了连接
                return Ok(());
            };
            let mut req = HeadParts::parse(&lines)?;
            let client_keep = wants_keep_alive(&req);
            let upgrading = wants_upgrade(&req);

            // ★★ v0.5.6 修（审计总报告 M2，中危）：**请求侧 framing 校验**。
            //
            // 服务端 `vhost.rs` 早就做了这三项（TE+CL 并存 / 重复 CL /
            // 不支持的 TE），而客户端这条路径**一项都没有** ——
            // "同一语义写了两遍、只加固了一遍"的典型。
            //
            // 危害：`relay_request_body` 用的是弱判据 `body_length()`
            // （v0.5.4 的 H2 已经把它判定为不够用：只取第一个同名头、
            // 垃圾值静默变 None）⇒ 客户端与上游对"请求体到哪结束"的认知可能
            // 不一致 ⇒ **请求走私**。
            //
            // ⚠️ 可利用性前提（如实说明，不夸大）：服务端**不解析** plugin 路径的
            //    HTTP（plugin 类型走 TCP 透传），所以服务端不会替这里把关；
            //   但要触发它，本机用户得**主动**配 `plugin = "http_proxy"` 之类
            //   （v0.5.5 的 F1 修复已禁止服务端远程下发 plugin，攻击者无法自行制造）。
            //   定级因此是 Medium 而非 High。
            if let Err(e) = nfrp_common::http_relay::validate_request_framing(&req) {
                debug!(proxy = %ctx.proxy_name, "请求 framing 非法，按走私风险直接拒绝：{e}");
                let body = format!("{e}\n");
                io.stream
                    .write_all(
                        format!(
                            "HTTP/1.1 400 Bad Request\r\n\
                             Content-Type: text/plain; charset=utf-8\r\n\
                             Content-Length: {}\r\n\
                             Connection: close\r\n\r\n{body}",
                            body.len()
                        )
                        .as_bytes(),
                    )
                    .await?;
                io.stream.flush().await?;
                return Ok(());
            }

            // 客户端在等 100-continue 才肯发请求体。上游那边我们不做中间态转发
            // （那要处理"响应先于请求体"的重排序），直接自己回一个 100 ——
            // 这是各家代理的通行做法，语义上也说得通：我们确实继续了。
            if req
                .get("expect")
                .is_some_and(|v| v.eq_ignore_ascii_case("100-continue"))
            {
                io.stream
                    .write_all(b"HTTP/1.1 100 Continue\r\n\r\n")
                    .await?;
                io.stream.flush().await?;
                req.remove("expect");
            }

            let head = self.rewrite_request(&mut req, ctx, upgrading);
            // ★ v0.5.8 修（第八轮审计 F8T-1，低危）：连上游、等上游响应这两段
            //   都**同时盯着访问侧**（见 `wait_upstream` 的说明）——上游悬挂时
            //   访问方撤离，插件必须立刻收尾，而不是替已经离开的访问者继续等。
            let Some(up) = Self::wait_upstream(&mut io, self.dial_upstream()).await? else {
                debug!(proxy = %ctx.proxy_name, "访问方已撤离，放弃连接上游");
                return Ok(());
            };
            let mut up = HttpIo::new(up);
            up.stream.write_all(&head).await?;
            relay_request_body(&mut io, &mut up.stream, &req).await?;
            up.stream.flush().await?;

            let Some(resp_head) = Self::wait_upstream(&mut io, up.read_head()).await? else {
                debug!(
                    proxy = %ctx.proxy_name,
                    "访问方已撤离，释放上游连接（不再替它等响应）"
                );
                return Ok(());
            };
            let Some(resp_lines) = resp_head else {
                bail!("上游 {} 在返回任何响应之前就关闭了连接", self.local_addr);
            };
            let mut resp = HeadParts::parse(&resp_lines)?;

            // 升级（WebSocket 之类）：101 之后这条连接就是**裸字节**，
            // 不再是 HTTP 了，后面只需双向对拷。
            let switched = upgrading && resp.start_token(1) == Some("101");

            // 响应既没有 Content-Length、也不是 chunked、也不是 1xx/204/304 时，
            // 只能靠关连接来表示"体到这儿结束"。必须**在写响应头之前**告诉客户端。
            let framed =
                has_no_body(&resp) || is_chunked(&resp) || body_length(&resp).is_some() || switched;
            let keep = client_keep && wants_keep_alive(&resp) && framed;

            // ★★ v0.5.6 修（审计总报告 M2，中危）：**响应侧剥逐跳头**。
            //
            // 原先这里只在两个分支里分别 `set("Connection","close")` /
            // `remove("connection")` —— **只处理了 `Connection` 这一个头**。
            // 而 `Connection: keep-alive, X-Secret` 里点名的字段、
            // 以及 `Upgrade` / `Keep-Alive` / `Proxy-*` 等常驻逐跳头
            // 全都**原样泄漏给公网访客**（已实测复现）。
            //
            // 服务端 `vhost.rs` 的响应侧早就用 `HOP_BY_HOP + connection_tokens`
            // 全量剥过了 —— 这又是"两条路径只加固了一条"。
            //
            // ★ 顺序：**先剥、再写我们自己的 `Connection`**（否则刚写的会被剥掉）。
            nfrp_common::http_relay::strip_hop_by_hop(&mut resp);
            if !keep {
                resp.set("Connection", "close");
            }

            io.stream.write_all(&resp.to_bytes()).await?;
            io.stream.flush().await?;

            if switched {
                debug!(proxy = %ctx.proxy_name, "协议升级成功，转入裸流对拷");
                util::relay_between(&mut io.stream, &mut up.stream).await?;
                return Ok(());
            }

            relay_body(&mut up, &mut io.stream, &resp).await?;
            io.stream.flush().await?;

            if !keep {
                return Ok(());
            }
        }
    }

    /// 连上游：明文或 TLS（不校验证书，对齐官方的 `InsecureSkipVerify: true`）。
    ///
    /// ★ v0.5.8 修（第八轮审计 F8T-1，低危）：连接与**上游 TLS 握手**都套
    /// `UPSTREAM_DIAL_TIMEOUT` —— 悬挂的上游不能把插件永久卡在这里（访问侧
    /// 撤离的即时收尾另由 `wait_upstream` 负责，两道防线互补）。
    async fn dial_upstream(&self) -> Result<BoxStream> {
        let tcp = tokio::time::timeout(
            UPSTREAM_DIAL_TIMEOUT,
            TcpStream::connect(self.local_addr.trim()),
        )
        .await
        .map_err(|_| {
            anyhow!(
                "连接上游 {} 超时（{:?}）—— 对端不可达或未响应",
                self.local_addr,
                UPSTREAM_DIAL_TIMEOUT
            )
        })?
        .with_context(|| format!("连接上游 {} 失败（localAddr 配错了？）", self.local_addr))?;
        tcp.set_nodelay(true).ok();
        if !self.out_tls {
            return Ok(Box::pin(tcp));
        }
        let host = host_part(&self.local_addr);
        let name = rustls::pki_types::ServerName::try_from(host.to_string())
            .map_err(|e| anyhow!("上游地址 {host} 不能用作 TLS 名字：{e}"))?;
        let conn = tokio::time::timeout(
            UPSTREAM_DIAL_TIMEOUT,
            TlsConnector::from(client_config()?).connect(name, tcp),
        )
        .await
        .map_err(|_| {
            anyhow!(
                "与上游 {} 做 TLS 握手超时（{:?}）—— 对端 accept 后没有完成握手",
                self.local_addr,
                UPSTREAM_DIAL_TIMEOUT
            )
        })?
        .with_context(|| format!("与上游 {} 做 TLS 握手失败", self.local_addr))?;
        Ok(Box::pin(conn))
    }

    /// 把客户端发来的请求改写成"发给上游"的样子，返回序列化后的头字节。
    fn rewrite_request(&self, req: &mut HeadParts, ctx: &Ctx<'_>, upgrading: bool) -> Vec<u8> {
        // ---- 1. 请求行：绝对形式 → 原始形式 ----
        // 代理可能按 `GET http://host/path HTTP/1.1` 的绝对形式发过来，
        // 但转发给上游（一个普通源站）必须还原成 `GET /path HTTP/1.1`。
        if let Some(target) = req.start_token(1).map(str::to_string) {
            if let Some(path) = origin_form(&target) {
                let method = req.start_token(0).unwrap_or("GET").to_string();
                let ver = req.start_token(2).unwrap_or("HTTP/1.1").to_string();
                req.start_line = format!("{method} {path} {ver}");
            }
        }

        // ---- 2. X-Forwarded-* ----
        // 先按官方 `httputil.ReverseProxy` 的 `Rewrite` 语义处理：设了 Rewrite
        // 就会先删掉这三个头（防客户端伪造）。
        let client_ip = ctx.src.map(|s| s.ip().to_string());
        if self.set_x_forwarded {
            // https2*：保留客户端传来的 X-Forwarded-For 作为 `prior`，
            // 再把真实客户端 IP 追加进去；Host / Proto 由我们重建。
            let prior: Vec<String> = req
                .get("x-forwarded-for")
                .map(|v| v.split(',').map(|s| s.trim().to_string()).collect())
                .unwrap_or_default();
            match client_ip {
                Some(ip) => {
                    let mut chain = prior;
                    chain.push(ip);
                    req.set("X-Forwarded-For", &chain.join(", "));
                }
                None => req.remove("x-forwarded-for"),
            }
            let inbound_host = req.get("host").unwrap_or("").to_string();
            req.set("X-Forwarded-Host", &inbound_host);
            req.set("X-Forwarded-Proto", "https");
        } else if self.in_tls.is_some() {
            // 理论上到不了（https2* 都走上面那个分支），留个兜底免得以后加插件时漏掉。
            req.set("X-Forwarded-Proto", "https");
        } else if self.out_tls {
            // http2https：官方是**原样透传**客户端那几行，不做增删。
        } else {
            // http2http：官方不补，等于删掉。
            //
            // ★★ v0.5.8 修（第七轮审计 **E-3**，低危）：**补上 `Forwarded`**。
            //
            // # 归因校正（我先前的理解与 E 组的说法都过于笼统）
            //
            // E 组报的是"只剥离 3 个 `X-Forwarded-*`，另外 9 个客户端 IP 头原样透传"。
            // 我去查了**本机权威副本** `tmp/frp-0.71.0/pkg/plugin/client/http_common.go:36-51`，
            // 发现官方 `rewriteHTTPPluginRequest` **自己一个头都没删**：
            //
            // ```go
            // func rewriteHTTPPluginRequest(req *http.Request, scheme string, localAddr string, ...) {
            //     req.URL.Scheme = scheme
            //     req.URL.Host = localAddr
            //     if hostHeaderRewrite != "" { req.Host = hostHeaderRewrite }
            //     for k, v := range requestHeaders.Set { req.Header.Set(k, v) }
            // }
            // ```
            //
            // 真正删头的是 Go 的 `httputil.ReverseProxy` —— 它在**调用 `Rewrite` 之前**
            // 就把这些头从 `Out` 移掉了。Go 官方文档原文（pkg.go.dev/net/http/httputil）：
            //
            // > The **Forwarded, X-Forwarded, X-Forwarded-Host, and X-Forwarded-Proto**
            // > headers are removed from the outbound request before Rewrite is called.
            //
            // ⇒ **官方删的是 4 个，不是 3 个**，NFrp 漏的**只有 `Forwarded`**。
            //
            // # 实测（`tmp/audit7/e_independent/repro_e3_forwarded.py`，6/6）
            //
            // 上游实际收到（其余全被正确删除）：
            // ```text
            // forwarded            ← ❌ 未删除（与官方不一致）
            // x-forwarded-for      ← ✅ 已删除
            // x-forwarded-host     ← ✅ 已删除
            // x-forwarded-proto    ← ✅ 已删除
            // ```
            //
            // # 为什么**只**补这一个（不补那 8 个）
            //
            // `X-Real-IP` / `X-Client-IP` / `X-Originating-IP` / `X-Remote-IP` /
            // `X-Remote-Addr` / `True-Client-IP` / `CF-Connecting-IP` / `X-ProxyUser-Ip`
            // —— 这 8 个**官方也不删**（它们不在 Go 的那份清单里）。
            // 删它们会**偏离官方语义**：用户的后端/中间件可能正依赖这些头，
            // 而官方 frp 会把它们透传过去。**那是"修得过头"** ——
            // 第四轮已经因为"修得过头把合法的也拒了"返工过一次，不再犯。
            //
            // ⇒ 判据是"**与官方一致**"，而不是"我觉得该删哪些"。
            req.remove("forwarded");
            req.remove("x-forwarded-for");
            req.remove("x-forwarded-host");
            req.remove("x-forwarded-proto");
        }

        // ---- 3. 逐跳头 ----
        // 升级请求要留着 `Connection` / `Upgrade`，否则上游不会给我们 101。
        let extra = connection_tokens(req);
        let drop_it = |k: &str| {
            HOP_BY_HOP.iter().any(|h| h.eq_ignore_ascii_case(k))
                || extra.iter().any(|t| t.eq_ignore_ascii_case(k))
        };
        if !upgrading {
            req.headers.retain(|(k, _)| !drop_it(k));
            // 进出的 `Connection` 语义由我们自己决定：这是一条**全新的**上游连接，
            // 不复用，所以告诉上游可以关（响应边界因此更明确）。
            req.set("Connection", "close");
        }

        // ---- 4. Host 与自定义头 ----
        if !self.host_rewrite.trim().is_empty() {
            req.set("Host", self.host_rewrite.trim());
        }
        for (k, v) in &self.extra_headers {
            req.set(k, v);
        }

        let _ = ctx;
        req.to_bytes()
    }
}

/// 从 `ProxyConfig` 里构造桥接插件（`plugin::Plugin::from_proxy` 用）。
pub fn build(kind: &str, p: &nfrp_common::config::ProxyConfig) -> Result<Bridge> {
    let c = BridgeConfig {
        local_addr: p.plugin_local_addr.clone(),
        host_rewrite: p.plugin_host_header_rewrite.clone(),
        extra_headers: p.plugin_request_headers.clone(),
        crt_path: p.plugin_crt_path.clone(),
        key_path: p.plugin_key_path.clone(),
    };
    match kind {
        "http2http" => Bridge::http2http(c),
        "http2https" => Bridge::http2https(c),
        "https2http" => Bridge::https2http(c),
        "https2https" => Bridge::https2https(c),
        "tls2raw" => Bridge::tls2raw(c),
        other => bail!("不是 HTTP 桥接插件：{other}"),
    }
}

/// 这三个插件要在 frpc 侧终止 TLS，所以证书是**必须**的。
///
/// 不提前拦的话，用户忘了配 `crtPath` 会看到"读取 PEM 文件  失败"（路径是空的），
/// 完全猜不到是缺配置。
fn load_inbound_tls(kind: &str, c: &BridgeConfig) -> Result<Arc<rustls::ServerConfig>> {
    if c.crt_path.trim().is_empty() || c.key_path.trim().is_empty() {
        bail!(
            "插件 {kind} 要在 frpc 这一侧终止 TLS，必须同时配置 crtPath 和 keyPath\
             （证书与私钥是本地服务用的，不是 frps 的）"
        );
    }
    server_config_from_pem(c.crt_path.trim(), c.key_path.trim())
}

/// 从 `host:port` 里取出主机名（IPv6 的方括号也要剥掉）。
fn host_part(addr: &str) -> &str {
    let a = addr.trim();
    if let Some(rest) = a.strip_prefix('[') {
        return rest.split(']').next().unwrap_or(rest);
    }
    a.rsplit_once(':').map(|(h, _)| h).unwrap_or(a)
}

/// 绝对形式的请求目标 → 原始形式（`http://h/p?q` → `/p?q`）。
///
/// 不是绝对形式就返回 `None`（绝大多数情况）。
fn origin_form(target: &str) -> Option<String> {
    let rest = target
        .strip_prefix("http://")
        .or_else(|| target.strip_prefix("https://"))?;
    match rest.find('/') {
        Some(i) => Some(rest[i..].to_string()),
        None => Some("/".to_string()),
    }
}

/// 一条 `warn!` 的收尾：把插件名和上游写全，方便排查。
pub fn log_failure(proxy_name: &str, e: &anyhow::Error) {
    warn!(proxy = %proxy_name, "插件处理工作连接失败：{e:#}");
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parts(v: &[&str]) -> HeadParts {
        HeadParts::parse(&v.iter().map(|s| s.to_string()).collect::<Vec<_>>()).unwrap()
    }

    fn bridge(kind: &str) -> Bridge {
        let c = BridgeConfig {
            local_addr: "127.0.0.1:8080".into(),
            host_rewrite: String::new(),
            extra_headers: BTreeMap::new(),
            crt_path: String::new(),
            key_path: String::new(),
        };
        match kind {
            "http2http" => Bridge::http2http(c).unwrap(),
            "http2https" => Bridge::http2https(c).unwrap(),
            _ => unreachable!(),
        }
    }

    fn ctx() -> Ctx<'static> {
        Ctx {
            proxy_name: "p",
            src: Some("203.0.113.7:1234".parse().unwrap()),
        }
    }

    #[test]
    fn 上游主机名解析() {
        assert_eq!(host_part("127.0.0.1:8080"), "127.0.0.1");
        assert_eq!(host_part("example.com:443"), "example.com");
        assert_eq!(host_part("example.com"), "example.com");
        assert_eq!(host_part("[::1]:8080"), "::1");
        assert_eq!(host_part("  a.b:1  "), "a.b");
    }

    #[test]
    fn 绝对形式还原成原始形式() {
        assert_eq!(origin_form("http://a.b/c?d=1"), Some("/c?d=1".to_string()));
        assert_eq!(origin_form("https://a.b"), Some("/".to_string()));
        assert_eq!(origin_form("/c?d=1"), None);
        assert_eq!(origin_form("*"), None);
    }

    // ==================================================================
    // v0.5.6 回归（审计总报告 M2）：客户端插件路径补齐服务端已有的防护
    //
    // 这组测试盯的是"同一语义写了两遍、只加固了一遍"这个模式：
    // 服务端 `vhost.rs` 早就做了全套 framing 校验与逐跳头剥离，
    // 客户端 `plugin_bridge.rs` 只做了其中一部分。
    // ==================================================================

    /// ★★ M2 之一：**请求 framing 校验**（服务端有、客户端原先一项都没有）。
    ///
    /// 危害是请求走私：`relay_request_body` 用的 `body_length()` 是弱判据
    /// （只取第一个同名头、垃圾值静默变 None），与上游的解读可能不一致。
    #[test]
    fn 客户端插件路径必须做请求_framing_校验() {
        use nfrp_common::http_relay::validate_request_framing as check;

        // 合法请求：三种形态都该放行
        for ok in [
            vec!["POST / HTTP/1.1", "Host: x", "Content-Length: 5"],
            vec!["POST / HTTP/1.1", "Host: x", "Transfer-Encoding: chunked"],
            // `identity, chunked` 是 RFC 允许的（末尾是 chunked）
            vec![
                "POST / HTTP/1.1",
                "Host: x",
                "Transfer-Encoding: identity, chunked",
            ],
            vec!["GET / HTTP/1.1", "Host: x"],
        ] {
            let p = parts(&ok);
            assert!(
                check(&p).is_ok(),
                "合法请求被误拒：{ok:?} -> {:?}",
                check(&p)
            );
        }

        // ★ TE + CL 并存 ⇒ 拒绝（CL.TE 走私）
        let p = parts(&[
            "POST / HTTP/1.1",
            "Host: x",
            "Content-Length: 5",
            "Transfer-Encoding: chunked",
        ]);
        assert!(check(&p).is_err(), "TE 与 CL 并存必须拒绝");

        // ★ 重复的 Content-Length ⇒ 拒绝（CL.CL 走私）
        let p = parts(&[
            "POST / HTTP/1.1",
            "Host: x",
            "Content-Length: 5",
            "Content-Length: 6",
        ]);
        assert!(check(&p).is_err(), "重复的 Content-Length 必须拒绝");

        // ★ 不支持的 TE 形态 ⇒ 拒绝（TE.TE 走私）
        for bad_te in ["chunked, identity", "xchunked", "chunked, gzip"] {
            let p = parts(&[
                "POST / HTTP/1.1",
                "Host: x",
                &format!("Transfer-Encoding: {bad_te}"),
            ]);
            assert!(check(&p).is_err(), "TE={bad_te} 必须拒绝");
        }
    }

    /// ★★ M2 之二：**响应侧必须剥掉全部逐跳头**（原先只处理 `connection` 一个）。
    ///
    /// 实测泄漏场景（审计报告给的复现）：内网服务回
    /// `Connection: keep-alive, x-secret` + `x-secret` + `upgrade` + `keep-alive`，
    /// 服务端会全部吸收，而客户端把 `x-secret` 等**原样泄漏给公网访客**。
    #[test]
    fn 客户端响应侧必须剥掉全部逐跳头() {
        use nfrp_common::http_relay::strip_hop_by_hop;

        let mut resp = parts(&[
            "HTTP/1.1 200 OK",
            "Content-Type: text/html",
            "Connection: keep-alive, x-secret",
            "X-Secret: internal-token-abc",
            "Upgrade: h2c",
            "Keep-Alive: timeout=5",
            "Proxy-Authenticate: Basic",
            "Trailer: X-Foo",
            "Te: trailers",
        ]);
        strip_hop_by_hop(&mut resp);

        // 业务头必须留着
        assert_eq!(resp.get("content-type"), Some("text/html"));
        // 常驻逐跳头 + Connection 点名的自定义头，全部不许剩
        for gone in [
            "connection",
            "x-secret", // ← 这就是原先泄漏的那个内部令牌
            "upgrade",
            "keep-alive",
            "proxy-authenticate",
            "trailer",
            "te",
        ] {
            assert!(
                resp.get(gone).is_none(),
                "{gone} 必须被剥掉，实际仍在：{:?}",
                resp.get(gone)
            );
        }
        // 序列化出来也不许含敏感值
        let raw = String::from_utf8(resp.to_bytes())
            .unwrap()
            .to_ascii_lowercase();
        assert!(
            !raw.contains("internal-token-abc"),
            "内网令牌绝不能出现在转发给客户的响应里：{raw}"
        );
    }

    #[test]
    fn http2http_要删掉客户端的_x_forwarded() {
        let b = bridge("http2http");
        let mut req = parts(&[
            "GET / HTTP/1.1",
            "Host: vhost.example.com",
            "X-Forwarded-For: 1.2.3.4",
            "Connection: keep-alive",
        ]);
        let raw = String::from_utf8(b.rewrite_request(&mut req, &ctx(), false)).unwrap();
        assert!(
            !raw.to_ascii_lowercase().contains("x-forwarded-for"),
            "http2http 不该透传伪造的 XFF：{raw}"
        );
        assert!(
            raw.contains("Host: vhost.example.com"),
            "Host 默认透传：{raw}"
        );
        assert!(raw.contains("Connection: close"), "{raw}");
    }

    /// ★★ v0.5.8 回归（第七轮审计 **E-3**，低危）：
    /// **`http2http` 必须删掉官方删除的完整 4 个头 —— 含 `Forwarded`。**
    ///
    /// # 判据来自官方，不是"我觉得该删哪些"
    ///
    /// 官方 `rewriteHTTPPluginRequest`（`tmp/frp-0.71.0/pkg/plugin/client/http_common.go:36-51`）
    /// **自己一个头都不删**；真正删头的是 Go 的 `httputil.ReverseProxy`，
    /// 它在调用 `Rewrite` **之前**就把这些头移掉。Go 官方文档原文：
    ///
    /// > The **Forwarded, X-Forwarded, X-Forwarded-Host, and X-Forwarded-Proto**
    /// > headers are removed from the outbound request before Rewrite is called.
    ///
    /// ⇒ 官方删 **4 个**；NFrp 原先只删 3 个，**漏了 `Forwarded`**
    ///   （实测 `tmp/audit7/e_independent/repro_e3_forwarded.py`，6/6：
    ///   上游收到了 `forwarded`）。
    ///
    /// # 反向也要锁住：**不该删的不能删**
    ///
    /// `X-Real-IP` / `X-Client-IP` / `CF-Connecting-IP` 等 8 个"客户端 IP 类"头
    /// **官方也不删**（不在那份清单里）。删它们会偏离官方语义、
    /// 破坏依赖这些头的后端 —— 那是"**修得过头**"，
    /// 第四轮已经因为"修得过头把合法的也拒了"返工过一次。
    #[test]
    fn http2http_要删掉官方清单里的全部四个头() {
        let b = bridge("http2http");
        let mut req = parts(&[
            "GET / HTTP/1.1",
            "Host: h",
            "Forwarded: for=6.6.6.6",
            "X-Forwarded-For: 6.6.6.6",
            "X-Forwarded-Host: evil.example.com",
            "X-Forwarded-Proto: https",
            // ★ 官方**不删**的两个代表（用来守住"别修得过头"）
            "X-Real-IP: 6.6.6.6",
            "CF-Connecting-IP: 6.6.6.6",
        ]);
        let raw = String::from_utf8(b.rewrite_request(&mut req, &ctx(), false)).unwrap();
        let low = raw.to_ascii_lowercase();

        // ---- ① 官方清单里的 4 个必须全删 ----
        for h in [
            "forwarded",
            "x-forwarded-for",
            "x-forwarded-host",
            "x-forwarded-proto",
        ] {
            assert!(
                !low.contains(&format!("{h}:")),
                "★ `{h}` 必须被删除（Go Rewrite 在调用前就移除它）—— \
                 原先漏了 `Forwarded`，与官方语义不一致（E-3）。实际报文：{raw}"
            );
        }

        // ---- ② 官方不删的不能被误删（防"修得过头"）----
        for h in ["x-real-ip", "cf-connecting-ip"] {
            assert!(
                low.contains(&format!("{h}:")),
                "`{h}` **不该**被删 —— 官方也不删它（不在 Go 那份清单里）。\
                 删掉会偏离官方语义、破坏依赖它的后端。实际报文：{raw}"
            );
        }
    }

    #[test]
    fn http2https_要原样透传_x_forwarded() {
        let b = bridge("http2https");
        let mut req = parts(&["GET / HTTP/1.1", "Host: h", "X-Forwarded-For: 1.2.3.4"]);
        let raw = String::from_utf8(b.rewrite_request(&mut req, &ctx(), false)).unwrap();
        assert!(raw.contains("X-Forwarded-For: 1.2.3.4"), "{raw}");
        // 官方 http2https 不补 X-Forwarded-Proto
        assert!(!raw.contains("X-Forwarded-Proto"), "{raw}");
    }

    #[test]
    fn https2http_要补_x_forwarded_并追加真实客户端_ip() {
        // 直接构造（不加载证书，测的是改写逻辑）
        let b = Bridge {
            in_tls: Some(Arc::new(
                rustls::ServerConfig::builder_with_provider(
                    nfrp_common::frp::tls::crypto_provider(),
                )
                .with_safe_default_protocol_versions()
                .unwrap()
                .with_no_client_auth()
                .with_cert_resolver(Arc::new(NoCerts)),
            )),
            out_tls: false,
            raw: false,
            local_addr: "127.0.0.1:8080".into(),
            host_rewrite: String::new(),
            extra_headers: BTreeMap::new(),
            set_x_forwarded: true,
        };
        let mut req = parts(&[
            "GET / HTTP/1.1",
            "Host: vhost.example.com",
            "X-Forwarded-For: 10.0.0.1",
        ]);
        let raw = String::from_utf8(b.rewrite_request(&mut req, &ctx(), false)).unwrap();
        assert!(
            raw.contains("X-Forwarded-For: 10.0.0.1, 203.0.113.7"),
            "必须追加**真实客户端** IP：{raw}"
        );
        assert!(raw.contains("X-Forwarded-Host: vhost.example.com"), "{raw}");
        assert!(raw.contains("X-Forwarded-Proto: https"), "{raw}");
    }

    #[test]
    fn host_rewrite_与自定义头生效() {
        let mut b = bridge("http2http");
        b.host_rewrite = "backend.internal".into();
        b.extra_headers.insert("X-From-Where".into(), "frp".into());
        let mut req = parts(&["GET /a?b=1 HTTP/1.1", "Host: old"]);
        let raw = String::from_utf8(b.rewrite_request(&mut req, &ctx(), false)).unwrap();
        assert!(raw.starts_with("GET /a?b=1 HTTP/1.1\r\n"), "{raw}");
        assert!(raw.contains("Host: backend.internal"), "{raw}");
        assert!(raw.contains("X-From-Where: frp"), "{raw}");
        assert!(!raw.contains("Host: old"), "{raw}");
    }

    #[test]
    fn 绝对形式请求行会被还原() {
        let b = bridge("http2http");
        let mut req = parts(&["GET http://vhost.example.com/a?b=1 HTTP/1.1", "Host: x"]);
        let raw = String::from_utf8(b.rewrite_request(&mut req, &ctx(), false)).unwrap();
        assert!(raw.starts_with("GET /a?b=1 HTTP/1.1\r\n"), "{raw}");
    }

    #[test]
    fn 升级请求必须留着_connection_和_upgrade() {
        let b = bridge("http2http");
        let mut req = parts(&[
            "GET /ws HTTP/1.1",
            "Host: h",
            "Connection: Upgrade",
            "Upgrade: websocket",
        ]);
        assert!(wants_upgrade(&req));
        let raw = String::from_utf8(b.rewrite_request(&mut req, &ctx(), true)).unwrap();
        assert!(
            raw.to_ascii_lowercase().contains("upgrade: websocket"),
            "{raw}"
        );
        assert!(
            raw.to_ascii_lowercase().contains("connection: upgrade"),
            "{raw}"
        );
        assert!(
            !raw.contains("Connection: close"),
            "升级时不能改成 close：{raw}"
        );
    }

    #[test]
    fn 没有_upgrade_头的_connection_upgrade_不算升级() {
        assert!(!wants_upgrade(&parts(&[
            "GET / HTTP/1.1",
            "Connection: upgrade"
        ])));
        assert!(!wants_upgrade(&parts(&["GET / HTTP/1.1", "Upgrade: h2c"])));
        assert!(wants_upgrade(&parts(&[
            "GET / HTTP/1.1",
            "Connection: TE, Upgrade",
            "Upgrade: h2c"
        ])));
    }

    // ------------------------------------------------------------------
    // 真跑一遍：起一个假上游，内存管道当工作连接，走完整的 `serve` 流程。
    //
    // 上面那些改写断言只能证明"头拼得对"，证明不了"请求真到了上游、
    // 响应真回到了客户端"。尤其**请求体**那条：实现一旦退化成"读到 EOF"，
    // 改写断言照样全绿，只有这种真跑会挂住（由超时抓出来）。
    // ------------------------------------------------------------------

    use std::net::SocketAddr;
    use std::time::Duration;

    use nfrp_common::http_relay::find_subslice;
    use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
    use tokio::net::TcpListener;

    const TIMEOUT: Duration = Duration::from_secs(5);

    /// 从流里读出一条完整请求：请求头 + 按 `Content-Length` 声明的体。
    async fn read_request<S: AsyncRead + Unpin>(s: &mut S) -> Vec<u8> {
        let mut got = Vec::new();
        let mut b = [0u8; 4096];
        let head_end = loop {
            let n = tokio::time::timeout(TIMEOUT, s.read(&mut b))
                .await
                .expect("上游读请求头超时")
                .expect("上游读请求头出错");
            assert!(
                n > 0,
                "头没读完客户端就断了：{:?}",
                String::from_utf8_lossy(&got)
            );
            got.extend_from_slice(&b[..n]);
            if let Some(i) = find_subslice(&got, b"\r\n\r\n") {
                break i + 4;
            }
        };
        let head = String::from_utf8_lossy(&got[..head_end]).to_ascii_lowercase();
        let want: usize = head
            .lines()
            .find_map(|l| l.strip_prefix("content-length:"))
            .and_then(|v| v.trim().parse().ok())
            .unwrap_or(0);
        while got.len() < head_end + want {
            let n = tokio::time::timeout(TIMEOUT, s.read(&mut b))
                .await
                .expect("上游读请求体超时")
                .expect("上游读请求体出错");
            if n == 0 {
                break;
            }
            got.extend_from_slice(&b[..n]);
        }
        got
    }

    /// 上游收一条请求 → 回固定响应 → 把收到的原始请求交回来对账。
    async fn serve_one<S: AsyncRead + AsyncWrite + Unpin>(mut s: S, reply: &[u8]) -> Vec<u8> {
        let got = read_request(&mut s).await;
        s.write_all(reply).await.expect("上游写响应失败");
        s.flush().await.expect("上游 flush 失败");
        got
    }

    /// 明文假上游。
    async fn fake_upstream(reply: &'static [u8]) -> (SocketAddr, tokio::task::JoinHandle<Vec<u8>>) {
        let l = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("绑定假上游失败");
        let addr = l.local_addr().unwrap();
        let h = tokio::spawn(async move {
            let (s, _) = l.accept().await.expect("假上游 accept 失败");
            serve_one(s, reply).await
        });
        (addr, h)
    }

    /// TLS 假上游。出站客户端不校验证书，所以用 frp 那套自签证书就能握上手。
    #[allow(clippy::type_complexity)]
    async fn fake_tls_upstream(
        reply: &'static [u8],
    ) -> (SocketAddr, tokio::task::JoinHandle<Vec<u8>>) {
        let l = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("绑定假上游失败");
        let addr = l.local_addr().unwrap();
        let h = tokio::spawn(async move {
            let (s, _) = l.accept().await.expect("假上游 accept 失败");
            let s = TlsAcceptor::from(nfrp_common::frp::tls::server_config().unwrap())
                .accept(s)
                .await
                .expect("假上游 TLS 握手失败");
            serve_one(s, reply).await
        });
        (addr, h)
    }

    /// 假上游：accept 后**永远沉默**（不回任何字节）。
    ///
    /// - `got`：已经读到对端第一段数据（明文请求 / TLS ClientHello）时汇报
    ///   —— 用例据此确认"插件真的连上并走到了等待点"再撤离访问方；
    /// - `closed`：看守到对端关闭（EOF/RST）时汇报 —— 用例据此断言
    ///   "上游连接真的被释放了"。
    ///
    /// 两个通道都只是观测用，mod 里没有超时就靠 300ms 轮询 + 20 次保底收尾。
    #[allow(clippy::type_complexity)]
    async fn silent_upstream() -> (
        SocketAddr,
        tokio::sync::oneshot::Receiver<()>,
        tokio::sync::oneshot::Receiver<()>,
    ) {
        let l = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("绑定假上游失败");
        let addr = l.local_addr().unwrap();
        let (got_tx, got_rx) = tokio::sync::oneshot::channel();
        let (cls_tx, cls_rx) = tokio::sync::oneshot::channel();
        tokio::spawn(async move {
            let (mut s, _) = l.accept().await.expect("假上游 accept 失败");
            let mut b = [0u8; 4096];
            // 第一段数据（请求 / ClientHello）读到就汇报，之后闭嘴
            if let Ok(Ok(_)) = tokio::time::timeout(Duration::from_secs(3), s.read(&mut b)).await {
                let _ = got_tx.send(());
            }
            let mut idle = 0u32;
            loop {
                match tokio::time::timeout(Duration::from_millis(300), s.read(&mut b)).await {
                    Ok(Ok(0)) | Ok(Err(_)) => break,
                    Ok(Ok(_)) => {}
                    Err(_) => {
                        idle += 1;
                        if idle > 20 {
                            break;
                        }
                    }
                }
            }
            let _ = cls_tx.send(());
        });
        (addr, got_rx, cls_rx)
    }

    /// 假上游：读到请求后**延迟**再回响应（模拟合法的慢上游 / 长轮询）。
    async fn slow_upstream(reply: &'static [u8], delay: Duration) -> SocketAddr {
        let l = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("绑定假上游失败");
        let addr = l.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut s, _) = l.accept().await.expect("假上游 accept 失败");
            let _ = read_request(&mut s).await;
            tokio::time::sleep(delay).await;
            let _ = s.write_all(reply).await;
            let _ = s.flush().await;
        });
        addr
    }

    /// 起一个 `Bridge::plain` 并把访问侧端点交给用例（不读响应、不做断言）。
    fn spawn_drive(b: Bridge) -> (tokio::io::DuplexStream, tokio::task::JoinHandle<Result<()>>) {
        let (cli, srv) = tokio::io::duplex(64 * 1024);
        let task = tokio::spawn(async move {
            let ctx = real_ctx();
            b.serve(Box::pin(srv), Vec::new(), &ctx).await
        });
        (cli, task)
    }

    /// ★ v0.5.8（第八轮审计 **F8T-1**，低危）回归：上游 accept 后悬挂、
    /// 访问方撤离（FIN），插件必须**立刻**释放上游连接 —— 而不是像修复前
    /// 那样替一个已经离开的访问者一直等响应（每轮访问留 1 条 ESTABLISHED，
    /// 公开访问方可反复放大）。
    #[tokio::test]
    async fn 上游悬挂时访问方撤离必须释放上游连接() {
        let (addr, got, closed) = silent_upstream().await;
        let (mut cli, task) = spawn_drive(Bridge::plain(cfg_to(addr), false, false));
        write_req(&mut cli, b"GET / HTTP/1.1\r\nHost: x\r\n\r\n").await;
        // 确认插件已经连上并走到"等响应"再撤离（否则断在别处也算过，测不准）
        tokio::time::timeout(Duration::from_secs(2), got)
            .await
            .expect("上游 2s 内应当收到请求")
            .expect("通道不该丢");
        drop(cli); // 访问方撤离
        tokio::time::timeout(Duration::from_secs(2), closed)
            .await
            .expect("访问方撤离后 2s 内上游连接必须被释放")
            .expect("通道不该丢");
        let r = tokio::time::timeout(TIMEOUT, task)
            .await
            .expect("插件应当立即收尾")
            .expect("插件任务不 panic");
        assert!(r.is_ok(), "访问方撤离应当安静收尾：{r:?}");
    }

    /// ★★★ v0.6.7 的「关门测试」：`wait_upstream` **不许忙等**。
    ///
    /// 前两次修复（第十五 / 十七轮）都栽在这里：改成 `read_buf` 之后，
    /// `loop { select! }` 里总有一路立刻就绪，于是 100% CPU 空转
    /// （云端 4 个进程各烧 20 分钟 CPU，本地单进程烧 1288 秒）。
    ///
    /// 所以这里**数 poll 次数**，而不是看耗时：一个永不完成的 fut + 一个沉默
    /// 的对端，等 200ms。正常实现只会被 poll 个位数次；忙等会是几十万次。
    /// 这条测试是这次重构的验收条件 —— 没有它，同样的错误会第三次发生。
    #[tokio::test]
    async fn wait_upstream_不许忙等() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::sync::Arc;
        use std::task::{Context, Poll};

        struct Never(Arc<AtomicUsize>);
        impl std::future::Future for Never {
            type Output = Result<()>;
            fn poll(self: std::pin::Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Self::Output> {
                let n = self.0.fetch_add(1, Ordering::Relaxed) + 1;
                // ★ 数到 1 万次就**直接 panic**，而不是靠外面那个 200ms 超时：
                //   忙等会把单线程 runtime 占死，连定时器都轮不到，测试会**挂住**
                //   而不是失败（实测：旧写法跑 60s 还没退出）。挂住的测试在 CI 里
                //   只是一条超时，看不出原因；这里让它在毫秒级给出明确断言。
                if n > 10_000 {
                    panic!("wait_upstream 在忙等：已轮询 {n} 次（阈值 10000）");
                }
                Poll::Pending
            }
        }

        let (mut cli, mut srv) = tokio::io::duplex(64);
        let mut io = HttpIo::new(&mut srv);
        // ★ 关键前提：先把**字节灌进缓冲**，模拟"管道化的下一条请求已经到齐"。
        //   这正是前两次翻车的形状 —— 缓冲非空时 `watch_closed` 立刻返回，
        //   `loop { select! }` 就转成了死循环。缓冲空时谁也转不起来，
        //   所以那种测法抓不到忙等（第一版这条测试就写错了）。
        cli.write_all(b"x").await.unwrap();
        io.fill().await.unwrap();
        assert_eq!(io.available(), 1, "前置条件：缓冲里必须有 1 个字节");

        let polls = Arc::new(AtomicUsize::new(0));
        let r = tokio::time::timeout(
            Duration::from_millis(200),
            Bridge::wait_upstream(&mut io, Never(polls.clone())),
        )
        .await;
        assert!(
            r.is_err(),
            "fut 永不完成、对端沉默 ⇒ 应当一直等（200ms 超时）"
        );
        let n = polls.load(Ordering::Relaxed);
        assert!(
            n < 50,
            "wait_upstream 在忙等：200ms 内轮询了 {n} 次（阈值 50）"
        );
    }

    /// ★★ v0.6.7 回归：修之前这条路径在 Linux 上 10 次跑出 5 次 5 秒超时
    /// （"插件收到连接却从未把请求转给上游"）。单跑一次抓不住竞态，
    /// 所以连跑 20 次 —— 单次失败概率 50% 时，20 次全过的概率是 1e-6。
    #[tokio::test]
    async fn 端到端_http2http_连跑20次不许偶发挂住() {
        for i in 0..20 {
            let (up, got) = fake_upstream(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok").await;
            let b = Bridge::http2http(cfg_to(up)).unwrap();
            let (out, r) = drive(
                b,
                b"POST /a HTTP/1.1\r\nHost: vhost.example.com\r\nContent-Length: 5\r\n\
                  Connection: close\r\n\r\nhello",
            )
            .await;
            r.unwrap_or_else(|e| panic!("第 {i} 轮插件应当正常收尾：{e:?}"));
            let up_req = got
                .await
                .unwrap_or_else(|e| panic!("第 {i} 轮上游任务：{e:?}"));
            assert!(
                up_req.ends_with(b"\r\n\r\nhello"),
                "第 {i} 轮请求体必须完整到达上游：{:?}",
                String::from_utf8_lossy(&up_req)
            );
            assert!(
                out.ends_with(b"ok"),
                "第 {i} 轮响应必须完整搬回：{:?}",
                String::from_utf8_lossy(&out)
            );
        }
    }

    /// ★ v0.5.8（第八轮审计 **F8T-1**）回归（上游 TLS 握手悬挂）：`https2https`
    /// 卡在"与上游握手"时访问方撤离，同样必须**立刻**放弃并释放那条 TCP 连接。
    #[tokio::test]
    async fn 上游tls握手悬挂时访问方撤离必须释放连接() {
        let (addr, got, closed) = silent_upstream().await; // 纯 TCP 沉默，不回应 ClientHello
        let (mut cli, task) = spawn_drive(Bridge::plain(cfg_to(addr), false, true)); // out_tls = true
        write_req(&mut cli, b"GET / HTTP/1.1\r\nHost: x\r\n\r\n").await;
        // 上游收到 ClientHello ⇒ 插件确实卡在握手里
        tokio::time::timeout(Duration::from_secs(2), got)
            .await
            .expect("上游 2s 内应当收到 ClientHello")
            .expect("通道不该丢");
        drop(cli);
        tokio::time::timeout(Duration::from_secs(2), closed)
            .await
            .expect("访问方撤离后 2s 内上游连接必须被释放")
            .expect("通道不该丢");
        let r = tokio::time::timeout(TIMEOUT, task)
            .await
            .expect("插件应当立即收尾")
            .expect("插件任务不 panic");
        assert!(r.is_ok(), "访问方撤离应当安静收尾：{r:?}");
    }

    /// ★ v0.5.8（第八轮审计 **F8T-1**）回归（上游 TLS 握手无超时）：访问方
    /// 还活着、上游 accept 后沉默时，上游 TLS 握手必须**有界**失败 ——
    /// 修复前会永久卡住（连接永不释放）。测试用缩短的超时（800ms）。
    #[tokio::test]
    async fn 上游tls握手沉默时有界失败() {
        let (addr, _got, _closed) = silent_upstream().await;
        let (mut cli, task) = spawn_drive(Bridge::plain(cfg_to(addr), false, true));
        let t0 = std::time::Instant::now();
        write_req(&mut cli, b"GET / HTTP/1.1\r\nHost: x\r\n\r\n").await;
        let r = tokio::time::timeout(TIMEOUT, task)
            .await
            .expect("上游 TLS 握手必须**有界**失败，不能永久挂住")
            .expect("插件任务不 panic");
        let e = r.expect_err("沉默上游 + 在线访问方：应当报握手超时");
        assert!(format!("{e:#}").contains("超时"), "错误要说清是超时：{e:#}");
        assert!(
            t0.elapsed() < Duration::from_secs(3),
            "应当快速失败（test 超时 800ms），实际 {:?}",
            t0.elapsed()
        );
    }

    /// 反向回归（F8T-1 的兼容性约束）：上游只是**慢**（2s 才出响应）时不能
    /// 误伤 —— 访问方在线，响应必须完整送达；"等响应头"阶段故意没有人为
    /// 超时（长轮询 / SSE 的合法等待不能被砍）。
    #[tokio::test]
    async fn 慢响应上游照常送达不误伤() {
        let addr = slow_upstream(
            b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
            Duration::from_millis(2000),
        )
        .await;
        let (mut cli, task) = spawn_drive(Bridge::plain(cfg_to(addr), false, false));
        write_req(&mut cli, b"GET / HTTP/1.1\r\nHost: x\r\n\r\n").await;
        let out = read_resp(&mut cli).await; // TIMEOUT = 5s，2s 的响应在窗口内
        assert!(
            out.starts_with(b"HTTP/1.1 200"),
            "慢上游的响应必须完整送达：{:?}",
            String::from_utf8_lossy(&out)
        );
        assert!(out.ends_with(b"ok"));
        let r = tokio::time::timeout(TIMEOUT, task)
            .await
            .expect("插件应正常收尾")
            .expect("插件任务不 panic");
        assert!(r.is_ok(), "{r:?}");
    }

    /// 生成一对自签证书落盘，返回 `(crtPath, keyPath)` —— 给 `https2*` / `tls2raw` 用。
    fn tmp_cert(tag: &str) -> (String, String) {
        let k = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
        let dir = std::env::temp_dir().join(format!("nfrp-plugin-{tag}"));
        std::fs::create_dir_all(&dir).unwrap();
        let crt = dir.join("crt.pem");
        let key = dir.join("key.pem");
        std::fs::write(&crt, k.cert.pem()).unwrap();
        std::fs::write(&key, k.key_pair.serialize_pem()).unwrap();
        (
            crt.to_string_lossy().into_owned(),
            key.to_string_lossy().into_owned(),
        )
    }

    fn cfg_to(addr: SocketAddr) -> BridgeConfig {
        BridgeConfig {
            local_addr: addr.to_string(),
            host_rewrite: String::new(),
            extra_headers: BTreeMap::new(),
            crt_path: String::new(),
            key_path: String::new(),
        }
    }

    fn real_ctx() -> Ctx<'static> {
        Ctx {
            proxy_name: "p",
            src: Some("203.0.113.7:1234".parse().unwrap()),
        }
    }

    async fn write_req<S: AsyncWrite + Unpin>(s: &mut S, b: &[u8]) {
        tokio::time::timeout(TIMEOUT, s.write_all(b))
            .await
            .expect("写请求超时")
            .expect("写请求失败");
    }

    /// 读到 EOF。超时基本就是"响应没有边界"或请求体那边死锁了。
    async fn read_resp<S: AsyncRead + Unpin>(s: &mut S) -> Vec<u8> {
        let mut out = Vec::new();
        let mut b = [0u8; 4096];
        loop {
            match tokio::time::timeout(TIMEOUT, s.read(&mut b)).await {
                Err(_) => panic!("读响应超时，已读到 {:?}", String::from_utf8_lossy(&out)),
                Ok(Ok(0)) => break,
                Ok(Ok(n)) => out.extend_from_slice(&b[..n]),
                Ok(Err(e)) => panic!("读响应出错：{e}"),
            }
        }
        out
    }

    /// 把桥接插件接到内存管道的一端，喂一段原始请求，返回 `(响应, serve 结果)`。
    async fn drive(b: Bridge, req: &[u8]) -> (Vec<u8>, Result<()>) {
        let (mut cli, srv) = tokio::io::duplex(64 * 1024);
        let task = tokio::spawn(async move {
            let ctx = real_ctx();
            b.serve(Box::pin(srv), Vec::new(), &ctx).await
        });
        write_req(&mut cli, req).await;
        let out = read_resp(&mut cli).await;
        let r = tokio::time::timeout(TIMEOUT, task)
            .await
            .expect("插件收尾超时")
            .expect("插件任务 panic");
        (out, r)
    }

    #[tokio::test]
    async fn 端到端_http2http_把请求体一起送给上游并把响应搬回来() {
        let (up, got) = fake_upstream(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok").await;
        let b = Bridge::http2http(cfg_to(up)).unwrap();
        let (out, r) = drive(
            b,
            b"POST /a?b=1 HTTP/1.1\r\nHost: vhost.example.com\r\n\
              X-Forwarded-For: 1.2.3.4\r\nContent-Length: 5\r\n\
              Connection: close\r\n\r\nhello",
        )
        .await;
        r.expect("插件应当正常收尾");

        let up_req = String::from_utf8(got.await.expect("假上游任务 panic")).unwrap();
        assert!(up_req.starts_with("POST /a?b=1 HTTP/1.1\r\n"), "{up_req}");
        assert!(
            up_req.ends_with("\r\n\r\nhello"),
            "请求体必须完整交给上游（少一个字节上游就会一直等）：{up_req}"
        );
        assert!(
            !up_req.to_ascii_lowercase().contains("x-forwarded-for"),
            "http2http 要删掉伪造的 XFF：{up_req}"
        );
        assert!(up_req.contains("Connection: close"), "{up_req}");

        let resp = String::from_utf8(out).unwrap();
        assert!(resp.starts_with("HTTP/1.1 200 OK\r\n"), "{resp}");
        assert!(resp.ends_with("ok"), "响应体要原样搬回来：{resp}");
    }

    #[tokio::test]
    async fn 端到端_http2https_上游握手与响应都通() {
        let (up, got) = fake_tls_upstream(b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\ntls").await;
        let b = Bridge::http2https(cfg_to(up)).unwrap();
        let (out, r) = drive(
            b,
            b"GET / HTTP/1.1\r\nHost: vhost\r\nX-Forwarded-For: 1.2.3.4\r\nConnection: close\r\n\r\n",
        )
        .await;
        r.expect("插件应当正常收尾");
        assert!(
            String::from_utf8(got.await.unwrap())
                .unwrap()
                .contains("X-Forwarded-For: 1.2.3.4"),
            "http2https 要原样透传 XFF"
        );
        let resp = String::from_utf8(out).unwrap();
        assert!(resp.ends_with("tls"), "{resp}");
    }

    #[tokio::test]
    async fn 端到端_https2http_终止tls并补真实客户端ip() {
        let (crt, key) = tmp_cert("h2h");
        let (up, got) = fake_upstream(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n").await;
        let mut c = cfg_to(up);
        c.crt_path = crt;
        c.key_path = key;
        let b = Bridge::https2http(c).unwrap();

        let (cli, srv) = tokio::io::duplex(64 * 1024);
        let task = tokio::spawn(async move {
            let ctx = real_ctx();
            b.serve(Box::pin(srv), Vec::new(), &ctx).await
        });
        // 客户端这一侧按 TLS 连（插件是 frpc 侧的 TLS 服务端）。
        let name = rustls::pki_types::ServerName::try_from("localhost").unwrap();
        let tls = TlsConnector::from(nfrp_common::frp::tls::client_config().unwrap())
            .connect(name, cli)
            .await
            .expect("与插件做 TLS 握手失败");
        let mut tls = Box::pin(tls);
        write_req(
            &mut tls,
            b"GET / HTTP/1.1\r\nHost: vhost.example.com\r\nX-Forwarded-For: 10.0.0.1\r\nConnection: close\r\n\r\n",
        )
        .await;
        let out = read_resp(&mut tls).await;
        task.await.unwrap().unwrap();

        let up_req = String::from_utf8(got.await.unwrap()).unwrap();
        assert!(
            up_req.contains("X-Forwarded-For: 10.0.0.1, 203.0.113.7"),
            "要追加真实客户端 IP：{up_req}"
        );
        assert!(up_req.contains("X-Forwarded-Proto: https"), "{up_req}");
        assert!(
            up_req.contains("X-Forwarded-Host: vhost.example.com"),
            "{up_req}"
        );
        assert!(String::from_utf8(out)
            .unwrap()
            .starts_with("HTTP/1.1 200 OK"));
    }

    #[tokio::test]
    async fn 端到端_https2https_两端都是tls() {
        let (crt, key) = tmp_cert("h2hs");
        let (up, got) = fake_tls_upstream(b"HTTP/1.1 204 No Content\r\n\r\n").await;
        let mut c = cfg_to(up);
        c.crt_path = crt;
        c.key_path = key;
        let b = Bridge::https2https(c).unwrap();

        let (cli, srv) = tokio::io::duplex(64 * 1024);
        let task = tokio::spawn(async move {
            let ctx = real_ctx();
            b.serve(Box::pin(srv), Vec::new(), &ctx).await
        });
        let name = rustls::pki_types::ServerName::try_from("localhost").unwrap();
        let tls = TlsConnector::from(nfrp_common::frp::tls::client_config().unwrap())
            .connect(name, cli)
            .await
            .expect("与插件做 TLS 握手失败");
        let mut tls = Box::pin(tls);
        write_req(
            &mut tls,
            b"GET /x HTTP/1.1\r\nHost: h\r\nConnection: close\r\n\r\n",
        )
        .await;
        let out = read_resp(&mut tls).await;
        task.await.unwrap().unwrap();
        assert!(String::from_utf8(got.await.unwrap())
            .unwrap()
            .starts_with("GET /x HTTP/1.1"));
        assert!(String::from_utf8(out).unwrap().contains("204 No Content"));
    }

    #[tokio::test]
    async fn 端到端_tls2raw_不解析http直接裸对流拷() {
        // 上游是个"收到 EOF 再回吐"的裸回显服务：能证明过去的是**明文**而不是 HTTP。
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let up = l.local_addr().unwrap();
        let got = tokio::spawn(async move {
            let (mut s, _) = l.accept().await.unwrap();
            let mut buf = Vec::new();
            s.read_to_end(&mut buf).await.unwrap();
            s.write_all(&buf).await.unwrap();
            s.flush().await.unwrap();
            buf
        });

        let (crt, key) = tmp_cert("t2r");
        let mut c = cfg_to(up);
        c.crt_path = crt;
        c.key_path = key;
        let b = Bridge::tls2raw(c).unwrap();

        let (cli, srv) = tokio::io::duplex(64 * 1024);
        let task = tokio::spawn(async move {
            let ctx = real_ctx();
            b.serve(Box::pin(srv), Vec::new(), &ctx).await
        });
        let name = rustls::pki_types::ServerName::try_from("localhost").unwrap();
        let tls = TlsConnector::from(nfrp_common::frp::tls::client_config().unwrap())
            .connect(name, cli)
            .await
            .expect("与插件做 TLS 握手失败");
        let mut tls = Box::pin(tls);
        write_req(&mut tls, b"raw-bytes-not-http").await;
        tls.shutdown().await.expect("关掉 TLS 写方向失败");
        let out = read_resp(&mut tls).await;
        task.await.unwrap().unwrap();

        assert_eq!(
            got.await.unwrap(),
            b"raw-bytes-not-http",
            "上游该收到明文原样"
        );
        assert_eq!(out, b"raw-bytes-not-http", "回程也要原样");
    }

    // ---- 一个"永远不返回证书"的解析器，只为把 ServerConfig 造出来 ----
    #[derive(Debug)]
    struct NoCerts;
    impl rustls::server::ResolvesServerCert for NoCerts {
        fn resolve(
            &self,
            _hello: rustls::server::ClientHello<'_>,
        ) -> Option<Arc<rustls::sign::CertifiedKey>> {
            None
        }
    }
}
