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
            let mut up = HttpIo::new(self.dial_upstream().await?);
            up.stream.write_all(&head).await?;
            relay_request_body(&mut io, &mut up.stream, &req).await?;
            up.stream.flush().await?;

            let Some(resp_lines) = up.read_head().await? else {
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
            if !keep {
                resp.set("Connection", "close");
            } else {
                // 客户端要复用、上游也给得了边界：把头原样交给客户端，
                // `Connection` 由服务端下发的那个决定不了什么，摘掉更干净。
                resp.remove("connection");
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
    async fn dial_upstream(&self) -> Result<BoxStream> {
        let tcp = TcpStream::connect(self.local_addr.trim())
            .await
            .with_context(|| format!("连接上游 {} 失败（localAddr 配错了？）", self.local_addr))?;
        tcp.set_nodelay(true).ok();
        if !self.out_tls {
            return Ok(Box::pin(tcp));
        }
        let host = host_part(&self.local_addr);
        let name = rustls::pki_types::ServerName::try_from(host.to_string())
            .map_err(|e| anyhow!("上游地址 {host} 不能用作 TLS 名字：{e}"))?;
        let conn = TlsConnector::from(client_config()?)
            .connect(name, tcp)
            .await
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
