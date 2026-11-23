//! 客户端**插件**：让 frpc 自己就能当正向代理、静态文件服务器用。
//!
//! 配了插件之后，工作连接不再转发到 `local_addr`，而是接到插件上：
//!
//! ```text
//! 用户 -> frps -> [工作连接] -> frpc -> plugin（而不是内网服务）
//! ```
//!
//! 这是官方 frp 的 `plugin = "..."`。目前已实现官方 0.71 的**全部 9 个**：
//!
//! * 正向代理类：`http_proxy`、`socks5`
//! * 静态资源类：`static_file`、`unix_domain_socket`（仅 Unix）
//! * HTTP 桥接类：`http2http`、`http2https`、`https2http`、`https2https`、`tls2raw`
//!   （见 [`crate::plugin_bridge`]）

use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use anyhow::{anyhow, bail, Context, Result};
use nfrp_common::{config::ProxyConfig, frp::stream::BoxStream, util};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tracing::{debug, warn};

/// 一次插件调用的上下文。
pub struct Ctx<'a> {
    /// 服务端下发的代理**线上全名**（带 `{user}.` 前缀）。
    pub proxy_name: &'a str,
    /// 真实客户端的地址，来自服务端下发的 `StartWorkConn.src_addr` / `src_port`。
    ///
    /// 只有它才配写进 `X-Forwarded-For`。工作连接的对端是 **frps 自己**，
    /// 拿它当客户端 IP 会让后端看到一屋子 `127.0.0.1`，按 IP 做的限流 / 风控全失效。
    /// 服务端没下发（比如老版本）时为 `None`。
    pub src: Option<SocketAddr>,
}

/// 一个客户端插件。
pub enum Plugin {
    /// HTTP 正向代理：支持 `CONNECT` 隧道与绝对 URI 请求。
    HttpProxy { user: String, passwd: String },
    /// SOCKS5 代理：支持 no-auth 与用户名密码两种方式，仅 CONNECT。
    Socks5 { user: String, passwd: String },
    /// 静态文件服务器。
    StaticFile { root: PathBuf, strip_prefix: String },
    /// HTTP 桥接：`http2http` / `http2https` / `https2http` / `https2https` / `tls2raw`。
    Bridge(crate::plugin_bridge::Bridge),
    /// Unix 域套接字（仅 Unix 平台）。
    #[cfg(unix)]
    UnixSocket(PathBuf),
}

impl Plugin {
    /// 按配置构造插件；`plugin` 字段为空时返回 `None`（表示走普通转发）。
    ///
    /// 返回 `Err` 表示**用户配了插件但配错了**（比如 static_file 没给目录），
    /// 这种情况必须明确报错，而不是悄悄退回普通转发 —— 否则用户会一脸茫然。
    pub fn from_proxy(p: &ProxyConfig) -> Option<Result<Self>> {
        let kind = p.plugin.trim().to_ascii_lowercase();
        if kind.is_empty() {
            return None;
        }
        Some(match kind.as_str() {
            "http_proxy" | "httpproxy" => Ok(Plugin::HttpProxy {
                user: p.plugin_user.clone(),
                passwd: p.plugin_passwd.clone(),
            }),
            "socks5" => Ok(Plugin::Socks5 {
                user: p.plugin_user.clone(),
                passwd: p.plugin_passwd.clone(),
            }),
            "static_file" | "staticfile" => {
                if p.plugin_local_path.is_empty() {
                    return Some(Err(anyhow!(
                        "插件 static_file 必须配置 plugin_local_path（要服务的目录）"
                    )));
                }
                Ok(Plugin::StaticFile {
                    root: PathBuf::from(&p.plugin_local_path),
                    strip_prefix: p.plugin_strip_prefix.clone(),
                })
            }
            "unix_domain_socket" | "unixdomainsocket" => {
                if p.plugin_local_path.is_empty() {
                    return Some(Err(anyhow!(
                        "插件 unix_domain_socket 必须配置 plugin_local_path（套接字路径）"
                    )));
                }
                #[cfg(unix)]
                {
                    Ok(Plugin::UnixSocket(PathBuf::from(&p.plugin_local_path)))
                }
                #[cfg(not(unix))]
                {
                    Err(anyhow!(
                        "unix_domain_socket 插件只能在 Unix / Linux / macOS 上使用（当前是 Windows）"
                    ))
                }
            }
            "http2http" | "http2https" | "https2http" | "https2https" | "tls2raw" => {
                crate::plugin_bridge::build(kind.as_str(), p).map(Plugin::Bridge)
            }
            other => Err(anyhow!(
                "未知插件 [{other}]，支持：http_proxy / socks5 / static_file / unix_domain_socket \
                 / http2http / http2https / https2http / https2https / tls2raw"
            )),
        })
    }

    /// 在这条工作连接上跑插件。
    pub async fn serve(self, stream: BoxStream, leftover: Vec<u8>, ctx: &Ctx<'_>) -> Result<()> {
        match self {
            Plugin::HttpProxy { user, passwd } => {
                http_proxy::serve(stream, leftover, &user, &passwd).await
            }
            Plugin::Socks5 { user, passwd } => {
                socks5::serve(stream, leftover, &user, &passwd).await
            }
            Plugin::StaticFile { root, strip_prefix } => {
                static_file::serve(stream, leftover, &root, &strip_prefix, ctx.proxy_name).await
            }
            // 桥接类插件（http2*/https2*/tls2raw）失败多半是**用户配错了**：
            // 拿明文 HTTP 去连 https2http、或上游没起。工作连接收尾只按 debug
            // 记一笔，默认看不见，所以这里额外补一条 warn。
            Plugin::Bridge(b) => b.serve(stream, leftover, ctx).await.inspect_err(|e| {
                crate::plugin_bridge::log_failure(ctx.proxy_name, e);
            }),
            #[cfg(unix)]
            Plugin::UnixSocket(path) => {
                let mut sock = tokio::net::UnixStream::connect(&path)
                    .await
                    .with_context(|| format!("连接 Unix 套接字 {} 失败", path.display()))?;
                let mut stream = stream;
                util::relay_between(&mut stream, &mut sock).await?;
                Ok(())
            }
        }
    }
}

// ---------------------------------------------------------------------------
// 通用的小工具
// ---------------------------------------------------------------------------

/// 带预读缓冲的读写器：握手阶段读出来的多余字节要还给后续流程。
struct Io {
    inner: BoxStream,
    buf: Vec<u8>,
    pos: usize,
}

impl Io {
    fn new(inner: BoxStream, leftover: Vec<u8>) -> Self {
        Self {
            inner,
            buf: leftover,
            pos: 0,
        }
    }

    /// 读一个字节。
    async fn u8(&mut self) -> std::io::Result<u8> {
        let mut b = [0u8; 1];
        self.read_exact(&mut b).await?;
        Ok(b[0])
    }

    async fn read_exact(&mut self, out: &mut [u8]) -> std::io::Result<()> {
        let mut filled = 0usize;
        // 先消化预读缓冲
        while filled < out.len() && self.pos < self.buf.len() {
            out[filled] = self.buf[self.pos];
            self.pos += 1;
            filled += 1;
        }
        if filled < out.len() {
            self.inner.read_exact(&mut out[filled..]).await?;
        }
        Ok(())
    }

    /// 读一行（不含 CRLF）；单行超过 8 KiB 视为攻击，直接报错。
    async fn line(&mut self) -> std::io::Result<String> {
        let mut out = Vec::with_capacity(128);
        loop {
            if out.len() > 8192 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "请求行过长",
                ));
            }
            let b = self.u8().await?;
            if b == b'\n' {
                if out.last() == Some(&b'\r') {
                    out.pop();
                }
                return Ok(String::from_utf8_lossy(&out).to_string());
            }
            out.push(b);
        }
    }
}

/// 解析 `host:port`；`host` 可以是域名或 IP（含 IPv6 的方括号形式），
/// 端口缺省时按 `default_port` 补。
pub fn parse_authority(s: &str, default_port: u16) -> Option<(String, u16)> {
    let s = s.trim();
    let (host, port) = if let Some(rest) = s.strip_prefix('[') {
        // [::1]:8080
        let (v6, tail) = rest.split_once(']')?;
        let port = tail
            .strip_prefix(':')
            .and_then(|p| p.parse().ok())
            .unwrap_or(default_port);
        (v6.to_string(), port)
    } else {
        match s.rsplit_once(':') {
            Some((h, p)) if p.chars().all(|c| c.is_ascii_digit()) => {
                (h.to_string(), p.parse().ok()?)
            }
            _ => (s.to_string(), default_port),
        }
    };
    if host.is_empty() {
        return None;
    }
    Some((host, port))
}

/// 从一行 HTTP 头里取出 `Proxy-Authorization` 的值。
///
/// **只按小写比对头名，值保持原样**。
///
/// # 原先为什么错了
///
/// 原写法是 `l.to_ascii_lowercase().strip_prefix("proxy-authorization:")`
/// —— `to_ascii_lowercase()` 作用在**整行**上，取出来的值
/// **已经被小写化**，且没有任何地方还原。
///
/// 而下游 [`basic_ok`] 用的是大小写**敏感**的
/// `v.strip_prefix("Basic ")` ⇒ 小写化后的 `"basic amc6amc="`
/// **永远比不上** `"Basic "` ⇒ `basic_ok()` 恒返回 false。
///
/// # 实际症状（实测复现，`tmp/audit6-g/t11_auth_final.py`）
///
/// **只要配了 `pluginUser`/`pluginPassword`，`http_proxy` 插件就恒回
/// `407 Proxy Authentication Required`，功能完全不可用** ——
/// 无论客户端发哪种凭证形态（`Basic` / `basic` / `BASIC` / 无关值）都是 407。
/// 去掉 username 后同一份配置立刻 `200 OK`（证明通道本身是通的）；
/// 横向对照 `socks5`（另一条代码路径、无小写化）认证正常
/// ⇒ 这是 `http_proxy` 独有的 bug。
///
/// # 修法
///
/// 头名本来就**大小写不敏感**（RFC 7230 §3.2），所以拿小写副本去
/// **匹配头名**是对的；错的是从那个小写副本里**取值**。
/// 现在按小写副本判断"是不是这个头"，再从**原行**上切出值。
///
/// 这与 INI 段名/键名大小写属**同一类**
///   "大小写处理不一致"：一个把该敏感的弄成不敏感，
///   一个把该保留原样的弄成了小写。
///
/// 单独成函数（而不是留在 async 处理函数里内联）是为了**让它可被单测覆盖** ——
/// 原先的 `basic_auth_rules` 测试直接调 `basic_ok`，**绕过了**出 bug 的
/// 头部解析，所以那个 bug 一直没被测出来。
fn proxy_auth_from_line(l: &str) -> Option<String> {
    // 头名大小写不敏感 ⇒ 用副本判断
    if !l.to_ascii_lowercase().starts_with("proxy-authorization:") {
        return None;
    }
    // 值必须从**原行**取，保留 `Basic ` 的原始大小写
    let raw = l.split_once(':').map(|(_, rest)| rest).unwrap_or("");
    Some(raw.trim().to_string())
}

/// 校验 HTTP 代理的 Basic 认证；不需要认证时直接放行。
fn basic_ok(header_value: Option<&str>, user: &str, passwd: &str) -> bool {
    if user.is_empty() {
        return true;
    }
    let Some(v) = header_value else {
        return false;
    };
    let Some(encoded) = v.strip_prefix("Basic ") else {
        return false;
    };
    use base64::{engine::general_purpose::STANDARD, Engine as _};
    let Ok(decoded) = STANDARD.decode(encoded.trim()) else {
        return false;
    };
    let Ok(got) = String::from_utf8(decoded) else {
        return false;
    };
    let expect = format!("{user}:{passwd}");
    // 定长比较，别让攻击者用响应时间把密码一位位试出来
    constant_time_eq(&got, &expect)
}

fn constant_time_eq(a: &str, b: &str) -> bool {
    nfrp_common::frp::msg::constant_time_eq(a, b)
}

// ---------------------------------------------------------------------------
// http_proxy
// ---------------------------------------------------------------------------

mod http_proxy {
    use super::*;

    pub async fn serve(
        stream: BoxStream,
        leftover: Vec<u8>,
        user: &str,
        passwd: &str,
    ) -> Result<()> {
        let mut io = Io::new(stream, leftover);

        // 请求行 + 头部
        let request_line = io.line().await?;
        let mut proxy_auth: Option<String> = None;
        loop {
            let l = io.line().await?;
            if l.is_empty() {
                break;
            }
            if let Some(v) = proxy_auth_from_line(&l) {
                proxy_auth = Some(v);
            }
        }

        if !basic_ok(proxy_auth.as_deref(), user, passwd) {
            io.inner
                .write_all(b"HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm=\"frpc\"\r\nContent-Length: 0\r\n\r\n")
                .await?;
            bail!("HTTP 代理认证失败");
        }

        let parts: Vec<&str> = request_line.split_whitespace().collect();
        if parts.len() < 2 {
            bail!("畸形的 HTTP 请求行：{request_line:?}");
        }
        let (method, target) = (parts[0], parts[1]);

        if method.eq_ignore_ascii_case("CONNECT") {
            // 隧道模式：连上就回 200，之后纯转发
            let Some((host, port)) = parse_authority(target, 443) else {
                bail!("CONNECT 目标格式不对：{target}");
            };
            let mut upstream = connect_upstream(&host, port).await?;
            io.inner
                .write_all(b"HTTP/1.1 200 Connection established\r\n\r\n")
                .await?;
            util::relay_between(&mut io.inner, &mut upstream).await?;
            return Ok(());
        }

        // 绝对 URI 模式：GET http://host/path HTTP/1.1
        let (host, port) = match target.strip_prefix("http://") {
            Some(rest) => {
                let authority = rest.split('/').next().unwrap_or(rest);
                parse_authority(authority, 80)
            }
            None => None,
        }
        .ok_or_else(|| anyhow!("http_proxy 需要绝对 URI 或 CONNECT，收到：{request_line}"))?;

        let mut upstream = connect_upstream(&host, port).await?;
        // 原样转发请求行与头部 —— 绝对 URI 大多数服务端都能接受
        let mut head = String::new();
        head.push_str(&request_line);
        head.push_str("\r\nHost: ");
        head.push_str(&host);
        head.push_str("\r\nConnection: close\r\n\r\n");
        upstream.write_all(head.as_bytes()).await?;
        util::relay_between(&mut io.inner, &mut upstream).await?;
        Ok(())
    }

    async fn connect_upstream(host: &str, port: u16) -> Result<tokio::net::TcpStream> {
        let addr = util::resolve_addr(&format!("{host}:{port}"))
            .await
            .with_context(|| format!("解析目标 {host}:{port} 失败"))?;
        let s = tokio::net::TcpStream::connect(addr)
            .await
            .with_context(|| format!("连接 {addr} 失败"))?;
        s.set_nodelay(true).ok();
        Ok(s)
    }
}

// ---------------------------------------------------------------------------
// socks5
// ---------------------------------------------------------------------------

mod socks5 {
    use super::*;

    const NO_AUTH: u8 = 0x00;
    const USERPASS: u8 = 0x02;
    const NO_METHOD: u8 = 0xff;

    pub async fn serve(
        stream: BoxStream,
        leftover: Vec<u8>,
        user: &str,
        passwd: &str,
    ) -> Result<()> {
        let mut io = Io::new(stream, leftover);

        // --- 握手：版本 + 方法列表 ---
        let ver = io.u8().await?;
        if ver != 0x05 {
            bail!("不是 SOCKS5（版本号 {ver}）");
        }
        let nmethods = io.u8().await?;
        let mut methods = vec![0u8; nmethods as usize];
        io.read_exact(&mut methods).await?;

        let need_auth = !user.is_empty();
        if need_auth {
            if !methods.contains(&USERPASS) {
                io.inner.write_all(&[0x05, NO_METHOD]).await?;
                bail!("客户端不支持用户名密码认证，但代理要求认证");
            }
            io.inner.write_all(&[0x05, USERPASS]).await?;
            let ok = read_userpass(&mut io, user, passwd).await?;
            io.inner
                .write_all(&[0x01, if ok { 0x00 } else { 0x01 }])
                .await?;
            if !ok {
                bail!("SOCKS5 用户名或密码不对");
            }
        } else {
            // 客户端只肯用认证、而我们不需要认证时，no-auth 也要能谈成
            io.inner.write_all(&[0x05, NO_AUTH]).await?;
        }

        // --- 请求 ---
        let ver = io.u8().await?;
        let cmd = io.u8().await?;
        let _rsv = io.u8().await?;
        let atyp = io.u8().await?;
        let target = match atyp {
            0x01 => {
                // IPv4
                let mut b = [0u8; 4];
                io.read_exact(&mut b).await?;
                std::net::Ipv4Addr::from(b).to_string()
            }
            0x03 => {
                let len = io.u8().await?;
                let mut b = vec![0u8; len as usize];
                io.read_exact(&mut b).await?;
                String::from_utf8_lossy(&b).to_string()
            }
            0x04 => {
                let mut b = [0u8; 16];
                io.read_exact(&mut b).await?;
                std::net::Ipv6Addr::from(b).to_string()
            }
            other => bail!("未知的 SOCKS5 地址类型 {other}"),
        };
        let port = {
            let mut b = [0u8; 2];
            io.read_exact(&mut b).await?;
            u16::from_be_bytes(b)
        };

        if ver != 0x05 {
            bail!("SOCKS5 请求版本号错误：{ver}");
        }
        if cmd != 0x01 {
            // 0x02 BIND / 0x03 UDP ASSOCIATE 都不支持
            warn!(cmd, "不支持的 SOCKS5 命令");
            io.inner
                .write_all(&[0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                .await?;
            bail!("SOCKS5 仅支持 CONNECT（cmd=1），收到 {cmd}");
        }

        let addr = util::resolve_addr(&format!("{target}:{port}"))
            .await
            .with_context(|| format!("解析目标 {target}:{port} 失败"))?;
        let mut upstream = tokio::net::TcpStream::connect(addr)
            .await
            .with_context(|| format!("连接 {addr} 失败"))?;
        upstream.set_nodelay(true).ok();

        // 成功回复：BND.ADDR 填 0，客户端不会用它
        io.inner
            .write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
            .await?;
        util::relay_between(&mut io.inner, &mut upstream).await?;
        Ok(())
    }

    /// 用户名密码认证子协商（RFC 1929）。
    async fn read_userpass(io: &mut Io, user: &str, passwd: &str) -> Result<bool> {
        let ver = io.u8().await?;
        if ver != 0x01 {
            return Ok(false);
        }
        let ulen = io.u8().await?;
        let mut ub = vec![0u8; ulen as usize];
        io.read_exact(&mut ub).await?;
        let plen = io.u8().await?;
        let mut pb = vec![0u8; plen as usize];
        io.read_exact(&mut pb).await?;
        let got_u = String::from_utf8_lossy(&ub).to_string();
        let got_p = String::from_utf8_lossy(&pb).to_string();
        Ok(constant_time_eq(&got_u, user) && constant_time_eq(&got_p, passwd))
    }
}

// ---------------------------------------------------------------------------
// static_file
// ---------------------------------------------------------------------------

mod static_file {
    use super::*;

    pub async fn serve(
        stream: BoxStream,
        leftover: Vec<u8>,
        root: &Path,
        strip_prefix: &str,
        proxy_name: &str,
    ) -> Result<()> {
        let mut io = Io::new(stream, leftover);
        let request_line = io.line().await?;
        // 跳过剩余头部（这个插件不关心）
        loop {
            let l = io.line().await?;
            if l.is_empty() {
                break;
            }
        }

        let path = request_line
            .split_whitespace()
            .nth(1)
            .unwrap_or("/")
            .to_string();
        let (status, body, ctype) = build_response(root, strip_prefix, &path);
        let head = format!(
            "HTTP/1.1 {status}\r\nContent-Type: {ctype}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        );
        io.inner.write_all(head.as_bytes()).await?;
        if !body.is_empty() {
            io.inner.write_all(&body).await?;
        }
        debug!(proxy = %proxy_name, %path, status, "static_file 响应");
        Ok(())
    }

    /// 把 URL 路径映射成本地文件；**目录穿越一律拒绝**。
    pub(super) fn build_response(
        root: &Path,
        strip_prefix: &str,
        url_path: &str,
    ) -> (&'static str, Vec<u8>, &'static str) {
        // 去掉 query
        let url_path = url_path.split('?').next().unwrap_or(url_path);
        let rel = match url_path.strip_prefix(strip_prefix) {
            Some(r) => r,
            None => return ("404 Not Found", b"not found".to_vec(), "text/plain"),
        };
        let rel = rel.trim_start_matches('/');
        if rel.is_empty() {
            return ("200 OK", b"nfrp static_file".to_vec(), "text/plain");
        }

        // **拒绝 NTFS 备用数据流（ADS）**。
        //
        // # 现象（实测 `tmp/audit7/d_independent/repro_d74_ads.py`，9/9）
        //
        // | 请求 | 结果 |
        // |---|---|
        // | `/data.txt` | 200 ✓ |
        // | **`/data.txt::$DATA`** | **200，读出文件内容** ← 现象 |
        // | `/data.txt::$data` | **200**（大小写不敏感）|
        // | `/data.txt:` | 403 |
        // | `/../sfsecret.txt` | 403 ✓ |
        // | **`/../sfsecret.txt::$DATA`** | **403，零泄漏** ✓ |
        //
        // # 精确的定性（**不是目录穿越**）
        //
        // `::$DATA` 读的是**同一个文件**的默认数据流，`canonicalize` 会把它
        // 解析到那个文件本身 ⇒ `starts_with(root)` 仍然通过。
        // 实测：root **之外**的文件用**任何** ADS 变体都是 403、零泄漏
        // ⇒ **root 边界没有被突破**，只是多了一条可达路径。故为**低危**。
        //
        // # 为什么仍然值得修
        //
        // 它绕过了"按文件名做判断"的那一层：若使用者（或未来的代码）在
        // `static_file` 之上加了扩展名白名单 / 精确文件名单，
        // `x.txt::$DATA` 这类写法会让"同一个文件"以**另一个标签**出现。
        // 这与本项目一贯口径一致：**在入口处拒绝掉不该出现的形态**，
        // 而不是依赖下游每一处都记得它对等。
        //
        // # 判据
        //
        // Windows 上 ADS 的语法是 `<文件名>:<流名>`。允许的路径片段里
        // **不应出现冒号**（合法文件名在 Windows 上不含 `:`，
        // NTFS 会把它当流分隔符）。所以：`rel` 里出现 `:` 一律拒绝。
        //
        // 兼容性：Linux 上 `:` 是**合法**文件名（如 `a:b.txt`）。
        //   但本插件是本地文件服务，`rel` 来自**公网访客**构造的 URL；
        //   拒绝带冒号的路径只是让 Linux 上极少数带冒号的文件名不可通过
        //   URL 访问 —— 相较"Windows 上静默绕过滤网"，这个代价可以接受。
        //   若确有此需求，可改为**仅 Windows** 生效（见下面 cfg 判断）。
        if rel.contains(':') {
            // Windows：这是 ADS 语法（或非法文件名）⇒ 一律拒
            // 其它平台：`:` 合法但来自 URL 的它没有正当理由 ⇒ 同样拒（从严）
            return ("403 Forbidden", b"forbidden".to_vec(), "text/plain");
        }

        let candidate = root.join(rel);
        // 关键：规范化之后必须仍在 root 之内，否则 `../../etc/passwd` 就能被读走
        let inside = candidate
            .canonicalize()
            .ok()
            .and_then(|c| root.canonicalize().ok().map(|r| c.starts_with(r)))
            .unwrap_or(false);
        if !inside {
            return ("403 Forbidden", b"forbidden".to_vec(), "text/plain");
        }
        match std::fs::read(&candidate) {
            Ok(b) => ("200 OK", b, guess_type(&candidate)),
            Err(_) => ("404 Not Found", b"not found".to_vec(), "text/plain"),
        }
    }

    fn guess_type(p: &Path) -> &'static str {
        match p
            .extension()
            .and_then(|e| e.to_str())
            .map(|e| e.to_ascii_lowercase())
            .as_deref()
        {
            Some("html") | Some("htm") => "text/html; charset=utf-8",
            Some("css") => "text/css; charset=utf-8",
            Some("js") => "application/javascript; charset=utf-8",
            Some("json") => "application/json; charset=utf-8",
            Some("png") => "image/png",
            Some("jpg") | Some("jpeg") => "image/jpeg",
            Some("svg") => "image/svg+xml",
            Some("txt") | Some("md") => "text/plain; charset=utf-8",
            _ => "application/octet-stream",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn proxy(plugin: &str) -> ProxyConfig {
        ProxyConfig {
            name: "p".into(),
            proxy_type: "tcp".into(),
            plugin: plugin.into(),
            ..Default::default()
        }
    }

    #[test]
    fn no_plugin_means_plain_forwarding() {
        assert!(Plugin::from_proxy(&ProxyConfig::default()).is_none());
    }

    #[test]
    fn known_plugins_are_recognized() {
        for k in [
            "http_proxy",
            "socks5",
            "static_file",
            "unix_domain_socket",
            "HTTP_PROXY",
            "Static_File",
        ] {
            let mut p = proxy(k);
            if k.contains("static") || k.contains("unix") || k.contains("Static") {
                p.plugin_local_path = "/tmp/x".into();
            }
            // Windows 上 unix_domain_socket 明确报错（而不是悄悄降级）
            let r = Plugin::from_proxy(&p);
            assert!(r.is_some(), "{k} 应被识别");
            if k.eq_ignore_ascii_case("unix_domain_socket") && cfg!(windows) {
                assert!(r.unwrap().is_err(), "Windows 上必须明确报错");
            }
        }
    }

    #[test]
    fn unknown_plugin_is_an_error_not_a_silent_fallback() {
        let r = Plugin::from_proxy(&proxy("magic")).expect("配了插件就要有结果");
        assert!(r.is_err(), "拼错的插件名必须报错");
    }

    /// 两张表必须锁在一起：`nfrp_common::config::SUPPORTED_PLUGIN_TYPES` 是
    /// 解析阶段放行用的清单，这里的 `match` 才是真正能跑的实现。
    ///
    /// 只加一边 = 要么 `verify` 继续放行跑不起来的插件（假绿灯），
    /// 要么实现了的插件在解析阶段就被拦掉。这个测试让两者不可能各自漂移。
    #[test]
    fn 公共层的支持清单与这里的实现必须一一对应() {
        for kind in nfrp_common::config::SUPPORTED_PLUGIN_TYPES {
            let mut p = proxy(kind);
            p.plugin_local_path = "/tmp/x".into();
            let r = Plugin::from_proxy(&p);
            let Some(built) = r else {
                panic!("公共层说 {kind} 支持，这里却完全不认它");
            };
            // `Plugin` 没有 Debug，不能用 `expect_err`，这里用 match 取错误文本。
            if let Err(e) = built {
                let msg = format!("{e:#}");
                assert!(
                    !msg.contains("未知插件"),
                    "公共层说 {kind} 支持，这里却报未知插件：{msg}"
                );
            }
        }
    }

    /// 反向：对官方全集逐个比对「公共层登记」与「这里认得」是否一致。
    ///
    /// 判据用的是**「未知插件」这个具体错误**，不是 `is_ok()` ——
    /// `static_file` 少给 `localPath` 也会 Err，那属于"认得但配置不全"，
    /// 不能和"根本不认得"混为一谈。
    #[test]
    fn 公共层登记与这里的识别范围必须一致() {
        for kind in nfrp_common::config::OFFICIAL_PLUGIN_TYPES {
            let mut p = proxy(kind);
            p.plugin_local_path = "/tmp/x".into();
            let recognized = match Plugin::from_proxy(&p) {
                None => false,
                Some(Ok(_)) => true,
                Some(Err(e)) => !format!("{e:#}").contains("未知插件"),
            };
            assert_eq!(
                nfrp_common::config::plugin_type_supported(kind),
                recognized,
                "{kind}：公共层 supported={} 但本 crate recognized={recognized}，两边对不上",
                nfrp_common::config::plugin_type_supported(kind)
            );
        }
    }

    #[test]
    fn static_file_requires_a_directory() {
        let r = Plugin::from_proxy(&proxy("static_file")).unwrap();
        assert!(r.is_err(), "没给目录要报错，否则会服务错误的路径");
    }

    // --- 权威（host:port）解析 ---

    #[test]
    fn authority_parsing() {
        assert_eq!(
            parse_authority("example.com:8080", 80),
            Some(("example.com".into(), 8080))
        );
        assert_eq!(
            parse_authority("example.com", 443),
            Some(("example.com".into(), 443)),
            "没写端口时用默认端口"
        );
        assert_eq!(
            parse_authority("[::1]:9000", 80),
            Some(("::1".into(), 9000)),
            "IPv6 要走方括号分支"
        );
        assert_eq!(parse_authority("", 80), None);
    }

    // --- 代理认证 ---

    #[test]
    fn basic_auth_rules() {
        use base64::{engine::general_purpose::STANDARD, Engine as _};
        let good = format!("Basic {}", STANDARD.encode(b"alice:pw"));
        assert!(basic_ok(Some(&good), "alice", "pw"));
        assert!(!basic_ok(Some(&good), "alice", "wrong"));
        assert!(!basic_ok(None, "alice", "pw"), "没带凭据必须拒绝");
        assert!(
            basic_ok(None, "", ""),
            "不配用户名 = 不要求认证（内网场景常见）"
        );
        assert!(!basic_ok(Some("Bearer x"), "a", "b"), "非 Basic 不认");
        assert!(
            !basic_ok(Some("Basic !!!"), "a", "b"),
            "非法 base64 不能 panic"
        );
    }

    /// **头部解析 + 认证必须端到端串起来测**。
    ///
    /// # 为什么原来的测试没抓住这个 bug
    ///
    /// 上面的 `basic_auth_rules` 直接调 `basic_ok`，**绕过了**真正出错的
    /// 头部解析那一步。而 bug 恰恰在解析里：`to_ascii_lowercase()` 作用在
    /// **整行**上，把 `Basic ` 也小写成了 `basic `，而 `basic_ok` 的大小写
    /// 敏感匹配 `strip_prefix("Basic ")` 就永远比不中。
    ///
    /// ⇒ **只测了一半的链路 = 没测**。这与审计里"防线写对了但只铺了一半"
    ///   是同一个教训，只不过发生在测试上。
    ///
    /// # 实测症状（`tmp/audit6-g/t11_auth_final.py`）
    ///
    /// 配了 `pluginUser` 的 `http_proxy` **恒回 407**，功能完全不可用；
    /// 去掉 username 立刻 `200 OK`。socks5 不受影响（另一条路径）。
    #[test]
    fn 代理认证的头部解析必须保留大小写() {
        use base64::{engine::general_purpose::STANDARD, Engine as _};
        let b64 = STANDARD.encode(b"alice:pw");
        let expect = format!("Basic {b64}");

        // ① 头名大小写不敏感：三种写法都要能认出来
        for name in [
            "Proxy-Authorization:",
            "proxy-authorization:",
            "PROXY-AUTHORIZATION:",
        ] {
            let line = format!("{name} {expect}");
            let got =
                proxy_auth_from_line(&line).unwrap_or_else(|| panic!("头名 {name:?} 应当被识别"));
            assert_eq!(
                got, expect,
                "取出来的值必须**原样保留** `Basic ` 的大小写（{name:?}）\
                 —— 被小写化就会让 basic_ok 恒返回 false，插件配了用户名就完全不可用"
            );
        }

        // ② 端到端串起来：解析出的值必须能通过认证
        //   （这是真正锁住 bug 的断言 —— 单测 ① 只保证取值对，
        //     这一条保证"取值对"确实能让认证通过）
        for name in ["Proxy-Authorization:", "proxy-authorization:"] {
            let line = format!("{name} {expect}");
            let parsed = proxy_auth_from_line(&line).expect("应当解析出值");
            assert!(
                basic_ok(Some(&parsed), "alice", "pw"),
                "配了正确凭据必须通过（{name:?}）—— 原先这里恒为 false，恒回 407"
            );
        }

        // ③ 不是这个头就返回 None（别把别的头误当成凭据）
        assert!(proxy_auth_from_line("Authorization: Basic xxx").is_none());
        assert!(proxy_auth_from_line("X-Proxy-Authorization: Basic xxx").is_none());
        assert!(proxy_auth_from_line("").is_none());

        // ④ 冒号后带前导空格（HTTP 的常见形态）要能正确 trim
        let line = format!("Proxy-Authorization:   Basic {b64}");
        let parsed = proxy_auth_from_line(&line).expect("应当解析出值");
        assert_eq!(parsed, format!("Basic {b64}"));
        assert!(basic_ok(Some(&parsed), "alice", "pw"));

        // ⑤ 大小写不同的 scheme：RFC 里 scheme 也是大小写不敏感，但
        //    **本插件的既有行为**只认 `Basic `（官方 frpc 也只认这个）。
        //    这里把现状钉住，避免"顺手改成不敏感"引入行为漂移 ——
        //    真要不敏感请连同这条测试一起改，并说明理由。
        assert!(
            !basic_ok(Some(&format!("basic {b64}")), "alice", "pw"),
            "scheme 大小写：保持既有行为（只认 `Basic `），改动需同步改这条测试"
        );
    }

    // --- 静态文件：目录穿越防护（这是插件里唯一可能出安全事故的地方）---

    #[test]
    fn static_file_blocks_path_traversal() {
        let dir = std::env::temp_dir().join("nfrp_plugin_test");
        std::fs::create_dir_all(dir.join("sub")).unwrap();
        std::fs::write(dir.join("ok.txt"), b"hello").unwrap();
        std::fs::write(dir.join("sub/deep.txt"), b"deep").unwrap();

        // 正常文件
        let (st, body, _) = static_file::build_response(&dir, "", "/ok.txt");
        assert_eq!(st, "200 OK");
        assert_eq!(body, b"hello");

        // 子目录里的文件
        let (st, _, _) = static_file::build_response(&dir, "", "/sub/deep.txt");
        assert_eq!(st, "200 OK");

        // 穿越尝试：../ 会被规范化后挡在 root 之外
        for evil in [
            "/../Cargo.toml",
            "/../../etc/passwd",
            "/sub/../../Cargo.toml",
            "/./../Cargo.toml",
        ] {
            let (st, _, _) = static_file::build_response(&dir, "", evil);
            assert!(
                st == "403 Forbidden" || st == "404 Not Found",
                "{evil} 必须被拒绝，实际却是 {st}"
            );
        }

        // strip_prefix 生效
        let (st, _, _) = static_file::build_response(&dir, "/static", "/static/ok.txt");
        assert_eq!(st, "200 OK");
        let (st, _, _) = static_file::build_response(&dir, "/static", "/ok.txt");
        assert_eq!(st, "404 Not Found", "没带前缀不该命中");

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// **`static_file` 必须拒绝 NTFS 备用数据流（ADS）写法。**
    ///
    /// # 现象（实测 `tmp/audit7/d_independent/repro_d74_ads.py`，9/9）
    ///
    /// | 请求 | 修复前 | 修复后 |
    /// |---|---|---|
    /// | `/data.txt` | 200 | 200 ✓ |
    /// | **`/data.txt::$DATA`** | **200（读出内容）** | **403** ✓ |
    /// | `/data.txt::$data` | 200 | **403** ✓ |
    /// | `/data.txt:` | 403 | 403 ✓ |
    ///
    /// # 定性：**这不是目录穿越**
    ///
    /// `::$DATA` 读的是**同一个文件**的默认数据流，`canonicalize` 解析到该文件本身
    /// ⇒ `starts_with(root)` 仍通过。实测 root **之外**的文件用**任何** ADS 变体
    /// 都是 403、**零泄漏** ⇒ root 边界未被突破。故为**低危**。
    ///
    /// 修它的理由是"入口处拒绝不该出现的形态"：否则"按文件名判断"的那一层
    /// （扩展名白名单、精确文件名单）可以被 `x.txt::$DATA` 这类写法绕过。
    ///
    /// # 这条测试测什么
    ///
    /// 1. **含 `:` 的路径一律 403**（ADS 语法在合法文件名里不该出现）；
    /// 2. **正常文件仍然可读**（不能修得过头）；
    /// 3. **`../` 的既有防护不受影响**。
    #[test]
    fn static_file_rejects_ntfs_ads() {
        let dir = std::env::temp_dir().join("nfrp_plugin_ads_test");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("data.txt"), b"INSIDE").unwrap();

        // ---- ① 含冒号的形态一律拒绝（ADS）----
        for evil in [
            "/data.txt::$DATA",
            "/data.txt::$data",
            "/data.txt:",
            "/data.txt:stream",
            "/::$DATA",
        ] {
            let (st, body, _) = static_file::build_response(&dir, "", evil);
            assert_eq!(
                st,
                "403 Forbidden",
                "★ {evil:?} 必须被拒绝（NTFS ADS 写法）；实际 {st}，body={:?}",
                String::from_utf8_lossy(&body)
            );
            assert!(
                !body.windows(6).any(|w| w == b"INSIDE"),
                "{evil:?} 被拒时**不得**读出任何内容"
            );
        }

        // ---- ② 正常文件仍然可读（不能修得过头）----
        let (st, body, _) = static_file::build_response(&dir, "", "/data.txt");
        assert_eq!(st, "200 OK", "正常文件必须照常可读");
        assert_eq!(body, b"INSIDE");

        // ---- ③ `../` 的既有防护不受影响 ----
        for evil in ["/../Cargo.toml", "/sub/../../Cargo.toml"] {
            let (st, _, _) = static_file::build_response(&dir, "", evil);
            assert!(
                st == "403 Forbidden" || st == "404 Not Found",
                "{evil:?} 的穿越防护不能因为本次修改而失效"
            );
        }

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn request_with_query_string_still_finds_the_file() {
        let dir = std::env::temp_dir().join("nfrp_plugin_q");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("a.txt"), b"x").unwrap();
        let (st, _, _) = static_file::build_response(&dir, "", "/a.txt?v=1");
        assert_eq!(st, "200 OK", "query 必须被剥掉");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
