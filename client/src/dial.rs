//! 出站拨号与底层连接建立（TCP / TLS / WebSocket / KCP）。
//!
//! 职责：解析服务端地址，按 `dialServerTimeout` / `connectServerLocalIP` /
//! `dialServerKeepalive` 拨号，并套上 TLS / WebSocket / KCP，供控制连接与工作
//! 连接复用。
//! 并发/所有权契约：全部是无状态函数，每条连接各建一条流；不持有任务、通道或
//! 原子计数。
//! 不变量：拨号超时与 keepalive 语义必须与官方 frpc 一致（`0` = 关闭该超时 /
//! 不打开 keepalive）；日志里的代理地址必须经 `redact_proxy` 脱敏。

use std::{sync::Arc, time::Duration};

use anyhow::{anyhow, Context, Result};
use nfrp_common::{
    config::{is_kcp, ClientConfig},
    frp::{self, stream::BoxStream, tls},
    util, ws,
};
use tokio::net::{TcpSocket, TcpStream, UdpSocket};
use tracing::{debug, info, warn};

/// 到 `server` 的出口 IP：连一个 UDP socket（不发包）读本地地址。
///
/// 这是"取默认路由源地址"的常用办法：`connect` 只设置路由与本地端点，
/// 不会真的产生流量，也不需要任何外部服务配合。
pub(crate) async fn outbound_ip(server: std::net::SocketAddr) -> Option<std::net::IpAddr> {
    let any: std::net::SocketAddr = if server.is_ipv4() {
        "0.0.0.0:0".parse().ok()?
    } else {
        "[::]:0".parse().ok()?
    };
    let sock = UdpSocket::bind(any).await.ok()?;
    sock.connect(server).await.ok()?;
    Some(sock.local_addr().ok()?.ip())
}

/// 服务端 QUIC 地址（与 TCP 用同一个端口号，只是走 UDP）。
pub(crate) async fn quic_server_addr(cfg: &ClientConfig) -> Result<std::net::SocketAddr> {
    let s = format!("{}:{}", cfg.server_addr, cfg.server_port);
    util::resolve_addr(&s)
        .await
        .with_context(|| format!("解析服务端 QUIC 地址 {s} 失败"))
}

/// NLink QUIC 服务端地址：显式 `quic_addr` 优先，否则退回 `server_addr:server_port`。
pub(crate) async fn nlink_quic_server_addr(cfg: &ClientConfig) -> Result<std::net::SocketAddr> {
    let s = if cfg.nlink.quic_addr.trim().is_empty() {
        format!("{}:{}", cfg.server_addr, cfg.server_port)
    } else {
        cfg.nlink.quic_addr.trim().to_string()
    };
    util::resolve_addr(&s)
        .await
        .with_context(|| format!("解析 NLink QUIC 地址 {s} 失败（检查 [nlink] quic_addr）"))
}

/// 带 `dialServerTimeout` / `connectServerLocalIP` 的拨号。
///
/// 官方语义（`pkg/config/v1/connector.go` 的建连路径）：
/// * `dialServerTimeout`（默认 10 秒）—— 建连超时，**控制连接与每条新拨的
///   工作连接都过这里**（`tcpMux = true` 时工作连接复用控制连接，不再拨号）；
/// * `connectServerLocalIP` —— 拨号前把本地出口绑到指定 IP（官方注释：仅
///   TCP / WebSocket 协议有效，KCP 不支持；nfrp 同样只在 TCP 路径用它）；
/// * `dialServerKeepalive`（默认 7200 秒）—— 建连成功后给 socket 打开
///   `SO_KEEPALIVE` 并把空闲时长设为该值（`0` = 不打开）。
///
/// `dial_server_timeout = 0` 表示**不设超时**（跟随系统默认），与项目其它
/// 超时项"0 = 关掉这项"的约定一致（官方把 0 折算成 10，这里不复刻）。
async fn dial_server(cfg: &ClientConfig, addr: std::net::SocketAddr) -> Result<TcpStream> {
    let fut = async {
        if cfg.connect_server_local_ip.trim().is_empty() {
            return TcpStream::connect(addr).await.map_err(anyhow::Error::from);
        }
        let local = parse_local_bind(&cfg.connect_server_local_ip)?;
        let socket = match (local, addr) {
            (std::net::SocketAddr::V4(_), std::net::SocketAddr::V4(_)) => TcpSocket::new_v4(),
            (std::net::SocketAddr::V6(_), std::net::SocketAddr::V6(_)) => TcpSocket::new_v6(),
            _ => {
                return Err(anyhow!(
                    "connectServerLocalIP 与远端地址的协议族不一致：本地是 {local}，远端是 {addr}"
                ))
            }
        }?;
        // 本地端口默认取 0（让内核分配），与官方 `ResolveTCPAddr` 缺端口补 0 一致。
        socket
            .bind(local)
            .with_context(|| format!("绑定本地地址 {local} 失败"))?;
        socket.connect(addr).await.map_err(anyhow::Error::from)
    };
    let stream = if cfg.dial_server_timeout == 0 {
        fut.await
    } else {
        let limit = Duration::from_secs(cfg.dial_server_timeout);
        tokio::time::timeout(limit, fut).await.map_err(|_| {
            anyhow!(
                "等待建连超时（dialServerTimeout = {} 秒；设 0 可关闭该超时）",
                cfg.dial_server_timeout
            )
        })?
    }?;

    // TCP keepalive：官方挂在拨号器
    // （`libnet.WithKeepAlive`）上，控制连接与每条新拨的工作连接都过这里，
    // 所以放在 `dial_server` 出口处一次覆盖。`0` = 不打开（项目约定）。
    if cfg.dial_server_keepalive > 0 {
        if let Err(e) = util::set_tcp_keepalive(&stream, cfg.dial_server_keepalive) {
            warn!(
                "设置 TCP keepalive 失败（dialServerKeepalive = {} 秒）：{e}",
                cfg.dial_server_keepalive
            );
        }
    }
    Ok(stream)
}

/// 解析 `connectServerLocalIP`：接受 `IP`（端口补 0）或 `IP:端口`。
///
/// 带方括号的 IPv6（`[::1]:0`）与裸 IPv6（`::1`，按整个字符串当地址解析、
/// 端口 0）都认；解析不出来就报错，不做猜测。
fn parse_local_bind(raw: &str) -> Result<std::net::SocketAddr> {
    let s = raw.trim();
    if s.is_empty() {
        return Err(anyhow!("connectServerLocalIP 是空串"));
    }
    // 先按完整 SocketAddr 解析（`1.2.3.4:0` / `[::1]:0`）
    if let Ok(sa) = s.parse::<std::net::SocketAddr>() {
        return Ok(sa);
    }
    // 再按裸 IP 解析（端口取 0）
    if let Ok(ip) = s.parse::<std::net::IpAddr>() {
        return Ok(std::net::SocketAddr::new(ip, 0));
    }
    Err(anyhow!(
        "connectServerLocalIP {s:?} 不是合法地址（应为 `IP` 或 `IP:端口`；\
         IPv6 带端口要写方括号，如 `[::1]:0`）"
    ))
}

/// 建立一条到服务端的底层连接（TCP，按需 TLS，按需 WebSocket）。
///
/// 套壳顺序与官方 frpc 一致：`TCP -> [TLS] -> [WebSocket]`，
/// yamux 由 [`ServerLink`] 再套在外面。
/// 把代理 URL 里的 `user:pass@` 抹掉，只留 `scheme://host:port`。
///
/// 代理密码写进日志是真实事故（日志会被收集、转发、贴到 issue 里），
/// 所以**每一处**打代理地址的地方都必须过这里。
fn redact_proxy(url: &str) -> String {
    match url.rsplit_once('@') {
        Some((_, rest)) => match url.split_once("://") {
            Some((scheme, _)) => format!("{scheme}://{rest}"),
            None => rest.to_string(),
        },
        None => url.to_string(),
    }
}

pub(crate) async fn raw_connect(cfg: &ClientConfig) -> Result<BoxStream> {
    // KCP 是另一条路：裸 UDP 上的可靠传输，TLS / WebSocket 那几层跟它没关系
    if is_kcp(&cfg.transport_protocol) {
        return kcp_connect(cfg).await;
    }
    let server = format!("{}:{}", cfg.server_addr, cfg.server_port);
    // 配了 `dnsServer` 就用它解析服务端域名；
    // 没配就走系统 resolver（原路径，行为不变）。
    let addr = if cfg.dns_server.trim().is_empty() {
        util::resolve_addr(&server)
            .await
            .with_context(|| format!("解析服务端地址 {server} 失败"))?
    } else {
        nfrp_common::dns::resolve_addr_via(&cfg.dns_server, &server)
            .await
            .with_context(|| {
                format!(
                    "用自定义 DNS {} 解析服务端地址 {server} 失败",
                    cfg.dns_server
                )
            })?
    };
    // `transport.proxyURL` —— 走出站代理时直接拿到一条已建好的隧道流；
    // 不走代理时保持原样（TcpStream + nodelay）——零回归。
    //
    // 为什么代理路径跳过 `set_nodelay`：那个方法只在 `TcpStream` 上有，
    // 而代理链路上拿到的是 `BoxStream`（可能还包了 TLS）。
    // 代理链路上延迟主要来自代理本身，nodelay 作用有限。
    let stream: BoxStream = if cfg.proxy_url.trim().is_empty() {
        let s = dial_server(cfg, addr)
            .await
            .with_context(|| format!("连接 {addr} 失败"))?;
        s.set_nodelay(true).ok();
        Box::pin(s)
    } else {
        debug!(
            proxy = %redact_proxy(&cfg.proxy_url),
            %server,
            "通过代理连接服务端"
        );
        nfrp_common::net_proxy::connect(&cfg.proxy_url, &cfg.server_addr, cfg.server_port, None)
            .await
            .with_context(|| {
                format!(
                    "经代理 {} 连接服务端 {server} 失败",
                    redact_proxy(&cfg.proxy_url)
                )
            })?
    };

    let name = if cfg.tls_server_name.is_empty() {
        &cfg.server_addr
    } else {
        &cfg.tls_server_name
    };
    // `protocol = "wss"` 自带 TLS，不用再写一遍 `transport.tls.enable`。
    let tls_on = cfg.tls_enable || cfg.websocket_tls();

    // **`verifyServerCert = true`
    //    但 TLS 没开时必须显著告警** —— 否则这是"安全配置静默失效"。
    //
    // # 原先为什么危险
    //
    // `tls::connect_client`（`common/src/frp/tls.rs:312`）第一件事是
    // `if !enable { return Ok(Box::pin(stream)); }` ——
    // **`verify` 参数在 `enable == false` 时被完全忽略**，而原先这里
    // 只在 `tls_on` 为真时才打印"已开启证书校验"。于是：
    //
    // 用户配了 `verifyServerCert = true`，看到配置"校验通过"，
    // 以为**既加密又校验**；实际**两个都没有**，链路是明文。
    //
    // # 实测铁证（`tmp/audit7/b_independent/repro_b2_tls.py`，4/4）
    //
    // 抓链路首字节：
    // * 正确开 TLS ⇒ `17 16 03 01 …`（TLS 记录）✓
    // * 驼峰 `tlsEnable = true` + `verifyServerCert = true` ⇒ **明文**
    // * 只写 `verifyServerCert = true` ⇒ **明文**
    //
    // 明文里**直接可见凭据**：
    // ```text
    // {"version":"0.71.0","hostname":"NUO","os":"windows",
    //  "privilege_key":"35a8601c28fa58a4fdb819c451100ae6", …}
    // ```
    // 而 `privilege_key = md5(token + timestamp)` —— 拿到它**可以直接重放登录**。
    //
    // 这一条还叠加了第二个坑：**同一结构体里命名风格混用**
    //   （`config.rs`）：`tls_verify_server_cert` 的 serde 名是驼峰
    //   `verifyServerCert`，而 `tls_enable` **没有任何 rename**（只能是
    //   `tls_enable`）。用户照着驼峰风格写 `tlsEnable = true`，
    //   **serde 静默丢弃**（不报错）⇒ `tls_enable` 保持 false ⇒ 触发本条。
    if cfg.tls_verify_server_cert && !tls_on {
        warn!(
            "配置里写了 `verifyServerCert = true`，但 **TLS 没有开启** —— \
             证书校验**不会生效**，且链路是**明文**：\
             登录凭据（privilege_key）可被链路上任何人嗅探并重放。\
             请同时配上 TLS：`[transport.tls] enable = true`（或 `tls_enable = true`）。"
        );
    }

    // `verifyServerCert = true` 时**真正校验**对端证书。
    //   默认 false ⇒ 与官方 frp 一致（`InsecureSkipVerify = true`），保互通。
    if cfg.tls_verify_server_cert && tls_on {
        info!(
            server_name = %name,
            trusted_ca = %if cfg.tls_trusted_ca_file.is_empty() {
                "（未配 trustedCaFile，只用内置根证书）".to_string()
            } else {
                cfg.tls_trusted_ca_file.clone()
            },
            "已开启服务端证书校验（verifyServerCert = true）"
        );
    }
    let stream = tls::connect_client(
        stream,
        &tls::ClientTlsOptions {
            enable: tls_on,
            server_name: name,
            disable_custom_first_byte: !cfg.tls_custom_first_byte,
            verify: cfg.tls_verify_server_cert,
            trusted_ca_file: &cfg.tls_trusted_ca_file,
            client_cert_file: &cfg.tls_cert_file,
            client_key_file: &cfg.tls_key_file,
        },
    )
    .await?;

    if !cfg.websocket_enabled() {
        return Ok(stream);
    }

    // TLS + WebSocket 同时打开是个真实的坑，必须当场喊出来：
    // 官方 frps 在 **TLS 之前**按明文前缀 `GET /~!frp` 嗅探 WebSocket，
    // 套了 TLS 之后首字节变成 0x16，服务端只会把它当成一条普通 frp 连接，
    // 表现为"连上就断"，而两边日志都看不出所以然。
    if tls_on && !cfg.websocket_tls() {
        warn!(
            "同时打开了 transport.tls 与 WebSocket：官方 frps 在 TLS **之前**嗅探 \
             WebSocket 前缀，这种组合直连主端口会握手失败；\
             如果要 wss，请把 protocol 设为 \"wss\" 并由前置代理（nginx 等）终结 TLS"
        );
    }

    let host = if cfg.websocket.host.trim().is_empty() {
        cfg.server_addr.as_str()
    } else {
        cfg.websocket.host.as_str()
    };
    let path = cfg.websocket.effective_path();
    let ws = ws::connect(stream, host, path, &[])
        .await
        .with_context(|| format!("WebSocket 握手失败（{host}{path}）"))?;
    info!(%host, %path, tls = tls_on, "控制连接改走 WebSocket 传输");
    Ok(Box::pin(ws))
}

/// 建立一条 KCP 连接（裸 UDP 上的可靠传输）。
///
/// 服务端要开 `kcp_bind_port`，客户端把 `transport.protocol` 设成 `kcp` 即可；
/// 上层照旧套 yamux（`tcp_mux`），所以控制连接和工作连接共用这一条 KCP 会话。
async fn kcp_connect(cfg: &ClientConfig) -> Result<BoxStream> {
    let server = format!("{}:{}", cfg.server_addr, cfg.server_port);
    let addr = util::resolve_addr(&server)
        .await
        .with_context(|| format!("解析服务端 KCP 地址 {server} 失败"))?;
    let sock = Arc::new(
        UdpSocket::bind("0.0.0.0:0")
            .await
            .context("绑定本地 UDP 端口失败（KCP 传输需要）")?,
    );
    // conv 由发起方定，服务端从第一个数据报的头里读出来照抄。
    // 用时间戳派生即可，只要保证非零（0 容易被当成无效会话号）。
    let conv = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.subsec_nanos())
        .unwrap_or(0)
        | 1;
    let stream = frp::kcp::KcpStream::connect(sock, addr, conv).await;
    info!(%addr, conv, "KCP 传输已建立");
    Ok(Box::pin(stream))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `dialServerKeepalive > 0` 时拨号成功返回的 socket 必须真的
    /// 开上 TCP keepalive；`0` 时保持内核默认（不开）。
    ///
    /// `）：
    /// 原先的 accept task **只等一次连接就结束** ——
    ///
    /// ```rust
    /// tokio::spawn(async move { let _ = l.accept().await; });  // ← 只 accept 一次
    /// let s  = dial_server(&cfg,  addr)...;   // 第 1 次 OK
    /// let s2 = dial_server(&cfg0, addr)...;   // 第 2 次：listener 已 drop ⇒ ECONNREFUSED
    /// ```
    ///
    /// 本机（Windows）能过，是因为第 2 次 `connect` 恰好在 listener 被回收前
    /// 完成了三次握手；Linux 上 listener 一 drop 端口立即失效 ⇒ 稳定失败。
    ///
    /// ⇒ 改成**常驻 accept 循环**（与产品 `web::run` / `serve.rs` 的写法一致）。
    ///   本测试要验证的是 keepalive 的 setsockopt 行为，与 accept 次数无关。
    #[tokio::test]
    async fn dial_server_按配置开_keepalive() {
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap();
        tokio::spawn(async move {
            // 常驻：本测试会拨两次号
            while let Ok((stream, _)) = l.accept().await {
                drop(stream);
            }
        });

        let cfg = ClientConfig {
            dial_server_timeout: 5,
            dial_server_keepalive: 321,
            ..Default::default()
        };
        let s = dial_server(&cfg, addr).await.unwrap();
        assert!(
            util::tcp_keepalive_enabled(&s).unwrap(),
            "dialServerKeepalive > 0 时必须开 SO_KEEPALIVE"
        );
        #[cfg(unix)]
        assert_eq!(
            util::tcp_keepalive_idle(&s).unwrap(),
            std::time::Duration::from_secs(321),
            "空闲时长要等于 dialServerKeepalive"
        );

        // 0 = 不打开
        let cfg0 = ClientConfig {
            dial_server_timeout: 5,
            dial_server_keepalive: 0,
            ..Default::default()
        };
        let s2 = dial_server(&cfg0, addr).await.unwrap();
        assert!(
            !util::tcp_keepalive_enabled(&s2).unwrap(),
            "dialServerKeepalive = 0 时不得开"
        );
    }

    /// `connectServerLocalIP` 的解析：`IP`、`IP:端口`、带方括号的 IPv6 都要认，
    /// 垃圾输入要明确报错。
    #[test]
    fn connect_server_local_ip_解析() {
        let a = parse_local_bind("192.168.1.5").unwrap();
        assert_eq!(a.ip().to_string(), "192.168.1.5");
        assert_eq!(a.port(), 0);

        let a = parse_local_bind("192.168.1.5:1234").unwrap();
        assert_eq!(a.port(), 1234);

        let a = parse_local_bind("::1").unwrap();
        assert!(a.is_ipv6());
        assert_eq!(a.port(), 0);

        let a = parse_local_bind("[::1]:0").unwrap();
        assert!(a.is_ipv6());
        assert_eq!(a.port(), 0);

        assert!(parse_local_bind("not-an-ip").is_err());
        assert!(parse_local_bind("").is_err());
    }
}
