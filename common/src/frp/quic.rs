//! QUIC 传输层（`transport.protocol = "quic"`）。
//!
//! ## 为什么值得单独做一层
//!
//! 默认传输是 `TCP -> [TLS] -> [yamux] -> frp v2`。换成 QUIC 之后变成
//! `QUIC -> frp v2`：加密与多路复用都由 QUIC 自己提供，于是
//!
//! - **握手 RTT 更少**：QUIC 把传输握手与加密握手合并，1-RTT（重连 0-RTT），
//!   而 TCP + TLS1.3 是 1（TCP）+ 1（TLS）= 2 RTT，弱网/高延迟链路上差别明显；
//! - **弱网更抗丢包**：TCP 丢一个包会阻塞整条连接上所有流（队头阻塞），
//!   QUIC 的流之间互相独立；
//! - **天然多路复用**：不需要 yamux，一条 QUIC 连接上的每条流就是一条 frp 连接。
//!
//! 证书沿用与 TLS 传输一样的策略：服务端自签、客户端不校验 ——
//! 真正的身份靠 frp 的 `token` 与 stcp/xtcp 的密钥，不靠 CA。

use std::{
    net::SocketAddr,
    pin::Pin,
    sync::{Arc, OnceLock},
    task::{Context, Poll},
    time::Duration,
};

use anyhow::{anyhow, Context as _, Result};
use quinn::{RecvStream, SendStream};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::frp::tls::crypto_provider;

/// QUIC 的 ALPN 标识。
pub const ALPN: &[u8] = b"rustunnel-frp";
/// 服务端名字：证书自签且跳过校验，但 rustls 要求它是合法 DNS 名。
pub const SERVER_NAME: &str = "rustunnel.frp";

/// 与 TCP 传输一致的 QUIC 心跳/空闲参数。
fn transport_config() -> Arc<quinn::TransportConfig> {
    let mut t = quinn::TransportConfig::default();
    t.keep_alive_interval(Some(Duration::from_secs(15)));
    let _ = t.max_idle_timeout(Some(Duration::from_secs(60).try_into().expect("超时溢出")));
    Arc::new(t)
}

static SERVER_CFG: OnceLock<quinn::ServerConfig> = OnceLock::new();

/// 服务端 QUIC 配置（自签证书）。
pub fn server_config(alpn: &[u8]) -> Result<quinn::ServerConfig> {
    if let Some(c) = SERVER_CFG.get() {
        return Ok(c.clone());
    }
    let key = rcgen::generate_simple_self_signed(vec![SERVER_NAME.to_string()])
        .context("生成 QUIC 自签证书失败")?;
    let cert_der = key.cert.der().clone();
    let key_der = key.key_pair.serialize_der();

    // ALPN 来自 rustls 而不是 quinn：两端不一致会直接握手失败
    // （错误是 "peer doesn't support any known protocol"）
    let mut tls = rustls::ServerConfig::builder_with_provider(crypto_provider())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|e| anyhow!("TLS 版本配置失败：{e}"))?
        .with_no_client_auth()
        .with_single_cert(
            vec![cert_der],
            rustls::pki_types::PrivateKeyDer::try_from(key_der)
                .map_err(|e| anyhow!("转换 QUIC 私钥失败：{e}"))?,
        )
        .context("构造 QUIC 服务端 TLS 配置失败")?;
    tls.alpn_protocols = vec![alpn.to_vec()];

    let quic_cfg = quinn::crypto::rustls::QuicServerConfig::try_from(tls)
        .map_err(|e| anyhow!("构造 QUIC 服务端配置失败：{e}"))?;
    let mut cfg = quinn::ServerConfig::with_crypto(Arc::new(quic_cfg));
    cfg.transport_config(transport_config());
    let _ = SERVER_CFG.set(cfg.clone());
    Ok(cfg)
}

/// 客户端 QUIC 配置（跳过证书校验）。
pub fn client_config(alpn: &[u8]) -> Result<quinn::ClientConfig> {
    use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
    use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
    use rustls::{DigitallySignedStruct, SignatureScheme};

    #[derive(Debug)]
    struct SkipVerify;

    impl ServerCertVerifier for SkipVerify {
        fn verify_server_cert(
            &self,
            _end_entity: &CertificateDer<'_>,
            _intermediates: &[CertificateDer<'_>],
            _server_name: &ServerName<'_>,
            _ocsp: &[u8],
            _now: UnixTime,
        ) -> Result<ServerCertVerified, rustls::Error> {
            Ok(ServerCertVerified::assertion())
        }
        fn verify_tls12_signature(
            &self,
            _m: &[u8],
            _c: &CertificateDer<'_>,
            _d: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, rustls::Error> {
            Ok(HandshakeSignatureValid::assertion())
        }
        fn verify_tls13_signature(
            &self,
            _m: &[u8],
            _c: &CertificateDer<'_>,
            _d: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, rustls::Error> {
            Ok(HandshakeSignatureValid::assertion())
        }
        fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
            crypto_provider()
                .signature_verification_algorithms
                .supported_schemes()
        }
    }

    let mut tls = rustls::ClientConfig::builder_with_provider(crypto_provider())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|e| anyhow!("TLS 版本配置失败：{e}"))?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(SkipVerify))
        .with_no_client_auth();
    tls.alpn_protocols = vec![alpn.to_vec()];

    let quic_cfg = quinn::crypto::rustls::QuicClientConfig::try_from(tls)
        .map_err(|e| anyhow!("构造 QUIC 客户端配置失败：{e}"))?;
    let mut cfg = quinn::ClientConfig::new(Arc::new(quic_cfg));
    cfg.transport_config(transport_config());
    Ok(cfg)
}

/// 服务端监听一个 UDP 端口。
pub async fn listen(addr: &SocketAddr) -> Result<quinn::Endpoint> {
    let sock = tokio::net::UdpSocket::bind(addr)
        .await
        .with_context(|| format!("监听 QUIC 端口 {addr} 失败"))?;
    quinn::Endpoint::new(
        quinn::EndpointConfig::default(),
        Some(server_config(ALPN)?),
        sock.into_std().context("转换 UDP socket 失败")?,
        Arc::new(quinn::TokioRuntime),
    )
    .context("创建 QUIC endpoint 失败")
}

/// 客户端连到服务端。
///
/// 返回 `(endpoint, 已握手好的连接)`。
///
/// 必须把 `Connection` 交回调用方：quinn 的最后一个连接句柄被 drop 时连接会
/// 立刻关闭，所以不能"连上就丢"。之后每条 frp 连接都是这条 QUIC 连接上的
/// 一条双向流（QUIC 原生多路复用，比一条 TCP 一条连接省得多）。
pub async fn connect(
    server: &SocketAddr,
    bind: Option<SocketAddr>,
) -> Result<(quinn::Endpoint, quinn::Connection)> {
    connect_with_retry(server, bind, HANDSHAKE_TIMEOUT, HANDSHAKE_ATTEMPTS).await
}

/// 单次 QUIC 握手的最长等待。
///
/// 为什么必须显式设：QUIC 跑在 UDP 上，"对面根本没在听这个端口"是**静默**的 ——
/// 数据报扔掉，没有 RST、没有 ICMP 通知应用层。服务端没配
/// `transport_protocol = "quic"`（两端不一致）时，客户端会一直卡在握手上，
/// 直到 60s 的 idle timeout 才失败，而期间日志里一个字都没有。
///
/// 这是实测踩到的：Linux 冒烟里 quic 客户端启动后静坐 13 秒、零日志，
/// 看上去像"卡死"，实际只是没人回包。所以给一个短超时 + 能直接照做的提示。
///
/// 4 秒是怎么定的：QUIC 的 Initial 只要一个 RTT 就能拿到回包，公网 RTT 按 200ms
/// 算也只用掉 5% 的预算；就算首飞丢了，quinn 还会按 PTO（初始约 1s）再重传一次，
/// 4 秒足够覆盖"首包丢 + 一次重传"。真正要防的不是"等得不够久"，
/// 而是"等太久会让一次丢包变成几十秒不可用"——一秒钟的丢包不该陪上十秒钟的等待。
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(4);

/// 握手失败时一共尝试几次。**每次都会换一个新的本地 UDP 端口重新来过。**
///
/// 为什么是"换端口重试"而不是"在同一个 socket 上多等一会儿"：
///
/// UDP 的首飞丢包在公网上是常态，而且**丢法往往是按流的** —— 中间设备（NAT、
/// 防火墙、运营商的 DPI/限速设备）会先对一个新五元组做策略判定，判定窗口内这个
/// 流的包被整批吞掉。此时同一条流上重传多少次都没用，**换一个源端口立刻就好**。
///
/// 这是实测踩到的：某云主机上装了第三方 DPI（nft `queue` 进 NFQUEUE，再由用户态
/// 程序判定），它对**所有网卡、连回环 `lo` 一起**生效，并偶发地吞掉新建 UDP 流的
/// 头几个包。当时用 strace 抓客户端系统调用，`sendto()` 全部返回 1200（成功交给
/// 内核），而 tcpdump 在设备层一个包都抓不到 —— 包在内核 netfilter 里就没了。
/// 表现就是冒烟里 QUIC 正向用例 1/8 ~ 1/4 概率失败。
///
/// 3 次 × 4 秒 + 2 次间隔 ≈ 12.5 秒封顶：比原来"单次等 10 秒"放弃得还早一点，
/// 但成功概率高得多（3 条互相独立的流 vs 1 条）。
const HANDSHAKE_ATTEMPTS: u32 = 3;

/// 换端口重试前的间隔。
///
/// 给中间设备一点时间更新策略/表项，也避免三次都撞在同一个判定窗口里。
const HANDSHAKE_RETRY_DELAY: Duration = Duration::from_millis(250);

/// 带重试的 `connect_with_timeout`：逐次换新的本地端口，直到成功或用完次数。
///
/// `bind` 为 `None` 时每次都由内核分配一个新端口，这正是能从"按流丢包"里
/// 恢复过来的原因；显式指定了 `bind` 的调用方（测试）会复用同一个端口，
/// 此时重试退化成了"多试几次"，仍然不会更差。
async fn connect_with_retry(
    server: &SocketAddr,
    bind: Option<SocketAddr>,
    attempt_timeout: Duration,
    attempts: u32,
) -> Result<(quinn::Endpoint, quinn::Connection)> {
    let attempts = attempts.max(1);
    let mut last: Option<anyhow::Error> = None;
    for attempt in 1..=attempts {
        match connect_with_timeout(server, bind, attempt_timeout).await {
            Ok(v) => return Ok(v),
            Err(e) => {
                if attempt < attempts {
                    tracing::warn!(
                        "QUIC 握手第 {attempt}/{attempts} 次未成功（{e:#}），换个本地端口重试"
                    );
                    tokio::time::sleep(HANDSHAKE_RETRY_DELAY).await;
                }
                last = Some(e);
            }
        }
    }
    let e = last.expect("attempts 至少为 1，循环必然执行过");
    Err(e.context(format!("连续 {attempts} 次 QUIC 握手都没成功")))
}

/// 同 [`connect`]，但可指定**单次**握手超时（测试用短超时，避免真等 4 秒）。
///
/// 注意这里没有重试：调用方要的就是"一次尝试"的语义（比如冒烟里验证配错时
/// 要快速失败）。需要重试请用 [`connect`]。
pub async fn connect_with_timeout(
    server: &SocketAddr,
    bind: Option<SocketAddr>,
    timeout: Duration,
) -> Result<(quinn::Endpoint, quinn::Connection)> {
    let sock = match bind {
        Some(a) => tokio::net::UdpSocket::bind(a).await,
        None => {
            // 与对端同族即可，端口交给内核
            let any: SocketAddr = if server.is_ipv4() {
                "0.0.0.0:0"
            } else {
                "[::]:0"
            }
            .parse()
            .expect("硬编码地址合法");
            tokio::net::UdpSocket::bind(any).await
        }
    }
    .context("绑定本地 UDP 端口失败")?;

    let endpoint = quinn::Endpoint::new(
        quinn::EndpointConfig::default(),
        None,
        sock.into_std().context("转换 UDP socket 失败")?,
        Arc::new(quinn::TokioRuntime),
    )
    .context("创建 QUIC endpoint 失败")?;

    // 这里就把手握完：后续 open_bi 出问题能立刻定位，
    // 而不是等到注册代理超时才报一个含糊的错
    let connecting = endpoint
        .connect_with(client_config(ALPN)?, *server, SERVER_NAME)
        .map_err(|e| anyhow!("发起 QUIC 连接失败：{e}"))?;
    // `Connecting` 实现的是 `IntoFuture` 而不是 `Future`，而 `tokio::time::timeout`
    // 要的是 `Future`，所以这里显式转一下（UFCS 写法对两种实现都成立）。
    let conn = match tokio::time::timeout(timeout, std::future::IntoFuture::into_future(connecting))
        .await
    {
        Ok(Ok(c)) => c,
        Ok(Err(e)) => return Err(anyhow!("QUIC 握手失败：{e}")),
        Err(_) => {
            return Err(anyhow!(
                "QUIC 握手超时（{server}，等了 {} 秒）：UDP 无回应。\
                 请确认服务端也配了 transport_protocol = \"quic\"，且 UDP 端口已放行",
                timeout.as_secs()
            ))
        }
    };
    Ok((endpoint, conn))
}

/// 一条 QUIC 双向流，对外表现为普通的读写流。
///
/// QUIC 的收发是分开的（SendStream / RecvStream），这里合并成一个对象，
/// 好让它能直接塞进 `BoxStream` 交给上层握手代码。
pub struct QuicStream {
    send: SendStream,
    recv: RecvStream,
}

impl QuicStream {
    pub fn new(send: SendStream, recv: RecvStream) -> Self {
        Self { send, recv }
    }

    /// 直接用 `connection.open_bi()` 的结果构造。
    pub fn from_bi(v: (SendStream, RecvStream)) -> Self {
        Self {
            send: v.0,
            recv: v.1,
        }
    }
}

impl AsyncRead for QuicStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.recv).poll_read(cx, buf)
    }
}

impl AsyncWrite for QuicStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.send)
            .poll_write(cx, buf)
            .map_err(std::io::Error::from)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.send)
            .poll_flush(cx)
            .map_err(std::io::Error::from)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.send)
            .poll_shutdown(cx)
            .map_err(std::io::Error::from)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncWriteExt;

    #[test]
    fn configs_build() {
        let _ = server_config(ALPN).expect("服务端配置");
        let _ = client_config(ALPN).expect("客户端配置");
    }

    /// 真连一次：验证 listen/connect/QuicStream 这条链路能跑通数据。
    #[tokio::test]
    async fn quic_stream_carries_data_both_ways() {
        let srv = listen(&"127.0.0.1:0".parse().unwrap()).await.expect("监听");
        let addr = srv.local_addr().expect("本地地址");

        let server_task = tokio::spawn(async move {
            let incoming = srv.accept().await.expect("accept");
            let conn = incoming.accept().unwrap().await.expect("握手");
            let (mut send, mut recv) = conn.accept_bi().await.expect("等流");
            let mut buf = [0u8; 4];
            recv.read_exact(&mut buf).await.unwrap();
            send.write_all(b"pong").await.unwrap();
            send.flush().await.unwrap();
            // Endpoint 一旦被 drop，它上面的连接会立刻关闭 ——
            // 留一点时间让客户端把回程数据读完，否则测试会假失败
            tokio::time::sleep(Duration::from_millis(200)).await;
            drop(srv);
            buf
        });

        let (_cli, conn) = connect(&addr, None).await.expect("连接");
        let (mut send, mut recv) = conn.open_bi().await.expect("开流");
        send.write_all(b"ping").await.unwrap();

        let got = server_task.await.unwrap();
        assert_eq!(&got, b"ping", "服务端应收到客户端的数据");

        let mut buf = [0u8; 4];
        recv.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"pong", "客户端也应收到回程数据");
    }

    /// 对面没人听 UDP 时，必须在**超时内**报错。
    ///
    /// 回归的是实测踩到的坑：服务端没配 `transport_protocol = "quic"`（于是不监听 UDP）
    /// 时，客户端启动后一句话都不打、静坐等 60s idle timeout —— 看上去像卡死。
    /// 不管平台是把"端口不可达"报成 ICMP 错误还是干脆静默，都不该让调用方无限等。
    #[tokio::test]
    async fn connect_fails_fast_when_nobody_listens() {
        // 拿一个刚释放的 UDP 端口：基本可以确定没人监听
        let dead = {
            let s = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
            s.local_addr().unwrap()
        };
        let start = std::time::Instant::now();
        let err = connect_with_timeout(&dead, None, Duration::from_millis(400))
            .await
            .expect_err("没人监听时必须报错，而不是一直挂着");
        let msg = format!("{err:#}");
        assert!(msg.contains("QUIC"), "错误信息应能定位到 QUIC，实际：{msg}");
        assert!(
            start.elapsed() < Duration::from_secs(5),
            "应在超时内返回，实际耗时 {:?}",
            start.elapsed()
        );
    }

    /// 握手失败必须**换个本地端口重试**若干次，而不是一次就放弃。
    ///
    /// 回归的是云端实测：宿主上的第三方 DPI 会偶发吞掉新建 UDP 流的头几个包，
    /// 而且吞法是**按流**的 —— 同一条流上重传多少遍都没用，换一个源端口立刻通。
    /// 所以 `connect` 的语义是"换端口多试几次"，这里断言它真的试满了次数：
    /// 错误里必须写明试了几次（那正是循环跑满的证据）。
    #[tokio::test]
    async fn connect_retries_before_giving_up() {
        let dead = {
            let s = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
            s.local_addr().unwrap()
        };
        let start = std::time::Instant::now();
        let err = connect_with_retry(&dead, None, Duration::from_millis(200), 3)
            .await
            .expect_err("没人监听时必须报错");
        let elapsed = start.elapsed();
        let msg = format!("{err:#}");
        assert!(
            msg.contains("连续 3 次"),
            "错误信息应交代清楚重试了几次，实际：{msg}"
        );
        assert!(msg.contains("QUIC"), "错误信息应能定位到 QUIC，实际：{msg}");
        assert!(
            elapsed >= Duration::from_millis(200),
            "至少要跑完一次超时才谈得上重试，实际只用了 {elapsed:?}"
        );
        assert!(
            elapsed < Duration::from_secs(5),
            "重试也必须封顶，不能无限拖，实际耗时 {elapsed:?}"
        );
    }
}
