//! xtcp 的**真 P2P**实现：UDP 打洞 + QUIC 直连。
//!
//! ## 为什么官方能打洞、中继版不能
//!
//! stcp 与中继版 xtcp 的流量都要经过服务端，瓶颈在服务端带宽。
//! 真 P2P 让两个内网主机直接通信，前提是各自在 NAT 上开一个"洞"——
//! 而洞只能由**内向外**发包来开。所以完整的建立过程是：
//!
//! ```text
//!  1. 牵线  双方各向 frps 的 p2p_port 发 HELLO{sid}；服务端从 UDP 源地址
//!          学到各自的公网地址，凑齐后互换下发 PEER。
//!  2. 开洞  provider 先绑好 socket，然后**持续**向 visitor 的公网地址发裸 UDP
//!          包，在自己 NAT 上留下 "本地端口 -> visitor" 的 outbound 记录。
//!  3. 直连  visitor 用**同一个** socket（交给 quinn 接管）向 provider 发 QUIC
//!          握手。因为 provider 的洞已经开好，Initial 包能进来。
//!  4. 校验  provider 确认对方地址就是牵线下发的那个，双方再对一次口令。
//! ```
//!
//! 任何一步失败都会返回 `Err`，调用方回退 stcp 中继 ——
//! 所以 xtcp 永远不会比 stcp 更差，只会更好。
//!
//! ## 关于同一个 socket
//!
//! 第 2 步和第 3 步必须共用**同一个本地端口**，否则 NAT 上开的是两个不同的洞，
//! 白打。所以这里用 `try_clone()` 拿到指向同一 socket 的第二个句柄：
//! 一个交给 quinn，一个留着发打洞包。

use std::{
    collections::HashMap,
    net::SocketAddr,
    pin::Pin,
    sync::{Arc, OnceLock},
    task::{Context, Poll},
    time::Duration,
};

use anyhow::{anyhow, bail, Context as _, Result};
use quinn::{Connection, Endpoint, EndpointConfig, RecvStream, SendStream, TokioRuntime};
use rustunnel_common::{
    config::{ClientConfig, ProxyConfig},
    frp::msg::{constant_time_eq, NatHoleClient, NatHoleResp, NatHoleVisitor},
    p2p::{self, Packet, Role, HANDSHAKE_OK, SERVER_NAME},
};
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    net::UdpSocket,
    time::Instant,
};
use tracing::{debug, info, warn};

/// 一次 P2P 尝试的总时限：超过就认定打洞失败，回退中继。
const PUNCH_TIMEOUT: Duration = Duration::from_secs(8);
/// 打洞包的发送间隔：比 QUIC 的重传间隔密一些，保证洞一直是热的。
const PUNCH_INTERVAL: Duration = Duration::from_millis(50);
/// 牵线阶段 HELLO 的重发间隔（UDP 会丢包，且要等慢一拍的对端）。
const HELLO_INTERVAL: Duration = Duration::from_millis(200);
/// 口令长度（`handshake_token` 是 32 字节的十六进制）。
const TOKEN_LEN: usize = 64;
/// QUIC 心跳间隔：必须**小于** NAT 的 UDP 映射老化时间（常见 30s），
/// 否则洞会在空闲期间悄悄关掉，数据再也过不去。
const KEEP_ALIVE: Duration = Duration::from_secs(5);
/// 空闲超时：心跳断了这么久就认为对端没了。
const IDLE_TIMEOUT: Duration = Duration::from_secs(30);

// ---------------------------------------------------------------------------
// 对外入口
// ---------------------------------------------------------------------------

/// visitor 侧：牵线 -> 主动向 provider 发起 QUIC 连接 -> 握手成功返回数据通道。
pub async fn connect_as_visitor(
    server: &SocketAddr,
    sid: &str,
    secret_key: &str,
) -> Result<P2PStream> {
    let sock = UdpSocket::bind(any_addr(server))
        .await
        .context("绑定 P2P 本地端口失败")?;
    let peer = rendezvous(&sock, server, Role::Visitor, sid, PUNCH_TIMEOUT).await?;
    debug!(%peer, %sid, "牵线完成，visitor 开始 QUIC 握手");

    let raw = sock.into_std().context("转换 UDP socket 失败")?;
    let endpoint = Endpoint::new(EndpointConfig::default(), None, raw, Arc::new(TokioRuntime))
        .context("创建 QUIC endpoint 失败")?;

    let deadline = Instant::now() + PUNCH_TIMEOUT;
    let connecting = endpoint
        .connect_with(client_config()?, peer, SERVER_NAME)
        .map_err(|e| anyhow!("发起 QUIC 连接失败：{e}"))?;
    let conn = tokio::time::timeout_at(deadline, connecting)
        .await
        .map_err(|_| anyhow!("QUIC 握手超时（打洞未成功）"))?
        .map_err(|e| anyhow!("QUIC 握手失败：{e}"))?;

    let (send, recv) = client_handshake(&conn, sid, secret_key).await?;
    info!(%peer, %sid, "xtcp P2P 直连已建立（数据不再经过服务端）");
    Ok(P2PStream { send, recv })
}

/// provider 侧：牵线 -> 边打洞边等入站 QUIC -> 握手成功返回数据通道。
pub async fn accept_as_provider(
    server: &SocketAddr,
    sid: &str,
    secret_key: &str,
) -> Result<P2PStream> {
    let sock = UdpSocket::bind(any_addr(server))
        .await
        .context("绑定 P2P 本地端口失败")?;
    let peer = rendezvous(&sock, server, Role::Provider, sid, PUNCH_TIMEOUT).await?;
    debug!(%peer, %sid, "牵线完成，provider 开始打洞并等待入站");

    let raw = sock.into_std().context("转换 UDP socket 失败")?;
    // 关键：克隆出同端口的第二个句柄 —— quinn 接管 raw，克隆体用来持续打洞
    let puncher = UdpSocket::from_std(raw.try_clone().context("克隆 UDP socket 失败")?)
        .context("包装打洞 socket 失败")?;

    let endpoint = Endpoint::new(
        EndpointConfig::default(),
        Some(server_config()?),
        raw,
        Arc::new(TokioRuntime),
    )
    .context("创建 QUIC endpoint 失败")?;

    let deadline = Instant::now() + PUNCH_TIMEOUT;
    let punching = tokio::spawn(async move {
        while Instant::now() < deadline {
            if puncher.send_to(p2p::PUNCH_MAGIC, peer).await.is_err() {
                break;
            }
            tokio::time::sleep(PUNCH_INTERVAL).await;
        }
        debug!(%peer, "打洞任务结束");
    });

    let accept = async {
        let incoming = endpoint
            .accept()
            .await
            .ok_or_else(|| anyhow!("QUIC endpoint 已关闭"))?;
        let conn = incoming
            .accept()
            .map_err(|e| anyhow!("接受 QUIC 连接失败：{e}"))?
            .await
            .map_err(|e| anyhow!("QUIC 握手失败：{e}"))?;
        // 安全底线：只认牵线下发过的那个地址。
        // 打洞意味着本地端口对公网敞开了，少了这道校验谁都能连进来。
        let remote = conn.remote_address();
        if remote != peer {
            conn.close(0u32.into(), b"unexpected peer");
            bail!("拒绝来自 {remote} 的 P2P 连接（牵线的地址是 {peer}）");
        }
        Ok(conn)
    };
    let conn: Connection = match tokio::time::timeout_at(deadline, accept).await {
        Ok(r) => r?,
        Err(_) => {
            punching.abort();
            bail!("等待入站 P2P 连接超时（打洞未成功）");
        }
    };

    let stream = server_handshake(&conn, sid, secret_key).await;
    punching.abort();
    let (send, recv) = stream?;
    info!(%peer, %sid, "xtcp P2P 直连已建立（provider 侧）");
    Ok(P2PStream { send, recv })
}

// ---------------------------------------------------------------------------
// 与控制连接的协作
// ---------------------------------------------------------------------------

/// 打洞消息的收发中枢。
///
/// `NatHoleVisitor` 必须发在**控制连接**上（服务端也只在控制连接上回），
/// 但控制连接被主循环的 `recv_msg` 独占着。于是走一条旁路：
/// 请求方把消息丢进通道由主循环代发，响应按 `transaction_id` 回给等待者。
pub struct PunchBus {
    req_tx: tokio::sync::mpsc::UnboundedSender<NatHoleVisitor>,
    waiters: std::sync::Mutex<HashMap<String, tokio::sync::oneshot::Sender<NatHoleResp>>>,
}

impl PunchBus {
    fn new() -> (
        Arc<Self>,
        tokio::sync::mpsc::UnboundedReceiver<NatHoleVisitor>,
    ) {
        let (req_tx, req_rx) = tokio::sync::mpsc::unbounded_channel();
        (
            Arc::new(Self {
                req_tx,
                waiters: std::sync::Mutex::new(HashMap::new()),
            }),
            req_rx,
        )
    }

    /// 发一个打洞请求，并拿到等响应的收端。
    pub fn request(
        &self,
        m: NatHoleVisitor,
    ) -> Result<tokio::sync::oneshot::Receiver<NatHoleResp>> {
        let (tx, rx) = tokio::sync::oneshot::channel();
        self.waiters
            .lock()
            .unwrap()
            .insert(m.transaction_id.clone(), tx);
        self.req_tx
            .send(m)
            .map_err(|_| anyhow!("控制连接已关闭，无法发起打洞"))?;
        Ok(rx)
    }

    /// 主循环收到 `NatHoleResp` 时调用：按 transaction_id 交给等待者。
    pub fn deliver(&self, resp: NatHoleResp) {
        let waiter = self.waiters.lock().unwrap().remove(&resp.transaction_id);
        if let Some(tx) = waiter {
            let _ = tx.send(resp);
        } else {
            debug!(txn = %resp.transaction_id, "收到无人等待的 NatHoleResp，丢弃");
        }
    }

    /// 控制连接断开时清空等待者，否则对端会一直挂到超时。
    pub fn clear(&self) {
        self.waiters.lock().unwrap().clear();
    }
}

/// 本次会话里 P2P 需要的全部上下文。
pub struct P2PRoute {
    /// 服务端牵线服务的 UDP 地址。
    pub server_udp: SocketAddr,
    pub bus: Arc<PunchBus>,
}

/// 建一套打洞中枢；`None` 表示配置里没开 P2P（xtcp 将只走中继）。
pub async fn setup(
    cfg: &ClientConfig,
) -> Option<(
    Arc<P2PRoute>,
    tokio::sync::mpsc::UnboundedReceiver<NatHoleVisitor>,
)> {
    let port = cfg.p2p_port?;
    if !cfg.p2p_enable {
        return None;
    }
    let addr = rustunnel_common::util::resolve_addr(&format!("{}:{}", cfg.server_addr, port))
        .await
        .ok()?;
    let (bus, rx) = PunchBus::new();
    Some((
        Arc::new(P2PRoute {
            server_udp: addr,
            bus,
        }),
        rx,
    ))
}

/// provider 侧：收到服务端的 `NatHoleClient` 后打洞，成功后把流量转给内网服务。
pub async fn serve_as_provider(
    cfg: Arc<ClientConfig>,
    proxy: ProxyConfig,
    m: NatHoleClient,
) -> Result<()> {
    let Some(port) = cfg.p2p_port else {
        bail!("收到打洞请求但未配置 p2p_port，忽略");
    };
    let server_udp = rustunnel_common::util::resolve_addr(&format!("{}:{}", cfg.server_addr, port))
        .await
        .with_context(|| format!("解析牵线地址 {}:{} 失败", cfg.server_addr, port))?;

    let local_addr = rustunnel_common::util::resolve_addr(&proxy.local_addr)
        .await
        .with_context(|| format!("解析内网地址 {} 失败", proxy.local_addr))?;

    let stream = accept_as_provider(&server_udp, &m.sid, &proxy.secret_key).await?;
    debug!(proxy = %m.proxy_name, local = %local_addr, "P2P 已建立，连接内网服务");
    let mut local = tokio::net::TcpStream::connect(local_addr)
        .await
        .with_context(|| format!("连接内网服务 {local_addr} 失败"))?;
    local.set_nodelay(true).ok();
    let mut stream = stream;
    match rustunnel_common::util::relay_between(&mut local, &mut stream).await {
        Ok((up, down)) => debug!(proxy = %m.proxy_name, "P2P 转发结束：上行 {up}B / 下行 {down}B"),
        Err(e) => debug!(proxy = %m.proxy_name, "P2P 转发中断：{e}"),
    }
    Ok(())
}

/// visitor 侧：请服务端牵线并尝试 P2P 直连。
///
/// 返回 `Err` **不代表失败**——调用方应当据此回退到 stcp 中继。
pub async fn try_punch_as_visitor(
    route: &P2PRoute,
    run_id: &str,
    target: &str,
    secret_key: &str,
) -> Result<P2PStream> {
    let txn = rustunnel_common::util::new_run_id();
    let ts = rustunnel_common::util::now_unix_secs() as i64;
    let req = NatHoleVisitor {
        transaction_id: txn.clone(),
        proxy_name: target.to_string(),
        // 服务端用与 stcp 相同的规则校验：hex(md5(secret_key + timestamp))
        sign_key: rustunnel_common::frp::msg::auth_key(secret_key, ts),
        timestamp: ts,
        protocol: "quic".to_string(),
        ..Default::default()
    };
    let _ = run_id;

    let rx = route.bus.request(req)?;
    let resp = tokio::time::timeout(PUNCH_TIMEOUT, rx)
        .await
        .map_err(|_| anyhow!("等待服务端牵线响应超时"))?
        .map_err(|_| anyhow!("打洞请求被丢弃（控制连接断开了？）"))?;
    if !resp.error.is_empty() {
        bail!("服务端拒绝打洞：{}", resp.error);
    }
    if resp.sid.is_empty() {
        bail!("服务端未下发 sid（可能未启用 P2P）");
    }
    connect_as_visitor(&route.server_udp, &resp.sid, secret_key).await
}

// ---------------------------------------------------------------------------
// 牵线
// ---------------------------------------------------------------------------

/// 与服务端交换公网地址：反复发 HELLO，直到收到属于自己的 PEER。
async fn rendezvous(
    sock: &UdpSocket,
    server: &SocketAddr,
    role: Role,
    sid: &str,
    timeout: Duration,
) -> Result<SocketAddr> {
    let hello = p2p::encode_hello(role, sid).context("sid 长度不是 32，无法编码 HELLO")?;
    let deadline = Instant::now() + timeout;
    let mut buf = [0u8; 512];
    let mut ticker = tokio::time::interval(HELLO_INTERVAL);
    ticker.tick().await; // 丢掉立即触发的那一次，先发再等更合理

    loop {
        let remain = deadline.saturating_duration_since(Instant::now());
        if remain.is_zero() {
            bail!("等待服务端牵线下发对端地址超时（{timeout:?}）");
        }
        tokio::select! {
            _ = ticker.tick() => {
                sock.send_to(&hello, server).await.context("发送 HELLO 失败")?;
            }
            got = tokio::time::timeout(remain, sock.recv_from(&mut buf)) => {
                let (n, _from) = got??;
                // sid 是 128 位随机值，对得上就足以证明这是本次会话的回包，
                // 所以不校验源地址（服务端多网卡时它未必是解析出来的那个 IP）
                match p2p::decode(&buf[..n]) {
                    Some(Packet::Peer { role: r, sid: s, addr }) if s == sid && r == role.peer() => {
                        return Ok(addr);
                    }
                    other => debug!(?other, "忽略非预期的牵线报文"),
                }
            }
        }
    }
}

/// 按对端地址族挑一个"任意地址"用于绑定本地端口。
fn any_addr(remote: &SocketAddr) -> SocketAddr {
    if remote.is_ipv4() {
        "0.0.0.0:0"
    } else {
        "[::]:0"
    }
    .parse()
    .expect("硬编码的任意地址必然合法")
}

// ---------------------------------------------------------------------------
// 应用握手
// ---------------------------------------------------------------------------

/// visitor：先写口令，再等对方回 `HANDSHAKE_OK`；之后这条流就是数据通道。
async fn client_handshake(
    conn: &Connection,
    sid: &str,
    secret_key: &str,
) -> Result<(SendStream, RecvStream)> {
    let (mut send, mut recv) = conn
        .open_bi()
        .await
        .map_err(|e| anyhow!("打开 QUIC 双向流失败：{e}"))?;
    // 注意：这里**不能** finish() —— 这条流握手完还要继续当数据通道用
    send.write_all(p2p::handshake_token(secret_key, sid).as_bytes())
        .await?;
    let mut ok = [0u8; HANDSHAKE_OK.len()];
    tokio::time::timeout(PUNCH_TIMEOUT, recv.read_exact(&mut ok))
        .await
        .map_err(|_| anyhow!("等待 P2P 握手响应超时"))??;
    if ok != HANDSHAKE_OK {
        bail!("对端拒绝了 P2P 握手（口令不匹配）");
    }
    Ok((send, recv))
}

/// provider：读口令并校验，校验通过才回 `HANDSHAKE_OK`。
async fn server_handshake(
    conn: &Connection,
    sid: &str,
    secret_key: &str,
) -> Result<(SendStream, RecvStream)> {
    let (mut send, mut recv) = conn
        .accept_bi()
        .await
        .map_err(|e| anyhow!("等待 QUIC 双向流失败：{e}"))?;
    let mut got = vec![0u8; TOKEN_LEN];
    tokio::time::timeout(PUNCH_TIMEOUT, recv.read_exact(&mut got))
        .await
        .map_err(|_| anyhow!("等待 P2P 口令超时"))??;
    let got = String::from_utf8(got).map_err(|_| anyhow!("P2P 口令不是 UTF-8"))?;
    let expect = p2p::handshake_token(secret_key, sid);
    if !constant_time_eq(&got, &expect) {
        warn!(%sid, "P2P 握手口令不匹配，拒绝该连接");
        let _ = send.write_all(b"BAD").await;
        let _ = send.finish();
        bail!("P2P 握手口令不匹配（对方不是本次 xtcp 会话的 peer）");
    }
    send.write_all(HANDSHAKE_OK).await?;
    Ok((send, recv))
}

// ---------------------------------------------------------------------------
// QUIC 配置
// ---------------------------------------------------------------------------

static SERVER_CFG: OnceLock<quinn::ServerConfig> = OnceLock::new();

/// 自签证书 + 跳过校验的服务端配置（与 frp 的 xtcp 一致：无 CA，靠口令鉴权）。
fn server_config() -> Result<quinn::ServerConfig> {
    if let Some(c) = SERVER_CFG.get() {
        return Ok(c.clone());
    }
    let key = rcgen::generate_simple_self_signed(vec![SERVER_NAME.to_string()])
        .context("生成 P2P 自签证书失败")?;
    let cert_der = key.cert.der().clone();
    let key_der = key.key_pair.serialize_der();

    // ALPN 来自 rustls 的配置而不是 quinn 的（quinn 只转发），
    // 所以必须在这里设；两端不一致会报 "peer doesn't support any known protocol"。
    let mut tls = rustls::ServerConfig::builder_with_provider(common_crypto_provider())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|e| anyhow!("TLS 版本配置失败：{e}"))?
        .with_no_client_auth()
        .with_single_cert(
            vec![cert_der],
            rustls::pki_types::PrivateKeyDer::try_from(key_der)
                .map_err(|e| anyhow!("转换 P2P 私钥失败：{e}"))?,
        )
        .context("构造 P2P 服务端 TLS 配置失败")?;
    tls.alpn_protocols = vec![p2p::ALPN.to_vec()];

    let quic_cfg = quinn::crypto::rustls::QuicServerConfig::try_from(tls)
        .map_err(|e| anyhow!("构造 QUIC 服务端配置失败：{e}"))?;
    let mut cfg = quinn::ServerConfig::with_crypto(Arc::new(quic_cfg));
    cfg.transport_config(transport_config());
    let _ = SERVER_CFG.set(cfg.clone());
    Ok(cfg)
}

/// visitor 用的客户端配置：证书一律跳过校验。
fn client_config() -> Result<quinn::ClientConfig> {
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
            rustls::crypto::ring::default_provider()
                .signature_verification_algorithms
                .supported_schemes()
        }
    }

    let mut tls = rustls::ClientConfig::builder_with_provider(common_crypto_provider())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|e| anyhow!("TLS 版本配置失败：{e}"))?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(SkipVerify))
        .with_no_client_auth();
    tls.alpn_protocols = vec![p2p::ALPN.to_vec()];

    let quic_cfg = quinn::crypto::rustls::QuicClientConfig::try_from(tls)
        .map_err(|e| anyhow!("构造 QUIC 客户端配置失败：{e}"))?;
    let mut cfg = quinn::ClientConfig::new(Arc::new(quic_cfg));
    cfg.transport_config(transport_config());
    Ok(cfg)
}

fn common_crypto_provider() -> Arc<rustls::crypto::CryptoProvider> {
    rustunnel_common::frp::tls::crypto_provider()
}

/// 两端共用的传输参数：P2P 链路上要有心跳，否则 NAT 的洞会悄悄关掉。
fn transport_config() -> Arc<quinn::TransportConfig> {
    let mut t = quinn::TransportConfig::default();
    t.keep_alive_interval(Some(KEEP_ALIVE));
    // try_into 只在 Duration 大到溢出 u32 毫秒时失败，这里不可能
    let _ = t.max_idle_timeout(Some(IDLE_TIMEOUT.try_into().expect("超时溢出")));
    Arc::new(t)
}

// ---------------------------------------------------------------------------
// 数据通道
// ---------------------------------------------------------------------------

/// 一条 P2P 数据通道：对外就是一个既能读又能写的流，
/// 这样上层可以直接把它丢给 `relay_between`，不必关心 QUIC 的收发分离。
pub struct P2PStream {
    send: SendStream,
    recv: RecvStream,
}

impl AsyncRead for P2PStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.recv).poll_read(cx, buf)
    }
}

impl AsyncWrite for P2PStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        // quinn 的写错误不是 std::io::Error，这里统一翻译成 io::Error，
        // 这样上层（relay_between）只需要处理一种错误类型
        Pin::new(&mut self.send)
            .poll_write(cx, buf)
            .map_err(std::io::Error::from)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.send).poll_flush(cx)
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

    #[test]
    fn any_addr_follows_remote_family() {
        let v4: SocketAddr = "1.2.3.4:7000".parse().unwrap();
        let v6: SocketAddr = "[2001:db8::1]:7000".parse().unwrap();
        assert!(any_addr(&v4).is_ipv4());
        assert!(any_addr(&v6).is_ipv6());
        assert_eq!(any_addr(&v4).port(), 0, "端口交给内核分配");
    }

    #[test]
    fn server_and_client_config_both_build() {
        // 只要能构造出来就说明 rcgen + danger 配置这条链路是通的。
        // 生成自签证书有几十毫秒开销，所以服务端配置走 OnceLock —— 这里顺带
        // 确认第二次调用不会因为已被缓存而出错。
        let _ = server_config().expect("服务端配置");
        let _ = server_config().expect("服务端配置（缓存命中）");
        let _ = client_config().expect("客户端配置");
    }

    /// `TransportConfig` 没有 getter 读不回来，所以退一步断言**常量关系**：
    /// 心跳必须比空闲超时短，且都比常见的 NAT 老化时间（30s）短。
    #[test]
    fn keepalive_is_shorter_than_idle_timeout() {
        assert!(
            KEEP_ALIVE < IDLE_TIMEOUT,
            "心跳必须比空闲超时短，否则永远等不到心跳"
        );
        assert!(
            KEEP_ALIVE <= Duration::from_secs(30),
            "心跳间隔必须小于常见 NAT 的 UDP 老化时间，否则洞会关掉"
        );
        // 顺带确认 transport_config 能构造成功（溢出会 panic）
        let _ = transport_config();
    }

    /// 端到端：同一台机器上两个 endpoint 互相打，验证握手序列本身是对的。
    ///
    /// 这不是真的 NAT 打洞（回环上没有 NAT），但能验证
    /// "口令 -> OK -> 数据" 这条序列以及地址校验逻辑。
    #[tokio::test]
    async fn handshake_over_real_quic() {
        let scfg = server_config().unwrap();

        let srv_sock = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let srv_addr = srv_sock.local_addr().unwrap();
        let server = Endpoint::new(
            EndpointConfig::default(),
            Some(scfg),
            srv_sock,
            Arc::new(TokioRuntime),
        )
        .unwrap();

        let mut ccfg = client_config().unwrap();
        let _ = &mut ccfg;
        let cli_sock = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let client = Endpoint::new(
            EndpointConfig::default(),
            None,
            cli_sock,
            Arc::new(TokioRuntime),
        )
        .unwrap();

        let sid = "0123456789abcdef0123456789abcdef";
        let sk = "top-secret";

        let srv_task = tokio::spawn(async move {
            let incoming = server.accept().await.expect("accept");
            let conn = incoming.accept().unwrap().await.expect("handshake");
            server_handshake(&conn, sid, sk).await
        });

        let conn = client
            .connect_with(client_config().unwrap(), srv_addr, SERVER_NAME)
            .unwrap()
            .await
            .expect("连接成功");
        let (mut send, mut recv) = client_handshake(&conn, sid, sk).await.expect("握手成功");

        send.write_all(b"ping").await.unwrap();

        let (mut s_send, mut s_recv) = srv_task.await.unwrap().expect("服务端握手");
        let mut buf = [0u8; 4];
        s_recv.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"ping");
        s_send.write_all(b"pong").await.unwrap();
        recv.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"pong");
    }

    /// 迷你牵线服务：把两个 peer 的地址互换（逻辑与服务端 `P2PHub` 一致）。
    async fn mini_rendezvous(sock: UdpSocket) {
        let mut buf = [0u8; 512];
        let mut first: Option<(SocketAddr, Role, String)> = None;
        loop {
            let Ok((n, peer)) = sock.recv_from(&mut buf).await else {
                break;
            };
            let Some(Packet::Hello { role, sid }) = p2p::decode(&buf[..n]) else {
                continue;
            };
            match first.take() {
                None => first = Some((peer, role, sid)),
                // 凑齐一对（同 sid、不同角色）就互换地址
                Some((a, a_role, a_sid)) if a_sid == sid && a_role != role => {
                    if let Some(pkt) = p2p::encode_peer(a_role.peer(), &sid, &peer) {
                        let _ = sock.send_to(&pkt, a).await;
                    }
                    if let Some(pkt) = p2p::encode_peer(role.peer(), &sid, &a) {
                        let _ = sock.send_to(&pkt, peer).await;
                    }
                    return;
                }
                Some(other) => first = Some(other),
            }
        }
    }

    /// 完整链路：牵线 -> 打洞 -> QUIC -> 口令 -> 双向数据。
    ///
    /// 回环上没有 NAT，所以这不是真的"穿墙"；但它验证的是**除了 NAT 之外**
    /// 的所有东西：牵线报文、双方地址交换、同一 socket 打洞 + 握手、
    /// 口令校验、以及数据能不能真的双向流通。
    #[tokio::test]
    async fn full_p2p_over_rendezvous() {
        use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

        let rd = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let rd_addr = rd.local_addr().unwrap();
        tokio::spawn(mini_rendezvous(rd));

        let sid = "aaaabbbbccccddddeeeeffff00001111";
        let sk = "p2p-secret";

        let provider = tokio::spawn({
            let server = rd_addr;
            async move { accept_as_provider(&server, sid, sk).await }
        });
        let mut visitor = connect_as_visitor(&rd_addr, sid, sk)
            .await
            .expect("visitor 侧 P2P 建立失败");

        let mut provider_stream = provider.await.unwrap().expect("provider 侧 P2P 建立失败");

        visitor.write_all(b"ping").await.unwrap();
        let mut buf = [0u8; 4];
        provider_stream.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"ping");

        provider_stream.write_all(b"pong").await.unwrap();
        visitor.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"pong", "P2P 链路必须双向可通");
    }

    /// 口令不对时必须失败，而不是"能连上就算过"。
    #[tokio::test]
    async fn wrong_token_is_rejected() {
        let scfg = server_config().unwrap();

        let srv_sock = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let srv_addr = srv_sock.local_addr().unwrap();
        let server = Endpoint::new(
            EndpointConfig::default(),
            Some(scfg),
            srv_sock,
            Arc::new(TokioRuntime),
        )
        .unwrap();

        let cli_sock = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let client = Endpoint::new(
            EndpointConfig::default(),
            None,
            cli_sock,
            Arc::new(TokioRuntime),
        )
        .unwrap();

        let sid = "0123456789abcdef0123456789abcdef";
        let srv_task = tokio::spawn(async move {
            let incoming = server.accept().await.expect("accept");
            let conn = incoming.accept().unwrap().await.expect("handshake");
            server_handshake(&conn, sid, "right-key").await
        });

        let conn = client
            .connect_with(client_config().unwrap(), srv_addr, SERVER_NAME)
            .unwrap()
            .await
            .expect("连接成功");
        // 用错密钥握手：客户端读回来的不是 OK，必须报错
        let r = client_handshake(&conn, sid, "wrong-key").await;
        assert!(r.is_err(), "口令不对却成功了：等于 NAT 外谁都能进来");
        // 服务端侧也必须失败
        let srv = srv_task.await.unwrap();
        assert!(srv.is_err());
    }
}
