//! xtcp 的**真 P2P**实现：UDP 打洞 + （QUIC 或 KCP）直连。
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
//!  2. 采样  为了对付对称 NAT，双方实际各用**多个** socket 发 HELLO，
//!          于是服务端能观察到一段端口序列（见 [端口预测](#端口预测)）。
//!  3. 开洞  provider 先绑好 socket，然后**持续**向 visitor 的候选地址发裸 UDP
//!          包，在自己 NAT 上留下 outbound 记录。
//!  4. 直连  visitor 用**同一个** socket 向 provider 发握手包。洞已经开好，
//!           包能进来。
//!  5. 校验  provider 确认对方 IP 就是牵线下发的那个，双方再对一次口令。
//! ```
//!
//! 任何一步失败都会返回 `Err`，调用方回退 stcp 中继 ——
//! 所以 xtcp 永远不会比 stcp 更差，只会更好。
//!
//! ## 端口预测（对称 NAT）
//!
//! 锥型（cone）NAT 给内网 `ip:port` 分配的公网端口与**目的地无关**，
//! 所以服务端看到的那个端口就是双方通信用的端口 —— 这才是"打洞"能成的前提。
//!
//! 对称 NAT 每换一个目的地就换一个端口，服务端看到的 `1.2.3.4:51000`
//! 根本不是 peer 之间通信用的那个。官方 frp 到这里就放弃、回退中继。
//!
//! 但现实里的对称 NAT 绝大多数是**顺序分配**（每条新流端口 +1 / +2），
//! 于是 [`rustunnel_common::p2p::predict_ports`] 用服务端观察到的端口序列
//! 推步长、预测接下来会拿到哪些端口，两端把整批候选端口一起打 ——
//! 命中任何一个就握手成功。
//!
//! 这条路**不保证成功**（真随机端口的对称 NAT 仍然无解），
//! 但它把"对称 NAT 必然回退"变成了"大概率能直连"，
//! 而且失败的代价只是多等一个 `PUNCH_TIMEOUT`，之后照旧回退中继。
//!
//! ## 关于同一个 socket
//!
//! 第 3 步和第 4 步必须共用**同一个本地端口**，否则 NAT 上开的是两个不同的洞，
//! 白打。所以 QUIC 模式下用 `try_clone()` 拿到指向同一 socket 的第二个句柄：
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
    frp::{
        kcp::{self, KcpStream},
        msg::{constant_time_eq, NatHoleClient, NatHoleResp, NatHoleVisitor},
    },
    p2p::{self, Packet, Role, Transport, HANDSHAKE_OK, SERVER_NAME},
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf},
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
/// 端口预测时额外开的采样 socket 数（含主 socket）。
///
/// 3 个样本足够判出步长（两个差值），再多只会让 NAT 表变胖、也拖慢牵线。
const PREDICT_SAMPLES: usize = 3;
/// 多个候选端口之间发起握手的错峰间隔。
const CANDIDATE_STAGGER: Duration = Duration::from_millis(60);
/// KCP 模式下先发几轮裸打洞包再开始握手（等价于 QUIC 的持续打洞）。
const KCP_PUNCH_ROUNDS: u32 = 6;

// ---------------------------------------------------------------------------
// 对外入口
// ---------------------------------------------------------------------------

/// visitor 侧：牵线 -> 主动向 provider 发起直连 -> 握手成功返回数据通道。
pub async fn connect_as_visitor(
    server: &SocketAddr,
    sid: &str,
    secret_key: &str,
    transport: Transport,
    window: u16,
) -> Result<P2PStream> {
    let sock = UdpSocket::bind(any_addr(server))
        .await
        .context("绑定 P2P 本地端口失败")?;
    let rd = rendezvous(&sock, server, Role::Visitor, sid, transport, window).await?;
    debug!(peer = ?rd.addrs, %sid, transport = ?rd.transport, "牵线完成，visitor 开始直连");

    let raw = sock.into_std().context("转换 UDP socket 失败")?;
    let stream = match rd.transport {
        Transport::Quic => {
            let endpoint =
                Endpoint::new(EndpointConfig::default(), None, raw, Arc::new(TokioRuntime))
                    .context("创建 QUIC endpoint 失败")?;
            let conn = quic_connect_any(&endpoint, &rd.candidates, sid).await?;
            let (send, recv) = conn.open_bi().await.map_err(quic_err("打开双向流"))?;
            let mut s = P2PStream::Quic(QuicStream {
                send,
                recv,
                _endpoint: endpoint,
            });
            greet_client(&mut s, sid, secret_key).await?;
            s
        }
        Transport::Kcp => {
            let sock = UdpSocket::from_std(raw).context("包装 KCP socket 失败")?;
            let mut s = P2PStream::Kcp(kcp_connect_any(sock, &rd.candidates, sid).await?);
            greet_client(&mut s, sid, secret_key).await?;
            s
        }
    };
    info!(peer = ?rd.addrs, %sid, transport = ?rd.transport, "xtcp P2P 直连已建立（数据不再经过服务端）");
    Ok(stream)
}

/// provider 侧：牵线 -> 边打洞边等入站 -> 握手成功返回数据通道。
pub async fn accept_as_provider(
    server: &SocketAddr,
    sid: &str,
    secret_key: &str,
    window: u16,
) -> Result<P2PStream> {
    let sock = UdpSocket::bind(any_addr(server))
        .await
        .context("绑定 P2P 本地端口失败")?;
    let rd = rendezvous(&sock, server, Role::Provider, sid, Transport::Quic, window).await?;
    debug!(peer = ?rd.addrs, %sid, transport = ?rd.transport, "牵线完成，provider 开始打洞并等待入站");

    // 预测模式下 visitor 的**端口**不一定等于牵线下发的那个（对称 NAT），
    // 所以准入条件放宽到"IP 必须是牵线下发的那个" —— 真正的身份校验是
    // 后面的应用口令，地址校验只是第一道筛子。
    let expect_ip = rd.addrs.first().map(|a| a.ip());

    let raw = sock.into_std().context("转换 UDP socket 失败")?;
    let stream = match rd.transport {
        Transport::Quic => {
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
            let punching = tokio::spawn(punch_loop(puncher, rd.candidates.clone(), deadline));

            let accepted = quic_accept(&endpoint, expect_ip, deadline).await;
            punching.abort();
            let conn = accepted?;
            let (send, recv) = conn
                .accept_bi()
                .await
                .map_err(quic_err("等待 QUIC 双向流"))?;
            let mut s = P2PStream::Quic(QuicStream {
                send,
                recv,
                _endpoint: endpoint,
            });
            greet_server(&mut s, sid, secret_key).await?;
            s
        }
        Transport::Kcp => {
            let sock = UdpSocket::from_std(raw).context("包装 KCP socket 失败")?;
            let s = kcp_accept(sock, &rd.candidates, expect_ip, sid, PUNCH_TIMEOUT).await?;
            let mut s = P2PStream::Kcp(s);
            greet_server(&mut s, sid, secret_key).await?;
            s
        }
    };
    info!(peer = ?rd.addrs, %sid, transport = ?rd.transport, "xtcp P2P 直连已建立（provider 侧）");
    Ok(stream)
}

fn quic_err(what: &str) -> impl Fn(quinn::ConnectionError) -> anyhow::Error + '_ {
    move |e| anyhow!("{what}失败：{e}")
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
    /// 本端偏好的传输（visitor 的选择会通过牵线服务端同步给 provider）。
    pub transport: Transport,
    /// 端口预测窗口；0 表示只用牵线下发的那一个地址（官方行为）。
    pub predict_window: u16,
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
            transport: parse_transport(&cfg.xtcp_transport),
            predict_window: if cfg.xtcp_port_predict {
                cfg.xtcp_predict_window.max(1)
            } else {
                0
            },
        }),
        rx,
    ))
}

/// 配置里的传输名 → [`Transport`]；认不出来就退回 QUIC。
///
/// 不直接报错是有意的：一个拼错的传输名不该让整条 xtcp 变成"连不上"，
/// 退回默认的 QUIC 最多是没吃到 KCP 的弱网收益。
fn parse_transport(s: &str) -> Transport {
    match s.trim().to_ascii_lowercase().as_str() {
        "kcp" => Transport::Kcp,
        _ => Transport::Quic,
    }
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

    let window = if cfg.xtcp_port_predict {
        cfg.xtcp_predict_window.max(1)
    } else {
        0
    };
    let stream = accept_as_provider(&server_udp, &m.sid, &proxy.secret_key, window).await?;
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
        protocol: match route.transport {
            Transport::Quic => "quic".to_string(),
            Transport::Kcp => "kcp".to_string(),
        },
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
    connect_as_visitor(
        &route.server_udp,
        &resp.sid,
        secret_key,
        route.transport,
        route.predict_window,
    )
    .await
}

// ---------------------------------------------------------------------------
// 牵线
// ---------------------------------------------------------------------------

/// 牵线的结果：对端的公网地址（可能多个）+ 双方共用的传输。
struct Rendezvous {
    /// 服务端观察到的对端地址（第一个是它连服务端时用的那个）。
    addrs: Vec<SocketAddr>,
    /// 展开后的候选地址（含端口预测结果）。
    candidates: Vec<SocketAddr>,
    transport: Transport,
}

/// 与服务端交换公网地址：反复发 HELLO，直到收到属于自己的 PEER/PEERS。
///
/// 除了主 socket，还会临时多开 [`PREDICT_SAMPLES`] - 1 个 socket 各发一份
/// HELLO —— 服务端由此观察到一段**端口序列**，peer 拿它做端口预测。
/// 这些采样 socket 用完即弃，真正承载数据的始终是主 socket。
async fn rendezvous(
    sock: &UdpSocket,
    server: &SocketAddr,
    role: Role,
    sid: &str,
    transport: Transport,
    window: u16,
) -> Result<Rendezvous> {
    let hello =
        p2p::encode_hello(role, sid, transport).context("sid 长度不是 32，无法编码 HELLO")?;

    // 采样 socket：连续 bind，端口相邻，NAT 分配出来的公网端口也倾向于相邻
    let mut probes: Vec<UdpSocket> = Vec::new();
    if window > 0 {
        for _ in 1..PREDICT_SAMPLES {
            match UdpSocket::bind(any_addr(server)).await {
                Ok(s) => probes.push(s),
                Err(e) => {
                    debug!("开采样 socket 失败，端口预测样本会少一个：{e}");
                    break;
                }
            }
        }
    }

    let deadline = Instant::now() + PUNCH_TIMEOUT;
    let mut buf = [0u8; 512];
    let mut ticker = tokio::time::interval(HELLO_INTERVAL);
    ticker.tick().await; // 丢掉立即触发的那一次，先发再等更合理

    loop {
        let remain = deadline.saturating_duration_since(Instant::now());
        if remain.is_zero() {
            bail!("等待服务端牵线下发对端地址超时（{PUNCH_TIMEOUT:?}）");
        }
        // 主 socket 先发：服务端回包只会回到主 socket
        sock.send_to(&hello, server)
            .await
            .context("发送 HELLO 失败")?;
        for p in &probes {
            let _ = p.send_to(&hello, server).await;
        }
        let got = tokio::time::timeout(remain, sock.recv_from(&mut buf)).await;
        match got {
            Ok(Ok((n, _from))) => {
                // sid 是 128 位随机值，对得上就足以证明这是本次会话的回包，
                // 所以不校验源地址（服务端多网卡时它未必是解析出来的那个 IP）
                match p2p::decode(&buf[..n]) {
                    Some(Packet::Peers {
                        role: r,
                        sid: s,
                        transport: t,
                        addrs,
                    }) if s == sid && r == role.peer() => {
                        return Ok(build_rendezvous(addrs, t, window));
                    }
                    Some(Packet::Peer {
                        role: r,
                        sid: s,
                        transport: t,
                        addr,
                    }) if s == sid && r == role.peer() => {
                        return Ok(build_rendezvous(vec![addr], t, window));
                    }
                    other => debug!(?other, "忽略非预期的牵线报文"),
                }
            }
            Ok(Err(e)) => return Err(e).context("读取牵线响应失败"),
            Err(_) => bail!("等待服务端牵线下发对端地址超时（{PUNCH_TIMEOUT:?}）"),
        }
        tokio::time::sleep(HELLO_INTERVAL).await;
    }
}

fn build_rendezvous(addrs: Vec<SocketAddr>, transport: Transport, window: u16) -> Rendezvous {
    let candidates = if window > 0 {
        p2p::expand_candidates(&addrs, window)
    } else {
        addrs.clone()
    };
    Rendezvous {
        addrs,
        candidates,
        transport,
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
// 打洞
// ---------------------------------------------------------------------------

/// 持续向**所有**候选地址发裸 UDP 包，直到 deadline。
///
/// 打一批而不是打一个，正是端口预测的关键：对称 NAT 下我们只能给出一组
/// 猜测，把它们全打一遍，命中任何一个，NAT 上就留下了对应的洞。
async fn punch_loop(sock: UdpSocket, candidates: Vec<SocketAddr>, deadline: Instant) {
    while Instant::now() < deadline {
        for c in &candidates {
            if sock.send_to(p2p::PUNCH_MAGIC, c).await.is_err() {
                return;
            }
        }
        tokio::time::sleep(PUNCH_INTERVAL).await;
    }
}

// ---------------------------------------------------------------------------
// QUIC 直连
// ---------------------------------------------------------------------------

/// 依次（错峰）尝试每个候选端口，任何一个握手成功就返回。
async fn quic_connect_any(
    endpoint: &Endpoint,
    candidates: &[SocketAddr],
    sid: &str,
) -> Result<Connection> {
    if candidates.is_empty() {
        bail!("牵线没有给出任何候选地址");
    }
    let deadline = Instant::now() + PUNCH_TIMEOUT;
    let cfg = client_config()?;

    // 只有一个候选时不必兴师动众
    if candidates.len() == 1 {
        let connecting = endpoint
            .connect_with(cfg, candidates[0], SERVER_NAME)
            .map_err(|e| anyhow!("发起 QUIC 连接失败：{e}"))?;
        return tokio::time::timeout_at(deadline, connecting)
            .await
            .map_err(|_| anyhow!("QUIC 握手超时（打洞未成功）"))?
            .map_err(|e| anyhow!("QUIC 握手失败：{e}"));
    }

    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
    for (i, addr) in candidates.iter().enumerate() {
        let ep = endpoint.clone();
        let cfg = cfg.clone();
        let addr = *addr;
        let tx = tx.clone();
        tokio::spawn(async move {
            // 错峰：一窝蜂发 Initial 容易把 NAT 表打爆，也浪费带宽
            tokio::time::sleep(CANDIDATE_STAGGER * i as u32).await;
            let r = match ep.connect_with(cfg, addr, SERVER_NAME) {
                Ok(c) => c.await.map_err(|e| anyhow!("QUIC 握手失败（{addr}）：{e}")),
                Err(e) => Err(anyhow!("发起 QUIC 连接失败（{addr}）：{e}")),
            };
            let _ = tx.send((addr, r));
        });
    }
    drop(tx);

    let mut last_err = None;
    let mut pending = candidates.len();
    while pending > 0 {
        match tokio::time::timeout_at(deadline, rx.recv()).await {
            Ok(Some((addr, Ok(conn)))) => {
                debug!(%addr, %sid, "候选端口握手成功");
                return Ok(conn);
            }
            Ok(Some((_addr, Err(e)))) => {
                last_err = Some(e);
                pending -= 1;
            }
            Ok(None) => break,
            Err(_) => break,
        }
    }
    Err(last_err.unwrap_or_else(|| anyhow!("QUIC 握手超时（打洞未成功）")))
}

/// 等一个入站 QUIC 连接；只认牵线下发过的那个 **IP**。
///
/// 端口不再要求完全一致：端口预测场景下 visitor 的实际源端口本来就是
/// 猜出来的，要求逐字节相等等于把预测功能废掉。真正的身份校验在
/// [`greet_server`] 那一步（一次一变的会话口令）。
async fn quic_accept(
    endpoint: &Endpoint,
    expect_ip: Option<std::net::IpAddr>,
    deadline: Instant,
) -> Result<Connection> {
    let incoming = tokio::time::timeout_at(deadline, endpoint.accept())
        .await
        .map_err(|_| anyhow!("等待入站 P2P 连接超时（打洞未成功）"))?
        .ok_or_else(|| anyhow!("QUIC endpoint 已关闭"))?;
    let conn = incoming
        .accept()
        .map_err(|e| anyhow!("接受 QUIC 连接失败：{e}"))?
        .await
        .map_err(|e| anyhow!("QUIC 握手失败：{e}"))?;
    let remote = conn.remote_address();
    if let Some(ip) = expect_ip {
        if remote.ip() != ip {
            conn.close(0u32.into(), b"unexpected peer");
            bail!("拒绝来自 {remote} 的 P2P 连接（牵线下发的 IP 是 {ip}）");
        }
    }
    Ok(conn)
}

// ---------------------------------------------------------------------------
// KCP 直连
// ---------------------------------------------------------------------------

/// KCP 侧 visitor：先打几轮洞，再向每个候选端口建 KCP 会话，口令对上就算成功。
async fn kcp_connect_any(
    sock: UdpSocket,
    candidates: &[SocketAddr],
    sid: &str,
) -> Result<KcpStream> {
    let conv = kcp::conv_from_sid(sid);
    if candidates.is_empty() {
        bail!("牵线没有给出任何候选地址");
    }
    // 先发裸包开洞：KCP 的第一个包如果打在没开的洞上，会直接被 NAT 丢掉
    for _ in 0..KCP_PUNCH_ROUNDS {
        for c in candidates {
            let _ = sock.send_to(p2p::PUNCH_MAGIC, c).await;
        }
        tokio::time::sleep(PUNCH_INTERVAL).await;
    }
    debug!(first = %candidates[0], total = candidates.len(), %sid, "KCP 开始建链（未锁定前会轮流试候选）");
    Ok(KcpStream::spawn_candidates(sock, candidates, conv, None))
}

/// KCP 侧 provider：边打洞边等第一个数据报，从中认出 visitor。
async fn kcp_accept(
    sock: UdpSocket,
    candidates: &[SocketAddr],
    expect_ip: Option<std::net::IpAddr>,
    sid: &str,
    timeout: Duration,
) -> Result<KcpStream> {
    let conv = kcp::conv_from_sid(sid);
    let deadline = Instant::now() + timeout;
    let mut buf = vec![0u8; 2048];
    loop {
        let remain = deadline.saturating_duration_since(Instant::now());
        if remain.is_zero() {
            bail!("等待入站 P2P 连接超时（打洞未成功）");
        }
        // 打洞与收包交替进行：只在开头打一轮是不够的，
        // NAT 上的洞要靠持续的出站包维持
        for c in candidates {
            let _ = sock.send_to(p2p::PUNCH_MAGIC, c).await;
        }
        match tokio::time::timeout(remain.min(PUNCH_INTERVAL * 4), sock.recv_from(&mut buf)).await {
            Ok(Ok((n, from))) => {
                if let Some(ip) = expect_ip {
                    if from.ip() != ip {
                        debug!(%from, "忽略陌生来源的 P2P 报文");
                        continue;
                    }
                }
                debug!(%from, %sid, "KCP 收到首个数据报，开始建链");
                return Ok(KcpStream::spawn(sock, from, conv, Some(buf[..n].to_vec())));
            }
            Ok(Err(e)) => return Err(e).context("读取 P2P 数据报失败"),
            Err(_) => continue,
        }
    }
}

// ---------------------------------------------------------------------------
// 应用握手
// ---------------------------------------------------------------------------

/// visitor：先写口令，再等对方回 `HANDSHAKE_OK`；之后这条流就是数据通道。
async fn greet_client<S>(s: &mut S, sid: &str, secret_key: &str) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    // 注意：这里**不能**关掉写方向 —— 这条流握手完还要继续当数据通道用
    s.write_all(p2p::handshake_token(secret_key, sid).as_bytes())
        .await?;
    let mut ok = [0u8; HANDSHAKE_OK.len()];
    tokio::time::timeout(PUNCH_TIMEOUT, s.read_exact(&mut ok))
        .await
        .map_err(|_| anyhow!("等待 P2P 握手响应超时"))??;
    if ok != HANDSHAKE_OK {
        bail!("对端拒绝了 P2P 握手（口令不匹配）");
    }
    Ok(())
}

/// provider：读口令并校验，校验通过才回 `HANDSHAKE_OK`。
async fn greet_server<S>(s: &mut S, sid: &str, secret_key: &str) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut got = vec![0u8; TOKEN_LEN];
    tokio::time::timeout(PUNCH_TIMEOUT, s.read_exact(&mut got))
        .await
        .map_err(|_| anyhow!("等待 P2P 口令超时"))??;
    let got = String::from_utf8(got).map_err(|_| anyhow!("P2P 口令不是 UTF-8"))?;
    let expect = p2p::handshake_token(secret_key, sid);
    if !constant_time_eq(&got, &expect) {
        warn!(%sid, "P2P 握手口令不匹配，拒绝该连接");
        let _ = s.write_all(b"BAD").await;
        let _ = s.shutdown().await;
        bail!("P2P 握手口令不匹配（对方不是本次 xtcp 会话的 peer）");
    }
    s.write_all(HANDSHAKE_OK).await?;
    Ok(())
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
            _end_entder: &CertificateDer<'_>,
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

/// 一条 QUIC 双向流：收发两个方向合成一个既能读又能写的对象。
pub(crate) struct QuicStream {
    send: SendStream,
    recv: RecvStream,
    /// 把 endpoint 的句柄**留住**。
    ///
    /// 建链用的 `Endpoint` 是 `connect_as_visitor` / `accept_as_provider` 里的
    /// 局部变量，函数一返回它就被 drop 了。quinn 的 endpoint 一撤，
    /// 它名下的连接也跟着没 —— 表现为 P2P 刚握完手就
    /// `closed by peer: 0`，上层拿到的是一条死流。
    _endpoint: Endpoint,
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

/// 一条 P2P 数据通道：对外就是一个既能读又能写的流，
/// 这样上层可以直接把它丢给 `relay_between`，不必关心底下跑的是什么。
pub enum P2PStream {
    Quic(QuicStream),
    Kcp(KcpStream),
}

impl AsyncRead for P2PStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            Self::Quic(s) => Pin::new(s).poll_read(cx, buf),
            Self::Kcp(s) => Pin::new(s).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for P2PStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        match self.get_mut() {
            Self::Quic(s) => Pin::new(s).poll_write(cx, buf),
            Self::Kcp(s) => Pin::new(s).poll_write(cx, buf),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            Self::Quic(s) => Pin::new(s).poll_flush(cx),
            Self::Kcp(s) => Pin::new(s).poll_flush(cx),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            Self::Quic(s) => Pin::new(s).poll_shutdown(cx),
            Self::Kcp(s) => Pin::new(s).poll_shutdown(cx),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    #[test]
    fn any_addr_follows_remote_family() {
        let v4: SocketAddr = "1.2.3.4:7000".parse().unwrap();
        let v6: SocketAddr = "[2001:db8::1]:7000".parse().unwrap();
        assert!(any_addr(&v4).is_ipv4());
        assert!(any_addr(&v6).is_ipv6());
        assert_eq!(any_addr(&v4).port(), 0, "端口交给内核分配");
    }

    #[test]
    fn transport_names_are_lenient() {
        assert_eq!(parse_transport("kcp"), Transport::Kcp);
        assert_eq!(parse_transport("KCP"), Transport::Kcp);
        assert_eq!(parse_transport("quic"), Transport::Quic);
        // 拼错不该让 xtcp 挂掉，退回默认的 QUIC
        assert_eq!(parse_transport("kcpp"), Transport::Quic);
        assert_eq!(parse_transport(""), Transport::Quic);
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

    /// 候选地址必须**包含**牵线下发的原始地址 ——
    /// 否则锥型 NAT（原本能直连的场景）反而连不上了。
    #[test]
    fn candidates_always_include_the_observed_address() {
        let rd = build_rendezvous(
            vec!["203.0.113.9:45001".parse().unwrap()],
            Transport::Quic,
            8,
        );
        assert!(rd
            .candidates
            .contains(&"203.0.113.9:45001".parse().unwrap()));
        assert!(rd.candidates.len() > 1, "开了预测就该多出候选端口");
    }

    /// 关掉预测（window = 0）时行为必须退回官方：只打那一个地址。
    #[test]
    fn zero_window_falls_back_to_single_address() {
        let rd = build_rendezvous(
            vec!["203.0.113.9:45001".parse().unwrap()],
            Transport::Quic,
            0,
        );
        assert_eq!(rd.candidates.len(), 1);
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

        let cli_sock = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let client = Endpoint::new(
            EndpointConfig::default(),
            None,
            cli_sock,
            Arc::new(TokioRuntime),
        )
        .unwrap();
        // endpoint 是 Clone 的：多留一份句柄给 QuicStream，验证"留住 endpoint"
        // 这件事确实能把连接撑住
        let server2 = server.clone();

        let sid = "0123456789abcdef0123456789abcdef";
        let sk = "top-secret";

        // 服务端必须**活到客户端读完**为止：endpoint 一撤，连接立刻没，
        // 客户端那边只会看到一句没有信息量的 `closed by peer: 0`。
        // 用 oneshot 把生命周期显式钉住，而不是靠 sleep 赌时序。
        let (done_tx, done_rx) = tokio::sync::oneshot::channel::<()>();
        let srv_task = tokio::spawn(async move {
            let incoming = server.accept().await.expect("accept");
            let conn = incoming.accept().unwrap().await.expect("handshake");
            let (send, recv) = conn.accept_bi().await.expect("accept_bi");
            let mut s = P2PStream::Quic(QuicStream {
                send,
                recv,
                _endpoint: server2,
            });
            let r = greet_server(&mut s, sid, sk).await;
            let _ = done_rx.await;
            r
        });

        let conn = client
            .connect_with(client_config().unwrap(), srv_addr, SERVER_NAME)
            .unwrap()
            .await
            .expect("连接成功");
        let (send, recv) = conn.open_bi().await.expect("open_bi");
        let mut s = P2PStream::Quic(QuicStream {
            send,
            recv,
            _endpoint: client,
        });
        greet_client(&mut s, sid, sk).await.expect("握手成功");

        s.write_all(b"ping").await.unwrap();
        drop(done_tx);
        srv_task.await.unwrap().expect("服务端握手");
    }

    /// 迷你牵线服务：把两个 peer 的地址互换（逻辑与服务端 `P2PHub` 一致）。
    ///
    /// 与服务端的差别只有"没有超时回收"，行为上必须一一对应：
    /// **按角色分别攒地址**，凑齐两个角色后把对方的全部采样地址下发出去，
    /// 端口预测才有输入。
    async fn mini_rendezvous(sock: UdpSocket) {
        let mut buf = [0u8; 512];
        // role -> (观测到的地址列表, 该角色声明的传输)
        let mut seen: HashMap<Role, (Vec<SocketAddr>, Transport)> = HashMap::new();
        loop {
            let Ok((n, peer)) = sock.recv_from(&mut buf).await else {
                break;
            };
            let Some(Packet::Hello {
                role,
                sid,
                transport,
            }) = p2p::decode(&buf[..n])
            else {
                continue;
            };
            let (addrs, t) = seen.entry(role).or_insert((Vec::new(), transport));
            if !addrs.contains(&peer) {
                addrs.push(peer);
            }
            *t = transport;

            let Some((other_addrs, _)) = seen.get(&role.peer()) else {
                continue;
            };
            // 传输由 visitor 说了算（与服务端 P2PHub::register 一致）
            let chosen = seen
                .get(&Role::Visitor)
                .map(|(_, t)| *t)
                .unwrap_or(transport);
            let mine = seen[&role].0.clone();
            let other = other_addrs.clone();
            // 给当前发送方回"对方的地址"，给对方回"当前发送方的全部采样地址"
            if let Some(pkt) = p2p::encode_peers(role.peer(), &sid, chosen, &other) {
                let _ = sock.send_to(&pkt, peer).await;
            }
            if let Some(pkt) = p2p::encode_peers(role, &sid, chosen, &mine) {
                for a in &other {
                    let _ = sock.send_to(&pkt, a).await;
                }
            }
            return;
        }
    }

    /// 完整链路（QUIC）：牵线 -> 打洞 -> 握手 -> 口令 -> 双向数据。
    #[tokio::test]
    async fn full_p2p_over_rendezvous() {
        let rd = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let rd_addr = rd.local_addr().unwrap();
        tokio::spawn(mini_rendezvous(rd));

        let sid = "aaaabbbbccccddddeeeeffff00001111";
        let sk = "p2p-secret";

        let provider = tokio::spawn({
            let server = rd_addr;
            async move { accept_as_provider(&server, sid, sk, 4).await }
        });
        let mut visitor = connect_as_visitor(&rd_addr, sid, sk, Transport::Quic, 4)
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

    /// 同一条链路换成 KCP：验证"弱网备选通道"这条路径也是通的。
    #[tokio::test]
    async fn full_p2p_over_rendezvous_with_kcp() {
        let rd = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let rd_addr = rd.local_addr().unwrap();
        tokio::spawn(mini_rendezvous(rd));

        let sid = "11112222333344445555666677778888";
        let sk = "kcp-secret";

        let provider = tokio::spawn({
            let server = rd_addr;
            async move { accept_as_provider(&server, sid, sk, 4).await }
        });
        let mut visitor = connect_as_visitor(&rd_addr, sid, sk, Transport::Kcp, 4)
            .await
            .expect("visitor 侧 KCP P2P 建立失败");

        let mut provider_stream = provider
            .await
            .unwrap()
            .expect("provider 侧 KCP P2P 建立失败");
        assert!(
            matches!(provider_stream, P2PStream::Kcp(_)),
            "provider 也必须走 KCP"
        );

        visitor.write_all(b"ping").await.unwrap();
        let mut buf = [0u8; 4];
        provider_stream.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"ping");

        provider_stream.write_all(b"pong").await.unwrap();
        visitor.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"pong", "KCP P2P 链路必须双向可通");
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
        let server2 = server.clone();
        let srv_task = tokio::spawn(async move {
            let incoming = server.accept().await.expect("accept");
            let conn = incoming.accept().unwrap().await.expect("handshake");
            let (send, recv) = conn.accept_bi().await.expect("accept_bi");
            let mut s = P2PStream::Quic(QuicStream {
                send,
                recv,
                _endpoint: server2,
            });
            greet_server(&mut s, sid, "right-key").await
        });

        let conn = client
            .connect_with(client_config().unwrap(), srv_addr, SERVER_NAME)
            .unwrap()
            .await
            .expect("连接成功");
        let (send, recv) = conn.open_bi().await.expect("open_bi");
        let mut s = P2PStream::Quic(QuicStream {
            send,
            recv,
            _endpoint: client,
        });
        // 用错密钥握手：客户端读回来的不是 OK，必须报错
        let r = greet_client(&mut s, sid, "wrong-key").await;
        assert!(r.is_err(), "口令不对却成功了：等于 NAT 外谁都能进来");
        // 服务端侧也必须失败
        let srv = srv_task.await.unwrap();
        assert!(srv.is_err());
    }
}
