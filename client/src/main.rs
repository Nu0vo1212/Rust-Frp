//! `rustunnel-client`：frp v2 兼容的客户端（等价于原版 frpc）。

use std::{collections::HashMap, sync::Arc, time::Duration};

use anyhow::{anyhow, bail, Context, Result};
use clap::Parser;
use rustunnel_common::{
    config::{default_config_path, ClientConfig, Protocol},
    frp::{
        conn::{self},
        msg::{FrpMessage, NewProxy, Ping},
        mux::MuxSession,
        stream::BoxStream,
        tls,
    },
    util,
};
use tokio::{net::TcpStream, time::interval};
use tokio::io::AsyncWriteExt;
use tracing::{debug, error, info, warn};

#[derive(Parser, Debug)]
#[command(name = "rustunnel-client", version, about = "rustunnel 客户端（兼容原版 frp）")]
struct Cli {
    /// 配置文件路径（默认 ./client.toml）
    #[arg(short, long, value_name = "PATH")]
    config: Option<std::path::PathBuf>,

    /// 打印一份示例配置到标准输出
    #[arg(long)]
    print_example: bool,

    /// 生成示例配置文件到指定路径
    #[arg(long, value_name = "PATH")]
    gen_config: Option<std::path::PathBuf>,

    /// 覆盖配置里的日志级别
    #[arg(long, value_name = "LEVEL")]
    log_level: Option<String>,

    /// 覆盖配置里的线协议（frp-v2 / rustunnel）
    #[arg(long, value_name = "PROTOCOL")]
    protocol: Option<String>,

    /// 服务端地址（覆盖配置）
    #[arg(long, value_name = "ADDR")]
    server_addr: Option<String>,

    /// 服务端端口（覆盖配置）
    #[arg(short, long, value_name = "PORT")]
    server_port: Option<u16>,

    /// 认证 token（覆盖配置）
    #[arg(short, long, value_name = "TOKEN")]
    token: Option<String>,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    if cli.print_example {
        println!("{}", ClientConfig::example_toml());
        return Ok(());
    }
    if let Some(path) = &cli.gen_config {
        ClientConfig::write_example(path)?;
        println!("已生成示例配置：{}", path.display());
        return Ok(());
    }

    let path = cli
        .config
        .clone()
        .unwrap_or_else(|| default_config_path("client.toml"));
    if !path.exists() {
        bail!(
            "配置文件不存在：{}\n可先执行：{} --gen-config {}",
            path.display(),
            std::env::args()
                .next()
                .unwrap_or_else(|| "rustunnel-client".into()),
            path.display()
        );
    }
    let mut cfg = ClientConfig::load(&path)
        .with_context(|| format!("读取配置 {} 失败", path.display()))?;
    if let Some(p) = &cli.protocol {
        cfg.protocol = p.parse::<Protocol>().map_err(anyhow::Error::msg)?;
    }
    if let Some(a) = &cli.server_addr {
        cfg.server_addr = a.clone();
    }
    if let Some(p) = cli.server_port {
        cfg.server_port = p;
    }
    if let Some(t) = &cli.token {
        cfg.token = t.clone();
    }

    let level = cli
        .log_level
        .clone()
        .unwrap_or_else(|| cfg.log_level.clone());
    util::init_tracing(&level);

    if cfg.protocol != Protocol::FrpV2 {
        bail!("当前版本客户端仅实现 frp-v2 协议（可在配置里设置 protocol = \"frp-v2\"）");
    }
    if cfg.proxies.is_empty() {
        warn!("配置里没有 [[proxies]]，客户端不会暴露任何端口");
    }

    let cfg = Arc::new(cfg);
    info!(
        "rustunnel-client 启动：连接 {}:{}，共 {} 个代理",
        cfg.server_addr,
        cfg.server_port,
        cfg.proxies.len()
    );

    let shutdown = util::shutdown_signal();
    tokio::pin!(shutdown);

    loop {
        let fut = run_session(cfg.clone());
        tokio::select! {
            r = fut => {
                match r {
                    Ok(()) => info!("与控制服务端的会话结束"),
                    Err(e) => error!("会话出错：{e:#}"),
                }
            }
            _ = &mut shutdown => {
                info!("客户端已停止");
                return Ok(());
            }
        }

        info!("{} 秒后重连…", cfg.reconnect_interval);
        tokio::select! {
            _ = tokio::time::sleep(Duration::from_secs(cfg.reconnect_interval)) => {}
            _ = &mut shutdown => {
                info!("客户端已停止");
                return Ok(());
            }
        }
    }
}

/// 与服务端之间的连接工厂。
///
/// 负责按配置依次套上 TLS 与 yamux：
/// - `tls_enable` 打开时先发 frp 自定义首字节再握手；
/// - `tcp_mux` 打开时只在会话开始时建一条 TCP，后续所有连接都开 yamux stream。
struct ServerLink {
    cfg: Arc<ClientConfig>,
    mux: Option<MuxSession>,
}

impl ServerLink {
    async fn open(cfg: Arc<ClientConfig>) -> Result<Self> {
        let mux = if cfg.tcp_mux {
            let stream = raw_connect(&cfg).await?;
            Some(MuxSession::new(stream))
        } else {
            None
        };
        Ok(Self { cfg, mux })
    }

    /// 取得一条到服务端的流：yamux stream，或一条新的 TCP（+TLS）。
    async fn connect(&self) -> Result<BoxStream> {
        match &self.mux {
            Some(m) => m.open_stream().await,
            None => raw_connect(&self.cfg).await,
        }
    }
}

/// 建立一条到服务端的底层连接（TCP，按需 TLS）。
async fn raw_connect(cfg: &ClientConfig) -> Result<BoxStream> {
    let server = format!("{}:{}", cfg.server_addr, cfg.server_port);
    let addr = util::resolve_addr(&server)
        .await
        .with_context(|| format!("解析服务端地址 {server} 失败"))?;
    let stream = TcpStream::connect(addr)
        .await
        .with_context(|| format!("连接 {addr} 失败"))?;
    stream.set_nodelay(true).ok();

    let name = if cfg.tls_server_name.is_empty() {
        &cfg.server_addr
    } else {
        &cfg.tls_server_name
    };
    tls::connect_client(
        stream,
        cfg.tls_enable,
        name,
        !cfg.tls_custom_first_byte,
    )
    .await
}

/// 建立一次完整的控制连接会话，直到连接断开或出错。
async fn run_session(cfg: Arc<ClientConfig>) -> Result<()> {
    let server = format!("{}:{}", cfg.server_addr, cfg.server_port);
    let link = Arc::new(ServerLink::open(cfg.clone()).await?);
    info!(%server, "已连接到服务端，开始握手");

    let stream = link.connect().await?;
    let (mut conn, run_id) =
        conn::client_handshake(stream, &cfg.token, &cfg.client_id, cfg.pool_count).await?;
    info!(%run_id, "登录成功（控制通道已启用 AES-256-GCM）");

    // 注册代理
    //
    // 注意：官方 frps 会在 NewProxyResp 之间插入 ReqWorkConn（填充工作连接池），
    // 所以不能发送一个就死等一个响应，必须边读边按代理名匹配。
    let proxies: Arc<HashMap<String, String>> = Arc::new(
        cfg.proxies
            .iter()
            .map(|p| (p.name.clone(), p.local_addr.clone()))
            .collect(),
    );
    let run_id = Arc::new(run_id);

    for p in &cfg.proxies {
        conn.send_msg(&FrpMessage::NewProxy(NewProxy {
            proxy_name: p.name.clone(),
            proxy_type: "tcp".to_string(),
            remote_port: p.remote_port,
            ..Default::default()
        }))
        .await?;
    }

    let mut pending: std::collections::HashSet<String> =
        cfg.proxies.iter().map(|p| p.name.clone()).collect();
    while !pending.is_empty() {
        let msg = tokio::time::timeout(Duration::from_secs(15), conn.recv_msg())
            .await
            .context("等待 NewProxyResp 超时")??;
        match msg {
            Some(FrpMessage::NewProxyResp(r)) => {
                pending.remove(&r.proxy_name);
                let local = proxies.get(&r.proxy_name).map(|s| s.as_str()).unwrap_or("?");
                if r.error.is_empty() {
                    info!(proxy = %r.proxy_name, remote = %r.remote_addr, local, "代理注册成功");
                } else {
                    error!(proxy = %r.proxy_name, "代理注册失败：{}", r.error);
                }
            }
            Some(FrpMessage::ReqWorkConn) => {
                spawn_work_conn(link.clone(), run_id.clone(), proxies.clone());
            }
            Some(other) => debug!("注册期间收到 {}，忽略", other.name()),
            None => bail!("服务端在代理注册完成前断开"),
        }
    }

    // 预建工作连接（与官方 frpc 的 pool_count 行为一致）
    for _ in 0..cfg.pool_count.max(0) {
        spawn_work_conn(link.clone(), run_id.clone(), proxies.clone());
    }

    let mut ticker = interval(Duration::from_secs(cfg.heartbeat_interval.max(1) as u64));
    ticker.tick().await; // 丢掉立即触发的第一次
    let mut last_pong = std::time::Instant::now();

    loop {
        tokio::select! {
            msg = conn.recv_msg() => {
                let Some(msg) = msg? else { info!("服务端关闭了控制连接"); break };
                match msg {
                    FrpMessage::ReqWorkConn => {
                        debug!("收到 ReqWorkConn，建立工作连接");
                        spawn_work_conn(link.clone(), run_id.clone(), proxies.clone());
                    }
                    FrpMessage::Pong(p) => {
                        if !p.error.is_empty() {
                            warn!("服务端 Pong 返回错误：{}", p.error);
                        }
                        last_pong = std::time::Instant::now();
                    }
                    FrpMessage::NewProxyResp(_) => {}
                    other => debug!("忽略消息：{}", other.name()),
                }
            }
            _ = ticker.tick() => {
                conn.send_msg(&FrpMessage::Ping(Ping {
                    timestamp: util::now_unix_secs() as i64,
                    ..Default::default()
                }))
                .await?;
                if last_pong.elapsed() > Duration::from_secs(cfg.heartbeat_timeout) {
                    bail!("{} 秒未收到 Pong，判定连接已死", cfg.heartbeat_timeout);
                }
            }
        }
    }
    Ok(())
}

fn spawn_work_conn(
    link: Arc<ServerLink>,
    run_id: Arc<String>,
    proxies: Arc<HashMap<String, String>>,
) {
    tokio::spawn(async move {
        if let Err(e) = work_conn_flow(link, run_id, proxies).await {
            debug!("工作连接结束：{e:#}");
        }
    });
}

/// 建立一条工作连接：取流 -> NewWorkConn -> 等 StartWorkConn -> 连内网服务 -> 双向转发。
async fn work_conn_flow(
    link: Arc<ServerLink>,
    run_id: Arc<String>,
    proxies: Arc<HashMap<String, String>>,
) -> Result<()> {
    let stream = link.connect().await?;

    let ts = util::now_unix_secs() as i64;
    let (mut work, leftover, start) =
        conn::client_work_conn(stream, &run_id, &link.cfg.token, ts).await?;

    let local_addr = proxies
        .get(&start.proxy_name)
        .ok_or_else(|| anyhow!("服务端指定了未知代理：{}", start.proxy_name))?;
    let local = util::resolve_addr(local_addr)
        .await
        .with_context(|| format!("解析内网地址 {local_addr} 失败"))?;
    let mut local_stream = TcpStream::connect(local)
        .await
        .with_context(|| format!("连接内网服务 {local} 失败"))?;
    local_stream.set_nodelay(true).ok();

    debug!(proxy = %start.proxy_name, %local, "工作连接已建立，开始转发");
    if !leftover.is_empty() {
        local_stream.write_all(&leftover).await?;
    }
    let r = tokio::io::copy_bidirectional(&mut work, &mut local_stream).await;
    if let Err(e) = r {
        debug!(proxy = %start.proxy_name, "转发中断：{e}");
    }
    Ok(())
}
