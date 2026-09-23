//! 客户端 VirtualNet：把本机 TUN 网卡上的 IP 包灌进服务端的虚拟交换机。
//!
//! # 一句话
//!
//! 给客户端加一块"虚拟网卡"，同网段里其他客户端 ping 得到你、你也 ping 得到它们，
//! 走的全是已有的那条穿透隧道外的独立连接（`vnet_port`）。
//!
//! # 三段式
//!
//! ```text
//!   ① 注册：连 vnet_port，发一行 JSON（带 privilege_key），拿回分配到的地址
//!   ② 建卡：open_tun(name, mtu, "<ip>/<prefix>")  ← 需要 root / CAP_NET_ADMIN
//!   ③ 转发：tun 读 → 封帧 → 写 socket ；socket 读 → 拆帧 → 写 tun
//! ```
//!
//! # 为什么"建卡"只做一次
//!
//! 断线重连要无限重试，但**建设备失败重试一万次也没用** —— 那是权限问题，
//! 得有人去改。所以 TUN 在第一次注册成功后建好并复用；之后每次重连只更新
//! 地址（服务端重启、地址池换网段时地址会变）。
//!
//! # 不碰默认路由
//!
//! 只加一条"本虚拟网段走 TUN"的直连路由（靠 `ip addr add` 的网段地址天然带来）。
//! **绝不**设默认路由 —— 一个默默把你全部流量劫走的内网穿透工具是灾难。
//! 想让整机流量走虚拟网络，请用户自己 `ip route add default via <网关>`。

use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use rustunnel_common::auth::oidc::TokenSource;
use rustunnel_common::config::ClientConfig;
use rustunnel_common::vnet::{
    encode_frame, open_tun, read_json_line, take_frame, Subnet, Tun, VnetRegister,
    VnetRegisterResp, MAX_IP_PACKET,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tracing::{debug, error, info, warn};

use crate::current_credential;

/// 虚拟网卡名模板。`%d` 交给内核挑号（`rustunnel0`、`rustunnel1`…），
/// 免得与用户自己建的 `tun0` 撞名。
const TUN_NAME: &str = "rustunnel%d";

/// 注册响应的行上限。
const MAX_RESP_LINE: usize = 8 * 1024;

/// 常驻任务：断线就一直重连，直到进程退出。
pub async fn run(cfg: Arc<ClientConfig>, token_source: Option<Arc<TokenSource>>) -> Result<()> {
    let interval = Duration::from_secs(cfg.reconnect_interval.max(1));
    let mut tun: Option<Tun> = None;
    // 上一次配到网卡上的地址。重连后地址变了就必须 replace，否则包会以
    // 一个服务端不认识的源地址发出去（查无此人 → 对端回包无处可去）。
    let mut current_spec: Option<String> = None;

    loop {
        match session(&cfg, &token_source, &mut tun, &mut current_spec).await {
            Ok(()) => info!("VirtualNet 会话正常结束，{interval:?} 后重连"),
            Err(e) => {
                error!("VirtualNet 会话中断：{e:#}");
                // 建设备失败是**不可重试**的：重试一万次还是没权限，
                // 只会把日志刷满。第一种错误直接退出任务，把原因留在日志里。
                if e.to_string().contains("TUN") && tun.is_none() {
                    return Err(e);
                }
                warn!("{interval:?} 后重试");
            }
        }
        tokio::time::sleep(interval).await;
    }
}

/// 一次完整的会话：注册 → （首次）建卡 → 转发，直到连接断开。
async fn session(
    cfg: &ClientConfig,
    token_source: &Option<Arc<TokenSource>>,
    tun: &mut Option<Tun>,
    current_spec: &mut Option<String>,
) -> Result<()> {
    let port = cfg.virtual_net.server_port;
    if port == 0 {
        anyhow::bail!(
            "开了 [virtualNet] 但没写 serverPort —— 不知道服务端的 VirtualNet 端口是哪个。\
             请在客户端配置里补上 `serverPort = <服务端 vnet_port>`。"
        );
    }
    let server = format!("{}:{}", cfg.server_addr, port);
    let addr = rustunnel_common::util::resolve_addr(&server)
        .await
        .with_context(|| format!("解析 VirtualNet 服务端地址 {server} 失败"))?;
    let mut stream = TcpStream::connect(addr)
        .await
        .with_context(|| format!("连接 VirtualNet 服务端 {addr} 失败"))?;
    stream.set_nodelay(true).ok();

    // ① 注册。token 字段放的是**privilege_key**（不是原始密钥）——
    //    与普通控制连接的 `Login.privilege_key` 完全同一套语义。
    let ts = rustunnel_common::util::now_unix_secs() as i64;
    let cred = current_credential(cfg, token_source).await?;
    let reg = VnetRegister {
        client: cfg.client_id.clone(),
        network: cfg.virtual_net.network.clone(),
        address: cfg.virtual_net.address.clone(),
        token: cred.wire_value(ts),
        timestamp: ts,
    };
    stream.write_all(&reg.to_line()?).await?;
    stream.flush().await?;

    let mut resp_buf: Vec<u8> = Vec::with_capacity(256);
    let resp_line = read_json_line(&mut stream, &mut resp_buf, MAX_RESP_LINE)
        .await
        .context("读 VirtualNet 注册应答失败（多半是认证失败或端口不对）")?;
    let resp = VnetRegisterResp::from_line(&resp_line)?;
    if !resp.ok {
        anyhow::bail!("VirtualNet 注册被拒绝：{}", resp.error);
    }
    let ip: std::net::Ipv4Addr = resp
        .address
        .parse()
        .with_context(|| format!("服务端返回的地址无法解析：{:?}", resp.address))?;
    let sub = Subnet::parse(&resp.subnet)
        .with_context(|| format!("服务端返回的网段无法解析：{:?}", resp.subnet))?;
    let mtu = if resp.mtu == 0 { 1400 } else { resp.mtu };
    let spec = format!("{ip}/{}", sub.prefix());

    // ② 建卡（只在第一次）
    match tun {
        None => {
            let gw = resp.gateway.clone();
            let dev = open_tun(TUN_NAME, mtu, Some(&spec), None).with_context(|| {
                format!(
                    "创建虚拟网卡失败（需要 root 或 CAP_NET_ADMIN）。\
                     服务端分配的地址是 {spec}，网关 {gw}"
                )
            })?;
            info!(
                dev = dev.name(),
                %ip,
                subnet = %sub,
                %gw,
                mtu,
                "VirtualNet 网卡已就绪"
            );
            *current_spec = Some(spec);
            *tun = Some(dev);
        }
        Some(dev) => {
            // ③ 重连：地址可能与上次不同，换掉
            if current_spec.as_deref() != Some(spec.as_str()) {
                warn!(
                    old = ?current_spec,
                    new = %spec,
                    "重连后虚拟地址变了，正在更新网卡"
                );
                dev.set_address(&spec)?;
                *current_spec = Some(spec);
            }
            debug!(dev = dev.name(), %ip, "VirtualNet 重连成功");
        }
    }

    relay(stream, tun.as_mut().expect("上面刚保证过")).await
}

/// 双向转发主循环。
///
/// 一个任务同时管两个方向（而不是各开一个）：TUN 的读写共用同一个 fd 与同一个
/// `AsyncFd`，分成两个任务就得拿锁，而"持锁等待可读"会把另一个方向的写
/// 一起卡住 —— 那正是最难查的一类问题。
async fn relay(stream: TcpStream, tun: &mut Tun) -> Result<()> {
    let (mut sock_rd, mut sock_wr) = stream.into_split();
    let mut tun_buf = vec![0u8; MAX_IP_PACKET];
    let mut sock_buf = vec![0u8; MAX_IP_PACKET];
    let mut pending: Vec<u8> = Vec::new();

    loop {
        tokio::select! {
            // 本机 → 虚拟网络
            n = tun.read(&mut tun_buf) => {
                let n = n.context("读 TUN 失败")?;
                if n == 0 {
                    anyhow::bail!("TUN 返回 0 字节（设备被删除？）");
                }
                let frame = encode_frame(&tun_buf[..n])?;
                sock_wr.write_all(&frame).await.context("写 VirtualNet socket 失败")?;
                sock_wr.flush().await.ok();
            }
            // 虚拟网络 → 本机
            n = sock_rd.read(&mut sock_buf) => {
                let n = n.context("读 VirtualNet socket 失败")?;
                if n == 0 {
                    anyhow::bail!("服务端关闭了 VirtualNet 连接");
                }
                pending.extend_from_slice(&sock_buf[..n]);
                while let Some(pkt) = take_frame(&mut pending)? {
                    // 写进 TUN 就等于把包交给内核协议栈 —— 内核自己会做去重、
                    // 校验和检查、以及"这不是给我的包"的判断，我们不用管。
                    tun.write_all(&pkt).await.context("写 TUN 失败")?;
                }
            }
        }
    }
}
