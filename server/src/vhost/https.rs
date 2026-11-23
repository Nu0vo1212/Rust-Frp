//! HTTPS 虚拟主机：只嗅探 TLS ClientHello 的 SNI，**不终止 TLS**。
//!
//! 职责：从访客连接读出 ClientHello，按 SNI 查路由，向客户端要一条工作连接，
//! 把 ClientHello 原始字节与后续 TLS 字节原样透传给内网服务（证书由内网
//! 服务自己出）。路由匹配复用 `router`，连接包装复用 `conn`。
//!
//! 锁顺序契约：路由查找只短暂持有 `VhostTable` 的 `Mutex`（在 `lookup` 内），
//! 之后释放；索取工作连接走 `ClientState` 的池锁，二者不重叠加锁。
//! 本模块自身不引入新的锁。
//!
//! 不变量：TLS 密文始终原样透传，绝不解密或改写；SNI 缺失 / 无匹配路由 /
//! 等待工作连接失败都不写任何应答，直接关连接。`ConnGuard` 保证活跃连接数
//! 在所有返回路径上归还。

use std::{net::SocketAddr, sync::Arc};

use anyhow::{anyhow, Context, Result};
use nfrp_common::frp::{
    conn::FrpConn,
    msg::{FrpMessage, StartWorkConn},
};
use tokio::{io::AsyncWriteExt, net::TcpStream};
use tracing::{debug, warn};

use crate::registry::Registry;

use super::{
    conn::{record_bytes, wrap_work_stream, ConnGuard},
    router::{VhostKind, VhostTable},
};

// ---------------------------------------------------------------------------
// HTTPS：SNI 嗅探 + 原样透传
// ---------------------------------------------------------------------------
pub(super) async fn handle_https(
    mut visitor: TcpStream,
    peer: SocketAddr,
    table: Arc<VhostTable>,
    _port: u16,
    registry: Arc<Registry>,
) -> Result<()> {
    // 读出 ClientHello（返回原始字节，之后要原样转发给内网服务）
    let (sni, hello_bytes) = nfrp_common::frp::sni::sniff_client_hello(&mut visitor)
        .await
        .context("读取 TLS ClientHello 失败")?;
    let Some(sni) = sni else {
        debug!(%peer, "ClientHello 中没有 SNI，无法路由");
        return Ok(());
    };

    let Some((route, _)) = table.lookup(&sni, "/", None, VhostKind::Https) else {
        warn!(%peer, sni = %nfrp_common::util::LogSafe(&sni), "没有匹配的 https 代理");
        return Ok(());
    };

    // 等待时长由服务端 `userConnTimeout`（默认 10 秒）决定，不再硬编码 15 秒。
    let work = route
        .client
        .acquire_work_conn()
        .await
        .ok_or_else(|| anyhow!("等待工作连接超时"))?;
    let mut work_conn: FrpConn = work.conn;
    // 注意：不能下发 dst_addr。官方 frpc 会把它当 TCP 地址去解析，
    // 域名解析失败就直接关掉工作连接（PROXY protocol 才需要它）。
    work_conn
        .send_msg(&FrpMessage::StartWorkConn(StartWorkConn {
            proxy_name: route.proxy_name.clone(),
            src_addr: peer.ip().to_string(),
            src_port: peer.port(),
            ..Default::default()
        }))
        .await
        .context("发送 StartWorkConn 失败")?;

    registry.metrics().https_conns.inc();
    let _guard = ConnGuard::new(&registry);

    debug!(%peer, sni = %nfrp_common::util::LogSafe(&sni), proxy = %route.proxy_name, "HTTPS 透传开始");
    let (stream, leftover) = work_conn.into_stream();
    if !leftover.is_empty() {
        // 极少见：StartWorkConn 之后客户端已经把响应写回来了
        debug!("HTTPS 上游有 {} 字节预读数据", leftover.len());
    }
    let mut upstream = wrap_work_stream(
        stream,
        leftover,
        route.client.proxy_flags(&route.proxy_name),
        registry.security().auth_cfg.token.as_str(),
    );
    upstream.write_all(&hello_bytes).await?;
    upstream.flush().await?;
    let mut visitor = visitor;
    let r = nfrp_common::util::relay_between(&mut visitor, &mut upstream).await;
    record_bytes(&registry, &r);
    if let Err(e) = r {
        debug!(%peer, sni = %nfrp_common::util::LogSafe(&sni), "HTTPS 透传中断：{e}");
    }
    Ok(())
}
