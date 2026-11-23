//! 工作连接数据面：`StartWorkConn` 之后的内网转发。
//!
//! 职责：按需起一条工作连接（`spawn_work_conn`），握手后按代理类型分流到 UDP
//! 转发器、插件或内网 TCP，并处理 PROXY 头、加密 / 压缩与限速。
//! 并发/所有权契约：每条工作连接是一个独立 `tokio::spawn` 任务，持有
//! `Arc<ServerLink>`、run_id、`ProxyTable` 与健康检查器；任务之间不共享可变缓冲，
//! 连接结束即释放。
//! 不变量：服务端下发的 `proxy_name` 必须经 `resolve_uploaded_proxy` 剥前缀；
//! 加密 / 压缩开启时 `leftover` 必须先拼回 work 流再包 `ProxyStream`。

use std::sync::Arc;

use anyhow::{anyhow, Context, Result};
use nfrp_common::{
    frp::conn::{self, FrpConn},
    proxy_protocol, throttle, util,
};
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use tracing::debug;

use crate::{
    health,
    link::ServerLink,
    nlink, plugin, registry,
    session::{current_credential, resolve_uploaded_proxy},
    udp_proxy,
};

pub(crate) fn spawn_work_conn(
    link: Arc<ServerLink>,
    run_id: Arc<String>,
    proxies: registry::ProxyTable,
    health: Arc<health::Monitor>,
    nlink: Arc<nlink::ClientNLink>,
) {
    tokio::spawn(async move {
        if let Err(e) = work_conn_flow(link, run_id, proxies, health, nlink).await {
            debug!("工作连接结束：{e:#}");
        }
    });
}

/// 建立一条工作连接：取流 -> NewWorkConn -> 等 StartWorkConn -> 连内网服务 -> 双向转发。
async fn work_conn_flow(
    link: Arc<ServerLink>,
    run_id: Arc<String>,
    proxies: registry::ProxyTable,
    health: Arc<health::Monitor>,
    nlink: Arc<nlink::ClientNLink>,
) -> Result<()> {
    let stream = link.connect().await?;

    let ts = util::now_unix_secs() as i64;
    // 每次建工作连接都现取一次凭证：OIDC 的 access token 会过期。
    //   token 模式 → `auth_key(token, ts)`；OIDC 模式 → 原始 JWT。
    //   0.7.6 及以前这里固定用 `link.cfg.token` 派生，OIDC 部署下服务端
    //   会以「不是合法的 JWT」拒掉每一条工作连接。
    let cred = current_credential(&link.cfg, &link.token_source).await?;
    // NLink 身份令牌：协商了才带（`identity()` 为 None 时字段不出现）。
    let identity = nlink.identity();
    let (work, leftover, start) =
        conn::client_work_conn_with(stream, link.wire, &run_id, &cred, ts, identity.as_deref())
            .await?;

    // 服务端下发的名字是**线上全名**（带 `{user}.` 前缀），本地映射表按配置里的
    // 原始 `name` 建 —— 统一走 `resolve_uploaded_proxy`。
    let (proxy_name, proxy) =
        resolve_uploaded_proxy(&link.cfg.user, &start.proxy_name, &proxies)
            .ok_or_else(|| anyhow!("服务端指定了未知代理：{}", start.proxy_name))?;
    let proxy = proxy.clone();

    // 健康检查不通过：直接拒掉这条工作连接，让用户去连别的后端
    if !health.is_healthy(&proxy_name) {
        anyhow::bail!("代理 [{proxy_name}] 健康检查未通过，暂不提供服务");
    }

    // UDP / SUDP 代理：工作连接上跑的是 UdpPacket 消息，交给专门的转发器。
    // SUDP（secret UDP）的数据面与普通 UDP 完全一致——都是一条专用工作连接
    // 上跑 UdpPacket 帧；差别只在它没有公网端口、访问方走 visitor 通道进来。
    if matches!(proxy.proxy_type.as_str(), "udp" | "sudp") {
        // 工作连接握手后是裸字节流，这里重新包一层帧读写器
        // （工作连接本身不加密，所以直接 new 即可）。
        let mut udp_conn = FrpConn::new(work, link.wire);
        udp_conn.set_udp_codec(link.udp_binary.load(std::sync::atomic::Ordering::Relaxed));
        return udp_proxy::run(
            udp_conn,
            proxy.local_addr.clone(),
            proxy_name.to_string(),
            nfrp_common::config::clamp_udp_packet_size(link.cfg.udp_packet_size),
        )
        .await;
    }

    // 插件：工作连接直接接到插件上，不再连内网服务
    if let Some(built) = plugin::Plugin::from_proxy(&proxy) {
        let plug = built.with_context(|| format!("代理 [{}] 的插件配置有误", proxy.name))?;
        debug!(proxy = %start.proxy_name, "工作连接交给插件处理");
        // 真实客户端地址来自服务端下发的 `src_addr/src_port`：只有它能写进
        // `X-Forwarded-For`（工作连接的对端是 frps 自己，那是 `127.0.0.1`）。
        let src = if start.src_addr.is_empty() || start.src_port == 0 {
            None
        } else {
            util::resolve_addr(&format!("{}:{}", start.src_addr, start.src_port))
                .await
                .ok()
        };
        let ctx = plugin::Ctx {
            proxy_name: &start.proxy_name,
            src,
        };
        return plug.serve(work, leftover, &ctx).await;
    }

    let local_addr = &proxy.local_addr;
    let local = util::resolve_addr(local_addr)
        .await
        .with_context(|| format!("解析内网地址 {local_addr} 失败"))?;
    let mut local_stream = TcpStream::connect(local)
        .await
        .with_context(|| format!("连接内网服务 {local} 失败"))?;
    local_stream.set_nodelay(true).ok();

    debug!(proxy = %start.proxy_name, %local, "工作连接已建立，开始转发");

    // ---- PROXY 协议：把真实客户端地址告诉内网服务 ----
    //
    // 不加这一段，后端看到的对端永远是从 frpc 自己发起的连接，来源地址变成
    // `127.0.0.1` —— 于是所有按 IP 做的限流 / 审计 / 风控全部失效。
    //
    // 头**写在内网服务这一侧**（顺序：先 PROXY 头，再真实业务数据），
    // 与官方 frpc 的 `HandleTCPWorkConnection` 完全一致：
    //
    // ```go
    // if baseCfg.Transport.ProxyProtocolVersion != "" && m.SrcAddr != "" && m.SrcPort != 0 {
    //     header := netpkg.BuildProxyProtocolHeaderStruct(connInfo.SrcAddr, connInfo.DstAddr, ...)
    // }
    // ...
    // if connInfo.ProxyProtocolHeader != nil {
    //     connInfo.ProxyProtocolHeader.WriteTo(localConn)
    // }
    // ```
    //
    // dst 的取值也照抄官方：`StartWorkConn.dst_addr` 为空时**回落 `127.0.0.1`**
    // （`if m.DstAddr == "" { m.DstAddr = "127.0.0.1" }`）。别自作聪明改用
    // `local_addr` 里的主机名 —— 官方就是回落到回环地址，后端收到的目的地址
    // 与真 frpc 不一致，会让"和官方行为对拍"这件事失去意义。
    if let Some(ver) = proxy.proxy_protocol_version() {
        if start.src_addr.is_empty() || start.src_port == 0 {
            debug!(
                proxy = %start.proxy_name,
                "服务端没下发来源地址（官方 frps 才有），PROXY 头跳过"
            );
        } else {
            let dst_ip = if start.dst_addr.trim().is_empty() {
                "127.0.0.1".to_string()
            } else {
                start.dst_addr.clone()
            };
            let src = util::resolve_addr(&format!("{}:{}", start.src_addr, start.src_port))
                .await
                .with_context(|| format!("解析 PROXY 头源地址 {} 失败", start.src_addr))?;
            let dst = util::resolve_addr(&format!("{}:{}", dst_ip, start.dst_port))
                .await
                .with_context(|| format!("解析 PROXY 头目的地址 {dst_ip} 失败"))?;
            let head = proxy_protocol::encode(&src, &dst, ver)
                .with_context(|| format!("生成 PROXY {ver} 头失败"))?;
            local_stream
                .write_all(&head)
                .await
                .context("向内网服务写 PROXY 头失败")?;
            debug!(
                proxy = %start.proxy_name,
                version = ver,
                %src,
                %dst,
                "已向内网服务发送 PROXY 协议头"
            );
        }
    }

    // 加密/压缩时 leftover 必须进 ProxyStream，不能直接写给内网服务！
    //
    // leftover 是读 StartWorkConn 时多读到的字节，它属于 **frps → frpc** 方向。
    // 明文时它就是用户请求的开头，直接写给内网服务是对的；
    // **但开了加密/压缩时它是密文/压缩流的前缀**，直接写会把内网服务
    // 破坏成倒时间头（实测：本地 HTTP 服务报 "Exception occurred during
    // processing of request"，然后不返回响应，客户端看到的就是超时）。
    //
    // 正确做法：把 leftover 当作 work 流的**前缀**，先拼回去，再包 ProxyStream。
    let need_wrap_early = proxy.use_encryption
        || link.cfg.use_encryption
        || proxy.use_compression
        || link.cfg.use_compression;
    if !leftover.is_empty() && !need_wrap_early {
        local_stream.write_all(&leftover).await?;
    }
    let work: nfrp_common::frp::stream::BoxStream = if need_wrap_early {
        Box::pin(nfrp_common::frp::stream::PrefixedStream::new(
            leftover, work,
        ))
    } else {
        work
    };
    let mut work = work;

    // 带宽限流：配了就按令牌桶限速，没配就走原路径（行为完全不变）
    let limit = throttle::parse_bandwidth(&proxy.bandwidth_limit).unwrap_or(0);

    // 数据面加密 / 压缩（官方 transport.useEncryption / useCompression）
    //
    // 位置很关键：包在**工作连接**这一侧（`work` = 到 frps 的那条连接），
    // 内网服务那一侧（`local_stream`）保持明文 —— 与官方 `GetRealConn` 的
    // 包装方向一致。
    //
    // 不配时**一个字节都不多走**：`need_wrap` 为假直接走原路径，
    // 行为与之前完全一致。
    // 官方语义：客户端级 `[transport]` 开关 + NFRP 的代理级开关，取或。
    let eff_enc = proxy.use_encryption || link.cfg.use_encryption;
    let eff_comp = proxy.use_compression || link.cfg.use_compression;
    if eff_enc || eff_comp {
        let key = eff_enc.then(|| nfrp_common::frp::v1::derive_key(link.cfg.token.as_bytes()));
        debug!(
            proxy = %start.proxy_name,
            enc = eff_enc,
            comp = eff_comp,
            "数据面已启用加密/压缩"
        );
        let wrapped = nfrp_common::frp::proxy_stream::ProxyStream::new(work, key, eff_comp);
        // relay_throttled 按值接收并要求 'static，所以这里把 wrapped 交出去
        let r = if limit > 0 {
            throttle::relay_throttled(wrapped, local_stream, limit, limit).await
        } else {
            let mut w = wrapped;
            util::relay_between(&mut w, &mut local_stream).await
        };
        if let Err(e) = r {
            debug!(proxy = %start.proxy_name, "转发中断：{e}");
        }
        return Ok(());
    }

    let r = if limit > 0 {
        debug!(proxy = %start.proxy_name, limit, "按 {} 字节/秒限速", limit);
        throttle::relay_throttled(work, local_stream, limit, limit).await
    } else {
        util::relay_between(&mut work, &mut local_stream).await
    };
    if let Err(e) = r {
        debug!(proxy = %start.proxy_name, "转发中断：{e}");
    }
    Ok(())
}
