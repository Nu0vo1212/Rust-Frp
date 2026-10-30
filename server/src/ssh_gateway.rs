//! 官方 frps 的 `[sshTunnelGateway]` 兼容层。
//!
//! # 它到底是什么
//!
//! 不是"SSH 跳板机"，而是**把一条 SSH 连接当成一个虚拟 frpc**：
//!
//! ```text
//! ssh -R 7000:127.0.0.1:22 v0@frps -p 2200 tcp --remote_port 7000
//! ```
//!
//! * OpenSSH 先发 `tcpip-forward`（“我要在 7000 上收连接”）；
//! * 再开一个 session channel，用 `exec` 把 `tcp --remote_port 7000` 交给网关；
//! * 网关把它注册成 `tcp` 代理（和普通 frpc 的 `NewProxy` 等价）；
//! * 有用户访问 7000 时，网关通过 SSH 的 `forwarded-tcpip` 反向开一条
//!   channel，这条 channel 就是 frp 的“工作连接”，直接和用户连接对接。
//!
//! 因此数据面完全复用现有的 [`crate::serve::spawn_bridge`]，不需要另写转发。
//!
//! # 支持范围
//!
//! 与官方 `pkg/ssh/server.go` 一致：`tcp` / `http` / `https` / `tcpmux` / `stcp`。
//! 不支持 `udp` / `xtcp` / `sudp`（官方也不支持）。
//!
//! # 认证
//!
//! * `authorizedKeysFile` 为空 ⇒ 不校验 SSH 公钥；此时官方要求虚拟客户端
//!   再用 `--token` 过 frps 的 token 认证，这里同样执行一次
//!   [`crate::guard::SecurityContext::verify_login`]。
//! * 非空 ⇒ 只接受文件里的公钥；**公钥注释就是 frp 用户名**（官方语义）。
//!
//! SSH 层只做“是不是我们的钥匙”，RBAC / ACL / 端口白名单在注册代理时仍走
//! 服务端现有检查，SSH 网关不会成为绕过这些控制的侧门。

use std::{
    collections::HashMap,
    net::SocketAddr,
    path::PathBuf,
    sync::{Arc, Mutex},
    time::Duration,
};

use anyhow::{anyhow, bail, Context as _, Result};
use nfrp_common::{
    config::ServerConfig,
    frp::{msg::Login, msg::NewProxy, BoxStream, FrpConn, WireVersion},
    plugin, util,
};
use russh::server::{PublicKeyOffer, VerifiedPublicKey};
use russh::{
    keys::{ssh_key::LineEnding, Algorithm, PrivateKey, PublicKey},
    server::{Auth, Handler, Msg, Server, Session},
    Channel, ChannelId,
};
use tokio::{
    net::TcpListener,
    sync::{mpsc, watch},
};
use tracing::{debug, info, warn};

use crate::{
    guard::SecurityContext,
    pool::{ClientState, CtrlCmd, WorkItem},
    registry::Registry,
    serve::{register_proxy, spawn_bridge},
};

const SUPPORTED_TYPES: &[&str] = &["tcp", "http", "https", "tcpmux", "stcp"];

/// 启动前校验。`--check` 与真正启动共用，避免“预检绿灯、启动才炸”。
pub fn validate_config(cfg: &ServerConfig) -> Result<()> {
    let g = &cfg.ssh_tunnel_gateway;
    if !g.enabled() {
        return Ok(());
    }
    if g.bind_port == cfg.frp_bind_port() {
        bail!(
            "sshTunnelGateway.bindPort 不能与 bindPort 相同（都是 {}）",
            g.bind_port
        );
    }
    if !g.authorized_keys_file.trim().is_empty() {
        let keys = AuthorizedKeys::load(&g.authorized_keys_file)?;
        if keys.is_empty() {
            bail!(
                "sshTunnelGateway.authorizedKeysFile = {:?} 里没有任何公钥；\
                 如果确实想关闭 SSH 公钥认证，请把该字段留空并依靠 --token",
                g.authorized_keys_file
            );
        }
    }
    if !g.private_key_file.trim().is_empty() {
        russh::keys::load_secret_key(&g.private_key_file, None).with_context(|| {
            format!(
                "读取 sshTunnelGateway.privateKeyFile = {:?} 失败",
                g.private_key_file
            )
        })?;
    }
    // 自动生成路径的父目录必须存在：真正启动时会在那里写私钥。
    let auto = effective_auto_key_path(g);
    if g.private_key_file.trim().is_empty() && !auto.as_os_str().is_empty() {
        if let Some(parent) = auto.parent() {
            if !parent.as_os_str().is_empty() && !parent.exists() {
                bail!(
                    "sshTunnelGateway.autoGenPrivateKeyPath 的父目录不存在：{}",
                    parent.display()
                );
            }
        }
    }
    Ok(())
}

fn effective_auto_key_path(g: &nfrp_common::config::SshTunnelGatewayConfig) -> PathBuf {
    if !g.auto_gen_private_key_path.trim().is_empty() {
        PathBuf::from(&g.auto_gen_private_key_path)
    } else {
        PathBuf::from("./.autogen_ssh_key")
    }
}

/// 启动监听。只有 `bindPort > 0` 时才会被调用。
pub async fn run(
    cfg: Arc<ServerConfig>,
    registry: Arc<Registry>,
    security: Arc<SecurityContext>,
    bind_addr: &str,
) -> Result<()> {
    let g = cfg.ssh_tunnel_gateway.clone();
    validate_config(&cfg)?;
    let host_key = load_or_generate_host_key(&g)?;
    let authorized = Arc::new(AuthorizedKeys::load(&g.authorized_keys_file)?);

    let addr = util::resolve_addr(&format!("{bind_addr}:{}", g.bind_port))
        .await
        .with_context(|| format!("解析 SSH 网关地址 {bind_addr}:{} 失败", g.bind_port))?;
    let listener = TcpListener::bind(addr)
        .await
        .with_context(|| format!("监听 SSH 网关 {addr} 失败（端口可能被占用）"))?;
    let local = listener.local_addr().unwrap_or(addr);
    info!(
        %local,
        auth = if authorized.is_empty() { "token" } else { "authorized_keys" },
        "SSH 隧道网关已监听（官方 [sshTunnelGateway]）"
    );

    let config = Arc::new(russh::server::Config {
        keys: vec![host_key],
        auth_rejection_time: Duration::from_millis(300),
        auth_rejection_time_initial: Some(Duration::from_millis(0)),
        inactivity_timeout: Some(Duration::from_secs(60 * 60 * 24)),
        ..Default::default()
    });
    let mut server = GatewayServer {
        cfg,
        registry,
        security,
        authorized,
    };
    // 绑定已经成功才返回；这样“端口被占用”会在启动阶段直接报出来，
    // 而不是在后台任务里悄悄失败、面板看起来一切正常。
    tokio::spawn(async move {
        if let Err(e) = server.run_on_socket(config, &listener).await {
            warn!("SSH 网关监听循环退出：{e}");
        }
    });
    Ok(())
}

struct GatewayServer {
    cfg: Arc<ServerConfig>,
    registry: Arc<Registry>,
    security: Arc<SecurityContext>,
    authorized: Arc<AuthorizedKeys>,
}

impl Server for GatewayServer {
    type Handler = GatewayHandler;

    fn new_client(&mut self, peer: Option<SocketAddr>) -> Self::Handler {
        GatewayHandler {
            cfg: self.cfg.clone(),
            registry: self.registry.clone(),
            security: self.security.clone(),
            authorized: self.authorized.clone(),
            peer,
            key_user: String::new(),
            forward: Arc::new(Mutex::new(None)),
            cancel: watch::channel(false).0,
            first_channel: None,
        }
    }
}

struct GatewayHandler {
    cfg: Arc<ServerConfig>,
    registry: Arc<Registry>,
    security: Arc<SecurityContext>,
    authorized: Arc<AuthorizedKeys>,
    peer: Option<SocketAddr>,
    /// authorized_keys 里公钥后面的注释（官方用它当 frp 用户名）。
    key_user: String,
    /// OpenSSH 的 `tcpip-forward` 请求：反向 channel 要按这个地址开。
    forward: Arc<Mutex<Option<(String, u32)>>>,
    /// SSH 会话结束时通知隧道任务退出。
    cancel: watch::Sender<bool>,
    first_channel: Option<Channel<Msg>>,
}

impl Drop for GatewayHandler {
    fn drop(&mut self) {
        let _ = self.cancel.send(true);
    }
}

impl Handler for GatewayHandler {
    type Error = anyhow::Error;

    async fn auth_none(&mut self, _user: &str) -> Result<Auth> {
        // 官方：authorizedKeysFile 为空时 NoClientAuth = true。
        if self.authorized.is_empty() {
            Ok(Auth::Accept)
        } else {
            Ok(Auth::reject())
        }
    }

    async fn auth_publickey_offered(
        &mut self,
        _user: &str,
        offer: PublicKeyOffer<'_>,
    ) -> Result<Auth> {
        // russh 0.65：offered 阶段拿到的是 PublicKeyOffer，公钥在 .public_key 上
        let key = offer.public_key;
        if self.authorized.is_empty() || self.authorized.user_for(key).is_some() {
            Ok(Auth::Accept)
        } else {
            Ok(Auth::reject())
        }
    }

    async fn auth_publickey(&mut self, _user: &str, key: VerifiedPublicKey<'_>) -> Result<Auth> {
        // russh 0.65：验证通过后给的是 VerifiedPublicKey，公钥在 .public_key 上
        let key = key.public_key;
        if self.authorized.is_empty() {
            return Ok(Auth::Accept);
        }
        if let Some(user) = self.authorized.user_for(key) {
            self.key_user = user;
            Ok(Auth::Accept)
        } else {
            Ok(Auth::reject())
        }
    }

    async fn channel_open_session(
        &mut self,
        channel: Channel<Msg>,
        reply: russh::server::ChannelOpenHandle,
        _session: &mut Session,
    ) -> Result<()> {
        if self.first_channel.is_some() {
            // 官方只处理第一条 session channel。
            // russh 0.65 用「不 accept」表示拒绝（旧版是 return Ok(false)）。
            reply
                .reject(russh::ChannelOpenFailure::AdministrativelyProhibited)
                .await;
            return Ok(());
        }
        // russh 0.65：接受 channel 要显式 reply.accept()
        reply.accept().await;
        self.first_channel = Some(channel);
        Ok(())
    }

    async fn exec_request(
        &mut self,
        channel: ChannelId,
        data: &[u8],
        session: &mut Session,
    ) -> Result<()> {
        let command = String::from_utf8_lossy(data).trim().to_string();
        let Some(ch) = self.first_channel.take() else {
            return Ok(());
        };
        let _ = session.channel_success(channel);

        let cfg = self.cfg.clone();
        let registry = self.registry.clone();
        let security = self.security.clone();
        let forward = self.forward.clone();
        let mut cancel = self.cancel.subscribe();
        let key_user = self.key_user.clone();
        let peer = self.peer;
        let require_token = self.authorized.is_empty();
        let handle = session.handle();

        tokio::spawn(async move {
            let err_handle = handle.clone();
            let result = run_tunnel(
                cfg,
                registry,
                security,
                handle,
                forward,
                &mut cancel,
                key_user,
                require_token,
                peer,
                &command,
            )
            .await;
            if let Err(e) = result {
                let text = format!("{e:#}\n");
                let _ = ch.data(text.as_bytes()).await;
                let _ = ch.eof().await;
                // 配置/认证错误不是“隧道已建立”，必须主动断开；否则
                // OpenSSH 会一直挂着等一个永远不会来的 EOF（实测如此）。
                let _ = err_handle
                    .disconnect(
                        russh::Disconnect::ByApplication,
                        "ssh tunnel setup failed".to_string(),
                        String::new(),
                    )
                    .await;
            } else {
                let _ = ch.eof().await;
            }
        });
        Ok(())
    }

    async fn tcpip_forward(
        &mut self,
        address: &str,
        port: &mut u32,
        _session: &mut Session,
    ) -> Result<bool> {
        if *port == 0 || *port > u16::MAX as u32 {
            return Ok(false);
        }
        *self.forward.lock().unwrap_or_else(|e| e.into_inner()) =
            Some((address.to_string(), *port));
        Ok(true)
    }

    async fn cancel_tcpip_forward(
        &mut self,
        _address: &str,
        _port: u32,
        _session: &mut Session,
    ) -> Result<bool> {
        *self.forward.lock().unwrap_or_else(|e| e.into_inner()) = None;
        Ok(true)
    }
}

#[allow(clippy::too_many_arguments)]
async fn run_tunnel(
    cfg: Arc<ServerConfig>,
    registry: Arc<Registry>,
    security: Arc<SecurityContext>,
    handle: russh::server::Handle,
    forward: Arc<Mutex<Option<(String, u32)>>>,
    cancel: &mut watch::Receiver<bool>,
    key_user: String,
    require_token: bool,
    peer: Option<SocketAddr>,
    command: &str,
) -> Result<()> {
    if command.trim().is_empty() {
        bail!("缺少代理命令；示例：tcp --remote_port 7000");
    }
    let cmd = TunnelCmd::parse(command)?;
    let run_id = util::new_run_id();
    let user = if !key_user.trim().is_empty() {
        key_user.trim().to_string()
    } else {
        cmd.user.clone()
    };
    if user.trim().is_empty() && !cmd.token.trim().is_empty() {
        bail!("--token 已提供，但缺少 --user；请用 `-u <user>` 或 authorized_keys 注释指定用户");
    }

    // 没有 SSH 公钥认证时，官方要求虚拟客户端再走一次 frps token 认证。
    if security.role_for(&user).is_err() {
        bail!("用户 {user:?} 没有匹配的角色");
    }
    if let Some(addr) = peer {
        if let Err(e) = security.check_ip(addr.ip()) {
            bail!("SSH 网关来源 {addr} 被 ACL 拒绝：{e}");
        }
    }
    if require_token || !cmd.token.trim().is_empty() {
        // 公钥认证通过时官方不再验 token；只有 authorized_keys 为空才强制。
        // 但用户显式给了 --token 也校验一次，避免“token 写错却静默通过”。
        let ts = util::now_unix_secs() as i64;
        security
            .verify_login(&cmd.token, ts, &run_id)
            .map_err(|e| anyhow!("SSH 网关 token 认证失败：{e}"))?;
    }

    // 虚拟客户端：和普通 frpc 共用 ClientState，工作连接由 SSH channel 提供。
    let (req_tx, mut req_rx) = mpsc::unbounded_channel();
    let limits = registry.limits().clone();
    let (conn_limit, backlog_limit, proxy_limit) = limits.per_client();
    let peer_ip = peer
        .map(|p| p.ip())
        .unwrap_or(std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST));
    let client = Arc::new(ClientState::new(
        run_id.clone(),
        format!("ssh-{run_id}"),
        user.clone(),
        req_tx,
        Duration::from_secs(cfg.work_conn_idle_timeout.clamp(60, 3600)),
        cfg.user_conn_timeout(),
        Default::default(),
        false,
        WireVersion::V1,
        conn_limit,
        backlog_limit,
        cfg.max_pool_count,
        proxy_limit,
        peer_ip,
    ));
    let role = security.role_for(&user)?;
    client.set_allow_manage(role.allow_manage);
    let _slot = registry
        .insert(client.clone())
        .ok_or_else(|| anyhow!("客户端数量已达上限，SSH 隧道被拒绝"))?;
    let mut cleanup = ClientCleanup {
        registry: registry.clone(),
        run_id: run_id.clone(),
        armed: true,
    };

    let name = cmd.proxy_name(&run_id);
    let mut m = cmd.to_new_proxy(&name);
    m.proxy_name = util::canonical_wire_name(&user, &m.proxy_name);

    // 与普通客户端一致：先过 HTTP 插件，再过 RBAC。
    if !registry.plugins().is_empty() {
        let plugins = registry.plugins();
        let user_info = plugin::user_info(
            &Login {
                user: user.clone(),
                ..Default::default()
            },
            &run_id,
        );
        let content = plugin::content_with_user(&m, user_info)?;
        let v = plugins
            .handle_mutable(plugin::OP_NEW_PROXY, content)
            .await
            .map_err(|e| anyhow!("HTTP 插件拒绝代理注册：{e}"))?;
        m = serde_json::from_value(v).context("插件返回的 NewProxy 内容无法解析")?;
        m.proxy_name = util::canonical_wire_name(&user, &m.proxy_name);
    }
    security.check_proxy(
        &role,
        &m.proxy_name,
        &m.proxy_type,
        m.remote_port,
        client.proxy_count(),
    )?;

    let outcome = register_proxy(&cfg, &registry, &client, &m).await?;
    // 普通 frpc 的 NewProxy 分支在 `register_proxy` 成功后自己加这两个指标；
    // SSH 网关走的是同一套 `register_proxy`，但绕过了那段分支。漏加会让
    // `proxies_active` 只在客户端断开时被 `Registry::remove()` 减一次，
    // 实际 e2e 表现是 3 条 SSH 代理全部断开后面板显示 **-3**。
    if !outcome.adopted {
        registry.metrics().proxies_total.inc();
        registry.metrics().proxies_active.inc();
    }
    let remote_addr = outcome.remote_addr;
    info!(
        run_id = %run_id,
        user = %user,
        proxy = %m.proxy_name,
        kind = %m.proxy_type,
        remote_addr = %remote_addr,
        "SSH 隧道代理已注册"
    );

    loop {
        tokio::select! {
            changed = cancel.changed() => {
                if changed.is_err() || *cancel.borrow() {
                    break;
                }
            }
            cmd = req_rx.recv() => {
                let Some(cmd) = cmd else { break };
                match cmd {
                    CtrlCmd::RequestWork => {
                        let Some((addr, port)) = forward
                            .lock()
                            .unwrap_or_else(|e| e.into_inner())
                            .clone()
                        else {
                            warn!(run_id = %run_id, "SSH 客户端没有先发 tcpip-forward，无法建立工作连接");
                            continue;
                        };
                        match handle
                            .channel_open_forwarded_tcpip(addr.clone(), port, addr, port)
                            .await
                        {
                            Ok(ch) => {
                                let stream = ssh_work_stream(ch);
                                let work = WorkItem::new(FrpConn::new(stream, WireVersion::V1));
                                if let Some(paired) = client.submit_work(work) {
                                    spawn_bridge(paired.user, paired.work, registry.clone());
                                }
                            }
                            Err(e) => {
                                warn!(run_id = %run_id, "SSH 打开 forwarded-tcpip 失败：{e}");
                            }
                        }
                    }
                    CtrlCmd::Send(_) | CtrlCmd::ServerCmd { .. } => {
                        debug!(run_id = %run_id, "SSH 虚拟客户端忽略面板管理命令");
                    }
                }
            }
        }
    }

    // 通知 CloseProxy 插件（失败不影响清理，官方同语义）。
    if !registry.plugins().is_empty() {
        let plugins = registry.plugins();
        let info = plugin::user_info(
            &Login {
                user: user.clone(),
                ..Default::default()
            },
            &run_id,
        );
        let content = plugin::content_with_user(
            &nfrp_common::frp::msg::CloseProxy {
                proxy_name: m.proxy_name.clone(),
            },
            info,
        )?;
        plugins.notify(plugin::OP_CLOSE_PROXY, content).await;
    }
    registry.remove(&run_id);
    cleanup.armed = false;
    Ok(())
}

/// 把一条 SSH `forwarded-tcpip` channel 变成 frps 眼里正常的“工作连接”。
///
/// # 为什么不能直接把 channel 交给 bridge
///
/// 普通 frpc 收到工作连接后，第一件事是读一条 `StartWorkConn` 帧，知道
/// 这条连接服务哪个代理，**然后**才把后面的裸字节接到本地服务。而
/// OpenSSH 的 `-R` 只会把 channel 原样转给本地端口 —— 它不懂 frp 帧。
/// 直接把 channel 交给 bridge，`StartWorkConn` 会被当成业务数据发给本地
/// HTTP 服务（实测返回 `501 Unsupported method ('s\0\0...')`）。
///
/// 所以这里用一对内存 duplex 模拟一个最小 frpc：
///
/// ```text
/// bridge -> 服务端 duplex -> [FrpConn 读 StartWorkConn] -> SSH channel -> 本地服务
/// ```
///
/// 读到 `StartWorkConn` 后两边都退化成裸字节，再做双向 relay。
fn ssh_work_stream(channel: Channel<Msg>) -> BoxStream {
    use nfrp_common::frp::msg::FrpMessage;

    let (server, client) = tokio::io::duplex(64 * 1024);
    tokio::spawn(async move {
        let mut frpc = FrpConn::new(Box::pin(client), WireVersion::V1);
        match frpc.recv_msg().await {
            Ok(Some(FrpMessage::StartWorkConn(_))) => {}
            Ok(Some(other)) => {
                debug!("SSH 工作连接首帧不是 StartWorkConn：{other:?}");
                return;
            }
            Ok(None) => return,
            Err(e) => {
                debug!("SSH 工作连接读取 StartWorkConn 失败：{e:#}");
                return;
            }
        }
        let (mut frpc_stream, leftover) = frpc.into_stream();
        let mut ssh_stream = channel.into_stream();
        if !leftover.is_empty() {
            use tokio::io::AsyncWriteExt;
            if let Err(e) = ssh_stream.write_all(&leftover).await {
                debug!("SSH 工作连接写 leftover 失败：{e}");
                return;
            }
        }
        if let Err(e) = nfrp_common::util::relay_between(&mut ssh_stream, &mut frpc_stream).await {
            debug!("SSH 工作连接 relay 结束：{e}");
        }
    });
    Box::pin(server)
}

/// 保证任何提前返回（插件拒绝、注册失败、任务 panic 前）都把虚拟客户端
/// 从 Registry 里摘掉；否则面板会留下一个永远在线的“幽灵客户端”，
/// 它占的端口/域名也不会释放。
struct ClientCleanup {
    registry: Arc<Registry>,
    run_id: String,
    armed: bool,
}

impl Drop for ClientCleanup {
    fn drop(&mut self) {
        if self.armed {
            self.registry.remove(&self.run_id);
        }
    }
}

// ---------------------------------------------------------------------------
// authorized_keys
// ---------------------------------------------------------------------------

struct AuthorizedKeys {
    /// 公钥 wire bytes -> 注释（frp 用户名）。
    keys: HashMap<Vec<u8>, String>,
}

impl AuthorizedKeys {
    fn load(path: &str) -> Result<Self> {
        if path.trim().is_empty() {
            return Ok(Self {
                keys: HashMap::new(),
            });
        }
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("读取 authorizedKeysFile = {path:?} 失败"))?;
        let mut keys = HashMap::new();
        for (lineno, line) in text.lines().enumerate() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            // 跳过 authorized_keys 的可选前缀（command="..."、from="..." 等）。
            let Some(pos) = find_key_start(line) else {
                bail!(
                    "authorizedKeysFile 第 {} 行不是可识别的 SSH 公钥：{}",
                    lineno + 1,
                    line
                );
            };
            let parsed = PublicKey::from_openssh(&line[pos..]).with_context(|| {
                format!("authorizedKeysFile 第 {} 行的公钥无法解析", lineno + 1)
            })?;
            let bytes = parsed.to_bytes().context("authorized key 编码失败")?;
            // russh 0.65：comment() 返回 ssh_key 的 Comment，用 as_str() 取原文
            // russh 0.65：comment() 返回 ssh_key 的 Comment，as_str() 是 Result（非 UTF-8 会报错）。
            // 注释就是 frp 用户名，解不出就当空处理，不让整个 keys 文件失效。
            let comment = parsed.comment().as_str().unwrap_or("").trim().to_string();
            keys.insert(bytes, comment);
        }
        Ok(Self { keys })
    }

    fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }

    fn user_for(&self, key: &PublicKey) -> Option<String> {
        let bytes = key.to_bytes().ok()?;
        self.keys.get(&bytes).cloned()
    }
}

fn find_key_start(line: &str) -> Option<usize> {
    const PREFIXES: &[&str] = &[
        "ssh-ed25519 ",
        "ssh-rsa ",
        "ssh-dss ",
        "ecdsa-sha2-",
        "sk-ssh-ed25519@openssh.com ",
        "sk-ecdsa-sha2-nistp256@openssh.com ",
    ];
    PREFIXES.iter().filter_map(|p| line.find(p)).min()
}

// ---------------------------------------------------------------------------
// 命令解析
// ---------------------------------------------------------------------------

#[derive(Debug, Default)]
struct TunnelCmd {
    proxy_type: String,
    proxy_name: String,
    remote_port: u16,
    custom_domains: Vec<String>,
    subdomain: String,
    locations: Vec<String>,
    http_user: String,
    http_pwd: String,
    host_header_rewrite: String,
    multiplexer: String,
    sk: String,
    allow_users: Vec<String>,
    user: String,
    token: String,
}

impl TunnelCmd {
    fn parse(raw: &str) -> Result<Self> {
        let tokens = tokenize(raw)?;
        if tokens.is_empty() {
            bail!("缺少代理类型");
        }
        let proxy_type = tokens[0].trim().to_ascii_lowercase();
        if !SUPPORTED_TYPES.contains(&proxy_type.as_str()) {
            bail!(
                "不支持的 SSH 代理类型 {proxy_type:?}；支持：{}",
                SUPPORTED_TYPES.join(" / ")
            );
        }
        let mut cmd = Self {
            proxy_type,
            ..Default::default()
        };
        let mut i = 1;
        while i < tokens.len() {
            let tok = &tokens[i];
            let (key, inline) = match tok.split_once('=') {
                Some((k, v)) if k.starts_with('-') => (k.to_string(), Some(v.to_string())),
                _ => (tok.clone(), None),
            };
            let normalized = normalize_flag(&key);
            let value = |i: &mut usize| -> Result<String> {
                if let Some(v) = inline.clone() {
                    return Ok(v);
                }
                *i += 1;
                tokens
                    .get(*i)
                    .cloned()
                    .ok_or_else(|| anyhow!("参数 {key} 缺少取值"))
            };
            match normalized.as_str() {
                "proxy_name" | "name" => cmd.proxy_name = value(&mut i)?,
                "remote_port" => {
                    let v = value(&mut i)?;
                    cmd.remote_port = v
                        .parse::<u16>()
                        .with_context(|| format!("remote_port 不是合法端口：{v}"))?;
                }
                "custom_domain" | "custom_domains" => {
                    cmd.custom_domains.extend(split_csv(&value(&mut i)?))
                }
                "sd" | "subdomain" => cmd.subdomain = value(&mut i)?,
                "locations" => cmd.locations.extend(split_csv(&value(&mut i)?)),
                "http_user" => cmd.http_user = value(&mut i)?,
                "http_pwd" | "http_password" => cmd.http_pwd = value(&mut i)?,
                "host_header_rewrite" => cmd.host_header_rewrite = value(&mut i)?,
                "mux" | "multiplexer" => cmd.multiplexer = value(&mut i)?,
                "sk" | "secret_key" => cmd.sk = value(&mut i)?,
                "allow_users" => cmd.allow_users.extend(split_csv(&value(&mut i)?)),
                "user" => cmd.user = value(&mut i)?,
                "token" => cmd.token = value(&mut i)?,
                "h" | "help" => {
                    bail!("SSH 隧道命令帮助：tcp --remote_port <port> [--proxy_name <name>]")
                }
                other => bail!("未知参数 {other:?}（SSH 隧道只支持代理配置参数）"),
            }
            i += 1;
        }
        cmd.validate()?;
        Ok(cmd)
    }

    fn validate(&self) -> Result<()> {
        match self.proxy_type.as_str() {
            "tcp" if self.remote_port == 0 => {
                bail!("tcp 代理必须指定 --remote_port")
            }
            "http" | "https" | "tcpmux"
                if self.custom_domains.is_empty() && self.subdomain.trim().is_empty() =>
            {
                bail!("{} 代理必须指定 --custom_domain 或 --sd", self.proxy_type)
            }
            "stcp" if self.sk.trim().is_empty() => {
                bail!("stcp 代理必须指定 --sk（secret key）")
            }
            _ => {}
        }
        Ok(())
    }

    fn proxy_name(&self, run_id: &str) -> String {
        if !self.proxy_name.trim().is_empty() {
            return self.proxy_name.trim().to_string();
        }
        let suffix = run_id.rsplit('_').next().unwrap_or(run_id);
        let short = &suffix[..suffix.len().min(8)];
        format!("sshtunnel-{}-{short}", self.proxy_type)
    }

    fn to_new_proxy(&self, name: &str) -> NewProxy {
        NewProxy {
            proxy_name: name.to_string(),
            proxy_type: self.proxy_type.clone(),
            remote_port: self.remote_port,
            custom_domains: self.custom_domains.clone(),
            subdomain: self.subdomain.clone(),
            locations: self.locations.clone(),
            http_user: self.http_user.clone(),
            http_pwd: self.http_pwd.clone(),
            host_header_rewrite: self.host_header_rewrite.clone(),
            multiplexer: if self.proxy_type == "tcpmux" {
                if self.multiplexer.trim().is_empty() {
                    "httpconnect".to_string()
                } else {
                    self.multiplexer.clone()
                }
            } else {
                self.multiplexer.clone()
            },
            sk: self.sk.clone(),
            allow_users: self.allow_users.clone(),
            ..Default::default()
        }
    }
}

fn normalize_flag(flag: &str) -> String {
    let f = flag.trim();
    let f = f.strip_prefix("--").unwrap_or(f);
    let f = f.strip_prefix('-').unwrap_or(f);
    let f = f.replace('-', "_").to_ascii_lowercase();
    // 官方 cobra 注册的短选项（SSH 模式）：
    // -n proxy_name / -r remote_port / -u user / -t token / -d custom_domain
    match f.as_str() {
        "n" => "proxy_name".to_string(),
        "r" => "remote_port".to_string(),
        "u" => "user".to_string(),
        "t" => "token".to_string(),
        "d" => "custom_domain".to_string(),
        _ => f,
    }
}

fn split_csv(v: &str) -> Vec<String> {
    v.split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(ToString::to_string)
        .collect()
}

/// 简易 shell 分词：支持单/双引号与反斜杠转义。
fn tokenize(raw: &str) -> Result<Vec<String>> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut quote: Option<char> = None;
    let mut escaped = false;
    for ch in raw.chars() {
        if escaped {
            cur.push(ch);
            escaped = false;
            continue;
        }
        match (quote, ch) {
            (_, '\\') => escaped = true,
            (Some(q), c) if c == q => quote = None,
            (Some(_), c) => cur.push(c),
            (None, '\'' | '"') => quote = Some(ch),
            (None, c) if c.is_whitespace() => {
                if !cur.is_empty() {
                    out.push(std::mem::take(&mut cur));
                }
            }
            (None, c) => cur.push(c),
        }
    }
    if quote.is_some() {
        bail!("命令里的引号没有闭合");
    }
    if escaped {
        cur.push('\\');
    }
    if !cur.is_empty() {
        out.push(cur);
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// 主机私钥
// ---------------------------------------------------------------------------

fn load_or_generate_host_key(
    g: &nfrp_common::config::SshTunnelGatewayConfig,
) -> Result<PrivateKey> {
    if !g.private_key_file.trim().is_empty() {
        return russh::keys::load_secret_key(&g.private_key_file, None).with_context(|| {
            format!(
                "读取 sshTunnelGateway.privateKeyFile = {:?} 失败",
                g.private_key_file
            )
        });
    }
    let path = effective_auto_key_path(g);
    if path.exists() {
        if let Ok(k) = russh::keys::load_secret_key(&path, None) {
            return Ok(k);
        }
        warn!(path = %path.display(), "自动生成的 SSH 主机私钥无法解析，将重新生成");
    }
    // 用 OS 熵源：`PrivateKey::random` 要求 `rand_core::CryptoRng`，
    // 而 `rand::thread_rng()`（ThreadRng）在新版 rand_core 下不再满足该 trait
    // （russh 0.60 升级后暴露）。生成主机私钥本来也该走 OS 随机源。
    let key = PrivateKey::random(&mut rand010::rng(), Algorithm::Ed25519)
        .context("生成 SSH 主机私钥失败")?;
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent).ok();
        }
    }
    key.write_openssh_file(&path, LineEnding::LF)
        .with_context(|| format!("写入自动生成的 SSH 主机私钥 {} 失败", path.display()))?;
    info!(path = %path.display(), "已生成 SSH 主机私钥");
    Ok(key)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn 命令行解析_tcp() {
        let c = TunnelCmd::parse("tcp --remote_port 7000 --proxy_name web -u alice").unwrap();
        assert_eq!(c.proxy_type, "tcp");
        assert_eq!(c.remote_port, 7000);
        assert_eq!(c.proxy_name, "web");
        assert_eq!(c.user, "alice");
        assert_eq!(c.to_new_proxy("web").remote_port, 7000);
    }

    #[test]
    fn 连字符参数名归一化() {
        let c = TunnelCmd::parse("http --custom-domain a.example.com --http-user u").unwrap();
        assert_eq!(c.custom_domains, vec!["a.example.com"]);
        assert_eq!(c.http_user, "u");
    }

    #[test]
    fn 引号与转义() {
        let toks = tokenize(r#"tcp --proxy_name "my proxy" --sd a"#).unwrap();
        assert_eq!(toks, vec!["tcp", "--proxy_name", "my proxy", "--sd", "a"]);
    }

    #[test]
    fn 必填项缺失会报错() {
        assert!(TunnelCmd::parse("tcp").is_err());
        assert!(TunnelCmd::parse("http").is_err());
        assert!(TunnelCmd::parse("stcp").is_err());
        assert!(TunnelCmd::parse("udp --remote_port 1").is_err());
    }

    #[test]
    fn 默认代理名稳定且带类型() {
        let c = TunnelCmd::parse("tcp -r 7000").unwrap();
        let n = c.proxy_name("run_0123456789abcdef");
        assert!(n.starts_with("sshtunnel-tcp-"), "{n}");
        assert_eq!(n, c.proxy_name("run_0123456789abcdef"));
    }

    #[test]
    fn 公钥前缀跳过_options() {
        // 只需要能找到 key 起点；不依赖真实密钥内容。
        let line = r#"command="/bin/false",no-pty ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAAA"#;
        let pos = find_key_start(line).unwrap();
        assert!(line[pos..].starts_with("ssh-ed25519 "));
    }

    #[test]
    fn authorized_keys_注释就是_frp_用户() {
        let key = PrivateKey::random(&mut rand010::rng(), Algorithm::Ed25519).unwrap();
        let other = PrivateKey::random(&mut rand010::rng(), Algorithm::Ed25519).unwrap();
        let line = format!(
            "command=\"/bin/false\",no-pty {} alice\n",
            key.public_key().to_openssh().unwrap()
        );
        let path = std::env::temp_dir().join(format!(
            "nfrp-authorized-{}-{}.txt",
            std::process::id(),
            rand::random::<u64>()
        ));
        std::fs::write(&path, line).unwrap();
        let keys = AuthorizedKeys::load(path.to_str().unwrap()).unwrap();
        let _ = std::fs::remove_file(&path);
        assert_eq!(keys.user_for(key.public_key()).as_deref(), Some("alice"));
        assert!(keys.user_for(other.public_key()).is_none());
    }

    #[test]
    fn 空_authorized_keys_文件表示关闭公钥认证() {
        let path = std::env::temp_dir().join(format!(
            "nfrp-authorized-empty-{}-{}.txt",
            std::process::id(),
            rand::random::<u64>()
        ));
        std::fs::write(&path, "# only a comment\n\n").unwrap();
        let keys = AuthorizedKeys::load(path.to_str().unwrap()).unwrap();
        let _ = std::fs::remove_file(&path);
        assert!(keys.is_empty());
    }
}
