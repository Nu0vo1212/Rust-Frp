//! 客户端本地管理界面（`[webServer]`）。
//!
//! # 与官方 frpc 的关系
//!
//! 官方 frpc 也有 `[webServer]`，但它**只能看和重载配置** —— 想加一条隧道
//! 仍然得回去改配置文件。这里多做了一步：可以直接增删代理，而且走的是和
//! "服务端面板下发的 `ServerCmd`"**同一条链路**（注册 `NewProxy` / 撤销
//! `CloseProxy`），所以两个入口的行为完全一致，不会出现"面板加得了、
//! 本地界面加不了"这种分裂。
//!
//! # 为什么写操作要排队
//!
//! 控制连接（[`FrpConn`]）是被会话主循环**独占**的：收发都在那一个 `select!`
//! 里。所以 Web 侧不能直接 `conn.send_msg(...)`，只能把请求塞进一条通道，
//! 由主循环取出来执行（见 [`handle_request`]）。
//!
//! 这不只是为了"避免数据竞争"，还为了**等 `NewProxyResp` 期间能顺手处理
//! `ReqWorkConn`**：服务端一边回注册结果、一边在要工作连接，如果这里只顾着
//! 等回应、不去建连接，服务端就会认为本端掉线，把刚注册的代理收回去。
//!
//! # 默认关闭
//!
//! `[webServer] port` 不写就是 0 —— 那时候整个模块**一行都不会执行**：
//! 没有监听端口，没有后台任务，与上一个版本完全一致。

use std::{
    net::SocketAddr,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use rustunnel_common::{
    config::{ClientConfig, ProxyConfig},
    frp::{
        conn::FrpConn,
        msg::{CloseProxy, FrpMessage, NewProxy},
    },
    http1, util,
};
use tokio::{
    net::{TcpListener, TcpStream},
    sync::{mpsc, oneshot},
};
use tracing::{debug, info, warn};

use crate::{health, registry::ProxyTable, store::Store, ClientSession, ServerLink};

/// 等 `NewProxyResp` 的最长时间。
const REGISTER_TIMEOUT: Duration = Duration::from_secs(15);

/// Web 侧等主循环完成一次写操作的最长时间。
///
/// 比 [`REGISTER_TIMEOUT`] 长一点：多出来的时间是留给"请求在主循环里排队"的
/// —— 比如主循环此刻正在处理服务端下发的 `ServerCmd`。
const REQUEST_TIMEOUT: Duration = Duration::from_secs(20);

/// 健康检查路径（免鉴权）。
pub const HEALTHZ_PATH: &str = "/api/healthz";

/// 一次写操作的回执。
pub type Reply = oneshot::Sender<Result<String, String>>;

/// 交给会话主循环执行的写操作。
pub enum Request {
    /// 新增代理并注册到服务端。
    AddProxy {
        proxy: Box<ProxyConfig>,
        reply: Reply,
    },
    /// 移除代理并通知服务端。
    RemoveProxy { name: String, reply: Reply },
}

/// 会话守卫：会话一结束就把请求通道摘掉。
///
/// 用 `Drop` 而不是在函数末尾手写一句 `detach` —— 会话里有好几处提前
/// `?` 返回，手写的话迟早漏掉一条，而漏掉的后果是"重连期间界面上的操作
/// 全部卡 20 秒然后超时"，很难联想到是这个原因。
pub struct SessionGuard(Arc<Hub>);

impl SessionGuard {
    pub fn new(hub: Arc<Hub>, tx: mpsc::UnboundedSender<Request>) -> Self {
        hub.attach_session(tx);
        Self(hub)
    }
}

impl Drop for SessionGuard {
    fn drop(&mut self) {
        self.0.detach_session();
    }
}

/// Web 界面的共享状态。
pub struct Hub {
    cfg: Arc<ClientConfig>,
    proxies: ProxyTable,
    store: Arc<Store>,
    health: Arc<health::Monitor>,
    /// 当前会话（重连期间为 None）。
    session: tokio::sync::watch::Receiver<Option<Arc<ClientSession>>>,
    /// 与**当前**会话之间的写请求通道。会话重建时会被换掉。
    req_tx: Mutex<Option<mpsc::UnboundedSender<Request>>>,
}

impl Hub {
    pub fn new(
        cfg: Arc<ClientConfig>,
        proxies: ProxyTable,
        store: Arc<Store>,
        health: Arc<health::Monitor>,
        session: tokio::sync::watch::Receiver<Option<Arc<ClientSession>>>,
    ) -> Arc<Self> {
        Arc::new(Self {
            cfg,
            proxies,
            store,
            health,
            session,
            req_tx: Mutex::new(None),
        })
    }

    /// 会话建立时挂上请求通道。
    pub fn attach_session(&self, tx: mpsc::UnboundedSender<Request>) {
        *self.req_tx.lock().unwrap_or_else(|e| e.into_inner()) = Some(tx);
    }

    /// 会话结束时摘掉。
    ///
    /// 不摘的话，重连窗口期的请求会被投进一个**没有人读**的通道，
    /// 用户看到的是"卡 20 秒然后超时"，而不是立刻被告知"客户端没连上"。
    pub fn detach_session(&self) {
        *self.req_tx.lock().unwrap_or_else(|e| e.into_inner()) = None;
    }

    async fn ask<F>(&self, make: F) -> Result<String, String>
    where
        F: FnOnce(Reply) -> Request,
    {
        let (tx, rx) = oneshot::channel();
        let req = make(tx);
        let sender = self
            .req_tx
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone();
        let Some(sender) = sender else {
            return Err("客户端当前没有连上服务端（正在重连？），稍后再试".to_string());
        };
        if sender.send(req).is_err() {
            return Err("客户端会话已结束，请稍后再试".to_string());
        }
        match tokio::time::timeout(REQUEST_TIMEOUT, rx).await {
            Ok(Ok(r)) => r,
            Ok(Err(_)) => Err("会话在处理这条请求前断开了".to_string()),
            Err(_) => Err(format!("{} 秒内没有完成", REQUEST_TIMEOUT.as_secs())),
        }
    }

    async fn add(&self, body: &str) -> Result<String, String> {
        if body.trim().is_empty() {
            return Err("请求体不能为空（要一个 JSON 的代理配置）".to_string());
        }
        let p: ProxyConfig =
            serde_json::from_str(body).map_err(|e| format!("代理配置解析失败：{e}"))?;
        if p.name.trim().is_empty() {
            return Err("缺少 name".to_string());
        }
        if p.proxy_type.trim().is_empty() {
            return Err("缺少 type".to_string());
        }
        if self.proxies.get(&p.name).is_some() {
            return Err(format!("已存在同名代理 [{}]", p.name));
        }
        self.ask(|reply| Request::AddProxy {
            proxy: Box::new(p),
            reply,
        })
        .await
    }

    async fn remove(&self, body: &str) -> Result<String, String> {
        let name = proxy_name_of(body)?;
        if self.proxies.get(&name).is_none() {
            return Err(format!("本地没有代理 [{name}]"));
        }
        self.ask(|reply| Request::RemoveProxy { name, reply }).await
    }
}

/// 从请求体里取代理名。
///
/// 两种写法都收：`{"name":"web"}` 和裸的 `web`
/// —— `curl -d web` 比 `curl -d '{"name":"web"}'` 好敲得多。
fn proxy_name_of(body: &str) -> Result<String, String> {
    let t = body.trim();
    if t.is_empty() {
        return Err("请求体不能为空（代理名或 {\"name\":\"...\"}）".to_string());
    }
    if !t.starts_with('{') {
        return Ok(t.to_string());
    }
    let v: serde_json::Value =
        serde_json::from_str(t).map_err(|e| format!("请求体不是合法 JSON：{e}"))?;
    let n = v
        .get("name")
        .and_then(|x| x.as_str())
        .unwrap_or_default()
        .trim()
        .to_string();
    if n.is_empty() {
        return Err("缺少 name".to_string());
    }
    Ok(n)
}

/// 启动本地管理界面。
///
/// 调用方负责在 `[webServer] port != 0` 时才调用它 —— 函数本身不做判断，
/// 免得"要不要监听"这件事有两个地方各判一次。
pub async fn run(listener: TcpListener, hub: Arc<Hub>) {
    let addr = listener.local_addr().ok();
    info!(
        "客户端管理界面已启动：http://{}/  （/api/status 状态、/api/proxies 代理表）",
        addr.map(|a| a.to_string()).unwrap_or_default()
    );
    let user = hub.cfg.web_server.user.trim();
    if user.is_empty() {
        // 默认只监听回环地址；这句话是给"手滑改成 0.0.0.0 又没配密码"的人看的
        if !is_loopback_addr(&hub.cfg.web_server.addr) {
            warn!(
                addr = %hub.cfg.web_server.addr,
                "管理界面监听在非回环地址上却没有配置 user/password —— 任何能访问这个端口的人都能增删你的隧道。强烈建议配上凭证"
            );
        }
    } else {
        info!("管理界面已启用 Basic Auth（用户 {user}）");
    }

    loop {
        match listener.accept().await {
            Ok((stream, peer)) => {
                let hub = hub.clone();
                tokio::spawn(async move {
                    if let Err(e) = handle(stream, peer, hub).await {
                        debug!(%peer, "客户端管理界面连接结束：{e:#}");
                    }
                });
            }
            Err(e) => {
                warn!("客户端管理界面 accept 失败：{e}");
                tokio::time::sleep(Duration::from_millis(200)).await;
            }
        }
    }
}

fn is_loopback_addr(addr: &str) -> bool {
    let a = addr.trim();
    a == "127.0.0.1" || a == "localhost" || a == "::1"
}

async fn handle(mut stream: TcpStream, peer: SocketAddr, hub: Arc<Hub>) -> anyhow::Result<()> {
    let req = http1::read_request(&mut stream).await?;
    let path = req.path.as_str();
    let method = req.method.as_str();

    // 健康探针排在鉴权**之前**：容器探针不方便带凭据，
    // 而它只回一个 "ok"，泄露的信息量为零。
    if path == HEALTHZ_PATH {
        if method != "GET" && method != "HEAD" {
            http1::send_json(
                &mut stream,
                405,
                &err_body("method_not_allowed", "只支持 GET"),
            )
            .await?;
            return Ok(());
        }
        http1::send(&mut stream, 200, "text/plain; charset=utf-8", b"ok\n", &[]).await?;
        return Ok(());
    }

    if let Some(body) = auth_failure(&hub, &req) {
        http1::send(
            &mut stream,
            401,
            "application/json; charset=utf-8",
            body.as_bytes(),
            &[("WWW-Authenticate", "Basic realm=\"rustunnel-client\"")],
        )
        .await?;
        return Ok(());
    }

    let (code, ctype, body) = route(&hub, method, path, &req).await;
    http1::send(&mut stream, code, ctype, body.as_bytes(), &[]).await?;
    debug!(%peer, %method, %path, code, "客户端管理界面请求已处理");
    Ok(())
}

/// `Some(响应体)` 表示鉴权没过。
fn auth_failure(hub: &Hub, req: &http1::Request) -> Option<String> {
    let user = hub.cfg.web_server.user.trim();
    if user.is_empty() {
        return None;
    }
    let expected = format!("{}:{}", user, hub.cfg.web_server.password);
    match http1::basic_auth(req.authorization().as_deref()) {
        Some(g) if http1::constant_time_eq(&g, &expected) => None,
        _ => Some(err_body("unauthorized", "需要 Basic Auth 凭证")),
    }
}

const CT_JSON: &str = "application/json; charset=utf-8";
const CT_HTML: &str = "text/html; charset=utf-8";

async fn route(
    hub: &Arc<Hub>,
    method: &str,
    path: &str,
    req: &http1::Request,
) -> (u16, &'static str, String) {
    match (method, path) {
        ("GET", "/") | ("GET", "/index.html") => (200, CT_HTML, html_page()),
        ("GET", "/api/status") => (200, CT_JSON, status_json(hub)),
        ("GET", "/api/proxies") => (200, CT_JSON, proxies_json(hub)),
        ("POST", "/api/proxies/add") => match hub.add(&req.body).await {
            Ok(m) => (200, CT_JSON, ok_body(&m)),
            Err(e) => (400, CT_JSON, err_body("add_failed", &e)),
        },
        ("POST", "/api/proxies/remove") => match hub.remove(&req.body).await {
            Ok(m) => (200, CT_JSON, ok_body(&m)),
            Err(e) => (400, CT_JSON, err_body("remove_failed", &e)),
        },
        _ => {
            const KNOWN: &[&str] = &[
                "/",
                "/index.html",
                "/api/status",
                "/api/proxies",
                "/api/proxies/add",
                "/api/proxies/remove",
            ];
            if KNOWN.contains(&path) {
                (
                    405,
                    CT_JSON,
                    err_body("method_not_allowed", &format!("{path} 不支持 {method}")),
                )
            } else {
                (
                    404,
                    CT_JSON,
                    err_body("not_found", &format!("没有这个路径：{path}")),
                )
            }
        }
    }
}

// ---------------------------------------------------------------------------
// 会话侧：在主循环里执行写请求
// ---------------------------------------------------------------------------

/// 执行一条来自 Web 界面的写请求。
///
/// 由会话主循环调用 —— 它此刻**独占着控制连接**，所以能安全地发消息、
/// 并在等回应的同时处理 `ReqWorkConn`。
#[allow(clippy::too_many_arguments)]
pub async fn handle_request(
    req: Request,
    conn: &mut FrpConn,
    link: &Arc<ServerLink>,
    run_id: &Arc<String>,
    proxies: &ProxyTable,
    store: &Store,
    health: &Arc<health::Monitor>,
    cfg: &ClientConfig,
) {
    match req {
        Request::AddProxy { proxy, reply } => {
            let r = add_live(conn, link, run_id, proxies, store, health, cfg, *proxy).await;
            let _ = reply.send(r);
        }
        Request::RemoveProxy { name, reply } => {
            let r = remove_live(conn, proxies, store, cfg, &name).await;
            let _ = reply.send(r);
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn add_live(
    conn: &mut FrpConn,
    link: &Arc<ServerLink>,
    run_id: &Arc<String>,
    proxies: &ProxyTable,
    store: &Store,
    health: &Arc<health::Monitor>,
    cfg: &ClientConfig,
    p: ProxyConfig,
) -> Result<String, String> {
    if proxies.get(&p.name).is_some() {
        return Err(format!("已存在同名代理 [{}]", p.name));
    }
    let wire = NewProxy::from_config(&p, &cfg.user);

    // 本地表**先认下这条代理**。
    //
    // 顺序不能反：服务端随时可能为它发 `ReqWorkConn`，而工作连接要拿代理名
    // 查本地表，查不到就只能打一句"未知代理"然后把连接断掉 —— 用户看到的是
    // "添加成功但访问一直 503"。
    proxies.insert(p.clone());

    if let Err(e) = conn.send_msg(&FrpMessage::NewProxy(wire)).await {
        proxies.remove(&p.name);
        return Err(format!("向服务端发送 NewProxy 失败：{e:#}"));
    }

    let deadline = Instant::now() + REGISTER_TIMEOUT;
    loop {
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            proxies.remove(&p.name);
            return Err(format!(
                "{} 秒内没等到服务端的回应（已撤回本地改动）",
                REGISTER_TIMEOUT.as_secs()
            ));
        }
        let msg = match tokio::time::timeout(left, conn.recv_msg()).await {
            Err(_) => {
                proxies.remove(&p.name);
                return Err(format!(
                    "{} 秒内没等到服务端的回应（已撤回本地改动）",
                    REGISTER_TIMEOUT.as_secs()
                ));
            }
            Ok(Err(e)) => {
                proxies.remove(&p.name);
                return Err(format!("控制连接出错：{e:#}"));
            }
            Ok(Ok(None)) => {
                proxies.remove(&p.name);
                return Err("服务端关闭了控制连接".to_string());
            }
            Ok(Ok(Some(m))) => m,
        };

        match msg {
            FrpMessage::NewProxyResp(r) => {
                if !r.error.is_empty() {
                    proxies.remove(&p.name);
                    return Err(format!("服务端拒绝：{}", r.error));
                }
                // 落盘：重启后它还认得回来（没配 `[store] path` 时是空操作）
                if let Err(e) = store.put(&p) {
                    warn!(proxy = %p.name, error = %e, "写入 store 失败：重启后这条代理会丢失");
                }
                info!(proxy = %p.name, remote = %r.remote_addr, "管理界面新增代理成功");
                return Ok(format!("代理 [{}] 已生效：{}", p.name, r.remote_addr));
            }
            FrpMessage::ReqWorkConn => {
                // **必须处理**：服务端正在等工作连接，这里不去建，
                // 它就会认为本端掉线，把刚注册的代理收回去。
                crate::spawn_work_conn(
                    link.clone(),
                    run_id.clone(),
                    proxies.clone(),
                    health.clone(),
                );
            }
            FrpMessage::Pong(pong) => {
                if !pong.error.is_empty() {
                    warn!("服务端 Pong 返回错误：{}", pong.error);
                }
            }
            other => debug!("等待 NewProxyResp 期间收到 {}，忽略", other.name()),
        }
    }
}

async fn remove_live(
    conn: &mut FrpConn,
    proxies: &ProxyTable,
    store: &Store,
    cfg: &ClientConfig,
    name: &str,
) -> Result<String, String> {
    let Some(p) = proxies.remove(name) else {
        return Err(format!("本地没有代理 [{name}]"));
    };
    // 通知服务端把端口 / 域名收回去。用的是**线上全名**（带 `{user}.` 前缀）。
    let wire_name = util::add_user_prefix(&cfg.user, name);
    if let Err(e) = conn
        .send_msg(&FrpMessage::CloseProxy(CloseProxy {
            proxy_name: wire_name,
        }))
        .await
    {
        // 本地已经摘掉了，服务端那边最多多留一会儿；下次心跳复核也会清掉
        warn!(proxy = %name, error = %e, "通知服务端关闭代理失败（本地已移除）");
    }
    if let Err(e) = store.remove(name) {
        warn!(proxy = %name, error = %e, "从 store 删除失败（内存里已移除）");
    }
    info!(proxy = %name, r#type = %p.proxy_type, "管理界面移除代理");
    Ok(format!("代理 [{name}] 已移除"))
}

// ---------------------------------------------------------------------------
// 内容生成
// ---------------------------------------------------------------------------

fn ok_body(message: &str) -> String {
    serde_json::json!({ "data": { "message": message } }).to_string()
}

fn err_body(code: &str, message: &str) -> String {
    serde_json::json!({ "error": { "code": code, "message": message } }).to_string()
}

fn status_json(hub: &Arc<Hub>) -> String {
    let sess = hub.session.borrow().clone();
    let (connected, run_id, wire) = match &sess {
        Some(s) => (true, s.run_id.to_string(), s.link.wire.to_string()),
        None => (false, String::new(), String::new()),
    };
    let proxies: Vec<serde_json::Value> = hub
        .proxies
        .list()
        .iter()
        .map(|p| proxy_json(hub, p))
        .collect();
    serde_json::json!({
        "data": {
            "client_id": hub.cfg.client_id,
            "user": hub.cfg.user,
            "server": format!("{}:{}", hub.cfg.server_addr, hub.cfg.server_port),
            "connected": connected,
            "run_id": run_id,
            "wire_protocol": wire,
            "proxies": proxies,
            "visitor_count": hub.cfg.visitors.len(),
            "store": {
                "enabled": hub.store.is_enabled(),
                "path": hub
                    .store
                    .path()
                    .map(|p| p.display().to_string())
                    .unwrap_or_default(),
                "dynamic": hub.store.dynamic_names(),
            },
            "features": {
                "websocket": hub.cfg.websocket_enable,
                "virtual_net": hub.cfg.virtual_net.is_enabled(),
                "p2p": hub.cfg.p2p_port.is_some(),
            },
        }
    })
    .to_string()
}

fn proxies_json(hub: &Arc<Hub>) -> String {
    let dynamic = hub.store.dynamic_names();
    let items: Vec<serde_json::Value> = hub
        .proxies
        .list()
        .iter()
        .map(|p| {
            let mut v = proxy_json(hub, p);
            v["dynamic"] = serde_json::Value::Bool(dynamic.contains(&p.name));
            v
        })
        .collect();
    serde_json::json!({ "data": items }).to_string()
}

fn proxy_json(hub: &Hub, p: &ProxyConfig) -> serde_json::Value {
    serde_json::json!({
        "name": p.name,
        "type": p.proxy_type,
        "local_addr": p.local_addr,
        "remote_port": p.remote_port,
        "custom_domains": p.custom_domains,
        "healthy": hub.health.is_healthy(&p.name),
    })
}

fn html_page() -> String {
    r#"<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>rustunnel 客户端</title>
<style>
  :root { color-scheme: light; }
  body { margin:0; font:14px/1.6 system-ui,-apple-system,"Segoe UI",sans-serif;
         background:#f6f7f9; color:#1f2328; }
  header { background:#0f6e56; color:#fff; padding:14px 22px; font-size:16px; }
  main { max-width: 1000px; margin: 22px auto; padding: 0 18px; }
  .cards { display:grid; grid-template-columns:repeat(auto-fit,minmax(170px,1fr)); gap:12px; }
  .card { background:#fff; border:1px solid #d8dee4; border-radius:8px; padding:14px 16px; }
  .card .k { font-size:12px; color:#6e7781; }
  .card .v { font-size:18px; font-weight:600; margin-top:4px; word-break:break-all; }
  section { margin-top: 26px; }
  h2 { font-size:15px; margin:0 0 10px; padding-bottom:6px; border-bottom:1px solid #d8dee4; }
  table { width:100%; border-collapse:collapse; background:#fff;
          border:1px solid #d8dee4; border-radius:8px; overflow:hidden; }
  th,td { text-align:left; padding:8px 12px; border-bottom:1px solid #eaeef2; font-size:13px; }
  th { background:#f6f8fa; color:#57606a; font-weight:600; }
  tr:last-child td { border-bottom:none; }
  .empty { color:#6e7781; padding:12px; background:#fff; border:1px dashed #d8dee4; border-radius:8px; }
  .tag { display:inline-block; padding:1px 7px; border-radius:10px; font-size:11px; }
  .on { background:#e1f5ee; color:#0f6e56; }
  .off { background:#f1efe8; color:#5f5e5a; }
  .bad { background:#fcebeb; color:#a32d2d; }
  code { background:#eff1f3; padding:1px 5px; border-radius:4px; }
</style>
</head>
<body>
<header>rustunnel 客户端管理</header>
<main>
  <div class="cards" id="cards"></div>
  <section>
    <h2>代理</h2>
    <div id="proxies"></div>
  </section>
  <section>
    <h2>接口</h2>
    <div class="empty">
      <code>GET /api/status</code> 状态 ·
      <code>GET /api/proxies</code> 代理表 ·
      <code>POST /api/proxies/add</code> 新增（body 是代理的 JSON）·
      <code>POST /api/proxies/remove</code> 移除（body 是代理名）
    </div>
  </section>
</main>
<script>
function esc(s) {
  return String(s == null ? '' : s).replace(/[&<>"]/g, function (c) {
    return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c];
  });
}
function card(k, v) {
  return '<div class="card"><div class="k">' + esc(k) + '</div><div class="v">' + esc(v) + '</div></div>';
}
function refresh() {
  fetch('api/status').then(function (r) { return r.json(); }).then(function (res) {
    var d = res.data || {};
    document.getElementById('cards').innerHTML =
      card('连接状态', d.connected ? '已连接' : '未连接') +
      card('服务端', d.server) +
      card('线协议', d.wire_protocol || '-') +
      card('run_id', d.run_id || '-') +
      card('代理数', (d.proxies || []).length) +
      card('Store', d.store && d.store.enabled ? '已启用' : '未启用');
    var rows = (d.proxies || []).map(function (p) {
      var h = p.healthy === false
        ? '<span class="tag bad">不健康</span>'
        : '<span class="tag on">正常</span>';
      return '<tr><td>' + esc(p.name) + '</td><td>' + esc(p.type) + '</td><td>' +
        esc(p.local_addr) + '</td><td>' + esc(p.remote_port || '-') + '</td><td>' +
        esc((p.custom_domains || []).join(', ')) + '</td><td>' + h + '</td></tr>';
    }).join('');
    document.getElementById('proxies').innerHTML = rows
      ? '<table><tr><th>名字</th><th>类型</th><th>本地地址</th><th>远程端口</th><th>域名</th><th>健康</th></tr>' + rows + '</table>'
      : '<div class="empty">还没有代理</div>';
  }).catch(function (e) {
    document.getElementById('cards').innerHTML =
      '<div class="card"><div class="k">错误</div><div class="v">' + esc(e) + '</div></div>';
  });
}
refresh();
setInterval(refresh, 3000);
</script>
</body>
</html>
"#
    .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hub_with(proxies: ProxyTable) -> Arc<Hub> {
        let cfg = Arc::new(ClientConfig::default());
        let store = Arc::new(Store::from_config(&cfg).expect("默认配置不落盘"));
        let health = health::Monitor::start(&cfg);
        let (_tx, rx) = tokio::sync::watch::channel::<Option<Arc<ClientSession>>>(None);
        Hub::new(cfg, proxies, store, health, rx)
    }

    fn req(raw: &str) -> http1::Request {
        http1::parse_str(raw)
    }

    /// route 的三元组响应：`(状态码, content-type, body)`。
    type Resp = (u16, &'static str, String);

    fn body_of(r: &Resp) -> serde_json::Value {
        serde_json::from_str(&r.2).expect("响应必须是合法 JSON")
    }

    fn proxy(name: &str) -> ProxyConfig {
        ProxyConfig {
            name: name.into(),
            proxy_type: "tcp".into(),
            local_addr: "127.0.0.1:80".into(),
            remote_port: 7000,
            ..Default::default()
        }
    }

    #[test]
    fn 代理名两种写法都收() {
        assert_eq!(proxy_name_of("  web  ").unwrap(), "web");
        assert_eq!(proxy_name_of(r#"{"name":"web"}"#).unwrap(), "web");
        assert!(proxy_name_of("").is_err());
        assert!(proxy_name_of("   ").is_err());
        assert!(proxy_name_of(r#"{"nope":1}"#).is_err(), "缺 name 要报错");
        assert!(proxy_name_of("{不是 JSON").is_err());
    }

    /// `0.0.0.0` **不是**回环 —— 它恰恰是需要告警的那一种。
    #[test]
    fn 回环地址识别() {
        assert!(is_loopback_addr("127.0.0.1"));
        assert!(is_loopback_addr(" localhost "));
        assert!(is_loopback_addr("::1"));
        assert!(!is_loopback_addr("0.0.0.0"));
        assert!(!is_loopback_addr("192.168.1.5"));
    }

    #[tokio::test]
    async fn 状态接口给出连接与代理() {
        let hub = hub_with(ProxyTable::from_iter([proxy("web")]));
        let r = route(
            &hub,
            "GET",
            "/api/status",
            &req("GET /api/status HTTP/1.1\r\n\r\n"),
        )
        .await;
        assert_eq!(r.0, 200);
        let v = body_of(&r);
        assert_eq!(v["data"]["connected"], false, "没有会话就是未连接");
        assert_eq!(v["data"]["proxies"][0]["name"], "web");
        assert_eq!(v["data"]["proxies"][0]["remote_port"], 7000);
        assert_eq!(v["data"]["store"]["enabled"], false);
        assert_eq!(v["data"]["features"]["websocket"], false);
    }

    /// 代理列表顺序必须**稳定**：面板每 3 秒刷新一次，
    /// 顺序乱跳的话用户会以为自己在看不同的东西。
    #[tokio::test]
    async fn 代理列表按名字排序() {
        let hub = hub_with(ProxyTable::from_iter([
            proxy("zeta"),
            proxy("alpha"),
            proxy("mid"),
        ]));
        let r = route(
            &hub,
            "GET",
            "/api/proxies",
            &req("GET /api/proxies HTTP/1.1\r\n\r\n"),
        )
        .await;
        let v = body_of(&r);
        let names: Vec<&str> = v["data"]
            .as_array()
            .unwrap()
            .iter()
            .map(|x| x["name"].as_str().unwrap())
            .collect();
        assert_eq!(names, vec!["alpha", "mid", "zeta"]);
    }

    #[tokio::test]
    async fn 根路径给_html_页面() {
        let hub = hub_with(ProxyTable::default());
        let r = route(&hub, "GET", "/", &req("GET / HTTP/1.1\r\n\r\n")).await;
        assert_eq!(r.0, 200);
        assert!(
            r.1.starts_with("text/html"),
            "content-type 要是 html：{}",
            r.1
        );
        assert!(r.2.contains("rustunnel"), "页面里要有标题");
        assert!(r.2.contains("/api/status"), "页面要真的去拉状态接口");
    }

    #[tokio::test]
    async fn 未知路径是_404_方法不对是_405() {
        let hub = hub_with(ProxyTable::default());
        let r = route(&hub, "GET", "/nope", &req("GET /nope HTTP/1.1\r\n\r\n")).await;
        assert_eq!(r.0, 404);
        assert_eq!(body_of(&r)["error"]["code"], "not_found");

        let r = route(
            &hub,
            "POST",
            "/api/status",
            &req("POST /api/status HTTP/1.1\r\n\r\n"),
        )
        .await;
        assert_eq!(r.0, 405, "路径对、方法错应当 405 而不是 404");
        assert_eq!(body_of(&r)["error"]["code"], "method_not_allowed");
    }

    /// 没有活跃会话时必须**立刻**给出人话错误，而不是让调用方干等 20 秒。
    #[tokio::test]
    async fn 未连接时写操作立刻失败() {
        let hub = hub_with(ProxyTable::default());
        let r = route(
            &hub,
            "POST",
            "/api/proxies/add",
            &req("POST /api/proxies/add HTTP/1.1\r\n\r\n\
                 {\"name\":\"a\",\"type\":\"tcp\",\"local_addr\":\"127.0.0.1:80\"}"),
        )
        .await;
        assert_eq!(r.0, 400);
        let v = body_of(&r);
        assert_eq!(v["error"]["code"], "add_failed");
        assert!(
            v["error"]["message"].as_str().unwrap().contains("没有连上"),
            "错误要说清是没连上：{}",
            v["error"]["message"]
        );
    }

    /// 缺字段、重名这类问题要在**打到会话之前**就拦下 ——
    /// 发过去也是被服务端拒绝，白跑一次往返，错误信息还没这里的清楚。
    #[tokio::test]
    async fn 新增的本地校验() {
        let hub = hub_with(ProxyTable::from_iter([proxy("web")]));
        const ADD: &str = "POST /api/proxies/add HTTP/1.1\r\n\r\n";

        let r = route(
            &hub,
            "POST",
            "/api/proxies/add",
            &req(&format!(
                "{ADD}{{\"name\":\"\",\"type\":\"tcp\",\"local_addr\":\"127.0.0.1:80\"}}"
            )),
        )
        .await;
        assert_eq!(r.0, 400);
        assert!(
            body_of(&r)["error"]["message"]
                .as_str()
                .unwrap()
                .contains("name"),
            "缺 name 要指名道姓：{}",
            body_of(&r)["error"]["message"]
        );

        // `type` 在配置层有默认值（`tcp`），所以**缺了不报错** ——
        // 必须和 TOML 走同一套默认值语义，否则同一份配置从文件读和从
        // API 发会得到两种代理。这里能走到"没有连上"，就说明默认值生效了。
        let r = route(
            &hub,
            "POST",
            "/api/proxies/add",
            &req(&format!(
                "{ADD}{{\"name\":\"x\",\"local_addr\":\"127.0.0.1:80\"}}"
            )),
        )
        .await;
        assert_eq!(r.0, 400);
        assert!(
            body_of(&r)["error"]["message"]
                .as_str()
                .unwrap()
                .contains("没有连上"),
            "缺 type 应当按默认值 tcp 处理，而不是被拒：{}",
            body_of(&r)["error"]["message"]
        );

        // 但显式写成空串是**用户的失误**，不能悄悄当 tcp 收下
        let r = route(
            &hub,
            "POST",
            "/api/proxies/add",
            &req(&format!(
                "{ADD}{{\"name\":\"x\",\"type\":\"\",\"local_addr\":\"127.0.0.1:80\"}}"
            )),
        )
        .await;
        assert!(
            body_of(&r)["error"]["message"]
                .as_str()
                .unwrap()
                .contains("type"),
            "空 type 要点明：{}",
            body_of(&r)["error"]["message"]
        );

        let r = route(
            &hub,
            "POST",
            "/api/proxies/add",
            &req(&format!(
                "{ADD}{{\"name\":\"web\",\"type\":\"tcp\",\"local_addr\":\"127.0.0.1:80\"}}"
            )),
        )
        .await;
        assert!(
            body_of(&r)["error"]["message"]
                .as_str()
                .unwrap()
                .contains("已存在"),
            "同名代理不该被放过去"
        );

        let r = route(&hub, "POST", "/api/proxies/add", &req(ADD)).await;
        assert!(body_of(&r)["error"]["message"]
            .as_str()
            .unwrap()
            .contains("不能为空"));

        // `local_addr` 是必填字段（官方 frpc 也是），缺了要在解析阶段就报出来，
        // 而不是收下一条"本地地址是空串"的代理 —— 那样服务端注册成功、
        // 每次转发却都连不上，排查起来要绕一大圈。
        let r = route(
            &hub,
            "POST",
            "/api/proxies/add",
            &req(&format!("{ADD}{{\"name\":\"x\",\"type\":\"tcp\"}}")),
        )
        .await;
        assert_eq!(r.0, 400);
        assert!(
            body_of(&r)["error"]["message"]
                .as_str()
                .unwrap()
                .contains("local_addr"),
            "错误里要点明缺的是哪个字段：{}",
            body_of(&r)["error"]["message"]
        );
    }

    #[tokio::test]
    async fn 删除不存在的代理被拒() {
        let hub = hub_with(ProxyTable::default());
        let r = route(
            &hub,
            "POST",
            "/api/proxies/remove",
            &req("POST /x HTTP/1.1\r\n\r\nnope"),
        )
        .await;
        assert_eq!(r.0, 400);
        assert!(body_of(&r)["error"]["message"]
            .as_str()
            .unwrap()
            .contains("没有代理"));
    }

    /// 没配 `user` 就不鉴权（默认只监听回环，所以这是安全的默认值）。
    #[test]
    fn 没配用户名就不鉴权() {
        let hub = hub_with(ProxyTable::default());
        assert!(auth_failure(&hub, &req("GET / HTTP/1.1\r\n\r\n")).is_none());
    }

    #[test]
    fn 配了用户名就必须带对的凭证() {
        use base64::{engine::general_purpose::STANDARD, Engine as _};
        let mut c = ClientConfig::default();
        c.web_server.user = "admin".into();
        c.web_server.password = "pw".into();
        let store = Arc::new(Store::from_config(&c).unwrap());
        let health = health::Monitor::start(&c);
        let (_tx, rx) = tokio::sync::watch::channel::<Option<Arc<ClientSession>>>(None);
        let hub = Hub::new(Arc::new(c), ProxyTable::default(), store, health, rx);

        assert!(
            auth_failure(&hub, &req("GET / HTTP/1.1\r\n\r\n")).is_some(),
            "没带 Authorization 必须拒"
        );

        let cred = STANDARD.encode("admin:pw");
        let ok = format!("GET / HTTP/1.1\r\nAuthorization: Basic {cred}\r\n\r\n");
        assert!(auth_failure(&hub, &req(&ok)).is_none(), "正确凭证要放行");

        let bad = STANDARD.encode("admin:wrong");
        let bad = format!("GET / HTTP/1.1\r\nAuthorization: Basic {bad}\r\n\r\n");
        assert!(
            auth_failure(&hub, &req(&bad)).is_some(),
            "密码不对必须拒 —— 只比用户名等于把界面敞开"
        );
    }
}
