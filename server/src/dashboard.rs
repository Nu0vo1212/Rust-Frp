//! 内置可观测面板：`/metrics`（Prometheus）、`/api/status`（JSON）、`/`（HTML 面板）。
//!
//! 之前这个项目**完全黑盒**：想知道有几个客户端在线、转发有没有成功、
//! 流量走了多少，只能靠看日志猜。这里把进程内的原子指标直接暴露出来，
//! 不引入 Prometheus client crate —— 指标只有十几个时序，手写导出器更省体积。

use std::{
    net::SocketAddr,
    sync::{Arc, RwLock},
};

use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};
use tracing::{debug, warn};

use crate::{
    admin, api_v2,
    observability::{encode_json, encode_prometheus, Snapshot},
    registry::Registry,
};
use rustunnel_common::config::ServerConfig;

/// 面板的鉴权信息；`None` 表示不校验（只建议在回环地址上这样配）。
pub type DashboardAuth = Arc<RwLock<Option<(String, String)>>>;

/// 健康检查路径。
///
/// 抽成常量是为了让"哪些路径不需要鉴权"只有一处定义 ——
/// 实现与测试都引它，避免哪天改了字面量而测试还在测旧路径。
pub const HEALTHZ_PATH: &str = "/api/healthz";

/// Prometheus 指标名前缀。
const METRIC_PREFIX: &str = "rustunnel";

/// 单条请求行的最大长度。
const MAX_LINE: usize = 8 * 1024;

/// 启动面板服务。
pub async fn run(
    listener: TcpListener,
    registry: Arc<Registry>,
    auth: DashboardAuth,
    cfg: Arc<ServerConfig>,
) {
    let addr = listener.local_addr().ok();
    tracing::info!(
        "面板已启动：{}  （/ 面板、/metrics 指标、/api/status 状态）",
        addr.map(|a| a.to_string()).unwrap_or_default()
    );
    loop {
        match listener.accept().await {
            Ok((stream, peer)) => {
                let registry = registry.clone();
                let auth = auth.clone();
                let cfg = cfg.clone();
                tokio::spawn(async move {
                    if let Err(e) = handle(stream, peer, registry, auth, cfg).await {
                        debug!(%peer, "面板连接结束：{e:#}");
                    }
                });
            }
            Err(e) => {
                warn!("面板 accept 失败：{e}");
                tokio::time::sleep(std::time::Duration::from_millis(200)).await;
            }
        }
    }
}

async fn handle(
    mut stream: TcpStream,
    peer: SocketAddr,
    registry: Arc<Registry>,
    auth: DashboardAuth,
    cfg: Arc<ServerConfig>,
) -> anyhow::Result<()> {
    // 读到"请求头结束"为止，如果带了 `Content-Length`，还要把**请求体读全**。
    //
    // 只按 `\r\n\r\n` 收尾是不够的，会踩两个坑：
    // * 请求体被拆到第二个 TCP 段里 → 我们提前收手，body 被截断，
    //   JSON 解析失败；
    // * 更隐蔽的：客户端发来了数据而我们没读完就关 socket，
    //   内核会回 RST 而不是 FIN —— Windows 上表现为客户端拿到
    //   `ConnectionResetError`，连已经写出去的响应都一起丢了。
    //   鉴权失败的 POST 就正好卡在这条上：面板明明回了 401，客户端却看不到。
    let mut buf = Vec::with_capacity(1024);
    let mut chunk = [0u8; 1024];
    loop {
        let n = stream.read(&mut chunk).await?;
        if n == 0 {
            break;
        }
        buf.extend_from_slice(&chunk[..n]);
        let head_done = buf.windows(4).any(|w| w == b"\r\n\r\n");
        if !head_done {
            if buf.len() > MAX_LINE * 4 {
                break;
            }
            continue;
        }
        // 头齐了：按 Content-Length 补齐请求体（没有该字段就当作没有体）
        let want = content_length_of(&String::from_utf8_lossy(&buf));
        let have = buf_body_len(&buf);
        if have >= want || buf.len() > MAX_LINE * 4 {
            break;
        }
    }
    let req = String::from_utf8_lossy(&buf).to_string();
    let (method, path) = parse_request_line(&req);
    let given = basic_auth_of(&req);
    let body = body_of(&req);
    let query = query_of(&req);

    // 健康探针必须在鉴权**之前**处理。
    //
    // k8s 的 liveness/readiness、docker 的 HEALTHCHECK、各类 LB 的健康检查
    // 都不方便带 Basic Auth，而放行它泄露的信息量为零（只回一个 "ok"）。
    // 早先它排在鉴权后面，于是探针永远拿到 401 —— 容器会被反复重启。
    // 注意：`/metrics` 不在此列，它含业务信息，Prometheus 可以配 basic_auth 抓。
    if path == HEALTHZ_PATH {
        if method != "GET" && method != "HEAD" {
            send(
                &mut stream,
                405,
                "text/plain; charset=utf-8",
                b"Method Not Allowed\n",
                &[],
            )
            .await?;
            return Ok(());
        }
        send(&mut stream, 200, "text/plain; charset=utf-8", b"ok\n", &[]).await?;
        debug!(%peer, "健康检查");
        return Ok(());
    }

    // Basic Auth：只在配置了用户名时才校验。
    //
    // 必须比对完整的 `user:password` —— 只比用户名等于把面板敞开，
    // 这里用定长比较，避免通过响应耗时逐字节猜密码。
    let expected = auth.read().ok().and_then(|g| g.clone());
    if let Some((user, pwd)) = expected {
        let expect_cred = format!("{}:{}", user, pwd);
        match &given {
            Some(g) if constant_time_eq(g, &expect_cred) => {}
            _ => {
                send(
                    &mut stream,
                    401,
                    "text/plain; charset=utf-8",
                    b"Unauthorized\n".as_slice(),
                    &[("WWW-Authenticate", "Basic realm=\"rustunnel\"")],
                )
                .await?;
                return Ok(());
            }
        }
    }

    // `/api/v2/*` 例外：让 v2 自己回它的统一错误信封。
    //
    // 否则 `DELETE /api/v2/clients` 会先撞上这道总闸、拿到一段纯文本 405，
    // 而调用方（都按信封解析）看到的是"响应体解析不了"—— 版本化 API 的
    // 错误格式必须是**全路径一致**的，不能一半信封一半纯文本。
    if !matches!(method.as_str(), "GET" | "HEAD" | "POST") && !path.starts_with(api_v2::PREFIX) {
        send(
            &mut stream,
            405,
            "text/plain; charset=utf-8",
            b"Method Not Allowed\n",
            &[],
        )
        .await?;
        return Ok(());
    }

    // API v2 在这里整段接管。
    //
    // 放在这个位置（鉴权之后、v1 的 POST 表之前）有两个理由：
    // * **鉴权之后** —— v2 里同样有开端口、踢人的写接口，绝不能绕开 Basic Auth；
    // * **v1 分支之前** —— v2 自带一套完整的路由和错误信封，不需要 v1 的
    //   路径表参与；而 `route` 对非 `/api/v2/` 的路径返回 `None`，
    //   v1 那些老路径一个字节都不会被碰到。
    if let Some(resp) = api_v2::route(&registry, &cfg, &method, &path, &query, body).await {
        send(
            &mut stream,
            resp.status,
            "application/json; charset=utf-8",
            resp.body.as_bytes(),
            &[],
        )
        .await?;
        debug!(%peer, %method, %path, status = resp.status, "面板 v2 请求已处理");
        return Ok(());
    }

    // 写操作：**所有 POST 都走这里**。
    //
    // 位置很关键 —— 必须排在鉴权**之后**。这些接口能开端口、能踢人，
    // 绝不能因为"没配 dashboard_user"就对全世界敞开。
    // 路径集中写在 `ADMIN_PATHS` 一张表里，散在 match 里迟早漏一个，
    // 而漏掉的那一个就是后门。
    if method == "POST" {
        if let Some((_, op)) = ADMIN_PATHS.iter().find(|(p, _)| *p == path.as_str()) {
            let outcome = admin_dispatch(*op, &registry, &cfg, body).await;
            let (code, payload) = match outcome {
                Ok(msg) => (200, format!("{{\"ok\":true,\"message\":{:?}}}", msg)),
                Err(e) => (400, format!("{{\"ok\":false,\"error\":{:?}}}", e)),
            };
            send(
                &mut stream,
                code,
                "application/json; charset=utf-8",
                payload.as_bytes(),
                &[],
            )
            .await?;
            return Ok(());
        }
    }

    let snapshot = registry.observ.snapshot();
    match path.as_str() {
        "/metrics" => {
            let body = encode_prometheus(&snapshot, METRIC_PREFIX);
            send(
                &mut stream,
                200,
                "text/plain; version=0.0.4; charset=utf-8",
                body.as_bytes(),
                &[],
            )
            .await?;
        }
        "/api/status" | "/api/status.json" => {
            let body = status_json(&registry, &snapshot);
            send(
                &mut stream,
                200,
                "application/json; charset=utf-8",
                body.as_bytes(),
                &[],
            )
            .await?;
        }
        "/" | "/index.html" | "/dashboard" => {
            let body = html_page();
            send(
                &mut stream,
                200,
                "text/html; charset=utf-8",
                body.as_bytes(),
                &[],
            )
            .await?;
        }
        other => {
            let body = format!("404 Not Found: {other}\n");
            send(
                &mut stream,
                404,
                "text/plain; charset=utf-8",
                body.as_bytes(),
                &[],
            )
            .await?;
        }
    }
    debug!(%peer, %method, %path, "面板请求已处理");
    Ok(())
}

// ---------------------------------------------------------------------------
// 写操作接口
// ---------------------------------------------------------------------------

/// 面板支持的写操作路径。
///
/// 集中列成一张表，是为了让"哪些路径要 POST + 鉴权"只有一处定义 ——
/// 散在 match 里迟早会漏一个，那一个就是后门。
const ADMIN_PATHS: &[(&str, AdminOp)] = &[
    ("/api/proxies/add", AdminOp::AddProxy),
    ("/api/proxies/remove", AdminOp::RemoveProxy),
    ("/api/clients/kick", AdminOp::Kick),
];

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum AdminOp {
    AddProxy,
    RemoveProxy,
    Kick,
}

async fn admin_dispatch(
    op: AdminOp,
    registry: &Arc<Registry>,
    cfg: &Arc<ServerConfig>,
    body: &str,
) -> Result<String, String> {
    // body 是 JSON：手工取字段，不引 serde 派生 —— 面板的请求体只有三四个键，
    // 为一个 {"run_id": "..."} 建一整套结构体不划算。
    let v: serde_json::Value = if body.trim().is_empty() {
        serde_json::Value::Null
    } else {
        serde_json::from_str(body).map_err(|e| format!("请求体不是合法 JSON：{e}"))?
    };
    let str_field = |k: &str| {
        v.get(k)
            .and_then(|x| x.as_str())
            .unwrap_or_default()
            .to_string()
    };
    let run_id = str_field("run_id");
    if run_id.is_empty() {
        return Err("缺少 run_id".to_string());
    }

    match op {
        AdminOp::AddProxy => {
            let proxy = v
                .get("proxy")
                .ok_or_else(|| "缺少 proxy 配置".to_string())?;
            let p: rustunnel_common::config::ProxyConfig = serde_json::from_value(proxy.clone())
                .map_err(|e| format!("proxy 配置解析失败：{e}"))?;
            admin::add_proxy(cfg, registry, &run_id, p).await
        }
        AdminOp::RemoveProxy => {
            let name = str_field("name");
            if name.is_empty() {
                return Err("缺少 name".to_string());
            }
            admin::remove_proxy(registry, &run_id, &name).await
        }
        AdminOp::Kick => admin::kick(registry, &run_id, &str_field("reason")).await,
    }
}

/// 请求头里的 `Content-Length`（没有就当 0）。
fn content_length_of(req: &str) -> usize {
    header_value(req, "content-length")
        .and_then(|v| v.parse::<usize>().ok())
        .unwrap_or(0)
}

/// 已经收到的请求体字节数。
fn buf_body_len(buf: &[u8]) -> usize {
    let sep = b"\r\n\r\n";
    match buf.windows(4).position(|w| w == sep) {
        Some(i) => buf.len() - (i + 4),
        None => 0,
    }
}

/// 取请求体：HTTP 头结束（空行）之后的全部内容。
fn body_of(req: &str) -> &str {
    match req.find("\r\n\r\n") {
        Some(i) => &req[i + 4..],
        None => "",
    }
}

fn parse_request_line(req: &str) -> (String, String) {
    let mut parts = req.split_whitespace();
    let method = parts.next().unwrap_or("").to_ascii_uppercase();
    let target = parts.next().unwrap_or("/").to_string();
    // 去掉 query string
    let path = target.split('?').next().unwrap_or("/").to_string();
    (method, if path.is_empty() { "/".into() } else { path })
}

/// 请求行里的 query string（`?` 之后的部分，不含 `?`）。
///
/// `parse_request_line` 会把 query 丢掉（v1 的路径表是按纯路径匹配的），
/// 但 v2 的分页/过滤全靠它，所以单独再抽一次。没带 query 就是空串。
fn query_of(req: &str) -> String {
    let target = req.split_whitespace().nth(1).unwrap_or("");
    match target.split_once('?') {
        Some((_, q)) => q.to_string(),
        None => String::new(),
    }
}

fn header_value(req: &str, name: &str) -> Option<String> {
    for line in req.lines() {
        if let Some((k, v)) = line.split_once(':') {
            if k.trim().eq_ignore_ascii_case(name) {
                return Some(v.trim().to_string());
            }
        }
    }
    None
}

fn basic_auth_of(req: &str) -> Option<String> {
    use base64::{engine::general_purpose::STANDARD, Engine as _};
    let raw = header_value(req, "authorization")?;
    let (scheme, value) = raw.split_once(' ')?;
    if !scheme.eq_ignore_ascii_case("basic") {
        return None;
    }
    let decoded = STANDARD.decode(value.trim().as_bytes()).ok()?;
    String::from_utf8(decoded).ok()
}

/// 定长比较：避免通过响应时间推测密码。
fn constant_time_eq(a: &str, b: &str) -> bool {
    rustunnel_common::frp::msg::constant_time_eq(a, b)
}

async fn send(
    stream: &mut TcpStream,
    code: u16,
    content_type: &str,
    body: &[u8],
    extra: &[(&str, &str)],
) -> anyhow::Result<()> {
    let reason = match code {
        200 => "OK",
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        409 => "Conflict",
        500 => "Internal Server Error",
        502 => "Bad Gateway",
        503 => "Service Unavailable",
        504 => "Gateway Timeout",
        _ => "Status",
    };
    let mut out = format!(
        "HTTP/1.1 {code} {reason}\r\n\
         Content-Type: {content_type}\r\n\
         Content-Length: {}\r\n\
         Connection: close\r\n",
        body.len()
    );
    for (k, v) in extra {
        out.push_str(&format!("{k}: {v}\r\n"));
    }
    out.push_str("\r\n");
    stream.write_all(out.as_bytes()).await?;
    stream.write_all(body).await?;
    stream.flush().await?;
    Ok(())
}

// ---------------------------------------------------------------------------
// 内容生成
// ---------------------------------------------------------------------------

fn status_json(registry: &Registry, snap: &Snapshot) -> String {
    let mut clients = String::from("[");
    let infos = registry.clients();
    for (i, c) in infos.iter().enumerate() {
        if i > 0 {
            clients.push(',');
        }
        // run_id 必须带上：面板上的"新增代理 / 踢出"是拿它当主键的。
        // client_id 会重复（同一个 client_id 重连多次），不能当主键用。
        clients.push_str(&format!(
            "{{\"run_id\":{:?},\"client_id\":{:?},\"user\":{:?},\"proxies\":{:?},\"backlog\":{},\"idle_work_conns\":{},\"managed\":{}}}",
            c.run_id, c.client_id, c.user, c.proxies, c.backlog, c.idle_work_conns, c.managed
        ));
    }
    clients.push(']');

    let mut visitors = String::from("[");
    let list = registry.visitors.list();
    for (i, v) in list.iter().enumerate() {
        if i > 0 {
            visitors.push(',');
        }
        visitors.push_str(&format!(
            "{{\"proxy_name\":{:?},\"type\":{:?},\"provider_user\":{:?},\"allow_users\":{:?}}}",
            v.proxy_name, v.proxy_type, v.provider_user, v.allow_users
        ));
    }
    visitors.push(']');

    let ports: Vec<String> = registry
        .reserved_ports()
        .iter()
        .map(|p| p.to_string())
        .collect();

    format!(
        concat!(
            "{{\"status\":{},\"clients\":{},\"visitors\":{},\"ports\":[{}],",
            "\"p2p_enabled\":{},\"limits\":{{\"max_clients\":{},\"max_total_conns\":{},\"max_conns_per_client\":{}}}}}"
        ),
        encode_json(snap),
        clients,
        visitors,
        ports.join(","),
        registry.p2p().is_some(),
        registry.limits().max_clients,
        registry.limits().max_total_conns,
        registry.limits().max_conns_per_client,
    )
}

/// 面板页面：纯静态 HTML + 一点 JS 轮询 `/api/status`。
fn html_page() -> String {
    r#"<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>rustunnel 面板</title>
<style>
  :root { color-scheme: light; }
  body { margin:0; font:14px/1.6 system-ui,-apple-system,"Segoe UI",sans-serif;
         background:#f6f7f9; color:#1f2328; }
  header { background:#24292f; color:#fff; padding:14px 22px; font-size:16px; }
  main { max-width: 1080px; margin: 22px auto; padding: 0 18px; }
  .cards { display:grid; grid-template-columns:repeat(auto-fit,minmax(160px,1fr)); gap:12px; }
  .card { background:#fff; border:1px solid #d8dee4; border-radius:8px; padding:14px 16px; }
  .card .k { font-size:12px; color:#6e7781; }
  .card .v { font-size:22px; font-weight:600; margin-top:4px; }
  section { margin-top: 26px; }
  h2 { font-size:15px; margin:0 0 10px; padding-bottom:6px; border-bottom:1px solid #d8dee4; }
  table { width:100%; border-collapse:collapse; background:#fff;
          border:1px solid #d8dee4; border-radius:8px; overflow:hidden; }
  th,td { text-align:left; padding:8px 12px; border-bottom:1px solid #eaeef2; font-size:13px; }
  th { background:#f6f8fa; color:#57606a; font-weight:600; }
  tr:last-child td { border-bottom:none; }
  .empty { color:#6e7781; padding:12px; background:#fff; border:1px dashed #d8dee4; border-radius:8px; }
  code { background:#eff1f3; padding:1px 5px; border-radius:4px; }
  .admin { background:#fff; border:1px solid #d8dee4; border-radius:8px; padding:14px 16px; }
  .admin .row { display:flex; flex-wrap:wrap; gap:12px; align-items:center; margin-bottom:10px; }
  .admin label { font-size:12px; color:#57606a; display:flex; gap:6px; align-items:center; }
  .admin input, .admin select { font:inherit; padding:5px 8px; border:1px solid #d0d7de;
          border-radius:6px; background:#fff; color:#1f2328; }
  button { font:inherit; padding:5px 12px; border:1px solid #d0d7de; border-radius:6px;
           background:#f6f8fa; color:#1f2328; cursor:pointer; }
  button:hover { background:#eef1f4; }
  button.danger { border-color:#f0c0c0; color:#a40e26; }
  pre#outcome { margin:8px 0 0; padding:10px 12px; border-radius:6px; background:#f6f8fa;
                color:#1f2328; font-size:12px; white-space:pre-wrap; min-height:1.4em; }
  footer { color:#6e7781; font-size:12px; text-align:center; padding:26px 0; }
</style>
</head>
<body>
<header>rustunnel 面板</header>
<main>
  <div class="cards" id="cards"></div>
  <section>
    <h2>在线客户端</h2>
    <div id="clients"></div>
  </section>
  <section>
    <h2>stcp / xtcp 代理</h2>
    <div id="visitors"></div>
  </section>
  <section>
    <h2>管理操作</h2>
    <div class="admin">
      <div class="row">
        <label>目标客户端 <select id="target"></select></label>
      </div>
      <div class="row">
        <label>代理名 <input id="p_name" placeholder="web"></label>
        <label>类型 <select id="p_type">
          <option value="tcp">tcp</option><option value="udp">udp</option>
          <option value="http">http</option><option value="https">https</option>
          <option value="stcp">stcp</option><option value="xtcp">xtcp</option>
        </select></label>
        <label>公网端口 <input id="p_port" type="number" placeholder="7000"></label>
        <label>内网地址 <input id="p_local" placeholder="127.0.0.1:8080"></label>
      </div>
      <div class="row">
        <button id="btn_add">新增代理</button>
        <button id="btn_del" class="danger">移除代理（按上面的名字）</button>
      </div>
      <pre id="outcome"></pre>
    </div>
  </section>
  <footer>Prometheus 指标：<code>GET /metrics</code> · 状态接口：<code>GET /api/status</code>
    · 管理接口：<code>POST /api/proxies/add</code> / <code>/api/proxies/remove</code> / <code>/api/clients/kick</code></footer>
</main>
<script>
const KB = 1024, MB = 1024*1024, GB = 1024*1024*1024;
function bytes(n){ if(n>=GB) return (n/GB).toFixed(2)+' GB'; if(n>=MB) return (n/MB).toFixed(2)+' MB';
  if(n>=KB) return (n/KB).toFixed(1)+' KB'; return n+' B'; }
function card(k,v){ return `<div class="card"><div class="k">${k}</div><div class="v">${v}</div></div>`; }
function table(headers, rows){
  if(!rows.length) return '<div class="empty">暂无数据</div>';
  return `<table><thead><tr>${headers.map(h=>`<th>${h}</th>`).join('')}</tr></thead><tbody>`
    + rows.map(r=>`<tr>${r.map(c=>`<td>${c}</td>`).join('')}</tr>`).join('') + '</tbody></table>';
}
async function refresh(){
  try {
    const r = await fetch('/api/status'); const s = await r.json();
    const st = s.status || {};
    document.getElementById('cards').innerHTML = [
      card('在线客户端', st.clients_active ?? 0),
      card('生效代理', st.proxies_active ?? 0),
      card('活跃转发连接', st.conns_active ?? 0),
      card('上行流量', bytes(st.bytes_up ?? 0)),
      card('下行流量', bytes(st.bytes_down ?? 0)),
      card('被拒连接', st.conns_rejected ?? 0),
    ].join('');
    window.__clients = s.clients||[];
    document.getElementById('clients').innerHTML = table(
      ['客户端', 'user', '代理', '排队', '空闲', '管理'],
      (s.clients||[]).map(c=>[c.client_id, c.user||'-', (c.proxies||[]).join(', ')||'-',
        c.backlog, c.idle_work_conns,
        '<button data-kick="'+esc(c.run_id)+'">踢出</button>']));
    // 客户端下拉框（新增代理要选一个客户端）
    const sel = document.getElementById('target');
    if (sel) {
      const keep = sel.value;
      sel.innerHTML = (s.clients||[]).map(c =>
        '<option value="'+esc(c.run_id)+'">'+esc(c.client_id)+' / '+esc(c.user||'-')+'</option>').join('');
      if (keep) sel.value = keep;
    }
    document.getElementById('visitors').innerHTML = table(
      ['代理名', '类型', 'provider 用户', 'allow_users'],
      (s.visitors||[]).map(v=>[v.proxy_name, v.type, v.provider_user||'-', (v.allow_users||[]).join(', ')||'同 user']));
  } catch(e) {
    document.getElementById('cards').innerHTML = '<div class="empty">读取状态失败：'+e+'</div>';
  }
}
function esc(s){ return String(s).replace(/[&<>"]/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c])); }
function val(id){ return (document.getElementById(id)||{}).value || ''; }
async function call(path, payload){
  const out = document.getElementById('outcome');
  out.textContent = '请求中…';
  try {
    const r = await fetch(path, {method:'POST', headers:{'Content-Type':'application/json'},
                                 body: JSON.stringify(payload)});
    const j = await r.json();
    out.textContent = j.ok ? ('成功：'+j.message) : ('失败：'+j.error);
    out.style.background = j.ok ? '#eaf6ec' : '#fdecec';
    refresh();
  } catch(e) { out.textContent = '请求失败：'+e; out.style.background = '#fdecec'; }
}
document.addEventListener('click', async ev => {
  const runId = ev.target.getAttribute && ev.target.getAttribute('data-kick');
  if (runId) {
    if (!confirm('确定踢出这个客户端？它的所有代理会立刻失效。')) return;
    await call('/api/clients/kick', {run_id: runId, reason: '面板操作'});
  }
});
const addBtn = document.getElementById('btn_add');
if (addBtn) addBtn.onclick = async () => {
  const port = parseInt(val('p_port'), 10);
  const proxy = {name: val('p_name'), type: val('p_type'), local_addr: val('p_local')};
  if (!isNaN(port)) proxy.remote_port = port;
  if (!proxy.name) { document.getElementById('outcome').textContent = '请先填代理名'; return; }
  await call('/api/proxies/add', {run_id: val('target'), proxy: proxy});
};
const delBtn = document.getElementById('btn_del');
if (delBtn) delBtn.onclick = async () => {
  if (!val('p_name')) { document.getElementById('outcome').textContent = '请先填代理名'; return; }
  await call('/api/proxies/remove', {run_id: val('target'), name: val('p_name')});
};
refresh(); setInterval(refresh, 3000);
</script>
</body>
</html>
"#
    .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_line_parsing_drops_query_and_method_is_uppercased() {
        assert_eq!(
            parse_request_line("get /api/status?x=1 HTTP/1.1\r\n"),
            ("GET".to_string(), "/api/status".to_string())
        );
        assert_eq!(
            parse_request_line("GET / HTTP/1.1"),
            ("GET".to_string(), "/".to_string())
        );
        assert_eq!(parse_request_line(""), ("".to_string(), "/".to_string()));
    }

    /// v2 的分页与过滤全靠 query，抽错了就是"翻页永远翻不动"。
    #[test]
    fn query_extraction() {
        assert_eq!(
            query_of("GET /api/v2/clients?page=2&page_size=5 HTTP/1.1\r\n"),
            "page=2&page_size=5"
        );
        assert_eq!(query_of("GET /api/v2/clients HTTP/1.1"), "");
        // 只有一个 `?` 也算"没有 query"，不能把它当成 query 传下去
        assert_eq!(query_of("GET /api/v2/clients? HTTP/1.1"), "");
        assert_eq!(query_of(""), "");
    }

    async fn http_get(addr: SocketAddr, path: &str, auth: Option<(&str, &str)>) -> String {
        use base64::{engine::general_purpose::STANDARD, Engine as _};
        let mut req = format!("GET {path} HTTP/1.1\r\nHost: localhost\r\n");
        if let Some((u, p)) = auth {
            let cred = STANDARD.encode(format!("{u}:{p}"));
            req.push_str(&format!("Authorization: Basic {cred}\r\n"));
        }
        req.push_str("\r\n");
        let mut s = TcpStream::connect(addr).await.expect("连上面板");
        s.write_all(req.as_bytes()).await.expect("写请求");
        let mut buf = Vec::new();
        s.read_to_end(&mut buf).await.expect("读响应");
        String::from_utf8_lossy(&buf).into_owned()
    }

    /// v2 走**完整 HTTP 链路**（真实 socket + 鉴权）也必须能跑。
    ///
    /// 只测 `api_v2::route` 是不够的：那样测不到"query 有没有从请求行抽出来"
    /// 和"鉴权有没有先拦住"这两件最容易出错的事。
    #[tokio::test]
    async fn v2_over_real_http() {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("绑端口");
        let addr = listener.local_addr().unwrap();
        let registry = Arc::new(Registry::unlimited());
        let auth: DashboardAuth = Arc::new(RwLock::new(Some(("u".into(), "p".into()))));

        let srv = {
            let registry = registry.clone();
            let auth = auth.clone();
            tokio::spawn(async move {
                loop {
                    let Ok((stream, peer)) = listener.accept().await else {
                        break;
                    };
                    let registry = registry.clone();
                    let auth = auth.clone();
                    tokio::spawn(async move {
                        let cfg = Arc::new(ServerConfig::default());
                        let _ = handle(stream, peer, registry, auth, cfg).await;
                    });
                }
            })
        };

        // ① 没带鉴权：401。v2 的写接口能开端口能踢人，绝不能绕过 Basic Auth。
        let resp = http_get(addr, "/api/v2/status", None).await;
        assert!(resp.starts_with("HTTP/1.1 401"), "未鉴权应当 401：{resp}");

        // ② 带上鉴权：200，且是统一信封。
        let resp = http_get(addr, "/api/v2/status", Some(("u", "p"))).await;
        assert!(resp.starts_with("HTTP/1.1 200"), "{resp}");
        assert!(resp.contains("\"api\":\"v2\""), "缺少版本标识：{resp}");

        // ③ query 要真的生效：非法的分页参数必须被拒，而不是悄悄回第一页。
        let resp = http_get(addr, "/api/v2/clients?page=0", Some(("u", "p"))).await;
        assert!(resp.starts_with("HTTP/1.1 400"), "{resp}");
        assert!(resp.contains("bad_request"), "{resp}");

        // ④ v1 的老路径不受影响（零行为变化）。
        let resp = http_get(addr, "/api/status", Some(("u", "p"))).await;
        assert!(resp.starts_with("HTTP/1.1 200"), "v1 必须照常工作：{resp}");
        assert!(resp.contains("\"clients\""), "{resp}");

        // ⑤ 非 GET/HEAD/POST 的方法打到 `/api/v2/*`，也必须走 v2 的统一错误信封。
        //
        // 回归：早先面板的总闸（只允许前三个方法）排在 v2 之前，`DELETE /api/v2/x`
        // 会拿到一段纯文本 405 —— 按信封解析的调用方只会看到"响应体坏了"。
        {
            use base64::{engine::general_purpose::STANDARD, Engine as _};
            let cred = STANDARD.encode("u:p");
            let req = format!(
                "DELETE /api/v2/clients HTTP/1.1\r\nHost: localhost\r\n\
                 Authorization: Basic {cred}\r\n\r\n"
            );
            let mut s = TcpStream::connect(addr).await.expect("连上面板");
            s.write_all(req.as_bytes()).await.expect("写请求");
            let mut buf = Vec::new();
            s.read_to_end(&mut buf).await.expect("读响应");
            let resp = String::from_utf8_lossy(&buf).into_owned();
            assert!(resp.starts_with("HTTP/1.1 405"), "{resp}");
            assert!(
                resp.contains("method_not_allowed"),
                "v2 路径的 405 必须是统一信封：{resp}"
            );
        }

        srv.abort();
    }

    #[test]
    fn header_lookup_is_case_insensitive() {
        let req = "GET / HTTP/1.1\r\nHost: x\r\nAuthorization: Basic abc\r\n\r\n";
        assert_eq!(
            header_value(req, "authorization"),
            Some("Basic abc".to_string())
        );
        assert_eq!(header_value(req, "HOST"), Some("x".to_string()));
        assert_eq!(header_value(req, "missing"), None);
    }

    #[test]
    fn basic_auth_is_decoded() {
        use base64::{engine::general_purpose::STANDARD, Engine as _};
        let cred = STANDARD.encode(b"admin:s3cret");
        let req = format!("GET / HTTP/1.1\r\nAuthorization: Basic {cred}\r\n\r\n");
        assert_eq!(basic_auth_of(&req), Some("admin:s3cret".to_string()));
    }

    #[test]
    fn bearer_token_is_not_treated_as_basic() {
        let req = "GET / HTTP/1.1\r\nAuthorization: Bearer x\r\n\r\n";
        assert_eq!(basic_auth_of(req), None);
    }

    /// 回归：早先的实现只比对用户名就放行，等于没有密码。
    #[test]
    fn auth_requires_full_user_and_password() {
        use base64::{engine::general_purpose::STANDARD, Engine as _};
        let expect_cred = String::from("admin:s3cret");

        let build = |raw: &[u8]| -> String {
            let mut s = String::from(
                "GET / HTTP/1.1
Authorization: Basic ",
            );
            s.push_str(&STANDARD.encode(raw));
            s.push_str(
                "

",
            );
            s
        };
        let matches = |raw: &[u8]| -> bool {
            basic_auth_of(&build(raw))
                .map(|g| constant_time_eq(&g, &expect_cred))
                .unwrap_or(false)
        };

        assert!(matches(b"admin:s3cret"), "正确的用户名密码必须放行");
        assert!(!matches(b"admin:guess"), "密码不对必须拒绝");
        assert!(!matches(b"admin"), "只给用户名（没有密码）也必须拒绝");
        assert!(!matches(b"other:s3cret"), "用户名不对也必须拒绝");
    }

    #[test]
    fn constant_time_compare_works() {
        assert!(constant_time_eq("abc", "abc"));
        assert!(!constant_time_eq("abc", "abd"));
        assert!(!constant_time_eq("ab", "abc"), "长度不同也不能算相等");
    }

    #[test]
    fn status_json_is_well_formed() {
        let registry = Registry::unlimited();
        let snap = registry.observ.snapshot();
        let j = status_json(&registry, &snap);
        assert!(j.starts_with('{') && j.ends_with('}'), "{j}");
        assert!(j.contains("\"clients\":["));
        assert!(j.contains("\"visitors\":["));
        assert!(j.contains("\"p2p_enabled\":false"));
        // 括号必须配平，否则前端 JSON.parse 会直接炸
        assert_eq!(j.matches('{').count(), j.matches('}').count(), "{j}");
        assert_eq!(j.matches('[').count(), j.matches(']').count(), "{j}");
    }

    #[test]
    fn html_page_has_required_endpoints_and_no_unclosed_tags() {
        let html = html_page();
        assert!(html.starts_with("<!DOCTYPE html>"));
        assert!(html.contains("/api/status"));
        assert!(html.contains("/metrics"));
        assert!(html.contains("refresh()"));
        assert_eq!(html.matches("<script>").count(), 1);
        assert_eq!(html.matches("</script>").count(), 1);
    }

    #[test]
    fn metrics_endpoint_output_is_prometheus_shaped() {
        let registry = Registry::unlimited();
        let snap = registry.observ.snapshot();
        let out = encode_prometheus(&snap, METRIC_PREFIX);
        assert!(out.contains("rustunnel_uptime_seconds"));
        assert!(out.contains("# TYPE rustunnel_conns_active gauge"));
    }
}
