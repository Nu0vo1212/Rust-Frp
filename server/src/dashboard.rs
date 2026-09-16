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
    observability::{encode_json, encode_prometheus, Snapshot},
    registry::Registry,
};

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
pub async fn run(listener: TcpListener, registry: Arc<Registry>, auth: DashboardAuth) {
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
                tokio::spawn(async move {
                    if let Err(e) = handle(stream, peer, registry, auth).await {
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
) -> anyhow::Result<()> {
    // 面板只面向自己的运维，请求通常很小，一次读完就够
    let mut buf = Vec::with_capacity(1024);
    let mut chunk = [0u8; 1024];
    loop {
        let n = stream.read(&mut chunk).await?;
        if n == 0 {
            break;
        }
        buf.extend_from_slice(&chunk[..n]);
        if buf.len() > MAX_LINE * 4 || buf.windows(4).any(|w| w == b"\r\n\r\n") {
            break;
        }
    }
    let req = String::from_utf8_lossy(&buf).to_string();
    let (method, path) = parse_request_line(&req);
    let given = basic_auth_of(&req);

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
// 极简 HTTP 解析（够用即可，不为面板引入完整 HTTP 栈）
// ---------------------------------------------------------------------------

fn parse_request_line(req: &str) -> (String, String) {
    let mut parts = req.split_whitespace();
    let method = parts.next().unwrap_or("").to_ascii_uppercase();
    let target = parts.next().unwrap_or("/").to_string();
    // 去掉 query string
    let path = target.split('?').next().unwrap_or("/").to_string();
    (method, if path.is_empty() { "/".into() } else { path })
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
        401 => "Unauthorized",
        404 => "Not Found",
        405 => "Method Not Allowed",
        _ => "OK",
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
        clients.push_str(&format!(
            "{{\"client_id\":{:?},\"user\":{:?},\"proxies\":{:?},\"backlog\":{},\"idle_work_conns\":{}}}",
            c.client_id, c.user, c.proxies, c.backlog, c.idle_work_conns
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
  <footer>Prometheus 指标：<code>GET /metrics</code> · 状态接口：<code>GET /api/status</code></footer>
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
    document.getElementById('clients').innerHTML = table(
      ['客户端', 'user', '代理', '排队', '空闲工作连接'],
      (s.clients||[]).map(c=>[c.client_id, c.user||'-', (c.proxies||[]).join(', ')||'-', c.backlog, c.idle_work_conns]));
    document.getElementById('visitors').innerHTML = table(
      ['代理名', '类型', 'provider 用户', 'allow_users'],
      (s.visitors||[]).map(v=>[v.proxy_name, v.type, v.provider_user||'-', (v.allow_users||[]).join(', ')||'同 user']));
  } catch(e) {
    document.getElementById('cards').innerHTML = '<div class="empty">读取状态失败：'+e+'</div>';
  }
}
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
