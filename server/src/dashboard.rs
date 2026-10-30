//! 内置可观测面板：`/metrics`（Prometheus）、`/api/status`（JSON）、`/`（HTML 面板）。
//!
//! 之前这个项目**完全黑盒**：想知道有几个客户端在线、转发有没有成功、
//! 流量走了多少，只能靠看日志猜。这里把进程内的原子指标直接暴露出来，
//! 不引入 Prometheus client crate —— 指标只有十几个时序，手写导出器更省体积。

use std::{
    net::SocketAddr,
    sync::{Arc, RwLock},
};

#[cfg(test)]
use tokio::net::TcpStream;
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::TcpListener,
};
use tokio_rustls::TlsAcceptor;
use tracing::{debug, warn};

use crate::{
    admin, api_v2,
    observability::{encode_json, encode_prometheus, Snapshot},
    registry::Registry,
};
use nfrp_common::config::ServerConfig;

/// 面板的鉴权信息；`None` 表示不校验（只建议在回环地址上这样配）。
pub type DashboardAuth = Arc<RwLock<Option<(String, String)>>>;

/// 健康检查路径。
///
/// 抽成常量是为了让"哪些路径不需要鉴权"只有一处定义 ——
/// 实现与测试都引它，避免哪天改了字面量而测试还在测旧路径。
pub const HEALTHZ_PATH: &str = "/api/healthz";

/// Prometheus 指标名前缀。
const METRIC_PREFIX: &str = "nfrp";

/// 面板所有响应都会带的**安全响应头**（v0.6.4，渗透测试 PT-05）。
///
/// # 为什么加
///
/// 面板是一个带 Basic Auth 的网页，曾经一个安全头都没有。这些头不改变
/// 服务端逻辑，但决定浏览器怎么对待页面：
///
/// | 头 | 作用 |
/// |---|---|
/// | `X-Content-Type-Options: nosniff` | 禁止浏览器嗅探 MIME。少了它，一个被上传的"文件"可能被当 HTML 执行 |
/// | `X-Frame-Options: DENY` | 禁止被 `<iframe>` 嵌入 —— 挡住点击劫持（把面板套进攻击者页面，诱导管理员点"踢出"） |
/// | `Referrer-Policy: no-referrer` | 面板 URL 不通过 `Referer` 泄露给外部站点 |
/// | `Content-Security-Policy` | 只允许内联样式与脚本（面板是单文件 HTML，没有外部资源），禁止一切外域加载与 `frame-ancestors` |
///
/// # HSTS
///
/// 面板现在支持 `[webServer.tls]`。HSTS 头在 HTTPS 响应上生效；如果仍是
/// 明文 HTTP，浏览器按 RFC 6797 §7.2 会忽略它，因此统一发送不会把 HTTP
/// 伪装成 HTTPS，也不会改变 HTTP 的行为。
///
/// # CSP 的取舍
///
/// 面板 HTML 的所有脚本与样式都是内联的（`html_page()` 单文件），所以
/// `script-src` / `style-src` 必须允许 `'unsafe-inline'`。这不是疏忽 ——
/// 在一个自包含页面上，能挡的部分是 `default-src 'none'`（禁止一切外域
/// 请求、图片、字体、frame），而那正好是最有价值的部分。
const SEC_HEADERS: &[(&str, &str)] = &[
    ("X-Content-Type-Options", "nosniff"),
    ("X-Frame-Options", "DENY"),
    ("Referrer-Policy", "no-referrer"),
    (
        "Strict-Transport-Security",
        "max-age=31536000; includeSubDomains",
    ),
    (
        "Content-Security-Policy",
        "default-src 'none'; script-src 'unsafe-inline'; \
         style-src 'unsafe-inline'; img-src 'self' data:; \
         connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'",
    ),
];

/// 单条请求行的最大长度。
const MAX_LINE: usize = 8 * 1024;

/// 面板能同时处理的连接数上限。
///
/// 面板是个"低频管理界面"，不是业务数据面 —— 正常使用下并发个位数就够。
/// 没有上限时，谁都能开一堆连接把任务/Arena 占满，进而拖垮整个服务端进程
/// （面板和业务跑在同一个进程里）。
///
/// 取 128 是个很松的值：正常永远碰不到，但足以挡住洪水式连接。
const MAX_DASHBOARD_CONNS: usize = 128;

/// 读完整请求头的总超时（v0.5.4，L1）。
///
/// 没有它的话，128 个连接各发一个字节就能长期占满上面那道并发闸门
/// （slowloris）—— 而面板与业务同进程，会连带拖累业务。
const HEAD_READ_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

/// 启动面板服务（明文 HTTP，保留给测试和旧调用方）。
pub async fn run(
    listener: TcpListener,
    registry: Arc<Registry>,
    auth: DashboardAuth,
    cfg: Arc<ServerConfig>,
) {
    run_with_tls(listener, registry, auth, cfg, None).await
}

/// [`run`] 的 TLS 版本。`tls = Some(..)` 时监听器只接受 HTTPS。
pub async fn run_with_tls(
    listener: TcpListener,
    registry: Arc<Registry>,
    auth: DashboardAuth,
    cfg: Arc<ServerConfig>,
    tls: Option<TlsAcceptor>,
) {
    let addr = listener.local_addr().ok();
    tracing::info!(
        "面板已启动：{}  （/ 面板、/metrics 指标、/api/status 状态，{}）",
        addr.map(|a| a.to_string()).unwrap_or_default(),
        if tls.is_some() { "HTTPS" } else { "HTTP" }
    );
    // 并发闸门：拿不到许可就直接关掉这条连接（不回 503 —— 那还要多写一次，
    // 而洪水场景下我们连写都不想写）。
    let gate = Arc::new(tokio::sync::Semaphore::new(MAX_DASHBOARD_CONNS));
    loop {
        match listener.accept().await {
            Ok((stream, peer)) => {
                // ★★ v0.5.9 修（第九轮审计 **E9-2**，低危）：**面板也要过 ACL**。
                //
                // # 原先为什么错了
                //
                // `[acl]` 的语义在文档里是"**谁能连上来**"
                // （`common/src/security.rs:3`），且明确写着
                // "**在认证之前执行**，所以被拒的连接连 token 都不用发"
                // （`assets/frps.toml`）。**两条都没把面板排除在外。**
                //
                // 而 `dashboard.rs` 原先**零 `check_ip` 调用**。
                //
                // # 实测（`tmp/audit9/_indep/verify_dashboard_acl.py`，8/8 判据全过）
                //
                // `[acl] deny = ["127.0.0.1"]` 下：
                //
                // | 端点 | 无凭据 | 错凭据 | **正确凭据** |
                // |---|---|---|---|
                // | `/` | 401 | 401 | **200** |
                // | `/api/status` | 401 | 401 | **200** |
                // | `/metrics` | 401 | 401 | **200** |
                // | `/api/healthz` | **200** | 200 | 200 |
                //
                // 而**同一条 ACL 让控制面登录被拒**、日志出现"IP 访问控制拒绝"
                // ⇒ 证明 ACL 本身有效，只是**没覆盖面板**。
                //
                // # 定级为什么是「低危」而非更高
                //
                // 面板**有独立的 Basic Auth**（无/错凭据一律 401），
                // 所以这不是认证绕过，而是**纵深防御缺失**：
                // 管理员若用 `[acl]` 表达"只允许办公网访问面板"，这个意图会静默落空。
                //
                // ★ 与 UDP 那条（E9-0，中危）的区别正在于此：
                //   **UDP 代理没有别的防线**，面板**有**。
                //
                // # 关于 `/api/healthz`（免鉴权探针端点）
                //
                // 这里**一视同仁**都会被 ACL 判定 —— 因为 ACL 的语义是来源管控，
                // 不该有"某些端点例外"的隐含规则（那又是一个"没铺满"）。
                // 用 k8s/docker 探针的部署，只要把**探针来源**放进 allow 即可；
                // 这是管理员配置时该做的事，不是代码该替他猜的事。
                let sec = registry.security();
                if let Err(reason) = sec.check_ip(peer.ip()) {
                    registry.audit().record(
                        crate::audit::AuditEvent::new(crate::audit::kind::LOGIN_DENIED, false)
                            .ip(peer.ip().to_string())
                            .detail(format!("{reason}（管理面板数据面）")),
                    );
                    debug!(%peer, "面板数据面 IP 访问控制拒绝：{reason}");
                    drop(stream);
                    continue;
                }
                let Ok(permit) = gate.clone().try_acquire_owned() else {
                    debug!(%peer, limit = MAX_DASHBOARD_CONNS, "面板并发连接已达上限，直接关闭");
                    drop(stream);
                    continue;
                };
                let registry = registry.clone();
                let auth = auth.clone();
                let cfg = cfg.clone();
                let tls = tls.clone();
                tokio::spawn(async move {
                    // permit 随任务存活，任务结束即归还
                    let _permit = permit;
                    let result = match tls {
                        Some(acceptor) => {
                            // 与主控制端口一致：TLS 握手也要有上限，防止慢速
                            // ClientHello 占满面板闸门。
                            match tokio::time::timeout(
                                std::time::Duration::from_secs(10),
                                acceptor.accept(stream),
                            )
                            .await
                            {
                                Ok(Ok(tls_stream)) => {
                                    handle(tls_stream, peer, registry, auth, cfg).await
                                }
                                Ok(Err(e)) => Err(anyhow::anyhow!("面板 TLS 握手失败：{e}")),
                                Err(_) => Err(anyhow::anyhow!("面板 TLS 握手超时")),
                            }
                        }
                        None => handle(stream, peer, registry, auth, cfg).await,
                    };
                    if let Err(e) = result {
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

async fn handle<S>(
    mut stream: S,
    peer: SocketAddr,
    registry: Arc<Registry>,
    auth: DashboardAuth,
    cfg: Arc<ServerConfig>,
) -> anyhow::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
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
    // ★★ v0.5.4 修（L1）：读头阶段加**整体超时**。
    //
    // 原先这个循环没有任何时限 —— 128 个连接各发一个字节就能长期占满
    // 面板的并发闸门（`MAX_DASHBOARD_CONNS`），构成 slowloris。
    // 面板与业务跑在**同一个进程**里，被占满会连带拖累业务。
    //
    // 取 10s 与 vhost 路径同一量级；正常面板请求是毫秒级，无可感知影响。
    let read_head = async {
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
        Ok::<(), std::io::Error>(())
    };
    match tokio::time::timeout(HEAD_READ_TIMEOUT, read_head).await {
        Ok(Ok(())) => {}
        Ok(Err(e)) => return Err(e.into()),
        Err(_) => {
            debug!(%peer, "面板读头超时（{:?}），断开", HEAD_READ_TIMEOUT);
            return Ok(());
        }
    }
    let req = String::from_utf8_lossy(&buf).to_string();
    let (method, path) = parse_request_line(&req);
    let given = basic_auth_of(&req);
    let body = body_of(&req);
    let query = query_of(&req);

    // v0.6.4（渗透测试 PT-03）：`HEAD` 只回响应头，不回 body。
    // 见 [`send`] 的 `head_only` 参数说明。
    let head_only = method == "HEAD";

    // ★ NFRP-13：安全相关头必须唯一。出现两个以上 Authorization
    // 直接当畸形请求拒掉，而不是“取第一个”——否则与前置代理 / WAF 的
    // 取值口径一旦相反，就是鉴权差异（请求走私类问题的典型前提）。
    if unique_header(&req, "authorization").is_err() {
        send(
            &mut stream,
            400,
            "text/plain; charset=utf-8",
            b"Duplicate Authorization header\n",
            SEC_HEADERS,
            head_only,
        )
        .await?;
        return Ok(());
    }

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
                SEC_HEADERS,
                head_only,
            )
            .await?;
            return Ok(());
        }
        send(
            &mut stream,
            200,
            "text/plain; charset=utf-8",
            b"ok\n",
            SEC_HEADERS,
            head_only,
        )
        .await?;
        debug!(%peer, "健康检查");
        return Ok(());
    }

    // Basic Auth：只在配置了**完整**凭据时才校验。
    //
    // 必须比对完整的 `user:password` —— 只比用户名等于把面板敞开，
    // 这里用定长比较，避免通过响应耗时逐字节猜密码。
    //
    // ★★ v0.5.6 修（审计总报告 H1，纵深防御）：**用户名非空但密码为空
    //   一律按"没有凭据"处理**（`expected` 视为 None）⇒ 走下面的拒绝分支。
    //
    //   为什么不能去比 `"admin:"`：那等于"知道用户名就能进"，
    //   攻击者随手构造一个 `Authorization: Basic YWRtaW46` 就通过了。
    //   这正是 H1 攻击链的第 ⑤⑥ 步。
    //
    //   注意这条是**纵深防御**：真正的闸门在启动校验与热重载闸门
    //   （它们已经用 `has_dashboard_creds()` 拦住了这种配置）。
    //   但鉴权点是"最后一米"，这里也必须自己站得住 ——
    //   不能假设上游永远拦住了（`serve_with` 可被别的宿主直接调用）。
    let expected = auth
        .read()
        .ok()
        .and_then(|g| g.clone())
        .filter(|(u, p)| nfrp_common::config::has_dashboard_creds(u, p));
    if let Some((user, pwd)) = expected {
        let expect_cred = format!("{}:{}", user, pwd);
        match &given {
            Some(g) if constant_time_eq(g, &expect_cred) => {}
            _ => {
                // 认证失败加一个小延迟，压低暴力破解速率。
                //
                // 定长比较挡住了"按耗时逐字节猜"，但挡不住"猜得快"——
                // 面板走 TCP，本地/内网链路上每秒能试几千次。加 200ms
                // 之后单连接降到 ~5 次/秒，配合上面的并发上限（128），
                // 整体速率被压到可控范围。
                //
                // 用 `sleep` 而不是"按 IP 计数熔断"：后者要引入一张会
                // 无限增长的表（还得处理过期清理），对面板这个低频接口
                // 不划算。
                tokio::time::sleep(std::time::Duration::from_millis(200)).await;
                send(
                    &mut stream,
                    401,
                    "text/plain; charset=utf-8",
                    b"Unauthorized\n".as_slice(),
                    SEC_HEADERS_WITH_AUTH.as_slice(),
                    head_only,
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
            SEC_HEADERS,
            head_only,
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
            SEC_HEADERS,
            head_only,
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
                SEC_HEADERS,
                head_only,
            )
            .await?;
            return Ok(());
        }

        // ★ v0.6.4（渗透测试 PT-07）：**未匹配的 POST 一律 405**。
        //
        // 旧行为是落进下面的 `match path`，于是 `POST /api/status` 会命中
        // `"/api/status"` 分支、返回 200 + 完整状态 JSON。那既违反直觉
        // （只读端点接受了写方法），也让只按"状态码 200 就算成功"的
        // 客户端 / 监控误判。
        //
        // 用 405 而不是 404：路径确实存在，只是方法不对 —— 这是 HTTP 语义
        // 要求，顺带用 `Allow` 告诉调用方该用什么方法。
        send(
            &mut stream,
            405,
            "text/plain; charset=utf-8",
            b"Method Not Allowed: read-only endpoint\n",
            SEC_HEADERS_WITH_ALLOW.as_slice(),
            head_only,
        )
        .await?;
        return Ok(());
    }

    let snapshot = registry.observ.snapshot();
    match path.as_str() {
        // 官方 frps 的 `webServer.pprofEnable`：在面板监听器上挂 Go pprof。
        // Rust 侧用 pprof-rs 输出同格式的 protobuf，路径与参数保持一致。
        "/debug/pprof" | "/debug/pprof/" => {
            if !cfg.effective_pprof_enable() {
                send(
                    &mut stream,
                    404,
                    "text/plain; charset=utf-8",
                    b"pprof disabled: set webServer.pprofEnable = true\n",
                    SEC_HEADERS,
                    head_only,
                )
                .await?;
            } else {
                send(
                    &mut stream,
                    200,
                    "text/plain; charset=utf-8",
                    b"GET /debug/pprof/profile?seconds=N\n",
                    SEC_HEADERS,
                    head_only,
                )
                .await?;
            }
        }
        "/debug/pprof/profile" => {
            if !cfg.effective_pprof_enable() {
                send(
                    &mut stream,
                    404,
                    "text/plain; charset=utf-8",
                    b"pprof disabled: set webServer.pprofEnable = true\n",
                    SEC_HEADERS,
                    head_only,
                )
                .await?;
            } else {
                let secs = nfrp_common::pprof_http::parse_seconds(&query);
                // 采集是阻塞的（pprof guard 在 drop 时收尾），必须离开 async
                // 执行器；否则一个 60 秒的请求会把整块 worker 占死。
                match tokio::task::spawn_blocking(move || {
                    nfrp_common::pprof_http::capture_cpu_profile(secs)
                })
                .await
                {
                    Ok(Ok(body)) => {
                        send(
                            &mut stream,
                            200,
                            "application/octet-stream",
                            &body,
                            SEC_HEADERS,
                            head_only,
                        )
                        .await?;
                    }
                    Ok(Err(e)) => {
                        let text = format!("pprof failed: {e:#}\n");
                        let code = if text.contains("only supported on Unix") {
                            501
                        } else {
                            500
                        };
                        send(
                            &mut stream,
                            code,
                            "text/plain; charset=utf-8",
                            text.as_bytes(),
                            SEC_HEADERS,
                            head_only,
                        )
                        .await?;
                    }
                    Err(e) => {
                        let text = format!("pprof task failed: {e}\n");
                        send(
                            &mut stream,
                            500,
                            "text/plain; charset=utf-8",
                            text.as_bytes(),
                            SEC_HEADERS,
                            head_only,
                        )
                        .await?;
                    }
                }
            }
        }
        "/metrics" => {
            // ★ v0.6.5（对齐官方 frps 的 `enablePrometheus`）：
            //   官方默认**不开**这个端点，配了 `enablePrometheus = true` 才有
            //   （`server.go`："EnablePrometheus will export prometheus metrics
            //   on {dashboard_addr}:{dashboard_port}"）。
            //
            //   我们之前是无条件开放的 —— 两处不妥：
            //   ① 与官方默认不一致，照官方文档部署的人会以为它关着；
            //   ② 指标含业务信息（在线客户端数、代理数、流量字节），
            //      在"只想开个面板"的部署里**默认多暴露一份数据面**。
            //
            //   所以默认改成关闭、与官方一致；要开就显式配。
            //   `/api/healthz` 不受影响 —— 健康探针本来就该永远可用。
            if cfg.enable_prometheus {
                let body = encode_prometheus(&snapshot, METRIC_PREFIX);
                send(
                    &mut stream,
                    200,
                    "text/plain; version=0.0.4; charset=utf-8",
                    body.as_bytes(),
                    SEC_HEADERS,
                    head_only,
                )
                .await?;
            } else {
                send(
                    &mut stream,
                    404,
                    "text/plain; charset=utf-8",
                    b"metrics disabled: set enablePrometheus = true\n",
                    SEC_HEADERS,
                    head_only,
                )
                .await?;
            }
        }
        "/api/status" | "/api/status.json" => {
            let body = status_json(&registry, &snapshot);
            send(
                &mut stream,
                200,
                "application/json; charset=utf-8",
                body.as_bytes(),
                SEC_HEADERS,
                head_only,
            )
            .await?;
        }
        "/" | "/index.html" | "/dashboard" => {
            // ★ v0.6.6（对齐官方 frps 的 `webServer.assetsDir`）：
            // 配了目录就优先用里面的 index.html，否则用内嵌的那份。
            match load_asset(cfg.effective_assets_dir(), "index.html") {
                Some((body, ctype)) => {
                    send(&mut stream, 200, ctype, &body, SEC_HEADERS, head_only).await?;
                }
                None => {
                    let body = html_page();
                    send(
                        &mut stream,
                        200,
                        "text/html; charset=utf-8",
                        body.as_bytes(),
                        SEC_HEADERS,
                        head_only,
                    )
                    .await?;
                }
            }
        }
        other => {
            // 配了 assets_dir 时，其余路径也当作静态资源找一遍
            // （面板换皮通常还带 css/js/图片）。找不到才 404。
            if let Some((body, ctype)) = load_asset(cfg.effective_assets_dir(), other) {
                send(&mut stream, 200, ctype, &body, SEC_HEADERS, head_only).await?;
            } else {
                let body = format!("404 Not Found: {other}\n");
                send(
                    &mut stream,
                    404,
                    "text/plain; charset=utf-8",
                    body.as_bytes(),
                    SEC_HEADERS,
                    head_only,
                )
                .await?;
            }
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
            let p: nfrp_common::config::ProxyConfig = serde_json::from_value(proxy.clone())
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
    // ★ v0.5.8 修（第八轮审计 F8-L1，低危）：只看**头区**，body 行不得参与解析。
    //
    // `req` 是整个读缓冲的转码（见 `handle` 里的读循环）—— 与请求头同一批
    // 到达的请求体字节也在里面。原先逐行扫描整个缓冲，于是写在 body 里的
    // `Authorization: Basic ...` 会被当成头参与鉴权（第八轮实测：同段发送
    // 时 control=401 / body 行=200）。这与标准 HTTP 语义、以及上游中间件
    // （反代/WAF/网关只按头区判定）的口径不一致，属解析卫生问题；
    // 按纵深防御收紧到头区（`\r\n\r\n` 之前）。
    let head = req.split("\r\n\r\n").next().unwrap_or(req);
    for line in head.lines() {
        if let Some((k, v)) = line.split_once(':') {
            if k.trim().eq_ignore_ascii_case(name) {
                return Some(v.trim().to_string());
            }
        }
    }
    None
}

/// 安全相关头：**必须唯一**。重复即为畸形请求（NFRP-13）。
///
/// 为什么不能“取第一个就算了”：面板前面经常挂 Nginx / WAF / SSO 网关，
/// 上游与 NFrp 对“哪个 `Authorization` 生效”理解一旦相反，就是鉴权差异，
/// 属于请求走私类问题的经典前置条件。
///
/// 返回 `Err(())` 表示同名头出现两次以上，调用方应直接回 400。
fn unique_header(req: &str, name: &str) -> std::result::Result<Option<String>, ()> {
    let head = req.split("\r\n\r\n").next().unwrap_or(req);
    let mut it = head
        .lines()
        .filter_map(|l| l.split_once(':'))
        .filter(|(k, _)| k.trim().eq_ignore_ascii_case(name))
        .map(|(_, v)| v.trim().to_string());

    match (it.next(), it.next()) {
        (None, _) => Ok(None),
        (Some(v), None) => Ok(Some(v)),
        _ => Err(()),
    }
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
    nfrp_common::frp::msg::constant_time_eq(a, b)
}

/// 把「调用点自己的头」与 [`SEC_HEADERS`] 合并。
///
/// 401 要带 `WWW-Authenticate`、405 要带 `Allow` —— 这些是**协议必需**的头，
/// 不能因为加安全头而丢掉。
///
/// 注意：这里**不用**运行时拼接函数。`send` 收的是 `&[(&str, &str)]`，
/// 写 `&with_sec_headers(...)` 会产生临时值、活不过调用表达式；改成两个
/// `static` 数组在编译期就固定下来，零运行时开销、也没有生命周期问题。
/// 只有需要额外头的调用点才用它们，其余直接传 [`SEC_HEADERS`]。
static SEC_HEADERS_WITH_AUTH: [(&str, &str); SEC_HEADERS.len() + 1] = concat_headers_auth();

static SEC_HEADERS_WITH_ALLOW: [(&str, &str); SEC_HEADERS.len() + 1] = concat_headers_allow();

/// 401 用：`WWW-Authenticate` + 安全头。
const fn concat_headers_auth() -> [(&'static str, &'static str); SEC_HEADERS.len() + 1] {
    let mut out = [("", ""); SEC_HEADERS.len() + 1];
    out[0] = ("WWW-Authenticate", "Basic realm=\"nfrp\"");
    let mut i = 0;
    while i < SEC_HEADERS.len() {
        out[i + 1] = SEC_HEADERS[i];
        i += 1;
    }
    out
}

/// 405 用：`Allow` + 安全头。
const fn concat_headers_allow() -> [(&'static str, &'static str); SEC_HEADERS.len() + 1] {
    let mut out = [("", ""); SEC_HEADERS.len() + 1];
    out[0] = ("Allow", "GET, HEAD");
    let mut i = 0;
    while i < SEC_HEADERS.len() {
        out[i + 1] = SEC_HEADERS[i];
        i += 1;
    }
    out
}

/// 写一个完整的 HTTP 响应。
///
/// # `head_only`（v0.6.4，渗透测试 PT-03）
///
/// `HEAD` 请求**必须只回头、不回头**（RFC 9110 §9.3.2）。
/// 早先这里无差别地写 body，于是一个 `HEAD /` 会回 10368 字节 HTML。
///
/// 危害有限（不是漏洞，是协议违规），但会带来实际问题：
/// * 一些健康检查 / 监控用 HEAD 探测，白白拉一遍完整页面；
/// * 某些缓存与代理对 HEAD 的 body 处理不一致，可能污染缓存。
///
/// `Content-Length` **仍然按真实 body 长度发送** —— 这正是 HEAD 的语义：
/// 告诉对端 GET 会拿到多少字节，但不真的发。
async fn send<S>(
    stream: &mut S,
    code: u16,
    content_type: &str,
    body: &[u8],
    extra: &[(&str, &str)],
    head_only: bool,
) -> anyhow::Result<()>
where
    S: AsyncWrite + Unpin,
{
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
    // HEAD：只回头，body 一个字节都不写
    if !head_only {
        stream.write_all(body).await?;
    }
    stream.flush().await?;
    Ok(())
}

// ---------------------------------------------------------------------------
// 内容生成
// ---------------------------------------------------------------------------

fn status_json(registry: &Registry, snap: &Snapshot) -> String {
    // ★★ NFRP-05（P0）：不能用 `format!` + `{:?}` 拼 JSON。
    //
    // Rust 的 `Debug` 对控制字符输出 **`\u{1}`**（Rust 语法），
    // 而 JSON 只接受 **`\u0001`**（4 位十六进制）。
    //
    // 实测（本机复现，commit c7214ab）：只要一个已注册客户端把
    // `client_id` 里塞一个 `\u{1}`，`/api/status` 就变成非法 JSON
    // （Python / PowerShell 两个独立解析器都报错），面板 `JSON.parse` 直接白屏。
    // 等于“让管理员看不见我”。
    //
    // 这里交给 serde_json，转义规则不再由我们自己担。
    let clients: Vec<serde_json::Value> = registry
        .clients()
        .iter()
        .map(|c| {
            serde_json::json!({
                // run_id 必须带上：面板的"新增代理 / 踢出"是拿它当主键的。
                // client_id 会重复（同一个 client_id 重连多次），不能当主键用。
                "run_id": c.run_id,
                "client_id": c.client_id,
                "user": c.user,
                "proxies": c.proxies,
                "backlog": c.backlog,
                "idle_work_conns": c.idle_work_conns,
                "managed": c.managed,
            })
        })
        .collect();

    let visitors: Vec<serde_json::Value> = registry
        .visitors
        .list()
        .iter()
        .map(|v| {
            serde_json::json!({
                "proxy_name": v.proxy_name,
                "type": v.proxy_type,
                "provider_user": v.provider_user,
                "allow_users": v.allow_users,
            })
        })
        .collect();

    let ports: Vec<u16> = registry.reserved_ports();

    serde_json::json!({
        // `status` 段原本就走 `encode_json`（数字字段，本来就安全）；
        // 这里把它作为**已序列化的 JSON 片段**嵌入，保持输出结构完全不变。
        "status": serde_json::from_str::<serde_json::Value>(&encode_json(snap))
            .unwrap_or(serde_json::Value::Null),
        "clients": clients,
        "visitors": visitors,
        "ports": ports,
        "p2p_enabled": registry.p2p().is_some(),
        "limits": {
            "max_clients": registry.limits().max_clients,
            "max_total_conns": registry.limits().max_total_conns,
            "max_conns_per_client": registry.limits().max_conns_per_client,
        }
    })
    .to_string()
}

/// 面板页面：纯静态 HTML + 一点 JS 轮询 `/api/status`。
/// 从 `assets_dir` 里取一个静态文件；返回 `(内容, MIME)`。
///
/// `rel` 是请求路径（可能带前导 `/`）。返回 `None` 表示"没有这个文件"，
/// 由调用方回退到内嵌面板 / 404。
///
/// # 安全：三道防线
///
/// 1. `assets_dir` 为空 ⇒ 直接返回 `None`（默认行为，一个字节都不多读）；
/// 2. 把 `rel` 里的 `..` / 绝对路径段挡掉 —— 光靠 `canonicalize` 不够，
///    Windows 上 `..\\` 与 `..%5c` 都可能是穿越向量；
/// 3. `canonicalize` 之后**再确认结果仍在 assets_dir 之内** ——
///    这一步才真正挡住符号链接把根指到目录外。
fn load_asset(assets_dir: &str, rel: &str) -> Option<(Vec<u8>, &'static str)> {
    if assets_dir.trim().is_empty() {
        return None;
    }

    // 只保留正常的路径段；任何 `..` 或盘符直接拒
    let mut parts: Vec<&str> = Vec::new();
    for seg in rel.split(['/', '\\']) {
        if seg.is_empty() || seg == "." {
            continue;
        }
        if seg == ".." || seg.contains(':') {
            return None;
        }
        parts.push(seg);
    }
    if parts.is_empty() {
        return None;
    }

    let root = std::path::Path::new(assets_dir);
    let mut full = root.to_path_buf();
    for p in &parts {
        full.push(p);
    }

    // ② 解析真实路径，并确认没有跑出根目录
    let canon_root = root.canonicalize().ok()?;
    let canon_full = full.canonicalize().ok()?;
    if !canon_full.starts_with(&canon_root) {
        tracing::warn!(
            assets_dir,
            requested = rel,
            "静态资源路径越出 assets_dir，已拒绝"
        );
        return None;
    }
    if !canon_full.is_file() {
        return None;
    }

    let body = std::fs::read(&canon_full).ok()?;
    Some((body, mime_of(&canon_full)))
}

/// 按扩展名给 MIME。认不出来的按二进制流 —— 宁可让浏览器下载，
/// 也不要把未知内容当 HTML 渲染（那是 XSS 面）。
fn mime_of(p: &std::path::Path) -> &'static str {
    match p
        .extension()
        .and_then(|e| e.to_str())
        .map(|e| e.to_ascii_lowercase())
        .as_deref()
    {
        Some("html") | Some("htm") => "text/html; charset=utf-8",
        Some("css") => "text/css; charset=utf-8",
        Some("js") | Some("mjs") => "text/javascript; charset=utf-8",
        Some("json") => "application/json; charset=utf-8",
        Some("svg") => "image/svg+xml",
        Some("png") => "image/png",
        Some("jpg") | Some("jpeg") => "image/jpeg",
        Some("gif") => "image/gif",
        Some("webp") => "image/webp",
        Some("ico") => "image/x-icon",
        Some("woff") => "font/woff",
        Some("woff2") => "font/woff2",
        Some("txt") | Some("map") => "text/plain; charset=utf-8",
        _ => "application/octet-stream",
    }
}

fn html_page() -> String {
    r#"<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>NFrp 面板</title>
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
<header>NFrp 面板</header>
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
          <option value="tcpmux">tcpmux</option>
          <option value="stcp">stcp</option><option value="sudp">sudp</option><option value="xtcp">xtcp</option>
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
function card(k,v){ return `<div class="card"><div class="k">${esc(k)}</div><div class="v">${esc(v)}</div></div>`; }
// ★★ v0.5.6 修（审计总报告 H4，高危 · 存储型 XSS）：
//   `table()` 原先**直接插值单元格**，而单元格里装着攻击者可控的字符串 ——
//   低权限客户端注册一个名字为 `<img src=x onerror=...>` 的代理，
//   管理员一打开面板就在**管理员会话**里执行攻击者的脚本
//   ⇒ 越权调用 /api/*（踢人、增删代理、开公网端口）。
//
//   数据来源全部可控（`/api/status`）：
//     clients[].client_id / user / proxies[]（代理名）
//     visitors[].proxy_name / type / provider_user / allow_users
//
//   `esc()` 本来就存在、也在这同一个文件里被正确用过（`c.run_id`、
//   下拉框的每个字段）—— **唯独 `table()` 这条路径漏了**。
//   客户端 `web.rs` 的实现一直是对的（`card()` 辅助函数内部自己转义），
//   这里照它的模式改。
//
//   需要嵌入 HTML 的（"踢出"按钮）用 `raw()` **显式**标记，
//   避免二次转义把按钮变成文本。
function raw(html){ return {__raw: String(html)}; }
function cell(c){
  return (c && typeof c === 'object' && '__raw' in c) ? c.__raw : esc(c);
}
function table(headers, rows){
  if(!rows.length) return '<div class="empty">暂无数据</div>';
  return `<table><thead><tr>${headers.map(h=>`<th>${esc(h)}</th>`).join('')}</tr></thead><tbody>`
    + rows.map(r=>`<tr>${r.map(c=>`<td>${cell(c)}</td>`).join('')}</tr>`).join('') + '</tbody></table>';
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
        // ★ H4：这是**唯一**需要嵌 HTML 的单元格 ⇒ 用 raw() 显式标记，
        //   否则会被 esc() 转义成文本、按钮显示不出来。
        //   注意里面的 run_id 仍然要 esc()（它进了 HTML 属性）。
        raw('<button data-kick="'+esc(c.run_id)+'">踢出</button>')]));
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
    // ★★ v0.6.1 修（Shannon 审计，加固）：`e` 也要过 `esc()`。
    //
    // 第五轮 H4 修了 `table()` / `card()` 的转义，**唯独漏了这条 catch 分支**
    // —— 又是"防线没铺满"那个模式。
    //
    // # 今天为什么不可利用（如实记录）
    //
    // `e` 是本地 JS 的 `Error` 对象（来自 `fetch` 或 `JSON.parse` 失败），
    // **不是服务端返回的文本**，内容由浏览器生成、攻击者控制不了。
    //
    // # 为什么仍然要改
    //
    // ① 它违反了本文件"所有动态内容一律过 `esc()`"的约定；
    // ② 它的安全性依赖"`e` 永远不含远端文本"这个**隐含假设**——
    //    将来谁在这里改成先 `await r.text()` 再 catch，就立刻变成存储型 XSS；
    // ③ 转义一次的成本为零。
    document.getElementById('cards').innerHTML = '<div class="empty">读取状态失败：'+esc(e)+'</div>';
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
        http_req(addr, "GET", path, auth).await
    }

    /// 通用请求（v0.6.4）：可以指定方法，用于测 HEAD / POST 的语义。
    async fn http_req(
        addr: SocketAddr,
        method: &str,
        path: &str,
        auth: Option<(&str, &str)>,
    ) -> String {
        use base64::{engine::general_purpose::STANDARD, Engine as _};
        let mut req = format!("{method} {path} HTTP/1.1\r\nHost: localhost\r\n");
        if let Some((u, p)) = auth {
            let cred = STANDARD.encode(format!("{u}:{p}"));
            req.push_str(&format!("Authorization: Basic {cred}\r\n"));
        }
        req.push_str("Content-Length: 0\r\n\r\n");
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

    /// ★ v0.5.8（第八轮审计 F8-L1，低危）回归：**body 行不得参与头解析/鉴权**。
    ///
    /// 修复前：`Authorization: Basic ...` 只要和请求头**同段到达**（LAN/localhost
    /// 常规如此），即使写在 `Content-Length` 声明的请求体里也会被当成头 →
    /// 面板返回 200。与上游中间件（按标准语义只看头区）产生口径差，
    /// 属请求走私/解析差异类隐患，纵深防御必须收紧。
    #[test]
    fn header_lookup_must_ignore_body_lines() {
        use base64::{engine::general_purpose::STANDARD, Engine as _};

        let cred = STANDARD.encode("u:p");
        let body = format!("Authorization: Basic {cred}");
        let req = format!(
            "GET /api/status HTTP/1.1\r\nHost: x\r\nContent-Length: {}\r\n\r\n{body}",
            body.len()
        );
        assert_eq!(
            header_value(&req, "authorization"),
            None,
            "body 行不能当 Authorization 头"
        );
        assert_eq!(basic_auth_of(&req), None, "body 凭据不得通过鉴权解析");

        // 修的是"只认头区"，不是"拒绝一切"：头区里的 Authorization 必须照常取到
        let ok = format!("GET / HTTP/1.1\r\nAuthorization: Basic {cred}\r\n\r\nbody-尾");
        assert_eq!(
            header_value(&ok, "authorization"),
            Some(format!("Basic {cred}"))
        );
        assert_eq!(basic_auth_of(&ok), Some("u:p".to_string()));
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

    // ==================================================================
    // v0.5.6 回归（审计总报告 H4）：面板表格必须转义单元格
    // ==================================================================

    /// ★★ H4 核心回归：`table()` 必须逐个单元格走 `cell()`（默认 `esc()`）。
    ///
    /// 修复前它直接 `<td>${c}</td>` 插值，而单元格里装着**攻击者可控**的
    /// 代理名 / 用户名 ⇒ 低权限客户端注册一个名字为
    /// `<img src=x onerror=...>` 的代理，管理员一开面板就在**管理员会话**里
    /// 执行攻击者的脚本（存储型 XSS）⇒ 越权调 `/api/*`。
    ///
    /// ★ 这里断言的是"接线"，不是"运行时行为"（面板 JS 不在 Rust 测试里跑）。
    ///   但接线正是本 bug 的全部内容 —— `esc()` 一直存在，
    ///   只是 `table()` 这条路径没接上。
    #[test]
    fn 面板表格必须转义单元格() {
        let html = html_page();

        // 表头与单元格都必须过 esc()/cell()
        assert!(
            html.contains("headers.map(h=>`<th>${esc(h)}</th>`)"),
            "表头必须转义"
        );
        assert!(
            html.contains("r.map(c=>`<td>${cell(c)}</td>`)"),
            "单元格必须走 cell()（内部默认 esc）"
        );
        // ★ 反向：绝不能残留"直接插值"的旧写法
        assert!(
            !html.contains("r.map(c=>`<td>${c}</td>`)"),
            "不得残留未转义的单元格插值（H4）"
        );

        // cell() / raw() 必须存在且语义正确
        assert!(html.contains("function cell(c)"), "cell() 必须存在");
        assert!(html.contains("function raw(html)"), "raw() 必须存在");
        assert!(
            html.contains("'__raw' in c) ? c.__raw : esc(c)"),
            "cell() 必须默认转义、只对 raw() 放行"
        );
        // 唯一的 raw() 使用点是那个按钮
        assert_eq!(
            html.matches("raw('<button").count(),
            1,
            "只有『踢出』按钮该用 raw()"
        );
        // 按钮里的 run_id 自己仍然要转义（它进了 HTML 属性）
        assert!(html.contains("esc(c.run_id)"), "属性里的 run_id 仍须转义");

        // ★★ v0.6.1（Shannon 审计，加固）：**catch 分支里的 `e` 也必须转义**。
        //
        // 第五轮 H4 修了 `table()` / `card()`，**唯独漏了这条 catch 分支** ——
        // 又是"防线没铺满"那个模式。
        //
        // 今天不可利用（`e` 是本地 JS 的 Error，不是服务端文本），
        // 但它违反了本文件"动态内容一律过 esc()"的约定，
        // 而安全性只依赖"`e` 永远不含远端文本"这个隐含假设。
        assert!(
            html.contains("读取状态失败：'+esc(e)+'"),
            "catch 分支里的 e 必须过 esc()"
        );
        assert!(
            !html.contains("读取状态失败：'+e+'"),
            "不得残留未转义的 catch 插值（H4 漏掉的路径）"
        );

        // 卡片也一并转义（原先同样直接插值；虽然当前只喂数字，但别留地雷）
        assert!(
            html.contains(
                "function card(k,v){ return `<div class=\"card\"><div class=\"k\">${esc(k)}</div>"
            ),
            "card() 也必须转义"
        );
    }

    #[test]
    fn metrics_endpoint_output_is_prometheus_shaped() {
        let registry = Registry::unlimited();
        let snap = registry.observ.snapshot();
        let out = encode_prometheus(&snap, METRIC_PREFIX);
        assert!(out.contains("nfrp_uptime_seconds"));
        assert!(out.contains("# TYPE nfrp_conns_active gauge"));
    }

    /// ★ v0.6.5：`enablePrometheus` **默认关闭**（对齐官方 frps）。
    ///
    /// 这条防的是"以后有人图方便把默认改回 true"—— 那会重新变成
    /// "只想开面板却默认多暴露一份业务指标"。
    #[test]
    fn enable_prometheus_默认关闭() {
        let cfg = ServerConfig::default();
        assert!(
            !cfg.enable_prometheus,
            "官方 frps 默认不开 metrics，我们必须一致"
        );
    }

    /// 配置里能真正读进来（官方 camelCase 与 NFrp snake_case 都认）。
    #[test]
    fn enable_prometheus_能读进来() {
        let a =
            nfrp_common::config::parse_server_toml("bindPort = 7000\nenablePrometheus = true\n")
                .expect("解析失败");
        assert!(a.enable_prometheus, "camelCase 写法要认");

        let b =
            nfrp_common::config::parse_server_toml("bind_port = 7000\nenable_prometheus = true\n")
                .expect("解析失败");
        assert!(b.enable_prometheus, "snake_case 写法要认");

        let c = nfrp_common::config::parse_server_toml("bind_port = 7000\n").expect("解析失败");
        assert!(!c.enable_prometheus, "不配就是关");
    }

    // ==================================================================
    // v0.6.4（渗透测试 PT-03 / PT-05 / PT-07）：HTTP 语义与安全响应头
    // ==================================================================

    /// 起一个真实面板，返回监听地址。测完不用管，测试进程退出即回收。
    async fn spawn_dashboard() -> (SocketAddr, tokio::task::JoinHandle<()>) {
        spawn_dashboard_cfg(ServerConfig::default()).await
    }

    /// 同上，但可以指定 `enable_prometheus`（v0.6.5）。
    async fn spawn_dashboard_with(prometheus: bool) -> (SocketAddr, tokio::task::JoinHandle<()>) {
        spawn_dashboard_cfg(ServerConfig {
            enable_prometheus: prometheus,
            ..Default::default()
        })
        .await
    }

    /// 起一个配了 `assets_dir` 的面板（v0.6.6）。
    async fn spawn_dashboard_with_assets(
        assets_dir: &str,
    ) -> (SocketAddr, tokio::task::JoinHandle<()>) {
        spawn_dashboard_cfg(ServerConfig {
            assets_dir: assets_dir.to_string(),
            ..Default::default()
        })
        .await
    }

    /// 面板块的真实监听循环，配置由调用方给，避免每个新字段都复制一段 accept。
    async fn spawn_dashboard_cfg(cfg: ServerConfig) -> (SocketAddr, tokio::task::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("绑端口");
        let addr = listener.local_addr().unwrap();
        let registry = Arc::new(Registry::unlimited());
        let auth: DashboardAuth = Arc::new(RwLock::new(Some(("u".into(), "p".into()))));
        let cfg = Arc::new(cfg);
        let h = tokio::spawn(async move {
            while let Ok((stream, peer)) = listener.accept().await {
                let registry = registry.clone();
                let auth = auth.clone();
                let cfg = cfg.clone();
                tokio::spawn(async move {
                    let _ = handle(stream, peer, registry, auth, cfg).await;
                });
            }
        });
        (addr, h)
    }

    /// 真实 HTTPS 面板：自签证书 + rustls 客户端，验证 200 与 HSTS。
    #[tokio::test]
    async fn web_server_tls_真实_https_和_hsts() {
        let dir = std::env::temp_dir().join(format!("nfrp-web-tls-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
        let cert_path = dir.join("cert.pem");
        let key_path = dir.join("key.pem");
        std::fs::write(&cert_path, cert.cert.pem()).unwrap();
        std::fs::write(&key_path, cert.key_pair.serialize_pem()).unwrap();

        let tls = nfrp_common::frp::tls::server_config_from_pem_with_ca(
            cert_path.to_str().unwrap(),
            key_path.to_str().unwrap(),
            "",
        )
        .expect("加载自签证书");
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let registry = Arc::new(Registry::unlimited());
        let auth: DashboardAuth = Arc::new(RwLock::new(Some(("u".into(), "p".into()))));
        let h = tokio::spawn(run_with_tls(
            listener,
            registry,
            auth,
            Arc::new(ServerConfig::default()),
            Some(TlsAcceptor::from(tls)),
        ));

        let mut roots = tokio_rustls::rustls::RootCertStore::empty();
        roots.add(cert.cert.der().clone()).unwrap();
        let client = tokio_rustls::rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        let connector = tokio_rustls::TlsConnector::from(Arc::new(client));
        let tcp = TcpStream::connect(addr).await.unwrap();
        let name = tokio_rustls::rustls::pki_types::ServerName::try_from("localhost").unwrap();
        let mut tls = connector.connect(name, tcp).await.expect("TLS 握手");
        tls.write_all(b"GET /api/healthz HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
            .await
            .unwrap();
        let mut buf = vec![0u8; 4096];
        let n = tls.read(&mut buf).await.unwrap();
        let text = String::from_utf8_lossy(&buf[..n]).to_ascii_lowercase();
        assert!(text.starts_with("http/1.1 200"), "实际响应：{text}");
        assert!(
            text.contains("strict-transport-security: max-age=31536000"),
            "HTTPS 必须带 HSTS：{text}"
        );
        h.abort();
    }

    // ==================================================================
    // NFRP-05：`/api/status` 必须是合法 JSON
    // ==================================================================

    /// 远端可控字段带控制字符时，输出**仍然必须是合法 JSON**。
    ///
    /// 旧实现用 `format!("{:?}")`，控制字符被写成 `\u{1}`（Rust 语法），
    /// JSON 解析器直接报错 —— 面板白屏、采集器全挂。
    #[test]
    fn status_json_对控制字符仍然合法() {
        let registry = Arc::new(Registry::unlimited());
        let snap = Snapshot::default();

        // 空 registry 先保证基线是合法 JSON
        let base = status_json(&registry, &snap);
        serde_json::from_str::<serde_json::Value>(&base).expect("空状态必须是合法 JSON");

        // 含控制字符的名字：这里直接验证转义函数的行为约定
        // （Registry 里塞假客户端需要内部状态，单测层面用 serde_json 对照）
        let evil = "poc\u{1}id\nINFO 伪造行";
        let v = serde_json::json!({ "client_id": evil });
        let js = v.to_string();
        assert!(
            !js.contains("\\u{1}"),
            "绝不能出现 Rust 风格的 \\u{{1}}：{js}"
        );
        serde_json::from_str::<serde_json::Value>(&js).expect("必须是合法 JSON");
        assert!(js.contains("\\u0001"), "控制字符要转成 JSON 的 \\u0001");
    }

    /// `status_json` 的顶层键必须齐全（改实现时别把字段弄丢）。
    #[test]
    fn status_json_字段齐全() {
        let registry = Arc::new(Registry::unlimited());
        let snap = Snapshot::default();
        let v: serde_json::Value =
            serde_json::from_str(&status_json(&registry, &snap)).expect("合法 JSON");
        for key in [
            "status",
            "clients",
            "visitors",
            "ports",
            "p2p_enabled",
            "limits",
        ] {
            assert!(v.get(key).is_some(), "缺少字段 {key}：{v}");
        }
        assert!(v["clients"].is_array());
        assert!(v["visitors"].is_array());
        assert!(v["limits"]["max_clients"].is_number());
    }

    // ==================================================================
    // NFRP-13：重复 Authorization 必须拒绝
    // ==================================================================

    #[test]
    fn 重复_authorization_被判为畸形() {
        let one = "GET / HTTP/1.1\r\nAuthorization: Basic YQ==\r\n\r\n";
        assert_eq!(
            unique_header(one, "authorization"),
            Ok(Some("Basic YQ==".to_string()))
        );

        let two = "GET / HTTP/1.1\r\nAuthorization: Basic bad\r\nAuthorization: Basic good\r\n\r\n";
        assert!(
            unique_header(two, "authorization").is_err(),
            "出现两个 Authorization 必须报错（不能取第一个）"
        );

        // 反向顺序也一样
        let two2 =
            "GET / HTTP/1.1\r\nAuthorization: Basic good\r\nAuthorization: Basic bad\r\n\r\n";
        assert!(unique_header(two2, "authorization").is_err());

        // 没有该头 ⇒ Ok(None)
        assert_eq!(
            unique_header("GET / HTTP/1.1\r\n\r\n", "authorization"),
            Ok(None)
        );
    }

    #[test]
    fn 重复_authorization_返回_400() {
        // 起一个最小面板，发两个 Authorization，必须 400
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            let (addr, _h) = spawn_dashboard_with(false).await;
            use tokio::io::{AsyncReadExt, AsyncWriteExt};
            let evil = concat!(
                "GET /api/status HTTP/1.1\r\n",
                "Host: x\r\n",
                "Authorization: Basic dTpw\r\n",
                "Authorization: Basic dTpw\r\n",
                "Connection: close\r\n\r\n"
            );
            let mut s = tokio::net::TcpStream::connect(addr).await.expect("连面板");
            s.write_all(evil.as_bytes()).await.expect("发请求");
            let mut buf = Vec::new();
            let _ = s.read_to_end(&mut buf).await;
            let body = String::from_utf8_lossy(&buf).to_string();
            assert!(
                body.starts_with("HTTP/1.1 400"),
                "重复 Authorization 必须 400，实际：{}",
                &body[..body.len().min(80)]
            );
        });
    }

    // ==================================================================
    // v0.6.6：`assetsDir`（面板静态资源目录）
    // ==================================================================

    /// 造一个临时资源目录。
    fn tmp_assets(tag: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("nfrp-assets-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    /// 没配目录时**一个字节都不多读**（默认行为不变）。
    #[test]
    fn assets_dir_为空时不读文件() {
        assert!(load_asset("", "index.html").is_none());
        assert!(load_asset("   ", "index.html").is_none());
    }

    /// 正常读取，并按扩展名给 MIME。
    #[test]
    fn assets_dir_能读文件且_mime_正确() {
        let d = tmp_assets("ok");
        std::fs::write(d.join("index.html"), b"<h1>hi</h1>").unwrap();
        std::fs::write(d.join("app.css"), b"body{}").unwrap();
        std::fs::write(d.join("blob.bin"), b"\x00\x01").unwrap();

        let dir = d.to_string_lossy().into_owned();
        let (body, ctype) = load_asset(&dir, "/index.html").expect("index.html 应当读到");
        assert_eq!(body, b"<h1>hi</h1>");
        assert!(ctype.starts_with("text/html"));

        let (_, ctype) = load_asset(&dir, "/app.css").expect("app.css 应当读到");
        assert!(ctype.starts_with("text/css"));

        // 未知扩展名按二进制（不要把未知内容当 HTML 渲染，那是 XSS 面）
        let (_, ctype) = load_asset(&dir, "/blob.bin").expect("blob.bin 应当读到");
        assert_eq!(ctype, "application/octet-stream");

        // 不存在的文件
        assert!(load_asset(&dir, "/nope.html").is_none());

        let _ = std::fs::remove_dir_all(&d);
    }

    /// ★ 目录穿越必须被挡：`../`、绝对路径、盘符一律拒。
    #[test]
    fn assets_dir_挡住目录穿越() {
        let d = tmp_assets("trav");
        std::fs::create_dir_all(d.join("sub")).unwrap();
        std::fs::write(d.join("index.html"), b"ok").unwrap();
        // 在**父目录**放一个秘密文件，穿越成功就能读到它
        let parent = d
            .parent()
            .unwrap()
            .join(format!("nfrp-secret-{}.txt", std::process::id()));
        std::fs::write(&parent, b"TOP-SECRET").unwrap();

        let dir = d.to_string_lossy().into_owned();

        for evil in [
            "../nfrp-secret-1.txt",
            "/../index.html/../../etc/passwd",
            "..",
            "sub/../../x",
            "C:\\Windows\\win.ini",
            "..\\..\\etc\\passwd",
        ] {
            assert!(
                load_asset(&dir, evil).is_none(),
                "穿越路径 [{evil}] 必须被拒，绝不能读到目录外的东西"
            );
        }

        // 子目录里的正常文件仍可读
        std::fs::write(d.join("sub/a.js"), b"1").unwrap();
        assert!(load_asset(&dir, "/sub/a.js").is_some(), "子目录内应可读");

        let _ = std::fs::remove_dir_all(&d);
        let _ = std::fs::remove_file(&parent);
    }

    /// 配了 assets_dir 时，`/` 返回目录里的 index.html；没配则用内嵌 HTML。
    #[tokio::test]
    async fn assets_dir_影响面板首页() {
        let d = tmp_assets("home");
        std::fs::write(d.join("index.html"), b"<h1>custom panel</h1>").unwrap();
        let dir = d.to_string_lossy().into_owned();

        let (addr, _h) = spawn_dashboard_with_assets(&dir).await;
        let resp = http_req(addr, "GET", "/", Some(("u", "p"))).await;
        assert!(resp.contains("custom panel"), "应当返回自定义面板：{resp}");
        // 安全头仍在
        assert!(resp.to_ascii_lowercase().contains("x-frame-options: deny"));

        // 换成空目录 ⇒ 回退到内嵌面板
        let empty = tmp_assets("home-empty");
        let (addr2, _h2) = spawn_dashboard_with_assets(&empty.to_string_lossy()).await;
        let resp2 = http_req(addr2, "GET", "/", Some(("u", "p"))).await;
        assert!(
            resp2.contains("<!DOCTYPE html>") || resp2.contains("<html"),
            "空目录应当回退到内嵌面板：{}",
            &resp2[..resp2.len().min(120)]
        );

        let _ = std::fs::remove_dir_all(&d);
        let _ = std::fs::remove_dir_all(&empty);
    }

    /// ★ v0.6.5：`/metrics` 默认关闭时返回 404，并提示怎么开。
    #[tokio::test]
    async fn metrics_default_is_disabled() {
        let (addr, _h) = spawn_dashboard().await;
        let resp = http_req(addr, "GET", "/metrics", Some(("u", "p"))).await;
        assert!(
            resp.starts_with("HTTP/1.1 404"),
            "未开 enablePrometheus 时 /metrics 必须 404：{resp}"
        );
        assert!(
            resp.contains("enablePrometheus"),
            "提示里要写清怎么开启：{resp}"
        );

        // 健康探针**不受**这个开关影响 —— 否则容器会被反复重启
        let hz = http_req(addr, "GET", "/api/healthz", None).await;
        assert!(
            hz.starts_with("HTTP/1.1 200"),
            "healthz 必须永远可用，与 enablePrometheus 无关：{hz}"
        );
    }

    /// 开启后 `/metrics` 正常工作，且 HEAD 仍然不返回 body。
    #[tokio::test]
    async fn head_works_on_metrics_when_enabled() {
        let (addr, _h) = spawn_dashboard_with(true).await;

        let get = http_req(addr, "GET", "/metrics", Some(("u", "p"))).await;
        assert!(get.starts_with("HTTP/1.1 200"), "开启后应当 200：{get}");
        assert!(get.contains("nfrp_uptime_seconds"), "应当有指标内容：{get}");

        let head = http_req(addr, "HEAD", "/metrics", Some(("u", "p"))).await;
        let head_end = head.find("\r\n\r\n").expect("必须有头尾分隔");
        assert!(
            head[head_end + 4..].is_empty(),
            "HEAD /metrics 也不能返回 body：{head}"
        );
    }

    /// ★ PT-03：`HEAD` **不得**返回响应体（RFC 9110 §9.3.2）。
    ///
    /// 修复前：`HEAD /` 会回 10368 字节 HTML，`HEAD /api/status` 回 659 字节。
    /// 但 `Content-Length` **必须照常是真实 body 长度** —— 那正是 HEAD 的语义。
    #[tokio::test]
    async fn head_returns_headers_without_body() {
        let (addr, _h) = spawn_dashboard().await;

        // ★ v0.6.5：`/metrics` 已改为默认关闭（`enablePrometheus`），
        //   spawn_dashboard() 用的是默认配置，所以这里不能再断言它 200。
        //   它的 HEAD 语义由 `head_works_on_metrics_when_enabled` 覆盖。
        for path in ["/", "/api/status", "/api/healthz"] {
            let resp = http_req(addr, "HEAD", path, Some(("u", "p"))).await;

            // 状态行 + 头部分
            let head_end = resp.find("\r\n\r\n").expect("响应必须有头尾分隔");
            let head = &resp[..head_end];
            let body = &resp[head_end + 4..];

            assert!(
                resp.starts_with("HTTP/1.1 200"),
                "HEAD {path} 应当 200：{resp}"
            );
            assert!(
                body.is_empty(),
                "★ HEAD {path} 绝不能返回 body，实际多回 {} 字节：{:?}",
                body.len(),
                &body[..body.len().min(80)]
            );
            // Content-Length 仍然要按真实长度给
            assert!(
                head.to_ascii_lowercase().contains("content-length:"),
                "HEAD {path} 仍须给 Content-Length：{head}"
            );
        }
    }

    /// 对照：同一个路径用 GET 必须**照常**返回 body。
    ///
    /// 这条防的是"把 HEAD 的修法扩大到 GET 上"——那会把面板变成空白页。
    #[tokio::test]
    async fn get_still_returns_body() {
        let (addr, _h) = spawn_dashboard().await;
        let resp = http_req(addr, "GET", "/", Some(("u", "p"))).await;
        let body = resp.split("\r\n\r\n").nth(1).unwrap_or("");
        assert!(!body.is_empty(), "GET / 必须有 body：{resp}");
        assert!(body.contains("<html"), "GET / 应当是 HTML 页面");
    }

    /// ★ PT-07：只读端点**不接受 POST**，必须回 405。
    ///
    /// 修复前 `POST /api/status` 会落进 `match path` 的只读分支，返回
    /// 200 + 完整状态 JSON —— 只按"200 就算成功"的客户端会误判。
    #[tokio::test]
    async fn post_to_readonly_endpoint_is_405() {
        let (addr, _h) = spawn_dashboard().await;

        for path in ["/api/status", "/metrics", "/"] {
            let resp = http_req(addr, "POST", path, Some(("u", "p"))).await;
            assert!(
                resp.starts_with("HTTP/1.1 405"),
                "★ POST {path} 必须 405，实际：{}",
                resp.lines().next().unwrap_or("")
            );
            assert!(
                resp.to_ascii_lowercase().contains("allow:"),
                "405 应当带 Allow 头告诉调用方该用什么方法：{resp}"
            );
        }

        // 真正的写接口不受影响
        let resp = http_req(addr, "POST", "/api/clients/kick", Some(("u", "p"))).await;
        assert!(
            !resp.starts_with("HTTP/1.1 405"),
            "写接口不能被 405 拦掉：{resp}"
        );
    }

    /// ★ PT-05：所有响应都要带安全头。
    #[tokio::test]
    async fn security_headers_on_every_response() {
        let (addr, _h) = spawn_dashboard().await;

        // 覆盖成功、未鉴权、方法不允许三类响应
        let cases = [
            ("GET", "/", Some(("u", "p"))),
            ("GET", "/api/status", Some(("u", "p"))),
            ("GET", "/api/status", None),              // 401
            ("POST", "/api/status", Some(("u", "p"))), // 405
            ("GET", "/api/healthz", None),             // 免鉴权
        ];

        for (method, path, auth) in cases {
            let resp = http_req(addr, method, path, auth).await;
            let lower = resp.to_ascii_lowercase();
            for h in [
                "x-content-type-options: nosniff",
                "x-frame-options: deny",
                "referrer-policy: no-referrer",
                "content-security-policy:",
            ] {
                assert!(
                    lower.contains(h),
                    "★ {method} {path} 缺少安全头 {h}：\n{resp}"
                );
            }
        }
    }

    /// 401 的 `WWW-Authenticate` 不能被安全头挤掉 —— 那是 Basic Auth 的协议要求。
    #[tokio::test]
    async fn unauthorized_still_carries_www_authenticate() {
        let (addr, _h) = spawn_dashboard().await;
        let resp = http_req(addr, "GET", "/api/status", None).await;
        assert!(resp.starts_with("HTTP/1.1 401"), "{resp}");
        assert!(
            resp.to_ascii_lowercase()
                .contains("www-authenticate: basic realm=\"nfrp\""),
            "401 必须带 WWW-Authenticate：{resp}"
        );
        // 同时也要有安全头
        assert!(
            resp.to_ascii_lowercase().contains("x-frame-options: deny"),
            "401 同样要带安全头：{resp}"
        );
    }

    /// `webServer.pprofEnable` 默认关闭时必须真的是 404，而不是只把字段读进来；
    /// 打开后索引页可用，且 HEAD 不返回 body。
    #[tokio::test]
    async fn pprof_disabled_is_404_and_index_when_enabled_is_200() {
        let (addr, _h) = spawn_dashboard().await;
        for path in [
            "/debug/pprof",
            "/debug/pprof/",
            "/debug/pprof/profile?seconds=1",
        ] {
            let resp = http_req(addr, "GET", path, Some(("u", "p"))).await;
            assert!(
                resp.starts_with("HTTP/1.1 404"),
                "默认关闭必须是 404：{resp}"
            );
            assert!(
                resp.contains("pprof disabled"),
                "错误要说清怎么打开：{resp}"
            );
        }

        let (addr, _h) = spawn_dashboard_cfg(ServerConfig {
            pprof_enable: true,
            ..Default::default()
        })
        .await;
        for path in ["/debug/pprof", "/debug/pprof/"] {
            let resp = http_req(addr, "GET", path, Some(("u", "p"))).await;
            assert!(
                resp.starts_with("HTTP/1.1 200"),
                "打开后索引页应 200：{resp}"
            );
            assert!(
                resp.contains("GET /debug/pprof/profile?seconds=N"),
                "{resp}"
            );
        }
        let head = http_req(addr, "HEAD", "/debug/pprof", Some(("u", "p"))).await;
        assert!(head.starts_with("HTTP/1.1 200"), "{head}");
        assert_eq!(
            head.split("\r\n\r\n").nth(1).unwrap_or(""),
            "",
            "HEAD 不能返回索引 body：{head}"
        );
    }

    /// Windows 没有 perf signal/`ucontext_t`，端点必须明确 501，不能 500 或挂住。
    #[cfg(not(unix))]
    #[tokio::test]
    async fn pprof_profile_on_windows_is_501() {
        let (addr, _h) = spawn_dashboard_cfg(ServerConfig {
            pprof_enable: true,
            ..Default::default()
        })
        .await;
        let resp = http_req(
            addr,
            "GET",
            "/debug/pprof/profile?seconds=1",
            Some(("u", "p")),
        )
        .await;
        assert!(resp.starts_with("HTTP/1.1 501"), "{resp}");
        assert!(resp.contains("only supported on Unix"), "{resp}");
    }

    /// Unix 上真正跑一次 1 秒 CPU profile，验证 200 + protobuf 二进制响应，
    /// 而不是只验证路由分支。
    #[cfg(unix)]
    #[tokio::test]
    async fn pprof_profile_on_unix_returns_protobuf() {
        let (addr, _h) = spawn_dashboard_cfg(ServerConfig {
            pprof_enable: true,
            ..Default::default()
        })
        .await;
        let resp = http_req(
            addr,
            "GET",
            "/debug/pprof/profile?seconds=1",
            Some(("u", "p")),
        )
        .await;
        assert!(resp.starts_with("HTTP/1.1 200"), "{resp}");
        assert!(
            resp.to_ascii_lowercase()
                .contains("content-type: application/octet-stream"),
            "{resp}"
        );
        let body = resp.split("\r\n\r\n").nth(1).unwrap_or("");
        assert!(!body.is_empty(), "profile body 不能为空：{resp}");
    }

    /// 安全头常量本身要合理：不能为空、不能有重复名。
    #[test]
    fn sec_headers_are_sane() {
        assert!(!SEC_HEADERS.is_empty(), "安全头不能是空的");
        let names: Vec<String> = SEC_HEADERS
            .iter()
            .map(|(k, _)| k.to_ascii_lowercase())
            .collect();
        let mut dedup = names.clone();
        dedup.sort();
        dedup.dedup();
        assert_eq!(dedup.len(), names.len(), "安全头里有重复的名字：{names:?}");

        // 合并后的数组必须包含原头 + 全部安全头
        assert_eq!(SEC_HEADERS_WITH_AUTH[0].0, "WWW-Authenticate");
        assert_eq!(SEC_HEADERS_WITH_ALLOW[0].0, "Allow");
        assert_eq!(SEC_HEADERS_WITH_AUTH.len(), SEC_HEADERS.len() + 1);
        assert_eq!(SEC_HEADERS_WITH_ALLOW.len(), SEC_HEADERS.len() + 1);
        // 合并数组的后半段就是 SEC_HEADERS 本身
        assert_eq!(&SEC_HEADERS_WITH_AUTH[1..], SEC_HEADERS);
        assert_eq!(&SEC_HEADERS_WITH_ALLOW[1..], SEC_HEADERS);
    }
}
