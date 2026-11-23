//! 面板 API v2：版本化路径 + 统一错误信封 + 分页。
//!
//! # 为什么要另起一套
//!
//! v1 的接口是"能用就行"的产物，用久了会疼在三个地方：
//!
//! 1. **路径不带版本**。`/api/status` 里想改个字段名，所有写好的脚本
//!    当天全挂。有了 `/api/v2/` 前缀，就能"v2 加字段、v1 永远保持原样"。
//! 2. **错误格式是散的**。成功回 `{"ok":true,...}`、失败回
//!    `{"ok":false,"error":"人话"}`，客户端得写两套判断；而且错误里只有
//!    文案没有**机器可读的错误码**，脚本没法分支，文案一改就全崩。
//!    现在失败一律 `{"error":{"code","message","details"}}`。
//! 3. **列表不分页**。`/api/status` 一次性把全部客户端塞进一个 JSON，
//!    几千个客户端时面板直接卡死。v2 的列表接口一律 `page` / `page_size`，
//!    并在 `pagination` 里回总条数与总页数。
//!
//! # 硬约束：v1 一个字节都不改
//!
//! 老面板页面、老脚本、Prometheus 抓取全都继续照常工作。v2 只做加法，
//! 所以 [`route`] 对任何非 `/api/v2/` 的路径都返回 `None`，由 v1 的
//! 老代码去处理。

use std::{collections::BTreeMap, sync::Arc};

use nfrp_common::config::{ProxyConfig, ServerConfig};

use crate::{admin, audit::AuditFilter, observability::encode_json, registry::Registry};

/// 所有 v2 路径的前缀。
pub const PREFIX: &str = "/api/v2";

/// 响应顶层回显的 API 版本号。
const API_VERSION: &str = "v2";

/// 单页默认条数。
pub const DEFAULT_PAGE_SIZE: usize = 20;

/// 单页条数上限。
///
/// 设上限是**为了保护服务端**：`?page_size=100000000` 这种请求会让
/// 我们先把全部记录 clone 进一个 Vec 再截断，等于给对方一个免费的
/// 内存放大器。500 对任何面板页面都够用。
pub const MAX_PAGE_SIZE: usize = 500;

/// 机器可读的错误码。
///
/// 这些字符串是**接口契约的一部分**，客户端会拿它们做分支，
/// 因此不能随手改；要改就得开 v3。
pub mod code {
    /// 请求本身有问题（缺字段、类型不对、分页参数非法）。
    pub const BAD_REQUEST: &str = "bad_request";
    /// 资源不存在（比如要操作的客户端不在线）。
    pub const NOT_FOUND: &str = "not_found";
    /// 路径存在，但用的 HTTP 方法不对。
    pub const METHOD_NOT_ALLOWED: &str = "method_not_allowed";
    /// 请求合法，但操作没能完成（客户端拒绝、超时…）。
    pub const ADMIN_FAILED: &str = "admin_failed";
    /// 服务端内部问题。
    pub const INTERNAL: &str = "internal";
}

/// 一次 v2 请求的响应。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Response {
    pub status: u16,
    pub body: String,
}

impl Response {
    fn json(status: u16, body: String) -> Self {
        Self { status, body }
    }
}

/// v2 的错误类型。::to_json 产出的就是统一信封。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApiError {
    pub status: u16,
    pub code: &'static str,
    pub message: String,
    pub details: Option<serde_json::Value>,
}

impl ApiError {
    fn new(status: u16, code: &'static str, message: impl Into<String>) -> Self {
        Self {
            status,
            code,
            message: message.into(),
            details: None,
        }
    }

    pub fn bad_request(message: impl Into<String>) -> Self {
        Self::new(400, code::BAD_REQUEST, message)
    }

    pub fn not_found(message: impl Into<String>) -> Self {
        Self::new(404, code::NOT_FOUND, message)
    }

    pub fn method_not_allowed(message: impl Into<String>) -> Self {
        Self::new(405, code::METHOD_NOT_ALLOWED, message)
    }

    /// 管理操作没做成：请求没错，是**下游**（客户端）不配合。
    ///
    /// 用 502 而不是 400 是要让调用方能一眼区分"我发错了"和
    /// "对端没干成"—— 前者重试没用，后者值得重试。
    pub fn admin_failed(message: impl Into<String>) -> Self {
        Self::new(502, code::ADMIN_FAILED, message)
    }

    pub fn internal(message: impl Into<String>) -> Self {
        Self::new(500, code::INTERNAL, message)
    }

    pub fn with_details(mut self, details: serde_json::Value) -> Self {
        self.details = Some(details);
        self
    }

    /// 统一错误信封。
    fn to_json(&self) -> String {
        let mut err = serde_json::json!({
            "code": self.code,
            "message": self.message,
        });
        if let Some(d) = &self.details {
            err["details"] = d.clone();
        }
        serde_json::json!({ "api": API_VERSION, "error": err }).to_string()
    }

    /// 按 `detailedErrorsToClient` 决定是否脱敏。
    ///
    /// * `detailed_errors_to_client = true`（默认，与官方一致）⇒ **逐字不变**
    ///   （仍走 [`Self::to_json`]）；
    /// * `false` ⇒ 只回**状态码 + 错误码**，`message` 换成一句通用文案，
    ///   `details` 整个去掉。
    ///
    /// # 为什么保留错误码
    ///
    /// 错误码（`bad_request` / `not_found` / `admin_failed` …）是**调用方编程用**的，
    /// 不含任何租户信息；去掉它会让关掉详细错误的部署完全无法自动化。
    /// 真正需要脱敏的是 `message` 与 `details` —— 它们才含
    /// "域名已被代理 alice.web 占用"这类**别人的代理名**。
    fn to_json_redacted(&self, cfg: &ServerConfig) -> String {
        if cfg.detailed_errors_to_client {
            return self.to_json();
        }
        serde_json::json!({
            "api": API_VERSION,
            "error": {
                "code": self.code,
                "message": "request failed（detailedErrorsToClient = false，详情见服务端日志）",
            }
        })
        .to_string()
    }
}

/// 解析后的 query string。
pub type Query = BTreeMap<String, String>;

/// 分页参数。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Page {
    /// 从 **1** 开始（不是 0）—— 面板 URL 上写 `?page=0` 会让人以为出错。
    pub page: usize,
    pub size: usize,
}

impl Default for Page {
    fn default() -> Self {
        Self {
            page: 1,
            size: DEFAULT_PAGE_SIZE,
        }
    }
}

impl Page {
    pub fn offset(&self) -> usize {
        self.page.saturating_sub(1).saturating_mul(self.size)
    }

    /// 总页数。空集合也算 1 页（`total_pages: 0` 会让前端的分页器算出 0/0）。
    pub fn total_pages(&self, total: usize) -> usize {
        if self.size == 0 {
            return 1;
        }
        total.div_ceil(self.size).max(1)
    }

    /// 从 query 解析。
    ///
    /// 非法值**直接报错**而不是悄悄退回默认值：面板上写错 `page_size=abc`
    /// 却拿到"看起来正常"的第一页，用户会以为自己翻页成功了。
    pub fn from_query(q: &Query) -> Result<Self, ApiError> {
        let mut p = Self::default();
        if let Some(v) = q.get("page") {
            let t = v.trim();
            if !t.is_empty() {
                let n: usize = t
                    .parse()
                    .map_err(|_| ApiError::bad_request(format!("page 必须是正整数，收到 {t:?}")))?;
                if n == 0 {
                    return Err(ApiError::bad_request("page 从 1 开始"));
                }
                p.page = n;
            }
        }
        // 两种写法都收：下划线是 URL 惯例，驼峰是前端习惯
        if let Some(v) = q.get("page_size").or_else(|| q.get("pageSize")) {
            let t = v.trim();
            if !t.is_empty() {
                let n: usize = t.parse().map_err(|_| {
                    ApiError::bad_request(format!("page_size 必须是正整数，收到 {t:?}"))
                })?;
                if n == 0 {
                    return Err(ApiError::bad_request("page_size 必须大于 0"));
                }
                if n > MAX_PAGE_SIZE {
                    return Err(ApiError::bad_request(format!(
                        "page_size 最大 {MAX_PAGE_SIZE}，收到 {n}"
                    )));
                }
                p.size = n;
            }
        }
        Ok(p)
    }
}

/// 把 `a=1&b=2` 拆成键值对（键与值都做百分号解码）。
///
/// 实现放在 `common::http1` 里，客户端的管理面板用同一份 ——
/// 解析规则各写一遍，迟早会在"`+` 算不算空格"这种细节上漂移。
pub fn parse_query(raw: &str) -> Query {
    nfrp_common::http1::parse_query(raw)
}

/// 只接受 GET 的路径。
const GET_PATHS: &[&str] = &[
    "",
    "/",
    "/version",
    "/status",
    "/clients",
    "/proxies",
    "/visitors",
    "/ports",
    "/audit",
];

/// 只接受 POST 的路径（写操作）。
const POST_PATHS: &[&str] = &["/proxies/add", "/proxies/remove", "/clients/kick"];

/// 尝试按 v2 处理一条请求。
///
/// 返回 `None` 表示"这不是 v2 的路径"，调用方应当继续走 v1 的老分支 ——
/// 这正是"v1 零行为变化"的实现方式：v2 拦不到的请求一个字节都不碰。
pub async fn route(
    registry: &Arc<Registry>,
    cfg: &Arc<ServerConfig>,
    method: &str,
    path: &str,
    query: &str,
    body: &str,
) -> Option<Response> {
    let rest = path.strip_prefix(PREFIX)?;
    let q = parse_query(query);
    Some(
        match dispatch(registry, cfg, method, rest, &q, body).await {
            Ok(r) => r,
            // **走 `detailedErrorsToClient` 脱敏**。
            //
            // 原先这里直接回 `e.to_json()` —— 而 v2 的错误文案里含
            // **别的租户的代理名 / 客户端名 / 端口占用情况**
            // （如"域名 x 已被代理 alice.web 占用"）。
            //
            // 同一个错误在 `serve.rs` 的客户端路径上**套了** `cfg.error_to_client()`
            // （那里注释明确写着"详细错误里往往带着别人的代理名 / 端口占用"），
            // 而面板这条路径**没套** —— 又是"同一语义只加固了一半"。
            //
            // 只在 `detailed_errors_to_client = false` 时改变行为；
            //   默认（true，与官方一致）**逐字不变**。
            Err(e) => Response::json(e.status, e.to_json_redacted(cfg)),
        },
    )
}

async fn dispatch(
    registry: &Arc<Registry>,
    cfg: &Arc<ServerConfig>,
    method: &str,
    rest: &str,
    q: &Query,
    body: &str,
) -> Result<Response, ApiError> {
    let m = method.to_ascii_uppercase();
    let out = match (m.as_str(), rest) {
        ("GET", "" | "/") | ("GET", "/version") => Ok(version_response()),
        ("GET", "/status") => Ok(status_response(registry)),
        ("GET", "/clients") => clients_response(registry, q),
        ("GET", "/proxies") => proxies_response(registry, q),
        ("GET", "/visitors") => visitors_response(registry, q),
        ("GET", "/ports") => Ok(ports_response(registry)),
        ("GET", "/audit") => audit_response(registry, q),
        ("POST", "/proxies/add") => add_proxy_response(registry, cfg, body).await,
        ("POST", "/proxies/remove") => remove_proxy_response(registry, body).await,
        ("POST", "/clients/kick") => kick_response(registry, body).await,
        _ => {
            // 路径对但方法不对，要给 405 而不是 404 ——
            // 前者能让调用方立刻发现自己漏了 POST，后者会被误当成"接口写错了"
            if GET_PATHS.contains(&rest) || POST_PATHS.contains(&rest) {
                Err(ApiError::method_not_allowed(format!(
                    "{PREFIX}{rest} 不支持 {m}"
                )))
            } else {
                Err(ApiError::not_found(format!(
                    "API v2 里没有 {PREFIX}{rest}（可用：{}）",
                    GET_PATHS
                        .iter()
                        .chain(POST_PATHS.iter())
                        .filter(|p| !p.is_empty())
                        .map(|p| format!("{PREFIX}{p}"))
                        .collect::<Vec<_>>()
                        .join(" ")
                )))
            }
        }
    };
    out
}

// ---------------------------------------------------------------------------
// 读接口
// ---------------------------------------------------------------------------

fn data_response(v: serde_json::Value) -> Response {
    Response::json(
        200,
        serde_json::json!({ "api": API_VERSION, "data": v }).to_string(),
    )
}

fn list_response(items: serde_json::Value, page: Page, total: usize) -> Response {
    Response::json(
        200,
        serde_json::json!({
            "api": API_VERSION,
            "data": items,
            "pagination": {
                "page": page.page,
                "page_size": page.size,
                "total": total,
                "total_pages": page.total_pages(total),
            }
        })
        .to_string(),
    )
}

fn version_response() -> Response {
    data_response(serde_json::json!({
        "api": API_VERSION,
        "server": env!("CARGO_PKG_VERSION"),
        // 本进程能说哪几代 frp 线协议。客户端据此决定要不要降级。
        "wire_protocols": ["v1", "v2"],
        "frp_wire_version": nfrp_common::frp::FRP_WIRE_VERSION,
    }))
}

fn status_response(registry: &Registry) -> Response {
    let snap = registry.observ.snapshot();
    let clients = registry.clients();
    let proxy_count: usize = clients.iter().map(|c| c.proxies.len()).sum();
    let limits = registry.limits();
    // 指标是手写导出的（`encode_json`），这里转成 Value 嵌进 data 里，
    // 免得同一份指标写两遍序列化逻辑。
    let metrics = serde_json::from_str::<serde_json::Value>(&encode_json(&snap))
        .unwrap_or(serde_json::Value::Null);
    data_response(serde_json::json!({
        "metrics": metrics,
        "counts": {
            "clients": clients.len(),
            "clients_online": snap.clients_active,
            "proxies": proxy_count,
            "visitors": registry.visitors.list().len(),
            "reserved_ports": registry.reserved_ports().len(),
        },
        "limits": {
            "max_clients": limits.max_clients,
            "max_total_conns": limits.max_total_conns,
            "max_conns_per_client": limits.max_conns_per_client,
        },
        "features": {
            "p2p": registry.p2p().is_some(),
            "vnet": registry.vnet().is_some(),
            "vhost": registry.vhosts().is_some(),
            "audit": registry.audit().is_enabled(),
        },
        "audit": {
            "enabled": registry.audit().is_enabled(),
            "buffered": registry.audit().len(),
            "total": registry.audit().total(),
        },
    }))
}

fn clients_response(registry: &Registry, q: &Query) -> Result<Response, ApiError> {
    // 不带过滤条件即全平台枚举 ⇒ 必须显式 ?all=1
    require_explicit_enumeration(q, "/api/v2/clients")?;
    let page = Page::from_query(q)?;
    let user = q.get("user").map(String::as_str).unwrap_or("");
    let needle = q
        .get("q")
        .map(|s| s.to_ascii_lowercase())
        .unwrap_or_default();

    let mut all: Vec<serde_json::Value> = registry
        .clients()
        .into_iter()
        .filter(|c| user.is_empty() || c.user == user)
        .filter(|c| {
            needle.is_empty()
                || c.client_id.to_ascii_lowercase().contains(&needle)
                || c.run_id.to_ascii_lowercase().contains(&needle)
                || c.user.to_ascii_lowercase().contains(&needle)
        })
        .map(|c| {
            serde_json::json!({
                "run_id": c.run_id,
                "client_id": c.client_id,
                "user": c.user,
                "proxies": c.proxies.len(),
                "proxy_names": c.proxies,
                "backlog": c.backlog,
                "idle_work_conns": c.idle_work_conns,
                "managed": c.managed,
            })
        })
        .collect();

    // **必须排序**：注册表是 HashMap，迭代顺序每次都不一样。
    // 不排序的话第 1 页和第 2 页会随机重叠/漏掉条目 —— 分页会变成"看起来能翻"。
    all.sort_by(|a, b| a["run_id"].as_str().cmp(&b["run_id"].as_str()));

    let total = all.len();
    let page_items: Vec<serde_json::Value> = all
        .into_iter()
        .skip(page.offset())
        .take(page.size)
        .collect();
    Ok(list_response(
        serde_json::Value::Array(page_items),
        page,
        total,
    ))
}

/// **枚举门槛**：不带任何过滤条件时，必须显式写 `?all=1`
///
/// # 问题
///
/// `/clients`、`/proxies`、`/visitors`、`/audit` 原先在**不传 `user` 时返回全平台数据**：
///
/// ```text
/// .filter(|c| user.is_empty() || c.user == user)   // user 为空 ⇒ 全部放行
/// ```
///
/// 而 `run_id` / 代理名正是写接口（`POST /clients/kick`、`/proxies/remove`）
/// 的**主键** ⇒ **读接口直接喂出了写接口所需的全部标识**。
///
/// # 影响（诚实定位）
///
/// * 写接口仍受 `allow_manage`（RBAC）拦截 ⇒ **配了 `[[roles]]` 的部署下不构成越权**；
/// * 但**默认配置（无 roles）**下 `role_for` 对任何用户返回 `unrestricted`
///   ⇒ **面板凭据即等于全平台管理权**。
///
/// 另需明确：`api_v2` 挂在面板之下，**需要面板 Basic 凭据** ——
/// 它不是一个未认证接口。所以这不是"匿名可达"，而是
/// "面板凭据的权限边界比使用者以为的更宽"。
///
/// # 修法与其局限（如实说明）
///
/// 要求显式 `?all=1`：**不能阻止**持有面板凭据的人枚举，
/// 但能让"全量导出"成为一个**有意识的选择**而不是默认行为，
/// 也让审计日志 / 反向代理日志里能看出这是一次全量查询。
///
/// 根本解法是给面板引入**只读角色**（面板凭据 → 受限 scope），
///   那是一次接口与配置的扩展，不在本轮范围（已记进 SECURITY-FIXES-ROUND5.md）。
///
/// `/status` 与 `/version` **不适用**本门槛：它们只回聚合计数、
/// 不含任何租户标识。
fn require_explicit_enumeration(q: &Query, what: &str) -> Result<(), ApiError> {
    // 这些键任一非空都算"有过滤条件"（`kind`/`ok` 是 /audit 专有的）
    let has_filter = ["user", "client", "q", "kind", "ok"]
        .iter()
        .any(|k| q.get(*k).is_some_and(|v| !v.trim().is_empty()));
    if has_filter {
        return Ok(());
    }
    // `all=1` / `all=true` / `all=yes` 都认（大小写不敏感）
    let all = q
        .get("all")
        .map(|v| {
            let v = v.trim().to_ascii_lowercase();
            v == "1" || v == "true" || v == "yes"
        })
        .unwrap_or(false);
    if all {
        return Ok(());
    }
    Err(ApiError::bad_request(format!(
        "{what} 的全量枚举需要显式确认：请加过滤条件（?user= / ?client= / ?q=），\
         或显式写 ?all=1 表明你要导出全平台数据。\n\
         注意：面板凭据在全平台范围内有效，默认配置下没有租户隔离。"
    )))
}

fn proxies_response(registry: &Registry, q: &Query) -> Result<Response, ApiError> {
    // 全量枚举要显式确认
    require_explicit_enumeration(q, "/api/v2/proxies")?;
    let page = Page::from_query(q)?;
    let user = q.get("user").map(String::as_str).unwrap_or("");
    let client = q.get("client").map(String::as_str).unwrap_or("");
    let needle = q
        .get("q")
        .map(|s| s.to_ascii_lowercase())
        .unwrap_or_default();

    // 代理名在注册表里是**线上全名**（带 `{user}.` 前缀），因为
    // 那正是服务端内部表的键。这里原样给出，需要配置里那个原始名的话
    // 由调用方自己剥前缀（`util::strip_user_prefix`）。
    let mut all: Vec<serde_json::Value> = Vec::new();
    for c in registry.clients() {
        if !user.is_empty() && c.user != user {
            continue;
        }
        if !client.is_empty() && c.run_id != client && c.client_id != client {
            continue;
        }
        for name in c.proxies {
            if !needle.is_empty() && !name.to_ascii_lowercase().contains(&needle) {
                continue;
            }
            all.push(serde_json::json!({
                "name": name,
                "user": c.user,
                "client_id": c.client_id,
                "run_id": c.run_id,
            }));
        }
    }
    all.sort_by(|a, b| a["name"].as_str().cmp(&b["name"].as_str()));

    let total = all.len();
    let page_items: Vec<serde_json::Value> = all
        .into_iter()
        .skip(page.offset())
        .take(page.size)
        .collect();
    Ok(list_response(
        serde_json::Value::Array(page_items),
        page,
        total,
    ))
}

fn visitors_response(registry: &Registry, q: &Query) -> Result<Response, ApiError> {
    // 全量枚举要显式确认
    require_explicit_enumeration(q, "/api/v2/visitors")?;
    let page = Page::from_query(q)?;
    let needle = q
        .get("q")
        .map(|s| s.to_ascii_lowercase())
        .unwrap_or_default();

    let mut all: Vec<serde_json::Value> = registry
        .visitors
        .list()
        .into_iter()
        .filter(|v| needle.is_empty() || v.proxy_name.to_ascii_lowercase().contains(&needle))
        .map(|v| {
            serde_json::json!({
                "proxy_name": v.proxy_name,
                "type": v.proxy_type,
                "provider_user": v.provider_user,
                "client_id": v.client_id,
                "allow_users": v.allow_users,
            })
        })
        .collect();
    all.sort_by(|a, b| a["proxy_name"].as_str().cmp(&b["proxy_name"].as_str()));

    let total = all.len();
    let page_items: Vec<serde_json::Value> = all
        .into_iter()
        .skip(page.offset())
        .take(page.size)
        .collect();
    Ok(list_response(
        serde_json::Value::Array(page_items),
        page,
        total,
    ))
}

fn ports_response(registry: &Registry) -> Response {
    let ports: Vec<serde_json::Value> = registry
        .reserved_ports()
        .into_iter()
        .map(|p| {
            // 同 group 的几个代理会共享一个端口，`backends` 就是它们 ——
            // 面板上"这个端口后面挂着谁"全靠它。
            let backends: Vec<serde_json::Value> = registry
                .backend_loads(p)
                .into_iter()
                .map(
                    |(client_id, load)| serde_json::json!({ "client_id": client_id, "load": load }),
                )
                .collect();
            serde_json::json!({ "port": p, "backends": backends })
        })
        .collect();
    data_response(serde_json::Value::Array(ports))
}

fn audit_response(registry: &Registry, q: &Query) -> Result<Response, ApiError> {
    // 审计日志含全部租户的 run_id / user / IP ⇒ 全量枚举要显式确认
    require_explicit_enumeration(q, "/api/v2/audit")?;
    let page = Page::from_query(q)?;
    let ok = match q.get("ok") {
        Some(v) if !v.trim().is_empty() => Some(parse_bool(v.trim()).ok_or_else(|| {
            ApiError::bad_request(format!("ok 只能是 true/false/1/0，收到 {v:?}"))
        })?),
        _ => None,
    };
    let filter = AuditFilter {
        kind: q.get("kind").filter(|s| !s.is_empty()).cloned(),
        user: q.get("user").filter(|s| !s.is_empty()).cloned(),
        ok,
        offset: page.offset(),
        limit: page.size,
    };
    let (total, events) = registry.audit().query(&filter);
    // 审计默认是关的。这时 `total` 为 0，前端只会看到空列表 ——
    // 一句"没配 audit"比一片空白有用得多，所以额外带上开关状态。
    let body = serde_json::to_value(&events).unwrap_or(serde_json::Value::Null);
    let mut resp = list_response(body, page, total);
    if !registry.audit().is_enabled() {
        resp.body = serde_json::json!({
            "api": API_VERSION,
            "data": serde_json::Value::Array(vec![]),
            "pagination": {
                "page": page.page,
                "page_size": page.size,
                "total": 0,
                "total_pages": 1,
            },
            "notice": "服务端未启用审计日志（在 [audit] 里配 path）",
        })
        .to_string();
    }
    Ok(resp)
}

fn parse_bool(s: &str) -> Option<bool> {
    match s.to_ascii_lowercase().as_str() {
        "true" | "1" | "yes" => Some(true),
        "false" | "0" | "no" => Some(false),
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// 写接口
// ---------------------------------------------------------------------------

fn body_value(body: &str) -> Result<serde_json::Value, ApiError> {
    if body.trim().is_empty() {
        return Ok(serde_json::Value::Null);
    }
    serde_json::from_str(body)
        .map_err(|e| ApiError::bad_request(format!("请求体不是合法 JSON：{e}")))
}

fn str_field(v: &serde_json::Value, k: &str) -> String {
    v.get(k)
        .and_then(|x| x.as_str())
        .unwrap_or_default()
        .to_string()
}

fn action_ok(message: String) -> Response {
    data_response(serde_json::json!({ "message": message }))
}

/// 管理操作的人话错误 → 带错误码的 v2 错误。
///
/// `admin::*` 返回的是给面板直接显示的中文，这里只做**分类**：
/// "没有这个客户端"是 404（路径/资源问题），其余是下游没配合。
fn admin_error(message: String) -> ApiError {
    if message.contains("没有在线客户端") {
        ApiError::not_found(message)
    } else {
        ApiError::admin_failed(message)
    }
}

async fn add_proxy_response(
    registry: &Arc<Registry>,
    cfg: &Arc<ServerConfig>,
    body: &str,
) -> Result<Response, ApiError> {
    let v = body_value(body)?;
    let run_id = str_field(&v, "run_id");
    if run_id.is_empty() {
        return Err(
            ApiError::bad_request("缺少 run_id").with_details(serde_json::json!({
                "hint": "run_id 从 GET /api/v2/clients 拿；client_id 会重复，不能当主键"
            })),
        );
    }
    let proxy = v
        .get("proxy")
        .ok_or_else(|| ApiError::bad_request("缺少 proxy 配置对象"))?;
    let p: ProxyConfig = serde_json::from_value(proxy.clone())
        .map_err(|e| ApiError::bad_request(format!("proxy 配置解析失败：{e}")))?;
    admin::add_proxy(cfg, registry, &run_id, p)
        .await
        .map(action_ok)
        .map_err(admin_error)
}

async fn remove_proxy_response(registry: &Arc<Registry>, body: &str) -> Result<Response, ApiError> {
    let v = body_value(body)?;
    let run_id = str_field(&v, "run_id");
    if run_id.is_empty() {
        return Err(ApiError::bad_request("缺少 run_id"));
    }
    let name = str_field(&v, "name");
    if name.is_empty() {
        return Err(ApiError::bad_request("缺少 name"));
    }
    admin::remove_proxy(registry, &run_id, &name)
        .await
        .map(action_ok)
        .map_err(admin_error)
}

async fn kick_response(registry: &Arc<Registry>, body: &str) -> Result<Response, ApiError> {
    let v = body_value(body)?;
    let run_id = str_field(&v, "run_id");
    if run_id.is_empty() {
        return Err(ApiError::bad_request("缺少 run_id"));
    }
    admin::kick(registry, &run_id, &str_field(&v, "reason"))
        .await
        .map(action_ok)
        .map_err(admin_error)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vhost::VhostTable;

    fn reg() -> Arc<Registry> {
        Arc::new(Registry::unlimited())
    }

    fn cfg() -> Arc<ServerConfig> {
        Arc::new(ServerConfig::default())
    }

    fn body_of(r: &Response) -> serde_json::Value {
        serde_json::from_str(&r.body).expect("v2 的响应必须是合法 JSON")
    }

    /// v1 的路径必须原样放行 —— 这是"v1 零行为变化"的底线。
    #[tokio::test]
    async fn 非_v2_路径返回_none() {
        for p in [
            "/api/status",
            "/api/status.json",
            "/metrics",
            "/",
            "/api/proxies/add",
            "/api/healthz",
        ] {
            let r = route(&reg(), &cfg(), "GET", p, "", "").await;
            assert!(r.is_none(), "{p} 不该被 v2 拦下");
        }
    }

    #[tokio::test]
    async fn 版本信息带_api_与线协议() {
        let r = route(&reg(), &cfg(), "GET", "/api/v2/version", "", "")
            .await
            .expect("v2 路径");
        assert_eq!(r.status, 200);
        let v = body_of(&r);
        assert_eq!(v["api"], "v2");
        assert_eq!(v["data"]["api"], "v2");
        assert!(v["data"]["server"].is_string());
        assert_eq!(v["data"]["wire_protocols"][0], "v1");
        assert_eq!(v["data"]["wire_protocols"][1], "v2");
    }

    /// 列表接口没数据时也要给出完整的分页元信息。
    #[tokio::test]
    async fn 空列表也有分页元信息() {
        // 全量枚举现在要显式 ?all=1
        let r = route(&reg(), &cfg(), "GET", "/api/v2/clients", "?all=1", "")
            .await
            .expect("v2 路径");
        let v = body_of(&r);
        assert_eq!(v["data"].as_array().unwrap().len(), 0);
        assert_eq!(v["pagination"]["page"], 1);
        assert_eq!(v["pagination"]["page_size"], DEFAULT_PAGE_SIZE);
        assert_eq!(v["pagination"]["total"], 0);
        assert_eq!(v["pagination"]["total_pages"], 1, "空集合也算 1 页");
    }

    #[tokio::test]
    async fn 未知路径是_404_且带错误码() {
        let r = route(&reg(), &cfg(), "GET", "/api/v2/nope", "", "")
            .await
            .expect("v2 路径");
        assert_eq!(r.status, 404);
        let v = body_of(&r);
        assert_eq!(v["error"]["code"], code::NOT_FOUND);
        assert!(
            v["error"]["message"].as_str().unwrap().contains("clients"),
            "错误里要列可用路径：{}",
            v["error"]["message"]
        );
    }

    /// 路径对、方法错 → 405（不是 404）。
    #[tokio::test]
    async fn 方法不对是_405() {
        let r = route(&reg(), &cfg(), "DELETE", "/api/v2/clients", "", "")
            .await
            .expect("v2 路径");
        assert_eq!(r.status, 405);
        assert_eq!(body_of(&r)["error"]["code"], code::METHOD_NOT_ALLOWED);
    }

    #[tokio::test]
    async fn 分页参数非法要报错而不是静默用默认值() {
        for bad in ["?page=0", "?page=abc", "?page_size=0", "?page_size=abc"] {
            let r = route(&reg(), &cfg(), "GET", "/api/v2/clients", bad, "")
                .await
                .expect("v2 路径");
            assert_eq!(r.status, 400, "{bad} 应当被拒");
            assert_eq!(body_of(&r)["error"]["code"], code::BAD_REQUEST);
        }
    }

    #[tokio::test]
    async fn page_size_超上限被拒() {
        let r = route(
            &reg(),
            &cfg(),
            "GET",
            "/api/v2/clients",
            &format!("?all=1&page_size={}", MAX_PAGE_SIZE + 1),
            "",
        )
        .await
        .expect("v2 路径");
        assert_eq!(r.status, 400);
        assert!(body_of(&r)["error"]["message"]
            .as_str()
            .unwrap()
            .contains(&MAX_PAGE_SIZE.to_string()));
    }

    /// 驼峰写法也要认（前端习惯）。
    #[test]
    fn page_size_驼峰也能解析() {
        assert_eq!(
            Page::from_query(&parse_query("pageSize=5")).unwrap().size,
            5
        );
        assert_eq!(
            Page::from_query(&parse_query("page_size=5")).unwrap().size,
            5
        );
    }

    #[test]
    fn 分页偏移与总页数() {
        let p = Page { page: 3, size: 20 };
        assert_eq!(p.offset(), 40);
        assert_eq!(p.total_pages(0), 1);
        assert_eq!(p.total_pages(1), 1);
        assert_eq!(p.total_pages(20), 1);
        assert_eq!(p.total_pages(21), 2);
        assert_eq!(p.total_pages(120), 6);
        // page=1 的 offset 必须是 0，否则第一页会凭空少几条
        assert_eq!(Page { page: 1, size: 20 }.offset(), 0);
    }

    #[test]
    fn query_解析与百分号解码() {
        let q = parse_query("user=%E5%BC%A0%E4%B8%89&q=a+b&empty=&flag");
        assert_eq!(q.get("user").unwrap(), "张三");
        assert_eq!(q.get("q").unwrap(), "a b", "`+` 要当空格");
        assert_eq!(q.get("empty").unwrap(), "");
        assert_eq!(q.get("flag").unwrap(), "", "没有 = 的键当作空值");
    }

    /// 非法百分号序列不能被静默吃掉 —— 宁可原样保留，也别改用户的数据。
    /// 非法百分号序列不能被静默吃掉 —— 这条规则现在住在 `common::http1`，
    /// 两个面板共用同一份实现，这里只确认引用接对了。
    #[test]
    fn 非法百分号序列原样保留() {
        use nfrp_common::http1::percent_decode;
        assert_eq!(percent_decode("a%zzb"), "a%zzb");
        assert_eq!(percent_decode("100%"), "100%");
        assert_eq!(percent_decode("%4"), "%4");
    }

    #[tokio::test]
    async fn 写接口缺字段给出带_hint_的_400() {
        let r = route(
            &reg(),
            &cfg(),
            "POST",
            "/api/v2/proxies/add",
            "",
            r#"{"proxy":{"name":"x","type":"tcp"}}"#,
        )
        .await
        .expect("v2 路径");
        assert_eq!(r.status, 400);
        let v = body_of(&r);
        assert_eq!(v["error"]["code"], code::BAD_REQUEST);
        assert!(
            v["error"]["details"]["hint"].is_string(),
            "要给出怎么拿到 run_id"
        );
    }

    #[tokio::test]
    async fn 请求体不是_json_是_400() {
        let r = route(&reg(), &cfg(), "POST", "/api/v2/clients/kick", "", "{不是")
            .await
            .expect("v2 路径");
        assert_eq!(r.status, 400);
        assert_eq!(body_of(&r)["error"]["code"], code::BAD_REQUEST);
    }

    /// 客户端不在线 → 404（资源不存在），不是 400。
    #[tokio::test]
    async fn 客户端不在线归类为_404() {
        let r = route(
            &reg(),
            &cfg(),
            "POST",
            "/api/v2/clients/kick",
            "",
            r#"{"run_id":"nope"}"#,
        )
        .await
        .expect("v2 路径");
        assert_eq!(r.status, 404);
        assert_eq!(body_of(&r)["error"]["code"], code::NOT_FOUND);
    }

    #[tokio::test]
    async fn 状态里带出特性开关() {
        let reg = reg();
        let r = route(&reg, &cfg(), "GET", "/api/v2/status", "", "")
            .await
            .expect("v2 路径");
        let v = body_of(&r);
        assert!(v["data"]["metrics"]["uptime_secs"].is_number());
        assert_eq!(v["data"]["counts"]["clients"], 0);
        assert_eq!(v["data"]["features"]["p2p"], false);
        assert_eq!(v["data"]["features"]["vnet"], false);
        // 审计默认关闭 —— 面板要靠这个字段决定显不显示那一栏
        assert_eq!(v["data"]["features"]["audit"], false);
        assert_eq!(v["data"]["audit"]["enabled"], false);

        // 挂上 vhost 表之后 features 要跟着变
        reg.attach_vhosts(Arc::new(VhostTable::default()));
        let r = route(&reg, &cfg(), "GET", "/api/v2/status", "", "")
            .await
            .expect("v2 路径");
        assert_eq!(body_of(&r)["data"]["features"]["vhost"], true);
    }

    /// 审计默认关闭时，接口不该回一个"空错误"让人以为坏了。
    #[tokio::test]
    async fn 审计关闭时给出说明() {
        // 审计日志含全部租户信息，全量枚举要显式确认
        let r = route(&reg(), &cfg(), "GET", "/api/v2/audit", "?all=1", "")
            .await
            .expect("v2 路径");
        assert_eq!(r.status, 200);
        let v = body_of(&r);
        assert!(v["notice"].as_str().unwrap().contains("audit"));
        assert_eq!(v["data"].as_array().unwrap().len(), 0);
    }

    // ------------------------------------------------------------------
    // 读接口不得默认全量枚举
    // ------------------------------------------------------------------

    /// 不带过滤条件时必须要求显式 `?all=1`。
    ///
    /// 原先 `user` 为空即返回全平台数据，而 `run_id` / 代理名正是
    /// `POST /clients/kick` 与 `/proxies/remove` 的**主键** ——
    /// 读接口直接喂出了写接口所需的全部标识。
    #[tokio::test]
    async fn 读接口不得默认全量枚举() {
        for path in [
            "/api/v2/clients",
            "/api/v2/proxies",
            "/api/v2/visitors",
            "/api/v2/audit",
        ] {
            // 不带任何参数 ⇒ 必须 400，并告诉调用方怎么显式确认
            let r = route(&reg(), &cfg(), "GET", path, "", "")
                .await
                .expect("v2 路径");
            assert_eq!(r.status, 400, "{path} 不带参数时应要求显式确认");
            let msg = body_of(&r)["error"]["message"]
                .as_str()
                .unwrap_or_default()
                .to_string();
            assert!(msg.contains("all=1"), "{path} 的提示要点明 ?all=1：{msg}");

            // 显式 ?all=1 ⇒ 放行
            let r = route(&reg(), &cfg(), "GET", path, "?all=1", "")
                .await
                .expect("v2 路径");
            assert_eq!(r.status, 200, "{path} 带 ?all=1 时应放行");

            // 任一过滤条件 ⇒ 放行（不需要 all）
            let r = route(&reg(), &cfg(), "GET", path, "?user=alice", "")
                .await
                .expect("v2 路径");
            assert_eq!(r.status, 200, "{path} 带 ?user= 时应放行");

            // 空值不算过滤条件（`?user=` 与不传等价）
            let r = route(&reg(), &cfg(), "GET", path, "?user=", "")
                .await
                .expect("v2 路径");
            assert_eq!(r.status, 400, "{path} 的 ?user= 为空时仍需显式确认");
        }

        // `/status` 与 `/version` 只回聚合计数 ⇒ **不适用**该门槛
        for path in ["/api/v2/status", "/api/v2/version", "/api/v2/ports"] {
            let r = route(&reg(), &cfg(), "GET", path, "", "")
                .await
                .expect("v2 路径");
            assert_eq!(r.status, 200, "{path} 不含租户标识，不该被门槛挡住");
        }
    }

    /// `?all=` 的取值容错：1/true/yes 都认，大小写不敏感。
    #[tokio::test]
    async fn all_参数的取值容错() {
        for v in ["1", "true", "TRUE", "True", "yes", "YES", " 1 "] {
            let r = route(
                &reg(),
                &cfg(),
                "GET",
                "/api/v2/clients",
                &format!("?all={v}"),
                "",
            )
            .await
            .expect("v2 路径");
            assert_eq!(r.status, 200, "all={v:?} 应被认作确认");
        }
        for v in ["0", "false", "no", "", "x"] {
            let r = route(
                &reg(),
                &cfg(),
                "GET",
                "/api/v2/clients",
                &format!("?all={v}"),
                "",
            )
            .await
            .expect("v2 路径");
            assert_eq!(r.status, 400, "all={v:?} 不该被认作确认");
        }
    }

    // ------------------------------------------------------------------
    // v2 错误文案必须可脱敏
    // ------------------------------------------------------------------

    /// 关掉详细错误后，错误文案里**不得含任何租户标识**。
    ///
    /// 同一个错误在 `serve.rs` 的客户端路径上套了 `cfg.error_to_client()`，
    /// 面板这条路径原先**没套** —— 于是"域名 x 已被代理 alice.web 占用"
    /// 这类**别人的代理名**会被回显给调用方。
    #[tokio::test]
    async fn 关掉详细错误后_v2_不回显租户信息() {
        // 造一个必然报错的请求：页大小超上限
        let q = format!("?all=1&page_size={}", MAX_PAGE_SIZE + 1);

        // (1) 默认 true ⇒ 逐字不变（与官方一致，不能改行为）
        let r = route(&reg(), &cfg(), "GET", "/api/v2/clients", &q, "")
            .await
            .expect("v2 路径");
        assert_eq!(r.status, 400);
        let detailed = body_of(&r)["error"]["message"]
            .as_str()
            .unwrap()
            .to_string();
        assert!(
            detailed.contains(&MAX_PAGE_SIZE.to_string()),
            "detailedErrorsToClient = true 时应回详细原因：{detailed}"
        );

        // (2) 关掉 ⇒ 只回通用文案，不含具体数值
        let mut c = (*cfg()).clone();
        c.detailed_errors_to_client = false;
        let c = Arc::new(c);
        let r = route(&reg(), &c, "GET", "/api/v2/clients", &q, "")
            .await
            .expect("v2 路径");
        assert_eq!(r.status, 400, "状态码不变 —— 调用方仍能区分错误类别");
        let v = body_of(&r);
        let redacted = v["error"]["message"].as_str().unwrap();
        assert!(
            !redacted.contains(&MAX_PAGE_SIZE.to_string()),
            "脱敏后不得再含具体配置值：{redacted}"
        );
        // 错误码必须保留（调用方编程依赖它，且它不含租户信息）
        assert_eq!(
            v["error"]["code"].as_str(),
            Some("bad_request"),
            "错误码要保留，否则关掉详细错误的部署无法自动化"
        );
        assert!(v["error"]["details"].is_null(), "details 整个去掉");
    }

    /// 脱敏开关对**成功响应**零影响（别修得过头）。
    #[tokio::test]
    async fn 脱敏开关不影响成功响应() {
        let mut c = (*cfg()).clone();
        c.detailed_errors_to_client = false;
        let r = route(&reg(), &cfg(), "GET", "/api/v2/version", "", "")
            .await
            .expect("v2 路径");
        assert_eq!(r.status, 200);
        assert_eq!(body_of(&r)["data"]["api"], "v2");
    }

    #[tokio::test]
    async fn 端口列表可枚举() {
        let r = route(&reg(), &cfg(), "GET", "/api/v2/ports", "", "")
            .await
            .expect("v2 路径");
        let v = body_of(&r);
        assert!(v["data"].is_array());
    }

    #[test]
    fn 错误信封结构固定() {
        let e = ApiError::bad_request("坏了").with_details(serde_json::json!({"k": 1}));
        let v: serde_json::Value = serde_json::from_str(&e.to_json()).unwrap();
        assert_eq!(v["api"], "v2");
        assert_eq!(v["error"]["code"], "bad_request");
        assert_eq!(v["error"]["message"], "坏了");
        assert_eq!(v["error"]["details"]["k"], 1);
        // 没有 details 时不该出现 null 字段（前端 `if (d)` 判断会误判）
        let bare: serde_json::Value =
            serde_json::from_str(&ApiError::not_found("x").to_json()).unwrap();
        assert!(bare["error"].get("details").is_none());
    }
}
