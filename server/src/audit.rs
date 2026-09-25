//! 审计日志：把"谁在什么时候做了什么"记下来。
//!
//! # 为什么要它
//!
//! 出事后最常见的三个问题是「谁连上来的」「他加了什么代理」「谁把隧道删了」。
//! 没有审计日志时，这些只能靠翻普通日志里零散的 `info`，而普通日志：
//! - 会按 `log_level` 被关掉（`warn` 级别下登录成功什么都不打）；
//! - 是自由文本，`grep` 出来对不上格式，更没法喂给 SIEM；
//! - 会被轮转冲掉，且**能被改**（谁都能 `sed -i` 一句日志）。
//!
//! 所以这里做两件事：**结构化**（JSONL，一行一个事件）+ **独立留存**
//! （单独文件，不受 `log_level` 影响）。
//!
//! # 两种留存方式，都不启用时零开销
//!
//! - 内存环形缓冲：面板 `/api/audit` 可查最近 N 条，重启即失；
//! - JSONL 文件：`[audit] path = "/var/log/nfrp/audit.jsonl"`，
//!   追加写、每行一个 JSON，直接 `jq` / Filebeat 就能吃。
//!
//! `enable = false`（默认）时**连事件对象都不构造**，与老版本零差异。
//!
//! # 写失败怎么办
//!
//! 磁盘满、权限错、目录被删 —— 这些都不该让服务端挂掉或者拒绝服务，
//! 但也**绝不能静默**：第一次失败打一条 `error` 并置位，之后不再刷屏
//! （否则磁盘满会把日志也撑爆，形成二次故障）。

use std::collections::VecDeque;
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

/// 事件类型。用短字符串而不是 enum：JSONL 要能被人直接读懂，
/// 也要能在新增类型时不破坏老的解析方。
pub mod kind {
    pub const LOGIN: &str = "login";
    pub const LOGIN_DENIED: &str = "login_denied";
    pub const LOGOUT: &str = "logout";
    pub const PROXY_ADD: &str = "proxy_add";
    pub const PROXY_REMOVE: &str = "proxy_remove";
    pub const PROXY_REJECTED: &str = "proxy_rejected";
    pub const ADMIN_ACTION: &str = "admin_action";
    pub const CONFIG_RELOAD: &str = "config_reload";
    pub const VNET_JOIN: &str = "vnet_join";
    pub const VNET_LEAVE: &str = "vnet_leave";
}

/// 一条审计事件。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEvent {
    /// Unix 秒。
    pub ts: i64,
    /// 事件类型，见 [`kind`]。
    pub kind: String,
    /// 是否成功。**失败同样要记** —— 只有成功的记录，等于看不见攻击。
    pub ok: bool,
    /// 客户端 `run_id`（能定位到具体某一次连接）。
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub client: String,
    /// 客户端声明的用户名。
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub user: String,
    /// 来源 IP。代理场景下是直连的对端地址。
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub ip: String,
    /// 操作对象（代理名 / 面板路径 / 虚拟网络名…）。
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub target: String,
    /// 人话说明。
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub detail: String,
}

impl AuditEvent {
    pub fn new(kind: &str, ok: bool) -> Self {
        Self {
            ts: now_secs(),
            kind: kind.to_string(),
            ok,
            client: String::new(),
            user: String::new(),
            ip: String::new(),
            target: String::new(),
            detail: String::new(),
        }
    }

    pub fn client(mut self, v: impl Into<String>) -> Self {
        self.client = v.into();
        self
    }
    pub fn user(mut self, v: impl Into<String>) -> Self {
        self.user = v.into();
        self
    }
    pub fn ip(mut self, v: impl Into<String>) -> Self {
        self.ip = v.into();
        self
    }
    pub fn target(mut self, v: impl Into<String>) -> Self {
        self.target = v.into();
        self
    }
    pub fn detail(mut self, v: impl Into<String>) -> Self {
        self.detail = v.into();
        self
    }
}

fn now_secs() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// 审计日志本体。
#[derive(Debug)]
pub struct AuditLog {
    enabled: bool,
    /// 内存里保留多少条。
    cap: usize,
    buf: Mutex<VecDeque<AuditEvent>>,
    /// 落盘文件；`None` 表示只留内存。
    file: Mutex<Option<File>>,
    /// 落盘路径（回显给面板用）。
    path: Option<PathBuf>,
    /// 是否已经为"写失败"告过警 —— 防止磁盘满时把日志刷爆。
    warned: AtomicBool,
    /// 累计写入条数（含因缓冲上限被挤掉的）。
    total: std::sync::atomic::AtomicU64,
}

impl AuditLog {
    /// 构造。`enable = false` 时返回一个**空操作**实例，调用方不用到处判空。
    pub fn from_config(cfg: &nfrp_common::security::AuditConfig) -> anyhow::Result<Self> {
        if !cfg.enable {
            return Ok(Self::disabled());
        }
        let path = if cfg.path.trim().is_empty() {
            None
        } else {
            Some(PathBuf::from(cfg.path.trim()))
        };
        let file = match &path {
            Some(p) => {
                if let Some(dir) = p.parent() {
                    if !dir.as_os_str().is_empty() {
                        std::fs::create_dir_all(dir).map_err(|e| {
                            anyhow::anyhow!("创建审计日志目录 {} 失败：{e}", dir.display())
                        })?;
                    }
                }
                let f = OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open(p)
                    .map_err(|e| anyhow::anyhow!("打开审计日志 {} 失败：{e}", p.display()))?;
                Some(f)
            }
            None => None,
        };
        Ok(Self {
            enabled: true,
            cap: cfg.max_entries.max(1),
            buf: Mutex::new(VecDeque::new()),
            file: Mutex::new(file),
            path,
            warned: AtomicBool::new(false),
            total: std::sync::atomic::AtomicU64::new(0),
        })
    }

    /// 完全关闭的实例（不分配、不落盘）。
    pub fn disabled() -> Self {
        Self {
            enabled: false,
            cap: 1,
            buf: Mutex::new(VecDeque::new()),
            file: Mutex::new(None),
            path: None,
            warned: AtomicBool::new(true),
            total: std::sync::atomic::AtomicU64::new(0),
        }
    }

    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    pub fn path(&self) -> Option<&std::path::Path> {
        self.path.as_deref()
    }

    /// 记一条。**从不返回错误** —— 审计写不进去不该让业务失败。
    pub fn record(&self, ev: AuditEvent) {
        if !self.enabled {
            return;
        }
        self.total.fetch_add(1, Ordering::Relaxed);

        // 1) 内存环形缓冲
        {
            let mut buf = self.buf.lock().unwrap_or_else(|e| e.into_inner());
            if buf.len() >= self.cap {
                buf.pop_front();
            }
            buf.push_back(ev.clone());
        }

        // 2) 落盘
        let line = match serde_json::to_string(&ev) {
            Ok(s) => s,
            Err(e) => {
                tracing::warn!(error = %e, "审计事件序列化失败，已跳过落盘");
                return;
            }
        };
        let mut guard = self.file.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(f) = guard.as_mut() {
            // JSONL：一行一条，且**一次 write 写完**（避免多进程下交错半行）
            let mut rec = line.into_bytes();
            rec.push(b'\n');
            if let Err(e) = f.write_all(&rec) {
                if !self.warned.swap(true, Ordering::Relaxed) {
                    tracing::error!(
                        error = %e,
                        path = ?self.path,
                        "写审计日志失败（后续同类错误不再刷屏）；\
                         审计记录仍在内存里，面板可查"
                    );
                }
            }
        }
    }

    /// 最近 `n` 条（按时间正序返回，最新的在最后）。
    pub fn recent(&self, n: usize) -> Vec<AuditEvent> {
        let buf = self.buf.lock().unwrap_or_else(|e| e.into_inner());
        let skip = buf.len().saturating_sub(n);
        buf.iter().skip(skip).cloned().collect()
    }

    /// 按条件过滤 + 分页（面板 v2 用）。
    pub fn query(&self, filter: &AuditFilter) -> (usize, Vec<AuditEvent>) {
        let buf = self.buf.lock().unwrap_or_else(|e| e.into_inner());
        let matched: Vec<AuditEvent> = buf.iter().filter(|e| filter.matches(e)).cloned().collect();
        let total = matched.len();
        let page: Vec<AuditEvent> = matched
            .into_iter()
            .skip(filter.offset)
            .take(filter.limit.min(1000))
            .collect();
        (total, page)
    }

    pub fn len(&self) -> usize {
        self.buf.lock().unwrap_or_else(|e| e.into_inner()).len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn total(&self) -> u64 {
        self.total.load(Ordering::Relaxed)
    }
}

/// 审计查询条件。
#[derive(Debug, Clone, Default)]
pub struct AuditFilter {
    pub kind: Option<String>,
    pub user: Option<String>,
    pub ok: Option<bool>,
    pub offset: usize,
    /// 单页条数，默认 100、上限 1000（由 [`Self::from_query`] 兜底）。
    pub limit: usize,
}

impl AuditFilter {
    pub fn matches(&self, e: &AuditEvent) -> bool {
        if let Some(k) = &self.kind {
            if !k.is_empty() && &e.kind != k {
                return false;
            }
        }
        if let Some(u) = &self.user {
            if !u.is_empty() && &e.user != u {
                return false;
            }
        }
        if let Some(ok) = self.ok {
            if e.ok != ok {
                return false;
            }
        }
        true
    }

    /// 从查询串里解析（面板用）。
    pub fn from_query(q: &str) -> Self {
        let mut f = Self {
            limit: 100,
            ..Default::default()
        };
        for pair in q.split('&') {
            let Some((k, v)) = pair.split_once('=') else {
                continue;
            };
            let v = url_decode(v);
            match k {
                "kind" if !v.is_empty() => f.kind = Some(v),
                "user" if !v.is_empty() => f.user = Some(v),
                "ok" => f.ok = Some(v == "true" || v == "1"),
                "offset" => f.offset = v.parse().unwrap_or(0),
                "limit" => {
                    if let Ok(n) = v.parse::<usize>() {
                        f.limit = n.clamp(1, 1000);
                    }
                }
                _ => {}
            }
        }
        f
    }
}

/// 极简的 percent-decode（只处理 `%XX` 与 `+`，够查询串用）。
fn url_decode(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            b'%' if i + 2 < b.len() => {
                let hex = std::str::from_utf8(&b[i + 1..i + 3]).unwrap_or("");
                match u8::from_str_radix(hex, 16) {
                    Ok(v) => {
                        out.push(v);
                        i += 3;
                    }
                    Err(_) => {
                        out.push(b[i]);
                        i += 1;
                    }
                }
            }
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            c => {
                out.push(c);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use nfrp_common::security::AuditConfig;

    fn tmp_path(name: &str) -> PathBuf {
        let mut p = std::env::temp_dir();
        p.push(format!(
            "nfrp-audit-test-{}-{}.jsonl",
            std::process::id(),
            name
        ));
        let _ = std::fs::remove_file(&p);
        p
    }

    #[test]
    fn 关闭时不记录任何东西() {
        let log = AuditLog::from_config(&AuditConfig::default()).unwrap();
        assert!(!log.is_enabled());
        log.record(AuditEvent::new(kind::LOGIN, true));
        assert_eq!(log.len(), 0);
        assert_eq!(log.total(), 0);
        assert!(log.recent(10).is_empty());
    }

    #[test]
    fn 内存环形缓冲按上限淘汰() {
        let mut cfg = AuditConfig {
            enable: true,
            ..Default::default()
        };
        cfg.max_entries = 3;
        let log = AuditLog::from_config(&cfg).unwrap();
        for i in 0..5 {
            log.record(AuditEvent::new(kind::LOGIN, true).target(format!("c{i}")));
        }
        assert_eq!(log.len(), 3, "内存里只该留 3 条");
        assert_eq!(log.total(), 5, "累计条数要如实统计");
        let r = log.recent(10);
        // 留下的是最后 3 条（c2/c3/c4），顺序为时间正序
        assert_eq!(r[0].target, "c2");
        assert_eq!(r[2].target, "c4");
    }

    #[test]
    fn 落盘是_jsonl_且能读回() {
        let path = tmp_path("jsonl");
        let cfg = AuditConfig {
            enable: true,
            path: path.to_string_lossy().to_string(),
            max_entries: 100,
        };
        let log = AuditLog::from_config(&cfg).unwrap();
        log.record(
            AuditEvent::new(kind::LOGIN, true)
                .user("alice")
                .ip("1.2.3.4"),
        );
        log.record(
            AuditEvent::new(kind::LOGIN_DENIED, false)
                .user("mallory")
                .detail("token 不匹配"),
        );

        let text = std::fs::read_to_string(&path).unwrap();
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(lines.len(), 2, "一行一个事件");
        // 每行都必须是**独立的**合法 JSON（能被 jq 直接消费）
        let first: AuditEvent = serde_json::from_str(lines[0]).unwrap();
        assert_eq!(first.kind, "login");
        assert_eq!(first.user, "alice");
        assert!(first.ok);
        let second: AuditEvent = serde_json::from_str(lines[1]).unwrap();
        assert_eq!(second.kind, "login_denied");
        assert!(!second.ok, "失败事件必须真的记下来");
        // 空字段不该出现在报文里（日志小一点）
        assert!(!lines[0].contains("\"detail\""), "{}", lines[0]);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn 追加写不会覆盖历史() {
        let path = tmp_path("append");
        let cfg = AuditConfig {
            enable: true,
            path: path.to_string_lossy().to_string(),
            max_entries: 10,
        };
        {
            let log = AuditLog::from_config(&cfg).unwrap();
            log.record(AuditEvent::new(kind::LOGIN, true).user("first"));
        }
        // 进程"重启"：重新打开同一个文件
        let log2 = AuditLog::from_config(&cfg).unwrap();
        log2.record(AuditEvent::new(kind::LOGOUT, true).user("second"));
        let text = std::fs::read_to_string(&path).unwrap();
        assert_eq!(text.lines().count(), 2, "重启后必须接着写而不是截断");
        assert!(text.contains("first") && text.contains("second"));
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn 过滤与分页() {
        let mut cfg = AuditConfig {
            enable: true,
            ..Default::default()
        };
        cfg.max_entries = 100;
        let log = AuditLog::from_config(&cfg).unwrap();
        for _ in 0..5 {
            log.record(AuditEvent::new(kind::LOGIN, true).user("alice"));
        }
        for _ in 0..3 {
            log.record(AuditEvent::new(kind::LOGIN_DENIED, false).user("bob"));
        }

        let f = AuditFilter {
            user: Some("alice".into()),
            limit: 100,
            ..Default::default()
        };
        let (total, page) = log.query(&f);
        assert_eq!(total, 5);
        assert_eq!(page.len(), 5);

        // 只看失败的
        let f = AuditFilter {
            ok: Some(false),
            limit: 100,
            ..Default::default()
        };
        assert_eq!(log.query(&f).0, 3);

        // 分页
        let f = AuditFilter {
            limit: 2,
            offset: 4,
            ..Default::default()
        };
        let (total, page) = log.query(&f);
        assert_eq!(total, 8, "total 是过滤后的总数，不受分页影响");
        assert_eq!(page.len(), 2);
    }

    #[test]
    fn 查询串解析() {
        let f = AuditFilter::from_query("kind=login&user=a%20b&ok=false&limit=50&offset=10");
        assert_eq!(f.kind.as_deref(), Some("login"));
        assert_eq!(f.user.as_deref(), Some("a b"), "percent-decode 要生效");
        assert_eq!(f.ok, Some(false));
        assert_eq!(f.limit, 50);
        assert_eq!(f.offset, 10);
        // 默认值与上限
        let d = AuditFilter::from_query("");
        assert_eq!(d.limit, 100);
        assert!(AuditFilter::from_query("limit=99999").limit <= 1000);
        // 无关参数不影响
        let x = AuditFilter::from_query("foo=bar");
        assert!(x.kind.is_none());
    }

    /// 目录不存在时要**自动创建** —— 否则用户得先 mkdir 一遍才能开审计，
    /// 而失败又发生在启动阶段，很容易让人以为"功能坏了"。
    #[test]
    fn 自动创建父目录() {
        let mut dir = std::env::temp_dir();
        dir.push(format!("nfrp-audit-dir-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let mut path = dir.clone();
        path.push("sub");
        path.push("audit.jsonl");
        let cfg = AuditConfig {
            enable: true,
            path: path.to_string_lossy().to_string(),
            max_entries: 10,
        };
        let log = AuditLog::from_config(&cfg).expect("应当自动建目录");
        log.record(AuditEvent::new(kind::LOGIN, true));
        assert!(path.exists());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
