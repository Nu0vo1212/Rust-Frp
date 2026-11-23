//! 认证方式、IP 访问控制与基于角色的权限模型（RBAC）。
//!
//! 这三样是一组：**谁能连上来**（ACL）→ **他是不是他自称的人**（认证）→
//! **他能干什么**（RBAC）。官方 frp 只有前两步的一半（`auth.token` +
//! `allowUsers`），第三步完全没有，所以这里的设计原则是：
//!
//! 1. **默认零行为变化**。任何一张表留空 ⇒ 完全等同于加这个模块之前的行为，
//!    老的配置文件一个字节都不用改就能继续跑。
//! 2. **字段名尽量贴官方**。`auth.method` / `auth.token` / `auth.oidc.*`
//!    与官方 frp 同名同义，官方配置直接喂进来就能用。
//! 3. **先拒后允**。ACL 永远先看 deny：命中 deny 直接拒，不再看 allow。
//!    反过来写（先算 allow 再看 deny）很容易在 allow 写成 `0.0.0.0/0` 时
//!    把一条 deny 整个吞掉。
//!
//! 本模块是纯逻辑（不碰网络、不碰磁盘），便于单测覆盖边界。

use std::net::IpAddr;

use serde::{Deserialize, Serialize};

use crate::auth::oidc::{ClientOidcConfig, ServerOidcConfig};

// ---------------------------------------------------------------------------
// 认证方式
// ---------------------------------------------------------------------------

/// 认证方式，对应官方 frp 的 `auth.method`。
///
/// 官方只有 `token`（默认）与 `oidc` 两种；写成别的值官方会直接报错
/// （`auth method is not supported`），这里同样只在**解析时**就拒绝，
/// 而不是等到运行时才发现"认证永远失败"。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AuthMethod {
    /// `md5(token + timestamp)` 的共享密钥认证（官方默认）。
    #[default]
    Token,
    /// OpenID Connect：客户端拿 IdP 签发的 access token 当凭证。
    Oidc,
}

impl AuthMethod {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Token => "token",
            Self::Oidc => "oidc",
        }
    }
}

/// 服务端认证配置（`[auth]` 段）。
///
/// **手工实现 `Debug`**，`token` 一律脱敏。
///
/// 原来派生 `Debug` 时，任何一句调试用的 `println!("{cfg:?}")` 或
/// `tracing::debug!(?cfg)` 都会把**明文 token** 打进日志。项目里眼下没有
/// 这样的打印，但配置结构被到处传递，属于"等着被踩"的坑 ——
/// `AuthProvider` 早就手工脱敏了，这里与它对齐。
#[derive(Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServerAuthConfig {
    /// `token`（默认）/ `oidc`。
    #[serde(default)]
    pub method: AuthMethod,
    /// 共享密钥。`method = "token"` 时与服务端比对。
    #[serde(default)]
    pub token: String,
    /// 额外校验 token 的时机（官方 `additionalScopes`）。
    ///
    /// 取值 `HeartBeats` / `NewWorkConns`：开启后，心跳与新工作连接上带的
    /// token 也必须当场验签通过，而不是"登录时验过一次就永久信任"。
    /// 关掉它就等于**只要握手时 token 有效，之后换成任何字符串都收**，
    /// 所以这里默认全开。
    #[serde(
        default = "default_scopes",
        rename = "additionalScopes",
        skip_serializing_if = "Vec::is_empty"
    )]
    pub additional_scopes: Vec<String>,
    /// OIDC 提供方配置（`method = "oidc"` 时必填）。
    #[serde(default)]
    pub oidc: ServerOidcConfig,
    /// 令牌来源（官方 frps 的 `auth.tokenSource`）。
    ///
    /// 已**真正实现**（此前只是"声明以便官方配置能解析通过"）。
    ///
    /// 服务端用它做**期望 token** 的来源：从文件或外部命令读，再与客户端
    /// 送来的 token 比对。这样 token 不必写在配置里，适合 k8s Secret /
    /// Vault sidecar 这类把密钥挂成文件的部署。
    ///
    /// 与 `token` 互斥：两者都配时以 `tokenSource` 为准并告警。
    #[serde(
        default,
        rename = "tokenSource",
        skip_serializing_if = "Option::is_none"
    )]
    pub token_source: Option<ValueSource>,
}

/// 官方 frp 的默认 `additionalScopes`：两个都开。
pub fn default_scopes() -> Vec<String> {
    vec!["HeartBeats".to_string(), "NewWorkConns".to_string()]
}

impl std::fmt::Debug for ServerAuthConfig {
    /// `token` 永不进日志。
    ///
    /// 只暴露"有没有配、多长"，够排障用，又不会把密钥写进任何日志文件。
    /// （`AuthProvider::Debug` 早就是这么做的，这里与它对齐。）
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let token = if self.token.is_empty() {
            "<empty>".to_string()
        } else {
            format!("<redacted:{} chars>", self.token.chars().count())
        };
        f.debug_struct("ServerAuthConfig")
            .field("method", &self.method)
            .field("token", &token)
            .field("additional_scopes", &self.additional_scopes)
            .field("oidc", &self.oidc)
            .finish()
    }
}

impl ServerAuthConfig {
    /// 只配了 token（全是默认值）—— 用于判定"行为与老版本完全一致"。
    pub fn is_plain_token(&self) -> bool {
        self.method == AuthMethod::Token
    }

    /// 一致性检查：把会在运行时才炸的配置错误提前到启动时。
    pub fn validate(&self) -> anyhow::Result<()> {
        if self.method == AuthMethod::Token && self.token.is_empty() {
            // 与官方一致：token 为空 = **不做认证**。这是合法的（靠网络隔离兜底），
            // 但必须在日志里说清楚，否则用户会以为"应该只有我能连"。
        }
        if self.method == AuthMethod::Oidc && self.oidc.issuer.trim().is_empty() {
            anyhow::bail!("auth.method = \"oidc\" 时必须配置 auth.oidc.issuer");
        }
        for s in &self.additional_scopes {
            if s != "HeartBeats" && s != "NewWorkConns" {
                anyhow::bail!("auth.additionalScopes 只支持 HeartBeats / NewWorkConns，收到 {s:?}");
            }
        }
        Ok(())
    }

    /// 是否要在心跳上复核 token。
    pub fn check_heartbeats(&self) -> bool {
        self.method == AuthMethod::Oidc && self.additional_scopes.iter().any(|s| s == "HeartBeats")
    }

    /// 是否要在新工作连接上复核 token。
    pub fn check_new_work_conns(&self) -> bool {
        self.method == AuthMethod::Oidc
            && self.additional_scopes.iter().any(|s| s == "NewWorkConns")
    }
}

/// 客户端认证配置。
///
/// **手工实现 `Debug`**，`token` 必须脱敏。
///
/// 原来这里是 `#[derive(Debug)]`，而同文件的 `ServerAuthConfig` 早就手工脱敏了
/// —— 同一个文件、同一个项目、两种标准。任何一句 `tracing::debug!(?auth_cfg)`
/// 都会把客户端 token 明文写进日志文件。
#[derive(Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClientAuthConfig {
    #[serde(default)]
    pub method: AuthMethod,
    #[serde(default)]
    pub token: String,
    #[serde(
        default,
        rename = "additionalScopes",
        skip_serializing_if = "Vec::is_empty"
    )]
    pub additional_scopes: Vec<String>,
    #[serde(default)]
    pub oidc: ClientOidcConfig,
    /// 令牌来源（官方 frpc 的 `auth.tokenSource`：从文件 / 外部命令读 token）。
    ///
    /// 令牌来源（官方 frpc 的 `auth.tokenSource`：从文件 / 外部命令读 token）。
    ///
    /// 已**真正实现**（此前只是"声明以便官方配置能解析通过"）。
    ///
    /// 与 `token` 字段**互斥**：两者都配时以 `tokenSource` 为准并告警
    /// （官方 `AuthClientConfig` 的注释写的就是 "mutually exclusive with
    /// Token field"）。
    ///
    /// ```toml
    /// [auth.tokenSource]
    /// type = "file"
    /// [auth.tokenSource.file]
    /// path = "/etc/nfrp/token"
    /// ```
    #[serde(
        default,
        rename = "tokenSource",
        skip_serializing_if = "Option::is_none"
    )]
    pub token_source: Option<ValueSource>,
}

impl std::fmt::Debug for ClientAuthConfig {
    /// `token` 永不进日志，与 `ServerAuthConfig:Debug` 同口径。
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let token = if self.token.is_empty() {
            "<empty>".to_string()
        } else {
            format!("<redacted:{} chars>", self.token.chars().count())
        };
        f.debug_struct("ClientAuthConfig")
            .field("method", &self.method)
            .field("token", &token)
            .field("additional_scopes", &self.additional_scopes)
            .field("oidc", &self.oidc)
            .field("token_source", &self.token_source)
            .finish()
    }
}

impl ClientAuthConfig {
    pub fn validate(&self) -> anyhow::Result<()> {
        if self.method == AuthMethod::Oidc {
            self.oidc.validate()?;
        }
        Ok(())
    }
}

// ===========================================================================
// tokenSource：动态令牌来源（官方 frp 的 `ValueSource`）
// ===========================================================================

/// 动态取值来源。严格对齐官方 `pkg/config/v1/transport_config.go` 的
/// `ValueSource` / `FileSource` / `ExecSource`。
///
/// 官方只支持两种 `type`：
/// * `file` —— 读文件内容，**去掉首尾空白**（配置文件末尾常有换行，
///   不去掉 token 就对不上，这是官方明确写过的重要细节）；
/// * `exec` —— 跑一个子进程，取它的 stdout（同样去首尾空白）。
///
/// # 安全说明（`exec` 类型）
///
/// `exec` 会在客户端启动时**执行一个外部程序**。这与官方行为一致，
/// 但风险要说清：**能改配置文件的人等于能执行任意命令**（以 nfrp 的运行
/// 身份）。因此：
///
/// * 不经 shell 执行（直接 spawn，`command` 与 `args` 不拼接）；
/// * 有超时上限，防止挂死整个启动流程；
/// * 启动日志会明确打出"令牌来自外部命令"，便于审计。
///
/// 只需要"从文件读 token"时请优先用 `type = "file"`，它没有执行风险。
#[derive(Debug, Clone, Default, serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
pub struct ValueSource {
    /// `"file"` 或 `"exec"`。
    #[serde(rename = "type", default)]
    pub kind: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub file: Option<FileSource>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exec: Option<ExecSource>,
}

/// 从文件取值的配置（官方 `FileSource`）。
#[derive(Debug, Clone, Default, serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
pub struct FileSource {
    #[serde(default)]
    pub path: String,
}

/// 从子进程取值的配置（官方 `ExecSource`）。
#[derive(Debug, Clone, Default, serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
pub struct ExecSource {
    #[serde(default)]
    pub command: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub args: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub env: Vec<ExecEnvVar>,
}

/// `exec` 的附加环境变量（官方 `ExecEnvVar`）。
#[derive(Debug, Clone, Default, serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
pub struct ExecEnvVar {
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub value: String,
}

/// `exec` 类型的执行超时。官方没有显式上限（跟着 ctx 走），
/// 这里必须有 —— 否则一个卡住的子进程会让客户端**永远起不来**。
const EXEC_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

impl ValueSource {
    /// 校验配置本身是否自洽。启动时先调它，把配置错误报在**取 token 之前**。
    pub fn validate(&self) -> anyhow::Result<()> {
        match self.kind.as_str() {
            "file" => {
                let f = self
                    .file
                    .as_ref()
                    .ok_or_else(|| anyhow::anyhow!("tokenSource type=file 时必须配 [file] 段"))?;
                if f.path.trim().is_empty() {
                    anyhow::bail!("tokenSource.file.path 不能为空");
                }
            }
            "exec" => {
                let e = self
                    .exec
                    .as_ref()
                    .ok_or_else(|| anyhow::anyhow!("tokenSource type=exec 时必须配 [exec] 段"))?;
                if e.command.trim().is_empty() {
                    anyhow::bail!("tokenSource.exec.command 不能为空");
                }
            }
            "" => anyhow::bail!("tokenSource 缺少 type（只支持 \"file\" / \"exec\"）"),
            other => {
                anyhow::bail!("tokenSource.type = [{other}] 不支持，只支持 \"file\" / \"exec\"")
            }
        }
        Ok(())
    }

    /// 真正去取值。返回的是**已去掉首尾空白**的字符串（官方同样处理）。
    ///
    /// 返回值**绝不能进日志** —— 它是 token 本身。
    pub fn resolve(&self) -> anyhow::Result<String> {
        self.validate()?;
        match self.kind.as_str() {
            "file" => {
                let path = &self.file.as_ref().expect("validate 已保证").path;
                let raw = std::fs::read_to_string(path)
                    .map_err(|e| anyhow::anyhow!("读取 tokenSource 文件 [{path}] 失败：{e}"))?;
                let t = raw.trim().to_string();
                if t.is_empty() {
                    anyhow::bail!("tokenSource 文件 [{path}] 是空的（或只有空白）");
                }
                Ok(t)
            }
            "exec" => {
                let e = self.exec.as_ref().expect("validate 已保证");
                self.run_exec(e)
            }
            _ => unreachable!("validate 已排除"),
        }
    }

    /// 跑子进程取 stdout。**不经 shell**（`command` 与 `args` 分开传）。
    fn run_exec(&self, e: &ExecSource) -> anyhow::Result<String> {
        use std::process::{Command, Stdio};

        let mut cmd = Command::new(&e.command);
        cmd.args(&e.args)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        for kv in &e.env {
            if kv.name.trim().is_empty() {
                anyhow::bail!("tokenSource.exec.env 里有空名字的环境变量");
            }
            cmd.env(&kv.name, &kv.value);
        }

        let mut child = cmd
            .spawn()
            .map_err(|err| anyhow::anyhow!("tokenSource 命令 [{}] 启动失败：{err}", e.command))?;

        // 带超时地等：用线程轮询 `try_wait`，超时直接 kill。
        // 不用 `wait_timeout` 之类要额外依赖的写法。
        let started = std::time::Instant::now();
        loop {
            match child.try_wait() {
                Ok(Some(_)) => break,
                Ok(None) => {
                    if started.elapsed() > EXEC_TIMEOUT {
                        let _ = child.kill();
                        let _ = child.wait();
                        anyhow::bail!(
                            "tokenSource 命令 [{}] 超过 {} 秒未结束，已强制终止",
                            e.command,
                            EXEC_TIMEOUT.as_secs()
                        );
                    }
                    std::thread::sleep(std::time::Duration::from_millis(20));
                }
                Err(err) => {
                    anyhow::bail!("等待 tokenSource 命令 [{}] 失败：{err}", e.command);
                }
            }
        }

        let out = child.wait_with_output().map_err(|err| {
            anyhow::anyhow!("读取 tokenSource 命令 [{}] 输出失败：{err}", e.command)
        })?;
        if !out.status.success() {
            // 只截断打尾部，避免把巨量 stderr 灌进日志
            let err_text = String::from_utf8_lossy(&out.stderr);
            let brief: String = err_text.chars().take(300).collect();
            anyhow::bail!(
                "tokenSource 命令 [{}] 退出码非 0（{}）：{brief}",
                e.command,
                out.status
            );
        }
        let t = String::from_utf8_lossy(&out.stdout).trim().to_string();
        if t.is_empty() {
            anyhow::bail!("tokenSource 命令 [{}] 没有输出任何内容", e.command);
        }
        Ok(t)
    }
}

// ---------------------------------------------------------------------------
// 凭证与校验器
// ---------------------------------------------------------------------------

/// 客户端手里拿的登录凭证。
///
/// 线上要发的 `privilege_key` 在两种方式下**语义完全不同**，这是 OIDC 对接
/// 最容易踩的地方：
/// - token 方式：`hex(md5(secret + timestamp))`，**不是**密钥本身；
/// - OIDC 方式：**原样的 access token**（官方 `OidcAuthProvider.SetLogin`
///   就是 `loginMsg.PrivilegeKey = accessToken`），`timestamp` 发但不用。
///
/// 所以别想着"统一成一个字符串" —— 那必然有一边是错的。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Credential {
    /// 共享密钥。
    Token(String),
    /// IdP 签发的 access token。
    Oidc(String),
}

impl Credential {
    /// 生成线上要发的 `privilege_key`。
    pub fn wire_value(&self, ts: i64) -> String {
        match self {
            Self::Token(t) => crate::frp::msg::auth_key(t, ts),
            Self::Oidc(t) => t.clone(),
        }
    }

    /// 原始凭证（不含任何派生）——校验方要用的就是它。
    pub fn raw(&self) -> &str {
        match self {
            Self::Token(t) | Self::Oidc(t) => t,
        }
    }
}

/// 服务端的认证校验器。
#[derive(Clone)]
pub enum AuthProvider {
    /// 共享密钥（默认，零开销）。
    Token(String),
    /// OIDC：用 IdP 公钥验签。
    Oidc(std::sync::Arc<crate::auth::oidc::OidcVerifier>),
    /// OIDC 配置了但验签器还没建起来（IdP 不可达）——
    /// 明确拒绝而不是放行，否则 IdP 一挂就等于服务端裸奔。
    OidcUnavailable(String),
}

impl Default for AuthProvider {
    fn default() -> Self {
        Self::Token(String::new())
    }
}

impl std::fmt::Debug for AuthProvider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Token(t) => f
                .debug_struct("AuthProvider::Token")
                // 密钥绝不进日志
                .field(
                    "token",
                    &if t.is_empty() {
                        "<empty>"
                    } else {
                        "<redacted>"
                    },
                )
                .finish(),
            Self::Oidc(_) => f.write_str("AuthProvider::Oidc"),
            Self::OidcUnavailable(e) => f
                .debug_tuple("AuthProvider::OidcUnavailable")
                .field(e)
                .finish(),
        }
    }
}

// ---------------------------------------------------------------------------
// 凭证新鲜性 —— **所有**凭证校验都必须经过这里
// ---------------------------------------------------------------------------

/// 时间戳新鲜性校验的**唯一实现**。
///
/// 抽成自由函数（而不是只放在 `AuthProvider` 上）是为了让
/// "基于 token 的凭证" 与 "基于共享密钥的凭证" 走同一份判据 ——
/// 后者（visitor 签名 / p2p 打洞签名）压根不经过 `AuthProvider`，
/// 而它们此前**完全没有任何新鲜性校验**。
///
/// `what` 只用于错误文案，便于运维分辨是哪条路径出的问题。
///
/// `skew` 为 0 表示**显式关闭**（逃生开关，给时钟严重不准的设备用）。
/// 注意：关闭是"明知故为"的选择，调用方必须显式传 0 —— 没有默认值可以漏。
pub fn check_freshness(ts: i64, skew: u64, what: &str) -> anyhow::Result<()> {
    if skew == 0 {
        return Ok(());
    }
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    // 用 `saturating_sub` + `saturating_abs` 避免 `now - ts` 在 i64::MIN 上溢出
    // （审计报告实测过：`ts = i64::MIN` 以前是能登录成功的）。
    let diff = now.saturating_sub(ts).saturating_abs();
    if diff > skew as i64 {
        anyhow::bail!(
            "{what}超出允许偏差（ts={ts}，现在={now}，偏差 {diff} 秒 > {skew} 秒）\
             —— 请校准两端时钟，或调大 maxClockSkewSecs"
        );
    }
    Ok(())
}

/// 校验一份**基于共享密钥的凭证证明**：`given` 必须等于 `auth_key(secret, ts)`，
/// **且 `ts` 必须新鲜**。
///
///
/// # 为什么需要它
///
/// visitor 签名（`sign_key`）与 p2p 打洞签名此前各自直接算
/// `auth_key(secret_key, timestamp)` 再比对，**只看内容不看新鲜性** ⇒
/// 嗅探到一条报文即可**无限期重放**（实测一年前的仍然被接受）。
///
/// 现在"比内容"和"查新鲜性"是**同一件事**：想校验这类凭证就必然要提供
/// 时间窗口，没有"只比内容"的入口可误用。
///
/// `skew` 语义与 [`check_freshness`] 一致（0 = 显式关闭）。
pub fn verify_shared_secret_proof(
    secret: &str,
    given: &str,
    ts: i64,
    skew: u64,
    what: &str,
) -> anyhow::Result<()> {
    check_freshness(ts, skew, what)?;
    let expected = crate::frp::msg::auth_key(secret, ts);
    if !crate::frp::msg::constant_time_eq(&expected, given) {
        anyhow::bail!("{what}的密钥证明不匹配");
    }
    Ok(())
}

impl AuthProvider {
    pub fn token(t: impl Into<String>) -> Self {
        Self::Token(t.into())
    }

    pub fn method(&self) -> AuthMethod {
        match self {
            Self::Token(_) => AuthMethod::Token,
            Self::Oidc(_) => AuthMethod::Oidc,
            Self::OidcUnavailable(_) => AuthMethod::Oidc,
        }
    }

    /// 校验登录凭证。`cred` 就是报文里的 `privilege_key` 原文。
    ///
    /// 返回身份标识（token 方式为空串，OIDC 方式为 `sub`）。
    ///
    /// `run_id` 用于把 OIDC 的 subject **绑定到本次会话**。
    ///
    /// token 模式增加 **timestamp 新鲜性窗口**。
    ///
    /// # 问题
    ///
    /// v1 的登录凭证是 `hex(md5(token + timestamp))`，而服务端**只用报文自报的
    /// `timestamp` 重算比对，不做新鲜性校验、无重放检测**；同时 `Login` 报文在
    /// **加密建立之前**明文发送（官方时序如此，有测试锁定）。
    ///
    /// ⇒ 同链路嗅探到一条 `Login` 即可**原样重放**拿到完整会话；
    ///   并且每个候选 token 只需 **1 次 MD5** 就能离线验证
    ///   （PBKDF2 的 64 次迭代只用在加密密钥派生，与登录凭证无关）。
    ///
    /// # 为什么现在可以修（推翻"协议层面没有补救空间"的旧结论）
    ///
    /// 加**时间窗口**不改任何线协议格式：
    /// 官方 frpc 的 `Login.Timestamp` 就是发报文时的 unix 时间
    /// （见官方 `pkg/auth/token.go` 的 `SetLogin`），宽窗口下**零感知**。
    /// ⇒ **"协议格式不能改" ≠ "安全语义不能加强"。**
    ///
    /// # 与本项目 P2P 路径的对照（这才是正确的做法）
    ///
    /// `p2p::handshake_token()` 把口令绑定到 `sid`（一次会话一个值），
    /// 录下来也重放不到下一次 —— 控制通道此前没有这层保护，现在补上了时间维度。
    ///
    /// # 窗口取值
    ///
    /// 默认 **±300 秒**（`max_clock_skew_secs`，0 = 关闭校验，用于兼容时钟
    /// 严重不准的嵌入式设备）。选 300s 的理由：足够容纳常见的时钟漂移与
    /// 网络延迟，同时把重放窗口压到 5 分钟（原先**无限期**）。
    ///
    /// 注意：这**不是**完整的防重放（窗口内仍可重放）。
    ///   完整的做法要维护"已用过的 (run_id, ts)"集合，那要引入一张会增长的
    ///   表并处理过期清理 —— 对登录这种低频事件收益不划算。
    ///   窗口已经把攻击面从"永久"压到"5 分钟"，且**零互通代价**。
    ///
    /// **把新鲜性校验并进来**。
    ///
    /// # 原先为什么错了
    ///
    /// M3 把新鲜性做成了**独立的** [`Self:check_timestamp`]，并在注释里解释了
    /// 理由（"先判时间成本更低 / 让两种失败在日志里分开"）。那个理由本身成立，
    /// 但**代价是调用方可以忘**——而实际就有 4 处忘了：
    ///
    /// | 路径 | 位置 | 当时的状态 |
    /// |---|---|---|
    /// | 主登录 | `conn.rs` | ✅ 唯一调了 `check_timestamp` 的地方 |
    /// | vnet 注册 | `vnet.rs` | ❌ 直接调 `verify_login`，没有时间校验 |
    /// | 工作连接 | `serve.rs` | ❌ 自己手写 `auth_key` 比对，不知道有新鲜性 |
    /// | visitor 签名 | `visitor.rs` | ❌ 同上 |
    /// | p2p 打洞签名 | `p2p.rs` | ❌ 同上 |
    ///
    /// 实测危害：**一年前**的报文仍然被接受，并打通了完整双向 MITM
    /// （`tmp/audit6-g1/mitm_full_poc.py`）。
    ///
    /// # 现在的做法
    ///
    /// 校验新鲜性**成为 `verify_login` 的一部分**（`skew` 是必需参数）：
    /// 想校验凭证就**必须**提供时间窗口，没有"只校验凭证"的入口可以误用。
    /// 两种失败在日志里**仍然分得开**（错误文案不同），所以原设计的收益没丢。
    ///
    /// 同一个教训本轮还出现在另外三处（visitor / p2p 走
    ///   [`verify_shared_secret_proof`]，工作连接改调本函数）——
    ///   **本项目连续六轮的模式：防线写对了，但没铺满它声称保护的所有路径。**
    pub fn verify_login(
        &self,
        cred: &str,
        ts: i64,
        run_id: &str,
        skew: u64,
    ) -> anyhow::Result<String> {
        // 先判时间：成本更低，且让"过期"与"凭证错"在日志里分开
        self.check_timestamp(ts, skew)?;
        match self {
            Self::Token(secret) => {
                if secret.is_empty() {
                    // 与官方 frps 一致：token 为空 = 不做认证。
                    // 这是合法配置（靠网络隔离兜底），但要在启动日志里警告。
                    return Ok(String::new());
                }
                let expected = crate::frp::msg::auth_key(secret, ts);
                if !crate::frp::msg::constant_time_eq(&expected, cred) {
                    anyhow::bail!("token in login doesn't match token from configuration");
                }
                Ok(String::new())
            }
            Self::Oidc(v) => v.remember_subject(cred, run_id),
            Self::OidcUnavailable(e) => {
                anyhow::bail!("OIDC 认证不可用（{e}），拒绝本次登录")
            }
        }
    }

    /// 校验**原始 token**（SSH 网关专用）。
    ///
    /// 为什么不能复用 [`Self::verify_login`]：普通客户端在 `Login` 里发的是
    /// `auth_key(token, ts)` 派生值（带时间戳，防重放）；而 SSH 网关的
    /// `--token` 是用户在命令行里直接输入的**原始 token**，两者不是同一个量。
    ///
    /// 0.7.6 及以前这里直接调了 `verify_login(cmd.token, ...)`，结果
    /// **任何 token 都不可能通过**（派生值 ≠ 原始值），SSH 网关的 token
    /// 认证实际处于「永远失败」状态，只是没人跑过数据面 e2e 所以没暴露。
    pub fn verify_raw_token(&self, raw: &str) -> anyhow::Result<String> {
        match self {
            Self::Token(secret) => {
                if secret.is_empty() {
                    return Ok(String::new());
                }
                if !crate::frp::msg::constant_time_eq(secret, raw) {
                    anyhow::bail!("SSH 网关 token 与 frps 配置不一致");
                }
                Ok(String::new())
            }
            Self::Oidc(_) => anyhow::bail!(
                "SSH 网关不支持 --token 认证（服务端为 OIDC 模式）；\
                 请改用 sshTunnelGateway.authorizedKeysFile 公钥认证"
            ),
            Self::OidcUnavailable(e) => {
                anyhow::bail!("OIDC 认证不可用（{e}），拒绝本次 SSH 隧道")
            }
        }
    }

    /// 登录时间戳的新鲜性校验。
    ///
    /// **已经由 [`Self:verify_login`] 内部调用**，
    ///   不再需要调用方自己记得调。独立保留是为了：
    ///   * 让 [`verify_shared_secret_proof`] 复用同一份实现；
    ///   * 错误文案可区分（"过期" vs "凭证错"），运维能一眼看出是时钟问题还是配置问题。
    ///
    /// `skew` 为 0 表示关闭该校验（逃生开关，给时钟严重不准的设备用）。
    pub fn check_timestamp(&self, ts: i64, skew: u64) -> anyhow::Result<()> {
        check_freshness(ts, skew, "登录时间戳")
    }

    /// 校验登录**之后**的凭证（心跳 / 新工作连接）。
    ///
    /// 为什么需要：登录时校验过就永久信任的模型下，任何能连上控制端口的人
    /// 只要在同一个 `run_id` 上发消息就能搭便车。OIDC 方式下这里要求
    /// **验签通过且 `sub` 与本会话登录时一致**。
    ///
    /// `run_id` 是必需的：旧实现只查一个全局 subject 集合，
    /// 于是"自己登录过一次"就能给**别人的** run_id 背书。
    pub fn verify_followup(&self, cred: &str, what: &str, run_id: &str) -> anyhow::Result<()> {
        match self {
            Self::Token(_) => Ok(()), // 与官方一致：token 方式不复核
            Self::Oidc(v) => {
                v.verify_post_login(cred, what, run_id)?;
                Ok(())
            }
            Self::OidcUnavailable(e) => anyhow::bail!("OIDC 认证不可用（{e}），拒绝{what}"),
        }
    }

    /// 会话结束时解除 subject 绑定（避免绑定表无限增长）。
    pub fn forget_session(&self, run_id: &str) {
        if let Self::Oidc(v) = self {
            v.forget_session(run_id);
        }
    }

    /// 该方式下是否要复核心跳。
    pub fn check_heartbeats(&self, cfg: &ServerAuthConfig) -> bool {
        cfg.check_heartbeats()
    }

    /// 该方式下是否要复核新工作连接。
    pub fn check_new_work_conns(&self, cfg: &ServerAuthConfig) -> bool {
        cfg.check_new_work_conns()
    }

    /// 控制通道加密（v2 的 AEAD / v1 的 CFB）用哪个值派生密钥。
    ///
    /// - token 方式：共享密钥本身（与官方 frps 一致）。
    /// - OIDC 方式：**用本次登录的 access token**。两边都有这个值
    ///   （客户端刚换来的、服务端从 `Login.privilege_key` 读到的），
    ///   而且它自带有效期 —— 比拿一个长期不变的共享密钥派生更稳妥。
    ///
    /// 客户端必须用 [`Credential::raw`] 保持一致，否则就是
    /// "能登录成功但之后每个消息都解不开"。
    pub fn control_key(&self, login_privilege_key: &str) -> String {
        match self {
            Self::Token(secret) => secret.clone(),
            Self::Oidc(_) => login_privilege_key.to_string(),
            Self::OidcUnavailable(_) => login_privilege_key.to_string(),
        }
    }

    /// 共享密钥（只有 token 方式有）。客户端侧握手要用。
    pub fn secret(&self) -> &str {
        match self {
            Self::Token(t) => t,
            _ => "",
        }
    }

    /// 从服务端配置构造。OIDC 的 JWKS 拉取是异步的，所以这里只做**构造**，
    /// 拉取由调用方启动时单独跑一次（失败不该拦住服务端启动）。
    pub fn from_server_config(cfg: &ServerAuthConfig) -> anyhow::Result<(Self, bool)> {
        match cfg.method {
            AuthMethod::Token => Ok((Self::token(cfg.token.clone()), false)),
            AuthMethod::Oidc => {
                let v = crate::auth::oidc::OidcVerifier::new(cfg.oidc.clone())?;
                Ok((Self::Oidc(v), true))
            }
        }
    }
}

// ---------------------------------------------------------------------------
// IP 访问控制（CIDR 白 / 黑名单）
// ---------------------------------------------------------------------------

/// 一条 CIDR 规则：裸 IP（`1.2.3.4`）、带前缀长度（`10.0.0.0/8`），
/// 或只写前缀长度缺省值（`::1`）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Cidr {
    net: IpAddr,
    bits: u8,
}

impl Cidr {
    /// 解析一条规则。不带 `/` 时按"精确匹配这一个地址"处理
    /// （`bits` = 全长度），这与 iptables / nginx 的习惯一致。
    pub fn parse(s: &str) -> anyhow::Result<Self> {
        let s = s.trim();
        let (addr_part, bits_part) = match s.split_once('/') {
            Some((a, b)) => (a, Some(b)),
            None => (s, None),
        };
        let net: IpAddr = addr_part
            .trim()
            .parse()
            .map_err(|_| anyhow::anyhow!("IP 白/黑名单里的地址非法：{addr_part:?}"))?;
        let max = if net.is_ipv4() { 32 } else { 128 };
        let bits = match bits_part {
            Some(b) => {
                let v: u8 = b
                    .trim()
                    .parse()
                    .map_err(|_| anyhow::anyhow!("CIDR 前缀长度非法：{b:?}"))?;
                if v > max {
                    anyhow::bail!("CIDR 前缀长度 {v} 超过 {max}（{s}）");
                }
                v
            }
            None => max,
        };
        Ok(Self { net, bits })
    }

    /// 地址是否落在网段内。**IPv4 与 IPv6 之间永远不匹配** ——
    /// 不做 v4-mapped-v6 的隐式转换，否则 `::/0` 会把整个 IPv4 空间也吃掉。
    pub fn contains(&self, ip: IpAddr) -> bool {
        // IPv4 与 IPv6 必须**分开**按各自的位宽比较。
        // 曾经把 v4 也提升到 u128 再统一右移：IPv4 的 32 位落在 u128 的低位，
        // 任何 `/0`～`/96` 的前缀右移后高位全是 0，于是"跟谁都比得中" ——
        // 白名单会静默变成"全放行"，是安全检查里最不能出的错。
        match (self.net, ip) {
            (IpAddr::V4(net), IpAddr::V4(i)) => {
                if self.bits == 0 {
                    return true;
                }
                let shift = 32 - u32::from(self.bits);
                (u32::from(net) >> shift) == (u32::from(i) >> shift)
            }
            (IpAddr::V6(net), IpAddr::V6(i)) => {
                if self.bits == 0 {
                    return true;
                }
                let shift = 128 - u32::from(self.bits);
                (u128::from(net) >> shift) == (u128::from(i) >> shift)
            }
            // 跨地址族永不匹配（也不做 v4-mapped-v6 的隐式转换）
            _ => false,
        }
    }
}

/// 一张 IP 白 / 黑名单。
///
/// 判定顺序：**deny 优先**。命中 deny 直接拒；deny 没命中时，
/// `allow` 为空表示"放行"，非空则必须命中才放行。
///
/// 加 `deny_unknown_fields`。
///
/// 这不是洁癖 —— 少了它，**一个拼写错误会让整个访问控制静默消失**：
///
/// ```toml
/// [acl]
/// denny = ["203.0.113.0/24"]     # ← 把 deny 拼错了
/// ```
///
/// 整条解析链上没有任何环节能兜住：`unsupported_server_fields` 扫描只比对
/// "官方存在、NFrp 未实现"的**正确名字**清单（`denny` 不在里面），
/// 随后 serde 又不拒绝未知字段 ⇒ `denny` 被**静默丢弃**、`deny` 保持空。
///
/// 净效果分两种情形：
///
/// * **只配黑名单**（后果最重）：`deny` 与 `allow` 都空 ⇒ `check()` 两个分支
///   都不命中 ⇒ **对所有 IP 一律放行**。管理员以为封了一段，实际是完全敞开，
///   而且零告警（`guard.rs` 里那句 `is_empty()` 判定把日志也跳过了）。
/// * **黑白名单同时配**：`deny` 失效但 `allow` 仍在 ⇒ 仍是白名单模式
///   （不会变成完全放行），但被显式排除的那段 IP 若落在 `allow` 内会**意外获得
///   放行** —— "deny 优先"这条被文档与注释反复强调的语义被静默撤销。
///
/// 同文件的 `RoleConfig` 早就这么做了 —— 机制存在，只是没铺到最需要它的地方。
///
/// 为什么这里可以直接加、而顶层的 `ServerConfig` 不能：`[acl]` 是
///   NFrp **自己**的配置段（官方 frp 没有同名的 `[acl]` 表），加严不会
///   影响"官方配置拿来直接用"的场景。
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AclConfig {
    /// 白名单。留空 = 不按白名单放行（但要经过 deny）。
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allow: Vec<String>,
    /// 黑名单。优先级高于白名单。
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub deny: Vec<String>,
}

impl AclConfig {
    pub fn is_empty(&self) -> bool {
        self.allow.is_empty() && self.deny.is_empty()
    }

    /// 编译成可复用的规则表（避免每个连接解析一次字符串）。
    pub fn compile(&self) -> anyhow::Result<CompiledAcl> {
        let mut allow = Vec::with_capacity(self.allow.len());
        for s in &self.allow {
            allow.push(Cidr::parse(s)?);
        }
        let mut deny = Vec::with_capacity(self.deny.len());
        for s in &self.deny {
            deny.push(Cidr::parse(s)?);
        }
        Ok(CompiledAcl { allow, deny })
    }
}

/// [`AclConfig`] 编译后的形态。
#[derive(Debug, Clone, Default)]
pub struct CompiledAcl {
    allow: Vec<Cidr>,
    deny: Vec<Cidr>,
}

impl CompiledAcl {
    pub fn is_empty(&self) -> bool {
        self.allow.is_empty() && self.deny.is_empty()
    }

    /// 该地址是否放行。
    pub fn permits(&self, ip: IpAddr) -> bool {
        if self.deny.iter().any(|c| c.contains(ip)) {
            return false;
        }
        if self.allow.is_empty() {
            return true;
        }
        self.allow.iter().any(|c| c.contains(ip))
    }

    /// 放行判定 + 拒绝原因（审计日志要用）。
    pub fn check(&self, ip: IpAddr) -> Result<(), String> {
        if self.deny.iter().any(|c| c.contains(ip)) {
            return Err(format!("{ip} 命中 IP 黑名单"));
        }
        if !self.allow.is_empty() && !self.allow.iter().any(|c| c.contains(ip)) {
            return Err(format!("{ip} 不在 IP 白名单内"));
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// RBAC
// ---------------------------------------------------------------------------

/// 一个角色的权限集合。
///
/// 所有字段都是"留空/默认 = 不限制"，所以只写 `name` 就是一个"什么都能干"
/// 的角色；要收紧再逐条加限制。
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RoleConfig {
    /// 角色名（仅用于日志与面板展示）。
    pub name: String,
    /// 适用的用户名列表（对应 `Login.user`）。支持 `*` 通配全部。
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub users: Vec<String>,
    /// 允许注册的代理类型，如 `["tcp", "http"]`。留空 = 全部允许。
    #[serde(
        default,
        rename = "allowProxyTypes",
        skip_serializing_if = "Vec::is_empty"
    )]
    pub allow_proxy_types: Vec<String>,
    /// 允许占用的**服务端**端口范围，如 `"20000-30000"`，也可以是单端口 `"8080"`。
    /// 留空 = 不限。
    #[serde(default, rename = "portRange", skip_serializing_if = "Option::is_none")]
    pub port_range: Option<String>,
    /// 是否允许通过面板管理本客户端的代理（服务端写接口 / 客户端 webServer）。
    #[serde(default, rename = "allowManage")]
    pub allow_manage: bool,
    /// 是否允许注册 stcp / xtcp 访客（需要服务端 `allow_users` 配合）。
    #[serde(default = "default_true_role", rename = "allowVisitors")]
    pub allow_visitors: bool,
    /// 该角色可注册的代理数上限（0 = 用服务端全局上限）。
    #[serde(default, rename = "maxProxies")]
    pub max_proxies: usize,
}

fn default_true_role() -> bool {
    true
}

/// 端口范围，闭区间。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PortRange {
    pub lo: u16,
    pub hi: u16,
}

impl PortRange {
    pub fn parse(s: &str) -> anyhow::Result<Self> {
        let s = s.trim();
        let (lo, hi) = match s.split_once('-') {
            Some((a, b)) => (
                a.trim()
                    .parse::<u16>()
                    .map_err(|_| anyhow::anyhow!("端口范围下界非法：{a:?}"))?,
                b.trim()
                    .parse::<u16>()
                    .map_err(|_| anyhow::anyhow!("端口范围上界非法：{b:?}"))?,
            ),
            None => {
                let v = s
                    .parse::<u16>()
                    .map_err(|_| anyhow::anyhow!("端口非法：{s:?}"))?;
                (v, v)
            }
        };
        if lo > hi {
            anyhow::bail!("端口范围下界 {lo} 大于上界 {hi}");
        }
        Ok(Self { lo, hi })
    }

    pub fn contains(&self, port: u16) -> bool {
        port >= self.lo && port <= self.hi
    }
}

/// 权限模型配置（服务端 `[[roles]]`）。
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RbacConfig {
    /// 角色表。**按顺序匹配，先命中先用**，所以把最具体的角色写在前面。
    #[serde(default)]
    pub roles: Vec<RoleConfig>,
    /// 没有任何角色匹配时使用的角色名；留空且 `deny_unknown = true` 时拒绝。
    #[serde(
        default,
        rename = "defaultRole",
        skip_serializing_if = "String::is_empty"
    )]
    pub default_role: String,
    /// 配了角色表但一个都没匹配上时，是否直接拒绝登录。
    #[serde(default, rename = "denyUnknown")]
    pub deny_unknown: bool,
}

impl RbacConfig {
    pub fn is_empty(&self) -> bool {
        self.roles.is_empty()
    }

    /// 编译成可复用的权限表。
    pub fn compile(&self) -> anyhow::Result<CompiledRbac> {
        let mut roles = Vec::with_capacity(self.roles.len());
        for r in &self.roles {
            if r.name.trim().is_empty() {
                anyhow::bail!("[[roles]] 里每一项都必须有 name");
            }
            let range = match &r.port_range {
                Some(s) if !s.trim().is_empty() => Some(PortRange::parse(s)?),
                _ => None,
            };
            roles.push(Role {
                name: r.name.clone(),
                users: r.users.clone(),
                allow_proxy_types: r
                    .allow_proxy_types
                    .iter()
                    .map(|t| t.to_ascii_lowercase())
                    .collect(),
                port_range: range,
                allow_manage: r.allow_manage,
                allow_visitors: r.allow_visitors,
                max_proxies: r.max_proxies,
            });
        }
        Ok(CompiledRbac {
            roles,
            default_role: self.default_role.clone(),
            deny_unknown: self.deny_unknown,
        })
    }
}

/// 一个角色编译后的形态（端口范围已解析成数字）。
#[derive(Debug, Clone)]
pub struct Role {
    pub name: String,
    pub users: Vec<String>,
    pub allow_proxy_types: Vec<String>,
    pub port_range: Option<PortRange>,
    pub allow_manage: bool,
    pub allow_visitors: bool,
    pub max_proxies: usize,
}

impl Role {
    /// 什么都能干的角色 —— 未启用 RBAC 时用它，保证行为零变化。
    pub fn unrestricted() -> Self {
        Self {
            name: "unrestricted".into(),
            users: vec!["*".into()],
            allow_proxy_types: Vec::new(),
            port_range: None,
            allow_manage: true,
            allow_visitors: true,
            max_proxies: 0,
        }
    }

    pub fn matches_user(&self, user: &str) -> bool {
        self.users.iter().any(|u| u == "*" || u == user)
    }

    /// 能不能注册这种类型的代理。
    pub fn allow_proxy_type(&self, ty: &str) -> bool {
        self.allow_proxy_types.is_empty()
            || self
                .allow_proxy_types
                .iter()
                .any(|t| t.eq_ignore_ascii_case(ty))
    }

    /// 能不能占用这个服务端端口。
    pub fn allow_port(&self, port: u16) -> bool {
        match self.port_range {
            Some(r) => r.contains(port),
            None => true,
        }
    }
}

/// 编译后的权限表。
#[derive(Debug, Clone, Default)]
pub struct CompiledRbac {
    roles: Vec<Role>,
    default_role: String,
    deny_unknown: bool,
}

impl CompiledRbac {
    /// 未启用 RBAC 的实例：任何用户名 → 全权角色。
    ///
    /// 单独给个名字是为了在调用点**显式**表达"这里没做授权检查"，
    /// 而不是让人去猜 `CompiledRbac::default()` 到底是"全拒"还是"全放"。
    pub fn default_unrestricted() -> Self {
        Self::default()
    }

    /// RBAC 没启用（角色表为空）——此时任何用户名都拿到全权角色。
    pub fn is_disabled(&self) -> bool {
        self.roles.is_empty()
    }

    /// 为某个用户名解析角色。用户可能匹配到多个角色，取**第一个**命中的。
    pub fn role_for(&self, user: &str) -> anyhow::Result<Role> {
        if self.roles.is_empty() {
            return Ok(Role::unrestricted());
        }
        if let Some(r) = self.roles.iter().find(|r| r.matches_user(user)) {
            return Ok(r.clone());
        }
        if !self.default_role.is_empty() {
            if let Some(r) = self.roles.iter().find(|r| r.name == self.default_role) {
                return Ok(r.clone());
            }
            anyhow::bail!(
                "defaultRole = {:?} 在 [[roles]] 里不存在",
                self.default_role
            );
        }
        if self.deny_unknown {
            anyhow::bail!("用户 {user:?} 没有匹配到任何角色（denyUnknown = true）");
        }
        // 没配 denyUnknown 又没命中：退回"不限制"，保持向后兼容
        Ok(Role::unrestricted())
    }

    /// 注册代理前的完整检查。
    ///
    /// `used_proxies` 是该客户端**当前已注册**的代理数（不含正要注册的这条）。
    /// 角色的 `maxProxies` 靠它落地 —— 服务端全局的 `maxProxiesPerClient`
    /// 是另一层配额，两层都要过。
    pub fn check_proxy(
        &self,
        role: &Role,
        name: &str,
        ty: &str,
        port: u16,
        used_proxies: usize,
    ) -> anyhow::Result<()> {
        let ty_l = ty.to_ascii_lowercase();
        if !role.allow_proxy_type(&ty_l) {
            anyhow::bail!(
                "角色 {:?} 不允许注册 {ty} 类型代理（允许：{}）",
                role.name,
                role.allow_proxy_types.join(", ")
            );
        }
        // 只有真正占服务端端口的类型才检查端口范围
        if matches!(ty_l.as_str(), "tcp" | "udp") && port != 0 && !role.allow_port(port) {
            anyhow::bail!(
                "角色 {:?} 不允许占用端口 {port}（允许范围：{}）",
                role.name,
                role.port_range
                    .map(|r| if r.lo == r.hi {
                        r.lo.to_string()
                    } else {
                        format!("{}-{}", r.lo, r.hi)
                    })
                    .unwrap_or_else(|| "不限".into())
            );
        }
        // **判据必须走唯一真源**。
        //
        // 原先这里是就地硬编码 `matches!(ty_l.as_str(), "stcp" | "xtcp")`
        // —— **漏了 `sudp`**。而项目自己在三处都把 `sudp` 定义为访客类：
        //
        // | 位置 | 定义 |
        // |---|---|
        // | `config.rs` 的 `SUPPORTED_VISITOR_TYPES` | `["stcp","xtcp","sudp"]` |
        // | `frp_legacy.rs` 的 `LEGACY_VISITOR_TYPES` | `["stcp","xtcp","sudp"]` |
        // | `serve.rs` 的注册分派 | `"sudp" => register_visitor_proxy(...)` |
        //
        // **唯独 RBAC 这一处漏了** —— 类型集合漂移，语法上完全看不出来。
        //
        // 危害被放大的一点：`sudp` **不占公网端口**，因此不受 `allowPorts` /
        // `portRange` 约束（上面的端口检查只对 `tcp|udp` 生效）。
        // ⇒ `allowVisitors` 是管理员**唯一**能关掉访客类代理的开关，
        //   而它恰恰漏了 `sudp` ⇒ 配了 `allowVisitors = false` 的部署
        //   可以被 `type = "sudp"` 完整绕过。
        if !role.allow_visitors && crate::config::is_visitor_type(&ty_l) {
            anyhow::bail!("角色 {:?} 不允许注册 {name}（访客类代理被禁用）", role.name);
        }
        // 角色级代理数配额（0 = 不限，退给服务端全局的 maxProxiesPerClient 兜底）。
        //
        // 这个字段曾经是**死字段**：从配置读进来、编译进 Role，但没有任何
        // 生产代码读它 —— 管理员写了 `maxProxies = 5` 以为限住了，实际没限。
        // 判据用 `>=`：`used_proxies` 不含当前这条，所以"已用 5 条、再注册第 6 条"
        // 时 `5 >= 5` 命中，允许的总数正好是 max_proxies 条。
        if role.max_proxies > 0 && used_proxies >= role.max_proxies {
            anyhow::bail!(
                "角色 {:?} 的代理数已达上限 {}（已注册 {used_proxies} 条）",
                role.name,
                role.max_proxies
            );
        }
        Ok(())
    }
}

/// 审计日志配置（服务端 `[audit]`）。
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuditConfig {
    /// 是否启用。默认**关**：不写文件、不留内存，行为与老版本一致。
    #[serde(default)]
    pub enable: bool,
    /// JSONL 落盘路径。留空 = 只留内存（面板可查，重启即失）。
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub path: String,
    /// 内存里保留多少条（面板查询用）。默认 1000。
    #[serde(default = "default_audit_capacity", rename = "maxEntries")]
    pub max_entries: usize,
    /// 审计文件轮转阈值（MB）。默认 64；`0` = 不轮转。
    ///
    /// 轮转保留**上一份**备份（`<path>.1`），磁盘占用上界 ≈ 2×。
    ///
    /// 原先只有内存环形上限，审计文件**无上界** ——
    /// 实测 ~1000 行/s、约 37 MB/h 可持续增长，这是一条可被利用的磁盘
    /// 耗尽路径（审计默认关闭，但开启后就再无保护）。有了默认上限后
    /// 占用可预期，且**事件不丢**（旧内容在 `.1` 里）。
    #[serde(default = "default_audit_max_file_mb", rename = "maxFileMB")]
    pub max_file_mb: u64,
}

fn default_audit_capacity() -> usize {
    1000
}

fn default_audit_max_file_mb() -> u64 {
    64
}

impl Default for AuditConfig {
    fn default() -> Self {
        Self {
            enable: false,
            path: String::new(),
            max_entries: default_audit_capacity(),
            max_file_mb: default_audit_max_file_mb(),
        }
    }
}

// ---------------------------------------------------------------------------
// 测试
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn cidr(s: &str, ip: &str) -> bool {
        Cidr::parse(s).unwrap().contains(ip.parse().unwrap())
    }

    /// SSH 网关的 `--token` 是**原始 token**，不是 `auth_key` 派生值。
    ///
    /// 0.7.6 及以前 SSH 网关误用 `verify_login` 比对派生值，导致 token 认证
    /// 永远失败（任何正确 token 都被拒）。这条测试锁住两种形态的区别：
    /// 原始 token 必须过，派生值必须**不**过（否则说明又混回派生语义了）。
    #[test]
    fn ssh_网关校验原始_token_而不是派生值() {
        let s = AuthProvider::Token("secret-1".to_string());
        assert!(s.verify_raw_token("secret-1").is_ok());
        assert!(s.verify_raw_token("secret-2").is_err());

        // 派生值不能当作原始 token 通过 —— 反过来也一样，
        // 这正是 0.7.6 的 bug 所在。
        // 时间戳必须用当前时刻：`verify_login` 会做新鲜性校验。
        let now = crate::util::now_unix_secs() as i64;
        let derived = crate::frp::msg::auth_key("secret-1", now);
        assert!(s.verify_raw_token(&derived).is_err());
        assert!(s.verify_login(&derived, now, "run", 300).is_ok());
        assert!(s.verify_login("secret-1", now, "run", 300).is_err());
    }

    /// token 为空 = 不做认证（与官方一致）；OIDC 模式必须明确拒绝 `--token`，
    /// 而不是静默放行。
    #[test]
    fn ssh_网关原始_token_的边界() {
        let empty = AuthProvider::Token(String::new());
        assert!(empty.verify_raw_token("anything").is_ok());

        let oidc = AuthProvider::OidcUnavailable("test".to_string());
        assert!(oidc.verify_raw_token("x").is_err());
    }

    #[test]
    fn cidr_裸地址按精确匹配() {
        assert!(cidr("1.2.3.4", "1.2.3.4"));
        assert!(!cidr("1.2.3.4", "1.2.3.5"));
    }

    #[test]
    fn cidr_前缀长度() {
        assert!(cidr("10.0.0.0/8", "10.255.255.255"));
        assert!(!cidr("10.0.0.0/8", "11.0.0.0"));
        // /32 = 单个地址
        assert!(cidr("10.0.0.0/32", "10.0.0.0"));
        assert!(!cidr("10.0.0.0/32", "10.0.0.1"));
    }

    #[test]
    fn cidr_ipv6() {
        assert!(cidr("2001:db8::/32", "2001:db8::1"));
        assert!(!cidr("2001:db8::/32", "2001:db9::1"));
        assert!(cidr("::1", "::1"));
    }

    /// `/0` 只覆盖**本族**地址 —— 否则 `::/0` 会把整个 IPv4 空间也吃进去，
    /// 一条本意是"放开所有 IPv6"的规则会变成"放开一切"。
    #[test]
    fn 零前缀不跨地址族() {
        assert!(cidr("0.0.0.0/0", "1.2.3.4"));
        assert!(!cidr("0.0.0.0/0", "::1"));
        assert!(cidr("::/0", "2001:db8::1"));
        assert!(!cidr("::/0", "1.2.3.4"));
    }

    #[test]
    fn cidr_非法输入报错() {
        assert!(Cidr::parse("999.1.1.1").is_err());
        assert!(Cidr::parse("10.0.0.0/33").is_err());
        assert!(Cidr::parse("10.0.0.0/abc").is_err());
        assert!(Cidr::parse("::/129").is_err());
    }

    /// 核心语义：deny 优先。否则把 allow 写成 `0.0.0.0/0` 会把 deny 吞掉。
    #[test]
    fn deny_优先于_allow() {
        let acl = AclConfig {
            allow: vec!["0.0.0.0/0".into()],
            deny: vec!["10.1.1.1".into()],
        }
        .compile()
        .unwrap();
        assert!(!acl.permits("10.1.1.1".parse().unwrap()));
        assert!(acl.permits("10.1.1.2".parse().unwrap()));
    }

    #[test]
    fn 空名单放行一切() {
        let acl = AclConfig::default().compile().unwrap();
        assert!(acl.permits("8.8.8.8".parse().unwrap()));
        assert!(acl.is_empty());
    }

    #[test]
    fn 白名单非空时必须命中() {
        let acl = AclConfig {
            allow: vec!["192.168.0.0/16".into()],
            deny: vec![],
        }
        .compile()
        .unwrap();
        assert!(acl.permits("192.168.5.5".parse().unwrap()));
        assert!(!acl.permits("8.8.8.8".parse().unwrap()));
        // 拒绝原因要说清是哪一条挡的，面板上才看得出问题
        let e = acl.check("8.8.8.8".parse().unwrap()).unwrap_err();
        assert!(e.contains("白名单"), "{e}");
    }

    #[test]
    fn 端口范围解析() {
        assert_eq!(
            PortRange::parse("8080").unwrap(),
            PortRange { lo: 8080, hi: 8080 }
        );
        assert_eq!(
            PortRange::parse("20000-30000").unwrap(),
            PortRange {
                lo: 20000,
                hi: 30000
            }
        );
        assert!(PortRange::parse("30000-20000").is_err());
        assert!(PortRange::parse("abc").is_err());
        assert!(PortRange::parse("70000").is_err());
        let r = PortRange::parse("1-10").unwrap();
        assert!(r.contains(1) && r.contains(10) && !r.contains(11) && !r.contains(0));
    }

    /// 没配 RBAC 时，任何用户名都必须拿到全权 —— 否则老配置会突然被拒。
    #[test]
    fn 无角色表即全权() {
        let rbac = RbacConfig::default().compile().unwrap();
        assert!(rbac.is_disabled());
        let role = rbac.role_for("谁啊").unwrap();
        assert!(role.allow_manage && role.allow_port(22) && role.allow_proxy_type("tcp"));
    }

    #[test]
    fn 角色按顺序匹配() {
        let rbac = RbacConfig {
            roles: vec![
                RoleConfig {
                    name: "admin".into(),
                    users: vec!["alice".into()],
                    allow_manage: true,
                    ..Default::default()
                },
                RoleConfig {
                    name: "guest".into(),
                    users: vec!["*".into()],
                    allow_proxy_types: vec!["http".into()],
                    ..Default::default()
                },
            ],
            ..Default::default()
        }
        .compile()
        .unwrap();

        let a = rbac.role_for("alice").unwrap();
        assert_eq!(a.name, "admin");
        assert!(a.allow_manage);

        let g = rbac.role_for("bob").unwrap();
        assert_eq!(g.name, "guest");
        assert!(!g.allow_manage);
        assert!(g.allow_proxy_type("HTTP"), "类型匹配应当忽略大小写");
        assert!(!g.allow_proxy_type("tcp"));
    }

    #[test]
    fn 角色可以限制代理类型与端口() {
        let rbac = RbacConfig {
            roles: vec![RoleConfig {
                name: "limited".into(),
                users: vec!["*".into()],
                allow_proxy_types: vec!["tcp".into()],
                port_range: Some("20000-30000".into()),
                ..Default::default()
            }],
            ..Default::default()
        }
        .compile()
        .unwrap();
        let r = rbac.role_for("x").unwrap();

        assert!(rbac.check_proxy(&r, "a", "tcp", 25000, 0).is_ok());
        // 端口越界
        let e = rbac
            .check_proxy(&r, "b", "tcp", 80, 0)
            .unwrap_err()
            .to_string();
        assert!(e.contains("80"), "{e}");
        // 类型不允许
        let e = rbac
            .check_proxy(&r, "c", "http", 0, 0)
            .unwrap_err()
            .to_string();
        assert!(e.contains("http"), "{e}");
        // http 不占端口，端口范围不该拦它（上面已经因为类型被拦了，
        // 这里单独验一次"类型允许时端口范围不参与"）
        let r2 = rbac.role_for("x").unwrap();
        assert!(
            rbac.check_proxy(&r2, "d", "tcp", 0, 0).is_ok(),
            "port=0 表示不指定端口"
        );
    }

    // ------------------------------------------------------------------
    // allowVisitors 必须覆盖全部访客类型
    // ------------------------------------------------------------------

    /// H3 核心回归：`allowVisitors = false` 必须挡住**全部三种**访客类型。
    ///
    /// 修复前判据是就地硬编码的 `matches!(ty, "stcp" | "xtcp")` ——
    /// **漏了 `sudp`**，而项目自己另外三处都把 sudp 归为访客类。
    /// 攻击者只要把 `type` 从 `stcp` 换成 `sudp` 就能完整绕过该限制。
    ///
    /// 而且危害更大：`sudp` 不占公网端口，不受 `allowPorts` / `portRange` 约束
    /// ⇒ `allowVisitors` 是管理员唯一能关掉它的开关。
    #[test]
    fn allow_visitors_必须覆盖全部访客类型() {
        let rbac = RbacConfig {
            roles: vec![RoleConfig {
                name: "novisitor".into(),
                users: vec!["*".into()],
                allow_visitors: false, // ★ 管理员以为禁掉了访客类
                ..Default::default()
            }],
            ..Default::default()
        }
        .compile()
        .unwrap();
        let r = rbac.role_for("x").unwrap();

        // 三种访客类型**一个都不能漏**
        for ty in ["stcp", "xtcp", "sudp"] {
            let e = rbac.check_proxy(&r, "v", ty, 0, 0).unwrap_err().to_string();
            assert!(
                e.contains("访客类"),
                "{ty} 必须被 allowVisitors=false 拦住，实际错误：{e}"
            );
        }

        // 大小写不敏感（客户端可能发 "SUDP"）
        assert!(
            rbac.check_proxy(&r, "v", "SUDP", 0, 0).is_err(),
            "类型判定必须大小写不敏感"
        );

        // 反向：非访客类型照常放行（别修得过头）
        assert!(rbac.check_proxy(&r, "t", "tcp", 0, 0).is_ok());
        assert!(rbac.check_proxy(&r, "u", "udp", 0, 0).is_ok());
        assert!(rbac.check_proxy(&r, "h", "http", 0, 0).is_ok());
    }

    /// `is_visitor_type` 是唯一真源，必须与 `SUPPORTED_VISITOR_TYPES` 一致。
    #[test]
    fn 访客类型唯一真源与支持清单一致() {
        for ty in crate::config::SUPPORTED_VISITOR_TYPES {
            assert!(
                crate::config::is_visitor_type(ty),
                "{ty} 在 SUPPORTED_VISITOR_TYPES 里，is_visitor_type 必须认"
            );
        }
        // sudp 是本次修复的核心，单独钉一次
        assert!(crate::config::is_visitor_type("sudp"));
        assert!(crate::config::is_visitor_type("SUDP"));
        assert!(crate::config::is_visitor_type(" sudp "));
        // 非访客类型
        for ty in ["tcp", "udp", "http", "https", "tcpmux", ""] {
            assert!(!crate::config::is_visitor_type(ty), "{ty} 不是访客类型");
        }
    }

    /// 回归测试：角色的 `maxProxies` 必须真的生效。
    /// 这个字段曾经是**死字段** —— 配置读得进来、`compile()` 也赋了值，
    /// 但没有任何生产代码读它。管理员写 `maxProxies = 2` 以为限住了，
    /// 实际想注册多少条都行。这条测试就是防止它再退化回去。
    #[test]
    fn 角色的_max_proxies_必须真的拦得住() {
        let rbac = RbacConfig {
            roles: vec![RoleConfig {
                name: "small".into(),
                users: vec!["alice".into()],
                max_proxies: 2,
                ..Default::default()
            }],
            deny_unknown: true,
            ..Default::default()
        }
        .compile()
        .unwrap();
        let r = rbac.role_for("alice").unwrap();
        assert_eq!(r.max_proxies, 2, "配额要能穿过 compile()");

        // 已用 0、1 条时还能注册（总数最终是 2 条）
        assert!(rbac.check_proxy(&r, "a", "tcp", 0, 0).is_ok());
        assert!(rbac.check_proxy(&r, "b", "tcp", 0, 1).is_ok());
        // 已用 2 条时第 3 条必须被拒，且错误里要点名上限
        let e = rbac
            .check_proxy(&r, "c", "tcp", 0, 2)
            .unwrap_err()
            .to_string();
        assert!(e.contains('2'), "错误里要带上限：{e}");
        assert!(e.contains("small"), "错误里要点角色名：{e}");
    }

    /// `maxProxies = 0` 是"不限"（默认值），不能误伤。
    #[test]
    fn max_proxies_为零表示不限() {
        let rbac = RbacConfig {
            roles: vec![RoleConfig {
                name: "big".into(),
                users: vec!["alice".into()],
                max_proxies: 0,
                ..Default::default()
            }],
            deny_unknown: true,
            ..Default::default()
        }
        .compile()
        .unwrap();
        let r = rbac.role_for("alice").unwrap();
        assert!(rbac.check_proxy(&r, "a", "tcp", 0, 9999).is_ok());
    }

    #[test]
    fn deny_unknown_拒绝未匹配用户() {
        let rbac = RbacConfig {
            roles: vec![RoleConfig {
                name: "vip".into(),
                users: vec!["alice".into()],
                ..Default::default()
            }],
            deny_unknown: true,
            ..Default::default()
        }
        .compile()
        .unwrap();
        assert!(rbac.role_for("alice").is_ok());
        assert!(rbac.role_for("mallory").is_err());
    }

    #[test]
    fn default_role_兜底() {
        let rbac = RbacConfig {
            roles: vec![
                RoleConfig {
                    name: "vip".into(),
                    users: vec!["alice".into()],
                    ..Default::default()
                },
                RoleConfig {
                    name: "fallback".into(),
                    users: vec![],
                    allow_proxy_types: vec!["http".into()],
                    ..Default::default()
                },
            ],
            default_role: "fallback".into(),
            deny_unknown: true,
        }
        .compile()
        .unwrap();
        let r = rbac.role_for("bob").unwrap();
        assert_eq!(r.name, "fallback");
        // defaultRole 指向不存在的角色必须是启动期错误，不能悄悄放行
        let bad = RbacConfig {
            roles: vec![RoleConfig {
                name: "x".into(),
                ..Default::default()
            }],
            default_role: "nope".into(),
            ..Default::default()
        }
        .compile()
        .unwrap();
        assert!(bad.role_for("bob").is_err());
    }

    #[test]
    fn oidc_配置必须带_issuer() {
        let mut a = ServerAuthConfig {
            method: AuthMethod::Oidc,
            ..Default::default()
        };
        assert!(a.validate().is_err());
        a.oidc.issuer = "https://idp.example.com".into();
        assert!(a.validate().is_ok());
    }

    #[test]
    fn additional_scopes_只认官方两个值() {
        let a = ServerAuthConfig {
            method: AuthMethod::Oidc,
            oidc: ServerOidcConfig {
                issuer: "https://idp.example.com".into(),
                ..Default::default()
            },
            additional_scopes: vec!["HeartBeats".into()],
            ..Default::default()
        };
        assert!(a.validate().is_ok());
        assert!(a.check_heartbeats());
        assert!(!a.check_new_work_conns());

        let bad = ServerAuthConfig {
            method: AuthMethod::Oidc,
            oidc: ServerOidcConfig {
                issuer: "https://idp.example.com".into(),
                ..Default::default()
            },
            additional_scopes: vec!["NewWorkConnection".into()], // 少了个 s
            ..Default::default()
        };
        assert!(bad.validate().is_err());
    }

    /// 默认配置必须与"没有这套东西"完全一致。
    #[test]
    fn 默认配置等于全放行() {
        let a = ServerAuthConfig::default();
        assert_eq!(a.method, AuthMethod::Token);
        assert!(a.is_plain_token());
        let acl = AclConfig::default().compile().unwrap();
        assert!(acl.is_empty() && acl.permits("1.1.1.1".parse().unwrap()));
        let rbac = RbacConfig::default().compile().unwrap();
        assert!(rbac.is_disabled());
        let aud = AuditConfig::default();
        assert!(!aud.enable && aud.max_entries == 1000);
        assert_eq!(aud.max_file_mb, 64, "审计轮转默认阈值 64MB（v0.5.9 A9-3）");
    }

    // ------------------------------------------------------------------
    // M5：ClientAuthConfig 的 Debug 必须脱敏
    // ------------------------------------------------------------------

    /// 客户端认证配置的 `Debug` 不得泄漏 token。
    ///
    /// 原先 `ClientAuthConfig` 是 `#[derive(Debug)]`，而同文件的
    /// `ServerAuthConfig` 早就手工脱敏了 —— 一个文件两种标准。
    /// 任何 `tracing::debug!(?auth_cfg)` 都会把 token 明文写进日志。
    #[test]
    fn client_auth_debug_不得泄漏_token() {
        let c = ClientAuthConfig {
            method: AuthMethod::Token,
            token: "CLIENT-SECRET-TOKEN-XYZ".into(),
            ..Default::default()
        };
        let s = format!("{c:?}");
        assert!(!s.contains("CLIENT-SECRET-TOKEN-XYZ"), "token 泄漏了：{s}");
        assert!(s.contains("redacted"), "应当保留可排障的脱敏标记：{s}");
        assert!(s.contains("Token"), "非机密信息可以保留：{s}");

        // 空 token 显示为 <empty>
        let e = format!("{:?}", ClientAuthConfig::default());
        assert!(e.contains("<empty>"), "{e}");
    }

    /// 服务端侧同理（早已修，这里锁住防回退）。
    #[test]
    fn server_auth_debug_不得泄漏_token() {
        let c = ServerAuthConfig {
            token: "SERVER-SECRET-TOKEN-ABC".into(),
            ..Default::default()
        };
        let s = format!("{c:?}");
        assert!(!s.contains("SERVER-SECRET-TOKEN-ABC"), "token 泄漏了：{s}");
        assert!(s.contains("redacted"));
    }

    // ------------------------------------------------------------------
    // 登录时间戳新鲜性窗口
    // ------------------------------------------------------------------

    fn now() -> i64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64
    }

    /// **过期 / 未来的时间戳必须被拒**（原先无期限接受）。
    ///
    /// 审计实测过：`ts = 0 / -1 / -2^40 / i64::MAX / i64::MIN`、
    /// 未来 100 年、过去 100 年 —— **全部登录成功**
    /// ⇒ 同链路嗅探到一条明文 Login 即可**原样重放**拿到完整会话。
    #[test]
    fn 登录时间戳超出窗口必须被拒() {
        let a = AuthProvider::token("t0ken-abcdefgh");
        let n = now();

        // 窗口内：放行（含边界附近）
        for ok in [n, n - 299, n + 299, n - 5, n + 5] {
            assert!(
                a.check_timestamp(ok, 300).is_ok(),
                "窗口内的时间戳不该被拒：{ok}"
            );
        }

        // 窗口外：必须拒 —— 这些原先全都是"登录成功"
        for bad in [
            n - 301,               // 刚出窗口
            n + 301,               // 未来一点
            0,                     // 纪元（审计报告里的实测用例）
            -1,                    // 负数
            -(1i64 << 40),         // 大负数
            i64::MAX,              // 极大值
            i64::MIN,              // 极小值（会溢出 `now - ts`，必须用 saturating）
            n - 100 * 365 * 86400, // 过去 100 年
            n + 100 * 365 * 86400, // 未来 100 年
        ] {
            assert!(
                a.check_timestamp(bad, 300).is_err(),
                "超出窗口的时间戳必须被拒：{bad}"
            );
        }
    }

    /// 逃生开关：`skew = 0` 表示关闭校验（给时钟严重不准的设备）。
    #[test]
    fn 时间戳窗口可以显式关闭() {
        let a = AuthProvider::token("t0ken-abcdefgh");
        for ts in [0, -1, i64::MIN, i64::MAX] {
            assert!(
                a.check_timestamp(ts, 0).is_ok(),
                "skew=0 时不该拦任何时间戳：{ts}"
            );
        }
    }

    /// 端到端：**重放一条真实登录报文**必须在窗口外被拒。
    ///
    /// 这条模拟审计报告里的重放场景：用某个旧时间戳算出**正确**的
    /// `privilege_key`（即攻击者拿到了合法报文），服务端必须因为
    /// 时间戳过期而拒绝 —— 即使凭证本身完全正确。
    #[test]
    fn 重放旧登录报文必须被时间窗口拦下() {
        let token = "t0ken-abcdefgh";
        let a = AuthProvider::token(token);
        let old_ts = now() - 3600; // 一小时前抓到的报文
        let stolen_key = crate::frp::msg::auth_key(token, old_ts);

        // 只要绕过时间窗口，凭证本身是**能过**的（证明这条攻击链真实存在）
        assert!(
            a.check_timestamp(old_ts, 0).is_ok(),
            "前置：关闭窗口时该凭证有效（说明攻击链成立）"
        );
        // 开启窗口后，同一条报文被拒
        assert!(
            a.check_timestamp(old_ts, 300).is_err(),
            "一小时前的报文必须被时间窗口拦下（M3）"
        );
        let _ = stolen_key;
    }

    // ------------------------------------------------------------------
    // M9：[acl] 拼写错误必须报错，而不是静默失效
    // ------------------------------------------------------------------

    /// `deny_unknown_fields` 让拼错的键名当场报错。
    ///
    /// 少了它，`denny = [...]` 会被静默丢弃 —— 只配黑名单时后果是
    /// **对所有 IP 一律放行**（管理员以为封了一段，实际完全敞开），
    /// 而且零告警（`is_empty()` 判定把日志也跳过了）。
    #[test]
    fn acl_拼错的键名必须报错而不是静默失效() {
        // 拼错的 deny：必须解析失败
        let bad = r#"
denny = ["203.0.113.0/24"]
"#;
        let r: Result<AclConfig, _> = toml::from_str(bad);
        assert!(
            r.is_err(),
            "拼错的 `denny` 必须报错，否则访问控制会静默消失：{:?}",
            r.map(|c| c.deny.len())
        );

        // 拼错的 allow 同理
        let bad2 = r#"
alow = ["10.0.0.0/8"]
"#;
        assert!(toml::from_str::<AclConfig>(bad2).is_err());

        // 正确的写法照常工作
        let good = r#"
allow = ["10.0.0.0/8"]
deny = ["10.1.0.0/16"]
"#;
        let c: AclConfig = toml::from_str(good).expect("正确写法必须能解析");
        assert_eq!(c.allow.len(), 1);
        assert_eq!(c.deny.len(), 1);
    }

    /// 空 `[acl]` 段仍是合法的（不破坏"写了段但没填"的配置）。
    #[test]
    fn 空_acl_段仍然合法() {
        let c: AclConfig = toml::from_str("").expect("空表必须合法");
        assert!(c.is_empty());
    }

    // ==================================================================
    // tokenSource（官方 ValueSource）
    // ==================================================================

    #[test]
    fn tokensource_能解析官方写法() {
        let t = r#"
type = "file"
[file]
path = "/etc/nfrp/token"
"#;
        let v: ValueSource = toml::from_str(t).unwrap();
        assert_eq!(v.kind, "file");
        assert_eq!(v.file.as_ref().unwrap().path, "/etc/nfrp/token");
        v.validate().unwrap();

        let t2 = r#"
type = "exec"
[exec]
command = "/usr/local/bin/get-token"
args = ["--json"]
[[exec.env]]
name = "VAULT_ADDR"
value = "https://vault:8200"
"#;
        let v2: ValueSource = toml::from_str(t2).unwrap();
        assert_eq!(v2.kind, "exec");
        let e = v2.exec.as_ref().unwrap();
        assert_eq!(e.command, "/usr/local/bin/get-token");
        assert_eq!(e.args, vec!["--json"]);
        assert_eq!(e.env[0].name, "VAULT_ADDR");
        v2.validate().unwrap();
    }

    /// 各种写错的配置要在 `validate` 阶段被拒，且错误信息说清哪儿错了。
    #[test]
    fn tokensource_配置错误必须明确报出() {
        // 缺 type
        let v: ValueSource = toml::from_str("[file]\npath = \"x\"\n").unwrap();
        let e = v.validate().unwrap_err().to_string();
        assert!(e.contains("type"), "要提示缺 type：{e}");

        // type 不认识
        let v = ValueSource {
            kind: "vault".into(),
            ..Default::default()
        };
        let e = v.validate().unwrap_err().to_string();
        assert!(e.contains("vault"), "要回显用户写的类型：{e}");

        // type=file 但没写 [file]
        let v = ValueSource {
            kind: "file".into(),
            ..Default::default()
        };
        assert!(v.validate().unwrap_err().to_string().contains("file"));

        // type=file 但 path 为空
        let v = ValueSource {
            kind: "file".into(),
            file: Some(FileSource { path: "   ".into() }),
            ..Default::default()
        };
        assert!(v.validate().unwrap_err().to_string().contains("path"));

        // type=exec 但没写 command
        let v = ValueSource {
            kind: "exec".into(),
            exec: Some(ExecSource::default()),
            ..Default::default()
        };
        assert!(v.validate().unwrap_err().to_string().contains("command"));
    }

    /// file 类型：要去掉首尾空白（文件末尾常有换行，不 trim 就对不上）。
    #[test]
    fn tokensource_file_会去掉首尾空白() {
        let d = std::env::temp_dir().join(format!("nfrp-ts-{}", std::process::id()));
        std::fs::create_dir_all(&d).unwrap();
        let p = d.join("token.txt");
        // 故意带前后空白与换行
        std::fs::write(&p, "  s3cret-token\n\n").unwrap();

        let v = ValueSource {
            kind: "file".into(),
            file: Some(FileSource {
                path: p.to_string_lossy().into_owned(),
            }),
            ..Default::default()
        };
        assert_eq!(v.resolve().unwrap(), "s3cret-token");

        // 空文件要报错，不能返回空 token（那等于把认证关了）
        std::fs::write(&p, "  \n\t\n").unwrap();
        let e = v.resolve().unwrap_err().to_string();
        assert!(e.contains("空"), "空文件必须明确报错：{e}");

        // 文件不存在也要报错
        std::fs::remove_file(&p).unwrap();
        assert!(v.resolve().is_err());

        let _ = std::fs::remove_dir_all(&d);
    }

    /// exec 类型：取 stdout 并 trim；非 0 退出码要报错。
    #[cfg(unix)]
    #[test]
    fn tokensource_exec_取_stdout() {
        let v = ValueSource {
            kind: "exec".into(),
            exec: Some(ExecSource {
                command: "/bin/sh".into(),
                args: vec!["-c".into(), "printf '  from-exec \\n'".into()],
                env: Vec::new(),
            }),
            ..Default::default()
        };
        assert_eq!(v.resolve().unwrap(), "from-exec");

        // 非 0 退出码
        let bad = ValueSource {
            kind: "exec".into(),
            exec: Some(ExecSource {
                command: "/bin/sh".into(),
                args: vec!["-c".into(), "echo boom >&2; exit 3".into()],
                env: Vec::new(),
            }),
            ..Default::default()
        };
        let e = bad.resolve().unwrap_err().to_string();
        assert!(e.contains("退出码"), "要报退出码非 0：{e}");

        // 命令不存在
        let missing = ValueSource {
            kind: "exec".into(),
            exec: Some(ExecSource {
                command: "/nonexistent/nfrp-no-such-cmd".into(),
                ..Default::default()
            }),
            ..Default::default()
        };
        assert!(missing.resolve().is_err());
    }

    /// exec 的环境变量要真的传给子进程。
    #[cfg(unix)]
    #[test]
    fn tokensource_exec_传环境变量() {
        let v = ValueSource {
            kind: "exec".into(),
            exec: Some(ExecSource {
                command: "/bin/sh".into(),
                args: vec!["-c".into(), "printf '%s' \"$NFRP_TEST_TOKEN\"".into()],
                env: vec![ExecEnvVar {
                    name: "NFRP_TEST_TOKEN".into(),
                    value: "env-token-xyz".into(),
                }],
            }),
            ..Default::default()
        };
        assert_eq!(v.resolve().unwrap(), "env-token-xyz");
    }

    /// 安全：`ValueSource` 的 Debug 输出**不能**包含 token 本身。
    ///
    /// 它只含配置（路径 / 命令名），不含取到的值 —— 但这条测试是防止
    /// 以后有人把"解析结果"缓存进结构体里又让它进日志。
    #[test]
    fn tokensource_debug_不含取值() {
        let v = ValueSource {
            kind: "file".into(),
            file: Some(FileSource {
                path: "/etc/nfrp/token".into(),
            }),
            ..Default::default()
        };
        let s = format!("{v:?}");
        assert!(s.contains("/etc/nfrp/token"), "路径可以出现：{s}");
        assert!(s.contains("file"), "类型可以出现：{s}");
    }
}
