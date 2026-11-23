//! `nfrp-server` 的命令行入口。
//!
//! 这里只负责：**解析参数 -> 读配置 -> 组装 Registry -> 交棒给 [`serve`]**。
//! 全部业务逻辑都在库里，方便测试也方便复用。

use std::sync::Arc;

use anyhow::{Context, Result};
use clap::Parser;
use nfrp_common::{
    config::{default_config_path, ServerConfig},
    util,
};
use nfrp_server::{limits_from, Registry};

#[derive(Parser, Debug)]
#[command(name = "nfrp-server", version, about = "NFrp 服务端（兼容原版 frp）")]
struct Cli {
    /// 打印**上游 frp 兼容版本号**（等价于原版 frps 的 `frps -v`）
    ///
    /// 只输出裸版本号（如 `0.71.0`），方便脚本解析。
    /// 想看 NFrp 自己的版本请用 `--version`。
    #[arg(short = 'v', long = "frp-version")]
    frp_version: bool,

    /// 配置文件路径（默认 ./server.toml）
    #[arg(short, long, value_name = "PATH")]
    config: Option<std::path::PathBuf>,

    /// 打印一份示例配置到标准输出
    #[arg(long)]
    print_example: bool,

    /// 生成示例配置文件到指定路径
    #[arg(long, value_name = "PATH")]
    gen_config: Option<std::path::PathBuf>,

    /// 覆盖配置里的日志级别
    #[arg(long, value_name = "LEVEL")]
    log_level: Option<String>,

    /// 覆盖配置里的线协议（frp-v2 / nfrp）
    #[arg(long, value_name = "PROTOCOL")]
    protocol: Option<String>,

    /// 监听端口（覆盖配置）
    #[arg(short, long, value_name = "PORT")]
    port: Option<u16>,

    /// 认证 token（覆盖配置）
    #[arg(short, long, value_name = "TOKEN")]
    token: Option<String>,

    /// 只检查配置文件是否合法，不真正启动（用于 systemd reload 前的预检 / CI）
    #[arg(long)]
    check: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    // 与原版 frps 一致：`-v` 只打印版本号就退出（脚本/面板会解析它）
    if cli.frp_version {
        println!("{}", nfrp_common::frp::FRP_WIRE_VERSION);
        return Ok(());
    }

    if cli.print_example {
        println!("{}", ServerConfig::example_toml());
        return Ok(());
    }
    if let Some(path) = &cli.gen_config {
        ServerConfig::write_example(path)?;
        println!("已生成示例配置：{}", path.display());
        return Ok(());
    }

    let path = cli
        .config
        .clone()
        .unwrap_or_else(|| default_config_path("server.toml"));
    if !path.exists() {
        anyhow::bail!(
            "配置文件不存在：{}\n可先执行：{} --gen-config {}",
            path.display(),
            std::env::args()
                .next()
                .unwrap_or_else(|| "nfrp-server".into()),
            path.display()
        );
    }
    let mut cfg =
        ServerConfig::load(&path).with_context(|| format!("读取配置 {} 失败", path.display()))?;
    if let Some(p) = &cli.protocol {
        cfg.protocol = p
            .parse::<nfrp_common::config::Protocol>()
            .map_err(anyhow::Error::msg)?;
    }
    if let Some(port) = cli.port {
        cfg.bind_port = Some(port);
    }
    if let Some(token) = &cli.token {
        cfg.token = token.clone();
    }

    // `auth.tokenSource` —— 服务端的**期望 token** 也能来自外部源。
    //
    // 位置说明：必须放在 `check_token_strength` **之前** —— 那个检查看的是
    //   实际生效的 token，先检查后解析等于在检查空字符串（会误报"token 太弱"）。
    //   但此时 tracing 还没初始化，所以这里**只做解析，失败就 `?` 返回**
    //   （启动错误用户一定看得到），"令牌来自文件/命令"这类提示放到
    //   日志初始化之后再打。
    //
    // 语义与官方一致（"mutually exclusive with Token field"）：
    // 两者都配时以 tokenSource 为准。CLI `-t` 是用户即时意图，优先级最高。
    let mut token_source_conflict = false;
    let token_source_kind: Option<String> = match &cfg.auth.token_source {
        Some(src) if cli.token.is_none() => {
            src.validate()
                .with_context(|| "auth.tokenSource 配置有误")?;
            let resolved = src
                .resolve()
                .with_context(|| "从 auth.tokenSource 读取令牌失败")?;
            let previous = cfg.effective_auth().token;
            if !previous.is_empty() && previous != resolved {
                token_source_conflict = true;
            }
            cfg.auth.token = resolved;
            // 顶层 token 同步清空：避免 `effective_auth()` 的回落逻辑
            // 在热重载等路径上读到两份不一致的值
            cfg.token.clear();
            Some(src.kind.clone())
        }
        Some(_) => None, // 命令行 -t 优先
        None => None,
    };
    // 弱/占位 token 的强告警。
    //
    // 背景：v1 控制通道的登录凭证是
    // `md5(token + timestamp)`，而且服务端**对 timestamp 不做新鲜性校验**
    // （只用报文自报的 ts 重算比对）。攻击者抓到**一条** Login 报文后，
    // 枚举一个候选 token 只需要 **1 次 MD5** —— 也就是说 token 的实际强度
    // 取决于它自己够不够随机，PBKDF2 那 64 次迭代帮不上忙（那个参数是
    // 官方 golib 硬编码的，改了就跟官方断互通，**不能改**）。
    //
    // 所以这里只能在**启动期**把风险摆出来。不拒绝启动：用户的既有部署
    // 可能正用着某个短 token，直接拒绝会比漏洞本身更难处理。
    check_token_strength(&cfg);

    let level = cli
        .log_level
        .clone()
        .unwrap_or_else(|| cfg.log_level.clone());
    // 开了热重载就用可替换的日志过滤器，这样改 log_level 不用重启
    let log_handle = if cfg.hot_reload {
        util::init_tracing_reloadable(&level, &cfg.log_to, cfg.max_days, cfg.disable_print_color)
    } else {
        util::init_tracing(&level, &cfg.log_to, cfg.max_days, cfg.disable_print_color);
        None
    };

    // 令牌来源的提示（放在日志初始化之后，见上面 tokenSource 解析处的说明）
    if let Some(kind) = &token_source_kind {
        match kind.as_str() {
            "file" => {
                let p = cfg
                    .auth
                    .token_source
                    .as_ref()
                    .and_then(|s| s.file.as_ref())
                    .map(|f| f.path.as_str())
                    .unwrap_or_default();
                tracing::info!("服务端期望令牌来自文件 [{p}]");
            }
            "exec" => {
                let c = cfg
                    .auth
                    .token_source
                    .as_ref()
                    .and_then(|s| s.exec.as_ref())
                    .map(|e| e.command.as_str())
                    .unwrap_or_default();
                tracing::info!("服务端期望令牌来自外部命令 [{c}]（以本进程身份执行）");
            }
            _ => {}
        }
        if token_source_conflict {
            tracing::warn!(
                "auth.token 与 auth.tokenSource 同时配置且值不同，按官方语义以 tokenSource 为准"
            );
        }
    }

    // 官方 frp 支持、但 nfrp **未实现**的字段：官方 frps 默认 strict 解析，
    // 未知字段直接报错；NFrp 的 serde 不拒绝未知字段，于是它们被**静默吞掉**。
    // 其中既有"限流/鉴权"语义的（静默忽略会让管理员以为已经限制住了，
    // 实际全部放开），也有纯功能项 —— 必须在日志里明说。
    // 注意放在 init_tracing 之后，否则日志根本没被订阅。
    if !cfg.unsupported_fields.is_empty() {
        tracing::warn!(
            "配置里有 {} 项字段是官方 frps 支持、但 nfrp **未实现**的，已按默认值忽略：{}",
            cfg.unsupported_fields.len(),
            cfg.unsupported_fields.join(", ")
        );
    }
    // **明文控制通道也要告警**。
    //
    // 原先"空 token""面板无密码"都有强告警，唯独 `transport.tls.force = false`
    // （= 控制通道可明文）**完全静默** —— 三处安全项、两处有告警。
    //
    // 为什么值得说：控制通道明文意味着 token / 面板凭据 / 全部代理元数据
    // 在链路上可被嗅探；而 `login` 报文里的 `privilege_key` 也可以被
    // **原样重放**（M3 只把重放窗口压到 5 分钟，没消除重放本身）。
    //
    // 与官方 frp 一致：官方也默认不强制 TLS（`transport.tls.force` 默认 false），
    //   所以**只告警、不拒绝启动** —— 拒绝会破坏"官方客户端零配置直连"
    //   这个核心承诺（官方 frpc 默认 `tls.enable = false` 时走明文）。
    if !cfg.tls_force {
        tracing::warn!(
            "未强制 TLS（transport.tls.force = false）—— 控制通道可能以**明文**建立，\
             token 与登录凭据在链路上可被嗅探。\
             跨公网部署请设 transport.tls.force = true（官方 frpc 默认走明文，\
             置 true 前请确认客户端也开了 tls.enable）"
        );
    }

    // 端口白名单是安全项：配了就明确说一句"生效范围"，免得用户不确定到底拦没拦住。
    if !cfg.allow_ports.is_empty() {
        tracing::info!(
            "allowPorts 已生效：客户端只能申请这些远端端口 {}",
            nfrp_common::config::format_port_ranges(&cfg.allow_ports)
        );
    } else {
        // **空白名单必须告警**。
        //
        // 原先只有 `if`、**没有 `else`** —— 于是 `allowPorts` 留空（= 全放行）
        // 这件事在启动日志里**完全静默**。
        //
        // 为什么值得告警：管理员写了 `allowPorts` 却因为拼错键名 / 放错段
        // 而没生效时，日志同样是静默的 ⇒ 他以为限制了、实际全放行。
        // 而同样是安全项的"空 token""面板无密码"都有强告警，
        // 唯独这一项没有（`serve.rs` 里有对应的强告警，启动路径漏了）。
        //
        // 只是 warn 不是拒绝：默认配置就是全放行，
        //   拒绝启动会让出厂配置起不来（与空 token 那条同一个考量）。
        tracing::warn!(
            "未配置 allowPorts —— 客户端可以申请**任意**远端端口（除系统保留端口）。\
             若要限制，请配置 allowPorts = [\"20000-30000\"] 之类的范围"
        );
    }

    // RBAC 的经典陷阱：配了 [[roles]] 却忘了 denyUnknown。
    //
    // 此时**没匹配到任何角色**的用户会拿到 `unrestricted`（全权）——
    // 因为 `role_for` 里那条分支是为了"老配置不启用 RBAC 时行为不变"而留的。
    // 但一旦你写了角色表，本意显然是"只有名单里的人能用"，于是拼错用户名、
    // 或者某个新同事还没加进名单，都能拿到**比任何角色都大的权限**。
    //
    // 这个默认值不能直接改（会破坏"配了角色表但想放行其余人"的合法用法），
    // 但可以明确告警，把"你以为的限制"和"实际的行为"对齐。
    if !cfg.roles.is_empty() && !cfg.deny_unknown && cfg.default_role.is_empty() {
        tracing::warn!(
            "配置了 {} 个 [[roles]] 角色，但既没写 denyUnknown 也没写 defaultRole —— \
             **没匹配到任何角色**的用户会拿到不受限的全权角色（可以注册任意类型代理、\
             占任意端口）。如果本意是「只有名单里的人能用」，请加 denyUnknown = true；\
             如果想给其他人一个受限角色，请加 defaultRole = \"<角色名>\"。",
            cfg.roles.len()
        );
    }
    if cfg.max_ports_per_client > 0 {
        tracing::info!(
            "maxPortsPerClient 已生效：单客户端最多占用 {} 个端口",
            cfg.max_ports_per_client
        );
    }

    // **配了 [[roles]] 但用共享 token
    //   ⇒ 整套分权可以被伪造**。
    //
    // 判据与完整说明见 [`rbac_identity_is_unverifiable`]。
    if rbac_identity_is_unverifiable(&cfg) {
        tracing::warn!(
            "配置了 {} 个 [[roles]] 角色，但认证方式是**共享 token** —— \
             `user` 是客户端**自报**字段、服务端无法验证，所以**任何持有 token 的人 \
             都可以把自己报成别人的 `user`，从而拿到那个人的全部角色**\
             （端口范围 / 代理类型 / 代理数 / allowManage / allow_users 白名单）。\
             也就是说：这里的角色划分**不是**租户隔离，只是一层防误操作。\
             需要真正的隔离请改用 [auth] method = \"oidc\"（身份来自验签过的 sub），\
             或给每个租户发独立 token 并分实例部署。",
            cfg.roles.len()
        );
    }

    nfrp_server::serve::ensure_protocol(&cfg)?;

    // 插件地址/路径的合法性在启动前就检查，`--check` 也要能发现。
    let plugin_manager = std::sync::Arc::new(nfrp_common::plugin::PluginManager::from_config(
        &cfg.http_plugins,
    )?);
    if !plugin_manager.is_empty() {
        tracing::info!(
            "HTTP 插件已装载：{} 个插件，{} 个 op 订阅",
            cfg.http_plugins.len(),
            cfg.http_plugins.iter().map(|p| p.ops.len()).sum::<usize>()
        );
    }

    if cli.check {
        // **预检必须与启动同口径**。
        //
        // 原先这里只调 `validate(&cfg)` 就返回，而真正启动还会构造
        // `SecurityContext`（ACL / RBAC / 认证 / 审计一整块校验）。
        // ⇒ 实测 `--check` 放过了 5/7 条"启动时必然失败"的配置
        //   （`deny = ["10.0.0.1/33"]`、`portRange = "abc"`、
        //     `portRange = "30000-20000"` …）。
        //
        // `--check` 的用途是「systemd reload 前预检 / CI」，放过这些
        // 等于给了一个**假绿灯** —— 而它恰好在安全相关配置上最容易被信。
        validate(&cfg)?;
        nfrp_server::serve::preflight(&cfg)?;
        println!("配置 {} 合法", path.display());
        return Ok(());
    }
    validate(&cfg)?;

    let cfg = Arc::new(cfg);
    let registry = Arc::new(Registry::new(limits_from(&cfg)));
    registry.set_plugins(plugin_manager);
    let extras = nfrp_server::ServeExtras {
        config_path: Some(path.clone()),
        log_handle,
    };
    nfrp_server::serve_with(cfg, registry, extras).await
}

/// **配了 `[[roles]]` 但身份不可验证** —— 即"角色划分看起来是租户隔离、
/// 实际只是防误操作"。
///
///
/// # 为什么这是个真问题（而不是"已知设计"）
///
/// 角色解析的输入是登录报文里的 `Login.user`，由客户端**自报**、
/// 服务端不验任何东西 ⇒ 任何**持有 token** 的人把 `user` 写成 `"bob"`，
/// 就拿到 bob 的全部角色：`portRange`、`allowProxyTypes`、`maxProxies`、
/// `allowManage`，以及 `allow_users` 白名单里的身份。
///
/// 实测（`tmp/audit6-d/d05_identity.py`）：
/// * 冒充者(user=bob) 登录成功并**拿到 bob 的端口段**（占 alice 段被正确拒绝）
/// * 能注册进 `bob.*` 命名空间，并以 bob 身份穿过 `allow_users=["bob"]` 白名单
/// * 面板上同时出现两个 `user=bob`，管理员**无法区分**
///
/// 审计任务书里提示"默认无 RBAC 时 `user` 只是自报标签是已知设计" ——
/// **这一条不是那个**：管理员写了 `[[roles]]`，已经**明确表达**了
/// "alice 只能占 A 段 / bob 只能占 B 段"的意图，而 `user` 不可验证
/// 让这个意图**完全无法落地**。frp 的 token 是**服务端级共享凭据**，
/// 而 `[[roles]]` 存在的理由**恰恰就是在共享 token 之上用 user 再分权**。
///
/// ⇒ **假安全比不配更危险**：配了角色表会让人以为已经隔离了。
///
/// # 判据
///
/// * 有角色表（`roles` 非空），**且**
/// * 认证方式是 token 且 token 非空（共享凭据）
///
/// 配 OIDC 时身份来自**验签过的** `sub`（见 `remember_subject`），
/// `user` 不再是唯一判据，所以不告警；token 为空时压根没认证，
/// 另有更严重的告警。
///
/// # 为什么不在这个版本里直接改成"按 token 指纹匹配角色"
///
/// 那会**改变 `[[roles]]` 的语义**：既有配置里 `users = ["alice"]` 是按
/// 用户名匹配的，改成按凭据指纹匹配会让所有既有部署**静默失效**
/// （所有人都匹配不上角色）。正确做法是新增一种角色匹配方式并让
/// 两者共存、文档说明迁移路径 —— 那是独立的架构改动，不该塞进一个
/// 安全修复版本里。本版先做**诚实告警**，把"你以为的"和"实际的"对齐。
fn rbac_identity_is_unverifiable(cfg: &ServerConfig) -> bool {
    !cfg.roles.is_empty() && !cfg.effective_auth().token.is_empty()
}

/// 弱 token 检测。
/// 为什么值得单独做一件事：v1 的登录凭证是 `md5(token + timestamp)`，
/// 抓到一条 Login 之后离线枚举一条候选只要 1 次 MD5。token 的强度
/// **完全取决于它自身的随机性**，协议层面没有补救空间
/// （PBKDF2 的 64 次迭代是官方 golib 的硬编码值）。
///
/// 更正：本注释原先写"服务端对 `timestamp` **没有新鲜性校验**"，
/// 那句已经**过时** —— M3给主登录加了 ±300 秒窗口，
/// G-1把它铺到了全部 6 个凭证入口。
///   但**弱 token 依然是问题**：窗口只把重放面从"永久"压到 5 分钟，
///   攻击者在窗口内抓到一条 Login 仍然能离线枚举 token
///   （枚举成本与时间窗口无关）。所以这条检测继续保留。
///
/// 这里只告警、不拒绝启动 —— 既有部署可能正在用短 token，
/// 直接拦下来会比风险本身造成更大的破坏。但要把"为什么危险"说清楚。
fn check_token_strength(cfg: &ServerConfig) {
    let token = cfg.token.trim();
    if token.is_empty() {
        return; // 空 token 走上面那条"未配置 token"的告警，别重复报
    }

    // 常见的占位/示例值：照抄文档里那句 `your_secret_token` 等于没设
    const PLACEHOLDERS: &[&str] = &[
        "your_secret_token",
        "change_me",
        "changeme",
        "your_token",
        "secret",
        "password",
        "123456",
        "admin",
        "test",
        "token",
    ];
    let lower = token.to_ascii_lowercase();
    if PLACEHOLDERS.contains(&lower.as_str()) {
        tracing::warn!(
            "token 是示例里的占位值（{:?}）—— 这等于没有设置 token：\
             任何看过示例配置的人都能直接连上本服务端。请换成随机串。",
            token
        );
    }

    // 长度与字符集：太短或只有单一字符类的，都在"可离线枚举"的范围里
    let len = token.chars().count();
    let classes = [
        token.chars().any(|c| c.is_ascii_lowercase()),
        token.chars().any(|c| c.is_ascii_uppercase()),
        token.chars().any(|c| c.is_ascii_digit()),
        token.chars().any(|c| !c.is_ascii_alphanumeric()),
    ]
    .iter()
    .filter(|b| **b)
    .count();

    if len < 16 || classes < 2 {
        tracing::warn!(
            "token 强度偏低（长度 {len}，字符类 {classes} 种）：\
             v1 登录凭证是 md5(token+timestamp) 且服务端不校验时间戳新鲜性，\
             攻击者抓到一条登录报文后枚举一个候选只要 1 次 MD5。\
             建议换成 **至少 16 位、含大小写/数字/符号** 的随机串\
             （例如 `openssl rand -base64 24`），或用 [auth] method = \"oidc\"。"
        );
    }
}

/// 启动前把明显不合理 / 互相冲突的配置挡下来。
///
/// 这类错误往往要等很久才会表现为奇怪的运行时故障（比如面板端口和控制端口
/// 撞在一起时，只有一个能抢到端口，另一个失败得莫名其妙），不如提前说清楚。
fn validate(cfg: &ServerConfig) -> Result<()> {
    let frp_port = cfg.frp_bind_port();
    if let Some(v) = cfg.p2p_port {
        anyhow::ensure!(
            v != frp_port,
            "p2p_port({v}) 不能与控制端口 {frp_port} 相同（UDP 与 TCP 端口空间是共用的）"
        );
    }
    // **另外两个 UDP 监听口也要查**。
    //
    // 原先只有 `p2p_port` 有冲突检查，`kcp_bind_port` 与 `vnet_port`
    // **同为 UDP 监听口却一个都没查** —— 又是一处"同一语义只加固了一个"。
    //
    // 后果与其他端口冲突一样：撞在一起时只有一个能抢到端口，
    // 另一个在 bind 时报"地址被占用"，错误信息完全指不到配置上
    // （尤其是 KCP：它绑不上只表现为"KCP 客户端连不上"，离原因很远）。
    //
    // 用同一个循环处理三个 UDP 口，避免下次再加 UDP 口时又漏一个。
    let udp_ports = [
        ("p2p_port", cfg.p2p_port),
        ("kcp_bind_port", cfg.kcp_bind_port),
        ("vnet_port", cfg.vnet_port),
    ];
    // (1) 每个 UDP 口都不能与控制端口撞（UDP/TCP 端口空间共用）
    for (name, p) in udp_ports.iter() {
        if let Some(p) = p {
            anyhow::ensure!(
                *p != frp_port,
                "{name}({p}) 不能与控制端口 {frp_port} 相同（UDP 与 TCP 端口空间是共用的）"
            );
        }
    }
    // (2) UDP 口之间也不能互相撞
    for (i, (name_a, a)) in udp_ports.iter().enumerate() {
        let Some(a) = a else { continue };
        for (name_b, b) in &udp_ports[i + 1..] {
            if let Some(b) = b {
                anyhow::ensure!(a != b, "{name_a} 与 {name_b} 不能相同（{a}）");
            }
        }
    }
    if let Some(d) = cfg.dashboard_port {
        anyhow::ensure!(
            d != frp_port,
            "dashboard_port({d}) 不能与控制端口 {frp_port} 相同"
        );
    }
    // 三个虚拟主机端口各自绑一个监听器，撞在一起只会在 bind 时报"地址被占用"，
    // 完全指不到配置上，所以在这里先拦掉。
    let vhost_ports = [
        ("vhost_http_port", cfg.vhost_http_port),
        ("vhost_https_port", cfg.vhost_https_port),
        ("tcpmux_http_connect_port", cfg.tcpmux_http_connect_port),
    ];
    for (i, (name_a, a)) in vhost_ports.iter().enumerate() {
        let Some(a) = a else { continue };
        for (name_b, b) in &vhost_ports[i + 1..] {
            if let Some(b) = b {
                anyhow::ensure!(a != b, "{name_a} 与 {name_b} 不能相同（{a}）");
            }
        }
    }
    if cfg.max_total_conns > 0 && cfg.max_conns_per_client > cfg.max_total_conns {
        tracing::warn!(
            "max_conns_per_client({}) 大于 max_total_conns({})，实际只会按后者生效",
            cfg.max_conns_per_client,
            cfg.max_total_conns
        );
    }

    // ---- 面板鉴权：对外监听时**必须**配 dashboard_user ----
    //
    // 原先只要 `dashboard_user` 为空，`dashboard.rs` 就整块跳过鉴权。而面板
    // 跟随 `bind_addr` —— 默认 `0.0.0.0` ⇒ 面板端口一旦配了就是**公网可写**：
    // 匿名者能读 `/api/status`（全部客户端、代理名、端口、流量），能
    // `POST /api/clients/kick` 踢掉任意客户端（这条连能力协商都不需要，
    // 无条件生效），若目标客户端是 nfrp 自研的还能 `POST /api/proxies/add`
    // 直接开公网端口。已实测复现过。
    //
    // 所以：绑非回环 + 没配用户名 ⇒ **拒绝启动**，而不是只打一条 warn 让人
    // 从日志里自己发现。真要裸奔（比如面板只在跳板机能到的内网里），
    // 显式写 `allow_insecure_dashboard = true` 表明是知情选择。
    //
    // 判据同时看**用户名与密码**。
    //
    // 原先这里只判 `dashboard_user.trim().is_empty()`，而上面那段注释写的却是
    // "配置 dashboard_user + dashboard_pwd" —— **注释与实现不符**，
    // 这也正是审计漏看它的原因。
    //
    // 为什么空密码必须算"没有凭据"：鉴权处把两者拼成 `"user:pwd"` 再比
    // Basic 头，密码为空时期望值就是 `"admin:"` —— 攻击者随手可构造，
    // 等于**鉴权退化成"知道用户名就能进"**。空密码不是弱密码，是**没有密码**。
    //
    // 四个判据现在共用 `nfrp_common::config::has_dashboard_creds()` 这一个真源
    //   （本处 + 热重载闸门 + 暴露判定 + 客户端 webServer 校验）。
    if cfg.dashboard_port.is_some()
        && !nfrp_common::config::has_dashboard_creds(&cfg.dashboard_user, &cfg.dashboard_pwd)
    {
        let loopback = nfrp_common::util::is_loopback_addr(&cfg.bind_addr);
        if loopback {
            tracing::warn!(
                "面板未配置完整凭据（dashboard_user / dashboard_pwd 需同时非空）—— \
                 当前只监听回环地址 {}，仅本机可访问。",
                cfg.bind_addr
            );
        } else {
            anyhow::ensure!(
                cfg.allow_insecure_dashboard,
                "面板端口 {} 配在了非回环地址 {}，但没有配置**完整的**凭据 —— \
                 这会让匿名者可以读面板、踢掉任意客户端、并（对 nfrp 客户端）直接开公网端口。\n\
                 请二选一：① 配置 dashboard_user + dashboard_pwd（两者都不能为空）；\
                 ② 把 bind_addr 设成 127.0.0.1 只让本机访问；\
                 ③ 确实要裸奔就显式写 allow_insecure_dashboard = true（自担风险）。",
                cfg.dashboard_port.unwrap_or_default(),
                cfg.bind_addr
            );
        }
    }

    // ---- 认证：空 token + 显式对外监听 ⇒ **拒绝启动**----
    //
    // 与上面面板那条同一标准；但 **这里有个关键差异，不能照抄**：
    //
    // 面板是**可选功能** —— 不配 `dashboard_port` 就压根没有面板，所以
    // "配了面板 + 无凭据 + 对外"可以安全地判为"用户搞错了"。
    //
    // 而 `bind_addr` / `token` 是**核心项**，且 `ServerConfig::default()` 的
    // 出厂值就是 `bind_addr = "0.0.0.0"` + 空 token（与官方 frps 一致）。
    // 若无条件 `ensure!` 拒绝，**出厂默认配置将完全无法启动** ——
    // 连 `--gen-config` 生成的示例都起不来。这不是理论担忧：实测加上
    // 无条件 ensure 后当场打破 5 条既有测试。
    //
    // 所以口径分三档：
    //   * 绑**回环** ⇒ 合法（只有本机能连），只 warn；
    //   * 绑**对外** + 用户**显式写过** `bind_addr` ⇒ 拒绝启动，
    //     除非显式 `allow_insecure_no_auth = true`（知情选择）；
    //   * 绑**对外** + `bind_addr` 是**默认值**（用户没写过）⇒
    //     不拒绝启动（否则默认配置废掉），但给出可操作的强告警。
    // 判据改用**唯一真源** `has_no_auth()`。
    //
    // 原先这里是 `cfg.token.is_empty()` —— **只看顶层 token 字段、且不看
    // `auth.method`**。而 `guard.rs` 那边用的是
    // `auth.method() == Token && cfg.effective_auth().token.is_empty()`。
    // 两套口径。
    //
    // 后果：**纯 OIDC 部署**（`[auth] method = "oidc"` + `issuer`，
    // **不配 token —— 这是完全正确的配置**）下 `cfg.token` 为空 ⇒
    // 会打出"未配置 token 且正在监听对外地址 —— **任何人**都能连上来注册代理"。
    // **而事实是 OIDC 认证已正确启用，告警与事实完全相反。**
    //
    // `effective_auth()` 会做字段合并（`[auth] token` 为空时回落到顶层 `token`），
    // 所以判据必须走它；`has_no_auth()` 同时判了 `method`，
    // 这样 OIDC 模式下"没有 token"就不会被误判成"没有认证"。
    if cfg.has_no_auth() {
        if nfrp_common::util::is_loopback_addr(&cfg.bind_addr) {
            tracing::warn!(
                "未配置 token：任何人只要能连上 {}:{} 就能使用本服务端（当前只监听回环，仅本机可达）",
                cfg.bind_addr,
                cfg.frp_bind_port()
            );
        } else if cfg.bind_addr_explicitly_set {
            anyhow::ensure!(
                cfg.allow_insecure_no_auth,
                "未配置 token，却把 bind_addr 显式设成了对外地址 {}:{} —— \
                 这等于对外开放一个**无认证**的 frps：任何人都能连上来注册代理、\
                 申请公网端口，把你的服务器当成公共内网穿透节点。\n\
                 请三选一：① 配置 token（推荐）；\
                 ② 把 bind_addr 设成 127.0.0.1 只让本机访问；\
                 ③ 确实要这样跑就显式写 allow_insecure_no_auth = true（自担风险）。",
                cfg.bind_addr,
                cfg.frp_bind_port()
            );
            tracing::warn!(
                "已显式允许「无 token + 对外监听」：{}:{} 上任何人都能使用本服务端。\
                 仅在你确认网络层已隔离（安全组 / 防火墙 / 跳板机）时才这样跑。",
                cfg.bind_addr,
                cfg.frp_bind_port()
            );
        } else {
            // 出厂默认（用户没写过 bind_addr）：不拒绝启动，但把话说到位
            tracing::warn!(
                "未配置 token 且正在监听对外地址 {}:{}（默认值）—— \
                 **任何人**都能连上来注册代理、申请公网端口。\
                 若这台机器有公网入口，请务必配置 token（或用 [acl] 限制来源 IP）；\
                 纯内网使用可忽略本告警。",
                cfg.bind_addr,
                cfg.frp_bind_port()
            );
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg() -> ServerConfig {
        ServerConfig::default()
    }

    #[test]
    fn default_config_passes_validation() {
        assert!(validate(&cfg()).is_ok());
    }

    #[test]
    fn p2p_port_must_not_collide_with_control_port() {
        let mut c = cfg();
        c.p2p_port = Some(c.frp_bind_port());
        let e = validate(&c).unwrap_err().to_string();
        assert!(e.contains("p2p_port"), "{e}");
    }

    #[test]
    fn dashboard_port_must_not_collide_with_control_port() {
        let mut c = cfg();
        c.dashboard_port = Some(c.frp_bind_port());
        assert!(validate(&c).is_err());
    }

    #[test]
    fn http_and_https_vhost_ports_must_differ() {
        let mut c = cfg();
        c.vhost_http_port = Some(8080);
        c.vhost_https_port = Some(8080);
        assert!(validate(&c).is_err());
        c.vhost_https_port = Some(8443);
        assert!(validate(&c).is_ok());
    }

    #[test]
    fn per_client_greater_than_total_only_warns() {
        let mut c = cfg();
        c.max_total_conns = 10;
        c.max_conns_per_client = 999;
        assert!(validate(&c).is_ok(), "这只是浪费配额，不是错误");
    }

    /// 回归测试：面板配在非回环地址上却不配用户名，必须**拒绝启动**。
    ///
    /// 这是实测复现过的漏洞：`dashboard_user` 为空 ⇒ `dashboard.rs` 整块
    /// 跳过鉴权 ⇒ 匿名者能读 `/api/status`、踢掉任意客户端、并对 nfrp
    /// 客户端直接开公网端口。
    #[test]
    fn 面板对外监听却不配用户名必须拒绝启动() {
        let mut c = cfg();
        c.dashboard_port = Some(17500);
        c.bind_addr = "0.0.0.0".into();
        // 用户名留空
        let e = validate(&c).expect_err("必须拒绝启动").to_string();
        assert!(e.contains("dashboard_user"), "错误里要点名配置项：{e}");

        // 补上用户名就能起
        c.dashboard_user = "admin".into();
        c.dashboard_pwd = "s3cret".into();
        assert!(validate(&c).is_ok());

        // 或者显式声明"我知道风险"
        c.dashboard_user.clear();
        c.allow_insecure_dashboard = true;
        assert!(validate(&c).is_ok());
    }

    /// 绑回环时留空用户名是允许的（只有本机能连），不该拦。
    #[test]
    fn 面板只监听回环时留空用户名可以启动() {
        let mut c = cfg();
        c.dashboard_port = Some(17500);
        c.bind_addr = "127.0.0.1".into();
        assert!(validate(&c).is_ok());
    }

    /// 压根没配面板端口时，上面那条规则不该生效。
    #[test]
    fn 没配面板端口时用户名留空不影响启动() {
        let c = cfg();
        assert!(c.dashboard_port.is_none());
        assert!(validate(&c).is_ok());
    }

    /// `[[roles]]` + 共享 token
    /// ⇒ 身份不可验证，必须告警。
    ///
    /// 锁三件事：
    /// 1. 有角色表 + 非空 token ⇒ **告警**（这是被测的那条）
    /// 2. 没有角色表 ⇒ 不告警（"user 只是标签"在那个场景下是已知设计）
    /// 3. token 为空 ⇒ 不告警（另有"根本没认证"的告警，不该重复刷屏）
    #[test]
    fn 配了角色表又用共享token时必须告警() {
        // ① 被测：有角色表 + 共享 token
        let mut c = cfg();
        c.token = "s3cret".into();
        c.roles = vec![nfrp_common::security::RoleConfig {
            name: "dev".into(),
            users: vec!["alice".into()],
            ..Default::default()
        }];
        assert!(
            rbac_identity_is_unverifiable(&c),
            "配了 [[roles]] 且认证是共享 token 时必须告警 —— \
             否则管理员会以为角色表就是租户隔离"
        );

        // ② 没有角色表：不告警（此时 user 只是标签，是已知设计）
        let mut c = cfg();
        c.token = "s3cret".into();
        c.roles = vec![];
        assert!(
            !rbac_identity_is_unverifiable(&c),
            "没配角色表时不该告警（那是已知设计，不是缺陷）"
        );

        // ③ token 为空：不告警（另有更严重的"没有认证"告警）
        let mut c = cfg();
        c.token = String::new();
        c.roles = vec![nfrp_common::security::RoleConfig {
            name: "dev".into(),
            users: vec!["alice".into()],
            ..Default::default()
        }];
        assert!(
            !rbac_identity_is_unverifiable(&c),
            "空 token 时不该走这条告警（已有『没有认证』的告警）"
        );
    }

    /// 弱 token 不阻止启动。
    #[test]
    fn 弱token不阻止启动() {
        for weak in [
            "short",
            "your_secret_token",
            "aaaaaaaaaaaaaaaaaaaa",
            "123456",
        ] {
            let mut c = cfg();
            c.token = weak.into();
            assert!(
                validate(&c).is_ok(),
                "token={weak:?} 不该拦启动（只能告警）"
            );
            check_token_strength(&c); // 不应 panic
        }
    }

    /// 强 token 与空 token 都不该触发占位值分支。
    #[test]
    fn 强token与空token都能通过检查() {
        let mut c = cfg();
        c.token = String::new();
        check_token_strength(&c);

        c.token = "Xk9#mQ2$vL7@pR4!wZ8&".into();
        check_token_strength(&c);

        // 占位值判定应当大小写不敏感
        c.token = "Your_Secret_Token".into();
        check_token_strength(&c);
    }

    // ------------------------------------------------------------------
    // M4：空 token + **显式**对外监听必须拒绝启动
    // ------------------------------------------------------------------

    /// M4 核心回归：**显式**把 bind_addr 写成对外地址 + 空 token ⇒ 拒绝启动。
    ///
    /// 原先只打一条 `warn!` 就放行：那等于对外开放一个任何人都能用的 frps
    /// （注册代理 + 申请公网端口），而同一个风险在面板路径上是 `ensure!` 拒绝的。
    #[test]
    fn 空token且显式对外监听必须拒绝启动() {
        let mut c = cfg();
        c.token = String::new();
        c.bind_addr = "0.0.0.0".into();
        c.bind_addr_explicitly_set = true; // 用户确实写过这一行
        let e = validate(&c).expect_err("显式对外 + 空 token 必须被拒绝");
        let msg = e.to_string();
        assert!(
            msg.contains("allow_insecure_no_auth"),
            "错误里要给出逃生开关：{msg}"
        );
        assert!(msg.contains("无认证"), "错误要说清后果：{msg}");
    }

    /// **出厂默认配置必须能启动** —— 这是"拒绝启动"不能无条件的理由。
    ///
    /// `ServerConfig::default()` 就是 `bind_addr = "0.0.0.0"` + 空 token
    /// （与官方 frps 一致）。若无条件拒绝，连 `--gen-config` 生成的示例
    /// 都起不来。实测：加上无条件 `ensure!` 后当场打破 5 条既有测试。
    #[test]
    fn 出厂默认配置必须能启动() {
        let c = cfg();
        assert!(c.token.is_empty(), "默认就是空 token");
        assert!(!c.bind_addr_explicitly_set, "默认没写过 bind_addr");
        assert!(
            validate(&c).is_ok(),
            "出厂默认配置必须能启动，否则默认部署全废"
        );
    }

    /// 逃生开关生效：显式声明后可启动。
    #[test]
    fn 空token对外监听可用逃生开关放行() {
        let mut c = cfg();
        c.token = String::new();
        c.bind_addr = "0.0.0.0".into();
        c.bind_addr_explicitly_set = true;
        c.allow_insecure_no_auth = true;
        assert!(validate(&c).is_ok(), "显式声明后应当放行（知情选择）");
    }

    /// 空 token 绑回环是合法的（只有本机能连），不该拦。
    #[test]
    fn 空token绑回环可以启动() {
        for lo in ["127.0.0.1", "::1", "127.5.5.5"] {
            let mut c = cfg();
            c.token = String::new();
            c.bind_addr = lo.into();
            c.bind_addr_explicitly_set = true;
            assert!(validate(&c).is_ok(), "{lo} 是回环，不该拦");
        }
    }

    /// 配了 token 就与这条规则无关（无论绑哪里）。
    #[test]
    fn 有token时对外监听不受影响() {
        let mut c = cfg();
        c.token = "a-sufficiently-long-token-123456".into();
        c.bind_addr = "0.0.0.0".into();
        c.bind_addr_explicitly_set = true;
        assert!(validate(&c).is_ok());
    }

    /// `parse_server_toml` 必须正确识别"用户写没写过 bind_addr"
    /// —— 这是上面那套判定的输入。
    #[test]
    fn 能识别用户是否显式写过_bind_addr() {
        use nfrp_common::config::parse_server_toml;

        // 没写 ⇒ false（走"默认值"分支，不拒绝启动）
        let c = parse_server_toml("bind_port = 7000\n").unwrap();
        assert!(!c.bind_addr_explicitly_set);

        // 写了 ⇒ true（走"显式"分支）
        let c = parse_server_toml("bind_addr = \"0.0.0.0\"\nbind_port = 7000\n").unwrap();
        assert!(c.bind_addr_explicitly_set);

        // 官方驼峰写法也算
        let c = parse_server_toml("bindAddr = \"0.0.0.0\"\n").unwrap();
        assert!(c.bind_addr_explicitly_set, "官方 bindAddr 写法也要认");
    }
}
