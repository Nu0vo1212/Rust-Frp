//! 本地管理子命令与 `[webServer]` 启动期安全校验。
//!
//! 职责：实现 `verify` / `status` / `stop`（后两者走本地管理界面 HTTP API），
//! 以及必须发生在 bind 之前的 `check_web_server_is_safe`。
//! 并发/所有权契约：没有长驻任务；只读 `ClientConfig`，不持有通道或原子计数。
//! 不变量：`check_web_server_is_safe` 必须在绑定端口之前调用 —— 绑定后再拒绝会
//! 留下"日志说拒绝、端口却开着"的状态；`verify` 的"通过"只能在校验全过后打印。

use anyhow::{bail, Context, Result};
use nfrp_common::config::{default_config_path, ClientConfig};

use crate::cli::{AdminArgs, VerifyArgs};

/// `verify` 子命令：解析配置并报告结果，**不建立任何连接**。
///
/// 等价原版 `frpc verify -c <配置>`：官方默认 strict 解析、有问题就非 0 退出，
/// 启动器据此判断"这份配置能不能用"。这里把 `unsupported_fields` 一并报出来 ——
/// 官方 frpc 对未知字段会**直接报错**，NFrp 只是忽略，得让用户知道差在哪。
///
/// ★★ v0.5.7 修（第六轮审计 F-1，中危）：**必须跑完整启动校验，不能只解析配置**。
///
/// # 原先为什么错了
///
/// 原实现只调 `parse_client` 就报"配置校验通过"，而真正启动还会跑
/// [`check_web_server_is_safe`] 等启动期检查。实测
/// （`tmp/audit6-aclverify/verify_client_verify.py`）：
///
/// ```toml
/// [webServer]
/// addr = "0.0.0.0"    # 绑对外
/// port = 17300        # 且没配 user/password
/// ```
///
/// * `frpc verify` ⇒ **"配置校验通过"**（退出码 0）
/// * 真正启动 ⇒ **立刻退出**，报的是"请二选一：① 配 user+password；
///   ② 把 addr 改回 127.0.0.1；③ 显式写 allowInsecureRemote = true"
///
/// ⇒ 与服务端 `frps --check` 是**同一个毛病**（预检只做浅层校验），
///   属系统性缺陷而非某一处的疏漏。
///
/// # 为什么这个方向的假绿灯特别危险
///
/// 被漏掉的那条检查恰恰是**安全**检查（对外裸奔的管理界面 = 任何能访问
/// 该端口的人都能增删隧道、直接停掉客户端）。绿灯会让人**不去检查**它。
/// 本项目**此前已因"假绿灯"栽过一次**：`reject_unimplemented_plugin` 的注释里
/// 写着 `frpc verify` 对着未实现的插件回"配置校验通过"，用户拿绿灯上线、
/// 全量连接才逐个失败。
pub(crate) fn cmd_verify(a: &VerifyArgs) -> Result<()> {
    let path = a
        .config
        .clone()
        .unwrap_or_else(|| default_config_path("client.toml"));
    if !path.exists() {
        bail!("配置文件不存在：{}", path.display());
    }
    let raw = std::fs::read_to_string(&path)
        .with_context(|| format!("读取配置 {} 失败", path.display()))?;
    match nfrp_common::config::parse_client(&raw) {
        Ok(cfg) => {
            // ★ v0.5.7（F-1）：与启动同口径的启动期校验。
            //
            // 注意**放在打印"通过"之前** —— 否则会先打"配置校验通过"
            // 再报错退出，用户（和解析输出的启动器）会被那句"通过"误导。
            // 这是本节修复的要点：不是"多跑一个检查"，而是
            // **"通过"这两个字必须只在校验全过之后才出现**。
            if let Err(e) = check_web_server_is_safe(&cfg) {
                eprintln!("配置校验失败：{}", path.display());
                eprintln!("{e:#}");
                std::process::exit(1);
            }

            println!("配置校验通过：{}", path.display());
            println!("  服务端：{}:{}", cfg.server_addr, cfg.server_port);
            println!(
                "  代理 {} 个 / 访客 {} 个",
                cfg.proxies.len(),
                cfg.visitors.len()
            );
            for p in &cfg.proxies {
                if p.plugin.is_empty() {
                    println!("    - [{}] {} -> {}", p.name, p.proxy_type, p.local_addr);
                } else {
                    // 插件代理不看 `localIP` / `localPort`，工作连接是交给插件的。
                    // 照直打会得到 `127.0.0.1:0`，看着像配错了 —— 显示插件的上游。
                    let up = if p.plugin_local_addr.is_empty() {
                        &p.local_addr
                    } else {
                        &p.plugin_local_addr
                    };
                    println!(
                        "    - [{}] {} + 插件 [{}] -> {}",
                        p.name, p.proxy_type, p.plugin, up
                    );
                }
            }
            for v in &cfg.visitors {
                println!(
                    "    - [{}] {} -> {}.{}",
                    v.name, v.visitor_type, v.server_user, v.server_name
                );
            }
            if !cfg.unsupported_fields.is_empty() {
                println!(
                    "  警告：{} 项是官方 frp 支持、但 NFrp 未实现的字段（已忽略）：{}",
                    cfg.unsupported_fields.len(),
                    cfg.unsupported_fields.join(", ")
                );
            }
            Ok(())
        }
        Err(e) => {
            eprintln!("配置校验失败：{}", path.display());
            eprintln!("{e:#}");
            std::process::exit(1);
        }
    }
}

/// 启动前检查 `[webServer]` 的鉴权配置是否安全。
///
/// **必须在 bind 之前调用** —— 这是"拒绝启动"与"起了一半"的分界：
/// 端口一旦绑上，管理界面就已经在服务了，此时再 `return` 只会留下
/// "日志说拒绝了、端口却开着"的误导状态。
///
/// 规则：监听非回环地址时**必须**配 `user`/`password`，除非显式写
/// `allowInsecureRemote = true` 表明知情。回环地址上留空是允许的
/// （默认值就是 127.0.0.1，只有本机能连）。
///
/// ★★ v0.5.6 修（审计总报告 H1，高危）：判据同时看 `user` **与** `password`。
///
/// 原先只判 `user.trim().is_empty()`，但上面这段注释写的是
/// "必须配 `user`/`password`" —— **注释与实现不符**（审计报告 H1 的 C 处）。
///
/// 为什么空密码必须算"没有凭据"：`web.rs` 的鉴权把两者拼成
/// `format!("{}:{}", user, password)` 再比 Basic 头，密码为空时期望值就是
/// `"admin:"` —— 任何能访问该端口的人送一个 `admin:` 就能进来，
/// 等于**鉴权退化成"知道用户名就能进"**。
///
/// ★ 与服务端共用同一个真源 `nfrp_common::config::has_dashboard_creds()`，
///   保证两端口径永不漂移。
pub(crate) fn check_web_server_is_safe(cfg: &ClientConfig) -> Result<()> {
    // 先校验 TLS 文件成对，避免端口已经绑定后才在启动路径深处失败。
    cfg.web_server.tls.files()?;
    let has_creds =
        nfrp_common::config::has_dashboard_creds(&cfg.web_server.user, &cfg.web_server.password);
    if !has_creds
        && !nfrp_common::util::is_loopback_addr(&cfg.web_server.addr)
        && !cfg.web_server.allow_insecure_remote
    {
        bail!(
            "管理界面配置为监听 {}:{} 却没有配置**完整的** user/password（两者都不能为空）—— \
             任何能访问这个端口的人都能增删你的隧道、并可直接停止客户端。\n\
             请二选一：① 配置 [webServer] user + password；\
             ② 把 addr 改回 127.0.0.1；\
             ③ 确实要裸奔就显式写 allowInsecureRemote = true（自担风险）。",
            cfg.web_server.addr,
            cfg.web_server.port
        );
    }
    Ok(())
}

/// 从配置的 `[webServer]` 取本地管理界面地址。
///
/// `status` / `stop` 靠它定位运行中的进程 —— 官方 frpc 也是这个路子
/// （读配置里的 `webServer.addr/port`，再打本地 API）。
fn admin_base(cfg: &ClientConfig) -> Result<String> {
    if !cfg.web_server.is_enabled() {
        bail!(
            "配置里没有启用 [webServer]，无法定位运行中的客户端。\n\
             请在配置里加上：\n  [webServer]\n  addr = \"127.0.0.1\"\n  port = 7400"
        );
    }
    let host = if cfg.web_server.addr.trim().is_empty() {
        "127.0.0.1"
    } else {
        cfg.web_server.addr.trim()
    };
    Ok(format!("http://{host}:{}", cfg.web_server.port))
}

/// 读配置、算出管理界面地址。
fn load_admin_base(a: &AdminArgs) -> Result<String> {
    let path = a
        .config
        .clone()
        .unwrap_or_else(|| default_config_path("client.toml"));
    if !path.exists() {
        bail!("配置文件不存在：{}", path.display());
    }
    let cfg =
        ClientConfig::load(&path).with_context(|| format!("读取配置 {} 失败", path.display()))?;
    admin_base(&cfg)
}

/// `status` 子命令：打印运行中客户端的状态（走本地管理界面 API）。
pub(crate) async fn cmd_status(a: &AdminArgs) -> Result<()> {
    let base = load_admin_base(a)?;
    let url = format!("{base}/api/status");
    let resp = nfrp_common::httpc::get(&url, &[], &Default::default())
        .await
        .with_context(|| format!("请求 {url} 失败（客户端没在跑？或 [webServer] 地址不对）"))?;
    println!("{}", String::from_utf8_lossy(&resp.body));
    if resp.status != 200 {
        std::process::exit(1);
    }
    Ok(())
}

/// `stop` 子命令：让运行中的客户端退出（走本地管理界面 API）。
pub(crate) async fn cmd_stop(a: &AdminArgs) -> Result<()> {
    let base = load_admin_base(a)?;
    let url = format!("{base}/api/stop");
    let resp = nfrp_common::httpc::request("POST", &url, &[], None, &Default::default())
        .await
        .with_context(|| format!("请求 {url} 失败（客户端没在跑？或 [webServer] 地址不对）"))?;
    println!("{}", String::from_utf8_lossy(&resp.body).trim());
    if resp.status != 200 {
        std::process::exit(1);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// ★ 回归测试：管理界面监听非回环却不配凭据，必须**拒绝启动**。
    ///
    /// 原先只打一条 warn 就放行 ⇒ 任何能访问该端口的人都能增删隧道、
    /// 直接停止客户端。而且这个检查必须在 bind **之前** —— 否则端口已经
    /// 在服务了，日志说拒绝了也没用。
    #[test]
    fn 管理界面对外监听却不配凭据必须拒绝启动() {
        let mut cfg = ClientConfig::default();
        cfg.web_server.port = 7400;
        cfg.web_server.addr = "0.0.0.0".into();
        let e = check_web_server_is_safe(&cfg)
            .expect_err("必须拒绝启动")
            .to_string();
        assert!(e.contains("user"), "错误里要点名该怎么修：{e}");

        // 配了用户名就能起
        cfg.web_server.user = "admin".into();
        cfg.web_server.password = "pw".into();
        assert!(check_web_server_is_safe(&cfg).is_ok());

        // 或者显式声明知情
        cfg.web_server.user.clear();
        cfg.web_server.allow_insecure_remote = true;
        assert!(check_web_server_is_safe(&cfg).is_ok());
    }

    /// 绑回环时不配凭据是合法的（默认配置就是这样），不能误伤。
    #[test]
    fn 管理界面只监听回环时不配凭据可以启动() {
        let mut cfg = ClientConfig::default();
        cfg.web_server.port = 7400;
        // 默认 addr 就是 127.0.0.1
        assert_eq!(cfg.web_server.addr, "127.0.0.1");
        assert!(check_web_server_is_safe(&cfg).is_ok());
    }
}
