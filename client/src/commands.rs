//! 服务端下发管理命令的应用（`add_proxy` / `remove_proxy`）。
//!
//! 职责：把 `ServerCmd` 落到本地代理表与 store，并无论成败都回一条
//! `ServerCmdResp`。
//! 并发/所有权契约：运行在控制会话循环内，独占 `FrpConn`；代理表与 store 是进程
//! 级共享（`&ProxyTable` / `&Store`），本模块不建长驻任务。
//! 不变量：远程命令只能动动态代理（不得覆盖 / 删除配置来源的条目），且远程下发
//! 的配置必须过 `validate_remote_proxy(_, true)` 的本机资源字段黑名单。

use anyhow::{anyhow, Result};
use nfrp_common::{
    config::ProxyConfig,
    frp::{
        conn::FrpConn,
        msg::{self, FrpMessage},
    },
    util,
};
use tracing::{info, warn};

use crate::{registry, store};

/// 执行一条服务端下发的管理命令，并把回执发回去。
///
/// **无论成功失败都必须回一条** `ServerCmdResp`：面板是同步等回包的，
/// 收不到就只能在超时后报「已下发但结果未知」，体验很差。
pub(crate) async fn apply_server_cmd(
    proxies: &registry::ProxyTable,
    user: &str,
    store: &store::Store,
    cmd: &msg::ServerCmd,
    conn: &mut FrpConn,
) -> Result<()> {
    let result = match cmd.op.as_str() {
        msg::CMD_ADD_PROXY => add_proxy_cmd(proxies, store, cmd),
        msg::CMD_REMOVE_PROXY => {
            let requested = cmd.proxy_name.clone();
            if requested.is_empty() {
                Err(anyhow!("remove_proxy 缺少 proxy_name"))
            } else {
                // ★★ v0.5.5（第四轮 F2）：**只许删动态代理，不许删配置里的**。
                //
                // 配置文件的语义是"本机用户写下的意图"，服务端不该有能力让它
                // 在运行期失效。实弹（`tmp/f2_remove_config_proxy.py`）：
                // 面板对配置里的 `victim-ssh` 发一条 remove，端口立刻连不上，
                // 客户端日志 `按服务端命令移除代理 proxy=victim-ssh total=0`。
                //
                // `remove_dynamic` 会对配置来源的条目返回 Err（带人话原因）。
                //
                // ★ v0.5.8 修（第八轮审计 F8-L2，低危）：**列表名字必须能直接删**。
                //
                // 面板列表展示的是线上全名 `{user}.{name}`；v0.5.8 起服务端
                // 下发的已是本地名，这里再兜一层：原样查不到时，剥掉本客户端
                // `user` 前缀再查 —— 覆盖"客户端先升级、服务端还是旧版"的
                // 滚动升级窗口（旧服务端转发的就是面板给的全名）。
                // 修复前客户端拿全名查本地表 ⇒ 拒删，而服务端侧已经摘干净 ⇒
                // 两端状态分裂、接口回 502 把"半成功"表达成失败。
                let mut name = requested.clone();
                let mut removed = proxies.remove_dynamic(&name);
                if matches!(removed, Ok(None)) {
                    let local = util::strip_user_prefix(user, &requested);
                    if local != requested {
                        let local = local.to_string();
                        let again = proxies.remove_dynamic(&local);
                        if !matches!(again, Ok(None)) {
                            name = local;
                            removed = again;
                        }
                    }
                }
                match removed {
                    Err(e) => Err(anyhow!(e)),
                    Ok(None) => {
                        // 把当前有哪些代理一并报回去 —— 面板上最常见的失败原因
                        // 就是名字打错，光说"没有"用户没法自查
                        let have = proxies.names().join(", ");
                        Err(anyhow!(
                            "本地没有名为 [{requested}] 的代理（当前有：{}）",
                            if have.is_empty() {
                                "无".to_string()
                            } else {
                                have
                            }
                        ))
                    }
                    Ok(Some(_)) => {
                        // store 里也要删 —— 否则下次启动它又"复活"，而用户已经
                        // 在面板上明确删过一次了
                        if let Err(e) = store.remove(&name) {
                            warn!(proxy = %name, error = %e, "从 store 删除失败（内存里已移除）");
                        }
                        info!(proxy = %name, total = proxies.len(), reason = %cmd.reason, "按服务端命令移除代理");
                        Ok(())
                    }
                }
            }
        }
        other => Err(anyhow!("未知命令：{other}")),
    };

    let resp = msg::ServerCmdResp {
        id: cmd.id.clone(),
        op: cmd.op.clone(),
        proxy_name: cmd.proxy_name.clone(),
        error: result
            .as_ref()
            .map_err(|e| e.to_string())
            .err()
            .unwrap_or_default(),
    };
    // 命令本身失败了也要**先把回执发出去**，再让上层记日志
    conn.send_msg(&FrpMessage::ServerCmdResp(resp)).await?;
    result.map(|_| ())
}

/// 面板新增代理：把配置塞进本地表，再补发一条 `NewProxy` 让服务端开端口。
fn add_proxy_cmd(
    proxies: &registry::ProxyTable,
    store: &store::Store,
    cmd: &msg::ServerCmd,
) -> Result<()> {
    // 命令里带的是 `serde_json::Value` 而不是 `ProxyConfig`：
    // 配置结构体将来改字段名时，不该让一条命令因为多/少一个键就整个解析失败。
    let p: ProxyConfig = cmd.proxy_config().map_err(anyhow::Error::msg)?;
    if p.name.is_empty() {
        anyhow::bail!("代理配置缺少 name");
    }
    if p.proxy_type.is_empty() {
        anyhow::bail!("代理配置缺少 type");
    }
    // ★ 服务端下发的配置**不能**只查 name/type 就照单全收。
    //
    // 走配置文件的代理要过类型 / 插件 / tcpmux 三道校验，而这条路径原先
    // 一道都不过。更要命的是 `ProxyConfig` 里混着「本机资源字段」——
    // `plugin_local_path`（读哪个文件）、`plugin_local_addr`（连哪个内网地址）、
    // `plugin_crt_path` / `plugin_key_path`（读哪对证书）。服务端能下发这些，
    // 就等于让它决定客户端去读本机哪个文件、连内网哪个地址。
    //
    // `is_remote = true` ⇒ 上述本机资源字段一律拒绝；类型/插件/tcpmux 照常校验。
    nfrp_common::config::validate_remote_proxy(&p, true)
        .map_err(|e| anyhow::anyhow!("服务端下发的代理配置未通过校验：{e}"))?;
    let name = p.name.clone();
    // ★★ v0.5.5（第四轮 F3）：**远程下发不许覆盖配置文件里的代理**。
    //
    // 这是"双杀"链条的第一环，也是必须堵的那一环：
    //   1. 服务端下发同名 `add_proxy(my-web)`（用户配置里已有 `my-web`）；
    //   2. 客户端 `insert` 覆盖 ⇒ **用户那条此刻已经没了**；
    //   3. 服务端 `register_proxy` 失败（端口被旧连接占着）⇒ 走回滚，
    //      再下发 `remove_proxy("my-web")`；
    //   4. 客户端按名删 ⇒ 删掉的是第 2 步塞进去的那条，
    //      **用户原本的配置永远不会被恢复**。
    //
    // 结果：一条**服务端自己都判为失败**（HTTP 400 "已回滚"）的命令，
    // 把用户的隧道永久打掉了（实弹 `tmp/f3b_rollback_kills_config_proxy.py`）。
    //
    // 只在第一步拒绝，整条链就断了 —— 用户的配置代理从头到尾没被动过。
    let existed = proxies
        .insert_dynamic(p.clone())
        .map_err(|e| anyhow::anyhow!(e))?
        .is_some();
    if existed {
        warn!(proxy = %name, "覆盖了同名的已有代理");
    }
    // 动态加进来的代理要落盘，否则重启就丢（`[store] path` 没配时是空操作）
    if let Err(e) = store.put(&p) {
        // 落盘失败不该让"这次添加"失败：内存里已经生效、端口已经开了，
        // 告诉面板"失败"反而会让用户以为隧道没起来。
        warn!(proxy = %name, error = %e, "写入 store 失败：重启后这条代理会丢失");
    }
    info!(proxy = %name, r#type = %p.proxy_type, total = proxies.len(), reason = %cmd.reason, "按服务端命令新增代理");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    use nfrp_common::config::ClientConfig;
    use nfrp_common::frp;

    // -----------------------------------------------------------------------
    // 面板下发的管理命令（ServerCmd）
    // -----------------------------------------------------------------------

    /// 造一对连起来的 `FrpConn`：一头给被测代码，另一头用来读它发出去的回执。
    fn cmd_pair() -> (FrpConn, FrpConn) {
        let (a, b) = tokio::io::duplex(64 * 1024);
        (
            FrpConn::new(Box::pin(a), frp::WireVersion::V1),
            FrpConn::new(Box::pin(b), frp::WireVersion::V1),
        )
    }

    fn add_cmd(name: &str) -> msg::ServerCmd {
        let p = ProxyConfig {
            name: name.to_string(),
            proxy_type: "tcp".to_string(),
            // ★ v0.5.8（第七轮审计 E7 附带发现）：**必须给一个合法的 local_addr**。
            //
            // 原先这里是 `..Default::default()`（`local_addr` = 空串），
            // 于是这些用例**意外依赖了"空地址也会被接受"**这个行为。
            // 而空地址的 tcp 代理**必然连不上任何地方** ——
            // 面板却回「已生效」（实测见 `tmp/audit7/e/localip_bypass_probe.py`），
            // 属于"假绿灯"。v0.5.8 起远程下发**拒绝**空 `local_addr`。
            //
            // ⇒ 这是**有意的行为收紧**，测试数据跟上被测行为是正确的处置
            //   （与第六轮"冒烟脚本过时"同一处理原则：先分清是设计变更还是回归，
            //    确认是前者后再更新测试工件）。
            //
            // 给默认值还有个好处：像"不支持的代理类型必须被拒绝"这类用例
            // 现在能**先过** local_addr 检查，从而确保拒绝的原因真的是**类型**
            // —— 判据的区分力变强了。
            local_addr: "127.0.0.1:8080".to_string(),
            remote_port: 7000,
            ..Default::default()
        };
        msg::ServerCmd {
            id: "cmd-1".to_string(),
            op: msg::CMD_ADD_PROXY.to_string(),
            proxy_name: name.to_string(),
            proxy: Some(serde_json::to_value(&p).expect("序列化")),
            reason: "dashboard".to_string(),
        }
    }

    /// 测试用的"不落盘"的 store（`[store] path` 没配就是它）。
    fn no_store() -> store::Store {
        store::Store::from_config(&ClientConfig::default()).expect("默认配置永远不该失败")
    }

    /// 造一条带某个插件字段的服务端管理命令。
    fn add_cmd_with(name: &str, f: impl FnOnce(&mut ProxyConfig)) -> msg::ServerCmd {
        let mut p = ProxyConfig {
            name: name.to_string(),
            proxy_type: "tcp".to_string(),
            // ★ 同上：默认给一个合法回环地址，避免用例意外依赖"空地址被接受"。
            local_addr: "127.0.0.1:8080".to_string(),
            remote_port: 7000,
            ..Default::default()
        };
        f(&mut p);
        msg::ServerCmd {
            id: "cmd-1".to_string(),
            op: msg::CMD_ADD_PROXY.to_string(),
            proxy_name: name.to_string(),
            proxy: Some(serde_json::to_value(&p).expect("序列化")),
            reason: "dashboard".to_string(),
        }
    }

    /// 造一条"移除代理"的服务端管理命令。
    fn remove_cmd(name: &str) -> msg::ServerCmd {
        msg::ServerCmd {
            id: "cmd-rm".to_string(),
            op: msg::CMD_REMOVE_PROXY.to_string(),
            proxy_name: name.to_string(),
            reason: "dashboard".to_string(),
            ..Default::default()
        }
    }

    /// ★ 回归测试：服务端**不能**用管理命令让客户端去读任意本机文件。
    ///
    /// `pluginLocalPath` 这类本机资源字段只该由本机配置文件指定。放行它的
    /// 后果是：服务端配一条 `plugin = "static_file"` + `localPath = "/etc"`
    /// 的代理，就能借公网端口把客户端本机的文件服务出去。
    /// 这几条字段曾经**完全没有校验**（只查 name/type 非空）。
    #[tokio::test]
    async fn 远程下发的_plugin_local_path_必须被拒绝() {
        for (field, set) in [
            (
                "pluginLocalPath",
                Box::new(|p: &mut ProxyConfig| p.plugin_local_path = "/etc".to_string())
                    as Box<dyn FnOnce(&mut ProxyConfig)>,
            ),
            (
                "pluginLocalAddr",
                Box::new(|p: &mut ProxyConfig| {
                    p.plugin_local_addr = "169.254.169.254:80".to_string()
                }),
            ),
            (
                "pluginCrtPath",
                Box::new(|p: &mut ProxyConfig| p.plugin_crt_path = "/etc/shadow".to_string()),
            ),
            (
                "pluginKeyPath",
                Box::new(|p: &mut ProxyConfig| p.plugin_key_path = "/etc/shadow".to_string()),
            ),
        ] {
            let (mut me, _peer) = cmd_pair();
            let table = registry::ProxyTable::default();
            let cmd = add_cmd_with("evil", set);
            let err = apply_server_cmd(&table, "", &no_store(), &cmd, &mut me)
                .await
                .expect_err(&format!("{field} 必须被拒绝"));
            let msg = err.to_string();
            assert!(msg.contains(field), "错误里要点名 {field}：{msg}");
            assert_eq!(table.len(), 0, "{field} 被拒时不该留下代理");
        }
    }

    /// ★★ v0.5.4 回归（H4）：服务端下发的 `local_addr` **只能指向本机回环**。
    ///
    /// 威胁模型：`local_addr` 决定客户端**往哪里连**（见本文件里
    /// `TcpStream::connect(local)`）。它原先不在远程黑名单里，于是不可信的
    /// 服务端/面板只要下发 `169.254.169.254:80`，就能让客户端去连**云元数据服务**
    /// —— 服务端可控的 SSRF。内网地址（`10.0.0.5:6379`）同理可做横向。
    #[tokio::test]
    async fn 远程下发的_local_addr_只能指向本机() {
        // —— 这些必须被拒 ——
        for bad in [
            "169.254.169.254:80", // 云元数据服务
            "10.0.0.5:6379",      // 内网 Redis
            "192.168.1.1:22",     // 内网主机
            "0.0.0.0:80",         // "监听全部"不是"连本机"
            "[fd00::1]:80",       // IPv6 内网
            "example.com:80",     // 域名（解析结果不可控）
        ] {
            let (mut me, _peer) = cmd_pair();
            let table = registry::ProxyTable::default();
            let cmd = add_cmd_with("ssrf", |p| p.local_addr = bad.to_string());
            let err = apply_server_cmd(&table, "", &no_store(), &cmd, &mut me)
                .await
                .expect_err(&format!("{bad} 必须被拒绝"));
            assert!(
                err.to_string().contains("local_addr"),
                "错误里要点名 local_addr：{err}"
            );
            assert_eq!(table.len(), 0, "{bad} 被拒时不该留下代理");
        }

        // —— 这些是合法用法，必须放行 ——
        //
        // ★★ v0.5.8（第七轮审计 **E-1**）修正：**`localhost` 从这份白名单里去掉了。**
        //
        // 原先这里把 `localhost:3000` 当作"合法的本机地址"放行。E-1 实测证明
        // 那个假设**不成立**：
        //
        // 在 `127.0.0.1:<P>` 与 `[::1]:<P>` 上各起一个诱饵（同端口号），
        // 远程下发 `local_addr = "localhost:<P>"` ⇒ 被接受，且流量命中
        // **v6** 诱饵（v4=0 / v6=1）—— 用户配的"本机 v4 服务"被绕到了另一个地址族。
        // （`tmp/audit7/e_independent/repro_e1_localhost.py`，9/9）
        //
        // 根因是**同一语义两套相反实现**：
        //   * `util::is_loopback_addr` 对 `localhost` 返回 **false**
        //     （注释写明"解析结果取决于 hosts 与 DNS，不能靠名字赌"）；
        //   * `config::is_loopback_host` 原先无条件返回 **true**；
        //   而守卫远程下发路径的是**后者**（弱的那套）。
        //
        // ⇒ 现在两边口径统一为"从严"：`localhost` **不再是**合法的远程下发地址。
        //   要连本机就写 `127.0.0.1` / `::1` —— 明确且不受 hosts/DNS 影响。
        //   本机配置文件里的 `localhost` 不受影响（这条检查只作用于远程下发）。
        for ok in ["127.0.0.1:8080", "127.0.0.2:9000", "[::1]:8080"] {
            let (mut me, _peer) = cmd_pair();
            let table = registry::ProxyTable::default();
            let cmd = add_cmd_with("local-ok", |p| p.local_addr = ok.to_string());
            apply_server_cmd(&table, "", &no_store(), &cmd, &mut me)
                .await
                .unwrap_or_else(|e| panic!("{ok} 是合法的本机地址，不该被拒：{e}"));
            assert_eq!(table.len(), 1, "{ok} 应当成功加入");
        }

        // ★ E-1：`localhost` 现在必须被拒（含大小写变体）。
        //   这是**有意的行为收紧**，不是回归 —— 理由见上面那段注释。
        for bad_host in ["localhost:3000", "LocalHost:3000", "LOCALHOST:3000"] {
            let (mut me, _peer) = cmd_pair();
            let table = registry::ProxyTable::default();
            let cmd = add_cmd_with("local-bad", |p| p.local_addr = bad_host.to_string());
            let err = apply_server_cmd(&table, "", &no_store(), &cmd, &mut me)
                .await
                .expect_err(&format!(
                    "{bad_host} 必须被拒（E-1）：它的解析结果取决于本机 hosts 与 DNS，\
                     判据不能靠名字赌"
                ));
            assert!(
                err.to_string().contains("local_addr"),
                "错误里要点名 local_addr：{err}"
            );
            assert_eq!(table.len(), 0, "{bad_host} 被拒时不该留下代理");
        }
    }

    // ------------------------------------------------------------------
    // 第四轮 F1：插件路径绕过 H4（远程下发开放代理）
    // ------------------------------------------------------------------

    /// ★★ F1 核心回归：远程下发**一律不许带插件**。
    ///
    /// 这是第四轮实弹打出来的高危（`tmp/audit4-verify-F1b.py`）：
    ///
    /// * H4 的回环检查有前提 —— `local_addr` 非空
    ///   （`config.rs` 里 `if !p.local_addr.trim().is_empty()`）；
    /// * 而插件路径**根本不需要 `local_addr`**；
    /// * `plugin` 这个"能力开关"本身又不在黑名单里。
    ///
    /// 三者叠加 ⇒ 下发 `local_addr="" + plugin="http_proxy"` 全部校验通过 ⇒
    /// 客户端那个公网端口变成**开放正向代理**，攻击者可现指定任意目标
    /// （内网横向 + 拿客户端当跳板隐藏来源）。
    ///
    /// 实测对照：同一目标 `192.168.3.15:17912`，普通代理被 400 拒，
    /// 换成 `plugin=http_proxy`/`socks5` 就 200 放行并取回内网数据。
    #[tokio::test]
    async fn 远程下发不得携带插件字段() {
        // 每一种都单独验证（不能只测一个组合）
        type Case = (&'static str, Box<dyn FnOnce(&mut ProxyConfig)>);
        let cases: Vec<Case> = vec![
            (
                "plugin",
                Box::new(|p: &mut ProxyConfig| p.plugin = "http_proxy".to_string()),
            ),
            (
                "plugin",
                Box::new(|p: &mut ProxyConfig| p.plugin = "socks5".to_string()),
            ),
            (
                "plugin",
                Box::new(|p: &mut ProxyConfig| p.plugin = "static_file".to_string()),
            ),
            (
                "pluginUser",
                Box::new(|p: &mut ProxyConfig| p.plugin_user = "u".to_string()),
            ),
            (
                "pluginPasswd",
                Box::new(|p: &mut ProxyConfig| p.plugin_passwd = "pw".to_string()),
            ),
            (
                "pluginHostHeaderRewrite",
                Box::new(|p: &mut ProxyConfig| p.plugin_host_header_rewrite = "x".to_string()),
            ),
            (
                "pluginStripPrefix",
                Box::new(|p: &mut ProxyConfig| p.plugin_strip_prefix = "/a".to_string()),
            ),
        ];

        for (label, set) in cases {
            let (mut me, _peer) = cmd_pair();
            let table = registry::ProxyTable::default();
            // ★ 关键：**local_addr 留空** —— 这正是绕开 H4 的那种形态
            let cmd = add_cmd_with("openproxy", |p| {
                p.local_addr = String::new();
                set(p);
            });
            let err = apply_server_cmd(&table, "", &no_store(), &cmd, &mut me)
                .await
                .expect_err(&format!("{label} 必须被拒绝（哪怕 local_addr 为空）"));
            assert!(
                err.to_string().contains(label),
                "错误里要点名 {label}：{err}"
            );
            assert_eq!(table.len(), 0, "{label} 被拒时不该留下代理");
        }
    }

    /// F1 的反向保护：**不带插件**的合法远程下发仍然要能用。
    ///
    /// 这一条防止"修得太狠" —— 面板的正常「添加代理」功能必须照旧工作。
    #[tokio::test]
    async fn 不带插件的远程下发仍然可用() {
        let (mut me, _peer) = cmd_pair();
        let table = registry::ProxyTable::default();
        let cmd = add_cmd_with("normal", |p| {
            p.local_addr = "127.0.0.1:8080".to_string();
            p.remote_port = 6100;
        });
        apply_server_cmd(&table, "", &no_store(), &cmd, &mut me)
            .await
            .expect("普通的回环代理应当照常放行");
        assert_eq!(table.len(), 1);
    }

    /// ★ 回归测试：服务端下发**不认识的插件类型**要在解析阶段就被拒。
    ///
    /// 原先这条路径一道校验都不过，拼错的插件名能一路溜到运行期，
    /// 变成"每条工作连接逐个失败"。
    ///
    /// ★ v0.5.5（第四轮 F1）调整：现在**任何**插件都不许远程下发，
    /// 所以这条用例改到**配置文件**路径去验证（`is_remote = false`）——
    /// "拼错的插件名要被解析阶段拦住"这个不变量本身仍然有效，
    /// 只是它的适用场景从"远程下发"变成了"本机配置"。
    #[test]
    fn 不认识插件类型在解析阶段被拒() {
        let mut p = ProxyConfig {
            name: "bad-plugin".into(),
            proxy_type: "tcp".into(),
            local_addr: "127.0.0.1:80".into(),
            plugin: "totally_made_up".into(),
            ..Default::default()
        };
        // 本机配置路径：仍然要走插件类型自检
        let err = nfrp_common::config::validate_remote_proxy(&p, false)
            .expect_err("本机配置里的未知插件类型也必须被拒");
        assert!(
            err.to_string().contains("totally_made_up"),
            "错误里要点名插件：{err}"
        );

        // 远程路径：连合法插件名都不许（F1 的更严不变量）
        p.plugin = "socks5".into();
        let err2 = nfrp_common::config::validate_remote_proxy(&p, true)
            .expect_err("远程下发不得携带任何插件");
        assert!(err2.to_string().contains("plugin"), "{err2}");
    }

    /// ★ 回归测试：服务端下发**不受支持的代理类型**要被拒。
    #[tokio::test]
    async fn 远程下发的不支持代理类型必须被拒绝() {
        let (mut me, _peer) = cmd_pair();
        let table = registry::ProxyTable::default();
        let cmd = add_cmd_with("bad-type", |p| p.proxy_type = "not-a-thing".to_string());
        let err = apply_server_cmd(&table, "", &no_store(), &cmd, &mut me)
            .await
            .expect_err("不支持的代理类型必须被拒绝");
        assert!(
            err.to_string().contains("not-a-thing"),
            "错误里要点名类型：{err}"
        );
        assert_eq!(table.len(), 0);
    }

    /// 新增代理：本地表里要真的多出一条，且必须回一条成功回执。
    #[tokio::test]
    async fn 管理命令_新增代理() {
        let (mut me, mut peer) = cmd_pair();
        let table = registry::ProxyTable::default();
        apply_server_cmd(&table, "", &no_store(), &add_cmd("panel-web"), &mut me)
            .await
            .expect("新增应当成功");

        assert_eq!(table.len(), 1, "代理要真的进到本地表里");
        assert_eq!(table.get("panel-web").expect("能查到").remote_port, 7000);

        // 回执：id 必须原样带回，error 为空
        let resp = expect_cmd_resp(&mut peer).await;
        assert_eq!(resp.id, "cmd-1", "id 必须原样带回");
        assert_eq!(resp.op, msg::CMD_ADD_PROXY);
        assert!(resp.error.is_empty(), "不该带错误：{}", resp.error);
    }

    /// **失败也必须回包**：面板是同步等回执的，不回就只能等到超时。
    #[tokio::test]
    async fn 管理命令_失败也要回执() {
        let (mut me, mut peer) = cmd_pair();
        let table = registry::ProxyTable::default();

        // 移除一个不存在的代理
        let cmd = msg::ServerCmd {
            id: "cmd-2".to_string(),
            op: msg::CMD_REMOVE_PROXY.to_string(),
            proxy_name: "nope".to_string(),
            ..Default::default()
        };
        apply_server_cmd(&table, "", &no_store(), &cmd, &mut me)
            .await
            .expect_err("移除不存在的代理应当失败");

        let resp = expect_cmd_resp(&mut peer).await;
        assert_eq!(resp.id, "cmd-2");
        assert!(
            resp.error.contains("nope"),
            "错误里要带上名字方便自查：{}",
            resp.error
        );
        // 顺便确认错误里会把当前有哪些代理列出来 —— 名字打错是最常见的失败原因
        assert!(
            resp.error.contains("无"),
            "应当顺便列出当前代理：{}",
            resp.error
        );
    }

    /// 未知命令要报错，而不是被当成成功。
    #[tokio::test]
    async fn 管理命令_未知op被拒绝() {
        let (mut me, mut peer) = cmd_pair();
        let table = registry::ProxyTable::default();
        let cmd = msg::ServerCmd {
            id: "cmd-3".to_string(),
            op: "format_disk".to_string(),
            ..Default::default()
        };
        apply_server_cmd(&table, "", &no_store(), &cmd, &mut me)
            .await
            .expect_err("未知命令必须失败");
        assert!(expect_cmd_resp(&mut peer).await.error.contains("未知命令"));
    }

    /// 先加后删：整条生命周期要闭环。
    ///
    /// ★ v0.5.5（第四轮 F2）调整：原来这条用例删的是 `from_iter` 建进来的
    /// `"old"` —— 那是**配置来源**的代理，现在远程 `remove` 会（正确地）拒绝它。
    /// 也就是说这条测试原先在无意中**断言了 F2 那个漏洞**（面板能删配置代理）。
    /// 现在改成"加一条动态的、再删那条动态的"，生命周期照样闭环，
    /// 而配置代理必须原样留着 —— 下面多加了断言把这个不变量钉住。
    #[tokio::test]
    async fn 管理命令_先加后删() {
        let (mut me, mut peer) = cmd_pair();
        let table = registry::ProxyTable::from_iter([ProxyConfig {
            name: "old".into(),
            ..Default::default()
        }]);

        apply_server_cmd(&table, "", &no_store(), &add_cmd("new"), &mut me)
            .await
            .expect("新增");
        let _ = expect_cmd_resp(&mut peer).await;
        assert_eq!(table.len(), 2);

        // 删**动态加进来的**那条 —— 这是合法路径
        let cmd = msg::ServerCmd {
            id: "cmd-4".to_string(),
            op: msg::CMD_REMOVE_PROXY.to_string(),
            proxy_name: "new".to_string(),
            ..Default::default()
        };
        apply_server_cmd(&table, "", &no_store(), &cmd, &mut me)
            .await
            .expect("移除动态代理");
        let _ = expect_cmd_resp(&mut peer).await;
        assert_eq!(table.len(), 1, "删掉之后只剩配置里那条");
        assert!(table.get("new").is_none(), "动态那条应当被删掉");
        assert!(table.get("old").is_some(), "配置那条必须原样留着（F2）");

        // ★ 反向：远程删**配置来源**的代理必须被拒，且那条要还在
        let cmd = msg::ServerCmd {
            id: "cmd-5".to_string(),
            op: msg::CMD_REMOVE_PROXY.to_string(),
            proxy_name: "old".to_string(),
            ..Default::default()
        };
        apply_server_cmd(&table, "", &no_store(), &cmd, &mut me)
            .await
            .expect_err("删配置代理必须被拒（F2）");
        let resp = expect_cmd_resp(&mut peer).await;
        assert!(
            resp.error.contains("配置文件"),
            "回执要说清原因：{}",
            resp.error
        );
        assert!(table.get("old").is_some(), "被拒之后配置代理必须还在");
    }

    /// ★★ F3 回归：远程下发**同名** `add_proxy` 不得覆盖配置里的代理。
    ///
    /// 这是"双杀"链条的第一环：覆盖成功 → 服务端回滚发 remove →
    /// 用户的配置永久消失。堵住第一环，整条链就断了。
    #[tokio::test]
    async fn 管理命令_不得覆盖配置里的同名代理() {
        let (mut me, mut peer) = cmd_pair();
        let mut cfg = ProxyConfig {
            name: "my-web".into(),
            ..Default::default()
        };
        cfg.remote_port = 18202;
        let table = registry::ProxyTable::from_iter([cfg]);

        let cmd = add_cmd_with("my-web", |p| {
            p.remote_port = 9999;
            p.local_addr = "127.0.0.1:9".into();
        });
        apply_server_cmd(&table, "", &no_store(), &cmd, &mut me)
            .await
            .expect_err("覆盖配置代理必须被拒（F3）");
        let resp = expect_cmd_resp(&mut peer).await;
        assert!(
            resp.error.contains("配置文件"),
            "回执要说清原因：{}",
            resp.error
        );
        // 用户那条必须原样（端口没变）
        assert_eq!(
            table.get("my-web").expect("配置代理必须还在").remote_port,
            18202,
            "配置代理不该被改掉"
        );
    }

    /// 读一条回执。**带超时** —— 没有超时的话，一旦发送侧没写出去，
    /// 这条测试会永远挂住，把整个测试进程一起拖死（踩过一次）。
    async fn expect_cmd_resp(conn: &mut FrpConn) -> msg::ServerCmdResp {
        let got = tokio::time::timeout(Duration::from_secs(5), conn.recv_msg())
            .await
            .expect("5 秒内必须收到回执 —— 没收到说明发送侧根本没写出去")
            .expect("读回执");
        match got {
            Some(FrpMessage::ServerCmdResp(r)) => r,
            other => panic!("应当是 ServerCmdResp，实际：{other:?}"),
        }
    }

    /// ★ v0.5.8（第八轮审计 F8-L2，低危）回归：面板列表里的**线上全名**
    /// 也要能直接删掉。
    ///
    /// 服务端 v0.5.8 起下发的已是本地名（`admin.rs` 剥了前缀）；这里覆盖
    /// "客户端先升级、服务端仍是旧版"的滚动升级窗口 —— 旧服务端转发的就是
    /// 面板给的全名。修复前客户端拿全名查本地表 ⇒ 拒删 ⇒ 服务端已摘、
    /// 客户端留条目（两端状态分裂，v2 回 502）。
    #[tokio::test]
    async fn 用线上全名也能删除动态代理() {
        let (mut me, _peer) = cmd_pair();
        let table = registry::ProxyTable::default();
        let user = "probeuser";

        // 动态加两条（`add_proxy_cmd` 会把它们放进"可被远程删除"的表）
        apply_server_cmd(&table, user, &no_store(), &add_cmd("web"), &mut me)
            .await
            .expect("动态添加 web");
        apply_server_cmd(&table, user, &no_store(), &add_cmd("web2"), &mut me)
            .await
            .expect("动态添加 web2");
        assert_eq!(table.len(), 2);

        // ① 旧服务端行为：下发**全名** `probeuser.web` —— 必须容错到本地名
        apply_server_cmd(
            &table,
            user,
            &no_store(),
            &remove_cmd("probeuser.web"),
            &mut me,
        )
        .await
        .expect("全名删除必须成功（剥本端 user 前缀兜底）");
        assert!(
            !table.names().iter().any(|n| n == "web"),
            "web 应已从本地表删除"
        );

        // ② 对照：下发本地名（v0.5.8 服务端的正常契约）
        apply_server_cmd(&table, user, &no_store(), &remove_cmd("web2"), &mut me)
            .await
            .expect("本地名删除应成功");
        assert_eq!(table.len(), 0);

        // ③ 窥探面：不相干的名字不能被"剥前缀"误删
        //     （user=probeuser，删 "alice.web" 时 strip 是恒等 ⇒ 仍应报"没有"）
        let err = apply_server_cmd(&table, user, &no_store(), &remove_cmd("alice.web"), &mut me)
            .await
            .expect_err("别人的前缀不该被剥");
        assert!(
            err.to_string().contains("alice.web"),
            "错误里保留原名：{err}"
        );
    }
}
