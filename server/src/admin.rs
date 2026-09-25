//! 面板的**写操作**：增删代理、踢客户端。
//!
//! 官方 frp 到 v0.68 才补上"通过 API 操作代理"，而且客户端必须是自家的 frpc。
//! 这里做成 NFrp 私有能力：服务端在 `LoginResp` 里回显 `server_cmd`
//! 之后，才往客户端发 [`ServerCmd`]；连着官方 frpc 时能力不开，
//! 面板直接回一句人话错误，而不是干等到超时。
//!
//! 三个操作都走同一条纪律：**先问客户端，再动服务端**，且客户端说不行就回滚。

use std::{sync::Arc, time::Duration};

use nfrp_common::{
    config::{ProxyConfig, ServerConfig},
    frp::msg::{self, NewProxy, ServerCmd},
};
use tokio::sync::oneshot;

use crate::{
    pool::{ClientState, CtrlCmd},
    registry::Registry,
};

/// 等客户端回执的最长时间。
///
/// 面板是同步等这个结果的，太长会让界面卡住；太短又会把"慢但成功"的操作
/// 误判成失败。5 秒足够一个正常客户端解析配置并回包。
const ACK_TIMEOUT: Duration = Duration::from_secs(5);

/// 一次管理操作的结果：要么是给人看的成功文案，要么是人话错误。
pub type AdminResult = Result<String, String>;

/// 给某个客户端**新增**一条代理。
///
/// 顺序很讲究：
///
/// 1. 先让客户端把代理放进它自己的表（它不认识这条代理，后面所有
///    工作连接都会因为"未知代理"而失败）；
/// 2. 客户端确认了，服务端才开端口 / 注册域名；
/// 3. 服务端开端口失败，要回头让客户端把刚加的那条删掉。
///
/// 反过来（先开端口再通知客户端）会留下一个"端口开着但没有后端"的洞，
/// 而洞比失败更难发现。
pub async fn add_proxy(
    cfg: &Arc<ServerConfig>,
    registry: &Arc<Registry>,
    run_id: &str,
    proxy: ProxyConfig,
) -> AdminResult {
    if proxy.name.is_empty() {
        return Err("代理配置缺少 name".to_string());
    }
    if proxy.proxy_type.is_empty() {
        return Err("代理配置缺少 type".to_string());
    }
    let client = registry
        .client(run_id)
        .ok_or_else(|| format!("没有在线客户端 [{run_id}]"))?;
    let name = proxy.name.clone();

    // 1) 客户端先认下这条代理
    ask(
        &client,
        ServerCmd {
            id: new_cmd_id(),
            op: msg::CMD_ADD_PROXY.to_string(),
            proxy_name: name.clone(),
            proxy: Some(serde_json::to_value(&proxy).map_err(|e| e.to_string())?),
            reason: "dashboard".to_string(),
        },
    )
    .await
    .map_err(|e| format!("客户端拒绝新增代理：{e}"))?;

    // 2) 服务端开端口 / 注册域名
    let wire = NewProxy::from_config(&proxy, &client.user);
    match crate::serve::register_proxy(cfg, registry, &client, &wire).await {
        Ok(remote) => {
            registry.metrics().proxies_total.inc();
            registry.metrics().proxies_active.inc();
            tracing::info!(%run_id, proxy = %name, remote = %remote, "面板新增代理成功");
            Ok(format!("代理 [{name}] 已生效：{remote}"))
        }
        Err(e) => {
            // 3) 回滚：端口没开成，客户端那边也不能留着这条
            let _ = ask(
                &client,
                ServerCmd {
                    id: new_cmd_id(),
                    op: msg::CMD_REMOVE_PROXY.to_string(),
                    proxy_name: name.clone(),
                    reason: "rollback".to_string(),
                    ..Default::default()
                },
            )
            .await;
            Err(format!("服务端注册代理失败（已回滚）：{e}"))
        }
    }
}

/// 停掉某个客户端的一条代理。**先停服务端，再让客户端摘掉**。
///
/// 与 [`add_proxy`] 的顺序相反是故意的：撤资源没有"开洞"的风险，
/// 而先停服务端能立刻切断新流量，不用等客户端回包。
pub async fn remove_proxy(registry: &Arc<Registry>, run_id: &str, name: &str) -> AdminResult {
    if name.is_empty() {
        return Err("缺少代理名".to_string());
    }
    let client = registry
        .client(run_id)
        .ok_or_else(|| format!("没有在线客户端 [{run_id}]"))?;

    // 服务端这侧：端口 / 域名 / visitor 全摘掉（与客户端主动 CloseProxy 同款清理）
    let wire_name = nfrp_common::util::add_user_prefix(&client.user, name);
    registry.visitors.remove(&wire_name);
    if let Some(t) = registry.vhosts() {
        t.remove_proxy(&wire_name);
    }
    if let Some(port) = client.stop_proxy(&wire_name) {
        registry.release_port(port, &client, &wire_name);
    }
    registry.metrics().proxies_active.dec();

    // 客户端那侧：失败也只是它表里多留一条（服务端已经不放流量进来了），
    // 所以这里只告警、不回滚
    match ask(
        &client,
        ServerCmd {
            id: new_cmd_id(),
            op: msg::CMD_REMOVE_PROXY.to_string(),
            proxy_name: name.to_string(),
            reason: "dashboard".to_string(),
            ..Default::default()
        },
    )
    .await
    {
        Ok(()) => {
            tracing::info!(%run_id, proxy = %name, "面板移除代理成功");
            Ok(format!("代理 [{name}] 已移除"))
        }
        Err(e) => Err(format!(
            "服务端已移除，但客户端侧失败（{e}）—— 它会在下次重连后自愈"
        )),
    }
}

/// 踢掉一个客户端：立刻切断它的所有代理，并结束它的控制连接。
pub async fn kick(registry: &Arc<Registry>, run_id: &str, reason: &str) -> AdminResult {
    let client = registry
        .remove(run_id)
        .ok_or_else(|| format!("没有在线客户端 [{run_id}]"))?;
    // `remove` 内部已经 `stop()` 了：它名下的工作连接请求会立刻失败，
    // 控制连接也会在下一个心跳周期自己退出（见 serve.rs 的 stopped 检查）。
    client.stop();
    registry.release_ports_of(&client);
    tracing::warn!(%run_id, %reason, "面板踢出客户端");
    Ok(format!(
        "客户端 [{run_id}] 已踢出（{}）",
        if reason.is_empty() {
            "无理由"
        } else {
            reason
        }
    ))
}

/// 下发一条命令并等回执。
async fn ask(client: &Arc<ClientState>, cmd: ServerCmd) -> Result<(), String> {
    let (tx, rx) = oneshot::channel();
    let sent = client.req_tx().send(CtrlCmd::ServerCmd {
        cmd: Box::new(cmd),
        ack: tx,
    });
    if sent.is_err() {
        return Err("客户端的控制连接已断开".to_string());
    }
    match tokio::time::timeout(ACK_TIMEOUT, rx).await {
        // 控制连接先断了：rx 那头被 drop
        Ok(Err(_)) => Err("客户端在回执前断开".to_string()),
        Ok(Ok(outcome)) => outcome,
        Err(_) => Err(format!("{} 秒内没有收到回执", ACK_TIMEOUT.as_secs())),
    }
}

fn new_cmd_id() -> String {
    nfrp_common::util::new_run_id()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::registry::ServerLimits;

    fn client(run_id: &str) -> Arc<ClientState> {
        let (tx, rx) = tokio::sync::mpsc::unbounded_channel::<CtrlCmd>();
        std::mem::forget(rx);
        let (conn, backlog, proxy) = ServerLimits::default().per_client();
        Arc::new(ClientState::new(
            run_id.to_string(),
            run_id.to_string(),
            "alice".to_string(),
            tx,
            Duration::from_secs(60),
            Default::default(),
            false,
            nfrp_common::frp::WireVersion::V1,
            conn,
            backlog,
            proxy,
        ))
    }

    /// 客户端不在线时必须给出**人话**错误，而不是 panic 或空成功。
    #[tokio::test]
    async fn missing_client_is_reported_not_panicked() {
        let r = Arc::new(Registry::unlimited());

        let e = remove_proxy(&r, "nope", "web").await.expect_err("应当报错");
        assert!(e.contains("nope"), "错误里要带上找不到的 run_id：{e}");
        let e = kick(&r, "nope", "").await.expect_err("应当报错");
        assert!(e.contains("nope"));
    }

    /// 缺字段要**在发命令之前**被拦住 —— 发过去也是被客户端拒绝，
    /// 白白多一次往返，而且错误信息还没这里的清楚。
    #[tokio::test]
    async fn missing_fields_are_rejected_locally() {
        let r = Arc::new(Registry::unlimited());
        let cfg = Arc::new(ServerConfig::default());
        let c = client("c1");
        r.insert(c.clone()).expect("插入");

        let e = add_proxy(&cfg, &r, "c1", ProxyConfig::default())
            .await
            .expect_err("缺 name 应当报错");
        assert!(e.contains("name"), "错误要指名道姓：{e}");

        let p = ProxyConfig {
            name: "web".into(),
            ..Default::default()
        };
        let e = add_proxy(&cfg, &r, "c1", p)
            .await
            .expect_err("缺 type 应当报错");
        assert!(e.contains("type"), "错误要指名道姓：{e}");
    }

    /// 踢人之后这个客户端必须真的从注册表里消失。
    #[tokio::test]
    async fn kick_removes_the_client() {
        let r = Arc::new(Registry::unlimited());
        let c = client("c1");
        r.insert(c.clone()).expect("插入");
        assert_eq!(r.clients().len(), 1);

        kick(&r, "c1", "测试").await.expect("踢出成功");
        assert_eq!(r.clients().len(), 0, "踢完之后不该还留在注册表里");
        assert!(c.is_stopped(), "被踢的客户端必须标记为已停止");
        // 再踢一次应当是"没有这个客户端"，而不是 panic
        assert!(kick(&r, "c1", "").await.is_err());
    }
}
