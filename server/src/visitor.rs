//! stcp / xtcp 的 **visitor 接入表**。
//!
//! 与 tcp / udp / http 不同，stcp / xtcp 的 provider **不在公网上开端口**：
//! 服务端只为它登记一条记录（`provider 的工作连接来源 + 共享密钥`），
//! 等 visitor 主动连进来时再校验密钥、把双方配对。
//!
//! 对应官方 frps 的 `server/visitor.Manager` + `proxy.startVisitorListener`。

use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};

use crate::ClientState;

/// 一条已注册的 stcp / xtcp 代理（等待 visitor 来连）。
pub struct VisitorEntry {
    pub proxy_name: String,
    /// provider 配置的共享密钥；visitor 的签名必须由它算出。
    pub secret_key: String,
    /// 允许接入的访客列表；为空时退化为"只允许 provider 自己的 user"。
    pub allow_users: Vec<String>,
    /// provider 客户端在 `Login` 里声明的顶层 `user`（`allow_users` 为空时的默认白名单）。
    pub provider_user: String,
    /// provider 所属的客户端，配对工作连接时要用它去要连接。
    pub client: Arc<ClientState>,
    /// `stcp` 或 `xtcp`（仅用于日志/遥测）。
    pub proxy_type: String,
}

impl VisitorEntry {
    /// 校验 visitor 的签名：`hex(md5(secret_key + timestamp))`。
    pub fn check_sign(&self, sign_key: &str, timestamp: i64) -> bool {
        let expected = rustunnel_common::frp::msg::auth_key(&self.secret_key, timestamp);
        rustunnel_common::frp::msg::constant_time_eq(&expected, sign_key)
    }

    /// 校验访客用户是否被允许，语义与官方 frps 完全一致：
    ///
    /// ```text
    /// if allowUsers == [] { allowUsers = [provider.User] }   // 空 → 只允许同一 user
    /// allow  <=>  allowUsers 含 visitorUser  或  allowUsers 含 "*"
    /// ```
    ///
    /// 注意比对的是**访问方 frpc 顶层的 `user`**（`Login.User`），不是 `[[visitors]]` 的 `name`。
    pub fn check_user(&self, visitor_user: &str) -> bool {
        if self.allow_users.is_empty() {
            return self.provider_user == visitor_user;
        }
        self.allow_users
            .iter()
            .any(|u| u == "*" || u == visitor_user)
    }
}

/// 一条 stcp / xtcp 代理的只读快照（给面板 / API 用）。
#[derive(Debug, Clone)]
pub struct VisitorInfo {
    pub proxy_name: String,
    pub proxy_type: String,
    pub provider_user: String,
    pub allow_users: Vec<String>,
    pub client_id: String,
}

/// 全局的 visitor 表（按代理名索引）。
#[derive(Default)]
pub struct VisitorTable {
    inner: Mutex<HashMap<String, Arc<VisitorEntry>>>,
}

impl VisitorTable {
    /// 注册一条 stcp / xtcp 代理；同名重复注册会失败（与 frp 的 "repeated" 行为一致）。
    pub fn register(&self, entry: VisitorEntry) -> Result<(), String> {
        let name = entry.proxy_name.clone();
        let mut g = self.inner.lock().unwrap();
        if g.contains_key(&name) {
            return Err(format!("custom listener for [{name}] is repeated"));
        }
        g.insert(name, Arc::new(entry));
        Ok(())
    }

    /// 按代理名查一条记录。
    pub fn get(&self, name: &str) -> Option<Arc<VisitorEntry>> {
        self.inner.lock().unwrap().get(name).cloned()
    }

    /// 客户端主动 `CloseProxy` 时摘掉一条记录，之后同名代理可以重新注册。
    pub fn remove(&self, name: &str) -> Option<Arc<VisitorEntry>> {
        self.inner.lock().unwrap().remove(name)
    }

    /// 全部 stcp / xtcp 代理的快照（面板展示用）。
    pub fn list(&self) -> Vec<VisitorInfo> {
        self.inner
            .lock()
            .unwrap()
            .values()
            .map(|e| VisitorInfo {
                proxy_name: e.proxy_name.clone(),
                proxy_type: e.proxy_type.clone(),
                provider_user: e.provider_user.clone(),
                allow_users: e.allow_users.clone(),
                client_id: e.client.client_id().to_string(),
            })
            .collect()
    }

    /// 客户端断开时回收它的全部 stcp / xtcp 代理。
    pub fn unregister_client(&self, client: &Arc<ClientState>) {
        let mut g = self.inner.lock().unwrap();
        g.retain(|_, e| !Arc::ptr_eq(&e.client, client));
    }
}
