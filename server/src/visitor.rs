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
    /// `stcp` / `xtcp` / `sudp`（仅用于日志/遥测）。
    pub proxy_type: String,
}

impl VisitorEntry {
    /// 校验 visitor 的签名：`hex(md5(secret_key + timestamp))`。
    ///
    /// **`skew` 是必需参数，
    ///    新鲜性校验就嵌在函数体里**。
    ///
    /// # 原先为什么错了
    ///
    /// 旧签名是 `check_sign(&self, sign_key, timestamp)`，只比内容、
    /// **完全不看 `timestamp` 有多旧** ⇒ 嗅探到一条 `NewVisitorConn`
    /// 即可**无限期重放**加入他人的私密隧道。实测**一年前**的报文仍被接受。
    ///
    /// 这与 M3 修过的"登录凭证重放"是**同一个洞的另一条路径** ——
    /// M3 只铺了主登录一处，而凭证入口一共有 6 个
    ///
    /// # 为什么把 skew 做成必需参数
    ///
    /// 只要"只校验内容"这个入口存在，调用方就可能忘了查新鲜性 ——
    /// 这正是本轮的成因。现在**没有只比内容的入口**：想校验签名就必须
    /// 提供时间窗口（`skew = 0` 是显式的"我要关掉它"，不是默认值）。
    pub fn check_sign(&self, sign_key: &str, timestamp: i64, skew: u64) -> bool {
        nfrp_common::security::verify_shared_secret_proof(
            &self.secret_key,
            sign_key,
            timestamp,
            skew,
            "visitor 签名",
        )
        .is_ok()
    }

    /// 校验访客用户是否被允许，语义与官方 frps 完全一致：
    ///
    /// ```text
    /// if allowUsers == [] { allowUsers = [provider.User] }   // 空 → 只允许同一 user
    /// allow  <=>  allowUsers 含 visitorUser  或  allowUsers 含 "*"
    /// ```
    ///
    /// 注意比对的是**访问方 frpc 顶层的 `user`**（`Login.User`），不是 `[[visitors]]` 的 `name`。
    ///
    /// **空串显式判 false**（纵深防御）。
    ///
    /// # 为什么
    ///
    /// 官方语义里 `"*"` 是"任意**已登录的 frpc 用户**可访问"，
    /// **不是**"任意 TCP 连接可访问"。而 `.any(|u| u == "*" || u == visitor_user)`
    /// 在 `visitor_user` 为空串时会让 `u == "*"` **直接命中** ⇒
    /// 一个"没有身份"的连接被当成合法访客。
    ///
    /// 调用点（`serve.rs` 的 `handle_visitor`）本轮已经改成
    /// "空 `run_id` 一律拒绝 + 身份从会话反查"，所以这里**正常情况下
    /// 不会再收到空串**。但认证路径上"字段缺失 ⇒ 跳过校验"是危险模式，
    /// 所以在**判据本身**里再堵一层：即使将来某个调用点又传了空串，
    /// 它也不会被当成"匹配任意"。
    ///
    /// -5 修正（功能回归）：上面那句"即使传了空串也不匹配任意"
    /// 原先实现成 **空串一律 false** —— 但空 `user` 不是攻击者的专利：
    /// 双方都没配 `user`（配置里的默认值就是空）时，官方 frps 走
    /// "空 `allow_users` ⇒ 只允许 provider 自己的 user" ⇒ `"" == ""` 放行。
    /// 实测该组合下 stcp visitor **完全无法配对**（A9-5 调试：
    /// 服务端打 `visitor 用户不在 allow_users 白名单内`）。
    /// 现在只在**命中白名单**的方向上堵空串；`allow_users` 为空时恢复官方语义。
    pub fn check_user(&self, visitor_user: &str) -> bool {
        if self.allow_users.is_empty() {
            // 官方语义：空 `allow_users` 退化成"只允许 provider 自己的 user"。
            // 登录已完成认证，这里比的是"身份相同"，不是"匹配任意" ——
            // 空 provider_user 与空访客 identity 相等是合法的默认场景。
            return self.provider_user == visitor_user;
        }
        // `allow_users = ["*"]` 的语义是"任意**已登录用户**"，不是"任意 TCP
        // 连接" —— 空身份不得命中星号，也不得命具名白名单。
        if visitor_user.is_empty() {
            return false;
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
        let mut g = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        if g.contains_key(&name) {
            return Err(format!("custom listener for [{name}] is repeated"));
        }
        g.insert(name, Arc::new(entry));
        Ok(())
    }

    /// 按代理名查一条记录。
    pub fn get(&self, name: &str) -> Option<Arc<VisitorEntry>> {
        self.inner
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(name)
            .cloned()
    }

    /// 客户端主动 `CloseProxy` 时摘掉一条记录，之后同名代理可以重新注册。
    ///
    /// **必须同时比客户端身份，不能只比名字**。
    ///
    /// 这是 H1 的**同一个根因、漏掉的第二处**：
    /// vhost 的三处判定在 H1 里补上了客户端身份，而本函数漏了。
    /// 注意**同一个文件里** `unregister_client`（下面）一直是对的
    /// —— 用的是 `Arc::ptr_eq(&e.client, client)`。
    ///
    /// 原先只按名字摘的后果：客户端 A 发一条
    /// `CloseProxy("{victim}.{name}")` 就能摘掉**受害者 B** 的 stcp/xtcp 注册记录
    /// ⇒ B 的私密隧道对新 visitor 立即失效（B 自己的客户端还活着、日志无异常）。
    /// 而且 `register` 只在"名字已存在"时失败，所以摘掉之后攻击者还能把
    /// **自己的**记录注册到那个名字上，让 B 的隧道彻底连不上（DoS）。
    ///
    /// 与 H1 的 `remove_proxy` 面完全同构：**一次不需要任何权限的跨租户拒绝服务**。
    pub fn remove(&self, client: &Arc<ClientState>, name: &str) -> Option<Arc<VisitorEntry>> {
        let mut g = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        // 先确认这条记录确实属于这个客户端，再摘 —— 不能"先删了再看是谁的"
        match g.get(name) {
            Some(e) if Arc::ptr_eq(&e.client, client) => g.remove(name),
            _ => None,
        }
    }

    /// 全部 stcp / xtcp 代理的快照（面板展示用）。
    pub fn list(&self) -> Vec<VisitorInfo> {
        self.inner
            .lock()
            .unwrap_or_else(|e| e.into_inner())
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
        let mut g = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        g.retain(|_, e| !Arc::ptr_eq(&e.client, client));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pool::dummy_client;

    fn entry(name: &str, client: &Arc<ClientState>) -> VisitorEntry {
        VisitorEntry {
            proxy_name: name.to_string(),
            secret_key: "sk".to_string(),
            allow_users: Vec::new(),
            provider_user: "u".to_string(),
            client: client.clone(),
            proxy_type: "stcp".to_string(),
        }
    }

    /// 持有者自己能摘掉自己的记录。
    #[test]
    fn 持有者可以摘掉自己的_visitor_记录() {
        let t = VisitorTable::default();
        let me = dummy_client("me");
        t.register(entry("u.sec1", &me)).expect("注册");
        assert!(t.get("u.sec1").is_some());

        assert!(t.remove(&me, "u.sec1").is_some(), "持有者应当能摘掉");
        assert!(t.get("u.sec1").is_none(), "摘掉之后查不到了");
    }

    /// **空串身份不是"匹配任意"**。
    ///
    /// # 锁的是什么
    ///
    /// 官方语义里 `allow_users = ["*"]` 是"任意**已登录的 frpc 用户**可访问"，
    /// **不是**"任意 TCP 连接可访问"。而 `.any(|u| u == "*" || u == visitor_user)`
    /// 在 `visitor_user` 为空串时会让 `u == "*"` **直接命中**
    /// ⇒ 一个"没有身份"的连接被当成合法访客。
    ///
    /// 实测（`tmp/audit6-d/_repro_d2_anon.py`）端到端确认过：匿名连接发出的
    /// payload **真的到达了 alice 的工作连接**。
    ///
    /// # 为什么这条测试必须单独存在（退回验证发现的）
    ///
    /// D-2 有**两层**修复：
    /// 1. `serve.rs`：空 `run_id` 一律拒绝 + 身份从会话反查
    /// 2. `visitor.rs`（本函数）：空串显式判 false（**纵深防御**）
    ///
    /// 第 1 层已经让空串**走不到**这里，所以把第 2 层退掉时**原有测试仍全绿** ——
    /// 退回验证（`tmp/verify_round6_revert.py`）就是这样发现"这一层没有测试"的。
    /// 纵深防御层**必须有独立的测试**，否则它只是个没人验证的注释。
    #[test]
    fn 空身份不能匹配星号白名单() {
        // 空 allow_users：退化成"只允许 provider 自己的 user"
        let mut e = entry("u.sec1", &dummy_client("me"));
        e.allow_users = Vec::new();
        e.provider_user = "bob".into();
        assert!(
            !e.check_user(""),
            "空身份不能等同于 provider_user（除非 provider_user 本身是空）"
        );
        assert!(e.check_user("bob"), "provider 自己的 user 应当放行");
        assert!(!e.check_user("alice"), "别的 user 应当拒绝");

        // -5：provider 自己也是空 user（默认场景）时，
        //   空身份 == 空 provider_user 必须放行（否则 visitor 功能不可用）。
        e.allow_users = Vec::new();
        e.provider_user = String::new();
        assert!(
            e.check_user(""),
            "双方都没配 user 是默认场景，官方语义放行；不许回归"
        );
        assert!(!e.check_user("alice"), "空 provider 只允许空身份");

        // 被测的那条：`["*"]`（"对所有人开放"）也不能被空身份命中
        e.allow_users = vec!["*".into()];
        assert!(
            !e.check_user(""),
            "`allow_users = [\"*\"]` 的语义是『任意**已登录用户**』，\
             不是『任意 TCP 连接』—— 空身份必须被拒，否则匿名连接会被当成合法访客"
        );
        assert!(
            e.check_user("anyone"),
            "有身份的任意用户应当放行（* 的本意）"
        );

        // 具名白名单同样不能被空身份命中
        e.allow_users = vec!["bob".into(), "carol".into()];
        assert!(!e.check_user(""), "空身份不得命中具名白名单");
        assert!(e.check_user("bob"));
        assert!(e.check_user("carol"));
        assert!(!e.check_user("dave"));
    }

    /// B-1 核心回归：**别的租户不能按名字摘掉我的记录**。
    ///
    /// 修复前 `remove` 只比名字 ⇒ 攻击者发一条
    /// `CloseProxy("u.sec1")` 就能摘掉受害者的 stcp 注册记录，
    /// 之后还能把**自己的**记录注册到那个名字上（`register` 只在重名时失败），
    /// 让受害者的私密隧道彻底连不上 —— 一次不需要任何权限的跨租户 DoS。
    #[test]
    fn 别的租户不得按名字摘掉我的_visitor_记录() {
        let t = VisitorTable::default();
        let victim = dummy_client("victim-run");
        let attacker = dummy_client("attacker-run");
        t.register(entry("victim.sec1", &victim))
            .expect("受害者注册");

        // 攻击者按名字摘 —— 必须失败（摘不到任何东西）
        assert!(
            t.remove(&attacker, "victim.sec1").is_none(),
            "攻击者不该能摘掉别人的记录"
        );
        assert!(t.get("victim.sec1").is_some(), "受害者的记录必须还在");

        // 而且攻击者也不能趁机把同名记录据为己有（register 会因重名失败）
        assert!(
            t.register(entry("victim.sec1", &attacker)).is_err(),
            "重名注册应当失败，攻击者不能抢占受害者的名字"
        );
        // 确认表里那条仍然属于受害者
        assert!(
            Arc::ptr_eq(&t.get("victim.sec1").unwrap().client, &victim),
            "记录必须仍归受害者"
        );
    }

    /// 断开清理只清自己的（这个函数一直都写对了，锁住防回退）。
    #[test]
    fn 断开只清自己的_visitor_记录() {
        let t = VisitorTable::default();
        let a = dummy_client("a");
        let b = dummy_client("b");
        t.register(entry("a.s", &a)).unwrap();
        t.register(entry("b.s", &b)).unwrap();

        t.unregister_client(&a);
        assert!(t.get("a.s").is_none(), "自己的应当被清掉");
        assert!(t.get("b.s").is_some(), "别人的不该被清掉");
    }
}
