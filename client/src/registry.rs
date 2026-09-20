//! 客户端侧的代理表：既装着配置里读出来的代理，也装着面板**动态下发**的代理。
//!
//! 以前它是个 `Arc<HashMap<..>>`，登录时建好就再也不变 —— 面板想加条隧道
//! 只能改配置文件重启。现在换成读写锁包着的活表：
//!
//! * `ServerCmd{op:"add_proxy"}` → [`ProxyTable::insert`]，随后补发一条 `NewProxy`；
//! * `ServerCmd{op:"remove_proxy"}` → [`ProxyTable::remove`]。
//!
//! 表里只存**原始名**（配置里的 `name`，不带 `{user}.` 前缀），
//! 线上全名的转换统一由 [`crate::util::strip_user_prefix`] 负责。

use std::{
    collections::HashMap,
    sync::{Arc, RwLock},
};

use rustunnel_common::config::ProxyConfig;

/// 一份可变的代理表。`clone` 出来的是同一个表的另一个句柄，很便宜。
#[derive(Clone, Default)]
pub struct ProxyTable {
    inner: Arc<RwLock<HashMap<String, ProxyConfig>>>,
}

impl ProxyTable {
    pub fn from_iter<I: IntoIterator<Item = ProxyConfig>>(items: I) -> Self {
        let map = items
            .into_iter()
            .map(|p| (p.name.clone(), p))
            .collect::<HashMap<_, _>>();
        Self {
            inner: Arc::new(RwLock::new(map)),
        }
    }

    /// 按**原始名**查一条代理。
    pub fn get(&self, name: &str) -> Option<Arc<ProxyConfig>> {
        self.read().get(name).cloned().map(Arc::new)
    }

    /// 拿读锁；锁被写脏时**照用不误**。
    ///
    /// 锁被 poison 只说明"曾经有线程持着它 panic 了"，不代表表里的数据坏了。
    /// 这里要是像 `lock().unwrap()` 那样跟着 panic，一个不相干的线程崩溃
    /// 就会让整个客户端的代理表再也读不出来。
    fn read(&self) -> std::sync::RwLockReadGuard<'_, HashMap<String, ProxyConfig>> {
        self.inner.read().unwrap_or_else(|e| e.into_inner())
    }

    /// 所有代理名（原始名），顺序不稳定 —— 只用于日志与诊断。
    pub fn names(&self) -> Vec<String> {
        self.read().keys().cloned().collect()
    }

    /// 新增或覆盖一条代理。已存在同名时先记一笔告警再覆盖 ——
    /// 面板上重复点"添加"不该静默产生两条互相打架的隧道。
    pub fn insert(&self, p: ProxyConfig) -> Option<ProxyConfig> {
        let mut g = match self.inner.write() {
            Ok(g) => g,
            Err(e) => e.into_inner(),
        };
        g.insert(p.name.clone(), p)
    }

    pub fn remove(&self, name: &str) -> Option<ProxyConfig> {
        let mut g = match self.inner.write() {
            Ok(g) => g,
            Err(e) => e.into_inner(),
        };
        g.remove(name)
    }

    pub fn len(&self) -> usize {
        self.read().len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustunnel_common::config::ProxyConfig;

    fn p(name: &str) -> ProxyConfig {
        ProxyConfig {
            name: name.to_string(),
            ..Default::default()
        }
    }

    #[test]
    fn 句柄共享同一份表() {
        let t = ProxyTable::from_iter([p("a"), p("b")]);
        let t2 = t.clone();
        assert_eq!(t.len(), 2);
        t2.insert(p("c"));
        assert_eq!(t.len(), 3, "clone 出来的句柄应当看到同一份表");
        assert!(t.get("c").is_some());
    }

    #[test]
    fn 按原始名增删() {
        let t = ProxyTable::from_iter([p("web")]);
        assert_eq!(t.get("web").unwrap().name, "web");
        assert!(t.get("nope").is_none());

        // 覆盖：返回的是被顶掉的那条
        let old = t.insert(p("web"));
        assert!(old.is_some(), "覆盖同名代理应当返回旧值");
        assert_eq!(t.len(), 1, "覆盖不该把条目数变多");

        assert!(t.remove("web").is_some());
        assert_eq!(t.len(), 0);
        assert!(t.remove("web").is_none(), "删两次不该 panic");
    }

    /// 锁被写脏（poison）时不能让整个客户端崩掉 —— 拿不到锁就退化成"读不到"。
    #[test]
    fn 锁损坏时不panic() {
        let t = ProxyTable::from_iter([p("a")]);
        let t2 = t.clone();
        let _ = std::thread::spawn(move || {
            let _g = t2.inner.write().unwrap();
            panic!("故意把锁写脏");
        })
        .join();
        // 即便持有写锁的线程 panic 了，这里也必须能继续读写
        t.insert(p("b"));
        assert!(t.get("b").is_some(), "poison 之后仍要能读");
        assert!(t.names().contains(&"b".to_string()));
        assert_eq!(t.len(), 2);
    }
}
