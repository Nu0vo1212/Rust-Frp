//! 客户端侧的代理表：既装着配置里读出来的代理，也装着面板**动态下发**的代理。
//!
//! 以前它是个 `Arc<HashMap<..>>`，登录时建好就再也不变 —— 面板想加条隧道
//! 只能改配置文件重启。现在换成读写锁包着的活表：
//!
//! * `ServerCmd{op:"add_proxy"}` → [`ProxyTable::insert_dynamic`]，随后补发一条 `NewProxy`；
//! * `ServerCmd{op:"remove_proxy"}` → [`ProxyTable::remove_dynamic`]。
//!
//! 表里只存**原始名**（配置里的 `name`，不带 `{user}.` 前缀），
//! 线上全名的转换统一由 [`crate::util::strip_user_prefix`] 负责。
//!
//! 表里每条都带**来源标记** [`ProxyOrigin`]，
//! 远程下发只许操作 `Dynamic` 那批。详见这两个 enum 的注释。

use std::{
    collections::HashMap,
    sync::{Arc, RwLock},
};

use nfrp_common::config::ProxyConfig;

/// 一条代理的**来源**。
///
/// 为什么必须区分：配置文件的语义是"**本机用户**看着它写下的意图"，
/// 服务端不该有能力让它在运行期失效或被人顶掉。而在此之前
/// `ProxyTable` 把两类代理混在一张 `HashMap` 里、只按名字操作，
/// 于是有两条实弹证成的越权（`tmp/f2_remove_config_proxy.py` 等）：
///
/// * **F2**：面板下发 `remove_proxy("victim-ssh")` 能把用户**配置文件里**
///   那条隧道删掉（实测端口立刻连不上，客户端日志 `total=0`）；
/// * **F3**：一条**服务端自己判为失败**的同名 `add_proxy`（先覆盖、再因端口
///   冲突回滚删除）会把用户的配置代理**永久**打掉 —— 因为回滚是"按名字删"，
///   删掉的是它刚覆盖进去的那条，而**原配置永远不会被恢复**。
///
/// 修法就是给每条代理记来源，远程增删**只碰 `Dynamic`**：
/// 想覆盖/删除配置里的代理 ⇒ 明确拒绝并告诉调用方"请改本机配置文件"。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ProxyOrigin {
    /// 来自本机配置文件（含 `--gen-config` 写出来的那份）。
    Config,
    /// 来自服务端下发（面板"添加代理"）或 store 恢复。
    Dynamic,
}

/// 表里的一条记录。
#[derive(Clone)]
struct ProxyEntry {
    cfg: ProxyConfig,
    origin: ProxyOrigin,
}

/// 一份可变的代理表。`clone` 出来的是同一个表的另一个句柄，很便宜。
#[derive(Clone, Default)]
pub struct ProxyTable {
    inner: Arc<RwLock<HashMap<String, ProxyEntry>>>,
}

impl ProxyTable {
    /// 从配置构造：**全部标为 [`ProxyOrigin::Config`]**。
    pub fn from_iter<I: IntoIterator<Item = ProxyConfig>>(items: I) -> Self {
        let map = items
            .into_iter()
            .map(|p| {
                (
                    p.name.clone(),
                    ProxyEntry {
                        cfg: p,
                        origin: ProxyOrigin::Config,
                    },
                )
            })
            .collect::<HashMap<_, _>>();
        Self {
            inner: Arc::new(RwLock::new(map)),
        }
    }

    /// 把一批代理**并入**表并标为 [`ProxyOrigin::Dynamic`]（store 恢复用）。
    ///
    /// 已存在的同名条目不覆盖（配置优先，与 `store::merge_initial` 同口径）。
    pub fn load_dynamic<I: IntoIterator<Item = ProxyConfig>>(&self, items: I) {
        let mut g = match self.inner.write() {
            Ok(g) => g,
            Err(e) => e.into_inner(),
        };
        for p in items {
            g.entry(p.name.clone()).or_insert(ProxyEntry {
                cfg: p,
                origin: ProxyOrigin::Dynamic,
            });
        }
    }

    /// 按**原始名**查一条代理。
    pub fn get(&self, name: &str) -> Option<Arc<ProxyConfig>> {
        self.read().get(name).map(|e| Arc::new(e.cfg.clone()))
    }

    /// 这条代理的来源（不存在时 `None`）。
    pub fn origin_of(&self, name: &str) -> Option<ProxyOrigin> {
        self.read().get(name).map(|e| e.origin)
    }

    /// 拿读锁；锁被写脏时**照用不误**。
    ///
    /// 锁被 poison 只说明"曾经有线程持着它 panic 了"，不代表表里的数据坏了。
    /// 这里要是像 `lock().unwrap()` 那样跟着 panic，一个不相干的线程崩溃
    /// 就会让整个客户端的代理表再也读不出来。
    fn read(&self) -> std::sync::RwLockReadGuard<'_, HashMap<String, ProxyEntry>> {
        self.inner.read().unwrap_or_else(|e| e.into_inner())
    }

    /// 所有代理名（原始名），顺序不稳定 —— 只用于日志与诊断。
    pub fn names(&self) -> Vec<String> {
        self.read().keys().cloned().collect()
    }

    /// 表里全部代理的副本，**按名字排序**。
    ///
    /// 给 Web 界面用：面板上的列表必须顺序稳定，否则每 3 秒刷新一次，
    /// 行序就会跳来跳去（`HashMap` 的迭代顺序每次都不一样）。
    pub fn list(&self) -> Vec<ProxyConfig> {
        let mut v: Vec<ProxyConfig> = self.read().values().map(|e| e.cfg.clone()).collect();
        v.sort_by(|a, b| a.name.cmp(&b.name));
        v
    }

    /// **远程下发**的新增/覆盖（`ServerCmd{op:"add_proxy"}`）。
    ///
    /// 与 [`Self:insert`] 的区别：**拒绝覆盖配置文件里的代理**（F3 的修法）。
    ///
    /// 为什么必须拒绝而不是"悄悄覆盖"：服务端下发同名 `add_proxy` 时，
    /// 客户端先 `insert`（此刻用户那条就没了）→ 服务端再因端口冲突回滚
    /// 并下发 `remove_proxy` → 按名字删掉的是刚塞进去的那条 ⇒
    /// **用户的配置永远不会被恢复**。一条"注定失败"的命令就能永久打掉用户隧道。
    pub fn insert_dynamic(&self, p: ProxyConfig) -> Result<Option<ProxyConfig>, String> {
        let mut g = match self.inner.write() {
            Ok(g) => g,
            Err(e) => e.into_inner(),
        };
        if let Some(existing) = g.get(&p.name) {
            if existing.origin == ProxyOrigin::Config {
                return Err(format!(
                    "代理 [{}] 来自本机配置文件，远程下发不能覆盖它；\
                     请在本机改配置文件（或换个名字）",
                    p.name
                ));
            }
        }
        Ok(g.insert(
            p.name.clone(),
            ProxyEntry {
                cfg: p,
                origin: ProxyOrigin::Dynamic,
            },
        )
        .map(|e| e.cfg))
    }

    /// **远程下发**的删除（`ServerCmd{op:"remove_proxy"}`）。
    ///
    /// **拒绝删除配置文件里的代理**（F2 的修法）。
    pub fn remove_dynamic(&self, name: &str) -> Result<Option<ProxyConfig>, String> {
        let mut g = match self.inner.write() {
            Ok(g) => g,
            Err(e) => e.into_inner(),
        };
        if let Some(existing) = g.get(name) {
            if existing.origin == ProxyOrigin::Config {
                return Err(format!(
                    "代理 [{name}] 来自本机配置文件，远程下发不能删除它；\
                     请在本机改配置文件"
                ));
            }
        }
        Ok(g.remove(name).map(|e| e.cfg))
    }

    /// 本机侧的无条件新增/覆盖（**只在测试与本机流程里用**）。
    ///
    /// 远程下发的路径必须走 [`Self::insert_dynamic`] —— 那个会拒绝覆盖配置代理。
    pub fn insert(&self, p: ProxyConfig) -> Option<ProxyConfig> {
        let mut g = match self.inner.write() {
            Ok(g) => g,
            Err(e) => e.into_inner(),
        };
        let origin = g
            .get(&p.name)
            .map(|e| e.origin)
            .unwrap_or(ProxyOrigin::Dynamic);
        g.insert(p.name.clone(), ProxyEntry { cfg: p, origin })
            .map(|e| e.cfg)
    }

    /// 本机侧的无条件删除（**只在测试与本机流程里用**）。
    ///
    /// 远程下发的路径必须走 [`Self::remove_dynamic`]。
    pub fn remove(&self, name: &str) -> Option<ProxyConfig> {
        let mut g = match self.inner.write() {
            Ok(g) => g,
            Err(e) => e.into_inner(),
        };
        g.remove(name).map(|e| e.cfg)
    }

    pub fn len(&self) -> usize {
        self.read().len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nfrp_common::config::ProxyConfig;

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

    // ------------------------------------------------------------------
    // /F3：远程下发不得动配置里的代理
    // ------------------------------------------------------------------

    /// 远程 `remove` 不能删配置文件里的代理。
    #[test]
    fn 远程删除不得动配置里的代理() {
        let t = ProxyTable::from_iter([p("victim-ssh")]);
        assert_eq!(t.origin_of("victim-ssh"), Some(ProxyOrigin::Config));

        let e = t
            .remove_dynamic("victim-ssh")
            .expect_err("删配置代理必须被拒");
        assert!(e.contains("配置文件"), "错误要说清原因：{e}");
        assert!(t.get("victim-ssh").is_some(), "被拒之后那条代理必须还在");
    }

    /// 远程 `add` 不能覆盖配置文件里的代理。
    ///
    /// 这正是"双杀"链条的第一环：覆盖成功之后，服务端一回滚就会把
    /// 用户那条永久删掉。只要这里拒绝，整条链就断了。
    #[test]
    fn 远程新增不得覆盖配置里的代理() {
        let mut cfg = p("my-web");
        cfg.remote_port = 18202;
        let t = ProxyTable::from_iter([cfg.clone()]);

        let mut evil = p("my-web");
        evil.local_addr = "127.0.0.1:9".into();
        let e = t.insert_dynamic(evil).expect_err("覆盖配置代理必须被拒");
        assert!(e.contains("配置文件"), "错误要说清原因：{e}");

        // 用户那条必须**原样**还在（端口没变）
        let got = t.get("my-web").expect("配置代理必须还在");
        assert_eq!(got.remote_port, 18202, "配置代理的端口不该被改掉");
    }

    /// 动态代理之间可以正常增删（别修得过头，把面板功能也堵了）。
    #[test]
    fn 动态代理之间照常增删() {
        let t = ProxyTable::from_iter([p("cfg-one")]);
        t.insert_dynamic(p("dyn-one")).expect("新增动态代理");
        assert_eq!(t.origin_of("dyn-one"), Some(ProxyOrigin::Dynamic));

        // 同名动态代理可以覆盖（面板重复点"添加"）
        t.insert_dynamic(p("dyn-one"))
            .expect("覆盖动态代理应当允许");

        // 删除动态代理也可以
        assert!(t.remove_dynamic("dyn-one").expect("删动态代理").is_some());
        assert!(t.get("dyn-one").is_none());

        // 配置那条始终没被动过
        assert!(t.get("cfg-one").is_some());
    }

    /// store 恢复进来的算动态（能被远程删），配置的算静态。
    #[test]
    fn store_恢复的代理算动态() {
        let t = ProxyTable::from_iter([p("from-config")]);
        t.load_dynamic([p("from-store")]);

        assert_eq!(t.origin_of("from-config"), Some(ProxyOrigin::Config));
        assert_eq!(t.origin_of("from-store"), Some(ProxyOrigin::Dynamic));
        // 动态的可以远程删
        assert!(t.remove_dynamic("from-store").expect("应可删").is_some());
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
