//! 动态代理的落盘（`[store]`）。
//!
//! # 解决什么问题
//!
//! 面板上点"添加代理"加出来的隧道**只活在内存里**：客户端一重启就没了。
//! 而这类隧道往往是用户临时开给别人用的，不一定记得回来补进配置文件。
//! 配了 `[store] path` 之后它们会落盘，重启自动恢复。
//!
//! # 只存"动态"的那些
//!
//! 这是本模块最关键的一条约定：落盘文件里**只放面板/API 加进来的代理**，
//! 配置文件中写的代理一个都不进去。
//!
//! 反过来（把整张表都写进去）看着更简单，但会立刻出问题：
//! 用户从配置文件里删掉一条隧道 → 重启后它又从 store 里复活了，
//! 而且用户翻遍配置文件也找不到它在哪。配置文件必须始终是"我写了什么"的
//! 唯一真相，store 只是补上动态那部分的记忆。
//!
//! # 文件格式
//!
//! ```json
//! { "version": 1, "proxies": [ { "name": "x", "type": "tcp", ... } ] }
//! ```
//!
//! `version` 是**给自己留的后路**：将来格式要变，能识别出旧文件并给出可读的
//! 提示，而不是让 `serde` 抛一句"missing field"。另外官方 frp 的 store 是
//! Go 的 `configmgmt` 序列化格式，与这里**不通用** —— 换实现时得重新加一遍，
//! README 里写明了。

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use anyhow::{Context, Result};
use rustunnel_common::config::{ClientConfig, ProxyConfig};
use serde::{Deserialize, Serialize};
use tracing::{debug, info, warn};

/// 落盘文件的当前版本号。
const STORE_VERSION: u32 = 1;

/// 落盘文件的结构。
#[derive(Debug, Serialize, Deserialize)]
struct StoreFile {
    /// 格式版本。缺省按 1 处理（老文件没有这个字段也能读）。
    #[serde(default = "default_version")]
    version: u32,
    #[serde(default)]
    proxies: Vec<ProxyConfig>,
}

fn default_version() -> u32 {
    1
}

/// 动态代理的持久化。
pub struct Store {
    /// 落盘路径。`None` = 不持久化（默认，与老版本完全一致）。
    path: Option<PathBuf>,
    /// 用 `BTreeMap` 而不是 `Vec`：文件里的顺序稳定，diff 好看，
    /// 测试也不用担心"顺序对不对"这种噪声。
    dynamic: Mutex<BTreeMap<String, ProxyConfig>>,
}

impl Store {
    /// 从配置构造，并把已有文件读进来。
    ///
    /// 读失败**不拦启动**：文件损坏或者格式不对时，最合理的做法是带着
    /// 一条响亮的告警继续跑（配置里的代理照常工作），而不是让整个客户端
    /// 起不来 —— 用户此刻可能正在外面用手机远程重启它。
    /// 但文件**不会**被立刻覆盖：只有下一次真的增删代理时才会重写。
    pub fn from_config(cfg: &ClientConfig) -> Result<Self> {
        let path = cfg.store.path.trim();
        if path.is_empty() {
            return Ok(Self {
                path: None,
                dynamic: Mutex::new(BTreeMap::new()),
            });
        }
        let path = PathBuf::from(path);
        let mut dynamic = BTreeMap::new();

        if path.exists() {
            match std::fs::read_to_string(&path) {
                Ok(raw) => match serde_json::from_str::<StoreFile>(&raw) {
                    Ok(f) => {
                        if f.version > STORE_VERSION {
                            warn!(
                                path = %path.display(),
                                file_version = f.version,
                                supported = STORE_VERSION,
                                "store 文件的版本比本程序新，已忽略其内容（不会覆盖它）"
                            );
                        } else {
                            for p in f.proxies {
                                if p.name.is_empty() {
                                    continue;
                                }
                                dynamic.insert(p.name.clone(), p);
                            }
                        }
                    }
                    Err(e) => warn!(
                        path = %path.display(),
                        error = %e,
                        "store 文件解析失败，已忽略（下次增删代理时会用新内容覆盖）"
                    ),
                },
                Err(e) => warn!(path = %path.display(), error = %e, "读取 store 文件失败，已忽略"),
            }
        }

        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() && !parent.exists() {
                std::fs::create_dir_all(parent)
                    .with_context(|| format!("创建 store 目录 {} 失败", parent.display()))?;
            }
        }

        info!(
            path = %path.display(),
            restored = dynamic.len(),
            "客户端 Store 已启用：动态添加的代理会落盘并在重启后恢复"
        );

        Ok(Self {
            path: Some(path),
            dynamic: Mutex::new(dynamic),
        })
    }

    pub fn is_enabled(&self) -> bool {
        self.path.is_some()
    }

    pub fn path(&self) -> Option<&Path> {
        self.path.as_deref()
    }

    /// 文件里记着的动态代理（启动时并入代理表）。
    pub fn dynamic(&self) -> Vec<ProxyConfig> {
        self.lock().values().cloned().collect()
    }

    pub fn dynamic_names(&self) -> Vec<String> {
        self.lock().keys().cloned().collect()
    }

    /// 记下（或更新）一条动态代理并落盘。
    pub fn put(&self, p: &ProxyConfig) -> Result<()> {
        if self.path.is_none() {
            return Ok(());
        }
        self.lock().insert(p.name.clone(), p.clone());
        self.flush()
    }

    /// 忘掉一条动态代理并落盘。返回它原本是否在文件里。
    pub fn remove(&self, name: &str) -> Result<bool> {
        if self.path.is_none() {
            return Ok(false);
        }
        let existed = self.lock().remove(name).is_some();
        if existed {
            self.flush()?;
        }
        Ok(existed)
    }

    /// 原子写：先写 `<path>.tmp` 再 rename。
    ///
    /// 直接往目标文件里写，一旦在写一半时进程被 kill / 磁盘满，
    /// 留下的是**半截 JSON** —— 下次启动就解析失败，所有动态隧道一起丢。
    /// rename 在同一文件系统内是原子的，最坏情况只是丢掉这一次改动。
    fn flush(&self) -> Result<()> {
        let Some(path) = self.path.as_ref() else {
            return Ok(());
        };
        let file = StoreFile {
            version: STORE_VERSION,
            proxies: self.lock().values().cloned().collect(),
        };
        let body = serde_json::to_vec_pretty(&file).context("序列化 store 失败")?;

        let tmp = path.with_extension("tmp");
        std::fs::write(&tmp, &body)
            .with_context(|| format!("写临时文件 {} 失败", tmp.display()))?;
        std::fs::rename(&tmp, path)
            .with_context(|| format!("把 {} 改名为 {} 失败", tmp.display(), path.display()))?;
        debug!(path = %path.display(), count = file.proxies.len(), "store 已落盘");
        Ok(())
    }

    /// 锁被 poison 时照用不误：那说明"曾有人持锁 panic 了"，
    /// 不代表这份数据坏了 —— 跟着 panic 只会让动态代理全部失效。
    fn lock(&self) -> std::sync::MutexGuard<'_, BTreeMap<String, ProxyConfig>> {
        self.dynamic.lock().unwrap_or_else(|e| e.into_inner())
    }
}

impl std::fmt::Debug for Store {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Store")
            .field("path", &self.path)
            .field("dynamic", &self.dynamic_names())
            .finish()
    }
}

/// 把配置里的代理与 store 里的动态代理并成一张初始表。
///
/// **配置文件优先**：同名时以配置文件为准，并告警。
/// 理由是配置文件是用户"我看着它写下的"那份东西，必须说话算数；
/// 而且从配置文件里删掉一条隧道时，用户期待的是它真的消失
/// （如果让 store 优先，它会被 store 里的旧副本复活，且无处可查）。
pub fn merge_initial(config: &[ProxyConfig], stored: Vec<ProxyConfig>) -> Vec<ProxyConfig> {
    let mut out: Vec<ProxyConfig> = config.to_vec();
    let mut seen: std::collections::HashSet<String> =
        config.iter().map(|p| p.name.clone()).collect();
    for p in stored {
        if seen.contains(&p.name) {
            warn!(
                proxy = %p.name,
                "store 里的动态代理与配置文件同名，按配置文件为准（store 里那条已忽略）"
            );
            continue;
        }
        seen.insert(p.name.clone());
        out.push(p);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg_with_path(path: &Path) -> ClientConfig {
        let mut c = ClientConfig::default();
        c.store.path = path.to_string_lossy().to_string();
        c
    }

    fn proxy(name: &str) -> ProxyConfig {
        ProxyConfig {
            name: name.into(),
            proxy_type: "tcp".into(),
            local_addr: "127.0.0.1:80".into(),
            remote_port: 6000,
            ..Default::default()
        }
    }

    #[test]
    fn 默认不落盘() {
        let c = ClientConfig::default();
        let s = Store::from_config(&c).unwrap();
        assert!(!s.is_enabled());
        assert!(s.path().is_none());
        // 关着的时候增删都是空操作，也不该建任何文件
        s.put(&proxy("a")).unwrap();
        assert!(s.dynamic().is_empty());
    }

    #[test]
    fn 落盘并能在新进程里读回() {
        let dir = std::env::temp_dir().join(format!("rustunnel-store-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let path = dir.join("store.json");
        let c = cfg_with_path(&path);

        {
            let s = Store::from_config(&c).unwrap();
            assert!(s.is_enabled());
            s.put(&proxy("panel-web")).unwrap();
            s.put(&proxy("panel-db")).unwrap();
            assert_eq!(s.dynamic_names(), vec!["panel-db", "panel-web"]);
        }

        // 模拟重启：重新打开同一个路径
        let s2 = Store::from_config(&c).unwrap();
        let names = s2.dynamic_names();
        assert_eq!(names, vec!["panel-db", "panel-web"], "重启后必须能读回");

        // 删掉一条也要落盘
        assert!(s2.remove("panel-web").unwrap());
        let s3 = Store::from_config(&c).unwrap();
        assert_eq!(s3.dynamic_names(), vec!["panel-db"]);
        assert!(!s3.remove("panel-web").unwrap(), "重复删除返回 false");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn 文件损坏不拦启动() {
        let dir = std::env::temp_dir().join(format!("rustunnel-store-bad-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("store.json");
        std::fs::write(&path, "{ 这不是 JSON").unwrap();

        let c = cfg_with_path(&path);
        let s = Store::from_config(&c).expect("损坏的 store 不该拦住启动");
        assert!(s.dynamic().is_empty());
        // 而且**不能**因为读失败就把它覆盖掉 —— 用户可能还想去手工抢救
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "{ 这不是 JSON");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn 目录不存在会自动创建() {
        let dir = std::env::temp_dir().join(format!("rustunnel-store-mk-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let path = dir.join("deep").join("store.json");
        let c = cfg_with_path(&path);
        let s = Store::from_config(&c).unwrap();
        s.put(&proxy("a")).unwrap();
        assert!(path.exists(), "嵌套目录也要能自动建出来");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn 配置文件优先于_store() {
        let merged = merge_initial(
            &[proxy("web"), proxy("ssh")],
            vec![proxy("web"), proxy("tmp")],
        );
        let names: Vec<String> = merged.iter().map(|p| p.name.clone()).collect();
        assert_eq!(names, vec!["web", "ssh", "tmp"]);
        // web 只出现一次，且来自配置文件
        assert_eq!(merged.iter().filter(|p| p.name == "web").count(), 1);
    }
}
