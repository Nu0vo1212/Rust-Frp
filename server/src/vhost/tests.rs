//! 跨模块测试：`[acl]` 必须铺满**全部**接收外部连接的 server 文件。
//!
//! 职责：用源码扫描守住「新增一条数据面入口就忘加 `check_ip`」这一族缺陷；
//! 判据落在**代码行**上（排除注释），而不是「文本里出现过这个词」。
//!
//! 锁顺序契约：本模块不涉及运行期加锁，只在编译产物里做纯文本检查。
//!
//! 不变量：清单 `MUST_HAVE_ACL` 覆盖所有接收外部连接的 server 文件；
//! 每个文件在**测试模块之前**的生产代码里都必须真的调用 `check_ip`。
//! 拆分后 vhost 的 accept 分支位于 `vhost/listen.rs`，清单跟随实现位置。

// -----------------------------------------------------------------------
// -0/E9-1/E9-2：ACL 必须铺满**全部**数据面入口
// -----------------------------------------------------------------------

/// **`[acl]` 必须铺满所有数据面入口。**
///
/// 判据：源码里有一行**真的在调用** `check_ip`（排除注释行）。
///
/// 为什么要排除注释：
///   本测试第一版只做 `prod.contains("check_ip")` —— 于是**把调用注释掉**
///   （`// [退回验证] sec.check_ip(...)`）测试**仍然通过**，
///   因为字符串还在文件里。退回验证因此 **0/3**，一个都没守住。
///   ⇒ 判据必须落在"**代码行**"上，而不是"文本里出现过这个词"。
fn has_real_check_ip(src: &str) -> bool {
    src.lines().any(|line| {
        let code = match line.find("//") {
            Some(i) => &line[..i],
            None => line,
        };
        code.contains("check_ip")
    })
}
///
/// # 这三条是一起发现的
///
/// 里 `SecurityContext:check_ip` 只有 **4 处**调用
/// （控制面 / TCP 代理 / vhost / VNet），而下面三条路径**一处都没有**：
///
/// | 路径 | 文件 | 定级 |
/// |---|---|---|
/// | **UDP 代理端口** | `udp_proxy.rs` | **中危**（无其它防线） |
/// | **xtcp 牵线 UDP** | `p2p.rs` | 低危（B-1 来源绑定间接生效） |
/// | **管理面板** | `dashboard.rs` | 低危（有 Basic Auth） |
///
/// 实测（`tmp/audit9/_indep/`）：
/// * `verify_udp_acl.py`：ACL deny 的源仍能把 UDP 包送进内网服务（包数 1→2）
/// * `verify_p2p_acl.py`：被 deny 的源发出的 HELLO 被服务端照收
/// * `verify_dashboard_acl.py`：正确凭据仍能拿到 200
///
/// # 这条测试为什么用**源码扫描**而不是功能测试
///
/// 功能测试只能覆盖"我已经想到的那几条路径"。而这一族缺陷的本质是
/// 「**新增了一条路径，忘了加 ACL**」—— 只有**枚举文件**才能防住它。
///
/// ⇒ 它守的是一个"清单不变量"：**每个接收外部连接的 server 文件里，
/// 都必须出现 `check_ip`**。将来若新增数据面文件而忘了加 ACL，
/// 这条测试会**直接变红**（把文件加进 `MUST_HAVE_ACL` 或给它加 check_ip）。
///
/// 这正是项目那个连续多轮的模式（"防线没铺满"）的**治本方向**：
///   让"漏掉"变得不可能，而不是靠每次审计去数。
#[test]
fn acl_必须铺满全部数据面入口() {
    use std::path::PathBuf;

    // server/src 下所有**接收外部连接**的文件 —— 每一个都必须有 check_ip。
    const MUST_HAVE_ACL: &[&str] = &[
        "serve/conn.rs",     // 控制端口 / frp 握手 ACL
        "serve/register.rs", // TCP / UDP 代理 accept ACL
        "vhost/listen.rs",   // HTTP / HTTPS / tcpmux accept
        "vnet.rs",           // VirtualNet 注册
        "udp_proxy.rs",      // ★ E9-0：UDP 代理端口
        "p2p.rs",            // ★ E9-1：xtcp 牵线 UDP
        "dashboard.rs",      // ★ E9-2：管理面板
    ];

    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut missing = Vec::new();
    for f in MUST_HAVE_ACL {
        let path = dir.join(f);
        let text =
            std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("读不到 {path:?}：{e}"));
        // 只认生产代码：排除掉**测试模块**部分。
        //
        // 不能用"第一个 `#[cfg(test)]`"分界 —— 有的文件在中部就有
        //   `#[cfg(test)] pub(crate) fn len()` 之类的小 helper，
        //   按它切会把**后面的生产代码一起切掉**（本测试第一版就因此误报）。
        //   正确做法：找**最后一个** `mod tests {` 的起点。
        let prod = match text.rfind("mod tests") {
            Some(i) => &text[..i],
            None => &text[..],
        };
        if !has_real_check_ip(prod) {
            missing.push(*f);
        }
    }

    assert!(
        missing.is_empty(),
        "★ 这些文件接收外部连接却**没有** `check_ip`：{:?}\n\
         `[acl]` 的语义是『谁能连上来』（见 security.rs 模块文档），\
         它必须覆盖**所有**数据面入口。\n\
         第九轮实测：UDP 代理端口 / xtcp 牵线 / 管理面板 三条都漏了 —— \
         这正是『防线没铺满』模式的又一次出现。",
        missing
    );
}
