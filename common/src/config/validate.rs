//! 配置与代理校验。
//!
//! 职责：代理/访客类型与插件自检、`annotations` 与 tcpmux 校验，以及远程下发代理的 `local_addr` 回环白名单（`validate_remote_proxy`）。
//! 并发/所有权契约：纯校验函数，无锁、无共享可变状态；只读配置，不做 I/O、不修改任何全局状态。
//! 不变量：类型/插件判定的唯一真源在 `parse` 模块（`SUPPORTED_*` / `plugin_type_supported`），本模块只消费。

use crate::error::Result;

use super::client::ClientConfig;
use super::parse::{
    plugin_key, plugin_type_supported, unimplemented_plugin_types, SUPPORTED_PLUGIN_TYPES,
    SUPPORTED_PROXY_TYPES, SUPPORTED_VISITOR_TYPES,
};
use super::proxy::ProxyConfig;

/// 单条代理的**解码类**自检：类型 + 插件。
///
/// "解码类" = 官方在 JSON 解码阶段就会报错的项（`pkg/config/v1/decode.go` 的
/// `unknown proxy type` / `unknown plugin type`）。因此它在 [`parse_client`] 里
/// 必须跑在 `enabled = false` **过滤之前** —— 官方同样如此：解码先于
/// `FilterClientConfigurers`，`enabled = false` 不能把未知类型变成合法。
fn reject_decoded_proxy(p: &ProxyConfig) -> Result<()> {
    if !SUPPORTED_PROXY_TYPES.contains(&p.proxy_type.as_str()) {
        return Err(crate::error::Error::Protocol(format!(
            "代理 [{}] 的类型 {:?} 不受支持（NFrp 实现了 {}）",
            p.name,
            p.proxy_type,
            SUPPORTED_PROXY_TYPES.join(" / ")
        )));
    }
    reject_unimplemented_plugin(p)
}

/// 单条代理的**结构化**校验：tcpmux 约束 + 注解。
///
/// 与 [`reject_decoded_proxy`] 分开是因为二者在官方流程里的**时机不同**：
/// 解码检查在 enabled 过滤**前**，结构化校验（`ValidateClientConfig` 一族）
/// 在过滤**后** —— 所以"禁用但暂时不完整"的配置块不该被这两项拦住。
/// 见 [`parse_client`] 里的执行顺序。
pub(super) fn reject_structured_proxy(p: &ProxyConfig) -> Result<()> {
    reject_bad_tcpmux(p)?;
    reject_bad_annotations(p)
}

/// 单条代理的完整自检（类型 + 插件 + tcpmux + 注解），远程下发路径共用。
fn reject_bad_proxy(p: &ProxyConfig) -> Result<()> {
    reject_decoded_proxy(p)?;
    reject_structured_proxy(p)
}

/// 解析路径的**解码类**检查（未知代理 / 访客 / 插件类型）。
pub(super) fn reject_unimplemented_types(cfg: &ClientConfig) -> Result<()> {
    for p in &cfg.proxies {
        reject_decoded_proxy(p)?;
    }
    for v in &cfg.visitors {
        if !SUPPORTED_VISITOR_TYPES.contains(&v.visitor_type.as_str()) {
            return Err(crate::error::Error::Protocol(format!(
                "访客 [{}] 的类型 {:?} 不受支持（NFrp 实现了 {}）",
                v.name,
                v.visitor_type,
                SUPPORTED_VISITOR_TYPES.join(" / ")
            )));
        }
    }
    Ok(())
}

/// 单条代理的插件类型自检。
///
/// # 为什么必须在**解析阶段**就报错
///
/// 插件类型的匹配原先只发生在**客户端** `plugin::Plugin::from_proxy` —— 那是
/// **每条工作连接**到来时才走的路径。于是 `frpc verify` 对着一份
/// `plugin.type = "tls2raw"` 的配置会回**「配置校验通过」**，用户拿着这个绿灯去上线，
/// 全量连接才逐个失败。绿灯是假的，比红灯危险得多。
///
/// 官方 frp 对未知插件类型是在**解码阶段**直接 `unknown plugin type: %s`
/// （`pkg/config/v1/decode.go:115`）—— 这里对齐它的时机。
fn reject_unimplemented_plugin(p: &ProxyConfig) -> Result<()> {
    let kind = p.plugin.trim();
    if kind.is_empty() {
        return Ok(());
    }
    if plugin_type_supported(kind) {
        return Ok(());
    }
    let missing = unimplemented_plugin_types();
    // 分两种情况说清楚，别让用户拿"支持的清单"去猜自己是拼错了还是官方有而这里没有。
    if missing.iter().any(|t| plugin_key(t) == plugin_key(kind)) {
        return Err(crate::error::Error::Protocol(format!(
            "代理 [{}] 的插件 {:?} 是官方 frp 有、但 NFrp **尚未实现**的插件 —— \
             现在放行只会让每条连接在运行期逐个失败，所以在这里直接拒绝。\n\
             官方有而 NFrp 没有的插件：{}",
            p.name,
            kind,
            missing.join(" / ")
        )));
    }
    Err(crate::error::Error::Protocol(format!(
        "代理 [{}] 的插件 {:?} 不认识（NFrp 实现了 {}）",
        p.name,
        kind,
        SUPPORTED_PLUGIN_TYPES.join(" / ")
    )))
}

/// 校验**远程下发**的代理配置（`ServerCmd` / 客户端 Web API 两条入口共用）。
///
/// # 为什么必须有这个函数
///
/// 走**配置文件**的代理要过三道关（[`reject_unimplemented_types`] /
/// [`reject_unimplemented_plugin`] / [`reject_bad_tcpmux`]），但走
/// **服务端 `ServerCmd`** 和**客户端本地 Web API** 的代理**一道都不过** ——
/// 那两条路径原先只检查 `name` / `type` 非空。
///
/// 后果不是理论上的：`ProxyConfig` 里混着两类字段 ——
///
/// * **代理语义字段**（`name` / `type` / `remote_port` / `custom_domains`…），
///   服务端下发了没问题，这正是"面板增删代理"功能要的；
/// * **本机资源字段**（`plugin_local_path` / `plugin_local_addr` /
///   `plugin_crt_path` / `plugin_key_path`），**只有本机用户才有资格决定**。
///
/// 服务端能把第二类一起下发，就等于让它指定客户端**读哪个文件**、
/// **连哪个内网地址**（`plugin = "static_file"` + `local_path = "/etc"` 配
/// 一个公网域名，就是可读的任意文件服务；`plugin_local_addr` 则是内网 SSRF）。
///
/// 所以这里的策略是：**远程来源一律不许携带任何本机资源字段**，
/// 且代理类型 / 插件类型 / tcpmux 约束仍要照常过。
///
/// # 参数
///
/// `is_remote` 为 `true` 时启用"禁止本机资源字段"这条。配置文件路径传
/// `false`（它本来就走完整校验，这里只是复用类型检查）。
pub fn validate_remote_proxy(p: &ProxyConfig, is_remote: bool) -> Result<()> {
    if is_remote {
        // 一条代理里只要沾了本机资源字段就整条拒绝 —— 不做"悄悄丢弃该字段"，
        // 那样服务端以为自己下发成功了，用户却拿到一条行为不同的代理。
        let mut offending: Vec<&str> = Vec::new();
        if !p.plugin_local_path.trim().is_empty() {
            offending.push("pluginLocalPath");
        }
        if !p.plugin_local_addr.trim().is_empty() {
            offending.push("pluginLocalAddr");
        }
        if !p.plugin_crt_path.trim().is_empty() {
            offending.push("pluginCrtPath");
        }
        if !p.plugin_key_path.trim().is_empty() {
            offending.push("pluginKeyPath");
        }
        if !offending.is_empty() {
            return Err(crate::error::Error::Protocol(format!(
                "代理 [{}] 来自远程下发，不允许携带本机资源字段（{}）—— \
                 这些字段决定读哪个文件、连哪个内网地址，只能由本机配置文件指定。",
                p.name,
                offending.join(" / ")
            )));
        }

        // `local_addr` 必须**只允许回环**。
        //
        // 为什么这是必需的：`local_addr` 决定客户端**往哪里连**
        // （`client/src/main.rs` 里每个工作连接都会 `TcpStream::connect(local)`）。
        // 它原先**不在**上面那份黑名单里，于是一个不可信的服务端
        // （或能下发 `ServerCmd` 的面板）只要下发
        // `local_addr = "169.254.169.254:80"`，就能让客户端去连**云元数据服务** ——
        // 这就是服务端可控的 SSRF。同理 `10.0.0.5:6379` 可做内网横向。
        //
        // 这里刻意**反过来用允许清单**（默认拒绝），而不是继续往黑名单里加一条。
        // H3 与 H4 是同一类错误的两个实例：「防线写对了，但没铺满它声称要保护的
        //   字段/路径」。黑名单每漏一个字段就是一次漏洞；允许清单漏一个字段
        //   只是"少支持一个场景"。远程下发**本来就不该**决定客户端连哪里。
        //
        // 兼容性说明：远程下发通常来自面板的"添加代理"功能，而面板自己填的
        // `local_addr` 本来就是内网服务地址（`127.0.0.1:xxxx` 最常见）。
        // 真有跨机场景的，应当由本机配置文件写死，而不是让服务端远程指定。
        if !p.local_addr.trim().is_empty() {
            let host = local_addr_host(&p.local_addr);
            if !is_loopback_host(host) {
                return Err(crate::error::Error::Protocol(format!(
                    "代理 [{}] 来自远程下发，`local_addr` 只能指向本机回环地址，\
                     收到 {:?}（主机部分 {:?}）—— 远程下发不该决定客户端往哪里连。\
                     若确实需要连别的地址，请写在本机配置文件里。",
                    p.name, p.local_addr, host
                )));
            }
        }

        // **远程下发一律不允许携带插件**。
        //
        // 这是上面那条回环检查的**完整绕过**，而且是实测打出来的：
        //
        // * 上面的检查有个前提 —— `local_addr` 非空。而插件路径**根本不需要
        //   `local_addr`**：`local_addr=""` + `plugin="http_proxy"` 时，
        //   那段回环检查被 `if !p.local_addr.trim().is_empty()` 整个跳过；
        // * 黑名单只列了 4 个 `plugin_local_*` 字段，**`plugin` 这个能力开关
        //   本身没进判定**，`plugin_user` / `plugin_passwd` 也没管。
        //
        // 净效果：服务端（或任何能调面板 `/api/proxies/add` 的人）下发一条
        // `plugin="http_proxy"` / `"socks5"` 的代理，客户端就把那个公网端口
        // 变成**开放正向代理** —— 攻击者可现指定任意目标，既能内网横向，
        // 也能拿客户端当跳板隐藏来源（出站源 IP 是客户端）。
        //
        // 实测对照（`tmp/audit4-verify-F1b.py`，目标 192.168.3.15:17912）：
        //
        // | 下发形态 | 结果 | 可达 |
        // |---|---|---|
        // | 普通 tcp + `local_addr=192.168.3.15:17912` | HTTP 400 拒绝 | 不可达 |
        // | `plugin=http_proxy` + `local_addr=""` | HTTP 200 放行 | **读到数据** |
        // | `plugin=socks5` + `local_addr=""` | HTTP 200 放行 | **读到数据** |
        //
        // 为什么是"一律拒绝"而不是"只拒绝无鉴权的插件"：
        //   插件的正当用途是**本机用户自己**决定"这台机器要对外提供什么能力"
        //   （静态站点、SOCKS 代理、TLS 终结……）。这是**知情选择**，
        //   本机配置文件里照旧完全可用。但**服务端不该能远程改变客户端的性质**
        //   —— 这与 `local_addr` 是同一个理由，而且更强：`local_addr` 只是
        //   "连哪里"，`plugin` 是"变成什么"。
        //
        // 沿用 H4 的教训：**用允许清单，不继续扩黑名单**（黑名单必然漏下一个字段）。
        //
        // **补上 `plugin_request_headers`**。
        //
        // 上面这段注释写着"用允许清单、不继续扩黑名单"，但代码实际是一个
        // **5 字段枚举** —— 恰好漏了 `plugin_request_headers`
        // （一个 `BTreeMap<String,String>`，可注入任意请求头 + CRLF）。
        //
        // 与"注释声称用允许清单、实际是枚举"这个不符同时出现 ——
        //   审计报告把"注释与实现不符"列为**高效漏洞信号源**，这里正是一例。
        //
        // 可利用性：`http_relay.rs` 的 `strip_crlf` 对键和值都做了过滤
        //   （注释也点明了该字段远程可控），所以**不能注入 CRLF**；
        //   残余能力是"给内网服务加任意请求头"（如 `X-Forwarded-For` 伪造、
        // 绕过后端的 IP 白名单）。危害低于 F1，故定 Low —— 但它
        //   **仍然属于"服务端不该能远程改变客户端行为"**的同一类，
        //   且既然这段代码的意图是"一律拒绝插件相关字段"，漏一个就是漏。
        let mut caps: Vec<&str> = Vec::new();
        if !p.plugin.trim().is_empty() {
            caps.push("plugin");
        }
        if !p.plugin_user.trim().is_empty() {
            caps.push("pluginUser");
        }
        if !p.plugin_passwd.trim().is_empty() {
            caps.push("pluginPasswd");
        }
        if !p.plugin_host_header_rewrite.trim().is_empty() {
            caps.push("pluginHostHeaderRewrite");
        }
        if !p.plugin_strip_prefix.trim().is_empty() {
            caps.push("pluginStripPrefix");
        }
        // 这一项原先漏了
        if !p.plugin_request_headers.is_empty() {
            caps.push("pluginRequestHeaders");
        }
        if !caps.is_empty() {
            return Err(crate::error::Error::Protocol(format!(
                "代理 [{}] 来自远程下发，不允许携带插件相关字段（{}）—— \
                 插件决定客户端**变成什么**（本地文件服务 / 正向代理 / 私钥终结），\
                 只能由本机配置文件指定。远程下发要连内网服务，请用普通 tcp/http 代理。",
                p.name,
                caps.join(" / ")
            )));
        }

        // **非插件代理的
        //    `local_addr` 不能为空**。
        //
        // # 原先为什么是个"假绿灯"
        //
        // 上面那段回环检查有个前提 —— `if !p.local_addr.trim().is_empty()`。
        // 而 `ProxyConfig` 里**没有** `localIP` / `localPort` 字段
        // （只有合并式的 `local_addr`），所以两段式写法会被 serde **静默丢弃**。
        // ⇒ 下发 `{"local_addr":"", "localIP":"10.0.0.5", "localPort":80}`
        //   可以通过回环检查（因为 `local_addr` 是空串），
        //   面板回 **200「代理已生效」**、公网端口**真的被占上**、
        //   `/api/status` 里也显示"已生效"……
        //   **但 `local_addr` 为空 ⇒ 这条代理连不上任何地方，每条连接必然失败。**
        //
        // 实测（`tmp/audit7/e/localip_bypass_probe.py`）：
        // * `localIP`+`localPort`（**无** `local_addr`）⇒ 400「missing field local_addr」
        //   （serde 的 required 检查挡住了）
        // * **`local_addr:""` + `localIP`+`localPort`** ⇒ **200 已生效**，但代理不可用
        //
        // 而且我用**诱饵服务**做过决定性判定（`tmp/audit7/e/e71_verify_bypass.py`）：
        // 两段式字段确实被丢弃、**没有**真的去连 `10.0.0.5` ——
        // 所以这**不是 SSRF**，只是"**假绿灯**"：面板说成功，实际拿到的是一条
        // 必然失败的隧道。
        //
        // 与此前的 F-1「`--check` / `frpc verify` 假绿灯」是**同一族问题**，
        //   只是这次发生在**运行期**（面板写接口返回成功）而不是预检期。
        //
        // # 为什么现在才补
        //
        // 插件代理**不看** `local_addr`（工作连接交给插件），所以不能一刀切
        // —— 那会把正当的插件用法（虽然远程下发已禁插件，但本机配置仍需放行）
        // 一起拒掉。这里显式排除插件情形。
        if p.plugin.trim().is_empty() && p.local_addr.trim().is_empty() {
            return Err(crate::error::Error::Protocol(format!(
                "代理 [{}] 来自远程下发，但 `local_addr` 是空的 —— \
                 这条代理连不上任何地方，客户端会把它注册上去（面板显示「已生效」）\
                 然后每条连接都失败。请填上内网服务地址（如 `127.0.0.1:8080`）。\
                 ★ 注意字段名是**合并式**的 `local_addr`（`ip:port`）：\
                 官方的 `localIP` + `localPort` 两段式在**远程下发**里不被接受，\
                 写了也会被静默丢弃。",
                p.name
            )));
        }
    }
    reject_bad_proxy(p)
}

/// 从 `host:port` 里切出主机部分（兼容 `[::1]:80` 这种带方括号的 IPv6）。
///
/// 单独抽出来是因为 `rsplit_once(':')` 对 IPv6 是错的：
/// `[::1]:80` 会切成 `[:`，`::1` 会切成 `:`。项目里 `canonical_host`
/// 已经在处理同类问题，这里保持一致的口径。
pub(super) fn local_addr_host(addr: &str) -> &str {
    let a = addr.trim();
    if let Some(rest) = a.strip_prefix('[') {
        // **方括号必须紧跟着 port 冒号**，
        //    不能"取第一个 `]` 之前就算主机"。
        //
        // # 原先为什么错了（check-vs-use）
        //
        // 原先写的是 `rest.split(']').next()` —— 对 `[::1].evil.com:PORT`
        // 会取到 `::1`，于是：
        //   * **判据**看到 `::1` ⇒ `is_loopback_host` 为真 ⇒ **放行**；
        //   * **实际连接**（`client/src/main.rs:1472`）用的却是**原始串**
        //     `resolve_addr("[::1].evil.com:PORT")` ⇒ **走 DNS**。
        //
        // ⇒ 校验器看的是 A 串、实际连的是 B 串。域名一旦可解析，
        // 连到哪里就由**域名持有者**决定 —— 这正是 H4 要封的服务端可控 SSRF。
        //
        // # 实测（`tmp/audit7/e_independent/repro_e2_decisive.py`，7/7）
        //
        // 用 v6 诱饵 + 一个 DNS 查不到的名字做区分：
        //
        // | 下发值 | 判据 | 实际转发 |
        // |---|---|---|
        // | `[::1]:<P>` | 接受 | **成功**（收到 `V6-DECOY`）|
        // | **`[::1].nonexistent-….local:<P>`** | **接受** | **失败**（v6 命中 0）|
        //
        // 若连接用的也是切片后的 `::1`，第二条**必应成功** —— 差异即是铁证。
        // 客户端日志同时给出直接证据：
        // `解析内网地址 [::1].nonexistent-nfrp-e2-probe.local:50458 失败`。
        //
        // # 修法
        //
        // **方括号形式必须整段就是 `[host]:port`**：`]` 之后只能是
        // 「空」或「:数字端口」。否则**不认这种写法**，整串当主机
        // ⇒ 解析不出 IP ⇒ `is_loopback_host` 从严判 `false` ⇒ 拒绝。
        //
        // 这样"判据看到的主机"与"连接用的主机"**强制一致**：
        // 要么整串被认作 `[host]:port`（那就连 host），要么整串当主机（那就拒）。
        let (host, after) = match rest.split_once(']') {
            Some(v) => v,
            // 有 `[` 没有 `]` ⇒ 不是合法的 `[host]:port` ⇒ 整串当主机（从严）
            None => return a,
        };
        let tail_ok = after.is_empty()
            || (after.starts_with(':')
                && after[1..].bytes().all(|b| b.is_ascii_digit())
                && !after[1..].is_empty());
        if tail_ok {
            return host;
        }
        // `]` 之后还有别的东西（如 `[::1].evil.com:80`）⇒ 不是回环写法，从严
        return a;
    }
    // 无方括号时的关键判断：冒号**只有一个**才可能是 `host:port`。
    //
    // 裸 IPv6（`::1`、`fd00::1`）有多个冒号，按 `rsplit_once(':')` 切会得到
    // `":"` 这种垃圾 —— 而那会让**合法的 `::1` 被误拒**（诊断时实测踩到）。
    // 所以先数冒号：多于一个就整串当主机。
    if a.matches(':').count() != 1 {
        return a;
    }
    match a.rsplit_once(':') {
        Some((h, port)) if !port.is_empty() && port.bytes().all(|b| b.is_ascii_digit()) => h,
        _ => a,
    }
}

/// 这个主机名/地址是不是"只有本机"。
///
/// 接受 `127.0.0.0/8`、`::1`。**不接受** `0.0.0.0`（那是"监听全部"，
/// 不是"连本机"），也不接受任何解析不出 IP 的名字 —— 名字解析到哪个地址
/// 取决于本机 hosts 与 DNS，而且解析结果在连接时才确定，判据不能靠它。
///
/// **不再无条件放行 `localhost`**。
///
/// # 原先为什么错了
///
/// 这个函数原先在 IP 解析**之前**无条件返回 true：
///
/// ```ignore
/// if h.eq_ignore_ascii_case("localhost") {
///     return true;          // ← 先于 IP 解析，无条件放行
/// }
/// ```
///
/// 而**同一个仓库**里 `common/src/util.rs:535` 的 `is_loopback_addr()`
/// 对 `localhost` 的结论**正好相反**，注释还写明了理由：
///
/// > `localhost` 也按**非回环**处理：它解析到哪个地址取决于本机 hosts 与 DNS，
/// > 解析到非回环地址时就是一个对外端口，**不能靠名字赌**。
///
/// ⇒ **同一语义、两套结论相反的实现**，而守卫**远程下发白名单**
/// （见本文件 `validate_remote_proxy` 里的 H4 检查）的是**弱的那套**。
///
/// # 实测后果（`tmp/audit7/e_independent/repro_e1_localhost.py`，9/9）
///
/// 在 `127.0.0.1:<P>` 与 `[::1]:<P>` 上各起一个 banner 诱饵（同端口号），
/// 再远程下发三种 `local_addr`：
///
/// | 下发值 | 面板响应 | 实际命中 |
/// |---|---|---|
/// | `127.0.0.1:<P>` | 200 接受 | **v4** 诱饵 ✓（正对照） |
/// | `10.0.0.5:<P>` | **400 拒绝** | —（H4 生效） |
/// | **`localhost:<P>`** | **200 接受** | **v4=0 / v6=1** ⇒ 命中了 **v6** 端点 |
///
/// ⇒ 用户配的是"连本机 v4 服务"，实际流量送到了**另一个地址族**的端点。
/// 这证明判据**放行了一个它无法保证指向的名字** —— 只要本机 hosts 或 DNS
/// 把 `localhost` 指到别处，流量就跟着去别处。这正是 H4 要封的
/// 「服务端可控 SSRF」：`local_addr` 决定客户端**往哪里连**。
///
/// # 修法
///
/// 与 `util.rs` 的口径**统一**：`localhost` 一律当作**非回环**（从严）。
/// 想连本机就写 `127.0.0.1` 或 `::1` —— 那是**明确的、不受 hosts/DNS 影响**的写法。
///
/// 兼容性：远程下发（面板"添加代理"）的正常用法本来就是填 `127.0.0.1:xxxx`；
///   写 `localhost` 的人需要改成 `127.0.0.1`。本机配置文件里的 `localhost`
///   **不受影响**（这条检查只作用于远程下发路径）。
pub(super) fn is_loopback_host(host: &str) -> bool {
    let h = host.trim();
    // `localhost` 从严处理 —— 解析结果不受控，不能靠名字赌。
    //   （原先这里无条件 return true，与 `util::is_loopback_addr` 的结论相反。）
    match h.parse::<std::net::IpAddr>() {
        Ok(std::net::IpAddr::V4(v4)) => v4.is_loopback(),
        Ok(std::net::IpAddr::V6(v6)) => v6.is_loopback(),
        // 解析不出（域名，含 `localhost`）⇒ 从严当作"非本机"
        Err(_) => false,
    }
}

/// `annotations` 校验，对齐官方 `ValidateAnnotations`（`pkg/config/v1/validation/proxy.go:243`）。
///
/// 规则（与官方逐条对应）：
/// 1. 键先**整体转小写**再校验（官方 `validation.IsQualifiedName(strings.ToLower(k))`），
///    所以键里写大写字母不会报错；
/// 2. 键是 Kubernetes 风格的 qualified name：`[前缀/]名字` —— 前缀（可选）是
///    ≤253 字符的 DNS 子域，名字 ≤63 字符、以字母数字开头结尾、中间可含 `- _ .`；
///    多于一个 `/` 不合法；
/// 3. 全部键值对的**总字节数**（键 + 值）不超过 256 KiB（官方
///    `TotalAnnotationSizeLimitB = 256 * (1 << 10)`）。
///
/// 官方 frps 对随 `NewProxy` 收到的注解只存不查（`server/` 下没有任何读取点，
/// 0.71 实测），所以只需要管客户端侧这一遍。
fn reject_bad_annotations(p: &ProxyConfig) -> Result<()> {
    if p.annotations.is_empty() {
        return Ok(());
    }
    let mut total: usize = 0;
    for (k, v) in &p.annotations {
        total = total.saturating_add(k.len()).saturating_add(v.len());
        if let Some(reason) = annotation_key_error(k) {
            return Err(crate::error::Error::Protocol(format!(
                "代理 [{}] 的注解键 {k:?} 不合法：{reason}",
                p.name
            )));
        }
    }
    /// 与官方 `TotalAnnotationSizeLimitB` 一致：256 KiB。
    const ANNOTATION_SIZE_LIMIT: usize = 256 * (1 << 10);
    if total > ANNOTATION_SIZE_LIMIT {
        return Err(crate::error::Error::Protocol(format!(
            "代理 [{}] 的 annotations 总大小 {total} 字节，超过官方上限 256 KiB（{ANNOTATION_SIZE_LIMIT} 字节）",
            p.name
        )));
    }
    Ok(())
}

/// 单个注解键的合格性检查，返回 `Some(原因)` 表示不合格。
///
/// 逐条对齐 Kubernetes `validation.IsQualifiedName`（官方直接调用它，且
/// **先做 `strings.ToLower`**）：格式为 `[前缀/]名字`。
fn annotation_key_error(key: &str) -> Option<String> {
    let lower = key.to_lowercase();
    let parts: Vec<&str> = lower.split('/').collect();
    let name = match parts.as_slice() {
        [name] => *name,
        [prefix, name] => {
            if prefix.is_empty() {
                return Some("`/` 前面不能为空".to_string());
            }
            if !is_dns1123_subdomain(prefix) {
                return Some(format!(
                    "前缀 {prefix:?} 不是合法的 DNS 子域（小写字母数字与 `-`、`.`，\
                     每段以字母数字开头结尾且 ≤63 字符，总长 ≤253）"
                ));
            }
            *name
        }
        _ => return Some("最多只能有一个 `/`（格式 `前缀/名字`）".to_string()),
    };
    if !is_qualified_name_part(name) {
        return Some(format!(
            "名字 {name:?} 不合法（字母数字开头结尾，中间可含 `- _ .`，长度 ≤63）"
        ));
    }
    None
}

/// DNS-1123 子域：点分标签，每个标签是 DNS-1123 label，总长 ≤253。
fn is_dns1123_subdomain(s: &str) -> bool {
    if s.is_empty() || s.len() > 253 {
        return false;
    }
    s.split('.').all(is_dns1123_label)
}

/// DNS-1123 label：`[a-z0-9]` 开头结尾，中间可含 `-`，长度 ≤63。
fn is_dns1123_label(s: &str) -> bool {
    if s.is_empty() || s.len() > 63 {
        return false;
    }
    let b = s.as_bytes();
    let edge = |c: u8| c.is_ascii_lowercase() || c.is_ascii_digit();
    edge(b[0]) && edge(b[b.len() - 1]) && b.iter().all(|&c| edge(c) || c == b'-')
}

/// Kubernetes qualified-name 的"名字"部分（不含前缀）：
/// 字母数字开头结尾、中间可含 `[-_.]`，长度 ≤63。
///
/// 注意名字部分**不是** DNS label —— 它允许大写、`_` 和 `.`
/// （官方先整体小写，所以实践上等效于允许 `[a-z0-9._-]` 这些字符）。
fn is_qualified_name_part(s: &str) -> bool {
    if s.is_empty() || s.len() > 63 {
        return false;
    }
    let b = s.as_bytes();
    let alnum = |c: u8| c.is_ascii_alphanumeric();
    let mid = |c: u8| c.is_ascii_alphanumeric() || matches!(c, b'-' | b'_' | b'.');
    alnum(b[0]) && alnum(b[b.len() - 1]) && b.iter().all(|&c| mid(c))
}

/// `tcpmux` 的两条必填约束，对齐官方 `validateTCPMuxProxyConfigForClient`。
/// 1. `multiplexer` 只认 `httpconnect`（官方报 `not support multiplexer: %s`）。
///    留空也算不认识 —— 官方那边空串同样过不了 `slices.Contains`。
/// 2. 必须配 `customDomains` 或 `subdomain`。tcpmux **不绑端口**，全靠 CONNECT
///    请求里的域名分发，没有域名就等于这条代理没有任何入口。
///
/// 两条都放在**解析阶段**：不然 `frpc verify` 回绿灯，用户拿去上线才发现服务端
/// 拒绝 —— 和之前那批"假绿灯"是同一个坑（见 [`reject_unimplemented_plugin`]）。
fn reject_bad_tcpmux(p: &ProxyConfig) -> Result<()> {
    if p.proxy_type != "tcpmux" {
        return Ok(());
    }
    if p.multiplexer != "httpconnect" {
        return Err(crate::error::Error::Protocol(format!(
            "代理 [{}] 的 multiplexer 是 {:?}，只支持 \"httpconnect\"（官方也只有这一种）",
            p.name, p.multiplexer
        )));
    }
    let no_domain = p.custom_domains.iter().all(|d| d.trim().is_empty());
    if no_domain && p.subdomain.trim().is_empty() {
        return Err(crate::error::Error::Protocol(format!(
            "代理 [{}] 是 tcpmux：它不绑端口、只按 CONNECT 请求里的域名分发，\
             所以 customDomains 和 subdomain 至少要配一个",
            p.name
        )));
    }
    Ok(())
}
