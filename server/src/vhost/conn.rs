//! 虚拟主机三条转发路径共用的连接包装与工具函数。
//!
//! 职责：`wrap_work_stream` 按 `useEncryption` / `useCompression` 包装工作连接
//! （并把握手期预读字节挂成读前缀）、`record_bytes` 累计流量、
//! `ConnGuard` 维护活跃连接 gauges、`canonical_host` 归一化 authority / `Host`。
//!
//! 锁顺序契约：本模块不获取任何锁。`ConnGuard` 只做指标原子量 `inc` / `dec`；
//! `wrap_work_stream` 只消费已移交给它的 `BoxStream`。指标原子量与
//! `VhostTable` 的 `Mutex`、`ClientState` 连接池锁之间没有嵌套。
//!
//! 不变量：包装顺序与 `serve.rs::bridge` 一致（压缩在外、加密在内）；
//! `leftover` 是**读方向前缀**且只能消费一次；`ConnGuard` 一旦构造成功，
//! 活跃连接计数必然在 `Drop` 时恰好减一，任何提前返回路径都不例外。

use std::sync::Arc;

use nfrp_common::frp::stream::PrefixedStream;

use crate::registry::Registry;

// ---------------------------------------------------------------------------
// 工作连接包装 / 流量计数 / 连接守卫
// ---------------------------------------------------------------------------
/// 把「工作连接 + 握手期预读字节」按代理的数据面标志包成一条流。
///
/// `flags` 是 `(useEncryption, useCompression)`，由调用方从
/// `ClientState::proxy_flags(proxy_name)` 取（注册时记下）。
///
/// ★ v0.7.6 修：vhost 的三条转发路径（http / https / tcpmux）此前都是**直接对
/// 原始工作连接做中继**，`useEncryption` / `useCompression` 被完全忽略。
/// 客户端开了加密时，服务端把密文当成明文透传 —— 隧道能建立、握手也可能过，
/// 但数据全乱或直接超时，而日志里没有任何报错。
///
/// 包装顺序与 `serve.rs::bridge` 保持一致（压缩在外、加密在内）；
/// `leftover` 是握手期间已经从工作连接读到、属于业务数据的字节，这里挂成
/// **读方向前缀**：开了加密时它是一段密文，必须经过解密才能交给下游。
pub(super) fn wrap_work_stream(
    stream: nfrp_common::frp::stream::BoxStream,
    leftover: Vec<u8>,
    flags: (bool, bool),
    token: &str,
) -> nfrp_common::frp::stream::BoxStream {
    let (enc, comp) = flags;
    if !enc && !comp {
        return Box::pin(PrefixedStream::new(leftover, stream));
    }
    let key = enc.then(|| nfrp_common::frp::v1::derive_key(token.as_bytes()));
    Box::pin(nfrp_common::frp::proxy_stream::ProxyStream::new(
        PrefixedStream::new(leftover, stream),
        key,
        comp,
    ))
}

/// 累计一次转发的流量。
pub(super) fn record_bytes(registry: &Registry, r: &std::io::Result<(u64, u64)>) {
    let m = registry.metrics();
    if let Ok((up, down)) = r {
        m.bytes_up.inc_by(*up);
        m.bytes_down.inc_by(*down);
    }
}

/// RAII 守卫：**任何**返回路径都会自动归还活跃连接数。
///
/// `handle_http` 有六七个提前 `return` 的分支（404 / 401 / 502…），
/// 用手动 decrement 必然会在某条路径上漏掉，时间长了 gauge 就飘上天。
pub(super) struct ConnGuard(Arc<Registry>);

impl ConnGuard {
    pub(super) fn new(registry: &Arc<Registry>) -> Option<Self> {
        registry.metrics().conns_active.inc();
        registry.metrics().conns_total.inc();
        Some(Self(registry.clone()))
    }
}

impl Drop for ConnGuard {
    fn drop(&mut self) {
        self.0.metrics().conns_active.dec();
    }
}
// ---------------------------------------------------------------------------
// authority / Host 归一化
// ---------------------------------------------------------------------------
/// 从 CONNECT 的 authority 取域名：去 scheme、去路径、去端口、转小写、去末尾点。
///
/// 对齐官方 `pkg/util/http.CanonicalHost`（先 `ToLower`、再 `SplitHostPort`、
/// 最后去末尾的点）。域名必须取**请求行里的 authority** 而不是 `Host` 头：
/// Go 的 `http.ReadRequest` 对 authority-form 也是这么取 `req.Host` 的
/// （`req.URL.Host` 优先，`Host` 头只在没有 URL host 时兜底）。
///
/// 这里比官方多容忍一种写法：部分 HTTP 库会把 CONNECT 发成绝对形式
/// （`CONNECT http://a.b/ HTTP/1.1`），所以先剥掉 scheme 和路径。
pub(super) fn canonical_host(authority: &str) -> String {
    let mut a = authority.trim();
    if let Some(rest) = a
        .strip_prefix("http://")
        .or_else(|| a.strip_prefix("https://"))
    {
        a = rest;
    }
    if let Some(i) = a.find('/') {
        a = &a[..i];
    }
    a = a.trim();
    // 去端口：IPv6 写成 `[::1]:80`，普通域名写成 `a.b:80`
    let host = if let Some(rest) = a.strip_prefix('[') {
        rest.split(']').next().unwrap_or(rest)
    } else {
        a.rsplit_once(':').map(|(h, _)| h).unwrap_or(a)
    };
    host.trim().trim_end_matches('.').to_ascii_lowercase()
}
#[cfg(test)]
mod tests {
    //! 连接包装与 authority 归一化的单元测试。

    use super::*;
    use tokio::io::AsyncWriteExt;
    /// ★ 回归测试：`Host` 头里的 IPv6 要能正确取到域名。
    ///
    /// 原先按 `:` 硬切，`[::1]:8080` 会切出一个孤零零的 `[`。
    #[test]
    fn canonical_host_处理_ipv6_与端口() {
        assert_eq!(canonical_host("[::1]:8080"), "::1");
        assert_eq!(canonical_host("[::1]"), "::1");
        assert_eq!(canonical_host("a.example.com:8080"), "a.example.com");
        assert_eq!(canonical_host("A.Example.COM."), "a.example.com");
        assert_eq!(canonical_host("a.example.com"), "a.example.com");
        // 绝对形式（部分库会这么发 CONNECT）
        assert_eq!(canonical_host("http://a.b/x"), "a.b");
    }

    #[test]
    fn connect_的域名去端口转小写去尾点() {
        // 官方 CanonicalHost 的语义：cURL 发的就是 `host:port` 形式
        assert_eq!(
            canonical_host("normal.example.com:80"),
            "normal.example.com"
        );
        assert_eq!(canonical_host("Normal.Example.COM"), "normal.example.com");
        assert_eq!(canonical_host("a.b."), "a.b");
        // IPv6 authority 必须带方括号，去掉端口后只留地址
        assert_eq!(canonical_host("[::1]:8080"), "::1");
        assert_eq!(canonical_host("[2001:db8::1]"), "2001:db8::1");
        // 容忍绝对形式（有些库会这么发）
        assert_eq!(canonical_host("http://a.b/x"), "a.b");
        assert_eq!(canonical_host("  a.b:1  "), "a.b");
    }

    /// ★★ v0.7.6 回归：vhost 工作连接必须按代理的加密/压缩标志包装。
    ///
    /// 守的是**行为**而不是 helper：两端都按生产同一条包装，数据必须能原样往返。
    /// 退回修复（裸流中继）时，客户端侧的密文会被当成明文，读出来的内容与写入
    /// 的不一致 —— 这正是线上「隧道建立了、页面空白/超时」的成因。
    #[tokio::test]
    async fn vhost_工作连接必须按加密压缩标志包装() {
        use nfrp_common::frp::proxy_stream::ProxyStream;
        use nfrp_common::frp::v1::derive_key;
        use tokio::io::AsyncReadExt;

        let (server_side, client_side) = tokio::io::duplex(64 * 1024);
        let token = "vhost-test-token";

        // 客户端侧：与生产完全一致（压缩在外、加密在内）
        let key = derive_key(token.as_bytes());
        let mut client = ProxyStream::new(client_side, Some(key), true);

        // 服务端侧：被测包装（没有 leftover —— 开了加密时 leftover 必须是密文，
        // 明文前缀单独由下一条测试覆盖）
        let mut server = wrap_work_stream(Box::pin(server_side), Vec::new(), (true, true), token);

        // 客户端 -> 服务端
        client.write_all(b"hello vhost").await.unwrap();
        client.flush().await.unwrap();
        let mut got = [0u8; 11];
        server.read_exact(&mut got).await.unwrap();
        assert_eq!(&got, b"hello vhost", "密文/压缩字节必须被正确解密解压");

        // 服务端 -> 客户端
        server.write_all(b"world").await.unwrap();
        server.flush().await.unwrap();
        let mut back = [0u8; 5];
        client.read_exact(&mut back).await.unwrap();
        assert_eq!(&back, b"world", "发送方向也必须按同一套编码写入");
    }

    /// `leftover` 必须作为**读方向前缀**交出去（明文路径）。
    ///
    /// 客户端在握手期抢跑写出的字节属于业务数据，丢掉就会截断响应；
    /// 把它写回工作连接（旧 tcpmux 路径的写法）则是把数据弹回给客户端。
    #[tokio::test]
    async fn vhost_工作连接把预读字节作为读前缀() {
        use tokio::io::AsyncReadExt;

        let (server_side, client_side) = tokio::io::duplex(4096);
        let mut server = wrap_work_stream(
            Box::pin(server_side),
            b"PRE".to_vec(),
            (false, false),
            "unused",
        );
        let mut client = client_side;

        let mut pre = [0u8; 3];
        server.read_exact(&mut pre).await.unwrap();
        assert_eq!(&pre, b"PRE", "握手期预读的字节必须原样交给下游");

        client.write_all(b"later").await.unwrap();
        client.flush().await.unwrap();
        let mut got = [0u8; 5];
        server.read_exact(&mut got).await.unwrap();
        assert_eq!(&got, b"later", "前缀之后的数据必须照常可读");
    }
}
