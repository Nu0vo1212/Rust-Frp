//! HTTP / HTTPS / tcpmux 虚拟主机代理（等价官方 `server/proxy/http.go` +
//! `server/proxy/tcpmux.go` + `pkg/util/vhost`）。
//!
//! * **HTTP**：服务端在 `vhost_http_port` 上按 `Host` 头路由，把请求原样转发到
//!   内网服务，并支持 frp 的几种花活：`locations` 前缀、Basic Auth、
//!   `host_header_rewrite`、自定义请求/响应头；
//! * **HTTPS**：只在 `vhost_https_port` 上嗅探 TLS ClientHello 里的 **SNI**，
//!   之后把 TLS 字节**原样透传**给内网服务（frp 不终止 TLS，证书由内网服务自己出）；
//! * **tcpmux**：所有 tcpmux 代理共用 `tcpmux_http_connect_port` 一个端口，
//!   按 HTTP `CONNECT` 请求行里的 authority 分发（详见 `tcpmux` 模块）。
//!
//! 三种共用同一张路由表（域名匹配 / 最长路径前缀 / `routeByHTTPUser`
//! 三级优先级完全一致），差别只在"域名从哪看"和"怎么把连接交给内网服务"。
//!
//! 与 TCP 代理一样，每个请求/连接都从客户端要一条工作连接；
//! 区别在于服务端要自己解析协议语义，才能决定连接何时可以复用。
//!
//! # 模块划分
//!
//! * `router`：路由表（域名 / 路径 / `routeByHTTPUser` 的注册、注销、查找）；
//! * `listen`：`bind`、`VhostOpts`、accept 循环与按 kind 分发；
//! * `https`：TLS ClientHello 的 SNI 嗅探与原样透传；
//! * `tcpmux`：共享端口上的 HTTP `CONNECT` 复用；
//! * `http`：HTTP 报文解析、Basic Auth、请求 / 响应转发；
//! * `conn`：工作连接包装、字节计数、连接计数守卫、`canonical_host`。
//!
//! 职责：只做模块声明与公开路径的再导出（`pub use`），不承载业务逻辑。
//!
//! 锁顺序契约：本模块不加锁。全局只有 `VhostTable` 的 `Mutex<VhostInner>`
//! 一把路由表锁；它从不与 `ClientState` 连接池锁、`Registry` 的锁嵌套，
//! 指标计数只是原子量。`listen` 的 accept 分支先释放 `Registry` 相关读锁，
//! 再由协议处理函数获取 `VhostTable` 锁。
//!
//! 不变量：`nfrp_server::vhost::{VhostKind, VhostRoute, VhostTable, VhostOpts,
//! bind, run_vhost}` 是外部唯一依赖的公开路径；子模块之间只放宽到
//! `pub(super)` / `pub(crate)`，不新增 `pub` 项。

mod conn;
mod http;
mod https;
mod listen;
mod router;
mod tcpmux;

#[cfg(test)]
mod tests;

pub use listen::{bind, run_vhost, VhostOpts};
pub use router::{VhostKind, VhostRoute, VhostTable};
