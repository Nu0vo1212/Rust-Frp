//! 服务端网络入口：监听、分发、控制连接处理、代理注册与转发配对。
//!
//! 与原版 frps 一致，控制连接与工作连接**复用同一个端口**，靠首帧消息类型区分：
//! `Login` 走控制连接流程，`NewWorkConn` 走工作连接流程，
//! `NewVisitorConn` 走 visitor 接入流程（stcp / xtcp）。
//!
//! # 模块划分
//!
//! * `preauth`：未认证握手的全局并发闸门；
//! * `startup`：启动 / 监听 / 预检 / 配置折算；
//! * `conn`：首帧探测、yamux 分层与 frp 握手分发；
//! * `control`：控制连接状态机与续传指纹；
//! * `register`：按代理类型注册与公网端口 accept 循环；
//! * `work`：visitor 准入、工作连接认证与配对；
//! * `bridge`：配对后的双向转发与 SUDP 帧中继。
//!
//! 职责：只做模块声明与公开路径的再导出（`pub use`），不承载业务逻辑。
//!
//! 锁顺序契约：全模块统一为 registry → client state → pool。`Registry` 的
//! 安全上下文 / 插件 / nlink / 指标只取短锁或原子量快照；`ClientState` 的
//! 代理表 / 队列锁在其后获取；`VhostTable` 锁再后。任何路径都不反向获取。
//!
//! 不变量：`nfrp_server::serve::{limits_from, ServeExtras, serve, preflight,
//! serve_with, serve_on, serve_on_with, admit_user, spawn_bridge, bridge,
//! ensure_protocol}` 是外部唯一依赖的公开路径；子模块之间只放宽到
//! `pub(super)` / `pub(crate)`，不新增 `pub` 项。

mod bridge;
mod conn;
mod control;
mod preauth;
mod register;
mod startup;
mod work;

#[cfg(test)]
mod tests;

pub use bridge::{bridge, spawn_bridge};
pub use startup::{
    ensure_protocol, limits_from, preflight, serve, serve_on, serve_on_with, serve_with,
    ServeExtras,
};
pub use work::admit_user;

pub(crate) use register::register_proxy;
