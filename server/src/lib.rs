//! `rustunnel-server`：frp v2 兼容的服务端。
//!
//! 与原版 frps 一致，控制连接与工作连接复用**同一个端口**，靠首帧消息类型区分：
//! `Login` 走控制连接流程，`NewWorkConn` 走工作连接流程，
//! `NewVisitorConn` 走 visitor 接入流程（stcp / xtcp）。
//!
//! 已实现的代理类型：`tcp` / `udp` / `http` / `https` / `stcp` / `xtcp`。
//!
//! 本 crate 以**库**的形式提供（二进制只是一个薄薄的 CLI 壳），
//! 因此所有核心状态机——连接池、路由表、visitor 准入、资源上限、指标——
//! 都有对应的单元测试，集成测试也能直接驱动它们。

pub mod dashboard;
pub mod limits;
pub mod observability;
pub mod p2p;
pub mod pool;
pub mod registry;
pub mod reload;
pub mod serve;
pub mod udp_proxy;
pub mod vhost;
pub mod visitor;

pub use pool::{ClientState, CtrlCmd};
pub use registry::{Registry, ServerLimits};
pub use serve::{limits_from, serve, serve_on, serve_on_with, serve_with, ServeExtras};
