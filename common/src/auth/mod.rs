//! 认证后端。
//!
//! 目前只有 [`oidc`] 一个模块 —— token 认证（`md5(token + timestamp)`）
//! 是线协议的一部分，实现在 `frp` 模块里，不走这里。

pub mod oidc;
