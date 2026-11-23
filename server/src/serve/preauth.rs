//! 未认证握手的全局并发闸门。
//!
//! 职责：`PREAUTH_MAX` / `PREAUTH_WAIT` 常量、全局信号量单例 `preauth_gate`、
//! `acquire_preauth_slot` / `acquire_preauth_slot_with`，以及三态入场方式
//! `PreauthSlot`（直连自取 / mux 预取 / 已认证免闸）。
//!
//! 锁顺序契约：本模块不加锁，只使用 `tokio::sync::Semaphore`（内部原子量）。
//! 名额在 ACL 判定之后、握手之前获取，握手结束（成功 / 失败 / 超时）立刻释放；
//! 与 `Registry` 的锁、`ClientState` 连接池锁之间没有嵌套。
//!
//! 不变量：`PREAUTH_MAX` / `PREAUTH_WAIT` 是编译期常量，运行期只读；
//! `PreauthSlot::Preacquired` 持有唯一名额并在 drop 时归还，`Bypassed` 永远没有名额。

use std::time::Duration;

/// 未认证握手的**全局**并发上限。
///
/// # 为什么
///
/// 每条未认证的 frp 握手（明文连接或 yamux 子流）在认证完成前要占住一个
/// 任务和一份读缓冲。实测（`tmp/audit9/c/c9_3_yamux_flood.py`）：
/// yamux 未认证开流每条 ≈9.5 KiB、单会话上限 512 条、跨会话**没有**全局
/// 上限 —— 攻击者 129 KB 流量 + 22 个 fd 就把服务端内存抬到 +100 MB。
///
/// 这里给**所有**未认证握手一个全局名额：超出即短暂排队，排队也拿不到
/// 名额就断开 ⇒ 未认证内存峰值有界（≈ 2048 × ~10 KiB ≈ 20 MB），
/// 与攻击者的会话数、fd 数无关。
///
/// 复验修正（同日，C9-3 元验证抓出）：**名额必须在 spawn 之前取**。
/// 第一版把闸门放在任务体内部 —— 攻击者 11264 条流照旧全量 spawn，
/// 而每条流一 spawn 就分配 ~9 KiB 的 future ⇒ 峰值仍 +97 MB（约等于
/// 未修复）。现在 mux accept 循环先取名额再 spawn；已认证会话
/// （控制流登录成功后置位）的工作流直接放行（每条仍要各自握手认证）。
/// 配合 mux 通道反压（容量 8）与内核 TCP 缓冲，"已创建但未认证"的
/// 流数量被钉在闸门上限附近。
pub(super) const PREAUTH_MAX: usize = 2048;

/// 拿不到名额时最多排队的时长：给突发重连留出空间，之后直接断开
/// （攻击流量下让队列尽快排空，而不是无限堆积）。
const PREAUTH_WAIT: Duration = Duration::from_secs(5);

/// 全局闸门的单例。
static PREAUTH_HANDSHAKES: std::sync::OnceLock<tokio::sync::Semaphore> = std::sync::OnceLock::new();

pub(super) fn preauth_gate() -> &'static tokio::sync::Semaphore {
    PREAUTH_HANDSHAKES.get_or_init(|| tokio::sync::Semaphore::new(PREAUTH_MAX))
}

/// 申请一个未认证握手名额；排队超时（或信号量异常）返回 `None`。
///
/// 抽成独立函数是为了让测试能用小信号量直接验证"排满即超时"的行为。
pub(super) async fn acquire_preauth_slot(
    gate: &tokio::sync::Semaphore,
) -> Option<tokio::sync::SemaphorePermit<'_>> {
    acquire_preauth_slot_with(gate, PREAUTH_WAIT).await
}

/// [`acquire_preauth_slot`] 的可参数化本体（测试用短超时）。
pub(super) async fn acquire_preauth_slot_with(
    gate: &tokio::sync::Semaphore,
    wait: Duration,
) -> Option<tokio::sync::SemaphorePermit<'_>> {
    match tokio::time::timeout(wait, gate.acquire()).await {
        Ok(Ok(permit)) => Some(permit),
        // `Ok(Err(_))`：信号量被关闭（本进程不会发生）；`Err(_)`：排队超时。
        _ => None,
    }
}

/// 未认证握手闸门的**入场方式**（C9-3 复验补强）。
///
/// 用三态枚举而不是 `Option<Permit>`：`Option` 的 `None` 会同时被解释成
/// "没有预取（自己去取）"和"免闸门"，第一版就栽在这里 —— mux 已认证会话
/// 的流走了放行分支（`None`），任务体却又把它当成"没预取"去排队取名额，
/// 闸门满载时把合法工作流挡在门外（实测攻击期间转发失败，日志变体
/// "…断开" + 合法会话端口）。三态后语义唯一：
pub(super) enum PreauthSlot {
    /// 直连路径：由 `handle_frp_stream` 在 ACL 之后自己取名额。
    Deferred,
    /// mux 未认证会话：accept 循环已在 spawn 之前取好名额（内存封顶关键）。
    Preacquired(tokio::sync::SemaphorePermit<'static>),
    /// mux 已认证会话的后续流：免闸门（每条仍要各自通过握手认证）。
    Bypassed,
}
