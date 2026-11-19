//! CPU profiling 端点（官方 frps 的 `pprofEnable`）。
//!
//! # 官方语义
//!
//! `server.go`：`Enable golang pprof handlers in dashboard listener.`
//! 挂上 `/debug/pprof/*` 后可以直接 `go tool pprof` 抓 CPU / 堆。
//!
//! # 这里的等价物
//!
//! Rust 没有 Go runtime 那套采样器，但有 [`pprof`] crate（基于 perf 事件 /
//! 信号采样）。我们提供**同样的路径与参数约定**，让它能配 `go tool pprof`
//! 之外的通用工具（也能直接喂给 `pprof` / `flamegraph`）：
//!
//! | 路径 | 说明 |
//! |---|---|
//! | `GET /debug/pprof/profile?seconds=N` | 采 N 秒 CPU（默认 10，上限 60） |
//!
//! # 安全
//!
//! * 端点受 `pprof_enable` 控制，**默认关闭**（与 `enablePrometheus` 同口径：
//!   诊断端点不该在"只想开个面板"的部署里默认暴露）；
//! * 采集期间会阻塞该请求 N 秒 —— **必须限制时长**，否则一个请求就能把
//!   面板连接长期占住（上限 60 秒）；
//! * 结果按 Go 的 protobuf profile 格式返回（`application/octet-stream`），
//!   `go tool pprof` / `pprof` / `flamegraph` 都能读。

#[cfg(all(
    unix,
    not(target_os = "android"),
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
use std::{sync::Mutex, time::Duration};

#[cfg(all(
    unix,
    not(target_os = "android"),
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
use anyhow::Context;
use anyhow::Result;
// `Profile` 的 `encode` 来自 prost 的 `Message` trait；pprof 在启用
// `prost-codec` 时把它 re-export 到 crate 根。Windows 上 pprof 依赖不编译，
// 因此这个 import 也必须跟着 `cfg(unix)`。
#[cfg(all(
    unix,
    not(target_os = "android"),
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
use pprof::protos::Message as _;

/// 同一时刻只允许一个采集。
///
/// pprof-rs 的 perf 采样是进程级的；两个请求同时采会把同一个 perf fd
/// 关掉再开，结果是两个 profile 都不完整。这里用 `try_lock` 而不是排队：
/// 面板并发上限 128，若允许排队，128 个请求各等 60 秒会长期占满闸门。
#[cfg(all(
    unix,
    not(target_os = "android"),
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
static PROFILE_LOCK: Mutex<()> = Mutex::new(());

/// 默认采样时长。
const DEFAULT_SECS: u64 = 10;
/// 采样时长上限：再长就把面板连接占太久了。
const MAX_SECS: u64 = 60;
/// 采样频率（Hz）。99 是 Linux perf 常用的值，避开与 `HZ=100` 的整数倍共振。
#[cfg(all(
    unix,
    not(target_os = "android"),
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
const SAMPLE_HZ: i32 = 99;

/// 解析 `?seconds=N`，夹到 `[1, MAX_SECS]`。
pub fn parse_seconds(query: &str) -> u64 {
    let raw = query
        .split('&')
        .find_map(|kv| kv.strip_prefix("seconds="))
        .and_then(|v| v.trim().parse::<u64>().ok())
        .unwrap_or(DEFAULT_SECS);
    raw.clamp(1, MAX_SECS)
}

/// 采一段 CPU profile，返回 Go 兼容的 protobuf 字节。
///
/// 这是**阻塞**调用（`pprof` 的 guard 在 drop 时才结束采样），
/// 调用方应当把它放到 `spawn_blocking` 里，别卡住 async 执行器。
#[cfg(all(
    unix,
    not(target_os = "android"),
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
pub fn capture_cpu_profile(seconds: u64) -> Result<Vec<u8>> {
    let seconds = seconds.clamp(1, MAX_SECS);
    let _one_at_a_time = PROFILE_LOCK
        .try_lock()
        .map_err(|_| anyhow::anyhow!("another CPU profile is already running"))?;

    let guard = pprof::ProfilerGuardBuilder::default()
        .frequency(SAMPLE_HZ)
        .blocklist(&["libc", "libgcc", "pthread", "vdso"])
        .build()
        .context("启动 CPU profiler 失败（内核不支持 perf 事件？）")?;

    std::thread::sleep(Duration::from_secs(seconds));

    let report = guard
        .report()
        .build()
        .context("生成 CPU profile 报告失败")?;

    let mut body = Vec::new();
    report
        .pprof()
        .context("把报告转成 pprof 格式失败")?
        .encode(&mut body)
        .context("序列化 pprof 数据失败")?;
    Ok(body)
}

/// 不支持的平台：Windows（没有 perf 信号 / `ucontext_t`）、Android、
/// 以及 32 位 ARM / MIPS（pprof 0.15 的 frame-pointer 采样路径只在
/// x86_64/aarch64/riscv64/loongarch64 上实现）。
///
/// 明确报"平台不支持"，而不是返回空文件让调用方以为采集成功。
/// 官方 frps 的 pprofEnable 在 Windows 上依赖 Go runtime，Rust 侧没有
/// 等价实现；这与 README 里其他平台限制同一口径。
#[cfg(not(all(
    unix,
    not(target_os = "android"),
    any(target_arch = "x86_64", target_arch = "aarch64")
)))]
pub fn capture_cpu_profile(_seconds: u64) -> Result<Vec<u8>> {
    anyhow::bail!(
        "pprof CPU profiling is only supported on 64-bit Unix (linux/macos x86_64/aarch64)"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn 解析_seconds_参数() {
        assert_eq!(parse_seconds(""), DEFAULT_SECS);
        assert_eq!(parse_seconds("seconds=5"), 5);
        assert_eq!(parse_seconds("a=1&seconds=7"), 7);
        // 越界要夹住：0 秒没有意义，超长会把面板连接占死
        assert_eq!(parse_seconds("seconds=0"), 1);
        assert_eq!(parse_seconds("seconds=9999"), MAX_SECS);
        // 垃圾值退回默认
        assert_eq!(parse_seconds("seconds=abc"), DEFAULT_SECS);
    }
}
