//! 带宽限流（对应 frp 的 `transport.bandwidthLimit`）。
//!
//! 为什么要限：一个不限速的代理能把整条上行链路吃满，
//! 于是同机器上的其它代理一起变慢。限流让带宽变成**可分配**的资源。
//!
//! 实现是令牌桶：
//!
//! ```text
//! 令牌以 rate 的速度持续生成，最多攒 1 秒的量（burst）；
//! 转发 n 字节要先拿到 n 个令牌，不够就睡到够为止。
//! ```
//!
//! 攒 1 秒的量意味着**允许短时突发到两倍速率**——这是刻意的：
//! 网页这类小响应不该被限速拖慢，真正被压住的是持续的大流量。

use std::time::{Duration, Instant};

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::util::RELAY_BUF;

/// 令牌桶限流器；速率为 0 表示不限。
#[derive(Debug, Clone)]
pub struct Limiter {
    /// 每秒字节数；0 = 不限。
    rate: u64,
    /// 当前令牌数（字节）。
    tokens: f64,
    /// 上次补充令牌的时刻。
    last: Option<Instant>,
}

impl Limiter {
    /// 不限速。
    pub const fn unlimited() -> Self {
        Self {
            rate: 0,
            tokens: 0.0,
            last: None,
        }
    }

    /// 按每秒字节数构造。
    pub const fn new(bytes_per_sec: u64) -> Self {
        Self {
            rate: bytes_per_sec,
            tokens: 0.0,
            last: None,
        }
    }

    const fn enabled(&self) -> bool {
        self.rate > 0
    }

    /// 取 `n` 个字节的令牌；不够就等到够。
    pub async fn take(&mut self, n: u64) {
        if !self.enabled() || n == 0 {
            return;
        }
        let now = Instant::now();
        let last = self.last.unwrap_or(now);
        // 补充这一段时间产生的令牌
        let elapsed = now.saturating_duration_since(last).as_secs_f64();
        self.tokens = (self.tokens + elapsed * self.rate as f64).min(self.rate as f64);
        self.last = Some(now);

        if self.tokens >= n as f64 {
            self.tokens -= n as f64;
            return;
        }
        // 还差多少就睡多久：睡醒后令牌刚好够
        let missing = n as f64 - self.tokens;
        let wait = Duration::from_secs_f64((missing / self.rate as f64).max(0.0));
        self.tokens = 0.0;
        if wait > Duration::from_micros(200) {
            tokio::time::sleep(wait).await;
            // 睡过之后时钟已经推进了，下回再补令牌
            self.last = Some(Instant::now());
        }
    }
}

/// 把 `bandwidthLimit` 之类的字符串解析成"每秒字节数"。
///
/// 支持 `100KB` / `2MB` / `500K` / `1MB` / 纯数字（按字节/秒）。
/// 单位换算沿用 frp 的习惯：`KB = 1000`、`KiB = 1024`、`MB = 1000*1000`。
pub fn parse_bandwidth(s: &str) -> Option<u64> {
    let t = s.trim();
    if t.is_empty() || t == "0" {
        return None;
    }
    let (digits, unit) = {
        let i = t
            .find(|c: char| !c.is_ascii_digit() && c != '.')
            .unwrap_or(t.len());
        let (d, u) = t.split_at(i);
        (d.trim().to_string(), u.trim().to_ascii_lowercase())
    };
    let value: f64 = digits.parse().ok()?;
    if value <= 0.0 {
        return None;
    }
    let mul: f64 = match unit.as_str() {
        "" | "b" => 1.0,
        "k" | "kb" => 1_000.0,
        "kib" => 1_024.0,
        "m" | "mb" => 1_000_000.0,
        "mib" => 1_024.0 * 1_024.0,
        "g" | "gb" => 1_000_000_000.0,
        _ => return None,
    };
    Some((value * mul) as u64)
}

/// 单向拷贝并限速，返回搬运的字节数。
async fn copy_one<R, W>(mut r: R, mut w: W, limit: u64) -> std::io::Result<u64>
where
    R: AsyncRead + Unpin + Send + 'static,
    W: AsyncWrite + Unpin + Send + 'static,
{
    let mut buf = vec![0u8; RELAY_BUF];
    let mut limiter = Limiter::new(limit);
    let mut total = 0u64;
    loop {
        let n = r.read(&mut buf).await?;
        if n == 0 {
            break;
        }
        limiter.take(n as u64).await;
        w.write_all(&buf[..n]).await?;
        total += n as u64;
    }
    // 让对端看到 EOF，否则 HTTP/1.1 keep-alive 这类协议会一直等
    let _ = w.shutdown().await;
    Ok(total)
}

/// 双向转发，两个方向各自限流（`0` = 不限）。
///
/// 不限速时行为与 [`crate::util::relay_between`] 完全一致（走同一条拷贝路径），
/// 所以调用方可以无条件使用这个函数。
pub async fn relay_throttled<A, B>(a: A, b: B, up: u64, down: u64) -> std::io::Result<(u64, u64)>
where
    A: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    B: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let (ar, aw) = tokio::io::split(a);
    let (br, bw) = tokio::io::split(b);

    let t1 = tokio::spawn(copy_one(ar, bw, up));
    let t2 = tokio::spawn(copy_one(br, aw, down));

    // 一个方向结束（对端 EOF）后，另一个方向通常也会很快结束。
    // 给它 10 秒收尾是为了拿到准确的回程字节数；超时就直接取消 ——
    // 有些服务端收到半关闭并不会主动断开，死等会把连接挂住。
    let up_bytes = match t1.await {
        Ok(r) => r?,
        Err(e) => return Err(std::io::Error::other(e)),
    };
    match tokio::time::timeout(Duration::from_secs(10), t2).await {
        Ok(Ok(Ok(down))) => Ok((up_bytes, down)),
        Ok(Ok(Err(e))) => Err(e),
        Ok(Err(e)) => Err(std::io::Error::other(e)),
        Err(_) => Ok((up_bytes, 0)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bandwidth_strings() {
        assert_eq!(parse_bandwidth("100KB"), Some(100_000));
        assert_eq!(parse_bandwidth("1MB"), Some(1_000_000));
        assert_eq!(parse_bandwidth("500"), Some(500));
        assert_eq!(parse_bandwidth("2 MiB"), Some(2 * 1024 * 1024));
        assert_eq!(parse_bandwidth("0"), None, "0 表示不限");
        assert_eq!(parse_bandwidth(""), None);
        assert_eq!(parse_bandwidth("abc"), None, "非法输入要返回 None 而不是崩");
        assert_eq!(parse_bandwidth("1XB"), None, "未知单位不认");
    }

    #[tokio::test]
    async fn unlimited_never_waits() {
        let mut l = Limiter::unlimited();
        let t0 = Instant::now();
        // 就算一次取 1GB 也不该等
        l.take(1_000_000_000).await;
        assert!(t0.elapsed() < Duration::from_millis(50), "不限速时不能阻塞");
    }

    /// 限速的核心是"睡多久"要算对：10 KB/s 下搬 10 KB 至少得 1 秒。
    #[tokio::test]
    async fn small_rate_slows_down_large_transfers() {
        let mut l = Limiter::new(10_000);
        let t0 = Instant::now();
        // 第一次取：桶是空的，要等
        l.take(10_000).await;
        let elapsed = t0.elapsed();
        assert!(
            elapsed >= Duration::from_millis(500),
            "10KB/s 下取 10KB 至少要等接近 1 秒，实际 {elapsed:?}"
        );
    }

    #[tokio::test]
    async fn burst_is_allowed_up_to_one_second() {
        let mut l = Limiter::new(1_000_000);
        // 先让它攒一会儿，然后一次取走 —— 攒下的令牌不该被浪费
        tokio::time::sleep(Duration::from_millis(100)).await;
        let t0 = Instant::now();
        l.take(50_000).await;
        assert!(
            t0.elapsed() < Duration::from_millis(80),
            "攒够令牌后不该再等：{:?}",
            t0.elapsed()
        );
    }

    /// 端到端：走一遍限流拷贝，数据必须一个字节不少。
    #[tokio::test]
    async fn throttled_copy_keeps_every_byte() {
        let payload = vec![0xABu8; 64 * 1024];
        let (client, mut server) = tokio::io::duplex(256 * 1024);
        let (_r, w) = tokio::io::split(client);

        let p2 = payload.clone();
        let writer = tokio::spawn(async move {
            // Cursor 包住 owned Vec 才能送进 spawn（借用活不过 'static）
            copy_one(std::io::Cursor::new(p2), w, 400_000).await
        });

        let mut got = Vec::new();
        tokio::io::AsyncReadExt::read_to_end(&mut server, &mut got)
            .await
            .expect("读到 EOF");
        let n = writer.await.expect("任务").expect("拷贝");
        assert_eq!(n, payload.len() as u64, "拷贝计数要准");
        assert_eq!(got.len(), payload.len(), "限速不能丢字节");
        assert!(got.iter().all(|b| *b == 0xAB), "内容不能被改写");
    }

    /// 限速到 400KB/s 传 64KB 至少要有可感知的等待，否则说明限流根本没生效。
    #[tokio::test]
    async fn throttled_copy_actually_waits() {
        let payload = vec![0u8; 200 * 1024];
        let (client, mut server) = tokio::io::duplex(1024 * 1024);
        let (_r, w) = tokio::io::split(client);

        let p2 = payload.clone();
        let t0 = Instant::now();
        let writer =
            tokio::spawn(async move { copy_one(std::io::Cursor::new(p2), w, 200_000).await });
        let mut got = Vec::new();
        tokio::io::AsyncReadExt::read_to_end(&mut server, &mut got)
            .await
            .expect("读到 EOF");
        writer.await.unwrap().unwrap();
        let elapsed = t0.elapsed();
        assert_eq!(got.len(), payload.len());
        assert!(
            elapsed >= Duration::from_millis(300),
            "200KB/s 传 200KB 至少要 0.3 秒以上，实际 {elapsed:?} —— 限流没生效？"
        );
    }
}
