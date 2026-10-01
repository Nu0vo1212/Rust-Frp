//! 按天切分的日志文件写入，对应官方 frp 的 `log.to` + `log.maxDays`。
//!
//! # 为什么要自己写而不是引第三方
//!
//! `tracing-appender` 的 `rolling::daily` 生成的文件名是 `prefix.YYYY-MM-DD`
//! （**不含时分秒**），而官方 golib 的 `RotateFileWriter` 用的是
//! `prefix.YYYYMMDD-HHMMSS.ext`（见 `log/output_rotatefile.go` 的
//! `backupTimeFormat = "20060102-150405"`）。两者一比，"今天已经轮转过一次"
//! 的判据就完全不同，用户从 frps 迁过来会看到文件名对不上。
//!
//! 这个模块按官方那套规则重新实现：**同名文件 + 时间戳后缀 + 按天裁剪**，
//! 且只用标准库，不引入 `chrono` / `time` 这类时区依赖。
//!
//! # 与官方的一处**有意偏离**：轮转时刻按 UTC
//!
//! 官方在**本地时区**的 0 点轮转（`log.RotateFileModeDaily` 依赖
//! `time.Now()` 的本地时刻）。NFrp 的日志时间戳本身就是 **UTC**
//! （`tracing-subscriber` 默认计时器输出 `2026-10-01T09:06:58.699670Z`），
//! 所以这里按 **UTC 0 点**切分 —— 日志里的日期字段与文件名里的日期字段永远一致。
//! 若按本地时区切，UTC+8 下会出现"文件名写 10-02、里面每行都是 10-01T16:00Z"
//! 的错位，排障时反而更容易误判。
//!
//! # 行为对照（可逐条核对 `output_rotatefile.go`）
//!
//! | 场景 | 官方 | 这里 |
//! |---|---|---|
//! | `to = "console"` | 写 stdout | 写 stdout（调用方处理，不进本模块） |
//! | 首次写 | 文件在就 append，不在就新建 | 同 |
//! | 轮转 | `x.log` → `x.20260925-000000.log`，再新建空的 `x.log` | 同 |
//! | 裁剪 | 后缀时间戳早于 `now - maxDays` 的备份文件删除 | 同 |
//! | `maxDays <= 0` | 不裁剪 | 同 |
//! | 目录不存在 | `MkdirAll(0755)` | 同 |
//! | 文件权限 | 沿用已有文件的 mode，新建 0600 | 同 |

use std::{
    fs::{self, File, OpenOptions},
    io::{self, Write},
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

/// 官方 `backupTimeFormat = "20060102-150405"` 等价物。
const BACKUP_STAMP_LEN: usize = 15; // YYYYMMDD-HHMMSS

/// 拿到"现在"的时钟；抽成函数是为了测试能塞一个假的进去。
type Clock = Box<dyn Fn() -> SystemTime + Send + Sync>;

fn real_now() -> SystemTime {
    SystemTime::now()
}

/// 一个按天切分的日志文件。
///
/// 多线程安全：内部一把 `Mutex` 串行化"判断是否要轮转 + 写"。
/// 日志写入本来就是顺序的，争抢只发生在多线程同时打日志，代价可接受。
pub struct DailyFile {
    path: PathBuf,
    max_days: i64,
    now: Clock,
    inner: Mutex<State>,
}

#[derive(Default)]
struct State {
    file: Option<File>,
    /// 当前打开的文件属于哪一天（自 epoch 起的 UTC 天数）。
    day: Option<i64>,
}

impl DailyFile {
    /// 打开（必要时创建）`path` 作为日志文件；`max_days > 0` 时保留相应天数。
    pub fn open<P: AsRef<Path>>(path: P, max_days: i64) -> io::Result<Arc<Self>> {
        Self::with_clock(path, max_days, Box::new(real_now))
    }

    fn with_clock<P: AsRef<Path>>(path: P, max_days: i64, now: Clock) -> io::Result<Arc<Self>> {
        let me = Arc::new(Self {
            path: path.as_ref().to_path_buf(),
            max_days,
            now,
            inner: Mutex::new(State::default()),
        });
        // 目录建不出来就别等到第一条日志才报错 —— 启动时就暴露问题。
        if let Some(dir) = me.parent_dir() {
            fs::create_dir_all(&dir)?;
        }
        Ok(me)
    }

    /// 日志文件所在目录（相对路径且没有目录部分时返回 `None`）。
    fn parent_dir(&self) -> Option<PathBuf> {
        match self.path.parent() {
            Some(p) if !p.as_os_str().is_empty() => Some(p.to_path_buf()),
            _ => None,
        }
    }

    /// 轮转用到的三件套：`(目录, 文件名前缀, 扩展名)`。
    ///
    /// `logs/frps.log` → `("logs", "frps", ".log")`；`logs/frps` → `("logs", "frps", "")`。
    fn name_parts(&self) -> (Option<PathBuf>, String, String) {
        let file = self
            .path
            .file_name()
            .map(|s| s.to_string_lossy().into_owned())
            .unwrap_or_default();
        // `file_stem` / `extension` 对 "frps.log" 给出 ("frps", "log")；
        // 但 ".hidden" 这种会被当成"无 stem"，所以**手工**按最后一个点切，
        // 与 Go 的 `filepath.Ext`（取最后一个点之后的全部）保持一致。
        match file.rfind('.') {
            // 点在开头（`.log`）时 Go 的 Ext 也是 ".log"、prefix 为空
            Some(0) => (self.parent_dir(), String::new(), file.clone()),
            Some(i) => (
                self.parent_dir(),
                file[..i].to_string(),
                file[i..].to_string(),
            ),
            None => (self.parent_dir(), file, String::new()),
        }
    }

    /// 备份文件名：`frps.log` + 2026-09-25 00:00:00 → `frps.20260925-000000.log`。
    fn backup_name(&self, at: SystemTime) -> PathBuf {
        let (dir, prefix, ext) = self.name_parts();
        let name = format!("{prefix}.{}{ext}", stamp(at));
        match dir {
            Some(d) => d.join(name),
            None => PathBuf::from(name),
        }
    }

    /// 写一段字节。跨天时自动轮转。
    fn write_bytes(&self, buf: &[u8]) -> io::Result<()> {
        let mut g = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        let today = day_of((self.now)());
        match g.day {
            // 首次写入**不轮转**：只按官方 `openExistingOrNew` 的语义
            // "文件在就 append、不在就新建"。少这一条，昨天的日志会在
            // 启动瞬间被改名成备份、而新文件是空的 —— 看着像"日志丢了一天"。
            None => {
                g.day = Some(today);
            }
            Some(prev) if prev != today => {
                self.rotate_locked(&mut g)?;
                g.day = Some(today);
            }
            Some(_) => {}
        }
        if g.file.is_none() {
            g.file = Some(self.open_existing_or_new()?);
        }
        let f = g.file.as_mut().expect("刚填过");
        f.write_all(buf)
    }

    /// 轮转一次（等价官方的 `Rotate()`）：当前文件改名成带时间戳的备份，
    /// 再建一个新的空文件，然后按 `maxDays` 清理老备份。
    ///
    /// 供测试与"日志被切开"这类显式需求调用；正常写入路径由 [`Self::write_bytes`]
    /// 在跨天时自动触发。
    pub fn rotate(&self) -> io::Result<()> {
        let mut g = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        self.rotate_locked(&mut g)
    }

    fn rotate_locked(&self, g: &mut State) -> io::Result<()> {
        g.file = None; // 关掉旧句柄（drop 即 close）
        if self.path.exists() {
            // 只有真的有内容才值得备份：空文件改名会留下一堆 0 字节垃圾。
            if self.path.metadata().map(|m| m.len() > 0).unwrap_or(false) {
                let at = (self.now)();
                let target = self.backup_name(at);
                fs::rename(&self.path, &target)?;
            } else {
                let _ = fs::remove_file(&self.path);
            }
        }
        self.prune_locked()?;
        g.file = Some(self.create_new()?);
        Ok(())
    }

    /// 首次打开：文件在就接着 append（与官方 `openExistingOrNew` 一致），
    /// 不在就新建。**不**轮转 —— 官方启动时也不轮转。
    fn open_existing_or_new(&self) -> io::Result<File> {
        match OpenOptions::new().append(true).open(&self.path) {
            Ok(f) => Ok(f),
            Err(_) => self.create_new(),
        }
    }

    /// 新建日志文件；沿用已有文件的权限，没有则用 0600（与官方一致）。
    fn create_new(&self) -> io::Result<File> {
        if let Some(dir) = self.parent_dir() {
            fs::create_dir_all(&dir)?;
        }
        let mut opt = OpenOptions::new();
        opt.create(true).write(true).truncate(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt as _;
            let mode = fs::metadata(&self.path)
                .map(|m| m.permissions().mode())
                .ok();
            // 官方对新建文件用 0600：日志里可能有 token / 内网地址，不该给同机其他用户看。
            opt.mode(mode.unwrap_or(0o600));
        }
        opt.open(&self.path)
    }

    /// 删掉后缀时间戳早于 `now - maxDays` 的备份文件。
    fn prune_locked(&self) -> io::Result<()> {
        if self.max_days <= 0 {
            return Ok(());
        }
        let (dir, prefix, ext) = self.name_parts();
        let dir = dir.unwrap_or_else(|| PathBuf::from("."));
        // 带点前缀，避免把 `frps2.log` 当成 `frps` 的备份
        let prefix = format!("{prefix}.");
        let cutoff = (self.now)()
            .checked_sub(Duration::from_secs(
                (self.max_days.max(0) as u64).saturating_mul(24 * 3600),
            ))
            .unwrap_or(UNIX_EPOCH);
        let Ok(entries) = fs::read_dir(&dir) else {
            return Ok(());
        };
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().into_owned();
            let Some(ts) = parse_backup_stamp(&name, &prefix, &ext) else {
                continue;
            };
            if ts < cutoff {
                let _ = fs::remove_file(entry.path());
            }
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// 时间换算（只用标准库，全部按 UTC）
// ---------------------------------------------------------------------------

/// 自 Unix epoch 起的整天数。
fn day_of(t: SystemTime) -> i64 {
    secs_of(t).div_euclid(86_400)
}

fn secs_of(t: SystemTime) -> i64 {
    match t.duration_since(UNIX_EPOCH) {
        Ok(d) => d.as_secs() as i64,
        // epoch 之前的时刻（时钟被拨回去）按负值处理，不 panic
        Err(e) => -(e.duration().as_secs() as i64),
    }
}

/// `YYYYMMDD-HHMMSS`（UTC）。
fn stamp(t: SystemTime) -> String {
    let secs = secs_of(t);
    let days = secs.div_euclid(86_400);
    let rem = secs.rem_euclid(86_400);
    let (y, m, d) = civil_from_days(days);
    format!(
        "{y:04}{m:02}{d:02}-{:02}{:02}{:02}",
        rem / 3600,
        (rem % 3600) / 60,
        rem % 60
    )
}

/// 把后备文件名里的时间戳解析回 `SystemTime`；格式不符返回 `None`。
fn parse_backup_stamp(name: &str, prefix: &str, ext: &str) -> Option<SystemTime> {
    let rest = name.strip_prefix(prefix)?;
    let rest = rest.strip_suffix(ext)?;
    if rest.len() != BACKUP_STAMP_LEN || !rest.is_ascii() || &rest[8..9] != "-" {
        return None;
    }
    let num = |s: &str| s.parse::<i64>().ok();
    let y = num(&rest[0..4])?;
    let mo = num(&rest[4..6])?;
    let d = num(&rest[6..8])?;
    let h = num(&rest[9..11])?;
    let mi = num(&rest[11..13])?;
    let s = num(&rest[13..15])?;
    if !(1..=12).contains(&mo) || !(1..=31).contains(&d) || h > 23 || mi > 59 || s > 59 {
        return None;
    }
    let days = days_from_civil(y, mo as u32, d as u32);
    let total = days * 86_400 + h * 3600 + mi * 60 + s;
    if total < 0 {
        None
    } else {
        Some(UNIX_EPOCH + Duration::from_secs(total as u64))
    }
}

/// 儒略日算法（Howard Hinnant `civil_from_days`），把"自 1970-01-01 起的天数"
/// 换成公历年月日。
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64; // [0, 146096]
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365; // [0, 399]
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
    let mp = (5 * doy + 2) / 153; // [0, 11]
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32; // [1, 31]
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32; // [1, 12]
    (if m <= 2 { y + 1 } else { y }, m, d)
}

/// `civil_from_days` 的逆运算。
fn days_from_civil(y: i64, m: u32, d: u32) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = (y - era * 400) as u64;
    let mp = if m > 2 { m - 3 } else { m + 9 } as u64;
    let doy = (153 * mp + 2) / 5 + d as u64 - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe as i64 - 719_468
}

// ---------------------------------------------------------------------------
// 接进 tracing
// ---------------------------------------------------------------------------

/// 给 `tracing-subscriber` 用的写入器：每写一次就落到 [`DailyFile`]。
#[derive(Clone)]
pub struct DailyFileWriter(Arc<DailyFile>);

impl DailyFileWriter {
    pub fn new(file: Arc<DailyFile>) -> Self {
        Self(file)
    }
}

impl Write for DailyFileWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0.write_bytes(buf)?;
        Ok(buf.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for DailyFileWriter {
    type Writer = Self;
    fn make_writer(&'a self) -> Self::Writer {
        self.clone()
    }
}

/// 把 `log.to` 解释成写入器。
///
/// 返回 `None` 表示"照旧写控制台"：`to` 为空或 `console`（大小写不敏感）。
/// `to` 指向的文件打不开时**回落到控制台并打一条警告**，而不是让进程起不来 ——
/// 日志写不进去固然要报警，但比服务起不来轻得多。
pub fn sink_from_config(to: &str, max_days: i64) -> Option<DailyFileWriter> {
    let to = to.trim();
    if to.is_empty() || to.eq_ignore_ascii_case("console") {
        return None;
    }
    match DailyFile::open(to, max_days) {
        Ok(f) => Some(DailyFileWriter::new(f)),
        Err(e) => {
            eprintln!("日志文件 {to} 打不开（{e}），已回落到控制台输出");
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 临时目录（不依赖外部 crate）。
    fn tmpdir(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!(
            "nfrp-logfile-{tag}-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(&d).unwrap();
        d
    }

    fn at(secs: i64) -> SystemTime {
        UNIX_EPOCH + Duration::from_secs(secs as u64)
    }

    /// 2026-09-25 00:00:00 UTC
    const D1: i64 = 1_790_294_400;
    const DAY: i64 = 86_400;

    #[test]
    fn 时间戳格式与官方一致() {
        assert_eq!(stamp(at(D1)), "20260925-000000");
        assert_eq!(stamp(at(D1 + 3661)), "20260925-010101");
        // 跨天：2026-09-26
        assert_eq!(stamp(at(D1 + DAY)), "20260926-000000");
    }

    #[test]
    fn 公历换算能来回走() {
        for z in [-20_000i64, -1, 0, 1, 20_000, 20_700] {
            let (y, m, d) = civil_from_days(z);
            assert_eq!(days_from_civil(y, m, d), z, "{z} -> {y}-{m}-{d}");
        }
        assert_eq!(civil_from_days(0), (1970, 1, 1));
    }

    #[test]
    fn 后备名解析只认自家格式() {
        let sz = |s: &str| parse_backup_stamp(s, "frps.", ".log");
        assert!(sz("frps.20260925-000000.log").is_some());
        assert!(sz("frps.log").is_none());
        assert!(sz("frps2.20260925-000000.log").is_none());
        assert!(sz("frps.20260925-000000.txt").is_none());
        assert!(sz("frps.20261325-000000.log").is_none(), "13 月必须落空");
        assert!(sz("frps.20260925T000000.log").is_none());
    }

    #[test]
    fn 首次写入会在文件不存在时新建() {
        let d = tmpdir("first");
        let p = d.join("frps.log");
        let f = DailyFile::with_clock(&p, 3, Box::new(|| at(D1))).unwrap();
        f.write_bytes(b"hello\n").unwrap();
        assert_eq!(fs::read_to_string(&p).unwrap(), "hello\n");
        fs::remove_dir_all(&d).ok();
    }

    #[test]
    fn 已有文件是追加而不是覆盖() {
        let d = tmpdir("append");
        let p = d.join("frps.log");
        fs::write(&p, "old\n").unwrap();
        let f = DailyFile::with_clock(&p, 3, Box::new(|| at(D1))).unwrap();
        f.write_bytes(b"new\n").unwrap();
        assert_eq!(fs::read_to_string(&p).unwrap(), "old\nnew\n");
        fs::remove_dir_all(&d).ok();
    }

    #[test]
    fn 跨天会自动轮转且文件名带时间戳() {
        let d = tmpdir("rotate");
        let p = d.join("frps.log");
        let clock = Arc::new(Mutex::new(at(D1)));
        let c2 = clock.clone();
        let f = DailyFile::with_clock(&p, 3, Box::new(move || *c2.lock().unwrap())).unwrap();

        f.write_bytes(b"day1\n").unwrap();
        // 拨到第二天
        *clock.lock().unwrap() = at(D1 + DAY);
        f.write_bytes(b"day2\n").unwrap();

        assert_eq!(
            fs::read_to_string(&p).unwrap(),
            "day2\n",
            "新文件只装新一天"
        );
        // 备份名里的时间戳是**轮转发生的时刻**（官方 `backupName(name, clock.Now())`
        // 也是这个语义），所以这里带的是第二天的零点。
        let backup = d.join("frps.20260926-000000.log");
        assert!(
            backup.exists(),
            "备份名必须是 frps.<轮转时刻>.log，实际目录：{:?}",
            fs::read_dir(&d)
                .unwrap()
                .flatten()
                .map(|e| e.file_name())
                .collect::<Vec<_>>()
        );
        assert_eq!(fs::read_to_string(&backup).unwrap(), "day1\n");
        fs::remove_dir_all(&d).ok();
    }

    #[test]
    fn 超过保留天数的备份会被删掉() {
        let d = tmpdir("prune");
        let p = d.join("frps.log");
        // 三个老备份：1 天前 / 5 天前 / 10 天前
        fs::write(d.join("frps.20260924-000000.log"), "d-1\n").unwrap();
        fs::write(d.join("frps.20260920-000000.log"), "d-5\n").unwrap();
        fs::write(d.join("frps.20260915-000000.log"), "d-10\n").unwrap();
        let f = DailyFile::with_clock(&p, 3, Box::new(|| at(D1))).unwrap();
        f.write_bytes(b"now\n").unwrap();
        f.rotate().unwrap();

        assert!(d.join("frps.20260924-000000.log").exists(), "1 天前该留着");
        assert!(!d.join("frps.20260920-000000.log").exists(), "5 天前该删");
        assert!(!d.join("frps.20260915-000000.log").exists(), "10 天前该删");
        // 新文件与本次轮转产生的备份都在
        assert!(p.exists());
        assert!(d.join("frps.20260925-000000.log").exists());
        fs::remove_dir_all(&d).ok();
    }

    #[test]
    fn max_days_为零时不裁剪() {
        let d = tmpdir("noprune");
        let p = d.join("frps.log");
        fs::write(d.join("frps.20200101-000000.log"), "ancient\n").unwrap();
        let f = DailyFile::with_clock(&p, 0, Box::new(|| at(D1))).unwrap();
        f.write_bytes(b"now\n").unwrap();
        f.rotate().unwrap();
        assert!(
            d.join("frps.20200101-000000.log").exists(),
            "maxDays=0 语义是「不裁剪」"
        );
        fs::remove_dir_all(&d).ok();
    }

    #[test]
    fn 空文件不产生垃圾备份() {
        let d = tmpdir("empty");
        let p = d.join("frps.log");
        fs::write(&p, "").unwrap();
        let f = DailyFile::with_clock(&p, 3, Box::new(|| at(D1))).unwrap();
        f.rotate().unwrap();
        let names: Vec<String> = fs::read_dir(&d)
            .unwrap()
            .flatten()
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .collect();
        assert_eq!(names, vec!["frps.log".to_string()], "0 字节不该留备份");
        fs::remove_dir_all(&d).ok();
    }

    #[test]
    fn 目录不存在会自动建() {
        let d = tmpdir("mkdir");
        let p = d.join("nested").join("deep").join("frps.log");
        let f = DailyFile::with_clock(&p, 3, Box::new(|| at(D1))).unwrap();
        f.write_bytes(b"x\n").unwrap();
        assert!(p.exists());
        fs::remove_dir_all(&d).ok();
    }

    #[test]
    fn console_与空值都回落到控制台() {
        assert!(sink_from_config("", 3).is_none());
        assert!(sink_from_config("console", 3).is_none());
        assert!(sink_from_config("CONSOLE", 3).is_none());
        // 打不开的路径也不 panic，只是回落
        assert!(sink_from_config("Z:/definitely/not/here/x.log", 3).is_none());
    }

    #[test]
    fn 写入器能真的落盘() {
        let d = tmpdir("writer");
        let p = d.join("frps.log");
        let f = DailyFile::with_clock(&p, 3, Box::new(|| at(D1))).unwrap();
        let mut w = DailyFileWriter::new(f);
        w.write_all(b"line1\n").unwrap();
        w.write_all(b"line2\n").unwrap();
        assert_eq!(fs::read_to_string(&p).unwrap(), "line1\nline2\n");
        fs::remove_dir_all(&d).ok();
    }
}
