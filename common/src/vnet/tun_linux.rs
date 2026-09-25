//! Linux 的 TUN 设备实现（`/dev/net/tun`）。
//!
//! # 建设备的四步
//!
//! 1. `open("/dev/net/tun", O_RDWR)` —— 拿到一个普通 fd；
//! 2. `ioctl(fd, TUNSETIFF, &ifreq)` —— **这一步才把 fd 变成网卡**，
//!    `ifr_name` 里写期望的名字、`ifr_flags` 里写 `IFF_TUN | IFF_NO_PI`；
//! 3. 内核把实际用的名字回填进 `ifreq.ifr_name`（名字带 `%d` 时由内核挑号）；
//! 4. 把 fd 设成非阻塞，交给 tokio 的 `AsyncFd` 做就绪通知。
//!
//! # `IFF_NO_PI` 是关键
//!
//! 不加这个 flag，内核会在每个包的**前面**塞 4 字节 `struct tun_pi`
//! （flags + proto）。那样读出来的就不再是裸 IP 报文，而我们按 IP 头解析地址
//! 会全错（把 tun_pi 的 proto 当成 IP 版本号）。加了它才是干净的 IP 包。
//!
//! # 为什么要配 IP / 起网卡
//!
//! `TUNSETIFF` 只是把设备建出来，**既不配地址也不 up**。这两件事必须靠
//! `ip addr add` / `ip link set up`（或 netlink）完成，需要 root。
//! 这里用 `ip` 命令而不是 netlink：netlink 要写几百行，而 `iproute2`
//! 在目标环境里几乎必然存在；失败时把命令原文回给用户，他自己敲一遍就能复现。

use std::io;
use std::os::fd::{AsRawFd, RawFd};
use std::pin::Pin;
use std::task::{Context, Poll};

use tokio::io::unix::AsyncFd;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use super::MAX_IP_PACKET;

/// `/dev/net/tun`，Linux 上唯一的 TUN 设备节点。
const TUN_PATH: &str = "/dev/net/tun";

/// `IFF_TUN`：三层设备（只有 IP 报文，没有以太头）。
const IFF_TUN: libc::c_short = 0x0001;
/// `IFF_NO_PI`：不要 4 字节的 `tun_pi` 前缀，读写都是裸 IP 包。
const IFF_NO_PI: libc::c_short = 0x1000;

/// `struct ifreq` 在 x86_64 / aarch64 上都是 40 字节：
/// `char ifr_name[16]` + 24 字节的 union（我们只用其中的 `short ifr_flags`）。
#[repr(C)]
#[derive(Clone, Copy)]
struct IfReq {
    name: [u8; libc::IFNAMSIZ],
    flags: libc::c_short,
    _pad: [u8; 22],
}

impl IfReq {
    fn new(name: &str) -> Self {
        let mut r = Self {
            name: [0; libc::IFNAMSIZ],
            flags: 0,
            _pad: [0; 22],
        };
        let b = name.as_bytes();
        let n = b.len().min(libc::IFNAMSIZ - 1);
        r.name[..n].copy_from_slice(&b[..n]);
        r
    }

    /// 内核回填的设备名（截到第一个 NUL）。
    fn resolved_name(&self) -> String {
        let end = self
            .name
            .iter()
            .position(|c| *c == 0)
            .unwrap_or(self.name.len());
        String::from_utf8_lossy(&self.name[..end]).to_string()
    }
}

/// Linux 上的平台无关入口，与 [`super::open_tun`] 的签名严格一致。
///
/// `addr` / `peer` 传 `None` 表示只建设备、不配地址（调用方拿到服务端
/// 分配的地址之后再自己配）—— 但那样设备是 up 不起来的，所以正常路径
/// 都是拿到地址后一次建好。
pub fn open_tun(
    name: &str,
    mtu: u32,
    addr: Option<&str>,
    peer: Option<&str>,
) -> anyhow::Result<Tun> {
    Tun::create_with_params(name, mtu, addr, peer)
}

/// 一个已就绪的 TUN 设备。读写都是**裸 IP 报文**（无以太头、无 tun_pi）。
pub struct Tun {
    fd: AsyncFd<OwnedFd>,
    name: String,
    mtu: u32,
}

struct OwnedFd(RawFd);

impl AsRawFd for OwnedFd {
    fn as_raw_fd(&self) -> RawFd {
        self.0
    }
}

impl Drop for OwnedFd {
    fn drop(&mut self) {
        // 关掉 fd 会自动销毁这个 TUN 设备（内核语义），不需要显式 TUNSETPERSIST 撤销
        unsafe { libc::close(self.0) };
    }
}

impl Tun {
    /// 创建设备并**把地址配上、网卡 up**。
    ///
    /// `addr` 形如 `100.64.0.2/24`；`name` 留空时由内核挑（`tun%d`）。
    pub fn create(name: &str, mtu: u32, addr: Option<&str>) -> anyhow::Result<Self> {
        Self::create_with_params(name, mtu, addr, None)
    }

    /// 完整版：可以指定点对点对端地址（`ip addr add <addr> peer <peer>`）。
    ///
    /// 给 `peer` 是为了让"路由表里没有的地址"自动走 TUN —— 只有这样
    /// 服务端网关之外的流量才会被抓进隧道，否则用户还得自己加路由。
    pub fn create_with_params(
        name: &str,
        mtu: u32,
        addr: Option<&str>,
        peer: Option<&str>,
    ) -> anyhow::Result<Self> {
        let raw = unsafe { libc::open(c_tun_path(), libc::O_RDWR | libc::O_CLOEXEC) };
        if raw < 0 {
            let e = io::Error::last_os_error();
            return Err(anyhow::anyhow!(
                "打开 {TUN_PATH} 失败：{e}。\
                 通常是权限不足（需要 CAP_NET_ADMIN，即 root）或容器没挂 /dev/net/tun。"
            ));
        }

        let mut req = IfReq::new(name);
        // 没指定名字时给个模板，让内核挑号（`tun0` / `tun1`…）
        if req.name[0] == 0 {
            req.name[..4].copy_from_slice(b"tun%d");
        }
        req.flags = IFF_TUN | IFF_NO_PI;

        let rc = unsafe { libc::ioctl(raw, tunsetiff(), &mut req as *mut IfReq) };
        if rc < 0 {
            let e = io::Error::last_os_error();
            unsafe { libc::close(raw) };
            return Err(anyhow::anyhow!(
                "ioctl(TUNSETIFF) 失败：{e}。\
                 常见原因：名字里带了非法字符、同名设备已存在、或没有 CAP_NET_ADMIN。"
            ));
        }
        let dev = req.resolved_name();

        // 交给 AsyncFd；它要求 fd 是非阻塞的
        if let Err(e) = set_nonblocking(raw) {
            unsafe { libc::close(raw) };
            return Err(e);
        }

        let tun = Self {
            fd: AsyncFd::new(OwnedFd(raw))?,
            name: dev,
            mtu,
        };

        // 配地址 + up。失败就把设备还回去 —— 留一个没有地址的网卡只会误导人。
        // 这里必须写成 `?`（clippy::question_mark；同样是本机 Windows 编不到、
        // 只有云端 clippy 才能发现的那类问题）。
        if let Some(a) = addr {
            tun.configure(a, peer, mtu)?;
        }
        Ok(tun)
    }

    /// 用 `ip` 命令配地址、设 MTU、把网卡拉起来。
    fn configure(&self, addr: &str, peer: Option<&str>, mtu: u32) -> anyhow::Result<()> {
        let addr_spec = match peer {
            // `ip addr add 100.64.0.2/24 peer 100.64.0.1 dev tun0`
            Some(p) => format!("{addr} peer {p}"),
            None => addr.to_string(),
        };
        // MTU 要先落到一个具名绑定里：`&mtu.to_string()` 那种临时值的借用
        // 活不过这条语句，Linux 上会直接 E0716（本机 Windows 编不到这段代码，
        // 所以只能在云端暴露 —— 已踩过一次）。
        let mtu_s = mtu.to_string();
        let script = [
            vec!["addr", "add", &addr_spec, "dev", &self.name],
            vec!["link", "set", &self.name, "mtu", &mtu_s],
            vec!["link", "set", &self.name, "up"],
        ];
        for args in script {
            let out = std::process::Command::new("ip").args(&args).output();
            match out {
                Ok(o) if o.status.success() => {}
                Ok(o) => {
                    let err = String::from_utf8_lossy(&o.stderr).trim().to_string();
                    // "RTNETLINK answers: File exists" 表示地址已经在了，重复配不是错
                    if err.contains("File exists") {
                        continue;
                    }
                    return Err(anyhow::anyhow!(
                        "配置 TUN 网卡失败：ip {} —— {err}",
                        args.join(" ")
                    ));
                }
                Err(e) => {
                    return Err(anyhow::anyhow!(
                        "执行 `ip` 命令失败：{e}。\
                         需要 iproute2（Debian/Ubuntu: apt install iproute2）。"
                    ))
                }
            }
        }
        Ok(())
    }

    /// 断线重连后把地址换成新的（服务端重启、地址池换网段都会发生）。
    ///
    /// 用 `ip addr replace` 而不是先 del 再 add：replace 对"没有旧地址"和
    /// "已有同地址"两种情形都是幂等的，掉线期间不会出现一个短暂无地址的窗口
    /// （那几毫秒里出去的包会以错误的源地址发出去）。
    ///
    /// 只动这一个地址，**绝不碰默认路由** —— 一个默默把你所有流量劫走的
    /// 内网穿透工具是灾难，要不要走虚拟网络上网得让用户自己决定。
    pub fn set_address(&self, addr_spec: &str) -> anyhow::Result<()> {
        let addr_spec = addr_spec.to_string();
        let script = [
            vec!["addr", "replace", &addr_spec, "dev", &self.name],
            vec!["link", "set", &self.name, "up"],
        ];
        for args in script {
            let out = std::process::Command::new("ip").args(&args).output();
            match out {
                Ok(o) if o.status.success() => {}
                Ok(o) => {
                    let err = String::from_utf8_lossy(&o.stderr).trim().to_string();
                    return Err(anyhow::anyhow!("ip {} 失败：{err}", args.join(" ")));
                }
                Err(e) => return Err(anyhow::anyhow!("执行 `ip` 命令失败：{e}")),
            }
        }
        Ok(())
    }

    /// 设备名，如 `tun0`。
    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn mtu(&self) -> u32 {
        self.mtu
    }

    /// 底层 fd（诊断用）。
    pub fn raw_fd(&self) -> RawFd {
        self.fd.as_raw_fd()
    }
}

impl AsyncRead for Tun {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        loop {
            let mut guard = match this.fd.poll_read_ready(cx) {
                Poll::Ready(Ok(g)) => g,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            };
            // `initialize_unfilled` 把"未初始化"的那段当成已初始化交给我们。
            // 不用 `unfilled_mut` / `assume_init` —— 那两个还在 nightly 上。
            let res = guard.try_io(|inner| {
                let dst = buf.initialize_unfilled();
                let want = dst.len().min(MAX_IP_PACKET);
                let n = unsafe {
                    libc::read(
                        inner.as_raw_fd(),
                        dst.as_mut_ptr() as *mut libc::c_void,
                        want,
                    )
                };
                if n < 0 {
                    Err(io::Error::last_os_error())
                } else {
                    Ok(n as usize)
                }
            });
            match res {
                Ok(Ok(n)) => {
                    buf.advance(n);
                    return Poll::Ready(Ok(()));
                }
                // WouldBlock：就绪状态是"假"的，重新登记等待
                Ok(Err(e)) if e.kind() == io::ErrorKind::WouldBlock => continue,
                Ok(Err(e)) => return Poll::Ready(Err(e)),
                Err(_would_block) => continue,
            }
        }
    }
}

impl AsyncWrite for Tun {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        loop {
            let mut guard = match this.fd.poll_write_ready(cx) {
                Poll::Ready(Ok(g)) => g,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            };
            let res = guard.try_io(|inner| {
                let n = unsafe {
                    libc::write(
                        inner.as_raw_fd(),
                        buf.as_ptr() as *const libc::c_void,
                        buf.len(),
                    )
                };
                if n < 0 {
                    Err(io::Error::last_os_error())
                } else {
                    Ok(n as usize)
                }
            });
            match res {
                Ok(Ok(n)) => return Poll::Ready(Ok(n)),
                Ok(Err(e)) if e.kind() == io::ErrorKind::WouldBlock => continue,
                Ok(Err(e)) => return Poll::Ready(Err(e)),
                Err(_) => continue,
            }
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        // TUN 的 write 是直接投递到内核协议栈，没有用户态缓冲要刷
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

// ---------------------------------------------------------------------------
// 平台调用
// ---------------------------------------------------------------------------

/// `TUNSETIFF` 的请求码（函数名按 Rust 习惯小写 —— 大写会触发 non_snake_case，
/// 而这段代码只在 Linux 上参与编译，本机 Windows 的 clippy 看不到它）。
///
/// Linux 的 `_IOW('T', 202, int)`：`dir=1(write)`、`size=4`、`type='T'`、`nr=202`
/// ⇒ `0x400454ca`。直接写常量而不是引 `libc` 的宏，是因为 libc 里这个宏
/// 在部分架构上被定义成函数式的，取值反而更绕。
///
/// ★ **返回类型必须是 `libc::Ioctl`，不能写死 `c_ulong`**：libc 的
/// `ioctl(fd: c_int, request: Ioctl, ...)` 里 `Ioctl` 是按目标 libc 分的
/// —— glibc / uclibc 是 `c_ulong`(u64)，**musl 与 android 是 `c_int`(i32)**
/// （见 libc `unix/linux_like/linux/musl/mod.rs`）。写死 `c_ulong` 时
/// glibc 目标编得过、musl 目标直接
/// `error[E0308]: mismatched types —— expected i32, found u64`。
/// 而这段又是 `cfg(target_os = "linux")`，本机 Windows 编不到它，
/// 只有 CI 的 musl 交叉编译才会暴露 ⇒ 用 libc 自己的别名，两边都对。
/// 取值 `0x400454ca` 只有 31 位，窄化到 i32 不丢信息。
fn tunsetiff() -> libc::Ioctl {
    const DIR_WRITE: libc::Ioctl = 1;
    const SIZE_INT: libc::Ioctl = 4;
    const TYPE_T: libc::Ioctl = b'T' as libc::Ioctl;
    const NR: libc::Ioctl = 202;
    (DIR_WRITE << 30) | (SIZE_INT << 16) | (TYPE_T << 8) | NR
}

/// `/dev/net/tun` 的 C 字符串（每次调用重建，避免用 `static mut`）。
fn c_tun_path() -> *const libc::c_char {
    // 尾部 NUL 靠字面量自带
    b"/dev/net/tun\0".as_ptr() as *const libc::c_char
}

fn set_nonblocking(fd: RawFd) -> anyhow::Result<()> {
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags < 0 {
        return Err(anyhow::anyhow!(
            "fcntl(F_GETFL) 失败：{}",
            io::Error::last_os_error()
        ));
    }
    let rc = unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) };
    if rc < 0 {
        return Err(anyhow::anyhow!(
            "fcntl(F_SETFL) 失败：{}",
            io::Error::last_os_error()
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// ioctl 请求码必须与内核头文件一致，写错就是 EINVAL，
    /// 而现象只是"打不开网卡"，非常难查 —— 所以直接对着常量断言。
    #[test]
    fn tunsetiff_请求码() {
        assert_eq!(tunsetiff(), 0x400454ca);
    }

    #[test]
    fn ifreq_大小与名字回填() {
        assert_eq!(
            std::mem::size_of::<IfReq>(),
            40,
            "struct ifreq 在 64 位 Linux 上是 40 字节"
        );
        let mut r = IfReq::new("tun0");
        assert_eq!(r.resolved_name(), "tun0");
        // 名字过长要被截断并保留结尾 NUL
        let long = IfReq::new("0123456789abcdefghij");
        assert_eq!(long.resolved_name().len(), libc::IFNAMSIZ - 1);
        // 内核回填：模拟把 tun%d 换成 tun3
        r.name[3] = b'3';
        assert_eq!(r.resolved_name(), "tun3");
    }

    /// 没有 root / 没有 /dev/net/tun 时必须是**清晰的报错**，
    /// 而不是 panic 或者返回一个不能用的设备。
    #[test]
    fn 无权限时报错而不是恐慌() {
        match Tun::create("nfrp-test-%d", 1400, None) {
            Ok(t) => {
                // 有权限的环境（root）下真的建出来了，至少要能 self-consistent
                assert!(t.name().starts_with("nfrp-test-"), "{}", t.name());
                assert!(t.raw_fd() >= 0);
            }
            Err(e) => {
                let s = e.to_string();
                assert!(
                    s.contains("权限") || s.contains("CAP_NET_ADMIN") || s.contains("tun"),
                    "错误信息要能指导排查，实际：{s}"
                );
            }
        }
    }
}
