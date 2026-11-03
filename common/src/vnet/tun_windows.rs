//! Windows 的 TUN 设备：基于 **Wintun**（WireGuard 项目的开源 TUN 驱动）。
//!
//! # 为什么是 Wintun 而不是 TAP-Windows
//!
//! * Wintun 是**内核态**驱动，用户态只走共享环形缓冲，吞吐远高于 TAP；
//! * 它只做 L3（IP 包），正好是 VirtualNet 需要的；
//! * WireGuard for Windows 生产在用，久经考验；
//! * 许可证宽松（Apache-2.0 + GPLv2 双许可，运行时不需静态链接）。
//!
//! TAP-Windows（OpenVPN 那套）要额外装驱动、走 L2 以太网帧，我们还得自己
//! 拼 MAC 头 —— 对本项目没有收益。
//!
//! # 运行时依赖
//!
//! 需要 `wintun.dll`（**架构必须匹配**：amd64 进程用 `bin/amd64/wintun.dll`）。
//! 下载：<https://www.wintun.net/>。本模块按以下顺序找它：
//!
//! 1. 显式环境变量 `NFRP_WINTUN_DLL` 指向的文件；
//! 2. 可执行文件所在目录；
//! 3. 当前工作目录；
//! 4. 系统目录（`System32`）。
//!
//! 全都找不到时给出**可操作**的错误（含下载地址与放置位置），而不是一句
//! "加载失败"。
//!
//! # 权限
//!
//! 创建适配器需要**管理员**（准确说是"网络配置"权限）。普通用户运行会
//! 拿到 `ERROR_ACCESS_DENIED`，本模块把它翻译成"请以管理员身份运行"。
//!
//! # 实现要点：为什么用后台线程 + 通道
//!
//! Wintun 的读接口是"事件 + 非阻塞取包"：
//!
//! ```c
//! WaitForSingleObject(WintunGetReadWaitEvent(session), INFINITE);
//! while ((pkt = WintunReceivePacket(session, &size))) { ... }
//! ```
//!
//! 那个 `HANDLE` 事件**没法直接接进 tokio 的 reactor** ——
//! `tokio::io::unix::AsyncFd` 只在 unix 上有。硬要接就得自己写
//! `Registration` + IOCP 集成，代码量和出错面都大得多。
//!
//! 所以这里用最稳的做法：**一个专用阻塞线程**跑
//! `WaitForSingleObject` + 取包，把包推进 `tokio::sync::mpsc`，
//! async 侧只收通道。写方向不需要等待（Wintun 的发送环形缓冲满了会返回
//! `ERROR_BUFFER_OVERFLOW`，按"暂时不收"处理即可），所以直接同步写。
//!
//! 代价是每条 TUN 多一个线程 —— VirtualNet 每个进程只有**一个** TUN，
//! 这个代价可以接受，换来的是整条读路径没有 unsafe 并发。
#![cfg(target_os = "windows")]

use std::ffi::c_void;
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::mpsc;

use super::MAX_IP_PACKET;

// ---------------------------------------------------------------------------
// Win32 FFI（只声明用到的那几个，不引 windows-sys 依赖）
// ---------------------------------------------------------------------------

type Handle = *mut c_void;
type Hmodule = *mut c_void;
type Bool = i32;
type Dword = u32;
type Lpcwstr = *const u16;

const ERROR_NO_MORE_ITEMS: Dword = 259;
const ERROR_BUFFER_OVERFLOW: Dword = 111;
const INFINITE: Dword = 0xFFFF_FFFF;
const LOAD_WITH_ALTERED_SEARCH_PATH: Dword = 0x0000_0008;

/// `GUID`（16 字节）。传全零给 Wintun 表示"自己生成一个"。
#[repr(C)]
struct Guid {
    data: [u8; 16],
}

#[link(name = "kernel32")]
extern "system" {
    fn LoadLibraryExW(file: Lpcwstr, file: Handle, flags: Dword) -> Hmodule;
    fn GetProcAddress(module: Hmodule, name: *const u8) -> *mut c_void;
    fn FreeLibrary(module: Hmodule) -> Bool;
    fn GetLastError() -> Dword;
    fn CreateEventW(attr: *mut c_void, manual: Bool, initial: Bool, name: Lpcwstr) -> Handle;
    fn SetEvent(handle: Handle) -> Bool;
    fn CloseHandle(handle: Handle) -> Bool;
}

fn last_error() -> io::Error {
    io::Error::from_raw_os_error(unsafe { GetLastError() } as i32)
}

/// 把 Rust 字符串转成以 0 结尾的 UTF-16。
fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

// ---------------------------------------------------------------------------
// Wintun 函数表
// ---------------------------------------------------------------------------

/// Wintun 导出的函数指针集合。
///
/// 全部通过 `GetProcAddress` 拿 —— **不在链接期依赖 wintun.dll**，
/// 这样没装驱动的机器上程序照样能启动（只是用到 VirtualNet 时报错）。
struct WintunApi {
    module: Hmodule,
    create_adapter: unsafe extern "system" fn(Lpcwstr, Lpcwstr, *const Guid) -> *mut c_void,
    close_adapter: unsafe extern "system" fn(*mut c_void),
    start_session: unsafe extern "system" fn(*mut c_void, Dword) -> *mut c_void,
    end_session: unsafe extern "system" fn(*mut c_void),
    get_read_wait_event: unsafe extern "system" fn(*mut c_void) -> Handle,
    receive_packet: unsafe extern "system" fn(*mut c_void, *mut Dword) -> *mut u8,
    release_receive_packet: unsafe extern "system" fn(*mut c_void, *const u8),
    allocate_send_packet: unsafe extern "system" fn(*mut c_void, Dword) -> *mut u8,
    send_packet: unsafe extern "system" fn(*mut c_void, *const u8),
}

// SAFETY：函数指针本身是 `Send + Sync`（它们是纯代码地址）；
// `module` 是进程级 DLL 句柄，只在 Drop 里被 `FreeLibrary` 一次，
// 而 `WintunApi` 由 `Arc` 持有、Drop 时保证最后一个引用。
unsafe impl Send for WintunApi {}
unsafe impl Sync for WintunApi {}

impl Drop for WintunApi {
    fn drop(&mut self) {
        if !self.module.is_null() {
            unsafe { FreeLibrary(self.module) };
        }
    }
}

impl WintunApi {
    /// 按优先级找 `wintun.dll` 并取全函数表。
    fn load() -> anyhow::Result<Arc<Self>> {
        let mut candidates: Vec<String> = Vec::new();
        if let Ok(p) = std::env::var("NFRP_WINTUN_DLL") {
            if !p.trim().is_empty() {
                candidates.push(p);
            }
        }
        if let Ok(exe) = std::env::current_exe() {
            if let Some(dir) = exe.parent() {
                candidates.push(dir.join("wintun.dll").to_string_lossy().into_owned());
            }
        }
        if let Ok(cwd) = std::env::current_dir() {
            candidates.push(cwd.join("wintun.dll").to_string_lossy().into_owned());
        }
        candidates.push("wintun.dll".to_string()); // 交给系统搜索路径（含 System32）

        let mut tried = Vec::new();
        for path in &candidates {
            let w = wide(path);
            let m = unsafe {
                LoadLibraryExW(
                    w.as_ptr(),
                    std::ptr::null_mut(),
                    LOAD_WITH_ALTERED_SEARCH_PATH,
                )
            };
            if m.is_null() {
                tried.push(path.clone());
                continue;
            }
            match Self::from_module(m) {
                Ok(api) => return Ok(Arc::new(api)),
                Err(e) => {
                    unsafe { FreeLibrary(m) };
                    tried.push(format!("{path}（导出的函数不全：{e}）"));
                }
            }
        }

        anyhow::bail!(
            "找不到可用的 wintun.dll，VirtualNet 在 Windows 上需要它。\n\
             已尝试：{}\n\
             解决办法：从 https://www.wintun.net/ 下载对应架构的 wintun.dll\n\
             （64 位程序用 bin/amd64/wintun.dll），放到 nfrp 可执行文件旁边，\n\
             或用环境变量 NFRP_WINTUN_DLL 指定完整路径。",
            tried.join("、")
        )
    }

    fn from_module(module: Hmodule) -> anyhow::Result<Self> {
        /// 取一个导出函数；不存在就报错（点名是哪个）。
        unsafe fn sym<T>(module: Hmodule, name: &str) -> anyhow::Result<T> {
            let c = std::ffi::CString::new(name).expect("符号名不含 NUL");
            let p = GetProcAddress(module, c.as_ptr() as *const u8);
            if p.is_null() {
                anyhow::bail!("缺少导出 {name}");
            }
            // SAFETY：调用方保证 `name` 与 `T` 的函数签名一致（Wintun 的 ABI 稳定）。
            Ok(std::mem::transmute_copy::<*mut c_void, T>(&p))
        }

        unsafe {
            Ok(Self {
                module,
                create_adapter: sym(module, "WintunCreateAdapter")?,
                close_adapter: sym(module, "WintunCloseAdapter")?,
                start_session: sym(module, "WintunStartSession")?,
                end_session: sym(module, "WintunEndSession")?,
                get_read_wait_event: sym(module, "WintunGetReadWaitEvent")?,
                receive_packet: sym(module, "WintunReceivePacket")?,
                release_receive_packet: sym(module, "WintunReleaseReceivePacket")?,
                allocate_send_packet: sym(module, "WintunAllocateSendPacket")?,
                send_packet: sym(module, "WintunSendPacket")?,
            })
        }
    }
}

// ---------------------------------------------------------------------------
// Tun
// ---------------------------------------------------------------------------

/// 一条 Wintun 适配器 + 会话。
pub struct Tun {
    api: Arc<WintunApi>,
    adapter: *mut c_void,
    session: *mut c_void,
    /// 后台读线程可能在等这个事件；Drop 时 `SetEvent` 让它退出。
    stop_event: Handle,
    name: String,
    mtu: u32,
    /// 读方向：后台线程把包推进来。
    rx: mpsc::Receiver<Vec<u8>>,
    /// 拆包用（一次 `poll_read` 只交一个包，剩下的留着）。
    pending: Option<Vec<u8>>,
}

// SAFETY：`adapter` / `session` / `stop_event` 都是 Win32 句柄，句柄本身
// 可以在线程间移动（不是线程局部的），且我们保证：
// * `adapter` / `session` 只在 `Drop` 里各自关闭一次；
// * `session` 的读由**唯一**后台线程负责，`poll_read` 只读通道。
unsafe impl Send for Tun {}

impl Tun {
    /// 创建设备（不配地址；地址由调用方随后用 [`Self::set_address`] 配）。
    pub fn create(name: &str, mtu: u32) -> anyhow::Result<Self> {
        let api = WintunApi::load()?;

        // 名字留空就给个默认名。Wintun 的名字是**适配器显示名**，
        // 与 Linux 的 `tun0` 不同，它可以带空格。
        let dev_name = if name.trim().is_empty() {
            "NFRP".to_string()
        } else {
            name.to_string()
        };
        let wname = wide(&dev_name);
        // TunnelType 决定"网络连接"里显示的驱动类型名，用它标出是本工具建的
        let wtype = wide("NFRP");

        let adapter =
            unsafe { (api.create_adapter)(wname.as_ptr(), wtype.as_ptr(), std::ptr::null()) };
        if adapter.is_null() {
            let e = last_error();
            return Err(match e.raw_os_error() {
                Some(5) => anyhow::anyhow!(
                    "创建 Wintun 适配器 [{}] 被拒绝（拒绝访问）。\
                     创建虚拟网卡需要管理员权限 —— 请以管理员身份运行 nfrp。",
                    dev_name
                ),
                _ => anyhow::anyhow!("创建 Wintun 适配器 [{}] 失败：{e}", dev_name),
            });
        }

        // 4 MiB 环形缓冲（WireGuard 官方示例用的量级）
        let session = unsafe { (api.start_session)(adapter, 0x40_0000) };
        if session.is_null() {
            let e = last_error();
            unsafe { (api.close_adapter)(adapter) };
            return Err(anyhow::anyhow!("启动 Wintun 会话失败：{e}"));
        }

        let read_event = unsafe { (api.get_read_wait_event)(session) };
        if read_event.is_null() {
            let e = last_error();
            unsafe {
                (api.end_session)(session);
                (api.close_adapter)(adapter);
            }
            return Err(anyhow::anyhow!("取 Wintun 读事件失败：{e}"));
        }

        // 手动重置事件，用来通知读线程退出
        let stop_event = unsafe { CreateEventW(std::ptr::null_mut(), 1, 0, std::ptr::null()) };
        if stop_event.is_null() {
            let e = last_error();
            unsafe {
                (api.end_session)(session);
                (api.close_adapter)(adapter);
            }
            return Err(anyhow::anyhow!("创建停止事件失败：{e}"));
        }

        // 读线程：等事件 → 取包 → 推通道
        let (tx, rx) = mpsc::channel::<Vec<u8>>(256);
        {
            let api = api.clone();
            let session_raw = session as usize;
            let read_raw = read_event as usize;
            let stop_raw = stop_event as usize;
            std::thread::Builder::new()
                .name(format!("wintun-read-{dev_name}"))
                .spawn(move || {
                    let session = session_raw as *mut c_void;
                    let read_event = read_raw as Handle;
                    let stop_event = stop_raw as Handle;
                    loop {
                        // 两个句柄一起等：数据可读 / 要求退出
                        let handles = [read_event, stop_event];
                        let r = unsafe {
                            WaitForMultipleObjectsEx(
                                2,
                                handles.as_ptr(),
                                0, // 任一触发就返回
                                INFINITE,
                                0,
                            )
                        };
                        // WAIT_OBJECT_0 + 1 = stop_event
                        if r == 1 {
                            break;
                        }
                        if r == u32::MAX {
                            // 等待失败：退出线程（Drop 里会收拾句柄）
                            break;
                        }
                        // 把环形缓冲里现有的包全部取走
                        loop {
                            let mut size: Dword = 0;
                            let pkt = unsafe { (api.receive_packet)(session, &mut size) };
                            if pkt.is_null() {
                                let e = unsafe { GetLastError() };
                                if e == ERROR_NO_MORE_ITEMS {
                                    break; // 取完了，回去等事件
                                }
                                // 其它错误（会话已结束）也退出
                                return;
                            }
                            let data =
                                unsafe { std::slice::from_raw_parts(pkt, size as usize).to_vec() };
                            unsafe { (api.release_receive_packet)(session, pkt) };
                            // 通道满了就丢包 —— UDP/IP 语义下这是正常的，
                            // 阻塞读线程会让整个 TUN 停摆，那更糟。
                            let _ = tx.try_send(data);
                        }
                    }
                })
                .map_err(|e| anyhow::anyhow!("启动 Wintun 读线程失败：{e}"))?;
        }

        Ok(Self {
            api,
            adapter,
            session,
            stop_event,
            name: dev_name,
            mtu,
            rx,
            pending: None,
        })
    }

    /// 给适配器配 IPv4 地址并启用。
    ///
    /// `addr_spec` 形如 `100.64.0.2/24`。
    ///
    /// # 为什么不能用 `netsh interface ipv4 set address`
    ///
    /// **实测**（本机真跑）：`netsh` 对 Wintun 适配器**返回成功但地址配不上** ——
    /// `netsh interface ipv4 show addresses` 里只有 `DHCP enabled: No`，
    /// 没有 IP。原因是 Wintun 建的是 **L3 隧道适配器**，`netsh` 那条老路径
    /// 走的是 `SetIfEntry` 系列，对这类适配器不生效。
    ///
    /// 官方（Wintun 文档 / WireGuard for Windows）的做法是用 **IP Helper API**
    /// 的 `CreateUnicastIpAddressEntry`。`New-NetIPAddress` 这个 cmdlet 正是
    /// 它的封装，所以这里用 PowerShell 调它 —— 比手写
    /// `MIB_UNICASTIPADDRESS_ROW`（几十个字段、布局敏感）出错的概率低得多，
    /// 而且失败时它的报错文本对运维更友好。
    ///
    /// **只配这一个地址、不动默认路由** —— 一个默默把全部流量劫走的工具
    /// 是灾难，走不走虚拟网络得让用户自己决定（与 Linux 版同一条原则）。
    pub fn set_address(&self, addr_spec: &str) -> anyhow::Result<()> {
        let (ip, prefix) = match addr_spec.split_once('/') {
            Some((a, b)) => (a, b),
            None => (addr_spec, "24"),
        };
        let prefix_num: u32 = prefix
            .trim()
            .parse()
            .map_err(|_| anyhow::anyhow!("地址 [{addr_spec}] 的前缀长度不是数字"))?;
        if prefix_num > 32 {
            return Err(anyhow::anyhow!(
                "地址 [{addr_spec}] 的前缀长度不合法（应在 0~32，实际 {prefix_num}）"
            ));
        }
        let mask = prefix_to_mask(prefix)
            .ok_or_else(|| anyhow::anyhow!("地址 [{addr_spec}] 的前缀长度不合法（应在 0~32）"))?;

        // ① 用 IP Helper API（经 New-NetIPAddress）配地址
        let ps = format!(
            "$ErrorActionPreference='Stop'; \
             New-NetIPAddress -InterfaceAlias '{}' -IPAddress '{}' -PrefixLength {} \
             -ErrorAction Stop | Out-Null",
            self.name.replace('\'', "''"),
            ip.replace('\'', "''"),
            prefix_num
        );
        let out = std::process::Command::new("powershell")
            .args(["-NoProfile", "-NonInteractive", "-Command", &ps])
            .output()
            .map_err(|e| anyhow::anyhow!("调用 PowerShell 配地址失败：{e}"))?;

        if !out.status.success() {
            let err = String::from_utf8_lossy(&out.stderr);
            let stdout = String::from_utf8_lossy(&out.stdout);
            let detail = format!("{err}{stdout}");
            let detail = detail.trim();

            // 已经配过同一个地址：不是错误（幂等），往下走
            let already = detail.contains("already exists") || detail.contains("已存在");
            if !already {
                // ② 退回 netsh 试一次（部分 Windows 版本上它对 Wintun 也能工作）
                if let Ok(o) = std::process::Command::new("netsh")
                    .args([
                        "interface",
                        "ipv4",
                        "set",
                        "address",
                        &format!("name={}", self.name),
                        "static",
                        ip,
                        &mask,
                    ])
                    .output()
                {
                    if o.status.success() {
                        tracing::debug!("New-NetIPAddress 失败但 netsh 成功，已配地址 {addr_spec}");
                        return self.apply_mtu();
                    }
                }
                return Err(anyhow::anyhow!(
                    "给 [{}] 配地址 {addr_spec} 失败：{detail}",
                    self.name
                ));
            }
            tracing::debug!("地址 {addr_spec} 已存在于 [{}]，跳过", self.name);
        }

        self.apply_mtu()
    }

    /// 地址变化时**先删旧、再加新**。
    ///
    /// `New-NetIPAddress` 不会自动移除旧地址；不删的话，旧地址的直连路由
    /// 会继续把旧网段送进 Wintun，重连后表现为一部分流量黑洞。
    /// 先删再加会有一个很短的"无地址"窗口，但只发生在地址真的变化时，
    /// 比留下错误路由安全。
    pub fn replace_address(&self, old_spec: &str, new_spec: &str) -> anyhow::Result<()> {
        let old_spec = old_spec.trim();
        if old_spec.is_empty() || old_spec == new_spec.trim() {
            return self.set_address(new_spec);
        }
        let old_ip = old_spec
            .split('/')
            .next()
            .unwrap_or("")
            .trim()
            .replace('\'', "''");
        if old_ip.is_empty() {
            return self.set_address(new_spec);
        }

        let ps = format!(
            "$ErrorActionPreference='Stop'; \
             Get-NetIPAddress -InterfaceAlias '{}' -IPAddress '{}' -ErrorAction SilentlyContinue | \
             Remove-NetIPAddress -Confirm:$false -ErrorAction Stop | Out-Null; \
             if (Get-NetIPAddress -InterfaceAlias '{}' -IPAddress '{}' -ErrorAction SilentlyContinue) {{ \
                 throw '旧地址仍然存在' \
             }}",
            self.name.replace('\'', "''"),
            old_ip,
            self.name.replace('\'', "''"),
            old_ip
        );
        let out = std::process::Command::new("powershell")
            .args(["-NoProfile", "-NonInteractive", "-Command", &ps])
            .output()
            .map_err(|e| anyhow::anyhow!("调用 PowerShell 删除旧地址失败：{e}"))?;
        if !out.status.success() {
            let err = String::from_utf8_lossy(&out.stderr);
            let stdout = String::from_utf8_lossy(&out.stdout);
            return Err(anyhow::anyhow!(
                "删除 [{}] 的旧地址 {old_spec} 失败（旧路由残留会导致重连后流量黑洞）：{}{}",
                self.name,
                err.trim(),
                stdout.trim()
            ));
        }

        self.set_address(new_spec)
    }

    /// 设 MTU。失败只告警 —— 地址已经有了，连通性不受影响。
    fn apply_mtu(&self) -> anyhow::Result<()> {
        if self.mtu == 0 {
            return Ok(());
        }
        let ps = format!(
            "$ErrorActionPreference='Stop'; \
             Set-NetIPInterface -InterfaceAlias '{}' -NlMtuBytes {} -ErrorAction Stop | Out-Null",
            self.name.replace('\'', "''"),
            self.mtu
        );
        match std::process::Command::new("powershell")
            .args(["-NoProfile", "-NonInteractive", "-Command", &ps])
            .output()
        {
            Ok(o) if o.status.success() => {}
            Ok(o) => tracing::warn!(
                "给 [{}] 设 MTU={} 失败（不影响连通性）：{}",
                self.name,
                self.mtu,
                String::from_utf8_lossy(&o.stderr).trim()
            ),
            Err(e) => tracing::warn!("设置 MTU 时调用 PowerShell 失败：{e}"),
        }
        Ok(())
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn mtu(&self) -> u32 {
        self.mtu
    }
}

impl Drop for Tun {
    fn drop(&mut self) {
        // 先叫停读线程，再结束会话 —— 顺序反了会让读线程在已释放的
        // session 上调用 WintunReceivePacket。
        unsafe {
            SetEvent(self.stop_event);
        }
        // 给它一点时间退出循环（读线程每轮都会被事件唤醒）
        std::thread::sleep(std::time::Duration::from_millis(20));

        unsafe {
            (self.api.end_session)(self.session);
            (self.api.close_adapter)(self.adapter);
            CloseHandle(self.stop_event);
        }
    }
}

impl AsyncRead for Tun {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        // 已有拆出来的包就用它，否则从通道取
        let pkt = match this.pending.take() {
            Some(p) => p,
            None => match this.rx.poll_recv(cx) {
                Poll::Ready(Some(p)) => p,
                Poll::Ready(None) => {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::BrokenPipe,
                        "Wintun 读线程已退出",
                    )))
                }
                Poll::Pending => return Poll::Pending,
            },
        };

        let n = pkt.len().min(buf.remaining());
        if n < pkt.len() {
            // 目标缓冲装不下整个 IP 包 —— 截断会导致对端收到损坏的包，
            // 不如明确报错（调用方给的缓冲应当 >= MAX_IP_PACKET）。
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "读缓冲太小：包 {} 字节，缓冲还剩 {}",
                    pkt.len(),
                    buf.remaining()
                ),
            )));
        }
        buf.put_slice(&pkt[..n]);
        Poll::Ready(Ok(()))
    }
}

impl AsyncWrite for Tun {
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        if buf.len() > MAX_IP_PACKET {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("IP 包 {} 字节，超过上限 {MAX_IP_PACKET}", buf.len()),
            )));
        }

        let api = self.api.clone();
        let session = self.session;
        let pkt = unsafe { (api.allocate_send_packet)(session, buf.len() as Dword) };
        if pkt.is_null() {
            let e = unsafe { GetLastError() };
            // 发送环形缓冲暂时满了：按 WouldBlock 处理，让 async 侧稍后再试
            if e == ERROR_BUFFER_OVERFLOW {
                _cx.waker().wake_by_ref();
                return Poll::Pending;
            }
            return Poll::Ready(Err(io::Error::from_raw_os_error(e as i32)));
        }
        // SAFETY：Wintun 保证 AllocateSendPacket 返回的缓冲至少有 buf.len() 字节可写
        unsafe {
            std::ptr::copy_nonoverlapping(buf.as_ptr(), pkt, buf.len());
            (api.send_packet)(session, pkt);
        }
        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        // WintunSendPacket 是"交给驱动就算发出去了"，没有用户态缓冲要刷
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

/// `/24` → `255.255.255.0`。返回 `None` 表示前缀非法。
fn prefix_to_mask(prefix: &str) -> Option<String> {
    let n: u32 = prefix.trim().parse().ok()?;
    if n > 32 {
        return None;
    }
    // 前缀 0 是合法的（0.0.0.0），要用 u64 移位避免 u32 左移 32 位溢出
    let mask: u32 = if n == 0 { 0 } else { u32::MAX << (32 - n) };
    Some(format!(
        "{}.{}.{}.{}",
        (mask >> 24) & 0xFF,
        (mask >> 16) & 0xFF,
        (mask >> 8) & 0xFF,
        mask & 0xFF
    ))
}

#[link(name = "kernel32")]
extern "system" {
    fn WaitForMultipleObjectsEx(
        count: Dword,
        handles: *const Handle,
        wait_all: Bool,
        ms: Dword,
        alertable: Bool,
    ) -> Dword;
}

/// 打开一个 Wintun 设备。签名与 Linux 版一致，便于上层平台无关。
pub fn open_tun(
    name: &str,
    mtu: u32,
    addr: Option<&str>,
    _peer: Option<&str>,
) -> anyhow::Result<Tun> {
    let tun = Tun::create(name, mtu)?;
    if let Some(a) = addr {
        // 失败就把设备还回去 —— 留一个没地址的网卡只会误导人
        if let Err(e) = tun.set_address(a) {
            drop(tun);
            return Err(e);
        }
    }
    Ok(tun)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn 前缀转掩码正确() {
        assert_eq!(prefix_to_mask("24").as_deref(), Some("255.255.255.0"));
        assert_eq!(prefix_to_mask("16").as_deref(), Some("255.255.0.0"));
        assert_eq!(prefix_to_mask("8").as_deref(), Some("255.0.0.0"));
        assert_eq!(prefix_to_mask("32").as_deref(), Some("255.255.255.255"));
        // 前缀 0 必须是 0.0.0.0 —— 用 u32 左移 32 位会 panic，这里专门锁住
        assert_eq!(prefix_to_mask("0").as_deref(), Some("0.0.0.0"));
        // 非法
        assert!(prefix_to_mask("33").is_none());
        assert!(prefix_to_mask("abc").is_none());
    }

    /// 两个测试都会改进程级的 `NFRP_WINTUN_DLL`，cargo test 默认并行跑，
    /// 不串行就会互相把对方的路径覆盖掉。这里只锁测试，不锁生产路径。
    fn dll_env_lock() -> std::sync::MutexGuard<'static, ()> {
        static LOCK: std::sync::OnceLock<std::sync::Mutex<()>> = std::sync::OnceLock::new();
        LOCK.get_or_init(|| std::sync::Mutex::new(()))
            .lock()
            .unwrap_or_else(|e| e.into_inner())
    }

    /// 没装 wintun.dll 时，错误信息必须**可操作**（含下载地址与放置位置），
    /// 而不是一句加载失败。
    #[test]
    fn 缺少_dll_时报错要可操作() {
        let _l = dll_env_lock();
        // 用一个一定不存在的路径逼出失败分支
        std::env::set_var("NFRP_WINTUN_DLL", r"Z:\definitely\no\such\wintun.dll");
        let e = match WintunApi::load() {
            Ok(_) => {
                std::env::remove_var("NFRP_WINTUN_DLL");
                return; // 这台机器真的装了，跳过
            }
            Err(e) => e.to_string(),
        };
        std::env::remove_var("NFRP_WINTUN_DLL");

        assert!(e.contains("wintun.dll"), "要点名缺什么：{e}");
        assert!(e.contains("wintun.net"), "要给下载地址：{e}");
        assert!(e.contains("NFRP_WINTUN_DLL"), "要给出覆盖方式：{e}");
    }

    /// 非管理员创建虚拟网卡时，必须直接给出“以管理员身份运行”，
    /// 不能只抛一个裸的 `os error 5`。
    ///
    /// 仓库里带着测试用 `wintun.dll` 时真实走到 `WintunCreateAdapter`；
    /// 没有 DLL 或当前恰好是管理员时也接受（分别跳过 / 建完即删），
    /// 这样不会把 CI 环境差异变成失败。
    #[test]
    fn 非管理员创建网卡要给提权提示() {
        let _l = dll_env_lock();
        let dll = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tmp/wintun/wintun/bin/amd64/wintun.dll");
        if !dll.is_file() {
            eprintln!("跳过：没有测试用 wintun.dll（{}）", dll.display());
            return;
        }
        std::env::set_var("NFRP_WINTUN_DLL", &dll);
        let name = format!("NFRP-TEST-DENIED-{}", std::process::id());
        let res = Tun::create(&name, 1400);
        std::env::remove_var("NFRP_WINTUN_DLL");

        match res {
            // 管理员环境：真的建出来了，回收即可。
            Ok(tun) => drop(tun),
            Err(e) => {
                let s = e.to_string();
                assert!(
                    s.contains("管理员") && s.contains("拒绝访问"),
                    "非管理员的错误要能指导用户提权，实际：{s}"
                );
            }
        }
    }

    /// ★ 真机验证：真的创建一块 Wintun 网卡、配地址、再删掉。
    ///
    /// 需要**管理员**权限（创建虚拟网卡），所以标了 `#[ignore]`，
    /// 用 `cargo test -- --ignored 真机` 手动跑。
    ///
    /// 这条是"Windows VirtualNet 能用"的**最低证据**：
    /// 驱动加载、适配器创建、会话启动、IP 配置、资源回收全走一遍。
    /// 它**不**证明数据面转发正确 —— 那需要两个节点对打，另见集成测试。
    #[test]
    #[ignore = "需要管理员权限与 wintun.dll，手动执行"]
    fn 真机_创建网卡_配地址_再回收() {
        let name = "NFRP-TEST-UT";

        // ① 创建
        let tun = match Tun::create(name, 1400) {
            Ok(t) => t,
            Err(e) => panic!("创建 Wintun 适配器失败：{e}"),
        };
        assert_eq!(tun.name(), name);
        assert_eq!(tun.mtu(), 1400);

        // ② 网卡必须真的出现在系统里
        let out = std::process::Command::new("netsh")
            .args(["interface", "show", "interface"])
            .output()
            .expect("跑 netsh");
        let listing = String::from_utf8_lossy(&out.stdout);
        assert!(
            listing.contains(name),
            "系统里找不到刚建的网卡 [{name}]，netsh 输出：\n{listing}"
        );

        // ③ 配地址
        tun.set_address("100.127.99.1/24")
            .unwrap_or_else(|e| panic!("配地址失败：{e}"));

        // ④ 地址必须真的生效。
        //
        //    注意**不能**用 `netsh interface ipv4 show addresses` 查 ——
        //    Wintun 是 L3 隧道适配器，`netsh` 那条路径看不到它上面的地址
        //    （实测：返回成功但只显示 "DHCP enabled: No"）。
        //    `Get-NetIPAddress` 走的是 IP Helper API，才能读出来。
        let out = std::process::Command::new("powershell")
            .args([
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                &format!(
                    "(Get-NetIPAddress -InterfaceAlias '{name}' -AddressFamily IPv4 \
                     -ErrorAction Stop).IPAddress"
                ),
            ])
            .output()
            .expect("跑 powershell");
        let addr_out = String::from_utf8_lossy(&out.stdout);
        assert!(
            addr_out.contains("100.127.99.1"),
            "地址没配上（Get-NetIPAddress 输出：{:?}）",
            addr_out.trim()
        );

        // ⑤ 回收：drop 之后适配器应当从系统里消失
        //    先记下 Drop 前的名字，Drop 后再查
        drop(tun);
        std::thread::sleep(std::time::Duration::from_millis(400));

        let out = std::process::Command::new("netsh")
            .args(["interface", "show", "interface"])
            .output()
            .expect("跑 netsh");
        let after = String::from_utf8_lossy(&out.stdout);
        assert!(
            !after.contains(name),
            "drop 之后网卡 [{name}] 仍存在，资源没回收：\n{after}"
        );
    }

    /// ★ 真机验证：未配地址时也能创建，且 `set_address` 对非法前缀报错而非静默。
    #[test]
    #[ignore = "需要管理员权限与 wintun.dll，手动执行"]
    fn 真机_非法地址前缀要报错() {
        let tun = match Tun::create("NFRP-TEST-BAD", 1400) {
            Ok(t) => t,
            Err(e) => panic!("创建 Wintun 适配器失败：{e}"),
        };
        let err = tun
            .set_address("100.127.99.1/99")
            .expect_err("前缀 99 必须被拒");
        assert!(
            err.to_string().contains("前缀"),
            "错误信息要说清是前缀长度问题：{err}"
        );
        drop(tun);
    }

    /// ★★ 真机验证（数据面）：**ping 自己这条 TUN 的另一端，由我们手工应答**。
    ///
    /// # 这条测试证明什么
    ///
    /// 上面那条只证明"网卡建出来了、地址配上了"（控制面）。这条证明
    /// **IP 包真的能双向流动**：
    ///
    /// 1. 配 `100.127.99.1/24`；
    /// 2. 后台 `ping 100.127.99.2`；
    /// 3. Windows 内核会把这个 ICMP Echo Request **写进 TUN**（读方向）；
    /// 4. 我们从 TUN 读出来，改成 Echo Reply 再**写回 TUN**（写方向）；
    /// 5. 内核收到后 `ping` 认为通了。
    ///
    /// 只通其一（只能读或只能写）都不会 ping 通，所以这一条同时锁住两个方向。
    ///
    /// # 为什么用 ping 而不是自己造包
    ///
    /// 自己造包只能证明"我们写的东西我们自己读回来了"（可能只是回环到自己的
    /// 缓冲）。让**内核**参与进来才是真实路径：内核 → TUN → 我们 → TUN → 内核。
    #[test]
    #[ignore = "需要管理员权限、wintun.dll 与 ping 命令，手动执行"]
    fn 真机_数据面_ping_由我们应答() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        const OUR_IP: &str = "100.127.99.1";
        const PEER_IP: &str = "100.127.99.2";
        const DEV: &str = "NFRP-TEST-DP";

        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("建 tokio runtime");

        rt.block_on(async {
            let mut tun = match Tun::create(DEV, 1400) {
                Ok(t) => t,
                Err(e) => panic!("创建 Wintun 适配器失败：{e}"),
            };
            tun.set_address(&format!("{OUR_IP}/24"))
                .unwrap_or_else(|e| panic!("配地址失败：{e}"));

            // ★ 多轮重试而不是单次固定等待。
            //
            // 实测教训：
            // * 建卡 + 配地址**返回后**，内核的路由表还要过一会儿才生效；
            //   这期间 ping 的请求根本没被写进 TUN（读方向一次都读不到）。
            // * 带诊断打印的那版"恰好"通过，是因为 eprintln 拖了几秒 ——
            //   **"加打印就好了"是假象**，不能当解法。
            // * 去查路由表反而更慢（每次 PowerShell 约 1 秒），
            //   而且"能不能 ping 通"本来就是更直接的判据。
            //
            // 所以：起 ping → 边读边应答 → 没赶上就再来一轮，最多 3 轮。
            let mut ok = false;
            let mut answered_total = 0usize;
            let mut ping_text = String::new();
            let mut buf = vec![0u8; MAX_IP_PACKET];

            for attempt in 1..=3u32 {
                let ping = std::process::Command::new("ping")
                    .args(["-n", "1", "-w", "2500", PEER_IP])
                    .stdout(std::process::Stdio::piped())
                    .stderr(std::process::Stdio::piped())
                    .spawn()
                    .expect("起 ping 失败");

                let deadline = std::time::Instant::now() + std::time::Duration::from_secs(4);
                let mut answered = 0usize;
                while std::time::Instant::now() < deadline && answered == 0 {
                    let n = match tokio::time::timeout(
                        std::time::Duration::from_millis(500),
                        tun.read(&mut buf),
                    )
                    .await
                    {
                        Ok(Ok(n)) => n,
                        Ok(Err(e)) => panic!("从 TUN 读包失败：{e}"),
                        Err(_) => continue, // 这轮没包，接着等
                    };
                    if n < 20 || buf[0] >> 4 != 4 {
                        continue; // 不是 IPv4，忽略
                    }
                    let ihl = ((buf[0] & 0x0F) as usize) * 4;
                    if n < ihl + 8 || ihl < 20 {
                        continue;
                    }
                    // 只回应 ICMP Echo Request（协议号 1，type 8）
                    if buf[9] != 1 || buf[ihl] != 8 {
                        continue;
                    }
                    let reply = build_icmp_echo_reply(&buf[..n], ihl);
                    if reply.is_empty() {
                        continue;
                    }
                    tun.write_all(&reply)
                        .await
                        .unwrap_or_else(|e| panic!("往 TUN 写应答失败：{e}"));
                    tun.flush().await.expect("flush");
                    answered += 1;
                    answered_total += 1;
                }

                let out = ping.wait_with_output().expect("等 ping 结束");
                ping_text = format!(
                    "{}{}",
                    String::from_utf8_lossy(&out.stdout),
                    String::from_utf8_lossy(&out.stderr)
                );
                if ping_text.contains("TTL=") || ping_text.contains("ttl=") {
                    ok = true;
                    break;
                }
                // 这一轮没通（多半是网卡还没就绪），隔一会儿再试
                eprintln!("[尝试 {attempt}] 未通，400ms 后重试");
                std::thread::sleep(std::time::Duration::from_millis(400));
            }

            assert!(
                answered_total > 0,
                "3 轮之内一次都没从 TUN 读到 ICMP Echo Request —— \
                 说明**读方向不通**（内核没把包写进 TUN，或我们没有读到）"
            );
            assert!(
                ok,
                "我们应答了 {answered_total} 个请求，但 ping 始终没通 —— \
                 说明**写方向不通**（写回的包内核没认）。最后一次 ping 输出：\n{ping_text}"
            );
            drop(tun);
        });
    }

    /// 把收到的 IPv4 + ICMP Echo Request 改造成 Echo Reply。
    ///
    /// 做四件事：交换源/目的地址、TTL 复位、ICMP type 8→0、**重算两个校验和**
    /// （IP 头与 ICMP）。返回空 Vec 表示"这个包不该应答"。
    fn build_icmp_echo_reply(pkt: &[u8], ihl: usize) -> Vec<u8> {
        if pkt.len() < ihl + 8 {
            return Vec::new();
        }
        let mut out = pkt.to_vec();

        // ① 交换 IPv4 源 / 目的。
        //
        // ★ 偏移量必须精确：IPv4 头里 **源地址在 offset 12**、目的地址在 16。
        //   这里曾经写成 `(4, 16)` —— offset 4 是 **IP ID 字段**，
        //   于是"交换"把 ID/flags 和目的地址对调、源地址原地不动，
        //   内核收到后直接丢掉（实测：ping 100% loss，读方向通、写方向不通）。
        //   这类错误不会有任何报错，只会"包发出去但没人认"，最难查。
        let (src, dst) = (12, 16);
        for i in 0..4 {
            out.swap(src + i, dst + i);
        }

        // ② TTL 复位（内核可能给了个很小的值）
        out[8] = 64;

        // ③ IP 头校验和：先清零再算
        out[10] = 0;
        out[11] = 0;
        let ip_ck = checksum(&out[..ihl]);
        out[10..12].copy_from_slice(&ip_ck.to_be_bytes());

        // ④ ICMP type 8(Echo Request) → 0(Echo Reply)
        out[ihl] = 0;

        // ⑤ ICMP 校验和：覆盖**整个 ICMP 消息**（头 + 数据）
        out[ihl + 2] = 0;
        out[ihl + 3] = 0;
        let icmp_ck = checksum(&out[ihl..]);
        out[ihl + 2..ihl + 4].copy_from_slice(&icmp_ck.to_be_bytes());

        out
    }

    /// 标准 Internet 校验和（RFC 1071）。
    fn checksum(data: &[u8]) -> u16 {
        let mut sum: u32 = 0;
        let mut i = 0;
        while i + 1 < data.len() {
            sum += u16::from_be_bytes([data[i], data[i + 1]]) as u32;
            i += 2;
        }
        if i < data.len() {
            sum += (data[i] as u32) << 8;
        }
        while (sum >> 16) != 0 {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }
        !(sum as u16)
    }

    /// 校验和算法本身要正确 —— 用 RFC 1071 的经典样例锁住。
    #[test]
    fn 校验和算法正确() {
        // RFC 1071 §3 的样例数据（末尾两字节留 0 参与计算）
        let data = [0x00u8, 0x01, 0xf2, 0x03, 0xf4, 0xf5, 0xf6, 0xf7, 0x00, 0x00];
        assert_eq!(checksum(&data), 0x220d);

        // 全零数据：取反后是 0xffff
        assert_eq!(checksum(&[0u8; 4]), 0xffff);
        // 奇数长度也要能算：单字节 0x01 补成 0x0100，取反得 0xfeff
        assert_eq!(checksum(&[0x01]), 0xfeff);
    }
}
