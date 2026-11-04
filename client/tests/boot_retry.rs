//! 开机自启回归测试（真进程，不是 mock）。
//!
//! 背景：Windows 开机时 `frpc.vbs` 拉起 `frpc.exe`，网络 / `proxyURL` 代理 /
//! KCP(UDP) 通道往往比进程晚几秒就绪。旧行为是 `loginFailExit = true` 一刀切：
//! 首次 `dial` 失败 → 进程退出 → 启动器再也不管 → 隧道永远不通。
//!
//! 这里锁死两条边界：
//! 1. **连不上**（端口不可达）→ 进程必须活着并退避重试；
//! 2. **被服务端明确拒绝**（`LoginResp.error`）→ 尊重 `loginFailExit = true`，
//!    快速退出且退出码非 0，避免把配置错误藏起来。

use std::io::{Read, Write};
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

/// 工作区里真实构建出来的客户端二进制（Cargo 保证 build 先于测试）。
const BIN: &str = env!("CARGO_BIN_EXE_nfrp-client");

fn unique_dir(tag: &str) -> PathBuf {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let dir = std::env::temp_dir().join(format!(
        "nfrp-boot-retry-{tag}-{}-{nanos}",
        std::process::id()
    ));
    std::fs::create_dir_all(&dir).expect("创建临时目录");
    dir
}

fn write_config(dir: &Path, port: u16) -> PathBuf {
    let path = dir.join("frpc.toml");
    // 与服务端只连 127.0.0.1；关掉 yamux 与 TLS，保证假服务端能直接
    // 读到明文 Login 帧（否则最先到达的是 yamux 的控制帧）。
    let body = format!(
        "server_addr = \"127.0.0.1\"\n\
         server_port = {port}\n\
         login_fail_exit = true\n\
         tls_enable = false\n\
         tcp_mux = false\n"
    );
    std::fs::write(&path, body).expect("写测试配置");
    path
}

fn spawn_frpc(config: &Path) -> Child {
    Command::new(BIN)
        .arg("-c")
        .arg(config)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("启动 nfrp-client")
}

fn output_text(child: Child) -> String {
    let out = child.wait_with_output().expect("收集进程输出");
    format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    )
}

/// 取一个当前没人监听的 TCP 端口（bind 后立即释放）。
fn closed_port() -> u16 {
    let l = TcpListener::bind("127.0.0.1:0").expect("bind 临时端口");
    let port = l.local_addr().unwrap().port();
    drop(l);
    port
}

#[test]
fn 端口不可达时进程不退出并持续退避重试() {
    let dir = unique_dir("unreachable");
    let config = write_config(&dir, closed_port());
    let mut child = spawn_frpc(&config);

    // 旧实现会在第一次 dial 失败后立刻退出；退避 1+2+4 秒，6 秒内应有 3 次尝试。
    std::thread::sleep(Duration::from_secs(6));
    let alive = child.try_wait().expect("try_wait").is_none();
    let text = if alive {
        child.kill().ok();
        output_text(child)
    } else {
        output_text(child)
    };

    assert!(
        alive,
        "端口不可达 ≠ 登录被拒；进程必须继续重试。输出：\n{text}"
    );
    let retries = text.matches("秒后重试").count();
    assert!(
        retries >= 2,
        "6 秒内至少应有 2 次退避重试日志，实际 {retries} 次。输出：\n{text}"
    );
    assert!(
        text.contains("首次登录失败"),
        "每次失败都要留下可观测日志。输出：\n{text}"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn 服务端明确拒绝登录时按_login_fail_exit_快速退出() {
    let dir = unique_dir("rejected");
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind 假服务端");
    let port = listener.local_addr().unwrap().port();

    let server = std::thread::spawn(move || {
        let (mut socket, _) = listener.accept().expect("接受客户端登录");
        socket.set_read_timeout(Some(Duration::from_secs(5))).ok();
        // 读 v1 帧头：1 字节类型 + 8 字节长度，然后读 Login 正文。
        let mut head = [0u8; 9];
        socket.read_exact(&mut head).expect("读取 Login 帧头");
        assert_eq!(
            head[0],
            nfrp_common::frp::v1::TYPE_LOGIN,
            "首帧必须是明文 Login（tls 已关）：head={head:02x?}"
        );
        let len = i64::from_be_bytes(head[1..9].try_into().unwrap());
        assert!(
            (0..=1024 * 1024).contains(&len),
            "Login 正文长度异常：{len}，head={head:02x?}"
        );
        let mut body = vec![0u8; len as usize];
        socket.read_exact(&mut body).expect("读取 Login 正文");

        // 服务端明确拒绝（对应 Go 的 LoginResp{Error: "..."}）。
        let resp = serde_json::json!({
            "version": "0.71.0",
            "error": "token 不正确",
        })
        .to_string();
        let frame = nfrp_common::frp::v1::encode_msg(
            nfrp_common::frp::v1::TYPE_LOGIN_RESP,
            resp.as_bytes(),
        );
        socket.write_all(&frame).expect("写 LoginResp");
        socket.flush().ok();
        // 留一点时间让客户端读完，再断开。
        std::thread::sleep(Duration::from_millis(500));
    });

    let config = write_config(&dir, port);
    let mut child = spawn_frpc(&config);

    // 被拒绝不是"网络未就绪"：不应进入退避重试，必须很快退出。
    let deadline = Instant::now() + Duration::from_secs(10);
    let status = loop {
        match child.try_wait().expect("try_wait") {
            Some(status) => break status,
            None if Instant::now() >= deadline => {
                child.kill().ok();
                let text = output_text(child);
                panic!("服务端已明确拒绝，进程却还在跑（配置错误被掩盖）。输出：\n{text}");
            }
            None => std::thread::sleep(Duration::from_millis(100)),
        }
    };
    assert!(
        !status.success(),
        "登录被拒必须以非 0 退出码结束，实际：{status:?}"
    );
    let text = output_text(child);
    assert!(
        text.contains("拒绝登录") || text.contains("loginFailExit"),
        "退出前必须把「被拒绝」讲清楚。输出：\n{text}"
    );

    server.join().ok();
    let _ = std::fs::remove_dir_all(&dir);
}
