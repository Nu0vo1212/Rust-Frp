#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""OpenWrt 官方 rootfs 容器内的 musl 二进制 e2e（真 frps + 真 frpc + 真 TCP 后端）。

设计：
    宿主机跑本脚本，负责编排 docker 与 TCP echo 后端；容器跑 OpenWrt 官方
    rootfs 里的 musl 版 frps/frpc。容器用 --network host，于是宿主机既是
    「内网服务」（frpc 的 local_addr）也是「公网访客」（连 frps 的 remote_port），
    数据真的穿过容器边界，端到端验证而非 mock。

覆盖：
    1) frps -v / frpc -v 在 OpenWrt rootfs 里输出裸 0.71.0
    2) init 脚本在 mock procd 下 source 后 start_service 带 respawn、
       stdout/stderr 交给 logd、配置路径正确；reload_service 调 restart
    3) 一条 tcp 代理端到端（宿主机 echo <-> 容器 frpc <-> 容器 frps <-> 宿主机访客）
    4) 空闲 RSS（从容器 /proc/<pid>/status 读 VmRSS）
    5) --official-interop-only：官方 frpc 连 NFrp frps 的互通；
       拉不到官方二进制时明确写明跳过，绝不伪造通过

用法：
    python3 scripts/e2e_openwrt.py --bin-dir target/x86_64-unknown-linux-musl/release \
        --rootfs-image nfrp-openwrt:test
    python3 scripts/e2e_openwrt.py ... --official-interop-only
退出码 0 = 全部通过（或官方互通明确跳过）。
"""

from __future__ import annotations

import argparse
import random
import shutil
import socket
import subprocess
import sys
import tarfile
import tempfile
import threading
import time
import urllib.request
from pathlib import Path

sys.stdout.reconfigure(encoding="utf-8", errors="replace")

ROOT = Path(__file__).resolve().parent.parent
TOKEN = "openwrt-e2e-token"
OFFICIAL_VERSION = "0.71.0"
OFFICIAL_URL = (
    "https://github.com/fatedier/frp/releases/download/"
    f"v{OFFICIAL_VERSION}/frp_{OFFICIAL_VERSION}_linux_amd64.tar.gz"
)
CONTAINER = "nfrp-openwrt-e2e"
RESULTS: list[tuple[str, bool, str]] = []


def report(name: str, ok: bool, detail: str = "") -> None:
    RESULTS.append((name, ok, detail))
    print(f"[{'PASS' if ok else 'FAIL'}] {name}" + (f" -- {detail}" if detail else ""), flush=True)


def run(cmd: list[str], *, check: bool = True, capture: bool = True) -> subprocess.CompletedProcess:
    p = subprocess.run(cmd, capture_output=capture, text=True, encoding="utf-8", errors="replace")
    if check and p.returncode != 0:
        raise RuntimeError(f"命令失败 ({p.returncode}): {' '.join(cmd)}\n{p.stdout}\n{p.stderr}")
    return p


def dexec(*args: str, check: bool = True) -> subprocess.CompletedProcess:
    return run(["docker", "exec", CONTAINER, *args], check=check)


def free_port(lo: int = 20000, hi: int = 45000) -> int:
    for _ in range(200):
        p = random.randint(lo, hi)
        with socket.socket() as s:
            try:
                s.bind(("127.0.0.1", p))
            except OSError:
                continue
        return p
    raise RuntimeError("找不到空闲端口")


def wait_port(port: int, timeout: float = 15.0, host: str = "127.0.0.1") -> bool:
    end = time.time() + timeout
    while time.time() < end:
        try:
            with socket.create_connection((host, port), timeout=0.5):
                return True
        except OSError:
            time.sleep(0.15)
    return False


def start_tcp_echo() -> tuple[int, socket.socket]:
    """宿主机上的 TCP echo 后端，返回 (端口, listen socket)。"""
    srv = socket.socket()
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 0))
    srv.listen(16)
    port = srv.getsockname()[1]

    def handle(c: socket.socket) -> None:
        try:
            while True:
                d = c.recv(4096)
                if not d:
                    break
                c.sendall(b"ECHO:" + d)
        except OSError:
            pass
        finally:
            c.close()

    def loop() -> None:
        while True:
            try:
                c, _ = srv.accept()
                threading.Thread(target=handle, args=(c,), daemon=True).start()
            except OSError:
                break

    threading.Thread(target=loop, daemon=True).start()
    return port, srv


def cleanup_container() -> None:
    run(["docker", "rm", "-f", CONTAINER], check=False, capture=True)


def start_container(image: str) -> None:
    cleanup_container()
    # 用 sleep 保活；--network host 让宿主机既是内网服务也是公网访客
    run([
        "docker", "run", "-d", "--name", CONTAINER, "--network", "host",
        "--entrypoint", "/bin/sh", image, "-c", "sleep infinity",
    ])


def stage_files(bin_dir: Path, work: Path) -> None:
    """把 musl 二进制、init 脚本、示例配置拷到临时目录供 docker cp。"""
    for name in ("nfrp-server", "nfrp-client"):
        src = bin_dir / name
        if not src.is_file():
            raise RuntimeError(f"找不到产物 {src}")
        shutil.copy2(src, work / name)
    init_src = ROOT / "openwrt" / "etc" / "init.d"
    for name in ("frpc", "frps"):
        shutil.copy2(init_src / name, work / f"init-{name}")


def check_versions() -> None:
    for name in ("nfrp-server", "nfrp-client"):
        p = dexec(f"/usr/bin/{name}", "-v")
        v = p.stdout.strip()
        report(f"{name} -v 裸版本", v == OFFICIAL_VERSION, f"[{v}]")


def check_init_scripts() -> None:
    """用 mock procd 函数 source init 脚本，验证 respawn / logd / reload。"""
    # 直接把 mock 写成脚本注入容器执行，避免 shell 引号层层转义
    script = """#!/bin/sh
LOG=/tmp/procd-call.log
: > "$LOG"
procd_open_instance() { echo open >> "$LOG"; }
procd_set_param() { echo "param:$*" >> "$LOG"; }
procd_close_instance() { echo close >> "$LOG"; }
restart() { echo restart-called >> "$LOG"; }
logger() { :; }
ifstatus() { echo '{"up":true}'; }
date() { echo 1700000000; }
. "$1"
start_service
echo ---RELOAD---
reload_service
cat "$LOG"
"""
    # init 脚本会检查二进制与配置都存在，先备好占位配置
    dexec("mkdir", "-p", "/etc/frp")
    for name in ("frpc", "frps"):
        dexec("sh", "-c", f"printf 'log_level = \"info\"\\n' > /etc/frp/{name}.toml")
    for name in ("frpc", "frps"):
        local = Path(tempfile.gettempdir()) / f"mock-procd-{name}.sh"
        local.write_text(script, encoding="utf-8", newline="\n")
        run(["docker", "cp", str(local), f"{CONTAINER}:/tmp/mock-procd.sh"])
        p = dexec("/bin/sh", "/tmp/mock-procd.sh", f"/etc/init.d/{name}", check=False)
        out = p.stdout
        ok = (
            "param:respawn " in out
            and "param:stdout 1" in out
            and "param:stderr 1" in out
            and "restart-called" in out
        )
        report(f"{name} init: respawn/logd/reload", ok, out.replace("\n", " | ")[:300])


def write_server_config(work: Path, bind_port: int) -> None:
    (work / "frps-test.toml").write_text(
        f'bind_addr = "0.0.0.0"\nbind_port = {bind_port}\n'
        f'token = "{TOKEN}"\ntcp_mux = true\nlog_level = "info"\n',
        encoding="utf-8", newline="\n",
    )


def write_client_config(work: Path, server_port: int, local_port: int, remote_port: int) -> None:
    (work / "frpc-test.toml").write_text(
        f'server_addr = "127.0.0.1"\nserver_port = {server_port}\n'
        f'token = "{TOKEN}"\ntcp_mux = true\nlog_level = "info"\n\n'
        f'[[proxies]]\nname = "tcp-e2e"\ntype = "tcp"\n'
        f'local_ip = "127.0.0.1"\nlocal_port = {local_port}\n'
        f'remote_port = {remote_port}\n',
        encoding="utf-8", newline="\n",
    )


def read_rss(pid_marker: str) -> str:
    p = dexec("sh", "-c", f'pid=$(pgrep -f "{pid_marker}" | head -1); '
                          f'[ -n "$pid" ] && grep VmRSS /proc/$pid/status || echo NO-RSS', check=False)
    return p.stdout.strip() or "NO-RSS"


def tcp_proxy_e2e(work: Path) -> tuple[bool, str]:
    echo_port, echo_sock = start_tcp_echo()
    bind_port = free_port()
    remote_port = free_port()
    write_server_config(work, bind_port)
    write_client_config(work, bind_port, echo_port, remote_port)
    dexec("mkdir", "-p", "/etc/frp")
    run(["docker", "cp", str(work / "frps-test.toml"), f"{CONTAINER}:/etc/frp/frps.toml"])
    run(["docker", "cp", str(work / "frpc-test.toml"), f"{CONTAINER}:/etc/frp/frpc.toml"])

    srv = dexec("sh", "-c", "/usr/bin/nfrp-server -c /etc/frp/frps.toml >/tmp/frps.log 2>&1 & echo $!")
    srv_pid = srv.stdout.strip()
    if not wait_port(bind_port, 10):
        echo_sock.close()
        return False, "frps 未监听 bind_port: " + dexec("cat", "/tmp/frps.log", check=False).stdout[:200]
    cli = dexec("sh", "-c", "/usr/bin/nfrp-client -c /etc/frp/frpc.toml >/tmp/frpc.log 2>&1 & echo $!")
    if not wait_port(remote_port, 10):
        echo_sock.close()
        dexec("kill", srv_pid, check=False)
        return False, "frpc 未建立 remote_port: " + dexec("cat", "/tmp/frpc.log", check=False).stdout[:200]

    ok, detail = False, ""
    try:
        with socket.create_connection(("127.0.0.1", remote_port), timeout=5) as c:
            c.sendall(b"openwrt-hello")
            data = c.recv(4096)
        ok = data == b"ECHO:openwrt-hello"
        detail = f"收到 {data!r}"
    except OSError as e:
        detail = f"连接失败: {e}"
    rss_srv = read_rss("nfrp-server")
    rss_cli = read_rss("nfrp-client")
    detail += f" | frps {rss_srv}, frpc {rss_cli}"
    dexec("sh", "-c", f'kill {srv_pid} 2>/dev/null; pkill -f nfrp-client 2>/dev/null; true', check=False)
    echo_sock.close()
    return ok, detail


def download_official_frpc(dest: Path) -> Path | None:
    """下载官方 frpc；失败返回 None 并写明原因（不伪造通过）。"""
    archive = dest / "official-frp.tar.gz"
    try:
        req = urllib.request.Request(OFFICIAL_URL, headers={"User-Agent": "nfrp-e2e/1.0"})
        with urllib.request.urlopen(req, timeout=60) as resp, open(archive, "wb") as f:
            shutil.copyfileobj(resp, f)
    except Exception as e:  # noqa: BLE001 - 明确跳过，记录原因
        print(f"[SKIP] 官方 frpc 下载失败，跳过互通验证：{e}", flush=True)
        return None
    try:
        with tarfile.open(archive, "r:gz") as t:
            member = next((m for m in t.getmembers() if m.name.endswith("/frpc")), None)
            if member is None:
                print("[SKIP] 官方包里没有 frpc，跳过互通验证", flush=True)
                return None
            data = t.extractfile(member)
            if data is None:
                return None
            out = dest / "frpc-official"
            out.write_bytes(data.read())
            out.chmod(0o755)
            return out
    except Exception as e:  # noqa: BLE001
        print(f"[SKIP] 官方包解包失败，跳过互通验证：{e}", flush=True)
        return None


def official_interop(work: Path) -> None:
    frpc = download_official_frpc(work)
    if frpc is None:
        report("官方 frpc 互通", True, "SKIP（二进制不可得，已写明原因）")
        return
    echo_port, echo_sock = start_tcp_echo()
    bind_port = free_port()
    remote_port = free_port()
    write_server_config(work, bind_port)
    (work / "official-frpc.toml").write_text(
        f'serverAddr = "127.0.0.1"\nserverPort = {bind_port}\n'
        f'token = "{TOKEN}"\ntransport = {{ tcpMux = true }}\n\n'
        f'[[proxies]]\nname = "official-tcp"\ntype = "tcp"\n'
        f'localIP = "127.0.0.1"\nlocalPort = {echo_port}\n'
        f'remotePort = {remote_port}\n',
        encoding="utf-8", newline="\n",
    )
    dexec("mkdir", "-p", "/etc/frp")
    run(["docker", "cp", str(work / "frps-test.toml"), f"{CONTAINER}:/etc/frp/frps.toml"])
    srv = dexec("sh", "-c", "/usr/bin/nfrp-server -c /etc/frp/frps.toml >/tmp/frps-of.log 2>&1 & echo $!")
    if not wait_port(bind_port, 10):
        echo_sock.close()
        dexec("kill", srv.stdout.strip(), check=False)
        report("官方 frpc 互通", False, "frps 未起来")
        return
    proc = subprocess.Popen([str(frpc), "-c", str(work / "official-frpc.toml")],
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    time.sleep(2)
    ok, detail = False, ""
    try:
        if wait_port(remote_port, 8):
            with socket.create_connection(("127.0.0.1", remote_port), timeout=5) as c:
                c.sendall(b"official-hello")
                data = c.recv(4096)
            ok = data == b"ECHO:official-hello"
            detail = f"收到 {data!r}"
        else:
            detail = "官方 frpc 未建立 remote_port"
    except OSError as e:
        detail = f"连接失败: {e}"
    proc.terminate()
    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        proc.kill()
    dexec("kill", srv.stdout.strip(), check=False)
    echo_sock.close()
    report("官方 frpc -> NFrp frps", ok, detail)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--bin-dir", required=True, help="musl 构建产物目录")
    ap.add_argument("--rootfs-image", default="nfrp-openwrt:test", help="docker import 的 rootfs 镜像")
    ap.add_argument("--official-interop-only", action="store_true", help="只跑官方 frpc 互通")
    args = ap.parse_args()

    bin_dir = Path(args.bin_dir).resolve()
    if not bin_dir.is_dir():
        print(f"产物目录不存在：{bin_dir}", file=sys.stderr)
        return 2
    if shutil.which("docker") is None:
        print("找不到 docker，无法跑 OpenWrt rootfs 冒烟", file=sys.stderr)
        return 2

    with tempfile.TemporaryDirectory(prefix="nfrp-openwrt-") as td:
        work = Path(td)
        try:
            start_container(args.rootfs_image)
            stage_files(bin_dir, work)
            run(["docker", "cp", str(work / "nfrp-server"), f"{CONTAINER}:/usr/bin/nfrp-server"])
            run(["docker", "cp", str(work / "nfrp-client"), f"{CONTAINER}:/usr/bin/nfrp-client"])
            for name in ("frpc", "frps"):
                run(["docker", "cp", str(work / f"init-{name}"), f"{CONTAINER}:/etc/init.d/{name}"])
                dexec("chmod", "+x", f"/etc/init.d/{name}")

            if args.official_interop_only:
                official_interop(work)
            else:
                check_versions()
                check_init_scripts()
                ok, detail = tcp_proxy_e2e(work)
                report("tcp 代理端到端", ok, detail)
        finally:
            cleanup_container()

    failed = [n for n, ok, _ in RESULTS if not ok]
    print(f"\n结果：{len(RESULTS) - len(failed)}/{len(RESULTS)} 通过", flush=True)
    if failed:
        print("失败项：" + ", ".join(failed), flush=True)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
