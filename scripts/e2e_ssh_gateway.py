#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""SSH 网关数据面 e2e（真 frps + 系统 ssh 客户端 + 真后端）。

为什么需要这一层：
    `server/src/ssh_gateway.rs` 的单元测试只覆盖到「代理注册 / 状态 / 清理」，
    数据面（字节是否真的穿过去）一直没人跑。0.7.7 跑起来立刻发现一个真缺陷：
    SSH 网关把 `--token`（原始 token）当成 `auth_key(token, ts)` 派生值去比对，
    导致 token 认证**永远失败**。修完才能连通。

覆盖：
    tcp      ssh -R + `tcp --remote_port`   → 回环 echo
    tcpmux   ssh -R + `tcpmux --custom_domain` → CONNECT 后访问 http 后端
    stcp     ssh -R + `stcp --sk`           → nfrp-client 作 visitor 访问

用法：
    python scripts/e2e_ssh_gateway.py --bin-dir ../dist/autostart-0.7.7
    python3 scripts/e2e_ssh_gateway.py --bin-dir /opt/nfrp
退出码 0 = 全部通过。
"""

from __future__ import annotations

import argparse
import http.server
import os
import random
import socket
import subprocess
import sys
import tempfile
import threading
import time
import traceback
from pathlib import Path

sys.stdout.reconfigure(encoding="utf-8", errors="replace")

ROOT = Path(__file__).resolve().parent.parent
TOKEN = "ssh-gw-token"
USER = "alice"
RESULTS: list[tuple[str, bool, str]] = []


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


def wait_port(port: int, timeout: float = 15.0) -> bool:
    end = time.time() + timeout
    while time.time() < end:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.5):
                return True
        except OSError:
            time.sleep(0.15)
    return False


# ---------------------------------------------------------------- 后端
def start_tcp_echo() -> int:
    srv = socket.socket()
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 0))
    srv.listen(16)
    port = srv.getsockname()[1]

    def handle(c):
        try:
            while True:
                d = c.recv(4096)
                if not d:
                    break
                c.sendall(b"TCP-ECHO:" + d)
        except OSError:
            pass
        finally:
            c.close()

    def loop():
        while True:
            try:
                c, _ = srv.accept()
            except OSError:
                return
            threading.Thread(target=handle, args=(c,), daemon=True).start()

    threading.Thread(target=loop, daemon=True).start()
    return port


class _Http(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        body = b"TCPMUX-BACKEND-OK"
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass


def start_http_backend() -> int:
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _Http)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv.server_address[1]


# ---------------------------------------------------------------- 进程
class Proc:
    def __init__(self, args, log_path):
        self.log = Path(log_path)
        self.fh = open(self.log, "wb")
        self.p = subprocess.Popen(args, stdout=self.fh, stderr=subprocess.STDOUT)

    def stop(self):
        try:
            self.p.terminate()
            self.p.wait(timeout=8)
        except Exception:
            self.p.kill()
        try:
            self.fh.close()
        except Exception:
            pass

    def text(self) -> str:
        try:
            return self.log.read_text(encoding="utf-8", errors="replace")
        except Exception:
            return ""


# ---------------------------------------------------------------- 用例
def ssh_tunnel(ssh_exe, gw, remote_port, local_port, command):
    args = [
        ssh_exe, "-p", str(gw),
        "-o", "StrictHostKeyChecking=no",
        "-o", "UserKnownHostsFile=" + os.devnull,
        "-o", "PreferredAuthentications=none",
        "-o", "BatchMode=yes",
        "-o", "ConnectTimeout=8",
        "-o", "ServerAliveInterval=5",
        "-o", f"User={USER}",
        "-R", f"{remote_port}:127.0.0.1:{local_port}",
        "127.0.0.1", command,
    ]
    return args


def check_tcp(remote: int) -> tuple[bool, str]:
    end = time.time() + 20
    last = ""
    while time.time() < end:
        try:
            with socket.create_connection(("127.0.0.1", remote), timeout=2) as c:
                c.settimeout(3)
                c.sendall(b"hello-ssh")
                data = c.recv(4096)
                if data.startswith(b"TCP-ECHO:hello-ssh"):
                    return True, data.decode(errors="replace")
                last = repr(data)
        except Exception as e:  # noqa: BLE001
            last = f"{type(e).__name__}: {e}"
        time.sleep(0.4)
    return False, last


def check_tcpmux(mux_port: int, domain: str) -> tuple[bool, str]:
    end = time.time() + 20
    last = ""
    while time.time() < end:
        try:
            with socket.create_connection(("127.0.0.1", mux_port), timeout=3) as c:
                c.settimeout(4)
                c.sendall(
                    f"CONNECT {domain} HTTP/1.1\r\nHost: {domain}\r\n\r\n".encode()
                )
                resp = c.recv(4096)
                if b"200" in resp[:32]:
                    c.sendall(f"GET /mux HTTP/1.1\r\nHost: {domain}\r\n\r\n".encode())
                    body = c.recv(65535)
                    if b"TCPMUX-BACKEND-OK" in body:
                        return True, body.decode(errors="replace")[:200]
                last = repr(resp[:160])
        except Exception as e:  # noqa: BLE001
            last = f"{type(e).__name__}: {e}"
        time.sleep(0.4)
    return False, last


def check_stcp(visitor_port: int) -> tuple[bool, str]:
    end = time.time() + 20
    last = ""
    while time.time() < end:
        try:
            with socket.create_connection(("127.0.0.1", visitor_port), timeout=3) as c:
                c.settimeout(4)
                c.sendall(b"hello-stcp")
                data = c.recv(4096)
                if data.startswith(b"TCP-ECHO:hello-stcp"):
                    return True, data.decode(errors="replace")
                last = repr(data)
        except Exception as e:  # noqa: BLE001
            last = f"{type(e).__name__}: {e}"
        time.sleep(0.4)
    return False, last


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--bin-dir", help="frps/frpc（或 nfrp-server/nfrp-client）目录")
    ap.add_argument("--keep", action="store_true")
    args = ap.parse_args()

    ext = ".exe" if os.name == "nt" else ""
    cands = []
    if args.bin_dir:
        cands.append(Path(args.bin_dir))
    cands += [
        *sorted(ROOT.parent.glob("dist/autostart-*"), reverse=True),
        ROOT / "target" / "release",
        ROOT / "target" / "debug",
    ]
    bindir = None
    for d in cands:
        if (d / f"frps{ext}").is_file() and (d / f"frpc{ext}").is_file():
            bindir = (d, "frps", "frpc")
            break
        if (d / f"nfrp-server{ext}").is_file() and (d / f"nfrp-client{ext}").is_file():
            bindir = (d, "nfrp-server", "nfrp-client")
            break
    if bindir is None:
        print("找不到 frps/frpc；用 --bin-dir 指定")
        return 2
    d, srv_name, cli_name = bindir
    frps = d / f"{srv_name}{ext}"
    frpc = d / f"{cli_name}{ext}"
    print(f"二进制：{frps.name} / {frpc.name} @ {d}")

    ssh_exe = "ssh"
    if os.name == "nt":
        ssh_exe = r"C:\Windows\System32\OpenSSH\ssh.exe"
        if not Path(ssh_exe).is_file():
            print("找不到 Windows OpenSSH 客户端")
            return 2

    work = Path(tempfile.mkdtemp(prefix="nfrp-sshgw-"))
    bind, gw = free_port(), free_port()
    mux_port = free_port()
    echo_port = start_tcp_echo()
    http_port = start_http_backend()

    (work / "frps.toml").write_text(
        f'bind_addr = "127.0.0.1"\nbind_port = {bind}\ntoken = "{TOKEN}"\n'
        f'log_level = "debug"\n'
        f'tcpmux_http_connect_port = {mux_port}\n'
        f'[sshTunnelGateway]\nbind_port = {gw}\n',
        encoding="utf-8",
    )
    srv = Proc([str(frps), "-c", str(work / "frps.toml")], work / "frps.log")
    procs = [srv]
    sshs: list[Proc] = []

    def run_case(name, command, remote_port, target_port, checker):
        ssh_args = ssh_tunnel(ssh_exe, gw, remote_port, target_port, command)
        p = Proc(ssh_args, work / f"ssh-{name.split('/')[0]}.log")
        sshs.append(p)
        ok, detail = checker()
        RESULTS.append((name, ok, detail))
        print(("  ✅ " if ok else "  ❌ ") + name)
        if not ok:
            print("     ", detail)
            print("      --- ssh.log ---")
            print(Path(p.log).read_text(encoding="utf-8", errors="replace")[-1200:])
            print("      --- frps.log(尾) ---")
            print(srv.text()[-2000:])

    try:
        if not wait_port(gw):
            print("❌ SSH 网关未监听")
            return 1

        # tcp
        r1 = free_port()
        run_case(
            "tcp",
            f"tcp --remote_port {r1} --token {TOKEN} --user {USER} --proxy_name ssh-tcp",
            r1, echo_port, lambda: check_tcp(r1),
        )

        # tcpmux
        r2 = free_port()
        run_case(
            "tcpmux",
            f"tcpmux --custom_domain sshmux.test --token {TOKEN} --user {USER} "
            f"--proxy_name ssh-mux",
            r2, http_port, lambda: check_tcpmux(mux_port, "sshmux.test"),
        )

        # stcp：SSH 侧是 provider，再用 nfrp-client 起 visitor 访问
        r3 = free_port()
        visitor_port = free_port()
        (work / "visitor.toml").write_text(
            f'server_addr = "127.0.0.1"\nserver_port = {bind}\ntoken = "{TOKEN}"\n'
            f'user = "{USER}"\nlogin_fail_exit = true\n'
            f'[[visitors]]\nname = "ssh-stcp-visitor"\ntype = "stcp"\n'
            f'server_name = "ssh-stcp"\nsecret_key = "sk-ssh-e2e"\n'
            f'bind_addr = "127.0.0.1"\nbind_port = {visitor_port}\n',
            encoding="utf-8",
        )
        vis = Proc([str(frpc), "-c", str(work / "visitor.toml")], work / "visitor.log")
        procs.append(vis)
        run_case(
            "stcp",
            f"stcp --sk sk-ssh-e2e --allow_users {USER} --token {TOKEN} --user {USER} "
            f"--proxy_name ssh-stcp",
            free_port(), echo_port, lambda: check_stcp(visitor_port),
        )

        print("\n" + "=" * 56)
        passed = sum(1 for _, ok, _ in RESULTS if ok)
        for n, ok, _ in RESULTS:
            print(f"{'PASS' if ok else 'FAIL'}  {n}")
        print(f"{passed}/{len(RESULTS)} 通过")
        if passed != len(RESULTS) or args.keep:
            print(f"日志保留在：{work}")
        return 0 if passed == len(RESULTS) else 1
    finally:
        for p in sshs:
            p.stop()
        for p in procs:
            p.stop()


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception:  # noqa: BLE001
        traceback.print_exc()
        sys.exit(3)
