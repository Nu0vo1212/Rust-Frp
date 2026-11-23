#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""内存基准：起 N 条隧道，从 /proc/<pid>/status 读 frps 的 VmRSS，输出 Markdown 表。

**仅支持 Linux**（依赖 /proc/<pid>/status）。在 Windows / macOS 上运行会明确
打印「仅支持 Linux」并以非零码退出，不会假装成功。

测量口径：
    * 基线 = frps 已监听、nfrp-client 已登录但**没有任何代理**时的 RSS；
    * 每隧道增量 = (RSS(N) - RSS(基线)) / N；
    * 每个 N 重复 `--repeat` 次（默认 3），取中位数；每次都是全新的 frps + frpc
      进程，不复用上一次的路由 / 会话状态。
    * 确认 N 条 remote_port 都可达（会各建一次短连接，随即关闭）后，再等 1.5 s
      让工作连接回收，然后读 RSS —— 因此数字包含稳态下的会话表开销，
      不含正在传输的连接。

用法：
    # 本机 Linux，指向 cargo 产物（nfrp-server / nfrp-client）
    python3 scripts/bench_mem.py --nfrp-bin-dir target/release

    # 指定隧道数阶梯（默认 1,10,100）
    python3 scripts/bench_mem.py --nfrp-bin-dir target/release --tunnels 1,10,100,500

    # 加一个官方 frps 作对照（前端仍是 nfrp-client）
    python3 scripts/bench_mem.py --nfrp-bin-dir target/release \
        --official-frps /opt/frp_0.71.0_linux_amd64/frps

    # 重复 5 次取中位数，保留日志
    python3 scripts/bench_mem.py --nfrp-bin-dir target/release --repeat 5 --keep

退出码：0 成功 / 2 平台或参数不支持 / 3 运行期失败。
"""

from __future__ import annotations

import argparse
import os
import random
import shutil
import socket
import statistics
import subprocess
import sys
import tempfile
import threading
import time
import traceback
from pathlib import Path

sys.stdout.reconfigure(encoding="utf-8", errors="replace")

ROOT = Path(__file__).resolve().parent.parent
TOKEN = "bench-mem-token"
SETTLE_SECONDS = 1.5


# ---------------------------------------------------------------------------
# 平台与端口
# ---------------------------------------------------------------------------
def linux_only() -> None:
    if sys.platform.startswith("linux") and Path("/proc/self/status").is_file():
        return
    print(
        f"此脚本仅支持 Linux（需要 /proc/<pid>/status 读取 VmRSS）；"
        f"当前平台：{sys.platform}",
        file=sys.stderr,
    )
    sys.exit(2)


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


def alloc_ports(n: int) -> list[int]:
    ports: set[int] = set()
    while len(ports) < n:
        ports.add(free_port())
    return sorted(ports)


def wait_port(port: int, timeout: float = 20.0) -> bool:
    end = time.time() + timeout
    while time.time() < end:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.5):
                return True
        except OSError:
            time.sleep(0.1)
    return False


# ---------------------------------------------------------------------------
# RSS
# ---------------------------------------------------------------------------
def parse_vmrss(text: str) -> int | None:
    """从 /proc/<pid>/status 内容里取 VmRSS（KiB）；解析不出返回 None。"""
    for line in text.splitlines():
        line = line.strip()
        if line.startswith("VmRSS:"):
            parts = line.split()
            if len(parts) >= 2:
                try:
                    return int(parts[1])
                except ValueError:
                    return None
    return None


def read_rss(pid: int) -> int:
    status = Path(f"/proc/{pid}/status")
    text = status.read_text(encoding="utf-8", errors="replace")
    kb = parse_vmrss(text)
    if kb is None:
        raise RuntimeError(f"/proc/{pid}/status 里没有可解析的 VmRSS")
    return kb


# ---------------------------------------------------------------------------
# 后端 / 进程
# ---------------------------------------------------------------------------
def start_tcp_backend() -> tuple[int, socket.socket]:
    srv = socket.socket()
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 0))
    srv.listen(128)
    port = srv.getsockname()[1]

    def handle(c: socket.socket) -> None:
        try:
            while True:
                d = c.recv(4096)
                if not d:
                    break
                c.sendall(d)
        except OSError:
            pass
        finally:
            c.close()

    def loop() -> None:
        while True:
            try:
                c, _ = srv.accept()
            except OSError:
                return
            threading.Thread(target=handle, args=(c,), daemon=True).start()

    threading.Thread(target=loop, daemon=True).start()
    return port, srv


class Proc:
    def __init__(self, args: list[str], log: Path):
        log.parent.mkdir(parents=True, exist_ok=True)
        self.log = log
        self.fh = open(log, "wb")
        self.p = subprocess.Popen(args, stdout=self.fh, stderr=subprocess.STDOUT)

    def stop(self) -> None:
        try:
            self.p.terminate()
            self.p.wait(timeout=8)
        except Exception:  # noqa: BLE001
            try:
                self.p.kill()
                self.p.wait(timeout=5)
            except Exception:  # noqa: BLE001
                pass
        try:
            self.fh.close()
        except Exception:  # noqa: BLE001
            pass

    def text(self) -> str:
        try:
            self.fh.flush()
        except Exception:  # noqa: BLE001
            pass
        try:
            return self.log.read_text(encoding="utf-8", errors="replace")
        except Exception:  # noqa: BLE001
            return ""


# ---------------------------------------------------------------------------
# 配置
# ---------------------------------------------------------------------------
def write_server_config(path: Path, bind_port: int, official: bool) -> None:
    if official:
        # 官方 0.71 的 TOML 键名（camelCase + auth 表）
        text = (
            f'bindAddr = "127.0.0.1"\nbindPort = {bind_port}\n'
            f'auth.method = "token"\nauth.token = "{TOKEN}"\n'
            f'log.level = "warn"\nlog.to = "console"\n'
        )
    else:
        text = (
            f'bind_addr = "127.0.0.1"\nbind_port = {bind_port}\n'
            f'token = "{TOKEN}"\nlog_level = "warn"\n'
        )
    path.write_text(text, encoding="utf-8", newline="\n")


def write_client_config(
    path: Path, bind_port: int, backend_port: int, remote_ports: list[int]
) -> None:
    lines = [
        'server_addr = "127.0.0.1"',
        f"server_port = {bind_port}",
        f'token = "{TOKEN}"',
        "login_fail_exit = true",
        'log_level = "warn"',
        "",
    ]
    for i, rp in enumerate(remote_ports):
        lines += [
            "[[proxies]]",
            f'name = "t{i}"',
            'type = "tcp"',
            'local_ip = "127.0.0.1"',
            f"local_port = {backend_port}",
            f"remote_port = {rp}",
            "",
        ]
    path.write_text("\n".join(lines), encoding="utf-8", newline="\n")


# ---------------------------------------------------------------------------
# 一次采样
# ---------------------------------------------------------------------------
def sample_once(
    server_bin: Path,
    official: bool,
    client_bin: Path,
    n: int,
    backend_port: int,
    work: Path,
    tag: str,
) -> int:
    """起一对进程，等 N 条隧道就绪，返回 frps 的 VmRSS（KiB）。"""
    d = work / tag
    d.mkdir(parents=True, exist_ok=True)
    bind_port = free_port()
    remote_ports = alloc_ports(n)
    write_server_config(d / "frps.toml", bind_port, official)
    write_client_config(d / "frpc.toml", bind_port, backend_port, remote_ports)

    server = Proc([str(server_bin), "-c", str(d / "frps.toml")], d / "frps.log")
    client = None
    try:
        if not wait_port(bind_port, 20):
            raise RuntimeError(
                f"frps 未监听 bind_port={bind_port}（{server_bin}）\n" + server.text()[-2000:]
            )
        client = Proc([str(client_bin), "-c", str(d / "frpc.toml")], d / "frpc.log")

        deadline = time.time() + 30
        pending = list(remote_ports)
        while pending and time.time() < deadline:
            pending = [p for p in pending if not wait_port(p, timeout=0.2)]
        if pending:
            raise RuntimeError(
                f"{len(pending)} 个 remote_port 未就绪（N={n}）\n"
                + client.text()[-2000:]
            )
        time.sleep(SETTLE_SECONDS)
        return read_rss(server.p.pid)
    finally:
        if client is not None:
            client.stop()
        server.stop()


def median_rss(
    server_bin: Path,
    official: bool,
    client_bin: Path,
    n: int,
    backend_port: int,
    work: Path,
    repeats: int,
    tag: str,
) -> int:
    samples = [
        sample_once(server_bin, official, client_bin, n, backend_port, work, f"{tag}-r{i}")
        for i in range(repeats)
    ]
    print(f"    {tag}: N={n} 采样 {samples} KiB → 中位数 {statistics.median(samples):.0f} KiB")
    return int(statistics.median(samples))


# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------
def main() -> int:
    ap = argparse.ArgumentParser(description="Linux 内存基准：N 条隧道下的 frps VmRSS")
    ap.add_argument("--nfrp-bin-dir", required=True,
                    help="含 nfrp-server / nfrp-client（或 frps / frpc）的目录")
    ap.add_argument("--official-frps", help="可选：官方 frps 可执行文件，作对照")
    ap.add_argument("--tunnels", default="1,10,100",
                    help="隧道数阶梯，逗号分隔（默认 1,10,100）")
    ap.add_argument("--repeat", type=int, default=3, help="每个 N 的重复次数（默认 3）")
    ap.add_argument("--keep", action="store_true", help="保留临时工作目录与日志")
    args = ap.parse_args()

    linux_only()

    try:
        counts = sorted({int(x) for x in args.tunnels.split(",") if x.strip()})
    except ValueError:
        print(f"--tunnels 解析失败：{args.tunnels}", file=sys.stderr)
        return 2
    if not counts or counts[0] < 0:
        print("--tunnels 至少给一个 >= 0 的整数", file=sys.stderr)
        return 2
    if args.repeat < 1:
        print("--repeat 至少为 1", file=sys.stderr)
        return 2

    ext = ".exe" if os.name == "nt" else ""
    bin_dir = Path(args.nfrp_bin_dir)
    pairs = (("nfrp-server", "nfrp-client"), ("frps", "frpc"))
    server_bin = client_bin = None
    for srv, cli in pairs:
        if (bin_dir / f"{srv}{ext}").is_file() and (bin_dir / f"{cli}{ext}").is_file():
            server_bin, client_bin = bin_dir / f"{srv}{ext}", bin_dir / f"{cli}{ext}"
            break
    if server_bin is None or client_bin is None:
        print(f"目录里找不到 nfrp-server/nfrp-client（或 frps/frpc）：{bin_dir}", file=sys.stderr)
        return 2

    official_path = Path(args.official_frps).resolve() if args.official_frps else None
    if official_path is not None and not official_path.is_file():
        print(f"--official-frps 不存在：{official_path}", file=sys.stderr)
        return 2

    work = Path(tempfile.mkdtemp(prefix="nfrp-bench-mem-"))
    backend_port, backend_sock = start_tcp_backend()
    print(f"nfrp 服务端：{server_bin}")
    print(f"nfrp 客户端：{client_bin}")
    if official_path:
        print(f"官方 frps 对照：{official_path}")
    print(f"隧道阶梯：{counts}；重复 {args.repeat} 次取中位数；工作目录：{work}\n")

    try:
        nfrp_rss = {
            n: median_rss(server_bin, False, client_bin, n, backend_port, work,
                          args.repeat, "nfrp")
            for n in counts
        }
        official_rss: dict[int, int] = {}
        if official_path:
            official_rss = {
                n: median_rss(official_path, True, client_bin, n, backend_port, work,
                              args.repeat, "official")
                for n in counts
            }
    finally:
        backend_sock.close()

    base_n = min(counts)
    base = nfrp_rss[base_n]
    if base_n != 0:
        print(f"⚠️ 阶梯里没有 0；每隧道增量以 N={base_n} 的 RSS 为基线，"
              "会低估固定开销的占比")

    def delta(values: dict[int, int], n: int, baseline: int) -> str:
        if n == baseline:
            return "—"
        return f"{(values[n] - baseline) / (n - baseline):.1f}"

    print("\n## frps 常驻内存（VmRSS，中位数）\n")
    if official_path:
        base_off = official_rss[base_n]
        print("| N | nfrp frps RSS (KiB) | 官方 frps RSS (KiB) | nfrp 每隧道增量 (KiB) | 官方 每隧道增量 (KiB) |")
        print("|---:|---:|---:|---:|---:|")
        for n in counts:
            print(
                f"| {n} | {nfrp_rss[n]} | {official_rss[n]} | "
                f"{delta(nfrp_rss, n, base)} | {delta(official_rss, n, base_off)} |"
            )
    else:
        print("| N | frps RSS (KiB) | 每隧道增量 (KiB) |")
        print("|---:|---:|---:|")
        for n in counts:
            print(f"| {n} | {nfrp_rss[n]} | {delta(nfrp_rss, n, base)} |")

    print("\n说明：每隧道增量 = (RSS(N) - 基线) / (N - 基线N)；"
          f"基线为 N={base_n}。数据为 {args.repeat} 次独立进程采样的中位数。")

    if args.keep:
        print(f"\n日志保留在：{work}")
    else:
        shutil.rmtree(work, ignore_errors=True)
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except SystemExit:
        raise
    except Exception:  # noqa: BLE001
        traceback.print_exc()
        sys.exit(3)
