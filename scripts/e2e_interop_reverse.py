#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""反向互通 e2e：**官方 frps 0.71.0** + **nfrp-client**（真二进制、真后端）。

与 `e2e_openwrt.py --official-interop-only` 的区别：
    那一项验的是「官方 frpc → NFrp frps」；本脚本验反方向
    「官方 frps → NFrp frpc」，README 互通表里的第二行就在这里落地。

做什么：
    1) 下载官方 frp 0.71.0 的 frps（按平台选 windows_amd64.zip /
       linux_amd64.tar.gz，另支持 darwin），带 sha256 校验与 3 次重试；
    2) 起官方 frps（token + 随机 bind_port 20000-45000 + 随机 vhost端口）；
    3) nfrp-client 连上去，跑一条 tcp、一条 http；
    4) tcp 用本地 echo 后端校验数据面内容，http 用 Host 头校验响应体。

sha256 的诚实说明：
    官方 Release 是否提供校验和文件取决于版本。脚本会先试
    `frp_sha256_checksums.txt` / `frp_0.71.0_checksums.txt`；拿到就按官方值
    校验。拿不到时**不伪造**一个「已验证」的哈希，而是首次下载把实际 sha256
    记到缓存目录的 `.sha256` 旁路文件（TOFU：trust on first use），后续下载
    都与该记录比对。日志里会明确标注这次是「官方校验和」还是「本地 TOFU」。

失败语义：
    下载失败、解压失败、找不到 nfrp-client、官方 frps 起不来 → 一律非零退出，
    绝不 SKIP 后当通过。

用法：
    python scripts/e2e_interop_reverse.py --bin-dir ../dist/autostart-0.7.10
    python3 scripts/e2e_interop_reverse.py --bin-dir /opt/nfrp --keep
    python3 scripts/e2e_interop_reverse.py --bin-dir target/release \
        --workdir /tmp/interop-reverse

退出码：
    0 全部通过 / 1 有用例失败 / 2 下载或环境准备失败 / 3 未预期异常
"""

from __future__ import annotations

import argparse
import hashlib
import http.client
import http.server
import os
import platform
import random
import shutil
import socket
import subprocess
import sys
import tarfile
import tempfile
import threading
import time
import traceback
import urllib.request
import zipfile
from pathlib import Path

sys.stdout.reconfigure(encoding="utf-8", errors="replace")

ROOT = Path(__file__).resolve().parent.parent
OFFICIAL_VERSION = "0.71.0"
TOKEN = "interop-reverse-token"
CACHE_DIR = ROOT / "tmp" / "interop-cache"
RESULTS: list[tuple[str, bool, str]] = []


# ---------------------------------------------------------------------------
# 平台 / 下载 / 校验
# ---------------------------------------------------------------------------
def platform_asset() -> tuple[str, str]:
    """返回 (资产名, 归档类型)；不支持时抛 RuntimeError。"""
    machine = platform.machine().lower()
    arch = {
        "x86_64": "amd64",
        "amd64": "amd64",
        "aarch64": "arm64",
        "arm64": "arm64",
    }.get(machine)
    if arch is None:
        raise RuntimeError(f"不支持的 CPU 架构：{machine}")

    if sys.platform.startswith("win"):
        return f"frp_{OFFICIAL_VERSION}_windows_{arch}.zip", "zip"
    if sys.platform.startswith("linux"):
        return f"frp_{OFFICIAL_VERSION}_linux_{arch}.tar.gz", "tar.gz"
    if sys.platform == "darwin":
        return f"frp_{OFFICIAL_VERSION}_darwin_{arch}.tar.gz", "tar.gz"
    raise RuntimeError(f"不支持的操作系统：{sys.platform}")


def release_url(asset: str) -> str:
    return (
        "https://github.com/fatedier/frp/releases/download/"
        f"v{OFFICIAL_VERSION}/{asset}"
    )


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def download(url: str, dest: Path, attempts: int = 3, timeout: int = 120) -> None:
    """下载到 dest（先写 .part，成功后改名），失败重试 attempts 次。"""
    dest.parent.mkdir(parents=True, exist_ok=True)
    part = dest.with_suffix(dest.suffix + ".part")
    last: Exception | None = None
    for i in range(1, attempts + 1):
        try:
            print(f"  下载 ({i}/{attempts})：{url}")
            req = urllib.request.Request(url, headers={"User-Agent": "nfrp-interop/1.0"})
            with urllib.request.urlopen(req, timeout=timeout) as resp, open(part, "wb") as f:
                shutil.copyfileobj(resp, f)
            part.replace(dest)
            return
        except Exception as e:  # noqa: BLE001 - 统一重试并保留最后错误
            last = e
            print(f"  ⚠️ 第 {i} 次下载失败：{type(e).__name__}: {e}")
            try:
                part.unlink()
            except OSError:
                pass
            if i < attempts:
                time.sleep(min(2 ** i, 10))
    raise RuntimeError(f"下载失败（重试 {attempts} 次）：{url}\n{last}")


def official_checksums(asset: str) -> tuple[str | None, str]:
    """尽力取官方 sha256；取不到返回 (None, 说明)。"""
    names = ["frp_sha256_checksums.txt", f"frp_{OFFICIAL_VERSION}_checksums.txt"]
    for name in names:
        try:
            req = urllib.request.Request(
                release_url(name), headers={"User-Agent": "nfrp-interop/1.0"}
            )
            with urllib.request.urlopen(req, timeout=30) as resp:
                text = resp.read().decode("utf-8", "replace")
        except Exception as e:  # noqa: BLE001 - 有就校验，没有就标注 TOFU
            print(f"  （官方校验和 {name} 不可得：{type(e).__name__}）")
            continue
        for line in text.splitlines():
            parts = line.split()
            if len(parts) >= 2 and parts[-1].lstrip("*") == asset:
                return parts[0].lower(), f"官方 {name}"
    return None, "官方未提供可核对的 sha256"


def verify_or_record(archive: Path, asset: str) -> str:
    """返回本次校验方式的说明；不匹配直接非零退出。"""
    actual = sha256_file(archive)
    expected, source = official_checksums(asset)
    sidecar = CACHE_DIR / f"{asset}.sha256"

    if expected is not None:
        if actual != expected:
            print(
                f"\n❌ sha256 与{source}不一致\n"
                f"  期望 {expected}\n  实际 {actual}\n  文件 {archive}",
                file=sys.stderr,
            )
            raise SystemExit(2)
        return f"sha256 已按{source}校验（{actual}）"

    if sidecar.is_file():
        recorded = sidecar.read_text(encoding="utf-8").split()[0].strip().lower()
        if actual != recorded:
            print(
                f"\n❌ sha256 与首次下载记录不一致（TOFU）\n"
                f"  记录 {recorded}\n  实际 {actual}\n"
                f"  记录文件 {sidecar}；确认上游是否重新发布了同名资产",
                file=sys.stderr,
            )
            raise SystemExit(2)
        return f"sha256 与首次下载记录一致（TOFU，{actual}）"

    CACHE_DIR.mkdir(parents=True, exist_ok=True)
    sidecar.write_text(f"{actual}  {asset}\n", encoding="utf-8")
    return (
        f"⚠️ {source}；已按 TOFU 记录本次 sha256（{actual}）到 {sidecar}，"
        "后续下载将与它比对 —— 这不是官方校验，别当成「已验证」"
    )


def extract_frps(archive: Path, kind: str, dest_dir: Path) -> Path:
    """从归档里取出官方 frps 可执行文件。"""
    want = "frps.exe" if os.name == "nt" else "frps"
    out = dest_dir / want
    if kind == "zip":
        with zipfile.ZipFile(archive) as z:
            member = next(
                (m for m in z.namelist() if m.replace("\\", "/").endswith("/" + want)),
                None,
            )
            if member is None:
                raise RuntimeError(f"{archive.name} 里没有 {want}")
            with z.open(member) as src, open(out, "wb") as f:
                shutil.copyfileobj(src, f)
    else:
        with tarfile.open(archive, "r:gz") as t:
            member = next(
                (
                    m
                    for m in t.getmembers()
                    if m.name.endswith("/" + want) and m.isfile()
                ),
                None,
            )
            if member is None:
                raise RuntimeError(f"{archive.name} 里没有 {want}")
            fh = t.extractfile(member)
            if fh is None:
                raise RuntimeError(f"{archive.name} 里的 {want} 读不出内容")
            out.write_bytes(fh.read())
    if os.name != "nt":
        out.chmod(0o755)
    return out


def cache_note() -> None:
    """缓存目录应被 .gitignore 覆盖；不覆盖时明确警告（不阻断）。"""
    gi = ROOT / ".gitignore"
    text = gi.read_text(encoding="utf-8", errors="replace") if gi.is_file() else ""
    if "/tmp" not in text and "tmp/" not in text:
        print(
            f"⚠️ 缓存目录 {CACHE_DIR} 未被根 .gitignore 的 /tmp 覆盖，请确认不要误提交"
        )


# ---------------------------------------------------------------------------
# 后端 / 端口 / 进程
# ---------------------------------------------------------------------------
class _HttpHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):  # noqa: N802
        body = f"INTEROP-HTTP-OK path={self.path} host={self.headers.get('Host', '')}".encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):  # 静音
        pass


def start_tcp_echo() -> tuple[int, socket.socket]:
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
                c.sendall(b"INTEROP-TCP:" + d)
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


def start_http_backend() -> tuple[int, http.server.ThreadingHTTPServer]:
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _HttpHandler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv.server_address[1], srv


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


class Proc:
    def __init__(self, args: list[str], log: Path):
        self.log = log
        self.log.parent.mkdir(parents=True, exist_ok=True)
        self.fh = open(log, "wb")
        self.p = subprocess.Popen(args, stdout=self.fh, stderr=subprocess.STDOUT)

    def alive(self) -> bool:
        return self.p.poll() is None

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
# 用例
# ---------------------------------------------------------------------------
def wait_tcp_echo(port: int, timeout: float = 20.0) -> tuple[bool, str]:
    deadline = time.time() + timeout
    last = ""
    payload = b"interop-ping-" + str(random.randint(0, 9999)).encode()
    while time.time() < deadline:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=3) as c:
                c.settimeout(5)
                c.sendall(payload)
                data = c.recv(4096)
            if data == b"INTEROP-TCP:" + payload:
                return True, data.decode(errors="replace")
            last = repr(data)
        except Exception as e:  # noqa: BLE001
            last = f"{type(e).__name__}: {e}"
        time.sleep(0.4)
    return False, last


def wait_http_vhost(port: int, host: str, timeout: float = 20.0) -> tuple[bool, str]:
    deadline = time.time() + timeout
    last = ""
    while time.time() < deadline:
        try:
            c = http.client.HTTPConnection("127.0.0.1", port, timeout=4)
            c.request("GET", "/interop", headers={"Host": host})
            r = c.getresponse()
            body = r.read().decode("utf-8", "replace")
            c.close()
            if r.status == 200 and "INTEROP-HTTP-OK" in body and "path=/interop" in body:
                return True, body
            last = f"status={r.status} body={body[:200]}"
        except Exception as e:  # noqa: BLE001
            last = f"{type(e).__name__}: {e}"
        time.sleep(0.4)
    return False, last


def write_client_config(
    path: Path, bind_port: int, proxies: str
) -> None:
    path.write_text(
        f'server_addr = "127.0.0.1"\nserver_port = {bind_port}\n'
        f'token = "{TOKEN}"\nlogin_fail_exit = true\nlog_level = "info"\n\n' + proxies,
        encoding="utf-8",
        newline="\n",
    )


def resolve_client(bin_dir: str | None) -> Path:
    ext = ".exe" if os.name == "nt" else ""
    cands: list[Path] = []
    if bin_dir:
        cands.append(Path(bin_dir))
    cands += [
        *sorted(ROOT.parent.glob("dist/autostart-*"), reverse=True),
        ROOT / "target" / "release",
        ROOT / "target" / "debug",
    ]
    for d in cands:
        for name in ("nfrp-client", "frpc"):
            p = d / f"{name}{ext}"
            if p.is_file():
                return p
    raise SystemExit(
        "找不到 nfrp-client（或 frpc）；用 --bin-dir 指定目录。tried: "
        + ", ".join(str(c) for c in cands)
    )


def run_case(name: str, work: Path, client: Path, bind_port: int, proxies: str, check) -> None:
    d = work / name
    d.mkdir(parents=True, exist_ok=True)
    write_client_config(d / "frpc.toml", bind_port, proxies)
    proc = Proc([str(client), "-c", str(d / "frpc.toml")], d / "frpc.log")
    try:
        ok, detail = check()
    finally:
        client_log = proc.text()
        proc.stop()
    if not ok:
        detail += "\n--- frpc.log(尾) ---\n" + client_log[-2500:]
    RESULTS.append((name, ok, detail))
    print(("  ✅ " if ok else "  ❌ ") + name + ("" if ok else "\n" + detail), flush=True)


def main() -> int:
    ap = argparse.ArgumentParser(
        description="反向互通：官方 frps 0.71.0 + nfrp-client（tcp / http 各一条隧道）"
    )
    ap.add_argument("--bin-dir", help="nfrp-client 所在目录（默认自动查找）")
    ap.add_argument("--workdir", help="工作目录（日志落这里；默认临时目录）")
    ap.add_argument("--keep", action="store_true", help="结束后保留临时工作目录")
    args = ap.parse_args()

    cache_note()
    CACHE_DIR.mkdir(parents=True, exist_ok=True)

    # --- 官方 frps ---------------------------------------------------------
    try:
        asset, kind = platform_asset()
    except RuntimeError as e:
        print(f"❌ {e}", file=sys.stderr)
        return 2
    archive = CACHE_DIR / asset
    if archive.is_file():
        print(f"缓存命中：{archive}（仍会重新校验 sha256）")
    else:
        try:
            download(release_url(asset), archive)
        except RuntimeError as e:
            print(f"\n❌ 官方 frps 下载失败，无法跑反向互通：\n{e}", file=sys.stderr)
            return 2

    try:
        how = verify_or_record(archive, asset)
    except SystemExit as e:
        print(f"❌ sha256 校验失败（退出码 {e.code}）", file=sys.stderr)
        return 2
    print(f"校验方式：{how}")

    work = Path(args.workdir) if args.workdir else Path(tempfile.mkdtemp(prefix="nfrp-interop-rev-"))
    work.mkdir(parents=True, exist_ok=True)
    frps = extract_frps(archive, kind, work)
    print(f"官方 frps：{frps}")

    # 确认拿到的是 0.71.0，而不是别的版本 / 别的二进制
    vp = subprocess.run([str(frps), "-v"], capture_output=True, text=True,
                        encoding="utf-8", errors="replace")
    version_text = (vp.stdout or vp.stderr).strip()
    if version_text != OFFICIAL_VERSION:
        print(f"❌ 官方 frps 版本不是 {OFFICIAL_VERSION}：[{version_text}]", file=sys.stderr)
        return 2
    print(f"官方 frps -v = {version_text}")

    client = resolve_client(args.bin_dir)
    print(f"nfrp-client：{client}")

    # --- 后端 --------------------------------------------------------------
    tcp_backend, tcp_sock = start_tcp_echo()
    http_backend, http_srv = start_http_backend()

    # --- 官方 frps ---------------------------------------------------------
    bind_port = free_port()
    vhost_port = free_port()
    (work / "frps.toml").write_text(
        f'bindAddr = "127.0.0.1"\nbindPort = {bind_port}\n'
        f'vhostHTTPPort = {vhost_port}\n'
        f'auth.method = "token"\nauth.token = "{TOKEN}"\n'
        f'log.level = "info"\nlog.to = "console"\n',
        encoding="utf-8",
        newline="\n",
    )
    server = Proc([str(frps), "-c", str(work / "frps.toml")], work / "frps.log")
    print(f"后端：tcp={tcp_backend} http={http_backend}")
    print(f"官方 frps：bind={bind_port} vhost={vhost_port}")
    print(f"工作目录：{work}\n")

    remote_tcp = free_port()
    try:
        if not wait_port(bind_port, 15):
            print("❌ 官方 frps 未监听 bind_port：\n" + server.text()[-3000:], file=sys.stderr)
            return 1

        run_case(
            "tcp",
            work,
            client,
            bind_port,
            f'[[proxies]]\nname = "interop-tcp"\ntype = "tcp"\n'
            f'local_ip = "127.0.0.1"\nlocal_port = {tcp_backend}\n'
            f'remote_port = {remote_tcp}\n',
            lambda: wait_tcp_echo(remote_tcp),
        )

        run_case(
            "http",
            work,
            client,
            bind_port,
            f'[[proxies]]\nname = "interop-http"\ntype = "http"\n'
            f'local_ip = "127.0.0.1"\nlocal_port = {http_backend}\n'
            f'custom_domains = ["interop.test"]\n',
            lambda: wait_http_vhost(vhost_port, "interop.test"),
        )
    finally:
        server_text = server.text()
        server.stop()
        tcp_sock.close()
        http_srv.shutdown()

    print("\n" + "=" * 62)
    passed = sum(1 for _, ok, _ in RESULTS if ok)
    for name, ok, _ in RESULTS:
        print(f"{'PASS' if ok else 'FAIL'}  {name}")
    print(f"{passed}/{len(RESULTS)} 通过")

    if passed != len(RESULTS):
        print("\n--- frps.log(尾) ---\n" + server_text[-3000:])

    keep = args.keep or bool(args.workdir) or passed != len(RESULTS)
    if keep:
        print(f"日志与配置保留在：{work}")
    else:
        shutil.rmtree(work, ignore_errors=True)

    return 0 if passed == len(RESULTS) else 1


if __name__ == "__main__":
    try:
        sys.exit(main())
    except SystemExit:
        raise
    except Exception:  # noqa: BLE001
        traceback.print_exc()
        sys.exit(3)
