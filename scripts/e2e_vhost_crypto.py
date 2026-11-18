#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""v0.7.6 vhost/udp 数据面加密压缩 —— 真二进制端到端验证。

为什么要这个脚本（而不是只信单测）：
    0.7.6 修的是「服务端 vhost 把工作连接当裸流中继，忽略 useEncryption /
    useCompression」。这条路径的单测是内存流对拷，能过；但真实链路里
    客户端写的是密文/压缩帧，服务端若按明文转发，后端看到的就是乱码。
    所以必须起 **真的 frps.exe + frpc.exe + 真的后端**跑一遍。

覆盖矩阵：
    http  明文 / 仅加密 / 仅压缩 / 加密+压缩
    tcp   加密+压缩（对照组，这条路径 0.7.6 之前就是对的）
    udp   加密+压缩
    https 加密+压缩（TLS 后端）
    tcpmux 加密+压缩

用法：
    # Windows：指向解压后的发布目录
    python scripts/e2e_vhost_crypto.py --bin-dir ..\\dist\\autostart-0.7.7
    # Linux / macOS：二进制不带 .exe 后缀
    python3 scripts/e2e_vhost_crypto.py --bin-dir /opt/nfrp

默认会依次尝试 `dist/autostart-<ver>`、`target/release`、`../dist/release`。
退出码 0 = 全部通过。
"""

from __future__ import annotations

import argparse
import http.client
import http.server
import json
import os
import random
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time
import traceback
from pathlib import Path

sys.stdout.reconfigure(encoding="utf-8", errors="replace")

ROOT = Path(__file__).resolve().parent.parent
TOKEN = "e2e-crypto-token"


def resolve_bin_dir(explicit: str | None) -> Path:
    """找一对可执行的 frps / frpc。"""
    ext = ".exe" if os.name == "nt" else ""
    candidates: list[Path] = []
    if explicit:
        candidates.append(Path(explicit))
    candidates += [
        *sorted(ROOT.parent.glob("dist/autostart-*"), reverse=True),
        ROOT / "target" / "release",
        ROOT.parent / "dist" / "release",
    ]
    for d in candidates:
        # 发布包里叫 frps/frpc，cargo 产物叫 nfrp-server/nfrp-client
        for srv, cli in (("frps", "frpc"), ("nfrp-server", "nfrp-client")):
            s, c = d / f"{srv}{ext}", d / f"{cli}{ext}"
            if s.is_file() and c.is_file():
                return d
    raise SystemExit(
        "找不到 frps/frpc；用 --bin-dir 指定发布目录\tried: "
        + ", ".join(str(c) for c in candidates)
    )


BIN = Path(".")
FRPS = Path("frps")
FRPC = Path("frpc")

results: list[tuple[str, bool, str]] = []


def free_port() -> int:
    """在 20000-45000 之间找一个空闲端口（避开 Windows 动态端口段）。"""
    for _ in range(200):
        p = random.randint(20000, 45000)
        with socket.socket() as s:
            try:
                s.bind(("127.0.0.1", p))
            except OSError:
                continue
        return p
    raise RuntimeError("找不到空闲端口")


# ---------------------------------------------------------------------------
# 后端服务
# ---------------------------------------------------------------------------
class _Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):  # noqa: N802
        body = f"BACKEND-OK path={self.path} host={self.headers.get('Host', '')}".encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):  # 静音
        pass


def start_http_backend() -> tuple[int, http.server.ThreadingHTTPServer]:
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv.server_address[1], srv


class _TlsHandler(_Handler):
    pass


def start_https_backend(certdir: Path) -> tuple[int, http.server.ThreadingHTTPServer]:
    """自签证书的 HTTPS 后端（用 cryptography 生成，不依赖系统 openssl）。"""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID
    import datetime as dt

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "127.0.0.1")])
    now = dt.datetime.now(dt.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(minutes=5))
        .not_valid_after(now + dt.timedelta(days=2))
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName("tls.e2e"), x509.IPAddress(__import__("ipaddress").ip_address("127.0.0.1"))]),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )
    keypath = certdir / "backend.key"
    crtpath = certdir / "backend.crt"
    keypath.write_bytes(
        key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )
    crtpath.write_bytes(cert.public_bytes(serialization.Encoding.PEM))

    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _TlsHandler)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(str(crtpath), str(keypath))
    srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv.server_address[1], srv


class _UdpEcho(threading.Thread):
    def __init__(self, sock: socket.socket):
        super().__init__(daemon=True)
        self.sock = sock

    def run(self):
        while True:
            try:
                data, addr = self.sock.recvfrom(65535)
            except OSError:
                return
            try:
                self.sock.sendto(b"UDP-ECHO:" + data, addr)
            except OSError:
                return


def start_udp_backend() -> tuple[int, socket.socket]:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("127.0.0.1", 0))
    _UdpEcho(s).start()
    return s.getsockname()[1], s


# ---------------------------------------------------------------------------
# 进程管理
# ---------------------------------------------------------------------------
class Proc:
    def __init__(self, args: list[str], log: Path):
        self.log = log
        self.fh = open(log, "wb")
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
            self.fh.flush()
        except Exception:
            pass
        try:
            return self.log.read_text(encoding="utf-8", errors="replace")
        except Exception:
            return ""


def tcp_open(port: int, timeout: float = 1.0) -> bool:
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=timeout):
            return True
    except OSError:
        return False


# ---------------------------------------------------------------------------
# 单个场景
# ---------------------------------------------------------------------------
def run_case(
    name: str,
    work: Path,
    server_extra: str,
    proxies: str,
    check,
) -> None:
    """起一对 frps/frpc，跑 check()，记录结果。"""
    d = work / name.replace("/", "_")
    d.mkdir(parents=True, exist_ok=True)
    bind = free_port()

    (d / "frps.toml").write_text(
        f'bind_addr = "127.0.0.1"\nbind_port = {bind}\ntoken = "{TOKEN}"\n'
        f'log_level = "debug"\n' + server_extra,
        encoding="utf-8",
    )
    (d / "frpc.toml").write_text(
        f'server_addr = "127.0.0.1"\nserver_port = {bind}\ntoken = "{TOKEN}"\n'
        f'log_level = "debug"\nlogin_fail_exit = true\n' + proxies,
        encoding="utf-8",
    )

    srv = Proc([str(FRPS), "-c", str(d / "frps.toml")], d / "frps.log")
    try:
        # 等监听口就绪
        for _ in range(50):
            if tcp_open(bind):
                break
            time.sleep(0.1)
        cli = Proc([str(FRPC), "-c", str(d / "frpc.toml")], d / "frpc.log")
        try:
            ok, detail = check(d)
        finally:
            cli_text = cli.text()
            cli.stop()
        if not ok:
            # 把两侧日志尾部带进失败原因，便于定位
            detail += (
                "\n--- frpc.log(尾) ---\n" + cli_text[-2500:]
                + "\n--- frps.log(尾) ---\n" + srv.text()[-2500:]
            )
        results.append((name, ok, detail))
        print(("  ✅ " if ok else "  ❌ ") + name + ("" if ok else "\n" + detail))
    finally:
        srv.stop()


def wait_http(port: int, host: str, timeout: float = 15.0) -> tuple[bool, str]:
    """轮询直到 http 转发真的返回内容。"""
    deadline = time.time() + timeout
    last = ""
    while time.time() < deadline:
        try:
            c = http.client.HTTPConnection("127.0.0.1", port, timeout=3)
            c.request("GET", "/probe", headers={"Host": host})
            r = c.getresponse()
            body = r.read().decode("utf-8", "replace")
            c.close()
            if r.status == 200 and "BACKEND-OK" in body:
                return True, body
            last = f"status={r.status} body={body[:200]}"
        except Exception as e:  # noqa: BLE001
            last = f"{type(e).__name__}: {e}"
        time.sleep(0.3)
    return False, last


def transport(enc: bool, comp: bool) -> str:
    if not enc and not comp:
        return ""
    return "\n  [proxies.transport]\n" + (
        "  use_encryption = true\n" if enc else ""
    ) + ("  use_compression = true\n" if comp else "")


def main() -> int:
    global BIN, FRPS, FRPC

    ap = argparse.ArgumentParser()
    ap.add_argument("--bin-dir", help="frps/frpc 所在目录（默认自动查找）")
    ap.add_argument("--keep", action="store_true", help="结束后保留临时目录")
    args = ap.parse_args()

    BIN = resolve_bin_dir(args.bin_dir)
    ext = ".exe" if os.name == "nt" else ""
    for srv, cli in (("frps", "frpc"), ("nfrp-server", "nfrp-client")):
        if (BIN / f"{srv}{ext}").is_file():
            FRPS, FRPC = BIN / f"{srv}{ext}", BIN / f"{cli}{ext}"
            break
    print(f"二进制目录：{BIN}")

    if not FRPS.is_file() or not FRPC.is_file():
        print(f"找不到二进制：{BIN}")
        return 2

    work = Path(tempfile.mkdtemp(prefix="nfrp-e2e-crypto-"))
    http_port, http_srv = start_http_backend()
    udp_port, udp_sock = start_udp_backend()
    tcp_srv = socket.socket()
    tcp_srv.bind(("127.0.0.1", 0))
    tcp_srv.listen(16)
    tcp_port = tcp_srv.getsockname()[1]

    def tcp_echo_loop():
        while True:
            try:
                c, _ = tcp_srv.accept()
            except OSError:
                return
            threading.Thread(target=_echo_conn, args=(c,), daemon=True).start()

    threading.Thread(target=tcp_echo_loop, daemon=True).start()

    print(f"后端：http={http_port} tcp={tcp_port} udp={udp_port}")
    print(f"工作目录：{work}\n")

    # ---- http 四组 -------------------------------------------------------
    for enc, comp in [(False, False), (True, False), (False, True), (True, True)]:
        label = f"http/{'enc' if enc else 'plain'}{'+comp' if comp else ''}"
        vhost = free_port()
        run_case(
            label,
            work,
            f'vhost_http_port = {vhost}\n',
            f'[[proxies]]\nname = "web"\ntype = "http"\n'
            f'local_ip = "127.0.0.1"\nlocal_port = {http_port}\n'
            f'custom_domains = ["e2e.test"]\n' + transport(enc, comp),
            lambda d, vhost=vhost: wait_http(vhost, "e2e.test"),
        )

    # ---- tcp 对照 --------------------------------------------------------
    def check_tcp(d):
        deadline = time.time() + 15
        last = ""
        while time.time() < deadline:
            try:
                with socket.create_connection(("127.0.0.1", rport), timeout=3) as s:
                    s.sendall(b"ping-tcp")
                    data = s.recv(4096)
                    if data.startswith(b"TCP-ECHO:ping-tcp"):
                        return True, data.decode(errors="replace")
                    last = repr(data)
            except Exception as e:  # noqa: BLE001
                last = f"{type(e).__name__}: {e}"
            time.sleep(0.3)
        return False, last

    rport = free_port()
    run_case(
        "tcp/enc+comp",
        work,
        "",
        f'[[proxies]]\nname = "tcp"\ntype = "tcp"\n'
        f'local_ip = "127.0.0.1"\nlocal_port = {tcp_port}\nremote_port = {rport}\n'
        + transport(True, True),
        check_tcp,
    )

    # ---- udp 加密压缩 ----------------------------------------------------
    def check_udp(d):
        deadline = time.time() + 15
        last = ""
        while time.time() < deadline:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                s.settimeout(3)
                s.sendto(b"ping-udp", ("127.0.0.1", uport))
                data, _ = s.recvfrom(65535)
                s.close()
                if data.startswith(b"UDP-ECHO:ping-udp"):
                    return True, data.decode(errors="replace")
                last = repr(data)
            except Exception as e:  # noqa: BLE001
                last = f"{type(e).__name__}: {e}"
            time.sleep(0.3)
        return False, last

    uport = free_port()
    run_case(
        "udp/enc+comp",
        work,
        "",
        f'[[proxies]]\nname = "udp"\ntype = "udp"\n'
        f'local_ip = "127.0.0.1"\nlocal_port = {udp_port}\nremote_port = {uport}\n'
        + transport(True, True),
        check_udp,
    )

    # ---- tcpmux 加密压缩 -------------------------------------------------
    def check_tcpmux(d):
        # CONNECT 隧道：先连 server 的 tcpmux port，发 HTTP CONNECT
        deadline = time.time() + 15
        last = ""
        while time.time() < deadline:
            try:
                s = socket.create_connection(("127.0.0.1", multiplex_port), timeout=3)
                s.sendall(
                    b"CONNECT e2e-mux HTTP/1.1\r\nHost: e2e-mux\r\n\r\n"
                )
                s.settimeout(3)
                resp = s.recv(4096)
                if b"200" in resp[:32]:
                    s.sendall(b"GET /mux HTTP/1.1\r\nHost: e2e-mux\r\n\r\n")
                    body = s.recv(65535)
                    s.close()
                    if b"BACKEND-OK" in body:
                        return True, body.decode(errors="replace")[:300]
                s.close()
                last = repr(resp[:200])
            except Exception as e:  # noqa: BLE001
                last = f"{type(e).__name__}: {e}"
            time.sleep(0.3)
        return False, last

    multiplex_port = free_port()
    run_case(
        "tcpmux/enc+comp",
        work,
        f"tcpmux_http_connect_port = {multiplex_port}\n",
        f'[[proxies]]\nname = "mux"\ntype = "tcpmux"\n'
        f'local_ip = "127.0.0.1"\nlocal_port = {http_port}\n'
        f'custom_domains = ["e2e-mux"]\nmultiplexer = "httpconnect"\n'
        + transport(True, True),
        check_tcpmux,
    )

    # ---- https2http（TLS 后端）加密压缩 ----------------------------------
    try:
        https_port_backend, https_srv = start_https_backend(work)
    except Exception as e:  # noqa: BLE001
        print(f"  ⚠️ 跳过 https（openssl 不可用：{e}）")
        https_srv = None
        https_port_backend = 0

    if https_srv is not None:
        vsport = free_port()
        run_case(
            "https/enc+comp",
            work,
            f"vhost_https_port = {vsport}\n",
            f'[[proxies]]\nname = "tlsweb"\ntype = "https"\n'
            f'local_ip = "127.0.0.1"\nlocal_port = {https_port_backend}\n'
            f'custom_domains = ["tls.e2e"]\n' + transport(True, True),
            lambda d: _check_https(vsport, "tls.e2e"),
        )

    # ---- 汇总 ------------------------------------------------------------
    print("\n" + "=" * 62)
    passed = sum(1 for _, ok, _ in results if ok)
    for name, ok, _ in results:
        print(f"{'PASS' if ok else 'FAIL'}  {name}")
    print(f"{passed}/{len(results)} 通过")
    if args.keep or passed != len(results):
        print(f"日志与配置保留在：{work}")

    if https_srv is not None:
        https_srv.shutdown()
    http_srv.shutdown()
    udp_sock.close()
    tcp_srv.close()
    if not args.keep and passed == len(results):
        import shutil

        shutil.rmtree(work, ignore_errors=True)
    return 0 if passed == len(results) else 1


def _echo_conn(c: socket.socket):
    try:
        data = c.recv(65535)
        c.sendall(b"TCP-ECHO:" + data)
        time.sleep(0.2)
    except OSError:
        pass
    finally:
        c.close()


def _check_https(port: int, host: str) -> tuple[bool, str]:
    """https 代理是 TLS 透传：客户端必须用 TLS 连接 vhost_https_port。

    SNI 走 `host`，证书是自签的，所以这里显式跳过校验 —— 校验的是「数据有没有
    完好穿过去」，不是 PKI。
    """
    import ssl as _ssl

    ctx = _ssl.SSLContext(_ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = _ssl.CERT_NONE

    deadline = time.time() + 15
    last = ""
    while time.time() < deadline:
        try:
            # ★ SNI 必须是代理域名（frps 按 SNI 选代理），而连接目标是回环地址。
            #   用 HTTPSConnection 时 SNI 会等于连接目标，等于永远匹配不到代理。
            raw = socket.create_connection(("127.0.0.1", port), timeout=3)
            tls = ctx.wrap_socket(raw, server_hostname=host)
            tls.sendall(
                f"GET /tls HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n".encode()
            )
            chunks = []
            while True:
                b = tls.recv(65535)
                if not b:
                    break
                chunks.append(b)
            tls.close()
            resp = b"".join(chunks).decode("utf-8", "replace")
            if "200" in resp.split("\r\n", 1)[0] and "BACKEND-OK" in resp:
                return True, resp[:300]
            last = resp[:300]
        except Exception as e:  # noqa: BLE001
            last = f"{type(e).__name__}: {e}"
        time.sleep(0.3)
    return False, last


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception:  # noqa: BLE001
        traceback.print_exc()
        sys.exit(3)
