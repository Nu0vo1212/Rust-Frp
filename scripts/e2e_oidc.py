#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""B4：真实 OIDC 流程 e2e（真 frps + 真 frpc + 一个真的 HTTP IdP）。

"真实"指什么：
    不是把 OidcVerifier 单测里的解析函数再调一遍，而是让 frps **真的走 HTTP**
    去拉 `.well-known/openid-configuration` 与 `jwks.json`，让 frpc **真的发
    client_credentials 请求**拿 RS256 签名的 JWT，再由 frps 验签、验 aud/iss/exp。
    任何一环（discovery 路径、JWK 编码、签名算法、audience 比对）错了都通不过。

IdP 是自建的最小实现（约 120 行），刻意不引第三方 mock 库 —— 那样等于把
"被测代码"和"mock 的行为"绑在一起，什么都证明不了。

Python 3.6 兼容（云服务器是 3.6.8）。

用法：
    python3 b4_oidc_e2e.py --bin-dir /opt/cargo-target-076/release
"""

import argparse
import base64
import json
import os
import socket
import subprocess
import sys
import tempfile
import threading
import time
import traceback
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa


def b64u(data):
    return base64.urlsafe_b64encode(data).decode().rstrip("=")


def int_to_bytes(n):
    length = (n.bit_length() + 7) // 8
    return n.to_bytes(length, "big")


class IdP(object):
    def __init__(self):
        self.key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        nums = self.key.public_key().public_numbers()
        self.jwk = {
            "kty": "RSA",
            "kid": "e2e-key-1",
            "use": "sig",
            "alg": "RS256",
            "n": b64u(int_to_bytes(nums.n)),
            "e": b64u(int_to_bytes(nums.e)),
        }
        self.issuer = ""
        self.client_id = "nfrp-e2e-client"
        self.client_secret = "nfrp-e2e-secret"
        self.audience = "nfrp-e2e-audience"
        self.token_requests = 0

    def issue(self, sub="alice@example.com"):
        header = {"alg": "RS256", "typ": "JWT", "kid": self.jwk["kid"]}
        claims = {
            "iss": self.issuer,
            "aud": self.audience,
            "sub": sub,
            "exp": int(time.time()) + 3600,
            "iat": int(time.time()),
        }
        signing_input = (
            b64u(json.dumps(header).encode()) + "." + b64u(json.dumps(claims).encode())
        )
        sig = self.key.sign(
            signing_input.encode(), padding.PKCS1v15(), hashes.SHA256()
        )
        return signing_input + "." + b64u(sig)


IDP = IdP()


class Handler(BaseHTTPRequestHandler):
    def _json(self, obj, code=200):
        body = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        path = self.path.split("?")[0]
        if path == "/.well-known/openid-configuration":
            self._json({
                "issuer": IDP.issuer,
                "jwks_uri": IDP.issuer + "/.well-known/jwks.json",
                "token_endpoint": IDP.issuer + "/token",
                "id_token_signing_alg_values_supported": ["RS256"],
            })
        elif path == "/.well-known/jwks.json":
            self._json({"keys": [IDP.jwk]})
        else:
            self._json({"error": "not found"}, 404)

    def do_POST(self):
        if self.path.split("?")[0] != "/token":
            self._json({"error": "not found"}, 404)
            return
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length).decode() if length else ""
        form = parse_qs(body)
        cid = (form.get("client_id") or [""])[0]
        csec = (form.get("client_secret") or [""])[0]
        auth = self.headers.get("Authorization", "")
        if auth.lower().startswith("basic "):
            try:
                raw = base64.b64decode(auth.split(None, 1)[1]).decode()
                cid, _, csec = raw.partition(":")
            except Exception:
                pass
        if cid != IDP.client_id or csec != IDP.client_secret:
            self._json({"error": "invalid_client"}, 401)
            return
        IDP.token_requests += 1
        token = IDP.issue()
        self._json({
            "access_token": token,
            "id_token": token,
            "token_type": "Bearer",
            "expires_in": 3600,
        })

    def log_message(self, *args):
        pass


def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


class Proc(object):
    def __init__(self, args, log):
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

    def text(self):
        try:
            return open(self.log, encoding="utf-8", errors="replace").read()
        except Exception:
            return ""


def resolve_bin_dir(explicit):
    """找一对 nfrp-server / nfrp-client（或发布包里的 frps / frpc）。"""
    here = os.path.dirname(os.path.abspath(__file__))
    root = os.path.dirname(here)
    ext = ".exe" if os.name == "nt" else ""
    cands = []
    if explicit:
        cands.append(explicit)
    parent = os.path.dirname(root)
    if os.path.isdir(parent):
        cands += sorted(
            [os.path.join(parent, d) for d in os.listdir(parent)
             if d.startswith("autostart-")],
            reverse=True,
        )
    cands += [os.path.join(root, "target", "release"),
              os.path.join(root, "target", "debug")]
    for d in cands:
        for srv, cli in (("nfrp-server", "nfrp-client"), ("frps", "frpc")):
            if os.path.isfile(os.path.join(d, srv + ext)) and os.path.isfile(
                os.path.join(d, cli + ext)
            ):
                return d, srv + ext, cli + ext
    return None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--bin-dir", default=None)
    args = ap.parse_args()
    found = resolve_bin_dir(args.bin_dir)
    if not found:
        print("找不到 nfrp-server / nfrp-client；用 --bin-dir 指定目录")
        return 2
    d, srv_name, cli_name = found
    frps = os.path.join(d, srv_name)
    frpc = os.path.join(d, cli_name)
    print("二进制: " + frps + " / " + frpc)

    work = tempfile.mkdtemp(prefix="nfrp-oidc-")
    idp_port = free_port()
    IDP.issuer = "http://127.0.0.1:" + str(idp_port)
    httpd = HTTPServer(("127.0.0.1", idp_port), Handler)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()

    bind = free_port()
    echo_port = free_port()
    remote_port = free_port()

    # echo 后端
    srv = socket.socket()
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", echo_port))
    srv.listen(8)

    def echo_loop():
        while True:
            try:
                c, _ = srv.accept()
            except OSError:
                return
            threading.Thread(target=echo_one, args=(c,), daemon=True).start()

    def echo_one(c):
        try:
            while True:
                data = c.recv(4096)
                if not data:
                    break
                c.sendall(b"OIDC-ECHO:" + data)
        except OSError:
            pass
        finally:
            c.close()

    threading.Thread(target=echo_loop, daemon=True).start()

    frps_toml = os.path.join(work, "frps.toml")
    with open(frps_toml, "w") as f:
        f.write(
            'bind_addr = "127.0.0.1"\nbind_port = {0}\nlog_level = "debug"\n'
            '[auth]\nmethod = "oidc"\n[auth.oidc]\nissuer = "{1}"\n'
            'audience = "{2}"\nallowInsecureIssuer = true\n'
            'insecureSkipVerify = true\n'.format(bind, IDP.issuer, IDP.audience)
        )

    frpc_toml = os.path.join(work, "frpc.toml")
    with open(frpc_toml, "w") as f:
        f.write(
            'server_addr = "127.0.0.1"\nserver_port = {0}\nlogin_fail_exit = true\n'
            '[auth]\nmethod = "oidc"\n[auth.oidc]\nclientID = "{1}"\n'
            'clientSecret = "{2}"\naudience = "{3}"\n'
            'tokenEndpointURL = "{4}/token"\ninsecureSkipVerify = true\n'
            '[[proxies]]\nname = "oidc-tcp"\ntype = "tcp"\n'
            'local_ip = "127.0.0.1"\nlocal_port = {5}\nremote_port = {6}\n'.format(
                bind, IDP.client_id, IDP.client_secret, IDP.audience,
                IDP.issuer, echo_port, remote_port,
            )
        )

    sp = Proc([frps, "-c", frps_toml], os.path.join(work, "frps.log"))
    cp = None
    try:
        end = time.time() + 20
        while time.time() < end:
            try:
                socket.create_connection(("127.0.0.1", bind), timeout=0.5).close()
                break
            except OSError:
                time.sleep(0.2)
        cp = Proc([frpc, "-c", frpc_toml], os.path.join(work, "frpc.log"))

        ok, detail = False, ""
        end = time.time() + 25
        while time.time() < end:
            try:
                c = socket.create_connection(("127.0.0.1", remote_port), timeout=2)
                c.settimeout(3)
                c.sendall(b"hello-oidc")
                data = c.recv(4096)
                c.close()
                if data.startswith(b"OIDC-ECHO:hello-oidc"):
                    ok, detail = True, data.decode(errors="replace")
                    break
                detail = repr(data)
            except Exception as e:
                detail = type(e).__name__ + ": " + str(e)
            time.sleep(0.5)

        print(("✅" if ok else "❌") + " OIDC 登录 + 隧道数据面")
        print("   IdP token 请求次数: " + str(IDP.token_requests))
        if ok:
            print("   回显: " + detail)
        else:
            print("   最后结果: " + detail)
            print("   --- frpc.log ---")
            print(cp.text()[-2000:])
            print("   --- frps.log ---")
            print(sp.text()[-3000:])
        print("   工作目录: " + work)
        return 0 if ok else 1
    finally:
        if cp is not None:
            cp.stop()
        sp.stop()
        httpd.shutdown()


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception:
        traceback.print_exc()
        sys.exit(3)
