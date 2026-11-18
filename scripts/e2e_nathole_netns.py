#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""B5：NatHole 真实 NAT 拓扑验证（Linux network namespace）。

为什么用 netns：
    memory 里一直写着「NatHole 只覆盖 EasyNAT mode 0，HardNAT / 端口预测 /
    TTL 没验证」。判据（easyCount / hardCount / portsChangedRegularCount）
    只有在**真实的 NAT 设备**后面才有意义 —— 单测里喂几个数字，证明不了
    分类逻辑对应的是真实网络行为。

拓扑：
        ns-inet  10.0.0.1/24   ← frps :7000 + 自建 STUN :3478
          │  veth
        ns-a  10.0.1.2/24  SNAT MASQUERADE --random  （端口不规律的对称 NAT）
        ns-b  10.0.2.2/24  SNAT MASQUERADE --random

验证：
    ns-a 里的 frpc 当 xtcp provider，ns-b 里的 frpc 当 visitor。
    visitor 监听 10.0.2.2:<V>；从 ns-inet 连它并回显 provider 侧后端。
    然后读双方日志里的 mode 选择与 fallback 结果 ——
    **打洞失败也算结果**（说明走了设计内的中继降级），不能算"通过"。

判定口径（重要，别读成比实际更强的结论）：
    * 数据面能通  —— 连通性成立（打洞直连或中继降级都算数据面可用）；
    * 直连成功    —— 只有日志里出现 P2P 直连转发才判 `DIRECT`；
    * 中继降级    —— 日志出现「按策略走中继」时判 `RELAY`，这是设计内的
                     降级路径，**不代表打洞能力已验证**。
    退出码：0 = 数据面通（含 RELAY）；1 = 数据面不通；2 = 环境/二进制缺失。

用法（需 root，且宿主机有 iproute2 + iptables + 可用的 python3）：
    sudo python3 scripts/e2e_nathole_netns.py --bin-dir /opt/nfrp
"""

import argparse
import os
import re
import socket
import struct
import subprocess
import sys
import time
import traceback

NS_INET, NS_A, NS_B = "nf-inet", "nf-a", "nf-b"
BIN = "/opt/nfrp"


def sh(cmd, check=False):
    p = subprocess.run(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    out = p.stdout.decode(errors="replace").strip()
    if check and p.returncode != 0:
        raise RuntimeError("命令失败: %s\n%s" % (cmd, out))
    return out


def cleanup():
    for ns in (NS_A, NS_B, NS_INET):
        sh("ip netns del %s 2>/dev/null" % ns)
    sh("pkill -f 'nfrp-server -c /tmp/nf-' 2>/dev/null")
    sh("pkill -f 'nfrp-client -c /tmp/nf-' 2>/dev/null")
    sh("pkill -f 'nfrp-server -c /tmp/nf' 2>/dev/null")
    sh("pkill -f 'nfrp-client -c /tmp/nf' 2>/dev/null")
    sh("pkill -f 'nfrp-client -c /tmp/nf' 2>/dev/null")


class StunServer:
    """最小 STUN（RFC 5389）：只回 Binding Success + XOR-MAPPED-ADDRESS。"""

    def __init__(self, host, port=3478):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind((host, port))
        self.running = True
        import threading

        threading.Thread(target=self._loop, daemon=True).start()

    def _loop(self):
        while self.running:
            try:
                data, addr = self.sock.recvfrom(2048)
            except OSError:
                return
            if len(data) < 20:
                continue
            mtype, mlen, cookie = struct.unpack(">HHI", data[:8])
            if mtype != 0x0001:
                continue
            tid = data[8:20]
            # XOR-MAPPED-ADDRESS
            port = addr[1] ^ 0x2112
            ip = struct.unpack(">I", socket.inet_aton(addr[0]))[0] ^ 0x2112A442
            attr = struct.pack(">HHBBHI", 0x0020, 8, 0, 0x01, port, ip)
            body = struct.pack(">I", 0x2112A442) + tid + attr
            resp = struct.pack(">HH", 0x0101, len(body)) + body
            try:
                self.sock.sendto(resp, addr)
            except OSError:
                pass

    def close(self):
        self.running = False
        self.sock.close()


def setup_topology():
    cleanup()
    sh("ip netns add %s" % NS_INET, True)
    sh("ip netns add %s" % NS_A, True)
    sh("ip netns add %s" % NS_B, True)

    def wire(ns, a_if, ia_if, subnet_a, subnet_ia):
        # ★ 注意：netns 名是 `nf-a`，不是 `ns-a`。早期版本这里写死 `ns-%s`，
        #   直接报 "Cannot open network namespace ns-a"，拓扑根本没建起来。
        sh("ip link add veth-%s type veth peer name veth-%s" % (a_if, ia_if), True)
        sh("ip link set veth-%s netns %s" % (a_if, ns), True)
        sh("ip link set veth-%s netns %s" % (ia_if, NS_INET), True)
        sh("ip netns exec %s ip addr add %s dev veth-%s" % (ns, subnet_a, a_if), True)
        sh("ip netns exec %s ip link set veth-%s up" % (ns, a_if), True)
        sh("ip netns exec %s ip addr add %s dev veth-%s" % (NS_INET, subnet_ia, ia_if), True)
        sh("ip netns exec %s ip link set veth-%s up" % (NS_INET, ia_if), True)

    wire(NS_A, "a", "ia", "10.0.1.2/24", "10.0.1.1/24")
    wire(NS_B, "b", "ib", "10.0.2.2/24", "10.0.2.1/24")

    sh("ip netns exec %s ip link set lo up" % NS_INET, True)
    # 「公网地址」10.0.0.1 挂在 ns-inet 的 lo 上。只给 veth 配 10.0.1.1/10.0.2.1
    # 是不够的 —— frps 绑 10.0.0.1 会直接 EADDRNOTAVAIL（踩过）。
    sh("ip netns exec %s ip addr add 10.0.0.1/32 dev lo" % NS_INET, True)
    for ns in (NS_A, NS_B):
        sh("ip netns exec %s ip link set lo up" % ns, True)
        sh("ip netns exec %s ip route add default via 10.0.%s.1"
           % (ns, "1" if ns == NS_A else "2"), True)
        # 对称 NAT：源端口随机化，且每次新连接都换端口 → "端口不规律"
        sh("ip netns exec %s iptables -t nat -A POSTROUTING -o veth-%s -j MASQUERADE --random-fully"
           % (ns, "a" if ns == NS_A else "b"), True)
        sh("ip netns exec %s iptables -A FORWARD -i veth-%s -j ACCEPT"
           % (ns, "a" if ns == NS_A else "b"), True)
    sh("ip netns exec %s sysctl -qw net.ipv4.ip_forward=1" % NS_INET, True)
    sh("ip netns exec %s iptables -A FORWARD -j ACCEPT" % NS_INET, True)


def wait_ready(host, port, timeout=15):
    """在拓扑内部探测 frps —— 从宿主连 10.0.0.1 是不通的（它只在 ns-inet 里）。"""
    end = time.time() + timeout
    code = (
        "import socket,sys\n"
        "try:\n"
        "    socket.create_connection(('%s',%d),timeout=0.5).close();print('ok')\n"
        "except OSError:\n"
        "    sys.exit(1)\n" % (host, port)
    )
    while time.time() < end:
        out = sh("ip netns exec %s python3 -c %s" % (
            NS_INET, '"' + code.replace('"', '\\"') + '"'))
        if out.strip().endswith("ok"):
            return True
        time.sleep(0.3)
    return False


def ns_connect_test(ns, host, port, payload):
    """在某个 netns 里发数据并读回显。"""
    code = (
        "import socket\n"
        "try:\n"
        "    c=socket.create_connection(('%s',%d),timeout=3);c.settimeout(6)\n"
        "    c.sendall(%r);d=c.recv(4096);c.close()\n"
        "    print(d.decode('utf-8','replace'))\n"
        "except Exception as e:\n"
        "    print('ERR:'+str(e))\n" % (host, port, payload)
    )
    return sh("ip netns exec %s python3 -c %s" % (ns, '"' + code.replace('"', '\\"') + '"'))


STUN_SRC = '''
import socket, struct
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("0.0.0.0", 3478))
while True:
    data, addr = s.recvfrom(2048)
    if len(data) < 20:
        continue
    mtype, mlen, cookie = struct.unpack(">HHI", data[:8])
    if mtype != 0x0001:
        continue
    tid = data[8:20]
    port = addr[1] ^ 0x2112
    ip = struct.unpack(">I", socket.inet_aton(addr[0]))[0] ^ 0x2112A442
    attr = struct.pack(">HHBBHI", 0x0020, 8, 0, 0x01, port, ip)
    body = struct.pack(">I", 0x2112A442) + tid + attr
    s.sendto(struct.pack(">HH", 0x0101, len(body)) + body, addr)
'''


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--bin-dir", default=BIN)
    ap.add_argument("--keep", action="store_true")
    args = ap.parse_args()
    srv = os.path.join(args.bin_dir, "nfrp-server")
    cli = os.path.join(args.bin_dir, "nfrp-client")
    if not os.path.isfile(srv) or not os.path.isfile(cli):
        print("找不到二进制: %s" % args.bin_dir)
        return 2

    setup_topology()
    # ★ STUN 必须跑在 ns-inet 里：10.0.0.1 只存在于那个 netns。
    #   放在宿主进程里 bind 会直接 EADDRNOTAVAIL（踩过）。
    open("/tmp/nf-stun.py", "w").write(STUN_SRC)
    stun = subprocess.Popen(
        ["ip", "netns", "exec", NS_INET, sys.executable, "/tmp/nf-stun.py"],
        stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT,
    )
    print("拓扑就绪：frps 10.0.0.1:7000，STUN 10.0.0.1:3478")

    open("/tmp/nf-frps.toml", "w").write(
        'bind_addr = "10.0.0.1"\nbind_port = 7000\ntoken = "nf-token"\n'
        'log_level = "debug"\n'
    )
    prov = "/tmp/nf-prov.toml"
    open(prov, "w").write(
        'server_addr = "10.0.0.1"\nserver_port = 7000\ntoken = "nf-token"\n'
        'login_fail_exit = false\nlog_level = "debug"\n'
        'nat_hole_stun_server = "10.0.0.1:3478"\n'
        '[[proxies]]\nname = "xtcp-p2p"\ntype = "xtcp"\n'
        'local_ip = "127.0.0.1"\nlocal_port = 18099\nsecret_key = "sk-p2p"\n'
    )
    vis = "/tmp/nf-vis.toml"
    open(vis, "w").write(
        'server_addr = "10.0.0.1"\nserver_port = 7000\ntoken = "nf-token"\n'
        'login_fail_exit = false\nlog_level = "debug"\n'
        'nat_hole_stun_server = "10.0.0.1:3478"\n'
        '[[visitors]]\nname = "xtcp-vis"\ntype = "xtcp"\n'
        'server_name = "xtcp-p2p"\nsecret_key = "sk-p2p"\n'
        'bind_addr = "0.0.0.0"\nbind_port = 18098\n'
    )

    # provider 侧后端必须跑在 **ns-a 里**：127.0.0.1 是 per-netns 的，
    # 起在宿主会让 provider 一直 `Connection refused`（踩过）。
    echo = subprocess.Popen(
        ["ip", "netns", "exec", NS_A, sys.executable, "-c",
         "import socket,threading\n"
         "s=socket.socket();s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)\n"
         "s.bind(('127.0.0.1',18099));s.listen(8)\n"
         "def h(c):\n"
         "    d=c.recv(4096);c.sendall(b'XTCP-ECHO:'+d);c.close()\n"
         "while True:\n"
         "    c,_=s.accept();threading.Thread(target=h,args=(c,),daemon=True).start()\n"],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    time.sleep(1)

    # STUN 自检：确认客户端所在 netns 真的能拿到映射地址。
    stun_probe = (
        "import socket,struct\n"
        "s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);s.settimeout(3)\n"
        "s.sendto(struct.pack('>HHI',0x0001,0,0x2112A442)+b'0123456789ab',('10.0.0.1',3478))\n"
        "d,_=s.recvfrom(2048)\n"
        "print('STUN-RESP-LEN', len(d), 'from', _)\n"
    )
    print("STUN 自检:", sh("ip netns exec %s python3 -c %s"
                         % (NS_A, '"' + stun_probe.replace('"', '\\"') + '"')).strip())

    procs = [stun]
    try:
        procs.append(subprocess.Popen(
            ["ip", "netns", "exec", NS_INET, srv, "-c", "/tmp/nf-frps.toml"],
            stdout=open("/tmp/nf-frps.log", "wb"), stderr=subprocess.STDOUT))
        if not wait_ready("10.0.0.1", 7000):
            print("❌ frps 未监听")
            print("--- nf-frps.log ---")
            try:
                print(open("/tmp/nf-frps.log", encoding="utf-8", errors="replace").read()[-2000:])
            except Exception as ex:
                print("读日志失败:", ex)
            print("--- ip addr(ns-inet) ---")
            print(sh("ip netns exec %s ip addr" % NS_INET))
            return 1

        procs.append(subprocess.Popen(
            ["ip", "netns", "exec", NS_A, cli, "-c", prov],
            stdout=open("/tmp/nf-prov.log", "wb"), stderr=subprocess.STDOUT))
        time.sleep(2)
        procs.append(subprocess.Popen(
            ["ip", "netns", "exec", NS_B, cli, "-c", vis],
            stdout=open("/tmp/nf-vis.log", "wb"), stderr=subprocess.STDOUT))

        ok, detail = False, ""
        end = time.time() + 45
        while time.time() < end:
            out = ns_connect_test(NS_A, "10.0.2.2", 18098, b"p2p-hello")
            if out.startswith("XTCP-ECHO:p2p-hello"):
                ok, detail = True, out.strip()
                break
            detail = out.strip()
            time.sleep(2)

        plog = open("/tmp/nf-prov.log", encoding="utf-8", errors="replace").read()
        vlog = open("/tmp/nf-vis.log", encoding="utf-8", errors="replace").read()
        both = plog + vlog
        modes = sorted(set(re.findall(r"mode[=: ]+([0-9]+)", both)))

        # 路径判定：直连成功才写 P2P 转发结束；否则看中继降级的日志。
        direct = bool(re.search(r"P2P (?:转发结束|直连)", both)) and not re.search(
            r"P2P 打洞失败", both)
        relay = bool(re.search(r"按策略走中继", both))
        path = "DIRECT" if direct else ("RELAY" if relay else "UNKNOWN")
        reasons = sorted(set(re.findall(r'reason="?([a-z\-]+)"?', both)))

        print(("✅" if ok else "❌") + " xtcp 数据面（路径判定: %s）" % path)
        if path == "RELAY":
            print("   ⚠️ 中继降级已验证，**打洞能力未验证**（%s）"
                  % (", ".join(reasons) or "日志未给出原因"))
        print("   观察到的 mode: %s" % (", ".join(modes) or "未记录"))
        if ok:
            print("   回显: %s" % detail)
        else:
            print("   最后结果: %s" % (detail or "<空：netns 内连接未产生输出>"))
            for name in ("prov", "vis", "frps"):
                print("   --- nf-%s.log（末 25 行） ---" % name)
                try:
                    tail = open("/tmp/nf-%s.log" % name, encoding="utf-8",
                                errors="replace").read().splitlines()[-25:]
                    for line in tail:
                        print("     " + line)
                except Exception as ex:
                    print("     <读取失败: %s>" % ex)
        print("   日志: /tmp/nf-{prov,vis,frps}.log" + ("（已保留）" if args.keep else ""))
        return 0 if ok else 1
    finally:
        for p in procs:
            p.terminate()
        echo.terminate()
        if not args.keep:
            cleanup()


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception:
        traceback.print_exc()
        cleanup()
        sys.exit(3)
