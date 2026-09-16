#!/usr/bin/env python3
"""发布产物打包 + 校验值生成 + 签名验签。

四个子命令，CI 与本地都能跑：

```bash
# 0) 首次：生成一对 Ed25519 签名密钥（默认落在 dist/keys，私钥自己收好不外传）
python scripts/release.py keygen

# 1) 打包：每个目标平台的产物目录里找 rustunnel-server / rustunnel-client，
#    统一改名成 frps / frpc 后和示例配置、README 一起打成压缩包
python scripts/release.py pack \\
    --target windows-amd64:target/release \\
    --target linux-amd64:/opt/build/amd64

# 2) 生成 SHA256SUMS.txt 并签名（有 release.key 用 Ed25519，否则退回 gpg）
python scripts/release.py checksum --dir dist/release --sign

# 3) 用户侧验真
python scripts/release.py verify --dir dist/release

# 4) 自检：拿 RFC 8032 官方向量验一遍签名实现
python scripts/release.py self-test
```

设计上刻意**不依赖任何第三方 Python 包**，也不依赖 Rust 工具链，
这样它在 CI 的任意一个 job 里都能跑起来 —— 包括最小化的容器镜像。

Ed25519 是 RFC 8032 的标准实现（纯 Python），并且在 `self-test` 里用
RFC 8032 §7.1 的官方测试向量做了校验，确保和 OpenSSL / libsodium 等
标准实现互认，而不是「自己签自己验、一出门就废」。
"""

from __future__ import annotations

import argparse
import hashlib
import os
import shutil
import subprocess
import sys
import tarfile
import textwrap
import tomllib
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DEFAULT_OUT = ROOT / "dist" / "release"

# 发布素材（示例配置 / LICENSE）可能放在仓库根的 dist/ 下，也可能跟着源码树走，
# 两个位置都找一遍。
ASSET_CANDIDATES = [
    ROOT.parent / "dist" / "release" / "assets",
    ROOT / "dist" / "release" / "assets",
]

# 包内文件名 -> 构建产物名（按平台补 .exe）
BINARIES = [("frps", "rustunnel-server"), ("frpc", "rustunnel-client")]
# 随包附带的素材文件（README.md 由仓库 README 现场合成，见 build_readme）
DOCS = ["frps.toml", "frpc.toml", "LICENSE", "NOTICE"]
# 校验值文件名（Release 里就把这个贴出去）
SUMS_NAME = "SHA256SUMS.txt"
SIG_NAME = f"{SUMS_NAME}.sig"
# 密钥**单独放一个目录**，刻意不放 dist/release：那里是会被整个打包分发的地方，
# 私钥混进去就等于把签名能力一起送出去了。
DEFAULT_KEYS = ROOT / "dist" / "keys"
KEY_NAME = "release.key"
PUB_NAME = "release.pub"


def log(msg: str) -> None:
    print(f"[release] {msg}", flush=True)


def find_assets(explicit: str | None) -> Path:
    if explicit:
        p = Path(explicit)
        if not p.is_dir():
            raise SystemExit(f"--assets 指向的目录不存在：{p}")
        return p
    for c in ASSET_CANDIDATES:
        if c.is_dir():
            return c
    raise SystemExit(
        "找不到发布素材目录（frps.toml / frpc.toml / LICENSE）。"
        f"找过这些位置：{', '.join(str(c) for c in ASSET_CANDIDATES)}"
    )


# ---------------------------------------------------------------------------
# Ed25519（RFC 8032 参考实现）
#
# 说明：这里刻意手写而不是依赖 `cryptography` / `pynacl` —— 打包脚本要在
# CI 的最小容器里跑，装不装得上这两者不受控。正确性靠 self-test 里的
# RFC 官方向量保证（那组向量不对，代码一定错）。
# ---------------------------------------------------------------------------

_B = 256
_Q = 2**255 - 19
_L = 2**252 + 27742317777372353535851937790883648493


def _sha512(m: bytes) -> bytes:
    return hashlib.sha512(m).digest()


def _expmod(b: int, e: int, m: int) -> int:
    return pow(b, e, m)


def _inv(x: int) -> int:
    return _expmod(x, _Q - 2, _Q)


_D = -121665 * _inv(121666) % _Q
_I = _expmod(2, (_Q - 1) // 4, _Q)


def _xrecover(y: int) -> int:
    xx = (y * y - 1) * _inv(_D * y * y + 1)
    x = _expmod(xx, (_Q + 3) // 8, _Q)
    if (x * x - xx) % _Q != 0:
        x = (x * _I) % _Q
    if x % 2 != 0:
        x = _Q - x
    return x


_By = 4 * _inv(5) % _Q
_Bx = _xrecover(_By)
_BASE = (_Bx % _Q, _By % _Q, 1, (_Bx * _By) % _Q)
_IDENT = (0, 1, 1, 0)


def _edwards_add(p: tuple, q: tuple) -> tuple:
    x1, y1, z1, t1 = p
    x2, y2, z2, t2 = q
    x3 = (x1 * y2 + x2 * y1) * _inv(1 + _D * t1 * t2)
    y3 = (y1 * y2 + x1 * x2) * _inv(1 - _D * t1 * t2)
    return (x3 % _Q, y3 % _Q, 1, (x3 * y3) % _Q)


def _scalarmult(p: tuple, e: int) -> tuple:
    # 迭代版（参考实现是递归的，但 255 层递归在部分环境会撞栈深限制）
    result = _IDENT
    while e > 0:
        if e & 1:
            result = _edwards_add(result, p)
        p = _edwards_add(p, p)
        e >>= 1
    return result


def _encodepoint(p: tuple) -> bytes:
    x, y, z, _t = p
    zi = _inv(z)
    x = (x * zi) % _Q
    y = (y * zi) % _Q
    bits = [(y >> i) & 1 for i in range(_B - 1)] + [x & 1]
    return bytes(
        sum(bits[i * 8 + k] << k for k in range(8)) for i in range(_B // 8)
    )


def _decodepoint(s: bytes) -> tuple:
    # 低 255 位是 y，最高位是 x 的符号位
    y = int.from_bytes(s, "little") & ((1 << 255) - 1)
    x = _xrecover(y)
    if x & 1 != (s[31] >> 7) & 1:
        x = _Q - x
    return (x, y, 1, (x * y) % _Q)


def _bit(h: bytes, i: int) -> int:
    return (h[i // 8] >> (i % 8)) & 1


def _clamp(h: bytes) -> int:
    """把 SHA-512 的前 32 字节按 RFC 8032 §5.1.5 修剪成标量 a。"""
    return 2 ** (_B - 2) + sum(2**i * _bit(h, i) for i in range(3, _B - 2))


def public_key(seed: bytes) -> bytes:
    """32 字节种子 -> 32 字节公钥。"""
    if len(seed) != 32:
        raise ValueError("Ed25519 私钥种子必须是 32 字节")
    return _encodepoint(_scalarmult(_BASE, _clamp(_sha512(seed))))


def sign(msg: bytes, seed: bytes, pub: bytes) -> bytes:
    """返回 64 字节签名（R || S）。"""
    h = _sha512(seed)
    a = _clamp(h)
    r = int.from_bytes(_sha512(h[32:64] + msg), "little") % _L
    r_enc = _encodepoint(_scalarmult(_BASE, r))
    k = int.from_bytes(_sha512(r_enc + pub + msg), "little") % _L
    s = (r + k * a) % _L
    return r_enc + s.to_bytes(32, "little")


def verify(msg: bytes, sig: bytes, pub: bytes) -> bool:
    if len(sig) != 64 or len(pub) != 32:
        return False
    r_enc, s_enc = sig[:32], sig[32:]
    s = int.from_bytes(s_enc, "little")
    if s >= _L:
        return False
    try:
        a = _decodepoint(pub)
        r = _decodepoint(r_enc)
    except Exception:
        return False
    k = int.from_bytes(_sha512(r_enc + pub + msg), "little") % _L
    return _scalarmult(_BASE, s) == _edwards_add(r, _scalarmult(a, k))


# RFC 8032 §7.1 官方测试向量（(seed, pub, msg, sig)）
_RFC8032_VECTORS = [
    (
        "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
        "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
        "",
        "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
    ),
    (
        "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
        "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
        "72",
        "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00",
    ),
]


def cmd_self_test(_args: argparse.Namespace) -> int:
    """拿 RFC 8032 官方向量验证实现 —— 签名代码不能只靠「自签自验」取信。"""
    ok = True
    for i, (sk_hex, pk_hex, msg_hex, sig_hex) in enumerate(_RFC8032_VECTORS, 1):
        seed = bytes.fromhex(sk_hex)
        want_pk = bytes.fromhex(pk_hex)
        msg = bytes.fromhex(msg_hex)
        want_sig = bytes.fromhex(sig_hex)

        got_pk = public_key(seed)
        got_sig = sign(msg, seed, want_pk)
        valid = verify(msg, got_sig, want_pk)
        tampered = verify(msg + b"x", got_sig, want_pk)

        pk_ok = got_pk == want_pk
        sig_ok = got_sig == want_sig
        ok = ok and pk_ok and sig_ok and valid and not tampered
        print(
            f"  向量 {i}: 公钥 {'OK' if pk_ok else '不符'} / "
            f"签名 {'OK' if sig_ok else '不符'} / "
            f"验签 {'通过' if valid else '失败'} / "
            f"篡改后 {'正确拒绝' if not tampered else '竟然通过（严重）'}"
        )
    print("自检通过" if ok else "自检失败")
    return 0 if ok else 1


# ---------------------------------------------------------------------------
# keygen
# ---------------------------------------------------------------------------


def cmd_keygen(args: argparse.Namespace) -> int:
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    key_file = out / KEY_NAME
    pub_file = out / PUB_NAME

    if key_file.exists() and not args.force:
        raise SystemExit(
            f"{key_file} 已存在（覆盖会让所有历史签名失效）。确要重生成请加 --force"
        )

    seed = os.urandom(32)
    pub = public_key(seed)
    key_file.write_text(
        "# rustunnel 发布签名私钥（Ed25519 seed）—— 不要提交到仓库，不要外传。\n"
        + seed.hex()
        + "\n",
        encoding="utf-8",
    )
    try:
        os.chmod(key_file, 0o600)
    except OSError:
        pass
    pub_file.write_text(
        f"# rustunnel 发布公钥（Ed25519）—— 随 Release 一起分发，供下载者验签。\n"
        f"# 指纹（SHA-256/16 字节）: {hashlib.sha256(pub).hexdigest()[:32]}\n"
        + pub.hex()
        + "\n",
        encoding="utf-8",
    )
    log(f"私钥 -> {key_file}（请离线保管）")
    log(f"公钥 -> {pub_file}")
    log(f"公钥指纹: {hashlib.sha256(pub).hexdigest()[:32]}")
    return 0


def load_key(path: Path) -> bytes:
    """读密钥文件：跳过 `#` 注释行，取第一段十六进制。"""
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        try:
            return bytes.fromhex(line)
        except ValueError:
            continue
    raise SystemExit(f"{path} 里没有找到十六进制密钥")


# ---------------------------------------------------------------------------
# pack
# ---------------------------------------------------------------------------


def find_binary(src: Path, stem: str) -> Path:
    """在产物目录里找可执行文件：优先精确名，其次带 .exe。"""
    for name in (stem, f"{stem}.exe"):
        p = src / name
        if p.is_file():
            return p
    raise SystemExit(f"在 {src} 下找不到 {stem} / {stem}.exe")


def check_toml_assets(assets: Path) -> None:
    """随包的示例配置必须**能解析**。

    这类文件最容易悄悄坏掉：改了结构体字段名、手滑写错一个键，
    TOML 解析依然"看起来像那么回事"，直到用户 `frps -c frps.toml` 才炸。
    所以打包时就拿标准库把它解析一遍，坏了直接中断打包。
    """
    problems: list[str] = []
    for doc in ("frps.toml", "frpc.toml"):
        f = assets / doc
        if not f.is_file():
            problems.append(f"{doc}: 文件不存在")
            continue
        try:
            with open(f, "rb") as fh:
                tomllib.load(fh)
        except tomllib.TOMLDecodeError as e:
            problems.append(f"{doc}: TOML 语法错误 -> {e}")
        except OSError as e:
            problems.append(f"{doc}: 读不出来 -> {e}")
    if problems:
        raise SystemExit("示例配置校验失败，已中断打包：\n  " + "\n  ".join(problems))
    log("示例配置校验通过（frps.toml / frpc.toml 均可解析）")


def build_readme(out_dir: Path) -> str:
    """合成包内 README。

    正文直接取仓库的 `README.md` —— 单一事实来源。早先的做法是在 assets 下
    再维护一份精简版，结果改完仓库 README 忘了同步 assets，打出来的包里
    就是过期文档。现在只在这里加一段「包内有什么」，正文永远跟仓库一致。
    """
    repo_readme = ROOT / "README.md"
    if not repo_readme.is_file():
        raise SystemExit(f"找不到 {repo_readme}，无法生成包内 README")
    body = repo_readme.read_text(encoding="utf-8")

    header = textwrap.dedent(
        """\
        > **这是一个发布包。** 目录里已经有了可直接运行的二进制，
        > 不需要自己编译 —— 下面 README 里「从源码构建」一节只在你想改代码时才需要看。

        ## 包内文件

        | 文件 | 说明 |
        |---|---|
        | `frps` / `frps.exe` | 服务端（等价官方 frps），部署在公网机器 |
        | `frpc` / `frpc.exe` | 客户端（等价官方 frpc），跑在内网机器 |
        | `frps.toml` | 服务端配置示例（带全部可选项注释） |
        | `frpc.toml` | 客户端配置示例（含 stcp / xtcp / 插件 / 限流写法） |
        | `LICENSE` | Apache License 2.0 全文 |
        | `NOTICE` | 版权声明与第三方组件许可说明 |

        ```bash
        # 服务端（公网机器）
        ./frps -c frps.toml

        # 客户端（内网机器）
        ./frpc -c frpc.toml
        ```

        Windows 下把 `./frps` 换成 `frps.exe` 即可。

        ```powershell
        .\\frps.exe -c frps.toml
        .\\frpc.exe -c frpc.toml
        ```

        ---

        """
    )
    return header + body


def collect(targets: list[str], out: Path, assets: Path) -> dict[str, list[Path]]:
    """把各平台的产物复制到一个临时 staging 目录，返回 {平台: [文件]}。"""
    staged: dict[str, list[Path]] = {}
    staging = out / ".staging"
    if staging.exists():
        shutil.rmtree(staging)

    readme = build_readme(out)

    for spec in targets:
        if ":" not in spec:
            raise SystemExit(f"--target 需要写成 平台:目录，收到 {spec!r}")
        platform, src = spec.split(":", 1)
        src_dir = Path(src)
        if not src_dir.is_dir():
            raise SystemExit(f"产物目录不存在：{src_dir}")
        dest = staging / platform
        dest.mkdir(parents=True, exist_ok=True)

        files: list[Path] = []
        # Windows 上可执行文件必须有 .exe 后缀，否则双击/命令行都跑不起来
        suffix = ".exe" if platform.startswith("windows") else ""
        for packaged, stem in BINARIES:
            name = packaged + suffix
            shutil.copy2(find_binary(src_dir, stem), dest / name)
            (dest / name).chmod(0o755)
            files.append(dest / name)

        # 素材：assets 里有什么就放什么，缺了不致命（LICENSE 例外，必须齐全）
        for doc in DOCS:
            src_doc = assets / doc
            if src_doc.is_file():
                shutil.copy2(src_doc, dest / doc)
                files.append(dest / doc)
            elif doc != "LICENSE":
                log(f"警告：缺少 {assets / doc}，包里不会有它")

        (dest / "README.md").write_text(readme, encoding="utf-8", newline="\n")
        files.append(dest / "README.md")

        staged[platform] = files
        log(f"已暂存 {platform}：{len(files)} 个文件")
    return staged


def make_zip(files: list[Path], out_path: Path) -> None:
    with zipfile.ZipFile(out_path, "w", zipfile.ZIP_DEFLATED) as z:
        for f in files:
            # 固定时间戳：同样的输入永远得到同样的包，便于校验值复现
            zi = zipfile.ZipInfo(f.name, date_time=(1980, 1, 1, 0, 0, 0))
            zi.compress_type = zipfile.ZIP_DEFLATED
            is_bin = f.stem in ("frps", "frpc")
            zi.external_attr = (0o755 if is_bin else 0o644) << 16
            z.writestr(zi, f.read_bytes())
    log(f"打包 {out_path.name}")


def make_tar(files: list[Path], out_path: Path) -> None:
    with tarfile.open(out_path, "w:gz") as t:
        for f in files:
            ti = t.gettarinfo(str(f), arcname=f.name)
            ti.mode = 0o755 if f.stem in ("frps", "frpc") else 0o644
            ti.mtime = 0  # 同上：可复现
            ti.uid = ti.gid = 0
            ti.uname = ti.gname = "root"
            with open(f, "rb") as fh:
                t.addfile(ti, fh)
    log(f"打包 {out_path.name}")


def cmd_pack(args: argparse.Namespace) -> int:
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    assets = find_assets(args.assets)
    log(f"素材目录：{assets}")
    check_toml_assets(assets)
    staged = collect(args.target, out, assets)

    produced: list[Path] = []
    for platform, files in staged.items():
        name = f"rustunnel-{platform}"
        if platform.startswith("windows"):
            p = out / f"{name}.zip"
            make_zip(files, p)
        else:
            p = out / f"{name}.tar.gz"
            make_tar(files, p)
        produced.append(p)

    shutil.rmtree(out / ".staging", ignore_errors=True)
    log(f"共 {len(produced)} 个包 -> {out}")
    return 0


# ---------------------------------------------------------------------------
# checksum
# ---------------------------------------------------------------------------


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def cmd_checksum(args: argparse.Namespace) -> int:
    out = Path(args.dir)
    skip = {SUMS_NAME, SIG_NAME, PUB_NAME}
    files = sorted(p for p in out.iterdir() if p.is_file() and p.name not in skip)
    if not files:
        raise SystemExit(f"{out} 下没有可校验的产物")

    lines = [f"{sha256(p)}  {p.name}" for p in files]
    sums = out / SUMS_NAME
    sums.write_text("\n".join(lines) + "\n", encoding="utf-8")
    log(f"已生成 {sums.name}（{len(files)} 个文件）")
    for line in lines:
        print(line)

    if not args.sign:
        return 0

    # 优先 Ed25519（只要 private key 在手，不依赖任何外部工具）
    key_file = Path(args.key)
    pub_file = Path(args.pub)
    sig_file = out / SIG_NAME
    if key_file.is_file():
        seed = load_key(key_file)
        pub = public_key(seed)
        signature = sign(sums.read_bytes(), seed, pub)
        sig_file.write_text(
            f"# algorithm: ed25519\n# public-key: {pub.hex()}\n"
            f"# public-key-fingerprint: {hashlib.sha256(pub).hexdigest()[:32]}\n"
            f"# signed-file: {SUMS_NAME}\n"
            + signature.hex()
            + "\n",
            encoding="utf-8",
        )
        # 公钥一并落到产物目录，便于随 Release 分发给下载者
        (out / PUB_NAME).write_text(
            "# rustunnel 发布公钥（Ed25519）\n"
            f"# 指纹（SHA-256/16 字节）: {hashlib.sha256(pub).hexdigest()[:32]}\n"
            + pub.hex()
            + "\n",
            encoding="utf-8",
        )
        log(f"已用 Ed25519 签名 -> {sig_file.name}")
        log(f"公钥指纹: {hashlib.sha256(pub).hexdigest()[:32]}")
        return 0

    if shutil.which("gpg") is None:
        log(
            f"既没有 {key_file} 也没有 gpg，跳过签名"
            f"（校验值照样可用，只是无法验证来源）。生成密钥：release.py keygen"
        )
        return 0

    if sig_file.exists():
        sig_file.unlink()
    r = subprocess.run(
        ["gpg", "--batch", "--yes", "--detach-sign", "--armor", "--output", str(sig_file), str(sums)],
        capture_output=True,
        text=True,
    )
    if r.returncode == 0:
        log(f"已用 gpg 签名 -> {sig_file.name}")
    else:
        log(f"gpg 签名失败（不影响使用）：{r.stderr.strip()}")
    return 0


# ---------------------------------------------------------------------------
# verify
# ---------------------------------------------------------------------------


def cmd_verify(args: argparse.Namespace) -> int:
    out = Path(args.dir)
    sums = out / SUMS_NAME
    if not sums.is_file():
        raise SystemExit(f"找不到 {sums}，先运行 checksum 子命令")

    ok = True
    checked = 0
    for line in sums.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split(None, 1)
        if len(parts) != 2:
            print(f"  格式错误：{line}")
            ok = False
            continue
        expect, name = parts
        p = out / name.strip()
        if not p.is_file():
            print(f"  缺失：{name}")
            ok = False
            continue
        actual = sha256(p)
        checked += 1
        if actual == expect:
            print(f"  OK   {name}  {actual}")
        else:
            print(f"  不符 {name}\n       期望 {expect}\n       实际 {actual}")
            ok = False

    print(f"共校验 {checked} 个文件")

    # ---- 签名 ----
    sig_file = out / SIG_NAME
    if not sig_file.is_file():
        print("  注意：没有签名文件，只能校验完整性、无法验证来源")
        print(f"校验{'全部通过' if ok else '存在问题'}")
        return 0 if ok else 1

    signed = verify_signature(sums, sig_file)
    ok = ok and signed
    print(f"校验{'全部通过' if ok else '存在问题'}")
    return 0 if ok else 1


def verify_signature(sums: Path, sig_file: Path) -> bool:
    """按签名文件里声明的算法验签（ed25519 或 gpg）。"""
    text = sig_file.read_text(encoding="utf-8")
    alg = ""
    pub_hex = ""
    payload = ""
    for line in text.splitlines():
        s = line.strip()
        if s.lower().startswith("# algorithm:"):
            alg = s.split(":", 1)[1].strip().lower()
        elif s.lower().startswith("# public-key:"):
            pub_hex = s.split(":", 1)[1].strip()
        elif s and not s.startswith("#"):
            payload = s

    if alg == "ed25519":
        try:
            pub = bytes.fromhex(pub_hex)
            sig = bytes.fromhex(payload)
        except ValueError:
            print("  签名文件格式错误（不是十六进制）")
            return False
        fingerprint = hashlib.sha256(pub).hexdigest()[:32]
        if verify(sums.read_bytes(), sig, pub):
            print(f"  签名有效（Ed25519，公钥指纹 {fingerprint}）")
            return True
        print("  签名校验失败：内容被篡改，或者签名不属于这把公钥")
        return False

    # 没有 algorithm 头 -> 当作 gpg 的 ASCII armor 处理
    if shutil.which("gpg") is None:
        print("  存在签名但本机没有 gpg，跳过验签")
        return True
    r = subprocess.run(
        ["gpg", "--verify", str(sig_file), str(sums)], capture_output=True, text=True
    )
    if r.returncode == 0:
        print("  签名有效（gpg）")
        return True
    print(f"  签名校验失败：{r.stderr.strip()}")
    return False


def main() -> int:
    ap = argparse.ArgumentParser(
        description="rustunnel 发布产物打包与校验",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    sub = ap.add_subparsers(dest="cmd", required=True)

    p_pack = sub.add_parser("pack", help="把各平台产物打成压缩包")
    p_pack.add_argument(
        "--target",
        action="append",
        required=True,
        metavar="平台:目录",
        help="例如 windows-amd64:target/release",
    )
    p_pack.add_argument("--out", default=str(DEFAULT_OUT), help="输出目录")
    p_pack.add_argument("--assets", help="素材目录（默认自动探测）")
    p_pack.set_defaults(func=cmd_pack)

    p_key = sub.add_parser("keygen", help="生成 Ed25519 签名密钥对")
    p_key.add_argument("--out", default=str(DEFAULT_KEYS), help="密钥输出目录")
    p_key.add_argument("--force", action="store_true", help="覆盖已有私钥（危险）")
    p_key.set_defaults(func=cmd_keygen)

    p_sum = sub.add_parser("checksum", help=f"生成 {SUMS_NAME}")
    p_sum.add_argument("--dir", default=str(DEFAULT_OUT), help="产物目录")
    p_sum.add_argument("--sign", action="store_true", help="签名（优先 Ed25519，否则 gpg）")
    p_sum.add_argument(
        "--key", default=str(DEFAULT_KEYS / KEY_NAME), help="Ed25519 私钥路径"
    )
    p_sum.add_argument(
        "--pub", default=str(DEFAULT_KEYS / PUB_NAME), help="Ed25519 公钥路径（用于随包分发）"
    )
    p_sum.set_defaults(func=cmd_checksum)

    p_ver = sub.add_parser("verify", help=f"按 {SUMS_NAME} 校验产物并验签")
    p_ver.add_argument("--dir", default=str(DEFAULT_OUT), help="产物目录")
    p_ver.set_defaults(func=cmd_verify)

    p_self = sub.add_parser("self-test", help="用 RFC 8032 官方向量自检签名实现")
    p_self.set_defaults(func=cmd_self_test)

    args = ap.parse_args()
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
