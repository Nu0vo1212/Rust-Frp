#!/usr/bin/env python3
"""打包 Android 交付物：`nfrp-android-v<ver>.zip`。

包内结构（二进制改名成官方风格 `frps` / `frpc`，与桌面版一致）：

```
nfrp-android-aarch64/frps    frps 的 aarch64 构建
nfrp-android-aarch64/frpc
nfrp-android-x86_64/frps
nfrp-android-x86_64/frpc
README-ANDROID.md
```

## 为什么要先编译再跑这个脚本

本脚本**只打包，不编译**。产物目录一律从 `cargo metadata` 的
`target_directory` 推导（尊重 `CARGO_TARGET_DIR` 与本机 `.cargo/config.toml`），
所以编译时必须用同一个目录，否则打进去的是上一次的旧二进制 ——
v0.5.5 的安卓包被打进 v0.5.6、2026-10-26 那次打出 8.0 MB 的包，都是这么来的。

编译命令（NDK 路径见 `memory/ANDROID-BUILD.md`）：

```powershell
$NDK = "E:\\AndroidSDK\\ndk\\30.0.16248370"
$BIN = "$NDK\\toolchains\\llvm\\prebuilt\\windows-x86_64\\bin"
$env:CC_aarch64_linux_android                  = "$BIN\\aarch64-linux-android26-clang.cmd"
$env:AR_aarch64_linux_android                  = "$BIN\\llvm-ar.exe"
$env:CARGO_TARGET_AARCH64_LINUX_ANDROID_LINKER = "$BIN\\aarch64-linux-android26-clang.cmd"
$env:CC_x86_64_linux_android                   = "$BIN\\x86_64-linux-android26-clang.cmd"
$env:AR_x86_64_linux_android                   = "$BIN\\llvm-ar.exe"
$env:CARGO_TARGET_X86_64_LINUX_ANDROID_LINKER  = "$BIN\\x86_64-linux-android26-clang.cmd"

cargo build --release --target aarch64-linux-android -p nfrp-server -p nfrp-client
cargo build --release --target x86_64-linux-android  -p nfrp-server -p nfrp-client
python scripts/pack_android.py
```

## 打包后自检

写完 zip 立刻解开，把包内 `frps` / `frpc` 与源产物逐个比 sha256，不一致直接
非零退出。理由同桌面版：`dist/` 是手工维护的，读错目录不会报错，只会静默
发错版本。
"""

from __future__ import annotations

import hashlib
import json
import re
import shutil
import subprocess
import sys
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT.parent / "dist" / "android"

ARCHS = [("aarch64", "aarch64-linux-android"), ("x86_64", "x86_64-linux-android")]
BINS = [("frps", "nfrp-server"), ("frpc", "nfrp-client")]


def log(msg: str) -> None:
    print(f"[android] {msg}", flush=True)


def cargo_target_dir() -> Path:
    env = __import__("os").environ.get("CARGO_TARGET_DIR")
    if env:
        p = Path(env)
        return p if p.is_absolute() else ROOT / p
    r = subprocess.run(
        ["cargo", "metadata", "--no-deps", "--format-version", "1"],
        cwd=ROOT,
        capture_output=True,
        encoding="utf-8",
        errors="replace",
    )
    if r.returncode != 0 or not (r.stdout or "").strip():
        raise SystemExit("cargo metadata 失败，推导不出产物目录")
    return Path(json.loads(r.stdout)["target_directory"])


def version() -> str:
    t = (ROOT / "Cargo.toml").read_text(encoding="utf-8")
    m = re.search(r'^version\s*=\s*"([^"]+)"', t, re.M)
    if not m:
        raise SystemExit("Cargo.toml 里没找到 workspace 版本")
    return m.group(1)


def sha256(p: Path) -> str:
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def main() -> int:
    ver = version()
    target = cargo_target_dir()
    log(f"版本 {ver}，源产物目录 {target}")

    stage = OUT / "stage"
    if stage.exists():
        shutil.rmtree(stage)

    real: dict[str, Path] = {}
    for arch, triple in ARCHS:
        d = stage / f"nfrp-android-{arch}"
        d.mkdir(parents=True)
        for dst, src in BINS:
            s = target / triple / "release" / src
            if not s.is_file():
                raise SystemExit(f"缺少产物：{s}\n  先按脚本开头的命令编译该 target")
            shutil.copy2(s, d / dst)
            real[f"nfrp-android-{arch}/{dst}"] = s
            log(f"  {arch:<8} {dst:<5} {s.stat().st_size / 1e6:.2f} MB  ({s})")

    readme = OUT / "README-ANDROID.md"
    if not readme.is_file():
        raise SystemExit(f"缺少 {readme}")
    shutil.copy2(readme, stage / "README-ANDROID.md")

    zip_path = OUT / f"nfrp-android-v{ver}.zip"
    if zip_path.exists():
        zip_path.unlink()
    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED, compresslevel=9) as z:
        for p in sorted(stage.rglob("*")):
            if p.is_file():
                z.write(p, p.relative_to(stage))

    # ---- 打包后自检：包内二进制 vs 源产物 ----
    with zipfile.ZipFile(zip_path) as z:
        for name, src in real.items():
            got = hashlib.sha256(z.read(name)).hexdigest()
            want = sha256(src)
            if got != want:
                raise SystemExit(f"自检失败：{name} 与源产物 sha256 不一致\n  包内 {got}\n  源   {want}")
    log(f"自检通过：包内 {len(real)} 个二进制与源产物 sha256 一致")

    h = sha256(zip_path)
    log(f"{zip_path}  {zip_path.stat().st_size / 1e6:.2f} MB")
    log(f"sha256 {h}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
