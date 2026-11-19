#!/usr/bin/env python3
"""发布包命名一致性检查。

用途：汇总比对 install-openwrt.sh / release.py / release.yml / ci.yml /
e2e_openwrt.py / openwrt/README.md / 下载页 / Android / 源码包脚本里的包名：

  1. 只用连字符命名，且不带版本号：`nfrp-linux-amd64.tar.gz`；
  2. mipsel 写成 linux-mipsle（对齐官方 frp 的 mipsle，不是 mipsel 直译）；
  3. Windows 与 Android 用 .zip，其余平台用 .tar.gz；
  4. 三个权威来源（安装器 / release.yml / openwrt README）各自覆盖全部 5 个
     Linux 包名，缺一个就红。

历史说明：v0.7.7 之前有一版试过下划线（nfrp-linux_amd64.tar.gz），
安装器保留了下划线回退兼容，所以 install-openwrt.sh 与 openwrt/README.md
允许出现下划线形式，但只允许在历史说明/回退逻辑里，其它文件一律禁止。

接入 CI：ci.yml 的 lint job 调用本脚本。
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

# 规范包名后缀（连字符、无版本号）
CANONICAL = {
    "linux-amd64",
    "linux-arm64",
    "linux-arm-hf",
    "linux-mipsle",
    "linux-mips",
}
# 下划线形式：只允许出现在历史兼容说明里
LEGACY_UNDERSCORE = {
    "linux_amd64",
    "linux_arm64",
    "linux_arm_hf",
    "linux_mipsle",
    "linux_mips",
}
# 错误拼写（任何地方都不该出现）
FORBIDDEN_ANYWHERE = {
    "linux-mipsel",   # 官方是 mipsle
    "linux-armhf",    # 统一写 arm-hf，避免两种写法
}

# 允许出现下划线历史说明的文件
UNDERSCORE_EXEMPT = {
    "scripts/install-openwrt.sh",
    "openwrt/README.md",
}

# 每个权威来源必须覆盖全部 5 个 Linux 包名
SOURCES_REQUIRING_ALL = [
    "scripts/install-openwrt.sh",
    ".github/workflows/release.yml",
    "openwrt/README.md",
]

errors: list[str] = []


def scan(rel: str) -> str:
    p = ROOT / rel
    if not p.exists():
        errors.append(f"缺文件: {rel}")
        return ""
    return p.read_text(encoding="utf-8", errors="replace")


def main() -> int:
    scanned = {
        rel: scan(rel)
        for rel in [
            "scripts/install-openwrt.sh",
            "scripts/e2e_openwrt.py",
            "scripts/release.py",
            "scripts/pack_android.py",
            "scripts/make_src_tarball.py",
            ".github/workflows/release.yml",
            ".github/workflows/ci.yml",
            "openwrt/README.md",
            "docs/index.html",
            "docs/assets/i18n.js",
        ]
    }

    # 1) 错误拼写：一个都不许有
    for rel, text in scanned.items():
        for bad in sorted(FORBIDDEN_ANYWHERE):
            if bad in text:
                for i, line in enumerate(text.splitlines(), 1):
                    if bad in line:
                        errors.append(f"{rel}:{i} 错误拼写 '{bad}': {line.strip()[:80]}")

    # 2) 下划线命名：只有豁免文件允许
    for rel, text in scanned.items():
        if rel in UNDERSCORE_EXEMPT:
            continue
        for bad in sorted(LEGACY_UNDERSCORE):
            if bad in text:
                for i, line in enumerate(text.splitlines(), 1):
                    if bad not in line:
                        continue
                    # 官方 frp 自己的资产名就是 frp_0.71.0_linux_amd64.tar.gz
                    # （下划线）。下载/互通脚本里出现官方名是正常的，不算我们违规。
                    if "frp_" in line or "official" in line.lower():
                        continue
                    errors.append(
                        f"{rel}:{i} 用了下划线命名 '{bad}'（应为连字符）: {line.strip()[:80]}"
                    )

    # 3) 权威来源覆盖全部 5 个 Linux 包名
    for rel in SOURCES_REQUIRING_ALL:
        text = scanned[rel]
        missing = {c for c in CANONICAL if c not in text}
        if missing:
            errors.append(f"{rel} 缺少包名: {', '.join(sorted(missing))}")

    # 4) 任何 nfrp-<linux-*>.<ext> 必须是规范名，且 Linux 包不能用 zip
    pkg_re = re.compile(r"nfrp-(linux[-_][a-z0-9_-]+?)\.(tar\.gz|zip|tgz)")
    for rel, text in scanned.items():
        if rel in UNDERSCORE_EXEMPT:
            # 历史兼容说明里会出现旧的 nfrp-linux_xxx.tar.gz，属于有意保留
            continue
        for m in pkg_re.finditer(text):
            plat, ext = m.group(1), m.group(2)
            if plat not in CANONICAL:
                errors.append(f"{rel} 出现非规范包名: nfrp-{plat}.{ext}")
            if ext in ("zip", "tgz"):
                errors.append(f"{rel} 的 Linux 包扩展名不对: nfrp-{plat}.{ext}")

    # 5) Windows / Android 必须是 zip，且不带版本号
    for rel in [".github/workflows/release.yml", "docs/index.html"]:
        text = scanned[rel]
        if "nfrp-windows-amd64.zip" not in text:
            errors.append(f"{rel} 缺少 nfrp-windows-amd64.zip")
        if re.search(r"nfrp-windows[_-]amd64\.(tar\.gz|tgz)", text):
            errors.append(f"{rel} 的 Windows 包不是 zip")
    android_py = scanned["scripts/pack_android.py"]
    if "nfrp-android.zip" not in android_py:
        errors.append("scripts/pack_android.py 未输出 nfrp-android.zip")
    if re.search(r"nfrp-android-v", android_py):
        errors.append("scripts/pack_android.py 的 Android 包仍然带版本号")

    # 6) 源码包不带版本号
    if "nfrp-src.tar.gz" not in scanned["scripts/make_src_tarball.py"]:
        errors.append("scripts/make_src_tarball.py 未输出 nfrp-src.tar.gz")

    if errors:
        print("命名一致性检查失败：")
        for e in errors:
            print("  -", e)
        return 1

    print("命名一致性检查通过：")
    print("  规范包名:", ", ".join(sorted(CANONICAL)))
    print("  Windows / Android 用 zip，其余 tar.gz，全部不带版本号")
    print("  权威来源覆盖:", ", ".join(SOURCES_REQUIRING_ALL))
    return 0


if __name__ == "__main__":
    sys.exit(main())
