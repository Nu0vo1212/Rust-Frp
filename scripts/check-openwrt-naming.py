#!/usr/bin/env python3
"""OpenWrt 发布包命名一致性检查。

用途：汇总比对 install-openwrt.sh / release.py / release.yml / ci.yml /
e2e_openwrt.py / openwrt/README.md 里出现的 linux 包名，确保：
  1. 只出现规范的 5 个下划线命名（含 linux_mipsle，不是 linux_mipsel）；
  2. mipsel 一律写成 linux_mipsle（对齐官方 frp 的 linux_mipsle）；
  3. 每个"权威来源"文件都覆盖到全部 5 个包名，不多不少。

历史连字符命名（nfrp-linux-arm64 等）只允许出现在：
  - install-openwrt.sh 的历史回退兼容逻辑；
  - SECURITY-ALL-FIXES.md / memory/ 等历史记录（不扫描）。

接入 CI：ci.yml 的 naming-consistency job 调用本脚本。
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

# 规范的 5 个平台后缀（对齐官方 frp；mipsel 用 linux_mipsle）
CANONICAL = {
    "linux_amd64",
    "linux_arm64",
    "linux_arm_hf",
    "linux_mipsle",
    "linux_mips",
}
# 常见错误拼写（必须一个都不出现）
FORBIDDEN = {
    "linux_mipsel",      # 官方是 mipsle，不是 mipsel
    "linux-mipsle",      # 连字符
    "linux-mips",        # 连字符
    "linux-amd64",       # 连字符
    "linux-arm64",       # 连字符
    "linux-arm-hf",      # 连字符
}

# 每个权威来源文件里，5 个规范包名应全部出现
SOURCES_REQUIRING_ALL = [
    "scripts/install-openwrt.sh",
    ".github/workflows/release.yml",
    "openwrt/README.md",
]

errors: list[str] = []


def scan_file(rel: str) -> str:
    p = ROOT / rel
    if not p.exists():
        errors.append(f"缺文件: {rel}")
        return ""
    return p.read_text(encoding="utf-8", errors="replace")


def main() -> int:
    # 收集所有被扫描文件
    scanned = {
        rel: scan_file(rel)
        for rel in [
            "scripts/install-openwrt.sh",
            "scripts/e2e_openwrt.py",
            "scripts/release.py",
            ".github/workflows/release.yml",
            ".github/workflows/ci.yml",
            "openwrt/README.md",
            "docs/index.html",
        ]
    }

    # 1) 禁止的拼写：历史回退/历史说明文件例外
    #    install-openwrt.sh 必须保留连字符回退逻辑；
    #    openwrt/README.md 必须说明"老版本用连字符安装器也认"。
    #    这两个文件仍禁止 linux_mipsel 这种错误拼写。
    HYPHEN_ALLOWED = {"scripts/install-openwrt.sh", "openwrt/README.md"}
    for rel, text in scanned.items():
        for bad in sorted(FORBIDDEN):
            if rel in HYPHEN_ALLOWED and bad != "linux_mipsel":
                continue
            if bad in text:
                # 定位行号
                for i, line in enumerate(text.splitlines(), 1):
                    if bad in line:
                        errors.append(f"{rel}:{i} 出现错误包名 '{bad}': {line.strip()[:80]}")

    # 2) 权威来源必须覆盖全部 5 个规范包名
    for rel in SOURCES_REQUIRING_ALL:
        text = scanned[rel]
        found = {c for c in CANONICAL if c in text}
        missing = CANONICAL - found
        if missing:
            errors.append(f"{rel} 缺少包名: {', '.join(sorted(missing))}")

    # 3) 全局确认：任何 nfrp-linux_* 包名都属于规范集合
    pkg_re = re.compile(r"nfrp-(linux_[a-z0-9_]+)\.tar\.gz")
    for rel, text in scanned.items():
        for m in pkg_re.finditer(text):
            if m.group(1) not in CANONICAL:
                # install 脚本里的连字符回退是 nfrp-linux-xxx（连字符），不匹配本正则
                errors.append(f"{rel} 出现非规范包名: nfrp-{m.group(1)}.tar.gz")

    if errors:
        print("命名一致性检查失败：")
        for e in errors:
            print("  -", e)
        return 1

    print("命名一致性检查通过：")
    print("  规范包名:", ", ".join(sorted(CANONICAL)))
    print("  mipsel 统一为 linux_mipsle（对齐官方 frp）")
    print("  权威来源覆盖:", ", ".join(SOURCES_REQUIRING_ALL))
    return 0


if __name__ == "__main__":
    sys.exit(main())
