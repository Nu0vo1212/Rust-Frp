#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""文档数字一致性门禁：Cargo.toml / 四份 README / docs 站 / QUALITY.md。

检查什么：
    1. 版本号
       - 参考值：Cargo.toml `[workspace.package] version`
       - README.{md,zh-CN.md,ja.md,ru.md} 的版本徽章
       - docs/index.html 的顶栏版本、hero 徽章、`-V` 示例输出
       - docs/assets/i18n.js 的 hero 徽章（中文/英文两份文案）
       > docs 里大量 `v0.7.4` / `0.7.2` / `0.7.1` 是**历史叙述**
       > （例如 “自 v0.7.4 起提供”），不是“当前版本”声明，因此不做全量
       > 正则扫描，只认上面这些明确的当前版本位点。
    2. 测试总数
       - 真实执行 `cargo test --workspace`（或读取 test job 产出的报告），
         汇总所有 `test result: ok. X passed; Y failed; Z ignored` 的 X / Y / Z
         （**不估算**；构建/测试失败直接非零退出）
       - 与 QUALITY.md 的命令注释、合计行、四份 README 的命令注释与正文比对
    3. 忽略测试数（`ignored`），按平台取参考值
       - 参考值来自机器可读锚点 `<!-- test-ignored: windows=13 linux=10 -->`，
         分别写在 QUALITY.md 与四份 README 里
       - Linux 不编译 `cfg(target_os = "windows")` 的 Wintun 模块，因此是 10；
         Windows 是 13。只按当前平台比对，不要求两边相同
    4. 四份 README 都写到的常驻内存数字（本仓库实际存在的“体积/占用”数字）

用法：
    python scripts/check-docs-consistency.py
    python scripts/check-docs-consistency.py --test-output test-output.txt  # 读 CI test job 的报告，不重跑
    python scripts/check-docs-consistency.py --platform linux              # 在 Windows 上校验 Linux 报告时指定
    python scripts/check-docs-consistency.py --skip-tests                  # 不跑测试，只做语法校验

退出码：
    0 全部一致（打印 OK）
    1 发现不一致（逐条打印差异）
    2 无法完成检查（例如 cargo test 失败、参考值解析不出）
"""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

sys.stdout.reconfigure(encoding="utf-8", errors="replace")

ROOT = Path(__file__).resolve().parent.parent
README_FILES = ["README.md", "README.zh-CN.md", "README.ja.md", "README.ru.md"]


@dataclass
class Claim:
    key: str
    source: str
    value: str
    line: int


def read(path: Path) -> str:
    return path.read_text(encoding="utf-8", errors="replace")


def line_of(text: str, pos: int) -> int:
    return text.count("\n", 0, pos) + 1


def collect(
    path: Path,
    pattern: str,
    key: str,
    label: str,
    group: int = 1,
    value_map=None,
) -> list[Claim]:
    """按正则收集所有命中，带上文件与行号。"""
    text = read(path)
    out: list[Claim] = []
    for m in re.finditer(pattern, text):
        raw = m.group(group)
        value = value_map(raw) if value_map else raw
        out.append(Claim(key, f"{path.relative_to(ROOT)}:{line_of(text, m.start())} {label}", value, line_of(text, m.start())))
    return out


# ---------------------------------------------------------------------------
# 收集
# ---------------------------------------------------------------------------
def workspace_version() -> str:
    text = read(ROOT / "Cargo.toml")
    m = re.search(r"^\[workspace\.package\](.*?)(?=^\[)", text, re.S | re.M)
    if not m:
        raise RuntimeError("Cargo.toml 里找不到 [workspace.package]")
    v = re.search(r'^version\s*=\s*"([^"]+)"', m.group(1), re.M)
    if not v:
        raise RuntimeError("Cargo.toml [workspace.package] 里没有 version")
    return v.group(1)


def version_claims() -> list[Claim]:
    claims: list[Claim] = []
    for name in README_FILES:
        p = ROOT / name
        if not p.is_file():
            continue
        claims += collect(p, r"badge/version-([0-9][^-\s\"]*)-", "version", "版本徽章")
    idx = ROOT / "docs" / "index.html"
    if idx.is_file():
        claims += collect(idx, r'id="verBadge">([^<]+)<', "version", "docs 顶栏 verBadge")
        claims += collect(idx, r'hero-badge">v([0-9][0-9.]*)', "version", "docs hero 徽章")
        claims += collect(idx, r"-V\s+#\s*nfrp-(?:server|client)\s+([0-9][0-9.]*)", "version", "docs -V 示例")
    i18n = ROOT / "docs" / "assets" / "i18n.js"
    if i18n.is_file():
        claims += collect(i18n, r"'hero-badge':\s*'v([0-9][0-9.]*)", "version", "docs i18n hero 徽章")
    return claims


IGNORED_ANCHOR_RE = re.compile(
    r"test-ignored:\s*windows=(\d+)\s+linux=(\d+)"
)


def parse_test_claims() -> tuple[list[Claim], dict[str, list[Claim]]]:
    """返回 (测试总数 claims, 按平台分组的 ignored claims)。

    ignored 不能只认一个数：3 条 Wintun 测试在
    `#![cfg(target_os = "windows")]` 模块里，Linux 不编译。
    因此参考值写在机器可读锚点 `<!-- test-ignored: windows=13 linux=10 -->`，
    由当前平台选择对应值比对。
    """
    total: list[Claim] = []
    ignored: dict[str, list[Claim]] = {"windows": [], "linux": []}

    q = ROOT / "QUALITY.md"
    if q.is_file():
        total += collect(q, r"cargo test --workspace\s+#\s*(\d+)\s*个测试通过", "tests", "QUALITY 命令注释")
        total += collect(q, r"\*\*合计\*\*\s*\|\s*\*\*(\d+)\*\*\s*\|\s*\*\*(\d+)\*\*", "tests", "QUALITY 合计行")

    patterns = {
        "README.md": (r"(\d+)\s+automated tests", r"#\s*(\d+)\s+passed\s*/\s*(\d+)\s+failed\s*/\s*(\d+)\s+ignored"),
        "README.zh-CN.md": (r"(\d+)\s*个自动化测试", r"#\s*(\d+)\s*通过\s*/\s*(\d+)\s*失败\s*/\s*(\d+)\s*ignored"),
        "README.ja.md": (r"自動テスト\s*(\d+)\s*件", r"#\s*(\d+)\s*通過\s*/\s*(\d+)\s*失敗\s*/\s*(\d+)\s*ignored"),
        "README.ru.md": (r"(\d+)\s+автоматических тестов", r"#\s*(\d+)\s+пройдено\s*/\s*(\d+)\s+провалено\s*/\s*(\d+)\s+ignored"),
    }
    for name, (prose_re, cmd_re) in patterns.items():
        p = ROOT / name
        if not p.is_file():
            continue
        text = read(p)
        total += collect(p, prose_re, "tests", "正文测试数")
        total += collect(p, cmd_re, "tests", "测试命令注释")

    # 文档站概览卡片也必须与真实测试数一致。data-count 驱动数字动画，
    # stat-value 是首屏可见值，两者都要校验，避免只改一处。
    site = ROOT / "docs" / "index.html"
    if site.is_file():
        total += collect(
            site,
            r'data-count="(\d+)"[^>]*><div class="stat-value">\d+</div>'
            r'<div class="stat-label" data-i18n="stat-tests"',
            "tests", "文档站概览 data-count")
        total += collect(
            site,
            r'data-count="\d+"[^>]*><div class="stat-value">(\d+)</div>'
            r'<div class="stat-label" data-i18n="stat-tests"',
            "tests", "文档站概览可见值")

    for name in ["QUALITY.md", *README_FILES]:
        p = ROOT / name
        if not p.is_file():
            continue
        text = read(p)
        for m in IGNORED_ANCHOR_RE.finditer(text):
            ln = line_of(text, m.start())
            ignored["windows"].append(
                Claim("ignored", f"{name}:{ln} ignored 锚点", m.group(1), ln))
            ignored["linux"].append(
                Claim("ignored", f"{name}:{ln} ignored 锚点", m.group(2), ln))
    return total, ignored


def memory_claims() -> list[Claim]:
    """四份 README 都写到的「服务端常驻内存」数字（MB）。"""
    claims: list[Claim] = []
    patterns = {
        "README.md": r"[Aa]bout\s+([\d.]+)\s*MB resident",
        "README.zh-CN.md": r"常驻内存约\s*([\d.]+)\s*MB",
        "README.ja.md": r"約\s*([\d.]+)\s*MB",
        "README.ru.md": r"около\s*([\d,]+)\s*МБ",
    }
    for name, pat in patterns.items():
        p = ROOT / name
        if p.is_file():
            claims += collect(p, pat, "server_rss_mb", "服务端常驻内存",
                              value_map=lambda s: s.replace(",", "."))
    return claims


# ---------------------------------------------------------------------------
# 真实测试
# ---------------------------------------------------------------------------
RESULT_RE = re.compile(
    r"test result: (ok|FAILED)\. (\d+) passed; (\d+) failed; (\d+) ignored"
)


def summarize_test_output(out: str, origin: str) -> tuple[int, int, int]:
    matches = RESULT_RE.findall(out)
    if not matches:
        print("\n--- 测试输出（尾） ---")
        print(out[-4000:])
        raise RuntimeError(f"{origin} 里没有任何 'test result:' 行，无法汇总")
    passed = sum(int(m[1]) for m in matches)
    failed = sum(int(m[2]) for m in matches)
    ignored = sum(int(m[3]) for m in matches)
    print(f"{origin}：{passed} passed / {failed} failed / {ignored} ignored"
          f"（{len(matches)} 个 test target）")
    if failed:
        raise RuntimeError(f"{origin} 有 {failed} 个失败")
    return passed, failed, ignored


def run_cargo_tests() -> tuple[int, int, int]:
    print("运行 cargo test --workspace（解析真实输出，不估算）…", flush=True)
    p = subprocess.run(
        ["cargo", "test", "--workspace"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    out = (p.stdout or "") + "\n" + (p.stderr or "")
    if p.returncode != 0:
        print("\n--- cargo test 输出（尾） ---")
        print(out[-4000:])
        raise RuntimeError(f"cargo test --workspace 失败，退出码 {p.returncode}")
    return summarize_test_output(out, "cargo test --workspace")


def load_test_output(path: Path) -> tuple[int, int, int]:
    """读取 test job 保存的报告，不重跑测试。"""
    if not path.is_file():
        raise RuntimeError(f"找不到测试报告：{path}")
    out = path.read_text(encoding="utf-8", errors="replace")
    return summarize_test_output(out, f"{path}（test job 报告）")


# ---------------------------------------------------------------------------
# 比对
# ---------------------------------------------------------------------------
def check_group(
    title: str, claims: list[Claim], reference: str, ref_desc: str
) -> list[str]:
    print(f"\n== {title} ==")
    print(f"  参考：{ref_desc} = {reference}")
    bad: list[str] = []
    for c in claims:
        ok = c.value == reference
        print(f"  {'✓' if ok else '✗'} {c.source} = {c.value}" + ("" if ok else f"（≠ {reference}）"))
        if not ok:
            bad.append(f"{c.source}: {c.value} ≠ {reference}")
    if not claims:
        print("  （没有找到任何声明）")
    return bad


def main() -> int:
    ap = argparse.ArgumentParser(description="文档数字一致性门禁")
    ap.add_argument("--skip-tests", action="store_true",
                    help="不跑 cargo test，只用 QUALITY.md 现有值做语法校验")
    ap.add_argument("--test-output", type=Path, metavar="FILE",
                    help="读取 test job 产出的报告，而不是重跑 cargo test")
    ap.add_argument("--platform", choices=["windows", "linux"],
                    help="校验 ignored 时使用的平台（默认按当前系统推断）")
    args = ap.parse_args()

    platform = args.platform or ("windows" if sys.platform.startswith("win") else "linux")

    try:
        version = workspace_version()
    except Exception as e:  # noqa: BLE001
        print(f"❌ 无法解析 Cargo.toml 版本：{e}", file=sys.stderr)
        return 2

    test_claims, ignored_by_platform = parse_test_claims()
    ignored_claims = ignored_by_platform[platform]

    actual_passed = actual_ignored = None
    if args.skip_tests:
        quality = [c for c in test_claims if c.source.startswith("QUALITY.md")]
        if not quality:
            print("❌ --skip-tests 需要 QUALITY.md 里可解析的测试总数作为参考值", file=sys.stderr)
            return 2
        for c in test_claims:
            if not c.value.isdigit() or int(c.value) <= 0:
                print(f"❌ {c.source} 的测试总数不是正整数：[{c.value}]", file=sys.stderr)
                return 2
        for c in ignored_claims:
            if not c.value.isdigit():
                print(f"❌ {c.source} 的 ignored 数不是整数：[{c.value}]", file=sys.stderr)
                return 2
        tests_ref = quality[0].value
        tests_ref_desc = "QUALITY.md（--skip-tests 未跑测试）"
        ignored_ref = ignored_claims[0].value if ignored_claims else None
        ignored_ref_desc = "QUALITY.md（--skip-tests 未跑测试）"
        print("⚠️ --skip-tests：没有运行 cargo test，测试数只做语法校验，不构成「已验证」")
    else:
        try:
            if args.test_output:
                actual_passed, _, actual_ignored = load_test_output(args.test_output)
                origin = f"{args.test_output}（test job 报告，未重跑测试）"
            else:
                actual_passed, _, actual_ignored = run_cargo_tests()
                origin = "cargo test --workspace 真实输出"
        except Exception as e:  # noqa: BLE001
            print(f"\n❌ {e}", file=sys.stderr)
            return 2
        tests_ref = str(actual_passed)
        tests_ref_desc = origin
        ignored_ref = str(actual_ignored)
        ignored_ref_desc = f"{origin}，平台 {platform}"

    mismatches: list[str] = []
    mismatches += check_group("版本号", version_claims(), version, "Cargo.toml [workspace.package]")
    mismatches += check_group("测试总数", test_claims, tests_ref, tests_ref_desc)
    if ignored_ref is not None:
        mismatches += check_group(f"忽略测试数（{platform}）", ignored_claims, ignored_ref, ignored_ref_desc)

    mem = memory_claims()
    if mem:
        mismatches += check_group("服务端常驻内存（MB）", mem, mem[0].value, "README.md（基准）")

    print("\n" + "=" * 62)
    if mismatches:
        print(f"不一致 {len(mismatches)} 项：")
        for m in mismatches:
            print(f"  - {m}")
        return 1
    print("OK：版本号、测试总数、忽略测试数、内存数字全部一致")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except SystemExit:
        raise
    except Exception:  # noqa: BLE001
        import traceback

        traceback.print_exc()
        sys.exit(2)
