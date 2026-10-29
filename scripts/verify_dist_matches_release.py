#!/usr/bin/env python3
"""发版闸门：本地 `dist/release/` 必须与 GitHub Release 的资产一一对应。

用法（在仓库根跑）：

```bash
python scripts/verify_dist_matches_release.py                 # 对比最新 Release
python scripts/verify_dist_matches_release.py --tag v0.6.6     # 指定 tag
python scripts/verify_dist_matches_release.py --dir dist/release --check-android
```

为什么要有它：dist 目录是**手工维护**的，历史上出现过

- `dist/release/` 只有 3 个平台包，而 Release 页面实际挂了 8 个资产；
- `dist/android/` 里 0.5.3 ~ 0.6.6 十四份并存，发版时靠人记得拿最新那份。

这两种漂移都不会报错，只会让人发出错的东西。这个脚本把「本地应该有
哪些文件、内容对不对」变成一条命令、一个非零退出码。

比对规则：
    名称 —— Release 资产名 vs 本地文件名，必须完全一致（缺或多都算差异）
    sha256 —— 逐个比对；GitHub 现在会给每个资产算 `digest`，
               没有 digest 的旧资产退化成只比大小（并在输出里标注）

令牌：优先环境变量 `GH_TOKEN`，其次仓库外的 `../tmp/gh-token.txt`
（`tmp/` 不入库，令牌不会进仓库）。
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
API = "https://api.github.com"
DEFAULT_REPO = "Nu0vo1212/Rust-Frp"
TOKEN_CANDIDATES = [
    ROOT.parent / "tmp" / "gh-token.txt",
    ROOT / "tmp" / "gh-token.txt",
]


def token() -> str | None:
    if os.environ.get("GH_TOKEN"):
        return os.environ["GH_TOKEN"].strip()
    for p in TOKEN_CANDIDATES:
        if p.is_file():
            return p.read_text(encoding="utf-8").strip()
    return None


def api_get(url: str, tok: str | None, tries: int = 4) -> dict:
    headers = {"Accept": "application/vnd.github+json", "User-Agent": "nfrp-dist-verify"}
    if tok:
        headers["Authorization"] = "Bearer " + tok
    last: Exception | None = None
    for _ in range(tries):
        try:
            req = urllib.request.Request(url, headers=headers)
            with urllib.request.urlopen(req, timeout=60) as r:
                return json.loads(r.read())
        except Exception as e:  # 网络抖动（含 IncompleteRead）就重试
            last = e
    raise SystemExit(f"请求失败：{url}\n  {last!r}")


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def pick_release(repo: str, tok: str | None, tag: str | None) -> dict:
    if tag:
        return api_get(f"{API}/repos/{repo}/releases/tags/{tag}", tok)
    rels = api_get(f"{API}/repos/{repo}/releases?per_page=1", tok)
    if not rels:
        raise SystemExit("仓库里没有任何 Release")
    return rels[0]


def compare(local_dir: Path, assets: list[dict], check_android: bool) -> int:
    remote = {a["name"]: a for a in assets}
    local = {p.name: p for p in local_dir.iterdir() if p.is_file()} if local_dir.is_dir() else {}

    rows: list[tuple[str, str, str]] = []
    ok = True

    for name in sorted(remote):
        a = remote[name]
        if name not in local:
            rows.append(("缺失", name, f"Release 有（{a['size']} 字节），本地 dist/release 没有"))
            ok = False
            continue
        p = local[name]
        digest = a.get("digest") or ""
        if digest.startswith("sha256:"):
            want = digest.split(":", 1)[1]
            got = sha256(p)
            if got != want:
                rows.append(("内容不符", name, f"Release sha256 {want[:16]}… / 本地 {got[:16]}…"))
                ok = False
            else:
                rows.append(("一致", name, "sha256 相同"))
        else:
            if p.stat().st_size != a["size"]:
                rows.append(("大小不符", name, f"Release {a['size']} / 本地 {p.stat().st_size}"))
                ok = False
            else:
                rows.append(("一致(仅大小)", name, f"{a['size']} 字节；该资产没有 digest"))

    if check_android:
        android_dir = local_dir.parent / "android"
        ver = next((n for n in remote if n.startswith("nfrp-android-")), None)
        if ver:
            want_name = ver
            current = [p.name for p in android_dir.glob("nfrp-android-v*.zip")]
            extra = sorted(n for n in current if n != want_name)
            if want_name not in current:
                rows.append(("缺失", want_name, "dist/android 里没有当前版本的安卓包"))
                ok = False
            if extra:
                rows.append(
                    ("多余", "dist/android", f"{len(extra)} 个非当前版本包未归档：" + ", ".join(extra[:6]))
                )
                ok = False

    width = max(len(r[0]) for r in rows) if rows else 6
    print(f"{'状态'.ljust(width)}  资产")
    print("-" * (width + 60))
    for state, name, detail in rows:
        print(f"{state.ljust(width)}  {name}")
        if state != "一致":
            print(f"{''.ljust(width)}    {detail}")
    print()
    print("结论：" + ("本地 dist/release 与 Release 完全一致" if ok else "存在差异，发版前必须处理"))
    return 0 if ok else 1


def default_dist() -> Path:
    """交付产物目录：优先仓库**上一层**的 `dist/`（真实发版用的那份）。

    本仓库有两种 dist，历史上就是它们对不上才出的事：
    - `../dist/` —— 真正的交付目录，Release 说明、安卓包、release/ 都在这里；
    - `dist/`    —— gitignore 的本地构建暂存，曾经留着更早的 0.6.6 包。
    默认取前者；不存在才退回后者。
    """
    outer = ROOT.parent / "dist" / "release"
    return outer if outer.is_dir() else ROOT / "dist" / "release"


def main() -> int:
    ap = argparse.ArgumentParser(description="校验 dist/release 与 GitHub Release 资产是否一一对应")
    ap.add_argument("--dir", default=str(default_dist()), help="本地产物目录")
    ap.add_argument("--tag", help="Release tag（默认取最新）")
    ap.add_argument("--repo", default=DEFAULT_REPO, help="owner/repo")
    ap.add_argument("--check-android", action="store_true", help="顺带检查 dist/android 是否只留当前版本")
    ap.add_argument("--list", action="store_true", help="只打印 Release 资产清单")
    a = ap.parse_args()

    tok = token()
    rel = pick_release(a.repo, tok, a.tag)
    assets = rel.get("assets", [])
    print(f"Release {rel.get('tag_name')}（{rel.get('published_at')}）共 {len(assets)} 个资产")

    if a.list:
        for x in assets:
            print(f"  {x['name']:<32} {x['size']:>10}  {x.get('digest') or ''}")
        return 0

    return compare(Path(a.dir), assets, a.check_android)


if __name__ == "__main__":
    sys.exit(main())
