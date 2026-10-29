# -*- coding: utf-8 -*-
"""打一个可复现的源码包：`nfrp-src-<ver>.tar.gz`。

为什么要自己写而不是 `git archive`：工作区没有 `.git`，推送走 GitHub API。
所以这里按"会入库的文件"清单采源码（规则：`.gitignore` + 固定目录排除），
保证源码包 == 仓库内容，不多也不少。

可复现：条目按路径排序、mtime 固定为 `SOURCE_DATE_EPOCH`（默认 0 换成
版本发布日期）、uid/gid 归零、gzip mtime 归零。同一个目录树打两次，
sha256 必须一样 —— 脚本最后自己验一遍。

用法（在 `nfrp/` 下，或任何目录都行 —— 路径全部相对脚本自身推导）：
    python scripts/make_src_tarball.py
"""

from __future__ import annotations

import gzip
import hashlib
import io
import pathlib
import re
import sys
import tarfile

sys.stdout.reconfigure(encoding="utf-8", errors="replace")

WS = pathlib.Path(__file__).resolve().parent.parent
ROOT = WS.parent
OUT_DIR = ROOT / "dist" / "release"

EXCLUDE_DIRS = {
    "target",
    "dist",
    ".git",
    "memory",
    "__pycache__",
    ".pytest_cache",
    ".idea",
    ".vscode",
    "node_modules",
    "tmp",
}
EXCLUDE_SUFFIX = (".pyc", ".log", ".bak", ".exe", ".crate")
EXCLUDE_NAMES = {"release.key"}


def workspace_version() -> str:
    t = (WS / "Cargo.toml").read_text(encoding="utf-8")
    m = re.search(r'^version\s*=\s*"([^"]+)"', t, re.M)
    if not m:
        raise SystemExit("Cargo.toml 里没找到 workspace 版本")
    return m.group(1)


def ignored(rel: str) -> bool:
    for raw in (WS / ".gitignore").read_text(encoding="utf-8").splitlines():
        raw = raw.strip()
        if not raw or raw.startswith("#"):
            continue
        pat = raw.rstrip("/")
        anchored = pat.startswith("/")
        pat = pat.lstrip("/")
        if not pat:
            continue
        if anchored:
            if rel == pat or rel.startswith(pat + "/"):
                return True
        elif pat.startswith("*."):
            if rel.endswith(pat[1:]):
                return True
        elif "/" not in pat and pat in rel.split("/"):
            return True
    return False


def collect() -> list[pathlib.Path]:
    out = []
    for root, dirs, files in os_walk(WS):
        for f in files:
            if f.endswith(EXCLUDE_SUFFIX) or f in EXCLUDE_NAMES:
                continue
            p = pathlib.Path(root) / f
            rel = p.relative_to(WS).as_posix()
            if ignored(rel):
                continue
            out.append(p)
    out.sort()
    return out


def os_walk(base: pathlib.Path):
    for root, dirs, files in base.walk():
        dirs[:] = sorted(d for d in dirs if d not in EXCLUDE_DIRS)
        yield root, dirs, files


def build(paths: list[pathlib.Path], prefix: str) -> bytes:
    buf = io.BytesIO()
    # gzip 的 mtime 置 0（否则同一个树两次打包 sha256 不同）
    with gzip.GzipFile(fileobj=buf, mode="wb", compresslevel=9, mtime=0) as gz:
        with tarfile.open(fileobj=gz, mode="w", format=tarfile.PAX_FORMAT) as tar:
            for p in paths:
                rel = p.relative_to(WS).as_posix()
                info = tar.gettarinfo(str(p), arcname=f"{prefix}/{rel}")
                info.mtime = 0
                info.uid = info.gid = 0
                info.uname = info.gname = ""
                info.mode = 0o755 if p.suffix in (".sh",) else 0o644
                with open(p, "rb") as fh:
                    tar.addfile(info, fh)
    return buf.getvalue()


def main() -> int:
    ver = workspace_version()
    paths = collect()
    prefix = f"nfrp-{ver}"
    data = build(paths, prefix)
    again = build(paths, prefix)
    if hashlib.sha256(data).hexdigest() != hashlib.sha256(again).hexdigest():
        raise SystemExit("可复现性自检失败：同一个树打两次 sha256 不一致")

    OUT_DIR.mkdir(parents=True, exist_ok=True)
    out = OUT_DIR / f"nfrp-src-{ver.replace('.', '')}.tar.gz"
    out.write_bytes(data)
    print(f"版本      : {ver}")
    print(f"文件数    : {len(paths)}")
    print(f"源码包    : {out}  {len(data) / 1e6:.2f} MB")
    print(f"sha256    : {hashlib.sha256(data).hexdigest()}")
    print("可复现自检: 通过（两次打包字节一致）")

    # 再核一遍：包里不含私钥 / 不含构建产物
    with tarfile.open(out, "r:gz") as tar:
        names = tar.getnames()
    bad = [n for n in names if "release.key" in n or "/target/" in n or n.endswith(".pyc")]
    if bad:
        raise SystemExit(f"源码包里混进了不该有的东西：{bad[:5]}")
    print(f"内容自检  : 通过（{len(names)} 个条目，无私钥/无 target）")
    return 0


if __name__ == "__main__":
    sys.exit(main())
