#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""把 `docs/nlink.md` 同步到站点页面与本地记忆文档。

## 为什么要有这个脚本

NLink 的内容同时出现在两处：

1. **站点页面** `docs/assets/pages.zh.js` / `pages.en.js` 里的 `PAGES_XX['nlink']`
2. **本地记忆** `memory/NLINK-V1-EVALUATION.md`（不上传）

两处手工维护迟早漂移 —— 改了一处忘了另一处，或者站点上是新版、
memory 里还是旧的。所以约定：

* 唯一内容源是 `docs/nlink.md`
* 这个脚本负责生成两个**生成物**
* `--check` 只校验有没有漂移，不改文件（适合放进 CI / 提交前跑）

## 用法

```powershell
python scripts/sync_nlink_doc.py           # 生成
python scripts/sync_nlink_doc.py --check   # 只检查，有漂移则退出码 1
```

## 生成的 HTML 约定

站点页面是直接 innerHTML 注入的静态 HTML，所以：

* `## 标题` → `<h2 data-i18n="nlink-xxx-h">`
* `### 标题` → `<h3 data-i18n="nlink-xxx-h">`
* 表格 → `<div class="table-wrap"><table>...`
* `:::callout 标题 / 正文 / :::` → `<div class="callout">` 结构
* 内联 `**粗体**` / `` `代码` `` → `<strong>` / `<code>`

`data-i18n` 的 key 由序号生成（`nlink-s1`、`nlink-s2`…），不依赖标题文本，
这样改标题也不会让 key 漂移。
"""
import argparse
import io
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent          # nfrp/
SRC = ROOT / "docs" / "nlink.md"
ZH = ROOT / "docs" / "assets" / "pages.zh.js"
EN = ROOT / "docs" / "assets" / "pages.en.js"
MEM = ROOT / "memory" / "NLINK-V1-EVALUATION.md"

BEGIN = "<!-- BEGIN nlink (generated from docs/nlink.md, do not edit) -->"
END = "<!-- END nlink -->"


# --------------------------------------------------------------------------
# Markdown -> HTML
# --------------------------------------------------------------------------
def inline_html(text: str) -> str:
    """把行内 Markdown 转成 HTML。

    只处理这一份文档用到的子集：粗体、行内代码、斜体。
    顺序很重要 —— 先抽出代码段占位，再处理粗体，否则
    `` `useCompression` `` 里的下划线会被斜体规则误伤。
    """
    codes: list[str] = []

    def stash(m):
        codes.append(m.group(1))
        return f"\x00{len(codes) - 1}\x00"

    text = re.sub(r"`([^`]+)`", stash, text)
    text = re.sub(r"\*\*(.+?)\*\*", r"<strong>\1</strong>", text)
    text = re.sub(r"(?<!\*)\*([^*]+)\*(?!\*)", r"<em>\1</em>", text)
    # 还原代码段（转义 HTML 特殊字符）
    for i, c in enumerate(codes):
        esc = c.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
        text = text.replace(f"\x00{i}\x00", f"<code>{esc}</code>")
    return text


def slug_key(prefix: str, n: int) -> str:
    return f"{prefix}{n}"


def md_to_html(md: str) -> str:
    """整篇 Markdown 转站点用的 HTML 片段。"""
    lines = md.split("\n")
    out: list[str] = []
    i = 0
    h2_n = 0
    h3_n = 0
    lead_used = False

    while i < len(lines):
        line = lines[i]
        s = line.rstrip()

        # 空行
        if not s.strip():
            i += 1
            continue

        # 围栏代码块 ```lang ... ```
        #
        # 必须在**所有其它规则之前**判断：否则 ``` 会被当成普通段落，
        # 反引号原样进到 JS 模板字符串里，直接把 pages.*.js 的语法弄坏。
        m = re.match(r"^\s*```(\w*)\s*$", s)
        if m:
            lang = m.group(1)
            i += 1
            body: list[str] = []
            while i < len(lines) and not re.match(r"^\s*```\s*$", lines[i]):
                body.append(lines[i])
                i += 1
            i += 1  # 跳过收尾的 ```
            code = "\n".join(body)
            esc = (
                code.replace("&", "&amp;")
                .replace("<", "&lt;")
                .replace(">", "&gt;")
            )
            cls = f' class="language-{lang}"' if lang else ""
            out.append(f'<pre class="code-block"><code{cls}>{esc}</code></pre>')
            continue

        # 引用块（文件头的元信息，站点不展示）
        if s.lstrip().startswith(">"):
            while i < len(lines) and (lines[i].lstrip().startswith(">") or not lines[i].strip()):
                i += 1
            continue

        # 分隔线
        if re.match(r"^-{3,}$", s.strip()):
            i += 1
            continue

        # 一级标题（页面里被站点的 h1 占位，跳过）
        if s.startswith("# ") and not s.startswith("## "):
            i += 1
            continue

        # callout
        m = re.match(r"^:::callout\s*(.*)$", s.strip())
        if m:
            title = m.group(1).strip()
            body: list[str] = []
            i += 1
            while i < len(lines) and lines[i].strip() != ":::":
                if lines[i].strip():
                    body.append(lines[i].strip())
                i += 1
            i += 1  # 跳过收尾的 :::
            out.append('<div class="callout">')
            out.append(
                '  <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" '
                'stroke-width="2" stroke-linecap="round" stroke-linejoin="round">'
                '<circle cx="12" cy="12" r="10"/><path d="M12 16v-4M12 8h.01"/></svg>'
            )
            out.append("  <div>")
            if title:
                out.append(f"    <strong>{inline_html(title)}</strong>")
            if body:
                out.append(f"    <p>{inline_html(' '.join(body))}</p>")
            out.append("  </div>")
            out.append("</div>")
            continue

        # 三级标题
        if s.startswith("### "):
            h3_n += 1
            key = slug_key("nlink-c", h3_n) + "-h"
            out.append(f'<h3 data-i18n="{key}">{inline_html(s[4:])}</h3>')
            i += 1
            continue

        # 二级标题
        if s.startswith("## "):
            h2_n += 1
            key = f"nlink-s{h2_n}-h"
            out.append(f'<h2 data-i18n="{key}">{inline_html(s[3:])}</h2>')
            i += 1
            continue

        # 表格
        if s.lstrip().startswith("|") and i + 1 < len(lines) and re.match(
            r"^\s*\|[\s:|-]+\|\s*$", lines[i + 1]
        ):
            header = [c.strip() for c in s.strip().strip("|").split("|")]
            i += 2
            rows: list[list[str]] = []
            while i < len(lines) and lines[i].lstrip().startswith("|"):
                rows.append([c.strip() for c in lines[i].strip().strip("|").split("|")])
                i += 1
            out.append('<div class="table-wrap">')
            out.append("<table>")
            out.append("<thead><tr>")
            for h in header:
                out.append(f"<th>{inline_html(h)}</th>")
            out.append("</tr></thead>")
            out.append("<tbody>")
            for r in rows:
                out.append("<tr>")
                for c in r:
                    out.append(f"<td>{inline_html(c)}</td>")
                out.append("</tr>")
            out.append("</tbody>")
            out.append("</table>")
            out.append("</div>")
            continue

        # 有序列表
        if re.match(r"^\d+\.\s", s):
            out.append("<ol>")
            while i < len(lines) and re.match(r"^\d+\.\s", lines[i]):
                item = re.sub(r"^\d+\.\s+", "", lines[i])
                out.append(f"<li>{inline_html(item)}</li>")
                i += 1
            out.append("</ol>")
            continue

        # 无序列表
        if re.match(r"^[-*]\s", s):
            out.append("<ul>")
            while i < len(lines) and re.match(r"^[-*]\s", lines[i]):
                item = re.sub(r"^[-*]\s+", "", lines[i])
                out.append(f"<li>{inline_html(item)}</li>")
                i += 1
            out.append("</ul>")
            continue

        # 段落：连续非空行合并
        para: list[str] = []
        while i < len(lines) and lines[i].strip() and not re.match(
            r"^(#{1,3}\s|\||\d+\.\s|[-*]\s|:::callout|-{3,}$)", lines[i].strip()
        ):
            para.append(lines[i].strip())
            i += 1
        if para:
            text = " ".join(para)
            # 第一段当作 lead（与站点既有页面风格一致）
            if not lead_used and h2_n == 0:
                out.append(f'<p class="lead" data-i18n="nlink-lead">{inline_html(text)}</p>')
                lead_used = True
            else:
                out.append(f"<p>{inline_html(text)}</p>")
            continue

        i += 1

    return "\n".join(out)


# --------------------------------------------------------------------------
# 生成物拼接
# --------------------------------------------------------------------------
def build_pages_block(html: str, var: str) -> str:
    """生成页面块。

    `var` 必须是目标文件里真实存在的对象名（`PAGES_ZH` / `PAGES_EN`）——
    写错不会立刻报错，而是让页面在浏览器里抛 ReferenceError 白屏。
    """
    return f"{BEGIN}\n{var}['nlink'] = `\n{html}\n`;\n{END}"


def strip_meta(md: str) -> str:
    """去掉文件头的引用块与分隔线，只留正文（memory 用）。"""
    lines = md.split("\n")
    i = 0
    # 跳过开头的 # 标题
    while i < len(lines) and not lines[i].strip():
        i += 1
    if i < len(lines) and lines[i].startswith("# "):
        i += 1
    # 跳过紧随其后的引用块与分隔线
    while i < len(lines):
        s = lines[i].strip()
        if not s or s.startswith(">") or re.match(r"^-{3,}$", s):
            i += 1
            continue
        break
    return "\n".join(lines[i:]).strip() + "\n"


MEM_HEADER = """# NLink v1 规划（本地记忆版）

> **这是生成物，不要直接编辑。**
>
> 内容源：`docs/nlink.md`
> 生成器：`scripts/sync_nlink_doc.py`
> 改完内容源后运行：`python scripts/sync_nlink_doc.py`
>
> 同一个内容源还会生成站点页面 `docs/assets/pages.zh.js` 里的 `PAGES_ZH['nlink']`，
> 所以改一处、跑一次，两边都同步。
>
> 这个文件放在 `memory/` 下，已被 `.gitignore` 的 `/memory` 屏蔽，**不会上传**。

---

"""


def replace_block(text: str, new_block: str) -> str:
    """替换两个标记之间的内容；没有标记就追加到末尾。"""
    if BEGIN in text and END in text:
        pre = text[: text.index(BEGIN)]
        post = text[text.index(END) + len(END) :]
        return pre + new_block + post
    return text.rstrip() + "\n\n" + new_block + "\n"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--check", action="store_true", help="只检查是否漂移，不写文件")
    args = ap.parse_args()

    if not SRC.is_file():
        print(f"内容源不存在：{SRC}")
        return 2

    md = io.open(SRC, encoding="utf-8").read()
    html = md_to_html(md)
    mem_text = MEM_HEADER + strip_meta(md)

    targets = [
        (ZH, build_pages_block(html, "PAGES_ZH"), "docs/assets/pages.zh.js"),
        (EN, build_pages_block(html, "PAGES_EN"), "docs/assets/pages.en.js"),
        (MEM, mem_text, "memory/NLINK-V1-EVALUATION.md"),
    ]

    drift = []
    for path, block, label in targets:
        cur = io.open(path, encoding="utf-8").read() if path.is_file() else ""
        want = replace_block(cur, block) if path != MEM else block
        if cur.strip() != want.strip():
            drift.append(label)
            if not args.check:
                path.parent.mkdir(parents=True, exist_ok=True)
                io.open(path, "w", encoding="utf-8", newline="").write(want)
                print(f"  已更新 {label}")

    if args.check:
        if drift:
            print("❌ 生成物与内容源不一致，请运行 python scripts/sync_nlink_doc.py")
            for d in drift:
                print(f"   - {d}")
            return 1
        print("✅ 生成物与内容源一致")
        return 0

    if drift:
        print(f"同步完成，更新了 {len(drift)} 个文件")
    else:
        print("已是最新，无需改动")
    return 0


if __name__ == "__main__":
    sys.exit(main())
