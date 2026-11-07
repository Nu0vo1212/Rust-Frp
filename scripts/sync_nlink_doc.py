#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""把 `docs/nlink.md` / `docs/nlink.en.md` 同步到站点页面与本地记忆文档。

## 为什么要有这个脚本

NLink 的内容同时出现在三处：

1. **中文站点页面** `docs/assets/pages.zh.js` 里的 `PAGES_ZH['nlink']`
2. **英文站点页面** `docs/assets/pages.en.js` 里的 `PAGES_EN['nlink']`
3. **本地记忆** `memory/NLINK-V1-EVALUATION.md`（不上传）

手工维护迟早漂移 —— 改了一处忘了另一处。所以约定：

* 中文唯一内容源是 `docs/nlink.md`
* 英文唯一内容源是 `docs/nlink.en.md`
* 这个脚本负责生成三个**生成物**
* `--check` 只校验有没有漂移，不改文件（适合放进 CI / 提交前跑）

## 用法

```powershell
python scripts/sync_nlink_doc.py           # 生成
python scripts/sync_nlink_doc.py --check   # 只检查，有漂移则退出码 1
```

## 生成的 HTML 约定

站点页面是直接 innerHTML 注入的静态 HTML，所以：

* `# 标题` → `<h1>`（与 v1 / v2 等页面一致）
* `## 标题` → `<h2>`
* `### 标题` → `<h3>`
* 表格 → `<div class="table-wrap"><table>...`
* `:::callout 标题 / 正文 / :::` → `<div class="callout">` 结构
* 内联 `**粗体**` / `` `代码` `` → `<strong>` / `<code>`

**不再生成 `data-i18n` 属性**：站点按语言选择整份页面文件
（`PAGES_ZH` / `PAGES_EN`），页面内元素不需要再挂 key；
v1 / v2 页面也是这么写的。
"""
import argparse
import io
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent          # nfrp/
SRC = ROOT / "docs" / "nlink.md"
SRC_EN = ROOT / "docs" / "nlink.en.md"
ZH = ROOT / "docs" / "assets" / "pages.zh.js"
EN = ROOT / "docs" / "assets" / "pages.en.js"
MEM = ROOT / "memory" / "NLINK-V1-EVALUATION.md"

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


def md_to_html(md: str) -> str:
    """整篇 Markdown 转站点用的 HTML 片段。"""
    lines = md.split("\n")
    out: list[str] = []
    i = 0
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

        # 一级标题 -> 页面标题
        if s.startswith("# ") and not s.startswith("## "):
            out.append(f"<h1>{inline_html(s[2:].strip())}</h1>")
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
            out.append(f"<h3>{inline_html(s[4:])}</h3>")
            i += 1
            continue

        # 二级标题
        if s.startswith("## "):
            out.append(f"<h2>{inline_html(s[3:])}</h2>")
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
            if not lead_used:
                out.append(f'<p class="lead">{inline_html(text)}</p>')
                lead_used = True
            else:
                out.append(f"<p>{inline_html(text)}</p>")
            continue

        i += 1

    return "\n".join(out)


# --------------------------------------------------------------------------
# 生成物拼接
# --------------------------------------------------------------------------
def build_pages_block(html: str, var: str, source: str) -> str:
    """生成页面块。

    `var` 必须是目标文件里真实存在的对象名（`PAGES_ZH` / `PAGES_EN`）——
    写错不会立刻报错，而是让页面在浏览器里抛 ReferenceError 白屏。

    页面块是 **JS 模板字符串**，因此必须处理两个会让内容失真的字符：

    * 反斜杠：`FRP\\0\\x02\\r\\n` 这样的魔术字若原样写进模板字符串，
      JS 会把 `\\0` / `\\x02` / `\\r\\n` 当成转义序列，浏览器实际显示的是一串控制字符。
      所以先转义成 `\\\\`，让页面显示字面量。
    * 反引号与 `${`：直接终止模板字符串，属于语法错误，出现即拒绝生成。
    """
    if "`" in html:
        raise SystemExit("内容里出现反引号，会终止 JS 模板字符串，请改用其它写法")
    if "${" in html:
        raise SystemExit("内容里出现 ${，会当作模板插值，请改成其它写法")
    body = html.replace("\\", "\\\\")
    marker = f"<!-- BEGIN nlink (generated from {source}, do not edit) -->"
    return f"{marker}\n{var}['nlink'] = `\n{body}\n`;\n{END}"


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


MEM_HEADER = """# NLink v1 规范（本地记忆版）

> **这是生成物，不要直接编辑。**
>
> 内容源：`docs/nlink.md`
> 生成器：`scripts/sync_nlink_doc.py`
> 改完内容源后运行：`python scripts/sync_nlink_doc.py`
>
> 同一个内容源还会生成站点页面 `docs/assets/pages.zh.js` 里的 `PAGES_ZH['nlink']`，
> 英文页由 `docs/nlink.en.md` 生成；改一处、跑一次，全部同步。
>
> 这个文件放在 `memory/` 下，已被 `.gitignore` 的 `/memory` 屏蔽，**不会上传**。

---

"""


def replace_block(text: str, new_block: str) -> str:
    """替换两个标记之间的内容；没有标记就追加到末尾。

    起始标记里带内容源文件名，所以用正则匹配而不是精确比较 ——
    否则换了内容源文件名之后，旧块永远匹配不上，会在文件里堆叠两份页面。
    """
    m = re.search(re.escape("<!-- BEGIN nlink") + r".*?-->", text, re.S)
    if m and END in text:
        end = text.index(END) + len(END)
        if end > m.end():
            return text[: m.start()] + new_block + text[end:]
    return text.rstrip() + "\n\n" + new_block + "\n"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--check", action="store_true", help="只检查是否漂移，不写文件")
    args = ap.parse_args()

    if not SRC.is_file():
        print(f"中文内容源不存在：{SRC}")
        return 2
    if not SRC_EN.is_file():
        print(f"英文内容源不存在：{SRC_EN}")
        return 2

    md_zh = io.open(SRC, encoding="utf-8").read()
    md_en = io.open(SRC_EN, encoding="utf-8").read()
    html_zh = md_to_html(md_zh)
    html_en = md_to_html(md_en)
    mem_text = MEM_HEADER + strip_meta(md_zh)

    targets = [
        (ZH, build_pages_block(html_zh, "PAGES_ZH", "docs/nlink.md"), "docs/assets/pages.zh.js"),
        (EN, build_pages_block(html_en, "PAGES_EN", "docs/nlink.en.md"), "docs/assets/pages.en.js"),
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
