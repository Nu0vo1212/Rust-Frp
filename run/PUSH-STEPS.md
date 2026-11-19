# 推送 / 发版准备（OpenWrt 分支）

分支 `feat/openwrt`，9 个提交，**全部在本地，没有 remote，没有 tag，没有 Release**。
补丁已导出到 `../openwrt-patches/`（9 个 `.patch`）。
本文件只写"你要做什么"，以及每一步的验收标准；不写"应该没问题"。

---

## 0. 先确认两件事实

### 0.1 CRLF：这个仓库的提交内容是 CRLF 行尾

```
$ git show HEAD:scripts/release.py | grep -c $'\r'
970
```

不是某一个文件，`Cargo.toml`、`README.md`、`openwrt/etc/init.d/frpc`、
`server/src/pool.rs` 全都是 CRLF。原因是 baseline 快照本身就是从 Windows 目录建的仓。

后果只有一个，但很关键：**`git am` 必须加 `--keep-cr`**，否则 mailinfo 会把补丁
里的 CR 去掉，上下文立刻和 CRLF 文件对不上，报 `patch does not apply`。
（这是实测出来的：不加 `--keep-cr` 在第 2 个补丁就停，加了 `--keep-cr` 之后 9 个全过，
重放出来的树与 `feat/openwrt` **零差异**。）

如果你打算推到**一个已经存在、且原本是 LF 行尾的上游仓库**（不是自己新建的空仓库），
别直接 `git am --keep-cr` 把 CRLF 灌进去 —— 那会让每个文件都变成"整文件重写"。
这种情况先做行尾归一：见第 3 节的可选步骤。

### 0.2 补丁重放已验证

在干净的 clone 上从 baseline 重放全部 9 个补丁：

```
$ git checkout -B t 89f4526
$ git am --keep-cr ../openwrt-patches/*.patch
Applying: feat(openwrt): 用 portable-atomic 垫片支持 32 位 MIPS 原子
...
Applying: docs(openwrt): 交付报告与推送步骤
$ git diff --stat t origin/feat/openwrt
（无输出）
```

`git diff` 空输出 = 补丁能完整还原分支，不缺文件、不改内容。

---

## 1. 方式 A：自己新建的空仓库 → 直接推分支

```bash
cd "E:/项目/RustFrp/nfrp"
git remote add origin git@github.com:<你的账号>/<仓库名>.git
git push -u origin main          # baseline 快照
git push -u origin feat/openwrt  # 9 个提交
```

验收：GitHub 上 `feat/openwrt` 有 9 个提交，`main` 只有 baseline 一个。
推完直接看 Actions —— 见第 4 节的预期。

## 2. 方式 B：目标仓库已有历史 → 用补丁重放

不要 `git push` 本地分支（baseline 和目标仓库没有共同祖先，推不上去也没意义）。

```bash
# 在目标仓库的干净工作区里，从你想落地的提交开分支
git switch -c feat/openwrt-upstream <目标基线>
git am --keep-cr /path/to/openwrt-patches/*.patch
```

- 有冲突时：`git am --show-current-patch=diff` 看当前补丁，
  改完 `git add` + `git am --continue`；想放弃整串就 `git am --abort`。
- 验收：`git log --oneline` 有 9 条，`git diff --stat <目标基线>` 只应出现
  `Cargo.toml`、`Cargo.lock`、三个 crate 的清单与 6 个源码文件、
  `.github/workflows/{ci,release}.yml`、`scripts/*`、`openwrt/*`、
  `docs/*`、`QUALITY.md`、`run/*` 这些路径。

## 3. 可选：把行尾归一成 LF（仅当目标仓库原本是 LF）

```bash
# 一次性，别和功能改动混在一起
printf '* text=auto eol=lf\n' > .gitattributes
git add .gitattributes
git commit -m "chore: .gitattributes 统一 LF 行尾"
git add --renormalize .
git commit -m "chore: 归一为 LF（仅行尾，无内容变更）"
git diff --stat HEAD~1 HEAD | tail -1   # 只应是行尾变更
```

之后再推/重放补丁，`git am` 就**不再需要** `--keep-cr`。
注意：`add --renormalize` 只改索引里的行尾，二进制文件（`*.png`、`*.exe`、
`*.db`）靠 `text=auto` 自动跳过，但提交前仍要看一眼 `git diff --stat` 有没有
体积异常的文件。

---

## 4. 推上去之后先看什么

预期结果（详细依据见 `run/OPENWRT-REPORT.md` 第七节）：

| job | 预期 | 说明 |
|---|---|---|
| `lint`（fmt / clippy / 命名检查 / e2e 单测） | 应全绿 | 命名检查与单测都在本机跑过，20 个用例全过 |
| `test` | 应全绿 | 本机 `cargo test --workspace` 通过 |
| `cross-build` amd64 / arm64 / arm_hf | 应全绿 | musl 静态交叉，cross 镜像自带工具链 |
| `cross-build-mips`（2 个目标） | **大概率红** | 硬阻塞是 `ring 0.17` 没有 mips32 汇编；`continue-on-error`，不影响主 CI |
| `openwrt-smoke` | 应全绿 | 官方 x86_64 rootfs 容器 + mock procd + tcp 互通 |
| `openwrt-smoke` 里 "official frpc interop" 那一步 | 可能 SKIP | 拉不到官方二进制时脚本明确写 SKIP 并给原因，不算失败 |

判断红的是"环境问题"还是"我们的问题"：

- MIPS job 红在 `Compiling ring` / `custom build command for ring`：属于已知阻塞
  （ring 0.17 没有 mips32 汇编，官方不支持 32 位 MIPS），见报告第七节，不用改代码。
- `openwrt-smoke` 红在 `docker import` / 下载 rootfs 404：CI 网络问题，重跑。
- `lint` 红：先在本机复现同一条命令（`cargo fmt --all -- --check`、
  `cargo clippy --workspace --all-targets -- -D warnings`、
  `python scripts/check-openwrt-naming.py`、`python scripts/test_e2e_openwrt.py`）。

## 5. 发布前先跑 dry run

`release.yml` 加了一个 `dry_run` 输入，这是唯一能验证整条发布链而不产出发布物的方式：

Actions → Release → Run workflow →
`tag` 填目标版本（如 `v0.7.8`），`dry_run` 勾上 → Run。

它会跑完 `build`（4 个平台）、`build-mips`（保持 best effort）、`checksums`
（生成 SHA256SUMS、cosign 真签、逐包验签），然后**跳过** `release` 与 `docker`
两个 job：不建 Release、不推 `ghcr.io`。

验收：`checksums` job 日志里能看到 `全部签名验证通过`。
dry run 都红的话，真发版一定也红，先在 dry run 上把问题解决。

## 6. 真发版

```bash
git tag v0.7.8
git push origin v0.7.8
```

必须知道的后果：

- **MIPS 两个包可能不存在**。`build-mips` 是 best effort，红了就只有
  amd64 / arm64 / arm_hf / windows 四个包，`SHA256SUMS.txt` 也只覆盖这四个。
  这是有意的：不为了凑数量去关安全特性或删代码。
- 包名已从连字符改成下划线（`nfrp-linux_amd64.tar.gz`）。安装器两种都认，
  但如果你别处有按旧名硬编码的下载脚本，要同步改。
- 签名密钥不在仓库里、也不在补丁里。`release.py checksum --sign` 需要
  `dist/keys/release.key`，发版前确认本机有；没有就走 gpg 回退。

## 7. 不要做的事

- 不要 `git push --force` 到 `main`：baseline 是唯一的历史根，强推会丢它。
- 不要把 `dist/keys/`（私钥）提交或打进任何包。
- 不要为了"让 MIPS 变绿"去删 `continue-on-error` 或降级 TLS/认证相关代码。
  红了就红了，报告里写清楚了它是实验性的。
