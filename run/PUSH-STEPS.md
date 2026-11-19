# 推送 / 发版记录（OpenWrt 分支）

> 本文档已从「待办清单」变成「已完成记录」。2026-11-19 22:55 实际发版 v0.7.8 之后重写。

---

## 一、当前状态：已发版

| 项 | 值 |
|---|---|
| 分支 | `feat/openwrt` |
| 分支 HEAD | `8d8aa5fa590e7c2532bea1f0cca954713857d000` |
| `main` | 已 fast-forward 到 `8d8aa5fa` |
| tag | `v0.7.8` → `8d8aa5fa` |
| 提交数 | 12（`0fcf2d0b` 之上） |
| 改动量 | 37 文件，+2328 / −342 |

提交链：

```
ad8f0d5 fix(ci): 修掉第二轮 CI 的三处失败（MIPS 原子 / Windows 501 / KCP 超时 / shellcheck）
9a58356 fix(ci): 修掉 armv7 / mips / rootfs-smoke 三处真实失败
7c2a50a release: 0.7.8 打包格式改连字符、不带版本号、Windows/Android 用 zip
338a46f docs(openwrt): 交付报告与推送步骤
ff2e032 fix(release): windows runner 上没有 python3 时回退 python
a51086c test(openwrt): 命名一致性门禁 + e2e 纯逻辑单测
41789f1 fix(openwrt): 包名统一下划线、撤掉 -latomic 误判、lock 去掉无关漂移
805ef78 ci: 接入 5 个 musl 目标与 OpenWrt rootfs 容器冒烟
e1568ba feat(openwrt): DISTRIB_ARCH 映射安装器与 rootfs 容器 e2e
ab84d3f feat(openwrt): procd 启动脚本与最小示例配置
962f85b feat(openwrt): pack 随 Linux 包附带 openwrt/ 目录与安装器
f2da193 feat(openwrt): 用 portable-atomic 垫片支持 32 位 MIPS 原子
```

---

## 二、推送是怎么做成的（下次复用）

`git push` 在这个环境里**走不通**，不是凭据问题：

- 本机全局 gitconfig 有 `url.https://ghfast.top/https://github.com/.insteadOf https://github.com/`
- 这个镜像对 fetch 好用，对 push 是要真认证的，镜像 host 上没有任何凭据 ⇒ `Authentication failed`
- 直连网络本身是通的（`git ls-remote https://github.com/...` 正常返回）
- 令牌本身也是好的：`GET /user` 返回 200，`POST /git/refs` 建探针分支返回 201

所以走 **GitHub REST API 的 Git Data 接口**建提交：

```bash
cd "E:/项目/RustFrp"
python tmp/push_fast.py --branch feat/openwrt --msg-file tmp/commit_msg_ci3.txt
```

它的工作方式（`tmp/push_fast.py`）：

1. 扫描工作区（跳过 `target/ dist/ .git/ memory/`、`*.pyc/.log/.bak/.exe`）
2. 取远端当前 HEAD 的 tree，**按 blob sha 比对，内容相同的直接复用**
3. 只把变化的文件 `POST /git/blobs`（16 线程并发）
4. `POST /git/trees`（带 `base_tree`）→ `POST /git/commits` → `PATCH /git/refs/heads/<branch>`

实测：159 个文件里只有 4 个真上传，其余 155 个复用，几秒完成。

**注意**：它建的是新 commit（sha 与本地不同，内容等同），不是把本地历史原样搬上去。
所以远端 commit sha 与本地 `ad8f0d5` 不一样，这是正常的。

本轮结果：远端 `8d8aa5fa`，新传 4 个 blob（`Cargo.toml`、`client/src/p2p.rs`、
`client/src/web.rs`、`scripts/install-openwrt.sh`）。

---

## 三、MIPS：走路线 A，不发包

结论是**不发 MIPS 生产包**，但也不砍代码、不关安全特性。

硬阻塞在 `ring 0.17.14`，是上游零支持，不是我们的 bug：

| 位置 | 事实 |
|---|---|
| `pregenerated/` 目录 | 只有 x86_64 / x86 / armv8 / armv4 / aarch64 的汇编，没有一条 mips |
| `build.rs` | 架构常量只定义了 `x86_64` / `aarch64` / `arm` |
| `include/ring-core/target.h` | mips 直接落到 `#error "Unknown target CPU"` |

而 ring 在本项目依赖树里是硬的（OIDC 验 RS256、rustls TLS、quinn QUIC、
rcgen 自签、russh SSH 网关）。换后端也不解：`aws-lc-rs` 只到 x86_64/aarch64，
openssl 要整棵 TLS 栈换掉，纯 Rust provider 还是 alpha。

所以 `build-mips` 保持 `continue-on-error: true` 的 best effort：
红了不拖垮 CI，也不产出包。发布包里没有 mips 是**预期结果**，不是漏了。

> 另一条路（路线 B）是用 `cfg(target_arch = "mips")` 把 TLS/QUIC/SSH/OIDC 全部门控掉，
> 做一个只支持明文 TCP + tcpMux 的精简版。约 40–60 处 cfg 加运行时报错桩，
> 本机无法验证（没有 mips 交叉工具链），只能靠 CI 一轮轮试。
> 这是**功能阉割版**，需要单独拍板，不在 v0.7.8 范围内。

---

## 四、发布包规格（v0.7.8 生效）

全连字符、全不带版本号：

| 平台 | 文件名 | 格式 |
|---|---|---|
| Windows x64 | `nfrp-windows-amd64.zip` | zip |
| Linux x64 | `nfrp-linux-amd64.tar.gz` | tar.gz |
| Linux arm64 | `nfrp-linux-arm64.tar.gz` | tar.gz |
| Linux armv7 硬浮点 | `nfrp-linux-arm-hf.tar.gz` | tar.gz |
| Android | `nfrp-android.zip` | zip |
| 源码 | `nfrp-src.tar.gz` | tar.gz |
| MIPS（best effort） | `nfrp-linux-mips(le).tar.gz` | tar.gz，本轮不产出 |

规则由 `scripts/check-openwrt-naming.py` 强约束，CI 里跑：

1. Linux 包不许用 zip
2. Windows / Android 必须 zip
3. Android 与源码包不许带版本号

包内结构：二进制改回官方风格名 `frps` / `frpc`，附示例配置、许可证、包内 README；
Linux 包额外带 `openwrt/` 目录与 `install-openwrt.sh`。

---

## 五、发版流程（已执行）

```bash
# 1. 推送分支（走 REST API，见第二节）
python tmp/push_fast.py --branch feat/openwrt --msg-file <msg>

# 2. 合并 main（fast-forward，0fcf2d0b 是 8d8aa5fa 的祖先，可直接 PATCH ref）
PATCH /repos/Nu0vo1212/Rust-Frp/git/refs/heads/main  {"sha":"8d8aa5fa...","force":false}

# 3. 打 tag 触发 release.yml
POST  /repos/Nu0vo1212/Rust-Frp/git/refs  {"ref":"refs/tags/v0.7.8","sha":"8d8aa5fa..."}

# 4. release.yml 自动跑：4 平台构建 → checksums + cosign keyless 签名 → 建 Release
# 5. 安卓包与源码包 workflow 里没有 job，必须本地出再上传
```

`release.yml` 的 `release` job 用 `files: out/*` 把所有 artifact 一次性传上去，
`fail_on_unmatched_files: false`，所以缺哪个平台不会炸整个 job。

---

## 六、不要做的事

- 不要让 `git push` 走 `ghfast.top` 镜像：那个 host 上没有凭据，一定失败。
- 不要 `git push --force` 到 `main`。
- 不要把 `dist/keys/`（私钥）提交或打进任何包。
- 不要为了让 MIPS 变绿去删 `continue-on-error`、也不要降级 TLS / 认证相关代码。
- 不要用 Python `read_text()` / `write_text()` 改仓库里的原有源码文件：
  这个仓库基线是 **CRLF**，那样会把整文件变成 LF（`scripts/release.py` 因此出现过
  1940 行 diff）。要改就字节级替换，或者改完 `git checkout --` 重来。
  本文件与 `OPENWRT-REPORT.md` 是新建的 LF 文件，不受此限。
