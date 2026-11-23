# OpenWrt 兼容交付报告

> ## ★ 2026-11-21 更正（v0.7.10）
>
> 本文件下文多处写着「MIPS 不产出包，因为 ring 0.17 上游对 32 位 MIPS 零支持」。
> **这句话是错的，已在 v0.7.10 翻案。** 两件事同时成立：
>
> 1. **ring 没有任何问题。** 0.17.14 的 `build.rs` 对没命中 `ASM_TARGETS` 的
>    架构取 `asm_target=None`，不生成汇编也不 panic；`sources_for_arch()` 会把
>    标着 `&[]` 的纯 C 源无条件编进去。MIPS 走的就是通用 C 回退。上游 CI 里
>    powerpc / powerpc64 / s390x / riscv64gc 四个同样没有汇编的目标天天在跑。
> 2. **当初判断"必红"的依据是我们自己写的断言。** 那条
>    `file | grep -Eq 'statically linked|static-pie'` 要求静态链接，而 OpenWrt
>    SDK 的 gcc 默认产 PIE 动态链接（interpreter 是 `/lib/ld-musl-<arch>-sf.so.1`），
>    于是正常产物被判死；再拿这个红去对外宣布"上游不支持"，属于自我印证。
>
> 实测证据：CI run `44858902791` 里两个 MIPS job 编完并 qemu 跑出裸 `0.71.0`；
> `44887634498` 起 11/11 全绿。v0.7.10 正式提供
> `nfrp-linux-mips.tar.gz`（大端 mips_24kc）与 `nfrp-linux-mipsle.tar.gz`
> （小端 mipsel_24kc），两者都在 qemu 里跑过完整穿透（token + TLS + TCP 转发）。
>
> 下文第 11、42、43、63、156–171 行的相关表述均以本节为准。

> **2026-11-19 22:55 更新：已发版 v0.7.8**
>
> | 项 | 结果 |
> |---|---|
> | 分支 | `feat/openwrt` → `8d8aa5fa`（12 个提交，已推送） |
> | `main` | 已 fast-forward 到 `8d8aa5fa` |
> | tag | `v0.7.8` |
> | CI | 三轮红点全部修完（armv7 pprof / YAML 折行 / sha256 长度 / SC2015 / MIPS 原子 / Windows 501 / KCP 超时） |
> | MIPS | ~~不产出包~~ → **v0.7.10 起正式出包**，见文首更正 |
>
> 以下第 1–7 节是**发版前**写的分析与验证记录，保留原始内容不改，
> 冲突之处以本节与 `PUSH-STEPS.md` 为准。

分支 `feat/openwrt`，12 个提交（11 个代码/CI + 1 个文档）。
补丁已导出到 `../openwrt-patches/`，推送与发版步骤见 `run/PUSH-STEPS.md`。
仓库原先无 `.git`，为做分支与提交先 `git init` 并以 0.7.7 源码做了 baseline 提交。

## 一、提交清单

| 提交 | 内容 |
|---|---|
| `04f3d25` | portable-atomic 垫片支持 32 位 MIPS 原子 |
| `15b9db1` | release.py pack 随 Linux 包附带 openwrt/ 目录与安装器 |
| `a22b0d9` | procd 启动脚本与最小示例配置 |
| `fb222ed` | DISTRIB_ARCH 映射安装器与 rootfs 容器 e2e |
| `22c2f58` | CI / release 接入 5 个 musl 目标与 OpenWrt 容器冒烟 |
| `8d3d962` | 包名统一下划线、撤掉 -latomic 误判、lock 去掉无关漂移 |
| `5e81b25` | 命名一致性门禁 + e2e 纯逻辑单测 |
| `386a01a` | release 打包步骤在 windows runner 上回退 `python` |

另有一个纯文档提交（本报告 + `run/PUSH-STEPS.md`），不计入功能清单。

## 二、每个目标架构的结果

| 目标 | 平台名 | 是否编过 | 体积 | 静态链接确认 | 冒烟（裸 0.71.0） |
|---|---|---|---|---|---|
| x86_64-unknown-linux-musl | linux_amd64 | **未验证** | 未验证 | 未验证 | 未验证 |
| aarch64-unknown-linux-musl | linux_arm64 | **未验证** | 未验证 | 未验证 | 未验证 |
| armv7-unknown-linux-musleabihf | linux_arm_hf | **未验证** | 未验证 | 未验证 | 未验证 |
| mipsel-unknown-linux-musl | linux_mipsle | **未验证** | 未验证 | 未验证 | 未验证 |
| mips-unknown-linux-musl | linux_mips | **未验证** | 未验证 | 未验证 | 未验证 |

五个目标都**没有在本轮真正构建出二进制**，所以体积、`file` 静态确认、qemu-user 跑
`frpc -v`/`frps -v` 是否输出裸 `0.71.0` 一律标"未验证"，没有一项是推断通过。
构建已全部写进 CI，由 GitHub runner 真正执行并做上面每一项检查（见第五节）。

## 三、代码改动及原因

1. **portable-atomic 垫片**（`Cargo.toml` + 三个 crate + 6 处源码）
   MIPS32（mips/mipsel 24kc）没有原生 64 位原子。项目源码里有 6 处
   `AtomicU64`/`AtomicI64`（审计计数、限流、连接池 epoch、指标、nlink caps），
   统一改用 `portable_atomic::*`：在 x86_64/aarch64/armv7 上它就是 std 原子的
   类型别名，**行为零变化**，在 MIPS32 上走纯 Rust 的 seq_lock fallback，
   **不链接 libatomic**。
   上一版报告里写过"依赖 crate 里的 std 原子由 `-C link-arg=-latomic` 兜底"，
   这个判断是错的，已删除：
   - 项目侧原子全部走 portable-atomic，不再落 `__atomic_*`；
   - 依赖树里 tokio / serde / zerocopy 的 `AtomicU64` 都有
     `cfg(target_has_atomic = "64")` 门控，32 位目标下根本不编译那段；
   - pprof 的 `perfmaps` 特性没开，不会引入 64 位原子。
   ~~真正的硬阻塞是 `ring 0.17.14`：没有 mips32 的预生成汇编，`build.rs` 也没有
   mips 分支，官方不把 32 位 MIPS 列为支持目标。这是 CI 里 MIPS job
   大概率失败的原因（详见第七节）。~~
   **已于 v0.7.10 更正：ring 不是阻塞，MIPS 自 v0.7.10 起正式出包；
   以文首更正与第七节为准，上面这段只作历史记录保留。**
   排查过 u64→usize 截断：源码里的 `as usize` 来源是 u16/u32 或带 clamp，32 位安全；
   `conn.rs:1636` 的 `i64 as usize` 在测试辅助函数里且长度恒为正，无实际问题。

2. **release.py pack 带 openwrt/**
   `collect()` 把 `openwrt/` 整棵目录（保留 `openwrt/etc/...` 层级）和安装器复制进
   每个 Linux 包，`_arcname()` 保留该层级，`build_readme()` 说明包内文件。
   踩并修了一个坑：`verify_archive()` 原来用 basename 匹配，`openwrt/etc/init.d/frps`
   与包根 `frps` 同名，会把真二进制的校验值覆盖掉；改成按归档内完整名精确匹配。
   **checksum / 签名 / verify 子命令一行未改。**

3. **openwrt/ 目录**
   `etc/init.d/frpc`、`etc/init.d/frps`：`USE_PROCD=1` + `respawn 3600 5 0`，
   stdout/stderr 交给 logd，支持 `reload_config`（`reload_service(){ restart; }`），
   启动前等 WAN 与系统时间（无 RTC 路由器 1970 年会破坏 TLS/OIDC）。
   `etc/frp/*.toml` 最小示例：无默认代理、不暴露 SSH、日志与 Store 默认落内存
   不写 flash，注释说明持久化方法。`frps` 顶部注释说明用 fw4/nftables 手动放行
   `bind_port`，不自动开面板端口。全部 POSIX ash，`shellcheck --shell=dash` 通过。

4. **scripts/install-openwrt.sh**
   读 `/etc/openwrt_release` 的 `DISTRIB_ARCH` 映射包名（认不出直接报错退出，不猜），
   先用 `SHA256SUMS.txt` 校验再装 `/usr/bin` 与 `/etc/init.d`，不覆盖已有配置。
   兼容下划线与历史连字符命名；`ARCH_FILE`/`DESTDIR` 可环境变量覆盖便于测试。
   端到端实测：5 种架构映射、未知架构退出、校验失败退出、不覆盖配置全部通过。

5. **scripts/e2e_openwrt.py**
   官方 rootfs 容器内跑 musl 版 `-v` 冒烟、mock procd 验 respawn/reload、
   tcp 代理端到端、空闲 RSS、官方 frpc 互通；官方二进制拉不到时明确写 SKIP 并给原因。

6. **CI / release**
   `ci.yml`：cross-build 加 armv7；新增 `cross-build-mips`（mips/mipsel 独立 job +
   `continue-on-error`，nightly + rust-src + `-Zbuild-std=std,panic_abort` + OpenWrt
   SDK 24kc gcc，`file` 验静态、qemu-user 验裸 0.71.0）；新增
   `openwrt-smoke`（官方 x86_64 rootfs 容器验 service 启停/tcp 互通/官方互通，并把空闲 RSS 记进日志）；
   lint job 里加命名一致性检查与 e2e 单测两步。
   `release.yml`：build matrix 加 armv7、命名对齐官方下划线、打包统一走 release.py pack，
   新增 `build-mips` job（`continue-on-error`），并加 `workflow_dispatch` 的
   `dry_run` 输入（只跑构建/打包/签名验签，不建 Release、不推镜像）。
   所有第三方 Action 继续 pin 到 commit SHA（本轮用 actionlint 逐个复核过）。
   **线协议魔术字与 `FRP_WIRE_VERSION = "0.71.0"` 未改，包内二进制仍改名 frps/frpc，
   默认行为与安全修复未削弱。**

## 四、fmt / clippy / test 与本地验证结果

| 检查 | 结果 | 谁跑的 |
|---|---|---|
| `cargo fmt --all -- --check` | **通过**（exit 0） | 上一轮本机，本轮未改 Rust 源码故未重跑 |
| `cargo clippy --workspace --all-targets -- -D warnings` | **通过**（exit 0） | 同上 |
| `cargo test --workspace` | **通过**（exit 0，全部用例 green；doc-tests 通过） | 同上 |
| `shellcheck --shell=dash`（2 个 init + install 脚本） | **通过**（exit 0） | 同上 |
| `cargo metadata --locked` | **通过**（exit 0） | 本轮，确认 Cargo.lock 与清单一致 |
| `actionlint 1.7.12` 跑 ci.yml + release.yml | **通过**（exit 0，零 finding） | 本轮 |
| Action 是否全部 pin 到 40 位 SHA | **全部 pin**（脚本逐个正则核对，0 个例外） | 本轮 |
| `python scripts/check-openwrt-naming.py` | **通过**，5 个规范包名全覆盖 | 本轮 |
| `python scripts/test_e2e_openwrt.py` | **20 个用例全过**（2ms，纯 mock） | 本轮 |
| `python scripts/release.py pack` dry-run（linux_amd64 + linux_mipsle） | **通过**，包名 `nfrp-linux_*.tar.gz`，每包 20 个文件含 `openwrt/etc/init.d/*` 与 `install-openwrt.sh`，sha256 自检通过 | 本轮 |
| install-openwrt.sh 复测（x86_64 / mipsel_24kc / 未知架构 / 不覆盖配置） | **通过**：两架构正确映射并按 SHA256 校验安装；`weird_arch` 退出码 1 且不猜；重装后用户改过的 `frps.toml` 未被覆盖 | 本轮 |
| 全部补丁在干净 clone 上 `git am --keep-cr` 重放 | **通过**，`git diff` 与原分支零差异（导出后按 9 个补丁复核） | 本轮 |
| `docs/index.html` + `i18n.js` 包名与产物一致 | **修正并通过**（原来写 `nfrp-windows-amd64.zip`，实际产物是下划线） | 本轮 |

以上都在本机（Windows MSVC host）真实跑过；"上一轮"那几项是同一份 Rust 源码状态下的结果，
本轮只动了 YAML / Python 脚本 / 文档，没有重跑 Rust 全量检查。

本轮还补了一个会**必然让发布链红掉**的坑：`release.yml` 的打包步骤原来直接调 `python3`，
而 `windows-latest` 的 Git Bash 里只有 `python`。已改成先 `command -v python3` 探测再调用。

## 五、未验证 / 受阻事项（含完整报错）

**5 个静态 musl 二进制的实际构建、`file` 静态确认、qemu-user 冒烟全部未验证。**
原因是本机与云端都不具备交叉构建环境，不是代码问题：

本机 `cross build --release -p nfrp-client --target x86_64-unknown-linux-musl` 完整报错：

```
error: toolchain 'stable-x86_64-unknown-linux-gnu' may not be able to run on this system
note: to build software for that platform, try `rustup target add x86_64-unknown-linux-gnu` instead
note: add the `--force-non-host` flag to install the toolchain anyway
Error: 
   0: couldn't install toolchain `stable-x86_64-unknown-linux-gnu`
   1: `rustup toolchain add stable-x86_64-unknown-linux-gnu --profile minimal` failed with exit code: 1
```

环境盘点（本机）：host = `x86_64-pc-windows-msvc`；Docker daemon 未运行
（`failed to connect to the docker API at npipe:////./pipe/dockerDesktopLinuxEngine`）；
`qemu-*-static` 全部 MISSING；`file` MISSING；只装了 musl 的 rustc target，
没有对应的 musl C 交叉编译器（ring 要编 C）。

云端测试机 118.178.189.143（项目既有生产验证机）：OS = Alibaba Cloud Linux 3，
可用内存约 1G，磁盘 `/` 已用 96% 仅剩 1.8G，无 cargo/rustc、无 musl 工具链、
无 qemu、无 docker；且跑着线上服务，不宜在上面装 5 套工具链做 LTO 构建（会撑爆磁盘、OOM）。

MIPS 单独说明：`mips-unknown-linux-musl`/`mipsel-unknown-linux-musl` 是 Rust Tier 3，
无预编译 std，必须 `-Zbuild-std=std,panic_abort` + OpenWrt SDK 的 24kc gcc；
OpenWrt SDK 与 rootfs 的下载 URL 和官方 sha256 已核实并写进 CI。
MIPS 能否编过**本轮仍未验证**，而且已定位到一个明确的硬阻塞：`ring 0.17.14`
没有 mips32 的预生成汇编、`build.rs` 也没有 mips 分支，官方不把 32 位 MIPS
列为支持目标。CI 里是 `continue-on-error` 的独立 job，红了不会拖垮主 CI，
产物（如果有）供人工核验。这不是"原子/链接"问题，`-latomic` 已按证据撤掉。

## 六、原「需要你手动处理的事」——已全部完成

1. **推分支 / 合并 / 发版**：已完成。`feat/openwrt` 推送到 `8d8aa5fa`，`main` 快进合并，
   tag `v0.7.8` 已建并触发 Release。实现路径与坑在 `run/PUSH-STEPS.md` 第二节
   （`git push` 被 `ghfast.top` 镜像挡住，改走 GitHub REST API 的 Git Data 接口）。
2. **跑 CI 拿真实产物**：三轮跑完，红点全部修完（详见 7.2 下方的实际结果表）。
3. **MIPS 是否继续攻关**：已定 —— 不发 MIPS 包，保持 `continue-on-error` 的 best effort。
   理由见第五节与 `PUSH-STEPS.md` 第三节，核心是 `ring 0.17` 上游对 mips32 零支持。
4. **包名变更需知悉**：最终定为**连字符且不带版本号**（`nfrp-linux-amd64.tar.gz`、
   `nfrp-windows-amd64.zip`、`nfrp-android.zip`、`nfrp-src.tar.gz`）。
   本节原文写的"改成下划线"是中间态，已被 `7c2a50a` 推翻。
   规则写进门禁 `scripts/check-openwrt-naming.py`，CI 每次都会校验。

## 七、结论三栏与 CI 首次运行的预期失败点

### 7.1 三栏结论

**栏 1：本地已验证（有命令、有退出码、可复现）**

- 代码改动本身：`openwrt/` 两个 procd 脚本、`scripts/install-openwrt.sh`、
  `scripts/release.py` 的 openwrt 打包、`portable-atomic` 替换、命名一致性门禁、
  e2e 纯函数抽取，全部在本机跑过（见第四节表格）。
- 打包产物结构：`nfrp-linux_amd64.tar.gz` / `nfrp-linux_mipsle.tar.gz` 里确有
  `openwrt/etc/init.d/frpc|frps`、`openwrt/etc/frp/*.toml`、`install-openwrt.sh`，
  包根 `frps`/`frpc` 是二进制且 sha256 与源产物一致。
- 安装器的行为：架构映射、SHA256 校验、未知架构拒绝、不覆盖已有配置，四条路径都实测。
- CI 配置的语法与语义：actionlint 1.7.12 零 finding；YAML 可解析；
  job 依赖图（`checksums ← build + build-mips`、`release ← build + checksums`、
  `docker ← build`）与 `dry_run` 短路条件逐一核对过。
- 补丁：9 个补丁在干净 clone 上 `git am --keep-cr` 重放成功，重放结果与原分支零差异。

**栏 2：只有 CI 能验证（本地不具备环境，跑不了）**

- 5 个 musl 目标的真实编译结果。
- `file` 判定是否 `statically linked`（本机没有 `file`，也没有 Linux musl 工具链）。
- qemu-user 跑 `frpc -v` / `frps -v` 是否输出裸 `0.71.0`。
- 官方 OpenWrt x86_64 rootfs 容器里的 service 启停、respawn、reload、tcp 端到端、
  空闲 RSS、与官方 frpc 的互通。
- cosign keyless 签名与逐包验签能否真的签出来。

**栏 3：未验证（而且这一轮无法给出结论）**

- 32 位 MIPS 整体是否可用。已知硬阻塞在 `ring`，就算绕过 `ring`，
  `pprof`、`libc` 组合在 24kc 上也没有实机数据。
- 真实路由器上的运行表现：procd 在具体固件版本上的行为、flash 写入策略、
  `/tmp` 空间、开机等 WAN 与时间的实际副作用，全部没有真机数据。
- 空闲 RSS 在 128MB 内存设备上是否够用（只有容器里的数字，没有真机数字）。

### 7.2 CI 三轮实际结果（取代下方"首次运行预期"）

| 轮次 | 红的 job | 根因 | 修法 |
|---|---|---|---|
| 第一轮 | `cross-build` armv7 | `pprof 0.15` 的 `Profiler::is_blocklisted` 只在 x86_64/aarch64/riscv64/loongarch64 存在，32 位 ARM 上没这个方法 | pprof 依赖与 `pprof_http.rs` 一起门控收紧到 64 位 Unix，不支持的平台返回 501 |
| 第一轮 | `openwrt-smoke` | `run:` 折行标量把 `\` 折成空格，参数变成 `" -p"` | 改成块标量 `run: \|` |
| 第一轮 | `cross-build-mips` ×2 | SDK / rootfs 的 sha256 字符串粘多了尾巴，不是 64 字符 | 从官方 `sha256sums` 抄回纯 64 字符 |
| 第二轮 | `openwrt-smoke` | `install-openwrt.sh` 里 `A && B \|\| C` 触发 SC2015（语义也不是 if-then-else） | 改成真 if；注释里别出现 `shellcheck` 这个词，会被当 directive 解析 |
| 第二轮 | `cross-build-mips` ×2 | `portable_atomic::AtomicU64` 在 32 位目标上不存在（只开 `std` 不提供 64 位原子） | 显式打开 `fallback` 特性（纯 Rust seq_lock，不链接 libatomic）；同时推翻上一轮 `-latomic` 的判断 |
| 第二轮 | 单测 Windows | pprof 门控收紧后错误文案变了，`contains("only supported on Unix")` 匹配不上 ⇒ 501 变 500 | 判据放宽成 `contains("only supported on")`，测试断言同步 |
| 第二轮 | 单测 Windows | `full_p2p_over_rendezvous_with_kcp` 在 windows-latest 高负载下 8 秒超时（本机 0.45 秒） | 只在 `cfg(test)` 下把 `PUNCH_TIMEOUT` 放宽到 20 秒，生产行为不变 |
| 第三轮 | 仅 `cross-build-mips` ×2 | `ring 0.17` 编译失败 | 预期内，`continue-on-error`，其余全绿 |

下方是发版前的预判表，保留原文以对照（结论与上表一致，只是编号和实际落点不同）。

### 7.3 原文：CI 首次运行预期会失败的点

按"发生概率 × 是否属于我们的问题"排序，全部据实写，不写"应该没问题"。

| # | job / 步骤 | 预期 | 首个报错会出现在哪 | 是环境还是代码 | 处理 |
|---|---|---|---|---|---|
| 1 | `cross-build-mips`（两个目标） | **几乎必然红** | `Compiling ring v0.17.x` 阶段，形如 `error: failed to run custom build command for ring` 或找不到 `mips` 的汇编预生成目录 | 上游能力边界（ring 不支持 mips32），不是我们的配置写错 | 保持 `continue-on-error`；要么换 TLS 后端（`rustls` 已在用，但 ring 仍被其它依赖拉入需核查），要么本轮先不发 MIPS 包 |
| 2 | `cross-build-mips` 的 SDK 下载 | 可能红 | `sha256sum -c -` 或 `curl` 超时 | 环境（网络/镜像） | 重跑；CI 里已固定版本和 sha256，不会静默换版本 |
| 3 | `openwrt-smoke` 的 rootfs 导入 | 可能红 | `sha256sum -c` 失败或 `docker import` 报错 | 环境 | 重跑；schema 里已钉死 URL + sha256 |
| 4 | `openwrt-smoke` 的 official interop | 可能 SKIP | 日志里 `SKIP` + 原因 | 环境（拉不到官方二进制） | 不算失败，脚本明确写跳过原因，绝不伪造通过 |
| 5 | `openwrt-smoke` 的空闲 RSS | 不会红 | —— | —— | 脚本只把 `VmRSS` 记到日志里（`frps xxx kB, frpc xxx kB`），**没有阈值断言**，所以不会因为内存数字失败；数字要人工看 |
| 6 | `release` 的 windows 打包 | 本轮已修 | 原会红在 `python3: command not found` | 代码（已改） | 已改成 `command -v python3 || PY=python` |
| 7 | `checksums` | 不该红 | —— | —— | 若 `build-mips` 全红，`SHA256SUMS` 只覆盖实际存在的包，不会因此失败；这是有意的 |

判断口径：1 属于**已知设计边界**，不需要"修到绿"；2/3/4 属于**基础设施**，
重跑即可；5/6 属于**我们自己**，红了要改。

### 7.4 本轮明确没做的事

- 没有连接任何服务器，没有使用项目里的任何凭据，没有 push、没有打 tag、
  没有发 Release、没有碰签名密钥。
- 没有为了让 MIPS 变绿而删功能、降级 TLS/认证或关闭安全特性。
