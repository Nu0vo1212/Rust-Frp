# 质量保障与安全门

> 这份文件收纳 README 里放不下的质量细节。README 只留一句话概述 + 指向这里。
>
> 对应版本：**v0.7.4** · 最后核对：2026-11-03

---

## 一、本地三道门

提交前依次跑：

```bash
cargo fmt --all -- --check                 # 格式
cargo clippy --workspace --all-targets -- -D warnings   # 静态检查，当前 0 告警
cargo test --workspace                     # 999 个测试通过
```

三项全绿才算过。CI 上跑的是同一组命令，参数一致，不存在"本地过了 CI 不过"。

---

## 二、测试分布（v0.7.6 实测）

`cargo test --workspace` 实测输出：

| 目标 | 通过 | 忽略 |
|---|---|---|
| `nfrp-client` 单元测试 | 141 |  |
| `nfrp-client` 开机自启端到端（真进程） | 2 |  |
| `nfrp-common` 单元测试（lib） | 502 | 3（Wintun 真机） |
| `nfrp-common` 集成测试（OIDC） | 9 |  |
| `nfrp-server` 单元测试（lib） | 293 |  |
| `nfrp-server` 单元测试（bin） | 17 |  |
| `nfrp-server` 端到端集成测试 | 26 |  |
| `nfrp-server` NLink 端到端 | 16 |  |
| 文档测试（common） | 2 | 5 |
| 文档测试（server） | 0 | 5 |
| **合计** | **1008** | **13** |

**关于 13 条 `#[ignore]`**：3 条是**需要真机硬件或管理员权限**的 Windows Wintun
设备面测试，另外 10 条是文档示例里明确标注 `ignore` 的代码块（不是失败/被跳过
的问题测试）。Wintun 真机测试在有权限的环境里可以用 `cargo test -- --ignored`
单独跑。

**数字对不上时以 `cargo test` 输出为准** —— 这张表是人手抄的，会漂移。

---

## 三、测试覆盖了什么

不只是单元测试，以下几类是有实际抓包/真栈参与的：

| 类型 | 说明 |
|---|---|
| 真实 QUIC 栈握手 | 起真 `quinn` endpoint，不是 mock |
| 端到端集成 | 真 frps + 真 frpc + 真内网回显服务 |
| 官方密文解密回归 | 用官方 frpc/frps 真实抓下来的密文做解密断言 |
| NLink 逐项覆盖 | `server/tests/nlink_e2e.rs` 的 16 条用例一一对应 8 项能力 |
| 打包产物核对 | 包内二进制与源产物逐个 sha256 比对 |

---

## 三之二、值得记住的修复

有些缺陷不值得单独写一篇文档，但"为什么代码长成这样"必须留个记号，
否则将来有人会"顺手简化"掉关键的几行。

| 版本 | 缺陷 | 关键点 |
|---|---|---|
| **0.7.4** | 限流转发在半关闭后不释放工作连接 | `relay_throttled` 原先用 `try_join!` 等两个方向都结束。客户端只关一个方向时，另一侧的 `read()` 一直挂着，`try_join!` 永不返回 ⇒ 工作连接与 fd 泄漏。修法：`copy_throttled` 读到 EOF 后**主动 shutdown 写端**，对端收到 FIN 也会读到 EOF。测试 `限流转发在半关闭后必须返回释放连接`，用 `timeout` 包住，回归时 2 秒失败而不是挂死 |
| **0.7.4** | `ResumeCommit` 分片上限按"片数"限不合理 | 0.7.2 写死"最多 64 片"（≈512 KiB）。改成按**字节预算**（8 MiB），片数由预算推出。额外加了一道"累计字节"检查——片数合法但每片塞满时仍可能超预算 |
| **0.7.4** | HTTP vhost CONNECT 的早期数据被丢掉 | 客户端没等 200 就把隧道数据发来时，`read_head` 已把字节预读进 `HttpIo` 缓冲；随后直接对底层流做 `relay_between` 会跳过缓冲。修法：CONNECT 分支先 `take_buffered()` 补写上游，再用 `PrefixedStream` 把工作连接预读字节补回下游。带正 `Content-Length` 或 `Transfer-Encoding` 的 CONNECT 按官方口径回 400 |
| **0.7.4** | VNet 重连后旧地址/旧路由残留，连续失败重试无上限 | `ip addr replace` / `New-NetIPAddress` 换 IP 时会留下旧地址和旧直连路由；改为显式删除旧地址。连续失败改为指数退避并封顶 300 秒，同时把超大失败计数限制在安全移位范围内，避免溢出成 0 后疯狂重试；并为每次登记分配代次，旧 `JoinGuard` 晚到的 Drop 只能跳过，不能删新连接的路由 |
| **0.7.3** | NatHole 的六个 mode 分支只测了一个 | 补 `mode_选择的六个分支与官方一致`，把六种 `(easy, hard, regular)` 组合的首选 mode 全钉死。之前只测 `easy==2` 那一支，其余写错不会被发现 |
| **0.7.2** | 续传是 bearer 会话（`user + client_id + session_id`） | 三个值都是**标识**不是凭证。加一次性令牌（HMAC 绑定四项 + 用一次就作废）。但明文链路上仍可被抢先消费——`transport.tls.force = true` 才是根治 |
| **0.7.2** | `ResumeCommit` 超 8 KiB 静默降级 | 名单装不下时客户端只能拒发，对账能力退化成 10 秒宽限期。改自动分片，单帧时线上格式不变 |
| **0.7.1** | 续传只恢复"名单"，没恢复监听器 | 之前续传回 `ok=1` 但端口没保留，等于重连。改成保留同一份 `ClientState`（监听器 / 端口 / vhost / visitor 全在） |
| **0.7.0** | HTTP 插件在 Linux 上偶发挂起 | `HttpIo::fill()` 改用 `read_buf` 直接写自有缓冲——`select!` 取消 future 时，局部数组里的字节会跟着消失 |

---

## 四、CI

`.github/workflows/ci.yml` 在每次 push / PR 上跑：

1. `fmt --check` + `clippy -D warnings`
2. Linux / Windows / macOS 三系统全量测试
3. 两个 musl 目标的交叉构建
4. 端到端冒烟

**第三方 GitHub Action 全部 pin 到 commit SHA**（不用浮动 tag，避免上游被投毒）。
cosign 签名失败即红灯，不会"警告后继续"。

---

## 五、依赖安全：做到哪一步，把措辞说准

这一节刻意写得很啰嗦，因为这类描述最容易被读成比实际更强的承诺。

| 工具 | 实际管什么 | 当前状态 |
|---|---|---|
| `cargo audit` | 与**已公开的 RUSTSEC 公告**做比对 | 0 命中（330 个依赖） |
| `cargo deny` | 许可证、来源、重复依赖 | 通过 |
| `cargo vet` | 人工审计记录 | **只有 184 条 exemption** |

**关键澄清**：`cargo vet` 的 184 条 exemption 的意思是「**暂时接受、未经人工审计**」，
**不等于"依赖经过人工审计"**。本仓库任何地方都不该被读成后者。

`cargo audit` 0 命中也不等于"没有漏洞"——它只能发现**已经公开并收录**的公告。

---

## 六、发布产物校验

每次发版必须过这几道：

```bash
# 打三平台包（包内统一命名 frps / frpc，附示例配置与 README）
# `@release` = `cargo metadata` 认定的 target_directory + /release，
# 不要写死 `target/release`：本机构建目录可能被挪到别的盘。
python scripts/release.py pack \
  --target windows-amd64:@release \
  --target linux-amd64:/path/to/amd64 \
  --target linux-arm64:/path/to/arm64 \
  --out dist/release

# 源码包（可复现：同一个树打两次字节一致，脚本自己验）
python scripts/make_src_tarball.py

# 生成校验和 + Ed25519 分离签名
python scripts/release.py checksum --dir dist/release --sign \
    --key dist/keys/release.key --pub dist/keys/release.pub

# 本地验签 + 校验
python scripts/release.py verify --dir dist/release

# 发版闸门：本地 dist/release 与 GitHub Release 资产一一对应
python scripts/verify_dist_matches_release.py --check-android
```

`pack` 打完包会**自动解包自检**：包内 `frps` / `frpc` 与源产物逐个 sha256 比对，
不一致直接非零退出。最后那道闸门核对**资产名称 + sha256 全部一致**，任何一侧
多了少了都会红。

`release.py` 不依赖第三方 Python 包，也不依赖 Rust 工具链。签名缺失或失败会
**非零退出**；确实要发未签名制品需显式加 `--allow-unsigned`。

### 签名密钥

Ed25519，公钥指纹 `763896b5d759c6cbe1f208c3c35c9f71`，历次发布用同一把，可以连续验签。

### 跨平台构建要点

**Linux amd64**：在 Linux 机器上原生 `cargo build --release`，产物是 glibc 动态链接。

**Linux arm64**：用 `aarch64-linux-gnu-gcc` 交叉编译，并加
`RUSTFLAGS="-C target-feature=+crt-static"` 得到全静态、无 glibc 依赖的二进制。
`ring` 需要 C 工具链，交叉时**必须**同时指明两个变量：

```bash
export CC_aarch64_unknown_linux_gnu=aarch64-linux-gnu-gcc
export CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER=aarch64-linux-gnu-gcc
```

> 漏掉 `CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER` 会退到主机链接器，
> 报 `rust-lld: error: --fix-cortex-a53-843419 is only supported on AArch64` ——
> 这个报错看着像架构问题，实际是链接器选错了。

**内存**：fat LTO（`lto=true, codegen-units=1`）的单次链接峰值约 1.34 GB。
在 1.8 GB 内存的机器上会被 OOM 杀掉（`signal: 9, SIGKILL`），`-j 1` 也救不了
——因为它是**单次链接**就要这么多，不是并发导致的。两种情况下的对策：
机器内存 ≥ 2.5 GB 用默认 fat LTO；不够就设 `CARGO_PROFILE_RELEASE_LTO=thin`
（产物约大 20%，功能一致）。

**Android**：先编出两个 target，再交给 `pack_android.py`：

```bash
NDK=/path/to/android-ndk
BIN=$NDK/toolchains/llvm/prebuilt/linux-x86_64/bin   # Windows 上是 windows-x86_64
export CC_aarch64_linux_android=$BIN/aarch64-linux-android26-clang
export AR_aarch64_linux_android=$BIN/llvm-ar
export CARGO_TARGET_AARCH64_LINUX_ANDROID_LINKER=$CC_aarch64_linux_android
export CC_x86_64_linux_android=$BIN/x86_64-linux-android26-clang
export AR_x86_64_linux_android=$BIN/llvm-ar
export CARGO_TARGET_X86_64_LINUX_ANDROID_LINKER=$CC_x86_64_linux_android

cargo build --release --target aarch64-linux-android -p nfrp-server -p nfrp-client
cargo build --release --target x86_64-linux-android  -p nfrp-server -p nfrp-client
python scripts/pack_android.py
```

包名里的 `26` 是 `minSdk 26`；用别的 API 级别就把文件名后缀一起改掉。

### 为什么这些闸门是必须的

历史上有过两次真实事故：

- **v0.5.6 安卓包**打进了上一版的二进制；
- **8.0 MB 异常包**（正常 4 MB 左右，多出的是没被清掉的调试产物）。

两次都是"包名和版本号都对，但里面的东西不对"。所以现在的原则是：
**不信任文件名和 Cargo.toml 里的版本号，只信任二进制本身**。

---

## 七、发版前的人工核对清单

脚本能查的都查了，剩下这几条得人来看：

- [ ] `cargo test --workspace` 全绿，失败数为 0
- [ ] `cargo clippy --workspace --all-targets -- -D warnings` 0 告警
- [ ] 每个包里的二进制版本串与本次发版号一致（Windows 包直接跑 `-V` 验证）
- [ ] 发版闸门 `verify_dist_matches_release.py` 输出"完全一致"
- [ ] README 的版本徽章、文档站版本号、`Cargo.toml` 三处已同步
- [ ] Release 说明里如实写了没做的事（不为了清单好看去勾）
