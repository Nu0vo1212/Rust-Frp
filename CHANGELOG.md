# Changelog

格式参考 [Keep a Changelog 1.1.0](https://keepachangelog.com/zh-CN/1.1.0/)，
版本号遵循 [Semantic Versioning](https://semver.org/lang/zh-CN/)。

> 本文件的条目只从 `git log` 中可核对的事实提炼（仓库内**不存在** `docs/fix-log.md`，
> 因此没有可对齐的旧编号）。每条列出问题、结论与回归测试名；找不到可命名的
> 测试时写「未标注」，不拿 e2e 名称去冒充单元测试。

## [Unreleased]

### Docs

- **Unreleased · 2026-11-21** —— 问题：README 里 pprof 被写成「Unix 有，Windows 501」，
  且 SSH 网关 e2e 的覆盖情况描述过期；结论：改为「仅 64 位 Unix 支持，Windows / Android /
  32 位 ARM / MIPS 一律 501」，并写明 tcpmux / stcp 数据面 e2e 自 0.7.8 起已覆盖；
  回归测试：未标注（纯文档）。提交 `3893553`。
- **Unreleased · 2026-11-21** —— 问题：README 暗示 0.7.8 / 0.7.10 已发布到 crates.io；
  结论：如实写明 crates.io 仍停在 0.7.7，0.7.8 与 0.7.10 只有 GitHub Release 包；
  回归测试：未标注（纯文档）。提交 `c2ee48e`。
- **Unreleased · 2026-11-21** —— 问题：OpenWrt 交付报告里「ring 不支持 MIPS」的旧结论
  仍然留着；结论：更正为 ring 不是阻塞、0.7.10 起正式出包；
  回归测试：未标注（报告文档 `run/OPENWRT-REPORT.md`）。提交 `44ca7af`。

## [0.7.10] - 2026-11-21

### Added

- **0.7.10 / 2026-11-21** —— 问题：Android 包一直靠本机手工打（`README-ANDROID.md`
  只躺在仓库外，CI 上 `pack_android.py` 直接 raise），且该文件内容还停在 0.5.5；
  结论：把 README 收进 `assets/`，给 `pack_android.py` 加 `--out` / `--no-sync-release`，
  由 `release.yml` 的 `build-android` 在 ubuntu-latest 上编 aarch64 与 x86_64 并产出
  `nfrp-android.zip`，checksums 与 cosign 自动覆盖；
  回归测试：未标注（CI 工作流）。提交 `1169cc0`。

### Changed

- **0.7.10 / 2026-11-21** —— 问题：32 位 MIPS 此前只验过 `-v`，属于「实验性 best effort」，
  不能算可交付；结论：在 qemu 里对 mipsel_24kc / mips_24kc 各跑一遍 nfrp-server +
  nfrp-client（token + `transport.tls.enable`），把本地 HTTP 经 remotePort 穿透并校验内容，
  MIPS 由此转为正式出包；CI cross-build 的 artifact 名也与 Release 包名对齐；
  回归测试：未标注（qemu 手工端到端穿透）。提交 `763a520`。
- **0.7.10 / 2026-11-21** —— 问题：`make_src_tarball.py` 只排除 `target`，交叉编译产生的
  `target-linux` / `target-cross` 会被打进源码包（曾到 209 MB）；
  结论：排除所有 `target*` 同级目录；
  回归测试：未标注。提交 `763a520`。

### Fixed

- **0.7.10 / 2026-11-21** —— 问题：CI 的 MIPS 断言要求静态链接，但 OpenWrt SDK 的 gcc
  默认产出 PIE 动态链接（interpreter 为 `/lib/ld-musl-<arch>-sf.so.1`），
  被误判成 ring 不支持；结论：断言放宽为「必须是 32 位 MIPS ELF，且静态或 interpreter
  指向 ld-musl」，并补 `STAGING_DIR`；
  回归测试：未标注（CI 断言）。提交 `525ba2b`。
- **0.7.10 / 2026-11-21** —— 问题：rootfs smoke 的两项 `frpc init` / `frps init` 恒报
  「缺少 respawn / stdout=logd / stderr=logd」，实际是 mock 环境没放 `/usr/bin/frpc|frps`，
  `start_service()` 在 `[ -x "$BIN" ]` 的第一道门就 return；结论：mock 前先放占位可执行文件；
  回归测试：`scripts/e2e_openwrt.py` 的 `frpc init: respawn/logd/reload`、
  `frps init: respawn/logd/reload`（解析逻辑由 `scripts/test_e2e_openwrt.py` 的
  `TestProcdLog` 覆盖）。提交 `2f0aa0f`。
- **0.7.10 / 2026-11-21** —— 问题：openwrt rootfs smoke 的 `run:` 续行 `\` 被 YAML 折叠成
  「转义空格」，argv 出现带前导空格的参数，argparse 报 `required: --bin-dir`；
  结论：两处改成 `|` 块标量；
  回归测试：未标注（CI 工作流）。提交 `b5a4fd6`。

### Removed

- **0.7.10 / 2026-11-21** —— 问题：误加的 `release-ghcr.yml` 与 `release.yml` 重复，
  打 tag 时会重复构建；结论：删除该工作流（362 行）；
  回归测试：未标注。提交 `e463dc1`。
