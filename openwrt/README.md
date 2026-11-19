# NFrp on OpenWrt

走"预编译静态 musl 二进制 + procd 启动脚本"路线 不做 ipk / apk 包

## 支持架构与包名

| OpenWrt `DISTRIB_ARCH` | 发布包 | rustc target |
|---|---|---|
| `aarch64_*` | `nfrp-linux-arm64.tar.gz` | aarch64-unknown-linux-musl |
| `arm_cortex-a*` 带 vfp / neon | `nfrp-linux-arm-hf.tar.gz` | armv7-unknown-linux-musleabihf |
| `x86_64` | `nfrp-linux-amd64.tar.gz` | x86_64-unknown-linux-musl |
| `mipsel_24kc` | `nfrp-linux-mipsle.tar.gz` | mipsel-unknown-linux-musl |
| `mips_24kc` | `nfrp-linux-mips.tar.gz` | mips-unknown-linux-musl |

## 安装

把 `SHA256SUMS.txt` 和对应平台的 tar.gz 放在同一目录 然后在路由器上

```sh
sh install-openwrt.sh /path/to/dist
```

安装器做三件事 认不出架构会直接报错退出 不会猜

1. 读 `/etc/openwrt_release` 的 `DISTRIB_ARCH` 选包
2. 用 `SHA256SUMS.txt` 校验包的 sha256 不匹配就拒绝
3. 装 `/usr/bin/frpc` `/usr/bin/frps` 与 `/etc/init.d` 脚本 示例配置只在不存在时落盘

包名不带版本号 全部用连字符。v0.7.7 之前有一版试过下划线（如 `nfrp-linux_amd64.tar.gz`）
安装器也认 优先连字符

## 启用

```sh
/etc/init.d/frpc enable
/etc/init.d/frpc start
# 服务端同理 /etc/init.d/frps
```

改完配置用 `/etc/init.d/frpc reload`（走 `reload_config`）或直接 `restart`

## 目录说明

- `etc/init.d/frpc` `etc/init.d/frps`：procd 脚本 `USE_PROCD=1` + respawn 日志交给 logd
  启动前等 WAN 与系统时间就绪（路由器无 RTC 1970 年时间会破坏 TLS / OIDC）
- `etc/frp/frpc.toml` `etc/frp/frps.toml`：最小示例 不含任何默认代理 不暴露 SSH

## 几个刻意的设计

- **日志和 Store 默认不写 flash**：不配 `[log].to` 时日志走标准输出由 logd 存内存
  用 `logread -e frpc` 查看；动态代理的 `[store]` 默认不落盘。想持久化请指向
  U 盘等可写介质 并自行承担 flash 寿命代价（示例配置里有注释）
- **不自动开放防火墙**：`frps` 的 `bind_port`（默认 7000）需要手动放行
  用 fw4 / nftables 在 `/etc/config/firewall` 加 rule 见 `etc/init.d/frps` 顶部注释。
  面板端口不要对公网开放
- **不暴露 SSH**：示例配置里没有任何把 22 端口转发出去的代理

## 二进制口径

包内二进制仍叫 `frps` / `frpc`（由 `nfrp-server` / `nfrp-client` 改名而来）
`frpc -v` / `frps -v` 输出裸 `0.71.0`（对齐官方 frp 便于面板和启动器解析）
线协议魔术字与版本串未改动 与官方 0.71 互通不退化
