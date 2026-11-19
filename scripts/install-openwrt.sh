#!/bin/sh
# NFrp OpenWrt 安装器（POSIX sh 只用 busybox 自带命令）
#
# 用法：
#   sh install-openwrt.sh /path/to/dist/release
#   sh install-openwrt.sh /path/to/nfrp-linux-mipsle.tar.gz
#
# 流程：
#   1) 读 /etc/openwrt_release 的 DISTRIB_ARCH 决定该下哪个包（认不出就退出，绝不猜）
#   2) 用同目录的 SHA256SUMS.txt 校验包的 sha256（不匹配立即退出）
#   3) 解压到临时目录，装二进制到 /usr/bin、init 脚本到 /etc/init.d
#   4) 示例配置只在目标不存在时安装，绝不覆盖用户已有配置
#
# ★ 不联网、不装 opkg、不碰防火墙规则；放行端口见包内 openwrt/etc/init.d/frps 注释

set -eu

usage() {
    echo "用法： sh $0 <发布目录 或 .tar.gz 包路径>" >&2
    exit 2
}

[ "$#" -ge 1 ] || usage
SRC=$1
[ -e "$SRC" ] || { echo "路径不存在：$SRC" >&2; exit 2; }

# ARCH_FILE / DESTDIR 允许环境变量覆盖 仅为自动化测试与打包预检用
# 正常运行都不设置：固定读 /etc/openwrt_release 固定装到根目录
ARCH_FILE=${ARCH_FILE:-/etc/openwrt_release}
DESTDIR=${DESTDIR:-}
[ -f "$ARCH_FILE" ] || { echo "找不到 $ARCH_FILE 这不是 OpenWrt 系统" >&2; exit 1; }

# 从 /etc/openwrt_release 里取 DISTRIB_ARCH
# 文件格式： DISTRIB_ARCH='mipsel_24kc'
DISTRIB_ARCH=$(sed -n "s/^DISTRIB_ARCH=['\"]\{0,1\}\([^'\"]*\)['\"]\{0,1\}$/\1/p" "$ARCH_FILE" | head -n 1)
[ -n "$DISTRIB_ARCH" ] || { echo "无法从 $ARCH_FILE 读取 DISTRIB_ARCH" >&2; exit 1; }

# 架构到发布包后缀的映射
#   mipsel_24kc            -> linux-mipsle  （小端 MIPS 24kc）
#   mips_24kc              -> linux-mips    （大端 MIPS 24kc）
#   aarch64_*              -> linux-arm64
#   arm_cortex-a*_...vfp.. -> linux-arm-hf  （带 VFP 的硬浮点 ARMv7）
#   x86_64                 -> linux-amd64
case "$DISTRIB_ARCH" in
    mipsel_24kc)        PLATFORM=linux-mipsle ;;
    mips_24kc)          PLATFORM=linux-mips ;;
    aarch64_*)          PLATFORM=linux-arm64 ;;
    arm_cortex-a*vfp*|\
    arm_cortex-a*neon*) PLATFORM=linux-arm-hf ;;
    x86_64)             PLATFORM=linux-amd64 ;;
    *)
        echo "不支持的 DISTRIB_ARCH=$DISTRIB_ARCH" >&2
        echo "本发布支持 mipsel_24kc / mips_24kc / aarch64_* / arm_cortex-a*(vfp) / x86_64" >&2
        echo "不猜测架构 请确认你的设备确实属于其中之一" >&2
        exit 1
        ;;
esac

PKG_NAME="nfrp-$PLATFORM.tar.gz"
# 历史兼容：v0.7.7 之前有一版试过下划线命名（nfrp-linux_arm64.tar.gz）。
# 现在统一回连字符（nfrp-linux-arm64.tar.gz），下划线那版也认，优先连字符。
LEGACY_NAME="nfrp-$(printf '%s' "$PLATFORM" | tr '-' '_').tar.gz"

# 定位包与 SHA256SUMS.txt
if [ -d "$SRC" ]; then
    BASE_DIR=$SRC
    if [ -f "$BASE_DIR/$PKG_NAME" ]; then
        PKG=$BASE_DIR/$PKG_NAME
    elif [ -f "$BASE_DIR/$LEGACY_NAME" ]; then
        PKG=$BASE_DIR/$LEGACY_NAME
        PKG_NAME=$LEGACY_NAME
    else
        PKG=$BASE_DIR/$PKG_NAME
    fi
else
    BASE_DIR=$(dirname "$SRC")
    BASENAME_SRC=$(basename "$SRC")
    if [ "$BASENAME_SRC" = "$PKG_NAME" ] || [ "$BASENAME_SRC" = "$LEGACY_NAME" ]; then
        PKG=$SRC
        PKG_NAME=$BASENAME_SRC
    else
        echo "传入的包 $BASENAME_SRC 与架构 $DISTRIB_ARCH 不匹配 期望 $PKG_NAME 或 $LEGACY_NAME" >&2
        exit 1
    fi
fi
echo "架构 $DISTRIB_ARCH -> 发布包 $PKG_NAME"
SUMS=$BASE_DIR/SHA256SUMS.txt

[ -f "$PKG" ] || { echo "找不到发布包 $PKG" >&2; exit 1; }
[ -f "$SUMS" ] || { echo "找不到校验文件 $SUMS 拒绝安装" >&2; exit 1; }

# 从 SHA256SUMS.txt 里取本包的期望值
# 支持 "<hash>  <name>" 与 "<hash> *<name>" 两种常见格式
EXPECTED=$(sed -n "s/^\([0-9a-fA-F]\{64\}\)[[:space:]][[:space:]]*[*]\{0,1\}$PKG_NAME\$/\1/p" "$SUMS" | head -n 1)
[ -n "$EXPECTED" ] || { echo "$SUMS 里没有 $PKG_NAME 的校验值 拒绝安装" >&2; exit 1; }

ACTUAL=$(sha256sum "$PKG" | awk '{print $1}')
if [ "$ACTUAL" != "$EXPECTED" ]; then
    echo "SHA256 不匹配 拒绝安装" >&2
    echo "  期望 $EXPECTED" >&2
    echo "  实际 $ACTUAL" >&2
    exit 1
fi
echo "SHA256 校验通过"

TMPDIR=$(mktemp -d /tmp/nfrp-install.XXXXXX) || exit 1
trap 'rm -rf "$TMPDIR"' EXIT HUP INT TERM
tar xzf "$PKG" -C "$TMPDIR"

# 解压后的目录结构有两种可能 包内文件平铺在根 或套一层目录
if [ -f "$TMPDIR/frpc" ] && [ -f "$TMPDIR/frps" ]; then
    ROOT=$TMPDIR
else
    ROOT=$(find "$TMPDIR" -type f -name frpc -exec dirname {} \; | head -n 1)
fi
# 用 -f 而非 -x：install -m 0755 会重设权限，存在即可
[ -n "$ROOT" ] && [ -f "$ROOT/frpc" ] && [ -f "$ROOT/frps" ] || {
    echo "包里没有 frpc / frps 二进制 拒绝安装" >&2
    exit 1
}

mkdir -p "$DESTDIR/usr/bin" "$DESTDIR/etc/init.d"
install -m 0755 "$ROOT/frpc" "$DESTDIR/usr/bin/frpc"
install -m 0755 "$ROOT/frps" "$DESTDIR/usr/bin/frps"
echo "已安装二进制到 $DESTDIR/usr/bin/frpc 与 $DESTDIR/usr/bin/frps"

# init 脚本 已存在的同理保留 由用户决定是否替换
for s in frpc frps; do
    if [ -f "$ROOT/openwrt/etc/init.d/$s" ]; then
        if [ -e "$DESTDIR/etc/init.d/$s" ]; then
            echo "保留已有的 $DESTDIR/etc/init.d/$s 未覆盖"
        else
            install -m 0755 "$ROOT/openwrt/etc/init.d/$s" "$DESTDIR/etc/init.d/$s"
            echo "已安装 $DESTDIR/etc/init.d/$s"
        fi
    fi
done

# 示例配置 只在不存在时落盘
mkdir -p "$DESTDIR/etc/frp"
for c in frpc.toml frps.toml; do
    if [ -f "$ROOT/openwrt/etc/frp/$c" ]; then
        if [ -e "$DESTDIR/etc/frp/$c" ]; then
            echo "保留已有的 $DESTDIR/etc/frp/$c 未覆盖"
        else
            install -m 0644 "$ROOT/openwrt/etc/frp/$c" "$DESTDIR/etc/frp/$c"
            echo "已安装示例 $DESTDIR/etc/frp/$c 请按需要修改 server_addr 与 token"
        fi
    fi
done

echo "完成。启用自启： /etc/init.d/frpc enable && /etc/init.d/frps enable"
echo "防火墙放行 bind_port 见 /etc/init.d/frps 顶部注释 本脚本不自动开放任何端口"
