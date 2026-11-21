# NFrp Android 版

NFrp 的 frps / frpc 交叉编译到 Android 的产物 可以直接跑在 Termux 云手机
MuMu 这类模拟器 也可以塞进自己的 App 里当内置穿透

版本 **0.7.10** `-v` 输出的兼容标识仍是裸 `0.71.0` 与桌面版完全一致

## 包内结构

| 路径 | 说明 |
|---|---|
| `nfrp-android-aarch64/frps` | 64 位 ARM 服务端 真机用 |
| `nfrp-android-aarch64/frpc` | 64 位 ARM 客户端 真机用 |
| `nfrp-android-x86_64/frps` | x86_64 服务端 模拟器用 |
| `nfrp-android-x86_64/frpc` | x86_64 客户端 模拟器用 |

## 快速开始

推一个到设备上 加执行权限就能跑

```sh
adb push nfrp-android-aarch64/frpc /data/local/tmp/frpc
adb shell chmod +x /data/local/tmp/frpc
adb shell /data/local/tmp/frpc -v
```

`-v` 应该输出裸 `0.71.0` 这一行就是兼容标识

配置文件格式与桌面版完全一样 参考同仓库 `assets/frpc.toml`

```sh
adb push frpc.toml /data/local/tmp/frpc.toml
adb shell /data/local/tmp/frpc -c /data/local/tmp/frpc.toml
```

## 注意事项

- Android 上没有 `/etc/frp` 这类目录 配置路径自己用 `-c` 给
- 非 root 设备只能监听 1024 以上的端口
- MuMu 这类 x86_64 模拟器用 `x86_64` 那套 真机用 `aarch64`
- 裸二进制后台运行会被系统回收 长期用建议放进 App 进程或者用 `nohup`

## 与桌面版的差异

内核是同一份源码 协议 加密 代理类型全部一致

唯一区别是编译目标平台 pprof 性能剖析端点在这两个 Android 目标上返回 501
与 Linux 桌面版一致 不影响任何穿透功能
