# 多阶段构建：在 alpine 里静态编译（musl），最终镜像只有几 MB。
#
#   docker build -t nfrp:latest .
#   docker run --rm -p 17000:17000 -p 17002:17002/udp -v $PWD/frps.toml:/etc/frps.toml nfrp:latest frps -c /etc/frps.toml
#
# 最终镜像里同时有 frps 与 frpc，用命令参数决定启动哪个。

# ★ 基础镜像的供应链说明（v0.5.3 补记）。
#
# 理想做法是按 **digest** 固定（`FROM alpine:3.20@sha256:...`）——那样上游
# 重新推送同名标签时构建会直接失败，而不是"下次 CI 编出来的东西悄悄变了"。
#
# **但目前没有这么做**，原因如实写在这里：定 digest 需要先 `docker pull`
# 拿到真实值，而本机与国内 CI 环境都不一定连得上 Docker Hub；
# 写一个猜的 digest 会让构建**必然失败**，比可变标签更糟。
#
# 已经做到的改善：`rust:alpine` 没有版本号（等于永远跟最新的 Rust 跑，
# 上游换 Rust 大版本会把构建打挂且原因不明显）⇒ 钉到明确的 `1.90-alpine`。
#
# TODO（有 docker 的环境里补）：
#   docker pull alpine:3.20 && docker inspect --format='{{index .RepoDigests 0}}' alpine:3.20
#   然后写成 FROM alpine:3.20@sha256:<上面查到的值>
ARG REGISTRY=docker.m.daocloud.io/library/
FROM ${REGISTRY}rust:1.90-alpine AS builder

RUN apk add --no-cache musl-dev build-base

WORKDIR /src

# ★ 不再做"占位文件预热依赖"那一层。
#
# 原写法（写空 src → cargo build || true → 拷真实源码 → touch → 重编）想在
# 改代码时复用依赖编译缓存，但那个 `|| true` 会把**半成品构建脚本状态**留在
# target/ 里，真实构建复用时报：
#   error: failed to join paths from `$LD_LIBRARY_PATH` together
# 0.7.3 的镜像构建就是这么失败的（exit 101）。
#
# 试过"占位编完再删本项目产物"的补救，仍然不可靠：cargo 的指纹可能认为
# 占位版就是最新，从而链接到空 main。镜像构建的可靠性优先于那点缓存收益，
# 所以直接一次编完。需要加速就给构建机配好 crates 缓存（BuildKit 的
# --mount=type=cache）。
COPY . .

# ★ musl 基础镜像里 `LD_LIBRARY_PATH` 是**空字符串**（不是未设置）。
#   空值时 cargo 会报：
#     error: failed to join paths from `$LD_LIBRARY_PATH` together
#   但给多段（含 `:`）同样会报 "path segment contains separator `:`"
#   —— cargo 的某些代码路径把它当单一路径处理。
#   所以这里只给**一个**目录，满足"非空且不含分隔符"。
ENV LD_LIBRARY_PATH=/usr/local/lib

# crates 源。默认用 rsproxy 的 sparse 协议（国内可达）；
# 海外构建可传 --build-arg CARGO_REGISTRY=https://index.crates.io/ 覆盖。
ARG CARGO_REGISTRY=sparse+https://rsproxy.cn/index/
RUN mkdir -p "$CARGO_HOME" && \
    printf '[source.crates-io]\nreplace-with = "mirror"\n\n[source.mirror]\nregistry = "%s"\n\n[net]\nretry = 5\ntimeout = 120\n' \
      "$CARGO_REGISTRY" > "$CARGO_HOME/config.toml"

# 先只编依赖（不碰本项目源码）：
# 这一步用 --offline 不行（依赖还没下），所以靠 crates 源。
RUN cargo fetch --locked

RUN cargo build --release --locked -p nfrp-server -p nfrp-client \
    && ls -l target/release/nfrp-server target/release/nfrp-client

FROM ${REGISTRY}alpine:3.20

RUN apk add --no-cache ca-certificates \
    && addgroup -S nfrp \
    && adduser -S -G nfrp nfrp

COPY --from=builder /src/target/release/nfrp-server /usr/local/bin/frps
COPY --from=builder /src/target/release/nfrp-client /usr/local/bin/frpc

# 默认配置（可用 -v 覆盖）；模板随源码走，放在仓库根的 assets/
#
# ★ v0.5.3：**只拷 frps.toml**。
#   原来把 frpc.toml 也拷进来了，但那是**客户端**配置，服务端镜像里根本不用它；
#   而它里面有一条默认启用的 SSH 代理示例 —— 等于白送攻击者一份"这套部署
#   打算怎么暴露内网"的说明书。要用 frpc 就跑客户端镜像 / 另外挂载。
#   （compose 里的 frpc 演示段本来就是挂载挂进去的，不依赖镜像内这份。）
COPY assets/frps.toml /etc/nfrp/frps.toml

# 17000 控制+数据，17002/udp xtcp 打洞牵线，17500 面板
EXPOSE 17000 17002/udp 17500

# ---- 健康检查 ----
#
# ★ 这里**故意不写 HEALTHCHECK**。
#
# 唯一适合做探针的是免鉴权的 `/api/healthz`，但它挂在**面板端口**上，
# 而随包发出的 `assets/frps.toml` 里 `dashboard_port` 默认是**注释掉的**
# （面板不启用）。写死一个探针 ⇒ 用户一 `docker compose up` 就看到
# `unhealthy`，而且不知道该改哪儿；做成环境变量又没用 —— HEALTHCHECK
# 在构建期就固化了，运行期改配置影响不到它。
#
# 「容器看起来一直是 unhealthy」比「没有健康检查」更难排查，所以宁可不加。
# 需要探针时请自己启用面板并补一行：
#
#   HEALTHCHECK CMD wget -qO- http://127.0.0.1:7500/api/healthz >/dev/null || exit 1
#
# （alpine 的 busybox 自带 wget，直接就能用。）
#
# 控制端口 17000 不适合做探针：它是 frp 协议端口，不是 HTTP，
# 探针连上去只会被当成一个握手失败并被断开。

USER nfrp
ENTRYPOINT ["/usr/local/bin/frps"]
CMD ["-c", "/etc/nfrp/frps.toml"]
