# 多阶段构建：在 alpine 里静态编译（musl），最终镜像只有几 MB。
#
#   docker build -t rustunnel:0.2.0 .
#   docker run --rm -p 17000:17000 -p 17002:17002/udp -v $PWD/frps.toml:/etc/frps.toml rustunnel:0.2.0 frps -c /etc/frps.toml
#
# 最终镜像里同时有 frps 与 frpc，用命令参数决定启动哪个。

FROM rust:alpine AS builder

RUN apk add --no-cache musl-dev build-base

WORKDIR /src
# 先只拷清单文件，把依赖编译这层缓存下来（改代码时不必重编依赖）
COPY Cargo.toml Cargo.lock ./
COPY common ./common
COPY server ./server
COPY client ./client
# 占位：让 cargo 能解析工作区结构
RUN mkdir -p common/src server/src client/src \
    && echo "" > common/src/lib.rs \
    && echo "fn main() {}" > server/src/main.rs \
    && echo "fn main() {}" > client/src/main.rs \
    && cargo build --release --locked 2>/dev/null || true

# 真正的源码
COPY . .
# touch 一下确保时间戳比占位文件新
RUN touch common/src/lib.rs server/src/main.rs client/src/main.rs \
    && cargo build --release --locked -p rustunnel-server -p rustunnel-client

FROM alpine:3.20

RUN apk add --no-cache ca-certificates \
    && addgroup -S rustunnel \
    && adduser -S -G rustunnel rustunnel

COPY --from=builder /src/target/release/rustunnel-server /usr/local/bin/frps
COPY --from=builder /src/target/release/rustunnel-client /usr/local/bin/frpc

# 默认配置（可用 -v 覆盖）
COPY dist/release/assets/frps.toml /etc/rustunnel/frps.toml
COPY dist/release/assets/frpc.toml /etc/rustunnel/frpc.toml

# 17000 控制+数据，17002/udp xtcp 打洞牵线，17500 面板
EXPOSE 17000 17002/udp 17500

USER rustunnel
ENTRYPOINT ["/usr/local/bin/frps"]
CMD ["-c", "/etc/rustunnel/frps.toml"]
