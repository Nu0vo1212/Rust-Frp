//! 传输层抽象。
//!
//! MVP 阶段控制连接与工作连接都是**明文 TCP**，但这里预留了加密接口：
//! 后续接入 `rustls`（TLS）或 `snow`（Noise）时，只需要新增一个
//! 实现 [`Transport`] 的类型（把 `TcpStream` 包装成密文流），
//! 在 `main` 里替换 `PlainTransport` 即可，上层的连接管理 / 转发逻辑零改动。

use std::{
    io,
    pin::Pin,
    task::{Context, Poll},
};

use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    net::TcpStream,
};

use crate::error::Result;

/// 一个可读可写的隧道流对象。
///
/// 对 `AsyncRead + AsyncWrite + Send + Unpin` 做自动 blanket impl，
/// 因此 `TcpStream`、`tokio_rustls::TlsStream`、`snow` 的 transport state
/// 只要满足约束就能直接放进来。
pub trait TunnelStream: AsyncRead + AsyncWrite + Send + Unpin + 'static {}

impl<T> TunnelStream for T where T: AsyncRead + AsyncWrite + Send + Unpin + 'static {}

/// 类型擦除后的隧道流，让服务端 / 客户端代码不必泛型化。
pub struct TunnelIo(Box<dyn TunnelStream>);

impl TunnelIo {
    /// 包装任意满足 [`TunnelStream`] 的流。
    pub fn new<S: TunnelStream>(stream: S) -> Self {
        Self(Box::new(stream))
    }

    /// 明文包装（外部用户连接、本地内网连接使用）。
    pub fn plain(stream: TcpStream) -> Self {
        Self::new(stream)
    }
}

impl AsyncRead for TunnelIo {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        Pin::new(&mut *this.0).poll_read(cx, buf)
    }
}

impl AsyncWrite for TunnelIo {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        Pin::new(&mut *this.0).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        Pin::new(&mut *this.0).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        Pin::new(&mut *this.0).poll_shutdown(cx)
    }
}

/// 传输层：负责把一条已建立的 TCP 连接升级成隧道流。
///
/// 默认实现 [`PlainTransport`] 直接透传；加密实现可在此做握手。
pub trait Transport: Send + Sync + 'static {
    /// 传输层名称，用于启动日志。
    fn name(&self) -> &'static str;

    /// 包装一条 TCP 连接。
    fn wrap(&self, stream: TcpStream) -> Result<TunnelIo>;
}

/// 明文传输（MVP 默认）。
#[derive(Debug, Clone, Copy, Default)]
pub struct PlainTransport;

impl Transport for PlainTransport {
    fn name(&self) -> &'static str {
        "plain"
    }

    fn wrap(&self, stream: TcpStream) -> Result<TunnelIo> {
        Ok(TunnelIo::plain(stream))
    }
}
