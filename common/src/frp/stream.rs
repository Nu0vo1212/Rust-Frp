//! 通用流抽象：把 TcpStream / TLS 流 / yamux 子流统一成同一种类型。
//!
//! frp 的传输层次是 `TCP -> [TLS] -> [yamux] -> frp v2 连接`，
//! 有了这层抽象，上层握手代码就不需要关心底层到底是哪一种流。

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// 读写合一的 trait，用于在 trait object 里同时表达 `AsyncRead + AsyncWrite`。
///
/// Rust 的 trait object 只允许一个非 auto trait，所以要先把两者合并成一个。
pub trait IoStream: AsyncRead + AsyncWrite + Send + 'static {}
impl<T: AsyncRead + AsyncWrite + Send + 'static> IoStream for T {}

/// 统一的异步流：`TcpStream`、`TlsStream<TcpStream>`、`yamux::Stream` 都能装进来。
///
/// 用 `Pin<Box<...>>` 是为了让它自动满足 `Unpin`，可以直接喂给 `copy_bidirectional`。
pub type BoxStream = Pin<Box<dyn IoStream>>;

/// 把一段"已经被读出来"的字节塞回流的最前面。
///
/// frp 服务端靠探测首字节来判断是不是 TLS 连接（`0x17` = frp 自定义首字节，
/// `0x16` = 标准 TLS 握手）。非 TLS 时这个字节属于 frp 协议本身，必须还回去，
/// 否则握手会失败。
pub struct PrefixedStream<S> {
    prefix: Vec<u8>,
    pos: usize,
    inner: S,
}

impl<S> PrefixedStream<S> {
    pub fn new(prefix: Vec<u8>, inner: S) -> Self {
        Self {
            prefix,
            pos: 0,
            inner,
        }
    }

    #[allow(dead_code)]
    pub fn into_inner(self) -> S {
        self.inner
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for PrefixedStream<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.as_mut().get_mut();
        if this.pos < this.prefix.len() {
            if buf.remaining() == 0 {
                return Poll::Ready(Ok(()));
            }
            let rest = &this.prefix[this.pos..];
            let n = rest.len().min(buf.remaining());
            buf.put_slice(&rest[..n]);
            this.pos += n;
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut this.inner).poll_read(cx, buf)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for PrefixedStream<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.as_mut().get_mut().inner).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.as_mut().get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.as_mut().get_mut().inner).poll_shutdown(cx)
    }
}
