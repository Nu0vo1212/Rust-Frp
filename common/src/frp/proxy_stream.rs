//! 数据面的逐代理加密与压缩（官方 frp 的 `useEncryption` / `useCompression`）。
//!
//! # 官方语义
//!
//! `client/proxy/proxy.go` 的 `GetRealConn`：
//!
//! ```go
//! if pxy.baseCfg.Transport.UseEncryption {   // baseCfg 是 *v1.ProxyBaseConfig
//!     rwc, err = libio.WithEncryption(rwc, encKey)
//! }
//! if pxy.baseCfg.Transport.UseCompression {
//!     rwc, recycleFn = libio.WithCompressionFromPool(rwc)  // 在加密**外层**
//! }
//! ```
//!
//! 所以写方向是「先压缩、再加密」，读方向反过来。这两个开关在
//! **代理级** `[proxies.transport]`（不是客户端级 `[transport]`，后者官方会
//! 直接报 unknown field）—— 这一点用官方 0.71 二进制实测 + 源码双向确认过。
//!
//! # 格式细节（差一点就静默不兼容）
//!
//! * **加密**：密钥 = `pbkdf2(md5(token), salt="frp", iter=64, 16B)`；每条连接先
//!   明文写 16 字节随机 IV，之后是 AES-128-CFB128 密文，CFB 状态跨 write 保持。
//! * **压缩**：`snappy.NewBufferedWriter` ⇒ Snappy **framing** 格式
//!   （stream identifier + 分块长度/校验），不是裸块格式。
//!
//! # 写路径为什么要 `pending_out`
//!
//! 压缩器是**有缓冲**的：小数据写进去后可能一个字节都不吐，要等到 `flush`
//! 或攒满一块才输出。这意味着两件事：
//!
//! 1. `poll_write` 不能假设「我编码了 N 字节就一定能立刻写出 N 字节」；
//! 2. `poll_flush` **必须**先把压缩器的残余冲刷出来，否则尾部数据永远发不出去
//!    —— 实测表现是「内容大致正确、结尾少一截」，属于最难查的一类。
//!
//! 内层流一旦返回 `Pending`，已编码的字节不能丢（加密流有状态，重来会得到不同
//! 密文），所以统一放进 [`ProxyStream::pending_out`]，下次写/刷先把它送完。

use std::io::{Cursor, Write};
use std::pin::Pin;
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::frp::v1::{Cfb, IV_LEN, KEY_LEN};

/// 数据面的一条已包装连接：`Compressed(Encrypted(inner))`。
pub struct ProxyStream<S> {
    inner: S,
    enc: Option<EncState>,
    comp: Option<CompState>,
    /// 已编码（压缩/加密完）但还没成功写进内层的字节。
    pending_out: Vec<u8>,
    /// `pending_out` 里已写出去的位置。
    pending_pos: usize,
}

struct EncState {
    /// 写方向的 CFB；`None` 表示 IV 还没写出去。
    write_cfb: Option<Cfb>,
    /// 读方向的 CFB；`None` 表示 IV 还没收全。
    read_cfb: Option<Cfb>,
    key: [u8; KEY_LEN],
    /// 读方向已收到的 IV 字节。
    iv_buf: Vec<u8>,
}

struct CompState {
    enc: snap::write::FrameEncoder<Cursor<Vec<u8>>>,
    /// 解压器的输入队列（原始 snappy framing 字节，未消费的前缀）。
    inbuf: Vec<u8>,
    /// 解压出来、还没交给调用方的字节。
    out: Vec<u8>,
    out_pos: usize,
}

impl<S> ProxyStream<S> {
    /// `key = None` 不加密；`compress` 决定是否压缩。
    pub fn new(inner: S, key: Option<[u8; KEY_LEN]>, compress: bool) -> Self {
        let enc = key.map(|key| EncState {
            write_cfb: None,
            read_cfb: None,
            key,
            iv_buf: Vec::with_capacity(IV_LEN),
        });
        let comp = compress.then(|| CompState {
            enc: snap::write::FrameEncoder::new(Cursor::new(Vec::new())),
            inbuf: Vec::new(),
            out: Vec::new(),
            out_pos: 0,
        });
        Self {
            inner,
            enc,
            comp,
            pending_out: Vec::new(),
            pending_pos: 0,
        }
    }

    pub fn get_ref(&self) -> &S {
        &self.inner
    }

    pub fn get_mut(&mut self) -> &mut S {
        &mut self.inner
    }

    pub fn into_inner(self) -> S {
        self.inner
    }

    /// 把 `plain` 按「压缩 → 加密」编码后压进 `pending_out`（只编码，不碰内层）。
    fn encode_into_pending(&mut self, plain: &[u8]) {
        // ① 压缩
        let mut body: Vec<u8> = match self.comp.as_mut() {
            Some(c) => {
                if c.enc.write_all(plain).and_then(|()| c.enc.flush()).is_err() {
                    // 压缩器出错时退化成透传：宁可失去压缩也不能丢数据
                    plain.to_vec()
                } else {
                    let cur = c.enc.get_mut();
                    // Cursor 写的时候 position 会推进到末尾，所以必须取**整个**缓冲
                    // （上一次已经 clear + 归零，整个缓冲就是本次新增）。
                    // 用 `[position..]` 会永远取到空 —— 那会让压缩一个字节都发不出去。
                    let produced = cur.get_ref().clone();
                    cur.get_mut().clear();
                    cur.set_position(0);
                    produced
                }
            }
            None => plain.to_vec(),
        };

        // ② 加密（首写先明文发 16 字节 IV）
        if let Some(e) = self.enc.as_mut() {
            let first = e.write_cfb.is_none();
            let mut framed = Vec::with_capacity(IV_LEN + body.len());
            if first {
                let mut iv = [0u8; IV_LEN];
                // CFB 的 IV 可预测 ⇒ 密钥流可预测，必须真随机
                ring::rand::SecureRandom::fill(&ring::rand::SystemRandom::new(), &mut iv)
                    .expect("系统随机数不可用");
                e.write_cfb = Some(Cfb::new(&e.key, &iv));
                framed.extend_from_slice(&iv);
            }
            e.write_cfb
                .as_mut()
                .expect("上面已确保 write_cfb 存在")
                .encrypt(&mut body);
            framed.extend_from_slice(&body);
            body = framed;
        }

        tracing::trace!(
            plain = plain.len(),
            encoded = body.len(),
            comp = self.comp.is_some(),
            enc = self.enc.is_some(),
            "ProxyStream 编码"
        );
        if !body.is_empty() {
            self.pending_out.extend_from_slice(&body);
        }
    }
}

impl<S: AsyncWrite + Unpin> ProxyStream<S> {
    /// 尽量把 `pending_out` 写进内层流。
    ///
    /// 写空 ⇒ `Ready(Ok(()))`；内层 `Pending` ⇒ `Pending`（**字节留在缓冲里**）。
    fn flush_pending(&mut self, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        while self.pending_pos < self.pending_out.len() {
            let rest = &self.pending_out[self.pending_pos..];
            match Pin::new(&mut self.inner).poll_write(cx, rest) {
                Poll::Ready(Ok(0)) => {
                    return Poll::Ready(Err(std::io::Error::new(
                        std::io::ErrorKind::WriteZero,
                        "内层流不再接收数据",
                    )));
                }
                Poll::Ready(Ok(n)) => self.pending_pos += n,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }
        self.pending_out.clear();
        self.pending_pos = 0;
        Poll::Ready(Ok(()))
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for ProxyStream<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let this = self.get_mut();

        // 先把上一轮积压写完（否则会乱序）
        match this.flush_pending(cx) {
            Poll::Ready(Ok(())) => {}
            Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
            Poll::Pending => return Poll::Pending,
        }

        this.encode_into_pending(buf);

        // 立刻尝试送出；送不完就留在 pending 里，对上层报告已消费
        // （数据没丢，下次 poll_write / poll_flush 会继续送）
        match this.flush_pending(cx) {
            Poll::Ready(Ok(())) => Poll::Ready(Ok(buf.len())),
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Pending => Poll::Ready(Ok(buf.len())),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();

        // 关键：先让压缩器把残余冲刷出来（空写 + flush 会输出未满的块），
        //   否则尾部数据永远发不出去。
        this.encode_into_pending(&[]);

        match this.flush_pending(cx) {
            Poll::Ready(Ok(())) => {}
            Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
            Poll::Pending => return Poll::Pending,
        }
        Pin::new(&mut this.inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        this.encode_into_pending(&[]);
        match this.flush_pending(cx) {
            Poll::Ready(Ok(())) => {}
            Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
            Poll::Pending => return Poll::Pending,
        }
        Pin::new(&mut this.inner).poll_shutdown(cx)
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for ProxyStream<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        if buf.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }

        loop {
            // 已解压但没交付完的，先交付
            if let Some(c) = this.comp.as_mut() {
                if c.out_pos < c.out.len() {
                    let n = (c.out.len() - c.out_pos).min(buf.remaining());
                    buf.put_slice(&c.out[c.out_pos..c.out_pos + n]);
                    c.out_pos += n;
                    if c.out_pos >= c.out.len() {
                        c.out.clear();
                        c.out_pos = 0;
                    }
                    return Poll::Ready(Ok(()));
                }
            }

            // 读内层
            let mut raw = vec![0u8; 16 * 1024];
            let mut tmp = ReadBuf::new(&mut raw);
            match Pin::new(&mut this.inner).poll_read(cx, &mut tmp) {
                Poll::Ready(Ok(())) => {}
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
            let n = tmp.filled().len();
            if n == 0 {
                tracing::trace!("ProxyStream 读到 EOF");
                return Poll::Ready(Ok(())); // EOF
            }
            let mut data = tmp.filled().to_vec();

            // 解密：可能要先攒够 IV
            if let Some(e) = this.enc.as_mut() {
                if e.read_cfb.is_none() {
                    let need = IV_LEN - e.iv_buf.len();
                    let take = need.min(data.len());
                    e.iv_buf.extend_from_slice(&data[..take]);
                    data.drain(..take);
                    if e.iv_buf.len() < IV_LEN {
                        continue; // IV 没齐，再读一轮
                    }
                    let mut iv = [0u8; IV_LEN];
                    iv.copy_from_slice(&e.iv_buf);
                    e.read_cfb = Some(Cfb::new(&e.key, &iv));
                }
                e.read_cfb
                    .as_mut()
                    .expect("上面已建立 read_cfb")
                    .decrypt(&mut data);
            }
            if data.is_empty() {
                continue;
            }

            // 解压
            match this.comp.as_mut() {
                Some(c) => {
                    c.inbuf.extend_from_slice(&data);
                    let v = decode_available(c);
                    tracing::trace!(raw = data.len(), decoded = v.len(), "ProxyStream 解码");
                    if v.is_empty() {
                        continue; // 帧还没收全
                    }
                    let k = v.len().min(buf.remaining());
                    buf.put_slice(&v[..k]);
                    if k < v.len() {
                        c.out = v;
                        c.out_pos = k;
                    }
                    return Poll::Ready(Ok(()));
                }
                None => {
                    let k = data.len().min(buf.remaining());
                    buf.put_slice(&data[..k]);
                    return Poll::Ready(Ok(()));
                }
            }
        }
    }
}

/// Snappy framing 的 stream identifier 固定内容。
const SNAPPY_STREAM_ID: &[u8] = b"sNaPpY";
/// 单个 chunk 的最大长度（framing 规范里 3 字节长度域，实际实现按 64 KiB 切）。
const SNAPPY_MAX_CHUNK: usize = 16 * 1024 * 1024;

/// 从输入队列里尽可能多地解出明文。
///
/// **不完整就停**：任何"还差几个字节"的情况都直接返回已解出的部分，
/// 把剩余字节留在 `inbuf` 等下次 —— 这样绝不会破坏帧状态。
fn decode_available(c: &mut CompState) -> Vec<u8> {
    let mut out = Vec::new();
    let mut pos = 0usize;

    loop {
        let rest = &c.inbuf[pos..];
        if rest.len() < 4 {
            break; // 连 chunk 头都不够
        }
        let ctype = rest[0];
        let clen = u32::from_le_bytes([rest[1], rest[2], rest[3], 0]) as usize;

        match ctype {
            // stream identifier
            0xff => {
                if rest.len() < 4 + clen {
                    break;
                }
                let payload = &rest[4..4 + clen];
                if payload != SNAPPY_STREAM_ID {
                    // 不是 snappy 流：别再往下猜了，把已解出的交付，
                    // 剩余字节丢掉（继续解析只会一直错位）
                    tracing::warn!("对端数据不是 snappy 流（stream identifier 不符），放弃解压");
                    c.inbuf.clear();
                    return out;
                }
                pos += 4 + clen;
            }
            // compressed data / uncompressed data
            0x00 | 0x01 => {
                if !(4..=SNAPPY_MAX_CHUNK).contains(&clen) {
                    tracing::warn!(clen, "snappy chunk 长度异常，放弃解压");
                    c.inbuf.clear();
                    return out;
                }
                if rest.len() < 4 + clen {
                    break; // 数据还没收全
                }
                // 规范：data 的前 4 字节是 CRC-32C，之后才是 payload。
                //   （不是“负载 + 尾部 crc”，这一点差点就全盘错位。）
                let payload = &rest[8..4 + clen];
                if ctype == 0x00 {
                    match snap::raw::Decoder::new().decompress_vec(payload) {
                        Ok(v) => out.extend_from_slice(&v),
                        Err(e) => {
                            tracing::warn!("snappy 块解压失败（跳过该块）：{e}");
                        }
                    }
                } else {
                    out.extend_from_slice(payload);
                }
                pos += 4 + clen;
            }
            // skippable
            0x02..=0x7f | 0xfe => {
                if rest.len() < 4 + clen {
                    break;
                }
                pos += 4 + clen;
            }
            // reserved unskippable
            // 0x80..=0xfd 是 reserved unskippable，0xfe 已在上面按 skippable 处理，
            // 所以这里覆盖了剩余全部取值 —— 不需要也不再允许 _ 分支。
            0x80..=0xfd => {
                tracing::warn!(ctype, "snappy 保留 chunk 类型，放弃解压");
                c.inbuf.clear();
                return out;
            }
        }
    }

    if pos > 0 {
        c.inbuf.drain(..pos);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    fn key_of(token: &str) -> [u8; KEY_LEN] {
        crate::frp::v1::derive_key(token.as_bytes())
    }

    async fn roundtrip(token: &str, compress: bool, payload: &[u8]) -> Vec<u8> {
        let (a, b) = tokio::io::duplex(64 * 1024);
        let mut w = ProxyStream::new(a, Some(key_of(token)), compress);
        let mut r = ProxyStream::new(b, Some(key_of(token)), compress);

        let data = payload.to_vec();
        let want = data.len();
        let handle = tokio::spawn(async move {
            w.write_all(&data).await.expect("写失败");
            w.flush().await.expect("flush");
        });

        let mut got = vec![0u8; want];
        match tokio::time::timeout(std::time::Duration::from_secs(5), r.read_exact(&mut got)).await
        {
            Ok(Ok(_)) => {}
            Ok(Err(e)) => panic!("读失败：{e}"),
            Err(_) => panic!("读超时（5s）—— 解压/解密可能卡住了"),
        }
        handle.await.expect("写任务 panic");
        got
    }

    #[tokio::test]
    async fn 加密往返一致() {
        let p = b"hello nfrp encrypted data plane 1234567890";
        assert_eq!(roundtrip("tok", false, p).await, p);
    }

    #[tokio::test]
    async fn 压缩往返一致() {
        let p = b"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".repeat(20);
        assert_eq!(roundtrip("tok", true, &p).await, p);
    }

    /// 组合：压缩缓冲 + 加密状态一起跑，尾部必须一个字节都不少。
    #[tokio::test]
    async fn 加密加压缩往返一致() {
        let p = b"NFRP both encryption and compression.".repeat(10);
        assert_eq!(roundtrip("tok", true, &p).await, p);
    }

    /// 小数据 + 压缩：`poll_flush` 漏刷残余会被这条抓到。
    #[tokio::test]
    async fn 压缩小数据不丢尾巴() {
        let p = b"tiny";
        assert_eq!(roundtrip("tok", true, p).await, p);
    }

    /// 多次 write 交替 flush，覆盖 pending 缓冲的续写路径。
    #[tokio::test]
    async fn 分片写入压缩往返一致() {
        let (a, b) = tokio::io::duplex(8 * 1024);
        let mut w = ProxyStream::new(a, Some(key_of("tok")), true);
        let mut r = ProxyStream::new(b, Some(key_of("tok")), true);
        let parts: Vec<Vec<u8>> = (0..12).map(|i| vec![b'a' + i as u8; 300]).collect();
        let want: Vec<u8> = parts.iter().flatten().copied().collect();

        let ps = parts.clone();
        let h = tokio::spawn(async move {
            for p in ps {
                w.write_all(&p).await.unwrap();
                w.flush().await.unwrap();
            }
        });

        let mut got = vec![0u8; want.len()];
        tokio::time::timeout(std::time::Duration::from_secs(5), r.read_exact(&mut got))
            .await
            .expect("超时")
            .expect("读失败");
        h.await.unwrap();
        assert_eq!(got, want, "分片写入后内容必须完全一致");
    }

    #[tokio::test]
    async fn 不加密不压缩是透明的() {
        let (a, b) = tokio::io::duplex(4096);
        let mut w = ProxyStream::new(a, None, false);
        let mut r = ProxyStream::new(b, None, false);
        let p = b"plain bytes";
        let h = tokio::spawn(async move {
            w.write_all(p).await.unwrap();
            w.flush().await.unwrap();
        });
        let mut got = vec![0u8; p.len()];
        tokio::time::timeout(std::time::Duration::from_secs(5), r.read_exact(&mut got))
            .await
            .expect("超时")
            .unwrap();
        h.await.unwrap();
        assert_eq!(&got, p);
    }

    #[tokio::test]
    async fn 错误密钥解出乱码() {
        let p = b"0123456789abcdef0123456789abcdef";
        let (a, b) = tokio::io::duplex(4096);
        let mut w = ProxyStream::new(a, Some(key_of("A")), false);
        let mut r = ProxyStream::new(b, Some(key_of("B")), false);
        let h = tokio::spawn(async move {
            w.write_all(p).await.unwrap();
            w.flush().await.unwrap();
        });
        let mut got = vec![0u8; p.len()];
        tokio::time::timeout(std::time::Duration::from_secs(5), r.read_exact(&mut got))
            .await
            .expect("超时")
            .unwrap();
        h.await.unwrap();
        assert_ne!(&got[..], &p[..], "换密钥必须解出不同内容");
    }

    /// 双向并发：真实 relay 是同一条连接上两个方向同时跑。
    /// 单向测试覆盖不到「写 pending 与读解压互相影响」的情况。
    #[tokio::test]
    async fn 双向并发加解密压缩() {
        let (a, b) = tokio::io::duplex(16 * 1024);
        let client = ProxyStream::new(a, Some(key_of("tok")), true);
        let server = ProxyStream::new(b, Some(key_of("tok")), true);

        // 两端各发一段、各收一段，并且分片写 + 多次 flush
        let c2s: Vec<u8> = (0..40)
            .flat_map(|i| vec![b'A' + (i % 26) as u8; 97])
            .collect();
        let s2c: Vec<u8> = (0..40)
            .flat_map(|i| vec![b'a' + (i % 26) as u8; 89])
            .collect();

        let (mut cr, mut cw) = tokio::io::split(client);
        let (mut sr, mut sw) = tokio::io::split(server);

        let c2s_len = c2s.len();
        let s2c_len = s2c.len();
        let c2s_clone = c2s.clone();
        let s2c_clone = s2c.clone();

        let tc = tokio::spawn(async move {
            for chunk in c2s_clone.chunks(97) {
                cw.write_all(chunk).await.unwrap();
                cw.flush().await.unwrap();
            }
            let mut got = vec![0u8; s2c_len];
            cr.read_exact(&mut got).await.unwrap();
            got
        });
        let ts = tokio::spawn(async move {
            for chunk in s2c_clone.chunks(89) {
                sw.write_all(chunk).await.unwrap();
                sw.flush().await.unwrap();
            }
            let mut got = vec![0u8; c2s_len];
            sr.read_exact(&mut got).await.unwrap();
            got
        });

        let (got_at_server, got_at_client) =
            tokio::time::timeout(std::time::Duration::from_secs(10), async {
                (ts.await.unwrap(), tc.await.unwrap())
            })
            .await
            .expect("双向传输超时（10s）");

        assert_eq!(got_at_server, c2s, "服务端收到的必须与客户端发出的完全一致");
        assert_eq!(got_at_client, s2c, "客户端收到的必须与服务端发出的完全一致");
    }

    #[test]
    fn 密文不含明文() {
        let mut b = b"PLAINTEXT-MARKER".to_vec();
        Cfb::new(&key_of("t"), &[7u8; IV_LEN]).encrypt(&mut b);
        assert!(
            !b.windows(9).any(|w| w == b"PLAINTEXT"),
            "密文里不该出现明文"
        );
    }
}
