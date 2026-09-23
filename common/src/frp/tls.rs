//! frp 的 `transport.tls` 实现。
//!
//! 注意：frp 说的"自定义 TLS"其实是**标准 TLS**（Go `crypto/tls`），
//! "自定义"只体现在两点：
//!
//! 1. 服务端自动生成一张自签名证书（默认 RSA-2048，我们这里用 ECDSA-P256）；
//! 2. 客户端默认 `InsecureSkipVerify = true`，不校验服务端证书。
//!
//! 另外 frp 客户端在 TLS 握手前会先发一个 `0x17`（TLS Application Data 记录类型）
//! 用于伪装，服务端据此判断这是 TLS 连接。可通过
//! `transport.tls.disableCustomTLSFirstByte = true` 关掉。

use std::net::IpAddr;
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::ring;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, SignatureScheme};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite};
use tokio::net::TcpStream;
use tokio_rustls::{TlsAcceptor, TlsConnector};

use super::stream::{BoxStream, PrefixedStream};

/// frp 自定义首字节：`0x17` = TLS Application Data，用于把 frp 流量伪装成 TLS。
pub const FRP_TLS_HEAD_BYTE: u8 = 0x17;
/// 标准 TLS 握手的第一个字节（Handshake）。
const TLS_HANDSHAKE_BYTE: u8 = 0x16;

/// 探测首字节的等待时间，与 frp 的 `connReadTimeout` 对应。
const PROBE_TIMEOUT: Duration = Duration::from_secs(10);

/// 服务端证书只生成一次：RSA/ECDSA 密钥生成有几十毫秒开销，
/// 每个连接都生成会明显拖慢握手。
static SERVER_TLS_CONFIG: OnceLock<Arc<rustls::ServerConfig>> = OnceLock::new();

/// 进程共用的 rustls 加密后端（QUIC 直连也要用同一个 provider）。
pub fn crypto_provider() -> Arc<rustls::crypto::CryptoProvider> {
    Arc::new(ring::default_provider())
}

/// 生成自签名证书并构造服务端 TLS 配置。
pub fn server_config() -> Result<Arc<rustls::ServerConfig>> {
    if let Some(c) = SERVER_TLS_CONFIG.get() {
        return Ok(c.clone());
    }
    let key = rcgen::generate_simple_self_signed(vec!["frp".to_string()])
        .context("生成自签名证书失败")?;
    let cert_der: CertificateDer<'static> = key.cert.der().clone();
    let key_der = PrivateKeyDer::try_from(key.key_pair.serialize_der())
        .map_err(|e| anyhow!("转换私钥失败：{e}"))?;

    let cfg = rustls::ServerConfig::builder_with_provider(crypto_provider())
        .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])
        .map_err(|e| anyhow!("TLS 协议版本配置失败：{e}"))?
        .with_no_client_auth()
        .with_single_cert(vec![cert_der], key_der)
        .context("装载服务端证书失败")?;

    let cfg = Arc::new(cfg);
    let _ = SERVER_TLS_CONFIG.set(cfg.clone());
    Ok(cfg)
}

/// 客户端 TLS 配置：与 frp 默认行为一致，不校验服务端证书。
pub fn client_config() -> Result<Arc<rustls::ClientConfig>> {
    let cfg = rustls::ClientConfig::builder_with_provider(crypto_provider())
        .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])
        .map_err(|e| anyhow!("TLS 协议版本配置失败：{e}"))?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(SkipServerVerification))
        .with_no_client_auth();
    Ok(Arc::new(cfg))
}

/// 把主机名转成 rustls 的 ServerName（IP 和域名是两种不同的变体）。
fn to_server_name(host: &str) -> Result<ServerName<'static>> {
    if let Ok(ip) = host.parse::<IpAddr>() {
        return Ok(ServerName::from(ip));
    }
    ServerName::try_from(host.to_string()).map_err(|e| anyhow!("无效的 SNI 名称 {host}：{e:?}"))
}

/// 服务端：探测首字节，按需升级到 TLS。
///
/// - `0x17`：frp 自定义首字节，该字节被消费掉，随后是真正的 TLS 握手；
/// - `0x16`：标准 TLS 握手，首字节要还回流里；
/// - 其他：明文连接，首字节要还回流里。
///
/// 泛型化是为了让调用方在 TLS 之前先做一层探测（WebSocket 嗅探就是），
/// 探测读掉的字节可以用 [`PrefixedStream`] 还回来，不影响这里的首字节判断。
pub async fn accept_server<S>(mut stream: S, enable: bool, force: bool) -> Result<BoxStream>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    if !enable && !force {
        return Ok(Box::pin(stream));
    }

    let mut first = [0u8; 1];
    let n = tokio::time::timeout(PROBE_TIMEOUT, stream.read_exact(&mut first))
        .await
        .context("等待首字节超时")?
        .context("读取首字节失败")?;
    if n == 0 {
        bail!("连接在对端发送首字节前就关闭了");
    }

    match first[0] {
        FRP_TLS_HEAD_BYTE => {
            let acceptor = TlsAcceptor::from(server_config()?);
            let tls = acceptor
                .accept(stream)
                .await
                .context("TLS 服务端握手失败")?;
            Ok(Box::pin(tls))
        }
        TLS_HANDSHAKE_BYTE => {
            let acceptor = TlsAcceptor::from(server_config()?);
            let tls = acceptor
                .accept(PrefixedStream::new(vec![first[0]], stream))
                .await
                .context("TLS 服务端握手失败")?;
            Ok(Box::pin(tls))
        }
        other => {
            if force {
                bail!("服务端强制 TLS，但收到非 TLS 首字节 0x{other:02x}");
            }
            Ok(Box::pin(PrefixedStream::new(vec![other], stream)))
        }
    }
}

/// 客户端：按需发送 frp 自定义首字节并发起 TLS 握手。
pub async fn connect_client(
    mut stream: TcpStream,
    enable: bool,
    server_name: &str,
    disable_custom_first_byte: bool,
) -> Result<BoxStream> {
    if !enable {
        return Ok(Box::pin(stream));
    }
    if !disable_custom_first_byte {
        tokio::io::AsyncWriteExt::write_all(&mut stream, &[FRP_TLS_HEAD_BYTE])
            .await
            .context("发送 frp 自定义首字节失败")?;
    }
    let name = to_server_name(server_name)?;
    let connector = TlsConnector::from(client_config()?);
    let tls = connector
        .connect(name, stream)
        .await
        .context("TLS 客户端握手失败")?;
    Ok(Box::pin(tls))
}

/// 不校验服务端证书（等价于 frp 的 `InsecureSkipVerify = true`）。
///
/// `pub` 是为了让 OIDC 那边（[`crate::httpc`]）在配了 `insecureSkipVerify`
/// 时复用同一份实现 —— 两边对"不校验"的理解必须完全一致。
#[derive(Debug)]
pub struct SkipServerVerification;

impl ServerCertVerifier for SkipServerVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::ECDSA_NISTP384_SHA384,
            SignatureScheme::RSA_PSS_SHA256,
            SignatureScheme::RSA_PSS_SHA384,
            SignatureScheme::RSA_PSS_SHA512,
            SignatureScheme::RSA_PKCS1_SHA256,
            SignatureScheme::RSA_PKCS1_SHA384,
            SignatureScheme::RSA_PKCS1_SHA512,
        ]
    }

    fn requires_raw_public_keys(&self) -> bool {
        false
    }
}
