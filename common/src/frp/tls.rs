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
use tokio_rustls::{TlsAcceptor, TlsConnector};

use super::stream::{BoxStream, PrefixedStream};

/// frp 自定义首字节：`0x17` = TLS Application Data，用于把 frp 流量伪装成 TLS。
pub const FRP_TLS_HEAD_BYTE: u8 = 0x17;
/// 标准 TLS 握手的第一个字节（Handshake）。
const TLS_HANDSHAKE_BYTE: u8 = 0x16;

/// 探测首字节的等待时间，与 frp 的 `connReadTimeout` 对应。
const PROBE_TIMEOUT: Duration = Duration::from_secs(10);

/// TLS 握手阶段的总超时。
///
/// 原先 `accept_server` 对 rustls 握手**没有任何时限**：只发一个 `0x16`
/// （或 `0x17`）字节后静默，`TlsAcceptor::accept` 会永远等下去 ——
/// 实测（`tmp/audit9/c/c9_4_timeouts_tls.py`）：50s 后仍被挂住，
/// 且可线性囤积（500 条连接 +515 句柄 / +6.4MB，无一被清理）。
/// rustls 自己不做握手超时（协议层允许任意慢的来包），必须在调用侧加。
///
/// 取 30s 与登录握手的 `HANDSHAKE_TIMEOUT` 同口径：正常 TLS 握手是
/// 毫秒级（本地实测 <10ms），30s 足以覆盖高延迟链路，超时即断开。
const TLS_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(30);

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

/// 已经安装过的自定义 TLS 文件（用于热重载/重复启动时判断“是不是同一份”）。
static CONFIGURED_TLS_FILES: OnceLock<(String, String, String)> = OnceLock::new();

/// 启动时安装 `transport.tls.certFile/keyFile/trustedCaFile`。
///
/// 必须在任何 `accept_server()` 之前调用；否则 `server_config()` 会先安装
/// 自签名证书，之后再改就晚了。三者为空时保持官方默认（自签名、不校验客户端）。
///
/// `trusted_ca_file` 非空 = 启用 mTLS：客户端必须出示由该 CA 签发的证书。
///
/// 同一份配置重复调用是幂等的（热重载/测试会重复进入）；换成另一组文件则
/// 明确报错 —— rustls 的 `ServerConfig` 是本进程全局的，不能悄悄换掉旧连接
/// 还在用的配置。
pub fn configure_server_tls(cert_file: &str, key_file: &str, trusted_ca_file: &str) -> Result<()> {
    if cert_file.trim().is_empty()
        && key_file.trim().is_empty()
        && trusted_ca_file.trim().is_empty()
    {
        return Ok(());
    }
    if cert_file.trim().is_empty() || key_file.trim().is_empty() {
        bail!("transport.tls.certFile 与 keyFile 必须同时配置（当前只配了一个）");
    }
    let wanted = (
        cert_file.to_string(),
        key_file.to_string(),
        trusted_ca_file.to_string(),
    );
    if let Some(existing) = CONFIGURED_TLS_FILES.get() {
        if existing == &wanted {
            return Ok(());
        }
        bail!(
            "服务端 TLS 配置已用另一组 certFile/keyFile/trustedCaFile 初始化，\
             本进程内不能热切换证书；请重启进程"
        );
    }
    let cfg = server_config_from_pem_with_ca(cert_file, key_file, trusted_ca_file)?;
    SERVER_TLS_CONFIG
        .set(cfg)
        .map_err(|_| anyhow!("服务端 TLS 配置已经初始化，不能再更换 certFile/keyFile"))?;
    let _ = CONFIGURED_TLS_FILES.set(wanted);
    Ok(())
}

/// 只校验证书文件是否能装载，不安装到进程全局（给 `--check` / 预检用）。
pub fn validate_server_tls_files(
    cert_file: &str,
    key_file: &str,
    trusted_ca_file: &str,
) -> Result<()> {
    if cert_file.trim().is_empty() && key_file.trim().is_empty() {
        if !trusted_ca_file.trim().is_empty() {
            bail!("配置了 transport.tls.trustedCaFile，但没有 certFile/keyFile");
        }
        return Ok(());
    }
    if cert_file.trim().is_empty() || key_file.trim().is_empty() {
        bail!("transport.tls.certFile 与 keyFile 必须同时配置（当前只配了一个）");
    }
    let _ = server_config_from_pem_with_ca(cert_file, key_file, trusted_ca_file)?;
    Ok(())
}

/// 客户端 TLS 配置：与 frp 默认行为一致，不校验服务端证书。
///
/// 保留这个默认，但**新增**
/// [`client_config_verifying`] 提供"真正校验"的可选路径。
///
/// # 为什么默认不改
///
/// 官方 frp 的 `transport.tls.enable = true` **默认不校验对端证书**
/// （`InsecureSkipVerify = true`）。改了默认会让"官方 frpc ↔ NFrp frps"
/// 这条零配置互通链路直接断掉 —— 而 README 明确承诺了它。
/// 这是**设计取舍**，不是遗漏（报告也这么定位）。
///
/// # 但必须给用户一条更安全的路
///
/// 现状的问题是"用户**没有选择**"：想校验也做不到。
/// 同项目的 `httpc`（OIDC 那边）默认是**校验**的 —— 同一个仓库两套默认，
/// 而其中一套无法切换。本函数补上那个开关。
pub fn client_config() -> Result<Arc<rustls::ClientConfig>> {
    let cfg = rustls::ClientConfig::builder_with_provider(crypto_provider())
        .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])
        .map_err(|e| anyhow!("TLS 协议版本配置失败：{e}"))?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(SkipServerVerification))
        .with_no_client_auth();
    Ok(Arc::new(cfg))
}

/// 客户端 TLS 配置：**校验服务端证书**。
///
/// 用系统根证书 + 可选的额外信任 CA（`trustedCaFile`）。
/// 与 [`client_config`] 的区别只有"验不验证书"。
///
/// # 什么时候用
///
/// * 服务端用的是**受信任 CA 签发的证书**（Let's Encrypt 等）⇒ 直接可用；
/// * 服务端用**自签证书** ⇒ 把该证书填进 `transport.tls.trustedCaFile`，
///   同时 `tlsServerName` 要能对上证书里的名字。
///
/// 注意：开了校验之后，**官方 frpc 默认连不上**（它不校验，但也不提供
///   证书给你）—— 所以这个开关是给"自有客户端 + 自有服务端"的部署用的。
///   双方都配好 CA 即可。
pub fn client_config_verifying(
    trusted_ca_file: &str,
    server_name: &str,
    client_cert_file: &str,
    client_key_file: &str,
) -> Result<Arc<rustls::ClientConfig>> {
    let mut roots = rustls::RootCertStore::empty();

    // 内置的公开根证书（与 `httpc` 用同一份 `webpki-roots`，
    // 避免"同一个仓库两套根证书来源"）。
    //
    // 不引 `rustls-native-certs`：它会读系统信任库（Windows 证书store /
    //   Linux ca-certificates），覆盖面更广，但**多一个依赖 + 平台差异**；
    //   而本项目已有的 `httpc` 走的就是 `webpki-roots`。保持一致更重要 ——
    //   自签场景本来就必须配 `trustedCaFile`，那时系统根证书帮不上忙。
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    tracing::debug!(
        count = roots.len(),
        "已装载内置公开根证书（自签服务端请配 transport.tls.trustedCaFile）"
    );

    // 用户额外指定的 CA（自签服务端必填）
    if !trusted_ca_file.trim().is_empty() {
        let blocks = read_pem_blocks(trusted_ca_file)?;
        let mut n = 0usize;
        for (_label, der) in blocks.iter().filter(|(l, _)| l == "CERTIFICATE") {
            roots
                .add(rustls::pki_types::CertificateDer::from(der.clone()))
                .with_context(|| format!("{trusted_ca_file} 里的第 {} 个证书无法解析", n + 1))?;
            n += 1;
        }
        if n == 0 {
            bail!("{trusted_ca_file} 里没有 CERTIFICATE 块（可能只给了私钥？）");
        }
        tracing::debug!(count = n, path = %trusted_ca_file, "已装载额外信任 CA");
    }

    if roots.is_empty() {
        bail!(
            "要校验对端证书，但一个可信 CA 都没有：\
             内置根证书为空，且没配 transport.tls.trustedCaFile。\
             自签服务端请把其证书填进 trustedCaFile"
        );
    }

    let builder = rustls::ClientConfig::builder_with_provider(crypto_provider())
        .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])
        .map_err(|e| anyhow!("TLS 协议版本配置失败：{e}"))?
        .with_root_certificates(roots);
    let cfg = match load_client_identity(client_cert_file, client_key_file)? {
        Some((certs, key)) => builder
            .with_client_auth_cert(certs, key)
            .context("装载客户端证书失败（检查 certFile/keyFile）")?,
        None => builder.with_no_client_auth(),
    };

    if !server_name.trim().is_empty() {
        tracing::debug!(server_name, "TLS 将校验该名字");
    }
    Ok(Arc::new(cfg))
}

/// 不校验服务端证书，但**出示客户端证书**（mTLS 服务端 + 不自签校验场景）。
pub fn client_config_with_identity(
    client_cert_file: &str,
    client_key_file: &str,
) -> Result<Arc<rustls::ClientConfig>> {
    let builder = rustls::ClientConfig::builder_with_provider(crypto_provider())
        .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])
        .map_err(|e| anyhow!("TLS 协议版本配置失败：{e}"))?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(SkipServerVerification));
    let cfg = match load_client_identity(client_cert_file, client_key_file)? {
        Some((certs, key)) => builder
            .with_client_auth_cert(certs, key)
            .context("装载客户端证书失败（检查 certFile/keyFile）")?,
        None => builder.with_no_client_auth(),
    };
    Ok(Arc::new(cfg))
}

/// 读 PEM 文件，返回 `(块标签, DER 字节)` 的列表，顺序保留。
///
/// 标签是 `CERTIFICATE` / `PRIVATE KEY` / `RSA PRIVATE KEY` / `EC PRIVATE KEY` 这类
/// BEGIN 行里的那个词。**按标签区分私钥格式是必须的** —— 三种格式的 DER 结构不同，
/// 猜错会在握手时才报一个和文件内容完全无关的错。
///
/// 这里是**唯一**一处解析 PEM 的地方：客户端插件的 `crtPath` / `keyPath`
/// 和 OIDC 的 `trustedCaFile` 都走它，省得两处对"什么算合法 PEM"理解不一致。
pub fn read_pem_blocks(path: &str) -> Result<Vec<(String, Vec<u8>)>> {
    use base64::{engine::general_purpose::STANDARD, Engine as _};
    let text =
        std::fs::read_to_string(path).with_context(|| format!("读取 PEM 文件 {path} 失败"))?;
    let mut out = Vec::new();
    let mut label: Option<String> = None;
    let mut b64 = String::new();
    for line in text.lines() {
        let l = line.trim();
        if let Some(rest) = l.strip_prefix("-----BEGIN ") {
            let name = rest.trim_end_matches('-').trim().to_string();
            label = Some(name);
            b64.clear();
            continue;
        }
        if l.starts_with("-----END ") {
            if let Some(name) = label.take() {
                let der = STANDARD
                    .decode(b64.as_bytes())
                    .map_err(|e| anyhow!("PEM 文件 {path} 的 {name} 块不是合法 base64：{e}"))?;
                out.push((name, der));
            }
            continue;
        }
        if label.is_some() {
            b64.push_str(l);
        }
    }
    if out.is_empty() {
        bail!("PEM 文件 {path} 里没有找到任何 -----BEGIN ...----- 块");
    }
    Ok(out)
}

/// 装载证书链（PEM 中的全部 `CERTIFICATE` 块）。
fn load_pem_cert_chain(path: &str) -> Result<Vec<CertificateDer<'static>>> {
    let certs: Vec<CertificateDer<'static>> = read_pem_blocks(path)?
        .into_iter()
        .filter(|(label, _)| label.eq_ignore_ascii_case("CERTIFICATE"))
        .map(|(_, der)| CertificateDer::from(der))
        .collect();
    if certs.is_empty() {
        bail!("证书文件 {path} 里没有 CERTIFICATE 块");
    }
    Ok(certs)
}

/// 装载私钥（PKCS#8 / PKCS#1 / SEC1）。
fn load_pem_private_key(path: &str) -> Result<PrivateKeyDer<'static>> {
    let (label, der) = read_pem_blocks(path)?
        .into_iter()
        .find(|(label, _)| label.to_ascii_uppercase().contains("PRIVATE KEY"))
        .ok_or_else(|| anyhow!("私钥文件 {path} 里没有 PRIVATE KEY 块"))?;
    Ok(match label.to_ascii_uppercase().as_str() {
        "PRIVATE KEY" => PrivateKeyDer::Pkcs8(der.into()),
        "RSA PRIVATE KEY" => PrivateKeyDer::Pkcs1(der.into()),
        "EC PRIVATE KEY" => PrivateKeyDer::Sec1(der.into()),
        other => bail!("私钥文件 {path} 的块类型 {other} 不认识"),
    })
}

/// 客户端证书 + 私钥；两个都空返回 `None`，只配一个直接报错。
fn load_client_identity(
    cert_file: &str,
    key_file: &str,
) -> Result<Option<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>)>> {
    let cert_empty = cert_file.trim().is_empty();
    let key_empty = key_file.trim().is_empty();
    if cert_empty && key_empty {
        return Ok(None);
    }
    if cert_empty || key_empty {
        bail!("transport.tls.certFile 与 keyFile 必须同时配置（当前只配了一个）");
    }
    Ok(Some((
        load_pem_cert_chain(cert_file)?,
        load_pem_private_key(key_file)?,
    )))
}

/// 从 PEM 文件构造服务端 TLS 配置（对应官方 frp 的 `transport.NewServerTLSConfig`）。
///
/// 用于客户端的 `https2http` / `https2https` / `tls2raw` 三个插件 —— 它们在
/// frpc 这一侧**终止** TLS，所以要拿用户给的证书自己当 TLS 服务端
/// （frp 的 https 代理与之相反：服务端只嗅探 SNI，不终止 TLS）。
pub fn server_config_from_pem(crt_path: &str, key_path: &str) -> Result<Arc<rustls::ServerConfig>> {
    server_config_from_pem_with_ca(crt_path, key_path, "")
}

/// 服务端证书 + 可选客户端 CA（`trustedCaFile`，mTLS）。
pub fn server_config_from_pem_with_ca(
    crt_path: &str,
    key_path: &str,
    trusted_ca_file: &str,
) -> Result<Arc<rustls::ServerConfig>> {
    let certs = load_pem_cert_chain(crt_path)?;
    let key = load_pem_private_key(key_path)?;

    let builder = rustls::ServerConfig::builder_with_provider(crypto_provider())
        .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])
        .map_err(|e| anyhow!("TLS 协议版本配置失败：{e}"))?;

    let cfg = if trusted_ca_file.trim().is_empty() {
        builder
            .with_no_client_auth()
            .with_single_cert(certs, key)
            .with_context(|| format!("装载证书 {crt_path} + 私钥 {key_path} 失败"))?
    } else {
        let mut roots = rustls::RootCertStore::empty();
        let mut n = 0usize;
        for (_label, der) in read_pem_blocks(trusted_ca_file)?
            .into_iter()
            .filter(|(l, _)| l.eq_ignore_ascii_case("CERTIFICATE"))
        {
            roots.add(CertificateDer::from(der)).with_context(|| {
                format!("{trusted_ca_file} 里的第 {} 张 CA 证书无法解析", n + 1)
            })?;
            n += 1;
        }
        if n == 0 {
            bail!("{trusted_ca_file} 里没有 CERTIFICATE 块（trustedCaFile 必须是 CA 证书）");
        }
        let verifier = rustls::server::WebPkiClientVerifier::builder_with_provider(
            Arc::new(roots),
            crypto_provider(),
        )
        .build()
        .context("构造客户端证书校验器失败")?;
        builder
            .with_client_cert_verifier(verifier)
            .with_single_cert(certs, key)
            .with_context(|| format!("装载证书 {crt_path} + 私钥 {key_path} 失败"))?
    };
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
            // 握手必须有总时限，否则单字节就能永久占住一条连接。
            let tls = tokio::time::timeout(TLS_HANDSHAKE_TIMEOUT, acceptor.accept(stream))
                .await
                .context("TLS 服务端握手超时")?
                .context("TLS 服务端握手失败")?;
            Ok(Box::pin(tls))
        }
        TLS_HANDSHAKE_BYTE => {
            let acceptor = TlsAcceptor::from(server_config()?);
            let tls = tokio::time::timeout(
                TLS_HANDSHAKE_TIMEOUT,
                acceptor.accept(PrefixedStream::new(vec![first[0]], stream)),
            )
            .await
            .context("TLS 服务端握手超时")?
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

/// 客户端 TLS 选项（参数太多，收成一个结构体，避免调用点按位置猜）。
#[derive(Debug, Clone, Copy)]
pub struct ClientTlsOptions<'a> {
    /// 是否启用 TLS（`transport.tls.enable`）。
    pub enable: bool,
    /// SNI / 证书校验名（`tlsServerName`）。
    pub server_name: &'a str,
    /// 是否禁用 frp 自定义首字节（`disableCustomTLSFirstByte`）。
    pub disable_custom_first_byte: bool,
    /// 是否校验服务端证书（`verifyServerCert`）。
    pub verify: bool,
    /// 额外信任的 CA（`trustedCaFile`）。
    pub trusted_ca_file: &'a str,
    /// 客户端证书（`certFile`，mTLS）。
    pub client_cert_file: &'a str,
    /// 客户端私钥（`keyFile`，mTLS）。
    pub client_key_file: &'a str,
}

/// 客户端：按需发送 frp 自定义首字节并发起 TLS 握手。
///
/// `verify = false` 走与官方一致的"不校验"（保互通），
/// `true` 走真正校验（需要 `trustedCaFile` 配合自签场景）。
pub async fn connect_client<S>(mut stream: S, opts: &ClientTlsOptions<'_>) -> Result<BoxStream>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    if !opts.enable {
        return Ok(Box::pin(stream));
    }
    if !opts.disable_custom_first_byte {
        tokio::io::AsyncWriteExt::write_all(&mut stream, &[FRP_TLS_HEAD_BYTE])
            .await
            .context("发送 frp 自定义首字节失败")?;
    }
    let name = to_server_name(opts.server_name)?;
    let has_identity =
        !opts.client_cert_file.trim().is_empty() || !opts.client_key_file.trim().is_empty();
    let cfg = if opts.verify {
        client_config_verifying(
            opts.trusted_ca_file,
            opts.server_name,
            opts.client_cert_file,
            opts.client_key_file,
        )?
    } else if has_identity {
        client_config_with_identity(opts.client_cert_file, opts.client_key_file)?
    } else {
        client_config()?
    };
    let connector = TlsConnector::from(cfg);
    let tls = connector
        .connect(name, stream)
        .await
        .context(if opts.verify {
            "TLS 客户端握手失败（已开启证书校验 —— 若是自签服务端，\
             请把其证书填进 transport.tls.trustedCaFile，\
             并确认 tlsServerName 与证书里的名字一致）"
        } else {
            "TLS 客户端握手失败"
        })?;
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

#[cfg(test)]
mod tests {
    use super::*;

    fn write_self_signed(dir: &std::path::Path) -> (String, String) {
        let ck = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
        let cert = dir.join("cert.pem");
        let key = dir.join("key.pem");
        std::fs::write(&cert, ck.cert.pem()).unwrap();
        std::fs::write(&key, ck.key_pair.serialize_pem()).unwrap();
        (
            cert.to_string_lossy().into_owned(),
            key.to_string_lossy().into_owned(),
        )
    }

    fn temp_dir(tag: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!(
            "nfrp-tls-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    /// 生成一套真实的 CA / 服务端 / 客户端证书，用于**握手**测试，而不是只
    /// 构造 `ServerConfig`。返回值顺序：服务端 cert、服务端 key、客户端 cert、
    /// 客户端 key、CA cert。
    fn write_mtls_pki(dir: &std::path::Path) -> (String, String, String, String, String) {
        use rcgen::{
            BasicConstraints, CertificateParams, ExtendedKeyUsagePurpose, IsCa, KeyPair,
            KeyUsagePurpose,
        };

        let ca_key = KeyPair::generate().unwrap();
        let mut ca_params = CertificateParams::new(vec!["nfrp-test-ca".to_string()]).unwrap();
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        ca_params.key_usages = vec![
            KeyUsagePurpose::KeyCertSign,
            KeyUsagePurpose::CrlSign,
            KeyUsagePurpose::DigitalSignature,
        ];
        let ca_cert = ca_params.self_signed(&ca_key).unwrap();

        let server_key = KeyPair::generate().unwrap();
        let mut server_params = CertificateParams::new(vec!["localhost".to_string()]).unwrap();
        server_params
            .extended_key_usages
            .push(ExtendedKeyUsagePurpose::ServerAuth);
        let server_cert = server_params
            .signed_by(&server_key, &ca_cert, &ca_key)
            .unwrap();

        let client_key = KeyPair::generate().unwrap();
        let mut client_params =
            CertificateParams::new(vec!["nfrp-test-client".to_string()]).unwrap();
        client_params
            .extended_key_usages
            .push(ExtendedKeyUsagePurpose::ClientAuth);
        let client_cert = client_params
            .signed_by(&client_key, &ca_cert, &ca_key)
            .unwrap();

        let sc = dir.join("server.pem");
        let sk = dir.join("server-key.pem");
        let cc = dir.join("client.pem");
        let ck = dir.join("client-key.pem");
        let ca = dir.join("ca.pem");
        std::fs::write(&sc, server_cert.pem()).unwrap();
        std::fs::write(&sk, server_key.serialize_pem()).unwrap();
        std::fs::write(&cc, client_cert.pem()).unwrap();
        std::fs::write(&ck, client_key.serialize_pem()).unwrap();
        std::fs::write(&ca, ca_cert.pem()).unwrap();
        (
            sc.to_string_lossy().into_owned(),
            sk.to_string_lossy().into_owned(),
            cc.to_string_lossy().into_owned(),
            ck.to_string_lossy().into_owned(),
            ca.to_string_lossy().into_owned(),
        )
    }

    /// 内存里对拉 rustls 两端，返回是否握手成功。不做 socket，避免端口/时序干扰。
    fn drive_tls_handshake(
        client: &mut rustls::ClientConnection,
        server: &mut rustls::ServerConnection,
    ) -> bool {
        let mut c2s = Vec::new();
        let mut s2c = Vec::new();
        for _ in 0..32 {
            c2s.clear();
            while client.wants_write() {
                if client.write_tls(&mut c2s).is_err() {
                    return false;
                }
            }
            if !c2s.is_empty() {
                let mut r = &c2s[..];
                if server.read_tls(&mut r).is_err() || server.process_new_packets().is_err() {
                    return false;
                }
            }

            s2c.clear();
            while server.wants_write() {
                if server.write_tls(&mut s2c).is_err() {
                    return false;
                }
            }
            if !s2c.is_empty() {
                let mut r = &s2c[..];
                if client.read_tls(&mut r).is_err() || client.process_new_packets().is_err() {
                    return false;
                }
            }

            if !client.is_handshaking() && !server.is_handshaking() {
                return true;
            }
        }
        false
    }

    #[test]
    fn server_config_from_pem_loads_custom_cert() {
        let d = temp_dir("server");
        let (cert, key) = write_self_signed(&d);
        assert!(server_config_from_pem(&cert, &key).is_ok());
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn server_config_from_pem_with_ca_builds_mtls_verifier() {
        let d = temp_dir("mtls");
        let (cert, key) = write_self_signed(&d);
        // 用同一张自签证书当 CA，仅验证 verifier 能构造；不验证握手链。
        assert!(server_config_from_pem_with_ca(&cert, &key, &cert).is_ok());
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn mtls_handshake_accepts_valid_client_cert_and_rejects_missing_one() {
        let d = temp_dir("mtls-handshake");
        let (sc, sk, cc, ck, ca) = write_mtls_pki(&d);

        let server_cfg = server_config_from_pem_with_ca(&sc, &sk, &ca).unwrap();
        let client_cfg = client_config_verifying(&ca, "localhost", &cc, &ck).unwrap();
        let mut server = rustls::ServerConnection::new(server_cfg).unwrap();
        let mut client =
            rustls::ClientConnection::new(client_cfg, ServerName::try_from("localhost").unwrap())
                .unwrap();
        assert!(
            drive_tls_handshake(&mut client, &mut server),
            "带合法客户端证书的 mTLS 握手应成功"
        );
        assert_eq!(
            server.peer_certificates().map(|c| c.len()),
            Some(1),
            "服务端应拿到一张客户端证书"
        );

        // 同一个 mTLS 服务端配置，客户端不带证书：必须在握手阶段失败。
        let server_cfg = server_config_from_pem_with_ca(&sc, &sk, &ca).unwrap();
        let no_identity_cfg = client_config_verifying(&ca, "localhost", "", "").unwrap();
        let mut server = rustls::ServerConnection::new(server_cfg).unwrap();
        let mut client = rustls::ClientConnection::new(
            no_identity_cfg,
            ServerName::try_from("localhost").unwrap(),
        )
        .unwrap();
        assert!(
            !drive_tls_handshake(&mut client, &mut server),
            "没有客户端证书时，mTLS 握手必须失败"
        );

        // 客户端证书由另一套 CA 签发：服务端也必须拒绝。
        let other = temp_dir("mtls-wrong-ca");
        let (_other_sc, _other_sk, other_cc, other_ck, _other_ca) = write_mtls_pki(&other);
        let wrong_ca_cfg = client_config_verifying(&ca, "localhost", &other_cc, &other_ck).unwrap();
        let server_cfg = server_config_from_pem_with_ca(&sc, &sk, &ca).unwrap();
        let mut server = rustls::ServerConnection::new(server_cfg).unwrap();
        let mut client =
            rustls::ClientConnection::new(wrong_ca_cfg, ServerName::try_from("localhost").unwrap())
                .unwrap();
        assert!(
            !drive_tls_handshake(&mut client, &mut server),
            "客户端证书由错误 CA 签发时，mTLS 握手必须失败"
        );

        let _ = std::fs::remove_dir_all(&d);
        let _ = std::fs::remove_dir_all(&other);
    }

    #[test]
    fn client_identity_requires_both_files() {
        assert!(load_client_identity("", "").unwrap().is_none());
        assert!(load_client_identity("cert.pem", "").is_err());
        assert!(load_client_identity("", "key.pem").is_err());
    }

    #[test]
    fn client_config_verifying_loads_ca_and_identity() {
        let d = temp_dir("client");
        let (cert, key) = write_self_signed(&d);
        assert!(client_config_verifying(&cert, "localhost", &cert, &key).is_ok());
        assert!(client_config_with_identity(&cert, &key).is_ok());
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn validate_rejects_half_configured_cert() {
        assert!(validate_server_tls_files("cert.pem", "", "").is_err());
        assert!(validate_server_tls_files("", "", "ca.pem").is_err());
        assert!(validate_server_tls_files("", "", "").is_ok());
    }

    #[test]
    fn configure_tls_is_idempotent_for_same_files() {
        let d = temp_dir("configure");
        let (cert, key) = write_self_signed(&d);
        assert!(configure_server_tls(&cert, &key, "").is_ok());
        assert!(
            configure_server_tls(&cert, &key, "").is_ok(),
            "同一份配置重复进入（热重载/测试）必须幂等"
        );
        assert!(
            configure_server_tls(&cert, &key, "another-ca.pem").is_err(),
            "换另一组文件必须明确报错，不能悄悄替换全局 TLS 配置"
        );
        let _ = std::fs::remove_dir_all(&d);
    }
}
