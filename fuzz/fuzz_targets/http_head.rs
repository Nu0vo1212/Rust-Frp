#![no_main]

//! HTTP/1 头部解析与请求走私判定 fuzz。
//!
//! 入口（全部为 common crate 的纯函数 / 纯结构）：
//! * `http1::parse` / `http1::parse_str` / `Request::params`
//! * `http_relay::HeadParts::parse` + `content_length_strict`
//! * `http_relay::validate_request_framing` / `validate_response_framing`
//! * `http_relay::is_chunked` / `transfer_encoding_tokens` /
//!   `transfer_encoding_is_unsupported` / `body_length` / `has_no_body`
//!
//! 另外用内存在 `HttpIo<Cursor<Vec<u8>>>` 上验证 `MAX_HEAD` 超限确实被拒
//! （不碰网络、不写文件）。

use libfuzzer_sys::fuzz_target;
use nfrp_common::{http1, http_relay};
use std::sync::Once;

static LIMITS: Once = Once::new();

/// 构造"恰好超过 MAX_HEAD"的头部，验证 `read_head_raw` 拒绝它。
fn check_head_limit_once() {
    LIMITS.call_once(|| {
        assert_eq!(http1::MAX_HEAD, http_relay::MAX_HEAD);

        let mut head = vec![b'a'; http_relay::MAX_HEAD + 1];
        let n = head.len();
        head[n - 4..].copy_from_slice(b"\r\n\r\n");
        let mut io = http_relay::HttpIo::new(std::io::Cursor::new(head));
        let res = futures::executor::block_on(io.read_head_raw());
        assert!(res.is_err(), "超过 MAX_HEAD 的 HTTP 头必须被拒绝");
    });
}

fuzz_target!(|data: &[u8]| {
    check_head_limit_once();

    // 面板侧的解析器（lossy，不 panic 是它的契约）。
    let _ = http1::parse(data);
    let text = String::from_utf8_lossy(data);
    let req = http1::parse_str(&text);
    let _ = req.params();
    let _ = req.content_length();
    let _ = req.header("content-length");
    let _ = req.headers_all("transfer-encoding");

    // 转发侧的头部结构：与 `HttpIo::read_head_raw` 相同的切行方式。
    let lines: Vec<String> = text
        .split("\r\n")
        .filter(|l| !l.is_empty())
        .map(|l| l.to_string())
        .collect();
    let Ok(parts) = http_relay::HeadParts::parse(&lines) else {
        return;
    };

    let _ = parts.content_length_strict();
    let _ = http_relay::body_length(&parts);
    let _ = http_relay::is_chunked(&parts);
    let _ = http_relay::transfer_encoding_tokens(&parts);
    let _ = http_relay::transfer_encoding_is_unsupported(&parts);
    let _ = http_relay::wants_keep_alive(&parts);
    let _ = http_relay::wants_upgrade(&parts);
    let _ = http_relay::has_no_body(&parts);
    let _ = http_relay::connection_tokens(&parts);
    let _ = parts.start_token(1);
    let _ = parts.to_bytes();

    let request_verdict = http_relay::validate_request_framing(&parts);
    let _ = http_relay::validate_response_framing(&parts);

    // 按现有语义：Content-Length 与 Transfer-Encoding 同时出现必须被拒。
    if parts.count("content-length") > 0 && parts.get("transfer-encoding").is_some() {
        assert!(
            request_verdict.is_err(),
            "Content-Length 与 Transfer-Encoding 同时出现时 validate_request_framing 必须拒绝"
        );
    }
});
