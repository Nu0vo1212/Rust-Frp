#![no_main]

//! frp v1 帧解析 fuzz。
//!
//! 真实入口：`nfrp_common::frp::v1::take_msg`（`[type u8][i64 大端长度][json]`），
//! 以及 `type_byte` / `type_id` 映射。断言恶意长度不会 panic、也不会触发超大分配。

use libfuzzer_sys::fuzz_target;
use nfrp_common::frp::v1;
use std::sync::Once;

static LIMITS: Once = Once::new();

fuzz_target!(|data: &[u8]| {
    LIMITS.call_once(|| {
        // 合法帧往返。
        let frame = v1::encode_msg(v1::TYPE_PING, b"{}");
        let mut buf = frame;
        let (ty, body) = v1::take_msg(&mut buf)
            .expect("合法帧必须解析成功")
            .expect("合法帧不应被判定为数据不足");
        assert_eq!(ty, v1::TYPE_PING);
        assert_eq!(body, b"{}");
        assert!(buf.is_empty());

        // i64::MAX 的声明长度：必须在读负载之前就被拒绝。
        let mut huge = vec![v1::TYPE_LOGIN];
        huge.extend_from_slice(&i64::MAX.to_be_bytes());
        assert!(v1::take_msg(&mut huge).is_err(), "超大长度必须被拒绝");

        // 负长度同样拒绝。
        let mut neg = vec![v1::TYPE_LOGIN];
        neg.extend_from_slice(&(-1i64).to_be_bytes());
        assert!(v1::take_msg(&mut neg).is_err(), "负长度必须被拒绝");
    });

    let mut buf = data.to_vec();
    let _ = v1::take_msg(&mut buf);

    let pair = [
        data.first().copied().unwrap_or(0),
        data.get(1).copied().unwrap_or(0),
    ];
    let _ = v1::type_byte(u16::from_be_bytes(pair));
    let _ = v1::type_id(data.first().copied().unwrap_or(0));
});
