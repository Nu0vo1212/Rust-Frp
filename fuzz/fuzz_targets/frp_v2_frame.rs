#![no_main]

//! frp v2 帧 / Hello / 消息号解析 fuzz。
//!
//! 覆盖的公开入口：
//! * `wire::MAGIC_V2`（魔术字识别）
//! * `wire::FRAME_CLIENT_HELLO` / `FRAME_SERVER_HELLO` / `FRAME_MESSAGE` +
//!   `wire::ClientHello` / `wire::ServerHello` 的 JSON 解析
//! * `wire::validate_client_hello` / `wire::new_server_hello`
//! * `msg::FrpMessage::decode`（消息号 → 具体消息体）
//! * `msg::decode_udp_binary`
//!
//! 说明：`conn::take_frame`（8 字节帧头切帧）是 **私有函数**，这里按同样的
//! 布局做纯内存切帧，再交给上面这些 pub 入口。

use libfuzzer_sys::fuzz_target;
use nfrp_common::frp::{msg, wire};

fn decode_message_payload(payload: &[u8]) {
    if payload.len() < 2 {
        return;
    }
    let type_id = u16::from_be_bytes([payload[0], payload[1]]);
    let _ = msg::FrpMessage::decode(type_id, &payload[2..]);
    let _ = msg::decode_udp_binary(&payload[2..]);
}

fuzz_target!(|data: &[u8]| {
    // 魔术字：纯切片前缀比较。
    let _ = data.starts_with(wire::MAGIC_V2);

    // 直接把输入当成"消息帧载荷"：2 字节 type_id + JSON。
    decode_message_payload(data);

    // 按 v2 帧头布局切帧：type u16 | flags u16 | length u32（全大端）。
    if data.len() < 8 {
        return;
    }
    let frame_type = u16::from_be_bytes([data[0], data[1]]);
    let flags = u16::from_be_bytes([data[2], data[3]]);
    let len = u32::from_be_bytes([data[4], data[5], data[6], data[7]]) as usize;

    // 与 conn::take_frame 一致：flags 必须为 0，负载不得超过 MAX_FRAME_PAYLOAD。
    if flags != 0 || len > wire::MAX_FRAME_PAYLOAD || data.len() < 8 + len {
        return;
    }
    let payload = &data[8..8 + len];

    match frame_type {
        wire::FRAME_CLIENT_HELLO => {
            if let Ok(hello) = serde_json::from_slice::<wire::ClientHello>(payload) {
                let _ = wire::validate_client_hello(&hello);
                let _ = wire::new_server_hello(&hello);
            }
        }
        wire::FRAME_SERVER_HELLO => {
            let _ = serde_json::from_slice::<wire::ServerHello>(payload);
        }
        wire::FRAME_MESSAGE => decode_message_payload(payload),
        _ => {}
    }
});
