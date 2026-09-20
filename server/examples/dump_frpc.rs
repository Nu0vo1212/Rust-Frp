//! 「假 frps」抓包工具：把官方 frpc 发来的控制消息**原样**打印成 JSON。
//!
//! # 为什么需要它
//!
//! 和第三方 frp 平台（LoliaFRP / OpenFrp / SakuraFrp …）对接时，光看文档
//! 或读 frp 的 Go 源码都不够 —— 各版本之间字段差异很大，服务端到底在校验
//! 什么、客户端到底发了什么，只有抓下来看最准。
//!
//! 好消息是 rustunnel 自己实现了完整的 frp v2 握手与 AES-GCM 控制通道，
//! 所以只要把它当成一个"假 frps"，就能把 frpc 的明文消息直接读出来，
//! 不需要证书、也不需要中间人。
//!
//! # 用法
//!
//! ```text
//! cargo run -p rustunnel-server --example dump_frpc -- 17777
//! ```
//!
//! 然后把待测 frpc 的 `serverAddr` / `serverPort` 改成 `127.0.0.1:17777` 跑起来。
//! token 故意留空 —— 与多数 frp 平台的服务端一致（它们靠 `metas` 认隧道）。

use rustunnel_common::frp::{
    msg::{self, FrpMessage},
    server_handshake, wire, FrpConn, ServerAccept,
};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let port: u16 = std::env::args()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(17777);
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", port)).await?;
    println!("[dump_frpc] 假 frps 已监听 127.0.0.1:{port}（token 留空，接受任意 frpc）");
    println!("[dump_frpc] 把待测 frpc 的 serverAddr 改成 127.0.0.1、serverPort 改成 {port}");

    loop {
        let (stream, peer) = match listener.accept().await {
            Ok(v) => v,
            Err(e) => {
                println!("[dump_frpc] accept 失败：{e}");
                continue;
            }
        };
        println!("\n===== 新连接：{peer} =====");

        let stream: rustunnel_common::frp::BoxStream = Box::pin(stream);
        let mut conn = match server_handshake(stream, "", "dump-run-id").await {
            Ok(ServerAccept::Control {
                conn,
                login,
                udp_binary,
                caps: _caps,
            }) => {
                println!("[Login] {login:?}");
                println!("[Login] udp_binary={udp_binary}（ClientHello 协商出的报文编码）");
                conn
            }
            Ok(ServerAccept::Work { conn, msg }) => {
                println!("[NewWorkConn] {msg:?}");
                conn
            }
            Ok(ServerAccept::Visitor { conn, msg }) => {
                println!("[NewVisitorConn] {msg:?}");
                conn
            }
            Err(e) => {
                println!("[dump_frpc] 握手失败：{e:#}");
                continue;
            }
        };

        dump_session(&mut conn).await;
        println!("===== 连接结束 =====");
    }
}

/// 逐帧读取并打印。
///
/// 用 `read_frame` 而不是 `recv_msg`：后者按 rustunnel 自己的结构体反序列化，
/// **会丢掉我们不认识、但服务端可能要求的字段**，而这次的目的恰恰是看清
/// "到底有哪些字段"。所以这里拿原始 JSON 字节直接打。
async fn dump_session(conn: &mut FrpConn) {
    loop {
        let got = match conn.read_frame().await {
            Ok(v) => v,
            Err(e) => {
                println!("[dump_frpc] 读帧失败：{e:#}");
                return;
            }
        };
        let Some((ft, payload)) = got else {
            println!("[dump_frpc] 对端关闭连接");
            return;
        };
        if ft != wire::FRAME_MESSAGE || payload.len() < 2 {
            println!("[dump_frpc] 非消息帧 ft={ft} len={}", payload.len());
            continue;
        }
        let msg_type = u16::from_be_bytes([payload[0], payload[1]]);
        let body = String::from_utf8_lossy(&payload[2..]);
        println!(
            "[msg_type={msg_type} {}] {}",
            type_name(msg_type),
            body.trim()
        );

        // 让会话活着：frpc 会发 Ping，不回 Pong 它会重连
        if msg_type == msg::TYPE_PING {
            let _ = conn.send_msg(&FrpMessage::Pong(Default::default())).await;
        }
    }
}

fn type_name(t: u16) -> &'static str {
    match t {
        msg::TYPE_LOGIN => "Login",
        msg::TYPE_LOGIN_RESP => "LoginResp",
        msg::TYPE_NEW_PROXY => "NewProxy",
        msg::TYPE_NEW_PROXY_RESP => "NewProxyResp",
        msg::TYPE_CLOSE_PROXY => "CloseProxy",
        msg::TYPE_NEW_WORK_CONN => "NewWorkConn",
        msg::TYPE_REQ_WORK_CONN => "ReqWorkConn",
        msg::TYPE_START_WORK_CONN => "StartWorkConn",
        msg::TYPE_NEW_VISITOR_CONN => "NewVisitorConn",
        msg::TYPE_NEW_VISITOR_CONN_RESP => "NewVisitorConnResp",
        msg::TYPE_PING => "Ping",
        msg::TYPE_PONG => "Pong",
        msg::TYPE_UDP_PACKET => "UdpPacket",
        msg::TYPE_NAT_HOLE_VISITOR => "NatHoleVisitor",
        msg::TYPE_NAT_HOLE_CLIENT => "NatHoleClient",
        msg::TYPE_NAT_HOLE_RESP => "NatHoleResp",
        msg::TYPE_NAT_HOLE_SID => "NatHoleSid",
        msg::TYPE_NAT_HOLE_REPORT => "NatHoleReport",
        _ => "其他",
    }
}
