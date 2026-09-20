//! KCP：跑在 UDP 上的可靠有序传输，作为 xtcp 在弱网下的**备选**数据通道。
//!
//! ## 为什么还要一个 KCP
//!
//! QUIC 很完善，但它的重传策略是为"公网 + 中等丢包"设计的：丢一个包要等
//! RTO（至少 200ms 量级）才重传，而且按**包号**判定丢包。移动网络 / 跨国链路
//! 上丢包率能到 5%~20%，这时 QUIC 的吞吐会被重传等待拖垮。
//!
//! KCP 换了个思路，牺牲带宽换延迟：
//!
//! * **选择性重传**：收到 `sn=3` 而 `sn=1` 没到，立刻给 `sn=1` 记一次
//!   `fastack`；攒够 [`IKCP_FASTACK_LIMIT`] 次就**不等 RTO**直接重传；
//! * **更密的 `update`**：默认 10ms 一跳，丢包能被更早发现；
//! * **可关拥塞控制**：`nodelay` 打开后窗口不再因丢包腰斩。
//!
//! 代价是 KCP 不加密。P2P 场景里这一点可以接受 —— 通道建立后还有一层
//! 应用口令鉴权（与 QUIC 侧完全一致），口令不对的连接会被立刻关掉。
//!
//! ## 实现范围
//!
//! 这是 `ikcp` / `kcp-go` 的精简移植，**只做 Rust 侧两端都用得到的部分**：
//! 分片与重组、UNA + ACK、快速重传、RTO 计算、窗口探测。
//! 没做 FEC（kcp-go 里也是可选）和流控的 `nocwnd` 之外的调优开关。
//! 两端都是 rustunnel，所以不需要与 kcp-go 的字节流严格对齐。

use std::collections::VecDeque;

use bytes::Bytes;
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    net::UdpSocket,
    sync::mpsc::{self, UnboundedReceiver, UnboundedSender},
    time::interval,
};

// ---------------------------------------------------------------------------
// 常量（ikcp.go）
// ---------------------------------------------------------------------------

const IKCP_RTO_NDL: u32 = 30; // no delay min rto
const IKCP_RTO_MIN: u32 = 100; // normal min rto
const IKCP_RTO_DEF: u32 = 200;
const IKCP_RTO_MAX: u32 = 60_000;

const IKCP_CMD_PUSH: u8 = 81; // cmd: push data
const IKCP_CMD_ACK: u8 = 82; // cmd: ack
const IKCP_CMD_WASK: u8 = 83; // cmd: window probe (ask)
const IKCP_CMD_WINS: u8 = 84; // cmd: window size (tell)
const IKCP_ASK_SEND: u32 = 1; // need to send IKCP_CMD_WASK
const IKCP_ASK_TELL: u32 = 2; // need to send IKCP_CMD_WINS

const IKCP_WND_SND: u32 = 32;
const IKCP_WND_RCV: u32 = 128;
const IKCP_MTU_DEF: usize = 1400;
const IKCP_INTERVAL: u32 = 10;
const IKCP_OVERHEAD: usize = 24;
const IKCP_FASTACK_LIMIT: u32 = 5;
const IKCP_THRESH_INIT: u32 = 2;
const IKCP_THRESH_MIN: u32 = 2;
const IKCP_PROBE_INIT: u32 = 7000;
const IKCP_PROBE_LIMIT: u32 = 120_000;

/// 报文头长度：conv(4) cmd(1) frg(1) wnd(2) ts(4) sn(4) una(4) len(4)。
const HEADER: usize = IKCP_OVERHEAD;

// ---------------------------------------------------------------------------
// 段（ikcp_seg）
// ---------------------------------------------------------------------------

#[derive(Clone, Debug)]
struct Seg {
    conv: u32,
    cmd: u8,
    frg: u8,
    wnd: u16,
    ts: u32,
    sn: u32,
    una: u32,
    data: Vec<u8>,
    /// 下次重传的时间戳。
    resendts: u32,
    /// 该段的重传超时。
    rto: u32,
    /// 被"跳过的 ACK"计数：达到上限就触发快速重传。
    fastack: u32,
    /// 已发送次数。
    xmit: u32,
}

impl Seg {
    fn new(data: Vec<u8>) -> Self {
        Self {
            conv: 0,
            cmd: 0,
            frg: 0,
            wnd: 0,
            ts: 0,
            sn: 0,
            una: 0,
            data,
            resendts: 0,
            rto: 0,
            fastack: 0,
            xmit: 0,
        }
    }

    fn encode(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.conv.to_le_bytes());
        out.push(self.cmd);
        out.push(self.frg);
        out.extend_from_slice(&self.wnd.to_le_bytes());
        out.extend_from_slice(&self.ts.to_le_bytes());
        out.extend_from_slice(&self.sn.to_le_bytes());
        out.extend_from_slice(&self.una.to_le_bytes());
        out.extend_from_slice(&(self.data.len() as u32).to_le_bytes());
        out.extend_from_slice(&self.data);
    }
}

/// 从一个数据报里切出所有段（KCP 允许一个 UDP 包里装多个段）。
fn decode_segs(pkt: &[u8]) -> Result<Vec<Seg>, KcpError> {
    let mut segs = Vec::new();
    let mut i = 0usize;
    while i + HEADER <= pkt.len() {
        let conv = u32::from_le_bytes(pkt[i..i + 4].try_into().unwrap());
        let cmd = pkt[i + 4];
        let frg = pkt[i + 5];
        let wnd = u16::from_le_bytes(pkt[i + 6..i + 8].try_into().unwrap());
        let ts = u32::from_le_bytes(pkt[i + 8..i + 12].try_into().unwrap());
        let sn = u32::from_le_bytes(pkt[i + 12..i + 16].try_into().unwrap());
        let una = u32::from_le_bytes(pkt[i + 16..i + 20].try_into().unwrap());
        let len = u32::from_le_bytes(pkt[i + 20..i + 24].try_into().unwrap()) as usize;
        i += HEADER;
        if pkt.len() - i < len {
            return Err(KcpError::Truncated);
        }
        segs.push(Seg {
            conv,
            cmd,
            frg,
            wnd,
            ts,
            sn,
            una,
            data: pkt[i..i + len].to_vec(),
            resendts: 0,
            rto: 0,
            fastack: 0,
            xmit: 0,
        });
        i += len;
    }
    if segs.is_empty() {
        return Err(KcpError::TooShort);
    }
    Ok(segs)
}

#[derive(Debug, thiserror::Error)]
pub enum KcpError {
    #[error("KCP 数据报过短")]
    TooShort,
    #[error("KCP 数据报被截断")]
    Truncated,
    #[error("KCP 会话号不匹配")]
    WrongConv,
    #[error("KCP 连接已断开")]
    Dead,
}

// ---------------------------------------------------------------------------
// KCP 状态机
// ---------------------------------------------------------------------------

/// 一条 KCP 会话（纯状态机，不碰 IO）。
///
/// 调用方负责三件事：定时 [`Kcp::update`]、把收到的 UDP 数据报喂给
/// [`Kcp::input`]、把 [`Kcp::out`] 里攒下的数据报发出去。
pub struct Kcp {
    conv: u32,
    mss: usize,

    snd_una: u32,
    snd_nxt: u32,
    rcv_nxt: u32,

    ssthresh: u32,
    rx_rttval: u32,
    rx_srtt: u32,
    rx_rto: u32,
    rx_minrto: u32,

    snd_wnd: u32,
    rcv_wnd: u32,
    rmt_wnd: u32,
    cwnd: u32,
    probe: u32,
    interval: u32,
    ts_flush: u32,
    nodelay: bool,
    updated: bool,
    ts_probe: u32,
    probe_wait: u32,
    incr: u32,
    current: u32,
    /// 被跳过 ACK 多少次就触发快速重传（0 = 关闭）。
    fastresend: u32,

    snd_queue: VecDeque<Seg>,
    rcv_queue: VecDeque<Seg>,
    snd_buf: VecDeque<Seg>,
    rcv_buf: VecDeque<Seg>,
    /// 待回的 ACK：`(sn, ts)`。
    acklist: Vec<(u32, u32)>,

    /// 待发出的 UDP 数据报。调用方取走并发送。
    pub out: VecDeque<Vec<u8>>,
    /// 对端被判定为"死链"（重传次数超限）。
    pub dead: bool,
}

impl Kcp {
    pub fn new(conv: u32, mtu: usize) -> Self {
        let mtu = if mtu == 0 { IKCP_MTU_DEF } else { mtu };
        Self {
            conv,
            mss: mtu - HEADER,
            snd_una: 0,
            snd_nxt: 0,
            rcv_nxt: 0,
            ssthresh: IKCP_THRESH_INIT,
            rx_rttval: 0,
            rx_srtt: 0,
            rx_rto: IKCP_RTO_DEF,
            rx_minrto: IKCP_RTO_MIN,
            snd_wnd: IKCP_WND_SND,
            rcv_wnd: IKCP_WND_RCV,
            rmt_wnd: IKCP_WND_RCV,
            cwnd: 0,
            probe: 0,
            interval: IKCP_INTERVAL,
            ts_flush: IKCP_INTERVAL,
            nodelay: false,
            updated: false,
            ts_probe: 0,
            probe_wait: 0,
            incr: 0,
            current: 0,
            fastresend: 0,
            snd_queue: VecDeque::new(),
            rcv_queue: VecDeque::new(),
            snd_buf: VecDeque::new(),
            rcv_buf: VecDeque::new(),
            acklist: Vec::new(),
            out: VecDeque::new(),
            dead: false,
        }
    }

    /// 弱网模式：关掉延迟 ACK / 拥塞退让，让重传尽可能激进。
    ///
    /// P2P 通道上只有一条业务流，也不需要和别人共享带宽，
    /// 所以这里默认就把 `nodelay` 打开 —— 这正是选 KCP 而不是 QUIC 的理由。
    pub fn set_nodelay(&mut self, nodelay: bool, interval: u32, fastresend: u32) {
        self.nodelay = nodelay;
        if nodelay {
            self.rx_minrto = IKCP_RTO_NDL;
        } else {
            self.rx_minrto = IKCP_RTO_MIN;
        }
        if interval > 0 {
            self.interval = interval.clamp(1, 5000);
            self.ts_flush = self.interval;
        }
        // 0 表示关闭快速重传
        self.fastresend = fastresend;
        self.incr = 0;
    }

    /// 单段最大载荷。
    pub fn mss(&self) -> usize {
        self.mss
    }

    /// 还有多少字节没被对端确认（写侧积压）。
    pub fn waitsnd(&self) -> usize {
        self.snd_buf.len() + self.snd_queue.len()
    }

    /// 接收队列里已经攒好的字节数。
    pub fn queued_bytes(&self) -> usize {
        self.rcv_queue.iter().map(|s| s.data.len()).sum()
    }

    /// 发送：把一段数据按 `mss` 分片后压入发送队列。
    ///
    /// 返回写入的字节数（当前实现要么全写入要么 0）。
    pub fn send(&mut self, buf: &[u8]) -> usize {
        if buf.is_empty() {
            return 0;
        }
        let mss = self.mss;
        // 一条消息被切成 n 片，frg 从 n-1 递减到 0（接收端据此判断消息边界）
        let count = buf.len().div_ceil(mss);
        if count > 255 {
            // 超过 frg 能表达的上限，KCP 无法承载，直接拒绝
            return 0;
        }
        let count = count as u8;
        for (i, chunk) in buf.chunks(mss).enumerate() {
            let mut seg = Seg::new(chunk.to_vec());
            seg.frg = count - 1 - i as u8;
            self.snd_queue.push_back(seg);
        }
        buf.len()
    }

    /// 定时驱动：推进时间、刷 ACK、必要时重传。
    pub fn update(&mut self, current: u32) {
        self.current = current;
        if !self.updated {
            self.updated = true;
            self.ts_flush = current;
        }
        // 用 wrapping 差，兼容 u32 回绕；`slap` 很大说明中间隔了很久
        // （比如任务被暂停过），也要立刻刷一次
        let mut slap = current.wrapping_sub(self.ts_flush);
        // 时间倒着走（有人用了墙钟又回拨）时 slap 会是个巨大的数，
        // 直接按 ikcp 的做法把基准拉回当前时刻，避免误判成"隔了很久"
        if slap >= 0x8000_0000 {
            self.ts_flush = current;
            slap = 0;
        }
        if slap >= self.interval || slap >= 10_000 {
            self.ts_flush = current;
            self.flush();
        }
    }

    /// 立即刷一次（不等定时器），用于刚写完想马上发出去的场景。
    pub fn flush_now(&mut self, current: u32) {
        self.current = current;
        self.flush();
    }

    /// 收到一个 UDP 数据报。
    pub fn input(&mut self, pkt: &[u8]) -> Result<(), KcpError> {
        let segs = decode_segs(pkt)?;
        for seg in segs {
            if seg.conv != self.conv {
                return Err(KcpError::WrongConv);
            }
            self.handle_seg(&seg);
        }
        Ok(())
    }

    /// 取出一条完整的应用消息；没有拼完整的就返回 `None`。
    pub fn recv(&mut self) -> Option<Vec<u8>> {
        // 先确认有一条**完整**的消息（最后一片的 frg == 0）
        let complete = {
            let mut total = 0usize;
            let mut found = false;
            for s in &self.rcv_queue {
                total += s.data.len();
                if s.frg == 0 {
                    found = true;
                    break;
                }
            }
            if found {
                Some(total)
            } else {
                None
            }
        }?;

        let mut out = Vec::with_capacity(complete);
        while let Some(s) = self.rcv_queue.pop_front() {
            let last = s.frg == 0;
            out.extend_from_slice(&s.data);
            if last {
                break;
            }
        }
        Some(out)
    }

    // -----------------------------------------------------------------------

    fn handle_seg(&mut self, seg: &Seg) {
        self.rmt_wnd = seg.wnd as u32;

        // 1) UNA：对端说"这些我都收到了"
        // UNA 的语义是"我已经收到了 una 之前的**所有**段"，
        // 所以 sn == una 的那一段**还没被确认**，绝不能一起删掉 ——
        // 早先这里写成 `> 0`（保留 sn > una），正好把对端最缺的那一段
        // 当已确认丢出 snd_buf，于是它永远不会被重传，整条流就此卡死。
        self.snd_buf
            .retain(|s| i32_from(s.sn.wrapping_sub(seg.una)) >= 0);
        // snd_una 只能前进（u32 会回绕，不能直接用 max 比大小）
        if i32_from(seg.una.wrapping_sub(self.snd_una)) > 0 {
            self.snd_una = seg.una;
        }

        match seg.cmd {
            IKCP_CMD_ACK => {
                // 2) RTT 采样
                let rtt = self.current.wrapping_sub(seg.ts);
                if rtt < 0x8000_0000 {
                    self.update_rtt(rtt);
                }
                // 3) 摘掉被确认的那一段，并给它之后的所有段记一次 fastack
                if let Some(pos) = self.snd_buf.iter().position(|s| s.sn == seg.sn) {
                    self.snd_buf.remove(pos);
                }
                let sn = seg.sn;
                for s in self.snd_buf.iter_mut() {
                    if i32_from(s.sn.wrapping_sub(sn)) > 0 {
                        s.fastack += 1;
                    } else {
                        break;
                    }
                }
            }
            IKCP_CMD_PUSH => {
                // 4) 落在接收窗口内且是新的 → 收下，排 ACK
                let sn = seg.sn;
                if i32_from(sn.wrapping_sub(self.rcv_nxt.wrapping_add(self.rcv_wnd))) < 0
                    && i32_from(sn.wrapping_sub(self.rcv_nxt)) >= 0
                {
                    self.acklist.push((sn, seg.ts));
                    if i32_from(sn.wrapping_sub(self.rcv_nxt)) >= 0 {
                        // 按 sn 升序插入 rcv_buf（去重）
                        if !self.rcv_buf.iter().any(|s| s.sn == sn) {
                            let mut new = seg.clone();
                            new.resendts = 0;
                            let pos = self
                                .rcv_buf
                                .iter()
                                .position(|s| i32_from(s.sn.wrapping_sub(sn)) > 0)
                                .unwrap_or(self.rcv_buf.len());
                            self.rcv_buf.insert(pos, new);
                        }
                        // 把连续的部分搬到 rcv_queue
                        while let Some(front) = self.rcv_buf.front() {
                            if front.sn != self.rcv_nxt
                                || self.rcv_queue.len() >= self.rcv_wnd as usize
                            {
                                break;
                            }
                            let s = self.rcv_buf.pop_front().unwrap();
                            self.rcv_nxt = self.rcv_nxt.wrapping_add(1);
                            self.rcv_queue.push_back(s);
                        }
                    }
                }
            }
            IKCP_CMD_WASK => self.probe |= IKCP_ASK_TELL,
            IKCP_CMD_WINS => {}
            _ => {}
        }
    }

    fn update_rtt(&mut self, rtt: u32) {
        if self.rx_srtt == 0 {
            self.rx_srtt = rtt;
            self.rx_rttval = rtt / 2;
        } else {
            let delta = (rtt as i32) - (self.rx_srtt as i32);
            self.rx_srtt = (self.rx_srtt as i32 + delta / 8) as u32;
            let d = if delta < 0 { -delta } else { delta } as u32;
            self.rx_rttval =
                (self.rx_rttval as i32 + (d as i32 - self.rx_rttval as i32) / 4) as u32;
        }
        let rto = self.rx_srtt + (self.rx_rttval * 4).max(self.interval);
        self.rx_rto = rto.max(self.rx_minrto).min(IKCP_RTO_MAX);
    }

    fn wnd_unused(&self) -> u32 {
        let queued = self.rcv_queue.len() as u32;
        self.rcv_wnd.saturating_sub(queued)
    }

    fn flush(&mut self) {
        let current = self.current;

        // ---- 1) ACK ----
        for (sn, ts) in std::mem::take(&mut self.acklist) {
            let seg = Seg {
                conv: self.conv,
                cmd: IKCP_CMD_ACK,
                frg: 0,
                wnd: self.wnd_unused() as u16,
                ts,
                sn,
                una: self.rcv_nxt,
                data: Vec::new(),
                resendts: 0,
                rto: 0,
                fastack: 0,
                xmit: 0,
            };
            self.emit(&seg);
        }

        // ---- 2) 对端窗口为 0 时定期探测 ----
        if self.rmt_wnd == 0 {
            if self.probe_wait == 0 {
                self.probe_wait = IKCP_PROBE_INIT;
                self.ts_probe = current + self.probe_wait;
            } else if i32_from(current.wrapping_sub(self.ts_probe)) >= 0 {
                self.probe_wait = (self.probe_wait + self.probe_wait / 2).min(IKCP_PROBE_LIMIT);
                self.ts_probe = current + self.probe_wait;
                self.probe |= IKCP_ASK_SEND;
            }
        } else {
            self.ts_probe = 0;
            self.probe_wait = 0;
        }
        if self.probe & IKCP_ASK_SEND != 0 {
            self.emit(&Seg {
                conv: self.conv,
                cmd: IKCP_CMD_WASK,
                frg: 0,
                wnd: self.wnd_unused() as u16,
                ts: 0,
                sn: 0,
                una: self.rcv_nxt,
                data: Vec::new(),
                resendts: 0,
                rto: 0,
                fastack: 0,
                xmit: 0,
            });
        }
        if self.probe & IKCP_ASK_TELL != 0 {
            self.emit(&Seg {
                conv: self.conv,
                cmd: IKCP_CMD_WINS,
                frg: 0,
                wnd: self.wnd_unused() as u16,
                ts: 0,
                sn: 0,
                una: self.rcv_nxt,
                data: Vec::new(),
                resendts: 0,
                rto: 0,
                fastack: 0,
                xmit: 0,
            });
        }
        self.probe = 0;

        // ---- 3) 拥塞窗口（nodelay 下不生效，P2P 单流不需要退让）----
        if !self.nodelay {
            if self.cwnd < self.ssthresh {
                self.cwnd += 1;
                self.incr += self.mss as u32;
            } else {
                let incr = (self.mss * self.mss) as u32 / self.incr.max(1) + self.mss as u32 / 16;
                self.incr = 0;
                self.cwnd = (self.cwnd + incr.max(1)).min(self.rmt_wnd.max(1) * 2);
            }
        }

        // 下面的循环要同时改 `snd_buf` 又读其它字段，先把这些值取出来，
        // 否则借不开（Rust 不允许多次借 `self` 的可变/不可变部分重叠）
        let wnd = self.wnd_unused() as u16;
        let rx_rto = self.rx_rto;
        let nodelay = self.nodelay;
        let rcv_nxt = self.rcv_nxt;
        let window = self.snd_wnd.min(self.rmt_wnd);
        let max_sn = self.snd_una.wrapping_add(window);

        // ---- 4) 把发送队列里的段推进发送缓冲 ----
        while i32_from(self.snd_nxt.wrapping_sub(max_sn)) < 0 {
            let Some(mut seg) = self.snd_queue.pop_front() else {
                break;
            };
            seg.conv = self.conv;
            seg.cmd = IKCP_CMD_PUSH;
            seg.wnd = wnd;
            seg.ts = current;
            seg.sn = self.snd_nxt;
            seg.una = rcv_nxt;
            seg.resendts = current;
            seg.rto = rx_rto;
            seg.fastack = 0;
            seg.xmit = 0;
            self.snd_buf.push_back(seg);
            self.snd_nxt = self.snd_nxt.wrapping_add(1);
        }

        // ---- 5) 重传判定 ----
        // 快速重传阈值；0 表示关闭，此时取 u32::MAX 让比较永不成立。
        let fast_limit = if self.fastresend > 0 {
            self.fastresend
        } else {
            u32::MAX
        };
        // 参与窗口运算时必须是个有限值，否则 `cwnd * mss` 会溢出
        let resent = self.fastresend.max(1);
        let rtomin = if nodelay { 0 } else { rx_rto >> 3 };
        let mut lost = false;
        let mut change = 0u32;
        let mut to_emit: Vec<Seg> = Vec::new();

        for seg in self.snd_buf.iter_mut() {
            let mut needsend = false;
            if seg.xmit == 0 {
                needsend = true;
                seg.xmit += 1;
                seg.rto = rx_rto;
                seg.resendts = current + seg.rto + rtomin;
            } else if i32_from(current.wrapping_sub(seg.resendts)) >= 0 {
                // 超时重传：RTO 退避（nodelay 下退避得更慢，避免越丢越慢）
                needsend = true;
                seg.rto += if nodelay {
                    seg.rto / 2
                } else {
                    seg.rto.max(rx_rto)
                };
                seg.xmit += 1;
                seg.resendts = current + seg.rto;
                if seg.xmit >= IKCP_DEADLINK_DEFAULT {
                    lost = true;
                }
                change += 1;
            } else if seg.fastack >= fast_limit {
                // 快速重传：后面的段都到了就说明这段大概率丢了，不等 RTO
                needsend = true;
                seg.fastack = 0;
                seg.rto = rx_rto;
                seg.resendts = current + seg.rto;
                seg.xmit += 1;
                change += 1;
            }
            if needsend {
                seg.ts = current;
                seg.wnd = wnd;
                seg.una = rcv_nxt;
                to_emit.push(seg.clone());
            }
        }
        for s in &to_emit {
            self.emit(s);
        }

        // ---- 6) 收缩窗口 / 判死链 ----
        if change > 0 && !nodelay {
            let inflight = self.snd_nxt.wrapping_sub(self.snd_una);
            self.ssthresh = (inflight / 2).max(IKCP_THRESH_MIN);
            self.cwnd = self.ssthresh + resent;
            self.incr = self.cwnd * self.mss as u32;
        }
        if lost {
            self.ssthresh = IKCP_THRESH_MIN;
            self.cwnd = 1;
            self.incr = self.mss as u32;
            self.dead = true;
        }
    }

    fn emit(&mut self, seg: &Seg) {
        let mut buf = Vec::with_capacity(HEADER + seg.data.len());
        seg.encode(&mut buf);
        self.out.push_back(buf);
    }
}

/// 重传多少次就判定对端已死（ikcp 的 `dead_link`）。
const IKCP_DEADLINK_DEFAULT: u32 = 20;

/// 把"环绕差"当**有符号**理解（KCP 的 `_itimediff`）。
fn i32_from(v: u32) -> i32 {
    v as i32
}

// ---------------------------------------------------------------------------
// 异步流封装
// ---------------------------------------------------------------------------

/// 驱动循环的 tick 间隔：KCP 默认 10ms 一跳。
const TICK: std::time::Duration = std::time::Duration::from_millis(10);
/// 单个 UDP 数据报的读缓冲。
const READ_BUF: usize = 2048;

/// 一条 KCP 数据流（实现 `AsyncRead` + `AsyncWrite`）。
///
/// 内部起一个驱动任务：定时 `update`、收发数据报、把拼好的消息交给读端。
/// `Drop` 时会 abort 驱动任务，socket 随之归还。
pub struct KcpStream {
    /// 驱动 → 应用：已经拼完整的应用数据。
    rx: UnboundedReceiver<Bytes>,
    /// 应用 → 驱动：待发送的应用数据。
    tx: UnboundedSender<Bytes>,
    task: Option<tokio::task::JoinHandle<()>>,
}

impl Drop for KcpStream {
    fn drop(&mut self) {
        if let Some(t) = self.task.take() {
            t.abort();
        }
    }
}

impl KcpStream {
    /// 客户端侧：向 `peer` 发起一条 KCP 会话。
    pub async fn connect(sock: UdpSocket, peer: std::net::SocketAddr, conv: u32) -> Self {
        Self::spawn(sock, peer, conv, None)
    }

    /// 服务端侧：已经知道对端地址（比如从第一个数据报的源地址学来）。
    pub fn spawn(
        sock: UdpSocket,
        peer: std::net::SocketAddr,
        conv: u32,
        first: Option<Vec<u8>>,
    ) -> Self {
        Self::spawn_candidates(sock, &[peer], conv, first)
    }

    /// 真正的构造入口：单个或多个候选地址。
    ///
    /// 端口预测会给出一串候选端口，而 KCP 是**无连接**的 —— 换目的端口只要
    /// 换 `send_to` 的地址。所以这里不"每个候选开一条会话"，而是让驱动任务
    /// 在锁定对端之前**轮流试**每个候选：谁先回包就锁定谁。
    pub fn spawn_candidates(
        sock: UdpSocket,
        candidates: &[std::net::SocketAddr],
        conv: u32,
        first: Option<Vec<u8>>,
    ) -> Self {
        let mut kcp = Kcp::new(conv, IKCP_MTU_DEF);
        kcp.set_nodelay(true, IKCP_INTERVAL, IKCP_FASTACK_LIMIT);
        if let Some(pkt) = first {
            let _ = kcp.input(&pkt);
        }
        let cands: Vec<std::net::SocketAddr> = candidates.to_vec();
        let fallback: std::net::SocketAddr = "127.0.0.1:0".parse().expect("硬编码地址必然合法");
        let mut peer = cands.first().copied().unwrap_or(fallback);
        let (app_tx, app_rx) = mpsc::unbounded_channel();
        let (net_tx, mut net_rx) = mpsc::unbounded_channel::<Bytes>();

        let task = tokio::spawn(async move {
            let mut tick = interval(TICK);
            let mut rbuf = vec![0u8; READ_BUF];
            let start = std::time::Instant::now();
            let mut idx = 0usize;
            let mut locked = false;
            let mut last_switch = std::time::Instant::now();
            loop {
                // 先把 KCP 想发的东西全发出去
                pump(&mut kcp, &sock, &peer).await;
                tokio::select! {
                    Some(data) = net_rx.recv() => {
                        if kcp.send(&data) == 0 { continue; }
                    }
                    r = sock.recv_from(&mut rbuf) => {
                        match r {
                            Ok((n, from)) => {
                                // 锁定前：候选列表里谁先回包就认定是谁
                                // （对称 NAT 下源端口未必等于我们发过去的那个目的端口）。
                                // 锁定后：洞是敞开的，陌生源一律丢掉。
                                if locked {
                                    if from != peer { continue; }
                                } else if let Some(i) = cands.iter().position(|c| *c == from) {
                                    peer = from;
                                    idx = i;
                                    locked = true;
                                } else {
                                    continue;
                                }
                                if kcp.input(&rbuf[..n]).is_err() { continue; }
                                while let Some(msg) = kcp.recv() {
                                    if app_tx.send(Bytes::from(msg)).is_err() { return; }
                                }
                            }
                            Err(e) if transient(&e) => continue,
                            Err(_) => return,
                        }
                    }
                    _ = tick.tick() => {
                        kcp.update(ms_since(&start));
                        if kcp.dead {
                            debug_dead();
                            return;
                        }
                        // 还没人对答：换下一个候选端口再试一轮
                        if !locked && cands.len() > 1 && last_switch.elapsed() >= CANDIDATE_SWITCH
                        {
                            idx = (idx + 1) % cands.len();
                            peer = cands[idx];
                            last_switch = std::time::Instant::now();
                        }
                    }
                }
                // 应用数据 / ACK 都要尽快落地，不等下一个 tick
                kcp.update(ms_since(&start));
                pump(&mut kcp, &sock, &peer).await;
                while let Some(msg) = kcp.recv() {
                    if app_tx.send(Bytes::from(msg)).is_err() {
                        return;
                    }
                }
            }
        });

        Self {
            rx: app_rx,
            tx: net_tx,
            task: Some(task),
        }
    }
}

/// 还没锁定对端时，多久换一个候选端口试。
const CANDIDATE_SWITCH: std::time::Duration = std::time::Duration::from_millis(400);

/// 这个收包错误是"可以当没发生"的吗？
///
/// Windows 上**必须**做这个判断：往一个没开端口发 UDP（打洞时再正常不过 ——
/// 预测出来的候选端口大部分就是空的），对端回一个 ICMP 不可达，
/// 系统会在**下一次** `recv_from` 上报 `WSAECONNRESET`。
/// 早先这里不分青红皂白 `return`，于是打洞过程中的一发空包
/// 就把整条 KCP 通道干掉了。
fn transient(e: &std::io::Error) -> bool {
    matches!(
        e.kind(),
        std::io::ErrorKind::ConnectionReset
            | std::io::ErrorKind::ConnectionRefused
            | std::io::ErrorKind::Interrupted
            | std::io::ErrorKind::WouldBlock
    )
}

fn debug_dead() {
    tracing::debug!("KCP 判定对端为死链，关闭通道");
}

fn ms_since(start: &std::time::Instant) -> u32 {
    start.elapsed().as_millis() as u32
}

async fn pump(kcp: &mut Kcp, sock: &UdpSocket, peer: &std::net::SocketAddr) {
    while let Some(pkt) = kcp.out.pop_front() {
        if sock.send_to(&pkt, peer).await.is_err() {
            break;
        }
    }
}

impl AsyncRead for KcpStream {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        match self.rx.poll_recv(cx) {
            std::task::Poll::Ready(Some(bytes)) => {
                let n = bytes.len().min(buf.remaining());
                buf.put_slice(&bytes[..n]);
                std::task::Poll::Ready(Ok(()))
            }
            std::task::Poll::Ready(None) => std::task::Poll::Ready(Ok(())), // EOF
            std::task::Poll::Pending => std::task::Poll::Pending,
        }
    }
}

impl AsyncWrite for KcpStream {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        match self.tx.send(Bytes::copy_from_slice(buf)) {
            Ok(()) => std::task::Poll::Ready(Ok(buf.len())),
            Err(_) => std::task::Poll::Ready(Err(std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "KCP 通道已关闭",
            ))),
        }
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::task::Poll::Ready(Ok(()))
    }

    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::task::Poll::Ready(Ok(()))
    }
}

/// 由 sid 派生一个会话号（两端各自算，结果必须一致）。
pub fn conv_from_sid(sid: &str) -> u32 {
    use sha2::{Digest, Sha256};
    let h = Sha256::digest(sid.as_bytes());
    u32::from_be_bytes([h[0], h[1], h[2], h[3]])
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 一段可控的"虚拟链路"：两端各有一组待发数据报，可按比例丢包。
    struct Wire {
        loss: u32, // 千分之几
        rng: u64,
    }

    impl Wire {
        fn new(loss_permille: u32) -> Self {
            Self {
                loss: loss_permille,
                rng: 0x1234_5678,
            }
        }
        /// 简易 xorshift，避免引入 rand 依赖。
        fn next(&mut self) -> u32 {
            let mut x = self.rng as u32;
            x ^= x << 13;
            x ^= x >> 17;
            x ^= x << 5;
            self.rng = x as u64;
            x
        }
        fn drop_it(&mut self) -> bool {
            self.next() % 1000 < self.loss
        }
    }

    /// 在一条会丢包的链路两端跑 KCP，直到 `data` 全部送达。
    fn transfer(loss_permille: u32, data: &[u8]) -> Vec<u8> {
        let mut a = Kcp::new(1, IKCP_MTU_DEF);
        let mut b = Kcp::new(1, IKCP_MTU_DEF);
        a.set_nodelay(true, IKCP_INTERVAL, IKCP_FASTACK_LIMIT);
        b.set_nodelay(true, IKCP_INTERVAL, IKCP_FASTACK_LIMIT);

        let mut wire = Wire::new(loss_permille);
        let mut got = Vec::new();
        let mut to_b: Vec<Vec<u8>> = Vec::new();
        let mut to_a: Vec<Vec<u8>> = Vec::new();

        assert_eq!(a.send(data), data.len(), "发送应当整段收下");

        for step in 0..200_000u32 {
            let now = step * 10;
            a.update(now);
            b.update(now);
            // 搬运（带丢包）
            for p in a.out.drain(..) {
                if !wire.drop_it() {
                    to_b.push(p);
                }
            }
            for p in b.out.drain(..) {
                if !wire.drop_it() {
                    to_a.push(p);
                }
            }
            for p in to_b.drain(..) {
                let _ = b.input(&p);
            }
            for p in to_a.drain(..) {
                let _ = a.input(&p);
            }
            while let Some(m) = b.recv() {
                got.extend_from_slice(&m);
            }
            if got.len() >= data.len() {
                break;
            }
        }
        got
    }

    #[test]
    fn segment_header_roundtrip() {
        let seg = Seg {
            conv: 0xdead_beef,
            cmd: IKCP_CMD_PUSH,
            frg: 3,
            wnd: 32,
            ts: 12345,
            sn: 7,
            una: 6,
            data: b"hello".to_vec(),
            resendts: 0,
            rto: 0,
            fastack: 0,
            xmit: 0,
        };
        let mut buf = Vec::new();
        seg.encode(&mut buf);
        assert_eq!(buf.len(), HEADER + 5);
        let back = decode_segs(&buf).unwrap();
        assert_eq!(back.len(), 1);
        let s = &back[0];
        assert_eq!(s.conv, seg.conv);
        assert_eq!(s.cmd, seg.cmd);
        assert_eq!(s.frg, seg.frg);
        assert_eq!(s.sn, seg.sn);
        assert_eq!(s.una, seg.una);
        assert_eq!(&s.data, b"hello");
    }

    #[test]
    fn multiple_segments_in_one_datagram() {
        let mut buf = Vec::new();
        for i in 0..3u8 {
            let mut s = Seg::new(vec![i; 4]);
            s.sn = i as u32;
            s.encode(&mut buf);
        }
        let segs = decode_segs(&buf).unwrap();
        assert_eq!(segs.len(), 3);
        assert_eq!(segs[2].sn, 2);
    }

    #[test]
    fn truncated_datagram_is_rejected() {
        let mut s = Seg::new(vec![1, 2, 3, 4]);
        s.cmd = IKCP_CMD_PUSH;
        let mut buf = Vec::new();
        s.encode(&mut buf);
        buf.pop();
        assert!(matches!(decode_segs(&buf), Err(KcpError::Truncated)));
    }

    #[test]
    fn reliable_over_perfect_link() {
        let data = vec![0xab_u8; 5000];
        assert_eq!(transfer(0, &data).len(), data.len());
    }

    /// 核心卖点：30% 丢包下仍然能把数据送完，且内容一致。
    #[test]
    fn reliable_over_very_lossy_link() {
        let data: Vec<u8> = (0..20_000u32).map(|i| (i % 251) as u8).collect();
        let got = transfer(300, &data);
        assert_eq!(
            got.len(),
            data.len(),
            "30% 丢包下必须仍然可靠送达（实际 {} / {}）",
            got.len(),
            data.len()
        );
        assert_eq!(got, data, "内容必须逐字节一致");
    }

    /// 5% 丢包（典型弱网）下要能扛住。
    #[test]
    fn reliable_over_mildly_lossy_link() {
        let data: Vec<u8> = (0..40_000u32).map(|i| (i % 97) as u8).collect();
        let got = transfer(50, &data);
        assert_eq!(got, data);
    }

    #[test]
    fn small_messages_are_framed() {
        // 三条短消息必须各自独立成帧，不能被粘成一条
        let mut a = Kcp::new(9, IKCP_MTU_DEF);
        let mut b = Kcp::new(9, IKCP_MTU_DEF);
        a.send(b"aaa");
        a.send(b"bbbb");
        a.send(b"c");
        let mut to_b = Vec::new();
        for step in 0..100u32 {
            let now = step * 10;
            a.update(now);
            b.update(now);
            to_b.extend(a.out.drain(..));
            let batch: Vec<_> = std::mem::take(&mut to_b);
            for p in batch {
                let _ = b.input(&p);
            }
        }
        assert_eq!(b.recv().as_deref(), Some(&b"aaa"[..]));
        assert_eq!(b.recv().as_deref(), Some(&b"bbbb"[..]));
        assert_eq!(b.recv().as_deref(), Some(&b"c"[..]));
        assert!(b.recv().is_none(), "没有更多消息了");
    }

    #[test]
    fn wrong_conv_is_rejected() {
        let mut a = Kcp::new(1, IKCP_MTU_DEF);
        let mut b = Kcp::new(2, IKCP_MTU_DEF);
        a.send(b"x");
        // 第一次 update 只是把时间基准对齐（ikcp 的行为），要立刻刷一帧得用
        // flush_now —— 否则这里拿到的是空队列
        a.flush_now(0);
        let pkt = a.out.pop_front().unwrap();
        assert!(matches!(b.input(&pkt), Err(KcpError::WrongConv)));
    }

    #[test]
    fn conv_from_sid_is_stable_and_shared() {
        assert_eq!(conv_from_sid("sid-1"), conv_from_sid("sid-1"));
        assert_ne!(conv_from_sid("sid-1"), conv_from_sid("sid-2"));
    }

    #[test]
    fn oversized_message_is_refused() {
        let mut k = Kcp::new(1, IKCP_MTU_DEF);
        // mss = 1400-24 = 1376，1376*256 片超过 frg 上限
        let big = vec![0u8; k.mss() * 256];
        assert_eq!(k.send(&big), 0, "分片数超过 255 时必须拒绝而不是静默截断");
    }

    #[tokio::test]
    async fn kcp_stream_roundtrip_over_loopback() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let srv = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let srv_addr = srv.local_addr().unwrap();
        let cli = UdpSocket::bind("127.0.0.1:0").await.unwrap();

        let conv = conv_from_sid("unit-test");
        let server = tokio::spawn(async move {
            let mut buf = vec![0u8; READ_BUF];
            let (n, from) = srv.recv_from(&mut buf).await.unwrap();
            let mut s = KcpStream::spawn(srv, from, conv, Some(buf[..n].to_vec()));
            let mut got = vec![0u8; 4];
            s.read_exact(&mut got).await.unwrap();
            assert_eq!(&got, b"ping");
            s.write_all(b"pong").await.unwrap();
            tokio::time::sleep(std::time::Duration::from_millis(200)).await;
            got
        });

        // 客户端要先说一句话，服务端才能从数据报里学到地址
        let mut c = KcpStream::connect(cli, srv_addr, conv).await;
        c.write_all(b"ping").await.unwrap();
        let mut reply = vec![0u8; 4];
        tokio::time::timeout(std::time::Duration::from_secs(5), c.read_exact(&mut reply))
            .await
            .expect("KCP 往返超时")
            .unwrap();
        assert_eq!(&reply, b"pong");
        server.await.unwrap();
    }
}
