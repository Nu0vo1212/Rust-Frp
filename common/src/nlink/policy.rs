//! 策略与兼容性矩阵：XTCP 直连策略、NAT 探测阶梯、与官方的边界行为。

use std::fmt;

use serde::{Deserialize, Serialize};

use crate::nlink::Caps;

// ---------------------------------------------------------------------------
// XTCP 混合版本直连策略
// ---------------------------------------------------------------------------

/// 直连策略。
///
/// 混合部署（我方 frpc + 官方 frpc）时，"一方以为能打洞、另一方在等中继"
/// 是最常见的事故。把决策显式化，并且让**双方都用同一张表**：
///
/// | 策略 | 能直连时 | 不能直连时 |
/// |---|---|---|
/// | `auto`（默认） | 直连 | 退回中继 |
/// | `prefer-direct` | 直连 | 退回中继（与 auto 相同，但会多试一轮探测） |
/// | `direct-only` | 直连 | **失败**，不静默退回中继 |
/// | `relay-only` | 不走直连 | 中继 |
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum XtcpPolicy {
    #[default]
    Auto,
    PreferDirect,
    DirectOnly,
    RelayOnly,
}

impl XtcpPolicy {
    pub fn parse(s: &str) -> Option<Self> {
        match s.trim() {
            "" | "auto" => Some(Self::Auto),
            "prefer-direct" | "prefer_direct" => Some(Self::PreferDirect),
            "direct-only" | "direct_only" => Some(Self::DirectOnly),
            "relay-only" | "relay_only" => Some(Self::RelayOnly),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Auto => "auto",
            Self::PreferDirect => "prefer-direct",
            Self::DirectOnly => "direct-only",
            Self::RelayOnly => "relay-only",
        }
    }
}

impl fmt::Display for XtcpPolicy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// 一次直连决策的结果。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DirectDecision {
    /// 可以尝试直连。
    Direct,
    /// 用中继。
    Relay { reason: FailureCode },
    /// 策略要求直连但条件不满足：**必须报错**，不能静默降级。
    Fail { reason: FailureCode },
}

/// 决策输入。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DirectContext {
    /// 对端是否声明了 XTCP 策略能力（官方 frpc 不会声明）。
    pub peer_has_policy: bool,
    /// 本端是否有公网可达地址（打洞的前提）。
    pub have_public_addr: bool,
    /// NAT 行为是否对称（对称 NAT 下打洞成功率极低）。
    pub symmetric: bool,
}

/// 直连策略的唯一决策点。
///
/// 所有判断都收在这里，服务端 / 客户端 / 测试共用同一份逻辑 —— 避免出现
/// "客户端以为能直连、服务端已经在等中继"的两套判断。
pub fn decide_direct(policy: XtcpPolicy, ctx: DirectContext) -> DirectDecision {
    use DirectDecision::*;
    use FailureCode as F;

    if policy == XtcpPolicy::RelayOnly {
        return Relay {
            reason: F::PolicyRelayOnly,
        };
    }

    // 对端不认识策略扩展：只能按最保守的 auto 处理（这是"混合版本"的核心）。
    if !ctx.peer_has_policy {
        return match policy {
            // 官方对端：老行为，能直连就直连，失败退回中继
            XtcpPolicy::DirectOnly => Fail {
                reason: F::VersionMismatch,
            },
            _ => {
                if ctx.have_public_addr && !ctx.symmetric {
                    Direct
                } else {
                    Relay {
                        reason: if ctx.symmetric {
                            F::SymmetricNat
                        } else {
                            F::NoPublicAddr
                        },
                    }
                }
            }
        };
    }

    if !ctx.have_public_addr {
        return match policy {
            XtcpPolicy::DirectOnly => Fail {
                reason: F::NoPublicAddr,
            },
            _ => Relay {
                reason: F::NoPublicAddr,
            },
        };
    }

    if ctx.symmetric {
        return match policy {
            XtcpPolicy::DirectOnly => Fail {
                reason: F::SymmetricNat,
            },
            _ => Relay {
                reason: F::SymmetricNat,
            },
        };
    }

    Direct
}

// ---------------------------------------------------------------------------
// P2P 打洞：TTL 阶梯与失败原因码
// ---------------------------------------------------------------------------

/// 失败原因码（线上可观测："为什么这次没打成"）。
///
/// 官方 `NatHoleResp` 只带行为模式与地址列表，失败时客户端只能看到"超时"。
/// 这里给每个失败一个稳定的数字，服务端日志、扩展帧、兼容性矩阵共用。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum FailureCode {
    Ok = 0,
    NoPublicAddr = 1,
    SymmetricNat = 2,
    Timeout = 3,
    PeerUnreachable = 4,
    PolicyRelayOnly = 5,
    VersionMismatch = 6,
    AuthFailed = 7,
    KnockRequired = 8,
    ResumeExpired = 9,
    BatchRejected = 10,
}

impl FailureCode {
    pub fn as_u8(self) -> u8 {
        self as u8
    }

    pub fn from_u8(v: u8) -> Option<Self> {
        Some(match v {
            0 => Self::Ok,
            1 => Self::NoPublicAddr,
            2 => Self::SymmetricNat,
            3 => Self::Timeout,
            4 => Self::PeerUnreachable,
            5 => Self::PolicyRelayOnly,
            6 => Self::VersionMismatch,
            7 => Self::AuthFailed,
            8 => Self::KnockRequired,
            9 => Self::ResumeExpired,
            10 => Self::BatchRejected,
            _ => return None,
        })
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Ok => "ok",
            Self::NoPublicAddr => "no-public-addr",
            Self::SymmetricNat => "symmetric-nat",
            Self::Timeout => "timeout",
            Self::PeerUnreachable => "peer-unreachable",
            Self::PolicyRelayOnly => "policy-relay-only",
            Self::VersionMismatch => "version-mismatch",
            Self::AuthFailed => "auth-failed",
            Self::KnockRequired => "knock-required",
            Self::ResumeExpired => "resume-expired",
            Self::BatchRejected => "batch-rejected",
        }
    }
}

impl fmt::Display for FailureCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// 探测阶梯：先近后远，命中即停。
///
/// 官方是一次性把地址全给出去然后同时打；这里改成**逐级**：
/// TTL 1 只到本机网关，2/4/8 逐步覆盖常见路径。好处是失败时能明确
/// 告诉用户"卡在第几跳"，而不是笼统的 timeout。
pub fn ttl_ladder(max_hops: u8) -> Vec<u8> {
    let max_hops = max_hops.clamp(1, 64);
    let mut out = Vec::new();
    let mut ttl: u16 = 1;
    while ttl <= max_hops as u16 {
        out.push(ttl as u8);
        ttl *= 2;
    }
    if out.last().copied() != Some(max_hops) {
        out.push(max_hops);
    }
    out
}

/// 一次探测轮次。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProbeRound {
    pub round: u8,
    pub ttl: u8,
    pub timeout_ms: u32,
}

/// 根据阶梯生成探测轮次；每轮超时随 TTL 轻微放大（远端 RTT 更大）。
pub fn probe_plan(max_hops: u8, base_timeout_ms: u32) -> Vec<ProbeRound> {
    ttl_ladder(max_hops)
        .into_iter()
        .enumerate()
        .map(|(i, ttl)| ProbeRound {
            round: i as u8,
            ttl,
            timeout_ms: base_timeout_ms.saturating_mul(1 + ttl as u32 / 8),
        })
        .collect()
}

/// 根据探测结果归类失败原因。
///
/// * 有回应 ⇒ 成功；
/// * 只有前几跳有回应、目标跳没有 ⇒ `peer-unreachable`（路径通、对端没开）；
/// * 全部没回应 ⇒ `timeout`。
pub fn classify(results: &[(u8, bool)]) -> FailureCode {
    if results.iter().any(|(_, ok)| *ok) {
        return FailureCode::Ok;
    }
    if results.is_empty() {
        FailureCode::Timeout
    } else {
        FailureCode::PeerUnreachable
    }
}

// ---------------------------------------------------------------------------
// 与官方的兼容边界（可测试的表）
// ---------------------------------------------------------------------------

/// 一行兼容性矩阵。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MatrixRow {
    /// 功能名（与 `Caps::names()` 一致）。
    pub feature: &'static str,
    /// 支持级别。
    pub level: Support,
    /// 对应 e2e 用例名（在 `server/tests/nlink_e2e.rs` 里，必须真实存在）。
    pub e2e: &'static str,
    /// 一句话说明（含限制）。
    pub note: &'static str,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Support {
    /// 已实现并有 e2e。
    Full,
    /// 已实现但有限制（限制写在 note 里）。
    Limited,
    /// 只协商不启用（能力位存在，运行时默认关闭）。
    NegotiateOnly,
}

impl Support {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Full => "已实现",
            Self::Limited => "有限实现",
            Self::NegotiateOnly => "仅协商",
        }
    }
}

/// NLink v1 的兼容性矩阵。
///
/// 这张表是**唯一事实来源**：`scripts/nlink_matrix_check.py` 会逐行去
/// `server/tests/nlink_e2e.rs` 里找同名的 `#[tokio::test]`，找不到就报错。
/// 这样"矩阵里写了但没测"在 CI 上直接红，不靠人记得。
pub const MATRIX: &[MatrixRow] = &[
    MatrixRow {
        feature: "quic",
        level: Support::Full,
        e2e: "nlink_quic_多路复用_同一条连接跑多条流",
        note: "控制/工作连接都能走 QUIC；一条 QUIC 连接上开多条双向流",
    },
    MatrixRow {
        feature: "quic-migration",
        level: Support::Full,
        e2e: "nlink_quic_连接迁移后数据不断",
        note: "客户端换本地端口（endpoint.rebind）后连接继续，connection id 不变",
    },
    MatrixRow {
        feature: "nat-adaptive",
        level: Support::Limited,
        e2e: "nlink_nat_探测阶梯与失败原因码",
        note: "TTL 阶梯 + 失败原因码；真实对称 NAT 环境仍需专项验证",
    },
    MatrixRow {
        feature: "identity",
        level: Support::Full,
        e2e: "nlink_身份令牌_伪造与过期都被拒",
        note: "每会话 HMAC 令牌，工作连接必须出示；默认 300 秒有效",
    },
    MatrixRow {
        feature: "rate-limit",
        level: Support::Full,
        e2e: "nlink_限流_按代理令牌桶真的限速",
        note: "按用户×代理的令牌桶，支持 burst；在桥接层按实际字节计费",
    },
    MatrixRow {
        feature: "trace",
        level: Support::Full,
        e2e: "nlink_trace_控制连接与数据面共享同一个_id",
        note: "preamble 里带 trace id，登录日志与代理会话都带同一个值",
    },
    MatrixRow {
        feature: "batch-work-conn",
        level: Support::Full,
        e2e: "nlink_批量工作连接_一条帧换_n_条连接",
        note: "一条扩展帧申请 N 条工作连接，替代 N 次 ReqWorkConn",
    },
    MatrixRow {
        feature: "resume",
        level: Support::Limited,
        e2e: "nlink_断线续传_端口与代理状态保留",
        note: "保留隧道状态与监听端口；已在途的 TCP 流无法续（内核状态不可迁移）",
    },
    MatrixRow {
        feature: "port-knock",
        level: Support::Full,
        e2e: "nlink_端口敲门_不敲门连不上敲门后能连",
        note: "数据面魔术字 + HMAC 时间窗；未授权连接的表现为端口关闭",
    },
    MatrixRow {
        feature: "xtcp-policy",
        level: Support::Full,
        e2e: "nlink_xtcp_策略_混合版本下不误判直连",
        note: "auto/prefer-direct/direct-only/relay-only 四种策略，决策点唯一",
    },
    MatrixRow {
        feature: "compat-probe",
        level: Support::Full,
        e2e: "nlink_兼容边界_官方忽略的字段与报错的字段",
        note: "逐字段列出官方忽略/报错/我们更严的行为，由 e2e 断言",
    },
];

/// 取一行的辅助函数（面板 / 迁移工具用）。
pub fn matrix_row(feature: &str) -> Option<&'static MatrixRow> {
    MATRIX.iter().find(|r| r.feature == feature)
}

/// 本端能力里有、矩阵里没写的项（防止"加了能力忘了写矩阵"）。
pub fn matrix_gaps(caps: Caps) -> Vec<&'static str> {
    caps.names()
        .into_iter()
        .filter(|n| matrix_row(n).is_none())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn 策略解析与回显一致() {
        for (s, p) in [
            ("auto", XtcpPolicy::Auto),
            ("prefer-direct", XtcpPolicy::PreferDirect),
            ("direct-only", XtcpPolicy::DirectOnly),
            ("relay-only", XtcpPolicy::RelayOnly),
        ] {
            assert_eq!(XtcpPolicy::parse(s), Some(p));
            assert_eq!(p.as_str(), s);
            assert_eq!(XtcpPolicy::parse(p.as_str()), Some(p));
        }
        assert_eq!(XtcpPolicy::parse("不认识的策略"), None);
        assert_eq!(XtcpPolicy::parse(""), Some(XtcpPolicy::Auto));
    }

    #[test]
    fn relay_only_永远不走直连() {
        let d = decide_direct(
            XtcpPolicy::RelayOnly,
            DirectContext {
                peer_has_policy: true,
                have_public_addr: true,
                symmetric: false,
            },
        );
        assert!(matches!(
            d,
            DirectDecision::Relay {
                reason: FailureCode::PolicyRelayOnly
            }
        ));
    }

    #[test]
    fn direct_only_失败时必须报错而不是静默降级() {
        let d = decide_direct(
            XtcpPolicy::DirectOnly,
            DirectContext {
                peer_has_policy: true,
                have_public_addr: false,
                symmetric: false,
            },
        );
        assert!(matches!(
            d,
            DirectDecision::Fail {
                reason: FailureCode::NoPublicAddr
            }
        ));
    }

    #[test]
    fn 混合版本_官方对端不认识策略() {
        // 官方对端 + direct-only：不能假装能直连
        let d = decide_direct(
            XtcpPolicy::DirectOnly,
            DirectContext {
                peer_has_policy: false,
                have_public_addr: true,
                symmetric: false,
            },
        );
        assert!(matches!(
            d,
            DirectDecision::Fail {
                reason: FailureCode::VersionMismatch
            }
        ));

        // 官方对端 + auto：按老行为，条件满足就直连
        let d = decide_direct(
            XtcpPolicy::Auto,
            DirectContext {
                peer_has_policy: false,
                have_public_addr: true,
                symmetric: false,
            },
        );
        assert_eq!(d, DirectDecision::Direct);
    }

    #[test]
    fn 对称_nat_在_auto_下退回中继() {
        let d = decide_direct(
            XtcpPolicy::Auto,
            DirectContext {
                peer_has_policy: true,
                have_public_addr: true,
                symmetric: true,
            },
        );
        assert!(matches!(
            d,
            DirectDecision::Relay {
                reason: FailureCode::SymmetricNat
            }
        ));
    }

    #[test]
    fn ttl_阶梯单调递增且包含最大值() {
        assert_eq!(ttl_ladder(1), vec![1]);
        assert_eq!(ttl_ladder(16), vec![1, 2, 4, 8, 16]);
        assert_eq!(ttl_ladder(20), vec![1, 2, 4, 8, 16, 20]);
        for max in 1..=64u8 {
            let l = ttl_ladder(max);
            assert!(l.windows(2).all(|w| w[0] < w[1]));
            assert_eq!(*l.last().unwrap(), max);
        }
    }

    #[test]
    fn 探测计划超时随跳数放大() {
        let plan = probe_plan(8, 100);
        assert_eq!(plan.len(), 4);
        assert!(plan.windows(2).all(|w| w[0].timeout_ms <= w[1].timeout_ms));
    }

    #[test]
    fn 失败原因码稳定() {
        for code in [
            FailureCode::Ok,
            FailureCode::NoPublicAddr,
            FailureCode::SymmetricNat,
            FailureCode::Timeout,
            FailureCode::PeerUnreachable,
            FailureCode::PolicyRelayOnly,
            FailureCode::VersionMismatch,
            FailureCode::AuthFailed,
            FailureCode::KnockRequired,
            FailureCode::ResumeExpired,
            FailureCode::BatchRejected,
        ] {
            assert_eq!(FailureCode::from_u8(code.as_u8()), Some(code));
            assert!(!code.as_str().is_empty());
        }
        assert_eq!(FailureCode::from_u8(200), None);
    }

    #[test]
    fn 探测结果分类() {
        assert_eq!(classify(&[(1, false)]), FailureCode::PeerUnreachable);
        assert_eq!(classify(&[]), FailureCode::Timeout);
        assert_eq!(classify(&[(1, false), (2, true)]), FailureCode::Ok);
    }

    #[test]
    fn 矩阵覆盖所有能力位() {
        assert!(
            matrix_gaps(Caps::ALL).is_empty(),
            "有能力位没写进矩阵：{:?}",
            matrix_gaps(Caps::ALL)
        );
        // 每一行都必须有名字不重复的 e2e
        let mut seen = std::collections::HashSet::new();
        for row in MATRIX {
            assert!(!row.e2e.is_empty(), "{} 没有 e2e 用例名", row.feature);
            assert!(seen.insert(row.e2e), "e2e 用例名重复：{}", row.e2e);
            assert!(!row.note.is_empty(), "{} 没有说明", row.feature);
        }
        assert_eq!(MATRIX.len(), Caps::ALL.names().len());
    }
}
