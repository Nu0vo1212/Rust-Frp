//! `allowPorts` 端口区间解析与格式化。
//!
//! 职责：定义 [`PortRange`] / `PortSpec`，以及 `parse_port_ranges`、`format_port_ranges`、`port_allowed`、`de_port_ranges`。
//! 并发/所有权契约：纯值类型与纯函数，无锁、无共享可变状态；反序列化只读输入字符串。
//! 不变量：区间一律是闭区间 `[start, end]`，且 `start <= end` 只由 `PortRange::new` / `PortRange::single` 保证。

use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// allowPorts：允许客户端申请的远端端口白名单
// ---------------------------------------------------------------------------

/// `allowPorts` 里的一条端口区间，对应官方 `pkg/config/types.PortsRange`。
///
/// 官方把它设计成"单端口 / 区间"两个可选字段：
///
/// ```toml
/// allowPorts = [
///   { start = 2000, end = 3000 },
///   { single = 3001 },
///   { start = 4000, end = 5000 },
/// ]
/// ```
///
/// 内部统一成闭区间 `[start, end]`（单端口就是 `start == end`），
/// 判断"端口是否被允许"只需一次比较。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PortRange {
    pub start: u16,
    pub end: u16,
}

impl PortRange {
    /// 单个端口。
    pub fn single(port: u16) -> Self {
        Self {
            start: port,
            end: port,
        }
    }

    /// 闭区间；`end < start` 时自动交换，调用方不用先排好序。
    pub fn new(a: u16, b: u16) -> Self {
        if a <= b {
            Self { start: a, end: b }
        } else {
            Self { start: b, end: a }
        }
    }

    pub fn contains(&self, port: u16) -> bool {
        self.start <= port && port <= self.end
    }
}

impl std::fmt::Display for PortRange {
    /// 与官方 `PortsRangeSlice.String()` 一致：单端口写 `3000`，区间写 `1000-2000`。
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.start == self.end {
            write!(f, "{}", self.start)
        } else {
            write!(f, "{}-{}", self.start, self.end)
        }
    }
}

/// 反序列化 `allowPorts`：每一项可以是官方那种表，也可以直接写字符串。
///
/// 官方 TOML 只认表（`{ start = …, end = … }`），字符串写法只在 legacy INI /
/// 命令行 `--allow_ports` 里出现。这里两种都收 —— 用户把
/// `allow_ports = 1000-2000,3000` 从 frps.ini 抄到 frps.toml 时不会撞墙。
///
/// ★ 每一项用 [`PortSpec`]（自己实现 `deserialize_any`）而**不是**
///   `#[serde(untagged)]`：untagged 会把内层错误整个吞掉，只留下一句
///   "data did not match any variant"，于是"区间反了"这种能一句话说清的
///   配置错误，用户要查半天。自实现 visitor 后错误信息可以原样透出。
pub(super) fn de_port_ranges<'de, D>(d: D) -> std::result::Result<Vec<PortRange>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let specs: Vec<PortSpec> = Vec::deserialize(d)?;
    Ok(specs.into_iter().flat_map(|s| s.0).collect())
}

/// `allowPorts` 数组里的一项：表 **或** 字符串。
///
/// 字符串可以带逗号（`"1000-2000,3000"`），所以一项可能展开成多条区间 ——
/// 这也是它不叫 `PortRange` 的原因。
struct PortSpec(Vec<PortRange>);

impl<'de> Deserialize<'de> for PortSpec {
    fn deserialize<D>(d: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct V;
        impl<'de> serde::de::Visitor<'de> for V {
            type Value = PortSpec;

            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str(
                    "allowPorts 的每一项：{ start = …, end = … } / { single = … }，\
                     或 \"1000-2000,3000\" 这样的字符串",
                )
            }

            fn visit_str<E: serde::de::Error>(self, s: &str) -> std::result::Result<PortSpec, E> {
                parse_port_ranges(s).map(PortSpec).map_err(E::custom)
            }

            fn visit_map<A>(self, mut map: A) -> std::result::Result<PortSpec, A::Error>
            where
                A: serde::de::MapAccess<'de>,
            {
                use serde::de::Error as _;
                let (mut start, mut end, mut single) = (None, None, None);
                while let Some(key) = map.next_key::<String>()? {
                    match key.as_str() {
                        "start" => start = Some(map.next_value::<u16>()?),
                        "end" => end = Some(map.next_value::<u16>()?),
                        "single" => single = Some(map.next_value::<u16>()?),
                        // 官方走 Go 的 encoding/json，未知键是**忽略**的，这里照做
                        // （但必须把值消费掉，否则 map 走不下去）。
                        _ => {
                            let _ = map.next_value::<serde::de::IgnoredAny>()?;
                        }
                    }
                }
                match (single, start, end) {
                    (Some(s), None, None) => Ok(PortSpec(vec![PortRange::single(s)])),
                    // `{ start = 1000 }`（官方没这么写，但语义无歧义）
                    (None, Some(a), None) => Ok(PortSpec(vec![PortRange::single(a)])),
                    (None, Some(a), Some(b)) => {
                        if b < a {
                            Err(A::Error::custom(format!(
                                "allowPorts 区间反了：start={a} end={b}"
                            )))
                        } else {
                            Ok(PortSpec(vec![PortRange::new(a, b)]))
                        }
                    }
                    _ => Err(A::Error::custom(
                        "allowPorts 每一项要么是 { start = …, end = … }，要么是 { single = … }",
                    )),
                }
            }
        }
        d.deserialize_any(V)
    }
}

/// 解析 `"1000-2000,3000,4000-5000"` 这种逗号分隔的端口列表。
///
/// 逐条对齐官方 `types.NewPortsRangeSliceFromString`：按 `,` 切、每项按 `-` 切，
/// 切成 1 段当单端口、2 段当区间、其它段数报错；区间反过来（`2000-1000`）也报错。
pub fn parse_port_ranges(s: &str) -> std::result::Result<Vec<PortRange>, String> {
    let mut out = Vec::new();
    let trimmed = s.trim();
    if trimmed.is_empty() {
        return Ok(out);
    }
    for item in trimmed.split(',') {
        let item = item.trim();
        let parts: Vec<&str> = item.split('-').collect();
        let num = |t: &str| -> std::result::Result<u16, String> {
            t.trim()
                .parse::<u16>()
                .map_err(|_| format!("allowPorts 里的数字非法：{t:?}"))
        };
        match parts.len() {
            1 => out.push(PortRange::single(num(parts[0])?)),
            2 => {
                let a = num(parts[0])?;
                let b = num(parts[1])?;
                if b < a {
                    return Err(format!("allowPorts 区间反了：{item}"));
                }
                out.push(PortRange::new(a, b));
            }
            _ => return Err(format!("allowPorts 的分段数非法：{item}")),
        }
    }
    Ok(out)
}

/// 反向格式化（官方 `PortsRangeSlice.String()`），给面板 / API 展示用。
pub fn format_port_ranges(rs: &[PortRange]) -> String {
    rs.iter()
        .map(|r| r.to_string())
        .collect::<Vec<_>>()
        .join(",")
}

impl Serialize for PortRange {
    fn serialize<S: serde::Serializer>(&self, s: S) -> std::result::Result<S::Ok, S::Error> {
        use serde::ser::SerializeStruct as _;
        if self.start == self.end {
            // 官方单端口的写法是 `{ single = 3000 }`
            let mut st = s.serialize_struct("PortsRange", 1)?;
            st.serialize_field("single", &self.start)?;
            st.end()
        } else {
            let mut st = s.serialize_struct("PortsRange", 2)?;
            st.serialize_field("start", &self.start)?;
            st.serialize_field("end", &self.end)?;
            st.end()
        }
    }
}

/// 端口是否落在白名单里。
///
/// `allow_ports` 为空 = **不限制**（与官方 `ports.Manager` 在
/// `len(allowPorts) == 0` 时把 1..65535 全放进 freePorts 一致）。
pub fn port_allowed(allow: &[PortRange], port: u16) -> bool {
    allow.is_empty() || allow.iter().any(|r| r.contains(port))
}
