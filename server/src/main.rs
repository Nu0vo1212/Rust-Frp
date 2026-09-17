//! `rustunnel-server` 的命令行入口。
//!
//! 这里只负责：**解析参数 -> 读配置 -> 组装 Registry -> 交棒给 [`serve`]**。
//! 全部业务逻辑都在库里，方便测试也方便复用。

use std::sync::Arc;

use anyhow::{Context, Result};
use clap::Parser;
use rustunnel_common::{
    config::{default_config_path, ServerConfig},
    util,
};
use rustunnel_server::{limits_from, Registry};

#[derive(Parser, Debug)]
#[command(
    name = "rustunnel-server",
    version,
    about = "rustunnel 服务端（兼容原版 frp）"
)]
struct Cli {
    /// 打印**上游 frp 兼容版本号**（等价于原版 frps 的 `frps -v`）
    ///
    /// 只输出裸版本号（如 `0.71.0`），方便脚本解析。
    /// 想看 rustunnel 自己的版本请用 `--version`。
    #[arg(short = 'v', long = "frp-version")]
    frp_version: bool,

    /// 配置文件路径（默认 ./server.toml）
    #[arg(short, long, value_name = "PATH")]
    config: Option<std::path::PathBuf>,

    /// 打印一份示例配置到标准输出
    #[arg(long)]
    print_example: bool,

    /// 生成示例配置文件到指定路径
    #[arg(long, value_name = "PATH")]
    gen_config: Option<std::path::PathBuf>,

    /// 覆盖配置里的日志级别
    #[arg(long, value_name = "LEVEL")]
    log_level: Option<String>,

    /// 覆盖配置里的线协议（frp-v2 / rustunnel）
    #[arg(long, value_name = "PROTOCOL")]
    protocol: Option<String>,

    /// 监听端口（覆盖配置）
    #[arg(short, long, value_name = "PORT")]
    port: Option<u16>,

    /// 认证 token（覆盖配置）
    #[arg(short, long, value_name = "TOKEN")]
    token: Option<String>,

    /// 只检查配置文件是否合法，不真正启动（用于 systemd reload 前的预检 / CI）
    #[arg(long)]
    check: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    // 与原版 frps 一致：`-v` 只打印版本号就退出（脚本/面板会解析它）
    if cli.frp_version {
        println!("{}", rustunnel_common::frp::FRP_WIRE_VERSION);
        return Ok(());
    }

    if cli.print_example {
        println!("{}", ServerConfig::example_toml());
        return Ok(());
    }
    if let Some(path) = &cli.gen_config {
        ServerConfig::write_example(path)?;
        println!("已生成示例配置：{}", path.display());
        return Ok(());
    }

    let path = cli
        .config
        .clone()
        .unwrap_or_else(|| default_config_path("server.toml"));
    if !path.exists() {
        anyhow::bail!(
            "配置文件不存在：{}\n可先执行：{} --gen-config {}",
            path.display(),
            std::env::args()
                .next()
                .unwrap_or_else(|| "rustunnel-server".into()),
            path.display()
        );
    }
    let mut cfg =
        ServerConfig::load(&path).with_context(|| format!("读取配置 {} 失败", path.display()))?;
    if let Some(p) = &cli.protocol {
        cfg.protocol = p
            .parse::<rustunnel_common::config::Protocol>()
            .map_err(anyhow::Error::msg)?;
    }
    if let Some(port) = cli.port {
        cfg.bind_port = Some(port);
    }
    if let Some(token) = &cli.token {
        cfg.token = token.clone();
    }
    if cfg.token.is_empty() {
        tracing::warn!("未配置 token：任何人都能连接本服务端，强烈建议设置");
    }

    let level = cli
        .log_level
        .clone()
        .unwrap_or_else(|| cfg.log_level.clone());
    // 开了热重载就用可替换的日志过滤器，这样改 log_level 不用重启
    let log_handle = if cfg.hot_reload {
        util::init_tracing_reloadable(&level)
    } else {
        util::init_tracing(&level);
        None
    };

    rustunnel_server::serve::ensure_protocol(&cfg)?;

    if cli.check {
        // 配置能被解析 + 通过静态合法性校验就够格了，不需要真的绑端口
        validate(&cfg)?;
        println!("配置 {} 合法", path.display());
        return Ok(());
    }
    validate(&cfg)?;

    let cfg = Arc::new(cfg);
    let registry = Arc::new(Registry::new(limits_from(&cfg)));
    let extras = rustunnel_server::ServeExtras {
        config_path: Some(path.clone()),
        log_handle,
    };
    rustunnel_server::serve_with(cfg, registry, extras).await
}

/// 启动前把明显不合理 / 互相冲突的配置挡下来。
///
/// 这类错误往往要等很久才会表现为奇怪的运行时故障（比如面板端口和控制端口
/// 撞在一起时，只有一个能抢到端口，另一个失败得莫名其妙），不如提前说清楚。
fn validate(cfg: &ServerConfig) -> Result<()> {
    let frp_port = cfg.frp_bind_port();
    if let Some(v) = cfg.p2p_port {
        anyhow::ensure!(
            v != frp_port,
            "p2p_port({v}) 不能与控制端口 {frp_port} 相同（UDP 与 TCP 端口空间是共用的）"
        );
    }
    if let Some(d) = cfg.dashboard_port {
        anyhow::ensure!(
            d != frp_port,
            "dashboard_port({d}) 不能与控制端口 {frp_port} 相同"
        );
    }
    if let Some(h) = cfg.vhost_http_port {
        if let Some(hs) = cfg.vhost_https_port {
            anyhow::ensure!(
                h != hs,
                "vhost_http_port 与 vhost_https_port 不能相同（{h}）"
            );
        }
    }
    if cfg.max_total_conns > 0 && cfg.max_conns_per_client > cfg.max_total_conns {
        tracing::warn!(
            "max_conns_per_client({}) 大于 max_total_conns({})，实际只会按后者生效",
            cfg.max_conns_per_client,
            cfg.max_total_conns
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg() -> ServerConfig {
        ServerConfig::default()
    }

    #[test]
    fn default_config_passes_validation() {
        assert!(validate(&cfg()).is_ok());
    }

    #[test]
    fn p2p_port_must_not_collide_with_control_port() {
        let mut c = cfg();
        c.p2p_port = Some(c.frp_bind_port());
        let e = validate(&c).unwrap_err().to_string();
        assert!(e.contains("p2p_port"), "{e}");
    }

    #[test]
    fn dashboard_port_must_not_collide_with_control_port() {
        let mut c = cfg();
        c.dashboard_port = Some(c.frp_bind_port());
        assert!(validate(&c).is_err());
    }

    #[test]
    fn http_and_https_vhost_ports_must_differ() {
        let mut c = cfg();
        c.vhost_http_port = Some(8080);
        c.vhost_https_port = Some(8080);
        assert!(validate(&c).is_err());
        c.vhost_https_port = Some(8443);
        assert!(validate(&c).is_ok());
    }

    #[test]
    fn per_client_greater_than_total_only_warns() {
        let mut c = cfg();
        c.max_total_conns = 10;
        c.max_conns_per_client = 999;
        assert!(validate(&c).is_ok(), "这只是浪费配额，不是错误");
    }
}
