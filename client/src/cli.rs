//! 客户端命令行接口（clap 定义）。
//!
//! 职责：声明 `nfrp-client` 的顶层参数与 `verify` / `status` / `stop` 子命令，
//! 只做解析，不含任何业务逻辑。
//! 并发/所有权契约：纯数据，`main` 解析后按值持有；没有任务、通道、原子计数。
//! 不变量：字段名与 clap 注解（尤其 `-v/--frp-version` 只输出裸版本号）是面板 /
//! 启动器逐字符解析的对外契约，改动会直接改变 `frpc -v` 的输出。

use clap::Parser;

#[derive(Parser, Debug)]
#[command(name = "nfrp-client", version, about = "NFrp 客户端（兼容原版 frp）")]
pub(crate) struct Cli {
    /// 子命令：`verify` / `status` / `reload` / `stop`，对应原版 frpc 的同名命令。
    ///
    /// **不写子命令时行为与以前完全一致**（读配置、跑隧道）—— 只是多了一层
    /// 可选的分支，老脚本、启动器拉的 `nfrp-client -c xxx.toml` 不受影响。
    #[command(subcommand)]
    pub(crate) command: Option<Command>,

    /// 打印**上游 frp 兼容版本号**（等价于原版 frpc 的 `frpc -v`）
    ///
    /// 只输出裸版本号（如 `0.71.0`），一个多余的字都不加 —— 因为面板和启动器
    /// 会逐字符解析它：NetTool 里的樱花、OpenFrp 都是跑 `frpc -v` 拿到版本号后
    /// 报给平台，平台据此决定下发 **legacy INI** 还是 **TOML** 配置。
    /// 这一项解析不出来时对方会当我们是远古版本，于是丢来一份 INI。
    ///
    /// 想看 NFrp 自己的版本请用 `--version`。
    #[arg(short = 'v', long = "frp-version")]
    pub(crate) frp_version: bool,

    /// 配置文件路径（默认 ./client.toml）
    #[arg(short, long, value_name = "PATH")]
    pub(crate) config: Option<std::path::PathBuf>,

    /// 打印一份示例配置到标准输出
    #[arg(long)]
    pub(crate) print_example: bool,

    /// 生成示例配置文件到指定路径
    #[arg(long, value_name = "PATH")]
    pub(crate) gen_config: Option<std::path::PathBuf>,

    /// 覆盖配置里的日志级别
    #[arg(long, value_name = "LEVEL")]
    pub(crate) log_level: Option<String>,

    /// 覆盖配置里的线协议（frp-v2 / nfrp）
    #[arg(long, value_name = "PROTOCOL")]
    pub(crate) protocol: Option<String>,

    /// 服务端地址（覆盖配置）
    #[arg(long, value_name = "ADDR")]
    pub(crate) server_addr: Option<String>,

    /// 服务端端口（覆盖配置）
    #[arg(short, long, value_name = "PORT")]
    pub(crate) server_port: Option<u16>,

    /// 认证 token（覆盖配置）
    #[arg(short, long, value_name = "TOKEN")]
    pub(crate) token: Option<String>,
}

/// 子命令（对齐原版 frpc 的命令面）。
#[derive(clap::Subcommand, Debug)]
pub(crate) enum Command {
    /// 校验配置文件（等价原版 `frpc verify -c <配置>`）
    ///
    /// 解析配置并检查语义（代理类型是否支持、必填项是否齐全），**不建立任何连接**。
    /// 退出码 0 = 通过，非 0 = 有问题 —— 启动器/脚本可以据此判断。
    Verify(VerifyArgs),

    /// 查看运行中的客户端状态（走本地管理界面的 API，需配置里开了 [webServer]）
    Status(AdminArgs),

    /// 停止运行中的客户端（等价原版 `frpc stop`）
    Stop(AdminArgs),
}

/// `verify` 的参数。
#[derive(clap::Args, Debug)]
pub(crate) struct VerifyArgs {
    /// 要校验的配置文件（默认 ./client.toml）
    #[arg(short, long, value_name = "PATH")]
    pub(crate) config: Option<std::path::PathBuf>,
}

/// `status` / `stop` 共享的参数：都要从配置里找到管理界面地址。
#[derive(clap::Args, Debug)]
pub(crate) struct AdminArgs {
    /// 客户端配置文件（用于取 [webServer] 的地址，默认 ./client.toml）
    #[arg(short, long, value_name = "PATH")]
    pub(crate) config: Option<std::path::PathBuf>,
}
