mod commands;
mod sandbox;
mod shell_proxy;
mod tui;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use std::process::{Command, Stdio};

use commands::analyze::OutputFormat;

#[derive(Parser)]
#[command(
    name = "agentshield",
    about = "Security runtime for AI coding agents",
    version,
    long_about = "Intercepts, analyzes, and enforces security policies on commands run by AI agents."
)]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand)]
enum Commands {
    /// Analyze a command without executing it
    Analyze {
        command: String,
        #[arg(long, value_enum, default_value_t = OutputFormat::Text)]
        format: OutputFormat,
    },
    /// Initialize AgentShield in the current environment
    Init {
        #[arg(long, default_value = "default")]
        profile: String,
    },
    /// Install AgentShield (use --deep for OS-native daemon)
    Install {
        #[arg(long)]
        deep: bool,
    },
    /// Daemon and runtime status
    Status,
    /// Live terminal dashboard
    Dashboard,
    /// Generate a report from logs
    Report {
        #[arg(long, default_value = "today")]
        period: String,
    },
    /// Configure webhook notifications
    Notify {
        #[command(subcommand)]
        action: NotifyCommands,
    },
    /// WASM plugin management
    Plugin {
        #[command(subcommand)]
        action: PluginCommands,
    },
    /// Start MCP tool server (stdio transport)
    Mcp,
    /// Run bypass test harness
    Test,
}

#[derive(Subcommand)]
enum NotifyCommands {
    /// Add a webhook URL
    Set {
        #[arg(long)]
        webhook: String,
    },
    /// List configured webhooks
    List,
}

#[derive(Subcommand)]
enum PluginCommands {
    /// List installed plugins
    List,
    /// Install a WASM plugin
    Install { name: String, path: String },
}

fn sibling_binary(name: &str) -> Result<Command> {
    let exe = std::env::current_exe().context("resolve agentshield binary path")?;
    let dir = exe.parent().context("binary parent directory")?;
    let candidate = if cfg!(windows) {
        dir.join(format!("{name}.exe"))
    } else {
        dir.join(name)
    };
    let path = if candidate.exists() {
        candidate
    } else {
        dir.join(name)
    };
    if path.exists() {
        Ok(Command::new(path))
    } else {
        Ok(Command::new(name))
    }
}

fn exec_sibling(name: &str) -> Result<()> {
    let mut cmd = sibling_binary(name)?;
    cmd.stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit());
    let status = cmd
        .status()
        .with_context(|| format!("failed to run {name}"))?;
    if status.success() {
        Ok(())
    } else {
        anyhow::bail!("{name} exited with {status}");
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        None => shell_proxy::run().await,
        Some(Commands::Analyze { command, format }) => {
            commands::analyze::run(&command, format).await
        }
        Some(Commands::Init { profile }) => commands::init::run(&profile),
        Some(Commands::Install { deep }) => commands::install::run(deep),
        Some(Commands::Status) => commands::status::run().await,
        Some(Commands::Dashboard) => tui::run_dashboard(),
        Some(Commands::Report { period }) => commands::report::run(&period),
        Some(Commands::Notify { action }) => match action {
            NotifyCommands::Set { webhook } => commands::notify_cmd::configure(&webhook),
            NotifyCommands::List => commands::notify_cmd::list(),
        },
        Some(Commands::Plugin { action }) => match action {
            PluginCommands::List => commands::plugin::list(),
            PluginCommands::Install { name, path } => commands::plugin::install(&name, &path),
        },
        Some(Commands::Mcp) => exec_sibling("agentshield-mcp"),
        Some(Commands::Test) => {
            let mut cmd = sibling_binary("agentshield-test-harness")?;
            cmd.arg("bypass")
                .stdin(Stdio::inherit())
                .stdout(Stdio::inherit())
                .stderr(Stdio::inherit());
            let status = cmd
                .status()
                .context("failed to run agentshield-test-harness")?;
            if status.success() {
                Ok(())
            } else {
                anyhow::bail!("agentshield-test-harness exited with {status}");
            }
        }
    }
}
