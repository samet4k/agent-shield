use anyhow::Result;

use crate::commands::analyze::OutputFormat;

pub async fn run(format: OutputFormat) -> Result<()> {
    let daemon_active = agentshield_core::ipc::client::daemon_available().await;
    let daemon = if daemon_active {
        agentshield_core::ipc::client::daemon_status().await.ok()
    } else {
        None
    };

    let log_dir = agentshield_core::log_directory();

    match format {
        OutputFormat::Json => {
            let payload = serde_json::json!({
                "daemon": {
                    "active": daemon.is_some(),
                    "version": daemon.as_ref().map(|s| s.version.clone()),
                    "total_commands": daemon.as_ref().map(|s| s.total_commands),
                    "blocked_count": daemon.as_ref().map(|s| s.blocked_count),
                    "prompt_count": daemon.as_ref().map(|s| s.prompt_count),
                    "sandbox_count": daemon.as_ref().map(|s| s.sandbox_count),
                    "collectors": daemon.as_ref().map(|s| s.collectors.clone()),
                },
                "logs": log_dir.display().to_string(),
            });
            println!("{}", serde_json::to_string_pretty(&payload)?);
        }
        OutputFormat::Text => {
            if let Some(status) = daemon {
                println!("AgentShield daemon: ACTIVE (v{})", status.version);
                println!("  Commands:  {}", status.total_commands);
                println!("  Blocked:   {}", status.blocked_count);
                println!("  Prompted:  {}", status.prompt_count);
                println!("  Sandbox:   {}", status.sandbox_count);
                if !status.collectors.is_empty() {
                    println!("  Collectors: {}", status.collectors.join(", "));
                }
            } else if daemon_active {
                println!("Daemon socket exists but unreachable");
            } else {
                println!("AgentShield daemon: INACTIVE");
                println!("  Start with: cargo run -p agentshield-daemon");
                println!("  Or: agentshield install --deep");
            }
            println!("  Logs: {}", log_dir.display());
        }
    }
    Ok(())
}