use anyhow::Result;

pub async fn run() -> Result<()> {
    if agentshield_core::ipc::client::daemon_available().await {
        match agentshield_core::ipc::client::daemon_status().await {
            Ok(status) => {
                println!("AgentShield daemon: ACTIVE (v{})", status.version);
                println!("  Commands:  {}", status.total_commands);
                println!("  Blocked:   {}", status.blocked_count);
                println!("  Prompted:  {}", status.prompt_count);
                println!("  Sandbox:   {}", status.sandbox_count);
                if !status.collectors.is_empty() {
                    println!("  Collectors: {}", status.collectors.join(", "));
                }
            }
            Err(e) => println!("Daemon socket exists but unreachable: {e}"),
        }
    } else {
        println!("AgentShield daemon: INACTIVE");
        println!("  Start with: cargo run -p agentshield-daemon");
        println!("  Or: agentshield install --deep");
    }

    let log_dir = agentshield_core::log_directory();
    println!("  Logs: {}", log_dir.display());
    Ok(())
}
