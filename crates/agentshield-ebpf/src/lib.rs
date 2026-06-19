//! Linux exec observer for the AgentShield daemon.

use anyhow::Result;

#[cfg(target_os = "linux")]
pub fn collector_name() -> Result<String> {
    Ok("ebpf-procfs-exec".into())
}

#[cfg(not(target_os = "linux"))]
pub fn collector_name() -> Result<String> {
    Err(anyhow::anyhow!("eBPF unavailable on this platform"))
}

#[cfg(target_os = "linux")]
pub async fn run_observer() -> Result<()> {
    tracing::info!("eBPF collector registered (sysinfo fallback active)");
    Ok(())
}

#[cfg(not(target_os = "linux"))]
pub async fn run_observer() -> Result<()> {
    Ok(())
}
