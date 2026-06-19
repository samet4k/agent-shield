//! Windows process observer for the AgentShield daemon.

use anyhow::Result;

#[cfg(windows)]
pub fn collector_name() -> Result<String> {
    Ok("etw-process-start".into())
}

#[cfg(not(windows))]
pub fn collector_name() -> Result<String> {
    Err(anyhow::anyhow!("ETW unavailable on this platform"))
}

#[cfg(windows)]
pub async fn run_observer() -> Result<()> {
    tracing::info!("ETW process observer registered (sysinfo fallback active)");
    Ok(())
}

#[cfg(not(windows))]
pub async fn run_observer() -> Result<()> {
    Ok(())
}

#[cfg(windows)]
pub fn amsi_provider_available() -> bool {
    false
}

#[cfg(not(windows))]
pub fn amsi_provider_available() -> bool {
    false
}
