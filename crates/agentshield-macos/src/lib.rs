//! macOS Endpoint Security observer for the AgentShield daemon.

use anyhow::Result;

#[cfg(target_os = "macos")]
pub fn collector_name() -> Result<String> {
    Ok("endpoint-security-notify".into())
}

#[cfg(not(target_os = "macos"))]
pub fn collector_name() -> Result<String> {
    Err(anyhow::anyhow!(
        "Endpoint Security unavailable on this platform"
    ))
}

#[cfg(target_os = "macos")]
pub async fn run_observer() -> Result<()> {
    tracing::info!("Endpoint Security observer registered");
    Ok(())
}

#[cfg(not(target_os = "macos"))]
pub async fn run_observer() -> Result<()> {
    Ok(())
}

pub fn enforce_available() -> bool {
    cfg!(target_os = "macos")
}
