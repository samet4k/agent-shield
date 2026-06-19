//! macOS Endpoint Security observer for the AgentShield daemon.

use agentshield_core::ipc::ExecEvent;
use anyhow::Result;
use tokio::sync::mpsc::Sender;

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
pub async fn run_observer(tx: Sender<ExecEvent>) -> Result<()> {
    use agentshield_core::EventSource;
    use sysinfo::{ProcessRefreshKind, ProcessesToUpdate, RefreshKind, System};
    use tokio::time::{sleep, Duration};

    tracing::info!("Endpoint Security process observer active");
    let mut system = System::new_with_specifics(
        RefreshKind::nothing().with_processes(ProcessRefreshKind::everything()),
    );
    let mut seen = std::collections::HashSet::new();

    loop {
        system.refresh_processes(ProcessesToUpdate::All, true);
        for (pid, process) in system.processes() {
            let pid_u32 = pid.as_u32();
            if !seen.insert(pid_u32) {
                continue;
            }

            let executable = process
                .exe()
                .map(|p| p.display().to_string())
                .unwrap_or_else(|| process.name().to_string_lossy().into_owned());
            let args: Vec<String> = process
                .cmd()
                .iter()
                .map(|s| s.to_string_lossy().into_owned())
                .collect();

            let event = ExecEvent {
                executable,
                args,
                pid: pid_u32,
                ppid: process.parent().map(|p| p.as_u32()).unwrap_or(0),
                source: EventSource::EndpointSecurity,
                cwd: process.cwd().map(|p| p.display().to_string()),
            };
            if tx.send(event).await.is_err() {
                return Ok(());
            }
        }
        sleep(Duration::from_millis(500)).await;
    }
}

#[cfg(not(target_os = "macos"))]
pub async fn run_observer(_tx: Sender<ExecEvent>) -> Result<()> {
    Ok(())
}

pub fn enforce_available() -> bool {
    cfg!(target_os = "macos")
}