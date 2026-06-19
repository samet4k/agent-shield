//! Windows process observer for the AgentShield daemon.

use agentshield_core::ipc::ExecEvent;
use agentshield_core::EventSource;
use anyhow::Result;
use tokio::sync::mpsc::Sender;
use tokio::time::{sleep, Duration};

#[cfg(windows)]
pub fn collector_name() -> Result<String> {
    Ok("etw-process-start".into())
}

#[cfg(not(windows))]
pub fn collector_name() -> Result<String> {
    Err(anyhow::anyhow!("ETW unavailable on this platform"))
}

#[cfg(windows)]
pub async fn run_observer(tx: Sender<ExecEvent>) -> Result<()> {
    use sysinfo::{ProcessRefreshKind, ProcessesToUpdate, RefreshKind, System};

    tracing::info!("ETW/toolhelp process observer active");
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
                source: EventSource::Etw,
                cwd: process.cwd().map(|p| p.display().to_string()),
            };
            if tx.send(event).await.is_err() {
                return Ok(());
            }
        }
        sleep(Duration::from_millis(500)).await;
    }
}

#[cfg(not(windows))]
pub async fn run_observer(_tx: Sender<ExecEvent>) -> Result<()> {
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