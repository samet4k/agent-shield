//! Linux exec observer for the AgentShield daemon.

use agentshield_core::ipc::ExecEvent;
use anyhow::Result;
use tokio::sync::mpsc::Sender;

#[cfg(target_os = "linux")]
pub fn collector_name() -> Result<String> {
    Ok("ebpf-procfs-exec".into())
}

#[cfg(not(target_os = "linux"))]
pub fn collector_name() -> Result<String> {
    Err(anyhow::anyhow!("eBPF unavailable on this platform"))
}

#[cfg(target_os = "linux")]
pub async fn run_observer(tx: Sender<ExecEvent>) -> Result<()> {
    use agentshield_core::EventSource;
    use tokio::time::{sleep, Duration};

    tracing::info!("eBPF/procfs exec observer active");
    let mut seen = std::collections::HashSet::new();

    loop {
        if let Ok(entries) = std::fs::read_dir("/proc") {
            for entry in entries.flatten() {
                let Ok(name) = entry.file_name().into_string() else {
                    continue;
                };
                let Ok(pid) = name.parse::<u32>() else {
                    continue;
                };
                if !seen.insert(pid) {
                    continue;
                }

                let cmdline_path = entry.path().join("cmdline");
                let Ok(raw) = std::fs::read(cmdline_path) else {
                    continue;
                };
                if raw.is_empty() {
                    continue;
                }

                let parts: Vec<String> = raw
                    .split(|b| *b == 0)
                    .filter(|s| !s.is_empty())
                    .map(|s| String::from_utf8_lossy(s).into_owned())
                    .collect();
                if parts.is_empty() {
                    continue;
                }

                let executable = parts[0].clone();
                let args = parts[1..].to_vec();
                let ppid = read_ppid(entry.path());

                let event = ExecEvent {
                    executable,
                    args,
                    pid,
                    ppid,
                    source: EventSource::Ebpf,
                    cwd: None,
                };
                if tx.send(event).await.is_err() {
                    return Ok(());
                }
            }
        }
        sleep(Duration::from_millis(500)).await;
    }
}

#[cfg(target_os = "linux")]
fn read_ppid(proc_path: &std::path::Path) -> u32 {
    let status = std::fs::read_to_string(proc_path.join("status")).unwrap_or_default();
    for line in status.lines() {
        if let Some(val) = line.strip_prefix("PPid:\t") {
            return val.trim().parse().unwrap_or(0);
        }
    }
    0
}

#[cfg(not(target_os = "linux"))]
pub async fn run_observer(_tx: Sender<ExecEvent>) -> Result<()> {
    Ok(())
}