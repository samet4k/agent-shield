use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;

use agentshield_core::ipc::ExecEvent;
use agentshield_core::EventSource;
use anyhow::Result;
use sysinfo::{ProcessRefreshKind, ProcessesToUpdate, RefreshKind, System};
use tokio::time::sleep;

use crate::analysis::handle_exec_event;
use crate::state::SharedState;

pub async fn spawn_collectors(state: Arc<SharedState>) -> Result<()> {
    let mut collectors = vec!["sysinfo-process".to_string()];

    if let Ok(name) = agentshield_ebpf::collector_name() {
        collectors.push(name);
        tokio::spawn(async move {
            if let Err(e) = agentshield_ebpf::run_observer().await {
                tracing::warn!("eBPF collector: {e}");
            }
        });
    }

    if let Ok(name) = agentshield_etw::collector_name() {
        collectors.push(name);
        tokio::spawn(async move {
            if let Err(e) = agentshield_etw::run_observer().await {
                tracing::warn!("ETW collector: {e}");
            }
        });
    }

    if let Ok(name) = agentshield_macos::collector_name() {
        collectors.push(name);
        tokio::spawn(async move {
            if let Err(e) = agentshield_macos::run_observer().await {
                tracing::warn!("Endpoint Security collector: {e}");
            }
        });
    }

    *state.collectors.write().await = collectors.clone();
    tracing::info!("collectors: {:?}", collectors);

    let state = Arc::clone(&state);
    tokio::spawn(async move {
        if let Err(e) = sysinfo_observer(state).await {
            tracing::warn!("sysinfo observer: {e}");
        }
    });

    Ok(())
}

async fn sysinfo_observer(state: Arc<SharedState>) -> Result<()> {
    let mut system = System::new_with_specifics(
        RefreshKind::nothing().with_processes(ProcessRefreshKind::everything()),
    );
    let mut seen: HashSet<u32> = HashSet::new();

    loop {
        system.refresh_processes(ProcessesToUpdate::All, true);
        for (pid, process) in system.processes() {
            let pid_u32 = pid.as_u32();
            if seen.contains(&pid_u32) {
                continue;
            }
            seen.insert(pid_u32);

            let exe = process
                .exe()
                .map(|p| p.display().to_string())
                .unwrap_or_else(|| process.name().to_string_lossy().into_owned());

            let args: Vec<String> = process
                .cmd()
                .iter()
                .map(|s| s.to_string_lossy().into_owned())
                .collect();

            let event = ExecEvent {
                executable: exe,
                args,
                pid: pid_u32,
                ppid: process.parent().map(|p| p.as_u32()).unwrap_or(0),
                source: EventSource::Etw,
                cwd: process.cwd().map(|p| p.display().to_string()),
            };

            if let Err(e) = handle_exec_event(&state, event, None).await {
                tracing::warn!("exec event analysis failed: {e}");
            }
        }
        sleep(Duration::from_millis(750)).await;
    }
}
