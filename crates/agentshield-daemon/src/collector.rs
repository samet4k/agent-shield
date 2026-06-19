use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::Duration;

use agentshield_core::ipc::ExecEvent;
use agentshield_core::EventSource;
use anyhow::Result;
use sysinfo::{ProcessRefreshKind, ProcessesToUpdate, RefreshKind, System};
use tokio::sync::mpsc;
use tokio::time::sleep;

use crate::analysis::handle_exec_event;
use crate::state::SharedState;

const POLL_INTERVAL_MS: u64 = 500;

const AGENT_PARENT_NAMES: &[&str] = &[
    "cursor", "code", "claude", "aider", "codex", "windsurf", "copilot", "continue", "zed",
    "node", "python", "agentshield",
];

pub async fn spawn_collectors(state: Arc<SharedState>) -> Result<()> {
    let (tx, mut rx) = mpsc::channel::<ExecEvent>(512);
    let mut collectors = vec!["sysinfo-process".to_string()];

    if let Ok(name) = agentshield_ebpf::collector_name() {
        collectors.push(name);
        let tx_ebpf = tx.clone();
        tokio::spawn(async move {
            if let Err(e) = agentshield_ebpf::run_observer(tx_ebpf).await {
                tracing::warn!("eBPF collector: {e}");
            }
        });
    }

    if let Ok(name) = agentshield_etw::collector_name() {
        collectors.push(name);
        let tx_etw = tx.clone();
        tokio::spawn(async move {
            if let Err(e) = agentshield_etw::run_observer(tx_etw).await {
                tracing::warn!("ETW collector: {e}");
            }
        });
    }

    if let Ok(name) = agentshield_macos::collector_name() {
        collectors.push(name);
        let tx_mac = tx.clone();
        tokio::spawn(async move {
            if let Err(e) = agentshield_macos::run_observer(tx_mac).await {
                tracing::warn!("Endpoint Security collector: {e}");
            }
        });
    }

    *state.collectors.write().await = collectors.clone();
    tracing::info!("collectors: {:?}", collectors);

    let state_events = Arc::clone(&state);
    tokio::spawn(async move {
        while let Some(event) = rx.recv().await {
            if let Err(e) = handle_exec_event(&state_events, event, None).await {
                tracing::warn!("exec event analysis failed: {e}");
            }
        }
    });

    let state_sys = Arc::clone(&state);
    tokio::spawn(async move {
        if let Err(e) = sysinfo_observer(state_sys, tx).await {
            tracing::warn!("sysinfo observer: {e}");
        }
    });

    Ok(())
}

async fn sysinfo_observer(_state: Arc<SharedState>, tx: mpsc::Sender<ExecEvent>) -> Result<()> {
    let mut system = System::new_with_specifics(
        RefreshKind::nothing().with_processes(ProcessRefreshKind::everything()),
    );
    let mut seen: HashSet<u32> = HashSet::new();
    let mut shell_env_by_pid: HashMap<u32, String> = HashMap::new();

    loop {
        system.refresh_processes(ProcessesToUpdate::All, true);
        for (pid, process) in system.processes() {
            let pid_u32 = pid.as_u32();
            if seen.contains(&pid_u32) {
                continue;
            }
            seen.insert(pid_u32);

            if !is_agent_descendant(&system, process.parent().map(|p| p.as_u32())) {
                continue;
            }

            let exe = process
                .exe()
                .map(|p| p.display().to_string())
                .unwrap_or_else(|| process.name().to_string_lossy().into_owned());

            let args: Vec<String> = process
                .cmd()
                .iter()
                .map(|s| s.to_string_lossy().into_owned())
                .collect();

            watch_shell_env_change(pid_u32, &args, &mut shell_env_by_pid);

            let event = ExecEvent {
                executable: exe,
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
        sleep(Duration::from_millis(POLL_INTERVAL_MS)).await;
    }
}

fn is_agent_descendant(system: &System, ppid: Option<u32>) -> bool {
    let Some(mut current) = ppid else {
        return false;
    };

    for _ in 0..12 {
        if current == 0 {
            return false;
        }
        if let Some(parent) = system.processes().get(&sysinfo::Pid::from_u32(current)) {
            let name = parent.name().to_string_lossy().to_lowercase();
            if AGENT_PARENT_NAMES.iter().any(|a| name.contains(a)) {
                return true;
            }
            current = parent.parent().map(|p| p.as_u32()).unwrap_or(0);
        } else {
            return false;
        }
    }
    false
}

fn watch_shell_env_change(
    pid: u32,
    args: &[String],
    shell_env_by_pid: &mut HashMap<u32, String>,
) {
    for arg in args {
        if let Some(value) = arg.strip_prefix("SHELL=") {
            if let Some(prev) = shell_env_by_pid.insert(pid, value.to_string()) {
                if prev != *value {
                    tracing::error!(
                        pid,
                        old = %prev,
                        new = %value,
                        "CRITICAL: SHELL environment variable changed for agent child process"
                    );
                }
            } else {
                shell_env_by_pid.insert(pid, value.to_string());
            }
        }
    }
}