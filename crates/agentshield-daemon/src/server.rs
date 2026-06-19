use std::sync::Arc;

use agentshield_core::ipc::{AnalyzeParams, DaemonStatus, ExecEvent, IpcRequest, IpcResponse};
use anyhow::{Context, Result};
use interprocess::local_socket::tokio::Stream as LocalSocketStream;
use interprocess::local_socket::traits::tokio::{Listener as _, Stream as _};
use interprocess::local_socket::{GenericFilePath, ListenerOptions, ToFsName};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

use crate::analysis::{analyze_command, handle_exec_event};
use crate::state::SharedState;

const VERSION: &str = env!("CARGO_PKG_VERSION");

pub async fn run(state: Arc<SharedState>) -> Result<()> {
    let socket_path = agentshield_core::ipc::ipc_socket_path();
    if let Some(parent) = socket_path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    if socket_path.exists() {
        std::fs::remove_file(&socket_path).ok();
    }

    tracing::info!("daemon listening on {}", socket_path.display());

    let name = socket_path
        .clone()
        .to_fs_name::<GenericFilePath>()
        .context("socket path")?;

    let listener = ListenerOptions::new()
        .name(name)
        .create_tokio()
        .context("create IPC listener")?;

    loop {
        let stream = listener.accept().await.context("accept IPC")?;
        let state = Arc::clone(&state);
        tokio::spawn(async move {
            if let Err(e) = handle_client(stream, state).await {
                tracing::warn!("client error: {e}");
            }
        });
    }
}

async fn handle_client(stream: LocalSocketStream, state: Arc<SharedState>) -> Result<()> {
    let (reader, mut writer) = stream.split();
    let mut lines = BufReader::new(reader).lines();

    while let Some(line) = lines.next_line().await? {
        let req: IpcRequest = serde_json::from_str(&line)?;
        let resp = dispatch(&state, req).await;
        writer
            .write_all(format!("{}\n", serde_json::to_string(&resp)?).as_bytes())
            .await?;
    }
    Ok(())
}

async fn dispatch(state: &Arc<SharedState>, req: IpcRequest) -> IpcResponse {
    match req.method.as_str() {
        "analyze" => match serde_json::from_value::<AnalyzeParams>(req.params) {
            Ok(params) => match analyze_command(state, params).await {
                Ok(result) => ok(req.id, serde_json::to_value(result).unwrap_or_default()),
                Err(e) => err(req.id, -32000, e.to_string()),
            },
            Err(e) => err(req.id, -32602, e.to_string()),
        },
        "status" => {
            let status = DaemonStatus {
                active: true,
                version: VERSION.into(),
                total_commands: state.stats.total.load(std::sync::atomic::Ordering::Relaxed),
                blocked_count: state
                    .stats
                    .blocked
                    .load(std::sync::atomic::Ordering::Relaxed),
                prompt_count: state
                    .stats
                    .prompted
                    .load(std::sync::atomic::Ordering::Relaxed),
                sandbox_count: state
                    .stats
                    .sandboxed
                    .load(std::sync::atomic::Ordering::Relaxed),
                collectors: state.collectors.read().await.clone(),
            };
            ok(req.id, serde_json::to_value(status).unwrap_or_default())
        }
        "exec_event" => match serde_json::from_value::<ExecEvent>(req.params) {
            Ok(event) => match handle_exec_event(state, event).await {
                Ok(result) => ok(req.id, serde_json::to_value(result).unwrap_or_default()),
                Err(e) => err(req.id, -32000, e.to_string()),
            },
            Err(e) => err(req.id, -32602, e.to_string()),
        },
        _ => err(req.id, -32601, format!("unknown method: {}", req.method)),
    }
}

fn ok(id: u64, result: serde_json::Value) -> IpcResponse {
    IpcResponse {
        id,
        result: Some(result),
        error: None,
    }
}

fn err(id: u64, code: i32, message: String) -> IpcResponse {
    IpcResponse {
        id,
        result: None,
        error: Some(agentshield_core::ipc::IpcError { code, message }),
    }
}
