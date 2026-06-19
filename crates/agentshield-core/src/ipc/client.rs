use std::sync::Mutex;
use std::time::Duration;

use anyhow::{Context, Result};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::time::timeout;
use uuid::Uuid;

use super::{AnalyzeParams, AnalyzeResult, DaemonStatus, IpcRequest, IpcResponse};
use crate::decision::Decision;

static REQ_ID: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);
static SESSION_CACHE: Mutex<Option<Uuid>> = Mutex::new(None);

pub async fn daemon_available() -> bool {
    super::ipc_socket_path().exists()
}

pub async fn analyze_via_daemon(mut params: AnalyzeParams) -> Result<AnalyzeResult> {
    if params.session_id.is_none() {
        if let Ok(guard) = SESSION_CACHE.lock() {
            params.session_id = *guard;
        }
    }

    let id = REQ_ID.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let req = IpcRequest {
        id,
        method: "analyze".into(),
        params: serde_json::to_value(&params)?,
    };
    let resp = call_daemon(req).await?;
    if let Some(err) = resp.error {
        anyhow::bail!("{}", err.message);
    }
    let result: AnalyzeResult = serde_json::from_value(resp.result.context("empty result")?)
        .context("decode analyze result")?;

    if let Ok(mut guard) = SESSION_CACHE.lock() {
        *guard = Some(result.session_id);
    }

    Ok(result)
}

pub async fn daemon_status() -> Result<DaemonStatus> {
    let id = REQ_ID.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let req = IpcRequest {
        id,
        method: "status".into(),
        params: serde_json::json!({}),
    };
    let resp = call_daemon(req).await?;
    if let Some(err) = resp.error {
        anyhow::bail!("{}", err.message);
    }
    serde_json::from_value(resp.result.context("empty result")?).context("decode status")
}

async fn call_daemon(req: IpcRequest) -> Result<IpcResponse> {
    use interprocess::local_socket::traits::tokio::Stream as _;
    use interprocess::local_socket::GenericFilePath;
    use interprocess::local_socket::ToFsName;

    let socket_path = super::ipc_socket_path();
    let name = socket_path
        .to_fs_name::<GenericFilePath>()
        .context("socket path")?;

    let stream = timeout(
        Duration::from_secs(2),
        interprocess::local_socket::tokio::prelude::LocalSocketStream::connect(name),
    )
    .await
    .context("connect timeout")?
    .context("connect daemon")?;

    let (reader, mut writer) = stream.split();
    writer
        .write_all(format!("{}\n", serde_json::to_string(&req)?).as_bytes())
        .await?;
    let mut lines = BufReader::new(reader).lines();
    let line = lines
        .next_line()
        .await?
        .context("daemon closed connection")?;
    serde_json::from_str(&line).context("decode IPC response")
}

impl AnalyzeResult {
    pub fn into_decision(self) -> Decision {
        self.decision
    }
}
