//! Platform-specific daemon IPC transport (Unix domain socket / Windows named pipe).

use std::time::Duration;

use anyhow::{Context, Result};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

use super::{IpcRequest, IpcResponse};

/// Windows named pipe path for daemon IPC.
#[cfg(windows)]
pub const IPC_PIPE_NAME: &str = r"\\.\pipe\agentshield";

/// Returns whether the daemon IPC endpoint appears reachable.
pub async fn endpoint_available() -> bool {
    #[cfg(windows)]
    {
        use tokio::net::windows::named_pipe::ClientOptions;
        tokio::task::spawn_blocking(|| ClientOptions::new().open(IPC_PIPE_NAME))
            .await
            .ok()
            .and_then(|r| r.ok())
            .is_some()
    }
    #[cfg(unix)]
    {
        super::ipc_socket_path().exists()
    }
}

/// Send one JSON-RPC request and read a single-line response.
pub async fn call_daemon(req: &IpcRequest) -> Result<IpcResponse> {
    #[cfg(windows)]
    {
        call_daemon_windows(req).await
    }
    #[cfg(unix)]
    {
        call_daemon_unix(req).await
    }
}

#[cfg(windows)]
async fn call_daemon_windows(req: &IpcRequest) -> Result<IpcResponse> {
    use tokio::net::windows::named_pipe::ClientOptions;

    let stream = tokio::time::timeout(
        Duration::from_secs(2),
        tokio::task::spawn_blocking(|| ClientOptions::new().open(IPC_PIPE_NAME)),
    )
    .await
    .context("connect timeout")?
    .context("connect daemon pipe task")?
    .context("connect daemon pipe")?;

    exchange_json_line(stream, req).await
}

#[cfg(unix)]
async fn call_daemon_unix(req: &IpcRequest) -> Result<IpcResponse> {
    use interprocess::local_socket::traits::tokio::Stream as _;
    use interprocess::local_socket::GenericFilePath;
    use interprocess::local_socket::ToFsName;

    let socket_path = super::ipc_socket_path();
    let name = socket_path
        .to_fs_name::<GenericFilePath>()
        .context("socket path")?;

    let stream = tokio::time::timeout(
        Duration::from_secs(2),
        interprocess::local_socket::tokio::prelude::LocalSocketStream::connect(name),
    )
    .await
    .context("connect timeout")?
    .context("connect daemon")?;

    exchange_json_line(stream, req).await
}

async fn exchange_json_line<S>(stream: S, req: &IpcRequest) -> Result<IpcResponse>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let (reader, mut writer) = tokio::io::split(stream);
    writer
        .write_all(format!("{}\n", serde_json::to_string(req)?).as_bytes())
        .await?;
    writer.flush().await?;
    let mut lines = BufReader::new(reader).lines();
    let line = lines
        .next_line()
        .await?
        .context("daemon closed connection")?;
    serde_json::from_str(&line).context("decode IPC response")
}