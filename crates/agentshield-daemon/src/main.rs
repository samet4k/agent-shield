mod analysis;
mod collector;
mod ipc_listener;
mod state;

use anyhow::Result;
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> Result<()> {
    agentshield_core::logging::spawn_log_maintenance();

    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    let shared = state::SharedState::new()?;
    collector::spawn_collectors(shared.clone()).await?;

    let expiry_state = shared.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(300));
        loop {
            interval.tick().await;
            let purged = expiry_state.sessions.purge_expired().await;
            if purged > 0 {
                tracing::info!("purged {purged} expired sessions");
            }
        }
    });

    ipc_listener::run(shared).await
}
