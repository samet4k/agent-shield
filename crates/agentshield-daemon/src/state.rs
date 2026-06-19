use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use agentshield_core::{PipelineError, SessionManager};
use tokio::sync::RwLock;

pub struct SharedState {
    pub sessions: Arc<SessionManager>,
    pub stats: Stats,
    pub collectors: RwLock<Vec<String>>,
    next_connection: AtomicU64,
}

pub struct Stats {
    pub total: AtomicU64,
    pub blocked: AtomicU64,
    pub prompted: AtomicU64,
    pub sandboxed: AtomicU64,
}

impl SharedState {
    pub fn new() -> Result<Arc<Self>, PipelineError> {
        let cwd = std::env::current_dir().unwrap_or_else(|_| std::path::PathBuf::from("."));
        let sessions = SessionManager::new(Some(&cwd))?;

        Ok(Arc::new(Self {
            sessions,
            stats: Stats {
                total: AtomicU64::new(0),
                blocked: AtomicU64::new(0),
                prompted: AtomicU64::new(0),
                sandboxed: AtomicU64::new(0),
            },
            collectors: RwLock::new(Vec::new()),
            next_connection: AtomicU64::new(1),
        }))
    }

    pub fn next_connection_id(&self) -> agentshield_core::ConnectionId {
        agentshield_core::ConnectionId(self.next_connection.fetch_add(1, Ordering::Relaxed))
    }

    pub fn record_decision(&self, label: &str) {
        self.stats.total.fetch_add(1, Ordering::Relaxed);
        match label {
            "block" => {
                self.stats.blocked.fetch_add(1, Ordering::Relaxed);
            }
            "prompt" => {
                self.stats.prompted.fetch_add(1, Ordering::Relaxed);
            }
            "sandbox" => {
                self.stats.sandboxed.fetch_add(1, Ordering::Relaxed);
            }
            _ => {}
        }
    }
}
