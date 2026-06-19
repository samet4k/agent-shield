use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use agentshield_core::{AnalysisPipeline, PipelineError};
use tokio::sync::{Mutex, RwLock};

pub struct SharedState {
    pub pipeline: Mutex<AnalysisPipeline>,
    pub stats: Stats,
    pub collectors: RwLock<Vec<String>>,
}

pub struct Stats {
    pub total: AtomicU64,
    pub blocked: AtomicU64,
    pub prompted: AtomicU64,
    pub sandboxed: AtomicU64,
}

impl SharedState {
    pub fn new() -> Result<Arc<Self>, PipelineError> {
        let cwd = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
        let pipeline = AnalysisPipeline::from_project(Some(&cwd), Some("daemon".into()))?;

        Ok(Arc::new(Self {
            pipeline: Mutex::new(pipeline),
            stats: Stats {
                total: AtomicU64::new(0),
                blocked: AtomicU64::new(0),
                prompted: AtomicU64::new(0),
                sandboxed: AtomicU64::new(0),
            },
            collectors: RwLock::new(Vec::new()),
        }))
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
