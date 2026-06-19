use std::collections::VecDeque;
use std::path::PathBuf;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::decision::Decision;

/// Origin of a captured security event.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EventSource {
    ShellProxy,
    Ebpf,
    EndpointSecurity,
    Etw,
    Sdk,
    Mcp,
}

/// Kind of security-relevant activity.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EventKind {
    Command,
    FileRead,
    FileWrite,
    Network,
}

/// Normalized event consumed by the analysis pipeline.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityEvent {
    pub session_id: Uuid,
    pub agent_id: Option<String>,
    pub source: EventSource,
    pub event_kind: EventKind,
    pub command_raw: String,
    pub command_normalized: String,
    pub cwd: PathBuf,
    pub timestamp: DateTime<Utc>,
}

/// Record of a prior command in the session threat chain.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommandRecord {
    pub command_normalized: String,
    pub risk_score: f64,
    pub decision: Decision,
    pub patterns: Vec<String>,
    pub timestamp: DateTime<Utc>,
}

/// Sliding-window session state for multi-step threat analysis.
#[derive(Debug, Clone)]
pub struct SessionState {
    pub id: Uuid,
    pub agent_id: Option<String>,
    pub history: VecDeque<CommandRecord>,
    pub cumulative_risk: f64,
    pub window_size: usize,
}

impl SessionState {
    pub fn new(agent_id: Option<String>, window_size: usize) -> Self {
        Self {
            id: Uuid::new_v4(),
            agent_id,
            history: VecDeque::new(),
            cumulative_risk: 0.0,
            window_size,
        }
    }

    pub fn push(&mut self, record: CommandRecord) {
        self.history.push_back(record);
        while self.history.len() > self.window_size {
            self.history.pop_front();
        }
        self.recompute_cumulative();
    }

    fn recompute_cumulative(&mut self) {
        let n = self.history.len();
        if n == 0 {
            self.cumulative_risk = 0.0;
            return;
        }
        let mut total = 0.0;
        for (i, record) in self.history.iter().enumerate() {
            let weight = (i + 1) as f64 / n as f64;
            total += record.risk_score * weight;
        }
        self.cumulative_risk = (total / n as f64).min(1.0);
    }
}
