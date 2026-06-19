use std::path::Path;
use std::time::Instant;

use thiserror::Error;

use crate::ast::{parse_command, CommandParser};
use crate::decision::Decision;
use crate::obfuscation::normalize;
use crate::policy::PolicyEngine;
use crate::session::{EventKind, EventSource, SecurityEvent, SessionState};

const LATENCY_WARN_MS: f64 = 50.0;

#[derive(Debug, Error)]
pub enum PipelineError {
    #[error("policy error: {0}")]
    Policy(#[from] crate::policy::PolicyError),
    #[error("ast parse error: {0}")]
    Ast(#[from] crate::ast::AstError),
    #[error("session not found: {0}")]
    SessionNotFound(uuid::Uuid),
}

#[derive(Debug, Clone, Default)]
pub struct ExecContext {
    pub pid: Option<u32>,
    pub ppid: Option<u32>,
}

#[derive(Debug, Clone)]
pub struct AnalysisResult {
    pub event: SecurityEvent,
    pub decision: Decision,
    pub risk_score: f64,
    pub cumulative_session_risk: f64,
    pub rule_triggered: Option<String>,
    pub patterns_matched: Vec<String>,
    pub obfuscation_detected: bool,
    pub execution_time_ms: f64,
    pub allow_by_parent: bool,
}

pub struct AnalysisPipeline {
    policy: PolicyEngine,
    command_parser: CommandParser,
    threat_analyzer: crate::threat::ThreatChainAnalyzer,
    session: SessionState,
}

impl AnalysisPipeline {
    pub fn new(policy: PolicyEngine, agent_id: Option<String>) -> Result<Self, PipelineError> {
        let window = policy.document.session.threat_chain_window.unwrap_or(20);
        let threshold = policy
            .document
            .session
            .cumulative_risk_threshold
            .unwrap_or(0.8);

        Ok(Self {
            policy,
            command_parser: CommandParser::new()?,
            threat_analyzer: crate::threat::ThreatChainAnalyzer::new(threshold),
            session: SessionState::new(agent_id, window),
        })
    }

    pub fn from_policy(
        policy: PolicyEngine,
        agent_id: Option<String>,
        session_id: uuid::Uuid,
        window: usize,
        threshold: f64,
    ) -> Result<Self, PipelineError> {
        Ok(Self {
            policy,
            command_parser: CommandParser::new()?,
            threat_analyzer: crate::threat::ThreatChainAnalyzer::new(threshold),
            session: SessionState::with_id(session_id, agent_id, window),
        })
    }

    pub fn set_session_id(&mut self, id: uuid::Uuid) {
        self.session.id = id;
    }

    pub fn from_project(
        project_root: Option<&Path>,
        agent_id: Option<String>,
    ) -> Result<Self, PipelineError> {
        let policy = PolicyEngine::load_layered(project_root)?;
        Self::new(policy, agent_id)
    }

    pub fn session_id(&self) -> uuid::Uuid {
        self.session.id
    }

    pub fn analyze_command(
        &mut self,
        raw: &str,
        cwd: &Path,
    ) -> Result<AnalysisResult, PipelineError> {
        futures::executor::block_on(self.analyze_command_async(raw, cwd, ExecContext::default()))
    }

    pub async fn analyze_command_async(
        &mut self,
        raw: &str,
        cwd: &Path,
        exec_ctx: ExecContext,
    ) -> Result<AnalysisResult, PipelineError> {
        let start = Instant::now();

        if let Some(ppid) = exec_ctx.ppid {
            if self.session.process_tree.is_allowed_child(ppid) {
                let elapsed = start.elapsed().as_secs_f64() * 1000.0;
                let event = SecurityEvent {
                    session_id: self.session.id,
                    agent_id: self.session.agent_id.clone(),
                    source: EventSource::ShellProxy,
                    event_kind: EventKind::Command,
                    command_raw: raw.to_string(),
                    command_normalized: raw.to_string(),
                    cwd: cwd.to_path_buf(),
                    timestamp: chrono::Utc::now(),
                };
                return Ok(AnalysisResult {
                    event,
                    decision: Decision::Allow,
                    risk_score: 0.0,
                    cumulative_session_risk: self.session.cumulative_risk,
                    rule_triggered: Some("allow-by-parent".into()),
                    patterns_matched: vec!["allow-by-parent".into()],
                    obfuscation_detected: false,
                    execution_time_ms: elapsed,
                    allow_by_parent: true,
                });
            }
        }

        let norm = tokio::task::spawn_blocking({
            let raw_owned = raw.to_string();
            move || normalize(&raw_owned)
        })
        .await
        .map_err(|_| PipelineError::Ast(crate::ast::AstError::ParseFailed))?;

        let ir = self
            .command_parser
            .parse(&norm.normalized)
            .unwrap_or_else(|_| parse_command(&norm.normalized).unwrap_or_default());

        let obfuscation_detected = norm.obfuscation_detected || ir.obfuscation_hint;

        let event = SecurityEvent {
            session_id: self.session.id,
            agent_id: self.session.agent_id.clone(),
            source: EventSource::ShellProxy,
            event_kind: EventKind::Command,
            command_raw: raw.to_string(),
            command_normalized: norm.normalized.clone(),
            cwd: cwd.to_path_buf(),
            timestamp: chrono::Utc::now(),
        };

        let mut policy_match = self.policy.evaluate(&event, &norm, &ir);

        if let Some(decision) = crate::plugins::secrets_guard(&ir, &norm) {
            policy_match = crate::policy::PolicyMatch {
                decision,
                rule_name: Some("secrets-guard".into()),
                risk_score: policy_match.risk_score.max(0.95),
                patterns_matched: {
                    let mut p = policy_match.patterns_matched;
                    p.push("secrets-guard".into());
                    p
                },
            };
        }
        if let Some(decision) = crate::plugins::crypto_miner_detect(&event.command_normalized) {
            policy_match = crate::policy::PolicyMatch {
                decision,
                rule_name: Some("crypto-miner-detect".into()),
                risk_score: 1.0,
                patterns_matched: vec!["crypto-miner-detect".into()],
            };
        }

        let threat_result = self.threat_analyzer.analyze(&self.session, &policy_match);

        let mut patterns = policy_match.patterns_matched.clone();
        patterns.extend(threat_result.chain_patterns.clone());
        patterns.sort();
        patterns.dedup();

        self.threat_analyzer.record(
            &mut self.session,
            norm.normalized,
            &threat_result,
            patterns.clone(),
        );

        if matches!(threat_result.decision, Decision::Allow) {
            if let Some(pid) = exec_ctx.pid {
                self.session.process_tree.record_allowed(pid);
            }
        }

        let rule_triggered = policy_match
            .rule_name
            .or_else(|| match &threat_result.decision {
                Decision::Block { rule, .. } | Decision::Sandbox { rule, .. } => Some(rule.clone()),
                _ => None,
            });

        let elapsed = start.elapsed().as_secs_f64() * 1000.0;
        if elapsed > LATENCY_WARN_MS {
            tracing::warn!(
                "analysis latency {:.1}ms exceeded {}ms for command prefix: {}",
                elapsed,
                LATENCY_WARN_MS,
                raw.chars().take(40).collect::<String>()
            );
        }

        Ok(AnalysisResult {
            event: SecurityEvent {
                command_normalized: event.command_normalized,
                ..event
            },
            decision: threat_result.decision,
            risk_score: threat_result.risk_score,
            cumulative_session_risk: threat_result.cumulative_session_risk,
            rule_triggered,
            patterns_matched: patterns,
            obfuscation_detected,
            execution_time_ms: elapsed,
            allow_by_parent: false,
        })
    }

    pub fn analyze_command_static(
        raw: &str,
        policy: &PolicyEngine,
    ) -> Result<(Decision, f64, Vec<String>), PipelineError> {
        let norm = normalize(raw);
        let ir = parse_command(&norm.normalized).unwrap_or_default();

        let normalized = norm.normalized.clone();
        let event = SecurityEvent {
            session_id: uuid::Uuid::new_v4(),
            agent_id: None,
            source: EventSource::ShellProxy,
            event_kind: EventKind::Command,
            command_raw: raw.to_string(),
            command_normalized: normalized,
            cwd: std::env::current_dir().unwrap_or_default(),
            timestamp: chrono::Utc::now(),
        };

        let m = policy.evaluate(&event, &norm, &ir);
        Ok((m.decision, m.risk_score, m.patterns_matched))
    }
}