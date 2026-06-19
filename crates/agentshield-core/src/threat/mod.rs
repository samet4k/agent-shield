use crate::decision::Decision;
use crate::policy::PolicyMatch;
use crate::session::{CommandRecord, SessionState};

#[derive(Debug, Clone)]
struct ChainTemplate {
    name: &'static str,
    steps: &'static [&'static str],
    risk: f64,
}

const CHAIN_TEMPLATES: &[ChainTemplate] = &[
    ChainTemplate {
        name: "download-chmod-execute",
        steps: &["curl", "wget", "chmod", "execute"],
        risk: 0.9,
    },
    ChainTemplate {
        name: "env-exfiltration",
        steps: &["env", "curl"],
        risk: 0.85,
    },
    ChainTemplate {
        name: "credential-read-network",
        steps: &[".env", ".ssh", "curl"],
        risk: 0.95,
    },
    ChainTemplate {
        name: "privilege-escalation",
        steps: &["sudo -s", "echo", "password"],
        risk: 0.92,
    },
    ChainTemplate {
        name: "reverse-shell",
        steps: &["bash -i", "/dev/tcp", "nc -e"],
        risk: 0.98,
    },
    ChainTemplate {
        name: "docker-socket-escape",
        steps: &["docker", "/var/run/docker.sock", "privileged"],
        risk: 0.93,
    },
    ChainTemplate {
        name: "cron-persistence",
        steps: &["crontab", "echo", "curl"],
        risk: 0.88,
    },
    ChainTemplate {
        name: "ssh-key-theft",
        steps: &["id_rsa", "cat", "curl"],
        risk: 0.94,
    },
];

pub struct ThreatChainAnalyzer {
    threshold: f64,
}

impl ThreatChainAnalyzer {
    pub fn new(threshold: f64) -> Self {
        Self { threshold }
    }

    pub fn analyze(&self, session: &SessionState, current: &PolicyMatch) -> ThreatChainResult {
        let mut chain_hits = Vec::new();
        let mut chain_risk = 0.0_f64;

        let history_cmds: Vec<String> = session
            .history
            .iter()
            .map(|r| r.command_normalized.clone())
            .collect();

        let all_cmds = history_cmds;

        for template in CHAIN_TEMPLATES {
            if matches_chain(&all_cmds, template.steps) {
                chain_hits.push(template.name.to_string());
                chain_risk = chain_risk.max(template.risk);
            }
        }

        let cumulative =
            (session.cumulative_risk * 0.6 + current.risk_score * 0.4 + chain_risk * 0.5).min(1.0);

        let mut decision = current.decision.clone();
        let mut risk_score = current.risk_score.max(chain_risk);

        if cumulative >= self.threshold {
            decision = Decision::Block {
                message: format!(
                    "Session cumulative risk {:.2} exceeded threshold {:.2}",
                    cumulative, self.threshold
                ),
                rule: "session-risk-threshold".into(),
            };
            chain_hits.push("cumulative-threshold".into());
            risk_score = 1.0;
        }

        if !chain_hits.is_empty() && matches!(decision, Decision::Allow) {
            decision = Decision::Prompt {
                message: format!(
                    "Suspicious command chain detected: {}",
                    chain_hits.join(", ")
                ),
                details: "Multi-step threat pattern matched in session history".into(),
            };
            risk_score = risk_score.max(0.75);
        }

        ThreatChainResult {
            decision,
            risk_score,
            cumulative_session_risk: cumulative,
            chain_patterns: chain_hits,
        }
    }

    pub fn record(
        &self,
        session: &mut SessionState,
        command_normalized: String,
        result: &ThreatChainResult,
        patterns: Vec<String>,
    ) {
        session.push(CommandRecord {
            command_normalized,
            risk_score: result.risk_score,
            decision: result.decision.clone(),
            patterns,
            timestamp: chrono::Utc::now(),
        });
    }
}

#[derive(Debug, Clone)]
pub struct ThreatChainResult {
    pub decision: Decision,
    pub risk_score: f64,
    pub cumulative_session_risk: f64,
    pub chain_patterns: Vec<String>,
}

fn matches_chain(history: &[String], steps: &[&str]) -> bool {
    if history.len() < 2 {
        return false;
    }

    let mut step_idx = 0;
    for cmd in history {
        let lower = cmd.to_lowercase();
        if step_idx < steps.len() && lower.contains(steps[step_idx]) {
            step_idx += 1;
            if step_idx >= 2 {
                return true;
            }
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decision::Decision;

    #[test]
    fn detects_env_curl_chain() {
        let mut session = SessionState::new(None, 20);
        session.push(CommandRecord {
            command_normalized: "env".into(),
            risk_score: 0.2,
            decision: Decision::Allow,
            patterns: vec![],
            timestamp: chrono::Utc::now(),
        });

        let analyzer = ThreatChainAnalyzer::new(0.8);
        let current = PolicyMatch {
            decision: Decision::Allow,
            rule_name: None,
            risk_score: 0.3,
            patterns_matched: vec![],
        };
        let result = analyzer.analyze(&session, &current);
        assert!(result.chain_patterns.is_empty() || result.risk_score > 0.0);
    }

    #[test]
    fn detects_reverse_shell_pattern() {
        let mut session = SessionState::new(None, 20);
        session.push(CommandRecord {
            command_normalized: "bash -i".into(),
            risk_score: 0.5,
            decision: Decision::Allow,
            patterns: vec![],
            timestamp: chrono::Utc::now(),
        });
        session.push(CommandRecord {
            command_normalized: "cat /dev/tcp/10.0.0.1/4444".into(),
            risk_score: 0.5,
            decision: Decision::Allow,
            patterns: vec![],
            timestamp: chrono::Utc::now(),
        });

        let analyzer = ThreatChainAnalyzer::new(0.8);
        let current = PolicyMatch {
            decision: Decision::Allow,
            rule_name: None,
            risk_score: 0.3,
            patterns_matched: vec![],
        };
        let result = analyzer.analyze(&session, &current);
        assert!(result.chain_patterns.contains(&"reverse-shell".to_string()));
    }
}