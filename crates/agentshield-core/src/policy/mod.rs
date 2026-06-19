mod schema;

pub use schema::*;

use std::path::{Path, PathBuf};

use globset::{Glob, GlobSet, GlobSetBuilder};
use thiserror::Error;

use crate::ast::{BashParser, CommandIr};
use crate::decision::Decision;
use crate::obfuscation::NormalizationResult;
use crate::session::SecurityEvent;

#[derive(Debug, Error)]
pub enum PolicyError {
    #[error("failed to read policy file {path}: {source}")]
    Read {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("failed to parse policy: {0}")]
    Parse(#[from] serde_yaml::Error),
    #[error("invalid glob pattern: {0}")]
    Glob(#[from] globset::Error),
}

#[derive(Debug, Clone)]
pub struct PolicyEngine {
    pub document: PolicyDocument,
    read_deny: GlobSet,
    write_allow: GlobSet,
    write_deny: GlobSet,
}

impl PolicyEngine {
    pub fn from_document(document: PolicyDocument) -> Result<Self, PolicyError> {
        Ok(Self {
            read_deny: compile_globs(&document.filesystem.deny_read)?,
            write_allow: compile_globs(&document.filesystem.allow_write)?,
            write_deny: compile_globs(&document.filesystem.deny_write)?,
            document,
        })
    }

    pub fn load_layered(project_root: Option<&Path>) -> Result<Self, PolicyError> {
        let mut merged = PolicyDocument::builtin_default();
        let mut loaded_any = false;

        if let Some(system) = system_policy_path() {
            if system.exists() {
                merge_document(&mut merged, &load_file(&system)?);
                loaded_any = true;
            }
        }

        if let Some(user) = user_policy_path() {
            if user.exists() {
                merge_document(&mut merged, &load_file(&user)?);
                loaded_any = true;
            }
        }

        if let Some(root) = project_root {
            let project = root.join(".agentshield.yml");
            if project.exists() {
                merge_document(&mut merged, &load_file(&project)?);
                loaded_any = true;
            }
        }

        if !loaded_any {
            merged = PolicyDocument::builtin_default();
        }

        Self::from_document(merged)
    }

    pub fn evaluate(
        &self,
        event: &SecurityEvent,
        norm: &NormalizationResult,
        ir: &CommandIr,
    ) -> PolicyMatch {
        let mut patterns = Vec::new();
        let mut risk_score = 0.0_f64;
        let mut best: Option<PolicyMatch> = None;

        if norm.obfuscation_detected {
            patterns.push("obfuscation".into());
            risk_score += 0.4;
        }
        if ir.pipe_to_shell {
            patterns.push("pipe-to-shell".into());
            risk_score += 0.85;
        }
        if !ir.indirect_executors.is_empty() {
            patterns.push("indirect-exec".into());
            risk_score += 0.5;
        }
        if !ir.external_urls.is_empty() {
            patterns.push("external-url-fetch".into());
            risk_score += 0.3;
        }

        for rule in &self.document.rules {
            if rule_matches(rule, &event.command_normalized, ir, norm) {
                patterns.push(rule.name.clone());
                risk_score = risk_score.max(rule.severity.risk_weight());

                let decision = match rule.action {
                    RuleAction::Allow => Decision::Allow,
                    RuleAction::Prompt => Decision::Prompt {
                        message: rule.message.clone().unwrap_or_else(|| rule.name.clone()),
                        details: format!("Rule '{}' matched", rule.name),
                    },
                    RuleAction::Block => Decision::Block {
                        message: rule.message.clone().unwrap_or_else(|| rule.name.clone()),
                        rule: rule.name.clone(),
                    },
                    RuleAction::Sandbox => Decision::Sandbox {
                        message: rule.message.clone().unwrap_or_else(|| rule.name.clone()),
                        rule: rule.name.clone(),
                    },
                };

                let candidate = PolicyMatch {
                    decision,
                    rule_name: Some(rule.name.clone()),
                    risk_score: risk_score.min(1.0),
                    patterns_matched: patterns.clone(),
                };

                best = Some(merge_match(best, candidate));
            }
        }

        if let Some(network) = self.check_network(&event.command_normalized) {
            best = Some(merge_match(best, network));
        }

        best.unwrap_or(PolicyMatch {
            decision: Decision::Allow,
            rule_name: None,
            risk_score: risk_score.min(1.0),
            patterns_matched: patterns,
        })
    }

    pub fn check_read_path(&self, path: &str) -> Option<Decision> {
        if self.read_deny.is_match(path) {
            return Some(Decision::Block {
                message: format!("Read denied for protected path: {path}"),
                rule: "filesystem-deny-read".into(),
            });
        }
        None
    }

    pub fn check_write_path(&self, path: &str) -> Option<Decision> {
        if self.write_deny.is_match(path) {
            return Some(Decision::Block {
                message: format!("Write denied for protected path: {path}"),
                rule: "filesystem-deny-write".into(),
            });
        }
        if !self.write_allow.is_empty() && !self.write_allow.is_match(path) {
            return Some(Decision::Prompt {
                message: format!("Write outside allowed paths: {path}"),
                details: "Path not in filesystem.allow_write".into(),
            });
        }
        None
    }

    fn check_network(&self, command: &str) -> Option<PolicyMatch> {
        let fetchers = ["curl", "wget", "nc", "ncat"];
        if !fetchers.iter().any(|f| command.contains(f)) {
            return None;
        }

        if self.document.network.block_unknown {
            for domain in &self.document.network.allowed_domains {
                if command.contains(domain) {
                    return None;
                }
            }
            return Some(PolicyMatch {
                decision: Decision::Block {
                    message: "Network request to unknown domain blocked".into(),
                    rule: "network-block-unknown".into(),
                },
                rule_name: Some("network-block-unknown".into()),
                risk_score: 0.7,
                patterns_matched: vec!["network-egress".into()],
            });
        }
        None
    }
}

#[derive(Debug, Clone)]
pub struct PolicyMatch {
    pub decision: Decision,
    pub rule_name: Option<String>,
    pub risk_score: f64,
    pub patterns_matched: Vec<String>,
}

fn merge_match(current: Option<PolicyMatch>, next: PolicyMatch) -> PolicyMatch {
    match current {
        None => next,
        Some(cur) => {
            if decision_priority(&next.decision) >= decision_priority(&cur.decision) {
                PolicyMatch {
                    patterns_matched: {
                        let mut p = cur.patterns_matched;
                        p.extend(next.patterns_matched);
                        p.sort();
                        p.dedup();
                        p
                    },
                    risk_score: cur.risk_score.max(next.risk_score),
                    ..next
                }
            } else {
                let mut cur = cur;
                cur.risk_score = cur.risk_score.max(next.risk_score);
                cur.patterns_matched.extend(next.patterns_matched);
                cur.patterns_matched.sort();
                cur.patterns_matched.dedup();
                cur
            }
        }
    }
}

fn decision_priority(d: &Decision) -> u8 {
    match d {
        Decision::Allow => 0,
        Decision::Sandbox { .. } => 1,
        Decision::Prompt { .. } => 2,
        Decision::Block { .. } => 3,
    }
}

fn rule_matches(rule: &Rule, command: &str, ir: &CommandIr, norm: &NormalizationResult) -> bool {
    if let Some(cmd) = &rule.r#match.command {
        if !command_contains_cmd(command, cmd) && !ir_has_cmd(ir, cmd) {
            return false;
        }
    }

    if let Some(flags) = &rule.r#match.flags_include {
        if !flags.iter().all(|f| command.contains(f)) {
            return false;
        }
    }

    if let Some(pattern) = &rule.r#match.pattern {
        if !command.contains(pattern) && !norm.normalized.contains(pattern) {
            return false;
        }
    }

    if let Some(requires) = &rule.r#match.requires_any {
        if !requires.iter().any(|r| command.contains(r)) {
            return false;
        }
    }

    if rule.r#match.pipe_to_shell == Some(true) && !ir.pipe_to_shell {
        return false;
    }

    if rule.r#match.obfuscation == Some(true) && !norm.obfuscation_detected {
        return false;
    }

    if rule.r#match.indirect_exec == Some(true) && ir.indirect_executors.is_empty() {
        return false;
    }

    if let Some(ctx) = &rule.r#match.context {
        if ctx.contains("pipe_destination") && !ir.pipe_to_shell {
            return false;
        }
    }

    true
}

fn command_contains_cmd(command: &str, cmd: &str) -> bool {
    command
        .split_whitespace()
        .any(|w| w == cmd || w.ends_with(&format!("/{cmd}")))
}

fn ir_has_cmd(ir: &CommandIr, cmd: &str) -> bool {
    ir.pipelines
        .iter()
        .flat_map(|p| &p.commands)
        .any(|c| c.name == cmd)
}

fn compile_globs(patterns: &[String]) -> Result<GlobSet, PolicyError> {
    let mut builder = GlobSetBuilder::new();
    for p in patterns {
        builder.add(Glob::new(p)?);
    }
    Ok(builder.build()?)
}

fn load_file(path: &Path) -> Result<PolicyDocument, PolicyError> {
    let content = std::fs::read_to_string(path).map_err(|source| PolicyError::Read {
        path: path.to_path_buf(),
        source,
    })?;
    Ok(serde_yaml::from_str(&content)?)
}

fn merge_document(base: &mut PolicyDocument, overlay: &PolicyDocument) {
    if overlay.version.is_some() {
        base.version = overlay.version.clone();
    }
    if overlay.trust_level.is_some() {
        base.trust_level = overlay.trust_level;
    }
    base.rules.extend(overlay.rules.clone());
    base.filesystem
        .allow_write
        .extend(overlay.filesystem.allow_write.clone());
    base.filesystem
        .deny_read
        .extend(overlay.filesystem.deny_read.clone());
    base.filesystem
        .deny_write
        .extend(overlay.filesystem.deny_write.clone());
    base.network
        .allowed_domains
        .extend(overlay.network.allowed_domains.clone());
    if overlay.network.block_unknown {
        base.network.block_unknown = true;
    }
    if let Some(w) = overlay.session.threat_chain_window {
        base.session.threat_chain_window = Some(w);
    }
    if let Some(t) = overlay.session.cumulative_risk_threshold {
        base.session.cumulative_risk_threshold = Some(t);
    }
}

pub fn system_policy_path() -> Option<PathBuf> {
    if cfg!(windows) {
        std::env::var("PROGRAMDATA")
            .ok()
            .map(|p| PathBuf::from(p).join("agentshield").join("policy.yml"))
    } else {
        Some(PathBuf::from("/etc/agentshield/policy.yml"))
    }
}

pub fn user_policy_path() -> Option<PathBuf> {
    dirs::config_dir().map(|p| p.join("agentshield").join("policy.yml"))
}

pub fn parse_for_test(command: &str) -> (NormalizationResult, CommandIr) {
    let norm = crate::obfuscation::normalize(command);
    let ir = BashParser::new()
        .and_then(|mut p| p.parse(&norm.normalized))
        .unwrap_or_default();
    (norm, ir)
}
