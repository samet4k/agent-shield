//! Network egress enforcement backed by policy domain rules.

use crate::decision::Decision;
use crate::policy::PolicyEngine;

/// Extract a likely hostname from a URL or command fragment.
pub fn extract_host(target: &str) -> Option<String> {
    let trimmed = target.trim();
    let without_scheme = trimmed
        .strip_prefix("https://")
        .or_else(|| trimmed.strip_prefix("http://"))
        .unwrap_or(trimmed);
    let host = without_scheme.split('/').next()?.split(':').next()?;
    if host.is_empty() || host.contains(' ') {
        None
    } else {
        Some(host.to_lowercase())
    }
}

/// Evaluate a network request target against policy.
pub fn check_request(policy: &PolicyEngine, target: &str) -> Option<Decision> {
    let host = extract_host(target)?;
    let command = format!("curl {host}");
    policy
        .evaluate_network_command(&command)
        .map(|m| m.decision)
}

/// Enforce network egress for a URL or host.
pub fn enforce_request(policy: &PolicyEngine, target: &str) -> Result<(), String> {
    match check_request(policy, target) {
        Some(Decision::Block { message, .. }) => Err(message),
        Some(Decision::Prompt { message, .. }) => Err(message),
        _ => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::PolicyDocument;

    #[test]
    fn blocks_unknown_domain_when_configured() {
        let mut doc = PolicyDocument::builtin_default();
        doc.network.block_unknown = true;
        doc.network.allowed_domains = vec!["github.com".into()];
        let policy = PolicyEngine::from_document(doc).unwrap();
        assert!(enforce_request(&policy, "https://evil.com/leak").is_err());
        assert!(enforce_request(&policy, "https://github.com/repo").is_ok());
    }
}