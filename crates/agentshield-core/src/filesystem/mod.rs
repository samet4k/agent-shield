//! Filesystem path enforcement backed by policy glob rules.

use crate::decision::Decision;
use crate::policy::PolicyEngine;

/// Evaluate read access to a filesystem path.
pub fn check_read(policy: &PolicyEngine, path: &str) -> Option<Decision> {
    policy.check_read_path(path)
}

/// Evaluate write access to a filesystem path.
pub fn check_write(policy: &PolicyEngine, path: &str) -> Option<Decision> {
    policy.check_write_path(path)
}

/// Enforce read access, returning an error message when blocked.
pub fn enforce_read(policy: &PolicyEngine, path: &str) -> Result<(), String> {
    match check_read(policy, path) {
        Some(Decision::Block { message, .. }) => Err(message),
        Some(Decision::Prompt { message, .. }) => Err(message),
        _ => Ok(()),
    }
}

/// Enforce write access, returning an error message when blocked or prompted.
pub fn enforce_write(policy: &PolicyEngine, path: &str) -> Result<(), String> {
    match check_write(policy, path) {
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
    fn blocks_sensitive_read() {
        let mut doc = PolicyDocument::builtin_default();
        doc.filesystem.deny_read.push("**/.env".into());
        let policy = PolicyEngine::from_document(doc).unwrap();
        assert!(enforce_read(&policy, ".env").is_err());
        assert!(enforce_read(&policy, "readme.md").is_ok());
    }
}