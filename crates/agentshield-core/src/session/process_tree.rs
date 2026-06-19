use std::collections::HashSet;

/// Tracks PIDs that received an explicit allow decision for allow-by-parent bypass.
#[derive(Debug, Default, Clone)]
pub struct ProcessTreeTracker {
    allowed_pids: HashSet<u32>,
}

impl ProcessTreeTracker {
    pub fn record_allowed(&mut self, pid: u32) {
        if pid > 0 {
            self.allowed_pids.insert(pid);
        }
    }

    pub fn is_allowed_child(&self, ppid: u32) -> bool {
        ppid > 0 && self.allowed_pids.contains(&ppid)
    }

    pub fn clear(&mut self) {
        self.allowed_pids.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allow_by_parent() {
        let mut tree = ProcessTreeTracker::default();
        tree.record_allowed(100);
        assert!(tree.is_allowed_child(100));
        assert!(!tree.is_allowed_child(200));
    }
}