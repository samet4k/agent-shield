//! Built-in policy analyzers (Rust-native; WASM plugins live in plugin-sdk).

use crate::ast::CommandIr;
use crate::decision::Decision;
use crate::obfuscation::NormalizationResult;

pub fn secrets_guard(ir: &CommandIr, norm: &NormalizationResult) -> Option<Decision> {
    let touches_env = norm.normalized.contains("env")
        || ir
            .pipelines
            .iter()
            .flat_map(|p| &p.commands)
            .any(|c| c.name == "env");
    let has_network = !ir.external_urls.is_empty()
        || norm.normalized.contains("curl")
        || norm.normalized.contains("wget");

    if touches_env && has_network {
        return Some(Decision::Block {
            message: "Env file access with network capability detected".into(),
            rule: "secrets-guard".into(),
        });
    }
    None
}

pub fn crypto_miner_detect(command: &str) -> Option<Decision> {
    let miners = ["xmrig", "minerd", "cpuminer", "stratum+tcp"];
    if miners.iter().any(|m| command.contains(m)) {
        return Some(Decision::Block {
            message: "Cryptocurrency miner pattern detected".into(),
            rule: "crypto-miner-detect".into(),
        });
    }
    None
}

pub fn filesystem_fence(path: &str) -> Option<Decision> {
    let denied = [".ssh/id_rsa", "/etc/shadow", "credentials.json"];
    if denied.iter().any(|d| path.contains(d)) {
        return Some(Decision::Block {
            message: format!("Filesystem fence blocked access to {path}"),
            rule: "filesystem-fence".into(),
        });
    }
    None
}
