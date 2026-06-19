use std::fs;
use std::path::Path;

use agentshield_core::{Decision, PolicyDocument, PolicyEngine};
use anyhow::{bail, Context, Result};
use walkdir::WalkDir;

#[derive(Debug, serde::Deserialize)]
struct BypassCase {
    name: String,
    command: String,
    expect: String,
    #[serde(default)]
    min_risk: Option<f64>,
}

fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();
    let suite = args.get(1).map(|s| s.as_str()).unwrap_or("bypass");

    match suite {
        "bypass" => run_bypass_suite(),
        "bench" => run_bench(),
        _ => bail!("unknown suite: {suite}"),
    }
}

fn run_bypass_suite() -> Result<()> {
    let policy = PolicyEngine::from_document(PolicyDocument::builtin_default())?;
    let suite_dir = Path::new("tests/bypass-suite");

    let mut passed = 0u32;
    let mut failed = 0u32;

    for entry in WalkDir::new(suite_dir).into_iter().filter_map(|e| e.ok()) {
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("yml") {
            continue;
        }

        let content = fs::read_to_string(path).context("read bypass case")?;
        let case: BypassCase = serde_yaml::from_str(&content)?;

        let (decision, risk, patterns) =
            agentshield_core::pipeline::AnalysisPipeline::analyze_command_static(
                &case.command,
                &policy,
            )?;

        let ok = match case.expect.as_str() {
            "block" => matches!(decision, Decision::Block { .. }),
            "prompt" => matches!(decision, Decision::Prompt { .. }),
            "allow" => matches!(decision, Decision::Allow),
            other => bail!("unknown expectation: {other}"),
        };

        let risk_ok = case.min_risk.map(|min| risk >= min).unwrap_or(true);

        if ok && risk_ok {
            println!(
                "PASS  {} ({:?}, risk={:.2})",
                case.name,
                decision.label(),
                risk
            );
            passed += 1;
        } else {
            println!(
                "FAIL  {} expected={} got={} risk={:.2} patterns={:?}",
                case.name,
                case.expect,
                decision.label(),
                risk,
                patterns
            );
            failed += 1;
        }
    }

    println!("\n{passed} passed, {failed} failed");
    if failed > 0 {
        bail!("bypass suite failures");
    }
    Ok(())
}

fn run_bench() -> Result<()> {
    use std::time::Instant;

    let policy = PolicyEngine::from_document(PolicyDocument::builtin_default())?;
    let commands = ["ls -la", "pwd", "echo hello", "git status", "cargo check"];

    let n = 2000usize;
    let start = Instant::now();
    for i in 0..n {
        let cmd = commands[i % commands.len()];
        let _ = agentshield_core::pipeline::AnalysisPipeline::analyze_command_static(cmd, &policy)?;
    }
    let elapsed = start.elapsed();
    let avg_ms = elapsed.as_secs_f64() * 1000.0 / n as f64;
    println!("Benchmark: {n} commands, avg {avg_ms:.3}ms");
    Ok(())
}
