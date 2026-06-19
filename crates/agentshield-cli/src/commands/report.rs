use std::fs;

use agentshield_core::log_directory;
use anyhow::{Context, Result};
use serde::Deserialize;

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct LogLine {
    decision: String,
    #[serde(default)]
    risk_score: f64,
    rule_triggered: Option<String>,
    #[serde(default)]
    command_raw: String,
}

pub fn run(period: &str) -> Result<()> {
    let log_dir = log_directory();
    let today = chrono::Utc::now().format("%Y-%m-%d").to_string();

    let files: Vec<_> = fs::read_dir(&log_dir)
        .context("read log dir")?
        .filter_map(|e| e.ok())
        .filter(|e| {
            let name = e.file_name().to_string_lossy().to_string();
            if period == "today" {
                name.contains(&today)
            } else {
                name.ends_with(".jsonl")
            }
        })
        .collect();

    let mut total = 0u64;
    let mut blocked = 0u64;
    let mut prompted = 0u64;
    let mut rules: std::collections::HashMap<String, u64> = std::collections::HashMap::new();

    for entry in files {
        let content = fs::read_to_string(entry.path())?;
        for line in content.lines() {
            if line.trim().is_empty() {
                continue;
            }
            if let Ok(entry) = serde_json::from_str::<LogLine>(line) {
                total += 1;
                match entry.decision.as_str() {
                    "block" => blocked += 1,
                    "prompt" => prompted += 1,
                    _ => {}
                }
                if let Some(rule) = entry.rule_triggered {
                    *rules.entry(rule).or_insert(0) += 1;
                }
            }
        }
    }

    println!("# AgentShield Report ({period})\n");
    println!("| Metric | Value |");
    println!("|--------|-------|");
    println!("| Total commands | {total} |");
    println!("| Blocked | {blocked} |");
    println!("| Prompted | {prompted} |");

    if !rules.is_empty() {
        println!("\n## Top Rules\n");
        let mut sorted: Vec<_> = rules.into_iter().collect();
        sorted.sort_by_key(|(_, count)| std::cmp::Reverse(*count));
        for (rule, count) in sorted.into_iter().take(5) {
            println!("- {rule}: {count}");
        }
    }

    Ok(())
}
