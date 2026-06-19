use std::fs;
use std::path::PathBuf;

use anyhow::{Context, Result};
use serde_json::{Map, Value};

const BASH_MARKER: &str = "# agentshield bootstrap";
const ZSH_MARKER: &str = "# agentshield bootstrap";
const PS_MARKER: &str = "# agentshield bootstrap";

pub fn run(profile: &str) -> Result<()> {
    let exe = std::env::current_exe().context("resolve agentshield binary")?;
    let exe_str = exe.to_string_lossy().into_owned();

    inject_shell_config(&exe_str)?;
    write_project_policy(profile)?;
    patch_vscode_settings(&exe_str)?;

    println!("AgentShield initialized.");
    println!("  Binary:  {exe_str}");
    println!("  Profile: {profile}");
    println!();
    println!("Set SHELL={exe_str} in your agent environment, or restart your shell.");

    Ok(())
}

fn inject_shell_config(exe: &str) -> Result<()> {
    if cfg!(windows) {
        inject_powershell_profile(exe)?;
    } else {
        inject_unix_shell(exe)?;
    }
    Ok(())
}

fn inject_unix_shell(exe: &str) -> Result<()> {
    let home = dirs::home_dir().context("home directory")?;

    for (name, rc) in [(".bashrc", BASH_MARKER), (".zshrc", ZSH_MARKER)] {
        let path = home.join(name);
        if path.exists() {
            backup(&path)?;
            append_if_missing(&path, rc, &format!("export SHELL='{exe}'"))?;
        }
    }
    Ok(())
}

fn inject_powershell_profile(exe: &str) -> Result<()> {
    let docs = dirs::document_dir().unwrap_or_else(|| PathBuf::from("."));
    let profile = docs
        .join("PowerShell")
        .join("Microsoft.PowerShell_profile.ps1");

    if let Some(parent) = profile.parent() {
        fs::create_dir_all(parent)?;
    }

    append_if_missing(&profile, PS_MARKER, &format!("$env:SHELL = '{exe}'"))?;
    Ok(())
}

fn write_project_policy(profile: &str) -> Result<()> {
    let cwd = std::env::current_dir().context("current dir")?;
    let src = match profile {
        "web-dev" => include_str!("../../../../policies/web-dev.yml"),
        "devops" => include_str!("../../../../policies/devops.yml"),
        "data-science" => include_str!("../../../../policies/data-science.yml"),
        "paranoid" | "minimal-paranoid" => include_str!("../../../../policies/paranoid.yml"),
        _ => include_str!("../../../../policies/default.yml"),
    };

    let dest = cwd.join(".agentshield.yml");
    if !dest.exists() {
        fs::write(&dest, src).context("write .agentshield.yml")?;
        println!("  Created {}", dest.display());
    }
    Ok(())
}

fn patch_vscode_settings(exe: &str) -> Result<()> {
    let Some(config_dir) = dirs::config_dir() else {
        return Ok(());
    };

    let settings_path = config_dir.join("Code").join("User").join("settings.json");

    let mut value: Value = if settings_path.exists() {
        let content = fs::read_to_string(&settings_path)?;
        match serde_json::from_str(&content) {
            Ok(v) => v,
            Err(e) => {
                eprintln!(
                    "  Warning: VS Code settings.json is not valid JSON ({e}); skipping patch"
                );
                return Ok(());
            }
        }
    } else {
        Value::Object(Map::new())
    };

    let obj = match value.as_object_mut() {
        Some(o) => o,
        None => return Ok(()),
    };

    if obj.contains_key("agentshield.enabled") {
        return Ok(());
    }

    if settings_path.exists() {
        backup(&settings_path)?;
    }

    set_env_block(obj, "terminal.integrated.env.linux", exe, true);
    set_env_block(obj, "terminal.integrated.env.osx", exe, true);
    set_env_block(obj, "terminal.integrated.env.windows", exe, false);
    obj.insert("agentshield.enabled".into(), Value::Bool(true));

    fs::write(
        &settings_path,
        serde_json::to_string_pretty(obj).context("serialize vscode settings")?,
    )
    .context("write vscode settings")?;
    println!("  Patched VS Code settings");
    Ok(())
}

fn set_env_block(obj: &mut Map<String, Value>, key: &str, exe: &str, use_shell: bool) {
    let mut env = obj
        .get(key)
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_default();
    if use_shell {
        env.insert("SHELL".into(), Value::String(exe.into()));
    } else {
        env.insert("AGENTSHIELD_BIN".into(), Value::String(exe.into()));
    }
    env.insert("AGENTSHIELD_AGENT".into(), Value::String("vscode".into()));
    obj.insert(key.into(), Value::Object(env));
}

fn backup(path: &PathBuf) -> Result<()> {
    let backup_path =
        path.with_extension(format!("bak.{}", chrono::Utc::now().format("%Y%m%d%H%M%S")));
    if path.exists() {
        fs::copy(path, &backup_path).context("backup config")?;
        println!(
            "  Backed up {} -> {}",
            path.display(),
            backup_path.display()
        );
    }
    Ok(())
}

fn append_if_missing(path: &PathBuf, marker: &str, line: &str) -> Result<()> {
    let content = fs::read_to_string(path).unwrap_or_default();
    if content.contains(marker) {
        return Ok(());
    }
    let mut file = fs::OpenOptions::new().append(true).open(path)?;
    use std::io::Write;
    writeln!(file, "\n{marker}")?;
    writeln!(file, "{line}")?;
    println!("  Updated {}", path.display());
    Ok(())
}
