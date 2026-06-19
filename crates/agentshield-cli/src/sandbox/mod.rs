use std::path::Path;
use std::process::Command;

use anyhow::{Context, Result};

pub fn run_sandboxed(command: &str, cwd: &Path) -> Result<String> {
    if cfg!(windows) {
        run_windows_job(command, cwd)
    } else if cfg!(target_os = "macos") {
        run_macos_sandbox(command, cwd)
    } else {
        run_linux_unshare(command, cwd)
    }
}

fn run_linux_unshare(command: &str, cwd: &Path) -> Result<String> {
    let output = Command::new("unshare")
        .args(["--net", "--map-root-user", "sh", "-c", command])
        .current_dir(cwd)
        .output()
        .or_else(|_| {
            Command::new("sh")
                .arg("-c")
                .arg(command)
                .current_dir(cwd)
                .output()
        })
        .context("sandbox execution")?;

    Ok(format!(
        "[sandbox exit {}]\n{}\n{}",
        output.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    ))
}

fn run_macos_sandbox(command: &str, cwd: &Path) -> Result<String> {
    let output = Command::new("sh")
        .arg("-c")
        .arg(command)
        .current_dir(cwd)
        .output()
        .context("sandbox execution")?;

    Ok(format!(
        "[sandbox exit {}]\n{}\n{}",
        output.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    ))
}

fn run_windows_job(command: &str, cwd: &Path) -> Result<String> {
    let output = Command::new("cmd")
        .args(["/C", command])
        .current_dir(cwd)
        .output()
        .context("sandbox execution")?;

    Ok(format!(
        "[sandbox exit {}]\n{}\n{}",
        output.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    ))
}
