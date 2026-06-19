use std::process::Command;

use anyhow::{Context, Result};

pub fn run(deep: bool) -> Result<()> {
    let exe = std::env::current_exe().context("resolve binary")?;
    let daemon_exe = find_daemon_binary()?;

    if deep {
        install_daemon_service(&daemon_exe)?;
        println!("Deep install complete.");
        println!("  Daemon: {}", daemon_exe.display());
        println!("  OS-native collectors: enabled");
    } else {
        println!("Standard install: use `agentshield init` for shell proxy setup.");
    }

    println!("  CLI:    {}", exe.display());
    println!();
    println!("Run `agentshield status` to verify daemon connectivity.");

    Ok(())
}

fn find_daemon_binary() -> Result<std::path::PathBuf> {
    let current = std::env::current_exe()?;
    let dir = current.parent().context("binary parent")?;

    let candidates = [
        dir.join("agentshield-daemon.exe"),
        dir.join("agentshield-daemon"),
        dir.join("../agentshield-daemon.exe"),
        dir.join("../agentshield-daemon"),
    ];

    for c in candidates {
        if c.exists() {
            return Ok(c.canonicalize().unwrap_or(c));
        }
    }

    which_daemon_via_cargo()
}

fn which_daemon_via_cargo() -> Result<std::path::PathBuf> {
    let out = Command::new("cargo")
        .args(["build", "-p", "agentshield-daemon", "--quiet"])
        .status();
    if out.map(|s| s.success()).unwrap_or(false) {
        let path = std::path::PathBuf::from("target/debug/agentshield-daemon.exe");
        if path.exists() {
            return Ok(path);
        }
        let path = std::path::PathBuf::from("target/debug/agentshield-daemon");
        if path.exists() {
            return Ok(path);
        }
    }
    anyhow::bail!("agentshield-daemon binary not found; run `cargo build -p agentshield-daemon`")
}

#[cfg(windows)]
fn install_daemon_service(daemon: &std::path::Path) -> Result<()> {
    use std::os::windows::process::CommandExt;
    const CREATE_NO_WINDOW: u32 = 0x0800_0000;

    let script = format!(
        r#"
$action = New-ScheduledTaskAction -Execute '{exe}'
$trigger = New-ScheduledTaskTrigger -AtLogOn
Register-ScheduledTask -TaskName 'AgentShieldDaemon' -Action $action -Trigger $trigger -Force
Start-ScheduledTask -TaskName 'AgentShieldDaemon'
"#,
        exe = daemon.display()
    );

    Command::new("powershell")
        .args(["-NoProfile", "-Command", &script])
        .creation_flags(CREATE_NO_WINDOW)
        .status()
        .context("register scheduled task")?;

    println!("  Registered Windows scheduled task: AgentShieldDaemon");
    Ok(())
}

#[cfg(not(windows))]
fn install_daemon_service(daemon: &std::path::Path) -> Result<()> {
    let service_dir = dirs::config_dir()
        .unwrap_or_else(|| std::path::PathBuf::from("."))
        .join("agentshield");

    std::fs::create_dir_all(&service_dir)?;
    let script = service_dir.join("start-daemon.sh");
    std::fs::write(
        &script,
        format!("#!/bin/sh\nexec '{}' \"$@\"\n", daemon.display()),
    )?;

    #[cfg(target_os = "linux")]
    {
        let unit = format!(
            "[Unit]\nDescription=AgentShield Security Daemon\nAfter=network.target\n\n[Service]\nExecStart={}\nRestart=on-failure\n\n[Install]\nWantedBy=default.target\n",
            daemon.display()
        );
        let unit_path = service_dir.join("agentshield-daemon.service");
        std::fs::write(&unit_path, unit)?;
        println!("  systemd unit written: {}", unit_path.display());
        println!("  Enable: systemctl --user enable {}", unit_path.display());
    }

    Command::new(daemon).spawn().context("spawn daemon")?;
    println!("  Daemon started in background");
    Ok(())
}
