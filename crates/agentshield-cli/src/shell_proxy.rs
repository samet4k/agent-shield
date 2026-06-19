use std::io::{IsTerminal, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use anyhow::{Context, Result};
use portable_pty::{native_pty_system, CommandBuilder, PtySize};

use agentshield_core::{write_command_log, AnalysisPipeline, Decision, PipelineError};

use crate::sandbox;

const PROMPT_PREFIX: &str = "[agentshield] ";

pub async fn run() -> Result<()> {
    let cwd = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
    let agent_id = std::env::var("AGENTSHIELD_AGENT").ok();

    let pipeline = AnalysisPipeline::from_project(Some(&cwd), agent_id)
        .map_err(|e: PipelineError| anyhow::anyhow!("{e}"))?;
    let pipeline = Arc::new(Mutex::new(pipeline));

    if std::io::stdin().is_terminal() {
        run_interactive(Arc::clone(&pipeline), cwd)
    } else {
        let mut input = String::new();
        std::io::stdin()
            .read_to_string(&mut input)
            .context("read stdin")?;
        let command = input.trim();
        if command.is_empty() {
            return Ok(());
        }
        let result = {
            let mut guard = pipeline.lock().unwrap();
            guard.analyze_command(command, &cwd)?
        };
        execute_result(&result, command, &cwd).await
    }
}

fn run_interactive(pipeline: Arc<Mutex<AnalysisPipeline>>, cwd: PathBuf) -> Result<()> {
    let pty_system = native_pty_system();
    let pair = pty_system
        .openpty(PtySize {
            rows: 24,
            cols: 80,
            pixel_width: 0,
            pixel_height: 0,
        })
        .context("open pty")?;

    let shell = default_shell();
    let mut cmd = CommandBuilder::new(&shell);
    cmd.cwd(&cwd);
    if !cfg!(windows) {
        cmd.arg("-i");
    }

    let _child = pair.slave.spawn_command(cmd).context("spawn shell")?;

    let mut reader = pair.master.try_clone_reader().context("pty reader")?;
    let mut writer = pair.master.take_writer().context("pty writer")?;

    let line_buffer: Arc<Mutex<String>> = Arc::new(Mutex::new(String::new()));
    let intercept_buffer = Arc::clone(&line_buffer);

    std::thread::spawn(move || {
        let mut buf = [0u8; 4096];
        loop {
            match reader.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => {
                    let _ = std::io::stdout().write_all(&buf[..n]);
                    let _ = std::io::stdout().flush();
                }
                Err(_) => break,
            }
        }
    });

    let mut stdin_buf = [0u8; 1];
    loop {
        let n = std::io::stdin().read(&mut stdin_buf)?;
        if n == 0 {
            break;
        }
        let byte = stdin_buf[0];

        let mut guard = intercept_buffer.lock().unwrap();
        if byte == b'\n' || byte == b'\r' {
            let line = guard.trim().to_string();
            guard.clear();
            drop(guard);

            if line.is_empty() {
                let _ = writer.write_all(&[byte]);
            } else if line == "exit" {
                break;
            } else {
                let mut pipe = pipeline.lock().unwrap();
                match pipe.analyze_command(&line, &cwd) {
                    Ok(result) => {
                        write_command_log(&result).ok();
                        match handle_decision_sync(&result.decision, &line, &cwd, &mut writer) {
                            Ok(forward) => {
                                if forward {
                                    writeln!(writer, "{line}")?;
                                    writer.flush()?;
                                }
                            }
                            Err(e) => eprintln!("{PROMPT_PREFIX}{e}"),
                        }
                    }
                    Err(e) => eprintln!("{PROMPT_PREFIX}{e}"),
                }
            }
        } else if byte == 127 || byte == 8 {
            guard.pop();
            let _ = writer.write_all(&[byte]);
        } else {
            guard.push(byte as char);
            let _ = writer.write_all(&[byte]);
        }
    }

    Ok(())
}

fn handle_decision_sync(
    decision: &Decision,
    command: &str,
    cwd: &Path,
    writer: &mut Box<dyn Write + Send>,
) -> Result<bool> {
    match decision {
        Decision::Allow => Ok(true),
        Decision::Prompt { message, details } => {
            writeln!(writer, "\r\n{PROMPT_PREFIX}{message}")?;
            writeln!(writer, "{PROMPT_PREFIX}{details}")?;
            write!(writer, "{PROMPT_PREFIX}Allow? [Y/n] ")?;
            writer.flush()?;
            Ok(prompt_approved()?)
        }
        Decision::Block { message, rule } => {
            writeln!(writer, "\r\n{PROMPT_PREFIX}BLOCKED [{rule}]: {message}")?;
            writer.flush()?;
            Ok(false)
        }
        Decision::Sandbox { message, rule } => {
            writeln!(writer, "\r\n{PROMPT_PREFIX}SANDBOX [{rule}]: {message}")?;
            let output = sandbox::run_sandboxed(command, cwd)?;
            write!(writer, "{output}")?;
            writer.flush()?;
            Ok(false)
        }
    }
}

async fn execute_result(
    result: &agentshield_core::pipeline::AnalysisResult,
    command: &str,
    cwd: &Path,
) -> Result<()> {
    write_command_log(result).ok();

    match &result.decision {
        Decision::Allow => run_command(command, cwd).await,
        Decision::Prompt { message, details } => {
            eprintln!("{PROMPT_PREFIX}{message}");
            eprintln!("{PROMPT_PREFIX}{details}");
            if prompt_approved()? {
                run_command(command, cwd).await
            } else {
                eprintln!("{PROMPT_PREFIX}Command blocked by user.");
                std::process::exit(1);
            }
        }
        Decision::Block { message, rule } => {
            eprintln!("{PROMPT_PREFIX}BLOCKED [{rule}]: {message}");
            std::process::exit(1);
        }
        Decision::Sandbox { message, rule } => {
            eprintln!("{PROMPT_PREFIX}SANDBOX [{rule}]: {message}");
            let output = sandbox::run_sandboxed(command, cwd)?;
            print!("{output}");
            Ok(())
        }
    }
}

async fn run_command(command: &str, cwd: &Path) -> Result<()> {
    let shell = default_shell();
    let status = if cfg!(windows) {
        tokio::process::Command::new(&shell)
            .args(["/C", command])
            .current_dir(cwd)
            .status()
            .await?
    } else {
        tokio::process::Command::new(&shell)
            .arg("-c")
            .arg(command)
            .current_dir(cwd)
            .status()
            .await?
    };

    if !status.success() {
        std::process::exit(status.code().unwrap_or(1));
    }
    Ok(())
}

fn prompt_approved() -> Result<bool> {
    let mut line = String::new();
    std::io::stdin().read_line(&mut line)?;
    let answer = line.trim().to_lowercase();
    Ok(answer.is_empty() || answer == "y" || answer == "yes")
}

fn default_shell() -> String {
    if cfg!(windows) {
        std::env::var("COMSPEC").unwrap_or_else(|_| "cmd.exe".into())
    } else {
        std::env::var("AGENTSHIELD_REAL_SHELL")
            .or_else(|_| std::env::var("SHELL"))
            .unwrap_or_else(|_| "/bin/bash".into())
    }
}
