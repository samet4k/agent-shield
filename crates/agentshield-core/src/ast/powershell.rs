use super::{CommandIr, CommandNode, Pipeline, ShellDialect};

pub fn is_powershell_command(source: &str) -> bool {
    let lower = source.to_lowercase();
    lower.contains("invoke-expression")
        || lower.contains(" iex ")
        || lower.starts_with("iex ")
        || lower.contains("-encodedcommand")
        || lower.contains(" -e ")
        || lower.contains(" -ec ")
        || lower.contains("pwsh")
        || lower.contains("powershell")
        || source.contains(".ps1")
        || source.contains("[system.convert]::frombase64string")
        || source.contains('`')
}

pub fn parse_powershell(source: &str) -> CommandIr {
    let mut ir = CommandIr {
        shell_dialect: ShellDialect::PowerShell,
        ..CommandIr::default()
    };

    if source.to_lowercase().contains("invoke-expression") || source.to_lowercase().contains("iex")
    {
        ir.indirect_executors.push("Invoke-Expression".into());
    }

    if source.to_lowercase().contains("-encodedcommand")
        || source.contains(" -e ")
        || source.contains(" -ec ")
        || source
            .to_lowercase()
            .contains("[system.convert]::frombase64string")
    {
        ir.obfuscation_hint = true;
    }

    if source.contains('`') {
        ir.obfuscation_hint = true;
    }

    let segments: Vec<&str> = source.split('|').collect();
    for segment in segments {
        let trimmed = segment.trim();
        if trimmed.is_empty() {
            continue;
        }
        if let Some(cmd) = tokenize_segment(trimmed) {
            let mut pipeline = Pipeline::default();
            pipeline.commands.push(cmd);
            ir.pipelines.push(pipeline);
        }
    }

    if ir.pipelines.is_empty() {
        if let Some(cmd) = tokenize_segment(source.trim()) {
            ir.pipelines.push(Pipeline {
                commands: vec![cmd],
            });
        }
    }

    detect_ps_pipe_to_shell(&mut ir);
    ir
}

fn tokenize_segment(segment: &str) -> Option<CommandNode> {
    let parts: Vec<&str> = segment.split_whitespace().collect();
    if parts.is_empty() {
        return None;
    }

    let name = parts[0].trim_matches(|c| c == '&' || c == ';').to_string();
    let mut args = Vec::new();
    let mut flags = Vec::new();

    for part in parts.iter().skip(1) {
        let p = part.to_string();
        if p.starts_with('-') {
            flags.push(p.clone());
        }
        args.push(p);
    }

    Some(CommandNode {
        name,
        args,
        flags,
        redirects: Vec::new(),
    })
}

fn detect_ps_pipe_to_shell(ir: &mut CommandIr) {
    if ir.pipelines.len() < 2 {
        return;
    }
    let shells = ["powershell", "pwsh", "cmd"];
    let last = ir
        .pipelines
        .last()
        .and_then(|p| p.commands.first())
        .map(|c| c.name.to_lowercase())
        .unwrap_or_default();
    if shells.iter().any(|s| last.contains(s)) {
        ir.pipe_to_shell = true;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_invoke_expression() {
        let ir = parse_powershell("Invoke-Expression $code");
        assert!(ir
            .indirect_executors
            .iter()
            .any(|e| e.contains("Invoke-Expression")));
    }

    #[test]
    fn detects_encoded_command() {
        let ir = parse_powershell("powershell -EncodedCommand SGVsbG8=");
        assert!(ir.obfuscation_hint);
    }

    #[test]
    fn parses_pipe_chain() {
        let ir = parse_powershell("Get-Content file.txt | Select-String secret");
        assert_eq!(ir.pipelines.len(), 2);
    }
}
