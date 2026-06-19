use std::fs;
use std::io;
use std::time::Duration;

use agentshield_core::log_directory;
use anyhow::Result;
use crossterm::event::{self, Event, KeyCode};
use crossterm::terminal::{
    disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen,
};
use crossterm::ExecutableCommand;
use ratatui::layout::{Constraint, Direction, Layout};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, List, ListItem, Paragraph};
use ratatui::DefaultTerminal;

#[derive(Debug, serde::Deserialize)]
#[allow(dead_code)]
struct LogEntry {
    decision: String,
    command_raw: String,
    risk_score: f64,
    #[serde(default)]
    rule_triggered: Option<String>,
}

pub fn run_dashboard() -> Result<()> {
    let mut stdout = io::stdout();
    enable_raw_mode()?;
    stdout.execute(EnterAlternateScreen)?;

    let terminal = ratatui::init();
    let result = run_loop(terminal);
    ratatui::restore();
    disable_raw_mode()?;
    stdout.execute(LeaveAlternateScreen)?;
    result
}

fn run_loop(mut terminal: DefaultTerminal) -> Result<()> {
    loop {
        let entries = load_recent_logs(50);
        let (total, blocked, prompted) = summarize(&entries);

        terminal.draw(|frame| {
            let chunks = Layout::default()
                .direction(Direction::Vertical)
                .constraints([
                    Constraint::Length(3),
                    Constraint::Min(10),
                    Constraint::Length(4),
                ])
                .split(frame.area());

            let header = Paragraph::new("AgentShield Dashboard")
                .style(Style::default().add_modifier(Modifier::BOLD))
                .block(Block::default().borders(Borders::ALL).title("Status"));
            frame.render_widget(header, chunks[0]);

            let items: Vec<ListItem> = entries
                .iter()
                .map(|e| {
                    let color = match e.decision.as_str() {
                        "block" => Color::Red,
                        "prompt" => Color::Yellow,
                        "sandbox" => Color::Magenta,
                        _ => Color::Green,
                    };
                    ListItem::new(Line::from(vec![
                        Span::styled(format!("{:8}", e.decision), Style::default().fg(color)),
                        Span::raw(format!(" [{:.2}] ", e.risk_score)),
                        Span::raw(truncate(&e.command_raw, 60)),
                    ]))
                })
                .collect();

            let list = List::new(items).block(
                Block::default()
                    .borders(Borders::ALL)
                    .title("Recent Commands"),
            );
            frame.render_widget(list, chunks[1]);

            let summary = Paragraph::new(format!(
                "Total: {total}  Blocked: {blocked}  Prompted: {prompted}  |  q: quit  r: refresh"
            ))
            .block(Block::default().borders(Borders::ALL).title("Summary"));
            frame.render_widget(summary, chunks[2]);
        })?;

        if event::poll(Duration::from_millis(500))? {
            if let Event::Key(key) = event::read()? {
                match key.code {
                    KeyCode::Char('q') => break,
                    KeyCode::Char('r') => continue,
                    _ => {}
                }
            }
        }
    }
    Ok(())
}

fn load_recent_logs(limit: usize) -> Vec<LogEntry> {
    let log_dir = log_directory();
    let Ok(entries) = fs::read_dir(&log_dir) else {
        return Vec::new();
    };

    let mut lines = Vec::new();
    for entry in entries.filter_map(|e| e.ok()) {
        if let Ok(content) = fs::read_to_string(entry.path()) {
            for line in content.lines() {
                if let Ok(e) = serde_json::from_str::<LogEntry>(line) {
                    lines.push(e);
                }
            }
        }
    }
    lines.sort_by(|a, b| {
        b.risk_score
            .partial_cmp(&a.risk_score)
            .unwrap_or(std::cmp::Ordering::Equal)
    });
    lines.truncate(limit);
    lines
}

fn summarize(entries: &[LogEntry]) -> (usize, usize, usize) {
    let total = entries.len();
    let blocked = entries.iter().filter(|e| e.decision == "block").count();
    let prompted = entries.iter().filter(|e| e.decision == "prompt").count();
    (total, blocked, prompted)
}

fn truncate(s: &str, max: usize) -> String {
    if s.len() <= max {
        s.to_string()
    } else {
        format!("{}...", &s[..max])
    }
}
