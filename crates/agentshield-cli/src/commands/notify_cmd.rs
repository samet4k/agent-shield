use agentshield_core::notify::{self, WebhookTarget};
use anyhow::Result;

pub fn configure(webhook: &str) -> Result<()> {
    let mut config = notify::load_config();
    if !config.webhooks.iter().any(|w| w.url == webhook) {
        config.webhooks.push(WebhookTarget {
            url: webhook.to_string(),
            events: vec!["block".into(), "prompt".into()],
        });
    }
    notify::save_config(&config)?;
    println!("Webhook configured: {webhook}");
    println!("Config: {}", notify::config_path().display());
    Ok(())
}

pub fn list() -> Result<()> {
    let config = notify::load_config();
    if config.webhooks.is_empty() {
        println!("No webhooks configured.");
        return Ok(());
    }
    for w in &config.webhooks {
        println!("  {} (events: {})", w.url, w.events.join(", "));
    }
    Ok(())
}
