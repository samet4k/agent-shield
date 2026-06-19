use anyhow::{Context, Result};

pub fn list() -> Result<()> {
    let runtime = agentshield_plugin_sdk::PluginRuntime::new()?;
    let plugins = runtime.list_installed()?;
    if plugins.is_empty() {
        println!("No WASM plugins installed.");
        println!(
            "Plugin directory: {}",
            agentshield_plugin_sdk::PluginRuntime::plugins_dir().display()
        );
        return Ok(());
    }
    for p in plugins {
        println!("  {p}");
    }
    Ok(())
}

pub fn install(name: &str, path: &str) -> Result<()> {
    let bytes = std::fs::read(path).with_context(|| format!("read {path}"))?;
    let runtime = agentshield_plugin_sdk::PluginRuntime::new()?;
    let dest = runtime.install(name, &bytes)?;
    println!("Installed plugin '{name}' -> {}", dest.display());
    Ok(())
}
