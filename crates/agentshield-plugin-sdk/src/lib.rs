//! WASM plugin host for AgentShield policy extensions.

use std::path::{Path, PathBuf};

use agentshield_core::decision::Decision;
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use wasmtime::*;

#[derive(Debug, Error)]
pub enum PluginError {
    #[error("plugin not found: {0}")]
    NotFound(String),
    #[error("wasm error: {0}")]
    Wasm(String),
}

/// Context passed to WASM plugins (JSON-serialized across the boundary).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginContext {
    pub command: String,
    pub normalized: String,
    pub cwd: String,
    pub touches_env: bool,
    pub has_network: bool,
}

/// Plugin verdict returned from WASM guest.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PluginVerdict {
    Pass,
    Block { message: String },
    Prompt { message: String },
}

/// WASM plugin runtime with fuel limits.
pub struct PluginRuntime {
    engine: Engine,
}

impl Default for PluginRuntime {
    fn default() -> Self {
        Self::new().expect("wasmtime engine")
    }
}

impl PluginRuntime {
    pub fn new() -> Result<Self> {
        let mut config = Config::new();
        config.consume_fuel(true);
        config.epoch_interruption(true);
        let engine = Engine::new(&config)?;
        Ok(Self { engine })
    }

    pub fn plugins_dir() -> PathBuf {
        dirs::data_local_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join("agentshield")
            .join("plugins")
    }

    pub fn list_installed(&self) -> Result<Vec<String>> {
        let dir = Self::plugins_dir();
        if !dir.exists() {
            return Ok(Vec::new());
        }
        Ok(std::fs::read_dir(dir)?
            .filter_map(|e| e.ok())
            .filter(|e| e.path().extension().and_then(|x| x.to_str()) == Some("wasm"))
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .collect())
    }

    pub fn install(&self, name: &str, wasm_bytes: &[u8]) -> Result<PathBuf> {
        let dir = Self::plugins_dir();
        std::fs::create_dir_all(&dir)?;
        let path = dir.join(format!("{name}.wasm"));
        std::fs::write(&path, wasm_bytes)?;
        Ok(path)
    }

    pub fn evaluate_file(&self, path: &Path, ctx: &PluginContext) -> Result<Option<Decision>> {
        let bytes = std::fs::read(path).context("read plugin wasm")?;
        self.evaluate_bytes(&bytes, ctx)
    }

    pub fn evaluate_bytes(&self, bytes: &[u8], ctx: &PluginContext) -> Result<Option<Decision>> {
        let module = match Module::new(&self.engine, bytes) {
            Ok(m) => m,
            Err(e) => return Err(PluginError::Wasm(e.to_string()).into()),
        };

        let mut store = Store::new(&self.engine, ());
        store.set_fuel(1_000_000).ok();

        let instance = match Instance::new(&mut store, &module, &[]) {
            Ok(i) => i,
            Err(_) => return Ok(None),
        };

        let Ok(analyze) = instance.get_typed_func::<(i32, i32), i32>(&mut store, "analyze") else {
            return Ok(None);
        };

        let input = serde_json::to_string(ctx)?;
        let input_bytes = input.as_bytes();

        let Some(memory) = instance.get_memory(&mut store, "memory") else {
            return Ok(None);
        };

        if memory.data_size(&store) < input_bytes.len() {
            return Ok(None);
        }

        memory.write(&mut store, 0, input_bytes)?;
        let result_code = analyze.call(&mut store, (0, input_bytes.len() as i32))?;

        Ok(match result_code {
            1 => Some(Decision::Block {
                message: "Blocked by WASM plugin".into(),
                rule: "wasm-plugin".into(),
            }),
            2 => Some(Decision::Prompt {
                message: "Plugin requests approval".into(),
                details: "wasm-plugin".into(),
            }),
            _ => None,
        })
    }
}
