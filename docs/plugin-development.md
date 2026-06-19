# Plugin Development

AgentShield plugins are WASM modules loaded by `agentshield-cli plugin`.

## Built-in Analyzers

- `secrets-guard` — detects credential patterns in AST fragments
- `crypto-miner-detect` — flags mining pool URLs and binaries

## WASM SDK

Use `agentshield-plugin-sdk` to export `analyze(command: &str) -> i32` from your plugin.

```bash
agentshield plugin install ./my-plugin.wasm
agentshield plugin list
```