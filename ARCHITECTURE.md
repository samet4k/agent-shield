# AgentShield Architecture

## Overview

AgentShield is a layered security runtime. All interception sources normalize events into `SecurityEvent` and pass through `agentshield-core`'s analysis pipeline.

## Crates

| Crate | Responsibility |
|-------|----------------|
| `agentshield-core` | AST parsing, obfuscation normalization, YAML policy, threat chain, JSON logging |
| `agentshield-cli` | Shell proxy (PTY), `init`, `analyze`, `dashboard`, `report` |
| `agentshield-daemon` | IPC server, process collectors, session state |
| `agentshield-test-harness` | Bypass suite runner and benchmarks |

## Analysis Pipeline

```
Raw Command
  → Obfuscation Normalizer
  → tree-sitter Bash AST → CommandIr
  → Policy Engine (YAML rules + glob filesystem/network)
  → Threat Chain Analyzer (sliding window)
  → Decision (allow | prompt | block | sandbox)
  → Structured JSON log
```

## Interception Layers

### Layer 1 — Shell Proxy

`agentshield` binary acts as login shell. Non-interactive stdin (how most AI agents work) is analyzed then forwarded to the real shell.

### Layer 2 — OS Native

- Linux: eBPF exec observer (sysinfo fallback)
- macOS: Endpoint Security notify observer
- Windows: ETW process observer (sysinfo fallback)

### Layer 3 — In-Process SDK

`import agentshield` monkey-patches `subprocess.run` and `os.system`.

## Policy Layering

1. Built-in `policies/default.yml`
2. `~/.config/agentshield/policy.yml` (user)
3. `.agentshield.yml` (project root) — highest priority

## Decision Modes

| Mode | Behavior |
|------|----------|
| `allow` | Execute immediately |
| `prompt` | Interactive Y/n approval |
| `block` | Reject + log |
| `sandbox` | Isolated subprocess (platform-dependent) |

## Observability

Logs: `%LOCALAPPDATA%\agentshield\logs\` (Windows) or `~/.local/share/agentshield/logs/` (XDG).

Format: JSON Lines with `decision`, `risk_score`, `patterns_matched`, `execution_time_ms`.