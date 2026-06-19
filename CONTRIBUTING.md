# Contributing to AgentShield

## Development Setup

```bash
git clone https://github.com/agentshield/agentshield
cd agentshield
cargo build --workspace
cargo test -p agentshield-core
```

## Pull Request Guidelines

- Run `cargo fmt` and `cargo clippy` before submitting
- Add bypass-suite tests for new security rules
- Document agent integration changes in `docs/agent-integration/`
- Keep `agentshield-core` free of platform-specific dependencies

## Architecture

See [ARCHITECTURE.md](ARCHITECTURE.md).