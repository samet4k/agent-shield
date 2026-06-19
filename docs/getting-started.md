# Getting Started

## Install

```bash
cargo install --path crates/agentshield-cli
cargo build -p agentshield-daemon -p agentshield-mcp
```

## Quick setup

```bash
agentshield init --profile web-dev
agentshield install --deep   # OS-native daemon + collectors
export SHELL=$(which agentshield)
```

## MCP (Claude Desktop)

```json
{
  "mcpServers": {
    "agentshield": {
      "command": "agentshield-mcp"
    }
  }
}
```

## Python agents

```python
import agentshield
from agentshield import session, guard

with session():
    import subprocess
    subprocess.run(["ls", "-la"])
```