# Claude Code Integration

```bash
agentshield init
export SHELL=$(which agentshield)
export AGENTSHIELD_AGENT=claude-code
export AGENTSHIELD_REAL_SHELL=/bin/bash
```

Claude Code uses the configured shell for all tool executions. AgentShield proxies every command transparently.