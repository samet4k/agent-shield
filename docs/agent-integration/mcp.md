# MCP Integration

Run the MCP server:

```bash
cargo run -p agentshield-mcp
```

## Tools

| Tool | Description |
|------|-------------|
| `execute_command` | Shell command through policy pipeline |
| `read_file` | File read with deny_read rules |
| `write_file` | File write with allow_write rules |
| `network_request` | Egress policy check for URLs |