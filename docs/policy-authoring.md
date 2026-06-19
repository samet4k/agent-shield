# Policy Authoring

AgentShield policies are YAML documents layered from system, user, and project paths.

## Rule Matching

- `pattern` — substring match on normalized command text
- `ast_pattern` — mini DSL over `CommandIr` (e.g. `pipeline > command[name='bash']`)
- `context` — structural checks (e.g. `pipe_destination == 'bash'`, `has_flag('-rf')`)
- `requires_any` — at least one substring must be present

## Trust Levels

| Level | Behavior |
|-------|----------|
| `minimal` | Prompt decisions escalate to block |
| `standard` | Default balanced enforcement |
| `permissive` | Low-severity rules are skipped |

## Filesystem and Network

```yaml
filesystem:
  deny_read: ["**/.env", "**/.ssh/**"]
  allow_write: ["./src/**"]
network:
  block_unknown: true
  allowed_domains: ["github.com", "pypi.org"]
```