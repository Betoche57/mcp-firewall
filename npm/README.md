# mcp-firewall

A security firewall proxy for [Model Context Protocol](https://modelcontextprotocol.io/) (MCP) servers. Sits between your AI client and downstream MCP servers, enforcing policy, redacting sensitive data, sandboxing processes, and verifying supply chain integrity.

## Features

- **Policy Engine** — CEL-based rules with `allow`, `deny`, and `prompt` effects. First-match-wins evaluation, fail-closed on error.
- **Interactive Approval** — `prompt` effect triggers MCP elicitation for user confirmation, with configurable timeout.
- **Redaction** — Regex patterns applied to tool input arguments and output content before they reach the client.
- **Process Sandbox** — Per-downstream Linux sandboxing via user/network namespaces and Landlock LSM filesystem restrictions. Graceful degradation on unsupported platforms.
- **Supply Chain Controls** — SHA-256 hash pinning and path allowlisting for downstream binaries, verified before any process is spawned.
- **Multi-Server Proxy** — Route multiple downstream MCP servers through a single firewall with `__`-namespaced tools and resources.
- **Multi-Profile Config** — Named configuration profiles with environment-based selection and workspace-scoped local overrides (restrict-only merge).
- **Audit Logging** — Structured JSON logs with append-only SHA-256 hash chain, tracking policy decisions, redaction, sandbox status, and hash verification.
- **Introspection** — Built-in `explain_effective_policy` tool returns the resolved configuration with provenance annotations.

## Installation

### npx (recommended for MCP clients)

```bash
npx -y @vikingowl/mcp-firewall --config /path/to/config.yaml
```

### Go install

```bash
go install github.com/VikingOwl91/mcp-firewall/cmd/mcp-firewall@latest
```

### GitHub Releases

Download prebuilt binaries from [GitHub Releases](https://github.com/VikingOwl91/mcp-firewall/releases) for Linux, macOS, and Windows (amd64/arm64).

## Quick Start

### 1. Create a config file

```bash
mcp-firewall --init
# Creates ~/.mcp-firewall/config.yaml with a commented template
```

Then edit it to add your downstream servers and policy rules:

```yaml
downstreams:
  myserver:
    command: my-mcp-server
    args: ["--port", "3000"]

policy:
  default: deny
  rules:
    - name: allow-safe-tools
      expression: 'tool.name == "search" || tool.name == "list"'
      effect: allow
    - name: prompt-for-writes
      expression: 'tool.name.startsWith("write")'
      effect: prompt
      message: "This tool will modify data. Approve?"
```

### 2. Configure your MCP client

```json
{
  "mcpServers": {
    "firewall": {
      "command": "npx",
      "args": ["-y", "mcp-firewall", "--config", "/path/to/config.yaml"]
    }
  }
}
```

### 3. Run directly (optional)

```bash
mcp-firewall --config config.yaml
```

## Configuration

### Minimal Config

```yaml
downstreams:
  echo:
    command: ./my-echo-server
```

### Full Reference

```yaml
# Downstream MCP servers
downstreams:
  myserver:
    command: /usr/local/bin/my-server    # Executable path
    args: ["--flag"]                      # Command arguments
    env: ["API_KEY=secret"]               # Environment variables
    timeout: 10s                          # Per-downstream timeout override
    sandbox: strict                       # Sandbox profile name (or "none")
    hash: "sha256:abc123..."              # SHA-256 hash pin

# Policy engine
policy:
  default: deny                           # Default effect: allow | deny
  rules:
    - name: rule-name
      expression: 'CEL expression'        # Must evaluate to bool
      effect: allow                       # allow | deny | prompt
      message: "Custom prompt message"    # Optional, for prompt effect

# Redaction
redaction:
  patterns:
    - name: api-keys
      pattern: 'sk-[a-zA-Z0-9]{32}'      # Regex pattern

# Supply chain controls
supply_chain:
  allowed_paths:
    - /usr/local/bin
    - ~/trusted-tools

# Sandbox profiles
sandbox_profiles:
  custom:
    network: false                        # Block network access
    env_allowlist: [PATH, HOME]           # Env var whitelist
    fs_deny: [/root, /sys]               # Deny filesystem access
    fs_allow_ro: [/etc, /usr]            # Read-only access
    fs_allow_rw: [/tmp]                  # Read-write access
    workspace: true                      # Allow workspace directory access

# Global settings
timeout: 30s                              # Default tool/resource timeout
approval_timeout: 2m                      # Interactive approval timeout
max_output_bytes: 524288                  # Output truncation limit
log_level: info                           # debug | info | warn | error
```

### CEL Expression Variables

| Variable | Type | Description |
|----------|------|-------------|
| `method` | string | Request method (`"tools/call"`, `"resources/read"`, etc.) |
| `server` | string | Downstream alias |
| `tool.name` | string | Tool name (when `method == "tools/call"`) |
| `tool.arguments` | map | Tool arguments (when `method == "tools/call"`) |
| `resource.uri` | string | Resource URI (when `method == "resources/read"`) |

Use `has()` guards for optional fields: `has(tool.arguments.filename) && tool.arguments.filename.startsWith("/etc")`

### Profiles

Define named configuration profiles for different environments:

```yaml
# Inline defaults (used when no profile is selected)
downstreams:
  myserver:
    command: ./server

policy:
  default: allow

# Named profiles
profiles:
  production:
    downstreams:
      myserver:
        command: /opt/server
        sandbox: strict
        hash: "sha256:..."
    policy:
      default: deny
      rules:
        - name: allow-reads
          expression: 'tool.name.startsWith("read")'
          effect: allow
```

Select a profile:
```bash
mcp-firewall --config config.yaml --profile production
# or
MCP_FIREWALL_PROFILE=production mcp-firewall --config config.yaml
```

### Local Overrides

Place a `.mcp-firewall/config.yaml` in your workspace directory to add restrictions:

```yaml
# Local overrides can only add restrictions, not loosen them
policy:
  rules:
    - name: block-dangerous
      expression: 'tool.name == "delete_everything"'
      effect: deny

redaction:
  patterns:
    - name: internal-tokens
      pattern: 'ghp_[a-zA-Z0-9]{36}'
```

Local overrides are automatically detected from the working directory, or specify explicitly:
```bash
mcp-firewall --config config.yaml --workspace /path/to/project
```

**Restrictions:** Local overrides cannot modify `downstreams`, `profiles`, `supply_chain`, or `policy.default`. Deny/prompt rules are prepended; allow rules are rejected unless the base config enables `allow_expansion`. Timeouts can only be lowered.

## CLI Flags

| Flag | Default | Description |
|------|---------|-------------|
| `--config` | `~/.mcp-firewall/config.yaml` | Path to config file |
| `--init` | | Create default config file and exit |
| `--profile` | *(env/inline)* | Config profile name |
| `--workspace` | *(auto-detect)* | Workspace directory for local overrides |
| `--generate-lockfile` | | Compute SHA-256 hashes for all downstreams and print YAML |
| `--version` | | Print version and exit |

## Supply Chain Verification

Pin downstream binaries to known hashes:

```bash
# Generate hashes for all downstreams
mcp-firewall --config config.yaml --generate-lockfile
```

Output:
```yaml
downstreams:
  myserver:
    hash: "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
```

Copy the `hash` values into your config. The firewall will verify each binary before spawning it.

## Introspection

The firewall exposes an `explain_effective_policy` tool that returns the resolved configuration as JSON, including:

- Active profile and local override path
- Merged policy rules with source provenance (`inline`, `profile:name`, `local`)
- Redaction patterns with provenance
- Sandbox capabilities and per-downstream profiles
- Supply chain verification results

## Audit Logging

All requests are logged to stderr as structured JSON with:

- Policy decision (`allow`/`deny`/`prompt`) and matching rule
- Redaction status
- Sandbox level (`full`/`partial`/`minimal`)
- Hash verification status
- Approval action (`accept`/`decline`/`cancel`/`timeout`/`unsupported`)
- Sequential hash chain (`audit_seq`, `entry_hash`, `prev_hash`) for tamper detection

## Platform Support

| Feature | Linux | macOS | Windows |
|---------|-------|-------|---------|
| Policy engine | Yes | Yes | Yes |
| Redaction | Yes | Yes | Yes |
| Interactive approval | Yes | Yes | Yes |
| Sandbox (namespaces) | Yes | No* | No* |
| Sandbox (Landlock) | Yes (5.13+) | No* | No* |
| Supply chain | Yes | Yes | Yes |

*Sandbox features gracefully degrade to minimal isolation on unsupported platforms. Use `strict` mode in sandbox profiles to fail instead of degrading.

## License

[MIT](LICENSE)
