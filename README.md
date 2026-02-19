# sovr-mcp-proxy

[![npm version](https://img.shields.io/npm/v/sovr-mcp-proxy.svg)](https://www.npmjs.com/package/sovr-mcp-proxy)
[![License: BSL-1.1](https://img.shields.io/badge/License-BSL--1.1-blue.svg)](./LICENSE)

**Transparent MCP Proxy — The Execution Firewall for AI Agents.**

`sovr-mcp-proxy` is a superset of [`sovr-mcp-server`](https://www.npmjs.com/package/sovr-mcp-server). It includes all MCP Server capabilities **plus** a transparent proxy layer that intercepts, evaluates, and audits every agent→tool call against configurable policy rules before forwarding to downstream MCP servers.

## Architecture

```
┌─────────────┐     ┌──────────────────┐     ┌─────────────────┐
│  AI Agent    │────▶│  sovr-mcp-proxy  │────▶│ Downstream MCP  │
│ (Claude etc) │     │  Gate-Check Layer│     │ (Stripe/GitHub) │
└─────────────┘     └──────────────────┘     └─────────────────┘
                         │
                    Policy Rules
                    Permit/Receipt
                    Audit Trail
```

## Key Differences: Proxy vs Server

| Feature | sovr-mcp-proxy | sovr-mcp-server |
|---------|---------------|-----------------|
| **286 Native Tools** | ✅ | ✅ |
| **1630 SDK Routes** | ✅ | ✅ |
| **Transparent Proxy Mode** | ✅ | ❌ |
| **Downstream Server Interception** | ✅ | ❌ |
| **Spawn/Discover/Intercept/Forward** | ✅ | ❌ |
| **Multi-server Routing** | ✅ | ❌ |
| **Anti-loop Protection** | ✅ | N/A |
| **Hop Counter** | ✅ | N/A |

## Quick Start

### Install

```bash
npm install -g sovr-mcp-proxy
```

### Claude Desktop Configuration

```json
{
  "mcpServers": {
    "sovr-proxy": {
      "command": "npx",
      "args": ["sovr-mcp-proxy"],
      "env": {
        "SOVR_API_KEY": "sovr_sk_...",
        "SOVR_PROXY_CONFIG": "/path/to/proxy.json"
      }
    }
  }
}
```

### Proxy Configuration (proxy.json)

```json
{
  "downstream": {
    "stripe": {
      "command": "npx",
      "args": ["@stripe/agent-toolkit"],
      "env": { "STRIPE_SECRET_KEY": "sk_test_..." }
    },
    "github": {
      "command": "npx",
      "args": ["@modelcontextprotocol/server-github"],
      "env": { "GITHUB_TOKEN": "ghp_..." }
    }
  }
}
```

Every tool call to `stripe` or `github` is intercepted by SOVR's gate-check layer before forwarding.

## How It Works

1. **Spawn** — On startup, sovr-mcp-proxy spawns all downstream MCP servers as child processes
2. **Discover** — Enumerates tools from each downstream server via `tools/list`
3. **Intercept** — When the AI agent calls any tool, the proxy evaluates it against policy rules
4. **Gate-Check** — Applies permit/deny/escalate verdict based on rules
5. **Forward** — Approved calls are forwarded to the downstream server; denied calls return an error

## Security Features

### HTTPS Enforcement
All non-localhost connections are validated for HTTPS. HTTP connections to external hosts are rejected.

### Fail-Close / Fail-Local Degradation
- **Default (fail-close)**: If SOVR Cloud is unreachable, all gated operations are denied
- **Configurable (fail-local)**: Set `SOVR_FAIL_MODE=fail-local` to fall back to 20 built-in local rules

### Three-State Degradation

| Mode | Behavior | Use Case |
|------|----------|----------|
| `strict` (default) | Enforce all deny/escalate verdicts | Production |
| `record-only` | Log violations but allow execution | Emergency availability rescue |
| `propose-only` | Return verdict without executing | Dry-run / testing |

### Anti-Loop Protection
- Hop counter prevents infinite proxy chains (default max: 3 hops)
- Re-entry guard detects circular tool call patterns

### Data Redaction
Sensitive fields (`password`, `secret`, `token`, `key`, `authorization`, `cookie`, `ssn`, `credit_card`) are automatically redacted in all logs and audit entries.

### Unified Alert Dispatcher
Configurable alert routing to Webhook, Slack, PagerDuty, or OpsGenie (replaces hardcoded Telegram).

## Built-in Rules (Free Tier)

| Rule | Effect | Description |
|------|--------|-------------|
| Destructive Commands | **DENY** | Blocks `rm -rf`, `mkfs`, `dd`, `shred` |
| DDL Operations | **DENY** | Blocks `DROP`, `TRUNCATE`, `ALTER` |
| Privilege Escalation | **ESCALATE** | Flags `sudo`, `chmod`, `chown` for approval |
| Payment APIs | **ESCALATE** | Flags Stripe, PayPal calls for approval |
| Deployment Ops | **ESCALATE** | Flags deploy/publish/release for approval |

## Environment Variables

| Variable | Required | Description |
|----------|----------|-------------|
| `SOVR_API_KEY` | No | Connect to SOVR Cloud for expanded tools and persistent audit |
| `SOVR_PROXY_CONFIG` | No | Path to proxy configuration JSON |
| `SOVR_RULES_FILE` | No | Path to custom rules JSON file |
| `SOVR_PROXY_MODE` | No | `strict` / `record-only` / `propose-only` (default: `strict`) |
| `SOVR_FAIL_MODE` | No | `fail-close` / `fail-local` (default: `fail-close`) |
| `SOVR_MAX_HOPS` | No | Max proxy hop count before loop detection (default: 3) |
| `SOVR_TENANT_ID` | No | Tenant identifier for multi-tenant deployments |
| `SOVR_ACTOR_ID` | No | Actor identifier for audit trail |
| `SOVR_SESSION_ID` | No | Session identifier for trace correlation |
| `SOVR_ENDPOINT` | No | Custom Cloud endpoint (advanced) |

## Tier Comparison

| | Free | Personal | Starter | Pro | Enterprise |
|---|---|---|---|---|---|
| **Tools** | 8 | 23 | 48 | 98 | 274 |
| **Built-in Rules** | 5 | 15+ | 15+ | 15+ | 15+ |
| **Custom Rules** | 3 | Unlimited | Unlimited | Unlimited | Unlimited |
| **Proxy Downstream** | 1 server | Unlimited | Unlimited | Unlimited | Unlimited |
| **Permit/Receipt** | Local only | Cloud | Cloud | Cloud | Cloud |
| **Audit Trail** | In-memory | Persistent | Persistent | Persistent | Persistent |
| **Approval Workflow** | — | Basic | Full | Full | Full + SLA |

Free tier works offline with zero configuration. Upgrade at [sovr.inc/pricing](https://sovr.inc/pricing).

## Related Packages

- [`sovr-mcp-server`](https://www.npmjs.com/package/sovr-mcp-server) — MCP Server mode only (no proxy capabilities)

## License

[BSL-1.1](./LICENSE) — Code is source-available. Free for non-commercial use. Commercial use requires a license from SOVR AI.

After the Change Date (February 18, 2030), this software converts to Apache-2.0.

---

**SOVR — Eyes on AI.** [sovr.inc](https://sovr.inc)
