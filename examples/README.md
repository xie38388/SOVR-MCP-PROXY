# SOVR MCP Server — Examples

## Custom Rules

Create your own policy rules to extend the 15 built-in safety rules.

### Rule Schema

```typescript
{
  id: string;              // Unique identifier
  description: string;     // Human-readable description
  channels: Channel[];     // ["mcp", "http", "sql", "exec"]
  action_pattern: string;  // Glob pattern for actions (supports | for OR)
  resource_pattern: string; // Glob pattern for resources
  conditions?: Condition[]; // Optional extra conditions
  effect: Verdict;         // "allow" | "deny" | "escalate"
  risk_level: RiskLevel;   // "none" | "low" | "medium" | "high" | "critical"
  priority: number;        // Higher = evaluated first (1-100)
}
```

### Example: Block Production Database Writes

```json
{
  "rules": [
    {
      "id": "block-prod-writes",
      "description": "Block all writes to production database",
      "channels": ["sql"],
      "action_pattern": "INSERT|UPDATE|DELETE|DROP",
      "resource_pattern": "prod_*",
      "effect": "deny",
      "risk_level": "critical",
      "priority": 100
    }
  ]
}
```

### Example: Escalate Payment Operations

```json
{
  "rules": [
    {
      "id": "escalate-payments",
      "description": "Require human approval for payment operations",
      "channels": ["mcp", "http"],
      "action_pattern": "*payment*|*charge*|*refund*",
      "resource_pattern": "*stripe*|*paypal*",
      "effect": "escalate",
      "risk_level": "high",
      "priority": 90
    }
  ]
}
```

### Usage

```bash
SOVR_RULES_FILE=./my-rules.json npx sovr-mcp-server
```

Rules are additive — custom rules are merged with the 15 built-in safety rules. Built-in rules cannot be overridden.

## Industry Rule Templates

Pre-built rule packs for regulated industries (Financial Services, Healthcare, E-Commerce) are available with SOVR Cloud.

Visit [sovr.inc](https://sovr.inc) for details.
