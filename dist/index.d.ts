import * as node_child_process from 'node:child_process';
import { EventEmitter } from 'node:events';

/**
 * sovr-mcp-proxy v2.0.0 — Full SDK Coverage + Programmable Proxy API
 *
 * Complete MCP interface covering ALL SOVR SDK methods
 * organized into 286 tools with operation-based routing.
 *
 * Two modes:
 * 1. **Local** (free) — Built-in policy engine with 15 rules
 * 2. **Cloud** (SOVR Cloud) — Full SDK access via API proxy
 *
 * Zero external dependencies. Self-contained stdio MCP transport.
 *
 * @example
 * ```json
 * {
 *   "mcpServers": {
 *     "sovr": {
 *       "command": "npx",
 *       "args": ["sovr-mcp-server"],
 *       "env": {
 *         "SOVR_API_KEY": "sovr_sk_...",
 *         "SOVR_ENDPOINT": "https://your-sovr-instance.com"
 *       }
 *     }
 *   }
 * }
 * ```
 */
type Channel = "mcp" | "http" | "sql" | "exec";
type Verdict = "allow" | "deny" | "escalate";
type RiskLevel = "none" | "low" | "medium" | "high" | "critical";
interface PolicyRule {
    id: string;
    description: string;
    channels: Channel[];
    action_pattern: string;
    resource_pattern: string;
    conditions: Array<{
        field: string;
        operator: string;
        value: string;
    }>;
    effect: Verdict;
    risk_level: RiskLevel;
    require_approval: boolean;
    priority: number;
    enabled: boolean;
}
/** Request payload for the evaluate() function */
interface EvalRequest {
    channel: Channel;
    action: string;
    resource: string;
    context?: McpContext;
}
/** Context object passed to policy evaluation */
type McpContext = Record<string, unknown>;
interface EvalResult {
    verdict: Verdict;
    risk_score: number;
    matched_rules: string[];
    reason: string;
    decision_id: string;
    timestamp: number;
    channel: Channel;
    [key: string]: unknown;
}
interface AuditEntry {
    decision_id: string;
    timestamp: number;
    channel: Channel;
    action: string;
    resource: string;
    verdict: Verdict;
    risk_score: number;
    matched_rules: string[];
}
declare let rules: PolicyRule[];
declare const auditLog: AuditEntry[];
declare const VERSION = "2.1.0";
type DownstreamTransport = "stdio" | "sse" | "streamable-http";
interface DownstreamServer {
    name: string;
    transportType: DownstreamTransport;
    process: ReturnType<typeof node_child_process.spawn> | null;
    remoteUrl?: string;
    remoteHeaders?: Record<string, string>;
    remotePostUrl?: string;
    sseAbort?: AbortController;
    tools: Array<{
        name: string;
        description?: string;
        inputSchema?: unknown;
    }>;
    ready: boolean;
    buffer: string;
    pendingRequests: Map<number, {
        resolve: (v: unknown) => void;
        reject: (e: Error) => void;
        timer: ReturnType<typeof setTimeout>;
    }>;
    nextId: number;
}
declare const downstreamServers: Map<string, DownstreamServer>;
declare const proxyToolMap: Map<string, string>;
declare let proxyEnabled: boolean;
declare function initProxy(): Promise<void>;
declare function getProxyTools(): Array<{
    name: string;
    description?: string;
    inputSchema?: unknown;
}>;
declare function proxyToolCall(toolName: string, args: Record<string, unknown>): Promise<{
    content: Array<{
        type: string;
        text: string;
    }>;
    isError?: boolean;
}>;
declare function shutdownProxy(): void;
declare function evaluate(channel: Channel, action: string, resource: string, context?: Record<string, unknown>): EvalResult;
interface ParsedCommand {
    command: string;
    subCommand: string | null;
    args: string[];
    hasSudo: boolean;
    hasPipe: boolean;
    hasChain: boolean;
    riskIndicators: string[];
}
declare function parseCommand(raw: string): ParsedCommand;
interface ParsedSQL {
    type: string;
    tables: string[];
    hasWhereClause: boolean;
    isMultiStatement: boolean;
    raw: string;
}
declare function parseSQL(raw: string): ParsedSQL;
type Tier = "free" | "personal" | "starter" | "pro" | "enterprise";
declare function tierHasAccess(userTier: Tier, toolName: string): boolean;
declare function filterToolsByTier<T extends {
    name: string;
}>(tools: T[], tier: Tier): T[];
interface McpToolDef {
    name: string;
    description: string;
    inputSchema: {
        type: "object";
        properties: Record<string, unknown>;
        required?: string[];
    };
}
declare const TOOLS: McpToolDef[];
type ToolResult = {
    content: Array<{
        type: "text";
        text: string;
    }>;
};
declare function handleToolCall(name: string, args: Record<string, unknown>): Promise<ToolResult>;
declare function main(): Promise<void>;
/** How to connect to the upstream MCP server (single-upstream mode) */
interface SingleUpstreamConfig {
    /** Command to spawn the upstream MCP server (stdio transport) */
    command: string;
    /** Arguments for the command */
    args?: string[];
    /** Environment variables for the upstream process */
    env?: Record<string, string>;
    /** Working directory */
    cwd?: string;
}
/** Proxy configuration for the McpProxy class */
interface McpProxyConfig {
    /** Upstream MCP server (stdio) */
    upstream: SingleUpstreamConfig;
    /** Custom policy rules (defaults to built-in 15 rules) */
    customRules?: PolicyRule[];
    /** Server name for identification */
    serverName?: string;
    /** Whether to log intercepted calls */
    verbose?: boolean;
    /** Callback when a call is blocked */
    onBlocked?: (info: BlockedCallInfo) => void | Promise<void>;
    /** Callback when a call is escalated */
    onEscalated?: (info: EscalatedCallInfo) => void | Promise<void>;
    /** Callback for all intercepted calls (for audit) */
    onIntercept?: (info: InterceptInfo) => void | Promise<void>;
}
interface BlockedCallInfo {
    method: string;
    toolName: string;
    arguments: Record<string, unknown>;
    decision: EvalResult;
    timestamp: number;
}
interface EscalatedCallInfo {
    method: string;
    toolName: string;
    arguments: Record<string, unknown>;
    decision: EvalResult;
    timestamp: number;
}
interface InterceptInfo {
    method: string;
    toolName: string;
    arguments: Record<string, unknown>;
    decision: EvalResult;
    forwarded: boolean;
    timestamp: number;
}
/** Proxy statistics */
interface ProxyStats {
    totalCalls: number;
    allowedCalls: number;
    blockedCalls: number;
    escalatedCalls: number;
    upstreamErrors: number;
    startedAt: number;
}
declare class McpProxy extends EventEmitter {
    private upstreamConfig;
    private upstream;
    private _serverName;
    private _verbose;
    private _onBlocked?;
    private _onEscalated?;
    private _onIntercept?;
    private _stats;
    private _customRules;
    constructor(config: McpProxyConfig);
    /**
     * Start the proxy in stdio mode.
     * Reads JSON-RPC messages from stdin, intercepts tool calls,
     * and forwards approved calls to the upstream MCP server.
     */
    start(): Promise<void>;
    /** Stop the proxy and kill the upstream process. */
    stop(): void;
    /** Get proxy statistics. */
    getStats(): ProxyStats;
    private handleAgentMessage;
    private handleUpstreamMessage;
    private interceptToolCall;
    /**
     * Extract danger signals from tool arguments for rule matching.
     * Normalizes common patterns across different MCP servers.
     */
    private extractDangerSignals;
    private sendBlockedResponse;
    private sendEscalatedResponse;
    private forwardToUpstream;
}
/**
 * CLI entry point for single-upstream proxy mode.
 * Usage:
 *   sovr-mcp-proxy --upstream "npx -y @modelcontextprotocol/server-filesystem /tmp"
 *   sovr-mcp-proxy --upstream "node my-mcp-server.js" --rules ./policy.json
 */
declare function proxyCli(args: string[]): Promise<void>;

export { type BlockedCallInfo, type Channel, type EscalatedCallInfo, type EvalRequest, type EvalResult, type InterceptInfo, type McpContext, McpProxy, type McpProxyConfig, type PolicyRule, type ProxyStats, type RiskLevel, type SingleUpstreamConfig, TOOLS, VERSION, type Verdict, auditLog, McpProxy as default, downstreamServers, evaluate, filterToolsByTier, getProxyTools, handleToolCall, initProxy, main, parseCommand, parseSQL, proxyCli, proxyEnabled, proxyToolCall, proxyToolMap, rules, shutdownProxy, tierHasAccess };
