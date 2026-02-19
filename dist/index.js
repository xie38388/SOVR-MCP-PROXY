#!/usr/bin/env node
var __require = /* @__PURE__ */ ((x) => typeof require !== "undefined" ? require : typeof Proxy !== "undefined" ? new Proxy(x, {
  get: (a, b) => (typeof require !== "undefined" ? require : a)[b]
}) : x)(function(x) {
  if (typeof require !== "undefined") return require.apply(this, arguments);
  throw Error('Dynamic require of "' + x + '" is not supported');
});

// src/index.ts
import { spawn as nodeSpawn } from "child_process";
import { createInterface } from "readline";
import { EventEmitter } from "events";
var BUILT_IN_RULES = [
  { id: "exec-destructive-commands", description: "Block destructive shell commands (rm -rf, mkfs, dd, shred)", channels: ["exec"], action_pattern: "rm|mkfs|dd|shred|wipefs", resource_pattern: "*", conditions: [], effect: "deny", risk_level: "critical", require_approval: true, priority: 100, enabled: true },
  { id: "exec-kubernetes-destructive", description: "Escalate destructive Kubernetes operations", channels: ["exec"], action_pattern: "kubectl_delete|kubectl_drain|kubectl_cordon", resource_pattern: "*", conditions: [], effect: "escalate", risk_level: "high", require_approval: true, priority: 90, enabled: true },
  { id: "exec-docker-destructive", description: "Escalate destructive Docker operations", channels: ["exec"], action_pattern: "docker_rm|docker_rmi|docker_system_prune|docker_stop", resource_pattern: "*", conditions: [], effect: "escalate", risk_level: "high", require_approval: true, priority: 90, enabled: true },
  { id: "exec-privilege-escalation", description: "Escalate privilege escalation commands", channels: ["exec"], action_pattern: "sudo|su|chmod|chown|passwd", resource_pattern: "*", conditions: [], effect: "escalate", risk_level: "high", require_approval: true, priority: 85, enabled: true },
  { id: "exec-network-reconfig", description: "Escalate network reconfiguration commands", channels: ["exec"], action_pattern: "iptables|ufw|firewall-cmd|route|ip_route", resource_pattern: "*", conditions: [], effect: "escalate", risk_level: "high", require_approval: true, priority: 85, enabled: true },
  { id: "sql-ddl-block", description: "Block DDL operations (DROP, TRUNCATE, ALTER)", channels: ["sql"], action_pattern: "DROP|TRUNCATE|ALTER", resource_pattern: "*", conditions: [], effect: "deny", risk_level: "critical", require_approval: true, priority: 100, enabled: true },
  { id: "sql-delete-no-where", description: "Block DELETE without WHERE clause", channels: ["sql"], action_pattern: "DELETE", resource_pattern: "*", conditions: [{ field: "has_where_clause", operator: "eq", value: "false" }], effect: "deny", risk_level: "critical", require_approval: true, priority: 95, enabled: true },
  { id: "sql-update-no-where", description: "Escalate UPDATE without WHERE clause", channels: ["sql"], action_pattern: "UPDATE", resource_pattern: "*", conditions: [{ field: "has_where_clause", operator: "eq", value: "false" }], effect: "escalate", risk_level: "high", require_approval: true, priority: 90, enabled: true },
  { id: "sql-grant-revoke", description: "Escalate permission changes", channels: ["sql"], action_pattern: "GRANT|REVOKE", resource_pattern: "*", conditions: [], effect: "escalate", risk_level: "high", require_approval: true, priority: 85, enabled: true },
  { id: "http-payment-apis", description: "Escalate payment API calls (Stripe, PayPal, etc.)", channels: ["http"], action_pattern: "POST|PUT|DELETE", resource_pattern: "*stripe*|*paypal*|*braintree*|*square*", conditions: [], effect: "escalate", risk_level: "high", require_approval: true, priority: 90, enabled: true },
  { id: "http-cloud-destructive", description: "Escalate destructive cloud API calls", channels: ["http"], action_pattern: "DELETE|PUT", resource_pattern: "*amazonaws*|*googleapis*|*azure*", conditions: [], effect: "escalate", risk_level: "high", require_approval: true, priority: 85, enabled: true },
  { id: "mcp-filesystem-write", description: "Escalate filesystem write operations via MCP", channels: ["mcp"], action_pattern: "write_file|delete_file|move_file|create_directory", resource_pattern: "*", conditions: [], effect: "escalate", risk_level: "medium", require_approval: false, priority: 70, enabled: true },
  { id: "mcp-database-write", description: "Escalate database write operations via MCP", channels: ["mcp"], action_pattern: "*write*|*delete*|*update*|*insert*|*drop*|*create*", resource_pattern: "*database*|*db*|*sql*", conditions: [], effect: "escalate", risk_level: "high", require_approval: true, priority: 80, enabled: true },
  { id: "mcp-email-send", description: "Escalate email sending operations via MCP", channels: ["mcp"], action_pattern: "*send*email*|*send*message*|*send*notification*", resource_pattern: "*", conditions: [], effect: "escalate", risk_level: "medium", require_approval: true, priority: 75, enabled: true },
  { id: "mcp-deploy-operations", description: "Escalate deployment operations via MCP", channels: ["mcp"], action_pattern: "*deploy*|*publish*|*release*", resource_pattern: "*", conditions: [], effect: "escalate", risk_level: "high", require_approval: true, priority: 85, enabled: true }
];
var rules = BUILT_IN_RULES.map((r) => ({ ...r, conditions: [...r.conditions] }));
var auditLog = [];
var MAX_AUDIT = 500;
var VERSION = "2.1.0";
var downstreamServers = /* @__PURE__ */ new Map();
var proxyToolMap = /* @__PURE__ */ new Map();
var proxyEnabled = false;
function getProxyConfig() {
  const configPath = process.env.SOVR_PROXY_CONFIG;
  if (!configPath) return null;
  try {
    const fs = __require("fs");
    return JSON.parse(fs.readFileSync(configPath, "utf8"));
  } catch (err) {
    log(`[proxy] Warning: Failed to load proxy config from ${configPath}: ${err}`);
    return null;
  }
}
function sendToDownstream(server, message) {
  if (server.transportType === "stdio") {
    if (!server.process?.stdin?.writable) return;
    const json = JSON.stringify(message);
    const payload = `Content-Length: ${Buffer.byteLength(json)}\r
\r
${json}`;
    server.process.stdin.write(payload);
  } else if (server.transportType === "sse") {
    const postUrl = server.remotePostUrl;
    if (!postUrl) {
      log(`[proxy:${server.name}] SSE post URL not yet established`);
      return;
    }
    const json = JSON.stringify(message);
    fetch(postUrl, {
      method: "POST",
      headers: { "Content-Type": "application/json", ...server.remoteHeaders ?? {} },
      body: json,
      signal: AbortSignal.timeout(3e4)
    }).catch((err) => log(`[proxy:${server.name}] SSE POST error: ${err}`));
  } else if (server.transportType === "streamable-http") {
  }
}
function requestFromDownstream(server, method, params) {
  if (server.transportType === "streamable-http") {
    return requestFromDownstreamHttp(server, method, params);
  }
  if (server.transportType === "sse") {
    return requestFromDownstreamSse(server, method, params);
  }
  return new Promise((resolve, reject) => {
    const id = server.nextId++;
    const TIMEOUT_MS = 3e4;
    const timer = setTimeout(() => {
      server.pendingRequests.delete(id);
      reject(new Error(`[proxy] Timeout waiting for ${server.name} response to ${method}`));
    }, TIMEOUT_MS);
    server.pendingRequests.set(id, { resolve, reject, timer });
    sendToDownstream(server, { jsonrpc: "2.0", id, method, params: params ?? {} });
  });
}
function requestFromDownstreamSse(server, method, params) {
  return new Promise((resolve, reject) => {
    const id = server.nextId++;
    const TIMEOUT_MS = 3e4;
    const timer = setTimeout(() => {
      server.pendingRequests.delete(id);
      reject(new Error(`[proxy] Timeout waiting for ${server.name} SSE response to ${method}`));
    }, TIMEOUT_MS);
    server.pendingRequests.set(id, { resolve, reject, timer });
    const postUrl = server.remotePostUrl;
    if (!postUrl) {
      clearTimeout(timer);
      server.pendingRequests.delete(id);
      reject(new Error(`[proxy:${server.name}] SSE post URL not established`));
      return;
    }
    const json = JSON.stringify({ jsonrpc: "2.0", id, method, params: params ?? {} });
    fetch(postUrl, {
      method: "POST",
      headers: { "Content-Type": "application/json", ...server.remoteHeaders ?? {} },
      body: json,
      signal: AbortSignal.timeout(TIMEOUT_MS)
    }).catch((err) => {
      clearTimeout(timer);
      server.pendingRequests.delete(id);
      reject(new Error(`[proxy:${server.name}] SSE POST failed: ${err}`));
    });
  });
}
async function requestFromDownstreamHttp(server, method, params) {
  const id = server.nextId++;
  const url = server.remoteUrl;
  if (!url) throw new Error(`[proxy:${server.name}] No remote URL configured`);
  const json = JSON.stringify({ jsonrpc: "2.0", id, method, params: params ?? {} });
  const TIMEOUT_MS = 3e4;
  const resp = await fetch(url, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "Accept": "application/json, text/event-stream",
      ...server.remoteHeaders ?? {}
    },
    body: json,
    signal: AbortSignal.timeout(TIMEOUT_MS)
  });
  if (!resp.ok) {
    throw new Error(`[proxy:${server.name}] HTTP ${resp.status}: ${resp.statusText}`);
  }
  const contentType = resp.headers.get("content-type") ?? "";
  if (contentType.includes("application/json")) {
    const data2 = await resp.json();
    if (data2.error) throw new Error(data2.error.message ?? "Downstream error");
    return data2.result;
  }
  if (contentType.includes("text/event-stream")) {
    const text = await resp.text();
    for (const line of text.split("\n")) {
      if (!line.startsWith("data: ")) continue;
      try {
        const msg = JSON.parse(line.slice(6));
        if (msg.id === id) {
          if (msg.error) throw new Error(msg.error.message ?? "Downstream error");
          return msg.result;
        }
      } catch {
      }
    }
    throw new Error(`[proxy:${server.name}] No matching response in SSE stream`);
  }
  const data = await resp.json();
  if (data.error) throw new Error(data.error.message ?? "Downstream error");
  return data.result;
}
function handleDownstreamData(server, chunk) {
  server.buffer += chunk;
  while (true) {
    const headerEnd = server.buffer.indexOf("\r\n\r\n");
    if (headerEnd === -1) break;
    const header = server.buffer.substring(0, headerEnd);
    const clMatch = header.match(/Content-Length:\s*(\d+)/i);
    if (!clMatch) {
      server.buffer = server.buffer.substring(headerEnd + 4);
      continue;
    }
    const cl = parseInt(clMatch[1], 10);
    const bodyStart = headerEnd + 4;
    if (server.buffer.length < bodyStart + cl) break;
    const body = server.buffer.substring(bodyStart, bodyStart + cl);
    server.buffer = server.buffer.substring(bodyStart + cl);
    try {
      const msg = JSON.parse(body);
      if (msg.id !== void 0 && server.pendingRequests.has(msg.id)) {
        const pending = server.pendingRequests.get(msg.id);
        clearTimeout(pending.timer);
        server.pendingRequests.delete(msg.id);
        if (msg.error) {
          pending.reject(new Error(msg.error.message ?? "Downstream error"));
        } else {
          pending.resolve(msg.result);
        }
      }
    } catch {
      log(`[proxy] Failed to parse response from ${server.name}`);
    }
  }
}
function resolveTransport(config) {
  if (config.transport) return config.transport;
  if ("command" in config && config.command) return "stdio";
  if ("url" in config && config.url) {
    const u = config.url;
    if (u.includes("/sse")) return "sse";
    return "streamable-http";
  }
  return "stdio";
}
function createDownstreamServer(name, transport) {
  return {
    name,
    transportType: transport,
    process: null,
    tools: [],
    ready: false,
    buffer: "",
    pendingRequests: /* @__PURE__ */ new Map(),
    nextId: 1
  };
}
async function connectStdioDownstream(name, config) {
  const { spawn } = __require("child_process");
  const server = createDownstreamServer(name, "stdio");
  const env = { ...process.env, ...config.env ?? {} };
  delete env.SOVR_PROXY_CONFIG;
  const proc = spawn(config.command, config.args ?? [], {
    stdio: ["pipe", "pipe", "pipe"],
    env
  });
  server.process = proc;
  proc.stdout.setEncoding("utf8");
  proc.stdout.on("data", (chunk) => handleDownstreamData(server, chunk));
  proc.stderr.setEncoding("utf8");
  proc.stderr.on("data", (chunk) => {
    for (const line of chunk.split("\n").filter(Boolean)) {
      log(`[proxy:${name}] ${line}`);
    }
  });
  proc.on("exit", (code) => {
    log(`[proxy] Downstream ${name} exited with code ${code}`);
    server.ready = false;
    for (const [, pending] of server.pendingRequests) {
      clearTimeout(pending.timer);
      pending.reject(new Error(`Downstream ${name} process exited`));
    }
    server.pendingRequests.clear();
  });
  await initializeMcpHandshake(server);
  return server;
}
async function connectSseDownstream(name, config) {
  const server = createDownstreamServer(name, "sse");
  server.remoteUrl = config.url;
  server.remoteHeaders = { ...config.headers ?? {} };
  if (config.env) {
    for (const [k, v] of Object.entries(config.env)) {
      if (k.toLowerCase().includes("token") || k.toLowerCase().includes("key") || k.toLowerCase().includes("auth")) {
        if (!server.remoteHeaders["Authorization"]) {
          server.remoteHeaders["Authorization"] = `Bearer ${v}`;
        }
      }
    }
  }
  const abort = new AbortController();
  server.sseAbort = abort;
  log(`[proxy:${name}] Connecting to SSE endpoint: ${config.url}`);
  try {
    const resp = await fetch(config.url, {
      method: "GET",
      headers: {
        "Accept": "text/event-stream",
        ...server.remoteHeaders
      },
      signal: abort.signal
    });
    if (!resp.ok) {
      throw new Error(`SSE connection failed: HTTP ${resp.status} ${resp.statusText}`);
    }
    if (!resp.body) {
      throw new Error("SSE response has no body");
    }
    const reader = resp.body.getReader();
    const decoder = new TextDecoder();
    let sseBuf = "";
    const readLoop = async () => {
      try {
        while (true) {
          const { done, value } = await reader.read();
          if (done) {
            log(`[proxy:${name}] SSE stream ended`);
            server.ready = false;
            break;
          }
          sseBuf += decoder.decode(value, { stream: true });
          const events = sseBuf.split("\n\n");
          sseBuf = events.pop() ?? "";
          for (const event of events) {
            if (!event.trim()) continue;
            let eventType = "message";
            let eventData = "";
            for (const line of event.split("\n")) {
              if (line.startsWith("event: ")) {
                eventType = line.slice(7).trim();
              } else if (line.startsWith("data: ")) {
                eventData += (eventData ? "\n" : "") + line.slice(6);
              } else if (line.startsWith("data:")) {
                eventData += (eventData ? "\n" : "") + line.slice(5);
              }
            }
            if (eventType === "endpoint" && eventData) {
              const endpointUrl = eventData.trim();
              try {
                const base = new URL(config.url);
                server.remotePostUrl = new URL(endpointUrl, base).toString();
              } catch {
                server.remotePostUrl = endpointUrl;
              }
              log(`[proxy:${name}] SSE message endpoint: ${server.remotePostUrl}`);
            } else if (eventType === "message" && eventData) {
              try {
                const msg = JSON.parse(eventData);
                if (msg.id !== void 0 && server.pendingRequests.has(msg.id)) {
                  const pending = server.pendingRequests.get(msg.id);
                  clearTimeout(pending.timer);
                  server.pendingRequests.delete(msg.id);
                  if (msg.error) {
                    pending.reject(new Error(msg.error.message ?? "Downstream SSE error"));
                  } else {
                    pending.resolve(msg.result);
                  }
                }
              } catch {
                log(`[proxy:${name}] Failed to parse SSE message: ${eventData.substring(0, 200)}`);
              }
            }
          }
        }
      } catch (err) {
        if (!abort.signal.aborted) {
          log(`[proxy:${name}] SSE read error: ${err}`);
          server.ready = false;
        }
      }
    };
    readLoop();
    const endpointTimeout = 15e3;
    const startWait = Date.now();
    while (!server.remotePostUrl && Date.now() - startWait < endpointTimeout) {
      await new Promise((r) => setTimeout(r, 100));
    }
    if (!server.remotePostUrl) {
      throw new Error(`SSE server did not send endpoint URL within ${endpointTimeout}ms`);
    }
    await initializeMcpHandshake(server);
  } catch (err) {
    log(`[proxy:${name}] SSE connection failed: ${err}`);
    abort.abort();
  }
  return server;
}
async function connectHttpDownstream(name, config) {
  const server = createDownstreamServer(name, "streamable-http");
  server.remoteUrl = config.url;
  server.remoteHeaders = { ...config.headers ?? {} };
  if (config.env) {
    for (const [k, v] of Object.entries(config.env)) {
      if (k.toLowerCase().includes("token") || k.toLowerCase().includes("key") || k.toLowerCase().includes("auth")) {
        if (!server.remoteHeaders["Authorization"]) {
          server.remoteHeaders["Authorization"] = `Bearer ${v}`;
        }
      }
    }
  }
  log(`[proxy:${name}] Connecting to Streamable HTTP endpoint: ${config.url}`);
  try {
    await initializeMcpHandshake(server);
  } catch (err) {
    log(`[proxy:${name}] Streamable HTTP connection failed: ${err}`);
  }
  return server;
}
async function initializeMcpHandshake(server) {
  try {
    await requestFromDownstream(server, "initialize", {
      protocolVersion: "2024-11-05",
      capabilities: {},
      clientInfo: { name: "sovr-proxy", version: VERSION }
    });
    if (server.transportType === "stdio") {
      sendToDownstream(server, { jsonrpc: "2.0", method: "notifications/initialized" });
    } else if (server.transportType === "sse" && server.remotePostUrl) {
      fetch(server.remotePostUrl, {
        method: "POST",
        headers: { "Content-Type": "application/json", ...server.remoteHeaders ?? {} },
        body: JSON.stringify({ jsonrpc: "2.0", method: "notifications/initialized" })
      }).catch(() => {
      });
    } else if (server.transportType === "streamable-http" && server.remoteUrl) {
      fetch(server.remoteUrl, {
        method: "POST",
        headers: { "Content-Type": "application/json", ...server.remoteHeaders ?? {} },
        body: JSON.stringify({ jsonrpc: "2.0", method: "notifications/initialized" })
      }).catch(() => {
      });
    }
    const toolsResult = await requestFromDownstream(server, "tools/list", {});
    server.tools = toolsResult?.tools ?? [];
    server.ready = true;
    for (const tool of server.tools) {
      proxyToolMap.set(tool.name, server.name);
    }
    log(`[proxy] ${server.name}: ${server.tools.length} tools discovered (${server.transportType})`);
  } catch (err) {
    log(`[proxy] Failed to initialize ${server.name}: ${err}`);
  }
}
async function connectDownstream(name, config) {
  const transport = resolveTransport(config);
  log(`[proxy] Connecting to ${name} via ${transport}...`);
  switch (transport) {
    case "stdio":
      return connectStdioDownstream(name, config);
    case "sse":
      return connectSseDownstream(name, config);
    case "streamable-http":
      return connectHttpDownstream(name, config);
    default:
      throw new Error(`Unknown transport: ${transport}`);
  }
}
async function initProxy() {
  const config = getProxyConfig();
  if (!config?.downstream || Object.keys(config.downstream).length === 0) return;
  proxyEnabled = true;
  log(`[proxy] Initializing transparent interception for ${Object.keys(config.downstream).length} downstream servers...`);
  const results = await Promise.allSettled(
    Object.entries(config.downstream).map(([name, cfg]) => connectDownstream(name, cfg))
  );
  for (const result of results) {
    if (result.status === "fulfilled" && result.value.ready) {
      downstreamServers.set(result.value.name, result.value);
    } else if (result.status === "rejected") {
      log(`[proxy] Failed to start downstream: ${result.reason}`);
    }
  }
  const totalTools = Array.from(downstreamServers.values()).reduce((sum, s) => sum + s.tools.length, 0);
  log(`[proxy] Transparent wall active \u2014 ${downstreamServers.size} downstream servers, ${totalTools} intercepted tools`);
}
function getProxyTools() {
  const tools = [];
  for (const [, server] of downstreamServers) {
    if (!server.ready) continue;
    for (const tool of server.tools) {
      tools.push(tool);
    }
  }
  return tools;
}
async function proxyToolCall(toolName, args) {
  const serverName = proxyToolMap.get(toolName);
  if (!serverName) {
    return { content: [{ type: "text", text: `Unknown proxied tool: ${toolName}` }], isError: true };
  }
  const server = downstreamServers.get(serverName);
  if (!server?.ready) {
    return { content: [{ type: "text", text: `Downstream server ${serverName} is not available` }], isError: true };
  }
  const gateResult = evaluate("mcp", toolName, serverName, {
    tool_name: toolName,
    server_name: serverName,
    args_keys: Object.keys(args),
    args_summary: JSON.stringify(args).substring(0, 500),
    proxy: true
  });
  if (gateResult.verdict === "deny") {
    log(`[proxy] BLOCKED ${serverName}/${toolName} \u2014 ${gateResult.reason} (risk:${gateResult.risk_score})`);
    return {
      content: [{
        type: "text",
        text: JSON.stringify({
          error: "SOVR_POLICY_VIOLATION",
          message: `Action blocked by SOVR Responsibility Layer: ${gateResult.reason}`,
          decision_id: gateResult.decision_id,
          risk_score: gateResult.risk_score,
          matched_rules: gateResult.matched_rules,
          verdict: "deny"
        }, null, 2)
      }],
      isError: true
    };
  }
  if (gateResult.verdict === "escalate") {
    log(`[proxy] ESCALATED ${serverName}/${toolName} \u2014 requires approval (risk:${gateResult.risk_score})`);
    return {
      content: [{
        type: "text",
        text: JSON.stringify({
          status: "PENDING_APPROVAL",
          message: `Action requires human approval via SOVR: ${gateResult.reason}`,
          decision_id: gateResult.decision_id,
          risk_score: gateResult.risk_score,
          matched_rules: gateResult.matched_rules,
          verdict: "escalate",
          instructions: "Use sovr_approve_decision or sovr_request_approval to proceed."
        }, null, 2)
      }],
      isError: true
    };
  }
  log(`[proxy] FORWARDING ${serverName}/${toolName} (decision:${gateResult.decision_id})`);
  try {
    const result = await requestFromDownstream(server, "tools/call", { name: toolName, arguments: args });
    return result;
  } catch (err) {
    log(`[proxy] Error forwarding to ${serverName}: ${err}`);
    return {
      content: [{
        type: "text",
        text: `Error forwarding to ${serverName}: ${err instanceof Error ? err.message : String(err)}`
      }],
      isError: true
    };
  }
}
function shutdownProxy() {
  for (const [name, server] of downstreamServers) {
    log(`[proxy] Shutting down ${name} (${server.transportType})`);
    if (server.transportType === "stdio" && server.process) {
      server.process.kill("SIGTERM");
    } else if (server.sseAbort) {
      server.sseAbort.abort();
    }
    for (const [, pending] of server.pendingRequests) {
      clearTimeout(pending.timer);
      pending.reject(new Error(`Downstream ${name} shutting down`));
    }
    server.pendingRequests.clear();
  }
  downstreamServers.clear();
  proxyToolMap.clear();
}
process.on("SIGINT", () => {
  shutdownProxy();
  process.exit(0);
});
process.on("SIGTERM", () => {
  shutdownProxy();
  process.exit(0);
});
function generateId() {
  return `sovr_${Date.now().toString(36)}_${Math.random().toString(36).slice(2, 8)}`;
}
function matchesPattern(value, pattern) {
  if (pattern === "*") return true;
  if (pattern.includes("|")) return pattern.split("|").some((p) => matchesPattern(value, p.trim()));
  const escaped = pattern.replace(/[.+^${}()[\]\\]/g, "\\$&").replace(/\*/g, ".*");
  return new RegExp("^" + escaped + "$", "i").test(value);
}
function evaluateCondition(cond, context) {
  const actual = String(context[cond.field] ?? "");
  switch (cond.operator) {
    case "eq":
      return actual === cond.value;
    case "neq":
      return actual !== cond.value;
    case "contains":
      return actual.includes(cond.value);
    case "regex":
      return new RegExp(cond.value, "i").test(actual);
    default:
      return false;
  }
}
var RISK_SCORES = { none: 0, low: 20, medium: 50, high: 80, critical: 100 };
function evaluate(channel, action, resource, context = {}) {
  const matchedRules = [];
  const sorted = [...rules].filter((r) => r.enabled && r.channels.includes(channel)).sort((a, b) => b.priority - a.priority);
  for (const rule of sorted) {
    if (!matchesPattern(action, rule.action_pattern)) continue;
    if (!matchesPattern(resource, rule.resource_pattern)) continue;
    const condsMet = rule.conditions.length === 0 || rule.conditions.every((c) => evaluateCondition(c, context));
    if (condsMet) matchedRules.push(rule);
  }
  let verdict = "allow";
  let riskScore = 0;
  let reason = "No matching rules \u2014 action allowed by default";
  if (matchedRules.length > 0) {
    const top = matchedRules[0];
    verdict = top.effect;
    riskScore = RISK_SCORES[top.risk_level] ?? 50;
    reason = top.description;
  }
  const entry = { decision_id: generateId(), timestamp: Date.now(), channel, action, resource, verdict, risk_score: riskScore, matched_rules: matchedRules.map((r) => r.id) };
  auditLog.unshift(entry);
  if (auditLog.length > MAX_AUDIT) auditLog.length = MAX_AUDIT;
  log(`[gate] ${verdict.toUpperCase()} ${channel}:${action} \u2192 ${resource} (risk:${riskScore}, rules:${matchedRules.length})`);
  return { verdict, risk_score: riskScore, matched_rules: matchedRules.map((r) => r.id), reason, decision_id: entry.decision_id, timestamp: entry.timestamp, channel };
}
function parseCommand(raw) {
  const trimmed = raw.trim();
  const parts = trimmed.split(/\s+/);
  let idx = 0;
  const hasSudo = parts[0] === "sudo";
  if (hasSudo) idx++;
  const command = parts[idx] ?? "";
  idx++;
  const subCmdTools = ["kubectl", "docker", "git", "npm", "pnpm", "yarn", "systemctl", "apt", "brew", "pip"];
  let subCommand = null;
  if (subCmdTools.includes(command) && parts[idx] && !parts[idx].startsWith("-")) {
    subCommand = parts[idx];
    idx++;
  }
  const args = parts.slice(idx);
  const hasPipe = trimmed.includes("|");
  const hasChain = trimmed.includes("&&") || trimmed.includes(";");
  const riskIndicators = [];
  if (hasSudo) riskIndicators.push("sudo");
  if (trimmed.includes("-rf") || trimmed.includes("-fr")) riskIndicators.push("recursive-force");
  if (trimmed.includes("--force") || trimmed.includes("-f")) riskIndicators.push("force-flag");
  if (trimmed.includes("--no-preserve-root")) riskIndicators.push("no-preserve-root");
  if (/\/(etc|boot|sys|proc|dev)\b/.test(trimmed)) riskIndicators.push("system-path");
  if (trimmed.includes("> /dev/") || trimmed.includes(">/dev/")) riskIndicators.push("device-write");
  if (hasPipe) riskIndicators.push("pipe");
  if (hasChain) riskIndicators.push("chain");
  return { command, subCommand, args, hasSudo, hasPipe, hasChain, riskIndicators };
}
function parseSQL(raw) {
  const trimmed = raw.trim();
  const isMultiStatement = trimmed.includes(";") && trimmed.replace(/;$/, "").includes(";");
  const typePatterns = [["DROP", /^DROP\b/i], ["TRUNCATE", /^TRUNCATE\b/i], ["ALTER", /^ALTER\b/i], ["CREATE", /^CREATE\b/i], ["DELETE", /^DELETE\b/i], ["UPDATE", /^UPDATE\b/i], ["INSERT", /^INSERT\b/i], ["SELECT", /^SELECT\b/i], ["GRANT", /^GRANT\b/i], ["REVOKE", /^REVOKE\b/i], ["EXEC", /^EXEC\b/i]];
  let type = "UNKNOWN";
  for (const [t, re] of typePatterns) {
    if (re.test(trimmed)) {
      type = t;
      break;
    }
  }
  const tables = [];
  const tablePatterns = [/\bFROM\s+(\w+)/gi, /\bJOIN\s+(\w+)/gi, /\bUPDATE\s+(\w+)/gi, /\bINTO\s+(\w+)/gi, /\bTABLE\s+(?:IF\s+(?:NOT\s+)?EXISTS\s+)?(\w+)/gi, /\bTRUNCATE\s+(?:TABLE\s+)?(\w+)/gi];
  for (const pattern of tablePatterns) {
    let match;
    while ((match = pattern.exec(trimmed)) !== null) {
      if (match[1] && !tables.includes(match[1])) tables.push(match[1]);
    }
  }
  const hasWhereClause = /\bWHERE\b/i.test(trimmed);
  return { type, tables, hasWhereClause, isMultiStatement, raw: trimmed };
}
var DEFAULT_CLOUD_URL = "https://sovr-ai-mkzgqqeh.manus.space";
var cloudEndpoint = null;
var cloudApiKey = null;
var TIER_LEVEL = { free: 0, personal: 1, starter: 2, pro: 3, enterprise: 4 };
var FREE_TOOLS = /* @__PURE__ */ new Set(["sovr_gate_check", "sovr_check_command", "sovr_check_sql", "sovr_check_http", "sovr_request_approval", "sovr_submit_receipt", "sovr_add_rule", "sovr_audit_log"]);
var PERSONAL_TOOLS = /* @__PURE__ */ new Set([...FREE_TOOLS, "sovr_health_check", "sovr_status_v2", "sovr_monitoring", "sovr_kill_switch", "sovr_degradation", "sovr_rollback", "sovr_budget", "sovr_list_rules", "sovr_test_rule", "sovr_delete_rule", "sovr_log_decision", "sovr_adapter", "sovr_gate", "sovr_risk", "sovr_monitor", "sovr_cloud_status", "sovr_escalate", "sovr_poll_escalation", "sovr_query_decisions"]);
var STARTER_TOOLS = /* @__PURE__ */ new Set([...PERSONAL_TOOLS, "sovr_audit_replay", "sovr_trust_bundle", "sovr_compliance", "sovr_report", "sovr_execute_report", "sovr_verification", "sovr_generate_certificate", "sovr_generate_diff", "sovr_snapshot", "sovr_receipt", "sovr_policy", "sovr_policy_guide", "sovr_list_policy", "sovr_deprecate_policy", "sovr_detect_policy", "sovr_rule", "sovr_create_rule", "sovr_list_report", "sovr_delete_report", "sovr_create_report", "sovr_sovr_export", "sovr_sovr_verify", "sovr_sovr_check", "sovr_update_verification", "sovr_validate_access", "sovr_query_violations", "sovr_report_violation", "sovr_get_violation_stats", "sovr_replay_decision", "sovr_export_bundle", "sovr_grant_permit", "sovr_openguard_scan", "sovr_openguard_quick_scan"]);
var PRO_TOOLS = /* @__PURE__ */ new Set([...STARTER_TOOLS, "sovr_cognitive", "sovr_threat", "sovr_scan", "sovr_detect_hallucination", "sovr_detect_conflict", "sovr_open_guard", "sovr_default_deny", "sovr_protect", "sovr_quick_hallucination", "sovr_security_review", "sovr_tenant", "sovr_create_tenant", "sovr_rbac", "sovr_feature_flag", "sovr_canary", "sovr_create_canary", "sovr_deployment", "sovr_cancel_deployment", "sovr_experiment", "sovr_sla", "sovr_scheduler", "sovr_task_queue", "sovr_model_ops", "sovr_webhook", "sovr_integration", "sovr_external_api", "sovr_external_gate", "sovr_p0", "sovr_p0_alerts", "sovr_p3_fusion", "sovr_p3_ops", "sovr_p5", "sovr_p6", "sovr_approval", "sovr_arbitrate", "sovr_batch_ops", "sovr_metering", "sovr_cost", "sovr_failure_budget", "sovr_regression", "sovr_qa", "sovr_execute_quality", "sovr_replay", "sovr_create_replay", "sovr_list_replay", "sovr_find_precedents", "sovr_resolve_conflict", "sovr_manual_trigger", "sovr_record_metric", "sovr_evaluate_metric"]);
function getToolTier(toolName) {
  if (FREE_TOOLS.has(toolName)) return "free";
  if (PERSONAL_TOOLS.has(toolName)) return "personal";
  if (STARTER_TOOLS.has(toolName)) return "starter";
  if (PRO_TOOLS.has(toolName)) return "pro";
  return "enterprise";
}
function tierHasAccess(userTier, toolName) {
  return TIER_LEVEL[userTier] >= TIER_LEVEL[getToolTier(toolName)];
}
function filterToolsByTier(tools, tier) {
  return tools.filter((t) => tierHasAccess(tier, t.name));
}
var currentTier = "free";
async function verifyKeyTier() {
  if (!cloudEndpoint || !cloudApiKey) return "free";
  try {
    const resp = await fetch(`${cloudEndpoint}/api/sovr/v1/key/verify`, {
      method: "POST",
      headers: { "Content-Type": "application/json", "X-SOVR-API-Key": cloudApiKey },
      body: JSON.stringify({ action: "verify_tier" }),
      signal: AbortSignal.timeout(8e3)
    });
    if (!resp.ok) {
      log(`[tier] Cloud verification failed (${resp.status}), defaulting to free tier`);
      return "free";
    }
    const data = await resp.json();
    const rawTier = (data.tier || data.plan || "free").toLowerCase();
    const validTiers = ["free", "personal", "starter", "pro", "enterprise"];
    if (validTiers.includes(rawTier)) return rawTier;
    if (rawTier === "basic" || rawTier === "individual") return "personal";
    if (rawTier === "team" || rawTier === "business") return "pro";
    return "personal";
  } catch (err) {
    log(`[tier] Cloud verification error: ${err instanceof Error ? err.message : String(err)}`);
    return cloudApiKey ? "personal" : "free";
  }
}
var pendingCloudReqs = [];
async function cloudRequest(path, body, timeoutMs = 5e3) {
  if (!cloudEndpoint || !cloudApiKey) return { ok: false, error: "SOVR Cloud not configured" };
  try {
    const resp = await fetch(`${cloudEndpoint}${path}`, {
      method: "POST",
      headers: { "Content-Type": "application/json", "X-SOVR-API-Key": cloudApiKey },
      body: JSON.stringify(body),
      signal: AbortSignal.timeout(timeoutMs)
    });
    if (!resp.ok) return { ok: false, error: `Cloud API ${resp.status}: ${resp.statusText}` };
    return { ok: true, data: await resp.json() };
  } catch (err) {
    return { ok: false, error: `Cloud error: ${err instanceof Error ? err.message : String(err)}` };
  }
}
async function cloudGet(path, timeoutMs = 5e3) {
  if (!cloudEndpoint || !cloudApiKey) return { ok: false, error: "SOVR Cloud not configured" };
  try {
    const resp = await fetch(`${cloudEndpoint}${path}`, {
      method: "GET",
      headers: { "Content-Type": "application/json", "X-SOVR-API-Key": cloudApiKey },
      signal: AbortSignal.timeout(timeoutMs)
    });
    if (!resp.ok) return { ok: false, error: `Cloud API ${resp.status}: ${resp.statusText}` };
    return { ok: true, data: await resp.json() };
  } catch (err) {
    return { ok: false, error: `Cloud error: ${err instanceof Error ? err.message : String(err)}` };
  }
}
function cloudSyncFire(path, body) {
  if (!cloudEndpoint || !cloudApiKey) return;
  const p = cloudRequest(path, body);
  pendingCloudReqs.push(p);
  p.finally(() => {
    const idx = pendingCloudReqs.indexOf(p);
    if (idx >= 0) pendingCloudReqs.splice(idx, 1);
  });
}
var hasCloud = () => !!cloudEndpoint && !!cloudApiKey;
var SDK_ROUTES = {
  "abTestGetTestResults": { method: "GET", path: "/p6/abTest/get-test-results" },
  "abTestGetVariant": { method: "GET", path: "/p6/abTest/get-variant" },
  "abTestTrackEvent": { method: "GET", path: "/p6/abTest/track-event" },
  "acknowledgeAlert": { method: "POST", path: "/monitoring/alerts/ack" },
  "acknowledgeP0Alert": { method: "POST", path: "/p5/acknowledge-p0-alert" },
  "acknowledgeP3Alert": { method: "POST", path: "/p5/acknowledge-p3-alert" },
  "activatePolicy": { method: "POST", path: "/p5/activate-policy" },
  "activateTenant": { method: "POST", path: "/p5/activate-tenant" },
  "addStripeQuotaPoolMember": { method: "POST", path: "/p5/add-stripe-quota-pool-member" },
  "addTenantMember": { method: "POST", path: "/p5/add-tenant-member" },
  "advanceCanary": { method: "POST", path: "/experiment/advance-canary" },
  "agentIntegrationConfigureCallback": { method: "POST", path: "/p6/agentIntegration/configure-callback" },
  "agentIntegrationGetIntegrationGuide": { method: "GET", path: "/p6/agentIntegration/get-integration-guide" },
  "agentIntegrationRegister": { method: "GET", path: "/p6/agentIntegration/register" },
  "agentIntegrationReportOperation": { method: "GET", path: "/p6/agentIntegration/report-operation" },
  "aggregatedHealth": { method: "GET", path: "/p7/health/aggregated" },
  "aiChatGetFaqAnalytics": { method: "GET", path: "/p6/aiChat/get-faq-analytics" },
  "aiChatGetOrCreateSession": { method: "GET", path: "/p6/aiChat/get-or-create-session" },
  "aiChatMarkHelpful": { method: "GET", path: "/p6/aiChat/mark-helpful" },
  "analyzeComplianceGaps": { method: "POST", path: "/p5/analyze-compliance-gaps" },
  "analyzeGaps": { method: "POST", path: "/p3/compliance/gaps" },
  "analyzeReasoning": { method: "POST", path: "/p5/analyze-reasoning" },
  "analyzeReasoning_ext": { method: "POST", path: "/p5/analyze-reasoning" },
  "apiKeyBatchDelete": { method: "POST", path: "/p6/apiKey/batch-delete" },
  "apiKeyBatchDisable": { method: "POST", path: "/p6/apiKey/batch-disable" },
  "apiKeyBatchEnable": { method: "POST", path: "/p6/apiKey/batch-enable" },
  "apiKeyExportUsageLogs": { method: "POST", path: "/p6/apiKey/export-usage-logs" },
  "apiKeyGet": { method: "GET", path: "/p6/apiKey/get" },
  "apiKeyGetAlertSettings": { method: "GET", path: "/p6/apiKey/get-alert-settings" },
  "apiKeyGetAuditLogs": { method: "GET", path: "/p6/apiKey/get-audit-logs" },
  "apiKeyGetUsage": { method: "GET", path: "/p6/apiKey/get-usage" },
  "apiKeyRateLimitStatus": { method: "GET", path: "/p6/apiKey/rate-limit-status" },
  "apiKeyRateLimiterHealth": { method: "GET", path: "/p6/apiKey/rate-limiter-health" },
  "apiKeyRenew": { method: "GET", path: "/p6/apiKey/renew" },
  "apiKeySaveAlertSettings": { method: "POST", path: "/p6/apiKey/save-alert-settings" },
  "arbitrate": { method: "POST", path: "/p5/arbitrate" },
  "assessRisk": { method: "POST", path: "/p5/assess-risk" },
  "assessRisk_ext": { method: "POST", path: "/p5/assess-risk" },
  "assignToExperiment": { method: "POST", path: "/p3/experiments/assign" },
  "autoAdjustDefaultDeny": { method: "POST", path: "/default-deny/auto-adjust" },
  "batchCalculateScores": { method: "POST", path: "/p3/scoring/batch" },
  "batchCalculateTrustScore": { method: "POST", path: "/p5/batch-calculate-trust-score" },
  "batchProcessApprovals": { method: "POST", path: "/approval/batch-process" },
  "batchToggleRules": { method: "POST", path: "/p5/batch-toggle-rules" },
  "billingExportBill": { method: "POST", path: "/p6/billing/export-bill" },
  "billingGetOverageBill": { method: "GET", path: "/p6/billing/get-overage-bill" },
  "billingGetQuotaPrediction": { method: "GET", path: "/p6/billing/get-quota-prediction" },
  "billingGetQuotaStatuses": { method: "GET", path: "/p6/billing/get-quota-statuses" },
  "billingGetQuotaTrends": { method: "GET", path: "/p6/billing/get-quota-trends" },
  "billingGetUsageSummary": { method: "GET", path: "/p6/billing/get-usage-summary" },
  "billingGetUsageTrend": { method: "GET", path: "/p6/billing/get-usage-trend" },
  "calculateAggregateTrustScore": { method: "POST", path: "/p5/calculate-aggregate-trust-score" },
  "calculateStripeAuditorAccountCost": { method: "GET", path: "/p6/stripe/calculate-auditor-account-cost" },
  "calculateStripeDeploymentAddonsCost": { method: "GET", path: "/p6/stripe/calculate-deployment-addons-cost" },
  "calculateStripeEnterprisePrice": { method: "GET", path: "/p6/stripe/calculate-enterprise-price" },
  "calculateTrustScore": { method: "POST", path: "/p5/calculate-trust-score" },
  "calculateTrustScore_ext": { method: "POST", path: "/p5/calculate-trust-score" },
  "canCreateStripeQuotaPool": { method: "GET", path: "/p5/can-create-stripe-quota-pool" },
  "canExportTrustBundle": { method: "GET", path: "/p5/can-export-trust-bundle" },
  "canIssueTrustBundle": { method: "GET", path: "/p5/can-issue-trust-bundle" },
  "canProceed": { method: "POST", path: "/budget/can-proceed" },
  "cancelDeploymentAddonSubscription": { method: "POST", path: "/stripe/cancel-deployment-addon-subscription" },
  "cancelFusionSubscription": { method: "POST", path: "/p5/cancel-fusion-subscription" },
  "cancelP3Task": { method: "POST", path: "/p5/cancel-p3-task" },
  "cancelTask": { method: "POST", path: "/p3/task-queue/cancel" },
  "changeFusionPlan": { method: "POST", path: "/p5/change-fusion-plan" },
  "checkApprovalIsolation": { method: "POST", path: "/rbac/check-approval-isolation" },
  "checkConsent": { method: "POST", path: "/rbac/check" },
  "checkConsent_ext": { method: "POST", path: "/p5/check-consent" },
  "checkConstraints": { method: "POST", path: "/p5/check-constraints" },
  "checkContract": { method: "POST", path: "/p5/check-contract" },
  "checkDataQuality": { method: "POST", path: "/p3/data-governance/quality" },
  "checkDualApproval": { method: "POST", path: "/rbac/check-dual-approval" },
  "checkForbiddenPatterns": { method: "POST", path: "/p5/check-forbidden-patterns" },
  "checkKillSwitchOperation": { method: "POST", path: "/kill-switch/check-operation" },
  "checkNarrative": { method: "POST", path: "/p5/check-narrative" },
  "checkPermission": { method: "POST", path: "/rbac/check-permission" },
  "checkPrecedent": { method: "POST", path: "/rbac/check" },
  "checkQuota": { method: "POST", path: "/rbac/check" },
  "checkReality": { method: "POST", path: "/rbac/check" },
  "checkStripeDeploymentAddonEligibility": { method: "GET", path: "/stripe/deployment-addon-eligibility/${addonId}" },
  "checkStripeOverageAllowance": { method: "GET", path: "/p6/stripe/check-overage-allowance" },
  "checkStripeQuota": { method: "GET", path: "/p5/check-stripe-quota" },
  "checkStripeQuotaWithDegrade": { method: "GET", path: "/p6/stripe/check-quota-with-degrade" },
  "checkTenantQuota": { method: "POST", path: "/p5/check-tenant-quota" },
  "classifyData": { method: "POST", path: "/p5/classify-data" },
  "classifyData_ext": { method: "POST", path: "/p5/classify-data" },
  "clearP1P2Cache": { method: "POST", path: "/p6/core/clear-cache" },
  "cognitiveDetect": { method: "POST", path: "/p5/cognitive-detect" },
  "compareCheckpoints": { method: "POST", path: "/p5/compare-checkpoints" },
  "compareSnapshots": { method: "POST", path: "/p3/audit-replay/compare" },
  "compareWithCurrent": { method: "POST", path: "/p5/compare-with-current" },
  "compilePolicy": { method: "POST", path: "/policy/compile" },
  "completeLifecycle": { method: "POST", path: "/p5/complete-lifecycle" },
  "completeTask": { method: "POST", path: "/p3/task-queue/complete" },
  "computeModelRisk": { method: "GET", path: "/p5/compute-model-risk" },
  "computeRuleHealth": { method: "GET", path: "/p5/compute-rule-health" },
  "configureEmail": { method: "POST", path: "/p5/configure-email" },
  "configureSlack": { method: "POST", path: "/p5/configure-slack" },
  "consumeBudget": { method: "POST", path: "/budget/consume" },
  "consumeMeteringQuota": { method: "GET", path: "/p6/sovr/consume-quota" },
  "coreAccessLogs": { method: "GET", path: "/p6/core/access-logs" },
  "coreAcknowledgeChannelAlert": { method: "GET", path: "/p6/core/acknowledge-channel-alert" },
  "coreAdapters": { method: "GET", path: "/p6/core/adapters" },
  "coreAddEvidence": { method: "POST", path: "/p6/core/add-evidence" },
  "coreAllKillSwitchApprovals": { method: "GET", path: "/p6/core/all-kill-switch-approvals" },
  "coreApplyCustomTemplate": { method: "GET", path: "/p6/core/apply-custom-template" },
  "coreApplyPermissionPreset": { method: "GET", path: "/p6/core/apply-permission-preset" },
  "coreApplyPreset": { method: "GET", path: "/p6/core/apply-preset" },
  "coreApplyQuietHoursPreset": { method: "GET", path: "/p6/core/apply-quiet-hours-preset" },
  "coreApplyThresholdPreset": { method: "GET", path: "/p6/core/apply-threshold-preset" },
  "coreApprove": { method: "GET", path: "/p6/core/approve" },
  "coreArchive": { method: "GET", path: "/p6/core/archive" },
  "coreArchiveTest": { method: "GET", path: "/p6/core/archive-test" },
  "coreAutoGenerateReports": { method: "GET", path: "/p6/core/auto-generate-reports" },
  "coreBatchAcknowledge": { method: "POST", path: "/p6/core/batch-acknowledge" },
  "coreBatchCreateForDecisions": { method: "POST", path: "/p6/core/batch-create-for-decisions" },
  "coreBatchEnqueue": { method: "POST", path: "/p6/core/batch-enqueue" },
  "coreBatchExport": { method: "POST", path: "/p6/core/batch-export" },
  "coreBatchImport": { method: "POST", path: "/p6/core/batch-import" },
  "coreBatchImportDryRun": { method: "POST", path: "/p6/core/batch-import-dry-run" },
  "coreBatchManualReEvaluate": { method: "POST", path: "/p6/core/batch-manual-re-evaluate" },
  "coreBatchReEvaluate": { method: "POST", path: "/p6/core/batch-re-evaluate" },
  "coreBatchUpdatePermissionMatrix": { method: "POST", path: "/p6/core/batch-update-permission-matrix" },
  "coreBatchUpdateRoles": { method: "POST", path: "/p6/core/batch-update-roles" },
  "coreBillingRecords": { method: "GET", path: "/p6/core/billing-records" },
  "coreBillingSummary": { method: "GET", path: "/p6/core/billing-summary" },
  "coreBroadcastIMMessage": { method: "GET", path: "/p6/core/broadcast-i-m-message" },
  "coreByCategory": { method: "GET", path: "/p6/core/by-category" },
  "coreBypassStats": { method: "GET", path: "/p6/core/bypass-stats" },
  "coreCancelImportTask": { method: "POST", path: "/p6/core/cancel-import-task" },
  "coreCancelQueued": { method: "POST", path: "/p6/core/cancel-queued" },
  "coreCancelRoleRequest": { method: "POST", path: "/p6/core/cancel-role-request" },
  "coreCategories": { method: "GET", path: "/p6/core/categories" },
  "coreChainedLogs": { method: "GET", path: "/p6/core/chained-logs" },
  "coreChangePassword": { method: "POST", path: "/p6/core/change-password" },
  "coreCheckAllChannelsHealth": { method: "GET", path: "/p6/core/check-all-channels-health" },
  "coreCheckAllRunningTests": { method: "GET", path: "/p6/core/check-all-running-tests" },
  "coreCheckBypassed": { method: "GET", path: "/p6/core/check-bypassed" },
  "coreCheckChannelHealth": { method: "GET", path: "/p6/core/check-channel-health" },
  "coreCheckCircuitBreakerChanges": { method: "GET", path: "/p6/core/check-circuit-breaker-changes" },
  "coreCheckDecisionsHaveBundles": { method: "GET", path: "/p6/core/check-decisions-have-bundles" },
  "coreCheckExpiringKeys": { method: "GET", path: "/p6/core/check-expiring-keys" },
  "coreCheckKillSwitchChanges": { method: "GET", path: "/p6/core/check-kill-switch-changes" },
  "coreCheckQuotaExhaustion": { method: "GET", path: "/p6/core/check-quota-exhaustion" },
  "coreCheckRateLimit": { method: "GET", path: "/p6/core/check-rate-limit" },
  "coreCircuitBreakerStatus": { method: "GET", path: "/p6/core/circuit-breaker-status" },
  "coreCleanupExecutions": { method: "GET", path: "/p6/core/cleanup-executions" },
  "coreCleanupExpired": { method: "GET", path: "/p6/core/cleanup-expired" },
  "coreCleanupExpiredArchives": { method: "GET", path: "/p6/core/cleanup-expired-archives" },
  "coreCleanupMerkleTreeCaches": { method: "GET", path: "/p6/core/cleanup-merkle-tree-caches" },
  "coreCleanupStats": { method: "GET", path: "/p6/core/cleanup-stats" },
  "coreClearCache": { method: "POST", path: "/p6/core/clear-cache" },
  "coreCodeFixGate": { method: "GET", path: "/p6/core/code-fix-gate" },
  "coreCodeReview": { method: "GET", path: "/p6/core/code-review" },
  "coreCompareArchives": { method: "GET", path: "/p6/core/compare-archives" },
  "coreCompareVersions": { method: "GET", path: "/p6/core/compare-versions" },
  "coreComprehensiveHealthCheck": { method: "GET", path: "/p6/core/comprehensive-health-check" },
  "coreControlPlane": { method: "GET", path: "/p6/core/control-plane" },
  "coreCreateAsyncImportTask": { method: "POST", path: "/p6/core/create-async-import-task" },
  "coreCreateBatchExport": { method: "POST", path: "/p6/core/create-batch-export" },
  "coreCreateBatchTest": { method: "POST", path: "/p6/core/create-batch-test" },
  "coreCreateCleanupPolicy": { method: "POST", path: "/p6/core/create-cleanup-policy" },
  "coreCreateConfig": { method: "POST", path: "/p6/core/create-config" },
  "coreCreateCustomTemplate": { method: "POST", path: "/p6/core/create-custom-template" },
  "coreCreateForDecision": { method: "POST", path: "/p6/core/create-for-decision" },
  "coreCreateKey": { method: "POST", path: "/p6/core/create-key" },
  "coreCreateKillSwitchApproval": { method: "POST", path: "/p6/core/create-kill-switch-approval" },
  "coreCreateReportSubscription": { method: "POST", path: "/p6/core/create-report-subscription" },
  "coreCreateRoleRequest": { method: "POST", path: "/p6/core/create-role-request" },
  "coreCreateRuleFromTemplate": { method: "POST", path: "/p6/core/create-rule-from-template" },
  "coreCreateShareLink": { method: "POST", path: "/p6/core/create-share-link" },
  "coreCreateTemplate": { method: "POST", path: "/p6/core/create-template" },
  "coreCreateWeights": { method: "POST", path: "/p6/core/create-weights" },
  "coreDbTables": { method: "GET", path: "/p6/core/db-tables" },
  "coreDefaultTemplate": { method: "GET", path: "/p6/core/default-template" },
  "coreDemoEvaluate": { method: "GET", path: "/p6/core/demo-evaluate" },
  "coreDeploymentHistory": { method: "GET", path: "/p6/core/deployment-history" },
  "coreDeploymentStats": { method: "GET", path: "/p6/core/deployment-stats" },
  "coreDeprecateKey": { method: "GET", path: "/p6/core/deprecate-key" },
  "coreDetailWithHistory": { method: "GET", path: "/p6/core/detail-with-history" },
  "coreDownloadBatchExport": { method: "GET", path: "/p6/core/download-batch-export" },
  "coreDownloadBundlePdf": { method: "GET", path: "/p6/core/download-bundle-pdf" },
  "coreDryRun": { method: "GET", path: "/p6/core/dry-run" },
  "coreDynamicAdapterConfigs": { method: "GET", path: "/p6/core/dynamic-adapter-configs" },
  "coreEngineActivate": { method: "GET", path: "/p6/core/engine-activate" },
  "coreEngineDeactivate": { method: "GET", path: "/p6/core/engine-deactivate" },
  "coreEngineStatus": { method: "GET", path: "/p6/core/engine-status" },
  "coreEnhancedReview": { method: "GET", path: "/p6/core/enhanced-review" },
  "coreEnqueue": { method: "GET", path: "/p6/core/enqueue" },
  "coreEvaluationHistory": { method: "GET", path: "/p6/core/evaluation-history" },
  "coreEvaluationStats": { method: "GET", path: "/p6/core/evaluation-stats" },
  "coreEventTypes": { method: "GET", path: "/p6/core/event-types" },
  "coreEvidenceChain": { method: "GET", path: "/p6/core/evidence-chain" },
  "coreEvidenceWeights": { method: "GET", path: "/p6/core/evidence-weights" },
  "coreExecuteBatchTest": { method: "GET", path: "/p6/core/execute-batch-test" },
  "coreExportCleanupReportCsv": { method: "POST", path: "/p6/core/export-cleanup-report-csv" },
  "coreExportJson": { method: "POST", path: "/p6/core/export-json" },
  "coreExportPdf": { method: "POST", path: "/p6/core/export-pdf" },
  "coreExportReport": { method: "POST", path: "/p6/core/export-report" },
  "coreExportReportJson": { method: "POST", path: "/p6/core/export-report-json" },
  "coreExportReportMarkdown": { method: "POST", path: "/p6/core/export-report-markdown" },
  "coreExportReportPdf": { method: "POST", path: "/p6/core/export-report-pdf" },
  "coreFeatured": { method: "GET", path: "/p6/core/featured" },
  "coreFindMatchingRules": { method: "GET", path: "/p6/core/find-matching-rules" },
  "coreForgotPassword": { method: "GET", path: "/p6/core/forgot-password" },
  "coreFullReview": { method: "GET", path: "/p6/core/full-review" },
  "coreGenerateAnalysisReport": { method: "GET", path: "/p6/core/generate-analysis-report" },
  "coreGenerateApiKey": { method: "GET", path: "/p6/core/generate-api-key" },
  "coreGenerateCleanupReport": { method: "GET", path: "/p6/core/generate-cleanup-report" },
  "coreGenerateCoverageReport": { method: "GET", path: "/p6/core/generate-coverage-report" },
  "coreGeneratePdfContent": { method: "GET", path: "/p6/core/generate-pdf-content" },
  "coreGenerateQuotePdf": { method: "GET", path: "/p6/core/generate-quote-pdf" },
  "coreGet": { method: "GET", path: "/p6/core/get" },
  "coreGetAbTestDetail": { method: "GET", path: "/p6/core/get-ab-test-detail" },
  "coreGetAbTestEmailTemplate": { method: "GET", path: "/p6/core/get-ab-test-email-template" },
  "coreGetAbTestEmailTemplates": { method: "GET", path: "/p6/core/get-ab-test-email-templates" },
  "coreGetAbTestStats": { method: "GET", path: "/p6/core/get-ab-test-stats" },
  "coreGetAlertThreshold": { method: "GET", path: "/p6/core/get-alert-threshold" },
  "coreGetAllChannelsHealthTrend": { method: "GET", path: "/p6/core/get-all-channels-health-trend" },
  "coreGetAllRulesTriggerSummary": { method: "GET", path: "/p6/core/get-all-rules-trigger-summary" },
  "coreGetArchive": { method: "GET", path: "/p6/core/get-archive" },
  "coreGetArchiveByTestId": { method: "GET", path: "/p6/core/get-archive-by-test-id" },
  "coreGetArchiveStats": { method: "GET", path: "/p6/core/get-archive-stats" },
  "coreGetArchives": { method: "GET", path: "/p6/core/get-archives" },
  "coreGetAutoTriggerConfig": { method: "GET", path: "/p6/core/get-auto-trigger-config" },
  "coreGetAutoTriggerStatus": { method: "GET", path: "/p6/core/get-auto-trigger-status" },
  "coreGetAvailableVariables": { method: "GET", path: "/p6/core/get-available-variables" },
  "coreGetBatchExportFile": { method: "GET", path: "/p6/core/get-batch-export-file" },
  "coreGetBatchExportStatus": { method: "GET", path: "/p6/core/get-batch-export-status" },
  "coreGetById": { method: "GET", path: "/p6/core/get-by-id" },
  "coreGetByRequestId": { method: "GET", path: "/p6/core/get-by-request-id" },
  "coreGetBySlug": { method: "GET", path: "/p6/core/get-by-slug" },
  "coreGetChannelHealthTrend": { method: "GET", path: "/p6/core/get-channel-health-trend" },
  "coreGetCleanupReport": { method: "GET", path: "/p6/core/get-cleanup-report" },
  "coreGetCleanupReportSummary": { method: "GET", path: "/p6/core/get-cleanup-report-summary" },
  "coreGetCleanupSettings": { method: "GET", path: "/p6/core/get-cleanup-settings" },
  "coreGetCurrentMerkleRoot": { method: "GET", path: "/p6/core/get-current-merkle-root" },
  "coreGetCustomTemplate": { method: "GET", path: "/p6/core/get-custom-template" },
  "coreGetDailyQuotaSummary": { method: "GET", path: "/p6/core/get-daily-quota-summary" },
  "coreGetDailyUsage": { method: "GET", path: "/p6/core/get-daily-usage" },
  "coreGetDecisionScore": { method: "GET", path: "/p6/core/get-decision-score" },
  "coreGetDefaultEmailTemplate": { method: "GET", path: "/p6/core/get-default-email-template" },
  "coreGetDefaultTemplate": { method: "GET", path: "/p6/core/get-default-template" },
  "coreGetDefaultThresholdPolicy": { method: "GET", path: "/p6/core/get-default-threshold-policy" },
  "coreGetDeliveryHistory": { method: "GET", path: "/p6/core/get-delivery-history" },
  "coreGetDetailedVersionDiff": { method: "GET", path: "/p6/core/get-detailed-version-diff" },
  "coreGetExpiryStatus": { method: "GET", path: "/p6/core/get-expiry-status" },
  "coreGetFilterOptions": { method: "GET", path: "/p6/core/get-filter-options" },
  "coreGetFixSuggestion": { method: "GET", path: "/p6/core/get-fix-suggestion" },
  "coreGetIMChannel": { method: "GET", path: "/p6/core/get-i-m-channel" },
  "coreGetIMChannels": { method: "GET", path: "/p6/core/get-i-m-channels" },
  "coreGetIMMessageLogs": { method: "GET", path: "/p6/core/get-i-m-message-logs" },
  "coreGetImportTask": { method: "GET", path: "/p6/core/get-import-task" },
  "coreGetImportTaskItems": { method: "GET", path: "/p6/core/get-import-task-items" },
  "coreGetKey": { method: "GET", path: "/p6/core/get-key" },
  "coreGetKeyAuditLogs": { method: "GET", path: "/p6/core/get-key-audit-logs" },
  "coreGetKeyUsageLogs": { method: "GET", path: "/p6/core/get-key-usage-logs" },
  "coreGetLatestQuotaUsage": { method: "GET", path: "/p6/core/get-latest-quota-usage" },
  "coreGetLatestVersion": { method: "GET", path: "/p6/core/get-latest-version" },
  "coreGetMerkleTaskStatus": { method: "GET", path: "/p6/core/get-merkle-task-status" },
  "coreGetMockDataTemplate": { method: "GET", path: "/p6/core/get-mock-data-template" },
  "coreGetPendingSilencedCount": { method: "GET", path: "/p6/core/get-pending-silenced-count" },
  "coreGetPreset": { method: "GET", path: "/p6/core/get-preset" },
  "coreGetPresets": { method: "GET", path: "/p6/core/get-presets" },
  "coreGetQuietHours": { method: "GET", path: "/p6/core/get-quiet-hours" },
  "coreGetQuietHoursPresets": { method: "GET", path: "/p6/core/get-quiet-hours-presets" },
  "coreGetQuotaAlerts": { method: "GET", path: "/p6/core/get-quota-alerts" },
  "coreGetQuotaHistory": { method: "GET", path: "/p6/core/get-quota-history" },
  "coreGetQuotaUsage": { method: "GET", path: "/p6/core/get-quota-usage" },
  "coreGetReportData": { method: "GET", path: "/p6/core/get-report-data" },
  "coreGetRetryConfig": { method: "GET", path: "/p6/core/get-retry-config" },
  "coreGetRuleTriggerStats": { method: "GET", path: "/p6/core/get-rule-trigger-stats" },
  "coreGetRuleTriggerTrend": { method: "GET", path: "/p6/core/get-rule-trigger-trend" },
  "coreGetRuleVersions": { method: "GET", path: "/p6/core/get-rule-versions" },
  "coreGetRulesTriggerStats": { method: "GET", path: "/p6/core/get-rules-trigger-stats" },
  "coreGetShareLinkAccessLogs": { method: "GET", path: "/p6/core/get-share-link-access-logs" },
  "coreGetShareLinkStats": { method: "GET", path: "/p6/core/get-share-link-stats" },
  "coreGetShareLinkUsage": { method: "GET", path: "/p6/core/get-share-link-usage" },
  "coreGetShareLinks": { method: "GET", path: "/p6/core/get-share-links" },
  "coreGetSilencedNotifications": { method: "GET", path: "/p6/core/get-silenced-notifications" },
  "coreGetStats": { method: "GET", path: "/p6/core/get-stats" },
  "coreGetSummaryHistory": { method: "GET", path: "/p6/core/get-summary-history" },
  "coreGetTaskCalendar": { method: "GET", path: "/p6/core/get-task-calendar" },
  "coreGetTaskStats": { method: "GET", path: "/p6/core/get-task-stats" },
  "coreGetTemplate": { method: "GET", path: "/p6/core/get-template" },
  "coreGetTemplateImportHistory": { method: "GET", path: "/p6/core/get-template-import-history" },
  "coreGetTemplateVariables": { method: "GET", path: "/p6/core/get-template-variables" },
  "coreGetTenantKeyAuditLogs": { method: "GET", path: "/p6/core/get-tenant-key-audit-logs" },
  "coreGetTestHistory": { method: "GET", path: "/p6/core/get-test-history" },
  "coreGetThresholdPolicy": { method: "GET", path: "/p6/core/get-threshold-policy" },
  "coreGetThresholdPresets": { method: "GET", path: "/p6/core/get-threshold-presets" },
  "coreGetTimezones": { method: "GET", path: "/p6/core/get-timezones" },
  "coreGetUsageStats": { method: "GET", path: "/p6/core/get-usage-stats" },
  "coreGetUserRuleSubscriptions": { method: "GET", path: "/p6/core/get-user-rule-subscriptions" },
  "coreGetUserShareLinks": { method: "GET", path: "/p6/core/get-user-share-links" },
  "coreGetVapidKey": { method: "GET", path: "/p6/core/get-vapid-key" },
  "coreGetVaultTenant": { method: "GET", path: "/p6/core/get-vault-tenant" },
  "coreGetVersion": { method: "GET", path: "/p6/core/get-version" },
  "coreGetVersionDetail": { method: "GET", path: "/p6/core/get-version-detail" },
  "coreGetVersionHistory": { method: "GET", path: "/p6/core/get-version-history" },
  "coreGetWeights": { method: "GET", path: "/p6/core/get-weights" },
  "coreGetWeightsHistory": { method: "GET", path: "/p6/core/get-weights-history" },
  "coreHasPassword": { method: "GET", path: "/p6/core/has-password" },
  "coreHotLoadEvents": { method: "GET", path: "/p6/core/hot-load-events" },
  "coreHotLoaderStatus": { method: "GET", path: "/p6/core/hot-loader-status" },
  "coreImChannelHealth": { method: "GET", path: "/p6/core/im-channel-health" },
  "coreImportEventsFromAuditLogs": { method: "POST", path: "/p6/core/import-events-from-audit-logs" },
  "coreImportEventsFromCsv": { method: "POST", path: "/p6/core/import-events-from-csv" },
  "coreImportEventsFromJson": { method: "POST", path: "/p6/core/import-events-from-json" },
  "coreImportFromShareLink": { method: "POST", path: "/p6/core/import-from-share-link" },
  "coreIncrementUsage": { method: "GET", path: "/p6/core/increment-usage" },
  "coreInitBuiltInTemplates": { method: "GET", path: "/p6/core/init-built-in-templates" },
  "coreInitPresetTemplates": { method: "GET", path: "/p6/core/init-preset-templates" },
  "coreInitializePresets": { method: "GET", path: "/p6/core/initialize-presets" },
  "coreKillSwitchApprovalDetail": { method: "GET", path: "/p6/core/kill-switch-approval-detail" },
  "coreLinked": { method: "GET", path: "/p6/core/linked" },
  "coreListAbTests": { method: "GET", path: "/p6/core/list-ab-tests" },
  "coreListAlertHistory": { method: "GET", path: "/p6/core/list-alert-history" },
  "coreListAlertThresholds": { method: "GET", path: "/p6/core/list-alert-thresholds" },
  "coreListAllConfigs": { method: "GET", path: "/p6/core/list-all-configs" },
  "coreListAnalysisReports": { method: "GET", path: "/p6/core/list-analysis-reports" },
  "coreListApiKeys": { method: "GET", path: "/p6/core/list-api-keys" },
  "coreListBatchExports": { method: "GET", path: "/p6/core/list-batch-exports" },
  "coreListBatchTests": { method: "GET", path: "/p6/core/list-batch-tests" },
  "coreListCleanupExecutions": { method: "GET", path: "/p6/core/list-cleanup-executions" },
  "coreListCleanupPolicies": { method: "GET", path: "/p6/core/list-cleanup-policies" },
  "coreListCleanupReports": { method: "GET", path: "/p6/core/list-cleanup-reports" },
  "coreListConfigs": { method: "GET", path: "/p6/core/list-configs" },
  "coreListCustomTemplates": { method: "GET", path: "/p6/core/list-custom-templates" },
  "coreListDeliveryLogs": { method: "GET", path: "/p6/core/list-delivery-logs" },
  "coreListFrozen": { method: "GET", path: "/p6/core/list-frozen" },
  "coreListHistory": { method: "GET", path: "/p6/core/list-history" },
  "coreListImportTasks": { method: "GET", path: "/p6/core/list-import-tasks" },
  "coreListKeys": { method: "GET", path: "/p6/core/list-keys" },
  "coreListQueue": { method: "GET", path: "/p6/core/list-queue" },
  "coreListReportSubscriptions": { method: "GET", path: "/p6/core/list-report-subscriptions" },
  "coreListShareLinks": { method: "GET", path: "/p6/core/list-share-links" },
  "coreListSubscriptions": { method: "GET", path: "/p6/core/list-subscriptions" },
  "coreListTemplates": { method: "GET", path: "/p6/core/list-templates" },
  "coreListTestEvents": { method: "GET", path: "/p6/core/list-test-events" },
  "coreListVersions": { method: "GET", path: "/p6/core/list-versions" },
  "coreLoadActiveDSL": { method: "GET", path: "/p6/core/load-active-d-s-l" },
  "coreLogin": { method: "GET", path: "/p6/core/login" },
  "coreLogout": { method: "GET", path: "/p6/core/logout" },
  "coreManifest": { method: "GET", path: "/p6/core/manifest" },
  "coreManifests": { method: "GET", path: "/p6/core/manifests" },
  "coreManualReEvaluate": { method: "GET", path: "/p6/core/manual-re-evaluate" },
  "coreMe": { method: "GET", path: "/p6/core/me" },
  "coreMyRoleRequests": { method: "GET", path: "/p6/core/my-role-requests" },
  "coreMyShareLinks": { method: "GET", path: "/p6/core/my-share-links" },
  "coreNetworkStats": { method: "GET", path: "/p6/core/network-stats" },
  "coreOverview": { method: "GET", path: "/p6/core/overview" },
  "coreParseVariables": { method: "GET", path: "/p6/core/parse-variables" },
  "corePendingBypassRequests": { method: "GET", path: "/p6/core/pending-bypass-requests" },
  "corePendingDeployments": { method: "GET", path: "/p6/core/pending-deployments" },
  "corePendingKillSwitchApprovals": { method: "GET", path: "/p6/core/pending-kill-switch-approvals" },
  "corePermissionHistory": { method: "GET", path: "/p6/core/permission-history" },
  "corePermissionMatrix": { method: "GET", path: "/p6/core/permission-matrix" },
  "corePermissionPresetTemplate": { method: "GET", path: "/p6/core/permission-preset-template" },
  "corePermissionPresetTemplates": { method: "GET", path: "/p6/core/permission-preset-templates" },
  "corePersistedAdapters": { method: "GET", path: "/p6/core/persisted-adapters" },
  "corePersistenceReady": { method: "GET", path: "/p6/core/persistence-ready" },
  "corePresetDefinitions": { method: "GET", path: "/p6/core/preset-definitions" },
  "corePreviewCleanup": { method: "GET", path: "/p6/core/preview-cleanup" },
  "corePreviewEmailTemplate": { method: "GET", path: "/p6/core/preview-email-template" },
  "corePreviewEval": { method: "GET", path: "/p6/core/preview-eval" },
  "corePreviewPermissionChanges": { method: "GET", path: "/p6/core/preview-permission-changes" },
  "corePreviewPermissionPreset": { method: "GET", path: "/p6/core/preview-permission-preset" },
  "corePreviewReport": { method: "GET", path: "/p6/core/preview-report" },
  "corePreviewSummary": { method: "GET", path: "/p6/core/preview-summary" },
  "corePreviewTemplate": { method: "GET", path: "/p6/core/preview-template" },
  "corePreviewTemplateRendering": { method: "GET", path: "/p6/core/preview-template-rendering" },
  "coreProcessAllSummaries": { method: "POST", path: "/p6/core/process-all-summaries" },
  "coreProcessImportBatch": { method: "POST", path: "/p6/core/process-import-batch" },
  "coreProcessQueue": { method: "POST", path: "/p6/core/process-queue" },
  "coreQuotaPredictions": { method: "GET", path: "/p6/core/quota-predictions" },
  "coreRecalculateScore": { method: "GET", path: "/p6/core/recalculate-score" },
  "coreRecordCodeFix": { method: "POST", path: "/p6/core/record-code-fix" },
  "coreRecordUsage": { method: "POST", path: "/p6/core/record-usage" },
  "coreRegister": { method: "GET", path: "/p6/core/register" },
  "coreRegisterActionRisk": { method: "GET", path: "/p6/core/register-action-risk" },
  "coreRegisterResourceSensitivity": { method: "GET", path: "/p6/core/register-resource-sensitivity" },
  "coreRenderTemplate": { method: "GET", path: "/p6/core/render-template" },
  "coreRequestBypass": { method: "GET", path: "/p6/core/request-bypass" },
  "coreResendSubscriptionConfirmation": { method: "GET", path: "/p6/core/resend-subscription-confirmation" },
  "coreResendVerificationEmail": { method: "GET", path: "/p6/core/resend-verification-email" },
  "coreResetAlertThreshold": { method: "POST", path: "/p6/core/reset-alert-threshold" },
  "coreResetFailureCount": { method: "POST", path: "/p6/core/reset-failure-count" },
  "coreResetPassword": { method: "POST", path: "/p6/core/reset-password" },
  "coreRestoreVersion": { method: "GET", path: "/p6/core/restore-version" },
  "coreRetryFailed": { method: "POST", path: "/p6/core/retry-failed" },
  "coreReview": { method: "GET", path: "/p6/core/review" },
  "coreRevokeKey": { method: "POST", path: "/p6/core/revoke-key" },
  "coreRevokeShareLink": { method: "POST", path: "/p6/core/revoke-share-link" },
  "coreRiskDistribution": { method: "GET", path: "/p6/core/risk-distribution" },
  "coreRoleHistory": { method: "GET", path: "/p6/core/role-history" },
  "coreRoleStats": { method: "GET", path: "/p6/core/role-stats" },
  "coreRollbackPermissionConfig": { method: "POST", path: "/p6/core/rollback-permission-config" },
  "coreRollbackToVersion": { method: "POST", path: "/p6/core/rollback-to-version" },
  "coreRollbackWeights": { method: "POST", path: "/p6/core/rollback-weights" },
  "coreRotateKey": { method: "GET", path: "/p6/core/rotate-key" },
  "coreRunCleanup": { method: "GET", path: "/p6/core/run-cleanup" },
  "coreRunExpiryCheck": { method: "GET", path: "/p6/core/run-expiry-check" },
  "coreSaveActiveDSL": { method: "POST", path: "/p6/core/save-active-d-s-l" },
  "coreSaveAlertThreshold": { method: "POST", path: "/p6/core/save-alert-threshold" },
  "coreSaveVersion": { method: "POST", path: "/p6/core/save-version" },
  "coreScheduleHistoricalMerkleComputation": { method: "GET", path: "/p6/core/schedule-historical-merkle-computation" },
  "coreScheduleMerkleComputation": { method: "GET", path: "/p6/core/schedule-merkle-computation" },
  "coreSendIMMessage": { method: "POST", path: "/p6/core/send-i-m-message" },
  "coreSendTest": { method: "POST", path: "/p6/core/send-test" },
  "coreSetEnabled": { method: "POST", path: "/p6/core/set-enabled" },
  "coreSetPassword": { method: "POST", path: "/p6/core/set-password" },
  "coreSimulateThresholdChange": { method: "GET", path: "/p6/core/simulate-threshold-change" },
  "coreSubmitFeedback": { method: "GET", path: "/p6/core/submit-feedback" },
  "coreSubmitFix": { method: "GET", path: "/p6/core/submit-fix" },
  "coreSubscribe": { method: "GET", path: "/p6/core/subscribe" },
  "coreSufficiencyThresholds": { method: "GET", path: "/p6/core/sufficiency-thresholds" },
  "coreSummary": { method: "GET", path: "/p6/core/summary" },
  "coreTestAllRules": { method: "POST", path: "/p6/core/test-all-rules" },
  "coreTestHistory": { method: "POST", path: "/p6/core/test-history" },
  "coreTimeRanges": { method: "GET", path: "/p6/core/time-ranges" },
  "coreTlsCheckPolicy": { method: "GET", path: "/p6/core/tls-check-policy" },
  "coreTlsHistory": { method: "GET", path: "/p6/core/tls-history" },
  "coreTlsInspect": { method: "GET", path: "/p6/core/tls-inspect" },
  "coreTlsPolicy": { method: "GET", path: "/p6/core/tls-policy" },
  "coreTlsStats": { method: "GET", path: "/p6/core/tls-stats" },
  "coreToggleReportSubscription": { method: "POST", path: "/p6/core/toggle-report-subscription" },
  "coreTopActions": { method: "GET", path: "/p6/core/top-actions" },
  "coreTopPolicies": { method: "GET", path: "/p6/core/top-policies" },
  "coreTriggerAutoAnalysis": { method: "POST", path: "/p6/core/trigger-auto-analysis" },
  "coreTriggerSummary": { method: "POST", path: "/p6/core/trigger-summary" },
  "coreUnlink": { method: "GET", path: "/p6/core/unlink" },
  "coreUnsubscribe": { method: "GET", path: "/p6/core/unsubscribe" },
  "coreUpdateAllQuietHours": { method: "POST", path: "/p6/core/update-all-quiet-hours" },
  "coreUpdateArchive": { method: "POST", path: "/p6/core/update-archive" },
  "coreUpdateCleanupPolicy": { method: "POST", path: "/p6/core/update-cleanup-policy" },
  "coreUpdateCleanupSettings": { method: "POST", path: "/p6/core/update-cleanup-settings" },
  "coreUpdateConfig": { method: "POST", path: "/p6/core/update-config" },
  "coreUpdateCustomTemplate": { method: "POST", path: "/p6/core/update-custom-template" },
  "coreUpdatePermissionMatrix": { method: "POST", path: "/p6/core/update-permission-matrix" },
  "coreUpdatePreferences": { method: "POST", path: "/p6/core/update-preferences" },
  "coreUpdateQuietHours": { method: "POST", path: "/p6/core/update-quiet-hours" },
  "coreUpdateReportSubscription": { method: "POST", path: "/p6/core/update-report-subscription" },
  "coreUpdateRetryConfig": { method: "POST", path: "/p6/core/update-retry-config" },
  "coreUpdateStatus": { method: "POST", path: "/p6/core/update-status" },
  "coreUpdateSubscription": { method: "POST", path: "/p6/core/update-subscription" },
  "coreUpdateTemplate": { method: "POST", path: "/p6/core/update-template" },
  "coreUpdateThresholdPolicy": { method: "POST", path: "/p6/core/update-threshold-policy" },
  "coreUpdateUserRuleSubscription": { method: "POST", path: "/p6/core/update-user-rule-subscription" },
  "coreUsageSnapshots": { method: "GET", path: "/p6/core/usage-snapshots" },
  "coreValidateDSL": { method: "POST", path: "/p6/core/validate-d-s-l" },
  "coreValidateFilters": { method: "POST", path: "/p6/core/validate-filters" },
  "coreValidateImport": { method: "POST", path: "/p6/core/validate-import" },
  "coreValidateShareLink": { method: "POST", path: "/p6/core/validate-share-link" },
  "coreValidateVariables": { method: "POST", path: "/p6/core/validate-variables" },
  "coreVaultTenantUsage": { method: "GET", path: "/p6/core/vault-tenant-usage" },
  "coreVaultTenants": { method: "GET", path: "/p6/core/vault-tenants" },
  "coreVerifyConfig": { method: "GET", path: "/p6/core/verify-config" },
  "coreVerifyDelivery": { method: "GET", path: "/p6/core/verify-delivery" },
  "coreVerifyEmail": { method: "GET", path: "/p6/core/verify-email" },
  "coreVerifyEvidence": { method: "GET", path: "/p6/core/verify-evidence" },
  "coreWebhookHistory": { method: "GET", path: "/p6/core/webhook-history" },
  "coreWebhookStats": { method: "GET", path: "/p6/core/webhook-stats" },
  "createApiKey": { method: "POST", path: "/integration/create-api-key" },
  "createBackup": { method: "POST", path: "/p5/create-backup" },
  "createCanary": { method: "POST", path: "/experiment/create-canary" },
  "createCheckout": { method: "POST", path: "/stripe/create-checkout" },
  "createCheckpoint": { method: "POST", path: "/p5/create-checkpoint" },
  "createConsentRecord": { method: "POST", path: "/p5/create-consent-record" },
  "createContextBundle": { method: "POST", path: "/p1p2/context/bundle" },
  "createCustomPattern": { method: "POST", path: "/open-guard/create-custom-pattern" },
  "createDataAsset": { method: "POST", path: "/p5/create-data-asset" },
  "createDegradation": { method: "GET", path: "/kill-switch/degradation" },
  "createDispute": { method: "POST", path: "/p5/create-dispute" },
  "createExperiment": { method: "POST", path: "/p3/experiments/create" },
  "createFeatureFlag": { method: "POST", path: "/p6/sovr/create-flag" },
  "createFusionRule": { method: "POST", path: "/p3-fusion/automation/create-rule" },
  "createFusionSubscription": { method: "POST", path: "/p5/create-fusion-subscription" },
  "createIncident": { method: "POST", path: "/p5/create-incident" },
  "createIntegrationRule": { method: "POST", path: "/p3/integration/rules" },
  "createLifecycle": { method: "POST", path: "/p5/create-lifecycle" },
  "createMaskingRule": { method: "POST", path: "/p5/create-masking-rule" },
  "createP1P2Bundle": { method: "POST", path: "/p6/p1p2/create-bundle" },
  "createP3IntegrationConfig": { method: "POST", path: "/p5/create-p3-integration-config" },
  "createP3SlackIntegration": { method: "POST", path: "/p5/create-p3-slack-integration" },
  "createP3Task": { method: "POST", path: "/p5/create-p3-task" },
  "createP3Webhook": { method: "POST", path: "/p5/create-p3-webhook" },
  "createP3WebhookRule": { method: "POST", path: "/p5/create-p3-webhook-rule" },
  "createPolicy": { method: "POST", path: "/p3/policy-engine/create" },
  "createPolicyVersion": { method: "POST", path: "/p6/sovr/create-version" },
  "createPolicy_ext": { method: "POST", path: "/p3-fusion/policies/create" },
  "createPromptTemplate": { method: "POST", path: "/p3/model-ops/prompt-templates" },
  "createRegressionSuite": { method: "POST", path: "/p3/audit-regression/suites" },
  "createRegressionSuiteExtended": { method: "POST", path: "/p6/sovr/create-suite" },
  "createReplaySession": { method: "POST", path: "/p3/audit-replay/sessions" },
  "createReplaySessionExtended": { method: "POST", path: "/p6/sovr/create-session" },
  "createReportSchedule": { method: "POST", path: "/p5/create-report-schedule" },
  "createRestore": { method: "POST", path: "/p5/create-restore" },
  "createRiskMitigation": { method: "POST", path: "/p5/create-risk-mitigation" },
  "createRule": { method: "POST", path: "/p6/core/create-rule-from-template" },
  "createSnapshot": { method: "POST", path: "/p3/audit-replay/snapshots" },
  "createStripeAuditorAccount": { method: "POST", path: "/p6/stripe/create-auditor-account" },
  "createStripeDeploymentAddonCheckout": { method: "POST", path: "/p6/stripe/create-deployment-addon-checkout" },
  "createStripeDeploymentSubscription": { method: "POST", path: "/p5/create-stripe-deployment-subscription" },
  "createStripeEnterpriseCheckout": { method: "POST", path: "/p6/stripe/create-enterprise-checkout" },
  "createStripeEnvironmentConfig": { method: "POST", path: "/p5/create-stripe-environment-config" },
  "createStripePortalSession": { method: "POST", path: "/p5/create-stripe-portal-session" },
  "createStripeQuotaPackCheckout": { method: "POST", path: "/p6/stripe/create-quota-pack-checkout" },
  "createStripeQuotaPool": { method: "POST", path: "/p5/create-stripe-quota-pool" },
  "createTask": { method: "POST", path: "/p3/task-queue/create" },
  "createTenant": { method: "POST", path: "/p5/create-tenant" },
  "createTopUpCheckout": { method: "POST", path: "/stripe/create-top-up-checkout" },
  "createWebhook": { method: "POST", path: "/integration/create-webhook" },
  "deactivatePromptTemplate": { method: "POST", path: "/p3/model-ops/prompt-templates/${encodeURIComponent(id)}/deactivate" },
  "deductFromBalance": { method: "POST", path: "/stripe/deduct-from-balance" },
  "deleteCustomPattern": { method: "POST", path: "/open-guard/delete-custom-pattern" },
  "deleteFusionRule": { method: "POST", path: "/p5/delete-rule" },
  "deleteP3Webhook": { method: "POST", path: "/p5/delete-p3-webhook" },
  "deleteP3WebhookRule": { method: "POST", path: "/p5/delete-rule" },
  "deleteReportSchedule": { method: "POST", path: "/p5/delete-report-schedule" },
  "deleteRule": { method: "POST", path: "/p5/delete-rule" },
  "demoAddComment": { method: "POST", path: "/p6/tryDemo/add-comment" },
  "demoAddGroupMember": { method: "POST", path: "/p6/tryDemo/add-group-member" },
  "demoApiKeyUsageTrend": { method: "GET", path: "/p6/tryDemo/api-key-usage-trend" },
  "demoBatchDelete": { method: "POST", path: "/p6/tryDemo/batch-delete" },
  "demoCompareResults": { method: "GET", path: "/p6/tryDemo/compare-results" },
  "demoCreateNotificationGroup": { method: "POST", path: "/p6/tryDemo/create-notification-group" },
  "demoCreateTemplate": { method: "POST", path: "/p6/tryDemo/create-template" },
  "demoDeleteComment": { method: "POST", path: "/p6/tryDemo/delete-comment" },
  "demoDeleteNotificationGroup": { method: "POST", path: "/p6/tryDemo/delete-notification-group" },
  "demoDeletePlaygroundHistory": { method: "POST", path: "/p6/tryDemo/delete-playground-history" },
  "demoDeleteTemplate": { method: "POST", path: "/p6/tryDemo/delete-template" },
  "demoExportHistory": { method: "POST", path: "/p6/tryDemo/export-history" },
  "demoExportPlaygroundJSON": { method: "POST", path: "/p6/tryDemo/export-playground-j-s-o-n" },
  "demoExportPlaygroundPDF": { method: "POST", path: "/p6/tryDemo/export-playground-p-d-f" },
  "demoGetComments": { method: "GET", path: "/p6/tryDemo/get-comments" },
  "demoGetFailurePatternStats": { method: "GET", path: "/p6/tryDemo/get-failure-pattern-stats" },
  "demoGetGroupMembers": { method: "GET", path: "/p6/tryDemo/get-group-members" },
  "demoGetHallucinationTrends": { method: "GET", path: "/p6/tryDemo/get-hallucination-trends" },
  "demoGetMyCheckHistory": { method: "GET", path: "/p6/tryDemo/get-my-check-history" },
  "demoGetMyTemplates": { method: "GET", path: "/p6/tryDemo/get-my-templates" },
  "demoGetNotificationGroups": { method: "GET", path: "/p6/tryDemo/get-notification-groups" },
  "demoGetNotificationPrefs": { method: "GET", path: "/p6/tryDemo/get-notification-prefs" },
  "demoGetPlaygroundHistory": { method: "GET", path: "/p6/tryDemo/get-playground-history" },
  "demoGetSharedResult": { method: "GET", path: "/p6/tryDemo/get-shared-result" },
  "demoGetTemplateStats": { method: "GET", path: "/p6/tryDemo/get-template-stats" },
  "demoGetTemplateVersions": { method: "GET", path: "/p6/tryDemo/get-template-versions" },
  "demoGetTemplates": { method: "GET", path: "/p6/tryDemo/get-templates" },
  "demoListApiKeys": { method: "GET", path: "/p6/tryDemo/list-api-keys" },
  "demoMyHistory": { method: "GET", path: "/p6/tryDemo/my-history" },
  "demoMyStats": { method: "GET", path: "/p6/tryDemo/my-stats" },
  "demoMyTrend": { method: "GET", path: "/p6/tryDemo/my-trend" },
  "demoPlaygroundAnalyze": { method: "GET", path: "/p6/tryDemo/playground-analyze" },
  "demoRemoveGroupMember": { method: "POST", path: "/p6/tryDemo/remove-group-member" },
  "demoRollbackTemplateVersion": { method: "POST", path: "/p6/tryDemo/rollback-template-version" },
  "demoSavePlaygroundHistory": { method: "POST", path: "/p6/tryDemo/save-playground-history" },
  "demoSaveTemplateVersion": { method: "POST", path: "/p6/tryDemo/save-template-version" },
  "demoTeamHistory": { method: "GET", path: "/p6/tryDemo/team-history" },
  "demoTeamStats": { method: "GET", path: "/p6/tryDemo/team-stats" },
  "demoToggleTemplateInteraction": { method: "POST", path: "/p6/tryDemo/toggle-template-interaction" },
  "demoUpdateNotificationGroup": { method: "POST", path: "/p6/tryDemo/update-notification-group" },
  "demoUpdateNotificationPrefs": { method: "POST", path: "/p6/tryDemo/update-notification-prefs" },
  "demoUpdateTemplate": { method: "POST", path: "/p6/tryDemo/update-template" },
  "demoUpdateVisibility": { method: "POST", path: "/p6/tryDemo/update-visibility" },
  "deprecatePolicy": { method: "POST", path: "/p5/deprecate-policy" },
  "detectAdversarial": { method: "POST", path: "/p5/detect-adversarial" },
  "detectAdversarial_ext": { method: "POST", path: "/p5/detect-adversarial" },
  "detectConflict": { method: "POST", path: "/p5/detect-conflict" },
  "detectConflicts": { method: "GET", path: "/p3/policy-engine/conflicts" },
  "detectHallucination": { method: "POST", path: "/p5/detect-hallucination" },
  "detectPII": { method: "POST", path: "/p5/detect-pii" },
  "detectPII_ext": { method: "POST", path: "/p5/detect-pii" },
  "detectPolicyConflicts": { method: "POST", path: "/p5/detect-policy-conflicts" },
  "detectRisks": { method: "POST", path: "/p5/detect-risks" },
  "detectRisks_ext": { method: "POST", path: "/p5/detect-risks" },
  "dispatchP3Notification": { method: "POST", path: "/p5/dispatch-p3-notification" },
  "enableLifecycle": { method: "POST", path: "/p5/enable-lifecycle" },
  "enterpriseQuoteGetById": { method: "GET", path: "/p6/enterpriseQuote/get-by-id" },
  "enterpriseQuoteGetScenarios": { method: "GET", path: "/p6/enterpriseQuote/get-scenarios" },
  "enterpriseQuoteGetStaleQuotes": { method: "GET", path: "/p6/enterpriseQuote/get-stale-quotes" },
  "enterpriseQuoteGetStats": { method: "GET", path: "/p6/enterpriseQuote/get-stats" },
  "enterpriseQuoteGetTiers": { method: "GET", path: "/p6/enterpriseQuote/get-tiers" },
  "enterpriseQuoteMarkEmailSent": { method: "GET", path: "/p6/enterpriseQuote/mark-email-sent" },
  "enterpriseQuoteSendFollowUpReminder": { method: "POST", path: "/p6/enterpriseQuote/send-follow-up-reminder" },
  "enterpriseQuoteUpdateDetails": { method: "POST", path: "/p6/enterpriseQuote/update-details" },
  "enterpriseQuoteUpdateStatus": { method: "POST", path: "/p6/enterpriseQuote/update-status" },
  "epistemicCheck": { method: "POST", path: "/rbac/check" },
  "evaluateMetaSupervision": { method: "GET", path: "/p1p2/meta-supervision/evaluate" },
  "evaluateMetric": { method: "POST", path: "/p5/evaluate-metric" },
  "evaluatePolicy": { method: "POST", path: "/p3/policy-engine/evaluate" },
  "evaluatePolicy_ext": { method: "POST", path: "/p3-fusion/policies/evaluate" },
  "executeP3Task": { method: "POST", path: "/p5/execute-p3-task" },
  "executeQualityCheck": { method: "POST", path: "/p5/execute-quality-check" },
  "executeReport": { method: "POST", path: "/p5/execute-report" },
  "executeRollback": { method: "POST", path: "/p5/execute-rollback" },
  "exportAuditReport": { method: "POST", path: "/audit/export" },
  "exportBundle": { method: "POST", path: "/export-bundle" },
  "exportMeteringCSV": { method: "POST", path: "/p6/rule/export-csv" },
  "exportRulesCsv": { method: "GET", path: "/p5/export-rules-csv" },
  "exportTrustScoreHistory": { method: "GET", path: "/verification/export-trust-score-history${format ? " },
  "externalApiAuditLogs": { method: "GET", path: "/p6/externalApi/audit-logs" },
  "externalGateAddPolicy": { method: "POST", path: "/p6/externalGate/add-policy" },
  "externalGateAuditLogs": { method: "GET", path: "/p6/externalGate/audit-logs" },
  "externalGateBatchUpdatePolicies": { method: "POST", path: "/p6/externalGate/batch-update-policies" },
  "externalGateDecisions": { method: "GET", path: "/p6/externalGate/decisions" },
  "externalGateRemovePolicy": { method: "POST", path: "/p6/externalGate/remove-policy" },
  "externalGateResetPolicies": { method: "POST", path: "/p6/externalGate/reset-policies" },
  "externalGateTestDualGate": { method: "POST", path: "/p6/externalGate/test-dual-gate" },
  "externalGateTestGateCheck": { method: "POST", path: "/p6/externalGate/test-gate-check" },
  "externalGateUpdatePolicy": { method: "POST", path: "/p6/externalGate/update-policy" },
  "failTask": { method: "POST", path: "/p3/task-queue/fail" },
  "filterItems": { method: "POST", path: "/p5/filter-items" },
  "filterNarrative": { method: "POST", path: "/p1p2/narrative/filter" },
  "findPrecedents": { method: "POST", path: "/p5/find-precedents" },
  "formatStripePrice": { method: "GET", path: "/p6/stripe/format-price" },
  "freezeBalance": { method: "POST", path: "/stripe/freeze-balance" },
  "gateCheck": { method: "POST", path: "/p6/externalGate/test-gate-check" },
  "gdprCheckComplianceStatus": { method: "GET", path: "/p6/gdpr/check-compliance-status" },
  "gdprCreateDSRRequest": { method: "POST", path: "/p6/gdpr/create-d-s-r-request" },
  "gdprGetDSRRequest": { method: "GET", path: "/p6/gdpr/get-d-s-r-request" },
  "gdprGetDSRRequestsByUser": { method: "GET", path: "/p6/gdpr/get-d-s-r-requests-by-user" },
  "gdprGetPendingDSRRequests": { method: "GET", path: "/p6/gdpr/get-pending-d-s-r-requests" },
  "gdprGetUserConsents": { method: "GET", path: "/p6/gdpr/get-user-consents" },
  "gdprRecordConsent": { method: "POST", path: "/p6/gdpr/record-consent" },
  "gdprUpdateDSRStatus": { method: "POST", path: "/p6/gdpr/update-d-s-r-status" },
  "gdprVerifyIdentity": { method: "GET", path: "/p6/gdpr/verify-identity" },
  "gdprWithdrawConsent": { method: "GET", path: "/p6/gdpr/withdraw-consent" },
  "generateCertificate": { method: "POST", path: "/p5/generate-certificate" },
  "generateComplianceReport": { method: "POST", path: "/p5/generate-compliance-report" },
  "generateComplianceReport_ext": { method: "GET", path: "/p6/p3Fusion/generate-report" },
  "generateDiffReport": { method: "POST", path: "/p5/generate-diff-report" },
  "getActionTypeTrend": { method: "GET", path: "/metering/action-type-trend?${params}" },
  "getActiveAlerts": { method: "GET", path: "/monitoring/active-alerts" },
  "getActivePolicyVersion": { method: "GET", path: "/metering/active-policy-version" },
  "getAdjacentDiffs": { method: "GET", path: "/verification/adjacent-diffs/${id}" },
  "getAlertRules": { method: "GET", path: "/monitoring/alert-rules" },
  "getAlerts": { method: "GET", path: "/monitoring/alerts" },
  "getAllModelHealthStatus": { method: "GET", path: "/health" },
  "getAllPermissions": { method: "GET", path: "/rbac/all-permissions" },
  "getApiKeyUsageStats": { method: "GET", path: "/integration/api-key-usage-stats?key_id=${keyId}" },
  "getApprovalDetail": { method: "GET", path: "/approval/detail?id=${approvalId}" },
  "getApprovalStats": { method: "GET", path: "/approval/stats" },
  "getAuditChain": { method: "GET", path: "/audit/chain" },
  "getAuditDetail": { method: "GET", path: "/audit/detail?id=${auditId}" },
  "getAuditStats": { method: "GET", path: "/approval/stats" },
  "getAuditTrail": { method: "GET", path: "/audit/trail${qs ? " },
  "getBalance": { method: "GET", path: "/stripe/get-balance" },
  "getBalanceStats": { method: "GET", path: "/stripe/get-balance-stats" },
  "getBalanceTransactions": { method: "GET", path: "/stripe/get-balance-transactions" },
  "getBudgetAlerts": { method: "GET", path: "/budget/alerts" },
  "getBudgetFullStatus": { method: "GET", path: "/status" },
  "getBudgetHistory": { method: "GET", path: "/budget/history${qs ? " },
  "getBudgetStatus": { method: "GET", path: "/p5/get-budget-status" },
  "getBudgetStatus_ext": { method: "GET", path: "/p5/get-budget-status" },
  "getChatModels": { method: "GET", path: "/p5/get-chat-models" },
  "getCheckpoint": { method: "GET", path: "/verification/checkpoint/${id}" },
  "getCircuitBreakerEvents": { method: "GET", path: "/p3/model-ops/circuit-breaker${qs ? " },
  "getComplianceControl": { method: "GET", path: "/p3-fusion/compliance/controls/${id}" },
  "getComplianceDashboard": { method: "GET", path: "/p3-fusion/compliance/dashboard" },
  "getComplianceReport": { method: "GET", path: "/p3-fusion/compliance/reports/${id}" },
  "getConstraintTrend": { method: "GET", path: "/p1p2/constraint-trend${days ? " },
  "getContentPatterns": { method: "POST", path: "/openguard/patterns" },
  "getContextBundle": { method: "GET", path: "/p1p2/context/bundle/${bundleId}" },
  "getCostStatus": { method: "GET", path: "/p5/get-cost-status" },
  "getCustomPattern": { method: "GET", path: "/open-guard/get-custom-pattern?id=${patternId}" },
  "getDangerousTools": { method: "GET", path: "/p5/get-dangerous-tools" },
  "getDataAsset": { method: "GET", path: "/p3-fusion/assets/${id}" },
  "getDataLineage": { method: "GET", path: "/p3-fusion/assets/${assetId}/lineage" },
  "getDeadLetterQueue": { method: "GET", path: "/p3/task-queue/dead-letter${qs}" },
  "getDeadLetterQueueItems": { method: "GET", path: "/task-queue/dead-letter-queue${limit ? " },
  "getDegradationState": { method: "GET", path: "/kill-switch/degradation-state" },
  "getDispute": { method: "GET", path: "/p0/disputes/${id}" },
  "getEntitySnapshots": { method: "GET", path: "/p3/audit-replay/snapshots/${encodeURIComponent(entityType)}/${encodeURIComponent(entityId)}${qs}" },
  "getFailureBudget": { method: "GET", path: "/p1p2/failure/budget" },
  "getFusionAutomationDashboard": { method: "GET", path: "/p3-fusion/automation/dashboard" },
  "getFusionSeedStatus": { method: "GET", path: "/status" },
  "getFusionSubscription": { method: "GET", path: "/p3-fusion/subscriptions/${id}" },
  "getFusionSubscriptionStats": { method: "GET", path: "/approval/stats" },
  "getGateConfig": { method: "GET", path: "/gate/config" },
  "getGeoStats": { method: "GET", path: "/openguard/geo-stats" },
  "getHighRiskActions": { method: "GET", path: "/gate/high-risk-actions" },
  "getKillSwitchFullStatus": { method: "GET", path: "/status" },
  "getKillSwitchStatus": { method: "GET", path: "/status" },
  "getKnownActions": { method: "GET", path: "/default-deny/known-actions" },
  "getLatestRegressionRuns": { method: "GET", path: "/p3/audit-regression/runs/latest${qs}" },
  "getLatestRegressionRunsExtended": { method: "GET", path: "/audit-regression/get-latest-runs${limit ? " },
  "getLatestSafeCheckpoint": { method: "GET", path: "/p5/get-latest-safe-checkpoint" },
  "getLatestTrustScore": { method: "GET", path: "/p3-fusion/trust-score/latest?subject=${subject}" },
  "getMaintenanceMode": { method: "GET", path: "/p5/get-maintenance-mode" },
  "getMeteringDailyStats": { method: "GET", path: "/metering/daily-stats${date ? " },
  "getMeteringQuotaStatus": { method: "GET", path: "/metering/quota-status" },
  "getMeteringSubscription": { method: "GET", path: "/metering/subscription" },
  "getMeteringUsageStats": { method: "GET", path: "/metering/usage-stats${period ? " },
  "getMetricHistory": { method: "GET", path: "/monitoring/metric-history" },
  "getMetrics": { method: "GET", path: "/monitoring/metrics?${params.toString()}" },
  "getModelUsageStats": { method: "GET", path: "/p3/model-ops/usage-stats${qs ? " },
  "getNotificationHistory": { method: "GET", path: "/verification/notification-history${limit ? " },
  "getOpenGuardScanStats": { method: "GET", path: "/open-guard/scan-stats${tenantId ? " },
  "getOpenGuardStats": { method: "GET", path: "/approval/stats" },
  "getP0Plan": { method: "GET", path: "/p0/plan" },
  "getP0Values": { method: "GET", path: "/p0/values" },
  "getP1P2Bundle": { method: "GET", path: "/p1p2/bundle/${id}" },
  "getP1P2Dashboard": { method: "GET", path: "/p1p2/dashboard?${qs}" },
  "getP1P2Stats": { method: "GET", path: "/approval/stats" },
  "getP3Dashboard": { method: "GET", path: "/p3/dashboard" },
  "getP3DeliveryLogs": { method: "GET", path: "/p3/webhooks/delivery-logs?${qs}" },
  "getP3Stats": { method: "GET", path: "/approval/stats" },
  "getP3Task": { method: "GET", path: "/p3/tasks/${id}" },
  "getP3TaskDashboard": { method: "GET", path: "/p3/tasks/dashboard" },
  "getP3TaskStats": { method: "GET", path: "/approval/stats" },
  "getP3TaskSteps": { method: "GET", path: "/p3/tasks/${id}/steps" },
  "getP3Webhook": { method: "POST", path: "/integration/webhooks" },
  "getP3WebhookRule": { method: "GET", path: "/p3/webhooks/rule/${id}" },
  "getPendingSuggestions": { method: "GET", path: "/p5/get-pending-suggestions" },
  "getPermit": { method: "GET", path: "/permit" },
  "getPolicy": { method: "GET", path: "/p3-fusion/policies/${id}" },
  "getPolicyDashboard": { method: "GET", path: "/p3-fusion/policies/dashboard" },
  "getPolicyVersion": { method: "GET", path: "/policy/version" },
  "getPrivacyDashboard": { method: "GET", path: "/p3-fusion/privacy/dashboard" },
  "getPromptTemplate": { method: "GET", path: "/p3/model-ops/prompt-templates/${encodeURIComponent(name)}${qs}" },
  "getQualityDashboard": { method: "GET", path: "/p3-fusion/quality/dashboard" },
  "getRealTrustScoreTrend": { method: "GET", path: "/verification/real-trust-score-trend${days ? " },
  "getRegressionRunsBySuite": { method: "GET", path: "/p3/audit-regression/suites/${encodeURIComponent(suiteId)}/runs${qs}" },
  "getRegressionRunsBySuiteExtended": { method: "GET", path: "/p6/sovr/get-runs-by-suite" },
  "getRegressionSuite": { method: "GET", path: "/p3/audit-regression/suites/${encodeURIComponent(suiteId)}" },
  "getRegressionSuiteById": { method: "GET", path: "/p6/sovr/get-suite" },
  "getReportSchedule": { method: "GET", path: "/p3-fusion/scheduler/schedules/${id}" },
  "getRiskDashboard": { method: "GET", path: "/p3-fusion/risk/dashboard" },
  "getRiskDefinition": { method: "GET", path: "/p3-fusion/risk/definitions/${id}" },
  "getRolePermissions": { method: "GET", path: "/rbac/role-permissions?role=${role}" },
  "getRollbackHistory": { method: "GET", path: "/verification/rollback-history${limit ? " },
  "getRollbackPolicy": { method: "GET", path: "/p5/get-rollback-policy" },
  "getRoutingDecisionLog": { method: "GET", path: "/p3/model-ops/routing-log${qs}" },
  "getRuleAuditLog": { method: "GET", path: "/rules/${ruleId}/audit-log" },
  "getRuleStats": { method: "GET", path: "/p5/get-rule-stats" },
  "getRuleVersionHistory": { method: "GET", path: "/rules/${ruleId}/version-history" },
  "getSLAMetrics": { method: "GET", path: "/p5/get-sla-metrics" },
  "getScanLogs": { method: "GET", path: "/openguard/scan-logs" },
  "getScanStats": { method: "GET", path: "/openguard/scan-stats" },
  "getSchedulerDashboard": { method: "GET", path: "/p3-fusion/scheduler/dashboard" },
  "getSemanticModels": { method: "GET", path: "/openguard/semantic-models" },
  "getSlaMetrics": { method: "GET", path: "/p5/get-sla-metrics" },
  "getStatus": { method: "GET", path: "/status" },
  "getStripeAuditorAccount": { method: "GET", path: "/stripe/auditor-accounts/${id}" },
  "getStripeAuditorAccountPricing": { method: "GET", path: "/stripe/auditor-account-pricing" },
  "getStripeAuditorAccountStats": { method: "GET", path: "/stripe/auditor-account-stats" },
  "getStripeBillingEventWeights": { method: "GET", path: "/p5/get-stripe-billing-event-weights" },
  "getStripeBillingStats": { method: "GET", path: "/p5/get-stripe-billing-stats" },
  "getStripeBonusQuota": { method: "GET", path: "/p5/get-stripe-bonus-quota" },
  "getStripeDailyStats": { method: "GET", path: "/p5/get-stripe-daily-stats" },
  "getStripeDegradeConfig": { method: "GET", path: "/p5/get-stripe-degrade-config" },
  "getStripeDeploymentAddon": { method: "GET", path: "/p5/get-stripe-deployment-addon-catalog" },
  "getStripeDeploymentAddonCatalog": { method: "GET", path: "/p5/get-stripe-deployment-addon-catalog" },
  "getStripeEndpointStats": { method: "GET", path: "/p5/get-stripe-endpoint-stats" },
  "getStripeEnterprisePricingConfig": { method: "GET", path: "/p5/get-stripe-enterprise-pricing-config" },
  "getStripeEnvBillingPolicies": { method: "GET", path: "/stripe/env-billing-policies" },
  "getStripeEnvironmentStats": { method: "GET", path: "/stripe/environment-stats" },
  "getStripeJoinedQuotaPools": { method: "GET", path: "/p5/get-stripe-joined-quota-pools" },
  "getStripeOveragePricing": { method: "GET", path: "/p5/get-stripe-overage-pricing" },
  "getStripeOverageStats": { method: "GET", path: "/p5/get-stripe-overage-stats" },
  "getStripeOwnedQuotaPools": { method: "GET", path: "/p5/get-stripe-owned-quota-pools" },
  "getStripePaymentDetail": { method: "GET", path: "/stripe/payments/${id}" },
  "getStripePayments": { method: "GET", path: "/stripe/payments?${qs}" },
  "getStripePlanLimits": { method: "GET", path: "/p5/get-stripe-plan-limits" },
  "getStripeProducts": { method: "GET", path: "/p5/get-stripe-products" },
  "getStripeQuotaPacks": { method: "GET", path: "/p5/get-stripe-quota-packs" },
  "getStripeQuotaPool": { method: "GET", path: "/stripe/quota-pool/${id}" },
  "getStripeQuotaPoolMembers": { method: "GET", path: "/stripe/quota-pool/${poolId}/members" },
  "getStripeQuotaPrediction": { method: "GET", path: "/p5/get-stripe-quota-prediction" },
  "getStripeSubscription": { method: "GET", path: "/p5/get-stripe-subscription" },
  "getStripeTrustBundleBalance": { method: "GET", path: "/p5/get-stripe-trust-bundle-balance" },
  "getStripeTrustBundlePricing": { method: "GET", path: "/stripe/trust-bundle-pricing" },
  "getStripeTrustBundleProducts": { method: "GET", path: "/p5/get-stripe-trust-bundle-products" },
  "getStripeUsageHistory": { method: "GET", path: "/stripe/usage-history${params?.days ? " },
  "getStripeUsageStats": { method: "GET", path: "/p5/get-stripe-usage-stats" },
  "getStripeUsageTrend": { method: "GET", path: "/stripe/usage-trend${days ? " },
  "getSubscriptionStats": { method: "GET", path: "/approval/stats" },
  "getSystemHealth": { method: "GET", path: "/health" },
  "getSystemTrustStatus": { method: "GET", path: "/p5/get-system-trust-status" },
  "getTaskById": { method: "GET", path: "/p3/task-queue/${encodeURIComponent(taskId)}" },
  "getTaskQueueById": { method: "GET", path: "/p6/sovr/get-by-id" },
  "getTaskQueueFullStats": { method: "GET", path: "/task-queue/stats" },
  "getTaskQueueStats": { method: "GET", path: "/approval/stats" },
  "getTenant": { method: "GET", path: "/p6/core/get-tenant-key-audit-logs" },
  "getTenantDashboard": { method: "GET", path: "/p3-fusion/tenants/dashboard${tenantId ? " },
  "getTenantQuotas": { method: "GET", path: "/p3-fusion/tenants/${tenantId}/quotas" },
  "getTodayCost": { method: "GET", path: "/p5/get-today-cost" },
  "getTopActionTypes": { method: "GET", path: "/metering/top-action-types${limit ? " },
  "getTopUpAmounts": { method: "GET", path: "/stripe/get-top-up-amounts" },
  "getTrustScoreDashboard": { method: "GET", path: "/p3-fusion/trust-score/dashboard" },
  "getTrustScoreHistory": { method: "POST", path: "/p3/scoring/history" },
  "getTrustScoreHistory_ext": { method: "GET", path: "/p3-fusion/trust-score/history?${qs}" },
  "getTrustScoreModel": { method: "GET", path: "/p3-fusion/trust-score/models/${id}" },
  "getTrustScoreTrend": { method: "GET", path: "/verification/trust-score-trend${days ? " },
  "getVerificationApiStats": { method: "GET", path: "/p5/get-verification-api-stats" },
  "getVerificationApiTimeSeries": { method: "GET", path: "/verification/api-time-series${days ? " },
  "getVerificationDailyStats": { method: "GET", path: "/p5/get-verification-daily-stats" },
  "getVerificationHourlyHeatmap": { method: "GET", path: "/p5/get-verification-hourly-heatmap" },
  "getVerificationTopEndpoints": { method: "GET", path: "/p5/get-verification-top-endpoints" },
  "getVerificationWebhookConfig": { method: "GET", path: "/p5/get-verification-webhook-config" },
  "grantPermit": { method: "POST", path: "/grant-permit" },
  "healthCheck": { method: "GET", path: "/health" },
  "identifyStripeEnvironment": { method: "GET", path: "/p6/stripe/identify-environment" },
  "importRulesCsv": { method: "POST", path: "/p5/import-rules-csv" },
  "isFeatureEnabled": { method: "POST", path: "/experiment/is-feature-enabled" },
  "isOperationAllowed": { method: "POST", path: "/default-deny/is-operation-allowed" },
  "jobGetStaleQuotes": { method: "GET", path: "/p6/job/get-stale-quotes" },
  "jobRunStaleQuoteReminder": { method: "GET", path: "/p6/job/run-stale-quote-reminder" },
  "jobTriggerStaleQuoteReminderByKey": { method: "POST", path: "/p6/job/trigger-stale-quote-reminder-by-key" },
  "listActiveABTests": { method: "GET", path: "/p3/model-ops/ab-tests${qs}" },
  "listBackups": { method: "GET", path: "/p5/list-backups" },
  "listCheckpoints": { method: "GET", path: "/verification/list-checkpoints${limit ? " },
  "listComplianceControls": { method: "GET", path: "/p5/list-compliance-controls" },
  "listComplianceGaps": { method: "GET", path: "/p5/list-compliance-gaps" },
  "listComplianceReports": { method: "GET", path: "/p5/list-compliance-reports" },
  "listConsentRecords": { method: "GET", path: "/p3-fusion/privacy/consent-records?${qs}" },
  "listCustomPatterns": { method: "GET", path: "/open-guard/custom-patterns?${params}" },
  "listDataAssets": { method: "GET", path: "/p3/data-governance/assets" },
  "listDataAssets_ext": { method: "GET", path: "/integration/list" },
  "listDegradations": { method: "GET", path: "/integration/list" },
  "listDisputes": { method: "GET", path: "/integration/list" },
  "listExperiments": { method: "GET", path: "/integration/list" },
  "listFusionEvents": { method: "GET", path: "/p3-fusion/automation/events?${qs}" },
  "listFusionRules": { method: "GET", path: "/p3-fusion/automation/rules" },
  "listIncidents": { method: "GET", path: "/p3/risk/incidents" },
  "listIncidents_ext": { method: "GET", path: "/p0/list-incidents?${qs}" },
  "listIntegrationRules": { method: "GET", path: "/p3/integration/rules" },
  "listIntegrations": { method: "GET", path: "/integration/integrations" },
  "listLifecycles": { method: "GET", path: "/integration/list" },
  "listMaskingRules": { method: "GET", path: "/p5/list-masking-rules" },
  "listModels": { method: "GET", path: "/p3/model-ops/models" },
  "listNarrativeRules": { method: "GET", path: "/p1p2/narrative/rules" },
  "listP0Alerts": { method: "GET", path: "/p5/list-p0-alerts" },
  "listP3Alerts": { method: "GET", path: "/p5/list-p3-alerts" },
  "listP3IntegrationConfigs": { method: "GET", path: "/p5/list-p3-integration-configs" },
  "listP3SlackIntegrations": { method: "GET", path: "/p5/list-p3-slack-integrations" },
  "listP3Tasks": { method: "GET", path: "/integration/list" },
  "listP3WebhookRules": { method: "GET", path: "/p5/list-p3-webhook-rules" },
  "listP3Webhooks": { method: "GET", path: "/integration/list" },
  "listPIAs": { method: "GET", path: "/p5/list-pi-as" },
  "listPIAs_ext": { method: "GET", path: "/p5/list-pi-as" },
  "listPendingApprovals": { method: "GET", path: "/approval/pending" },
  "listPendingArbitrations": { method: "GET", path: "/p5/list-pending-arbitrations" },
  "listPolicies": { method: "GET", path: "/integration/list" },
  "listPolicies_ext": { method: "GET", path: "/integration/list" },
  "listPolicyConflicts": { method: "GET", path: "/p5/list-policy-conflicts" },
  "listPolicyVersions": { method: "GET", path: "/policy/:policyId/versions" },
  "listPromptTemplates": { method: "GET", path: "/p3/model-ops/prompt-templates" },
  "listQualityRules": { method: "GET", path: "/p5/list-quality-rules" },
  "listRegressionSuites": { method: "GET", path: "/p3/audit-regression/suites" },
  "listRegressionSuitesExtended": { method: "GET", path: "/p6/sovr/list-suites" },
  "listReplaySessions": { method: "GET", path: "/p3/audit-replay/sessions" },
  "listReplaySessionsExtended": { method: "GET", path: "/p6/sovr/list-sessions" },
  "listReportExecutions": { method: "GET", path: "/p3-fusion/scheduler/executions?${qs}" },
  "listReportSchedules": { method: "GET", path: "/p5/list-report-schedules" },
  "listRiskAssessments": { method: "GET", path: "/p3-fusion/risk/assessments?${qs}" },
  "listRiskDefinitions": { method: "GET", path: "/p5/list-risk-definitions" },
  "listRiskIncidents": { method: "GET", path: "/p3-fusion/risk/incidents?${qs}" },
  "listRiskMitigations": { method: "GET", path: "/p3-fusion/risk/mitigations${riskId ? " },
  "listRules": { method: "GET", path: "/integration/list" },
  "listStripeAuditorAccounts": { method: "GET", path: "/p5/list-stripe-auditor-accounts" },
  "listStripeDeploymentAddons": { method: "GET", path: "/p5/list-stripe-deployment-addons" },
  "listStripeEnvironmentConfigs": { method: "GET", path: "/p5/list-stripe-environment-configs" },
  "listStripeUserDeploymentSubscriptions": { method: "GET", path: "/p5/list-stripe-user-deployment-subscriptions" },
  "listTasksByStatus": { method: "GET", path: "/p3/task-queue/list${qs ? " },
  "listTasksByStatusExtended": { method: "GET", path: "/p6/sovr/list-by-status" },
  "listTenantBillings": { method: "GET", path: "/p3-fusion/tenants/${tenantId}/billings" },
  "listTenantMembers": { method: "GET", path: "/p3-fusion/tenants/${tenantId}/members" },
  "listTenants": { method: "GET", path: "/p5/list-tenants" },
  "listThreatIndicators": { method: "GET", path: "/p5/list-threat-indicators" },
  "listTrustScoreModels": { method: "GET", path: "/p5/list-trust-score-models" },
  "liveChatGetSessionHistory": { method: "GET", path: "/p6/liveChat/get-session-history" },
  "liveChatGetStats": { method: "GET", path: "/p6/liveChat/get-stats" },
  "liveChatListSessions": { method: "GET", path: "/p6/liveChat/list-sessions" },
  "liveChatSendMessage": { method: "POST", path: "/p6/liveChat/send-message" },
  "loadIndex": { method: "POST", path: "/p5/load-index" },
  "logCanaryDecision": { method: "POST", path: "/p1p2/canary/log" },
  "logDecision": { method: "POST", path: "/p5/log-decision" },
  "manualTransition": { method: "POST", path: "/p5/manual-transition" },
  "manualTriggerFusion": { method: "POST", path: "/p5/manual-trigger-fusion" },
  "manusIntegrationCheckApprovalStatus": { method: "GET", path: "/p6/manusIntegration/check-approval-status" },
  "manusIntegrationGetIntegrationGuide": { method: "GET", path: "/p6/manusIntegration/get-integration-guide" },
  "manusIntegrationGetIntegrationStatus": { method: "GET", path: "/p6/manusIntegration/get-integration-status" },
  "manusIntegrationPreExecuteVerify": { method: "GET", path: "/p6/manusIntegration/pre-execute-verify" },
  "manusIntegrationReportExecutionResult": { method: "GET", path: "/p6/manusIntegration/report-execution-result" },
  "manusIntegrationRequestRollback": { method: "GET", path: "/p6/manusIntegration/request-rollback" },
  "marketingAddPublishHistory": { method: "POST", path: "/p6/marketing/add-publish-history" },
  "marketingCancelScheduledPost": { method: "POST", path: "/p6/marketing/cancel-scheduled-post" },
  "marketingCreateScheduledPost": { method: "POST", path: "/p6/marketing/create-scheduled-post" },
  "marketingGetActiveLogos": { method: "GET", path: "/p6/marketing/get-active-logos" },
  "marketingGetCalendarData": { method: "GET", path: "/p6/marketing/get-calendar-data" },
  "marketingGetEvents": { method: "GET", path: "/p6/marketing/get-events" },
  "marketingGetExperimentResults": { method: "GET", path: "/p6/marketing/get-experiment-results" },
  "marketingGetPlatformStats": { method: "GET", path: "/p6/marketing/get-platform-stats" },
  "marketingGetPlatformStatus": { method: "GET", path: "/p6/marketing/get-platform-status" },
  "marketingGetPublishHistory": { method: "GET", path: "/p6/marketing/get-publish-history" },
  "marketingGetScheduledPosts": { method: "GET", path: "/p6/marketing/get-scheduled-posts" },
  "marketingGetStats": { method: "GET", path: "/p6/marketing/get-stats" },
  "marketingPostToAll": { method: "POST", path: "/p6/marketing/post-to-all" },
  "marketingPostToLinkedIn": { method: "POST", path: "/p6/marketing/post-to-linked-in" },
  "marketingPostToTwitter": { method: "POST", path: "/p6/marketing/post-to-twitter" },
  "marketingReorder": { method: "GET", path: "/p6/marketing/reorder" },
  "marketingTrack": { method: "GET", path: "/p6/marketing/track" },
  "marketingUpdateEngagement": { method: "POST", path: "/p6/marketing/update-engagement" },
  "marketingUpdateScheduledPost": { method: "POST", path: "/p6/marketing/update-scheduled-post" },
  "maskData": { method: "POST", path: "/p5/mask-data" },
  "maskData_ext": { method: "POST", path: "/p5/mask-data" },
  "mcpInstanceRemove": { method: "POST", path: "/p6/mcpInstance/remove" },
  "mcpInstanceRestart": { method: "GET", path: "/p6/mcpInstance/restart" },
  "mcpInstanceRevive": { method: "GET", path: "/p6/mcpInstance/revive" },
  "mcpInstanceScanAndRestart": { method: "GET", path: "/p6/mcpInstance/scan-and-restart" },
  "mcpInstanceToggleAutoRestart": { method: "POST", path: "/p6/mcpInstance/toggle-auto-restart" },
  "mcpStatsGetOverview": { method: "GET", path: "/p6/mcpStats/get-overview" },
  "mcpStatsGetRecentLogs": { method: "GET", path: "/p6/mcpStats/get-recent-logs" },
  "mcpStatsGetTrend": { method: "GET", path: "/p6/mcpStats/get-trend" },
  "mcpStatsLogUsage": { method: "GET", path: "/p6/mcpStats/log-usage" },
  "p0Check": { method: "POST", path: "/p5/p0-check" },
  "p0Get": { method: "GET", path: "/p6/p0/get" },
  "p0GetConfig": { method: "GET", path: "/p6/p0/get-config" },
  "p0GetPlan": { method: "GET", path: "/p6/p0/get-plan" },
  "p0GetValues": { method: "GET", path: "/p6/p0/get-values" },
  "p0HealthCheck": { method: "GET", path: "/p0/health-check" },
  "p0ListAlerts": { method: "GET", path: "/p6/p0/list-alerts" },
  "p0UpdateStatus": { method: "POST", path: "/p6/p0/update-status" },
  "p1p2Check": { method: "POST", path: "/p5/p1p2-check" },
  "p1p2ClearCache": { method: "POST", path: "/p6/p1p2/clear-cache" },
  "p1p2CreateBundle": { method: "POST", path: "/p6/p1p2/create-bundle" },
  "p1p2GetBundle": { method: "GET", path: "/p6/p1p2/get-bundle" },
  "p1p2Search": { method: "POST", path: "/p5/p1p2-search" },
  "p1p2Write": { method: "POST", path: "/p5/p1p2-write" },
  "p3CreateConfig": { method: "POST", path: "/p6/p3/create-config" },
  "p3CreateSlackIntegration": { method: "POST", path: "/p6/p3/create-slack-integration" },
  "p3FusionAddMember": { method: "POST", path: "/p6/p3Fusion/add-member" },
  "p3FusionCancelSubscription": { method: "POST", path: "/p6/p3Fusion/cancel-subscription" },
  "p3FusionChangePlan": { method: "POST", path: "/p6/p3Fusion/change-plan" },
  "p3FusionCreateAsset": { method: "POST", path: "/p6/p3Fusion/create-asset" },
  "p3FusionCreateMitigation": { method: "POST", path: "/p6/p3Fusion/create-mitigation" },
  "p3FusionCreateSchedule": { method: "POST", path: "/p6/p3Fusion/create-schedule" },
  "p3FusionCreateSubscription": { method: "POST", path: "/p6/p3Fusion/create-subscription" },
  "p3FusionDeleteSchedule": { method: "POST", path: "/p6/p3Fusion/delete-schedule" },
  "p3FusionGenerateReport": { method: "GET", path: "/p6/p3Fusion/generate-report" },
  "p3FusionGetAsset": { method: "GET", path: "/p6/p3Fusion/get-asset" },
  "p3FusionGetControl": { method: "GET", path: "/p6/p3Fusion/get-control" },
  "p3FusionGetDashboard": { method: "GET", path: "/p6/p3Fusion/get-dashboard" },
  "p3FusionGetDefinition": { method: "GET", path: "/p6/p3Fusion/get-definition" },
  "p3FusionGetLatestScore": { method: "GET", path: "/p6/p3Fusion/get-latest-score" },
  "p3FusionGetLineage": { method: "GET", path: "/p6/p3Fusion/get-lineage" },
  "p3FusionGetQuotas": { method: "GET", path: "/p6/p3Fusion/get-quotas" },
  "p3FusionGetScoreHistory": { method: "GET", path: "/p6/p3Fusion/get-score-history" },
  "p3FusionListAssessments": { method: "GET", path: "/p6/p3Fusion/list-assessments" },
  "p3FusionListAssets": { method: "GET", path: "/p6/p3Fusion/list-assets" },
  "p3FusionListBillings": { method: "GET", path: "/p6/p3Fusion/list-billings" },
  "p3FusionListConflicts": { method: "GET", path: "/p6/p3Fusion/list-conflicts" },
  "p3FusionListControls": { method: "GET", path: "/p6/p3Fusion/list-controls" },
  "p3FusionListDefinitions": { method: "GET", path: "/p6/p3Fusion/list-definitions" },
  "p3FusionListEvents": { method: "GET", path: "/p6/p3Fusion/list-events" },
  "p3FusionListExecutions": { method: "GET", path: "/p6/p3Fusion/list-executions" },
  "p3FusionListGaps": { method: "GET", path: "/p6/p3Fusion/list-gaps" },
  "p3FusionListMembers": { method: "GET", path: "/p6/p3Fusion/list-members" },
  "p3FusionListMitigations": { method: "GET", path: "/p6/p3Fusion/list-mitigations" },
  "p3FusionListSchedules": { method: "GET", path: "/p6/p3Fusion/list-schedules" },
  "p3FusionListVersions": { method: "GET", path: "/p6/p3Fusion/list-versions" },
  "p3FusionRollbackToVersion": { method: "POST", path: "/p6/p3Fusion/rollback-to-version" },
  "p3FusionUpdateSchedule": { method: "POST", path: "/p6/p3Fusion/update-schedule" },
  "p3FusionUpgradePlan": { method: "POST", path: "/p6/p3Fusion/upgrade-plan" },
  "p3Get": { method: "GET", path: "/p6/p3/get" },
  "p3GetStats": { method: "GET", path: "/p6/p3/get-stats" },
  "p3GetSteps": { method: "GET", path: "/p6/p3/get-steps" },
  "p3ListAlerts": { method: "GET", path: "/p6/p3/list-alerts" },
  "p3ListConfigs": { method: "GET", path: "/p6/p3/list-configs" },
  "p3ListSlackIntegrations": { method: "GET", path: "/p6/p3/list-slack-integrations" },
  "p3ResolveAlert": { method: "POST", path: "/p6/p3/resolve-alert" },
  "p3RetryDelivery": { method: "POST", path: "/p6/p3/retry-delivery" },
  "p3SendTest": { method: "POST", path: "/p6/p3/send-test" },
  "p3TestConfig": { method: "POST", path: "/p6/p3/test-config" },
  "pauseLifecycle": { method: "POST", path: "/p5/pause-lifecycle" },
  "processApproval": { method: "POST", path: "/approval/process" },
  "processContext": { method: "POST", path: "/p5/process-context" },
  "protect": { method: "POST", path: "/gate-check" },
  "publishEvent": { method: "POST", path: "/p3/integration/events" },
  "publishFusionEvent": { method: "POST", path: "/p5/publish-fusion-event" },
  "quickCompareLatest": { method: "GET", path: "/p5/quick-compare-latest" },
  "quickFactCheck": { method: "POST", path: "/p5/quick-fact-check" },
  "quickHallucinationCheck": { method: "POST", path: "/p5/quick-hallucination-check" },
  "quickScan": { method: "POST", path: "/openguard-quick-scan" },
  "recordCostEvent": { method: "POST", path: "/p1p2/cost/record" },
  "recordEvent": { method: "POST", path: "/p5/record-event" },
  "recordFailure": { method: "POST", path: "/p5/record-failure" },
  "recordMeteringEvent": { method: "POST", path: "/p5/record-event" },
  "recordMetric": { method: "POST", path: "/p5/record-metric" },
  "recordMetric_ext": { method: "POST", path: "/p5/record-metric" },
  "recoverKillSwitch": { method: "POST", path: "/killswitch/recover" },
  "referralGetBonusQuota": { method: "GET", path: "/p6/referral/get-bonus-quota" },
  "referralGetMyReferralCode": { method: "GET", path: "/p6/referral/get-my-referral-code" },
  "referralGetMyReferralRewards": { method: "GET", path: "/p6/referral/get-my-referral-rewards" },
  "referralGetPublicReferralInfo": { method: "GET", path: "/p6/referral/get-public-referral-info" },
  "referralRedeemReferralCode": { method: "POST", path: "/p6/referral/redeem-referral-code" },
  "refreshRuleCache": { method: "POST", path: "/p6/rule/refresh-cache" },
  "refundToBalance": { method: "POST", path: "/stripe/refund-to-balance" },
  "regenerateStripeAuditorToken": { method: "POST", path: "/p5/regenerate-stripe-auditor-token" },
  "renderPrompt": { method: "POST", path: "/p3/model-ops/render-prompt" },
  "replayCanaryDecision": { method: "POST", path: "/p1p2/canary/replay/${decisionId}" },
  "replayDecision": { method: "POST", path: "/replay-decision" },
  "replayDecision_ext": { method: "POST", path: "/p1p2/replay-decision" },
  "reportIncident": { method: "POST", path: "/p3/risk/incident" },
  "reportRiskIncident": { method: "POST", path: "/p5/report-risk-incident" },
  "requestApproval": { method: "POST", path: "/request-approval" },
  "requestApproval_ext": { method: "POST", path: "/request-approval" },
  "resetAllFusion": { method: "POST", path: "/p5/reset-all-fusion" },
  "resolveConflict": { method: "POST", path: "/p5/resolve-conflict" },
  "resolveDegradation": { method: "POST", path: "/p1p2/degrade/resolve/${degradationId}" },
  "resolveDispute": { method: "POST", path: "/p5/resolve-dispute" },
  "resolveLifecycle": { method: "POST", path: "/p5/resolve-lifecycle" },
  "resolveP3Alert": { method: "POST", path: "/p5/resolve-p3-alert" },
  "resolvePolicyConflict": { method: "POST", path: "/p5/resolve-conflict" },
  "retryP3Delivery": { method: "POST", path: "/p5/retry-p3-delivery" },
  "retryP3Task": { method: "POST", path: "/p5/retry-p3-task" },
  "revokeApiKey": { method: "POST", path: "/integration/revoke-api-key" },
  "revokeStripeAuditorAccount": { method: "POST", path: "/p6/stripe/revoke-auditor-account" },
  "roleRequestStats": { method: "GET", path: "/p7/rbac/role-request-stats" },
  "rollbackCanary": { method: "POST", path: "/experiment/rollback-canary" },
  "rollbackLifecycle": { method: "POST", path: "/p5/rollback-lifecycle" },
  "rollbackPolicyToVersion": { method: "POST", path: "/p5/rollback-policy-to-version" },
  "rollbackRuleToVersion": { method: "POST", path: "/p5/rollback-rule-to-version" },
  "ruleExportCsv": { method: "POST", path: "/p6/rule/export-csv" },
  "ruleImportCsv": { method: "POST", path: "/p6/rule/import-csv" },
  "ruleRefreshCache": { method: "POST", path: "/p6/rule/refresh-cache" },
  "ruleRollbackToVersion": { method: "POST", path: "/p6/rule/rollback-to-version" },
  "ruleTestPattern": { method: "POST", path: "/p6/rule/test-pattern" },
  "runAllP1P2": { method: "POST", path: "/p1p2/run-all" },
  "runComplianceCheck": { method: "POST", path: "/p5/run-compliance-check" },
  "runComplianceCheck_ext": { method: "POST", path: "/p5/run-compliance-check" },
  "runFullEvaluation": { method: "POST", path: "/p1p2/run-full-evaluation" },
  "runLLMEvaluation": { method: "POST", path: "/p1p2/llm-evaluator/run" },
  "runRegressionSuite": { method: "POST", path: "/p3/audit-regression/run" },
  "runRegressionSuiteExtended": { method: "GET", path: "/p6/sovr/run-suite" },
  "runVerificationPipeline": { method: "GET", path: "/p6/verification/run-pipeline" },
  "scanContent": { method: "POST", path: "/openguard-scan" },
  "searchMemory": { method: "POST", path: "/p1p2/memory/search" },
  "secureAgentChat": { method: "POST", path: "/p5/secure-agent-chat" },
  "secureBatchChat": { method: "POST", path: "/p5/secure-batch-chat" },
  "secureChat": { method: "POST", path: "/p5/secure-chat" },
  "secureChatGetModels": { method: "GET", path: "/p6/chat/get-models" },
  "seedAllFusion": { method: "POST", path: "/p5/seed-all-fusion" },
  "selectModel": { method: "POST", path: "/p3/model-ops/select" },
  "sendP3Test": { method: "POST", path: "/p6/p3/send-test" },
  "sendTelegramTest": { method: "POST", path: "/p5/send-telegram-test" },
  "setBudgetLimit": { method: "POST", path: "/budget/set-limit" },
  "setMaintenanceMode": { method: "POST", path: "/p5/set-maintenance-mode" },
  "shouldRequireHuman": { method: "POST", path: "/budget/should-require-human" },
  "sovrCheckOperation": { method: "GET", path: "/p6/sovr/check-operation" },
  "sovrConsumeQuota": { method: "GET", path: "/p6/sovr/consume-quota" },
  "sovrCreateFlag": { method: "POST", path: "/p6/sovr/create-flag" },
  "sovrCreateSession": { method: "POST", path: "/p6/sovr/create-session" },
  "sovrCreateSuite": { method: "POST", path: "/p6/sovr/create-suite" },
  "sovrCreateVersion": { method: "POST", path: "/p6/sovr/create-version" },
  "sovrExportCSV": { method: "POST", path: "/p6/sovr/export-c-s-v" },
  "sovrGet": { method: "GET", path: "/p6/sovr/get" },
  "sovrGetById": { method: "GET", path: "/p6/sovr/get-by-id" },
  "sovrGetLatestRuns": { method: "GET", path: "/p6/sovr/get-latest-runs" },
  "sovrGetRunsBySuite": { method: "GET", path: "/p6/sovr/get-runs-by-suite" },
  "sovrGetSuite": { method: "GET", path: "/p6/sovr/get-suite" },
  "sovrListByStatus": { method: "GET", path: "/p6/sovr/list-by-status" },
  "sovrListSessions": { method: "GET", path: "/p6/sovr/list-sessions" },
  "sovrListSuites": { method: "GET", path: "/p6/sovr/list-suites" },
  "sovrRunSuite": { method: "GET", path: "/p6/sovr/run-suite" },
  "sovrUpdateLevel": { method: "POST", path: "/p6/sovr/update-level" },
  "sovrVerifyChain": { method: "GET", path: "/p6/sovr/verify-chain" },
  "startExperiment": { method: "POST", path: "/p3/experiments/${encodeURIComponent(experimentId)}/start" },
  "stopExperiment": { method: "POST", path: "/p3/experiments/${encodeURIComponent(experimentId)}/stop" },
  "stripeAddQuotaPoolMember": { method: "POST", path: "/p6/stripe/add-quota-pool-member" },
  "stripeCalculateAuditorAccountCost": { method: "GET", path: "/p6/stripe/calculate-auditor-account-cost" },
  "stripeCalculateDeploymentAddonsCost": { method: "GET", path: "/p6/stripe/calculate-deployment-addons-cost" },
  "stripeCalculateEnterprisePrice": { method: "GET", path: "/p6/stripe/calculate-enterprise-price" },
  "stripeCanCreateQuotaPool": { method: "GET", path: "/p6/stripe/can-create-quota-pool" },
  "stripeCheckDeploymentAddonEligibility": { method: "GET", path: "/p6/stripe/check-deployment-addon-eligibility" },
  "stripeCheckOverageAllowance": { method: "GET", path: "/p6/stripe/check-overage-allowance" },
  "stripeCheckQuotaWithDegrade": { method: "GET", path: "/p6/stripe/check-quota-with-degrade" },
  "stripeCreateAuditorAccount": { method: "POST", path: "/p6/stripe/create-auditor-account" },
  "stripeCreateDeploymentAddonCheckout": { method: "POST", path: "/p6/stripe/create-deployment-addon-checkout" },
  "stripeCreateDeploymentSubscription": { method: "POST", path: "/p6/stripe/create-deployment-subscription" },
  "stripeCreateEnterpriseCheckout": { method: "POST", path: "/p6/stripe/create-enterprise-checkout" },
  "stripeCreateEnvironmentConfig": { method: "POST", path: "/p6/stripe/create-environment-config" },
  "stripeCreatePortalSession": { method: "POST", path: "/p6/stripe/create-portal-session" },
  "stripeCreateQuotaPackCheckout": { method: "POST", path: "/p6/stripe/create-quota-pack-checkout" },
  "stripeCreateQuotaPool": { method: "POST", path: "/p6/stripe/create-quota-pool" },
  "stripeFormatPrice": { method: "GET", path: "/p6/stripe/format-price" },
  "stripeGetAuditorAccount": { method: "GET", path: "/p6/stripe/get-auditor-account" },
  "stripeGetAuditorAccountPricing": { method: "GET", path: "/p6/stripe/get-auditor-account-pricing" },
  "stripeGetAuditorAccountStats": { method: "GET", path: "/p6/stripe/get-auditor-account-stats" },
  "stripeGetBillingEventWeights": { method: "GET", path: "/p6/stripe/get-billing-event-weights" },
  "stripeGetBillingStats": { method: "GET", path: "/p6/stripe/get-billing-stats" },
  "stripeGetBonusQuota": { method: "GET", path: "/p6/stripe/get-bonus-quota" },
  "stripeGetDailyStats": { method: "GET", path: "/p6/stripe/get-daily-stats" },
  "stripeGetDegradeConfig": { method: "GET", path: "/p6/stripe/get-degrade-config" },
  "stripeGetDeploymentAddon": { method: "GET", path: "/p6/stripe/get-deployment-addon" },
  "stripeGetDeploymentAddonCatalog": { method: "GET", path: "/p6/stripe/get-deployment-addon-catalog" },
  "stripeGetEndpointStats": { method: "GET", path: "/p6/stripe/get-endpoint-stats" },
  "stripeGetEnterprisePricingConfig": { method: "GET", path: "/p6/stripe/get-enterprise-pricing-config" },
  "stripeGetEnvBillingPolicies": { method: "GET", path: "/p6/stripe/get-env-billing-policies" },
  "stripeGetEnvironmentStats": { method: "GET", path: "/p6/stripe/get-environment-stats" },
  "stripeGetJoinedQuotaPools": { method: "GET", path: "/p6/stripe/get-joined-quota-pools" },
  "stripeGetOveragePricing": { method: "GET", path: "/p6/stripe/get-overage-pricing" },
  "stripeGetOverageStats": { method: "GET", path: "/p6/stripe/get-overage-stats" },
  "stripeGetOwnedQuotaPools": { method: "GET", path: "/p6/stripe/get-owned-quota-pools" },
  "stripeGetPaymentDetail": { method: "GET", path: "/p6/stripe/get-payment-detail" },
  "stripeGetPayments": { method: "GET", path: "/p6/stripe/get-payments" },
  "stripeGetPlanLimits": { method: "GET", path: "/p6/stripe/get-plan-limits" },
  "stripeGetProducts": { method: "GET", path: "/p6/stripe/get-products" },
  "stripeGetQuotaPacks": { method: "GET", path: "/p6/stripe/get-quota-packs" },
  "stripeGetQuotaPool": { method: "GET", path: "/p6/stripe/get-quota-pool" },
  "stripeGetQuotaPoolMembers": { method: "GET", path: "/p6/stripe/get-quota-pool-members" },
  "stripeGetQuotaPrediction": { method: "GET", path: "/p6/stripe/get-quota-prediction" },
  "stripeGetTrustBundleBalance": { method: "GET", path: "/p6/stripe/get-trust-bundle-balance" },
  "stripeGetTrustBundlePricing": { method: "GET", path: "/p6/stripe/get-trust-bundle-pricing" },
  "stripeGetTrustBundleProducts": { method: "GET", path: "/p6/stripe/get-trust-bundle-products" },
  "stripeGetUsageHistory": { method: "GET", path: "/p6/stripe/get-usage-history" },
  "stripeGetUsageStats": { method: "GET", path: "/p6/stripe/get-usage-stats" },
  "stripeGetUsageTrend": { method: "GET", path: "/p6/stripe/get-usage-trend" },
  "stripeIdentifyEnvironment": { method: "GET", path: "/p6/stripe/identify-environment" },
  "stripeListAuditorAccounts": { method: "GET", path: "/p6/stripe/list-auditor-accounts" },
  "stripeListDeploymentAddons": { method: "GET", path: "/p6/stripe/list-deployment-addons" },
  "stripeListEnvironmentConfigs": { method: "GET", path: "/p6/stripe/list-environment-configs" },
  "stripeListUserDeploymentSubscriptions": { method: "GET", path: "/p6/stripe/list-user-deployment-subscriptions" },
  "stripeRegenerateAuditorToken": { method: "POST", path: "/p6/stripe/regenerate-auditor-token" },
  "stripeRevokeAuditorAccount": { method: "POST", path: "/p6/stripe/revoke-auditor-account" },
  "stripeSyncDeploymentAddonSubscriptions": { method: "POST", path: "/p6/stripe/sync-deployment-addon-subscriptions" },
  "stripeUpdateAuditorAccount": { method: "POST", path: "/p6/stripe/update-auditor-account" },
  "stripeUpdateDegradeConfig": { method: "POST", path: "/p6/stripe/update-degrade-config" },
  "stripeUpdateDeploymentSubscriptionStatus": { method: "POST", path: "/p6/stripe/update-deployment-subscription-status" },
  "stripeUpdateEnvironmentConfig": { method: "POST", path: "/p6/stripe/update-environment-config" },
  "submitEvidence": { method: "POST", path: "/p5/submit-evidence" },
  "submitEvidence_ext": { method: "POST", path: "/p5/submit-evidence" },
  "submitReceipt": { method: "POST", path: "/submit-receipt" },
  "submitReceipt_ext": { method: "POST", path: "/submit-receipt" },
  "suspendTenant": { method: "POST", path: "/p5/suspend-tenant" },
  "syncStripeDeploymentAddonSubscriptions": { method: "POST", path: "/p5/sync-stripe-deployment-addon-subscriptions" },
  "testNotification": { method: "POST", path: "/p5/test-notification" },
  "testP3IntegrationConfig": { method: "POST", path: "/p5/test-p3-integration-config" },
  "testP3Webhook": { method: "POST", path: "/p5/test-p3-webhook" },
  "testRulePattern": { method: "POST", path: "/p5/test-rule-pattern" },
  "traceDataLineage": { method: "POST", path: "/p5/trace-data-lineage" },
  "traceLineage": { method: "GET", path: "/p3/data-governance/lineage/${assetId}" },
  "trialAgentChat": { method: "POST", path: "/p5/trial-agent-chat" },
  "trialChat": { method: "POST", path: "/p5/trial-chat" },
  "triggerKillSwitch": { method: "POST", path: "/killswitch/trigger" },
  "trustCheckSilentModeEligibility": { method: "GET", path: "/p6/trust/check-silent-mode-eligibility" },
  "trustGetAnomalyPushConfig": { method: "GET", path: "/p6/trust/get-anomaly-push-config" },
  "trustGetCostStats": { method: "GET", path: "/p6/trust/get-cost-stats" },
  "trustGetCostStatsHistory": { method: "GET", path: "/p6/trust/get-cost-stats-history" },
  "trustGetCurrentScore": { method: "GET", path: "/p6/trust/get-current-score" },
  "trustGetLevelInfo": { method: "GET", path: "/p6/trust/get-level-info" },
  "trustGetPushLogs": { method: "GET", path: "/p6/trust/get-push-logs" },
  "trustGetScoreHistory": { method: "GET", path: "/p6/trust/get-score-history" },
  "trustGetSilentModeConfig": { method: "GET", path: "/p6/trust/get-silent-mode-config" },
  "trustGetSilentModeLogs": { method: "GET", path: "/p6/trust/get-silent-mode-logs" },
  "trustRefreshCostStats": { method: "POST", path: "/p6/trust/refresh-cost-stats" },
  "trustRefreshScore": { method: "POST", path: "/p6/trust/refresh-score" },
  "trustResetSilentModeCount": { method: "POST", path: "/p6/trust/reset-silent-mode-count" },
  "trustTestPushChannel": { method: "POST", path: "/p6/trust/test-push-channel" },
  "trustUpdateAnomalyPushConfig": { method: "POST", path: "/p6/trust/update-anomaly-push-config" },
  "trustUpdateSilentModeConfig": { method: "POST", path: "/p6/trust/update-silent-mode-config" },
  "twitterGetMarketingEvents": { method: "GET", path: "/p6/twitter/get-marketing-events" },
  "twitterGetMentions": { method: "GET", path: "/p6/twitter/get-mentions" },
  "twitterGetSchedulerStatus": { method: "GET", path: "/p6/twitter/get-scheduler-status" },
  "twitterPostTweet": { method: "POST", path: "/p6/twitter/post-tweet" },
  "twitterPublishNow": { method: "POST", path: "/p6/twitter/publish-now" },
  "twitterVerifyCredentials": { method: "GET", path: "/p6/twitter/verify-credentials" },
  "unfreezeBalance": { method: "POST", path: "/stripe/unfreeze-balance" },
  "updateCustomPattern": { method: "POST", path: "/open-guard/update-custom-pattern" },
  "updateDegradationLevel": { method: "POST", path: "/p6/sovr/update-level" },
  "updateDisputeStatus": { method: "POST", path: "/p5/update-dispute-status" },
  "updateFusionRule": { method: "POST", path: "/p3-fusion/automation/update-rule" },
  "updateIncidentStatus": { method: "POST", path: "/p5/update-incident-status" },
  "updateLifecycle": { method: "POST", path: "/p5/update-lifecycle" },
  "updateP3Webhook": { method: "POST", path: "/p5/update-p3-webhook" },
  "updateP3WebhookRule": { method: "POST", path: "/p5/update-p3-webhook-rule" },
  "updatePromptTemplate": { method: "POST", path: "/p3/model-ops/prompt-templates/update" },
  "updateReportSchedule": { method: "POST", path: "/p5/update-report-schedule" },
  "updateRollbackPolicy": { method: "POST", path: "/p5/update-rollback-policy" },
  "updateRule": { method: "POST", path: "/rules/update" },
  "updateStripeAuditorAccount": { method: "POST", path: "/p6/stripe/update-auditor-account" },
  "updateStripeDegradeConfig": { method: "POST", path: "/p5/update-stripe-degrade-config" },
  "updateStripeDeploymentSubscriptionStatus": { method: "POST", path: "/p5/update-stripe-deployment-subscription-status" },
  "updateStripeEnvironmentConfig": { method: "POST", path: "/p5/update-stripe-environment-config" },
  "updateVerificationWebhookConfig": { method: "POST", path: "/p5/update-verification-webhook-config" },
  "upgradeTenantPlan": { method: "POST", path: "/p5/upgrade-tenant-plan" },
  "validateAccess": { method: "POST", path: "/p3/saas/access/validate" },
  "validateApiKey": { method: "POST", path: "/integration/validate-api-key" },
  "validatePolicy": { method: "POST", path: "/policy/validate" },
  "validateReality": { method: "POST", path: "/p5/validate-reality" },
  "validateTenantAccess": { method: "POST", path: "/p5/validate-tenant-access" },
  "verifyAuditChain": { method: "GET", path: "/audit/verify${qs ? " },
  "verifyBundle": { method: "GET", path: "/bundles/${bundleId}/verify" },
  "verifyCertificate": { method: "POST", path: "/p5/verify-certificate" },
  "verifyDailyRoot": { method: "POST", path: "/audit/verify-daily-root" },
  "verifyDemo": { method: "POST", path: "/p5/verify-demo" },
  "verifyDemoVerify": { method: "GET", path: "/p6/verification/demo-verify" },
  "verifyFact": { method: "GET", path: "/p6/verification/fact-verify" },
  "verifyFactVerify": { method: "GET", path: "/p6/verification/fact-verify" },
  "verifyGetApiStats": { method: "GET", path: "/p6/verification/get-api-stats" },
  "verifyGetApiTimeSeries": { method: "GET", path: "/p6/verification/get-api-time-series" },
  "verifyGetDailyStats": { method: "GET", path: "/p6/verification/get-daily-stats" },
  "verifyGetHourlyHeatmap": { method: "GET", path: "/p6/verification/get-hourly-heatmap" },
  "verifyGetTopEndpoints": { method: "GET", path: "/p6/verification/get-top-endpoints" },
  "verifyGetWebhookConfig": { method: "GET", path: "/p6/verification/get-webhook-config" },
  "verifyIMChannel": { method: "POST", path: "/p7/im/verify-channel" },
  "verifyQuick": { method: "POST", path: "/p5/verify-quick" },
  "verifyQuickVerify": { method: "GET", path: "/p6/verification/quick-verify" },
  "verifyRunPipeline": { method: "GET", path: "/p6/verification/run-pipeline" },
  "verifyTrustChain": { method: "POST", path: "/trust-bundle/verify-chain" },
  "verifyUpdateWebhookConfig": { method: "POST", path: "/p6/verification/update-webhook-config" },
  "writeEvidence": { method: "POST", path: "/trust-bundle/write-evidence" },
  "writeMemory": { method: "POST", path: "/p1p2/memory/write" },
  // ── Auto-synced from MCP Proxy (v4.1.0) ──
  "approvalApprove": { method: "POST", path: "/approval/approve" },
  "approvalReject": { method: "POST", path: "/approval/reject" },
  "rbacRole": { method: "GET", path: "/rbac/role/:role" },
  "rbacDualApprovalCheck": { method: "POST", path: "/rbac/dual-approval-check" },
  "budgetCheckProceed": { method: "POST", path: "/budget/check-proceed" },
  "budgetCheckHuman": { method: "POST", path: "/budget/check-human" },
  "default_denyCheck": { method: "POST", path: "/default-deny/check" },
  "meteringUsage": { method: "GET", path: "/metering/usage" },
  "meteringQuota": { method: "GET", path: "/metering/quota" },
  "meteringDaily": { method: "GET", path: "/metering/daily" },
  "experimentFeatureFlags": { method: "GET", path: "/experiment/feature-flags" },
  "experimentFeatureFlagsToggle": { method: "POST", path: "/experiment/feature-flags/:flagId/toggle" },
  "experimentCanaryDeployments": { method: "GET", path: "/experiment/canary-deployments" },
  "integrationApiKeys": { method: "GET", path: "/integration/api-keys" },
  "integrationApiKeysRevoke": { method: "POST", path: "/integration/api-keys/:keyId/revoke" },
  "task_queueDeadLetter": { method: "GET", path: "/task-queue/dead-letter" },
  "task_queueDeadLetterRetry": { method: "POST", path: "/task-queue/dead-letter/:itemId/retry" },
  "p5VerifyFact": { method: "POST", path: "/p5/verify-fact" },
  "p5RunVerificationPipeline": { method: "POST", path: "/p5/run-verification-pipeline" },
  "p5CreateP1P2Bundle": { method: "POST", path: "/p5/create-p1-p2-bundle" },
  "p5ClearP1P2Cache": { method: "POST", path: "/p5/clear-p1-p2-cache" },
  "p5DeleteP3WebhookRule": { method: "POST", path: "/p5/delete-p3-webhook-rule" },
  "p5SendP3Test": { method: "POST", path: "/p5/send-p3-test" },
  "p5ResolvePolicyConflict": { method: "POST", path: "/p5/resolve-policy-conflict" },
  "p5DeleteFusionRule": { method: "POST", path: "/p5/delete-fusion-rule" },
  "p5RefreshRuleCache": { method: "POST", path: "/p5/refresh-rule-cache" },
  "p5FormatStripePrice": { method: "POST", path: "/p5/format-stripe-price" },
  "p5CreateStripeQuotaPackCheckout": { method: "POST", path: "/p5/create-stripe-quota-pack-checkout" },
  "p5CheckStripeQuotaWithDegrade": { method: "GET", path: "/p5/check-stripe-quota-with-degrade" },
  "p5CheckStripeOverageAllowance": { method: "GET", path: "/p5/check-stripe-overage-allowance" },
  "p5CreateStripeAuditorAccount": { method: "POST", path: "/p5/create-stripe-auditor-account" },
  "p5UpdateStripeAuditorAccount": { method: "POST", path: "/p5/update-stripe-auditor-account" },
  "p5RevokeStripeAuditorAccount": { method: "POST", path: "/p5/revoke-stripe-auditor-account" },
  "p5CalculateStripeAuditorAccountCost": { method: "POST", path: "/p5/calculate-stripe-auditor-account-cost" },
  "p5CalculateStripeDeploymentAddonsCost": { method: "POST", path: "/p5/calculate-stripe-deployment-addons-cost" },
  "p5CreateStripeDeploymentAddonCheckout": { method: "POST", path: "/p5/create-stripe-deployment-addon-checkout" },
  "p5CreateStripeEnterpriseCheckout": { method: "POST", path: "/p5/create-stripe-enterprise-checkout" },
  "status_v2": { method: "GET", path: "/status-v2" },
  "p6AgentIntegrationConfigureCallback": { method: "GET", path: "/p6/agent-integration/configure-callback" },
  "p6AgentIntegrationGetIntegrationGuide": { method: "GET", path: "/p6/agent-integration/get-integration-guide" },
  "p6AgentIntegrationRegister": { method: "GET", path: "/p6/agent-integration/register" },
  "p6AgentIntegrationReportOperation": { method: "GET", path: "/p6/agent-integration/report-operation" },
  "p6AiRiskAssessment": { method: "GET", path: "/p6/ai/risk-assessment" },
  "p6AlertAcknowledge": { method: "GET", path: "/p6/alert/acknowledge" },
  "p6AlertCreateRule": { method: "GET", path: "/p6/alert/create-rule" },
  "p6AlertCreateTemplate": { method: "GET", path: "/p6/alert/create-template" },
  "p6AlertExportRules": { method: "GET", path: "/p6/alert/export-rules" },
  "p6AlertGetRule": { method: "GET", path: "/p6/alert/get-rule" },
  "p6AlertGetSubscription": { method: "GET", path: "/p6/alert/get-subscription" },
  "p6AlertImportRules": { method: "GET", path: "/p6/alert/import-rules" },
  "p6AlertListRules": { method: "GET", path: "/p6/alert/list-rules" },
  "p6AlertListTemplates": { method: "GET", path: "/p6/alert/list-templates" },
  "p6AlertRollbackRule": { method: "GET", path: "/p6/alert/rollback-rule" },
  "p6AlertStats": { method: "GET", path: "/p6/alert/stats" },
  "p6AlertTestRule": { method: "GET", path: "/p6/alert/test-rule" },
  "p6AlertToggleRule": { method: "GET", path: "/p6/alert/toggle-rule" },
  "p6AlertTrigger": { method: "GET", path: "/p6/alert/trigger" },
  "p6AlertTypes": { method: "GET", path: "/p6/alert/types" },
  "p6AlertUpdateRule": { method: "GET", path: "/p6/alert/update-rule" },
  "p6ApiKeysCreate": { method: "GET", path: "/p6/api-keys/create" },
  "p6ApiKeysList": { method: "GET", path: "/p6/api-keys/list" },
  "p6ApiKeysToggle": { method: "GET", path: "/p6/api-keys/toggle" },
  "p6ApprovalList": { method: "GET", path: "/p6/approval/list" },
  "p6ApprovalPending": { method: "GET", path: "/p6/approval/pending" },
  "p6ApprovalResolve": { method: "GET", path: "/p6/approval/resolve" },
  "p6AuditList": { method: "GET", path: "/p6/audit/list" },
  "p6BlogList": { method: "GET", path: "/p6/blog/list" },
  "p6BudgetAcknowledgeAlert": { method: "GET", path: "/p6/budget/acknowledge-alert" },
  "p6BudgetAlerts": { method: "GET", path: "/p6/budget/alerts" },
  "p6BudgetGet": { method: "GET", path: "/p6/budget/get" },
  "p6BudgetList": { method: "GET", path: "/p6/budget/list" },
  "p6BudgetUsageHistory": { method: "GET", path: "/p6/budget/usage-history" },
  "p6DecisionCreateShareLink": { method: "GET", path: "/p6/decision/create-share-link" },
  "p6DecisionGetById": { method: "GET", path: "/p6/decision/get-by-id" },
  "p6DecisionList": { method: "GET", path: "/p6/decision/list" },
  "p6DecisionReplay": { method: "GET", path: "/p6/decision/replay" },
  "p6DecisionRevokeShareLink": { method: "GET", path: "/p6/decision/revoke-share-link" },
  "p6DecisionSearch": { method: "GET", path: "/p6/decision/search" },
  "p6DecisionStats": { method: "GET", path: "/p6/decision/stats" },
  "p6DecisionValidateShareLink": { method: "GET", path: "/p6/decision/validate-share-link" },
  "p6EmailCheckRateLimit": { method: "GET", path: "/p6/email/check-rate-limit" },
  "p6EmailCompareVersions": { method: "GET", path: "/p6/email/compare-versions" },
  "p6EmailCreateConfig": { method: "GET", path: "/p6/email/create-config" },
  "p6EmailCreateTemplate": { method: "GET", path: "/p6/email/create-template" },
  "p6EmailGetVersionHistory": { method: "GET", path: "/p6/email/get-version-history" },
  "p6EmailListConfigs": { method: "GET", path: "/p6/email/list-configs" },
  "p6EmailListTemplates": { method: "GET", path: "/p6/email/list-templates" },
  "p6EmailQueueStats": { method: "GET", path: "/p6/email/queue-stats" },
  "p6EmailRollbackToVersion": { method: "GET", path: "/p6/email/rollback-to-version" },
  "p6EmailSendTest": { method: "GET", path: "/p6/email/send-test" },
  "p6EmailUpdateConfig": { method: "GET", path: "/p6/email/update-config" },
  "p6EmailUpdateTemplate": { method: "GET", path: "/p6/email/update-template" },
  "p6ExportCreate": { method: "GET", path: "/p6/export/create" },
  "p6ExportGetById": { method: "GET", path: "/p6/export/get-by-id" },
  "p6ExportHistory": { method: "GET", path: "/p6/export/history" },
  "p6ExportStats": { method: "GET", path: "/p6/export/stats" },
  "p6ExportUpdateStatus": { method: "GET", path: "/p6/export/update-status" },
  "p6ExternalApiAuditLogs": { method: "GET", path: "/p6/external-api/audit-logs" },
  "p6ExternalApiExecute": { method: "GET", path: "/p6/external-api/execute" },
  "p6ExternalApiHealth": { method: "GET", path: "/p6/external-api/health" },
  "p6ExternalApiStatus": { method: "GET", path: "/p6/external-api/status" },
  "p6ExternalApiVerify": { method: "GET", path: "/p6/external-api/verify" },
  "p6ExternalGateAddPolicy": { method: "GET", path: "/p6/external-gate/add-policy" },
  "p6ExternalGateAuditLogs": { method: "GET", path: "/p6/external-gate/audit-logs" },
  "p6ExternalGateBatchUpdatePolicies": { method: "GET", path: "/p6/external-gate/batch-update-policies" },
  "p6ExternalGateDecisions": { method: "GET", path: "/p6/external-gate/decisions" },
  "p6ExternalGateEvaluatePolicy": { method: "GET", path: "/p6/external-gate/evaluate-policy" },
  "p6ExternalGateListPolicies": { method: "GET", path: "/p6/external-gate/list-policies" },
  "p6ExternalGateRemovePolicy": { method: "GET", path: "/p6/external-gate/remove-policy" },
  "p6ExternalGateResetPolicies": { method: "POST", path: "/p6/external-gate/reset-policies" },
  "p6ExternalGateStatus": { method: "GET", path: "/p6/external-gate/status" },
  "p6ExternalGateTestDualGate": { method: "GET", path: "/p6/external-gate/test-dual-gate" },
  "p6ExternalGateTestGateCheck": { method: "GET", path: "/p6/external-gate/test-gate-check" },
  "p6ExternalGateUpdatePolicy": { method: "GET", path: "/p6/external-gate/update-policy" },
  "p6KillSwitchDeactivate": { method: "GET", path: "/p6/kill-switch/deactivate" },
  "p6KillSwitchHistory": { method: "GET", path: "/p6/kill-switch/history" },
  "p6KillSwitchStatus": { method: "GET", path: "/p6/kill-switch/status" },
  "p6KillSwitchTrigger": { method: "GET", path: "/p6/kill-switch/trigger" },
  "p6ManusIntegrationCheckApprovalStatus": { method: "GET", path: "/p6/manus-integration/check-approval-status" },
  "p6ManusIntegrationGetIntegrationGuide": { method: "GET", path: "/p6/manus-integration/get-integration-guide" },
  "p6ManusIntegrationGetIntegrationStatus": { method: "GET", path: "/p6/manus-integration/get-integration-status" },
  "p6ManusIntegrationPreExecuteVerify": { method: "GET", path: "/p6/manus-integration/pre-execute-verify" },
  "p6ManusIntegrationReportExecutionResult": { method: "GET", path: "/p6/manus-integration/report-execution-result" },
  "p6ManusIntegrationRequestRollback": { method: "GET", path: "/p6/manus-integration/request-rollback" },
  "p6NewsletterGetStats": { method: "GET", path: "/p6/newsletter/get-stats" },
  "p6PolicyActive": { method: "GET", path: "/p6/policy/active" },
  "p6PolicyCreate": { method: "GET", path: "/p6/policy/create" },
  "p6PolicyGetById": { method: "GET", path: "/p6/policy/get-by-id" },
  "p6PolicyGetRules": { method: "GET", path: "/p6/policy/get-rules" },
  "p6PolicyList": { method: "GET", path: "/p6/policy/list" },
  "p6PolicyVersionHistory": { method: "GET", path: "/p6/policy/version-history" },
  "p6PushCleanupExpired": { method: "POST", path: "/p6/push/cleanup-expired" },
  "p6PushCompareVersions": { method: "GET", path: "/p6/push/compare-versions" },
  "p6PushCompleteAbTest": { method: "GET", path: "/p6/push/complete-ab-test" },
  "p6PushCreateAbTest": { method: "GET", path: "/p6/push/create-ab-test" },
  "p6PushGetAbTestDetail": { method: "GET", path: "/p6/push/get-ab-test-detail" },
  "p6PushGetAbTestStats": { method: "GET", path: "/p6/push/get-ab-test-stats" },
  "p6PushGetVersionDetail": { method: "GET", path: "/p6/push/get-version-detail" },
  "p6PushGetVersionHistory": { method: "GET", path: "/p6/push/get-version-history" },
  "p6PushHistory": { method: "GET", path: "/p6/push/history" },
  "p6PushListAbTests": { method: "GET", path: "/p6/push/list-ab-tests" },
  "p6PushPublishVersion": { method: "GET", path: "/p6/push/publish-version" },
  "p6PushRollbackToVersion": { method: "GET", path: "/p6/push/rollback-to-version" },
  "p6PushStats": { method: "GET", path: "/p6/push/stats" },
  "p6PushSubscribe": { method: "GET", path: "/p6/push/subscribe" },
  "p6PushTestNotification": { method: "POST", path: "/p6/push/test-notification" },
  "p6PushUnsubscribe": { method: "GET", path: "/p6/push/unsubscribe" },
  "p6PushUpdateAbTestStatus": { method: "GET", path: "/p6/push/update-ab-test-status" },
  "p6ReportGenerate": { method: "GET", path: "/p6/report/generate" },
  "p6ReportList": { method: "GET", path: "/p6/report/list" },
  "p6ReviewGateHistory": { method: "GET", path: "/p6/review-gate/history" },
  "p6ReviewGateStats": { method: "GET", path: "/p6/review-gate/stats" },
  "p6RuleDefinitionsAuditLog": { method: "GET", path: "/p6/rule-definitions/audit-log" },
  "p6RuleDefinitionsBatchToggle": { method: "GET", path: "/p6/rule-definitions/batch-toggle" },
  "p6RuleDefinitionsCreate": { method: "GET", path: "/p6/rule-definitions/create" },
  "p6RuleDefinitionsDelete": { method: "GET", path: "/p6/rule-definitions/delete" },
  "p6RuleDefinitionsExportCsv": { method: "GET", path: "/p6/rule-definitions/export-csv" },
  "p6RuleDefinitionsImportCsv": { method: "GET", path: "/p6/rule-definitions/import-csv" },
  "p6RuleDefinitionsList": { method: "GET", path: "/p6/rule-definitions/list" },
  "p6RuleDefinitionsRefreshCache": { method: "POST", path: "/p6/rule-definitions/refresh-cache" },
  "p6RuleDefinitionsRollbackToVersion": { method: "GET", path: "/p6/rule-definitions/rollback-to-version" },
  "p6RuleDefinitionsStats": { method: "GET", path: "/p6/rule-definitions/stats" },
  "p6RuleDefinitionsTestPattern": { method: "GET", path: "/p6/rule-definitions/test-pattern" },
  "p6RuleDefinitionsUpdate": { method: "GET", path: "/p6/rule-definitions/update" },
  "p6RuleDefinitionsVersionHistory": { method: "GET", path: "/p6/rule-definitions/version-history" },
  "p6RuleTemplateBatchExtendShareLinks": { method: "GET", path: "/p6/rule-template/batch-extend-share-links" },
  "p6RuleTemplateBatchRevokeShareLinks": { method: "GET", path: "/p6/rule-template/batch-revoke-share-links" },
  "p6RuleTemplateCreate": { method: "GET", path: "/p6/rule-template/create" },
  "p6RuleTemplateDeprecate": { method: "GET", path: "/p6/rule-template/deprecate" },
  "p6RuleTemplateExport": { method: "GET", path: "/p6/rule-template/export" },
  "p6RuleTemplateGet": { method: "GET", path: "/p6/rule-template/get" },
  "p6RuleTemplateImport": { method: "GET", path: "/p6/rule-template/import" },
  "p6RuleTemplateList": { method: "GET", path: "/p6/rule-template/list" },
  "p6RuleTemplateStats": { method: "GET", path: "/p6/rule-template/stats" },
  "p6RuleTemplateUpdate": { method: "GET", path: "/p6/rule-template/update" },
  "p6RuleTemplateVersions": { method: "GET", path: "/p6/rule-template/versions" },
  "p6SandboxCreate": { method: "GET", path: "/p6/sandbox/create" },
  "p6SandboxGet": { method: "GET", path: "/p6/sandbox/get" },
  "p6SandboxList": { method: "GET", path: "/p6/sandbox/list" },
  "p6SandboxRevokeApiKey": { method: "GET", path: "/p6/sandbox/revoke-api-key" },
  "p6SandboxValidateApiKey": { method: "GET", path: "/p6/sandbox/validate-api-key" },
  "p6ScheduledReportCreate": { method: "GET", path: "/p6/scheduled-report/create" },
  "p6ScheduledReportExecutions": { method: "GET", path: "/p6/scheduled-report/executions" },
  "p6ScheduledReportGet": { method: "GET", path: "/p6/scheduled-report/get" },
  "p6ScheduledReportList": { method: "GET", path: "/p6/scheduled-report/list" },
  "p6ScheduledReportSchedules": { method: "GET", path: "/p6/scheduled-report/schedules" },
  "p6ScheduledReportStats": { method: "GET", path: "/p6/scheduled-report/stats" },
  "p6ScheduledReportTrigger": { method: "GET", path: "/p6/scheduled-report/trigger" },
  "p6ScheduledReportTypes": { method: "GET", path: "/p6/scheduled-report/types" },
  "p6ScheduledReportUpdate": { method: "GET", path: "/p6/scheduled-report/update" },
  "p6SchedulerHistory": { method: "GET", path: "/p6/scheduler/history" },
  "p6SchedulerStatus": { method: "GET", path: "/p6/scheduler/status" },
  "p6SchedulerTasks": { method: "GET", path: "/p6/scheduler/tasks" },
  "p6SchedulerTrigger": { method: "GET", path: "/p6/scheduler/trigger" },
  "p6SecureChatAgentChat": { method: "GET", path: "/p6/secure-chat/agent-chat" },
  "p6SecureChatBatchChat": { method: "GET", path: "/p6/secure-chat/batch-chat" },
  "p6SecureChatChat": { method: "GET", path: "/p6/secure-chat/chat" },
  "p6SecureChatGetDangerousTools": { method: "GET", path: "/p6/secure-chat/get-dangerous-tools" },
  "p6SecureChatGetModels": { method: "GET", path: "/p6/secure-chat/get-models" },
  "p6SecureChatTrialAgentChat": { method: "GET", path: "/p6/secure-chat/trial-agent-chat" },
  "p6SecureChatTrialChat": { method: "GET", path: "/p6/secure-chat/trial-chat" },
  "approvalList": { method: "GET", path: "/approval/list" },
  "approvalResolve": { method: "GET", path: "/approval/resolve" },
  "auditChainedLogs": { method: "GET", path: "/audit/chained-logs" },
  "auditCleanupMerkleTreeCaches": { method: "POST", path: "/audit/cleanup-merkle-tree-caches" },
  "auditCreateCleanupPolicy": { method: "GET", path: "/audit/create-cleanup-policy" },
  "auditGetCurrentMerkleRoot": { method: "GET", path: "/audit/get-current-merkle-root" },
  "auditGetMerkleTaskStatus": { method: "GET", path: "/audit/get-merkle-task-status" },
  "auditList": { method: "GET", path: "/audit/list" },
  "auditListCleanupExecutions": { method: "GET", path: "/audit/list-cleanup-executions" },
  "auditListCleanupPolicies": { method: "GET", path: "/audit/list-cleanup-policies" },
  "auditScheduleHistoricalMerkleComputation": { method: "GET", path: "/audit/schedule-historical-merkle-computation" },
  "auditScheduleMerkleComputation": { method: "GET", path: "/audit/schedule-merkle-computation" },
  "auditUpdateCleanupPolicy": { method: "GET", path: "/audit/update-cleanup-policy" },
  "audit_replayCompareSnapshots": { method: "GET", path: "/audit-replay/compare-snapshots" },
  "audit_replayCreateSnapshot": { method: "GET", path: "/audit-replay/create-snapshot" },
  "audit_replayGetEntitySnapshots": { method: "GET", path: "/audit-replay/get-entity-snapshots" },
  "budgetAcknowledgeAlert": { method: "GET", path: "/budget/acknowledge-alert" },
  "budgetGet": { method: "GET", path: "/budget/get" },
  "budgetIncrementUsage": { method: "GET", path: "/budget/increment-usage" },
  "budgetList": { method: "GET", path: "/budget/list" },
  "budgetListFrozen": { method: "GET", path: "/budget/list-frozen" },
  "budgetSummary": { method: "GET", path: "/budget/summary" },
  "budgetUsageHistory": { method: "GET", path: "/budget/usage-history" },
  "experimentAssign": { method: "GET", path: "/experiment/assign" },
  "experimentCreate": { method: "GET", path: "/experiment/create" },
  "experimentStart": { method: "GET", path: "/experiment/start" },
  "experimentStop": { method: "GET", path: "/experiment/stop" },
  "gateCheckV2": { method: "GET", path: "/gate/check" },
  "health_checkAcknowledgeAlert": { method: "GET", path: "/health-check/acknowledge-alert" },
  "health_checkAggregatedHealth": { method: "GET", path: "/health-check/aggregated-health" },
  "health_checkAlertHistory": { method: "GET", path: "/health-check/alert-history" },
  "health_checkCreateTestAlert": { method: "GET", path: "/health-check/create-test-alert" },
  "health_checkListAlerts": { method: "GET", path: "/health-check/list-alerts" },
  "health_checkModuleHealth": { method: "GET", path: "/health-check/module-health" },
  "health_checkResolveAlert": { method: "GET", path: "/health-check/resolve-alert" },
  "integrationCreateRule": { method: "GET", path: "/integration/create-rule" },
  "integrationDeleteRule": { method: "GET", path: "/integration/delete-rule" },
  "integrationGetDashboard": { method: "GET", path: "/integration/get-dashboard" },
  "integrationListEvents": { method: "GET", path: "/integration/list-events" },
  "integrationListRules": { method: "GET", path: "/integration/list-rules" },
  "integrationManualTrigger": { method: "GET", path: "/integration/manual-trigger" },
  "integrationPublishEvent": { method: "GET", path: "/integration/publish-event" },
  "integrationUpdateRule": { method: "GET", path: "/integration/update-rule" },
  "kill_switchApprove": { method: "GET", path: "/kill-switch/approve" },
  "kill_switchDeactivate": { method: "GET", path: "/kill-switch/deactivate" },
  "kill_switchEngineActivate": { method: "GET", path: "/kill-switch/engine-activate" },
  "kill_switchEngineDeactivate": { method: "GET", path: "/kill-switch/engine-deactivate" },
  "kill_switchEngineStatus": { method: "GET", path: "/kill-switch/engine-status" },
  "kill_switchHistory": { method: "GET", path: "/kill-switch/history" },
  "kill_switchStatus": { method: "GET", path: "/kill-switch/status" },
  "meteringRecordEvent": { method: "GET", path: "/metering/record-event" },
  "model_opsCreatePromptTemplate": { method: "GET", path: "/model-ops/create-prompt-template" },
  "model_opsDeactivatePromptTemplate": { method: "GET", path: "/model-ops/deactivate-prompt-template" },
  "model_opsGetAllModelHealthStatus": { method: "GET", path: "/model-ops/get-all-model-health-status" },
  "model_opsGetCircuitBreakerEvents": { method: "GET", path: "/model-ops/get-circuit-breaker-events" },
  "model_opsGetModelUsageStats": { method: "GET", path: "/model-ops/get-model-usage-stats" },
  "model_opsGetPromptTemplate": { method: "GET", path: "/model-ops/get-prompt-template" },
  "model_opsGetRoutingDecisionLog": { method: "GET", path: "/model-ops/get-routing-decision-log" },
  "model_opsListActiveAbtests": { method: "GET", path: "/model-ops/list-active-abtests" },
  "model_opsListModels": { method: "GET", path: "/model-ops/list-models" },
  "model_opsListPromptTemplates": { method: "GET", path: "/model-ops/list-prompt-templates" },
  "model_opsRenderPrompt": { method: "GET", path: "/model-ops/render-prompt" },
  "model_opsSelectModel": { method: "GET", path: "/model-ops/select-model" },
  "model_opsUpdatePromptTemplate": { method: "GET", path: "/model-ops/update-prompt-template" },
  "monitoringHealthCheck": { method: "GET", path: "/monitoring/health-check" },
  "monitoringRecordMetric": { method: "GET", path: "/monitoring/record-metric" },
  "open_guardGeoStats": { method: "GET", path: "/open-guard/geo-stats" },
  "open_guardPatterns": { method: "GET", path: "/open-guard/patterns" },
  "open_guardQuickScan": { method: "GET", path: "/open-guard/quick-scan" },
  "open_guardScan": { method: "GET", path: "/open-guard/scan" },
  "open_guardScanLogs": { method: "GET", path: "/open-guard/scan-logs" },
  "open_guardSemanticModels": { method: "GET", path: "/open-guard/semantic-models" },
  "open_guardStats": { method: "GET", path: "/open-guard/stats" },
  "policyActive": { method: "GET", path: "/policy/active" },
  "policyCreate": { method: "GET", path: "/policy/create" },
  "policyDefaultTemplate": { method: "GET", path: "/policy/default-template" },
  "policyGetById": { method: "GET", path: "/policy/get-by-id" },
  "policyGetRules": { method: "GET", path: "/policy/get-rules" },
  "policyList": { method: "GET", path: "/policy/list" },
  "policyLoadActiveDsl": { method: "GET", path: "/policy/load-active-dsl" },
  "policyPreviewEval": { method: "GET", path: "/policy/preview-eval" },
  "policyRestoreVersion": { method: "GET", path: "/policy/restore-version" },
  "policySaveActiveDsl": { method: "GET", path: "/policy/save-active-dsl" },
  "policyValidateDsl": { method: "GET", path: "/policy/validate-dsl" },
  "policyVersionHistory": { method: "GET", path: "/policy/version-history" },
  "task_queueCancel": { method: "GET", path: "/task-queue/cancel" },
  "task_queueComplete": { method: "POST", path: "/task-queue/complete" },
  "task_queueCreate": { method: "GET", path: "/task-queue/create" },
  "task_queueFail": { method: "GET", path: "/task-queue/fail" },
  "task_queueGetById": { method: "GET", path: "/task-queue/get-by-id" },
  "trust_bundleActivate": { method: "GET", path: "/trust-bundle/activate" },
  "trust_bundleAddEvidence": { method: "GET", path: "/trust-bundle/add-evidence" },
  "trust_bundleBatchActivate": { method: "GET", path: "/trust-bundle/batch-activate" },
  "trust_bundleBatchCreateForDecisions": { method: "GET", path: "/trust-bundle/batch-create-for-decisions" },
  "trust_bundleBatchExport": { method: "GET", path: "/trust-bundle/batch-export" },
  "trust_bundleBatchManualReEvaluate": { method: "GET", path: "/trust-bundle/batch-manual-re-evaluate" },
  "trust_bundleBatchReEvaluate": { method: "GET", path: "/trust-bundle/batch-re-evaluate" },
  "trust_bundleBatchRevoke": { method: "GET", path: "/trust-bundle/batch-revoke" },
  "trust_bundleCheckDecisionsHaveBundles": { method: "GET", path: "/trust-bundle/check-decisions-have-bundles" },
  "trust_bundleCreate": { method: "GET", path: "/trust-bundle/create" },
  "trust_bundleCreateBatchExport": { method: "GET", path: "/trust-bundle/create-batch-export" },
  "trust_bundleCreateForDecision": { method: "GET", path: "/trust-bundle/create-for-decision" },
  "trust_bundleDetail": { method: "GET", path: "/trust-bundle/detail" },
  "trust_bundleDownloadBatchExport": { method: "GET", path: "/trust-bundle/download-batch-export" },
  "trust_bundleDownloadBundlePdf": { method: "GET", path: "/trust-bundle/download-bundle-pdf" },
  "trust_bundleEvaluate": { method: "GET", path: "/trust-bundle/evaluate" },
  "trust_bundleEvaluationHistory": { method: "GET", path: "/trust-bundle/evaluation-history" },
  "trust_bundleEvaluationStats": { method: "GET", path: "/trust-bundle/evaluation-stats" },
  "trust_bundleEvidenceWeights": { method: "GET", path: "/trust-bundle/evidence-weights" },
  "trust_bundleExportJson": { method: "GET", path: "/trust-bundle/export-json" },
  "trust_bundleGeneratePdfContent": { method: "GET", path: "/trust-bundle/generate-pdf-content" },
  "trust_bundleGenerateQuotePdf": { method: "GET", path: "/trust-bundle/generate-quote-pdf" },
  "trust_bundleGetBatchExportFile": { method: "GET", path: "/trust-bundle/get-batch-export-file" },
  "trust_bundleGetBatchExportStatus": { method: "GET", path: "/trust-bundle/get-batch-export-status" },
  "trust_bundleGetDeliveryHistory": { method: "GET", path: "/trust-bundle/get-delivery-history" },
  "trust_bundleList": { method: "GET", path: "/trust-bundle/list" },
  "trust_bundleListBatchExports": { method: "GET", path: "/trust-bundle/list-batch-exports" },
  "trust_bundleManualReEvaluate": { method: "GET", path: "/trust-bundle/manual-re-evaluate" },
  "trust_bundleReEvaluateOnThresholdChange": { method: "GET", path: "/trust-bundle/re-evaluate-on-threshold-change" },
  "trust_bundleRevoke": { method: "GET", path: "/trust-bundle/revoke" },
  "trust_bundleStats": { method: "GET", path: "/trust-bundle/stats" },
  "trust_bundleSufficiencyThresholds": { method: "GET", path: "/trust-bundle/sufficiency-thresholds" },
  "trust_bundleVerifyDelivery": { method: "GET", path: "/trust-bundle/verify-delivery" },
  "trust_bundleVerifyEvidence": { method: "GET", path: "/trust-bundle/verify-evidence" },
  "p6SovrEngineCheckNarrative": { method: "GET", path: "/p6/sovr-engine/check-narrative" },
  "p6SovrEngineDetectAdversarial": { method: "GET", path: "/p6/sovr-engine/detect-adversarial" },
  "p6SovrEngineHealth": { method: "GET", path: "/p6/sovr-engine/health" },
  "p6SovrEngineKillSwitchStatus": { method: "GET", path: "/p6/sovr-engine/kill-switch-status" },
  "p6SystemSettingsUpdate": { method: "GET", path: "/p6/system-settings/update" },
  "p6TemplateVersionCompleteAbTest": { method: "GET", path: "/p6/template-version/complete-ab-test" },
  "p6TemplateVersionCreateAbTestEmailTemplate": { method: "GET", path: "/p6/template-version/create-ab-test-email-template" },
  "p6TemplateVersionCreateImchannel": { method: "GET", path: "/p6/template-version/create-imchannel" },
  "p6TemplateVersionCreateTenantConfig": { method: "GET", path: "/p6/template-version/create-tenant-config" },
  "p6TemplateVersionPublishVersion": { method: "GET", path: "/p6/template-version/publish-version" },
  "p6TemplateVersionUpdateAbTestEmailTemplate": { method: "GET", path: "/p6/template-version/update-ab-test-email-template" },
  "p6TemplateVersionUpdateAbTestStatus": { method: "GET", path: "/p6/template-version/update-ab-test-status" },
  "p6TemplateVersionUpdateAutoTriggerConfig": { method: "GET", path: "/p6/template-version/update-auto-trigger-config" },
  "p6TemplateVersionUpdateImchannel": { method: "GET", path: "/p6/template-version/update-imchannel" },
  "p6TemplateVersionVerifyImchannel": { method: "GET", path: "/p6/template-version/verify-imchannel" },
  "p6TenantCreate": { method: "GET", path: "/p6/tenant/create" },
  "p6TenantGet": { method: "GET", path: "/p6/tenant/get" },
  "p6TenantGetQuotaUsage": { method: "GET", path: "/p6/tenant/get-quota-usage" },
  "p6TenantList": { method: "GET", path: "/p6/tenant/list" },
  "p6TenantUpdateStatus": { method: "GET", path: "/p6/tenant/update-status" },
  "p6TrendsSeries": { method: "GET", path: "/p6/trends/series" },
  "p6TrendsSummary": { method: "GET", path: "/p6/trends/summary" },
  "p6TrustBundleActivate": { method: "GET", path: "/p6/trust-bundle/activate" },
  "p6TrustBundleBatchActivate": { method: "GET", path: "/p6/trust-bundle/batch-activate" },
  "p6TrustBundleBatchRevoke": { method: "GET", path: "/p6/trust-bundle/batch-revoke" },
  "p6TrustBundleCreate": { method: "GET", path: "/p6/trust-bundle/create" },
  "p6TrustBundleDetail": { method: "GET", path: "/p6/trust-bundle/detail" },
  "p6TrustBundleEvaluate": { method: "GET", path: "/p6/trust-bundle/evaluate" },
  "p6TrustBundleList": { method: "GET", path: "/p6/trust-bundle/list" },
  "p6TrustBundleReEvaluateOnThresholdChange": { method: "GET", path: "/p6/trust-bundle/re-evaluate-on-threshold-change" },
  "p6TrustBundleRevoke": { method: "GET", path: "/p6/trust-bundle/revoke" },
  "p6TrustBundleStats": { method: "GET", path: "/p6/trust-bundle/stats" },
  "p6UserList": { method: "GET", path: "/p6/user/list" },
  "p6UserListRoleRequests": { method: "GET", path: "/p6/user/list-role-requests" },
  "p6UserPendingRoleRequests": { method: "GET", path: "/p6/user/pending-role-requests" },
  "p6UserReviewRoleRequest": { method: "GET", path: "/p6/user/review-role-request" },
  "p6UserRoleRequestStats": { method: "GET", path: "/p6/user/role-request-stats" },
  "p6VaultStatus": { method: "GET", path: "/p6/vault/status" },
  "p6VaultTenantQuotas": { method: "GET", path: "/p6/vault/tenant-quotas" },
  "p6VaultWebhookConfig": { method: "GET", path: "/p6/vault/webhook-config" },
  "p6VaultWebhookRules": { method: "GET", path: "/p6/vault/webhook-rules" },
  "p6VerificationCompareCheckpoints": { method: "GET", path: "/p6/verification/compare-checkpoints" },
  "p6VerificationCompareWithCurrent": { method: "GET", path: "/p6/verification/compare-with-current" },
  "p6VerificationConfigureEmail": { method: "GET", path: "/p6/verification/configure-email" },
  "p6VerificationConfigureSlack": { method: "GET", path: "/p6/verification/configure-slack" },
  "p6VerificationCreateCheckpoint": { method: "GET", path: "/p6/verification/create-checkpoint" },
  "p6VerificationDetectHallucination": { method: "GET", path: "/p6/verification/detect-hallucination" },
  "p6VerificationExecuteRollback": { method: "GET", path: "/p6/verification/execute-rollback" },
  "p6VerificationExportTrustScoreHistory": { method: "GET", path: "/p6/verification/export-trust-score-history" },
  "p6VerificationGenerateCertificate": { method: "GET", path: "/p6/verification/generate-certificate" },
  "p6VerificationGenerateDiffReport": { method: "GET", path: "/p6/verification/generate-diff-report" },
  "p6VerificationGetAdjacentDiffs": { method: "GET", path: "/p6/verification/get-adjacent-diffs" },
  "p6VerificationGetCheckpoint": { method: "GET", path: "/p6/verification/get-checkpoint" },
  "p6VerificationGetLatestSafeCheckpoint": { method: "GET", path: "/p6/verification/get-latest-safe-checkpoint" },
  "p6VerificationGetMaintenanceMode": { method: "GET", path: "/p6/verification/get-maintenance-mode" },
  "p6VerificationGetNotificationHistory": { method: "GET", path: "/p6/verification/get-notification-history" },
  "p6VerificationGetRealTrustScoreTrend": { method: "GET", path: "/p6/verification/get-real-trust-score-trend" },
  "p6VerificationGetRollbackHistory": { method: "GET", path: "/p6/verification/get-rollback-history" },
  "p6VerificationGetRollbackPolicy": { method: "GET", path: "/p6/verification/get-rollback-policy" },
  "p6VerificationGetSystemTrustStatus": { method: "GET", path: "/p6/verification/get-system-trust-status" },
  "p6VerificationGetTrustScoreTrend": { method: "GET", path: "/p6/verification/get-trust-score-trend" },
  "p6VerificationListCheckpoints": { method: "GET", path: "/p6/verification/list-checkpoints" },
  "p6VerificationQuickCompareLatest": { method: "POST", path: "/p6/verification/quick-compare-latest" },
  "p6VerificationQuickFactCheck": { method: "GET", path: "/p6/verification/quick-fact-check" },
  "p6VerificationQuickHallucinationCheck": { method: "GET", path: "/p6/verification/quick-hallucination-check" },
  "p6VerificationSendTelegramTest": { method: "GET", path: "/p6/verification/send-telegram-test" },
  "p6VerificationSetMaintenanceMode": { method: "GET", path: "/p6/verification/set-maintenance-mode" },
  "p6VerificationTestNotification": { method: "POST", path: "/p6/verification/test-notification" },
  "p6VerificationUpdateRollbackPolicy": { method: "GET", path: "/p6/verification/update-rollback-policy" },
  "p6VerificationVerifyCertificate": { method: "GET", path: "/p6/verification/verify-certificate" },
  "p6WebhookDeliveryLogs": { method: "GET", path: "/p6/webhook/delivery-logs" },
  "p6WebhookDispatch": { method: "GET", path: "/p6/webhook/dispatch" },
  "p6WebhookList": { method: "GET", path: "/p6/webhook/list" },
  "p6WebhookTest": { method: "GET", path: "/p6/webhook/test" },
  "p6WebhookUpdateRetryConfig": { method: "GET", path: "/p6/webhook/update-retry-config" },
  "p3_fusionDataGovernanceExecuteQualityCheck": { method: "POST", path: "/p3-fusion/data-governance/execute-quality-check" },
  "p3_fusionPrivacyListConsentRecords": { method: "GET", path: "/p3-fusion/privacy/list-consent-records" },
  "p3_fusionComplianceGetReport": { method: "GET", path: "/p3-fusion/compliance/get-report" },
  "p3_fusionComplianceGetSchedule": { method: "GET", path: "/p3-fusion/compliance/get-schedule" },
  "p3_fusionComplianceGetSchedulerDashboard": { method: "GET", path: "/p3-fusion/compliance/get-scheduler-dashboard" },
  "p3_fusionComplianceRunComplianceCheck": { method: "POST", path: "/p3-fusion/compliance/run-compliance-check" },
  "p3_fusionSaasActivateTenant": { method: "POST", path: "/p3-fusion/saas/activate-tenant" },
  "p3_fusionSaasCreateTenant": { method: "POST", path: "/p3-fusion/saas/create-tenant" },
  "p3_fusionSaasGetSubscriptionStats": { method: "GET", path: "/p3-fusion/saas/get-subscription-stats" },
  "p3_fusionSaasGetTenant": { method: "GET", path: "/p3-fusion/saas/get-tenant" },
  "p3_fusionSaasListTenants": { method: "GET", path: "/p3-fusion/saas/list-tenants" },
  "p3_fusionScoringGetModel": { method: "GET", path: "/p3-fusion/scoring/get-model" },
  "p3_fusionPolicyActivatePolicy": { method: "POST", path: "/p3-fusion/policy/activate-policy" },
  "p3_fusionPolicyCreatePolicy": { method: "POST", path: "/p3-fusion/policy/create-policy" },
  "p3_fusionPolicyGetPolicy": { method: "GET", path: "/p3-fusion/policy/get-policy" },
  "p3_fusionSeedGetStatus": { method: "GET", path: "/p3-fusion/seed/get-status" },
  "p0IrreversibleProcessApproval": { method: "POST", path: "/p0/irreversible/process-approval" },
  "p0IrreversibleRequestApproval": { method: "POST", path: "/p0/irreversible/request-approval" },
  "monitoringAlertRulesList": { method: "GET", path: "/monitoring/alert-rules-list" },
  "monitoringMetricHistoryData": { method: "GET", path: "/monitoring/metric-history-data" },
  "gateConfigData": { method: "GET", path: "/gate/config-data" },
  "gateHighRiskActionsList": { method: "GET", path: "/gate/high-risk-actions-list" },
  "default_denyKnownActionsList": { method: "GET", path: "/default-deny/known-actions-list" },
  "p6AuditChainData": { method: "GET", path: "/p6/audit/chain-data" },
  "p6Report": { method: "GET", path: "/p6/report" },
  // ── Cloud MCP Server parity routes (v5.4.0) ──────────────────────────────
  "cloudStatus": { method: "GET", path: "/cloud-status" },
  "escalate": { method: "POST", path: "/escalate" },
  "pollEscalation": { method: "GET", path: "/poll-escalation" },
  "queryDecisions": { method: "GET", path: "/decisions" },
  "queryViolations": { method: "GET", path: "/violations" },
  "reportViolation": { method: "POST", path: "/violation" },
  "getViolationStats": { method: "GET", path: "/violation-stats" },
  // ── Parity batch: 72 missing MCP API routes ──
  "approvalDetail": { method: "GET", path: "/approval/detail" },
  "auditRegressionGetLatestRuns": { method: "GET", path: "/audit-regression/get-latest-runs" },
  "auditDetail": { method: "GET", path: "/audit/detail" },
  "auditTrail": { method: "GET", path: "/audit/trail" },
  "auditVerify": { method: "GET", path: "/audit/verify" },
  "budgetHistory": { method: "GET", path: "/budget/history" },
  "bundlesList": { method: "GET", path: "/bundles" },
  "integrationApiKeyUsageStats": { method: "GET", path: "/integration/api-key-usage-stats" },
  "meteringActionTypeTrend": { method: "GET", path: "/metering/action-type-trend" },
  "meteringDailyStats": { method: "GET", path: "/metering/daily-stats" },
  "meteringTopActionTypes": { method: "GET", path: "/metering/top-action-types" },
  "meteringUsageStats": { method: "GET", path: "/metering/usage-stats" },
  "monitoringMetrics": { method: "GET", path: "/monitoring/metrics" },
  "openGuardCustomPatterns": { method: "GET", path: "/open-guard/custom-patterns" },
  "openGuardGetCustomPattern": { method: "GET", path: "/open-guard/get-custom-pattern" },
  "openGuardScanStats": { method: "GET", path: "/open-guard/scan-stats" },
  "p0Disputes": { method: "GET", path: "/p0/disputes" },
  "p0ListIncidents": { method: "GET", path: "/p0/list-incidents" },
  "p1p2Bundle": { method: "GET", path: "/p1p2/bundle" },
  "p1p2CanaryReplay": { method: "POST", path: "/p1p2/canary/replay" },
  "p1p2ConstraintTrend": { method: "GET", path: "/p1p2/constraint-trend" },
  "p1p2Dashboard": { method: "GET", path: "/p1p2/dashboard" },
  "p1p2DegradeResolve": { method: "POST", path: "/p1p2/degrade/resolve" },
  "p3FusionAssets": { method: "GET", path: "/p3-fusion/assets" },
  "p3FusionAutomationEvents": { method: "GET", path: "/p3-fusion/automation/events" },
  "p3FusionComplianceControls": { method: "GET", path: "/p3-fusion/compliance/controls" },
  "p3FusionComplianceReports": { method: "GET", path: "/p3-fusion/compliance/reports" },
  "p3FusionPolicies": { method: "GET", path: "/p3-fusion/policies" },
  "p3FusionPrivacyConsentRecords": { method: "GET", path: "/p3-fusion/privacy/consent-records" },
  "p3FusionRiskAssessments": { method: "GET", path: "/p3-fusion/risk/assessments" },
  "p3FusionRiskDefinitions": { method: "GET", path: "/p3-fusion/risk/definitions" },
  "p3FusionRiskIncidents": { method: "GET", path: "/p3-fusion/risk/incidents" },
  "p3FusionRiskMitigations": { method: "GET", path: "/p3-fusion/risk/mitigations" },
  "p3FusionSchedulerExecutions": { method: "GET", path: "/p3-fusion/scheduler/executions" },
  "p3FusionSchedulerSchedules": { method: "GET", path: "/p3-fusion/scheduler/schedules" },
  "p3FusionSubscriptions": { method: "GET", path: "/p3-fusion/subscriptions" },
  "p3FusionTenants": { method: "GET", path: "/p3-fusion/tenants" },
  "p3FusionTenantsDashboard": { method: "GET", path: "/p3-fusion/tenants/dashboard" },
  "p3FusionTrustScoreHistory": { method: "GET", path: "/p3-fusion/trust-score/history" },
  "p3FusionTrustScoreLatest": { method: "GET", path: "/p3-fusion/trust-score/latest" },
  "p3FusionTrustScoreModels": { method: "GET", path: "/p3-fusion/trust-score/models" },
  "p3AuditRegressionRunsLatest": { method: "GET", path: "/p3/audit-regression/runs/latest" },
  "p3DataGovernanceLineage": { method: "GET", path: "/p3/data-governance/lineage" },
  "p3Experiments": { method: "POST", path: "/p3/experiments" },
  "p3ModelOpsAbTests": { method: "GET", path: "/p3/model-ops/ab-tests" },
  "p3ModelOpsCircuitBreaker": { method: "GET", path: "/p3/model-ops/circuit-breaker" },
  "p3ModelOpsRoutingLog": { method: "GET", path: "/p3/model-ops/routing-log" },
  "p3ModelOpsUsageStats": { method: "GET", path: "/p3/model-ops/usage-stats" },
  "p3TaskQueue": { method: "GET", path: "/p3/task-queue" },
  "p3TaskQueueDeadLetter": { method: "GET", path: "/p3/task-queue/dead-letter" },
  "p3TaskQueueList": { method: "GET", path: "/p3/task-queue/list" },
  "p3Tasks": { method: "GET", path: "/p3/tasks" },
  "p3WebhooksDeliveryLogs": { method: "GET", path: "/p3/webhooks/delivery-logs" },
  "p3WebhooksRule": { method: "GET", path: "/p3/webhooks/rule" },
  "rbacRolePermissions": { method: "GET", path: "/rbac/role-permissions" },
  "rulesList": { method: "GET", path: "/rules" },
  "stripeAuditorAccounts": { method: "GET", path: "/stripe/auditor-accounts" },
  "stripeDeploymentAddonEligibility": { method: "GET", path: "/stripe/deployment-addon-eligibility" },
  "stripePayments": { method: "GET", path: "/stripe/payments" },
  "stripeQuotaPool": { method: "GET", path: "/stripe/quota-pool" },
  "stripeUsageHistory": { method: "GET", path: "/stripe/usage-history" },
  "stripeUsageTrend": { method: "GET", path: "/stripe/usage-trend" },
  "taskQueueDeadLetterQueue": { method: "GET", path: "/task-queue/dead-letter-queue" },
  "verificationAdjacentDiffs": { method: "GET", path: "/verification/adjacent-diffs" },
  "verificationApiTimeSeries": { method: "GET", path: "/verification/api-time-series" },
  "verificationCheckpoint": { method: "GET", path: "/verification/checkpoint" },
  "verificationExportTrustScoreHistory": { method: "GET", path: "/verification/export-trust-score-history" },
  "verificationListCheckpoints": { method: "GET", path: "/verification/list-checkpoints" },
  "verificationNotificationHistory": { method: "GET", path: "/verification/notification-history" },
  "verificationRealTrustScoreTrend": { method: "GET", path: "/verification/real-trust-score-trend" },
  "verificationRollbackHistory": { method: "GET", path: "/verification/rollback-history" },
  "verificationTrustScoreTrend": { method: "GET", path: "/verification/trust-score-trend" }
};
async function cloudDispatch(toolName, operation, params) {
  if (!hasCloud()) {
    return fmt({
      status: "unavailable",
      tool: toolName,
      operation,
      message: "Requires SOVR Cloud. Set SOVR_API_KEY and SOVR_ENDPOINT.",
      cloud_upgrade: "https://sovr.inc/cloud"
    });
  }
  if (operation === "list") {
    const toolOps = Object.keys(SDK_ROUTES).filter((k) => {
      const toolSuffix = toolName.replace("sovr_", "").toLowerCase();
      return k.toLowerCase().includes(toolSuffix) || k.toLowerCase().startsWith(toolSuffix.slice(0, 4));
    });
    return fmt({
      status: "success",
      tool: toolName,
      message: `Available operations for ${toolName}. Pass the operation name as the 'operation' parameter.`,
      operations: toolOps.length > 0 ? toolOps : ["Contact SOVR Cloud support or check docs at sovr.inc"],
      total: toolOps.length
    });
  }
  const route = SDK_ROUTES[operation];
  if (!route) {
    return fmt({ status: "error", message: `Unknown operation: ${operation}. Use operation="list" to see available operations.`, tool: toolName });
  }
  const CLOUD_API_PATHS = /* @__PURE__ */ new Set([
    "/gate-check",
    "/grant-permit",
    "/submit-receipt",
    "/replay-decision",
    "/export-bundle",
    "/status",
    "/request-approval",
    "/permit",
    "/openguard-scan",
    "/openguard-quick-scan",
    "/openguard-stats",
    "/role-request-stats",
    "/cloud-status",
    "/escalate",
    "/poll-escalation",
    "/decisions",
    "/violations",
    "/violation",
    "/violation-stats"
  ]);
  const isCloudApiPath = CLOUD_API_PATHS.has(route.path) || route.path.startsWith("/gate-check");
  const apiPrefix = isCloudApiPath ? "/api/sovr/v1/cloud" : "/api/mcp";
  const apiPath = `${apiPrefix}${route.path.startsWith("/") ? "" : "/"}${route.path}`;
  try {
    let resp;
    if (route.method === "GET") {
      const qs = Object.entries(params).filter(([, v]) => v !== void 0 && v !== null).map(([k, v]) => `${encodeURIComponent(k)}=${encodeURIComponent(String(v))}`).join("&");
      resp = await cloudGet(`${apiPath}${qs ? "?" + qs : ""}`, 15e3);
    } else {
      resp = await cloudRequest(apiPath, params, 15e3);
    }
    if (resp.ok) {
      return fmt({ status: "success", operation, ...typeof resp.data === "object" && resp.data !== null ? resp.data : { data: resp.data } });
    }
    return fmt({ status: "error", operation, message: resp.error });
  } catch (err) {
    return fmt({ status: "error", operation, message: err instanceof Error ? err.message : String(err) });
  }
}
var TOOLS = [
  // ── Auto-synced domains from MCP Proxy ──
  {
    name: "sovr_audit_replay",
    description: "Manage audit replay operations. Available operations: audit_replayCompareSnapshots, audit_replayCreateSnapshot, audit_replayGetEntitySnapshots",
    inputSchema: { type: "object", properties: { operation: { type: "string", description: "Operation name" }, params: { type: "object", description: "Operation parameters" } }, required: ["operation"] }
  },
  {
    name: "sovr_health_check",
    description: "Manage health check operations. Available operations: health_checkAcknowledgeAlert, health_checkAggregatedHealth, health_checkAlertHistory, health_checkCreateTestAlert, health_checkListAlerts, health_checkModuleHealth, health_checkResolveAlert",
    inputSchema: { type: "object", properties: { operation: { type: "string", description: "Operation name" }, params: { type: "object", description: "Operation parameters" } }, required: ["operation"] }
  },
  {
    name: "sovr_monitoring",
    description: "Manage monitoring operations. Available operations: monitoringHealthCheck, monitoringRecordMetric, monitoringAlertRulesList, monitoringMetricHistoryData",
    inputSchema: { type: "object", properties: { operation: { type: "string", description: "Operation name" }, params: { type: "object", description: "Operation parameters" } }, required: ["operation"] }
  },
  {
    name: "sovr_open_guard",
    description: "Manage open guard operations. Available operations: open_guardGeoStats, open_guardPatterns, open_guardQuickScan, open_guardScan, open_guardScanLogs, open_guardSemanticModels, open_guardStats",
    inputSchema: { type: "object", properties: { operation: { type: "string", description: "Operation name" }, params: { type: "object", description: "Operation parameters" } }, required: ["operation"] }
  },
  {
    name: "sovr_p0",
    description: "Manage p0 operations. Available operations: p0IrreversibleProcessApproval, p0IrreversibleRequestApproval",
    inputSchema: { type: "object", properties: { operation: { type: "string", description: "Operation name" }, params: { type: "object", description: "Operation parameters" } }, required: ["operation"] }
  },
  {
    name: "sovr_p3_fusion",
    description: "Manage p3 fusion operations. Available operations: p3_fusionDataGovernanceExecuteQualityCheck, p3_fusionPrivacyListConsentRecords, p3_fusionComplianceGetReport, p3_fusionComplianceGetSchedule, p3_fusionComplianceGetSchedulerDashboard, p3_fusionComplianceRunComplianceCheck, p3_fusionSaasActivateTenant, p3_fusionSaasCreateTenant, p3_fusionSaasGetSubscriptionStats, p3_fusionSaasGetTenant... and 6 more",
    inputSchema: { type: "object", properties: { operation: { type: "string", description: "Operation name" }, params: { type: "object", description: "Operation parameters" } }, required: ["operation"] }
  },
  {
    name: "sovr_p5",
    description: "Manage p5 operations. Available operations: p5VerifyFact, p5RunVerificationPipeline, p5CreateP1P2Bundle, p5ClearP1P2Cache, p5DeleteP3WebhookRule, p5SendP3Test, p5ResolvePolicyConflict, p5DeleteFusionRule, p5RefreshRuleCache, p5FormatStripePrice... and 10 more",
    inputSchema: { type: "object", properties: { operation: { type: "string", description: "Operation name" }, params: { type: "object", description: "Operation parameters" } }, required: ["operation"] }
  },
  {
    name: "sovr_p6",
    description: "Manage p6 operations. Available operations: p6AgentIntegrationConfigureCallback, p6AgentIntegrationGetIntegrationGuide, p6AgentIntegrationRegister, p6AgentIntegrationReportOperation, p6AiRiskAssessment, p6AlertAcknowledge, p6AlertCreateRule, p6AlertCreateTemplate, p6AlertExportRules, p6AlertGetRule... and 230 more",
    inputSchema: { type: "object", properties: { operation: { type: "string", description: "Operation name" }, params: { type: "object", description: "Operation parameters" } }, required: ["operation"] }
  },
  {
    name: "sovr_status_v2",
    description: "Manage status v2 operations. Available operations: status_v2",
    inputSchema: { type: "object", properties: { operation: { type: "string", description: "Operation name" }, params: { type: "object", description: "Operation parameters" } }, required: ["operation"] }
  },
  {
    name: "sovr_trust_bundle",
    description: "Manage trust bundle operations. Available operations: trust_bundleActivate, trust_bundleAddEvidence, trust_bundleBatchActivate, trust_bundleBatchCreateForDecisions, trust_bundleBatchExport, trust_bundleBatchManualReEvaluate, trust_bundleBatchReEvaluate, trust_bundleBatchRevoke, trust_bundleCheckDecisionsHaveBundles, trust_bundleCreate... and 24 more",
    inputSchema: { type: "object", properties: { operation: { type: "string", description: "Operation name" }, params: { type: "object", description: "Operation parameters" } }, required: ["operation"] }
  },
  // ── Original 13 local tools (v3.1.0 compatible) ──────────────────────────
  {
    name: "sovr_gate_check",
    description: "Evaluate an action against SOVR policy rules before execution. Returns allow/deny/escalate verdict with risk score. ALWAYS call this BEFORE performing any potentially dangerous action.",
    inputSchema: { type: "object", properties: { action: { type: "string", description: 'The action to evaluate (e.g. "send_payment", "delete_record")' }, resource: { type: "string", description: 'The target resource (e.g. "stripe/charges", "users_table")' }, channel: { type: "string", description: "Channel: mcp, http, sql, or exec", enum: ["mcp", "http", "sql", "exec"] }, context: { type: "object", description: "Additional context" } }, required: ["action", "resource"] }
  },
  {
    name: "sovr_check_command",
    description: "Check if a shell command is safe. Parses the command, detects risk indicators, evaluates against rules.",
    inputSchema: { type: "object", properties: { command: { type: "string", description: "Full shell command" } }, required: ["command"] }
  },
  {
    name: "sovr_check_sql",
    description: "Check if a SQL statement is safe. Detects DDL, dangerous DML, permission changes.",
    inputSchema: { type: "object", properties: { sql: { type: "string", description: "SQL statement" } }, required: ["sql"] }
  },
  {
    name: "sovr_check_http",
    description: "Check if an outbound HTTP request is safe.",
    inputSchema: { type: "object", properties: { method: { type: "string", description: "HTTP method" }, url: { type: "string", description: "Target URL" } }, required: ["method", "url"] }
  },
  {
    name: "sovr_request_approval",
    description: "Request human approval for a high-risk action.",
    inputSchema: { type: "object", properties: { action: { type: "string" }, resource: { type: "string" }, reason: { type: "string" }, urgency: { type: "string", enum: ["low", "medium", "high", "critical"] } }, required: ["action", "resource", "reason"] }
  },
  {
    name: "sovr_submit_receipt",
    description: "Report execution result back to SOVR for audit trail. Automatically obtains permit and computes evidence hash.",
    inputSchema: { type: "object", properties: { decision_id: { type: "string", description: "The decision ID from gate_check" }, status: { type: "string", enum: ["success", "failure", "partial", "rollback"], description: "Execution outcome" }, output_summary: { type: "string", description: "Brief summary of what was executed" }, external_ref: { type: "string", description: "External reference ID" }, artifact_refs: { type: "array", items: { type: "string" }, description: "References to output artifacts" } }, required: ["decision_id", "status"] }
  },
  {
    name: "sovr_add_rule",
    description: "Add a custom policy rule for the current session.",
    inputSchema: { type: "object", properties: { id: { type: "string" }, description: { type: "string" }, channels: { type: "array", items: { type: "string", enum: ["mcp", "http", "sql", "exec"] } }, action_pattern: { type: "string" }, resource_pattern: { type: "string" }, effect: { type: "string", enum: ["allow", "deny", "escalate"] }, risk_level: { type: "string", enum: ["none", "low", "medium", "high", "critical"] }, priority: { type: "number" } }, required: ["id", "description", "channels", "action_pattern", "resource_pattern", "effect"] }
  },
  {
    name: "sovr_audit_log",
    description: "View recent audit log entries.",
    inputSchema: { type: "object", properties: { limit: { type: "number" }, channel: { type: "string", enum: ["mcp", "http", "sql", "exec"] }, verdict: { type: "string", enum: ["allow", "deny", "escalate"] } } }
  },
  // ── Cloud MCP Server parity tools (v5.4.0) ─────────────────────────────
  {
    name: "sovr_cloud_status",
    description: "Check SOVR Cloud API health and connectivity status.",
    inputSchema: { type: "object", properties: {} }
  },
  {
    name: "sovr_escalate",
    description: "Manually escalate an action for human approval. Creates an escalation request with Telegram/webhook notification.",
    inputSchema: { type: "object", properties: { action: { type: "string", description: "Action being escalated" }, resource: { type: "string", description: "Resource being acted on" }, reason: { type: "string", description: "Why escalation is needed" }, context: { type: "object", description: "Additional context" } }, required: ["action", "resource", "reason"] }
  },
  {
    name: "sovr_poll_escalation",
    description: "Poll the status of a pending escalation request.",
    inputSchema: { type: "object", properties: { decision_id: { type: "string", description: "Decision ID from escalation" } }, required: ["decision_id"] }
  },
  {
    name: "sovr_query_decisions",
    description: "Query historical gate-check decisions with optional filters.",
    inputSchema: { type: "object", properties: { limit: { type: "number" }, verdict: { type: "string", enum: ["allow", "deny", "escalate"] }, action: { type: "string" }, from: { type: "string", description: "ISO date string" }, to: { type: "string", description: "ISO date string" } } }
  },
  {
    name: "sovr_query_violations",
    description: "Query violation records with optional filters.",
    inputSchema: { type: "object", properties: { limit: { type: "number" }, severity: { type: "string", enum: ["low", "medium", "high", "critical"] }, status: { type: "string", enum: ["open", "resolved", "dismissed"] } } }
  },
  {
    name: "sovr_report_violation",
    description: "Report a policy violation event for audit and alerting.",
    inputSchema: { type: "object", properties: { action: { type: "string" }, resource: { type: "string" }, violation_type: { type: "string" }, severity: { type: "string", enum: ["low", "medium", "high", "critical"] }, details: { type: "string" }, decision_id: { type: "string" } }, required: ["action", "resource", "violation_type", "severity"] }
  },
  {
    name: "sovr_get_violation_stats",
    description: "Get aggregated violation statistics.",
    inputSchema: { type: "object", properties: { period: { type: "string", enum: ["24h", "7d", "30d"], description: "Time period" } } }
  },
  {
    name: "sovr_replay_decision",
    description: "Replay a historical decision to see what would happen with current rules.",
    inputSchema: { type: "object", properties: { decision_id: { type: "string", description: "Decision ID to replay" } }, required: ["decision_id"] }
  },
  {
    name: "sovr_export_bundle",
    description: "Export a decision bundle with full audit trail for compliance.",
    inputSchema: { type: "object", properties: { decision_id: { type: "string" }, format: { type: "string", enum: ["json", "pdf"] } }, required: ["decision_id"] }
  },
  {
    name: "sovr_grant_permit",
    description: "Grant a time-limited permit for a specific action, bypassing normal gate-check.",
    inputSchema: { type: "object", properties: { action: { type: "string" }, resource: { type: "string" }, duration_minutes: { type: "number" }, reason: { type: "string" } }, required: ["action", "resource", "duration_minutes", "reason"] }
  },
  {
    name: "sovr_openguard_scan",
    description: "Run a full OpenGuard content safety scan on text.",
    inputSchema: { type: "object", properties: { content: { type: "string", description: "Content to scan" }, categories: { type: "array", items: { type: "string" }, description: "Categories to check" } }, required: ["content"] }
  },
  {
    name: "sovr_openguard_quick_scan",
    description: "Run a quick OpenGuard safety scan (faster, less thorough).",
    inputSchema: { type: "object", properties: { content: { type: "string", description: "Content to scan" } }, required: ["content"] }
  },
  {
    name: "sovr_adapter",
    description: 'SOVR Adapter. Cloud mode \u2014 run with operation="list" to discover available operations.',
    inputSchema: {
      type: "object",
      properties: {
        operation: { type: "string", description: 'Operation to perform. Run with operation="list" to see available operations.' },
        params: { type: "object", description: "Operation parameters (passed to SDK method)" }
      },
      required: ["operation"]
    }
  },
  {
    name: "sovr_ai_chat",
    description: 'SOVR Ai Chat. Cloud mode \u2014 run with operation="list" to discover available operations.',
    inputSchema: {
      type: "object",
      properties: {
        operation: { type: "string", description: 'Operation to perform. Run with operation="list" to see available operations.' },
        params: { type: "object", description: "Operation parameters (passed to SDK method)" }
      },
      required: ["operation"]
    }
  },
  {
    name: "sovr_api_key",
    description: 'SOVR Api Key. Cloud mode \u2014 run with operation="list" to discover available operations.',
    inputSchema: {
      type: "object",
      properties: {
        operation: { type: "string", description: 'Operation to perform. Run with operation="list" to see available operations.' },
        params: { type: "object", description: "Operation parameters (passed to SDK method)" }
      },
      required: ["operation"]
    }
  },
  {
    name: "sovr_approval",
    description: 'SOVR Approval. Cloud mode \u2014 run with operation="list" to discover available operations.',
    inputSchema: {
      type: "object",
      properties: {
        operation: { type: "string", description: 'Operation to perform. Run with operation="list" to see available operations.' },
        params: { type: "object", description: "Operation parameters (passed to SDK method)" }
      },
      required: ["operation"]
    }
  },
  {
    name: "sovr_arbitrate",
    description: 'SOVR Arbitrate. Cloud mode \u2014 run with operation="list" to discover available operations.',
    inputSchema: {
      type: "object",
      properties: {
        operation: { type: "string", description: 'Operation to perform. Run with operation="list" to see available operations.' },
        params: { type: "object", description: "Operation parameters (passed to SDK method)" }
      },
      required: ["operation"]
    }
  },
  {
    name: "sovr_assign_to",
    description: 'SOVR Assign To. Cloud mode \u2014 run with operation="list" to discover available operations.',
    inputSchema: {
      type: "object",
      properties: {
        operation: { type: "string", description: 'Operation to perform. Run with operation="list" to see available operations.' },
        params: { type: "object", description: "Operation parameters (passed to SDK method)" }
      },
      required: ["operation"]
    }
  },
  {
    name: "sovr_audit",
    description: 'SOVR Audit. Cloud mode \u2014 run with operation="list" to discover available operations.',
    inputSchema: {
      type: "object",
      properties: {
        operation: { type: "string", description: 'Operation to perform. Run with operation="list" to see available operations.' },
        params: { type: "object", description: "Operation parameters (passed to SDK method)" }
      },
      required: ["operation"]
    }
  },
  {
    name: "sovr_backup",
    description: 'SOVR Backup. Cloud mode \u2014 run with operation="list" to discover available operations.',
    inputSchema: {
      type: "object",
      properties: {
        operation: { type: "string", description: 'Operation to perform. Run with operation="list" to see available operations.' },
        params: { type: "object", description: "Operation parameters (passed to SDK method)" }
      },
      required: ["operation"]
    }
  },
  {
    name: "sovr_balance",
    description: 'SOVR Balance. Cloud mode \u2014 run with operation="list" to discover available operations.',
    inputSchema: {
      type: "object",
      properties: {
        operation: { type: "string", description: 'Operation to perform. Run with operation="list" to see available operations.' },
        params: { type: "object", description: "Operation parameters (passed to SDK method)" }
      },
      required: ["operation"]
    }
  },
  {
    name: "sovr_batch_ops",
    description: 'SOVR Batch Ops. Cloud mode \u2014 run with operation="list" to discover available operations.',
    inputSchema: {
      type: "object",
      properties: {
        operation: { type: "string", description: 'Operation to perform. Run with operation="list" to see available operations.' },
        params: { type: "object", description: "Operation parameters (passed to SDK method)" }
      },
      required: ["operation"]
    }
  },
  {
    name: "sovr_budget",
    description: 'SOVR Budget. Cloud mode \u2014 run with operation="list" to discover available operations.',
    inputSchema: {
      type: "object",
      properties: {
        operation: { type: "string", description: 'Operation to perform. Run with operation="list" to see available operations.' },
        params: { type: "object", description: "Operation parameters (passed to SDK method)" }
      },
      required: ["operation"]
    }
  },
  {
    name: "sovr_bundle",
    description: 'SOVR Bundle. Cloud mode \u2014 run with operation="list" to discover available operations.',
    inputSchema: {
      type: "object",
      properties: {
        operation: { type: "string", description: 'Operation to perform. Run with operation="list" to see available operations.' },
        params: { type: "object", description: "Operation parameters (passed to SDK method)" }
      },
      required: ["operation"]
    }
  },
  {
    name: "sovr_calculate_aggregate",
    description: 'SOVR Calculate Aggregate. Cloud mode \u2014 run with operation="list" to discover available operations.',
    inputSchema: {
      type: "object",
      properties: {
        operation: { type: "string", description: 'Operation to perform. Run with operation="list" to see available operations.' },
        params: { type: "object", description: "Operation parameters (passed to SDK method)" }
      },
      required: ["operation"]
    }
  },
  {
    name: "sovr_canary",
    description: 'SOVR Canary. Cloud mode \u2014 run with operation="list" to discover available operations.',
    inputSchema: {
      type: "object",
      properties: {
        operation: { type: "string", description: 'Operation to perform. Run with operation="list" to see available operations.' },
        params: { type: "object", description: "Operation parameters (passed to SDK method)" }
      },
      required: ["operation"]
    }
  },
  {
    name: "sovr_cancel_deployment",
    description: 'SOVR Cancel Deployment. Cloud mode \u2014 run with operation="list" to discover available operations.',
    inputSchema: {
      type: "object",
      properties: {
        operation: { type: "string", description: 'Operation to perform. Run with operation="list" to see available operations.' },
        params: { type: "object", description: "Operation parameters (passed to SDK method)" }
      },
      required: ["operation"]
    }
  },
  {
    name: "sovr_cleanup",
    description: 'SOVR Cleanup. Cloud mode \u2014 run with operation="list" to discover available operations.',
    inputSchema: {
      type: "object",
      properties: {
        operation: { type: "string", description: 'Operation to perform. Run with operation="list" to see available operations.' },
        params: { type: "object", description: "Operation parameters (passed to SDK method)" }
      },
      required: ["operation"]
    }
  },
  {
    name: "sovr_cognitive",
    description: 'SOVR Cognitive. Cloud mode \u2014 run with operation="list" to discover available operations.',
    inputSchema: {
      type: "object",
      properties: {
        operation: { type: "string", description: 'Operation to perform. Run with operation="list" to see available operations.' },
        params: { type: "object", description: "Operation parameters (passed to SDK method)" }
      },
      required: ["operation"]
    }
  },
  {
    name: "sovr_compare_with",
    description: 'SOVR Compare With. Cloud mode \u2014 run with operation="list" to discover available operations.',
    inputSchema: {
      type: "object",
      properties: {
        operation: { type: "string", description: 'Operation to perform. Run with operation="list" to see available operations.' },
        params: { type: "object", description: "Operation parameters (passed to SDK method)" }
      },
      required: ["operation"]
    }
  },
  {
    name: "sovr_compliance",
    description: 'SOVR Compliance. Cloud mode \u2014 run with operation="list" to discover available operations.',
    inputSchema: {
      type: "object",
      properties: {
        operation: { type: "string", description: 'Operation to perform. Run with operation="list" to see available operations.' },
        params: { type: "object", description: "Operation parameters (passed to SDK method)" }
      },
      required: ["operation"]
    }
  },
  {
    name: "sovr_config",
    description: 'SOVR Config. Cloud mode \u2014 run with operation="list" to discover available operations.',
    inputSchema: {
      type: "object",
      properties: {
        operation: { type: "string", description: 'Operation to perform. Run with operation="list" to see available operations.' },
        params: { type: "object", description: "Operation parameters (passed to SDK method)" }
      },
      required: ["operation"]
    }
  },
  {
    name: "sovr_core_acknowledge",
    description: 'SOVR Core Acknowledge. Cloud mode \u2014 run with operation="list" to discover available operations.',
    inputSchema: {
      type: "object",
      properties: {
        operation: { type: "string", description: 'Operation to perform. Run with operation="list" to see available operations.' },
        params: { type: "object", description: "Operation parameters (passed to SDK method)" }
      },
      required: ["operation"]
    }
  },
  {
    name: "sovr_core_batch",
    description: 'SOVR Core Batch. Cloud mode \u2014 run with operation="list" to discover available operations.',
    inputSchema: {
      type: "object",
      properties: {
        operation: { type: "string", description: 'Operation to perform. Run with operation="list" to see available operations.' },
        params: { type: "object", description: "Operation parameters (passed to SDK method)" }
      },
      required: ["operation"]
    }
  },
  {
    name: "sovr_core_cancel",
    description: 'SOVR Core Cancel. Cloud mode \u2014 run with operation="list" to discover available operations.',
    inputSchema: {
      type: "object",
      properties: {
        operation: { type: "string", description: 'Operation to perform. Run with operation="list" to see available operations.' },
        params: { type: "object", description: "Operation parameters (passed to SDK method)" }
      },
      required: ["operation"]
    }
  },
  {
    name: "sovr_core_check",
    description: 'SOVR Core Check. Cloud mode \u2014 run with operation="list" to discover available operations.',
    inputSchema: {
      type: "object",
      properties: {
        operation: { type: "string", description: 'Operation to perform. Run with operation="list" to see available operations.' },
        params: { type: "object", description: "Operation parameters (passed to SDK method)" }
      },
      required: ["operation"]
    }
  },
  {
    name: "sovr_core_create",
    description: 'SOVR Core Create. Cloud mode \u2014 run with operation="list" to discover available operations.',
    inputSchema: {
      type: "object",
      properties: {
        operation: { type: "string", description: 'Operation to perform. Run with operation="list" to see available operations.' },
        params: { type: "object", description: "Operation parameters (passed to SDK method)" }
      },
      required: ["operation"]
    }
  },
  {
    name: "sovr_core_demo",
    description: 'SOVR Core Demo. Cloud mode \u2014 run with operation="list" to discover available operations.',
    inputSchema: {
      type: "object",
      properties: {
        operation: { type: "string", description: 'Operation to perform. Run with operation="list" to see available operations.' },
        params: { type: "object", description: "Operation parameters (passed to SDK method)" }
      },
      required: ["operation"]
    }
  },
  {
    name: "sovr_core_detail",
    description: 'SOVR Core Detail. Cloud mode \u2014 run with operation="list" to discover available operations.',
    inputSchema: {
      type: "object",
      properties: {
        operation: { type: "string", description: 'Operation to perform. Run with operation="list" to see available operations.' },
        params: { type: "object", description: "Operation parameters (passed to SDK method)" }
      },
      required: ["operation"]
    }
  },
  {
    name: "sovr_core_event",
    description: 'SOVR Core Event. Cloud mode \u2014 run with operation="list" to discover available operations.',
    inputSchema: {
      type: "object",
      properties: {
        operation: { type: "string", description: 'Operation to perform. Run with operation="list" to see available operations.' },
        params: { type: "object", description: "Operation parameters (passed to SDK method)" }
      },
      required: ["operation"]
    }
  },
  {
    name: "sovr_core_execute",
    description: 'SOVR Core Execute. Cloud mode \u2014 run with operation="list" to discover available operations.',
    inputSchema: {
      type: "object",
      properties: {
        operation: { type: "string", description: 'Operation to perform. Run with operation="list" to see available operations.' },
        params: { type: "object", description: "Operation parameters (passed to SDK method)" }
      },
      required: ["operation"]
    }
  },
  {
    name: "sovr_core_find",
    description: 'SOVR Core Find. Cloud mode \u2014 run with operation="list" to discover available operations.',
    inputSchema: {
      type: "object",
      properties: {
        operation: { type: "string", description: 'Operation to perform. Run with operation="list" to see available operations.' },
        params: { type: "object", description: "Operation parameters (passed to SDK method)" }
      },
      required: ["operation"]
    }
  },
  {
    name: "sovr_core_forgot",
    description: 'SOVR Core Forgot. Cloud mode \u2014 run with operation="list" to discover available operations.',
    inputSchema: {
      type: "object",
      properties: {
        operation: { type: "string", description: 'Operation to perform. Run with operation="list" to see available operations.' },
        params: { type: "object", description: "Operation parameters (passed to SDK method)" }
      },
      required: ["operation"]
    }
  },
  {
    name: "sovr_core_full",
    description: 'SOVR Core Full. Cloud mode \u2014 run with operation="list" to discover available operations.',
    inputSchema: {
      type: "object",
      properties: {
        operation: { type: "string", description: 'Operation to perform. Run with operation="list" to see available operations.' },
        params: { type: "object", description: "Operation parameters (passed to SDK method)" }
      },
      required: ["operation"]
    }
  },
  {
    name: "sovr_core_generate",
    description: 'SOVR Core Generate. Cloud mode \u2014 run with operation="list" to discover available operations.',
    inputSchema: {
      type: "object",
      properties: {
        operation: { type: "string", description: 'Operation to perform. Run with operation="list" to see available operations.' },
        params: { type: "object", description: "Operation parameters (passed to SDK method)" }
      },
      required: ["operation"]
    }
  },
  {
    name: "sovr_core_get",
    description: 'SOVR Core Get. Cloud mode \u2014 run with operation="list" to discover available operations.',
    inputSchema: {
      type: "object",
      properties: {
        operation: { type: "string", description: 'Operation to perform. Run with operation="list" to see available operations.' },
        params: { type: "object", description: "Operation parameters (passed to SDK method)" }
      },
      required: ["operation"]
    }
  },
  {
    name: "sovr_core_has",
    description: 'SOVR Core Has. Cloud mode \u2014 run with operation="list" to discover available operations.',
    inputSchema: {
      type: "object",
      properties: {
        operation: { type: "string", description: 'Operation to perform. Run with operation="list" to see available operations.' },
        params: { type: "object", description: "Operation parameters (passed to SDK method)" }
      },
      required: ["operation"]
    }
  },
  {
    name: "sovr_core_hot",
    description: 'SOVR Core Hot. Cloud mode \u2014 run with operation="list" to discover available operations.',
    inputSchema: {
      type: "object",
      properties: {
        operation: { type: "string", description: 'Operation to perform. Run with operation="list" to see available operations.' },
        params: { type: "object", description: "Operation parameters (passed to SDK method)" }
      },
      required: ["operation"]
    }
  },
  {
    name: "sovr_core_im",
    description: 'SOVR Core Im. Cloud mode \u2014 run with operation="list" to discover available operations.',
    inputSchema: {
      type: "object",
      properties: {
        operation: { type: "string", description: 'Operation to perform. Run with operation="list" to see available operations.' },
        params: { type: "object", description: "Operation parameters (passed to SDK method)" }
      },
      required: ["operation"]
    }
  },
  {
    name: "sovr_core_increment",
    description: 'SOVR Core Increment. Cloud mode \u2014 run with operation="list" to discover available operations.',
    inputSchema: {
      type: "object",
      properties: {
        operation: { type: "string", description: 'Operation to perform. Run with operation="list" to see available operations.' },
        params: { type: "object", description: "Operation parameters (passed to SDK method)" }
      },
      required: ["operation"]
    }
  },
  {
    name: "sovr_core_init",
    description: 'SOVR Core Init. Cloud mode \u2014 run with operation="list" to discover available operations.',
    inputSchema: {
      type: "object",
      properties: {
        operation: { type: "string", description: 'Operation to perform. Run with operation="list" to see available operations.' },
        params: { type: "object", description: "Operation parameters (passed to SDK method)" }
      },
      required: ["operation"]
    }
  },
  {
    name: "sovr_core_initialize",
    description: 'SOVR Core Initialize. Cloud mode \u2014 run with operation="list" to discover available operations.',
    inputSchema: {
      type: "object",
      properties: {
        operation: { type: "string", description: 'Operation to perform. Run with operation="list" to see available operations.' },
        params: { type: "object", description: "Operation parameters (passed to SDK method)" }
      },
      required: ["operation"]
    }
  },
  {
    name: "sovr_core_linked",
    description: 'SOVR Core Linked. Cloud mode \u2014 run with operation="list" to discover available operations.',
    inputSchema: {
      type: "object",
      properties: {
        operation: { type: "string", description: 'Operation to perform. Run with operation="list" to see available operations.' },
        params: { type: "object", description: "Operation parameters (passed to SDK method)" }
      },
      required: ["operation"]
    }
  },
  {
    name: "sovr_core_list",
    description: 'SOVR Core List. Cloud mode \u2014 run with operation="list" to discover available operations.',
    inputSchema: {
      type: "object",
      properties: {
        operation: { type: "string", description: 'Operation to perform. Run with operation="list" to see available operations.' },
        params: { type: "object", description: "Operation parameters (passed to SDK method)" }
      },
      required: ["operation"]
    }
  },
  {
    name: "sovr_core_load",
    description: 'SOVR Core Load. Cloud mode \u2014 run with operation="list" to discover available operations.',
    inputSchema: {
      type: "object",
      properties: {
        operation: { type: "string", description: 'Operation to perform. Run with operation="list" to see available operations.' },
        params: { type: "object", description: "Operation parameters (passed to SDK method)" }
      },
      required: ["operation"]
    }
  },
  {
    name: "sovr_core_login",
    description: 'SOVR Core Login. Cloud mode \u2014 run with operation="list" to discover available operations.',
    inputSchema: {
      type: "object",
      properties: {
        operation: { type: "string", description: 'Operation to perform. Run with operation="list" to see available operations.' },
        params: { type: "object", description: "Operation parameters (passed to SDK method)" }
      },
      required: ["operation"]
    }
  },
  {
    name: "sovr_core_logout",
    description: 'SOVR Core Logout. Cloud mode \u2014 run with operation="list" to discover available operations.',
    inputSchema: {
      type: "object",
      properties: {
        operation: { type: "string", description: 'Operation to perform. Run with operation="list" to see available operations.' },
        params: { type: "object", description: "Operation parameters (passed to SDK method)" }
      },
      required: ["operation"]
    }
  },
  {
    name: "sovr_core_manifest",
    description: 'SOVR Core Manifest. Cloud mode \u2014 run with operation="list" to discover available operations.',
    inputSchema: {
      type: "object",
      properties: {
        operation: { type: "string", description: 'Operation to perform. Run with operation="list" to see available operations.' },
        params: { type: "object", description: "Operation parameters (passed to SDK method)" }
      },
      required: ["operation"]
    }
  },
  {
    name: "sovr_core_manifests",
    description: 'SOVR Core Manifests. Cloud mode \u2014 run with operation="list" to discover available operations.',
    inputSchema: {
      type: "object",
      properties: {
        operation: { type: "string", description: 'Operation to perform. Run with operation="list" to see available operations.' },
        params: { type: "object", description: "Operation parameters (passed to SDK method)" }
      },
      required: ["operation"]
    }
  },
  {
    name: "sovr_core_manual",
    description: 'SOVR Core Manual. Cloud mode \u2014 run with operation="list" to discover available operations.',
    inputSchema: {
      type: "object",
      properties: {
        operation: { type: "string", description: 'Operation to perform. Run with operation="list" to see available operations.' },
        params: { type: "object", description: "Operation parameters (passed to SDK method)" }
      },
      required: ["operation"]
    }
  },
  {
    name: "sovr_core_me",
    description: 'SOVR Core Me. Cloud mode \u2014 run with operation="list" to discover available operations.',
    inputSchema: {
      type: "object",
      properties: {
        operation: { type: "string", description: 'Operation to perform. Run with operation="list" to see available operations.' },
        params: { type: "object", description: "Operation parameters (passed to SDK method)" }
      },
      required: ["operation"]
    }
  },
  {
    name: "sovr_core_my",
    description: 'SOVR Core My. Cloud mode \u2014 run with operation="list" to discover available operations.',
    inputSchema: {
      type: "object",
      properties: {
        operation: { type: "string", description: 'Operation to perform. Run with operation="list" to see available operations.' },
        params: { type: "object", description: "Operation parameters (passed to SDK method)" }
      },
      required: ["operation"]
    }
  },
  {
    name: "sovr_core_network",
    description: 'SOVR Core Network. Cloud mode \u2014 run with operation="list" to discover available operations.',
    inputSchema: {
      type: "object",
      properties: {
        operation: { type: "string", description: 'Operation to perform. Run with operation="list" to see available operations.' },
        params: { type: "object", description: "Operation parameters (passed to SDK method)" }
      },
      required: ["operation"]
    }
  },
  {
    name: "sovr_core_overview",
    description: 'SOVR Core Overview. Cloud mode \u2014 run with operation="list" to discover available operations.',
    inputSchema: {
      type: "object",
      properties: {
        operation: { type: "string", description: 'Operation to perform. Run with operation="list" to see available operations.' },
        params: { type: "object", description: "Operation parameters (passed to SDK method)" }
      },
      required: ["operation"]
    }
  },
  {
    name: "sovr_core_parse",
    description: 'SOVR Core Parse. Cloud mode \u2014 run with operation="list" to discover available operations.',
    inputSchema: {
      type: "object",
      properties: {
        operation: { type: "string", description: 'Operation to perform. Run with operation="list" to see available operations.' },
        params: { type: "object", description: "Operation parameters (passed to SDK method)" }
      },
      required: ["operation"]
    }
  },
  {
    name: "sovr_core_persisted",
    description: 'SOVR Core Persisted. Cloud mode \u2014 run with operation="list" to discover available operations.',
    inputSchema: {
      type: "object",
      properties: {
        operation: { type: "string", description: 'Operation to perform. Run with operation="list" to see available operations.' },
        params: { type: "object", description: "Operation parameters (passed to SDK method)" }
      },
      required: ["operation"]
    }
  },
  {
    name: "sovr_core_persistence",
    description: 'SOVR Core Persistence. Cloud mode \u2014 run with operation="list" to discover available operations.',
    inputSchema: {
      type: "object",
      properties: {
        operation: { type: "string", description: 'Operation to perform. Run with operation="list" to see available operations.' },
        params: { type: "object", description: "Operation parameters (passed to SDK method)" }
      },
      required: ["operation"]
    }
  },
  {
    name: "sovr_core_preset",
    description: 'SOVR Core Preset. Cloud mode \u2014 run with operation="list" to discover available operations.',
    inputSchema: {
      type: "object",
      properties: {
        operation: { type: "string", description: 'Operation to perform. Run with operation="list" to see available operations.' },
        params: { type: "object", description: "Operation parameters (passed to SDK method)" }
      },
      required: ["operation"]
    }
  },
  {
    name: "sovr_core_preview",
    description: 'SOVR Core Preview. Cloud mode \u2014 run with operation="list" to discover available operations.',
    inputSchema: {
      type: "object",
      properties: {
        operation: { type: "string", description: 'Operation to perform. Run with operation="list" to see available operations.' },
        params: { type: "object", description: "Operation parameters (passed to SDK method)" }
      },
      required: ["operation"]
    }
  },
  {
    name: "sovr_core_process",
    description: 'SOVR Core Process. Cloud mode \u2014 run with operation="list" to discover available operations.',
    inputSchema: {
      type: "object",
      properties: {
        operation: { type: "string", description: 'Operation to perform. Run with operation="list" to see available operations.' },
        params: { type: "object", description: "Operation parameters (passed to SDK method)" }
      },
      required: ["operation"]
    }
  },
  {
    name: "sovr_core_quota",
    description: 'SOVR Core Quota. Cloud mode \u2014 run with operation="list" to discover available operations.',
    inputSchema: {
      type: "object",
      properties: {
        operation: { type: "string", description: 'Operation to perform. Run with operation="list" to see available operations.' },
        params: { type: "object", description: "Operation parameters (passed to SDK method)" }
      },
      required: ["operation"]
    }
  },
  {
    name: "sovr_core_recalculate",
    description: 'SOVR Core Recalculate. Cloud mode \u2014 run with operation="list" to discover available operations.',
    inputSchema: {
      type: "object",
      properties: {
        operation: { type: "string", description: 'Operation to perform. Run with operation="list" to see available operations.' },
        params: { type: "object", description: "Operation parameters (passed to SDK method)" }
      },
      required: ["operation"]
    }
  },
  {
    name: "sovr_core_register",
    description: 'SOVR Core Register. Cloud mode \u2014 run with operation="list" to discover available operations.',
    inputSchema: {
      type: "object",
      properties: {
        operation: { type: "string", description: 'Operation to perform. Run with operation="list" to see available operations.' },
        params: { type: "object", description: "Operation parameters (passed to SDK method)" }
      },
      required: ["operation"]
    }
  },
  {
    name: "sovr_core_render",
    description: 'SOVR Core Render. Cloud mode \u2014 run with operation="list" to discover available operations.',
    inputSchema: {
      type: "object",
      properties: {
        operation: { type: "string", description: 'Operation to perform. Run with operation="list" to see available operations.' },
        params: { type: "object", description: "Operation parameters (passed to SDK method)" }
      },
      required: ["operation"]
    }
  },
  {
    name: "sovr_core_request",
    description: 'SOVR Core Request. Cloud mode \u2014 run with operation="list" to discover available operations.',
    inputSchema: {
      type: "object",
      properties: {
        operation: { type: "string", description: 'Operation to perform. Run with operation="list" to see available operations.' },
        params: { type: "object", description: "Operation parameters (passed to SDK method)" }
      },
      required: ["operation"]
    }
  },
  {
    name: "sovr_core_resend",
    description: 'SOVR Core Resend. Cloud mode \u2014 run with operation="list" to discover available operations.',
    inputSchema: {
      type: "object",
      properties: {
        operation: { type: "string", description: 'Operation to perform. Run with operation="list" to see available operations.' },
        params: { type: "object", description: "Operation parameters (passed to SDK method)" }
      },
      required: ["operation"]
    }
  },
  {
    name: "sovr_core_reset",
    description: 'SOVR Core Reset. Cloud mode \u2014 run with operation="list" to discover available operations.',
    inputSchema: {
      type: "object",
      properties: {
        operation: { type: "string", description: 'Operation to perform. Run with operation="list" to see available operations.' },
        params: { type: "object", description: "Operation parameters (passed to SDK method)" }
      },
      required: ["operation"]
    }
  },
  {
    name: "sovr_core_restore",
    description: 'SOVR Core Restore. Cloud mode \u2014 run with operation="list" to discover available operations.',
    inputSchema: {
      type: "object",
      properties: {
        operation: { type: "string", description: 'Operation to perform. Run with operation="list" to see available operations.' },
        params: { type: "object", description: "Operation parameters (passed to SDK method)" }
      },
      required: ["operation"]
    }
  },
  {
    name: "sovr_core_retry",
    description: 'SOVR Core Retry. Cloud mode \u2014 run with operation="list" to discover available operations.',
    inputSchema: {
      type: "object",
      properties: {
        operation: { type: "string", description: 'Operation to perform. Run with operation="list" to see available operations.' },
        params: { type: "object", description: "Operation parameters (passed to SDK method)" }
      },
      required: ["operation"]
    }
  },
  {
    name: "sovr_core_review",
    description: 'SOVR Core Review. Cloud mode \u2014 run with operation="list" to discover available operations.',
    inputSchema: {
      type: "object",
      properties: {
        operation: { type: "string", description: 'Operation to perform. Run with operation="list" to see available operations.' },
        params: { type: "object", description: "Operation parameters (passed to SDK method)" }
      },
      required: ["operation"]
    }
  },
  {
    name: "sovr_core_revoke",
    description: 'SOVR Core Revoke. Cloud mode \u2014 run with operation="list" to discover available operations.',
    inputSchema: {
      type: "object",
      properties: {
        operation: { type: "string", description: 'Operation to perform. Run with operation="list" to see available operations.' },
        params: { type: "object", description: "Operation parameters (passed to SDK method)" }
      },
      required: ["operation"]
    }
  },
  {
    name: "sovr_core_risk",
    description: 'SOVR Core Risk. Cloud mode \u2014 run with operation="list" to discover available operations.',
    inputSchema: {
      type: "object",
      properties: {
        operation: { type: "string", description: 'Operation to perform. Run with operation="list" to see available operations.' },
        params: { type: "object", description: "Operation parameters (passed to SDK method)" }
      },
      required: ["operation"]
    }
  },
  {
    name: "sovr_core_rotate",
    description: 'SOVR Core Rotate. Cloud mode \u2014 run with operation="list" to discover available operations.',
    inputSchema: {
      type: "object",
      properties: {
        operation: { type: "string", description: 'Operation to perform. Run with operation="list" to see available operations.' },
        params: { type: "object", description: "Operation parameters (passed to SDK method)" }
      },
      required: ["operation"]
    }
  },
  {
    name: "sovr_core_run",
    description: 'SOVR Core Run. Cloud mode \u2014 run with operation="list" to discover available operations.',
    inputSchema: {
      type: "object",
      properties: {
        operation: { type: "string", description: 'Operation to perform. Run with operation="list" to see available operations.' },
        params: { type: "object", description: "Operation parameters (passed to SDK method)" }
      },
      required: ["operation"]
    }
  },
  {
    name: "sovr_core_save",
    description: 'SOVR Core Save. Cloud mode \u2014 run with operation="list" to discover available operations.',
    inputSchema: {
      type: "object",
      properties: {
        operation: { type: "string", description: 'Operation to perform. Run with operation="list" to see available operations.' },
        params: { type: "object", description: "Operation parameters (passed to SDK method)" }
      },
      required: ["operation"]
    }
  },
  {
    name: "sovr_core_schedule",
    description: 'SOVR Core Schedule. Cloud mode \u2014 run with operation="list" to discover available operations.',
    inputSchema: {
      type: "object",
      properties: {
        operation: { type: "string", description: 'Operation to perform. Run with operation="list" to see available operations.' },
        params: { type: "object", description: "Operation parameters (passed to SDK method)" }
      },
      required: ["operation"]
    }
  },
  {
    name: "sovr_core_set",
    description: 'SOVR Core Set. Cloud mode \u2014 run with operation="list" to discover available operations.',
    inputSchema: {
      type: "object",
      properties: {
        operation: { type: "string", description: 'Operation to perform. Run with operation="list" to see available operations.' },
        params: { type: "object", description: "Operation parameters (passed to SDK method)" }
      },
      required: ["operation"]
    }
  },
  {
    name: "sovr_core_simulate",
    description: 'SOVR Core Simulate. Cloud mode \u2014 run with operation="list" to discover available operations.',
    inputSchema: {
      type: "object",
      properties: {
        operation: { type: "string", description: 'Operation to perform. Run with operation="list" to see available operations.' },
        params: { type: "object", description: "Operation parameters (passed to SDK method)" }
      },
      required: ["operation"]
    }
  },
  {
    name: "sovr_core_subscribe",
    description: 'SOVR Core Subscribe. Cloud mode \u2014 run with operation="list" to discover available operations.',
    inputSchema: {
      type: "object",
      properties: {
        operation: { type: "string", description: 'Operation to perform. Run with operation="list" to see available operations.' },
        params: { type: "object", description: "Operation parameters (passed to SDK method)" }
      },
      required: ["operation"]
    }
  },
  {
    name: "sovr_core_sufficiency",
    description: 'SOVR Core Sufficiency. Cloud mode \u2014 run with operation="list" to discover available operations.',
    inputSchema: {
      type: "object",
      properties: {
        operation: { type: "string", description: 'Operation to perform. Run with operation="list" to see available operations.' },
        params: { type: "object", description: "Operation parameters (passed to SDK method)" }
      },
      required: ["operation"]
    }
  },
  {
    name: "sovr_core_summary",
    description: 'SOVR Core Summary. Cloud mode \u2014 run with operation="list" to discover available operations.',
    inputSchema: {
      type: "object",
      properties: {
        operation: { type: "string", description: 'Operation to perform. Run with operation="list" to see available operations.' },
        params: { type: "object", description: "Operation parameters (passed to SDK method)" }
      },
      required: ["operation"]
    }
  },
  {
    name: "sovr_core_test",
    description: 'SOVR Core Test. Cloud mode \u2014 run with operation="list" to discover available operations.',
    inputSchema: {
      type: "object",
      properties: {
        operation: { type: "string", description: 'Operation to perform. Run with operation="list" to see available operations.' },
        params: { type: "object", description: "Operation parameters (passed to SDK method)" }
      },
      required: ["operation"]
    }
  },
  {
    name: "sovr_core_time",
    description: 'SOVR Core Time. Cloud mode \u2014 run with operation="list" to discover available operations.',
    inputSchema: {
      type: "object",
      properties: {
        operation: { type: "string", description: 'Operation to perform. Run with operation="list" to see available operations.' },
        params: { type: "object", description: "Operation parameters (passed to SDK method)" }
      },
      required: ["operation"]
    }
  },
  {
    name: "sovr_core_tls",
    description: 'SOVR Core Tls. Cloud mode \u2014 run with operation="list" to discover available operations.',
    inputSchema: {
      type: "object",
      properties: {
        operation: { type: "string", description: 'Operation to perform. Run with operation="list" to see available operations.' },
        params: { type: "object", description: "Operation parameters (passed to SDK method)" }
      },
      required: ["operation"]
    }
  },
  {
    name: "sovr_core_toggle",
    description: 'SOVR Core Toggle. Cloud mode \u2014 run with operation="list" to discover available operations.',
    inputSchema: {
      type: "object",
      properties: {
        operation: { type: "string", description: 'Operation to perform. Run with operation="list" to see available operations.' },
        params: { type: "object", description: "Operation parameters (passed to SDK method)" }
      },
      required: ["operation"]
    }
  },
  {
    name: "sovr_core_top",
    description: 'SOVR Core Top. Cloud mode \u2014 run with operation="list" to discover available operations.',
    inputSchema: {
      type: "object",
      properties: {
        operation: { type: "string", description: 'Operation to perform. Run with operation="list" to see available operations.' },
        params: { type: "object", description: "Operation parameters (passed to SDK method)" }
      },
      required: ["operation"]
    }
  },
  {
    name: "sovr_core_trigger",
    description: 'SOVR Core Trigger. Cloud mode \u2014 run with operation="list" to discover available operations.',
    inputSchema: {
      type: "object",
      properties: {
        operation: { type: "string", description: 'Operation to perform. Run with operation="list" to see available operations.' },
        params: { type: "object", description: "Operation parameters (passed to SDK method)" }
      },
      required: ["operation"]
    }
  },
  {
    name: "sovr_core_unlink",
    description: 'SOVR Core Unlink. Cloud mode \u2014 run with operation="list" to discover available operations.',
    inputSchema: {
      type: "object",
      properties: {
        operation: { type: "string", description: 'Operation to perform. Run with operation="list" to see available operations.' },
        params: { type: "object", description: "Operation parameters (passed to SDK method)" }
      },
      required: ["operation"]
    }
  },
  {
    name: "sovr_core_unsubscribe",
    description: 'SOVR Core Unsubscribe. Cloud mode \u2014 run with operation="list" to discover available operations.',
    inputSchema: {
      type: "object",
      properties: {
        operation: { type: "string", description: 'Operation to perform. Run with operation="list" to see available operations.' },
        params: { type: "object", description: "Operation parameters (passed to SDK method)" }
      },
      required: ["operation"]
    }
  },
  {
    name: "sovr_core_update",
    description: 'SOVR Core Update. Cloud mode \u2014 run with operation="list" to discover available operations.',
    inputSchema: {
      type: "object",
      properties: {
        operation: { type: "string", description: 'Operation to perform. Run with operation="list" to see available operations.' },
        params: { type: "object", description: "Operation parameters (passed to SDK method)" }
      },
      required: ["operation"]
    }
  },
  {
    name: "sovr_core_usage",
    description: 'SOVR Core Usage. Cloud mode \u2014 run with operation="list" to discover available operations.',
    inputSchema: {
      type: "object",
      properties: {
        operation: { type: "string", description: 'Operation to perform. Run with operation="list" to see available operations.' },
        params: { type: "object", description: "Operation parameters (passed to SDK method)" }
      },
      required: ["operation"]
    }
  },
  {
    name: "sovr_core_validate",
    description: 'SOVR Core Validate. Cloud mode \u2014 run with operation="list" to discover available operations.',
    inputSchema: {
      type: "object",
      properties: {
        operation: { type: "string", description: 'Operation to perform. Run with operation="list" to see available operations.' },
        params: { type: "object", description: "Operation parameters (passed to SDK method)" }
      },
      required: ["operation"]
    }
  },
  {
    name: "sovr_core_vault",
    description: 'SOVR Core Vault. Cloud mode \u2014 run with operation="list" to discover available operations.',
    inputSchema: {
      type: "object",
      properties: {
        operation: { type: "string", description: 'Operation to perform. Run with operation="list" to see available operations.' },
        params: { type: "object", description: "Operation parameters (passed to SDK method)" }
      },
      required: ["operation"]
    }
  },
  {
    name: "sovr_cost",
    description: 'SOVR Cost. Cloud mode \u2014 run with operation="list" to discover available operations.',
    inputSchema: {
      type: "object",
      properties: {
        operation: { type: "string", description: 'Operation to perform. Run with operation="list" to see available operations.' },
        params: { type: "object", description: "Operation parameters (passed to SDK method)" }
      },
      required: ["operation"]
    }
  },
  {
    name: "sovr_create_backup",
    description: 'SOVR Create Backup. Cloud mode \u2014 run with operation="list" to discover available operations.',
    inputSchema: {
      type: "object",
      properties: {
        operation: { type: "string", description: 'Operation to perform. Run with operation="list" to see available operations.' },
        params: { type: "object", description: "Operation parameters (passed to SDK method)" }
      },
      required: ["operation"]
    }
  },
  {
    name: "sovr_create_canary",
    description: 'SOVR Create Canary. Cloud mode \u2014 run with operation="list" to discover available operations.',
    inputSchema: {
      type: "object",
      properties: {
        operation: { type: "string", description: 'Operation to perform. Run with operation="list" to see available operations.' },
        params: { type: "object", description: "Operation parameters (passed to SDK method)" }
      },
      required: ["operation"]
    }
  },
  {
    name: "sovr_create_checkout",
    description: 'SOVR Create Checkout. Cloud mode \u2014 run with operation="list" to discover available operations.',
    inputSchema: {
      type: "object",
      properties: {
        operation: { type: "string", description: 'Operation to perform. Run with operation="list" to see available operations.' },
        params: { type: "object", description: "Operation parameters (passed to SDK method)" }
      },
      required: ["operation"]
    }
  },
  {
    name: "sovr_create_checkpoint",
    description: 'SOVR Create Checkpoint. Cloud mode \u2014 run with operation="list" to discover available operations.',
    inputSchema: {
      type: "object",
      properties: {
        operation: { type: "string", description: 'Operation to perform. Run with operation="list" to see available operations.' },
        params: { type: "object", description: "Operation parameters (passed to SDK method)" }
      },
      required: ["operation"]
    }
  },
  {
    name: "sovr_create_consent",
    description: 'SOVR Create Consent. Cloud mode \u2014 run with operation="list" to discover available operations.',
    inputSchema: {
      type: "object",
      properties: {
        operation: { type: "string", description: 'Operation to perform. Run with operation="list" to see available operations.' },
        params: { type: "object", description: "Operation parameters (passed to SDK method)" }
      },
      required: ["operation"]
    }
  },
  {
    name: "sovr_create_custom",
    description: 'SOVR Create Custom. Cloud mode \u2014 run with operation="list" to discover available operations.',
    inputSchema: {
      type: "object",
      properties: {
        operation: { type: "string", description: 'Operation to perform. Run with operation="list" to see available operations.' },
        params: { type: "object", description: "Operation parameters (passed to SDK method)" }
      },
      required: ["operation"]
    }
  },
  {
    name: "sovr_create_data",
    description: 'SOVR Create Data. Cloud mode \u2014 run with operation="list" to discover available operations.',
    inputSchema: {
      type: "object",
      properties: {
        operation: { type: "string", description: 'Operation to perform. Run with operation="list" to see available operations.' },
        params: { type: "object", description: "Operation parameters (passed to SDK method)" }
      },
      required: ["operation"]
    }
  },
  {
    name: "sovr_create_dispute",
    description: 'SOVR Create Dispute. Cloud mode \u2014 run with operation="list" to discover available operations.',
    inputSchema: {
      type: "object",
      properties: {
        operation: { type: "string", description: 'Operation to perform. Run with operation="list" to see available operations.' },
        params: { type: "object", description: "Operation parameters (passed to SDK method)" }
      },
      required: ["operation"]
    }
  },
  {
    name: "sovr_create_feature",
    description: 'SOVR Create Feature. Cloud mode \u2014 run with operation="list" to discover available operations.',
    inputSchema: {
      type: "object",
      properties: {
        operation: { type: "string", description: 'Operation to perform. Run with operation="list" to see available operations.' },
        params: { type: "object", description: "Operation parameters (passed to SDK method)" }
      },
      required: ["operation"]
    }
  },
  {
    name: "sovr_create_fusion",
    description: 'SOVR Create Fusion. Cloud mode \u2014 run with operation="list" to discover available operations.',
    inputSchema: {
      type: "object",
      properties: {
        operation: { type: "string", description: 'Operation to perform. Run with operation="list" to see available operations.' },
        params: { type: "object", description: "Operation parameters (passed to SDK method)" }
      },
      required: ["operation"]
    }
  },
  {
    name: "sovr_create_incident",
    description: 'SOVR Create Incident. Cloud mode \u2014 run with operation="list" to discover available operations.',
    inputSchema: {
      type: "object",
      properties: {
        operation: { type: "string", description: 'Operation to perform. Run with operation="list" to see available operations.' },
        params: { type: "object", description: "Operation parameters (passed to SDK method)" }
      },
      required: ["operation"]
    }
  },
  {
    name: "sovr_create_lifecycle",
    description: 'SOVR Create Lifecycle. Cloud mode \u2014 run with operation="list" to discover available operations.',
    inputSchema: {
      type: "object",
      properties: {
        operation: { type: "string", description: 'Operation to perform. Run with operation="list" to see available operations.' },
        params: { type: "object", description: "Operation parameters (passed to SDK method)" }
      },
      required: ["operation"]
    }
  },
  {
    name: "sovr_create_masking",
    description: 'SOVR Create Masking. Cloud mode \u2014 run with operation="list" to discover available operations.',
    inputSchema: {
      type: "object",
      properties: {
        operation: { type: "string", description: 'Operation to perform. Run with operation="list" to see available operations.' },
        params: { type: "object", description: "Operation parameters (passed to SDK method)" }
      },
      required: ["operation"]
    }
  },
  {
    name: "sovr_create_p",
    description: 'SOVR Create P. Cloud mode \u2014 run with operation="list" to discover available operations.',
    inputSchema: {
      type: "object",
      properties: {
        operation: { type: "string", description: 'Operation to perform. Run with operation="list" to see available operations.' },
        params: { type: "object", description: "Operation parameters (passed to SDK method)" }
      },
      required: ["operation"]
    }
  },
  {
    name: "sovr_create_replay",
    description: 'SOVR Create Replay. Cloud mode \u2014 run with operation="list" to discover available operations.',
    inputSchema: {
      type: "object",
      properties: {
        operation: { type: "string", description: 'Operation to perform. Run with operation="list" to see available operations.' },
        params: { type: "object", description: "Operation parameters (passed to SDK method)" }
      },
      required: ["operation"]
    }
  },
  {
    name: "sovr_create_report",
    description: 'SOVR Create Report. Cloud mode \u2014 run with operation="list" to discover available operations.',
    inputSchema: {
      type: "object",
      properties: {
        operation: { type: "string", description: 'Operation to perform. Run with operation="list" to see available operations.' },
        params: { type: "object", description: "Operation parameters (passed to SDK method)" }
      },
      required: ["operation"]
    }
  },
  {
    name: "sovr_create_restore",
    description: 'SOVR Create Restore. Cloud mode \u2014 run with operation="list" to discover available operations.',
    inputSchema: {
      type: "object",
      properties: {
        operation: { type: "string", description: 'Operation to perform. Run with operation="list" to see available operations.' },
        params: { type: "object", description: "Operation parameters (passed to SDK method)" }
      },
      required: ["operation"]
    }
  },
  {
    name: "sovr_create_risk",
    description: 'SOVR Create Risk. Cloud mode \u2014 run with operation="list" to discover available operations.',
    inputSchema: {
      type: "object",
      properties: {
        operation: { type: "string", description: 'Operation to perform. Run with operation="list" to see available operations.' },
        params: { type: "object", description: "Operation parameters (passed to SDK method)" }
      },
      required: ["operation"]
    }
  },
  {
    name: "sovr_create_rule",
    description: 'SOVR Create Rule. Cloud mode \u2014 run with operation="list" to discover available operations.',
    inputSchema: {
      type: "object",
      properties: {
        operation: { type: "string", description: 'Operation to perform. Run with operation="list" to see available operations.' },
        params: { type: "object", description: "Operation parameters (passed to SDK method)" }
      },
      required: ["operation"]
    }
  },
  {
    name: "sovr_create_stripe",
    description: 'SOVR Create Stripe. Cloud mode \u2014 run with operation="list" to discover available operations.',
    inputSchema: {
      type: "object",
      properties: {
        operation: { type: "string", description: 'Operation to perform. Run with operation="list" to see available operations.' },
        params: { type: "object", description: "Operation parameters (passed to SDK method)" }
      },
      required: ["operation"]
    }
  },
  {
    name: "sovr_create_tenant",
    description: 'SOVR Create Tenant. Cloud mode \u2014 run with operation="list" to discover available operations.',
    inputSchema: {
      type: "object",
      properties: {
        operation: { type: "string", description: 'Operation to perform. Run with operation="list" to see available operations.' },
        params: { type: "object", description: "Operation parameters (passed to SDK method)" }
      },
      required: ["operation"]
    }
  },
  {
    name: "sovr_data_governance",
    description: 'SOVR Data Governance. Cloud mode \u2014 run with operation="list" to discover available operations.',
    inputSchema: {
      type: "object",
      properties: {
        operation: { type: "string", description: 'Operation to perform. Run with operation="list" to see available operations.' },
        params: { type: "object", description: "Operation parameters (passed to SDK method)" }
      },
      required: ["operation"]
    }
  },
  {
    name: "sovr_deactivate_prompt",
    description: 'SOVR Deactivate Prompt. Cloud mode \u2014 run with operation="list" to discover available operations.',
    inputSchema: {
      type: "object",
      properties: {
        operation: { type: "string", description: 'Operation to perform. Run with operation="list" to see available operations.' },
        params: { type: "object", description: "Operation parameters (passed to SDK method)" }
      },
      required: ["operation"]
    }
  },
  {
    name: "sovr_default_deny",
    description: 'SOVR Default Deny. Cloud mode \u2014 run with operation="list" to discover available operations.',
    inputSchema: {
      type: "object",
      properties: {
        operation: { type: "string", description: 'Operation to perform. Run with operation="list" to see available operations.' },
        params: { type: "object", description: "Operation parameters (passed to SDK method)" }
      },
      required: ["operation"]
    }
  },
  {
    name: "sovr_degradation",
    description: 'SOVR Degradation. Cloud mode \u2014 run with operation="list" to discover available operations.',
    inputSchema: {
      type: "object",
      properties: {
        operation: { type: "string", description: 'Operation to perform. Run with operation="list" to see available operations.' },
        params: { type: "object", description: "Operation parameters (passed to SDK method)" }
      },
      required: ["operation"]
    }
  },
  {
    name: "sovr_delete_fusion",
    description: 'SOVR Delete Fusion. Cloud mode \u2014 run with operation="list" to discover available operations.',
    inputSchema: {
      type: "object",
      properties: {
        operation: { type: "string", description: 'Operation to perform. Run with operation="list" to see available operations.' },
        params: { type: "object", description: "Operation parameters (passed to SDK method)" }
      },
      required: ["operation"]
    }
  },
  {
    name: "sovr_delete_p",
    description: 'SOVR Delete P. Cloud mode \u2014 run with operation="list" to discover available operations.',
    inputSchema: {
      type: "object",
      properties: {
        operation: { type: "string", description: 'Operation to perform. Run with operation="list" to see available operations.' },
        params: { type: "object", description: "Operation parameters (passed to SDK method)" }
      },
      required: ["operation"]
    }
  },
  {
    name: "sovr_delete_report",
    description: 'SOVR Delete Report. Cloud mode \u2014 run with operation="list" to discover available operations.',
    inputSchema: {
      type: "object",
      properties: {
        operation: { type: "string", description: 'Operation to perform. Run with operation="list" to see available operations.' },
        params: { type: "object", description: "Operation parameters (passed to SDK method)" }
      },
      required: ["operation"]
    }
  },
  {
    name: "sovr_delete_rule",
    description: 'SOVR Delete Rule. Cloud mode \u2014 run with operation="list" to discover available operations.',
    inputSchema: {
      type: "object",
      properties: {
        operation: { type: "string", description: 'Operation to perform. Run with operation="list" to see available operations.' },
        params: { type: "object", description: "Operation parameters (passed to SDK method)" }
      },
      required: ["operation"]
    }
  },
  {
    name: "sovr_demo",
    description: 'SOVR Demo. Cloud mode \u2014 run with operation="list" to discover available operations.',
    inputSchema: {
      type: "object",
      properties: {
        operation: { type: "string", description: 'Operation to perform. Run with operation="list" to see available operations.' },
        params: { type: "object", description: "Operation parameters (passed to SDK method)" }
      },
      required: ["operation"]
    }
  },
  {
    name: "sovr_deployment",
    description: 'SOVR Deployment. Cloud mode \u2014 run with operation="list" to discover available operations.',
    inputSchema: {
      type: "object",
      properties: {
        operation: { type: "string", description: 'Operation to perform. Run with operation="list" to see available operations.' },
        params: { type: "object", description: "Operation parameters (passed to SDK method)" }
      },
      required: ["operation"]
    }
  },
  {
    name: "sovr_deprecate_policy",
    description: 'SOVR Deprecate Policy. Cloud mode \u2014 run with operation="list" to discover available operations.',
    inputSchema: {
      type: "object",
      properties: {
        operation: { type: "string", description: 'Operation to perform. Run with operation="list" to see available operations.' },
        params: { type: "object", description: "Operation parameters (passed to SDK method)" }
      },
      required: ["operation"]
    }
  },
  {
    name: "sovr_detect_conflict",
    description: 'SOVR Detect Conflict. Cloud mode \u2014 run with operation="list" to discover available operations.',
    inputSchema: {
      type: "object",
      properties: {
        operation: { type: "string", description: 'Operation to perform. Run with operation="list" to see available operations.' },
        params: { type: "object", description: "Operation parameters (passed to SDK method)" }
      },
      required: ["operation"]
    }
  },
  {
    name: "sovr_detect_hallucination",
    description: 'SOVR Detect Hallucination. Cloud mode \u2014 run with operation="list" to discover available operations.',
    inputSchema: {
      type: "object",
      properties: {
        operation: { type: "string", description: 'Operation to perform. Run with operation="list" to see available operations.' },
        params: { type: "object", description: "Operation parameters (passed to SDK method)" }
      },
      required: ["operation"]
    }
  },
  {
    name: "sovr_detect_policy",
    description: 'SOVR Detect Policy. Cloud mode \u2014 run with operation="list" to discover available operations.',
    inputSchema: {
      type: "object",
      properties: {
        operation: { type: "string", description: 'Operation to perform. Run with operation="list" to see available operations.' },
        params: { type: "object", description: "Operation parameters (passed to SDK method)" }
      },
      required: ["operation"]
    }
  },
  {
    name: "sovr_dispatch_p",
    description: 'SOVR Dispatch P. Cloud mode \u2014 run with operation="list" to discover available operations.',
    inputSchema: {
      type: "object",
      properties: {
        operation: { type: "string", description: 'Operation to perform. Run with operation="list" to see available operations.' },
        params: { type: "object", description: "Operation parameters (passed to SDK method)" }
      },
      required: ["operation"]
    }
  },
  {
    name: "sovr_dispute",
    description: 'SOVR Dispute. Cloud mode \u2014 run with operation="list" to discover available operations.',
    inputSchema: {
      type: "object",
      properties: {
        operation: { type: "string", description: 'Operation to perform. Run with operation="list" to see available operations.' },
        params: { type: "object", description: "Operation parameters (passed to SDK method)" }
      },
      required: ["operation"]
    }
  },
  {
    name: "sovr_email",
    description: 'SOVR Email. Cloud mode \u2014 run with operation="list" to discover available operations.',
    inputSchema: {
      type: "object",
      properties: {
        operation: { type: "string", description: 'Operation to perform. Run with operation="list" to see available operations.' },
        params: { type: "object", description: "Operation parameters (passed to SDK method)" }
      },
      required: ["operation"]
    }
  },
  {
    name: "sovr_enable_lifecycle",
    description: 'SOVR Enable Lifecycle. Cloud mode \u2014 run with operation="list" to discover available operations.',
    inputSchema: {
      type: "object",
      properties: {
        operation: { type: "string", description: 'Operation to perform. Run with operation="list" to see available operations.' },
        params: { type: "object", description: "Operation parameters (passed to SDK method)" }
      },
      required: ["operation"]
    }
  },
  {
    name: "sovr_enterprise",
    description: 'SOVR Enterprise. Cloud mode \u2014 run with operation="list" to discover available operations.',
    inputSchema: {
      type: "object",
      properties: {
        operation: { type: "string", description: 'Operation to perform. Run with operation="list" to see available operations.' },
        params: { type: "object", description: "Operation parameters (passed to SDK method)" }
      },
      required: ["operation"]
    }
  },
  {
    name: "sovr_evaluate_metric",
    description: 'SOVR Evaluate Metric. Cloud mode \u2014 run with operation="list" to discover available operations.',
    inputSchema: {
      type: "object",
      properties: {
        operation: { type: "string", description: 'Operation to perform. Run with operation="list" to see available operations.' },
        params: { type: "object", description: "Operation parameters (passed to SDK method)" }
      },
      required: ["operation"]
    }
  },
  {
    name: "sovr_execute_p",
    description: 'SOVR Execute P. Cloud mode \u2014 run with operation="list" to discover available operations.',
    inputSchema: {
      type: "object",
      properties: {
        operation: { type: "string", description: 'Operation to perform. Run with operation="list" to see available operations.' },
        params: { type: "object", description: "Operation parameters (passed to SDK method)" }
      },
      required: ["operation"]
    }
  },
  {
    name: "sovr_execute_quality",
    description: 'SOVR Execute Quality. Cloud mode \u2014 run with operation="list" to discover available operations.',
    inputSchema: {
      type: "object",
      properties: {
        operation: { type: "string", description: 'Operation to perform. Run with operation="list" to see available operations.' },
        params: { type: "object", description: "Operation parameters (passed to SDK method)" }
      },
      required: ["operation"]
    }
  },
  {
    name: "sovr_execute_report",
    description: 'SOVR Execute Report. Cloud mode \u2014 run with operation="list" to discover available operations.',
    inputSchema: {
      type: "object",
      properties: {
        operation: { type: "string", description: 'Operation to perform. Run with operation="list" to see available operations.' },
        params: { type: "object", description: "Operation parameters (passed to SDK method)" }
      },
      required: ["operation"]
    }
  },
  {
    name: "sovr_execute_rollback",
    description: 'SOVR Execute Rollback. Cloud mode \u2014 run with operation="list" to discover available operations.',
    inputSchema: {
      type: "object",
      properties: {
        operation: { type: "string", description: 'Operation to perform. Run with operation="list" to see available operations.' },
        params: { type: "object", description: "Operation parameters (passed to SDK method)" }
      },
      required: ["operation"]
    }
  },
  {
    name: "sovr_experiment",
    description: 'SOVR Experiment. Cloud mode \u2014 run with operation="list" to discover available operations.',
    inputSchema: {
      type: "object",
      properties: {
        operation: { type: "string", description: 'Operation to perform. Run with operation="list" to see available operations.' },
        params: { type: "object", description: "Operation parameters (passed to SDK method)" }
      },
      required: ["operation"]
    }
  },
  {
    name: "sovr_external_api",
    description: 'SOVR External Api. Cloud mode \u2014 run with operation="list" to discover available operations.',
    inputSchema: {
      type: "object",
      properties: {
        operation: { type: "string", description: 'Operation to perform. Run with operation="list" to see available operations.' },
        params: { type: "object", description: "Operation parameters (passed to SDK method)" }
      },
      required: ["operation"]
    }
  },
  {
    name: "sovr_external_gate",
    description: 'SOVR External Gate. Cloud mode \u2014 run with operation="list" to discover available operations.',
    inputSchema: {
      type: "object",
      properties: {
        operation: { type: "string", description: 'Operation to perform. Run with operation="list" to see available operations.' },
        params: { type: "object", description: "Operation parameters (passed to SDK method)" }
      },
      required: ["operation"]
    }
  },
  {
    name: "sovr_failure_budget",
    description: 'SOVR Failure Budget. Cloud mode \u2014 run with operation="list" to discover available operations.',
    inputSchema: {
      type: "object",
      properties: {
        operation: { type: "string", description: 'Operation to perform. Run with operation="list" to see available operations.' },
        params: { type: "object", description: "Operation parameters (passed to SDK method)" }
      },
      required: ["operation"]
    }
  },
  {
    name: "sovr_feature_flag",
    description: 'SOVR Feature Flag. Cloud mode \u2014 run with operation="list" to discover available operations.',
    inputSchema: {
      type: "object",
      properties: {
        operation: { type: "string", description: 'Operation to perform. Run with operation="list" to see available operations.' },
        params: { type: "object", description: "Operation parameters (passed to SDK method)" }
      },
      required: ["operation"]
    }
  },
  {
    name: "sovr_filter_items",
    description: 'SOVR Filter Items. Cloud mode \u2014 run with operation="list" to discover available operations.',
    inputSchema: {
      type: "object",
      properties: {
        operation: { type: "string", description: 'Operation to perform. Run with operation="list" to see available operations.' },
        params: { type: "object", description: "Operation parameters (passed to SDK method)" }
      },
      required: ["operation"]
    }
  },
  {
    name: "sovr_find_precedents",
    description: 'SOVR Find Precedents. Cloud mode \u2014 run with operation="list" to discover available operations.',
    inputSchema: {
      type: "object",
      properties: {
        operation: { type: "string", description: 'Operation to perform. Run with operation="list" to see available operations.' },
        params: { type: "object", description: "Operation parameters (passed to SDK method)" }
      },
      required: ["operation"]
    }
  },
  {
    name: "sovr_fusion",
    description: 'SOVR Fusion. Cloud mode \u2014 run with operation="list" to discover available operations.',
    inputSchema: {
      type: "object",
      properties: {
        operation: { type: "string", description: 'Operation to perform. Run with operation="list" to see available operations.' },
        params: { type: "object", description: "Operation parameters (passed to SDK method)" }
      },
      required: ["operation"]
    }
  },
  {
    name: "sovr_gate",
    description: 'SOVR Gate. Cloud mode \u2014 run with operation="list" to discover available operations.',
    inputSchema: {
      type: "object",
      properties: {
        operation: { type: "string", description: 'Operation to perform. Run with operation="list" to see available operations.' },
        params: { type: "object", description: "Operation parameters (passed to SDK method)" }
      },
      required: ["operation"]
    }
  },
  {
    name: "sovr_generate_certificate",
    description: 'SOVR Generate Certificate. Cloud mode \u2014 run with operation="list" to discover available operations.',
    inputSchema: {
      type: "object",
      properties: {
        operation: { type: "string", description: 'Operation to perform. Run with operation="list" to see available operations.' },
        params: { type: "object", description: "Operation parameters (passed to SDK method)" }
      },
      required: ["operation"]
    }
  },
  {
    name: "sovr_generate_diff",
    description: 'SOVR Generate Diff. Cloud mode \u2014 run with operation="list" to discover available operations.',
    inputSchema: {
      type: "object",
      properties: {
        operation: { type: "string", description: 'Operation to perform. Run with operation="list" to see available operations.' },
        params: { type: "object", description: "Operation parameters (passed to SDK method)" }
      },
      required: ["operation"]
    }
  },
  {
    name: "sovr_geo",
    description: 'SOVR Geo. Cloud mode \u2014 run with operation="list" to discover available operations.',
    inputSchema: {
      type: "object",
      properties: {
        operation: { type: "string", description: 'Operation to perform. Run with operation="list" to see available operations.' },
        params: { type: "object", description: "Operation parameters (passed to SDK method)" }
      },
      required: ["operation"]
    }
  },
  {
    name: "sovr_get_action",
    description: 'SOVR Get Action. Cloud mode \u2014 run with operation="list" to discover available operations.',
    inputSchema: {
      type: "object",
      properties: {
        operation: { type: "string", description: 'Operation to perform. Run with operation="list" to see available operations.' },
        params: { type: "object", description: "Operation parameters (passed to SDK method)" }
      },
      required: ["operation"]
    }
  },
  {
    name: "sovr_get_active",
    description: 'SOVR Get Active. Cloud mode \u2014 run with operation="list" to discover available operations.',
    inputSchema: {
      type: "object",
      properties: {
        operation: { type: "string", description: 'Operation to perform. Run with operation="list" to see available operations.' },
        params: { type: "object", description: "Operation parameters (passed to SDK method)" }
      },
      required: ["operation"]
    }
  },
  {
    name: "sovr_get_adjacent",
    description: 'SOVR Get Adjacent. Cloud mode \u2014 run with operation="list" to discover available operations.',
    inputSchema: {
      type: "object",
      properties: {
        operation: { type: "string", description: 'Operation to perform. Run with operation="list" to see available operations.' },
        params: { type: "object", description: "Operation parameters (passed to SDK method)" }
      },
      required: ["operation"]
    }
  },
  {
    name: "sovr_get_alert",
    description: 'SOVR Get Alert. Cloud mode \u2014 run with operation="list" to discover available operations.',
    inputSchema: {
      type: "object",
      properties: {
        operation: { type: "string", description: 'Operation to perform. Run with operation="list" to see available operations.' },
        params: { type: "object", description: "Operation parameters (passed to SDK method)" }
      },
      required: ["operation"]
    }
  },
  {
    name: "sovr_get_all",
    description: 'SOVR Get All. Cloud mode \u2014 run with operation="list" to discover available operations.',
    inputSchema: {
      type: "object",
      properties: {
        operation: { type: "string", description: 'Operation to perform. Run with operation="list" to see available operations.' },
        params: { type: "object", description: "Operation parameters (passed to SDK method)" }
      },
      required: ["operation"]
    }
  },
  {
    name: "sovr_get_approval",
    description: 'SOVR Get Approval. Cloud mode \u2014 run with operation="list" to discover available operations.',
    inputSchema: {
      type: "object",
      properties: {
        operation: { type: "string", description: 'Operation to perform. Run with operation="list" to see available operations.' },
        params: { type: "object", description: "Operation parameters (passed to SDK method)" }
      },
      required: ["operation"]
    }
  },
  {
    name: "sovr_get_chat",
    description: 'SOVR Get Chat. Cloud mode \u2014 run with operation="list" to discover available operations.',
    inputSchema: {
      type: "object",
      properties: {
        operation: { type: "string", description: 'Operation to perform. Run with operation="list" to see available operations.' },
        params: { type: "object", description: "Operation parameters (passed to SDK method)" }
      },
      required: ["operation"]
    }
  },
  {
    name: "sovr_get_checkpoint",
    description: 'SOVR Get Checkpoint. Cloud mode \u2014 run with operation="list" to discover available operations.',
    inputSchema: {
      type: "object",
      properties: {
        operation: { type: "string", description: 'Operation to perform. Run with operation="list" to see available operations.' },
        params: { type: "object", description: "Operation parameters (passed to SDK method)" }
      },
      required: ["operation"]
    }
  },
  {
    name: "sovr_get_constraint",
    description: 'SOVR Get Constraint. Cloud mode \u2014 run with operation="list" to discover available operations.',
    inputSchema: {
      type: "object",
      properties: {
        operation: { type: "string", description: 'Operation to perform. Run with operation="list" to see available operations.' },
        params: { type: "object", description: "Operation parameters (passed to SDK method)" }
      },
      required: ["operation"]
    }
  },
  {
    name: "sovr_get_content",
    description: 'SOVR Get Content. Cloud mode \u2014 run with operation="list" to discover available operations.',
    inputSchema: {
      type: "object",
      properties: {
        operation: { type: "string", description: 'Operation to perform. Run with operation="list" to see available operations.' },
        params: { type: "object", description: "Operation parameters (passed to SDK method)" }
      },
      required: ["operation"]
    }
  },
  {
    name: "sovr_get_cost",
    description: 'SOVR Get Cost. Cloud mode \u2014 run with operation="list" to discover available operations.',
    inputSchema: {
      type: "object",
      properties: {
        operation: { type: "string", description: 'Operation to perform. Run with operation="list" to see available operations.' },
        params: { type: "object", description: "Operation parameters (passed to SDK method)" }
      },
      required: ["operation"]
    }
  },
  {
    name: "sovr_get_custom",
    description: 'SOVR Get Custom. Cloud mode \u2014 run with operation="list" to discover available operations.',
    inputSchema: {
      type: "object",
      properties: {
        operation: { type: "string", description: 'Operation to perform. Run with operation="list" to see available operations.' },
        params: { type: "object", description: "Operation parameters (passed to SDK method)" }
      },
      required: ["operation"]
    }
  },
  {
    name: "sovr_get_dangerous",
    description: 'SOVR Get Dangerous. Cloud mode \u2014 run with operation="list" to discover available operations.',
    inputSchema: {
      type: "object",
      properties: {
        operation: { type: "string", description: 'Operation to perform. Run with operation="list" to see available operations.' },
        params: { type: "object", description: "Operation parameters (passed to SDK method)" }
      },
      required: ["operation"]
    }
  },
  {
    name: "sovr_get_data",
    description: 'SOVR Get Data. Cloud mode \u2014 run with operation="list" to discover available operations.',
    inputSchema: {
      type: "object",
      properties: {
        operation: { type: "string", description: 'Operation to perform. Run with operation="list" to see available operations.' },
        params: { type: "object", description: "Operation parameters (passed to SDK method)" }
      },
      required: ["operation"]
    }
  },
  {
    name: "sovr_get_dispute",
    description: 'SOVR Get Dispute. Cloud mode \u2014 run with operation="list" to discover available operations.',
    inputSchema: {
      type: "object",
      properties: {
        operation: { type: "string", description: 'Operation to perform. Run with operation="list" to see available operations.' },
        params: { type: "object", description: "Operation parameters (passed to SDK method)" }
      },
      required: ["operation"]
    }
  },
  {
    name: "sovr_get_entity",
    description: 'SOVR Get Entity. Cloud mode \u2014 run with operation="list" to discover available operations.',
    inputSchema: {
      type: "object",
      properties: {
        operation: { type: "string", description: 'Operation to perform. Run with operation="list" to see available operations.' },
        params: { type: "object", description: "Operation parameters (passed to SDK method)" }
      },
      required: ["operation"]
    }
  },
  {
    name: "sovr_get_gate",
    description: 'SOVR Get Gate. Cloud mode \u2014 run with operation="list" to discover available operations.',
    inputSchema: {
      type: "object",
      properties: {
        operation: { type: "string", description: 'Operation to perform. Run with operation="list" to see available operations.' },
        params: { type: "object", description: "Operation parameters (passed to SDK method)" }
      },
      required: ["operation"]
    }
  },
  {
    name: "sovr_get_high",
    description: 'SOVR Get High. Cloud mode \u2014 run with operation="list" to discover available operations.',
    inputSchema: {
      type: "object",
      properties: {
        operation: { type: "string", description: 'Operation to perform. Run with operation="list" to see available operations.' },
        params: { type: "object", description: "Operation parameters (passed to SDK method)" }
      },
      required: ["operation"]
    }
  },
  {
    name: "sovr_get_known",
    description: 'SOVR Get Known. Cloud mode \u2014 run with operation="list" to discover available operations.',
    inputSchema: {
      type: "object",
      properties: {
        operation: { type: "string", description: 'Operation to perform. Run with operation="list" to see available operations.' },
        params: { type: "object", description: "Operation parameters (passed to SDK method)" }
      },
      required: ["operation"]
    }
  },
  {
    name: "sovr_get_metric",
    description: 'SOVR Get Metric. Cloud mode \u2014 run with operation="list" to discover available operations.',
    inputSchema: {
      type: "object",
      properties: {
        operation: { type: "string", description: 'Operation to perform. Run with operation="list" to see available operations.' },
        params: { type: "object", description: "Operation parameters (passed to SDK method)" }
      },
      required: ["operation"]
    }
  },
  {
    name: "sovr_get_open",
    description: 'SOVR Get Open. Cloud mode \u2014 run with operation="list" to discover available operations.',
    inputSchema: {
      type: "object",
      properties: {
        operation: { type: "string", description: 'Operation to perform. Run with operation="list" to see available operations.' },
        params: { type: "object", description: "Operation parameters (passed to SDK method)" }
      },
      required: ["operation"]
    }
  },
  {
    name: "sovr_get_p",
    description: 'SOVR Get P. Cloud mode \u2014 run with operation="list" to discover available operations.',
    inputSchema: {
      type: "object",
      properties: {
        operation: { type: "string", description: 'Operation to perform. Run with operation="list" to see available operations.' },
        params: { type: "object", description: "Operation parameters (passed to SDK method)" }
      },
      required: ["operation"]
    }
  },
  {
    name: "sovr_get_pending",
    description: 'SOVR Get Pending. Cloud mode \u2014 run with operation="list" to discover available operations.',
    inputSchema: {
      type: "object",
      properties: {
        operation: { type: "string", description: 'Operation to perform. Run with operation="list" to see available operations.' },
        params: { type: "object", description: "Operation parameters (passed to SDK method)" }
      },
      required: ["operation"]
    }
  },
  {
    name: "sovr_get_risk",
    description: 'SOVR Get Risk. Cloud mode \u2014 run with operation="list" to discover available operations.',
    inputSchema: {
      type: "object",
      properties: {
        operation: { type: "string", description: 'Operation to perform. Run with operation="list" to see available operations.' },
        params: { type: "object", description: "Operation parameters (passed to SDK method)" }
      },
      required: ["operation"]
    }
  },
  {
    name: "sovr_get_role",
    description: 'SOVR Get Role. Cloud mode \u2014 run with operation="list" to discover available operations.',
    inputSchema: {
      type: "object",
      properties: {
        operation: { type: "string", description: 'Operation to perform. Run with operation="list" to see available operations.' },
        params: { type: "object", description: "Operation parameters (passed to SDK method)" }
      },
      required: ["operation"]
    }
  },
  {
    name: "sovr_get_rollback",
    description: 'SOVR Get Rollback. Cloud mode \u2014 run with operation="list" to discover available operations.',
    inputSchema: {
      type: "object",
      properties: {
        operation: { type: "string", description: 'Operation to perform. Run with operation="list" to see available operations.' },
        params: { type: "object", description: "Operation parameters (passed to SDK method)" }
      },
      required: ["operation"]
    }
  },
  {
    name: "sovr_get_scan",
    description: 'SOVR Get Scan. Cloud mode \u2014 run with operation="list" to discover available operations.',
    inputSchema: {
      type: "object",
      properties: {
        operation: { type: "string", description: 'Operation to perform. Run with operation="list" to see available operations.' },
        params: { type: "object", description: "Operation parameters (passed to SDK method)" }
      },
      required: ["operation"]
    }
  },
  {
    name: "sovr_get_status",
    description: 'SOVR Get Status. Cloud mode \u2014 run with operation="list" to discover available operations.',
    inputSchema: {
      type: "object",
      properties: {
        operation: { type: "string", description: 'Operation to perform. Run with operation="list" to see available operations.' },
        params: { type: "object", description: "Operation parameters (passed to SDK method)" }
      },
      required: ["operation"]
    }
  },
  {
    name: "sovr_get_top",
    description: 'SOVR Get Top. Cloud mode \u2014 run with operation="list" to discover available operations.',
    inputSchema: {
      type: "object",
      properties: {
        operation: { type: "string", description: 'Operation to perform. Run with operation="list" to see available operations.' },
        params: { type: "object", description: "Operation parameters (passed to SDK method)" }
      },
      required: ["operation"]
    }
  },
  {
    name: "sovr_integration",
    description: 'SOVR Integration. Cloud mode \u2014 run with operation="list" to discover available operations.',
    inputSchema: {
      type: "object",
      properties: {
        operation: { type: "string", description: 'Operation to perform. Run with operation="list" to see available operations.' },
        params: { type: "object", description: "Operation parameters (passed to SDK method)" }
      },
      required: ["operation"]
    }
  },
  {
    name: "sovr_kill_switch",
    description: 'SOVR Kill Switch. Cloud mode \u2014 run with operation="list" to discover available operations.',
    inputSchema: {
      type: "object",
      properties: {
        operation: { type: "string", description: 'Operation to perform. Run with operation="list" to see available operations.' },
        params: { type: "object", description: "Operation parameters (passed to SDK method)" }
      },
      required: ["operation"]
    }
  },
  {
    name: "sovr_lifecycle",
    description: 'SOVR Lifecycle. Cloud mode \u2014 run with operation="list" to discover available operations.',
    inputSchema: {
      type: "object",
      properties: {
        operation: { type: "string", description: 'Operation to perform. Run with operation="list" to see available operations.' },
        params: { type: "object", description: "Operation parameters (passed to SDK method)" }
      },
      required: ["operation"]
    }
  },
  {
    name: "sovr_list_active",
    description: 'SOVR List Active. Cloud mode \u2014 run with operation="list" to discover available operations.',
    inputSchema: {
      type: "object",
      properties: {
        operation: { type: "string", description: 'Operation to perform. Run with operation="list" to see available operations.' },
        params: { type: "object", description: "Operation parameters (passed to SDK method)" }
      },
      required: ["operation"]
    }
  },
  {
    name: "sovr_list_custom",
    description: 'SOVR List Custom. Cloud mode \u2014 run with operation="list" to discover available operations.',
    inputSchema: {
      type: "object",
      properties: {
        operation: { type: "string", description: 'Operation to perform. Run with operation="list" to see available operations.' },
        params: { type: "object", description: "Operation parameters (passed to SDK method)" }
      },
      required: ["operation"]
    }
  },
  {
    name: "sovr_list_fusion",
    description: 'SOVR List Fusion. Cloud mode \u2014 run with operation="list" to discover available operations.',
    inputSchema: {
      type: "object",
      properties: {
        operation: { type: "string", description: 'Operation to perform. Run with operation="list" to see available operations.' },
        params: { type: "object", description: "Operation parameters (passed to SDK method)" }
      },
      required: ["operation"]
    }
  },
  {
    name: "sovr_list_p",
    description: 'SOVR List P. Cloud mode \u2014 run with operation="list" to discover available operations.',
    inputSchema: {
      type: "object",
      properties: {
        operation: { type: "string", description: 'Operation to perform. Run with operation="list" to see available operations.' },
        params: { type: "object", description: "Operation parameters (passed to SDK method)" }
      },
      required: ["operation"]
    }
  },
  {
    name: "sovr_list_pending",
    description: 'SOVR List Pending. Cloud mode \u2014 run with operation="list" to discover available operations.',
    inputSchema: {
      type: "object",
      properties: {
        operation: { type: "string", description: 'Operation to perform. Run with operation="list" to see available operations.' },
        params: { type: "object", description: "Operation parameters (passed to SDK method)" }
      },
      required: ["operation"]
    }
  },
  {
    name: "sovr_list_policy",
    description: 'SOVR List Policy. Cloud mode \u2014 run with operation="list" to discover available operations.',
    inputSchema: {
      type: "object",
      properties: {
        operation: { type: "string", description: 'Operation to perform. Run with operation="list" to see available operations.' },
        params: { type: "object", description: "Operation parameters (passed to SDK method)" }
      },
      required: ["operation"]
    }
  },
  {
    name: "sovr_list_replay",
    description: 'SOVR List Replay. Cloud mode \u2014 run with operation="list" to discover available operations.',
    inputSchema: {
      type: "object",
      properties: {
        operation: { type: "string", description: 'Operation to perform. Run with operation="list" to see available operations.' },
        params: { type: "object", description: "Operation parameters (passed to SDK method)" }
      },
      required: ["operation"]
    }
  },
  {
    name: "sovr_list_report",
    description: 'SOVR List Report. Cloud mode \u2014 run with operation="list" to discover available operations.',
    inputSchema: {
      type: "object",
      properties: {
        operation: { type: "string", description: 'Operation to perform. Run with operation="list" to see available operations.' },
        params: { type: "object", description: "Operation parameters (passed to SDK method)" }
      },
      required: ["operation"]
    }
  },
  {
    name: "sovr_list_rules",
    description: 'SOVR List Rules. Cloud mode \u2014 run with operation="list" to discover available operations.',
    inputSchema: {
      type: "object",
      properties: {
        operation: { type: "string", description: 'Operation to perform. Run with operation="list" to see available operations.' },
        params: { type: "object", description: "Operation parameters (passed to SDK method)" }
      },
      required: ["operation"]
    }
  },
  {
    name: "sovr_list_trust",
    description: 'SOVR List Trust. Cloud mode \u2014 run with operation="list" to discover available operations.',
    inputSchema: {
      type: "object",
      properties: {
        operation: { type: "string", description: 'Operation to perform. Run with operation="list" to see available operations.' },
        params: { type: "object", description: "Operation parameters (passed to SDK method)" }
      },
      required: ["operation"]
    }
  },
  {
    name: "sovr_live_chat",
    description: 'SOVR Live Chat. Cloud mode \u2014 run with operation="list" to discover available operations.',
    inputSchema: {
      type: "object",
      properties: {
        operation: { type: "string", description: 'Operation to perform. Run with operation="list" to see available operations.' },
        params: { type: "object", description: "Operation parameters (passed to SDK method)" }
      },
      required: ["operation"]
    }
  },
  {
    name: "sovr_log_decision",
    description: 'SOVR Log Decision. Cloud mode \u2014 run with operation="list" to discover available operations.',
    inputSchema: {
      type: "object",
      properties: {
        operation: { type: "string", description: 'Operation to perform. Run with operation="list" to see available operations.' },
        params: { type: "object", description: "Operation parameters (passed to SDK method)" }
      },
      required: ["operation"]
    }
  },
  {
    name: "sovr_manual_trigger",
    description: 'SOVR Manual Trigger. Cloud mode \u2014 run with operation="list" to discover available operations.',
    inputSchema: {
      type: "object",
      properties: {
        operation: { type: "string", description: 'Operation to perform. Run with operation="list" to see available operations.' },
        params: { type: "object", description: "Operation parameters (passed to SDK method)" }
      },
      required: ["operation"]
    }
  },
  {
    name: "sovr_marketing",
    description: 'SOVR Marketing. Cloud mode \u2014 run with operation="list" to discover available operations.',
    inputSchema: {
      type: "object",
      properties: {
        operation: { type: "string", description: 'Operation to perform. Run with operation="list" to see available operations.' },
        params: { type: "object", description: "Operation parameters (passed to SDK method)" }
      },
      required: ["operation"]
    }
  },
  {
    name: "sovr_mcp_instance",
    description: 'SOVR Mcp Instance. Cloud mode \u2014 run with operation="list" to discover available operations.',
    inputSchema: {
      type: "object",
      properties: {
        operation: { type: "string", description: 'Operation to perform. Run with operation="list" to see available operations.' },
        params: { type: "object", description: "Operation parameters (passed to SDK method)" }
      },
      required: ["operation"]
    }
  },
  {
    name: "sovr_memory",
    description: 'SOVR Memory. Cloud mode \u2014 run with operation="list" to discover available operations.',
    inputSchema: {
      type: "object",
      properties: {
        operation: { type: "string", description: 'Operation to perform. Run with operation="list" to see available operations.' },
        params: { type: "object", description: "Operation parameters (passed to SDK method)" }
      },
      required: ["operation"]
    }
  },
  {
    name: "sovr_metering",
    description: 'SOVR Metering. Cloud mode \u2014 run with operation="list" to discover available operations.',
    inputSchema: {
      type: "object",
      properties: {
        operation: { type: "string", description: 'Operation to perform. Run with operation="list" to see available operations.' },
        params: { type: "object", description: "Operation parameters (passed to SDK method)" }
      },
      required: ["operation"]
    }
  },
  {
    name: "sovr_model_ops",
    description: 'SOVR Model Ops. Cloud mode \u2014 run with operation="list" to discover available operations.',
    inputSchema: {
      type: "object",
      properties: {
        operation: { type: "string", description: 'Operation to perform. Run with operation="list" to see available operations.' },
        params: { type: "object", description: "Operation parameters (passed to SDK method)" }
      },
      required: ["operation"]
    }
  },
  {
    name: "sovr_monitor",
    description: 'SOVR Monitor. Cloud mode \u2014 run with operation="list" to discover available operations.',
    inputSchema: {
      type: "object",
      properties: {
        operation: { type: "string", description: 'Operation to perform. Run with operation="list" to see available operations.' },
        params: { type: "object", description: "Operation parameters (passed to SDK method)" }
      },
      required: ["operation"]
    }
  },
  {
    name: "sovr_p0_alerts",
    description: 'SOVR P0 Alerts. Cloud mode \u2014 run with operation="list" to discover available operations.',
    inputSchema: {
      type: "object",
      properties: {
        operation: { type: "string", description: 'Operation to perform. Run with operation="list" to see available operations.' },
        params: { type: "object", description: "Operation parameters (passed to SDK method)" }
      },
      required: ["operation"]
    }
  },
  {
    name: "sovr_p3_ops",
    description: 'SOVR P3 Ops. Cloud mode \u2014 run with operation="list" to discover available operations.',
    inputSchema: {
      type: "object",
      properties: {
        operation: { type: "string", description: 'Operation to perform. Run with operation="list" to see available operations.' },
        params: { type: "object", description: "Operation parameters (passed to SDK method)" }
      },
      required: ["operation"]
    }
  },
  {
    name: "sovr_permit",
    description: 'SOVR Permit. Cloud mode \u2014 run with operation="list" to discover available operations.',
    inputSchema: {
      type: "object",
      properties: {
        operation: { type: "string", description: 'Operation to perform. Run with operation="list" to see available operations.' },
        params: { type: "object", description: "Operation parameters (passed to SDK method)" }
      },
      required: ["operation"]
    }
  },
  {
    name: "sovr_policy",
    description: 'SOVR Policy. Cloud mode \u2014 run with operation="list" to discover available operations.',
    inputSchema: {
      type: "object",
      properties: {
        operation: { type: "string", description: 'Operation to perform. Run with operation="list" to see available operations.' },
        params: { type: "object", description: "Operation parameters (passed to SDK method)" }
      },
      required: ["operation"]
    }
  },
  {
    name: "sovr_protect",
    description: 'SOVR Protect. Cloud mode \u2014 run with operation="list" to discover available operations.',
    inputSchema: {
      type: "object",
      properties: {
        operation: { type: "string", description: 'Operation to perform. Run with operation="list" to see available operations.' },
        params: { type: "object", description: "Operation parameters (passed to SDK method)" }
      },
      required: ["operation"]
    }
  },
  {
    name: "sovr_qa",
    description: 'SOVR Qa. Cloud mode \u2014 run with operation="list" to discover available operations.',
    inputSchema: {
      type: "object",
      properties: {
        operation: { type: "string", description: 'Operation to perform. Run with operation="list" to see available operations.' },
        params: { type: "object", description: "Operation parameters (passed to SDK method)" }
      },
      required: ["operation"]
    }
  },
  {
    name: "sovr_quick_fact",
    description: 'SOVR Quick Fact. Cloud mode \u2014 run with operation="list" to discover available operations.',
    inputSchema: {
      type: "object",
      properties: {
        operation: { type: "string", description: 'Operation to perform. Run with operation="list" to see available operations.' },
        params: { type: "object", description: "Operation parameters (passed to SDK method)" }
      },
      required: ["operation"]
    }
  },
  {
    name: "sovr_quick_hallucination",
    description: 'SOVR Quick Hallucination. Cloud mode \u2014 run with operation="list" to discover available operations.',
    inputSchema: {
      type: "object",
      properties: {
        operation: { type: "string", description: 'Operation to perform. Run with operation="list" to see available operations.' },
        params: { type: "object", description: "Operation parameters (passed to SDK method)" }
      },
      required: ["operation"]
    }
  },
  {
    name: "sovr_rbac",
    description: 'SOVR Rbac. Cloud mode \u2014 run with operation="list" to discover available operations.',
    inputSchema: {
      type: "object",
      properties: {
        operation: { type: "string", description: 'Operation to perform. Run with operation="list" to see available operations.' },
        params: { type: "object", description: "Operation parameters (passed to SDK method)" }
      },
      required: ["operation"]
    }
  },
  {
    name: "sovr_real_time",
    description: 'SOVR Real Time. Cloud mode \u2014 run with operation="list" to discover available operations.',
    inputSchema: {
      type: "object",
      properties: {
        operation: { type: "string", description: 'Operation to perform. Run with operation="list" to see available operations.' },
        params: { type: "object", description: "Operation parameters (passed to SDK method)" }
      },
      required: ["operation"]
    }
  },
  {
    name: "sovr_receipt",
    description: 'SOVR Receipt. Cloud mode \u2014 run with operation="list" to discover available operations.',
    inputSchema: {
      type: "object",
      properties: {
        operation: { type: "string", description: 'Operation to perform. Run with operation="list" to see available operations.' },
        params: { type: "object", description: "Operation parameters (passed to SDK method)" }
      },
      required: ["operation"]
    }
  },
  {
    name: "sovr_record_metric",
    description: 'SOVR Record Metric. Cloud mode \u2014 run with operation="list" to discover available operations.',
    inputSchema: {
      type: "object",
      properties: {
        operation: { type: "string", description: 'Operation to perform. Run with operation="list" to see available operations.' },
        params: { type: "object", description: "Operation parameters (passed to SDK method)" }
      },
      required: ["operation"]
    }
  },
  {
    name: "sovr_referral",
    description: 'SOVR Referral. Cloud mode \u2014 run with operation="list" to discover available operations.',
    inputSchema: {
      type: "object",
      properties: {
        operation: { type: "string", description: 'Operation to perform. Run with operation="list" to see available operations.' },
        params: { type: "object", description: "Operation parameters (passed to SDK method)" }
      },
      required: ["operation"]
    }
  },
  {
    name: "sovr_regression",
    description: 'SOVR Regression. Cloud mode \u2014 run with operation="list" to discover available operations.',
    inputSchema: {
      type: "object",
      properties: {
        operation: { type: "string", description: 'Operation to perform. Run with operation="list" to see available operations.' },
        params: { type: "object", description: "Operation parameters (passed to SDK method)" }
      },
      required: ["operation"]
    }
  },
  {
    name: "sovr_replay",
    description: 'SOVR Replay. Cloud mode \u2014 run with operation="list" to discover available operations.',
    inputSchema: {
      type: "object",
      properties: {
        operation: { type: "string", description: 'Operation to perform. Run with operation="list" to see available operations.' },
        params: { type: "object", description: "Operation parameters (passed to SDK method)" }
      },
      required: ["operation"]
    }
  },
  {
    name: "sovr_report",
    description: 'SOVR Report. Cloud mode \u2014 run with operation="list" to discover available operations.',
    inputSchema: {
      type: "object",
      properties: {
        operation: { type: "string", description: 'Operation to perform. Run with operation="list" to see available operations.' },
        params: { type: "object", description: "Operation parameters (passed to SDK method)" }
      },
      required: ["operation"]
    }
  },
  {
    name: "sovr_reset_all",
    description: 'SOVR Reset All. Cloud mode \u2014 run with operation="list" to discover available operations.',
    inputSchema: {
      type: "object",
      properties: {
        operation: { type: "string", description: 'Operation to perform. Run with operation="list" to see available operations.' },
        params: { type: "object", description: "Operation parameters (passed to SDK method)" }
      },
      required: ["operation"]
    }
  },
  {
    name: "sovr_resolve_conflict",
    description: 'SOVR Resolve Conflict. Cloud mode \u2014 run with operation="list" to discover available operations.',
    inputSchema: {
      type: "object",
      properties: {
        operation: { type: "string", description: 'Operation to perform. Run with operation="list" to see available operations.' },
        params: { type: "object", description: "Operation parameters (passed to SDK method)" }
      },
      required: ["operation"]
    }
  },
  {
    name: "sovr_resolve_p",
    description: 'SOVR Resolve P. Cloud mode \u2014 run with operation="list" to discover available operations.',
    inputSchema: {
      type: "object",
      properties: {
        operation: { type: "string", description: 'Operation to perform. Run with operation="list" to see available operations.' },
        params: { type: "object", description: "Operation parameters (passed to SDK method)" }
      },
      required: ["operation"]
    }
  },
  {
    name: "sovr_retry_p",
    description: 'SOVR Retry P. Cloud mode \u2014 run with operation="list" to discover available operations.',
    inputSchema: {
      type: "object",
      properties: {
        operation: { type: "string", description: 'Operation to perform. Run with operation="list" to see available operations.' },
        params: { type: "object", description: "Operation parameters (passed to SDK method)" }
      },
      required: ["operation"]
    }
  },
  {
    name: "sovr_risk",
    description: 'SOVR Risk. Cloud mode \u2014 run with operation="list" to discover available operations.',
    inputSchema: {
      type: "object",
      properties: {
        operation: { type: "string", description: 'Operation to perform. Run with operation="list" to see available operations.' },
        params: { type: "object", description: "Operation parameters (passed to SDK method)" }
      },
      required: ["operation"]
    }
  },
  {
    name: "sovr_rollback",
    description: 'SOVR Rollback. Cloud mode \u2014 run with operation="list" to discover available operations.',
    inputSchema: {
      type: "object",
      properties: {
        operation: { type: "string", description: 'Operation to perform. Run with operation="list" to see available operations.' },
        params: { type: "object", description: "Operation parameters (passed to SDK method)" }
      },
      required: ["operation"]
    }
  },
  {
    name: "sovr_rule",
    description: 'SOVR Rule. Cloud mode \u2014 run with operation="list" to discover available operations.',
    inputSchema: {
      type: "object",
      properties: {
        operation: { type: "string", description: 'Operation to perform. Run with operation="list" to see available operations.' },
        params: { type: "object", description: "Operation parameters (passed to SDK method)" }
      },
      required: ["operation"]
    }
  },
  {
    name: "sovr_run_all",
    description: 'SOVR Run All. Cloud mode \u2014 run with operation="list" to discover available operations.',
    inputSchema: {
      type: "object",
      properties: {
        operation: { type: "string", description: 'Operation to perform. Run with operation="list" to see available operations.' },
        params: { type: "object", description: "Operation parameters (passed to SDK method)" }
      },
      required: ["operation"]
    }
  },
  {
    name: "sovr_run_full",
    description: 'SOVR Run Full. Cloud mode \u2014 run with operation="list" to discover available operations.',
    inputSchema: {
      type: "object",
      properties: {
        operation: { type: "string", description: 'Operation to perform. Run with operation="list" to see available operations.' },
        params: { type: "object", description: "Operation parameters (passed to SDK method)" }
      },
      required: ["operation"]
    }
  },
  {
    name: "sovr_run_l",
    description: 'SOVR Run L. Cloud mode \u2014 run with operation="list" to discover available operations.',
    inputSchema: {
      type: "object",
      properties: {
        operation: { type: "string", description: 'Operation to perform. Run with operation="list" to see available operations.' },
        params: { type: "object", description: "Operation parameters (passed to SDK method)" }
      },
      required: ["operation"]
    }
  },
  {
    name: "sovr_scan",
    description: 'SOVR Scan. Cloud mode \u2014 run with operation="list" to discover available operations.',
    inputSchema: {
      type: "object",
      properties: {
        operation: { type: "string", description: 'Operation to perform. Run with operation="list" to see available operations.' },
        params: { type: "object", description: "Operation parameters (passed to SDK method)" }
      },
      required: ["operation"]
    }
  },
  {
    name: "sovr_scheduler",
    description: 'SOVR Scheduler. Cloud mode \u2014 run with operation="list" to discover available operations.',
    inputSchema: {
      type: "object",
      properties: {
        operation: { type: "string", description: 'Operation to perform. Run with operation="list" to see available operations.' },
        params: { type: "object", description: "Operation parameters (passed to SDK method)" }
      },
      required: ["operation"]
    }
  },
  {
    name: "sovr_secure_chat",
    description: 'SOVR Secure Chat. Cloud mode \u2014 run with operation="list" to discover available operations.',
    inputSchema: {
      type: "object",
      properties: {
        operation: { type: "string", description: 'Operation to perform. Run with operation="list" to see available operations.' },
        params: { type: "object", description: "Operation parameters (passed to SDK method)" }
      },
      required: ["operation"]
    }
  },
  {
    name: "sovr_sla",
    description: 'SOVR Sla. Cloud mode \u2014 run with operation="list" to discover available operations.',
    inputSchema: {
      type: "object",
      properties: {
        operation: { type: "string", description: 'Operation to perform. Run with operation="list" to see available operations.' },
        params: { type: "object", description: "Operation parameters (passed to SDK method)" }
      },
      required: ["operation"]
    }
  },
  {
    name: "sovr_snapshot",
    description: 'SOVR Snapshot. Cloud mode \u2014 run with operation="list" to discover available operations.',
    inputSchema: {
      type: "object",
      properties: {
        operation: { type: "string", description: 'Operation to perform. Run with operation="list" to see available operations.' },
        params: { type: "object", description: "Operation parameters (passed to SDK method)" }
      },
      required: ["operation"]
    }
  },
  {
    name: "sovr_sovr_check",
    description: 'SOVR Check. Cloud mode \u2014 run with operation="list" to discover available operations.',
    inputSchema: {
      type: "object",
      properties: {
        operation: { type: "string", description: 'Operation to perform. Run with operation="list" to see available operations.' },
        params: { type: "object", description: "Operation parameters (passed to SDK method)" }
      },
      required: ["operation"]
    }
  },
  {
    name: "sovr_sovr_consume",
    description: 'SOVR Consume. Cloud mode \u2014 run with operation="list" to discover available operations.',
    inputSchema: {
      type: "object",
      properties: {
        operation: { type: "string", description: 'Operation to perform. Run with operation="list" to see available operations.' },
        params: { type: "object", description: "Operation parameters (passed to SDK method)" }
      },
      required: ["operation"]
    }
  },
  {
    name: "sovr_sovr_export",
    description: 'SOVR Export. Cloud mode \u2014 run with operation="list" to discover available operations.',
    inputSchema: {
      type: "object",
      properties: {
        operation: { type: "string", description: 'Operation to perform. Run with operation="list" to see available operations.' },
        params: { type: "object", description: "Operation parameters (passed to SDK method)" }
      },
      required: ["operation"]
    }
  },
  {
    name: "sovr_sovr_update",
    description: 'SOVR Update. Cloud mode \u2014 run with operation="list" to discover available operations.',
    inputSchema: {
      type: "object",
      properties: {
        operation: { type: "string", description: 'Operation to perform. Run with operation="list" to see available operations.' },
        params: { type: "object", description: "Operation parameters (passed to SDK method)" }
      },
      required: ["operation"]
    }
  },
  {
    name: "sovr_sovr_verify",
    description: 'SOVR Verify. Cloud mode \u2014 run with operation="list" to discover available operations.',
    inputSchema: {
      type: "object",
      properties: {
        operation: { type: "string", description: 'Operation to perform. Run with operation="list" to see available operations.' },
        params: { type: "object", description: "Operation parameters (passed to SDK method)" }
      },
      required: ["operation"]
    }
  },
  {
    name: "sovr_stripe",
    description: 'SOVR Stripe. Cloud mode \u2014 run with operation="list" to discover available operations.',
    inputSchema: {
      type: "object",
      properties: {
        operation: { type: "string", description: 'Operation to perform. Run with operation="list" to see available operations.' },
        params: { type: "object", description: "Operation parameters (passed to SDK method)" }
      },
      required: ["operation"]
    }
  },
  {
    name: "sovr_subscription",
    description: 'SOVR Subscription. Cloud mode \u2014 run with operation="list" to discover available operations.',
    inputSchema: {
      type: "object",
      properties: {
        operation: { type: "string", description: 'Operation to perform. Run with operation="list" to see available operations.' },
        params: { type: "object", description: "Operation parameters (passed to SDK method)" }
      },
      required: ["operation"]
    }
  },
  {
    name: "sovr_task_queue",
    description: 'SOVR Task Queue. Cloud mode \u2014 run with operation="list" to discover available operations.',
    inputSchema: {
      type: "object",
      properties: {
        operation: { type: "string", description: 'Operation to perform. Run with operation="list" to see available operations.' },
        params: { type: "object", description: "Operation parameters (passed to SDK method)" }
      },
      required: ["operation"]
    }
  },
  {
    name: "sovr_template",
    description: 'SOVR Template. Cloud mode \u2014 run with operation="list" to discover available operations.',
    inputSchema: {
      type: "object",
      properties: {
        operation: { type: "string", description: 'Operation to perform. Run with operation="list" to see available operations.' },
        params: { type: "object", description: "Operation parameters (passed to SDK method)" }
      },
      required: ["operation"]
    }
  },
  {
    name: "sovr_tenant",
    description: 'SOVR Tenant. Cloud mode \u2014 run with operation="list" to discover available operations.',
    inputSchema: {
      type: "object",
      properties: {
        operation: { type: "string", description: 'Operation to perform. Run with operation="list" to see available operations.' },
        params: { type: "object", description: "Operation parameters (passed to SDK method)" }
      },
      required: ["operation"]
    }
  },
  {
    name: "sovr_test_p",
    description: 'SOVR Test P. Cloud mode \u2014 run with operation="list" to discover available operations.',
    inputSchema: {
      type: "object",
      properties: {
        operation: { type: "string", description: 'Operation to perform. Run with operation="list" to see available operations.' },
        params: { type: "object", description: "Operation parameters (passed to SDK method)" }
      },
      required: ["operation"]
    }
  },
  {
    name: "sovr_test_rule",
    description: 'SOVR Test Rule. Cloud mode \u2014 run with operation="list" to discover available operations.',
    inputSchema: {
      type: "object",
      properties: {
        operation: { type: "string", description: 'Operation to perform. Run with operation="list" to see available operations.' },
        params: { type: "object", description: "Operation parameters (passed to SDK method)" }
      },
      required: ["operation"]
    }
  },
  {
    name: "sovr_threat",
    description: 'SOVR Threat. Cloud mode \u2014 run with operation="list" to discover available operations.',
    inputSchema: {
      type: "object",
      properties: {
        operation: { type: "string", description: 'Operation to perform. Run with operation="list" to see available operations.' },
        params: { type: "object", description: "Operation parameters (passed to SDK method)" }
      },
      required: ["operation"]
    }
  },
  {
    name: "sovr_today",
    description: 'SOVR Today. Cloud mode \u2014 run with operation="list" to discover available operations.',
    inputSchema: {
      type: "object",
      properties: {
        operation: { type: "string", description: 'Operation to perform. Run with operation="list" to see available operations.' },
        params: { type: "object", description: "Operation parameters (passed to SDK method)" }
      },
      required: ["operation"]
    }
  },
  {
    name: "sovr_trial",
    description: 'SOVR Trial. Cloud mode \u2014 run with operation="list" to discover available operations.',
    inputSchema: {
      type: "object",
      properties: {
        operation: { type: "string", description: 'Operation to perform. Run with operation="list" to see available operations.' },
        params: { type: "object", description: "Operation parameters (passed to SDK method)" }
      },
      required: ["operation"]
    }
  },
  {
    name: "sovr_trust_score",
    description: 'SOVR Trust Score. Cloud mode \u2014 run with operation="list" to discover available operations.',
    inputSchema: {
      type: "object",
      properties: {
        operation: { type: "string", description: 'Operation to perform. Run with operation="list" to see available operations.' },
        params: { type: "object", description: "Operation parameters (passed to SDK method)" }
      },
      required: ["operation"]
    }
  },
  {
    name: "sovr_twitter",
    description: 'SOVR Twitter. Cloud mode \u2014 run with operation="list" to discover available operations.',
    inputSchema: {
      type: "object",
      properties: {
        operation: { type: "string", description: 'Operation to perform. Run with operation="list" to see available operations.' },
        params: { type: "object", description: "Operation parameters (passed to SDK method)" }
      },
      required: ["operation"]
    }
  },
  {
    name: "sovr_update_p",
    description: 'SOVR Update P. Cloud mode \u2014 run with operation="list" to discover available operations.',
    inputSchema: {
      type: "object",
      properties: {
        operation: { type: "string", description: 'Operation to perform. Run with operation="list" to see available operations.' },
        params: { type: "object", description: "Operation parameters (passed to SDK method)" }
      },
      required: ["operation"]
    }
  },
  {
    name: "sovr_update_rollback",
    description: 'SOVR Update Rollback. Cloud mode \u2014 run with operation="list" to discover available operations.',
    inputSchema: {
      type: "object",
      properties: {
        operation: { type: "string", description: 'Operation to perform. Run with operation="list" to see available operations.' },
        params: { type: "object", description: "Operation parameters (passed to SDK method)" }
      },
      required: ["operation"]
    }
  },
  {
    name: "sovr_update_verification",
    description: 'SOVR Update Verification. Cloud mode \u2014 run with operation="list" to discover available operations.',
    inputSchema: {
      type: "object",
      properties: {
        operation: { type: "string", description: 'Operation to perform. Run with operation="list" to see available operations.' },
        params: { type: "object", description: "Operation parameters (passed to SDK method)" }
      },
      required: ["operation"]
    }
  },
  {
    name: "sovr_validate_access",
    description: 'SOVR Validate Access. Cloud mode \u2014 run with operation="list" to discover available operations.',
    inputSchema: {
      type: "object",
      properties: {
        operation: { type: "string", description: 'Operation to perform. Run with operation="list" to see available operations.' },
        params: { type: "object", description: "Operation parameters (passed to SDK method)" }
      },
      required: ["operation"]
    }
  },
  {
    name: "sovr_verification",
    description: 'SOVR Verification. Cloud mode \u2014 run with operation="list" to discover available operations.',
    inputSchema: {
      type: "object",
      properties: {
        operation: { type: "string", description: 'Operation to perform. Run with operation="list" to see available operations.' },
        params: { type: "object", description: "Operation parameters (passed to SDK method)" }
      },
      required: ["operation"]
    }
  },
  {
    name: "sovr_webhook",
    description: 'SOVR Webhook. Cloud mode \u2014 run with operation="list" to discover available operations.',
    inputSchema: {
      type: "object",
      properties: {
        operation: { type: "string", description: 'Operation to perform. Run with operation="list" to see available operations.' },
        params: { type: "object", description: "Operation parameters (passed to SDK method)" }
      },
      required: ["operation"]
    }
  }
];
function fmt(data) {
  return { content: [{ type: "text", text: JSON.stringify(data, null, 2) }] };
}
async function handleToolCall(name, args) {
  switch (name) {
    // ── Original Local Tools (v3.1.0 compatible) ────────────────────────
    case "sovr_gate_check": {
      const ch = args.channel ?? "mcp";
      const ctx = args.context ?? {};
      const d = evaluate(ch, args.action, args.resource, ctx);
      if (hasCloud()) {
        cloudSyncFire("/api/sovr/v1/cloud/gate", {
          decision_id: d.decision_id,
          verdict: d.verdict,
          risk_score: d.risk_score,
          channel: ch,
          action: args.action,
          matched_rules: d.matched_rules,
          reason: d.reason,
          parsed: ctx,
          timestamp: d.timestamp,
          mcp_server_version: VERSION
        });
      }
      return fmt({ ...d, cloud_connected: hasCloud(), tip: d.verdict === "escalate" ? "Action requires approval. Use sovr_request_approval." : d.verdict === "deny" ? "Action BLOCKED by policy. Do NOT proceed." : "Action allowed. Use sovr_submit_receipt after execution." });
    }
    case "sovr_check_command": {
      const p = parseCommand(args.command);
      const actionKey = p.subCommand ? `${p.command}_${p.subCommand}` : p.command;
      const d = evaluate("exec", actionKey, p.args.join(" ") || "*", { command: p.command, args: p.args.join(" "), has_sudo: p.hasSudo, has_pipe: p.hasPipe, has_chain: p.hasChain, sub_command: p.subCommand ?? void 0, risk_indicators: p.riskIndicators, raw_command: args.command.substring(0, 1e3) });
      if (hasCloud()) {
        cloudSyncFire("/api/sovr/v1/cloud/gate", { decision_id: d.decision_id, verdict: d.verdict, risk_score: d.risk_score, channel: "exec", action: args.command.substring(0, 128), matched_rules: d.matched_rules, reason: d.reason, parsed: { command: p.command, sub_command: p.subCommand, has_sudo: p.hasSudo }, timestamp: d.timestamp, mcp_server_version: VERSION });
      }
      return fmt({ ...d, parsed: { command: p.command, sub_command: p.subCommand, has_sudo: p.hasSudo, risk_indicators: p.riskIndicators } });
    }
    case "sovr_check_sql": {
      const p = parseSQL(args.sql);
      const d = evaluate("sql", p.type, p.tables.join(",") || "*", { statement_type: p.type, tables: p.tables, has_where_clause: p.hasWhereClause, raw_sql: p.raw.substring(0, 1e3), is_multi_statement: p.isMultiStatement });
      if (hasCloud()) {
        cloudSyncFire("/api/sovr/v1/cloud/gate", { decision_id: d.decision_id, verdict: d.verdict, risk_score: d.risk_score, channel: "sql", action: args.sql.substring(0, 128), matched_rules: d.matched_rules, reason: d.reason, parsed: { type: p.type, tables: p.tables, has_where_clause: p.hasWhereClause }, timestamp: d.timestamp, mcp_server_version: VERSION });
      }
      return fmt({ ...d, parsed: { type: p.type, tables: p.tables, has_where_clause: p.hasWhereClause, is_multi_statement: p.isMultiStatement } });
    }
    case "sovr_check_http": {
      const method = args.method.toUpperCase();
      let host;
      try {
        host = new URL(args.url).hostname;
      } catch {
        host = args.url;
      }
      const d = evaluate("http", method, host, { method, host, full_url: args.url.substring(0, 500) });
      if (hasCloud()) {
        cloudSyncFire("/api/sovr/v1/cloud/gate", { decision_id: d.decision_id, verdict: d.verdict, risk_score: d.risk_score, channel: "http", action: `${method} ${host}`, matched_rules: d.matched_rules, reason: d.reason, parsed: { method, host }, timestamp: d.timestamp, mcp_server_version: VERSION });
      }
      return fmt({ ...d, parsed: { method, host, full_url: args.url } });
    }
    case "sovr_request_approval": {
      if (hasCloud()) {
        const resp = await cloudRequest("/api/sovr/v1/cloud/approval", { action: args.action, resource: args.resource, reason: args.reason, urgency: args.urgency ?? "medium", channel: "mcp" }, 1e4);
        if (!resp.ok) return fmt({ status: "error", message: resp.error, fallback: "Cloud unavailable \u2014 logged locally only." });
        const ad = resp.data;
        if (!ad?.approval_id) return fmt({ status: "submitted", data: resp.data });
        const start = Date.now();
        let delay = 2e3;
        while (Date.now() - start < 6e5) {
          await new Promise((r) => setTimeout(r, delay));
          delay = Math.min(delay * 1.5, 15e3);
          try {
            const poll = await cloudRequest("/api/sovr/v1/cloud/approval", { approval_id: ad.approval_id, action: "check_status" }, 5e3);
            if (!poll.ok) continue;
            const pd = poll.data;
            if (pd.status === "approved") return fmt({ status: "approved", verdict: "allow", approval_id: ad.approval_id, message: "Action APPROVED. You may proceed.", elapsed_seconds: Math.round((Date.now() - start) / 1e3) });
            if (pd.status === "rejected") return fmt({ status: "rejected", verdict: "deny", approval_id: ad.approval_id, message: "Action REJECTED. Do NOT proceed.", elapsed_seconds: Math.round((Date.now() - start) / 1e3) });
            if (pd.status === "timed_out") return fmt({ status: "timed_out", verdict: "deny", approval_id: ad.approval_id, message: "Approval TIMED OUT. Denied by default." });
          } catch {
          }
        }
        return fmt({ status: "timed_out", verdict: "deny", approval_id: ad.approval_id, message: "Approval timed out after 600s. Denied by default." });
      }
      return fmt({ status: "pending_local", message: `Approval requested: ${args.action} on ${args.resource}`, reason: args.reason, note: "Local mode \u2014 connect to SOVR Cloud for full approval workflow.", cloud_upgrade: "https://sovr.inc/cloud" });
    }
    case "sovr_submit_receipt": {
      if (hasCloud()) {
        const permitResp = await cloudRequest("/api/sovr/v1/cloud/grant-permit", { decision_id: args.decision_id, ttl_seconds: 300 }, 1e4);
        if (!permitResp.ok) return fmt({ status: "error", message: `Failed to obtain permit: ${permitResp.error}` });
        const permitData = permitResp.data;
        if (!permitData?.permit_id) return fmt({ status: "error", message: "Permit response missing permit_id", data: permitResp.data });
        const now = Date.now();
        const outputSummary = args.output_summary || "";
        const externalRef = args.external_ref || `mcp-${now}`;
        const artifactRefs = args.artifact_refs || [];
        const idempotencyKey = `idem_${args.decision_id}_${now}`;
        const evidenceStr = JSON.stringify({ decision_id: args.decision_id, permit_id: permitData.permit_id, status: args.status, output_summary: outputSummary });
        let outputHash;
        try {
          const crypto = await import("crypto");
          outputHash = crypto.createHash("sha256").update(evidenceStr).digest("hex");
        } catch {
          outputHash = `hash_${now}`;
        }
        const resp = await cloudRequest("/api/sovr/v1/cloud/submit-receipt", {
          decision_id: args.decision_id,
          permit_id: permitData.permit_id,
          external_ref: externalRef,
          status: args.status === "partial" ? "success" : args.status === "rollback" ? "failure" : args.status,
          started_at: now - 1e3,
          finished_at: now,
          output_hash: outputHash,
          artifact_refs: artifactRefs,
          idempotency_key: idempotencyKey,
          ...args.status === "failure" || args.status === "rollback" ? { error_code: "EXEC_FAILED", error_message: outputSummary } : {}
        }, 1e4);
        if (resp.ok) return fmt({ ...resp.data, permit_id: permitData.permit_id, message: "Receipt submitted with permit and evidence hash." });
        return fmt({ status: "error", message: resp.error });
      }
      return fmt({ status: "logged_locally", decision_id: args.decision_id, note: "Connect to SOVR Cloud for persistent audit trail." });
    }
    case "sovr_add_rule": {
      const nr = { id: args.id, description: args.description, channels: args.channels, action_pattern: args.action_pattern, resource_pattern: args.resource_pattern, conditions: [], effect: args.effect, risk_level: args.risk_level ?? "medium", require_approval: args.effect !== "allow", priority: args.priority ?? 50, enabled: true };
      rules.push(nr);
      return fmt({ status: "added", rule: { id: nr.id, description: nr.description, effect: nr.effect }, total_rules: rules.length });
    }
    case "sovr_audit_log": {
      let entries = [...auditLog];
      const limit = Math.min(args.limit ?? 20, 100);
      if (args.channel) entries = entries.filter((e) => e.channel === args.channel);
      if (args.verdict) entries = entries.filter((e) => e.verdict === args.verdict);
      return fmt({ count: Math.min(entries.length, limit), entries: entries.slice(0, limit) });
    }
    // ── Cloud MCP Server parity tools (v5.4.0) ─────────────────────────
    case "sovr_cloud_status": {
      return await cloudDispatch("sovr_cloud_status", "cloudStatus", {});
    }
    case "sovr_escalate": {
      return await cloudDispatch("sovr_escalate", "escalate", {
        action: args.action,
        resource: args.resource,
        reason: args.reason,
        context: args.context ?? {}
      });
    }
    case "sovr_poll_escalation": {
      return await cloudDispatch("sovr_poll_escalation", "pollEscalation", {
        decision_id: args.decision_id
      });
    }
    case "sovr_query_decisions": {
      return await cloudDispatch("sovr_query_decisions", "queryDecisions", {
        limit: args.limit,
        verdict: args.verdict,
        action: args.action,
        from: args.from,
        to: args.to
      });
    }
    case "sovr_query_violations": {
      return await cloudDispatch("sovr_query_violations", "queryViolations", {
        limit: args.limit,
        severity: args.severity,
        status: args.status
      });
    }
    case "sovr_report_violation": {
      return await cloudDispatch("sovr_report_violation", "reportViolation", {
        action: args.action,
        resource: args.resource,
        violation_type: args.violation_type,
        severity: args.severity,
        details: args.details,
        decision_id: args.decision_id
      });
    }
    case "sovr_get_violation_stats": {
      return await cloudDispatch("sovr_get_violation_stats", "getViolationStats", {
        period: args.period
      });
    }
    case "sovr_replay_decision": {
      return await cloudDispatch("sovr_replay_decision", "replayDecision", {
        decision_id: args.decision_id
      });
    }
    case "sovr_export_bundle": {
      return await cloudDispatch("sovr_export_bundle", "exportBundle", {
        decision_id: args.decision_id,
        format: args.format
      });
    }
    case "sovr_grant_permit": {
      return await cloudDispatch("sovr_grant_permit", "grantPermit", {
        action: args.action,
        resource: args.resource,
        duration_minutes: args.duration_minutes,
        reason: args.reason
      });
    }
    case "sovr_openguard_scan": {
      return await cloudDispatch("sovr_openguard_scan", "scanContent", {
        content: args.content,
        categories: args.categories
      });
    }
    case "sovr_openguard_quick_scan": {
      return await cloudDispatch("sovr_openguard_quick_scan", "quickScan", {
        content: args.content
      });
    }
    // ── SDK Cloud-Dispatched Tools (254 tools) ──────────────────────────
    case "sovr_adapter": {
      const op = args.operation;
      const params = args.params ?? {};
      return await cloudDispatch("sovr_adapter", op, params);
    }
    case "sovr_ai_chat": {
      const op = args.operation;
      const params = args.params ?? {};
      return await cloudDispatch("sovr_ai_chat", op, params);
    }
    case "sovr_api_key": {
      const op = args.operation;
      const params = args.params ?? {};
      return await cloudDispatch("sovr_api_key", op, params);
    }
    case "sovr_approval": {
      const op = args.operation;
      const params = args.params ?? {};
      return await cloudDispatch("sovr_approval", op, params);
    }
    case "sovr_arbitrate": {
      const op = args.operation;
      const params = args.params ?? {};
      return await cloudDispatch("sovr_arbitrate", op, params);
    }
    case "sovr_assign_to": {
      const op = args.operation;
      const params = args.params ?? {};
      return await cloudDispatch("sovr_assign_to", op, params);
    }
    case "sovr_audit": {
      const op = args.operation;
      const params = args.params ?? {};
      return await cloudDispatch("sovr_audit", op, params);
    }
    case "sovr_backup": {
      const op = args.operation;
      const params = args.params ?? {};
      return await cloudDispatch("sovr_backup", op, params);
    }
    case "sovr_balance": {
      const op = args.operation;
      const params = args.params ?? {};
      return await cloudDispatch("sovr_balance", op, params);
    }
    case "sovr_batch_ops": {
      const op = args.operation;
      const params = args.params ?? {};
      return await cloudDispatch("sovr_batch_ops", op, params);
    }
    case "sovr_budget": {
      const op = args.operation;
      const params = args.params ?? {};
      return await cloudDispatch("sovr_budget", op, params);
    }
    case "sovr_bundle": {
      const op = args.operation;
      const params = args.params ?? {};
      return await cloudDispatch("sovr_bundle", op, params);
    }
    case "sovr_calculate_aggregate": {
      const op = args.operation;
      const params = args.params ?? {};
      return await cloudDispatch("sovr_calculate_aggregate", op, params);
    }
    case "sovr_canary": {
      const op = args.operation;
      const params = args.params ?? {};
      return await cloudDispatch("sovr_canary", op, params);
    }
    case "sovr_cancel_deployment": {
      const op = args.operation;
      const params = args.params ?? {};
      return await cloudDispatch("sovr_cancel_deployment", op, params);
    }
    case "sovr_cleanup": {
      const op = args.operation;
      const params = args.params ?? {};
      return await cloudDispatch("sovr_cleanup", op, params);
    }
    case "sovr_cognitive": {
      const op = args.operation;
      const params = args.params ?? {};
      return await cloudDispatch("sovr_cognitive", op, params);
    }
    case "sovr_compare_with": {
      const op = args.operation;
      const params = args.params ?? {};
      return await cloudDispatch("sovr_compare_with", op, params);
    }
    case "sovr_compliance": {
      const op = args.operation;
      const params = args.params ?? {};
      return await cloudDispatch("sovr_compliance", op, params);
    }
    case "sovr_config": {
      const op = args.operation;
      const params = args.params ?? {};
      return await cloudDispatch("sovr_config", op, params);
    }
    case "sovr_core_acknowledge": {
      const op = args.operation;
      const params = args.params ?? {};
      return await cloudDispatch("sovr_core_acknowledge", op, params);
    }
    case "sovr_core_batch": {
      const op = args.operation;
      const params = args.params ?? {};
      return await cloudDispatch("sovr_core_batch", op, params);
    }
    case "sovr_core_cancel": {
      const op = args.operation;
      const params = args.params ?? {};
      return await cloudDispatch("sovr_core_cancel", op, params);
    }
    case "sovr_core_check": {
      const op = args.operation;
      const params = args.params ?? {};
      return await cloudDispatch("sovr_core_check", op, params);
    }
    case "sovr_core_create": {
      const op = args.operation;
      const params = args.params ?? {};
      return await cloudDispatch("sovr_core_create", op, params);
    }
    case "sovr_core_demo": {
      const op = args.operation;
      const params = args.params ?? {};
      return await cloudDispatch("sovr_core_demo", op, params);
    }
    case "sovr_core_detail": {
      const op = args.operation;
      const params = args.params ?? {};
      return await cloudDispatch("sovr_core_detail", op, params);
    }
    case "sovr_core_event": {
      const op = args.operation;
      const params = args.params ?? {};
      return await cloudDispatch("sovr_core_event", op, params);
    }
    case "sovr_core_execute": {
      const op = args.operation;
      const params = args.params ?? {};
      return await cloudDispatch("sovr_core_execute", op, params);
    }
    case "sovr_core_find": {
      const op = args.operation;
      const params = args.params ?? {};
      return await cloudDispatch("sovr_core_find", op, params);
    }
    case "sovr_core_forgot": {
      const op = args.operation;
      const params = args.params ?? {};
      return await cloudDispatch("sovr_core_forgot", op, params);
    }
    case "sovr_core_full": {
      const op = args.operation;
      const params = args.params ?? {};
      return await cloudDispatch("sovr_core_full", op, params);
    }
    case "sovr_core_generate": {
      const op = args.operation;
      const params = args.params ?? {};
      return await cloudDispatch("sovr_core_generate", op, params);
    }
    case "sovr_core_get": {
      const op = args.operation;
      const params = args.params ?? {};
      return await cloudDispatch("sovr_core_get", op, params);
    }
    case "sovr_core_has": {
      const op = args.operation;
      const params = args.params ?? {};
      return await cloudDispatch("sovr_core_has", op, params);
    }
    case "sovr_core_hot": {
      const op = args.operation;
      const params = args.params ?? {};
      return await cloudDispatch("sovr_core_hot", op, params);
    }
    case "sovr_core_im": {
      const op = args.operation;
      const params = args.params ?? {};
      return await cloudDispatch("sovr_core_im", op, params);
    }
    case "sovr_core_increment": {
      const op = args.operation;
      const params = args.params ?? {};
      return await cloudDispatch("sovr_core_increment", op, params);
    }
    case "sovr_core_init": {
      const op = args.operation;
      const params = args.params ?? {};
      return await cloudDispatch("sovr_core_init", op, params);
    }
    case "sovr_core_initialize": {
      const op = args.operation;
      const params = args.params ?? {};
      return await cloudDispatch("sovr_core_initialize", op, params);
    }
    case "sovr_core_linked": {
      const op = args.operation;
      const params = args.params ?? {};
      return await cloudDispatch("sovr_core_linked", op, params);
    }
    case "sovr_core_list": {
      const op = args.operation;
      const params = args.params ?? {};
      return await cloudDispatch("sovr_core_list", op, params);
    }
    case "sovr_core_load": {
      const op = args.operation;
      const params = args.params ?? {};
      return await cloudDispatch("sovr_core_load", op, params);
    }
    case "sovr_core_login": {
      const op = args.operation;
      const params = args.params ?? {};
      return await cloudDispatch("sovr_core_login", op, params);
    }
    case "sovr_core_logout": {
      const op = args.operation;
      const params = args.params ?? {};
      return await cloudDispatch("sovr_core_logout", op, params);
    }
    case "sovr_core_manifest": {
      const op = args.operation;
      const params = args.params ?? {};
      return await cloudDispatch("sovr_core_manifest", op, params);
    }
    case "sovr_core_manifests": {
      const op = args.operation;
      const params = args.params ?? {};
      return await cloudDispatch("sovr_core_manifests", op, params);
    }
    case "sovr_core_manual": {
      const op = args.operation;
      const params = args.params ?? {};
      return await cloudDispatch("sovr_core_manual", op, params);
    }
    case "sovr_core_me": {
      const op = args.operation;
      const params = args.params ?? {};
      return await cloudDispatch("sovr_core_me", op, params);
    }
    case "sovr_core_my": {
      const op = args.operation;
      const params = args.params ?? {};
      return await cloudDispatch("sovr_core_my", op, params);
    }
    case "sovr_core_network": {
      const op = args.operation;
      const params = args.params ?? {};
      return await cloudDispatch("sovr_core_network", op, params);
    }
    case "sovr_core_overview": {
      const op = args.operation;
      const params = args.params ?? {};
      return await cloudDispatch("sovr_core_overview", op, params);
    }
    case "sovr_core_parse": {
      const op = args.operation;
      const params = args.params ?? {};
      return await cloudDispatch("sovr_core_parse", op, params);
    }
    case "sovr_core_persisted": {
      const op = args.operation;
      const params = args.params ?? {};
      return await cloudDispatch("sovr_core_persisted", op, params);
    }
    case "sovr_core_persistence": {
      const op = args.operation;
      const params = args.params ?? {};
      return await cloudDispatch("sovr_core_persistence", op, params);
    }
    case "sovr_core_preset": {
      const op = args.operation;
      const params = args.params ?? {};
      return await cloudDispatch("sovr_core_preset", op, params);
    }
    case "sovr_core_preview": {
      const op = args.operation;
      const params = args.params ?? {};
      return await cloudDispatch("sovr_core_preview", op, params);
    }
    case "sovr_core_process": {
      const op = args.operation;
      const params = args.params ?? {};
      return await cloudDispatch("sovr_core_process", op, params);
    }
    case "sovr_core_quota": {
      const op = args.operation;
      const params = args.params ?? {};
      return await cloudDispatch("sovr_core_quota", op, params);
    }
    case "sovr_core_recalculate": {
      const op = args.operation;
      const params = args.params ?? {};
      return await cloudDispatch("sovr_core_recalculate", op, params);
    }
    case "sovr_core_register": {
      const op = args.operation;
      const params = args.params ?? {};
      return await cloudDispatch("sovr_core_register", op, params);
    }
    case "sovr_core_render": {
      const op = args.operation;
      const params = args.params ?? {};
      return await cloudDispatch("sovr_core_render", op, params);
    }
    case "sovr_core_request": {
      const op = args.operation;
      const params = args.params ?? {};
      return await cloudDispatch("sovr_core_request", op, params);
    }
    case "sovr_core_resend": {
      const op = args.operation;
      const params = args.params ?? {};
      return await cloudDispatch("sovr_core_resend", op, params);
    }
    case "sovr_core_reset": {
      const op = args.operation;
      const params = args.params ?? {};
      return await cloudDispatch("sovr_core_reset", op, params);
    }
    case "sovr_core_restore": {
      const op = args.operation;
      const params = args.params ?? {};
      return await cloudDispatch("sovr_core_restore", op, params);
    }
    case "sovr_core_retry": {
      const op = args.operation;
      const params = args.params ?? {};
      return await cloudDispatch("sovr_core_retry", op, params);
    }
    case "sovr_core_review": {
      const op = args.operation;
      const params = args.params ?? {};
      return await cloudDispatch("sovr_core_review", op, params);
    }
    case "sovr_core_revoke": {
      const op = args.operation;
      const params = args.params ?? {};
      return await cloudDispatch("sovr_core_revoke", op, params);
    }
    case "sovr_core_risk": {
      const op = args.operation;
      const params = args.params ?? {};
      return await cloudDispatch("sovr_core_risk", op, params);
    }
    case "sovr_core_rotate": {
      const op = args.operation;
      const params = args.params ?? {};
      return await cloudDispatch("sovr_core_rotate", op, params);
    }
    case "sovr_core_run": {
      const op = args.operation;
      const params = args.params ?? {};
      return await cloudDispatch("sovr_core_run", op, params);
    }
    case "sovr_core_save": {
      const op = args.operation;
      const params = args.params ?? {};
      return await cloudDispatch("sovr_core_save", op, params);
    }
    case "sovr_core_schedule": {
      const op = args.operation;
      const params = args.params ?? {};
      return await cloudDispatch("sovr_core_schedule", op, params);
    }
    case "sovr_core_set": {
      const op = args.operation;
      const params = args.params ?? {};
      return await cloudDispatch("sovr_core_set", op, params);
    }
    case "sovr_core_simulate": {
      const op = args.operation;
      const params = args.params ?? {};
      return await cloudDispatch("sovr_core_simulate", op, params);
    }
    case "sovr_core_subscribe": {
      const op = args.operation;
      const params = args.params ?? {};
      return await cloudDispatch("sovr_core_subscribe", op, params);
    }
    case "sovr_core_sufficiency": {
      const op = args.operation;
      const params = args.params ?? {};
      return await cloudDispatch("sovr_core_sufficiency", op, params);
    }
    case "sovr_core_summary": {
      const op = args.operation;
      const params = args.params ?? {};
      return await cloudDispatch("sovr_core_summary", op, params);
    }
    case "sovr_core_test": {
      const op = args.operation;
      const params = args.params ?? {};
      return await cloudDispatch("sovr_core_test", op, params);
    }
    case "sovr_core_time": {
      const op = args.operation;
      const params = args.params ?? {};
      return await cloudDispatch("sovr_core_time", op, params);
    }
    case "sovr_core_tls": {
      const op = args.operation;
      const params = args.params ?? {};
      return await cloudDispatch("sovr_core_tls", op, params);
    }
    case "sovr_core_toggle": {
      const op = args.operation;
      const params = args.params ?? {};
      return await cloudDispatch("sovr_core_toggle", op, params);
    }
    case "sovr_core_top": {
      const op = args.operation;
      const params = args.params ?? {};
      return await cloudDispatch("sovr_core_top", op, params);
    }
    case "sovr_core_trigger": {
      const op = args.operation;
      const params = args.params ?? {};
      return await cloudDispatch("sovr_core_trigger", op, params);
    }
    case "sovr_core_unlink": {
      const op = args.operation;
      const params = args.params ?? {};
      return await cloudDispatch("sovr_core_unlink", op, params);
    }
    case "sovr_core_unsubscribe": {
      const op = args.operation;
      const params = args.params ?? {};
      return await cloudDispatch("sovr_core_unsubscribe", op, params);
    }
    case "sovr_core_update": {
      const op = args.operation;
      const params = args.params ?? {};
      return await cloudDispatch("sovr_core_update", op, params);
    }
    case "sovr_core_usage": {
      const op = args.operation;
      const params = args.params ?? {};
      return await cloudDispatch("sovr_core_usage", op, params);
    }
    case "sovr_core_validate": {
      const op = args.operation;
      const params = args.params ?? {};
      return await cloudDispatch("sovr_core_validate", op, params);
    }
    case "sovr_core_vault": {
      const op = args.operation;
      const params = args.params ?? {};
      return await cloudDispatch("sovr_core_vault", op, params);
    }
    case "sovr_cost": {
      const op = args.operation;
      const params = args.params ?? {};
      return await cloudDispatch("sovr_cost", op, params);
    }
    case "sovr_create_backup": {
      const op = args.operation;
      const params = args.params ?? {};
      return await cloudDispatch("sovr_create_backup", op, params);
    }
    case "sovr_create_canary": {
      const op = args.operation;
      const params = args.params ?? {};
      return await cloudDispatch("sovr_create_canary", op, params);
    }
    case "sovr_create_checkout": {
      const op = args.operation;
      const params = args.params ?? {};
      return await cloudDispatch("sovr_create_checkout", op, params);
    }
    case "sovr_create_checkpoint": {
      const op = args.operation;
      const params = args.params ?? {};
      return await cloudDispatch("sovr_create_checkpoint", op, params);
    }
    case "sovr_create_consent": {
      const op = args.operation;
      const params = args.params ?? {};
      return await cloudDispatch("sovr_create_consent", op, params);
    }
    case "sovr_create_custom": {
      const op = args.operation;
      const params = args.params ?? {};
      return await cloudDispatch("sovr_create_custom", op, params);
    }
    case "sovr_create_data": {
      const op = args.operation;
      const params = args.params ?? {};
      return await cloudDispatch("sovr_create_data", op, params);
    }
    case "sovr_create_dispute": {
      const op = args.operation;
      const params = args.params ?? {};
      return await cloudDispatch("sovr_create_dispute", op, params);
    }
    case "sovr_create_feature": {
      const op = args.operation;
      const params = args.params ?? {};
      return await cloudDispatch("sovr_create_feature", op, params);
    }
    case "sovr_create_fusion": {
      const op = args.operation;
      const params = args.params ?? {};
      return await cloudDispatch("sovr_create_fusion", op, params);
    }
    case "sovr_create_incident": {
      const op = args.operation;
      const params = args.params ?? {};
      return await cloudDispatch("sovr_create_incident", op, params);
    }
    case "sovr_create_lifecycle": {
      const op = args.operation;
      const params = args.params ?? {};
      return await cloudDispatch("sovr_create_lifecycle", op, params);
    }
    case "sovr_create_masking": {
      const op = args.operation;
      const params = args.params ?? {};
      return await cloudDispatch("sovr_create_masking", op, params);
    }
    case "sovr_create_p": {
      const op = args.operation;
      const params = args.params ?? {};
      return await cloudDispatch("sovr_create_p", op, params);
    }
    case "sovr_create_replay": {
      const op = args.operation;
      const params = args.params ?? {};
      return await cloudDispatch("sovr_create_replay", op, params);
    }
    case "sovr_create_report": {
      const op = args.operation;
      const params = args.params ?? {};
      return await cloudDispatch("sovr_create_report", op, params);
    }
    case "sovr_create_restore": {
      const op = args.operation;
      const params = args.params ?? {};
      return await cloudDispatch("sovr_create_restore", op, params);
    }
    case "sovr_create_risk": {
      const op = args.operation;
      const params = args.params ?? {};
      return await cloudDispatch("sovr_create_risk", op, params);
    }
    case "sovr_create_rule": {
      const op = args.operation;
      const params = args.params ?? {};
      return await cloudDispatch("sovr_create_rule", op, params);
    }
    case "sovr_create_stripe": {
      const op = args.operation;
      const params = args.params ?? {};
      return await cloudDispatch("sovr_create_stripe", op, params);
    }
    case "sovr_create_tenant": {
      const op = args.operation;
      const params = args.params ?? {};
      return await cloudDispatch("sovr_create_tenant", op, params);
    }
    case "sovr_data_governance": {
      const op = args.operation;
      const params = args.params ?? {};
      return await cloudDispatch("sovr_data_governance", op, params);
    }
    case "sovr_deactivate_prompt": {
      const op = args.operation;
      const params = args.params ?? {};
      return await cloudDispatch("sovr_deactivate_prompt", op, params);
    }
    case "sovr_default_deny": {
      const op = args.operation;
      const params = args.params ?? {};
      return await cloudDispatch("sovr_default_deny", op, params);
    }
    case "sovr_degradation": {
      const op = args.operation;
      const params = args.params ?? {};
      return await cloudDispatch("sovr_degradation", op, params);
    }
    case "sovr_delete_fusion": {
      const op = args.operation;
      const params = args.params ?? {};
      return await cloudDispatch("sovr_delete_fusion", op, params);
    }
    case "sovr_delete_p": {
      const op = args.operation;
      const params = args.params ?? {};
      return await cloudDispatch("sovr_delete_p", op, params);
    }
    case "sovr_delete_report": {
      const op = args.operation;
      const params = args.params ?? {};
      return await cloudDispatch("sovr_delete_report", op, params);
    }
    case "sovr_delete_rule": {
      const op = args.operation;
      const params = args.params ?? {};
      return await cloudDispatch("sovr_delete_rule", op, params);
    }
    case "sovr_demo": {
      const op = args.operation;
      const params = args.params ?? {};
      return await cloudDispatch("sovr_demo", op, params);
    }
    case "sovr_deployment": {
      const op = args.operation;
      const params = args.params ?? {};
      return await cloudDispatch("sovr_deployment", op, params);
    }
    case "sovr_deprecate_policy": {
      const op = args.operation;
      const params = args.params ?? {};
      return await cloudDispatch("sovr_deprecate_policy", op, params);
    }
    case "sovr_detect_conflict": {
      const op = args.operation;
      const params = args.params ?? {};
      return await cloudDispatch("sovr_detect_conflict", op, params);
    }
    case "sovr_detect_hallucination": {
      const op = args.operation;
      const params = args.params ?? {};
      return await cloudDispatch("sovr_detect_hallucination", op, params);
    }
    case "sovr_detect_policy": {
      const op = args.operation;
      const params = args.params ?? {};
      return await cloudDispatch("sovr_detect_policy", op, params);
    }
    case "sovr_dispatch_p": {
      const op = args.operation;
      const params = args.params ?? {};
      return await cloudDispatch("sovr_dispatch_p", op, params);
    }
    case "sovr_dispute": {
      const op = args.operation;
      const params = args.params ?? {};
      return await cloudDispatch("sovr_dispute", op, params);
    }
    case "sovr_email": {
      const op = args.operation;
      const params = args.params ?? {};
      return await cloudDispatch("sovr_email", op, params);
    }
    case "sovr_enable_lifecycle": {
      const op = args.operation;
      const params = args.params ?? {};
      return await cloudDispatch("sovr_enable_lifecycle", op, params);
    }
    case "sovr_enterprise": {
      const op = args.operation;
      const params = args.params ?? {};
      return await cloudDispatch("sovr_enterprise", op, params);
    }
    case "sovr_evaluate_metric": {
      const op = args.operation;
      const params = args.params ?? {};
      return await cloudDispatch("sovr_evaluate_metric", op, params);
    }
    case "sovr_execute_p": {
      const op = args.operation;
      const params = args.params ?? {};
      return await cloudDispatch("sovr_execute_p", op, params);
    }
    case "sovr_execute_quality": {
      const op = args.operation;
      const params = args.params ?? {};
      return await cloudDispatch("sovr_execute_quality", op, params);
    }
    case "sovr_execute_report": {
      const op = args.operation;
      const params = args.params ?? {};
      return await cloudDispatch("sovr_execute_report", op, params);
    }
    case "sovr_execute_rollback": {
      const op = args.operation;
      const params = args.params ?? {};
      return await cloudDispatch("sovr_execute_rollback", op, params);
    }
    case "sovr_experiment": {
      const op = args.operation;
      const params = args.params ?? {};
      return await cloudDispatch("sovr_experiment", op, params);
    }
    case "sovr_external_api": {
      const op = args.operation;
      const params = args.params ?? {};
      return await cloudDispatch("sovr_external_api", op, params);
    }
    case "sovr_external_gate": {
      const op = args.operation;
      const params = args.params ?? {};
      return await cloudDispatch("sovr_external_gate", op, params);
    }
    case "sovr_failure_budget": {
      const op = args.operation;
      const params = args.params ?? {};
      return await cloudDispatch("sovr_failure_budget", op, params);
    }
    case "sovr_feature_flag": {
      const op = args.operation;
      const params = args.params ?? {};
      return await cloudDispatch("sovr_feature_flag", op, params);
    }
    case "sovr_filter_items": {
      const op = args.operation;
      const params = args.params ?? {};
      return await cloudDispatch("sovr_filter_items", op, params);
    }
    case "sovr_find_precedents": {
      const op = args.operation;
      const params = args.params ?? {};
      return await cloudDispatch("sovr_find_precedents", op, params);
    }
    case "sovr_fusion": {
      const op = args.operation;
      const params = args.params ?? {};
      return await cloudDispatch("sovr_fusion", op, params);
    }
    case "sovr_gate": {
      const op = args.operation;
      const params = args.params ?? {};
      return await cloudDispatch("sovr_gate", op, params);
    }
    case "sovr_generate_certificate": {
      const op = args.operation;
      const params = args.params ?? {};
      return await cloudDispatch("sovr_generate_certificate", op, params);
    }
    case "sovr_generate_diff": {
      const op = args.operation;
      const params = args.params ?? {};
      return await cloudDispatch("sovr_generate_diff", op, params);
    }
    case "sovr_geo": {
      const op = args.operation;
      const params = args.params ?? {};
      return await cloudDispatch("sovr_geo", op, params);
    }
    case "sovr_get_action": {
      const op = args.operation;
      const params = args.params ?? {};
      return await cloudDispatch("sovr_get_action", op, params);
    }
    case "sovr_get_active": {
      const op = args.operation;
      const params = args.params ?? {};
      return await cloudDispatch("sovr_get_active", op, params);
    }
    case "sovr_get_adjacent": {
      const op = args.operation;
      const params = args.params ?? {};
      return await cloudDispatch("sovr_get_adjacent", op, params);
    }
    case "sovr_get_alert": {
      const op = args.operation;
      const params = args.params ?? {};
      return await cloudDispatch("sovr_get_alert", op, params);
    }
    case "sovr_get_all": {
      const op = args.operation;
      const params = args.params ?? {};
      return await cloudDispatch("sovr_get_all", op, params);
    }
    case "sovr_get_approval": {
      const op = args.operation;
      const params = args.params ?? {};
      return await cloudDispatch("sovr_get_approval", op, params);
    }
    case "sovr_get_chat": {
      const op = args.operation;
      const params = args.params ?? {};
      return await cloudDispatch("sovr_get_chat", op, params);
    }
    case "sovr_get_checkpoint": {
      const op = args.operation;
      const params = args.params ?? {};
      return await cloudDispatch("sovr_get_checkpoint", op, params);
    }
    case "sovr_get_constraint": {
      const op = args.operation;
      const params = args.params ?? {};
      return await cloudDispatch("sovr_get_constraint", op, params);
    }
    case "sovr_get_content": {
      const op = args.operation;
      const params = args.params ?? {};
      return await cloudDispatch("sovr_get_content", op, params);
    }
    case "sovr_get_cost": {
      const op = args.operation;
      const params = args.params ?? {};
      return await cloudDispatch("sovr_get_cost", op, params);
    }
    case "sovr_get_custom": {
      const op = args.operation;
      const params = args.params ?? {};
      return await cloudDispatch("sovr_get_custom", op, params);
    }
    case "sovr_get_dangerous": {
      const op = args.operation;
      const params = args.params ?? {};
      return await cloudDispatch("sovr_get_dangerous", op, params);
    }
    case "sovr_get_data": {
      const op = args.operation;
      const params = args.params ?? {};
      return await cloudDispatch("sovr_get_data", op, params);
    }
    case "sovr_get_dispute": {
      const op = args.operation;
      const params = args.params ?? {};
      return await cloudDispatch("sovr_get_dispute", op, params);
    }
    case "sovr_get_entity": {
      const op = args.operation;
      const params = args.params ?? {};
      return await cloudDispatch("sovr_get_entity", op, params);
    }
    case "sovr_get_gate": {
      const op = args.operation;
      const params = args.params ?? {};
      return await cloudDispatch("sovr_get_gate", op, params);
    }
    case "sovr_get_high": {
      const op = args.operation;
      const params = args.params ?? {};
      return await cloudDispatch("sovr_get_high", op, params);
    }
    case "sovr_get_known": {
      const op = args.operation;
      const params = args.params ?? {};
      return await cloudDispatch("sovr_get_known", op, params);
    }
    case "sovr_get_metric": {
      const op = args.operation;
      const params = args.params ?? {};
      return await cloudDispatch("sovr_get_metric", op, params);
    }
    case "sovr_get_open": {
      const op = args.operation;
      const params = args.params ?? {};
      return await cloudDispatch("sovr_get_open", op, params);
    }
    case "sovr_get_p": {
      const op = args.operation;
      const params = args.params ?? {};
      return await cloudDispatch("sovr_get_p", op, params);
    }
    case "sovr_get_pending": {
      const op = args.operation;
      const params = args.params ?? {};
      return await cloudDispatch("sovr_get_pending", op, params);
    }
    case "sovr_get_risk": {
      const op = args.operation;
      const params = args.params ?? {};
      return await cloudDispatch("sovr_get_risk", op, params);
    }
    case "sovr_get_role": {
      const op = args.operation;
      const params = args.params ?? {};
      return await cloudDispatch("sovr_get_role", op, params);
    }
    case "sovr_get_rollback": {
      const op = args.operation;
      const params = args.params ?? {};
      return await cloudDispatch("sovr_get_rollback", op, params);
    }
    case "sovr_get_scan": {
      const op = args.operation;
      const params = args.params ?? {};
      return await cloudDispatch("sovr_get_scan", op, params);
    }
    case "sovr_get_status": {
      const op = args.operation;
      const params = args.params ?? {};
      return await cloudDispatch("sovr_get_status", op, params);
    }
    case "sovr_get_top": {
      const op = args.operation;
      const params = args.params ?? {};
      return await cloudDispatch("sovr_get_top", op, params);
    }
    case "sovr_integration": {
      const op = args.operation;
      const params = args.params ?? {};
      return await cloudDispatch("sovr_integration", op, params);
    }
    case "sovr_kill_switch": {
      const op = args.operation;
      const params = args.params ?? {};
      return await cloudDispatch("sovr_kill_switch", op, params);
    }
    case "sovr_lifecycle": {
      const op = args.operation;
      const params = args.params ?? {};
      return await cloudDispatch("sovr_lifecycle", op, params);
    }
    case "sovr_list_active": {
      const op = args.operation;
      const params = args.params ?? {};
      return await cloudDispatch("sovr_list_active", op, params);
    }
    case "sovr_list_custom": {
      const op = args.operation;
      const params = args.params ?? {};
      return await cloudDispatch("sovr_list_custom", op, params);
    }
    case "sovr_list_fusion": {
      const op = args.operation;
      const params = args.params ?? {};
      return await cloudDispatch("sovr_list_fusion", op, params);
    }
    case "sovr_list_p": {
      const op = args.operation;
      const params = args.params ?? {};
      return await cloudDispatch("sovr_list_p", op, params);
    }
    case "sovr_list_pending": {
      const op = args.operation;
      const params = args.params ?? {};
      return await cloudDispatch("sovr_list_pending", op, params);
    }
    case "sovr_list_policy": {
      const op = args.operation;
      const params = args.params ?? {};
      return await cloudDispatch("sovr_list_policy", op, params);
    }
    case "sovr_list_replay": {
      const op = args.operation;
      const params = args.params ?? {};
      return await cloudDispatch("sovr_list_replay", op, params);
    }
    case "sovr_list_report": {
      const op = args.operation;
      const params = args.params ?? {};
      return await cloudDispatch("sovr_list_report", op, params);
    }
    case "sovr_list_rules": {
      const op = args.operation;
      const params = args.params ?? {};
      return await cloudDispatch("sovr_list_rules", op, params);
    }
    case "sovr_list_trust": {
      const op = args.operation;
      const params = args.params ?? {};
      return await cloudDispatch("sovr_list_trust", op, params);
    }
    case "sovr_live_chat": {
      const op = args.operation;
      const params = args.params ?? {};
      return await cloudDispatch("sovr_live_chat", op, params);
    }
    case "sovr_log_decision": {
      const op = args.operation;
      const params = args.params ?? {};
      return await cloudDispatch("sovr_log_decision", op, params);
    }
    case "sovr_manual_trigger": {
      const op = args.operation;
      const params = args.params ?? {};
      return await cloudDispatch("sovr_manual_trigger", op, params);
    }
    case "sovr_marketing": {
      const op = args.operation;
      const params = args.params ?? {};
      return await cloudDispatch("sovr_marketing", op, params);
    }
    case "sovr_mcp_instance": {
      const op = args.operation;
      const params = args.params ?? {};
      return await cloudDispatch("sovr_mcp_instance", op, params);
    }
    case "sovr_memory": {
      const op = args.operation;
      const params = args.params ?? {};
      return await cloudDispatch("sovr_memory", op, params);
    }
    case "sovr_metering": {
      const op = args.operation;
      const params = args.params ?? {};
      return await cloudDispatch("sovr_metering", op, params);
    }
    case "sovr_model_ops": {
      const op = args.operation;
      const params = args.params ?? {};
      return await cloudDispatch("sovr_model_ops", op, params);
    }
    case "sovr_monitor": {
      const op = args.operation;
      const params = args.params ?? {};
      return await cloudDispatch("sovr_monitor", op, params);
    }
    case "sovr_p0_alerts": {
      const op = args.operation;
      const params = args.params ?? {};
      return await cloudDispatch("sovr_p0_alerts", op, params);
    }
    case "sovr_p3_ops": {
      const op = args.operation;
      const params = args.params ?? {};
      return await cloudDispatch("sovr_p3_ops", op, params);
    }
    case "sovr_permit": {
      const op = args.operation;
      const params = args.params ?? {};
      return await cloudDispatch("sovr_permit", op, params);
    }
    case "sovr_policy": {
      const op = args.operation;
      const params = args.params ?? {};
      return await cloudDispatch("sovr_policy", op, params);
    }
    case "sovr_protect": {
      const op = args.operation;
      const params = args.params ?? {};
      return await cloudDispatch("sovr_protect", op, params);
    }
    case "sovr_qa": {
      const op = args.operation;
      const params = args.params ?? {};
      return await cloudDispatch("sovr_qa", op, params);
    }
    case "sovr_quick_fact": {
      const op = args.operation;
      const params = args.params ?? {};
      return await cloudDispatch("sovr_quick_fact", op, params);
    }
    case "sovr_quick_hallucination": {
      const op = args.operation;
      const params = args.params ?? {};
      return await cloudDispatch("sovr_quick_hallucination", op, params);
    }
    case "sovr_rbac": {
      const op = args.operation;
      const params = args.params ?? {};
      return await cloudDispatch("sovr_rbac", op, params);
    }
    case "sovr_real_time": {
      const op = args.operation;
      const params = args.params ?? {};
      return await cloudDispatch("sovr_real_time", op, params);
    }
    case "sovr_receipt": {
      const op = args.operation;
      const params = args.params ?? {};
      return await cloudDispatch("sovr_receipt", op, params);
    }
    case "sovr_record_metric": {
      const op = args.operation;
      const params = args.params ?? {};
      return await cloudDispatch("sovr_record_metric", op, params);
    }
    case "sovr_referral": {
      const op = args.operation;
      const params = args.params ?? {};
      return await cloudDispatch("sovr_referral", op, params);
    }
    case "sovr_regression": {
      const op = args.operation;
      const params = args.params ?? {};
      return await cloudDispatch("sovr_regression", op, params);
    }
    case "sovr_replay": {
      const op = args.operation;
      const params = args.params ?? {};
      return await cloudDispatch("sovr_replay", op, params);
    }
    case "sovr_report": {
      const op = args.operation;
      const params = args.params ?? {};
      return await cloudDispatch("sovr_report", op, params);
    }
    case "sovr_reset_all": {
      const op = args.operation;
      const params = args.params ?? {};
      return await cloudDispatch("sovr_reset_all", op, params);
    }
    case "sovr_resolve_conflict": {
      const op = args.operation;
      const params = args.params ?? {};
      return await cloudDispatch("sovr_resolve_conflict", op, params);
    }
    case "sovr_resolve_p": {
      const op = args.operation;
      const params = args.params ?? {};
      return await cloudDispatch("sovr_resolve_p", op, params);
    }
    case "sovr_retry_p": {
      const op = args.operation;
      const params = args.params ?? {};
      return await cloudDispatch("sovr_retry_p", op, params);
    }
    case "sovr_risk": {
      const op = args.operation;
      const params = args.params ?? {};
      return await cloudDispatch("sovr_risk", op, params);
    }
    case "sovr_rollback": {
      const op = args.operation;
      const params = args.params ?? {};
      return await cloudDispatch("sovr_rollback", op, params);
    }
    case "sovr_rule": {
      const op = args.operation;
      const params = args.params ?? {};
      return await cloudDispatch("sovr_rule", op, params);
    }
    case "sovr_run_all": {
      const op = args.operation;
      const params = args.params ?? {};
      return await cloudDispatch("sovr_run_all", op, params);
    }
    case "sovr_run_full": {
      const op = args.operation;
      const params = args.params ?? {};
      return await cloudDispatch("sovr_run_full", op, params);
    }
    case "sovr_run_l": {
      const op = args.operation;
      const params = args.params ?? {};
      return await cloudDispatch("sovr_run_l", op, params);
    }
    case "sovr_scan": {
      const op = args.operation;
      const params = args.params ?? {};
      return await cloudDispatch("sovr_scan", op, params);
    }
    case "sovr_scheduler": {
      const op = args.operation;
      const params = args.params ?? {};
      return await cloudDispatch("sovr_scheduler", op, params);
    }
    case "sovr_secure_chat": {
      const op = args.operation;
      const params = args.params ?? {};
      return await cloudDispatch("sovr_secure_chat", op, params);
    }
    case "sovr_sla": {
      const op = args.operation;
      const params = args.params ?? {};
      return await cloudDispatch("sovr_sla", op, params);
    }
    case "sovr_snapshot": {
      const op = args.operation;
      const params = args.params ?? {};
      return await cloudDispatch("sovr_snapshot", op, params);
    }
    case "sovr_sovr_check": {
      const op = args.operation;
      const params = args.params ?? {};
      return await cloudDispatch("sovr_sovr_check", op, params);
    }
    case "sovr_sovr_consume": {
      const op = args.operation;
      const params = args.params ?? {};
      return await cloudDispatch("sovr_sovr_consume", op, params);
    }
    case "sovr_sovr_export": {
      const op = args.operation;
      const params = args.params ?? {};
      return await cloudDispatch("sovr_sovr_export", op, params);
    }
    case "sovr_sovr_update": {
      const op = args.operation;
      const params = args.params ?? {};
      return await cloudDispatch("sovr_sovr_update", op, params);
    }
    case "sovr_sovr_verify": {
      const op = args.operation;
      const params = args.params ?? {};
      return await cloudDispatch("sovr_sovr_verify", op, params);
    }
    case "sovr_stripe": {
      const op = args.operation;
      const params = args.params ?? {};
      return await cloudDispatch("sovr_stripe", op, params);
    }
    case "sovr_subscription": {
      const op = args.operation;
      const params = args.params ?? {};
      return await cloudDispatch("sovr_subscription", op, params);
    }
    case "sovr_task_queue": {
      const op = args.operation;
      const params = args.params ?? {};
      return await cloudDispatch("sovr_task_queue", op, params);
    }
    case "sovr_template": {
      const op = args.operation;
      const params = args.params ?? {};
      return await cloudDispatch("sovr_template", op, params);
    }
    case "sovr_tenant": {
      const op = args.operation;
      const params = args.params ?? {};
      return await cloudDispatch("sovr_tenant", op, params);
    }
    case "sovr_test_p": {
      const op = args.operation;
      const params = args.params ?? {};
      return await cloudDispatch("sovr_test_p", op, params);
    }
    case "sovr_test_rule": {
      const op = args.operation;
      const params = args.params ?? {};
      return await cloudDispatch("sovr_test_rule", op, params);
    }
    case "sovr_threat": {
      const op = args.operation;
      const params = args.params ?? {};
      return await cloudDispatch("sovr_threat", op, params);
    }
    case "sovr_today": {
      const op = args.operation;
      const params = args.params ?? {};
      return await cloudDispatch("sovr_today", op, params);
    }
    case "sovr_trial": {
      const op = args.operation;
      const params = args.params ?? {};
      return await cloudDispatch("sovr_trial", op, params);
    }
    case "sovr_trust_score": {
      const op = args.operation;
      const params = args.params ?? {};
      return await cloudDispatch("sovr_trust_score", op, params);
    }
    case "sovr_twitter": {
      const op = args.operation;
      const params = args.params ?? {};
      return await cloudDispatch("sovr_twitter", op, params);
    }
    case "sovr_update_p": {
      const op = args.operation;
      const params = args.params ?? {};
      return await cloudDispatch("sovr_update_p", op, params);
    }
    case "sovr_update_rollback": {
      const op = args.operation;
      const params = args.params ?? {};
      return await cloudDispatch("sovr_update_rollback", op, params);
    }
    case "sovr_update_verification": {
      const op = args.operation;
      const params = args.params ?? {};
      return await cloudDispatch("sovr_update_verification", op, params);
    }
    case "sovr_validate_access": {
      const op = args.operation;
      const params = args.params ?? {};
      return await cloudDispatch("sovr_validate_access", op, params);
    }
    case "sovr_verification": {
      const op = args.operation;
      const params = args.params ?? {};
      return await cloudDispatch("sovr_verification", op, params);
    }
    case "sovr_webhook": {
      const op = args.operation;
      const params = args.params ?? {};
      return await cloudDispatch("sovr_webhook", op, params);
    }
    // ── Auto-synced handlers from MCP Proxy ──
    case "sovr_audit_replay": {
      const op = args.operation;
      const params = args.params ?? {};
      return await cloudDispatch("sovr_audit_replay", op, params);
    }
    case "sovr_health_check": {
      const op = args.operation;
      const params = args.params ?? {};
      return await cloudDispatch("sovr_health_check", op, params);
    }
    case "sovr_monitoring": {
      const op = args.operation;
      const params = args.params ?? {};
      return await cloudDispatch("sovr_monitoring", op, params);
    }
    case "sovr_open_guard": {
      const op = args.operation;
      const params = args.params ?? {};
      return await cloudDispatch("sovr_open_guard", op, params);
    }
    case "sovr_p0": {
      const op = args.operation;
      const params = args.params ?? {};
      return await cloudDispatch("sovr_p0", op, params);
    }
    case "sovr_p3_fusion": {
      const op = args.operation;
      const params = args.params ?? {};
      return await cloudDispatch("sovr_p3_fusion", op, params);
    }
    case "sovr_p5": {
      const op = args.operation;
      const params = args.params ?? {};
      return await cloudDispatch("sovr_p5", op, params);
    }
    case "sovr_p6": {
      const op = args.operation;
      const params = args.params ?? {};
      return await cloudDispatch("sovr_p6", op, params);
    }
    case "sovr_status_v2": {
      const op = args.operation;
      const params = args.params ?? {};
      return await cloudDispatch("sovr_status_v2", op, params);
    }
    case "sovr_trust_bundle": {
      const op = args.operation;
      const params = args.params ?? {};
      return await cloudDispatch("sovr_trust_bundle", op, params);
    }
    default:
      throw new Error(`Unknown tool: ${name}`);
  }
}
function log(msg) {
  process.stderr.write(`[sovr] ${msg}
`);
}
function sendResponse(resp) {
  const json = JSON.stringify(resp);
  process.stdout.write(`Content-Length: ${Buffer.byteLength(json)}\r
\r
${json}`);
}
async function handleRequest(req) {
  const { id, method, params } = req;
  try {
    switch (method) {
      case "initialize":
        sendResponse({ jsonrpc: "2.0", id, result: { protocolVersion: "2024-11-05", capabilities: { tools: {}, prompts: {}, resources: {} }, serverInfo: { name: "sovr-mcp-server", version: VERSION } } });
        break;
      case "notifications/initialized":
        log("Client connected");
        break;
      case "tools/list":
        {
          const allNativeTools = filterToolsByTier(TOOLS, currentTier);
          const allTools = proxyEnabled ? [...allNativeTools, ...getProxyTools()] : allNativeTools;
          sendResponse({ jsonrpc: "2.0", id, result: { tools: allTools } });
        }
        break;
      case "prompts/list":
        sendResponse({ jsonrpc: "2.0", id, result: { prompts: [
          { name: "sovr_security_review", description: "Review an AI agent action for security risks before execution.", arguments: [{ name: "action", description: "The action to review", required: true }, { name: "context", description: "Additional context", required: false }] },
          { name: "sovr_policy_guide", description: "Get guidance on SOVR security policies.", arguments: [{ name: "topic", description: "Policy topic (sql, shell, http, payments)", required: false }] }
        ] } });
        break;
      case "prompts/get": {
        const pn = params.name;
        const pa = params.arguments;
        if (pn === "sovr_security_review") {
          sendResponse({ jsonrpc: "2.0", id, result: { description: "Security review for AI agent action", messages: [{ role: "user", content: { type: "text", text: `Review this action for security risks:

Action: ${pa?.action ?? "unknown"}
Context: ${pa?.context ?? "none"}

Use sovr_gate_check to evaluate, then explain the verdict.` } }] } });
        } else if (pn === "sovr_policy_guide") {
          sendResponse({ jsonrpc: "2.0", id, result: { description: "SOVR policy guidance", messages: [{ role: "user", content: { type: "text", text: `Explain SOVR policies for: ${pa?.topic ?? "all"}

Use sovr_list_rules to show relevant rules, then explain what is blocked/escalated/allowed.` } }] } });
        } else {
          sendResponse({ jsonrpc: "2.0", id, error: { code: -32602, message: `Unknown prompt: ${pn}` } });
        }
        break;
      }
      case "resources/list":
        sendResponse({ jsonrpc: "2.0", id, result: { resources: [
          { uri: "sovr://rules", name: "SOVR Policy Rules", description: "Current active policy rules", mimeType: "application/json" },
          { uri: "sovr://audit-log", name: "SOVR Audit Log", description: "Recent audit log entries", mimeType: "application/json" },
          { uri: "sovr://status", name: "SOVR Status", description: "Engine status", mimeType: "application/json" }
        ] } });
        break;
      case "resources/read": {
        const uri = params.uri;
        let rd;
        if (uri === "sovr://rules") {
          rd = rules.map((r) => ({ id: r.id, description: r.description, channels: r.channels, effect: r.effect, enabled: r.enabled }));
        } else if (uri === "sovr://audit-log") {
          rd = auditLog.slice(0, 50);
        } else if (uri === "sovr://status") {
          const visibleTools = filterToolsByTier(TOOLS, currentTier).length;
          rd = { mode: hasCloud() ? "cloud" : "local", version: VERSION, tier: currentTier, rules_count: rules.length, audit_count: auditLog.length, tools_available: visibleTools, cloud_connected: hasCloud(), proxy: { enabled: proxyEnabled, downstream_servers: downstreamServers.size, intercepted_tools: proxyToolMap.size } };
        } else {
          sendResponse({ jsonrpc: "2.0", id, error: { code: -32602, message: `Unknown resource: ${uri}` } });
          break;
        }
        sendResponse({ jsonrpc: "2.0", id, result: { contents: [{ uri, mimeType: "application/json", text: JSON.stringify(rd, null, 2) }] } });
        break;
      }
      case "tools/call": {
        const tn = params.name;
        const ta = params.arguments ?? {};
        try {
          if (!proxyToolMap.has(tn) && !tierHasAccess(currentTier, tn)) {
            const requiredTier = getToolTier(tn);
            sendResponse({ jsonrpc: "2.0", id, result: { content: [{ type: "text", text: `\u26D4 Access denied. Tool "${tn}" requires ${requiredTier.toUpperCase()} tier or above. Current tier: ${currentTier.toUpperCase()}. Upgrade at https://sovr.inc/pricing` }], isError: true } });
            break;
          }
          if (proxyEnabled && proxyToolMap.has(tn)) {
            const proxyResult = await proxyToolCall(tn, ta);
            sendResponse({ jsonrpc: "2.0", id, result: proxyResult });
          } else {
            const result = await handleToolCall(tn, ta);
            sendResponse({ jsonrpc: "2.0", id, result });
          }
        } catch (err) {
          sendResponse({ jsonrpc: "2.0", id, result: { content: [{ type: "text", text: `Error: ${err instanceof Error ? err.message : String(err)}` }], isError: true } });
        }
        break;
      }
      case "ping":
        sendResponse({ jsonrpc: "2.0", id, result: {} });
        break;
      default:
        sendResponse({ jsonrpc: "2.0", id, error: { code: -32601, message: `Method not found: ${method}` } });
    }
  } catch (err) {
    sendResponse({ jsonrpc: "2.0", id, error: { code: -32603, message: `Internal error: ${err instanceof Error ? err.message : String(err)}` } });
  }
}
function startStdioTransport() {
  let buffer = "";
  process.stdin.setEncoding("utf8");
  process.stdin.on("data", (chunk) => {
    buffer += chunk;
    while (true) {
      const headerEnd = buffer.indexOf("\r\n\r\n");
      if (headerEnd === -1) break;
      const header = buffer.substring(0, headerEnd);
      const clMatch = header.match(/Content-Length:\s*(\d+)/i);
      if (!clMatch) {
        buffer = buffer.substring(headerEnd + 4);
        continue;
      }
      const cl = parseInt(clMatch[1], 10);
      const bodyStart = headerEnd + 4;
      if (buffer.length < bodyStart + cl) break;
      const body = buffer.substring(bodyStart, bodyStart + cl);
      buffer = buffer.substring(bodyStart + cl);
      try {
        handleRequest(JSON.parse(body));
      } catch (err) {
        log(`Parse error: ${err}`);
      }
    }
  });
  process.stdin.on("end", async () => {
    log("Connection closed");
    if (pendingCloudReqs.length > 0) {
      log(`Flushing ${pendingCloudReqs.length} pending cloud sync(s)...`);
      await Promise.allSettled(pendingCloudReqs).catch(() => {
      });
    }
    process.exit(0);
  });
}
async function main() {
  if (process.argv.includes("--help") || process.argv.includes("-h")) {
    console.log(`
sovr-mcp-proxy v${VERSION} \u2014 Execution Firewall for AI Agents
The complete MCP interface + programmable proxy for the SOVR Responsibility Layer.
286 tools + McpProxy class for custom integrations.

USAGE:
  npx sovr-mcp-proxy

ENVIRONMENT:
  SOVR_API_KEY        Connect to SOVR Cloud for full SDK access
  SOVR_ENDPOINT       Custom Cloud endpoint (default: ${DEFAULT_CLOUD_URL})
  SOVR_RULES_FILE     Path to custom rules JSON file

LOCAL MODE (free, 15 built-in rules):
  {
    "mcpServers": {
      "sovr": { "command": "npx", "args": ["sovr-mcp-proxy"] }
    }
  }

CLOUD MODE (286 tools, full SDK):
  {
    "mcpServers": {
      "sovr": {
        "command": "npx",
        "args": ["sovr-mcp-proxy"],
        "env": { "SOVR_API_KEY": "sovr_sk_..." }
      }
    }
  }

PROXY MODE (transparent interception):
  {
    "mcpServers": {
      "sovr": {
        "command": "npx",
        "args": ["sovr-mcp-proxy"],
        "env": {
          "SOVR_API_KEY": "sovr_sk_...",
          "SOVR_PROXY_CONFIG": "/path/to/proxy.json"
        }
      }
    }
  }

  proxy.json format:
  {
    "downstream": {
      "stripe": { "command": "npx", "args": ["@stripe/agent-toolkit"] },
      "github": { "command": "npx", "args": ["@modelcontextprotocol/server-github"], "env": { "GITHUB_TOKEN": "..." } },
      "remote-sse": { "transport": "sse", "url": "https://mcp.example.com/sse", "headers": { "Authorization": "Bearer ..." } },
      "remote-http": { "transport": "streamable-http", "url": "https://mcp.example.com/mcp", "headers": { "Authorization": "Bearer ..." } }
    }
  }

SINGLE UPSTREAM PROXY MODE (programmable):
  sovr-mcp-proxy --upstream "npx -y @modelcontextprotocol/server-filesystem /tmp"
  sovr-mcp-proxy --upstream "node my-server.js" --rules ./policy.json --verbose

PROGRAMMATIC API:
  import { McpProxy } from 'sovr-mcp-proxy';
  const proxy = new McpProxy({
    upstream: { command: 'npx', args: ['-y', '@modelcontextprotocol/server-filesystem', '/tmp'] },
    onBlocked: (info) => console.log('Blocked:', info.toolName),
  });
  await proxy.start();

Learn more: https://sovr.inc
`);
    process.exit(0);
  }
  cloudApiKey = process.env.SOVR_API_KEY ?? null;
  cloudEndpoint = process.env.SOVR_ENDPOINT ?? (cloudApiKey ? DEFAULT_CLOUD_URL : null);
  if (process.env.SOVR_RULES_FILE) {
    try {
      const fs = __require("fs");
      const raw = JSON.parse(fs.readFileSync(process.env.SOVR_RULES_FILE, "utf8"));
      const customRules = Array.isArray(raw) ? raw : Array.isArray(raw?.rules) ? raw.rules : [];
      for (const r of customRules) {
        rules.push({
          id: r.id,
          description: r.description,
          channels: r.channels,
          action_pattern: r.action_pattern,
          resource_pattern: r.resource_pattern,
          conditions: r.conditions || [],
          effect: r.effect,
          risk_level: r.risk_level || "medium",
          require_approval: r.effect !== "allow",
          priority: r.priority ?? 50,
          enabled: true
        });
      }
      log(`Loaded ${customRules.length} custom rules from ${process.env.SOVR_RULES_FILE}`);
    } catch (err) {
      log(`Warning: Failed to load custom rules: ${err}`);
    }
  }
  if (hasCloud()) {
    currentTier = await verifyKeyTier();
  }
  const visibleCount = filterToolsByTier(TOOLS, currentTier).length;
  log(`Execution Firewall active \u2014 ${rules.length} rules loaded, tier: ${currentTier.toUpperCase()}, ${visibleCount}/${TOOLS.length} tools available`);
  if (cloudEndpoint) {
    log(`SOVR Cloud: ${cloudEndpoint} (${currentTier} tier)`);
  } else {
    log("Local mode \u2014 set SOVR_API_KEY for paid tier access. Free tier: 8 tools.");
  }
  if (process.env.SOVR_PROXY_CONFIG) {
    log("[proxy] SOVR_PROXY_CONFIG detected \u2014 starting transparent interception layer...");
    initProxy().then(() => {
      startStdioTransport();
    }).catch((err) => {
      log(`[proxy] Proxy init failed, starting without proxy: ${err}`);
      startStdioTransport();
    });
  } else {
    startStdioTransport();
  }
}
var isMain = typeof process !== "undefined" && process.argv[1] && (process.argv[1].includes("sovr-mcp-server") || process.argv[1].includes("sovr-mcp-proxy") || process.argv[1].endsWith("index.js") || process.argv[1].endsWith("index.mjs") || process.argv[1].endsWith("index.cjs"));
if (isMain) {
  if (process.argv.includes("--upstream") || process.argv.includes("-u")) {
    proxyCli(process.argv.slice(2));
  } else {
    main();
  }
}
var McpProxy = class extends EventEmitter {
  upstreamConfig;
  upstream = null;
  _serverName;
  _verbose;
  _onBlocked;
  _onEscalated;
  _onIntercept;
  _stats;
  _customRules;
  constructor(config) {
    super();
    this.upstreamConfig = config.upstream;
    this._serverName = config.serverName ?? "sovr-mcp-proxy";
    this._verbose = config.verbose ?? false;
    this._onBlocked = config.onBlocked;
    this._onEscalated = config.onEscalated;
    this._onIntercept = config.onIntercept;
    this._customRules = config.customRules ?? [];
    this._stats = {
      totalCalls: 0,
      allowedCalls: 0,
      blockedCalls: 0,
      escalatedCalls: 0,
      upstreamErrors: 0,
      startedAt: Date.now()
    };
    if (this._customRules.length > 0) {
      for (const r of this._customRules) {
        rules.push({ ...r, conditions: [...r.conditions || []], enabled: true });
      }
    }
  }
  /**
   * Start the proxy in stdio mode.
   * Reads JSON-RPC messages from stdin, intercepts tool calls,
   * and forwards approved calls to the upstream MCP server.
   */
  async start() {
    this.upstream = nodeSpawn(
      this.upstreamConfig.command,
      this.upstreamConfig.args ?? [],
      {
        stdio: ["pipe", "pipe", "pipe"],
        env: { ...process.env, ...this.upstreamConfig.env },
        cwd: this.upstreamConfig.cwd
      }
    );
    if (!this.upstream.stdout || !this.upstream.stdin) {
      throw new Error("Failed to spawn upstream MCP server");
    }
    const upstreamReader = createInterface({ input: this.upstream.stdout });
    upstreamReader.on("line", (line) => {
      this.handleUpstreamMessage(line);
    });
    this.upstream.stderr?.on("data", (data) => {
      if (this._verbose) {
        process.stderr.write(`[sovr-mcp-proxy] upstream stderr: ${data}`);
      }
    });
    this.upstream.on("exit", (code) => {
      if (this._verbose) {
        process.stderr.write(`[sovr-mcp-proxy] upstream exited with code ${code}
`);
      }
      this.emit("upstream-exit", code);
    });
    const agentReader = createInterface({ input: process.stdin });
    agentReader.on("line", (line) => {
      this.handleAgentMessage(line);
    });
    process.stdin.on("end", () => {
      this.stop();
    });
    if (this._verbose) {
      process.stderr.write(`[sovr-mcp-proxy] started, proxying to ${this.upstreamConfig.command}
`);
    }
  }
  /** Stop the proxy and kill the upstream process. */
  stop() {
    if (this.upstream) {
      this.upstream.kill();
      this.upstream = null;
    }
  }
  /** Get proxy statistics. */
  getStats() {
    return { ...this._stats };
  }
  // ---------- Internal ----------
  handleAgentMessage(line) {
    let msg;
    try {
      msg = JSON.parse(line);
    } catch {
      this.forwardToUpstream(line);
      return;
    }
    if (msg.method === "tools/call") {
      this.interceptToolCall(msg);
    } else {
      this.forwardToUpstream(line);
    }
  }
  handleUpstreamMessage(line) {
    process.stdout.write(line + "\n");
  }
  interceptToolCall(request) {
    this._stats.totalCalls++;
    const params = request.params ?? {};
    const toolName = params.name ?? "unknown";
    const toolArgs = params.arguments ?? {};
    const dangerSignals = this.extractDangerSignals(toolName, toolArgs);
    const decision = evaluate("mcp", toolName, toolName, {
      tool_name: toolName,
      server_name: this._serverName,
      arguments: toolArgs,
      ...dangerSignals
    });
    const interceptInfo = {
      method: request.method,
      toolName,
      arguments: toolArgs,
      decision,
      forwarded: decision.verdict === "allow",
      timestamp: Date.now()
    };
    if (this._onIntercept) {
      Promise.resolve(this._onIntercept(interceptInfo)).catch(() => {
      });
    }
    this.emit("intercept", interceptInfo);
    if (decision.verdict === "deny") {
      this._stats.blockedCalls++;
      this.sendBlockedResponse(request, decision);
      if (this._onBlocked) {
        Promise.resolve(this._onBlocked({
          method: request.method,
          toolName,
          arguments: toolArgs,
          decision,
          timestamp: Date.now()
        })).catch(() => {
        });
      }
      if (this._verbose) {
        process.stderr.write(`[sovr-mcp-proxy] BLOCKED: ${toolName} \u2014 ${decision.reason}
`);
      }
    } else if (decision.verdict === "escalate") {
      this._stats.escalatedCalls++;
      this.sendEscalatedResponse(request, decision);
      if (this._onEscalated) {
        Promise.resolve(this._onEscalated({
          method: request.method,
          toolName,
          arguments: toolArgs,
          decision,
          timestamp: Date.now()
        })).catch(() => {
        });
      }
      if (this._verbose) {
        process.stderr.write(`[sovr-mcp-proxy] ESCALATED: ${toolName} \u2014 ${decision.reason}
`);
      }
    } else {
      this._stats.allowedCalls++;
      this.forwardToUpstream(JSON.stringify(request));
      if (this._verbose) {
        process.stderr.write(`[sovr-mcp-proxy] ALLOWED: ${toolName} (risk: ${decision.risk_score})
`);
      }
    }
  }
  /**
   * Extract danger signals from tool arguments for rule matching.
   * Normalizes common patterns across different MCP servers.
   */
  extractDangerSignals(toolName, args) {
    const signals = {};
    if (toolName.includes("file") || toolName.includes("write") || toolName.includes("read")) {
      signals.is_file_operation = true;
      if (args.path) signals.file_path = args.path;
    }
    if (toolName.includes("shell") || toolName.includes("exec") || toolName.includes("run")) {
      signals.is_shell_operation = true;
      if (args.command) signals.shell_command = args.command;
    }
    if (toolName.includes("db") || toolName.includes("sql") || toolName.includes("query")) {
      signals.is_db_operation = true;
      if (args.query || args.sql) signals.sql_query = args.query || args.sql;
    }
    if (toolName.includes("fetch") || toolName.includes("http") || toolName.includes("request")) {
      signals.is_network_operation = true;
      if (args.url) signals.target_url = args.url;
    }
    return signals;
  }
  sendBlockedResponse(request, decision) {
    const response = {
      jsonrpc: "2.0",
      id: request.id,
      error: {
        code: -32001,
        message: `[SOVR] Action blocked by policy: ${decision.reason}`,
        data: {
          sovr_decision_id: decision.decision_id,
          sovr_verdict: decision.verdict,
          sovr_risk_score: decision.risk_score,
          sovr_matched_rules: decision.matched_rules
        }
      }
    };
    process.stdout.write(JSON.stringify(response) + "\n");
  }
  sendEscalatedResponse(request, decision) {
    const response = {
      jsonrpc: "2.0",
      id: request.id,
      error: {
        code: -32002,
        message: `[SOVR] Action requires human approval: ${decision.reason}`,
        data: {
          sovr_decision_id: decision.decision_id,
          sovr_verdict: decision.verdict,
          sovr_risk_score: decision.risk_score,
          sovr_matched_rules: decision.matched_rules,
          sovr_requires_approval: true
        }
      }
    };
    process.stdout.write(JSON.stringify(response) + "\n");
  }
  forwardToUpstream(data) {
    if (!this.upstream?.stdin) {
      process.stderr.write("[sovr-mcp-proxy] ERROR: upstream not connected\n");
      this._stats.upstreamErrors++;
      return;
    }
    this.upstream.stdin.write(data + "\n");
  }
};
async function proxyCli(args) {
  let upstreamCmd = "";
  let upstreamArgs = [];
  let rulesFile = null;
  let verbose = false;
  for (let i = 0; i < args.length; i++) {
    switch (args[i]) {
      case "--upstream":
      case "-u": {
        const parts = (args[++i] ?? "").split(" ");
        upstreamCmd = parts[0];
        upstreamArgs = parts.slice(1);
        break;
      }
      case "--rules":
      case "-r":
        rulesFile = args[++i];
        break;
      case "--verbose":
      case "-v":
        verbose = true;
        break;
    }
  }
  if (!upstreamCmd) {
    return main();
  }
  let customRules = [];
  if (rulesFile) {
    const fs = await import("fs");
    const content = fs.readFileSync(rulesFile, "utf-8");
    const parsed = JSON.parse(content);
    customRules = parsed.rules ?? parsed;
  }
  const proxy = new McpProxy({
    upstream: { command: upstreamCmd, args: upstreamArgs },
    customRules,
    verbose,
    onBlocked: (info) => {
      process.stderr.write(
        `[BLOCKED] ${info.toolName}: ${info.decision.reason}
`
      );
    },
    onEscalated: (info) => {
      process.stderr.write(
        `[ESCALATED] ${info.toolName}: ${info.decision.reason}
`
      );
    }
  });
  await proxy.start();
}
var index_default = McpProxy;
export {
  McpProxy,
  TOOLS,
  VERSION,
  auditLog,
  index_default as default,
  downstreamServers,
  evaluate,
  filterToolsByTier,
  getProxyTools,
  handleToolCall,
  initProxy,
  main,
  parseCommand,
  parseSQL,
  proxyCli,
  proxyEnabled,
  proxyToolCall,
  proxyToolMap,
  rules,
  shutdownProxy,
  tierHasAccess
};
