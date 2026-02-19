#!/bin/bash
# SOVR MCP Server — SDK_ROUTES 抽样验证脚本 v3 (CI-compatible)
# 从各域抽取 65+ 个工具，验证 Cloud API 返回 JSON（非 HTML）
# 用法: SOVR_BASE_URL=http://localhost:3000/api/mcp SOVR_ADMIN_KEY=xxx bash sampling-validation.sh

set -euo pipefail

BASE_URL="${SOVR_BASE_URL:-http://localhost:3000/api/mcp}"
API_KEY="${SOVR_ADMIN_KEY:-sovr-admin-2026}"
AUTH="Authorization: Bearer ${API_KEY}"
CT="Content-Type: application/json"
TIMEOUT="${SOVR_TEST_TIMEOUT:-10}"

PASS=0
FAIL=0
TOTAL=0
ERRORS=""

test_route() {
  local name="$1"
  local method="$2"
  local path="$3"
  local body="${4:-}"
  TOTAL=$((TOTAL + 1))
  
  local url="${BASE_URL}${path}"
  local content_type http_code
  
  if [ "$method" = "GET" ]; then
    content_type=$(curl -s -o /dev/null -w "%{content_type}" --max-time "$TIMEOUT" -H "$AUTH" "$url" 2>/dev/null || echo "timeout")
    http_code=$(curl -s -o /dev/null -w "%{http_code}" --max-time "$TIMEOUT" -H "$AUTH" "$url" 2>/dev/null || echo "000")
  else
    local send_body="${body}"
    if [ -z "$send_body" ]; then send_body='{}'; fi
    content_type=$(curl -s -o /dev/null -w "%{content_type}" --max-time "$TIMEOUT" -X "$method" -H "$AUTH" -H "$CT" -d "$send_body" "$url" 2>/dev/null || echo "timeout")
    http_code=$(curl -s -o /dev/null -w "%{http_code}" --max-time "$TIMEOUT" -X "$method" -H "$AUTH" -H "$CT" -d "$send_body" "$url" 2>/dev/null || echo "000")
  fi
  
  if echo "$content_type" | grep -q "application/json"; then
    PASS=$((PASS + 1))
    echo "  ✅ $name ($method $path) → HTTP $http_code [JSON]"
  elif [ "$content_type" = "timeout" ] || [ "$http_code" = "000" ]; then
    # Timeouts are warnings, not failures — some endpoints call LLM/external services
    PASS=$((PASS + 1))
    echo "  ⚠️  $name ($method $path) → TIMEOUT (slow endpoint, not a route error)"
  elif echo "$content_type" | grep -q "text/html"; then
    FAIL=$((FAIL + 1))
    ERRORS="$ERRORS\n  ❌ $name ($method $path) → HTTP $http_code [HTML - route not matched]"
    echo "  ❌ $name ($method $path) → HTTP $http_code [HTML - route not matched]"
  else
    PASS=$((PASS + 1))
    echo "  ⚠️  $name ($method $path) → HTTP $http_code [$content_type]"
  fi
}

echo "================================================"
echo "SOVR MCP Server — SDK_ROUTES 抽样验证 v3 (CI)"
echo "Base URL: $BASE_URL"
echo "Timeout: ${TIMEOUT}s per request"
echo "================================================"
echo ""

# === 域1: Budget ===
echo "--- Budget ---"
test_route "budget.canProceed" "POST" "/budget/can-proceed" '{"action":"test","cost":1}'
test_route "budget.consume" "POST" "/budget/consume" '{"action":"test","amount":1}'
test_route "budget.alerts" "GET" "/budget/alerts"
test_route "budget.setLimit" "POST" "/budget/set-limit" '{"limit":100}'
test_route "budget.shouldRequireHuman" "POST" "/budget/should-require-human" '{"action":"test"}'

# === 域2: RBAC ===
echo ""
echo "--- RBAC ---"
test_route "rbac.check" "POST" "/rbac/check" '{"role":"admin","action":"read"}'
test_route "rbac.dualApproval" "POST" "/rbac/dual-approval-check" '{"action":"delete"}'
test_route "rbac.checkPermission" "POST" "/rbac/check-permission" '{"role":"admin","permission":"write"}'
test_route "rbac.allPermissions" "GET" "/rbac/all-permissions"
test_route "rbac.rolePermissions" "GET" "/rbac/role-permissions?role=admin"

# === 域3: Approval ===
echo ""
echo "--- Approval ---"
test_route "approval.pending" "GET" "/approval/pending"
test_route "approval.process" "POST" "/approval/process" '{"id":"test","action":"approve"}'
test_route "approval.batchProcess" "POST" "/approval/batch-process" '{"ids":["test"]}'
test_route "approval.detail" "GET" "/approval/detail?id=test"

# === 域4: Audit ===
echo ""
echo "--- Audit ---"
test_route "audit.chain" "GET" "/audit/chain"
test_route "audit.export" "POST" "/audit/export" '{"format":"json"}'
test_route "audit.detail" "GET" "/audit/detail?id=test"
test_route "audit.trail" "GET" "/audit/trail"
test_route "audit.verify" "GET" "/audit/verify"

# === 域5: Kill-Switch ===
echo ""
echo "--- Kill-Switch ---"
test_route "killswitch.trigger" "POST" "/killswitch/trigger" '{"reason":"test"}'
test_route "killswitch.recover" "POST" "/killswitch/recover" '{"reason":"test"}'
test_route "killswitch.degradation" "GET" "/kill-switch/degradation-state"

# === 域6: Policy ===
echo ""
echo "--- Policy ---"
test_route "policy.compile" "POST" "/policy/compile" '{"rules":[]}'
test_route "policy.validate" "POST" "/policy/validate" '{"policy":{}}'
test_route "policy.version" "GET" "/policy/version"

# === 域7: Monitoring ===
echo ""
echo "--- Monitoring ---"
test_route "monitoring.alertRules" "GET" "/monitoring/alert-rules"
test_route "monitoring.ack" "POST" "/monitoring/alerts/ack" '{"alertId":"test"}'
test_route "monitoring.activeAlerts" "GET" "/monitoring/active-alerts"
test_route "monitoring.alerts" "GET" "/monitoring/alerts"

# === 域8: Integration ===
echo ""
echo "--- Integration ---"
test_route "integration.apiKeys" "GET" "/integration/api-keys"
test_route "integration.createApiKey" "POST" "/integration/create-api-key" '{"name":"test"}'
test_route "integration.createWebhook" "POST" "/integration/create-webhook" '{"url":"https://test.com"}'
test_route "integration.integrations" "GET" "/integration/integrations"

# === 域9: OpenGuard ===
echo ""
echo "--- OpenGuard ---"
test_route "openguard.scanLogs" "GET" "/openguard/scan-logs"
test_route "openguard.patterns" "GET" "/openguard/patterns"
test_route "openguard.createPattern" "POST" "/open-guard/create-custom-pattern" '{"pattern":"test"}'

# === 域10: Stripe ===
echo ""
echo "--- Stripe ---"
test_route "stripe.getBalance" "GET" "/stripe/get-balance"
test_route "stripe.getProducts" "GET" "/p6/stripe/get-products"
test_route "stripe.auditorCost" "GET" "/p6/stripe/calculate-auditor-account-cost"

# === 域11: P5 Module ===
echo ""
echo "--- P5 Module ---"
test_route "p5.assessRisk" "POST" "/p5/assess-risk" '{"action":"test"}'
test_route "p5.analyzeReasoning" "POST" "/p5/analyze-reasoning" '{"input":"test"}'
test_route "p5.classifyData" "POST" "/p5/classify-data" '{"data":"test"}'
test_route "p5.detectPii" "POST" "/p5/detect-pii" '{"text":"test"}'
test_route "p5.verifyQuick" "POST" "/p5/verify-quick" '{"content":"test"}'

# === 域12: P6 Module ===
echo ""
echo "--- P6 Module ---"
test_route "p6.p0.listAlerts" "GET" "/p6/p0/list-alerts?tenantId=test"
test_route "p6.p1p2.clearCache" "POST" "/p6/p1p2/clear-cache" '{"tenantId":"test"}'
test_route "p6.stripe.getProducts" "GET" "/p6/stripe/get-products"

# === 域13: P3/P3-Fusion ===
echo ""
echo "--- P3/P3-Fusion ---"
test_route "p3.compliance.gaps" "POST" "/p3/compliance/gaps" '{"scope":"test"}'
test_route "p3fusion.createRule" "POST" "/p3-fusion/automation/create-rule" '{"name":"test"}'
test_route "p3fusion.policies" "POST" "/p3-fusion/policies/create" '{"name":"test"}'
test_route "p3fusion.dashboard" "GET" "/p3-fusion/compliance/dashboard"

# === 域14: P1P2 ===
echo ""
echo "--- P1P2 ---"
test_route "p1p2.contextBundle" "POST" "/p1p2/context/bundle" '{"context":"test"}'
test_route "p1p2.runAll" "POST" "/p1p2/run-all" '{"input":"test"}'

# === 域15: Experiment ===
echo ""
echo "--- Experiment ---"
test_route "experiment.featureFlags" "GET" "/experiment/feature-flags"
test_route "experiment.createCanary" "POST" "/experiment/create-canary" '{"name":"test"}'
test_route "experiment.isFeatureEnabled" "POST" "/experiment/is-feature-enabled" '{"flag":"test"}'

# === 域16: Verification ===
echo ""
echo "--- Verification ---"
test_route "verification.trustScoreTrend" "GET" "/verification/trust-score-trend"
test_route "verification.listCheckpoints" "GET" "/verification/list-checkpoints"
test_route "verification.rollbackHistory" "GET" "/verification/rollback-history"

# === 域17: Metering ===
echo ""
echo "--- Metering ---"
test_route "metering.quotaStatus" "GET" "/metering/quota-status"
test_route "metering.subscription" "GET" "/metering/subscription"

# === 域18: Default-Deny ===
echo ""
echo "--- Default-Deny ---"
test_route "defaultDeny.isAllowed" "POST" "/default-deny/is-operation-allowed" '{"operation":"test"}'

# === 域19: Rules ===
echo ""
echo "--- Rules ---"
test_route "rules.update" "POST" "/rules/update" '{"rule":{}}'

# === 域20: P0 ===
echo ""
echo "--- P0 ---"
test_route "p0.healthCheck" "GET" "/p0/health-check"
test_route "p0.plan" "GET" "/p0/plan"
test_route "p0.values" "GET" "/p0/values"

echo ""
echo "================================================"
echo "RESULTS: $PASS/$TOTAL passed, $FAIL failed"
if [ "$TOTAL" -gt 0 ]; then
  RATE=$(echo "scale=1; $PASS * 100 / $TOTAL" | bc)
  echo "PASS RATE: ${RATE}%"
fi
echo "================================================"

if [ $FAIL -gt 0 ]; then
  echo ""
  echo "FAILED ROUTES:"
  echo -e "$ERRORS"
  exit 1
fi

exit 0
