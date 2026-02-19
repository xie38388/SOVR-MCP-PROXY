/**
 * SOVR Tool Tier Classification
 * 
 * Tier hierarchy (cumulative — each tier includes all tools from lower tiers):
 *   free       →  8 tools  (core interception engine)
 *   personal   → 23 tools  (+15 basic operations)
 *   starter    → 48 tools  (+25 compliance & audit)
 *   pro        → 98 tools  (+50 advanced security & enterprise ops)
 *   enterprise → 274 tools (full SDK — all core_*, create_*, get_*, etc.)
 */

export type Tier = "free" | "personal" | "starter" | "pro" | "enterprise";

// ── Free (8 tools) ──────────────────────────────────────────────────────────
// Core interception engine — the open-source hook
const FREE_TOOLS = new Set([
  "sovr_gate_check",        // Core gate check
  "sovr_check_command",     // Exec channel parser
  "sovr_check_sql",         // SQL channel parser
  "sovr_check_http",        // HTTP channel parser
  "sovr_request_approval",  // Request human approval
  "sovr_submit_receipt",    // Submit execution receipt
  "sovr_add_rule",          // Add custom rule
  "sovr_audit_log",         // Local audit log
]);

// ── Personal (+15 = 23 tools) ───────────────────────────────────────────────
// Basic operations — you can manage, not just intercept
const PERSONAL_ADDITIONS = new Set([
  "sovr_health_check",      // System health
  "sovr_status_v2",         // Status overview
  "sovr_monitoring",        // Basic monitoring
  "sovr_kill_switch",       // Emergency stop
  "sovr_degradation",       // Graceful degradation
  "sovr_rollback",          // Rollback actions
  "sovr_budget",            // Budget overview
  "sovr_list_rules",        // List active rules
  "sovr_test_rule",         // Test a rule
  "sovr_delete_rule",       // Delete a rule
  "sovr_log_decision",      // Log a decision
  "sovr_adapter",           // Channel adapter
  "sovr_gate",              // Gate management
  "sovr_risk",              // Risk assessment
  "sovr_monitor",           // Monitor status
]);

// ── Starter (+25 = 48 tools) ────────────────────────────────────────────────
// Compliance & audit — prove your AI is trustworthy
const STARTER_ADDITIONS = new Set([
  "sovr_audit_replay",      // Decision replay
  "sovr_trust_bundle",      // Trust bundle generation
  "sovr_compliance",        // Compliance checks
  "sovr_report",            // Generate reports
  "sovr_execute_report",    // Execute report generation
  "sovr_verification",      // Verification service
  "sovr_generate_certificate", // Generate certificates
  "sovr_generate_diff",     // Generate policy diffs
  "sovr_snapshot",          // State snapshots
  "sovr_receipt",           // Receipt management
  "sovr_policy",            // Policy management
  "sovr_policy_guide",      // Policy guidance
  "sovr_list_policy",       // List policies
  "sovr_deprecate_policy",  // Deprecate policies
  "sovr_detect_policy",     // Detect policy issues
  "sovr_rule",              // Rule management
  "sovr_create_rule",       // Create rules
  "sovr_list_report",       // List reports
  "sovr_delete_report",     // Delete reports
  "sovr_create_report",     // Create reports
  "sovr_sovr_export",       // Export data
  "sovr_sovr_verify",       // Verify integrity
  "sovr_sovr_check",        // System check
  "sovr_update_verification", // Update verification
  "sovr_validate_access",   // Validate access
]);

// ── Pro (+50 = 98 tools) ────────────────────────────────────────────────────
// Advanced security + enterprise operations
const PRO_ADDITIONS = new Set([
  // Cognitive security
  "sovr_cognitive",          // Cognitive security engine
  "sovr_threat",             // Threat detection
  "sovr_scan",               // Security scanning
  "sovr_detect_hallucination", // Hallucination detection
  "sovr_detect_conflict",   // Conflict detection
  "sovr_open_guard",         // Open guard
  "sovr_default_deny",       // Default deny mode
  "sovr_protect",            // Protection layer
  "sovr_quick_hallucination", // Quick hallucination check
  "sovr_security_review",   // Security review
  // Enterprise ops
  "sovr_tenant",             // Multi-tenant management
  "sovr_create_tenant",      // Create tenant
  "sovr_rbac",               // Role-based access control
  "sovr_feature_flag",       // Feature flags
  "sovr_canary",             // Canary deployments
  "sovr_create_canary",      // Create canary
  "sovr_deployment",         // Deployment management
  "sovr_cancel_deployment",  // Cancel deployment
  "sovr_experiment",         // A/B experiments
  "sovr_sla",                // SLA management
  "sovr_scheduler",          // Task scheduler
  "sovr_task_queue",         // Task queue
  "sovr_model_ops",          // Model operations
  "sovr_webhook",            // Webhook management
  "sovr_integration",        // Integration management
  "sovr_external_api",       // External API management
  "sovr_external_gate",      // External gate
  // Pipeline tools
  "sovr_p0",                 // P0 pipeline
  "sovr_p0_alerts",          // P0 alerts
  "sovr_p3_fusion",          // P3 fusion
  "sovr_p3_ops",             // P3 operations
  "sovr_p5",                 // P5 pipeline
  "sovr_p6",                 // P6 pipeline
  // Advanced operations
  "sovr_approval",           // Approval workflows
  "sovr_arbitrate",          // Arbitration
  "sovr_batch_ops",          // Batch operations
  "sovr_metering",           // Usage metering
  "sovr_cost",               // Cost management
  "sovr_failure_budget",     // Failure budget
  "sovr_regression",         // Regression testing
  "sovr_qa",                 // Quality assurance
  "sovr_execute_quality",    // Execute quality checks
  "sovr_replay",             // Replay system
  "sovr_create_replay",      // Create replay
  "sovr_list_replay",        // List replays
  "sovr_find_precedents",    // Find precedents
  "sovr_resolve_conflict",   // Resolve conflicts
  "sovr_manual_trigger",     // Manual trigger
  "sovr_record_metric",      // Record metrics
  "sovr_evaluate_metric",    // Evaluate metrics
]);

// ── Enterprise (all 274 tools) ──────────────────────────────────────────────
// Everything above + full core_*, create_*, get_*, list_*, update_*, delete_*
// No explicit set needed — enterprise gets everything

/**
 * Returns the minimum tier required to access a given tool.
 */
export function getToolTier(toolName: string): Tier {
  if (FREE_TOOLS.has(toolName)) return "free";
  if (PERSONAL_ADDITIONS.has(toolName)) return "personal";
  if (STARTER_ADDITIONS.has(toolName)) return "starter";
  if (PRO_ADDITIONS.has(toolName)) return "pro";
  return "enterprise";
}

/**
 * Tier hierarchy for comparison.
 */
const TIER_LEVEL: Record<Tier, number> = {
  free: 0,
  personal: 1,
  starter: 2,
  pro: 3,
  enterprise: 4,
};

/**
 * Check if a tier has access to a tool.
 */
export function tierHasAccess(userTier: Tier, toolName: string): boolean {
  const requiredTier = getToolTier(toolName);
  return TIER_LEVEL[userTier] >= TIER_LEVEL[requiredTier];
}

/**
 * Filter tools array by tier — returns only tools the tier can access.
 */
export function filterToolsByTier<T extends { name: string }>(tools: T[], tier: Tier): T[] {
  return tools.filter(t => tierHasAccess(tier, t.name));
}

/**
 * Get tool counts per tier (cumulative).
 */
export function getTierToolCounts(allTools: { name: string }[]): Record<Tier, number> {
  const tiers: Tier[] = ["free", "personal", "starter", "pro", "enterprise"];
  const counts: Record<string, number> = {};
  for (const tier of tiers) {
    counts[tier] = filterToolsByTier(allTools, tier).length;
  }
  return counts as Record<Tier, number>;
}
