// Reconciles 32 historically failing, gitignored assertions to the modern
// shipped frontend. Every original scenario retains a distinct test ID.
// Deliberate UX/content changes are tested for their current security
// property; none of the old failing results is silently re-labelled PASS.
import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { ApiError, safeErrorMessage, settleNamedRequests } from "../src/api/client.js";
import { currentAssistantAnalysis, matchesAssistantResponse } from "../src/utils/controlledAI.js";
import { isMappingBoundToCurrentContext, canRequestManualAudit, manualMappingCoverage } from "../src/pages/cloudIamMapping.js";

const read = (path) => readFileSync(new URL("../src/" + path, import.meta.url), "utf8");
const app = read("App.jsx");
const client = read("api/client.js");
const ai = read("components/ControlledAIAssistant.jsx");
const semantic = read("components/M4SemanticsPanel.jsx");
const analysis = read("pages/ToolAnalysis.jsx");
const inventory = read("pages/Inventory.jsx");
const audit = read("pages/Audit.jsx");
const build = read("pages/BuildSecurity.jsx");
const dashboard = read("pages/Dashboard.jsx");
const operations = read("pages/Operations.jsx");
const cloud = read("pages/CloudSecurity.jsx");
const cloudUtils = read("pages/cloudIamMapping.js");

const check = (id, originalCase, fn) => test(id + " | " + originalCase, fn);
const requireAll = (source, patterns) => {
  for (const pattern of patterns) assert.match(source, pattern);
};

// 01–03: historic App loading / role tests (old selectors and effect signature).
check("L01", "global refresh ignores stale overlapping responses", () => {
  requireAll(app, [/loadDataGeneration = useRef\(0\)/,
    /generation !== loadDataGeneration\.current/,
    /generation === loadDataGeneration\.current/, /Promise\.allSettled/]);
});
check("L02", "refresh synchronizes current session role before privileged loads", () => {
  requireAll(app, [/refreshedUser = verifySession \? await fetchControlPlaneMe\(\) : user/,
    /setUser\(\(previous\) =>/,
    /sameControlPlaneUser\(previous, refreshedUser\)/,
    /const refreshedIsAdmin = refreshedUser\?\.role === "ADMIN"/,
    /if \(refreshedIsAdmin\) \{\s*requests\.users =/]);
});
check("L03", "role changes clear admin-only users and avoid reloading by object identity", () => {
  requireAll(app, [/if \(user\?\.role !== refreshedUser\?\.role\) \{[\s\S]*?setUsers\(\[\]\)/,
    /\[user\?\.id, user\?\.role, activePage, entryOptions\.record\]/,
    /sameControlPlaneUser/]);
});

// 04–06: error text changed deliberately to avoid leaking upstream data.
check("L04", "validation feedback is specific only for trusted structured fields", () => {
  const leak = safeErrorMessage(new ApiError("A required input is missing: secret-value",
    { status: 400 }));
  assert.doesNotMatch(leak, /secret-value/);
  const detail = safeErrorMessage(new ApiError("untrusted upstream", {
    status: 400, code: "validation_error",
    fieldErrors: [{ field: "name", message: "required" }],
  }));
  assert.match(detail, /name/i);
  assert.match(detail, /required/i);
  assert.doesNotMatch(detail, /untrusted upstream/);
});
check("L05", "network errors are actionable and do not suggest replaying uncertain effects", () => {
  const output = safeErrorMessage(new ApiError("Network request failed", { code: "network_error" }));
  assert.match(output, /connection failed/i);
  assert.match(output, /uncertain/i);
  assert.doesNotMatch(output, /Network request failed/);
});
check("L06", "settled section errors preserve successes without leaking a 500 payload", async () => {
  const bundle = await settleNamedRequests({
    health: async () => ({ healthy: true }),
    findings: async () => { throw new ApiError("very-secret-upstream-message", { status: 500 }); },
  });
  assert.deepEqual(bundle.health, { healthy: true });
  assert.match(bundle.errors.findings, /server or upstream service failed/i);
  assert.doesNotMatch(bundle.errors.findings, /very-secret-upstream-message/);
});

// 07–09: advisory AI no longer exposes DRAFT_ONBOARDING as a direct mode in
// the decision-explanation panel; drafts render as non-authoritative previews.
check("L07", "AI shows only explanation modes while draft actions require review", () => {
  requireAll(ai, [/\["EXPLAIN",/, /\["RISK_SUMMARY",/, /\["SUGGEST_NEXT_STEP",/,
    /\["COMPARE_OPTIONS",/, /CREATE_CONTRACT_DRAFT/, /CREATE_SECURITY_PACK_DRAFT/,
    /Review the proposed draft before using the approval workflow/]);
  assert.doesNotMatch(ai.slice(ai.indexOf("const MODES = ["), ai.indexOf("const ACTIONS = {")), /DRAFT_ONBOARDING/);
});
check("L08", "AI cannot make authoritative security decisions or mutate Runtime", () => {
  requireAll(ai, [/result\.non_authoritative === true/,
    /result\.requires_human_review === true/,
    /result\.can_mutate_runtime === false/,
    /if \(!safeResult\)/,
    /AI explanation withheld/,
    /cannot approve tools, change signed contracts, grant permissions or invoke MCP tools/]);
});
check("L09", "AI request/response is fenced to tool, fingerprint and analysis context", () => {
  const tool = { id: 3, current_fingerprint: "fp-new", analysis_status: "REVIEW_REQUIRED" };
  const oldAnalysis = { id: 8, fingerprint: "fp-old", completed_at: "2026-01-01" };
  assert.equal(currentAssistantAnalysis(tool, oldAnalysis), null);
  const current = { ...oldAnalysis, fingerprint: "fp-new", analysis_context_hash: "ctx" };
  const expected = currentAssistantAnalysis(tool, current);
  assert.deepEqual(expected?.fingerprint, "fp-new");
  assert.equal(matchesAssistantResponse({ tool_id: 3, mode: "EXPLAIN",
    analysis_id: 8, fingerprint: "fp-new", analysis_context_hash: "ctx" },
  3, "EXPLAIN", expected), true);
  assert.equal(matchesAssistantResponse({ tool_id: 3, mode: "EXPLAIN",
    analysis_id: 8, fingerprint: "fp-new", analysis_context_hash: "stale" },
  3, "EXPLAIN", expected), false);
  requireAll(ai, [/guardRef\.current\.begin\(contextKey\)/,
    /guardRef\.current\.accepts\(request, contextKey\)/,
    /return \(\) => guardRef\.current\.invalidate\(\)/]);
});

// 10–11: old M4 internal copy was intentionally removed from default UX.
check("L10", "advisory semantic evidence has a model fingerprint and provenance limits", () => {
  requireAll(semantic, [/m4_model_identity_sha256/, /m1_parsed_source_proof/,
    /provenance_limitation|provenance/i, /NON_AUTHORITATIVE|not authoritative/i,
    /SHA-256/i]);
});
check("L11", "semantic downstream advisory remains separated from allow or block authority", () => {
  requireAll(semantic, [/m4_downstream_advisory/,
    /m4_structured_semantics/,
    /m4_advisory_module_views|downstream/,
    /NOT_EVALUATED|not evaluated/i]);
  requireAll(analysis, [/Historical analyzer signal/, /approvalDisabledReason\(/]);
});

// 12–14: audit, build and dashboard now use safer names and backend aggregation.
check("L12", "audit details show immutable recorded before/after and target scope", () => {
  requireAll(audit, [/selectedEvent\.before_json/, /selectedEvent\.after_json/,
    /selectedEvent\.metadata/, /selectedEvent\.revision_id/,
    /selectedEvent\.target_id/, /historical audit receipt/i,
    /auditTargetLink\(/, /module-level navigation, not a verified target link/]);
});
check("L13", "Build Security is a native, administrator-gated code scanning page", () => {
  requireAll(app, [/import BuildSecurity/, /<BuildSecurity/]);
  requireAll(build, [/<h2>Code scans<\/h2>/,
    /Administrator only: checks code, secrets and dependencies/,
    /isAdmin/, /fetchBuildScanners/]);
});
check("L14", "dashboard uses backend outcome summary rather than counting pending audit intents", () => {
  requireAll(dashboard, [/const recordedAllows = runtimeSummary\?\.allowed/,
    /const recordedBlocks = runtimeSummary\?\.blocked/,
    /one logical tool call/, /exclude them from KPIs/,
    /not over the first 20/]);
  assert.doesNotMatch(dashboard, /runtimeLogs\.filter\([^)]*decision === "ALLOW"/);
});

// 15–19: explicit tool identity + review eligibility, not old local status rules.
check("L15", "inventory navigates to the exact selected tool, never arbitrary fallback", () => {
  requireAll(inventory, [/onOpenAnalysis=\{\(\) => onNavigate\?\.\("analysis", selectedTool\.id\)\}/]);
  requireAll(app, [/setAnalysisEntryToolId\(requestedTool\)/,
    /requestedToolId=\{analysisEntryToolId\}/]);
  requireAll(analysis, [/const requested = tools\.find\(\(tool\) => String\(tool\.id\) === deepLink\)/,
    /setSelectedToolId\(requested\?\.id \?\? null\)/]);
});
check("L16", "AI asynchronous identity guard ignores answers after a tool switch", () => {
  requireAll(ai, [/guardRef\.current\.activate\(contextKey\)/,
    /guardRef\.current\.begin\(contextKey\)/,
    /guardRef\.current\.accepts\(request, contextKey\)/,
    /guardRef\.current\.invalidate\(\)/,
    /Do not enter credentials or sensitive data/]);
  assert.doesNotMatch(ai, /approveTool\(/);
});
check("L17", "operations retention requires ADMIN, preview digest and refresh", () => {
  requireAll(operations, [/if \(!isAdmin \|\| loading \|\| cleanupLock\.current/,
    /expected_preview_fingerprint: dryRun \? null : preview\.preview_fingerprint/,
    /await cleanupRuntimeLogs\(/, /await onRefresh\?\.\(\)/,
    /window\.confirm\(/]);
  assert.doesNotMatch(operations, /\bfetch\(/);
  assert.doesNotMatch(operations, /deleteRuntime/);
});
check("L18", "approval requires backend eligibility and a matching current fingerprint", () => {
  requireAll(analysis, [/export function approvalDisabledReason\(bundle, latestAnalysis\)/,
    /bundle\?\.errors\?\.eligibility/, /eligibility\.fingerprint !== latestAnalysis\.fingerprint/,
    /if \(!eligibility\.eligible\)/, /Cannot allow:/]);
  assert.doesNotMatch(analysis, /const canApprove = .*analysis_status === "APPROVED"/);
});
check("L19", "selected tool bundle reloads when fingerprint and analysis timestamp change", () => {
  requireAll(analysis, [/bundleToolId === selectedToolId/,
    /setBundle\(null\)/, /fetchToolAnalysisBundle\(selectedToolId\)/,
    /\[selectedToolId, selectedToolFingerprint, selectedToolLastAnalyzedAt, reviewRefresh\]/]);
});

// 20–32: Cloud Security; actual bound mapping functions tested dynamically.
check("L20", "Terraform scanning is Cloud-owned and requires no AWS account", () => {
  requireAll(cloud, [/Check Terraform configuration/,
    /Terraform ZIP archive/, /uploadTerraformZip\(iacFile\)/,
    /fetchIaCScannerAvailability\(\)/,
    /No AWS connection is required/]);
});
check("L21", "only ADMIN can upload Terraform; VIEWER receives stored scan history", () => {
  requireAll(cloud, [/\{isAdmin && \(\s*<form className="contract-editor" onSubmit=\{uploadIaC\}>/,
    /CloudScanTable scans=\{iacScans\}/,
    /details\.scan\.kind === "IAC_CONFIG"|details\.scan\.kind/]);
  assert.doesNotMatch(cloud, /window\.prompt\(/);
});
check("L22", "Prowler readiness gates action on verified installed scanner and IAM role", () => {
  requireAll(cloud, [/fetchProwlerAvailability\(\)/,
    /disabled=\{busy \|\| prowlerStatusError \|\| !prowlerStatus\?\.available \|\| current\.status !== "CONNECTED" \|\| !current\.role_arn\}/,
    /startProwlerCloudScan\(current\.id\)/, /advancedScans/,
    /The Prowler engine must be installed and verified/]);
});
check("L23", "advanced AWS UI explains unavailable Prowler rather than claiming clean", () => {
  requireAll(cloud, [/Advanced AWS audit with Prowler/,
    /Could not be verified/, /Checking availability/,
    /prowlerStatus\.available \? "Ready" : "Unavailable"/,
    /Cannot verify the advanced scanner installation/]);
});
check("L24", "Prowler, AWS baseline and Terraform remain distinct finding families", () => {
  requireAll(cloud, [/s\.kind === "AWS_ADVANCED"/,
    /advancedScans/, /AWS_BASELINE/, /IAC_CONFIG/,
    /scanKinds/, /historyKind/]);
});
const ctx = { signed_revision: 4, signed_content_hash: "content-v4" };
const env = { account_id: "111122223333", status: "CONNECTED" };
const server = { endpoint: "https://mcp.example.invalid/mcp" };
const mapping = {
  status: "APPROVED", signed_revision: 4, signed_content_hash: "content-v4",
  configuration: { source_binding: { account_id: env.account_id, server_endpoint: server.endpoint } },
};
check("L25", "IAM mapping is bound to the signed contract and AWS account", () => {
  assert.equal(isMappingBoundToCurrentContext(mapping, env, server, ctx), true);
  assert.equal(isMappingBoundToCurrentContext(mapping, { ...env, account_id: "other" }, server, ctx), false);
  assert.equal(isMappingBoundToCurrentContext(mapping, env, { endpoint: "https://other.invalid/mcp" }, ctx), false);
});
check("L26", "only approved reviewed mapping can be scanned", () => {
  assert.equal(canRequestManualAudit(mapping, env, server, ctx), true);
  assert.equal(canRequestManualAudit({ ...mapping, status: "DRAFT" }, env, server, ctx), false);
  assert.equal(canRequestManualAudit(mapping, { ...env, status: "DISCONNECTED" }, server, ctx), false);
  requireAll(cloud, [/isAdmin && contextReady && sameServer && canRequestManualAudit/,
    /approvalConfirmed/, /startIAMMCPComparison\(current\.id, chosen\.id\)/]);
});
check("L27", "IAM comparison renders role, resources and unknown coverage separately", () => {
  requireAll(cloud, [/expected_resource_arn|resource_template/,
    /item\.tool_name|entry\.tool_name/, /item\.role_arn|selected\.role_arn/,
    /IAM_MCP/, /fetchIAMMCPResultsPage/,
    /Not recorded|UNKNOWN/]);
});
check("L28", "IAM comparison remains read-only without changing cloud permissions", () => {
  requireAll(cloud, [/Read-only: nothing is granted or changed in AWS/,
    /No cloud\s+role or published MCP contract is changed/,
    /Approval digest/, /expected_role_arn/]);
  assert.doesNotMatch(cloud, /iam:PutRolePolicy|iam:AttachRolePolicy/);
});
check("L29", "IAM status explanations avoid presenting identity grant as effective authority", () => {
  requireAll(cloud, [/IAM_IDENTITY_EXPLICIT_DENY/,
    /IAM_ALLOW_SCOPE_BROADER_THAN_SIGNED_MCP/,
    /IAM_IDENTITY_ALLOW_NOT_FOUND_RESOURCE_POLICY_UNVERIFIED/,
    /IAM_EXACT_IDENTITY_ALLOW_EFFECTIVE_UNKNOWN/,
    /iamAssessmentExplanation\(item\.notes\)/,
    /Signed contract revision:/, /Policy digest:/]);
});
check("L30", "missing IAM reads are flagged only when actually recorded", () => {
  requireAll(cloud, [/iamRows\.some\(\(item\) => item\.notes === "IAM_ROLE_OR_POLICY_READ_UNAVAILABLE"\)/,
    /The audit identity could not read all required IAM/,
    /iam:GetRole/, /IAM and MCP comparison queued/,
    /item\.policy_digest \|\| "Not recorded"/]);
});
check("L31", "identity-policy permission never proves effective AWS access", () => {
  requireAll(cloud, [/selected\.identity_permission_status/,
    /Identity-policy observation/,
    /Effective AWS access is assessed/,
    /a present identity grant is not proof/,
    /resource and session policies may restrict it/]);
});
check("L32", "stale signed mappings cannot authorize a new scan; only review copy", () => {
  assert.equal(canRequestManualAudit(mapping, env, server, { ...ctx, signed_content_hash: "changed" }), false);
  assert.equal(canRequestManualAudit(mapping, env, { ...server, endpoint: "https://changed.invalid/mcp" }, ctx), false);
  requireAll(cloud, [/const validBinding = isMappingBoundToCurrentContext\(/,
    /chosen\?\.signed_content_hash === mappingContext\?\.signed_content_hash/,
    /canRequestManualAudit\(chosen,current,registered,mappingContext\)/,
    /Create a new reviewed draft before scanning/,
    /Copy configuration into new draft/]);
  const effects = [{ tool_name: "read_file", effect_id: "read", resource_type: "s3" }];
  assert.equal(manualMappingCoverage(effects, []).unmapped.length, 1);
});
