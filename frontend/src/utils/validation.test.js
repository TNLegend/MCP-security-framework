import assert from "node:assert/strict";
import test from "node:test";

import {
  discoverySubmissionArguments,
  discoveryPayload,
  emergencyDenyPayload,
  enabledAdminCount,
  formatLocalDateTime,
  futureLocalDateTime,
  hasNonEmptyAnalysisEvidence,
  isContentDirty,
  isFinalEnabledAdmin,
  localDateTimeToIso,
  oauthMcpRegistrationPayload,
  parseJsonContent,
  pendingToolAnalysisCount,
  reviewRequiredToolCount,
  validateChangeSummary,
  validateCredentialRef,
  validateDiscovery,
  validateEmergencyDeny,
  validateLogin,
  validatePassword,
  validatePasswordReset,
  validateToolJustification,
  validateUserCreate,
} from "./validation.js";

test("password and confirmation validation mirrors backend shape", () => {
  assert.match(validatePassword("1234"), /at least 8/);
  assert.equal(validatePassword("12345678"), "");
  assert.match(
    validatePasswordReset({
      password: "12345678",
      confirmation: "different",
      reason: "reset",
    }).confirmation,
    /does not match/,
  );
});

test("username display name and reason validation reject common invalid input", () => {
  assert.match(validateUserCreate({
    username: "bad name",
    password: "12345678",
    confirmation: "12345678",
    role: "VIEWER",
    display_name: "",
  }).username, /whitespace/);
  assert.match(validateUserCreate({
    username: "good",
    password: "12345678",
    confirmation: "12345678",
    role: "VIEWER",
    display_name: "x".repeat(256),
  }).display_name, /at most 255/);
  assert.match(validatePasswordReset({
    password: "12345678",
    confirmation: "12345678",
    reason: "no",
  }).reason, /at least 3/);
});

test("tool review and config summaries enforce minimum lengths", () => {
  assert.match(validateToolJustification("short"), /at least 8/);
  assert.match(validateChangeSummary("no"), /at least 3/);
});

test("emergency deny validation handles target reason and expiry rules", () => {
  const now = new Date("2026-08-19T12:00:00");
  assert.match(validateEmergencyDeny({
    target_type: "server_tool",
    target_value: "server",
    target_secondary_value: "",
    reason: "valid reason",
    expires_at: "2026-08-19T13:00",
  }, now).target_secondary_value, /Tool name is required/);
  assert.match(validateEmergencyDeny({
    target_type: "agent_id",
    target_value: "agent_demo",
    target_secondary_value: "",
    reason: "short",
    expires_at: "2026-08-19T13:00",
  }, now).reason, /at least 8/);
  assert.match(validateEmergencyDeny({
    target_type: "global",
    target_value: "",
    target_secondary_value: "",
    reason: "valid reason",
    expires_at: "2026-08-19T11:00",
  }, now).expires_at, /future/);
});

test("emergency deny payload converts valid local datetime to ISO", () => {
  const result = emergencyDenyPayload({
    target_type: "server_tool",
    target_value: "server",
    target_secondary_value: "tool",
    reason: "valid reason",
    expires_at: "2026-08-19T13:00",
  }, new Date("2026-08-19T12:00:00"));
  assert.equal(result.payload.target_value, "server");
  assert.match(result.payload.expires_at, /^\d{4}-\d{2}-\d{2}T/);
});

test("datetime-local helpers use local components and future defaults", () => {
  const now = new Date(2026, 7, 19, 12, 5, 0);
  assert.equal(formatLocalDateTime(now), "2026-08-19T12:05");
  const future = futureLocalDateTime(60 * 60 * 1000, now);
  assert.equal(future, "2026-08-19T13:05");
  assert.ok(new Date(localDateTimeToIso(future, now).iso) > now);
});

test("discovery validation rejects unsafe browser-detectable endpoint shapes", () => {
  assert.match(validateDiscovery({
    endpoint: " http://127.0.0.1:9000/mcp ",
    authMode: "NONE",
    credentialRef: "",
  }).endpoint, /whitespace/);
  assert.match(validateDiscovery({
    endpoint: "http://127.0.0.1:9000\\mcp",
    authMode: "NONE",
    credentialRef: "",
  }).endpoint, /backslashes/);
  assert.match(validateDiscovery({
    endpoint: "ftp://example.test/mcp",
    authMode: "NONE",
    credentialRef: "",
  }).endpoint, /http or https/);
  assert.match(validateDiscovery({
    endpoint: "https://user:pass@example.test/mcp",
    authMode: "NONE",
    credentialRef: "",
  }).endpoint, /credentials/);
  assert.match(validateDiscovery({
    endpoint: "https://example.test/mcp#token",
    authMode: "NONE",
    credentialRef: "",
  }).endpoint, /fragment/);
  assert.match(validateDiscovery({
    endpoint: "https://example.test/mcp?token=secret",
    authMode: "NONE",
    credentialRef: "",
  }).endpoint, /sensitive/);
  assert.match(validateDiscovery({
    endpoint: "https://example.test/mcp?api_key=secret",
    authMode: "NONE",
    credentialRef: "",
  }).endpoint, /sensitive/);
  assert.deepEqual(validateDiscovery({
    endpoint: "https://example.test/mcp?tenant=lab",
    authMode: "NONE",
    credentialRef: "",
  }), {});
  assert.equal(discoveryPayload({
    endpoint: "http://127.0.0.1:9000/mcp",
    authMode: "NONE",
    credentialRef: "",
  }).payload.endpoint, "http://127.0.0.1:9000/mcp");
});

test("discovery submission arguments use normalized endpoint and preserve auth fields", () => {
  assert.deepEqual(discoverySubmissionArguments({
    endpoint: "http://127.0.0.1:9000/mcp",
    authMode: "NONE",
    credentialRef: "",
  }).args, [
    "http://127.0.0.1:9000/mcp",
    "2025-11-25",
    "NONE",
    null,
  ]);

  assert.deepEqual(discoverySubmissionArguments({
    endpoint: "https://vendor.example/mcp",
    authMode: "BEARER",
    credentialRef: " mcp/vendor/service.token ",
  }).args, [
    "https://vendor.example/mcp",
    "2025-11-25",
    "BEARER",
    "mcp/vendor/service.token",
  ]);

  for (const endpoint of [
    " http://127.0.0.1:9000/mcp ",
    "http://127.0.0.1:9000\\mcp",
    "https://user:pass@example.test/mcp",
    "https://example.test/mcp#fragment",
    "https://example.test/mcp?token=secret",
  ]) {
    assert.equal(discoverySubmissionArguments({
      endpoint,
      authMode: "NONE",
      credentialRef: "",
    }).args, null);
  }
});

test("OAuth MCP registration keeps client credentials out of the endpoint and validates scopes", () => {
  const valid = oauthMcpRegistrationPayload({
    endpoint: "https://vendor.example/mcp",
    clientId: "framework-client",
    requestedScopes: "files:read profile",
    clientSecret: "client-secret",
  });
  assert.deepEqual(valid.errors, {});
  assert.deepEqual(valid.payload, {
    endpoint: "https://vendor.example/mcp",
    protocol_version: "2025-11-25",
    client_id: "framework-client",
    requested_scopes: "files:read profile",
    client_secret: "client-secret",
  });
  assert.match(
    oauthMcpRegistrationPayload({
      endpoint: "https://vendor.example/mcp?token=not-allowed",
      clientId: "framework-client",
      requestedScopes: "bad scope!",
      clientSecret: "",
    }).errors.endpoint,
    /sensitive/,
  );
});

test("analysis summary distinguishes pending analysis from tools requiring review", () => {
  const tools = [
    { id: "tool-1", analysis_status: "APPROVED" },
    { id: "tool-2", analysis_status: "REVIEW_REQUIRED" },
    { id: "tool-3", analysis_status: "QUARANTINED" },
    { id: "tool-4", analysis_status: "PENDING_ANALYSIS" },
    { id: "tool-5", analysis_status: "ANALYSIS_FAILED" },
  ];
  const pendingServers = [{ id: "server-1", security_status: "pending_analysis" }];

  assert.equal(pendingToolAnalysisCount(tools), 1);
  assert.equal(reviewRequiredToolCount(tools), 3);
  assert.ok(pendingToolAnalysisCount(tools) < tools.length + pendingServers.length);
});

test("login validation mirrors backend request shape", () => {
  assert.match(validateLogin({ username: "", password: "x" }).username, /required/);
  assert.equal(validateLogin({ username: "operator", password: "x" }).password, undefined);
  assert.match(
    validateLogin({ username: "u".repeat(129), password: "x" }).username,
    /at most 128/,
  );
  assert.match(
    validateLogin({ username: "operator", password: "p".repeat(4097) }).password,
    /at most 4096/,
  );
});

test("analysis evidence helpers reject empty containers", () => {
  assert.equal(hasNonEmptyAnalysisEvidence({}), false);
  assert.equal(hasNonEmptyAnalysisEvidence([]), false);
  assert.equal(hasNonEmptyAnalysisEvidence({ status: "NONE" }), true);
});

test("credential references reject malformed path segments", () => {
  assert.equal(validateCredentialRef("mcp/vendor/service.token"), "");
  assert.match(validateCredentialRef("mcp//service.token"), /empty path/);
  assert.match(validateCredentialRef("mcp/../service.token"), /explicit/);
});

test("final enabled admin is detected for UX only", () => {
  const users = [
    { id: "1", role: "ADMIN", enabled: true },
    { id: "2", role: "VIEWER", enabled: true },
  ];
  assert.equal(enabledAdminCount(users), 1);
  assert.equal(isFinalEnabledAdmin(users[0], users), true);
});

test("config helpers detect invalid JSON and dirty content", () => {
  assert.equal(parseJsonContent("{bad").error, "Invalid JSON.");
  assert.equal(isContentDirty('{"a":1}', { a: 1 }), false);
  assert.equal(isContentDirty('{"a":2}', { a: 1 }), true);
});
