import assert from "node:assert/strict";
import test from "node:test";
import { createServer } from "vite";
import {
  safeRuntimeText, sanitizeRuntimeEvidence, formatSafeRuntimeEvidence,
} from "../src/utils/runtimeRedaction.js";

test("RT-03: historical runtime records redact sensitive keys and embedded tokens without losing relevant evidence", () => {
  const raw = {
    operation_id: "12345678-1234-4321-89ab-0123456789ab",
    result: "policy blocked",
    authorization: "Bearer very-long-provider-access-token",
    oauth: { refresh_token: "a-top-secret-refresh-token", apiKey: "priv-api-key" },
    structured: { decisions: ["ALLOW", "BLOCK"], password: "a-password-secret" },
  };
  const displayed = formatSafeRuntimeEvidence(raw);
  assert.match(displayed, /12345678-1234-4321-89ab-0123456789ab/);
  assert.match(displayed, /policy blocked/);
  for (const secret of [
    "very-long-provider-access-token", "a-top-secret-refresh-token",
    "priv-api-key", "a-password-secret",
  ]) assert.ok(!displayed.includes(secret), "leaked " + secret);
  assert.match(displayed, /\[REDACTED\]/);
  assert.deepEqual(sanitizeRuntimeEvidence({ status: "BLOCK" }), { status: "BLOCK" });

  const rawText = 'Authorization: Bearer SomeReallyLongSecretAccessToken ' +
    'api_key=Abcdef1234567890 password=SuperSecretPassword1234 ' +
    'sk-12345678901234567890';
  const safe = safeRuntimeText(rawText);
  assert.doesNotMatch(safe, /SomeReallyLongSecretAccessToken|Abcdef1234567890|SuperSecretPassword1234|sk-12345678901234567890/);
  const rawJson = JSON.stringify(raw);
  const json = formatSafeRuntimeEvidence(rawJson);
  assert.ok(!json.includes("a-top-secret-refresh-token"));
  assert.match(formatSafeRuntimeEvidence({ nested: { data: [{ code: "guard_fail" }] } }), /guard_fail/);
  const limited = JSON.parse(formatSafeRuntimeEvidence({ records: Array(100).fill("safe") }));
  assert.equal(limited.records.length, 33);
  assert.equal(limited.records[32], "[additional items omitted]");
});

test("RT-03: historical runtime failure vocabulary is never rendered as neutral success", async () => {
  const server = await createServer({
    configFile: false, plugins: [(await import("@vitejs/plugin-react")).default()],
    server: { middlewareMode: true, hmr: false }, appType: "custom", logLevel: "silent",
  });
  try {
    const { getExecutionBadgeClass } =
      await server.ssrLoadModule("/src/pages/RuntimeLogs.jsx");
    const historical = [
      "tool_error", "protocol_error", "http_error", "upstream_outcome_unknown",
      "policy_error", "inventory_error", "client_initialization_error",
      "upstream_auth_error", "audit_completion_failed", "audit_unavailable",
    ];
    for (const code of historical) {
      assert.match(getExecutionBadgeClass(code), /badge-danger|badge-warning/, code);
    }
    assert.equal(getExecutionBadgeClass("success"), "badge-success");
    assert.equal(getExecutionBadgeClass("unknown"), "badge-unknown");
  } finally {
    await server.close();
  }
});