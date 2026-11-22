import assert from "node:assert/strict";
import test from "node:test";
import { readFileSync } from "node:fs";

const audit = readFileSync(new URL("../src/pages/Audit.jsx", import.meta.url), "utf8");
const client = readFileSync(new URL("../src/api/client.js", import.meta.url), "utf8");
const app = readFileSync(new URL("../src/App.jsx", import.meta.url), "utf8");

test("PH9: Generate report is explicitly ADMIN-only in the Audit view", () => {
  assert.match(app, /<Audit[^>]+isAdmin=\{isAdmin\}/);
  assert.match(audit, /\{isAdmin && \(/);
  assert.match(audit, />\s*Generate report\s*</);
});

test("PH9: dates and export formats are bounded user choices", () => {
  for (const value of ["7d", "30d", "90d", "all", "pdf", "html", "json", "csv"]) {
    assert.match(audit, new RegExp('value="' + value + '"'));
  }
  assert.match(audit, /includeEvidence/);
  assert.doesNotMatch(audit, /includePhase8|phase8_reference|Phase 8/i);
});

test("PH9: binary download is a CSRF-protected POST with credentials", () => {
  assert.match(client, /requestBlob\("\/control-plane\/audit\/reports\/generate"/);
  assert.match(client, /method: "POST"/);
  assert.match(client, /headers\["x-csrf-token"\]/);
  assert.match(client, /credentials: "include"/);
  assert.match(audit, /window\.URL\.createObjectURL/);
  assert.match(audit, /window\.URL\.revokeObjectURL/);
});

test("PH9: failure is shown as an actionable error, not a false success", () => {
  assert.match(audit, /safeErrorMessage\(err\)/);
  assert.match(audit, /reportError && <p role="alert"/);
  assert.match(audit, /reportBusy \? "Generating\.\.\." : "Generate & download"/);
});

test("PH9: generation never replays a scan or invokes a policy change", () => {
  assert.match(audit, /without running new scans/);
  assert.doesNotMatch(audit, /runSecurityScan|startGitBuildScan|applyMapping/);
});
