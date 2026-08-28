import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

const source = readFileSync(new URL("./ControlledAIAssistant.jsx", import.meta.url), "utf-8");

test("controlled AI exposes all advisory modes", () => {
  for (const mode of [
    "EXPLAIN",
    "RISK_SUMMARY",
    "SUGGEST_NEXT_STEP",
    "COMPARE_OPTIONS",
    "DRAFT_ONBOARDING",
  ]) {
    assert.match(source, new RegExp(mode));
  }
});

test("controlled AI UI makes authority boundary explicit", () => {
  assert.match(source, /Advisory only/);
  assert.match(source, /AI output never substitutes for administrator review/);
  assert.match(source, /AI cannot approve tools/);
  assert.match(source, /publish configuration/);
  assert.match(source, /grant capabilities/);
  assert.match(source, /execute MCP tools/);
  assert.match(source, /No runtime mutation/);
  assert.match(source, /not a Control Plane DRAFT/);
});

test("controlled AI requires a current analysis fingerprint and resets across tools", () => {
  assert.match(source, /tool\.current_fingerprint === currentAnalysis\.fingerprint/);
  assert.match(source, /const canAsk = Boolean\(isAdmin && tool\?\.id && contextFresh && !busy\)/);
  assert.match(source, /\[tool\?\.id, tool\?\.current_fingerprint\]/);
  assert.match(source, /completed analysis matching the tool's current fingerprint/);
});

test("controlled AI UI only imports advisory API functions", () => {
  assert.match(source, /requestControlledAIAssistance/);
  assert.doesNotMatch(source, /approveTool/);
  assert.doesNotMatch(source, /publishConfigRevision/);
  assert.doesNotMatch(source, /createToolContractDraft/);
  assert.doesNotMatch(source, /createToolSecurityPackDraft/);
  assert.doesNotMatch(source, /setSecurityPackEnabled/);
});

test("controlled AI is admin-only in the browser UI", () => {
  assert.match(source, /Controlled AI requests are ADMIN-only/);
  assert.match(source, /\{isAdmin && \(/);
  assert.match(source, /!isAdmin && \(/);
});
