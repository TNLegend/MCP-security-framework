import assert from "node:assert/strict";
import test from "node:test";

import { assistantErrorMessage, currentAssistantAnalysis, matchesAssistantResponse } from "../src/utils/controlledAI.js";

const fingerprint = "a".repeat(64);
const contextHash = "b".repeat(64);
const tool = { id: 4, current_fingerprint: fingerprint };
const analysis = {
  id: 6, fingerprint, completed_at: "2026-11-21T09:00:00Z", analysis_context_hash: contextHash,
  analysis_status: "BLOCKED", review_status: "REVIEW_REQUIRED",
};

test("assistant context requires a completed analysis of the current tool", () => {
  assert.deepEqual(currentAssistantAnalysis(tool, analysis), {
    id: 6, fingerprint, context_hash: contextHash, analysis_status: "BLOCKED", review_status: "REVIEW_REQUIRED",
  });
  assert.equal(currentAssistantAnalysis(tool, { ...analysis, fingerprint: "old" }), null);
  assert.equal(currentAssistantAnalysis(tool, { ...analysis, completed_at: null }), null);
  assert.equal(currentAssistantAnalysis({ ...tool, analysis_status: "PENDING_ANALYSIS" }, analysis), null);
});

test("advisory response must match tool, mode, analysis and evidence identity", () => {
  const expected = currentAssistantAnalysis(tool, analysis);
  const reply = { tool_id: 4, mode: "EXPLAIN", analysis_id: 6, fingerprint, analysis_context_hash: contextHash };
  assert.equal(matchesAssistantResponse(reply, tool.id, "EXPLAIN", expected), true);
  for (const change of [{ tool_id: 2 }, { mode: "DRAFT_ONBOARDING" }, { analysis_id: 5 },
    { fingerprint: "old" }, { analysis_context_hash: null }]) {
    assert.equal(matchesAssistantResponse({ ...reply, ...change }, tool.id, "EXPLAIN", expected), false);
  }
  const legacyExpected = currentAssistantAnalysis(tool, { ...analysis, analysis_context_hash: null });
  assert.equal(matchesAssistantResponse({ ...reply, analysis_context_hash: null }, tool.id, "EXPLAIN", legacyExpected), true);
});

test("operator errors distinguish timeout, network and quota without echoing provider data", () => {
  assert.match(assistantErrorMessage({ status: 429 }), /request limit/i);
  assert.match(assistantErrorMessage({ status: 504 }), /timed out/i);
  assert.match(assistantErrorMessage({ code: "network_error" }), /connection/i);
  assert.match(assistantErrorMessage({ code: "controlled_ai_unknown_evidence_ref" }), /could not be verified/i);
  assert.doesNotMatch(assistantErrorMessage({ message: "PRIVATE_UPSTREAM_DIAGNOSTIC", status: 503 }), /PRIVATE_/);
});
