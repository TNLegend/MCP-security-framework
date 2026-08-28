import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

const source = readFileSync(new URL("./ToolAnalysis.jsx", import.meta.url), "utf-8");

test("tool review uses modal justification and not window.prompt", () => {
  assert.doesNotMatch(source, /window\.prompt/);
  assert.match(source, /reviewDialog/);
  assert.match(source, /validateToolJustification/);
});

test("approve action is disabled for incomplete or stale analysis evidence", () => {
  assert.match(source, /approvalDisabledReason/);
  assert.match(source, /latestAnalysis\.fingerprint !== tool\.current_fingerprint/);
  assert.match(source, /!latestAnalysis\.completed_at/);
  assert.match(source, /analysis_context_hash/);
  assert.match(source, /ANALYSIS_FAILED/);
  assert.match(source, /STALE/);
  assert.match(source, /hasNonEmptyAnalysisEvidence\(latestAnalysis\.semantic_scores\)/);
  assert.match(source, /hasNonEmptyAnalysisEvidence\(latestAnalysis\.drift_result\)/);
  assert.match(source, /hasNonEmptyAnalysisEvidence\(latestAnalysis\.model_versions\)/);
  assert.match(source, /latestAnalysis\.review_status/);
});

test("tool bundle renders section-specific errors", () => {
  assert.match(source, /bundle\?\.errors\?\.status/);
  assert.match(source, /bundle\?\.errors\?\.versions/);
  assert.match(source, /bundle\?\.errors\?\.findings/);
  assert.match(source, /unavailable/);
});

test("tool evidence bundle is owned by the selected tool and reloads on same-tool analysis changes", () => {
  assert.match(source, /bundleToolId === selectedToolId/);
  assert.match(source, /selectedToolFingerprint/);
  assert.match(source, /selectedToolLastAnalyzedAt/);
  assert.match(source, /\[selectedToolId, selectedToolFingerprint, selectedToolLastAnalyzedAt\]/);
  assert.match(source, /setBundle\(null\)/);
});

test("tool evidence is organized into findings semantic AI history and raw tabs", () => {
  assert.match(source, /\["findings", "Findings"\]/);
  assert.match(source, /\["semantic", "Semantic"\]/);
  assert.match(source, /\["ai", "AI Assist"\]/);
  assert.match(source, /ControlledAIAssistant/);
  assert.match(source, /\["history", "History"\]/);
  assert.match(source, /\["contract", "Contract"\]/);
  assert.match(source, /\["raw", "Raw evidence"\]/);
  assert.match(source, /scores\?\.model_flagged/);
  assert.match(source, /scores\?\.corroborated/);
  assert.match(source, /scores\?\.abstained/);
  assert.match(source, /Observed facts/);
  assert.match(source, /semanticFactGroups/);
  assert.match(source, /unknown_reasons/);
});
