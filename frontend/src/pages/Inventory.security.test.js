import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

const source = readFileSync(new URL("./Inventory.jsx", import.meta.url), "utf-8");

test("inventory tool evidence bundle belongs to the selected tool only", () => {
  assert.match(source, /toolAnalysisToolId === selectedToolId/);
  assert.match(source, /setToolAnalysis\(null\)/);
  assert.match(source, /selectedToolFingerprint/);
  assert.match(source, /selectedToolLastAnalyzedAt/);
  assert.match(source, /\[selectedToolId, selectedToolFingerprint, selectedToolLastAnalyzedAt\]/);
});

test("inventory submits the validated normalized discovery payload", () => {
  assert.match(source, /discoverySubmissionArguments/);
  assert.match(source, /discoverHttpMcpServer\(\.\.\.args\)/);
  assert.doesNotMatch(source, /discoverHttpMcpServer\(\s*endpoint,/);
  assert.doesNotMatch(source, /discoverHttpMcpServer\(\s*payload\.endpoint\s*,\s*payload\.endpoint/);
});

test("inventory exposes status and versions bundle errors", () => {
  assert.match(source, /status_error/);
  assert.match(source, /versions_error/);
});

test("inventory pending analysis summary is based on tools only", () => {
  assert.match(source, /pendingToolAnalysisCount\(visibleTools\)/);
  assert.match(source, /reviewRequiredToolCount\(visibleTools\)/);
  assert.doesNotMatch(source, /servers\.filter\(\(server\) => hasPendingStatus/);
});

test("inventory details only show findings from the latest analysis", () => {
  assert.match(source, /const latestAnalysisFindings = latestAnalysis/);
  assert.match(source, /finding\.analysis_id === latestAnalysis\.id/);
  assert.match(source, /summarizeFindings\(latestAnalysisFindings\)/);
});

test("inventory hides archived servers by default and archives with a validated reason", () => {
  assert.match(source, /includeArchived \? servers : servers\.filter/);
  assert.match(source, /archiveServer\(selectedServer\.id, archiveDialog\.reason\.trim\(\)\)/);
  assert.match(source, /validateReason\(archiveDialog\.reason\)/);
  assert.match(source, /Include archived/);
});
