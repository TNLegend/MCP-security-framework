import assert from "node:assert/strict";
import test from "node:test";
import { driftComparisonState } from "../src/utils/analysisPresentation.js";

const FP_A = "a".repeat(64);
const FP_B = "b".repeat(64);
const bound = (comparison, changes = []) => ({ drift_result: { status: "NONE", changes, similarity: 1, comparison } });
const target = (extra = {}) => ({
  schema: "m6.comparison_target.v1", baseline_present: true, baseline_snapshot_available: true,
  baseline_id: 4, baseline_version_id: 9, baseline_fingerprint: FP_A, compared: true, comparison_ran: true, ...extra,
});

test("UX-06: empty changes with no baseline reads 'No approved baseline', never 'no changes'", () => {
  const analysis = { drift_result: { status: "NONE", changes: [], similarity: null,
    comparison: target({ baseline_present: false, baseline_fingerprint: null, baseline_version_id: null, compared: false }) } };
  const result = driftComparisonState(analysis, { baseline: null, errors: {} }, true);
  assert.equal(result.state, "no_baseline");
  assert.equal(result.label, "No approved baseline");
  assert.doesNotMatch(result.label, /no changes/i);
});

test("UX-06: unchanged is stated only for a completed comparison bound to a named baseline", () => {
  const result = driftComparisonState(bound(target()), { baseline: { fingerprint: FP_A }, errors: {} }, true);
  assert.equal(result.state, "unchanged");
  assert.match(result.label, /No drift against baseline aaaaaaaaaaaa/);
  assert.match(result.detail, /version 9/);
});

test("UX-06: recorded changes keep their count and comparison target", () => {
  const result = driftComparisonState(bound(target(), [{ type: "input_schema_modified" }, { type: "x" }]),
    { baseline: { fingerprint: FP_A }, errors: {} }, true);
  assert.equal(result.state, "changed");
  assert.match(result.label, /^2 change\(s\) recorded against approved baseline aaaaaaaaaaaa/);
});

test("UX-06: missing baseline snapshot, failed analysis, stale and not-current are 'unavailable' or 'stale'", () => {
  assert.equal(driftComparisonState(bound(target({ baseline_snapshot_available: false, compared: false })),
    { baseline: { fingerprint: FP_A }, errors: {} }, true).state, "unavailable");
  assert.equal(driftComparisonState(bound(target({ comparison_ran: false, compared: false })),
    { baseline: { fingerprint: FP_A }, errors: {} }, true).state, "unavailable");
  // Baseline approved after the analysis, or replaced since.
  const noBaselineThen = bound(target({ baseline_present: false, compared: false, baseline_fingerprint: null }));
  assert.equal(driftComparisonState(noBaselineThen, { baseline: { fingerprint: FP_B }, errors: {} }, true).state, "stale");
  assert.equal(driftComparisonState(bound(target()), { baseline: { fingerprint: FP_B }, errors: {} }, true).state, "stale");
  assert.equal(driftComparisonState(bound(target()), { baseline: { fingerprint: FP_A }, errors: {} }, false).state, "unavailable");
  assert.equal(driftComparisonState({ drift_result: null }, {}, true).state, "unavailable");
});

test("UX-06: legacy rows without a comparison reference stay conservative", () => {
  const legacyNull = { drift_result: { status: "NONE", changes: [], similarity: null } };
  assert.equal(driftComparisonState(legacyNull, { baseline: null, errors: {} }, true).state, "no_baseline");
  assert.equal(driftComparisonState(legacyNull, { baseline: { fingerprint: FP_A }, errors: {} }, true).state, "unavailable");
  assert.equal(driftComparisonState(legacyNull, { baseline: null, errors: { baseline: "503" } }, true).state, "unavailable");
  const legacyRan = { drift_result: { status: "NONE", changes: [], similarity: 1 } };
  const result = driftComparisonState(legacyRan, { baseline: { fingerprint: FP_A }, errors: {} }, true);
  assert.equal(result.state, "legacy_unchanged");
  assert.match(result.detail, /did not record which baseline/);
});
