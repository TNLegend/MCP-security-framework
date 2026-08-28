import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

const source = readFileSync(new URL("./Operations.jsx", import.meta.url), "utf-8");

test("operations UI exposes readiness runtime metrics pool storage and rotation", () => {
  assert.match(source, /Runtime Operations/);
  assert.match(source, /Service readiness/);
  assert.match(source, /Runtime window/);
  assert.match(source, /Gateway mediation/);
  assert.match(source, /Policy \/ backend/);
  assert.match(source, /Upstream MCP/);
  assert.match(source, /Result Guard/);
  assert.match(source, /PostgreSQL pool/);
  assert.match(source, /Runtime storage/);
  assert.match(source, /Process log bounds/);
});

test("operations maintenance is admin-only and preview-gated", () => {
  assert.match(source, /Cleanup is ADMIN-only/);
  assert.match(source, /VIEWER can inspect operations but cannot run maintenance/);
  assert.match(source, /Preview cleanup/);
  assert.match(source, /Apply bounded cleanup/);
  assert.match(source, /!preview \|\| preview\.planned <= 0/);
  assert.match(source, /dry_run: dryRun/);
});

test("operations UI only uses bounded maintenance API and refresh", () => {
  assert.match(source, /cleanupRuntimeLogs/);
  assert.match(source, /await onRefresh\?\.\(\)/);
  assert.doesNotMatch(source, /fetch\(/);
  assert.doesNotMatch(source, /deleteRuntime/);
  assert.doesNotMatch(source, /publish/);
});
