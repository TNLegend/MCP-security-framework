import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

function page(name) {
  return readFileSync(new URL(`../src/pages/${name}.jsx`, import.meta.url), "utf8");
}

test("inventory, review, and scan history expose native keyboard selection within tables", () => {
  for (const name of ["Inventory", "ToolAnalysis", "BuildSecurity"]) {
    const source = page(name);
    assert.match(source, /<td><button className="table-selection" aria-pressed=/);
    assert.doesNotMatch(source, /<tr\b[^>]*role="button"/s);
  }
});

test("server archive and trust reviews retain a named dialog and a bound server identity", () => {
  const source = page("Inventory");
  for (const name of ["archive", "trust"]) {
    assert.match(source, new RegExp(`aria-labelledby="inventory-${name}-title"`));
    assert.match(source, new RegExp(`useDialogFocus\\(Boolean\\(${name}Dialog && isAdmin`));
    assert.match(source, new RegExp(`selectedServer\\?\\.id !== ${name}Dialog\\.serverId`));
  }
});

test("scan history rejects old detail responses and lets operators retry the selected scan", () => {
  const source = page("BuildSecurity");
  assert.match(source, /const request = \+\+detailRequest\.current/);
  assert.match(source, /setRequestedScanId\(scanId\);\s*setSelectedScan\(null\)/);
  assert.match(source, /if \(request === detailRequest\.current\) setSelectedScan\(detail\)/);
  assert.match(source, /Retry loading scan evidence/);
});

test("review errors stay in the confirmation dialog and submission retains the evidence identity guard", () => {
  const source = page("ToolAnalysis");
  assert.match(source, /reviewDialog\.fingerprint !== selectedTool\.current_fingerprint/);
  assert.match(source, /reviewDialog\.analysisContextHash !== \(reviewAnalysis\?\.analysis_context_hash/);
  assert.match(source, /current \? \{ \.\.\.current, error: err\.message/);
});
