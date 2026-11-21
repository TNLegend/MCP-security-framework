import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import React from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { createServer } from "vite";

async function renderProvenance(decision) {
  const server = await createServer({
    configFile: false,
    plugins: [(await import("@vitejs/plugin-react")).default()],
    server: { middlewareMode: true, hmr: false },
    appType: "custom", logLevel: "silent",
  });
  try {
    const { DeployEvidenceExplanation } = await server.ssrLoadModule("/src/pages/CloudSecurity.jsx");
    return renderToStaticMarkup(
      React.createElement(DeployEvidenceExplanation, { decision }),
    );
  } finally {
    await server.close();
  }
}

test("CL-04: failed integrity/provenance gates are individually visible to operators", async () => {
  const html = await renderProvenance({
    classification: "EVIDENCE_INCOMPLETE",
    failed_checks: [
      "signed_revision_verified", "identity_policy_read_complete",
    ],
  });
  assert.match(html, /The published signed revision could not be verified/);
  assert.match(html, /Identity policies were not read completely/);
  assert.match(html, /signed_revision_verified/);
  assert.match(html, /identity_policy_read_complete/);
  assert.match(html, /Governance is advisory/);
  assert.doesNotMatch(html, /AWS access authorized/);
});

test("CL-04: missing and unrecognized proof cannot be represented as a verified clean audit", async () => {
  const html = await renderProvenance({
    classification: "EVIDENCE_INCOMPLETE",
    failed_checks: ["EVIDENCE_SCHEMA_UNRECOGNIZED"],
  });
  assert.match(html, /The evidence schema is not recognized/);
  assert.doesNotMatch(html, /No per-check evidence was preserved/);
});

if (process.env.LOT10_REAL_OPA_DECISION_FILE) {
  test("CL-04: actual OPA EVIDENCE_INCOMPLETE response reaches Cloud Security UI verbatim", async () => {
    const payload = JSON.parse(await readFile(process.env.LOT10_REAL_OPA_DECISION_FILE, "utf8"));
    assert.equal(payload.classification, "EVIDENCE_INCOMPLETE");
    assert.ok(payload.failed_checks.includes("signed_revision_verified"));
    assert.ok(payload.failed_checks.includes("identity_policy_read_complete"));
    assert.equal(payload.runtime_enforcement, false);
    assert.equal(payload.effective_aws_authorization_proven, false);
    const html = await renderProvenance(payload);
    assert.match(html, /The published signed revision could not be verified/);
    assert.match(html, /Identity policies were not read completely/);
    assert.match(html, /Governance is advisory/);
  });
}
