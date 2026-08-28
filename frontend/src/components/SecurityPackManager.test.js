import assert from "node:assert/strict";
import test from "node:test";
import { readFileSync } from "node:fs";

import { capabilityDomain, capabilityVerb, commaValues } from "./securityPackUtils.js";

const managerSource = readFileSync(new URL("./SecurityPackManager.jsx", import.meta.url), "utf-8");
const apiSource = readFileSync(new URL("../api/client.js", import.meta.url), "utf-8");

test("declarative pack fields normalize identifiers and comma values", () => {
  assert.equal(capabilityDomain("ticket.comment.write"), "ticket.comment");
  assert.equal(capabilityVerb("ticket.comment.write"), "write");
  assert.deepEqual(commaValues(" Ticket, issue,  read "), ["ticket", "issue", "read"]);
});

test("Lot 4 lifecycle UI exposes package validation and governed actions", () => {
  assert.match(managerSource, /Security Pack Lifecycle/);
  assert.match(managerSource, /Validate Package/);
  assert.match(managerSource, /Install Package/);
  assert.match(managerSource, /Enable after install/);
  assert.match(managerSource, /Rollback/);
  assert.match(managerSource, /Deprecate Version/);
  assert.match(managerSource, /Disable/);
  assert.match(managerSource, /Remove/);
  assert.match(managerSource, /Ed25519 verified/);
  assert.match(managerSource, /Quick Declarative Pack \(Lot 3 compatible\)/);
  assert.doesNotMatch(managerSource, /eval\(/);
  assert.doesNotMatch(managerSource, /new Function/);
});

test("Lot 4 lifecycle API uses protected control-plane endpoints", () => {
  for (const fragment of [
    "/control-plane/security-packs/lifecycle",
    "/control-plane/security-packs/lifecycle/validate",
    "/control-plane/security-packs/lifecycle/install",
    "/activate-version",
    "/deprecate-version",
  ]) {
    assert.match(apiSource, new RegExp(fragment.replaceAll("/", "\\/")));
  }
  assert.match(apiSource, /method: "DELETE"/);
  assert.match(apiSource, /encodeURIComponent\(packId\)/);
});

test("Lot 5 exposes the trusted adapter SDK without executable package imports", () => {
  assert.match(managerSource, /Trusted Adapter SDK/);
  assert.match(managerSource, /Trusted adapters:/);
  assert.match(managerSource, /Imported JSON packs cannot execute code/);
  assert.match(apiSource, /\/control-plane\/security-packs\/adapters/);
  assert.doesNotMatch(managerSource, /import\s*\(/);
  assert.doesNotMatch(managerSource, /new Function/);
});
