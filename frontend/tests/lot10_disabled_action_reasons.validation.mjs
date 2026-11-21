import assert from "node:assert/strict";
import test from "node:test";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

const ROOT = new URL("../src/", import.meta.url);

test("AUTH-03: privileged disabled actions never rely solely on hover tooltips", () => {
  const paths = [
    "pages/ToolAnalysis.jsx",
    "pages/SecurityConfiguration.jsx",
    "pages/Users.jsx",
    "components/SecurityPackManager.jsx",
    "components/ToolContractOnboarding.jsx",
  ];
  for (const filename of paths) {
    const code = readFileSync(fileURLToPath(new URL(filename, ROOT)), "utf8");
    // Restrict assertions to button opening elements; an unrelated metadata
    // title attribute is not an inaccessible disabled-action explanation.
    const openingButtons = [...code.matchAll(/<button\b[^>]*>/gs)].map((x) => x[0]);
    for (const button of openingButtons) {
      if (button.includes("disabled=")) {
        assert.doesNotMatch(button, /\btitle=/,
          filename + ": a disabled button must not hide its reason in title=");
      }
    }
  }
  const review = readFileSync(fileURLToPath(new URL("pages/ToolAnalysis.jsx", ROOT)), "utf8");
  const config = readFileSync(fileURLToPath(new URL("pages/SecurityConfiguration.jsx", ROOT)), "utf8");
  const users = readFileSync(fileURLToPath(new URL("pages/Users.jsx", ROOT)), "utf8");
  const packs = readFileSync(fileURLToPath(new URL("components/SecurityPackManager.jsx", ROOT)), "utf8");
  const contracts = readFileSync(fileURLToPath(new URL("components/ToolContractOnboarding.jsx", ROOT)), "utf8");
  assert.match(review, /Approval unavailable:/);
  assert.match(review, /Block action unavailable:/);
  assert.match(config, /id="revision-action-prerequisites"/);
  assert.match(config, /id="publish-unavailable-reason"/);
  assert.match(users, /"last-admin-reason-" \+ user.id/);
  assert.match(packs, /id="security-pack-install-reason"/);
  assert.match(contracts, /id="contract-publication-prerequisites"/);
});