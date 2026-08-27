import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

const source = readFileSync(new URL("./ToolContractOnboarding.jsx", import.meta.url), "utf-8");

test("no-match onboarding does not silently select an unrelated template", () => {
  assert.match(source, /No compatible template/);
  assert.match(source, /Create Security Pack/);
  assert.doesNotMatch(source, /fallbackTemplate/);
  assert.match(source, /setTemplateId\(first\?\.template_id \|\| ""\)/);
});

test("tool onboarding keeps pack contract publication and reanalysis in one flow", () => {
  assert.match(source, /ToolSecurityPackBuilder/);
  assert.match(source, /draft_revision_id: draftRevisionId/);
  assert.match(source, /publishConfigRevision/);
  assert.match(source, /reanalyzeToolContract/);
  assert.match(source, /Publish & reanalyse/);
});

test("advanced onboarding exposes effects constraints roles and typed scopes", () => {
  assert.match(source, /templateEffects\(selectedTemplate\)/);
  assert.match(source, /selectedConstraints/);
  assert.match(source, /binding\.role \|\| "RESOURCE"/);
  assert.match(source, /resource_type: resourceType/);
  assert.match(source, /Authorized scope \(\{resourceType\}\)/);
  assert.match(source, /resultControlLabel/);
});
