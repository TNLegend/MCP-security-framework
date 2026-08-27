import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

const source = readFileSync(new URL("./ToolSecurityPackBuilder.jsx", import.meta.url), "utf-8");

test("advanced Security Pack mode remains declarative and backend validated", () => {
  assert.match(source, /Advanced JSON/);
  assert.match(source, /Advanced Security Pack manifest/);
  assert.match(source, /JSON\.parse\(advancedManifestText\)/);
  assert.match(source, /Declarative JSON only/);
  assert.match(source, /createToolSecurityPackDraft/);
  assert.doesNotMatch(source, /eval\(/);
  assert.doesNotMatch(source, /new Function/);
});
