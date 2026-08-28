import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

const source = readFileSync(new URL("./AdapterGuidancePanel.jsx", import.meta.url), "utf-8");
const apiSource = readFileSync(new URL("../api/client.js", import.meta.url), "utf-8");

test("adapter guidance exposes fail-closed starters without browser code execution", () => {
  assert.match(source, /Adapter compatibility/);
  assert.match(source, /Closest trusted adapters/);
  assert.match(source, /Download Starter/);
  assert.match(source, /reviewed, signed by a trusted maintainer/);
  assert.match(apiSource, /adapters\/starters/);
  assert.match(apiSource, /requestBlob/);
  assert.doesNotMatch(source, /eval\(/);
  assert.doesNotMatch(source, /new Function/);
});
