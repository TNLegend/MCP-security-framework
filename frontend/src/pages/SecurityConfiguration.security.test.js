import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

const source = readFileSync(new URL("./SecurityConfiguration.jsx", import.meta.url), "utf-8");

test("configuration save parses JSON before issuing a patch request", () => {
  assert.match(source, /parseJsonContent\(contentText\)/);
  assert.match(source, /nextErrors\.content = parsed\.error/);
});

test("validate and publish are disabled while displayed content is unsaved", () => {
  assert.match(source, /Save draft changes before validating or publishing/);
  assert.match(source, /contentText !== loadedContentText/);
});

test("configuration mutations are guarded by busy state and summary validation", () => {
  assert.match(source, /validateChangeSummary\(summary\)/);
  assert.match(source, /busy/);
});

test("configuration field errors clear when edited", () => {
  assert.match(source, /clearFieldError/);
  assert.match(source, /updateContent/);
  assert.match(source, /updateSummary/);
});

test("configuration actions select the newly returned revision", () => {
  assert.match(source, /let updatedRevision = null/);
  assert.match(source, /setSelectedRevisionId\(updatedRevision\.id\)/);
});

test("configuration uses sectioned structured editors with an advanced raw fallback", () => {
  assert.match(source, /ConfigurationEditor/);
  assert.match(source, /updateStructuredContent/);
  assert.match(source, /contentObject/);
});
