import assert from "node:assert/strict";
import test from "node:test";
import { readFileSync } from "node:fs";


const source = readFileSync(new URL("./Audit.jsx", import.meta.url), "utf-8");


test("audit events expose lifecycle evidence details", () => {
  assert.match(source, /Audit event detail/);
  assert.match(source, /selectedEvent\.before_json/);
  assert.match(source, /selectedEvent\.after_json/);
  assert.match(source, /selectedEvent\.metadata/);
  assert.match(source, /selectedEvent\.revision_id/);
});
