import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

const source = readFileSync(new URL("./RuntimeLogs.jsx", import.meta.url), "utf-8");

test("runtime logs use backend filters cursor pagination and aggregate summaries", () => {
  assert.match(source, /fetchRuntimeLogs\(\{ \.\.\.filters, limit: PAGE_SIZE, cursor \}\)/);
  assert.match(source, /next_cursor/);
  assert.match(source, /cursorStack/);
  assert.match(source, /page\.summary\.blocked/);
  assert.match(source, /protocol_profile_id/);
});
