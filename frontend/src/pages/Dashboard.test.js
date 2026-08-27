import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

const source = readFileSync(new URL("./Dashboard.jsx", import.meta.url), "utf-8");

test("dashboard counts framework and admin approved tools with a filter callback", () => {
  assert.match(
    source,
    /tools\.filter\(\s*\(tool\) =>\s*\["APPROVED", "ADMIN_ALLOWED"\]\.includes\(tool\.analysis_status\)/,
  );
});
