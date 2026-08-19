import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";


const source = readFileSync(new URL("./Users.jsx", import.meta.url), "utf-8");


test("password reset never uses a visible browser prompt", () => {
  assert.doesNotMatch(source, /window\.prompt\([^)]*[Pp]assword/);
  assert.match(source, /type="password"/);
  assert.match(source, /setResetForm\(\{ password: "", confirmation: "", reason: "" \}\)/);
});

test("role escalation requires explicit confirmation", () => {
  assert.match(source, /role === "ADMIN"/);
  assert.match(source, /window\.confirm/);
});
