import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";


const source = readFileSync(new URL("./Users.jsx", import.meta.url), "utf-8");


test("password reset never uses a visible browser prompt", () => {
  assert.doesNotMatch(source, /window\.prompt\([^)]*[Pp]assword/);
  assert.match(source, /type="password"/);
  assert.match(source, /setResetForm\(\{ password: "", confirmation: "", reason: "" \}\)/);
});

test("password reset clears attempted secret after backend failure", () => {
  const submitBody =
    source.match(/async function submitPasswordReset[\s\S]*?async function submitReasonAction/)?.[0] ||
    "";
  assert.match(submitBody, /catch \(err\)/);
  assert.match(submitBody, /setResetForm\(\(current\) => \(\{ \.\.\.current, password: "", confirmation: "" \}\)\)/);
});

test("administrative reasons use the modal instead of window.prompt", () => {
  assert.doesNotMatch(source, /window\.prompt/);
  assert.match(source, /actionDialog/);
});

test("user modals close on Escape while no mutation is busy", () => {
  assert.match(source, /window\.addEventListener\("keydown", handleEscape\)/);
  assert.match(source, /event\.key !== "Escape" \|\| busyAction/);
  assert.match(source, /setActionDialog\(null\)/);
  assert.match(source, /setResetTarget\(null\)/);
});

test("user mutations use a synchronous single-flight guard", () => {
  assert.match(source, /useRef/);
  assert.match(source, /mutationLockRef = useRef\(false\)/);
  assert.match(source, /if \(mutationLockRef\.current\)/);
  assert.match(source, /mutationLockRef\.current = true/);
  assert.match(source, /mutationLockRef\.current = false/);
});

test("role escalation requires explicit confirmation", () => {
  assert.match(source, /role === "ADMIN"/);
  assert.match(source, /window\.confirm/);
});
