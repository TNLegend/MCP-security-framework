import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

const source = readFileSync(new URL("./App.jsx", import.meta.url), "utf-8");

test("global Control Center loading uses independent settled requests", () => {
  assert.match(source, /Promise\.allSettled/);
  assert.match(source, /Some Control Center data could not be refreshed/);
});

test("global refresh ignores stale overlapping responses", () => {
  assert.match(source, /loadDataGeneration/);
  assert.match(source, /generation !== loadDataGeneration\.current/);
  assert.match(source, /disabled=\{loading\}/);
});

test("global refresh synchronizes the current session role before role-specific loads", () => {
  const loadDataBody =
    source.match(/async function loadData[\s\S]*?useEffect\(\(\) => \{/)?.[0] || "";
  assert.match(loadDataBody, /refreshedUser = await fetchControlPlaneMe\(\)/);
  assert.match(loadDataBody, /sameControlPlaneUser\(previous, refreshedUser\)/);
  assert.match(loadDataBody, /const refreshedIsAdmin = refreshedUser\?\.role === "ADMIN"/);
  assert.match(loadDataBody, /if \(refreshedIsAdmin\) \{\s*requests\.users = \["Users", fetchUsers, setUsers\]/);
  assert.doesNotMatch(loadDataBody, /if \(isAdmin\) \{\s*requests\.users/);
});

test("role refresh avoids object identity effect loops and clears stale admin-only data", () => {
  assert.match(source, /\}, \[user\?\.id\]\)/);
  assert.match(source, /sameControlPlaneUser/);
  assert.match(source, /setUsers\(\[\]\)/);
});

test("login does not directly duplicate the user-effect data load", () => {
  const handleLoginBody = source.match(/async function handleLogin[\s\S]*?async function handleLogout/)?.[0] || "";
  assert.doesNotMatch(handleLoginBody, /loadData\(/);
});

test("a first visit without a session does not call the authenticated profile endpoint", () => {
  const restoreSessionBody =
    source.match(/async function restoreSession[\s\S]*?async function handleLogin/)?.[0] || "";
  assert.match(restoreSessionBody, /if \(!hasControlPlaneSession\(\)\)/);
  assert.match(restoreSessionBody, /setAuthLoading\(false\);/);
});

test("login form validates backend limits and prevents duplicate submits", () => {
  assert.match(source, /validateLogin/);
  assert.match(source, /maxLength=\{LIMITS\.usernameMax\}/);
  assert.match(source, /maxLength=\{LIMITS\.passwordMax\}/);
  assert.match(source, /disabled=\{busy\}/);
});
