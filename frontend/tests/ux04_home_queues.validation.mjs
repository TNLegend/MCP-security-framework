import assert from "node:assert/strict";
import test from "node:test";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import {
  REVIEW_QUEUE_STATES, normalizeOutcomeState, normalizeToolQueue, toolInQueue,
} from "../src/utils/toolQueues.js";

const read = (path) => readFileSync(fileURLToPath(new URL(path, import.meta.url)), "utf8");
const TOOLS = ["REVIEW_REQUIRED", "PENDING_ANALYSIS", "QUARANTINED", "ANALYSIS_FAILED", "STALE",
  "BLOCKED", "APPROVED", "ADMIN_ALLOWED", "UNKNOWN_FUTURE"].map((analysis_status, id) => ({ id, analysis_status }));

test("UX-04: Home and Security review share one queue definition (STALE included)", () => {
  assert.deepEqual(TOOLS.filter((t) => toolInQueue(t, "REVIEW")).map((t) => t.analysis_status), REVIEW_QUEUE_STATES);
  assert.deepEqual(TOOLS.filter((t) => toolInQueue(t, "BLOCKED")).map((t) => t.analysis_status), ["BLOCKED"]);
  assert.equal(TOOLS.filter((t) => toolInQueue(t, "nonsense")).length, TOOLS.length);
  assert.equal(normalizeToolQueue("blocked"), "BLOCKED");
  assert.equal(normalizeOutcomeState("sent_uncertain"), "sent_uncertain");
  assert.equal(normalizeOutcomeState("executed"), null);
  const home = read("../src/pages/Dashboard.jsx");
  const review = read("../src/pages/ToolAnalysis.jsx");
  assert.match(home, /toolInQueue\(tool, "REVIEW"\)/);
  assert.match(review, /toolInQueue\(tool, toolStateFilter\)/);
});

test("UX-04: each priority action lands on its exact filtered destination", () => {
  const home = read("../src/pages/Dashboard.jsx");
  assert.match(home, /onNavigate\("analysis", null, \{ queue: "REVIEW" \}\)/);
  assert.match(home, /onNavigate\("analysis", null, \{ queue: "BLOCKED" \}\)/);
  assert.match(home, /onNavigate\("runtime", null, \{ outcome: "sent_uncertain" \}\)/);
  const app = read("../src/App.jsx");
  assert.match(app, /url\.searchParams\.set\("queue", options\.queue\)/);
  assert.match(app, /url\.searchParams\.set\("outcome", options\.outcome\)/);
});
