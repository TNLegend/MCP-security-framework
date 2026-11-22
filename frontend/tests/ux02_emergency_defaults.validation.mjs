import assert from "node:assert/strict";
import test from "node:test";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import {
  EMERGENCY_BLAST_RADIUS,
  describeEmergencyDuration,
  describeEmergencyExpiry,
  emergencyDenyPayload,
  emptyEmergencyDenyForm,
  validateEmergencyDeny,
} from "../src/utils/validation.js";

const NOW = new Date("2026-11-22T10:00:00Z");
const page = readFileSync(fileURLToPath(new URL("../src/pages/EmergencyDeny.jsx", import.meta.url)), "utf8");

test("UX-02: an untouched emergency form names no scope and no reason, and cannot produce a payload", () => {
  const form = emptyEmergencyDenyForm(NOW);
  assert.equal(form.target_type, "");
  assert.equal(form.reason, "");
  assert.equal(form.global_acknowledged, false);
  const errors = validateEmergencyDeny(form, NOW);
  assert.equal(errors.target_type, "Choose a restriction scope.");
  assert.ok(errors.reason, "a blank incident reason must be rejected");
  assert.ok(emergencyDenyPayload(form, NOW).errors, "untouched form must not yield a payload");
  assert.doesNotMatch(page, /reason:\s*"Emergency deny from Control Center"/);
  assert.doesNotMatch(page, /target_type:\s*"global"/);
});

test("UX-02: global scope requires deliberate selection plus an explicit acknowledgement", () => {
  const base = { ...emptyEmergencyDenyForm(NOW), target_type: "global", reason: "Incident 42 exfil attempt" };
  assert.match(validateEmergencyDeny(base, NOW).global_acknowledged, /every governed MCP call/);
  const acknowledged = { ...base, global_acknowledged: true };
  assert.deepEqual(validateEmergencyDeny(acknowledged, NOW), {});
  const { payload } = emergencyDenyPayload(acknowledged, NOW);
  assert.equal(payload.target_type, "global");
  assert.equal(payload.target_value, null);
  assert.equal("global_acknowledged" in payload, false, "acknowledgement is a UI guard, not API data");
});

test("UX-02: targeted scopes keep exact target identity and never need the global acknowledgement", () => {
  const form = {
    ...emptyEmergencyDenyForm(NOW), target_type: "server_tool",
    target_value: " srv-ref-1 ", target_secondary_value: " delete_file ", reason: "Incident 43 rogue tool",
  };
  assert.deepEqual(validateEmergencyDeny(form, NOW), {});
  const { payload } = emergencyDenyPayload(form, NOW);
  assert.equal(payload.target_value, "srv-ref-1");
  assert.equal(payload.target_secondary_value, "delete_file");
});

test("UX-02: confirmation states time zone, UTC instant, duration and known blast radius", () => {
  const expiry = describeEmergencyExpiry("2026-11-22T11:30:00.000Z", "Europe/Paris");
  assert.equal(expiry.timeZone, "Europe/Paris");
  assert.equal(expiry.utc, "2026-11-22T11:30:00.000Z");
  assert.match(expiry.local, /12:30/);
  assert.equal(describeEmergencyDuration("2026-11-22T11:30:00.000Z", NOW), "1 h 30 min");
  assert.equal(describeEmergencyDuration("2026-11-24T10:05:00.000Z", NOW), "2 days 5 min");
  for (const scope of ["global", "agent_id", "framework_session_id", "server_ref", "server_tool"]) {
    assert.ok(EMERGENCY_BLAST_RADIUS[scope], scope + " needs a stated impact");
  }
  assert.match(page, /Known impact/);
  assert.match(page, /describeEmergencyDuration\(/);
  assert.match(page, /describeEmergencyExpiry\(/);
});

test("UX-02: the confirmation dialog focuses its container, not the destructive button", () => {
  assert.match(page, /useDialogFocus\(Boolean\(pendingCreate \|\| pendingRevoke\), modalRef, \{ focusContainer: true \}\)/);
  assert.match(page, /<option value="">Choose a scope…<\/option>/);
});
