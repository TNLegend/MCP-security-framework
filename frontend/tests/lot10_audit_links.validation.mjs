import assert from "node:assert/strict";
import test from "node:test";

import {
  auditOperationLink, auditTargetLink, normalizeOperationId, operationFromQuery, recordTypeForView,
} from "../src/utils/operationNavigation.js";

const ID = "12345678-1234-4321-89ab-0123456789ab";

test("AUD-01/OP-01: exact-ID audit links open only read-only operation investigations", () => {
  assert.equal(normalizeOperationId(ID.toUpperCase()), ID);
  assert.equal(auditOperationLink("runtime_operation", ID),
    "?view=operations&operation_id=" + ID);
  assert.equal(operationFromQuery("?view=operations&operation_id=" + ID), ID);
  assert.equal(operationFromQuery("?view=operations&operation_id=" + ID.toUpperCase()), ID);

  for (const [kind, value] of [
    ["runtime_logs", ID],
    ["cloud_scan", ID],
    ["runtime_operation", "../../admin"],
    ["runtime_operation", "123"],
    ["runtime_operation", "12345678-1234-4321-89ab-0123456789ab%0a"],
    ["runtime_operation", "https://evil.invalid"],
  ]) {
    assert.equal(auditOperationLink(kind, value), null);
  }
  assert.equal(operationFromQuery("?view=audit&operation_id=" + ID), null);
  assert.equal(operationFromQuery("?view=operations&operation_id=invalid"), null);
  assert.equal(operationFromQuery("?view=operations"), null);
  assert.equal(operationFromQuery(""), null);
});


test("UX-12: exact typed IDs become deep links without title or latest fallback", () => {
  assert.equal(auditTargetLink("mcp_tool", 42), "?view=analysis&tool=42");
  assert.equal(auditTargetLink("mcp_tool", "42"), "?view=analysis&tool=42");
  assert.equal(auditTargetLink("runtime_operation", ID),
    "?view=operations&operation_id=" + ID);
  for (const [type, id] of [
    ["mcp_tool", 0], ["mcp_tool", "-1"], ["mcp_tool", "0042"],
    ["mcp_tool", "42?view=users"], ["mcp_tool", "../../users"],
    ["mcp_tool", "999999999999999999"], ["mcp_tool", null],
    ["mcp_server", "0042"], ["cloud_scan", "scan-name"],
    ["tool_protocol_observation", "0042"], ["tool_protocol_observation", ID],
    ["tool_protocol_observation", "2147483648"],
    ["control_plane_config_revision", "latest"], ["runtime_logs", ID],
  ]) {
    assert.equal(auditTargetLink(type, id), null, type + " should not imply an exact verified link");
  }
});

test("record links address the resolved type and primary key", () => {
  assert.equal(auditTargetLink("mcp_server", 42), "?view=inventory&record=42");
  assert.equal(auditTargetLink("tool_protocol_observation", 42), "?view=analysis&record=42");
  assert.equal(recordTypeForView("analysis"), "tool_protocol_observation");
  assert.equal(auditTargetLink("cloud_scan", ID), "?view=cloud&scan=" + ID);
  assert.equal(auditTargetLink("control_plane_config_revision", ID), "?view=config&record=" + ID);
  assert.equal(auditTargetLink("emergency_deny", ID), "?view=emergency&record=" + ID);
  assert.equal(auditTargetLink("control_plane_user", ID), "?view=users&record=" + ID);
});
