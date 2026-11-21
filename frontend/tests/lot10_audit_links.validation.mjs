import assert from "node:assert/strict";
import test from "node:test";

import {
  auditOperationLink, normalizeOperationId, operationFromQuery,
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