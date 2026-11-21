import test from "node:test";
import assert from "node:assert/strict";

import { executionDisplay } from "../src/utils/runtimePresentation.js";
import { validateRecordedPage } from "../src/utils/recordedPage.js";
import { parseServerTime } from "../src/utils/serverTime.js";

test("unknown dispatch evidence takes precedence over the legacy execution boolean", () => {
  const unverified = { executed: false, dispatch_state: "SENT_OUTCOME_UNKNOWN" };
  assert.match(executionDisplay(unverified), /^Unknown/);
  assert.match(executionDisplay({ executed: false, execution_status: "upstream_outcome_unknown" }), /^Unknown/);
  assert.match(executionDisplay({ executed: false }), /^Not established/);
  assert.match(executionDisplay({ executed: false, dispatch_state: "NOT_SENT" }), /^Not sent/);
  assert.match(executionDisplay({ executed: false, dispatch_state: "PENDING" }), /^Pending/);
  assert.match(executionDisplay({ executed: true, execution_status: "result_blocked" }), /response withheld/);
});

test("IAM and Cloud pages must follow the previous records without overlap", () => {
  const previous = [{ id: 10 }];
  const page = {
    items: [{ id: 11 }], total: 3, offset: 1, returned: 1, has_more: true, collection: "findings",
  };
  assert.doesNotThrow(() => validateRecordedPage(page, previous, "findings"));
  assert.throws(() => validateRecordedPage(page, previous, "resources"));
  assert.throws(() => validateRecordedPage({ ...page, items: [{ id: 10 }] }, previous));
  assert.throws(() => validateRecordedPage({ ...page, offset: 2 }, previous));
  assert.throws(() => validateRecordedPage({ ...page, has_more: false }, previous));
  assert.throws(() => validateRecordedPage({ ...page, items: [], returned: 0 }, previous));
});

test("legacy stored dates sort in UTC alongside timestamps with explicit offsets", () => {
  const legacy = parseServerTime("2026-03-29 02:30:00");
  const explicit = parseServerTime("2026-03-29T03:00:00+02:00");
  assert.equal(legacy.toISOString(), "2026-03-29T02:30:00.000Z");
  assert.ok(legacy.getTime() > explicit.getTime());
});
