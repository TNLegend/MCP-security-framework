import assert from "node:assert/strict";
import test from "node:test";

import { capabilityDomain, capabilityVerb, commaValues } from "./securityPackUtils.js";

test("declarative pack fields normalize identifiers and comma values", () => {
  assert.equal(capabilityDomain("ticket.comment.write"), "ticket.comment");
  assert.equal(capabilityVerb("ticket.comment.write"), "write");
  assert.deepEqual(commaValues(" Ticket, issue,  read "), ["ticket", "issue", "read"]);
});
