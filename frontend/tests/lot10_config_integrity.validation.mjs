import assert from "node:assert/strict";
import test from "node:test";
import { displayedConfigIntegrity } from "../src/utils/configIntegrity.js";

const displayed = {
  id: "active-id", revision_number: 80,
  content_hash: "a".repeat(64), status: "PUBLISHED",
};
const verified = {
  status: "VERIFIED", revision_id: displayed.id,
  revision_number: 80, content_hash: displayed.content_hash,
  verification_scope: "backend_published_configuration",
};

test("CFG-02 shows verified only on exact active id/hash/number match", () => {
  assert.equal(displayedConfigIntegrity(displayed, verified).status, "VERIFIED");
  assert.equal(displayedConfigIntegrity(displayed, {...verified, content_hash: "b".repeat(64)}).status, "MISMATCH");
  assert.equal(displayedConfigIntegrity(displayed, {...verified, revision_id: "old"}).status, "MISMATCH");
  assert.equal(displayedConfigIntegrity(displayed, {...verified, revision_number: 79}).status, "MISMATCH");
  assert.equal(displayedConfigIntegrity({...displayed, status: "ARCHIVED"}, verified).status, "MISMATCH");
});
test("CFG-02 treats failed, missing or unverified signatures as not verified", () => {
  assert.equal(displayedConfigIntegrity(displayed, null).status, "NOT_CHECKED");
  assert.equal(displayedConfigIntegrity(null, verified).status, "NO_ACTIVE");
  assert.equal(displayedConfigIntegrity(displayed, {status: "FAILED", error_code: "revision_signature_invalid"}).status, "NOT_VERIFIED");
  assert.equal(displayedConfigIntegrity(displayed, {status: "UNAVAILABLE"}).status, "NOT_VERIFIED");
});
