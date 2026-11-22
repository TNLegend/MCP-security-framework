import assert from "node:assert/strict";
import test from "node:test";
import { assistantErrorMessage } from "../src/utils/controlledAI.js";

test("UX-14: a reply that failed validation is not described as an outage", () => {
  const invalid = assistantErrorMessage({ code: "controlled_ai_response_invalid", status: 502 });
  assert.match(invalid, /no reply passed validation/i);
  assert.match(invalid, /recorded evidence above is unaffected/i);
  assert.doesNotMatch(invalid, /unavailable/i);
});

test("UX-14: missing provider configuration, rate limit, timeout and outage stay distinct", () => {
  const messages = [
    assistantErrorMessage({ code: "controlled_ai_not_configured", status: 503 }),
    assistantErrorMessage({ code: "controlled_ai_rate_limited", status: 429 }),
    assistantErrorMessage({ code: "controlled_ai_timeout", status: 504 }),
    assistantErrorMessage({ code: "controlled_ai_unavailable", status: 503 }),
  ];
  assert.match(messages[0], /not configured/);
  assert.match(messages[1], /request limit/);
  assert.match(messages[2], /timed out/);
  assert.match(messages[3], /unavailable/);
  assert.equal(new Set(messages).size, 4);
  for (const message of messages) {
    assert.doesNotMatch(message, /key|token|Traceback|response body/i);
  }
});
