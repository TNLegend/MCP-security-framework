import assert from "node:assert/strict";
import test from "node:test";
import {
  ApiError, apiErrorFromResponse, safeErrorMessage, formatApiErrorDetail,
} from "../src/api/client.js";

test("XC-02: known API errors have readable, actionable and non-secret messages", () => {
  const codes = {
    upstream_oauth_dynamic_registration_unsupported: /client ID/i,
    upstream_oauth_authorization_denied: /denied/i,
    upstream_oauth_state_invalid: /original request/i,
    upstream_oauth_state_expired: /expired/i,
    upstream_oauth_token_exchange_failed: /provider connection/i,
    oauth_callback_failed: /callback/i,
    invalid_runtime_log_cursor: /log page/i,
    invalid_csrf_token: /Reload/i,
    controlled_ai_unavailable: /AI assistance/i,
    security_pack_ai_unavailable: /AI assistance/i,
    request_timeout: /timed out/i,
    network_error: /server connection/i,
  };
  for (const [code, expected] of Object.entries(codes)) {
    assert.match(safeErrorMessage(new ApiError(code, { code, status: 400 })), expected, code);
    assert.doesNotMatch(safeErrorMessage(new ApiError(code, { code, status: 400 })), /Traceback|C:\\Users/i);
  }
});

test("XC-02: all error status classes have safe fallback without leaking untrusted backend detail", () => {
  const leak = "secret_token=do-not-display C:\\private\\config.env";
  for (const [status, detail] of [
    [400, "UNKNOWN_MACHINE_ERROR"],
    [401, "Not authenticated"],
    [403, "access_denied"],
    [404, "unknown_record"],
    [409, "changed_approval"],
    [422, { detail: "UNRECOGNIZED_CODE", message: leak }],
    [429, "rate_limit_exceeded"],
    [500, leak],
    [503, "provider returned API key literal: " + leak],
  ]) {
    const err = apiErrorFromResponse(status, { detail });
    const display = safeErrorMessage(err);
    assert.ok(display.length > 20, display);
    assert.doesNotMatch(display, /secret_token|do-not-display|private\\config|provider returned API key/i);
  }
  assert.match(safeErrorMessage(new ApiError("Something failed", {
    code: "SQLITE_CORRUPTED_TABLE", status: 409,
  })), /SQLITE_CORRUPTED_TABLE/);
});

test("XC-02: validation fields remain actionable but no arbitrary nested object is printed", () => {
  const err = apiErrorFromResponse(422, { detail: [
    { loc: ["body", "profile_name"], type: "string_too_long", msg: "Too long." },
    { loc: ["query", "page"], type: "greater_than", msg: "Must be positive." },
  ]});
  assert.equal(err.code, "validation_error");
  assert.match(safeErrorMessage(err), /Profile name: Too long/);
  assert.match(safeErrorMessage(err), /Page: Must be positive/);
  assert.deepEqual(formatApiErrorDetail({ detail: { code: { payload: "secret" } } }).fieldErrors, []);
  assert.doesNotMatch(safeErrorMessage(apiErrorFromResponse(502,
    { detail: { code: "upstream_failure", message: "File /private/secret here" } })),
    /\/private\/secret/);
});
