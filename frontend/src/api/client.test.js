import assert from "node:assert/strict";
import test from "node:test";

import {
  ApiError,
  addDeclarativeSecurityPack,
  apiErrorFromResponse,
  buildDiscoveryRequestBody,
  archiveServer,
  trustServer,
  revokeServerTrust,
  discoverRegisteredMcpServer,
  discoverHttpMcpServer,
  fetchRuntimeLogs,
  fetchSecurityPacks,
  createToolContractDraft,
  createToolSecurityPackDraft,
  fetchAIToolSecurityPackDraft,
  fetchToolTemplateSuggestions,
  formatApiErrorDetail,
  hasControlPlaneSession,
  registerOAuthMcpServer,
  reanalyzeToolContract,
  safeErrorMessage,
  settleNamedRequests,
  startOAuthConnection,
} from "./client.js";

test("formats FastAPI string detail", () => {
  const error = apiErrorFromResponse(400, { detail: "user_already_exists" });
  assert.equal(error.status, 400);
  assert.match(error.message, /user_already_exists/);
});

test("formats FastAPI validation arrays without leaking input", () => {
  const formatted = formatApiErrorDetail([
    {
      loc: ["body", "password"],
      msg: "String should have at least 8 characters",
      type: "string_too_short",
      input: "super-secret-password",
    },
  ]);

  assert.equal(formatted.code, "validation_error");
  assert.match(formatted.message, /Password: String should have at least 8 characters/);
  assert.doesNotMatch(formatted.message, /\[object Object\]/);
  assert.doesNotMatch(formatted.message, /super-secret-password/);
  assert.doesNotMatch(JSON.stringify(formatted.fieldErrors), /super-secret-password/);
});

test("formats detail objects and plain text safely", () => {
  assert.match(formatApiErrorDetail({ code: "bad_request" }).message, /bad_request/);
  assert.match(formatApiErrorDetail("plain failure").message, /plain failure/);
  assert.match(
    formatApiErrorDetail("upstream_oauth_dynamic_registration_unsupported").message,
    /does not support automatic OAuth registration/,
  );
});

test("never stringifies nested error objects for users", () => {
  const nestedError = formatApiErrorDetail({ error: { code: "nested" } });
  assert.equal(nestedError.message, "Request failed.");
  assert.doesNotMatch(nestedError.message, /\[object Object\]/);

  const secretDetail = formatApiErrorDetail({ detail: { secret: "abc" } });
  assert.equal(secretDetail.message, "Request failed.");
  assert.doesNotMatch(secretDetail.message, /abc/);
  assert.doesNotMatch(secretDetail.message, /\[object Object\]/);

  const validation = formatApiErrorDetail([
    {
      loc: ["body", "payload"],
      msg: { error: "nested" },
      type: "value_error",
      input: { secret: "hidden" },
    },
  ]);
  assert.doesNotMatch(validation.message, /hidden/);
  assert.doesNotMatch(validation.message, /\[object Object\]/);
});

test("formats network failures safely", () => {
  const error = new ApiError("Network request failed.", { code: "network_error" });
  assert.equal(safeErrorMessage(error), "Network request failed.");
});

test("detects whether a browser session can be restored", () => {
  const previousDocument = globalThis.document;
  globalThis.document = { cookie: "theme=dark; mcp_control_plane_csrf=csrf-token" };
  assert.equal(hasControlPlaneSession(), true);

  globalThis.document = { cookie: "theme=dark" };
  assert.equal(hasControlPlaneSession(), false);

  globalThis.document = previousDocument;
});

test("settled named requests preserves successes and section errors", async () => {
  const bundle = await settleNamedRequests({
    status: async () => ({ ok: true }),
    findings: async () => {
      throw new ApiError("Backend request failed: 500: findings_failed", {
        status: 500,
      });
    },
  });

  assert.deepEqual(bundle.status, { ok: true });
  assert.match(bundle.errors.findings, /findings_failed/);
});

test("builds exact discovery request bodies", () => {
  assert.deepEqual(
    buildDiscoveryRequestBody("http://127.0.0.1:9000/mcp"),
    {
      endpoint: "http://127.0.0.1:9000/mcp",
      protocol_version: "2025-11-25",
      auth_mode: "NONE",
      credential_ref: null,
    },
  );

  assert.deepEqual(
    buildDiscoveryRequestBody(
      "https://vendor.example/mcp",
      "2025-11-25",
      "BEARER",
      "mcp/vendor/service.token",
    ),
    {
      endpoint: "https://vendor.example/mcp",
      protocol_version: "2025-11-25",
      auth_mode: "BEARER",
      credential_ref: "mcp/vendor/service.token",
    },
  );
});

test("discoverHttpMcpServer sends exact HTTP payload without argument shift", async () => {
  const noneRequest = await captureRequest(() =>
    discoverHttpMcpServer("http://127.0.0.1:9000/mcp"),
  );
  assert.match(noneRequest.url, /\/inventory\/discover-http$/);
  assert.equal(noneRequest.options.method, "POST");
  assert.deepEqual(noneRequest.body, {
    endpoint: "http://127.0.0.1:9000/mcp",
    protocol_version: "2025-11-25",
    auth_mode: "NONE",
    credential_ref: null,
  });
  assert.deepEqual(Object.keys(noneRequest.body).sort(), [
    "auth_mode",
    "credential_ref",
    "endpoint",
    "protocol_version",
  ]);

  const bearerRequest = await captureRequest(() =>
    discoverHttpMcpServer(
      "https://vendor.example/mcp",
      "2025-11-25",
      "BEARER",
      "mcp/vendor/service.token",
    ),
  );
  assert.deepEqual(bearerRequest.body, {
    endpoint: "https://vendor.example/mcp",
    protocol_version: "2025-11-25",
    auth_mode: "BEARER",
    credential_ref: "mcp/vendor/service.token",
  });
});

test("runtime logs encode server-side filters and cursor", async () => {
  const captured = await captureRequest(() => fetchRuntimeLogs({
    limit: 50,
    cursor: "cursor-value",
    decision: "BLOCK",
    tool_name: "read file",
  }));
  const url = new URL(captured.url);
  assert.equal(url.pathname.endsWith("/runtime/logs"), true);
  assert.equal(url.searchParams.get("limit"), "50");
  assert.equal(url.searchParams.get("cursor"), "cursor-value");
  assert.equal(url.searchParams.get("decision"), "BLOCK");
  assert.equal(url.searchParams.get("tool_name"), "read file");
});

test("archive server sends the administrative reason", async () => {
  const captured = await captureRequest(() => archiveServer(17, "Retired integration"));
  assert.match(captured.url, /\/servers\/17\/archive$/);
  assert.equal(captured.options.method, "POST");
  assert.deepEqual(captured.body, { reason: "Retired integration" });
});

test("server trust lifecycle sends protected administrative reasons", async () => {
  const trusted = await captureRequest(() => trustServer(17, "Reviewed server ownership"));
  assert.match(trusted.url, /\/servers\/17\/trust$/);
  assert.equal(trusted.options.method, "POST");
  assert.deepEqual(trusted.body, { reason: "Reviewed server ownership" });

  const revoked = await captureRequest(() => revokeServerTrust(17, "Trust review expired"));
  assert.match(revoked.url, /\/servers\/17\/revoke-trust$/);
  assert.equal(revoked.options.method, "POST");
  assert.deepEqual(revoked.body, { reason: "Trust review expired" });
});

test("OAuth control-plane calls use protected API endpoints and JSON bodies", async () => {
  const registration = await captureRequest(() => registerOAuthMcpServer({
    endpoint: "https://vendor.example/mcp",
    client_id: "framework-client",
    client_secret: "not-in-url",
  }));
  assert.match(registration.url, /\/control-plane\/upstream-oauth\/servers$/);
  assert.equal(registration.options.method, "POST");
  assert.equal(registration.body.client_secret, "not-in-url");
  assert.doesNotMatch(registration.url, /not-in-url/);

  const connect = await captureRequest(() => startOAuthConnection(42));
  assert.match(connect.url, /\/upstream-oauth\/servers\/42\/connect$/);
  assert.equal(connect.options.method, "POST");

  const rediscovery = await captureRequest(() => discoverRegisteredMcpServer(42));
  assert.match(rediscovery.url, /\/inventory\/servers\/42\/discover$/);
  assert.equal(rediscovery.options.method, "POST");
});

test("Security Pack onboarding uses protected generic endpoints", async () => {
  const catalog = await captureRequest(() => fetchSecurityPacks());
  assert.match(catalog.url, /\/control-plane\/security-packs$/);

  const payload = {
    template_id: "messaging.send",
    argument_mappings: { resource: ["recipient"] },
    fixed_resources: {},
    scopes: [],
    approve_observations: false,
    change_summary: "Add messaging contract",
  };
  const draft = await captureRequest(() => createToolContractDraft(12, payload));
  assert.match(draft.url, /\/security-packs\/tools\/12\/contracts\/draft$/);
  assert.equal(draft.options.method, "POST");
  assert.deepEqual(draft.body, payload);

  const packPayload = {
    draft_revision_id: "draft-1",
    change_summary: "Add ticket pack",
    manifest: { id: "ticketing" },
  };
  const pack = await captureRequest(() => addDeclarativeSecurityPack(packPayload));
  assert.match(pack.url, /\/control-plane\/security-packs\/declarative$/);
  assert.equal(pack.options.method, "POST");
  assert.deepEqual(pack.body, packPayload);

  const draftCatalog = await captureRequest(() => fetchSecurityPacks("draft-1"));
  assert.match(draftCatalog.url, /security-packs\?draft_revision_id=draft-1$/);

  const suggestions = await captureRequest(() => fetchToolTemplateSuggestions(12, "draft-1"));
  assert.match(suggestions.url, /tools\/12\/suggestions\?draft_revision_id=draft-1$/);

  const aiPack = await captureRequest(() => fetchAIToolSecurityPackDraft(12, "draft-1"));
  assert.match(aiPack.url, /tools\/12\/ai-pack-draft\?draft_revision_id=draft-1$/);
  assert.equal(aiPack.options.method, "POST");

  const toolPack = await captureRequest(() => createToolSecurityPackDraft(12, packPayload));
  assert.match(toolPack.url, /tools\/12\/packs\/draft$/);
  assert.equal(toolPack.options.method, "POST");

  const reanalysis = await captureRequest(() => reanalyzeToolContract(12));
  assert.match(reanalysis.url, /tools\/12\/reanalyze$/);
  assert.equal(reanalysis.options.method, "POST");
});

async function captureRequest(operation) {
  const previousFetch = globalThis.fetch;
  const hadDocument = Object.hasOwn(globalThis, "document");
  const previousDocument = globalThis.document;
  let captured = null;

  globalThis.document = { cookie: "" };
  globalThis.fetch = async (url, options) => {
    captured = {
      url,
      options,
      body: options.body ? JSON.parse(options.body) : null,
    };
    return {
      ok: true,
      status: 200,
      text: async () => JSON.stringify({ ok: true }),
    };
  };

  try {
    await operation();
    return captured;
  } finally {
    globalThis.fetch = previousFetch;
    if (hadDocument) {
      globalThis.document = previousDocument;
    } else {
      delete globalThis.document;
    }
  }
}
