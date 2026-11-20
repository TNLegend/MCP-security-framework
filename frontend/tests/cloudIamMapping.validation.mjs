import test from "node:test";
import assert from "node:assert/strict";
import {
  manualMappingCoverage, isMappingBoundToCurrentContext, canRequestManualAudit,
} from "../src/pages/cloudIamMapping.js";

const effects = [
  { tool_name: "read", effect_id: "read-1", resource_type: "cloud_object" },
  { tool_name: "write", effect_id: "write-1", resource_type: "cloud_object" },
];
const good = {
  tool_name: "read", effect_id: "read-1", scope_id: "signed",
  action: "s3:GetObject", resource_template: "arn:aws:s3:::bucket/$"+"{scope}",
};
const env = { account_id: "123456789012", status: "CONNECTED" };
const server = { endpoint: "https://example.com/mcp" };
const signed = { signed_revision: 12, signed_content_hash: "a".repeat(64) };
const mapping = {
  status: "APPROVED", signed_revision: 12, signed_content_hash: "a".repeat(64),
  configuration: {
    source_binding: { account_id: env.account_id, server_endpoint: server.endpoint },
  },
};

test("missing signed effects are never silently mapped", () => {
  const result = manualMappingCoverage(effects, [good]);
  assert.equal(result.completeRows.length, 1);
  assert.deepEqual(result.unmapped, [effects[1]]);
});

test("incomplete action or scope cannot cover a signed effect", () => {
  for (const field of ["action", "scope_id", "resource_template"]) {
    const row = { ...good, [field]: "" };
    assert.deepEqual(manualMappingCoverage(effects, [row]).unmapped, effects);
  }
});

test("two signed effects can be covered by independently declared actions", () => {
  const write = { ...good, tool_name: "write", effect_id: "write-1", action: "s3:PutObject" };
  const result = manualMappingCoverage(effects, [good, write]);
  assert.equal(result.unmapped.length, 0);
  assert.equal(result.completeRows.length, 2);
});

test("multiple IAM actions on one effect do not cover another effect", () => {
  assert.deepEqual(manualMappingCoverage(effects, [
    good, { ...good, action: "kms:Decrypt" },
  ]).unmapped, [effects[1]]);
});

test("account change invalidates an approved mapping", () => {
  assert.equal(isMappingBoundToCurrentContext(mapping,
    { ...env, account_id: "999" }, server, signed), false);
});

test("endpoint change invalidates an approved mapping", () => {
  assert.equal(isMappingBoundToCurrentContext(mapping, env,
    { endpoint: "https://changed/mcp" }, signed), false);
});

test("published revision change invalidates an approved mapping", () => {
  assert.equal(isMappingBoundToCurrentContext(mapping, env, server,
    { ...signed, signed_revision: 13 }), false);
});

test("signed content hash change invalidates an approved mapping", () => {
  assert.equal(isMappingBoundToCurrentContext(mapping, env, server,
    { ...signed, signed_content_hash: "b".repeat(64) }), false);
});

test("only approved mapping in connected environment can launch IAM review", () => {
  assert.equal(canRequestManualAudit(mapping, env, server, signed), true);
  assert.equal(canRequestManualAudit({ ...mapping, status: "DRAFT" }, env, server, signed), false);
  assert.equal(canRequestManualAudit(mapping,
    { ...env, status: "UNVERIFIED" }, server, signed), false);
  assert.equal(canRequestManualAudit(null, env, server, signed), false);
});


test("explicit resource-global IAM access is accepted only for unscoped signed effect", () => {
  const identityEffect = { tool_name: "whoami", effect_id: "identity", resource_type: null };
  const global = {
    tool_name: "whoami", effect_id: "identity", action: "sts:GetCallerIdentity",
    resource_template: "*", scope_id: null, global_resource_acknowledged: true,
    justification: "This AWS action requires account-global resource authorization",
  };
  assert.equal(manualMappingCoverage([identityEffect], [global]).unmapped.length, 0);
  assert.equal(manualMappingCoverage(effects, [{ ...global,
    tool_name: "read", effect_id: "read-1" }]).completeRows.length, 0);
});

test("global IAM access requires both acknowledgement and a specific justification", () => {
  const identityEffect = { tool_name: "whoami", effect_id: "identity", resource_type: null };
  const row = {
    tool_name: "whoami", effect_id: "identity", action: "sts:GetCallerIdentity",
    resource_template: "*", scope_id: null, global_resource_acknowledged: true,
    justification: "This action needs a global resource",
  };
  assert.equal(manualMappingCoverage([identityEffect],
    [{ ...row, global_resource_acknowledged: false }]).completeRows.length, 0);
  assert.equal(manualMappingCoverage([identityEffect],
    [{ ...row, justification: "short" }]).completeRows.length, 0);
  assert.equal(manualMappingCoverage([identityEffect],
    [{ ...row, scope_id: "other" }]).completeRows.length, 0);
});

test("unrecognized MCP effect cannot satisfy mapping coverage", () => {
  const unrelated = { ...good, effect_id: "not-approved" };
  const result = manualMappingCoverage(effects, [unrelated]);
  assert.equal(result.completeRows.length, 0);
  assert.equal(result.unmapped.length, 2);
});
