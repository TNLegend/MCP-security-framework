import assert from "node:assert/strict";
import test from "node:test";
import React from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { createServer } from "vite";

test("RT-02/03/06: original OPA verdict, later Proxy block, and missing evidence remain distinct", async () => {
  const server = await createServer({
    configFile: false,
    plugins: [(await import("@vitejs/plugin-react")).default()],
    server: { middlewareMode: true, hmr: false },
    appType: "custom", logLevel: "silent",
  });
  try {
    const { default: SecurityExplanation } = await server.ssrLoadModule("/src/components/securityexplanation.jsx");
    const view = (record) => renderToStaticMarkup(React.createElement(SecurityExplanation, { record }));

    const laterGuard = view({
      decision: "BLOCK", opa_decision: "ALLOW", opa_rule_id: "allow_generic_security_model_v2",
      rule_id: "canonical_arguments_changed_before_execution", decision_basis: "GUARD",
      guard_explanation: {
        explanation_version: 1, source: "proxy_internal_guard",
        phase: "PRE_DISPATCH", rule_id: "canonical_arguments_changed_before_execution",
      },
      execution_status: "blocked", dispatch_state: "NOT_SENT", operation_id: "synthetic",
    });
    assert.match(laterGuard, /Original OPA decision:<\/strong> ALLOW/);
    assert.match(laterGuard, /separate Proxy control subsequently imposed BLOCK/);
    assert.match(laterGuard, /Canonical tool arguments changed/);
    assert.match(laterGuard, /Not sent/);
    assert.doesNotMatch(laterGuard, /The recorded policy evaluation identified:/);

    const withheld = view({
      decision: "BLOCK", opa_decision: "ALLOW", rule_id: "result_guard_blocked",
      execution_status: "result_blocked", dispatch_state: "SENT_CONFIRMED",
      decision_basis: "GUARD", operation_id: "synthetic",
    });
    assert.match(withheld, /The tool was called and its response was withheld/);
    assert.match(withheld, /Remote effects may already have occurred/);
    assert.doesNotMatch(withheld, /Not sent/);

    const legacy = view({
      decision: "BLOCK", rule_id: "deny_generic_security_model_v2",
      decision_reason: "Generic security model authorization requirements were not satisfied.",
      execution_status: "blocked",
    });
    assert.match(legacy, /No detailed checks were preserved/);
    assert.match(legacy, /cannot establish which authorization condition failed/);
    assert.match(legacy, /No verified OPA verdict is recorded/);

    const precise = view({
      decision: "BLOCK", opa_decision: "BLOCK", rule_id: "deny_generic_security_model_v2",
      opa_explanation: {
        explanation_version: 1, scope: "runtime_security_model_v2",
        failed_checks: ["SIGNED_CONTRACT_BINDING_INVALID"],
        failed_effects: [{
          check: "CAPABILITY_NOT_GRANTED", effect_id: "synthetic-effect",
          capability: "synthetic:read",
        }],
      },
      dispatch_state: "NOT_SENT",
    });
    assert.match(precise, /Signed tool contract does not match/);
    assert.match(precise, /Agent lacks the required capability/);
    assert.match(precise, /synthetic-effect/);
    assert.match(precise, /synthetic:read/);

    const precaution = view({
      decision: "BLOCK", decision_basis: "FAIL_CLOSED_TECHNICAL",
      rule_id: "policy_error", dispatch_state: "NOT_SENT",
    });
    assert.match(precaution, /refused as a precaution/);
    assert.match(precaution, /not evidence of an OPA policy violation/);
  } finally {
    await server.close();
  }
});