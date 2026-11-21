import assert from "node:assert/strict";
import test from "node:test";
import { createServer } from "vite";
import React from "react";
import { renderToStaticMarkup } from "react-dom/server";



test("CLOUD-01: generic AWS role onboarding does not depend on the lab account or AWS CLI", async () => {
  const server = await createServer({
    configFile: false,
    plugins: [(await import("@vitejs/plugin-react")).default()],
    server: { middlewareMode: true, hmr: false },
    appType: "custom", logLevel: "silent",
  });
  try {
    const { awsCrossAccountTrustExample, explainDeployObligations,
      governanceFreshnessWindow, CloudScanTable } = await server.ssrLoadModule("/src/pages/CloudSecurity.jsx");
    assert.equal(governanceFreshnessWindow("IAM_MCP"), "24 hours");
    assert.equal(governanceFreshnessWindow("AWS_ADVANCED"), "7 days");
    assert.equal(governanceFreshnessWindow("IAC_CONFIG"), "7 days");
    const html = renderToStaticMarkup(React.createElement(CloudScanTable, {
      scans: [{
        id: "synthetic-audit", kind: "AWS_ADVANCED", status: "PARTIAL",
        created_at: "2026-11-21T17:00:00Z", resource_count: 2,
        finding_count: 1, unknown_checks: 4,
      }], label: "Synthetic AWS status", loading: false, empty: "No audits",
      onOpen: () => { throw new Error("Do not invoke actions while rendering"); },
    }));
    assert.match(html, /Partial/);
    assert.match(html, /Incomplete coverage; not a clean security verdict/);
    assert.doesNotMatch(html, /(?:Fully secure|All checks passed)/);
    const obligations = explainDeployObligations(["ADMIN_REVIEW", "LOG"]);
    assert.match(obligations, /Administrator review required/);
    assert.match(obligations, /Record the assessment/);
    assert.doesNotMatch(obligations, /ADMIN_REVIEW|\bLOG\b/);
    assert.match(explainDeployObligations(["UNRECOGNIZED_CODE"]), /Unrecognized requirement/);
    const demo = awsCrossAccountTrustExample("mcp-independent-customer-xyz");
    assert.equal(demo.Version, "2012-10-17");
    assert.equal(demo.Statement[0].Action, "sts:AssumeRole");
    assert.equal(
      demo.Statement[0].Condition.StringEquals["sts:ExternalId"],
      "mcp-independent-customer-xyz",
    );
    assert.match(demo.Statement[0].Principal.AWS, /FRAMEWORK_AUDIT_PRINCIPAL/);
    assert.doesNotMatch(JSON.stringify(demo), /565087261244|mcp-cloud-audit-operator/);
    const oldRole = awsCrossAccountTrustExample("");
    assert.ok(!("Condition" in oldRole.Statement[0]));
  } finally {
    await server.close();
  }
});

test("CLOUD-05: credential helper failure is actionable and not a network outage", async () => {
  const server = await createServer({
    configFile: false,
    plugins: [(await import("@vitejs/plugin-react")).default()],
    server: { middlewareMode: true, hmr: false },
    appType: "custom", logLevel: "silent",
  });
  try {
    const { cloudError, iamReadErrorGuidance } = await server.ssrLoadModule("/src/pages/CloudSecurity.jsx");
    const helper = cloudError({ message: "AWS_CREDENTIAL_PROCESS_FAILED" });
    assert.match(helper, /credential helper/);
    assert.match(helper, /named audit profile/);
    assert.match(helper, /No IAM permissions were changed/);
    assert.doesNotMatch(helper, /network outage|could not be reached/);
    const network = cloudError({ message: "AWS_CONNECTION_FAILED" });
    assert.match(network, /could not be reached/);
    assert.doesNotMatch(network, /credential helper/);
    const iam = iamReadErrorGuidance("AWS_CREDENTIAL_PROCESS_FAILED", "EKS");
    assert.match(iam, /Refresh the local named profile/);
    assert.match(iam, /Do not change IAM permissions/);

    for (const code of [
      "AWS_PROFILE_NOT_FOUND", "AWS_CREDENTIALS_UNAVAILABLE",
      "AWS_SESSION_EXPIRED", "AWS_ACCESS_DENIED",
      "AWS_CONNECTION_FAILED", "AWS_CREDENTIAL_PROCESS_FAILED",
      "AWS_INVALID_CREDENTIALS", "AWS_RATE_LIMITED",
      "AWS_API_ERROR", "CLOUD_SCAN_INTERNAL_ERROR",
    ]) {
      const message = cloudError({ message: code });
      assert.ok(message.length > 45, code);
      assert.doesNotMatch(message, /^[A-Z][A-Z0-9_]+$/, code);
      assert.ok(!message.includes("secret-token"), code);
    }
  } finally {
    await server.close();
  }
});