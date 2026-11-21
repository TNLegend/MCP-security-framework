import assert from "node:assert/strict";
import test from "node:test";
import React from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { createServer } from "vite";

test("IAM-05/CL-06: IAM read errors retain safe, workload-specific actions without claiming effective access", async () => {
  const server = await createServer({
    configFile: false,
    plugins: [(await import("@vitejs/plugin-react")).default()],
    server: { middlewareMode: true, hmr: false },
    appType: "custom", logLevel: "silent",
  });
  try {
    const { iamReadErrorGuidance, IAMPolicyEvidence } =
      await server.ssrLoadModule("/src/pages/CloudSecurity.jsx");

    const ec2 = iamReadErrorGuidance("AWS_ACCESS_DENIED", "EC2");
    assert.match(ec2, /iam:GetInstanceProfile/);
    assert.match(ec2, /before requesting narrowly scoped audit access/);

    const ecs = iamReadErrorGuidance("AWS_ACCESS_DENIED", "ECS");
    assert.match(ecs, /do not assume an EC2 instance-profile permission/);
    assert.doesNotMatch(ecs, /iam:GetInstanceProfile/);

    const lambda = iamReadErrorGuidance("AWS_ACCESS_DENIED", "LAMBDA");
    assert.match(lambda, /role binding directly/);
    assert.match(iamReadErrorGuidance("IAM_POLICY_PAGINATION_INCOMPLETE", "LAMBDA"), /cannot claim full coverage/);
    assert.match(iamReadErrorGuidance("AWS_RATE_LIMITED", "EC2"), /rate-limited/);
    assert.doesNotMatch(iamReadErrorGuidance("secret-token", "LAMBDA"), /secret-token/);

    const item = {
      notes: "IAM_ROLE_OR_POLICY_READ_UNAVAILABLE",
      expected_actions: ["s3:GetObject"], expected_resource_arn: "arn:aws:s3:::example/key",
      evidence_summary: {
        id: "evidence-synthetic", sha256: "0".repeat(64),
        checked_at: "2026-11-21T12:00:00",
        summary: {
          workload_type: "LAMBDA",
          action: "s3:GetObject", resource: "arn:aws:s3:::example/key",
          identity_policy_read_error_codes: ["AWS_ACCESS_DENIED"],
          warning_codes: [],
        },
      },
    };
    const view = (value) => renderToStaticMarkup(React.createElement(IAMPolicyEvidence, { item: value }));
    const recorded = view(item);
    assert.match(recorded, /Why IAM policy coverage is incomplete/);
    assert.match(recorded, /AWS_ACCESS_DENIED/);
    assert.match(recorded, /Not established by this identity-policy/);
    assert.doesNotMatch(recorded, /iam:GetInstanceProfile/);

    const legacy = view({
      ...item,
      evidence_summary: {
        ...item.evidence_summary,
        summary: { ...item.evidence_summary.summary, identity_policy_read_error_codes: undefined },
      },
    });
    assert.match(legacy, /original IAM read error was not preserved/);
    assert.doesNotMatch(legacy, /AWS_ACCESS_DENIED/);
  } finally {
    await server.close();
  }
});