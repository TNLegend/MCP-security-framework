import assert from "node:assert/strict";
import test from "node:test";
import { createServer } from "vite";

test("CL-02/CL-03: IAM warnings distinguish broad grants and unresolved statements", async () => {
  const server = await createServer({
    configFile: false,
    plugins: [(await import("@vitejs/plugin-react")).default()],
    server: { middlewareMode: true, hmr: false },
    appType: "custom", logLevel: "silent",
  });
  try {
    const { iamWarningExplanation: explain, iacFindingSourceEvidence: findSource } =
      await server.ssrLoadModule("/src/pages/CloudSecurity.jsx");
    const finding = { id: 19, resource_id: 2, rule_id: "CKV_AWS_23" };
    const sources = findSource(finding, [
      { id: 100, resource_id: 2, rule_id: "CKV_AWS_23", safe_summary: {
        scanner: "checkov", file: "terraform/main.tf", line: 12,
        version: "synthetic", source_fingerprint: "a".repeat(64),
      } },
      { id: 101, resource_id: 2, rule_id: "CKV_AWS_23", safe_summary: {
        scanner: "trivy", file: "terraform/main.tf", line: null,
      } },
      { id: 102, resource_id: 3, rule_id: "CKV_AWS_23", safe_summary: {
        scanner: "checkov", file: "private/other.tf", line: 9,
      } },
      { id: 103, resource_id: 2, rule_id: "DIFFERENT_RULE", safe_summary: {
        scanner: "checkov", file: "private/other.tf", line: 9,
      } },
    ]);
    assert.equal(sources.length, 2);
    assert.equal(sources[0].line, 12);
    assert.equal(sources[1].line, null);
    assert.equal(sources[0].file, "terraform/main.tf");
    assert.deepEqual(findSource({ resource_id: 2, rule_id: "ABSENT" }, []), []);
    assert.match(explain("IAM_BROAD_ACTION_ALLOW"), /additional IAM actions/i);
    assert.match(explain("IAM_BROAD_RESOURCE_ALLOW"), /additional AWS resources/i);
    assert.match(explain("IAM_NEGATED_ALLOW_POTENTIALLY_BROAD"), /may be very broad/i);
    assert.match(explain("IAM_CONDITIONAL_DENY_NOT_EVALUATED"), /not evaluated/i);
    assert.match(explain("IAM_CONDITIONAL_ALLOW_NOT_EVALUATED"), /not evaluated/i);
    assert.match(explain("SYNTHETIC_UNRECOGNIZED_CODE"), /not established/i);
    assert.doesNotMatch(explain("IAM_CONDITIONAL_DENY_NOT_EVALUATED"), /permission granted|effective access confirmed/i);
  } finally {
    await server.close();
  }
});
