import assert from "node:assert/strict";
import test from "node:test";
import { createServer } from "vite";

test("CL-10: merged Terraform finding shows independent Checkov and Trivy evidence without guessing equivalence", async () => {
  const server = await createServer({
    configFile: false, plugins: [(await import("@vitejs/plugin-react")).default()],
    server: { middlewareMode: true, hmr: false }, appType: "custom", logLevel: "silent",
  });
  try {
    const { iacFindingSourceEvidence } =
      await server.ssrLoadModule("/src/pages/CloudSecurity.jsx");
    const finding = { id: "finding-a", rule_id: "CKV_AWS_23", resource_id: "resource-a" };
    const evidence = [
      { id: "e1", resource_id: "resource-a", rule_id: "CKV_AWS_23",
        safe_summary: { scanner: "checkov", rule: "CKV_AWS_23", version: "3.0",
          file: "main.tf", line: 13, source_fingerprint: "a".repeat(64),
          linked_finding_id: "finding-a" } },
      { id: "e2", resource_id: "resource-a", rule_id: "AWS-0099",
        safe_summary: { scanner: "trivy", rule: "AWS-0099", version: "0.55",
          file: "main.tf", line: 27, source_fingerprint: "a".repeat(64),
          linked_finding_id: "finding-a" } },
      { id: "e3", resource_id: "resource-a", rule_id: "CKV_AWS_23",
        safe_summary: { scanner: "checkov", file: "main.tf",
          linked_finding_id: "another-finding" } },
      { id: "e4", resource_id: "resource-b", rule_id: "CKV_AWS_23",
        safe_summary: { scanner: "checkov", file: "other.tf",
          linked_finding_id: "finding-a" } },
      { id: "e5", resource_id: "resource-a", rule_id: "AWS-0107",
        safe_summary: { scanner: "trivy", file: "main.tf" } },
    ];
    const sources = iacFindingSourceEvidence(finding, evidence);
    assert.equal(sources.length, 2);
    assert.deepEqual(sources.map(x => [x.scanner,x.rule,x.version,x.line]),
      [["checkov","CKV_AWS_23","3.0",13], ["trivy","AWS-0099","0.55",27]]);
    assert.equal(iacFindingSourceEvidence({ ...finding, id: "other" }, evidence).length, 0);
  } finally {
    await server.close();
  }
});
