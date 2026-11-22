import assert from "node:assert/strict";
import test from "node:test";
import { createServer } from "vite";

test("UX-20: findings with identical titles are told apart by their exact comparison", async () => {
  const server = await createServer({
    configFile: false,
    plugins: [(await import("@vitejs/plugin-react")).default()],
    server: { middlewareMode: true, hmr: false }, appType: "custom", logLevel: "silent",
  });
  try {
    const { findingTarget } = await server.ssrLoadModule("/src/pages/CloudSecurity.jsx");
    const title = "IAM identity-policy grant outside this MCP's approved mapping";
    const evidence = [
      { safe_summary: { comparison_id: "c1".padEnd(36, "1"), action: "s3:GetObject", resource: "arn:aws:s3:::a/*" } },
      { safe_summary: { comparison_id: "c2".padEnd(36, "2"), action: "s3:PutObject", resource: "arn:aws:s3:::a/*" } },
    ];
    const first = { id: "f1".padEnd(36, "a"), rule_id: "IAM_MCP_OUTSIDE_APPROVED_MAPPING", title, comparison_id: "c1".padEnd(36, "1") };
    const second = { id: "f2".padEnd(36, "b"), rule_id: "IAM_MCP_OUTSIDE_APPROVED_MAPPING", title, comparison_id: "c2".padEnd(36, "2") };
    const legacy = { id: "f3".padEnd(36, "c"), rule_id: "IAM_MCP_OUTSIDE_APPROVED_MAPPING", title, comparison_id: null };
    assert.match(findingTarget(first, evidence).text, /^s3:GetObject on arn:aws:s3:::a\/\* \(ref f1aaaaaa\)$/);
    assert.match(findingTarget(second, evidence).text, /^s3:PutObject on/);
    assert.notEqual(findingTarget(first, evidence).text, findingTarget(second, evidence).text);
    const old = findingTarget(legacy, evidence);
    assert.equal(old.legacy, true);
    assert.match(old.text, /^Legacy finding, not linked to an exact comparison/);
    // A linked comparison whose evidence row is not loaded still names the comparison, never a guess.
    assert.match(findingTarget(first, []).text, /^comparison c1111111/);
    // Non-IAM findings are only given a stable reference.
    assert.equal(findingTarget({ id: "abcdef123", rule_id: "s3_bucket_public" }, evidence).text, "ref abcdef12");
  } finally {
    await server.close();
  }
});
