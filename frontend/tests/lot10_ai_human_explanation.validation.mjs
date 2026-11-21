import assert from "node:assert/strict";
import test from "node:test";
import React from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { createServer } from "vite";

test("AI review: meaningful prose appears before deterministic security facts, never raw JSON", async () => {
  const server = await createServer({
    configFile: false,
    plugins: [(await import("@vitejs/plugin-react")).default()],
    server: { middlewareMode: true, hmr: false },
    appType: "custom", logLevel: "silent",
  });
  try {
    const { ControlledAIResult } =
      await server.ssrLoadModule("/src/components/ControlledAIAssistant.jsx");
    const base = {
      mode: "EXPLAIN", provider: "gemini", fallback_used: false,
      non_authoritative: true, requires_human_review: true, can_mutate_runtime: false,
      draft_kind: "NONE",
      summary: "Recorded state: human review required.",
      ai_explanation:
        "The current tool has a HIGH finding about broad permissions. " +
        "The report supports further review, but it does not prove actual remote behavior.",
      risk_factors: ["HIGH finding TOOL_SCOPE_RISK: broader permission requested"],
      recommended_action: "HUMAN_REVIEW",
      rationale: "Open the finding and review its evidence.",
      uncertainties: ["Execution behavior was not verified"],
      evidence_refs: ["finding:TOOL_SCOPE_RISK"],
      template_options: [], adapter_options: [], confidence: 0.72,
    };
    const render = (result) =>
      renderToStaticMarkup(React.createElement(ControlledAIResult, { result }));
    const visible = render(base);
    const explanation = visible.indexOf("The current tool has a HIGH finding");
    const recorded = visible.indexOf("Recorded state: human review required.");
    assert.ok(explanation >= 0 && recorded > explanation);
    assert.match(visible, /Evidence behind this result/);
    assert.match(visible, /not an authorization/);
    assert.doesNotMatch(visible, /<pre|\{\s*"risk_factors"/);

    const noProse = render({ ...base, ai_explanation: null });
    assert.match(noProse, /AI did not provide a specific explanation/);

    const proposed = render({
      ...base, draft_kind: "TEMPLATE_MAPPING",
      draft_preview: {
        template_id: "reviewed-template", missing_bindings: ["environment_id"],
        argument_mappings: { recipient: "args.to" },
      },
    });
    assert.match(proposed, /Proposed configuration fields/);
    assert.match(proposed, /Template Id/);
    assert.match(proposed, /Missing Bindings/);
    assert.match(proposed, /Environment_id|environment_id/);
    assert.doesNotMatch(proposed, /<pre|\{\s*"template_id"/);

    const unsafe = render({ ...base, can_mutate_runtime: true });
    assert.match(unsafe, /AI explanation withheld/);
    assert.doesNotMatch(unsafe, /The current tool has a HIGH finding/);
  } finally {
    await server.close();
  }
});
