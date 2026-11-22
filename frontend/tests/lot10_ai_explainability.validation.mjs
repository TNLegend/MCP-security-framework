import assert from "node:assert/strict";
import test from "node:test";
import React from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { createServer } from "vite";

test("AI-01/AI-02: advisory content is never described as a framework fact and unsafe replies are withheld", async () => {
  const server = await createServer({
    configFile: false,
    plugins: [(await import("@vitejs/plugin-react")).default()],
    server: { middlewareMode: true, hmr: false },
    appType: "custom", logLevel: "silent",
  });
  try {
    const { ControlledAIResult } = await server.ssrLoadModule("/src/components/ControlledAIAssistant.jsx");
    const base = {
      non_authoritative: true, requires_human_review: true, can_mutate_runtime: false,
      draft_kind: "NONE", summary: "The model suggests that the finding deserves review.",
      rationale: "This is a hypothesis, not a verified authorization.",
      recommended_action: "HUMAN_REVIEW", mode: "EXPLAIN", provider: "test",
      evidence_refs: [], uncertainties: [], risk_factors: [],
      template_options: [], adapter_options: [], confidence: 0.5,
    };
    const view = (result) => renderToStaticMarkup(React.createElement(ControlledAIResult, { result }));
    const safe = view(base);
    assert.match(safe, /AI-selected evidence/);
    assert.match(safe, /The model suggests that the finding deserves review/);
    assert.doesNotMatch(safe, /What the framework recorded/);
    assert.match(safe, /advisory/i);
    for (const unsafe of [
      { ...base, non_authoritative: false },
      { ...base, requires_human_review: false },
      { ...base, can_mutate_runtime: true },
      { ...base, non_authoritative: undefined },
    ]) {
      const rejected = view(unsafe);
      assert.match(rejected, /AI explanation withheld/);
      assert.doesNotMatch(rejected, /The model suggests/);
      assert.doesNotMatch(rejected, /This is a hypothesis/);
    }
    const draft = view({ ...base, draft_kind: "CONTRACT", draft_preview: { allowed: false } });
    assert.match(draft, /What the AI proposed/);
    assert.match(draft, /Review the proposed draft/);
  } finally {
    await server.close();
  }
});