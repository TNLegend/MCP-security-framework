import assert from "node:assert/strict";
import test from "node:test";
import { createServer } from "vite";
import { readFile } from "node:fs/promises";

test("XC-04: primary operator guidance uses user-facing security concepts rather than internal model abbreviations", async () => {
  const server = await createServer({
    configFile: false, plugins: [(await import("@vitejs/plugin-react")).default()],
    server: { middlewareMode: true, hmr: false }, appType: "custom", logLevel: "silent",
  });
  try {
    const { analysisModuleCards, nextAnalysisAction } =
      await server.ssrLoadModule("/src/utils/analysisPresentation.js");
    const tool = { current_fingerprint: "a".repeat(64), analysis_status: "REVIEW_REQUIRED" };
    const analysis = {
      id: 42, fingerprint: tool.current_fingerprint, completed_at: "2026-11-21T21:00:00",
      semantic_scores: { m4_structured_semantics: { m6: { candidate_operation_count: 2 } } },
    };
    const visible = analysisModuleCards(tool, analysis, { analyses: [analysis] }).cards
      .flatMap((c) => [c.title, c.status, c.explanation, c.detail]).join(" ");
    assert.doesNotMatch(visible, /\bM[1-7]\b|GLiNER|DeBERTa|MiniLM|PASS10/i);
    assert.match(visible, /Prompt injection protection/);
    assert.match(visible, /not verified tool behavior|does not verify what the tool actually does/);
    assert.match(nextAnalysisAction(tool, analysis, true), /human review/);
    const reviewSrc = await readFile("src/pages/ToolAnalysis.jsx", "utf8");
    assert.match(reviewSrc, /Passive observation only/);
    assert.doesNotMatch(reviewSrc, /Mode: shadow/);
    const headings = await readFile("src/App.jsx", "utf8");
    assert.match(headings, /label: "Security review"/);
    assert.match(headings, /label: "Code scans"/);
  } finally {
    await server.close();
  }
});
