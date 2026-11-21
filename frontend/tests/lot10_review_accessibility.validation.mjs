import assert from "node:assert/strict";
import test from "node:test";
import React from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { createServer } from "vite";

test("AUTH-03: security-review disabled actions expose independent visible reasons", async () => {
  const server = await createServer({
    configFile: false,
    plugins: [(await import("@vitejs/plugin-react")).default()],
    server: { middlewareMode: true, hmr: false },
    appType: "custom",
    logLevel: "silent",
  });
  try {
    const { ReviewActionControls } = await server.ssrLoadModule("/src/pages/ToolAnalysis.jsx");
    const html = (props) => renderToStaticMarkup(
      React.createElement(ReviewActionControls, { isAdmin: true, ...props }),
    );

    const both = html({
      approveDisabledReason: "Current signed approval evidence is unavailable.",
      blockDisabledReason: "The latest analysis is still loading.",
    });
    assert.match(both, /aria-describedby="review-approval-unavailable"/);
    assert.match(both, /aria-describedby="review-block-unavailable"/);
    assert.match(both, /<strong>Approval unavailable:<\/strong> Current signed approval evidence is unavailable/);
    assert.match(both, /<strong>Block action unavailable:<\/strong> The latest analysis is still loading/);
    assert.equal((both.match(/disabled=""/g) || []).length, 2);

    const approvalOnly = html({ approveDisabledReason: "Approval not eligible" });
    assert.match(approvalOnly, /Approval not eligible/);
    assert.doesNotMatch(approvalOnly, /Block action unavailable/);
    assert.equal((approvalOnly.match(/disabled=""/g) || []).length, 1);

    const active = html({});
    assert.doesNotMatch(active, /disabled=""/);
    assert.doesNotMatch(active, /review-approval-unavailable/);
    assert.doesNotMatch(active, /review-block-unavailable/);
    assert.equal(renderToStaticMarkup(React.createElement(ReviewActionControls, {
      isAdmin: false,
      approveDisabledReason: "Private reason",
    })), "");
  } finally {
    await server.close();
  }
});