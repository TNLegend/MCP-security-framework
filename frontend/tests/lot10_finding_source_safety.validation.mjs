import assert from "node:assert/strict";
import test from "node:test";
import React from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { createServer } from "vite";

test("TA-03: the finding card retains safe catalogue titles and exact, evidenced source locations", async () => {
  const server = await createServer({
    configFile: false,
    plugins: [(await import("@vitejs/plugin-react")).default()],
    server: { middlewareMode: true, hmr: false }, appType: "custom", logLevel: "silent",
  });
  try {
    const { friendlyFindingTitle: title, findingEvidenceLocation: location,
            findingImpactLabel, FindingCard } =
      await server.ssrLoadModule("/src/pages/ToolAnalysis.jsx");

    const long = "An actual suspicious finding: " + "a".repeat(800);
    const candidate = { id: 1, code: "TOOL_SCOPE_RISK",
      title: "Description\ncontains " + long,
      source: "M3", severity: "HIGH", evidence: {
        decision: "REVIEW", source_path: "/description",
        start: 21, end: 63,
      },
    };
    assert.equal(title(candidate).length, 140);
    assert.ok(!title(candidate).includes("\n"));
    assert.equal(location(candidate), "/description (characters 21–63)");
    assert.equal(findingImpactLabel(candidate), "Requires a human security review; not an independent block");
    assert.equal(location({ evidence: { source_path: "/description" }}), "/description (field)");
    assert.equal(location({ evidence: { location: { source_pointer: "/inputSchema/properties/url", start: 0, end: 18 } } }),
      "/inputSchema/properties/url (characters 0–18)");

    for (const bad of [
      { path: "C:\\users\\secret\\file" }, { source_path: "/description", start: -1, end: 10 },
      { source_path: "/description", start: 45, end: 44 },
      { source_path: "http://remote.invalid/path", start: 0, end: 15 },
      { source_path: "/description", start: 1, end: "12" },
      { source_path: "/description/../secrets" },
      { source_path: "/description", start: 0, end: 10000000 },
    ]) {
      assert.equal(location({ evidence: bad }), null);
    }
    const visible = renderToStaticMarkup(React.createElement(React.Fragment, null,
      React.createElement(FindingCard, { finding: candidate }),
      React.createElement(FindingCard, { finding: {
        id: 2, code: "OTHER_RISK", title: "<script>alert('hi')</script>",
        evidence: {}, source: "M7", severity: "LOW",
      } }),
    ));
    assert.match(visible, /Exact source location/);
    assert.match(visible, /description \(characters 21/);
    assert.match(visible, /Not recorded in this finding/);
    assert.match(visible, /&lt;script&gt;/);
    assert.doesNotMatch(visible, /<script>/);
    assert.doesNotMatch(visible, /a{200}/);
    assert.match(visible, /Requires a human security review/);
  } finally { await server.close(); }
});
