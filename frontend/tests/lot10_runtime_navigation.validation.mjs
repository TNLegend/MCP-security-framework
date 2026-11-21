import assert from "node:assert/strict";
import test from "node:test";
import { createServer } from "vite";

test("RT-13: a Runtime event identifies only its exact known server and current reviewed tool", async () => {
  const server = await createServer({
    configFile: false, plugins: [(await import("@vitejs/plugin-react")).default()],
    server: { middlewareMode: true, hmr: false }, appType: "custom", logLevel: "silent",
  });
  try {
    const { runtimeServerLabel, matchingReviewedToolId } =
      await server.ssrLoadModule("/src/pages/RuntimeLogs.jsx");
    const fingerprint = "a".repeat(64);
    const log = { server_id: 1, tool_name: "send_message", tool_fingerprint: fingerprint };
    const servers = [{ id: 1, name: "Mail MCP", status: "active" },
                     { id: 2, name: "Other MCP", status: "active" }];
    const tools = [{ id: 5, server_id: 1, name: "send_message", current_fingerprint: fingerprint },
                   { id: 6, server_id: 2, name: "send_message", current_fingerprint: fingerprint }];
    assert.equal(runtimeServerLabel(log, servers), "Mail MCP (#1)");
    assert.equal(matchingReviewedToolId(log, tools), 5);
    assert.equal(matchingReviewedToolId({ ...log, tool_fingerprint: "b".repeat(64) }, tools), null);
    assert.equal(matchingReviewedToolId({ ...log, tool_fingerprint: null }, tools), null);
    assert.equal(matchingReviewedToolId(log, [tools[0], { ...tools[0], id: 7 }]), null);
    assert.equal(runtimeServerLabel({ server_id: 99 }, servers), "Server #99 (unverified)");
    assert.equal(runtimeServerLabel({ server_id: 1 }, [servers[0], { ...servers[0] }]), "Server #1 (unverified)");
    assert.equal(runtimeServerLabel({}, servers), "Not recorded");
  } finally {
    await server.close();
  }
});
