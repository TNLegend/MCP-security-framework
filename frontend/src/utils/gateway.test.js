import assert from "node:assert/strict";
import test from "node:test";

import { buildGovernedEndpoint } from "./gateway.js";


test("uses the configured local Gateway endpoint", () => {
  assert.equal(
    buildGovernedEndpoint(
      { status: "healthy", endpoint: "http://127.0.0.1:9234" },
      7,
    ),
    "http://127.0.0.1:9234/mcp/7",
  );
});

test("normalizes a configured remote Gateway base path", () => {
  assert.equal(
    buildGovernedEndpoint(
      { status: "healthy", endpoint: "https://framework.example/gateway/" },
      9,
    ),
    "https://framework.example/gateway/mcp/9",
  );
});

test("does not invent an endpoint when Gateway is unavailable", () => {
  assert.equal(
    buildGovernedEndpoint(
      { status: "unavailable", endpoint: "http://127.0.0.1:9001" },
      3,
    ),
    null,
  );
  assert.equal(buildGovernedEndpoint(null, 3), null);
});
