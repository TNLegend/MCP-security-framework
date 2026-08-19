import assert from "node:assert/strict";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";

import { build, loadEnv } from "vite";

import viteConfig from "./vite.config.js";

const frontendRoot = dirname(fileURLToPath(import.meta.url));
const repoRoot = resolve(frontendRoot, "..");

async function resolveConfig(env = {}) {
  return withEnv(env, async () => viteConfig({ mode: "development", command: "serve" }));
}

async function withEnv(values, callback) {
  const previous = new Map();
  for (const [name, value] of Object.entries(values)) {
    previous.set(name, process.env[name]);
    if (value === undefined) {
      delete process.env[name];
    } else {
      process.env[name] = value;
    }
  }
  try {
    return await callback();
  } finally {
    for (const [name, value] of previous.entries()) {
      if (value === undefined) {
        delete process.env[name];
      } else {
        process.env[name] = value;
      }
    }
  }
}

test("Vite loads environment variables from the repository root", async () => {
  const config = await resolveConfig();

  assert.equal(resolve(config.envDir), repoRoot);
});

test("Vite dev server uses FRONTEND_HOST and FRONTEND_PORT", async () => {
  const config = await resolveConfig({
    FRONTEND_HOST: "127.0.0.1",
    FRONTEND_PORT: "5321",
  });

  assert.equal(config.server.host, "127.0.0.1");
  assert.equal(config.server.port, 5321);
  assert.equal(config.server.strictPort, true);
});

test("Vite rejects invalid FRONTEND_PORT values clearly", async () => {
  await assert.rejects(
    () => resolveConfig({ FRONTEND_PORT: "invalid-port" }),
    /Invalid FRONTEND_PORT/,
  );
});

test("frontend API base URL is injected from root environment", async () => {
  const customApiBase = "http://127.0.0.1:8123/api/v1";

  await withEnv({ VITE_API_BASE_URL: customApiBase }, async () => {
    const viteEnv = loadEnv("production", repoRoot, "VITE_");
    assert.equal(viteEnv.VITE_API_BASE_URL, customApiBase);

    const result = await build({
      configFile: resolve(frontendRoot, "vite.config.js"),
      root: frontendRoot,
      logLevel: "silent",
      build: { write: false },
    });
    const outputs = Array.isArray(result) ? result.flatMap((item) => item.output) : result.output;
    const bundledJavaScript = outputs
      .filter((item) => item.type === "chunk")
      .map((item) => item.code)
      .join("\n");

    assert.match(bundledJavaScript, /http:\/\/127\.0\.0\.1:8123\/api\/v1/);
    assert.doesNotMatch(bundledJavaScript, /http:\/\/127\.0\.0\.1:8000\/api\/v1/);
  });
});

test("browser-visible Vite environment excludes server secrets", async () => {
  await withEnv(
    {
      POSTGRES_PASSWORD: "do-not-expose",
      TRUSTED_SESSION_TOKEN_PEPPER: "do-not-expose",
      MCP_PROXY_SERVICE_PRIVATE_KEY_PATH: ".runtime/secrets/private.pem",
      VITE_API_BASE_URL: "http://127.0.0.1:8123/api/v1",
    },
    async () => {
      const viteEnv = loadEnv("development", repoRoot, "VITE_");

      assert.deepEqual(Object.keys(viteEnv).filter((name) => !name.startsWith("VITE_")), []);
      assert.equal(viteEnv.POSTGRES_PASSWORD, undefined);
      assert.equal(viteEnv.TRUSTED_SESSION_TOKEN_PEPPER, undefined);
      assert.equal(viteEnv.MCP_PROXY_SERVICE_PRIVATE_KEY_PATH, undefined);
    },
  );
});
