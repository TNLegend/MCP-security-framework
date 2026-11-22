import react from "@vitejs/plugin-react";
import { execFileSync } from "node:child_process";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { defineConfig, loadEnv } from "vite";

const frontendRoot = dirname(fileURLToPath(import.meta.url));
const repoRoot = resolve(frontendRoot, "..");

function parsePort(value, defaultPort) {
  if (value === undefined || value === "") {
    return defaultPort;
  }
  const parsed = Number(value);
  if (!Number.isInteger(parsed) || parsed < 1 || parsed > 65535) {
    throw new Error("Invalid FRONTEND_PORT: expected an integer from 1 to 65535.");
  }
  return parsed;
}

// UX-01: the UI bundle's own identity, fixed when the build (or dev server)
// starts. It is compared with the API's start-time identity in System health.
function git(args) {
  try {
    return execFileSync("git", args, { cwd: repoRoot, encoding: "utf8", timeout: 3000,
      stdio: ["ignore", "pipe", "ignore"], windowsHide: true }).trim();
  } catch {
    return null;
  }
}

function uiBuildIdentity(env, command) {
  const fromRelease = /^[0-9a-f]{7,64}$/i.test(env.MCP_BUILD_REVISION || "") ? env.MCP_BUILD_REVISION.toLowerCase() : null;
  const head = fromRelease ? null : git(["rev-parse", "HEAD"]);
  const revision = fromRelease || (/^[0-9a-f]{7,64}$/i.test(head || "") ? head : null);
  const status = revision && !fromRelease ? git(["status", "--porcelain", "--untracked-files=no"]) : null;
  return {
    schema: "mcp.build_identity.v1",
    component: "ui",
    revision,
    revision_source: fromRelease ? "release_environment"
      : revision ? (command === "serve" ? "git_head_at_dev_server_start" : "git_head_at_build") : "unknown",
    worktree_dirty: status === null ? null : status.length > 0,
    started_at: new Date().toISOString(),
  };
}

export default defineConfig(({ command, mode }) => {
  const env = loadEnv(mode, repoRoot, "");
  return {
    envDir: repoRoot,
    plugins: [react()],
    define: {
      __MCP_UI_BUILD__: JSON.stringify(uiBuildIdentity(env, command)),
    },
    server: {
      host: env.FRONTEND_HOST || "127.0.0.1",
      port: parsePort(env.FRONTEND_PORT, 5173),
      strictPort: true,
      // The explanation catalog lives outside frontend/. Expose only this
      // exact JSON file, never the rest of the source tree or .runtime/.
      fs: {
        allow: [frontendRoot, resolve(repoRoot, "shared", "explanation_catalog.json")],
      },
    },
  };
});
