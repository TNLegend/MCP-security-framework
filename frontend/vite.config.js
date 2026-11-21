import react from "@vitejs/plugin-react";
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

export default defineConfig(({ mode }) => {
  const env = loadEnv(mode, repoRoot, "");
  return {
    envDir: repoRoot,
    plugins: [react()],
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
