import assert from "node:assert/strict";
import test from "node:test";
import { createServer } from "vite";

test("CLOUD-05: credential helper failure is actionable and not a network outage", async () => {
  const server = await createServer({
    configFile: false,
    plugins: [(await import("@vitejs/plugin-react")).default()],
    server: { middlewareMode: true, hmr: false },
    appType: "custom", logLevel: "silent",
  });
  try {
    const { cloudError, iamReadErrorGuidance } = await server.ssrLoadModule("/src/pages/CloudSecurity.jsx");
    const helper = cloudError({ message: "AWS_CREDENTIAL_PROCESS_FAILED" });
    assert.match(helper, /credential helper/);
    assert.match(helper, /named audit profile/);
    assert.match(helper, /No IAM permissions were changed/);
    assert.doesNotMatch(helper, /network outage|could not be reached/);
    const network = cloudError({ message: "AWS_CONNECTION_FAILED" });
    assert.match(network, /could not be reached/);
    assert.doesNotMatch(network, /credential helper/);
    const iam = iamReadErrorGuidance("AWS_CREDENTIAL_PROCESS_FAILED", "EKS");
    assert.match(iam, /Refresh the local named profile/);
    assert.match(iam, /Do not change IAM permissions/);

    for (const code of [
      "AWS_PROFILE_NOT_FOUND", "AWS_CREDENTIALS_UNAVAILABLE",
      "AWS_SESSION_EXPIRED", "AWS_ACCESS_DENIED",
      "AWS_CONNECTION_FAILED", "AWS_CREDENTIAL_PROCESS_FAILED",
      "AWS_INVALID_CREDENTIALS", "AWS_RATE_LIMITED",
      "AWS_API_ERROR", "CLOUD_SCAN_INTERNAL_ERROR",
    ]) {
      const message = cloudError({ message: code });
      assert.ok(message.length > 45, code);
      assert.doesNotMatch(message, /^[A-Z][A-Z0-9_]+$/, code);
      assert.ok(!message.includes("secret-token"), code);
    }
  } finally {
    await server.close();
  }
});