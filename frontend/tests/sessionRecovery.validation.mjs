import assert from "node:assert/strict";
import test from "node:test";

import {
  changeOwnPassword,
  fetchControlPlaneMe,
  loginControlPlane,
  SESSION_EXPIRED_EVENT,
  setCsrfToken,
} from "../src/api/client.js";

test("only a response for the current session can report expiry", async (t) => {
  globalThis.document = { cookie: "mcp_control_plane_csrf=test-session" };
  globalThis.window = new EventTarget();
  let expiryEvents = 0;
  window.addEventListener(SESSION_EXPIRED_EVENT, () => { expiryEvents += 1; });
  const rejectSession = () => Response.json({ detail: "Invalid session" }, { status: 401 });
  let finishOldRead;
  try {
    t.mock.method(globalThis, "fetch", (url) => {
      if (url.endsWith("/login")) return Promise.resolve(Response.json({ csrf_token: "new-session" }));
      if (url.endsWith("/change-password")) {
        return Promise.resolve(Response.json({ detail: "Invalid password" }, { status: 401 }));
      }
      return new Promise((resolve) => { finishOldRead = resolve; });
    });

    const oldRead = fetchControlPlaneMe();
    await loginControlPlane("fixture-user", "fixture-password");
    finishOldRead(rejectSession());
    await assert.rejects(oldRead, { code: "request_cancelled" });
    assert.equal(expiryEvents, 0);

    await assert.rejects(changeOwnPassword("wrong-password", "fixture-password"), { status: 401 });
    assert.equal(expiryEvents, 0);

    const currentRead = fetchControlPlaneMe();
    finishOldRead(rejectSession());
    await assert.rejects(currentRead, { status: 401 });
    assert.equal(expiryEvents, 1);
  } finally {
    delete globalThis.document;
    delete globalThis.window;
    setCsrfToken("");
  }
});
