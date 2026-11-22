import assert from "node:assert/strict";
import test from "node:test";
import {
  cancelControlPlaneReads, fetchServers, fetchTools, setCsrfToken,
} from "../src/api/client.js";

test("identical authenticated GETs coalesce only while in flight; cancellation and session changes isolate reads", async () => {
  const original = globalThis.fetch;
  const descriptor = Object.getOwnPropertyDescriptor(globalThis, "document");
  Object.defineProperty(globalThis, "document", { value: { cookie: "" }, configurable: true });
  const requests = [];
  globalThis.fetch = (url, { signal }) => new Promise((resolve, reject) => {
    requests.push({ url, complete: (id) => resolve(new Response(JSON.stringify([{ id }]))) });
    signal.addEventListener("abort", () => reject(new Error("synthetic abort")), { once: true });
  });
  try {
    setCsrfToken("");
    const one = fetchServers();
    const same = fetchServers();
    const different = fetchTools();
    assert.equal(requests.length, 2);
    requests[0].complete(1);
    requests[1].complete(2);
    assert.deepEqual(await one, await same);
    assert.deepEqual(await different, [{ id: 2 }]);

    const obsolete = fetchServers();
    const abandoned = assert.rejects(obsolete, { code: "request_cancelled" });
    cancelControlPlaneReads();
    const current = fetchServers();
    assert.equal(requests.length, 4);
    requests[3].complete(3);
    await abandoned;
    assert.deepEqual(await current, [{ id: 3 }]);

    const priorSession = fetchServers();
    const invalidated = assert.rejects(priorSession, { code: "request_cancelled" });
    setCsrfToken("synthetic-session-transition");
    const nextSession = fetchServers();
    requests[5].complete(4);
    await invalidated;
    assert.deepEqual(await nextSession, [{ id: 4 }]);
  } finally {
    setCsrfToken("");
    globalThis.fetch = original;
    if (descriptor) Object.defineProperty(globalThis, "document", descriptor);
    else delete globalThis.document;
  }
});
