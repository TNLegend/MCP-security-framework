import test from "node:test";
import assert from "node:assert/strict";
import { nestedPathDiff, publicationDiffInputs } from "../src/utils/nestedPathDiff.js";

test("compares nested types and array positions and preserves missing versus null", () => {
  const output = nestedPathDiff(
    { scope: { paths: ["old", 2], same: 4 }, deleted: null, api_key: "synthetic-old" },
    { scope: { paths: ["new", "2", "add"], same: 4 }, api_key: "synthetic-new" },
  );
  assert.equal(output.unchanged, 1);
  assert.deepEqual(output.rows.map((row) => [row.path, row.kind, row.beforeType, row.afterType]), [
    ["/scope/paths/0", "Changed", "string", "string"],
    ["/scope/paths/1", "Changed", "number", "string"],
    ["/scope/paths/2", "Added", "missing", "string"],
    ["/deleted", "Removed", "null", "missing"],
  ]);
  assert.equal(nestedPathDiff({ first: 1, second: 2 }, { first: 3, second: 4 }, 1).omitted, 1);
});

test("requires the exact server preview IDs and hashes for the published baseline and draft", () => {
  const active = { id: "active", status: "PUBLISHED", content_hash: "a", content: { scope: "old" } };
  const draft = { id: "draft", status: "DRAFT", content_hash: "b", content: { scope: "new" } };
  const preview = { active: { id: "active", content_hash: "a" }, draft: { id: "draft", content_hash: "b" } };
  assert.deepEqual(publicationDiffInputs(preview, draft, active), { before: active.content, after: draft.content });
  assert.equal(publicationDiffInputs(preview, draft, { ...active, status: "DRAFT" }), null);
  assert.equal(publicationDiffInputs(preview, { ...draft, content_hash: "other" }, active), null);
});
