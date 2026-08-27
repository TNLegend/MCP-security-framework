import assert from "node:assert/strict";
import test from "node:test";

import { hasRecordedInputSchema } from "./contractUtils.js";

test("contract onboarding requires a recorded input schema", () => {
  assert.equal(hasRecordedInputSchema(null), false);
  assert.equal(hasRecordedInputSchema({}), false);
  assert.equal(hasRecordedInputSchema([]), false);
  assert.equal(
    hasRecordedInputSchema({
      type: "object",
      properties: {},
      additionalProperties: false,
    }),
    true,
  );
});
