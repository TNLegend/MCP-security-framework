import test from "node:test";
import assert from "node:assert/strict";

import { groupIamComparisons, iamActionLabel } from "../src/utils/iamcomparisongroups.js";

test("groups 32 comparisons by recorded role, situation, and service exactly once", () => {
  const rows = Array.from({ length: 32 }, (_, index) => ({
    id: String(index),
    role_arn: index < 31 ? "arn:aws:iam::123456789012:role/Example" : null,
    status: index < 25 ? "OUTSIDE_MCP_MAPPING" : index < 28 ? "POTENTIAL_MISSING" : "UNKNOWN",
    observed_actions: index < 25 ? ["ssm:GetParameter"] : [],
    expected_actions: index === 25 ? ["s3:GetObject", "kms:Decrypt"] : [],
  }));
  const groups = groupIamComparisons(rows);
  const situations = groups.flatMap((role) => role.situations);
  assert.equal(groups.reduce((sum, group) => sum + group.count, 0), 32);
  assert.equal(groups[0].situations[0].count, 25);
  assert.equal(groups[0].situations[0].services[0].service, "ssm");
  assert.equal(groups[0].situations[1].services[0].service, "Multiple services");
  assert.equal(new Set(situations.flatMap((group) =>
    group.services.flatMap((service) => service.rows.map((row) => row.id)),
  )).size, 32);
  assert.equal(iamActionLabel(rows[0]), "ssm:GetParameter");
});
