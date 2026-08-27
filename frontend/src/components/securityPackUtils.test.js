import assert from "node:assert/strict";
import test from "node:test";

import {
  blankPackForTool,
  declarativeManifestFromForm,
  packFormFromManifest,
  securityIdentifier,
} from "./securityPackUtils.js";

test("blank pack IDs are stable valid identifiers derived from the selected tool", () => {
  assert.equal(securityIdentifier("Create / Update Ticket"), "create-update-ticket");
  const form = blankPackForTool({
    name: "transmute_qubits",
    title: "Transmute Qubits",
    input_schema: { properties: { lattice_id: { type: "string" } } },
  });
  assert.equal(form.packId, "transmute-qubits-pack");
  assert.equal(form.capabilityId, "transmute-qubits.use");
  assert.equal(form.hints, "lattice_id");
});

test("pack form round-trips through a safe declarative manifest", () => {
  const manifest = declarativeManifestFromForm({
    packId: "ticketing",
    title: "Ticketing",
    capabilityId: "ticket.read",
    resourceTypeId: "ticket_object",
    templateId: "ticket.read",
    keywords: "ticket, issue",
    hints: "ticket_id, issue_id",
    destructive: false,
    externalEffect: false,
  });
  const form = packFormFromManifest(manifest);

  assert.equal(manifest.origin, "DECLARATIVE");
  assert.equal(manifest.resource_types[0].adapter_id, "generic-declarative");
  assert.equal(form.capabilityId, "ticket.read");
  assert.equal(form.hints, "ticket_id, issue_id");
});
