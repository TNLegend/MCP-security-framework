export function commaValues(value) {
  return value.split(",").map((item) => item.trim().toLowerCase()).filter(Boolean);
}

export function capabilityDomain(value) {
  return value.trim().split(".").slice(0, -1).join(".");
}

export function capabilityVerb(value) {
  return value.trim().split(".").at(-1) || "";
}

export function securityIdentifier(value, fallback = "custom") {
  const normalized = String(value || "")
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "")
    .slice(0, 96);
  return normalized || fallback;
}

export function blankPackForTool(tool) {
  const base = securityIdentifier(tool?.name || tool?.title, "custom-tool");
  const title = String(tool?.title || tool?.name || "Custom Tool").trim();
  const schemaProperties = Object.keys(tool?.input_schema?.properties || {});
  const hint = schemaProperties[0] || "resource";
  return {
    packId: `${base}-pack`,
    title: `${title} Security`,
    capabilityId: `${base}.use`,
    resourceTypeId: `${base}-resource`,
    templateId: `${base}-template`,
    keywords: base.replaceAll("-", ", "),
    hints: hint,
    destructive: false,
    externalEffect: false,
  };
}

export function packFormFromManifest(manifest) {
  const capability = manifest?.capabilities?.[0] || {};
  const resource = manifest?.resource_types?.[0] || {};
  const template = manifest?.templates?.[0] || {};
  const binding = template.bindings?.[0] || {};
  return {
    packId: manifest?.id || "",
    title: manifest?.title || "",
    capabilityId: capability.id || "",
    resourceTypeId: resource.id || "",
    templateId: template.id || "",
    keywords: (template.keywords || []).join(", "),
    hints: (binding.argument_hints || []).join(", "),
    destructive: Boolean(capability.destructive),
    externalEffect: Boolean(capability.external_effect),
  };
}

export function declarativeManifestFromForm(form) {
  const capabilityId = form.capabilityId.trim();
  const resourceTypeId = form.resourceTypeId.trim();
  const title = form.title.trim();
  return {
    id: form.packId.trim(),
    version: "1.0.0",
    title,
    description: `${title} security capabilities.`,
    origin: "DECLARATIVE",
    capabilities: [{
      id: capabilityId,
      domain: capabilityDomain(capabilityId),
      verb: capabilityVerb(capabilityId),
      destructive: form.destructive,
      external_effect: form.externalEffect,
      requires_resource: true,
      allowed_resource_types: [resourceTypeId],
      lifecycle: "ACTIVE",
    }],
    resource_types: [{
      id: resourceTypeId,
      version: "1",
      canonicalizer: "hierarchical_name",
      hierarchy_support: true,
      allowed_matching_modes: ["SELF", "SUBTREE"],
      adapter_id: "generic-declarative",
      requires_specialized_interpretation: false,
      case_semantics: "authority-defined",
      unicode_policy: "NFC-strict",
    }],
    templates: [{
      id: form.templateId.trim(),
      title,
      description: `Govern ${capabilityId} tools.`,
      capability: capabilityId,
      keywords: commaValues(form.keywords),
      bindings: [{
        key: "resource",
        resource_type: resourceTypeId,
        required: true,
        multiple: false,
        argument_hints: commaValues(form.hints),
      }],
      max_resource_cardinality: 100,
      declared_reference_precision: "EXPLICIT",
    }],
    semantic_categories: [],
  };
}
