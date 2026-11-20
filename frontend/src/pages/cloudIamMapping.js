/** Signed MCP effects are covered only by complete administrator mappings. */
export function manualMappingCoverage(effects, rows) {
  const completeRows = rows.filter((row) => {
    const effect = effects.find((e) =>
      e.tool_name === row.tool_name && e.effect_id === row.effect_id);
    if (!effect || typeof row.action !== "string" || !row.action.trim() ||
        typeof row.resource_template !== "string") return false;
    const template = row.resource_template.trim();
    if (template === "*") {
      return !effect.resource_type &&
        row.global_resource_acknowledged === true &&
        !row.scope_id &&
        typeof row.justification === "string" &&
        row.justification.trim().length >= 12;
    }
    return Boolean(effect.resource_type) && Boolean(row.scope_id) &&
      Boolean(template) && row.global_resource_acknowledged !== true;
  });
  const covered = new Set(completeRows.map((row) => row.tool_name + "|" + row.effect_id));
  return {
    completeRows,
    unmapped: effects.filter((e) => !covered.has(e.tool_name + "|" + e.effect_id)),
  };
}

export function isMappingBoundToCurrentContext(mapping, environment, server, context) {
  const binding = mapping?.configuration?.source_binding;
  return Boolean(mapping && environment && server && context && binding &&
    binding.account_id === environment.account_id &&
    binding.server_endpoint === server.endpoint &&
    mapping.signed_revision === context.signed_revision &&
    mapping.signed_content_hash === context.signed_content_hash);
}

export function canRequestManualAudit(mapping, environment, server, context) {
  return mapping?.status === "APPROVED" &&
    environment?.status === "CONNECTED" &&
    isMappingBoundToCurrentContext(mapping, environment, server, context);
}
