const situations = {
  OUTSIDE_MCP_MAPPING: "Outside the approved mapping",
  POTENTIAL_EXCESS: "Potentially broader grant",
  POTENTIAL_MISSING: "Possible missing grant",
  EXPLICIT_DENY: "Explicit identity-policy denial",
  UNKNOWN: "Unverified comparison",
  READY: "Matched recorded identity policy",
};

function comparisonService(row) {
  const actions = [...(row.expected_actions || []), ...(row.observed_actions || [])];
  const services = new Set(actions.map((action) =>
    typeof action === "string" ? action.match(/^([a-z0-9-]+):/i)?.[1].toLowerCase() : null,
  ).filter(Boolean));
  if (services.size > 1) return "Multiple services";
  return services.values().next().value || "Service not recorded";
}

export function groupIamComparisons(items) {
  const roles = new Map();
  for (const row of items) {
    const role = row.role_arn || "Role not recorded";
    const situation = situations[row.status] || "Unverified comparison";
    const service = comparisonService(row);
    if (!roles.has(role)) roles.set(role, { role, count: 0, situations: new Map() });
    const roleGroup = roles.get(role);
    if (!roleGroup.situations.has(situation)) {
      roleGroup.situations.set(situation, { situation, count: 0, services: new Map() });
    }
    const group = roleGroup.situations.get(situation);
    if (!group.services.has(service)) group.services.set(service, { service, rows: [] });
    group.services.get(service).rows.push(row);
    roleGroup.count += 1;
    group.count += 1;
  }
  return Array.from(roles.values(), (role) => ({
    ...role,
    situations: Array.from(role.situations.values(), (group) => ({
      ...group, services: Array.from(group.services.values()),
    })),
  }));
}

export function iamActionLabel(row) {
  const reverse = row.evidence_summary?.summary?.direction === "IAM_POLICY_TO_APPROVED_MCP_NEEDS"
    || (!row.tool_name && !row.expected_actions?.length);
  return (reverse ? row.observed_actions : row.expected_actions)?.join(", ") || "Action not verified";
}
