export function buildGovernedEndpoint(gatewayStatus, serverId) {
  if (
    gatewayStatus?.status !== "healthy" ||
    typeof gatewayStatus?.endpoint !== "string" ||
    !gatewayStatus.endpoint.trim()
  ) {
    return null;
  }
  return `${gatewayStatus.endpoint.replace(/\/+$/, "")}/mcp/${serverId}`;
}
