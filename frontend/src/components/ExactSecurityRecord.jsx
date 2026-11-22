import { useEffect, useState } from "react";
import { fetchExactAuditTarget } from "../api/client.js";
import { auditTargetLink } from "../utils/operationNavigation.js";

const labels = {
  mcp_server: ["MCP server", "MCP servers"],
  control_plane_config_revision: ["Configuration revision", "Security rules"],
  emergency_deny: ["Emergency restriction", "Emergency block"],
  control_plane_user: ["User", "Users"],
};

export default function ExactSecurityRecord({ view, type, id, isAdmin }) {
  const [state, setState] = useState({ loading: true });
  const restricted = type === "control_plane_user" && !isAdmin;
  const invalid = !auditTargetLink(type, id);
  const [label, moduleLabel] = labels[type];
  useEffect(() => {
    if (restricted || invalid) return undefined;
    let current = true;
    fetchExactAuditTarget(type, id).then((record) => {
      if (current) setState(record?.type === type && record.id === id ? { record } : {});
    }).catch((error) => {
      if (current) setState({ retry: ![403, 404].includes(error.status) });
    });
    return () => { current = false; };
  }, [id, type, restricted, invalid]);

  return <section className="page-section">
    <div className="section-heading"><h2>{label}</h2></div>
    {state.loading && !restricted && !invalid ? <p role="status">Looking up the recorded ID…</p> :
      state.record && !restricted ? <div className="detail-panel">
        <h3>{state.record.label}</h3>
        <dl className="inline-metadata">
          <div><dt>Exact record ID</dt><dd><code>{state.record.id}</code></dd></div>
          <div><dt>Current record status</dt><dd>{state.record.status}</dd></div>
        </dl>
        <p className="hint-text">An audit receipt records what was observed at its timestamp.</p>
      </div> :
      <p role="alert">{state.retry
        ? `${label} could not be read. Reload to try again.`
        : `${label} was not found or is not available to you. No other ${label.toLowerCase()} was substituted.`}</p>}
    <p><a href={restricted ? "?" : "?view=" + view}>
      {restricted ? "Return to Home" : "Browse " + moduleLabel}</a></p>
  </section>;
}
