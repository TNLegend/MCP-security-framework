import { useEffect, useState } from "react";
import { fetchPublicationPreview, safeErrorMessage } from "../api/client";

// CF-01: renders the backend-computed diff and impact of a PUBLISH. It never
// computes an impact itself; it only displays what the API returned.

const SECTION_LABELS = {
  identity_bindings: "Identity bindings",
  agent_authorizations: "Agent permissions",
  policy_settings: "Policy settings",
  build_security: "Build security",
  security_packs: "Security packs",
  security_pack_installations: "Security pack installations",
  tool_security_contracts: "Tool security contracts",
  authority_resource_scopes: "Resource scopes",
  adapter_resolutions: "Adapter resolutions",
  tool_observation_approvals: "Tool observation approvals",
  authority_contexts: "Authority contexts",
};

const BLOCKER_LABELS = {
  only_draft_can_publish: "Only a draft can be published.",
  stale_draft_publication_conflict: "A newer revision is already active. Create a new draft from it.",
  draft_active_parent_changed: "The active revision changed since this draft was created. Create a new draft.",
  revision_hash_mismatch: "The stored content does not match its hash. Reload the draft.",
  configuration_invalid: "The configuration is invalid. Validate the draft to see the problem.",
};

export function publishBlockReason(preview, { loading = false, error = "" } = {}) {
  if (loading) return "Loading the publication preview...";
  if (error) return "The publication preview could not be loaded; publishing is disabled.";
  if (!preview) return "The publication preview has not been loaded.";
  if (!preview.preview_fingerprint) return "The preview has no fingerprint; publishing is disabled.";
  if (!preview.publishable) {
    const first = preview.blockers?.[0];
    return BLOCKER_LABELS[first] || `Publication is blocked (${first || "unknown reason"}).`;
  }
  return "";
}

function ListChange({ label, change }) {
  if (!change?.count) return null;
  return (
    <li>
      {label}: {change.count}
      {change.items?.length > 0 && <> ({change.items.join(", ")}{change.truncated ? ", ..." : ""})</>}
    </li>
  );
}

function SectionDiff({ name, section }) {
  const label = SECTION_LABELS[name] || name;
  if (section.changed_fields) {
    return <li><strong>{label}</strong>: changed fields {section.changed_fields.join(", ")}</li>;
  }
  return (
    <li>
      <strong>{label}</strong>
      <ul>
        <ListChange label="Added" change={section.added} />
        <ListChange label="Removed" change={section.removed} />
        <ListChange label="Changed" change={section.changed} />
      </ul>
    </li>
  );
}

function ImpactList({ impact }) {
  if (!impact?.computed) {
    return <p role="status">Impact not computed: {impact?.unavailable_reason || "unavailable"}.</p>;
  }
  return (
    <ul>
      {impact.first_publication && <li>This is the first published configuration.</li>}
      <li>Active agent sessions that will be revoked: <strong>{impact.sessions_to_revoke}</strong>
        {impact.identity_bindings_changed?.count > 0 &&
          <> (bindings changed: {impact.identity_bindings_changed.items.join(", ")}
            {impact.identity_bindings_changed.truncated ? ", ..." : ""})</>}
      </li>
      <li>Tools that will be restricted until their new contract is reviewed:{" "}
        <strong>{impact.tools_to_restrict?.count ?? 0}</strong>
        {impact.tools_to_restrict?.count > 0 &&
          <> ({impact.tools_to_restrict.items.join(", ")}{impact.tools_to_restrict.truncated ? ", ..." : ""})</>}
      </li>
    </ul>
  );
}

export default function PublicationPreview({ draftId, onChange }) {
  const [state, setState] = useState({ loading: true, preview: null, error: "" });

  useEffect(() => {
    let cancelled = false;
    setState({ loading: true, preview: null, error: "" });
    onChange?.(null);
    fetchPublicationPreview(draftId)
      .then((preview) => {
        if (cancelled) return;
        setState({ loading: false, preview, error: "" });
        onChange?.(preview);
      })
      .catch((err) => {
        if (cancelled) return;
        setState({ loading: false, preview: null, error: safeErrorMessage(err) });
        onChange?.(null);
      });
    return () => { cancelled = true; };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [draftId]);

  if (state.loading) return <p role="status">Loading the publication preview...</p>;
  if (state.error) {
    return <p className="error-text" role="alert">Publication preview unavailable: {state.error}</p>;
  }
  const { preview } = state;
  const changed = preview.diff?.changed_sections || [];
  return (
    <section className="publication-preview" aria-label="Publication preview">
      <h4>What this publication changes</h4>
      <p>
        Revision #{preview.draft.revision_number} replaces{" "}
        {preview.active ? `active revision #${preview.active.revision_number}` : "no active revision"}.
      </p>
      {preview.blockers?.length > 0 && (
        <div className="error-text" role="alert">
          <p>Publication is blocked:</p>
          <ul>{preview.blockers.map((code) => <li key={code}>{BLOCKER_LABELS[code] || code}</li>)}</ul>
        </div>
      )}
      {changed.length === 0 ? (
        <p>No configuration section changes.</p>
      ) : (
        <ul>
          {changed.map((name) => (
            <SectionDiff key={name} name={name} section={preview.diff.sections[name]} />
          ))}
        </ul>
      )}
      <h4>Impact when published</h4>
      <ImpactList impact={preview.impact} />
      <p className="muted-text">Computed by the server with the same rules publication applies.</p>
    </section>
  );
}
