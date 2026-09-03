import { useEffect, useState } from "react";

import { Pagination, usePagination } from "./Pagination";

const TABS = [
  ["identity", "Identity bindings"],
  ["authorization", "Agent authorizations"],
  ["policy", "Policy settings"],
  ["security", "Security model"],
  ["advanced", "Advanced JSON"],
];

function ConfigurationEditor({ content, contentText, error, onChange, onRawChange, readOnly }) {
  const [activeTab, setActiveTab] = useState("identity");
  const identity = content?.identity_bindings || { revision: "", bindings: [] };
  const authorizations = content?.agent_authorizations || { revision: "", subjects: {} };

  function updateSection(key, value) {
    onChange({ ...content, [key]: value });
  }

  return (
    <div className="configuration-editor">
      <div aria-label="Configuration sections" className="tab-list" role="tablist">
        {TABS.map(([id, label]) => (
          <button aria-selected={activeTab === id} className={activeTab === id ? "active-tab" : ""} key={id} onClick={() => setActiveTab(id)} role="tab" type="button">
            {label}
          </button>
        ))}
      </div>
      <div className="configuration-section" role="tabpanel">
        {activeTab === "identity" && (
          <IdentityEditor document={identity} onChange={(value) => updateSection("identity_bindings", value)} readOnly={readOnly} />
        )}
        {activeTab === "authorization" && (
          <AuthorizationEditor document={authorizations} onChange={(value) => updateSection("agent_authorizations", value)} readOnly={readOnly} />
        )}
        {activeTab === "policy" && (
          <PolicyEditor onChange={(value) => updateSection("policy_settings", value)} readOnly={readOnly} value={content?.policy_settings || { rules: {} }} />
        )}
        {activeTab === "security" && (
          <SecurityModelEditor content={content} onChange={onChange} readOnly={readOnly} />
        )}
        {activeTab === "advanced" && (
          <label className="textarea-label">
            Complete revision JSON
            <textarea aria-describedby="revision-content-error" aria-invalid={Boolean(error)} onChange={(event) => onRawChange(event.target.value)} readOnly={readOnly} value={contentText} />
            {error && <span className="field-error" id="revision-content-error">{error}</span>}
          </label>
        )}
      </div>
    </div>
  );
}

function IdentityEditor({ document, onChange, readOnly }) {
  const bindings = document.bindings || [];
  const indexedBindings = bindings.map((binding, index) => ({ binding, index }));
  const bindingPagination = usePagination(indexedBindings, String(bindings.length));
  if (readOnly) {
    return <ReadOnlyIdentityBindings bindings={bindings} revision={document.revision} />;
  }

  function updateBinding(index, field, value) {
    onChange({ ...document, bindings: bindings.map((binding, row) => row === index ? { ...binding, [field]: value } : binding) });
  }
  return (
    <div className="structured-editor">
      <TextField disabled={readOnly} label="Document revision" onChange={(revision) => onChange({ ...document, revision })} value={document.revision || ""} />
      <div className="editor-list">
        {bindingPagination.pageItems.map(({ binding, index }) => (
          <div className="editor-row identity-row" key={index}>
            <TextField disabled={readOnly} label="Issuer" onChange={(value) => updateBinding(index, "issuer", value)} value={binding.issuer || ""} />
            <TextField disabled={readOnly} label="Subject" onChange={(value) => updateBinding(index, "subject", value)} value={binding.subject || ""} />
            <TextField disabled={readOnly} label="Agent ID" onChange={(value) => updateBinding(index, "agent_id", value)} value={binding.agent_id || ""} />
            {!readOnly && <button className="danger-action" onClick={() => onChange({ ...document, bindings: bindings.filter((_, row) => row !== index) })} type="button">Remove</button>}
          </div>
        ))}
      </div>
      <Pagination
        label="Identity bindings"
        onPageChange={bindingPagination.setPage}
        page={bindingPagination.page}
        pageCount={bindingPagination.pageCount}
        total={bindingPagination.total}
      />
      {!readOnly && <button onClick={() => onChange({ ...document, bindings: [...bindings, { issuer: "", subject: "", agent_id: "" }] })} type="button">Add binding</button>}
    </div>
  );
}

function ReadOnlyIdentityBindings({ bindings, revision }) {
  const bindingPagination = usePagination(bindings, String(bindings.length));
  return (
    <div className="structured-editor">
      <ReadOnlyValue label="Document revision" value={revision || "-"} />
      {bindings.length === 0 ? (
        <div className="empty-state">No identity bindings are configured.</div>
      ) : (
        <div className="table-shell configuration-bindings-table">
          <table>
            <thead>
              <tr>
                <th>Issuer</th>
                <th>Subject</th>
                <th>Agent ID</th>
              </tr>
            </thead>
            <tbody>
              {bindingPagination.pageItems.map((binding, index) => (
                <tr key={`${binding.issuer}-${binding.subject}-${index}`}>
                  <td>{binding.issuer || "-"}</td>
                  <td>{binding.subject || "-"}</td>
                  <td>{binding.agent_id || "-"}</td>
                </tr>
              ))}
            </tbody>
          </table>
          <Pagination
            label="Identity bindings"
            onPageChange={bindingPagination.setPage}
            page={bindingPagination.page}
            pageCount={bindingPagination.pageCount}
            total={bindingPagination.total}
          />
        </div>
      )}
    </div>
  );
}

function AuthorizationEditor({ document, onChange, readOnly }) {
  const entries = Object.entries(document.subjects || {});
  const indexedEntries = entries.map((entry, index) => ({ entry, index }));
  const authorizationPagination = usePagination(indexedEntries, String(entries.length));
  if (readOnly) {
    return <ReadOnlyAuthorizations entries={entries} revision={document.revision} />;
  }

  function replaceEntries(nextEntries) {
    onChange({ ...document, subjects: Object.fromEntries(nextEntries) });
  }
  return (
    <div className="structured-editor">
      <TextField disabled={readOnly} label="Document revision" onChange={(revision) => onChange({ ...document, revision })} value={document.revision || ""} />
      <div className="editor-list">
        {authorizationPagination.pageItems.map(({ entry: [agentId, profile], index }) => (
          <AuthorizationRow
            agentId={agentId}
            key={index}
            onChange={(nextAgentId, nextProfile) => replaceEntries(entries.map((entry, row) => row === index ? [nextAgentId, nextProfile] : entry))}
            onRemove={() => replaceEntries(entries.filter((_, row) => row !== index))}
            profile={profile}
            readOnly={readOnly}
          />
        ))}
      </div>
      <Pagination
        label="Agent authorizations"
        onPageChange={authorizationPagination.setPage}
        page={authorizationPagination.page}
        pageCount={authorizationPagination.pageCount}
        total={authorizationPagination.total}
      />
      {!readOnly && <button onClick={() => replaceEntries([...entries, [uniqueAgentId(entries), { role: "viewer", grants: [] }]])} type="button">Add subject</button>}
    </div>
  );
}

function ReadOnlyAuthorizations({ entries, revision }) {
  const rows = entries.flatMap(([agentId, profile]) => {
    const grants = profile.grants || [];
    return (grants.length > 0 ? grants : [null]).map((grant) => ({
      agentId,
      role: profile.role || "-",
      capability: grant?.capability || "-",
      scopes: grant?.scopes?.join(", ") || "-",
    }));
  });
  const authorizationPagination = usePagination(rows, String(rows.length));

  return (
    <div className="structured-editor">
      <ReadOnlyValue label="Document revision" value={revision || "-"} />
      {rows.length === 0 ? (
        <div className="empty-state">No agent authorizations are configured.</div>
      ) : (
        <div className="table-shell configuration-authorizations-table">
          <table>
            <thead>
              <tr>
                <th>Agent ID</th>
                <th>Role</th>
                <th>Capability</th>
                <th>Scopes</th>
              </tr>
            </thead>
            <tbody>
              {authorizationPagination.pageItems.map((row, index) => (
                <tr key={`${row.agentId}-${row.capability}-${index}`}>
                  <td><span className="table-ellipsis" title={row.agentId}>{row.agentId}</span></td>
                  <td><span className="table-ellipsis" title={row.role}>{row.role}</span></td>
                  <td><span className="table-ellipsis" title={row.capability}>{row.capability}</span></td>
                  <td><span className="table-ellipsis" title={row.scopes}>{row.scopes}</span></td>
                </tr>
              ))}
            </tbody>
          </table>
          <Pagination
            label="Agent authorization grants"
            onPageChange={authorizationPagination.setPage}
            page={authorizationPagination.page}
            pageCount={authorizationPagination.pageCount}
            total={authorizationPagination.total}
          />
        </div>
      )}
    </div>
  );
}

function AuthorizationRow({ agentId, onChange, onRemove, profile, readOnly }) {
  const grants = profile.grants || [];
  const indexedGrants = grants.map((grant, index) => ({ grant, index }));
  const grantPagination = usePagination(indexedGrants, `${agentId}|${grants.length}`);
  function updateGrant(index, field, value) {
    onChange(agentId, { ...profile, grants: grants.map((grant, row) => row === index ? { ...grant, [field]: value } : grant) });
  }
  return (
    <section className="authorization-row">
      <div className="editor-row authorization-heading">
        <TextField disabled={readOnly} label="Agent ID" onChange={(value) => onChange(value, profile)} value={agentId} />
        <TextField disabled={readOnly} label="Role" onChange={(role) => onChange(agentId, { ...profile, role })} value={profile.role || ""} />
        {!readOnly && <button className="danger-action" onClick={onRemove} type="button">Remove subject</button>}
      </div>
      <div className="grant-list">
        {grantPagination.pageItems.map(({ grant, index }) => (
          <div className="editor-row grant-row" key={index}>
            <TextField disabled={readOnly} label="Capability" onChange={(value) => updateGrant(index, "capability", value)} value={grant.capability || ""} />
            <TextField disabled={readOnly} label="Scopes (comma separated)" onChange={(value) => updateGrant(index, "scopes", splitList(value))} value={(grant.scopes || []).join(", ")} />
            {!readOnly && <button onClick={() => onChange(agentId, { ...profile, grants: grants.filter((_, row) => row !== index) })} type="button">Remove grant</button>}
          </div>
        ))}
      </div>
      <Pagination
        label={`Grants for ${agentId}`}
        onPageChange={grantPagination.setPage}
        page={grantPagination.page}
        pageCount={grantPagination.pageCount}
        total={grantPagination.total}
      />
      {!readOnly && <button onClick={() => onChange(agentId, { ...profile, grants: [...grants, { capability: "", scopes: [] }] })} type="button">Add grant</button>}
    </section>
  );
}

function PolicyEditor({ onChange, readOnly, value }) {
  const rules = value.rules || {};
  const analysisRule = rules.tool_analysis_required || { enabled: true, severity: "HIGH" };
  return (
    <div className="structured-editor">
      <section className="policy-rule-row">
        <div><strong>Tool analysis required</strong><p>Mandatory admission rule for discovered tools.</p></div>
        <label className="toggle-control"><input checked={analysisRule.enabled !== false} disabled type="checkbox" />Enabled</label>
        <label>Severity<select disabled={readOnly} onChange={(event) => onChange({ ...value, rules: { ...rules, tool_analysis_required: { ...analysisRule, enabled: true, severity: event.target.value } } })} value={analysisRule.severity || "HIGH"}>
          {['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'].map((severity) => <option key={severity}>{severity}</option>)}
        </select></label>
      </section>
    </div>
  );
}

function SecurityModelEditor({ content, onChange, readOnly }) {
  const fields = [
    ["tool_security_contracts", "Tool security contracts"],
    ["authority_resource_scopes", "Authority resource scopes"],
    ["adapter_resolutions", "Adapter resolutions"],
    ["tool_observation_approvals", "Observation approvals"],
    ["authority_contexts", "Authority contexts"],
  ];
  return (
    <div className="structured-editor">
      <div className="schema-profile-row">
        <strong>Security model</strong>
        <span>Contracts and authority-scoped resources</span>
      </div>
      {fields.map(([key, label]) => (
        <JsonSection key={key} label={label} onChange={(value) => onChange({ ...content, [key]: value })} readOnly={readOnly || key === "tool_observation_approvals"} value={content?.[key]} />
      ))}
    </div>
  );
}

function JsonSection({ label, onChange, readOnly, value }) {
  const [text, setText] = useState(JSON.stringify(value ?? null, null, 2));
  const [error, setError] = useState("");
  useEffect(() => {
    setText(JSON.stringify(value ?? null, null, 2));
    setError("");
  }, [value]);
  function commit() {
    try {
      onChange(JSON.parse(text));
      setError("");
    } catch {
      setError("This section must contain valid JSON.");
    }
  }
  return (
    <details className="configuration-document">
      <summary>{label}{readOnly ? " (read only)" : ""}</summary>
      <textarea onBlur={commit} onChange={(event) => setText(event.target.value)} readOnly={readOnly} value={text} />
      {error && <span className="field-error">{error}</span>}
    </details>
  );
}

function TextField({ disabled, label, onChange, value }) {
  return <label>{label}<input disabled={disabled} onChange={(event) => onChange(event.target.value)} value={value} /></label>;
}

function ReadOnlyValue({ label, value }) {
  return <div className="read-only-field"><span>{label}</span><strong>{value}</strong></div>;
}

function splitList(value) {
  return String(value).split(",").map((item) => item.trim()).filter(Boolean);
}

function uniqueAgentId(entries) {
  const used = new Set(entries.map(([agentId]) => agentId));
  let index = entries.length + 1;
  while (used.has(`agent-${index}`)) index += 1;
  return `agent-${index}`;
}

export default ConfigurationEditor;
