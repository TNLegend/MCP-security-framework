import { useEffect, useMemo, useState } from "react";
import {
  createDraftRevision,
  patchConfigRevision,
  publishConfigRevision,
  rollbackConfigRevision,
  validateConfigRevision,
} from "../api/client";

function SecurityConfiguration({
  activeRevision,
  isAdmin = false,
  loading = false,
  onRefresh,
  policies = [],
  revisions = [],
}) {
  const [selectedRevisionId, setSelectedRevisionId] = useState(null);
  const [contentText, setContentText] = useState("");
  const [summary, setSummary] = useState("Control Center update");
  const [message, setMessage] = useState("");
  const [error, setError] = useState("");
  const selectedRevision = useMemo(
    () =>
      revisions.find((revision) => revision.id === selectedRevisionId) ||
      activeRevision ||
      revisions[0] ||
      null,
    [activeRevision, revisions, selectedRevisionId],
  );

  useEffect(() => {
    if (selectedRevision) {
      setContentText(JSON.stringify(selectedRevision.content, null, 2));
    }
  }, [selectedRevision]);

  async function runAction(action) {
    if (!selectedRevision) {
      return;
    }
    setError("");
    setMessage("");
    try {
      if (action === "draft") {
        await createDraftRevision(selectedRevision.id, summary);
      } else if (action === "save") {
        await patchConfigRevision(selectedRevision.id, JSON.parse(contentText), summary);
      } else if (action === "validate") {
        await validateConfigRevision(selectedRevision.id, summary);
      } else if (action === "publish") {
        await publishConfigRevision(selectedRevision.id, summary);
      } else if (action === "rollback") {
        if (!window.confirm("Rollback creates a new signed revision from this content.")) {
          return;
        }
        await rollbackConfigRevision(selectedRevision.id, summary);
      }
      setMessage("Configuration operation completed.");
      await onRefresh?.();
    } catch (err) {
      setError(err.message || "Configuration operation failed");
    }
  }

  if (loading) {
    return (
      <section className="page-section">
        <div className="section-heading">
          <h2>Security Configuration</h2>
          <p>Loading revisions...</p>
        </div>
      </section>
    );
  }

  return (
    <section className="page-section">
      <div className="section-heading">
        <h2>Security Configuration</h2>
        <p>{revisions.length} revision(s)</p>
      </div>
      {message && <div className="success-banner">{message}</div>}
      {error && <div className="error-banner">{error}</div>}

      <div className="summary-grid">
        <Summary label="Active revision" value={activeRevision?.revision_number ?? "-"} />
        <Summary label="Schema version" value={activeRevision?.schema_version ?? "-"} />
        <Summary label="Policy settings" value={Object.keys(activeRevision?.content?.policy_settings?.rules || {}).length} />
        <Summary label="Legacy policy rows" value={policies.length} />
      </div>

      <div className="split-layout">
        <div className="table-shell">
          <table>
            <thead>
              <tr>
                <th>Revision</th>
                <th>Status</th>
                <th>Schema</th>
                <th>Hash</th>
                <th>Published</th>
              </tr>
            </thead>
            <tbody>
              {revisions.map((revision) => (
                <tr
                  className={selectedRevision?.id === revision.id ? "selected-row" : ""}
                  key={revision.id}
                  onClick={() => setSelectedRevisionId(revision.id)}
                  role="button"
                  tabIndex="0"
                >
                  <td>{revision.revision_number}</td>
                  <td>
                    <Badge value={revision.status} />
                  </td>
                  <td>{revision.schema_version}</td>
                  <td>{shorten(revision.content_hash)}</td>
                  <td>{formatDate(revision.published_at)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>

        <div className="detail-panel">
          <h3>Revision Detail</h3>
          {selectedRevision ? (
            <>
              <dl className="compact-dl">
                <div>
                  <dt>id</dt>
                  <dd>{selectedRevision.id}</dd>
                </div>
                <div>
                  <dt>content_hash</dt>
                  <dd>{selectedRevision.content_hash}</dd>
                </div>
                <div>
                  <dt>signature</dt>
                  <dd>{shorten(selectedRevision.signature)}</dd>
                </div>
                <div>
                  <dt>signature_key_id</dt>
                  <dd>{selectedRevision.signature_key_id || "-"}</dd>
                </div>
              </dl>
              <label className="textarea-label">
                Revision content
                <textarea
                  readOnly={!isAdmin || selectedRevision.status !== "DRAFT"}
                  onChange={(event) => setContentText(event.target.value)}
                  value={contentText}
                />
              </label>
              {isAdmin && (
                <div className="action-panel">
                  <label>
                    Change summary
                    <input
                      onChange={(event) => setSummary(event.target.value)}
                      value={summary}
                    />
                  </label>
                  <div className="button-row">
                    <button onClick={() => runAction("draft")} type="button">
                      Create Draft
                    </button>
                    <button
                      disabled={selectedRevision.status !== "DRAFT"}
                      onClick={() => runAction("save")}
                      type="button"
                    >
                      Save Draft
                    </button>
                    <button
                      disabled={selectedRevision.status !== "DRAFT"}
                      onClick={() => runAction("validate")}
                      type="button"
                    >
                      Validate
                    </button>
                    <button
                      disabled={selectedRevision.status !== "DRAFT"}
                      onClick={() => runAction("publish")}
                      type="button"
                    >
                      Publish
                    </button>
                    <button
                      disabled={selectedRevision.status !== "ARCHIVED"}
                      onClick={() => runAction("rollback")}
                      type="button"
                    >
                      Rollback
                    </button>
                  </div>
                </div>
              )}
            </>
          ) : (
            <div className="empty-state">No configuration revision found.</div>
          )}
        </div>
      </div>
    </section>
  );
}

function Summary({ label, value }) {
  return (
    <div className="summary-card">
      <span>{label}</span>
      <strong>{value}</strong>
    </div>
  );
}

function Badge({ value }) {
  const normalized = String(value || "").toLowerCase();
  const className = normalized === "published" ? "badge-success" : "badge-muted";
  return <span className={`badge ${className}`}>{value || "unknown"}</span>;
}

function shorten(value) {
  if (!value) {
    return "-";
  }
  return `${String(value).slice(0, 12)}...${String(value).slice(-8)}`;
}

function formatDate(value) {
  if (!value) {
    return "-";
  }
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? String(value) : date.toLocaleString();
}

export default SecurityConfiguration;
