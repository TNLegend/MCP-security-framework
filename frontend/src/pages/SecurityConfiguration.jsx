import { useEffect, useMemo, useState } from "react";
import {
  createDraftRevision,
  createLatestConfigRevision,
  deleteConfigRevision,
  patchConfigRevision,
  publishConfigRevision,
  rollbackConfigRevision,
  validateConfigRevision,
} from "../api/client";
import {
  LIMITS,
  activateRowOnKeyboard,
  clearFieldError,
  parseJsonContent,
  validateChangeSummary,
} from "../utils/validation";
import ConfigurationEditor from "../components/ConfigurationEditor";
import SecurityPackManager from "../components/SecurityPackManager";
import { Pagination, usePagination } from "../components/Pagination";

function SecurityConfiguration({
  activeRevision,
  isAdmin = false,
  loading = false,
  onRefresh,
  revisions = [],
}) {
  const [selectedRevisionId, setSelectedRevisionId] = useState(null);
  const [contentText, setContentText] = useState("");
  const [loadedContentText, setLoadedContentText] = useState("");
  const [contentObject, setContentObject] = useState(null);
  const [summary, setSummary] = useState("Control Center update");
  const [fieldErrors, setFieldErrors] = useState({});
  const [message, setMessage] = useState("");
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const revisionPagination = usePagination(revisions, String(revisions.length));
  // An explicitly selected revision must never silently fall back to the
  // active one while refresh is fetching a newly created draft. Otherwise
  // controls can target a different (published) revision than the user chose.
  const selectedRevision = useMemo(
    () =>
      selectedRevisionId
        ? revisions.find((revision) => revision.id === selectedRevisionId) || null
        : activeRevision || revisions[0] || null,
    [activeRevision, revisions, selectedRevisionId],
  );

  useEffect(() => {
    if (selectedRevision) {
      const text = JSON.stringify(selectedRevision.content, null, 2);
      setContentText(text);
      setLoadedContentText(text);
      setContentObject(selectedRevision.content);
      setFieldErrors({});
    }
  }, [selectedRevision]);

  async function runAction(action) {
    if (busy || (!selectedRevision && action !== "latest")) {
      return;
    }
    const summaryError = validateChangeSummary(summary);
    const nextErrors = {};
    if (summaryError) {
      nextErrors.summary = summaryError;
    }
    const hasUnsavedChanges = contentText !== loadedContentText;
    if (["validate", "publish"].includes(action) && hasUnsavedChanges) {
      nextErrors.content = "Save draft changes before validating or publishing.";
    }
    let parsedContent = null;
    if (action === "save") {
      const parsed = parseJsonContent(contentText);
      if (parsed.error) {
        nextErrors.content = parsed.error;
      } else {
        parsedContent = parsed.value;
      }
    }
    setFieldErrors(nextErrors);
    if (Object.keys(nextErrors).length > 0) {
      return;
    }
    setError("");
    setMessage("");
    setBusy(true);
    try {
      let updatedRevision = null;
      if (action === "latest") {
        updatedRevision = await createLatestConfigRevision(summary);
      } else if (action === "draft") {
        updatedRevision = await createDraftRevision(selectedRevision.id, summary);
      } else if (action === "save") {
        updatedRevision = await patchConfigRevision(
          selectedRevision.id, parsedContent, summary, selectedRevision.content_hash
        );
      } else if (action === "validate") {
        await validateConfigRevision(selectedRevision.id, summary);
      } else if (action === "publish") {
        updatedRevision = await publishConfigRevision(selectedRevision.id, summary);
      } else if (action === "rollback") {
        if (!window.confirm("Rollback creates a new signed revision from this content.")) {
          return;
        }
        updatedRevision = await rollbackConfigRevision(selectedRevision.id, summary);
      } else if (action === "delete") {
        if (!window.confirm("Delete this inactive configuration revision? This cannot be undone.")) {
          return;
        }
        await deleteConfigRevision(selectedRevision.id, summary);
        setSelectedRevisionId(null);
      }
      if (updatedRevision?.id) {
        setSelectedRevisionId(updatedRevision.id);
      }
      setMessage("Configuration operation completed.");
      await onRefresh?.();
    } catch (err) {
      setError(err.message || "Configuration operation failed");
    } finally {
      setBusy(false);
    }
  }

  function updateContent(value) {
    setContentText(value);
    const parsed = parseJsonContent(value);
    if (!parsed.error) setContentObject(parsed.value);
    setFieldErrors((current) => clearFieldError(current, "content"));
  }

  function updateStructuredContent(value) {
    setContentObject(value);
    setContentText(JSON.stringify(value, null, 2));
    setFieldErrors((current) => clearFieldError(current, "content"));
  }

  function updateSummary(value) {
    setSummary(value);
    setFieldErrors((current) => clearFieldError(current, "summary"));
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
        <Summary label="Security controls" value={Object.keys(activeRevision?.content?.policy_settings?.rules || {}).length} />
      </div>

      <div className="configuration-layout">
        <div className="table-shell configuration-versions-table">
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
              {revisionPagination.pageItems.map((revision) => (
                <tr
                  className={selectedRevision?.id === revision.id ? "selected-row" : ""}
                  key={revision.id}
                  onClick={() => setSelectedRevisionId(revision.id)}
                  onKeyDown={(event) =>
                    activateRowOnKeyboard(event, () => setSelectedRevisionId(revision.id))
                  }
                  role="button"
                  tabIndex="0"
                >
                  <td>{revision.revision_number}</td>
                  <td>
                    <Badge value={revision.status} />
                  </td>
                  <td>{revision.schema_version}</td>
                  <td>
                    <span className="table-ellipsis" title={revision.content_hash}>
                      {shorten(revision.content_hash)}
                    </span>
                  </td>
                  <td>{formatDate(revision.published_at)}</td>
                </tr>
              ))}
            </tbody>
          </table>
          <Pagination
            label="Configuration revisions"
            onPageChange={revisionPagination.setPage}
            page={revisionPagination.page}
            pageCount={revisionPagination.pageCount}
            total={revisionPagination.total}
          />
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
              <ConfigurationEditor
                content={contentObject}
                contentText={contentText}
                error={fieldErrors.content}
                onChange={updateStructuredContent}
                onRawChange={updateContent}
                readOnly={!isAdmin || selectedRevision.status !== "DRAFT"}
              />
              {isAdmin && (
                <SecurityPackManager revision={selectedRevision} onComplete={onRefresh} />
              )}
              {contentText !== loadedContentText && (
                <div className="warning-banner">Unsaved changes</div>
              )}
              {isAdmin && (
                <div className="action-panel">
                  <label>
                    Change summary
                    <input
                      aria-describedby="change-summary-error"
                      aria-invalid={Boolean(fieldErrors.summary)}
                      maxLength={LIMITS.changeSummaryMax}
                      minLength={LIMITS.changeSummaryMin}
                      onChange={(event) => updateSummary(event.target.value)}
                      value={summary}
                    />
                    <FieldError id="change-summary-error" message={fieldErrors.summary} />
                  </label>
                  <div className="button-row">
                    <button
                      disabled={busy}
                      onClick={() => runAction("latest")}
                      type="button"
                    >
                      New Latest Config
                    </button>
                    <button
                      disabled={busy || selectedRevision.status !== "PUBLISHED"}
                      onClick={() => runAction("draft")}
                      title={
                        selectedRevision.status !== "PUBLISHED"
                          ? "Create Draft requires a PUBLISHED parent revision."
                          : undefined
                      }
                      type="button"
                    >
                      Create Draft
                    </button>
                    <button
                      disabled={busy || selectedRevision.status !== "DRAFT"}
                      onClick={() => runAction("save")}
                      type="button"
                    >
                      {busy ? "Working..." : "Save Draft"}
                    </button>
                    <button
                      disabled={
                        busy ||
                        selectedRevision.status !== "DRAFT" ||
                        contentText !== loadedContentText
                      }
                      onClick={() => runAction("validate")}
                      title={
                        contentText !== loadedContentText
                          ? "Save draft changes before validating."
                          : undefined
                      }
                      type="button"
                    >
                      Validate
                    </button>
                    <button
                      disabled={
                        busy ||
                        selectedRevision.status !== "DRAFT" ||
                        contentText !== loadedContentText
                      }
                      onClick={() => runAction("publish")}
                      title={
                        contentText !== loadedContentText
                          ? "Save draft changes before publishing."
                          : undefined
                      }
                      type="button"
                    >
                      Publish
                    </button>
                    <button
                      disabled={busy || selectedRevision.status !== "ARCHIVED"}
                      onClick={() => runAction("rollback")}
                      type="button"
                    >
                      Rollback
                    </button>
                    <button
                      className="danger-action"
                      disabled={busy || selectedRevision.status !== "DRAFT"}
                      onClick={() => runAction("delete")}
                      title={
                        selectedRevision.status !== "DRAFT"
                          ? "Only draft configurations can be deleted."
                          : undefined
                      }
                      type="button"
                    >
                      Delete
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

function FieldError({ id, message }) {
  return message ? (
    <span className="field-error" id={id}>
      {message}
    </span>
  ) : null;
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
