import { formatServerTime } from "../utils/serverTime.js";
import { useEffect, useMemo, useRef, useState } from "react";
import { useDialogFocus } from "../utils/useDialogFocus";
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
  clearFieldError,
  parseJsonContent,
  validateChangeSummary,
} from "../utils/validation";
import ConfigurationEditor from "../components/ConfigurationEditor";
import PublicationPreview, { publishBlockReason } from "../components/PublicationPreview";
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
  const [validationReceipt, setValidationReceipt] = useState(null);
  const [busy, setBusy] = useState(false);
  const [loadedRevision, setLoadedRevision] = useState(null);
  // CF-01: publication requires a reviewed, backend-computed preview.
  const [publishReview, setPublishReview] = useState(null);
  const [publicationPreview, setPublicationPreview] = useState(null);
  const actionLock = useRef(false);
  const publishDialogRef = useRef(null);
  useDialogFocus(Boolean(publishReview), publishDialogRef);
  useEffect(() => {
    if (!publishReview) return undefined;
    function handleEscape(event) {
      if (event.key === "Escape" && !actionLock.current) {
        event.preventDefault();
        setPublishReview(null);
      }
    }
    window.addEventListener("keydown", handleEscape);
    return () => window.removeEventListener("keydown", handleEscape);
  }, [publishReview]);
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

  const hasUnsavedChanges = contentText !== loadedContentText;
  const hasRevisionConflict = Boolean(
    selectedRevision && loadedRevision?.id === selectedRevision.id &&
    loadedRevision.hash !== selectedRevision.content_hash && hasUnsavedChanges
  );

  function loadEditor(revision) {
    setValidationReceipt(null);
    const text = JSON.stringify(revision.content, null, 2);
    setContentText(text);
    setLoadedContentText(text);
    setContentObject(revision.content);
    setLoadedRevision({ id: revision.id, hash: revision.content_hash });
    setFieldErrors({});
  }

  useEffect(() => {
    if (!selectedRevision || hasRevisionConflict ||
        (loadedRevision?.id === selectedRevision.id && loadedRevision.hash === selectedRevision.content_hash)) return;
    loadEditor(selectedRevision);
  }, [selectedRevision, loadedRevision, hasRevisionConflict]);

  function selectRevision(revision) {
    if (busy || revision.id === selectedRevision?.id) return;
    if (hasUnsavedChanges && !window.confirm("Discard unsaved edits and switch revisions?")) return;
    setSelectedRevisionId(revision.id);
    setValidationReceipt(null);
  }

  async function runAction(action) {
    if (!isAdmin || actionLock.current || (!selectedRevision && action !== "latest")) return;
    if (hasRevisionConflict && action === "save") return;
    if (["latest", "draft", "delete", "rollback"].includes(action) &&
        hasUnsavedChanges && !window.confirm("Continue and discard unsaved edits?")) return;
    const summaryError = validateChangeSummary(summary);
    const nextErrors = {};
    if (summaryError) {
      nextErrors.summary = summaryError;
    }
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
    if (action === "publish" && publishReview?.revisionId !== selectedRevision.id) {
      // First step: open the preview. Publishing happens from the dialog.
      setPublicationPreview(null);
      setPublishReview({ revisionId: selectedRevision.id, revisionNumber: selectedRevision.revision_number });
      return;
    }
    if (action === "publish" && publishBlockReason(publicationPreview)) {
      return;
    }
    setError("");
    setMessage("");
    if (action !== "validate") setValidationReceipt(null);
    actionLock.current = true;
    setBusy(true);
    try {
      let updatedRevision = null;
      if (action === "latest") {
        updatedRevision = await createLatestConfigRevision(summary);
      } else if (action === "draft") {
        updatedRevision = await createDraftRevision(selectedRevision.id, summary);
      } else if (action === "save") {
        updatedRevision = await patchConfigRevision(
          selectedRevision.id, parsedContent, summary, loadedRevision?.hash ?? selectedRevision.content_hash
        );
      } else if (action === "validate") {
        const receipt = await validateConfigRevision(selectedRevision.id, summary);
        if (receipt?.valid !== true || receipt?.content_hash !== selectedRevision.content_hash) {
          throw new Error("Validation receipt does not match the selected revision content; do not publish this draft.");
        }
        setValidationReceipt({ revisionId: selectedRevision.id, hash: receipt.content_hash });
      } else if (action === "publish") {
        updatedRevision = await publishConfigRevision(
          selectedRevision.id, summary, publicationPreview.preview_fingerprint,
        );
        setPublishReview(null);
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
      if (action === "save") {
        setLoadedContentText(contentText);
      }
      const messages = {
        latest: "A draft using the latest schema is ready to edit.",
        draft: "Draft created. Edit and validate it before publishing.",
        save: "Draft saved. Validate it before publishing.",
        validate: "Validation completed. Review the draft before publishing.",
        publish: "The revision is published and signed.",
        rollback: "A signed revision was published from the selected archive.",
        delete: "Draft deleted.",
      };
      setMessage(messages[action]);
      await onRefresh?.();
    } catch (err) {
      setError(err.message || "Configuration operation failed");
    } finally {
      actionLock.current = false;
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

  if (loading && !selectedRevision && revisions.length === 0) {
    return (
      <section className="page-section">
        <div className="section-heading">
          <h2>Security rules</h2>
          <p>Loading revisions...</p>
        </div>
      </section>
    );
  }

  return (
    <section className="page-section rules-page">
      <div className="section-heading">
        <h2>Security rules</h2>
        <p>Review and publish security rules.</p>
      </div>
      <p className="hint-text" role="note">Edits do not take effect until an administrator publishes them.</p>
      {message && <div className="success-banner" role="status">{message}</div>}
      {validationReceipt && selectedRevision?.id === validationReceipt.revisionId &&
        selectedRevision?.content_hash === validationReceipt.hash && !hasUnsavedChanges && (
        <div className="detail-panel" role="status">
          <strong>Validated draft receipt</strong>
          <p>Validation passed for revision #{selectedRevision.revision_number}.</p>
          <p>Content SHA-256: <code>{validationReceipt.hash}</code>.</p>
          <p>The validation applies only to this exact content. It does not publish, sign or activate the revision. A subsequent edit requires a new validation.</p>
        </div>
      )}
      {error && <div className="error-banner" role="alert">{error}</div>}
      {publishReview && isAdmin && (
        <div className="modal-backdrop" role="presentation">
          <section aria-modal="true" aria-labelledby="publish-review-title" className="modal-panel"
            ref={publishDialogRef} role="dialog" tabIndex={-1}>
            <h3 id="publish-review-title">Review publication of revision #{publishReview.revisionNumber}</h3>
            <PublicationPreview draftId={publishReview.revisionId} onChange={setPublicationPreview} />
            <p>Change summary: {summary}</p>
            <div className="button-row">
              <button className="danger-action"
                disabled={busy || Boolean(publishBlockReason(publicationPreview))}
                aria-describedby={publishBlockReason(publicationPreview) ? "publish-unavailable-reason" : undefined}
                onClick={() => runAction("publish")} type="button">
                {busy ? "Publishing..." : "Publish and sign"}
              </button>
              <button className="secondary-action" disabled={busy}
                onClick={() => setPublishReview(null)} type="button">Cancel</button>
            </div>
            {publishBlockReason(publicationPreview) && (
              <p className="hint-text" role="note" id="publish-unavailable-reason">
                Publication unavailable: {publishBlockReason(publicationPreview)}
              </p>
            )}
          </section>
        </div>
      )}

      <div className="summary-grid">
        <Summary label="Active revision" value={activeRevision?.revision_number ?? "-"} />
        <Summary label="Schema version" value={activeRevision?.schema_version ?? "-"} />
        <Summary label="Policy settings" value={Object.keys(activeRevision?.content?.policy_settings?.rules || {}).length} />
        <Summary label="Active revision status" value={activeRevision?.status || "Not published"} />
      </div>

      <nav aria-label="Security rules sections" className="management-jump-links">
        <a href="#configuration-history">Revision history</a>
        <a href="#configuration-editor">Revision details and editor</a>
        {isAdmin && <a href="#configuration-actions">Draft and publication actions</a>}
      </nav>
      <div className="configuration-layout management-config-layout">
        <section aria-labelledby="configuration-history-heading" id="configuration-history">
          <h3 id="configuration-history-heading">Revision history</h3>
          <div aria-label="Configuration revisions table" className="table-shell configuration-versions-table" tabIndex={0}>
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
                <tr className={(selectedRevision?.id === revision.id ? "selected-row " : "") + "selectable-record"} key={revision.id}
                  onClick={(event) => { if (!event.target.closest("button")) selectRevision(revision); }}>
                  <td><button aria-pressed={selectedRevision?.id === revision.id} className="record-link" disabled={busy}
                    onClick={() => selectRevision(revision)} type="button">#{revision.revision_number}</button></td>
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
          </div>
          <Pagination
            label="Configuration revisions"
            onPageChange={revisionPagination.setPage}
            page={revisionPagination.page}
            pageCount={revisionPagination.pageCount}
            total={revisionPagination.total}
          />
        </section>

        <div className="detail-panel" id="configuration-editor">
          <h3>Revision details</h3>
          {selectedRevision ? (
            <>
              <div className="configuration-selection-summary" role="status">
                <strong>Selected revision #{selectedRevision.revision_number}</strong>
                <Badge value={selectedRevision.status} />
                <span>
                  {selectedRevision.id === activeRevision?.id
                    ? "This is the current published revision."
                    : selectedRevision.status === "DRAFT"
                      ? "This is a draft. No runtime policy has been changed by editing it."
                      : "This is not the currently published revision."}
                </span>
              </div>
              <p className="hint-text" role="note">
                A stored signature and content fingerprint describe this
                published revision; they are not evidence that every running
                Gateway instance has loaded and verified it. Compare the
                active revision, Gateway status and startup integrity checks
                in <a href="?view=operations">System health</a> before
                relying on a Runtime policy change. A draft validation
                receipt does not replace that runtime verification.
              </p>
              <details className="configuration-technical-details">
                <summary>View revision IDs, content fingerprint and signature metadata</summary>
                <dl className="compact-dl">
                  <div><dt>id</dt><dd>{selectedRevision.id}</dd></div>
                  <div><dt>content_hash</dt><dd>{selectedRevision.content_hash}</dd></div>
                  <div><dt>signature</dt><dd>{selectedRevision.signature || "-"}</dd></div>
                  <div><dt>signature_key_id</dt><dd>{selectedRevision.signature_key_id || "-"}</dd></div>
                </dl>
              </details>
              {hasRevisionConflict && (
                <div className="warning-banner" role="alert">
                  <p>This draft changed on the server while you were editing. Your local text is still available to copy.</p>
                  <button onClick={() => {
                    if (window.confirm("Discard local edits and load the updated draft?")) loadEditor(selectedRevision);
                  }} type="button">Load updated draft</button>
                </div>
              )}
              <ConfigurationEditor
                content={contentObject}
                contentText={contentText}
                error={fieldErrors.content}
                onChange={updateStructuredContent}
                onRawChange={updateContent}
                readOnly={busy || !isAdmin || selectedRevision.status !== "DRAFT"}
              />
              {isAdmin && (
                <SecurityPackManager revision={selectedRevision} onComplete={onRefresh} />
              )}
              {contentText !== loadedContentText && (
                <div className="warning-banner" role="status">Unsaved changes</div>
              )}
              {isAdmin && (
                <div className="action-panel" id="configuration-actions">
                  <h4>Draft and publication actions</h4>
                  <p className="hint-text" role="note">
                    Prepare a draft, save all edits, validate the draft, then publish it deliberately.
                    Rollback creates a new signed revision; deleting is only allowed for DRAFT records.
                  </p>
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
                      aria-describedby={selectedRevision.status !== "PUBLISHED" ? "revision-action-prerequisites" : undefined}
                      type="button"
                    >
                      Create Draft
                    </button>
                    <button
                      disabled={busy || hasRevisionConflict || selectedRevision.status !== "DRAFT"}
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
                      aria-describedby={selectedRevision.status !== "DRAFT" || hasUnsavedChanges ? "revision-action-prerequisites" : undefined}
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
                      aria-describedby={selectedRevision.status !== "DRAFT" || hasUnsavedChanges ? "revision-action-prerequisites" : undefined}
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
                      aria-describedby={selectedRevision.status !== "DRAFT" ? "revision-action-prerequisites" : undefined}
                      type="button"
                    >
                      Delete
                    </button>
                  </div>
                  <p className="hint-text" role="note" id="revision-action-prerequisites">
                    Available actions depend on the selected revision, not on other published versions.
                    {selectedRevision.status !== "DRAFT" &&
                      " Editing, validation, publishing and deletion require a DRAFT revision."}
                    {selectedRevision.status !== "PUBLISHED" &&
                      " Create Draft requires a PUBLISHED parent revision."}
                    {selectedRevision.status !== "ARCHIVED" &&
                      " Rollback requires an ARCHIVED revision."}
                    {hasUnsavedChanges && " Save your local draft changes before validating or publishing."}
                    {hasRevisionConflict &&
                      " This revision changed after you started editing. Refresh it before saving; do not overwrite newer content."}
                  </p>
                </div>
              )}
            </>
          ) : (
            <div className="empty-state" id="configuration-actions">
              <p>{selectedRevisionId && loading ? "Loading selected revision..." : "No configuration revision selected."}</p>
              {isAdmin && !selectedRevisionId && (
                <div className="action-panel">
                  <label>Change summary
                    <input aria-describedby="empty-change-summary-error" aria-invalid={Boolean(fieldErrors.summary)}
                      maxLength={LIMITS.changeSummaryMax} onChange={(event) => updateSummary(event.target.value)} value={summary} />
                    <FieldError id="empty-change-summary-error" message={fieldErrors.summary} />
                  </label>
                  <button disabled={busy} onClick={() => runAction("latest")} type="button">New Latest Config</button>
                </div>
              )}
            </div>
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
  return formatServerTime(value);
}

export default SecurityConfiguration;
