import { formatServerTime } from "../utils/serverTime.js";
import { useEffect, useRef, useState } from "react";

import { fetchAuditEventPage, safeErrorMessage } from "../api/client";
import { Pagination } from "../components/Pagination";

const PAGE_SIZE = 20;

const EMPTY_EVENTS = [];
function Audit({ events = EMPTY_EVENTS, loading = false }) {
  const [query, setQuery] = useState("");
  const [selectedEvent, setSelectedEvent] = useState(null);
  const [page, setPage] = useState(1);
  const [pageData, setPageData] = useState({
    items: events.slice(0, PAGE_SIZE),
    total: events.length,
  });
  const [pageLoading, setPageLoading] = useState(false);
  const [retryCount, setRetryCount] = useState(0);
  const detailHeading = useRef(null);
  const eventControl = useRef(null);
  const loadedRemotePage = useRef(false);
  const [error, setError] = useState("");

  useEffect(() => {
    let cancelled = false;
    setPageLoading(true);
    setError("");
    const timer = window.setTimeout(async () => {
      try {
        const result = await fetchAuditEventPage({
          limit: PAGE_SIZE,
          offset: (page - 1) * PAGE_SIZE,
          search: query,
        });
        if (cancelled) return;
        const total = Number(result?.total || 0);
        const pageCount = Math.max(1, Math.ceil(total / PAGE_SIZE));
        if (page > pageCount) {
          setPage(pageCount);
          return;
        }
        loadedRemotePage.current = true;
        setPageData({
          items: Array.isArray(result?.items) ? result.items : [],
          total,
        });
      } catch (err) {
        if (!cancelled) {
          setError(safeErrorMessage(err) || "Audit events could not be loaded.");
        }
      } finally {
        if (!cancelled) {
          setPageLoading(false);
        }
      }
    }, 200);

    return () => {
      cancelled = true;
      window.clearTimeout(timer);
    };
  }, [page, query, retryCount, events]);

  useEffect(() => {
    if (!loadedRemotePage.current && !query && page === 1 && events.length > 0) {
      setPageData({ items: events.slice(0, PAGE_SIZE), total: events.length });
    }
  }, [events, page, query]);

  useEffect(() => {
    if (selectedEvent && !pageData.items.some((item) => item.id === selectedEvent.id)) {
      setSelectedEvent(null);
    }
  }, [pageData.items, selectedEvent]);

  const pageCount = Math.max(1, Math.ceil(pageData.total / PAGE_SIZE));

  function openEvent(event, record) {
    eventControl.current = event.currentTarget;
    setSelectedEvent(record);
    window.requestAnimationFrame(() => detailHeading.current?.focus());
  }

  function closeEvent() {
    setSelectedEvent(null);
    eventControl.current?.focus();
  }

  if (loading && pageData.items.length === 0 && !pageLoading) {
    return (
      <section className="page-section">
        <div className="section-heading">
          <h2>Audit history</h2>
          <p>Loading audit events...</p>
        </div>
      </section>
    );
  }

  return (
    <section className="page-section">
      <div className="section-heading">
        <h2>Audit history</h2>
        <p>{pageData.total} event(s) · 20 per page</p>
      </div>
      {error && (
        <div className="error-banner investigation-error" role="alert">
          <span>{error} Previous results are retained when available.</span>
          <button onClick={() => setRetryCount((value) => value + 1)} type="button">Retry</button>
        </div>
      )}
      <p className="hint-text" role="note">See who changed what. Original records remain available in Details.</p>
      <div className="action-panel inline-form">
        <label>
          Search events
          <input
            onChange={(event) => {
              setQuery(event.target.value);
              setSelectedEvent(null);
              setPage(1);
            }}
            placeholder="action, actor, target..."
            type="search"
            value={query}
          />
        </label>
        {query && <button onClick={() => { setQuery(""); setSelectedEvent(null); setPage(1); }} type="button">Clear search</button>}
      </div>
      {pageLoading && <p className="hint-text" role="status">Searching audit events...</p>}
      <div aria-busy={pageLoading} aria-label="Audit events table" className="table-shell audit-table" tabIndex={0}>
        <table>
          <thead>
            <tr>
              <th>Time</th>
              <th>Actor</th>
              <th>Action</th>
              <th>Target</th>
              <th>Revision</th>
              <th>Result</th>
              <th>Reason</th>
              <th>Details</th>
            </tr>
          </thead>
          <tbody>
            {pageLoading && pageData.items.length === 0 ? (
              <tr>
                <td colSpan="8">Loading audit events...</td>
              </tr>
            ) : pageData.items.length === 0 ? (
              <tr>
                <td colSpan="8">{query ? "No audit events match this search." : "No audit events have been recorded."}</td>
              </tr>
            ) : (
              pageData.items.map((event) => {
                const target = [event.target_type, event.target_id].filter(Boolean).join(" / ");
                return (
                  <tr key={event.id}>
                    <td>{formatDate(event.timestamp)}</td>
                    <td>{event.actor_username_snapshot || "system"}</td>
                    <td><strong>{humanizeAction(event.action)}</strong><small className="audit-action-code">{event.action}</small></td>
                    <td><span className="audit-target" title={target}>{shorten(target, 42)}</span></td>
                    <td>{shorten(event.revision_id)}</td>
                    <td>
                      <span className={`badge ${event.result === "SUCCESS" ? "badge-success" : event.result === "FAILED" ? "badge-danger" : "badge-muted"}`}>
                        {event.result}
                      </span>
                    </td>
                    <td>{event.reason || "-"}</td>
                    <td>
                      <button aria-expanded={selectedEvent?.id === event.id} onClick={(click) => openEvent(click, event)} type="button">
                        View
                      </button>
                    </td>
                  </tr>
                );
              })
            )}
          </tbody>
        </table>
      </div>
      <Pagination
        label="Audit events"
        onPageChange={(next) => {
          setSelectedEvent(null);
          setPage(next);
        }}
        page={page}
        pageCount={pageCount}
        total={pageData.total}
      />
      {selectedEvent && (
        <section className="audit-event-detail investigation-detail" aria-labelledby="audit-detail-heading">
          <div className="section-heading compact-heading">
            <h3 id="audit-detail-heading" ref={detailHeading} tabIndex={-1}>{humanizeAction(selectedEvent.action)}</h3>
            <button onClick={closeEvent} type="button">Close details</button>
          </div>
          <dl className="inline-metadata audit-event-metadata">
            <div><dt>Actor</dt><dd>{selectedEvent.actor_username_snapshot || "system"}</dd></div>
            <div><dt>Time</dt><dd>{formatDate(selectedEvent.timestamp)}</dd></div>
            <div><dt>Event ID</dt><dd>{selectedEvent.id}</dd></div>
            <div><dt>Target</dt><dd>{[selectedEvent.target_type, selectedEvent.target_id].filter(Boolean).join(" / ") || "-"}</dd></div>
            <div><dt>Revision</dt><dd>{selectedEvent.revision_id || "-"}</dd></div>
            <div><dt>Result</dt><dd>{selectedEvent.result}</dd></div>
            <div><dt>Source IP</dt><dd>{selectedEvent.source_ip || "-"}</dd></div>
            <div><dt>Reason</dt><dd>{selectedEvent.reason || "-"}</dd></div>
          </dl>
          <AuditChangedFields before={selectedEvent.before_json} after={selectedEvent.after_json} />
          <details className="audit-technical-details">
            <summary>View original Before / After / Metadata JSON</summary>
            <div className="audit-json-grid">
              <AuditJson title="Before" value={selectedEvent.before_json} />
              <AuditJson title="After" value={selectedEvent.after_json} />
              <AuditJson title="Metadata" value={selectedEvent.metadata} />
            </div>
          </details>
        </section>
      )}
    </section>
  );
}

function humanizeAction(action) {
  if (!action) return "Unknown action";
  return String(action).toLowerCase().replaceAll("_", " ")
    .replace(/^./, (first) => first.toUpperCase());
}

function AuditChangedFields({ before, after }) {
  const oldFields = before && typeof before === "object" && !Array.isArray(before) ? before : null;
  const newFields = after && typeof after === "object" && !Array.isArray(after) ? after : null;
  if (!oldFields || !newFields) {
    return <p className="hint-text">A complete before/after comparison was not recorded for this event.</p>;
  }
  const changed = [...new Set([...Object.keys(oldFields), ...Object.keys(newFields)])]
    .filter((key) => JSON.stringify(oldFields[key]) !== JSON.stringify(newFields[key]));
  return (
    <section className="audit-changed-fields" aria-label="Changed top-level fields">
      <h4>Recorded changes (top-level fields)</h4>
      {changed.length === 0 ? (
        <p>No top-level field differences in the recorded before/after objects.</p>
      ) : (
        <ul>
          {changed.map((key) => (
            <li key={key}>
              <strong>{key}</strong><span aria-hidden="true"> · </span>
              {!(key in oldFields) ? " field added"
                : !(key in newFields) ? " field removed" : " field updated"}
            </li>
          ))}
        </ul>
      )}
      <p className="hint-text">Nested changes and original values remain in the raw JSON; this summary does not prove runtime effects.</p>
    </section>
  );
}

function AuditJson({ title, value }) {
  return (
    <div>
      <h4>{title}</h4>
      <pre className="json-block">{value ? JSON.stringify(value, null, 2) : "-"}</pre>
    </div>
  );
}

function formatDate(value) {
  return formatServerTime(value);
}

function shorten(value, maxLength = 22) {
  if (!value) {
    return "-";
  }
  return String(value).length > maxLength
    ? `${String(value).slice(0, 10)}...${String(value).slice(-6)}`
    : String(value);
}

export default Audit;
