import { formatServerTime } from "../utils/serverTime.js";
import { useEffect, useRef, useState } from "react";

import { fetchAuditEventPage, fetchRelatedSecurityTimeline, safeErrorMessage } from "../api/client";
import { Pagination } from "../components/Pagination";
import { auditTargetLink } from "../utils/operationNavigation.js";

const PAGE_SIZE = 20;

const EMPTY_EVENTS = [];
function Audit({ events = EMPTY_EVENTS, loading = false }) {
  const [query, setQuery] = useState("");
  const [selectedEventId, setSelectedEventId] = useState(null);
  const [page, setPage] = useState(1);
  const [snapshot, setSnapshot] = useState(null);
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
          snapshotAt: snapshot?.at || null,
          snapshotId: snapshot?.id || null,
        });
        if (cancelled) return;
        const total = Number(result?.total || 0);
        const pageCount = Math.max(1, Math.ceil(total / PAGE_SIZE));
        if (page > pageCount) {
          setPage(pageCount);
          return;
        }
        loadedRemotePage.current = true;
        if (!snapshot && result?.snapshot_at && result?.snapshot_id) {
          setSnapshot({ at: result.snapshot_at, id: result.snapshot_id });
        }
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

  const selectedEvent = pageData.items.find((item) => item.id === selectedEventId);

  const pageCount = Math.max(1, Math.ceil(pageData.total / PAGE_SIZE));

  function openEvent(event, record) {
    eventControl.current = event.currentTarget;
    setSelectedEventId(record.id);
    window.requestAnimationFrame(() => detailHeading.current?.focus());
  }

  function closeEvent() {
    setSelectedEventId(null);
    eventControl.current?.focus();
  }

  function refreshResults() {
    setSnapshot(null);
    setSelectedEventId(null);
    setPage(1);
    setRetryCount((value) => value + 1);
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
      <RelatedSecurityTimeline />
      {error && (
        <div className="error-banner investigation-error" role="alert">
          <span>{error} Previous results are retained when available.</span>
          <button onClick={() => setRetryCount((value) => value + 1)} type="button">Retry</button>
        </div>
      )}
      <p className="hint-text" role="note">See who changed what. Original records remain available in Details.
        {snapshot ? " This search is anchored to the same latest-event boundary during pagination; new events do not shift the result pages. Use Refresh results to include newer events." : " A consistent page boundary is established when results load."}
      </p>
      <div className="action-panel inline-form">
        <label>
          Search events
          <input
            onChange={(event) => {
              setQuery(event.target.value);
              setSnapshot(null);
              setSelectedEventId(null);
              setPage(1);
            }}
            placeholder="action, actor, target..."
            type="search"
            value={query}
          />
        </label>
        {query && <button onClick={() => { setQuery(""); refreshResults(); }} type="button">Clear search</button>}
        <button type="button" disabled={pageLoading} onClick={refreshResults}>Refresh results</button>
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
          setSelectedEventId(null);
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
          <div className="detail-panel" aria-label="Audit target trace">
            <h4>Trace this event</h4>
            <p>This event is the historical audit receipt, not a live
              verification of the target object's current security status.</p>
            {(() => {
              const view = ({
                mcp_tool: "analysis",
                mcp_server: "inventory",
                tool_protocol_observation: "analysis",
                control_plane_config_revision: "config",
                cloud_scan: "cloud",
                cloud_environment: "cloud",
                runtime_operation: "operations",
                runtime_logs: "operations",
                control_plane_user: "users",
              })[selectedEvent.target_type];
              const exactTargetLink = auditTargetLink(selectedEvent.target_type, selectedEvent.target_id);
              return view ? (
                <p>Open the related <a href={exactTargetLink || "?view=" + view}>
                  {view === "operations" ? "System health" : view}</a> view
                  {exactTargetLink
                    ? <> to investigate the exact recorded target <code>{selectedEvent.target_id}</code>.
                        The destination will verify that the same target still exists,
                        and never substitute another record or replay an MCP call.</>
                    : <> to locate the recorded target ID <code>{selectedEvent.target_id}</code> manually;
                        this is a module-level navigation, not a verified target link.</>}
                  Historical evidence is not an independent verification of current authorization.</p>
              ) : <p>No module deep link is defined for target type
                <code>{selectedEvent.target_type || "unrecorded"}</code>.
                Use the recorded type and ID to investigate manually.</p>;
            })()}
            {selectedEvent.revision_id && <p>Recorded configuration revision:
              <code>{selectedEvent.revision_id}</code>. Compare it with the
              current published revision before taking action.</p>}
          </div>
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

function RelatedSecurityTimeline() {
  const [kind, setKind] = useState("runtime_operation");
  const [targetId, setTargetId] = useState("");
  const [result, setResult] = useState(null);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const request = useRef(0);
  useEffect(() => () => { request.current += 1; }, []);
  const validId = /^[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}$/.test(targetId);

  async function show(event) {
    event.preventDefault();
    if (busy || !validId) return;
    const generation = ++request.current;
    setBusy(true);
    setError("");
    setResult(null);
    try {
      const response = await fetchRelatedSecurityTimeline(kind, targetId);
      if (generation === request.current) setResult(response);
    } catch (err) {
      if (generation === request.current) {
        setError(safeErrorMessage(err) || "Related audit evidence is unavailable.");
      }
    } finally {
      if (generation === request.current) setBusy(false);
    }
  }

  function resetResponse() {
    request.current += 1;
    setResult(null);
    setError("");
    setBusy(false);
  }

  return (
    <section className="detail-panel" aria-label="Related security event timeline">
      <h3>Related security timeline</h3>
      <p>Correlate recorded events by an exact immutable operation or scan ID.
        Similar names, timestamps and resource labels are never treated as proof of a connection.</p>
      <form className="inline-form" onSubmit={show}>
        <label>Correlation target
          <select value={kind} onChange={(event) => {
            setKind(event.target.value); resetResponse();
          }}>
            <option value="runtime_operation">MCP operation</option>
            <option value="cloud_scan">Cloud audit scan</option>
          </select>
        </label>
        <label>Recorded UUID
          <input type="text" value={targetId}
            maxLength={36} placeholder="xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
            onChange={(event) => {
              setTargetId(event.target.value.trim().toLowerCase());
              resetResponse();
            }}/>
        </label>
        <button type="submit" disabled={!validId || busy}>
          {busy ? "Checking..." : "Show related events"}
        </button>
      </form>
      {error && <p role="alert">{error} No actions were replayed.</p>}
      {result && <div aria-label="Related security records">
        <p>Recorded target: <code>{targetId}</code>.</p>
        <p role="status">{result.events.length} stored related event(s) returned.
          {result.truncated ? " The response is bounded and additional events may exist." : ""}
        </p>
        {result.events.length ? <ol>
          {result.events.map((item) => <li key={item.source + ":" + item.id}>
            <strong>{item.source.replaceAll("_", " ")}</strong>
            {" · "}{formatDate(item.timestamp)}
            {" · "}{item.event_code}
            {item.result && <>{" · "}{item.result}</>}
            {" · "}<code>{item.id}</code>
          </li>)}
        </ol> : <p>No events were found under this exact ID. This does not establish that no activity occurred.</p>}
        <p><strong>Evidence limits:</strong> {result.limitations}</p>
      </div>}
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
