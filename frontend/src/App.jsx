import { useEffect, useMemo, useRef, useState } from "react";

import {
  cancelControlPlaneReads,
  fetchActiveConfigRevision,
  fetchAllToolAnalyses,
  fetchAuditEvents,
  fetchConfigRevisions,
  fetchEmergencyDenies,
  fetchHealth,
  fetchLocalRuntimeStatus,
  fetchOperationsSummary,
  fetchControlPlaneMe,
  hasControlPlaneSession,
  setCsrfToken,
  SESSION_EXPIRED_EVENT,
  loginControlPlane,
  logoutControlPlane,
  fetchPolicies,
  fetchRuntimeLogs,
  fetchServers,
  fetchTools,
  fetchUsers,
} from "./api/client";
import Dashboard from "./pages/Dashboard";
import BuildSecurity from "./pages/BuildSecurity";
import CloudSecurity from "./pages/CloudSecurity";
import Audit from "./pages/Audit";
import EmergencyDeny from "./pages/EmergencyDeny";
import Inventory from "./pages/Inventory";
import Operations from "./pages/Operations";
import RuntimeLogs from "./pages/RuntimeLogs";
import SecurityConfiguration from "./pages/SecurityConfiguration";
import ToolAnalysis from "./pages/ToolAnalysis";
import Users from "./pages/Users";
import AccountPasswordPanel from "./components/accountpasswordpanel.jsx";
import { LIMITS, clearFieldError, validateLogin } from "./utils/validation";
import { parseOAuthReturn, oauthReturnDescription } from "./utils/oauthreturn.js";
import { operationFromQuery, recordTypeForView } from "./utils/operationNavigation.js";
import ExactSecurityRecord from "./components/ExactSecurityRecord";
import { normalizeOutcomeState } from "./utils/toolQueues.js";

const pages = [
  { id: "dashboard", label: "Home", group: "Home" },
  { id: "inventory", label: "MCP tools", group: "Tools" },
  { id: "analysis", label: "Security review", group: "Tools" },
  { id: "build", label: "Code scans", group: "Security" },
  { id: "cloud", label: "Cloud security", group: "Security" },
  { id: "config", label: "Security rules", group: "Security" },
  { id: "emergency", label: "Emergency block", group: "Security" },
  { id: "runtime", label: "Tool activity", group: "Monitoring" },
  { id: "operations", label: "System health", group: "Monitoring" },
  { id: "audit", label: "Audit history", group: "Monitoring" },
  { id: "users", label: "Users", group: "Settings", adminOnly: true },
];
const navigationGroups = ["Home", "Tools", "Security", "Monitoring", "Settings"];
const routeReads = {
  dashboard: ["health", "runtimeStatus", "servers", "tools", "runtimeLogs", "activeRevision", "emergencyDenies", "audit"],
  inventory: ["servers", "tools", "runtimeStatus"],
  analysis: ["servers", "tools", "analyses"],
  config: ["revisions", "activeRevision", "policies"],
  build: ["servers", "revisions", "activeRevision"],
  runtime: ["servers", "tools"],
  operations: ["operations"],
  emergency: ["emergencyDenies"],
  users: ["users"],
};
const SESSION_EXPIRED_NOTICE = "Your session expired or was revoked. Sign in again.";

const EMPTY_RUNTIME_LOG_PAGE = {
  items: [],
  next_cursor: null,
  has_more: false,
  summary: { total: 0, allowed: 0, blocked: 0, executed: 0, skipped: 0, errors: 0 },
};

function pageFromLocation() {
  if (parseOAuthReturn(window.location.hash)) return "inventory";
  const view = new URLSearchParams(window.location.search).get("view");
  return pages.some((page) => page.id === view) ? view : "dashboard";
}

function toolFromLocation() {
  if (pageFromLocation() !== "analysis") return null;
  return new URLSearchParams(window.location.search).get("tool");
}

// UX-04: exact landing state for queue links (shareable, survives reload/Back).
function entryOptionsFromLocation() {
  const params = new URLSearchParams(window.location.search);
  const view = pageFromLocation();
  return {
    record: recordTypeForView(view) ? params.get("record") : null,
    queue: view === "analysis" ? params.get("queue") : null,
    section: view === "operations" ? params.get("section") : null,
    outcome: view === "runtime" ? normalizeOutcomeState(params.get("outcome")) : null,
    action: view === "inventory" && params.get("action") === "connect" ? "connect" : null,
  };
}

function pageUrl(pageId, toolId = null, options = {}) {
  const url = new URL(window.location.href);
  if (pageId === "dashboard") url.searchParams.delete("view");
  else url.searchParams.set("view", pageId);
  if (pageId === "analysis" && toolId !== null) url.searchParams.set("tool", toolId);
  else url.searchParams.delete("tool");
  // A normal navigation must not accidentally keep a previous investigation.
  url.searchParams.delete("operation_id");
  for (const key of ["queue", "section", "outcome", "scan", "env", "kind", "task", "action", "record"]) url.searchParams.delete(key);
  if (pageId === "inventory" && options.action === "connect") url.searchParams.set("action", "connect");
  if (pageId === "analysis" && options.queue) url.searchParams.set("queue", options.queue);
  if (pageId === "operations" && options.section) url.searchParams.set("section", options.section);
  if (pageId === "runtime" && normalizeOutcomeState(options.outcome)) {
    url.searchParams.set("outcome", options.outcome);
  }
  url.hash = "";
  return url;
}

// UX-16: explicit access boundary; the viewer session never reads the data.
export function AccessDenied({ pageLabel, onHome }) {
  const canGoBack = typeof window !== "undefined" && window.history.length > 1;
  return (
    <section className="page-section" aria-labelledby="access-denied-title">
      <div className="section-heading">
        <h2 id="access-denied-title">Administrator access required</h2>
      </div>
      <div className="detail-panel access-denied-panel" role="status">
        <p>{pageLabel} can only be opened by an administrator. Nothing was read or changed with your session.</p>
        <p>If you followed a link from an audit or activity record, ask an administrator to open it, or continue with the read-only views.</p>
        <div className="button-row">
          {canGoBack && <button className="secondary-action" onClick={() => window.history.back()} type="button">Go back</button>}
          <button className="console-primary" onClick={onHome} type="button">Return to Home</button>
        </div>
      </div>
    </section>
  );
}

const navIcons = {
  dashboard: "M3 10.5 12 3l9 7.5V20H3z M9 20v-6h6v6",
  inventory: "M4 4h16v6H4z M4 14h16v6H4z M7 7h.01 M7 17h.01",
  analysis: "M12 22s7-3 7-10V6l-7-3-7 3v6c0 7 7 10 7 10z M9 12l2 2 4-4",
  build: "m8 6-5 6 5 6m8-12 5 6-5 6m-3-15-2 18",
  cloud: "M7 18h11a4 4 0 1 0-.7-7.9A5.5 5.5 0 0 0 6.6 10 4 4 0 0 0 7 18z",
  config: "M4 6h16M4 12h16M4 18h16 M8 4v4m8 2v4m-6 2v4",
  emergency: "M8 3h8l5 5v8l-5 5H8l-5-5V8z M12 7v6m0 4h.01",
  runtime: "M3 12h4l3-7 4 14 3-7h4",
  operations: "M4 18v-5m5 5V6m5 12v-8m5 8V4M3 21h18",
  audit: "M7 3h8l4 4v14H5V3z M14 3v5h5M8 12h8m-8 4h8",
  users: "M16 21v-2a4 4 0 0 0-4-4H7a4 4 0 0 0-4 4v2 M21 21v-2a4 4 0 0 0-3-4 M13 7a3 3 0 1 1-6 0 3 3 0 0 1 6 0z M16 4a3 3 0 0 1 0 6",
};

function NavigationIcon({ page }) {
  return (
    <svg aria-hidden="true" focusable="false" viewBox="0 0 24 24" fill="none"
      stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" strokeLinejoin="round">
      <path d={navIcons[page]} />
    </svg>
  );
}

function App() {
  const [requestedPage, setActivePage] = useState(pageFromLocation);
  const [oauthReturn, setOAuthReturn] = useState(() => parseOAuthReturn(window.location.hash));
  const [mobileNavOpen, setMobileNavOpen] = useState(false);
  const mobileNavButtonRef = useRef(null);
  const [analysisEntryToolId, setAnalysisEntryToolId] = useState(toolFromLocation);
  const [operationEntryId, setOperationEntryId] = useState(() => operationFromQuery(window.location.search));
  const [entryOptions, setEntryOptions] = useState(() => entryOptionsFromLocation());
  const mainRef = useRef(null);
  const focusMainOnRender = useRef(false);
  const [user, setUser] = useState(null);
  const [authLoading, setAuthLoading] = useState(true);
  const [loginError, setLoginError] = useState("");
  const [loginNotice, setLoginNotice] = useState("");
  const [sessionCheckFailed, setSessionCheckFailed] = useState(false);
  const [accountOpen, setAccountOpen] = useState(false);
  const [logoutError, setLogoutError] = useState("");
  const [signingOut, setSigningOut] = useState(false);
  const [readStates, setReadStates] = useState({});
  // Per-source successful response receipt. Do not equate it with source measurement time.
  const [readTimestamps, setReadTimestamps] = useState({});
  const [health, setHealth] = useState(null);
  const [runtimeStatus, setRuntimeStatus] = useState(null);
  const [operationsSummary, setOperationsSummary] = useState(null);
  const [servers, setServers] = useState([]);
  const [tools, setTools] = useState([]);
  const [policies, setPolicies] = useState([]);
  const [runtimeLogPage, setRuntimeLogPage] = useState(EMPTY_RUNTIME_LOG_PAGE);
  const [toolAnalyses, setToolAnalyses] = useState([]);
  const [configRevisions, setConfigRevisions] = useState([]);
  const [activeRevision, setActiveRevision] = useState(null);
  const [emergencyDenies, setEmergencyDenies] = useState([]);
  const [auditEvents, setAuditEvents] = useState([]);
  const [users, setUsers] = useState([]);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(true);
  const [dashboardRefreshedAt, setDashboardRefreshedAt] = useState(null);
  // UX-03: header Refresh is an intent for the *visible* view as well as the
  // shared status reads; views that own their query re-read it on change.
  const [viewRefreshToken, setViewRefreshToken] = useState(0);
  const loadDataGeneration = useRef(0);
  const isAdmin = user?.role === "ADMIN";
  // UX-16: a protected URL opened by a non-admin shows an explicit access
  // boundary at the same address instead of silently substituting Home.
  const accessDenied = Boolean(user) && !isAdmin
    && Boolean(pages.find((page) => page.id === requestedPage)?.adminOnly);
  const activePage = accessDenied ? "access-denied" : requestedPage;
  const currentPage = pages.find((page) => page.id === (accessDenied ? requestedPage : activePage));
  const activeServers = useMemo(
    () => servers.filter((server) => server.status !== "archived"),
    [servers],
  );
  const activeServerIds = useMemo(
    () => new Set(activeServers.map((server) => server.id)),
    [activeServers],
  );
  const activeTools = useMemo(
    () => tools.filter((tool) => activeServerIds.has(tool.server_id)),
    [activeServerIds, tools],
  );
  const activeToolIds = useMemo(
    () => new Set(activeTools.map((tool) => tool.id)),
    [activeTools],
  );
  const activeToolAnalyses = useMemo(
    () => toolAnalyses.filter((analysis) => activeToolIds.has(analysis.tool_id)),
    [activeToolIds, toolAnalyses],
  );

  function navigateToPage(pageId, toolId = null, options = {}) {
    if (pageId !== requestedPage) {
      loadDataGeneration.current += 1;
      cancelControlPlaneReads();
    }
    focusMainOnRender.current = true;
    setMobileNavOpen(false);
    const requestedTool = pageId === "analysis" && toolId !== null ? String(toolId) : null;
    const url = pageUrl(pageId, requestedTool, options);
    setEntryOptions({
      queue: pageId === "analysis" ? options.queue || null : null,
      section: pageId === "operations" ? options.section || null : null,
      outcome: pageId === "runtime" ? normalizeOutcomeState(options.outcome) : null,
      action: pageId === "inventory" && options.action === "connect" ? "connect" : null,
    });
    if (url.href !== window.location.href) {
      window.history.pushState(null, "", url);
      window.scrollTo({ top: 0, behavior: "instant" });
    }
    if (pageId === requestedPage && requestedTool === analysisEntryToolId) {
      mainRef.current?.focus({ preventScroll: true });
      focusMainOnRender.current = false;
    }
    setAnalysisEntryToolId(requestedTool);
    setOperationEntryId(null);
    setActivePage(pageId);
  }

  function endSession({ error: sessionError = "", notice = "" } = {}) {
    loadDataGeneration.current += 1;
    setCsrfToken("");
    setUser(null);
    setAccountOpen(false);
    setMobileNavOpen(false);
    setReadStates({});
    setReadTimestamps({});
    setHealth(null);
    setRuntimeStatus(null);
    setOperationsSummary(null);
    setServers([]);
    setTools([]);
    setPolicies([]);
    setRuntimeLogPage(EMPTY_RUNTIME_LOG_PAGE);
    setToolAnalyses([]);
    setConfigRevisions([]);
    setActiveRevision(null);
    setEmergencyDenies([]);
    setAuditEvents([]);
    setUsers([]);
    setDashboardRefreshedAt(null);
    setError("");
    setLogoutError("");
    setSessionCheckFailed(false);
    setLoginError(sessionError);
    setLoginNotice(notice);
  }

  useEffect(() => {
    if (!oauthReturn) return;
    // A backend callback uses a fragment, so OAuth tokens must not be
    // inferred or stored by this frontend. Remove only the result marker.
    window.history.replaceState(null, "", pageUrl("inventory"));
  }, [oauthReturn]);

  async function restoreSession({ focusContent = false } = {}) {
    setLoginError("");
    setSessionCheckFailed(false);
    if (!hasControlPlaneSession()) {
      setUser(null);
      setAuthLoading(false);
      return;
    }
    setAuthLoading(true);
    try {
      const me = await fetchControlPlaneMe();
      focusMainOnRender.current = focusContent;
      setUser(me);
    } catch (err) {
      setUser(null);
      const expired = err?.status === 401;
      setSessionCheckFailed(!expired);
      setLoginError(expired ? SESSION_EXPIRED_NOTICE
        : "The sign-in service could not verify your session. Check your connection and try again.");
    } finally {
      setAuthLoading(false);
    }
  }

  async function handleLogin(username, password) {
    try {
      setLoginError("");
      setLoginNotice("");
      const payload = await loginControlPlane(username, password);
      setSessionCheckFailed(false);
      focusMainOnRender.current = true;
      setUser(payload.user);
      return true;
    } catch (err) {
      if (err.status === 401) setLoginError("Invalid username or password.");
      else if (err.status === 429) setLoginError("Too many sign-in attempts. Wait and try again.");
      else setLoginError("The sign-in service could not complete your request. Check your connection and try again.");
      return false;
    }
  }

  async function handleLogout() {
    setSigningOut(true);
    setLogoutError("");
    try {
      await logoutControlPlane();
      endSession({ notice: "You signed out." });
    } catch (err) {
      if (err.status === 401) endSession({ error: SESSION_EXPIRED_NOTICE });
      else setLogoutError("Sign out could not be confirmed. Check your connection and try again.");
    } finally {
      setSigningOut(false);
    }
  }

  async function loadData({ verifySession = true } = {}) {
    const generation = loadDataGeneration.current + 1;
    loadDataGeneration.current = generation;
    setLoading(true);
    setError("");
    try {
      let refreshedUser = null;
      try {
        refreshedUser = verifySession ? await fetchControlPlaneMe() : user;
      } catch (err) {
        if (generation !== loadDataGeneration.current) {
          return;
        }
        if (err?.status === 401) {
          endSession({ error: SESSION_EXPIRED_NOTICE });
          return;
        }
        setError("The sign-in service could not verify your session. Check your connection, then select Refresh.");
        return;
      }
      if (generation !== loadDataGeneration.current) {
        return;
      }
      if (user && refreshedUser?.id !== user.id) {
        endSession({ notice: "The signed-in account changed. Sign in again to continue." });
        return;
      }
      if (user?.role !== refreshedUser?.role) {
        cancelControlPlaneReads();
        setUsers([]);
      }
      setUser((previous) =>
        sameControlPlaneUser(previous, refreshedUser) ? previous : refreshedUser,
      );
      const refreshedIsAdmin = refreshedUser?.role === "ADMIN";
      const requests = {
        health: ["Health", fetchHealth, setHealth],
        runtimeStatus: ["Local runtime", fetchLocalRuntimeStatus, setRuntimeStatus],
        operations: ["Operations", fetchOperationsSummary, setOperationsSummary],
        servers: ["Servers", fetchServers, setServers],
        tools: ["Tools", fetchTools, setTools],
        policies: ["Policies", fetchPolicies, setPolicies],
        runtimeLogs: ["Runtime logs", () => fetchRuntimeLogs({ limit: 20 }), setRuntimeLogPage],
        analyses: ["Tool analyses", fetchAllToolAnalyses, setToolAnalyses],
        revisions: ["Config revisions", fetchConfigRevisions, setConfigRevisions],
        activeRevision: ["Active config", fetchActiveConfigRevision, setActiveRevision],
        emergencyDenies: ["Emergency Deny", fetchEmergencyDenies, setEmergencyDenies],
        audit: ["Audit", fetchAuditEvents, setAuditEvents],
      };
      if (refreshedIsAdmin) {
        requests.users = ["Users", fetchUsers, setUsers];
      } else {
        setUsers([]);
      }

      const scope = entryOptions.record != null ? [] : routeReads[activePage] || [];
      const entries = scope.filter((key) => Object.hasOwn(requests, key))
        .map((key) => [key, requests[key]]);
      // Display each completed read as it arrives. Slow/failed unrelated services
      // must not keep the inventory or security review behind a global spinner.
      // The generation fence prevents an older refresh from replacing newer data.
      const settled = await Promise.allSettled(entries.map(async ([key, [, fetcher, setter]]) => {
        try {
          const result = await fetcher();
          if (generation === loadDataGeneration.current) {
            setter(result);
            setReadStates((current) => ({ ...current, [key]: "ready" }));
            setReadTimestamps((current) => ({ ...current, [key]: new Date().toISOString() }));
          }
          return result;
        } catch (err) {
          if (generation === loadDataGeneration.current) {
            setReadStates((current) => ({ ...current, [key]: "unavailable" }));
          }
          throw err;
        }
      }));
      if (generation !== loadDataGeneration.current) {
        return;
      }
      const failed = [];
      let unauthorized = false;
      settled.forEach((result, index) => {
        const [, [label]] = entries[index];
        if (result.status === "fulfilled") {
          return;
        }
        if (result.reason?.status === 401) {
          unauthorized = true;
          return;
        }
        failed.push(label);
      });

      if (activePage === "dashboard") setDashboardRefreshedAt(new Date());
      if (unauthorized) {
        endSession({ error: SESSION_EXPIRED_NOTICE });
      } else if (failed.length > 0) {
        setError(`Some Control Center data could not be refreshed: ${failed.join(", ")}.`);
      } else {
        setError("");
      }
    } finally {
      if (generation === loadDataGeneration.current) {
        setLoading(false);
      }
    }
  }

  useEffect(() => {
    restoreSession();
    function onHistoryChange() {
      focusMainOnRender.current = true;
      setActivePage(pageFromLocation());
      setAnalysisEntryToolId(toolFromLocation());
      setOperationEntryId(operationFromQuery(window.location.search));
      setEntryOptions(entryOptionsFromLocation());
      setMobileNavOpen(false);
      setAccountOpen(false);
    }
    window.addEventListener("popstate", onHistoryChange);
    return () => window.removeEventListener("popstate", onHistoryChange);
  }, []);

  function closeMobileNavigation(event) {
    if (event.key !== "Escape" || !mobileNavOpen || event.target.closest?.('[role="dialog"]')) return;
    setMobileNavOpen(false);
    mobileNavButtonRef.current?.focus();
  }

  useEffect(() => {
    if (user) void loadData({ verifySession: false });
  }, [user?.id, user?.role, activePage, entryOptions.record]);

  useEffect(() => {
    if (!user) return undefined;
    const onSessionExpired = () => endSession({ error: SESSION_EXPIRED_NOTICE });
    window.addEventListener(SESSION_EXPIRED_EVENT, onSessionExpired);
    return () => window.removeEventListener(SESSION_EXPIRED_EVENT, onSessionExpired);
  }, [Boolean(user)]);

  useEffect(() => {
    document.title = `${user ? currentPage.label : "Sign in"} · MCP Security Framework`;
    if (user && focusMainOnRender.current) {
      mainRef.current?.focus({ preventScroll: true });
      focusMainOnRender.current = false;
    }
  }, [Boolean(user), activePage, analysisEntryToolId]);

  const pageContent = useMemo(() => {
    const recordType = recordTypeForView(requestedPage);
    if (entryOptions.record !== null && entryOptions.record !== undefined && recordType) {
      const recordId = entryOptions.record.toLowerCase();
      return <ExactSecurityRecord key={recordType + ":" + recordId} view={requestedPage}
        type={recordType} id={recordId} isAdmin={isAdmin} refreshToken={viewRefreshToken} />;
    }
    if (activePage === "inventory") {
      return (
        <Inventory
          key={"inventory-" + (entryOptions.action || "list")}
          requestedAction={entryOptions.action}
          isAdmin={isAdmin}
          servers={servers}
          tools={tools}
          loading={loading}
          onNavigate={navigateToPage}
          onRefresh={loadData}
          runtimeStatus={runtimeStatus}
        />
      );
    }

    if (activePage === "build") {
      return (
        <BuildSecurity
          activeRevision={activeRevision}
          isAdmin={isAdmin}
          onRefresh={loadData}
          revisions={configRevisions}
          refreshToken={viewRefreshToken}
          servers={activeServers}
        />
      );
    }

    if (activePage === "cloud") {
      return <CloudSecurity isAdmin={isAdmin} refreshToken={viewRefreshToken} />;
    }

    if (activePage === "analysis") {
      return (
        <ToolAnalysis
          analyses={activeToolAnalyses}
          requestedToolId={analysisEntryToolId}
          requestedQueue={entryOptions.queue}
          isAdmin={isAdmin}
          loading={loading}
          onRefresh={loadData}
          servers={activeServers}
          tools={activeTools}
        />
      );
    }

    if (activePage === "config") {
      return (
        <SecurityConfiguration
          activeRevision={activeRevision}
          isAdmin={isAdmin}
          loading={loading}
          onRefresh={loadData}
          policies={policies}
          revisions={configRevisions}
        />
      );
    }

    if (activePage === "emergency") {
      return (
        <EmergencyDeny
          denies={emergencyDenies}
          isAdmin={isAdmin}
          loading={loading}
          onRefresh={loadData}
        />
      );
    }

    if (activePage === "runtime") {
      return <RuntimeLogs key={"runtime-" + (entryOptions.outcome || "all")}
        initialPage={runtimeLogPage} loading={loading} servers={activeServers} tools={activeTools}
        initialFilters={entryOptions.outcome ? { outcome_state: entryOptions.outcome } : null}
        onNavigate={navigateToPage} refreshToken={viewRefreshToken} />;
    }

    if (activePage === "operations") {
      return (
        <Operations
          initialOperationId={operationEntryId}
          initialSection={entryOptions.section}
          isAdmin={isAdmin}
          loading={loading}
          onRefresh={loadData}
          onNavigate={navigateToPage}
          summary={operationsSummary}
        />
      );
    }

    if (activePage === "audit") {
      return <Audit events={auditEvents} loading={loading} refreshToken={viewRefreshToken} isAdmin={isAdmin} />;
    }

    if (activePage === "users" && isAdmin) {
      return <Users users={users} loading={loading} onRefresh={loadData} />;
    }

    if (activePage === "access-denied") {
      return <AccessDenied onHome={() => navigateToPage("dashboard")}
        pageLabel={pages.find((page) => page.id === requestedPage)?.label || "This page"} />;
    }

    return (
      <Dashboard
        activeRevision={activeRevision}
        auditEvents={auditEvents}
        emergencyDenies={emergencyDenies}
        health={health}
        isAdmin={isAdmin}
        servers={activeServers}
        tools={activeTools}
        policies={policies}
        runtimeLogs={runtimeLogPage.items}
        runtimeSummary={runtimeLogPage.summary}
        dashboardRefreshedAt={dashboardRefreshedAt}
        runtimeStatus={runtimeStatus}
        loading={loading}
        readStates={readStates}
        readTimestamps={readTimestamps}
        onNavigate={navigateToPage}
      />
    );
  }, [
    activePage,
    requestedPage,
    entryOptions,
    viewRefreshToken,
    analysisEntryToolId,
    operationEntryId,
    readStates,
    readTimestamps,
    activeServers,
    activeToolAnalyses,
    activeTools,
    activeRevision,
    auditEvents,
    emergencyDenies,
    health,
    isAdmin,
    loading,
    operationsSummary,
    policies,
    configRevisions,
    runtimeLogPage,
    runtimeStatus,
    users,
  ]);

  if (authLoading) {
    return <main className="app-shell session-loading" role="status">Checking your session…</main>;
  }

  if (!user) {
    return <LoginView error={loginError} notice={loginNotice} onLogin={handleLogin}
      onRetrySession={sessionCheckFailed ? () => restoreSession({ focusContent: true }) : null} />;
  }

  return (
    <div className="app-shell security-console" onKeyDown={closeMobileNavigation}>
      <a className="skip-navigation" href="#main-content" onClick={(event) => {
        event.preventDefault();
        mainRef.current?.focus();
        mainRef.current?.scrollIntoView({ block: "start" });
      }}>Skip to content</a>
      <aside className="console-sidebar">
        <div className="console-brand">
          <span className="console-brand-icon"><NavigationIcon page="analysis" /></span>
          <div><strong>Security Center</strong><span>MCP Security Framework</span></div>
        </div>
      <button
        ref={mobileNavButtonRef}
        className="mobile-nav-toggle secondary-action"
        aria-controls="primary-navigation"
        aria-expanded={mobileNavOpen}
        aria-label={mobileNavOpen ? "Close navigation menu" : "Open navigation menu"}
        onClick={() => setMobileNavOpen((previous) => !previous)}
        type="button"
      >
        <span>{mobileNavOpen ? "Close menu" : "Menu"}</span>
        <strong>{currentPage?.label || "Home"}</strong>
      </button>
      <nav id="primary-navigation" className={"app-nav" + (mobileNavOpen ? " mobile-open" : "")}
        aria-label="Main navigation">
        {navigationGroups.map((group) => {
          const items = pages.filter((page) => page.group === group && (!page.adminOnly || isAdmin));
          if (items.length === 0) return null;
          return (
            <div aria-label={group} className="app-nav-group" key={group} role="group">
              <span className="app-nav-group-label">{group}</span>
              <div className="app-nav-group-links">
                {items.map((page) => (
                  <a
                    aria-current={activePage === page.id ? "page" : undefined}
                    className={activePage === page.id ? "active" : ""}
                    href={pageUrl(page.id).href}
                    key={page.id}
                    onClick={(event) => {
                      if (event.ctrlKey || event.metaKey || event.shiftKey || event.altKey || event.button !== 0) return;
                      event.preventDefault();
                      navigateToPage(page.id);
                    }}
                  >
                    <NavigationIcon page={page.id} />
                    <span>{page.label}</span>
                  </a>
                ))}
              </div>
            </div>
          );
        })}
      </nav>

      </aside>
      <header className="app-header console-header">
        <div className="console-location">
          {currentPage.group !== currentPage.label && <span>{currentPage.group}</span>}
          <strong>{currentPage.label}</strong>
        </div>
        <div className="session-actions">
          <div className="session-user">
            <strong>{user.username}</strong>
            <span>{user.role === "ADMIN" ? "Administrator" : "Viewer"}</span>
          </div>
          <button className="secondary-action" disabled={loading || signingOut}
            onClick={() => { setViewRefreshToken((token) => token + 1); loadData(); }} type="button">
            {loading ? "Refreshing…" : "Refresh"}
          </button>
          <button className="secondary-action" type="button" aria-haspopup="dialog"
            onClick={() => setAccountOpen(true)}>
            My account
          </button>
          <button className="secondary-action" disabled={signingOut} onClick={handleLogout} type="button">
            {signingOut ? "Signing out…" : "Sign out"}
          </button>
        </div>
      </header>
      <main id="main-content" className="console-content" aria-label={currentPage.label} ref={mainRef} tabIndex={-1}>
        <h1 className="visually-hidden">Security Center</h1>
        {(error || logoutError) && <div className="error-banner" role="alert">{logoutError || error}</div>}
        {oauthReturn && <div className="detail-panel" role="status">
          <strong>OAuth connection return</strong>
          <p>{oauthReturnDescription(oauthReturn,
            readStates.servers === "ready"
              ? servers.find((server) => server.id === oauthReturn.serverId) : null)}</p>
          {oauthReturn.serverId && <p>Server ID: {oauthReturn.serverId}.
            {readStates.servers === "ready" && !servers.some((server) => server.id === oauthReturn.serverId)
              ? " This server is not in the current inventory."
              : " Check the corresponding server connection details."}</p>}
          <button type="button" onClick={() => { setOAuthReturn(null); }}>Dismiss callback notice</button>
        </div>}
        {accountOpen && <AccountPasswordPanel
          onClose={() => setAccountOpen(false)}
          onChanged={() => endSession({
            notice: "Your password changed and all sessions were revoked. Sign in again with your new password.",
          })}
        />}
        {pageContent}
      </main>
    </div>
  );
}

function LoginView({ error, notice, onLogin, onRetrySession }) {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [fieldErrors, setFieldErrors] = useState({});
  const [busy, setBusy] = useState(false);
  const headingRef = useRef(null);
  const usernameRef = useRef(null);
  const passwordRef = useRef(null);

  useEffect(() => {
    headingRef.current?.focus();
  }, []);

  async function submit(event) {
    event.preventDefault();
    if (busy) {
      return;
    }
    const errors = validateLogin({ username, password });
    setFieldErrors(errors);
    if (Object.keys(errors).length > 0) {
      (errors.username ? usernameRef : passwordRef).current?.focus();
      return;
    }
    setBusy(true);
    try {
      const success = await onLogin(username.trim(), password);
      if (!success) {
        setPassword("");
        passwordRef.current?.focus();
      }
    } finally {
      setBusy(false);
    }
  }

  return (
    <main className="app-shell login-shell">
      <div className="login-layout">
        <div className="login-intro">
          <span className="console-brand-icon"><NavigationIcon page="analysis" /></span>
          <p>MCP Security Framework</p>
          <h2>Security Center</h2>
          <p>Review MCP tools, cloud permissions and runtime activity in one place.</p>
        </div>
        <section className="login-panel" aria-labelledby="sign-in-heading">
          <h1 id="sign-in-heading" ref={headingRef} tabIndex={-1}>Sign in</h1>
          <p className="login-description">Use your Security Center account.</p>
          {error && <div className="error-banner" role="alert">{error}</div>}
          {notice && <div className="success-banner" role="status">{notice}</div>}
          {onRetrySession && <button className="secondary-action session-retry" type="button" disabled={busy}
            onClick={onRetrySession}>Retry session check</button>}
        <form onSubmit={submit} className="login-form" aria-busy={busy}>
          <label>
            Username
            <input
              aria-describedby={fieldErrors.username ? "login-username-error" : undefined}
              aria-invalid={Boolean(fieldErrors.username)}
              autoComplete="username"
              maxLength={LIMITS.usernameMax}
              onChange={(event) => {
                setUsername(event.target.value);
                setFieldErrors((current) => clearFieldError(current, "username"));
              }}
              required
              ref={usernameRef}
              type="text"
              value={username}
            />
            <FieldError id="login-username-error" message={fieldErrors.username} />
          </label>
          <label>
            Password
            <input
              aria-describedby={fieldErrors.password ? "login-password-error" : undefined}
              aria-invalid={Boolean(fieldErrors.password)}
              autoComplete="current-password"
              maxLength={LIMITS.passwordMax}
              onChange={(event) => {
                setPassword(event.target.value);
                setFieldErrors((current) => clearFieldError(current, "password"));
              }}
              required
              ref={passwordRef}
              type="password"
              value={password}
            />
            <FieldError id="login-password-error" message={fieldErrors.password} />
          </label>
          <button className="console-primary" disabled={busy} type="submit">
            {busy ? "Signing in…" : "Sign in"}
          </button>
        </form>
        </section>
      </div>
    </main>
  );
}

function FieldError({ id, message }) {
  return message ? (
    <span className="field-error" id={id}>
      {message}
    </span>
  ) : null;
}

function sameControlPlaneUser(left, right) {
  return (
    left?.id === right?.id &&
    left?.username === right?.username &&
    left?.role === right?.role &&
    left?.enabled === right?.enabled &&
    (left?.display_name || "") === (right?.display_name || "")
  );
}

export default App;
