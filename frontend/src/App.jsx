import { useEffect, useMemo, useRef, useState } from "react";

import {
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
  const [analysisEntryToolId, setAnalysisEntryToolId] = useState(null);
  const [user, setUser] = useState(null);
  const [authLoading, setAuthLoading] = useState(true);
  const [loginError, setLoginError] = useState("");
  const [loginNotice, setLoginNotice] = useState("");
  const [accountOpen, setAccountOpen] = useState(false);
  const [logoutError, setLogoutError] = useState("");
  const [signingOut, setSigningOut] = useState(false);
  const [readStates, setReadStates] = useState({});
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
  const loadDataGeneration = useRef(0);
  const isAdmin = user?.role === "ADMIN";
  const activePage = requestedPage === "users" && !isAdmin ? "dashboard" : requestedPage;
  const currentPage = pages.find((page) => page.id === activePage);
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

  function navigateToPage(pageId, toolId = null) {
    setMobileNavOpen(false);
    setAnalysisEntryToolId(pageId === "analysis" ? toolId : null);
    if (pageId !== pageFromLocation()) {
      const url = new URL(window.location.href);
      if (pageId === "dashboard") url.searchParams.delete("view");
      else url.searchParams.set("view", pageId);
      url.hash = "";
      window.history.pushState(null, "", url);
      window.scrollTo({ top: 0, behavior: "instant" });
    }
    setActivePage(pageId);
  }

  useEffect(() => {
    if (!oauthReturn) return;
    // A backend callback uses a fragment, so OAuth tokens must not be
    // inferred or stored by this frontend. Remove only the result marker.
    const url = new URL(window.location.href);
    url.searchParams.set("view", "inventory");
    url.hash = "";
    window.history.replaceState(null, "", url);
  }, [oauthReturn]);

  async function restoreSession() {
    if (!hasControlPlaneSession()) {
      setUser(null);
      setAuthLoading(false);
      return;
    }
    try {
      const me = await fetchControlPlaneMe();
      setUser(me);
    } catch (err) {
      setUser(null);
      setLoginError(err?.status === 401
        ? "Your session expired or was revoked. Sign in again."
        : "The server could not verify the existing session. This may be a network or backend outage, not an expired password. Check service health before retrying.");
    } finally {
      setAuthLoading(false);
    }
  }

  async function handleLogin(username, password) {
    try {
      setLoginError("");
      setLoginNotice("");
      const payload = await loginControlPlane(username, password);
      setUser(payload.user);
      return true;
    } catch (err) {
      setLoginError(err.message || "Login failed");
      return false;
    }
  }

  async function handleLogout() {
    setSigningOut(true);
    setLogoutError("");
    try {
      await logoutControlPlane();
      loadDataGeneration.current += 1;
      setReadStates({});
      setUser(null);
    } catch (err) {
      setLogoutError(err.message || "Sign out failed. Please try again.");
    } finally {
      setSigningOut(false);
    }
  }

  async function loadData() {
    const generation = loadDataGeneration.current + 1;
    loadDataGeneration.current = generation;
    setLoading(true);
    setError("");
    try {
      let refreshedUser = null;
      try {
        refreshedUser = await fetchControlPlaneMe();
      } catch (err) {
        if (generation !== loadDataGeneration.current) {
          return;
        }
        if (err?.status === 401) {
          setUser(null);
          setUsers([]);
          setError("");
          return;
        }
        setError("Current Control Plane session could not be refreshed.");
        return;
      }
      if (generation !== loadDataGeneration.current) {
        return;
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

      const entries = Object.entries(requests);
      // Display each completed read as it arrives. Slow/failed unrelated services
      // must not keep the inventory or security review behind a global spinner.
      // The generation fence prevents an older refresh from replacing newer data.
      const settled = await Promise.allSettled(entries.map(async ([key, [, fetcher, setter]]) => {
        try {
          const result = await fetcher();
          if (generation === loadDataGeneration.current) {
            setter(result);
            setReadStates((current) => ({ ...current, [key]: "ready" }));
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

      setDashboardRefreshedAt(new Date());
      if (unauthorized) {
        setUser(null);
        setError("");
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
      setActivePage(pageFromLocation());
      setAnalysisEntryToolId(null);
      setMobileNavOpen(false);
    }
    window.addEventListener("popstate", onHistoryChange);
    return () => window.removeEventListener("popstate", onHistoryChange);
  }, []);

  function closeMobileNavigation(event) {
    if (event.key !== "Escape" || !mobileNavOpen) return;
    setMobileNavOpen(false);
    mobileNavButtonRef.current?.focus();
  }

  useEffect(() => {
    if (user) {
      loadData();
    }
  }, [user?.id]);

  const pageContent = useMemo(() => {
    if (activePage === "inventory") {
      return (
        <Inventory
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
          isAdmin={isAdmin}
          onRefresh={loadData}
          revisions={configRevisions}
          servers={activeServers}
        />
      );
    }

    if (activePage === "cloud") {
      return <CloudSecurity isAdmin={isAdmin} />;
    }

    if (activePage === "analysis") {
      return (
        <ToolAnalysis
          analyses={activeToolAnalyses}
          requestedToolId={analysisEntryToolId}
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
      return <RuntimeLogs initialPage={runtimeLogPage} loading={loading} />;
    }

    if (activePage === "operations") {
      return (
        <Operations
          isAdmin={isAdmin}
          loading={loading}
          onRefresh={loadData}
          summary={operationsSummary}
        />
      );
    }

    if (activePage === "audit") {
      return <Audit events={auditEvents} loading={loading} />;
    }

    if (activePage === "users" && isAdmin) {
      return <Users users={users} loading={loading} onRefresh={loadData} />;
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
        onNavigate={navigateToPage}
      />
    );
  }, [
    activePage,
    analysisEntryToolId,
    readStates,
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
    return <LoginView error={loginError} notice={loginNotice} onLogin={handleLogin} />;
  }

  return (
    <div className="app-shell security-console" onKeyDown={closeMobileNavigation}>
      <a className="skip-navigation" href="#main-content">Skip to content</a>
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
        <strong>{pages.find((page) => page.id === activePage)?.label || "Home"}</strong>
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
                  <button
                    aria-current={activePage === page.id ? "page" : undefined}
                    className={activePage === page.id ? "active" : ""}
                    key={page.id}
                    onClick={() => {
                      navigateToPage(page.id);
                      if (window.matchMedia("(max-width: 760px)").matches) {
                        mobileNavButtonRef.current?.focus();
                      }
                    }}
                    type="button"
                  >
                    <NavigationIcon page={page.id} />
                    <span>{page.label}</span>
                  </button>
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
          <button className="secondary-action" disabled={loading || signingOut} onClick={loadData} type="button">
            {loading ? "Refreshing…" : "Refresh"}
          </button>
          <button className="secondary-action" type="button" aria-expanded={accountOpen}
            onClick={() => setAccountOpen((current) => !current)}>
            My account
          </button>
          <button className="secondary-action" disabled={signingOut} onClick={handleLogout} type="button">
            {signingOut ? "Signing out…" : "Sign out"}
          </button>
        </div>
      </header>
      <main id="main-content" className="console-content" tabIndex={-1}>
        <h1 className="visually-hidden">Security center</h1>
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
          onChanged={() => {
            setAccountOpen(false);
            setUser(null);
            setCsrfToken("");
            setLoginError("");
            setLoginNotice("Your password has been changed and all sessions were revoked. Sign in again with your new password.");
          }}
        />}
        {pageContent}
      </main>
    </div>
  );
}

function LoginView({ error, notice, onLogin }) {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [fieldErrors, setFieldErrors] = useState({});
  const [busy, setBusy] = useState(false);

  async function submit(event) {
    event.preventDefault();
    if (busy) {
      return;
    }
    const errors = validateLogin({ username, password });
    setFieldErrors(errors);
    if (Object.keys(errors).length > 0) {
      return;
    }
    setBusy(true);
    try {
      const success = await onLogin(username.trim(), password);
      if (!success) {
        setPassword("");
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
          <h1 id="sign-in-heading">Sign in</h1>
          <p className="login-description">Use your Security Center account.</p>
          {error && <div className="error-banner" role="alert">{error}</div>}
          {notice && <div className="success-banner" role="status">{notice}</div>}
        <form onSubmit={submit} className="login-form">
          <label>
            Username
            <input
              aria-describedby="login-username-error"
              aria-invalid={Boolean(fieldErrors.username)}
              autoComplete="username"
              maxLength={LIMITS.usernameMax}
              onChange={(event) => {
                setUsername(event.target.value);
                setFieldErrors((current) => clearFieldError(current, "username"));
              }}
              required
              type="text"
              value={username}
            />
            <FieldError id="login-username-error" message={fieldErrors.username} />
          </label>
          <label>
            Password
            <input
              aria-describedby="login-password-error"
              aria-invalid={Boolean(fieldErrors.password)}
              autoComplete="current-password"
              maxLength={LIMITS.passwordMax}
              onChange={(event) => {
                setPassword(event.target.value);
                setFieldErrors((current) => clearFieldError(current, "password"));
              }}
              required
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
