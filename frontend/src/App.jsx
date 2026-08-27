import { useEffect, useMemo, useRef, useState } from "react";

import {
  fetchActiveConfigRevision,
  fetchAllToolAnalyses,
  fetchAuditEvents,
  fetchConfigRevisions,
  fetchEmergencyDenies,
  fetchHealth,
  fetchLocalRuntimeStatus,
  fetchControlPlaneMe,
  hasControlPlaneSession,
  loginControlPlane,
  logoutControlPlane,
  fetchPolicies,
  fetchRuntimeLogs,
  fetchServers,
  fetchTools,
  fetchUsers,
} from "./api/client";
import Dashboard from "./pages/Dashboard";
import Audit from "./pages/Audit";
import EmergencyDeny from "./pages/EmergencyDeny";
import Inventory from "./pages/Inventory";
import RuntimeLogs from "./pages/RuntimeLogs";
import SecurityConfiguration from "./pages/SecurityConfiguration";
import ToolAnalysis from "./pages/ToolAnalysis";
import Users from "./pages/Users";
import { LIMITS, clearFieldError, validateLogin } from "./utils/validation";

const pages = [
  { id: "dashboard", label: "Dashboard" },
  { id: "inventory", label: "MCP Inventory" },
  { id: "analysis", label: "Tool Analysis" },
  { id: "config", label: "Security Configuration" },
  { id: "emergency", label: "Emergency Deny" },
  { id: "runtime", label: "Runtime Calls" },
  { id: "audit", label: "Audit" },
  { id: "users", label: "Users", adminOnly: true },
];

const EMPTY_RUNTIME_LOG_PAGE = {
  items: [],
  next_cursor: null,
  has_more: false,
  summary: { total: 0, allowed: 0, blocked: 0, executed: 0, skipped: 0, errors: 0 },
};

function App() {
  const [activePage, setActivePage] = useState("dashboard");
  const [user, setUser] = useState(null);
  const [authLoading, setAuthLoading] = useState(true);
  const [loginError, setLoginError] = useState("");
  const [health, setHealth] = useState(null);
  const [runtimeStatus, setRuntimeStatus] = useState(null);
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
  const loadDataGeneration = useRef(0);
  const isAdmin = user?.role === "ADMIN";
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

  async function restoreSession() {
    if (!hasControlPlaneSession()) {
      setUser(null);
      setAuthLoading(false);
      return;
    }
    try {
      const me = await fetchControlPlaneMe();
      setUser(me);
    } catch {
      setUser(null);
    } finally {
      setAuthLoading(false);
    }
  }

  async function handleLogin(username, password) {
    try {
      setLoginError("");
      const payload = await loginControlPlane(username, password);
      setUser(payload.user);
      return true;
    } catch (err) {
      setLoginError(err.message || "Login failed");
      return false;
    }
  }

  async function handleLogout() {
    await logoutControlPlane();
    setUser(null);
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
        servers: ["Servers", fetchServers, setServers],
        tools: ["Tools", fetchTools, setTools],
        policies: ["Policies", fetchPolicies, setPolicies],
        runtimeLogs: ["Runtime logs", () => fetchRuntimeLogs({ limit: 50 }), setRuntimeLogPage],
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
      const settled = await Promise.allSettled(entries.map(([, [, fetcher]]) => fetcher()));
      if (generation !== loadDataGeneration.current) {
        return;
      }
      const failed = [];
      let unauthorized = false;
      settled.forEach((result, index) => {
        const [, [label, , setter]] = entries[index];
        if (result.status === "fulfilled") {
          setter(result.value);
          return;
        }
        if (result.reason?.status === 401) {
          unauthorized = true;
          return;
        }
        failed.push(label);
      });

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
  }, []);

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
          onNavigate={setActivePage}
          onRefresh={loadData}
          runtimeStatus={runtimeStatus}
        />
      );
    }

    if (activePage === "analysis") {
      return (
        <ToolAnalysis
          analyses={activeToolAnalyses}
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
        runtimeStatus={runtimeStatus}
        loading={loading}
        onNavigate={setActivePage}
      />
    );
  }, [
    activePage,
    activeServers,
    activeToolAnalyses,
    activeTools,
    activeRevision,
    auditEvents,
    emergencyDenies,
    health,
    isAdmin,
    loading,
    policies,
    runtimeLogPage,
    runtimeStatus,
    users,
  ]);

  if (authLoading) {
    return <div className="app-shell">Loading session...</div>;
  }

  if (!user) {
    return <LoginView error={loginError} onLogin={handleLogin} />;
  }

  return (
    <div className="app-shell">
      <header className="app-header">
        <div>
          <p className="eyebrow">MCP Security Framework</p>
          <h1>Security Operations</h1>
        </div>
        <div className="session-actions">
          <div className="session-user">
            <strong>{user.username}</strong>
            <span>{user.role}</span>
          </div>
          <button
            className="secondary-action"
            disabled={loading}
            onClick={loadData}
            type="button"
          >
            {loading ? "Refreshing..." : "Refresh"}
          </button>
          <button className="secondary-action" onClick={handleLogout} type="button">
            Logout
          </button>
        </div>
      </header>

      <nav className="app-nav" aria-label="Main navigation">
        {pages.filter((page) => !page.adminOnly || isAdmin).map((page) => (
          <button
            className={activePage === page.id ? "active" : ""}
            key={page.id}
            onClick={() => setActivePage(page.id)}
            type="button"
          >
            {page.label}
          </button>
        ))}
      </nav>

      {error && <div className="error-banner">{error}</div>}

      <main>{pageContent}</main>
    </div>
  );
}

function LoginView({ error, onLogin }) {
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
    <div className="app-shell login-shell">
      <section className="login-panel">
        <p className="eyebrow">MCP Security Framework</p>
        <h1>Control Plane Login</h1>
        {error && <div className="error-banner">{error}</div>}
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
          <button className="secondary-action" disabled={busy} type="submit">
            {busy ? "Logging in..." : "Login"}
          </button>
        </form>
      </section>
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
