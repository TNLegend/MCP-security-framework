import { useEffect, useMemo, useState } from "react";

import {
  fetchActiveConfigRevision,
  fetchAllToolAnalyses,
  fetchAuditEvents,
  fetchConfigRevisions,
  fetchEmergencyDenies,
  fetchHealth,
  fetchLocalRuntimeStatus,
  fetchControlPlaneMe,
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
  const [runtimeLogs, setRuntimeLogs] = useState([]);
  const [toolAnalyses, setToolAnalyses] = useState([]);
  const [configRevisions, setConfigRevisions] = useState([]);
  const [activeRevision, setActiveRevision] = useState(null);
  const [emergencyDenies, setEmergencyDenies] = useState([]);
  const [auditEvents, setAuditEvents] = useState([]);
  const [users, setUsers] = useState([]);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(true);
  const isAdmin = user?.role === "ADMIN";

  async function restoreSession() {
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
      await loadData();
    } catch (err) {
      setLoginError(err.message || "Login failed");
    }
  }

  async function handleLogout() {
    await logoutControlPlane();
    setUser(null);
  }

  async function loadData() {
    try {
      setLoading(true);
      setError("");

      const [
        healthData,
        runtimeStatusData,
        serversData,
        toolsData,
        policiesData,
        runtimeData,
        analysesData,
        revisionsData,
        activeRevisionData,
        emergencyDenyData,
        auditData,
        usersData,
      ] =
        await Promise.all([
          fetchHealth(),
          fetchLocalRuntimeStatus(),
          fetchServers(),
          fetchTools(),
          fetchPolicies(),
          fetchRuntimeLogs(),
          fetchAllToolAnalyses(),
          fetchConfigRevisions(),
          fetchActiveConfigRevision(),
          fetchEmergencyDenies(),
          fetchAuditEvents(),
          isAdmin ? fetchUsers() : Promise.resolve([]),
        ]);

      setHealth(healthData);
      setRuntimeStatus(runtimeStatusData);
      setServers(serversData);
      setTools(toolsData);
      setPolicies(policiesData);
      setRuntimeLogs(runtimeData);
      setToolAnalyses(analysesData);
      setConfigRevisions(revisionsData);
      setActiveRevision(activeRevisionData);
      setEmergencyDenies(emergencyDenyData);
      setAuditEvents(auditData);
      setUsers(usersData);
    } catch (err) {
      setError(err.message || "Backend unavailable");
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    restoreSession();
  }, []);

  useEffect(() => {
    if (user) {
      loadData();
    }
  }, [user]);

  const pageContent = useMemo(() => {
    if (activePage === "inventory") {
      return (
        <Inventory
          isAdmin={isAdmin}
          servers={servers}
          tools={tools}
          loading={loading}
          onRefresh={loadData}
          runtimeStatus={runtimeStatus}
        />
      );
    }

    if (activePage === "analysis") {
      return (
        <ToolAnalysis
          analyses={toolAnalyses}
          isAdmin={isAdmin}
          loading={loading}
          onRefresh={loadData}
          servers={servers}
          tools={tools}
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
      return <RuntimeLogs logs={runtimeLogs} loading={loading} />;
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
        servers={servers}
        tools={tools}
        policies={policies}
        runtimeLogs={runtimeLogs}
        runtimeStatus={runtimeStatus}
        loading={loading}
        onNavigate={setActivePage}
      />
    );
  }, [
    activePage,
    activeRevision,
    auditEvents,
    emergencyDenies,
    health,
    isAdmin,
    loading,
    policies,
    runtimeLogs,
    runtimeStatus,
    servers,
    toolAnalyses,
    tools,
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
          <button className="secondary-action" onClick={loadData} type="button">
            Refresh
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

  function submit(event) {
    event.preventDefault();
    onLogin(username, password);
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
              autoComplete="username"
              onChange={(event) => setUsername(event.target.value)}
              required
              type="text"
              value={username}
            />
          </label>
          <label>
            Password
            <input
              autoComplete="current-password"
              onChange={(event) => setPassword(event.target.value)}
              required
              type="password"
              value={password}
            />
          </label>
          <button className="secondary-action" type="submit">
            Login
          </button>
        </form>
      </section>
    </div>
  );
}

export default App;
