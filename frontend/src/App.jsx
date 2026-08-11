import { useEffect, useMemo, useState } from "react";

import {
  fetchHealth,
  fetchControlPlaneMe,
  loginControlPlane,
  logoutControlPlane,
  fetchPolicies,
  fetchRuntimeLogs,
  fetchServers,
  fetchTools,
} from "./api/client";
import Dashboard from "./pages/Dashboard";
import Inventory from "./pages/Inventory";
import Policies from "./pages/Policies";
import RuntimeLogs from "./pages/RuntimeLogs";

const pages = [
  { id: "dashboard", label: "Dashboard" },
  { id: "inventory", label: "MCP Inventory" },
  { id: "policies", label: "Policies" },
  { id: "runtime", label: "Runtime Logs" },
];

function App() {
  const [activePage, setActivePage] = useState("dashboard");
  const [user, setUser] = useState(null);
  const [authLoading, setAuthLoading] = useState(true);
  const [loginError, setLoginError] = useState("");
  const [health, setHealth] = useState(null);
  const [servers, setServers] = useState([]);
  const [tools, setTools] = useState([]);
  const [policies, setPolicies] = useState([]);
  const [runtimeLogs, setRuntimeLogs] = useState([]);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(true);

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

      const [healthData, serversData, toolsData, policiesData, runtimeData] =
        await Promise.all([
          fetchHealth(),
          fetchServers(),
          fetchTools(),
          fetchPolicies(),
          fetchRuntimeLogs(),
        ]);

      setHealth(healthData);
      setServers(serversData);
      setTools(toolsData);
      setPolicies(policiesData);
      setRuntimeLogs(runtimeData);
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
      return <Inventory servers={servers} tools={tools} loading={loading} />;
    }

    if (activePage === "policies") {
      return <Policies policies={policies} loading={loading} />;
    }

    if (activePage === "runtime") {
      return <RuntimeLogs logs={runtimeLogs} loading={loading} />;
    }

    return (
      <Dashboard
        health={health}
        servers={servers}
        tools={tools}
        policies={policies}
        runtimeLogs={runtimeLogs}
        loading={loading}
      />
    );
  }, [activePage, health, loading, policies, runtimeLogs, servers, tools]);

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
        {pages.map((page) => (
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
