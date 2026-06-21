import { useEffect, useMemo, useState } from "react";

import {
  fetchHealth,
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
  const [health, setHealth] = useState(null);
  const [servers, setServers] = useState([]);
  const [tools, setTools] = useState([]);
  const [policies, setPolicies] = useState([]);
  const [runtimeLogs, setRuntimeLogs] = useState([]);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(true);

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
    loadData();
  }, []);

  const pageContent = useMemo(() => {
    if (activePage === "inventory") {
      return <Inventory servers={servers} loading={loading} />;
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

  return (
    <div className="app-shell">
      <header className="app-header">
        <div>
          <p className="eyebrow">MCP Security Framework</p>
          <h1>Security Operations</h1>
        </div>
        <button className="secondary-action" onClick={loadData} type="button">
          Refresh
        </button>
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

export default App;
