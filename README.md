# MCP Security Framework

Framework local de securite et de gouvernance pour agents IA utilisant MCP.

## Objective

The project protects MCP tool usage around this runtime rule:

```text
The LLM proposes a structured tool-call JSON.
The MCP Security Framework decides whether it can run.
```

The LLM must never execute MCP tools directly. It only proposes a tool call. The MCP Proxy resolves inventory metadata, asks the Policy Engine for a decision, calls the MCP server only after an `ALLOW` decision, and writes runtime logs. If the policy returns `BLOCK`, no MCP `tools/call` request is sent.

## Current Status

Phase 2 is complete.

Implemented:

- real local MCP Streamable HTTP lab server;
- MCP discovery/import into the backend inventory;
- backend MCP inventory with native MCP metadata and framework security metadata;
- React frontend views for dashboard, inventory, policies, and runtime logs;
- MCP Proxy runtime enforcement;
- Policy Engine decision before execution;
- runtime logs stored in PostgreSQL;
- frontend Runtime Logs view for ALLOW/BLOCK proof;
- provider-agnostic LLM agent demo;
- mock, Gemini, and Groq providers;
- fallback provider support;
- safe result summaries instead of full tool output storage.

Docker is not used for the local MVP. The project runs directly with Python, Node.js, and PostgreSQL.

## Architecture Overview

```text
User prompt
-> LLM provider selected by configuration
-> structured tool-call proposal JSON
-> Agent validates proposal
-> MCP Proxy
-> Backend inventory lookup
-> Policy Engine decision
-> ALLOW: MCP tools/call
-> BLOCK: no MCP call
-> Runtime logs
```

The forbidden architecture is:

```text
LLM provider -> direct MCP tool execution
```

Gemini and Groq are demo providers only. The framework is provider-agnostic through a common LLM provider interface.

## Control Plane Foundation

The Control Plane separates human administration from AI agent identity.

Human Control Plane users are stored in PostgreSQL as `ControlPlaneUser` records and have exactly one of two roles:

- `ADMIN`: full Control Plane administration.
- `VIEWER`: authenticated read-only access, with no user-management privileges.

AI agents remain separate. Agent identity continues to use upstream identities, identity bindings, trusted sessions, capabilities, scopes, and Tool Analyzer facts. Control Plane web sessions are never agent trusted sessions.

PostgreSQL is the only administrative runtime source of truth. Administrative
runtime configuration is versioned in PostgreSQL:

```text
DRAFT -> VALIDATE -> PUBLISH -> ROLLBACK
```

`PUBLISHED` and `ARCHIVED` revisions are immutable. A publish transaction archives the previous active revision, marks the draft as published, and updates `ControlPlaneState.active_revision_id`. Runtime components read administrative facts through a `PublishedConfigurationSnapshot`; missing or corrupt active configuration fails closed. The administrative YAML files remain for bootstrap, import, export, tests, and examples, but they are not a silent runtime fallback.

One tool call uses exactly one immutable published configuration snapshot:

```text
Tool Call A starts on Revision 4
Revision 5 is published while A is running
Tool Call A finishes on Revision 4
Tool Call B starts on Revision 5
```

The proxy loads the snapshot once at the start of the call and uses that same `revision_id`, `revision_number`, and `content_hash` for identity bindings, agent authorization, tool security profiles, resource scopes, and policy settings. These metadata are included in the runtime context and protected by the signed proxy-to-backend assertion, so the backend resolves authorization from the same revision instead of asking for the active revision again.

OPA/Rego remains the runtime policy engine. Python verifies identities, validates and loads trusted administrative facts, prepares policy context, and enforces fail-closed behavior. Rego decides `ALLOW` or `BLOCK`; the proxy enforces the decision and never calls MCP for blocked requests.

The framework has four separate identity boundaries:

```text
HUMAN CONTROL PLANE -> HttpOnly session -> ADMIN / VIEWER
AI AGENT            -> JWT/JWKS identity, trusted sessions, capabilities, scopes
MCP_PROXY SERVICE   -> Ed25519 signed service requests
MCP_DISCOVERY       -> Ed25519 signed service requests
```

Knowing an internal URL does not grant access. Internal service requests sign the service id, key id, HTTP method, exact path, timestamp, JTI, and canonical request body hash with Ed25519. The backend verifies the public key, timestamp window, anti-replay JTI, body integrity, and per-service permission. A public key cannot impersonate a service because only the corresponding private key can produce the signature.

The proxy no longer uses human inventory routes. It reads inventory through signed internal endpoints and writes runtime logs with its `MCP_PROXY` service identity. Tool discovery import is signed by a separate `MCP_DISCOVERY` identity; no shared discovery bearer token is accepted. Human legacy mutations such as `/servers`, `/tools`, and `/policies` are ADMIN-only.

Sensitive administrative actions are audited through `ControlPlaneAuditEvent`. Passwords, password hashes, session tokens, cookies, CSRF tokens, private keys, and secrets are excluded from audit payloads.

## Repository Structure

```text
mcp-security-framework/
|-- backend/      FastAPI API, PostgreSQL models, inventory, policies, decisions, logs
|-- frontend/     React/Vite UI for dashboard, inventory, policies, runtime logs
|-- mcp-lab/      Local MCP HTTP lab server and test data
|-- scripts/      Dependency checks and MCP discovery/import script
|-- proxy/        Runtime enforcement layer
|-- agent/        Provider-agnostic LLM agent demo
|-- policies/     Rego runtime policy and administrative YAML data
|-- scanners/     Reserved for future scanning modules
|-- docs/         Ignored local documentation workspace
|-- reports/      Ignored local report output
|-- .env.example
|-- .gitignore
`-- README.md
```

## Implemented Components

### `backend/`

FastAPI backend backed by local PostgreSQL. It stores MCP servers, MCP tools, runtime calls, policy decisions, and audit events. It exposes inventory, policy decision, health, and runtime log routes.

### `frontend/`

React/Vite frontend for:

- dashboard;
- MCP inventory;
- policies;
- runtime logs.

The inventory view separates native MCP metadata from framework security metadata. The runtime logs view shows decisions, matched rules, execution status, and safe summaries.

### `mcp-lab/http_server/`

Local MCP Streamable HTTP lab server.

Endpoint:

```text
http://127.0.0.1:9000/mcp
```

Implemented MCP methods:

- `initialize`
- `notifications/initialized`
- `tools/list`
- `tools/call`

Lab tools include:

- `read_file`
- `list_files`

### `scripts/discover_http_mcp_server.py`

Discovers the local MCP HTTP server by calling `initialize` and `tools/list`, then imports the discovered server and tools into the backend inventory.

### `proxy/`

Runtime enforcement layer. It:

- resolves server/tool metadata from backend inventory;
- asks OPA for a runtime policy decision through the backend;
- calls MCP only when execution is allowed;
- skips MCP execution when policy blocks;
- creates runtime logs.

### `agent/`

Provider-agnostic LLM agent demo. It supports:

- `mock`
- `gemini`
- `groq`
- fallback provider behavior

The agent validates the structured proposal and sends only approved tool-call requests to the proxy.

### `policies/opa/runtime_policy.rego`

Authoritative Rego runtime policy evaluated by OPA. Current decisions include:

```text
ALLOW, BLOCK, WARN, LIMIT, ASK_APPROVAL, LOG_ONLY
```

The other YAML files under `policies/` are administrative data for identity bindings, subject authorizations, tool profiles, and resource scopes.

## Environment Variables

Example local configuration:

```env
PROJECT_NAME=mcp-security-framework
ENVIRONMENT=local

BACKEND_HOST=127.0.0.1
BACKEND_PORT=8000

FRONTEND_HOST=127.0.0.1
FRONTEND_PORT=5173

POSTGRES_HOST=localhost
POSTGRES_PORT=5432
POSTGRES_DB=mcp_security
POSTGRES_USER=mcp_user
POSTGRES_PASSWORD=change_me

LLM_PROVIDER=mock
LLM_FALLBACK_PROVIDER=mock

GEMINI_API_KEY=
GEMINI_MODEL=

GROQ_API_KEY=
GROQ_MODEL=openai/gpt-oss-20b

LLM_TEMPERATURE=0
LLM_TIMEOUT_SECONDS=20

DEFAULT_POLICY_MODE=block
ENABLE_RUNTIME_LOGGING=true
```

Important:

- `.env` must never be committed.
- API keys must never be printed or exposed.
- `.env.example` must contain placeholders only.

## Local Setup

Required local dependencies:

- Python 3.11+
- pip
- Node.js 20+
- npm
- PostgreSQL 15+
- Git

Check local tools:

```powershell
python scripts/check_dependencies.py
```

Install backend dependencies from `backend/`:

```powershell
cd backend
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
cd ..
```

Install frontend dependencies from `frontend/`:

```powershell
cd frontend
npm.cmd install
cd ..
```

## Run Order

Initialize or sync database tables:

```powershell
cd backend
.\.venv\Scripts\python.exe -m app.db.init_db
cd ..
```

Start backend:

```powershell
.\backend\.venv\Scripts\uvicorn.exe app.main:app --app-dir backend --host 127.0.0.1 --port 8000
```

Start MCP lab server:

```powershell
.\backend\.venv\Scripts\uvicorn.exe server:app --app-dir mcp-lab/http_server --host 127.0.0.1 --port 9000
```

Discover and import the MCP lab server:

```powershell
.\backend\.venv\Scripts\python.exe scripts\provision_service_identities.py
.\backend\.venv\Scripts\python.exe scripts\discover_http_mcp_server.py
```

Run proxy demo:

```powershell
.\backend\.venv\Scripts\python.exe proxy\demo_proxy.py
```

Run frontend:

```powershell
cd frontend
npm.cmd run dev
```

On systems where PowerShell does not block npm scripts, this also works:

```powershell
cd frontend
npm run dev
```

Frontend URL:

```text
http://127.0.0.1:5173
```

## Validation Commands

Compile Python code:

```powershell
.\backend\.venv\Scripts\python.exe -m compileall backend/app proxy agent scripts mcp-lab/http_server
```

Check runtime logs:

```powershell
# Requires an authenticated Control Plane ADMIN or VIEWER session.
Invoke-RestMethod http://127.0.0.1:8000/api/v1/runtime/logs
```

Expected proxy behavior:

```text
read_file("contracts/contract1.txt")
=> decision: ALLOW
=> executed: true
=> mcp_called: true

read_file(".env")
=> decision: BLOCK
=> executed: false
=> mcp_called: false
```

Runtime logs store safe summaries only, for example:

```text
content_items=1, text_length=84, is_error=false
```

Full tool output and file content are not stored in runtime logs.

## LLM Provider Usage

Mock provider:

```powershell
$env:LLM_PROVIDER="mock"
.\backend\.venv\Scripts\python.exe agent\demo_llm_agent.py
```

Gemini provider with mock fallback:

```powershell
$env:LLM_PROVIDER="gemini"
$env:LLM_FALLBACK_PROVIDER="mock"
.\backend\.venv\Scripts\python.exe agent\demo_llm_agent.py
```

Groq provider with mock fallback:

```powershell
$env:LLM_PROVIDER="groq"
$env:LLM_FALLBACK_PROVIDER="mock"
$env:GROQ_MODEL="openai/gpt-oss-20b"
.\backend\.venv\Scripts\python.exe agent\demo_llm_agent.py
```

Expected LLM demo behavior:

- contract prompt proposes `read_file` with `contracts/contract1.txt`, policy returns `ALLOW`, MCP is called, runtime log is created;
- `.env` prompt proposes `read_file` with `.env`, policy returns `BLOCK`, MCP is not called, runtime log is created.

## Runtime Security Behavior

The runtime path enforces these rules:

- the LLM only proposes a JSON tool call;
- the agent validates the proposal and rejects invalid structures;
- the proxy resolves backend inventory metadata;
- OPA evaluates the call before execution;
- `ALLOW`, `WARN`, and `LOG_ONLY` may execute;
- `BLOCK` and `ASK_APPROVAL` do not execute in the current runtime;
- blocked calls still create runtime logs;
- logs keep summaries, not full sensitive outputs.

## Current Limitations

- MCP lab server is local and controlled.
- Runtime policy depends on OPA availability and fails closed when OPA is unavailable.
- No human approval workflow yet.
- No scanner or DevSecOps analysis yet.
- No AWS integration yet.
- No full audit report generation yet.
- Control Plane authentication is intentionally minimal and local-first: ADMIN/VIEWER, HttpOnly sessions, CSRF protection, and audit.

## Next Phases

Planned work:

- MCP security scanner;
- policy enrichment;
- human approval workflow;
- DevSecOps scanning;
- audit and reporting;
- AWS/cloud integration later;
- production hardening for authentication, authorization, and deployment.
