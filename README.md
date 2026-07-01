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

## Repository Structure

```text
mcp-security-framework/
|-- backend/      FastAPI API, PostgreSQL models, inventory, policies, decisions, logs
|-- frontend/     React/Vite UI for dashboard, inventory, policies, runtime logs
|-- mcp-lab/      Local MCP HTTP lab server and test data
|-- scripts/      Dependency checks and MCP discovery/import script
|-- proxy/        Runtime enforcement layer
|-- agent/        Provider-agnostic LLM agent demo
|-- policies/     YAML policy rules
|-- scanners/     Reserved for future scanning modules
|-- docs/         Ignored local documentation workspace
|-- reports/      Ignored local report output
|-- .env.example
|-- .gitignore
`-- README.md
```

## Implemented Components

### `backend/`

FastAPI backend backed by local PostgreSQL. It stores MCP servers, MCP tools, policy rules, runtime calls, policy decisions, and audit events. It exposes inventory, policy decision, health, and runtime log routes.

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
- asks the Policy Engine for a decision;
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

### `policies/default_rules.yaml`

YAML rules used by the Policy Engine. Current decisions include:

```text
ALLOW, BLOCK, WARN, LIMIT, ASK_APPROVAL, LOG_ONLY
```

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
- the Policy Engine evaluates the call before execution;
- `ALLOW`, `WARN`, and `LOG_ONLY` may execute;
- `BLOCK` and `ASK_APPROVAL` do not execute in the current runtime;
- blocked calls still create runtime logs;
- logs keep summaries, not full sensitive outputs.

## Current Limitations

- MCP lab server is local and controlled.
- Policy rules are still simple YAML rules.
- No human approval workflow yet.
- No scanner or DevSecOps analysis yet.
- No AWS integration yet.
- No full audit report generation yet.
- No production authentication or authorization layer yet.

## Next Phases

Planned work:

- MCP security scanner;
- policy enrichment;
- human approval workflow;
- DevSecOps scanning;
- audit and reporting;
- AWS/cloud integration later;
- production hardening for authentication, authorization, and deployment.
