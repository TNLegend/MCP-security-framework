# MCP Security Framework

Framework local de securite et de gouvernance pour agents IA utilisant MCP.

## Objective

The project provides an opt-in security and governance layer for MCP client
connections:

```text
MCP Client -> MCP Security Gateway -> Security Core -> upstream MCP
```

For governed connections, the client is configured with a framework endpoint
such as `/mcp/{server_id}`. The framework resolves the real upstream endpoint
from trusted Inventory, applies identity, Tool Analyzer, ToolSecurityContract,
scope, Emergency Deny, and OPA/Rego controls, and calls the upstream MCP only
after an `ALLOW` decision. If the decision is `BLOCK`, no upstream MCP
`tools/call` request is sent.

The included LLM agent is a demo integration: the LLM proposes user-level tool
intent, and the application builds a governed MCP request. The LLM does not
execute tools directly and does not choose upstream endpoints, capabilities,
roles, scopes, adapters, or trusted security facts.

## Current Status

The current implementation includes the Control Plane foundation, OPA-only
runtime authorization, Security Core v2, and the governed dual-era MCP Gateway.

Implemented:

- real local MCP Streamable HTTP lab server;
- local and remote HTTP/HTTPS MCP discovery/import into the backend inventory;
- backend MCP inventory with native MCP metadata and framework security metadata;
- React Control Center views for dashboard, inventory, analyzer review,
  configuration revisions, Emergency Deny, runtime calls, audit, and ADMIN user
  management;
- MCP Proxy runtime enforcement;
- Policy Engine decision before execution;
- runtime logs stored in PostgreSQL;
- frontend Runtime Logs view for ALLOW/BLOCK proof;
- provider-agnostic LLM agent demo;
- mock, Gemini, and Groq providers;
- fallback provider support;
- safe result summaries instead of full tool output storage;
- PostgreSQL-backed Control Plane revisions and immutable published snapshots;
- Tool Analyzer findings with human approval gates;
- signed configuration revisions and service-to-service Ed25519 requests;
- dual-era/multi-revision MCP gateway support for supported Legacy and Modern
  HTTP MCP profiles;
- framework-held Bearer authentication for upstream MCP servers through local
  secret references.

Docker is not used for the local MVP. The project runs directly with Python, Node.js, and PostgreSQL.

## Architecture Overview

```text
User / LLM / Agent
        |
    MCP Client
        |
        | framework MCP endpoint
        v
MCP Security Gateway
        |
    Security Core
        |
Inventory-selected upstream connection
        |
 +------+------+---------------+
 |             |               |
Local MCP   AWS MCP   Third-party MCP
```

The framework is deployment-agnostic. Upstream MCP infrastructure does not need
framework-specific modification: local and remote HTTP MCP servers use the same
Gateway abstraction, and a third-party MCP can be governed by registering it in
Inventory and configuring the client to use the framework endpoint. The
framework does not own arbitrary third-party MCP servers and does not claim that
unrelated clients cannot contact them directly. Governance applies to the MCP
connection configured through the framework.

Outbound MCP endpoints are parsed structurally and limited to HTTP/HTTPS. URL
userinfo, fragments, metadata/link-local/special destinations, and automatic
redirect following are rejected. DNS answers are checked before each governed
connection; the standard Python HTTP stack performs its own subsequent DNS
resolution, so complete DNS-rebinding resistance still requires deployment
egress controls or a future address-pinning transport. Private, loopback, LAN,
enterprise, AWS-hosted, and public MCP endpoints remain supported. Local lab
trust is assigned only to the exact parsed hosts `localhost`, `127.0.0.1`, and
`::1` over HTTP, never by a hostname prefix.

Optional network isolation, private subnets, AWS Security Groups, or mTLS can
strengthen deployments where the organization controls the MCP infrastructure,
but they are hardening measures rather than base requirements.

For an upstream that accepts a static Bearer credential, Inventory stores only
`auth_mode=BEARER` and a logical `credential_ref`. The token is read locally
from `.runtime/secrets/upstream/<credential_ref>` by discovery and the Gateway;
it is not returned by Inventory APIs or supplied by the agent.

For an HTTP MCP protected by OAuth, an ADMIN can select `OAuth 2.1 (PKCE)` in
Inventory, register a pre-configured client ID (and optional client secret),
then complete the provider consent flow. The framework discovers MCP Protected
Resource Metadata and Authorization Server Metadata, requires PKCE `S256`,
uses the MCP endpoint as the OAuth `resource` indicator, stores the resulting
access/refresh-token bundle under `.runtime/secrets/upstream/`, and refreshes it
only when the Gateway needs to call that same registered MCP. Tokens and client
secrets are never returned by Inventory APIs, audited, or accepted from agents.

Set `UPSTREAM_OAUTH_CALLBACK_URL` and `CONTROL_CENTER_PUBLIC_URL` for a
deployed Control Plane. In local development the callback defaults to
`http://127.0.0.1:8000/api/v1/control-plane/upstream-oauth/callback`; the
Inventory form exposes the effective value to register with the OAuth provider.
The current implementation intentionally supports pre-registered OAuth clients;
dynamic client registration and OAuth client-credentials grants are not enabled.

For the included LLM demo, the forbidden architecture is:

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

## Dual-Era Security Gateway

The proxy terminates an explicit, registry-controlled set of restricted MCP
profiles. Wire validation uses the pinned official `mcp-types` package, while the
framework allowlist remains code-owned so a package upgrade cannot silently enable
a future protocol revision.

| MCP revision | Era | Transport | Status |
| --- | --- | --- | --- |
| `2024-11-05` | Legacy | HTTP+SSE | supported |
| `2025-03-26` | Legacy | Streamable HTTP | supported |
| `2025-06-18` | Legacy | Streamable HTTP | supported |
| `2025-11-25` | Legacy | Streamable HTTP | supported |
| `2026-07-28` | Modern | Streamable HTTP | supported |

The `2024-11-05` path uses the historical HTTP+SSE transport: clients open a
persistent SSE GET, receive an `endpoint` event, deliver JSON-RPC messages with
POST to that endpoint, and receive JSON-RPC responses on the open SSE stream as
`message` events. It does not use `Mcp-Session-Id` as its session primitive.
Streamable HTTP revisions accept both `application/json` and request-scoped
`text/event-stream` responses where the negotiated MCP revision permits them.
Inbound MCP HTTP requests validate any supplied `Origin` against the configured
`MCP_GATEWAY_ALLOWED_ORIGINS` list using scheme, host, and effective port. Missing
`Origin` is accepted for non-browser clients; malformed or untrusted origins fail
with HTTP 403.
Gateway `GET /mcp/{server_id}` dispatches by selected transport: only
`2024-11-05` historical HTTP+SSE emits the `endpoint` event. Streamable HTTP
revisions return HTTP 405 for the optional/removed standalone GET stream in this
restricted implementation.
The restricted framework correlates SSE responses by JSON-RPC id, ignores only
known harmless notifications while waiting for the final response, and fails
closed for unsupported server-to-client requests, malformed events, wrong ids,
timeouts, disconnects, oversized events, or duplicate final responses.

`2024-10-07` is recognized only as a historical Legacy-era revision and is not
enabled in this prototype because it is not present in the current pinned
`mcp-types` registry. Unknown future revisions fail closed.

Modern exposes `server/discover`, `tools/list`, and `tools/call`; Legacy exposes
`initialize`, `notifications/initialized`, `tools/list`, and `tools/call`.
Resources, Prompts, Sampling, Elicitation, MRTR, Tasks, and subscriptions are
unsupported and fail closed even when a protocol revision defines them.

Client and upstream eras/revisions are independent. All supported revision
combinations normalize into one Tool Security Framework v2 based on approved
profile-specific observations, `ToolSecurityContract`, capabilities, resource
types, adapters, authority-qualified scopes, and OPA. No fallback to another
upstream era or revision occurs after authorization.

The v2 catalog is extended through versioned Security Packs. Built-in packs cover
filesystem, HTTP/API, database, messaging, cloud objects, calendars, payments,
process execution, identities, and secrets. An ADMIN can open a discovered tool's
`Contract` tab, select a suggested template, map exact JSON Schema fields, define
authority-qualified scopes, and create a DRAFT. Gemini with Groq fallback can be
requested explicitly for a suggestion, but its output is constrained to installed
templates and existing schema paths and never approves or publishes configuration.
Safe declarative packs can be added through
`POST /api/v1/control-plane/security-packs/declarative`; specialized parsing still
requires a reviewed adapter implementation.

Advanced declarative templates may model multiple conjunctive effects and
capabilities, multiple resource bindings with `RESOURCE`, `SOURCE`, or
`DESTINATION` roles, and bounded argument constraints (`EQ`, `NE`, `LT`, `LE`,
`GT`, `GE`, `IN`, `NOT_IN`, and `MAX_OCCURRENCES`). Multi-resource contracts use
an explicit resource type for each authority-qualified scope. Result controls may
classify a result and force exfiltration tracking through the existing Result
Guard, but a Security Pack cannot disable result inspection, execute arbitrary
code, grant an agent authorization, approve itself, or bypass OPA/Emergency Deny.
The Control Center exposes these fields in the Contract workflow and provides an
Advanced JSON editor whose submitted manifest is still validated by the same
strict declarative backend schema before it can enter a DRAFT.

Security Pack lifecycle management is also governed inside signed v2 configuration.
Custom packs can be validated and installed as JSON packages, tracked by canonical
SHA-256 manifest hashes, upgraded across strict semantic versions, enabled or
disabled, deprecated/restored per version, rolled back to an installed version, and
removed only when no active contract, authorization, scope, or installed dependency
still requires them. Optional detached Ed25519 signatures are cryptographically
verified when supplied and their public-key fingerprint is recorded; verification
proves integrity relative to that supplied key but does not by itself establish a
trusted publisher. Dependency version ranges and cycles are checked fail closed,
and capability/resource/template collisions are rejected. The runtime-facing
`security_packs` list remains only the projection of ENABLED lifecycle installations,
so installing or retaining a disabled version never grants runtime semantics by
itself.

The operator lifecycle is explicit and draft-scoped:

```text
validate package -> install disabled -> review -> enable
                 -> install upgrade -> activate or roll back
                 -> deprecate or restore an installed version
                 -> disable -> remove when no reference or dependency remains
```

Every lifecycle mutation requires a change summary and produces a Control Center
audit event containing the affected pack, revision, version state, and manifest
hash where applicable. Lot 4 packages are data-only manifests interpreted by the
built-in declarative adapter. A pack cannot ship or execute Python, JavaScript, or
another executable payload. Semantics that need a specialized parser or
canonicalizer belong to the reviewed, signed trusted-adapter SDK planned for Lot 5,
not to the declarative package import path.

The supported schema profile accepts bounded local `$defs`/`$ref`, nullable scalar
types, and `oneOf`/`anyOf` variants only when every branch exposes the same
accountable resource paths. External references, recursive references, open
objects, unbounded arrays, and ambiguous unions continue to fail closed.

New v2 published revisions are signed with Ed25519 and form a verified predecessor
chain. The private signing key remains under `.runtime/secrets/`. A v1 revision is
migrated by creating a new v2 DRAFT; historical content and hashes are not rewritten.

Discovery probes Modern and Legacy support independently. It records one tool
observation per supported upstream profile/revision and uses a configurable
periodic rediscovery interval (`MCP_PROTOCOL_REDISCOVERY_INTERVAL_SECONDS`,
default 900).
See [THREAT_MODEL.md](THREAT_MODEL.md) and
[GOVERNED_CONNECTION_CONTRACT.md](GOVERNED_CONNECTION_CONTRACT.md) for the
governed connection boundary, guarantees, and optional deployment hardening.

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
|-- frontend/     React/Vite Control Center UI
|-- mcp-lab/      Local MCP HTTP lab server and test data
|-- scripts/      Dependency checks, provisioning, launcher, and discovery tools
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

React/Vite Control Center for:

- dashboard;
- MCP inventory;
- Tool Analyzer evidence and ADMIN approval/block actions;
- security configuration revisions;
- Emergency Deny management;
- runtime calls;
- audit events;
- ADMIN-only user management.

The inventory view separates native MCP metadata from framework security
metadata and shows the governed Gateway endpoint to configure in external MCP
clients or agents. That URL comes from the authenticated runtime status and is
not hardcoded in React. VIEWER users can inspect evidence only. ADMIN users can use
the existing backend APIs for discovery, approval, configuration lifecycle,
Emergency Deny, and user management.

The Control Center is not a chat application. External MCP clients and agents
remain the framework consumers; the LLM demo is one integration, not the
security boundary.

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

Discovers an MCP HTTP server by probing supported Legacy and Modern profiles,
then imports the discovered server and tools into the backend inventory through
the signed `MCP_DISCOVERY` service identity. The backend also exposes an
ADMIN-only discovery route used by the Control Center; both paths reuse the same
discovery service and outbound endpoint policy. Use `--auth-mode BEARER
--credential-ref <logical-ref>` for a framework-held static Bearer credential.

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

Authoritative Rego runtime policy evaluated by OPA. Runtime execution currently
supports `ALLOW`, `BLOCK`, `WARN`, and `LOG_ONLY`; decisions that require
unsupported runtime obligations such as `LIMIT` or `ASK_APPROVAL` fail closed
until their enforcement semantics are implemented.

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
VITE_API_BASE_URL=http://127.0.0.1:8000/api/v1
MCP_SECURITY_API_BASE_URL=http://127.0.0.1:8000/api/v1

MCP_GATEWAY_HOST=127.0.0.1
MCP_GATEWAY_PORT=9001

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

```

Important:

- `.env` must never be committed.
- API keys must never be printed or exposed.
- `.env.example` must contain placeholders only.
- Local Backend, Gateway, and Frontend host/port values are configured from the
  repository-root `.env`. Vite also reads this root `.env`, so no
  `frontend/.env` is required; only `VITE_*` variables are exposed to browser
  code.

## Local Setup

The supported stage-MVP bootstrap target is a clean Windows installation. It
requires:

- Python 3.11+
- Node.js 20+
- npm
- PostgreSQL 15+
- Git

Create the local configuration from the tracked template and edit its external
PostgreSQL value(s). If `.env` is absent, setup creates it from the template and
stops with the names of values that still require operator input:

```powershell
Copy-Item .env.example .env
# Edit POSTGRES_* for the target PostgreSQL installation.
python scripts/setup_local_environment.py
```

The idempotent bootstrap performs the complete local provisioning flow:

- creates `backend/.venv`, installs `backend/requirements.txt`, and runs
  `npm ci` from the existing frontend lockfile;
- creates `.runtime` and provisions the pinned local OPA `1.18.2` binary;
- provisions the local Analyzer model snapshots
  `MoritzLaurer/multilingual-MiniLMv2-L6-mnli-xnli@0a71e92a985b6e1ad1828cf67ce9c459639c1dca`
  and `intfloat/multilingual-e5-small@614241f622f53c4eeff9890bdc4f31cfecc418b3`;
- generates installation-specific local IDP, Proxy assertion, MCP Proxy,
  Discovery, and revision-signing material under `.runtime/secrets`;
- generates the trusted-session pepper in ignored `.env` when it still has the
  template placeholder;
- checks PostgreSQL, runs the existing idempotent schema initialization, and
  interactively creates the first ADMIN when no active ADMIN exists;
- validates the installation without printing credentials or key material.

Existing valid private keys and an existing active ADMIN are retained. Invalid
private-key material fails setup instead of being silently overwritten. In a
non-interactive environment, setup reports the exact command needed to create
the initial ADMIN.

The operator or provider remains responsible for PostgreSQL credentials,
optional Gemini/Groq demo keys, third-party MCP Bearer credentials, and future
cloud credentials. Third-party MCP credentials are stored through governed
onboarding; the framework does not fabricate them. Optional LLM demo keys are
not required by the core framework.

After setup, start the Backend, local OPA, and Gateway supervisor:

```powershell
.\backend\.venv\Scripts\python.exe scripts\start_framework.py
```

Then start the already-provisioned frontend with `npm.cmd run dev` from
`frontend/`. The dev server reads `FRONTEND_HOST`, `FRONTEND_PORT`, and
`VITE_API_BASE_URL` from the repository-root `.env`. No separate `frontend/.env`,
key generation, OPA/Gateway startup, model download, or schema command is
required in the normal flow. Project-owned relative paths are resolved from the
repository root, independently of the current directory; intentionally absolute
external paths remain supported.

On a pristine Control Plane configuration database, setup also imports the
tracked administrative bootstrap YAML into PostgreSQL as the initial published
configuration. YAML is only bootstrap/import material; runtime configuration
reads PostgreSQL through the published configuration snapshot and has no YAML
fallback. If configuration revisions already exist but no valid active
configuration can be loaded, setup stops instead of selecting or publishing a
revision automatically.

Do not share a raw working-directory archive: it can include ignored `.env`,
`.runtime`, virtual environments, `node_modules`, caches, and private keys.
Create source distributions from tracked content instead:

```powershell
git archive --format=zip --output=mcp-security-framework.zip HEAD
```

Never copy `.runtime`, `.env`, or generated private keys from another
installation. Each installation provisions its own identities.

## Run Order

For manual developer mode, initialize or sync database tables explicitly:

```powershell
cd backend
.\.venv\Scripts\python.exe -m app.db.init_db
cd ..
```

Start backend:

```powershell
.\backend\.venv\Scripts\uvicorn.exe app.main:app --app-dir backend --host 127.0.0.1 --port 8000
```

Easy local mode can use the framework launcher instead. It checks PostgreSQL,
starts or reuses the project-local OPA process from `.runtime/tools/opa/opa.exe`,
starts or reuses the configured local identity provider, Backend, and Gateway.
An external JWKS provider is checked but never launched by the framework. It only uses
fixed framework commands with `shell=False` and only terminates child processes
it started. If PostgreSQL is unavailable and
`LOCAL_RUNTIME_MANAGED_POSTGRES_COMMAND_JSON` contains an explicitly trusted
local argv array, the launcher starts it and waits for readiness. Without that
configuration startup fails clearly. A PostgreSQL process started this way is
left running on framework shutdown because it is stateful infrastructure.
Backend, OPA, and Gateway children are monitored; an unexpected exit stops the
remaining framework-owned children and makes the launcher exit non-zero:

```powershell
.\backend\.venv\Scripts\python.exe scripts\start_framework.py
```

Manual mode remains available. Start OPA, Backend, and Gateway in separate
terminals; the launcher reuses healthy externally started services and never
terminates them:

```powershell
.\.runtime\tools\opa\opa.exe run --server --addr 127.0.0.1:8181 policies\opa
.\backend\.venv\Scripts\python.exe -m uvicorn app.main:app --app-dir backend --host 127.0.0.1 --port 8000
.\backend\.venv\Scripts\python.exe -m uvicorn proxy.gateway_app:app --host 127.0.0.1 --port 9001
```

Start the bundled MCP lab server in a separate terminal:

```powershell
.\backend\.venv\Scripts\python.exe -m uvicorn server:app `
  --app-dir mcp-lab/http_server `
  --host 127.0.0.1 `
  --port 9000
```

The bundled MCP lab is an upstream test MCP server. It is intentionally not
started by the framework supervisor because real upstream MCP servers may be
local, LAN, enterprise-hosted, cloud-hosted, or third-party services with their
own lifecycle. A simple liveness check with `curl.exe -i http://127.0.0.1:9000/mcp`
is expected to return HTTP 405; MCP discovery uses the POST protocol flow.

Discover and import the MCP lab server from the CLI, or use the ADMIN MCP
Inventory page in the Control Center:

```powershell
.\backend\.venv\Scripts\python.exe scripts\discover_http_mcp_server.py
```

The focused provisioning scripts remain available for manual debugging, but
normal installation invokes them through `setup_local_environment.py`.

Run proxy demo:

```powershell
.\backend\.venv\Scripts\python.exe proxy\demo_proxy.py
```

Run frontend:

```powershell
cd frontend
npm.cmd run dev
```

The frontend host and port come from the repository-root `.env`; the displayed
URL below is the default configuration.

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
- OPA/Rego evaluates the call before execution;
- only validated `ALLOW` decisions with supported obligations may execute;
- `DENY`, `DEFER`, invalid decisions, unavailable OPA, missing trusted facts,
  unapproved tools, and blocked analyzer states fail closed before MCP;
- blocked calls still create runtime logs;
- logs keep summaries, not full sensitive outputs.
- high-confidence secrets and prompt injection in tool results are withheld;
- temporary per-session content fingerprints block read-then-send replay without
  retaining the returned content in the taint store.

## Current Limitations

- Governance applies to MCP connections configured through the framework
  endpoint. Direct client reconfiguration or unrelated clients directly
  accessing a third-party MCP are outside the base framework boundary.
- Upstream authentication supports no-auth, framework-held Bearer references, and
  interactive OAuth 2.1 Authorization Code with PKCE for pre-registered clients.
  Dynamic client registration and client-credentials grants remain unsupported.
- DNS answers are screened for special destinations before outbound requests,
  but transport-level DNS pinning is not yet implemented.
- Runtime policy depends on OPA availability and fails closed when OPA is unavailable.
- Scanner and DevSecOps analysis are not a complete production pipeline yet.
- No AWS integration yet.
- No full audit report generation yet.
- Control Plane authentication is intentionally minimal and local-first: ADMIN/VIEWER, HttpOnly sessions, CSRF protection, and audit.

## Next Phases

Planned work:

- MCP security scanner expansion;
- policy enrichment;
- Control Plane approval UX hardening;
- DevSecOps scanning integration;
- audit and reporting;
- AWS/cloud integration later;
- production hardening for authentication, authorization, and deployment.
