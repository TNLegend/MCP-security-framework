# MCP Security Framework

## Portable installation — single launch

**Windows:** clone the source repository and double-click `start_framework.bat`
(or run it from a terminal). The launcher checks Python 3.11–3.13, Git,
Node.js/npm, and PostgreSQL 15+. On Windows with `winget`, missing system
prerequisites are installed using their official packages. Windows permission
prompts or a terminal restart may still be needed for system installers.
Then the Python virtual environment, pinned `backend/requirements.txt`,
frontend lockfile dependencies, OPA, security scanners, service identities,
database schema, and model caches are prepared. The launcher starts the
local backend, MCP lab, OPA, gateway, identity provider and the React frontend.

**Public fine-tuned M4 checkpoints** are hosted separately from GitHub:

- [GLiNER PASS10](https://huggingface.co/tnlegend/mcp-security-m4-gliner-pass10) — Apache 2.0, with Microsoft MIT attribution.
- [DeBERTa V2](https://huggingface.co/tnlegend/mcp-security-m4-deberta-v2) — MIT.

The installer anonymously downloads their **pinned Hugging Face commits**,
checks every executable model file's frozen SHA-256 and size, and installs
them to `.runtime/models/m4_semantics/GLINER/` and
`.runtime/models/m4_semantics/DEBERTA_V2/`. No Hugging Face account or
token is required. Exact model-bundle inventory is preserved for local
SHA-256 integrity (without an owner signature). Upstream license texts and attribution notices are downloaded
separately to `.runtime/models/m4_redistribution_notices/` on fresh install;
see each model repository's LICENSE, NOTICE, and README. Already verified
models are reused offline. M6 E5 is independently downloaded from its
public upstream repository; it is not part of the M4 semantics model.

**Experimental M3 Prompt Guard 2 V3 (Phase 3, B3 research):** the selected English
MCP-description classifier is **research SHADOW only**, never an authorization
or BLOCK source. It is **OFF by default**. A pinned, verified local V3
checkpoint can be provisioned without modifying M4 or M6:

```text
# Set M3_PG2_V3_SOURCE_DIR to the local folder containing V3 model.safetensors
# plus config.json, tokenizer.json, tokenizer_config.json, special_tokens_map.json.
# The existing start_framework script then installs those files during setup.
# Or install explicitly with backend/.venv Python:
python scripts/install_m3_pg2_v3.py --source "<local V3 checkpoint folder>"
python scripts/install_m3_pg2_v3.py --verify-only
```

**Public V3 model (research-only):** [Llama-MCP-Prompt-Guard-2-V3](https://huggingface.co/tnlegend/Llama-MCP-Prompt-Guard-2-V3)
is a text-only fine-tune of Meta Llama Prompt Guard 2 86M, licensed under
the **Llama 4 Community License** (not MIT/Apache). **Built with Llama.**
See its LICENSE, NOTICE, USE_POLICY.md, and README for source attribution,
redistribution conditions and restrictions. The derivative's model name
starts with Llama as required by that license.

The EXISTING startup now installs V3 anonymously using the immutable
`HF_FROZEN_REVISION`, verifies five model files and four legal notices,
and leaves the optional classifier **OFF unless explicitly opted in**.
A local source override `M3_PG2_V3_SOURCE_DIR` or alternative explicitly
pinned 40-character `M3_PG2_V3_HF_REVISION` is supported; neither implies
production qualification. To install manually:

```text
python scripts/install_m3_pg2_v3.py --from-public-hf
python scripts/install_m3_pg2_v3.py --verify-only
```

The former private-HF upload helper is historical and is **not** the
deployment path. Never paste tokens into chat or commit them to Git.

The installed model resides at `.runtime/models/m3_prompt_guard2_v3/` (never
committed). Its full model SHA-256 is
`5751dd3a08fad1178d835941a8ad98e019aadcdb6dcfd54a616d9908b0204bf8`.
For isolated **research QA only**, set `M3_PG2_V3_SHADOW_ENABLED=true`.
Since Phase 3 Lot B3, the engine returns a source-bound
`m3_report.neural_shadow` **PENDING** ticket without performing any Torch
inference in the request thread. One bounded dispatcher worker sends each
job to a **separate persistent subprocess using 4 CPU threads**. The subprocess
can be killed on IPC timeout; it is not a privileged sandbox or RAM limit.
Internal QA can retrieve its result using
`lookup_v3_neural_shadow_job(job_id, source_sha256=...)`; results expire and
are lost on restart. Existing authenticated control-plane ADMIN-only
read-only endpoints expose SHADOW health, an ephemeral job list, and a source-
SHA-bound result lookup under `/control-plane/tool-analysis/shadow/`.
Queue overflow, unknown language, deadlines and worker failures stay
incomplete/unknown, never benign. An IPC timeout kills the inference child. This build intentionally does not
impose an additional OS RAM cap or privilege sandbox on the research worker;
the existing input-size, queue, and timeout safety checks remain in place.
Phase 3 B11 QA (2026-11-18) exercised the actual HTTP Gateway, actual backend
and published Control Plane configuration, PostgreSQL, OPA and the bundled MCP
HTTP lab together. The QA created temporary ADMIN, agent JWT and service keys,
then performed genuine review and publication operations with the framework's
services (no mock backend approval or owner M4 signature). The modern client
was mediated to the lab's Legacy 2025-11-25 upstream protocol: an approved
read of test data returned HTTP 200 and an out-of-scope read was denied HTTP
403 before upstream execution. This validates local QA mediation with generated
QA actors, **not** authorization for production users or third-party servers.
Normal startup downloads the frozen public V3 assets but leaves inference
disabled unless explicitly enabled.
Do not enable this experimental queue in a production Gateway.
Existing deterministic decisions and M1/M2/M4/M6/M7 authority boundaries remain
unchanged. No pretrained or fine-tuned model may authorize or block MCP calls.

**Phase 3 research SHADOW qualification (B10/B11, 2026-11-18):**
M3 V3 model bytes are frozen at the SHA-256 above. The old MiniLM path,
dead M3 experiments, obsolete signing utilities, stale redundant caches and
transient QA files have been removed or explicitly retained only as archival
evidence. The normal installation needs no M4 owner-signing step, no extra
OS RAM cap was added to the M3 worker, and no additional training was done.

The historical, non-independent diagnostic cohort of 107 MCP descriptions
(39 author-declared attacks / 68 author-declared benign) yielded 27/39
attack flags and 0/68 benign flags at reporting threshold 0.5; in another
out-of-domain agentic benign group, 17/30 were flagged. Those examples and
labels are not independent human-certified ground truth. No sealed TEST
split was opened. There are **no certified production precision/recall
claims**, and V3 remains optional English-focused raw-description-only
research SHADOW.

On source revision `da240845`, prior focused QA passed 390 tests with
3 archived Git-commit-pin failures and 2 skips; targeted backend tests
passed 101 plus 63 subtests. A full backend run did **not** go green:
3,110 passed, 386 failed, 35 errors, 119 skipped and 405 subtests passed.
Many failures have old experiment/signature contracts or QA setup
dependencies; all remain visible, including cases needing investigation.
A second preprovisioned global run stopped at its 40-minute budget, so
it is not counted as a successful full regression. These historical
backend failures and environment-dependent integrations are not silently
waived. Phase 3 may be used as **research SHADOW**, not as a production
security certification. See the separate QA repository's B10/B11
qualification records; private fixtures, results and logs stay out of
the framework source repository.

**B12 obsolete-code and historical-test cleanup (2026-11-18):**
The never-imported V13 `tda/shadow/effects.py` and
`tda/shadow/instruction_hierarchy.py` prototypes, their package stub,
and the unused disabled `tda/sidecar.py` shim were removed after an
import-reference audit. Existing M3 V3 SHADOW, M4, M6/E5 and M7 paths
remain intact. The obsolete local V2 priority bridge and legacy suites
that exercised removed experiments/signature ceremony were archived
outside the collected test tree, not marked xfail/skip. Applicable
deterministic extraction, analyzer/E5 and administrative security tests
were updated to current SHA-256/local-generation contracts.

The backend's `backend/tests/` directory is intentionally ignored in
this source repository; the old test originals and local QA environment
remain outside public source Git. Portable replacement regression tests
live in the separate QA repository. **3,421 backend tests collected
without collection errors** after B12 cleanup; security-focused targeted
tests also passed. The complete separate QA suite reported **419 passed,
2 skipped, 4 warnings, 0 failures**. Three previously failing archival
source-pin tests now check their **original, unchanged commit objects**
instead of requiring today's checkout to equal an obsolete commit; the
research source metrics and their pinned SHAs are not republished as new
results. This verifies the updated test inventory and QA scope, **not**
a fully green backend regression: the original B11 environment-specific
failures and unresolved tests require separate QA qualification, and
the production Gateway latency limitation has not been waived.

**B13 obsolete-code and portable source-closure cleanup (2026-11-18):**
The old experimental M3 design-envelope adapter and the unused V1-style M7
semantic-score corroboration module were removed. M4 hypothesis projection now
lives directly in M7 (no M3 compatibility alias), while the explicit M3
instruction-review entrypoint no longer lives under M7. Unused legacy
semantic-score threshold and category-label constants were retired; active
M3/M4/M6/E5/M7 analysis and deterministic BLOCK/REVIEW protections remain.

A previous execution fingerprint named the Git-ignored
`scripts/replay_tda_engineering.py` research helper, which does not exist on
a fresh clone. The executable source closure no longer requires it. Both M4
source inventories now exclude **only** explicitly Git-ignored local QA
scripts, frontend test files and OPA `*_test.rego` files while preserving
hashing of production source modules, runtime scripts and policy files.
Unreviewed source files outside those narrow QA patterns remain inventoried,
and source symlinks remain rejected. This fixes identity differences caused
solely by private research files on a developer workstation.

The analyzer revision is now
`tool-description-analyzer-v19.4-local-sha256-runtime-closure`. As with
any analyzer source change, restart the framework and let PostgreSQL establish
the new local generation; previous tool analyses and approvals must not be
silently reused. No M4 owner-signature ceremony is reintroduced, and
Control Plane revision signing, service identities, OPA and Gateway admission
checks are unchanged. Private archive evidence and updated regression tests
are stored only in the separate QA repository; production readiness is
**not** inferred from this maintenance pass.

**On Linux/macOS:** `./start_framework.sh` uses Python and the same source
bootstrap, but the system prerequisites (Git, Node/npm, PostgreSQL server
binaries) must first be installed with the operating system's package manager.

**M4 model integrity without owner signatures:** the installer downloads
GLiNER PASS10 and DeBERTa V2 from pinned public Hugging Face revisions,
verifies their published file SHA-256 values, and computes a **local**
source/model/analyzer fingerprint when the backend starts. There is no
Ed25519 owner key, certificate, approval manifest, or manual signature
step. The same code can be installed under different Python/venv paths;
each installation computes its own fingerprint.

A local fingerprint is **not** cryptographic publisher authentication:
an attacker who controls the installed code and the expected hashes can
modify both. Run trusted, pinned source and dependencies. If the installed
analyzer changes, PostgreSQL advances its local generation and **old
analysis/approval evidence must not silently authorize dispatch**.
M4 remains English-only and advisory; no model result alone ALLOWs or
BLOCKs an MCP operation. Independent ADMIN tool approvals, policy checks,
M1/M2/M3/M5/M6/M7 checks, and Gateway enforcement remain required.
The retired signed V19 launch/sign tools are not part of normal setup.

**Source publication:** GitHub contains source and mandatory declarative
configuration plus this README. Models and trained weights remain on the dedicated **public Hugging Face**
model repositories with their licenses and immutable revisions, never in
GitHub. Logs, QA datasets, test results, qualification reports, release
manifests and secrets remain local/private and are not committed.

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
  secret references;
- Build Security with safe Local/Git/Inventory target intake, project-managed
  Semgrep/Gitleaks/Trivy scanners, normalized findings, deterministic
  `PASS/WARN/BLOCK/ERROR` assessment, audit, and finding history;
- optional signed Build evidence attached to Control Plane DRAFTs and enforced
  by OPA after VALIDATE/PUBLISH, with stale/missing/incomplete evidence failing
  closed when the Build gate is enabled.

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
redirect following are rejected. The built-in MCP HTTP/SSE, Discovery and upstream OAuth paths now use a
shared DNS-pinned HTTP(S) transport (common/pinned_http.py): all resolved
addresses are validated, and each socket connects directly to a validated
numeric address while retaining hostname-based TLS SNI/certificate checks.
Redirects and environment proxies are rejected. These transport protections
apply to the built-in paths; independently integrated/custom transports and
untrusted remote MCP implementations require separate security validation
and deployment egress controls. Private, loopback, LAN, enterprise,
AWS-hosted, and public MCP endpoints remain supported subject to policy. Local lab
trust is assigned only to the exact parsed hosts `localhost`, `127.0.0.1`, and
`::1` over HTTP, never by a hostname prefix.

Optional network isolation, private subnets, AWS Security Groups, or mTLS can
strengthen deployments where the organization controls the MCP infrastructure,
but they are hardening measures rather than base requirements.

For an upstream that accepts a static Bearer credential, Inventory stores only
`auth_mode=BEARER` and a logical `credential_ref`. The token is read locally
from `.runtime/secrets/upstream/<credential_ref>` by discovery and the Gateway;
it is not returned by Inventory APIs or supplied by the agent.

For an HTTP MCP protected by OAuth, an ADMIN can select `OAuth 2.1 (PKCE)`
in Inventory and complete the provider consent flow. The framework discovers MCP
Protected Resource Metadata and Authorization Server Metadata, requires PKCE
`S256`, uses the MCP endpoint as the OAuth `resource` indicator, and stores the
resulting access/refresh-token bundle under `.runtime/secrets/upstream/`.
A pre-registered client ID (and optional client secret) can be supplied, or the
framework can use Dynamic Client Registration when the authorization metadata
advertises a valid registration endpoint. Tokens and client secrets are never
returned by Inventory APIs, audited, or accepted from agents.

Set `UPSTREAM_OAUTH_CALLBACK_URL` and `CONTROL_CENTER_PUBLIC_URL` for a
deployed Control Plane. In local development the callback defaults to
`http://127.0.0.1:8000/api/v1/control-plane/upstream-oauth/callback`; the
Inventory form exposes the effective callback value. OAuth client-credentials
grants are intentionally not supported.

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
canonicalizer belong to the reviewed, signed Trusted Adapter SDK implemented in Lot 5,
not to the declarative package import path.

The Lot 5 Trusted Adapter SDK now provides a stable, fail-closed extension point
for reviewed specialized parsers and result validators. Built-in reference
adapters cover SQL, shell execution, payments, cloud IAM, Git, and messaging in an
opt-in pack that does not reinterpret existing contracts. External registrations
require a verified detached Ed25519 signature over the reviewed distribution;
adapter ID collisions, unsupported API versions, stale implementation snapshots,
and malformed specialized results are rejected. The Control Center exposes the
read-only adapter catalog and its validation/trust metadata. See
`docs/TRUSTED_ADAPTER_SDK.md` for the extension contract.

When no installed template matches a tool, the Contract view now separates the
direct declarative path from the specialized-adapter path, explains the trust
boundary, ranks nearby reviewed adapters only as non-authoritative onboarding
signals, and offers bounded fail-closed starter archives. The operator utility
creates, signs, validates, and installs reviewed distributions without accepting
executable uploads through the Control Center:

```powershell
python scripts/trusted_adapter.py starter blank widget-adapter .runtime/adapter-work/widget
python scripts/trusted_adapter.py sign .runtime/adapter-work/widget path/to/reviewer-private.pem .runtime/widget-adapter.zip
python scripts/trusted_adapter.py validate .runtime/widget-adapter.zip --trusted-fingerprint <sha256>
python scripts/trusted_adapter.py install .runtime/widget-adapter.zip .runtime/trusted-adapters --trusted-fingerprint <sha256>
```

`TRUSTED_ADAPTER_DIRECTORY` and `TRUSTED_ADAPTER_SIGNER_FINGERPRINTS` are read by
both the backend and Gateway. Every distribution is bounded, checked for an exact
archive layout, verified against the explicit signer allowlist, imported only after
signature verification, and activated by restarting both processes together.

Lot 6 adds Controlled AI Assistance inside Tool Analysis. The assistant is ADMIN-only,
advisory-only, and evidence-bound: a completed analysis must match the tool's current
fingerprint before a provider is called. Tool descriptions, schemas, findings, and the
optional operator question are treated as untrusted data; provider context is bounded
and sensitive-looking values are redacted.

The AI Assist tab supports Explain, Risk summary, Suggest next step, Compare options,
and Draft onboarding. Normal advisory modes may reference only evidence, templates,
and adapters supplied by the framework. Unknown IDs and unsupported actions fail
closed. Draft onboarding reuses the constrained Security Pack onboarding path and
returns a non-authoritative preview only.

Controlled AI cannot approve or block a tool, publish a revision, grant capabilities,
install or sign adapters, modify OPA, execute MCP calls, or disable Emergency Deny.
Successful and failed assistance requests are audited. See
`CONTROLLED_AI_ASSISTANCE.md` for the trust boundary and guarantees.

Lot 7 adds Runtime Operations. Governed calls persist bounded mediation, policy,
upstream MCP, and result-guard timings. The authenticated Operations page exposes
service readiness, exact recent call counters, sampled p50/p95/p99 latency evidence,
PostgreSQL pool state, bounded Runtime Call storage, and process-log rotation policy.

Runtime Calls are indexed for the filters used by the Control Center. Retention is
bounded by age and maximum row count, batch-limited, protects calls referenced by
policy-decision evidence, and supports both audited ADMIN preview/apply and bounded
automatic maintenance. Framework-owned process logs rotate actively by size.

The local supervisor uses bounded restart attempts and backoff for Backend, OPA,
Gateway, and the local identity provider. Exhausted or failed recovery stops the
framework instead of continuing partially. The concurrent benchmark harness can assert
EXECUTED or BLOCKED outcomes under load so performance testing also detects fail-open
behavior. See `RUNTIME_OPERATIONS.md` for the operational boundary and benchmark flow.

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

### Discovery generation identity and duplicate-tool protections (F11)

Both the legacy MCP `tools/list` pagination loop and the modern
`tools/list` discovery loop now maintain a profile-local set of tool
names for the complete in-memory generation. A duplicate within or across
pages is rejected before the discovery payload is returned. Discovered
names also use one common strict validator for paging and signed import:
1–255 printable NFC characters, no leading/trailing whitespace or
invisible formatting controls. The inventory database stores at most
255 characters for a tool name, so overlong names fail before mutation.
Each page is validated before updating cursor/name sets. The
`MAX_DISCOVERY_TOOLS=2000` ceiling is enforced over **all protocol profile
observations combined**, not reset for each profile; the 60-second
discovery deadline is likewise shared across negotiation and all profiles.
Both loops accept that same absolute monotonic deadline, and exceeding
either global budget refuses the whole discovery with no partial import.
Fixtures cover 75, 100, 500 and 1000 tools over real synthetic legacy and
modern pagination loops, cross-profile overflow, and a first-profile
deadline overrun. The deadline is cooperative at HTTP-call boundaries:
it cannot preempt a single blocking network operation without the
transport's own timeout and watchdog. Page-count and cursor-cycle limits
remain independently enforced.

A provider-specific optional `catalogRevision` **extension** is now
validated consistently across every `tools/list` page and all advertised
protocol profiles in one discovery. Mismatched, omitted-after-present or
malformed revisions fail closed with no partial payload. Set
`MCP_DISCOVERY_REQUIRE_CATALOG_REVISION=1` on the discovery backend/client
to **require** this metadata on every page; any non-`0`/`1` setting is
rejected. The default `0` retains protocol compatibility and does **not**
attest a stable remote snapshot when the revision is absent. The revision
is provider-asserted, not cryptographically authenticated: an upstream
server that lies or mutates between requests cannot be made to expose an
immutable snapshot by client-only logic. A signed provider version or
snapshot/session contract is required for that higher assurance.

The signed internal `/inventory/import-discovery` path and admin
discovery paths additionally reject duplicate **(tool name, upstream
protocol profile)** pairs *before upserting any inventory row or running
any Analyzer work*. Identically named tools from distinct supported
profiles remain valid independent observations. Synthetic fixtures exercise
both real page loops, import preflight, cursor limits, and a generation of
1,000 unique tools over 25 pages.

A PostgreSQL generation-fencing authority is implemented in
`backend/app/services/discovery_generation.py`, with durable
`MCPDiscoveryHead` / `MCPDiscoveryGeneration` records. ADMIN discovery
routes reserve and commit a generation **before** remote I/O; publication
executes inventory import under the same transactional advisory lock and
rejects a generation superseded by a newer reservation. The signed internal
CLI calls `/inventory/reserve-discovery` **before network discovery**, then
includes the signed reservation UUID in `/inventory/import-discovery`.
If the CLI loses the import's HTTP response, it **does not replay the
import**. Instead, it performs a separate signed, read-only
`GET /inventory/discovery-generations/{generation_id}` and validates
the returned UUID, committed state and `may_retry_import=false`.
A `PUBLISHED` result confirms the transaction committed (without
inventing the lost import summary); any other state, invalid status or
unavailable read fails closed as uncertain. The status endpoint is restricted
to the signed Discovery service identity, does not expose credential
fingerprints or endpoint scopes, and never itself authorizes a retry.
Unreserved historical imports now return HTTP 428; superseded, expired or
wrong-endpoint generations return HTTP 409 with no inventory mutation. The
reservation expires after 30 minutes to prevent a crashed worker publishing
an arbitrarily delayed result. Both the admin and signed-service paths
require PostgreSQL for this durable authority.

F11 context binding extends each durable generation with a nullable
`context_hash` (SHA-256 of canonical protocol/authentication metadata).
Both signed Discovery reservations and ADMIN discoveries pin the requested
authentication mode, credential reference and protocol version; registered
ADMIN rediscovery also pins the current profile and OAuth config snapshot.
At publication the signed import must match the reserved context, and the
existing server row is locked before any inventory upsert. This prevents
stale signed imports from restoring rotated credential references or pinned
profiles. An **unpinned discovered profile** may legitimately change and
must pass through Analyzer observation/review; it is not an automatic
authorization. The CLI has been updated to reserve with the original
protocol/authentication context before network discovery. The initial
requested protocol hint is retained separately as
`reserved_protocol_version`, because an authorized MCP negotiation can
legitimately select a different recognized version. The observed
`protocol_version` must match `negotiated_protocol_version` when reported,
be among advertised supported versions, and exist in the framework's
protocol registry; it does not silently replace the signed reservation's
requested-version context. Existing registered servers retain their
pinned protocol version unless explicitly reconfigured. For **BEARER**
credentials, the backend also resolves the trusted local secret at both
reservation and publication and incorporates a digest of that token
material in the context hash (never storing the token itself). An in-place
BEARER rotation under an unchanged `credential_ref` therefore causes the
older generation to fail closed, and unavailable/invalid credentials do
not authorize a discovery. The secret store must be consistent across
participating workers; independent host-local copies do not provide
the same guarantee. For **OAuth**, use the explicit connection-generation
binding of the v2 OAuth configuration rather than the refreshable access
token; multi-host credential/version authority remains work for F13.
For both signed import and ADMIN import, a second trusted credential
context check runs **after Inventory/Analyzer writes, before publication in
the same PostgreSQL transaction**. A BEARER rotation during a long import
therefore rolls back all staged Inventory writes rather than marking a
stale generation PUBLISHED. This check is not a distributed lock on a
remote secret service; the last check-to-commit window still exists.
There is no distributed transaction with a third-party MCP's filesystem
or credential service.

The active schema requires the reviewed migration
`scripts/migrations/20261025_f11_discovery_jobs.sql`, including the
additive `context_hash` column; **do not apply it to the production
database automatically**. Old in-flight generations without context
binding must be allowed to expire or explicitly cancelled during migration.

QA tests cover serialization, superseding, rollback, failure states and
profile-scoped import. Additional F11 crash fixtures use real independent
Windows processes terminating immediately **before** and **after** an
Inventory+generation PostgreSQL commit: the status is respectively
`RUNNING` with zero persisted Inventory rows and `PUBLISHED` with one
persisted Inventory row, never permission to retry. The fenced
Discovery-to-Inventory database import is also exercised with **75, 100,
500 and 1000 distinct tools**, exact persisted counts, and a deliberate
Analyzer failure at item 40 causing full transaction rollback. The large
batch uses a mocked Analyzer for throughput isolation; a separate small
six-tool batch exercises the real Analyzer and protocol-observation tables.
An additional ephemeral loopback **HTTP JSON-RPC MCP** fixture serves
75/100/500/1000 tools over real transport paging and verifies refusal of
revision drift. A separate end-to-end fixture uses 20 actual HTTP pages
(1000 tools, strict revision mode), then creates a fenced PostgreSQL QA
reservation, imports all 1000 rows and confirms the generation is PUBLISHED.
The 1000-tool import still mocks the semantic Analyzer for isolation.

These QA fixtures do **not** prove semantic quality for 1000 descriptions
or immutable snapshots from a mutating remote provider. Full real-provider
end-to-end deployment verification is still required. Legacy SQLite-only route tests must
mock this PostgreSQL-only authority while PostgreSQL QA integration tests
exercise it for real; never weaken the runtime PostgreSQL requirement
merely to make an in-memory SQLite unit test pass. A non-mutative old/new
response-order reproducer is retained at
`.runtime/coverage-20261024/lot33_f11_stale_generation_probe_20261025.py`,
which demonstrates why publication fencing is necessary, not the current
behavior of a migrated and enabled deployment.

An opt-in recovery/retention reconciler is now provided at
`scripts/reconcile_discovery_generations.py`. It defaults to a **read-only**
preview of expired RUNNING reservations. An apply run requires both
`--expected-db <exact PostgreSQL database name>` and `--confirm-apply`
alongside `--apply`, with bounded batches. The reconciler marks expired
RUNNING generations FAILED and prunes older terminal generations while
preserving each scope's latest reservation, latest published evidence,
and monotonically increasing head. It does not request credentials,
contact remote MCP servers, or replay possibly side-effecting calls.
The operation is intended for a reviewed periodic maintenance schedule:
**it is not automatically scheduled or running in this repository**.

An automatic remote rediscovery/resumption service still requires a
durable, authenticated and version-pinned job payload (endpoint, profile,
credential generation, state and retry policy), plus explicit safe retry
semantics. It is NOT implemented or proven by mere expiry reconciliation.
Credential-generation drift in the external discovery CLI, cache
invalidation, and full 75–1000-tool E2E load across multiple processes/
hosts remain F11 work. Expiry is fail-closed, not auto-resumption.
An upstream changing tool definitions during pagination is not proven to
offer an immutable snapshot without provider support.

### Filesystem lexical dialects and physical confinement limits (F08)

The `filesystem_path` security reference canonicalizer now accepts an
explicit trusted `filesystem_path_dialect`: `PORTABLE` (conservative default),
`POSIX`, or `WINDOWS`. The `WINDOWS` dialect canonicalizes ASCII case for
subtree and SELF matching, and both `PORTABLE` and `WINDOWS` reject Win32
device names (`CON`, `NUL`, `AUX`, `PRN`, `COM1..9`, `LPT1..9`, including
extension aliases) and trailing dots. `PORTABLE` additionally rejects uppercase/mixed-case
segments: it must not silently reinterpret one signed POSIX path as a
case-folded Windows path. For historical mixed-case scopes an administrator
must deliberately select and review the explicit dialect. Explicit POSIX
dialect preserves its ordinary case-sensitive names. UNC paths, drive letters, backslashes, device
paths, alternate data streams and parent traversal remain denied by this
version of the grammar. In Windows dialect, slash-rooted `ABSOLUTE` paths
are also rejected because their identity depends on a current drive; new
absolute Windows filesystem authorities need a separately designed,
versioned volume-root reference type and explicit review.

**Important scope of the guarantee:** these are lexical references for
authorization, **not** OS handles or proof of an upstream MCP's filesystem
confinement. A symlink, junction or reparse point can redirect a syntactically
valid `scope/path` outside its permitted root; the target can change after
validation. The proxy does not own the untrusted remote MCP's filesystem
operation and therefore cannot atomically open its files with no-follow
semantics. Do not advertise actual local/remote filesystem confinement from
a successful lexical scope check. A stronger guarantee requires a trusted
resource-serving adapter performing real operations on pinned, verified file
handles with platform-specific no-follow and TOCTOU mitigations, or an
independent process/container filesystem sandbox with verified mounts.
Windows junction and symlink TOCTOU tests are isolated QA demonstrations
of this distinction, not assertions of sandboxing.

Deployment/review: changes to case semantics or dialect for an existing
authorization require a new explicit scope/contract review. Do not silently
rewrite historical signed scopes or assume all upstream servers use the
proxy host's path semantics.

### Declared data production and result tracking (A6/F10)

The Security Pack capability catalogue supports an optional signed
`produces_data` boolean, and reviewed tool `result_control` declarations
can assert `produces_data` as well. These optional fields are omitted when
absent, preserving historical manifest and contract hashes. They travel via
the published capability catalogue into the Runtime Result Guard.

A `true` assertion by **any** effect, or a signed sensitive/secret result
classification, requires data-flow fingerprint tracking. Only a capability
catalogue where **every effect is explicitly `produces_data=false`**
allows tracking to be skipped. Missing metadata, unknown capabilities and
malformed catalogues are treated as **UNKNOWN**, conservatively tracked,
never automatically public. A tool's name or suffix cannot override signed
capability semantics; a negative tool-level declaration cannot suppress
another effect or an unknown catalogue entry.

Migrating a legacy Security Pack or tool contract to carry these assertions
requires deliberate review and a new signed revision. No default FALSE is
backfilled into historical manifests.

The Result Guard additionally performs **bounded URL-percent and Base64 /
URL-safe-Base64 decoding** of outbound argument strings when comparing with
previously observed session taint fingerprints. A decoding budget overflow,
invalid UTF-8 percent encoding, or incompletely inspectable structure
refuses conservatively rather than claiming there was no encoded copy.
This does not make arbitrary encodings, chunked/fragmented transmission,
compression, encryption or transformed secrets universally detectable.
For **same-host cooperating Proxy workers**, an opt-in durable shared
Result Guard ledger is supported. Set `MCP_RESULT_TAINT_SQLITE_PATH` to an
**absolute filename in an existing, access-restricted trusted local directory
on one shared volume**. All workers must use the exact same SQLite database
(WAL mode, FULL synchronous writes, BEGIN IMMEDIATE transactions). The ledger
stores SHA-256 session identifiers and result fingerprints, not raw tool
outputs. Transactions merge concurrent writes and maintain a conservative,
expiring global unknown-evidence watermark if a bounded ledger evicts
sessions. TTL is based on wall-clock time to survive restarts. A failed
lookup is interpreted as taint UNKNOWN and blocks external dispatch; failed
persistence after an upstream call withholds the result, records a security
error, and **preserves executed=True**.

Set `MCP_RESULT_TAINT_SHARED_REQUIRED=1` on a deployment configured for
shared taint. If no shared path is provided, external effects fail closed.
Without these settings, the historical process-local Result Guard remains
available for single-worker/testing configurations only: do **not** advertise
cross-worker data-flow guarantees for that mode. Restrict filesystem ACLs
to the Proxy service identity and back up/rotate the local ledger under a
reviewed operational procedure. The SQLite variant does **not** provide
multi-host distributed consistency on independent volumes, and storage
errors/expiry or clock drift may cause conservative denials.

Deployment topology is explicit with the environment variable
MCP_SECURITY_DEPLOYMENT_TOPOLOGY=single_host (default; only supported local
security-state topology). Setting multi_host or an unknown value fails closed
for the local Result Guard and local OAuth/Bearer credential authorities,
including OAuth authorization attempts, callback consumption, token exchange,
reading, writing, refreshing and deleting credentials. This gate does NOT
detect physical host count: deployment operators must declare
their topology accurately. A separate reviewed distributed authority is
required for a genuine multi-host deployment.

The Proxy also repeats its outgoing taint check in the pre-dispatch callback,
after upstream initialization/lock waits and immediately before durable
admission. This prevents the demonstrated stale-check gap.

These checks do not provide an atomic transaction between taint lookup and
actual remote MCP `tools/call` sending; newly arriving taint after that
check can race the send. A stronger guarantee requires a common, durable
dispatch/taint authority and admission ordering. Nor can the checks prove
that an untrusted upstream MCP honors declared flows or guarantee general
non-exfiltration. Taint fingerprints are defensive signals, not an
OS- or network-enforced data boundary.

### Signed semantic argument roles (F05/A5 — opt-in)

Security contracts can now carry an optional `argument_roles` manifest.
Its reviewed, signed entries assign **every schema leaf** a semantic role:
`RESOURCE` / `SOURCE` / `DESTINATION` (matching a resource binding),
`SELECTOR` (an effect selector with a required exact EQ constraint), `DATA`
(reviewed non-authority data), or `PROGRAM` (rejected until a dedicated
versioned interpreter sandbox is available). Partial/duplicate/conflicting
manifests are rejected; changing any role changes the contract hash.
Publication and Runtime apply the same role-coverage checks. A reviewed
selector value is pinned in the executable schema; renaming `action`,
`operation` or `q` does not silently change its semantics.

**Migration:** historic `unbound_arguments` remains exactly as signed and
is **not** implicitly treated as `DATA`. Absent roles preserve historic
contract hashes and the legacy conservative lexical selector guard. New
reviewed roles must be explicitly mapped and approved in a new contract/
Security Pack revision. A declarative template may supply additional
`argument_roles` entries for `DATA` / `PROGRAM`; selector/resource roles
are derived only from *explicit signed* selector constraints and resource
bindings, not from parameter names. Every other schema argument must be
accounted for or onboarding fails closed.

Semantic role assertions are **reviewed contract claims**, not proof that
an arbitrary or hostile upstream MCP actually obeys them. This improvement
does not guarantee confinement of a remote MCP implementation, nor infer
hidden effects from parameter strings.

The shared `compile_executable_contract_schema()` entrypoint now constructs
the **same executable schema** for signed publication and Runtime: restrictive
projection, reviewed schema bounds, exact signed selector EQ narrowing and
resource/argument role coverage. The original MCP schema is never mutated;
its observation fingerprint remains independent of this execution-only view.
Unsupported conditional branches, unsafe regex patterns, unbounded complex
shapes and executable PROGRAM roles continue to fail closed. No formerly
unsupported JSON Schema syntax was permissively enabled. A legacy contract
without reviewed roles continues to use the earlier conservative guards.

This is a supported-subset compiler, not a proof of provider-side execution
confinement. Wider JSON Schema support requires dedicated inclusion and
branch-coverage proofs before it can be enabled.

### OAuth credential authority binding (F13)

Framework-managed OAuth access/refresh tokens use a **version-2 bundle**
bound to a deterministic SHA-256 digest of the OAuth issuer,
authorization endpoint, token endpoint, client ID, resource, requested
scopes, client-secret reference (if any), and a randomly generated
credential generation. Each new OAuth authorization flow creates a fresh
generation; the authorization-code exchange and subsequent refreshes
preserve the same binding. The binding is recomputed and checked **before
returning a cached token or sending a refresh-token request**.

**Fail-closed migration:** previous version-1 token bundles were bound
only to the resource and cannot prove the original issuer/client identity.
They are **not automatically upgraded or re-signed**. An ADMIN must
reconnect/re-authorize affected OAuth MCP connections explicitly through
the existing control plane. During this transition, old bundles or
configurations missing generation and authority metadata return
`upstream_oauth_reauthorization_required`. A changed but complete
configuration returns `upstream_oauth_configuration_binding_mismatch`.
Do not copy old access/refresh tokens into a new version-2 bundle.

The credential lock serializes refresh/disconnect on one shared
filesystem. A deployment with multiple hosts and **unshared** upstream
secret directories does not inherit that cross-host revocation guarantee;
distributed credential storage and generation coordination remain a
separate infrastructure requirement. Fixtures use only synthetic tokens
and temporary directories, never deployed OAuth secrets.

### Durable operation reconciliation (F09)

Operators can inspect one logical Runtime operation with the authenticated
read-only endpoint
`GET /api/v1/control-plane/operations/runtime-operations/{operation_id}/reconciliation`.
It correlates the durable intent, unique admission audit marker and outcome
without revealing call arguments, inventing a result or replaying the call.
It reports `INTENT_ADMISSION_MISSING`, `ADMITTED_OUTCOME_MISSING`,
`RECORDED_UNCERTAIN_OUTCOME` or `OUTCOME_RECORDED`.

**No state returned by this endpoint grants permission to retry.** Even when
an admission record is absent, legacy instrumentation or a missing audit
marker requires manual investigation. An admitted request may have reached
the remote MCP even when its outcome is missing. Unknown effects are not
silently marked successful or harmless. Crash state reconciliation and any
future upstream-supported idempotency remain an explicit separate workflow.

### Ordered Runtime dispatch admission (A3)

After policy ALLOW and durable intent audit, the Proxy requests a **single-use
durable dispatch admission** from the backend. Admission and ADMIN Emergency Deny
creation/revocation acquire the **same PostgreSQL transaction advisory lock**,
so a deny committed before admission cannot be bypassed by a previously
authorized request waiting on upstream credentials, initialization or its
session lock. The signed admission API requires **`runtime.dispatch.admit`**,
distinct from the read-only **`emergency_deny.check`** permission. The official
`scripts/provision_service_identities.py` now includes the new permission for
the MCP_PROXY service identity only; MCP_DISCOVERY must not receive it.

**Deployment migration:** an existing `.runtime/secrets/internal-service-public-keys.json`
will not automatically acquire this permission merely by updating the Python
code. An administrator must deliberately reprovision/upgrade that **public
service-permission registry**, preserving and verifying the current keys, and
restart/revalidate the backend and Proxy before enabling traffic. Do not
silently grant this permission to another identity, copy any private key to
logs, or bypass the denied admission when the registry is out of date. Until
then, MCP calls **fail closed** at dispatch (HTTP 403). Avoid changing any
live secret registry during unit tests.

Admission is ordered with deny commits, **not** atomically coupled to the remote
server's side effects. Once admitted or possibly sent, an interruption can
leave the outcome unknown and must never trigger an automatic mutation retry.
This guarantee covers the built-in serialized MCP HTTP client; injected
nonstandard clients need their own trustworthy post-lock dispatch boundary.

**F01/F02 observation binding:** newly written intents also persist the exact
signed-approved `tool_fingerprint` selected by the Proxy. Dispatch checks the
same profile-specific current observation and linked analysis, human-review
holds, and equality of the original fingerprint. A rediscovery that changes
the tool definition between ALLOW and dispatch is refused, not automatically
approved under the old contract. The runtime audit schema includes a nullable
`tool_fingerprint` for historical records; old/missing fingerprints **cannot**
obtain a fresh dispatch admission. The database column is added by the normal
`init_db` migration path. Test migrations were applied only on the isolated
QA clone; production migration remains a controlled deployment step.


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
|-- scanners/     Build/Deploy scanner integration modules
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
- Build Security scan creation, scanner readiness, normalized findings,
  assessment evidence, and Runtime-governance attachment;
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

### `scanners/`

Build Security adapters and target-safety contracts. A scan resolves a local
directory, immutable Git revision, or Inventory-bound source into a validated
workspace, copies only bounded non-ignored content, and never executes target
code. For local sources, the ADMIN uses a native operating-system folder picker
to choose the MCP directory; the web application does not enumerate the local
filesystem. By default, any local drive/root can be selected. Operators can still
restrict accepted local paths by setting explicit entries in
`BUILD_SCAN_ALLOWED_ROOTS_JSON`. Semgrep, Gitleaks, and Trivy are invoked with
fixed argv arrays and bounded timeouts/output. Required-scanner failure or
unavailability produces an `ERROR` assessment, never `PASS`.

Gitleaks findings are normalized before persistence; detected secret values are
not stored in PostgreSQL, API payloads, audit events, or Runtime policy context.
Build findings use stable fingerprints so consecutive Inventory-linked scans can
classify evidence as `NEW`, `UNCHANGED`, `RESOLVED`, or `REGRESSED`.

A completed Inventory-linked scan may be attached by an ADMIN to a Control Plane
DRAFT. The published configuration stores only the exact scan/source fingerprint,
source revision, assessment status/policy version, required-scanner completion,
completion time, and gate mode. OPA remains the sole Runtime policy authority.
Scanner binaries are never executed on the MCP request path.

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

The tracked `.env.example` is the source of truth for local configuration. The
default local database uses a project-specific loopback port so it does not
collide with a normal PostgreSQL service:

```env
BACKEND_HOST=127.0.0.1
BACKEND_PORT=8000
FRONTEND_HOST=127.0.0.1
FRONTEND_PORT=5173
MCP_GATEWAY_HOST=127.0.0.1
MCP_GATEWAY_PORT=9001

POSTGRES_HOST=127.0.0.1
POSTGRES_PORT=55432
POSTGRES_DB=mcp_security
POSTGRES_USER=mcp_user
POSTGRES_PASSWORD=<generate-local>

LLM_PROVIDER=mock
GEMINI_API_KEY=
GROQ_API_KEY=
```

Important:

- `.env` must never be committed.
- `.env.example` contains placeholders only.
- for the default local database, setup replaces `<generate-local>` with a
  random installation-specific password without printing it;
- if an external PostgreSQL host is configured, its credentials remain an
  explicit operator responsibility and setup never invents them;
- optional Gemini/Groq keys and third-party MCP credentials are not required by
  the core framework;
- Vite reads the repository-root `.env`; no `frontend/.env` is required and
  only `VITE_*` values are exposed to browser code.

## Local Setup

The supported clone-ready target is a clean Windows source clone with these
system prerequisites installed:

- Python >=3.11 and <3.14;
- Node.js `^20.19.0` or `>=22.12.0` and npm;
- PostgreSQL 15+ server binaries;
- Git;
- Internet access for the first dependency/model/tool provisioning run.

Check them with:

```powershell
python scripts/check_dependencies.py
```

Then run one bootstrap command from the repository root:

```powershell
python scripts/setup_local_environment.py
```

No manual `pip install`, `npm install`, OPA installation, Semgrep/Gitleaks/Trivy
installation, Trivy vulnerability-database download, model download, key
generation, database/user creation, schema initialization, or initial
configuration import is required for the default local path.

The idempotent bootstrap:

- creates `backend/.venv` and installs the single pinned
  `backend/requirements.txt` used by runtime and validation;
- runs `npm ci` from the tracked frontend lockfile;
- downloads the pinned OPA `1.18.2` binary and verifies its SHA-256;
- provisions pinned project-managed Semgrep, Gitleaks, and Trivy under
  `.runtime/tools`, verifies downloaded binary checksums where applicable,
  and provisions the Trivy vulnerability database;
- downloads the two pinned local Tool Analyzer model snapshots;
- generates installation-specific service, assertion, revision-signing, and
  local-IDP key material under ignored `.runtime/secrets`;
- generates the trusted-session pepper and default local PostgreSQL password
  inside ignored `.env`;
- reuses a correctly configured reachable PostgreSQL database when available,
  otherwise initializes a project-local PostgreSQL cluster under
  `.runtime/postgres`, creates `mcp_security`, and records the managed local
  launcher in ignored `.env`;
- initializes/upgrades the schema, creates the initial PUBLISHED Control Plane
  configuration, and interactively creates the first ADMIN if needed;
- runs an installation self-check without printing credentials or private key
  material.

Existing valid local identities, database state, configuration and ADMIN users
are preserved on repeated setup runs. Invalid security material fails closed
instead of being silently replaced.

After setup, start the framework supervisor:

```powershell
.\backend\.venv\Scripts\python.exe scripts\start_framework.py
```

Then start the already-provisioned frontend in a second terminal:

```powershell
cd frontend
npm.cmd run dev
```

The local development supervisor starts or reuses PostgreSQL, OPA, the local identity provider,
the bundled MCP test lab, Backend and Gateway. External third-party MCP servers
remain outside the supervisor's lifecycle. The frontend reads its host, port and API base URL from the
repository-root `.env`.

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
starts or reuses the configured local identity provider, bundled local MCP Lab,
Backend, and Gateway.
An external JWKS provider is checked but never launched by the framework. It only uses
fixed framework commands with `shell=False` and only terminates child processes
it started. If PostgreSQL is unavailable and
`LOCAL_RUNTIME_MANAGED_POSTGRES_COMMAND_JSON` contains an explicitly trusted
local argv array, the launcher starts it and waits for readiness. The normal
local setup writes this launcher automatically for the project-local cluster;
custom/external database deployments may leave it empty. A PostgreSQL process
started this way is left running on framework shutdown because it is stateful
infrastructure.
Backend, OPA, Gateway, and local identity-provider children are monitored. An
unexpected exit triggers only the configured number of controlled restart attempts
with bounded backoff. If recovery is disabled, fails, or is exhausted, the remaining
framework-owned children are stopped and the launcher exits non-zero:

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

For manual startup (without `scripts/start_framework.py`), start the bundled MCP
lab server in a separate terminal:

```powershell
.\backend\.venv\Scripts\python.exe -m uvicorn server:app `
  --app-dir mcp-lab/http_server `
  --host 127.0.0.1 `
  --port 9000
```

The bundled MCP lab is a local upstream test server. In the standard development
launcher (`scripts/start_framework.py`) it is started or reused automatically;
the separate command above is only needed for manual startup. Real upstream MCP
servers on LAN, enterprise networks, or third-party services keep their own
lifecycle and are not started by the framework supervisor. A simple liveness check with `curl.exe -i http://127.0.0.1:9000/mcp`
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

Run the complete Python suite from the repository root:

```powershell
.\backend\.venv\Scripts\python.exe -m pytest -q
```

Validate the frontend and its lockfile:

```powershell
cd frontend
npm.cmd test
npm.cmd run build
npm.cmd audit
cd ..
```

Validate OPA/Rego policies:

```powershell
.\.runtime\tools\opa\opa.exe test policies\opa
```

Check Python dependency consistency and bytecode compilation:

```powershell
.\backend\.venv\Scripts\python.exe -m pip check
.\backend\.venv\Scripts\python.exe -m compileall -q backend proxy agent common scripts mcp-lab
```

Check runtime logs in the authenticated Control Center **Runtime Calls** page,
or make an API request with an actual authenticated Control Plane session cookie.
An unauthenticated `Invoke-RestMethod` request will return HTTP 401:

```text
GET http://127.0.0.1:8000/api/v1/runtime/logs
```

Expected behavior **when the agent identity is trusted, the exact tool observation
is approved, its contract and authority scopes are published, and OPA authorizes
the request**:

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

In the initial or rolled-back configuration, those authorizations may be absent:
even the benign read must fail closed until explicitly approved and published.
These examples describe a configured demonstration, not a blanket allow rule.

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

Expected LLM demo behavior **after an ADMIN publishes a compatible tool contract,
observation approval, trusted agent identity binding, authorization grant, and
resource scope**:

- contract prompt proposes `read_file` with `contracts/contract1.txt`; when the published authorization and OPA policy permit it, the MCP call executes and a runtime log is created;
- `.env` prompt proposes `read_file` with `.env`; the sensitive-path guard blocks execution and creates a runtime log.

The default published configuration does not authorize these calls automatically;
an unapproved tool or unbound agent must fail closed.

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
- Upstream authentication supports no-auth, framework-held Bearer references,
  and interactive OAuth 2.1 Authorization Code with PKCE. OAuth clients may be
  pre-registered or dynamically registered when the provider advertises a valid
  registration endpoint. Client-credentials grants remain unsupported.
- Built-in MCP HTTP/SSE, Discovery and OAuth requests use DNS-pinned
  connections and hostname-validated TLS. Deployment egress isolation and
  separate review of custom/nonstandard transports remain necessary;
  this does not attest a remote MCP's behavior.
- Runtime policy depends on OPA availability and fails closed when OPA is unavailable.
- Scanner and DevSecOps analysis are not a complete production pipeline yet.
- No AWS integration yet.
- No full audit report generation yet.
- Control Plane authentication is intentionally minimal and local-first: ADMIN/VIEWER, HttpOnly sessions, CSRF protection, and audit.

## Next Phases

The Runtime Security core and Phase 6 Build Security form the validated baseline.
Phase 6 has a dated certification record in `build_security_plan.md`.
The remaining planned work is:

- Phase 7 - Deploy Security / AWS-IAM with Checkov, Prowler, and boto3;
- controlled adversarial validation across Build, Deploy, and Runtime evidence;
- audit/report generation and governance mappings;
- optional SOC/Wazuh/Sigma integration if time permits.
