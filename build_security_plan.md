# Phase 6 — Build Security Plan

Status: COMPLETE

This phase adds source/build-time security evidence to the MCP Security Framework without weakening the existing Runtime reference-monitor guarantees.

## Non-negotiable principles

- The module is generic: scanners consume a validated workspace, not a hard-coded MCP implementation.
- Target code is analyzed, never executed as part of scanning.
- User-controlled paths/refs never become shell command strings; scanner processes use argv with `shell=False`.
- Secrets discovered by scanners are never persisted raw in PostgreSQL, APIs, logs, or audit evidence.
- Required scanner failure/timeout/unavailability can never be interpreted as PASS.
- Build evidence is bound to a source fingerprint/revision and scanner versions.
- Runtime remains governed by the published Control Plane snapshot and OPA; Build Security does not become an alternate Runtime authority.
- Clone-ready is a release gate for every lot: all Python dependencies stay in `backend/requirements.txt`; frontend dependencies stay lockfile-pinned; scanner binaries must be project-managed under `.runtime/tools` with pinned versions/checksums and provisioned by setup scripts.
- No machine-specific path or developer-specific configuration may enter tracked source.
- Existing dirty worktree changes are preserved; no reset/clean/commit/push is performed implicitly.

## Target UX

Control Center → Build Security → New Scan:

1. MCP from Inventory
2. Local source directory
3. Git repository

All target types resolve to one canonical `BuildTargetSnapshot` and one validated workspace before any scanner runs.

## Lot 6A — Foundation and contracts

Status: COMPLETE

Deliverables:

- Canonical enums/contracts for target, scan, scanner-run, finding and assessment states.
- Stable normalized finding schema.
- Deterministic finding fingerprint helper.
- Redaction boundary for secret-bearing scanner evidence.
- SQLAlchemy persistence for:
  - `build_scan_runs`
  - `build_scanner_runs`
  - `build_findings`
  - `build_assessments`
- Generic scanner protocol/adapter interface under `scanners/`.
- Target/workspace contracts that do not execute source code.
- Backend schemas for future API use.
- Database/index and contract tests.
- No Semgrep/Trivy/Gitleaks binary dependency yet.

Exit gate:

- Unit tests pass.
- Database creation works from a fresh schema.
- Existing full backend/frontend/OPA suites remain green.
- No secret-bearing field is exposed by the public finding schema.
- `git diff --check` clean.

## Lot 6B — Target intake and workspace safety

Status: COMPLETE

Deliverables:

- Local-directory target validation.
- Configurable allowed scan roots.
- Canonical path, traversal, symlink/junction/reparse-point and sensitive-path checks.
- File-count, total-size and individual-file bounds.
- Inventory-linked target resolution.
- Git URL/ref validation and immutable commit resolution.
- Isolated temporary workspaces under project `.runtime/tmp`.
- Cleanup with bounded failure handling.

Exit gate:

- Malicious path/ref tests.
- Windows path/reparse-point tests.
- No target code execution.
- Fresh-clone setup remains self-contained.

## Lot 6C — Semgrep adapter

Status: COMPLETE

Deliverables:

- Project-managed pinned Semgrep installation/provisioning.
- Generic SAST adapter/parser.
- Initial MCP-focused deterministic rules.
- Bounded JSON parsing, timeout and output handling.
- Normalized findings and fingerprints.

Exit gate:

- Clean fixture + command-injection/path/unsafe-process fixtures.
- Scanner unavailable/timeout/malformed-output fail closed.

## Lot 6D — Gitleaks adapter

Status: COMPLETE

Deliverables:

- Project-managed pinned Gitleaks binary + checksum.
- Secret scanner adapter/parser.
- Mandatory raw-secret redaction before persistence/logging.
- Stable redacted fingerprints.

Exit gate:

- Secret fixtures block as expected.
- No detected secret appears in DB/API/log/audit test output.

## Lot 6E — Trivy adapter

Status: COMPLETE

Deliverables:

- Project-managed pinned Trivy binary + checksum.
- Filesystem/dependency vulnerability scan.
- Normalized CVE/package findings and fixed-version metadata.
- Timeout/malformed-output handling.

Exit gate:

- Vulnerable dependency fixtures detected.
- Required-scanner failures cannot produce PASS.

## Lot 6F — Orchestration and assessment

Status: COMPLETE

Deliverables:

- Scan orchestrator across required scanners.
- Scanner lifecycle/status tracking.
- Deterministic Build Assessment: PASS / WARN / BLOCK / ERROR.
- Explainable assessment reasons.
- NEW / UNCHANGED / RESOLVED / REGRESSED comparison across bound source revisions.

Exit gate:

- Mixed finding and scanner failure E2E tests.
- Assessment is reproducible from persisted normalized evidence.

## Lot 6G — Control Plane API and audit

Status: COMPLETE

Deliverables:

- ADMIN-only scan creation/mutation.
- Authenticated read endpoints with bounded pagination/filtering.
- Control Plane audit events for scan start/completion/failure.
- No arbitrary path disclosure beyond intended administrative evidence.

Exit gate:

- ADMIN/VIEWER/CSRF/session tests.
- API response bounds and redaction tests.

## Lot 6H — Control Center UI

Status: COMPLETE

Deliverables:

- Build Security navigation section.
- New Scan flow for Inventory / Local / Git.
- Target validation preview.
- Scan status, scanner status, findings and assessment views.
- Inventory posture linkage.

Exit gate:

- Frontend tests/build/audit.
- Fresh UI startup and manual browser smoke test.

## Lot 6I — Runtime evidence integration

Status: COMPLETE

Deliverables:

- Published Build evidence reference in governed configuration.
- Immutable source/scan binding exposed as Runtime fact.
- OPA policy support for optional/mandatory Build gates.
- No scanner execution on Runtime request path.

Exit gate:

- OPA tests for PASS/WARN/BLOCK/ERROR/stale evidence.
- Runtime fail-closed behavior preserved.

## Lot 6J — Certification and documentation

Status: COMPLETE

Deliverables:

- Controlled vulnerable/clean/scanner-failure fixtures.
- Full backend/frontend/OPA/E2E suite.
- README/threat-model/operations documentation updates.
- Fresh-machine clone/setup/start/UI validation including scanner provisioning.
- Path/secret/ignored-runtime audit.

Final gate:

- A fresh clone can run dependency check + setup scripts, provision every required Build scanner and dependency, start the framework/frontend, scan a fixture, persist evidence and render the result without undocumented manual installation.

## Final certification — 31 August 2026

Phase 6 is frozen as complete in the current working tree.

Validated evidence:

- backend full suite: **800 passed**, 0 failed;
- frontend suite: **95 passed**, production Vite build successful;
- frontend dependency audit: **0 vulnerabilities**;
- OPA/Rego: **128/128 PASS**;
- `pip check`: clean;
- Python `compileall`: clean;
- Ruff `F,E9`: clean;
- `git diff --check`: clean;
- dependency check: Python, Git, Node/npm, PostgreSQL and project-managed OPA/Semgrep/Gitleaks/Trivy all ready;
- tracked sensitive-artifact audit: **0** tracked `.env`, `.runtime`, virtualenv, node_modules, private-key or certificate artifacts; remaining secret-like strings are deliberate test fixtures only;
- fresh-install self-check: **READY = true** for environment, Python/frontend dependencies, OPA, Semgrep, Gitleaks, Trivy + vulnerability DB, analyzer models, runtime directories, internal identities, PostgreSQL, schema, published configuration and initial ADMIN;
- fresh Control Center login smoke: ADMIN login successful and Build Security page rendered all three scanners as READY;
- fresh clean local-directory E2E scan: Semgrep/Gitleaks/Trivy all **COMPLETED**, 0 findings, deterministic assessment **PASS**;
- fresh Inventory-bound E2E scan: source binding persisted, Semgrep/Gitleaks/Trivy all **COMPLETED**, assessment **PASS**;
- fresh Runtime-governance E2E: exact Build evidence attached to Control Plane DRAFT #2 with `REQUIRE_PASS`, revision validated and published through the Control Center, previous revision archived, published evidence references the exact scan/fingerprint and reports required scanners complete;
- Windows Semgrep regression discovered during fresh E2E was fixed: the adapter now pins `--project-root .`, disables inherited Git ignore discovery, and removes framework-managed `TEMP/TMP/TMPDIR` only for the Semgrep child process on Windows. The regression is covered by tests.

No scanner executes on the Runtime `tools/call` path. OPA remains the authoritative Runtime policy engine, and enabled Build gates fail closed for missing, invalid, stale, incomplete, BLOCK or ERROR evidence according to the published mode.

No commit or push is part of this certification.
