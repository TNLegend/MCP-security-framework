# Phase 9 — Operational Audit Reporting

## Scope

A report generator is available in **Audit history → Generate report**, exclusively to authenticated ADMIN users. It summarizes evidence that the MCP Security Framework already recorded; generation does **not** run scans, change policies, initiate MCP calls, send requests to cloud services or use a generative AI provider.

**Regulatory framework mappings are intentionally out of scope** and reserved for future work. Historical laboratory campaigns are not imported into the operational report.

## User workflow

1. An ADMIN opens the existing Audit history page and selects **Generate report**.
2. The panel offers a period: **7 days, 30 days, 90 days, or all recorded history**.
3. The ADMIN chooses **PDF**, **HTML**, **JSON**, or **CSV**, and can include a small, redacted appendix of recent evidence references.
4. Selecting **Generate & download** sends a CSRF-protected POST, receives the generated file, and triggers a browser download.
5. The backend writes an auditable **SECURITY_REPORT_GENERATED** receipt with the actor, report identifier, time window, format, byte count and SHA-256.

Viewer accounts cannot see the button and cannot use the endpoint. Unauthorized requests, invalid periods/formats, and unexpected request parameters are rejected.

## Backend

- Route: `POST /api/v1/control-plane/audit/reports/generate`
- Service: `backend/app/services/audit_reports.py`
- API: `backend/app/api/routes_control_plane_audit.py`
- Frontend: `frontend/src/pages/Audit.jsx` and `frontend/src/api/client.js`

The collector reads PostgreSQL through SQLAlchemy and reports:

- **MCP inventory** — current server/tool counts and trust, review and risk categories;
- **Tool security** — recorded analyses, drift statuses, findings and severity;
- **Build Security** — completed/failed scans, assessments and findings;
- **Cloud Security** — cloud/IaC scans, findings and recorded IAM comparison statuses;
- **Runtime** — outcome rows by the existing Runtime outcome taxonomy, decisions and OPA decisions;
- **Audit & governance** — administrative event totals, results/actions, current emergency restrictions and the latest recorded published configuration revision;
- **Recommendations** — bounded recommendations derived from known recorded critical findings, uncertain dispatch outcomes and failed scans, without claiming unseen risks are absent;
- **Evidence appendix (optional)** — a maximum of 12 recent safe record references per category, timestamps and statuses.

The inventory is a **current state** snapshot and is not misrepresented as historical inventory as of the period start. Cloud findings and IAM comparisons are filtered by their parent scan date. Runtime event rows are not called unique or confirmed tool executions. No record means **no recorded evidence**, not security certification.

## Privacy and integrity

Raw MCP arguments, tool descriptions, credentials, user content, cloud account identifiers, resource ARNs, raw policies and audit JSON are not exported. Untrusted status labels are sanitized and bounded; HTML is escaped. CSV values protect against spreadsheet formula interpretation.

The endpoint is ADMIN-only, CSRF-protected and returns `Cache-Control: no-store, private`, `X-Content-Type-Options: nosniff`, a safe attachment filename, and `X-Report-SHA256`. The audit receipt stores only safe metadata, not the report document or private findings.

PDF output uses a dependency-free, selectable-text, multipage A4 renderer. HTML, JSON and CSV use the same database snapshot. The viewer only receives the finished file; no report is stored in the product source tree.

## Evidence and verification

Targeted backend tests: `backend/tests/test_phase9_audit_report.py`. Frontend validation: `frontend/tests/phase9_reporting.validation.mjs`. The existing role-boundary regression and existing frontend test suite are also run.

A real, isolated-browser QA acceptance exercise was performed on **22 November 2026** against separate frontend/backend ports and a dedicated PostgreSQL QA instance:

- GUI navigation to **Audit history**, opening the panel and pressing **Generate & download**;
- HTTP response **200**, `application/pdf`, PDF magic `%PDF-1.4`;
- Browser-created PDF Blob of **9,098 bytes**, and **no user-visible alert**;
- An audit receipt `SECURITY_REPORT_GENERATED / SUCCESS` with the matching byte count, period `30d` and a 64-character SHA-256;
- Audit history updated to display the newly generated receipt;
- No reference to external laboratory results in the report.

This browser acceptance uses a disposable QA environment, not a production user session. No changes were made to existing security controls, machine-learning models, or governance policies.

## Limitations

The generated document is a **summary of evidence currently recorded in this framework installation**, not a certified security assessment. Neither the endpoint nor the generated report performs regulatory mappings, active AWS checks, adversarial test campaigns or external verification. PDF/HTML formatting is intentionally simple and works offline without external assets.
