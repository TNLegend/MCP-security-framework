"""Visual audit and component-geometry regression for the built console.

All API traffic is intercepted with synthetic fixtures (no credentials, no live
services). For every scenario and viewport it captures a screenshot and runs a
geometry probe over the rendered DOM: control sizes, button wrapping, label /
control collisions, clipped badges, narrow code viewers, character-level
wrapping and clipped nested overflow. Use --strict to fail on any defect.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from playwright.sync_api import expect, sync_playwright

import gui_browser_smoke as smoke

DIGEST = smoke.DIGEST
STAMP = smoke.STAMP
CLOUD = smoke.CLOUD
LONG_ARN = "arn:aws:s3:::qa-evidence-bucket-with-a-deliberately-long-name-for-layout/documents/2026/11/*"
LONG_TOOL = "read_documents_from_the_regional_evidence_archive_with_a_very_long_name"

CAPABILITIES = {
    "tools": {"listChanged": True},
    "resources": {"subscribe": True, "listChanged": True},
    "prompts": {"listChanged": False},
    "logging": {},
    "experimental": {"x-qa-extension": {"version": "2026-11-25", "features": ["streaming", "batch"]}},
}
RAW_INIT = {
    "protocolVersion": "2025-11-25",
    "capabilities": CAPABILITIES,
    "serverInfo": {"name": "documentation-mcp", "title": "Documentation MCP", "version": "4.12.0-qa+build.7f3c9a1",
                   "description": "Synthetic server used for layout regression only.",
                   "websiteUrl": "https://docs.example.invalid/servers/documentation-mcp/overview"},
    "instructions": "Use read_documents for single documents. " * 4,
    "_meta": {"io.example/trace": DIGEST, "io.example/deployment": LONG_ARN},
}
SERVER = {**smoke.SERVER, "name": "Documentation MCP", "protocol_version": "2025-11-25",
          "auth_mode": "OAUTH", "oauth_status": "connected", "server_info_name": "documentation-mcp",
          "server_info_title": "Documentation MCP", "server_info_version": "4.12.0-qa+build.7f3c9a1",
          "server_info_description": "Synthetic server used for layout regression only.",
          "server_info_website_url": "https://docs.example.invalid/servers/documentation-mcp/overview",
          "capabilities": CAPABILITIES, "raw_initialize_result": RAW_INIT,
          "instructions": RAW_INIT["instructions"], "last_seen_at": STAMP, "last_scan_at": STAMP}
TOOLS = [smoke.TOOL, {**smoke.TOOL, "id": 2, "name": LONG_TOOL, "title": "Read documents from the regional archive",
                      "analysis_status": "BLOCKED", "review_status": "BLOCKED", "risk_level": "high"}]
USERS = [{"id": f"user-{i}", "username": name, "display_name": name.replace(".", " ").title(),
          "role": role, "enabled": enabled, "created_at": STAMP, "last_login_at": STAMP}
         for i, (name, role, enabled) in enumerate([
             ("qa-admin", "ADMIN", True), ("security.reviewer", "VIEWER", True),
             ("operations.analyst.with.a.long.username", "VIEWER", False), ("platform.owner", "ADMIN", True)])]
ADAPTERS = [{"adapter_id": f"framework.adapters.{name}", "display_name": name.replace("_", " ").title(),
             "family": family, "adapter_api_version": "1", "implementation_version": "1.4.2-qa.20261122",
             "trust_level": trust, "argument_validation": "JSON Schema 2020-12 strict",
             "result_validation": "Typed result guard with size limits"}
            for name, family, trust in [("aws_s3_documents", "cloud_storage", "BUILTIN_REVIEWED"),
                                        ("github_repositories", "source_control", "BUILTIN_REVIEWED"),
                                        ("postgres_readonly_reports", "database", "SIGNED_THIRD_PARTY")]]
REVISION = {"id": "rev-9", "revision_number": 9, "status": "DRAFT", "schema_version": 2, "created_at": STAMP,
            "content_hash": DIGEST, "content": {"schema_version": 2, "servers": [], "tools": []}}
SIGNED_CONTEXT = {
    "signed_revision": 8, "signed_content_hash": "c" * 64,
    "effects": [{"tool_name": tool, "effect_id": eid, "resource_type": "bucket", "capability": cap}
                for tool, eid, cap in [("list_documents", "list-a", "cloud.list"),
                                       ("read_documents", "read-a", "cloud.read"),
                                       ("write_documents", "write-a", "cloud.write")]],
    "scopes": [{"scope_id": "bucket-a", "resource_type": "bucket", "canonical_value": "qa-evidence-bucket"},
               {"scope_id": "bucket-b", "resource_type": "bucket",
                "canonical_value": "qa-evidence-bucket-with-a-deliberately-long-name-for-layout"}],
}
MAPPING = {"id": "mapping-a", "mcp_server_id": 1, "name": "Documentation MCP on EC2", "status": "DRAFT",
           "signed_revision": 8, "signed_content_hash": "c" * 64, "created_at": STAMP,
           "configuration": {"identity": {"kind": "EC2", "instance_id": "i-0123456789abcdef0", "region": "eu-west-3"},
                             "role_usage": "SHARED",
                             "entries": [{"tool_name": "read_documents", "effect_id": "read-a", "action": "s3:GetObject",
                                          "scope_id": "bucket-b", "resource_arn": LONG_ARN,
                                          "justification": "Read approved evidence documents only."},
                                         {"tool_name": "list_documents", "effect_id": "list-a", "action": "s3:ListBucket",
                                          "scope_id": "bucket-a", "resource_arn": "arn:aws:s3:::qa-evidence-bucket",
                                          "justification": "List keys in the approved bucket."}],
                             "source_binding": {"account_id": "123456789012",
                                                "server_endpoint": smoke.SERVER["endpoint"]}}}
BUILD_SCAN = {"id": "scan-build-1", "display_name": "documentation-mcp repository", "status": "COMPLETED",
              "target_type": "GIT_REPOSITORY", "created_at": STAMP, "source_fingerprint": DIGEST,
              "source_revision": "c" * 40}
BUILD_FINDINGS = [{"id": f"bf-{i:04d}", "scanner_id": ["semgrep", "trivy", "gitleaks"][i % 3],
                   "rule_id": f"python.lang.security.audit.rule-{i:03d}", "severity": ["CRITICAL", "HIGH", "MEDIUM", "LOW"][i % 4],
                   "finding_state": "OPEN", "title": f"Finding {i} with a reasonably descriptive title",
                   "file_path": f"src/services/very/deep/package/structure/module_{i:03d}_with_long_filename.py",
                   "line_start": 10 + i, "fingerprint": DIGEST,
                   **({"package_name": "urllib3", "package_version": "1.26.4", "fixed_version": "1.26.19",
                       "vulnerability_id": f"CVE-2026-{1000 + i}"} if i % 3 == 1 else {})} for i in range(400)]
AUDIT_ROWS = [{**smoke.AUDIT, "id": i, "correlation_id": "6f1c2d3e-4b5a-4c6d-8e7f-9a0b1c2d3e4f",
               "target_id": "3fc60cb3-13bd-4f9c-a506-d9ac811e6d94" if i % 2 else DIGEST}
              for i in range(1, 9)]


class VisualAPI(smoke.MockAPI):
    def read(self, path, query):
        rich = {
            "/servers": [SERVER], "/tools": TOOLS,
            "/control-plane/users": USERS,
            "/control-plane/security-packs/adapters": {"sdk_api_version": "1", "adapters": ADAPTERS},
            "/control-plane/security-packs/lifecycle": {"installations": []},
            "/control-plane/config/revisions": [REVISION],
            "/control-plane/security-packs": {"builtin_packs": [{"pack_id": "aws.s3", "name": "AWS S3 documents"}],
                                              "installations": [], "packs": []},
            "/control-plane/audit/events": AUDIT_ROWS,
            "/control-plane/audit/events/page": {"items": AUDIT_ROWS, "total": len(AUDIT_ROWS)},
            "/control-plane/build-security/scans": [BUILD_SCAN],
            "/control-plane/build-security/scanners": [{"scanner_id": s, "name": s.title(), "available": True,
                                                        "version": "1.0"} for s in ("semgrep", "trivy", "gitleaks")],
            CLOUD + "/environments/env-qa/iam-mappings": [MAPPING, {**MAPPING, "id": "mapping-b", "status": "APPROVED",
                                                                  "approval_digest": "d" * 64}],
            CLOUD + "/environments/env-qa/iam-mapping-context": SIGNED_CONTEXT,
        }
        if path in rich:
            return rich[path]
        if path == "/control-plane/build-security/scans/" + BUILD_SCAN["id"]:
            return {"scan": BUILD_SCAN, "scanner_runs": [{"scanner_id": s, "status": "COMPLETED", "required": True,
                                                          "finding_count": 20} for s in ("semgrep", "trivy", "gitleaks")],
                    "findings": BUILD_FINDINGS[:20], "assessment": None}
        if path == "/control-plane/build-security/scans/" + BUILD_SCAN["id"] + "/findings":
            offset = int((query.get("offset") or ["0"])[0])
            limit = int((query.get("limit") or ["50"])[0])
            rows = BUILD_FINDINGS[offset:offset + limit]
            return {"items": rows, "total": len(BUILD_FINDINGS), "unfiltered_total": len(BUILD_FINDINGS),
                    "offset": offset, "limit": limit, "returned": len(rows),
                    "has_more": offset + len(rows) < len(BUILD_FINDINGS)}
        return super().read(path, query)


PROBE = r"""
() => {
  const vw = document.documentElement.clientWidth;
  const out = [];
  const visible = (el) => { const r = el.getBoundingClientRect(); const s = getComputedStyle(el);
    return r.width > 0 && r.height > 0 && s.visibility !== 'hidden' && s.display !== 'none'; };
  const name = (el) => { const t = (el.getAttribute('aria-label') || el.innerText || el.value || el.placeholder || '').trim().replace(/\s+/g,' ');
    const id = el.id ? '#' + el.id : ''; const cls = (el.className && typeof el.className === 'string') ? '.' + el.className.trim().split(/\s+/).slice(0,2).join('.') : '';
    return el.tagName.toLowerCase() + id + cls + (t ? ' "' + t.slice(0, 48) + '"' : ''); };
  const lh = (el) => { const s = getComputedStyle(el); const v = parseFloat(s.lineHeight); return isNaN(v) ? parseFloat(s.fontSize) * 1.3 : v; };
  const add = (kind, el, detail) => out.push({kind, el: name(el), detail});
  const root = document.querySelector('[role=dialog]:not([hidden])') || document.querySelector('main') || document.body;
  const scope = [...document.querySelectorAll('main, [role=dialog]')];
  const inScope = (el) => scope.some((s) => s.contains(el));
  // 1. form controls
  for (const el of document.querySelectorAll('input, select, textarea')) {
    if (!inScope(el) || !visible(el)) continue;
    const type = (el.getAttribute('type') || '').toLowerCase();
    if (['checkbox', 'radio', 'hidden', 'file', 'range', 'color'].includes(type)) continue;
    const r = el.getBoundingClientRect(); const s = getComputedStyle(el);
    if (el.tagName !== 'TEXTAREA' && r.height > 56) add('control-too-tall', el, Math.round(r.height) + 'px');
    if (r.height < 30) add('control-too-short', el, Math.round(r.height) + 'px');
    const minW = vw < 480 ? 110 : 150;
    if (r.width < minW) add('control-too-narrow', el, Math.round(r.width) + 'px');
    if (el.tagName === 'SELECT' && r.width > Math.min(560, vw * 0.9) && vw >= 1024) add('select-too-wide', el, Math.round(r.width) + 'px');
    if (parseFloat(s.paddingLeft) < 4 && el.tagName !== 'SELECT') add('control-unstyled', el, 'padding-left ' + s.paddingLeft);
    if (s.borderTopStyle === 'inset' || (s.borderRadius === '0px' && el.tagName !== 'SELECT')) add('control-browser-default', el, s.borderTopStyle + ' r=' + s.borderRadius);
  }
  // 2. buttons
  for (const el of document.querySelectorAll('button, a[role=button], summary')) {
    if (!inScope(el) || !visible(el)) continue;
    const r = el.getBoundingClientRect(); const lines = Math.round((r.height - parseFloat(getComputedStyle(el).paddingTop) - parseFloat(getComputedStyle(el).paddingBottom)) / lh(el));
    const text = (el.innerText || '').trim();
    // Disclosure summaries may carry a longer label; buttons may not exceed two lines.
    if (text && lines > (el.tagName === 'SUMMARY' ? 3 : 2)) add('button-text-wraps', el, lines + ' lines @' + Math.round(r.width) + 'px');
    if (text.length > 3 && r.width < 44) add('button-too-narrow', el, Math.round(r.width) + 'px');
    if (r.height > 72 && el.tagName === 'BUTTON') add('button-too-tall', el, Math.round(r.height) + 'px');
  }
  // 3. label <-> control collision and separation
  for (const label of document.querySelectorAll('label')) {
    if (!inScope(label) || !visible(label)) continue;
    const control = label.control || label.querySelector('input,select,textarea');
    if (!control || !visible(control)) continue;
    const type = (control.getAttribute('type') || '').toLowerCase();
    if (['checkbox', 'radio'].includes(type)) continue;
    const range = document.createRange(); const textNode = [...label.childNodes].find((n) => n.nodeType === 3 && n.textContent.trim());
    if (!textNode) continue;
    range.selectNodeContents(textNode); const t = range.getBoundingClientRect(); const c = control.getBoundingClientRect();
    const sideBySide = t.right <= c.left + 1 || c.right <= t.left + 1;
    if (sideBySide) { const gap = Math.max(c.left - t.right, t.left - c.right); if (gap < 6) add('label-collides', label, 'gap ' + Math.round(gap) + 'px'); }
    else { const gap = c.top - t.bottom; if (gap < 0) add('label-overlaps-control', label, Math.round(gap) + 'px'); if (gap > 28) add('label-far-from-control', label, Math.round(gap) + 'px'); }
  }
  // 4. badges clipped or wrapped
  for (const el of document.querySelectorAll('.status-pill, .badge, [class*=badge], [class*=pill], .chip, [class*=-tag]')) {
    if (!inScope(el) || !visible(el)) continue;
    const r = el.getBoundingClientRect();
    if (el.scrollWidth > el.clientWidth + 1) add('badge-clipped', el, el.scrollWidth + '>' + el.clientWidth);
    if (r.height > lh(el) * 1.8 + 8 && (el.innerText || '').trim().length < 40) add('badge-wraps', el, Math.round(r.height) + 'px');
  }
  // 5. code / JSON viewers
  for (const el of document.querySelectorAll('pre, code, .json-viewer, [class*=json]')) {
    if (!inScope(el) || !visible(el)) continue;
    const r = el.getBoundingClientRect(); const s = getComputedStyle(el); const text = (el.innerText || '');
    if (el.tagName === 'PRE' && vw >= 768 && r.width < 320 && text.length > 60) add('code-viewer-narrow', el, Math.round(r.width) + 'px');
    if (el.tagName === 'PRE' && (s.wordBreak === 'break-all' || s.overflowWrap === 'anywhere') && text.includes('{')) add('json-breaks-anywhere', el, s.wordBreak + '/' + s.overflowWrap);
    if (el.tagName === 'PRE' && r.height < 120 && el.scrollHeight > el.clientHeight + 40) add('code-viewer-tiny-scroll', el, Math.round(r.height) + 'px of ' + el.scrollHeight);
  }
  // 6. character-level wrapping of ordinary text
  for (const el of root.querySelectorAll('dd, td, th, dt, p, span, strong, h3, h4')) {
    if (!visible(el) || el.children.length > 2) continue;
    const text = (el.innerText || '').trim(); const r = el.getBoundingClientRect();
    if (text.length > 18 && r.width < 70 && r.height > lh(el) * 4) add('text-wraps-per-character', el, Math.round(r.width) + 'x' + Math.round(r.height));
  }
  // 7. clipped nested overflow (hidden) and page overflow
  for (const el of root.querySelectorAll('*')) {
    if (!visible(el)) continue; const s = getComputedStyle(el);
    // Deliberate truncation is allowed only when the full value is exposed in a title (not for badges).
    const truncatedWithTitle = s.textOverflow === 'ellipsis' && (el.title || el.closest('[title]')) && !el.matches('.badge, .status-pill');
    if ((s.overflowX === 'hidden' || s.overflow === 'hidden') && el.scrollWidth > el.clientWidth + 4 && el.clientWidth > 40 && !truncatedWithTitle && !el.matches('.sr-only, .visually-hidden'))
      add('content-clipped', el, el.scrollWidth + '>' + el.clientWidth);
  }
  if (document.documentElement.scrollWidth > vw + 1) {
    const offenders = [...document.querySelectorAll('main *, [role=dialog] *')].filter((e) => visible(e) && e.getBoundingClientRect().right > vw + 1)
      .filter((e) => !e.parentElement || e.parentElement.getBoundingClientRect().right <= vw + 1).slice(0, 3).map(name).join(' | ');
    out.push({kind: 'page-horizontal-overflow', el: 'document', detail: document.documentElement.scrollWidth + '>' + vw + ' ' + offenders});
  }
  // 8. dialog sizing
  for (const d of document.querySelectorAll('[role=dialog]')) {
    if (!visible(d)) continue; const r = d.getBoundingClientRect();
    if (vw >= 600 && r.width < 400) add('dialog-too-narrow', d, Math.round(r.width) + 'px');
    if (r.right > vw + 1 || r.left < -1) add('dialog-off-screen', d, Math.round(r.left) + '..' + Math.round(r.right));
  }
  const seen = new Set();
  return out.filter((d) => { const k = d.kind + d.el; if (seen.has(k)) return false; seen.add(k); return true; });
}
"""


def open_visual(browser, server, role, width):
    api = VisualAPI(role)
    api.port = server.server_port
    url = f"http://127.0.0.1:{api.port}"
    context = browser.new_context(viewport={"width": width, "height": 900})
    context.route("**/*", api.route)
    context.add_cookies([{"name": "mcp_control_plane_csrf", "value": "qa-csrf", "url": url}])
    page = context.new_page()
    errors = []
    page.on("pageerror", lambda error: errors.append(str(error)))
    page.goto(url, wait_until="domcontentloaded")
    expect(page.get_by_role("heading", level=2).first).to_be_visible()
    return context, page, api, errors


def go(page, label, width):
    smoke.navigate(page, label, width)
    page.wait_for_timeout(250)


def s_page(label):
    def run(page, width):
        go(page, label, width)
    return run


def s_password(page, width):
    if width <= 760 and page.get_by_role("button", name="Open navigation menu").count():
        pass
    page.get_by_role("button", name="My account").first.click()
    expect(page.get_by_role("dialog", name="Change your password")).to_be_visible()


def s_server_metadata(page, width):
    go(page, "MCP tools", width)
    summary = page.get_by_text("MCP native metadata", exact=True).first
    summary.scroll_into_view_if_needed()
    summary.click()
    page.wait_for_timeout(200)
    summary.scroll_into_view_if_needed()


def s_review_ai(page, width):
    go(page, "Security review", width)
    row = page.get_by_role("row").filter(has_text="read_documents").first
    if row.count():
        row.click()
    tab = page.get_by_role("tab", name="Explain with AI")
    if tab.count():
        tab.click()
    page.wait_for_timeout(250)


def s_review_technical(page, width):
    go(page, "Security review", width)
    row = page.get_by_role("row").filter(has_text="read_documents").first
    if row.count():
        row.click()
    tab = page.get_by_role("tab", name="Technical details")
    if tab.count():
        tab.click()
    page.wait_for_timeout(250)


def s_build_findings(page, width):
    go(page, "Code scans", width)
    button = page.get_by_role("button", name="documentation-mcp repository").first
    if not button.count():
        button = page.get_by_text("documentation-mcp repository").first
    if button.count():
        button.click()
    page.wait_for_timeout(400)
    heading = page.get_by_text("Showing", exact=False).first
    if heading.count():
        heading.scroll_into_view_if_needed()


def s_cloud_mapping(page, width):
    go(page, "Cloud security", width)
    page.get_by_role("navigation", name="Cloud security tasks").get_by_role("button", name="MCP permissions", exact=True).click()
    page.wait_for_timeout(400)
    select = page.get_by_label("Mapping configuration")
    if select.count():
        select.select_option("mapping-a")
        page.wait_for_timeout(200)


def s_security_rules(page, width):
    go(page, "Security rules", width)
    page.wait_for_timeout(300)
    catalog = page.locator(".trusted-adapter-catalog")
    if catalog.count():
        catalog.first.scroll_into_view_if_needed()


def s_review_tab(name):
    def run(page, width):
        go(page, "Security review", width)
        row = page.get_by_role("row").filter(has_text="read_documents").first
        if row.count():
            row.click()
        page.get_by_role("tab", name=name).click()
        page.wait_for_timeout(300)
    return run


def s_cloud_task(task):
    def run(page, width):
        go(page, "Cloud security", width)
        page.get_by_role("navigation", name="Cloud security tasks").get_by_role("button", name=task, exact=True).click()
        page.wait_for_timeout(300)
    return run


def s_cloud_scan(page, width):
    s_cloud_task("Audit history")(page, width)
    button = page.get_by_role("button", name="View", exact=False).first
    button.click()
    page.wait_for_timeout(400)


def s_audit_detail(page, width):
    go(page, "Audit history", width)
    page.get_by_role("button", name="View", exact=True).first.click()
    page.wait_for_timeout(300)
    page.get_by_text("Recorded field changes").first.scroll_into_view_if_needed()


SCENARIOS = {
    "home": ("ADMIN", s_page("Home")),
    "password-modal": ("ADMIN", s_password),
    "mcp-tools": ("ADMIN", s_page("MCP tools")),
    "server-metadata": ("ADMIN", s_server_metadata),
    "review": ("ADMIN", s_page("Security review")),
    "review-ai": ("ADMIN", s_review_ai),
    "review-technical": ("ADMIN", s_review_technical),
    "review-issues": ("ADMIN", s_review_tab("Detected issues")),
    "review-description": ("ADMIN", s_review_tab("Description check")),
    "review-history": ("ADMIN", s_review_tab("History")),
    "review-tool-settings": ("ADMIN", s_review_tab("Tool settings")),
    "build": ("ADMIN", s_page("Code scans")),
    "build-findings": ("ADMIN", s_build_findings),
    "cloud": ("ADMIN", s_page("Cloud security")),
    "cloud-mapping": ("ADMIN", s_cloud_mapping),
    "cloud-advanced": ("ADMIN", s_cloud_task("Advanced AWS checks")),
    "cloud-terraform": ("ADMIN", s_cloud_task("Terraform files")),
    "cloud-scan": ("ADMIN", s_cloud_scan),
    "rules": ("ADMIN", s_security_rules),
    "emergency": ("ADMIN", s_page("Emergency block")),
    "activity": ("ADMIN", s_page("Tool activity")),
    "health": ("ADMIN", s_page("System health")),
    "audit": ("ADMIN", s_page("Audit history")),
    "audit-detail": ("ADMIN", s_audit_detail),
    "users": ("ADMIN", s_page("Users")),
    "viewer-home": ("VIEWER", s_page("Home")),
    "viewer-cloud-mapping": ("VIEWER", s_cloud_mapping),
}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("dist", type=Path)
    parser.add_argument("--chrome", required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--widths", default="320,390,768,1024,1440,1920")
    parser.add_argument("--only", default="")
    parser.add_argument("--strict", action="store_true")
    parser.add_argument("--full", action="store_true", help="full-page screenshots")
    args = parser.parse_args()
    args.out.mkdir(parents=True, exist_ok=True)
    widths = [int(w) for w in args.widths.split(",")]
    only = {s for s in args.only.split(",") if s}
    report = {}
    server = smoke.serve(args.dist)
    total = 0
    with sync_playwright() as pw:
        browser = pw.chromium.launch(executable_path=args.chrome)
        for key, (role, run) in SCENARIOS.items():
            if only and key not in only:
                continue
            for width in widths:
                context, page, api, errors = open_visual(browser, server, role, width)
                label = f"{key}@{width}"
                try:
                    run(page, width)
                    defects = page.evaluate(PROBE)
                    page.screenshot(path=str(args.out / f"{key}-{width}.png"), full_page=args.full)
                except Exception as exc:  # keep auditing other scenarios
                    defects = [{"kind": "scenario-error", "el": key, "detail": str(exc).splitlines()[0][:200]}]
                if errors:
                    defects.append({"kind": "page-error", "el": key, "detail": errors[0][:200]})
                report[label] = defects
                total += len(defects)
                print(f"{'FAIL' if defects else 'PASS'} {label}: {len(defects)} defect(s)")
                for d in defects[:12]:
                    print(f"   - {d['kind']}: {d['el']} ({d['detail']})")
                context.close()
        browser.close()
    server.shutdown()
    (args.out / "report.json").write_text(json.dumps(report, indent=1), encoding="utf-8")
    print(f"TOTAL {total}")
    if args.strict and total:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
