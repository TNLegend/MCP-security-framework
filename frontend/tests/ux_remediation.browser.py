"""Browser acceptance checks for the UX-01..UX-23 remediation register.

All API traffic is intercepted locally with synthetic fixtures (no live
services, accounts or provider calls). Each check is named by issue ID.

Usage: python ux_remediation.browser.py <dist> --chrome <chrome.exe> [--screenshots DIR] [--only UX-03,...]
"""
import argparse
import re
from pathlib import Path

from playwright.sync_api import expect, sync_playwright

import gui_browser_smoke as smoke

RUNTIME = "/runtime/logs"


BUCKETS = ("sent_uncertain", "response_withheld", "execution_recorded", "confirmed_not_sent", "legacy_or_unclassified")


def runtime_event(event_id, decision="BLOCK", tool="read_documents", bucket="confirmed_not_sent"):
    return {**smoke.EVENT, "id": event_id, "decision": decision, "tool_name": tool, "bucket": bucket,
            "operation_id": f"00000000-0000-4000-8000-{event_id:012d}"}


class RemediationAPI(smoke.MockAPI):
    tools_override = None

    def __init__(self, role):
        super().__init__(role)
        self.runtime_rows = [runtime_event(1)]

    def read(self, path, query):
        if path == RUNTIME:
            decision = (query.get("decision") or [""])[0]
            outcome = (query.get("outcome_state") or [""])[0]
            rows = [row for row in self.runtime_rows
                    if (not decision or row["decision"] == decision) and (not outcome or row["bucket"] == outcome)]
            return {"items": rows, "next_cursor": None, "has_more": False,
                    "summary": {"total": len(rows),
                                "allowed": sum(r["decision"] == "ALLOW" for r in rows),
                                "blocked": sum(r["decision"] == "BLOCK" for r in rows),
                                "executed": 0, "skipped": 0, "errors": 0,
                                "outcome_states": {b: sum(r["bucket"] == b for r in rows) for b in BUCKETS}}}
        if path == "/tools" and self.tools_override is not None:
            return self.tools_override
        return super().read(path, query)

    def runtime_reads(self):
        return [query for method, path, query in self.requests if method == "GET" and path == RUNTIME]


def header_refresh(page):
    page.get_by_role("banner").get_by_role("button", name="Refresh", exact=True).click()


def check_ux03(browser, server, shots):
    """UX-03: header Refresh and Refresh events re-read the visible applied query;
    a failed refresh keeps prior rows and labels them stale."""
    context, page, api, errors = smoke.open_page(browser, server, "ADMIN", 1440)
    smoke.navigate(page, "Tool activity", 1440)
    rows = page.locator(".runtime-section tbody tr")
    expect(rows).to_have_count(1)
    expect(page.get_by_test_id("runtime-freshness")).to_contain_text("Results read at")

    # Apply a filter, then add a second matching row and one non-matching row.
    page.get_by_label("Decision").select_option("BLOCK")
    page.get_by_role("button", name="Apply", exact=True).click()
    expect(rows).to_have_count(1)
    api.runtime_rows = [runtime_event(1), runtime_event(2), runtime_event(3, decision="ALLOW")]

    before = len(api.runtime_reads())
    header_refresh(page)
    expect(rows).to_have_count(2)
    reads = api.runtime_reads()[before:]
    # The visible view re-reads its applied filter (Home's shared read may also run).
    assert any(q.get("decision") == ["BLOCK"] and "cursor" not in q for q in reads), reads

    api.runtime_rows.append(runtime_event(4))
    page.get_by_role("button", name="Refresh events").click()
    expect(rows).to_have_count(3)

    # Forced failure: rows remain, labelled stale with the earlier read time.
    api.fail.add(RUNTIME)
    header_refresh(page)
    freshness = page.get_by_test_id("runtime-freshness")
    expect(freshness).to_contain_text("Latest refresh failed. Showing stale results read at")
    expect(rows).to_have_count(3)
    expect(page.locator(".stale-results")).to_have_count(1)
    expect(page.get_by_role("alert").filter(has_text="may be stale")).to_be_visible()
    if shots:
        page.screenshot(path=str(shots / "ux03-runtime-stale-after-failed-refresh-1440.png"), full_page=False)
    api.fail.discard(RUNTIME)
    page.get_by_role("button", name="Refresh events").click()
    expect(freshness).to_contain_text("Results read at")
    expect(page.locator(".stale-results")).to_have_count(0)
    assert not errors, errors
    context.close()
    return "ADMIN: header Refresh and Refresh events re-read applied decision=BLOCK; failed refresh kept 3 rows labelled stale"


def open_review(page):
    smoke.navigate(page, "Security review", 1440)
    row = page.get_by_role("row").filter(has_text="read_documents").first
    if row.count():
        row.click()
    expect(page.get_by_role("region", name="Security summary")).to_be_visible()
    return page.get_by_role("region", name="Security summary").locator("[data-drift-state]")


def check_ux06(browser, server, shots):
    """UX-06: empty drift changes are never presented as verified absence of drift."""
    context, page, api, errors = smoke.open_page(browser, server, "ADMIN", 1440)
    cell = open_review(page)
    expect(cell).to_have_attribute("data-drift-state", "no_baseline")
    expect(cell).to_contain_text("No approved baseline")
    expect(cell).not_to_contain_text("No changes recorded")
    if shots:
        page.get_by_role("region", name="Security summary").screenshot(path=str(shots / "ux06-drift-no-baseline.png"))
    context.close()

    bound = {**smoke.ANALYSIS, "drift_result": {"status": "NONE", "changes": [], "similarity": 1.0, "comparison": {
        "schema": "m6.comparison_target.v1", "baseline_present": True, "baseline_snapshot_available": True,
        "baseline_id": 4, "baseline_version_id": 9, "baseline_fingerprint": "c" * 64,
        "compared": True, "comparison_ran": True}}}
    original = RemediationAPI.read

    def read(self, path, query):
        if path.endswith("/tool-analysis/tools/1/analyses") or path == "/control-plane/tool-analysis/analyses":
            return [bound]
        if path.endswith("/tool-analysis/tools/1/baseline"):
            return {"id": 4, "tool_id": 1, "version_id": 9, "fingerprint": "c" * 64,
                    "approval_provenance": {"label": "Administrator approval"}}
        return original(self, path, query)

    RemediationAPI.read = read
    try:
        context, page, api, errors = smoke.open_page(browser, server, "ADMIN", 1440)
        cell = open_review(page)
        expect(cell).to_have_attribute("data-drift-state", "unchanged")
        expect(cell).to_contain_text("No drift against baseline cccccccccccc")
        if shots:
            page.get_by_role("region", name="Security summary").screenshot(path=str(shots / "ux06-drift-unchanged-bound.png"))
        assert not errors, errors
        context.close()
    finally:
        RemediationAPI.read = original
    return "no-baseline fixture reads 'No approved baseline'; bound comparison reads 'No drift against baseline cccccccccccc'"


def check_ux04(browser, server, shots):
    """UX-04: policy allows and uncertain outcomes are counted separately and each
    priority card opens its exact filtered destination (stable across reload)."""
    tools = [{**smoke.TOOL, "id": i, "name": name, "analysis_status": state}
             for i, (name, state) in enumerate([("review_a", "REVIEW_REQUIRED"), ("stale_b", "STALE"),
                                                ("blocked_c", "BLOCKED"), ("approved_d", "APPROVED")], start=1)]
    RemediationAPI.tools_override = tools
    try:
        context, page, api, errors = smoke.open_page(browser, server, "ADMIN", 1440)
        # ALLOW followed by uncertain dispatch: counts as a policy allow AND an
        # uncertain outcome, never as execution recorded.
        api.runtime_rows = [runtime_event(1, decision="ALLOW", bucket="sent_uncertain"),
                            runtime_event(2, decision="BLOCK", bucket="confirmed_not_sent")]
        page.get_by_role("banner").get_by_role("button", name="Refresh", exact=True).click()
        cards = page.get_by_role("region", name="What needs attention")
        review_card = cards.locator('[data-queue="REVIEW"]')
        expect(review_card.locator("strong")).to_have_text("2")  # REVIEW_REQUIRED + STALE
        expect(cards.locator('[data-queue="BLOCKED"] strong')).to_have_text("1")
        expect(cards.locator('[data-queue="sent_uncertain"] strong')).to_have_text("1")
        page.get_by_text("MCP inventory and decision counts").click()
        stats = page.locator(".stats-grid")
        expect(stats.locator(".stat-card", has_text="Recorded policy allows")).to_contain_text("1")
        expect(stats.locator(".stat-card", has_text="Outcome uncertain after send")).to_contain_text("1")
        expect(stats.locator(".stat-card", has_text="Execution recorded")).to_contain_text("0")
        expect(page.get_by_text("Allowed outcome events")).to_have_count(0)
        if shots:
            cards.screenshot(path=str(shots / "ux04-home-priority-1440.png"))

        cards.get_by_role("button", name="Open blocked tools").click()
        expect(page.get_by_role("heading", level=2, name="Security review")).to_be_visible()
        assert "queue=BLOCKED" in page.url, page.url
        expect(page.get_by_label("Analysis status")).to_have_value("BLOCKED")
        expect(page.get_by_text("1 displayed / 4 total")).to_be_visible()
        page.reload()
        expect(page.get_by_label("Analysis status")).to_have_value("BLOCKED")

        smoke.navigate(page, "Home", 1440)
        page.get_by_role("region", name="What needs attention").get_by_role("button", name="Open review queue").click()
        expect(page.get_by_label("Analysis status")).to_have_value("REVIEW")
        expect(page.get_by_text("2 displayed / 4 total")).to_be_visible()

        smoke.navigate(page, "Home", 1440)
        page.get_by_role("region", name="What needs attention").get_by_role("button", name="Review uncertain outcomes").click()
        expect(page.get_by_role("heading", level=2, name="Tool activity")).to_be_visible()
        assert "outcome=sent_uncertain" in page.url, page.url
        expect(page.get_by_label("Outcome")).to_have_value("sent_uncertain")
        expect(page.locator(".runtime-section tbody tr")).to_have_count(1)
        assert any(q.get("outcome_state") == ["sent_uncertain"] for q in api.runtime_reads())
        page.go_back()
        expect(page.get_by_role("heading", level=2, name="Security overview")).to_be_visible()
        assert not errors, errors
        context.close()
    finally:
        RemediationAPI.tools_override = None
    return "ALLOW+uncertain counted as 1 allow and 1 uncertain, 0 execution; REVIEW=2 incl. STALE, BLOCKED=1, uncertain=1 each equal their landing list; queue survives reload"


def check_ux01(browser, server, shots):
    """UX-01: System health shows loaded builds; a mixed-version stack and an
    unreachable component are visible and distinct from readiness."""
    import subprocess
    head = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=Path(__file__).parent, text=True).strip()
    policy = "d" * 64

    def provenance(api_rev, gateway, opa_digest=policy):
        gateway_up = gateway != "down"
        comparisons = [
            {"key": "gateway_revision_vs_api", "label": "Gateway revision matches API revision",
             "status": "unreachable" if not gateway_up else ("match" if gateway == api_rev else "mismatch"),
             "expected": api_rev, "observed": None if not gateway_up else gateway, "uncommitted_changes_at_start": False},
            {"key": "opa_policy_vs_api_start", "label": "Loaded OPA policies match the bundle the API started with",
             "status": "match" if opa_digest == policy else "mismatch", "expected": policy, "observed": opa_digest,
             "uncommitted_changes_at_start": False},
        ]
        return {"schema": "mcp.runtime_provenance.v1", "overall": "match", "comparisons": comparisons, "components": {
            "api": {"reachable": True, "probed_at": smoke.STAMP, "build": {"revision": api_rev, "revision_source": "git_head_at_process_start", "started_at": smoke.STAMP}},
            "gateway": {"reachable": gateway_up, "probed_at": smoke.STAMP, "build": {"revision": gateway, "revision_source": "git_head_at_process_start", "started_at": smoke.STAMP} if gateway_up else None},
            "opa": {"reachable": True, "probed_at": smoke.STAMP, "policy_bundle_digest": opa_digest, "policy_module_count": 2}}}

    scenario = {"value": provenance(head, head)}
    original = RemediationAPI.read

    def read(self, path, query):
        if path == "/control-plane/local-runtime/provenance":
            return scenario["value"]
        return original(self, path, query)

    RemediationAPI.read = read
    results = []
    try:
        context, page, api, errors = smoke.open_page(browser, server, "VIEWER", 1440)
        smoke.navigate(page, "System health", 1440)
        panel = page.locator("#build-provenance")
        overall = panel.locator("[data-provenance-overall]")
        expect(overall).to_have_attribute("data-provenance-overall", "match")
        expect(panel.locator('[data-provenance-check="ui_revision_vs_api"]')).to_have_attribute("data-status", "match")
        results.append("matched stack: match")

        # Deliberate mixed version: an older API and Gateway behind the current UI, changed policy.
        scenario["value"] = provenance("b" * 40, "c" * 40, opa_digest="e" * 64)
        panel.get_by_role("button", name="Check again").click()
        expect(overall).to_have_attribute("data-provenance-overall", "mismatch")
        expect(overall).to_contain_text("Mixed versions")
        for key in ("ui_revision_vs_api", "gateway_revision_vs_api", "opa_policy_vs_api_start"):
            expect(panel.locator(f'[data-provenance-check="{key}"]')).to_have_attribute("data-status", "mismatch")
        # Readiness is independent: the same page still reports readiness separately.
        expect(page.locator(".operations-ready")).to_be_visible()
        if shots:
            panel.screenshot(path=str(shots / "ux01-provenance-mixed-1440.png"))
        results.append("mixed stack: 3 mismatches")

        scenario["value"] = provenance(head, "down")
        panel.get_by_role("button", name="Check again").click()
        expect(overall).to_have_attribute("data-provenance-overall", "unreachable")
        expect(panel.locator('[data-provenance-check="gateway_revision_vs_api"]')).to_have_attribute("data-status", "unreachable")
        expect(panel.get_by_role("row", name="Gateway")).to_contain_text("Unreachable")
        results.append("stopped gateway: unreachable (not mismatch)")
        assert not errors, errors
        context.close()
    finally:
        RemediationAPI.read = original
    return "; ".join(results)


def prowler_fixture():
    severities = ["CRITICAL"] * 4 + ["HIGH"] * 14 + ["MEDIUM"] * 25 + ["LOW"] * 15
    scans, details = [], {}
    for label, minute in (("aaaa1111", "10:30"), ("bbbb2222", "10:30")):  # duplicate timestamps on purpose
        scan_id = label + "-0000-4000-8000-000000000000"
        scan = {"id": scan_id, "environment_id": "env-qa", "kind": "AWS_ADVANCED", "status": "COMPLETED",
                "created_at": f"2026-11-21T{minute}:00Z", "started_at": "2026-11-21T10:31:00Z",
                "completed_at": "2026-11-21T10:40:00Z", "resource_count": 31, "finding_count": 58,
                "unknown_checks": 0, "scanner_version": "5.x", "error_code": None}
        scans.append(scan)
        findings = [{"id": f"{label}-f{i}", "resource_id": None, "rule_id": f"rule_{i % 9}", "fingerprint": "f" * 64,
                     "severity": sev, "result": "FAIL", "title": f"Synthetic finding {i}",
                     "description": "Synthetic Prowler failure.", "remediation": None}
                    for i, sev in enumerate(severities)]
        details[scan_id] = {"scan": scan, "resources": [], "events": [], "evidence": [], "findings": findings,
                            "collection_coverage": {"findings": {"returned": 58, "display_limit": 300, "truncated": False}},
                            "assessment_summary": {
                                "execution": {"state": "COMPLETED", "source": "SCANNER_EXECUTION_EVIDENCE",
                                              "scanner": "prowler", "scanner_version": "5.x", "records_returned": 120, "error_code": None},
                                "findings": {"total": 58, "by_severity": {"CRITICAL": 4, "HIGH": 14, "MEDIUM": 25, "LOW": 15},
                                             "population": "ALL_PERSISTED_FINDINGS_FOR_SCAN", "matches_scan_counter": True},
                                "coverage": {"available": True, "reason": None, "resources_observed": 31,
                                             "unresolved_observations": 0, "unknown_service_reads": 0, "unassessed_services": 0}}}
    failed_id = "cccc3333-0000-4000-8000-000000000000"
    failed = {**scans[0], "id": failed_id, "status": "FAILED", "resource_count": 0, "finding_count": 0,
              "unknown_checks": 0, "started_at": None, "error_code": "PROWLER_EXECUTION_FAILED"}
    scans.append(failed)
    details[failed_id] = {"scan": failed, "resources": [], "events": [], "evidence": [], "findings": [],
                          "collection_coverage": {}, "assessment_summary": {
                              "execution": {"state": "FAILED", "source": "SCAN_STATUS", "error_code": "PROWLER_EXECUTION_FAILED"},
                              "findings": {"total": 0, "by_severity": {}, "population": "ALL_PERSISTED_FINDINGS_FOR_SCAN", "matches_scan_counter": True},
                              "coverage": {"available": False, "reason": "SCAN_FAILED_BEFORE_COLLECTION", "resources_observed": 0,
                                           "unresolved_observations": 0, "unknown_service_reads": 0, "unassessed_services": 0}}}
    return scans, details


def cloud_page(scans, query):
    """Server-side behaviour of /scans/page for the mocks (env, kind, IaC inclusion, paging)."""
    env = (query.get("environment_id") or [""])[0]
    kind = (query.get("kind") or [""])[0]
    include_iac = (query.get("include_unscoped_iac") or ["false"])[0] == "true"
    rows = [s for s in scans
            if (not kind or s["kind"] == kind)
            and (not env or s.get("environment_id") == env
                 or (include_iac and s["kind"] == "IAC_CONFIG" and not s.get("environment_id")))]
    rows.sort(key=lambda s: (s["created_at"], s["id"]), reverse=True)
    offset, limit = int((query.get("offset") or ["0"])[0]), int((query.get("limit") or ["25"])[0])
    items = rows[offset:offset + limit]
    return {"scope": "PERSISTED_CLOUD_SCANS", "items": items, "total": len(rows), "offset": offset,
            "limit": limit, "returned": len(items), "has_more": offset + len(items) < len(rows)}


def check_ux11(browser, server, shots):
    """UX-11: an older scan of a quiet environment stays in its own history and
    reopens by copied link, Reload and Back; an unknown ID is explicit."""
    envs = [{"id": "env-a", "name": "Quiet A", "provider": "AWS", "status": "CONNECTED", "regions": ["eu-west-3"],
             "services": ["S3"], "account_id": "111111111111", "role_arn": "arn:aws:iam::111111111111:role/QA"},
            {"id": "env-b", "name": "Busy B", "provider": "AWS", "status": "CONNECTED", "regions": ["eu-west-3"],
             "services": ["S3"], "account_id": "222222222222", "role_arn": "arn:aws:iam::222222222222:role/QA"}]
    base = {"kind": "AWS_ADVANCED", "status": "COMPLETED", "resource_count": 3, "finding_count": 0,
            "unknown_checks": 0, "scanner_version": "5.x", "error_code": None, "completed_at": None}
    scans = [{**base, "id": f"b{i:07d}-0000-4000-8000-000000000000", "environment_id": "env-b",
              "created_at": f"2026-11-21T{10 + i // 60:02d}:{i % 60:02d}:00Z", "started_at": None} for i in range(100)]
    older = {**base, "id": "a0000001-0000-4000-8000-000000000000", "environment_id": "env-a",
             "created_at": "2026-10-01T08:00:00Z", "started_at": "2026-10-01T08:01:00Z"}
    scans.append(older)
    original = RemediationAPI.read

    def read(self, path, query):
        if path == smoke.CLOUD + "/environments":
            return envs
        if path == smoke.CLOUD + "/scans":
            return sorted(scans, key=lambda s: s["created_at"], reverse=True)[:100]  # legacy latest-100
        if path == smoke.CLOUD + "/scans/page":
            return cloud_page(scans, query)
        if path.startswith(smoke.CLOUD + "/scans/"):
            scan_id, _, suffix = path.removeprefix(smoke.CLOUD + "/scans/").partition("/")
            found = next((s for s in scans if s["id"] == scan_id), None)
            if suffix == "" and found:
                return {"scan": found, "resources": [], "events": [], "evidence": [], "findings": [],
                        "collection_coverage": {}, "assessment_summary": None}
            return []
        return original(self, path, query)

    def route(self, route):
        from urllib.parse import urlsplit
        path = urlsplit(route.request.url).path.removeprefix("/api/v1")
        if path.startswith(smoke.CLOUD + "/scans/deadbeef"):
            return route.fulfill(status=404, json={"detail": "cloud_scan_not_found"})
        return super(RemediationAPI, self).route(route)

    RemediationAPI.read = read
    RemediationAPI.route = route
    try:
        context, page, api, errors = smoke.open_page(browser, server, "VIEWER", 1440)
        root = page.url.split("?")[0].rstrip("/")
        page.goto(root + "/?view=cloud&env=env-a&task=cloud-scans")
        history = page.get_by_role("region", name="Cloud audit history")
        expect(page.get_by_test_id("cloud-history-range")).to_have_text("Showing 1–1 of 1 stored scans.")
        open_a = history.get_by_role("button", name="View Advanced AWS a0000001", exact=False)
        expect(open_a).to_be_visible()
        assert any(q.get("environment_id") == ["env-a"] for m, p, q in api.requests if p.endswith("/scans/page"))
        open_a.click()
        expect(page.get_by_role("heading", name="Audit review")).to_be_visible()
        assert "scan=a0000001-0000-4000-8000-000000000000" in page.url, page.url
        copied = page.url
        page.reload()
        expect(page.get_by_text("Scan a0000001 was not found")).to_have_count(0)
        expect(page.locator(".cloud-review-summary")).to_contain_text("Advanced AWS")
        assert any(p.endswith("/scans/a0000001-0000-4000-8000-000000000000") for m, p, q in api.requests)
        page.go_back()
        expect(page.get_by_test_id("cloud-history-range")).to_be_visible()
        context.close()

        # A copied link opened in a fresh session reopens the same scan.
        context, page, api, errors = smoke.open_page(browser, server, "VIEWER", 1440)
        page.goto(copied)
        expect(page.locator(".cloud-review-summary")).to_contain_text("Advanced AWS")
        page.goto(root + "/?view=cloud&scan=deadbeef-0000-4000-8000-000000000000")
        expect(page.get_by_role("alert").filter(has_text="Scan deadbeef was not found or is not available to you. No other scan was substituted.")).to_be_visible()
        expect(page.locator(".cloud-review-summary")).to_have_count(0)
        if shots:
            page.locator("#cloud-detail").screenshot(path=str(shots / "ux11-cloud-unknown-scan-1440.png"))
        assert not [e for e in errors if "404" not in e], errors
        context.close()
    finally:
        RemediationAPI.read = original
        del RemediationAPI.route
    return "older A behind 100 newer B: found in A's history (server env filter), reopened by link, Reload, Back; unknown ID explicit, nothing substituted"


def check_ux19(browser, server, shots):
    """UX-19 (+UX-22/23 history text): execution, findings and coverage are separate;
    findings lead the detail; a failed run reads Coverage unavailable."""
    scans, details = prowler_fixture()
    original = RemediationAPI.read

    def read(self, path, query):
        if path == smoke.CLOUD + "/scans":
            return scans
        if path == smoke.CLOUD + "/scans/page":
            return cloud_page(scans, query)
        if path.startswith(smoke.CLOUD + "/scans/"):
            scan_id, _, suffix = path.removeprefix(smoke.CLOUD + "/scans/").partition("/")
            if suffix == "" and scan_id in details:
                return details[scan_id]
            return []
        return original(self, path, query)

    RemediationAPI.read = read
    try:
        context, page, api, errors = smoke.open_page(browser, server, "VIEWER", 1440)
        smoke.navigate(page, "Cloud security", 1440)
        page.get_by_role("navigation", name="Cloud security tasks").get_by_role("button", name="Audit history").click()
        history = page.get_by_role("region", name="Cloud audit history")
        expect(history.get_by_role("columnheader", name="Queued")).to_be_visible()
        expect(history.get_by_role("columnheader", name="Started")).to_be_visible()
        # Duplicate queue times stay distinguishable by a stable scan reference.
        expect(history.get_by_role("button", name="View Advanced AWS aaaa1111", exact=False)).to_be_visible()
        expect(history.get_by_role("button", name="View Advanced AWS bbbb2222", exact=False)).to_be_visible()
        expect(history.get_by_role("row").filter(has_text="cccc3333")).to_contain_text("Not collected")
        expect(history.get_by_role("row").filter(has_text="cccc3333")).to_contain_text("Not started")
        if shots:
            history.screenshot(path=str(shots / "ux19-prowler-history-1440.png"))

        history.get_by_role("button", name="View Advanced AWS aaaa1111", exact=False).click()
        summary = page.get_by_role("group", name="Scan result summary")
        expect(page.get_by_test_id("scan-findings-headline")).to_have_text("58 failed rule/resource findings")
        expect(page.get_by_test_id("scan-execution-headline")).to_have_text("Scanner execution complete")
        expect(page.get_by_test_id("scan-coverage-headline")).to_have_text("31 resources observed · 0 unresolved observations recorded")
        # Findings precede governance and come right after the summary.
        heading_y = page.locator("#cloud-findings-heading").bounding_box()["y"]
        governance = page.get_by_role("heading", name="Security assessment and administrator review")
        assert heading_y < governance.bounding_box()["y"], "findings must precede governance"
        summary.get_by_role("button", name="Critical 4").click()
        expect(page.locator(".cloud-finding")).to_have_count(4)
        expect(page.get_by_test_id("cloud-findings-scope")).to_contain_text("4 shown · 58 of 58 stored findings loaded")
        detail_text = page.locator("#cloud-detail").inner_text()
        for defect in ("31resources", "and0", "unresolved.This"):
            assert defect not in detail_text, defect
        if shots:
            page.locator("#cloud-detail").screenshot(path=str(shots / "ux19-prowler-detail-1440.png"))

        page.get_by_role("button", name="Browse audit history").click()
        history.get_by_role("button", name="View Advanced AWS cccc3333", exact=False).click()
        expect(page.get_by_test_id("scan-coverage-headline")).to_have_text("Coverage unavailable")
        expect(page.get_by_test_id("scan-findings-headline")).to_have_text("Findings not collected")
        expect(page.get_by_test_id("cloud-findings-empty")).to_contain_text("Scan failed · Coverage unavailable")
        expect(page.get_by_text("No confirmed findings in the collected results")).to_have_count(0)
        if shots:
            page.locator("#cloud-detail").screenshot(path=str(shots / "ux19-prowler-failed-1440.png"))
        assert not errors, errors
        context.close()

        context, page, api, errors = smoke.open_page(browser, server, "VIEWER", 390)
        smoke.navigate(page, "Cloud security", 390)
        page.get_by_role("navigation", name="Cloud security tasks").get_by_role("button", name="Audit history").click()
        page.get_by_role("region", name="Cloud audit history").get_by_role("button", name="View Advanced AWS aaaa1111", exact=False).click()
        expect(page.get_by_test_id("scan-findings-headline")).to_be_visible()
        box = page.locator("#cloud-findings-heading").bounding_box()
        assert box["y"] < 2600, f"findings start at {box['y']}px on mobile"
        if shots:
            page.screenshot(path=str(shots / "ux19-prowler-detail-390.png"), full_page=False)
        context.close()
        mobile_y = int(box["y"])
    finally:
        RemediationAPI.read = original
    return f"31/58/0 x2: execution/findings/coverage separate, severity 4/14/25/15, findings before governance (mobile heading at {mobile_y}px), failed run = Coverage unavailable"


def check_ux09(browser, server, shots):
    """UX-09: a finding beyond row 500 is reachable by exact ID and by paging, for both roles."""
    from urllib.parse import unquote
    build = "/control-plane/build-security"
    scan = {"id": "build-scan-501", "target_type": "LOCAL_DIRECTORY", "display_name": "synthetic-501",
            "status": "COMPLETED", "created_at": smoke.STAMP, "source_fingerprint": "f" * 64}
    findings = [{"id": f"finding-{i:04d}", "build_scan_id": scan["id"], "scanner_run_id": "run-1",
                 "scanner_id": "semgrep" if i % 2 else "trivy", "rule_id": f"rule.{i % 5}", "category": "code",
                 "severity": "LOW" if i < 500 else "INFO", "confidence": "HIGH", "finding_state": "NEW",
                 "fingerprint": "f" * 64, "title": f"Synthetic finding {i}", "file_path": f"src/m_{i:04d}.py",
                 "line_start": 1, "references": [], "safe_metadata": {}, "created_at": smoke.STAMP}
                for i in range(501)]
    detail = {"scan": scan, "scanner_runs": [{"id": "run-1", "scanner_id": "semgrep", "status": "COMPLETED",
                                               "required": True, "finding_count": 251},
                                              {"id": "run-2", "scanner_id": "trivy", "status": "COMPLETED",
                                               "required": True, "finding_count": 250}],
              "findings": findings[:500], "finding_total": 501, "findings_truncated": True, "assessment": None}
    original = RemediationAPI.read

    def read(self, path, query):
        if path == build + "/scans":
            return [scan]
        if path == build + f"/scans/{scan['id']}":
            return detail
        if path == build + f"/scans/{scan['id']}/findings":
            q = {k: unquote(v[0]) for k, v in query.items()}
            rows = [f for f in findings
                    if (not q.get("finding_id") or f["id"] == q["finding_id"])
                    and (not q.get("severity") or f["severity"] == q["severity"])
                    and (not q.get("path") or q["path"] in f["file_path"])]
            offset, limit = int(q.get("offset", 0)), int(q.get("limit", 50))
            page = rows[offset:offset + limit]
            return {"scope": "PERSISTED_SCAN_FINDINGS", "items": page, "total": len(rows), "unfiltered_total": 501,
                    "offset": offset, "limit": limit, "returned": len(page), "has_more": offset + len(page) < len(rows),
                    "filters": {}}
        return original(self, path, query)

    RemediationAPI.read = read
    results = []
    try:
        for role in ("ADMIN", "VIEWER"):
            context, page, api, errors = smoke.open_page(browser, server, role, 1440)
            smoke.navigate(page, "Code scans", 1440)
            page.get_by_role("region", name="Build scan history table").get_by_role("button", name="synthetic-501").click()
            browser_region = page.get_by_role("region", name="Build findings")
            rng = page.get_by_test_id("build-findings-range")
            expect(rng).to_have_text("Showing 1–50 of 501 stored.")
            page.get_by_label("Finding ID").fill("finding-0500")
            page.get_by_role("button", name="Apply", exact=True).first.click()
            expect(rng).to_have_text("Showing 1–1 of 1 · filtered from 501 stored.")
            expect(browser_region.locator('[data-finding-id="finding-0500"]')).to_contain_text("src/m_0500.py")
            page.get_by_role("button", name="Clear", exact=True).first.click()
            page.get_by_label("Severity").select_option("INFO")
            page.get_by_role("button", name="Apply", exact=True).first.click()
            expect(rng).to_have_text("Showing 1–1 of 1 · filtered from 501 stored.")
            page.get_by_role("button", name="Clear", exact=True).first.click()
            for _ in range(10):
                page.locator(".build-findings-browser").get_by_role("button", name="Next").click()
            expect(rng).to_have_text("Showing 501–501 of 501 stored.")
            expect(browser_region.locator('[data-finding-id="finding-0500"]')).to_be_visible()
            if role == "VIEWER":
                expect(browser_region.get_by_role("link", name="Open source at scanned revision")).to_have_count(0)
            if shots and role == "ADMIN":
                page.locator(".build-findings-browser").screenshot(path=str(shots / "ux09-build-findings-501-1440.png"))
            assert not errors, errors
            context.close()
            results.append(role + ": row 501 by exact ID, by INFO filter and by paging")
    finally:
        RemediationAPI.read = original
    return "; ".join(results)


def check_ux16(browser, server, shots):
    """UX-16: a VIEWER opening a protected Users link sees an explicit boundary at
    the same address, a safe return path, and no Users API read."""
    context, page, api, errors = smoke.open_page(browser, server, "VIEWER", 1440)
    smoke.navigate(page, "Audit history", 1440)
    origin = page.url
    page.goto(page.url.split("?")[0] + "?view=users")
    expect(page.get_by_role("heading", level=2, name="Administrator access required")).to_be_visible()
    assert "view=users" in page.url
    expect(page.get_by_role("main", name="Users")).to_be_visible()
    assert not any(path == "/control-plane/users" for _, path, _ in api.requests)
    if shots:
        page.screenshot(path=str(shots / "ux16-viewer-users-boundary-1440.png"))
    page.get_by_role("button", name="Go back").click()
    expect(page.get_by_role("heading", level=2, name="Audit history")).to_be_visible()
    assert page.url == origin
    page.goto(page.url.split("?")[0] + "?view=users")
    page.get_by_role("button", name="Return to Home").click()
    expect(page.get_by_role("heading", level=2, name="Security overview")).to_be_visible()
    assert not errors, errors
    context.close()
    context, page, api, errors = smoke.open_page(browser, server, "ADMIN", 1440)
    page.goto(page.url.split("?")[0] + "?view=users")
    expect(page.get_by_role("heading", level=2, name="Users")).to_be_visible()
    expect(page.get_by_text("Administrator access required")).to_have_count(0)
    context.close()
    return "VIEWER: boundary at ?view=users, no /users read, Go back to origin, Return to Home; ADMIN unaffected"


def check_ux05(browser, server, shots):
    """UX-05: Inventory states observation approval and the next recorded blocker,
    never a yes/no call permission; each endpoint has its own copy action;
    Home Add MCP opens the connect form."""
    context, page, api, errors = smoke.open_page(browser, server, "ADMIN", 1440)
    page.get_by_role("region", name="Quick actions").get_by_role("button", name="Add MCP server").click() \
        if page.get_by_role("region", name="Quick actions").count() else \
        page.locator(".dashboard-actions").get_by_role("button", name="Add MCP server").click()
    expect(page.get_by_role("heading", level=2, name="MCP tools")).to_be_visible()
    assert "action=connect" in page.url
    expect(page.locator("#inventory-connect")).to_have_attribute("open", "")
    page.locator("#inventory-servers").get_by_role("button").filter(has_text="Documentation MCP").first.click()
    expect(page.get_by_role("button", name="Copy upstream endpoint")).to_be_visible()
    page.locator("#inventory-tools").get_by_text("Read documents", exact=False).first.click()
    panel = page.get_by_test_id("tool-observation-approval")
    expect(panel).to_contain_text("Approval for current observation")
    expect(panel).to_contain_text("A human review decision is required for this observation.")
    expect(page.get_by_text("Can this tool be called now?")).to_have_count(0)
    if shots:
        panel.screenshot(path=str(shots / "ux05-inventory-observation-approval.png"))
    assert not errors, errors
    context.close()
    return "Home Add MCP opens ?view=inventory&action=connect with form open; upstream copy action; observation approval + REVIEW_REQUIRED blocker"


def check_ux10(browser, server, shots):
    """UX-10 (+UX-23 badges): execution, coverage, assessment and signed gate are
    separate; reasons link to the exact scanner run or findings filter; a draft
    attachment is not presented as enforcement; badges keep intrinsic height."""
    build = "/control-plane/build-security"
    scan_id = "11111111-2222-4333-8444-555555555555"
    scan = {"id": scan_id, "target_type": "LOCAL_DIRECTORY", "display_name": "partial-scan", "status": "FAILED",
            "created_at": smoke.STAMP, "source_fingerprint": "f" * 64}
    runs = [{"id": "r1", "scanner_id": "semgrep", "status": "COMPLETED", "required": True, "finding_count": 1},
            {"id": "r2", "scanner_id": "trivy", "status": "TIMED_OUT", "required": True, "finding_count": 0,
             "error_code": "scanner_timeout_after_600_seconds_while_reading_a_very_large_dependency_lockfile"}]
    critical = {"id": "crit-1", "build_scan_id": scan_id, "scanner_run_id": "r1", "scanner_id": "semgrep",
                "rule_id": "rule.crit", "category": "code", "severity": "CRITICAL", "confidence": "HIGH",
                "finding_state": "NEW", "fingerprint": "f" * 64, "title": "Critical synthetic", "file_path": "a.py",
                "line_start": 1, "references": [], "safe_metadata": {}, "created_at": smoke.STAMP}
    assessment = {"id": "a1", "build_scan_id": scan_id, "status": "ERROR", "policy_version": "build-policy-v1",
                  "required_scanners_complete": False, "reason_codes": ["required_scanner_incomplete", "critical_findings"],
                  "summary": "Incomplete.", "critical_count": 1, "high_count": 0, "medium_count": 0, "low_count": 0,
                  "info_count": 0, "created_at": smoke.STAMP}
    detail = {"scan": scan, "scanner_runs": runs, "findings": [critical], "finding_total": 1,
              "findings_truncated": False, "assessment": assessment}
    active = {"id": "rev", "revision_number": 7, "status": "PUBLISHED", "content_hash": "a" * 64,
              "content": {"build_security": {"mode": "REQUIRE_PASS", "max_evidence_age_hours": 168, "evidence": []}}}
    original = RemediationAPI.read

    def read(self, path, query):
        if path == build + "/scans":
            return [scan]
        if path == build + f"/scans/{scan_id}":
            return detail
        if path == build + f"/scans/{scan_id}/findings":
            sev = (query.get("severity") or [""])[0]
            rows = [critical] if sev in ("", "CRITICAL") else []
            return {"scope": "PERSISTED_SCAN_FINDINGS", "items": rows, "total": len(rows), "unfiltered_total": 1,
                    "offset": 0, "limit": 50, "returned": len(rows), "has_more": False, "filters": {}}
        if path == "/control-plane/config/active":
            return active
        return original(self, path, query)

    RemediationAPI.read = read
    try:
        context, page, api, errors = smoke.open_page(browser, server, "ADMIN", 1440)
        smoke.navigate(page, "Code scans", 1440)
        page.get_by_role("region", name="Build scan history table").get_by_role("button", name="partial-scan").click()
        facts = page.get_by_role("group", name="Build scan facts")
        expect(facts.locator('[data-fact="execution"]')).to_contain_text("1 of 2 scanner run(s) completed")
        expect(facts.locator('[data-fact="execution"]')).to_contain_text("trivy (timed_out)")
        expect(facts.locator('[data-fact="coverage"]')).to_contain_text("Required coverage incomplete")
        expect(facts.locator('[data-fact="assessment"]')).to_contain_text("ERROR · 1 critical / 0 high")
        expect(facts.locator('[data-fact="gate"]')).to_contain_text("Enforce (requires PASS)")
        expect(facts.locator('[data-fact="gate"]')).to_contain_text("not bound evidence in active signed revision 7")
        page.get_by_text("Recorded assessment reasons (2)").click()
        page.get_by_role("link", name="Open trivy run").click()
        assert page.url.endswith("#build-scanner-run-trivy")
        page.get_by_role("button", name="Show critical findings").click()
        expect(page.get_by_label("Severity")).to_have_value("CRITICAL")
        expect(page.get_by_role("region", name="Build findings").locator('[data-finding-id="crit-1"]')).to_be_visible()
        heights = page.evaluate("""() => [...document.querySelectorAll('.build-scanner-run-list article > .badge')]
            .map(b => b.getBoundingClientRect().height)""")
        assert len(heights) == 2 and max(heights) - min(heights) < 4, heights
        if shots:
            page.locator(".build-scan-detail").screenshot(path=str(shots / "ux10-build-scan-facts-1440.png"))
        assert not errors, errors
        context.close()
    finally:
        RemediationAPI.read = original
    return f"timed-out trivy + critical semgrep shown separately; signed gate REQUIRE_PASS not bound; reasons link to run and filter; badge heights {heights}"



def check_ux21(browser, server, shots, *, width=1440, keyboard=False):
    scan_id = "dddd4444-0000-4000-8000-000000000004"
    role = "arn:aws:iam::123456789012:role/QA/" + "LongSyntheticRole" * 4
    scan = {"id": scan_id, "kind": "IAM_MCP", "status": "COMPLETED",
            "environment_id": "env-qa", "finding_count": 28, "resource_count": 1, "unknown_checks": 4}
    comparisons = []
    for index in range(32):
        outside = index < 25
        comparisons.append({
            "id": f"comparison-{index}", "role_arn": role,
            "status": "OUTSIDE_MCP_MAPPING" if outside else "POTENTIAL_MISSING" if index < 28 else "UNKNOWN",
            "tool_name": None if outside else "synthetic_tool",
            "observed_actions": [f"ssm:FixtureAction{index}"] if outside else [],
            "expected_actions": [] if outside else ["s3:GetObject"],
            "expected_resource_arn": "*", "identity_permission_status": "IDENTITY_ALLOW_OUTSIDE_MAPPING",
            "effective_permission_status": "UNKNOWN", "linked_finding_ids": [f"finding-{index}"] if index < 28 else [],
            "notes": "IAM_ALLOW_ACTION_NOT_IN_MCP_MAPPING",
            "evidence_summary": {"id": f"evidence-{index}", "summary": {
                "comparison_id": f"comparison-{index}", "direction": "IAM_POLICY_TO_APPROVED_MCP_NEEDS" if outside else "MCP_NEED_TO_IAM",
                "action": f"ssm:FixtureAction{index}" if outside else "s3:GetObject", "resource": "*",
                "policy_statement_index": index, "role_usage_operator_declared": "SHARED",
                "effective_access_limitations": ["SCP_NOT_EVALUATED"]}}})
    findings = [{"id": f"finding-{i}", "comparison_id": f"comparison-{i}", "rule_id": "IAM_FIXTURE",
                 "title": "Synthetic observation", "severity": "MEDIUM"} for i in range(28)]
    original = RemediationAPI.read

    def read(self, path, query):
        base = smoke.CLOUD + "/scans/" + scan_id
        if path == base:
            return {"scan": scan, "resources": [], "events": [], "evidence": [], "findings": findings,
                    "collection_coverage": {}}
        if path == base + "/iam-comparisons/page":
            return {"items": comparisons, "total": 32, "offset": 0, "limit": 100, "returned": 32, "has_more": False}
        if path.startswith(base + "/"):
            return []
        return original(self, path, query)

    RemediationAPI.read = read
    try:
        context, page, api, errors = smoke.open_page(browser, server, "ADMIN", width)
        root = page.url.split("?")[0]
        page.goto(root + "?view=cloud&scan=" + scan_id)
        worklist = page.get_by_role("region", name="IAM comparison worklist")
        expect(worklist.get_by_text("Outside the approved mapping (25)", exact=True)).to_be_visible()
        expect(worklist.get_by_text("ssm (25)", exact=True)).to_be_visible()
        expect(worklist.locator(".iam-row")).to_have_count(32)
        selected = worklist.get_by_role("button", name=re.compile(r"ssm:FixtureAction4\b"))
        if keyboard:
            assert page.evaluate("document.documentElement.scrollWidth <= innerWidth"), width
            assert worklist.evaluate("(node) => node.scrollWidth <= node.clientWidth"), width
            worklist.focus()
            expect(worklist).to_be_focused()
            selected.focus()
            page.keyboard.press("Enter")
        else:
            selected.click()
        evidence = page.get_by_role("dialog", name="IAM comparison evidence")
        expect(evidence.get_by_role("heading", name="Approved MCP need")).to_be_visible()
        expect(evidence.get_by_role("heading", name="Observed IAM identity-policy statement")).to_be_visible()
        expect(evidence.get_by_text("UNKNOWN", exact=True)).to_be_visible()
        expect(evidence.get_by_text("scp not evaluated", exact=True)).to_be_visible()
        if shots:
            evidence.screenshot(path=str(shots / f"ux21-iam-evidence-{width}.png"))
        if keyboard:
            expect(evidence).to_be_focused()
            page.keyboard.press("Escape")
            expect(evidence).to_have_count(0)
            expect(selected).to_be_focused()
            if shots:
                worklist.screenshot(path=str(shots / f"ux17-iam-worklist-{width}.png"))
            context.close()
            return f"{width}px named scroll region, no horizontal overflow and keyboard focus restored"
        evidence.get_by_role("button", name="Request exception for linked finding finding-4").click()
        expect(page.get_by_label("Finding to review")).to_have_value("finding-4")
        assert not errors, errors
        context.close()
    finally:
        RemediationAPI.read = original
    return "32 exact rows grouped, observed and approved scope separated, UNKNOWN preserved, exact exception selected"


def check_ux17(browser, server, shots):
    return "; ".join(check_ux21(browser, server, shots, width=width, keyboard=True) for width in (320, 768, 1440))



def check_ux08(browser, server, shots):
    event = {**smoke.AUDIT, "before_json": {"contract": {"resource": ["public/*"]}, "same": True},
             "after_json": {"contract": {"resource": ["team/*"]}, "same": True}}
    original = RemediationAPI.read

    def read(self, path, query):
        if path == "/control-plane/audit/events/page":
            return {"items": [event], "total": 1}
        return original(self, path, query)

    RemediationAPI.read = read
    try:
        context, page, api, errors = smoke.open_page(browser, server, "VIEWER", 1440)
        smoke.navigate(page, "Audit history", 1440)
        page.locator("tbody tr button").first.click()
        diff = page.get_by_role("region", name="Recorded field changes")
        expect(diff.get_by_text("/contract/resource/0")).to_be_visible()
        expect(diff.get_by_text('"public/*"', exact=True)).to_be_visible()
        expect(diff.get_by_text('"team/*"', exact=True)).to_be_visible()
        expect(diff.get_by_text("1 unchanged keys", exact=False)).to_be_visible()
        if shots:
            diff.screenshot(path=str(shots / "ux08-audit-nested-diff-1440.png"))
        assert not errors, errors
        context.close()
    finally:
        RemediationAPI.read = original
    return "audit shows exact nested resource path, typed before/after and omitted unchanged count"



def check_ux22(browser, server, shots):
    scans, details = prowler_fixture()
    scan_id = scans[0]["id"]
    template = details[scan_id]["findings"][0]
    findings = [{**template, "id": f"bounded-{index:04}", "title": f"Bounded finding {index}"}
                for index in range(400)]
    resources = [{"id": f"asset-{index}", "resource_type": "fixture", "display_name": f"Asset {index}"}
                 for index in range(43)]
    events = [{"id": f"event-{index}", "message_code": f"EVENT_{index}", "created_at": smoke.STAMP}
              for index in range(43)]
    scans[0]["finding_count"] = 400
    detail = {**details[scan_id], "findings": findings[:300], "resources": resources, "events": events,
              "collection_coverage": {"findings": {"returned": 300, "display_limit": 300, "truncated": True}}}
    detail["assessment_summary"]["findings"].update(total=400, by_severity={"CRITICAL": 400})
    original = RemediationAPI.read

    def read(self, path, query):
        base = smoke.CLOUD + "/scans/" + scan_id
        if path == base:
            return detail
        if path == base + "/collections/findings":
            offset, limit = int(query["offset"][0]), int(query["limit"][0])
            items = findings[offset:offset + limit]
            return {"collection": "findings", "items": items, "offset": offset, "limit": limit,
                    "total": 400, "returned": len(items), "has_more": offset + len(items) < 400}
        if path.startswith(base + "/"):
            return []
        return original(self, path, query)

    RemediationAPI.read = read
    try:
        context, page, api, errors = smoke.open_page(browser, server, "VIEWER", 1440)
        page.goto(page.url.split("?")[0] + "?view=cloud&scan=" + scan_id)
        listing = page.get_by_role("region", name="Cloud findings")
        expect(listing.locator(".cloud-finding-row")).to_have_count(20)
        assert listing.evaluate("(node) => node.clientHeight < 550")
        assert page.evaluate("document.documentElement.scrollHeight") < 4400
        assert listing.bounding_box()["y"] < page.get_by_role(
            "heading", name="Security assessment and administrator review").bounding_box()["y"]
        listing.get_by_role("button", name=re.compile("Bounded finding 0")).first.click()
        expect(page.get_by_role("region", name="Selected cloud finding")).to_contain_text("bounded-0000")
        page.get_by_role("button", name="Load more findings records").click()
        expect(listing.get_by_text("CRITICAL: Bounded finding 300", exact=True)).to_be_visible()
        for label in ("Cloud resources", "Cloud events"):
            page.get_by_role("button", name=f"Next {label.lower()} page").click()
            expect(page.get_by_text(f"{label}: 21–40 of 43 loaded", exact=True)).to_be_visible()
        if shots:
            listing.screenshot(path=str(shots / "ux22-cloud-findings-1440.png"))
        assert not errors, errors
        context.close()
    finally:
        RemediationAPI.read = original
    return "400 findings, 20 DOM rows, first finding before governance, resources and events paged"



def check_ux12(browser, server, shots):
    revision_id = "abcd4321-0000-4000-8000-000000000012"
    missing_id = "abcd4321-0000-4000-8000-000000000013"
    user_id = "abcd4321-0000-4000-8000-000000000014"
    original = RemediationAPI.read

    def read(self, path, query):
        if path == "/control-plane/audit/resolve/control_plane_config_revision/" + revision_id:
            return {"type": "control_plane_config_revision", "id": revision_id, "label": "Revision #12", "status": "PUBLISHED"}
        return original(self, path, query)

    def route(self, req):
        if "/api/v1/control-plane/audit/resolve/" in req.request.url and req.request.url.endswith(missing_id):
            return req.fulfill(status=404, json={"detail": "audit_target_not_available"})
        return super(RemediationAPI, self).route(req)

    RemediationAPI.read = read
    RemediationAPI.route = route
    try:
        context, page, api, errors = smoke.open_page(browser, server, "VIEWER", 1440)
        root = page.url.split("?")[0]
        page.goto(root + "?view=config&record=" + revision_id)
        expect(page.get_by_role("heading", name="Revision #12")).to_be_visible()
        page.reload()
        expect(page.get_by_text(revision_id, exact=True)).to_be_visible()
        page.goto(root + "?view=config&record=" + missing_id)
        expect(page.get_by_role("alert").filter(has_text="No other configuration revision was substituted.")).to_be_visible()
        page.go_back()
        expect(page.get_by_role("heading", name="Revision #12")).to_be_visible()
        page.goto(root + "?view=users&record=" + user_id)
        expect(page.get_by_role("alert").filter(has_text="No other user was substituted.")).to_be_visible()
        assert not any(path.endswith(user_id) for _, path, _ in api.requests)
        if shots:
            page.screenshot(path=str(shots / "ux12-exact-viewer-boundary-1440.png"))
        context.close()
    finally:
        RemediationAPI.read = original
        del RemediationAPI.route
    return "exact and missing revision URLs survive reload/Back and viewer user link makes no request"


CHECKS = {"UX-12": check_ux12, "UX-22": check_ux22, "UX-08": check_ux08, "UX-17": check_ux17, "UX-21": check_ux21, "UX-05": check_ux05, "UX-10": check_ux10, "UX-01": check_ux01, "UX-03": check_ux03, "UX-04": check_ux04, "UX-06": check_ux06, "UX-16": check_ux16,
          "UX-09": check_ux09, "UX-11": check_ux11, "UX-19": check_ux19}
CHECKS = {key: value for key, value in CHECKS.items() if value}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("dist", type=Path)
    parser.add_argument("--chrome", type=Path, required=True)
    parser.add_argument("--screenshots", type=Path)
    parser.add_argument("--only", default="")
    args = parser.parse_args()
    smoke.MockAPI = RemediationAPI
    selected = [item for item in args.only.split(",") if item] or list(CHECKS)
    if args.screenshots:
        args.screenshots.mkdir(parents=True, exist_ok=True)
    server = smoke.serve(args.dist)
    failures = 0
    try:
        with sync_playwright() as playwright:
            browser = playwright.chromium.launch(executable_path=str(args.chrome), headless=True)
            for issue in selected:
                try:
                    print("PASS " + issue + ": " + CHECKS[issue](browser, server, args.screenshots))
                except Exception as exc:  # report every issue, then fail
                    failures += 1
                    print("FAIL " + issue + ": " + " | ".join(str(exc).splitlines()[:6])[:900])
            browser.close()
    finally:
        server.shutdown()
        server.server_close()
    raise SystemExit(1 if failures else 0)


if __name__ == "__main__":
    main()
