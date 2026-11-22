"""Browser acceptance checks for the UX-01..UX-23 remediation register.

All API traffic is intercepted locally with synthetic fixtures (no live
services, accounts or provider calls). Each check is named by issue ID.

Usage: python ux_remediation.browser.py <dist> --chrome <chrome.exe> [--screenshots DIR] [--only UX-03,...]
"""
import argparse
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


def check_ux19(browser, server, shots):
    """UX-19 (+UX-22/23 history text): execution, findings and coverage are separate;
    findings lead the detail; a failed run reads Coverage unavailable."""
    scans, details = prowler_fixture()
    original = RemediationAPI.read

    def read(self, path, query):
        if path == smoke.CLOUD + "/scans":
            return scans
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


CHECKS = {"UX-01": check_ux01, "UX-03": check_ux03, "UX-04": check_ux04, "UX-06": check_ux06, "UX-19": check_ux19}
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
