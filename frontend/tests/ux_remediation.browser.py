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


CHECKS = {"UX-02": None, "UX-03": check_ux03, "UX-04": check_ux04, "UX-06": check_ux06}
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
                    print("FAIL " + issue + ": " + str(exc).splitlines()[0][:400])
            browser.close()
    finally:
        server.shutdown()
        server.server_close()
    raise SystemExit(1 if failures else 0)


if __name__ == "__main__":
    main()
