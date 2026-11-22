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


def runtime_event(event_id, decision="BLOCK", tool="read_documents"):
    return {**smoke.EVENT, "id": event_id, "decision": decision, "tool_name": tool,
            "operation_id": f"00000000-0000-4000-8000-{event_id:012d}"}


class RemediationAPI(smoke.MockAPI):
    def __init__(self, role):
        super().__init__(role)
        self.runtime_rows = [runtime_event(1)]

    def read(self, path, query):
        if path == RUNTIME:
            decision = (query.get("decision") or [""])[0]
            rows = [row for row in self.runtime_rows if not decision or row["decision"] == decision]
            return {"items": rows, "next_cursor": None, "has_more": False,
                    "summary": {"total": len(rows), "allowed": 0, "blocked": len(rows),
                                "executed": 0, "skipped": len(rows), "errors": 0}}
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


CHECKS = {"UX-03": check_ux03}


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
