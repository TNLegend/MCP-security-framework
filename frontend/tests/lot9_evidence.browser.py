"""Browser coverage for Lot 9 evidence presentation, using only local fixtures."""
import argparse
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

from gui_browser_smoke import AUDIT, CLOUD, EVENT, STAMP, navigate, open_page, serve
from playwright.sync_api import expect, sync_playwright


def check_evidence(browser, server, role, width):
    context, page, _api, errors = open_page(browser, server, role, width)
    original_id = "00000000-0000-0000-0000-000000000001"
    current_id = "00000000-0000-0000-0000-000000000002"
    pending = []
    counts = {"audit": 0, "iam": 0}
    scan = {"status": "COMPLETED", "target_type": "LOCAL_DIRECTORY", "created_at": STAMP}
    signed_record = {
        **EVENT, "created_at": STAMP, "decision": "BLOCK", "opa_decision": "ALLOW",
        "executed": False, "dispatch_state": "SENT_OUTCOME_UNKNOWN", "operation_id": original_id,
    }

    def intercept(route):
        url = urlsplit(route.request.url)
        path = url.path.removeprefix("/api/v1")
        if path == "/runtime/logs":
            route.fulfill(json={"items": [signed_record], "summary": {"total": 1}})
        elif path.startswith("/control-plane/audit/related/"):
            if path.endswith(original_id):
                pending.append(route)
            else:
                route.fulfill(json={"events": [], "limitations": "Current target evidence"})
        elif path == "/control-plane/audit/events/page":
            counts["audit"] += 1
            query = parse_qs(url.query)
            result = {"items": [AUDIT], "total": 1, "snapshot_at": STAMP, "snapshot_id": 3}
            if counts["audit"] > 1 and not query.get("snapshot_at"):
                result.update(items=[{**AUDIT, "reason": "Recently recorded event"}])
            route.fulfill(json=result)
        elif path == CLOUD + "/scans/iam/iam-comparisons/page":
            offset = int(parse_qs(url.query)["offset"][0])
            counts["iam"] += int(offset > 0)
            comparison_id = original_id if offset == 0 or counts["iam"] == 1 else current_id
            item = {"id": comparison_id, "tool_name": "test_tool", "expected_actions": [],
                    "observed_actions": [], "status": "POTENTIAL_EXCESS",
                    "effective_permission_status": "UNKNOWN"}
            route.fulfill(json={"items": [item], "offset": offset,
                                "total": 2, "returned": 1, "has_more": not offset})
        elif path == "/control-plane/build-security/scans":
            offset = int(parse_qs(url.query).get("offset", ["0"])[0])
            if offset == 500:
                route.fulfill(json=[{**scan, "id": "older-scan", "display_name": "Earlier scan"}])
            else:
                route.fulfill(json=[
                    {**scan, "id": f"scan-{i}", "display_name": "Recent scan"}
                    for i in range(500)
                ])
        else:
            route.fallback()

    page.route("**/api/v1/**", intercept)
    navigate(page, "Tool activity", width)
    event = page.get_by_role("row").filter(has_text="read_documents")
    expect(event).to_contain_text("Unknown — upstream effect possible")
    event.get_by_role("button").click()
    expect(page.get_by_label("Security decision explanation")).to_contain_text("Original OPA decision:")
    expect(page.get_by_label("Security decision explanation")).to_contain_text("Do not retry automatically")

    navigate(page, "Audit history", width)
    expect(page.get_by_text(AUDIT["reason"])).to_be_visible()
    page.get_by_role("button", name="Refresh results").click()
    expect(page.get_by_text("Recently recorded event")).to_be_visible()
    target = page.get_by_role("textbox", name="Recorded UUID")
    target.fill(original_id)
    page.get_by_role("button", name="Show related events").click()
    expect(page.get_by_role("button", name="Checking...")).to_be_visible()
    target.fill(current_id)
    page.get_by_role("button", name="Show related events").click()
    expect(page.get_by_text("Current target evidence")).to_be_visible()
    assert len(pending) == 1
    with page.expect_response(lambda response: response.url.endswith(original_id)):
        pending[0].fulfill(json={"events": [], "limitations": "Stale target evidence"})
    expect(page.get_by_text("Current target evidence")).to_be_visible()
    expect(page.get_by_text("Stale target evidence")).to_have_count(0)

    navigate(page, "Cloud security", width)
    tasks = page.get_by_role("navigation", name="Cloud security tasks")
    tasks.get_by_role("button", name="Audit history", exact=True).click()
    history = page.get_by_role("region", name="Cloud audit history")
    history.get_by_role("row").filter(has_text="MCP permission").get_by_role("button").click()
    expect(page.get_by_text("Showing 1 of 2 recorded comparisons.", exact=False)).to_be_visible()
    next_page = page.get_by_role("button", name="Load next 100 comparisons")
    next_page.click()
    expect(page.get_by_text("The next IAM comparison page could not be verified.", exact=False)).to_be_visible()
    expect(page.get_by_text("Showing 1 of 2 recorded comparisons.", exact=False)).to_be_visible()
    next_page.click()
    expect(page.get_by_text("Showing 2 of 2 recorded comparisons.", exact=False)).to_be_visible()
    navigate(page, "Code scans", width)
    expect(page.get_by_text("Filters apply to the 500 loaded scans.", exact=False)).to_be_visible()
    page.get_by_role("searchbox", name="Search Build scans").fill("Earlier scan")
    expect(page.get_by_text("No loaded Build scan matches the current filters.")).to_be_visible()
    page.get_by_role("button", name="Load older scans").click()
    expect(page.get_by_role("button", name="Earlier scan")).to_be_visible()
    assert not errors, errors
    context.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("dist", type=Path)
    parser.add_argument("--chrome", required=True)
    args = parser.parse_args()
    server = serve(args.dist)
    try:
        with sync_playwright() as playwright:
            browser = playwright.chromium.launch(executable_path=args.chrome, headless=True)
            for role, width in [("ADMIN", 1280), ("VIEWER", 390)]:
                check_evidence(browser, server, role, width)
            browser.close()
        print("Lot 9 evidence journeys passed for ADMIN (desktop) and VIEWER (mobile).")
    finally:
        server.shutdown()
        server.server_close()


if __name__ == "__main__":
    main()
