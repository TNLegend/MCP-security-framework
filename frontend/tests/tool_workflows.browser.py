"""Browser checks for Inventory, Security Review and Code Scans using intercepted API data."""

import argparse
import json
from pathlib import Path

from playwright.sync_api import expect, sync_playwright

from gui_browser_smoke import DIGEST, STAMP, check_width, navigate, open_page, serve

BUILD = "/control-plane/build-security/scans"
SCAN_A = {"id": "slow", "display_name": "A old scan", "status": "COMPLETED",
          "target_type": "LOCAL_DIRECTORY", "created_at": STAMP, "source_fingerprint": DIGEST}
SCAN_B = {"id": "retry", "display_name": "B recent scan", "status": "FAILED",
          "target_type": "GIT_REPOSITORY", "created_at": "2026-11-21T10:30:00Z",
          "source_fingerprint": DIGEST}
SCAN_C = {"id": "created", "display_name": "Fixture repository", "status": "COMPLETED",
          "target_type": "GIT_REPOSITORY", "created_at": "2026-11-21T11:30:00Z",
          "source_fingerprint": "b" * 64, "source_revision": "c" * 64}


def exercise_inventory(page, api, width):
    navigate(page, "MCP tools", width)
    search = page.get_by_role("searchbox", name="Search tools on the selected server")
    search.fill("missing")
    expect(page.get_by_text("No tools match this search.")).to_be_visible()
    page.get_by_role("button", name="Clear tool search").click()
    selection = page.get_by_role("button", name="Read documents", exact=True)
    expect(selection).to_be_visible()
    selection.focus()
    selection.press("Enter")
    expect(selection).to_have_attribute("aria-pressed", "true")
    page.get_by_role("button", name="Revoke trust", exact=True).click()
    dialog = page.get_by_role("dialog", name="Revoke MCP Server Trust")
    expect(dialog).to_be_visible()
    expect(dialog.get_by_role("textbox", name="Reason")).to_be_focused()
    dialog.get_by_role("textbox", name="Reason").press("Shift+Tab")
    expect(dialog.get_by_role("button", name="Cancel")).to_be_focused()
    page.keyboard.press("Escape")
    expect(dialog).to_have_count(0)
    expect(page.get_by_role("button", name="Revoke trust", exact=True)).to_be_focused()
    assert api.mutations == [], api.mutations
    rediscovery = []

    def discover(route):
        rediscovery.append(route.request.method)
        route.fulfill(json={"total_tools_imported": 1, "tools_quarantined": 1})

    page.route("**/api/v1/inventory/servers/1/discover", discover)
    page.get_by_role("button", name="Discover tools", exact=True).click()
    expect(page.get_by_role("status").filter(has_text="Imported 1 tool(s); 1 require review.")).to_be_visible()
    assert rediscovery == ["POST"]
    check_width(page, "Inventory search and dialog")
    page.get_by_role("button", name="Open security review", exact=True).click()
    expect(page.locator("#review-selected-tool")).to_have_text("Read documents")
    assert "view=analysis" in page.url


def exercise_review(page, api, width):
    navigate(page, "Security review", width)
    expect(page.get_by_role("tab", name="Summary")).to_have_attribute("aria-selected", "true")
    page.get_by_role("tab", name="Summary").press("ArrowRight")
    expect(page.get_by_role("tab", name="Description check")).to_have_attribute("aria-selected", "true")
    page.get_by_role("tab", name="Description check").press("End")
    expect(page.get_by_role("tab", name="Technical details")).to_have_attribute("aria-selected", "true")
    page.get_by_role("button", name="Block tool", exact=True).click()
    dialog = page.get_by_role("dialog", name="Block tool")
    dialog.get_by_role("textbox").fill("Browser test of denied evidence review.")
    dialog.get_by_role("button", name="Confirm block", exact=True).click()
    expect(dialog.get_by_role("alert")).to_contain_text(
        "The record changed or conflicts with the current operation. Refresh its status before proceeding."
    )
    assert api.mutations[-1][1] == "/control-plane/tool-analysis/tools/1/block"
    assert DIGEST in api.mutations[-1][2]
    dialog.get_by_role("button", name="Cancel").click()
    check_width(page, "Review tabs and modal errors")


def exercise_build(page, width):
    slow_routes = []
    attempts = []
    submitted_scans = []

    def scans(route):
        route.fulfill(json=[SCAN_A, SCAN_B, SCAN_C] if submitted_scans else [SCAN_A, SCAN_B])

    def create_scan(route):
        assert route.request.method == "POST"
        submitted_scans.append(json.loads(route.request.post_data))
        route.fulfill(json=SCAN_C)

    def retry_scan(route):
        attempts.append(route.request.url)
        if len(attempts) == 1:
            route.fulfill(status=503, json={"detail": "Scan evidence is temporarily unavailable."})
        else:
            route.fulfill(json={"scan": SCAN_B, "scanner_runs": [], "findings": []})

    page.route("**/api/v1" + BUILD + "?*", scans)
    page.route("**/api/v1" + BUILD + "/slow", lambda route: slow_routes.append(route))
    page.route("**/api/v1" + BUILD + "/retry", retry_scan)
    page.route("**/api/v1" + BUILD + "/git", create_scan)
    page.route("**/api/v1" + BUILD + "/created",
               lambda route: route.fulfill(json={"scan": SCAN_C, "scanner_runs": [], "findings": []}))
    navigate(page, "Code scans", width)
    page.get_by_role("combobox", name="Filter Build scans by status").select_option("FAILED")
    expect(page.get_by_role("button", name="A old scan")).to_have_count(0)
    page.get_by_role("button", name="Clear filters").click()
    page.get_by_role("combobox", name="Sort Build scans").select_option("OLDEST")
    rows = page.get_by_role("region", name="Build scan history table").get_by_role("row")
    expect(rows.nth(1)).to_contain_text("A old scan")
    page.get_by_role("button", name="A old scan").press("Enter")
    expect(page.get_by_text("Loading Build scan evidence…")).to_be_visible()
    page.get_by_role("button", name="B recent scan").click()
    evidence = page.locator("#build-evidence")
    expect(evidence.get_by_role("alert")).to_contain_text("A server or upstream service failed.")
    evidence.get_by_role("button", name="Retry loading scan evidence").click()
    expect(evidence.get_by_text("B recent scan", exact=False)).to_be_visible()
    assert len(slow_routes) == 1
    slow_routes[0].fulfill(json={"scan": SCAN_A, "scanner_runs": [], "findings": []})
    page.wait_for_timeout(200)
    expect(evidence.get_by_text("B recent scan", exact=False)).to_be_visible()
    assert len(attempts) == 2
    page.get_by_role("button", name="Git repository", exact=True).click()
    page.get_by_role("textbox", name="Repository HTTPS URL").fill("https://github.com/example/mcp.git")
    page.get_by_role("textbox", name="Display name").fill(SCAN_C["display_name"])
    page.get_by_role("button", name="Fetch immutable revision and scan").click()
    expect(page.get_by_role("status").filter(has_text="Scan request recorded. Status:")).to_be_visible()
    expect(evidence.get_by_text(SCAN_C["display_name"], exact=False)).to_be_visible()
    assert len(submitted_scans) == 1
    assert submitted_scans[0]["repository_url"] == "https://github.com/example/mcp.git"
    assert submitted_scans[0]["source_ref"] == "HEAD"
    for viewport in (width, 320) if width < 768 else (width,):
        page.set_viewport_size({"width": viewport, "height": 940})
        check_width(page, "Build history and scan evidence")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("dist", type=Path)
    parser.add_argument("--chrome", required=True)
    args = parser.parse_args()
    server = serve(args.dist)
    try:
        with sync_playwright() as playwright:
            browser = playwright.chromium.launch(executable_path=args.chrome, headless=True)
            for width in (390, 1440):
                context, page, api, errors = open_page(browser, server, "ADMIN", width)
                page.set_default_timeout(4500)
                exercise_inventory(page, api, width)
                exercise_review(page, api, width)
                exercise_build(page, width)
                assert not errors, errors
                print(f"PASS ADMIN {width}px: inventory, review, scan history")
                context.close()

            context, page, api, errors = open_page(browser, server, "VIEWER", 768)
            navigate(page, "MCP tools", 768)
            expect(page.get_by_text("Add or connect an MCP server")).to_have_count(0)
            expect(page.get_by_role("button", name="Archive", exact=True)).to_have_count(0)
            navigate(page, "Security review", 768)
            expect(page.get_by_role("tab", name="Description check")).to_have_count(0)
            expect(page.get_by_role("button", name="Block tool", exact=True)).to_have_count(0)
            navigate(page, "Code scans", 768)
            expect(page.get_by_role("heading", name="New scan", exact=True)).to_have_count(0)
            expect(page.get_by_role("heading", name="Scan evidence", exact=True)).to_be_visible()
            assert not api.mutations, api.mutations
            assert not errors, errors
            print("PASS VIEWER 768px: inspection remains available, privileged controls are absent")
            context.close()
    finally:
        server.shutdown()
        server.server_close()


if __name__ == "__main__":
    main()
