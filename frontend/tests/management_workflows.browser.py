
"""Exercise security administration with an intercepted API and local build."""
import argparse
import json
from pathlib import Path
from urllib.parse import urlsplit

from playwright.sync_api import expect, sync_playwright

import gui_browser_smoke as smoke

REVISION = {"id": "active", "revision_number": 1, "schema_version": 2, "status": "PUBLISHED",
            "content_hash": "a" * 64, "signature": "f" * 144, "content": {}}
DRAFT = {"id": "draft", "revision_number": 2, "schema_version": 2, "status": "DRAFT",
         "content_hash": "b" * 64, "content": {"policy_settings": {"rules": {}}}}
VIEWER = {"id": "reader", "username": "reader", "display_name": "Incident observer",
          "role": "VIEWER", "enabled": False}
BLOCK = {"id": "block-agent", "target_type": "agent_id", "target_value": "qa-agent",
         "reason": "Browser fixture", "created_at": smoke.STAMP, "expires_at": "2030-01-01T00:00:00Z"}
DENIES = "/control-plane/emergency-denies"
CLEANUP = "/control-plane/operations/runtime-logs/cleanup"


class ManagementAPI(smoke.MockAPI):
    def __init__(self, role):
        super().__init__(role)
        self.blocks = [BLOCK]
        self.draft = DRAFT

    def read(self, path, query):
        if path == "/control-plane/config/revisions":
            return [self.draft, REVISION]
        if path == "/control-plane/config/active":
            return REVISION
        if path == "/control-plane/users":
            return [self.user, VIEWER]
        if path == DENIES:
            return self.blocks
        return super().read(path, query)

    def route(self, route):
        path = urlsplit(route.request.url).path.removeprefix("/api/v1")
        method = route.request.method
        if path == DENIES and method == "POST":
            body = json.loads(route.request.post_data)
            assert body["target_type"] == "global"
            self.mutations.append((method, path, body))
            record = {**body, "id": "block-global", "created_at": smoke.STAMP}
            self.blocks = [*self.blocks, record]
            route.fulfill(status=201, json=record)
        elif path.startswith(DENIES + "/") and method == "DELETE":
            self.mutations.append((method, path, None))
            self.blocks = [item for item in self.blocks if not path.endswith("/" + item["id"])]
            route.fulfill(status=200, json={})
        else:
            super().route(route)


def users(page):
    smoke.navigate(page, "Users", 1280)
    page.get_by_role("searchbox", name="Find an account").fill("incident observer")
    expect(page.get_by_text("1 of 2 accounts")).to_be_visible()
    expect(page.get_by_role("row").filter(has_text="reader")).to_be_visible()
    page.get_by_label("Filter by role").select_option("ADMIN")
    expect(page.get_by_text("No accounts match these filters.")).to_be_visible()
    page.get_by_role("button", name="Clear filters").click()
    page.get_by_role("row").filter(has_text="qa-admin").get_by_text("Manage account").click()
    expect(page.get_by_role("button", name="Make VIEWER")).to_be_disabled()
    expect(page.get_by_role("button", name="Disable", exact=True)).to_be_disabled()
    page.get_by_role("button", name="Reset Password").click()
    expect(page.get_by_role("dialog", name="Reset Password")).to_be_visible()
    page.keyboard.press("Escape")
    expect(page.get_by_role("dialog", name="Reset Password")).to_have_count(0)


def emergency(page, api):
    smoke.navigate(page, "Emergency block", 1280)
    page.get_by_label("Filter by scope").select_option("server_tool")
    expect(page.get_by_text("No block records match this scope.")).to_be_visible()
    page.get_by_label("Filter by scope").select_option("")
    page.get_by_role("button", name="Review block").click()
    expect(page.get_by_role("dialog", name="Confirm emergency block")).to_contain_text("All governed MCP calls")
    page.get_by_role("button", name="Cancel", exact=True).click()
    assert not any(path == DENIES for _, path, _ in api.mutations)
    page.get_by_role("button", name="Review block").click()
    page.get_by_role("button", name="Activate block").click()
    expect(page.get_by_text("Emergency Deny created.")).to_be_visible()
    page.get_by_label("Filter by scope").select_option("global")
    page.once("dialog", lambda dialog: dialog.accept())
    page.get_by_role("button", name="Revoke", exact=True).click()
    expect(page.get_by_text("Emergency Deny revoked.")).to_be_visible()
    expect(page.get_by_text("No block records match this scope.")).to_be_visible()


def rules(page, api):
    smoke.navigate(page, "Security rules", 1280)
    page.get_by_role("button", name="#2", exact=True).click()
    page.get_by_role("tab", name="Advanced JSON").click()
    editor = page.get_by_label("Complete revision JSON")
    edited = '{"policy_settings":{"rules":{}},"test_note":"draft edit"}'
    editor.fill(edited)
    expect(page.get_by_text("Unsaved changes", exact=True)).to_be_visible()
    page.get_by_role("button", name="Refresh", exact=True).click()
    expect(page.get_by_role("button", name="Refresh", exact=True)).to_be_enabled()
    expect(editor).to_have_value(edited)
    page.once("dialog", lambda dialog: dialog.dismiss())
    page.get_by_role("button", name="#1", exact=True).click()
    expect(editor).to_have_value(edited)
    api.draft = {**DRAFT, "content_hash": "c" * 64, "content": {"test_note": "remote edit"}}
    page.get_by_role("button", name="Refresh", exact=True).click()
    expect(page.get_by_text("This draft changed on the server", exact=False)).to_be_visible()
    expect(page.get_by_role("button", name="Save Draft")).to_be_disabled()
    expect(editor).to_have_value(edited)
    page.once("dialog", lambda dialog: dialog.accept())
    page.get_by_role("button", name="Load updated draft").click()
    expect(editor).to_have_value(json.dumps(api.draft["content"], indent=2))
    page.get_by_role("button", name="#1", exact=True).click()
    expect(editor).to_have_attribute("readonly", "")


def operations(page, api):
    smoke.navigate(page, "System health", 1280)
    apply = page.get_by_role("button", name="Apply bounded cleanup")
    preview = page.get_by_role("button", name="Preview cleanup")
    expect(apply).to_be_disabled()
    preview.click()
    expect(apply).to_be_enabled()
    page.get_by_label("Maintenance reason").fill("Revised reason for retention test")
    expect(apply).to_be_disabled()
    preview.click()
    expect(apply).to_be_enabled()
    page.once("dialog", lambda dialog: dialog.dismiss())
    apply.click()
    requests = [json.loads(data) for _, path, data in api.mutations if path == CLEANUP]
    assert requests and all(item["dry_run"] for item in requests)
    page.once("dialog", lambda dialog: dialog.accept())
    apply.click()
    expect(page.get_by_text("Retention applied", exact=False)).to_be_visible()
    expect(apply).to_be_disabled()
    requests = [json.loads(data) for _, path, data in api.mutations if path == CLEANUP]
    assert requests[-1] == {"dry_run": False, "reason": "Revised reason for retention test"}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("dist", type=Path)
    parser.add_argument("--chrome", type=Path, required=True)
    args = parser.parse_args()
    smoke.MockAPI = ManagementAPI
    server = smoke.serve(args.dist)
    try:
        with sync_playwright() as playwright:
            browser = playwright.chromium.launch(executable_path=str(args.chrome), headless=True)
            context, page, api, errors = smoke.open_page(browser, server, "ADMIN", 1280)
            for check in (users, emergency, rules, operations):
                check(page) if check is users else check(page, api)
                print("PASS ADMIN " + check.__name__)
            assert not errors, errors
            context.close()
            context, page, api, errors = smoke.open_page(browser, server, "VIEWER", 390)
            smoke.navigate(page, "Emergency block", 390)
            expect(page.get_by_role("button", name="Review block")).to_have_count(0)
            expect(page.get_by_role("button", name="Revoke")).to_have_count(0)
            smoke.navigate(page, "System health", 390)
            expect(page.get_by_role("button", name="Preview cleanup")).to_have_count(0)
            smoke.navigate(page, "Security rules", 390)
            page.get_by_role("tab", name="Advanced JSON").click()
            expect(page.get_by_label("Complete revision JSON")).to_have_attribute("readonly", "")
            expect(page.get_by_role("button", name="Publish", exact=True)).to_have_count(0)
            assert not api.mutations and not errors, (api.mutations, errors)
            print("PASS VIEWER emergency, system health and configuration boundaries")
            context.close()
            browser.close()
    finally:
        server.shutdown()
        server.server_close()


if __name__ == "__main__":
    main()
