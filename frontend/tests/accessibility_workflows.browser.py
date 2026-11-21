"""Keyboard, navigation and session recovery with the browser's real accessibility tree."""
import argparse
import re
from pathlib import Path
from urllib.parse import urlsplit

from playwright.sync_api import expect, sync_playwright

import gui_browser_smoke as smoke


def run(browser, server, role, width):
    context, page, api, errors = smoke.open_page(browser, server, role, width, signed_in=False)
    login_responses = {"status": 200, "expire_next_read": False, "fail_me": False}

    def intercept(route):
        path = urlsplit(route.request.url).path.removeprefix("/api/v1")
        if path == "/control-plane/auth/login" and login_responses["status"] != 200:
            return route.fulfill(status=login_responses["status"],
                                 json={"detail": "Fixture authentication diagnostic."})
        if path == "/control-plane/auth/change-password":
            return route.fulfill(status=401, json={"detail": "Invalid password"})
        if path == "/control-plane/auth/me" and login_responses["fail_me"]:
            return route.abort()
        if path == "/control-plane/audit/events/page" and login_responses["expire_next_read"]:
            return route.fulfill(status=401, json={"detail": "Invalid session"})
        return route.fallback()

    page.route("**/api/v1/**", intercept)
    try:
        expect(page.get_by_role("heading", name="Sign in")).to_be_focused()
        page.keyboard.press("Tab")
        expect(page.get_by_role("textbox", name="Username")).to_be_focused()
        page.get_by_label("Username").fill("qa-operator")
        for status, message in ((401, "Invalid username or password"),
                                (429, "Too many sign-in attempts"),
                                (503, "Check your connection and try again")):
            login_responses["status"] = status
            page.get_by_label("Password", exact=True).fill("synthetic-password")
            page.keyboard.press("Enter")
            expect(page.get_by_role("alert")).to_contain_text(message)
            expect(page.get_by_label("Password", exact=True)).to_be_focused()
            expect(page.get_by_label("Password", exact=True)).to_have_value("")

        login_responses["status"] = 200
        page.get_by_label("Password", exact=True).fill("synthetic-password")
        page.keyboard.press("Enter")
        expect(page.get_by_role("main", name="Home")).to_be_focused()

        # Skip activation leaves the URL and its history untouched.
        page.wait_for_function("!!document.querySelector('.skip-navigation')")
        before = page.url
        page.locator(".skip-navigation").focus()
        assert page.locator(".skip-navigation").evaluate("node => node.matches(':focus-visible')")
        page.keyboard.press("Enter")
        expect(page.get_by_role("main", name="Home")).to_be_focused()
        assert page.url == before

        nav = page.get_by_role("navigation", name="Main navigation")
        if width <= 760:
            toggle = page.get_by_role("button", name="Open navigation menu")
            toggle.focus()
            page.keyboard.press("Enter")
            expect(nav).to_be_visible()
            page.keyboard.press("Escape")
            expect(nav).to_be_hidden()
            expect(toggle).to_be_focused()

        smoke.navigate(page, "MCP tools", width)
        expect(page.get_by_role("main", name="MCP tools")).to_be_focused()
        expect(page).to_have_title(re.compile(r"^MCP tools ·"))
        if width > 760:
            expect(nav.get_by_role("link", name="MCP tools")).to_have_attribute("aria-current", "page")
        smoke.navigate(page, "Security review", width)
        expect(page.get_by_role("main", name="Security review")).to_be_focused()
        page.go_back()
        expect(page.get_by_role("main", name="MCP tools")).to_be_focused()
        page.go_forward()
        expect(page.get_by_role("main", name="Security review")).to_be_focused()

        my_account = page.get_by_role("button", name="My account")
        my_account.focus()
        page.keyboard.press("Enter")
        modal = page.get_by_role("dialog", name="Change your password")
        expect(modal).to_be_focused()
        expect(page.locator(".console-header")).to_have_attribute("inert", "")
        page.get_by_role("button", name="Sign out").evaluate("button => button.focus()")
        expect(modal).to_be_focused()
        cdp = context.new_cdp_session(page)
        tree = cdp.send("Accessibility.getFullAXTree")
        assert not any(node.get("name", {}).get("value") == "Sign out" and not node["ignored"]
                       for node in tree["nodes"])
        cdp.detach()
        page.keyboard.press("Shift+Tab")
        expect(modal.get_by_role("button", name="Cancel")).to_be_focused()
        page.keyboard.press("Tab")
        expect(modal.get_by_label("Current password")).to_be_focused()
        modal.get_by_label("Current password").fill("synthetic-wrong-password")
        modal.get_by_label("New password", exact=True).fill("synthetic-new-password")
        modal.get_by_label("Confirm new password").fill("synthetic-new-password")
        modal.get_by_role("button", name="Update password and revoke sessions").click()
        expect(modal.get_by_role("alert")).to_contain_text("The current password is incorrect")
        page.keyboard.press("Escape")
        expect(modal).to_have_count(0)
        expect(my_account).to_be_focused()

        # A temporary transport problem preserves the existing session view.
        login_responses["fail_me"] = True
        page.get_by_role("button", name="Refresh", exact=True).click()
        expect(page.get_by_role("alert")).to_contain_text("could not verify your session")
        expect(page.get_by_role("main", name="Security review")).to_be_visible()
        page.reload(wait_until="domcontentloaded")
        expect(page.get_by_role("alert")).to_contain_text("could not verify your session")
        expect(page.get_by_role("heading", name="Sign in")).to_be_focused()
        login_responses["fail_me"] = False
        page.get_by_role("button", name="Retry session check").click()
        expect(page.get_by_role("main", name="Security review")).to_be_focused()

        # An authenticated in-page read can detect expiry without a global refresh.
        login_responses["expire_next_read"] = True
        if width <= 760:
            page.get_by_role("button", name="Open navigation menu").click()
        nav.get_by_role("link", name="Audit history").click()
        expect(page.get_by_role("alert")).to_contain_text("Your session expired or was revoked")
        expect(page.get_by_role("heading", name="Sign in")).to_be_focused()
        login_responses["expire_next_read"] = False
        page.get_by_label("Username").fill("qa-operator")
        page.get_by_label("Password", exact=True).fill("synthetic-password")
        page.get_by_role("button", name="Sign in").click()
        expect(page.get_by_role("main", name="Audit history")).to_be_focused()

        if role == "VIEWER":
            page.goto(page.url.split("?")[0] + "?view=users")
            expect(page.get_by_role("main", name="Home")).to_be_visible()
            assert not any(path == "/control-plane/users" for _, path, _ in api.requests)
        page.get_by_role("button", name="Sign out").click()
        expect(page.get_by_role("status")).to_contain_text("You signed out")
        expect(page.get_by_role("heading", name="Sign in")).to_be_focused()
        assert not errors, errors
    finally:
        context.close()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("dist", type=Path)
    parser.add_argument("--chrome", type=Path, required=True)
    args = parser.parse_args()
    server = smoke.serve(args.dist)
    try:
        with sync_playwright() as playwright:
            browser = playwright.chromium.launch(executable_path=str(args.chrome), headless=True)
            for role, width in (("ADMIN", 1280), ("VIEWER", 390)):
                run(browser, server, role, width)
                print(f"PASS {role} {width}: keyboard, navigation, account dialog and session recovery")
    finally:
        server.shutdown()


if __name__ == "__main__":
    main()
