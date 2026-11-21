"""Browser regression for a built GUI. All API traffic is intercepted locally."""
import argparse
import functools
import json
import re
import threading
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

from playwright.sync_api import expect, sync_playwright


VIEWS = {
    "Home": "Security overview",
    "MCP tools": "MCP tools",
    "Security review": "Security review",
    "Code scans": "Code scans",
    "Cloud security": "Cloud security",
    "Security rules": "Security rules",
    "Emergency block": "Emergency block",
    "Tool activity": "Tool activity",
    "System health": "System health",
    "Audit history": "Audit history",
    "Users": "Users",
}
STAMP = "2026-11-21T09:30:00Z"
DIGEST = "a" * 64
SERVER = {"id": 1, "name": "Documentation MCP", "server_type": "mcp", "status": "active",
          "transport": "streamable_http", "trust_status": "trusted",
          "security_status": "review_required", "endpoint": "https://mcp.example.invalid/very/" + "long-segment-" * 12}
TOOL = {"id": 1, "server_id": 1, "name": "read_documents", "title": "Read documents", "status": "active",
        "description": "Read a document and return its content.", "analysis_status": "REVIEW_REQUIRED",
        "review_status": "REVIEW_REQUIRED", "risk_level": "medium", "risk_score": 35,
        "current_fingerprint": DIGEST, "input_schema": {"type": "object", "properties": {"key": {"type": "string"}}}}
ANALYSIS = {"id": 1, "tool_id": 1, "fingerprint": DIGEST, "analysis_status": "REVIEW_REQUIRED",
            "review_status": "REVIEW_REQUIRED", "risk_score": 35, "risk_level": "medium",
            "drift_status": "UNKNOWN", "consistency_status": "consistent", "completed_at": STAMP,
            "analysis_context_hash": DIGEST, "semantic_scores": {}, "drift_result": {"changes": []}}
AUDIT = {"id": 3, "timestamp": STAMP, "action": "UPDATE_CONFIGURATION", "result": "SUCCESS",
         "actor_username_snapshot": "qa-admin", "target_type": "configuration", "target_id": DIGEST,
         "reason": "Change the approved deployment scope.", "before_json": {"scope": "one"}, "after_json": {"scope": "two"}}
EVENT = {"id": 1, "timestamp": STAMP, "tool_name": "read_documents", "agent_id": "qa-reader",
         "decision": "BLOCK", "execution_status": "blocked", "reason": "Resource scope incomplete"}
SCANS = [{"id": name, "environment_id": "env-qa" if kind != "IAC_CONFIG" else None,
          "kind": kind, "status": status, "created_at": STAMP, "started_at": STAMP,
          "completed_at": STAMP, "finding_count": 1, "resource_count": 1, "unknown_checks": 2}
         for name, kind, status in [("baseline", "AWS_BASELINE", "COMPLETED"), ("advanced", "AWS_ADVANCED", "PARTIAL"),
                                    ("iam", "IAM_MCP", "PARTIAL"), ("terraform", "IAC_CONFIG", "FAILED")]]
CLOUD = "/control-plane/cloud-security"


class MockAPI:
    def __init__(self, role):
        self.role = role
        self.requests = []
        self.mutations = []
        self.fail = set()
        self.reject_login_once = False

    @property
    def user(self):
        return {"id": "qa-" + self.role.lower(), "username": "qa-" + self.role.lower(),
                "display_name": "QA operator", "role": self.role, "enabled": True}

    def route(self, route):
        url = urlsplit(route.request.url)
        if not url.path.startswith("/api/v1/"):
            if url.hostname == "127.0.0.1" and url.port == self.port:
                return route.continue_()
            return route.abort()
        path = url.path.removeprefix("/api/v1")
        method = route.request.method
        status = 200
        headers = {}
        self.requests.append((method, path, parse_qs(url.query)))
        if method != "GET":
            self.mutations.append((method, path, route.request.post_data))
        if path in self.fail:
            payload, status = {"detail": "The requested data is unavailable."}, 503
        elif path == "/control-plane/auth/login":
            if self.reject_login_once:
                self.reject_login_once = False
                payload, status = {"detail": "Invalid username or password."}, 401
            else:
                payload = {"user": self.user, "csrf_token": "qa-csrf"}
                headers["Set-Cookie"] = "mcp_control_plane_csrf=qa-csrf; Path=/"
        elif path == "/control-plane/auth/logout":
            payload = {}
            headers["Set-Cookie"] = "mcp_control_plane_csrf=; Path=/; Max-Age=0"
        elif path.endswith("/cleanup") and method == "POST":
            cleanup = json.loads(route.request.post_data)
            if cleanup["dry_run"]:
                payload = {"planned": 2, "deleted": 0, "preview_fingerprint": DIGEST}
            elif cleanup.get("expected_preview_fingerprint") == DIGEST:
                payload = {"planned": 2, "deleted": 2}
            else:
                payload, status = {"detail": "Preview no longer matches the candidate rows."}, 409
        elif method != "GET":
            payload, status = {"detail": "This mutation is outside the browser fixture."}, 409
        else:
            payload = self.read(path, parse_qs(url.query))
        route.fulfill(status=status, json=payload, headers=headers)

    def read(self, path, query):
        fixed = {
            "/control-plane/auth/me": self.user,
            "/health": {"status": "healthy"},
            "/control-plane/local-runtime/status": {"gateway": {"status": "ok"}, "database": {"status": "ok"}, "opa": {"status": "ok"}},
            "/control-plane/operations/summary": {"ready": True, "generated_at": STAMP, "components": {"gateway": {"status": "ok"}}},
            "/servers": [SERVER], "/tools": [TOOL], "/policies": [],
            "/control-plane/tool-analysis/analyses": [ANALYSIS],
            "/control-plane/config/revisions": [], "/control-plane/config/active": None,
            "/control-plane/emergency-denies": [],
            "/control-plane/audit/events": [AUDIT],
            "/control-plane/audit/events/page": {"items": [AUDIT], "total": 1},
            "/control-plane/users": [self.user],
            "/control-plane/security-packs": {"packs": []},
            "/control-plane/build-security/scanners": [],
            "/runtime/logs": {"items": [EVENT], "summary": {"total": 1, "allowed": 0, "blocked": 1, "executed": 0, "skipped": 1, "errors": 0}},
            CLOUD + "/environments": [{"id": "env-qa", "name": "QA AWS environment", "provider": "AWS",
                "status": "CONNECTED", "regions": ["eu-west-3"], "services": ["S3", "EC2", "IAM"],
                "account_id": "123456789012", "role_arn": "arn:aws:iam::123456789012:role/QAAudit"}],
            CLOUD + "/scans": SCANS,
            CLOUD + "/advanced/scanner": {"available": True, "version": "qa"},
            CLOUD + "/iac/scanners": [{"name": "Checkov", "available": True}, {"name": "Trivy", "available": False}],
        }
        if path in fixed:
            return fixed[path]
        if path.startswith(CLOUD + "/scans/"):
            scan_id, _, suffix = path.removeprefix(CLOUD + "/scans/").partition("/")
            if suffix == "":
                scan = next(item for item in SCANS if item["id"] == scan_id)
                return {"scan": scan, "resources": [], "events": [{"id": "event", "created_at": STAMP, "message_code": "SCAN_COMPLETED"}],
                        "findings": [{"id": "finding", "rule_id": "TEST-IAM", "title": "Check IAM resource scope", "severity": "HIGH",
                                      "description": "The evidence is incomplete.", "remediation": "Review the evidence."}],
                        "evidence": [{"id": "evidence", "evidence_sha256": DIGEST, "outcome": "UNKNOWN", "rule_id": "TEST-IAM"}]}
        if path.startswith("/tool-analysis/tools/1"):
            suffix = path.rsplit("/", 1)[-1]
            if suffix == "analyses":
                return [ANALYSIS]
            if suffix == "status":
                return {"analysis_status": "REVIEW_REQUIRED", "review_status": "REVIEW_REQUIRED"}
            if suffix in {"diff", "baseline"}:
                return None
        return []


class QuietHandler(SimpleHTTPRequestHandler):
    def log_message(self, *_args):
        pass


def serve(directory):
    server = ThreadingHTTPServer(("127.0.0.1", 0), functools.partial(QuietHandler, directory=str(directory)))
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server


def open_page(browser, server, role, width, *, signed_in=True):
    api = MockAPI(role)
    api.port = server.server_port
    url = f"http://127.0.0.1:{api.port}"
    context = browser.new_context(viewport={"width": width, "height": 940})
    context.route("**/*", api.route)
    if signed_in:
        context.add_cookies([{"name": "mcp_control_plane_csrf", "value": "qa-csrf", "url": url}])
    page = context.new_page()
    errors = []
    page.on("pageerror", lambda error: errors.append(str(error)))
    page.goto(url, wait_until="domcontentloaded")
    return context, page, api, errors


def navigate(page, label, width):
    navigation = page.get_by_role("navigation", name="Main navigation")
    if width <= 600 or page.locator(".security-console").count() and width <= 760:
        page.get_by_role("button", name="Open navigation menu").click()
    navigation.get_by_role("link", name=label, exact=True).click()
    expect(page.get_by_role("heading", level=2, name=VIEWS[label], exact=True)).to_be_visible()


def check_width(page, label):
    actual = page.evaluate("({viewport: document.documentElement.clientWidth, content: document.documentElement.scrollWidth})")
    if actual["content"] > actual["viewport"] + 1:
        offenders = page.evaluate("""() => [...document.querySelectorAll('main *')].filter(e => {
          const r=e.getBoundingClientRect();
          return r.width && r.right>innerWidth+1 && !e.closest('.table-shell,.table-scroll,.table-wrap,pre');
        }).slice(0,8).map(e=>[e.tagName, String(e.className).slice(0,100)])""")
        raise AssertionError(f"{label}: document overflow {actual}, elements {offenders}")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("dist", type=Path)
    parser.add_argument("--baseline", type=Path)
    parser.add_argument("--screenshots", type=Path)
    parser.add_argument("--chrome", type=Path, required=True)
    args = parser.parse_args()
    server = serve(args.dist)
    baseline = serve(args.baseline) if args.baseline else None
    failures = []
    route_checks = 0
    if args.screenshots:
        args.screenshots.mkdir(parents=True, exist_ok=True)
    try:
        with sync_playwright() as playwright:
            browser = playwright.chromium.launch(executable_path=str(args.chrome), headless=True)
            for role in ("ADMIN", "VIEWER"):
                for width in (360, 390, 768, 1280, 1600):
                    context, page, api, errors = open_page(browser, server, role, width)
                    try:
                        expect(page.get_by_role("heading", name="Security overview")).to_be_visible()
                        for label in VIEWS:
                            if label == "Users" and role == "VIEWER":
                                expect(page.get_by_role("navigation", name="Main navigation").get_by_role("link", name="Users", exact=True)).to_have_count(0)
                                continue
                            try:
                                navigate(page, label, width)
                                page.wait_for_timeout(110)
                                check_width(page, f"{role} {width} {label}")
                                route_checks += 1
                                if args.screenshots and role == "ADMIN" and label in {"Home", "Cloud security"} and width in {390, 1280}:
                                    page.screenshot(path=args.screenshots / f"after-{label.lower().replace(' ', '-')}-{width}.png")
                            except Exception as exc:
                                failures.append(f"{role} {width} {label}: {exc}")
                        if errors:
                            failures.append(f"{role} {width} JavaScript errors: {errors}")
                        if api.mutations:
                            failures.append(f"{role} {width} navigation caused mutations: {api.mutations}")
                    finally:
                        context.close()

            context, page, api, errors = open_page(browser, server, "ADMIN", 1280, signed_in=False)
            try:
                page.get_by_label("Username").fill("qa-admin")
                page.get_by_label("Password").fill("synthetic-password")
                api.reject_login_once = True
                page.get_by_role("button", name="Sign in").click()
                expect(page.get_by_role("alert")).to_contain_text("Invalid username or password")
                expect(page.get_by_label("Password")).to_have_value("")
                page.get_by_label("Password").fill("synthetic-password")
                page.get_by_role("button", name="Sign in").click()
                expect(page.get_by_role("heading", name="Security overview")).to_be_visible()
                refresh = page.locator(".console-header").get_by_role("button", name="Refresh", exact=True)
                expect(refresh).to_be_enabled()
                api.fail.add("/tools")
                refresh.click()
                expect(page.get_by_role("alert")).to_contain_text("Tools")
                expect(page.locator(".dashboard-priority-card").filter(has_text="Tools to review")).to_contain_text("The latest data is unavailable")
                api.fail.remove("/tools")
                refresh.click()
                expect(page.get_by_role("alert")).to_have_count(0)
                expect(refresh).to_be_enabled()
                navigate(page, "Cloud security", 1280)
                page.reload()
                expect(page.get_by_role("heading", name="Cloud security", exact=True)).to_be_visible()
                tasks = page.get_by_role("navigation", name="Cloud security tasks")
                for task in tasks.get_by_role("button").all():
                    task.click()
                    check_width(page, f"Cloud task {task.inner_text()}")
                tasks.get_by_role("button", name="Audit history", exact=True).click()
                page.get_by_role("button", name=re.compile(r"View MCP permissions")).first.click()
                expect(page.get_by_text("HIGH: Check IAM resource scope", exact=True)).to_be_visible()
                expect(page.get_by_role("heading", level=4, name="MCP permissions Partial")).to_be_visible()
                expect(page.get_by_role("heading", name="Audit review")).to_be_focused()
                navigate(page, "Tool activity", 1280)
                page.get_by_label("Search", exact=True).fill("read_documents")
                page.get_by_role("button", name="Apply", exact=True).click()
                expect(page.get_by_role("heading", name="Runtime Events")).to_be_visible()
                expect(page.get_by_role("button", name="Apply", exact=True)).to_be_enabled()
                assert any(params.get("search") == ["read_documents"] for verb, path, params in api.requests if path == "/runtime/logs")
                api.fail.add("/runtime/logs")
                page.get_by_role("button", name="Apply", exact=True).click()
                expect(page.get_by_role("alert")).to_contain_text("Previous results are retained")
                expect(page.get_by_role("button", name=re.compile(r"^read_documents")).first).to_be_visible()
                api.fail.remove("/runtime/logs")
                navigate(page, "Audit history", 1280)
                page.get_by_placeholder("action, actor, target...").fill("configuration")
                page.wait_for_timeout(450)
                assert any(params.get("search") == ["configuration"] for verb, path, params in api.requests if path.endswith("/events/page"))
                page.go_back()
                expect(page.get_by_role("heading", name="Tool activity", exact=True)).to_be_visible()
                page.get_by_role("button", name="Sign out", exact=True).click()
                expect(page.get_by_role("heading", name="Sign in")).to_be_visible()
                if errors:
                    failures.append(f"Workflow JavaScript errors: {errors}")
                print("PASS login rejection and retry, sign out, deep link, Back, Cloud task controls and evidence, runtime filters, audit search")
            except Exception as exc:
                failures.append(f"ADMIN workflow: {exc}")
            finally:
                context.close()

            context, page, api, errors = open_page(browser, server, "VIEWER", 390)
            try:
                expect(page.get_by_role("heading", name="Security overview")).to_be_visible()
                page.keyboard.press("Tab")
                expect(page.get_by_role("link", name="Skip to content")).to_be_focused()
                menu = page.get_by_role("button", name="Open navigation menu")
                menu.click()
                page.keyboard.press("Escape")
                expect(menu).to_be_focused()
                expect(menu).to_have_attribute("aria-expanded", "false")
                api.fail.add(CLOUD + "/scans")
                navigate(page, "Cloud security", 390)
                expect(page.get_by_role("alert").first).to_be_visible()
                page.goto(page.url.split("?")[0] + "?view=users")
                expect(page.get_by_role("heading", name="Security overview")).to_be_visible()
                assert all(path != "/control-plane/users" for _, path, _ in api.requests)
                print("PASS keyboard skip/Escape, Cloud read failure, VIEWER deep-link guard")
            except Exception as exc:
                failures.append(f"VIEWER workflow: {exc}")
            finally:
                context.close()

            if baseline and args.screenshots:
                for width in (390, 1280):
                    context, page, _, _ = open_page(browser, baseline, "ADMIN", width)
                    for label in ("Home", "Cloud security"):
                        navigate(page, label, width)
                        page.wait_for_timeout(200)
                        page.screenshot(path=args.screenshots / f"before-{label.lower().replace(' ', '-')}-{width}.png")
                    context.close()
            browser.close()
    finally:
        server.shutdown()
        server.server_close()
        if baseline:
            baseline.shutdown()
            baseline.server_close()
    print(f"Verified {route_checks}/105 role, viewport and route combinations.")
    if failures:
        for failure in failures:
            print("FAIL", failure)
        raise SystemExit(1)


if __name__ == "__main__":
    main()
