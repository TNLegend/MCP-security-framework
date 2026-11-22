"""Playwright regression for Cloud Security using intercepted API responses."""

import argparse
from io import BytesIO
from zipfile import ZipFile
from urllib.parse import parse_qs, urlsplit

from playwright.sync_api import expect, sync_playwright


SCAN_TIME = "2026-11-20T15:00:00Z"
PREFIX = "/control-plane/cloud-security"
ENVIRONMENT = {
    "id": "aws-a", "name": "Quality assurance", "status": "CONNECTED",
    "account_id": "123456789012", "regions": ["eu-west-3"],
    "services": ["EC2", "S3", "IAM"], "credential_mode": "SDK_DEFAULT",
    "role_arn": "arn:aws:iam::123456789012:role/QA",
}
SCANS = [
    {
        "id": scan_id, "kind": kind, "environment_id": environment,
        "status": status, "created_at": SCAN_TIME, "resource_count": 6,
        "source_file_count": 3, "finding_count": 1, "unknown_checks": 2,
    }
    for scan_id, kind, environment, status in [
        ("baseline", "AWS_BASELINE", "aws-a", "COMPLETED"),
        ("advanced", "AWS_ADVANCED", "aws-a", "PARTIAL"),
        ("iam", "IAM_MCP", "aws-a", "PARTIAL"),
        ("iac", "IAC_CONFIG", None, "FAILED"),
        ("other", "AWS_BASELINE", "aws-b", "COMPLETED"),
    ]
]
FINDING = {
    "id": "finding-a", "rule_id": "QA-1", "severity": "MEDIUM",
    "title": "Review bucket access", "description": "The fixture contains unknown checks.",
}
MCP_SERVER = {"id": 1, "name": "Fixture MCP", "status": "active", "endpoint": "https://example.invalid/mcp"}
SIGNED_CONTEXT = {
    "signed_revision": 8, "signed_content_hash": "c" * 64,
    "effects": [{
        "tool_name": "list_documents", "effect_id": "list-a",
        "resource_type": "bucket", "capability": "cloud.list",
    }],
    "scopes": [{"scope_id": "bucket-a", "resource_type": "bucket", "canonical_value": "fixture-bucket"}],
}


def audit_payload(scan):
    return {
        "scan": scan, "findings": [FINDING], "resources": [], "events": [],
        "evidence": [
            {"id": "evidence-a", "rule_id": "QA-1", "outcome": "UNKNOWN",
             "evidence_sha256": "b" * 64},
        ],
    }


def api_fixture(route, role, state):
    request = route.request
    url = urlsplit(request.url)
    path = url.path.removeprefix("/api/v1")
    if not url.path.startswith("/api/v1/"):
        route.continue_()
        return
    headers = {
        "access-control-allow-origin": request.headers.get("origin", "*"),
        "access-control-allow-credentials": "true",
        "access-control-allow-methods": "GET, POST, PATCH, OPTIONS",
        "access-control-allow-headers": "content-type, x-csrf-token",
    }

    def respond(payload, status=200):
        route.fulfill(status=status, headers=headers, json=payload)

    if request.method == "OPTIONS":
        route.fulfill(status=204, headers=headers)
        return
    if request.method == "POST" and path == f"{PREFIX}/iac/scans" and role == "ADMIN":
        assert request.headers["content-type"] == "application/zip"
        with ZipFile(BytesIO(request.post_data_buffer)) as archive:
            assert archive.namelist() == ["main.tf"]
        state["mutations"].append(("POST", path, "checked ZIP"))
        respond({"id": "iac-run"})
        return
    if request.method != "GET":
        payload = request.post_data_json
        state["mutations"].append((request.method, path, payload))
        mapping_url = f"{PREFIX}/environments/aws-a/iam-mappings"
        exception_url = f"{PREFIX}/scans/advanced/deploy-exceptions"
        if path == f"{PREFIX}/scans/advanced/deploy-governance/evaluations" and role == "ADMIN":
            respond({"classification": "REVIEW_REQUIRED", "explanation": "Evidence is partial.", "obligations": ["Review unknown checks"]})
        elif path == f"{PREFIX}/environments/aws-a/test" and role == "ADMIN":
            respond({"account_id": ENVIRONMENT["account_id"]})
        elif path in {f"{PREFIX}/environments/aws-a/scans", f"{PREFIX}/environments/aws-a/advanced-scans"} and role == "ADMIN":
            respond({"id": "aws-run"})
        elif path == mapping_url and role == "ADMIN":
            assert payload["entries"][0]["action"] == "s3:ListBucket"
            configuration = {**payload, "source_binding": {
                "account_id": ENVIRONMENT["account_id"], "server_endpoint": MCP_SERVER["endpoint"],
            }}
            mapping = {
                "id": "mapping-a", "mcp_server_id": 1, "name": payload["name"],
                "status": "DRAFT", "signed_revision": SIGNED_CONTEXT["signed_revision"],
                "signed_content_hash": SIGNED_CONTEXT["signed_content_hash"],
                "configuration": configuration,
            }
            state["mappings"].append(mapping)
            respond(mapping)
        elif path == f"{mapping_url}/mapping-a/approve" and role == "ADMIN":
            assert payload == {"confirm": True}
            mapping = state["mappings"][0]
            mapping.update(status="APPROVED", approval_digest="d" * 64)
            respond(mapping)
        elif path == f"{PREFIX}/environments/aws-a/iam-comparisons" and role == "ADMIN":
            assert payload == {"mapping_id": "mapping-a"}
            assert state["mappings"][0]["status"] == "APPROVED"
            respond({"id": "iam-run"})
        elif path == exception_url and role == "ADMIN":
            assert payload["finding_id"] == FINDING["id"] and len(payload["reason"]) >= 20
            exception_id = f"exception-{len(state['exceptions']) + 1}"
            item = {
                "exception_id": exception_id, "finding_id": payload["finding_id"],
                "state": "REQUESTED", "events": [
                    {"id": f"{exception_id}-request", "operation": "REQUEST", "reason": payload["reason"]},
                ],
            }
            state["exceptions"].append(item)
            respond(item)
        elif path.startswith(exception_url + "/") and path.endswith("/decide") and role == "ADMIN":
            item = next(it for it in state["exceptions"] if it["exception_id"] == path.split("/")[-2])
            operation = payload["operation"]
            assert len(payload["reason"]) >= 20
            if operation == "APPROVE":
                assert item["state"] == "REQUESTED" and payload["expires_days"] == 7
                item["expires_at"] = "2026-11-27T15:00:00Z"
            elif operation == "REVOKE":
                assert item["state"] == "APPROVED" and payload["expires_days"] is None
            elif operation == "REJECT":
                assert item["state"] == "REQUESTED" and payload["expires_days"] is None
            item["state"] = {"APPROVE": "APPROVED", "REVOKE": "REVOKED", "REJECT": "REJECTED"}[operation]
            item["events"].append({"id": operation, "operation": operation, "reason": payload["reason"]})
            respond(item)
        else:
            respond({"detail": "Unexpected mutation in the browser fixture"}, 403)
        return

    user = {"id": 1, "username": "fixture", "role": role, "enabled": True}
    responses = {
        "/control-plane/auth/me": user,
        "/health": {"status": "healthy"},
        "/control-plane/local-runtime/status": {},
        "/control-plane/operations/summary": {},
        "/runtime/logs": {"items": [], "summary": {}, "has_more": False},
        "/control-plane/config/active": None,
        "/control-plane/users": [user],
        "/servers": [MCP_SERVER],
        f"{PREFIX}/environments": [ENVIRONMENT],
        f"{PREFIX}/scans": SCANS,
        f"{PREFIX}/advanced/scanner": {"available": True, "expected_version": "fixture"},
        f"{PREFIX}/environments/aws-a/advanced/permissions": {
            "account_id": ENVIRONMENT["account_id"], "role_arn": ENVIRONMENT["role_arn"],
            "permission_checks": [],
        },
        f"{PREFIX}/iac/scanners": [{"available": True, "scanner": "Checkov"}],
        f"{PREFIX}/environments/aws-a/iam-mappings": state["mappings"],
        f"{PREFIX}/environments/aws-a/iam-mapping-context": SIGNED_CONTEXT,
        f"{PREFIX}/scans/advanced/deploy-exceptions": state["exceptions"],
        f"{PREFIX}/scans/advanced/deploy-governance": {
            "classification": "REVIEW_REQUIRED", "explanation": "Evidence is partial.",
            "obligations": ["Review unknown checks"],
        },
    }
    responses.update({f"{PREFIX}/scans/{scan['id']}": audit_payload(scan) for scan in SCANS})
    if path == f"{PREFIX}/scans/page":
        query = parse_qs(url.query)
        kind = query.get("kind", [""])[0]
        environment = query.get("environment_id", [""])[0]
        rows = [scan for scan in SCANS if (not kind or scan["kind"] == kind)
                and (not environment or scan["environment_id"] == environment or scan["kind"] == "IAC_CONFIG")]
        respond({"items": rows, "total": len(rows), "offset": 0, "limit": 25,
                 "returned": len(rows), "has_more": False})
    elif path == f"{PREFIX}/scans/advanced/deploy-governance/history":
        respond({"detail": "DEPLOY_DECISION_CHAIN_INVALID"}, 409)
    elif path in responses:
        respond(responses[path])
    else:
        respond([])


def check_mapping(page, task_nav):
    task_nav.get_by_role("button", name="MCP permissions", exact=True).click()
    page.get_by_label("EC2 instance ID").fill("i-0123456789abcdef0")
    page.get_by_label("AWS action", exact=True).fill("s3:ListBucket")
    page.get_by_label("Signed resource scope").select_option("bucket-a")
    page.get_by_label("Cloud resource ARN template").fill("arn:aws:s3:::${scope}")
    expect(page.get_by_role("button", name="Compare AWS and MCP permissions")).to_have_count(0)
    page.get_by_role("button", name="Save mapping draft").click()
    expect(page.get_by_label("Mapping configuration")).to_have_value("mapping-a")
    approve = page.get_by_role("button", name="Approve mapping")
    expect(approve).to_be_disabled()
    page.get_by_role("checkbox", name="I have reviewed the signed contract", exact=False).check()
    approve.click()
    page.get_by_role("button", name="Compare AWS and MCP permissions").click()
    expect(page.get_by_text("IAM and MCP comparison queued", exact=False)).to_be_visible()


def check_exceptions(page):
    request = page.get_by_role("button", name="Request exception", exact=True)
    expect(request).to_be_disabled()

    def submit():
        page.get_by_label("Finding to review").select_option(FINDING["id"])
        page.get_by_label("Exception request justification", exact=False).fill("Review this fixture finding during validation.")
        request.click()

    def decide(button, expected):
        page.get_by_role("button", name="Review this request").click()
        action = page.get_by_role("button", name=button, exact=True)
        expect(action).to_be_disabled()
        page.get_by_label("Review justification", exact=False).fill("This is the fixture administrator review justification.")
        action.click()
        expect(page.get_by_text(f"{FINDING['title']} - exception {expected.lower()}", exact=True)).to_be_visible()

    submit()
    decide("Approve temporary exception", "APPROVED")
    decide("Revoke exception", "REVOKED")
    submit()
    decide("Reject exception", "REJECTED")


def check_scan_launches(page, task_nav):
    launch = page.get_by_role("button", name="Start read-only audit", exact=True)
    launch.click()
    expect(page.get_by_text("AWS scan queued (aws-run).", exact=False)).to_be_visible()
    task_nav.get_by_role("button", name="Advanced AWS checks", exact=True).click()
    page.get_by_role("button", name="Check read-only AWS permissions").click()
    expect(page.get_by_role("heading", name="AWS permission diagnostic")).to_be_visible()
    page.get_by_role("button", name="Start advanced read-only audit", exact=True).click()
    expect(page.get_by_text("Advanced AWS audit queued (aws-run).", exact=True)).to_be_visible()
    task_nav.get_by_role("button", name="Terraform files", exact=True).click()
    submit = page.get_by_role("button", name="Scan Terraform ZIP")
    expect(submit).to_be_disabled()
    payload = BytesIO()
    with ZipFile(payload, "w") as archive:
        archive.writestr("main.tf", 'variable "region" { default = "eu-west-3" }')
    page.locator("#cloud-iac input[type=file]").set_input_files(
        {"name": "fixture.zip", "mimeType": "application/zip", "buffer": payload.getvalue()},
    )
    submit.click()
    expect(page.get_by_text("Terraform configuration scan queued (iac-run).", exact=False)).to_be_visible()
    expect(submit).to_be_disabled()


def check(browser, url, role, width):
    state = {"mutations": [], "mappings": [], "exceptions": []}
    errors = []
    context = browser.new_context(viewport={"width": width, "height": 900})
    context.add_cookies([{"name": "mcp_control_plane_csrf", "value": "fixture", "url": url}])
    page = context.new_page()
    page.set_default_timeout(8000)
    page.on("pageerror", lambda error: errors.append(str(error)))
    page.route("**/*", lambda route: api_fixture(route, role, state))
    page.goto(url)
    page.locator("#primary-navigation:visible, .mobile-nav-toggle:visible").first.wait_for()
    navigation = page.get_by_role("navigation", name="Main navigation")
    if not navigation.is_visible():
        page.get_by_role("button", name="Open navigation menu").click()
    navigation.get_by_role("link", name="Cloud security", exact=True).click()
    task_nav = page.get_by_role("navigation", name="Cloud security tasks")
    expect(task_nav.get_by_role("button")).to_have_count(6)
    expect(page.get_by_text("Quality assurance", exact=True)).to_have_count(1)
    expect(page.get_by_role("button", name="Test connection")).to_have_count(int(role == "ADMIN"))

    if role == "ADMIN":
        page.get_by_role("button", name="Test connection").click()
        expect(page.get_by_text("AWS connection verified for account", exact=False)).to_be_visible()
        if width == 1440:
            check_scan_launches(page, task_nav)
            check_mapping(page, task_nav)

    for name, heading in (
        ("Advanced AWS checks", "Advanced AWS audit with Prowler"),
        ("MCP permissions", "Review MCP cloud permissions"),
        ("Terraform files", "Check Terraform configuration"),
        ("Audit history", "Audit history"),
    ):
        task_nav.get_by_role("button", name=name, exact=True).click()
        expect(page.get_by_role("heading", name=heading, exact=True)).to_be_visible()
        assert page.evaluate("document.documentElement.scrollWidth <= innerWidth")

    history = page.get_by_role("region", name="Cloud audit history")
    expect(history.get_by_role("row")).to_have_count(5)
    page.get_by_label("Audit type").select_option("AWS_ADVANCED")
    expect(history.get_by_role("row")).to_have_count(2)
    history.get_by_role("button", name="View Advanced AWS", exact=False).click()
    expect(page.get_by_role("heading", name="Audit review", exact=True)).to_be_focused()
    expect(page.get_by_text("Assessment history could not be verified", exact=False)).to_be_visible()
    expect(page.get_by_text("No recorded assessments yet.", exact=True)).to_have_count(0)
    action = "Evaluate and record governance" if role == "ADMIN" else "Preview governance"
    page.get_by_role("button", name=action, exact=True).click()
    expect(page.get_by_text("Evidence is partial.", exact=True)).to_be_visible()
    expect(page.get_by_role("button", name="Request exception", exact=True)).to_have_count(int(role == "ADMIN"))
    if role == "ADMIN" and width == 1440:
        check_exceptions(page)
    page.get_by_text("Evidence records (1)", exact=True).click()
    expect(page.get_by_text("b" * 64, exact=True)).to_be_visible()
    assert page.evaluate("document.documentElement.scrollWidth <= innerWidth")
    page.get_by_role("button", name="Browse audit history", exact=True).click()
    expect(page.get_by_label("Audit type")).to_have_value("AWS_ADVANCED")
    expected = 13 if role == "ADMIN" and width == 1440 else 2 if role == "ADMIN" else 0
    assert len(state["mutations"]) == expected, state["mutations"]
    assert not errors, errors
    context.close()
    print(f"Cloud workflows passed: {role}, {width}px")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("url", help="URL of an isolated frontend")
    parser.add_argument("--chromium", help="Path to the installed browser executable")
    args = parser.parse_args()
    assert urlsplit(args.url).hostname in {"localhost", "127.0.0.1"}
    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(headless=True, executable_path=args.chromium)
        for width in (1440, 768, 390):
            for role in ("ADMIN", "VIEWER"):
                check(browser, args.url, role, width)
        browser.close()


if __name__ == "__main__":
    main()
