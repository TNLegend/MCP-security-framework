"""Playwright qualification of contextual AI assistance with synthetic responses."""

import argparse
from pathlib import Path

from playwright.sync_api import expect, sync_playwright

from gui_browser_smoke import DIGEST, navigate, open_page, serve


def exercise_assistant(page, width):
    submitted = []
    replies = iter((
        (200, {"evidence_refs": ["finding:17"], "confidence": 0.75,
               "ai_explanation": "Unsupported provider permission claim",
               "grounded_claims": [{"type": "RECORDED_FINDING", "evidence_ref": "finding:17",
                                     "label": "Recorded finding", "value": "HIGH · Fixture scope"}]}),
        (200, {"uncertainties": ["The observed scope is incomplete."], "evidence_refs": []}),
        (200, {"analysis_context_hash": "b" * 64, "summary": "Unexpected analysis"}),
        (200, {"can_mutate_runtime": True, "summary": "Unexpected authority"}),
        (429, {"detail": "Untrusted provider details"}),
        (504, {"detail": "Untrusted provider details"}),
    ))

    def request_assistance(route):
        submitted.append(route.request.post_data_json)
        status, patch = next(replies)
        recorded_response = {
            "tool_id": 1, "mode": "EXPLAIN", "analysis_id": 1,
            "analysis_context_hash": DIGEST, "fingerprint": DIGEST,
            "summary": "The framework recorded a review requirement.",
            "rationale": "The current observation is still waiting for review.",
            "draft_kind": "NONE", "recommended_action": "HUMAN_REVIEW",
            "provider": "gemini", "non_authoritative": True,
            "requires_human_review": True, "can_mutate_runtime": False,
        }
        route.fulfill(status=status, json={**recorded_response, **patch} if status == 200 else patch)

    page.route("**/api/v1/tool-analysis/tools/1/findings", lambda route: route.fulfill(json=[
        {"id": 17, "analysis_id": 1, "code": "FIXTURE_RULE", "severity": "HIGH", "summary": "Exact fixture finding"}
    ]))
    page.route("**/api/v1/control-plane/ai-assistance/tools/1", request_assistance)
    navigate(page, "Security review", width)
    page.get_by_role("tab", name="Explain with AI").click()
    assistant = page.get_by_role("region", name="AI assistance")
    ask = assistant.get_by_role("button", name="Explain this result", exact=True)
    expect(ask).to_be_enabled()
    ask.press("Enter")
    # Current candidate contract (the old "What the framework recorded" label was replaced before e3dc067).
    expect(assistant.get_by_role("heading", name="Recorded security facts")).to_be_visible()
    assistant.get_by_text("Supporting evidence and advanced options").click()
    expect(assistant.get_by_text("finding:17", exact=True).last).to_be_visible()
    expect(assistant.get_by_text("HIGH · Fixture scope")).to_be_visible()
    expect(assistant.get_by_text("Unsupported provider permission claim")).to_have_count(0)
    assistant.get_by_role("button", name="finding:17", exact=True).first.click()
    expect(page.locator('[data-finding-id="17"]')).to_contain_text("Exact fixture finding")
    page.get_by_role("tab", name="Explain with AI").click()
    expect(assistant.get_by_text("HIGH · Fixture scope")).to_be_visible()
    assert len(submitted) == 1
    # UX-14: uncalibrated model confidence is no longer displayed.
    expect(assistant.get_by_text("Advisory confidence:", exact=False)).to_have_count(0)
    ask.click()
    expect(assistant.get_by_text("The observed scope is incomplete.")).to_be_visible()
    expect(assistant.get_by_text("No evidence references were selected.", exact=False)).to_be_visible()
    assert submitted[0]["expected_analysis"] == {
        "id": 1, "fingerprint": DIGEST, "context_hash": DIGEST,
        "analysis_status": "REVIEW_REQUIRED", "review_status": "REVIEW_REQUIRED",
    }

    ask.click()
    expect(assistant.get_by_role("alert")).to_contain_text("The tool analysis changed")
    expect(assistant.get_by_text("Unexpected analysis")).to_have_count(0)

    ask.click()
    expect(assistant.get_by_role("heading", name="AI explanation withheld")).to_be_visible()
    expect(assistant.get_by_text("Unexpected authority")).to_have_count(0)

    ask.click()
    expect(assistant.get_by_role("alert")).to_contain_text("request limit")
    ask.click()
    expect(assistant.get_by_role("alert")).to_contain_text("timed out")
    expect(assistant.get_by_text("Untrusted provider details")).to_have_count(0)
    assert len(submitted) == 6


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
                context, page, _, errors = open_page(browser, server, "ADMIN", width)
                exercise_assistant(page, width)
                assert not errors, errors
                print(f"PASS ADMIN {width}px: advisory receipt, incomplete evidence, mismatch, safeguards, quota, timeout")
                context.close()

            context, page, api, errors = open_page(browser, server, "VIEWER", 768)
            navigate(page, "Security review", 768)
            page.get_by_role("tab", name="Explain with AI").click()
            expect(page.get_by_text("Only an administrator can request an AI explanation.")).to_be_visible()
            expect(page.get_by_role("button", name="Explain this result", exact=True)).to_have_count(0)
            assert not api.mutations and not errors, (api.mutations, errors)
            print("PASS VIEWER 768px: advisory gate and no provider request")
            context.close()
    finally:
        server.shutdown()


if __name__ == "__main__":
    main()
