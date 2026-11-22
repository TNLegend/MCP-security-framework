"""UX-01: loaded build identity and mixed-version detection (no network, no live services)."""
from __future__ import annotations

import common.build_identity as build_identity
from app.services.local_runtime_manager import LocalRuntimeManager

REV_A = "a" * 40
REV_B = "b" * 40
POLICY = "package runtime\nallow := false\n"


def api_identity(revision=REV_A, policy=None, dirty=False):
    digest = build_identity.policy_bundle_digest([POLICY]) if policy is None else policy
    return {"component": "api", "revision": revision, "revision_source": "git_head_at_process_start",
            "worktree_dirty": dirty, "policy_bundle_digest_at_start": digest}


def fetcher(gateway=REV_A, opa_raw=(POLICY,), gateway_up=True, opa_up=True):
    def fetch(url):
        if url.endswith("/health"):
            if not gateway_up:
                raise OSError("down")
            return {"status": "ok", "build": None if gateway is None else {"revision": gateway}}
        if url.endswith("/v1/policies"):
            if not opa_up:
                raise OSError("down")
            return {"result": [{"id": f"/p/{i}.rego", "raw": raw} for i, raw in enumerate(opa_raw)]
                    + [{"id": "/p/runtime_test.rego", "raw": "package test"}]}
        raise AssertionError(url)
    return fetch


def statuses(result):
    return {item["key"]: item["status"] for item in result["comparisons"]}


def test_matched_stack_reports_match():
    result = LocalRuntimeManager().provenance(api_identity(), json_fetcher=fetcher())
    assert statuses(result) == {"gateway_revision_vs_api": "match", "opa_policy_vs_api_start": "match"}
    assert result["overall"] == "match"


def test_mixed_version_gateway_and_changed_policy_are_mismatches():
    result = LocalRuntimeManager().provenance(
        api_identity(), json_fetcher=fetcher(gateway=REV_B, opa_raw=("package runtime\nallow := true\n",)))
    assert statuses(result) == {"gateway_revision_vs_api": "mismatch", "opa_policy_vs_api_start": "mismatch"}
    assert result["overall"] == "mismatch"


def test_unknown_version_is_distinct_from_unreachable():
    legacy_gateway = LocalRuntimeManager().provenance(api_identity(), json_fetcher=fetcher(gateway=None))
    assert statuses(legacy_gateway)["gateway_revision_vs_api"] == "unknown"
    stopped = LocalRuntimeManager().provenance(api_identity(), json_fetcher=fetcher(gateway_up=False, opa_up=False))
    assert statuses(stopped) == {"gateway_revision_vs_api": "unreachable", "opa_policy_vs_api_start": "unreachable"}
    assert stopped["components"]["gateway"]["reachable"] is False


def test_policy_digest_ignores_line_endings_and_order_and_test_modules():
    a = build_identity.policy_bundle_digest(["x\r\ny\r\n", "z\n"])
    b = build_identity.policy_bundle_digest(["z\n", "x\ny\n"])
    assert a == b and a is not None
    assert build_identity.policy_bundle_digest([]) is None


def test_identity_is_captured_once_and_contains_no_paths(monkeypatch):
    monkeypatch.setattr(build_identity, "_CAPTURED", {})
    monkeypatch.setenv("MCP_BUILD_REVISION", REV_B)
    first = build_identity.get_build_identity("gateway")
    monkeypatch.setenv("MCP_BUILD_REVISION", REV_A)
    second = build_identity.get_build_identity("gateway")
    assert first["revision"] == second["revision"] == REV_B  # disk/env changes after start do not leak in
    assert first["revision_source"] == "release_environment"
    assert first["source_digest"] and first["source_module_count"] > 0
    assert "\\" not in str(first) and "/Users/" not in str(first)
    monkeypatch.setenv("MCP_BUILD_REVISION", "not-a-revision")
    monkeypatch.setattr(build_identity, "_git", lambda *args: None)
    unknown = build_identity.capture_build_identity("ui", [])
    assert unknown["revision"] is None and unknown["revision_source"] == "unknown"
