"""UX-06: persisted drift results name their exact comparison target."""
from types import SimpleNamespace

from app.services.tda_application.analysis_service import (
    DRIFT_COMPARISON_SCHEMA,
    drift_result_with_comparison_target,
)

DRIFT = {"status": "NONE", "changes": [], "similarity": None}
BASELINE = SimpleNamespace(id=7, version_id=11, fingerprint="f" * 64, approval_source="ADMIN")


def test_no_baseline_is_recorded_as_absent_not_compared():
    result = drift_result_with_comparison_target(DRIFT, None, None)
    assert result["changes"] == [] and result["status"] == "NONE"
    comparison = result["comparison"]
    assert comparison["schema"] == DRIFT_COMPARISON_SCHEMA
    assert comparison["baseline_present"] is False
    assert comparison["compared"] is False
    assert comparison["baseline_fingerprint"] is None


def test_completed_comparison_binds_baseline_version_and_fingerprint():
    result = drift_result_with_comparison_target(
        {**DRIFT, "similarity": 1.0}, BASELINE, {"name": "tool"})
    comparison = result["comparison"]
    assert comparison["compared"] is True
    assert comparison["baseline_version_id"] == 11
    assert comparison["baseline_fingerprint"] == "f" * 64


def test_missing_snapshot_or_failed_analysis_never_claims_a_comparison():
    missing = drift_result_with_comparison_target(DRIFT, BASELINE, None)["comparison"]
    assert missing["baseline_present"] is True and missing["compared"] is False
    failed = drift_result_with_comparison_target(
        DRIFT, BASELINE, {"name": "tool"}, comparison_ran=False)["comparison"]
    assert failed["compared"] is False and failed["comparison_ran"] is False


def test_original_m6_fields_and_input_are_not_mutated():
    source = {"status": "HIGH", "changes": [{"type": "x"}], "similarity": 0.4}
    result = drift_result_with_comparison_target(source, BASELINE, {"name": "tool"})
    assert "comparison" not in source
    assert {k: result[k] for k in source} == source
    assert drift_result_with_comparison_target(None, BASELINE, {}) is None
