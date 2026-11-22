from types import SimpleNamespace

from app.services.controlled_ai_assistance import _generate_advice, _grounded_claims


def test_fake_provider_cannot_invent_permissions_using_any_valid_reference(monkeypatch):
    monkeypatch.setenv("CONTROLLED_AI_PROVIDER", "fake")
    monkeypatch.setenv("CONTROLLED_AI_FALLBACK_PROVIDER", "fake")

    class FakeProvider:
        def generate_json(self, _):
            return {
                "evidence_refs": ["analysis:7", "finding:4"],
                "explanation": "This authorizes a synthetic privileged action.",
                "claims": [
                    {"type": "EFFECTIVE_AWS_ALLOW", "evidence_ids": ["finding:4"]},
                    {"type": "RISK_LEVEL", "evidence_ids": ["finding:4"]},
                    {"type": "RECORDED_FINDING", "evidence_ids": ["finding:4"], "text": "Unverified grant"},
                    {"type": "RECORDED_FINDING", "evidence_ids": ["finding:4"]},
                    {"type": "REVIEW_STATUS", "evidence_ids": ["analysis:7"]},
                ],
            }

    advice, _, _ = _generate_advice("synthetic", allowed_evidence={"analysis:7", "finding:4"},
                                    provider_types={"fake": FakeProvider})
    findings = (SimpleNamespace(id=4, severity="HIGH", code="SYNTHETIC_SCOPE"),)
    analysis = SimpleNamespace(id=7, review_status="REVIEW_REQUIRED")
    claims = _grounded_claims(advice, analysis, findings)
    assert [(row.type, row.value, row.evidence_ref) for row in claims] == [
        ("RECORDED_FINDING", "HIGH · SYNTHETIC_SCOPE", "finding:4"),
        ("REVIEW_STATUS", "REVIEW_REQUIRED", "analysis:7"),
    ]
    assert _grounded_claims(advice, analysis, ())[-1].evidence_ref == "analysis:7"


def test_evidence_binding_is_stable_and_changes_with_scope_or_configuration():
    from app.services.controlled_ai_assistance import _assistance_digest

    recorded = SimpleNamespace(id=7, fingerprint="a" * 64, analysis_context_hash="b" * 64,
                               analysis_status="COMPLETE", review_status="PENDING")
    refs = ("analysis:7", "finding:4")
    bound = _assistance_digest(1, recorded, refs, None, {"x": 1, "y": 2})
    assert len(bound) == 64
    assert bound == _assistance_digest(1, recorded, refs, None, {"y": 2, "x": 1})
    assert bound != _assistance_digest(2, recorded, refs, None, {"x": 1, "y": 2})
    assert bound != _assistance_digest(1, recorded, refs, "other-revision", {"x": 1, "y": 2})
