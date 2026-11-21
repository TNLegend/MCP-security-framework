"""CL-10: a precisely verified cross-scanner Terraform equivalence has one
finding and two independently persisted scanner evidence records.
"""
from types import SimpleNamespace

from app.models.cloud_security import CloudEvidence, CloudFinding, CloudScanEvent
from app.services import cloud_iac_security as iac


class CaptureSession:
    def __init__(self):
        self.items = []

    def add(self, value):
        self.items.append(value)

    def flush(self):
        pass


def test_cross_scanner_equivalence_persists_both_rules_and_versions(tmp_path, monkeypatch):
    monkeypatch.setattr(iac, "IAC_ROOT", tmp_path)
    source = tmp_path / "synthetic-scan" / "source"
    source.mkdir(parents=True)
    (source / "main.tf").write_text("# synthetic terraform file only\n", encoding="utf8")
    db = CaptureSession()
    def issue(rule, resource, line, logical="synthetic-resource"):
        return {
            "file": "main.tf",
            "rule": rule,
            "resource_hash": resource,
            "logical_resource_hash": logical,
            "severity": "MEDIUM",
            "line": line,
        }

    count, unknown = iac._store_results(
        db, SimpleNamespace(id="synthetic-scan"), "f" * 64,
        [
            ("checkov", "COMPLETED", [issue("CKV_AWS_23", "hash-checkov", 13)], "checkov-qa-v1"),
            ("trivy", "COMPLETED", [
                issue("AWS-0099", "hash-trivy", 27),
                issue("AWS-0107", "hash-other", 55),
            ], "trivy-qa-v1"),
        ],
    )
    findings = [x for x in db.items if isinstance(x, CloudFinding)]
    proof = [x for x in db.items if isinstance(x, CloudEvidence) and x.outcome == "FAIL"]
    events = [x for x in db.items if isinstance(x, CloudScanEvent)]
    assert (count, unknown) == (2, 0)
    assert len(findings) == 2
    assert len(proof) == 3
    merged = next(f for f in findings if f.rule_id == "CKV_AWS_23")
    linked = [x for x in proof if x.safe_summary["linked_finding_id"] == merged.id]
    assert len(linked) == 2
    assert {(x.safe_summary["scanner"], x.rule_id, x.safe_summary["version"], x.safe_summary["line"])
            for x in linked} == {
        ("checkov", "CKV_AWS_23", "checkov-qa-v1", 13),
        ("trivy", "AWS-0099", "trivy-qa-v1", 27),
    }
    assert len({x.resource_id for x in linked}) == 1
    assert {x.safe_summary["source_fingerprint"] for x in linked} == {"f" * 64}
    assert any(x.message_code == "IAC_EQUIVALENT_FINDINGS_MERGED" for x in events)
    unrelated = next(f for f in findings if f.rule_id == "AWS-0107")
    assert unrelated.id != merged.id
    assert len([x for x in proof if x.safe_summary["linked_finding_id"] == unrelated.id]) == 1
