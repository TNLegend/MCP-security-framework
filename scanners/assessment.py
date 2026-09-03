from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
from typing import Iterable

from scanners.contracts import (
    BuildAssessmentStatus,
    FindingSeverity,
    ScannerRunStatus,
)

BUILD_ASSESSMENT_POLICY_VERSION = "build-policy-v1"


@dataclass(frozen=True, slots=True)
class AssessmentInput:
    required_scanner_statuses: tuple[ScannerRunStatus, ...]
    active_severities: tuple[FindingSeverity, ...]


@dataclass(frozen=True, slots=True)
class AssessmentDecision:
    status: BuildAssessmentStatus
    required_scanners_complete: bool
    reason_codes: tuple[str, ...]
    summary: str


def decide_build_assessment(value: AssessmentInput) -> AssessmentDecision:
    required_complete = all(
        status == ScannerRunStatus.COMPLETED
        for status in value.required_scanner_statuses
    )
    counts = Counter(severity.value for severity in value.active_severities)
    reasons: list[str] = []

    if not required_complete:
        reasons.append("required_scanner_incomplete")
        return AssessmentDecision(
            status=BuildAssessmentStatus.ERROR,
            required_scanners_complete=False,
            reason_codes=tuple(reasons),
            summary="Build Security evidence is incomplete because at least one required scanner did not complete.",
        )

    if counts["CRITICAL"]:
        reasons.append("critical_findings")
        return AssessmentDecision(
            status=BuildAssessmentStatus.BLOCK,
            required_scanners_complete=True,
            reason_codes=tuple(reasons),
            summary=f"Build Security blocked by {counts['CRITICAL']} critical finding(s).",
        )

    if counts["HIGH"]:
        reasons.append("high_findings")
    if counts["MEDIUM"]:
        reasons.append("medium_findings")
    if counts["LOW"]:
        reasons.append("low_findings")
    if counts["INFO"]:
        reasons.append("info_findings")

    if reasons:
        return AssessmentDecision(
            status=BuildAssessmentStatus.WARN,
            required_scanners_complete=True,
            reason_codes=tuple(reasons),
            summary=(
                "Build Security completed with findings requiring review: "
                f"{counts['HIGH']} high, {counts['MEDIUM']} medium, "
                f"{counts['LOW']} low, {counts['INFO']} informational."
            ),
        )

    return AssessmentDecision(
        status=BuildAssessmentStatus.PASS,
        required_scanners_complete=True,
        reason_codes=(),
        summary="All required Build Security scanners completed with no active findings.",
    )


def active_severities_from_values(values: Iterable[str]) -> tuple[FindingSeverity, ...]:
    result: list[FindingSeverity] = []
    for value in values:
        try:
            result.append(FindingSeverity(value))
        except ValueError:
            result.append(FindingSeverity.MEDIUM)
    return tuple(result)
