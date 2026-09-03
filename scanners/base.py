from __future__ import annotations

from typing import Protocol, runtime_checkable

from scanners.contracts import (
    ScannerAvailability,
    ScannerContext,
    ScannerExecutionResult,
    ValidatedWorkspace,
)


@runtime_checkable
class BuildScanner(Protocol):
    """Trusted adapter boundary for deterministic Build Security scanners."""

    scanner_id: str

    def probe(self) -> ScannerAvailability:
        ...

    def scan(
        self,
        workspace: ValidatedWorkspace,
        context: ScannerContext,
    ) -> ScannerExecutionResult:
        ...
