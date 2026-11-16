"""M7-owned, non-authoritative projection of M4 advisory directive hypotheses.

M3's deterministic instruction detection remains independent of M4. This
function carries M4 consumer hypotheses only, with no verdict or permission.
"""
from __future__ import annotations
from typing import Any


def interpret_m4_directives_advisory(view: dict[str, Any]) -> dict[str, Any]:
    """Allowed M7 -> M3 compatibility. M3 must not import M7."""
    from app.services.tda.m3_instructions.detectors import (
        interpret_m4_directives_advisory as legacy_pure_projection,
    )
    return legacy_pure_projection(view)
