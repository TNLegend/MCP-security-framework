"""Single bounded registry for trusted runtime diagnostic codes.

Loaded once when the process imports this module. Never read on the hot path.
"""
import json
from pathlib import Path

CATALOG = json.loads(Path(__file__).with_name("explanation_catalog.json").read_text("utf-8"))
assert CATALOG["schema_version"] == 1
RUNTIME_EXPLANATION_CHECKS = frozenset(CATALOG["runtime_checks"])
RUNTIME_EFFECT_CHECKS = frozenset(CATALOG["runtime_effect_checks"])
SAFE_RUNTIME_ERROR_CODES = frozenset(CATALOG["safe_runtime_error_codes"])

# Descriptions of internal Proxy refusal controls, never inferred from remote text.
RUNTIME_GUARDS = CATALOG["runtime_guards"]
