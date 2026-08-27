from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
import json
import re
from threading import RLock
from time import monotonic
from typing import Any


MAX_RESULT_SCAN_BYTES = 1_000_000
MAX_TRACKED_SESSIONS = 1024
MAX_FINGERPRINTS_PER_SESSION = 2048
TAINT_TTL_SECONDS = 900

HIGH_CONFIDENCE_PATTERNS = {
    "private_key_material": re.compile(
        r"-----BEGIN (?:RSA |EC |OPENSSH |PGP )?PRIVATE KEY-----",
        re.IGNORECASE,
    ),
    "cloud_access_key": re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b"),
    "github_access_token": re.compile(r"\bgh(?:p|o|u|s|r)_[A-Za-z0-9]{30,255}\b"),
    "jwt_bearer_token": re.compile(
        r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"
    ),
    "result_prompt_injection": re.compile(
        r"\b(ignore|override|disregard|forget).{0,60}\b(previous|system|developer|platform|security).{0,30}\b(instructions?|rules?|policy)\b",
        re.IGNORECASE | re.DOTALL,
    ),
}


@dataclass(frozen=True)
class ResultInspection:
    blocked: bool
    finding_codes: tuple[str, ...]


class ToolResultGuard:
    def __init__(self) -> None:
        self._lock = RLock()
        self._taints: dict[str, tuple[float, frozenset[str]]] = {}

    def inspect(self, result: Any) -> ResultInspection:
        text = _bounded_text(result)
        findings = tuple(
            code for code, pattern in HIGH_CONFIDENCE_PATTERNS.items() if pattern.search(text)
        )
        return ResultInspection(blocked=bool(findings), finding_codes=findings)

    def remember_read_result(self, session_reference: str, result: Any) -> None:
        fingerprints = _content_fingerprints(result)
        if not session_reference or not fingerprints:
            return
        now = monotonic()
        with self._lock:
            self._prune(now)
            current = self._taints.get(session_reference, (now, frozenset()))[1]
            merged = frozenset((*current, *fingerprints))
            if len(merged) > MAX_FINGERPRINTS_PER_SESSION:
                merged = frozenset(sorted(merged)[:MAX_FINGERPRINTS_PER_SESSION])
            self._taints[session_reference] = (now + TAINT_TTL_SECONDS, merged)

    def matches_prior_result(self, session_reference: str, arguments: Any) -> bool:
        if not session_reference:
            return False
        now = monotonic()
        with self._lock:
            self._prune(now)
            entry = self._taints.get(session_reference)
            if entry is None:
                return False
            return bool(entry[1].intersection(_content_fingerprints(arguments)))

    def _prune(self, now: float) -> None:
        self._taints = {
            key: value for key, value in self._taints.items() if value[0] > now
        }
        if len(self._taints) > MAX_TRACKED_SESSIONS:
            oldest = sorted(self._taints, key=lambda key: self._taints[key][0])
            for key in oldest[: len(self._taints) - MAX_TRACKED_SESSIONS]:
                self._taints.pop(key, None)


def is_external_effect(prepared_request: Any) -> bool:
    facts = prepared_request.normalized_facts or {}
    capabilities = {
        str(effect.get("capability_id") or "")
        for effect in facts.get("effects", ())
        if isinstance(effect, dict)
    }
    external = {
        str(item.get("id") or "")
        for item in prepared_request.capability_catalog
        if isinstance(item, dict) and item.get("external_effect") is True
    }
    if capabilities.intersection(external):
        return True
    return prepared_request.required_capability in {
        "message.send",
        "network.send",
        "network.request",
        "payment.initiate",
        "payment.refund",
    }


def is_read_effect(prepared_request: Any) -> bool:
    facts = prepared_request.normalized_facts or {}
    capabilities = {
        str(effect.get("capability_id") or "")
        for effect in facts.get("effects", ())
        if isinstance(effect, dict)
    }
    if any(value.endswith((".read", ".list")) for value in capabilities):
        return True
    return prepared_request.required_capability.endswith((".read", ".list"))


def _bounded_text(value: Any) -> str:
    try:
        serialized = json.dumps(value, ensure_ascii=False, sort_keys=True)
    except (TypeError, ValueError, RecursionError):
        serialized = str(value)
    return serialized.encode("utf-8", errors="replace")[:MAX_RESULT_SCAN_BYTES].decode(
        "utf-8", errors="ignore"
    )


def _content_fingerprints(value: Any) -> frozenset[str]:
    text = re.sub(r"\s+", " ", _bounded_text(value)).strip()
    if len(text) < 16:
        return frozenset()
    parts = [part.strip() for part in re.split(r"[\r\n,;]", text) if len(part.strip()) >= 16]
    words = text.split()
    parts.extend(" ".join(words[index:index + 4]) for index in range(max(0, len(words) - 3)))
    return frozenset(
        sha256(part.encode("utf-8")).hexdigest()
        for part in parts[:MAX_FINGERPRINTS_PER_SESSION]
        if len(part) >= 16
    )
