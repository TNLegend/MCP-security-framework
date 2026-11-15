from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
import os
import base64
import binascii
import json
import re
from urllib.parse import unquote
from threading import RLock
from time import monotonic
from typing import Any

from common.security_topology import local_security_authority_supported
from proxy.shared_taint_store import SharedTaintSQLiteStore, SharedTaintStoreError


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
    "github_access_token": re.compile(
        r"\b(?:gh(?:p|o|u|s|r)_[A-Za-z0-9]{30,255}|github_pat_[A-Za-z0-9_]{60,255})\b"
    ),
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
    def __init__(
        self, *, shared_store: SharedTaintSQLiteStore | None = None
    ) -> None:
        if not local_security_authority_supported():
            raise SharedTaintStoreError("taint_store_topology_unsupported")
        # All configured same-host workers must point to one trusted SQLite
        # file. Without a configured store we retain historical single-worker
        # semantics; multi-host storage requires a different distributed
        # backend and must NOT inherit this local-volume guarantee.
        configured = os.environ.get("MCP_RESULT_TAINT_SQLITE_PATH")
        self._shared_store = (
            shared_store if shared_store is not None
            else SharedTaintSQLiteStore(configured) if configured else None
        )
        self._shared_required_unavailable = (
            os.environ.get("MCP_RESULT_TAINT_SHARED_REQUIRED") == "1"
            and self._shared_store is None
        )
        self._lock = RLock()
        self._taints: dict[str, tuple[float, frozenset[str], bool]] = {}
        self._tracking_capacity_exceeded = False
        # We cannot recover evidence evicted at overflow, but the unknown
        # evidence also expires. Track that watermark rather than forever
        # poisoning unrelated sessions.
        self._tracking_capacity_exceeded_until = 0.0

    def inspect(self, result: Any) -> ResultInspection:
        # Never classify only the first bytes of a larger result as safe.
        # Serialize completely within the transport's upstream size bound,
        # then refuse payloads exceeding the inspection budget.
        try:
            text = json.dumps(result, ensure_ascii=False, sort_keys=True)
        except (TypeError, ValueError, RecursionError, OverflowError):
            return ResultInspection(True, ("result_serialization_invalid",))
        if len(text.encode("utf-8", errors="replace")) > MAX_RESULT_SCAN_BYTES:
            return ResultInspection(True, ("result_scan_limit_exceeded",))
        findings = tuple(
            code for code, pattern in HIGH_CONFIDENCE_PATTERNS.items() if pattern.search(text)
        )
        return ResultInspection(blocked=bool(findings), finding_codes=findings)

    def remember_read_result(self, session_reference: str, result: Any) -> None:
        fingerprints, complete = _content_fingerprints_with_coverage(result)
        # Missing authenticated session identity cannot partition taint.
        # Returning a result without recording its provenance would
        # silently disable the cross-call protection on the next request.
        if not session_reference:
            raise SharedTaintStoreError("taint_session_unbound")
        if not fingerprints and complete:
            return
        if self._shared_required_unavailable:
            raise SharedTaintStoreError("taint_store_required_unconfigured")
        if self._shared_store is not None:
            self._shared_store.merge(session_reference, fingerprints, complete)
            return
        now = monotonic()
        with self._lock:
            self._prune(now)
            old = self._taints.get(session_reference, (now, frozenset(), False))
            merged = set(old[1])
            merged.update(fingerprints)
            incomplete = old[2] or not complete or len(merged) > MAX_FINGERPRINTS_PER_SESSION
            # Keep a bounded evidence set; deny external effects if tracking
            # cannot represent all accepted read data.
            bounded = frozenset(sorted(merged)[:MAX_FINGERPRINTS_PER_SESSION])
            self._taints[session_reference] = (now + TAINT_TTL_SECONDS, bounded, incomplete)
            self._prune(now)

    def matches_prior_result(self, session_reference: str, arguments: Any) -> bool:
        if not session_reference:
            # External-effect checks must not equate missing security
            # identity with a fresh/untainted session.
            return True
        if self._shared_required_unavailable:
            return True
        if self._shared_store is not None:
            try:
                hashes, incomplete, watermark = self._shared_store.read(
                    session_reference
                )
            except SharedTaintStoreError:
                # A storage outage is not evidence of an empty taint ledger.
                return True
            if watermark or incomplete:
                return True
            if not hashes:
                return False
            argument_hashes, arguments_complete = _content_fingerprints_with_coverage(arguments)
            if not arguments_complete or hashes.intersection(argument_hashes):
                return True
            decoded_hashes, decoded_complete = _encoded_argument_fingerprints(arguments)
            return not decoded_complete or bool(hashes.intersection(decoded_hashes))
        now = monotonic()
        with self._lock:
            self._prune(now)
            entry = self._taints.get(session_reference)
            # A full store evicts old sessions; until reset, do not silently
            # claim exfil coverage for any session.
            if self._tracking_capacity_exceeded:
                return True
            if entry is None:
                return False
            if entry[2]:
                return True
            argument_hashes, arguments_complete = _content_fingerprints_with_coverage(arguments)
            if not arguments_complete:
                return True
            if entry[1].intersection(argument_hashes):
                return True
            decoded_hashes, decoded_complete = _encoded_argument_fingerprints(arguments)
            if not decoded_complete:
                # Decoding/inspection over budget is uncertain: no silent
                # authorization of an external effect.
                return True
            return bool(entry[1].intersection(decoded_hashes))

    def _prune(self, now: float) -> None:
        if self._tracking_capacity_exceeded and now >= self._tracking_capacity_exceeded_until:
            self._tracking_capacity_exceeded = False
            self._tracking_capacity_exceeded_until = 0.0
        self._taints = {
            key: value for key, value in self._taints.items() if value[0] > now
        }
        if len(self._taints) > MAX_TRACKED_SESSIONS:
            oldest = sorted(self._taints, key=lambda key: self._taints[key][0])
            for key in oldest[:len(self._taints) - MAX_TRACKED_SESSIONS]:
                evicted = self._taints.pop(key, None)
                if evicted is not None:
                    self._tracking_capacity_exceeded_until = max(
                        self._tracking_capacity_exceeded_until,
                        evicted[0],
                    )
            self._tracking_capacity_exceeded = True


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


def _declared_data_production(prepared_request: Any) -> bool | None:
    """Tri-state joined semantics for ALL effects, independent of their names.

    True: any signed catalog effect produces data.
    False: every involved effect is explicitly reviewed as not producing data.
    None: at least one effect/metadata record is unknown or malformed.
    This catalog is loaded from the signed published configuration, not from
    the provider's arbitrary names or an untrusted tool response.
    """
    facts = getattr(prepared_request, "normalized_facts", None) or {}
    effects = facts.get("effects", ()) if isinstance(facts, dict) else ()
    if not isinstance(effects, (list, tuple)):
        return None
    identifiers = {
        item.get("capability_id")
        for item in effects
        if isinstance(item, dict) and isinstance(item.get("capability_id"), str)
    }
    if len(identifiers) != len(effects):
        return None
    if not identifiers:
        required = getattr(prepared_request, "required_capability", None)
        if not isinstance(required, str) or not required:
            return None
        identifiers = {required}
    entries = getattr(prepared_request, "capability_catalog", ()) or ()
    if not isinstance(entries, (list, tuple)):
        return None
    catalog: dict[str, bool | None] = {}
    for item in entries:
        if not isinstance(item, dict) or not isinstance(item.get("id"), str):
            return None
        key = item["id"]
        if key in catalog:
            return None
        value = item.get("produces_data")
        catalog[key] = value if type(value) is bool else None
    classifications = [catalog.get(name) for name in identifiers]
    if any(value is True for value in classifications):
        return True
    if any(value is None for value in classifications):
        return None
    return False


def should_track_result(prepared_request: Any) -> bool:
    contract = getattr(prepared_request, "security_contract", None) or {}
    result_control = contract.get("result_control") if isinstance(contract, dict) else None
    if isinstance(result_control, dict):
        if result_control.get("track_for_exfiltration") is True:
            return True
        if result_control.get("produces_data") is True:
            return True
        if result_control.get("classification") in {"SENSITIVE", "SECRET"}:
            return True
    # Names and suffixes have no authority over the final data-flow decision.
    # Only all-effects signed FALSE can suppress tracking when no positive
    # contract signal was seen. UNKNOWN, including incomplete catalogs,
    # remains conservatively tracked.
    return _declared_data_production(prepared_request) is not False


def is_read_effect(prepared_request: Any) -> bool:
    # Legacy classification helper. The runtime decision uses the signed
    # capability metadata via should_track_result(), never this suffix
    # heuristic. Preserve historical helper behavior on missing catalogs.
    metadata = _declared_data_production(prepared_request)
    if metadata is not None:
        return metadata
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


def _content_fingerprints_with_coverage(value: Any) -> tuple[frozenset[str], bool]:
    # Exact string hashes and bounded textual fragments. All truncation is
    # propagated as incomplete coverage, instead of silently omitting taint.
    fingerprints: set[str] = set()
    stack = [value]
    visited = 0
    complete = True
    while stack:
        if visited >= 8_192 or len(fingerprints) >= MAX_FINGERPRINTS_PER_SESSION:
            complete = False
            break
        current = stack.pop()
        visited += 1
        if isinstance(current, str):
            encoded = current.encode("utf-8", errors="replace")
            if len(encoded) > MAX_RESULT_SCAN_BYTES:
                complete = False
            elif len(encoded) >= 16:
                fingerprints.add(sha256(encoded).hexdigest())
        elif isinstance(current, dict):
            values = list(current.values())
            if len(values) > 1_024:
                complete = False
            stack.extend(values[:1_024])
        elif isinstance(current, (tuple, list)):
            if len(current) > 1_024:
                complete = False
            stack.extend(current[:1_024])
    text = re.sub(r"\s+", " ", _bounded_text(value)).strip()
    if len(text) < 16:
        return frozenset(fingerprints), complete
    parts = [part.strip() for part in re.split(r"[\r\n,;]", text) if len(part.strip()) >= 16]
    words = text.split()
    parts.extend(" ".join(words[index:index + 4]) for index in range(max(0, len(words) - 3)))
    for part in parts:
        if len(fingerprints) >= MAX_FINGERPRINTS_PER_SESSION:
            complete = False
            break
        fingerprints.add(sha256(part.encode("utf-8")).hexdigest())
    return frozenset(fingerprints), complete


def _encoded_argument_fingerprints(value: Any) -> tuple[frozenset[str], bool]:
    """Decode a bounded set of commonplace transport encodings for taint matching.

    Treat budget exhaustion as incomplete rather than declaring a possibly
    encoded copy safe. No network access or arbitrary decompression.
    """
    fingerprints: set[str] = set()
    stack = [value]
    visited = 0
    candidates = 0
    total_bytes = 0
    while stack:
        if visited >= 8_192:
            return frozenset(fingerprints), False
        item = stack.pop()
        visited += 1
        if isinstance(item, dict):
            if len(item) > 1_024:
                return frozenset(fingerprints), False
            stack.extend(item.values())
            continue
        if isinstance(item, (list, tuple)):
            if len(item) > 1_024:
                return frozenset(fingerprints), False
            stack.extend(item)
            continue
        if not isinstance(item, str) or len(item) < 16:
            continue
        if len(item) > MAX_RESULT_SCAN_BYTES:
            return frozenset(fingerprints), False
        candidates += 1
        total_bytes += len(item.encode("utf-8", errors="replace"))
        if candidates > 128 or total_bytes > MAX_RESULT_SCAN_BYTES:
            return frozenset(fingerprints), False

        variants: list[str] = []
        if re.search(r"%[0-9a-fA-F]{2}", item):
            try:
                decoded = unquote(item, encoding="utf-8", errors="strict")
            except UnicodeDecodeError:
                return frozenset(fingerprints), False
            if decoded != item:
                variants.append(decoded)
        if re.fullmatch(r"[A-Za-z0-9+/_=-]{24,}", item):
            try:
                raw = base64.b64decode(
                    item + "=" * (-len(item) % 4),
                    altchars=b"-_", validate=True,
                )
                if len(raw) > MAX_RESULT_SCAN_BYTES:
                    return frozenset(fingerprints), False
                decoded = raw.decode("utf-8")
            except (ValueError, UnicodeDecodeError, binascii.Error):
                pass
            else:
                variants.append(decoded)
        for decoded in variants:
            hashes, complete = _content_fingerprints_with_coverage(decoded)
            if not complete:
                return frozenset(fingerprints), False
            fingerprints.update(hashes)
            if len(fingerprints) > MAX_FINGERPRINTS_PER_SESSION:
                return frozenset(fingerprints), False
    return frozenset(fingerprints), True


def _content_fingerprints(value: Any) -> frozenset[str]:
    return _content_fingerprints_with_coverage(value)[0]
