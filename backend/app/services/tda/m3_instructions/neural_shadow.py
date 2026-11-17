"""Optional M3 Prompt Guard 2 V3 research-only neural SHADOW signal.

Only one low-trust, raw M1 /description VALUE is scored. Source hashes
identify the exact input; predicted probabilities are MODEL_HYPOTHESIS, not
mechanical evidence, decoded attestation, a clean verdict, or permission.
No M2/M4/M6/M7 dependency is introduced; no model output changes policy.

Synchronous path is intentionally opt-in and NOT performance qualified;
keep disabled in normal Gateway/backend operation until Lot B proves
latency and resource budgets (including cold start).
"""
from __future__ import annotations

from functools import lru_cache
from hashlib import sha256
from threading import Lock
import json
import os
import time
from typing import Any

from app.core.runtime_paths import RUNTIME_MODELS_DIR
from app.services.tda.m1_sources.capture import AnalysisContext
from app.services.tda.m3_instructions.language_scope import language_scope

MODEL_ROOT = RUNTIME_MODELS_DIR / "m3_prompt_guard2_v3"
MODEL_SHA256 = "5751dd3a08fad1178d835941a8ad98e019aadcdb6dcfd54a616d9908b0204bf8"
SCHEMA = "m3-neural-shadow-prompt-guard-v3-v1"
MAX_DESCRIPTION_CHARS = 16_000
MAX_TOKEN_WINDOWS = 8
WINDOW_TOKENS = 512
STRIDE_TOKENS = 64
REFERENCE_THRESHOLD = 0.5  # reporting only; never policy or threshold tuning
_MODEL_LOAD_LOCK = Lock()  # Prevent duplicate 1.1GB loads on concurrent first calls.


def enabled() -> bool:
    """Only the explicit opt-in literal true/1 enables a model call."""
    return os.environ.get("M3_PG2_V3_SHADOW_ENABLED", "false").strip().lower() in ("true", "1")


def _verified_model() -> tuple[Any, Any, Any]:
    with _MODEL_LOAD_LOCK:
        return _load_once()


@lru_cache(maxsize=1)
def _load_once() -> tuple[Any, Any, Any]:
    # Verified once on first demand; no network, remote Python code or
    # implicit fallbacks to the original Meta model.
    from scripts.install_m3_pg2_v3 import verify_install
    verified = verify_install(MODEL_ROOT)
    if verified["weights_sha256"] != MODEL_SHA256:
        raise RuntimeError("M3_PG2_V3_MODEL_PIN_MISMATCH")
    import torch
    from transformers import AutoTokenizer, AutoModelForSequenceClassification

    tokenizer = AutoTokenizer.from_pretrained(
        MODEL_ROOT, local_files_only=True, trust_remote_code=False,
        use_fast=True,
    )
    classifier = AutoModelForSequenceClassification.from_pretrained(
        MODEL_ROOT, local_files_only=True, trust_remote_code=False,
        use_safetensors=True,
    ).to("cpu").eval()
    if classifier.config.num_labels != 2 or not getattr(tokenizer, "is_fast", False):
        raise ValueError("M3_PG2_V3_UNSUPPORTED_MODEL_CONTRACT")
    return tokenizer, classifier, torch


def _result_base(context: AnalysisContext) -> dict[str, Any]:
    return {
        "schema": SCHEMA,
        "mode": "SHADOW",
        "authority": "NONE",
        "model": "PROMPT_GUARD_2_86M_V3",
        "model_sha256": MODEL_SHA256,
        "source_pointer": "/description",
        "source_view_id": context.original.view_id,
        "source_sha256": context.original.sha256,
        "source_kind": "M1_RAW_VALUE",
        "input_text_sha256": None,
        "status": "NOT_ANALYZED",
        "reason": "UNKNOWN",
        "score": None,
        "score_support": "MODEL_HYPOTHESIS_ONLY",
        "reference_threshold_not_policy": REFERENCE_THRESHOLD,
        "windows_analyzed": 0,
        "token_window_max": WINDOW_TOKENS,
        "token_windows_omitted": False,
        "language_heuristic_not_certification": True,
        "coverage_complete": False,
        "clean_verdict": False,
        "mechanical_evidence": False,
        "creates_permissions": False,
        "security_decision_changes": "NONE",
        "runtime_contract_verified": False,
    }


def run_v3_neural_shadow(context: AnalysisContext) -> dict[str, Any]:
    """Score an attested M1 raw description, never derived model text.

    This function must be called only after explicit opt-in; failures are
    returned as non-authoritative ERROR/NOT_ANALYZED rather than hidden CLEAN.
    """
    if not isinstance(context, AnalysisContext):
        raise ValueError("M3_PG2_REQUIRES_M1_ANALYSIS_CONTEXT")
    answer = _result_base(context)
    if not enabled():
        answer["reason"] = "OPT_IN_DISABLED"
        return answer
    begun = time.perf_counter()
    try:
        snapshot = json.loads(context.original.json_bytes)
        if not isinstance(snapshot, dict):
            answer["reason"] = "SOURCE_NOT_TOOL_OBJECT"
            return answer
        description = snapshot.get("description")
        if not isinstance(description, str) or not description.strip():
            answer["reason"] = "RAW_DESCRIPTION_ABSENT_OR_EMPTY"
            return answer
        # Ensure the same text is in the M1 source inventory, not an
        # ad-hoc normalized or model-generated surrogate.
        candidates = [
            field for field in context.source_fields
            if field.pointer == "/description" and field.text == description
        ]
        if len(candidates) != 1:
            answer["reason"] = "M1_RAW_DESCRIPTION_NOT_ATTESTED"
            return answer
        answer["input_text_sha256"] = sha256(description.encode("utf8")).hexdigest()
        answer["input_chars"] = len(description)
        if len(description) > MAX_DESCRIPTION_CHARS:
            answer["reason"] = "DESCRIPTION_CHARACTER_BUDGET"
            return answer

        # Existing M3 language heuristic only provides positive cues,
        # NOT a certified language-ID. Unknown and non-English fail closed
        # as not analyzed, never reported benign.
        scope = language_scope(description)
        answer["language_scope"] = scope
        if scope != "ENGLISH_POSITIVE_CUES_NOT_CERTIFIED":
            answer["reason"] = "ENGLISH_SCOPE_UNVERIFIED"
            return answer

        tokenizer, classifier, torch = _verified_model()
        tokens = tokenizer(
            description, add_special_tokens=True,
            truncation=True, max_length=WINDOW_TOKENS, stride=STRIDE_TOKENS,
            return_overflowing_tokens=True, return_attention_mask=True,
        )
        # Never truncate silently. An over-budget record is UNKNOWN rather
        # than a falsely complete scan of the initial windows.
        ids = tokens["input_ids"]
        if not ids or len(ids) > MAX_TOKEN_WINDOWS:
            answer["reason"] = "TOKEN_WINDOW_BUDGET"
            answer["token_windows_omitted"] = bool(ids)
            return answer
        answer["total_windows"] = len(ids)
        scores: list[float] = []
        with torch.inference_mode():
            for index in range(0, len(ids), 4):
                windows = ids[index:index + 4]
                # Respect the model's 512-token cap and preserve exact
                # token IDs; do not decode/rewrite the raw source.
                batch = tokenizer.pad(
                    {"input_ids": windows},
                    padding=True, return_tensors="pt",
                )
                if batch["input_ids"].shape[1] > WINDOW_TOKENS:
                    raise ValueError("M3_PG2_WINDOW_EXCEEDS_512")
                logits = classifier(**batch).logits.float()
                probabilities = torch.softmax(logits, dim=1)[:, 1].tolist()
                if len(probabilities) != len(windows):
                    raise ValueError("M3_PG2_BATCH_OUTPUT_SHAPE")
                scores.extend(float(value) for value in probabilities)
        if not scores or not all(0 <= value <= 1 for value in scores):
            raise ValueError("M3_PG2_INVALID_INFERENCE_SCORE")
        answer.update({
            "status": "SCORED",
            "reason": "ADVISORY_MODEL_HYPOTHESIS_NOT_MALICIOUS_INTENT_PROOF",
            "score": max(scores),
            "windows_analyzed": len(scores),
            "coverage_complete": True,
            # The classifier does not provide token-localized evidence.
            "exact_attack_offsets": None,
        })
        return answer
    except Exception as exc:  # Never propagate an optional shadow-model failure.
        answer["status"] = "ERROR"
        answer["reason"] = "MODEL_SHADOW_ERROR_" + type(exc).__name__
        return answer
    finally:
        answer["elapsed_ms"] = round((time.perf_counter() - begun) * 1000, 3)
