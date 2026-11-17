"""Bounded, opt-in, research-only Prompt Guard 2 V3 async SHADOW queue.

A local daemon orchestrator submits to a persistent, separate inference
subprocess with hard 90-second kill on timeout. Model loading runs outside the
Gateway process, with four Torch threads in child only. No model score can
affect policy. This is still NOT an OS privilege or memory-hard-limit sandbox.
Tickets/results are process-local and ephemeral, not durable across restart.
"""
from __future__ import annotations

from collections import OrderedDict
from dataclasses import dataclass
from hashlib import sha256
import math
import json
import os
from queue import Full, Queue
from threading import Lock, Thread
import time
from typing import Any
from uuid import uuid4

from app.services.tda.m1_sources.capture import AnalysisContext
from app.services.tda.m3_instructions.language_scope import language_scope
from app.services.tda.m3_instructions.neural_shadow import (
    _result_base, enabled,
    MODEL_SHA256 as EXPECTED_MODEL_SHA256, SCHEMA as EXPECTED_RESULT_SCHEMA,
)
from app.services.tda.m3_instructions.neural_shadow_process_transport import (
    score_in_isolated_process, isolated_worker_health,
)

MAX_QUEUE = 8
MAX_RESULTS = 64
MAX_SOURCE_BYTES = 256 * 1024
MAX_DESCRIPTION_CHARS = 16_000
JOB_DEADLINE_SECONDS = 90.0
RESULT_TTL_SECONDS = 600.0
SCHEMA = "m3-neural-shadow-async-v3-research-v1"


@dataclass(frozen=True)
class _Job:
    job_id: str
    context: AnalysisContext
    submitted_at: float
    deadline: float


def _timeout_view(state: dict[str, Any]) -> dict[str, Any]:
    result = dict(state)
    result.update({
        "status": "TIMED_OUT",
        "reason": "DEADLINE_EXCEEDED_RESULT_NOT_TRUSTED",
        "score": None,
        "coverage_complete": False,
        "clean_verdict": False,
        "creates_permissions": False,
        "security_decision_changes": "NONE",
        "soft_timeout_does_not_cancel_worker": True,
    })
    return result


def _valid_worker_result(result: Any, pending: dict[str, Any]) -> bool:
    """Do not let untrusted/buggy model output impersonate provenance or policy."""
    if not isinstance(result, dict):
        return False
    for name in (
        "source_sha256", "source_view_id", "input_text_sha256",
        "source_pointer", "model_sha256",
    ):
        if result.get(name) != pending.get(name):
            return False
    if (result.get("schema") != EXPECTED_RESULT_SCHEMA
            or result.get("model_sha256") != EXPECTED_MODEL_SHA256
            or result.get("source_pointer") != "/description"
            or result.get("source_kind") != "M1_RAW_VALUE"
            or result.get("authority") != "NONE"
            or result.get("mechanical_evidence") is not False
            or result.get("clean_verdict") is not False
            or result.get("creates_permissions") is not False
            or result.get("security_decision_changes") != "NONE"):
        return False
    status = result.get("status")
    if status not in ("SCORED", "ERROR", "NOT_ANALYZED"):
        return False
    score = result.get("score")
    if status == "SCORED":
        return (
            isinstance(score, (float, int)) and not isinstance(score, bool)
            and math.isfinite(score) and 0 <= score <= 1
            and result.get("coverage_complete") is True
            and result.get("exact_attack_offsets") is None
            and isinstance(result.get("windows_analyzed"), int)
            and 1 <= result["windows_analyzed"] <= 8
        )
    return score is None and result.get("coverage_complete") is False


def _preflight(context: AnalysisContext) -> tuple[dict[str, Any], bool]:
    """No model/torch/tokenizer access. Only validated immutable M1 source."""
    if not isinstance(context, AnalysisContext):
        raise ValueError("M3_ASYNC_REQUIRES_M1_CONTEXT")
    answer = _result_base(context)
    answer.update({
        "async_schema": SCHEMA,
        "execution_kind": "PROCESS_LOCAL_BOUNDED_SHADOW_WORKER",
        "job_id": None,
        "result_lookup_scope": "SAME_PROCESS_SOURCE_SHA_BOUND",
        "results_persist_across_restart": False,
        "soft_timeout_does_not_cancel_worker": True,
    })
    if not enabled():
        answer["reason"] = "OPT_IN_DISABLED"
        return answer, False
    memory = sum(len(part or b"") for part in (
        context.original.json_bytes,
        context.profile_json,
        context.baseline_json,
    ))
    if memory > MAX_SOURCE_BYTES:
        answer["reason"] = "SOURCE_CONTEXT_MEMORY_BUDGET"
        return answer, False
    try:
        snapshot = json.loads(context.original.json_bytes)
        if not isinstance(snapshot, dict):
            answer["reason"] = "SOURCE_NOT_TOOL_OBJECT"
            return answer, False
        description = snapshot.get("description")
        if not isinstance(description, str) or not description.strip():
            answer["reason"] = "RAW_DESCRIPTION_ABSENT_OR_EMPTY"
            return answer, False
        matches = [
            field for field in context.source_fields
            if field.pointer == "/description" and field.text == description
        ]
        if len(matches) != 1:
            answer["reason"] = "M1_RAW_DESCRIPTION_NOT_ATTESTED"
            return answer, False
        answer["input_text_sha256"] = sha256(description.encode("utf8")).hexdigest()
        answer["input_chars"] = len(description)
        if len(description) > MAX_DESCRIPTION_CHARS:
            answer["reason"] = "DESCRIPTION_CHARACTER_BUDGET"
            return answer, False
        scope = language_scope(description)
        answer["language_scope"] = scope
        if scope != "ENGLISH_POSITIVE_CUES_NOT_CERTIFIED":
            answer["reason"] = "ENGLISH_SCOPE_UNVERIFIED"
            return answer, False
        return answer, True
    except (TypeError, ValueError, KeyError, OSError):
        answer["status"] = "ERROR"
        answer["reason"] = "ASYNC_PREFLIGHT_INVALID_M1_SOURCE"
        return answer, False


class _AsyncRuntime:
    """Private bounded state machine; separate instances allow isolated QA."""

    def __init__(
        self,
        *,
        queue_capacity: int = MAX_QUEUE,
        result_capacity: int = MAX_RESULTS,
        deadline_seconds: float = JOB_DEADLINE_SECONDS,
        ttl_seconds: float = RESULT_TTL_SECONDS,
    ):
        if (not 1 <= queue_capacity <= MAX_QUEUE
                or not 1 <= result_capacity <= MAX_RESULTS
                or not 0 < deadline_seconds <= JOB_DEADLINE_SECONDS
                or not 0 < ttl_seconds <= RESULT_TTL_SECONDS):
            raise ValueError("M3_ASYNC_INVALID_RESOURCE_LIMIT")
        self.queue_capacity = queue_capacity
        self.result_capacity = result_capacity
        self.deadline_seconds = deadline_seconds
        self.ttl_seconds = ttl_seconds
        self._queue: Queue[_Job] = Queue(maxsize=queue_capacity)
        self._results: OrderedDict[str, tuple[float, dict[str, Any]]] = OrderedDict()
        self._lock = Lock()
        self._worker: Thread | None = None
        self._pid = os.getpid()

    def _evict_locked(self, now: float) -> None:
        # Retention is measured since original submission, not last read.
        for identifier, (submitted, _) in list(self._results.items()):
            if now - submitted >= self.ttl_seconds:
                self._results.pop(identifier, None)
        while len(self._results) > self.result_capacity:
            self._results.popitem(last=False)

    def _start_worker_locked(self) -> None:
        if self._worker is None or not self._worker.is_alive():
            self._worker = Thread(
                target=self._work_forever,
                name="m3-pg2-v3-shadow-research-worker",
                daemon=True,
            )
            self._worker.start()

    @staticmethod
    def _execute(context: AnalysisContext) -> dict[str, Any]:
        # Model and tokenizer load exclusively in a separate subprocess.
        # A hard timeout forcibly kills the child rather than wedging TDA.
        return score_in_isolated_process(context)

    def _work_forever(self) -> None:
        while True:
            job = self._queue.get()
            try:
                with self._lock:
                    stored = self._results.get(job.job_id)
                    if stored is None:
                        continue
                    submitted, previous = stored
                    if previous["status"] not in ("PENDING", "RUNNING"):
                        continue
                    now = time.monotonic()
                    if now >= job.deadline:
                        self._results[job.job_id] = (submitted, _timeout_view(previous))
                        continue
                    running = dict(previous)
                    running["status"] = "RUNNING"
                    running["reason"] = "WORKER_INFERENCE_PENDING"
                    self._results[job.job_id] = (submitted, running)
                scored = self._execute(job.context)
                with self._lock:
                    stored = self._results.get(job.job_id)
                    if stored is None or stored[1]["status"] != "RUNNING":
                        continue
                    submitted, previous = stored
                    if time.monotonic() >= job.deadline:
                        final = _timeout_view(previous)
                    elif not _valid_worker_result(scored, previous):
                        final = dict(previous)
                        final.update({
                            "status": "ERROR",
                            "reason": "SHADOW_RESULT_CONTRACT_MISMATCH",
                            "score": None,
                            "coverage_complete": False,
                        })
                    else:
                        final = dict(scored)
                        final.update({
                            "async_schema": SCHEMA,
                            "execution_kind": "PROCESS_LOCAL_BOUNDED_SHADOW_WORKER",
                            "job_id": job.job_id,
                            "result_lookup_scope": "SAME_PROCESS_SOURCE_SHA_BOUND",
                            "results_persist_across_restart": False,
                            "soft_timeout_does_not_cancel_worker": False,
                        })
                    self._results[job.job_id] = (submitted, final)
                    self._evict_locked(time.monotonic())
            except BaseException:
                # Never expose exception messages (which may include input).
                # The worker remains alive, and the main policy is unaffected.
                with self._lock:
                    stored = self._results.get(job.job_id)
                    if stored is not None:
                        submitted, previous = stored
                        if previous["status"] in ("PENDING", "RUNNING"):
                            failure = dict(previous)
                            failure.update({
                                "status": "ERROR",
                                "reason": "SHADOW_WORKER_EXCEPTION",
                                "score": None,
                                "coverage_complete": False,
                                "clean_verdict": False,
                            })
                            self._results[job.job_id] = (submitted, failure)
            finally:
                self._queue.task_done()

    def submit(self, context: AnalysisContext) -> dict[str, Any]:
        """Never wait for model, tokenizer or a full queue slot."""
        answer, permitted = _preflight(context)
        if not permitted:
            return answer
        identifier = uuid4().hex
        now = time.monotonic()
        answer.update({
            "status": "PENDING",
            "reason": "QUEUED_ASYNC_MODEL_HYPOTHESIS_NOT_YET_AVAILABLE",
            "score": None,
            "job_id": identifier,
            "job_deadline_seconds": self.deadline_seconds,
            "coverage_complete": False,
        })
        job = _Job(identifier, context, now, now + self.deadline_seconds)
        with self._lock:
            if self._pid != os.getpid():
                # Never reuse pre-fork process-local results or dead worker.
                self._queue = Queue(maxsize=self.queue_capacity)
                self._results = OrderedDict()
                self._worker = None
                self._pid = os.getpid()
            self._evict_locked(now)
            if len(self._results) >= self.result_capacity:
                answer.update({
                    "status": "NOT_ANALYZED",
                    "reason": "ASYNC_RESULT_STORE_CAPACITY",
                    "job_id": None,
                })
                return answer
            self._results[identifier] = (now, dict(answer))
            try:
                self._queue.put_nowait(job)
            except Full:
                self._results.pop(identifier, None)
                answer.update({
                    "status": "NOT_ANALYZED",
                    "reason": "ASYNC_QUEUE_FULL",
                    "job_id": None,
                })
                return answer
            try:
                self._start_worker_locked()
            except (OSError, RuntimeError):
                # Orphaned queue entry will be discarded if worker restarts.
                self._results.pop(identifier, None)
                answer.update({
                    "status": "NOT_ANALYZED",
                    "reason": "ASYNC_WORKER_START_FAILED",
                    "job_id": None,
                })
                return answer
        return answer

    def lookup(self, job_id: str, *, source_sha256: str) -> dict[str, Any] | None:
        """Read-only same-process accessor, no new API or auth capability."""
        if not isinstance(job_id, str) or len(job_id) != 32:
            return None
        if not isinstance(source_sha256, str) or len(source_sha256) != 64:
            return None
        with self._lock:
            now = time.monotonic()
            self._evict_locked(now)
            stored = self._results.get(job_id)
            if stored is None:
                return None
            submitted, previous = stored
            if previous.get("source_sha256") != source_sha256:
                return None
            answer = dict(previous)
            if (answer["status"] in ("PENDING", "RUNNING")
                    and now >= submitted + self.deadline_seconds):
                answer = _timeout_view(answer)
                self._results[job_id] = (submitted, dict(answer))
            return answer

    def list_jobs_for_admin(self) -> list[dict[str, Any]]:
        """Ephemeral same-process research view; never expose raw tool text."""
        with self._lock:
            self._evict_locked(time.monotonic())
            return [
                {
                    "job_id": job_id,
                    "source_sha256": value.get("source_sha256"),
                    "input_text_sha256": value.get("input_text_sha256"),
                    "status": value.get("status"),
                    "reason": value.get("reason"),
                    "score": value.get("score") if value.get("status") == "SCORED" else None,
                    "score_support": "MODEL_HYPOTHESIS_ONLY",
                    "authority": "NONE",
                    "model_sha256": value.get("model_sha256"),
                    "mode": "SHADOW",
                }
                for job_id, (_, value) in reversed(self._results.items())
            ]

    def health(self) -> dict[str, int | bool]:
        with self._lock:
            self._evict_locked(time.monotonic())
            return {
                "queue_depth": self._queue.qsize(),
                "queue_capacity": self.queue_capacity,
                "result_store_count": len(self._results),
                "result_store_capacity": self.result_capacity,
                "one_daemon_worker_alive": bool(self._worker and self._worker.is_alive()),
                "hard_process_isolation": True,
                "hard_memory_limit_enforced": False,
            }


_DEFAULT = _AsyncRuntime()


def submit_v3_neural_shadow(context: AnalysisContext) -> dict[str, Any]:
    # Optional SHADOW failures must never escape into deterministic policy.
    try:
        return _DEFAULT.submit(context)
    except Exception:
        report = _result_base(context)
        report.update({
            "async_schema": SCHEMA,
            "status": "ERROR",
            "reason": "ASYNC_SUBMISSION_EXCEPTION",
            "score": None,
            "coverage_complete": False,
            "clean_verdict": False,
            "security_decision_changes": "NONE",
            "creates_permissions": False,
            "job_id": None,
        })
        return report


def lookup_v3_neural_shadow_job(
    job_id: str, *, source_sha256: str,
) -> dict[str, Any] | None:
    return _DEFAULT.lookup(job_id, source_sha256=source_sha256)


def async_shadow_queue_health() -> dict[str, int | bool | None]:
    # Read-only operational status. Never returns tool text or secrets.
    return {**_DEFAULT.health(), **isolated_worker_health()}


def list_v3_neural_shadow_jobs_for_admin() -> list[dict[str, Any]]:
    # The HTTP authorization boundary must be applied by the caller.
    return _DEFAULT.list_jobs_for_admin()
