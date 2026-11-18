"""Private stdin/stdout IPC worker for M3 Prompt Guard 2 V3 SHADOW.

This module is executed only as a separate local subprocess via python -m.
It never accepts client connections or credentials and never grants policy
authority. One JSON request per line, one size-bounded JSON reply. The parent
owns process lifetime, hard timeout, result provenance and authorization.

The worker uses four PyTorch intra-op CPU threads, scoped to this process.
No training, no remote code, no Hugging Face network access at inference.
"""
from __future__ import annotations

from hashlib import sha256
from dataclasses import replace
import re
import json
import os
import sys

MAX_LINE_BYTES = 320 * 1024
PREFIX = "M3PG2_V3_RESULT:"
MAX_REPLY_CHARS = 12_000


def _reply(nonce: str, *, result: dict | None = None, reason: str | None = None) -> None:
    message: dict = {"protocol": "m3-pg2-v3-local-ipc-v1", "nonce": nonce}
    if result is not None:
        message["result"] = result
    else:
        message["error"] = reason or "UNSPECIFIED"
    response = json.dumps(message, ensure_ascii=True, allow_nan=False,
                          separators=(",", ":"))
    if len(response) > MAX_REPLY_CHARS:
        response = json.dumps({
            "protocol": "m3-pg2-v3-local-ipc-v1", "nonce": nonce,
            "error": "RESPONSE_SIZE_LIMIT",
        }, separators=(",", ":"))
    sys.stdout.write(PREFIX + response + "\n")
    sys.stdout.flush()


def _handle(line: bytes) -> None:
    try:
        envelope = json.loads(line.decode("utf8"))
        if not isinstance(envelope, dict) or envelope.get("op") != "score":
            _reply("", reason="INVALID_REQUEST_FORMAT")
            return
        nonce = envelope.get("nonce")
        raw = envelope.get("source_json")
        expected_source = envelope.get("source_sha256")
        expected_view = envelope.get("source_view_id")
        expected_text = envelope.get("input_text_sha256")
        if not (isinstance(nonce, str) and len(nonce) == 32
                and all(ch in "0123456789abcdef" for ch in nonce)
                and isinstance(raw, str) and len(raw.encode("utf8")) <= 256 * 1024
                and isinstance(expected_source, str) and len(expected_source) == 64
                and isinstance(expected_view, str)
                and re.fullmatch(r"original:[0-9a-f]{64}", expected_view) is not None
                and isinstance(expected_text, str) and len(expected_text) == 64):
            _reply("", reason="INVALID_REQUEST_SOURCE")
            return

        from app.services.tda.m1_sources.capture import capture_context

        snapshot = json.loads(raw)
        if not isinstance(snapshot, dict):
            _reply(nonce, reason="INVALID_TOOL_SNAPSHOT")
            return
        context = capture_context(snapshot)
        description = snapshot.get("description")
        if (not isinstance(description, str)
                or sha256(description.encode("utf8")).hexdigest() != expected_text
                or context.original.sha256 != expected_source):
            _reply(nonce, reason="M1_SOURCE_SHA_MISMATCH")
            return
        # The original M1 view id is bound to the parent profile/baseline
        # context, which is deliberately NOT sent to this raw-text classifier.
        # Preserve that parent-supplied correlation only AFTER verifying
        # the exact raw JSON and /description hashes, so model output cannot
        # invent or transplant a source view across IPC.
        context = replace(context,
            context_id=expected_view.removeprefix("original:"),
            original=replace(context.original, view_id=expected_view))
        from app.services.tda.m3_instructions.neural_shadow import run_v3_neural_shadow

        scored = run_v3_neural_shadow(context)
        _reply(nonce, result=scored)
    except (ValueError, TypeError, OSError, KeyError, UnicodeError, ImportError):
        _reply("", reason="WORKER_INPUT_ERROR")
    except BaseException:
        _reply("", reason="WORKER_INTERNAL_ERROR")


def main() -> int:
    import torch
    threads = int(os.environ.get("M3_PG2_CHILD_TORCH_THREADS", "4"))
    if threads not in (4, 8):
        raise RuntimeError("M3_PG2_WORKER_CPU_THREADS_MUST_BE_4_OR_8")
    torch.set_num_threads(threads)
    torch.set_num_interop_threads(1)
    if os.environ.get("M3_PG2_V3_SHADOW_ENABLED", "").strip().lower() not in ("true", "1"):
        raise RuntimeError("M3_PG2_SHADOW_WORKER_NOT_OPTED_IN")
    while True:
        line = sys.stdin.buffer.readline(MAX_LINE_BYTES + 1)
        if not line:
            return 0
        if len(line) > MAX_LINE_BYTES:
            return 2
        _handle(line)


if __name__ == "__main__":
    raise SystemExit(main())
