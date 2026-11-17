"""Private process transport for M3 Prompt Guard 2 V3 research SHADOW.

Persistent child avoids 1.1 GB model reload on every description. Only the
single async queue worker calls execute(), never the Gateway request thread.
Hard deadline kills the child and drops its results; subsequent work launches
a fresh child. This is crash/process isolation, NOT a memory or OS sandbox.
"""
from __future__ import annotations

import atexit
import json
import os
from pathlib import Path
from queue import Empty, Queue
import subprocess
import sys
from threading import Lock, Thread
from typing import Any
from uuid import uuid4

from app.services.tda.m1_sources.capture import AnalysisContext
from app.services.tda.m3_instructions.neural_shadow_worker_process import PREFIX

ROOT = Path(__file__).resolve().parents[5]   # repository root, backend/app/services/tda/...
BACKEND = ROOT / "backend"
PROTOCOL = "m3-pg2-v3-local-ipc-v1"
MAX_RESPONSE_BYTES = 16 * 1024
MAX_REQUEST_BYTES = 320 * 1024
CHILD_TIMEOUT_SECONDS = 90.0


class IsolatedShadowWorkerFailure(RuntimeError):
    """No raw input or stdout attached to failures."""


class ProcessClient:
    def __init__(self) -> None:
        self._lock = Lock()
        self._child: subprocess.Popen[bytes] | None = None
        self._response_queue: Queue[bytes | None] | None = None
        self._owner_pid = os.getpid()
        self._last_tree_kill_confirmed: bool | None = None

    def _close_locked(self) -> None:
        child = self._child
        self._child = None
        self._response_queue = None
        if child is None:
            return
        self._last_tree_kill_confirmed = None
        try:
            if child.poll() is None:
                if os.name == "nt" and isinstance(child, subprocess.Popen):
                    # Windows venv python.exe can be a small redirector that
                    # launches the real Python/PyTorch interpreter as a child.
                    # Killing only Popen.pid would leave that model process
                    # running after a hard timeout. Kill the entire tree.
                    try:
                        completed = subprocess.run(
                            ["taskkill", "/PID", str(child.pid), "/T", "/F"],
                            stdout=subprocess.DEVNULL,
                            stderr=subprocess.DEVNULL,
                            timeout=8, check=False, shell=False,
                            creationflags=subprocess.CREATE_NO_WINDOW,
                        )
                        self._last_tree_kill_confirmed = completed.returncode == 0
                    except (OSError, subprocess.TimeoutExpired):
                        self._last_tree_kill_confirmed = False
                if child.poll() is None:
                    # Fallback is only a parent kill, NEVER proof of a
                    # descendant-tree termination.
                    child.kill()
            child.wait(timeout=2)
        except (OSError, subprocess.TimeoutExpired):
            pass
        try:
            if child.stdin:
                child.stdin.close()
            if child.stdout:
                child.stdout.close()
        except OSError:
            pass

    def close(self) -> None:
        with self._lock:
            self._close_locked()

    def _ensure_locked(self) -> tuple[subprocess.Popen[bytes], Queue[bytes | None]]:
        if self._owner_pid != os.getpid():
            # Child pipes and locks from a forked host are never reused.
            self._child = None
            self._response_queue = None
            self._owner_pid = os.getpid()
        if self._child is not None and self._child.poll() is not None:
            self._close_locked()
        if self._child is None:
            env = {
                key: value for key, value in os.environ.items()
                if key.upper() in {
                    "SYSTEMROOT", "WINDIR", "PATH", "PATHEXT", "COMSPEC",
                    "TEMP", "TMP", "TMPDIR", "HOME", "USERPROFILE",
                    "LOCALAPPDATA", "APPDATA", "PROGRAMDATA",
                    "SYSTEMDRIVE", "VIRTUAL_ENV", "LANG", "LC_ALL",
                }
            }
            env.update({
                "PYTHONPATH": os.pathsep.join((str(BACKEND), str(ROOT))),
                "M3_PG2_V3_SHADOW_ENABLED": "true",
                "M3_PG2_CHILD_TORCH_THREADS": "4",
                "HF_HUB_OFFLINE": "1",
                "TRANSFORMERS_OFFLINE": "1",
                "TOKENIZERS_PARALLELISM": "false",
                "PYTHONUNBUFFERED": "1",
            })
            flags = subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0
            child = subprocess.Popen(
                [sys.executable, "-u", "-m",
                 "app.services.tda.m3_instructions.neural_shadow_worker_process"],
                cwd=str(ROOT), env=env,
                stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL, shell=False,
                creationflags=flags, bufsize=0, close_fds=True,
            )
            assert child.stdout is not None
            queue: Queue[bytes | None] = Queue(maxsize=2)

            def _reader() -> None:
                try:
                    while True:
                        reply = child.stdout.readline(MAX_RESPONSE_BYTES + 1)
                        if not reply:
                            break
                        try:
                            queue.put_nowait(reply)
                        except Exception:
                            break
                        if len(reply) > MAX_RESPONSE_BYTES:
                            break
                except (OSError, ValueError):
                    pass
                finally:
                    try:
                        queue.put_nowait(None)
                    except Exception:
                        pass

            Thread(target=_reader, daemon=True,
                   name="m3-pg2-v3-process-stdout").start()
            self._child = child
            self._response_queue = queue
        assert self._child is not None and self._response_queue is not None
        return self._child, self._response_queue

    def execute(
        self, context: AnalysisContext, *, timeout_seconds: float = CHILD_TIMEOUT_SECONDS,
    ) -> dict[str, Any]:
        if not 0 < timeout_seconds <= CHILD_TIMEOUT_SECONDS:
            raise IsolatedShadowWorkerFailure("INVALID_TIMEOUT")
        if len(context.original.json_bytes) > 256 * 1024:
            raise IsolatedShadowWorkerFailure("ORIGINAL_TOO_LARGE")
        texts = [
            field.text for field in context.source_fields
            if field.pointer == "/description"
        ]
        if len(texts) != 1:
            raise IsolatedShadowWorkerFailure("M1_INPUT_NOT_BOUND")
        nonce = uuid4().hex
        packet = {
            "op": "score", "nonce": nonce,
            "source_json": context.original.json_bytes.decode("utf8"),
            "source_sha256": context.original.sha256,
            "input_text_sha256": __import__("hashlib").sha256(
                texts[0].encode("utf8")).hexdigest(),
        }
        data = (json.dumps(packet, ensure_ascii=True, separators=(",",":"))
                + "\n").encode("utf8")
        if len(data) > MAX_REQUEST_BYTES:
            raise IsolatedShadowWorkerFailure("REQUEST_EXCEEDS_IPC_BUDGET")
        with self._lock:
            try:
                child, responses = self._ensure_locked()
                assert child.stdin is not None
                child.stdin.write(data)
                child.stdin.flush()
                try:
                    reply = responses.get(timeout=timeout_seconds)
                except Empty:
                    raise IsolatedShadowWorkerFailure("HARD_TIMEOUT_CHILD_KILLED")
                if reply is None or len(reply) > MAX_RESPONSE_BYTES or not reply.startswith(PREFIX.encode()):
                    raise IsolatedShadowWorkerFailure("IPC_WORKER_TERMINATED_OR_PROTOCOL_INVALID")
                payload = json.loads(reply[len(PREFIX):])
                if (not isinstance(payload, dict)
                        or payload.get("protocol") != PROTOCOL
                        or payload.get("nonce") != nonce
                        or not isinstance(payload.get("result"), dict)):
                    raise IsolatedShadowWorkerFailure("IPC_REPLY_NONCE_OR_RESULT_INVALID")
                return payload["result"]
            except (OSError, ValueError, TypeError, json.JSONDecodeError,
                    IsolatedShadowWorkerFailure) as exc:
                self._close_locked()
                if isinstance(exc, IsolatedShadowWorkerFailure):
                    if (str(exc) == "HARD_TIMEOUT_CHILD_KILLED"
                            and os.name == "nt"
                            and self._last_tree_kill_confirmed is False):
                        raise IsolatedShadowWorkerFailure(
                            "HARD_TIMEOUT_TREE_KILL_NOT_CONFIRMED"
                        ) from None
                    raise
                raise IsolatedShadowWorkerFailure("IPC_TRANSPORT_FAILURE") from None

    def info(self) -> dict[str, int | bool | None]:
        with self._lock:
            alive = self._child is not None and self._child.poll() is None
            return {
                "subprocess_alive": alive,
                "subprocess_pid": self._child.pid if alive else None,
                "torch_threads_per_child": 4,
                "hard_inference_timeout_seconds": CHILD_TIMEOUT_SECONDS,
                "kill_child_on_hard_timeout": True,
                "windows_tree_kill_on_timeout": os.name == "nt",
                "last_tree_kill_confirmed": self._last_tree_kill_confirmed,
                "memory_hard_limit_enforced": False,
                "os_privilege_sandbox": False,
            }


_CLIENT = ProcessClient()
atexit.register(_CLIENT.close)


def score_in_isolated_process(context: AnalysisContext) -> dict[str, Any]:
    return _CLIENT.execute(context)


def isolated_worker_health() -> dict[str, int | bool | None]:
    return _CLIENT.info()
