from __future__ import annotations


TRUSTED_SERVER_STATES = frozenset({"trusted", "lab_trusted"})


def is_trusted_server_status(value: object) -> bool:
    return isinstance(value, str) and value in TRUSTED_SERVER_STATES
