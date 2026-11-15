"""Bound the guarantees of local security-state storage.

File locks and SQLite files are coherent only for cooperating workers sharing
one trusted local filesystem. A declared multi-host deployment must use a
separately implemented and verified distributed authority; it cannot inherit
local-only guarantees. The unset value retains existing single-host semantics.
"""

import os


def local_security_authority_supported() -> bool:
    return os.environ.get(
        "MCP_SECURITY_DEPLOYMENT_TOPOLOGY", "single_host"
    ) == "single_host"
