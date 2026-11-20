"""Local read-only CLI: discover AWS SDK operations and preview IAM candidates.

Example:
  python scripts/probe_cloud_iam_static.py --root . --source mcp-lab/aws_s3_document_server/server.py

Parses Python AST only, never imports/executes MCP source or accesses AWS IAM.
Results cannot be used as an approved mapping.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "backend"))

from app.services.cloud_iam_static_discovery import (  # noqa: E402
    DiscoveryError, analyze_python_project,
)
from app.services.cloud_iam_operation_catalog import (  # noqa: E402
    CatalogError, candidate_preview, dynamic_sdk_candidate_preview,
)
from app.services.cloud_iam_dynamic_discovery import (  # noqa: E402
    DynamicDiscoveryError, discover_dynamic_sdk_tools,
)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, default=ROOT,
                        help="Local source root; imported modules must be inside this root")
    parser.add_argument("--source", type=Path, required=True,
                        help="Python MCP entry file relative to --root")
    parser.add_argument("--raw", action="store_true",
                        help="Show source observations only, without offline IAM suggestions")
    parser.add_argument("--dynamic-sdk", action="store_true",
                        help="Also inspect SDK-generated tool candidates using locally installed botocore")
    options = parser.parse_args()
    root = options.root.resolve()
    source = (root / options.source).resolve()
    try:
        report = analyze_python_project(source, root)
        result = report if options.raw else candidate_preview(report)
        if options.dynamic_sdk:
            dynamic = discover_dynamic_sdk_tools(root, source)
            if options.raw:
                result["dynamic_sdk"] = dynamic
            else:
                result["dynamic_sdk"] = dynamic_sdk_candidate_preview(dynamic)
            # A static report cannot establish that SDK candidates are
            # exposed, version-matched or reviewed.
            result["audit_eligible"] = False
            result["mapping_approved"] = False
    except (DiscoveryError, DynamicDiscoveryError, CatalogError,
            OSError, SyntaxError, UnicodeError) as exc:
        print(json.dumps({"error": type(exc).__name__, "reason": str(exc)}),
              file=sys.stderr)
        return 2
    print(json.dumps(result, ensure_ascii=True, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
