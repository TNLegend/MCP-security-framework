from __future__ import annotations

import ast
import json
import re
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
REQUIREMENTS = ROOT / "backend" / "requirements.txt"

IMPORT_TO_DISTRIBUTION = {
    "argon2": "argon2-cffi",
    "cryptography": "cryptography",
    "dotenv": "python-dotenv",
    "fastapi": "fastapi",
    "httpx": "httpx",
    "huggingface_hub": "huggingface-hub",
    "jsonschema": "jsonschema",
    "jwt": "pyjwt",
    "mcp_types": "mcp-types",
    "psycopg": "psycopg",
    "pydantic": "pydantic",
    "pydantic_settings": "pydantic-settings",
    "requests": "requests",
    "rfc8785": "rfc8785",
    "sentence_transformers": "sentence-transformers",
    "sqlalchemy": "sqlalchemy",
    "torch": "torch",
    "transformers": "transformers",
    "uvicorn": "uvicorn",
    "yaml": "pyyaml",
}

PRODUCTION_DIRS = (
    ROOT / "backend" / "app",
    ROOT / "proxy",
    ROOT / "agent",
    ROOT / "common",
    ROOT / "mcp-lab",
    ROOT / "scripts",
    ROOT / "scanners",
)

LOCAL_IMPORT_ROOTS = {
    "app",
    "proxy",
    "agent",
    "common",
    "scripts",
    "scanners",
    "server",
}


def requirement_names() -> set[str]:
    result: set[str] = set()
    for line in REQUIREMENTS.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        name = re.split(r"[<>=!~\[]", stripped, maxsplit=1)[0]
        result.add(name.lower().replace("_", "-"))
    return result


def direct_third_party_imports() -> set[str]:
    result: set[str] = set()
    stdlib = set(sys.stdlib_module_names)
    for directory in PRODUCTION_DIRS:
        for path in directory.rglob("*.py"):
            if "tests" in path.parts or "__pycache__" in path.parts:
                continue
            tree = ast.parse(path.read_text(encoding="utf-8"))
            for node in ast.walk(tree):
                modules: list[str] = []
                if isinstance(node, ast.Import):
                    modules.extend(alias.name for alias in node.names)
                elif isinstance(node, ast.ImportFrom) and node.module:
                    modules.append(node.module)
                for module in modules:
                    top = module.split(".", 1)[0]
                    if top not in stdlib and top not in LOCAL_IMPORT_ROOTS:
                        result.add(top)
    return result


class DependencyManifestTests(unittest.TestCase):
    def test_repository_uses_one_python_requirements_manifest(self) -> None:
        manifests = []
        for path in ROOT.rglob("requirements*.txt"):
            if any(part in {".runtime", ".venv", "node_modules"} for part in path.parts):
                continue
            manifests.append(path.relative_to(ROOT).as_posix())
        self.assertEqual(manifests, ["backend/requirements.txt"])

    def test_every_requirement_is_exactly_pinned(self) -> None:
        unpinned = []
        for line in REQUIREMENTS.read_text(encoding="utf-8").splitlines():
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            if "==" not in stripped or any(operator in stripped for operator in (">=", "<=", "~=", "!=", "===")):
                unpinned.append(stripped)
        self.assertEqual(unpinned, [])

    def test_every_direct_python_dependency_is_pinned_in_single_requirements_file(self) -> None:
        requirements = requirement_names()
        imports = direct_third_party_imports()

        unknown_imports = sorted(imports - set(IMPORT_TO_DISTRIBUTION))
        self.assertEqual(
            unknown_imports,
            [],
            f"Map new third-party imports to their distribution names: {unknown_imports}",
        )

        missing = sorted(
            distribution
            for module, distribution in IMPORT_TO_DISTRIBUTION.items()
            if module in imports and distribution not in requirements
        )
        self.assertEqual(missing, [], f"Missing backend requirements: {missing}")
        self.assertIn("pytest", requirements)

    def test_frontend_external_imports_are_declared_and_lockfile_is_tracked(self) -> None:
        package_json = json.loads((ROOT / "frontend" / "package.json").read_text(encoding="utf-8"))
        declared = {
            **package_json.get("dependencies", {}),
            **package_json.get("devDependencies", {}),
        }
        imported: set[str] = set()
        pattern = re.compile(r"(?:from\s+|import\s*\()\s*['\"]([^'\"]+)['\"]")

        for path in (ROOT / "frontend").rglob("*"):
            if not path.is_file() or path.suffix not in {".js", ".jsx", ".mjs", ".cjs"}:
                continue
            if "node_modules" in path.parts or "dist" in path.parts:
                continue
            for value in pattern.findall(path.read_text(encoding="utf-8")):
                if value.startswith((".", "/", "node:")):
                    continue
                top = "/".join(value.split("/")[:2]) if value.startswith("@") else value.split("/")[0]
                imported.add(top)

        self.assertEqual(sorted(imported - set(declared)), [])
        self.assertTrue((ROOT / "frontend" / "package-lock.json").is_file())


if __name__ == "__main__":
    unittest.main()
