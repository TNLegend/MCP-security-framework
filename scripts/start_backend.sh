#!/bin/sh
set -eu

ROOT="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
VENV="$ROOT/backend/.venv"

if [ ! -x "$VENV/bin/python" ]; then
    python3 -m venv "$VENV"
    "$VENV/bin/python" -m pip install -r "$ROOT/backend/requirements.txt"
fi

cd "$ROOT"
"$VENV/bin/python" -m uvicorn app.main:app --app-dir backend --reload
