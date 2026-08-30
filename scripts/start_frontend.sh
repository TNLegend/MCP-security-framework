#!/bin/sh
set -eu

ROOT="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
cd "$ROOT/frontend"

if [ ! -d node_modules ]; then
    npm ci
fi

npm run dev
