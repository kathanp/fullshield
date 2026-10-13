#!/bin/sh
# FullShield pre-commit hook: block staged secrets.
set -e
ROOT=$(git rev-parse --show-toplevel)
cd "$ROOT"
if command -v npx >/dev/null 2>&1; then
  npx fullshield scan --modules secrets --staged --fail-on high
else
  echo "fullshield pre-commit: npx not found" >&2
  exit 1
fi
