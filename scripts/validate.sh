#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
temporary="$(mktemp -d)"
trap 'rm -rf "$temporary"' EXIT
cd "$repo_root"

python3 -m unittest discover -s tests -v
python3 -m py_compile src/enforcer.py function_app.py
python3 src/enforcer.py replay \
  --policy config/policy.json \
  --events examples/risk-events.json \
  --database "$temporary/one.db" \
  --output "$temporary/one.json"
python3 src/enforcer.py replay \
  --policy config/policy.json \
  --events examples/risk-events.json \
  --database "$temporary/two.db" \
  --output "$temporary/two.json"
cmp "$temporary/one.json" "$temporary/two.json"
for document in config/policy.json examples/risk-events.json host.json; do
  python3 -m json.tool "$document" >/dev/null
done

if command -v bicep >/dev/null 2>&1; then
  bicep build infra/main.bicep --outfile "$temporary/main.json"
elif command -v az >/dev/null 2>&1 &&
  AZURE_CONFIG_DIR="$temporary/az" az bicep version >/dev/null 2>&1; then
  AZURE_CONFIG_DIR="$temporary/az" az bicep build \
    --file infra/main.bicep --outfile "$temporary/main.json"
else
  echo "Bicep compiler unavailable; compile gate skipped locally." >&2
fi
if command -v shellcheck >/dev/null 2>&1; then
  shellcheck scripts/validate.sh
fi
