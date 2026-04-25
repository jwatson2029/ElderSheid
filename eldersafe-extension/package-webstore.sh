#!/usr/bin/env bash
# Build a Chrome Web Store–ready ZIP: manifest.json and all files at the ROOT of the archive.
# Usage: from repo root: ./eldersafe-extension/package-webstore.sh
#    or: cd eldersafe-extension && ./package-webstore.sh

set -euo pipefail
ROOT="$(cd "$(dirname "$0")" && pwd)"
cd "$ROOT"

VERSION="$(jq -r '.version' manifest.json)"
OUT_NAME="eldersafe-extension-webstore-v${VERSION}.zip"
OUT_ABS="$(cd .. && pwd)/${OUT_NAME}"

rm -f "$OUT_ABS"
zip -r "$OUT_ABS" . \
  -x '*.git*' \
  -x '**/.DS_Store' \
  -x '*.zip' \
  -x 'package-webstore.sh' \
  -x 'test-fixtures/*' \
  -x 'store-assets/*'

VERIFY_ZIP="$OUT_ABS" python3 << 'PY'
import os, sys, zipfile
path = os.environ["VERIFY_ZIP"]
with zipfile.ZipFile(path, "r") as z:
    for n in z.namelist():
        norm = n.replace("\\", "/").lstrip("./")
        parts = [p for p in norm.split("/") if p]
        if parts == ["manifest.json"]:
            print("OK: manifest.json at zip root (" + n + ")")
            sys.exit(0)
    print("ERROR: manifest.json not at root of:", path, file=sys.stderr)
    print("First entries:", z.namelist()[:25], file=sys.stderr)
    sys.exit(1)
PY

echo "Created: $OUT_ABS"
echo "Upload THIS file to the Chrome Web Store (not a folder zip, not the GitHub artifact wrapper)."
