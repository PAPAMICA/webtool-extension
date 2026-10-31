#!/usr/bin/env bash
# Build a Chrome Web Store–ready ZIP (MV3, manifest.json at archive root).
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

VERSION=$(python3 -c "import json; print(json.load(open('chrome/manifest.json'))['version'])")
OUT_DIR="$ROOT/web-ext-artifacts"
NAME="webtool_inspector_chrome-${VERSION}.zip"
mkdir -p "$OUT_DIR"

TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

cp chrome/manifest.json "$TMP/manifest.json"
mkdir -p "$TMP/icons" "$TMP/src/lib" "$TMP/src/content" "$TMP/src/popup"
cp icons/icon-48.png icons/icon-96.png icons/icon-128.png icons/icon.svg "$TMP/icons/"
cp src/background-chrome.js "$TMP/src/"
cp src/lib/*.js "$TMP/src/lib/"
cp src/content/*.js "$TMP/src/content/"
cp src/popup/popup.html src/popup/popup.js src/popup/popup.css src/popup/report.js "$TMP/src/popup/"

(
  cd "$TMP"
  zip -q -r "$OUT_DIR/$NAME" .
)

echo "Archive contents (top):"
unzip -l "$OUT_DIR/$NAME" | head -25
echo ""
echo "Built: $OUT_DIR/$NAME ($(du -h "$OUT_DIR/$NAME" | awk '{print $1}'))"
echo "Upload at https://chrome.google.com/webstore/devconsole"
