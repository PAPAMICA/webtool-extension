#!/usr/bin/env bash
# Build an AMO-ready ZIP (manifest.json at archive root).
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

VERSION=$(python3 -c "import json; print(json.load(open('manifest.json'))['version'])")
OUT_DIR="$ROOT/web-ext-artifacts"
NAME="webtool_inspector-${VERSION}.zip"
mkdir -p "$OUT_DIR"

TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

# Only ship runtime files (no git, docs extras still useful? keep PRIVACY out of xpi — linked from GitHub)
cp manifest.json "$TMP/"
mkdir -p "$TMP/icons" "$TMP/src/lib" "$TMP/src/content" "$TMP/src/popup"
cp icons/icon-48.png icons/icon-96.png icons/icon-128.png icons/icon.svg "$TMP/icons/"
cp src/background.js "$TMP/src/"
cp src/lib/*.js "$TMP/src/lib/"
cp src/content/*.js "$TMP/src/content/"
cp src/popup/popup.html src/popup/popup.js src/popup/popup.css "$TMP/src/popup/"

(
  cd "$TMP"
  zip -q -r "$OUT_DIR/$NAME" .
)

# Sanity: manifest at root
unzip -l "$OUT_DIR/$NAME" | head -20
echo ""
echo "Built: $OUT_DIR/$NAME ($(du -h "$OUT_DIR/$NAME" | awk '{print $1}'))"
echo "Upload this file at https://addons.mozilla.org/developers/addon/submit/"
