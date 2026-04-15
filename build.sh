#!/usr/bin/env bash
# ───────────────────────────────────────────────────
# Magic Fill Extension — Build Script
# Packages the extension for Chrome and Firefox
# ───────────────────────────────────────────────────
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BUILD_DIR="$SCRIPT_DIR/builds"
CHROME_DIR="$BUILD_DIR/chrome"
FIREFOX_DIR="$BUILD_DIR/firefox"

# Shared source files (relative to SCRIPT_DIR)
SHARED_FILES=(
  "browser-polyfill.js"
  "background.js"
  "popup/popup.html"
  "popup/popup.css"
  "popup/popup.js"
  "popup/import.html"
  "popup/import.js"
  "content/content.css"
  "content/content.js"
  "icons/icon16.png"
  "icons/icon48.png"
  "icons/icon128.png"
  "icons/icon.svg"
  "icons/icon_locked.svg"
)

echo "🧹 Cleaning previous builds..."
rm -rf "$BUILD_DIR"

# ──── Chrome Build ────
echo ""
echo "🔵 Building Chrome extension..."
mkdir -p "$CHROME_DIR"

for file in "${SHARED_FILES[@]}"; do
  if [ -f "$SCRIPT_DIR/$file" ]; then
    mkdir -p "$CHROME_DIR/$(dirname "$file")"
    cp "$SCRIPT_DIR/$file" "$CHROME_DIR/$file"
  fi
done

cp "$SCRIPT_DIR/manifest.json" "$CHROME_DIR/manifest.json"

# Create zip
cd "$CHROME_DIR"
zip -r "$BUILD_DIR/magic-fill-chrome.zip" . -x "*.DS_Store" > /dev/null 2>&1
echo "   ✅ Chrome package:  builds/magic-fill-chrome.zip"

# ──── Firefox Build ────
echo ""
echo "🦊 Building Firefox extension..."
mkdir -p "$FIREFOX_DIR"

for file in "${SHARED_FILES[@]}"; do
  if [ -f "$SCRIPT_DIR/$file" ]; then
    mkdir -p "$FIREFOX_DIR/$(dirname "$file")"
    cp "$SCRIPT_DIR/$file" "$FIREFOX_DIR/$file"
  fi
done

cp "$SCRIPT_DIR/manifest.firefox.json" "$FIREFOX_DIR/manifest.json"

# Create zip (Firefox uses .xpi but .zip also works for web-ext / AMO upload)
cd "$FIREFOX_DIR"
zip -r "$BUILD_DIR/magic-fill-firefox.zip" . -x "*.DS_Store" > /dev/null 2>&1
echo "   ✅ Firefox package: builds/magic-fill-firefox.zip"

echo ""
echo "──────────────────────────────────────────"
echo "📦 Build complete! Outputs in builds/"
echo ""
echo "  Chrome:  builds/magic-fill-chrome.zip"
echo "  Firefox: builds/magic-fill-firefox.zip"
echo ""
echo "📌 Chrome:  Load unpacked from builds/chrome/"
echo "📌 Firefox: Load temporary addon from builds/firefox/"
echo "             or use: cd builds/firefox && npx web-ext run"
echo "──────────────────────────────────────────"
