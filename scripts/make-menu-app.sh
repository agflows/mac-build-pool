#!/bin/sh
set -eu

root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
app=${1:-"$root/.build/Mac Build Pool.app"}
if [ -e "$app" ] || [ -L "$app" ]; then
    printf '%s\n' "Choose a new destination for the menu app." >&2
    exit 1
fi
mkdir -p "$(dirname -- "$app")"
stage=$(mktemp -d "$(dirname -- "$app")/.menu-build.XXXXXX")
trap 'rm -rf "$stage"' EXIT
bundle="$stage/Mac Build Pool.app"
mkdir -p "$bundle/Contents/MacOS"
/usr/bin/xcrun swiftc -O -swift-version 5 "$root/menu-bar/main.swift" -o "$bundle/Contents/MacOS/MacBuildPool"
cat > "$bundle/Contents/Info.plist" <<'PLIST'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleExecutable</key><string>MacBuildPool</string>
    <key>CFBundleIdentifier</key><string>org.agflows.mac-build-pool.menu</string>
    <key>CFBundleName</key><string>Mac Build Pool</string>
    <key>CFBundlePackageType</key><string>APPL</string>
    <key>CFBundleVersion</key><string>1</string>
    <key>CFBundleShortVersionString</key><string>1.0</string>
    <key>LSUIElement</key><true/>
</dict>
</plist>
PLIST
/usr/bin/codesign --force --sign - "$bundle"
/bin/mv "$bundle" "$app"
printf '%s\n' "$app"
