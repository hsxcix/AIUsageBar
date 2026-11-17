#!/bin/zsh
# Builds AIUsageBar.app next to this script and (re)starts it.
set -e
cd "${0:A:h}"
APP=AIUsageBar.app
mkdir -p $APP/Contents/MacOS
cat > $APP/Contents/Info.plist <<'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>CFBundleIdentifier</key><string>io.github.hsxcix.AIUsageBar</string>
  <key>CFBundleName</key><string>AIUsageBar</string>
  <key>CFBundleExecutable</key><string>AIUsageBar</string>
  <key>CFBundlePackageType</key><string>APPL</string>
  <key>CFBundleShortVersionString</key><string>0.1</string>
  <key>CFBundleVersion</key><string>1</string>
  <key>LSMinimumSystemVersion</key><string>14.0</string>
  <key>LSUIElement</key><true/>
</dict></plist>
EOF
swiftc -O main.swift -o $APP/Contents/MacOS/AIUsageBar
codesign --force --sign - $APP
pkill -x AIUsageBar 2>/dev/null || true
sleep 0.5
open $APP
echo "Built and started $PWD/$APP"
