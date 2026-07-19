#!/usr/bin/env bash
# Собирает macOS .app-бандл haqproxy.app из cmd/haqproxy-gui с иконкой.
# Требует: go, ImageMagick (magick), iconutil, sips (все — macOS/Homebrew).
set -euo pipefail
cd "$(dirname "$0")/.."

APP="haqproxy.app"
ICON_SVG="packaging/icon.svg"
BUILD="build"
BUNDLE_ID="ru.cyberist.haqproxy"
VERSION="1.0"

echo "==> сборка бинарника (CGO/WKWebView)"
rm -rf "$APP" "$BUILD/haqproxy.iconset"
mkdir -p "$APP/Contents/MacOS" "$APP/Contents/Resources" "$BUILD"
CGO_ENABLED=1 go build -trimpath -o "$APP/Contents/MacOS/haqproxy" ./cmd/haqproxy-gui

echo "==> иконка: градиент (ImageMagick) + глиф (svg) -> icns"
# Фон-градиент рисуем самим ImageMagick — его встроенный SVG-рендерер не тянет
# url(#gradient). Скругление — через маску. Стрелки — из glyph.svg (белые полигоны).
magick -size 1024x1024 gradient:'#7aa2f7-#bb9af7' "$BUILD/grad.png"
magick -size 1024x1024 xc:black -fill white -draw "roundrectangle 0,0,1023,1023,224,224" "$BUILD/mask.png"
magick "$BUILD/grad.png" "$BUILD/mask.png" -alpha off -compose CopyOpacity -composite "$BUILD/rounded.png"
magick -background none "packaging/glyph.svg" -resize 1024x1024 "$BUILD/glyph.png"
magick "$BUILD/rounded.png" "$BUILD/glyph.png" -compose over -composite "$BUILD/icon_1024.png"
ICONSET="$BUILD/haqproxy.iconset"
mkdir -p "$ICONSET"
for sz in 16 32 128 256 512; do
  sips -z "$sz" "$sz" "$BUILD/icon_1024.png" --out "$ICONSET/icon_${sz}x${sz}.png" >/dev/null
  d=$((sz * 2))
  sips -z "$d" "$d" "$BUILD/icon_1024.png" --out "$ICONSET/icon_${sz}x${sz}@2x.png" >/dev/null
done
iconutil -c icns "$ICONSET" -o "$APP/Contents/Resources/icon.icns"

echo "==> Info.plist"
cat > "$APP/Contents/Info.plist" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>CFBundleName</key><string>haqproxy</string>
  <key>CFBundleDisplayName</key><string>haqproxy</string>
  <key>CFBundleIdentifier</key><string>${BUNDLE_ID}</string>
  <key>CFBundleExecutable</key><string>haqproxy</string>
  <key>CFBundleIconFile</key><string>icon</string>
  <key>CFBundlePackageType</key><string>APPL</string>
  <key>CFBundleShortVersionString</key><string>${VERSION}</string>
  <key>CFBundleVersion</key><string>${VERSION}</string>
  <key>CFBundleInfoDictionaryVersion</key><string>6.0</string>
  <key>LSMinimumSystemVersion</key><string>11.0</string>
  <key>NSHighResolutionCapable</key><true/>
</dict>
</plist>
PLIST

echo "==> готово: $APP"
