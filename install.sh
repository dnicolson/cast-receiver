#!/bin/sh
# cast-receiver install script
# Usage: curl -sfL https://github.com/grave0x/cast-receiver/releases/latest/download/install.sh | sh
# Or:  ./install.sh [version]

set -eu

REPO="grave0x/cast-receiver"
BIN="cast-receiver"
INSTALL_DIR="${INSTALL_DIR:-/usr/local/bin}"

# Detect OS and arch
OS=$(uname -s | tr '[:upper:]' '[:lower:]')
ARCH=$(uname -m)
case "$ARCH" in
  x86_64) ARCH="x86_64" ;;
  aarch64|arm64) ARCH="aarch64" ;;
  *) echo "unsupported arch: $ARCH"; exit 1 ;;
esac

case "$OS" in
  linux) OS="Linux" ;;
  darwin) OS="Darwin" ;;
  *) echo "unsupported OS: $OS"; exit 1 ;;
esac

# Resolve version
VERSION="${1:-latest}"
if [ "$VERSION" = "latest" ]; then
  VERSION=$(curl -sfL "https://api.github.com/repos/$REPO/releases/latest" | grep '"tag_name"' | cut -d'"' -f4)
fi

# Download
URL="https://github.com/$REPO/releases/download/$VERSION/${BIN}_${OS}_${ARCH}.tar.gz"
echo "Downloading $URL ..."
curl -sfL "$URL" -o "/tmp/${BIN}.tar.gz"

# Extract and install
tar xzf "/tmp/${BIN}.tar.gz" -C /tmp
mv "/tmp/${BIN}" "$INSTALL_DIR/$BIN"
chmod +x "$INSTALL_DIR/$BIN"
rm -f "/tmp/${BIN}.tar.gz"

# Check deps
echo "Checking dependencies..."
MISSING=""
for cmd in ffplay openssl; do
  if ! command -v "$cmd" >/dev/null 2>&1; then
    MISSING="$MISSING $cmd"
  fi
done

if [ -n "$MISSING" ]; then
  echo "Warning: missing optional deps:$MISSING"
  echo "  ffplay: media playback (install ffmpeg)"
  echo "  openssl: TLS cert verification (install openssl)"
fi

echo ""
echo "Installed $BIN $VERSION to $INSTALL_DIR/$BIN"
echo ""
echo "Next steps:"
echo "  1. Run:  $BIN -name \"My Cast Receiver\""
echo "  2. Cast from Chrome/Android — the device appears on your LAN"
echo "  3. Open http://localhost:8009/ to verify it's running"
echo ""
echo "Options:"
echo "  $BIN -name \"Living Room\" -port 8009"
echo "  $BIN -help"
