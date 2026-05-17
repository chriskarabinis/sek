#!/bin/bash
set -e

REPO="chriskarabinis/sek"
INSTALL_DIR="/usr/local/bin"

# Detect OS
OS=$(uname -s | tr '[:upper:]' '[:lower:]')
case "$OS" in
  darwin|linux) ;;
  *) echo "[!] Unsupported OS: $OS" && exit 1 ;;
esac

# Detect architecture
ARCH=$(uname -m)
case "$ARCH" in
  x86_64)        ARCH="amd64" ;;
  arm64|aarch64) ARCH="arm64" ;;
  *) echo "[!] Unsupported architecture: $ARCH" && exit 1 ;;
esac

# Get latest release version
VERSION=$(curl -fsSL "https://api.github.com/repos/$REPO/releases/latest" \
  | grep '"tag_name"' \
  | sed 's/.*"tag_name": *"v\([^"]*\)".*/\1/')

if [ -z "$VERSION" ]; then
  echo "[!] Could not determine latest version. Check your internet connection."
  exit 1
fi

BINARY="sek_${OS}_${ARCH}"
URL="https://github.com/$REPO/releases/download/v${VERSION}/${BINARY}"

echo "[*] Installing sek v${VERSION} (${OS}/${ARCH})..."
curl -fsSL "$URL" -o /tmp/sek
chmod +x /tmp/sek

if [ -w "$INSTALL_DIR" ]; then
  mv /tmp/sek "$INSTALL_DIR/sek"
else
  sudo mv /tmp/sek "$INSTALL_DIR/sek"
fi

echo "[*] Installed to $INSTALL_DIR/sek"
echo "[*] Run: sek --help"
