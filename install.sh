#!/bin/bash
set -euo pipefail

REPO="chriskarabinis/sek"
INSTALL_DIR="/usr/local/bin"

# Detect OS
OS=$(uname -s | tr '[:upper:]' '[:lower:]')
case "$OS" in
  darwin|linux) ;;
  *) echo "[!] Unsupported OS: $OS" >&2; exit 1 ;;
esac

# Detect architecture
ARCH=$(uname -m)
case "$ARCH" in
  x86_64)        ARCH="amd64" ;;
  arm64|aarch64) ARCH="arm64" ;;
  *) echo "[!] Unsupported architecture: $ARCH" >&2; exit 1 ;;
esac

# Get latest release version
VERSION=$(curl -fsSL "https://api.github.com/repos/$REPO/releases/latest" \
  | grep '"tag_name"' \
  | sed 's/.*"tag_name": *"v\([^"]*\)".*/\1/')

if [ -z "$VERSION" ]; then
  echo "[!] Could not determine latest version. Check your internet connection." >&2
  exit 1
fi

BINARY="sek_${OS}_${ARCH}"
BASE_URL="https://github.com/$REPO/releases/download/v${VERSION}"

# Stage in a private temp dir. A fixed path like /tmp/sek is predictable and
# lets another user on the machine pre-create or symlink it.
WORKDIR=$(mktemp -d)
trap 'rm -rf "$WORKDIR"' EXIT

echo "[*] Installing sek v${VERSION} (${OS}/${ARCH})..."
curl -fsSL "$BASE_URL/${BINARY}" -o "$WORKDIR/sek"

if ! curl -fsSL "$BASE_URL/checksums.txt" -o "$WORKDIR/checksums.txt"; then
  echo "[!] Release v${VERSION} publishes no checksums.txt, so the download" >&2
  echo "    cannot be verified. Refusing to install." >&2
  exit 1
fi

if command -v sha256sum >/dev/null 2>&1; then
  ACTUAL=$(sha256sum "$WORKDIR/sek" | awk '{print $1}')
elif command -v shasum >/dev/null 2>&1; then
  ACTUAL=$(shasum -a 256 "$WORKDIR/sek" | awk '{print $1}')
else
  echo "[!] Neither sha256sum nor shasum is available; cannot verify download." >&2
  exit 1
fi

EXPECTED=$(awk -v want="$BINARY" '$2 == want || $2 == "*" want { print $1 }' "$WORKDIR/checksums.txt")

if [ -z "$EXPECTED" ]; then
  echo "[!] checksums.txt has no entry for ${BINARY}. Refusing to install." >&2
  exit 1
fi

if [ "$ACTUAL" != "$EXPECTED" ]; then
  echo "[!] Checksum mismatch for ${BINARY} — refusing to install." >&2
  echo "    expected $EXPECTED" >&2
  echo "    got      $ACTUAL" >&2
  exit 1
fi

echo "[*] Checksum verified."

if [ -w "$INSTALL_DIR" ]; then
  install -m 0755 "$WORKDIR/sek" "$INSTALL_DIR/sek"
else
  sudo install -m 0755 "$WORKDIR/sek" "$INSTALL_DIR/sek"
fi

echo "[*] Installed to $INSTALL_DIR/sek"
echo "[*] Run: sek --help"
