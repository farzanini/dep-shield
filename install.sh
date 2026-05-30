#!/usr/bin/env sh
# install.sh — download and install dep-shield for the current platform.
#
# Usage (always installs the latest release):
#   curl -fsSL https://raw.githubusercontent.com/dep-shield/dep-shield/main/install.sh | sh
#
# Usage (pin to a specific version):
#   curl -fsSL https://raw.githubusercontent.com/dep-shield/dep-shield/main/install.sh | sh -s -- --version v1.2.3
#
# Flags:
#   --version  VERSION   install a specific release tag (default: latest)
#   --install-dir DIR    where to put the binary (default: /usr/local/bin)
#   --no-verify          skip checksum verification (not recommended)
#
# Supported platforms:
#   Linux   amd64 / arm64
#   macOS   amd64 (Intel) / arm64 (Apple Silicon)
#
# The script requires: curl (or wget), tar, sha256sum (or shasum on macOS).
# All are present by default on macOS 10.x+ and every major Linux distro.

set -eu

# ── Defaults ─────────────────────────────────────────────────────────────────
REPO="dep-shield/dep-shield"
INSTALL_DIR="/usr/local/bin"
VERSION=""        # empty → fetch latest
VERIFY=1          # 1 = verify checksums, 0 = skip

# ── Parse arguments ───────────────────────────────────────────────────────────
while [ $# -gt 0 ]; do
  case "$1" in
    --version)    VERSION="$2"; shift 2 ;;
    --install-dir) INSTALL_DIR="$2"; shift 2 ;;
    --no-verify)  VERIFY=0; shift ;;
    --)           shift; break ;;
    *)            echo "Unknown argument: $1" >&2; exit 1 ;;
  esac
done

# ── Helpers ───────────────────────────────────────────────────────────────────
say()  { printf '\033[1m%s\033[0m\n' "$*"; }
err()  { printf '\033[31merror:\033[0m %s\n' "$*" >&2; exit 1; }
need() { command -v "$1" >/dev/null 2>&1 || err "Required command not found: $1"; }

# Download a URL to stdout.  Prefers curl, falls back to wget.
download() {
  if command -v curl >/dev/null 2>&1; then
    curl --proto '=https' --tlsv1.2 -fsSL "$1"
  elif command -v wget >/dev/null 2>&1; then
    wget -qO- "$1"
  else
    err "Neither curl nor wget found. Install one and try again."
  fi
}

# Download a URL to a file.
download_to() {
  local url="$1" dest="$2"
  if command -v curl >/dev/null 2>&1; then
    curl --proto '=https' --tlsv1.2 -fsSL -o "$dest" "$url"
  else
    wget -qO "$dest" "$url"
  fi
}

# ── Detect OS ─────────────────────────────────────────────────────────────────
OS="$(uname -s)"
case "$OS" in
  Linux)   OS_KEY="linux" ;;
  Darwin)  OS_KEY="darwin" ;;
  *)       err "Unsupported operating system: $OS. Use the Windows installer (install.ps1) on Windows." ;;
esac

# ── Detect architecture ───────────────────────────────────────────────────────
ARCH="$(uname -m)"
case "$ARCH" in
  x86_64 | amd64)   ARCH_KEY="amd64" ;;
  aarch64 | arm64)  ARCH_KEY="arm64" ;;
  *)                err "Unsupported architecture: $ARCH (dep-shield ships amd64 and arm64 binaries)." ;;
esac

# ── Resolve version ───────────────────────────────────────────────────────────
if [ -z "$VERSION" ]; then
  say "Fetching latest release version…"
  VERSION="$(download "https://api.github.com/repos/${REPO}/releases/latest" \
    | grep '"tag_name"' \
    | sed -E 's/.*"tag_name": *"([^"]+)".*/\1/')"
  [ -n "$VERSION" ] || err "Could not determine latest version. Check your network connection."
fi

say "Installing dep-shield ${VERSION} (${OS_KEY}/${ARCH_KEY})"

# ── Construct download URLs ───────────────────────────────────────────────────
# Archive name matches goreleaser's name_template in .goreleaser.yaml:
#   dep-shield_<version>_<os>_<arch>.tar.gz
ARCHIVE="dep-shield_${VERSION}_${OS_KEY}_${ARCH_KEY}.tar.gz"
BASE_URL="https://github.com/${REPO}/releases/download/${VERSION}"
ARCHIVE_URL="${BASE_URL}/${ARCHIVE}"
CHECKSUMS_URL="${BASE_URL}/checksums.txt"

# ── Create a temporary working directory ──────────────────────────────────────
TMP="$(mktemp -d)"
# shellcheck disable=SC2064
trap "rm -rf '${TMP}'" EXIT INT TERM

# ── Download archive + checksums ─────────────────────────────────────────────
say "Downloading ${ARCHIVE}…"
download_to "$ARCHIVE_URL"   "${TMP}/${ARCHIVE}"
download_to "$CHECKSUMS_URL" "${TMP}/checksums.txt"

# ── Verify checksum ───────────────────────────────────────────────────────────
if [ "$VERIFY" -eq 1 ]; then
  say "Verifying checksum…"
  # sha256sum on Linux; shasum -a 256 on macOS.
  if command -v sha256sum >/dev/null 2>&1; then
    (cd "$TMP" && grep "${ARCHIVE}" checksums.txt | sha256sum --check --status) \
      || err "Checksum verification failed. The downloaded file may be corrupted."
  elif command -v shasum >/dev/null 2>&1; then
    (cd "$TMP" && grep "${ARCHIVE}" checksums.txt | shasum -a 256 --check --status) \
      || err "Checksum verification failed. The downloaded file may be corrupted."
  else
    echo "Warning: sha256sum/shasum not found — skipping verification." >&2
  fi
fi

# ── Extract ───────────────────────────────────────────────────────────────────
say "Extracting…"
tar -xzf "${TMP}/${ARCHIVE}" -C "$TMP"

# ── Install ───────────────────────────────────────────────────────────────────
BINARY="${TMP}/dep-shield"
[ -f "$BINARY" ] || err "Binary not found after extraction. Archive may have unexpected layout."

chmod +x "$BINARY"

# If the install directory is not writable, try sudo.
if [ -w "$INSTALL_DIR" ]; then
  mv "$BINARY" "${INSTALL_DIR}/dep-shield"
else
  say "Requesting sudo to write to ${INSTALL_DIR}…"
  sudo mv "$BINARY" "${INSTALL_DIR}/dep-shield"
fi

# ── Verify the installation ───────────────────────────────────────────────────
INSTALLED_VERSION="$("${INSTALL_DIR}/dep-shield" version 2>/dev/null || true)"
say "Installed: ${INSTALLED_VERSION:-dep-shield ${VERSION}}"
echo ""
echo "Run 'dep-shield --help' to get started."

# Remind the user to add INSTALL_DIR to PATH if it is not already there.
case ":${PATH}:" in
  *":${INSTALL_DIR}:"*) ;;
  *)
    echo ""
    echo "Note: ${INSTALL_DIR} is not in your PATH."
    echo "Add this line to your shell profile (~/.bashrc, ~/.zshrc, etc.):"
    echo ""
    echo "  export PATH=\"${INSTALL_DIR}:\$PATH\""
    ;;
esac
