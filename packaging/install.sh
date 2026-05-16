#!/usr/bin/env bash
# One-liner installer:
#
#     curl -fsSL https://arc-exporter.dev/install.sh | bash
#
# Routes to the best installation method for the host OS and CPU:
#   - macOS                     -> Homebrew tap (or PyPI fallback)
#   - Linux (Debian/Ubuntu)     -> .deb from the latest GitHub Release
#   - Linux (Fedora/RHEL)       -> .rpm
#   - Linux (other)             -> pre-built single-file binary
#   - Windows                   -> instructs the user to use winget / .msi (no shell loop)
#
# The script is intentionally small; if anything fails it falls back to `pipx install`.

set -euo pipefail

REPO="${ARC_EXPORTER_REPO:-mhadifilms/arc-exporter}"
VERSION="${ARC_EXPORTER_VERSION:-latest}"

err() { printf 'error: %s\n' "$*" >&2; exit 1; }
have() { command -v "$1" >/dev/null 2>&1; }

os="$(uname -s 2>/dev/null || echo unknown)"
arch="$(uname -m 2>/dev/null || echo unknown)"

case "$os" in
  Darwin)
    if have brew; then
      brew tap mhadifilms/tap || true
      brew install arc-exporter && exit 0
    fi
    ;;
  Linux)
    case "$arch" in
      x86_64|amd64)
        if have apt-get; then
          tmp=$(mktemp -d)
          url="https://github.com/${REPO}/releases/${VERSION}/download/arc-exporter.deb"
          curl -fsSL "$url" -o "$tmp/arc-exporter.deb"
          sudo apt-get install -y "$tmp/arc-exporter.deb" && exit 0
        fi
        if have dnf; then
          url="https://github.com/${REPO}/releases/${VERSION}/download/arc-exporter.rpm"
          sudo dnf install -y "$url" && exit 0
        fi
        ;;
    esac
    ;;
  MINGW*|MSYS*|CYGWIN*)
    err "Windows: install via winget (\`winget install arc-exporter\`) or download the .msi from https://github.com/${REPO}/releases."
    ;;
esac

# Fallback: pipx then pip.
if have pipx; then
  pipx install arc-exporter && exit 0
fi
if have python3; then
  python3 -m pip install --user arc-exporter && exit 0
fi
err "No supported installer found. Please install Python 3.10+ and run \`pipx install arc-exporter\`."
