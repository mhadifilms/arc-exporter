#!/usr/bin/env bash
# Double-clickable launcher for macOS users who don't live in the terminal.
# Place this file on the Desktop (`chmod +x` it once) and double-click to run.
#
# It tries Homebrew first, falls back to pipx, then python -m pip --user.

set -euo pipefail

# Move to the user's home so any side-effect files land somewhere predictable.
cd "$HOME"

if ! command -v arc-exporter >/dev/null 2>&1; then
  echo "Installing arc-exporter..."
  if command -v brew >/dev/null 2>&1; then
    brew tap mhadifilms/tap >/dev/null 2>&1 || true
    brew install arc-exporter
  elif command -v pipx >/dev/null 2>&1; then
    pipx install arc-exporter
  else
    python3 -m pip install --user arc-exporter
  fi
fi

echo
echo "arc-exporter is ready."
echo "Run:  arc-exporter doctor"
echo "Run:  arc-exporter export all"
echo
echo "Press any key to open a terminal..."
read -n 1 -s -r
open -a Terminal
