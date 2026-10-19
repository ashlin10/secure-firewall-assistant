#!/bin/sh
set -eu
SFA_ROOT=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
SFA_UV=$(command -v uv || true)
if [ -z "$SFA_UV" ]; then
  for SFA_CANDIDATE in "$HOME/.local/bin/uv" "$HOME/.cargo/bin/uv" /opt/homebrew/bin/uv /usr/local/bin/uv; do
    if [ -x "$SFA_CANDIDATE" ]; then SFA_UV=$SFA_CANDIDATE; break; fi
  done
fi
if [ -z "$SFA_UV" ]; then echo "Install uv first; see README.md." >&2; exit 1; fi
if [ "$#" -eq 0 ]; then set -- --help; fi
exec "$SFA_UV" run --project "$SFA_ROOT" --frozen --no-dev --offline secure-firewall-assistant "$@"
