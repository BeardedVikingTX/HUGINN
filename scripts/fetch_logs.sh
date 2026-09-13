#!/usr/bin/env bash
# =============================================================================
#  HUGINN :: fetch_logs.sh
#  Pulls attacker-infrastructure logs down for local analysis.
# -----------------------------------------------------------------------------
#  Usage:
#     ./scripts/fetch_logs.sh <program_dir> [log_name]
#     ./scripts/fetch_logs.sh output/beardedviking_20260910
# =============================================================================
set -euo pipefail

PROGRAM_DIR="${1:?usage: fetch_logs.sh <program_dir> [log_name]}"
LOG_NAME="${2:-}"
BASE_URL="${HUGINN_LOG_URL:-https://beardedviking.org/huginn}"
VIEW_USER="${HUGINN_VIEW_USER:-huginn}"
VIEW_PASS="${HUGINN_VIEW_PASS:-change-me-please}"

DEST="$PROGRAM_DIR/recon/oob_logs"
mkdir -p "$DEST"

LOGS=(oob xss ssrf redirect landed)
[ -n "$LOG_NAME" ] && LOGS=("$LOG_NAME")

for log in "${LOGS[@]}"; do
  echo "[*] fetching $log…"
  curl -sf -u "$VIEW_USER:$VIEW_PASS" \
    "$BASE_URL/view.php?log=$log&tail=999999" \
    -o "$DEST/$log.html" || echo "    (empty or unavailable)"
done

# Cheap grep pass — count tokens found
echo
echo "[*] token summary:"
for f in "$DEST"/*.html; do
  [ -s "$f" ] || continue
  name=$(basename "$f" .html)
  hits=$(grep -oE 'huginn-[a-f0-9]{16,32}' "$f" 2>/dev/null | sort -u | wc -l)
  echo "    $name: $hits unique tokens"
done

echo
echo "[+] logs saved to $DEST"
