#!/usr/bin/env bash
# Runs Maven, retrying (up to 3 attempts) ONLY when a dependency or plugin download failed (Maven Central rate limits
# and outages: HTTP 429/5xx, "could not be resolved"). A compile error or a failing test is never retried.
#   scripts/mvn-retry.sh -B verify
set -uo pipefail
ATTEMPTS=3
for attempt in $(seq 1 "$ATTEMPTS"); do
  out="$(mktemp)"
  mvn "$@" 2>&1 | tee "$out"
  rc=${PIPESTATUS[0]}
  if [ "$rc" -eq 0 ]; then rm -f "$out"; exit 0; fi
  if [ "$attempt" -lt "$ATTEMPTS" ] && grep -qE "Could not transfer artifact|could not be resolved|Could not resolve|status code: (429|5[0-9][0-9])" "$out"; then
    wait=$((attempt * 30))
    echo "::warning::Maven could not download something (attempt $attempt of $ATTEMPTS); retrying in ${wait}s"
    rm -f "$out"; sleep "$wait"; continue
  fi
  rm -f "$out"; exit "$rc"
done
