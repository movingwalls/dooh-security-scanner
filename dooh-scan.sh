#!/usr/bin/env bash
# Launcher for Linux/macOS. Run from the folder that contains the jar.
cd "$(dirname "$0")" || exit 1
if ! command -v java >/dev/null 2>&1; then
  echo "Java 17 or newer is required. Install it from https://adoptium.net and try again." >&2
  exit 1
fi
MAJOR=$(java -version 2>&1 | head -1 | sed -E 's/.*version "([0-9]+)(\.([0-9]+))?.*/\1/')
[ "$MAJOR" = "1" ] && MAJOR=8
if [ "${MAJOR:-0}" -lt 17 ] 2>/dev/null; then
  echo "Java 17 or newer is required (found Java $MAJOR). Install it from https://adoptium.net" >&2
  exit 1
fi
exec java -jar dooh-security-scanner.jar "$@"
