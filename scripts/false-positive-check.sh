#!/usr/bin/env bash
# Starts a plain web server that looks like an ordinary router page and checks that the scanner
# reports PASS for it. Any FAIL/REVIEW here means a template matches too much.
# Requires: python3, java, nuclei (on PATH or NUCLEI env var), and the built jar in target/.
set -euo pipefail
cd "$(dirname "$0")/.."
NUCLEI="${NUCLEI:-nuclei}"
SITE="$(mktemp -d)"
trap 'kill "${PID:-0}" 2>/dev/null || true; rm -rf "$SITE"' EXIT
cat > "$SITE/index.html" <<'HTML'
<html><head><title>Home Router</title></head><body>Login <span>sn success admin</span></body></html>
HTML
(cd "$SITE" && python3 -m http.server 80 --bind 127.0.0.1 >/dev/null 2>&1) &
PID=$!
sleep 1
set +e
java -jar target/dooh-security-scanner.jar -h 127.0.0.1 --nuclei "$NUCLEI" --out "$SITE/scans" --yes | tee "$SITE/out.txt"
CODE=${PIPESTATUS[0]}
set -e
if [ "$CODE" -ne 0 ] || ! grep -q "^\[PASS\]" "$SITE/out.txt"; then
  echo "FALSE POSITIVE: a plain web server did not PASS (exit $CODE)" >&2
  exit 1
fi
echo "OK: plain web server passes"
