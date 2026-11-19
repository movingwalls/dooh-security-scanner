#!/usr/bin/env bash
# Target-machine test: proves the scanner works on the OS/CPU this script runs on, the way a user would use it.
# Run it on each platform (CI does: Linux x64/arm64, macOS Intel/Apple Silicon, Windows).
#
#   scripts/platform-test.sh            needs: JDK 17+, the jar built at target/dooh-security-scanner.jar
#
# For the latest Nuclei and for the tested (fallback) version it checks that:
#   1. the scanner downloads, checksum-verifies and installs the right Nuclei build for THIS machine,
#   2. that Nuclei runs and every template loads,
#   3. (Linux/macOS) a plain web server is reported as PASS, i.e. no template matches too much
#      (set SKIP_FALSE_POSITIVE=1 to skip this when you cannot bind port 80).
# Finally it runs the scanner on a "fresh machine" (empty cache, no Nuclei on PATH) with no flags except --yes.
set -euo pipefail
cd "$(dirname "$0")/.."

JAR=target/dooh-security-scanner.jar
[ -f "$JAR" ] || { echo "$JAR not found; run: mvn -B package" >&2; exit 1; }
TESTED="$(sed -nE 's/.*static final String VERSION = "([^"]+)".*/\1/p' src/main/java/com/dooh/NucleiInstaller.java)"
BASE="$(mktemp -d "${RUNNER_TEMP:-/tmp}/dooh-platform-test.XXXXXX")"
trap 'rm -rf "$BASE"' EXIT
UNAME="$(uname -s)"
echo "== Platform: $UNAME $(uname -m); Java: $(java -version 2>&1 | head -1)"

for WANT in latest "$TESTED"; do
  echo "== Nuclei '$WANT': download, verify, install"
  export DOOH_SCANNER_HOME="$BASE/home-$WANT"
  OUT="$(java -jar "$JAR" --install-nuclei --nuclei-version "$WANT" --yes </dev/null)"
  echo "$OUT"
  NUCLEI="$(printf '%s\n' "$OUT" | sed -n 's/^Nuclei is ready: //p' | tail -1)"
  [ -f "$NUCLEI" ] || { echo "Installed Nuclei not found: $NUCLEI" >&2; exit 1; }
  if [ "$WANT" != latest ]; then
    "$NUCLEI" -version -duc -nc 2>&1 | grep -q "v$WANT" || { echo "Wrong version installed" >&2; exit 1; }
  fi

  echo "== Nuclei '$WANT': every template loads"
  "$NUCLEI" -validate -t templates -nc -duc 2>&1 | tail -3

  case "${SKIP_FALSE_POSITIVE:+skip}$UNAME" in
    Linux)  # binding port 80 needs root on Linux
      echo "== Nuclei '$WANT': plain web server must PASS"
      sudo env "PATH=$PATH" NUCLEI="$NUCLEI" scripts/false-positive-check.sh ;;
    Darwin) # unprivileged processes may bind port 80 on macOS 10.14+
      echo "== Nuclei '$WANT': plain web server must PASS"
      NUCLEI="$NUCLEI" scripts/false-positive-check.sh ;;
  esac
done

echo "== Fresh machine: empty cache, no flags except --yes (downloads the latest Nuclei, then scans)"
export DOOH_SCANNER_HOME="$BASE/fresh"
set +e
java -jar "$JAR" -h 127.0.0.1 --yes --out "$BASE/scans" </dev/null
RC=$?
set -e
# 0 = PASS, 1 = findings (e.g. the runner's own sshd); 2+ = the scanner could not do its job.
[ "$RC" -lt 2 ] || { echo "Fresh-machine run failed with exit code $RC" >&2; exit 1; }
ls "$DOOH_SCANNER_HOME"/nuclei/*/ >/dev/null
echo "OK: $UNAME $(uname -m) passed"
