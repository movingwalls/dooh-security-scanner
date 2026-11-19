#!/usr/bin/env bash
# Builds the self-contained bundle (native launcher + its own Java runtime + pinned Nuclei + templates)
# for ONE platform. It must run on that platform, because jpackage cannot cross-compile.
#
#   scripts/build-bundle.sh <platform> <version>
#
#   platform: windows-x64 | linux-x64 | linux-arm64 | macos-x64 | macos-arm64
#   version:  e.g. 1.0.0-rc3 (as in the tag, without the leading "v")
#
# Needs: JDK 17+ (jpackage), the jar already built at target/dooh-security-scanner.jar, curl, unzip.
# Output: dist/dooh-security-scanner-<version>-<platform>.{zip|tar.gz} and a matching .sha256
# The Nuclei checksum is read from NucleiInstaller.java, so there is one place to update on a Nuclei bump.
set -euo pipefail

PLATFORM="${1:?usage: $0 <platform> <version>}"
VERSION="${2:?usage: $0 <platform> <version>}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

case "$PLATFORM" in
  windows-x64) NUCLEI_KEY=windows_amd64; EXE=nuclei.exe ;;
  linux-x64)   NUCLEI_KEY=linux_amd64;   EXE=nuclei ;;
  linux-arm64) NUCLEI_KEY=linux_arm64;   EXE=nuclei ;;
  macos-x64)   NUCLEI_KEY=macOS_amd64;   EXE=nuclei ;;
  macos-arm64) NUCLEI_KEY=macOS_arm64;   EXE=nuclei ;;
  *) echo "Unknown platform: $PLATFORM" >&2; exit 2 ;;
esac

JAVA_SRC=src/main/java/com/dooh/NucleiInstaller.java
NUCLEI_VERSION="$(sed -nE 's/.*static final String VERSION = "([^"]+)".*/\1/p' "$JAVA_SRC")"
# the archive hashes are in the SHA256 map; BINARY_SHA256 (hashes of the extracted executables) uses the same keys
NUCLEI_SHA256="$(sed -n '/Map<String, String> SHA256 = /,/);/p' "$JAVA_SRC" | sed -nE "s/.*\"${NUCLEI_KEY}\", *\"([0-9a-f]{64})\".*/\1/p")"
[ -n "$NUCLEI_VERSION" ] && [ -n "$NUCLEI_SHA256" ] || { echo "Cannot read pinned Nuclei version/checksum for $NUCLEI_KEY from $JAVA_SRC" >&2; exit 1; }
[ -f target/dooh-security-scanner.jar ] || { echo "target/dooh-security-scanner.jar not found; run: mvn -B package" >&2; exit 1; }

sha256_of() { if command -v sha256sum >/dev/null; then sha256sum "$1" | cut -d' ' -f1; else shasum -a 256 "$1" | cut -d' ' -f1; fi; }

WORK="$ROOT/dist/work-$PLATFORM"
rm -rf "$WORK"; mkdir -p "$WORK/input" "$WORK/nuclei"

echo "== Downloading Nuclei $NUCLEI_VERSION ($NUCLEI_KEY) and verifying its checksum"
curl -fsSL -o "$WORK/nuclei.zip" \
  "https://github.com/projectdiscovery/nuclei/releases/download/v${NUCLEI_VERSION}/nuclei_${NUCLEI_VERSION}_${NUCLEI_KEY}.zip"
ACTUAL="$(sha256_of "$WORK/nuclei.zip")"
[ "$ACTUAL" = "$NUCLEI_SHA256" ] || { echo "Nuclei checksum mismatch: expected $NUCLEI_SHA256, got $ACTUAL" >&2; exit 1; }
unzip -q "$WORK/nuclei.zip" "$EXE" -d "$WORK/nuclei"
chmod +x "$WORK/nuclei/$EXE"

cp target/dooh-security-scanner.jar "$WORK/input/"
cp -r templates "$WORK/input/"
cp "$WORK/nuclei/$EXE" LICENSE NOTICE THIRD_PARTY_LICENSES.md "$WORK/input/"

echo "== Building the native app with its own Java runtime (jpackage)"
APP_VERSION="${VERSION%%-*}"   # jpackage wants plain numbers: 1.0.0-rc3 -> 1.0.0
OUT="$WORK/out"
EXTRA=()
[ "$PLATFORM" = windows-x64 ] && EXTRA+=(--win-console)
jpackage --type app-image --name dooh-security-scanner \
  --input "$WORK/input" --main-jar dooh-security-scanner.jar \
  --main-class com.dooh.DOOHSecurityScanner \
  --app-version "$APP_VERSION" --vendor "Moving Walls" \
  --dest "$OUT" ${EXTRA[@]+"${EXTRA[@]}"}   # (empty-array safe on macOS bash 3.2)

# Folder that people extract and work in, plus the real executable inside it.
FOLDER="$OUT/dooh-security-scanner"
case "$PLATFORM" in
  windows-x64)
    BIN="$FOLDER/dooh-security-scanner.exe"
    ;;
  linux-*)
    BIN="$FOLDER/bin/dooh-security-scanner"
    ;;
  macos-*)
    # jpackage produces a .app bundle; keep it inside a normal folder next to the docs.
    mkdir -p "$WORK/macfolder"
    mv "$OUT/dooh-security-scanner.app" "$WORK/macfolder/"
    FOLDER="$WORK/macfolder"
    BIN="$FOLDER/dooh-security-scanner.app/Contents/MacOS/dooh-security-scanner"
    # Apple Silicon refuses unsigned code; an ad-hoc signature is enough to run (no developer identity needed).
    codesign --force --deep -s - "$FOLDER/dooh-security-scanner.app"
    ;;
esac

# Unix: one friendly launcher at the top of the folder, so the command is the same everywhere:
#   ./dooh-security-scanner -t targets.txt
if [ "$PLATFORM" != windows-x64 ]; then
  REL="${BIN#"$FOLDER"/}"
  cat > "$FOLDER/dooh-security-scanner" <<EOF
#!/bin/sh
# Launcher for the bundled app (includes its own Java runtime; no Java install needed).
DIR="\$(cd "\$(dirname "\$0")" && pwd)"
exec "\$DIR/${REL}" "\$@"
EOF
  chmod +x "$FOLDER/dooh-security-scanner"
fi

cp README.md SECURITY.md CHANGELOG.md targets.example.txt "$FOLDER/"
cp -r docs "$FOLDER/"
if [ "$PLATFORM" = windows-x64 ]; then
  cp dooh-scan.bat dooh-security-scanner*.bat "$FOLDER/"
fi

echo "== Smoke test"
"$BIN" --version
"$BIN" --help >/dev/null
# No Nuclei given and downloads forbidden => must fail cleanly with exit code 3, not crash.
set +e
"$BIN" -h 127.0.0.1 --yes --offline --nuclei missing-nuclei >/dev/null 2>&1
RC=$?
set -e
[ "$RC" -eq 3 ] || { echo "Expected exit code 3 for a missing Nuclei, got $RC" >&2; exit 1; }
# The scanner must find and TRUST the Nuclei shipped in the bundle (its SHA-256 must still match the official
# build after packaging/signing) and scan with it: empty cache, downloads forbidden. Exit 0/1 = scanned.
set +e
DOOH_SCANNER_HOME="$WORK/empty-home" "$BIN" -h 127.0.0.1 --yes --offline --out "$WORK/smoke-scans" >"$WORK/smoke.log" 2>&1
RC=$?
set -e
if [ "$RC" -ge 2 ] || grep -q "Skipping .*not the official Nuclei" "$WORK/smoke.log"; then
  echo "The bundled Nuclei was not accepted or the scan failed (exit $RC):" >&2; cat "$WORK/smoke.log" >&2; exit 1
fi
# The bundled Nuclei must be the pinned one and must run on this CPU.
"$(dirname "$(find "$FOLDER" -name "$EXE" -type f | head -1)")/$EXE" -version 2>&1 | grep -q "$NUCLEI_VERSION" \
  || { echo "Bundled Nuclei did not report version $NUCLEI_VERSION" >&2; exit 1; }

echo "== Archiving"
NAME="dooh-security-scanner-${VERSION}-${PLATFORM}"
mkdir -p "$ROOT/dist"
STAGE="$WORK/stage"; rm -rf "$STAGE"; mkdir -p "$STAGE"
cp -a "$FOLDER" "$STAGE/dooh-security-scanner-${VERSION}"
if [ "$PLATFORM" = windows-x64 ]; then
  ARCHIVE="$ROOT/dist/${NAME}.zip"; rm -f "$ARCHIVE"
  if command -v 7z >/dev/null; then (cd "$STAGE" && 7z a -tzip "$ARCHIVE" "dooh-security-scanner-${VERSION}" >/dev/null)
  else (cd "$STAGE" && zip -qr "$ARCHIVE" "dooh-security-scanner-${VERSION}"); fi
else
  ARCHIVE="$ROOT/dist/${NAME}.tar.gz"
  tar -C "$STAGE" -czf "$ARCHIVE" "dooh-security-scanner-${VERSION}"   # tar keeps the executable bits
fi
echo "$(sha256_of "$ARCHIVE")  $(basename "$ARCHIVE")" > "${ARCHIVE}.sha256"
rm -rf "$WORK"
echo "Built $ARCHIVE"
