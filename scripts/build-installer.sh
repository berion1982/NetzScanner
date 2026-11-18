#!/usr/bin/env bash
# Baut das Windows-Setup-Programm (NSIS) fuer NetzScanner. Laeuft unter Linux/macOS,
# dort wird "makensis" gebraucht (Debian/Ubuntu: sudo apt install nsis;
# Fedora/Nobara: sudo dnf install mingw32-nsis).
# Aufruf: scripts/build-installer.sh            -> amd64 und arm64
#         scripts/build-installer.sh amd64      -> nur eine Architektur
# Ergebnis: dist/netzscanner-setup-<Version>-windows-<arch>.exe
set -euo pipefail
cd "$(dirname "$0")/.."

command -v makensis >/dev/null || { echo "Fehler: makensis (NSIS) nicht gefunden." >&2; exit 1; }

# Gleiche Versionsdaten wie scripts/build.sh
VERSION="$(tr -d '[:space:]' < VERSION)"
DATE="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
COMMIT="$(git rev-parse --short HEAD 2>/dev/null || echo unbekannt)"
PKG="github.com/berion1982/netzscanner/internal/version"
LDFLAGS="-s -w -X ${PKG}.Version=${VERSION} -X ${PKG}.BuildDate=${DATE} -X ${PKG}.Commit=${COMMIT} -H=windowsgui"

# Architekturen: Argumente oder beide
ARCHS=(amd64 arm64)
[[ $# -gt 0 ]] && ARCHS=("$@")
mkdir -p dist
cp LICENSE dist/LICENSE
cp internal/licenses/THIRD_PARTY_LICENSES.txt dist/THIRD_PARTY_LICENSES.txt

for arch in "${ARCHS[@]}"; do
  exe="dist/netzscanner-${VERSION}-windows-${arch}.exe"
  out="dist/netzscanner-setup-${VERSION}-windows-${arch}.exe"
  echo "-> $out"
  # Programm frisch bauen (GUI-Build ohne Konsolenfenster, siehe build.sh)
  CGO_ENABLED=0 GOOS=windows GOARCH="$arch" go build -ldflags "$LDFLAGS" -o "$exe" ./cmd/netzscanner
  makensis -V2 \
    -DVERSION="$VERSION" -DARCH="$arch" \
    -DEXE="$PWD/$exe" -DLICENSE="$PWD/LICENSE" \
    -DTHIRD="$PWD/internal/licenses/THIRD_PARTY_LICENSES.txt" \
    -DICO="$PWD/installer/netzscanner.ico" \
    -DOUTFILE="$PWD/$out" \
    installer/netzscanner.nsi
done
