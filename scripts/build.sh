#!/usr/bin/env bash
# Baut NetzScanner fuer alle Zielplattformen (Cross-Compile, kein CGO noetig).
# Aufruf: scripts/build.sh            -> alle Plattformen nach dist/
#         scripts/build.sh native     -> nur die aktuelle Plattform
set -euo pipefail
cd "$(dirname "$0")/.."

# Versionsdaten sammeln: Nummer aus VERSION, Datum in UTC, Git-Hash (falls vorhanden)
VERSION="$(tr -d '[:space:]' < VERSION)"
DATE="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
COMMIT="$(git rev-parse --short HEAD 2>/dev/null || echo unbekannt)"
PKG="github.com/berion1982/netzscanner/internal/version"
LDFLAGS="-s -w -X ${PKG}.Version=${VERSION} -X ${PKG}.BuildDate=${DATE} -X ${PKG}.Commit=${COMMIT}"

# Zielplattformen: Betriebssystem/Architektur (inkl. ARM fuer Raspberry Pi)
TARGETS=(linux/amd64 linux/arm64 linux/arm windows/amd64 windows/arm64 darwin/amd64 darwin/arm64)

mkdir -p dist

# Lizenzdateien neben die Programme legen: Die AGPL (LICENSE) und die Lizenzen
# der Fremdbibliotheken muessen bei jeder Weitergabe der Binaries dabei sein.
cp LICENSE dist/LICENSE
cp internal/licenses/THIRD_PARTY_LICENSES.txt dist/THIRD_PARTY_LICENSES.txt

if [[ "${1:-}" == "native" ]]; then
  CGO_ENABLED=0 go build -ldflags "$LDFLAGS" -o dist/netzscanner ./cmd/netzscanner
  exit 0
fi

for t in "${TARGETS[@]}"; do
  os="${t%/*}"; arch="${t#*/}"
  ext=""; [[ "$os" == "windows" ]] && ext=".exe"
  out="dist/netzscanner-${VERSION}-${os}-${arch}${ext}"
  echo "-> $out"
  CGO_ENABLED=0 GOOS="$os" GOARCH="$arch" go build -ldflags "$LDFLAGS" -o "$out" ./cmd/netzscanner
done
