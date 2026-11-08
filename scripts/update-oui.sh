#!/usr/bin/env bash
# Erzeugt internal/scan/data/oui.txt aus der oeffentlichen IEEE-OUI-Registry (MA-L).
# Quelle: https://standards-oui.ieee.org/oui/oui.csv  (Spalten: Registry,Assignment,Organization Name,Address)
# Nutzung:  scripts/update-oui.sh [pfad/zur/oui.csv]   (ohne Argument wird heruntergeladen)
# Die IEEE-Lizenz-/Nutzungsbedingungen bitte selbst pruefen, bevor die Datei eingecheckt wird.
set -euo pipefail
cd "$(dirname "$0")/.."
OUT=internal/scan/data/oui.txt
SRC="${1:-}"
if [ -z "$SRC" ]; then
  SRC="$(mktemp)"
  curl -fsSL https://standards-oui.ieee.org/oui/oui.csv -o "$SRC"
fi
{
  echo "# Herstellerpraefixe (OUI) im Format: 6 Hex-Zeichen;Herstellername"
  echo "# Quelle: IEEE MA-L Registry (oui.csv), erzeugt mit scripts/update-oui.sh am $(date +%F)"
  # Echte CSV-Auswertung (Namen koennen Kommas/Anfuehrungszeichen enthalten) per Python.
  python3 -I - "$SRC" <<'PY'
import csv, sys
with open(sys.argv[1], newline="", encoding="utf-8-sig") as f:
    for row in csv.reader(f):
        if len(row) >= 3 and len(row[1]) == 6:
            name = row[2].replace(";", ",").strip()
            print(f"{row[1].upper()};{name}")
PY
} > "$OUT"
echo "Geschrieben: $OUT ($(wc -l < "$OUT") Zeilen)"
