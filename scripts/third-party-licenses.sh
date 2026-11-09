#!/usr/bin/env bash
# Erzeugt die Datei mit den Lizenztexten aller Fremdbibliotheken, die
# tatsaechlich in das NetzScanner-Programm einkompiliert werden.
#
# Warum: MIT-, BSD- und Apache-Lizenzen verlangen, dass ihr Lizenztext
# zusammen mit dem Programm weitergegeben wird. Go baut alle Bibliotheken
# in die eine Binary ein, deshalb muss die Datei bei jeder Weitergabe dabei sein.
#
# Aufruf:  scripts/third-party-licenses.sh
# Ergebnis: internal/licenses/THIRD_PARTY_LICENSES.txt (wird ins Programm
#           eingebettet und von "--licenses" ausgegeben)
#
# Bitte nach jeder Aenderung an go.mod neu ausfuehren und die Datei mit einchecken.
set -euo pipefail
cd "$(dirname "$0")/.."

OUT="internal/licenses/THIRD_PARTY_LICENSES.txt"

# Alle Module sicher lokal vorhanden haben (sonst fehlen Lizenzdateien).
go mod download

# Liste der Module, die wirklich im Programm landen (nicht nur Test-Abhaengigkeiten):
# "go list -deps" zaehlt alle Pakete auf, die cmd/netzscanner braucht.
# Ausgabe pro Zeile: Modulpfad Version Verzeichnis; das eigene Modul hat keine Version.
MODULES="$(go list -deps -f '{{with .Module}}{{if .Version}}{{.Path}} {{.Version}} {{.Dir}}{{end}}{{end}}' ./cmd/netzscanner | sort -u)"

{
  echo "NetzScanner - Lizenzen der verwendeten Fremdbibliotheken"
  echo "========================================================="
  echo
  echo "Diese Datei wird mit scripts/third-party-licenses.sh erzeugt."
  echo "Der NetzScanner selbst steht unter der GNU AGPL v3 (oder spaeter), siehe LICENSE."
  echo "Die folgenden Bibliotheken behalten ihre eigenen Lizenzen:"
  echo

  # Zuerst eine kurze Uebersicht, danach die vollstaendigen Texte.
  while read -r path ver dir; do
    echo "  - ${path} ${ver}"
  done <<< "$MODULES"
  echo

  # Die Go-Standardbibliothek steckt ebenfalls in jeder Binary (BSD-Lizenz).
  echo "################################################################"
  echo "# Go-Standardbibliothek $(go env GOVERSION)"
  echo "################################################################"
  echo "--- LICENSE ---"
  cat "$(go env GOROOT)/LICENSE"
  echo

  while read -r path ver dir; do
    echo "################################################################"
    echo "# ${path} ${ver}"
    echo "################################################################"
    # Lizenz- und NOTICE-Dateien im Modul-Hauptverzeichnis suchen
    # (Apache-2.0 verlangt, eine vorhandene NOTICE-Datei mitzuliefern).
    found=0
    for f in "$dir"/LICENSE* "$dir"/LICENCE* "$dir"/COPYING* "$dir"/NOTICE*; do
      [[ -f "$f" ]] || continue
      found=1
      echo "--- $(basename "$f") ---"
      cat "$f"
      echo
    done
    if [[ $found -eq 0 ]]; then
      # Nicht stillschweigend weglassen: fehlende Lizenz muss jemand pruefen.
      echo "!!! Keine Lizenzdatei im Modul gefunden - bitte manuell pruefen !!!"
      echo "WARNUNG: keine Lizenzdatei fuer ${path}" >&2
    fi
    echo
  done <<< "$MODULES"
} > "$OUT"

echo "geschrieben: $OUT ($(wc -l < "$OUT") Zeilen)"
