#!/usr/bin/env bash
# Aktualisieren, bauen, starten - alles mit einem Aufruf (I-071).
#
#   scripts/start.sh                  -> git pull, nativ bauen, NetzScanner starten
#   scripts/start.sh --listen 0.0.0.0:8484 --token abc
#                                     -> alle Optionen gehen unveraendert an das Programm
#
# Ablauf (bricht beim ersten Fehler ab, damit nie eine alte Version startet):
#   1. git pull --ff-only   (nur "vorspulen": keine Merges, keine Ueberraschungen;
#                            bei lokalen Konflikten Meldung lesen, nichts wird ueberschrieben)
#   2. scripts/build.sh native   (baut dist/netzscanner fuer diesen Rechner, ohne CGO)
#   3. dist/netzscanner "$@"     (ersetzt diese Shell durch das Programm: Strg+C beendet es sauber)
#
# Hinweis: "git pull" holt den Stand des Branches, auf dem man gerade ist.
# Fuer Windows (ohne bash) gilt das Skript nicht; dort build.sh in Git-Bash bzw. WSL nutzen.
set -euo pipefail

# Immer vom Projektordner aus arbeiten, egal von wo das Skript aufgerufen wird.
cd "$(dirname "$0")/.."

echo "==> git pull"
git pull --ff-only

echo "==> bauen (nativ)"
./scripts/build.sh native

echo "==> starten"
exec ./dist/netzscanner "$@"
