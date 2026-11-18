#!/usr/bin/env bash
# Erzeugt die Windows-Ressourcendateien (.syso) mit dem Programm-Icon (I-086).
# Go bindet "rsrc_windows_<arch>.syso" beim Windows-Build automatisch ein, dadurch
# hat netzscanner.exe selbst ein Icon (Explorer, Taskleiste, Verknuepfungen).
#
# Nur noetig, wenn sich das Icon aendert (installer/netzscanner.ico). Die erzeugten
# .syso-Dateien sind eingecheckt; normale Builds brauchen dieses Skript NICHT.
# Der Generator (scripts/winres/main.go) nutzt nur die Go-Standardbibliothek.
set -euo pipefail
cd "$(dirname "$0")/.."
go run scripts/winres/main.go -ico installer/netzscanner.ico -out cmd/netzscanner
