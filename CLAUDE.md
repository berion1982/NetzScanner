# CLAUDE.md – Arbeitsregeln für Claude in diesem Repo

Projekt: **NetzScanner** (Go + eingebettete dunkle Web-UI). Besitzer: Sascha. Sprache: Deutsch.
Zuerst `HANDOVER.md` lesen – dort steht der aktuelle Stand und der nächste Schritt.

## Token sparen (wichtig)
- Nicht das ganze Repo lesen. Erst `HANDOVER.md`, dann gezielt mit Grep/Glob nur die betroffenen Dateien.
- Große Dateien nur mit `offset`/`limit` lesen. Keine Dateien nach dem Edit erneut lesen.
- Ein Chat = eine Aufgabe. Nach jedem fertigen PR den Chat beenden (`/clear`) und neu starten.
- Bei langen Chats früh `/compact` oder `/clear`; vorher `HANDOVER.md` aktualisieren.
- Keine langen Erklärungen im Chat: Ergebnis in 3–5 Sätzen, Details gehören in Commit/PR/Doku.
- Unabhängige Tool-Aufrufe parallel ausführen. Keine Subagenten, außer ausdrücklich verlangt.
- Keine Ausgaben großer Logs in den Chat; mit `tail`/`grep` filtern.

## Git-Workflow
- Jede Änderung auf dem zugewiesenen Branch, dann **als Pull Request** (Sascha pullt selbst).
- Kleine, thematisch saubere Commits. Keine Merges/Force-Pushes ohne Auftrag.
- **Nichts löschen ohne Rückfrage** – lieber umbenennen (z. B. `datei.alt`).
- Jede sichtbare Änderung: `CHANGELOG.md` ergänzen, bei Release `VERSION` anheben (SemVer).
- GitHub-Actions-Tests werden **nicht** genutzt. Lokal prüfen: `go vet ./... && go test ./...`.

## Code-Regeln
- Detaillierte deutsche Kommentare, lesbarer Code (kurze Funktionen, sprechende Namen).
- Plattformunabhängig: Linux, Windows, macOS, ARM. Kein CGO, nur Go-Standard + wenige Pure-Go-Libs.
- Raw-Sockets/ICMP brauchen Rechte → immer Fallback (TCP-Connect) einbauen und dokumentieren.
- Zugangsdaten (Router, Domain-Admin) nie loggen, nie in Exporte schreiben, nie einchecken.
- Unsicheres klar benennen („Ich weiß es nicht“), nichts erfinden.

## Befehle
- `scripts/build.sh` (alle Plattformen) · `scripts/build.sh native` · `go test ./...`
