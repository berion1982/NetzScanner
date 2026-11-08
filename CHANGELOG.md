# Changelog
Format: [Keep a Changelog](https://keepachangelog.com/de/), Versionierung: [SemVer](https://semver.org/lang/de/).
Das Builddatum wird beim Build automatisch eingesetzt (`NetzScanner --version`).

## [Unreleased]

## [0.2.0] – 2026-11-08
### Hinzugefügt
- Eingebauter Webserver (`--listen`, Standard nur lokal `127.0.0.1:8484`) mit eingebetteter dunkler Oberfläche.
- Gemischtes Design A+B: Übersicht (Kennzahlen, Geräteliste, Details) und Reiter Topologie.
- Klickbare Web-Zugänge pro Gerät (Ports 80, 443, 5000, 5001, 8080 …), Öffnen in neuem Tab.
- Hilfe-Seite in der Oberfläche, Versions-/Builddatum-Anzeige in der Fußzeile.
- Datenmodell `Host`/`Port`, Demo-Daten (Scan-Kern folgt), Tests für Links und Server.
### Sicherheit
- Texte aus dem Netz werden nur als Text (nie als HTML) angezeigt; Link-URLs entstehen nur aus validierter IP.

## [0.1.0] – 2026-11-08
### Hinzugefügt
- Projektgrundlagen: README, CHANGELOG, HANDOVER, CLAUDE.md.
- Sprachentscheidung Go (ADR-0001).
- Go-Grundgerüst mit `--version` (Versionsnummer, Builddatum, Commit).
- Build-Skript für Linux/Windows/macOS inkl. ARM (`scripts/build.sh`).
- Drei dunkle Design-Konzepte als klickbare Entwürfe (`docs/design/`).
