# Changelog
Format: [Keep a Changelog](https://keepachangelog.com/de/), Versionierung: [SemVer](https://semver.org/lang/de/).
Das Builddatum wird beim Build automatisch eingesetzt (`NetzScanner --version`).

## [Unreleased]
### Hinzugefügt
- `IDEAS.md`: Ideenliste mit Priorität, Aufwand und Status; Regel dazu in `CLAUDE.md`.

## [0.3.1] – 2026-11-08
### Hinzugefügt
- Geräte per Häkchen auswählen (einzeln, „Alle“, „Auswahl aufheben“, Zähler); Auswahl wird auch in der Topologie markiert (I-040).
- Gerätenamen anpassen im Detail-Panel, mit „Zurücksetzen“ und Anzeige des Scan-Namens; Namen bleiben bis zum Programmende und über neue Scans (nach IP) erhalten (I-021).
- API `POST /api/hosts/name` (max. 64 Zeichen, keine Steuerzeichen).
### Hinweis
- Auswahl und Namen liegen nur im Speicher; der Export (CSV, Lesezeichen) folgt in I-030/I-032.

## [0.3.0] – 2026-11-08
### Hinzugefügt
- Scan-Kern (`internal/scan`): Zielauswertung (CIDR/Einzel-IP, max. /16), TCP-Connect-Portscan ohne Admin-Rechte, Banner-Abfrage, Reverse-DNS, MAC aus der ARP-Tabelle (Linux, Windows, macOS), Hersteller (kleine Beispieltabelle).
- Scan-API (`POST /api/scan`, Status, Abbruch) und Scan-Leiste in der Oberfläche mit Fortschritt.
- Startoptionen `--demo` (Demo-Daten) und `--allow-public`.
### Geändert
- Ohne `--demo` startet die Liste leer; es werden nur noch echte Scan-Ergebnisse gezeigt.
### Sicherheit
- Öffentliche Adressen sind standardmäßig gesperrt.
- POST nur mit `application/json` und passendem Origin (Schutz vor Cross-Site-Aufrufen auf localhost).
- Banner und Namen aus dem Netz werden bereinigt und nur als Text angezeigt.
### Bekannte Grenzen
- MAC nur im selben Subnetz; Geräte ohne offene Port-Antwort und ohne ARP-Eintrag werden nicht gefunden.
- Hersteller-Tabelle unvollständig; keine OS-Erkennung; Topologie noch ohne LLDP/SNMP (0.4.0).
- Nur lokal getestet (localhost); echter LAN-Scan steht aus.

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
