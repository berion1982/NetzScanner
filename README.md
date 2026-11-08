# NetzScanner

Netzwerk-Scanner für das **Onboarding neuer Netze**: liefert maximale Informationen über alle Geräte.
Status: **v0.1.0 – Grundlagen und Design-Konzepte** (Scanner noch nicht implementiert).

## Ziele
- Pro Gerät: **IP, Name, MAC (+Hersteller), offene Ports**
- Topologie so weit abfragbar (LLDP/CDP, SNMP, Traceroute)
- Optionale Logins (Router, Server/Domain-Admins) für Zusatzinfos
- Export: **CSV** und lesbare Tabelle, später JSON/XLSX
- Dunkle UI: schneller Überblick, bei Bedarf Details · eingebaute Hilfe-Seite
- Plattformen: Linux, Windows, macOS, ARM (z. B. Raspberry Pi)

## Technik
Go, eine statische Binary, Web-UI eingebettet. Begründung: [docs/ADR-0001-sprache.md](docs/ADR-0001-sprache.md).

## Bauen
```bash
scripts/build.sh          # alle Plattformen -> dist/
scripts/build.sh native   # nur aktuelle Plattform
./dist/netzscanner --version
```
Voraussetzung: Go ≥ 1.24.

## Design-Konzepte ansehen
`docs/design/index.html` im Browser öffnen.

## Dokumente
[CHANGELOG](CHANGELOG.md) · [HANDOVER](HANDOVER.md) · [CLAUDE.md](CLAUDE.md)

## Hinweis
Nur in Netzen scannen, für die du die Erlaubnis hast.
