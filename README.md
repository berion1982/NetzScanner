# NetzScanner

Netzwerk-Scanner für das **Onboarding neuer Netze**: liefert maximale Informationen über alle Geräte.
Status: **v0.3.0 – Scan-Kern** (TCP-Portscan, MAC, Namen, Banner). Topologie, Logins und Export folgen.

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
./dist/netzscanner --demo     # mit Demo-Daten ansehen
./dist/netzscanner            # startet die Oberfläche auf http://127.0.0.1:8484
./dist/netzscanner --listen 0.0.0.0:8484   # von anderen Rechnern erreichbar (z. B. Raspberry)
```
Voraussetzung: Go ≥ 1.24.

## Fehlersuche
```bash
./dist/netzscanner --diagnose 192.168.178.1   # prüft ein Gerät Schritt für Schritt
```
Die Ausgabe zeigt, welche Quellen (DNS, Zertifikat, Webseite) etwas liefern – hilfreich, wenn ein Name fehlt.

## Design-Konzepte ansehen
`docs/design/index.html` im Browser öffnen.

## Dokumente
[CHANGELOG](CHANGELOG.md) · [HANDOVER](HANDOVER.md) · [CLAUDE.md](CLAUDE.md)

## Hinweis
Nur in Netzen scannen, für die du die Erlaubnis hast.
