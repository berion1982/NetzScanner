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
./dist/netzscanner            # startet die Oberfläche auf http://127.0.0.1:8484 und öffnet den Browser (abschaltbar: --no-browser); beenden mit dem Knopf „Beenden“ oder Strg+C. Die Windows-.exe öffnet kein Konsolenfenster
./dist/netzscanner --listen 0.0.0.0:8484   # von anderen Rechnern erreichbar (z. B. Raspberry); zeigt ein Zugangstoken an
./dist/netzscanner --listen 0.0.0.0:8484 --token MeinGeheimesToken   # eigenes Token (oder Umgebung NETZSCANNER_TOKEN)
```
Voraussetzung: Go ≥ 1.24.

## Fehlersuche
```bash
./dist/netzscanner --scan 192.168.178.0/24 --out kunde.csv   # ohne Browser: scannt und schreibt CSV/MD/HTML/PDF
./dist/netzscanner --diagnose 192.168.178.1   # prüft ein Gerät Schritt für Schritt
```
Die Ausgabe zeigt, welche Quellen (DNS, Zertifikat, Webseite) etwas liefern – hilfreich, wenn ein Name fehlt.

## Design-Konzepte ansehen
`docs/design/index.html` im Browser öffnen.

## Dokumente
[CHANGELOG](CHANGELOG.md) · [HANDOVER](HANDOVER.md) · [CLAUDE.md](CLAUDE.md)

## Lizenz
NetzScanner ist freie Software unter der **GNU Affero General Public License v3 oder später** (`AGPL-3.0-or-later`), siehe [LICENSE](LICENSE).
Kurz (rechtlich gilt der Lizenztext): kostenlos nutzen, weitergeben und verändern ist erlaubt. Wer das Programm verändert weitergibt **oder über ein Netzwerk anbietet**, muss den Quellcode unter derselben Lizenz offenlegen. Keine Garantie.
Die eingebauten Fremdbibliotheken behalten ihre Lizenzen (MIT, BSD, Apache-2.0, MPL-2.0): `./dist/netzscanner --licenses` bzw. `THIRD_PARTY_LICENSES.txt` neben dem Programm. Nach Änderungen an `go.mod`: `scripts/third-party-licenses.sh` ausführen.

## Hinweis
Nur in Netzen scannen, für die du die Erlaubnis hast.
