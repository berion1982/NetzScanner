# HANDOVER – Übergabe für die nächste Claude-Sitzung

**Stand:** v0.24.0 · **Datum:** 2026-11-09 · Scan im echten LAN (FritzBox), Export und Router-Login von Sascha bestätigt.
Ausführlicher Verlauf (alte Fassung dieser Datei, nichts gelöscht): `docs/HANDOVER-Verlauf.md`.

## Entscheidungen (von Sascha bestätigt)
- **Leitlinie:** Der Scanner **sammelt und exportiert** (nur lesend). Kein Zurückschreiben in Router/Server/DHCP.
- Sprache **Go**, Web-UI eingebettet (`embed`), Zugriff per Browser (`docs/ADR-0001-sprache.md`).
- Repo-Freigabe: Dateien, Commits, Pushes, PRs. Löschen nur nach Rückfrage. Änderungen immer als PR, keine GitHub-Actions-Tests.
- Keine Einzelgeräte-Tabellen, keine Änderungen nur für ein einzelnes Netz (siehe `CLAUDE.md`).

## Was existiert
- **Start:** `./dist/netzscanner` → http://127.0.0.1:8484. Optionen: `--demo`, `--listen`, `--token`/`--no-token` (I-025), `--allow-public`, `--diagnose <IP>`, `--diagnose-router <IP>`, `--diagnose-mesh <IP>`, `--data <Datei>`, `--no-save`, `--version`. Bauen: `scripts/build.sh` (7 Plattformen).
- **Scan** (`internal/scan`): Ziel-Parser (Bereiche/Listen), TCP-Portscan, ARP/MAC, Banner, OUI (IEEE-Liste), OS-Vermutung (`osguess.go`), Namenssuche (`names.go`: DNS, mDNS, NetBIOS, LLMNR, SSDP, TLS, Seitentitel), Kategorien (`category.go`), Gateway/Uplink (`gateway.go`), SNMP (`snmp.go`, `lldp.go`, `vendor.go`), `MarkSharedMAC` (⚠ gleiche MAC).
- **Web** (`internal/web`): Server, Scan-API mit Live-Ergebnissen, Eingaben (Name, Benutzer, Standort, Kategorie, eigene Kategorien) mit Zwischenspeicher `eingaben.json` (`store.go`), SNMP-Topologie, Router (`router.go`), Mesh (`mesh.go`), Windows-DHCP (`dhcp.go`), Reservierungen (`reservations.go`), Export-API, Oberfläche `static/index.html`.
- **Router** (`internal/router`): FRITZ!Box per TR-064 (Geräteliste, Info, WLAN, Mesh). Nur Loopback, ein Anmeldeversuch pro Klick, Zugangsdaten und Ergebnis nur im RAM.
- **DHCP** (`internal/dhcp`): Windows-DHCP per WinRM (nur mit Testdaten geprüft).
- **Export** (`internal/export`): CSV, HTML, Markdown, Topologie-PDF (`pdf.go`), Router-Info, Reservierungen – ohne Passwörter, mit CSV-Injection-Schutz.
- **Doku:** README, CHANGELOG, IDEAS, CLAUDE.md, ADR-0001, `docs/design/`.

## Nächster Schritt
Reihenfolge (I-025 erledigt in 0.24.0; Befunde aus dem Test von 0.23.7 stehen als Ideen in `IDEAS.md`; danach laut Vorschlag I-064 → I-035 → I-034 → I-060/I-061):
1. **I-065** Gleiche MAC in PDF/Exporten kennzeichnen, nicht als eigene Netzwerkgeräte zählen.
2. **I-067** Mesh-Zuordnung prüfen (Gruppe hing im PDF unter einem Smartphone).
3. **I-066** Kennungs-Namen besser abwerten · **I-068** Status „Connecting“ + PDF-Kleinigkeiten.
4. **I-059** Kategorie „Mobilgeräte“ · **I-053** SNMP v3 · **I-020/I-022** Logins.

Pro Chat genau **eine** Idee, danach `/clear`.

## Noch im LAN zu prüfen (Sascha)
- Windows-DHCP (WinRM) und Reiter „Reservierungen“ – nur mit Testdaten geprüft, braucht einen Windows Server (DHCP-Rolle, WinRM, Benutzer in „DHCP-Benutzer“ + „Remoteverwaltungsbenutzer“). Bei Fehlern die Meldung schicken.
- SNMP-Topologie und LLDP an einem verwalteten Switch (SNMP v2c, LLDP am Gerät an): stimmen Ports/Uplinks?
- Hersteller-Erkennung per `sysObjectID` (`vendor.go`): Tabelle ungeprüft.
- Kategorie-Vermutung und OS-Vermutung bei weiteren Geräten; fehlende oder falsche Geräte melden.
- Zugangstoken (0.24.0): Login im echten Browser über `--listen 0.0.0.0:8484` und `/?token=…` testen (bisher nur Unit-Test und curl).
- Die Annahmen im Mesh-Parser (`node_1` = Vorgänger, Raten in kbit/s) sind nur an einer Box gesehen.

## Bekannte Grenzen
- Zugangstoken (I-025) schützt nur vor zufälligem Zugriff: Verbindung bleibt HTTP, das Token ist im selben Netz mitlesbar. TLS ist offen.
- FRITZ!Box-Reservierungen sind per TR-064 **nicht auslesbar** (`AddressSource` Static ≠ feste Zuweisung). Reiter „Reservierungen“ = nur Windows-DHCP.
- Router-Login erst **nach Scan-Ende** (vorher fehlen die MACs); Router-/Mesh-Daten nur im RAM → nach Neustart neu anmelden. Nach mehreren Logins kann eine kurze Sperre greifen (ungeprüft).
- Zufällige/lokale MACs haben keinen Hersteller. Geräte mit gleicher MAC werden nur markiert (⚠), nie ausgeblendet.
- Offen: SNMP v3 (I-053), VLAN-Communities (I-054), andere Router, Kerberos/HTTPS für WinRM, Rest von I-013 (SMB/TTL), Verschlüsselung der Eingaben-Datei.
- I-058 (Import/Zurückschreiben) wurde verworfen (Leitlinie: nur lesen).

## Roadmap
| Version | Inhalt |
|---|---|
| 0.2.0 ✅ | Web-UI, Hilfe, Web-Links, Demo-Daten |
| 0.3.x ✅ | Scan-Kern (Portscan, ARP/MAC, DNS, Banner), Auswahl/Umbenennen, `--diagnose` |
| 0.4.x ✅ | Export CSV/HTML/Markdown, Benutzername, TLS-Infos, OUI-Mechanismus |
| 0.5.x ✅ | mDNS/NetBIOS/LLMNR/SSDP, Live-Ergebnisse, Bereiche, Hilfe, Gateway-Stern, volle OUI-Liste |
| 0.6.0–0.13.x ✅ | CSV mit Hersteller, Topologie-PDF, OS-Vermutung, Standort, Kategorien (inkl. eigene), Eingaben speichern, Sammelgruppen |
| 0.14.x ✅ | SNMP-Topologie, kompaktere Tabelle |
| 0.15.0–0.16.0 ✅ | FRITZ!Box-Login (TR-064), Router-Info + WLAN |
| 0.17.0 ✅ | LLDP per SNMP (I-051) |
| 0.18.0 ✅ | Hersteller aus `sysObjectID` (I-052) |
| 0.19.0–0.20.0 ✅ | Windows-DHCP per WinRM, Reiter „Reservierungen“ (I-056/I-057) |
| 0.21.0–0.22.x ✅ | `--diagnose-router`, Reservierungen der Box als nicht machbar geklärt |
| 0.23.0–0.23.7 ✅ | Mesh-Topologie (I-055 c), Router-Login-Meldungen, Linien in Karte und PDF, ⚠ „MAC mehrfach“ |
| Plan | I-065 → I-067 → I-066/I-068 → I-059 → I-053 → I-020/I-022 |
| später (Plan) | SNMP sysName, ICMP mit Rechten, SMB/TTL, JSON/XLSX-Export, Scan-Vergleich, Eingaben-Datei verschlüsseln |

„Plan“ = Vorschlag; Sascha entscheidet die Reihenfolge, Details in `IDEAS.md`.

## Versionsführung (Pflicht bei jeder Änderung)
- Nummer in `VERSION` (Root) **und** `internal/version/VERSION` gleich halten (`go test ./...` prüft das). Zusätzlich: Kopf `CHANGELOG.md`, „Stand“ hier, Status in `IDEAS.md`.
- Anzeige: `--version`, `/api/version`, Hilfe-Seite, Exporte.

## Hinweise
- OUI-Liste `internal/scan/data/oui.txt` (IEEE) mit `scripts/update-oui.sh` aktualisieren. Bei `git pull`-Konflikt lokale Datei umbenennen (`.alt`), nicht löschen.
- Abhängigkeiten: Go-Standard + `go-pdf/fpdf`, `gosnmp`; neue Libs nur Pure-Go, kein CGO.
- ICMP/ARP-Raw braucht Rechte; Fallback TCP-Connect ist Pflicht.
- Erkenntnis: Mit systemd-resolved liefert Reverse-DNS für das Gateway `_gateway`; der echte Name kommt vom DNS des Geräts (Quelle `dns-geraet`).
