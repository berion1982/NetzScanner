# HANDOVER – Übergabe für die nächste Claude-Sitzung

**Stand:** v0.32.0 · **Datum:** 2026-11-09 · Scan im echten LAN (FritzBox), Export und Router-Login von Sascha bestätigt.
Ausführlicher Verlauf (alte Fassung dieser Datei, nichts gelöscht): `docs/HANDOVER-Verlauf.md`.

## Entscheidungen (von Sascha bestätigt)
- **Leitlinie:** Der Scanner **sammelt und exportiert** (nur lesend). Kein Zurückschreiben in Router/Server/DHCP.
- Sprache **Go**, Web-UI eingebettet (`embed`), Zugriff per Browser (`docs/ADR-0001-sprache.md`).
- Repo-Freigabe: Dateien, Commits, Pushes, PRs. Löschen nur nach Rückfrage. Änderungen immer als PR, keine GitHub-Actions-Tests.
- Keine Einzelgeräte-Tabellen, keine Änderungen nur für ein einzelnes Netz (siehe `CLAUDE.md`).

## Was existiert
- **Start:** `./dist/netzscanner` → http://127.0.0.1:8484. Optionen: `--demo`, `--listen`, `--token`/`--no-token` (I-025), `--allow-public`, `--diagnose <IP>`, `--diagnose-router <IP>`, `--diagnose-mesh <IP>`, `--data <Datei>`, `--no-save`, `--version`, `--licenses`. Bauen: `scripts/build.sh` (7 Plattformen).
- **Scan** (`internal/scan`): Ziel-Parser (Bereiche/Listen), TCP-Portscan, ARP/MAC, Banner, OUI (IEEE-Liste), OS-Vermutung (`osguess.go`), Namenssuche (`names.go`: DNS, mDNS, NetBIOS, LLMNR, SSDP, TLS, Seitentitel), Kategorien (`category.go`), Gateway/Uplink (`gateway.go`), Netz-Grunddaten des Scan-Rechners (`netinfo.go`, I-060: IP/Maske, Gateway, DNS, Suchdomäne), SNMP (`snmp.go`, `lldp.go`, `vendor.go`), `MarkSharedMAC` (⚠ gleiche MAC, `MirrorOf` = Spiegel eines Routers/Switches, zählt nicht als Netzwerkgerät; Hinweis steht in PDF und allen Exporten).
- **Web** (`internal/web`): Server, Scan-API mit Live-Ergebnissen, Eingaben (Name, Benutzer, Standort, Kategorie, eigene Kategorien) mit Zwischenspeicher `eingaben.json` (`store.go`), SNMP-Topologie, Router (`router.go`), Mesh (`mesh.go`), Windows-DHCP (`dhcp.go`), Reservierungen (`reservations.go`), Projektdatei speichern/laden (`project.go`, I-035), Scan-Vergleich (`compare.go`, I-034), Befundliste (`findings.go`, Paket `internal/findings`, I-064), Export-API, Oberfläche `static/index.html`.
- **Router** (`internal/router`): FRITZ!Box per TR-064 (Geräteliste, Info, WLAN, Mesh). Nur Loopback, ein Anmeldeversuch pro Klick, Zugangsdaten und Ergebnis nur im RAM.
- **DHCP** (`internal/dhcp`): Windows-DHCP per WinRM (nur mit Testdaten geprüft).
- **Export** (`internal/export`): CSV, HTML, Markdown, Topologie-PDF (`pdf.go`), Netzdokumentation-PDF (`netzdoku.go`, I-036: Deckblatt mit Netz-Grunddaten, Befunde, Karte, Liste), Router-Info, Reservierungen – ohne Passwörter, mit CSV-Injection-Schutz.
- **Lizenz** (I-069, 0.27.0): AGPL-3.0-or-later (`LICENSE`). Fremdlizenzen in `internal/licenses/THIRD_PARTY_LICENSES.txt` (eingebettet, `--licenses`), erzeugt mit `scripts/third-party-licenses.sh` – **nach jeder Änderung an `go.mod` neu erzeugen** (Test schlägt sonst fehl). `build.sh` legt `LICENSE` + Fremdlizenzen nach `dist/`. Quellcode-Link in der Oberfläche (AGPL §13).
- **Doku:** README, CHANGELOG, IDEAS, CLAUDE.md, ADR-0001, `docs/design/`.

## Nächster Schritt
Reihenfolge (I-025 erledigt in 0.24.0, I-064 in 0.25.0, I-065 in 0.25.1, I-067 in 0.25.2, I-066 in 0.25.3, I-068 in 0.25.4, I-059 in 0.26.0, I-069 (Lizenz) in 0.27.0, I-053 in 0.28.0, I-035 in 0.29.0, I-034 in 0.30.0, I-036 in 0.31.0, I-060 in 0.32.0; Befunde aus dem Test von 0.23.7 stehen als Ideen in `IDEAS.md`; danach laut Vorschlag I-061/I-070):
1. **I-061** (AD-Domäne per rootDSE), **I-070** (mehrere DHCP-Server); **I-020/I-022** Logins nach Wahl von Sascha.

Pro Chat genau **eine** Idee, danach `/clear`.

## Noch im LAN zu prüfen (Sascha)
- Windows-DHCP (WinRM) und Reiter „Reservierungen“ – nur mit Testdaten geprüft, braucht einen Windows Server (DHCP-Rolle, WinRM, Benutzer in „DHCP-Benutzer“ + „Remoteverwaltungsbenutzer“). Bei Fehlern die Meldung schicken.
- SNMP-Topologie und LLDP an einem verwalteten Switch (SNMP v2c, LLDP am Gerät an): stimmen Ports/Uplinks?
- Scan-Vergleich (0.30.0): Zwei echte Scans (Datei von gestern, aktueller Scan) vergleichen – stimmen neu/weg/geändert? Falsche Zuordnungen bei wechselnden IPs melden.
- Scan speichern/laden (0.29.0): Datei speichern, Programm neu starten, laden – stimmen Liste, Namen, Kategorien? Läuft es auch auf dem Handheld per Browser?
- SNMP v3 (0.28.0): Switch-Abfrage mit v3 (authPriv) gegen einen echten verwalteten Switch testen; bei Fehlern Meldung und Protokoll-Kombination nennen.
- Hersteller-Erkennung per `sysObjectID` (`vendor.go`): Tabelle ungeprüft.
- Kategorie-Vermutung und OS-Vermutung bei weiteren Geräten; fehlende oder falsche Geräte melden.
- MAC-Hinweis (0.25.1): Erscheint die Spalte „Hinweis“ in PDF/CSV, und zählen Scheineinträge des Routers nicht mehr als Netzwerkgeräte?
- Reiter „Befunde“ (0.25.0): Sinnvolle Schweregrade/Texte? Zu viele oder fehlende Regeln melden.
- Zugangstoken (0.24.0): Login im echten Browser über `--listen 0.0.0.0:8484` und `/?token=…` testen (bisher nur Unit-Test und curl).
- Mesh-Zuordnung (0.25.2): Hängt im PDF keine Gruppe mehr unter einem Smartphone? Sonst `--diagnose-mesh <IP>`-Ausgabe schicken.
- WAN-Status (0.25.4): Zeigt der Router-Info-Export jetzt „Connected“? Sonst `--diagnose-router <IP>` schicken. PDF-Zeile, die auf eine weitere Seite überläuft, ist nicht reproduziert (PDF schicken).
- Kategorie „Mobilgeräte“ (0.26.0): Landen Handys/Tablets richtig (iOS per Port 62078, WLAN + Privacy-MAC + keine Ports)? Treffen sie fälschlich Laptops? Bitte Fehlzuordnungen melden.
- Die Annahmen im Mesh-Parser (`node_1` = Vorgänger, Raten in kbit/s) sind nur an einer Box gesehen.

- Netzdokumentation-PDF (0.31.0): Knopf im Reiter Topologie mit echten Daten – Deckblatt, Befundtabelle, Seitenumbrüche, Umlaute okay?
- Netz-Grunddaten (0.32.0): Stimmen IP/Maske/Gateway/DNS/Suchdomäne unter Linux, Windows (PowerShell) und macOS mit dem, was das System zeigt?

## Bekannte Grenzen
- Zugangstoken (I-025) schützt nur vor zufälligem Zugriff: Verbindung bleibt HTTP, das Token ist im selben Netz mitlesbar. TLS ist offen.
- FRITZ!Box-Reservierungen sind per TR-064 **nicht auslesbar** (`AddressSource` Static ≠ feste Zuweisung). Reiter „Reservierungen“ = nur Windows-DHCP.
- Router-Login erst **nach Scan-Ende** (vorher fehlen die MACs); Router-/Mesh-Daten nur im RAM → nach Neustart neu anmelden. Nach mehreren Logins kann eine kurze Sperre greifen (ungeprüft).
- Zufällige/lokale MACs haben keinen Hersteller. Geräte mit gleicher MAC werden nur markiert (⚠), nie ausgeblendet.
- Offen: VLAN-Communities (I-054), andere Router, Kerberos/HTTPS für WinRM, Rest von I-013 (SMB/TTL), Verschlüsselung der Eingaben-Datei.
- I-058 (Import/Zurückschreiben) wurde verworfen (Leitlinie: nur lesen).
- Lizenz: Nutzungsbedingungen der IEEE für die eingebettete OUI-Liste (`internal/scan/data/oui.txt`) ungeprüft; ggf. Liste statt einbetten beim ersten Start laden.

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
| 0.24.0–0.30.0 ✅ | Zugangstoken (I-025), Befundliste (I-064), MAC-Hinweis in Exporten (I-065), Mesh-Zuordnung abgesichert (I-067), Kennungs-Namen (I-066), WAN-Status (I-068), Kategorie Mobilgeräte (I-059), SNMP v3 (I-053), Scan speichern/laden (I-035) |
| 0.31.0–0.32.0 ✅ | Netzdokumentation-PDF (I-036), Netz-Grunddaten (I-060) |
| Plan | I-061/I-070 → I-020/I-022 |
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
