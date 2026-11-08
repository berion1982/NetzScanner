# HANDOVER – Übergabe für die nächste Claude-Sitzung

**Stand:** v0.5.3 · **Datum:** 2026-11-08 · Scan im echten LAN (FritzBox) und Export von Sascha bestätigt (läuft).

## Entscheidungen (von Sascha bestätigt)
- Sprache: **Go**, Web-UI im Binary eingebettet (`embed`), Zugriff per Browser. Begründung: `docs/ADR-0001-sprache.md`.
- Repo-Freigabe erteilt: Dateien, Commits, Pushes, PRs. Löschen nur nach Rückfrage.
- Änderungen immer als PR. Keine GitHub-Actions-Tests.

## Was existiert
- **Start:** `./dist/netzscanner` → http://127.0.0.1:8484 (`--demo` Demo-Daten, `--listen`, `--allow-public`, `--diagnose <IP>`, `--version`). Bauen: `scripts/build.sh` (7 Plattformen).
- **Scan** (`internal/scan`): Ziel-Parser, TCP-Portscan, ARP/MAC, Banner, OUI (kleine Tabelle), Namenssuche in `names.go` (DNS → DNS des Geräts → TLS-Zertifikat → Seitentitel), `diagnose.go`.
- **Web** (`internal/web`): Server, Scan-API, Umbenennen und Benutzername (RAM, `names`/`users` in `server.go`), Export-API, Oberfläche `static/index.html` (Übersicht, Topologie, Hilfe, Auswahl per Häkchen).
- **Export** (`internal/export`): CSV (Excel Deutsch / Standard), HTML, Markdown – ohne Passwörter, mit Schutz vor CSV-Injection.
- **Modell** `internal/model` (Host, Port, WebLink), **Version** `internal/version`.
- **Doku:** README, CHANGELOG, IDEAS, CLAUDE.md, ADR-0001, Design-Konzepte in `docs/design/`.

## Ideenliste
Offene Ideen und Reihenfolge stehen in `IDEAS.md` (eine Idee pro Chat).

## Nächster Schritt (Vorschlag)
- **I-003 halb fertig (0.4.3):** Mechanismus (`internal/scan/oui.go`, `data/oui.txt`) und `scripts/update-oui.sh` stehen; die **volle IEEE-Liste fehlt**, weil `standards-oui.ieee.org` in der Cloud-Umgebung gesperrt ist. Auf Saschas PC: `scripts/update-oui.sh`, Ergebnis prüfen (IEEE-Nutzungsbedingungen!), committen. Alternative: Host in der Umgebung freigeben. Die nmap-Liste (`nmap-mac-prefixes`) wäre erreichbar, ihre Lizenz (NPSL) ist aber unklar → nicht eingebettet.
- **I-002 umgesetzt (0.5.0):** mDNS + NetBIOS in `internal/scan/udpnames.go`; nur mit lokalen Test-Servern geprüft → Sascha bitte im LAN testen: weniger „(unbekannt)“? Neue Ideen: I-007 (Hersteller in Tabelle/Export), I-008 (SSDP/LLMNR/SNMP).
- **I-008 teilweise (0.5.3):** LLMNR + SSDP/UPnP in `internal/scan/ssdp.go` (nur lokal getestet) → Sascha bitte im LAN testen (TV, Router, Mediaserver). Offen: SNMP sysName (braucht Community, später mit Logins), HTTP-Server-Header.
- **I-009 umgesetzt (0.5.1):** MAC-/EUI-64-artige Namen (`looksLikeIdentifier` in `names.go`) werden verworfen; letzter Ausweg „<Hersteller> (Vorschlag)“ (Quelle `hersteller`). Im LAN prüfen (Hue Bridge); wirkt voll erst mit großer OUI-Liste (I-003).
- **Neue Idee (nur in `IDEAS.md`, nicht umgesetzt):** I-024 (Router-/Windows-DHCP-Geräteliste nach Login abfragen, baut auf I-020/I-022 auf; Machbarkeit je Router offen).
- Empfohlene Reihenfolge: FTP/Telnet als Risiko → Topologie (I-010) → Logins (I-020/I-022) → I-024.

## Offen für Sascha
- **Entscheidung I-003:** volle OUI-Liste per `scripts/update-oui.sh` selbst erzeugen, Host `standards-oui.ieee.org` freigeben, oder nmap-Liste trotz Lizenzfrage?
- Scan im LAN wiederholen: Wie viele Geräte bleiben nach I-002 (mDNS/NetBIOS) noch „(unbekannt)“?
- Rückmeldung zum Export-Import im Zielprogramm (mag es das `'` bei Formel-Zeichen und die Spaltennamen?).
- Weitere Geräte im LAN prüfen: fehlen welche, sind MACs/Namen falsch? (I-005)
- WLAN-Idee I-050: nur eigene Umgebung oder alle sichtbaren WLANs?

## Roadmap
| Version | Inhalt |
|---|---|
| 0.2.0 ✅ | Web-UI (Design A+B), Hilfe, Web-Links, Demo-Daten |
| 0.3.0–0.3.3 ✅ | Scan-Kern (TCP-Portscan, ARP/MAC, Reverse-DNS, Banner), Auswahl/Umbenennen, mehrstufige Namenssuche, `--diagnose` |
| 0.4.0–0.4.3 ✅ | Export CSV/HTML/Markdown, Benutzername, Lesezeichen-Export, TLS-Zertifikatsinfos, OUI-Mechanismus (volle Liste fehlt, I-003) |
| 0.5.0–0.5.2 ✅ | mDNS/NetBIOS-Namen (I-002), Kennung-Namen abwerten (I-009), Versionsführung |
| 0.6.0 (Plan) | Weitere Namensquellen (I-008 SSDP/LLMNR), Hersteller in Tabelle/Export (I-007), ICMP mit Rechten, volle OUI-Liste (I-003) |
| 0.7.0 (Plan) | Topologie: LLDP/CDP, SNMP (ARP-/MAC-/Interface-Tabellen), Traceroute (I-010) |
| 0.8.0 (Plan) | Login-Abfragen: Router (SSH/SNMPv3), Server/Domain (LDAP/WinRM/SMB) – Zugangsdaten nur im RAM (I-020/I-022, I-024) |
| 0.9.0 (Plan) | Weitere Exporte (JSON, XLSX), Scan-Vergleich |

Die Zeilen mit „(Plan)“ sind Vorschläge; Sascha entscheidet die Reihenfolge, Details in `IDEAS.md`.

## Erkenntnisse aus dem echten Scan (FritzBox 192.168.178.1)
- Auf Linux mit systemd-resolved (Stub 127.0.0.53) liefert Reverse-DNS für die Gateway-IP den Pseudonamen `_gateway`. Der richtige Name `fritz.box` kommt erst vom DNS-Server direkt auf dem Gerät (Port 53) – Quelle `dns-geraet` in `internal/scan/names.go`.
- Fehlersuche bei Namen/Ports: `netzscanner --diagnose <IP>`.
- Offen: Hersteller (OUI) für `0C:72:74` fehlt (I-003); FTP-Port 21 wird noch nicht als Risiko gezählt.

## Versionsführung (Pflicht bei jeder Änderung)
- Nummer steht in `VERSION` (Root, nutzt `scripts/build.sh` per ldflags) **und** `internal/version/VERSION` (eingebettet; Fallback, wenn ohne ldflags gebaut wird, z. B. `go run`). Beide gleich anheben – `go test ./...` meldet Abweichungen.
- Zusätzlich: Kopf in `CHANGELOG.md`, „Stand“ oben in dieser Datei, Status in `IDEAS.md`.
- Anzeige: `netzscanner --version`, `GET /api/version`, Hilfe-Seite, Export-Kopf. Ohne ldflags zeigt Build-Datum/Commit „unbekannt“, die Nummer stimmt aber.
- Die Roadmap-Tabelle unten ist an die tatsächlich ausgelieferten Versionen angepasst (✅ = ausgeliefert, „Plan“ = Vorschlag).

## Hinweise
- Hersteller-Erkennung aus MAC (OUI-Liste) einplanen; Liste lizenzkonform einbetten.
- ICMP/ARP-Raw braucht Admin/root; Fallback TCP-Connect ist Pflicht.
