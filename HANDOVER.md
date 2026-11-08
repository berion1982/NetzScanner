# HANDOVER – Übergabe für die nächste Claude-Sitzung

**Stand:** v0.4.1 · **Datum:** 2026-11-08 · Scan im echten LAN (FritzBox) und Export von Sascha bestätigt (läuft).

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
- I-032 ist umgesetzt (0.4.1, `internal/export/bookmarks.go`). Ob die Markierung „Lesezeichenleiste“ in Firefox und Chrome greift, ist **unbestätigt** → Sascha muss den Import testen (sonst Variante „Ordner“). Nächste Idee: I-003 (OUI-Liste), FTP/Telnet als Risiko, dann Topologie (I-010).

## Offen für Sascha
- Rückmeldung zum Export-Import im Zielprogramm (mag es das `'` bei Formel-Zeichen und die Spaltennamen?).
- Weitere Geräte im LAN prüfen: fehlen welche, sind MACs/Namen falsch? (I-005)
- WLAN-Idee I-050: nur eigene Umgebung oder alle sichtbaren WLANs?

## Roadmap
| Version | Inhalt |
|---|---|
| 0.2.0 ✅ | Web-UI (Design A+B), Hilfe, Web-Links, Demo-Daten |
| 0.3.0 ✅ | Scan-Kern: TCP-Portscan, ARP/MAC, Reverse-DNS, Banner, Scan-API + UI |
| 0.3.x | mDNS/NetBIOS-Namen, ICMP (mit Rechten), vollständige OUI-Liste, TLS-Zertifikat-Infos |
| 0.4.0 ✅ | Export CSV + lesbare Tabelle (HTML/Markdown), Benutzername-Feld |
| 0.5.0 | Topologie: LLDP/CDP, SNMP (ARP-/MAC-/Interface-Tabellen), Traceroute |
| 0.6.0 | Login-Abfragen: Router (SSH/SNMPv3), Server/Domain (LDAP/WinRM/SMB) – Zugangsdaten nur im RAM |
| 0.7.0 | Weitere Exporte (JSON, XLSX), Scan-Vergleich |

## Erkenntnisse aus dem echten Scan (FritzBox 192.168.178.1)
- Auf Linux mit systemd-resolved (Stub 127.0.0.53) liefert Reverse-DNS für die Gateway-IP den Pseudonamen `_gateway`. Der richtige Name `fritz.box` kommt erst vom DNS-Server direkt auf dem Gerät (Port 53) – Quelle `dns-geraet` in `internal/scan/names.go`.
- Fehlersuche bei Namen/Ports: `netzscanner --diagnose <IP>`.
- Offen: Hersteller (OUI) für `0C:72:74` fehlt (I-003); FTP-Port 21 wird noch nicht als Risiko gezählt.

## Hinweise
- Hersteller-Erkennung aus MAC (OUI-Liste) einplanen; Liste lizenzkonform einbetten.
- ICMP/ARP-Raw braucht Admin/root; Fallback TCP-Connect ist Pflicht.
