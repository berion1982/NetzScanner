# HANDOVER – Übergabe für die nächste Claude-Sitzung

**Stand:** v0.3.3 (Scan-Kern + Auswahl + Umbenennen; nur localhost getestet) · **Datum:** 2026-11-08

## Entscheidungen (von Sascha bestätigt)
- Sprache: **Go**, Web-UI im Binary eingebettet (`embed`), Zugriff per Browser. Begründung: `docs/ADR-0001-sprache.md`.
- Repo-Freigabe erteilt: Dateien, Commits, Pushes, PRs. Löschen nur nach Rückfrage.
- Änderungen immer als PR. Keine GitHub-Actions-Tests.

## Was existiert
- Auswahl (Client, `selected` in index.html) und Umbenennen (Server, `names` in server.go, RAM). Export soll die Auswahl als IP-Liste an den Server senden (I-030).
- Scan: `internal/scan` (targets, ports, arp, oui, banner, scanner), API in `internal/web/server.go`. Start: `./dist/netzscanner`, dann Ziel eingeben.
- UI: `internal/web` (Server + `static/index.html`), Modell `internal/model`, Start: `./dist/netzscanner` → http://127.0.0.1:8484
- Grundgerüst: `cmd/netzscanner`, `internal/version`, `scripts/build.sh` (7 Plattformen, getestet).
- Doku: README, CHANGELOG, CLAUDE.md, ADR-0001.
- Design-Konzepte (statische HTML, dunkel): `docs/design/index.html` mit A, B, C.

## Ideenliste
Offene Ideen und Reihenfolge stehen in `IDEAS.md` (eine Idee pro Chat).

## Offen / Entscheidungen von Sascha
1. Design entschieden: Mix A+B, plus klickbare Web-Zugänge (umgesetzt in 0.2.0).
2. **Sascha: ersten echten Scan im eigenen LAN ausführen und Ergebnis/Probleme melden** (Container hat kein LAN).
3. Test-Netz für echte Scans? (Im Cloud-Container ist kein echtes LAN verfügbar.)

## Roadmap
| Version | Inhalt |
|---|---|
| 0.2.0 ✅ | Web-UI (Design A+B), Hilfe, Web-Links, Demo-Daten |
| 0.3.0 ✅ | Scan-Kern: TCP-Portscan, ARP/MAC, Reverse-DNS, Banner, Scan-API + UI |
| 0.3.x | mDNS/NetBIOS-Namen, ICMP (mit Rechten), vollständige OUI-Liste, TLS-Zertifikat-Infos |
| 0.3.y | Export CSV + lesbare Tabelle (HTML/Markdown) |
| 0.4.0 | Topologie: LLDP/CDP, SNMP (ARP-/MAC-/Interface-Tabellen), Traceroute |
| 0.5.0 | Login-Abfragen: Router (SSH/SNMPv3), Server/Domain (LDAP/WinRM/SMB) – Zugangsdaten nur im RAM |
| 0.6.0 | Weitere Exporte (JSON, XLSX), Scan-Vergleich |

## Hinweise
- Hersteller-Erkennung aus MAC (OUI-Liste) einplanen; Liste lizenzkonform einbetten.
- ICMP/ARP-Raw braucht Admin/root; Fallback TCP-Connect ist Pflicht.
