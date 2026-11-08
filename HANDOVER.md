# HANDOVER – Übergabe für die nächste Claude-Sitzung

**Stand:** v0.1.0 (Grundlagen + Design-Konzepte) · **Datum:** 2026-11-08

## Entscheidungen (von Sascha bestätigt)
- Sprache: **Go**, Web-UI im Binary eingebettet (`embed`), Zugriff per Browser. Begründung: `docs/ADR-0001-sprache.md`.
- Repo-Freigabe erteilt: Dateien, Commits, Pushes, PRs. Löschen nur nach Rückfrage.
- Änderungen immer als PR. Keine GitHub-Actions-Tests.

## Was existiert
- Grundgerüst: `cmd/netzscanner`, `internal/version`, `scripts/build.sh` (7 Plattformen, getestet).
- Doku: README, CHANGELOG, CLAUDE.md, ADR-0001.
- Design-Konzepte (statische HTML, dunkel): `docs/design/index.html` mit A, B, C.

## Offen / Entscheidungen von Sascha
1. Welches Design-Konzept (A/B/C oder Mix)? → danach UI bauen.
2. Test-Netz für echte Scans? (Im Cloud-Container ist kein echtes LAN verfügbar.)

## Roadmap
| Version | Inhalt |
|---|---|
| 0.2.0 | Scan-Kern: Host-Discovery (ARP/ICMP/TCP-Fallback), Portscan, Reverse-DNS/mDNS/NetBIOS |
| 0.3.0 | Web-UI (gewähltes Design), Hilfe-Seite, Export CSV + lesbare Tabelle (HTML/Markdown) |
| 0.4.0 | Topologie: LLDP/CDP, SNMP (ARP-/MAC-/Interface-Tabellen), Traceroute |
| 0.5.0 | Login-Abfragen: Router (SSH/SNMPv3), Server/Domain (LDAP/WinRM/SMB) – Zugangsdaten nur im RAM |
| 0.6.0 | Weitere Exporte (JSON, XLSX), Scan-Vergleich |

## Hinweise
- Hersteller-Erkennung aus MAC (OUI-Liste) einplanen; Liste lizenzkonform einbetten.
- ICMP/ARP-Raw braucht Admin/root; Fallback TCP-Connect ist Pflicht.
