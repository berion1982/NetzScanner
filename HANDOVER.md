# HANDOVER – Übergabe für die nächste Claude-Sitzung

**Stand:** v0.9.0 · **Datum:** 2026-11-08 · Scan im echten LAN (FritzBox) und Export von Sascha bestätigt (läuft).

## Entscheidungen (von Sascha bestätigt)
- Sprache: **Go**, Web-UI im Binary eingebettet (`embed`), Zugriff per Browser. Begründung: `docs/ADR-0001-sprache.md`.
- Repo-Freigabe erteilt: Dateien, Commits, Pushes, PRs. Löschen nur nach Rückfrage.
- Änderungen immer als PR. Keine GitHub-Actions-Tests.

## Was existiert
- **Start:** `./dist/netzscanner` → http://127.0.0.1:8484 (`--demo` Demo-Daten, `--listen`, `--allow-public`, `--diagnose <IP>`, `--version`). Bauen: `scripts/build.sh` (7 Plattformen).
- **Scan** (`internal/scan`): Ziel-Parser, TCP-Portscan, ARP/MAC, Banner, OUI (volle IEEE-Liste, `data/oui.txt`, Aktualisierung mit `scripts/update-oui.sh`), **Betriebssystem-Vermutung** (`osguess.go`: SSH-Banner, HTTP-Server-Header, Ports), Namenssuche in `names.go` (DNS → DNS des Geräts → TLS-Zertifikat → Seitentitel), `diagnose.go`.
- **Web** (`internal/web`): Server, Scan-API, Umbenennen, Benutzername und **Standort** (nur RAM, `names`/`users`/`locs` in `server.go`, Endpunkte `/api/hosts/name|user|location`), Export-API, Oberfläche `static/index.html` (Übersicht, Topologie, Hilfe, Auswahl per Häkchen).
- **Export** (`internal/export`): CSV (Excel Deutsch / Standard; Spalten: Benutzername, IP, MAC, Hersteller (Chip), Gerätename, Standort, Offene Ports), HTML, Markdown, **Topologie-PDF** (`pdf.go`, Lib `go-pdf/fpdf`, Endpunkt `POST /api/export/topology-pdf`, alle Geräte, Seite 1 Karte, danach Liste mit System und Standort; Zeichen außerhalb Windows-1252 erscheinen als „.“) – ohne Passwörter, mit Schutz vor CSV-Injection.
- **Modell** `internal/model` (Host, Port, WebLink), **Version** `internal/version`.
- **Doku:** README, CHANGELOG, IDEAS, CLAUDE.md, ADR-0001, Design-Konzepte in `docs/design/`.

## Ideenliste
Offene Ideen und Reihenfolge stehen in `IDEAS.md` (eine Idee pro Chat).

## Nächster Schritt (Vorschlag)
- **Neu in 0.6.0–0.9.0 (alles nur lokal/mit Tests geprüft, im LAN noch nicht):** CSV mit Hersteller (0.6.0, I-007), **Topologie-PDF** (0.7.0, I-012), **Betriebssystem-Vermutung** (0.8.0, I-013, teilweise: Banner/Ports), **Standort** (0.9.0, I-014). Sascha bitte im LAN testen: PDF-Button, OS-Vermutung bei Linux-Servern/Windows-Servern, Standort eintragen und in CSV prüfen.
- **I-013 Rest (offen):** Windows-Version per SMB/NTLM, SNMP sysDescr (Community nötig), TTL-Fingerprint (ICMP-Rechte), SSDP-SERVER-Header; OS-Spalte in Tabelle/CSV/HTML (bisher nur Detail-Panel und PDF-Liste).
- **I-014 Folgeidee:** Standort (und Namen/Benutzernamen) dauerhaft in einer Datei speichern – heute nur RAM.
- **I-003 erledigt (0.5.9):** volle IEEE-Liste (~40.000 Einträge) ist eingebettet. Im LAN prüfen: erscheinen Hersteller bei den Geräten (z. B. AVM bei `0C:72:74`)? Zufällige MACs bleiben ohne Hersteller.
- **I-002 umgesetzt (0.5.0):** mDNS + NetBIOS in `internal/scan/udpnames.go`; nur mit lokalen Test-Servern geprüft → Sascha bitte im LAN testen: weniger „(unbekannt)“? Folgeidee I-008 (SSDP/LLMNR/SNMP) ist teilweise umgesetzt.
- **I-008 teilweise (0.5.3):** LLMNR + SSDP/UPnP in `internal/scan/ssdp.go` (nur lokal getestet) → Sascha bitte im LAN testen (TV, Router, Mediaserver). Offen: SNMP sysName (braucht Community, später mit Logins). Der HTTP-Server-Header wird seit 0.8.0 nur für die OS-Vermutung genutzt, nicht für Namen.
- **I-044 umgesetzt (0.5.4):** Live-Ergebnisse (`Options.OnHost`, `upsertHost` im Server, Feld `pending`, Polling lädt die Liste jede Sekunde). Im LAN prüfen, ob es flüssig wirkt (Tabelle wird je Sekunde neu gezeichnet).
- **I-045/I-046 umgesetzt (0.5.5):** Ziel-Feld versteht Bereiche (`a.b.c.10-50`, `a.b.c.1-a.b.d.9`) und Komma-Listen (`ExpandTarget` in `targets.go`); Format-Hinweis unter dem Feld, Hilfe mit Tabelle. **I-042 umgesetzt (0.5.6):** Hilfe deckt jetzt Namensquellen, Hersteller, Risiko-Ports, Rechte/Fallback, Datenschutz, Lesezeichen und Startoptionen ab; bei neuen Funktionen weiter mitpflegen.
- **I-007 umgesetzt (0.5.8):** Spalte „Hersteller (Chip)“ in Tabelle, Detail und HTML/Markdown (mit Fußnote); CSV seit 0.6.0 mit Hersteller-Spalte.
- **I-010 Teil 1 umgesetzt (0.5.7):** `internal/scan/gateway.go` – Standard-Gateway → Rolle „router“ + Uplink für alle Geräte mit MAC (Sternansicht, keine echte Verkabelung). **Teil 2 offen:** LLDP/CDP (Rechte nötig) und SNMP (Community nötig, ARP-/MAC-/Interface-Tabellen) für echte Switch-Uplinks. Im LAN prüfen: steht die FritzBox oben?
- **I-009 umgesetzt (0.5.1):** MAC-/EUI-64-artige Namen (`looksLikeIdentifier` in `names.go`) werden verworfen; letzter Ausweg „<Hersteller> (Vorschlag)“ (Quelle `hersteller`). Im LAN prüfen (Hue Bridge).
- **Neue Idee (nur in `IDEAS.md`, nicht umgesetzt):** I-024 (Router-/Windows-DHCP-Geräteliste nach Login abfragen, baut auf I-020/I-022 auf; Machbarkeit je Router offen).
- Empfohlene Reihenfolge: I-010 Teil 2 → Logins (I-020/I-022) → I-024.

## Offen für Sascha
- **Topologie (I-010 Teil 1) im LAN prüfen:** Steht die FritzBox oben, hängen die Geräte darunter? Für Teil 2 entscheiden: SNMP (Community des Switches nötig) oder LLDP/CDP (braucht Rechte)?
- Scan im LAN wiederholen: Wie viele Geräte bleiben nach I-002/I-008 (mDNS, NetBIOS, LLMNR, SSDP) noch „(unbekannt)“? Bekommt die Hue Bridge einen sinnvollen Namen (I-009)?
- Live-Anzeige (I-044) im LAN: flüssig oder flackert die Tabelle? Funktionieren Bereiche/Listen im Ziel-Feld (I-046) wie erwartet?
- Rückmeldung zum Export-Import im Zielprogramm (mag es das `'` bei Formel-Zeichen und die Spaltennamen?).
- Weitere Geräte im LAN prüfen: fehlen welche, sind MACs/Namen falsch? (I-005)
- **Neue Funktionen im LAN prüfen (0.6.0–0.9.0):** Funktioniert „Topologie als PDF“ (Karte lesbar, Liste vollständig)? Stimmt die OS-Vermutung bei deinen Servern? Passt die neue CSV-Spaltenreihenfolge (Hersteller nach MAC, Standort nach Gerätename) zum Zielprogramm?
- Wünschst du die OS-Spalte auch in Tabelle/CSV/HTML und den Standort dauerhaft gespeichert?
- WLAN-Idee I-050: nur eigene Umgebung oder alle sichtbaren WLANs?

## Roadmap
| Version | Inhalt |
|---|---|
| 0.2.0 ✅ | Web-UI (Design A+B), Hilfe, Web-Links, Demo-Daten |
| 0.3.0–0.3.3 ✅ | Scan-Kern (TCP-Portscan, ARP/MAC, Reverse-DNS, Banner), Auswahl/Umbenennen, mehrstufige Namenssuche, `--diagnose` |
| 0.4.0–0.4.3 ✅ | Export CSV/HTML/Markdown, Benutzername, Lesezeichen-Export, TLS-Zertifikatsinfos, OUI-Mechanismus |
| 0.5.0–0.5.8 ✅ | mDNS/NetBIOS (I-002), Kennung-Namen abwerten (I-009), Versionsführung, LLMNR/SSDP (I-008, teilweise), Live-Ergebnisse (I-044), Bereiche + Format-Hinweis (I-045/I-046), Hilfe vollständig (I-042), Topologie-Stern unter Gateway (I-010 Teil 1), Hersteller-Spalte (I-007) |
| 0.5.9 ✅ | volle IEEE-OUI-Liste eingebettet (I-003) |
| 0.6.0 ✅ | CSV mit Spalte „Hersteller (Chip)“ |
| 0.7.0 ✅ | Topologie als PDF (I-012, Lib `go-pdf/fpdf`) |
| 0.8.0 ✅ | Betriebssystem-Vermutung (I-013, teilweise) |
| 0.9.0 ✅ | Standort pro Gerät (I-014) |
| 0.10.0 (Plan) | Rest von I-008 (SNMP sysName), ICMP mit Rechten, Rest von I-013 (SMB/SNMP/TTL) |
| 0.11.0 (Plan) | Topologie: LLDP/CDP, SNMP (ARP-/MAC-/Interface-Tabellen), Traceroute (I-010) |
| 0.12.0 (Plan) | Login-Abfragen: Router (SSH/SNMPv3), Server/Domain (LDAP/WinRM/SMB) – Zugangsdaten nur im RAM (I-020/I-022, I-024) |
| später (Plan) | Weitere Exporte (JSON, XLSX), Scan-Vergleich, Standort dauerhaft speichern |

Die Zeilen mit „(Plan)“ sind Vorschläge; Sascha entscheidet die Reihenfolge, Details in `IDEAS.md`.

## Erkenntnisse aus dem echten Scan (FritzBox 192.168.178.1)
- Auf Linux mit systemd-resolved (Stub 127.0.0.53) liefert Reverse-DNS für die Gateway-IP den Pseudonamen `_gateway`. Der richtige Name `fritz.box` kommt erst vom DNS-Server direkt auf dem Gerät (Port 53) – Quelle `dns-geraet` in `internal/scan/names.go`.
- Fehlersuche bei Namen/Ports: `netzscanner --diagnose <IP>`.
- Der Hersteller für `0C:72:74` (AVM) wird seit 0.5.9 erkannt. Offen: FTP-Port 21 wird noch nicht als Risiko gezählt.

## Versionsführung (Pflicht bei jeder Änderung)
- Nummer steht in `VERSION` (Root, nutzt `scripts/build.sh` per ldflags) **und** `internal/version/VERSION` (eingebettet; Fallback, wenn ohne ldflags gebaut wird, z. B. `go run`). Beide gleich anheben – `go test ./...` meldet Abweichungen.
- Zusätzlich: Kopf in `CHANGELOG.md`, „Stand“ oben in dieser Datei, Status in `IDEAS.md`.
- Anzeige: `netzscanner --version`, `GET /api/version`, Hilfe-Seite, Export-Kopf. Ohne ldflags zeigt Build-Datum/Commit „unbekannt“, die Nummer stimmt aber.
- Die Roadmap-Tabelle unten ist an die tatsächlich ausgelieferten Versionen angepasst (✅ = ausgeliefert, „Plan“ = Vorschlag).

## Hinweise
- OUI-Liste: `internal/scan/data/oui.txt` stammt aus der IEEE-Registry (Sascha hat sie mit `scripts/update-oui.sh` erzeugt; IEEE-Nutzungsbedingungen beachten). Zufällige (lokal administrierte) MACs haben keinen Hersteller.
- Abhängigkeiten: Go-Standard + `github.com/go-pdf/fpdf` (nur PDF). Neue Libs nur Pure-Go, kein CGO.
- Tipp bei `git pull`-Konflikt mit `oui.txt`: lokale Datei umbenennen (`.alt`), nicht löschen.
- ICMP/ARP-Raw braucht Admin/root; Fallback TCP-Connect ist Pflicht.
