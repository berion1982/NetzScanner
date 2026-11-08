# HANDOVER – Übergabe für die nächste Claude-Sitzung

**Stand:** v0.23.5 · **Datum:** 2026-11-08 · Scan im echten LAN (FritzBox) und Export von Sascha bestätigt (läuft).

## Entscheidungen (von Sascha bestätigt)
- **Leitlinie:** Der NetzScanner **sammelt und exportiert** Daten (lesend). Kein Zurückschreiben/Importieren in Router oder Server (z. B. DHCP-Reservierungen) – das übernehmen deren eigene Werkzeuge.
- Sprache: **Go**, Web-UI im Binary eingebettet (`embed`), Zugriff per Browser. Begründung: `docs/ADR-0001-sprache.md`.
- Repo-Freigabe erteilt: Dateien, Commits, Pushes, PRs. Löschen nur nach Rückfrage.
- Änderungen immer als PR. Keine GitHub-Actions-Tests.

## Was existiert
- **Start:** `./dist/netzscanner` → http://127.0.0.1:8484 (`--demo` Demo-Daten, `--listen`, `--allow-public`, `--diagnose <IP>`, `--data <Datei>`, `--no-save`, `--version`). Bauen: `scripts/build.sh` (7 Plattformen).
- **Scan** (`internal/scan`): Ziel-Parser, TCP-Portscan, ARP/MAC, Banner, OUI (volle IEEE-Liste, `data/oui.txt`, Aktualisierung mit `scripts/update-oui.sh`), **Betriebssystem-Vermutung** (`osguess.go`: SSH-Banner, HTTP-Server-Header, Ports), Namenssuche in `names.go` (DNS → DNS des Geräts → TLS-Zertifikat → Seitentitel), `diagnose.go`.
- **Web** (`internal/web`): Server, Scan-API, Umbenennen, Benutzername, **Standort** und **Kategorie** (Maps `names`/`users`/`locs`/`cats`/`macs` in `server.go`, Endpunkte `/api/hosts/name|user|location|category`), **Zwischenspeicher** `store.go` (`eingaben.json`, 0600, MAC-Schutz bei IP-Wechsel, `GET /api/inputs`, `POST /api/inputs/clear`), Export-API, Oberfläche `static/index.html` (Übersicht, Topologie, Hilfe, Auswahl per Häkchen).
- **Export** (`internal/export`): CSV (Excel Deutsch / Standard; Spalten: Benutzername, IP, MAC, Hersteller (Chip), Gerätename, Standort, Offene Ports, Kategorie – neue Spalte hinten), HTML, Markdown (beide mit Kategorie), **Topologie-PDF** (`pdf.go`, Lib `go-pdf/fpdf`, Endpunkt `POST /api/export/topology-pdf`, alle Geräte, Seite 1 Karte mit **Sammelgruppen je Kategorie** und Legende, danach Liste mit System und Standort; Zeichen außerhalb Windows-1252 erscheinen als „.“) – ohne Passwörter, mit Schutz vor CSV-Injection.
- **Kategorien** (I-015): Vermutung `internal/scan/category.go` (Rolle → Hersteller → Ports/System), Nutzerwahl überschreibt; Karte (Web `renderMap` in `index.html`, PDF `layoutTopology`) bildet Gruppen je (Uplink, Kategorie), Linien über Sammelschiene.
- **Eigene Kategorien** (I-017): Schlüssel `custom:<Name>` (`model.CustomKey`, `CategoryHue` für die Farbe), Liste im Server (`customCats`), Endpunkte `/api/categories[/delete]`, gespeichert in `eingaben.json` (`customCategories`). Im LAN prüfen: Anlegen/Zuweisen/Löschen, Farbe in Karte und PDF.
- **SNMP-Topologie** (I-010 Teil 2, 0.14.0): `internal/scan/snmp.go` (`QuerySwitch` per gosnmp, `BuildLinks` reine Logik), `internal/web/snmp.go` (`POST /api/topology/snmp[/clear]`, Ergebnis nur im RAM, Overlay in `viewLocked`). Community nie gespeichert/geloggt. **Im LAN prüfen** (Switch mit SNMP v2c nötig): stimmen Switch/Port-Zuordnungen? Offen: SNMP v3, LLDP/CDP, VLAN-Communities.
- **Router-Login** (I-024, 0.15.0): `internal/router/fritzbox.go` (TR-064 `Hosts:1`, Digest, genau ein Anmeldeversuch), `internal/web/router.go` (`POST /api/router/fritzbox|clear`, nur Loopback, Ergebnis nur im RAM als `routerInfo` nach MAC, Overlay in `viewLocked`). Nur gegen Test-Fake geprüft → **Sascha: an der echten FritzBox testen** („Zugriff für Anwendungen“ an, Benutzer mit Recht „FRITZ!Box Einstellungen“). **0.16.0 (I-055 a+b):** `internal/router/info.go` (DeviceInfo, WANIP/PPP, WANCommon, LANHostConfigMgm, WLANConfiguration 1–4; nur `Get*`, nie `GetSecurityKeys`), `internal/export/routerinfo.go` (Markdown/CSV, ohne externe IP), `GET /api/router/info`, `POST /api/router/export`; WLAN-Client-Angaben (SSID/Signal/Tempo) als Overlay am Gerät. Feldnamen aus Standard/Gedächtnis → an der echten Box prüfen. Offen: Mesh-Topologie (I-055 c), IP-Reservierungen (d), andere Router, Windows-DHCP, HTTPS (49443).
- **Modell** `internal/model` (Host, Port, WebLink, Kategorien), **Version** `internal/version`.
- **Doku:** README, CHANGELOG, IDEAS, CLAUDE.md, ADR-0001, Design-Konzepte in `docs/design/`.

## Ideenliste
Offene Ideen und Reihenfolge stehen in `IDEAS.md` (eine Idee pro Chat).

## Nächster Schritt (Vorschlag)
- **Offen zum Testen (Sascha, wenn ein Windows Server da ist):** Windows-DHCP per WinRM (0.19.0) und Reiter „Reservierungen“ mit Export (0.20.0) sind **nur mit Testdaten geprüft**. Voraussetzungen: DHCP-Rolle, WinRM (`Test-WSMan localhost`), Benutzer in „DHCP-Benutzer“ + „Remoteverwaltungsbenutzer“, Server mitgescannt. Bei Fehlern die Meldung schicken. **Wichtiger als FritzBox-Reservierungen** (Sascha).
- **Danach (Reihenfolge):** (1) I-055 (c) Mesh über `X_AVM-DE_GetMeshListPath` (Format erst an der Box ansehen), (2) I-053 SNMP v3, (3) I-020/I-022 Logins. Leitlinie: Scanner nur lesen/sammeln/exportieren.
- **0.22.2:** FRITZ!Box-Reservierungen **nicht auslesbar** (Static ≠ feste Zuweisung, von Sascha an der Box widerlegt; fest zugewiesener PC `nobara-pc` fehlte in der Static-Liste). Reiter „Reservierungen“ = nur Windows-DHCP. I-055 (d) damit abgeschlossen (nicht machbar per TR-064). Als Nächstes: Mesh (I-055 c) über `X_AVM-DE_GetMeshListPath`.
- **0.22.3 (I-055 c, Teil 1):** `--diagnose-mesh <FritzBox-IP>` gibt die Mesh-Liste roh aus. **Sascha: Ausgabe ausführen und schicken** (Namen/MACs vorher nach Wunsch schwärzen). Danach Teil 2: Parser + Uplinks aus dem Mesh in Karte/Overlay (`viewLocked`).
- **0.23.5:** PDF-Linien wie in der Web-Karte aus Gruppen heraus geführt. **Offen:** PDF-Fußnote „Sternansicht“ je nach Datenquelle (Mesh/SNMP) anpassen.
- **Nächste Idee (neuer Chat):** I-059 „Mobilgeräte“ als feste Kategorie (Vorschlag Sascha). Hinweis: Der Router-Login (und damit Mesh/Router-Namen) ist nur im RAM – nach jedem Neustart des Programms erneut anmelden, sonst steht die Karte wieder im Stern.
- **0.23.4:** Mesh funktioniert (Repeater haben Geräte darunter). Fix: Zuordnung in Stufen (MAC → MANAGEMENT-IP → IP), Kartenlinien aus Gruppen heraus. **Offen:** PDF-Karte (`layoutTopology`) nutzt noch die alte Linienführung; Sascha prüft Karte im LAN.
- **0.23.3:** 32/49 Router-Geräte zugeordnet (0.23.2 wirkt). Offen: Geräteinfo/WAN/WLAN/Mesh „nicht lesbar“ beim dritten Login; Hinweise nennen jetzt den echten Grund. **Sascha: Meldung erneut schicken.** Ungeklärt: .101/.103/.201–.203 („Hyperion“) tragen die FritzBox-MAC; Router kennt .103 als „Launch“ mit anderer MAC.
- **0.23.2:** Ursache für „0/49 zugeordnet“: Login während laufendem Scan (MACs fehlten noch). Login jetzt gesperrt, solange der Scan läuft; Mesh-Zuordnung live berechnet. **Sascha: nach Scan-Ende erneut Router-Login.** Beobachtung (ungeklärt): .101/.103/.201–.203 („Hyperion“) tragen die MAC der FritzBox.
- **0.23.1:** Router-Login meldet „Gleiche IP, aber andere MAC“. **Offener Fehler:** bei Sascha 0/49 Router-Geräte zugeordnet (Mesh greift deshalb nicht). Sascha schickt die Beispiel-Zeilen; danach Ursache beheben (evtl. IP als zweites Kriterium).
- **0.23.0 (I-055 c erledigt):** Mesh-Parser (`internal/router/mesh.go`) + Zuordnung (`internal/web/mesh.go`), Overlay in `viewLocked`. **Sascha im LAN prüfen:** nach Router-Login hängen Handys/Clients unter dem Repeater statt an der Box? Stimmt die Richtung (Annahme node_1 = Vorgänger)? Offen: Anzeige weiterer Mesh-Daten (Kanal, Auslastung), SNMP v3 (I-053).
- **Befund `--diagnose-router` (Sascha, FRITZ!Box 192.168.178.1):** Hosts:1 hat `GetHostNumberOfEntries/GetSpecificHostEntry/GetGenericHostEntry`, `X_AVM-DE_GetHostListPath`, **`X_AVM-DE_GetMeshListPath`**, `X_AVM-DE_GetSpecificHostEntryByIP`, Friendly-Name-/Geräteklasse-Setter – **keine Aktion für feste IP-Reservierungen**. LANHostConfigManagement: `GetAddressRange`, `SetDHCPServerEnable` usw., ebenfalls keine Reservierungsliste. Folgerungen: (d) per TR-064 vermutlich nicht möglich (Rest: `AddressSource`=Static prüfen oder undokumentiertes `data.lua`, fragil); (c) Mesh ist machbar über `GetMeshListPath` (Datei/JSON, Aufbau erst an der Box ansehen). Der Reiter „Reservierungen“ kennt vorerst nur Windows-DHCP.
- **0.21.0 (I-055 d, Teil 1):** `./dist/netzscanner --diagnose-router <FritzBox-IP>` (`internal/router/describe.go`) listet Dienste/Aktionen der echten Box; Router-Login zeigt „Adressvergabe laut Router“. **Sascha: Ausgabe beider Dinge schicken** (v. a. Zeilen mit `<<` und die Summe DHCP/Static). Danach Teil 2: Reservierungen der Box in den Reiter „Reservierungen“ übernehmen (Quelle dort nur Windows-DHCP).
- **0.20.0 (I-057):** Reiter „Reservierungen“ (`internal/web/reservations.go`, `internal/export/reservations.go`), Export CSV/Markdown. **I-058 (Import/Zurückschreiben) verworfen:** Der Scanner ist nur zum **Sammeln und Exportieren** da, Import macht der Windows Server selbst. Offen: FRITZ!Box-Reservierungen (I-055 d).
- **0.19.0 (I-056):** Reiter „DHCP & Router“ (Router-Login dorthin verschoben) + Windows-DHCP per WinRM (`internal/dhcp`, `internal/web/dhcp.go`). **Ungeprüft an echtem Server** – Sascha hat derzeit keinen. Offen: FRITZ!Box-Reservierungen (I-055 d), andere Router, Kerberos/HTTPS für WinRM. Keine festen Einzelgeräte-Tabellen (Regel in CLAUDE.md).
- **0.18.0 (I-052):** `internal/scan/vendor.go` (sysObjectID → Hersteller, Tabelle ungeprüft). Als Nächstes: I-055 (c) Mesh oder I-053 (SNMP v3). 0.17.0 (LLDP) von Sascha bestätigt („läuft“).
- **0.17.0 (I-051 LLDP):** `internal/scan/lldp.go`, Nachbarn aus `lldpRemTable` haben in `BuildLinks` Vorrang vor der MAC-Tabelle. **Sascha: an LANCOM/Netgear prüfen** (LLDP am Gerät an? stimmen Ports/Uplinks?). Als Nächstes: I-055 (c) Mesh oder I-052 (sysObjectID).
- **Empfehlung (Reihenfolge):** (1) **I-055 (c) Mesh-Topologie** aus der FritzBox – Nutzen für Saschas Heimnetz sofort sichtbar, aber Dienste/Felder unsicher („Ich weiß es nicht“), erst an der echten Box probieren; (2) **I-051 (LLDP-MIB per SNMP)** – herstellerneutral, nennt die echte Verkabelung inkl. Access Points; danach I-052 (Hersteller/Modell aus `sysObjectID`), I-053 (SNMP v3), I-054 (VLAN-Communities). Saschas Geräte: **LANCOM und Netgear** (Annahme: Standard-BRIDGE-MIB reicht, ungeprüft; unverwaltete Netgear-Switches haben kein SNMP). Danach Logins (I-020/I-022) → I-024.
- **Von Sascha bestätigt (v0.16.0):** Router-Login an der FritzBox mit Router-Info und WLAN **funktioniert** (Rückmeldung „Funktioniert“); damit sind die Feldnamen in `internal/router/info.go` zumindest für seine Box brauchbar. Offen aus I-055: **(c) Mesh-Topologie** (echte Uplinks aus der Box, evtl. ohne SNMP) und **(d) feste IP-Reservierungen**.
- **Zuletzt erledigt (0.15.0–0.16.0):** Router-Login FRITZ!Box per TR-064 (I-024 teilweise: Namen, Verbindungsart, nur Loopback, ein Versuch pro Klick), Router-Info + WLAN-Netze + WLAN-Clients mit Signal (I-055 a+b, Export Markdown/CSV ohne externe IP), Fix: Klick-Handler wurden mehrfach registriert (in `updateSelection` verschachtelt).
- **Früher erledigt (0.13.0–0.14.2):** eigene Kategorien (I-017), OS-Spalte in CSV/HTML/Markdown, Home Assistant (Port 8123/22222 → „Home Assistant (Linux-basiert)“, Kategorie Server), SNMP-Topologie (I-010 Teil 2), Tabelle kompakter (Web-Knöpfe „🌐 Port“ hinter dem Namen, Hersteller gekürzt, **System-Spalte aus der Tabelle entfernt** – bleibt in Details, PDF und Exporten).
- **Neu in 0.6.0–0.16.0 (alles nur lokal/mit Tests geprüft, im LAN noch nicht):** CSV mit Hersteller (0.6.0, I-007), **Topologie-PDF** (0.7.0, I-012), **Betriebssystem-Vermutung** (0.8.0, I-013, teilweise: Banner/Ports), **Standort** (0.9.0, I-014), **Kategorien** (0.10.0, I-015: Vermutung in `internal/scan/category.go`, im LAN prüfen, ob sie bei deinen Geräten stimmt). Sascha bitte im LAN testen: PDF-Button, OS-Vermutung bei Linux-Servern/Windows-Servern, Standort eintragen und in CSV prüfen, Karte mit vielen Geräten (Sammelgruppen) in Web und PDF, Neustart behält Eingaben.
- **I-013 Rest (offen):** Windows-Version per SMB/NTLM, SNMP sysDescr (Community nötig), TTL-Fingerprint (ICMP-Rechte), SSDP-SERVER-Header. (OS-Spalte in Tabelle/CSV/HTML/Markdown seit 0.13.1 erledigt.)
- **I-014 Folgeidee erledigt (0.11.0, I-016):** Eingaben liegen in `eingaben.json` (`internal/web/store.go`); im LAN prüfen: Neustart behält Namen/Standorte? Offen: Verschlüsselung der Datei, Export/Import.
- **I-003 erledigt (0.5.9):** volle IEEE-Liste (~40.000 Einträge) ist eingebettet. Im LAN prüfen: erscheinen Hersteller bei den Geräten (z. B. AVM bei `0C:72:74`)? Zufällige MACs bleiben ohne Hersteller.
- **I-002 umgesetzt (0.5.0):** mDNS + NetBIOS in `internal/scan/udpnames.go`; nur mit lokalen Test-Servern geprüft → Sascha bitte im LAN testen: weniger „(unbekannt)“? Folgeidee I-008 (SSDP/LLMNR/SNMP) ist teilweise umgesetzt.
- **I-008 teilweise (0.5.3):** LLMNR + SSDP/UPnP in `internal/scan/ssdp.go` (nur lokal getestet) → Sascha bitte im LAN testen (TV, Router, Mediaserver). Offen: SNMP sysName (braucht Community, später mit Logins). Der HTTP-Server-Header wird seit 0.8.0 nur für die OS-Vermutung genutzt, nicht für Namen.
- **I-044 umgesetzt (0.5.4):** Live-Ergebnisse (`Options.OnHost`, `upsertHost` im Server, Feld `pending`, Polling lädt die Liste jede Sekunde). Im LAN prüfen, ob es flüssig wirkt (Tabelle wird je Sekunde neu gezeichnet).
- **I-045/I-046 umgesetzt (0.5.5):** Ziel-Feld versteht Bereiche (`a.b.c.10-50`, `a.b.c.1-a.b.d.9`) und Komma-Listen (`ExpandTarget` in `targets.go`); Format-Hinweis unter dem Feld, Hilfe mit Tabelle. **I-042 umgesetzt (0.5.6):** Hilfe deckt jetzt Namensquellen, Hersteller, Risiko-Ports, Rechte/Fallback, Datenschutz, Lesezeichen und Startoptionen ab; bei neuen Funktionen weiter mitpflegen.
- **I-007 umgesetzt (0.5.8):** Spalte „Hersteller (Chip)“ in Tabelle, Detail und HTML/Markdown (mit Fußnote); CSV seit 0.6.0 mit Hersteller-Spalte.
- **I-010 Teil 1 umgesetzt (0.5.7):** `internal/scan/gateway.go` – Standard-Gateway → Rolle „router“ + Uplink für alle Geräte mit MAC (Sternansicht, keine echte Verkabelung). **Teil 2 offen:** LLDP/CDP (Rechte nötig) und SNMP (Community nötig, ARP-/MAC-/Interface-Tabellen) für echte Switch-Uplinks. Im LAN prüfen: steht die FritzBox oben?
- **I-009 umgesetzt (0.5.1):** MAC-/EUI-64-artige Namen (`looksLikeIdentifier` in `names.go`) werden verworfen; letzter Ausweg „<Hersteller> (Vorschlag)“ (Quelle `hersteller`). Im LAN prüfen (Hue Bridge).
- **I-024 teilweise umgesetzt (0.15.0):** nur FRITZ!Box (TR-064). Offen: andere Router (LANCOM-Router/Access Points: Machbarkeit unbekannt), Windows-DHCP, IP-Reservierungen (= I-055 d).
- Empfohlene Reihenfolge: I-055 (c/d) → I-051 → I-052 → weitere Logins (I-020/I-022, andere Router) → I-024-Rest (I-010 Teil 2 per SNMP v2c seit 0.14.0, FritzBox-Login seit 0.15.0 umgesetzt).

## Offen für Sascha
- **Topologie im LAN prüfen:** Steht die FritzBox oben, hängen die Geräte darunter? **SNMP (0.14.0) an LANCOM/Netgear testen:** SNMP v2c am Switch einschalten, Switch-IPs + Community im Topologie-Tab eingeben; stimmen die Ports? Bei Fehlern Modell und Meldung zurückmelden. Entschieden: SNMP (nicht LLDP zuerst); LLDP-MIB per SNMP folgt als I-051.
- Scan im LAN wiederholen: Wie viele Geräte bleiben nach I-002/I-008 (mDNS, NetBIOS, LLMNR, SSDP) noch „(unbekannt)“? Bekommt die Hue Bridge einen sinnvollen Namen (I-009)?
- Live-Anzeige (I-044) im LAN: flüssig oder flackert die Tabelle? Funktionieren Bereiche/Listen im Ziel-Feld (I-046) wie erwartet?
- Rückmeldung zum Export-Import im Zielprogramm (mag es das `'` bei Formel-Zeichen und die Spaltennamen?).
- Weitere Geräte im LAN prüfen: fehlen welche, sind MACs/Namen falsch? (I-005)
- **Neue Funktionen im LAN prüfen (0.6.0–0.16.0):** Funktioniert „Topologie als PDF“ (Karte lesbar, Liste vollständig)? Stimmt die OS-Vermutung bei deinen Servern? Passt die neue CSV-Spaltenreihenfolge (Hersteller nach MAC, Standort nach Gerätename) zum Zielprogramm?
- Mag das Zielprogramm die zusätzliche letzte CSV-Spalte „Betriebssystem (Vermutung)“? Passt die Home-Assistant-Erkennung (läuft er auf Port 8123)? Soll die Eingaben-Datei verschlüsselt werden oder ein Export/Import der Eingaben kommen?
- **Router-Login (0.15.0/0.16.0):** bestätigt. Hinweis: Die Eingabemaske merkt sich nichts; Passwort nach dem Klick weg. Bitte beim nächsten Test prüfen, ob ein Klick wirklich nur **einen** Anmeldeversuch auslöst (Fritz-Ereignisprotokoll: „Anmeldung… fehlgeschlagen“ zählen).
- WLAN-Idee I-050 (Umgebungs-WLANs; die FritzBox-WLAN-Daten aus I-055 betreffen nur die eigenen Netze): nur eigene Umgebung oder alle sichtbaren WLANs?

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
| 0.9.1 ✅ | Standort auch in der PDF-Karte (I-014) |
| 0.10.0 ✅ | Topologie-Kategorien Server/Client/Netzwerk/IoT (I-015) |
| 0.11.0 ✅ | Eingaben zwischenspeichern (I-016) |
| 0.11.1 ✅ | Fix: Karte bricht bei vielen Geräten um, Namen gekürzt |
| 0.12.0 ✅ | Karte: Sammelgruppen je Kategorie (Web) |
| 0.12.1 ✅ | PDF-Karte mit Sammelgruppen |
| 0.13.0 ✅ | Eigene Kategorien (I-017) |
| 0.13.1 ✅ | OS-Spalte in Tabelle/CSV/HTML/Markdown (I-013) |
| 0.13.2 ✅ | Home Assistant erkennen (Ports 8123/22222, I-013) |
| 0.13.3 ✅ | Home Assistant = Kategorie Server |
| 0.14.0 ✅ | Topologie per SNMP (I-010 Teil 2) |
| 0.14.1 ✅ | Tabelle kompakter, Web-Spalte vorn |
| 0.14.2 ✅ | System-Spalte aus der Tabelle (bleibt in Details/Exporten) |
| 0.15.0 ✅ | Router-Login FRITZ!Box per TR-064 (I-024, Teil) |
| 0.16.0 ✅ | Router-Info + WLAN der FRITZ!Box (I-055 a+b), Listener-Fix |
| nächste (Plan) | I-051 LLDP-MIB per SNMP, I-052 `sysObjectID`-Erkennung, I-053 SNMP v3, I-054 VLAN-Communities |
| später (Plan) | Rest von I-008 (SNMP sysName), ICMP mit Rechten, Rest von I-013 (SMB/TTL), Traceroute |
| 0.15.0 (Plan) | Login-Abfragen: Router (SSH/SNMPv3), Server/Domain (LDAP/WinRM/SMB) – Zugangsdaten nur im RAM (I-020/I-022, I-024) |
| später (Plan) | Weitere Exporte (JSON, XLSX), Scan-Vergleich, Eingaben-Datei verschlüsseln / Export-Import |

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
