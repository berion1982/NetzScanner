# HANDOVER – Übergabe für die nächste Claude-Sitzung

**Stand:** v0.53.0 · **Datum:** 2026-11-11 · Scan im echten LAN (FritzBox), Export und Router-Login von Sascha bestätigt.
Ausführlicher Verlauf (alte Fassung dieser Datei, nichts gelöscht): `docs/HANDOVER-Verlauf.md`.

## Entscheidungen (von Sascha bestätigt)
- **Leitlinie:** Der Scanner **sammelt und exportiert** (nur lesend). Kein Zurückschreiben in Router/Server/DHCP.
- Sprache **Go**, Web-UI eingebettet (`embed`), Zugriff per Browser (`docs/ADR-0001-sprache.md`).
- Repo-Freigabe: Dateien, Commits, Pushes, PRs. Löschen nur nach Rückfrage. Änderungen immer als PR, keine GitHub-Actions-Tests.
- Keine Einzelgeräte-Tabellen, keine Änderungen nur für ein einzelnes Netz (siehe `CLAUDE.md`).

## Was existiert
- **Start:** `./dist/netzscanner` → http://127.0.0.1:8484. Optionen: `--demo`, `--listen`, `--token`/`--no-token` (I-025), `--allow-public`, `--diagnose <IP>`, `--diagnose-router <IP>`, `--diagnose-mesh <IP>`, `--data <Datei>`, `--no-save`, `--version`, `--licenses`, `--scan <Ziel> --out <Datei>` (CLI ohne Browser, I-047, `cmd/netzscanner/cli.go`). Bauen: `scripts/build.sh` (7 Plattformen). Pull + Bauen + Starten in einem Schritt: `scripts/start.sh [Optionen]` (I-071).
- **Scan** (`internal/scan`): Ziel-Parser (Bereiche/Listen), TCP-Portscan, ARP/MAC, Banner, OUI (IEEE-Liste), OS-Vermutung (`osguess.go`), Namenssuche (`names.go`: DNS, mDNS, NetBIOS, LLMNR, SSDP, TLS, Seitentitel), Kategorien (`category.go`), Gateway/Uplink (`gateway.go`), Netz-Grunddaten des Scan-Rechners (`netinfo.go`, I-060: IP/Maske, Gateway, DNS, Suchdomäne), SNMP (`snmp.go`, `lldp.go`, `vendor.go`), `MarkSharedMAC` (⚠ gleiche MAC, `MirrorOf` = Spiegel eines Routers/Switches, zählt nicht als Netzwerkgerät; Hinweis steht in PDF und allen Exporten).
- **Web** (`internal/web`): Server, Scan-API mit Live-Ergebnissen, Eingaben (Name, Benutzer, Standort, Kategorie, eigene Kategorien) mit Zwischenspeicher `eingaben.json` (`store.go`), SNMP-Topologie, Router (`router.go`), Mesh (`mesh.go`), Windows-DHCP (`dhcp.go`), Reservierungen (`reservations.go`), Projektdatei speichern/laden (`project.go`, I-035), Scan-Vergleich (`compare.go`, I-034), Befundliste (`findings.go`, Paket `internal/findings`, I-064), Export-API, Oberfläche `static/index.html`.
- **Router** (`internal/router`): FRITZ!Box per TR-064 (Geräteliste, Info, WLAN, Mesh). Nur Loopback, ein Anmeldeversuch pro Klick, Zugangsdaten und Ergebnis nur im RAM.
- **DHCP** (`internal/dhcp`): Windows-DHCP per WinRM (nur mit Testdaten geprüft).
- **Export** (`internal/export`): CSV, HTML, Markdown, Topologie-PDF (`pdf.go`), Netzdokumentation-PDF (`netzdoku.go`, I-036: Deckblatt mit Netz-Grunddaten, Befunde, Karte, Liste), Router-Info, Reservierungen – ohne Passwörter, mit CSV-Injection-Schutz.
- **Lizenz** (I-069, 0.27.0): AGPL-3.0-or-later (`LICENSE`). Fremdlizenzen in `internal/licenses/THIRD_PARTY_LICENSES.txt` (eingebettet, `--licenses`), erzeugt mit `scripts/third-party-licenses.sh` – **nach jeder Änderung an `go.mod` neu erzeugen** (Test schlägt sonst fehl). `build.sh` legt `LICENSE` + Fremdlizenzen nach `dist/`. Quellcode-Link in der Oberfläche (AGPL §13).
- **Zugangsdaten** (I-020, `creds.go`): je Geräte-IP Benutzer/Passwort nur im RAM, nur Loopback, 15 Min Inaktivität, API ohne Passwort-Rückgabe.
- **Login-Test** (I-022, 0.36.0, `internal/logintest`, `internal/web/logintest.go`): SSH (Passwort/kbd-interaktiv) und Web (HTTP-Basic) mit dem Zugang aus `credStore`. Ein Passwort-Versuch pro Klick, Hostkey/Zertifikat erst nach bestätigtem Fingerabdruck, Ergebnisse nur im RAM am Zugang.
- **System-Infos** (I-023 Teil 1, 0.37.0, `logintest.SSHInfo`): nach SSH-Login über dieselbe Verbindung ein fester, lesender Befehl (Kernel, Hostname, os-release; ab 0.38.0 auch Modell, Firmware, Laufzeit, Schnittstellen); Anzeige im Detail-Panel, nur RAM. Ab 0.39.0 auch per SNMP (`scan/snmpinfo.go`, beim „Lesen“ im SNMP-Formular): Standort, Laufzeit, Modell/Firmware (ENTITY-MIB), Schnittstellen → `Host.SysInfo`.
- **SNMPv3-Login-Test** (I-022 Rest, 0.41.0, `scan.ProbeSNMPLogin`, Methode `snmpv3` in `web/logintest.go`): eine lesende Anfrage ohne Wiederholung; Benutzer/Passwort aus dem gemerkten Zugang, Protokolle und Verschlüsselungs-Passphrase aus dem Formular (nicht gespeichert).
- **WinRM-Login-Test** (I-022 Rest, 0.42.0, `logintest.WinRM`, Methode `winrm`, Port 5985): NTLM, ein Versuch, danach ein fester lesender PowerShell-Befehl; ab 0.43.0 (I-023) liefert er Computername, Domäne/Arbeitsgruppe, Modell, Windows-Version, Laufzeit. Kein 5986/Kerberos.
- **LDAP-Login-Test** (I-022 Rest, 0.46.0, `logintest.LDAP`, Methode `ldap`, Ports 389/636/3268/3269): ein einfacher Bind, LDAPS bzw. StartTLS mit bestätigtem Fingerabdruck, Klartext nur nach ausdrücklicher Bestätigung; danach rootDSE (Domäne, Server).
- **SMB-Login-Test** (I-022 Rest, 0.47.0, `logintest.SMB`, Methode `smb`, Port 445): ein NTLM-Versuch (`go-smb2`), danach nur die Freigabenamen (IPC$/srvsvc). Kein Kerberos, kein NetBIOS-Port 139.
- **Diagnose-Knopf je Gerät** (I-074, 0.48.0, `scan/diagdevice.go`, `web/diagnose.go`, `POST /api/diagnose`): Textbericht (Gespeichertes + aktive Prüfungen aus `--diagnose` + optional Ping, Traceroute, voller Portscan). Ping/Traceroute per Systembefehl (feste Argumente, keine Shell), Ersatz: TCP-Laufzeit. Streaming, nur Loopback, nur Listen-Geräte. Ab 0.50.1 erscheint die Befehlsausgabe live Zeile für Zeile (`lineWriter`).
- **Web-Infos nach Login** (I-023 Rest, 0.50.0, `logintest.WebInfo`, `readInfo` bei Methode `web`): derselbe eine Basic-Versuch, danach Seitentitel, Server-Kennung, Realm, Generator aus der gelieferten Startseite (max. 64 KB). Nur RAM. I-023 damit vollständig.
- **Detail-Panel ein-/ausklappen** (I-079, 0.50.2, `static/index.html`, `applyDetailFold`): Knopf im Panel, Zustand in `localStorage` (`detailFold`), CSS-Klasse `fold`. **Panelbreite** (I-080, 0.50.3, `applyDetailWide`): Randknopf (sticky, mittig) wechselt zwischen normal und `wide`, nur wenn für das Gerät ein Bericht in `diagCache` liegt; Start eines Berichts erweitert automatisch.
- **Knopf-Design** (I-081, 0.50.4): globale Basisregeln `button`/`select` in `static/index.html`; neue Knöpfe brauchen keine eigene Gestaltung, Sonderfälle über Klassen mit höherer Spezifität.
- **Browser-Autostart** (I-083 Teil 1, 0.51.0, `cmd/netzscanner/browser.go`): öffnet beim Start den Standardbrowser, nur bei Loopback, `--no-browser` schaltet ab. Teil 2 (0.52.0): Windows-Build mit `-H=windowsgui` (`scripts/build.sh`), `console_windows.go` (Anhängen an Eltern-Konsole, Meldungsfenster bei Startfehler), Knopf „Beenden“ (`web/shutdown.go`, `POST /api/shutdown`, nur Loopback), `scan/proc_windows.go` (`hidden()` gegen aufblitzende Fenster).
- **Beenden beim Tab-Schließen** (I-084, 0.53.0, `web/session.go`, Tab-Verwaltung in `index.html`): Tabs melden sich per `/api/session/hello|bye` an/ab, nach dem letzten 8 s Wartezeit, dann `Options.Shutdown`. Nur wenn der Browser selbst geöffnet wurde (`AutoExit`), `--keep-running` schaltet ab.
- **Programm-Icon** (I-082, 0.50.6): `static/icon-256.png`, `favicon-32.png`, `apple-touch-icon.png`, Links im Kopf von `index.html`, Logo in der Navigation. Exe-Icon (Windows `.syso`) offen.
- **Jahreszeiten-Effekt** (I-076, 0.49.0, `static/index.html`, Funktion `seasonFx`): Canvas-Animation nach Monat (Nordhalbkugel), Schalter in der Navigation, Wahl in `localStorage`, aus bei reduzierter Bewegung. Ab 0.49.1 (I-077) im Sommer zusätzlich Rasen unten und Blume neben der Versionsnummer.
- **Drucker per IPP** (I-062, 0.40.0, `scan/ipp.go`): bei offenem Port 631 eine lesende `Get-Printer-Attributes`-Anfrage; Ergebnis als Banner „IPP: …“ (Modell, Firmware, UUID, Status, Füllstände).
- **Doku:** README, CHANGELOG, IDEAS, CLAUDE.md, ADR-0001, `docs/design/`.

## Nächster Schritt
Reihenfolge (erledigt u. a.: I-025 0.24.0 … I-022 Teil 1 in 0.36.0, I-023 Teil 1 in 0.37.0, Teil 2 in 0.38.0, Teil 3 SNMP in 0.39.0, I-062 in 0.40.0, I-022 SNMPv3 in 0.41.0, I-022 WinRM in 0.42.0, I-023 Domäne/WinRM in 0.43.0, I-072 Drucker/Scanner in 0.44.0, I-047 CLI-Modus in 0.45.0, I-022 LDAP in 0.46.0, I-022 SMB in 0.47.0 – I-022 damit vollständig, I-074 Diagnose-Knopf in 0.48.0):
1. **I-075** (Rechte-Abfrage für Ping/Traceroute, nur falls nötig) oder nächste offene Idee aus `IDEAS.md` (z. B. I-054, Rest von I-013).

Pro Chat genau **eine** Idee, danach `/clear`.

## Noch im LAN zu prüfen (Sascha)
- Jahreszeiten-Effekt (0.50.5): Unter Windows Schalter unten links anklicken – startet die Animation jetzt? (War vorher gesperrt, vermutlich wegen „Animationseffekte“ aus; Ursache ist eine Annahme, nicht bestätigt.)
- Tab schließen (0.53.0): Beendet sich NetzScanner unter Windows ~8 s nach dem Schließen des letzten Tabs (Task-Manager)? Bleibt es bei F5 und bei zwei Tabs an? Erscheint die Browser-Warnung bei laufendem Scan?
- Windows ohne Konsole (0.52.0): Doppelklick auf die `.exe` → nur Browser, kein Fenster? Kein Aufblitzen bei Scan/Diagnose? „Beenden“ schließt das Programm (Task-Manager prüfen)? `netzscanner.exe --version` in PowerShell zeigt weiterhin Text? Antivirus-Meldungen bei GUI-Build?
- Browser-Autostart (0.51.0): Öffnet sich unter Windows (Doppelklick/Konsole) und Linux der Browser von selbst? Meldet `--no-browser` ihn ab?
- Icon (0.50.6): Erscheint es im Browser-Tab und in der Navigation (ggf. Cache leeren/Strg+F5)?
- Knopf-Design (0.50.4): Sind in allen Reitern (Topologie, DHCP & Router, Befunde, Reservierungen, Hilfe, Vergleich) keine hellen Standard-Knöpfe/Listen mehr zu sehen? Wirkt etwas jetzt zu dunkel/schlecht lesbar?
- Panelbreite (0.50.3): Erweitert sich das Panel beim Bericht, und der Randknopf (‹/›) stellt die normale Breite wieder her? Bleibt der Knopf beim Scrollen mittig sichtbar? Auch mit schmalem Fenster/Handheld prüfen.
- Detail-Panel (0.50.2): Lässt sich das Panel nach einem breiten Diagnose-Bericht zuklappen (Tabelle/Karte volle Breite) und wieder aufklappen? Bleibt die Wahl nach Neuladen? Stört das Zuklappen sonst etwas?
- Live-Diagnose (0.50.1): Erscheinen die Ping-/Traceroute-Zeilen nach „Diagnose-Daten erzeugen“ sofort einzeln statt erst am Ende? Bei Teil B (aktive Prüfungen) vor Ping kann es weiter etwas dauern.
- Web-Infos (0.50.0): An einem Gerät mit HTTP-Basic-Login (Router, NAS) Zugang merken, „Web-Login testen + Web-Infos lesen“ – erscheinen Seitentitel/Server/Realm? Geräte mit Formular-Login: kommt wie bisher „nicht testbar“? Falsches Passwort **einmal**: „abgelehnt" ohne Infos?
- Jahreszeiten-Effekt (0.49.0): Erscheint passend zum Monat eine dezente Animation? Stört sie Lesen/Klicken/Tabelle? Schalter unten links merkt sich die Wahl nach Neuladen? CPU-Last im Leerlauf spürbar?
- Diagnose-Knopf (0.48.0): Gerät wählen, rechts unten „Diagnose-Daten erzeugen“ mit Ping + Traceroute – stehen echte `ping`-/`traceroute`-Ausgaben im Bericht (nicht nur der TCP-Ersatz)? Fehlt dem Befehl ein Recht: kommt der Hinweis? Voller Portscan an einem Gerät: Dauer, Ergebnis plausibel? Gern einen Bericht schicken, wenn etwas fehlt, das du dir gewünscht hättest.
- SMB-Login-Test (0.47.0): An einem Windows-Rechner/NAS mit Port 445 Zugang merken (`DOMÄNE\benutzer` oder lokal), „SMB-Login testen“ – kommt „ok“ mit Liste der Freigaben? Falsches Passwort **einmal**: „abgelehnt“? Server mit aktivem Gast-Konto: wird ein falsches Passwort fälschlich akzeptiert? Meldung bei Abweichung schicken.
- Karte/PDF (0.46.1): Steht eine Gruppe neben einer anderen in derselben Zeile (z. B. Mobilgeräte neben IoT), läuft die Linie jetzt über die Lücke oberhalb der Zeile und von oben hinein – nicht mehr durch Titel/Rahmen der Gruppe davor. Stimmt das in Karte **und** PDF?
- LDAP-Login-Test (0.46.0): An einem Domänencontroller/LDAP-Server Zugang merken (`DOMÄNE\benutzer`), „LDAP-Login testen“ – erscheint erst der Fingerabdruck, danach „ok“ mit Domäne/Server? Falsches Passwort **einmal**: „abgelehnt“? Server ohne StartTLS: kommt die Klartext-Rückfrage? Meldung bei Abweichung schicken.
- CLI-Modus (0.45.0): `./dist/netzscanner --scan <dein-Netz> --out test.csv` (auch `.md/.html/.pdf`) – stimmt die Liste mit der Oberfläche überein? Ohne Rechte: wie bisher TCP-Fallback.
- Kategorie „Drucker/Scanner“ (0.44.0): Landen Drucker/Scanner dort (nicht mehr in IoT), Kameras/Smart-Home weiter in IoT? Fehlzuordnungen melden. Alte Projektdatei laden: Drucker ggf. noch „IoT“?
- WinRM-Infos (0.43.0): Nach „WinRM-Login testen“ an einem Windows-Rechner – erscheinen Computername, Domäne/Arbeitsgruppe, Modell, System, Laufzeit? Sonst Meldung schicken (z. B. „keine System-Infos lesbar“).
- WinRM-Login-Test (0.42.0): An einem Windows-Rechner mit Port 5985 Zugang merken, „WinRM-Login testen“ – kommt „ok“ mit Computername? Falsches Passwort **einmal**: „abgelehnt“? Domänenkonto als `DOMÄNE\benutzer` probieren. Meldung bei Abweichung schicken.
- SNMPv3-Login-Test (0.41.0): An einem Gerät mit SNMPv3 Zugang merken (Benutzer + Auth-Passphrase), Protokolle wählen, „SNMPv3-Login testen“ – kommt „ok“? Falsche Passphrase **einmal** testen: „abgelehnt“ oder nur „keine Antwort“ (viele Geräte schweigen)? Meldung bitte schicken.
- IPP (0.40.0): An einem Netzwerkdrucker (Port 631) Scan starten – erscheint im Detail-Panel unter Banner „IPP: Modell · Firmware · Status · Füllstände“? Welche Felder fehlen (modellabhängig)? Drucker ohne IPP-Antwort: normaler Banner wie zuvor?
- SNMP-System-Infos (0.39.0): An einem verwalteten Switch/Router im SNMP-Formular „Lesen“ – erscheinen im Detail-Panel Standort, Laufzeit und Schnittstellen (Zustand/MAC/Tempo)? Stimmt „Modell“ (ENTITY-MIB, Index-Wahl unbestätigt)? Ohne Infos darf die Topologie trotzdem funktionieren.
- System-Infos (0.37.0/0.38.0): An einem Linux-Gerät mit SSH „SSH-Login testen + System-Infos lesen“ – erscheinen Kernel, Hostname, System, Modell, Laufzeit und die Schnittstellen mit MAC/IP? Bei Router/Switch ohne Unix-Shell: kommt der Hinweis „keine System-Infos lesbar“ und bleibt der Login „ok“?
- Login-Test (0.36.0): An einem Gerät mit SSH und einem mit Web-Basic-Login (z. B. Router, NAS): Zugang merken, „SSH-/Web-Login testen“ – erscheint erst der Fingerabdruck zur Bestätigung (ohne Passwort), danach „ok“/„abgelehnt“? Falsches Passwort absichtlich nur **einmal** testen. Geräte mit nur Tastatur-interaktiv oder Formular-Login: kommt eine verständliche Meldung?
- Zugangsdaten (0.35.0): Im Browser Gerät wählen, Benutzer/Passwort merken – erscheint „gemerkt“ mit Restzeit, nie das Passwort? Verschwindet es nach „Zugang vergessen“? Per `--listen 0.0.0.0` von einem anderen Gerät: Eingabe gesperrt?
- DHCP-Prüfung (0.34.0): Knopf „DHCP-Server prüfen“ mit Root/Admin-Rechten im echten LAN – erscheint der Router als Server? Ohne Rechte: kommt „nicht prüfbar“? Zweiter Server (z. B. Testgerät) sichtbar?
- AD-rootDSE (0.33.0): An einem echten Domänencontroller prüfen, ob beim Port 389 „LDAP: Domäne … · Server …“ erscheint; wenn nicht, verweigert der DC den anonymen Abruf (Meldung/Verhalten schicken).
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
- Login-Test: SSH, Web-Basic, SNMPv3, WinRM (nur 5985/NTLM) und SMB (nur 445/NTLM; Gast-Konto kann falsches „ok“ liefern); LDAP nur einfacher Bind, kein Formular-/Digest-Login, keine bekannten-Hosts-Datei (Fingerabdruck wird jedes Mal bestätigt).
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
| 0.31.0–0.34.0 ✅ | Netzdokumentation-PDF (I-036), Netz-Grunddaten (I-060), AD-Domäne per rootDSE (I-061) |
| 0.38.0–0.50.0 ✅ | System-Infos (SSH/SNMP/WinRM), IPP, Login-Tests SNMPv3/WinRM/LDAP/SMB, CLI-Modus, Drucker/Scanner-Kategorie, Diagnose-Knopf je Gerät, Web-Infos nach Login |
| 0.35.0–0.37.0 ✅ | Zugangsdaten im RAM (I-020), Login-Test SSH/Web (I-022 Teil 1), System-Infos per SSH (I-023 Teil 1) |
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
