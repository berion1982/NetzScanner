# IDEAS – Ideenliste / Backlog

Einzige Quelle für offene Ideen. Regeln: Neue Ideen zuerst hier eintragen. Pro Chat **eine** Idee umsetzen,
danach Status + Version eintragen und PR öffnen. Nichts löschen: Verworfenes bleibt mit Begründung stehen.

- **Priorität:** hoch / mittel / niedrig (Vorschlag von Claude, Sascha entscheidet)
- **Aufwand:** S / M / L (grobe Schätzung, nicht gemessen)
- **Status:** offen · geplant (Zielversion) · in Arbeit · erledigt (Version) · verworfen (Grund)

## Scan
| ID | Idee | Prio | Aufwand | Status |
|---|---|---|---|---|
| I-001 | ICMP-Ping (mit Rechten) für Geräte ohne offene Ports; Fallback TCP bleibt | mittel | M | offen |
| I-002 | Namen per mDNS und NetBIOS | mittel | M | erledigt (0.5.0), Praxistest im LAN offen |
| I-003 | Vollständige IEEE-OUI-Herstellerliste einbetten (Lizenz/Quelle prüfen) | mittel | S | erledigt (0.5.9): volle IEEE-Liste eingebettet |
| I-004 | TLS-Zertifikatsinfos (CN, Ablauf) bei HTTPS-Ports | niedrig | S | erledigt (0.4.2) |
| I-006 | (teilweise in 0.3.2: Namen aus Zertifikat/Titel) Gerätetyp erkennen (z. B. FritzBox, NAS, Drucker) über Hersteller, HTTP-Titel/Server, TLS-Zertifikat, UPnP/SSDP; als Vorschlag für den Namen anzeigen | hoch | M | offen |
| I-007 | Hersteller aus der MAC (Netzwerkchip) auch in Tabelle und Export anzeigen, mit Hinweis „Chip-Hersteller, nicht zwingend Gerätehersteller“ (Vorschlag Sascha; Basis ist I-003, im Detail-Panel schon vorhanden) | mittel | S | erledigt (0.5.8; CSV ab 0.6.0) |
| I-008 | Weitere Namensquellen: SSDP/UPnP (TV, Router, Mediaserver), LLMNR, HTTP-Server-Header, SNMP sysName | mittel | M | teilweise erledigt (0.5.3: LLMNR, SSDP; offen: SNMP sysName, HTTP-Server-Header) |
| I-009 | Namen, die nur wie eine Kennung aussehen (z. B. `001788FFFE476CE2` = MAC/EUI-64 einer Hue Bridge), nicht als „bekannt“ werten, sondern als Platzhalter behandeln und besser aus Hersteller (OUI `00:17:88`), mDNS/SSDP oder HTTP-Titel ableiten, z. B. „Philips Hue Bridge (Vorschlag)“ | mittel | S | erledigt (0.5.1) |
| I-005 | Echter LAN-Scan durch Sascha, Fehler/Lücken melden | hoch | S | offen |

## WLAN
| ID | Idee | Prio | Aufwand | Status |
|---|---|---|---|---|
| I-050 | WLANs in Reichweite erkennen (SSID, BSSID/MAC, Kanal, Frequenzband, Signalstärke, Verschlüsselung) und in einer **separaten Datei** ablegen (CSV, später auch lesbare Tabelle); zusätzlich kennzeichnen, mit welchem WLAN der Scan-Rechner selbst verbunden ist | mittel | L | offen |
| I-051 | **LLDP-MIB per SNMP** (herstellerneutral): direkte Nachbarn (Switch↔Switch, Switch↔Access-Point) aus `lldpRemTable` lesen. Genauer als die MAC-Tabelle, weil sie die echte Verkabelung nennt und Access Points/Router einschließt; läuft bei LANCOM, Netgear, Cisco, HP/Aruba, Ubiquiti, MikroTik, sofern LLDP am Gerät aktiv ist | hoch | M | erledigt (0.17.0), im LAN bestätigt ("läuft") |
| I-052 | **Hersteller/Modell des Switches aus `sysObjectID`** (Enterprise-Nummer → LANCOM, Netgear, Cisco, HP, TP-Link, Zyxel, Ubiquiti, MikroTik …) für Rolle, System-Spalte und gezielte Hinweise („SNMP am Gerät einschalten“) | mittel | S | erledigt (0.18.0), Nummern-Tabelle ungeprüft |
| I-053 | **SNMP v3** (Benutzer, Authentifizierung/Verschlüsselung) zusätzlich zu v2c; Zugangsdaten nur im RAM (siehe I-020) | mittel | M | offen |
| I-054 | **VLAN-Communities** (`community@vlan`, vor allem Cisco) und Fallback-Verhalten, wenn ein Gerät nur eine der beiden Bridge-MIBs liefert | niedrig | M | offen |
| I-056 | **Reiter „DHCP & Router“** für Sonderquellen und **Windows-DHCP-Server auslesen** (Vorschlag Sascha): Leases + feste Reservierungen per WinRM/PowerShell (nur lesend), Zuordnung per MAC; Router-Login zieht in den Reiter um. Gleiche Zugangsdaten-Regeln wie I-020 | hoch | M | erledigt (0.19.0), **ungeprüft an echtem Windows Server** |
| I-057 | **Reiter „Reservierungen“** (Vorschlag Sascha): feste DHCP-Reservierungen als Liste anzeigen und als CSV/Markdown exportieren | hoch | S | erledigt (0.20.0), ungeprüft an echtem Windows Server |
| I-058 | **Reservierungen wieder einlesen** (Vorschlag Sascha): (a) CSV in den Scanner laden und mit dem Server/Scan **vergleichen** (nur lesend, ungefährlich); (b) **zurückschreiben** zum Windows-DHCP-Server (`Add-DhcpServerv4Reservation`, ggf. `Export-/Import-DhcpServer`) – **schreibend**, nur mit ausdrücklicher Bestätigung, Trockenlauf und Vorschau; ohne Testserver nicht prüfbar. Gleiche Regeln für Zugangsdaten wie I-020. Offene Frage an Sascha: (a), (b) oder beides? | mittel | M | verworfen (Sascha: Import ist Aufgabe des Windows Servers; der Scanner nur für Export und Sammeln der Daten) |
| I-055 | **FRITZ!Box: mehr Netzwerkdaten per TR-064** (Vorschlag Sascha): (a) **Router-Info** (Modell, Firmware, Laufzeit, WAN-Status/-Geschwindigkeit, DHCP-Bereich, DNS); (b) **WLAN der Box** (SSIDs je Band inkl. Gast-WLAN, Kanal, Standard, Verschlüsselungsart – **nie den WLAN-Schlüssel**) und **WLAN-Clients** mit Signalstärke/Geschwindigkeit; (c) **Mesh-Topologie** (welches Gerät an welchem Repeater/Port hängt → echte Uplinks ohne SNMP); (d) feste IP-Reservierungen. Ausgabe im Detail-Panel/Topologie und in einer eigenen Datei (zusammen mit I-050). **Ich weiß es nicht** genau, welche Dienste/Felder je Modell und FRITZ!OS vorhanden sind – je Dienst gegen die echte Box prüfen. Zugangsdaten-Regeln wie I-020 | hoch | L | teilweise (0.16.0: (a) Router-Info + (b) WLAN/Clients; (d) IP-Reservierungen: **verworfen, per TR-064 nicht auslesbar** (keine Aktion; `AddressSource`=Static ≠ feste Zuweisung, von Sascha an der Box widerlegt; Alternative undokumentiertes `data.lua`, nicht geplant) (Befund an Saschas Box, 0.21.0: Hosts:1 hat keine Reservierungs-Aktion; offen: ob `AddressSource` „Static“ liefert, Alternative undokumentiertes `data.lua`); (c) Mesh: **umgesetzt in 0.23.0** (0.22.3: `--diagnose-mesh`): Hosts:1 bietet `X_AVM-DE_GetMeshListPath` → Mesh-Liste lesbar, Format noch unbekannt) |

**Hinweise zu I-050 (Annahmen, noch nicht geprüft):**
- Geht nur, wenn der Rechner einen WLAN-Adapter hat (Raspberry Pi hat meist einen); ohne Adapter „nicht verfügbar“ melden, kein Fehler.
- Plattformabhängig, ohne CGO über vorhandene Systemwerkzeuge: Linux `nmcli`/`iw`, Windows `netsh wlan show networks mode=bssid`, macOS Systemwerkzeuge. Ausgabeformate und Rechte (z. B. Standortfreigabe unter macOS für SSIDs – vermutlich nötig) müssen je System getestet werden.
- Der Cloud-Container hat kein WLAN, Tests nur mit Beispieltexten der Werkzeuge möglich; echter Test bei Sascha nötig.
- Es werden nur öffentlich ausgesendete Daten gelistet (passiv); keine Passwörter, kein Verbinden.
- Offene Frage an Sascha: Nur WLANs der eigenen Umgebung auflisten oder auch fremde (Nachbarn)? Standard-Vorschlag: alle sichtbaren, mit Spalte „eigenes Netz“.

## Topologie
| ID | Idee | Prio | Aufwand | Status |
|---|---|---|---|---|
| I-010 | LLDP/CDP und SNMP (ARP-/MAC-/Interface-Tabellen) für echte Uplinks | hoch | L | teilweise (0.5.7: Stern unter Standard-Gateway; 0.14.0: SNMP v2c-Switch-Ports; offen: SNMP v3, LLDP/CDP) |
| I-011 | Traceroute für Segmente hinter Routern | niedrig | M | offen |
| I-013 | **Betriebssystem/Version auslesen** (Vorschlag Sascha): Vermutung aus SSH-Banner (OpenSSH-Version → Ubuntu/Debian-Release), HTTP-Server-Header (IIS, Apache/nginx mit Distribution) und typischen Ports (RDP, AFP, iOS); ohne Zusatzverkehr. Anzeige im Detail-Panel und PDF-Liste. **Nicht enthalten / Ideen dazu:** Windows-Version per SMB/NTLM, SNMP sysDescr (Community nötig), TTL-Fingerprint (ICMP-Rechte), SSDP-SERVER-Header | mittel | M | teilweise erledigt (0.8.0): Banner/Port-Vermutung; OS-Spalte in Tabelle/CSV/HTML/Markdown erledigt (0.13.1); Home Assistant per Port 8123 (0.13.2); Rest offen |
| I-014 | **Standort pro Gerät** (Vorschlag Sascha): Freitext im Detail-Panel (z. B. „Büro, Raum 2“), Anzeige in Tabelle, CSV, HTML/Markdown und PDF-Liste. Nur im RAM wie die Namen; dauerhaftes Speichern wäre eine Folgeidee | mittel | S | erledigt (0.9.0, PDF-Karte 0.9.1) |
| I-012 | **Topologie als PDF exportieren** (Vorschlag Sascha). Varianten: (a) Browser-Druck mit Druck-CSS „Als PDF speichern“ – ohne Abhängigkeit, aber manuell; (b) PDF serverseitig in Pure Go erzeugen (z. B. `go-pdf/fpdf`, kein CGO) und als Download anbieten, Karte aus denselben Daten wie die SVG-Ansicht zeichnen. Offen: nur ausgewählte oder alle Geräte? Mit Geräteliste (Name, IP, MAC, Hersteller)? Keine Zugangsdaten. | mittel | M | erledigt (0.7.0): Variante b, alle Geräte, Karte + Liste |
| I-015 | **Topologie-Kategorien** (Vorschlag Sascha): Geräte in Server, Clients, Netzwerkgeräte und IoT einteilen (automatische Vermutung aus Rolle, Hersteller, System, Ports; im Detail-Panel überschreibbar). Farbe + Legende + Ein-/Ausblenden in der Karte, Spalte in Tabelle, Export und PDF | hoch | M | erledigt (0.10.0) |
| I-016 | **Eingaben zwischenspeichern** (Vorschlag Sascha): Namen, Benutzernamen, Standorte und Kategorien nach jeder Änderung in einer Datei sichern und beim Start laden (Onboarding, wenn man zwischendurch nicht am Rechner ist). Klartext-Datei 0600, kein Passwort, Schutz vor IP-Wechsel per MAC, Löschen-Knopf, `--data`/`--no-save` | hoch | M | erledigt (0.11.0) |
| I-017 | **Eigene Kategorien** (Vorschlag Sascha): zusätzlich zu Netzwerk/Server/Client/IoT eigene Kategorien anlegen, zuweisen und löschen; automatische Farbe, in Karte, Legende, Tabelle, Exporten, PDF und Zwischenspeicher | hoch | M | erledigt (0.13.0) |

## Zugangsdaten und Login-Test
| ID | Idee | Prio | Aufwand | Status |
|---|---|---|---|---|
| I-020 | In der Oberfläche Zugangsdaten (Benutzer/Passwort) pro ausgewähltem Gerät hinterlegen – **nur temporär im RAM**, nie auf Platte, nie in Logs/Exporten; Löschen per Knopf, beim Beenden und nach Inaktivität | hoch | M | offen |
| I-021 | Gerätenamen in der Oberfläche anpassen (Anzeigename, wirkt auf Export/Lesezeichen) | hoch | S | erledigt (0.3.1) |
| I-022 | Login-Test je Gerät: SSH, SNMPv3, Web (HTTP-Anmeldung), später LDAP/WinRM/SMB (Domain-Admins); Ergebnis „ok/fehlgeschlagen“ in der Liste | hoch | L | offen |
| I-023 | Router-/Server-Infos nach erfolgreichem Login auslesen (Modell, Firmware, Schnittstellen, Domäne) | mittel | L | offen |
| I-024 | **Geräteliste direkt beim Router/DHCP-Server abfragen** (Vorschlag Sascha): nach Login Namen, MAC, IP und **feste IP-Reservierungen** auslesen und den Scan-Ergebnissen zuordnen (Name aus der Liste statt „unbekannt“). Router: FritzBox (TR-064/Web-API), SNMP, SSH; Windows-DHCP-Server: Leases/Reservierungen per WinRM/PowerShell (`Get-DhcpServerv4Lease`) oder RPC – **machbar ist es nur teilweise, Ich weiß es nicht** für jeden Router; je Modell prüfen. Braucht Eingabefelder für Adresse + Zugangsdaten (Sicherheitsregeln von I-020 gelten: nur RAM, nie loggen/exportieren) | hoch | L | teilweise (0.15.0: FRITZ!Box per TR-064, Namen/Verbindungsart; offen: andere Router, Windows-DHCP, IP-Reservierungen) |

**Sicherheitshinweise zu I-020/I-022 (müssen bei der Umsetzung beachtet werden):**
- Passwörter dürfen nur über eine lokale Verbindung eingegeben werden. Bei `--listen 0.0.0.0` (HTTP ohne Verschlüsselung) Eingabe sperren oder TLS verlangen.
- Keine Passwörter in URL, Logs, Fehlermeldungen, Exporten oder Browser-Speicher (kein `localStorage`).
- SSH-Hostkeys und Zertifikate nicht stillschweigend ignorieren (Warnung/Bestätigung anzeigen).
- Zu viele Fehlversuche vermeiden (Account-Sperren!): pro Gerät nur ein Versuch pro Klick.

## Export
| ID | Idee | Prio | Aufwand | Status |
|---|---|---|---|---|
| I-030 | CSV der **vom Nutzer ausgewählten** Geräte: Benutzername, IP, MAC, Hersteller (ab 0.6.0), Gerätename, offene Ports – **ohne Passwörter** (Passwörter werden separat beim Import eingegeben, außerhalb dieses Programms) | hoch | M | erledigt (0.4.0) |
| I-031 | Lesbare Tabelle (HTML/Markdown) zusätzlich zur CSV | hoch | S | erledigt (0.4.0) |
| I-032 | Lesezeichen-Datei (Netscape-Bookmark-HTML) für Firefox und Chrome mit den ausgewählten Geräten (Web-Links); Ordner als Lesezeichenleiste markiert (`PERSONAL_TOOLBAR_FOLDER="true"`) | mittel | M | erledigt (0.4.1), Import von Sascha getestet |
| I-033 | Weitere Formate: JSON, XLSX | niedrig | M | offen |
| I-034 | Scan-Vergleich (was ist neu/weg seit dem letzten Scan) | niedrig | L | offen |

**Hinweise zu I-030 bis I-032:**
- CSV: Zellen, die mit `=`, `+`, `-`, `@` beginnen, entschärfen (CSV-Injection in Excel); Gerätenamen kommen aus dem Netz. Für deutsche Excel-Version Trennzeichen `;` und UTF-8 mit BOM anbieten.
- Lesezeichen: Das Format wird von beiden Browsern importiert. **Ob** die Markierung für die Lesezeichenleiste greift, ist **nicht** bestätigt: Sascha meldet, dass der Import einen eigenen Ordner anlegt. Das reicht ihm; welcher Browser, ist nicht notiert.
- Lesezeichen enthalten nur URLs ohne Zugangsdaten.

## Oberfläche / Plattform
| ID | Idee | Prio | Aufwand | Status |
|---|---|---|---|---|
| I-040 | Geräte per Häkchen auswählen (Grundlage für I-020, I-030, I-032) | hoch | S | erledigt (0.3.1) |
| I-041 | Webview-Fenster statt Browser-Tab (optional) | niedrig | L | offen |
| I-042 | Hilfe-Seite um alles Wissenswerte erweitern (laufend, auf Wunsch Saschas): Zielformate (CIDR, Einzel-IP, später Bereiche), Namensquellen und ihre Reihenfolge samt „(Vorschlag)“-Bedeutung, Hersteller/OUI, Ports und Risiken, Rechte/Fallback (ARP, ICMP), Export-Formate, Lesezeichen-Import, Datenschutz (nur RAM, keine Passwörter), `--diagnose`, Start-Optionen, Versionsanzeige. Bei jeder neuen Funktion die Hilfe mit anpassen | mittel | S | umgesetzt (0.5.6; bei neuen Funktionen weiter pflegen) |
| I-043 | Windows/macOS-Ausführung real testen | mittel | S | offen |
| I-044 | **Live-Ergebnisse beim Scan:** Gefundene Geräte erscheinen sofort unten in der Liste und werden Stück für Stück ergänzt (erst IP/MAC, dann Ports, Namen, Hersteller, Zertifikat), statt erst nach Scan-Ende. Technisch: Scan-Status liefert Zwischenergebnisse (Polling des bestehenden Status oder Server-Sent Events); Zeilen nach IP zusammenführen, Auswahl/Umbenennen dürfen dabei nicht verloren gehen; Hinweis „Scan läuft – Angaben noch unvollständig“ | hoch | M | erledigt (0.5.4), Praxistest im LAN offen |
| I-045 | **Format-Hinweis unter dem Ziel-Feld:** kleine Zeile unter „Ziel“, wie man einen Teilbereich scannt. Heute geht nur CIDR (`192.168.1.0/28` = 14 Geräte, `192.168.1.64/26`) oder eine Einzel-IP (`192.168.1.5`); Bereiche wie `192.168.1.10-50` werden **noch nicht** unterstützt (siehe I-046), der Hinweis darf nur Unterstütztes nennen | mittel | S | erledigt (0.5.5) |
| I-046 | Bereichsschreibweise im Ziel-Feld (`192.168.1.10-50`, `192.168.1.10-192.168.1.50`, mehrere Ziele mit Komma); gleiche Grenzen wie bisher (max. /16 groß, öffentliche Adressen gesperrt) | mittel | S | erledigt (0.5.5) |

## Vorschlag zur Reihenfolge (Claude, nicht verbindlich)
1. I-005 (echter Scan) → I-040 (Auswahl) → I-021 (Namen) → I-030/I-031 (CSV, Tabelle) → I-032 (Lesezeichen)
2. danach I-010 (Topologie) → I-020/I-022 (Zugangsdaten, Login-Test)
