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
| I-003 | Vollständige IEEE-OUI-Herstellerliste einbetten (Lizenz/Quelle prüfen) | mittel | S | teilweise (0.4.3): Mechanismus + Skript fertig, volle Liste fehlt |
| I-004 | TLS-Zertifikatsinfos (CN, Ablauf) bei HTTPS-Ports | niedrig | S | erledigt (0.4.2) |
| I-006 | (teilweise in 0.3.2: Namen aus Zertifikat/Titel) Gerätetyp erkennen (z. B. FritzBox, NAS, Drucker) über Hersteller, HTTP-Titel/Server, TLS-Zertifikat, UPnP/SSDP; als Vorschlag für den Namen anzeigen | hoch | M | offen |
| I-007 | Hersteller aus der MAC (Netzwerkchip) auch in Tabelle und Export anzeigen, mit Hinweis „Chip-Hersteller, nicht zwingend Gerätehersteller“ (Vorschlag Sascha; Basis ist I-003, im Detail-Panel schon vorhanden) | mittel | S | offen |
| I-008 | Weitere Namensquellen: SSDP/UPnP (TV, Router, Mediaserver), LLMNR, HTTP-Server-Header, SNMP sysName | mittel | M | offen |
| I-005 | Echter LAN-Scan durch Sascha, Fehler/Lücken melden | hoch | S | offen |

## WLAN
| ID | Idee | Prio | Aufwand | Status |
|---|---|---|---|---|
| I-050 | WLANs in Reichweite erkennen (SSID, BSSID/MAC, Kanal, Frequenzband, Signalstärke, Verschlüsselung) und in einer **separaten Datei** ablegen (CSV, später auch lesbare Tabelle); zusätzlich kennzeichnen, mit welchem WLAN der Scan-Rechner selbst verbunden ist | mittel | L | offen |

**Hinweise zu I-050 (Annahmen, noch nicht geprüft):**
- Geht nur, wenn der Rechner einen WLAN-Adapter hat (Raspberry Pi hat meist einen); ohne Adapter „nicht verfügbar“ melden, kein Fehler.
- Plattformabhängig, ohne CGO über vorhandene Systemwerkzeuge: Linux `nmcli`/`iw`, Windows `netsh wlan show networks mode=bssid`, macOS Systemwerkzeuge. Ausgabeformate und Rechte (z. B. Standortfreigabe unter macOS für SSIDs – vermutlich nötig) müssen je System getestet werden.
- Der Cloud-Container hat kein WLAN, Tests nur mit Beispieltexten der Werkzeuge möglich; echter Test bei Sascha nötig.
- Es werden nur öffentlich ausgesendete Daten gelistet (passiv); keine Passwörter, kein Verbinden.
- Offene Frage an Sascha: Nur WLANs der eigenen Umgebung auflisten oder auch fremde (Nachbarn)? Standard-Vorschlag: alle sichtbaren, mit Spalte „eigenes Netz“.

## Topologie
| ID | Idee | Prio | Aufwand | Status |
|---|---|---|---|---|
| I-010 | LLDP/CDP und SNMP (ARP-/MAC-/Interface-Tabellen) für echte Uplinks | hoch | L | geplant (0.4.0) |
| I-011 | Traceroute für Segmente hinter Routern | niedrig | M | offen |

## Zugangsdaten und Login-Test
| ID | Idee | Prio | Aufwand | Status |
|---|---|---|---|---|
| I-020 | In der Oberfläche Zugangsdaten (Benutzer/Passwort) pro ausgewähltem Gerät hinterlegen – **nur temporär im RAM**, nie auf Platte, nie in Logs/Exporten; Löschen per Knopf, beim Beenden und nach Inaktivität | hoch | M | offen |
| I-021 | Gerätenamen in der Oberfläche anpassen (Anzeigename, wirkt auf Export/Lesezeichen) | hoch | S | erledigt (0.3.1) |
| I-022 | Login-Test je Gerät: SSH, SNMPv3, Web (HTTP-Anmeldung), später LDAP/WinRM/SMB (Domain-Admins); Ergebnis „ok/fehlgeschlagen“ in der Liste | hoch | L | offen |
| I-023 | Router-/Server-Infos nach erfolgreichem Login auslesen (Modell, Firmware, Schnittstellen, Domäne) | mittel | L | offen |

**Sicherheitshinweise zu I-020/I-022 (müssen bei der Umsetzung beachtet werden):**
- Passwörter dürfen nur über eine lokale Verbindung eingegeben werden. Bei `--listen 0.0.0.0` (HTTP ohne Verschlüsselung) Eingabe sperren oder TLS verlangen.
- Keine Passwörter in URL, Logs, Fehlermeldungen, Exporten oder Browser-Speicher (kein `localStorage`).
- SSH-Hostkeys und Zertifikate nicht stillschweigend ignorieren (Warnung/Bestätigung anzeigen).
- Zu viele Fehlversuche vermeiden (Account-Sperren!): pro Gerät nur ein Versuch pro Klick.

## Export
| ID | Idee | Prio | Aufwand | Status |
|---|---|---|---|---|
| I-030 | CSV der **vom Nutzer ausgewählten** Geräte: Benutzername, IP, MAC, Gerätename, offene Ports – **ohne Passwörter** (Passwörter werden separat beim Import eingegeben, außerhalb dieses Programms) | hoch | M | erledigt (0.4.0) |
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
| I-042 | Hilfe-Seite um neue Funktionen erweitern (laufend) | mittel | S | offen |
| I-043 | Windows/macOS-Ausführung real testen | mittel | S | offen |

## Vorschlag zur Reihenfolge (Claude, nicht verbindlich)
1. I-005 (echter Scan) → I-040 (Auswahl) → I-021 (Namen) → I-030/I-031 (CSV, Tabelle) → I-032 (Lesezeichen)
2. danach I-010 (Topologie) → I-020/I-022 (Zugangsdaten, Login-Test)
