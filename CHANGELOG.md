# Changelog
Format: [Keep a Changelog](https://keepachangelog.com/de/), Versionierung: [SemVer](https://semver.org/lang/de/).
Das Builddatum wird beim Build automatisch eingesetzt (`NetzScanner --version`).

## [0.4.1] – 2026-11-08
### Hinzugefügt
- **Lesezeichen-Export** (I-032): Netscape-Bookmark-HTML für Firefox und Chrome/Edge mit den Web-Links der ausgewählten Geräte. Zwei Varianten: Ordner als Lesezeichenleiste markiert (`PERSONAL_TOOLBAR_FOLDER`) oder normaler Ordner „NetzScanner“ (Fallback). Nur URLs, keine Zugangsdaten; Namen werden maskiert. Ohne Web-Link bei der Auswahl kommt eine Fehlermeldung.
- Hinweis: Ob die Leisten-Markierung in beiden Browsern greift, ist **unbestätigt** (Import-Test durch Sascha nötig).

## [0.4.2] – 2026-11-08
### Hinzugefügt
- **TLS-Zertifikatsinfos** (I-004): Bei HTTPS-Ports (443, 5001, 8443) liest der Scan Inhaber, Aussteller, Ablaufdatum und „selbst signiert“; das Detail-Panel zeigt sie samt Hinweis „ABGELAUFEN“ bzw. „läuft bald ab“ (< 30 Tage). Das Zertifikat wird nur gelesen, nicht geprüft; Texte werden bereinigt.

## [0.4.3] – 2026-11-08
### Geändert
- **Hersteller-Erkennung aus MAC** (I-003, Vorbereitung): Die Herstellerliste liegt jetzt als eingebettete Datei `internal/scan/data/oui.txt` (statt im Code) und wird beim ersten Zugriff geladen; MAC-Schreibweisen mit `:`, `-`, `.` oder ohne Trenner werden erkannt. Neues Skript `scripts/update-oui.sh` erzeugt die Datei aus der IEEE-Registry (`oui.csv`).
### Hinweis
- Enthalten ist vorerst nur die kleine Startliste: Der Download der IEEE-Liste war in der Entwicklungsumgebung gesperrt. Die vollständige Liste muss noch erzeugt und eingecheckt werden.

## [0.5.8] – 2026-11-08
### Hinzugefügt
- **Hersteller in Tabelle und Export** (I-007): neue Spalte „Hersteller (Chip)“ in der Geräteliste (Tooltip erklärt, dass es der Chip-Hersteller laut MAC ist, nicht zwingend der Gerätehersteller); gleiche Beschriftung im Detail-Panel und in HTML/Markdown-Export samt Fußnote. Hilfe-Seite ergänzt.
### Hinweis
- Die CSV bleibt unverändert bei den festen Spalten (Benutzername, IP, MAC, Gerätename, Offene Ports), damit der Import ins Zielprogramm nicht bricht. Soll der Hersteller auch in die CSV, wäre das eine Option – Entscheidung bei Sascha.
- Solange die OUI-Liste klein ist (I-003), bleibt die Spalte bei vielen Geräten leer.

## [0.5.7] – 2026-11-08
### Hinzugefügt
- **Topologie, erster Schritt** (I-010, Teil 1): Der Scan liest den Standard-Gateway des eigenen Rechners (Linux `/proc/net/route`, Windows `route print`, macOS `route -n get default`; ohne Rechte). Das Gerät mit dieser IP bekommt die Rolle „router“, alle anderen Geräte mit MAC (= selbes Subnetz) den Router als Uplink – die Topologie-Seite zeigt damit statt einer flachen Reihe einen Stern unter dem Router.
### Hinweis
- Das ist **keine echte Verkabelung**: Switch-Ports/Uplinks brauchen LLDP/CDP (Raw-Sockets, Rechte) oder SNMP (Community/Login) – offen als Teil 2 von I-010. Hilfe-Seite erklärt das.
- Nur mit Beispieltexten getestet; im echten LAN (Sascha) prüfen, ob der Router oben steht.

## [0.5.6] – 2026-11-08
### Geändert
- **Hilfe-Seite vervollständigt** (I-042): neue Abschnitte zu Namensquellen samt „(Vorschlag)“, Hersteller/MAC-Präfix, Ports und Risiko-Ports (inkl. TLS-Infos), Rechten und TCP-Fallback, Datenschutz, Lesezeichen-Export sowie Startoptionen (`--listen`, `--demo`, `--allow-public`, `--diagnose`, `--version`). Nur Text, keine Funktionsänderung.

## [0.5.5] – 2026-11-08
### Hinzugefügt
- **Bereiche im Ziel-Feld** (I-046): neben Netz (`192.168.1.0/28`) und Einzel-IP jetzt Bereiche in Kurzform (`192.168.1.10-50`) und ausführlich (`192.168.1.250-192.168.2.5`) sowie mehrere Angaben mit Komma (`192.168.1.5, 192.168.1.20-30`). Doppelte Adressen werden nur einmal gescannt.
- **Format-Hinweis** (I-045): kleine Zeile unter dem Ziel-Feld mit den erlaubten Schreibweisen; Hilfe-Seite mit eigener Tabelle „Ziel eingeben“.
### Sicherheit/Grenzen
- Unverändert: nur IPv4, höchstens 65.536 Adressen je Scan (auch für Bereiche und Listen zusammen), öffentliche Adressen gesperrt – bei Bereichen wird **jede** Adresse geprüft (ein Bereich über die Privatgrenze wird abgelehnt). Anfang hinter Ende, Zahl > 255 oder Müll ergibt eine Fehlermeldung.
- Bei Bereichen bleiben Netz- und Broadcast-Adresse enthalten (nur bei CIDR-Netzen bis /30 entfallen sie), weil der Bereich ausdrücklich angegeben wurde.

## [0.5.4] – 2026-11-08
### Hinzugefügt
- **Live-Ergebnisse beim Scan** (I-044): Gefundene Geräte erscheinen sofort in der Liste und werden Stück für Stück ergänzt – erst IP und offene Ports, dann MAC/Hersteller, zuletzt der Name (bis dahin grau „(wird ermittelt …)“). Fortschrittszeile zeigt die bisher gefundene Anzahl. Angeklickte Zeile, Auswahl und Umbenennen bleiben beim Nachladen erhalten; die Details werden nicht neu gezeichnet, solange man in einem Feld tippt.
- Wird ein Scan abgebrochen, bleiben die bis dahin gefundenen Geräte in der Liste (vorher leer).
- Hilfe-Seite: Abschnitt „Live-Ergebnisse beim Scan“.
### Technik
- `scan.Options.OnHost` meldet Teilergebnisse; neues Feld `pending` am Gerät; der Server führt sie nach IP sortiert zusammen (`upsertHost`). Abfrage weiter per Polling (1 s), keine neue Abhängigkeit.
### Hinweis
- Im Browser nur mit lokalem Scan geprüft (zu schnell, um die Zwischenstufen zu sehen); die Stufen sind per Go-Test abgesichert. Eindruck im echten LAN steht aus.

## [0.5.3] – 2026-11-08
### Hinzugefügt
- **Weitere Namensquellen** (I-008): **LLMNR** (UDP 5355, v. a. Windows) und **SSDP/UPnP** (UDP 1900: Fernseher, Router, Mediaserver) – das Gerät wird direkt gefragt; bei SSDP wird der „friendlyName“ aus der UPnP-Beschreibung gelesen. Reihenfolge: DNS → DNS des Geräts → mDNS → NetBIOS → LLMNR → SSDP → Zertifikat → Seitentitel. Quelle steht im Detail-Panel.
### Sicherheit
- SSDP folgt nur einer `http://`-LOCATION, deren Rechner exakt die abgefragte IP ist (kein Abfragen fremder Rechner), ohne Weiterleitungen, max. 64 KB, Ergebnis bereinigt.
### Hinweis
- Nur mit lokalen Test-Servern geprüft, **nicht im echten LAN**. SNMP-sysName und HTTP-Server-Header aus I-008 sind noch offen.

## [0.5.2] – 2026-11-08
### Geändert
- **Versionsführung:** Die Versionsnummer ist jetzt zusätzlich im Programm eingebettet (`internal/version/VERSION`). Auch bei `go run`/`go build` ohne Build-Skript zeigt das Programm die richtige Nummer statt „dev“. Ein Test stellt sicher, dass sie mit `VERSION` im Root übereinstimmt. Regeln dazu stehen in `CLAUDE.md` und `HANDOVER.md`.

## [0.5.1] – 2026-11-08
### Geändert
- **Kennung-Namen abgewertet** (I-009): Namen, die nur eine MAC-/EUI-64-Kennung sind (z. B. `001788FFFE476CE2` einer Hue Bridge), gelten nicht mehr als Gerätename; die Namenssuche probiert dann weitere Quellen (mDNS, NetBIOS, Zertifikat, Seitentitel).
- Findet keine Quelle einen Namen, aber die MAC einen Hersteller, erscheint „<Hersteller> (Vorschlag)“ mit Quelle „Hersteller aus der MAC“. Mit der kleinen Startliste greift das nur selten; erst die volle OUI-Liste (I-003) macht es nützlich.

## [0.5.0] – 2026-11-08
### Hinzugefügt
- **Bessere Namenssuche** (I-002): Geräte, die bisher „(unbekannt)“ blieben, werden zusätzlich per **mDNS/Bonjour** (UDP 5353, z. B. Apple-Geräte, Drucker, Chromecast) und **NetBIOS** (UDP 137, Windows-PCs, Samba-NAS) nach ihrem Namen gefragt. Beides braucht keine Sonderrechte; pro Gerät eine Anfrage direkt an dessen IP. Reihenfolge: DNS → DNS des Geräts → mDNS → NetBIOS → Zertifikat → Seitentitel. Die Namensquelle steht im Detail-Panel.
- Eigene, kleine DNS-/NetBIOS-Auswertung (`internal/scan/udpnames.go`) mit Schutz gegen manipulierte Antworten (Zeigerschleifen, zu kurze Pakete). Keine neuen Abhängigkeiten.
### Hinweis
- Nur im Test mit lokalen UDP-Servern geprüft, **nicht im echten LAN**. Geräte ohne mDNS/NetBIOS (z. B. Handys mit zufälliger MAC) bleiben weiter unbekannt.

## [Unreleased]
### Hinzugefügt
- `IDEAS.md`: neue Ideen I-044 (Live-Ergebnisse beim Scan), I-045 (Format-Hinweis am Ziel-Feld), I-046 (Bereichsschreibweise); I-042 (Hilfe) erweitert. Nur Doku.
- `HANDOVER.md`: Roadmap an die tatsächlich ausgelieferten Versionen angepasst (nur Doku, keine neue Version).
- `IDEAS.md`: Ideenliste mit Priorität, Aufwand und Status; Regel dazu in `CLAUDE.md`.

## [0.4.0] – 2026-11-08
### Hinzugefügt
- **Export der ausgewählten Geräte** (I-030, I-031): CSV (Excel Deutsch mit Semikolon + BOM, oder Standard mit Komma) mit den Spalten Benutzername, IP, MAC, Gerätename, Offene Ports – **ohne Passwörter**; lesbare Tabelle als HTML (hell/dunkel, mit Web-Links) und Markdown. Dateiname `netzscanner-JJJJMMTT-HHMM.<endung>`.
- Optionales Feld **Benutzername** je Gerät im Detail-Panel (nur Name, kein Passwort; nur im RAM) – API `POST /api/hosts/user`, `POST /api/export`.
### Sicherheit
- Schutz vor CSV-Injection: Werte, die mit `= + - @` (oder Tab/Zeilenumbruch) beginnen, bekommen ein `'` vorangestellt.
- Namen werden in Markdown und HTML maskiert; die Exportdatei wird mit `nosniff` ausgeliefert.
### Geändert
- Roadmap: Topologie jetzt 0.5.0, Logins 0.6.0.

## [0.3.3] – 2026-11-08
### Hinzugefügt
- Diagnose-Kommando `netzscanner --diagnose <IP>`: prüft ein Gerät Schritt für Schritt (DNS-Konfiguration, offene Ports, ARP/MAC, Reverse-DNS über drei Wege, TLS-Zertifikat, Web-Startseite, Ergebnis der Namenssuche) und zeigt jede Fehlermeldung. Zum Kopieren für die Fehlersuche; enthält keine Zugangsdaten.
### Hinweis
- Die mehrstufige Namenssuche aus 0.3.2 (Zertifikat, Seitentitel) war im Merge von PR #4 noch nicht enthalten und kommt mit diesem Release.

## [0.3.2] – 2026-11-08
### Behoben
- Gerätename „_gateway“ (gemeldet bei der FritzBox): Der System-Resolver lieferte einen lokalen Pseudonamen (vermutlich vom NSS-Modul `myhostname`). Es wird jetzt der eingebaute Go-Resolver genutzt, und Namen mit führendem `_` werden verworfen.
### Hinzugefügt
- Mehrstufige Namenssuche, wenn der System-DNS keinen Namen liefert (FritzBox zeigte „(unbekannt)“): 1. DNS, 2. DNS direkt beim Gerät (wenn Port 53 offen), 3. Name im TLS-Zertifikat, 4. Titel der Weboberfläche (nur Vorschlag, bleibt „unbekannt“ markiert).
- Die Namensquelle wird im Detail-Panel angezeigt.
### Sicherheit
- Zertifikate werden nur gelesen (ohne Prüfung, da Geräte meist selbst signiert sind); es werden keine Zugangsdaten gesendet.
### Bekannt
- Echter Gerätetyp-Erkennung (z. B. „FritzBox“ aus mehreren Hinweisen) bleibt offen: I-006. Die Quellen 2 und 4 sind nur gegen Test-Server geprüft, nicht gegen eine echte FritzBox.

## [0.3.1] – 2026-11-08
### Hinzugefügt
- Geräte per Häkchen auswählen (einzeln, „Alle“, „Auswahl aufheben“, Zähler); Auswahl wird auch in der Topologie markiert (I-040).
- Gerätenamen anpassen im Detail-Panel, mit „Zurücksetzen“ und Anzeige des Scan-Namens; Namen bleiben bis zum Programmende und über neue Scans (nach IP) erhalten (I-021).
- API `POST /api/hosts/name` (max. 64 Zeichen, keine Steuerzeichen).
### Hinweis
- Auswahl und Namen liegen nur im Speicher; der Export (CSV, Lesezeichen) folgt in I-030/I-032.

## [0.3.0] – 2026-11-08
### Hinzugefügt
- Scan-Kern (`internal/scan`): Zielauswertung (CIDR/Einzel-IP, max. /16), TCP-Connect-Portscan ohne Admin-Rechte, Banner-Abfrage, Reverse-DNS, MAC aus der ARP-Tabelle (Linux, Windows, macOS), Hersteller (kleine Beispieltabelle).
- Scan-API (`POST /api/scan`, Status, Abbruch) und Scan-Leiste in der Oberfläche mit Fortschritt.
- Startoptionen `--demo` (Demo-Daten) und `--allow-public`.
### Geändert
- Ohne `--demo` startet die Liste leer; es werden nur noch echte Scan-Ergebnisse gezeigt.
### Sicherheit
- Öffentliche Adressen sind standardmäßig gesperrt.
- POST nur mit `application/json` und passendem Origin (Schutz vor Cross-Site-Aufrufen auf localhost).
- Banner und Namen aus dem Netz werden bereinigt und nur als Text angezeigt.
### Bekannte Grenzen
- MAC nur im selben Subnetz; Geräte ohne offene Port-Antwort und ohne ARP-Eintrag werden nicht gefunden.
- Hersteller-Tabelle unvollständig; keine OS-Erkennung; Topologie noch ohne LLDP/SNMP (0.4.0).
- Nur lokal getestet (localhost); echter LAN-Scan steht aus.

## [0.2.0] – 2026-11-08
### Hinzugefügt
- Eingebauter Webserver (`--listen`, Standard nur lokal `127.0.0.1:8484`) mit eingebetteter dunkler Oberfläche.
- Gemischtes Design A+B: Übersicht (Kennzahlen, Geräteliste, Details) und Reiter Topologie.
- Klickbare Web-Zugänge pro Gerät (Ports 80, 443, 5000, 5001, 8080 …), Öffnen in neuem Tab.
- Hilfe-Seite in der Oberfläche, Versions-/Builddatum-Anzeige in der Fußzeile.
- Datenmodell `Host`/`Port`, Demo-Daten (Scan-Kern folgt), Tests für Links und Server.
### Sicherheit
- Texte aus dem Netz werden nur als Text (nie als HTML) angezeigt; Link-URLs entstehen nur aus validierter IP.

## [0.1.0] – 2026-11-08
### Hinzugefügt
- Projektgrundlagen: README, CHANGELOG, HANDOVER, CLAUDE.md.
- Sprachentscheidung Go (ADR-0001).
- Go-Grundgerüst mit `--version` (Versionsnummer, Builddatum, Commit).
- Build-Skript für Linux/Windows/macOS inkl. ARM (`scripts/build.sh`).
- Drei dunkle Design-Konzepte als klickbare Entwürfe (`docs/design/`).

## [0.5.9] – 2026-11-08
### Geändert
- **Volle IEEE-OUI-Liste eingebettet** (I-003): `internal/scan/data/oui.txt` enthält jetzt ~40.000 Herstellerpräfixe (erzeugt von Sascha mit `scripts/update-oui.sh`). Damit klappt die Chip-Erkennung aus der MAC (z. B. `0C:72:74` = AVM).
- Test `TestVendor` prüft den Namen als Teilstring („Raspberry Pi“), da die IEEE-Liste „Raspberry Pi Foundation/Trading Ltd“ liefert.
- Grenze bleibt: Zufällige (lokal administrierte) MAC-Adressen haben keinen Hersteller.

## [0.6.0] – 2026-11-08
### Geändert
- **CSV enthält jetzt den Chip-Hersteller** (I-007): neue Spalte „Hersteller (Chip)“ direkt nach „MAC“ (Reihenfolge: Benutzername, IP, MAC, Hersteller (Chip), Gerätename, Offene Ports). Achtung: Die Spaltenanzahl ändert sich – ein Import mit fester Spaltenzuordnung muss ggf. angepasst werden. Der Hersteller ist der Chip-Hersteller, nicht zwingend der Gerätehersteller; Zellen werden wie alle anderen gegen CSV-Injection entschärft.

## [0.7.0] – 2026-11-08
### Hinzugefügt
- **Topologie als PDF exportieren** (I-012): Button „Topologie als PDF“ im Reiter Topologie. Das PDF (A4 quer) zeigt auf Seite 1 die Karte aller Geräte (Router oben, Geräte darunter; bei vielen Geräten umgebrochen und verkleinert), danach eine Geräteliste mit Name, IP, MAC, Hersteller (Chip) und offenen Ports. Keine Zugangsdaten im PDF.
- Neue Abhängigkeit: `github.com/go-pdf/fpdf` (reines Go, kein CGO).
- Grenze: Es werden nur PDF-Standardschriften genutzt; Zeichen außerhalb von Windows-1252 (z. B. Kyrillisch) erscheinen als „.“. Wie die Weboberfläche zeigt das PDF eine Sternansicht, keine echte Verkabelung.
