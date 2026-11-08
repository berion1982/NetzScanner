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
