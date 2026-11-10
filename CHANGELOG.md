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

## [0.8.0] – 2026-11-08
### Hinzugefügt
- **Betriebssystem-Vermutung** (I-013): Das Feld „System (Vermutung)“ wird jetzt aus dem Scan gefüllt – aus SSH-Bannern (OpenSSH-Version + Ubuntu/Debian/Raspbian, RouterOS, Dropbear, Windows-OpenSSH), HTTP-Server-Headern (IIS-Version → Windows, Apache/nginx mit „(Ubuntu)“/„(Debian)“ …) und typischen Ports (RDP/RPC/WinRM → Windows, AFP → macOS, Port 62078 → iOS). Es wird nichts zusätzlich gesendet.
- Anzeige im Detail-Panel und als neue Spalte „System (Vermutung)“ in der PDF-Geräteliste.
- Grenzen: nur eine **Vermutung**; Versionszuordnung (z. B. OpenSSH 8.9 → Ubuntu 22.04) gilt nur für unveränderte Distributionspakete; ohne Banner (z. B. die meisten Windows-PCs, Handys) bleibt das Feld leer. Offen: Windows-Version per SMB, SNMP, TTL.

## [0.9.0] – 2026-11-08
### Hinzugefügt
- **Standort pro Gerät** (I-014): Im Detail-Panel gibt es ein Freitextfeld „Standort“ (z. B. „Büro, Raum 2“, max. 64 Zeichen). Der Standort steht in der Tabelle, in der **CSV** (neue Spalte „Standort“ nach „Gerätename“), in HTML/Markdown und in der PDF-Geräteliste. Neuer Endpunkt `POST /api/hosts/location`.
- Achtung: Die CSV hat wieder eine Spalte mehr (Benutzername, IP, MAC, Hersteller (Chip), Gerätename, Standort, Offene Ports).
- Wie Anzeigenamen und Benutzernamen liegt der Standort nur im Arbeitsspeicher und ist nach dem Beenden des Programms weg.

## [0.9.1] – 2026-11-08
### Geändert
- **Standort in allen Exporten** (I-014): CSV, HTML, Markdown und PDF-Liste hatten ihn schon; neu steht er auch in den Kästen der **PDF-Topologiekarte** (dritte Zeile, kursiv, nur wenn eingetragen). Lesezeichen enthalten bewusst keinen Standort.

## [0.10.0] – 2026-11-08
### Hinzugefügt
- **Topologie-Kategorien** (I-015): Jedes Gerät ist Netzwerkgerät, Server, Client oder IoT. Die Einordnung ist eine **Vermutung** (`internal/scan/category.go`) aus Router-Rolle, Chip-Hersteller, System-Vermutung und offenen Ports; im Detail-Panel überschreibbar („Automatisch“ setzt zurück, nur im RAM, Endpunkt `POST /api/hosts/category`).
- Karte: Farbe je Kategorie, Gruppierung je Ebene, Legende mit Anzahl; Klick auf die Legende blendet eine Kategorie aus. Spalte „Kategorie“ in der Tabelle.
- Exporte: CSV (neue Spalte **hinten**, bestehende Reihenfolge unverändert), HTML, Markdown und PDF (Kastenfarben, Legende, Spalte in der Liste). Lesezeichen bleiben unverändert.
- Hinweis: Die Heuristik ist ungetestet im echten LAN (z. B. TP-Link-Steckdosen gelten als Netzwerkgerät, Raspberry Pi mit SSH als Server).

## [0.11.0] – 2026-11-08
### Hinzugefügt
- **Eingaben zwischenspeichern** (I-016): Anzeigename, Benutzername, Standort und Kategorie werden nach jeder Änderung atomar in `eingaben.json` geschrieben (Standard: Konfigurationsordner des Benutzers, Datei 0600/Ordner 0700) und beim Start geladen. Nie Passwörter, keine Scan-Ergebnisse. Die Datei ist **unverschlüsselt**.
- Startoptionen `--data DATEI` (anderer Pfad) und `--no-save` (nur Arbeitsspeicher); im `--demo`-Modus wird nie gespeichert.
- Schutz vor IP-Wechsel: Die MAC wird mitgespeichert; steckt hinter der IP später ein anderes Gerät, werden die alten Eingaben dort nicht angezeigt (und beim Ändern verworfen).
- Kaputte oder zu große Datei: wird zu `.defekt` umbenannt (nicht gelöscht), das Programm startet normal. Knopf „Gespeicherte Eingaben löschen“ in der Hilfe (mit Rückfrage).
### Geändert
- Hilfe: Datenschutz-Abschnitt beschreibt jetzt den Zwischenspeicher.

## [0.11.1] – 2026-11-08
### Behoben
- **Topologie-Karte bei vielen Geräten:** Die Kästen einer Ebene überlappten sich und lange Namen liefen heraus. Jetzt wird auf mehrere Zeilen umgebrochen (6 pro Zeile, feste Abstände), Namen werden gekürzt (voller Name als Tooltip) und die Bildhöhe passt sich an.

## [0.12.0] – 2026-11-08
### Geändert
- **Topologie-Karte mit Sammelgruppen:** Geräte mit gleichem Uplink und gleicher Kategorie werden in einem gestrichelten Rahmen („IoT (19)“) zusammengefasst, statt eine Linie je Gerät zu zeichnen. Die Linien laufen über eine Sammelschiene links neben den Gruppen. Einzelne Geräte stehen ohne Rahmen. Nur die Weboberfläche; die PDF-Karte ist noch unverändert (Linie je Gerät).

## [0.12.1] – 2026-11-08
### Geändert
- **PDF-Karte mit Sammelgruppen** (wie die Weboberfläche seit 0.12.0): gestrichelter Rahmen je Gruppe in Kategoriefarbe mit Titel und Anzahl, eine Linie pro Gruppe über eine Sammelschiene, Einzelgeräte ohne Rahmen. Bis zu 6 Kästen pro Zeile in einer Gruppe; bei vielen Geräten wird die Karte wie bisher verkleinert.

## [0.13.0] – 2026-11-08
### Hinzugefügt
- **Eigene Kategorien** (I-017): Im Detail-Panel gibt es unter „Kategorie“ den Eintrag „+ Eigene Kategorie anlegen …“ (Name bis 30 Zeichen, bis zu 20 Stück, nicht wie eine feste Kategorie). Eigene Kategorien bekommen automatisch eine feste Farbe (aus dem Namen), erscheinen in Legende (ein-/ausblendbar), Karte mit Sammelgruppen, Tabelle, CSV/HTML/Markdown und im Topologie-PDF (Legende bricht bei vielen Kategorien um). „Kategorie … löschen“ entfernt sie wieder; betroffene Geräte fallen auf die automatische Vermutung zurück (es werden keine Geräte gelöscht).
- Neue Endpunkte `GET/POST /api/categories` und `POST /api/categories/delete`; die Liste steht in `eingaben.json` (Feld `customCategories`) und überlebt Neustarts auch ohne zugeordnete Geräte. Intern ist der Schlüssel `custom:<Name>`.

## [0.13.1] – 2026-11-08
### Hinzugefügt
- **Betriebssystem-Spalte** (I-013, Teil): „System (Vermutung)“ jetzt auch in der Geräte-Tabelle sowie in CSV (neue letzte Spalte „Betriebssystem (Vermutung)“, bestehende Spalten unverändert), HTML und Markdown. Weiterhin nur eine Vermutung aus SSH-Banner, HTTP-Server-Header und Ports; der Wert wird in der CSV gegen Formeln abgesichert.

## [0.13.2] – 2026-11-08
### Hinzugefügt
- **Home Assistant erkennen** (I-013): Die Standard-Portliste enthält jetzt 8123 (Weboberfläche von Home Assistant, mit Web-Link und HEAD-Abfrage) und 22222 (SSH von HA OS). Ist 8123 offen, lautet die Betriebssystem-Vermutung „Home Assistant (Linux-basiert, Vermutung aus Port 8123)“; ein Windows-Hinweis aus einem Banner hat Vorrang.
### Hinweis
- Das ist eine Vermutung aus dem Port. Eine genaue HA-/Linux-Version liefert der Scan ohne Login nicht. Im LAN noch nicht geprüft.

## [0.13.3] – 2026-11-08
### Geändert
- **Home Assistant → Kategorie „Server“** (I-015): Geräte mit offenem Port 8123 werden automatisch als Server eingeordnet, auch wenn der Chip-Hersteller sonst nach IoT aussieht. Die Wahl im Detail-Panel überschreibt das weiterhin.

## [0.14.0] – 2026-11-08
### Hinzugefügt
- **Echte Verbindungen per SNMP** (I-010, Teil 2): Im Topologie-Tab (Bereich „Echte Verbindungen per SNMP lesen“) gibst du die IPs deiner Switches (müssen in der Geräteliste stehen) und eine Nur-Lesen-Community ein. Der NetzScanner liest per SNMP v2c Name, Beschreibung und die MAC-Adresstabelle (BRIDGE-MIB und Q-BRIDGE-MIB) und hängt jedes Gerät an den Switch, an dem es steckt – auch Switches untereinander. Im Detail-Panel steht der Port („Anschluss (SNMP)“); die Karte (Web und PDF) zeigt die echte Hierarchie. Abgefragte Switches bekommen die Rolle „switch“ (Kategorie Netzwerkgeräte) und ihre Systembeschreibung als System-Vermutung.
- Regel: Der Uplink-Port eines Switches ist der Port, an dem die MAC des Routers gelernt wurde (sonst der Port mit den meisten MACs); ein Gerät hängt an dem anderen Port mit den wenigsten gesehenen MACs. „Zurücksetzen“ bringt die Sternansicht zurück.
- Neue Bibliothek: `github.com/gosnmp/gosnmp` (reines Go, kein CGO).
### Sicherheit / Grenzen
- Die Community wird nur im Anfragekoerper übertragen, nicht gespeichert, nicht protokolliert, nicht in Exporte oder Antworten geschrieben; das Feld wird nach dem Lesen geleert. Abgefragt werden nur Adressen aus der Geräteliste (höchstens 10).
- **Ungeprüft an echter Hardware** (nur Logiktests). Bekannte Grenzen: SNMP v2c ist unverschlüsselt; v3 fehlt; hinter nicht abgefragten Switches/Access Points erscheinen Geräte am selben Port; VLAN-Communities (`community@vlan`) werden evtl. nur teilweise gelesen; LLDP/CDP bleibt offen.

## [0.14.1] – 2026-11-08
### Geändert
- **Tabelle kompakter:** Neue Spalte „Web“ direkt hinter dem Namen mit kleinen Knöpfen „🌐 Port“ je Weboberfläche (Klick öffnet sie in neuem Tab); Geräte ohne Weboberfläche zeigen einen grauen Strich. Die breite Web-Spalte am Zeilenende entfällt.
- Hersteller werden gekürzt (Rechtsform-Zusätze wie „Inc.“/„GmbH“/„Technologies“ entfallen, max. 18 Zeichen); der volle Name steht im Tooltip und im Detail-Panel. System und Standort werden mit „…“ gekürzt, die Ports umbrechen.

## [0.14.2] – 2026-11-08
### Geändert
- **Spalte „System (Vermutung)“ aus der Tabelle entfernt** (Wunsch Sascha, Tabelle zu breit). Die Vermutung steht weiter im Detail-Panel, im PDF sowie in CSV/HTML/Markdown.

## [0.15.0] – 2026-11-08
### Hinzugefügt
- **Router-Login für die FRITZ!Box** (I-024, Teil): Auf der Übersicht gibt es den Bereich „Router-Login“. Mit Benutzer und Passwort liest der NetzScanner per TR-064 (Dienst `Hosts:1`, Port 49000, HTTP-Digest) die Geräteliste der Box: Name, MAC, Verbindungsart (WLAN/Kabel), aktiv/inaktiv. Die Zuordnung zu den Scan-Ergebnissen läuft über die MAC; unbekannte Geräte bekommen den Namen aus der Box (Quelle „Router-Geräteliste“), das Detail-Panel zeigt „Verbindung (Router)“ und „Name laut Router“. Geräte, die nur die Box kennt, werden nach dem Lesen aufgelistet. „Zurücksetzen“ entfernt die Angaben.
- Neues Paket `internal/router`, Endpunkte `POST /api/router/fritzbox` und `/api/router/clear`.
### Sicherheit
- Zugangsdaten nur im Arbeitsspeicher: nie gespeichert, nie protokolliert, nie in Fehlertexten, Antworten oder Exporten; das Passwortfeld wird sofort geleert. Ein Klick = **ein** Anmeldeversuch (bei Ablehnung sofortiger Abbruch, kein Wiederholen → keine Sperre). Der Endpunkt akzeptiert nur Anfragen von diesem Rechner (Loopback) und nur Router-Adressen aus der Geräteliste; keine Weiterleitungen, Antworten begrenzt.
### Grenzen
- Nur mit einem Test-Server geprüft, **nicht an einer echten FRITZ!Box**. Voraussetzung: „Zugriff für Anwendungen“ (TR-064) aktiv, Benutzer mit Recht „FRITZ!Box Einstellungen“. Die Antworten (Geräte-Namen) laufen bei HTTP unverschlüsselt im LAN. Nicht unterstützt: andere Router, Windows-DHCP, feste IP-Reservierungen, Mesh-Zuordnung.

## [0.16.0] – 2026-11-08
### Hinzugefügt
- **Router-Info und WLAN der FRITZ!Box** (I-055): Der Router-Login liest jetzt zusätzlich (nur lesend, TR-064) **Router-Info** (Modell, Firmware, Laufzeit, Internet-Status/-Zugang, Leitungsrate, DHCP-Bereich, Gateway/DNS) und die **WLAN-Netze** (Name/SSID, aktiv, Band und Kanal, Standard, Verschlüsselungsart; ein **offenes WLAN wird farbig markiert**) samt **WLAN-Clients mit Signalstärke und Geschwindigkeit**. Die Angaben erscheinen als Karte „Router und WLAN“ unter dem Login; im Detail-Panel eines Geräts steht „WLAN (Router)“ mit SSID, Signal und Tempo.
- **Eigene Datei:** „Als Markdown speichern“ (Router, WLAN-Netze, WLAN-Clients) und „WLANs als CSV speichern“ (Excel-freundlich, Formel-Schutz). **Nicht enthalten:** externe IP, Zugangsdaten; der WLAN-Schlüssel wird nie gelesen.
- Neue Endpunkte `GET /api/router/info`, `POST /api/router/export`. Fehlende Dienste/Felder (je Modell und FRITZ!OS verschieden) werden übersprungen und unter „Nicht gelesen“ genannt.
### Behoben
- **Wichtig:** Die Knöpfe „Topologie als PDF“, „SNMP lesen“ und „Router lesen“ wurden bei jedem Auswählen/Neuzeichnen der Tabelle **erneut registriert** (der Code stand versehentlich in `updateSelection`). Ein Klick konnte dadurch **mehrere gleiche Anfragen** auslösen – beim Router-Login also mehrere Anmeldeversuche. Die Handler werden jetzt einmalig registriert.
### Sicherheit / Grenzen
- Es werden nur `Get*`-Aktionen benutzt (ein Test stellt sicher, dass weder Schlüssel gelesen noch etwas gesetzt wird). Nur gegen einen Test-Server geprüft, **nicht an einer echten FRITZ!Box**; Feldnamen stammen aus dem TR-064-Standard bzw. dem Gedächtnis und können je Modell abweichen. Mesh-Topologie und IP-Reservierungen (I-055 c/d) sind noch offen.

## [0.17.0] – 2026-11-08
### Hinzugefügt
- **LLDP-Nachbarn per SNMP** (I-051): `internal/scan/lldp.go` liest die `lldpRemTable` (LLDP-MIB) der abgefragten Switches. Nachbarn werden über Chassis-MAC oder Management-IPv4 den gescannten Geräten zugeordnet und haben Vorrang vor der MAC-Tabelle; ein Router als Nachbar legt den Uplink-Port des Switches fest. Die Switch-Antwort zeigt „MAC-Einträge, LLDP-Nachbarn“.
### Hinweis (unbestätigt, im LAN prüfen)
- LLDP muss am Gerät aktiv sein; die Chassis-ID kann von der im Scan gesehenen MAC abweichen (dann Fallback MAC-Tabelle). Annahme: lokale LLDP-Portnummer = ifIndex. Nur mit Test-Daten geprüft, nicht an LANCOM/Netgear.

## [0.18.0] – 2026-11-08
### Hinzugefügt
- **Hersteller des Switches aus der `sysObjectID`** (I-052): Bei der SNMP-Abfrage wird die Enterprise-Nummer gelesen (`internal/scan/vendor.go`, u. a. LANCOM, Netgear, Cisco, HP, TP-Link, Zyxel, Ubiquiti, MikroTik). Der Hersteller erscheint hinter der Adresse im SNMP-Ergebnis und in der System-Spalte; bei Geräten ohne Tabellen gibt es einen gezielten Hinweis („Bridge-MIB bzw. LLDP am Gerät einschalten“).
### Hinweis
- Die Nummern-Tabelle ist aus dem Gedächtnis erstellt und **nicht gegen die IANA-Liste geprüft**; unbekannte Nummern bleiben ohne Herstellernamen.

## [0.19.0] – 2026-11-08
### Hinzugefügt
- **Neuer Reiter „DHCP & Router“** (I-056) für die Zusatzquellen. Der **Router-Login** (FRITZ!Box) ist von der Übersicht dorthin umgezogen, unverändert in der Funktion.
- **Windows-DHCP-Server auslesen** (I-056): `internal/dhcp/windows.go` liest per WinRM (Port 5985, NTLM mit Nachrichtenverschlüsselung, Bibliothek `masterzen/winrm`, Pure Go) mit PowerShell **nur lesend** alle Leases und festen Reservierungen (`Get-DhcpServerv4Scope/-Lease/-Reservation`). Zuordnung über die MAC (`POST /api/dhcp/windows`, `/api/dhcp/clear`): Name vom Server füllt „(unbekannt)“ und Hersteller-Vorschläge (Quelle „dhcp“), im Detail-Panel steht „DHCP-Server: feste Reservierung / Lease bis …“, Meldung listet Einträge, die der Scan nicht gefunden hat.
- Sicherheit wie beim Router-Login: nur Loopback, Zugangsdaten nur im RAM und nie geloggt/exportiert, Server muss in der Geräteliste stehen, Antwort wird bereinigt und begrenzt.
### Hinweis
- **Nicht an einem echten Windows Server geprüft** (nur Auswertung der Antwort und Zuordnung mit Testdaten). Annahmen aus dem Gedächtnis: WinRM ist auf Windows Server ab 2012 R2 standardmäßig an; ein Benutzer braucht „DHCP-Benutzer“ und „Remoteverwaltungsbenutzer“ (oder Admin). Kerberos wird nicht unterstützt (nur NTLM, Anmeldung als `DOMÄNE\benutzer`).
- Neue Regel in CLAUDE.md: keine festen Einzelgeräte-Werte in Tabellen.

## [0.20.0] – 2026-11-08
### Hinzugefügt
- **Neuer Reiter „Reservierungen“** (I-057): Liste der festen DHCP-Reservierungen aus dem zuletzt gelesenen Windows-DHCP-Server (Netz, IP, MAC, Name laut DHCP, Gerät im Scan), numerisch sortiert. Nur im Arbeitsspeicher.
- **Export der Liste** (`internal/export/reservations.go`): CSV (Excel Deutsch mit Semikolon und BOM oder Standard mit Komma) und lesbares Markdown. Die ersten vier CSV-Spalten (Netz, IP, MAC, Name) sind stabil gehalten, damit die Datei später wieder eingelesen werden kann; Zellen sind gegen Formel-Einschleusung geschützt.
### Hinweis
- Das **Wiedereinlesen** (Import in den Scanner bzw. Schreiben zurück zum DHCP-Server) ist **noch nicht gebaut**, siehe I-058 in IDEAS.md. Die Liste stammt wie die DHCP-Abfrage aus 0.19.0 und ist nicht an einem echten Windows Server geprüft.

### Nachtrag zu 0.20.0
- Entscheidung von Sascha: Das Wiedereinlesen/Zurückschreiben von Reservierungen (I-058) wird **nicht** gebaut; der NetzScanner ist nur zum Sammeln und Exportieren da, der Import ist Sache des Windows Servers.

## [0.21.0] – 2026-11-08
### Hinzugefügt
- **`--diagnose-router <IP>`** (I-055 d, Vorbereitung): Fragt die FRITZ!Box selbst, welche TR-064-Dienste und Aktionen sie anbietet (`tr64desc.xml` und die Beschreibungsdateien, nur HTTP-GET, **ohne Zugangsdaten**). Aktionen, die nach Reservierung/DHCP/Lease/Adresse aussehen, sind mit `<<` markiert. Grund: Ob und wie die Box feste IP-Reservierungen herausgibt, ist **unbekannt** („Ich weiß es nicht“) und die AVM-Doku war nicht erreichbar – statt zu raten, liefert die echte Box die Antwort.
- Router-Login zeigt zusätzlich **„Adressvergabe laut Router“** (Anzahl je `AddressSource`, z. B. DHCP/Static) – Hinweis, ob die Box feste Zuweisungen anders kennzeichnet.
### Hinweis
- Die Reservierungsliste der FRITZ!Box ist **noch nicht** im Reiter „Reservierungen“; sie folgt, sobald die Ausgabe von `--diagnose-router` an der echten Box zeigt, wo die Daten liegen. Die Annahme, dass die Beschreibungsdateien ohne Anmeldung lesbar sind, ist ungeprüft.

## [0.22.0] – 2026-11-08
### Hinzugefügt
- **FRITZ!Box-Zuweisungen im Reiter „Reservierungen“** (I-055 d): Geräte, die der Router mit Adressvergabe „Static“ meldet (bei Sascha 11 von 49), erscheinen in der Liste (Netz „FRITZ!Box (Static)“) und im Export. Hat der Windows-DHCP-Server dieselbe MAC, gilt dessen Eintrag.
### Hinweis
- Die FRITZ!Box bietet per TR-064 **keine** Reservierungsliste (Befund `--diagnose-router`). „Static“ als feste Zuweisung ist eine **Vermutung**: Bitte mit „Heimnetz → Netzwerk“ der Box abgleichen (Option „Diesem Netzwerkgerät immer die gleiche IPv4-Adresse zuweisen“).

## [0.22.1] – 2026-11-08
### Behoben
- **Reservierungsliste zeigte nur 2 statt 11 FRITZ!Box-Einträge** (vermutete Ursache, an der Box noch nicht bestätigt): Geräte mit Adressvergabe „Static“ wurden nur übernommen, wenn sie eine IP **und** eine MAC hatten und über die MAC im Scan geführt wurden (offline Geräte haben bei der Box oft keine IP). Jetzt zählt die komplette Router-Liste; Einträge ohne IP bleiben in der Liste.
- Router-Login meldet zusätzlich „Static ohne IP / ohne MAC“, damit man sieht, woran es liegt.

## [0.22.2] – 2026-11-08
### Entfernt
- **FRITZ!Box-Zeilen aus dem Reiter „Reservierungen“** (aus 0.22.0/0.22.1): Der Abgleich mit der echten Box (Sascha) zeigt, dass „Static“ im Router-Login **nicht** die festen Zuweisungen sind – es sind u. a. der Router selbst, VPN-Gegenstellen und Geräte ohne IP/MAC; Saschas fest zugewiesener PC fehlte dort. Die Annahme aus 0.22.0 war falsch.
### Hinweis
- Die FRITZ!Box gibt feste Zuweisungen per TR-064 nicht heraus (Befund `--diagnose-router`). Der Reiter zeigt wieder nur Windows-DHCP-Reservierungen und weist darauf hin. Die Zeile „Adressvergabe laut Router“ im Router-Login bleibt als Information. Einzige Alternative wäre das undokumentierte `data.lua` der Box-Oberfläche (fragil), derzeit nicht geplant.

## [0.22.3] – 2026-11-08
### Hinzugefügt
- **Diagnose der FRITZ!Box-Mesh-Liste** (I-055 c, Teil 1): `./dist/netzscanner --diagnose-mesh <FritzBox-IP>` ruft `X_AVM-DE_GetMeshListPath` ab und gibt das Mesh-Dokument **roh** aus (`internal/router/meshdump.go`). Zugangsdaten über `NETZSCANNER_ROUTER_USER`/`NETZSCANNER_ROUTER_PASS` oder Abfrage am Terminal (Passwort-Eingabe sichtbar); nichts wird gespeichert oder geloggt, die Session-ID im Pfad wird nicht ausgegeben. Nur lesend.
### Hinweis
- Das Dokumentformat der Box ist **unbekannt** („Ich weiß es nicht“). Der eigentliche Mesh-Parser (Teil 2) folgt, sobald die echte Ausgabe vorliegt.

## [0.23.0] – 2026-11-08
### Hinzugefügt
- **Mesh-Topologie der FRITZ!Box** (I-055 c, Teil 2): Der Router-Login liest zusätzlich die Mesh-Liste (`X_AVM-DE_GetMeshListPath`, JSON). Geräte werden dem Knoten zugeordnet, an dem sie laut Box hängen (Repeater/Box; Zuordnung über MAC, sonst IP; nicht gescannte Zwischenknoten werden übersprungen). Das ersetzt die Sternansicht; SNMP hat weiter Vorrang. Detail-Panel zeigt „Mesh-Verbindung“ (WLAN/LAN, Mbit/s, dBm). Code: `internal/router/mesh.go`, `internal/web/mesh.go`; Ergebnis nur im RAM.
### Hinweis
- Format und Annahme (node_1 = Vorgänger, Raten in kbit/s) stammen aus der Ausgabe von Saschas Box; andere Modelle sind **ungeprüft**. Fehlt die Mesh-Liste, erscheint ein Hinweis in den Router-Infos, der Login läuft trotzdem.

## [0.23.1] – 2026-11-08
### Geändert
- **Router-Login, Diagnose der Zuordnung:** Nach dem Login zeigt die Meldung Geräte mit **gleicher IP, aber anderer MAC** (Router / Scan, bis zu 8 Beispiele). Anlass: An Saschas Box wurde 0 von 49 Router-Geräten dem Scan zugeordnet, obwohl beide MACs haben; die Ursache ist noch unbekannt. Ohne Zuordnung greift auch die Mesh-Topologie (0.23.0) nicht.

## [0.23.2] – 2026-11-08
### Behoben
- **Router-Login während des Scans:** Beim Login lief der Scan noch, die Geräteliste hatte erst Teilergebnisse ohne MAC (ARP wird erst am Ende gelesen) → „0 Geräte zugeordnet“, keine Mesh-Zuordnung. Der Login wird jetzt abgelehnt, solange ein Scan läuft (klare Meldung). Ursache aus Saschas Diagnose (0.23.1) abgeleitet: Scan-MAC war bei den abweichenden Geräten leer.
- **Mesh-Zuordnung** wird bei jeder Ansicht aus den aktuellen Geräten berechnet (statt einmalig beim Login), passt also auch zu später gefundenen Geräten.

## [0.23.3] – 2026-11-08
### Geändert
- **Router-Login nennt den echten Grund:** Statt „nicht lesbar“/„nicht verfügbar“ zeigen die Hinweise jetzt HTTP-Status und UPnP-Fehlercode/-text der Box (z. B. „HTTP 500, UPnP 606 Action not authorized“) bzw. „Anmeldung abgelehnt“. Auch ein abgelehnter Mesh-Abruf wird gemeldet. Anlass: Bei Sascha wurden nach der Zuordnung (32/49 ok) Geräteinfo, WAN, WLAN und Mesh nicht gelesen; Ursache unbekannt (Vermutung, ungeprüft: Benutzer ohne Recht „FRITZ!Box Einstellungen“ oder Anmeldesperre nach mehreren Logins).

## [0.23.4] – 2026-11-08
### Behoben
- **Mesh-Zuordnung:** Ein Gerät mit alter/fremder IP im Mesh-Dokument (Nachbareintrag) konnte einem Repeater den Knoten wegnehmen – bei Sascha hingen dadurch drei Shelly-Stecker unter einem iPhone. Zuordnung jetzt in Stufen: MAC, dann eigene IP des Knotens (Merkmal `MANAGEMENT`), dann beliebige IP; jeder Knoten wird nur einmal vergeben. (Ursache aus den Screenshots abgeleitet, am echten Mesh-Dokument ungeprüft.)
- **Karte:** Linien von einem Uplink, der innerhalb einer Gruppe steht (Repeater unter „Clients“), laufen nicht mehr senkrecht durch andere Geräte/Gruppen, sondern gehen zuerst nach links aus der Gruppe heraus. Der Rand der Zeichnung wurde dafür um 30 Pixel erweitert. Das PDF nutzt noch die alte Führung.

## [0.23.5] – 2026-11-08
### Behoben
- **Topologie-PDF:** Linien von einem Uplink innerhalb einer Gruppe (Repeater unter „Clients“) laufen nicht mehr senkrecht durch fremde Geräte und Gruppen, sondern gehen zuerst nach links aus der Gruppe heraus – wie in der Web-Karte seit 0.23.4 (`levelMinX` in `internal/export/pdf.go`). Anlass: Saschas PDF, in dem die Linie vom Repeater durch die IoT-Gruppe lief.
### Hinweis
- Der Hinweis unter der PDF-Karte („Sternansicht … keine echte Verkabelung“) gilt bei Mesh-/SNMP-Daten nicht mehr uneingeschränkt; Text noch unverändert (offen).

## [0.23.6] – 2026-11-08
### Geändert
- **Topologie-PDF, Hinweis unter der Karte:** Der Text richtet sich nach der Datenquelle der Verbindungen (`topologyNote` in `internal/export/pdf.go`): Mesh-Liste der FRITZ!Box, SNMP, beides oder – ohne beides – wie bisher „Sternansicht“. Vorher stand auch bei Mesh-/SNMP-Daten „keine echte Verkabelung“.

## [0.23.7] – 2026-11-08
### Hinzugefügt
- **Hinweis bei gleicher MAC:** Haben mehrere Geräte dieselbe MAC-Adresse, markiert der Scanner sie mit ⚠ (Tabelle, Detail-Panel „MAC mehrfach“) und nennt die anderen IPs; der Hinweis lautet, im Router gegenzuprüfen. Hintergrund: Ein Router beantwortet ARP manchmal auch für fremde Adressen (Proxy-ARP, z. B. VPN-Clients), oder ein Gerät hat mehrere Adressen – das lässt sich aus dem Scan nicht unterscheiden. Es wird **nichts ausgeblendet** (`MarkSharedMAC` in `internal/scan/gateway.go`, Feld `Host.SameMAC`, wird bei jeder Ansicht berechnet). Allgemeine Regel ohne Geräte-/Adresstabelle. Hilfe ergänzt.
### Hinweis
- Eine zuvor erwogene automatische Ausblendung solcher Einträge wurde verworfen (Entscheidung Sascha: lieber Hinweis).

## [0.24.0] – 2026-11-09
### Hinzugefügt
- **Zugriffsschutz mit Zugangstoken** (I-025): Bei `--listen` außerhalb von Loopback (z. B. `0.0.0.0:8484`) erzeugt der Scanner beim Start ein Zufallstoken (128 Bit) und zeigt es **einmalig** in der Konsole an. Ohne Token liefert der Server weder Oberfläche noch API (401, Eingabeseite). Anmeldung im Browser über `/?token=…` (Cookie `HttpOnly`/`SameSite=Strict`, das Token verschwindet danach aus der Adresse); für Skripte `Authorization: Bearer <Token>`.
- Neue Optionen: `--token` (eigenes Token, mind. 8 Zeichen; alternativ Umgebung `NETZSCANNER_TOKEN`, das ist in der Prozessliste unsichtbar), `--no-token` (Schutz bei offenem `--listen` bewusst abschalten, mit Warnung).
- Reiner Loopback-Betrieb (Standard) bleibt ohne Token wie bisher.
### Hinweis
- Die Verbindung bleibt unverschlüsselt (HTTP): Wer im selben Netz mitliest, sieht das Token. Das Token schützt vor zufälligem Zugriff, ersetzt aber kein TLS (nicht umgesetzt).

## [0.25.0] – 2026-11-09
### Hinzugefügt
- **Befundliste** (I-064): Neuer Reiter „Befunde“ mit Auffälligkeiten aus den vorhandenen Scan-Daten, **ohne zusätzlichen Netzverkehr**: Telnet, FTP, RDP, VNC, SMB/NetBIOS, WinRM (HTTP), MQTT (unverschlüsselt), rpcbind, Datenbank-/Cache-Ports (MySQL, PostgreSQL, SQL Server, Oracle, MongoDB, Redis, Elasticsearch), abgelaufene bzw. in unter 30 Tagen ablaufende Zertifikate, Weboberfläche nur per HTTP und „MAC mehrfach“. Schweregrade Hoch/Mittel/Niedrig/Info, sortiert nach Schwere.
- Export der Befunde als CSV (Excel Deutsch oder Standard) und Markdown, mit CSV-Injection-Schutz. Neue API: `GET /api/findings`, `POST /api/findings/export`. Neues Paket `internal/findings` mit Tests; Hilfe-Seite ergänzt.
### Hinweis
- Die Regeln gelten allgemein nach Port/Zertifikat, nicht nach Gerät oder Hersteller. Befunde sind **Hinweise zum Gegenprüfen**, keine bewiesenen Schwachstellen. Aufnahme ins PDF folgt mit I-036.

## [0.25.1] – 2026-11-09
### Geändert
- **Gleiche MAC in allen Exporten** (I-065): Das ⚠ „MAC mehrfach“ steht jetzt auch in PDF-Geräteliste, CSV, Markdown und HTML (neue Spalte „Hinweis“ mit den anderen IPs).
- Ein Eintrag, der die MAC eines erkannten Routers/Switches teilt (`Host.MirrorOf`, z. B. Proxy-ARP-Scheineintrag), erbt dessen Hersteller/System nicht mehr und zählt **nicht** als eigenes „Netzwerkgerät“; die Kategorie wird neu vermutet (Nutzerwahl bleibt). Es wird weiterhin **nichts ausgeblendet**.
### Hinweis
- Allgemeine Regel nach Rolle und MAC, keine Geräte- oder Adresstabelle. CSV hat eine zusätzliche letzte Spalte.

## [0.25.2] – 2026-11-09
### Geändert
- **Mesh-Zuordnung abgesichert** (I-067): Die lose Zuordnung über beliebige IPs im Mesh-Dokument (z. B. alte Nachbar-Einträge) darf einen Knoten, der anderen Geräten als Uplink dient (Box, Repeater, Switch), nur noch an ein **Netzwerkgerät** vergeben. Damit hängt eine Gruppe nicht mehr unter einem Smartphone, das nur als Nachbar-Eintrag auftaucht. Netzwerkgeräte werden in jeder Stufe zuerst zugeordnet.
### Hinweis
- Allgemeine Regel nach Kategorie und Verbindungsstruktur, keine Geräte- oder Adresstabelle. Ursache am echten Netz **ungeprüft** („Ich weiß es nicht“): Bitte `--diagnose-mesh <IP>` und PDF erneut prüfen.

## [0.25.3] – 2026-11-09
### Geändert
- **Kennungs-Namen besser abwerten** (I-066): `looksLikeIdentifier` erkennt jetzt auch Namen mit führendem Vorzeichen, mit `_` als Trenner und Hex-/Ziffernfolgen beliebiger Länge (ab 8 Zeichen, mindestens eine Ziffer). Reine Wörter (z. B. „decade“) und kurze Namen bleiben erhalten. Gilt für alle Namensquellen (DNS, mDNS, SSDP …).

## [0.25.4] – 2026-11-09
### Behoben
- **Router-Info: Status „Connecting“** (I-068): Die FRITZ!Box-Abfrage liest jetzt beide WAN-Dienste (IP und PPP) und nimmt den mit Status „Connected“. Vorher wurde nur der erste antwortende Dienst gelesen; meldete dieser „Connecting“, obwohl die Verbindung über den anderen lief, stand das im Export. Gibt es keinen verbundenen Dienst, bleibt der echte Status des ersten stehen. Test für drei Fälle ergänzt.
- **PDF:** „Geräte“/„Geräteliste“ mit Umlaut in Kopfzeilen (die Standardschrift kann ä).
### Hinweis
- Die Ursache an der echten Box ist **ungeprüft** („Ich weiß es nicht“); die Korrektur folgt der plausibelsten Erklärung. Die einzeln auf eine weitere Seite überlaufende PDF-Zeile konnte ich nicht nachvollziehen: Die Seitenumbruch-Prüfung der Geräteliste rechnet Zeilenhöhe gegen den Seitenrand korrekt; bitte ein PDF mit betroffener Zeile schicken.

## [0.26.0] – 2026-11-09
### Hinzugefügt
- **Kategorie „Mobilgeräte“** (I-059): Smartphones und Tablets haben eine eigene Kategorie (Farbe lila in Karte, Legende, Auswahlliste und PDF; erscheint in allen Exporten über den Kategorienamen).
- Erkennung aus allgemeinen Regeln, ohne Geräte-Tabellen: OS-Vermutung iOS/iPadOS (Port 62078) oder Android; zusätzlich eine **schwache** Vermutung „WLAN laut Router + zufällige (lokal administrierte) MAC + kein Hersteller + keine offenen Ports“. Die Nutzerwahl überschreibt wie bei den anderen Kategorien.
### Hinweis
- Wie zuverlässig die schwache Regel ist, ist **ungeprüft** („Ich weiß es nicht“): Laptops mit zufälliger MAC können ebenfalls getroffen werden, Android ohne offene Ports wird ohne Router-Login nicht erkannt.

## [0.27.0] – 2026-11-09
### Hinzugefügt
- **Lizenz: GNU AGPL v3 oder später** (I-069, Entscheidung Sascha): Datei `LICENSE` mit dem vollständigen Lizenztext (SPDX `AGPL-3.0-or-later`).
- **Fremdlizenzen:** `scripts/third-party-licenses.sh` erzeugt `internal/licenses/THIRD_PARTY_LICENSES.txt` mit den Lizenztexten aller einkompilierten Bibliotheken und der Go-Standardbibliothek (MIT, BSD, Apache-2.0, MPL-2.0). Die Datei ist ins Programm eingebettet; `scripts/build.sh` legt sie zusammen mit `LICENSE` nach `dist/`.
- **`--licenses`:** gibt Lizenzhinweis und alle Fremdlizenzen aus.
- **Oberfläche:** Hilfe-Abschnitt „Lizenz“ und Link „Quellcode · AGPL“ neben der Versionsanzeige (AGPL Abschnitt 13: Nutzer im Netz bekommen den Quellcode angeboten). README mit Lizenz-Abschnitt.
- Test prüft, dass jede direkte Abhängigkeit aus `go.mod` in der Fremdlizenz-Datei steht.
### Hinweis
- Die Nutzungsbedingungen der IEEE für die eingebettete OUI-Liste sind **ungeprüft** („Ich weiß es nicht“).
- Keine Rechtsberatung; der deutsche Kurzhinweis ist eine Zusammenfassung, rechtlich gilt der englische Text in `LICENSE`.

## [0.28.0] – 2026-11-09
### Hinzugefügt
- **SNMP v3** (I-053) für die Switch-Abfrage: Auswahl „SNMP v2c / v3“ im Topologie-Reiter. v3 mit Benutzer und wahlweise Authentifizierung (SHA, SHA224/256/384/512, MD5) und Verschlüsselung (AES, AES192, AES256, DES); Stufen noAuthNoPriv, authNoPriv, authPriv. Verschlüsselung setzt Authentifizierung voraus, Passphrasen mindestens 8 Zeichen (Prüfung vor dem Senden).
- Zugangsdaten (Community, Benutzer, Passphrasen) nur im Anfragekörper, nie gespeichert, protokolliert oder zurückgegeben; die Felder werden nach dem Senden geleert.
### Hinweis
- Nur mit Unit-Tests geprüft (Validierung, Aufbau des gosnmp-Clients); **an einem echten Switch mit v3 ungetestet** („Ich weiß es nicht“, ob alle Hersteller-Kombinationen funktionieren).

## [0.29.0] – 2026-11-09
### Hinzugefügt
- **Scan speichern und laden** (I-035): Knöpfe „Scan speichern“ und „Scan laden“ in der Übersicht. Die Projektdatei (JSON, Download/Upload im Browser) enthält Geräteliste, Ziel, Zeitpunkt, Programmversion und die Eingaben (Name, Benutzer, Standort, Kategorie, eigene Kategorien). **Nicht** enthalten: Zugangsdaten, Router-/Mesh-/DHCP-/SNMP-Daten (nur im RAM; nach dem Laden bei Bedarf neu abfragen).
- Beim Laden wird die Datei wie fremde Eingabe geprüft (Format/Version, max. 16 MiB und 5000 Geräte, gültige IPs ohne Doppelte, Steuerzeichen entfernt, Texte gekürzt, unbekannte Kategorien → Client, Web-Links aus IP/Ports neu berechnet). Eingaben aus der Datei werden zu den vorhandenen hinzugefügt. Gespeichert werden kann nur, wenn kein Scan läuft.
### Hinweis
- Grundlage für I-034 (Scan-Vergleich) und I-036 (Netzdokumentation). Nur mit Unit-Tests geprüft, Bedienung im Browser noch nicht von Sascha getestet.

## [0.30.0] – 2026-11-09
### Hinzugefügt
- **Scan-Vergleich** (I-034): Knopf „Scan vergleichen“ – eine gespeicherte Scan-Datei (I-035) wird mit dem aktuellen Scan verglichen. Ergebnis: **neu**, **nicht mehr gefunden**, **geändert** (IP, Name, Hersteller, System, Kategorie, Ports neu/weg) und Anzahl unverändert. API `POST /api/project/compare`.
- Zuordnung allgemein: gleiche (eindeutige) MAC = dasselbe Gerät, auch bei neuer IP; sonst gleiche IP, außer die MACs unterscheiden sich (dann anderes Gerät). Doppelte MACs (Scheineinträge) werden nicht zur Zuordnung benutzt.
- Nur lesend: weder aktueller Scan noch Datei werden verändert; die Datei wird wie beim Laden geprüft und bereinigt.
### Grenzen
- Nur im Browser-Ergebnis, kein Export des Vergleichs. Nur mit Unit-Tests/Demo-Daten geprüft, nicht an zwei echten Scans im LAN.

## [0.31.0] – 2026-11-09
### Hinzugefügt
- **Netzdokumentation als ein PDF** (I-036): Knopf „Netzdokumentation (PDF)“ im Reiter Topologie. Inhalt: Deckblatt (Kunde, Netz/Standort, Bearbeiter frei eintragbar, Ziel, Datum, Programmversion) mit Zusammenfassung in Zahlen, Befundtabelle (I-064), Topologie-Karte und Geräteliste (wie bisher). Die Deckblatt-Angaben werden nicht gespeichert; Steuerzeichen werden entfernt, Texte auf 120 Zeichen gekürzt.
- Nutzt nur vorhandene Scan-Daten (kein zusätzlicher Netzverkehr), keine Zugangsdaten in der Datei. Der bisherige Knopf „Topologie als PDF“ bleibt unverändert.
### Grenzen
- Netz-Grunddaten (I-060) fehlen noch, sie kommen in die PDF, sobald es sie gibt. Nur mit Unit-Test geprüft, Aussehen im PDF-Betrachter noch nicht von Sascha gesehen.

## [0.32.0] – 2026-11-09
### Hinzugefügt
- **Netz-Grunddaten des Scan-Rechners** (I-060): eigene IP/Netzmaske, Standard-Gateway, DNS-Server und Suchdomäne. Anzeige unter dem Ziel-Feld im Reiter Übersicht (`GET /api/netinfo`), im Deckblatt der Netzdokumentation-PDF sowie im Kopf von Markdown- und HTML-Export.
- Nur lesend (Schnittstellen, `/etc/resolv.conf` bzw. `/run/systemd/resolve/resolv.conf`, unter Windows PowerShell), kein Netzverkehr, keine Rechte nötig. Nicht ermittelbare Angaben bleiben leer; Loopback-Stubs (z. B. 127.0.0.53) gelten nicht als DNS-Server.
### Grenzen
- Die Prüfung auf mehrere DHCP-Server ist als I-070 ausgelagert (offen). Unter Windows und macOS nur nach Dokumentation umgesetzt, nicht getestet; Linux nur mit Unit-Tests.

## [0.33.0] – 2026-11-09
### Hinzugefügt
- **AD-Domäne und Domänencontroller ohne Login erkennen** (I-061): Ist Port 389 (LDAP) offen, liest der Scan den `rootDSE` anonym aus (`internal/scan/ldap.go`, eigener minimaler BER-Leser, keine neue Bibliothek). Das Detail-Panel zeigt beim Port 389 z. B. „LDAP: Domäne corp.example.com · Server dc1.corp.example.com · Funktionsebene 2016“. Nur eine lesende Suchanfrage, kein Bind, keine Zugangsdaten, nichts wird geschrieben.
- Bei Nicht-AD-LDAP-Servern wird, falls vorhanden, der erste Namenskontext als „Basis …“ gezeigt. Antworten werden auf 64 KB begrenzt, Texte bereinigt.
### Grenzen
- **Ungeprüft:** Ob ein echter Domänencontroller den anonymen Abruf erlaubt (manche Server oder Richtlinien verweigern ihn) – dann bleibt nur die Port-Anzeige „ldap“. Nur mit Unit-Tests (Beispielantwort, kaputte Daten) geprüft, noch nicht an einem echten DC. LDAPS (636) wird nicht abgefragt.

## [0.34.0] – 2026-11-09
### Hinzugefügt
- **Mehrere DHCP-Server erkennen** (I-070): Neuer Knopf „DHCP-Server prüfen“ im Reiter „DHCP & Router“. Der Scanner sendet **ein** DHCPDISCOVER per Broadcast (zufällige, lokal verwaltete MAC) und sammelt ca. 4 Sekunden lang die Angebote (`internal/scan/dhcpprobe.go`, `POST /api/dhcp-probe`). Pro Server werden Kennung, angebotene Adresse, Maske, Gateway, DNS, Domäne und Lease angezeigt; antworten mehrere, erscheint ein Warnhinweis (fremder „Rogue“-Server oder gewollte Redundanz).
- Es wird nie ein DHCPREQUEST gesendet, also keine Adresse angenommen; es wird nichts im Router/DHCP verändert.
### Grenzen
- **Fallback:** Braucht UDP-Port 68. Ohne Rechte oder bei belegtem Port (laufender DHCP-Client) meldet die Prüfung „nicht prüfbar“ mit Grund.
- Geprüft wird nur das Netz der vom System gewählten Schnittstelle (keine weiteren VLANs). Manche Server halten ihr Angebot kurz vor (Annahme, serverabhängig). **Ungeprüft im echten LAN**; nur Unit-Tests (Paketaufbau, Parser, Auswertung). Server, die Broadcast-Antworten filtern, bleiben unsichtbar.

## [0.35.0] – 2026-11-09
### Hinzugefügt
- **Zugangsdaten je Gerät** (I-020): Im Detail-Panel eines Geräts können Benutzer und Passwort hinterlegt werden (`internal/web/creds.go`, `GET/POST /api/creds`, `POST /api/creds/delete`). Sie dienen später den Login-Tests (I-022); in dieser Version wird noch **nichts** damit angemeldet.
- **Sicherheit:** Nur im Arbeitsspeicher (nie in Eingaben-Datei, Projektdatei, Exporten oder Logs). Eingabe nur vom eigenen Rechner (Loopback). Die API gibt nie ein Passwort zurück, nur „gemerkt“, Benutzer und Restzeit. Das Passwortfeld wird nach dem Absenden geleert.
- **Vergessen:** automatisch nach 15 Minuten ohne Nutzung, per Knopf „Zugang vergessen“, bei „Eingaben löschen“ und beim Laden eines Projekts; beim Beenden verschwindet der RAM ohnehin. Das Passwort wird beim Löschen mit Nullen überschrieben (Best Effort).
### Grenzen
- Bei `--listen` außerhalb von Loopback ist die Eingabe gesperrt (HTTP unverschlüsselt). Go kann Kopien im Speicher nicht vollständig ausschließen. Browser-Passwortmanager können das Feld anbieten (`autocomplete="new-password"` gesetzt). Ungeprüft im Browser; nur Unit-Tests für den Speicher.

## [0.36.0] – 2026-11-10
### Hinzugefügt
- **Login-Test je Gerät** (I-022): Mit dem gemerkten Zugang (I-020) prüft ein Knopf im Detail-Panel, ob die Anmeldung per **SSH** (Passwort bzw. Tastatur-interaktiv) oder **Web** (HTTP-Basic) klappt. Ergebnis „ok / abgelehnt / nicht testbar“ steht samt Meldung im Detail-Panel (`internal/logintest`, `internal/web/logintest.go`, `POST /api/logintest`). Es wird nichts am Gerät verändert: SSH öffnet keine Sitzung, Web sendet nur ein GET auf `/`.
- **Sicherheit:** Pro Klick höchstens **ein** Passwort-Versuch (Schutz vor Konto-Sperren; parallele Tests je Gerät werden abgewiesen). SSH-Hostkey und Web-Zertifikat werden **nicht ignoriert**: Beim ersten Klick wird nur der Fingerabdruck geholt (es geht **kein** Passwort raus), der Nutzer bestätigt ihn, erst dann folgt der eine Versuch – bei abweichendem Fingerabdruck Abbruch. Web sendet Zugangsdaten nur, wenn das Gerät selbst 401 + „Basic“ verlangt; Weiterleitungen werden nicht verfolgt. Unverschlüsseltes HTTP nur nach ausdrücklicher Bestätigung. Nur vom eigenen Rechner (Loopback), nur für Geräte und als offen gefundene Ports aus der Scan-Liste. Ergebnisse liegen nur im RAM, ohne Passwort, und verschwinden mit dem Zugang (Vergessen, Timeout, neuer Zugang).
### Geändert
- `golang.org/x/crypto` ist jetzt direkte Abhängigkeit (SSH); Fremdlizenzen neu erzeugt.
### Grenzen
- Nicht enthalten: SNMPv3 (braucht eigene Auth-/Priv-Angaben, hat sein eigenes Formular), LDAP/WinRM/SMB, Formular-Logins und Digest-Auth bei Web. SSH-Schlüssel-Anmeldung entfällt. Es gibt keine bekannten-Hosts-Datei: Der Fingerabdruck muss bei jedem Test neu bestätigt werden. **Nur gegen lokale Test-Server geprüft, nicht an echten Geräten im LAN.**

## [0.37.0] – 2026-11-10
### Hinzugefügt
- **System-Infos per SSH lesen** (I-023, erster Schnitt): Neuer Knopf „SSH-Login testen + System-Infos lesen“ im Detail-Panel. Nach erfolgreicher Anmeldung läuft über **dieselbe Verbindung** (kein zweiter Passwort-Versuch) genau **ein fest eingebauter, nur lesender Befehl** (`uname -srm`, `hostname`, `/etc/os-release`). Angezeigt werden Kernel, Hostname, System und Version. Es gibt keine frei eingebbaren Befehle.
- **Sicherheit:** Hostkey-Bestätigung wie beim Login-Test (ohne bestätigten Fingerabdruck geht kein Passwort raus). Ausgabe auf 16 KiB begrenzt, 10 s Frist, Werte von Steuerzeichen befreit und gekürzt. Ergebnis nur im RAM am Zugang, nicht in Exporten.
### Grenzen
- Geräte ohne Unix-Shell (viele Router/Switches) liefern keine Infos; der Login gilt trotzdem als „ok“ mit entsprechendem Hinweis. Nur SSH; Web-/SNMP-/Domänen-Infos sowie Schnittstellen und Firmware sind noch offen (Rest von I-023).

## [0.37.1] – 2026-11-10
### Hinzugefügt
- **`scripts/start.sh`** (I-071): Ein Aufruf macht `git pull --ff-only`, `scripts/build.sh native` und startet `dist/netzscanner`. Optionen (z. B. `--listen`, `--token`) werden an das Programm durchgereicht. Bricht beim ersten Fehler ab, damit keine alte Version startet.
### Grenzen
- Nur bash (Linux/macOS, unter Windows Git-Bash/WSL). Nur lokal getestet (Syntaxprüfung), nicht im echten Ablauf mit `git pull`.

## [0.37.2] – 2026-11-10
### Behoben
- **Netzdokumentation-PDF, Deckblatt:** Lange Bezeichnungen (z. B. „Scan-Rechner (IP / Netzmaske)“) überlappten mit dem Wert. Die Bezeichnungsspalte richtet sich jetzt nach der längsten Bezeichnung (mindestens 50 mm, höchstens die halbe Seitenbreite; zu lange Texte werden gekürzt).

## [0.38.0] – 2026-11-10
### Hinzugefügt
- **System-Infos erweitert** (I-023 Rest, Teil 2): Der feste, nur lesende SSH-Befehl liest zusätzlich Modell (DMI bzw. Device-Tree), BIOS-/Firmware-Version, Firmware-Beschreibung bei Router-Linux (`/etc/openwrt_release`), Laufzeit und die **Schnittstellen** (Zustand, MAC, IPv4-Adressen; Loopback entfällt, höchstens 32). Weiterhin über dieselbe Verbindung, ohne zweiten Passwort-Versuch, nur im RAM.
### Grenzen
- Nur Geräte mit Linux-Shell und `ip`/`/sys`/`/proc`; Router/Switches ohne Shell liefern weiter nichts. Web-/SNMP-/Domänen-Infos bleiben offen.

## [0.39.0] – 2026-11-10
### Hinzugefügt
- **System-Infos per SNMP** (I-023 Rest, Teil 3): Beim „Lesen“ im SNMP-Formular (v2c oder v3) holt der Scanner zusätzlich Standort, Laufzeit, Modell/Firmware/Software (ENTITY-MIB, falls vorhanden) und die **Schnittstellen** (Zustand, MAC, Geschwindigkeit; Loopback entfällt, höchstens 32). Anzeige im Detail-Panel; nur im RAM, kein zusätzlicher Knopf und kein zusätzlicher Zugang nötig.
- Ausschließlich lesende Abfragen standardisierter OIDs (kein SET). Bewusst nicht gelesen: `sysContact` (kann Personendaten enthalten) und Seriennummern. Fehlende Werte lassen nur die Zeile weg, die Topologie-Abfrage scheitert deshalb nicht.
### Grenzen
- Welcher Eintrag der ENTITY-MIB als „Modell“ gilt, entscheidet nur der kleinste Index mit Inhalt – bei manchen Geräten ist das nicht das Hauptgerät (unbestätigt, im LAN prüfen). Web- und Domänen-Infos bleiben offen.

## [0.40.0] – 2026-11-10
### Hinzugefügt
- **Drucker-Details per IPP** (I-062): Hat ein Gerät Port 631 offen, sendet der Scan eine einzige lesende IPP-Anfrage (`Get-Printer-Attributes`, ohne Login). Ergebnis (Modell, Firmware, UUID, Status, Meldungen, Füllstände) erscheint als Banner-Zeile „IPP: …“ im Detail-Panel. Standard-IPP, keine Einzelgeräte-Tabellen.
### Grenzen
- Welche Attribute ein Drucker liefert, ist modellabhängig (ungeprüft im echten LAN): Fehlendes wird weggelassen, bei Fehler/Timeout bleibt der normale Banner. Nur unverschlüsseltes IPP (Port 631); keine Seriennummer; Füllstand-Sonderwerte (unbekannt, genug vorhanden) erscheinen als „?“.

## [0.41.0] – 2026-11-10
### Hinzugefügt
- **SNMPv3-Login-Test** (I-022, Rest): Im Detail-Panel unter dem gemerkten Zugang neuer Knopf „SNMPv3-Login testen (UDP 161)“. Benutzer und Passwort des gemerkten Zugangs gelten als v3-Benutzer und Authentifizierungs-Passphrase; Auth-/Verschlüsselungs-Protokoll wählt man im Formular, die Verschlüsselungs-Passphrase wird nur für diesen Klick gesendet und nicht gespeichert. Genau **eine** lesende Anfrage (sysDescr, ohne Wiederholung, kein SET) pro Klick; Ergebnis „ok / abgelehnt / nicht testbar“ wie bei SSH und Web, nur im RAM, nur über Loopback. Das Gerät muss in der Scan-Liste stehen (UDP 161 sieht der TCP-Scan nicht).
### Grenzen
- Viele Geräte schweigen bei falschem v3-Benutzer oder falscher Passphrase. Ein Timeout wird daher als „nicht testbar“ gemeldet, nicht als „abgelehnt“. Die Abgrenzung „abgelehnt“ vs. „keine Antwort“ ist **ungeprüft an echten Geräten**.

## [0.42.0] – 2026-11-10
### Hinzugefügt
- **WinRM-Login-Test** (I-022, Rest): Hat ein Gerät Port 5985 offen, erscheint im Detail-Panel der Knopf „WinRM-Login testen (Port 5985)“. Pro Klick genau ein Versuch (NTLM, Nachrichten verschlüsselt) mit dem gemerkten Zugang; danach ein fester, rein lesender Befehl (`hostname`), der Computername wird als Info angezeigt. Domänenkonten als `DOMÄNE\benutzer` oder `benutzer@domäne`. Ergebnis „ok“/„abgelehnt“ (HTTP 401)/„nicht testbar“ steht wie bei den anderen Tests in der Liste; das Passwort erscheint nie in Meldungen und wird nicht gespeichert.
### Grenzen
- Nur WinRM über HTTP (5985, NTLM-verschlüsselt); HTTPS (5986) und Kerberos fehlen. LDAP und SMB sind weiter offen (brauchen neue Bibliotheken). Gegen einen echten Windows-Rechner ungeprüft – nur Fehlerauswertung und „Port zu“ sind per Test abgedeckt.

## [0.43.0] – 2026-11-10
### Geändert
- **WinRM-Login-Test liest jetzt Domänen-/Systeminfos** (I-023, Teil „Domäne“): Statt nur `hostname` läuft nach der Anmeldung ein einziger, fest einprogrammierter, rein lesender PowerShell-Befehl (CIM: Computername, Domäne bzw. Arbeitsgruppe, Hersteller/Modell, Windows-Version, Laufzeit). Die Felder erscheinen im Detail-Panel wie bei SSH/SNMP, nur im RAM. Es wird nichts geschrieben und nichts aus Eingaben in den Befehl eingesetzt.
### Grenzen
- Gegen einen echten Windows-Rechner ungeprüft (nur Parser-Tests). Ist PowerShell/CIM nicht nutzbar, bleibt der Login „ok“ mit dem Hinweis „keine System-Infos lesbar“. Web-Infos nach Login bleiben offen.

## [0.44.0] – 2026-11-10
### Geändert
- **Eigene Kategorie „Drucker/Scanner“** (I-072): Drucker/Scanner sind nicht mehr unter „IoT“. Erkennung (Vermutung): Port 631/9100/515, IPP-Antwort („IPP: …“ aus I-062) oder Druckerhersteller laut MAC. „IoT“ bleibt für Smart-Home, Kameras (Port 554) und Sensoren. Neue Farbe in Karte, Legende, Detail-Auswahl, Tabelle, Exporten und PDF.
### Grenzen
- Alte Projektdateien laden weiter; Drucker darin behalten ihre gespeicherte Kategorie „IoT“, bis neu gescannt oder die Kategorie im Detail-Panel geändert wird (ungeprüft, ob beim Laden neu eingeordnet wird). mDNS-/SSDP-Diensttypen (`_ipp._tcp` …) werden noch nicht ausgewertet, weil sie nicht am Gerät gespeichert werden.
