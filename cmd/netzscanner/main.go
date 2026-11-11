// NetzScanner - Einstiegspunkt: startet den eingebauten Webserver mit der Oberflaeche.
package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/berion1982/netzscanner/internal/licenses"
	"github.com/berion1982/netzscanner/internal/router"
	"github.com/berion1982/netzscanner/internal/scan"
	"github.com/berion1982/netzscanner/internal/version"
	"github.com/berion1982/netzscanner/internal/web"
)

func main() {
	showVersion := flag.Bool("version", false, "Version und Builddatum anzeigen")
	// Lizenzhinweis (AGPL-3.0-or-later) und Lizenztexte der Fremdbibliotheken ausgeben
	showLicenses := flag.Bool("licenses", false, "Lizenz des NetzScanners (AGPL v3) und der Fremdbibliotheken anzeigen")
	// Standard: nur lokal erreichbar (Sicherheit). Fuer Raspberry/headless
	// bewusst oeffnen mit --listen 0.0.0.0:8484
	listen := flag.String("listen", "127.0.0.1:8484", "Adresse:Port des Webservers")
	demo := flag.Bool("demo", false, "Demo-Daten anzeigen (zum Ansehen der Oberflaeche)")
	allowPublic := flag.Bool("allow-public", false, "Scans oeffentlicher IP-Adressen erlauben (nur mit Erlaubnis!)")
	diagnoseRouter := flag.String("diagnose-router", "", "FRITZ!Box (IP): zeigt, welche TR-064-Dienste/Aktionen sie anbietet (ohne Zugangsdaten, nur lesend)")
	diagnoseMesh := flag.String("diagnose-mesh", "", "FRITZ!Box (IP): gibt die Mesh-Liste roh aus (Zugangsdaten per Umgebung NETZSCANNER_ROUTER_USER/_PASS oder Abfrage; nur lesend)")
	diagnose := flag.String("diagnose", "", "ein Geraet (IP) Schritt fuer Schritt pruefen und Ergebnis ausgeben (Fehlersuche)")
	dataFile := flag.String("data", web.DefaultStorePath(), "Datei fuer zwischengespeicherte Eingaben (Namen, Benutzernamen, Standorte, Kategorien)")
	noSave := flag.Bool("no-save", false, "Eingaben nicht auf die Platte speichern (nur im Arbeitsspeicher)")
	token := flag.String("token", "", "Zugangstoken fuer die Oberflaeche (mind. 8 Zeichen; auch per Umgebung NETZSCANNER_TOKEN). Ohne Angabe wird bei --listen ausserhalb von Loopback automatisch eines erzeugt")
	noToken := flag.Bool("no-token", false, "Zugangstoken auch bei --listen ausserhalb von Loopback abschalten (NICHT empfohlen: jeder im Netz sieht alle Daten)")
	// Browser automatisch oeffnen (I-083)
	noBrowser := flag.Bool("no-browser", false, "Den Browser nach dem Start nicht automatisch oeffnen (bei --listen ausserhalb von Loopback passiert das nie)")
	// Kommandozeilen-Modus ohne Browser (I-047)
	scanTarget := flag.String("scan", "", "Kommandozeilen-Modus: Ziel scannen (z. B. 192.168.1.0/24), Ergebnis nach --out schreiben, kein Webserver")
	scanOut := flag.String("out", "", "mit --scan: Ausgabedatei (.csv, .md, .html, .pdf); leer oder - = CSV nach stdout")
	scanFormat := flag.String("format", "", "mit --scan: csv, csv-excel, md, html oder pdf (Standard: aus der Dateiendung)")
	scanPorts := flag.String("ports", "", "mit --scan: Portliste wie in der Oberflaeche (leer = Standardports)")
	flag.Parse()
	if *noSave || *demo { // Demo-Daten sind erfunden: nie speichern

		*dataFile = ""
	}

	if *showVersion {
		fmt.Println(version.String())
		return
	}
	if *showLicenses {
		// Nur ausgeben und beenden; startet keinen Server und scannt nichts.
		fmt.Println(licenses.Full())
		return
	}

	if *diagnoseRouter != "" {
		router.Describe(context.Background(), *diagnoseRouter, os.Stdout)
		return
	}
	if *diagnoseMesh != "" {
		runMeshDump(*diagnoseMesh)
		return
	}
	if *diagnose != "" {
		scan.Diagnose(context.Background(), *diagnose, os.Stdout)
		return
	}

	if *scanTarget != "" {
		// Meldungen nach stderr, Daten ggf. nach stdout; Strg+C bricht den Scan sauber ab.
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer stop()
		err := runCLIScan(ctx, cliOptions{Target: *scanTarget, Ports: *scanPorts, Out: *scanOut, Format: *scanFormat, AllowPublic: *allowPublic}, os.Stdout, os.Stderr)
		if err != nil {
			fmt.Fprintln(os.Stderr, "Fehler:", err)
			os.Exit(1)
		}
		return
	}

	fmt.Println(version.String())
	if *dataFile != "" && !*demo {
		fmt.Println("Eingaben werden gespeichert in:", *dataFile, "(abschaltbar mit --no-save)")
	}
	tok := resolveToken(*token, *noToken, *listen)
	fmt.Printf("Oberflaeche: http://%s  (Strg+C beendet)\n", *listen)
	if tok != "" {
		// Einmalige Anzeige des Tokens (I-025): wird nirgends sonst ausgegeben oder gespeichert.
		fmt.Printf("Zugangstoken: %s\nBrowser-Link:  http://<Adresse-dieses-Rechners>:%s/?token=%s\n", tok, listenPort(*listen), tok)
	}
	// Erst lauschen, dann den Browser starten: so ist der Server beim Aufruf schon erreichbar.
	ln, err := net.Listen("tcp", *listen)
	if err != nil {
		log.Fatal(err)
	}
	if shouldOpenBrowser(*noBrowser, *listen) {
		if err := openBrowser("http://" + *listen); err != nil {
			// Kein Abbruch: die Adresse steht oben in der Konsole.
			fmt.Println("Hinweis:", err)
		}
	}
	log.Fatal(http.Serve(ln, web.NewHandler(web.Options{Demo: *demo, AllowPublic: *allowPublic, DataFile: *dataFile, Token: tok})))
}

// runMeshDump holt Zugangsdaten (Umgebung oder Abfrage am Terminal) und gibt die Mesh-Liste roh aus.
// Das Passwort wird nie gespeichert oder geloggt. Bei Abfrage am Terminal ist die Eingabe sichtbar.
func runMeshDump(host string) {
	user, pass := os.Getenv("NETZSCANNER_ROUTER_USER"), os.Getenv("NETZSCANNER_ROUTER_PASS")
	in := bufio.NewReader(os.Stdin)
	if user == "" {
		fmt.Fprint(os.Stderr, "FRITZ!Box-Benutzer: ")
		user, _ = in.ReadString('\n')
	}
	if pass == "" {
		fmt.Fprint(os.Stderr, "Passwort (Eingabe sichtbar): ")
		pass, _ = in.ReadString('\n')
	}
	user, pass = strings.TrimSpace(user), strings.TrimSpace(pass)
	if err := router.DumpMesh(context.Background(), host, user, pass, os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "Fehler:", err)
		os.Exit(1)
	}
}

// resolveToken bestimmt das Zugangstoken (I-025):
//  1. --token oder Umgebung NETZSCANNER_TOKEN (mind. web.MinTokenLen Zeichen),
//  2. sonst bei --listen ausserhalb von Loopback ein Zufallstoken,
//  3. sonst (nur lokal) keines. --no-token schaltet es bei offenem Listen ab.
//
// Ein zu kurzes Token oder ein Fehler beim Zufall beendet das Programm.
func resolveToken(flagTok string, disable bool, listen string) string {
	tok := flagTok
	if tok == "" {
		tok = os.Getenv("NETZSCANNER_TOKEN")
	}
	if tok != "" {
		if len(tok) < web.MinTokenLen {
			log.Fatalf("Zugangstoken zu kurz (mindestens %d Zeichen)", web.MinTokenLen)
		}
		return tok
	}
	if web.IsLoopbackListen(listen) {
		return ""
	}
	if disable {
		fmt.Println("WARNUNG: --no-token – die Oberflaeche ist ohne Anmeldung im Netz erreichbar!")
		return ""
	}
	t, err := web.NewToken()
	if err != nil {
		log.Fatalf("Token konnte nicht erzeugt werden: %v", err)
	}
	return t
}

// listenPort liefert den Port der Listen-Adresse fuer die Link-Anzeige.
func listenPort(listen string) string {
	if _, port, err := net.SplitHostPort(listen); err == nil {
		return port
	}
	return "8484"
}
