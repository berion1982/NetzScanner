// NetzScanner - Einstiegspunkt: startet den eingebauten Webserver mit der Oberflaeche.
package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"

	"github.com/berion1982/netzscanner/internal/router"
	"github.com/berion1982/netzscanner/internal/scan"
	"github.com/berion1982/netzscanner/internal/version"
	"github.com/berion1982/netzscanner/internal/web"
)

func main() {
	showVersion := flag.Bool("version", false, "Version und Builddatum anzeigen")
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
	flag.Parse()
	if *noSave || *demo { // Demo-Daten sind erfunden: nie speichern

		*dataFile = ""
	}

	if *showVersion {
		fmt.Println(version.String())
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

	fmt.Println(version.String())
	if *dataFile != "" && !*demo {
		fmt.Println("Eingaben werden gespeichert in:", *dataFile, "(abschaltbar mit --no-save)")
	}
	fmt.Printf("Oberflaeche: http://%s  (Strg+C beendet)\n", *listen)
	log.Fatal(http.ListenAndServe(*listen, web.NewHandler(web.Options{Demo: *demo, AllowPublic: *allowPublic, DataFile: *dataFile})))
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
