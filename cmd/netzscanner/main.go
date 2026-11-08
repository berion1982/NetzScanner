// NetzScanner - Einstiegspunkt: startet den eingebauten Webserver mit der Oberflaeche.
package main

import (
	"flag"
	"fmt"
	"log"
	"net/http"

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
	flag.Parse()

	if *showVersion {
		fmt.Println(version.String())
		return
	}

	fmt.Println(version.String())
	fmt.Printf("Oberflaeche: http://%s  (Strg+C beendet)\n", *listen)
	log.Fatal(http.ListenAndServe(*listen, web.NewHandler(web.Options{Demo: *demo, AllowPublic: *allowPublic})))
}
