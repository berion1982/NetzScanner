// NetzScanner - Einstiegspunkt.
//
// Stand v0.1.0: nur Grundgeruest (Version/Build-Info). Scanner, Web-UI und
// Export folgen gemaess ROADMAP in HANDOVER.md.
package main

import (
	"flag"
	"fmt"

	"github.com/berion1982/netzscanner/internal/version"
)

func main() {
	// --version gibt Versionsnummer + Builddatum aus und beendet das Programm.
	showVersion := flag.Bool("version", false, "Version und Builddatum anzeigen")
	flag.Parse()

	if *showVersion {
		fmt.Println(version.String())
		return
	}

	fmt.Println(version.String())
	fmt.Println("Grundgeruest - Scanner noch nicht implementiert (siehe HANDOVER.md).")
}
