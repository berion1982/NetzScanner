// Browser automatisch oeffnen (I-083): Nach dem Start oeffnet NetzScanner die
// Oberflaeche im Standardbrowser des Systems, damit niemand die Adresse tippen muss.
package main

import (
	"fmt"
	"os/exec"
	"runtime"

	"github.com/berion1982/netzscanner/internal/web"
)

// shouldOpenBrowser entscheidet, ob der Browser geoeffnet wird.
// Nur wenn der Nutzer es nicht abgeschaltet hat (--no-browser) UND der Server
// nur lokal (Loopback) lauscht. Bei --listen 0.0.0.0 (Server/Handheld ohne
// Bildschirm) wird nie ein Browser gestartet.
func shouldOpenBrowser(noBrowser bool, listen string) bool {
	return !noBrowser && web.IsLoopbackListen(listen)
}

// browserCommand liefert den Systembefehl zum Oeffnen einer Web-Adresse.
// Alle Argumente sind fest (keine Shell, keine Nutzereingaben ausser der eigenen URL).
func browserCommand(goos, url string) (name string, args []string) {
	switch goos {
	case "windows":
		// Standardprogramm fuer Web-Adressen, ohne Konsolenfenster.
		return "rundll32", []string{"url.dll,FileProtocolHandler", url}
	case "darwin":
		return "open", []string{url}
	default: // Linux und andere Unix-Systeme
		return "xdg-open", []string{url}
	}
}

// openBrowser startet den Standardbrowser mit der Adresse. Es wird nicht auf das
// Ende des Browsers gewartet. Schlaegt es fehl (z. B. kein xdg-open, kein Desktop),
// bleibt das Programm lauffaehig: die Adresse steht ohnehin in der Konsole.
func openBrowser(url string) error {
	name, args := browserCommand(runtime.GOOS, url)
	cmd := exec.Command(name, args...)
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("Browser konnte nicht gestartet werden (%s): %w", name, err)
	}
	// Prozess im Hintergrund einsammeln, damit kein Zombie-Prozess bleibt.
	go func() { _ = cmd.Wait() }()
	return nil
}
