// Package web enthaelt den eingebauten Webserver samt Oberflaeche.
package web

import (
	"embed"
	"encoding/json"
	"io/fs"
	"net/http"

	"github.com/berion1982/netzscanner/internal/version"
)

// Die Oberflaeche (HTML/JS/CSS) wird ins Programm eingebettet:
// dadurch genuegt eine einzige Datei zur Verteilung.
//
//go:embed static
var staticFiles embed.FS

// NewHandler baut den HTTP-Handler: Oberflaeche unter "/", Daten unter "/api/...".
func NewHandler() http.Handler {
	mux := http.NewServeMux()

	// Statische Dateien aus dem eingebetteten Ordner "static" ausliefern.
	sub, _ := fs.Sub(staticFiles, "static")
	mux.Handle("/", http.FileServer(http.FS(sub)))

	// Geraeteliste (aktuell Demo-Daten).
	mux.HandleFunc("/api/hosts", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, DemoHosts())
	})
	// Versionsinfo fuer Fusszeile und Hilfe-Seite.
	mux.HandleFunc("/api/version", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, map[string]string{
			"version": version.Version, "buildDate": version.BuildDate, "commit": version.Commit,
		})
	})
	return mux
}

// writeJSON schreibt v als JSON; "no-store" verhindert Caching sensibler Netzdaten.
func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(v)
}
