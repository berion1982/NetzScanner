package web

// Reiter "Befunde" (I-064): Auffaelligkeiten aus den vorhandenen Scan-Daten anzeigen und exportieren.
// Es wird kein zusaetzlicher Netzverkehr erzeugt; es sind keine Zugangsdaten beteiligt.

import (
	"bytes"
	"encoding/json"
	"net/http"
	"time"

	"github.com/berion1982/netzscanner/internal/export"
	"github.com/berion1982/netzscanner/internal/findings"
	"github.com/berion1982/netzscanner/internal/version"
)

// handleFindings liefert die Befundliste der aktuellen Geraete (leeres Feld, wenn keine Befunde).
func (s *server) handleFindings(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	view := s.viewLocked()
	s.mu.Unlock()
	writeJSON(w, http.StatusOK, findings.Analyze(view))
}

// handleFindingsExport liefert die Befunde als Datei: "csv-excel", "csv" oder "md".
func (s *server) handleFindingsExport(w http.ResponseWriter, r *http.Request) {
	var req struct{ Format string }
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, errBody("ungueltige Anfrage"))
		return
	}
	s.mu.Lock()
	view, target := s.viewLocked(), s.target
	s.mu.Unlock()
	list := findings.Analyze(view)
	if len(list) == 0 {
		writeJSON(w, http.StatusBadRequest, errBody("keine Befunde vorhanden"))
		return
	}
	meta := export.Meta{Target: target, Generated: time.Now(), Version: version.String()}
	var buf bytes.Buffer
	var ctype, ext string
	var err error
	switch req.Format {
	case "csv-excel", "csv":
		ctype, ext, err = "text/csv; charset=utf-8", "csv", export.WriteFindingsCSV(&buf, list, req.Format == "csv-excel")
	case "md":
		ctype, ext, err = "text/markdown; charset=utf-8", "md", export.WriteFindingsMarkdown(&buf, list, meta)
	default:
		writeJSON(w, http.StatusBadRequest, errBody("unbekanntes Format"))
		return
	}
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, errBody("Export fehlgeschlagen"))
		return
	}
	w.Header().Set("Content-Type", ctype)
	w.Header().Set("Content-Disposition", `attachment; filename="netzscanner-befunde-`+meta.Generated.Format("20060102-1504")+`.`+ext+`"`)
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	_, _ = w.Write(buf.Bytes())
}
