package web

// Netzdokumentation als ein PDF (I-036): Deckblatt, Befunde, Karte und Geraeteliste.
// Die Angaben fuer das Deckblatt tippt der Nutzer ein; sie werden nicht gespeichert.

import (
	"bytes"
	"encoding/json"
	"net/http"
	"time"

	"github.com/berion1982/netzscanner/internal/export"
	"github.com/berion1982/netzscanner/internal/findings"
	"github.com/berion1982/netzscanner/internal/scan"
	"github.com/berion1982/netzscanner/internal/version"
)

// handleNetworkDocPDF liefert die Netzdokumentation ALLER Geraete als PDF-Download.
func (s *server) handleNetworkDocPDF(w http.ResponseWriter, r *http.Request) {
	var req struct{ Customer, Network, Author string }
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8192)).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, errBody("ungueltige Anfrage"))
		return
	}
	s.mu.Lock()
	view, target := s.viewLocked(), s.target
	s.mu.Unlock()
	if len(view) == 0 {
		writeJSON(w, http.StatusBadRequest, errBody("keine Geraete in der Liste"))
		return
	}
	meta := export.Meta{Target: target, Generated: time.Now(), Version: version.String(), NetLines: scan.LocalNetInfo().Lines()}
	info := export.DocInfo{Customer: req.Customer, Network: req.Network, Author: req.Author}
	var buf bytes.Buffer
	if err := export.WriteNetworkDocPDF(&buf, view, findings.Analyze(view), info, meta); err != nil {
		writeJSON(w, http.StatusInternalServerError, errBody("PDF-Export fehlgeschlagen"))
		return
	}
	w.Header().Set("Content-Type", "application/pdf")
	w.Header().Set("Content-Disposition", `attachment; filename="netzscanner-netzdokumentation-`+meta.Generated.Format("20060102-1504")+`.pdf"`)
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	_, _ = w.Write(buf.Bytes())
}
