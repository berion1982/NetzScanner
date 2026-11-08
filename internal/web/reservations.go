package web

// Reiter "Reservierungen" (I-057): feste DHCP-Reservierungen als Liste anzeigen und exportieren.
// Quelle ist die zuletzt gelesene DHCP-Abfrage (nur im RAM). Keine Zugangsdaten beteiligt.

import (
	"bytes"
	"encoding/json"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/berion1982/netzscanner/internal/dhcp"
	"github.com/berion1982/netzscanner/internal/export"
	"github.com/berion1982/netzscanner/internal/scan"
	"github.com/berion1982/netzscanner/internal/version"
)

// reservations liefert die festen Reservierungen, sortiert nach Netz und IP, mit Scan-Namen.
func (s *server) reservations() []export.Reservation {
	s.mu.Lock()
	rows := append([]dhcp.Entry(nil), s.dhcpRows...)
	routerRows := s.routerReservationsLocked()
	view := s.viewLocked() // Geraete inkl. Namen; MAC -> Name nachschlagen
	s.mu.Unlock()
	nameOf := map[string]string{}
	for _, h := range view {
		if m := scan.NormMAC(h.MAC); m != "" && h.Known {
			nameOf[m] = h.Name
		}
	}
	var out []export.Reservation
	for _, e := range rows {
		if e.Reserved {
			out = append(out, export.Reservation{Scope: e.Scope, IP: e.IP, MAC: e.MAC, Name: e.Name, ScanName: nameOf[scan.NormMAC(e.MAC)]})
		}
	}
	// FRITZ!Box: Eintraege mit Adressvergabe "Static", sofern der Windows-Server dieselbe MAC nicht schon nennt.
	have := map[string]bool{}
	for _, r := range out {
		have[scan.NormMAC(r.MAC)] = true
	}
	for _, r := range routerRows {
		if !have[scan.NormMAC(r.MAC)] {
			r.ScanName = nameOf[scan.NormMAC(r.MAC)]
			out = append(out, r)
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Scope != out[j].Scope {
			return out[i].Scope < out[j].Scope
		}
		return ipLess(out[i].IP, out[j].IP)
	})
	return out
}

// handleReservations liefert die Liste fuer den Reiter (leeres Feld, wenn noch nichts gelesen wurde).
func (s *server) handleReservations(w http.ResponseWriter, r *http.Request) {
	list := s.reservations()
	if list == nil {
		list = []export.Reservation{}
	}
	writeJSON(w, http.StatusOK, list)
}

// handleReservationsExport liefert die Liste als Datei: "csv-excel", "csv" oder "md".
func (s *server) handleReservationsExport(w http.ResponseWriter, r *http.Request) {
	var req struct{ Format string }
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, errBody("ungueltige Anfrage"))
		return
	}
	list := s.reservations()
	if len(list) == 0 {
		writeJSON(w, http.StatusBadRequest, errBody("keine Reservierungen vorhanden (erst DHCP-Server lesen)"))
		return
	}
	meta := export.Meta{Generated: time.Now(), Version: version.String()}
	var buf bytes.Buffer
	var ctype, ext string
	var err error
	switch req.Format {
	case "csv-excel", "csv":
		ctype, ext, err = "text/csv; charset=utf-8", "csv", export.WriteReservationsCSV(&buf, list, req.Format == "csv-excel")
	case "md":
		ctype, ext, err = "text/markdown; charset=utf-8", "md", export.WriteReservationsMarkdown(&buf, list, meta)
	default:
		writeJSON(w, http.StatusBadRequest, errBody("unbekanntes Format"))
		return
	}
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, errBody("Export fehlgeschlagen"))
		return
	}
	w.Header().Set("Content-Type", ctype)
	w.Header().Set("Content-Disposition", `attachment; filename="netzscanner-reservierungen-`+meta.Generated.Format("20060102-1504")+`.`+ext+`"`)
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	_, _ = w.Write(buf.Bytes())
}

// routerReservationsLocked liefert die Router-Geraete mit Adressvergabe "Static" (s.mu muss gehalten werden).
// Die FRITZ!Box bietet per TR-064 keine eigene Reservierungsliste; "Static" ist eine Vermutung und
// wurde noch nicht mit den Einstellungen der Box abgeglichen.
func (s *server) routerReservationsLocked() []export.Reservation {
	var out []export.Reservation
	for m, e := range s.routerInfo {
		if strings.EqualFold(e.Source, "static") && e.IP != "" {
			out = append(out, export.Reservation{Scope: "FRITZ!Box (Static)", IP: e.IP, MAC: macColon(m), Name: e.Name})
		}
	}
	return out
}

// macColon macht aus "aabbcc001122" wieder "AA:BB:CC:00:11:22" (lesbare Anzeige).
func macColon(m string) string {
	if len(m) != 12 {
		return m
	}
	up := strings.ToUpper(m)
	return up[0:2] + ":" + up[2:4] + ":" + up[4:6] + ":" + up[6:8] + ":" + up[8:10] + ":" + up[10:12]
}
