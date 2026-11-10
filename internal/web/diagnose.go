package web

// Diagnose-Bericht je Geraet (I-074): POST /api/diagnose {ip, ping, trace, fullPorts}.
// Der Bericht entsteht in scan.DiagnoseDevice und wird als Text Zeile fuer Zeile gesendet
// (Streaming), damit lange Bausteine (Traceroute, voller Portscan) sofort sichtbar werden.
//
// Schutzregeln (wie beim Login-Test):
//   - nur von diesem Rechner aus (Loopback): Die Schnittstelle sendet aktiv Pakete ins Netz;
//   - nur Geraete aus der Scan-Liste (kein allgemeiner Ping-/Portscan-Dienst);
//   - pro Geraet laeuft immer nur ein Bericht;
//   - kein Passwort im Bericht: Login-Tests erscheinen nur mit Methode, Port, Status, Meldung.

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/berion1982/netzscanner/internal/model"
	"github.com/berion1982/netzscanner/internal/scan"
)

// diagBusy merkt Geraete, fuer die gerade ein Bericht laeuft.
var diagBusy = newBusySet()

// diagMaxDuration begrenzt einen ganzen Bericht (voller Portscan + Traceroute + Ping + Pruefungen).
const diagMaxDuration = 15 * time.Minute

func (s *server) handleDiagnose(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if !isLoopback(r) {
		writeJSON(w, http.StatusForbidden, errBody("Diagnose nur von diesem Rechner aus erlaubt"))
		return
	}
	var raw struct {
		IP        string `json:"ip"`
		Ping      bool   `json:"ping"`
		Trace     bool   `json:"trace"`
		FullPorts bool   `json:"fullPorts"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 2048)).Decode(&raw); err != nil {
		writeJSON(w, http.StatusBadRequest, errBody("ungueltige Anfrage"))
		return
	}
	host, ok := s.hostCopy(raw.IP)
	if !ok {
		writeJSON(w, http.StatusBadRequest, errBody("Gerät nicht in den Scan-Ergebnissen"))
		return
	}
	if !diagBusy.acquire(host.IP) {
		writeJSON(w, http.StatusConflict, errBody("Für dieses Gerät läuft gerade ein Bericht"))
		return
	}
	defer diagBusy.release(host.IP)

	// Ergebnisse der Login-Tests (ohne Passwort) als Zeilen mitgeben.
	var extra []string
	for _, c := range s.creds.list() {
		if c.IP != host.IP {
			continue
		}
		for _, t := range c.Tests {
			extra = append(extra, fmt.Sprintf("%s Port %d: %s – %s", t.Method, t.Port, t.Status, t.Message))
		}
	}

	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	ctx, cancel := context.WithTimeout(r.Context(), diagMaxDuration)
	defer cancel()
	out := &flushWriter{w: w}
	scan.DiagnoseDevice(ctx, host, scan.DiagOptions{Ping: raw.Ping, Trace: raw.Trace, FullPorts: raw.FullPorts}, extra, out)
}

// hostCopy liefert eine Kopie des Geraets samt Eingaben des Nutzers (Name, Standort ...).
func (s *server) hostCopy(ip string) (model.Host, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, h := range s.viewLocked() {
		if h.IP == ip {
			return h, true
		}
	}
	return model.Host{}, false
}

// flushWriter sendet jede Ausgabe sofort an den Browser (Streaming).
type flushWriter struct{ w http.ResponseWriter }

func (f *flushWriter) Write(b []byte) (int, error) {
	n, err := f.w.Write(b)
	if fl, ok := f.w.(http.Flusher); ok {
		fl.Flush()
	}
	return n, err
}

// busySet merkt, fuer welche Geraete gerade ein Vorgang laeuft (gegen Doppelklicks).
type busySet struct {
	mu sync.Mutex
	m  map[string]bool
}

func newBusySet() *busySet { return &busySet{m: map[string]bool{}} }

// acquire liefert false, wenn fuer den Schluessel schon ein Vorgang laeuft.
func (b *busySet) acquire(key string) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.m[key] {
		return false
	}
	b.m[key] = true
	return true
}

func (b *busySet) release(key string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	delete(b.m, key)
}
