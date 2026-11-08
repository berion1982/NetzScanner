package web

// Router-Login (I-024): Geraeteliste einer FRITZ!Box per TR-064 lesen und dem Scan zuordnen.
//
// Sicherheit (Zugangsdaten!):
//   - Nur von diesem Rechner aus erlaubt (Anfrage muss von Loopback kommen): ueber
//     "--listen 0.0.0.0" erreichbare Fremde koennen so keine Passwoerter eingeben/abgreifen.
//   - Benutzer/Passwort bleiben im Anfragekoerper, gehen nur an die Router-IP, werden weder
//     gespeichert noch protokolliert noch zurueckgegeben. Ein Klick = ein Anmeldeversuch.
//   - Der Router muss in der Geraeteliste stehen (gescannte Adresse im eigenen Netz).

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/berion1982/netzscanner/internal/model"
	"github.com/berion1982/netzscanner/internal/router"
	"github.com/berion1982/netzscanner/internal/scan"
)

// routerEntry sind die gemerkten Angaben zu einem Geraet laut Router (ohne Zugangsdaten).
type routerEntry struct {
	Name   string
	Iface  string
	Active bool
}

const (
	maxCredRunes  = 128
	routerTimeout = 60 * time.Second
	maxOnlyRouter = 30
)

// onlyRouter ist ein Geraet, das der Router kennt, der Scan aber nicht gefunden hat.
type onlyRouter struct {
	Name   string `json:"name"`
	IP     string `json:"ip,omitempty"`
	MAC    string `json:"mac,omitempty"`
	Active bool   `json:"active"`
}

// isLoopback prueft, ob die Anfrage vom eigenen Rechner kommt.
func isLoopback(r *http.Request) bool {
	h, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return false
	}
	ip := net.ParseIP(h)
	return ip != nil && ip.IsLoopback()
}

// okCredential: Benutzer/Passwort duerfen nicht leer, nicht zu lang und ohne Steuerzeichen sein.
func okCredential(s string, allowEmpty bool) bool {
	if s == "" {
		return allowEmpty
	}
	if utf8.RuneCountInString(s) > maxCredRunes {
		return false
	}
	for _, r := range s {
		if unicode.IsControl(r) {
			return false
		}
	}
	return true
}

// handleFritzbox liest die Geraeteliste der FRITZ!Box und ordnet sie den Scan-Ergebnissen zu.
func (s *server) handleFritzbox(w http.ResponseWriter, r *http.Request) {
	if !isLoopback(r) {
		writeJSON(w, http.StatusForbidden, errBody("Router-Login nur von diesem Rechner aus erlaubt"))
		return
	}
	var req struct {
		Host     string `json:"host"`
		User     string `json:"user"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8192)).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, errBody("ungueltige Anfrage"))
		return
	}
	req.Host = strings.TrimSpace(req.Host)
	if !okCredential(req.User, false) || !okCredential(req.Password, true) {
		writeJSON(w, http.StatusBadRequest, errBody("Benutzer fehlt oder Eingabe enthält unzulässige Zeichen"))
		return
	}

	// Routeradresse: Eingabe oder erkannter Router; muss in der Geraeteliste stehen.
	s.mu.Lock()
	hosts := append([]model.Host(nil), s.hosts...)
	s.mu.Unlock()
	host, found := req.Host, false
	for _, h := range hosts {
		if host == "" && h.Role == "router" {
			host = h.IP
		}
		if h.IP == host {
			found = true
		}
	}
	if !found {
		writeJSON(w, http.StatusBadRequest, errBody("Router-Adresse nicht in der Geräteliste (erst scannen, Router mit scannen)"))
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), routerTimeout)
	defer cancel()
	list, err := router.ReadFritzbox(ctx, host, req.User, req.Password)
	req.Password = "" // so frueh wie moeglich vergessen
	if err != nil {
		writeJSON(w, http.StatusBadGateway, errBody(err.Error()))
		return
	}

	// Zuordnung ueber die MAC.
	info := map[string]routerEntry{}
	inScan := map[string]bool{}
	for _, h := range hosts {
		if m := scan.NormMAC(h.MAC); m != "" {
			inScan[m] = true
		}
	}
	matched := 0
	var only []onlyRouter
	for _, e := range list {
		m := scan.NormMAC(e.MAC)
		if m == "" {
			continue
		}
		info[m] = routerEntry{Name: e.Name, Iface: e.Iface, Active: e.Active}
		if inScan[m] {
			matched++
		} else if len(only) < maxOnlyRouter {
			only = append(only, onlyRouter{Name: e.Name, IP: e.IP, MAC: e.MAC, Active: e.Active})
		}
	}
	s.mu.Lock()
	s.routerInfo = info
	s.mu.Unlock()
	writeJSON(w, http.StatusOK, map[string]any{"entries": len(list), "matched": matched, "onlyRouter": only})
}

// handleRouterClear verwirft die Router-Angaben (Namen/Verbindungsart).
func (s *server) handleRouterClear(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	s.routerInfo = nil
	s.mu.Unlock()
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}
