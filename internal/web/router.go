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
	"bytes"
	"context"
	"encoding/json"
	"net"
	"net/http"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/berion1982/netzscanner/internal/export"
	"github.com/berion1982/netzscanner/internal/model"
	"github.com/berion1982/netzscanner/internal/router"
	"github.com/berion1982/netzscanner/internal/scan"
	"github.com/berion1982/netzscanner/internal/version"
)

// routerEntry sind die gemerkten Angaben zu einem Geraet laut Router (ohne Zugangsdaten).
type routerEntry struct {
	Name          string
	Iface         string
	Active        bool
	SSID          string // WLAN, an dem das Geraet haengt (leer = kein WLAN-Client)
	Signal, Speed int
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
	running := s.running
	s.mu.Unlock()
	// Waehrend des Scans fehlen noch MACs (ARP wird erst am Ende gelesen) -> Zuordnung waere leer.
	if running {
		writeJSON(w, http.StatusConflict, errBody("Scan läuft noch – bitte erst nach Ende des Scans beim Router anmelden (sonst fehlen die MAC-Adressen für die Zuordnung)"))
		return
	}
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
	res, err := router.ReadFritzbox(ctx, host, req.User, req.Password)
	list := res.Hosts
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
	// Diagnose: Gleiche IP in Scan und Router, aber MAC passt nicht (oder fehlt) -> Beispiele zeigen.
	scanMACByIP := map[string]string{}
	for _, h := range hosts {
		scanMACByIP[h.IP] = h.MAC
	}
	var macDiff []string
	for _, e := range list {
		m := scan.NormMAC(e.MAC)
		if m == "" {
			continue
		}
		info[m] = routerEntry{Name: e.Name, Iface: e.Iface, Active: e.Active}
		if sm, same := scanMACByIP[e.IP]; same && e.IP != "" && scan.NormMAC(sm) != m && len(macDiff) < 8 {
			macDiff = append(macDiff, e.IP+": Router "+e.MAC+" / Scan "+sm)
		}
		if inScan[m] {
			matched++
		} else if len(only) < maxOnlyRouter {
			only = append(only, onlyRouter{Name: e.Name, IP: e.IP, MAC: e.MAC, Active: e.Active})
		}
	}
	// WLAN-Clients (I-055): SSID, Signal und Geschwindigkeit je MAC dazu.
	for _, wl := range res.Info.WLANs {
		for _, c := range wl.Clients {
			m := scan.NormMAC(c.MAC)
			e := info[m]
			e.SSID, e.Signal, e.Speed = wl.SSID, c.Signal, c.Speed
			info[m] = e
		}
	}
	sources := map[string]int{} // Wie viele Geraete je "AddressSource" (z. B. DHCP, Static) - Hinweis fuer Reservierungen (I-055 d)
	for _, e := range list {
		if e.Source != "" {
			sources[e.Source]++
		}
	}
	s.mu.Lock()
	s.routerInfo = info
	ri := res.Info
	s.routerData = &ri
	if len(res.Mesh.Nodes) > 0 {
		mesh := res.Mesh
		s.meshData = &mesh
	} else {
		s.meshData = nil
	}
	s.mu.Unlock()
	writeJSON(w, http.StatusOK, map[string]any{"entries": len(list), "matched": matched, "onlyRouter": only, "info": res.Info, "sources": sources, "macDiff": macDiff})
}

// handleRouterClear verwirft die Router-Angaben (Namen/Verbindungsart).
func (s *server) handleRouterClear(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	s.routerInfo, s.routerData, s.meshData = nil, nil, nil
	s.mu.Unlock()
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

// handleRouterInfo liefert die zuletzt gelesenen Router-Infos und WLANs (oder null).
func (s *server) handleRouterInfo(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	info := s.routerData
	s.mu.Unlock()
	writeJSON(w, http.StatusOK, info)
}

// handleRouterExport liefert Router-Info + WLANs als eigene Datei (I-055): "md" (lesbar) oder "csv" (WLAN-Liste).
// Die externe IP und die WLAN-Schluessel (werden nie gelesen) sind NICHT enthalten.
func (s *server) handleRouterExport(w http.ResponseWriter, r *http.Request) {
	var req struct{ Format string }
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, errBody("ungueltige Anfrage"))
		return
	}
	s.mu.Lock()
	info := s.routerData
	s.mu.Unlock()
	if info == nil {
		writeJSON(w, http.StatusBadRequest, errBody("erst den Router-Login ausführen"))
		return
	}
	meta := export.Meta{Generated: time.Now(), Version: version.String()}
	var buf bytes.Buffer
	var ctype, ext string
	var err error
	switch req.Format {
	case "md":
		ctype, ext, err = "text/markdown; charset=utf-8", "md", export.WriteRouterMarkdown(&buf, *info, meta)
	case "csv":
		ctype, ext, err = "text/csv; charset=utf-8", "csv", export.WriteRouterCSV(&buf, *info)
	default:
		writeJSON(w, http.StatusBadRequest, errBody("unbekanntes Format"))
		return
	}
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, errBody("Export fehlgeschlagen"))
		return
	}
	w.Header().Set("Content-Type", ctype)
	w.Header().Set("Content-Disposition", `attachment; filename="netzscanner-router-`+meta.Generated.Format("20060102-1504")+`.`+ext+`"`)
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	_, _ = w.Write(buf.Bytes())
}

var _ = router.Info{} // Typ der Router-Daten (siehe s.routerData)
