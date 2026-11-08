package web

// Windows-DHCP-Server auslesen (I-056): Leases und feste Reservierungen per WinRM, den
// Scan-Ergebnissen ueber die MAC zugeordnet. Die Abfrage selbst steckt in internal/dhcp.
//
// Sicherheit (Zugangsdaten!) - wie beim Router-Login:
//   - nur von diesem Rechner aus (Loopback), Zugangsdaten nur im Anfragekoerper, nur an den
//     Server, nie gespeichert, nie protokolliert, nie zurueckgegeben;
//   - der Server muss in der Geraeteliste stehen (gescannte Adresse im eigenen Netz).

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/berion1982/netzscanner/internal/dhcp"
	"github.com/berion1982/netzscanner/internal/model"
	"github.com/berion1982/netzscanner/internal/scan"
)

const dhcpTimeout = 90 * time.Second

// dhcpEntry sind die gemerkten Angaben zu einem Geraet laut DHCP-Server (ohne Zugangsdaten).
type dhcpEntry struct {
	Name     string
	Reserved bool
	Expires  string
}

// Label ist der kurze Text fuer das Detail-Panel.
func (e dhcpEntry) Label() string {
	if e.Reserved {
		return "feste Reservierung"
	}
	if e.Expires != "" {
		return "Lease bis " + e.Expires
	}
	return "Lease"
}

// dhcpResult ist die Antwort an die Oberflaeche.
type dhcpResult struct {
	Entries  int          `json:"entries"`
	Reserved int          `json:"reserved"`
	Matched  int          `json:"matched"`
	Only     []dhcp.Entry `json:"onlyDHCP"` // beim Server bekannt, im Scan nicht gefunden (gekuerzt)
}

// handleWindowsDHCP liest den Windows-DHCP-Server und ordnet die Eintraege den Geraeten zu.
func (s *server) handleWindowsDHCP(w http.ResponseWriter, r *http.Request) {
	if !isLoopback(r) {
		writeJSON(w, http.StatusForbidden, errBody("DHCP-Abfrage nur von diesem Rechner aus erlaubt"))
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
	if req.Host == "" || !okCredential(req.User, false) || !okCredential(req.Password, false) {
		writeJSON(w, http.StatusBadRequest, errBody("Server, Benutzer und Passwort angeben (ohne Sonderzeichen wie Zeilenumbrüche)"))
		return
	}

	s.mu.Lock()
	hosts := append([]model.Host(nil), s.hosts...)
	s.mu.Unlock()
	found := false
	for _, h := range hosts {
		if h.IP == req.Host {
			found = true
		}
	}
	if !found {
		writeJSON(w, http.StatusBadRequest, errBody("Server-Adresse nicht in der Geräteliste (erst scannen, Server mit scannen)"))
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), dhcpTimeout)
	defer cancel()
	rows, err := dhcp.ReadWindows(ctx, req.Host, req.User, req.Password)
	req.Password = "" // so frueh wie moeglich vergessen
	if err != nil {
		writeJSON(w, http.StatusBadGateway, errBody(err.Error()))
		return
	}

	info, res := matchDHCP(rows, hosts)
	s.mu.Lock()
	s.dhcpInfo = info
	s.mu.Unlock()
	writeJSON(w, http.StatusOK, res)
}

// matchDHCP ordnet die Eintraege ueber die MAC den Geraeten zu (reine Logik). Eine feste
// Reservierung hat Vorrang vor einem Lease derselben MAC.
func matchDHCP(rows []dhcp.Entry, hosts []model.Host) (map[string]dhcpEntry, dhcpResult) {
	const maxOnly = 30
	inScan := map[string]bool{}
	for _, h := range hosts {
		if m := scan.NormMAC(h.MAC); m != "" {
			inScan[m] = true
		}
	}
	info := map[string]dhcpEntry{}
	var res dhcpResult
	for _, e := range rows {
		m := scan.NormMAC(e.MAC)
		if m == "" {
			continue
		}
		res.Entries++
		if e.Reserved {
			res.Reserved++
		}
		if old, ok := info[m]; !ok || (e.Reserved && !old.Reserved) {
			info[m] = dhcpEntry{Name: e.Name, Reserved: e.Reserved, Expires: e.Expires}
		}
		if !inScan[m] && len(res.Only) < maxOnly {
			res.Only = append(res.Only, e)
		}
	}
	for m := range info {
		if inScan[m] {
			res.Matched++
		}
	}
	return info, res
}

// handleDHCPClear verwirft die DHCP-Angaben.
func (s *server) handleDHCPClear(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	s.dhcpInfo = nil
	s.mu.Unlock()
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}
