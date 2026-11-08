package web

// Web-Endpunkte fuer die SNMP-Topologie (I-010 Teil 2). Die Logik steckt in internal/scan/snmp.go.
//
// Sicherheit:
//   - Die SNMP-Community ist ein Zugangsdatum: Sie kommt nur im Anfragekoerper an, wird nur an
//     das Zielgeraet geschickt und weder gespeichert, noch protokolliert, noch zurueckgegeben.
//   - Abgefragt werden nur Geraete, die in der aktuellen Geraeteliste stehen (also gescannte
//     Adressen im eigenen Netz) - der Server laesst sich nicht auf beliebige Ziele richten.

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/berion1982/netzscanner/internal/model"
	"github.com/berion1982/netzscanner/internal/scan"
)

// snmpLink ist ein Anschluss samt MAC zum Zeitpunkt der Abfrage (Schutz vor IP-Wechsel).
type snmpLink struct {
	scan.Link
	mac string
}

// Grenzen fuer die Eingabe.
const (
	maxCommunityRunes = 64
	snmpTotalTimeout  = 90 * time.Second // Obergrenze fuer die ganze Abfrage
)

// snmpResult ist die Antwort an die Oberflaeche (ohne Zugangsdaten).
type snmpResult struct {
	Switches []snmpSwitchResult `json:"switches"`
	Linked   int                `json:"linked"` // Anzahl Geraete mit Port-Zuordnung
}

type snmpSwitchResult struct {
	IP      string `json:"ip"`
	Name    string `json:"name,omitempty"`
	Vendor  string `json:"vendor,omitempty"` // Hersteller aus sysObjectID (I-052)
	Entries int    `json:"entries"`          // Zeilen der MAC-Adresstabelle
	LLDP    int    `json:"lldp"`             // direkte Nachbarn laut LLDP (I-051)
	Error   string `json:"error,omitempty"`  // Klartext-Grund bei Fehler
}

// handleSNMP liest die MAC-Adresstabellen der genannten Switches und ordnet die Geraete zu.
func (s *server) handleSNMP(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Community string   `json:"community"`
		Targets   []string `json:"targets"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8192)).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, errBody("ungueltige Anfrage"))
		return
	}
	comm := strings.TrimSpace(req.Community)
	if comm == "" || utf8.RuneCountInString(comm) > maxCommunityRunes {
		writeJSON(w, http.StatusBadRequest, errBody("Community fehlt oder ist zu lang"))
		return
	}
	for _, c := range comm {
		if c > unicode.MaxASCII || unicode.IsControl(c) {
			writeJSON(w, http.StatusBadRequest, errBody("Community enthält unzulässige Zeichen"))
			return
		}
	}
	if len(req.Targets) == 0 || len(req.Targets) > scan.MaxSNMPTargets {
		writeJSON(w, http.StatusBadRequest, errBody("1 bis 10 Switch-Adressen angeben"))
		return
	}

	// Geraeteliste kopieren; Ziele muessen darin vorkommen.
	s.mu.Lock()
	hosts := append([]model.Host(nil), s.hosts...)
	s.mu.Unlock()
	known := map[string]bool{}
	routerMAC := ""
	for _, h := range hosts {
		known[h.IP] = true
		if h.Role == "router" {
			routerMAC = h.MAC
		}
	}
	var targets []string
	seen := map[string]bool{}
	for _, t := range req.Targets {
		t = strings.TrimSpace(t)
		if !known[t] {
			writeJSON(w, http.StatusBadRequest, errBody("Adresse nicht in der Geräteliste (erst scannen): "+sanitizeEcho(t)))
			return
		}
		if !seen[t] {
			seen[t] = true
			targets = append(targets, t)
		}
	}

	// Abfragen (nacheinander, mit Gesamt-Zeitlimit). Fehler pro Switch, nicht fuer alles.
	ctx, cancel := context.WithTimeout(r.Context(), snmpTotalTimeout)
	defer cancel()
	var res snmpResult
	var data []scan.SwitchData
	info := map[string]scan.SwitchInfo{}
	for _, ip := range targets {
		d, err := scan.QuerySwitch(ctx, ip, comm)
		sr := snmpSwitchResult{IP: ip, Name: d.SysName, Vendor: d.Vendor, Entries: len(d.FDB), LLDP: len(d.LLDP)}
		if err != nil {
			sr.Error = err.Error()
		} else {
			data = append(data, d)
			info[ip] = scan.SwitchInfo{Name: d.SysName, Descr: d.SysDescr, Vendor: d.Vendor}
		}
		res.Switches = append(res.Switches, sr)
	}
	if len(data) == 0 {
		writeJSON(w, http.StatusOK, res) // alle fehlgeschlagen: nichts aendern, Gruende anzeigen
		return
	}

	links := scan.BuildLinks(hosts, data, routerMAC)
	macOf := map[string]string{}
	for _, h := range hosts {
		macOf[h.IP] = scan.NormMAC(h.MAC)
	}
	s.mu.Lock()
	s.snmpLinks = map[string]snmpLink{}
	for ip, l := range links {
		s.snmpLinks[ip] = snmpLink{Link: l, mac: macOf[ip]}
	}
	s.snmpSwitch = info
	s.mu.Unlock()
	res.Linked = len(links)
	writeJSON(w, http.StatusOK, res)
}

// handleSNMPClear verwirft die SNMP-Zuordnung (zurueck zur Sternansicht).
func (s *server) handleSNMPClear(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	s.snmpLinks, s.snmpSwitch = nil, nil
	s.mu.Unlock()
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

// sanitizeEcho kuerzt und bereinigt Text, der in einer Fehlermeldung wiederholt wird.
func sanitizeEcho(t string) string {
	t = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return -1
		}
		return r
	}, t)
	if len(t) > 40 {
		t = t[:40]
	}
	return t
}
