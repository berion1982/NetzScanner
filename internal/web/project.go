package web

// Scan als Projektdatei speichern und wieder laden (I-035).
//
// Die Projektdatei ist eine JSON-Datei, die der Browser herunterlaedt bzw. hochlaedt
// (funktioniert damit auch auf einem Handheld/Server ohne Zugriff auf dessen Dateisystem).
// Inhalt: Scan-Ergebnis (Geraeteliste), Ziel, Zeitpunkt, Programmversion und die Eingaben
// des Nutzers (Name, Benutzer, Standort, Kategorie - KEINE Passwoerter).
//
// NICHT enthalten (nur im RAM, bewusst): Router-Login und -Daten, Mesh, Windows-DHCP,
// SNMP-Zuordnung sowie alle Zugangsdaten. Sie muessen nach dem Laden neu abgefragt werden.
//
// Beim Laden wird die Datei wie jede fremde Eingabe behandelt: Groessen- und Mengengrenzen,
// IP-Pruefung, Texte bereinigen und kuerzen, unbekannte Kategorien verwerfen.

import (
	"encoding/json"
	"net/http"
	"net/netip"
	"sort"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/berion1982/netzscanner/internal/model"
	"github.com/berion1982/netzscanner/internal/version"
)

const (
	projectFormat   = "netzscanner-scan" // Kennung im Dateikopf
	projectVersion  = 1                  // Version des Dateiformats (nicht der Programmversion)
	maxProjectBytes = 16 << 20           // 16 MiB beim Hochladen
	maxProjectHosts = 5000
	maxProjectPorts = 1024
	maxFieldRunes   = 300 // Kuerzung fuer Textfelder aus der Datei
)

// projectFile ist der Aufbau der Projektdatei.
type projectFile struct {
	Format     string                `json:"format"`
	FormatVer  int                   `json:"formatVersion"`
	AppVersion string                `json:"appVersion"` // Programmversion, die gespeichert hat (nur Information)
	SavedAt    time.Time             `json:"savedAt"`
	Target     string                `json:"target"`
	Finished   time.Time             `json:"finished"`
	Hosts      []model.Host          `json:"hosts"`
	Inputs     map[string]storeEntry `json:"inputs,omitempty"` // Eingaben je IP
	Custom     []string              `json:"customCategories,omitempty"`
}

// handleProjectSave liefert den aktuellen Scan als herunterladbare Projektdatei.
func (s *server) handleProjectSave(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	f := projectFile{
		Format: projectFormat, FormatVer: projectVersion, AppVersion: version.String(),
		SavedAt: time.Now(), Target: s.target, Finished: s.finished,
		Hosts: append([]model.Host{}, s.hosts...), Inputs: map[string]storeEntry{}, Custom: s.customCats,
	}
	for _, m := range []map[string]string{s.names, s.users, s.locs, s.cats} {
		for ip := range m {
			f.Inputs[ip] = storeEntry{MAC: s.macs[ip], Name: s.names[ip], User: s.users[ip], Location: s.locs[ip], Category: s.cats[ip]}
		}
	}
	running := s.running
	s.mu.Unlock()
	if running {
		writeJSON(w, http.StatusConflict, errBody("Scan läuft noch - erst abwarten oder abbrechen"))
		return
	}
	if len(f.Hosts) == 0 {
		writeJSON(w, http.StatusBadRequest, errBody("Kein Scan-Ergebnis zum Speichern"))
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Disposition", `attachment; filename="netzscan-`+time.Now().Format("2006-01-02_1504")+`.json"`)
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(f)
}

// handleProjectLoad ersetzt die Geraeteliste durch den Inhalt einer hochgeladenen Projektdatei.
func (s *server) handleProjectLoad(w http.ResponseWriter, r *http.Request) {
	var f projectFile
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxProjectBytes)).Decode(&f); err != nil {
		writeJSON(w, http.StatusBadRequest, errBody("Datei ist keine gültige Projektdatei"))
		return
	}
	if f.Format != projectFormat || f.FormatVer != projectVersion {
		writeJSON(w, http.StatusBadRequest, errBody("Unbekanntes Dateiformat (kein NetzScanner-Scan oder zu neu)"))
		return
	}
	hosts, ok := sanitizeProjectHosts(f.Hosts)
	if !ok {
		writeJSON(w, http.StatusBadRequest, errBody("Projektdatei enthält zu viele oder keine gültigen Geräte"))
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if s.running {
		writeJSON(w, http.StatusConflict, errBody("Es läuft ein Scan - erst abwarten oder abbrechen"))
		return
	}
	s.hosts, s.target, s.finished = hosts, clip(f.Target), f.Finished
	s.done, s.total, s.errMsg = len(hosts), len(hosts), ""
	// Daten aus Zusatzquellen gehoeren zum alten Scan und werden verworfen.
	s.routerData, s.routerInfo, s.meshData = nil, nil, nil
	s.dhcpRows, s.dhcpInfo = nil, nil
	s.snmpLinks, s.snmpSwitch = nil, nil
	s.creds.remove("") // Zugangsdaten gehoeren zu den alten Geraeten (I-020)
	// Eingaben aus der Datei (geprueft) zu den vorhandenen hinzufuegen.
	n := 0
	for ip, e := range f.Inputs {
		if n++; n > maxProjectHosts {
			break
		}
		s.applyEntry(ip, e)
	}
	for _, k := range f.Custom {
		if model.IsCustom(k) && model.ValidCategory(k) && !s.hasCustomLocked(k) && len(s.customCats) < model.MaxCustomCategories {
			s.customCats = append(s.customCats, k)
		}
	}
	if !s.opt.Demo {
		s.persistLocked()
	}
	writeJSON(w, http.StatusOK, map[string]any{"hosts": len(hosts), "target": s.target, "savedAt": f.SavedAt, "appVersion": clip(f.AppVersion)})
}

// sanitizeProjectHosts prueft und bereinigt die Geraete aus einer fremden Datei.
// Gibt false zurueck, wenn die Menge unzulaessig ist oder kein Geraet uebrig bleibt.
func sanitizeProjectHosts(in []model.Host) ([]model.Host, bool) {
	if len(in) == 0 || len(in) > maxProjectHosts {
		return nil, false
	}
	out := make([]model.Host, 0, len(in))
	seen := map[string]bool{}
	for _, h := range in {
		addr, err := netip.ParseAddr(h.IP)
		if err != nil || seen[addr.String()] {
			continue // ungueltige oder doppelte IP
		}
		seen[addr.String()] = true
		h.IP = addr.String()
		h.Pending = false // aus der Datei kommt nie ein "laeuft noch"
		for _, p := range []*string{&h.Name, &h.NameSource, &h.Location, &h.Username, &h.ScannedName, &h.MAC, &h.Vendor,
			&h.OS, &h.Uplink, &h.DHCP, &h.RouterName, &h.Connection, &h.WifiSSID, &h.MeshLink, &h.UplinkPort, &h.Role, &h.MirrorOf} {
			*p = clip(*p)
		}
		if !model.ValidCategory(h.Category) {
			h.Category = model.CatClient
		}
		if len(h.Ports) > maxProjectPorts {
			h.Ports = h.Ports[:maxProjectPorts]
		}
		for i := range h.Ports {
			h.Ports[i].Service, h.Ports[i].Banner = clip(h.Ports[i].Service), clip(h.Ports[i].Banner)
		}
		if len(h.SameMAC) > 50 {
			h.SameMAC = h.SameMAC[:50]
		}
		for i := range h.SameMAC {
			h.SameMAC[i] = clip(h.SameMAC[i])
		}
		h.FillWebLinks() // Links immer aus IP/Ports neu berechnen, nie aus der Datei
		out = append(out, h)
	}
	sort.Slice(out, func(i, j int) bool { return ipLess(out[i].IP, out[j].IP) })
	return out, len(out) > 0
}

// clip entfernt Steuerzeichen und kuerzt auf maxFieldRunes Zeichen.
func clip(s string) string {
	s = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return -1
		}
		return r
	}, s)
	if utf8.RuneCountInString(s) > maxFieldRunes {
		s = string([]rune(s)[:maxFieldRunes])
	}
	return s
}
