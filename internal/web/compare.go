package web

// Scan-Vergleich (I-034): Der aktuelle Scan wird mit einer frueher gespeicherten
// Projektdatei (I-035) verglichen. Ergebnis: neue Geraete, verschwundene Geraete und
// Aenderungen an Geraeten, die in beiden Staenden vorkommen.
//
// Nur lesen: Der Vergleich veraendert weder den aktuellen Scan noch die Datei.
// Die hochgeladene Datei wird wie beim Laden als fremde Eingabe geprueft und bereinigt.
//
// Zuordnung eines Geraets zwischen alt und neu (allgemeine Regel, keine Einzelfaelle):
//  1. gleiche MAC (nur eindeutige, nicht leere MACs) -> dasselbe Geraet, auch bei neuer IP;
//  2. sonst gleiche IP, sofern nicht beide Seiten verschiedene MACs haben;
//  3. alles andere ist "neu" (nur im aktuellen Scan) bzw. "weg" (nur in der Datei).

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/berion1982/netzscanner/internal/model"
	"github.com/berion1982/netzscanner/internal/scan"
)

// compareChange beschreibt eine Aenderung an einem Geraet, das in beiden Staenden vorkommt.
type compareChange struct {
	IP      string   `json:"ip"`      // IP im aktuellen Scan
	Name    string   `json:"name"`    // Name im aktuellen Scan
	Changes []string `json:"changes"` // lesbare Aenderungen, z. B. "Port 22 neu"
}

// compareDevice ist ein Geraet, das nur in einem der beiden Staende vorkommt.
type compareDevice struct {
	IP       string `json:"ip"`
	Name     string `json:"name"`
	MAC      string `json:"mac,omitempty"`
	Vendor   string `json:"vendor,omitempty"`
	Category string `json:"category,omitempty"`
}

// compareResult ist die Antwort von /api/project/compare.
type compareResult struct {
	OldSavedAt time.Time       `json:"oldSavedAt"` // Zeitpunkt der Datei
	OldTarget  string          `json:"oldTarget"`
	OldCount   int             `json:"oldCount"`
	NewCount   int             `json:"newCount"`
	Added      []compareDevice `json:"added"`   // nur im aktuellen Scan
	Removed    []compareDevice `json:"removed"` // nur in der Datei
	Changed    []compareChange `json:"changed"` // in beiden, aber veraendert
	Same       int             `json:"same"`    // in beiden, unveraendert
}

// handleProjectCompare vergleicht den aktuellen Scan mit der hochgeladenen Projektdatei.
func (s *server) handleProjectCompare(w http.ResponseWriter, r *http.Request) {
	var f projectFile
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxProjectBytes)).Decode(&f); err != nil {
		writeJSON(w, http.StatusBadRequest, errBody("Datei ist keine gültige Projektdatei"))
		return
	}
	if f.Format != projectFormat || f.FormatVer != projectVersion {
		writeJSON(w, http.StatusBadRequest, errBody("Unbekanntes Dateiformat (kein NetzScanner-Scan oder zu neu)"))
		return
	}
	old, ok := sanitizeProjectHosts(f.Hosts)
	if !ok {
		writeJSON(w, http.StatusBadRequest, errBody("Projektdatei enthält zu viele oder keine gültigen Geräte"))
		return
	}
	s.mu.Lock()
	cur := s.viewLocked() // so wie in der Liste angezeigt (Nutzer-Namen, Kategorie)
	running := s.running
	s.mu.Unlock()
	if running {
		writeJSON(w, http.StatusConflict, errBody("Es läuft ein Scan - erst abwarten oder abbrechen"))
		return
	}
	if len(cur) == 0 {
		writeJSON(w, http.StatusBadRequest, errBody("Kein aktueller Scan zum Vergleichen - erst scannen oder einen Scan laden"))
		return
	}
	viewOldHosts(old, f.Inputs)
	res := compareHosts(old, cur)
	res.OldSavedAt, res.OldTarget = f.SavedAt, clip(f.Target)
	writeJSON(w, http.StatusOK, res)
}

// viewOldHosts bringt die Geraete aus der Datei in dieselbe Darstellung wie viewLocked:
// Name und Kategorie aus den gespeicherten Eingaben, sonst die Kategorie-Vermutung neu
// berechnen (die Datei enthaelt die Vermutung nicht, nur Handeingaben).
func viewOldHosts(old []model.Host, inputs map[string]storeEntry) {
	for i := range old {
		e, has := inputs[old[i].IP]
		if has && e.Name != "" && (e.MAC == "" || strings.EqualFold(e.MAC, old[i].MAC)) {
			old[i].Name = clip(e.Name)
		}
		if c := e.Category; has && model.ValidCategory(c) && c != "" {
			old[i].Category = c
		} else {
			old[i].Category = scan.Categorize(old[i])
		}
	}
}

// compareHosts vergleicht zwei Geraetelisten (alt = Datei, cur = aktueller Scan).
func compareHosts(old, cur []model.Host) compareResult {
	res := compareResult{OldCount: len(old), NewCount: len(cur),
		Added: []compareDevice{}, Removed: []compareDevice{}, Changed: []compareChange{}}

	oldByMAC, oldByIP := map[string]int{}, map[string]int{}
	macCount := map[string]int{}
	for _, h := range old {
		macCount[strings.ToLower(h.MAC)]++
	}
	for i, h := range old {
		oldByIP[h.IP] = i
		// Nur eindeutige MACs taugen zur Zuordnung (doppelte MACs = Scheineintraege).
		if m := strings.ToLower(h.MAC); m != "" && macCount[m] == 1 {
			oldByMAC[m] = i
		}
	}
	curMACCount := map[string]int{}
	for _, h := range cur {
		curMACCount[strings.ToLower(h.MAC)]++
	}

	used := make([]bool, len(old)) // welche Datei-Geraete wurden zugeordnet
	for _, h := range cur {
		idx, found := -1, false
		if m := strings.ToLower(h.MAC); m != "" && curMACCount[m] == 1 {
			idx, found = lookup(oldByMAC, m)
		}
		if !found { // Regel 2: gleiche IP, ausser beide haben verschiedene MACs
			if i, okIP := oldByIP[h.IP]; okIP && !used[i] && !macConflict(old[i], h) {
				idx, found = i, true
			}
		}
		if !found || used[idx] {
			res.Added = append(res.Added, toDevice(h))
			continue
		}
		used[idx] = true
		if ch := diffHost(old[idx], h); len(ch) > 0 {
			res.Changed = append(res.Changed, compareChange{IP: h.IP, Name: h.Name, Changes: ch})
		} else {
			res.Same++
		}
	}
	for i, h := range old {
		if !used[i] {
			res.Removed = append(res.Removed, toDevice(h))
		}
	}
	byIP := func(d []compareDevice) {
		sort.Slice(d, func(i, j int) bool { return ipLess(d[i].IP, d[j].IP) })
	}
	byIP(res.Added)
	byIP(res.Removed)
	sort.Slice(res.Changed, func(i, j int) bool { return ipLess(res.Changed[i].IP, res.Changed[j].IP) })
	return res
}

// lookup liest einen Index aus der Map und meldet, ob er existiert.
func lookup(m map[string]int, k string) (int, bool) { i, ok := m[k]; return i, ok }

// macConflict: beide Seiten haben eine MAC, und sie unterscheiden sich
// (dann ist unter derselben IP ein anderes Geraet).
func macConflict(a, b model.Host) bool {
	return a.MAC != "" && b.MAC != "" && !strings.EqualFold(a.MAC, b.MAC)
}

func toDevice(h model.Host) compareDevice {
	return compareDevice{IP: h.IP, Name: h.Name, MAC: h.MAC, Vendor: h.Vendor, Category: h.Category}
}

// diffHost listet die Unterschiede zwischen altem und aktuellem Stand eines Geraets.
func diffHost(o, n model.Host) []string {
	var out []string
	if o.IP != n.IP {
		out = append(out, fmt.Sprintf("IP geändert: %s → %s", o.IP, n.IP))
	}
	for _, f := range []struct{ label, a, b string }{
		{"Name", o.Name, n.Name}, {"Hersteller", o.Vendor, n.Vendor},
		{"System", o.OS, n.OS}, {"Kategorie", o.Category, n.Category},
	} {
		if f.a != f.b {
			out = append(out, fmt.Sprintf("%s geändert: „%s“ → „%s“", f.label, f.a, f.b))
		}
	}
	oldPorts, newPorts := portSet(o), portSet(n)
	for _, p := range sortedKeys(newPorts) {
		if !oldPorts[p] {
			out = append(out, fmt.Sprintf("Port %d neu offen", p))
		}
	}
	for _, p := range sortedKeys(oldPorts) {
		if !newPorts[p] {
			out = append(out, fmt.Sprintf("Port %d nicht mehr offen", p))
		}
	}
	return out
}

func portSet(h model.Host) map[int]bool {
	m := map[int]bool{}
	for _, p := range h.Ports {
		m[p.Number] = true
	}
	return m
}

func sortedKeys(m map[int]bool) []int {
	k := make([]int, 0, len(m))
	for p := range m {
		k = append(k, p)
	}
	sort.Ints(k)
	return k
}
