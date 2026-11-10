package web

// Zugangsdaten je Geraet (I-020): Benutzer/Passwort fuer spaetere Login-Tests (I-022).
//
// Sicherheitsregeln (siehe IDEAS.md, Hinweise zu I-020/I-022):
//   - Nur im Arbeitsspeicher: nie auf Platte (auch nicht in der Eingaben-Datei, I-016),
//     nie in Projekt-/Scan-Dateien, nie in Exporten, nie in Logs oder Fehlermeldungen.
//   - Eingabe nur von diesem Rechner aus (Loopback). Bei "--listen 0.0.0.0" ist HTTP
//     unverschluesselt -> dort wird die Eingabe gesperrt.
//   - Die API gibt Passwoerter NIE zurueck, nur "gesetzt ja/nein" und die Restzeit.
//   - Automatisches Vergessen nach Inaktivitaet (credIdleTimeout), per Knopf (einzeln/alle)
//     und beim Laden eines Projekts / "Eingaben loeschen". Beim Beenden des Programms
//     verschwindet der Arbeitsspeicher ohnehin.
//   - Das Passwort liegt als []byte vor und wird beim Loeschen mit Nullen ueberschrieben
//     (Best Effort: Go kann Kopien im Speicher nicht vollstaendig ausschliessen).

import (
	"encoding/json"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/berion1982/netzscanner/internal/logintest"
)

// credIdleTimeout: Nach so langer Zeit ohne Nutzung werden Zugangsdaten vergessen.
const credIdleTimeout = 15 * time.Minute

// cred ist ein gemerkter Zugang zu einem Geraet.
type cred struct {
	user     string
	password []byte
	lastUse  time.Time // letzte Eingabe oder Nutzung (Start der Inaktivitaetsfrist)
}

// credStore haelt die Zugangsdaten (IP -> Zugang). Eigener Mutex, damit er nie mit s.mu verklemmt.
type credStore struct {
	mu      sync.Mutex
	items   map[string]*cred
	results map[string]map[string]logintest.Result // IP -> Methode -> letztes Test-Ergebnis (I-022, ohne Passwort)
	timeout time.Duration
	now     func() time.Time // austauschbar fuer Tests
}

// newCredStore legt einen leeren Speicher an.
func newCredStore(timeout time.Duration) *credStore {
	return &credStore{items: map[string]*cred{}, results: map[string]map[string]logintest.Result{}, timeout: timeout, now: time.Now}
}

// wipe ueberschreibt das Passwort mit Nullen.
func (c *cred) wipe() {
	for i := range c.password {
		c.password[i] = 0
	}
	c.password = nil
}

// expireLocked entfernt abgelaufene Eintraege (Aufrufer haelt c.mu).
func (cs *credStore) expireLocked() {
	for ip, c := range cs.items {
		if cs.now().Sub(c.lastUse) >= cs.timeout {
			c.wipe()
			delete(cs.items, ip)
			delete(cs.results, ip)
		}
	}
}

// set merkt Benutzer/Passwort fuer eine IP (ersetzt einen alten Eintrag).
func (cs *credStore) set(ip, user, password string) {
	cs.mu.Lock()
	defer cs.mu.Unlock()
	cs.expireLocked()
	if old := cs.items[ip]; old != nil {
		old.wipe()
	}
	cs.items[ip] = &cred{user: user, password: []byte(password), lastUse: cs.now()}
	delete(cs.results, ip) // Ergebnisse gehoerten zum alten Zugang
}

// setResult merkt das letzte Test-Ergebnis (nur solange der Zugang existiert).
func (cs *credStore) setResult(ip string, r logintest.Result) {
	cs.mu.Lock()
	defer cs.mu.Unlock()
	if cs.items[ip] == nil {
		return
	}
	if cs.results[ip] == nil {
		cs.results[ip] = map[string]logintest.Result{}
	}
	cs.results[ip][r.Method] = r
}

// get liefert den Zugang fuer I-022 (Login-Test) und setzt die Inaktivitaetsfrist neu.
// Das Passwort verlaesst den Speicher nur ueber diese Funktion - nie ueber die HTTP-API.
func (cs *credStore) get(ip string) (user, password string, ok bool) {
	cs.mu.Lock()
	defer cs.mu.Unlock()
	cs.expireLocked()
	c := cs.items[ip]
	if c == nil {
		return "", "", false
	}
	c.lastUse = cs.now()
	return c.user, string(c.password), true
}

// remove vergisst den Zugang einer IP; ip == "" vergisst alle.
func (cs *credStore) remove(ip string) {
	if cs == nil { // Server ohne Zugangsspeicher (z. B. in Tests direkt gebaut)
		return
	}
	cs.mu.Lock()
	defer cs.mu.Unlock()
	for k, c := range cs.items {
		if ip == "" || k == ip {
			c.wipe()
			delete(cs.items, k)
		}
	}
	// Ein Ergebnis gilt nur zu dem Zugang, mit dem es entstand -> mit vergessen.
	for k := range cs.results {
		if ip == "" || k == ip {
			delete(cs.results, k)
		}
	}
}

// credInfo ist die einzige Sicht, die nach aussen geht: KEIN Passwort.
type credInfo struct {
	IP         string `json:"ip"`
	User       string `json:"user"`
	ExpiresSec int    `json:"expiresSec"` // Restzeit bis zum automatischen Vergessen
	// Tests: letzte Login-Test-Ergebnisse (I-022) zu diesem Zugang, ohne Passwort.
	Tests []logintest.Result `json:"tests,omitempty"`
}

// list liefert die gemerkten Zugaenge ohne Passwoerter, sortiert nach IP.
func (cs *credStore) list() []credInfo {
	cs.mu.Lock()
	defer cs.mu.Unlock()
	cs.expireLocked()
	out := make([]credInfo, 0, len(cs.items))
	for ip, c := range cs.items {
		left := cs.timeout - cs.now().Sub(c.lastUse)
		info := credInfo{IP: ip, User: c.user, ExpiresSec: int(left.Seconds())}
		for _, r := range cs.results[ip] {
			info.Tests = append(info.Tests, r)
		}
		sort.Slice(info.Tests, func(i, j int) bool { return info.Tests[i].Method < info.Tests[j].Method })
		out = append(out, info)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].IP < out[j].IP })
	return out
}

// handleCredsList: GET /api/creds - Liste ohne Passwoerter plus Hinweis, ob die Eingabe hier erlaubt ist.
func (s *server) handleCredsList(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, map[string]any{
		"allowed":     isLoopback(r),
		"timeoutSec":  int(s.creds.timeout.Seconds()),
		"credentials": s.creds.list(),
	})
}

// handleCredsSet: POST /api/creds {ip, user, password} - nur lokal; Geraet muss in der Liste stehen.
func (s *server) handleCredsSet(w http.ResponseWriter, r *http.Request) {
	if !isLoopback(r) {
		writeJSON(w, http.StatusForbidden, errBody("Zugangsdaten nur von diesem Rechner aus erlaubt (HTTP im Netz ist unverschlüsselt)"))
		return
	}
	var req struct{ IP, User, Password string }
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8192)).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, errBody("ungueltige Anfrage"))
		return
	}
	req.IP = strings.TrimSpace(req.IP)
	if !okCredential(req.User, false) || !okCredential(req.Password, true) {
		writeJSON(w, http.StatusBadRequest, errBody("Benutzer fehlt oder Eingabe enthält unzulässige Zeichen"))
		return
	}
	s.mu.Lock()
	found := false
	for _, h := range s.hosts {
		if h.IP == req.IP {
			found = true
			break
		}
	}
	s.mu.Unlock()
	if !found {
		writeJSON(w, http.StatusBadRequest, errBody("Gerät nicht in der Liste"))
		return
	}
	s.creds.set(req.IP, req.User, req.Password)
	req.Password = "" // so frueh wie moeglich vergessen
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

// handleCredsDelete: POST /api/creds/delete {ip} - ohne IP werden alle Zugaenge vergessen.
func (s *server) handleCredsDelete(w http.ResponseWriter, r *http.Request) {
	var req struct{ IP string }
	_ = json.NewDecoder(http.MaxBytesReader(w, r.Body, 1024)).Decode(&req)
	s.creds.remove(strings.TrimSpace(req.IP))
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}
