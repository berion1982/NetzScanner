package web

import (
	"encoding/json"
	"net/http"
	"sync"
	"time"
)

// Automatisches Beenden beim Schliessen des Browser-Tabs (I-084).
//
// Jede geoeffnete Seite meldet sich mit einer Zufalls-ID an ("hello") und beim
// Schliessen ab ("bye", per sendBeacon). Sind alle Seiten weg, wartet der Server
// kurz (exitGrace) und beendet das Programm, falls keine neue Seite kommt.
// Die Wartezeit faengt Neuladen (F5) und Tab-Wechsel ab: dabei kommt "bye" und
// gleich danach wieder "hello".
//
// Grenzen (bewusst): Stuerzt der Browser ab oder wird hart beendet, kommt kein "bye";
// dann bleibt das Programm bis zum Klick auf "Beenden" aktiv - lieber zu lange
// laufen als einen Scan zu verlieren.

// exitGrace ist die Wartezeit nach dem letzten "bye" (in Tests verkuerzbar).
var exitGrace = 8 * time.Second

// sessionState merkt sich die offenen Seiten und den Beenden-Zeitgeber.
type sessionState struct {
	mu    sync.Mutex
	tabs  map[string]bool
	timer *time.Timer
}

// handleSessionHello: POST /api/session/hello {id} - Seite meldet sich an.
// Antwort: ob das Programm sich beim Schliessen selbst beendet ("autoExit"),
// damit die Seite vor dem Verlassen warnen kann.
func (s *server) handleSessionHello(w http.ResponseWriter, r *http.Request) {
	id, ok := s.sessionID(w, r)
	if !ok {
		return
	}
	st := &s.sess
	st.mu.Lock()
	if st.tabs == nil {
		st.tabs = map[string]bool{}
	}
	st.tabs[id] = true
	if st.timer != nil { // neue Seite da (z. B. nach F5): geplantes Beenden abbrechen
		st.timer.Stop()
		st.timer = nil
	}
	st.mu.Unlock()
	writeJSON(w, http.StatusOK, map[string]any{"autoExit": s.autoExitOn()})
}

// handleSessionBye: POST /api/session/bye {id} - Seite wurde geschlossen.
func (s *server) handleSessionBye(w http.ResponseWriter, r *http.Request) {
	id, ok := s.sessionID(w, r)
	if !ok {
		return
	}
	st := &s.sess
	st.mu.Lock()
	defer st.mu.Unlock()
	delete(st.tabs, id)
	if s.autoExitOn() && len(st.tabs) == 0 && st.timer == nil {
		st.timer = time.AfterFunc(exitGrace, s.exitIfNoTabs)
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// exitIfNoTabs beendet das Programm, wenn nach der Wartezeit noch keine Seite offen ist.
func (s *server) exitIfNoTabs() {
	st := &s.sess
	st.mu.Lock()
	empty := len(st.tabs) == 0
	st.timer = nil
	st.mu.Unlock()
	if empty && s.opt.Shutdown != nil {
		s.opt.Shutdown()
	}
}

// autoExitOn: Automatik nur, wenn sie gewuenscht ist und es einen Beenden-Weg gibt.
func (s *server) autoExitOn() bool { return s.opt.AutoExit && s.opt.Shutdown != nil }

// sessionID liest die Seiten-ID aus der Anfrage. Nur vom eigenen Rechner (Loopback);
// sonst koennte jemand im Netz das Programm per "bye" abschalten.
func (s *server) sessionID(w http.ResponseWriter, r *http.Request) (string, bool) {
	if !isLoopback(r) {
		writeJSON(w, http.StatusForbidden, errBody("nur von diesem Rechner aus erlaubt"))
		return "", false
	}
	var req struct{ ID string }
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1024)).Decode(&req); err != nil || req.ID == "" || len(req.ID) > 64 {
		writeJSON(w, http.StatusBadRequest, errBody("ungueltige Anfrage"))
		return "", false
	}
	return req.ID, true
}
