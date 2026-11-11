package web

import "net/http"

// handleShutdown: POST /api/shutdown - beendet das Programm (Knopf "Beenden",
// I-083 Teil 2). Noetig, weil die Windows-.exe ohne Konsolenfenster laeuft und
// sonst keinen Weg zum Beenden haette.
//
// Schutz: nur von diesem Rechner (Loopback) - sonst koennte jeder im Netz den
// Scanner abschalten. Der CSRF-Schutz (Content-Type JSON, Origin) greift ueber
// guardPost wie bei allen schreibenden Aufrufen.
func (s *server) handleShutdown(w http.ResponseWriter, r *http.Request) {
	if !isLoopback(r) {
		writeJSON(w, http.StatusForbidden, errBody("Beenden nur von diesem Rechner aus erlaubt"))
		return
	}
	if s.opt.Shutdown == nil {
		writeJSON(w, http.StatusNotImplemented, errBody("Beenden ist in diesem Modus nicht verfügbar"))
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
	// Antwort zuerst abschicken, dann herunterfahren (sonst sieht der Browser einen Abbruch).
	if f, ok := w.(http.Flusher); ok {
		f.Flush()
	}
	go s.opt.Shutdown()
}
