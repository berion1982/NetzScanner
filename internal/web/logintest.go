package web

// Login-Test je Geraet (I-022): prueft mit dem gemerkten Zugang (I-020), ob die Anmeldung
// per SSH oder Web (HTTP-Basic) funktioniert. Die eigentliche Pruefung steht in
// internal/logintest; hier liegen nur die Schutzregeln der HTTP-Schnittstelle.
//
// Regeln (IDEAS.md, Hinweise zu I-020/I-022):
//   - nur von diesem Rechner aus (Loopback) - das Passwort wird zwar nicht uebertragen,
//     aber ein Test soll nicht von fremden Rechnern im Netz ausgeloest werden koennen;
//   - nur Geraete aus der Scan-Liste und nur Ports, die der Scan als offen gefunden hat
//     (der Test ist kein allgemeiner Port-/Verbindungsdienst);
//   - pro Klick genau ein Versuch; parallele Tests desselben Geraets werden abgewiesen;
//   - Hostkey/Zertifikat nie still ignorieren: erst Fingerabdruck bestaetigen lassen;
//   - unverschluesseltes HTTP nur auf ausdrueckliche Bestaetigung ("allowPlain").

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/berion1982/netzscanner/internal/logintest"
)

// loginBusy merkt Geraete, mit denen gerade ein Test laeuft (gegen Doppelklicks/Fehlversuche).
var loginBusy sync.Map

// handleLoginTest: POST /api/logintest {ip, method, port, scheme, fingerprint, allowPlain}
func (s *server) handleLoginTest(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if !isLoopback(r) {
		writeJSON(w, http.StatusForbidden, errBody("Login-Tests nur von diesem Rechner aus erlaubt"))
		return
	}
	var req struct {
		IP, Method, Scheme, Fingerprint string
		Port                            int
		AllowPlain                      bool
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, errBody("ungueltige Anfrage"))
		return
	}
	req.IP = strings.TrimSpace(req.IP)
	if req.Method != logintest.MethodSSH && req.Method != logintest.MethodWeb {
		writeJSON(w, http.StatusBadRequest, errBody("Unbekannte Methode"))
		return
	}
	if !s.hostHasOpenPort(req.IP, req.Port) {
		writeJSON(w, http.StatusBadRequest, errBody("Gerät oder Port nicht in den Scan-Ergebnissen (Port muss als offen gefunden sein)"))
		return
	}
	if req.Method == logintest.MethodWeb {
		if req.Scheme != "http" && req.Scheme != "https" {
			writeJSON(w, http.StatusBadRequest, errBody("Schema muss http oder https sein"))
			return
		}
		if req.Scheme == "http" && !req.AllowPlain {
			writeJSON(w, http.StatusBadRequest, errBody("Unverschlüsseltes HTTP sendet das Passwort im Klartext und muss ausdrücklich bestätigt werden"))
			return
		}
	}
	user, password, ok := s.creds.get(req.IP)
	if !ok {
		writeJSON(w, http.StatusBadRequest, errBody("Erst Zugangsdaten für dieses Gerät merken"))
		return
	}
	if _, busy := loginBusy.LoadOrStore(req.IP, true); busy {
		writeJSON(w, http.StatusConflict, errBody("Für dieses Gerät läuft gerade ein Test"))
		return
	}
	defer loginBusy.Delete(req.IP)

	ctx, cancel := context.WithTimeout(r.Context(), 25*time.Second)
	defer cancel()
	var res logintest.Result
	if req.Method == logintest.MethodSSH {
		res = logintest.SSH(ctx, req.IP, req.Port, user, password, strings.TrimSpace(req.Fingerprint))
	} else {
		res = logintest.Web(ctx, req.IP, req.Port, req.Scheme, user, password, strings.TrimSpace(req.Fingerprint))
	}
	password = "" // so frueh wie moeglich vergessen
	// Ergebnisse "confirm" sind noch kein Test-Ergebnis - nur echte Ausgaenge in der Liste merken.
	if res.Status != logintest.StatusConfirm {
		s.creds.setResult(req.IP, res)
	}
	writeJSON(w, http.StatusOK, res)
}

// hostHasOpenPort prueft, ob die IP in der Liste steht und der Scan den Port als offen gefunden hat.
func (s *server) hostHasOpenPort(ip string, port int) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, h := range s.hosts {
		if h.IP != ip {
			continue
		}
		for _, p := range h.Ports {
			if p.Number == port {
				return true
			}
		}
	}
	return false
}
