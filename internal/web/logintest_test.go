package web

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/berion1982/netzscanner/internal/logintest"
	"github.com/berion1982/netzscanner/internal/model"
)

// newLoginServer baut einen Server mit einem Geraet (offener Port 22) fuer die Handler-Tests.
func newLoginServer() *server {
	s := &server{creds: newCredStore(time.Minute)}
	s.hosts = []model.Host{{IP: "192.0.2.10", Ports: []model.Port{{Number: 22}}}}
	return s
}

func postLogin(s *server, remote, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest("POST", "/api/logintest", strings.NewReader(body))
	req.RemoteAddr = remote
	rec := httptest.NewRecorder()
	s.handleLoginTest(rec, req)
	return rec
}

// Von fremden Rechnern wird kein Test ausgeloest.
func TestLoginTestNeedsLoopback(t *testing.T) {
	s := newLoginServer()
	if rec := postLogin(s, "192.168.1.50:5555", `{"ip":"192.0.2.10","method":"ssh","port":22}`); rec.Code != http.StatusForbidden {
		t.Fatalf("403 erwartet, war %d", rec.Code)
	}
}

// Ohne gemerkten Zugang, mit unbekanntem Port/Gerät oder Klartext-HTTP ohne Bestätigung: 400.
func TestLoginTestRejectsBadRequests(t *testing.T) {
	s := newLoginServer()
	for name, body := range map[string]string{
		"kein Zugang":      `{"ip":"192.0.2.10","method":"ssh","port":22}`,
		"Port nicht offen": `{"ip":"192.0.2.10","method":"ssh","port":2222}`,
		"fremde IP":        `{"ip":"192.0.2.99","method":"ssh","port":22}`,
		"Methode":          `{"ip":"192.0.2.10","method":"telnet","port":22}`,
	} {
		if rec := postLogin(s, "127.0.0.1:1", body); rec.Code != http.StatusBadRequest {
			t.Errorf("%s: 400 erwartet, war %d", name, rec.Code)
		}
	}
	s.hosts[0].Ports = append(s.hosts[0].Ports, model.Port{Number: 80})
	s.creds.set("192.0.2.10", "admin", "pw")
	if rec := postLogin(s, "127.0.0.1:1", `{"ip":"192.0.2.10","method":"web","port":80,"scheme":"http"}`); rec.Code != http.StatusBadRequest {
		t.Errorf("Klartext-HTTP ohne Bestaetigung: 400 erwartet, war %d", rec.Code)
	}
}

// Ergebnisse haengen am Zugang: neuer Zugang oder Vergessen loescht sie; Passwort steht nie darin.
func TestLoginResultsFollowCredentials(t *testing.T) {
	cs := newCredStore(time.Minute)
	cs.set("192.0.2.10", "admin", "geheim123")
	cs.setResult("192.0.2.10", logintest.Result{Method: "ssh", Status: logintest.StatusOK})
	if l := cs.list(); len(l) != 1 || len(l[0].Tests) != 1 {
		t.Fatalf("Ergebnis fehlt: %+v", l)
	}
	cs.set("192.0.2.10", "admin", "neu")
	if l := cs.list(); len(l[0].Tests) != 0 {
		t.Fatal("altes Ergebnis nach neuem Zugang")
	}
	cs.setResult("192.0.2.10", logintest.Result{Method: "ssh", Status: logintest.StatusFailed})
	cs.remove("192.0.2.10")
	cs.setResult("192.0.2.10", logintest.Result{Method: "ssh"}) // ohne Zugang wird nichts gemerkt
	if len(cs.results) != 0 {
		t.Fatal("Ergebnis ohne Zugang gemerkt")
	}
}
