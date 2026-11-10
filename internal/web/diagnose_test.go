package web

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/berion1982/netzscanner/internal/logintest"
	"github.com/berion1982/netzscanner/internal/model"
)

func postDiag(s *server, ctx context.Context, remote, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest("POST", "/api/diagnose", strings.NewReader(body)).WithContext(ctx)
	req.RemoteAddr = remote
	rec := httptest.NewRecorder()
	s.handleDiagnose(rec, req)
	return rec
}

// Fremde Rechner, unbekannte Geraete und ein laufender Bericht werden abgewiesen.
func TestDiagnoseRejects(t *testing.T) {
	s := &server{creds: newCredStore(time.Minute)}
	s.hosts = []model.Host{{IP: "127.0.0.1"}}
	if rec := postDiag(s, context.Background(), "192.168.1.50:1", `{"ip":"127.0.0.1"}`); rec.Code != http.StatusForbidden {
		t.Errorf("403 erwartet, war %d", rec.Code)
	}
	if rec := postDiag(s, context.Background(), "127.0.0.1:1", `{"ip":"192.0.2.99"}`); rec.Code != http.StatusBadRequest {
		t.Errorf("400 (fremde IP) erwartet, war %d", rec.Code)
	}
	if rec := postDiag(s, context.Background(), "127.0.0.1:1", `kaputt`); rec.Code != http.StatusBadRequest {
		t.Errorf("400 (ungueltig) erwartet, war %d", rec.Code)
	}
	diagBusy.acquire("127.0.0.1")
	defer diagBusy.release("127.0.0.1")
	if rec := postDiag(s, context.Background(), "127.0.0.1:1", `{"ip":"127.0.0.1"}`); rec.Code != http.StatusConflict {
		t.Errorf("409 erwartet, war %d", rec.Code)
	}
}

// Der Bericht enthaelt die gespeicherten Daten und die Login-Ergebnisse - aber nie das Passwort.
// (Der Kontext ist schon abgebrochen, damit keine echten Netzabfragen laufen.)
func TestDiagnoseReportHasNoPassword(t *testing.T) {
	s := &server{creds: newCredStore(time.Minute)}
	s.hosts = []model.Host{{IP: "127.0.0.1", Name: "testgeraet", Vendor: "Beispiel AG", Ports: []model.Port{{Number: 22, Service: "ssh"}}}}
	s.creds.set("127.0.0.1", "admin", "geheimes-passwort")
	s.creds.setResult("127.0.0.1", logintest.Result{Method: "ssh", Port: 22, Status: logintest.StatusFailed, Message: "abgelehnt"})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	rec := postDiag(s, ctx, "127.0.0.1:1", `{"ip":"127.0.0.1"}`)
	body := rec.Body.String()
	if rec.Code != http.StatusOK {
		t.Fatalf("200 erwartet, war %d: %s", rec.Code, body)
	}
	for _, want := range []string{"Geräte-Diagnose", "testgeraet", "Beispiel AG", "Port 22", "ssh Port 22: failed – abgelehnt"} {
		if !strings.Contains(body, want) {
			t.Errorf("fehlt %q im Bericht:\n%s", want, body)
		}
	}
	if strings.Contains(body, "geheimes-passwort") {
		t.Error("Passwort im Bericht!")
	}
	if !strings.HasPrefix(rec.Header().Get("Content-Type"), "text/plain") {
		t.Errorf("Content-Type: %q", rec.Header().Get("Content-Type"))
	}
}
