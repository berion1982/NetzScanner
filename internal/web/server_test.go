package web

import (
	"net"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"
)

// Startseite und API muessen antworten; die Demo-Daten enthalten Web-Links.
func TestHandlerDemo(t *testing.T) {
	h := NewHandler(Options{Demo: true})
	for path, want := range map[string]string{"/": "NetzScanner", "/api/hosts": "webLinks", "/api/version": "buildDate", "/api/scan": "running"} {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest("GET", path, nil))
		if rec.Code != 200 || !strings.Contains(rec.Body.String(), want) {
			t.Errorf("%s: Status %d, enthaelt %q nicht", path, rec.Code, want)
		}
	}
}

// Ohne Demo-Modus ist die Liste leer ("[]", nicht "null").
func TestHostsEmpty(t *testing.T) {
	rec := httptest.NewRecorder()
	NewHandler(Options{}).ServeHTTP(rec, httptest.NewRequest("GET", "/api/hosts", nil))
	if strings.TrimSpace(rec.Body.String()) != "[]" {
		t.Errorf("erwartet [], bekam %q", rec.Body.String())
	}
}

// POST-Schutz: ohne JSON-Content-Type und mit fremdem Origin wird abgelehnt.
func TestPostGuard(t *testing.T) {
	h := NewHandler(Options{})
	r := httptest.NewRequest("POST", "/api/scan", strings.NewReader(`{"target":"127.0.0.1"}`))
	r.Header.Set("Content-Type", "text/plain")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)
	if rec.Code != 415 {
		t.Errorf("text/plain: Status %d (erwartet 415)", rec.Code)
	}
	r = httptest.NewRequest("POST", "/api/scan", strings.NewReader(`{"target":"127.0.0.1"}`))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Origin", "http://evil.example")
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, r)
	if rec.Code != 403 {
		t.Errorf("fremder Origin: Status %d (erwartet 403)", rec.Code)
	}
}

// Ungueltige/oeffentliche Ziele werden sofort mit 400 abgelehnt.
func TestStartRejectsBadTarget(t *testing.T) {
	h := NewHandler(Options{})
	for _, body := range []string{`{"target":"8.8.8.8"}`, `{"target":"x"}`, `{"target":"127.0.0.1","ports":"99999"}`} {
		r := httptest.NewRequest("POST", "/api/scan", strings.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, r)
		if rec.Code != 400 {
			t.Errorf("%s: Status %d (erwartet 400)", body, rec.Code)
		}
	}
}

// Kompletter Ablauf: Scan starten, warten bis fertig, Ergebnis abrufen.
func TestScanFlow(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()
	port := ln.Addr().(*net.TCPAddr).Port

	h := NewHandler(Options{})
	r := httptest.NewRequest("POST", "/api/scan", strings.NewReader(`{"target":"127.0.0.1","ports":"`+strconv.Itoa(port)+`"}`))
	r.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)
	if rec.Code != 202 {
		t.Fatalf("Start: Status %d, %s", rec.Code, rec.Body.String())
	}
	for i := 0; i < 100; i++ { // bis zu 10 s warten
		rec = httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest("GET", "/api/scan", nil))
		if strings.Contains(rec.Body.String(), `"running":false`) {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "/api/hosts", nil))
	if !strings.Contains(rec.Body.String(), "127.0.0.1") || !strings.Contains(rec.Body.String(), strconv.Itoa(port)) {
		t.Errorf("Ergebnis enthaelt Host/Port nicht: %s", rec.Body.String())
	}
}
