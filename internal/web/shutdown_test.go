package web

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// post schickt einen JSON-POST mit frei waehlbarer Absenderadresse.
func postShutdown(h http.Handler, remote string) *httptest.ResponseRecorder {
	req := httptest.NewRequest("POST", "/api/shutdown", strings.NewReader("{}"))
	req.Header.Set("Content-Type", "application/json")
	req.RemoteAddr = remote
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

// Beenden: lokal erlaubt, aus dem Netz verboten, ohne Callback "nicht verfuegbar".
func TestShutdown(t *testing.T) {
	called := make(chan struct{}, 1)
	h := NewHandler(Options{Demo: true, Shutdown: func() { called <- struct{}{} }})

	if c := postShutdown(h, "192.168.1.50:5555").Code; c != http.StatusForbidden {
		t.Fatalf("fremder Rechner: %d, erwartet 403", c)
	}
	select {
	case <-called:
		t.Fatal("Shutdown wurde fuer fremden Rechner ausgeloest")
	case <-time.After(100 * time.Millisecond):
	}

	if c := postShutdown(h, "127.0.0.1:5555").Code; c != http.StatusOK {
		t.Fatalf("lokal: %d, erwartet 200", c)
	}
	select {
	case <-called:
	case <-time.After(time.Second):
		t.Fatal("Shutdown wurde lokal nicht ausgeloest")
	}

	h2 := NewHandler(Options{Demo: true})
	if c := postShutdown(h2, "127.0.0.1:5555").Code; c != http.StatusNotImplemented {
		t.Fatalf("ohne Callback: %d, erwartet 501", c)
	}
}
