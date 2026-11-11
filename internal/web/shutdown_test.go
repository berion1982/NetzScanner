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

// postJSONFrom schickt einen JSON-POST an einen Pfad mit Absenderadresse.
func postJSONFrom(h http.Handler, path, remote, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest("POST", path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.RemoteAddr = remote
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

// Tab-Schliessen (I-084): Beenden erst nach der Wartezeit und nur, wenn kein Tab mehr offen ist.
func TestAutoExitOnTabClose(t *testing.T) {
	old := exitGrace
	exitGrace = 100 * time.Millisecond
	defer func() { exitGrace = old }()

	called := make(chan struct{}, 4)
	h := NewHandler(Options{Demo: true, AutoExit: true, Shutdown: func() { called <- struct{}{} }})
	lo := "127.0.0.1:1"
	hello := func(id string) { postJSONFrom(h, "/api/session/hello", lo, `{"id":"`+id+`"}`) }
	bye := func(id string) { postJSONFrom(h, "/api/session/bye", lo, `{"id":"`+id+`"}`) }

	// Fremder Rechner darf nichts ausloesen.
	if c := postJSONFrom(h, "/api/session/bye", "10.0.0.5:1", `{"id":"a"}`).Code; c != http.StatusForbidden {
		t.Fatalf("fremd: %d", c)
	}
	// Zwei Tabs: erster zu -> kein Beenden.
	hello("a")
	hello("b")
	bye("a")
	select {
	case <-called:
		t.Fatal("beendet, obwohl noch ein Tab offen ist")
	case <-time.After(300 * time.Millisecond):
	}
	// Neuladen: bye, dann sofort hello -> kein Beenden.
	bye("b")
	hello("b2")
	select {
	case <-called:
		t.Fatal("beendet trotz Neuladen")
	case <-time.After(300 * time.Millisecond):
	}
	// Letzter Tab zu -> Beenden nach der Wartezeit.
	bye("b2")
	select {
	case <-called:
	case <-time.After(2 * time.Second):
		t.Fatal("nicht beendet nach Schliessen des letzten Tabs")
	}
}

// Ohne AutoExit (z. B. --keep-running, --no-browser) bleibt das Programm immer an.
func TestAutoExitAus(t *testing.T) {
	old := exitGrace
	exitGrace = 50 * time.Millisecond
	defer func() { exitGrace = old }()
	called := make(chan struct{}, 1)
	h := NewHandler(Options{Demo: true, Shutdown: func() { called <- struct{}{} }})
	postJSONFrom(h, "/api/session/hello", "127.0.0.1:1", `{"id":"a"}`)
	postJSONFrom(h, "/api/session/bye", "127.0.0.1:1", `{"id":"a"}`)
	select {
	case <-called:
		t.Fatal("beendet trotz ausgeschalteter Automatik")
	case <-time.After(300 * time.Millisecond):
	}
}
