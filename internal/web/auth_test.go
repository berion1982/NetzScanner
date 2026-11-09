package web

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// get schickt eine GET-Anfrage mit optionalem Cookie/Bearer an den Handler.
func get(h http.Handler, path string, mod func(*http.Request)) *httptest.ResponseRecorder {
	req := httptest.NewRequest("GET", path, nil)
	if mod != nil {
		mod(req)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func TestTokenRequired(t *testing.T) {
	h := NewHandler(Options{Demo: true, Token: "geheim-1234"})

	// Ohne Token: API -> 401 (JSON), Oberflaeche -> 401 mit Eingabeseite.
	if c := get(h, "/api/hosts", nil).Code; c != http.StatusUnauthorized {
		t.Fatalf("API ohne Token: %d, erwartet 401", c)
	}
	if rec := get(h, "/", nil); rec.Code != http.StatusUnauthorized {
		t.Fatalf("Oberflaeche ohne Token: %d, erwartet 401", rec.Code)
	}
	// Falsches Token (URL) und falscher Bearer werden abgelehnt.
	if c := get(h, "/?token=falsch", nil).Code; c != http.StatusUnauthorized {
		t.Fatalf("falsches Token: %d", c)
	}
	if c := get(h, "/api/hosts", func(r *http.Request) { r.Header.Set("Authorization", "Bearer falsch") }).Code; c != http.StatusUnauthorized {
		t.Fatalf("falscher Bearer: %d", c)
	}
}

func TestTokenLoginCookieAndBearer(t *testing.T) {
	h := NewHandler(Options{Demo: true, Token: "geheim-1234"})

	// Anmeldung per URL: Cookie wird gesetzt, Umleitung OHNE Token in der Adresse.
	rec := get(h, "/?token=geheim-1234", nil)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("Login: %d, erwartet 303", rec.Code)
	}
	if loc := rec.Header().Get("Location"); loc != "/" {
		t.Fatalf("Umleitung auf %q, erwartet \"/\" (Token darf nicht in der URL bleiben)", loc)
	}
	cs := rec.Result().Cookies()
	if len(cs) != 1 || !cs[0].HttpOnly || cs[0].SameSite != http.SameSiteStrictMode {
		t.Fatalf("Cookie fehlt oder ist nicht HttpOnly/SameSite=Strict: %+v", cs)
	}

	// Mit Cookie kommt man an die API.
	if c := get(h, "/api/hosts", func(r *http.Request) { r.AddCookie(cs[0]) }).Code; c != http.StatusOK {
		t.Fatalf("API mit Cookie: %d", c)
	}
	// Mit Bearer-Header ebenfalls (Skripte).
	if c := get(h, "/api/hosts", func(r *http.Request) { r.Header.Set("Authorization", "Bearer geheim-1234") }).Code; c != http.StatusOK {
		t.Fatalf("API mit Bearer: %d", c)
	}
}

func TestNoTokenMeansOpen(t *testing.T) {
	// Reiner Loopback-Betrieb: kein Token konfiguriert -> alles wie bisher.
	if c := get(NewHandler(Options{Demo: true}), "/api/hosts", nil).Code; c != http.StatusOK {
		t.Fatalf("ohne Token-Konfiguration: %d, erwartet 200", c)
	}
}

func TestIsLoopbackListen(t *testing.T) {
	cases := map[string]bool{
		"127.0.0.1:8484": true, "localhost:8484": true, "[::1]:8484": true,
		"0.0.0.0:8484": false, ":8484": false, "[::]:8484": false,
		"192.168.1.5:8484": false, "meinhost:8484": false, "kaputt": false,
	}
	for addr, want := range cases {
		if got := IsLoopbackListen(addr); got != want {
			t.Errorf("IsLoopbackListen(%q) = %v, erwartet %v", addr, got, want)
		}
	}
}

func TestNewTokenUnique(t *testing.T) {
	a, err1 := NewToken()
	b, err2 := NewToken()
	if err1 != nil || err2 != nil || len(a) != 32 || a == b {
		t.Fatalf("Token unbrauchbar: %q %q %v %v", a, b, err1, err2)
	}
}
