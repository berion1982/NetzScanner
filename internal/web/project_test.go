package web

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// Speichern und Wiederladen ergibt dieselbe Geraeteliste; Fremdes in der Datei wird bereinigt.
func TestProjectRoundtrip(t *testing.T) {
	src := NewHandler(Options{Demo: true})
	rec := httptest.NewRecorder()
	src.ServeHTTP(rec, httptest.NewRequest("GET", "/api/project/save", nil))
	if rec.Code != 200 || !strings.Contains(rec.Header().Get("Content-Disposition"), "attachment") {
		t.Fatalf("save: %d %v", rec.Code, rec.Header())
	}
	body := rec.Body.String()
	for _, verboten := range []string{"password", "passwort", "community"} {
		if strings.Contains(strings.ToLower(body), verboten) {
			t.Errorf("Datei enthält %q", verboten)
		}
	}
	dst := NewHandler(Options{})
	load := postJSON(dst, "/api/project/load", body)
	if load.Code != 200 {
		t.Fatalf("load: %d %s", load.Code, load.Body.String())
	}
	a, b := httptest.NewRecorder(), httptest.NewRecorder()
	src.ServeHTTP(a, httptest.NewRequest("GET", "/api/hosts", nil))
	dst.ServeHTTP(b, httptest.NewRequest("GET", "/api/hosts", nil))
	if a.Body.String() != b.Body.String() {
		t.Errorf("Geräteliste nach dem Laden weicht ab")
	}
}

// Ungueltige Dateien werden abgelehnt, ungueltige Einzelwerte bereinigt.
func TestProjectLoadValidation(t *testing.T) {
	h := NewHandler(Options{})
	bad := map[string]string{
		"kein JSON":       `xx`,
		"falsches Format": `{"format":"x","formatVersion":1,"hosts":[{"ip":"192.168.1.1"}]}`,
		"keine Geräte":    `{"format":"netzscanner-scan","formatVersion":1,"hosts":[]}`,
		"nur falsche IP":  `{"format":"netzscanner-scan","formatVersion":1,"hosts":[{"ip":"kein-ip"}]}`,
	}
	for name, body := range bad {
		rec := postJSON(h, "/api/project/load", body)
		if rec.Code != http.StatusBadRequest {
			t.Errorf("%s: %d, erwartet 400", name, rec.Code)
		}
	}
	ok := `{"format":"netzscanner-scan","formatVersion":1,"hosts":[{"ip":"192.168.1.5","name":"a\u0007b","category":"unsinn","pending":true},{"ip":"192.168.1.5"}]}`
	rec := postJSON(h, "/api/project/load", ok)
	if rec.Code != 200 {
		t.Fatalf("load: %d %s", rec.Code, rec.Body.String())
	}
	got := httptest.NewRecorder()
	h.ServeHTTP(got, httptest.NewRequest("GET", "/api/hosts", nil))
	s := got.Body.String()
	if strings.Count(s, `"ip"`) != 1 || strings.Contains(s, "\\u0007") || !strings.Contains(s, `"category":"client"`) || strings.Contains(s, `"pending":true`) {
		t.Errorf("Bereinigung fehlgeschlagen: %s", s)
	}
}
