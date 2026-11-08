package web

import (
	"net/http/httptest"
	"strings"
	"testing"
)

// Startseite und API muessen antworten; die Demo-Daten enthalten Web-Links.
func TestHandler(t *testing.T) {
	h := NewHandler()
	for path, want := range map[string]string{"/": "NetzScanner", "/api/hosts": "webLinks", "/api/version": "buildDate"} {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest("GET", path, nil))
		if rec.Code != 200 || !strings.Contains(rec.Body.String(), want) {
			t.Errorf("%s: Status %d, enthaelt %q nicht", path, rec.Code, want)
		}
	}
}
