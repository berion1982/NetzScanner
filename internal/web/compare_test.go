package web

import (
	"strings"
	"testing"

	"github.com/berion1982/netzscanner/internal/model"
)

// Neu, weg, geaendert und "IP gewechselt" werden korrekt erkannt.
func TestCompareHosts(t *testing.T) {
	old := []model.Host{
		{IP: "10.0.0.1", MAC: "aa:aa:aa:aa:aa:01", Name: "router", Ports: []model.Port{{Number: 80}}},
		{IP: "10.0.0.2", MAC: "aa:aa:aa:aa:aa:02", Name: "pc"},
		{IP: "10.0.0.3", MAC: "aa:aa:aa:aa:aa:03", Name: "weg"},
	}
	cur := []model.Host{
		{IP: "10.0.0.1", MAC: "aa:aa:aa:aa:aa:01", Name: "router", Ports: []model.Port{{Number: 80}, {Number: 443}}},
		{IP: "10.0.0.9", MAC: "aa:aa:aa:aa:aa:02", Name: "pc"},    // andere IP, gleiche MAC
		{IP: "10.0.0.3", MAC: "bb:bb:bb:bb:bb:03", Name: "fremd"}, // gleiche IP, andere MAC = anderes Geraet
	}
	r := compareHosts(old, cur)
	if len(r.Added) != 1 || r.Added[0].Name != "fremd" {
		t.Errorf("Added: %+v", r.Added)
	}
	if len(r.Removed) != 1 || r.Removed[0].Name != "weg" {
		t.Errorf("Removed: %+v", r.Removed)
	}
	if len(r.Changed) != 2 || r.Same != 0 {
		t.Fatalf("Changed: %+v same=%d", r.Changed, r.Same)
	}
	if !strings.Contains(strings.Join(r.Changed[0].Changes, ";"), "Port 443 neu offen") {
		t.Errorf("Port-Änderung fehlt: %+v", r.Changed[0])
	}
	if !strings.Contains(strings.Join(r.Changed[1].Changes, ";"), "IP geändert") {
		t.Errorf("IP-Wechsel fehlt: %+v", r.Changed[1])
	}
}

// Derselbe Scan gegen sich selbst ergibt keine Unterschiede (Demo-Daten, ueber die API).
func TestCompareAPISelf(t *testing.T) {
	src := NewHandler(Options{Demo: true})
	save := get(src, "/api/project/save", nil)
	rec := postJSON(src, "/api/project/compare", save.Body.String())
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), `"added":[]`) || !strings.Contains(rec.Body.String(), `"changed":[]`) {
		t.Fatalf("compare: %d %s", rec.Code, rec.Body.String())
	}
	if bad := postJSON(src, "/api/project/compare", `{"format":"x"}`); bad.Code != 400 {
		t.Errorf("ungültige Datei: %d", bad.Code)
	}
}
