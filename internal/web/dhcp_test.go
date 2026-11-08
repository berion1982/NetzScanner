package web

import (
	"testing"

	"github.com/berion1982/netzscanner/internal/dhcp"
	"github.com/berion1982/netzscanner/internal/model"
)

// Reservierung hat Vorrang vor Lease; Eintraege ohne Scan-Treffer landen in "onlyDHCP".
func TestMatchDHCP(t *testing.T) {
	hosts := []model.Host{{IP: "10.0.0.5", MAC: "AA:BB:CC:00:11:22"}, {IP: "10.0.0.6", MAC: "AA:BB:CC:00:11:33"}}
	rows := []dhcp.Entry{
		{IP: "10.0.0.5", MAC: "AA-BB-CC-00-11-22", Name: "drucker", Expires: "2026-11-09 08:00"},
		{IP: "10.0.0.5", MAC: "AA-BB-CC-00-11-22", Name: "Drucker Büro", Reserved: true},
		{IP: "10.0.0.99", MAC: "AA-BB-CC-00-99-99", Name: "unbekannt-im-scan"},
		{IP: "10.0.0.1", MAC: "kaputt"},
	}
	info, res := matchDHCP(rows, hosts)
	if e := info["aabbcc001122"]; !e.Reserved || e.Name != "Drucker Büro" || e.Label() != "feste Reservierung" {
		t.Errorf("Eintrag: %+v", e)
	}
	if res.Entries != 3 || res.Reserved != 1 || res.Matched != 1 || len(res.Only) != 1 {
		t.Errorf("Ergebnis: %+v", res)
	}
}
