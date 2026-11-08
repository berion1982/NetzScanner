package web

import (
	"testing"

	"github.com/berion1982/netzscanner/internal/dhcp"
	"github.com/berion1982/netzscanner/internal/model"
	"github.com/berion1982/netzscanner/internal/router"
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

// Reiter "Reservierungen": nur feste Reservierungen, numerisch sortiert, Scan-Name ueber die MAC.
func TestReservationsList(t *testing.T) {
	s := &server{
		hosts: []model.Host{{IP: "10.0.0.10", MAC: "AA:BB:CC:00:11:22", Name: "Drucker", Known: true}},
		dhcpRows: []dhcp.Entry{
			{Scope: "10.0.0.0", IP: "10.0.0.10", MAC: "AA-BB-CC-00-11-22", Name: "drucker-dhcp", Reserved: true},
			{Scope: "10.0.0.0", IP: "10.0.0.9", MAC: "AA-BB-CC-00-11-33", Name: "nas", Reserved: true},
			{Scope: "10.0.0.0", IP: "10.0.0.77", MAC: "AA-BB-CC-00-11-44", Name: "lease-only"}, // kein Lease in der Liste
		},
	}
	got := s.reservations()
	if len(got) != 2 || got[0].IP != "10.0.0.9" || got[1].IP != "10.0.0.10" {
		t.Fatalf("Reihenfolge/Auswahl: %+v", got)
	}
	if got[1].ScanName != "Drucker" || got[0].ScanName != "" {
		t.Errorf("Scan-Namen: %+v", got)
	}
}

// FRITZ!Box: Geraete mit "Static" erscheinen in der Liste - auch offline ohne IP; "DHCP" nicht;
// der Windows-Server hat bei gleicher MAC Vorrang.
func TestReservationsFromRouter(t *testing.T) {
	s := &server{
		routerHosts: []router.Host{
			{Name: "nas", IP: "192.168.178.20", MAC: "AA:BB:CC:00:11:22", Source: "Static"},
			{Name: "handy", IP: "192.168.178.30", MAC: "AA:BB:CC:00:11:33", Source: "DHCP"},
			{Name: "doppelt", IP: "192.168.178.40", MAC: "AA:BB:CC:00:11:44", Source: "Static"},
			{Name: "offline-geraet", IP: "", MAC: "AA:BB:CC:00:11:55", Source: "Static"},
		},
		dhcpRows: []dhcp.Entry{{Scope: "192.168.178.0", IP: "192.168.178.40", MAC: "AA-BB-CC-00-11-44", Name: "doppelt-win", Reserved: true}},
	}
	got := s.reservations()
	if len(got) != 3 {
		t.Fatalf("erwartet 3 Eintraege, bekam %+v", got)
	}
	names := map[string]bool{}
	for _, r := range got {
		names[r.Name] = true
	}
	if !names["nas"] || !names["offline-geraet"] || !names["doppelt-win"] || names["handy"] || names["doppelt"] {
		t.Errorf("falsche Auswahl: %+v", got)
	}
}
