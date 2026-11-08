package dhcp

import (
	"encoding/base64"
	"testing"
)

func TestParseOutput(t *testing.T) {
	json := `[{"scope":"192.168.10.0","reserved":true,"ip":"192.168.10.5","mac":"AA-BB-CC-00-11-22","name":"Drucker\n Büro","state":"Reservation"},
	{"scope":"192.168.10.0","reserved":false,"ip":"192.168.10.77","mac":"AA-BB-CC-00-11-33","name":"pc-7","expires":"2026-11-09 08:00","state":"Active"}]`
	rows, err := ParseOutput(base64.StdEncoding.EncodeToString([]byte(json)) + "\r\n")
	if err != nil || len(rows) != 2 {
		t.Fatalf("rows=%d err=%v", len(rows), err)
	}
	if !rows[0].Reserved || rows[0].Name != "Drucker Büro" { // Steuerzeichen raus, Umlaut bleibt
		t.Errorf("Reservierung: %+v", rows[0])
	}
	if rows[1].Reserved || rows[1].Expires == "" {
		t.Errorf("Lease: %+v", rows[1])
	}
}

func TestParseOutputGarbage(t *testing.T) {
	for _, in := range []string{"", "###", base64.StdEncoding.EncodeToString([]byte("kein json"))} {
		if _, err := ParseOutput(in); err == nil {
			t.Errorf("%q: Fehler erwartet", in)
		}
	}
}
