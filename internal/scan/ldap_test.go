package scan

import (
	"strings"
	"testing"
)

// fakeEntry baut eine SearchResultEntry-Antwort wie ein Server.
func fakeEntry(attrs map[string]string) []byte {
	var list []byte
	for k, v := range attrs {
		a := append(berTLV(0x04, []byte(k)), berTLV(0x31, berTLV(0x04, []byte(v)))...)
		list = append(list, berTLV(0x30, a)...)
	}
	entry := append(berTLV(0x04, nil), berTLV(0x30, list)...)
	msg := append(berTLV(0x02, []byte{1}), berTLV(0x64, entry)...)
	return berTLV(0x30, msg)
}

func TestRootDSEBeschreibung(t *testing.T) {
	data := fakeEntry(map[string]string{
		"defaultNamingContext": "DC=corp,DC=example,DC=com",
		"dnsHostName":          "dc1.corp.example.com",
		"domainFunctionality":  "7",
	})
	got := describeRootDSE(parseRootDSE(data))
	for _, w := range []string{"Domäne corp.example.com", "Server dc1.corp.example.com", "Funktionsebene 2016"} {
		if !strings.Contains(got, w) {
			t.Errorf("%q fehlt in %q", w, got)
		}
	}
}

func TestRootDSEKaputt(t *testing.T) {
	// Abgeschnittene/zufaellige Daten duerfen weder Panik noch Ergebnis liefern.
	for _, d := range [][]byte{nil, {0x30}, {0x30, 0x84, 0xff, 0xff, 0xff, 0xff}, []byte("SSH-2.0-x")} {
		if s := describeRootDSE(parseRootDSE(d)); s != "" {
			t.Errorf("erwartet leer, erhalten %q", s)
		}
	}
}

func TestRequestLesbar(t *testing.T) {
	tag, _, rest, ok := berRead(buildRootDSERequest())
	if !ok || tag != 0x30 || len(rest) != 0 {
		t.Fatal("Anfrage ist kein vollstaendiges BER-Element")
	}
}
