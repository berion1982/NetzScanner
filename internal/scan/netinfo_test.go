package scan

import "testing"

// Prueft das Auslesen von resolv.conf: Loopback-Stub und Routing-Domains fallen weg, Doppelte auch.
func TestParseResolvConf(t *testing.T) {
	text := "# Kommentar\nnameserver 127.0.0.53\nnameserver 192.0.2.1\nnameserver 192.0.2.1\nnameserver 192.0.2.2\nsearch lan.example ~.\ndomain corp.example\n"
	s, d := parseResolvConf(text)
	if len(s) != 2 || s[0] != "192.0.2.1" || s[1] != "192.0.2.2" {
		t.Fatalf("DNS-Server falsch: %v", s)
	}
	if len(d) != 2 || d[0] != "lan.example" || d[1] != "corp.example" {
		t.Fatalf("Suchdomaenen falsch: %v", d)
	}
}

// Leere Angaben erscheinen nicht in den Export-Zeilen.
func TestNetInfoLines(t *testing.T) {
	n := NetInfo{IP: "192.0.2.10", Mask: "255.255.255.0", DNS: []string{"192.0.2.1", "192.0.2.2"}}
	l := n.Lines()
	if len(l) != 2 || l[0][1] != "192.0.2.10 / 255.255.255.0" || l[1][1] != "192.0.2.1, 192.0.2.2" {
		t.Fatalf("Zeilen falsch: %v", l)
	}
	if len((NetInfo{}).Lines()) != 0 {
		t.Fatal("leere NetInfo muss leer sein")
	}
}
