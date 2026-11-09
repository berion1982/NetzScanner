package scan

import (
	"net"
	"testing"
)

// makeOffer baut ein Beispiel-DHCPOFFER eines Servers fuer die Tests.
func makeOffer(xid []byte, server string) []byte {
	p := make([]byte, dhcpHeaderLen)
	p[0] = 2
	copy(p[4:8], xid)
	copy(p[16:20], net.ParseIP("192.168.1.50").To4())
	p = append(p, 99, 130, 83, 99, 53, 1, dhcpOffer)
	p = append(p, 54, 4)
	p = append(p, net.ParseIP(server).To4()...)
	p = append(p, 1, 4, 255, 255, 255, 0, 3, 4, 192, 168, 1, 1, 6, 8, 1, 1, 1, 1, 8, 8, 8, 8)
	p = append(p, 51, 4, 0, 0, 0x0e, 0x10, 255)
	return p
}

func TestParseOffer(t *testing.T) {
	xid := []byte{1, 2, 3, 4}
	o, ok := parseOffer(makeOffer(xid, "192.168.1.1"), xid)
	if !ok || o.ServerID != "192.168.1.1" || o.OfferedIP != "192.168.1.50" ||
		o.Mask != "255.255.255.0" || o.Router != "192.168.1.1" || len(o.DNS) != 2 || o.LeaseSecs != 3600 {
		t.Fatalf("unerwartetes Ergebnis: %+v ok=%v", o, ok)
	}
}

func TestParseOfferRejects(t *testing.T) {
	xid := []byte{1, 2, 3, 4}
	pkt := makeOffer(xid, "192.168.1.1")
	if _, ok := parseOffer(pkt, []byte{9, 9, 9, 9}); ok {
		t.Error("fremde xid darf nicht akzeptiert werden")
	}
	if _, ok := parseOffer(pkt[:100], xid); ok {
		t.Error("zu kurzes Paket darf nicht akzeptiert werden")
	}
	pkt[240+2] = 5 // Nachrichtentyp ACK statt OFFER
	if _, ok := parseOffer(pkt, xid); ok {
		t.Error("kein OFFER darf nicht akzeptiert werden")
	}
	// Abgeschnittene Option darf nicht zu Panik fuehren.
	bad := append(makeOffer(xid, "192.168.1.1")[:244], 54, 200)
	_, _ = parseOffer(bad, xid)
}

func TestBuildProbeResult(t *testing.T) {
	if r := buildProbeResult(map[string]DHCPOffer{}); !r.Checked || r.Multi || len(r.Servers) != 0 {
		t.Errorf("leer: %+v", r)
	}
	two := map[string]DHCPOffer{"10.0.0.2": {ServerID: "10.0.0.2"}, "10.0.0.1": {ServerID: "10.0.0.1"}}
	r := buildProbeResult(two)
	if !r.Multi || r.Servers[0].ServerID != "10.0.0.1" {
		t.Errorf("zwei Server: %+v", r)
	}
}

func TestBuildDiscover(t *testing.T) {
	p := buildDiscover([]byte{1, 2, 3, 4}, []byte{2, 0, 0, 0, 0, 1})
	if p[0] != 1 || p[236] != 99 || p[len(p)-1] != 255 {
		t.Error("DISCOVER-Aufbau falsch")
	}
}
