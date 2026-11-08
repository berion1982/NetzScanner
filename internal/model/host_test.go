package model

import "testing"

// Prueft, dass nur Web-Ports zu Links werden und die URL korrekt aufgebaut ist.
func TestFillWebLinks(t *testing.T) {
	h := Host{IP: "192.168.1.10", Ports: []Port{{Number: 22}, {Number: 5001}, {Number: 80}}}
	h.FillWebLinks()
	if len(h.WebLinks) != 2 {
		t.Fatalf("erwartet 2 Links, bekam %d", len(h.WebLinks))
	}
	if h.WebLinks[0].URL != "http://192.168.1.10:80/" || h.WebLinks[1].URL != "https://192.168.1.10:5001/" {
		t.Errorf("unerwartete URLs: %+v", h.WebLinks)
	}
}

// IPv6 muss in eckigen Klammern stehen, ungueltige IPs ergeben keine Links.
func TestFillWebLinksEdgeCases(t *testing.T) {
	v6 := Host{IP: "fe80::1", Ports: []Port{{Number: 443}}}
	v6.FillWebLinks()
	if len(v6.WebLinks) != 1 || v6.WebLinks[0].URL != "https://[fe80::1]:443/" {
		t.Errorf("IPv6: %+v", v6.WebLinks)
	}
	bad := Host{IP: "evil\"><script>", Ports: []Port{{Number: 80}}}
	bad.FillWebLinks()
	if len(bad.WebLinks) != 0 {
		t.Errorf("ungueltige IP darf keine Links liefern: %+v", bad.WebLinks)
	}
}
