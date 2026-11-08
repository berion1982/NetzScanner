package scan

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

// SSDP: lokaler UDP-Server liefert eine LOCATION auf einen lokalen HTTP-Server,
// dessen UPnP-Beschreibung den friendlyName "Wohnzimmer TV" enthaelt.
func TestSSDPName(t *testing.T) {
	web := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`<?xml version="1.0"?><root><device><friendlyName>Wohnzimmer TV</friendlyName></device></root>`))
	}))
	defer web.Close()
	port := udpServer(t, func(req []byte) []byte {
		return []byte("HTTP/1.1 200 OK\r\nLOCATION: " + web.URL + "/desc.xml\r\nST: upnp:rootdevice\r\n\r\n")
	})
	if got := ssdpName(context.Background(), "127.0.0.1", port); got != "Wohnzimmer TV" {
		t.Errorf("ssdpName = %q", got)
	}
}

// SSRF-Schutz: LOCATION auf einen fremden Rechner oder https wird ignoriert.
func TestParseSSDPLocation(t *testing.T) {
	cases := map[string]string{
		"LOCATION: http://192.168.1.5:80/d.xml\r\n": "http://192.168.1.5:80/d.xml",
		"location: http://192.168.1.5/d.xml\r\n":    "http://192.168.1.5/d.xml",
		"LOCATION: http://10.0.0.9/d.xml\r\n":       "", // fremde IP
		"LOCATION: https://192.168.1.5/d.xml\r\n":   "", // kein http
		"LOCATION: http://evil.example/d.xml\r\n":   "",
		"ST: x\r\n": "",
	}
	for in, want := range cases {
		if got := parseSSDPLocation([]byte("HTTP/1.1 200 OK\r\n"+in), "192.168.1.5"); got != want {
			t.Errorf("parseSSDPLocation(%q) = %q, erwartet %q", in, got, want)
		}
	}
}

// friendlyName: Kennungen/IP/kaputtes XML ergeben keinen Namen.
func TestParseFriendlyName(t *testing.T) {
	wrap := func(n string) []byte {
		return []byte("<root><device><friendlyName>" + n + "</friendlyName></device></root>")
	}
	for in, want := range map[string]string{
		"Mediaserver  NAS": "Mediaserver NAS", "001788FFFE476CE2": "", "192.168.1.5": "", "": "",
	} {
		if got := parseFriendlyName(wrap(in)); got != want {
			t.Errorf("parseFriendlyName(%q) = %q, erwartet %q", in, got, want)
		}
	}
	if parseFriendlyName([]byte("<root><device>")) != "" || parseFriendlyName(nil) != "" {
		t.Error("kaputtes XML muss leer ergeben")
	}
}

// LLMNR nutzt das mDNS-Format; ein Server, der nicht antwortet, ergibt "".
func TestLLMNRNoAnswer(t *testing.T) {
	port := udpServer(t, func(req []byte) []byte { return []byte{1, 2, 3} }) // zu kurz
	if got := llmnrName(context.Background(), "127.0.0.1", port); got != "" {
		t.Errorf("llmnrName = %q, erwartet leer", got)
	}
}
