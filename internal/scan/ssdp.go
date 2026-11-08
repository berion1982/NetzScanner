package scan

import (
	"context"
	"encoding/xml"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Weitere Namensquellen (I-008), beide ohne Sonderrechte, Unicast direkt an die IP:
//   - LLMNR (UDP 5355): Windows-Rechner und manche Linux-Geraete; gleiches Format wie mDNS.
//   - SSDP/UPnP (UDP 1900): Fernseher, Router, Mediaserver, Drucker. Das Geraet
//     antwortet mit einer LOCATION-URL; dort steht in der Beschreibung (XML) der
//     "friendlyName" (z.B. "Wohnzimmer-TV").
// Nicht umgesetzt (offen in IDEAS.md): SNMP sysName, HTTP-Server-Header.

const (
	llmnrPort = 5355
	ssdpPort  = 1900
)

// llmnrName fragt das Geraet per LLMNR nach dem Namen seiner IP (Reverse-PTR).
func llmnrName(ctx context.Context, ip string, port int) string {
	return ptrName(ctx, ip, port)
}

// ssdpSearch ist die M-SEARCH-Anfrage. "ssdp:all" bringt jedes Geraet zum Antworten;
// MX=1 sagt dem Geraet, es solle hoechstens 1 s warten (wir fragen ja direkt).
const ssdpSearch = "M-SEARCH * HTTP/1.1\r\n" +
	"HOST: 239.255.255.250:1900\r\n" +
	"MAN: \"ssdp:discover\"\r\n" +
	"MX: 1\r\n" +
	"ST: ssdp:all\r\n\r\n"

// parseSSDPLocation holt die LOCATION-URL aus der SSDP-Antwort. Nur http-URLs, deren
// Rechner exakt die abgefragte IP ist: So kann ein manipuliertes Geraet uns nicht
// dazu bringen, andere Rechner abzufragen (SSRF-Schutz).
func parseSSDPLocation(resp []byte, ip string) string {
	for _, line := range strings.Split(string(resp), "\r\n") {
		key, val, ok := strings.Cut(line, ":")
		if !ok || !strings.EqualFold(strings.TrimSpace(key), "location") {
			continue
		}
		u, err := url.Parse(strings.TrimSpace(val))
		if err != nil || u.Scheme != "http" || u.Hostname() != ip {
			return ""
		}
		return u.String()
	}
	return ""
}

// upnpDescription ist der Teil der UPnP-Beschreibung, den wir brauchen.
type upnpDescription struct {
	Device struct {
		FriendlyName string `xml:"friendlyName"`
	} `xml:"device"`
}

// parseFriendlyName liest den friendlyName aus der UPnP-Beschreibung (XML).
// Ergebnis ist bereinigt; Namen, die nur eine Kennung sind, werden verworfen.
func parseFriendlyName(body []byte) string {
	var d upnpDescription
	if err := xml.Unmarshal(body, &d); err != nil {
		return ""
	}
	name := strings.Join(strings.Fields(sanitize(d.Device.FriendlyName)), " ")
	if name == "" || net.ParseIP(name) != nil || looksLikeIdentifier(name) {
		return ""
	}
	return name
}

// ssdpName fragt das Geraet per SSDP und liest den friendlyName aus der Beschreibung.
func ssdpName(ctx context.Context, ip string, port int) string {
	resp, err := udpExchange(ctx, ip, port, []byte(ssdpSearch))
	if err != nil {
		return ""
	}
	loc := parseSSDPLocation(resp, ip)
	if loc == "" {
		return ""
	}
	c, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(c, "GET", loc, nil)
	if err != nil {
		return ""
	}
	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	r, err := client.Do(req)
	if err != nil {
		return ""
	}
	defer r.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(r.Body, 64<<10)) // max. 64 KB
	return parseFriendlyName(body)
}
