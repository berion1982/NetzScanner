package scan

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/berion1982/netzscanner/internal/model"
)

// Namensquellen in dieser Reihenfolge (die erste mit Ergebnis gewinnt):
//  1. "dns"        Reverse-DNS ueber den konfigurierten DNS-Server
//  2. "dns-geraet" Reverse-DNS direkt beim Geraet (hat es Port 53 offen, z.B. Router)
//     "mdns" / "netbios" Name per mDNS (UDP 5353) bzw. NetBIOS (UDP 137), siehe udpnames.go
//  3. "zertifikat" Name im TLS-Zertifikat (Port 443 u.a.)
//  4. "http-titel" Titel der Weboberflaeche (nur Vorschlag, unsicher)

// httpsPorts liefern Weboberflaechen per TLS.
var httpsPorts = map[int]bool{443: true, 5001: true, 8443: true}

// dnsResolver erzwingt den eingebauten Go-Resolver (PreferGo). Der System-Resolver
// (cgo/NSS) kann lokale Pseudo-Namen liefern, z.B. "_gateway" vom NSS-Modul
// "myhostname" fuer den Standard-Gateway - das ist NICHT der Name des Geraets.
var dnsResolver = &net.Resolver{PreferGo: true}

// trimDot entfernt den Punkt am Ende eines DNS-Namens ("fritz.box." -> "fritz.box").
func trimDot(s string) string { return strings.TrimSuffix(s, ".") }

// cleanHostName macht aus einem Antwortnamen einen Anzeigenamen. Namen mit
// fuehrendem "_" (z.B. "_gateway") sind lokale Pseudonamen -> "" (verwerfen).
// IP-Adressen sind keine Namen -> ebenfalls "".
func cleanHostName(raw string) string {
	name := sanitize(trimDot(raw))
	if name == "" || name[0] == '_' || net.ParseIP(name) != nil {
		return ""
	}
	return name
}

// resolveNames ermittelt fuer alle Hosts einen Namen (parallel).
func resolveNames(ctx context.Context, hosts []model.Host) {
	var wg sync.WaitGroup
	for i := range hosts {
		wg.Add(1)
		go func(h *model.Host) {
			defer wg.Done()
			h.Name, h.NameSource = findName(ctx, h)
		}(&hosts[i])
	}
	wg.Wait()
}

// findName probiert die Namensquellen der Reihe nach. Liefert ("", "") ohne Treffer.
func findName(ctx context.Context, h *model.Host) (name, source string) {
	if n := reverseDNS(ctx, dnsResolver, h.IP); n != "" {
		return n, "dns"
	}
	if hasPort(h, 53) { // Router/DNS-Server kennt sich oft selbst
		own := &net.Resolver{PreferGo: true, Dial: func(c context.Context, network, _ string) (net.Conn, error) {
			d := net.Dialer{Timeout: time.Second}
			return d.DialContext(c, network, net.JoinHostPort(h.IP, "53"))
		}}
		if n := reverseDNS(ctx, own, h.IP); n != "" {
			return n, "dns-geraet"
		}
	}
	// UDP-Quellen ohne Sonderrechte (I-002): mDNS und NetBIOS.
	if n := mdnsName(ctx, h.IP, mdnsPort); n != "" {
		return n, "mdns"
	}
	if n := netbiosName(ctx, h.IP, netbiosPort); n != "" {
		return n, "netbios"
	}
	for _, p := range h.Ports {
		if httpsPorts[p.Number] {
			if n := certName(ctx, h.IP, p.Number); n != "" {
				return n, "zertifikat"
			}
		}
	}
	for _, p := range h.Ports {
		if httpPorts[p.Number] || httpsPorts[p.Number] {
			if n := httpTitle(ctx, h.IP, p.Number); n != "" {
				return n, "http-titel"
			}
		}
	}
	return "", ""
}

func hasPort(h *model.Host, port int) bool {
	for _, p := range h.Ports {
		if p.Number == port {
			return true
		}
	}
	return false
}

// reverseDNS fragt den PTR-Eintrag ab (1,5 s Timeout) und nimmt den ersten brauchbaren Namen.
func reverseDNS(ctx context.Context, r *net.Resolver, ip string) string {
	c, cancel := context.WithTimeout(ctx, 1500*time.Millisecond)
	defer cancel()
	names, err := r.LookupAddr(c, ip)
	if err != nil {
		return ""
	}
	for _, n := range names {
		if name := cleanHostName(n); name != "" {
			return name
		}
	}
	return ""
}

// certName liest den Namen aus dem TLS-Zertifikat des Geraets (zuerst DNS-Namen
// (SAN), sonst Common Name). Die Zertifikatspruefung ist hier ABSICHTLICH aus
// (InsecureSkipVerify): Geraete haben meist selbst signierte Zertifikate, und wir
// lesen nur das Zertifikat - es werden keine Daten oder Zugangsdaten gesendet.
func certName(ctx context.Context, ip string, port int) string {
	d := net.Dialer{Timeout: 1500 * time.Millisecond}
	raw, err := d.DialContext(ctx, "tcp", net.JoinHostPort(ip, strconv.Itoa(port)))
	if err != nil {
		return ""
	}
	conn := tls.Client(raw, &tls.Config{InsecureSkipVerify: true})
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
	if err := conn.HandshakeContext(ctx); err != nil {
		return ""
	}
	certs := conn.ConnectionState().PeerCertificates
	if len(certs) == 0 {
		return ""
	}
	for _, n := range certs[0].DNSNames {
		if name := cleanHostName(strings.TrimPrefix(n, "*.")); name != "" {
			return name
		}
	}
	return cleanHostName(certs[0].Subject.CommonName)
}

var reTitle = regexp.MustCompile(`(?is)<title[^>]*>(.*?)</title>`)

// httpTitle liest den <title> der Startseite (max. 64 KB, ohne Weiterleitungen).
// Der Titel ist nur ein Hinweis auf den Geraetetyp (z.B. "FRITZ!Box").
func httpTitle(ctx context.Context, ip string, port int) string {
	scheme := "http"
	if httpsPorts[port] {
		scheme = "https"
	}
	client := &http.Client{
		Timeout:       2500 * time.Millisecond,
		Transport:     &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}, // nur lesen, s.o.
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	req, err := http.NewRequestWithContext(ctx, "GET", scheme+"://"+net.JoinHostPort(ip, strconv.Itoa(port))+"/", nil)
	if err != nil {
		return ""
	}
	resp, err := client.Do(req)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	m := reTitle.FindSubmatch(body)
	if m == nil {
		return ""
	}
	title := strings.Join(strings.Fields(sanitize(string(m[1]))), " ")
	if len(title) > 60 {
		title = title[:60]
	}
	return title
}
