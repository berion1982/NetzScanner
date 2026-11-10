package scan

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/berion1982/netzscanner/internal/model"
	"github.com/berion1982/netzscanner/internal/version"
)

// Diagnose prueft EIN Geraet Schritt fuer Schritt und schreibt jedes Ergebnis samt
// Fehlermeldung in w. Gedacht fuer die Fehlersuche ("warum fehlt der Name?"):
// Der Nutzer kann die Ausgabe kopieren und weitergeben. Enthaelt keine Zugangsdaten.
func Diagnose(ctx context.Context, ip string, w io.Writer) {
	p := func(format string, a ...any) { fmt.Fprintf(w, format+"\n", a...) }
	p("== NetzScanner Diagnose ==")
	p("Version: %s", version.String())
	p("Ziel:    %s", ip)
	if net.ParseIP(ip) == nil {
		p("FEHLER: keine gueltige IP-Adresse")
		return
	}
	diagChecks(ctx, p, ip)
}

// diagChecks sind die Pruefschritte 1-7 (DNS, Ports, ARP, Reverse-DNS, TLS, Web, Namenssuche).
// Sie werden vom Kommandozeilen-Aufruf (Diagnose) und vom Geraete-Bericht (DiagnoseDevice) benutzt.
// Die IP muss vorher als gueltig geprueft sein.
func diagChecks(ctx context.Context, p func(string, ...any), ip string) {
	// 1. DNS-Konfiguration dieses Rechners (nur nameserver/search-Zeilen).
	p("\n[1] DNS-Konfiguration dieses Rechners (/etc/resolv.conf)")
	if data, err := os.ReadFile("/etc/resolv.conf"); err != nil {
		p("    nicht lesbar: %v (normal unter Windows)", err)
	} else {
		for _, l := range strings.Split(string(data), "\n") {
			if strings.HasPrefix(l, "nameserver") || strings.HasPrefix(l, "search") {
				p("    %s", strings.TrimSpace(l))
			}
		}
	}

	// 2. Offene Ports (Standardliste) samt Banner.
	p("\n[2] Offene Ports (Standardliste, %d Ports)", len(DefaultPorts))
	h := model.Host{IP: ip}
	sem := make(chan struct{}, 128)
	h.Ports = scanHost(ctx, mustAddr(ip), DefaultPorts, 1500*time.Millisecond, sem)
	sort.Slice(h.Ports, func(i, j int) bool { return h.Ports[i].Number < h.Ports[j].Number })
	if len(h.Ports) == 0 {
		p("    keine offenen Ports gefunden")
	}
	for _, pt := range h.Ports {
		p("    %d (%s) banner=%q", pt.Number, pt.Service, pt.Banner)
	}

	// 3. MAC aus ARP-Tabelle.
	p("\n[3] ARP-Tabelle")
	p("    MAC: %q", ReadARP()[ip])

	// 4. Reverse-DNS: eingebauter Resolver und (zum Vergleich) System-Resolver.
	p("\n[4] Reverse-DNS")
	diagLookup(ctx, p, "Go-Resolver (Konfig. dieses Rechners)", dnsResolver, ip)
	diagLookup(ctx, p, "System-Resolver (kann Pseudonamen wie _gateway liefern)", net.DefaultResolver, ip)
	own := &net.Resolver{PreferGo: true, Dial: func(c context.Context, network, _ string) (net.Conn, error) {
		d := net.Dialer{Timeout: time.Second}
		return d.DialContext(c, network, net.JoinHostPort(ip, "53"))
	}}
	diagLookup(ctx, p, "direkt beim Geraet "+ip+":53 (liest zuerst /etc/hosts)", own, ip)

	// 5. TLS-Zertifikate und 6. Web-Antworten.
	p("\n[5] TLS-Zertifikate")
	any5 := false
	for _, pt := range h.Ports {
		if httpsPorts[pt.Number] {
			any5 = true
			diagCert(ctx, p, ip, pt.Number)
		}
	}
	if !any5 {
		p("    kein TLS-Webport (443/5001/8443) offen")
	}
	p("\n[6] Web-Startseiten")
	any6 := false
	for _, pt := range h.Ports {
		if httpPorts[pt.Number] || httpsPorts[pt.Number] {
			any6 = true
			diagHTTP(ctx, p, ip, pt.Number)
		}
	}
	if !any6 {
		p("    kein Webport offen")
	}

	// 7. Ergebnis der echten Namenssuche.
	name, src := findName(ctx, &h)
	p("\n[7] Ergebnis der Namenssuche: name=%q quelle=%q", name, src)
}

// mustAddr wandelt eine (vorher geprueft gueltige) IP in netip.Addr.
func mustAddr(ip string) netip.Addr { a, _ := netip.ParseAddr(ip); return a }

func diagLookup(ctx context.Context, p func(string, ...any), label string, r *net.Resolver, ip string) {
	c, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	names, err := r.LookupAddr(c, ip)
	if err != nil {
		p("    %-52s Fehler: %v", label, err)
		return
	}
	p("    %-52s %q", label, names)
}

func diagCert(ctx context.Context, p func(string, ...any), ip string, port int) {
	d := net.Dialer{Timeout: 2 * time.Second}
	raw, err := d.DialContext(ctx, "tcp", net.JoinHostPort(ip, strconv.Itoa(port)))
	if err != nil {
		p("    :%d Verbindung fehlgeschlagen: %v", port, err)
		return
	}
	conn := tls.Client(raw, &tls.Config{InsecureSkipVerify: true}) // nur lesen
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
	if err := conn.HandshakeContext(ctx); err != nil {
		p("    :%d TLS-Handshake fehlgeschlagen: %v", port, err)
		return
	}
	certs := conn.ConnectionState().PeerCertificates
	if len(certs) == 0 {
		p("    :%d kein Zertifikat", port)
		return
	}
	c := certs[0]
	p("    :%d CN=%q SAN=%q Aussteller=%q", port, c.Subject.CommonName, c.DNSNames, c.Issuer.CommonName)
}

func diagHTTP(ctx context.Context, p func(string, ...any), ip string, port int) {
	scheme := "http"
	if httpsPorts[port] {
		scheme = "https"
	}
	client := &http.Client{
		Timeout:       3 * time.Second,
		Transport:     &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}, // nur lesen
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	req, _ := http.NewRequestWithContext(ctx, "GET", scheme+"://"+net.JoinHostPort(ip, strconv.Itoa(port))+"/", nil)
	resp, err := client.Do(req)
	if err != nil {
		p("    %s :%d Fehler: %v", scheme, port, err)
		return
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	title := ""
	if m := reTitle.FindSubmatch(body); m != nil {
		title = sanitize(string(m[1]))
	}
	p("    %s :%d Status=%d Server=%q Weiterleitung=%q Titel=%q", scheme, port, resp.StatusCode,
		sanitize(resp.Header.Get("Server")), sanitize(resp.Header.Get("Location")), title)
}
