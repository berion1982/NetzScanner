package router

// Diagnose der FRITZ!Box-Schnittstelle (I-055 d): Welche TR-064-Dienste und Aktionen bietet DIESE
// Box an? Hintergrund: Ich weiss nicht, ob und wie eine FRITZ!Box feste IP-Reservierungen ueber
// TR-064 herausgibt (die AVM-Doku war in der Entwicklungsumgebung nicht erreichbar). Statt zu
// raten, fragt dieser Befehl die Box selbst: Die Beschreibungsdateien (tr64desc.xml und die
// SCPD-Dateien der Dienste) liegen nach meinem Wissen ohne Anmeldung auf Port 49000.
// Es werden KEINE Zugangsdaten gebraucht und nichts veraendert (nur HTTP-GET).

import (
	"context"
	"encoding/xml"
	"fmt"
	"io"
	"net"
	"net/http"
	"regexp"
	"sort"
	"strings"
)

// interessant: Aktionen/Dienste, die auf Reservierungen oder DHCP hindeuten koennten.
var interessant = regexp.MustCompile(`(?i)reserv|static|lease|dhcp|fixed|address`)

// descService ist ein <service>-Eintrag aus tr64desc.xml.
type descService struct {
	Type string `xml:"serviceType"`
	SCPD string `xml:"SCPDURL"`
}

// descRoot sammelt rekursiv alle <service>-Eintraege (sie liegen in verschachtelten Geraeten).
type descRoot struct {
	Services []descService `xml:"device>serviceList>service"`
	Devices  []descDevice  `xml:"device>deviceList>device"`
}
type descDevice struct {
	Services []descService `xml:"serviceList>service"`
	Devices  []descDevice  `xml:"deviceList>device"`
}

func (d descDevice) all() []descService {
	out := append([]descService(nil), d.Services...)
	for _, c := range d.Devices {
		out = append(out, c.all()...)
	}
	return out
}

// scpdDoc ist eine SCPD-Datei: nur die Aktionsnamen interessieren.
type scpdDoc struct {
	Actions []struct {
		Name string `xml:"name"`
	} `xml:"actionList>action"`
}

// httpGet liest eine Datei von der Box (begrenzt auf 2 MB).
func httpGet(ctx context.Context, base, path string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, base+path, nil)
	if err != nil {
		return nil, err
	}
	resp, err := (&http.Client{Timeout: requestTimeout}).Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	return io.ReadAll(io.LimitReader(resp.Body, 2<<20))
}

// Describe schreibt alle Dienste der Box samt Aktionsnamen nach w; Treffer, die nach
// Reservierung/DHCP aussehen, werden mit "<<" markiert. Ohne Zugangsdaten.
func Describe(ctx context.Context, host string, w io.Writer) {
	p := func(f string, a ...any) { fmt.Fprintf(w, f+"\n", a...) }
	if net.ParseIP(host) == nil {
		p("FEHLER: keine gültige IP-Adresse")
		return
	}
	port := tr064Port
	if tr064PortOverride != "" {
		port = tr064PortOverride
	}
	base := "http://" + net.JoinHostPort(host, port)
	p("== FRITZ!Box-Schnittstellen (TR-064) von %s ==", host)
	raw, err := httpGet(ctx, base, "/tr64desc.xml")
	if err != nil {
		p("tr64desc.xml nicht lesbar: %v (TR-064 aktiv? Port %s erreichbar?)", err, port)
		return
	}
	var root descRoot
	if err := xml.Unmarshal(raw, &root); err != nil {
		p("tr64desc.xml nicht auswertbar")
		return
	}
	services := append([]descService(nil), root.Services...)
	for _, d := range root.Devices {
		services = append(services, d.all()...)
	}
	sort.Slice(services, func(i, j int) bool { return services[i].Type < services[j].Type })
	for _, s := range services {
		mark := ""
		if interessant.MatchString(s.Type) {
			mark = "  <<"
		}
		p("\n[%s]%s", s.Type, mark)
		if !strings.HasPrefix(s.SCPD, "/") {
			continue
		}
		body, err := httpGet(ctx, base, s.SCPD)
		if err != nil {
			p("   (Beschreibung nicht lesbar: %v)", err)
			continue
		}
		var doc scpdDoc
		if xml.Unmarshal(body, &doc) != nil {
			continue
		}
		for _, a := range doc.Actions {
			m := ""
			if interessant.MatchString(a.Name) {
				m = "  <<"
			}
			p("   %s%s", a.Name, m)
		}
	}
}
