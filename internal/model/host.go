// Package model beschreibt die Daten, die der NetzScanner pro Geraet sammelt.
package model

import (
	"fmt"
	"net"
	"sort"
)

// Port ist ein offener TCP-Port eines Geraets.
type Port struct {
	Number  int    `json:"number"`
	Service string `json:"service,omitempty"` // z.B. "ssh" (Vermutung anhand Portnummer/Banner)
	Banner  string `json:"banner,omitempty"`  // optional: gelesener Dienst-Banner
	Cert    *Cert  `json:"cert,omitempty"`    // nur bei TLS-Ports (z.B. 443): Infos zum Zertifikat
}

// Cert fasst das TLS-Zertifikat eines Ports zusammen (nur gelesen, nicht geprueft).
type Cert struct {
	Subject    string `json:"subject"`    // Common Name bzw. erster DNS-Name
	Issuer     string `json:"issuer"`     // Aussteller (Common Name)
	NotAfter   string `json:"notAfter"`   // Ablaufdatum, Format JJJJ-MM-TT
	DaysLeft   int    `json:"daysLeft"`   // Tage bis zum Ablauf (negativ = abgelaufen)
	Expired    bool   `json:"expired"`    // true, wenn das Ablaufdatum vorbei ist
	SelfSigned bool   `json:"selfSigned"` // Aussteller == Inhaber (selbst signiert)
}

// WebLink ist ein per Klick erreichbarer Web-Zugang (Router-Oberflaeche, NAS ...).
type WebLink struct {
	URL   string `json:"url"`
	Label string `json:"label"` // z.B. "https :443"
}

// Host ist ein gefundenes Geraet im Netz.
type Host struct {
	IP          string    `json:"ip"`
	Name        string    `json:"name"`                  // angezeigter Name (ggf. vom Nutzer geaendert)
	NameSource  string    `json:"nameSource,omitempty"`  // Herkunft des Namens: dns, dns-geraet, zertifikat, http-titel, nutzer
	Username    string    `json:"username,omitempty"`    // optional vom Nutzer eingetragen (KEIN Passwort!)
	ScannedName string    `json:"scannedName,omitempty"` // urspruenglicher Name aus dem Scan, nur gesetzt wenn umbenannt
	MAC         string    `json:"mac"`
	Vendor      string    `json:"vendor,omitempty"` // Hersteller aus der MAC (OUI)
	OS          string    `json:"os,omitempty"`     // Vermutung, kann leer/falsch sein
	Ports       []Port    `json:"ports"`
	Uplink      string    `json:"uplink,omitempty"` // Topologie: ID (IP) des vorgelagerten Geraets
	Role        string    `json:"role,omitempty"`   // "router", "switch" oder leer
	Known       bool      `json:"known"`            // false = unbekanntes Geraet
	WebLinks    []WebLink `json:"webLinks"`         // wird durch FillWebLinks berechnet
}

// webPorts ordnet Ports, die typischerweise eine Weboberflaeche liefern,
// dem passenden Schema zu. Nur diese Ports werden als Link angeboten.
var webPorts = map[int]string{
	80: "http", 443: "https", 631: "http", 5000: "http", 5001: "https",
	8000: "http", 8080: "http", 8081: "http", 8443: "https", 8888: "http",
}

// FillWebLinks berechnet aus IP und offenen Ports die klickbaren Web-Zugaenge.
// Die URL wird immer aus der (validierten) IP gebaut, nie aus Geraetenamen,
// damit manipulierte Namen im Netz keine Links veraendern koennen.
func (h *Host) FillWebLinks() {
	h.WebLinks = []WebLink{} // leeres Array statt null im JSON
	ip := net.ParseIP(h.IP)
	if ip == nil {
		return // ungueltige IP -> keine Links
	}
	host := ip.String()
	if ip.To4() == nil {
		host = "[" + host + "]" // IPv6 braucht eckige Klammern in URLs
	}
	nums := make([]int, 0, len(h.Ports))
	for _, p := range h.Ports {
		if _, ok := webPorts[p.Number]; ok {
			nums = append(nums, p.Number)
		}
	}
	sort.Ints(nums)
	for _, n := range nums {
		scheme := webPorts[n]
		h.WebLinks = append(h.WebLinks, WebLink{
			URL:   fmt.Sprintf("%s://%s:%d/", scheme, host, n),
			Label: fmt.Sprintf("%s :%d", scheme, n),
		})
	}
}
