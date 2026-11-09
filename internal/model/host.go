// Package model beschreibt die Daten, die der NetzScanner pro Geraet sammelt.
package model

import (
	"fmt"
	"net"
	"sort"
	"strings"
	"unicode"
	"unicode/utf8"
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

// Kategorien fuer die Topologie (I-015). Die Schluessel stehen in der API und im JSON.
const (
	CatNetwork = "network" // Router, Switches, Access Points ...
	CatServer  = "server"  // Server, NAS, Dienste-Rechner
	CatClient  = "client"  // PCs, Laptops und alles, was nicht eindeutig anders passt
	CatMobile  = "mobile"  // Smartphones und Tablets (I-059), nur wo erkennbar
	CatIoT     = "iot"     // Smart-Home, Drucker, Kameras, Medienplayer ...
)

// Categories listet alle Kategorien in der Reihenfolge der Anzeige (Karte, Legende, Liste).
var Categories = []string{CatNetwork, CatServer, CatClient, CatMobile, CatIoT}

// CustomPrefix kennzeichnet eigene Kategorien (I-017): Der Schluessel ist "custom:" + frei gewaehlter Name.
// So braucht jede Stelle (Karte, Exporte, PDF) keine Nachschlagetabelle: der Name steckt im Schluessel.
const CustomPrefix = "custom:"

// MaxCustomLabelRunes begrenzt die Laenge des Namens einer eigenen Kategorie.
const MaxCustomLabelRunes = 30

// MaxCustomCategories begrenzt die Anzahl eigener Kategorien (Schutz vor Missbrauch / ueberlangen Legenden).
const MaxCustomCategories = 20

// IsCustom sagt, ob c eine eigene (vom Nutzer angelegte) Kategorie ist.
func IsCustom(c string) bool { return strings.HasPrefix(c, CustomPrefix) }

// CleanCustomLabel prueft und bereinigt den Namen einer eigenen Kategorie.
// Rueckgabe: bereinigter Name und true, wenn er benutzbar ist (nicht leer, nicht zu lang,
// keine Steuerzeichen, kein Doppelgaenger einer eingebauten Kategorie).
func CleanCustomLabel(s string) (string, bool) {
	s = strings.Join(strings.Fields(s), " ") // Leerraum zusammenfassen und kuerzen
	n := utf8.RuneCountInString(s)
	if n == 0 || n > MaxCustomLabelRunes {
		return "", false
	}
	for _, r := range s {
		if unicode.IsControl(r) {
			return "", false
		}
	}
	for _, c := range Categories { // "Server" o. ae. waere verwirrend doppelt
		if strings.EqualFold(CategoryLabel(c), s) {
			return "", false
		}
	}
	return s, true
}

// CustomKey baut den Schluessel einer eigenen Kategorie aus dem (bereinigten) Namen.
func CustomKey(label string) string { return CustomPrefix + label }

// CategoryLabel liefert die deutsche Bezeichnung einer Kategorie (unbekannt -> "").
// Bei eigenen Kategorien ist das der Name hinter dem Praefix.
func CategoryLabel(c string) string {
	switch c {
	case CatNetwork:
		return "Netzwerkgeräte"
	case CatServer:
		return "Server"
	case CatClient:
		return "Clients"
	case CatMobile:
		return "Mobilgeräte"
	case CatIoT:
		return "IoT"
	}
	if IsCustom(c) {
		if l, ok := CleanCustomLabel(strings.TrimPrefix(c, CustomPrefix)); ok {
			return l
		}
	}
	return ""
}

// ValidCategory prueft, ob c eine eingebaute oder eine gueltige eigene Kategorie ist.
func ValidCategory(c string) bool { return CategoryLabel(c) != "" }

// CategoryRank liefert die Sortierposition einer Kategorie (eigene stehen hinter den eingebauten).
func CategoryRank(c string) int {
	for i, k := range Categories {
		if k == c {
			return i
		}
	}
	return len(Categories)
}

// CategoryHue liefert fuer eine eigene Kategorie einen festen Farbton (0-359 Grad) aus dem Namen
// (FNV-1a-Hash). Gleicher Name = gleiche Farbe in Karte, Legende und PDF. Der Goldene Winkel
// (137) streut aehnliche Namen weit auseinander.
func CategoryHue(c string) int {
	h := uint32(2166136261)
	for _, b := range []byte(c) {
		h ^= uint32(b)
		h *= 16777619
	}
	return int(h%360+137) % 360
}

// Host ist ein gefundenes Geraet im Netz.
type Host struct {
	IP             string    `json:"ip"`
	Name           string    `json:"name"`                  // angezeigter Name (ggf. vom Nutzer geaendert)
	NameSource     string    `json:"nameSource,omitempty"`  // Herkunft des Namens: dns, dns-geraet, zertifikat, http-titel, nutzer
	Location       string    `json:"location,omitempty"`    // optional vom Nutzer eingetragener Standort (Freitext, z. B. "Buero, Raum 2")
	Username       string    `json:"username,omitempty"`    // optional vom Nutzer eingetragen (KEIN Passwort!)
	ScannedName    string    `json:"scannedName,omitempty"` // urspruenglicher Name aus dem Scan, nur gesetzt wenn umbenannt
	MAC            string    `json:"mac"`
	Vendor         string    `json:"vendor,omitempty"` // Hersteller aus der MAC (OUI)
	OS             string    `json:"os,omitempty"`     // Vermutung, kann leer/falsch sein
	Ports          []Port    `json:"ports"`
	Uplink         string    `json:"uplink,omitempty"`         // Topologie: ID (IP) des vorgelagerten Geraets
	DHCP           string    `json:"dhcp,omitempty"`           // Angabe des DHCP-Servers: "Reservierung" oder "Lease bis ..." (I-056), nur nach DHCP-Abfrage
	RouterName     string    `json:"routerName,omitempty"`     // Name laut Router-Geraeteliste (I-024), nur nach Router-Login
	Connection     string    `json:"connection,omitempty"`     // Verbindungsart laut Router: "WLAN", "LAN (Kabel)" ...
	WifiSSID       string    `json:"wifiSSID,omitempty"`       // WLAN, an dem das Geraet laut Router haengt (I-055)
	WifiSignal     int       `json:"wifiSignal,omitempty"`     // Signalstaerke in Prozent laut Router (0 = unbekannt)
	WifiSpeed      int       `json:"wifiSpeed,omitempty"`      // WLAN-Verbindungsgeschwindigkeit in Mbit/s laut Router
	SameMAC        []string  `json:"sameMac,omitempty"`        // andere IPs mit derselben MAC (Hinweis: im Router gegenpruefen, siehe scan.MarkSharedMAC)
	MirrorOf       string    `json:"mirrorOf,omitempty"`       // IP des Routers/Switches, dessen MAC dieses Geraet (vermutlich als Scheineintrag) teilt (I-065)
	MeshLink       string    `json:"meshLink,omitempty"`       // Mesh der FRITZ!Box: Art/Geschwindigkeit/Signal der Verbindung zum Uplink (I-055 c)
	UplinkPort     string    `json:"uplinkPort,omitempty"`     // Topologie per SNMP: Port am Uplink-Switch (z. B. "Gi1/0/5")
	UplinkShared   int       `json:"uplinkShared,omitempty"`   // Topologie per SNMP: wie viele MACs an diesem Port gesehen wurden (>1 = Switch/AP dahinter)
	Role           string    `json:"role,omitempty"`           // "router", "switch" oder leer
	Category       string    `json:"category"`                 // Kategorie (CatNetwork ...): Vermutung aus dem Scan oder Wahl des Nutzers
	CategoryManual bool      `json:"categoryManual,omitempty"` // true = Nutzer hat die Kategorie selbst gesetzt
	Known          bool      `json:"known"`                    // false = unbekanntes Geraet
	Pending        bool      `json:"pending,omitempty"`        // true = Scan laeuft noch, Angaben (Name) unvollstaendig
	WebLinks       []WebLink `json:"webLinks"`                 // wird durch FillWebLinks berechnet
}

// webPorts ordnet Ports, die typischerweise eine Weboberflaeche liefern,
// dem passenden Schema zu. Nur diese Ports werden als Link angeboten.
var webPorts = map[int]string{
	80: "http", 443: "https", 631: "http", 5000: "http", 5001: "https",
	8000: "http", 8080: "http", 8081: "http", 8123: "http", 8443: "https", 8888: "http",
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

// SameMACNote liefert den Exporthinweis zu gleicher MAC (leer, wenn die MAC eindeutig ist).
// Er steht in PDF, CSV, Markdown und HTML, damit der Hinweis aus der Oberflaeche (⚠ MAC mehrfach)
// nicht verloren geht. Es wird nichts ausgeblendet, der Text ist nur ein Hinweis zum Gegenpruefen.
func (h Host) SameMACNote() string {
	if len(h.SameMAC) == 0 {
		return ""
	}
	note := "MAC mehrfach: " + strings.Join(h.SameMAC, ", ")
	if h.MirrorOf != "" {
		note += " (gleiche MAC wie " + h.MirrorOf + ", vermutlich Scheineintrag)"
	}
	return note
}
