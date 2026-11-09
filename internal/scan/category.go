package scan

import (
	"strconv"
	"strings"

	"github.com/berion1982/netzscanner/internal/model"
)

// Kategorisierung (I-015): ordnet jedes Geraet einer der Kategorien
// Netzwerkgeraet, IoT, Server oder Client zu.
//
// WICHTIG: Das ist eine VERMUTUNG aus Rolle, Hersteller (MAC-Chip), Betriebssystem
// und offenen Ports - kein sicheres Wissen. Ein WLAN-Chip-Hersteller sagt z. B. nicht,
// ob es ein Fernseher oder ein Laptop ist. Der Nutzer kann die Kategorie im
// Detail-Panel selbst festlegen (das hat immer Vorrang).

// networkVendors: Hersteller, deren Geraete (fast) immer Netzwerktechnik sind.
// Kleinbuchstaben, Teilstring-Vergleich. Ausnahmen (z. B. TP-Link-Steckdosen) sind moeglich.
var networkVendors = []string{
	"avm", "ubiquiti", "mikrotik", "routerboard", "netgear", "cisco", "aruba", "d-link",
	"zyxel", "tp-link", "devolo", "juniper", "ruckus", "engenius", "linksys", "draytek",
	"lancom", "edgecore", "tenda", "extreme networks",
}

// iotVendors: Hersteller typischer Smart-Home-, Medien- und Druckergeraete.
var iotVendors = []string{
	"espressif", "shelly", "allterco", "tuya", "signify", "philips lighting", "sonos",
	"amazon", "nest", "roku", "ring", "ecobee", "sonoff", "itead", "xiaomi", "ikea",
	"lifx", "wyze", "eufy", "tado", "eq-3", "homematic", "brother", "canon", "epson",
	"lexmark", "kyocera", "ricoh", "hikvision", "dahua", "reolink", "axis comm", "nuki", "somfy",
}

// serverVendors: Hersteller von NAS-/Serversystemen.
var serverVendors = []string{"synology", "qnap", "supermicro", "truenas", "ixsystems", "asustor"}

// iotPorts: Ports, die auf Drucker (631 IPP, 9100 JetDirect, 515 LPD) oder Kameras (554 RTSP) hindeuten.
var iotPorts = []int{631, 9100, 515, 554}

// serverPorts: Dienste, die ein normaler Client praktisch nie anbietet
// (Datenbanken, Mail, Verzeichnisdienste, NFS, DNS-Server-Rolle bleibt bewusst draussen).
var serverPorts = []int{
	1433, 3306, 5432, 27017, 6379, 9200, // Datenbanken
	25, 110, 143, 465, 587, 993, 995, // Mail
	389, 636, 88, // LDAP / Kerberos (Domaenencontroller)
	2049, // NFS
}

// Categorize liefert die vermutete Kategorie eines Geraets (immer einen gueltigen Schluessel).
// Reihenfolge: Netzwerk -> IoT -> Server -> Client (Standard).
func Categorize(h model.Host) string {
	vendor := strings.ToLower(h.Vendor)
	osName := strings.ToLower(h.OS)

	// 1) Netzwerkgeraet: per Gateway-Erkennung gesetzte Rolle, Hersteller oder System.
	// Scheineintraege (gleiche MAC wie ein Router/Switch, I-065) erben Hersteller/System des Routers
	// und zaehlen deshalb nicht als eigenes Netzwerkgeraet; sie fallen auf die uebrigen Regeln durch.
	if h.Role == "router" || h.Role == "switch" || (h.MirrorOf == "" && (containsAny(vendor, networkVendors) ||
		strings.Contains(osName, "routeros") || strings.Contains(osName, "fritz!os"))) {
		return model.CatNetwork
	}
	// 1b) Home Assistant (Port 8123) ist ein Server, auch wenn der Chip-Hersteller (z. B. Raspberry Pi) sonst nach IoT aussieht.
	if hasAnyPort(h, []int{8123}) {
		return model.CatServer
	}
	// 2) IoT: Smart-Home-/Druckerhersteller oder Drucker-/Kamera-Ports.
	if containsAny(vendor, iotVendors) || hasAnyPort(h, iotPorts) {
		return model.CatIoT
	}
	// 2b) Mobilgeraet (I-059): iOS/Android laut OS-Vermutung, sonst nur die schwache WLAN-Vermutung (s. isMobileGuess).
	if isMobileOS(osName) {
		return model.CatMobile
	}
	// 3) Server: NAS-Hersteller, Server-Dienste, Windows/IIS-Server oder Linux/Unix mit SSH + Weboberflaeche.
	if containsAny(vendor, serverVendors) || hasAnyPort(h, serverPorts) ||
		strings.Contains(osName, "server") || strings.Contains(osName, "iis") ||
		(isUnixLike(osName) && hasAnyPort(h, []int{22})) ||
		(hasAnyPort(h, []int{22}) && hasAnyPort(h, []int{80, 443, 8080, 8443})) {
		return model.CatServer
	}
	// 3b) Schwache Vermutung: WLAN-Geraet mit Privacy-MAC und ohne offene Ports (typisch fuer Smartphones/Tablets).
	if isMobileGuess(h) {
		return model.CatMobile
	}
	// 4) Alles andere: Client (PC, Laptop ...).
	return model.CatClient
}

// isMobileOS erkennt iOS/iPadOS/Android in der OS-Vermutung (Kleinbuchstaben).
func isMobileOS(osName string) bool {
	return strings.Contains(osName, "ios/ipados") || strings.Contains(osName, "android")
}

// isMobileGuess ist eine SCHWACHE Vermutung (I-059): Das Geraet haengt laut Router im WLAN, nutzt eine
// zufaellige/lokale MAC (Privacy-MAC), hat keinen Hersteller und keinen offenen Port. Auch Laptops koennen
// so aussehen (zufaellige MACs sind nicht auf Handys beschraenkt) - deshalb ist die Nutzerwahl immer staerker.
func isMobileGuess(h model.Host) bool {
	return strings.EqualFold(strings.TrimSpace(h.Connection), "WLAN") &&
		h.Vendor == "" && len(h.Ports) == 0 && isLocalMAC(h.MAC)
}

// isLocalMAC prueft das "lokal administriert"-Bit (0x02 im ersten Byte) einer MAC im Format aa:bb:... / aa-bb-...
// Solche MACs sind zufaellig vergeben (Privacy-MAC) und haben keinen Hersteller.
func isLocalMAC(mac string) bool {
	m := NormMAC(mac)
	if len(m) < 2 {
		return false
	}
	b, err := strconv.ParseUint(m[:2], 16, 8)
	return err == nil && b&0x02 != 0
}

// isUnixLike erkennt Linux/BSD-Systeme in der OS-Vermutung (Kleinbuchstaben).
func isUnixLike(osName string) bool {
	for _, k := range []string{"linux", "ubuntu", "debian", "freebsd", "unix"} {
		if strings.Contains(osName, k) {
			return true
		}
	}
	return false
}

// containsAny prueft, ob s einen der Teilstrings enthaelt (s leer -> false).
func containsAny(s string, subs []string) bool {
	if s == "" {
		return false
	}
	for _, sub := range subs {
		if strings.Contains(s, sub) {
			return true
		}
	}
	return false
}

// hasAnyPort prueft, ob das Geraet mindestens einen der Ports offen hat.
func hasAnyPort(h model.Host, ports []int) bool {
	for _, p := range h.Ports {
		for _, want := range ports {
			if p.Number == want {
				return true
			}
		}
	}
	return false
}
