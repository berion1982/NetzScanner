package scan

import (
	"encoding/hex"
	"net"
	"os"
	"os/exec"
	"regexp"
	"runtime"
	"strings"

	"github.com/berion1982/netzscanner/internal/model"
)

// Topologie ohne Zugangsdaten (I-010, erster Schritt):
// Ohne LLDP/SNMP kann der Scan nicht wissen, an welchem Switch ein Geraet haengt.
// Sicher bekannt ist aber der Standard-Gateway (Router) des eigenen Rechners. Alle
// Geraete im selben Subnetz (erkennbar an einer MAC aus der ARP-Tabelle) haengen
// aus Sicht des Netzes "hinter" diesem Router. Das ist eine Sternansicht - keine
// echte Verkabelung! Echte Uplinks (Switch-Ports) folgen spaeter per LLDP/SNMP.

// DefaultGateway liefert die IPv4-Adresse des Standard-Gateways oder "" (unbekannt).
// Es werden nur Systemdateien bzw. -werkzeuge gelesen, es braucht keine Rechte.
func DefaultGateway() string {
	if runtime.GOOS == "linux" {
		if data, err := os.ReadFile("/proc/net/route"); err == nil {
			if gw := parseLinuxRoute(string(data)); gw != "" {
				return gw
			}
		}
	}
	switch runtime.GOOS {
	case "windows":
		if out, err := exec.Command("route", "print", "-4", "0.0.0.0").Output(); err == nil {
			return parseWindowsRoute(string(out))
		}
	case "darwin":
		if out, err := exec.Command("route", "-n", "get", "default").Output(); err == nil {
			return parseDarwinRoute(string(out))
		}
	}
	return ""
}

// parseLinuxRoute wertet /proc/net/route aus. Spalten: Iface, Destination, Gateway,
// Flags, ... Die Standardroute hat Destination 00000000 und das Flag RTF_GATEWAY (0x2).
// Adressen stehen hexadezimal in der Byte-Reihenfolge des Rechners (little endian).
func parseLinuxRoute(text string) string {
	for i, line := range strings.Split(text, "\n") {
		f := strings.Fields(line)
		if i == 0 || len(f) < 4 || f[1] != "00000000" {
			continue
		}
		raw, err := hex.DecodeString(f[2])
		if err != nil || len(raw) != 4 {
			continue
		}
		// Der Hex-Wert steht in Rechner-Reihenfolge (little endian): Bytes umdrehen.
		ip := net.IPv4(raw[3], raw[2], raw[1], raw[0])
		if s := ip.String(); s != "0.0.0.0" {
			return s
		}
	}
	return ""
}

// reRouteDefault passt auf die Windows-Zeile "0.0.0.0  0.0.0.0  <Gateway>  <Schnittstelle> <Metrik>".
var reRouteDefault = regexp.MustCompile(`^\s*0\.0\.0\.0\s+0\.0\.0\.0\s+(\d{1,3}(?:\.\d{1,3}){3})\s`)

// parseWindowsRoute wertet "route print -4 0.0.0.0" aus (erste Standardroute).
func parseWindowsRoute(text string) string {
	for _, line := range strings.Split(text, "\n") {
		if m := reRouteDefault.FindStringSubmatch(line); m != nil {
			return m[1]
		}
	}
	return ""
}

// parseDarwinRoute wertet "route -n get default" (macOS) aus: Zeile "gateway: 192.168.1.1".
func parseDarwinRoute(text string) string {
	for _, line := range strings.Split(text, "\n") {
		f := strings.Fields(line)
		if len(f) == 2 && f[0] == "gateway:" && net.ParseIP(f[1]) != nil {
			return f[1]
		}
	}
	return ""
}

// ApplyGateway setzt Rolle und Uplink: Der Gateway bekommt die Rolle "router"; alle
// anderen Geraete mit MAC (= selbes Subnetz) bekommen ihn als Uplink. Geraete ohne
// MAC (hinter anderen Routern) bleiben ohne Uplink, weil ihr Weg unbekannt ist.
// Ist der Gateway nicht unter den gefundenen Geraeten, bleibt alles unveraendert.
func ApplyGateway(hosts []model.Host, gateway string) {
	if gateway == "" {
		return
	}
	found := false
	for i := range hosts {
		if hosts[i].IP == gateway {
			hosts[i].Role = "router"
			found = true
		}
	}
	if !found {
		return
	}
	for i := range hosts {
		if hosts[i].IP != gateway && hosts[i].MAC != "" {
			hosts[i].Uplink = gateway
		}
	}
}

// MarkSharedMAC vermerkt bei jedem Geraet die IPs, die dieselbe MAC-Adresse haben (Host.SameMAC).
// Gleiche MAC bei mehreren IPs ist oft ein Scheineintrag (ein Router beantwortet ARP fuer fremde Adressen,
// Proxy-ARP z. B. fuer VPN-Clients) oder ein Geraet mit mehreren Adressen. Der Scanner kann das nicht
// unterscheiden und blendet deshalb NICHTS aus; er weist nur darauf hin, dass der Router gegenzupruefen ist.
// Allgemeine Regel ohne Geraete-/Adresstabelle. Geraete ohne MAC werden ignoriert. Aendert nur die uebergebene Kopie.
func MarkSharedMAC(hosts []model.Host) {
	ips := map[string][]string{} // normalisierte MAC -> alle IPs
	for _, h := range hosts {
		if k := NormMAC(h.MAC); k != "" {
			ips[k] = append(ips[k], h.IP)
		}
	}
	for i := range hosts {
		hosts[i].SameMAC = nil
		hosts[i].MirrorOf = ""
		k := NormMAC(hosts[i].MAC)
		if k == "" || len(ips[k]) < 2 {
			continue
		}
		for _, ip := range ips[k] {
			if ip != hosts[i].IP {
				hosts[i].SameMAC = append(hosts[i].SameMAC, ip)
			}
		}
		hosts[i].MirrorOf = mirrorOf(hosts, i, k)
	}
}

// mirrorOf liefert die IP des Routers/Switches, dessen MAC das Geraet i (ohne eigene Netzwerk-Rolle)
// ebenfalls hat. Solche Eintraege sind meist Scheineintraege (Proxy-ARP des Routers) und sollen nicht
// als eigenes Netzwerkgeraet zaehlen. Ohne passenden Router/Switch: leer. Allgemeine Regel nach Rolle.
func mirrorOf(hosts []model.Host, i int, mac string) string {
	if hosts[i].Role == "router" || hosts[i].Role == "switch" {
		return ""
	}
	for j := range hosts {
		if j != i && (hosts[j].Role == "router" || hosts[j].Role == "switch") && NormMAC(hosts[j].MAC) == mac {
			return hosts[j].IP
		}
	}
	return ""
}
