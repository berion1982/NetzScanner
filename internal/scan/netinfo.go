package scan

import (
	"net"
	"os"
	"os/exec"
	"runtime"
	"strings"
)

// Netz-Grunddaten des Scan-Rechners (I-060): eigene IP/Netzmaske, Standard-Gateway,
// DNS-Server und Suchdomaene. Es wird nur gelesen (Schnittstellen, Systemdateien bzw.
// Systemwerkzeuge), es entsteht kein Netzverkehr und es werden keine Rechte gebraucht.
// Nicht ermittelbare Angaben bleiben leer - es wird nichts geraten.

// NetInfo beschreibt die Netzanbindung des Rechners, auf dem der Scanner laeuft.
type NetInfo struct {
	Interface     string   `json:"interface,omitempty"`      // Name der Schnittstelle, z. B. "eth0"
	IP            string   `json:"ip,omitempty"`             // eigene IPv4-Adresse
	Mask          string   `json:"mask,omitempty"`           // Netzmaske, z. B. "255.255.255.0"
	Prefix        int      `json:"prefix,omitempty"`         // Praefixlaenge, z. B. 24
	Gateway       string   `json:"gateway,omitempty"`        // Standard-Gateway
	DNS           []string `json:"dns,omitempty"`            // DNS-Server in der Reihenfolge des Systems
	SearchDomains []string `json:"search_domains,omitempty"` // Suchdomaene(n)
}

// LocalNetInfo sammelt die Grunddaten. Fehlende Teile bleiben leer.
func LocalNetInfo() NetInfo {
	gw := DefaultGateway()
	info := pickInterface(gw)
	info.Gateway = gw
	info.DNS, info.SearchDomains = systemDNS()
	return info
}

// pickInterface waehlt die Schnittstelle, in deren Subnetz der Gateway liegt.
// Gibt es keinen Gateway oder keinen Treffer, wird die erste aktive IPv4-Schnittstelle genommen.
func pickInterface(gateway string) NetInfo {
	var first NetInfo
	gwIP := net.ParseIP(gateway)
	ifaces, err := net.Interfaces()
	if err != nil {
		return first
	}
	for _, ifc := range ifaces {
		if ifc.Flags&net.FlagUp == 0 || ifc.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, _ := ifc.Addrs()
		for _, a := range addrs {
			ipn, ok := a.(*net.IPNet)
			if !ok || ipn.IP.To4() == nil {
				continue
			}
			ones, _ := ipn.Mask.Size()
			cand := NetInfo{Interface: ifc.Name, IP: ipn.IP.String(), Mask: net.IP(ipn.Mask).String(), Prefix: ones}
			if first.IP == "" {
				first = cand
			}
			if gwIP != nil && ipn.Contains(gwIP) {
				return cand
			}
		}
	}
	return first
}

// systemDNS liest DNS-Server und Suchdomaenen je nach Betriebssystem.
func systemDNS() (servers, domains []string) {
	switch runtime.GOOS {
	case "windows":
		return windowsDNS()
	default:
		// Linux/macOS/BSD: /etc/resolv.conf. Bei systemd-resolved zeigt diese Datei nur den
		// lokalen Stub (127.0.0.53); die echten Server stehen dann in /run/systemd/resolve/resolv.conf.
		for _, p := range []string{"/run/systemd/resolve/resolv.conf", "/etc/resolv.conf"} {
			if data, err := os.ReadFile(p); err == nil {
				s, d := parseResolvConf(string(data))
				if len(s) > 0 || len(d) > 0 {
					return s, d
				}
			}
		}
	}
	return nil, nil
}

// parseResolvConf wertet "nameserver", "search" und "domain" aus. Loopback-Stubs
// (127.x) werden weggelassen, weil sie nicht der eigentliche DNS-Server sind.
func parseResolvConf(text string) (servers, domains []string) {
	for _, line := range strings.Split(text, "\n") {
		f := strings.Fields(line)
		if len(f) < 2 {
			continue
		}
		switch f[0] {
		case "nameserver":
			if ip := net.ParseIP(f[1]); ip != nil && !ip.IsLoopback() {
				servers = appendUnique(servers, ip.String())
			}
		case "search", "domain":
			for _, d := range f[1:] {
				// "~." und "~domain" sind Routing-Angaben von systemd-resolved, keine Suchdomaenen.
				if !strings.HasPrefix(d, "~") && d != "." {
					domains = appendUnique(domains, d)
				}
			}
		}
	}
	return servers, domains
}

// windowsDNS fragt DNS-Server und Suchliste per PowerShell ab (ein Wert je Zeile,
// dadurch unabhaengig von der Sprache des Systems). Nur mit Testdaten geprueft.
func windowsDNS() (servers, domains []string) {
	run := func(script string) []string {
		out, err := hidden(exec.Command("powershell", "-NoProfile", "-NonInteractive", "-Command", script)).Output()
		if err != nil {
			return nil
		}
		return strings.Fields(string(out))
	}
	for _, s := range run("(Get-DnsClientServerAddress -AddressFamily IPv4).ServerAddresses") {
		if ip := net.ParseIP(s); ip != nil && !ip.IsLoopback() {
			servers = appendUnique(servers, ip.String())
		}
	}
	for _, d := range run("(Get-DnsClientGlobalSetting).SuffixSearchList") {
		domains = appendUnique(domains, d)
	}
	return servers, domains
}

// appendUnique haengt s an, falls es noch nicht enthalten ist.
func appendUnique(list []string, s string) []string {
	for _, x := range list {
		if x == s {
			return list
		}
	}
	return append(list, s)
}

// Lines liefert die Angaben als Paare "Bezeichnung, Wert" fuer Exporte (leere werden weggelassen).
func (n NetInfo) Lines() [][2]string {
	var out [][2]string
	add := func(k, v string) {
		if v != "" {
			out = append(out, [2]string{k, v})
		}
	}
	ip := n.IP
	if ip != "" && n.Mask != "" {
		ip += " / " + n.Mask
	}
	add("Scan-Rechner (IP / Netzmaske)", ip)
	add("Standard-Gateway", n.Gateway)
	add("DNS-Server", strings.Join(n.DNS, ", "))
	add("Suchdomäne", strings.Join(n.SearchDomains, ", "))
	return out
}
