package scan

import (
	"fmt"
	"strconv"
	"strings"
)

// DefaultPorts sind haeufige Dienste, die beim Onboarding interessieren.
var DefaultPorts = []int{
	21, 22, 23, 25, 53, 80, 110, 111, 123, 135, 139, 143, 161, 389, 443, 445, 465,
	515, 548, 587, 631, 636, 993, 995, 1433, 1521, 1723, 1883, 2049, 3000, 3306,
	3389, 5000, 5001, 5060, 5432, 5900, 5985, 5986, 6379, 8000, 8008, 8080, 8081,
	8123, 8443, 8883, 8888, 9000, 9090, 9100, 9200, 22222, 27017, 32400, 62078,
}

// serviceNames: Vermutung des Dienstes anhand der Portnummer (kein Beweis!).
var serviceNames = map[int]string{
	21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns", 80: "http", 110: "pop3",
	111: "rpcbind", 123: "ntp", 135: "msrpc", 139: "netbios", 143: "imap", 161: "snmp",
	389: "ldap", 443: "https", 445: "smb", 465: "smtps", 515: "lpd", 548: "afp",
	587: "submission", 631: "ipp", 636: "ldaps", 993: "imaps", 995: "pop3s",
	1433: "mssql", 1521: "oracle", 1723: "pptp", 1883: "mqtt", 2049: "nfs",
	3306: "mysql", 3389: "rdp", 5000: "http", 5001: "https", 5060: "sip",
	5432: "postgres", 5900: "vnc", 5985: "winrm", 5986: "winrm-ssl", 6379: "redis",
	8000: "http", 8008: "http", 8123: "homeassistant", 8080: "http", 8081: "http", 8443: "https",
	8883: "mqtts", 8888: "http", 9100: "jetdirect", 9200: "elasticsearch", 22222: "ssh",
	27017: "mongodb", 32400: "plex", 62078: "apple-lockdown",
}

// ServiceName liefert den vermuteten Dienstnamen oder "".
func ServiceName(port int) string { return serviceNames[port] }

// ParsePorts liest "22,80,8000-8100" oder "" (= Standardliste).
func ParsePorts(spec string) ([]int, error) {
	spec = strings.TrimSpace(spec)
	if spec == "" {
		return DefaultPorts, nil
	}
	seen := map[int]bool{}
	var out []int
	add := func(p int) {
		if !seen[p] {
			seen[p] = true
			out = append(out, p)
		}
	}
	for _, part := range strings.Split(spec, ",") {
		part = strings.TrimSpace(part)
		lo, hi, isRange := strings.Cut(part, "-")
		a, err := strconv.Atoi(strings.TrimSpace(lo))
		if err != nil || a < 1 || a > 65535 {
			return nil, fmt.Errorf("ungueltiger Port %q", part)
		}
		b := a
		if isRange {
			if b, err = strconv.Atoi(strings.TrimSpace(hi)); err != nil || b < a || b > 65535 {
				return nil, fmt.Errorf("ungueltiger Portbereich %q", part)
			}
		}
		for p := a; p <= b; p++ {
			add(p)
		}
	}
	return out, nil
}
