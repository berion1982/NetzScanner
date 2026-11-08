package scan

import (
	"os"
	"os/exec"
	"regexp"
	"runtime"
	"strings"
)

// ReadARP liest die ARP-Tabelle des Betriebssystems: IP -> MAC (grossgeschrieben).
// Das Betriebssystem fuellt sie von selbst, sobald wir Verbindungen zu Geraeten im
// selben Netz versuchen. Hinter einem Router (anderes Subnetz) gibt es keine MACs.
func ReadARP() map[string]string {
	if runtime.GOOS == "linux" {
		if data, err := os.ReadFile("/proc/net/arp"); err == nil {
			return parseLinuxARP(string(data))
		}
	}
	// Windows und macOS (und Linux-Fallback): "arp -a" auswerten.
	out, err := exec.Command("arp", "-a").Output()
	if err != nil {
		return map[string]string{}
	}
	return parseARPCommand(string(out))
}

// parseLinuxARP wertet /proc/net/arp aus. Spalten: IP, HW-Typ, Flags, MAC, Mask, Device.
// Flag 0x2 = Eintrag vollstaendig (Geraet hat geantwortet).
func parseLinuxARP(text string) map[string]string {
	res := map[string]string{}
	for i, line := range strings.Split(text, "\n") {
		f := strings.Fields(line)
		if i == 0 || len(f) < 4 || f[2] != "0x2" || f[3] == "00:00:00:00:00:00" {
			continue
		}
		res[f[0]] = strings.ToUpper(f[3])
	}
	return res
}

var (
	reARPIP  = regexp.MustCompile(`\b(\d{1,3}(?:\.\d{1,3}){3})\b`)
	reARPMAC = regexp.MustCompile(`\b([0-9a-fA-F]{1,2}(?:[:-][0-9a-fA-F]{1,2}){5})\b`)
)

// parseARPCommand wertet die Ausgabe von "arp -a" (Windows/macOS/Linux) aus.
// macOS kuerzt fuehrende Nullen ("0:11:32:...") -> wird auf 2 Stellen aufgefuellt.
func parseARPCommand(text string) map[string]string {
	res := map[string]string{}
	for _, line := range strings.Split(text, "\n") {
		ip := reARPIP.FindStringSubmatch(line)
		mac := reARPMAC.FindStringSubmatch(line)
		if ip == nil || mac == nil {
			continue
		}
		if m := normalizeMAC(mac[1]); m != "" { // Broadcast/leer ueberspringen
			res[ip[1]] = m
		}
	}
	return res
}

// normalizeMAC bringt eine MAC auf das Format AA:BB:CC:DD:EE:FF.
func normalizeMAC(m string) string {
	parts := strings.FieldsFunc(m, func(r rune) bool { return r == ':' || r == '-' })
	for i, p := range parts {
		if len(p) == 1 {
			parts[i] = "0" + p
		}
	}
	mac := strings.ToUpper(strings.Join(parts, ":"))
	// Broadcast/ungueltige Eintraege ausfiltern.
	if mac == "FF:FF:FF:FF:FF:FF" || mac == "00:00:00:00:00:00" {
		return ""
	}
	return mac
}
