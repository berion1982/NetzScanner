// Package scan enthaelt den Scan-Kern: Zielauswertung, Portscan, ARP/MAC, Namen, Banner.
package scan

import (
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
)

// MaxTargets begrenzt einen Scan auf maximal /16 (65.536 Adressen), damit
// ein Tippfehler (z.B. 10.0.0.0/8) nicht stundenlang das Netz belastet.
const MaxTargets = 1 << 16

// ExpandTarget wandelt eine Zielangabe in eine IP-Liste um (nur IPv4). Erlaubt sind,
// auch gemischt und durch Komma getrennt (I-046):
//   - Netz (CIDR):        192.168.1.0/24        (Netz- und Broadcast-Adresse entfallen bis /30)
//   - Einzel-IP:          192.168.1.5
//   - Bereich, kurz:      192.168.1.10-50       (nur die letzte Zahl wiederholt)
//   - Bereich, ausfuehrlich: 192.168.1.10-192.168.2.20
//
// Doppelte Adressen werden entfernt, die Reihenfolge bleibt. Insgesamt sind hoechstens
// MaxTargets Adressen erlaubt. Ohne allowPublic sind nur private/lokale Adressen erlaubt -
// das Tool ist fuers Onboarding eigener Netze gedacht, nicht zum Scannen des Internets.
func ExpandTarget(target string, allowPublic bool) ([]netip.Addr, error) {
	if strings.TrimSpace(target) == "" {
		return nil, fmt.Errorf("kein Ziel angegeben")
	}
	var out []netip.Addr
	seen := map[netip.Addr]bool{}
	for _, part := range strings.Split(target, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			return nil, fmt.Errorf("leeres Ziel in der Liste (Komma zu viel?)")
		}
		ips, err := expandPart(part)
		if err != nil {
			return nil, err
		}
		for _, a := range ips {
			if !allowPublic && !isLocalAddr(a) {
				return nil, fmt.Errorf("oeffentliche Adresse %s gesperrt (nur private Netze; --allow-public aktiviert sie)", a)
			}
			if !seen[a] {
				seen[a] = true
				out = append(out, a)
			}
		}
		if len(out) > MaxTargets {
			return nil, fmt.Errorf("zu viele Adressen (maximal %d)", MaxTargets)
		}
	}
	return out, nil
}

// expandPart wertet genau EINE Angabe (Netz, Einzel-IP oder Bereich) aus.
func expandPart(part string) ([]netip.Addr, error) {
	switch {
	case strings.Contains(part, "-"):
		return expandRange(part)
	case strings.Contains(part, "/"):
		return expandPrefix(part)
	default:
		return expandPrefix(part + "/32") // Einzel-IP wie /32
	}
}

// badTarget ist der einheitliche Fehler fuer nicht lesbare Angaben.
func badTarget(part string) error {
	return fmt.Errorf("ungueltiges Ziel %q (erwartet z.B. 192.168.1.0/24, 192.168.1.5 oder 192.168.1.10-50)", part)
}

// expandPrefix wertet ein Netz in CIDR-Schreibweise aus.
func expandPrefix(part string) ([]netip.Addr, error) {
	prefix, err := netip.ParsePrefix(part)
	if err != nil {
		return nil, badTarget(strings.TrimSuffix(part, "/32"))
	}
	prefix = prefix.Masked()
	if !prefix.Addr().Is4() {
		return nil, fmt.Errorf("nur IPv4 wird unterstuetzt")
	}
	if prefix.Bits() < 16 {
		return nil, fmt.Errorf("Netz zu gross (maximal /16 erlaubt)")
	}
	var out []netip.Addr
	for a := prefix.Addr(); prefix.Contains(a); a = a.Next() {
		out = append(out, a)
	}
	// Bei Netzen bis /30 Netz- und Broadcast-Adresse auslassen.
	if prefix.Bits() <= 30 && len(out) > 2 {
		out = out[1 : len(out)-1]
	}
	return out, nil
}

// expandRange wertet "a.b.c.10-50" (Kurzform) oder "a.b.c.10-a.b.d.20" aus.
// Anfang und Ende gehoeren dazu; Anfang muss <= Ende sein.
func expandRange(part string) ([]netip.Addr, error) {
	left, right, _ := strings.Cut(part, "-")
	left, right = strings.TrimSpace(left), strings.TrimSpace(right)
	start, err := netip.ParseAddr(left)
	if err != nil || !start.Is4() {
		return nil, badTarget(part)
	}
	var end netip.Addr
	if n, convErr := strconv.Atoi(right); convErr == nil && !strings.Contains(right, ".") {
		// Kurzform: nur die letzte Stelle des Endes angegeben.
		if n < 0 || n > 255 {
			return nil, badTarget(part)
		}
		b := start.As4()
		b[3] = byte(n)
		end = netip.AddrFrom4(b)
	} else if end, err = netip.ParseAddr(right); err != nil || !end.Is4() {
		return nil, badTarget(part)
	}
	if end.Less(start) {
		return nil, fmt.Errorf("Bereich %q: Anfang liegt hinter dem Ende", part)
	}
	// Groesse vorab pruefen, damit kein riesiger Bereich erst aufgebaut wird.
	if size := addrNumber(end) - addrNumber(start) + 1; size > MaxTargets {
		return nil, fmt.Errorf("Bereich zu gross (maximal %d Adressen)", MaxTargets)
	}
	var out []netip.Addr
	for a := start; ; a = a.Next() {
		out = append(out, a)
		if a == end {
			break
		}
	}
	return out, nil
}

// addrNumber macht aus einer IPv4-Adresse eine Zahl (zum Rechnen mit Bereichen).
func addrNumber(a netip.Addr) int {
	b := a.As4()
	return int(b[0])<<24 | int(b[1])<<16 | int(b[2])<<8 | int(b[3])
}

// isLocalAddr: privat (RFC1918), Loopback oder Link-Local.
func isLocalAddr(a netip.Addr) bool {
	return a.IsPrivate() || a.IsLoopback() || a.IsLinkLocalUnicast()
}

// LocalNetworks liefert die IPv4-Netze der lokalen Schnittstellen als
// Scan-Vorschlaege. Netze groesser als /24 werden auf das /24 der eigenen IP
// begrenzt, damit der Standardvorschlag schnell bleibt.
func LocalNetworks() []string {
	var out []string
	ifaces, err := net.Interfaces()
	if err != nil {
		return out
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
			ip, _ := netip.AddrFromSlice(ipn.IP.To4())
			ones, _ := ipn.Mask.Size()
			if ones < 24 {
				ones = 24
			}
			out = append(out, netip.PrefixFrom(ip, ones).Masked().String())
		}
	}
	return out
}
