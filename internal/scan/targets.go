// Package scan enthaelt den Scan-Kern: Zielauswertung, Portscan, ARP/MAC, Namen, Banner.
package scan

import (
	"fmt"
	"net"
	"net/netip"
	"strings"
)

// MaxTargets begrenzt einen Scan auf maximal /16 (65.536 Adressen), damit
// ein Tippfehler (z.B. 10.0.0.0/8) nicht stundenlang das Netz belastet.
const MaxTargets = 1 << 16

// ExpandTarget wandelt "192.168.1.0/24" oder "192.168.1.5" in eine IP-Liste um.
// Nur IPv4. Ohne allowPublic sind nur private/lokale Adressen erlaubt - das Tool
// ist fuers Onboarding eigener Netze gedacht, nicht zum Scannen des Internets.
func ExpandTarget(target string, allowPublic bool) ([]netip.Addr, error) {
	target = strings.TrimSpace(target)
	if target == "" {
		return nil, fmt.Errorf("kein Ziel angegeben")
	}
	// Einzelne IP wie /32 behandeln.
	if !strings.Contains(target, "/") {
		target += "/32"
	}
	prefix, err := netip.ParsePrefix(target)
	if err != nil {
		return nil, fmt.Errorf("ungueltiges Ziel %q (erwartet z.B. 192.168.1.0/24)", target)
	}
	prefix = prefix.Masked()
	if !prefix.Addr().Is4() {
		return nil, fmt.Errorf("nur IPv4 wird unterstuetzt")
	}
	if prefix.Bits() < 16 {
		return nil, fmt.Errorf("Netz zu gross (maximal /16 erlaubt)")
	}
	if !allowPublic && !isLocalAddr(prefix.Addr()) {
		return nil, fmt.Errorf("oeffentliche Adressen sind gesperrt (nur private Netze; --allow-public aktiviert sie)")
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
