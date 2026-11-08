package scan

// LLDP-Nachbarn per SNMP (I-051).
//
// LLDP (IEEE 802.1AB) ist ein herstellerneutrales Protokoll: Jedes Geraet meldet seinen
// direkten Nachbarn "Ich bin X, mein Port heisst Y". Per SNMP lassen sich diese Nachbarn aus
// der LLDP-MIB (lldpRemTable) lesen. Das ist genauer als die MAC-Adresstabelle, weil es die
// echte Verkabelung nennt - auch zu Access Points und Routern.
//
// Ehrlich zur Genauigkeit (Vermutung, keine Garantie):
//   - LLDP muss am Geraet eingeschaltet sein; sonst ist die Tabelle leer (dann gilt weiter
//     die MAC-Tabelle). Ich weiss nicht, welche Geraete von Sascha es ab Werk an haben.
//   - Die "Chassis-ID" ist oft die Basis-MAC des Geraets und kann von der MAC abweichen, die
//     der Scan sieht. Dann bleibt die Zuordnung aus (Fallback MAC-Tabelle).
//   - Annahme: Die lokale LLDP-Portnummer entspricht dem ifIndex (haeufig, nicht garantiert);
//     sie dient nur der Anzeige des Portnamens.

import (
	"fmt"
	"net"
	"strings"

	"github.com/gosnmp/gosnmp"

	"github.com/berion1982/netzscanner/internal/model"
)

// Werte von lldpRemChassisIdSubtype, die wir verstehen.
const (
	chassisSubtypeMAC  = 4 // macAddress
	chassisSubtypeAddr = 5 // networkAddress (erstes Byte: Adressfamilie, 1 = IPv4)
	maxLLDPNeighbors   = 2000
)

// LLDPNeighbor ist ein direkter Nachbar eines Switches.
type LLDPNeighbor struct {
	LocalPort string // Port am abgefragten Switch (gleiche Benennung wie in der MAC-Tabelle)
	MAC       string // normalisierte Chassis-MAC des Nachbarn ("" wenn nicht als MAC angegeben)
	IP        string // Management-IPv4 des Nachbarn ("" wenn nicht angegeben)
	SysName   string // Name, den der Nachbar von sich meldet
	RemPort   string // Port am Nachbarn (zur Anzeige)
}

// lldpColumn liest eine Spalte der lldpRemTable. Schluessel = "timeMark.lokalerPort.remIndex".
func lldpColumn(g *gosnmp.GoSNMP, col int) map[string]gosnmp.SnmpPDU {
	base := fmt.Sprintf("%s.%d", oidLldpRemBase, col)
	out := map[string]gosnmp.SnmpPDU{}
	pdus, err := g.BulkWalkAll(base)
	if err != nil {
		return out
	}
	for _, p := range pdus {
		oid := strings.TrimPrefix(p.Name, ".")
		if strings.HasPrefix(oid, base+".") && len(out) < maxLLDPNeighbors {
			out[oid[len(base)+1:]] = p
		}
	}
	return out
}

// lldpLocalPort holt die lokale Portnummer (mittlerer Teil) aus "timeMark.lokalerPort.remIndex".
func lldpLocalPort(key string) string {
	parts := strings.Split(key, ".")
	if len(parts) != 3 {
		return ""
	}
	return parts[1]
}

// queryLLDP liest die Nachbartabelle. ifNames (ifIndex -> Name) macht Portnamen vergleichbar
// mit denen der MAC-Tabelle. Fehler/leere Tabelle ergeben einfach keine Nachbarn.
func queryLLDP(g *gosnmp.GoSNMP, ifNames map[string]string) []LLDPNeighbor {
	subtypes := lldpColumn(g, 4)
	chassis := lldpColumn(g, 5)
	if len(chassis) == 0 {
		return nil
	}
	remPorts := lldpColumn(g, 8) // lldpRemPortDesc
	remIDs := lldpColumn(g, 7)   // lldpRemPortId (Ersatz)
	sysNames := lldpColumn(g, 9)
	locDesc := walkStrings(g, oidLldpLocDesc)

	var out []LLDPNeighbor
	for key, p := range chassis {
		lp := lldpLocalPort(key)
		if lp == "" {
			continue
		}
		// Portname: ifName (wie in der MAC-Tabelle) > LLDP-Beschreibung > "Port N".
		port := sanitize(ifNames[lp])
		if port == "" {
			port = sanitize(locDesc[lp])
		}
		if port == "" {
			port = "Port " + lp
		}
		n := LLDPNeighbor{LocalPort: port}
		n.MAC, n.IP = parseChassisID(pduBytes(p), subtypeOf(subtypes[key]))
		n.SysName = sanitize(pduString(sysNames[key]))
		n.RemPort = sanitize(pduString(remPorts[key]))
		if n.RemPort == "" {
			n.RemPort = sanitize(pduString(remIDs[key]))
		}
		out = append(out, n)
	}
	return out
}

// subtypeOf liest den Subtyp-Wert (0 = unbekannt).
func subtypeOf(p gosnmp.SnmpPDU) int {
	n, _ := pduInt(p)
	return n
}

// pduBytes liefert die Rohbytes eines OctetString-Werts.
func pduBytes(p gosnmp.SnmpPDU) []byte {
	switch v := p.Value.(type) {
	case []byte:
		return v
	case string:
		return []byte(v)
	}
	return nil
}

// parseChassisID macht aus der Chassis-ID eine MAC bzw. IPv4 (je nach Subtyp). Reine Logik.
func parseChassisID(raw []byte, subtype int) (mac, ip string) {
	switch subtype {
	case chassisSubtypeMAC:
		if len(raw) == 6 {
			return fmt.Sprintf("%02x%02x%02x%02x%02x%02x", raw[0], raw[1], raw[2], raw[3], raw[4], raw[5]), ""
		}
	case chassisSubtypeAddr:
		if len(raw) == 5 && raw[0] == 1 { // 1 = IPv4
			return "", net.IP(raw[1:]).String()
		}
	}
	return "", ""
}

// lldpLinks traegt Geraete ein, die ein Switch laut LLDP direkt an einem Port sieht.
// Ein Nachbar am Uplink-Port liegt "oberhalb" und wird hier uebersprungen (er taucht in
// der Tabelle des Nachbarn selbst als "unterhalb" auf, sofern dieser abgefragt wurde).
func lldpLinks(hosts []model.Host, switches []SwitchData, uplink map[string]string, routerMAC string, links map[string]Link) {
	for _, sw := range switches {
		for _, n := range sw.LLDP {
			if n.LocalPort == uplink[sw.IP] {
				continue
			}
			for _, h := range hosts {
				mac := NormMAC(h.MAC)
				if h.IP == sw.IP || (mac != "" && mac == routerMAC) {
					continue
				}
				if (n.IP != "" && n.IP == h.IP) || (n.MAC != "" && n.MAC == mac) {
					if _, done := links[h.IP]; !done {
						links[h.IP] = Link{Uplink: sw.IP, Port: n.LocalPort, Shared: 1}
					}
				}
			}
		}
	}
}
