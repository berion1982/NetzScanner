package scan

// Echte Uplinks per SNMP (I-010, Teil 2).
//
// Idee: Ein verwalteter Switch merkt sich in seiner "MAC-Adresstabelle" (Forwarding Database,
// BRIDGE-MIB), hinter welchem seiner Ports er welche MAC-Adresse gesehen hat. Fragt man die
// Tabellen der Switches ab, laesst sich fuer jedes Geraet sagen, an welchem Switch-Port es
// haengt - und damit auch, wie die Switches untereinander verbunden sind.
//
// Ehrlich zur Genauigkeit (Vermutung, keine Garantie):
//   - SNMP v2c, "read-only"-Community. Die Community ist ein Zugangsdatum: Sie wird NIE
//     protokolliert, NIE gespeichert und NIE ausgegeben. v2c ist im Netz unverschluesselt.
//   - Hinter einem nicht abgefragten Switch/Access-Point sieht man nur den Port davor; alle
//     Geraete dahinter erscheinen am selben Port. Die Karte zeigt sie dann am naechsten
//     abgefragten Switch.
//   - Switches mit VLAN-spezifischer Community (z. B. Cisco "community@vlan") werden nicht
//     vollstaendig gelesen.
//
// Aufbau: QuerySwitch (Netzwerk, gosnmp) liest die Tabellen; BuildLinks ist reine Logik
// ohne Netzwerk und deshalb gut testbar.

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/gosnmp/gosnmp"

	"github.com/berion1982/netzscanner/internal/model"
)

// OIDs (alle ohne fuehrenden Punkt):
const (
	oidSysDescr     = "1.3.6.1.2.1.1.1.0"
	oidSysName      = "1.3.6.1.2.1.1.5.0"
	oidDot1dFdbPort = "1.3.6.1.2.1.17.4.3.1.2"     // BRIDGE-MIB: dot1dTpFdbPort.<MAC>
	oidDot1qFdbPort = "1.3.6.1.2.1.17.7.1.2.2.1.2" // Q-BRIDGE-MIB: dot1qTpFdbPort.<FDB-ID>.<MAC> (VLAN-faehig)
	oidBasePortIf   = "1.3.6.1.2.1.17.1.4.1.2"     // dot1dBasePortIfIndex.<Bridge-Port>
	oidIfName       = "1.3.6.1.2.1.31.1.1.1.1"     // ifName.<ifIndex> (z. B. "Gi1/0/5")
	oidIfDescr      = "1.3.6.1.2.1.2.2.1.2"        // ifDescr.<ifIndex> (Ersatz, wenn ifName fehlt)
	oidLldpRemBase  = "1.0.8802.1.1.2.1.4.1.1"     // LLDP-MIB: lldpRemEntry.<Spalte>.<timeMark>.<lokalerPort>.<remIndex>
	oidLldpLocDesc  = "1.0.8802.1.1.2.1.3.7.1.4"   // LLDP-MIB: lldpLocPortDesc.<lokalerPort>
	snmpTimeout     = 2 * time.Second              // pro Anfrage
	snmpRetries     = 1                            // eine Wiederholung
	snmpRepetitions = 20                           // Zeilen je Bulk-Anfrage
	MaxSNMPTargets  = 10                           // Schutz: hoechstens so viele Switches je Abfrage
	maxFDBEntries   = 20000                        // Schutz vor riesigen/manipulierten Tabellen
)

// FDBEntry sagt: Diese MAC wurde an diesem Port gesehen.
type FDBEntry struct {
	MAC  string // normalisiert (ohne Trennzeichen, Kleinbuchstaben)
	Port string // Anzeigename, z. B. "Gi1/0/5" oder "Port 7"
}

// SwitchData sind die ausgelesenen Daten eines Switches.
type SwitchData struct {
	IP       string
	SysName  string
	SysDescr string
	FDB      []FDBEntry
	LLDP     []LLDPNeighbor // direkte Nachbarn laut LLDP-MIB (I-051)
}

// Link beschreibt, wo ein Geraet angeschlossen ist.
type Link struct {
	Uplink string // IP des Switches
	Port   string // Port am Switch
	Shared int    // wie viele MACs an diesem Port gesehen wurden (1 = genau ein Geraet)
}

// SwitchInfo sind Zusatzangaben zu einem abgefragten Switch (fuer Rolle und System).
type SwitchInfo struct {
	Name  string
	Descr string
}

// NormMAC macht aus "AA:BB:CC:00:11:22", "aa-bb-..." usw. "aabbcc001122" ("" bei Unsinn).
func NormMAC(s string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(s) {
		switch {
		case r >= '0' && r <= '9', r >= 'a' && r <= 'f':
			b.WriteRune(r)
		case r == ':' || r == '-' || r == '.':
		default:
			return ""
		}
	}
	if b.Len() != 12 {
		return ""
	}
	return b.String()
}

// QuerySwitch liest per SNMP v2c Name, Beschreibung und MAC-Adresstabelle eines Switches.
// Fehlermeldungen enthalten bewusst weder Community noch Rohdaten.
func QuerySwitch(ctx context.Context, ip, community string) (SwitchData, error) {
	data := SwitchData{IP: ip}
	g := &gosnmp.GoSNMP{
		Target: ip, Port: 161, Community: community, Version: gosnmp.Version2c,
		Timeout: snmpTimeout, Retries: snmpRetries, MaxRepetitions: snmpRepetitions, Context: ctx,
	}
	if err := g.Connect(); err != nil {
		return data, fmt.Errorf("Verbindung nicht möglich")
	}
	defer g.Conn.Close()

	// 1) Name und Beschreibung - dient auch als Test, ob Community/SNMP passen.
	res, err := g.Get([]string{oidSysName, oidSysDescr})
	if err != nil || len(res.Variables) < 2 {
		return data, fmt.Errorf("keine Antwort (Community falsch oder SNMP am Gerät aus?)")
	}
	data.SysName = sanitize(pduString(res.Variables[0]))
	data.SysDescr = sanitize(pduString(res.Variables[1]))

	// 2) Tabellen: Bridge-Port -> ifIndex -> Name.
	portIf := walkInts(g, oidBasePortIf)
	names := walkStrings(g, oidIfName)
	if len(names) == 0 {
		names = walkStrings(g, oidIfDescr)
	}
	label := func(bridgePort int) string {
		if idx, ok := portIf[fmt.Sprint(bridgePort)]; ok {
			if n := sanitize(names[fmt.Sprint(idx)]); n != "" {
				return n
			}
		}
		return fmt.Sprintf("Port %d", bridgePort)
	}

	// 3) MAC-Adresstabelle: erst die VLAN-faehige (Q-BRIDGE), sonst die klassische.
	seen := map[string]bool{}
	add := func(pdus []gosnmp.SnmpPDU, base string) {
		for _, p := range pdus {
			mac := macFromOID(p.Name, base)
			port, ok := pduInt(p)
			if mac == "" || !ok || port <= 0 { // Port 0 = Switch selbst/unbekannt
				continue
			}
			key := mac + "|" + fmt.Sprint(port)
			if seen[key] || len(data.FDB) >= maxFDBEntries {
				continue
			}
			seen[key] = true
			data.FDB = append(data.FDB, FDBEntry{MAC: mac, Port: label(port)})
		}
	}
	if pdus, err := g.BulkWalkAll(oidDot1qFdbPort); err == nil {
		add(pdus, oidDot1qFdbPort)
	}
	if pdus, err := g.BulkWalkAll(oidDot1dFdbPort); err == nil {
		add(pdus, oidDot1dFdbPort)
	}

	// 4) LLDP-Nachbarn (I-051): optional - viele Geraete haben LLDP aus oder gar nicht.
	data.LLDP = queryLLDP(g, names)

	if len(data.FDB) == 0 && len(data.LLDP) == 0 {
		return data, fmt.Errorf("Gerät antwortet, hat aber weder MAC-Adresstabelle noch LLDP-Nachbarn (kein Switch?)")
	}
	return data, nil
}

// macFromOID holt die 6 letzten OID-Teile hinter base als MAC (leer, wenn es nicht passt).
func macFromOID(oid, base string) string {
	oid = strings.TrimPrefix(oid, ".")
	if !strings.HasPrefix(oid, base+".") {
		return ""
	}
	parts := strings.Split(oid[len(base)+1:], ".")
	if len(parts) < 6 {
		return ""
	}
	var b strings.Builder
	for _, p := range parts[len(parts)-6:] {
		var n int
		if _, err := fmt.Sscanf(p, "%d", &n); err != nil || n < 0 || n > 255 {
			return ""
		}
		fmt.Fprintf(&b, "%02x", n)
	}
	return b.String()
}

// pduString liefert den Text eines OctetString-Werts ("" bei anderen Typen).
func pduString(p gosnmp.SnmpPDU) string {
	if b, ok := p.Value.([]byte); ok {
		return string(b)
	}
	if s, ok := p.Value.(string); ok {
		return s
	}
	return ""
}

// pduInt liefert eine ganze Zahl aus Integer/Gauge/Counter-Werten.
func pduInt(p gosnmp.SnmpPDU) (int, bool) {
	switch v := p.Value.(type) {
	case int:
		return v, true
	case uint:
		return int(v), true
	case uint32:
		return int(v), true
	case int64:
		return int(v), true
	case uint64:
		return int(v), true
	}
	return 0, false
}

// lastOIDPart: letzter Teil einer OID als Text ("..1.7" -> "7").
func lastOIDPart(oid string) string { return oid[strings.LastIndex(oid, ".")+1:] }

// walkInts liest eine Tabelle "Index -> Zahl" (Fehler = leere Tabelle).
func walkInts(g *gosnmp.GoSNMP, oid string) map[string]int {
	out := map[string]int{}
	if pdus, err := g.BulkWalkAll(oid); err == nil {
		for _, p := range pdus {
			if n, ok := pduInt(p); ok {
				out[lastOIDPart(p.Name)] = n
			}
		}
	}
	return out
}

// walkStrings liest eine Tabelle "Index -> Text" (Fehler = leere Tabelle).
func walkStrings(g *gosnmp.GoSNMP, oid string) map[string]string {
	out := map[string]string{}
	if pdus, err := g.BulkWalkAll(oid); err == nil {
		for _, p := range pdus {
			out[lastOIDPart(p.Name)] = pduString(p)
		}
	}
	return out
}

// BuildLinks ordnet jedem Geraet (mit MAC) den Switch-Port zu, an dem es haengt.
//
// Regeln (reine Logik, kein Netzwerk):
//  1. Pro Switch zaehlen wir, wie viele MACs je Port gesehen wurden.
//  2. Der "Uplink-Port" eines Switches ist der Port, an dem die MAC des Routers (Gateway)
//     gelernt wurde. Fehlt die Router-MAC, gilt der Port mit den meisten MACs.
//     Eine MAC auf dem Uplink-Port steht "irgendwo oberhalb", nicht an diesem Switch.
//  3. Ein Geraet haengt an dem Switch-Port (nicht Uplink), auf dem seine MAC steht und der
//     die wenigsten MACs hat. So gewinnt der Zugangsport vor Ports Richtung anderer Switches.
//     Das gilt auch fuer Switches selbst (ihre MAC ist in den Tabellen der Nachbarn).
//
// Geraete ohne Treffer bekommen keinen Eintrag (ihr bisheriger Uplink bleibt).
func BuildLinks(hosts []model.Host, switches []SwitchData, routerMAC string) map[string]Link {
	routerMAC = NormMAC(routerMAC)
	type portKey struct{ sw, port string }

	// Regel 1: MACs je Port (doppelte Eintraege ignorieren).
	macsOnPort := map[portKey]map[string]bool{}
	for _, sw := range switches {
		for _, e := range sw.FDB {
			k := portKey{sw.IP, e.Port}
			if macsOnPort[k] == nil {
				macsOnPort[k] = map[string]bool{}
			}
			macsOnPort[k][e.MAC] = true
		}
	}

	// Regel 2: Uplink-Port je Switch.
	uplink := map[string]string{}
	for _, sw := range switches {
		best, bestN := "", 0
		for _, n := range sw.LLDP { // LLDP nennt den Router direkt -> sicherster Hinweis
			if routerMAC != "" && n.MAC == routerMAC {
				best, bestN = n.LocalPort, -1
				break
			}
		}
		for _, e := range sw.FDB {
			if bestN == -1 {
				break
			}
			if routerMAC != "" && e.MAC == routerMAC {
				best = e.Port
				bestN = -1 // Router-MAC gefunden: endgueltig
				break
			}
		}
		if bestN == 0 { // Ersatz: Port mit den meisten MACs (Reihenfolge stabil halten)
			ports := map[string]bool{}
			for _, e := range sw.FDB {
				ports[e.Port] = true
			}
			names := make([]string, 0, len(ports))
			for p := range ports {
				names = append(names, p)
			}
			sort.Strings(names)
			for _, p := range names {
				if n := len(macsOnPort[portKey{sw.IP, p}]); n > bestN {
					best, bestN = p, n
				}
			}
		}
		uplink[sw.IP] = best
	}

	// Regel 3: bester Port je Geraet.
	links := map[string]Link{}
	lldpLinks(hosts, switches, uplink, routerMAC, links)
	for _, h := range hosts {
		mac := NormMAC(h.MAC)
		if mac == "" || mac == routerMAC {
			continue
		}
		if _, done := links[h.IP]; done {
			continue // LLDP ist genauer als die MAC-Tabelle
		}
		var best *Link
		for _, sw := range switches {
			if sw.IP == h.IP {
				continue // ein Switch haengt nicht an sich selbst
			}
			for _, e := range sw.FDB {
				if e.MAC != mac || e.Port == uplink[sw.IP] {
					continue
				}
				n := len(macsOnPort[portKey{sw.IP, e.Port}])
				if best == nil || n < best.Shared || (n == best.Shared && sw.IP < best.Uplink) {
					best = &Link{Uplink: sw.IP, Port: e.Port, Shared: n}
				}
			}
		}
		if best != nil {
			links[h.IP] = *best
		}
	}
	breakCycles(links)
	return links
}

// breakCycles entfernt Verbindungen, die einen Kreis bilden wuerden (bei widerspruechlichen
// Tabellen), damit die Karte nie in eine Endlosschleife laeuft.
func breakCycles(links map[string]Link) {
	ips := make([]string, 0, len(links))
	for ip := range links {
		ips = append(ips, ip)
	}
	sort.Strings(ips)
	for _, start := range ips {
		cur := start
		for steps := 0; steps <= len(links); steps++ {
			l, ok := links[cur]
			if !ok {
				break
			}
			if l.Uplink == start {
				delete(links, start) // Kreis geschlossen -> diese Verbindung verwerfen
				break
			}
			cur = l.Uplink
		}
	}
}
