package scan

// System-Infos per SNMP (I-023, Rest): Zusatzangaben, die ein Geraet nach erfolgreicher
// SNMP-Abfrage (v2c oder v3, Zugang aus dem SNMP-Formular) ueber sich preisgibt.
//
// Regeln:
//   - Ausschliesslich lesende GET-/Walk-Anfragen auf feste, standardisierte OIDs
//     (SNMPv2-MIB, IF-MIB, ENTITY-MIB). Es wird nichts geschrieben (kein SET).
//   - Alles ist optional: Fehlt ein Wert, fehlt nur die Zeile - die Abfrage scheitert deshalb nicht.
//   - Bewusst NICHT gelesen: sysContact (kann Namen/E-Mail einer Person enthalten) und
//     Seriennummern.
//   - Texte werden mit sanitize() bereinigt; Anzahl der Schnittstellen ist begrenzt.

import (
	"fmt"
	"sort"
	"strings"

	"github.com/gosnmp/gosnmp"

	"github.com/berion1982/netzscanner/internal/model"
)

// OIDs fuer die Zusatzangaben (ohne fuehrenden Punkt).
const (
	oidSysUpTime      = "1.3.6.1.2.1.1.3.0"         // SNMPv2-MIB: sysUpTime (Hundertstel Sekunden)
	oidSysLocation    = "1.3.6.1.2.1.1.6.0"         // SNMPv2-MIB: sysLocation (frei einstellbarer Standort)
	oidIfPhysAddress  = "1.3.6.1.2.1.2.2.1.6"       // IF-MIB: ifPhysAddress.<ifIndex>
	oidIfOperStatus   = "1.3.6.1.2.1.2.2.1.8"       // IF-MIB: ifOperStatus.<ifIndex> (1 = up, 2 = down ...)
	oidIfHighSpeed    = "1.3.6.1.2.1.31.1.1.1.15"   // IF-MIB: ifHighSpeed.<ifIndex> (Mbit/s)
	oidEntModelName   = "1.3.6.1.2.1.47.1.1.1.1.13" // ENTITY-MIB: entPhysicalModelName.<Index>
	oidEntFirmwareRev = "1.3.6.1.2.1.47.1.1.1.1.9"  // ENTITY-MIB: entPhysicalFirmwareRev.<Index>
	oidEntSoftwareRev = "1.3.6.1.2.1.47.1.1.1.1.10" // ENTITY-MIB: entPhysicalSoftwareRev.<Index>
	maxInfoIfaces     = 32                          // Schutz: hoechstens so viele Schnittstellen anzeigen
)

// querySystemInfo liest die Zusatzangaben ueber eine bereits verbundene Sitzung.
func querySystemInfo(g *gosnmp.GoSNMP) []model.InfoField {
	var out []model.InfoField
	add := func(name, value string) {
		if v := sanitize(value); v != "" {
			out = append(out, model.InfoField{Name: name, Value: v})
		}
	}

	// Standort und Laufzeit: je ein eigener GET, damit ein fehlender Wert den anderen nicht verhindert.
	if res, err := g.Get([]string{oidSysLocation}); err == nil && len(res.Variables) == 1 {
		add("Standort (SNMP)", pduString(res.Variables[0]))
	}
	if res, err := g.Get([]string{oidSysUpTime}); err == nil && len(res.Variables) == 1 {
		if ticks, ok := pduInt(res.Variables[0]); ok && ticks >= 0 {
			add("Laufzeit (SNMP)", formatTicks(ticks))
		}
	}

	// Modell und Firmware aus der ENTITY-MIB (nicht jedes Geraet bietet sie an).
	add("Modell (SNMP)", firstNonEmpty(walkStrings(g, oidEntModelName)))
	add("Firmware (SNMP)", firstNonEmpty(walkStrings(g, oidEntFirmwareRev)))
	add("Software (SNMP)", firstNonEmpty(walkStrings(g, oidEntSoftwareRev)))

	// Schnittstellen: Name, Zustand, MAC, Geschwindigkeit.
	names := walkStrings(g, oidIfName)
	if len(names) == 0 {
		names = walkStrings(g, oidIfDescr)
	}
	status := walkInts(g, oidIfOperStatus)
	speed := walkInts(g, oidIfHighSpeed)
	macs := map[string]string{}
	if pdus, err := g.BulkWalkAll(oidIfPhysAddress); err == nil {
		for _, p := range pdus {
			if b, ok := p.Value.([]byte); ok {
				macs[lastOIDPart(p.Name)] = formatMACBytes(b)
			}
		}
	}
	return append(out, ifaceFields(names, status, speed, macs)...)
}

// ifaceFields baut aus den Tabellen (Schluessel = ifIndex) die Anzeigezeilen "Schnittstelle <Name>".
// Reine Logik ohne Netzwerk. Sortiert nach ifIndex, hoechstens maxInfoIfaces Zeilen;
// Loopback-Schnittstellen ("lo", "Loopback...") werden uebersprungen.
func ifaceFields(names map[string]string, status, speed map[string]int, macs map[string]string) []model.InfoField {
	idx := make([]int, 0, len(names))
	for k := range names {
		var n int
		if _, err := fmt.Sscanf(k, "%d", &n); err == nil {
			idx = append(idx, n)
		}
	}
	sort.Ints(idx)
	var out []model.InfoField
	for _, n := range idx {
		if len(out) >= maxInfoIfaces {
			break
		}
		key := fmt.Sprint(n)
		name := sanitize(names[key])
		low := strings.ToLower(name)
		if name == "" || low == "lo" || strings.HasPrefix(low, "loopback") {
			continue
		}
		parts := []string{ifStatusText(status[key])}
		if mac := macs[key]; mac != "" {
			parts = append(parts, mac)
		}
		if sp := speed[key]; sp > 0 {
			parts = append(parts, formatMbit(sp))
		}
		out = append(out, model.InfoField{Name: "Schnittstelle " + name, Value: strings.Join(parts, ", ")})
	}
	return out
}

// ifStatusText uebersetzt ifOperStatus (RFC 2863) in Klartext.
func ifStatusText(v int) string {
	switch v {
	case 1:
		return "aktiv"
	case 2:
		return "inaktiv"
	case 3:
		return "Test"
	case 5:
		return "schlafend"
	case 6:
		return "nicht vorhanden"
	case 7:
		return "unterbrochen"
	}
	return "Zustand unbekannt"
}

// formatMbit zeigt Mbit/s, ab 1000 als Gbit/s ("1000" -> "1 Gbit/s").
func formatMbit(m int) string {
	if m >= 1000 && m%100 == 0 {
		if m%1000 == 0 {
			return fmt.Sprintf("%d Gbit/s", m/1000)
		}
		return fmt.Sprintf("%.1f Gbit/s", float64(m)/1000)
	}
	return fmt.Sprintf("%d Mbit/s", m)
}

// formatMACBytes zeigt 6 Bytes als "aa:bb:cc:dd:ee:ff"; alles andere (leer, 00:00..., falsche Laenge) ergibt "".
func formatMACBytes(b []byte) string {
	if len(b) != 6 {
		return ""
	}
	allZero := true
	parts := make([]string, 6)
	for i, v := range b {
		if v != 0 {
			allZero = false
		}
		parts[i] = fmt.Sprintf("%02x", v)
	}
	if allZero {
		return ""
	}
	return strings.Join(parts, ":")
}

// formatTicks wandelt sysUpTime (Hundertstel Sekunden) in "3 Tage 4 Std 5 Min" um.
func formatTicks(ticks int) string {
	sec := ticks / 100
	days, hours, mins := sec/86400, sec%86400/3600, sec%3600/60
	switch {
	case days > 0:
		return fmt.Sprintf("%d Tage %d Std %d Min", days, hours, mins)
	case hours > 0:
		return fmt.Sprintf("%d Std %d Min", hours, mins)
	}
	return fmt.Sprintf("%d Min", mins)
}

// firstNonEmpty liefert den ersten nicht leeren Wert der Tabelle mit dem kleinsten Index
// (bei der ENTITY-MIB meist das Gehaeuse bzw. Hauptgeraet; ob das stimmt, haengt vom Geraet ab).
func firstNonEmpty(table map[string]string) string {
	keys := make([]int, 0, len(table))
	for k := range table {
		var n int
		if _, err := fmt.Sscanf(k, "%d", &n); err == nil {
			keys = append(keys, n)
		}
	}
	sort.Ints(keys)
	for _, n := range keys {
		if v := strings.TrimSpace(table[fmt.Sprint(n)]); v != "" {
			return v
		}
	}
	return ""
}
