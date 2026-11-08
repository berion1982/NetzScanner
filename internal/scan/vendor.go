package scan

// Hersteller eines SNMP-Geraets aus der sysObjectID (I-052).
//
// Jedes SNMP-Geraet nennt unter 1.3.6.1.2.1.1.2.0 (sysObjectID) eine OID, die mit
// 1.3.6.1.4.1.<Enterprise-Nummer> beginnt. Die Enterprise-Nummer (IANA "Private Enterprise
// Numbers") verraet den Hersteller. Die Tabelle unten ist aus dem Gedaechtnis erstellt und
// bewusst klein - ich habe sie nicht gegen die IANA-Liste geprueft ("Ich weiss es nicht"
// fuer jeden Eintrag). Unbekannte Nummern ergeben einfach keinen Herstellernamen.

import "strings"

// enterpriseVendors: Enterprise-Nummer -> Herstellername.
var enterpriseVendors = map[string]string{
	"9":     "Cisco",
	"11":    "HP",
	"171":   "D-Link",
	"674":   "Dell",
	"890":   "Zyxel",
	"1916":  "Extreme Networks",
	"1991":  "Brocade",
	"2011":  "Huawei",
	"2356":  "LANCOM",
	"2636":  "Juniper",
	"4526":  "Netgear",
	"6574":  "Synology",
	"8072":  "net-snmp (Linux/Unix)",
	"11863": "TP-Link",
	"12356": "Fortinet",
	"14823": "Aruba",
	"14988": "MikroTik",
	"41112": "Ubiquiti",
}

const enterprisePrefix = "1.3.6.1.4.1."

// VendorFromObjectID liefert den Hersteller zur sysObjectID ("" wenn unbekannt). Reine Logik.
func VendorFromObjectID(oid string) string {
	oid = strings.TrimPrefix(strings.TrimSpace(oid), ".")
	if !strings.HasPrefix(oid, enterprisePrefix) {
		return ""
	}
	num := oid[len(enterprisePrefix):]
	if i := strings.Index(num, "."); i >= 0 {
		num = num[:i]
	}
	return enterpriseVendors[num]
}

// vendorHint ist der Hinweistext, wenn ein Geraet antwortet, aber keine Tabellen liefert.
func vendorHint(vendor string) string {
	if vendor == "" {
		return "Gerät antwortet, hat aber weder MAC-Adresstabelle noch LLDP-Nachbarn (kein Switch? Bridge-MIB/LLDP am Gerät einschalten)"
	}
	return "Gerät (" + vendor + ") antwortet, liefert aber weder MAC-Adresstabelle noch LLDP-Nachbarn – Bridge-MIB bzw. LLDP am Gerät einschalten oder ist es kein Switch?"
}
