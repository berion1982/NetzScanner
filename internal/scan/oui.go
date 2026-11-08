package scan

import "strings"

// ouiTable ist NUR eine kleine Beispieltabelle (Herstellerpraefixe der MAC).
// Sie ist unvollstaendig und nicht gegen die IEEE-Liste geprueft.
// TODO (Roadmap): vollstaendige IEEE-OUI-Liste einbetten.
var ouiTable = map[string]string{
	"B8:27:EB": "Raspberry Pi", "DC:A6:32": "Raspberry Pi", "E4:5F:01": "Raspberry Pi",
	"00:11:32": "Synology", "00:1B:A9": "Brother", "3C:A6:2F": "AVM (FRITZ!)",
}

// Vendor liefert den Hersteller zu einer MAC. Ist das "lokal verwaltet"-Bit
// gesetzt (zweites Hex-Zeichen 2/6/A/E), ist die MAC zufaellig/virtuell -
// typisch fuer Smartphones mit Privatsphaere-Funktion oder virtuelle Maschinen.
func Vendor(mac string) string {
	if len(mac) < 8 {
		return ""
	}
	if v, ok := ouiTable[strings.ToUpper(mac[:8])]; ok {
		return v
	}
	if strings.ContainsRune("26AE", rune(strings.ToUpper(mac)[1])) {
		return "zufaellige/lokale MAC"
	}
	return ""
}
