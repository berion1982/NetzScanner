package scan

import (
	"bufio"
	_ "embed"
	"strings"
	"sync"
)

// ouiData ist die eingebettete Herstellerliste (internal/scan/data/oui.txt).
// Format pro Zeile: "AABBCC;Herstellername"; Zeilen mit "#" sind Kommentare.
// Die vollstaendige Liste erzeugt scripts/update-oui.sh aus der IEEE-Registry.
//
//go:embed data/oui.txt
var ouiData string

var (
	ouiOnce  sync.Once
	ouiTable map[string]string // Schluessel: 6 Hex-Zeichen in Grossbuchstaben
)

// parseOUI liest das Listenformat in eine Tabelle. Defekte Zeilen werden uebersprungen.
func parseOUI(data string) map[string]string {
	m := make(map[string]string, 40000)
	sc := bufio.NewScanner(strings.NewReader(data))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || line[0] == '#' {
			continue
		}
		prefix, name, ok := strings.Cut(line, ";")
		prefix = strings.ToUpper(strings.TrimSpace(prefix))
		if !ok || len(prefix) != 6 {
			continue
		}
		m[prefix] = strings.TrimSpace(name)
	}
	return m
}

// oui laedt die Tabelle beim ersten Zugriff (einmalig, threadsicher).
func oui() map[string]string {
	ouiOnce.Do(func() { ouiTable = parseOUI(ouiData) })
	return ouiTable
}

// macPrefix macht aus "b8:27:eb:12:34:56" (auch mit - oder ohne Trenner) "B827EB".
// Liefert "" bei zu kurzer/ungueltiger MAC.
func macPrefix(mac string) string {
	var b strings.Builder
	for _, r := range strings.ToUpper(mac) {
		switch {
		case r >= '0' && r <= '9', r >= 'A' && r <= 'F':
			b.WriteRune(r)
		case r == ':' || r == '-' || r == '.':
		default:
			return ""
		}
		if b.Len() == 6 {
			return b.String()
		}
	}
	return ""
}

// Vendor liefert den Hersteller zu einer MAC. Ist das "lokal verwaltet"-Bit
// gesetzt (zweites Hex-Zeichen 2/6/A/E), ist die MAC zufaellig/virtuell -
// typisch fuer Smartphones mit Privatsphaere-Funktion oder virtuelle Maschinen.
// Unbekannte Praefixe ergeben "".
func Vendor(mac string) string {
	p := macPrefix(mac)
	if p == "" {
		return ""
	}
	// Lokal verwaltete MACs stehen nicht in der IEEE-Liste -> zuerst pruefen.
	if strings.ContainsRune("26AE", rune(p[1])) {
		return "zufaellige/lokale MAC"
	}
	return oui()[p]
}
