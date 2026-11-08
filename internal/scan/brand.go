package scan

// Markennamen statt Firmennamen aus der IEEE-Liste.
//
// In der OUI-Liste steht oft die Firma, die den MAC-Block gekauft hat, nicht die Marke, die der
// Nutzer kennt (z. B. "Fantasia Trading LLC" statt "Anker"). Diese kleine Tabelle uebersetzt
// bekannte Faelle fuer den Namensvorschlag. Die Einordnung (Kategorie) nutzt weiter den
// Original-Herstellernamen. Eintraege nur, wenn sie bestaetigt sind - Sascha hat F4:9D:8A
// (Fantasia Trading LLC) als Anker-Geraet bestaetigt. Weitere Faelle bitte melden.

import "strings"

// brandAliases: Teilstring des IEEE-Herstellernamens (Kleinbuchstaben) -> Marke.
var brandAliases = map[string]string{
	"fantasia trading": "Anker (eufy)",
}

// BrandName liefert die bekannte Marke zum IEEE-Herstellernamen, sonst den Namen unveraendert.
func BrandName(vendor string) string {
	low := strings.ToLower(vendor)
	for part, brand := range brandAliases {
		if strings.Contains(low, part) {
			return brand + " – " + vendor
		}
	}
	return vendor
}
