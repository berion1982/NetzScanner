// Package licenses haelt die Lizenzangaben des NetzScanners.
//
// Der NetzScanner steht unter der GNU Affero General Public License v3
// (oder spaeter, SPDX: AGPL-3.0-or-later); der volle Text liegt in der
// Datei LICENSE im Repo-Wurzelverzeichnis und wird von scripts/build.sh
// neben die Programmdateien gelegt.
//
// Zusaetzlich bettet das Paket die Lizenztexte aller einkompilierten
// Fremdbibliotheken ein (THIRD_PARTY_LICENSES.txt). Diese Datei wird mit
// scripts/third-party-licenses.sh erzeugt und muss nach jeder Aenderung an
// go.mod neu erzeugt werden. Ausgabe im Programm: "--licenses".
package licenses

import (
	_ "embed" // fuer //go:embed
	"strings"
)

// SPDX ist die maschinenlesbare Kurzbezeichnung der Projektlizenz.
const SPDX = "AGPL-3.0-or-later"

// SourceURL ist der Ort des Quellcodes. Die AGPL (Abschnitt 13) verlangt,
// dass Nutzer, die das Programm ueber ein Netzwerk bedienen, den Quellcode
// angeboten bekommen; deshalb zeigt auch die Web-Oberflaeche diesen Link.
const SourceURL = "https://github.com/berion1982/NetzScanner"

// thirdParty ist der eingebettete Inhalt von THIRD_PARTY_LICENSES.txt.
//
//go:embed THIRD_PARTY_LICENSES.txt
var thirdParty string

// Notice liefert den kurzen Lizenzhinweis des NetzScanners selbst
// (deutsche Kurzfassung; rechtlich gilt der englische Originaltext in LICENSE).
func Notice() string {
	return strings.Join([]string{
		"NetzScanner - Lizenz: GNU Affero General Public License v3 oder spaeter (" + SPDX + ")",
		"Quellcode: " + SourceURL,
		"",
		"Dieses Programm ist freie Software: Du darfst es weitergeben und veraendern,",
		"solange du dich an die AGPL haeltst. Wer es veraendert weitergibt oder ueber",
		"ein Netzwerk anbietet, muss den Quellcode unter derselben Lizenz offenlegen.",
		"Es gibt KEINERLEI GARANTIE, soweit gesetzlich zulaessig.",
		"Der vollstaendige Lizenztext liegt in der Datei LICENSE.",
	}, "\n")
}

// ThirdParty liefert die Lizenztexte aller einkompilierten Fremdbibliotheken.
func ThirdParty() string { return thirdParty }

// Full liefert Projekt-Hinweis und Fremdlizenzen zusammen (fuer "--licenses").
func Full() string {
	return Notice() + "\n\n" + ThirdParty()
}
