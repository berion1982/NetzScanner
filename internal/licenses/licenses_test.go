package licenses

import (
	"os"
	"strings"
	"testing"
)

// TestThirdPartyCoversDirectDependencies prueft, dass jede direkte Abhaengigkeit
// aus go.mod in der eingebetteten Fremdlizenz-Datei vorkommt. Schlaegt der Test
// fehl, wurde go.mod geaendert, ohne scripts/third-party-licenses.sh auszufuehren.
func TestThirdPartyCoversDirectDependencies(t *testing.T) {
	data, err := os.ReadFile("../../go.mod")
	if err != nil {
		t.Fatalf("go.mod nicht lesbar: %v", err)
	}
	for _, mod := range directModules(string(data)) {
		if !strings.Contains(ThirdParty(), "# "+mod+" ") {
			t.Errorf("Lizenz fuer %s fehlt – scripts/third-party-licenses.sh ausfuehren", mod)
		}
	}
}

// TestNoMissingLicenseMarker stellt sicher, dass das Skript fuer kein Modul
// "keine Lizenzdatei gefunden" eingetragen hat.
func TestNoMissingLicenseMarker(t *testing.T) {
	if strings.Contains(ThirdParty(), "Keine Lizenzdatei im Modul gefunden") {
		t.Error("mindestens ein Modul ohne Lizenzdatei – bitte manuell pruefen")
	}
}

// TestNoticeNamesLicenseAndSource prueft die Pflichtangaben im Kurzhinweis.
func TestNoticeNamesLicenseAndSource(t *testing.T) {
	n := Notice()
	for _, want := range []string{SPDX, SourceURL, "LICENSE"} {
		if !strings.Contains(n, want) {
			t.Errorf("Hinweis enthaelt %q nicht", want)
		}
	}
}

// directModules liest aus go.mod alle Modulpfade, die nicht als
// "// indirect" markiert sind (einzeilige und Block-Schreibweise).
func directModules(gomod string) []string {
	var mods []string
	inBlock := false
	for _, line := range strings.Split(gomod, "\n") {
		line = strings.TrimSpace(line)
		switch {
		case line == "require (":
			inBlock = true
			continue
		case inBlock && line == ")":
			inBlock = false
			continue
		case strings.HasPrefix(line, "require "):
			line = strings.TrimPrefix(line, "require ")
		case !inBlock:
			continue
		}
		if line == "" || strings.Contains(line, "// indirect") {
			continue
		}
		mods = append(mods, strings.Fields(line)[0])
	}
	return mods
}
