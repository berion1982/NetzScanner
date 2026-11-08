// Package version haelt Versionsnummer und Builddatum des NetzScanners.
//
// Die Werte werden beim Build per -ldflags eingesetzt (siehe scripts/build.sh).
// Ohne ldflags (z.B. "go run") gelten die Standardwerte "dev" / "unbekannt".
package version

import (
	_ "embed" // fuer //go:embed
	"fmt"
	"strings"
)

// embeddedVersion ist die eingebettete Kopie der Versionsnummer. Sie sorgt dafuer,
// dass auch "go run" / "go build" ohne ldflags die richtige Nummer zeigen.
// Sie MUSS immer identisch mit der Datei VERSION im Repo-Wurzelverzeichnis sein
// (prueft TestEmbeddedMatchesRootFile); beide gemeinsam anheben.
//
//go:embed VERSION
var embeddedVersion string

func init() {
	// Nur wenn der Linker nichts gesetzt hat, gilt die eingebettete Nummer.
	if Version == "dev" {
		if v := strings.TrimSpace(embeddedVersion); v != "" {
			Version = v
		}
	}
}

// Diese Variablen werden vom Linker ueberschrieben. Sie muessen deshalb
// "var" (nicht "const") und vom Typ string sein.
var (
	// Version ist die SemVer-Nummer, z.B. "0.1.0" (Quelle: Datei VERSION).
	Version = "dev"
	// BuildDate ist der Build-Zeitpunkt in UTC, Format RFC 3339.
	BuildDate = "unbekannt"
	// Commit ist der kurze Git-Hash des Builds.
	Commit = "unbekannt"
)

// String liefert die menschenlesbare Versionszeile fuer --version und die Hilfe-Seite.
func String() string {
	return fmt.Sprintf("NetzScanner %s (Build %s, Commit %s)", Version, BuildDate, Commit)
}
