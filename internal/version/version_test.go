package version

import (
	"os"
	"strings"
	"testing"
)

// TestString prueft, dass Versionsnummer, Builddatum und Commit in der
// Ausgabe auftauchen - das verlangt die Anforderung "Versionshistorie
// inkl. Versionsnummer und Builddatum".
func TestString(t *testing.T) {
	Version, BuildDate, Commit = "1.2.3", "2026-01-01T00:00:00Z", "abc1234"
	got := String()
	for _, want := range []string{"1.2.3", "2026-01-01T00:00:00Z", "abc1234"} {
		if !strings.Contains(got, want) {
			t.Errorf("String() = %q, enthaelt %q nicht", got, want)
		}
	}
}

// TestEmbeddedMatchesRootFile stellt sicher, dass die eingebettete Kopie
// (internal/version/VERSION) und die Datei VERSION im Repo-Root gleich sind.
// Schlaegt der Test fehl, wurde nur eine der beiden Dateien angehoben.
func TestEmbeddedMatchesRootFile(t *testing.T) {
	root, err := os.ReadFile("../../VERSION")
	if err != nil {
		t.Fatalf("VERSION im Repo-Root nicht lesbar: %v", err)
	}
	if strings.TrimSpace(string(root)) != strings.TrimSpace(embeddedVersion) {
		t.Errorf("VERSION (%q) und internal/version/VERSION (%q) weichen ab", root, embeddedVersion)
	}
}
