package version

import (
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
