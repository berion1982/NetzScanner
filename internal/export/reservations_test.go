package export

import (
	"bytes"
	"strings"
	"testing"
	"time"
)

func TestReservationsExport(t *testing.T) {
	rows := []Reservation{{Scope: "10.0.0.0", IP: "10.0.0.5", MAC: "AA-BB-CC-00-11-22", Name: "=cmd|' /C calc'!A0", ScanName: "Drucker | Büro"}}
	var csvOut bytes.Buffer
	if err := WriteReservationsCSV(&csvOut, rows, true); err != nil {
		t.Fatal(err)
	}
	c := csvOut.String()
	if !strings.HasPrefix(c, "\xEF\xBB\xBF") || !strings.Contains(c, "Netz;IP;MAC;Name (DHCP)") {
		t.Errorf("Excel-CSV: %q", c)
	}
	if strings.Contains(c, ";=cmd") || strings.Contains(c, ";\"=cmd") { // Formel-Schutz
		t.Errorf("Formel nicht entschaerft: %q", c)
	}
	var std bytes.Buffer
	_ = WriteReservationsCSV(&std, rows, false)
	if strings.HasPrefix(std.String(), "\xEF") || !strings.HasPrefix(std.String(), "Netz,IP,MAC") {
		t.Errorf("Standard-CSV: %q", std.String())
	}
	var md bytes.Buffer
	_ = WriteReservationsMarkdown(&md, rows, Meta{Generated: time.Now(), Version: "x"})
	if !strings.Contains(md.String(), "Anzahl: 1") || strings.Contains(md.String(), "Büro |") && !strings.Contains(md.String(), `\|`) {
		t.Errorf("Markdown: %q", md.String())
	}
}
