package main

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/berion1982/netzscanner/internal/export"
)

// Die Dateiendung bestimmt das Format; alles Unbekannte wird CSV.
func TestFormatFromName(t *testing.T) {
	cases := map[string]string{"a.csv": "csv", "a.MD": "md", "a.html": "html", "a.pdf": "pdf", "": "csv", "-": "csv", "a.xyz": "csv"}
	for in, want := range cases {
		if got := formatFromName(in); got != want {
			t.Errorf("formatFromName(%q)=%q, erwartet %q", in, got, want)
		}
	}
}

// Fehlerfaelle muessen sofort und ohne Scan gemeldet werden.
func TestRunCLIScanFehler(t *testing.T) {
	var out, log bytes.Buffer
	ctx := context.Background()
	// Oeffentliche Adresse ohne --allow-public wird abgelehnt.
	if err := runCLIScan(ctx, cliOptions{Target: "8.8.8.8"}, &out, &log); err == nil {
		t.Error("oeffentliche Adresse haette abgelehnt werden muessen")
	}
	// Ungueltige Portliste.
	if err := runCLIScan(ctx, cliOptions{Target: "127.0.0.1", Ports: "abc"}, &out, &log); err == nil {
		t.Error("ungueltige Ports haetten abgelehnt werden muessen")
	}
	// PDF nach stdout geht nicht.
	if err := runCLIScan(ctx, cliOptions{Target: "127.0.0.1", Format: "pdf"}, &out, &log); err == nil || !strings.Contains(err.Error(), "PDF") {
		t.Errorf("PDF nach stdout haette abgelehnt werden muessen, err=%v", err)
	}
	if err := renderHosts(&out, "xyz", nil, exportMetaForTest()); err == nil {
		t.Error("unbekanntes Format haette abgelehnt werden muessen")
	}
}

func exportMetaForTest() export.Meta { return export.Meta{Target: "test"} }
