package export

import (
	"bytes"
	"github.com/berion1982/netzscanner/internal/findings"
	"strings"
	"testing"

	"github.com/berion1982/netzscanner/internal/model"
)

// TestTopologyNote: Der Hinweis unter der Karte richtet sich nach der Datenquelle der Verbindungen.
func TestTopologyNote(t *testing.T) {
	plain := []model.Host{{IP: "10.0.0.1"}}
	mesh := []model.Host{{IP: "10.0.0.2", MeshLink: "WLAN"}}
	snmp := []model.Host{{IP: "10.0.0.3", UplinkPort: "Gi1/0/5"}}
	for name, c := range map[string]struct {
		hosts []model.Host
		want  string
	}{
		"ohne":  {plain, "Sternansicht (Router oben"},
		"mesh":  {mesh, "Mesh-Liste der FRITZ!Box (Box/Repeater)"},
		"snmp":  {snmp, "laut SNMP (MAC-Tabellen"},
		"beide": {append(mesh, snmp...), "Mesh-Liste der FRITZ!Box und SNMP"},
	} {
		if got := topologyNote(c.hosts); !strings.Contains(got, c.want) {
			t.Errorf("%s: %q enthaelt nicht %q", name, got, c.want)
		}
	}
}

// TestNetworkDocPDF: Die Netzdokumentation entsteht mit und ohne Befunde als gueltige PDF-Datei;
// uebergrosse Deckblatt-Angaben werden gekuerzt, Steuerzeichen entfernt.
func TestNetworkDocPDF(t *testing.T) {
	hosts := []model.Host{{IP: "10.0.0.1", Name: "router"}, {IP: "10.0.0.2", Name: "pc"}}
	meta := Meta{Target: "10.0.0.0/24", Version: "NetzScanner test"}
	list := []findings.Finding{{Severity: findings.High, IP: "10.0.0.2", Name: "pc", Port: 23, Title: "Telnet offen", Detail: "Hinweis"}}
	for name, l := range map[string][]findings.Finding{"mit Befunden": list, "ohne Befunde": nil} {
		var buf bytes.Buffer
		if err := WriteNetworkDocPDF(&buf, hosts, l, DocInfo{Customer: "Kunde Ä"}, meta); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if !strings.HasPrefix(buf.String(), "%PDF-") {
			t.Errorf("%s: keine PDF-Datei", name)
		}
	}
	long := DocInfo{Customer: strings.Repeat("x", 500) + "\n"}.Clean()
	if len([]rune(long.Customer)) != docInfoMaxLen || strings.ContainsAny(long.Customer, "\n") {
		t.Errorf("Angabe nicht bereinigt: %d Zeichen", len([]rune(long.Customer)))
	}
}
