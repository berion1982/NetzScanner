package export

import (
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
