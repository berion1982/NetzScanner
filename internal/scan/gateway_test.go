package scan

import (
	"reflect"
	"testing"

	"github.com/berion1982/netzscanner/internal/model"
)

// TestMarkSharedMAC: Geraete mit gleicher MAC (auch bei anderer Schreibweise) verweisen aufeinander,
// Geraete mit eigener oder ohne MAC bleiben unberuehrt. Beispieldaten.
func TestMarkSharedMAC(t *testing.T) {
	hosts := []model.Host{
		{IP: "10.0.0.1", MAC: "02:00:00:00:00:01"},
		{IP: "10.0.0.5", MAC: "02-00-00-00-00-01"},
		{IP: "10.0.0.6", MAC: "02:00:00:00:00:01"},
		{IP: "10.0.0.7", MAC: "02:00:00:00:00:99"},
		{IP: "10.0.0.8"},
		{IP: "10.0.0.9"},
	}
	MarkSharedMAC(hosts)
	if want := []string{"10.0.0.5", "10.0.0.6"}; !reflect.DeepEqual(hosts[0].SameMAC, want) {
		t.Errorf("10.0.0.1: %v, erwartet %v", hosts[0].SameMAC, want)
	}
	if want := []string{"10.0.0.1", "10.0.0.6"}; !reflect.DeepEqual(hosts[1].SameMAC, want) {
		t.Errorf("10.0.0.5: %v, erwartet %v", hosts[1].SameMAC, want)
	}
	for _, i := range []int{3, 4, 5} {
		if hosts[i].SameMAC != nil {
			t.Errorf("%s darf keinen Hinweis haben: %v", hosts[i].IP, hosts[i].SameMAC)
		}
	}
}

// TestMirrorOfRouterMAC: Ein Eintrag mit der MAC eines Routers/Switches wird als Spiegel markiert und
// zaehlt trotz Router-Hersteller nicht als Netzwerkgeraet; der Router selbst bleibt Netzwerkgeraet.
func TestMirrorOfRouterMAC(t *testing.T) {
	hosts := []model.Host{
		{IP: "10.0.0.1", MAC: "02:00:00:00:00:01", Vendor: "AVM", Role: "router"},
		{IP: "10.0.0.5", MAC: "02:00:00:00:00:01", Vendor: "AVM"},
		{IP: "10.0.0.6", MAC: "02:00:00:00:00:02", Vendor: "AVM"},
	}
	MarkSharedMAC(hosts)
	if hosts[0].MirrorOf != "" || hosts[2].MirrorOf != "" {
		t.Errorf("Router/eigene MAC duerfen kein MirrorOf haben: %q %q", hosts[0].MirrorOf, hosts[2].MirrorOf)
	}
	if hosts[1].MirrorOf != "10.0.0.1" {
		t.Fatalf("MirrorOf = %q, erwartet 10.0.0.1", hosts[1].MirrorOf)
	}
	if got := Categorize(hosts[1]); got == model.CatNetwork {
		t.Errorf("Spiegeleintrag darf kein Netzwerkgeraet sein, ist %q", got)
	}
	if got := Categorize(hosts[0]); got != model.CatNetwork {
		t.Errorf("Router muss Netzwerkgeraet bleiben, ist %q", got)
	}
}
