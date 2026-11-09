package findings

import (
	"testing"

	"github.com/berion1982/netzscanner/internal/model"
)

// ruleSet sammelt die Regel-Kennungen der Befunde eines Geraets.
func ruleSet(fs []Finding) map[string]Finding {
	m := map[string]Finding{}
	for _, f := range fs {
		m[f.Rule] = f
	}
	return m
}

func TestPortRules(t *testing.T) {
	h := model.Host{IP: "10.0.0.5", Name: "x", Ports: []model.Port{{Number: 23}, {Number: 3389}, {Number: 6379}, {Number: 22}}}
	got := ruleSet(Analyze([]model.Host{h}))
	for _, r := range []string{"telnet", "rdp", "cache-redis"} {
		if _, ok := got[r]; !ok {
			t.Errorf("Regel %s fehlt", r)
		}
	}
	if got["telnet"].Severity != High {
		t.Errorf("Telnet muss Hoch sein, ist %s", got["telnet"].Severity)
	}
	if _, ok := got["ssh"]; ok || len(got) != 3 {
		t.Errorf("SSH darf keinen Befund erzeugen: %v", got)
	}
}

func TestCertRules(t *testing.T) {
	h := model.Host{IP: "10.0.0.6", Ports: []model.Port{
		{Number: 443, Cert: &model.Cert{Expired: true, NotAfter: "2020-01-01", DaysLeft: -5}},
		{Number: 8443, Cert: &model.Cert{NotAfter: "2099-01-01", DaysLeft: 10}},
		{Number: 5001, Cert: &model.Cert{NotAfter: "2099-01-01", DaysLeft: 300}},
	}}
	got := ruleSet(Analyze([]model.Host{h}))
	if got["cert-expired"].Port != 443 || got["cert-expiring"].Port != 8443 {
		t.Errorf("Zertifikats-Befunde falsch: %v", got)
	}
	if len(got) != 2 {
		t.Errorf("gesundes Zertifikat darf nichts melden: %v", got)
	}
}

func TestHTTPOnlyAndSameMAC(t *testing.T) {
	only := model.Host{IP: "10.0.0.7", Ports: []model.Port{{Number: 80}}, SameMAC: []string{"10.0.0.8"}}
	both := model.Host{IP: "10.0.0.9", Ports: []model.Port{{Number: 80}, {Number: 443}}}
	got := Analyze([]model.Host{only, both})
	r := ruleSet(got)
	if r["http-only"].IP != "10.0.0.7" || r["same-mac"].IP != "10.0.0.7" {
		t.Errorf("Befunde falsch: %v", r)
	}
	for _, f := range got {
		if f.IP == "10.0.0.9" {
			t.Errorf("HTTP+HTTPS darf nichts melden: %v", f)
		}
	}
}

func TestSortOrder(t *testing.T) {
	hs := []model.Host{
		{IP: "10.0.0.10", Ports: []model.Port{{Number: 23}}},
		{IP: "10.0.0.9", Ports: []model.Port{{Number: 23}, {Number: 21}}},
	}
	got := Analyze(hs)
	if len(got) != 3 || got[0].IP != "10.0.0.9" || got[1].IP != "10.0.0.10" || got[2].Rule != "ftp" {
		t.Errorf("Sortierung falsch: %+v", got)
	}
}
