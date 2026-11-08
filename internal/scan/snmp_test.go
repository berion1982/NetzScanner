package scan

import (
	"testing"

	"github.com/berion1982/netzscanner/internal/model"
)

// Aufbau: Router R -- Switch A -- Switch B; PC1 an A, PC2 und PC3 an B.
// A kennt hinter "p-B" alles von B; B kennt hinter "up" alles oberhalb.
func TestBuildLinksChain(t *testing.T) {
	hosts := []model.Host{
		{IP: "10.0.0.1", MAC: "AA:00:00:00:00:01"},  // Router
		{IP: "10.0.0.2", MAC: "AA:00:00:00:00:0A"},  // Switch A
		{IP: "10.0.0.3", MAC: "AA:00:00:00:00:0B"},  // Switch B
		{IP: "10.0.0.11", MAC: "AA:00:00:00:00:11"}, // PC1 an A
		{IP: "10.0.0.12", MAC: "AA:00:00:00:00:12"}, // PC2 an B
		{IP: "10.0.0.13", MAC: "AA:00:00:00:00:13"}, // PC3 an B
	}
	e := func(mac, port string) FDBEntry { return FDBEntry{MAC: NormMAC(mac), Port: port} }
	a := SwitchData{IP: "10.0.0.2", FDB: []FDBEntry{
		e("AA:00:00:00:00:01", "up"), // Router oberhalb
		e("AA:00:00:00:00:11", "p1"),
		e("AA:00:00:00:00:0B", "pB"), e("AA:00:00:00:00:12", "pB"), e("AA:00:00:00:00:13", "pB"),
	}}
	b := SwitchData{IP: "10.0.0.3", FDB: []FDBEntry{
		e("AA:00:00:00:00:01", "up"), e("AA:00:00:00:00:0A", "up"), e("AA:00:00:00:00:11", "up"),
		e("AA:00:00:00:00:12", "p2"), e("AA:00:00:00:00:13", "p3"),
	}}
	links := BuildLinks(hosts, []SwitchData{a, b}, "AA:00:00:00:00:01")

	want := map[string][2]string{
		"10.0.0.11": {"10.0.0.2", "p1"}, // PC1 an A, Port p1
		"10.0.0.12": {"10.0.0.3", "p2"}, // PC2 an B (nicht am Port pB von A)
		"10.0.0.13": {"10.0.0.3", "p3"},
		"10.0.0.3":  {"10.0.0.2", "pB"}, // Switch B haengt an A, Port pB
	}
	for ip, w := range want {
		if l, ok := links[ip]; !ok || l.Uplink != w[0] || l.Port != w[1] {
			t.Errorf("%s: %+v, erwartet %v", ip, links[ip], w)
		}
	}
	if _, ok := links["10.0.0.1"]; ok {
		t.Error("Router darf keinen Uplink bekommen")
	}
	if _, ok := links["10.0.0.2"]; ok {
		t.Error("Wurzel-Switch A steht in keiner Tabelle -> kein Eintrag (Gateway bleibt Uplink)")
	}
	if l := links["10.0.0.3"]; l.Shared != 3 {
		t.Errorf("Port pB hat 3 MACs, bekam %d", l.Shared)
	}
}

// Ohne Router-MAC gilt der Port mit den meisten MACs als Uplink.
func TestBuildLinksNoRouterMAC(t *testing.T) {
	hosts := []model.Host{{IP: "10.0.0.20", MAC: "aa:aa:aa:aa:aa:20"}}
	sw := SwitchData{IP: "10.0.0.2", FDB: []FDBEntry{
		{MAC: "aaaaaaaaaa20", Port: "p1"},
		{MAC: "bbbbbbbbbb01", Port: "up"}, {MAC: "bbbbbbbbbb02", Port: "up"}, {MAC: "bbbbbbbbbb03", Port: "up"},
	}}
	if l := BuildLinks(hosts, []SwitchData{sw}, ""); l["10.0.0.20"].Port != "p1" {
		t.Errorf("Zugangsport erwartet: %+v", l)
	}
}

// Widerspruechliche Tabellen duerfen keinen Kreis in den Uplinks ergeben.
func TestBreakCycles(t *testing.T) {
	links := map[string]Link{"a": {Uplink: "b"}, "b": {Uplink: "a"}, "c": {Uplink: "a"}}
	breakCycles(links)
	for ip := range links {
		cur := ip
		for i := 0; i < 5; i++ {
			l, ok := links[cur]
			if !ok {
				break
			}
			cur = l.Uplink
			if cur == ip {
				t.Fatalf("Kreis bei %s uebrig: %v", ip, links)
			}
		}
	}
}

func TestNormMACAndOID(t *testing.T) {
	if NormMAC("AA-BB-cc:00.11:22") != "aabbcc001122" || NormMAC("xyz") != "" || NormMAC("aa:bb") != "" {
		t.Error("NormMAC")
	}
	if m := macFromOID(".1.3.6.1.2.1.17.7.1.2.2.1.2.1.0.17.34.51.68.85", oidDot1qFdbPort); m != "001122334455" {
		t.Errorf("Q-BRIDGE-OID: %q", m)
	}
	if m := macFromOID("1.3.6.1.2.1.17.4.3.1.2.0.17.34.51.68.85", oidDot1dFdbPort); m != "001122334455" {
		t.Errorf("BRIDGE-OID: %q", m)
	}
	if macFromOID("1.3.6.1.2.1.17.4.3.1.2.0.17", oidDot1dFdbPort) != "" || macFromOID("1.2.3", oidDot1dFdbPort) != "" {
		t.Error("kaputte OID muss leer ergeben")
	}
}

// LLDP (I-051): Router R -- Switch A -- Switch B; B ist bei A als Nachbar auf Port "pB" sichtbar,
// der AP hinter B nur per LLDP von B (seine MAC taucht in keiner MAC-Tabelle auf).
func TestBuildLinksLLDP(t *testing.T) {
	hosts := []model.Host{
		{IP: "10.0.0.1", MAC: "AA:00:00:00:00:01"},  // Router
		{IP: "10.0.0.2", MAC: "AA:00:00:00:00:0A"},  // Switch A
		{IP: "10.0.0.3", MAC: "AA:00:00:00:00:0B"},  // Switch B
		{IP: "10.0.0.20", MAC: "AA:00:00:00:00:20"}, // Access Point an B
	}
	a := SwitchData{IP: "10.0.0.2", LLDP: []LLDPNeighbor{
		{LocalPort: "up", MAC: NormMAC("AA:00:00:00:00:01")},
		{LocalPort: "pB", MAC: NormMAC("AA:00:00:00:00:0B")},
	}}
	b := SwitchData{IP: "10.0.0.3", LLDP: []LLDPNeighbor{
		{LocalPort: "up", MAC: NormMAC("AA:00:00:00:00:0A")},
		{LocalPort: "p5", IP: "10.0.0.20"}, // Zuordnung ueber Management-IP
	}}
	links := BuildLinks(hosts, []SwitchData{a, b}, "AA:00:00:00:00:01")
	want := map[string][2]string{"10.0.0.3": {"10.0.0.2", "pB"}, "10.0.0.20": {"10.0.0.3", "p5"}}
	for ip, w := range want {
		if l := links[ip]; l.Uplink != w[0] || l.Port != w[1] {
			t.Errorf("%s: %+v, erwartet %v", ip, l, w)
		}
	}
	if _, ok := links["10.0.0.2"]; ok {
		t.Error("Switch A haengt am Router (Uplink-Port), nicht unter B")
	}
}

func TestParseChassisID(t *testing.T) {
	if m, _ := parseChassisID([]byte{0xaa, 0, 0, 0, 0, 0x0b}, 4); m != "aa000000000b" {
		t.Errorf("MAC: %q", m)
	}
	if _, ip := parseChassisID([]byte{1, 10, 0, 0, 20}, 5); ip != "10.0.0.20" {
		t.Errorf("IP: %q", ip)
	}
	if m, ip := parseChassisID([]byte{1, 2}, 4); m != "" || ip != "" {
		t.Error("Unsinn muss leer bleiben")
	}
}
