package scan

import "testing"

// TestIsRouterEcho: Proxy-ARP-Scheineintraege des Routers werden erkannt, echte Geraete nicht.
func TestIsRouterEcho(t *testing.T) {
	const gw, gwMAC = "10.0.0.1", "02:00:00:00:00:01" // Beispieldaten
	cases := []struct {
		name       string
		ip, mac    string
		ports      int
		gateway    string
		gatewayMAC string
		want       bool
	}{
		{"Proxy-ARP-Eintrag: Router-MAC, keine Ports", "10.0.0.103", "02:00:00:00:00:01", 0, gw, gwMAC, true},
		{"Router selbst", gw, gwMAC, 0, gw, gwMAC, false},
		{"Router-MAC, aber offener Port", "10.0.0.101", gwMAC, 1, gw, gwMAC, false},
		{"eigene MAC", "10.0.0.10", "02:00:00:00:00:99", 0, gw, gwMAC, false},
		{"Gateway unbekannt", "10.0.0.103", gwMAC, 0, "", gwMAC, false},
		{"Gateway-MAC unbekannt", "10.0.0.103", gwMAC, 0, gw, "", false},
		{"keine MAC", "10.0.0.103", "", 0, gw, gwMAC, false},
	}
	for _, c := range cases {
		if got := isRouterEcho(c.ip, c.mac, c.ports, c.gateway, c.gatewayMAC); got != c.want {
			t.Errorf("%s: %v, erwartet %v", c.name, got, c.want)
		}
	}
}
