package scan

import "testing"

// TestIsRouterEcho: VPN-/Proxy-ARP-Scheineintraege des Routers werden erkannt, echte Geraete nicht.
func TestIsRouterEcho(t *testing.T) {
	const gw, gwMAC = "192.168.178.1", "0C:72:74:D7:85:C4"
	cases := []struct {
		name       string
		ip, mac    string
		ports      int
		gateway    string
		gatewayMAC string
		want       bool
	}{
		{"VPN-Client: Router-MAC, keine Ports", "192.168.178.103", "0c:72:74:d7:85:c4", 0, gw, gwMAC, true},
		{"Router selbst", gw, gwMAC, 0, gw, gwMAC, false},
		{"Router-MAC, aber offener Port", "192.168.178.101", gwMAC, 1, gw, gwMAC, false},
		{"eigene MAC", "192.168.178.10", "68:1D:EF:46:43:56", 0, gw, gwMAC, false},
		{"Gateway unbekannt", "192.168.178.103", gwMAC, 0, "", gwMAC, false},
		{"Gateway-MAC unbekannt", "192.168.178.103", gwMAC, 0, gw, "", false},
		{"keine MAC", "192.168.178.103", "", 0, gw, gwMAC, false},
	}
	for _, c := range cases {
		if got := isRouterEcho(c.ip, c.mac, c.ports, c.gateway, c.gatewayMAC); got != c.want {
			t.Errorf("%s: %v, erwartet %v", c.name, got, c.want)
		}
	}
}
