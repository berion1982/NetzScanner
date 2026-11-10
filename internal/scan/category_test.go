package scan

import (
	"strings"
	"testing"

	"github.com/berion1982/netzscanner/internal/model"
)

// TestCategorize prueft typische Geraete gegen die erwartete Kategorie.
func TestCategorize(t *testing.T) {
	ports := func(n ...int) []model.Port {
		var ps []model.Port
		for _, x := range n {
			ps = append(ps, model.Port{Number: x})
		}
		return ps
	}
	tests := []struct {
		name string
		h    model.Host
		want string
	}{
		{"Router per Rolle", model.Host{Role: "router"}, model.CatNetwork},
		{"Switch per Hersteller", model.Host{Vendor: "Netgear"}, model.CatNetwork},
		{"MikroTik per System", model.Host{OS: "MikroTik RouterOS (SSH-Banner)"}, model.CatNetwork},
		{"Hue Bridge", model.Host{Vendor: "Signify B.V.", Ports: ports(80, 443)}, model.CatIoT},
		{"Drucker per Port", model.Host{Ports: ports(80, 631, 9100)}, model.CatPrinter},
		{"Drucker per Hersteller", model.Host{Vendor: "Seiko Epson Corp", Ports: ports(80)}, model.CatPrinter},
		{"Drucker per IPP-Banner", model.Host{Ports: []model.Port{{Number: 8631, Banner: "IPP: Modell X"}}}, model.CatPrinter},
		{"Kamera bleibt IoT", model.Host{Ports: ports(554)}, model.CatIoT},
		{"NAS per Hersteller", model.Host{Vendor: "Synology Incorporated", Ports: ports(5000)}, model.CatServer},
		{"Datenbank", model.Host{Ports: ports(5432)}, model.CatServer},
		{"Linux mit SSH", model.Host{OS: "Ubuntu 22.04 (SSH-Banner)", Ports: ports(22)}, model.CatServer},
		{"Windows-Server (IIS)", model.Host{OS: "Windows (IIS 10.0)", Ports: ports(80)}, model.CatServer},
		{"Windows-PC", model.Host{OS: "Windows (RDP/RPC/WinRM offen, Vermutung)", Ports: ports(135, 445)}, model.CatClient},
		{"iPhone per OS", model.Host{OS: "iOS/iPadOS (Apple, Vermutung)", Ports: ports(62078)}, model.CatMobile},
		{"Android per OS", model.Host{OS: "Android (Vermutung)"}, model.CatMobile},
		{"WLAN + Privacy-MAC ohne Ports", model.Host{MAC: "DA:11:22:33:44:55", Connection: "WLAN"}, model.CatMobile},
		{"Privacy-MAC per Kabel", model.Host{MAC: "DA:11:22:33:44:55", Connection: "LAN (Kabel)"}, model.CatClient},
		{"WLAN mit Hersteller-MAC", model.Host{MAC: "D8:11:22:33:44:55", Connection: "WLAN"}, model.CatClient},
		{"Unbekannt ohne Ports", model.Host{}, model.CatClient},
	}
	for _, tc := range tests {
		if got := Categorize(tc.h); got != tc.want {
			t.Errorf("%s: %q, erwartet %q", tc.name, got, tc.want)
		}
	}
}

// Home Assistant (Port 8123) wird als Linux-basiert erkannt; Windows-Banner haben Vorrang.
func TestGuessOSHomeAssistant(t *testing.T) {
	ha := model.Host{Ports: []model.Port{{Number: 8123}, {Number: 22222, Banner: "SSH-2.0-OpenSSH_9.6"}}}
	if got := GuessOS(ha); !strings.Contains(got, "Home Assistant") {
		t.Errorf("HA: %q", got)
	}
	win := model.Host{Ports: []model.Port{{Number: 8123}, {Number: 80, Banner: "Microsoft-IIS/10.0"}}}
	if got := GuessOS(win); !strings.Contains(got, "Windows") {
		t.Errorf("Windows-Vorrang: %q", got)
	}
}

// Home Assistant gilt als Server, auch bei IoT-nahem Hersteller.
func TestCategorizeHomeAssistant(t *testing.T) {
	h := model.Host{Vendor: "Philips Lighting", Ports: []model.Port{{Number: 8123}}}
	if got := Categorize(h); got != model.CatServer {
		t.Errorf("HA: %q", got)
	}
}
