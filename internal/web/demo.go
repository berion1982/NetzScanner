package web

import "github.com/berion1982/netzscanner/internal/model"

// DemoHosts liefert erfundene Beispieldaten, solange der Scan-Kern fehlt (v0.2.x).
func DemoHosts() []model.Host {
	p := func(n int, s string) model.Port { return model.Port{Number: n, Service: s} }
	hosts := []model.Host{
		{IP: "192.168.1.1", Name: "fritz.box", MAC: "3C:A6:2F:11:22:33", Vendor: "AVM", OS: "FRITZ!OS", Role: "router", Known: true,
			Ports: []model.Port{p(53, "dns"), p(80, "http"), p(443, "https")}},
		{IP: "192.168.1.2", Name: "switch-01", MAC: "10:7B:44:00:01:02", Vendor: "Netgear", Role: "switch", Uplink: "192.168.1.1", Known: true,
			Ports: []model.Port{p(22, "ssh"), p(80, "http")}},
		{IP: "192.168.1.10", Name: "nas-01", MAC: "00:11:32:AA:BB:CC", Vendor: "Synology", OS: "DSM 7", Uplink: "192.168.1.2", Known: true,
			Ports: []model.Port{p(22, "ssh"), p(445, "smb"), p(5000, "http"), p(5001, "https")}},
		{IP: "192.168.1.23", Name: "drucker-eg", MAC: "00:1B:A9:44:55:66", Vendor: "Brother", Uplink: "192.168.1.2", Known: true,
			Ports: []model.Port{p(80, "http"), p(631, "ipp"), p(9100, "jetdirect")}},
		{IP: "192.168.1.77", Name: "(unbekannt)", MAC: "B8:27:EB:99:88:77", Vendor: "Raspberry Pi", OS: "Linux?", Uplink: "192.168.1.2", Known: false,
			Ports: []model.Port{p(22, "ssh"), p(23, "telnet")}},
	}
	for i := range hosts {
		hosts[i].FillWebLinks()
	}
	return hosts
}
