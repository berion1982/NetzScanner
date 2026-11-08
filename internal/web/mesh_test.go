package web

import (
	"testing"

	"github.com/berion1982/netzscanner/internal/model"
	"github.com/berion1982/netzscanner/internal/router"
)

// Beispiel nach Saschas Box: Box (n-1) -> Repeater (n-397) -> Handy (n-304); WLED direkt an der Box;
// PC über einen nicht gescannten Switch (n-128) an der Box.
const meshJSON = `{"nodes":[
{"uid":"n-1","device_name":"fritz.box","device_mac_address":"AA:00:00:00:00:01","ip_addresses":[{"value":"192.168.178.1/24"}],"node_interfaces":[]},
{"uid":"n-397","device_name":"fritz.repeater","device_mac_address":"D4:24:DD:7A:86:3C","ip_addresses":[{"value":"169.254.1.1/16"},{"value":"192.168.178.72/24"}],
 "node_interfaces":[{"mac_address":"F6:24:DD:7A:86:3E","node_links":[{"uid":"nl-377","type":"WLAN","state":"CONNECTED","node_1_uid":"n-1","node_2_uid":"n-397","cur_data_rate_rx":164000,"cur_data_rate_tx":195000,"rx_rcpi":-61}]}]},
{"uid":"n-304","device_name":"handy","device_mac_address":"AA:00:00:00:03:04","ip_addresses":[],
 "node_interfaces":[{"mac_address":"AA:00:00:00:03:04","node_links":[{"uid":"nl-442","type":"WLAN","state":"CONNECTED","node_1_uid":"n-397","node_2_uid":"n-304","cur_data_rate_rx":142900,"cur_data_rate_tx":142000,"rx_rcpi":-60},
 {"uid":"nl-442","type":"WLAN","state":"CONNECTED","node_1_uid":"n-397","node_2_uid":"n-304"}]}]},
{"uid":"n-128","device_name":"switch","device_mac_address":"AA:00:00:00:01:28","ip_addresses":[],"node_interfaces":[{"mac_address":"AA:00:00:00:01:28","node_links":[{"uid":"nl-1","type":"LAN","state":"CONNECTED","node_1_uid":"n-1","node_2_uid":"n-128","cur_data_rate_rx":1000000}]}]},
{"uid":"n-239","device_name":"pc","device_mac_address":"AA:00:00:00:02:39","ip_addresses":[],"node_interfaces":[{"mac_address":"AA:00:00:00:02:39","node_links":[{"uid":"nl-241","type":"LAN","state":"CONNECTED","node_1_uid":"n-128","node_2_uid":"n-239","cur_data_rate_rx":100000}]}]},
{"uid":"n-9","device_name":"getrennt","device_mac_address":"AA:00:00:00:00:09","node_interfaces":[{"mac_address":"AA:00:00:00:00:09","node_links":[{"uid":"nl-9","type":"WLAN","state":"DISCONNECTED","node_1_uid":"n-1","node_2_uid":"n-9"}]}]}
]}`

func TestBuildMeshLinks(t *testing.T) {
	m, err := router.ParseMesh([]byte(meshJSON))
	if err != nil {
		t.Fatal(err)
	}
	if len(m.Links) != 4 { // nl-442 doppelt -> einmal; nl-9 getrennt -> keine
		t.Fatalf("Verbindungen: %d, erwartet 4", len(m.Links))
	}
	hosts := []model.Host{
		{IP: "192.168.178.1", MAC: "AA:00:00:00:00:01"},
		{IP: "192.168.178.72", MAC: "D4:24:DD:7A:86:3C"},
		{IP: "192.168.178.50", MAC: "AA:00:00:00:03:04"},
		{IP: "192.168.178.75", MAC: "AA:00:00:00:02:39"},
	}
	got := buildMeshLinks(m, hosts)
	if l := got["192.168.178.72"]; l.Uplink != "192.168.178.1" || l.Label != "WLAN · 195 Mbit/s · -61 dBm" {
		t.Errorf("Repeater: %+v", l)
	}
	if l := got["192.168.178.50"]; l.Uplink != "192.168.178.72" {
		t.Errorf("Handy sollte am Repeater hängen: %+v", l)
	}
	if l := got["192.168.178.75"]; l.Uplink != "192.168.178.1" { // Switch nicht gescannt -> übersprungen
		t.Errorf("PC: %+v", l)
	}
	if _, ok := got["192.168.178.1"]; ok {
		t.Error("Box darf keinen Uplink bekommen")
	}
}
