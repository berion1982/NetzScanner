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

// TestMeshStaleIPDoesNotStealNode: Ein iPhone, dessen alte IP bei einem Repeater als Nachbar steht,
// darf dem Repeater (eigene MANAGEMENT-IP, andere MAC) den Knoten nicht wegnehmen.
func TestMeshStaleIPDoesNotStealNode(t *testing.T) {
	doc := `{"nodes":[
{"uid":"n-1","device_name":"box","device_mac_address":"AA:00:00:00:00:01","ip_addresses":[{"value":"192.168.178.1/24","attributes":["MANAGEMENT"]}]},
{"uid":"n-7","device_name":"rep","device_mac_address":"BB:00:00:00:00:07","ip_addresses":[{"value":"192.168.178.112/24","attributes":["NEIGHBOUR_LIST"]},{"value":"192.168.178.123/24","attributes":["MANAGEMENT"]}],
 "node_interfaces":[{"mac_address":"BB:00:00:00:00:08","node_links":[{"uid":"nl-1","type":"WLAN","state":"CONNECTED","node_1_uid":"n-1","node_2_uid":"n-7"}]}]},
{"uid":"n-8","device_name":"plug","device_mac_address":"CC:00:00:00:00:08","node_interfaces":[{"mac_address":"CC:00:00:00:00:08","node_links":[{"uid":"nl-2","type":"WLAN","state":"CONNECTED","node_1_uid":"n-7","node_2_uid":"n-8"}]}]}]}`
	m, err := router.ParseMesh([]byte(doc))
	if err != nil {
		t.Fatal(err)
	}
	hosts := []model.Host{
		{IP: "192.168.178.1", MAC: "AA:00:00:00:00:01"},
		{IP: "192.168.178.112", MAC: "EA:00:00:00:00:12"}, // iPhone mit anderer MAC
		{IP: "192.168.178.123", MAC: "86:00:00:00:00:99"}, // Repeater mit zufälliger MAC
		{IP: "192.168.178.122", MAC: "CC:00:00:00:00:08"},
	}
	got := buildMeshLinks(m, hosts)
	if l := got["192.168.178.122"]; l.Uplink != "192.168.178.123" {
		t.Errorf("Stecker sollte am Repeater .123 hängen, nicht am iPhone: %+v", l)
	}
	if _, ok := got["192.168.178.112"]; ok {
		t.Error("iPhone hat keinen Knoten und darf keinen Uplink bekommen")
	}
}
