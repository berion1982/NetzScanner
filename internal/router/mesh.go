package router

// Mesh-Topologie der FRITZ!Box (I-055 c, Teil 2).
//
// Quelle: das Dokument hinter der TR-064-Aktion X_AVM-DE_GetMeshListPath (JSON). Aufbau, so wie
// er an Saschas Box (FRITZ!OS mit Repeater 600) gesehen wurde - ANDERE Modelle/Versionen kann ich
// nicht prüfen ("Ich weiß es nicht"):
//
//	{ "nodes": [ { "uid": "n-397", "device_name": "...", "device_mac_address": "...",
//	               "ip_addresses": [ {"value": "192.168.178.72/24"} ],
//	               "node_interfaces": [ { "mac_address": "...", "type": "LAN"|"WLAN",
//	                   "node_links": [ { "uid": "nl-377", "state": "CONNECTED",
//	                       "node_1_uid": "n-1", "node_2_uid": "n-397",
//	                       "cur_data_rate_rx": 164000, "cur_data_rate_tx": 195000, "rx_rcpi": -61 } ] } ] } ] }
//
// ANNAHME (aus den Beispieldaten abgeleitet, nicht dokumentiert): node_1 ist der vorgelagerte
// Knoten (Richtung Box), node_2 der nachgelagerte. Datenraten stehen in kbit/s.
// Jede Verbindung kann in beiden beteiligten Knoten auftauchen -> nach "uid" entdoppeln.

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"strings"
)

// MeshNode ist ein Geraet im Mesh-Dokument (Box, Repeater, aber auch normale Clients).
type MeshNode struct {
	UID   string   `json:"uid"`
	Name  string   `json:"name"`
	Model string   `json:"model,omitempty"`
	Role  string   `json:"role,omitempty"` // "master", "slave" oder "unknown" (kein Mesh-Mitglied)
	MACs  []string `json:"-"`              // Geraete-MAC und alle Schnittstellen-MACs
	IPs   []string `json:"-"`              // IP-Adressen ohne "/24"
}

// MeshLink ist eine Verbindung: Parent (naeher an der Box) -> Child.
type MeshLink struct {
	Parent, Child string // Knoten-UIDs
	Type          string // "LAN" oder "WLAN"
	RateMbit      int    // aktuelle Datenrate (groesserer Wert aus rx/tx) in Mbit/s, 0 = unbekannt
	RCPI          int    // Signal in dBm (nur WLAN, 0 = unbekannt)
}

// Mesh ist das ausgewertete Dokument.
type Mesh struct {
	Nodes []MeshNode
	Links []MeshLink
}

// Rohformat (nur die gebrauchten Felder; unbekannte werden ignoriert).
type rawMesh struct {
	Nodes []struct {
		UID        string                   `json:"uid"`
		Name       string                   `json:"device_name"`
		Friendly   string                   `json:"device_friendly_name"`
		Model      string                   `json:"device_model"`
		MAC        string                   `json:"device_mac_address"`
		Role       string                   `json:"mesh_role"`
		IPs        []struct{ Value string } `json:"ip_addresses"`
		Interfaces []struct {
			MAC   string `json:"mac_address"`
			Links []struct {
				UID    string `json:"uid"`
				Type   string `json:"type"`
				State  string `json:"state"`
				Node1  string `json:"node_1_uid"`
				Node2  string `json:"node_2_uid"`
				RateRx int    `json:"cur_data_rate_rx"`
				RateTx int    `json:"cur_data_rate_tx"`
				RCPI   int    `json:"rx_rcpi"`
			} `json:"node_links"`
		} `json:"node_interfaces"`
	} `json:"nodes"`
}

// ParseMesh wertet das Mesh-Dokument aus. Nur CONNECTED-Verbindungen werden uebernommen.
func ParseMesh(data []byte) (Mesh, error) {
	var raw rawMesh
	if err := json.Unmarshal(data, &raw); err != nil {
		return Mesh{}, errors.New("Mesh-Dokument ist kein lesbares JSON")
	}
	if len(raw.Nodes) == 0 {
		return Mesh{}, errors.New("Mesh-Dokument enthält keine Geräte")
	}
	var m Mesh
	seen := map[string]bool{}
	for _, n := range raw.Nodes {
		name := n.Name
		if n.Friendly != "" {
			name = n.Friendly
		}
		node := MeshNode{UID: n.UID, Name: clean(name, maxNameRunes), Model: clean(n.Model, maxNameRunes), Role: clean(n.Role, 16)}
		if n.MAC != "" {
			node.MACs = append(node.MACs, n.MAC)
		}
		for _, ip := range n.IPs {
			// "192.168.178.72/24" -> "192.168.178.72"; Link-Local (169.254.x.x) ist nutzlos.
			if a := strings.SplitN(ip.Value, "/", 2)[0]; net.ParseIP(a) != nil && !strings.HasPrefix(a, "169.254.") {
				node.IPs = append(node.IPs, a)
			}
		}
		for _, ni := range n.Interfaces {
			if ni.MAC != "" {
				node.MACs = append(node.MACs, ni.MAC)
			}
			for _, l := range ni.Links {
				if l.UID == "" || seen[l.UID] || !strings.EqualFold(l.State, "CONNECTED") || l.Node1 == "" || l.Node2 == "" {
					continue
				}
				seen[l.UID] = true
				ml := MeshLink{Parent: l.Node1, Child: l.Node2, Type: strings.ToUpper(clean(l.Type, 8)), RateMbit: max(l.RateRx, l.RateTx) / 1000}
				if l.RCPI < 0 && l.RCPI > -120 { // 255 = "unbekannt" bei AVM; sinnvoll nur echte dBm-Werte
					ml.RCPI = l.RCPI
				}
				m.Links = append(m.Links, ml)
			}
		}
		m.Nodes = append(m.Nodes, node)
	}
	return m, nil
}

// readMesh holt und wertet das Mesh-Dokument der Box aus (Fehler -> Hinweis, kein Abbruch).
func (c *client) readMesh(ctx context.Context) (Mesh, error) {
	r, err := c.call(ctx, svcHosts, "X_AVM-DE_GetMeshListPath", "")
	if err != nil {
		return Mesh{}, err
	}
	path := meshRequestURI(r["NewX_AVM-DE_MeshListPath"])
	if path == "" {
		return Mesh{}, errors.New("Box liefert keinen Mesh-Pfad")
	}
	body, status, err := c.getPath(ctx, path)
	if err != nil {
		return Mesh{}, err
	}
	if status != 200 {
		return Mesh{}, errors.New("Mesh-Dokument nicht abrufbar")
	}
	return ParseMesh(body)
}
