package web

// Mesh-Zuordnung (I-055 c): Aus dem Mesh-Dokument der FRITZ!Box (siehe internal/router/mesh.go)
// wird für jedes gescannte Gerät der vorgelagerte Knoten (Uplink) bestimmt, z. B. "Handy hängt am
// Repeater, der Repeater an der Box". Reine Logik ohne Netzwerk, damit sie testbar ist.

import (
	"fmt"

	"github.com/berion1982/netzscanner/internal/model"
	"github.com/berion1982/netzscanner/internal/router"
	"github.com/berion1982/netzscanner/internal/scan"
)

// meshLink ist das Ergebnis für ein Gerät (wird bei jeder Ansicht aus den aktuellen Geräten berechnet).
type meshLink struct {
	Uplink string // IP des vorgelagerten, gescannten Geräts
	Label  string // z. B. "WLAN · 195 Mbit/s · -61 dBm"
}

// maxMeshDepth begrenzt das Hochwandern in der Kette (Schutz vor Schleifen im Dokument).
const maxMeshDepth = 10

// buildMeshLinks ordnet Mesh-Knoten den gescannten Geräten zu (über MAC, sonst IP) und liefert
// je Geräte-IP den nächsten gescannten Vorgänger. Nicht gescannte Zwischenknoten werden übersprungen.
func buildMeshLinks(m router.Mesh, hosts []model.Host) map[string]meshLink {
	byMAC, byMgmt, byIP := map[string]string{}, map[string]string{}, map[string]string{} // -> Knoten-UID
	for _, n := range m.Nodes {
		for _, mac := range n.MACs {
			if k := scan.NormMAC(mac); k != "" {
				byMAC[k] = n.UID
			}
		}
		for _, ip := range n.MgmtIPs {
			byMgmt[ip] = n.UID
		}
		for _, ip := range n.IPs {
			byIP[ip] = n.UID
		}
	}
	// Zuordnung in drei Stufen, damit ein Gerät mit alter/fremder IP im Mesh-Dokument keinem Repeater den
	// Platz wegnimmt (z. B. ein iPhone, dessen frühere Adresse bei einem Repeater als Nachbar steht):
	// 1) MAC, 2) eigene (MANAGEMENT-)IP des Knotens, 3) beliebige IP - jeder Knoten wird nur einmal vergeben.
	hostOfUID, uidOfIP := map[string]model.Host{}, map[string]string{} // Knoten -> Gerät; Geräte-IP -> Knoten
	claim := func(h model.Host, uid string) {
		if uid == "" || uidOfIP[h.IP] != "" {
			return
		}
		if _, taken := hostOfUID[uid]; !taken {
			hostOfUID[uid], uidOfIP[h.IP] = h, uid
		}
	}
	for _, h := range hosts {
		if k := scan.NormMAC(h.MAC); k != "" {
			claim(h, byMAC[k])
		}
	}
	for _, h := range hosts {
		claim(h, byMgmt[h.IP])
	}
	for _, h := range hosts {
		claim(h, byIP[h.IP])
	}
	uidOf := func(h model.Host) string { return uidOfIP[h.IP] }
	parent := map[string]router.MeshLink{} // Kind-UID -> erste Verbindung nach oben
	for _, l := range m.Links {
		if _, ok := parent[l.Child]; !ok {
			parent[l.Child] = l
		}
	}
	out := map[string]meshLink{}
	for _, h := range hosts {
		uid := uidOf(h)
		first, ok := parent[uid]
		if uid == "" || !ok {
			continue
		}
		// Nach oben wandern, bis ein gescanntes Gerät gefunden ist.
		cur := first
		for depth := 0; depth < maxMeshDepth; depth++ {
			if up, found := hostOfUID[cur.Parent]; found && up.IP != h.IP {
				out[h.IP] = meshLink{Uplink: up.IP, Label: meshLabel(first)}
				break
			}
			next, more := parent[cur.Parent]
			if !more {
				break
			}
			cur = next
		}
	}
	return out
}

// meshLabel beschreibt die Verbindung des Geräts zu seinem direkten Vorgänger.
func meshLabel(l router.MeshLink) string {
	s := l.Type
	if s == "" {
		s = "Verbindung"
	}
	if l.RateMbit > 0 {
		s += fmt.Sprintf(" · %d Mbit/s", l.RateMbit)
	}
	if l.RCPI != 0 {
		s += fmt.Sprintf(" · %d dBm", l.RCPI)
	}
	return s
}
