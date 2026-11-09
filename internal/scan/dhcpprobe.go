package scan

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"net"
	"sort"
	"strings"
	"time"
)

// Mehrere DHCP-Server erkennen (I-070).
//
// Vorgehen: Es wird EIN DHCPDISCOVER per Broadcast gesendet; alle DHCP-Server im selben
// Broadcast-Bereich antworten mit einem DHCPOFFER. Antworten mehrere verschiedene Server,
// kann das ein zweiter (ggf. fremder, "Rogue") DHCP-Server sein - oder ein gewollter
// Redundanz-Server. Der Scanner bewertet das nur als HINWEIS.
//
// Eigenschaften / Annahmen:
//   - Es wird nur gelesen: Wir senden niemals ein DHCPREQUEST, nehmen also nie eine Adresse an.
//     Server halten ihr Angebot aber kurz vor (Annahme, je nach Server unterschiedlich).
//   - Als Absender-MAC dient eine zufaellige, lokal verwaltete MAC, damit kein echtes Geraet
//     "gestoert" wird.
//   - Braucht UDP-Port 68. Unter Linux/macOS meist nur mit Root-Rechten bzw. wenn der Port
//     frei ist (laeuft schon ein DHCP-Client, ist er belegt). FALLBACK: Ist der Port nicht
//     nutzbar, meldet die Pruefung "nicht pruefbar" mit Grund - sie rät nichts.
//   - Der Broadcast geht ueber die Schnittstelle, die das Betriebssystem waehlt; weitere
//     Netze/VLANs werden nicht geprueft.

// DHCPOffer beschreibt das Angebot eines DHCP-Servers.
type DHCPOffer struct {
	ServerID  string   `json:"server_id"`            // Server-Kennung (Option 54), meist dessen IP
	SourceIP  string   `json:"source_ip,omitempty"`  // Absender-IP des Pakets
	OfferedIP string   `json:"offered_ip,omitempty"` // angebotene Adresse (yiaddr)
	Mask      string   `json:"mask,omitempty"`       // Netzmaske (Option 1)
	Router    string   `json:"router,omitempty"`     // Gateway (Option 3)
	DNS       []string `json:"dns,omitempty"`        // DNS-Server (Option 6)
	Domain    string   `json:"domain,omitempty"`     // Domaenenname (Option 15)
	LeaseSecs uint32   `json:"lease_secs,omitempty"` // Leasedauer in Sekunden (Option 51)
}

// DHCPProbeResult ist das Ergebnis der Pruefung.
type DHCPProbeResult struct {
	Checked bool        `json:"checked"`        // false = nicht pruefbar (siehe Note)
	Servers []DHCPOffer `json:"servers"`        // je ein Eintrag pro Server-Kennung
	Multi   bool        `json:"multi"`          // true = mehr als ein Server hat geantwortet
	Note    string      `json:"note,omitempty"` // Erklaerung / Grund bei "nicht pruefbar"
}

// DHCP-Konstanten (RFC 2131/2132).
const (
	dhcpServerPort = 67
	dhcpClientPort = 68
	dhcpHeaderLen  = 236
	dhcpDiscover   = 1
	dhcpOffer      = 2
)

// ProbeDHCP sendet ein DHCPDISCOVER und sammelt Angebote bis zum Ablauf von wait.
func ProbeDHCP(ctx context.Context, wait time.Duration) DHCPProbeResult {
	conn, err := net.ListenPacket("udp4", fmt.Sprintf(":%d", dhcpClientPort))
	if err != nil {
		// Fallback: ohne Port 68 keine Pruefung (Rechte fehlen oder Port belegt).
		return DHCPProbeResult{Note: "Nicht prüfbar: UDP-Port 68 ist nicht nutzbar (" + err.Error() +
			"). Meist fehlen Administrator-/Root-Rechte, oder ein DHCP-Client belegt den Port."}
	}
	defer conn.Close()

	xid, mac := make([]byte, 4), make([]byte, 6)
	_, _ = rand.Read(xid)
	_, _ = rand.Read(mac)
	mac[0] = (mac[0] | 0x02) &^ 0x01 // lokal verwaltet, Unicast

	pkt := buildDiscover(xid, mac)
	dst := &net.UDPAddr{IP: net.IPv4bcast, Port: dhcpServerPort}
	if _, err := conn.WriteTo(pkt, dst); err != nil {
		return DHCPProbeResult{Note: "Nicht prüfbar: Broadcast konnte nicht gesendet werden (" + err.Error() + ")."}
	}

	byServer := map[string]DHCPOffer{}
	deadline := time.Now().Add(wait)
	buf := make([]byte, 1500)
	for time.Now().Before(deadline) && ctx.Err() == nil {
		_ = conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
		n, from, err := conn.ReadFrom(buf)
		if err != nil {
			continue // Zeitueberschreitung: weiter bis zur Gesamtfrist
		}
		offer, ok := parseOffer(buf[:n], xid)
		if !ok {
			continue
		}
		if ua, isUDP := from.(*net.UDPAddr); isUDP {
			offer.SourceIP = ua.IP.String()
		}
		if offer.ServerID == "" {
			offer.ServerID = offer.SourceIP // Server ohne Option 54: Absender nehmen
		}
		byServer[offer.ServerID] = offer
	}
	return buildProbeResult(byServer)
}

// buildProbeResult sortiert die Server und setzt Multi/Note.
func buildProbeResult(byServer map[string]DHCPOffer) DHCPProbeResult {
	res := DHCPProbeResult{Checked: true, Servers: []DHCPOffer{}}
	for _, o := range byServer {
		res.Servers = append(res.Servers, o)
	}
	sort.Slice(res.Servers, func(i, j int) bool { return res.Servers[i].ServerID < res.Servers[j].ServerID })
	res.Multi = len(res.Servers) > 1
	switch {
	case len(res.Servers) == 0:
		res.Note = "Kein DHCP-Server hat geantwortet (Netz ohne DHCP, Server filtert, oder anderes Netzsegment)."
	case res.Multi:
		res.Note = "Mehrere DHCP-Server haben geantwortet. Prüfen, ob alle gewollt sind (Redundanz) – sonst könnte ein fremder Server im Netz sein."
	default:
		res.Note = "Genau ein DHCP-Server hat geantwortet."
	}
	return res
}

// buildDiscover baut ein DHCPDISCOVER-Paket mit Broadcast-Flag (Antworten kommen per Broadcast).
func buildDiscover(xid, mac []byte) []byte {
	p := make([]byte, dhcpHeaderLen)
	p[0], p[1], p[2] = 1, 1, 6 // op=BOOTREQUEST, htype=Ethernet, hlen=6
	copy(p[4:8], xid)
	binary.BigEndian.PutUint16(p[10:12], 0x8000) // flags: Broadcast
	copy(p[28:34], mac)                          // chaddr
	p = append(p, 99, 130, 83, 99)               // Magic Cookie
	p = append(p, 53, 1, dhcpDiscover)           // Option 53: Nachrichtentyp
	p = append(p, 55, 6, 1, 3, 6, 15, 51, 54)    // Option 55: gewuenschte Parameter
	p = append(p, 255)                           // Ende
	return p
}

// parseOffer liest ein DHCPOFFER. ok=false bei fremder xid, falschem Typ oder kaputten Daten.
func parseOffer(b, xid []byte) (DHCPOffer, bool) {
	var o DHCPOffer
	if len(b) < dhcpHeaderLen+4 || b[0] != 2 || string(b[4:8]) != string(xid) {
		return o, false
	}
	if b[236] != 99 || b[237] != 130 || b[238] != 83 || b[239] != 99 {
		return o, false
	}
	if yi := net.IP(b[16:20]); !yi.IsUnspecified() {
		o.OfferedIP = yi.String()
	}
	isOffer := false
	opts := b[240:]
	for i := 0; i < len(opts); {
		code := opts[i]
		if code == 255 {
			break
		}
		if code == 0 { // Pad
			i++
			continue
		}
		if i+1 >= len(opts) {
			break
		}
		l := int(opts[i+1])
		if i+2+l > len(opts) {
			break // abgeschnitten
		}
		v := opts[i+2 : i+2+l]
		switch code {
		case 53:
			isOffer = l == 1 && v[0] == dhcpOffer
		case 54:
			if l == 4 {
				o.ServerID = net.IP(v).String()
			}
		case 1:
			if l == 4 {
				o.Mask = net.IP(v).String()
			}
		case 3:
			if l >= 4 {
				o.Router = net.IP(v[:4]).String()
			}
		case 6:
			for j := 0; j+4 <= l; j += 4 {
				o.DNS = append(o.DNS, net.IP(v[j:j+4]).String())
			}
		case 15:
			o.Domain = cleanText(string(v))
		case 51:
			if l == 4 {
				o.LeaseSecs = binary.BigEndian.Uint32(v)
			}
		}
		i += 2 + l
	}
	return o, isOffer
}

// cleanText entfernt Steuerzeichen aus Texten, die aus dem Netz stammen.
func cleanText(s string) string {
	return strings.Map(func(r rune) rune {
		if r < 32 || r == 127 {
			return -1
		}
		return r
	}, strings.TrimRight(s, "\x00"))
}
