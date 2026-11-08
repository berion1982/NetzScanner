package scan

import (
	"context"
	"encoding/binary"
	"net"
	"strconv"
	"strings"
	"time"
)

// Namensquellen ueber UDP (I-002). Beide brauchen KEINE Sonderrechte:
//   - mDNS  (UDP 5353): Apple-Geraete, Drucker, Chromecast, viele IoT-Geraete
//   - NetBIOS (UDP 137): Windows-PCs, Samba-NAS
// Es wird je Geraet genau eine Abfrage direkt an dessen IP geschickt (Unicast).
// Antwortet das Geraet nicht, ist das normal (viele haben den Dienst aus).

const (
	mdnsPort    = 5353
	netbiosPort = 137
	udpTimeout  = 1200 * time.Millisecond
)

// --------------------------------------------------------------------------
// DNS-Hilfen (gemeinsam fuer mDNS)
// --------------------------------------------------------------------------

// dnsQueryPTR baut eine DNS-Anfrage "PTR <name>" (ohne Antwortteil).
func dnsQueryPTR(name string) []byte {
	msg := make([]byte, 12, 64)
	binary.BigEndian.PutUint16(msg[4:], 1) // QDCOUNT = 1
	for _, label := range strings.Split(strings.TrimSuffix(name, "."), ".") {
		msg = append(msg, byte(len(label)))
		msg = append(msg, label...)
	}
	msg = append(msg, 0, 0, 12, 0, 1) // Ende des Namens, Typ PTR (12), Klasse IN (1)
	return msg
}

// skipName ueberspringt einen Namen (Labels oder Kompressionszeiger) und
// liefert die Position dahinter; -1 bei defekten Daten.
func skipName(msg []byte, off int) int {
	for off < len(msg) {
		l := int(msg[off])
		switch {
		case l == 0:
			return off + 1
		case l&0xC0 == 0xC0: // Zeiger: 2 Bytes, danach endet der Name
			if off+2 > len(msg) {
				return -1
			}
			return off + 2
		default:
			off += 1 + l
		}
	}
	return -1
}

// readName liest einen Namen und folgt Kompressionszeigern (max. 10 Spruenge,
// Schutz vor Endlosschleifen durch manipulierte Antworten).
func readName(msg []byte, off int) (string, bool) {
	var parts []string
	for jumps := 0; off < len(msg); {
		l := int(msg[off])
		switch {
		case l == 0:
			return strings.Join(parts, "."), true
		case l&0xC0 == 0xC0:
			if off+2 > len(msg) || jumps >= 10 {
				return "", false
			}
			off = int(binary.BigEndian.Uint16(msg[off:]) & 0x3FFF)
			jumps++
		default:
			if off+1+l > len(msg) {
				return "", false
			}
			parts = append(parts, string(msg[off+1:off+1+l]))
			off += 1 + l
		}
	}
	return "", false
}

// parsePTRAnswer liefert den Zielnamen des ersten PTR-Eintrags der Antwort.
func parsePTRAnswer(msg []byte) string {
	if len(msg) < 12 {
		return ""
	}
	qd, an := int(binary.BigEndian.Uint16(msg[4:])), int(binary.BigEndian.Uint16(msg[6:]))
	off := 12
	for i := 0; i < qd; i++ { // Fragen ueberspringen (Name + Typ + Klasse)
		if off = skipName(msg, off); off < 0 {
			return ""
		}
		off += 4
	}
	for i := 0; i < an; i++ {
		if off = skipName(msg, off); off < 0 || off+10 > len(msg) {
			return ""
		}
		typ, rdlen := binary.BigEndian.Uint16(msg[off:]), int(binary.BigEndian.Uint16(msg[off+8:]))
		off += 10
		if off+rdlen > len(msg) {
			return ""
		}
		if typ == 12 { // PTR
			if name, ok := readName(msg, off); ok {
				return name
			}
		}
		off += rdlen
	}
	return ""
}

// udpExchange schickt ein Paket an ip:port und liest eine Antwort.
func udpExchange(ctx context.Context, ip string, port int, req []byte) ([]byte, error) {
	var d net.Dialer
	conn, err := d.DialContext(ctx, "udp", net.JoinHostPort(ip, strconv.Itoa(port)))
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(udpTimeout))
	if _, err := conn.Write(req); err != nil {
		return nil, err
	}
	buf := make([]byte, 1500)
	n, err := conn.Read(buf)
	if err != nil {
		return nil, err
	}
	return buf[:n], nil
}

// --------------------------------------------------------------------------
// mDNS
// --------------------------------------------------------------------------

// mdnsName fragt das Geraet per mDNS nach dem Namen seiner IP (Reverse-PTR).
// Kommt als Antwort z.B. "iphone-von-anna.local", wird ".local" entfernt.
func mdnsName(ctx context.Context, ip string, port int) string {
	a := net.ParseIP(ip).To4()
	if a == nil {
		return "" // nur IPv4
	}
	rev := strconv.Itoa(int(a[3])) + "." + strconv.Itoa(int(a[2])) + "." +
		strconv.Itoa(int(a[1])) + "." + strconv.Itoa(int(a[0])) + ".in-addr.arpa"
	resp, err := udpExchange(ctx, ip, port, dnsQueryPTR(rev))
	if err != nil {
		return ""
	}
	name := parsePTRAnswer(resp)
	name = strings.TrimSuffix(strings.TrimSuffix(name, "."), ".local")
	return cleanHostName(name)
}

// --------------------------------------------------------------------------
// NetBIOS
// --------------------------------------------------------------------------

// nbstatQuery baut die NetBIOS-Anfrage "Node Status" fuer den Platzhalter-Namen "*".
func nbstatQuery() []byte {
	msg := make([]byte, 12, 50)
	binary.BigEndian.PutUint16(msg[0:], 0x4E42) // beliebige Transaktions-ID
	binary.BigEndian.PutUint16(msg[4:], 1)      // 1 Frage
	msg = append(msg, 0x20)                     // Namenslaenge: 32 Zeichen
	name := append([]byte{'*'}, make([]byte, 15)...)
	for _, b := range name { // "First Level Encoding": jedes Byte -> 2 Buchstaben A..P
		msg = append(msg, 'A'+b>>4, 'A'+b&0x0F)
	}
	return append(msg, 0, 0, 0x21, 0, 1) // Ende, Typ NBSTAT (0x21), Klasse IN
}

// parseNBSTAT liest aus der Antwort den Rechnernamen: erster eindeutiger
// (nicht Gruppen-)Eintrag mit Suffix 0x00 ("Workstation").
func parseNBSTAT(msg []byte) string {
	if len(msg) < 12 || binary.BigEndian.Uint16(msg[6:]) == 0 {
		return ""
	}
	off := skipName(msg, 12)
	if off < 0 || off+11 > len(msg) {
		return ""
	}
	off += 10 // Typ, Klasse, TTL, Datenlaenge
	count := int(msg[off])
	off++
	for i := 0; i < count && off+18 <= len(msg); i, off = i+1, off+18 {
		suffix, flags := msg[off+15], binary.BigEndian.Uint16(msg[off+16:])
		if suffix == 0x00 && flags&0x8000 == 0 { // Bit 15 = Gruppenname
			return cleanHostName(strings.TrimSpace(string(msg[off : off+15])))
		}
	}
	return ""
}

// netbiosName fragt Windows-/Samba-Geraete nach ihrem NetBIOS-Rechnernamen.
func netbiosName(ctx context.Context, ip string, port int) string {
	resp, err := udpExchange(ctx, ip, port, nbstatQuery())
	if err != nil {
		return ""
	}
	return parseNBSTAT(resp)
}
