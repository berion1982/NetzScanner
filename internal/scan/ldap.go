package scan

// ldap.go – anonyme rootDSE-Abfrage per LDAP (I-061).
//
// Ein Active-Directory-Domaenencontroller (und viele andere LDAP-Server) verraten ueber den
// "rootDSE" (leerer Suchpfad, Umfang "base") ohne Anmeldung Domaenenname, Servername und
// Funktionsebene. Wir senden genau EINE lesende Suchanfrage (kein Bind, keine Zugangsdaten,
// nichts wird geschrieben) und werten die Antwort mit einem minimalen BER-Leser aus.
//
// Ob ein Server den anonymen Abruf erlaubt, ist serverabhaengig: Antwortet er nicht oder mit
// Fehler, bleibt das Ergebnis leer (stiller Fallback, der Port 389 wird trotzdem angezeigt).

import (
	"context"
	"io"
	"net"
	"strconv"
	"strings"
	"time"
)

// rootDSEAttrs sind die abgefragten Attribute (Namen laut LDAP/AD-Schema).
var rootDSEAttrs = []string{
	"defaultNamingContext", "dnsHostName", "domainFunctionality",
	"forestFunctionality", "namingContexts",
}

// domainLevels ordnet den AD-Wert "domainFunctionality" der Windows-Server-Version zu
// (von Microsoft dokumentierte Konstanten, keine Geraete-Einzelfaelle).
var domainLevels = map[string]string{
	"0": "2000", "1": "2003 (Interim)", "2": "2003", "3": "2008",
	"4": "2008 R2", "5": "2012", "6": "2012 R2", "7": "2016",
}

// QueryRootDSE verbindet sich anonym mit ip:389 und liefert eine kurze Beschreibung,
// z. B. "LDAP: Domäne corp.example.com · Server dc1.corp.example.com · Funktionsebene 2016".
// Leerer String = nicht abrufbar (Server verweigert, antwortet nicht oder kein LDAP).
func QueryRootDSE(ctx context.Context, ip string, timeout time.Duration) string {
	d := net.Dialer{Timeout: timeout}
	conn, err := d.DialContext(ctx, "tcp", net.JoinHostPort(ip, "389"))
	if err != nil {
		return ""
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))
	if _, err := conn.Write(buildRootDSERequest()); err != nil {
		return ""
	}
	// Antwort lesen: hoechstens 64 KB (Schutz vor endlosen/boesartigen Antworten).
	data, _ := io.ReadAll(io.LimitReader(conn, 64*1024))
	return describeRootDSE(parseRootDSE(data))
}

// ---------- BER erzeugen ----------

// berTLV baut ein Tag-Laenge-Wert-Element (Laenge in Kurz- oder Langform).
func berTLV(tag byte, value []byte) []byte {
	n := len(value)
	var hdr []byte
	switch {
	case n < 128:
		hdr = []byte{tag, byte(n)}
	case n < 256:
		hdr = []byte{tag, 0x81, byte(n)}
	default:
		hdr = []byte{tag, 0x82, byte(n >> 8), byte(n)}
	}
	return append(hdr, value...)
}

// buildRootDSERequest baut die LDAP-SearchRequest-Nachricht (Message-ID 1, Basis "", Umfang base,
// Filter "(objectClass=*)" als "present", gewuenschte Attribute aus rootDSEAttrs).
func buildRootDSERequest() []byte {
	var attrs []byte
	for _, a := range rootDSEAttrs {
		attrs = append(attrs, berTLV(0x04, []byte(a))...)
	}
	var req []byte
	req = append(req, berTLV(0x04, nil)...)                   // baseObject ""
	req = append(req, berTLV(0x0a, []byte{0})...)             // scope = baseObject
	req = append(req, berTLV(0x0a, []byte{0})...)             // derefAliases = nie
	req = append(req, berTLV(0x02, []byte{0})...)             // sizeLimit 0 (unbegrenzt)
	req = append(req, berTLV(0x02, []byte{0})...)             // timeLimit 0
	req = append(req, berTLV(0x01, []byte{0})...)             // typesOnly = false
	req = append(req, berTLV(0x87, []byte("objectClass"))...) // Filter: present(objectClass)
	req = append(req, berTLV(0x30, attrs)...)                 // Attributliste
	msg := append(berTLV(0x02, []byte{1}), berTLV(0x63, req)...)
	return berTLV(0x30, msg)
}

// ---------- BER lesen ----------

// berRead liest ein TLV am Anfang von b und liefert Tag, Inhalt und den Rest.
// ok=false bei unvollstaendigen oder unzulaessigen Daten (nie Panik, nie Ueberlauf).
func berRead(b []byte) (tag byte, val, rest []byte, ok bool) {
	if len(b) < 2 {
		return 0, nil, nil, false
	}
	tag = b[0]
	l, off := int(b[1]), 2
	if l >= 0x80 { // Langform: unteres 7 Bit = Anzahl der Laengenbytes
		nb := l & 0x7f
		if nb == 0 || nb > 3 || len(b) < 2+nb {
			return 0, nil, nil, false
		}
		l = 0
		for i := 0; i < nb; i++ {
			l = l<<8 | int(b[2+i])
		}
		off = 2 + nb
	}
	if l < 0 || off+l > len(b) {
		return 0, nil, nil, false
	}
	return tag, b[off : off+l], b[off+l:], true
}

// parseRootDSE sucht in der Antwort den SearchResultEntry (Tag 0x64) und liefert
// Attributname (klein geschrieben) -> erster Wert. Unbrauchbare Antwort = leere Map.
func parseRootDSE(data []byte) map[string]string {
	out := map[string]string{}
	for len(data) > 0 {
		tag, msg, rest, ok := berRead(data) // LDAPMessage (SEQUENCE)
		if !ok || tag != 0x30 {
			break
		}
		data = rest
		_, _, afterID, ok := berRead(msg) // messageID ueberspringen
		if !ok {
			continue
		}
		optag, entry, _, ok := berRead(afterID)
		if !ok || optag != 0x64 { // 0x64 = SearchResultEntry
			continue
		}
		_, _, attrList, ok := berRead(entry) // objectName ueberspringen
		if !ok {
			continue
		}
		readAttributes(attrList, out)
	}
	return out
}

// readAttributes liest "SEQUENCE OF PartialAttribute" und fuellt out.
func readAttributes(list []byte, out map[string]string) {
	_, seq, _, ok := berRead(list)
	if !ok {
		return
	}
	for len(seq) > 0 {
		_, attr, rest, ok := berRead(seq)
		if !ok {
			return
		}
		seq = rest
		_, name, afterName, ok := berRead(attr)
		if !ok {
			continue
		}
		_, vals, _, ok := berRead(afterName) // SET OF value
		if !ok {
			continue
		}
		_, first, _, ok := berRead(vals) // nur der erste Wert wird gebraucht
		if ok {
			out[strings.ToLower(string(name))] = string(first)
		}
	}
}

// ---------- Aufbereiten ----------

// domainFromDN macht aus "DC=corp,DC=example,DC=com" den DNS-Namen "corp.example.com".
// Enthaelt der Pfad keine DC-Teile (z. B. "o=firma"), ist das Ergebnis leer.
func domainFromDN(dn string) string {
	var parts []string
	for _, rdn := range strings.Split(dn, ",") {
		rdn = strings.TrimSpace(rdn)
		if len(rdn) > 3 && strings.EqualFold(rdn[:3], "dc=") {
			parts = append(parts, rdn[3:])
		}
	}
	return strings.Join(parts, ".")
}

// describeRootDSE formt die Attribute zu einer einzeiligen, bereinigten Beschreibung.
// Leere Map oder nichts Verwertbares -> "".
func describeRootDSE(attrs map[string]string) string {
	var parts []string
	if dom := domainFromDN(attrs["defaultnamingcontext"]); dom != "" {
		parts = append(parts, "Domäne "+dom)
	} else if nc := attrs["namingcontexts"]; nc != "" {
		parts = append(parts, "Basis "+nc) // Nicht-AD-LDAP: erster Namenskontext
	}
	if host := attrs["dnshostname"]; host != "" {
		parts = append(parts, "Server "+host)
	}
	if lvl, ok := domainLevels[attrs["domainfunctionality"]]; ok {
		parts = append(parts, "Funktionsebene "+lvl)
	} else if n, err := strconv.Atoi(attrs["domainfunctionality"]); err == nil {
		parts = append(parts, "Funktionsebene "+strconv.Itoa(n))
	}
	if len(parts) == 0 {
		return ""
	}
	return sanitizeUTF8("LDAP: " + strings.Join(parts, " · "))
}

// sanitizeUTF8 entfernt Steuerzeichen und kuerzt auf 160 Zeichen (Text stammt aus dem Netz).
// Anders als sanitize() bleiben Umlaute und "·" erhalten.
func sanitizeUTF8(s string) string {
	var b strings.Builder
	for _, r := range s {
		if r >= 32 && r != 127 {
			b.WriteRune(r)
		}
		if b.Len() >= 160 {
			break
		}
	}
	return b.String()
}
