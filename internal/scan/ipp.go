package scan

// ipp.go – Drucker-Details per IPP (I-062).
//
// Drucker mit Port 631 sprechen das Internet Printing Protocol (RFC 8010/8011). Die Operation
// "Get-Printer-Attributes" ist lesend und braucht in der Regel keine Anmeldung. Wir senden genau
// EINE solche Anfrage (HTTP-POST, Inhaltstyp application/ipp) und werten die Antwort mit einem
// kleinen, defensiven Binaerleser aus. Es wird nichts am Drucker veraendert.
//
// Welche Attribute ein Drucker liefert, ist modellabhaengig: Fehlende Angaben werden einfach
// weggelassen; antwortet das Geraet nicht oder mit Fehler, bleibt das Ergebnis leer.

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// ippAttrs sind die angefragten Attribute (Namen laut IPP-Standard, kein Geraetewissen).
var ippAttrs = []string{
	"printer-make-and-model", "printer-firmware-string-version", "printer-uuid",
	"printer-state", "printer-state-reasons", "marker-names", "marker-levels",
}

// ippStates ordnet den Wert von "printer-state" (RFC 8011) einem Text zu.
var ippStates = map[int]string{3: "bereit", 4: "druckt", 5: "angehalten"}

// ippPaths sind die ueblichen Pfade; der erste Treffer zaehlt.
var ippPaths = []string{"/ipp/print", "/"}

// QueryIPP fragt Drucker-Details bei ip:631 ab und liefert eine kurze Beschreibung,
// z. B. "IPP: Modell X · Firmware 1.2 · Status bereit · Füllstände: Black 80 %".
// Leerer String = nicht abrufbar (kein IPP, verweigert oder keine nutzbaren Attribute).
func QueryIPP(ctx context.Context, ip string, timeout time.Duration) string {
	return queryIPPAt(ctx, "http://"+net.JoinHostPort(ip, "631"), ip, timeout)
}

// queryIPPAt macht die eigentliche Abfrage gegen eine Basis-URL (getrennt, damit Tests einen
// lokalen Server nutzen koennen).
func queryIPPAt(ctx context.Context, base, ip string, timeout time.Duration) string {
	// Keine Proxy-Nutzung: Die Anfrage geht direkt ins lokale Netz.
	client := &http.Client{Timeout: timeout, Transport: &http.Transport{Proxy: nil}}
	for _, path := range ippPaths {
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, base+path,
			bytes.NewReader(buildIPPRequest("ipp://"+net.JoinHostPort(ip, "631")+path)))
		if err != nil {
			return ""
		}
		req.Header.Set("Content-Type", "application/ipp")
		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		data, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024)) // Schutz vor endlosen Antworten
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			continue
		}
		if d := describeIPP(parseIPP(data)); d != "" {
			return d
		}
	}
	return ""
}

// ippString haengt eine IPP-Zeichenkette (Wert-Tag, Name, Wert) an die Anfrage an.
// Zusaetzliche Werte desselben Attributs haben laut Standard einen leeren Namen.
func ippString(b *bytes.Buffer, tag byte, name, value string) {
	b.WriteByte(tag)
	_ = binary.Write(b, binary.BigEndian, uint16(len(name)))
	b.WriteString(name)
	_ = binary.Write(b, binary.BigEndian, uint16(len(value)))
	b.WriteString(value)
}

// buildIPPRequest baut die Nachricht "Get-Printer-Attributes" (Version 2.0, Request-ID 1).
func buildIPPRequest(printerURI string) []byte {
	var b bytes.Buffer
	b.Write([]byte{0x02, 0x00, 0x00, 0x0B, 0x00, 0x00, 0x00, 0x01}) // Version, Operation, Request-ID
	b.WriteByte(0x01)                                               // Gruppe: operation-attributes
	ippString(&b, 0x47, "attributes-charset", "utf-8")
	ippString(&b, 0x48, "attributes-natural-language", "en")
	ippString(&b, 0x45, "printer-uri", printerURI)
	for i, a := range ippAttrs {
		name := ""
		if i == 0 {
			name = "requested-attributes"
		}
		ippString(&b, 0x44, name, a)
	}
	b.WriteByte(0x03) // Ende der Attribute
	return b.Bytes()
}

// ippValue ist ein gelesener Wert eines Attributs (Text oder Zahl).
type ippValue struct {
	tag  byte
	text string
	num  int
}

// parseIPP liest die Attribute aus einer IPP-Antwort. Liefert nil bei Fehlerstatus oder
// kaputten Daten (nie Panik, nie Ueberlauf). Verschachtelte Werte (Collections) werden uebersprungen.
func parseIPP(data []byte) map[string][]ippValue {
	if len(data) < 9 || binary.BigEndian.Uint16(data[2:4]) >= 0x0100 {
		return nil // zu kurz oder Status ist ein Fehler (>= 0x0100)
	}
	attrs := map[string][]ippValue{}
	pos, last, depth := 8, "", 0
	for pos < len(data) {
		tag := data[pos]
		pos++
		if tag == 0x03 {
			break // Ende
		}
		if tag <= 0x05 {
			continue // Gruppenbeginn (operation, job, printer ...)
		}
		if pos+2 > len(data) {
			return attrs
		}
		nl := int(binary.BigEndian.Uint16(data[pos:]))
		pos += 2
		if pos+nl+2 > len(data) {
			return attrs
		}
		name := string(data[pos : pos+nl])
		pos += nl
		vl := int(binary.BigEndian.Uint16(data[pos:]))
		pos += 2
		if pos+vl > len(data) {
			return attrs
		}
		val := data[pos : pos+vl]
		pos += vl
		switch tag {
		case 0x34: // Collection beginnt
			depth++
			continue
		case 0x37: // Collection endet
			if depth > 0 {
				depth--
			}
			continue
		}
		if depth > 0 || tag == 0x4A {
			continue
		}
		if name != "" {
			last = name
		}
		v := ippValue{tag: tag}
		if (tag == 0x21 || tag == 0x23) && vl == 4 { // Ganzzahl bzw. Aufzaehlung
			v.num = int(int32(binary.BigEndian.Uint32(val)))
		} else {
			v.text = cleanIPPText(string(val))
		}
		attrs[last] = append(attrs[last], v)
	}
	return attrs
}

// cleanIPPText entfernt Steuerzeichen und kuerzt, weil der Text aus dem Netz stammt.
func cleanIPPText(s string) string {
	s = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, s)
	s = strings.TrimSpace(s)
	if r := []rune(s); len(r) > 100 {
		s = string(r[:100])
	}
	return s
}

// describeIPP macht aus den Attributen eine kurze Zeile. Leer, wenn nichts Nutzbares dabei ist.
func describeIPP(a map[string][]ippValue) string {
	var parts []string
	first := func(name string) string {
		if v := a[name]; len(v) > 0 {
			return v[0].text
		}
		return ""
	}
	if m := first("printer-make-and-model"); m != "" {
		parts = append(parts, m)
	}
	if f := first("printer-firmware-string-version"); f != "" {
		parts = append(parts, "Firmware "+f)
	}
	if u := strings.TrimPrefix(first("printer-uuid"), "urn:uuid:"); u != "" {
		parts = append(parts, "UUID "+u)
	}
	if v := a["printer-state"]; len(v) > 0 {
		if s, ok := ippStates[v[0].num]; ok {
			parts = append(parts, "Status "+s)
		}
	}
	if r := ippReasons(a["printer-state-reasons"]); r != "" {
		parts = append(parts, "Meldungen "+r)
	}
	if l := ippMarkers(a["marker-names"], a["marker-levels"]); l != "" {
		parts = append(parts, "Füllstände "+l)
	}
	if len(parts) == 0 {
		return ""
	}
	return "IPP: " + strings.Join(parts, " · ")
}

// ippReasons nennt die Status-Meldungen ohne den Platzhalter "none".
func ippReasons(v []ippValue) string {
	var out []string
	for _, x := range v {
		if x.text != "" && x.text != "none" {
			out = append(out, x.text)
		}
	}
	return strings.Join(out, ", ")
}

// ippMarkers verbindet Verbrauchsmaterial-Namen mit Fuellstaenden in Prozent. Negative Werte
// (-1 = unbekannt, -2 = nicht ermittelbar, -3 = genug vorhanden) werden nicht als Zahl gezeigt.
func ippMarkers(names, levels []ippValue) string {
	var out []string
	for i, n := range names {
		if i >= len(levels) || n.text == "" {
			continue
		}
		if lv := levels[i].num; lv >= 0 && lv <= 100 {
			out = append(out, n.text+" "+strconv.Itoa(lv)+" %")
		} else {
			out = append(out, fmt.Sprintf("%s ?", n.text))
		}
	}
	return strings.Join(out, ", ")
}
