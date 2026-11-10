package scan

import (
	"bytes"
	"context"
	"encoding/binary"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// ippAttr baut ein Attribut fuer eine Test-Antwort (name leer = weiterer Wert).
func ippAttr(b *bytes.Buffer, tag byte, name string, val []byte) {
	b.WriteByte(tag)
	_ = binary.Write(b, binary.BigEndian, uint16(len(name)))
	b.WriteString(name)
	_ = binary.Write(b, binary.BigEndian, uint16(len(val)))
	b.Write(val)
}

func ippInt(n int32) []byte {
	v := make([]byte, 4)
	binary.BigEndian.PutUint32(v, uint32(n))
	return v
}

// testIPPAntwort liefert eine erfundene, aber standardkonforme Antwort.
func testIPPAntwort() []byte {
	var b bytes.Buffer
	b.Write([]byte{0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01}) // Status ok
	b.WriteByte(0x04)                                               // Gruppe printer-attributes
	ippAttr(&b, 0x41, "printer-make-and-model", []byte("Beispiel Laser 100"))
	ippAttr(&b, 0x23, "printer-state", ippInt(3))
	ippAttr(&b, 0x44, "printer-state-reasons", []byte("none"))
	ippAttr(&b, 0x42, "marker-names", []byte("Schwarz"))
	ippAttr(&b, 0x42, "", []byte("Cyan"))
	ippAttr(&b, 0x21, "marker-levels", ippInt(80))
	ippAttr(&b, 0x21, "", ippInt(-1))
	b.WriteByte(0x03)
	return b.Bytes()
}

func TestIPPBeschreibung(t *testing.T) {
	got := describeIPP(parseIPP(testIPPAntwort()))
	for _, w := range []string{"IPP: Beispiel Laser 100", "Status bereit", "Schwarz 80 %", "Cyan ?"} {
		if !strings.Contains(got, w) {
			t.Errorf("%q fehlt in %q", w, got)
		}
	}
	if strings.Contains(got, "Meldungen") {
		t.Errorf("\"none\" darf nicht erscheinen: %q", got)
	}
}

func TestIPPKaputt(t *testing.T) {
	good := testIPPAntwort()
	// Jede Abschneidung und Fehlerstatus duerfen weder Panik noch Text ergeben, der nicht stimmt.
	for i := 0; i < len(good); i++ {
		_ = describeIPP(parseIPP(good[:i]))
	}
	bad := append([]byte{}, good...)
	bad[2], bad[3] = 0x04, 0x00 // Fehlerstatus
	if describeIPP(parseIPP(bad)) != "" {
		t.Error("Fehlerstatus muss leer bleiben")
	}
	if describeIPP(parseIPP(nil)) != "" {
		t.Error("nil muss leer bleiben")
	}
}

func TestIPPAnfrageUndServer(t *testing.T) {
	var gotBody []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Content-Type") != "application/ipp" {
			http.Error(w, "x", http.StatusBadRequest)
			return
		}
		gotBody = make([]byte, 4096)
		n, _ := r.Body.Read(gotBody)
		gotBody = gotBody[:n]
		w.Write(testIPPAntwort())
	}))
	defer srv.Close()
	got := queryIPPAt(context.Background(), srv.URL, "192.0.2.1", 2*time.Second)
	if !strings.Contains(got, "Beispiel Laser 100") {
		t.Fatalf("Antwort nicht ausgewertet: %q", got)
	}
	// Operation Get-Printer-Attributes (0x000B) und die Pflichtattribute muessen gesendet worden sein.
	if len(gotBody) < 8 || gotBody[3] != 0x0B || !bytes.Contains(gotBody, []byte("printer-uri")) {
		t.Errorf("Anfrage unvollstaendig: %x", gotBody)
	}
}
