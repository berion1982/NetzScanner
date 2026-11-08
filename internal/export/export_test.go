package export

import (
	"bytes"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/berion1982/netzscanner/internal/model"
)

func sample() []model.Host {
	h := model.Host{IP: "192.168.1.10", Name: "nas-01", MAC: "00:11:32:AA:BB:CC", Vendor: "Synology", Username: "admin", Location: "Büro, Raum 2", Category: model.CatServer, OS: "Linux (Synology DSM)",
		Ports: []model.Port{{Number: 22, Service: "ssh"}, {Number: 5000, Service: "http"}}}
	h.FillWebLinks()
	return []model.Host{h}
}

// Die CSV hat genau die geforderten Spalten, kein Passwort, Ports als Liste.
func TestCSVStandard(t *testing.T) {
	var b bytes.Buffer
	if err := WriteCSV(&b, sample(), false); err != nil {
		t.Fatal(err)
	}
	want := "Benutzername,IP,MAC,Hersteller (Chip),Gerätename,Standort,Offene Ports,Kategorie,Betriebssystem (Vermutung)\r\nadmin,192.168.1.10,00:11:32:AA:BB:CC,Synology,nas-01,\"Büro, Raum 2\",\"22, 5000\",Server,Linux (Synology DSM)\r\n"
	if b.String() != want {
		t.Errorf("CSV:\n%q\nerwartet:\n%q", b.String(), want)
	}
}

// Excel-Variante: BOM am Anfang und Semikolon.
func TestCSVExcel(t *testing.T) {
	var b bytes.Buffer
	WriteCSV(&b, sample(), true)
	if !bytes.HasPrefix(b.Bytes(), []byte{0xEF, 0xBB, 0xBF}) || !strings.Contains(b.String(), "Benutzername;IP;MAC;Hersteller (Chip);Gerätename;Standort;Offene Ports;Kategorie;Betriebssystem (Vermutung)") {
		t.Errorf("Excel-CSV falsch: %q", b.String())
	}
}

// Formeln, Anfuehrungszeichen und Trennzeichen in Namen duerfen nichts kaputt machen.
func TestCSVInjectionAndQuoting(t *testing.T) {
	h := model.Host{IP: "10.0.0.1", Name: `=HYPERLINK("http://evil")`, Username: "+cmd", MAC: "-1"}
	h2 := model.Host{IP: "10.0.0.2", Name: `a;b,"c"`}
	var b bytes.Buffer
	WriteCSV(&b, []model.Host{h, h2}, true)
	out := b.String()
	if !strings.Contains(out, `'+cmd;10.0.0.1;'-1;;"'=HYPERLINK(""http://evil"")"`) {
		t.Errorf("Formel nicht entschaerft: %q", out)
	}
	if !strings.Contains(out, `"a;b,""c"""`) {
		t.Errorf("Quoting falsch: %q", out)
	}
}

// Markdown und HTML maskieren Sonderzeichen (Namen kommen aus dem Netz).
func TestTablesEscape(t *testing.T) {
	hs := sample()
	hs[0].Name = `<script>alert(1)</script>|x`
	m := Meta{Target: "192.168.1.0/24", Generated: time.Date(2026, 11, 8, 12, 0, 0, 0, time.UTC), Version: "test"}
	var md, ht bytes.Buffer
	WriteMarkdown(&md, hs, m)
	WriteHTML(&ht, hs, m)
	if strings.Contains(md.String(), "<script>") || !strings.Contains(md.String(), `\|x`) {
		t.Errorf("Markdown nicht maskiert: %s", md.String())
	}
	if strings.Contains(ht.String(), "<script>alert") || !strings.Contains(ht.String(), "&lt;script&gt;") {
		t.Errorf("HTML nicht maskiert: %s", ht.String())
	}
	if !strings.Contains(ht.String(), `href="http://192.168.1.10:5000/"`) || !strings.Contains(ht.String(), "22 (ssh), 5000 (http)") {
		t.Errorf("HTML ohne Links/Ports: %s", ht.String())
	}
}

// Lesezeichen: Netscape-Format, Leisten-Markierung nur auf Wunsch, Namen maskiert, keine Zugangsdaten.
func TestBookmarks(t *testing.T) {
	hs := sample()
	hs[0].Name = `<b>x</b>`
	m := Meta{Generated: time.Date(2026, 11, 8, 12, 0, 0, 0, time.UTC), Version: "test"}
	var bar, folder bytes.Buffer
	if err := WriteBookmarks(&bar, hs, m, true); err != nil {
		t.Fatal(err)
	}
	WriteBookmarks(&folder, hs, m, false)
	o := bar.String()
	if !strings.HasPrefix(o, "<!DOCTYPE NETSCAPE-Bookmark-file-1>") || !strings.Contains(o, `PERSONAL_TOOLBAR_FOLDER="true"`) {
		t.Errorf("Kopf/Leiste fehlt: %s", o)
	}
	if strings.Contains(folder.String(), "PERSONAL_TOOLBAR_FOLDER") {
		t.Error("Ordner-Variante darf nicht als Leiste markiert sein")
	}
	if !strings.Contains(o, `HREF="http://192.168.1.10:5000/"`) || strings.Contains(o, "<b>x") || !strings.Contains(o, "&lt;b&gt;x") {
		t.Errorf("Link/Maskierung falsch: %s", o)
	}
	if BookmarkCount(hs) != 1 {
		t.Error("BookmarkCount falsch")
	}
}

// Das PDF muss gueltig beginnen/enden, auch bei leerer Liste, Umlauten, Sonderzeichen und vielen Geraeten.
func TestWritePDF(t *testing.T) {
	meta := Meta{Target: "192.168.1.0/24", Version: "NetzScanner test"}
	hosts := sample()
	hosts[0].Name = "Büro-NAS Ünïcode Привет \n=1+1"
	hosts[0].Role = "router"
	for i := 0; i < 120; i++ { // viele Geraete: Umbruch in Zeilen, Skalierung, mehrere Listenseiten
		hosts = append(hosts, model.Host{IP: "192.168.1." + strconv.Itoa(i+20), Name: "gerät-" + strconv.Itoa(i), MAC: "AA:BB:CC:00:00:01",
			Vendor: "Hersteller GmbH & Co. KG", Uplink: "192.168.1.10", Ports: []model.Port{{Number: 22, Service: "ssh"}, {Number: 80, Service: "http"}}})
	}
	for i := 0; i < 12; i++ { // viele eigene Kategorien (I-017): Legende muss umbrechen, Farben muessen gueltig sein
		hosts[i+1].Category = model.CustomKey("Eigene " + strconv.Itoa(i))
	}
	for _, hs := range [][]model.Host{nil, sample(), hosts} {
		var b bytes.Buffer
		if err := WritePDF(&b, hs, meta); err != nil {
			t.Fatalf("WritePDF: %v", err)
		}
		if !bytes.HasPrefix(b.Bytes(), []byte("%PDF-")) || !bytes.Contains(b.Bytes()[b.Len()-32:], []byte("%%EOF")) {
			t.Errorf("kein gueltiges PDF (%d Hosts, %d Byte)", len(hs), b.Len())
		}
	}
}
