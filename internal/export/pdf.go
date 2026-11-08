package export

// PDF-Export der Topologie (I-012): Seite 1 zeigt die Karte (Router oben, Geraete darunter),
// danach folgt eine Geraeteliste mit Name, IP, MAC, Hersteller und offenen Ports.
//
// Technik: reines Go (github.com/go-pdf/fpdf, kein CGO). Es werden nur die PDF-Standardschriften
// verwendet (Helvetica, Zeichensatz Windows-1252). Zeichen ausserhalb davon (z. B. Kyrillisch
// in einem Geraetenamen) erscheinen als "." - dafuer braucht das Programm keine Schriftdatei.
//
// Zugangsdaten gehoeren nicht in den Export: Benutzername und Passwoerter werden NICHT ausgegeben.

import (
	"io"
	"sort"
	"strconv"
	"strings"

	"github.com/go-pdf/fpdf"

	"github.com/berion1982/netzscanner/internal/model"
)

// Seitenmasse (A4 quer, in Millimetern) und Karten-Layout.
const (
	pdfPageW   = 297.0
	pdfPageH   = 210.0
	pdfMargin  = 10.0
	pdfBoxW    = 38.0 // Breite eines Geraete-Kastens
	pdfBoxH    = 12.0 // Hoehe eines Geraete-Kastens
	pdfGapX    = 4.0  // Abstand zwischen Kaesten in einer Zeile
	pdfRowGap  = 6.0  // Abstand zwischen Zeilen innerhalb einer Ebene
	pdfLevelGp = 10.0 // zusaetzlicher Abstand zwischen zwei Ebenen
	pdfMaxDeep = 10   // Schutz vor Schleifen in der Uplink-Kette (wie in der Weboberflaeche)
)

// pdfNode ist ein Kasten auf der Karte (Position in mm, vor der Skalierung).
type pdfNode struct {
	host model.Host
	x, y float64 // linke obere Ecke
}

// pdfDepth liefert den Abstand eines Geraets zum Router (Anzahl Uplink-Schritte).
func pdfDepth(h model.Host, byIP map[string]model.Host) int {
	d, cur := 0, h
	for cur.Uplink != "" && d < pdfMaxDeep {
		next, ok := byIP[cur.Uplink]
		if !ok {
			break
		}
		cur = next
		d++
	}
	return d
}

// layoutTopology ordnet die Geraete in Ebenen an und liefert Knoten (nach IP) sowie die Gesamthoehe.
// Passen mehr Kaesten in eine Ebene, als eine Zeile fasst, wird auf mehrere Zeilen umgebrochen.
func layoutTopology(hosts []model.Host) (map[string]*pdfNode, float64) {
	byIP := make(map[string]model.Host, len(hosts))
	for _, h := range hosts {
		byIP[h.IP] = h
	}
	// Geraete nach Ebene gruppieren (Reihenfolge der Liste bleibt erhalten).
	levels := map[int][]model.Host{}
	maxD := 0
	for _, h := range hosts {
		d := pdfDepth(h, byIP)
		levels[d] = append(levels[d], h)
		if d > maxD {
			maxD = d
		}
	}
	// Innerhalb einer Ebene nach Kategorie sortieren (stabil: Reihenfolge der Liste bleibt je Kategorie).
	for _, l := range levels {
		sort.SliceStable(l, func(i, j int) bool {
			return model.CategoryRank(l[i].Category) < model.CategoryRank(l[j].Category)
		})
	}
	usableW := pdfPageW - 2*pdfMargin
	cols := int((usableW + pdfGapX) / (pdfBoxW + pdfGapX)) // Kaesten pro Zeile
	nodes := make(map[string]*pdfNode, len(hosts))
	y := 0.0
	for d := 0; d <= maxD; d++ {
		list := levels[d]
		for start := 0; start < len(list); start += cols {
			end := start + cols
			if end > len(list) {
				end = len(list)
			}
			row := list[start:end]
			for i, h := range row {
				// gleichmaessig ueber die Breite verteilen (wie die SVG-Ansicht)
				cx := usableW * float64(i+1) / float64(len(row)+1)
				nodes[h.IP] = &pdfNode{host: h, x: cx - pdfBoxW/2, y: y}
			}
			y += pdfBoxH + pdfRowGap
		}
		if len(list) > 0 {
			y += pdfLevelGp
		}
	}
	return nodes, y
}

// pdfText macht aus einem UTF-8-Text einen Text fuer die Standardschrift (Windows-1252).
func pdfText(tr func(string) string, s string) string {
	// Steuerzeichen (z. B. Zeilenumbrueche aus Netzwerknamen) durch Leerzeichen ersetzen.
	s = strings.Map(func(r rune) rune {
		if r < 32 || r == 127 {
			return ' '
		}
		return r
	}, s)
	return tr(s)
}

// fitText kuerzt einen Text mit "..." so, dass er in die Breite w (mm) passt.
func fitText(pdf *fpdf.Fpdf, s string, w float64) string {
	if pdf.GetStringWidth(s) <= w {
		return s
	}
	for len(s) > 0 && pdf.GetStringWidth(s+"...") > w {
		s = s[:len(s)-1]
	}
	return s + "..."
}

// wrapText bricht einen (bereits in Windows-1252 uebersetzten) Text auf Zeilen der Breite w (mm) um.
// fpdf.SplitText ist hier nicht nutzbar: Es zerlegt den Text in UTF-8-Runen, die uebersetzten
// Bytes (z. B. 0xFC fuer "ue") sind aber kein gueltiges UTF-8 und fuehren dort zum Absturz.
// Umbruch bevorzugt nach Leerzeichen; zu lange Woerter werden hart getrennt.
func wrapText(pdf *fpdf.Fpdf, s string, w float64) []string {
	var lines []string
	cur := ""
	for _, word := range strings.SplitAfter(s, " ") {
		if pdf.GetStringWidth(cur+word) <= w {
			cur += word
			continue
		}
		if cur != "" {
			lines = append(lines, strings.TrimRight(cur, " "))
			cur = ""
		}
		// Wort allein zu breit: Zeichen fuer Zeichen auf Zeilen verteilen.
		for len(word) > 0 && pdf.GetStringWidth(word) > w {
			n := 1
			for n < len(word) && pdf.GetStringWidth(word[:n+1]) <= w {
				n++
			}
			lines = append(lines, word[:n])
			word = word[n:]
		}
		cur = word
	}
	if cur != "" || len(lines) == 0 {
		lines = append(lines, strings.TrimRight(cur, " "))
	}
	return lines
}

// WritePDF schreibt die Topologie-Karte und die Geraeteliste aller uebergebenen Geraete als PDF.
func WritePDF(w io.Writer, hosts []model.Host, meta Meta) error {
	pdf := fpdf.New("L", "mm", "A4", "")
	pdf.SetMargins(pdfMargin, pdfMargin, pdfMargin)
	pdf.SetAutoPageBreak(false, pdfMargin)
	tr := pdf.UnicodeTranslatorFromDescriptor("") // UTF-8 -> Windows-1252
	t := func(s string) string { return pdfText(tr, s) }

	// Fusszeile mit Programmversion und Seitenzahl.
	pdf.SetFooterFunc(func() {
		pdf.SetY(-8)
		pdf.SetFont("Helvetica", "", 7)
		pdf.SetTextColor(110, 110, 110)
		pdf.CellFormat(0, 4, t(meta.Version)+"  -  Seite "+strconv.Itoa(pdf.PageNo()), "", 0, "C", false, 0, "")
	})

	drawTopologyPage(pdf, t, hosts, meta)
	drawDeviceList(pdf, t, hosts)
	return pdf.Output(w)
}

// pageTitle zeichnet Titel und Untertitel oben auf einer Seite.
func pageTitle(pdf *fpdf.Fpdf, t func(string) string, title, sub string) {
	pdf.SetTextColor(20, 20, 20)
	pdf.SetFont("Helvetica", "B", 15)
	pdf.SetXY(pdfMargin, pdfMargin)
	pdf.CellFormat(0, 7, t(title), "", 1, "L", false, 0, "")
	pdf.SetFont("Helvetica", "", 8)
	pdf.SetTextColor(90, 90, 90)
	pdf.SetX(pdfMargin)
	pdf.CellFormat(0, 4, t(sub), "", 1, "L", false, 0, "")
}

// drawTopologyPage zeichnet Seite 1: die Karte, bei Bedarf verkleinert, damit sie auf die Seite passt.
func drawTopologyPage(pdf *fpdf.Fpdf, t func(string) string, hosts []model.Host, meta Meta) {
	pdf.AddPage()
	pageTitle(pdf, t, "Netzwerk-Topologie",
		"Ziel: "+meta.Target+"  |  "+strconv.Itoa(len(hosts))+" Geraete  |  Stand: "+meta.Generated.Format("02.01.2006 15:04"))
	if len(hosts) == 0 {
		pdf.SetFont("Helvetica", "", 10)
		pdf.Ln(6)
		pdf.CellFormat(0, 6, t("Keine Geraete in der Liste."), "", 1, "L", false, 0, "")
		return
	}

	nodes, height := layoutTopology(hosts)
	top := pdf.GetY() + 4
	availH := pdfPageH - top - 20 // Platz fuer Legende, Hinweis und Fusszeile abziehen
	scale := 1.0
	if height > availH {
		scale = availH / height // alles gleichmaessig verkleinern, damit es auf die Seite passt
	}
	usableW := pdfPageW - 2*pdfMargin
	offX := pdfMargin + usableW*(1-scale)/2 // verkleinerte Karte mittig setzen

	// Position/Groesse nach Skalierung (links oben bzw. Kastenmasse).
	px := func(n *pdfNode) float64 { return offX + n.x*scale }
	py := func(n *pdfNode) float64 { return top + n.y*scale }
	bw, bh := pdfBoxW*scale, pdfBoxH*scale

	// 1) Verbindungslinien zuerst zeichnen, damit die Kaesten sie ueberdecken.
	pdf.SetDrawColor(150, 150, 150)
	pdf.SetLineWidth(0.25)
	for _, n := range nodes {
		if up, ok := nodes[n.host.Uplink]; ok && n.host.Uplink != n.host.IP {
			pdf.Line(px(up)+bw/2, py(up)+bh, px(n)+bw/2, py(n))
		}
	}
	// 2) Kaesten mit Name (fett), IP und ggf. Standort. Router/Switch farbig hervorheben.
	nameFont, ipFont := 8*scale, 7*scale
	if nameFont < 3 {
		nameFont, ipFont = 3, 2.6
	}
	for _, h := range hosts { // Reihenfolge der Liste -> stabile Ausgabe
		n := nodes[h.IP]
		fill := categoryFill(h.Category)
		pdf.SetFillColor(fill[0], fill[1], fill[2])
		pdf.SetDrawColor(90, 90, 90)
		pdf.RoundedRect(px(n), py(n), bw, bh, 1.2*scale, "1234", "DF")
		pdf.SetTextColor(20, 20, 20)
		// Ohne Standort: zwei Zeilen (Name, IP) wie bisher; mit Standort eine dritte Zeile.
		nameY, ipY, nameH, ipH := 0.14, 0.52, 0.40, 0.34
		if h.Location != "" {
			nameY, ipY, nameH, ipH = 0.06, 0.34, 0.28, 0.26
		}
		pdf.SetFont("Helvetica", "B", nameFont)
		pdf.SetXY(px(n), py(n)+bh*nameY)
		pdf.CellFormat(bw, bh*nameH, fitText(pdf, t(h.Name), bw-1), "", 0, "C", false, 0, "")
		pdf.SetFont("Helvetica", "", ipFont)
		pdf.SetTextColor(70, 70, 70)
		pdf.SetXY(px(n), py(n)+bh*ipY)
		pdf.CellFormat(bw, bh*ipH, fitText(pdf, t(h.IP), bw-1), "", 0, "C", false, 0, "")
		if h.Location != "" { // Standort (Freitext des Nutzers) kursiv unter der IP
			pdf.SetFont("Helvetica", "I", ipFont)
			pdf.SetXY(px(n), py(n)+bh*0.62)
			pdf.CellFormat(bw, bh*0.26, fitText(pdf, t(h.Location), bw-1), "", 0, "C", false, 0, "")
		}
	}
	drawLegend(pdf, t, hosts)
	// Hinweis zur Aussagekraft (gleich wie in der Hilfe der Oberflaeche).
	pdf.SetFont("Helvetica", "I", 7)
	pdf.SetTextColor(110, 110, 110)
	pdf.SetXY(pdfMargin, pdfPageH-14)
	pdf.CellFormat(0, 4, t("Hinweis: Ohne SNMP/LLDP ist dies eine Sternansicht (Router oben, Geraete im selben Subnetz darunter), keine echte Verkabelung."), "", 0, "L", false, 0, "")
}

// categoryFill liefert die helle Kastenfarbe (RGB) einer Kategorie; druckfreundlich.
func categoryFill(c string) [3]int {
	switch c {
	case model.CatNetwork:
		return [3]int{214, 232, 255} // hellblau
	case model.CatServer:
		return [3]int{222, 245, 226} // hellgruen
	case model.CatIoT:
		return [3]int{255, 236, 204} // hellorange
	}
	return [3]int{238, 238, 238} // Clients: hellgrau
}

// drawLegend zeichnet unter der Karte die Farbzuordnung der Kategorien samt Anzahl.
func drawLegend(pdf *fpdf.Fpdf, t func(string) string, hosts []model.Host) {
	count := map[string]int{}
	for _, h := range hosts {
		count[h.Category]++
	}
	x, y := pdfMargin, pdfPageH-20.0
	pdf.SetFont("Helvetica", "", 8)
	pdf.SetDrawColor(90, 90, 90)
	for _, c := range model.Categories {
		f := categoryFill(c)
		pdf.SetFillColor(f[0], f[1], f[2])
		pdf.Rect(x, y, 5, 3.5, "DF")
		pdf.SetTextColor(20, 20, 20)
		pdf.SetXY(x+6.5, y-0.3)
		label := t(model.CategoryLabel(c)) + " (" + strconv.Itoa(count[c]) + ")"
		pdf.CellFormat(40, 4, label, "", 0, "L", false, 0, "")
		x += 52
	}
}

// Spalten der Geraeteliste: Titel und Breite in mm (Summe = nutzbare Seitenbreite 277 mm).
var pdfCols = []struct {
	title string
	w     float64
}{
	{"Name", 40}, {"IP", 26}, {"MAC", 32}, {"Hersteller (Chip)", 36}, {"Kategorie", 22}, {"System (Vermutung)", 44}, {"Standort", 32}, {"Offene Ports", 45},
}

// drawDeviceList zeichnet die Geraeteliste ab Seite 2; Zeilen mit langem Text werden umgebrochen.
func drawDeviceList(pdf *fpdf.Fpdf, t func(string) string, hosts []model.Host) {
	const lineH = 4.2
	header := func() {
		pdf.AddPage()
		pageTitle(pdf, t, "Geraeteliste", strconv.Itoa(len(hosts))+" Geraete")
		pdf.Ln(2)
		pdf.SetFont("Helvetica", "B", 8)
		pdf.SetFillColor(225, 225, 225)
		pdf.SetTextColor(20, 20, 20)
		pdf.SetX(pdfMargin)
		for _, c := range pdfCols {
			pdf.CellFormat(c.w, 6, t(c.title), "1", 0, "L", true, 0, "")
		}
		pdf.Ln(-1)
	}
	header()
	pdf.SetFont("Helvetica", "", 8)
	for _, h := range hosts {
		cells := []string{h.Name, h.IP, h.MAC, h.Vendor, model.CategoryLabel(h.Category), h.OS, h.Location, portsText(h)}
		// Zeilenhoehe = hoechste Zelle (Text je Spalte umbrechen).
		lines := make([][]string, len(cells))
		maxLines := 1
		for i, c := range cells {
			if c == "" {
				c = "-"
			}
			parts := wrapText(pdf, t(c), pdfCols[i].w-2)
			if len(parts) == 0 {
				parts = []string{""}
			}
			lines[i] = parts
			if len(parts) > maxLines {
				maxLines = len(parts)
			}
		}
		rowH := float64(maxLines)*lineH + 1.6
		if pdf.GetY()+rowH > pdfPageH-14 { // Seitenende -> neue Seite mit Kopfzeile
			header()
			pdf.SetFont("Helvetica", "", 8)
		}
		x, y := pdfMargin, pdf.GetY()
		for i, c := range pdfCols {
			pdf.Rect(x, y, c.w, rowH, "D")
			for j, ln := range lines[i] {
				pdf.SetXY(x+1, y+0.8+float64(j)*lineH)
				pdf.CellFormat(c.w-2, lineH, ln, "", 0, "L", false, 0, "")
			}
			x += c.w
		}
		pdf.SetY(y + rowH)
	}
}

// portsText liefert die offenen Ports als "22 (ssh), 80 (http)".
func portsText(h model.Host) string {
	parts := make([]string, len(h.Ports))
	for i, p := range h.Ports {
		parts[i] = strconv.Itoa(p.Number)
		if p.Service != "" {
			parts[i] += " (" + p.Service + ")"
		}
	}
	return strings.Join(parts, ", ")
}
