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
	"math"
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

// Sammelgruppen (wie in der Weboberflaeche, I-015): Geraete mit gleichem Uplink UND gleicher
// Kategorie stehen in einem gestrichelten Rahmen; vom Uplink fuehrt nur eine Linie zur Gruppe.
const (
	pdfGroupPad   = 4.0 // Innenabstand im Rahmen
	pdfGroupTitle = 6.0 // Hoehe der Titelzeile ("IoT (19)")
	pdfUnitGap    = 8.0 // Abstand zwischen Gruppen/Einzelgeraeten einer Zeile
	pdfGroupCols  = 6   // Kaesten pro Zeile innerhalb einer Gruppe
)

// pdfFrame ist ein Gruppenrahmen (Position/Groesse in mm vor der Skalierung).
type pdfFrame struct {
	x, y, w, h float64
	cat, label string
}

// pdfLink ist eine Linie vom Uplink zu einer Gruppe/einem Einzelgeraet. Der Weg laeuft ueber eine
// "Sammelschiene" links neben den Gruppen der Ebene, damit keine Linie eine andere Gruppe kreuzt.
type pdfLink struct {
	from         string  // IP des Uplinks
	trunkX, busY float64 // senkrechte Schiene / waagerechte Hoehe unter dem Uplink
	toX, toY     float64 // Ziel: linke Kante der Einheit
}

// pdfLayout ist das Ergebnis von layoutTopology.
type pdfLayout struct {
	nodes  map[string]*pdfNode
	frames []pdfFrame
	links  []pdfLink
	height float64
}

// pdfUnit ist eine Gruppe (>= 2 Geraete) oder ein Einzelgeraet beim Layouten.
type pdfUnit struct {
	list  []model.Host
	group bool
	cols  int
	w, h  float64
}

// layoutTopology ordnet die Geraete in Ebenen an (Abstand zum Router) und bildet je Ebene
// Sammelgruppen nach (Uplink, Kategorie). Die Einheiten fliessen zeilenweise und brechen um,
// wenn die Seitenbreite nicht reicht.
func layoutTopology(hosts []model.Host) pdfLayout {
	byIP := make(map[string]model.Host, len(hosts))
	for _, h := range hosts {
		byIP[h.IP] = h
	}
	// Geraete nach Ebene gruppieren, je Ebene stabil nach Kategorie sortiert.
	levels := map[int][]model.Host{}
	maxD := 0
	for _, h := range hosts {
		d := pdfDepth(h, byIP)
		levels[d] = append(levels[d], h)
		if d > maxD {
			maxD = d
		}
	}
	usableW := pdfPageW - 2*pdfMargin
	lay := pdfLayout{nodes: make(map[string]*pdfNode, len(hosts))}
	y := 0.0
	for d := 0; d <= maxD; d++ {
		list := levels[d]
		if len(list) == 0 {
			continue
		}
		sort.SliceStable(list, func(i, j int) bool {
			return model.CategoryRank(list[i].Category) < model.CategoryRank(list[j].Category)
		})
		// 1) Einheiten bilden: Schluessel = Uplink + Kategorie (Reihenfolge des ersten Auftretens).
		var order []string
		buckets := map[string][]model.Host{}
		for _, h := range list {
			k := h.Uplink + "|" + h.Category
			if _, ok := buckets[k]; !ok {
				order = append(order, k)
			}
			buckets[k] = append(buckets[k], h)
		}
		var units []pdfUnit
		for _, k := range order {
			l := buckets[k]
			if len(l) < 2 { // Einzelgeraet: kein Rahmen
				units = append(units, pdfUnit{list: l, cols: 1, w: pdfBoxW, h: pdfBoxH})
				continue
			}
			cols := len(l)
			if cols > pdfGroupCols {
				cols = pdfGroupCols
			}
			rows := (len(l) + cols - 1) / cols
			units = append(units, pdfUnit{list: l, group: true, cols: cols,
				w: float64(cols)*pdfBoxW + float64(cols-1)*pdfGapX + 2*pdfGroupPad,
				h: pdfGroupTitle + float64(rows)*pdfBoxH + float64(rows-1)*pdfGapX + pdfGroupPad})
		}
		// 2) Einheiten in Zeilen verteilen (Umbruch bei Platzmangel).
		var lines [][]pdfUnit
		var cur []pdfUnit
		cw := 0.0
		for _, u := range units {
			if len(cur) > 0 && cw+pdfUnitGap+u.w > usableW {
				lines, cur, cw = append(lines, cur), nil, 0
			}
			if len(cur) > 0 {
				cw += pdfUnitGap
			}
			cw += u.w
			cur = append(cur, u)
		}
		if len(cur) > 0 {
			lines = append(lines, cur)
		}
		// 3) Positionen vergeben; jede Zeile mittig.
		levelTop, firstLink, minX := y, len(lay.links), usableW
		for _, line := range lines {
			total := pdfUnitGap * float64(len(line)-1)
			rowH := 0.0
			for _, u := range line {
				total += u.w
				if u.h > rowH {
					rowH = u.h
				}
			}
			x := (usableW - total) / 2
			for _, u := range line {
				first := u.list[0]
				toY := y + pdfBoxH/2
				if u.group {
					toY = y + pdfGroupTitle/2
					lay.frames = append(lay.frames, pdfFrame{x: x, y: y, w: u.w, h: u.h, cat: first.Category,
						label: model.CategoryLabel(first.Category) + " (" + strconv.Itoa(len(u.list)) + ")"})
					for i, h := range u.list {
						bx := x + pdfGroupPad + float64(i%u.cols)*(pdfBoxW+pdfGapX)
						by := y + pdfGroupTitle + float64(i/u.cols)*(pdfBoxH+pdfGapX)
						lay.nodes[h.IP] = &pdfNode{host: h, x: bx, y: by}
					}
				} else {
					lay.nodes[first.IP] = &pdfNode{host: first, x: x, y: y}
				}
				if x < minX {
					minX = x
				}
				if _, ok := byIP[first.Uplink]; ok && first.Uplink != "" && first.Uplink != first.IP {
					lay.links = append(lay.links, pdfLink{from: first.Uplink, toX: x, toY: toY})
				}
				x += u.w + pdfUnitGap
			}
			y += rowH + pdfRowGap
		}
		// Sammelschiene dieser Ebene: links neben den Einheiten, waagerechter Abschnitt knapp ueber der Ebene.
		for i := firstLink; i < len(lay.links); i++ {
			lay.links[i].trunkX = minX - pdfGapX
			lay.links[i].busY = levelTop - pdfLevelGp/2
		}
		y += pdfLevelGp
	}
	lay.height = y
	return lay
}

// categoryStroke liefert die kraeftigere Linienfarbe (RGB) einer Kategorie fuer Gruppenrahmen.
func categoryStroke(c string) [3]int {
	switch c {
	case model.CatNetwork:
		return [3]int{70, 130, 210}
	case model.CatServer:
		return [3]int{50, 140, 70}
	case model.CatIoT:
		return [3]int{200, 130, 20}
	}
	return [3]int{120, 120, 120}
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

	lay := layoutTopology(hosts)
	nodes, height := lay.nodes, lay.height
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

	// 1) Linien zuerst (Kaesten und Rahmen ueberdecken sie): Uplink -> Sammelschiene -> Gruppe.
	sx := func(x float64) float64 { return offX + x*scale }
	sy := func(y float64) float64 { return top + y*scale }
	pdf.SetDrawColor(150, 150, 150)
	pdf.SetLineWidth(0.25)
	for _, l := range lay.links {
		up, ok := nodes[l.from]
		if !ok {
			continue
		}
		ux, uy := px(up)+bw/2, py(up)+bh
		pdf.Line(ux, uy, ux, sy(l.busY))                            // vom Uplink nach unten
		pdf.Line(ux, sy(l.busY), sx(l.trunkX), sy(l.busY))          // waagerecht zur Sammelschiene
		pdf.Line(sx(l.trunkX), sy(l.busY), sx(l.trunkX), sy(l.toY)) // senkrecht zur Einheit
		pdf.Line(sx(l.trunkX), sy(l.toY), sx(l.toX), sy(l.toY))     // kurz hinein
	}
	// Gruppenrahmen: gestrichelt in Kategoriefarbe, Titel oben links.
	for _, f := range lay.frames {
		c := categoryStroke(f.cat)
		pdf.SetDrawColor(c[0], c[1], c[2])
		pdf.SetLineWidth(0.3)
		pdf.SetDashPattern([]float64{1.5, 1}, 0)
		pdf.RoundedRect(sx(f.x), sy(f.y), f.w*scale, f.h*scale, 2*scale, "1234", "D")
		pdf.SetDashPattern([]float64{}, 0)
		pdf.SetTextColor(c[0], c[1], c[2])
		pdf.SetFont("Helvetica", "B", math.Max(3, 7*scale))
		pdf.SetXY(sx(f.x)+2*scale, sy(f.y)+0.8*scale)
		pdf.CellFormat(f.w*scale-4*scale, 4*scale, t(f.label), "", 0, "L", false, 0, "")
	}
	pdf.SetLineWidth(0.2)
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
