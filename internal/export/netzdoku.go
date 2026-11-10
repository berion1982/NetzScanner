package export

// Netzdokumentation als ein PDF (I-036): Deckblatt (frei eintragbare Angaben), Zusammenfassung,
// Befunde (I-064), danach die vorhandene Topologie-Karte und die Geraeteliste aus pdf.go.
// Es werden nur vorhandene Scan-Daten verwendet; Zugangsdaten sind nie enthalten.

import (
	"io"
	"strconv"

	"github.com/go-pdf/fpdf"

	"github.com/berion1982/netzscanner/internal/findings"
	"github.com/berion1982/netzscanner/internal/model"
)

// DocInfo sind die vom Nutzer frei eingetragenen Angaben fuer das Deckblatt (alle optional).
type DocInfo struct {
	Customer string // Kunde bzw. Auftraggeber
	Network  string // Bezeichnung des Netzes / Standorts
	Author   string // Bearbeiter
}

// Grenzen fuer die Eingaben (Schutz gegen uebergrosse Texte im PDF).
const docInfoMaxLen = 120

// Clean kuerzt die Angaben auf eine sinnvolle Laenge (Zeichen, nicht Bytes) und entfernt Steuerzeichen.
func (d DocInfo) Clean() DocInfo {
	return DocInfo{Customer: cleanDocText(d.Customer), Network: cleanDocText(d.Network), Author: cleanDocText(d.Author)}
}

// cleanDocText entfernt Steuerzeichen (z. B. Zeilenumbrueche) und kuerzt auf docInfoMaxLen Zeichen.
func cleanDocText(s string) string {
	out := make([]rune, 0, len(s))
	for _, r := range s {
		if r < 0x20 || r == 0x7f {
			continue
		}
		out = append(out, r)
		if len(out) >= docInfoMaxLen {
			break
		}
	}
	return string(out)
}

// WriteNetworkDocPDF schreibt die komplette Netzdokumentation.
// Reihenfolge: Deckblatt+Zusammenfassung, Befunde, Topologie-Karte, Geraeteliste.
func WriteNetworkDocPDF(w io.Writer, hosts []model.Host, list []findings.Finding, info DocInfo, meta Meta) error {
	info = info.Clean()
	pdf := newPDF(meta)
	t := pdfTranslator(pdf)

	drawCoverPage(pdf, t, hosts, list, info, meta)
	drawFindingsPages(pdf, t, list)
	drawTopologyPage(pdf, t, hosts, meta)
	drawDeviceList(pdf, t, hosts)
	return pdf.Output(w)
}

// drawCoverPage zeichnet das Deckblatt mit Angaben und einer kurzen Zahlen-Zusammenfassung.
func drawCoverPage(pdf *fpdf.Fpdf, t func(string) string, hosts []model.Host, list []findings.Finding, info DocInfo, meta Meta) {
	pdf.AddPage()
	pdf.SetTextColor(20, 20, 20)
	pdf.SetFont("Helvetica", "B", 26)
	pdf.SetXY(pdfMargin, 40)
	pdf.CellFormat(0, 12, t("Netzdokumentation"), "", 1, "L", false, 0, "")

	// Angaben als Zeilen "Bezeichnung: Wert"; leere Angaben werden ausgelassen.
	rows := [][2]string{
		{"Kunde", info.Customer},
		{"Netz / Standort", info.Network},
		{"Gescanntes Ziel", meta.Target},
		{"Bearbeiter", info.Author},
		{"Erstellt am", meta.Generated.Format("02.01.2006 15:04")},
		{"Programm", meta.Version},
	}
	// Netz-Grunddaten des Scan-Rechners (I-060) direkt nach den Angaben.
	rows = append(rows, meta.NetLines...)
	pdf.Ln(6)
	// Breite der Bezeichnungsspalte aus dem laengsten Text berechnen (statt fest), damit
	// lange Bezeichnungen wie "Scan-Rechner (IP / Netzmaske)" nicht in den Wert hineinragen.
	pdf.SetFont("Helvetica", "", 11)
	labelW := 50.0 // Mindestbreite in mm
	for _, r := range rows {
		if r[1] == "" {
			continue
		}
		if w := pdf.GetStringWidth(t(r[0])) + 6; w > labelW { // +6 mm Abstand zum Wert
			labelW = w
		}
	}
	// Die Bezeichnungen duerfen hoechstens die halbe nutzbare Breite einnehmen; der Wert braucht Platz.
	if maxW := (pdfPageW - 2*pdfMargin) / 2; labelW > maxW {
		labelW = maxW
	}
	for _, r := range rows {
		if r[1] == "" {
			continue
		}
		pdf.SetX(pdfMargin)
		pdf.SetFont("Helvetica", "", 11)
		pdf.SetTextColor(90, 90, 90)
		pdf.CellFormat(labelW, 7, t(fitText(pdf, r[0], labelW-2)), "", 0, "L", false, 0, "")
		pdf.SetTextColor(20, 20, 20)
		pdf.CellFormat(0, 7, t(fitText(pdf, r[1], pdfPageW-2*pdfMargin-labelW)), "", 1, "L", false, 0, "")
	}

	// Zusammenfassung in Zahlen.
	pdf.Ln(10)
	pdf.SetX(pdfMargin)
	pdf.SetFont("Helvetica", "B", 13)
	pdf.CellFormat(0, 8, t("Zusammenfassung"), "", 1, "L", false, 0, "")
	pdf.SetFont("Helvetica", "", 11)
	for _, line := range summaryLines(hosts, list) {
		pdf.SetX(pdfMargin)
		pdf.CellFormat(0, 6.5, t(line), "", 1, "L", false, 0, "")
	}

	// Hinweis zur Aussagekraft (Befunde sind Hinweise, keine bewiesenen Schwachstellen).
	pdf.Ln(8)
	pdf.SetX(pdfMargin)
	pdf.SetFont("Helvetica", "I", 8.5)
	pdf.SetTextColor(90, 90, 90)
	pdf.MultiCell(pdfPageW-2*pdfMargin, 4.2, t("Stand der Daten: Zeitpunkt des Scans. Geräte, die zum Scan aus waren oder nicht antworteten, fehlen. "+
		"Befunde sind Hinweise aus den gesammelten Daten zum Gegenprüfen, keine bewiesenen Schwachstellen."), "", "L", false)
}

// summaryLines liefert die Zahlen fuer die Zusammenfassung (Geraete, Befunde je Schweregrad).
func summaryLines(hosts []model.Host, list []findings.Finding) []string {
	lines := []string{"Geräte in der Liste: " + strconv.Itoa(len(hosts))}
	if len(list) == 0 {
		return append(lines, "Befunde: keine")
	}
	count := map[string]int{}
	for _, f := range list {
		count[f.Severity]++
	}
	lines = append(lines, "Befunde: "+strconv.Itoa(len(list)))
	for _, s := range []string{findings.High, findings.Medium, findings.Low, findings.Info} {
		if count[s] > 0 {
			lines = append(lines, "   "+findings.SeverityLabel(s)+": "+strconv.Itoa(count[s]))
		}
	}
	return lines
}

// Spaltenbreiten der Befundtabelle (Summe = Seitenbreite - 2 * Rand = 277 mm).
var findingCols = []struct {
	title string
	w     float64
}{{"Grad", 16}, {"IP", 28}, {"Gerät", 42}, {"Port", 14}, {"Befund", 60}, {"Hinweis", 117}}

// drawFindingsPages zeichnet die Befundtabelle (eigene Seite(n); bei keinen Befunden ein kurzer Hinweis).
func drawFindingsPages(pdf *fpdf.Fpdf, t func(string) string, list []findings.Finding) {
	const lineH = 4.2
	header := func() {
		pdf.AddPage()
		pageTitle(pdf, t, "Befunde", strconv.Itoa(len(list))+" Hinweise (zum Gegenprüfen, keine bewiesenen Schwachstellen)")
		pdf.Ln(2)
		if len(list) == 0 {
			return
		}
		pdf.SetFont("Helvetica", "B", 8)
		pdf.SetFillColor(225, 225, 225)
		pdf.SetTextColor(20, 20, 20)
		pdf.SetX(pdfMargin)
		for _, c := range findingCols {
			pdf.CellFormat(c.w, 6, t(c.title), "1", 0, "L", true, 0, "")
		}
		pdf.Ln(-1)
	}
	header()
	if len(list) == 0 {
		pdf.SetX(pdfMargin)
		pdf.SetFont("Helvetica", "", 10)
		pdf.CellFormat(0, 8, t("Keine Befunde aus den vorhandenen Scan-Daten."), "", 1, "L", false, 0, "")
		return
	}
	pdf.SetFont("Helvetica", "", 8)
	for _, f := range list {
		port := ""
		if f.Port != 0 {
			port = strconv.Itoa(f.Port)
		}
		cells := []string{findings.SeverityLabel(f.Severity), f.IP, f.Name, port, f.Title, f.Detail}
		lines := make([][]string, len(cells))
		maxLines := 1
		for i, c := range cells {
			if c == "" {
				c = "-"
			}
			lines[i] = wrapText(pdf, t(c), findingCols[i].w-2)
			if len(lines[i]) > maxLines {
				maxLines = len(lines[i])
			}
		}
		rowH := float64(maxLines)*lineH + 1.6
		if pdf.GetY()+rowH > pdfPageH-14 { // Seitenende -> neue Seite mit Kopfzeile
			header()
			pdf.SetFont("Helvetica", "", 8)
		}
		x, y := pdfMargin, pdf.GetY()
		for i, c := range findingCols {
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
