package export

// Export der Befundliste (I-064) als CSV und lesbares Markdown. Die Befunde sind Hinweise
// zum Gegenpruefen, keine bewiesenen Schwachstellen - das steht auch in jeder Datei.

import (
	"encoding/csv"
	"fmt"
	"io"
	"strconv"
	"strings"

	"github.com/berion1982/netzscanner/internal/findings"
)

var findingsHeader = []string{"Schweregrad", "IP", "Gerät", "Port", "Befund", "Hinweis"}

// findingPort liefert den Port als Text ("" = nicht portbezogen).
func findingPort(f findings.Finding) string {
	if f.Port == 0 {
		return ""
	}
	return strconv.Itoa(f.Port)
}

// WriteFindingsCSV schreibt die Befunde. excel=true: Semikolon + BOM (Excel Deutsch).
// Geraetenamen stammen aus dem Netz -> Zellen sind gegen Formel-Einschleusung geschuetzt.
func WriteFindingsCSV(w io.Writer, list []findings.Finding, excel bool) error {
	if excel {
		if _, err := w.Write([]byte{0xEF, 0xBB, 0xBF}); err != nil {
			return err
		}
	}
	cw := csv.NewWriter(w)
	if excel {
		cw.Comma = ';'
	}
	cw.UseCRLF = true
	if err := cw.Write(findingsHeader); err != nil {
		return err
	}
	for _, f := range list {
		row := []string{findings.SeverityLabel(f.Severity), f.IP, f.Name, findingPort(f), f.Title, f.Detail}
		for i := range row {
			row[i] = safeCell(row[i])
		}
		if err := cw.Write(row); err != nil {
			return err
		}
	}
	cw.Flush()
	return cw.Error()
}

// WriteFindingsMarkdown schreibt die Befunde als lesbare Markdown-Tabelle.
func WriteFindingsMarkdown(w io.Writer, list []findings.Finding, m Meta) error {
	var b strings.Builder
	fmt.Fprintf(&b, "# NetzScanner – Befundliste\n\n- Erstellt: %s\n- Programm: %s\n- Ziel: %s\n- Anzahl: %d\n\n",
		m.Generated.Format("02.01.2006 15:04"), mdEscape(m.Version), mdEscape(m.Target), len(list))
	b.WriteString("| " + strings.Join(findingsHeader, " | ") + " |\n|---|---|---|---|---|---|\n")
	for _, f := range list {
		fmt.Fprintf(&b, "| %s | %s | %s | %s | %s | %s |\n", mdEscape(findings.SeverityLabel(f.Severity)),
			mdEscape(f.IP), mdEscape(f.Name), mdEscape(findingPort(f)), mdEscape(f.Title), mdEscape(f.Detail))
	}
	b.WriteString("\nHinweis: Die Befunde entstehen allein aus den Scan-Daten (offene Ports, Zertifikate, MAC) und sind **Hinweise zum Gegenprüfen**, keine bewiesenen Schwachstellen. Eine Portnummer verrät nur den üblichen Dienst.\n")
	_, err := io.WriteString(w, b.String())
	return err
}
